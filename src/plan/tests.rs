use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use super::*;
use crate::config::when::{Distro, Machine};
use crate::env::Env;
use crate::fs::{self, Mode as FileMode};
use crate::journal;
use crate::journal::tests::{crash_phases, finish_crash_phases};
use crate::journal::{Content, Ownership, Request};
use crate::paths::Portable;
use crate::state::{ExclusiveLock, Mechanism};
use crate::testing::{GuardedHome, guarded_home, mode_of};

/// An environment with nothing overridden and no terminal.
pub(crate) fn env(home: &Path) -> Env {
    Env {
        home: home.to_path_buf(),
        xdg_config_home: None,
        xdg_state_home: None,
        no_color: false,
        stdout_tty: false,
        stdin_tty: false,
        stderr_tty: false,
        user: None,
    }
}

/// Write `layer` as the repo's `bx.toml` under `home`.
pub(crate) fn seed(home: &Path, layer: &str) {
    let repo = home.join(".config/bx");
    std::fs::create_dir_all(&repo).expect("the config repo");
    std::fs::write(repo.join("bx.toml"), layer).expect("bx.toml");
}

/// Load the inputs for `home`.
pub(super) fn load(home: &Path) -> Inputs {
    Inputs::load(&env(home)).expect("the inputs load")
}

/// Write `layer` as the repo's `bx.toml` and load it.
pub(crate) fn inputs(home: &GuardedHome, layer: &str) -> Inputs {
    seed(home.path(), layer);
    load(home.path())
}

/// [`inputs`], decided as if this machine ran Linux: what a layer kept
/// to Linux, a systemd unit say, declares whatever OS runs the test.
pub(crate) fn inputs_on_linux(home: &GuardedHome, layer: &str) -> Inputs {
    seed(home.path(), layer);
    let machine = Machine {
        os: "linux".to_string(),
        ..Machine::read(None)
    };
    Inputs::load_on(
        &env(home.path()),
        activation::System::from_env().with_machine(machine),
    )
    .expect("the inputs load")
}

/// One inline target, as TOML. `content` is spelled as a TOML basic string.
pub(crate) fn inline(path: &str, content: &str) -> String {
    format!("[[target]]\npath = \"{path}\"\ncontent = \"{content}\"\n")
}

pub(super) fn plan(inputs: &Inputs) -> Report {
    run(inputs, Mode::Plan, &mut |_| panic!("plan never asks")).expect("plan runs")
}

pub(super) fn apply(inputs: &Inputs) -> Report {
    run(inputs, Mode::Apply, &mut |_| Ok(true)).expect("apply runs")
}

/// Write `bytes` at `~/rel` through a journalled session, so bx owns it
/// the way an `apply` would leave it.
pub(crate) fn own(home: &Path, rel: &str, bytes: &[u8], mechanism: Mechanism) {
    let state = StateDir::resolve(home);
    let target = Portable::parse_in(&format!("~/{rel}"), home).expect("a portable target");
    let dest = home.join(rel);
    let planned = fs::observe(&dest).expect("observe");
    let mut session =
        Session::open(&state, SessionKind::Apply, home, vec![target.clone()]).expect("a session");
    session
        .apply(Request {
            target,
            dest,
            content: Content::Bytes {
                bytes: bytes.to_vec(),
                planned,
            },
            mode: FileMode::DEFAULT_FILE,
            ownership: Ownership::Owned(mechanism),
        })
        .expect("the write");
    session.finish().expect("finish");
}

/// Every target the ledger under `state` holds: what `rm` hands back.
fn ledger_targets(state: &StateDir, home: &Path) -> Vec<Portable> {
    LedgerView::read(state, home)
        .expect("the ledger")
        .value
        .iter()
        .map(|(target, _)| target.clone())
        .collect()
}

fn text(change: &Change) -> &str {
    match change.diff.as_ref().map(|diff| &diff.kind) {
        Some(DiffKind::Text(text)) => text,
        other => panic!("expected a text diff, found {other:?}"),
    }
}

/// One path under a snapshot root: its bytes when it is a file, and its mode.
type Entry = (PathBuf, Option<Vec<u8>>, u32);

/// Every path under `root` except those beneath a `skip` prefix, with the
/// bytes of each regular file and every mode.
pub(crate) fn snapshot(root: &Path, skip: &[&str]) -> Vec<Entry> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a directory") {
            let path = entry.expect("an entry").path();
            let rel = path.strip_prefix(root).expect("under root").to_path_buf();
            if skip.iter().any(|prefix| rel.starts_with(prefix)) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path).expect("lstat");
            let bytes = meta
                .is_file()
                .then(|| std::fs::read(&path).expect("read a file"));
            if meta.is_dir() {
                stack.push(path);
            }
            found.push((rel, bytes, meta.permissions().mode()));
        }
    }
    found.sort();
    found
}

/// What neither a rollback nor a restore puts back: bx's own records, and
/// the repo.
const OUTSIDE: [&str; 2] = [".local", ".config/bx"];

#[test]
fn t1_an_absent_target_is_a_create_with_the_whole_body_added() {
    let home = guarded_home();
    let inputs = inputs(&home, &inline("~/.a", "one\\ntwo\\n"));

    let report = plan(&inputs);

    assert_eq!(report.actions(), vec![Action::Create]);
    assert_eq!(report.changes[0].target, "~/.a");
    assert_eq!(
        text(&report.changes[0]),
        "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -0,0 +1,2 @@\n+one\n+two\n"
    );
    assert!(!home.child(".a").exists(), "plan wrote the target");
    assert!(
        !StateDir::resolve(home.path()).root().exists(),
        "plan created the state directory"
    );
    assert_eq!(exit(&report, Mode::Plan), Exit::Pending);
}

#[test]
fn t2_an_owned_file_whose_content_differs_is_a_modify_with_the_exact_diff() {
    let home = guarded_home();
    own(home.path(), ".a", b"one\ntwo\nthree\n", Mechanism::Own);
    let inputs = inputs(&home, &inline("~/.a", "one\\nTWO\\nthree\\n"));

    let report = plan(&inputs);

    assert_eq!(report.actions(), vec![Action::Modify]);
    assert_eq!(report.changes[0].note, None);
    assert_eq!(
        text(&report.changes[0]),
        "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"
    );

    apply(&inputs);
    assert_eq!(
        std::fs::read(home.child(".a")).expect("the file"),
        b"one\nTWO\nthree\n"
    );
}

#[test]
fn t3_a_present_file_bx_does_not_own_is_a_conflict_apply_does_not_overwrite() {
    let home = guarded_home();
    home.write(".a", "mine\n");
    let inputs = inputs(
        &home,
        &[inline("~/.a", "bx\\n"), inline("~/.b", "b\\n")].concat(),
    );

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Conflict, Action::Create]);
    assert_eq!(
        report.changes[0].note.as_deref(),
        Some("exists and bx does not own it")
    );
    assert_eq!(
        text(&report.changes[0]),
        "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -1 +1 @@\n-mine\n+bx\n"
    );

    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Pending);
    assert_eq!(std::fs::read(home.child(".a")).expect("mine"), b"mine\n");
    assert_eq!(std::fs::read(home.child(".b")).expect("created"), b"b\n");
}

#[test]
fn t4_an_owned_file_edited_since_bx_wrote_it_is_a_conflict_not_overwritten() {
    let home = guarded_home();
    own(home.path(), ".a", b"bx\n", Mechanism::Own);
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    let inputs = inputs(&home, &inline("~/.a", "new\\n"));

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Conflict]);
    assert_eq!(
        report.changes[0].note.as_deref(),
        Some("edited since bx last wrote it")
    );

    let applied = apply(&inputs);
    assert!(!applied.executed, "nothing to write, so no session");
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
}

#[test]
fn an_owned_file_already_holding_the_body_is_unchanged() {
    let home = guarded_home();
    own(home.path(), ".a", b"bx\n", Mechanism::Own);
    let inputs = inputs(&home, &inline("~/.a", "bx\\n"));

    let report = plan(&inputs);

    assert_eq!(report.actions(), vec![Action::Unchanged]);
    assert_eq!(report.changes[0].diff, None);
    assert_eq!(exit(&report, Mode::Plan), Exit::Converged);
}

/// A file bx does not own at `~/.a`, already holding `bx\n` at `mode`, under
/// a target that wants exactly that.
fn an_unowned_match(home: &GuardedHome, mode: u32) -> Inputs {
    home.write(".a", "bx\n");
    fs::set_mode(&home.child(".a"), FileMode::from_bits(mode)).expect("chmod");
    let layer =
        format!("[[target]]\npath = \"~/.a\"\ncontent = \"bx\\n\"\nmode = \"{mode:04o}\"\n");
    inputs(home, &layer)
}

#[test]
fn a_file_bx_does_not_own_that_already_matches_is_claimed_with_no_diff() {
    let home = guarded_home();
    // Not the default mode, and no narrower than the home it sits in.
    let inputs = an_unowned_match(&home, 0o755);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Modify]);
    assert_eq!(planned.changes[0].diff, None);
    assert_eq!(planned.changes[0].note.as_deref(), Some(decide::CLAIM));
    assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);

    // Invariant 7: apply announces the row plan did, and writes nothing else.
    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(applied.changes, planned.changes);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"bx\n");
    assert_eq!(mode_of(&home.child(".a")), 0o755);

    let state = StateDir::resolve(home.path());
    let ledger = LedgerView::read(&state, home.path())
        .expect("the ledger")
        .value;
    let target = Portable::parse_in("~/.a", home.path()).expect("a portable target");
    let entry = ledger.get(&target).expect("claimed");
    let observed = fs::observe(&home.child(".a")).expect("observe");
    assert_eq!(Some(entry.written), observed.digest());
    assert_eq!(entry.mode, FileMode::from_bits(0o755));
    assert_eq!(entry.mechanism, Mechanism::Own);
    assert!(
        matches!(entry.prior, crate::state::Prior::Existed(_)),
        "{entry:?}"
    );

    // Invariant 3: the claim is recorded, so the next plan is empty.
    let again = plan(&inputs);
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert_eq!(again.changes[0].note, None);
    assert_eq!(exit(&again, Mode::Plan), Exit::Converged);
}

#[test]
fn a_claimed_file_takes_the_repo_s_next_change_as_a_modify() {
    let home = guarded_home();
    apply(&an_unowned_match(&home, 0o644));

    let changed = inputs(&home, &inline("~/.a", "v2\\n"));
    let planned = plan(&changed);
    assert_eq!(planned.actions(), vec![Action::Modify]);
    assert_eq!(planned.changes[0].note, None);
    assert_eq!(
        text(&planned.changes[0]),
        "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -1 +1 @@\n-bx\n+v2\n"
    );

    apply(&changed);
    assert_eq!(std::fs::read(home.child(".a")).expect("updated"), b"v2\n");
    assert_eq!(plan(&changed).actions(), vec![Action::Unchanged]);
}

#[test]
fn rm_hands_a_claimed_file_back_exactly_as_it_was_found() {
    let home = guarded_home();
    let inputs = an_unowned_match(&home, 0o600);
    let before = snapshot(home.path(), &OUTSIDE);

    apply(&inputs);
    let state = StateDir::resolve(home.path());
    let targets = ledger_targets(&state, home.path());
    assert_eq!(targets.len(), 1);
    crate::restore::restore(&state, home.path(), &targets).expect("restore");

    assert_eq!(snapshot(home.path(), &OUTSIDE), before);
    assert!(ledger_targets(&state, home.path()).is_empty());
}

#[test]
fn a_file_bx_attached_to_another_way_is_a_conflict() {
    let home = guarded_home();
    own(
        home.path(),
        ".a",
        b"old\n",
        Mechanism::Region { comment: '#' },
    );
    let inputs = inputs(&home, &inline("~/.a", "new\\n"));

    let report = plan(&inputs);

    assert_eq!(report.actions(), vec![Action::Conflict]);
    assert_eq!(
        report.changes[0].note.as_deref(),
        Some("bx attached to this file as a managed region")
    );
}

#[test]
fn t5_a_symlink_a_directory_and_an_unusable_parent_are_conflicts() {
    let home = guarded_home();
    home.write("real", "x\n");
    std::os::unix::fs::symlink(home.child("real"), home.child(".link")).expect("a link");
    std::fs::create_dir(home.child(".dir")).expect("a directory");
    home.write(".file", "not a directory\n");
    let layer = [
        inline("~/.link", "x\\n"),
        inline("~/.dir", "x\\n"),
        inline("~/.file/inner", "x\\n"),
    ]
    .concat();
    let inputs = inputs(&home, &layer);

    let report = plan(&inputs);

    assert_eq!(
        report.actions(),
        vec![Action::Conflict, Action::Conflict, Action::Conflict]
    );
    for change in &report.changes {
        assert!(change.note.is_some(), "{change:?}");
        assert_eq!(change.diff, None, "{change:?}");
    }
    assert!(
        report.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("symlink"))
    );
    assert!(
        report.changes[1]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("directory"))
    );

    assert!(!apply(&inputs).executed);
    assert!(home.child(".dir").is_dir());
}

#[test]
fn decision_9_every_unusable_parent_is_named_by_its_portable_path() {
    let home = guarded_home();
    home.write(".file", "not a directory\n");
    std::os::unix::fs::symlink(home.child("nowhere"), home.child(".dangling"))
        .expect("a dangling link");
    std::os::unix::fs::symlink(home.child(".loop"), home.child(".loop")).expect("a loop");
    let layer = [
        inline("~/.file/inner", "x\\n"),
        inline("~/.file/a/b", "x\\n"),
        inline("~/.dangling/x", "x\\n"),
        inline("~/.loop/x", "x\\n"),
    ]
    .concat();
    let inputs = inputs(&home, &layer);

    let report = plan(&inputs);

    let notes: Vec<&str> = report
        .changes
        .iter()
        .map(|change| change.note.as_deref().expect("a note"))
        .collect();
    assert_eq!(
        notes[..3],
        [
            "~/.file is not a directory, so bx cannot write a file inside it",
            "~/.file does not resolve to a directory, so bx cannot create ~/.file/a inside it",
            "~/.dangling does not resolve to a directory, so bx cannot create ~/.dangling \
                 inside it",
        ]
    );
    assert!(
        notes[3].starts_with("~/.loop does not resolve to a directory (")
            && notes[3].ends_with("), so bx cannot write a file inside it"),
        "{}",
        notes[3]
    );
    let absolute = home.path().to_string_lossy().into_owned();
    for note in notes {
        assert!(!note.contains(&absolute), "{note}");
    }
    assert_eq!(report.actions(), vec![Action::Conflict; 4]);
}

#[test]
fn t6_an_unset_required_value_blocks_its_target_with_the_init_hint() {
    let home = guarded_home();
    let layer = format!(
        "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\nrequired = true\n\
             is_root = true\n{}",
        inline("~/.env", "X={{scratch_root}}\\n")
    );
    let inputs = inputs(&home, &layer);

    let report = plan(&inputs);

    assert_eq!(report.actions(), vec![Action::Blocked]);
    assert_eq!(
        report.changes[0].note.as_deref(),
        Some(config::values::init_hint(&["scratch_root"]).as_str())
    );
    assert_eq!(report.changes[0].diff, None);

    assert!(!apply(&inputs).executed);
    assert!(!home.child(".env").exists());
}

#[test]
fn t7_rows_follow_the_configuration_order() {
    let home = guarded_home();
    let layer = [
        inline("~/.c", "c\\n"),
        inline("~/.a", "a\\n"),
        inline("~/.b", "b\\n"),
    ]
    .concat();
    let inputs = inputs(&home, &layer);

    let report = plan(&inputs);

    let targets: Vec<&str> = report.changes.iter().map(|c| c.target.as_str()).collect();
    assert_eq!(targets, ["~/.c", "~/.a", "~/.b"]);
}

#[test]
fn a_file_body_is_read_from_the_config_repo_verbatim() {
    let home = guarded_home();
    home.write(".config/bx/files/gitconfig", "[user]\n\tname = ~/x\n");
    let inputs = inputs(
        &home,
        "[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/gitconfig\"\n",
    );

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Create]);
    assert!(text(&report.changes[0]).ends_with("+[user]\n+\tname = ~/x\n"));

    apply(&inputs);
    assert_eq!(
        std::fs::read(home.child(".gitconfig")).expect("written"),
        b"[user]\n\tname = ~/x\n"
    );
}

#[test]
fn a_missing_file_body_is_an_error_naming_its_origin() {
    let home = guarded_home();
    let inputs = inputs(
        &home,
        "[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/absent\"\n",
    );

    let error = run(&inputs, Mode::Plan, &mut |_| Ok(false)).expect_err("a missing body");

    assert!(matches!(error, Error::Body { .. }), "{error:?}");
    assert!(error.to_string().contains("bx.toml:1"), "{error}");
}

/// A secret target for `~/.token`, its ciphertext at `secrets/token.age`.
pub(super) const SECRET_TARGET: &str =
    "[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n";

/// Encrypt `plaintext` to `recipient` as the repo's `secrets/token.age`.
pub(super) fn seal(home: &GuardedHome, recipient: &str, plaintext: &[u8]) {
    let path = home.child(".config/bx/secrets/token.age");
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("secrets/");
    std::fs::write(path, crate::secret::tests::encrypt_to(recipient, plaintext))
        .expect("the ciphertext");
}

/// A fresh age identity, written where `local.toml` names it.
pub(super) fn age_identity(home: &GuardedHome) -> String {
    let key = age::x25519::Identity::generate();
    home.write(
        ".config/age/key.txt",
        age::secrecy::ExposeSecret::expose_secret(&key.to_string()),
    );
    home.write(
        ".local/state/bx/local.toml",
        "[secrets]\nidentity = \"~/.config/age/key.txt\"\n",
    );
    key.to_public().to_string()
}

#[test]
fn t9_apply_twice_converges_and_changes_nothing_the_second_time() {
    let home = guarded_home();
    own(home.path(), ".owned", b"v1\n", Mechanism::Own);
    let layer = [
        inline("~/.config/new/deep.conf", "deep\\n"),
        inline("~/.owned", "v2\\n"),
        "[[target]]\npath = \"~/.private\"\ncontent = \"secret\\n\"\nmode = \"0600\"\n".to_string(),
    ]
    .concat();
    let inputs = inputs(&home, &layer);

    let first = apply(&inputs);
    assert!(first.executed);
    assert_eq!(
        first.actions(),
        vec![Action::Create, Action::Modify, Action::Create]
    );
    assert_eq!(exit(&first, Mode::Apply), Exit::Converged);

    let after = plan(&inputs);
    assert_eq!(after.actions(), vec![Action::Unchanged; 3]);
    assert_eq!(exit(&after, Mode::Plan), Exit::Converged);

    let written = snapshot(home.path(), &[]);
    let second =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("the second apply");
    assert!(!second.executed);
    assert_eq!(exit(&second, Mode::Apply), Exit::Converged);
    assert_eq!(
        snapshot(home.path(), &[".local/state/bx/lock"]),
        written
            .into_iter()
            .filter(|(path, _, _)| !path.starts_with(".local/state/bx/lock"))
            .collect::<Vec<_>>()
    );
    assert!(!StateDir::resolve(home.path()).journal().exists());
    assert_eq!(
        std::fs::metadata(home.child(".private"))
            .expect("private")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn t10_apply_announces_exactly_what_plan_announced_and_plan_changes_nothing() {
    let guard = guarded_home();
    let layer = [
        inline("~/.owned", "v2\\n"),
        inline("~/.new", "new\\n"),
        inline("~/.mine", "bx\\n"),
    ]
    .concat();
    let seeded = |name: &str| {
        let home = guard.child(name);
        std::fs::create_dir_all(&home).expect("a home");
        own(&home, ".owned", b"v1\n", Mechanism::Own);
        std::fs::write(home.join(".mine"), "mine\n").expect("mine");
        seed(&home, &layer);
        home
    };
    let planned_home = seeded("plan");
    let applied_home = seeded("apply");

    let before = snapshot(&planned_home, &[]);
    let planned = plan(&load(&planned_home));
    assert_eq!(
        snapshot(&planned_home, &[]),
        before,
        "plan changed the tree"
    );

    let mut shown = None;
    let applied = run(&load(&applied_home), Mode::Apply, &mut |report| {
        shown = Some(report.clone());
        Ok(true)
    })
    .expect("apply");
    let rows = |report: &Report| {
        report
            .changes
            .iter()
            .map(|c| (c.target.clone(), c.action, c.diff.clone(), c.note.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(rows(&applied), rows(&planned));
    assert_eq!(rows(&shown.expect("apply asked")), rows(&planned));
}

#[test]
fn t11_a_mode_only_drift_is_a_journalled_modify_that_converges() {
    let home = guarded_home();
    own(home.path(), ".a", b"same\n", Mechanism::Own);
    let inputs = inputs(
        &home,
        "[[target]]\npath = \"~/.a\"\ncontent = \"same\\n\"\nmode = \"0600\"\n",
    );

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Modify]);
    // The comparison's own note leads; a parent wider than 0600 — the
    // tempdir home — adds its own after it.
    assert!(
        report.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.starts_with("mode 0644 -> 0600")),
        "{:?}",
        report.changes[0].note
    );
    assert_eq!(
        report.changes[0].diff,
        Some(Diff {
            kind: DiffKind::Mode {
                from: FileMode::DEFAULT_FILE,
                to: FileMode::PRIVATE_FILE
            }
        })
    );

    assert!(apply(&inputs).executed);
    let meta = std::fs::metadata(home.child(".a")).expect("the file");
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    assert_eq!(std::fs::read(home.child(".a")).expect("bytes"), b"same\n");
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn decision_22_a_mode_the_user_changed_on_a_file_bx_owns_is_a_conflict() {
    // Ownership that compares the digest only re-widens a user's chmod
    // narrowing a file bx owns.
    let home = guarded_home();
    own(home.path(), ".a", b"token\n", Mechanism::Own);
    std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
        .expect("the user's chmod");
    let inputs = inputs(&home, &inline("~/.a", "token\\n"));

    let report = plan(&inputs);

    assert_eq!(report.actions(), vec![Action::Conflict]);
    assert!(
        report.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.starts_with("its mode changed since bx wrote it")),
        "{:?}",
        report.changes[0].note
    );
    let applied = apply(&inputs);
    assert!(!applied.executed, "nothing is written over the user's mode");
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("the file")
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode(&home.child(".a")), 0o600);

    // Declaring the mode the user chose is converged, not a conflict.
    let declared = inputs_for_mode(&home, "0600");
    assert_eq!(plan(&declared).actions(), vec![Action::Unchanged]);
}

/// `~/.a` holding `token\n` at the declared `mode`.
fn inputs_for_mode(home: &GuardedHome, mode: &str) -> Inputs {
    inputs(
        home,
        &format!("[[target]]\npath = \"~/.a\"\ncontent = \"token\\n\"\nmode = \"{mode}\"\n"),
    )
}

#[test]
fn decision_23_a_create_names_every_directory_apply_creates_with_its_mode() {
    // `apply` creates a target's missing parents, so a row must say so, or
    // plan would not announce every write apply makes.
    let home = guarded_home();
    let inputs = inputs(
        &home,
        &[
            inline("~/.config/made/deep/new.conf", "x\\n"),
            inline("~/.b", "b\\n"),
        ]
        .concat(),
    );

    let report = plan(&inputs);

    assert_eq!(report.actions(), vec![Action::Create, Action::Create]);
    assert_eq!(
        report.changes[0].note.as_deref(),
        Some("creates ~/.config/made 0755, ~/.config/made/deep 0755")
    );
    assert_eq!(report.changes[1].note, None, "the home is already there");
    assert!(
        !home.child(".config/made").exists(),
        "plan created a parent"
    );

    assert!(apply(&inputs).executed);
    for dir in [".config/made", ".config/made/deep"] {
        let meta = std::fs::symlink_metadata(home.child(dir)).expect("created");
        assert!(meta.is_dir(), "{dir}");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o755, "{dir}");
    }
}

#[test]
fn t12_everything_apply_writes_is_reversed_exactly_by_restore() {
    let home = guarded_home();
    home.write("mine.txt", "user\n");
    let layer = [
        inline("~/.config/deep/er/new.conf", "new\\n"),
        inline("~/.b", "b\\n"),
        inline("~/.owned", "v2\\n"),
    ]
    .concat();
    seed(home.path(), &layer);
    let before = snapshot(home.path(), &OUTSIDE);
    own(home.path(), ".owned", b"v1\n", Mechanism::Own);
    let inputs = load(home.path());

    let applied = apply(&inputs);
    assert_eq!(
        applied.actions(),
        vec![Action::Create, Action::Create, Action::Modify]
    );
    assert_ne!(snapshot(home.path(), &OUTSIDE), before);

    let state = StateDir::resolve(home.path());
    let targets = ledger_targets(&state, home.path());
    assert_eq!(targets.len(), 3);
    crate::restore::restore(&state, home.path(), &targets).expect("restore");

    assert_eq!(snapshot(home.path(), &OUTSIDE), before);
}

/// One symlink target, as TOML.
pub(super) fn symlink(path: &str, text: &str) -> String {
    format!("[[target]]\npath = \"{path}\"\nsymlink = \"{text}\"\n")
}

/// The two sides of a row's link diff.
pub(super) fn link(change: &Change) -> (Option<&str>, Option<&str>) {
    match change.diff.as_ref().map(|diff| &diff.kind) {
        Some(DiffKind::Link { from, to }) => (from.as_deref(), to.as_deref()),
        other => panic!("expected a link diff, found {other:?}"),
    }
}

/// The text of the link at `path`.
pub(super) fn text_of(path: &Path) -> PathBuf {
    std::fs::read_link(path).expect("a link")
}

/// The home the crash child applies in. Passed per command.
const CRASH_HOME: &str = "BX_PLAN_CRASH_HOME";

/// Two writes: a create under a directory bx must invent, then a modify of
/// a file bx owns.
pub(super) fn seed_crash(home: &Path) {
    std::fs::create_dir_all(home).expect("the crash home");
    own(home, ".owned", b"before\n", Mechanism::Own);
    seed(
        home,
        &[
            inline("~/.config/made/new.conf", "made\\n"),
            inline("~/.owned", "after\\n"),
        ]
        .concat(),
    );
}

/// How many writes [`seed_crash`]'s apply makes.
pub(super) const CRASH_WRITES: usize = 2;

/// Re-run this test binary as an apply that aborts at `phase` of write
/// `index`.
pub(super) fn spawn_crash_child(home: &Path, index: usize, phase: &str) -> Output {
    crate::testing::ignored_child("plan::tests::apply_crash_child")
        .env("BX_CRASH_AT", format!("{index}:{phase}"))
        .env(CRASH_HOME, home)
        // The child aborts, so it writes no profile; removing the pattern
        // keeps that independent of how coverage is configured.
        .env_remove("LLVM_PROFILE_FILE")
        .output()
        .expect("spawn the crash child")
}

#[test]
#[ignore = "spawned by the crash harness; it aborts on purpose"]
fn apply_crash_child() {
    let Some(home) = std::env::var_os(CRASH_HOME) else {
        return;
    };
    let inputs = load(Path::new(&home));
    run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("the apply");
}

#[test]
fn t13_an_apply_killed_at_any_journal_phase_recovers_to_the_clean_apply() {
    let guard = guarded_home();
    let clean = guard.child("clean");
    seed_crash(&clean);
    assert!(apply(&load(&clean)).executed);
    let want = snapshot(&clean, &OUTSIDE);

    let boundaries = (0..CRASH_WRITES)
        .flat_map(|index| crash_phases().map(move |phase| (index, phase)))
        .chain(finish_crash_phases().map(|phase| (CRASH_WRITES, phase)));
    let mut crossed = 0;
    for (index, phase) in boundaries {
        let at = format!("{index}:{phase}");
        let home = guard.child(format!("crash-{index}-{phase}"));
        seed_crash(&home);
        let output = spawn_crash_child(&home, index, phase);
        assert!(
            !output.status.success(),
            "{at}: the child did not stop: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let inputs = load(&home);
        let found = plan(&inputs);
        assert!(
            found.interrupted.is_some(),
            "{at}: no interruption reported"
        );
        assert_eq!(exit(&found, Mode::Plan), Exit::Pending, "{at}");

        // Decision 18: the first apply only recovers, and stops there.
        let recovering =
            run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("the recovering apply");
        assert!(
            recovering.recovered.is_some(),
            "{at}: nothing was recovered"
        );
        assert!(
            !recovering.executed,
            "{at}: the recovering apply also applied"
        );
        assert_eq!(exit(&recovering, Mode::Apply), Exit::Pending, "{at}");
        // The next apply decides against the recovered disk.
        run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("the apply after recovery");
        // Nothing may differ, and no `.bx-` temporary is left: the Intent
        // names a write's temporary file before the stage makes it, so
        // recovery removes it wherever the crash landed (#119).
        assert_eq!(snapshot(&home, &OUTSIDE), want, "{at}");

        let after = plan(&inputs);
        assert_eq!(after.interrupted, None, "{at}");
        assert_eq!(after.actions(), vec![Action::Unchanged; 2], "{at}");
        assert!(!StateDir::resolve(&home).journal().exists(), "{at}");
        crossed += 1;
    }
    assert_eq!(crossed, CRASH_WRITES * 6 + 2);
}

#[test]
fn decision_34_a_declined_apply_over_a_finished_session_reports_pending_like_plan() {
    // End to end, alongside decision_18's A2. A session whose
    // writes all landed but whose ledger save did not: the journal is
    // sealed with an End frame, so `pending` reports it complete and every
    // row is Unchanged — recording a write touches no file.
    //
    // At 5d1bba7 `bx plan` exited 2 and a DECLINED `bx apply` over the same
    // state exited 0, with the journal still standing: answering "no" on a
    // terminal reported the machine converged, and a driver keying on exit
    // 0 moved on.
    let guard = guarded_home();
    let home = guard.child("home");
    seed_crash(&home);
    let after_end = finish_crash_phases()[0];
    assert!(
        !spawn_crash_child(&home, CRASH_WRITES, after_end)
            .status
            .success()
    );
    let inputs = load(&home);

    let planned = plan(&inputs);
    let interrupted = planned.interrupted.as_ref().expect("an interruption");
    assert!(
        interrupted.complete,
        "the fixture is not a finished session"
    );
    assert_eq!(planned.actions(), vec![Action::Unchanged; CRASH_WRITES]);
    assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);

    let mut asked = 0;
    let declined = run(&inputs, Mode::Apply, &mut |_| {
        asked += 1;
        Ok(false)
    })
    .expect("a declined apply");

    assert_eq!(asked, 1, "the decline was never offered");
    assert!(!declined.executed);
    assert!(
        declined.recovered.is_none(),
        "a decline recovered something"
    );
    assert_eq!(declined.actions(), vec![Action::Unchanged; CRASH_WRITES]);
    assert!(
        StateDir::resolve(&home).journal().exists(),
        "the journal went on a declined apply"
    );
    assert_eq!(
        exit(&declined, Mode::Apply),
        Exit::Pending,
        "a declined apply reported converged over a standing journal"
    );
    assert_eq!(exit(&declined, Mode::Apply), exit(&planned, Mode::Plan));
}

#[test]
fn a_declined_apply_writes_nothing_and_opens_no_session() {
    let home = guarded_home();
    let inputs = inputs(&home, &inline("~/.a", "x\\n"));
    let mut asked = 0;

    let report = run(&inputs, Mode::Apply, &mut |report| {
        asked += 1;
        assert_eq!(report.actions(), vec![Action::Create]);
        Ok(false)
    })
    .expect("a declined apply");

    assert_eq!(asked, 1);
    assert!(!report.executed);
    assert_eq!(exit(&report, Mode::Apply), Exit::Pending);
    assert!(!home.child(".a").exists());
    assert!(!StateDir::resolve(home.path()).journal().exists());
}

#[test]
fn an_approval_that_fails_stops_the_run() {
    let home = guarded_home();
    let inputs = inputs(&home, &inline("~/.a", "x\\n"));

    let error = run(&inputs, Mode::Apply, &mut |_| {
        Err(Error::RepoMissing(PathBuf::from("/refused")))
    })
    .expect_err("the approval's error");

    assert!(matches!(error, Error::RepoMissing(_)), "{error:?}");
    assert!(!home.child(".a").exists());
}

#[test]
fn a_destination_changed_after_it_was_decided_is_not_replaced_and_is_rolled_back() {
    let home = guarded_home();
    let inputs = inputs(
        &home,
        &[inline("~/.b", "b\\n"), inline("~/.a", "bx\\n")].concat(),
    );
    let target = home.child(".a");

    let error = run(&inputs, Mode::Apply, &mut |_| {
        std::fs::write(&target, "raced\n").expect("the race");
        Ok(true)
    })
    .expect_err("the changed destination");

    assert!(
        matches!(
            error,
            Error::Journal(journal::Error::Write(crate::fs::Error::Changed { .. }))
        ),
        "{error:?}"
    );
    assert_eq!(std::fs::read(&target).expect("kept"), b"raced\n");
    assert!(StateDir::resolve(home.path()).journal().exists());

    // The next writing run only rolls the first write back (decision 18),
    // and the one after it decides.
    let recovering = apply(&inputs);
    assert!(recovering.recovered.is_some(), "{recovering:?}");
    assert!(!recovering.executed);
    assert!(!StateDir::resolve(home.path()).journal().exists());
    let next = apply(&inputs);
    assert_eq!(next.actions(), vec![Action::Create, Action::Conflict]);
}

fn report_of(actions: &[Action]) -> Report {
    Report {
        changes: actions
            .iter()
            .map(|&action| Change {
                target: "~/.a".to_string(),
                origin: Origin::unknown(Path::new("/repo/bx.toml")),
                action,
                diff: None,
                note: None,
            })
            .collect(),
        ..Report::default()
    }
}

#[test]
fn t20_exit_follows_the_mode_and_whether_apply_wrote() {
    use Action::{Blocked, Conflict, Create, Unchanged};

    assert_eq!(exit(&report_of(&[]), Mode::Plan), Exit::Converged);
    assert_eq!(exit(&report_of(&[Unchanged]), Mode::Plan), Exit::Converged);
    assert_eq!(exit(&report_of(&[Create]), Mode::Plan), Exit::Pending);

    // The table used to ask the interrupted report
    // under Mode::Plan only, and the unasked Mode::Apply cell was the wrong
    // one: a declined apply over a session that wrote everything but did
    // not record it has nothing but Unchanged rows, so it fell through to
    // them and reported the machine converged with the journal standing.
    // Decision 34 makes the answer mode-independent, so both cells are
    // asked, and `complete` — which is what makes every row Unchanged — is
    // varied rather than fixed.
    for complete in [false, true] {
        let mut interrupted = report_of(&[Unchanged]);
        interrupted.interrupted = Some(Interrupted {
            kind: SessionKind::Apply,
            journal: PathBuf::from("/state/journal"),
            complete,
            unreadable: !complete,
            unfinished: Vec::new(),
        });
        assert_eq!(exit(&interrupted, Mode::Plan), Exit::Pending, "{complete}");
        assert_eq!(exit(&interrupted, Mode::Apply), Exit::Pending, "{complete}");

        // An apply that recovered stopped there: the configured targets are
        // still undecided, so it is the same answer and not a second arm.
        let mut recovered = interrupted.clone();
        recovered.recovered = Some(recover::Outcome::Recorded { entries: 1 });
        assert_eq!(exit(&recovered, Mode::Apply), Exit::Pending, "{complete}");
    }

    // A run against another apply's held state directory decides its rows
    // against a directory that apply is concurrently changing.
    // Mode::Apply never reaches here — `run` refuses first — and a plan
    // that does must not contradict its own banner by reporting converged.
    let mut running = report_of(&[Unchanged]);
    running.apply_running = true;
    assert_eq!(exit(&running, Mode::Plan), Exit::Pending);

    let mut executed = report_of(&[Create, Unchanged]);
    executed.executed = true;
    assert_eq!(exit(&executed, Mode::Apply), Exit::Converged);
    let mut attention = report_of(&[Create, Blocked]);
    attention.executed = true;
    assert_eq!(exit(&attention, Mode::Apply), Exit::Pending);
    let mut conflict = report_of(&[Conflict]);
    conflict.executed = true;
    assert_eq!(exit(&conflict, Mode::Apply), Exit::Pending);

    assert_eq!(exit(&report_of(&[Create]), Mode::Apply), Exit::Pending);
    assert_eq!(exit(&report_of(&[Unchanged]), Mode::Apply), Exit::Converged);

    // A carry is not a bare apply's work, but it is sync's: one a sync
    // did not write is left undone.
    let carry = report_of(&[Action::Sync, Unchanged]);
    assert_eq!(exit(&carry, Mode::Plan), Exit::Converged);
    assert_eq!(exit(&carry, Mode::Apply), Exit::Converged);
    assert_eq!(exit(&carry, Mode::Sync), Exit::Pending);
    let mut carried = carry;
    carried.executed = true;
    assert_eq!(exit(&carried, Mode::Sync), Exit::Converged);
}

mod secrets;
mod state_paths;
mod tools;
/// Track mode: the machine's copy leads, and the repo's follows.
mod track;

mod undeclared;
