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
fn d1_a_secret_is_decrypted_into_a_private_file_and_never_shown() {
    let home = guarded_home();
    let recipient = age_identity(&home);
    seal(&home, &recipient, b"hunter2\n");
    let inputs = inputs(&home, SECRET_TARGET);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Create]);
    let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
    assert!(
        !shown.contains("hunter2"),
        "the plaintext was shown: {shown}"
    );
    assert!(
        shown.contains("secret, not shown: no file -> 8 bytes"),
        "{shown}"
    );

    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(
        std::fs::read(home.child(".token")).expect("written"),
        b"hunter2\n"
    );
    assert_eq!(mode_of(&home.child(".token")), 0o600);
}

#[test]
fn d1_applying_an_unchanged_secret_twice_writes_nothing_the_second_time() {
    let home = guarded_home();
    let recipient = age_identity(&home);
    seal(&home, &recipient, b"hunter2\n");
    let inputs = inputs(&home, SECRET_TARGET);
    apply(&inputs);

    let after = plan(&inputs);
    assert_eq!(after.actions(), vec![Action::Unchanged]);
    let written = snapshot(home.path(), &[".local/state/bx/lock"]);
    let second =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("the second apply");
    assert!(!second.executed);
    assert_eq!(second.actions(), vec![Action::Unchanged]);
    assert_eq!(snapshot(home.path(), &[".local/state/bx/lock"]), written);

    // A new ciphertext is a modify, and still never shown.
    seal(&home, &recipient, b"hunter3\n");
    let changed = plan(&inputs);
    assert_eq!(changed.actions(), vec![Action::Modify]);
    let shown = render(&changed, View::Plan, Palette::PLAIN, home.path());
    assert!(!shown.contains("hunter"), "{shown}");
    assert!(
        shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
        "{shown}"
    );
}

#[test]
fn d1_a_locked_identity_blocks_its_secret_and_nothing_asks() {
    let home = guarded_home();
    // The default identity, locked: plan and apply may not ask for it.
    home.write(".ssh/id_ed25519", crate::secret::tests::LOCKED_SSH_KEY);
    seal(&home, crate::secret::tests::LOCKED_SSH_PUB, b"x\n");
    let layer = [SECRET_TARGET, &inline("~/.a", "a\\n")].concat();
    let inputs = inputs(&home, &layer);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Blocked, Action::Create]);
    let note = planned.changes[0].note.as_deref().expect("a note");
    assert!(
        note.contains("~/.ssh/id_ed25519 is locked by a passphrase"),
        "{note}"
    );
    assert!(
        note.contains("`identity` under [secrets] in local.toml"),
        "names the fix"
    );
    assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);

    let applied = apply(&inputs);
    assert!(applied.executed, "the rest of the plan stands");
    assert!(!home.child(".token").exists());
    assert!(home.child(".a").exists());
}

#[test]
fn d1_a_secret_no_identity_opens_is_blocked_naming_why() {
    let home = guarded_home();
    seal(&home, crate::secret::tests::SSH_PUB, b"x\n");
    let inputs = inputs(&home, SECRET_TARGET);

    let none = plan(&inputs);
    assert_eq!(none.actions(), vec![Action::Blocked]);
    assert!(
        none.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("no identity at ~/.ssh/id_ed25519")),
        "{:?}",
        none.changes[0].note
    );

    age_identity(&home);
    let inputs = load(home.path());
    let wrong = plan(&inputs);
    assert_eq!(wrong.actions(), vec![Action::Blocked]);
    assert!(
        wrong.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("~/.config/age/key.txt is not one")),
        "{:?}",
        wrong.changes[0].note
    );
}

#[test]
fn d1_a_missing_ciphertext_is_an_error_naming_its_origin() {
    let home = guarded_home();
    let inputs = inputs(&home, SECRET_TARGET);

    let error = run(&inputs, Mode::Plan, &mut |_| Ok(false)).expect_err("no ciphertext");
    assert!(matches!(error, Error::Body { .. }), "{error:?}");
    assert!(error.to_string().contains("token.age"), "{error}");
}

#[test]
fn d1_a_secret_over_a_file_bx_does_not_own_is_a_conflict_shown_by_size_only() {
    let home = guarded_home();
    home.write(".token", "mine\n");
    let recipient = age_identity(&home);
    seal(&home, &recipient, b"hunter2\n");
    let inputs = inputs(&home, SECRET_TARGET);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
    assert!(
        !shown.contains("mine") && !shown.contains("hunter2"),
        "{shown}"
    );
    assert!(
        shown.contains("secret, not shown: 5 bytes -> 8 bytes"),
        "{shown}"
    );
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
    // P42R1-D7. A user's chmod narrowing a file bx owns was re-widened:
    // ownership compared the digest only.
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
    // P42R1-D8. `apply` creates a target's missing parents, and no row
    // said so, so plan did not announce every write apply made.
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

/// A stub tool at `~/bin/stub` that appends a line to `~/runs` each time
/// it runs and prints a one-line activation, and the machine that finds
/// it: `~/bin` is its whole `PATH`.
fn stub_tool(home: &GuardedHome) -> activation::System {
    let bin = home.child("bin");
    std::fs::create_dir_all(&bin).expect("~/bin");
    let stub = bin.join("stub");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\necho ran >> '{}'\nprintf 'stub_hook() {{ :; }}\\n'\n",
            home.child("runs").display()
        ),
    )
    .expect("the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("executable");
    // Another test thread that forks while the stub is open for writing
    // holds that descriptor until its child calls `exec`, and running the
    // stub inside that window fails with `ETXTBSY`. The window closes on
    // its own, so the stub is run once here, retrying only that error,
    // and the record of that run dropped, before any code under test runs
    // it.
    let mut warmed = false;
    for _ in 0..200 {
        match std::process::Command::new(&stub).output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => panic!("the stub would not run: {e}"),
            Ok(_) => {
                warmed = true;
                break;
            }
        }
    }
    assert!(warmed, "the stub stayed busy");
    std::fs::remove_file(home.child("runs")).expect("the warm-up's record");
    activation::System::new(bin.into_os_string(), activation::TIMEOUT)
}

/// How many times the stub tool has run.
fn stub_runs(home: &GuardedHome) -> usize {
    std::fs::read_to_string(home.child("runs")).map_or(0, |runs| runs.lines().count())
}

const STUB: &str = "[[activation]]\nname = \"stub\"\ncommand = [\"stub\", \"init\", \"zsh\"]\n\
                        phase = \"completions\"\n";

const INTERACTIVE: &str = ".local/share/bx/zshrc.zsh";

#[test]
fn a_declared_activation_is_run_once_cached_rendered_and_reversed() {
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    seed(home.path(), STUB);
    let inputs = load(home.path()).with_host(stub_tool(&home));
    let state = StateDir::resolve(home.path());

    // `plan` runs it twice, shows the capture, and writes nothing.
    let planned = plan(&inputs);
    assert_eq!(stub_runs(&home), 2);
    assert_eq!(
        planned.actions(),
        vec![Action::Create, Action::Modify, Action::Create]
    );
    assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);
    let shown = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        shown.contains("  + activation `stub`: run twice, output agreed; cached\n"),
        "{shown}"
    );
    assert!(!state.fingerprints().exists());

    // `apply` renders the output into the interactive file and records it.
    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(stub_runs(&home), 4, "one plan inside the apply, not two");
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
    assert!(
        file.contains(
            "\n# bx phase: completions\n# bx activation: stub\neval 'stub_hook() { :; }\n'\n"
        ),
        "{file}"
    );
    let cache = std::fs::read(state.fingerprints()).expect("the cache is saved");

    // On an unchanged machine nothing runs and nothing is written.
    let again = plan(&inputs);
    assert_eq!(stub_runs(&home), 4);
    assert_eq!(again.actions(), vec![Action::Unchanged; 3]);
    assert_eq!(exit(&again, Mode::Plan), Exit::Converged);
    let quiet = render(
        &again,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(!quiet.contains("activation"), "{quiet}");
    let status = render(
        &again,
        View::Status,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        status.contains("  = activation `stub`: cached output reused, nothing run\n"),
        "{status}"
    );
    let second =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("the second apply");
    assert!(!second.executed);
    assert_eq!(stub_runs(&home), 4);
    assert_eq!(
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
        file
    );
    assert_eq!(
        std::fs::read(state.fingerprints()).expect("the cache"),
        cache
    );

    // Losing the cache costs a re-run, and nothing else: the file is
    // already right, and the cache comes back byte for byte.
    std::fs::remove_file(state.fingerprints()).expect("lose the cache");
    let lost = apply(&inputs);
    assert!(lost.executed);
    assert_eq!(
        lost.actions(),
        vec![Action::Unchanged, Action::Unchanged, Action::Create]
    );
    assert_eq!(stub_runs(&home), 6);
    assert_eq!(
        std::fs::read(state.fingerprints()).expect("the cache"),
        cache
    );
    assert_eq!(
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
        file
    );

    // `rm` puts back exactly what was there before.
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("restore");
    assert_eq!(
        std::fs::read_to_string(home.child(".zshrc")).expect(".zshrc"),
        "user\n"
    );
    assert!(!home.child(INTERACTIVE).exists());
}

#[test]
fn each_shell_s_command_is_cached_and_rendered_in_its_own_file_and_reversed() {
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    home.write(".bashrc", "mine\n");
    seed(
        home.path(),
        "[[activation]]\nname = \"stub\"\ncommand = [\"stub\", \"init\", \"{shell}\"]\n\
             phase = \"completions\"\n\
             [[activation]]\nname = \"zonly\"\ncommand = [\"stub\", \"zsh\"]\n",
    );
    let inputs = load(home.path()).with_host(stub_tool(&home));
    let state = StateDir::resolve(home.path());

    // Three commands — `stub` for each shell, `zonly` for zsh alone —
    // each run twice.
    let planned = plan(&inputs);
    assert_eq!(stub_runs(&home), 6);
    let shown = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        shown.contains("  + activation `stub`: run twice, output agreed; cached\n")
            && shown.contains("  + activation `stub` for bash: run twice, output agreed; cached\n")
            && shown.contains("  + activation `zonly`: run twice, output agreed; cached\n")
            && !shown.contains("`zonly` for bash"),
        "{shown}"
    );
    // bash's row says why `zonly` is not in its file.
    let bash_row = planned
        .changes
        .iter()
        .find(|change| change.target == crate::shell::bash::FILE)
        .expect("bash's file");
    let note = bash_row.note.as_deref().expect("a note");
    assert!(
        note.ends_with("activation `zonly` declares no bash command, so it is not run for bash"),
        "{note}"
    );

    let applied = apply(&inputs);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    assert_eq!(stub_runs(&home), 12, "one plan inside the apply");
    let bash =
        std::fs::read_to_string(home.child(".local/share/bx/bashrc.bash")).expect("bash's file");
    assert_eq!(
        bash,
        "# Generated by bx. Edit the config repo, not this file.\n\
             \n# bx phase: completions\n# bx activation: stub\neval 'stub_hook() { :; }\n'\n\
             \n# bx: done, whichever plugins were found\ntrue\n"
    );
    let zsh = std::fs::read_to_string(home.child(INTERACTIVE)).expect("zsh's file");
    assert!(zsh.contains("# bx activation: stub\n"), "{zsh}");
    assert!(zsh.contains("# bx activation: zonly\n"), "{zsh}");

    // Idempotent: nothing runs, nothing is written.
    let again = plan(&inputs);
    assert_eq!(stub_runs(&home), 12);
    assert!(
        again.actions().iter().all(|a| *a == Action::Unchanged),
        "{:?}",
        again.actions()
    );

    // `rm` restores the user's `~/.bashrc` exactly.
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("restore");
    assert_eq!(
        std::fs::read_to_string(home.child(".bashrc")).expect(".bashrc"),
        "mine\n"
    );
    assert!(!home.child(".local/share/bx/bashrc.bash").exists());
}

#[test]
fn a_capture_under_another_path_renders_the_same_file() {
    // D1: a tool that prints the PATH it ran with, as `mise activate`
    // does. Re-captured under a different PATH, the file does not change.
    let home = guarded_home();
    let bin = home.child("bin");
    std::fs::create_dir_all(&bin).expect("~/bin");
    let stub = bin.join("stub");
    std::fs::write(
        &stub,
        "#!/bin/sh\nprintf \"export PATH='/opt/stub/bin:%s'\\n\" \"$PATH\"\n",
    )
    .expect("the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("executable");
    seed(home.path(), STUB);
    let state = StateDir::resolve(home.path());
    let under = |path: String| {
        load(home.path()).with_host(activation::System::new(path, activation::TIMEOUT))
    };

    let applied = apply(&under(bin.display().to_string()));
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
    assert!(
        file.contains("eval 'export PATH='\\''/opt/stub/bin:'\\''\"$PATH\"\n'\n"),
        "{file}"
    );

    std::fs::remove_file(state.fingerprints()).expect("lose the cache");
    let elsewhere = under(format!("{}:/nonexistent", bin.display()));
    let planned = plan(&elsewhere);
    assert_eq!(
        planned.actions(),
        vec![Action::Unchanged, Action::Unchanged, Action::Create]
    );
    apply(&elsewhere);
    assert_eq!(
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
        file
    );
}

#[test]
fn a_has_condition_looks_its_tool_up_on_the_host_the_inputs_were_loaded_with() {
    // The lookup used to read the process's own `PATH`, which
    // `Inputs::load` never took and no test controls. A tool only the
    // host's `PATH` holds is found, and one it does not hold is not.
    let home = guarded_home();
    seed(
        home.path(),
        "[[alias]]\nname = \"s\"\ncommand = \"stub\"\nwhen = \"has:stub\"\n",
    );
    let written = |host| {
        apply(&load(home.path()).with_host(host));
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file")
    };

    let without = written(activation::System::new("", activation::TIMEOUT));
    assert!(!without.contains("alias s="), "{without}");
    let with = written(stub_tool(&home));
    assert!(with.contains("alias s='stub'\n"), "{with}");
}

#[test]
fn on_macos_a_planned_bash_file_declares_the_bash_profile_region_too() {
    use crate::shell::bash::{FILE, PROFILE, STARTUP_FILE};
    let declared = |platform| {
        // bash's file planned and nothing else: as it is once nothing
        // places it and only the vacated file is left.
        let mut declared = BTreeSet::from([FILE]);
        declare_sourcing(&mut declared, platform);
        declared
    };
    assert_eq!(
        declared(Platform::Macos),
        BTreeSet::from([FILE, STARTUP_FILE, PROFILE])
    );
    assert_eq!(
        declared(Platform::Linux),
        BTreeSet::from([FILE, STARTUP_FILE])
    );
    // Nothing planned declares no startup file on either platform.
    for platform in [Platform::Linux, Platform::Macos] {
        let mut none = BTreeSet::new();
        declare_sourcing(&mut none, platform);
        assert!(none.is_empty(), "{platform:?}");
    }
}

#[test]
fn a_condition_on_the_machine_is_decided_by_the_facts_the_inputs_carry() {
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    home.write(".bashrc", "mine\n");
    seed(
        home.path(),
        "[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n\
             when = \"host:box\"\n\
             [[alias]]\nname = \"mac\"\ncommand = \"m\"\nwhen = [\"os:macos\", \"arch:aarch64\"]\n\
             [[alias]]\nname = \"lin\"\ncommand = \"l\"\nwhen = [\"os:linux\", \"ssh\"]\n\
             [[source]]\nname = \"boxed\"\npath = \"~/.boxed.sh\"\nwhen = \"host:box\"\n\
             [[function]]\nname = \"hi\"\nbody = \"print hi\"\nhook = \"precmd\"\n\
             when = [\"user:me\", \"distro:rhel\"]\nshells = [\"zsh\"]\n",
    );
    // The machine's facts are whatever the host the inputs carry says,
    // never this process's own.
    let on = |host: &str| {
        let machine = Machine {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            host: Some(host.to_string()),
            user: Some("me".to_string()),
            distro: Some(Distro {
                id: "fedora".to_string(),
                id_like: vec!["rhel".to_string()],
            }),
        };
        load(home.path())
            .with_host(activation::System::new("", activation::TIMEOUT).with_machine(machine))
    };
    let files = || {
        [INTERACTIVE, ".local/share/bx/bashrc.bash"]
            .map(|rel| std::fs::read_to_string(home.child(rel)).expect("a generated file"))
    };

    let boxed = on("BOX");
    assert_eq!(exit(&apply(&boxed), Mode::Apply), Exit::Converged);
    let [zsh, bash] = files();
    for file in [&zsh, &bash] {
        assert!(file.contains("export EDITOR=nvim\n"), "{file}");
        assert!(!file.contains("alias mac="), "{file}");
        assert!(
            file.contains("if [[ -n ${SSH_CONNECTION-} ]]; then\n  alias lin='l'\nfi\n"),
            "{file}"
        );
        assert!(file.contains("~/.boxed.sh"), "{file}");
    }
    assert!(zsh.contains("precmd_functions+=(__bx_hook_hi)\n"), "{zsh}");

    // Idempotent: a second plan is empty and the bytes do not move.
    let again = plan(&boxed);
    assert!(
        again.actions().iter().all(|a| *a == Action::Unchanged),
        "{:?}",
        again.actions()
    );
    apply(&boxed);
    assert_eq!(files(), [zsh.clone(), bash.clone()]);

    // A renamed host takes its lines out of both files, and nothing else.
    let renamed = on("other");
    let moved = plan(&renamed);
    let mut changed: Vec<(&str, Action)> = moved
        .changes
        .iter()
        .filter(|change| change.action != Action::Unchanged)
        .map(|change| (change.target.as_str(), change.action))
        .collect();
    changed.sort_unstable();
    assert_eq!(
        changed,
        [
            (crate::shell::bash::FILE, Action::Modify),
            ("~/.local/share/bx/zshrc.zsh", Action::Modify),
        ],
        "{:?}",
        moved.actions()
    );
    apply(&renamed);
    let [zsh_after, bash_after] = files();
    for file in [&zsh_after, &bash_after] {
        assert!(!file.contains("EDITOR"), "{file}");
        assert!(!file.contains("~/.boxed.sh"), "{file}");
        assert!(file.contains("alias lin='l'\n"), "{file}");
    }
    assert!(
        zsh_after.contains("precmd_functions+=(__bx_hook_hi)\n"),
        "{zsh_after}"
    );
}

#[test]
fn an_absent_tool_is_blocked_and_everything_else_is_still_written() {
    let home = guarded_home();
    seed(
        home.path(),
        &format!("{STUB}[[activation]]\nname = \"gone\"\ncommand = [\"gone\"]\n"),
    );
    let inputs = load(home.path()).with_host(stub_tool(&home));

    let planned = plan(&inputs);
    assert_eq!(
        planned.actions(),
        vec![
            Action::Create,
            Action::Create,
            Action::Create,
            Action::Blocked
        ]
    );
    let shown = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        shown.contains("  ? activation `gone`: omitted: `gone` is not on PATH\n"),
        "{shown}"
    );

    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Pending);
    let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
    assert!(file.contains("# bx activation: stub\n"), "{file}");
    assert!(!file.contains("gone"), "{file}");
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
    // P42R2-D4, end to end, alongside decision_18's A2. A session whose
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

/// Make `path` a FIFO. Opening it to read waits for a writer that never
/// comes, which is what any read of it that is not refused first does.
fn fifo_at(path: &Path) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("the FIFO's directory");
    }
    crate::testing::mkfifo(path);
}

/// The text of the error `run` in `mode` stops with, run on a thread so a
/// read that waits fails the test instead of hanging it.
fn refusal(inputs: &Inputs, mode: Mode) -> String {
    let (sent, received) = std::sync::mpsc::channel();
    let inputs = inputs.clone();
    std::thread::spawn(move || {
        let outcome = run(&inputs, mode, &mut |_| Ok(true))
            .map(|report| report.actions())
            .map_err(|error| error.to_string());
        let _ = sent.send(outcome);
    });
    match received.recv_timeout(std::time::Duration::from_secs(20)) {
        Ok(Err(message)) => message,
        Ok(Ok(actions)) => panic!("{mode:?} ran to completion: {actions:?}"),
        Err(_) => panic!("{mode:?} had not returned after 20 s: a read is waiting"),
    }
}

/// Stage an apply that died once its write was published: the journal
/// stands over `new\n`, and rolling it back needs the restore snapshot of
/// `old\n`. This is the state in which `bx plan` reads a fourth state file.
fn a_standing_write_over(home: &GuardedHome) -> Inputs {
    home.write(".conf", "old\n");
    let inputs = inputs(home, &inline("~/.conf", "new\\n"));
    let target = Portable::parse_in("~/.conf", home.path()).expect("a portable target");
    let dest = home.child(".conf");
    let mut session = Session::open(
        inputs.state(),
        SessionKind::Apply,
        home.path(),
        vec![target.clone()],
    )
    .expect("a session");
    session
        .apply(Request {
            target,
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"new\n".to_vec(),
                planned: fs::observe(&dest).expect("observe"),
            },
            mode: FileMode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect("the write");
    drop(session);
    inputs
}

/// Every path under `state`, deepest first, as the filesystem holds them.
///
/// Re-derived from disk on every run rather than written down: the point of
/// [`refuse_irregular_state_files`] after decision 33 is that its scope is
/// whatever is there, so a test that named the files would be the very
/// artefact the decision removed.
fn every_state_path(state: &StateDir) -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                walk(&path, found);
            } else {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(state.root(), &mut found);
    found
}

#[test]
fn decision_33_a_fifo_at_any_file_under_the_state_directory_is_refused_without_waiting() {
    // P42R2-D3 and P42R2-COV3. The guard used to name three files — the
    // ledger, the fingerprints and the journal — and the three tests that
    // exercised it mirrored that same list, so neither could find what the
    // list had missed: `bx plan` also reads <state>/restore/<digest>
    // through `interrupted_rows`, with no file-type check on that path, and
    // a FIFO there made `bx plan` — the read-only command — wait forever.
    //
    // This asks it of every file the state directory actually holds,
    // enumerated from disk at the head it runs against. A reader added
    // later brings its file with it and is covered the day it is written;
    // nobody has to remember to extend a list.
    let home = guarded_home();
    // A finished apply and a saved fingerprint cache first, so a saved
    // ledger and the fingerprints are among the files swept, beside the
    // standing journal's snapshot.
    own(home.path(), ".owned", b"owned\n", Mechanism::Own);
    let state = StateDir::resolve(home.path());
    let lock = ExclusiveLock::try_acquire(&state)
        .expect("try the lock")
        .expect("nothing holds it");
    let mut cache = crate::state::Fingerprints::default();
    cache.set("tracked", crate::state::Fingerprint::raw(b"seen".to_vec()));
    cache.save(&state, &lock).expect("save the fingerprints");
    drop(lock);
    let inputs = a_standing_write_over(&home);

    let paths = every_state_path(inputs.state());
    let blob_dir = inputs.state().restore();
    assert!(
        paths.contains(&inputs.state().ledger()),
        "the fixture holds no ledger: {paths:?}"
    );
    assert!(
        paths.contains(&inputs.state().fingerprints()),
        "the fixture holds no fingerprints: {paths:?}"
    );
    assert!(
        paths.iter().any(|path| path.parent() == Some(&*blob_dir)),
        "the fixture holds no restore snapshot, so the case that hung is untested: {paths:?}"
    );
    assert!(
        paths.contains(&inputs.state().journal()),
        "the fixture holds no journal: {paths:?}"
    );

    for path in paths {
        let kept = std::fs::read(&path).expect("the file's bytes");
        std::fs::remove_file(&path).expect("make way for the FIFO");
        fifo_at(&path);

        // `refusal` runs on a thread with a deadline, so a read that waits
        // fails the test instead of hanging it.
        for mode in [Mode::Plan, Mode::Apply] {
            let message = refusal(&inputs, mode);
            assert!(
                message.contains(&path.display().to_string()),
                "{mode:?} {}: {message}",
                path.display()
            );
            assert!(
                message.contains("not a regular file"),
                "{mode:?} {}: {message}",
                path.display()
            );
        }

        std::fs::remove_file(&path).expect("the FIFO goes");
        std::fs::write(&path, kept).expect("the file comes back");
    }

    // No refused apply wrote past its refusal.
    assert_eq!(
        std::fs::read(home.child(".conf")).expect("untouched"),
        b"new\n"
    );
    // With every file back as it was, the same run reports the
    // interruption rather than a refusal: the sweep left nothing behind.
    assert!(plan(&inputs).interrupted.is_some());
}

#[test]
fn decision_20_a_link_to_a_device_at_the_ledger_is_refused_before_any_read() {
    // Asked of the guard itself, not of `run`: were the guard ever to let
    // it through, the ledger's reader would read `/dev/zero` into memory
    // until the host ran out. The FIFO tests show `run` asks the guard
    // before anything is read.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir_all(state.root()).expect("the state directory");
    std::os::unix::fs::symlink("/dev/zero", state.ledger()).expect("the link");

    let error = refuse_irregular_state_files(&state).expect_err("a link is refused");

    assert!(
        matches!(&error, Error::NotARegularFile { path } if *path == state.ledger()),
        "{error:?}"
    );
    assert!(error.to_string().contains("not a regular file"), "{error}");

    // Absent state files, and regular ones, are read as before.
    let other = guarded_home();
    let fresh = StateDir::resolve(other.path());
    assert!(refuse_irregular_state_files(&fresh).is_ok());
    std::fs::create_dir_all(fresh.root()).expect("the state directory");
    std::fs::write(fresh.ledger(), b"a ledger's bytes").expect("a regular ledger");
    assert!(refuse_irregular_state_files(&fresh).is_ok());
}

#[test]
fn decision_38_a_linked_local_toml_is_the_users_layer_and_plan_and_apply_run() {
    // The walk refused every link under the state root, and the local
    // layer is the one file there the user writes and may link, so any
    // account with a linked `local.toml` could not run `bx` at all.
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let state = StateDir::resolve(home.path());
    std::fs::create_dir_all(state.root()).expect("the state directory");
    std::fs::set_permissions(state.root(), std::fs::Permissions::from_mode(0o700))
        .expect("a private state directory");
    let real = home.write("dotfiles/local.toml", "[values]\n");
    let local = paths::local_layer_path(state.root());
    std::os::unix::fs::symlink(&real, &local).expect("the link");
    let inputs = load(home.path());

    assert!(refuse_irregular_state_files(inputs.state()).is_ok());
    assert_eq!(plan(&inputs).actions(), [Action::Create]);
    assert_eq!(apply(&inputs).actions(), [Action::Create]);
    assert_eq!(plan(&inputs).actions(), [Action::Unchanged]);
    assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");
    assert!(
        std::fs::symlink_metadata(&local).is_ok_and(|meta| meta.file_type().is_symlink()),
        "the user's link is left as it was"
    );

    // Only that one name is exempt: a link anywhere else under the state
    // root is still refused.
    std::os::unix::fs::symlink(&real, state.ledger().with_file_name("other.toml"))
        .expect("a second link");
    assert!(matches!(
        refuse_irregular_state_files(inputs.state()),
        Err(Error::NotARegularFile { .. })
    ));
}

#[test]
fn decision_20_a_fifo_as_a_file_body_is_refused_without_waiting() {
    let home = guarded_home();
    let inputs = inputs(
        &home,
        "[[target]]\npath = \"~/.b\"\nfile = \"files/body\"\n",
    );
    let body = home.child(".config/bx/files/body");
    fifo_at(&body);

    for mode in [Mode::Plan, Mode::Apply] {
        let message = refusal(&inputs, mode);
        assert!(
            message.contains(&body.display().to_string()),
            "{mode:?}: {message}"
        );
        assert!(
            message.contains("not a regular file"),
            "{mode:?}: {message}"
        );
    }
    assert!(!home.child(".b").exists(), "written from a refused body");
}

#[test]
fn t15_apply_refuses_a_held_state_directory_and_plan_reports_it_running() {
    let home = guarded_home();
    let inputs = inputs(&home, &inline("~/.a", "x\\n"));
    let held = ExclusiveLock::acquire(inputs.state()).expect("the lock");

    // P42R2-D5. The refusal comes before anything else the run would do.
    // It used to come from `Session::open`, at the end: every target was
    // decided against a state directory the running apply was concurrently
    // changing, the whole plan was rendered, and the user was asked to
    // confirm work this run was never going to be allowed to do.
    let mut asked = 0;
    let error = run(&inputs, Mode::Apply, &mut |_| {
        asked += 1;
        Ok(true)
    })
    .expect_err("locked");
    assert!(
        matches!(error, Error::State(state::Error::Locked { .. })),
        "{error:?}"
    );
    assert_eq!(asked, 0, "apply prompted before refusing the held lock");

    let report = plan(&inputs);
    assert!(report.apply_running);
    assert_eq!(report.interrupted, None);
    assert_eq!(report.actions(), vec![Action::Create]);
    assert!(!home.child(".a").exists());

    drop(held);
    let report = plan(&inputs);
    assert!(
        !report.apply_running,
        "a released lock is not a running apply"
    );
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

    // P42R2-D4 and P42R2-COV2. The table used to ask the interrupted report
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

    // P42R2-D5. A run against another apply's held state directory decided
    // its rows against a directory that apply is concurrently changing.
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

/// Track mode: the machine's copy leads, and the repo's follows.
mod track;

mod undeclared;
