use super::super::{Inputs, Mode, Report, run};
use super::*;
use crate::plan::DiffKind;
use crate::plan::tests::inputs;
use crate::restore::{self, Restored};
use crate::sync::tests::{commit_all, run as git_run};
use crate::testing::{GuardedHome, guarded_home};

/// Where the external is checked out, relative to the home.
const AT: &str = ".zsh/plugins/a";

/// The url every test declares. `~/.gitconfig` rewrites it to the
/// upstream on disk, since a declared url may not be a local path.
const URL: &str = "https://example.invalid/upstream";

/// The upstream's commits: `first` and `second` on `master`, and `side`
/// on a branch of its own from `first`.
struct Upstream {
    first: String,
    second: String,
    side: String,
}

/// `git` for a test: the tempdir home's configuration only, unattended.
fn git(home: &Path) -> Git {
    crate::sync::tests::git(home).unattended()
}

/// An upstream repository at `~/upstream`, reachable as [`URL`].
fn upstream(home: &GuardedHome) -> Upstream {
    let dir = home.child("upstream");
    std::fs::create_dir_all(&dir).expect("the upstream");
    std::fs::write(
        home.child(".gitconfig"),
        format!(
            "[url \"file://{}/\"]\n\tinsteadOf = https://example.invalid/\n",
            home.path().display()
        ),
    )
    .expect("~/.gitconfig");
    git_run(home.path(), &dir, &["init", "--quiet", "-b", "master"]);
    std::fs::write(dir.join("a.zsh"), "one\n").expect("a file");
    commit_all(home.path(), &dir, "first");
    let first = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
    std::fs::write(dir.join("a.zsh"), "two\n").expect("a file");
    commit_all(home.path(), &dir, "second");
    let second = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
    git_run(
        home.path(),
        &dir,
        &["checkout", "--quiet", "-b", "side", &first],
    );
    std::fs::write(dir.join("side.zsh"), "side\n").expect("a file");
    commit_all(home.path(), &dir, "side");
    let side = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
    git_run(home.path(), &dir, &["checkout", "--quiet", "master"]);
    Upstream {
        first,
        second,
        side,
    }
}

/// One `[[external]]` at [`AT`] from [`URL`] at `rev`.
fn layer(rev: &str) -> String {
    format!("[[external]]\npath = \"~/{AT}\"\nurl = \"{URL}\"\nrev = \"{rev}\"\n")
}

/// The inputs for `layer`, seeing git as a test does.
fn load(home: &GuardedHome, layer: &str) -> Inputs {
    inputs(home, layer).with_git(git(home.path()))
}

fn plan(home: &GuardedHome, layer: &str) -> Report {
    run(&load(home, layer), Mode::Plan, &mut |_| {
        panic!("plan never asks")
    })
    .expect("plan runs")
}

fn apply(home: &GuardedHome, layer: &str) -> Report {
    run(&load(home, layer), Mode::Apply, &mut |_| Ok(true)).expect("apply runs")
}

/// Apply `layer`, running `change` once the decision is made and before
/// any of its work is done, as a user acting between the two would.
fn apply_after(home: &GuardedHome, layer: &str, mut change: impl FnMut()) -> Report {
    run(&load(home, layer), Mode::Apply, &mut |_| {
        change();
        Ok(true)
    })
    .expect("apply runs")
}

/// The one row `applied` stopped short of, and its note.
fn stopped_note(applied: &Report) -> String {
    assert_eq!(applied.stopped, [0], "{applied:?}");
    let row = only(applied);
    assert_eq!(row.action, Action::Blocked);
    row.note.clone().expect("a note")
}

/// The commit checked out at [`AT`].
fn checked_out(home: &GuardedHome) -> String {
    git_run(home.path(), &home.child(AT), &["rev-parse", "HEAD"])
}

fn entry(home: &GuardedHome) -> Option<LedgerEntry> {
    let target = Portable::parse_in(&format!("~/{AT}"), home.path()).expect("a target");
    LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("the ledger")
        .value
        .get(&target)
        .cloned()
}

fn target(home: &GuardedHome) -> Portable {
    Portable::parse_in(&format!("~/{AT}"), home.path()).expect("a target")
}

fn rm(home: &GuardedHome) -> Vec<Restored> {
    restore::restore_with(
        &StateDir::resolve(home.path()),
        home.path(),
        &[target(home)],
        &git(home.path()),
    )
    .expect("rm")
}

/// The one row that is not an interactive zsh or bash file a followed
/// external places for its update prompt, or the region sourcing it.
fn only(report: &Report) -> &Change {
    let rows: Vec<&Change> = report.changes.iter().filter(|row| !shell(row)).collect();
    assert_eq!(rows.len(), 1, "{:?}", report.changes);
    rows[0]
}

/// Whether `row` is a generated interactive zsh or bash file or its
/// region.
fn shell(row: &Change) -> bool {
    row.target == "~/.zshrc"
        || row.target == "~/.bashrc"
        || row.target.starts_with("~/.local/share/bx/")
}

#[test]
fn an_absent_external_is_a_create_that_clones_at_rev_and_then_converges() {
    let home = guarded_home();
    let up = upstream(&home);

    let planned = plan(&home, &layer(&up.first));
    let row = only(&planned);
    assert_eq!(row.action, Action::Create);
    assert_eq!(row.target, format!("~/{AT}"));
    assert_eq!(
        row.diff.as_ref().map(|diff| &diff.kind),
        Some(&DiffKind::Checkout {
            from: None,
            to: up.first.clone(),
            url: URL.to_string(),
        })
    );
    let note = row.note.as_deref().expect("a note");
    assert!(
        note.contains(&format!("clones {URL} at {}", up.first)),
        "{note}"
    );
    assert!(note.contains("creates ~/.zsh, ~/.zsh/plugins"), "{note}");
    assert!(!home.child(".zsh").exists(), "plan writes nothing");

    let applied = apply(&home, &layer(&up.first));
    assert!(
        applied.executed && applied.stopped.is_empty(),
        "{applied:?}"
    );
    assert_eq!(checked_out(&home), up.first);
    assert_eq!(
        std::fs::read_to_string(home.child(AT).join("a.zsh")).expect("the checkout"),
        "one\n"
    );
    let recorded = entry(&home).expect("recorded");
    assert_eq!(recorded.mechanism, Mechanism::Clone);
    assert_eq!(recorded.written, clone_written(Some(&up.first)));
    assert_eq!(
        recorded
            .created_dirs
            .iter()
            .map(Portable::as_str)
            .collect::<Vec<_>>(),
        ["~/.zsh/plugins", "~/.zsh"]
    );
    assert!(
        git_run(
            home.path(),
            &home.child(AT),
            &["for-each-ref", "refs/heads"]
        )
        .is_empty(),
        "bx makes no local branch"
    );

    // Converged: the second plan is empty, and neither it nor a second
    // apply reaches the remote, which is gone.
    std::fs::rename(home.child("upstream"), home.child("gone")).expect("move the remote");
    assert_eq!(
        plan(&home, &layer(&up.first)).actions(),
        [Action::Unchanged]
    );
    let again = apply(&home, &layer(&up.first));
    assert_eq!(again.actions(), [Action::Unchanged]);
    assert!(!again.executed, "nothing to do");
}

#[test]
fn a_clone_is_made_in_the_object_format_its_rev_is_written_in() {
    // A SHA-256 upstream: a 64-hex rev is cloned into a SHA-256 checkout.
    let home = guarded_home();
    let up = upstream(&home);
    let dir = home.child("upstream");
    std::fs::remove_dir_all(&dir).expect("the SHA-1 upstream");
    std::fs::create_dir(&dir).expect("the upstream");
    git_run(
        home.path(),
        &dir,
        &["init", "--quiet", "-b", "master", "--object-format=sha256"],
    );
    std::fs::write(dir.join("a.zsh"), "one\n").expect("a file");
    commit_all(home.path(), &dir, "first");
    let rev = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
    assert_eq!(rev.len(), 64);

    let applied = apply(&home, &layer(&rev));
    assert!(applied.stopped.is_empty(), "{applied:?}");
    assert_eq!(checked_out(&home), rev);
    assert_eq!(
        git_run(
            home.path(),
            &home.child(AT),
            &["rev-parse", "--show-object-format"]
        ),
        "sha256"
    );
    assert_eq!(plan(&home, &layer(&rev)).actions(), [Action::Unchanged]);
    drop(up);

    // A 40-hex rev is SHA-1 even where the user's git makes SHA-256.
    let home = guarded_home();
    let up = upstream(&home);
    let mut config = std::fs::read_to_string(home.child(".gitconfig")).expect("the config");
    config.push_str("[init]\n\tdefaultObjectFormat = sha256\n");
    std::fs::write(home.child(".gitconfig"), config).expect("~/.gitconfig");
    let applied = apply(&home, &layer(&up.first));
    assert!(applied.stopped.is_empty(), "{applied:?}");
    assert_eq!(checked_out(&home), up.first);
}

#[test]
fn a_rev_that_moved_is_a_modify_naming_both_commits_and_apply_fast_forwards() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));

    let planned = plan(&home, &layer(&up.second));
    let row = only(&planned);
    assert_eq!(row.action, Action::Modify);
    assert_eq!(
        row.diff.as_ref().map(|diff| &diff.kind),
        Some(&DiffKind::Checkout {
            from: Some(up.first.clone()),
            to: up.second.clone(),
            url: URL.to_string(),
        })
    );
    let note = row.note.as_deref().expect("a note");
    assert!(
        note.contains(&up.first) && note.contains(&up.second),
        "{note}"
    );

    let applied = apply(&home, &layer(&up.second));
    assert!(applied.stopped.is_empty(), "{applied:?}");
    assert_eq!(checked_out(&home), up.second);
    assert_eq!(
        entry(&home).expect("recorded").written,
        clone_written(Some(&up.second))
    );
    assert_eq!(
        plan(&home, &layer(&up.second)).actions(),
        [Action::Unchanged]
    );
}

#[test]
fn a_commit_fetched_only_at_apply_is_fast_forwarded_to() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    // A commit the checkout has never fetched.
    let dir = home.child("upstream");
    std::fs::write(dir.join("a.zsh"), "three\n").expect("a file");
    commit_all(home.path(), &dir, "third");
    let third = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);

    let planned = plan(&home, &layer(&third));
    let note = only(&planned).note.clone().expect("a note");
    assert!(note.starts_with(&format!("fetches {URL}")), "{note}");
    let applied = apply(&home, &layer(&third));
    assert!(applied.stopped.is_empty(), "{applied:?}");
    assert_eq!(checked_out(&home), third);
}

#[test]
fn a_rev_that_is_not_a_fast_forward_is_blocked_and_the_checkout_is_left() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.second));

    let planned = plan(&home, &layer(&up.side));
    let row = only(&planned);
    assert_eq!(row.action, Action::Blocked);
    let note = row.note.as_deref().expect("a note");
    assert!(note.contains("is not a fast-forward"), "{note}");
    let applied = apply(&home, &layer(&up.side));
    assert_eq!(applied.actions(), [Action::Blocked]);
    assert_eq!(checked_out(&home), up.second, "left as it was");
}

#[test]
fn a_rev_fetched_only_at_apply_that_is_not_a_fast_forward_stops_there() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    // A branch the checkout has never fetched, diverging from `second`.
    let dir = home.child("upstream");
    git_run(
        home.path(),
        &dir,
        &["checkout", "--quiet", "-b", "later", &up.second],
    );
    std::fs::write(dir.join("a.zsh"), "later\n").expect("a file");
    commit_all(home.path(), &dir, "later");
    let later = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
    // Move the checkout to `side` by hand, as a user might, then commit.
    let at = home.child(AT);
    git_run(
        home.path(),
        &at,
        &["checkout", "--quiet", "--detach", &up.side],
    );
    std::fs::write(at.join("mine.zsh"), "mine\n").expect("a file");
    commit_all(home.path(), &at, "mine");
    let mine = checked_out(&home);

    let planned = plan(&home, &layer(&later));
    assert_eq!(only(&planned).action, Action::Modify, "{planned:?}");
    let applied = apply(&home, &layer(&later));
    assert_eq!(applied.stopped, [0]);
    let row = only(&applied);
    assert_eq!(row.action, Action::Blocked);
    let note = row.note.as_deref().expect("a note");
    assert!(
        note.contains("has 1 local commit(s) not contained in"),
        "{note}"
    );
    assert_eq!(
        checked_out(&home),
        mine,
        "the user's commit is where it was"
    );
    assert_eq!(
        entry(&home).expect("recorded").written,
        clone_written(Some(&up.first)),
        "the ledger is unchanged"
    );
}

#[test]
fn a_checkout_with_uncommitted_changes_or_local_commits_is_blocked() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let at = home.child(AT);

    std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
    let row = only(&plan(&home, &layer(&up.second))).clone();
    assert_eq!(row.action, Action::Blocked);
    assert!(
        row.note
            .as_deref()
            .is_some_and(|n| n.contains("uncommitted changes")),
        "{row:?}"
    );
    apply(&home, &layer(&up.second));
    assert_eq!(
        std::fs::read_to_string(at.join("a.zsh")).expect("the edit"),
        "edited\n"
    );

    commit_all(home.path(), &at, "mine");
    let mine = checked_out(&home);
    let row = only(&plan(&home, &layer(&up.second))).clone();
    assert_eq!(row.action, Action::Blocked);
    assert!(
        row.note
            .as_deref()
            .is_some_and(|n| n.contains("has 1 local commit(s) not contained in")),
        "{row:?}"
    );
    apply(&home, &layer(&up.second));
    assert_eq!(checked_out(&home), mine);
}

#[test]
fn a_directory_bx_did_not_clone_is_a_conflict_and_is_never_touched() {
    let home = guarded_home();
    let up = upstream(&home);
    std::fs::create_dir_all(home.child(AT)).expect("the user's directory");
    std::fs::write(home.child(AT).join("mine"), "mine\n").expect("the user's file");

    let row = only(&plan(&home, &layer(&up.first))).clone();
    assert_eq!(row.action, Action::Conflict);
    assert!(
        row.note
            .as_deref()
            .is_some_and(|n| n.contains("bx did not clone it")),
        "{row:?}"
    );
    let applied = apply(&home, &layer(&up.first));
    assert!(!applied.executed);
    assert!(!home.child(AT).join(".git").exists());
    assert!(entry(&home).is_none());

    // A file there is refused the same way.
    let home = guarded_home();
    let up = upstream(&home);
    std::fs::create_dir_all(home.child(".zsh/plugins")).expect("parents");
    std::fs::write(home.child(AT), "a file\n").expect("a file");
    assert_eq!(plan(&home, &layer(&up.first)).actions(), [Action::Conflict]);
}

#[test]
fn a_remote_origin_other_than_the_declared_url_is_blocked() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    git_run(
        home.path(),
        &home.child(AT),
        &[
            "remote",
            "set-url",
            "origin",
            "https://example.invalid/other",
        ],
    );
    let row = only(&plan(&home, &layer(&up.second))).clone();
    assert_eq!(row.action, Action::Blocked);
    assert!(
        row.note
            .as_deref()
            .is_some_and(|n| n.contains("its remote `origin` is https://example.invalid/other")),
        "{row:?}"
    );
}

#[test]
fn a_failed_clone_is_blocked_and_leaves_nothing_behind() {
    let home = guarded_home();
    let up = upstream(&home);
    std::fs::rename(home.child("upstream"), home.child("gone")).expect("move the remote");

    let applied = apply(&home, &layer(&up.first));
    assert!(applied.executed);
    assert_eq!(applied.stopped, [0]);
    let row = only(&applied);
    assert_eq!(row.action, Action::Blocked);
    assert!(
        row.note.as_deref().is_some_and(|n| n.contains("git fetch")),
        "{row:?}"
    );
    assert!(
        !home.child(".zsh").exists(),
        "the clone and its parents are gone"
    );
    assert!(entry(&home).is_none(), "and so is its entry");
    assert_eq!(
        super::super::exit(&applied, Mode::Apply),
        crate::report::Exit::Pending
    );
}

#[test]
fn only_a_finished_clone_is_one_bx_reads_or_fetches_into() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    state.ensure().expect("the state directory");
    let other = Portable::parse_in("~/other", home.path()).expect("a path");
    let record = |path: &Portable, written, mechanism| {
        let lock = ExclusiveLock::acquire(&state).expect("the lock");
        let mut ledger = Ledger::open(&state, &lock, home.path())
            .expect("open")
            .value;
        ledger
            .record(NewEntry::new(
                path.clone(),
                written,
                fs::Mode::DEFAULT_DIR,
                mechanism,
                PriorBytes::Absent,
            ))
            .expect("record");
        ledger.save().expect("save");
    };
    let view = || {
        LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value
    };
    assert!(!finished_clone(&view(), &target(&home)), "no entry");
    assert!(!bx_clone(&view(), &target(&home)), "no entry");
    record(&target(&home), clone_written(None), Mechanism::Clone);
    assert!(!finished_clone(&view(), &target(&home)), "unfinished");
    assert!(bx_clone(&view(), &target(&home)), "bx's, unfinished");
    record(
        &target(&home),
        clone_written(Some(&"a".repeat(40))),
        Mechanism::Clone,
    );
    assert!(finished_clone(&view(), &target(&home)));
    assert!(bx_clone(&view(), &target(&home)));
    record(&other, clone_written(Some(&"a".repeat(40))), Mechanism::Own);
    assert!(!finished_clone(&view(), &other), "another kind of entry");
    assert!(!bx_clone(&view(), &other), "another kind of entry");
}

#[test]
fn an_interrupted_clone_is_removed_and_cloned_again() {
    let home = guarded_home();
    let up = upstream(&home);
    // What a clone that stopped part way leaves: an unfinished entry and a
    // half-populated directory.
    let state = StateDir::resolve(home.path());
    state.ensure().expect("the state directory");
    {
        let lock = ExclusiveLock::acquire(&state).expect("the lock");
        let mut ledger = Ledger::open(&state, &lock, home.path())
            .expect("open")
            .value;
        ledger
            .record(NewEntry::new(
                target(&home),
                clone_written(None),
                fs::Mode::DEFAULT_DIR,
                Mechanism::Clone,
                PriorBytes::Absent,
            ))
            .expect("record");
        ledger.save().expect("save");
    }
    std::fs::create_dir_all(home.child(AT).join(".git")).expect("a partial clone");
    std::fs::write(home.child(AT).join("half"), "half\n").expect("a partial file");

    let row = only(&plan(&home, &layer(&up.first))).clone();
    assert_eq!(row.action, Action::Create);
    assert!(
        row.note
            .as_deref()
            .is_some_and(|n| n.contains("removes what an interrupted clone left")),
        "{row:?}"
    );
    let applied = apply(&home, &layer(&up.first));
    assert!(applied.stopped.is_empty(), "{applied:?}");
    assert!(!home.child(AT).join("half").exists());
    assert_eq!(checked_out(&home), up.first);
    assert_eq!(
        plan(&home, &layer(&up.first)).actions(),
        [Action::Unchanged]
    );

    // With the directory gone too, the entry alone still reads as
    // interrupted, and the next apply completes it.
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    std::fs::remove_dir_all(home.child(AT)).expect("the user removed it");
    let row = only(&plan(&home, &layer(&up.first))).clone();
    assert_eq!(row.action, Action::Create);
    assert!(
        row.note.as_deref().is_some_and(|n| n.contains("is gone")),
        "{row:?}"
    );
}

#[test]
fn a_checkout_at_rev_the_ledger_does_not_record_is_recorded() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    // An apply that moved the checkout and stopped before saving.
    git_run(
        home.path(),
        &home.child(AT),
        &["fetch", "--quiet", "origin"],
    );
    git_run(
        home.path(),
        &home.child(AT),
        &["checkout", "--quiet", "--detach", &up.second],
    );

    let row = only(&plan(&home, &layer(&up.second))).clone();
    assert_eq!(row.action, Action::Modify);
    assert!(
        row.note
            .as_deref()
            .is_some_and(|n| n.contains("records that")),
        "{row:?}"
    );
    apply(&home, &layer(&up.second));
    assert_eq!(
        entry(&home).expect("recorded").written,
        clone_written(Some(&up.second))
    );
    assert_eq!(
        plan(&home, &layer(&up.second)).actions(),
        [Action::Unchanged]
    );
}

#[test]
fn a_path_that_appears_after_plan_is_not_cloned_into() {
    let home = guarded_home();
    let up = upstream(&home);
    let applied = apply_after(&home, &layer(&up.first), || {
        std::fs::create_dir_all(home.child(AT)).expect("the user's directory");
        std::fs::write(home.child(AT).join("mine"), "mine\n").expect("the user's file");
    });
    let note = stopped_note(&applied);
    assert!(
        note.contains("is a directory now, which is not what bx planned against"),
        "{note}"
    );
    assert_eq!(
        std::fs::read_to_string(home.child(AT).join("mine")).expect("the user's file"),
        "mine\n"
    );
    assert!(!home.child(AT).join(".git").exists(), "nothing cloned");
    assert!(entry(&home).is_none(), "nothing recorded");
}

#[test]
fn a_parent_that_cannot_be_made_at_apply_stops_the_clone_and_records_nothing() {
    use std::os::unix::fs::PermissionsExt as _;

    /// Reopens `~/.zsh` so the tempdir home can be removed.
    struct Reopen(std::path::PathBuf);
    impl Drop for Reopen {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }

    let home = guarded_home();
    let up = upstream(&home);
    let zsh = home.child(".zsh");
    let mut reopen = None;
    // Between plan and apply, the user makes the first parent plan said
    // apply creates, at a mode that denies its owner write.
    let applied = apply_after(&home, &layer(&up.first), || {
        std::fs::create_dir(&zsh).expect("the user's directory");
        std::fs::set_permissions(&zsh, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        reopen = Some(Reopen(zsh.clone()));
    });
    if std::fs::create_dir(zsh.join("probe")).is_ok() {
        crate::testing::skip_unconstructible("a directory its owner can write at 0500");
        return;
    }

    let note = stopped_note(&applied);
    assert!(
        note.starts_with("~/.zsh/plugins cannot be created: "),
        "{note}"
    );
    drop(reopen);
    assert!(zsh.is_dir(), "the user's directory is left");
    assert!(!home.child(".zsh/plugins").exists(), "nothing was made");
    assert!(entry(&home).is_none(), "nothing recorded");
}

#[test]
fn missing_dirs_names_every_absent_parent_and_refuses_one_that_cannot_hold_a_clone() {
    let home = guarded_home();
    let at = |rel: &str| home.child(rel);
    assert_eq!(
        missing_dirs(&at("a/b/c"), home.path()),
        Ok(vec![at("a/b"), at("a")]),
        "deepest first, stopping at the home"
    );
    home.write("file", "x\n");
    assert_eq!(
        missing_dirs(&at("file/c"), home.path()),
        Err("~/file is not a directory, so there is nowhere to clone it".to_string())
    );
    let beneath = missing_dirs(&at("file/b/c"), home.path()).expect_err("beneath a file");
    assert!(
        beneath.starts_with("~/file/b cannot be looked at: "),
        "{beneath}"
    );
}

#[test]
fn a_directory_inside_another_checkout_is_not_its_own_checkout() {
    let home = guarded_home();
    let outer = home.child("outer");
    let inner = outer.join("inner");
    std::fs::create_dir_all(&inner).expect("the directories");
    git_run(home.path(), &outer, &["init", "--quiet"]);
    let git = git(home.path());

    assert_eq!(own_checkout(&git, &outer), Ok(()));
    let top = std::fs::canonicalize(&outer).expect("canonical");
    assert_eq!(
        own_checkout(&git, &inner),
        Err(format!(
            "is not a git checkout of its own (git answers from {}); bx left it as it is",
            top.display()
        ))
    );
    let unread = own_checkout(&Git::at_home(home.path()).with_env("PATH", ""), &outer)
        .expect_err("no git to ask");
    assert!(
        unread.starts_with("is not a git checkout bx can read: ")
            && unread.ends_with("bx needs git on PATH"),
        "{unread}"
    );
}

#[test]
fn a_git_failure_counting_local_commits_is_named() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let recorded = entry(&home).expect("recorded");
    let missing = Git::at_home(home.path()).with_env("PATH", "");

    let note = not_forward(&missing, &home.child(AT), &up.first, &up.side, &recorded);

    assert!(note.contains("bx needs git on PATH"), "{note}");
}

#[test]
fn a_local_commit_count_git_answers_with_something_other_than_a_number_is_not_counted() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let recorded = entry(&home).expect("recorded");
    let bin = home.child("bin");
    std::fs::create_dir(&bin).expect("the stub's directory");
    let stub = bin.join("git");
    std::fs::write(&stub, "#!/bin/sh\necho many\n").expect("the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("executable");
    let garbled = Git::at_home(home.path()).with_env("PATH", &bin);

    let note = not_forward(&garbled, &home.child(AT), &up.first, &up.side, &recorded);

    assert_eq!(
        note,
        format!(
            "{} is not a fast-forward from {}; bx left it as it is",
            up.side, up.first
        )
    );
}

#[test]
fn a_checkout_that_changed_after_plan_is_not_fast_forwarded() {
    // Edited between plan and apply.
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let at = home.child(AT);
    let applied = apply_after(&home, &layer(&up.second), || {
        std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
    });
    let note = stopped_note(&applied);
    assert!(
        note.contains("has uncommitted changes since bx planned"),
        "{note}"
    );
    assert_eq!(checked_out(&home), up.first);
    assert_eq!(
        std::fs::read_to_string(at.join("a.zsh")).expect("the edit"),
        "edited\n"
    );
    assert_eq!(
        entry(&home).expect("recorded").written,
        clone_written(Some(&up.first))
    );

    // Moved to another commit between plan and apply.
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let at = home.child(AT);
    let applied = apply_after(&home, &layer(&up.second), || {
        git_run(home.path(), &at, &["fetch", "--quiet", "origin"]);
        git_run(
            home.path(),
            &at,
            &["checkout", "--quiet", "--detach", &up.side],
        );
    });
    let note = stopped_note(&applied);
    assert!(
        note.contains(&format!(
            "moved to {} since bx planned against {}",
            up.side, up.first
        )),
        "{note}"
    );
    assert_eq!(checked_out(&home), up.side, "left where the user put it");
    assert_eq!(
        entry(&home).expect("recorded").written,
        clone_written(Some(&up.first))
    );
}

#[test]
fn a_checkout_that_moved_after_plan_is_not_recorded_at_rev() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let at = home.child(AT);
    // The stale ledger `Work::Record` exists for: at `second`, recorded
    // at `first`.
    git_run(home.path(), &at, &["fetch", "--quiet", "origin"]);
    git_run(
        home.path(),
        &at,
        &["checkout", "--quiet", "--detach", &up.second],
    );

    let applied = apply_after(&home, &layer(&up.second), || {
        git_run(
            home.path(),
            &at,
            &["checkout", "--quiet", "--detach", &up.first],
        );
    });
    let note = stopped_note(&applied);
    assert!(
        note.contains(&format!("moved to {} since bx planned", up.first)),
        "{note}"
    );
    assert_eq!(checked_out(&home), up.first);
    assert_eq!(
        entry(&home).expect("recorded").written,
        clone_written(Some(&up.first)),
        "the ledger still says what is there"
    );
}

#[test]
fn a_path_bx_holds_another_way_or_under_a_file_is_a_conflict() {
    let home = guarded_home();
    let up = upstream(&home);
    std::fs::write(home.child(".zsh"), "a file\n").expect("a file where a parent goes");
    let row = only(&plan(&home, &layer(&up.first))).clone();
    assert_eq!(row.action, Action::Conflict, "{row:?}");

    let home = guarded_home();
    let up = upstream(&home);
    crate::plan::tests::own(home.path(), ".zsh-a", b"x", Mechanism::Own);
    let layer = format!(
        "[[external]]\npath = \"~/.zsh-a\"\nurl = \"{URL}\"\nrev = \"{}\"\n",
        up.first
    );
    let row = only(&plan(&home, &layer)).clone();
    assert_eq!(row.action, Action::Conflict);
    assert!(
        row.note
            .as_deref()
            .is_some_and(|n| n.contains("the whole file")),
        "{row:?}"
    );
}

#[test]
fn rm_removes_a_clean_clone_and_the_directories_bx_created_for_it() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));

    let done = rm(&home);
    assert!(
        matches!(done.as_slice(), [Restored::Removed { .. }]),
        "{done:?}"
    );
    assert!(
        !home.child(".zsh").exists(),
        "the checkout and its parents are gone"
    );
    assert!(entry(&home).is_none());
    assert!(
        matches!(rm(&home).as_slice(), [Restored::Unmanaged { .. }]),
        "a second rm is a no-op"
    );
}

#[test]
fn bx_rm_of_the_path_or_a_directory_above_it_removes_the_clone() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let ctx =
        crate::adopt::Context::load(&crate::plan::tests::env(home.path())).expect("the context");
    let above = Portable::parse_in("~/.zsh", home.path()).expect("a path");

    let removals = crate::adopt::rm(&ctx, &above).expect("rm");

    assert_eq!(removals.len(), 1, "{removals:?}");
    assert!(matches!(removals[0].restored, Restored::Removed { .. }));
    assert!(!home.child(AT).exists());
    assert!(entry(&home).is_none());
}

#[test]
fn rm_leaves_a_clone_holding_anything_of_the_users() {
    for (what, change) in [
        ("an edit", "edit"),
        ("an untracked file", "untracked"),
        ("a local commit", "commit"),
        ("a stash", "stash"),
    ] {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        let at = home.child(AT);
        match change {
            "edit" => std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit"),
            "untracked" => std::fs::write(at.join("new"), "new\n").expect("a file"),
            "commit" => {
                std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
                commit_all(home.path(), &at, "mine");
            }
            _ => {
                std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
                git_run(home.path(), &at, &["stash", "--quiet"]);
            }
        }

        let done = rm(&home);
        assert!(
            matches!(done.as_slice(), [Restored::Conflict { .. }]),
            "{what}: {done:?}"
        );
        assert!(at.join(".git").exists(), "{what}: the checkout stays");
        assert!(entry(&home).is_some(), "{what}: and so does its entry");
    }
}

#[test]
fn rm_ignores_what_the_repository_ignores_and_counts_a_rev_fetched_by_id() {
    let home = guarded_home();
    let up = upstream(&home);
    let dir = home.child("upstream");
    std::fs::write(dir.join(".gitignore"), "*.zwc\n").expect("an ignore file");
    commit_all(home.path(), &dir, "ignore");
    // A commit no branch holds, which the clone has to fetch by id.
    git_run(home.path(), &dir, &["checkout", "--quiet", "--detach"]);
    std::fs::write(dir.join("a.zsh"), "loose\n").expect("a file");
    commit_all(home.path(), &dir, "loose");
    let loose = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
    git_run(home.path(), &dir, &["checkout", "--quiet", "master"]);
    git_run(
        home.path(),
        &dir,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );

    let applied = apply(&home, &layer(&loose));
    assert!(applied.stopped.is_empty(), "{applied:?}");
    assert_eq!(checked_out(&home), loose);
    std::fs::write(home.child(AT).join("a.zsh.zwc"), "compiled").expect("an ignored file");

    let done = rm(&home);
    assert!(
        matches!(done.as_slice(), [Restored::Removed { .. }]),
        "{done:?}"
    );
    assert!(!home.child(AT).exists());
    let _ = up.second;
}

#[test]
fn rm_removes_an_unfinished_clone_whole_and_forgets_one_already_gone() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    // An rm that stopped part way: the entry says unfinished, and the
    // checkout holds what would otherwise stop an rm.
    std::fs::write(home.child(AT).join("new"), "new\n").expect("a file");
    let state = StateDir::resolve(home.path());
    {
        let lock = ExclusiveLock::acquire(&state).expect("the lock");
        let mut ledger = Ledger::open(&state, &lock, home.path())
            .expect("open")
            .value;
        ledger
            .record(NewEntry::new(
                target(&home),
                clone_written(None),
                fs::Mode::DEFAULT_DIR,
                Mechanism::Clone,
                PriorBytes::Absent,
            ))
            .expect("record");
        ledger.save().expect("save");
    }
    assert!(matches!(rm(&home).as_slice(), [Restored::Removed { .. }]));
    assert!(!home.child(".zsh").exists());

    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    std::fs::remove_dir_all(home.child(AT)).expect("the user removed it");
    assert!(matches!(
        rm(&home).as_slice(),
        [Restored::AlreadyGone { .. }]
    ));
    assert!(entry(&home).is_none());
    assert!(
        home.child(".zsh/plugins").is_dir(),
        "rm announced no removal of a parent, as for a file already gone"
    );
}

#[test]
fn rm_leaves_something_that_is_not_the_checkout() {
    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    std::fs::remove_dir_all(home.child(AT)).expect("the user removed it");
    std::fs::write(home.child(AT), "a file\n").expect("and put a file there");
    assert!(
        matches!(
            rm(&home).as_slice(),
            [Restored::Conflict { note, dest, .. }]
                if note == "is a file, not the checkout bx cloned; bx is leaving it and \
                            forgetting nothing"
                    && *dest == home.child(AT)
        ),
        "the note says what is there"
    );
    assert!(home.child(AT).is_file());
    assert!(entry(&home).is_some(), "the entry stays");
}

#[test]
fn only_git_exiting_1_reads_as_no_origin_or_not_an_ancestor() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = guarded_home();
    let up = upstream(&home);
    apply(&home, &layer(&up.first));
    let dest = home.child(AT);
    let git = git(home.path());

    // Git exits 1 for an unset key and for a commit that is not an
    // ancestor: each is an answer, not a failure.
    git_run(home.path(), &dest, &["remote", "remove", "origin"]);
    assert!(matches!(origin_url(&git, &dest), Ok(None)));
    assert!(matches!(
        is_ancestor(&git, &dest, &up.second, &up.first),
        Ok(false)
    ));

    // Any other failure is git's, and is reported rather than answered.
    let unknown = "0".repeat(40);
    assert!(matches!(
        is_ancestor(&git, &dest, &unknown, &up.first),
        Err(git::Error::Failed { .. })
    ));
    let bin = home.child("bin");
    std::fs::create_dir(&bin).expect("the stub's directory");
    let stub = bin.join("git");
    std::fs::write(&stub, "#!/bin/sh\nexit 2\n").expect("the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("executable");
    let failing = Git::at_home(home.path()).with_env("PATH", &bin);
    assert!(matches!(
        origin_url(&failing, &dest),
        Err(git::Error::Failed { .. })
    ));
    assert!(matches!(
        is_ancestor(&failing, &dest, &up.first, &up.second),
        Err(git::Error::Failed { .. })
    ));
}

#[test]
fn a_problem_names_what_git_said() {
    let home = guarded_home();
    let missing = Git::at_home(home.path()).with_env("PATH", "");
    let spawn = missing
        .query(home.path(), &["status"])
        .expect_err("no git on an empty PATH");
    assert!(problem(&spawn).contains("bx needs git on PATH"));
    let failed = git(home.path())
        .query(home.path(), &["rev-parse", "--verify", "no-such-ref"])
        .expect_err("no such ref");
    assert!(problem(&failed).starts_with("`git rev-parse --verify no-such-ref` failed"));
}

/// One `[[external]]` at [`AT`] from [`URL`], following `branch`.
fn followed(branch: &str) -> String {
    format!("[[external]]\npath = \"~/{AT}\"\nurl = \"{URL}\"\nbranch = \"{branch}\"\n")
}

/// Write `bx.lock`, locking [`AT`] for `url` and `branch` at `rev`.
fn lock(home: &GuardedHome, url: &str, branch: &str, rev: &str) {
    let mut lock = Lock::default();
    lock.set(
        target(home),
        lock::Locked {
            url: url.to_string(),
            branch: branch.to_string(),
            rev: rev.to_string(),
        },
    );
    let repo = home.child(".config/bx");
    std::fs::create_dir_all(&repo).expect("the config repo");
    std::fs::write(Lock::path_in(&repo), lock.render()).expect("bx.lock");
}

#[test]
fn a_followed_external_is_kept_at_the_commit_bx_lock_holds() {
    let home = guarded_home();
    let up = upstream(&home);
    let layer = followed("master");

    lock(&home, URL, "master", &up.first);
    let row = only(&plan(&home, &layer)).clone();
    assert_eq!(row.action, Action::Create, "{row:?}");
    let note = row.note.expect("a note");
    assert!(note.contains(&format!("at {}", up.first)), "{note}");
    apply(&home, &layer);
    assert_eq!(
        checked_out(&home),
        up.first,
        "the locked commit, not the tip"
    );
    assert_eq!(only(&plan(&home, &layer)).action, Action::Unchanged);

    lock(&home, URL, "master", &up.second);
    assert_eq!(only(&plan(&home, &layer)).action, Action::Modify);
    apply(&home, &layer);
    assert_eq!(checked_out(&home), up.second);
    assert_eq!(only(&plan(&home, &layer)).action, Action::Unchanged);
}

#[test]
fn a_followed_external_bx_lock_holds_nothing_for_is_blocked_on_bx_update() {
    let home = guarded_home();
    let up = upstream(&home);

    let applied = apply(&home, &followed("master"));
    let row = only(&applied);
    assert_eq!(row.action, Action::Blocked);
    let note = row.note.as_deref().expect("a note");
    assert!(note.contains("follows `master`"), "{note}");
    assert!(note.contains("bx.lock holds no commit"), "{note}");
    assert!(note.ends_with("`bx update` locks one"), "{note}");
    assert_eq!(
        note,
        "follows `master`, and bx.lock holds no commit for it yet; `bx update` locks one"
    );
    assert!(!home.child(AT).exists(), "nothing is cloned on a guess");

    for (url, branch) in [(URL, "side"), ("https://example.invalid/other", "master")] {
        lock(&home, url, branch, &up.side);
        let planned = plan(&home, &followed("master"));
        let row = only(&planned);
        assert_eq!(row.action, Action::Blocked, "{url} {branch}");
        let note = row.note.as_deref().expect("a note");
        assert!(
            note.contains(&format!("locks it for `{branch}` of {url}")),
            "{note}"
        );
        assert!(note.ends_with("`bx update` locks it again"), "{note}");
        assert_eq!(
            note,
            format!(
                "follows `master` of {URL}, and bx.lock locks it for `{branch}` of {url}; \
                     `bx update` locks it again"
            )
        );
    }
}

#[test]
fn a_follow_bx_update_never_locks_is_blocked_on_a_committed_layer_or_a_rev() {
    let home = guarded_home();
    let up = upstream(&home);
    let remedy = "`bx update` locks only what the committed configuration follows; \
                      declare it in a committed layer, or pin it with `rev`";

    // Only `local.toml` follows it, and bx.lock holds nothing for it.
    home.write(".local/state/bx/local.toml", &followed("master"));
    let planned = plan(&home, "");
    let row = only(&planned);
    assert_eq!(row.action, Action::Blocked, "{row:?}");
    let note = row.note.as_deref().expect("a note");
    assert!(note.contains("bx.lock holds no commit"), "{note}");
    assert!(note.ends_with(remedy), "{note}");
    assert_eq!(
        note,
        format!("follows `master`, and bx.lock holds no commit for it yet; {remedy}")
    );

    // `local.toml` points the committed follow at another branch, and
    // bx.lock holds the committed one's commit.
    lock(&home, URL, "master", &up.first);
    home.write(".local/state/bx/local.toml", &followed("side"));
    let planned = plan(&home, &followed("master"));
    let row = only(&planned);
    assert_eq!(row.action, Action::Blocked, "{row:?}");
    let note = row.note.as_deref().expect("a note");
    assert!(note.contains("locks it for `master`"), "{note}");
    assert!(
        note.ends_with(
            "`bx update` locks the branch and url the committed configuration follows \
                 here, not this one; pin it with `rev`"
        ),
        "{note}"
    );
    assert_eq!(
        note,
        format!(
            "follows `side` of {URL}, and bx.lock locks it for `master` of {URL}; \
                 `bx update` locks the branch and url the committed configuration follows \
                 here, not this one; pin it with `rev`"
        )
    );
}

/// Commit `files` on the upstream's `master`, and return the commit.
fn commit_upstream(home: &GuardedHome, files: &[&str]) -> String {
    let dir = home.child("upstream");
    for file in files {
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, "x\n").expect("a file");
    }
    commit_all(home.path(), &dir, "more");
    git_run(home.path(), &dir, &["rev-parse", "HEAD"])
}

/// [`followed`], linking each child of `skills/` holding `SKILL.md` into
/// `~/.claude/skills`.
fn linking(branch: &str) -> String {
    format!(
        "{}[[external.link]]\nfrom = \"skills/*\"\nto = \"~/.claude/skills/*\"\n\
             require = \"SKILL.md\"\n",
        followed(branch)
    )
}

/// Each row's target and action, in order.
fn rows(report: &Report) -> Vec<(String, Action)> {
    report
        .changes
        .iter()
        .filter(|row| !shell(row))
        .map(|row| (row.target.clone(), row.action))
        .collect()
}

/// The row for `target`.
fn row<'a>(report: &'a Report, target: &str) -> &'a Change {
    report
        .changes
        .iter()
        .find(|row| row.target == target)
        .unwrap_or_else(|| panic!("no row for {target}: {:?}", rows(report)))
}

/// The targets of the rows `report` stopped short of.
fn stopped(report: &Report) -> Vec<&str> {
    report
        .stopped
        .iter()
        .map(|&at| report.changes[at].target.as_str())
        .collect()
}

#[test]
fn a_link_is_pending_until_its_clone_then_each_child_is_linked_and_converges() {
    let home = guarded_home();
    upstream(&home);
    let rev = commit_upstream(
        &home,
        &["skills/a/SKILL.md", "skills/b/SKILL.md", "skills/c/x"],
    );
    lock(&home, URL, "master", &rev);
    let layer = linking("master");

    let planned = plan(&home, &layer);
    assert_eq!(
        rows(&planned),
        [
            (format!("~/{AT}"), Action::Create),
            ("~/.claude/skills/*".to_string(), Action::Create),
        ]
    );
    let note = row(&planned, "~/.claude/skills/*")
        .note
        .as_deref()
        .expect("a note");
    assert!(
        note.contains(&format!("`skills/*` holding `SKILL.md` in ~/{AT} at {rev}")),
        "{note}"
    );

    let applied = apply(&home, &layer);
    assert!(applied.stopped.is_empty(), "{applied:?}");
    assert_eq!(
        rows(&applied)[2..],
        [
            ("~/.claude/skills/a".to_string(), Action::Create),
            ("~/.claude/skills/b".to_string(), Action::Create),
        ],
        "the children, appended once the clone brought them"
    );
    for skill in ["a", "b"] {
        let link = home.child(format!(".claude/skills/{skill}"));
        assert_eq!(
            std::fs::read_link(&link).expect("a link"),
            home.child(format!("{AT}/skills/{skill}"))
        );
        assert!(
            link.join("SKILL.md").is_file(),
            "resolves into the checkout"
        );
    }
    assert!(!home.child(".claude/skills/c").exists(), "no SKILL.md");

    let again = plan(&home, &layer);
    assert!(
        again
            .changes
            .iter()
            .all(|row| row.action == Action::Unchanged),
        "{:?}",
        rows(&again)
    );
    assert_eq!(rows(&again).len(), 3, "the external and its two children");

    // A commit fetched but not checked out yet is not read until the
    // checkout moves to it: the link waits for its external, and then a
    // child the commit adds is linked, and one it drops is left as bx
    // made it, for `bx rm` to release.
    std::fs::remove_dir_all(home.child("upstream/skills/a")).expect("drop a");
    let next = commit_upstream(&home, &["skills/d/SKILL.md"]);
    git_run(
        home.path(),
        &home.child(AT),
        &["fetch", "--quiet", "origin"],
    );
    lock(&home, URL, "master", &next);
    let planned = plan(&home, &layer);
    assert_eq!(
        rows(&planned),
        [
            (format!("~/{AT}"), Action::Modify),
            ("~/.claude/skills/*".to_string(), Action::Create),
        ],
        "the external, then its link, waiting for it"
    );
    assert!(planned.stopped.is_empty());
    apply(&home, &layer);
    assert_eq!(checked_out(&home), next);
    assert!(home.child(".claude/skills/d/SKILL.md").is_file());
    assert!(
        std::fs::symlink_metadata(home.child(".claude/skills/a")).is_ok(),
        "left as bx made it"
    );
    assert_eq!(
        rows(&plan(&home, &layer))
            .into_iter()
            .filter(|(_, action)| *action != Action::Unchanged)
            .collect::<Vec<_>>(),
        [("~/.claude/skills/a".to_string(), Action::Undeclared)],
        "what nothing declares any more"
    );
}

#[test]
fn a_link_whose_clone_failed_is_stopped_with_why() {
    let home = guarded_home();
    upstream(&home);
    let missing = "c".repeat(40);
    lock(&home, URL, "master", &missing);
    // Two links, so the second's row is not the first after the
    // externals: each stopped row is the one its link announced.
    let layer = format!(
        "{}[[external.link]]\nfrom = \"*\"\nto = \"~/.other/*\"\n",
        linking("master")
    );
    let applied = apply(&home, &layer);
    assert_eq!(
        stopped(&applied),
        [
            format!("~/{AT}").as_str(),
            "~/.claude/skills/*",
            "~/.other/*"
        ],
        "{:?}",
        rows(&applied)
    );
    for target in ["~/.claude/skills/*", "~/.other/*"] {
        let row = row(&applied, target);
        assert_eq!(row.action, Action::Blocked);
        let note = row.note.as_deref().expect("a note");
        assert!(note.contains("is not at"), "{note}");
    }
    assert!(!home.child(".claude").exists());
}

#[test]
fn a_blocked_external_links_nothing_from_the_commit_it_was_not_moved_to() {
    let home = guarded_home();
    upstream(&home);
    let first = commit_upstream(&home, &["skills/a/SKILL.md"]);
    lock(&home, URL, "master", &first);
    let layer = linking("master");
    apply(&home, &layer);
    assert!(home.child(".claude/skills/a/SKILL.md").is_file());

    let next = commit_upstream(&home, &["skills/b/SKILL.md"]);
    git_run(
        home.path(),
        &home.child(AT),
        &["fetch", "--quiet", "origin"],
    );
    lock(&home, URL, "master", &next);
    std::fs::write(home.child(AT).join("skills/a/SKILL.md"), "edited\n").expect("an edit");
    let applied = apply(&home, &layer);
    assert_eq!(
        rows(&applied)
            .into_iter()
            .filter(|(_, action)| *action != Action::Unchanged)
            .collect::<Vec<_>>(),
        [(format!("~/{AT}"), Action::Blocked)],
        "no row for its link, and nothing it made called undeclared"
    );
    assert_eq!(checked_out(&home), first);
    assert!(
        std::fs::symlink_metadata(home.child(".claude/skills/b")).is_err(),
        "nothing linked from a commit the checkout is not at"
    );
    assert!(home.child(".claude/skills/a").exists(), "left as it was");
}

#[test]
fn a_child_a_target_already_declares_is_a_conflict_it_keeps() {
    let home = guarded_home();
    upstream(&home);
    let rev = commit_upstream(&home, &["skills/a/SKILL.md", "skills/b/SKILL.md"]);
    lock(&home, URL, "master", &rev);
    let layer = format!(
        "{}[[target]]\npath = \"~/.claude/skills/a\"\ncontent = \"mine\"\n",
        linking("master")
    );
    apply(&home, &layer);
    assert_eq!(
        std::fs::read_to_string(home.child(".claude/skills/a")).expect("the target"),
        "mine"
    );
    assert!(home.child(".claude/skills/b/SKILL.md").is_file());
    let planned = plan(&home, &layer);
    assert_eq!(
        row(&planned, "~/.claude/skills/a").action,
        Action::Unchanged,
        "the target keeps it"
    );
    let conflicts: Vec<&Change> = planned
        .changes
        .iter()
        .filter(|row| row.action == Action::Conflict)
        .collect();
    assert_eq!(conflicts.len(), 1, "{:?}", rows(&planned));
    assert_eq!(conflicts[0].target, "~/.claude/skills/a");
    let note = conflicts[0].note.as_deref().expect("a note");
    assert!(note.contains("another declaration already puts"), "{note}");
}

#[test]
fn a_link_of_an_unlocked_external_holds_what_it_made() {
    let home = guarded_home();
    upstream(&home);
    let rev = commit_upstream(&home, &["skills/a/SKILL.md"]);
    lock(&home, URL, "master", &rev);
    apply(&home, &linking("master"));
    // The declaration moves to another branch, which nothing locked yet.
    let planned = plan(&home, &linking("side"));
    assert_eq!(
        rows(&planned),
        [(format!("~/{AT}"), Action::Blocked)],
        "the link bx made is not reported as undeclared"
    );
}

#[test]
fn a_pending_child_something_of_the_users_stands_at_is_reported_as_stopped() {
    let home = guarded_home();
    upstream(&home);
    let rev = commit_upstream(&home, &["skills/a/SKILL.md", "skills/b/SKILL.md"]);
    lock(&home, URL, "master", &rev);
    home.write(".claude/skills/b", "the user's own\n");
    // A second link, so each rule row is found by its own index.
    let layer = format!(
        "{}[[external.link]]\nfrom = \"skills/*\"\nto = \"~/.more/*\"\n",
        linking("master")
    );
    let applied = apply(&home, &layer);
    assert_eq!(
        stopped(&applied),
        ["~/.claude/skills/b"],
        "{:?}",
        rows(&applied)
    );
    assert_eq!(row(&applied, "~/.claude/skills/b").action, Action::Conflict);
    for rule in ["~/.claude/skills/*", "~/.more/*"] {
        assert_eq!(
            row(&applied, rule).action,
            Action::Unchanged,
            "{rule}: the rule itself wrote nothing"
        );
    }
    assert!(home.child(".more/b/SKILL.md").is_file());
    assert_eq!(
        std::fs::read_to_string(home.child(".claude/skills/b")).expect("kept"),
        "the user's own\n"
    );
    assert!(home.child(".claude/skills/a/SKILL.md").is_file());
}

#[test]
fn an_interrupted_clone_with_links_converges_in_one_apply() {
    let home = guarded_home();
    upstream(&home);
    let rev = commit_upstream(&home, &["skills/a/SKILL.md"]);
    lock(&home, URL, "master", &rev);
    let state = StateDir::resolve(home.path());
    state.ensure().expect("the state directory");
    {
        let lock = ExclusiveLock::acquire(&state).expect("the lock");
        let mut ledger = Ledger::open(&state, &lock, home.path())
            .expect("open")
            .value;
        ledger
            .record(NewEntry::new(
                target(&home),
                clone_written(None),
                fs::Mode::DEFAULT_DIR,
                Mechanism::Clone,
                PriorBytes::Absent,
            ))
            .expect("record");
        ledger.save().expect("save");
    }
    std::fs::create_dir_all(home.child(AT).join(".git")).expect("a partial clone");
    let layer = linking("master");

    let planned = plan(&home, &layer);
    assert_eq!(
        row(&planned, "~/.claude/skills/*").action,
        Action::Create,
        "pending on the clone that replaces it: {:?}",
        rows(&planned)
    );
    apply(&home, &layer);
    assert!(home.child(".claude/skills/a/SKILL.md").is_file());
    let again = plan(&home, &layer);
    assert!(
        again
            .changes
            .iter()
            .all(|row| row.action == Action::Unchanged),
        "{:?}",
        rows(&again)
    );
}

#[test]
fn a_pinned_external_reads_no_lock() {
    let home = guarded_home();
    let up = upstream(&home);
    lock(&home, URL, "master", &up.second);
    apply(&home, &layer(&up.first));
    assert_eq!(
        checked_out(&home),
        up.first,
        "`rev` wins over any lock entry"
    );
}
