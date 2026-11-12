//! Restoring a directory target: removed with the parents bx invented, put
//! back at the mode bx narrowed, kept while it holds the user's files, and
//! made again when an `rm` of it was interrupted.

use super::*;
use crate::journal::tests::mode_at;

/// Let bx make the directory `rel` at `mode`, and return its target.
fn managed_dir(state: &StateDir, home: &Path, rel: &str, mode: Mode) -> Portable {
    let request = crate::journal::tests::dir_to(home, rel, mode);
    let portable = request.target.clone();
    applied(state, home, vec![request]);
    portable
}

#[test]
fn rm_removes_a_directory_bx_created_and_the_parents_it_invented() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed_dir(&state, home.path(), ".a/b", Mode::PRIVATE_DIR);

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");

    assert!(
        matches!(restored.as_slice(), [Restored::Removed { .. }]),
        "{restored:?}"
    );
    assert!(!home.child(".a").exists(), "nothing bx made is left");
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn rm_puts_back_the_mode_of_a_directory_bx_narrowed_and_nothing_else() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir(home.child(".d")).expect("the user's directory");
    home.write(".d/theirs", "kept\n");
    fs::set_mode(&home.child(".d"), Mode::DEFAULT_DIR).expect("chmod");
    let portable = managed_dir(&state, home.path(), ".d", Mode::PRIVATE_DIR);

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");

    assert!(
        matches!(restored.as_slice(), [Restored::Reverted { .. }]),
        "{restored:?}"
    );
    assert_eq!(mode_at(&home.child(".d")), Some(Mode::DEFAULT_DIR));
    assert_eq!(
        std::fs::read(home.child(".d/theirs")).expect("kept"),
        b"kept\n"
    );
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn rm_leaves_a_directory_bx_created_that_now_holds_the_users_files() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed_dir(&state, home.path(), ".d", Mode::PRIVATE_DIR);
    home.write(".d/theirs", "kept\n");

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");

    assert!(
        matches!(restored.as_slice(), [Restored::Removed { .. }]),
        "{restored:?}"
    );
    assert_eq!(
        std::fs::read(home.child(".d/theirs")).expect("kept"),
        b"kept\n"
    );
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn rm_of_a_directory_and_a_file_bx_put_inside_it_removes_both_in_either_order() {
    for directory_first in [true, false] {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dir = managed_dir(&state, home.path(), ".d", Mode::PRIVATE_DIR);
        let file = managed(&state, home.path(), ".d/f", "x\n", Mode::PRIVATE_FILE);
        let order = if directory_first {
            vec![dir.clone(), file.clone()]
        } else {
            vec![file.clone(), dir.clone()]
        };

        restore(&state, home.path(), &order).expect("rm");

        assert!(
            !home.child(".d").exists(),
            "directory first: {directory_first}"
        );
        assert!(
            LedgerView::read(&state, home.path())
                .expect("ledger")
                .value
                .is_empty()
        );
    }
}

#[test]
fn rm_of_a_directory_before_the_file_inside_it_in_separate_runs_still_removes_both() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dir = managed_dir(&state, home.path(), ".d", Mode::PRIVATE_DIR);
    let file = managed(&state, home.path(), ".d/f", "x\n", Mode::PRIVATE_FILE);

    restore(&state, home.path(), std::slice::from_ref(&dir)).expect("rm the directory");
    assert!(
        home.child(".d/f").exists(),
        "the file bx still manages stays"
    );
    restore(&state, home.path(), std::slice::from_ref(&file)).expect("rm the file");

    assert!(
        !home.child(".d").exists(),
        "the file's entry inherited the directory"
    );
}

#[test]
fn rm_refuses_a_directory_whose_mode_changed_since_bx_set_it_and_forgets_nothing() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed_dir(&state, home.path(), ".d", Mode::PRIVATE_DIR);
    fs::set_mode(&home.child(".d"), Mode::from_bits(0o750)).expect("the user's chmod");

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");

    let [Restored::Conflict { note, .. }] = restored.as_slice() else {
        panic!("{restored:?}");
    };
    assert!(note.contains("0750") && note.contains("0700"), "{note}");
    assert!(home.child(".d").is_dir());
    assert!(entry_for(&state, home.path(), &portable).is_some());
}

#[test]
fn rm_of_a_directory_somebody_removed_or_replaced() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let gone = managed_dir(&state, home.path(), ".gone", Mode::PRIVATE_DIR);
    let file = managed_dir(&state, home.path(), ".file", Mode::PRIVATE_DIR);
    std::fs::remove_dir(home.child(".gone")).expect("rmdir");
    std::fs::remove_dir(home.child(".file")).expect("rmdir");
    home.write(".file", "a file now\n");

    let restored = restore(&state, home.path(), &[gone.clone(), file.clone()]).expect("rm");

    assert!(
        matches!(
            restored.as_slice(),
            [Restored::AlreadyGone { .. }, Restored::Conflict { .. }]
        ),
        "{restored:?}"
    );
    assert!(!home.child(".gone").exists(), "bx does not make it again");
    assert!(entry_for(&state, home.path(), &gone).is_none());
    assert!(entry_for(&state, home.path(), &file).is_some());
}

#[test]
fn rm_of_a_directory_back_at_the_mode_it_had_only_forgets_it() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir(home.child(".d")).expect("the user's directory");
    fs::set_mode(&home.child(".d"), Mode::DEFAULT_DIR).expect("chmod");
    // Narrowed, then the declaration changed back to the mode it had: the
    // re-record keeps the first prior, which is now the mode on disk.
    managed_dir(&state, home.path(), ".d", Mode::PRIVATE_DIR);
    let portable = managed_dir(&state, home.path(), ".d", Mode::DEFAULT_DIR);
    let entry = entry_for(&state, home.path(), &portable).expect("managed");
    assert_eq!(
        plan_restore_with(&entry, home.path(), &Git::at_home(home.path())).expect("plan"),
        Restoration::Release {
            dest: home.child(".d")
        }
    );

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");

    assert!(
        matches!(restored.as_slice(), [Restored::Reverted { .. }]),
        "{restored:?}"
    );
    assert_eq!(mode_at(&home.child(".d")), Some(Mode::DEFAULT_DIR));
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn an_interrupted_rm_of_a_directory_makes_it_again() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed_dir(&state, home.path(), ".d", Mode::PRIVATE_DIR);
    let entry = entry_for(&state, home.path(), &portable).expect("managed");
    let Restoration::RemoveDir {
        dest,
        created_dirs,
        planned,
    } = plan_restore_with(&entry, home.path(), &Git::at_home(home.path())).expect("plan")
    else {
        panic!("bx created it");
    };
    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    session
        .apply(Request {
            target: portable.clone(),
            dest,
            content: Content::DirAbsent {
                created_dirs,
                planned: *planned,
            },
            mode: entry.mode,
            ownership: Ownership::Released,
        })
        .expect("apply");
    drop(session);
    assert!(!home.child(".d").exists());

    assert!(crate::recover::recover(&state).expect("recover").is_clear());
    assert_eq!(mode_at(&home.child(".d")), Some(Mode::PRIVATE_DIR));
    assert!(entry_for(&state, home.path(), &portable).is_some());
}
