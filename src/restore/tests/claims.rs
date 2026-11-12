//! Directories several targets share a claim on: removed once nothing bx
//! created holds them, handed on to an entry still beneath them, and never
//! pruned while a live entry names them.

use super::*;

/// How two targets sharing a directory bx created are applied and removed.
#[derive(Debug, Clone, Copy)]
enum Sharing {
    /// One apply session, one `rm` naming both, in declared order.
    OneRm,
    /// One apply session, one `rm` naming both, in reverse order.
    OneRmReversed,
    /// Two apply sessions, then two separate `rm` calls.
    SeparateRms,
}

/// Apply `~/.config/app/a.toml` and `b.toml`, remove both as `sharing` says,
/// and return whether `~/.config/app` and `~/.config` are still there.
fn remove_two_sharing_a_created_dir(sharing: Sharing, user_file: bool) -> (bool, bool) {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (a, b) = (".config/app/a.toml", ".config/app/b.toml");
    let (ta, tb) = (target(home.path(), a).0, target(home.path(), b).0);
    match sharing {
        Sharing::OneRm | Sharing::OneRmReversed => {
            let mut session = apply_session(&state, home.path());
            session
                .apply(write_to(home.path(), a, "a\n", Mode::DEFAULT_FILE))
                .expect("apply a");
            session
                .apply(write_to(home.path(), b, "b\n", Mode::DEFAULT_FILE))
                .expect("apply b");
            session.finish().expect("finish");
        }
        Sharing::SeparateRms => {
            managed(&state, home.path(), a, "a\n", Mode::DEFAULT_FILE);
            managed(&state, home.path(), b, "b\n", Mode::DEFAULT_FILE);
        }
    }
    if user_file {
        std::fs::write(home.child(".config/app/theirs"), "mine\n").expect("the user's file");
    }
    match sharing {
        Sharing::OneRm => {
            restore(&state, home.path(), &[ta.clone(), tb.clone()]).expect("rm");
        }
        Sharing::OneRmReversed => {
            restore(&state, home.path(), &[tb.clone(), ta.clone()]).expect("rm");
        }
        Sharing::SeparateRms => {
            restore(&state, home.path(), std::slice::from_ref(&ta)).expect("rm a");
            restore(&state, home.path(), std::slice::from_ref(&tb)).expect("rm b");
        }
    }
    assert!(!home.child(a).exists() && !home.child(b).exists());
    assert!(entry_for(&state, home.path(), &ta).is_none());
    assert!(entry_for(&state, home.path(), &tb).is_none());
    if user_file {
        assert_eq!(
            std::fs::read(home.child(".config/app/theirs")).expect("kept"),
            b"mine\n"
        );
    }
    (
        home.child(".config/app").exists(),
        home.child(".config").exists(),
    )
}

#[test]
fn rm_of_two_targets_sharing_a_created_directory_leaves_nothing_bx_created() {
    // Only the first write under a new directory claims it, and pruning
    // stops at the first non-empty directory, so without a hand-off removing
    // the claiming target first would leave `~/.config/app` and `~/.config`.
    for sharing in [Sharing::OneRm, Sharing::OneRmReversed, Sharing::SeparateRms] {
        assert_eq!(
            remove_two_sharing_a_created_dir(sharing, false),
            (false, false),
            "{sharing:?}"
        );
    }
}

#[test]
fn a_claim_is_handed_on_when_the_rm_session_dies_between_its_end_and_its_save() {
    // The hand-off is bookkeeping, so recovery's
    // rebuild of a terminated journal makes it too.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (a, b) = (".config/app/a.toml", ".config/app/b.toml");
    let ta = managed(&state, home.path(), a, "a\n", Mode::DEFAULT_FILE);
    let tb = managed(&state, home.path(), b, "b\n", Mode::DEFAULT_FILE);

    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), vec![ta.clone()]).expect("open");
    let entry = session.ledger().get(&ta).cloned().expect("managed");
    let Restoration::Remove {
        dest,
        created_dirs,
        planned,
    } = plan_restore_with(&entry, home.path(), &Git::at_home(home.path())).expect("plan")
    else {
        panic!("a file bx created is removed")
    };
    session
        .apply(Request {
            target: ta.clone(),
            dest,
            content: Content::Absent {
                created_dirs,
                planned: *planned,
            },
            mode: entry.mode,
            ownership: Ownership::Released,
        })
        .expect("remove a");
    drop(session);
    crate::journal::tests::seal(&state.journal(), 1);

    assert_eq!(
        recover::recover(&state).expect("recover"),
        recover::Outcome::Recorded { entries: 1 },
    );
    assert!(entry_for(&state, home.path(), &ta).is_none());
    assert_eq!(
        entry_for(&state, home.path(), &tb)
            .expect("b is still managed")
            .created_dirs
            .iter()
            .map(Portable::as_str)
            .collect::<Vec<_>>(),
        ["~/.config/app", "~/.config"],
    );
    restore(&state, home.path(), std::slice::from_ref(&tb)).expect("rm b");
    assert!(!home.child(".config").exists());
}

#[test]
fn a_forgotten_targets_claims_are_handed_to_an_entry_still_beneath_them() {
    // `rm` of a file bx created that is already gone forgets the entry and
    // keeps its claims for the hand-off; this pins that those claims reach it.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (a, b) = (".config/app/a.toml", ".config/app/b.toml");
    let ta = managed(&state, home.path(), a, "a\n", Mode::DEFAULT_FILE);
    let tb = managed(&state, home.path(), b, "b\n", Mode::DEFAULT_FILE);
    let claims = |portable: &Portable| {
        entry_for(&state, home.path(), portable)
            .expect("managed")
            .created_dirs
            .iter()
            .map(|dir| dir.as_str().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(claims(&ta), ["~/.config/app", "~/.config"]);
    assert!(claims(&tb).is_empty(), "only the first write claims");
    std::fs::remove_file(home.child(a)).expect("the user removes a");

    let done = restore(&state, home.path(), std::slice::from_ref(&ta)).expect("rm a");
    assert!(
        matches!(done.as_slice(), [Restored::AlreadyGone { .. }]),
        "{done:?}"
    );
    assert!(entry_for(&state, home.path(), &ta).is_none());
    assert!(
        home.child(".config/app").is_dir(),
        "plan announced no removal"
    );
    assert_eq!(claims(&tb), ["~/.config/app", "~/.config"]);

    restore(&state, home.path(), std::slice::from_ref(&tb)).expect("rm b");
    assert!(!home.child(".config").exists());
}

#[test]
fn a_claimed_directory_a_live_entry_names_is_never_pruned() {
    // Whichever entry claims a directory, one the ledger still holds as a
    // target stays.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let rel = ".config/app/a.toml";
    let ta = managed(&state, home.path(), rel, "a\n", Mode::DEFAULT_FILE);
    let (app, app_dir) = target(home.path(), ".config/app");
    {
        let lock = crate::state::ExclusiveLock::acquire(&state).expect("lock");
        let mut ledger = crate::state::Ledger::open(&state, &lock, home.path())
            .expect("open the ledger")
            .value;
        ledger
            .record(crate::state::NewEntry::new(
                app.clone(),
                ContentHash::of(b""),
                Mode::DEFAULT_DIR,
                crate::state::Mechanism::Own,
                crate::state::PriorBytes::Absent,
            ))
            .expect("a directory target");
        ledger.save().expect("save");
    }

    restore(&state, home.path(), std::slice::from_ref(&ta)).expect("rm");
    assert!(!home.child(rel).exists());
    assert!(
        app_dir.is_dir(),
        "empty, claimed, and still a target the ledger holds"
    );
    assert_eq!(
        entry_for(&state, home.path(), &app)
            .expect("still managed")
            .created_dirs
            .iter()
            .map(Portable::as_str)
            .collect::<Vec<_>>(),
        ["~/.config"],
        "the claim on its parent is handed to it",
    );
}

#[test]
fn rm_under_a_claimed_directory_the_user_replaced_with_a_symlink_finishes() {
    // The file goes through the link and pruning the claimed directory fails
    // with ENOTDIR. Treated as an error, that would leave the session for a
    // rollback that put the file back, and every `rm` after it would do the
    // same.
    //
    // `hand_off_claims`' guard for a claim that is no longer a directory
    // needs an entry beneath the path, or deleting it changes no assertion.
    // `heir.conf` is that entry. Without the guard the claim on `~/d` lands on it, and the
    // `rm` that removes it calls `remove_if_empty` on a symlink — the
    // breakage this test's own repair exists to stop.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed(&state, home.path(), "d/a.conf", "bx\n", Mode::DEFAULT_FILE);
    let heir = managed(
        &state,
        home.path(),
        "d/heir.conf",
        "bx\n",
        Mode::DEFAULT_FILE,
    );
    assert_eq!(
        entry_for(&state, home.path(), &portable)
            .expect("a.conf")
            .created_dirs
            .iter()
            .map(|dir| dir.render(home.path()))
            .collect::<Vec<_>>(),
        vec![home.child("d")],
        "a.conf claims the directory bx made",
    );
    assert!(
        entry_for(&state, home.path(), &heir)
            .expect("heir.conf")
            .created_dirs
            .is_empty(),
        "and heir.conf claims nothing yet",
    );
    std::fs::rename(home.child("d"), home.child("real")).expect("move the directory");
    std::os::unix::fs::symlink(home.child("real"), home.child("d")).expect("link it back");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(
        matches!(done.as_slice(), [Restored::Removed { .. }]),
        "{done:?}"
    );
    assert!(
        peek(&home.child("real/a.conf")).is_none(),
        "bx's file is gone"
    );
    assert!(
        std::fs::symlink_metadata(home.child("d"))
            .expect("the link stays")
            .file_type()
            .is_symlink()
    );
    assert!(home.child("real").is_dir(), "and so does what it names");
    assert!(!state.journal().exists(), "the session finished");
    assert!(entry_for(&state, home.path(), &portable).is_none());
    assert!(
        entry_for(&state, home.path(), &heir)
            .expect("heir.conf survives")
            .created_dirs
            .is_empty(),
        "a claim the user replaced with a symlink is not handed to the \
             entry beneath it",
    );

    let again = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(
        matches!(again.as_slice(), [Restored::Unmanaged { .. }]),
        "{again:?}"
    );
    // And the heir's own `rm` finishes: it inherited no claim to prune.
    let heir_done = restore(&state, home.path(), std::slice::from_ref(&heir)).expect("rm");
    assert!(
        matches!(heir_done.as_slice(), [Restored::Removed { .. }]),
        "{heir_done:?}"
    );
    assert!(peek(&home.child("real/heir.conf")).is_none());
    assert!(home.child("real").is_dir(), "the user's directory stays");
}

#[test]
fn a_user_file_inside_a_shared_created_directory_keeps_it() {
    for sharing in [Sharing::OneRm, Sharing::OneRmReversed, Sharing::SeparateRms] {
        assert_eq!(
            remove_two_sharing_a_created_dir(sharing, true),
            (true, true),
            "{sharing:?}"
        );
    }
}
