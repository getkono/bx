use super::*;

use crate::fs::Mode;
use crate::journal::tests::{
    applied, apply_session, interrupted, peek, plant_file, target, write_to,
};
use crate::journal::{Session, SessionKind};
use crate::state::{ContentHash, LedgerView, Prior};
use crate::testing::guarded_home;

mod claims;
mod directories;
mod links;

/// Let bx write `rel`, so the ledger records exactly what it displaced.
fn managed(state: &StateDir, home: &Path, rel: &str, bytes: &str, mode: Mode) -> Portable {
    let request = write_to(home, rel, bytes, mode);
    let portable = request.target.clone();
    applied(state, home, vec![request]);
    portable
}

/// The ledger entry for `portable`, as it stands on disk.
fn entry_for(
    state: &StateDir,
    home: &Path,
    portable: &Portable,
) -> Option<crate::state::LedgerEntry> {
    LedgerView::read(state, home)
        .expect("read the ledger")
        .value
        .get(portable)
        .cloned()
}

/// Every blob in `restore/`, and every blob the ledger references.
fn blobs_on_disk_and_referenced(
    state: &StateDir,
    home: &Path,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let on_disk = std::fs::read_dir(state.restore())
        .map(|entries| {
            entries
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        })
        .unwrap_or_default();
    let referenced = LedgerView::read(state, home)
        .expect("read the ledger")
        .value
        .iter()
        .flat_map(|(_, entry)| {
            let prior = match &entry.prior {
                Prior::Existed(reference) => Some(reference.blob_name()),
                Prior::Absent => None,
            };
            prior.into_iter().chain(
                entry
                    .superseded
                    .iter()
                    .map(crate::state::RestoreRef::blob_name),
            )
        })
        .collect();
    (on_disk, referenced)
}

/// Apply `rel` in a session that dies between its `End` frame and its
/// ledger save, then let recovery rebuild the ledger from the journal.
fn applied_through_recovery(state: &StateDir, home: &Path, rel: &str, bytes: &str) {
    interrupted(
        state,
        home,
        vec![write_to(home, rel, bytes, Mode::DEFAULT_FILE)],
    );
    crate::journal::tests::seal(&state.journal(), 1);
    assert_eq!(
        crate::recover::recover(state).expect("recover"),
        crate::recover::Outcome::Recorded { entries: 1 },
    );
}

/// Two applies and an `rm`: the file and every directory bx created go.
fn two_applies_then_rm_leaves_nothing(through_recovery: bool) {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let rel = ".config/newdir/x.conf";
    assert!(!home.child(".config").exists(), "bx creates ~/.config here");

    let portable = managed(&state, home.path(), rel, "x = 1\n", Mode::DEFAULT_FILE);
    if through_recovery {
        applied_through_recovery(&state, home.path(), rel, "x = 1\n");
    } else {
        managed(&state, home.path(), rel, "x = 1\n", Mode::DEFAULT_FILE);
    }
    assert_eq!(
        entry_for(&state, home.path(), &portable)
            .expect("managed")
            .created_dirs
            .iter()
            .map(Portable::as_str)
            .collect::<Vec<_>>(),
        ["~/.config/newdir", "~/.config"],
        "the second apply created no directory, and forgot none",
    );

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(
        matches!(restored.as_slice(), [Restored::Removed { .. }]),
        "{restored:?}"
    );
    assert!(!home.child(rel).exists(), "x.conf is gone");
    assert!(!home.child(".config/newdir").exists(), "newdir is gone");
    assert!(
        !home.child(".config").exists(),
        "~/.config, which bx created, is gone"
    );
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn two_applies_then_rm_removes_the_file_and_every_directory_bx_created() {
    two_applies_then_rm_leaves_nothing(false);
}

#[test]
fn two_applies_then_rm_removes_every_directory_bx_created_after_a_rebuild() {
    two_applies_then_rm_leaves_nothing(true);
}

/// bx creates `~/.foo`, the user replaces it, a second session writes over
/// it, and `rm` must hand back the user's bytes, not unlink them.
fn rm_restores_a_file_the_user_put_over_bxs(through_recovery: bool) {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".foo");

    let portable = managed(&state, home.path(), ".foo", "bx one\n", Mode::DEFAULT_FILE);
    plant_file(&dest, "the user's own\n", Mode::PRIVATE_FILE);
    if through_recovery {
        applied_through_recovery(&state, home.path(), ".foo", "bx two\n");
    } else {
        managed(&state, home.path(), ".foo", "bx two\n", Mode::DEFAULT_FILE);
    }

    let entry = entry_for(&state, home.path(), &portable).expect("managed");
    let Prior::Existed(reference) = &entry.prior else {
        panic!("the user's bytes must be the prior, got {:?}", entry.prior);
    };
    assert_eq!(reference.digest, ContentHash::of(b"the user's own\n"));
    // Nothing the sessions stored is an orphan the ledger cannot name.
    let (on_disk, referenced) = blobs_on_disk_and_referenced(&state, home.path());
    assert_eq!(on_disk, referenced, "every blob in restore/ is indexed");
    assert!(on_disk.contains(&reference.blob_name()));

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(
        matches!(restored.as_slice(), [Restored::Reverted { .. }]),
        "restored, not removed: {restored:?}"
    );
    assert_eq!(
        peek(&dest),
        Some((b"the user's own\n".to_vec(), Mode::PRIVATE_FILE)),
        "the user's bytes and mode are back",
    );
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn rm_restores_bytes_the_user_put_over_a_file_bx_created() {
    rm_restores_a_file_the_user_put_over_bxs(false);
}

#[test]
fn rm_restores_bytes_the_user_put_over_a_file_bx_created_after_a_rebuild() {
    rm_restores_a_file_the_user_put_over_bxs(true);
}

/// The on-disk state of a session that died inside `finish` after the ledger
/// was saved and before the journal was unlinked: the saved ledger already
/// holds the session's writes, and a terminated journal still stands.
fn finished_but_left_its_journal(state: &StateDir, home: &Path, rel: &str, bytes: &str) {
    let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
    session
        .apply(write_to(home, rel, bytes, Mode::DEFAULT_FILE))
        .expect("apply");
    let journal = std::fs::read(state.journal()).expect("the journal in flight");
    session.finish().expect("finish");
    std::fs::write(state.journal(), journal).expect("put the journal back");
    crate::journal::tests::seal(&state.journal(), 1);
}

#[test]
fn rm_after_a_crash_between_the_save_and_the_unlink_restores_the_users_original() {
    // Rebuilding the ledger from this journal must not re-record the second
    // write with bx's first output as its prior: the ledger would take that
    // for a third party's edit, adopt it, and `rm` would then hand back
    // "bx one" instead of the user's file.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "the user's original\n", Mode::PRIVATE_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx one\n", Mode::DEFAULT_FILE);
    finished_but_left_its_journal(&state, home.path(), ".conf", "bx two\n");
    let saved = entry_for(&state, home.path(), &portable).expect("managed");

    assert!(matches!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::Recorded { .. },
    ));
    assert_eq!(
        entry_for(&state, home.path(), &portable).expect("still managed"),
        saved,
        "a ledger that already holds the write is left exactly as it was",
    );

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(
        matches!(restored.as_slice(), [Restored::Reverted { .. }]),
        "{restored:?}"
    );
    assert_eq!(
        peek(&dest),
        Some((b"the user's original\n".to_vec(), Mode::PRIVATE_FILE)),
    );
}

#[test]
fn a_rewrite_over_a_user_edit_interrupted_before_the_save_still_adopts_the_edit() {
    // The case a rebuild that skipped every intent whose `after` the saved
    // ledger already holds would get wrong: bx writes the same bytes it wrote
    // last time over a file the user edited in between, and dies before the
    // save. The saved ledger holds those bytes already, but not the edit.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "the user's original\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx\n", Mode::DEFAULT_FILE);
    plant_file(&dest, "the user's edit\n", Mode::PRIVATE_FILE);
    applied_through_recovery(&state, home.path(), ".conf", "bx\n");

    let entry = entry_for(&state, home.path(), &portable).expect("managed");
    let Prior::Existed(reference) = &entry.prior else {
        panic!("the user's edit must be the prior, got {:?}", entry.prior);
    };
    assert_eq!(reference.digest, ContentHash::of(b"the user's edit\n"));

    restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert_eq!(
        peek(&dest),
        Some((b"the user's edit\n".to_vec(), Mode::PRIVATE_FILE)),
    );
}

#[test]
fn restore_puts_back_the_exact_bytes_and_the_exact_mode() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".ssh-config");
    // A file whose mode matters: a moment at 0644 would make ssh refuse it.
    plant_file(&dest, "Host bastion\n", Mode::PRIVATE_FILE);
    let portable = managed(
        &state,
        home.path(),
        ".ssh-config",
        "Host bastion\n  User bx\n",
        Mode::DEFAULT_FILE,
    );
    assert_eq!(peek(&dest).expect("bx wrote it").1, Mode::DEFAULT_FILE);

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert!(
        matches!(done.as_slice(), [Restored::Reverted { .. }]),
        "{done:?}"
    );
    assert_eq!(
        peek(&dest).expect("restored"),
        (b"Host bastion\n".to_vec(), Mode::PRIVATE_FILE),
        "exact bytes and exact mode, not one or the other",
    );
    assert!(
        entry_for(&state, home.path(), &portable).is_none(),
        "and bx no longer manages it",
    );
    assert!(
        !state.journal().exists(),
        "the restore session closed cleanly"
    );
}

#[test]
fn a_file_bx_created_is_removed_not_emptied() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed(
        &state,
        home.path(),
        ".config/deep/made.conf",
        "made\n",
        Mode::DEFAULT_FILE,
    );
    let dest = home.child(".config/deep/made.conf");
    assert!(dest.is_file());

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert!(
        matches!(done.as_slice(), [Restored::Removed { .. }]),
        "{done:?}"
    );
    assert!(
        !dest.exists(),
        "absence and emptiness are different states, and only one is what the user had",
    );
    assert!(!home.child(".config/deep").exists());
    assert!(!home.child(".config").exists());
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn restore_removes_the_directories_bx_created_and_nothing_else() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed(
        &state,
        home.path(),
        ".config/deep/made.conf",
        "made\n",
        Mode::DEFAULT_FILE,
    );
    // The user has since put something of their own in bx's directory.
    std::fs::write(home.child(".config/deep/theirs"), "mine").expect("write");

    restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert!(!home.child(".config/deep/made.conf").exists());
    assert!(
        home.child(".config/deep/theirs").is_file(),
        "the walk stops at the first directory that is not empty",
    );
    assert!(home.child(".config/deep").is_dir());
    assert!(home.child(".config").is_dir());
}

#[test]
fn a_file_edited_since_bx_wrote_it_is_a_conflict_not_an_overwrite() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);
    plant_file(&dest, "bx's\nand a line of mine\n", Mode::DEFAULT_FILE);

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    let [conflict] = done.as_slice() else {
        panic!("{done:?}")
    };
    assert!(conflict.is_conflict());
    assert_eq!(conflict.target(), &portable);
    let Restored::Conflict { note, .. } = conflict else {
        unreachable!()
    };
    assert!(note.contains("edited since bx wrote it"), "{note}");
    assert_eq!(
        peek(&dest).expect("untouched").0,
        b"bx's\nand a line of mine\n",
        "restoring the prior body would destroy bytes the user wrote",
    );
    assert!(
        entry_for(&state, home.path(), &portable).is_some(),
        "bx still manages it, so `rm` can be retried once the user has decided",
    );
}

#[test]
fn an_edited_file_nothing_declares_is_kept_byte_for_byte_and_forgotten() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);
    let created = managed(&state, home.path(), ".new", "bx's\n", Mode::DEFAULT_FILE);
    plant_file(&dest, "bx's\nand a line of mine\n", Mode::PRIVATE_FILE);
    plant_file(&home.child(".new"), "mine now\n", Mode::DEFAULT_FILE);
    let entry = entry_for(&state, home.path(), &portable).expect("managed");
    let git = Git::at_home(home.path());

    // Declared, `rm` would refuse; undeclared, it plans to keep the file.
    assert!(matches!(
        plan_restore_with(&entry, home.path(), &git).expect("plan"),
        Restoration::Conflict { .. }
    ));
    assert_eq!(
        plan_restore_undeclared(&entry, home.path(), &git).expect("plan"),
        Restoration::Keep { dest: dest.clone() }
    );

    let both = [portable.clone(), created.clone()];
    let undeclared: BTreeSet<Portable> = both.iter().cloned().collect();
    let done =
        restore_undeclared_with(&state, home.path(), &both, &undeclared, &git).expect("restore");
    assert_eq!(
        done,
        [
            Restored::Kept {
                target: portable.clone(),
                dest: dest.clone(),
            },
            Restored::Kept {
                target: created.clone(),
                dest: home.child(".new"),
            },
        ]
    );
    assert!(done.iter().all(|done| !done.is_conflict()));
    assert_eq!(
        peek(&dest),
        Some((b"bx's\nand a line of mine\n".to_vec(), Mode::PRIVATE_FILE)),
        "not a byte or a mode bit changed",
    );
    assert_eq!(
        peek(&home.child(".new")).expect("not removed").0,
        b"mine now\n",
        "a file bx created and the user edited is not unlinked",
    );
    assert!(entry_for(&state, home.path(), &portable).is_none());
    assert!(entry_for(&state, home.path(), &created).is_none());

    // Forgotten, so a second `rm` has nothing to do.
    let again =
        restore_undeclared_with(&state, home.path(), &both, &undeclared, &git).expect("again");
    assert!(
        again
            .iter()
            .all(|done| matches!(done, Restored::Unmanaged { .. })),
        "{again:?}"
    );
}

#[test]
fn an_undeclared_file_still_bxs_is_restored_and_other_drift_still_conflicts() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let kept = managed(&state, home.path(), ".kept", "bx's\n", Mode::DEFAULT_FILE);
    let dir = home.child(".dir");
    let replaced = managed(&state, home.path(), ".dir", "bx's\n", Mode::DEFAULT_FILE);
    std::fs::remove_file(&dir).expect("rm");
    std::fs::create_dir(&dir).expect("a directory in its place");
    let targets = [kept.clone(), replaced.clone()];
    let undeclared: BTreeSet<Portable> = targets.iter().cloned().collect();

    let done = restore_undeclared_with(
        &state,
        home.path(),
        &targets,
        &undeclared,
        &Git::at_home(home.path()),
    )
    .expect("restore");
    assert!(
        matches!(done[0], Restored::Removed { .. }),
        "undeclared and unedited is undone as ever: {done:?}"
    );
    assert!(done[1].is_conflict(), "only an edit is released: {done:?}");
    assert!(!home.child(".kept").exists());
    assert!(dir.is_dir());
    assert!(entry_for(&state, home.path(), &replaced).is_some());
}

#[test]
fn a_destination_that_is_no_longer_a_file_is_a_conflict() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);
    std::fs::remove_file(&dest).expect("remove");
    std::fs::create_dir(&dest).expect("a directory in its place");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert!(done[0].is_conflict(), "{done:?}");
    assert!(dest.is_dir(), "and bx wrote nothing");
}

#[test]
fn restore_verifies_the_blob_digest_before_writing() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);

    let blob = state.restore().join(ContentHash::of(b"theirs\n").to_hex());
    std::fs::write(&blob, "something else entirely").expect("corrupt the snapshot");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    let Restored::Conflict { note, .. } = &done[0] else {
        panic!("{done:?}")
    };
    assert!(note.contains("does not match"), "{note}");
    assert_eq!(
        peek(&dest).expect("untouched").0,
        b"bx's\n",
        "corrupted content is never written over the user's file",
    );
}

#[test]
fn a_missing_snapshot_is_reported_rather_than_guessed_at() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".conf"), "theirs\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);
    std::fs::remove_file(state.restore().join(ContentHash::of(b"theirs\n").to_hex()))
        .expect("delete the snapshot");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    let Restored::Conflict { note, .. } = &done[0] else {
        panic!("{done:?}")
    };
    assert!(note.contains("will not guess"), "{note}");
}

#[test]
fn restore_of_an_already_absent_create_is_not_an_error() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let portable = managed(&state, home.path(), ".made", "made\n", Mode::DEFAULT_FILE);
    std::fs::remove_file(home.child(".made")).expect("the user removed it");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert!(
        matches!(done.as_slice(), [Restored::AlreadyGone { .. }]),
        "{done:?}"
    );
    assert!(
        entry_for(&state, home.path(), &portable).is_none(),
        "bx stops managing it, which is what `rm` was asked for",
    );
}

#[test]
fn an_absent_file_bx_had_displaced_still_gets_its_prior_bytes_back() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::PRIVATE_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);
    std::fs::remove_file(&dest).expect("remove");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert!(
        matches!(done.as_slice(), [Restored::Reverted { .. }]),
        "{done:?}"
    );
    assert_eq!(
        peek(&dest).expect("restored"),
        (b"theirs\n".to_vec(), Mode::PRIVATE_FILE),
        "the user asked to unmanage it, and putting their original back is the promise",
    );
}

#[test]
fn a_target_bx_never_wrote_is_unmanaged() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, _) = target(home.path(), ".never-touched");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert_eq!(
        done,
        vec![Restored::Unmanaged {
            target: portable.clone()
        }],
    );
    assert_eq!(done[0].target(), &portable);
}

#[test]
fn restore_run_twice_changes_nothing_the_second_time() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);

    restore(&state, home.path(), std::slice::from_ref(&portable)).expect("first");
    let after_first = peek(&dest).expect("restored");

    let done = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("second");
    assert!(
        matches!(done.as_slice(), [Restored::Unmanaged { .. }]),
        "{done:?}"
    );
    assert_eq!(peek(&dest).expect("still restored"), after_first);
}

#[test]
fn one_conflicting_target_does_not_stop_the_others() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".a"), "a-theirs\n", Mode::DEFAULT_FILE);
    plant_file(&home.child(".b"), "b-theirs\n", Mode::DEFAULT_FILE);
    let a = managed(&state, home.path(), ".a", "a-bx\n", Mode::DEFAULT_FILE);
    let b = managed(&state, home.path(), ".b", "b-bx\n", Mode::DEFAULT_FILE);
    plant_file(&home.child(".a"), "a-edited\n", Mode::DEFAULT_FILE);

    let done = restore(&state, home.path(), &[a, b]).expect("restore");
    assert!(done[0].is_conflict());
    assert!(!done[1].is_conflict());
    assert_eq!(peek(&home.child(".a")).expect("skipped").0, b"a-edited\n");
    assert_eq!(peek(&home.child(".b")).expect("restored").0, b"b-theirs\n");
}

#[test]
fn a_destination_rm_cannot_read_is_a_conflict_and_the_rest_still_restore() {
    // Were `plan_restore_with` to return `Error::Read` for a destination
    // it cannot read, `restore` would drop its session with `?`: the
    // journal would stand, and the next writing run roll back every target
    // this `rm` had already restored.
    use std::os::unix::fs::PermissionsExt as _;

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut targets = Vec::new();
    for rel in [".a", ".b", ".c"] {
        plant_file(
            &home.child(rel),
            &format!("{rel} theirs\n"),
            Mode::DEFAULT_FILE,
        );
        targets.push(managed(
            &state,
            home.path(),
            rel,
            &format!("{rel} bx\n"),
            Mode::DEFAULT_FILE,
        ));
    }
    let unreadable = home.child(".b");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::read(&unreadable).is_ok() {
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644))
            .expect("chmod back");
        return crate::testing::cannot_build(
            "a_destination_rm_cannot_read_is_a_conflict_and_the_rest_still_restore",
            crate::journal::tests::WRITES_THROUGH_PERMISSIONS,
        );
    }

    let done = restore(&state, home.path(), &targets);
    let entry = entry_for(&state, home.path(), &targets[1]);
    let planned = entry
        .as_ref()
        .map(|entry| plan_restore_with(entry, home.path(), &Git::at_home(home.path())));
    // Before any assertion, so the tempdir can be removed whatever happens.
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644))
        .expect("chmod back");

    let done = done.expect("an unreadable destination does not stop rm");
    assert!(
        matches!(
            done.as_slice(),
            [
                Restored::Reverted { .. },
                Restored::Conflict { .. },
                Restored::Reverted { .. }
            ]
        ),
        "{done:?}"
    );
    let Restored::Conflict { note, .. } = &done[1] else {
        unreachable!()
    };
    assert!(note.contains("cannot be read"), "{note}");
    assert_eq!(peek(&home.child(".a")).expect("restored").0, b".a theirs\n");
    assert_eq!(peek(&home.child(".c")).expect("restored").0, b".c theirs\n");
    assert_eq!(peek(&unreadable).expect("left").0, b".b bx\n");
    assert!(!state.journal().exists(), "the session finished");
    assert!(entry.is_some(), "bx forgets nothing about the conflict");
    assert!(entry_for(&state, home.path(), &targets[0]).is_none());
    assert!(
        matches!(planned, Some(Ok(Restoration::Conflict { .. }))),
        "the preview says what rm did: {planned:?}"
    );
}

#[test]
fn an_rm_target_whose_parent_does_not_resolve_is_a_conflict_and_the_rest_still_restore() {
    // A destination whose parent does not resolve is observed as absent.
    // Were `plan_restore_with` to say Revert (or AlreadyGone) for it, rm's
    // write would fail with UnusableParent and stop the whole rm, and the
    // next writing run would roll back the target it had restored.
    let guard = guarded_home();
    for displaced in [true, false] {
        let case = format!("the second target displaced a file: {displaced}");
        let home = guard.child(format!("displaced-{displaced}"));
        let state = StateDir::resolve(&home);
        plant_file(
            &home.join(".first.conf"),
            "user first\n",
            Mode::DEFAULT_FILE,
        );
        let first = managed(
            &state,
            &home,
            ".first.conf",
            "bx first\n",
            Mode::DEFAULT_FILE,
        );
        if displaced {
            plant_file(
                &home.join(".linked/app.conf"),
                "user app\n",
                Mode::DEFAULT_FILE,
            );
        }
        let second = managed(
            &state,
            &home,
            ".linked/app.conf",
            "bx app\n",
            Mode::DEFAULT_FILE,
        );
        // `~/.linked` becomes a link into a checkout that is not mounted.
        std::fs::remove_dir_all(home.join(".linked")).expect("rm the directory");
        std::os::unix::fs::symlink(home.join("unmounted/linked"), home.join(".linked"))
            .expect("link");

        let entry = entry_for(&state, &home, &second).expect("managed");
        let preview = plan_restore_with(&entry, &home, &Git::at_home(&home)).expect("preview");
        let Restoration::Conflict { note, dest } = &preview else {
            panic!("{case}: the preview is a conflict: {preview:?}");
        };
        assert_eq!(*dest, home.join(".linked/app.conf"), "{case}");
        assert!(
            note.contains("its parent ~/.linked does not resolve"),
            "{case}: {note}"
        );
        assert!(!note.contains(&*home.to_string_lossy()), "{case}: {note}");

        let done = restore(&state, &home, &[first.clone(), second.clone()])
            .expect("an unusable parent does not stop rm");
        assert!(
            matches!(
                done.as_slice(),
                [Restored::Reverted { .. }, Restored::Conflict { .. }]
            ),
            "{case}: {done:?}"
        );
        let Restored::Conflict { note: reported, .. } = &done[1] else {
            unreachable!()
        };
        assert_eq!(reported, note, "{case}: rm says what the preview said");
        assert_eq!(
            peek(&home.join(".first.conf")).expect("restored").0,
            b"user first\n",
            "{case}"
        );
        assert!(!state.journal().exists(), "{case}: the session finished");
        assert!(entry_for(&state, &home, &first).is_none(), "{case}");
        assert!(
            entry_for(&state, &home, &second).is_some(),
            "{case}: bx forgets nothing about the conflict"
        );

        assert_eq!(
            crate::recover::recover(&state).expect("the next writing run"),
            crate::recover::Outcome::Nothing,
            "{case}"
        );
        assert_eq!(
            peek(&home.join(".first.conf")).expect("still restored").0,
            b"user first\n",
            "{case}: nothing rolled back"
        );
    }
}

#[test]
fn every_outcome_names_the_target_it_is_about() {
    // `Restored::target` for every outcome, not only `Unmanaged` and
    // `Conflict`.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".reverted"), "theirs\n", Mode::DEFAULT_FILE);
    let reverted = managed(&state, home.path(), ".reverted", "bx\n", Mode::DEFAULT_FILE);
    let removed = managed(&state, home.path(), ".removed", "bx\n", Mode::DEFAULT_FILE);
    let gone = managed(&state, home.path(), ".gone", "bx\n", Mode::DEFAULT_FILE);
    std::fs::remove_file(home.child(".gone")).expect("the user removes it");
    let conflict = managed(&state, home.path(), ".conflict", "bx\n", Mode::DEFAULT_FILE);
    plant_file(&home.child(".conflict"), "edited\n", Mode::DEFAULT_FILE);
    let unmanaged = target(home.path(), ".unmanaged").0;
    let targets = vec![reverted, removed, gone, unmanaged, conflict];

    let done = restore(&state, home.path(), &targets).expect("rm");
    assert!(
        matches!(
            done.as_slice(),
            [
                Restored::Reverted { .. },
                Restored::Removed { .. },
                Restored::AlreadyGone { .. },
                Restored::Unmanaged { .. },
                Restored::Conflict { .. },
            ]
        ),
        "{done:?}"
    );
    assert_eq!(
        done.iter().map(Restored::target).collect::<Vec<_>>(),
        targets.iter().collect::<Vec<_>>(),
    );
}

#[test]
fn restore_is_journalled_and_an_interrupted_restore_recovers() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::PRIVATE_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);

    // A restore session that dies halfway is exactly an apply session that
    // dies halfway, and the same machinery undoes it.
    let entry = entry_for(&state, home.path(), &portable).expect("managed");
    let Restoration::Revert {
        reference, planned, ..
    } = plan_restore_with(&entry, home.path(), &Git::at_home(home.path())).expect("plan")
    else {
        panic!("a displaced file is reverted")
    };
    let bytes = crate::state::restore::read(&state, &reference).expect("the snapshot");
    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    session
        .apply(crate::journal::Request {
            target: portable.clone(),
            dest: dest.clone(),
            content: crate::journal::Content::Bytes {
                bytes,
                planned: *planned,
            },
            mode: reference.mode,
            ownership: crate::journal::Ownership::Released,
        })
        .expect("apply");
    drop(session);

    let interrupted = recover::pending(&state)
        .expect("pending")
        .expect("an interrupted restore");
    assert_eq!(interrupted.kind, SessionKind::Restore);
    assert_eq!(peek(&dest).expect("mid-restore").0, b"theirs\n");

    assert!(matches!(
        recover::recover(&state).expect("recover"),
        recover::Outcome::RolledBack { .. },
    ));
    assert_eq!(
        peek(&dest).expect("rolled back"),
        (b"bx's\n".to_vec(), Mode::DEFAULT_FILE),
        "the rollback puts the file back the way the last finished run left it",
    );
    assert!(
        entry_for(&state, home.path(), &portable).is_some(),
        "and the ledger never moved, because a session saves it only at the end",
    );

    // And the restore then runs to completion.
    restore(&state, home.path(), std::slice::from_ref(&portable)).expect("restore");
    assert_eq!(
        peek(&dest).expect("restored"),
        (b"theirs\n".to_vec(), Mode::PRIVATE_FILE),
    );
}

#[test]
fn restore_resolves_an_earlier_interruption_before_it_writes() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".a"), "a-theirs\n", Mode::DEFAULT_FILE);
    plant_file(&home.child(".b"), "b-theirs\n", Mode::DEFAULT_FILE);
    let a = managed(&state, home.path(), ".a", "a-bx\n", Mode::DEFAULT_FILE);

    // An apply that never finished, over a different target.
    let mut session = apply_session(&state, home.path());
    session
        .apply(write_to(home.path(), ".b", "b-bx\n", Mode::DEFAULT_FILE))
        .expect("apply");
    drop(session);

    let done = restore(&state, home.path(), std::slice::from_ref(&a)).expect("restore");
    assert!(
        matches!(done.as_slice(), [Restored::Reverted { .. }]),
        "{done:?}"
    );
    assert_eq!(
        peek(&home.child(".b")).expect("rolled back").0,
        b"b-theirs\n",
        "the interruption was rolled back first",
    );
    assert_eq!(peek(&home.child(".a")).expect("restored").0, b"a-theirs\n");
}

#[test]
fn restore_refuses_while_an_interruption_cannot_be_resolved() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".a"), "a-theirs\n", Mode::DEFAULT_FILE);
    plant_file(&home.child(".b"), "b-theirs\n", Mode::DEFAULT_FILE);
    let a = managed(&state, home.path(), ".a", "a-bx\n", Mode::DEFAULT_FILE);

    let mut session = apply_session(&state, home.path());
    session
        .apply(write_to(home.path(), ".b", "b-bx\n", Mode::DEFAULT_FILE))
        .expect("apply");
    drop(session);
    // Somebody edited the interrupted target afterwards.
    plant_file(&home.child(".b"), "b-edited\n", Mode::DEFAULT_FILE);

    let err = restore(&state, home.path(), std::slice::from_ref(&a))
        .expect_err("a writing command must refuse over an unresolved interruption");
    assert!(
        matches!(err, Error::Recover(recover::Error::Blocked { .. })),
        "got {err}",
    );
    assert_eq!(
        peek(&home.child(".a")).expect("untouched").0,
        b"a-bx\n",
        "and nothing was restored",
    );
}

#[test]
fn plan_restore_says_exactly_what_restore_then_does() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".modified"), "theirs\n", Mode::PRIVATE_FILE);
    let modified = managed(
        &state,
        home.path(),
        ".modified",
        "bx's\n",
        Mode::DEFAULT_FILE,
    );
    let created = managed(
        &state,
        home.path(),
        ".config/made.conf",
        "made\n",
        Mode::DEFAULT_FILE,
    );

    let ledger = LedgerView::read(&state, home.path())
        .expect("read the ledger")
        .value;
    let plan_for = |portable: &Portable| {
        plan_restore_with(
            ledger.get(portable).expect("managed"),
            home.path(),
            &Git::at_home(home.path()),
        )
        .expect("plan")
    };

    match plan_for(&modified) {
        Restoration::Revert {
            dest, reference, ..
        } => {
            assert_eq!(dest, home.child(".modified"));
            assert_eq!(reference.digest, ContentHash::of(b"theirs\n"));
            assert_eq!(reference.mode, Mode::PRIVATE_FILE);
            assert_eq!(reference.len, 7);
        }
        other => panic!("{other:?}"),
    }
    match plan_for(&created) {
        Restoration::Remove {
            dest,
            created_dirs,
            planned,
        } => {
            assert_eq!(planned.path, home.child(".config/made.conf"));
            assert_eq!(dest, home.child(".config/made.conf"));
            assert_eq!(created_dirs, vec![home.child(".config")]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(ledger.get(&created).expect("managed").prior, Prior::Absent);

    // Nothing was written by planning.
    assert_eq!(
        peek(&home.child(".modified")).expect("still bx's").0,
        b"bx's\n"
    );
    assert!(home.child(".config/made.conf").is_file());

    let done = restore(&state, home.path(), &[modified, created]).expect("restore");
    assert!(
        matches!(
            done.as_slice(),
            [Restored::Reverted { .. }, Restored::Removed { .. }],
        ),
        "{done:?}",
    );
    assert_eq!(
        peek(&home.child(".modified")).expect("reverted"),
        (b"theirs\n".to_vec(), Mode::PRIVATE_FILE),
    );
    assert!(!home.child(".config/made.conf").exists());
    assert!(!home.child(".config").exists());
}

#[test]
fn an_edit_between_plan_restore_and_the_removal_is_kept_and_nothing_is_unlinked() {
    // A removal carries plan's observation; without it, an edit landing
    // after `plan_restore_with` would be unlinked, surviving only as a
    // blob nothing named.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let rel = ".config/app/created.conf";
    let portable = managed(&state, home.path(), rel, "bx created\n", Mode::DEFAULT_FILE);
    let dest = home.child(rel);

    let mut session = Session::open(
        &state,
        SessionKind::Restore,
        home.path(),
        vec![portable.clone()],
    )
    .expect("open");
    let entry = session.ledger().get(&portable).cloned().expect("managed");
    let plan = plan_restore_with(&entry, home.path(), &Git::at_home(home.path())).expect("plan");
    plant_file(
        &dest,
        "the user's edit after rm's plan\n",
        Mode::DEFAULT_FILE,
    );
    let Restoration::Remove {
        dest: to,
        created_dirs,
        planned,
    } = plan
    else {
        panic!("{plan:?}")
    };
    let err = session
        .apply(Request {
            target: portable.clone(),
            dest: to,
            content: Content::Absent {
                created_dirs,
                planned: *planned,
            },
            mode: entry.mode,
            ownership: Ownership::Released,
        })
        .expect_err("the destination changed since rm's plan");
    assert!(
        matches!(err, journal::Error::Write(fs::Error::Changed { .. })),
        "got {err}"
    );
    let finished = session.finish().expect_err("the session is poisoned");
    assert!(
        matches!(finished, journal::Error::Poisoned { .. }),
        "got {finished}"
    );

    assert_eq!(
        peek(&dest).expect("kept").0,
        b"the user's edit after rm's plan\n"
    );
    assert!(home.child(".config/app").is_dir());
    assert!(
        crate::journal::load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .is_none(),
        "refused before its Intent: nothing was stored or announced",
    );
    assert_eq!(
        recover::recover(&state).expect("recover"),
        recover::Outcome::RolledBack { undone: 0 },
    );
    assert_eq!(
        peek(&dest).expect("recovery touched nothing").0,
        b"the user's edit after rm's plan\n"
    );
    assert!(entry_for(&state, home.path(), &portable).is_some());
}

#[test]
fn a_prior_snapshot_that_cannot_be_read_stops_rm_and_restores_nothing() {
    // A missing or corrupt snapshot is a conflict; any
    // other failure to read one stops `rm`, as its documentation says.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);
    let blob = state.restore().join(ContentHash::of(b"theirs\n").to_hex());
    std::fs::remove_file(&blob).expect("remove the snapshot");
    std::fs::create_dir(&blob).expect("a directory where the snapshot was");

    let err = restore(&state, home.path(), std::slice::from_ref(&portable)).expect_err("rm stops");
    assert!(
        // The state layer refuses to read a snapshot that is not a
        // regular file, and that refusal is neither of the two verdicts.
        matches!(
            err,
            Error::State(crate::state::Error::RestoreNotAFile { .. })
        ),
        "got {err}"
    );
    assert_eq!(peek(&dest).expect("untouched").0, b"bx's\n");
    assert!(entry_for(&state, home.path(), &portable).is_some());
}

#[test]
fn a_write_rm_cannot_make_is_the_sessions_own_error() {
    // `restore_one` returns the session's failure for a
    // removal and for a revert, not the `Poisoned` a later `finish` gives.
    let guard = guarded_home();
    for revert in [false, true] {
        let case = if revert { "revert" } else { "remove" };
        let home = guard.child(case);
        std::fs::create_dir_all(&home).expect("the home");
        let state = StateDir::resolve(&home);
        let rel = "locked/app.conf";
        if revert {
            plant_file(&home.join(rel), "theirs\n", Mode::DEFAULT_FILE);
        }
        let portable = managed(&state, &home, rel, "bx\n", Mode::DEFAULT_FILE);
        let locked = home.join("locked");
        fs::set_mode(&locked, Mode::from_bits(0o555)).expect("make it read-only");
        if !crate::journal::tests::permissions_refuse(&locked) {
            fs::set_mode(&locked, Mode::DEFAULT_DIR).expect("make it writable again");
            // `continue`, not `return`: returning out of the whole test
            // would let the `remove` half's skip take the
            // `revert` half with it, and the revert half needs no
            // privilege this one lacks that the remove half does not.
            crate::testing::cannot_build(
                "a_write_rm_cannot_make_is_the_sessions_own_error",
                crate::journal::tests::WRITES_THROUGH_PERMISSIONS,
            );
            continue;
        }
        let result = restore(&state, &home, std::slice::from_ref(&portable));
        // Before any assertion, so the tempdir can be removed whatever happens.
        fs::set_mode(&locked, Mode::DEFAULT_DIR).expect("make it writable again");

        let err = result.expect_err(case);
        if revert {
            assert!(
                matches!(err, Error::Journal(journal::Error::Write(_))),
                "{case}: got {err}"
            );
        } else {
            assert!(
                matches!(err, Error::Journal(journal::Error::Io { .. })),
                "{case}: got {err}"
            );
        }
        assert_eq!(peek(&home.join(rel)).expect("untouched").0, b"bx\n");
        assert!(state.journal().exists(), "{case}: left for the next run");
        assert!(entry_for(&state, &home, &portable).is_some(), "{case}");
    }
}

/// The variable the foreign-prior child finds its directory in.
#[cfg(target_os = "linux")]
const FOREIGN_PRIOR_CHILD_DIR: &str = "BX_TEST_RESTORE_FOREIGN_PRIOR_DIR";

/// What the foreign-prior child prints first, so a child that never
/// started is told apart from one that ran and failed.
#[cfg(target_os = "linux")]
const FOREIGN_PRIOR_CHILD_RAN: &str = "bx-restore-foreign-prior-child-ran";

// `unshare` user namespaces are Linux's.
#[cfg(target_os = "linux")]
#[test]
fn rm_restores_a_prior_mode_without_owner_read_at_that_mode() {
    // Integration of #8 @746fdc0. restore_one passes the recorded prior
    // mode to stage, which refused any mode without owner read until
    // 4a3248d, so a foreign 0004 file bx replaced could never be put back.
    // Only somebody else's file can be read at 0004, so the apply and the
    // rm run as another uid.
    const NAME: &str = "restore::tests::rm_restores_a_prior_mode_without_owner_read_at_that_mode";
    let theirs = "theirs\n";
    let recorded = Mode::from_bits(0o004);

    if let Some(dir) = std::env::var_os(FOREIGN_PRIOR_CHILD_DIR) {
        println!("{FOREIGN_PRIOR_CHILD_RAN}");
        let home = PathBuf::from(dir).join("home");
        let state = StateDir::resolve(&home);
        let dest = home.join("foreign");

        let portable = managed(&state, &home, "foreign", "managed\n", Mode::DEFAULT_FILE);
        let entry = entry_for(&state, &home, &portable).expect("managed");
        let Prior::Existed(reference) = &entry.prior else {
            panic!("the foreign file must be the prior, got {:?}", entry.prior);
        };
        assert_eq!(reference.mode, recorded, "the prior mode is recorded");

        let done = restore(&state, &home, std::slice::from_ref(&portable))
            .expect("rm restores a prior mode without owner read");
        assert!(
            matches!(done.as_slice(), [Restored::Reverted { .. }]),
            "{done:?}"
        );
        let on_disk = std::fs::symlink_metadata(&dest).expect("restored");
        assert_eq!(
            Mode::from_bits(std::os::unix::fs::PermissionsExt::mode(
                &on_disk.permissions()
            )),
            recorded,
            "restored at the recorded mode",
        );
        fs::set_mode(&dest, Mode::DEFAULT_FILE).expect("unlock for the assertion");
        assert_eq!(std::fs::read(&dest).expect("read"), theirs.as_bytes());
        assert!(entry_for(&state, &home, &portable).is_none());
        assert!(!state.journal().exists(), "the rm session closed cleanly");
        // What this uid made, so the parent can remove its tempdir.
        std::fs::remove_dir_all(home.join(".local")).expect("tidy the state directory");
        return;
    }

    run_unprivileged_in_a_foreign_setgid_directory(NAME, FOREIGN_PRIOR_CHILD_DIR, |dir| {
        let home = dir.join("home");
        std::fs::create_dir(&home).expect("the home");
        fs::set_mode(&home, Mode::from_bits(0o777)).expect("a home uid 1 can write in");
        plant_file(&home.join("foreign"), theirs, recorded);
    });
}

/// Run the test `name` again as uid 1 with no supplementary groups, inside
/// a user namespace, with `child_env` naming a world-writable setgid
/// directory owned by a group that uid is not in. `seed` fills the
/// directory first, as this user, who is somebody else to uid 1.
///
/// The pattern of `fs::atomic`'s harness of the same name, whose test
/// module is private to it. Skips, with a message on stderr, wherever the
/// scenario cannot be constructed; fails only when the child ran and
/// failed.
#[cfg(target_os = "linux")]
fn run_unprivileged_in_a_foreign_setgid_directory(
    name: &str,
    child_env: &str,
    seed: impl FnOnce(&Path),
) {
    use std::os::unix::fs::MetadataExt as _;

    // Not an `eprintln!` that passes: a scenario this
    // machine cannot build fails unless a human opted the skip in. See
    // `crate::testing::cannot_build`.
    let skip = |why: &str| crate::testing::cannot_build(name, why);
    let home = guarded_home();
    // Another uid has to reach the directory and run this test binary.
    fs::set_mode(home.path(), Mode::DEFAULT_DIR).expect("open the home to traversal");
    let exe = home.child("bx-test");
    if let Err(e) = std::fs::copy(std::env::current_exe().expect("the test binary"), &exe) {
        return skip(&format!("the test binary could not be copied: {e}"));
    }
    fs::set_mode(&exe, Mode::from_bits(0o755)).expect("chmod the copy");
    let dir = home.child("shared");
    std::fs::create_dir(&dir).expect("mkdir");
    seed(&dir);

    let in_namespace = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new("unshare")
            .args(["--map-auto", "--map-root-user", "--"])
            .args(args)
            .env(child_env, &dir)
            .output()
    };
    for step in [
        [
            std::ffi::OsStr::new("chown"),
            "0:5".as_ref(),
            dir.as_os_str(),
        ],
        ["chmod".as_ref(), "2777".as_ref(), dir.as_os_str()],
    ] {
        match in_namespace(&step) {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                return skip(&format!(
                    "{step:?} in a user namespace failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            Err(e) => return skip(&format!("unshare could not run: {e}")),
        }
    }
    let meta = std::fs::metadata(&dir).expect("stat");
    if meta.mode() & 0o2000 == 0 || meta.gid() == rustix::process::getegid().as_raw() {
        return skip("the directory is not setgid to a foreign group");
    }

    let child = in_namespace(&[
        "setpriv".as_ref(),
        "--reuid=1".as_ref(),
        "--regid=1".as_ref(),
        "--clear-groups".as_ref(),
        "--".as_ref(),
        exe.as_os_str(),
        "--exact".as_ref(),
        name.as_ref(),
        "--nocapture".as_ref(),
    ]);
    let out = match child {
        Ok(out) => out,
        Err(e) => return skip(&format!("unshare could not run: {e}")),
    };
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    if !stdout.contains(FOREIGN_PRIOR_CHILD_RAN) {
        return skip(&format!("the unprivileged child did not start: {stderr}"));
    }
    assert!(
        out.status.success(),
        "the unprivileged child failed:\n{stdout}\n{stderr}"
    );
}
