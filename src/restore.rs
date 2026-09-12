//! `bx rm`: putting back exactly what bx displaced.
//!
//! The first half of `CLAUDE.md` Invariant 4 — *every write is recorded with the
//! prior bytes, so `rm` restores exactly*. [`crate::state::Ledger`] holds the
//! record; this module spends it.
//!
//! Four rules, each an invariant obligation rather than a preference:
//!
//! * **Exact bytes.** The blob is read from `restore/` and its digest verified
//!   before a single byte is written. A blob that is missing, or whose bytes do
//!   not hash to the digest that named them, is a conflict — never a guess.
//! * **Exact mode.** The mode comes from the prior snapshot and is set on the
//!   staged temporary file *before* the rename, so the restored file never
//!   exists at a wider mode than it had. That matters most for a file like
//!   `~/.ssh/config`, which a moment at `0644` would make unusable.
//! * **Absence, not emptiness.** A file bx created is unlinked, never truncated:
//!   "there is no file" and "there is an empty file" are different states, and
//!   only one of them is what the user had. Directories bx created are then
//!   removed deepest-first while they are empty.
//! * **Never overwrite a later edit.** The destination's current digest is
//!   compared with the digest bx recorded when it last wrote the file. If they
//!   differ, the user has edited it since, and restoring the whole prior body
//!   over it would destroy bytes the user wrote. bx reports it and writes
//!   nothing. This is Invariant 1, and it does not lapse because the command is
//!   called `rm`.
//!
//! A restore is a [`Session`] like any other write, so an interrupted `rm` is
//! detected and rolled back by the same machinery as an interrupted `apply`.
//!
//! # `plan` and `rm` share one function
//!
//! [`plan_restore`] decides what will happen to one target and writes nothing;
//! [`restore`] calls it and then does exactly what it said. That is Invariant 7
//! applied to the removal path: `rm` cannot do work its own preview did not
//! announce.

use std::path::{Path, PathBuf};

use crate::fs::{self, Kind};
use crate::journal::{self, Content, Ownership, Request, Session, SessionKind};
use crate::paths::Portable;
use crate::recover;
use crate::state::{LedgerEntry, Prior, RestoreRef, StateDir};

/// Everything that can go wrong restoring.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The session failed.
    #[error(transparent)]
    Journal(#[from] journal::Error),
    /// An earlier interruption stands and could not be resolved.
    #[error(transparent)]
    Recover(#[from] recover::Error),
    /// The state directory failed.
    #[error(transparent)]
    State(#[from] crate::state::Error),
    /// A destination could not be read.
    #[error(transparent)]
    Read(#[from] fs::Error),
}

/// What `rm` will do to one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restoration {
    /// bx created the file; it is unlinked and the directories bx created for it
    /// are removed while they are empty.
    Remove {
        /// The file to remove.
        dest: PathBuf,
        /// Directories bx created on the way to it, deepest first.
        created_dirs: Vec<PathBuf>,
    },
    /// bx displaced a file; its exact bytes and mode go back.
    Revert {
        /// The file to rewrite.
        dest: PathBuf,
        /// Where its prior bytes live, and the mode they had.
        reference: RestoreRef,
    },
    /// bx created the file and it is already gone. Only the ledger entry goes.
    AlreadyGone {
        /// The file that is not there.
        dest: PathBuf,
    },
    /// Something bx does not account for is at the destination. Reported and
    /// skipped, never overwritten.
    Conflict {
        /// The destination.
        dest: PathBuf,
        /// Why bx will not touch it.
        note: String,
    },
}

/// What `rm` did to one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restored {
    /// The prior bytes and mode were put back.
    Reverted {
        /// The target.
        target: Portable,
        /// Where it is.
        dest: PathBuf,
    },
    /// The file bx created was removed.
    Removed {
        /// The target.
        target: Portable,
        /// Where it was.
        dest: PathBuf,
    },
    /// The file bx created was already gone; bx stopped managing it.
    AlreadyGone {
        /// The target.
        target: Portable,
        /// Where it was.
        dest: PathBuf,
    },
    /// bx has never written this target, so there is nothing to put back.
    Unmanaged {
        /// The target.
        target: Portable,
    },
    /// Something else is there; bx wrote nothing.
    Conflict {
        /// The target.
        target: Portable,
        /// Where it is.
        dest: PathBuf,
        /// Why bx would not touch it.
        note: String,
    },
}

impl Restored {
    /// Whether bx left the destination alone and a human has to look.
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict { .. })
    }

    /// The target this is about.
    #[must_use]
    pub const fn target(&self) -> &Portable {
        match self {
            Self::Reverted { target, .. }
            | Self::Removed { target, .. }
            | Self::AlreadyGone { target, .. }
            | Self::Unmanaged { target }
            | Self::Conflict { target, .. } => target,
        }
    }
}

/// Decide what `rm` will do to one target, reading the destination and writing
/// nothing.
///
/// # Errors
///
/// [`Error::Read`] when the destination cannot be stat'd or read.
pub fn plan_restore(entry: &LedgerEntry, home: &Path) -> Result<Restoration, Error> {
    let dest = entry.path.render(home);
    let observed = fs::observe(&dest)?;

    match (observed.kind, observed.digest()) {
        (Kind::Absent, _) => Ok(match &entry.prior {
            // bx created it and it is already gone: there is nothing to put back
            // and nothing to remove.
            Prior::Absent => Restoration::AlreadyGone { dest },
            // The user asked bx to stop managing it, and putting their original
            // back is what `rm` promises — whoever removed it in the meantime.
            Prior::Existed(reference) => Restoration::Revert {
                dest,
                reference: reference.clone(),
            },
        }),
        (Kind::File, Some(digest)) if digest == entry.written => Ok(match &entry.prior {
            Prior::Absent => Restoration::Remove {
                created_dirs: entry
                    .created_dirs
                    .iter()
                    .map(|dir| dir.render(home))
                    .collect(),
                dest,
            },
            Prior::Existed(reference) => Restoration::Revert {
                dest,
                reference: reference.clone(),
            },
        }),
        (Kind::File, _) => Ok(Restoration::Conflict {
            note: format!(
                "has been edited since bx wrote it (bx left {}); \
                 restoring the file bx replaced would destroy those edits, \
                 so bx is leaving it and forgetting nothing",
                entry.written,
            ),
            dest,
        }),
        (kind, _) => Ok(Restoration::Conflict {
            note: format!("is {kind}, not the file bx wrote"),
            dest,
        }),
    }
}

/// Put back what bx displaced at each of `targets`, through a journalled
/// session.
///
/// Resolves any interrupted session first — `rm` is a writing command — then
/// opens a [`SessionKind::Restore`] session, so an `rm` interrupted halfway is
/// itself rolled back by the next run.
///
/// A target that conflicts is reported and skipped; the rest still restore. A
/// target bx has never written is [`Restored::Unmanaged`], which is what makes
/// running `rm` twice a no-op the second time.
///
/// # Errors
///
/// [`Error::Recover`] when an earlier interruption cannot be resolved,
/// [`Error::Journal`] when the session fails, and [`Error::Read`] when a
/// destination cannot be read.
pub fn restore(
    state: &StateDir,
    home: &Path,
    targets: &[Portable],
) -> Result<Vec<Restored>, Error> {
    recover::before_writing(state)?;

    let mut session = Session::open(state, SessionKind::Restore, home, targets.to_vec())?;
    let mut done = Vec::with_capacity(targets.len());
    for target in targets {
        done.push(restore_one(&mut session, target)?);
    }
    session.finish()?;
    Ok(done)
}

/// Restore one target inside an open session.
fn restore_one(session: &mut Session, target: &Portable) -> Result<Restored, Error> {
    let Some(entry) = session.ledger().get(target).cloned() else {
        return Ok(Restored::Unmanaged {
            target: target.clone(),
        });
    };

    match plan_restore(&entry, session.home())? {
        Restoration::AlreadyGone { dest } => {
            session.forget(target);
            Ok(Restored::AlreadyGone {
                target: target.clone(),
                dest,
            })
        }
        Restoration::Conflict { dest, note } => Ok(Restored::Conflict {
            target: target.clone(),
            dest,
            note,
        }),
        Restoration::Remove { dest, created_dirs } => {
            session.apply(Request {
                target: target.clone(),
                dest: dest.clone(),
                content: Content::Absent { created_dirs },
                mode: entry.mode,
                ownership: Ownership::Released,
            })?;
            Ok(Restored::Removed {
                target: target.clone(),
                dest,
            })
        }
        Restoration::Revert { dest, reference } => {
            // Verified before a single byte is written: `restore_bytes` rehashes
            // the blob and refuses if it does not match the digest that named
            // it. Restoring corrupted content over the user's file would be
            // worse than refusing.
            let bytes = match session.ledger().restore_bytes(session.state(), &reference) {
                Ok(bytes) => bytes,
                Err(
                    e @ (crate::state::Error::RestoreMissing { .. }
                    | crate::state::Error::RestoreCorrupt { .. }),
                ) => {
                    return Ok(Restored::Conflict {
                        target: target.clone(),
                        dest,
                        note: format!("{e}; bx will not guess at the bytes it displaced"),
                    });
                }
                Err(e) => return Err(e.into()),
            };
            session.apply(Request {
                target: target.clone(),
                dest: dest.clone(),
                content: Content::Bytes(bytes),
                mode: reference.mode,
                ownership: Ownership::Released,
            })?;
            Ok(Restored::Reverted {
                target: target.clone(),
                dest,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fs::Mode;
    use crate::journal::tests::{peek, plant_file, target, write_to};
    use crate::journal::{Session, SessionKind};
    use crate::state::{ContentHash, LedgerView, Prior};
    use crate::testing::guarded_home;

    /// Let bx write `rel`, so the ledger records exactly what it displaced.
    fn managed(state: &StateDir, home: &Path, rel: &str, bytes: &str, mode: Mode) -> Portable {
        let request = write_to(home, rel, bytes, mode);
        let portable = request.target.clone();
        let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
        session.apply(request).expect("apply");
        session.finish().expect("finish");
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
    fn restore_is_journalled_and_an_interrupted_restore_recovers() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "theirs\n", Mode::PRIVATE_FILE);
        let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);

        // A restore session that dies halfway is exactly an apply session that
        // dies halfway, and the same machinery undoes it.
        let entry = entry_for(&state, home.path(), &portable).expect("managed");
        let Restoration::Revert { reference, .. } =
            plan_restore(&entry, home.path()).expect("plan")
        else {
            panic!("a displaced file is reverted")
        };
        let bytes = LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value
            .restore_bytes(&state, &reference)
            .expect("the snapshot");
        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
        session
            .apply(crate::journal::Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: crate::journal::Content::Bytes(bytes),
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
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
            plan_restore(ledger.get(portable).expect("managed"), home.path()).expect("plan")
        };

        match plan_for(&modified) {
            Restoration::Revert { dest, reference } => {
                assert_eq!(dest, home.child(".modified"));
                assert_eq!(reference.digest, ContentHash::of(b"theirs\n"));
                assert_eq!(reference.mode, Mode::PRIVATE_FILE);
                assert_eq!(reference.len, 7);
            }
            other => panic!("{other:?}"),
        }
        match plan_for(&created) {
            Restoration::Remove { dest, created_dirs } => {
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
}
