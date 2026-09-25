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
//!   removed deepest-first while they are empty; one another managed file
//!   still holds is handed to that file's entry, so its own `rm` removes it,
//!   and one the user replaced with something that is not a directory is left.
//!   A claim is never simply dropped: a target handed back to the user, whose
//!   file stays where it is, gives its claims to a surviving entry beneath them
//!   the same way a removal does.
//!   The file is unlinked only while it is still the one the plan observed.
//! * **Never overwrite a later edit.** The destination's current digest is
//!   compared with the digest bx recorded when it last wrote the file. If they
//!   differ, the user has edited it since, and restoring the whole prior body
//!   over it would destroy bytes the user wrote. bx reports it and writes
//!   nothing. This is Invariant 1, and it does not lapse because the command is
//!   called `rm`.
//!
//! A directory target is held to the same rules with a mode in place of bytes:
//! only the directory is bx's, never what is inside it. One bx created is
//! removed while it is empty — one still holding anything is left, and handed
//! to a surviving entry beneath it — one bx narrowed gets its earlier mode
//! back, and one whose mode changed since bx set it is a conflict.
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

use crate::fs::{self, Kind, Mode};
use crate::journal::{self, Content, Ownership, Request, Session, SessionKind};
use crate::paths::Portable;
use crate::plan::external;
use crate::recover;
use crate::state::{
    Ledger, LedgerEntry, Mechanism, NewEntry, Prior, PriorBytes, RestoreRef, StateDir,
    clone_written,
};
use crate::sync::Git;

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
        /// What this plan observed at `dest`. The removal is checked against
        /// it, so a file that changed since is refused, not unlinked. Boxed,
        /// as in [`Restoration::Revert`].
        planned: Box<fs::Observed>,
    },
    /// bx displaced a file; its exact bytes and mode go back.
    Revert {
        /// The file to rewrite.
        dest: PathBuf,
        /// Where its prior bytes live, and the mode they had.
        reference: RestoreRef,
        /// What this plan observed at `dest`. The revert is staged against it,
        /// so a destination that changed since is refused, not reverted over.
        /// Boxed, because it holds the destination's bytes and the other
        /// variants hold a path.
        planned: Box<fs::Observed>,
    },
    /// bx created the directory; it is removed if it is empty, and so are the
    /// directories bx created for it. One still holding anything is left, and
    /// handed to a surviving entry beneath it if there is one.
    RemoveDir {
        /// The directory to remove.
        dest: PathBuf,
        /// Directories bx created on the way to it, deepest first.
        created_dirs: Vec<PathBuf>,
        /// What this plan observed at `dest`. The removal is checked against
        /// it, so a directory that changed since is refused.
        planned: Box<fs::Observed>,
    },
    /// bx changed the mode of a directory that was already there; the mode
    /// it had goes back. Nothing inside it is touched.
    RevertMode {
        /// The directory.
        dest: PathBuf,
        /// The mode it had before bx changed it.
        mode: Mode,
        /// What this plan observed at `dest`. The change is checked against
        /// it, so a directory that changed since is refused.
        planned: Box<fs::Observed>,
    },
    /// bx made the symlink; it is unlinked — never what it points at — and
    /// the directories bx created for it are removed while they are empty.
    RemoveLink {
        /// The link to remove.
        dest: PathBuf,
        /// Directories bx created on the way to it, deepest first.
        created_dirs: Vec<PathBuf>,
        /// What this plan observed at `dest`. The removal is checked against
        /// it, so a link retargeted since is refused, not unlinked.
        planned: Box<fs::Observed>,
    },
    /// bx replaced a symlink; the link it replaced goes back, holding the
    /// text it held.
    Relink {
        /// The link to put back.
        dest: PathBuf,
        /// Where the earlier link's text lives.
        reference: RestoreRef,
        /// What this plan observed at `dest`. The link is made against it, so
        /// a destination that changed since is refused.
        planned: Box<fs::Observed>,
    },
    /// bx cloned the git checkout, and nothing in it is anybody's but the
    /// remote's — or bx never finished it. The whole directory is removed, and
    /// the directories bx created for it are removed while they are empty.
    RemoveClone {
        /// The checkout to remove.
        dest: PathBuf,
        /// Directories bx created on the way to it, deepest first.
        created_dirs: Vec<PathBuf>,
    },
    /// bx changed a directory's mode and it is back at the mode it had before:
    /// there is nothing to put back. Only the ledger entry goes.
    Release {
        /// The directory.
        dest: PathBuf,
    },
    /// bx created the file or directory and it is already gone, or it is a
    /// directory whose mode bx changed and somebody has removed. Only the
    /// ledger entry goes: bx does not make a directory again to give it back.
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
/// A destination that cannot be stat'd or read, or whose parent cannot be, is
/// a [`Restoration::Conflict`], not an error: bx cannot compare it with what it
/// wrote, so `rm` writes nothing there, forgets nothing, and restores the
/// rest — and this preview says so, as `rm` does.
///
/// So is a destination whose parent is on the filesystem but does not resolve
/// to a directory — a dangling symlink, or a file — whatever prior bx
/// recorded. bx will not create the parent through or over what the user put
/// there, and cannot tell a file that is gone from one that is out of reach.
/// The note names the parent `~`-relative.
///
/// # Errors
///
/// [`Error::Read`] for a destination path that cannot be observed at all: one
/// with no parent, or with a `..` component.
pub fn plan_restore(entry: &LedgerEntry, home: &Path) -> Result<Restoration, Error> {
    plan_restore_with(entry, home, &Git::at_home(home))
}

/// [`plan_restore`], asking `git` about a checkout bx cloned.
///
/// # Errors
///
/// As [`plan_restore`].
pub fn plan_restore_with(
    entry: &LedgerEntry,
    home: &Path,
    git: &Git,
) -> Result<Restoration, Error> {
    let dest = entry.path.render(home);
    let observed = match fs::observe(&dest) {
        Ok(observed) => observed,
        Err(fs::Error::Read { source, .. }) => {
            return Ok(Restoration::Conflict {
                note: format!("cannot be read: {source}; bx wrote nothing and forgets nothing"),
                dest,
            });
        }
        // Not reached from a ledger entry. What is left of `observe`'s errors
        // is `NoParent` and `ParentComponent`, and `render` joins a non-empty
        // relative path onto an absolute home, so the destination always has
        // a parent; a `Portable` is lexically normalised and holds no `..`,
        // so only a home spelled with one could produce the second. Kept, so
        // the match stays total without a panic.
        Err(e) => return Err(e.into()),
    };
    // A parent that does not resolve is observed as an absent destination,
    // whichever prior bx recorded. Neither a revert nor a forget is sound
    // there: the write cannot be made through it, and bx cannot tell whether
    // the file is gone or only out of reach.
    if let Some(parent) = observed
        .parent
        .as_ref()
        .filter(|parent| parent.unusable().is_some())
    {
        return Ok(Restoration::Conflict {
            note: format!(
                "its parent {} does not resolve to a directory; \
                 bx wrote nothing and forgets nothing",
                crate::paths::to_portable(&parent.path, home),
            ),
            dest,
        });
    }
    if entry.mechanism == Mechanism::Dir {
        return Ok(plan_restore_dir(entry, home, dest, observed));
    }
    if entry.mechanism == Mechanism::Link {
        return Ok(plan_restore_link(entry, home, dest, observed));
    }
    if entry.mechanism == Mechanism::Clone {
        return Ok(plan_restore_clone(entry, home, dest, &observed, git));
    }

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
                planned: Box::new(observed.clone()),
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
                planned: Box::new(observed.clone()),
            },
            Prior::Existed(reference) => Restoration::Revert {
                dest,
                reference: reference.clone(),
                planned: Box::new(observed.clone()),
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

/// [`plan_restore`] for a directory target, from what was observed at `dest`.
///
/// Only the directory is bx's, never what is inside it, so the undo is a mode
/// or an empty directory's removal:
///
/// * Nothing there, whoever removed it, is [`Restoration::AlreadyGone`].
/// * A directory at the mode bx set is bx's: one bx created is
///   [`Restoration::RemoveDir`], and one that was already there gets its
///   earlier mode back — [`Restoration::RevertMode`], or
///   [`Restoration::Release`] when that is the mode it has.
/// * A directory at any other mode was changed since bx set it, and putting
///   the earlier mode back would undo that change; anything that is not a
///   directory is not what bx made. Both are a [`Restoration::Conflict`], and
///   nothing is forgotten.
fn plan_restore_dir(
    entry: &LedgerEntry,
    home: &Path,
    dest: PathBuf,
    observed: fs::Observed,
) -> Restoration {
    match (observed.kind, observed.mode) {
        (Kind::Absent, _) => Restoration::AlreadyGone { dest },
        (Kind::Dir, Some(mode)) if mode == entry.mode => match &entry.prior {
            Prior::Absent => Restoration::RemoveDir {
                created_dirs: entry
                    .created_dirs
                    .iter()
                    .map(|dir| dir.render(home))
                    .collect(),
                dest,
                planned: Box::new(observed),
            },
            Prior::Existed(reference) if reference.mode == mode => Restoration::Release { dest },
            Prior::Existed(reference) => Restoration::RevertMode {
                dest,
                mode: reference.mode,
                planned: Box::new(observed),
            },
        },
        (Kind::Dir, Some(mode)) => Restoration::Conflict {
            note: format!(
                "is a directory at {mode}, and bx left it at {}; putting back its earlier mode \
                 would undo that change, so bx is leaving it and forgetting nothing",
                entry.mode,
            ),
            dest,
        },
        (kind, _) => Restoration::Conflict {
            note: format!(
                "is {kind}, not the directory bx made; bx is leaving it and forgetting nothing"
            ),
            dest,
        },
    }
}

/// [`plan_restore`] for a symlink target, from what was observed at `dest`.
///
/// The rules a file follows, with a link's text in place of its bytes. Only
/// the link is bx's, never what it points at:
///
/// * nothing there: bx made the link and it is already gone,
///   [`Restoration::AlreadyGone`], or it replaced one, which goes back,
///   [`Restoration::Relink`], whoever removed it since;
/// * a link still holding the text bx left: [`Restoration::RemoveLink`] for
///   one bx made, [`Restoration::Relink`] for one it replaced;
/// * a link holding other text was retargeted since, and anything that is not
///   a link is not what bx made. Both are a [`Restoration::Conflict`], and
///   nothing is forgotten.
fn plan_restore_link(
    entry: &LedgerEntry,
    home: &Path,
    dest: PathBuf,
    observed: fs::Observed,
) -> Restoration {
    let put_back = |dest, planned| match &entry.prior {
        Prior::Absent => None,
        Prior::Existed(reference) => Some(Restoration::Relink {
            dest,
            reference: reference.clone(),
            planned,
        }),
    };
    match observed.kind {
        Kind::Absent => {
            put_back(dest.clone(), Box::new(observed)).unwrap_or(Restoration::AlreadyGone { dest })
        }
        Kind::Symlink if observed.link_digest() == Some(entry.written) => {
            let planned = Box::new(observed);
            put_back(dest.clone(), planned.clone()).unwrap_or_else(|| Restoration::RemoveLink {
                created_dirs: entry
                    .created_dirs
                    .iter()
                    .map(|dir| dir.render(home))
                    .collect(),
                dest,
                planned,
            })
        }
        Kind::Symlink => Restoration::Conflict {
            note: format!(
                "has been retargeted since bx made it (bx left {}); bx is leaving it and \
                 forgetting nothing",
                entry.written,
            ),
            dest,
        },
        kind => Restoration::Conflict {
            note: format!(
                "is {kind}, not the symlink bx made; bx is leaving it and forgetting nothing"
            ),
            dest,
        },
    }
}

/// [`plan_restore`] for a git checkout bx cloned, from what was observed at
/// `dest`.
///
/// The checkout is removed whole, and only when removing it loses nothing but
/// what the remote has:
///
/// * nothing there is [`Restoration::AlreadyGone`];
/// * a directory bx never finished cloning is [`Restoration::RemoveClone`] as
///   it stands — nothing in it was ever the user's;
/// * a finished checkout is [`Restoration::RemoveClone`] only when
///   `git status` shows nothing, ignored files aside, and every commit on any
///   ref, `HEAD` and the stash is on a remote-tracking branch or is the
///   commit bx left checked out. Anything else is a
///   [`Restoration::Conflict`] naming it, and nothing is forgotten;
/// * anything that is not a directory is not what bx cloned: a conflict.
fn plan_restore_clone(
    entry: &LedgerEntry,
    home: &Path,
    dest: PathBuf,
    observed: &fs::Observed,
    git: &Git,
) -> Restoration {
    let created_dirs = entry
        .created_dirs
        .iter()
        .map(|dir| dir.render(home))
        .collect();
    match observed.kind {
        Kind::Absent => Restoration::AlreadyGone { dest },
        Kind::Dir if entry.written == clone_written(None) => {
            Restoration::RemoveClone { dest, created_dirs }
        }
        Kind::Dir => match external::kept_by_rm(git, &dest, entry) {
            None => Restoration::RemoveClone { dest, created_dirs },
            Some(why) => Restoration::Conflict {
                note: format!("{why}; bx is leaving the checkout and forgetting nothing"),
                dest,
            },
        },
        kind => Restoration::Conflict {
            note: format!(
                "is {kind}, not the checkout bx cloned; bx is leaving it and forgetting nothing"
            ),
            dest,
        },
    }
}

/// Put back what bx displaced at each of `targets`, through a journalled
/// session.
///
/// Resolves any interrupted session first — `rm` is a writing command — then
/// opens a [`SessionKind::Restore`] session, so an `rm` interrupted halfway is
/// itself rolled back by the next run. Both happen under one exclusive lock
/// ([`recover::lock_for_writing`]), so a second bx cannot win the state
/// directory between the recovery and the session and be reported as an
/// interruption.
///
/// A target that conflicts is reported and skipped; the rest still restore. A
/// target bx has never written is [`Restored::Unmanaged`], which is what makes
/// running `rm` twice a no-op the second time.
///
/// A destination that cannot be read is one of those conflicts: bx cannot
/// compare it with what it wrote, so it writes nothing there and forgets
/// nothing. So is one whose parent does not resolve to a directory.
///
/// # Errors
///
/// [`Error::Recover`] when an earlier interruption cannot be resolved,
/// [`Error::Journal`] when the session fails, [`Error::State`] when a prior
/// snapshot cannot be read for a reason other than being missing or corrupt,
/// and [`Error::Read`] when a destination cannot be looked at at all. Each of
/// these stops `rm` where it is and leaves its journal, so the next writing
/// run rolls back every target this `rm` had already restored: nothing is left
/// half-done, and running `rm` again restores them.
pub fn restore(
    state: &StateDir,
    home: &Path,
    targets: &[Portable],
) -> Result<Vec<Restored>, Error> {
    restore_with(state, home, targets, &Git::at_home(home))
}

/// [`restore`], asking `git` about a checkout bx cloned.
///
/// A clone is not a write a journal can roll back — its bytes are git's, not
/// bx's — so it is removed outside the session, under the same lock and
/// before the session opens, by [`remove_clone`]. Every other target is
/// restored through the session exactly as [`restore`] says. The results are
/// in the order of `targets`.
///
/// # Errors
///
/// As [`restore`], and [`Error::Journal`] when a checkout cannot be removed.
pub fn restore_with(
    state: &StateDir,
    home: &Path,
    targets: &[Portable],
    git: &Git,
) -> Result<Vec<Restored>, Error> {
    // One lock across the recovery, the clones and the session: see
    // `recover::lock_for_writing`.
    let lock = recover::lock_for_writing(state)?;
    let mut done: Vec<Option<Restored>> = vec![None; targets.len()];
    let mut rest = Vec::with_capacity(targets.len());
    {
        let mut ledger = Ledger::open(state, &lock, home)
            .map_err(journal::Error::from)?
            .value;
        for (at, target) in targets.iter().enumerate() {
            let clone = ledger
                .get(target)
                .filter(|entry| entry.mechanism == Mechanism::Clone)
                .cloned();
            match clone {
                Some(entry) => done[at] = Some(remove_clone(&mut ledger, &entry, home, git)?),
                None => rest.push(at),
            }
        }
    }
    let scope = rest.iter().map(|at| targets[*at].clone()).collect();
    let mut session = Session::open_locked(state, SessionKind::Restore, home, scope, lock)?;
    for at in rest {
        done[at] = Some(restore_one(&mut session, &targets[at])?);
    }
    session.finish()?;
    Ok(done.into_iter().flatten().collect())
}

/// Remove one checkout bx cloned, as [`plan_restore_clone`] decides, and
/// forget it.
///
/// Crash-safe by the ledger alone. Before the first byte goes, the entry is
/// re-recorded as unfinished — [`clone_written`] of `None` — and saved, so a
/// removal that stops part way leaves an entry the next `rm` removes whole
/// and the next `apply` clones afresh, never a half-deleted directory taken
/// for the user's checkout. The entry is forgotten and saved only once the
/// directory is gone; the directories bx created for it are then removed
/// where empty, and a claim on one that still stands is handed to an entry
/// beneath it, as a session hands a removed file's claims.
fn remove_clone(
    ledger: &mut Ledger,
    entry: &LedgerEntry,
    home: &Path,
    git: &Git,
) -> Result<Restored, Error> {
    let target = entry.path.clone();
    match plan_restore_with(entry, home, git)? {
        Restoration::Conflict { dest, note } => Ok(Restored::Conflict { target, dest, note }),
        Restoration::AlreadyGone { dest } => {
            let claims: Vec<PathBuf> = entry.created_dirs.iter().map(|d| d.render(home)).collect();
            let _ = ledger.forget(&target);
            journal::hand_off_claims(ledger, home, &claims)?;
            ledger.save().map_err(journal::Error::from)?;
            Ok(Restored::AlreadyGone { target, dest })
        }
        Restoration::RemoveClone { dest, created_dirs } => {
            ledger
                .record(NewEntry::new(
                    target.clone(),
                    clone_written(None),
                    entry.mode,
                    Mechanism::Clone,
                    PriorBytes::Absent,
                ))
                .map_err(journal::Error::from)?;
            ledger.save().map_err(journal::Error::from)?;
            if std::fs::symlink_metadata(&dest).is_ok_and(|meta| meta.is_dir()) {
                std::fs::remove_dir_all(&dest).map_err(|source| journal::Error::Io {
                    path: dest.clone(),
                    source,
                })?;
            }
            let _ = ledger.forget(&target);
            journal::prune_claims(ledger, home, &created_dirs)?;
            journal::hand_off_claims(ledger, home, &created_dirs)?;
            ledger.save().map_err(journal::Error::from)?;
            Ok(Restored::Removed { target, dest })
        }
        // `plan_restore_clone` decides nothing else.
        _ => Ok(Restored::Conflict {
            target,
            dest: entry.path.render(home),
            note: "is a checkout bx cloned and cannot be removed; bx is leaving it and \
                   forgetting nothing"
                .to_string(),
        }),
    }
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
        Restoration::Release { dest } => {
            session.forget(target);
            Ok(Restored::Reverted {
                target: target.clone(),
                dest,
            })
        }
        Restoration::RemoveDir {
            dest,
            created_dirs,
            planned,
        } => {
            session.apply(Request {
                target: target.clone(),
                dest: dest.clone(),
                content: Content::DirAbsent {
                    created_dirs,
                    planned: *planned,
                },
                mode: entry.mode,
                ownership: Ownership::Released,
            })?;
            Ok(Restored::Removed {
                target: target.clone(),
                dest,
            })
        }
        Restoration::RevertMode {
            dest,
            mode,
            planned,
        } => {
            session.apply(Request {
                target: target.clone(),
                dest: dest.clone(),
                content: Content::Dir { planned: *planned },
                mode,
                ownership: Ownership::Released,
            })?;
            Ok(Restored::Reverted {
                target: target.clone(),
                dest,
            })
        }
        Restoration::RemoveLink {
            dest,
            created_dirs,
            planned,
        } => {
            session.apply(Request {
                target: target.clone(),
                dest: dest.clone(),
                content: Content::LinkAbsent {
                    created_dirs,
                    planned: *planned,
                },
                mode: entry.mode,
                ownership: Ownership::Released,
            })?;
            Ok(Restored::Removed {
                target: target.clone(),
                dest,
            })
        }
        Restoration::Relink {
            dest,
            reference,
            planned,
        } => {
            // The earlier text, verified as a file's bytes are before any is
            // written.
            let text = match session.ledger().restore_bytes(session.state(), &reference) {
                Ok(bytes) => PathBuf::from(
                    <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(bytes),
                ),
                Err(
                    e @ (crate::state::Error::RestoreMissing { .. }
                    | crate::state::Error::RestoreCorrupt { .. }),
                ) => {
                    return Ok(Restored::Conflict {
                        target: target.clone(),
                        dest,
                        note: format!("{e}; bx will not guess at the link it replaced"),
                    });
                }
                Err(e) => return Err(e.into()),
            };
            session.apply(Request {
                target: target.clone(),
                dest: dest.clone(),
                content: Content::Link {
                    text,
                    planned: *planned,
                },
                mode: reference.mode,
                ownership: Ownership::Released,
            })?;
            Ok(Restored::Reverted {
                target: target.clone(),
                dest,
            })
        }
        // A clone is removed by `remove_clone` before the session opens, so
        // one reaching a session is refused rather than removed unjournalled.
        Restoration::RemoveClone { dest, .. } => Ok(Restored::Conflict {
            target: target.clone(),
            dest,
            note: "is a checkout bx cloned, which rm removes only outside a session; bx is \
                   leaving it and forgetting nothing"
                .to_string(),
        }),
        Restoration::Remove {
            dest,
            created_dirs,
            planned,
        } => {
            session.apply(Request {
                target: target.clone(),
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs,
                    planned: *planned,
                },
                mode: entry.mode,
                ownership: Ownership::Released,
            })?;
            Ok(Restored::Removed {
                target: target.clone(),
                dest,
            })
        }
        Restoration::Revert {
            dest,
            reference,
            planned,
        } => {
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
                content: Content::Bytes {
                    bytes,
                    planned: *planned,
                },
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
        let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
        session
            .apply(write_to(home, rel, bytes, Mode::DEFAULT_FILE))
            .expect("apply");
        drop(session);
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
        // Review round 3, item 1. Rebuilding the ledger from this journal
        // re-recorded the second write with bx's first output as its prior; the
        // ledger took that for a third party's edit, adopted it, and `rm` then
        // handed back "bx one" instead of the user's file.
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
        // r3 round 1, Q. `plan_restore` returned `Error::Read` for a destination
        // it could not read, and `restore` dropped its session with `?`: the
        // journal stood, and the next writing run rolled back every target this
        // `rm` had already restored.
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
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        if std::fs::read(&unreadable).is_ok() {
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644))
                .expect("chmod back");
            return crate::journal::tests::cannot_build(
                "a_destination_rm_cannot_read_is_a_conflict_and_the_rest_still_restore",
                crate::journal::tests::WRITES_THROUGH_PERMISSIONS,
            );
        }

        let done = restore(&state, home.path(), &targets);
        let entry = entry_for(&state, home.path(), &targets[1]);
        let planned = entry.as_ref().map(|entry| plan_restore(entry, home.path()));
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
        // r3 round 2, P9R4-D1. A destination whose parent does not resolve is
        // observed as absent, so `plan_restore` said Revert (or AlreadyGone);
        // rm's write then failed with UnusableParent and stopped the whole rm,
        // and the next writing run rolled back the target it had restored.
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
            let preview = plan_restore(&entry, &home).expect("preview");
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
        // r3 coverage C4. `Restored::target` was reached only for `Unmanaged`
        // and `Conflict`.
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
        } = plan_restore(&entry, home.path()).expect("plan")
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
        // Review round 5, item 1. A removal carried no plan observation, so an
        // edit landing after `plan_restore` was unlinked, surviving only as a
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
        let plan = plan_restore(&entry, home.path()).expect("plan");
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
                let mut session =
                    Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
                        .expect("open");
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
        // Review round 5, item 4. Only the first write under a new directory
        // claims it, and pruning stopped at the first non-empty directory, so
        // removing the claiming target first left `~/.config/app` and `~/.config`.
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
        // Review round 5, item 4. The hand-off is bookkeeping, so recovery's
        // rebuild of a terminated journal makes it too.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (a, b) = (".config/app/a.toml", ".config/app/b.toml");
        let ta = managed(&state, home.path(), a, "a\n", Mode::DEFAULT_FILE);
        let tb = managed(&state, home.path(), b, "b\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), vec![ta.clone()])
                .expect("open");
        let entry = session.ledger().get(&ta).cloned().expect("managed");
        let Restoration::Remove {
            dest,
            created_dirs,
            planned,
        } = plan_restore(&entry, home.path()).expect("plan")
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
        // r3 coverage C1. `rm` of a file bx created that is already gone
        // forgets the entry and keeps its claims for the hand-off; nothing
        // pinned that those claims reach it.
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
        // Review round 5, item 4, and #8's open question: whichever entry
        // claims a directory, one the ledger still holds as a target stays.
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
        // r3 round 1, D1. The file went through the link, pruning the claimed
        // directory failed with ENOTDIR, and the session was left for a rollback
        // that put the file back: every `rm` after that did the same.
        //
        // Extended for r3 coverage COV3: `hand_off_claims`' guard for a claim
        // that is no longer a directory was reached with no entry beneath the
        // path, so deleting it changed no assertion. `heir.conf` is that
        // entry. Without the guard the claim on `~/d` lands on it, and the
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
    fn a_prior_snapshot_that_cannot_be_read_stops_rm_and_restores_nothing() {
        // r3 coverage C10. A missing or corrupt snapshot is a conflict; any
        // other failure to read one stops `rm`, as its documentation says.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
        let portable = managed(&state, home.path(), ".conf", "bx's\n", Mode::DEFAULT_FILE);
        let blob = state.restore().join(ContentHash::of(b"theirs\n").to_hex());
        std::fs::remove_file(&blob).expect("remove the snapshot");
        std::fs::create_dir(&blob).expect("a directory where the snapshot was");

        let err =
            restore(&state, home.path(), std::slice::from_ref(&portable)).expect_err("rm stops");
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
        // r3 coverage C11. `restore_one` returns the session's failure for a
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
                // `continue`, not `return`: r3 coverage COV1. Returning out of
                // the whole test meant the `remove` half's skip took the
                // `revert` half with it, and the revert half needs no
                // privilege this one lacks that the remove half does not.
                crate::journal::tests::cannot_build(
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

    /// Let bx make the directory `rel` at `mode`, and return its target.
    fn managed_dir(state: &StateDir, home: &Path, rel: &str, mode: Mode) -> Portable {
        let request = crate::journal::tests::dir_to(home, rel, mode);
        let portable = request.target.clone();
        let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
        session.apply(request).expect("apply");
        session.finish().expect("finish");
        portable
    }

    use crate::journal::tests::mode_at;

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
            plan_restore(&entry, home.path()).expect("plan"),
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
        } = plan_restore(&entry, home.path()).expect("plan")
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

    /// The variable the foreign-prior child finds its directory in.
    const FOREIGN_PRIOR_CHILD_DIR: &str = "BX_TEST_RESTORE_FOREIGN_PRIOR_DIR";

    /// What the foreign-prior child prints first, so a child that never
    /// started is told apart from one that ran and failed.
    const FOREIGN_PRIOR_CHILD_RAN: &str = "bx-restore-foreign-prior-child-ran";

    #[test]
    fn rm_restores_a_prior_mode_without_owner_read_at_that_mode() {
        // Integration of #8 @746fdc0. restore_one passes the recorded prior
        // mode to stage, which refused any mode without owner read until
        // 4a3248d, so a foreign 0004 file bx replaced could never be put back.
        // Only somebody else's file can be read at 0004, so the apply and the
        // rm run as another uid.
        const NAME: &str =
            "restore::tests::rm_restores_a_prior_mode_without_owner_read_at_that_mode";
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
    fn run_unprivileged_in_a_foreign_setgid_directory(
        name: &str,
        child_env: &str,
        seed: impl FnOnce(&Path),
    ) {
        use std::os::unix::fs::MetadataExt as _;

        // r3 coverage COV1. Not an `eprintln!` that passes: a scenario this
        // machine cannot build fails unless a human opted the skip in. See
        // `crate::journal::tests::cannot_build`.
        let skip = |why: &str| crate::journal::tests::cannot_build(name, why);
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

    /// Let bx make `rel` a link holding `text`, through a finished session.
    fn linked(state: &StateDir, home: &Path, rel: &str, text: &str) -> Portable {
        let request = crate::journal::tests::link_to(home, rel, text);
        let portable = request.target.clone();
        let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
        session.apply(request).expect("make the link");
        session.finish().expect("finish");
        portable
    }

    #[test]
    fn rm_removes_a_link_bx_made_with_the_directories_it_made_and_never_its_target() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        home.write("real/tool", "the tool\n");
        let portable = linked(&state, home.path(), ".opt/bin/tool", "../../real/tool");
        let linked_twice = linked(&state, home.path(), ".opt/bin/tool", "/elsewhere");
        assert_eq!(portable, linked_twice);

        assert!(matches!(
            plan_restore(
                &entry_for(&state, home.path(), &portable).expect("managed"),
                home.path()
            )
            .expect("plan"),
            Restoration::RemoveLink { .. }
        ));
        let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
        assert!(
            matches!(restored.as_slice(), [Restored::Removed { .. }]),
            "{restored:?}"
        );
        assert!(
            std::fs::symlink_metadata(home.child(".opt")).is_err(),
            "all gone"
        );
        assert_eq!(
            std::fs::read(home.child("real/tool")).expect("kept"),
            b"the tool\n",
            "what a link points at is never touched"
        );
        assert!(entry_for(&state, home.path(), &portable).is_none());

        let again = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
        assert!(matches!(again.as_slice(), [Restored::Unmanaged { .. }]));
    }

    #[test]
    fn rm_leaves_a_link_retargeted_since_and_anything_that_is_not_a_link() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let retargeted = linked(&state, home.path(), ".a", "/opt/a");
        std::fs::remove_file(home.child(".a")).expect("unlink");
        std::os::unix::fs::symlink("/opt/theirs", home.child(".a")).expect("retarget");
        let replaced = linked(&state, home.path(), ".b", "/opt/b");
        std::fs::remove_file(home.child(".b")).expect("unlink");
        home.write(".b", "a file now\n");
        let gone = linked(&state, home.path(), ".c", "/opt/c");
        std::fs::remove_file(home.child(".c")).expect("unlink");

        let restored = restore(
            &state,
            home.path(),
            &[retargeted.clone(), replaced.clone(), gone.clone()],
        )
        .expect("rm");
        let [
            Restored::Conflict { note: first, .. },
            Restored::Conflict { note: second, .. },
            Restored::AlreadyGone { .. },
        ] = restored.as_slice()
        else {
            panic!("{restored:?}");
        };
        assert!(first.contains("retargeted since bx made it"), "{first}");
        assert!(second.contains("not the symlink bx made"), "{second}");
        assert_eq!(
            std::fs::read_link(home.child(".a")).expect("kept"),
            Path::new("/opt/theirs")
        );
        assert_eq!(
            std::fs::read(home.child(".b")).expect("kept"),
            b"a file now\n"
        );
        assert!(entry_for(&state, home.path(), &retargeted).is_some());
        assert!(entry_for(&state, home.path(), &replaced).is_some());
        assert!(entry_for(&state, home.path(), &gone).is_none());
    }

    #[test]
    fn rm_puts_back_the_link_bx_replaced() {
        // No `apply` records a link bx replaced — a link bx did not make is a
        // conflict — so the entry is recorded directly, as an adoption would.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".tool");
        {
            let lock = crate::state::ExclusiveLock::acquire(&state).expect("lock");
            let mut ledger = crate::state::Ledger::open(&state, &lock, home.path())
                .expect("open the ledger")
                .value;
            ledger
                .record(crate::state::NewEntry::new(
                    portable.clone(),
                    fs::link::digest(Path::new("/opt/bx")),
                    Mode::LINK,
                    Mechanism::Link,
                    crate::state::PriorBytes::Bytes {
                        bytes: b"/opt/theirs".to_vec(),
                        mode: Mode::LINK,
                    },
                ))
                .expect("record");
            ledger.save().expect("save");
        }
        std::os::unix::fs::symlink("/opt/bx", &dest).expect("bx's link");

        let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
        assert!(
            matches!(restored.as_slice(), [Restored::Reverted { .. }]),
            "{restored:?}"
        );
        assert_eq!(
            std::fs::read_link(&dest).expect("a link"),
            Path::new("/opt/theirs")
        );
        assert!(entry_for(&state, home.path(), &portable).is_none());
    }

    #[test]
    fn every_link_bx_makes_is_removed_by_rm_with_the_directories_it_made() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let links = [
            linked(&state, home.path(), ".local/bin/one", "../../one"),
            linked(&state, home.path(), ".config/deep/two", "/opt/two"),
        ];
        restore(&state, home.path(), &links).expect("rm");
        assert!(std::fs::symlink_metadata(home.child(".local/bin")).is_err());
        assert!(std::fs::symlink_metadata(home.child(".config")).is_err());
    }
}
