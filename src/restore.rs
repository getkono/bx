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
//! The one exception is a checkout bx cloned: its bytes are git's, so it is
//! deleted outside the journal, before the session opens, and made crash-safe
//! by the ledger alone ([`restore_with`] says how).
//!
//! # `plan` and `rm` share one function
//!
//! [`plan_restore`] decides what will happen to one target and writes nothing;
//! [`restore_with`] calls it and then does exactly what it said. That is Invariant 7
//! applied to the removal path: `rm` cannot do work its own preview did not
//! announce.

use std::path::{Path, PathBuf};

use crate::fs::{self, Kind, Mode};
use crate::git::Git;
use crate::journal::{self, Content, Ownership, Request, Session, SessionKind};
use crate::paths::Portable;
use crate::plan::external;
use crate::recover;
use crate::state::{
    self, Ledger, LedgerEntry, Mechanism, NewEntry, Prior, PriorBytes, RestoreRef, StateDir,
    clone_written,
};

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

/// [`restore_with`], asking the user's own `git` at `home`.
#[cfg(test)]
pub fn restore(
    state: &StateDir,
    home: &Path,
    targets: &[Portable],
) -> Result<Vec<Restored>, Error> {
    restore_with(state, home, targets, &Git::at_home(home))
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
/// half-done, and running `rm` again restores them. [`Error::Journal`] too
/// when a checkout cannot be removed.
///
/// # A checkout bx cloned
///
/// `git` is asked about it. A clone is not a write a journal can roll back —
/// its bytes are git's, not bx's — so it is removed outside the session, under
/// the same lock and before the session opens, by [`remove_clone`]. Every
/// other target is restored through the session as above. The results are in
/// the order of `targets`.
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
            ledger
                .hand_off_claims(home, &claims)
                .map_err(journal::Error::from)?;
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
            ledger
                .prune_claims(home, &created_dirs)
                .map_err(journal::Error::from)?;
            ledger
                .hand_off_claims(home, &created_dirs)
                .map_err(journal::Error::from)?;
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
            let text = match state::restore::read(session.state(), &reference) {
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
            // Verified before a single byte is written: `restore::read` rehashes
            // the blob and refuses if it does not match the digest that named
            // it. Restoring corrupted content over the user's file would be
            // worse than refusing.
            let bytes = match state::restore::read(session.state(), &reference) {
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
mod tests;
