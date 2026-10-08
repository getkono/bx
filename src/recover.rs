//! Detecting an interrupted session, and undoing it.
//!
//! The second half of `CLAUDE.md` Invariant 4: *an interrupted `apply` must be
//! detectable and recoverable*. [`pending`] is the detection, [`recover`] is the
//! undo, and `abandon` is the escape when the undo cannot be taken.
//!
//! # Roll back, not forward
//!
//! Recovery **aborts** the interrupted transaction. Every [`Intent`] in the
//! journal is undone, including the ones that reached `Done`, because a
//! partially applied plan is not a state the user ever saw.
//!
//! Rolling *forward* was rejected on two grounds. The first is Invariant 7
//! inverted: `apply` must never do work `plan` did not announce, and completing
//! an interrupted session performs writes that no `plan` the user has seen
//! announced, because the plan that announced them belongs to a run that is
//! over. The second is self-containment: a rollback needs only `journal.mpk` and
//! the `restore/` blobs, both `fsync`ed before any destination was touched, so
//! it can always complete; a roll-forward would have to re-render the new bytes
//! from the configuration, in the one code path that has to work when everything
//! else is broken.
//!
//! Nothing is lost but time. `apply` is idempotent by Invariant 3, so the next
//! run re-announces and redoes the work — this time with a `plan` behind it.
//!
//! # Who recovers, and who only reports
//!
//! A **writing** command that recovers and then writes in the same run — `rm`
//! today — calls [`lock_for_writing`] first, which recovers under the state
//! directory's lock, refuses to go on if it cannot, and hands that same lock to
//! the session it is about to open, so no second bx can win the directory in
//! between. Nothing in the type system makes such a command use it rather than
//! [`recover`] followed by a fresh [`journal::Session::open`]; what makes it the
//! obvious one is that `lock_for_writing` is the only call that produces the
//! guard [`journal::Session::open_locked`] consumes, and the only one that
//! turns a blocked recovery into a refusal.
//!
//! `apply` is the exception, because recovery is itself work `plan` must
//! announce (Invariant 7). It reads the interruption with [`pending`], refuses
//! before rolling anything back when a write cannot be accounted for, shows the
//! rows recovery would make for approval, and once approved calls [`recover`] —
//! turning an [`Outcome::Blocked`] it returns into [`Error::Blocked`] itself —
//! and stops without opening a session. The next run decides the configured
//! targets against the disk recovery left.
//!
//! A **read-only** command — `plan`, `status`, `doctor` — calls [`pending`] and
//! writes nothing. It reports each write the session named as the row recovery
//! would make of it: a write to roll back as an [`Action::Modify`] with its
//! diff, one already holding what was there before as [`Action::Unchanged`]
//! (or a modify naming the directories recovery removes where empty), every
//! write of a session that finished as [`Action::Unchanged`], and a write
//! recovery cannot account for as an [`Action::Conflict`] naming `abandon`.
//! It exits [`Exit::Pending`] whatever the rows are. That is what keeps `plan` usable from CI, a prompt segment or a login
//! banner.
//!
//! # Why recovery is not itself journalled
//!
//! A journal of the journal has the same problem one level down. Recovery is
//! made **idempotent and re-runnable** instead, which is strictly stronger: each
//! step is a pure function of the journal and the destination's current bytes,
//! and lands the destination in one of two digest-identified states through the
//! same atomic writer. Re-reading the table after any crash produces the same
//! verdict, or the "nothing to do" verdict.
//!
//! One ordering rule makes that hold: **the journal is unlinked last** — or set
//! aside last, when bytes were discarded from it — after every step has
//! succeeded. Crash before that and the next run repeats a recovery that
//! converges; crash after it and there was nothing left to do.
//!
//! # When recovery is blocked
//!
//! If any destination holds bytes that are neither the state before the session
//! nor the state it was writing, somebody changed it after the crash. bx reports
//! it and leaves it: Invariant 1 says never to overwrite a byte the user wrote,
//! and that does not lapse because a crash happened. The journal is **not**
//! unlinked, so every writing command keeps refusing until it is resolved, and
//! the message names the file, both digests it could legitimately hold, and
//! `abandon` as the way out.
//!
//! A destination whose parent no longer resolves to a directory blocks
//! recovery the same way: bx can neither confirm what is there nor write the
//! undo through it, and the message names the parent and `abandon`.
//!
//! [`Action::Modify`]: crate::report::Action::Modify
//! [`Action::Unchanged`]: crate::report::Action::Unchanged
//! [`Action::Conflict`]: crate::report::Action::Conflict
//! [`Exit::Pending`]: crate::report::Exit::Pending
//! [`Intent`]: crate::journal::Intent

use std::path::PathBuf;

use crate::fs::{self, remove};
use crate::journal::{self, SessionKind};
use crate::paths::Portable;
#[cfg(test)]
use crate::report::{Action, Exit};

mod entry;
#[cfg(test)]
mod fixtures;
mod inspect;
mod rollback;

#[cfg(test)]
pub use entry::abandon;
pub use entry::{lock_for_writing, pending, recover};

/// Everything that can go wrong recovering.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The journal could not be read, written or unlinked.
    #[error(transparent)]
    Journal(#[from] journal::Error),
    /// The state directory failed.
    #[error(transparent)]
    State(#[from] crate::state::Error),
    /// A destination could not be read or written.
    #[error(transparent)]
    Write(#[from] fs::Error),
    /// A terminated journal has no session header, so the home its paths were
    /// rendered against is unknown.
    ///
    /// Not reachable from a journal on disk, which [`journal::load`] refuses
    /// when its first frame is not its header; kept so that a terminated
    /// journal without one could only ever be refused, never rolled back.
    #[error("the journal {} records a write with no session header", .path.display())]
    Headless {
        /// The journal.
        path: PathBuf,
    },
    /// Recovery could not account for at least one destination, and a writing
    /// command may not proceed over it.
    #[error(
        "an interrupted bx session left {} file(s) bx cannot account for:\n{}",
        .conflicts.len(),
        .conflicts.iter().map(Unfinished::describe).collect::<Vec<_>>().join("\n"),
    )]
    Blocked {
        /// What could not be accounted for.
        conflicts: Vec<Unfinished>,
    },
}

/// A rollback's removal fails as the journal's own removals do.
impl From<remove::Error> for Error {
    fn from(error: remove::Error) -> Self {
        Self::Journal(error.into())
    }
}

/// What is at an interrupted write's destination, relative to the two states the
/// journal says it may legitimately hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Exactly what was there before the session. There is nothing to undo.
    Prior,
    /// Exactly what the session was writing. The undo is well defined.
    Written,
    /// Nothing is there, and the journal says something should be. The user
    /// removed it after the crash, and bx does not resurrect a file.
    Vanished,
    /// A regular file matching neither recorded state: it was edited after the
    /// crash.
    Diverged,
    /// Not a regular file at all.
    Foreign,
    /// Out of reach: its parent is on the filesystem but does not resolve to
    /// a directory — a dangling symlink, a loop, or a file — so bx cannot
    /// tell what is at the destination, and cannot write there.
    Unreachable,
}

impl Standing {
    /// Whether recovery can act on this on its own.
    #[cfg(test)]
    #[must_use]
    pub const fn is_resolvable(self) -> bool {
        matches!(self, Self::Prior | Self::Written)
    }
}

impl std::fmt::Display for Standing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Prior => "holds the bytes that were there before",
            Self::Written => "holds the bytes the interrupted session wrote",
            Self::Vanished => "is gone",
            Self::Diverged => "was edited after the interruption",
            Self::Foreign => "is not a regular file",
            Self::Unreachable => "cannot be reached",
        })
    }
}

/// One write an interrupted session announced, as a later invocation finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unfinished {
    /// The target, home-relative.
    pub target: Portable,
    /// Where it is.
    pub dest: PathBuf,
    /// What is there now.
    pub standing: Standing,
    /// Whether recovery resolves this on its own. `false` is what blocks it.
    pub resolvable: bool,
    /// The one-line explanation a renderer prints after the path.
    pub note: String,
}

impl Unfinished {
    /// The action `plan` reports for this target.
    ///
    /// Always [`Action::Conflict`], and deliberately not a sixth variant. Its
    /// documented meaning — *something bx does not currently own is in the way,
    /// reported and skipped, never overwritten* — is exactly the situation, and
    /// [`Action::needs_attention`] makes [`Exit::from_actions`] yield
    /// [`Exit::Pending`], which is the right signal for "a human has to look".
    /// [`Exit::Error`] would be wrong: nothing is going wrong now.
    #[cfg(test)]
    #[must_use]
    pub const fn action(&self) -> Action {
        Action::Conflict
    }

    /// One line naming the file and what is wrong with it.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("  {} {}", self.dest.display(), self.note)
    }
}

/// An interrupted session, as [`pending`] found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interrupted {
    /// What the session was for.
    pub kind: SessionKind,
    /// The journal that records it.
    pub journal: PathBuf,
    /// Whether every write in it was published and only the ledger is behind.
    ///
    /// `true` means recovery has no destination to touch: it rebuilds the ledger
    /// entries from the journal and unlinks it. What is at a destination now
    /// does not change that — a file edited since is the user's edit to a file
    /// bx manages, which `plan` reports like any other — so such a session is
    /// blocked only by a prior snapshot recovery cannot read.
    pub complete: bool,
    /// Whether the journal is one no bx session could have written — see
    /// [`Loaded::Unreadable`] — so nothing in it is believed.
    ///
    /// Such a journal names no write, so `unfinished` is empty, `complete` is
    /// `false`, `kind` is [`SessionKind::Apply`] because no header was
    /// believed, and `Interrupted::exit` is
    /// [`Exit::Pending`](crate::report::Exit::Pending). The next writing command
    /// sets the file aside and rolls nothing back, and `plan` then reports what
    /// the session may have written as conflicts. It is reported rather than
    /// hidden because a read-only command is otherwise the one place a user
    /// would never learn of it.
    ///
    /// [`Loaded::Unreadable`]: crate::journal::Loaded::Unreadable
    pub unreadable: bool,
    /// Every write the session announced, `Done` or not.
    pub unfinished: Vec<Unfinished>,
}

impl Interrupted {
    /// The writes recovery cannot resolve on its own.
    pub fn blocked(&self) -> impl Iterator<Item = &Unfinished> {
        self.unfinished.iter().filter(|write| !write.resolvable)
    }

    /// The action per target a read-only command reports.
    #[cfg(test)]
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        self.unfinished.iter().map(Unfinished::action).collect()
    }

    /// The process status a read-only command exits with.
    ///
    /// [`Exit::Pending`] whenever anything was interrupted — including a session
    /// with no writes in it, because the machine is still not converged and
    /// somebody has to run a writing command.
    #[cfg(test)]
    #[must_use]
    pub fn exit(&self) -> Exit {
        if self.unfinished.is_empty() {
            Exit::Pending
        } else {
            Exit::from_actions(&self.actions())
        }
    }
}

/// What recovery did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// There was no interrupted session.
    Nothing,
    /// The interrupted session was rolled back.
    RolledBack {
        /// How many writes were undone or confirmed already undone.
        undone: usize,
    },
    /// Every write had landed and only the ledger was behind; it has been
    /// brought up to date. **No destination was touched.**
    Recorded {
        /// How many ledger entries were rebuilt.
        entries: usize,
    },
    /// At least one destination could not be accounted for. The journal is kept
    /// and every writing command refuses until it is resolved.
    Blocked {
        /// What could not be accounted for.
        conflicts: Vec<Unfinished>,
    },
}

impl Outcome {
    /// Whether the state directory is clear afterwards.
    #[cfg(test)]
    #[must_use]
    pub const fn is_clear(&self) -> bool {
        !matches!(self, Self::Blocked { .. })
    }
}
