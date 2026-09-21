//! Detecting an interrupted session, and undoing it.
//!
//! The second half of `CLAUDE.md` Invariant 4: *an interrupted `apply` must be
//! detectable and recoverable*. [`pending`] is the detection, [`recover`] is the
//! undo, and [`abandon`] is the escape when the undo cannot be taken.
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
//! A **writing** command — `apply`, `sync`, `init`, `add`, `rm` — calls
//! [`lock_for_writing`] first, which recovers under the state directory's lock,
//! refuses to go on if it cannot, and hands that same lock to the session it is
//! about to open, so no second bx can win the directory in between. Nothing in
//! the type system makes a writing command use it rather than [`recover`]
//! followed by a fresh [`journal::Session::open`]; what makes it the obvious
//! one is that `lock_for_writing` is the only call that produces the guard
//! [`journal::Session::open_locked`] consumes, and the only one that turns a
//! blocked recovery into a refusal. A
//! **read-only** command — `plan`, `status`, `doctor` — calls [`pending`],
//! reports every named target as [`Action::Conflict`], exits
//! [`Exit::Pending`](crate::report::Exit::Pending), and writes nothing. That is
//! what keeps `plan` usable from CI, a prompt segment or a login banner.
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
//! [`abandon`] as the way out.
//!
//! A destination whose parent no longer resolves to a directory blocks
//! recovery the same way: bx can neither confirm what is there nor write the
//! undo through it, and the message names the parent and [`abandon`].

use std::path::{Path, PathBuf};

use crate::fs::{self, Kind, Mode};
use crate::journal::{self, Intent, Loaded, SessionKind, Written};
use crate::paths::Portable;
use crate::report::{Action, Exit};
use crate::state::{
    ContentHash, ExclusiveLock, Ledger, LedgerView, NewEntry, Prior, PriorBytes, RestoreRef,
    StateDir,
};

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
    /// believed, and [`Interrupted::exit`] is
    /// [`Exit::Pending`](crate::report::Exit::Pending). The next writing command
    /// sets the file aside and rolls nothing back, and `plan` then reports what
    /// the session may have written as conflicts. It is reported rather than
    /// hidden because a read-only command is otherwise the one place a user
    /// would never learn of it.
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
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        self.unfinished.iter().map(Unfinished::action).collect()
    }

    /// The process status a read-only command exits with.
    ///
    /// [`Exit::Pending`] whenever anything was interrupted — including a session
    /// with no writes in it, because the machine is still not converged and
    /// somebody has to run a writing command.
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
    #[must_use]
    pub const fn is_clear(&self) -> bool {
        !matches!(self, Self::Blocked { .. })
    }
}

/// Whether an interrupted session stands, and what it names.
///
/// Read-only, destinations and state directory alike. A journal it cannot
/// believe is reported, with [`Interrupted::unreadable`] set and no writes, and
/// left exactly where it is: moving it aside is the degradation `CLAUDE.md`
/// requires of a machine-owned file, and the next writing command does it,
/// under the lock.
///
/// What it reports for each write is decided by the same function [`recover`]
/// acts on, over the same journal, so a report and a recovery that find the
/// same destinations and the same saved ledger reach the same verdict. They
/// can still differ when something changes in between — this is a snapshot —
/// and a journal that writes one target twice, over which a per-intent report
/// and a reverse-order rollback would disagree, is refused by the loader and
/// never written by a session.
///
/// It takes **no lock**, deliberately, so `plan` stays usable while an `apply`
/// runs — and that means a journal it finds may belong to a session that is in
/// flight right now rather than to one that died. The two are told apart by the
/// state directory's lock, not by the journal: a caller that wants to say "an
/// apply is in progress" rather than "an apply was interrupted" asks
/// [`crate::state::SharedLock::try_acquire`] first and reports the `None` case
/// as the live one. A session creates its journal whole, by rename, so the most
/// such a reader can see of one in flight is a torn tail frame, which it
/// discards.
///
/// # Errors
///
/// [`Error::Journal`] when the journal cannot be read, [`Error::Write`] when a
/// destination cannot be stat'd, [`Error::State`] when a prior snapshot cannot
/// be read, and [`Error::Headless`] for a terminated journal with no session
/// header — the same journal [`recover`] refuses.
pub fn pending(state: &StateDir) -> Result<Option<Interrupted>, Error> {
    let path = state.journal();
    let loaded = journal::load(&path)?;
    let complete = match loaded {
        Loaded::Absent => return Ok(None),
        Loaded::Unreadable { .. } => {
            return Ok(Some(Interrupted {
                kind: SessionKind::Apply,
                journal: path,
                complete: false,
                unreadable: true,
                unfinished: Vec::new(),
            }));
        }
        Loaded::Terminated(_) => true,
        Loaded::Unterminated(_) | Loaded::Torn { .. } => false,
    };
    let home = rebuild_home(&loaded, complete, &path)?;

    let kind = loaded
        .begin()
        .map_or(SessionKind::Apply, |begin| begin.kind);
    // A terminated journal's report depends on what the saved ledger already
    // holds, exactly as its rebuild does. Every state file is replaced by
    // rename, so this read needs no lock.
    let ledger = match home {
        // A mis-spelled home is `Error::ForeignPath` and stops the report, as
        // it stops the recovery. A damaged ledger is only reported here: a
        // reader without the lock moves nothing, and the recovery that holds
        // the lock quarantines it and rebuilds into an empty ledger, which is
        // the ledger this report judges against too.
        Some(home) => {
            let read = LedgerView::read(state, home)?;
            if let Some(damage) = read.health.damage() {
                tracing::warn!(
                    ?damage,
                    "the ledger is damaged; it is left in place, and the next writing bx run \
                     moves it aside before recovering",
                );
            }
            Some(read.value)
        }
        None => None,
    };
    let mut unfinished = Vec::new();
    for (intent, landed) in loaded.landed() {
        unfinished.push(decide(state, intent, home, ledger.as_ref(), landed)?.1);
    }
    Ok(Some(Interrupted {
        kind,
        journal: path,
        complete,
        unreadable: false,
        unfinished,
    }))
}

/// Resolve an interrupted session, or report why it cannot be.
///
/// Takes the state directory's exclusive lock for the duration. Safe to run when
/// there is nothing to do — that is [`Outcome::Nothing`] — and safe to run twice:
/// the second run finds no journal.
///
/// # Errors
///
/// [`Error::Journal`], [`Error::State`] or [`Error::Write`] for a filesystem
/// failure, and [`Error::Headless`] for a journal that records a write with no
/// header. A destination bx cannot account for is [`Outcome::Blocked`], not an
/// error: nothing is going wrong, a human has to look.
pub fn recover(state: &StateDir) -> Result<Outcome, Error> {
    let lock = ExclusiveLock::acquire(state)?;
    resolve(state, &lock)
}

/// [`lock_for_writing`]'s verdict, with the lock already held.
///
/// [`Outcome::Blocked`] becomes [`Error::Blocked`] here and nowhere else: a
/// command that is about to write must stop, while [`recover`] hands the same
/// verdict back as a value for a caller that only reports it.
fn resolved_or_blocked(state: &StateDir, lock: &ExclusiveLock) -> Result<Outcome, Error> {
    match resolve(state, lock)? {
        Outcome::Blocked { conflicts } => Err(Error::Blocked { conflicts }),
        resolved => Ok(resolved),
    }
}

/// Recover, refuse if it is blocked, and **keep the lock**.
///
/// The call every writing command makes. [`recover`] followed by
/// [`journal::Session::open`] releases the state directory between the two, so
/// a second bx can win it in between and this one's session then refuses with
/// [`journal::Error::InProgress`] naming a journal that belongs to a live run
/// rather than to an interruption. Handing the guard to
/// [`journal::Session::open_locked`] makes that error mean what it says: there
/// was an interruption this run could not resolve. See `r3 round 3`
/// decision 3.
///
/// Only the guard comes back. The recovery's [`Outcome`] is logged by
/// [`resolve`] and not returned: no writing command has a channel to report it
/// on yet, and a value every caller binds to `_` is a value the next reader has
/// to work out the point of. A command layer that grows such a channel adds it
/// back with a caller that reads it. Until then [`recover`] is the form that
/// answers "what did recovery do", for a caller that opens no session.
///
/// The caller opens the session itself, so a session's failure stays a
/// session's failure rather than becoming a recovery's.
///
/// # Errors
///
/// As [`recover`], plus [`Error::Blocked`] when a destination cannot be
/// accounted for — a command that is about to write must stop. The escape from
/// that is [`abandon`].
pub fn lock_for_writing(state: &StateDir) -> Result<ExclusiveLock, Error> {
    state.ensure()?;
    let lock = ExclusiveLock::acquire(state)?;
    resolved_or_blocked(state, &lock)?;
    Ok(lock)
}

/// Move an unresolvable journal aside without touching any destination.
///
/// The escape hatch for a recovery that stays blocked: it clears the refusal so
/// bx can run again, and leaves every file on disk exactly as it is. Whatever bx
/// then finds it does not own is reported by `plan` as a conflict — skipped,
/// never overwritten — which is the same safe outcome a corrupt journal reaches.
///
/// Returns where the journal was kept, or `None` when there was none.
///
/// # Errors
///
/// [`Error::State`] when the lock cannot be taken and [`Error::Journal`] when
/// the journal cannot be moved, or with [`journal::Error::FutureVersion`] when
/// a newer bx wrote it, which is left exactly where it is. A journal abandoned earlier is never renamed
/// over: this one takes the next free set-aside name.
pub fn abandon(state: &StateDir) -> Result<Option<PathBuf>, Error> {
    let lock = ExclusiveLock::acquire(state)?;
    let path = state.journal();
    // Looked at without following a link: a dangling one at the journal's
    // path is refused by every read (`journal::Error::NotAJournal`), so it
    // has to be something this can move aside.
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    // Refused here as everywhere else it is read: abandoning a newer bx's
    // journal from an older build discards a rollback only the newer bx can
    // make, and the way out is to run that bx. Any other failure to read is
    // left to the set-aside below, which reports its own.
    if let Err(future @ journal::Error::FutureVersion { .. }) = journal::load(&path) {
        return Err(future.into());
    }
    let aside = journal::set_aside(&path, &lock)?;
    tracing::warn!(
        path = %path.display(),
        moved_to = %aside.display(),
        "abandoned an interrupted bx session without touching any destination",
    );
    Ok(Some(aside))
}

/// The body of [`recover`], with the lock already held.
fn resolve(state: &StateDir, lock: &ExclusiveLock) -> Result<Outcome, Error> {
    let path = state.journal();
    let loaded = journal::load_exclusive(&path, lock)?;
    let complete = match loaded {
        Loaded::Absent | Loaded::Unreadable { .. } => return Ok(Outcome::Nothing),
        Loaded::Terminated(_) => true,
        Loaded::Unterminated(_) | Loaded::Torn { .. } => false,
    };
    // A journal that lost bytes is set aside at the end rather than unlinked.
    // The set-aside name is always free — the number after the highest
    // present, past any name taken since, or, once the top number is
    // present, the lowest free one — so nothing needs checking before the
    // rollback.
    let torn = matches!(loaded, Loaded::Torn { .. });
    let home = rebuild_home(&loaded, complete, &path)?;

    // Only a terminated journal's bookkeeping touches the ledger, and it is the
    // one kind with a home to check the ledger's stored paths against. A roll
    // back leaves the saved ledger exactly as it was, so it opens nothing.
    let mut ledger = match home {
        Some(home) => Some(Ledger::open(state, lock, home)?.value),
        None => None,
    };
    let mut conflicts = Vec::new();
    let mut resolved = 0_usize;
    // Every directory a target the terminated session dropped from the ledger
    // claimed. The session prunes a removal's after its `End` frame, so a crash
    // between the two leaves them standing. Handing on what still stands is
    // bookkeeping its save may not have reached; recovery removes none of them,
    // because a terminated session is never rolled back or finished on its
    // behalf, and one no entry is beneath is left for `bx doctor`, as
    // decision 11 keeps an orphaned temporary file.
    //
    // Owned rather than borrowed from the intents, because a dropped entry's
    // own claims are rendered here and belong to nobody else.
    let mut released: Vec<PathBuf> = Vec::new();

    let mut intents = loaded.landed();
    if !complete {
        // Reverse order, so a later write is undone before an earlier one it may
        // share a created directory with.
        intents.reverse();
    }
    for (intent, landed) in intents {
        let (step, report) = decide(state, intent, home, ledger.as_deref(), landed)?;
        // A temporary file the journal names is this write's, and goes once
        // recovery is acting on the write at all: a blocked write is not
        // recovery's to touch, its temporary file included. The loader has
        // already refused a journal whose temporary file is not a `.bx-` file
        // beside its destination, and one the journal does not name is never
        // touched.
        //
        // One that cannot be removed — its directory has since stopped
        // letting this process write — is left, with a warning, and the
        // rollback goes on. Recovery never needs it: it holds bytes no
        // destination was ever given, which makes it the same kind of orphan
        // decision 11 keeps for `bx doctor`, and stopping every writing
        // command over it would make a leftover bx does not need a reason to
        // write nothing. `pending` names it in the write's note.
        if !complete
            && !matches!(step, Step::Blocked)
            && let Some(temp) = &intent.temp
            && let Err(error) = journal::unlink(temp)
        {
            tracing::warn!(
                temp = %temp.display(),
                %error,
                "an interrupted write's temporary file could not be removed; \
                 it is left for bx doctor, and the rollback goes on",
            );
        }
        match step {
            Step::Blocked => {
                conflicts.push(report);
                continue;
            }
            Step::Skip => continue,
            Step::Keep => {
                if intent.creates() {
                    journal::prune_dirs(&intent.created_dirs)?;
                }
            }
            Step::Unlink => {
                journal::unlink(&intent.dest)?;
                journal::prune_dirs(&intent.created_dirs)?;
            }
            Step::Rewrite { bytes, mode } => fs::write_atomically(&intent.dest, &bytes, mode)?,
            // Rebuilding the bookkeeping touches no destination, so it is not
            // work `plan` failed to announce: the ledger is machine state, not
            // the user's.
            Step::Record(entry) => {
                if let Some(ledger) = ledger.as_mut() {
                    ledger.record(entry)?;
                }
            }
            Step::Forget => {
                let dropped = ledger
                    .as_mut()
                    .and_then(|ledger| ledger.forget(&intent.target));
                if intent.after == Written::Absent {
                    released.extend(intent.created_dirs.iter().cloned());
                }
                // The entry's *own* claims, which are not always the Intent's.
                // A removal's Intent carries them, because `plan_restore` takes
                // them from the entry; a released write's does not — it records
                // only the directories that write invented, which is none. The
                // replay path drops the same entry `Session::write` drops, so
                // it has to carry the same claim on, or a crash turns a
                // hand-off into a loss. See `r3 round 4` decision R3R4-1.
                if let (Some(dropped), Some(home)) = (dropped, home) {
                    released.extend(dropped.created_dirs.iter().map(|dir| dir.render(home)));
                }
            }
        }
        resolved += 1;
    }
    // Blocked first, and *before* the hand-off. r3 coverage COV4: the
    // hand-off used to stand ahead of this return behind a
    // `conflicts.is_empty()` guard, and deleting that guard changed no
    // assertion — a blocked run saves no ledger, so the mutation it protected
    // against was invisible and the arm's correctness rested on the drop.
    // Returning first is the same behaviour with the ordering as the
    // guarantee: past this point there are no conflicts, so nothing has to say
    // so a second time.
    if !conflicts.is_empty() {
        tracing::error!(
            blocked = conflicts.len(),
            journal = %path.display(),
            "recovery is blocked; the journal is kept and bx will not write until it is resolved",
        );
        return Ok(Outcome::Blocked { conflicts });
    }

    if let (Some(ledger), Some(home)) = (ledger.as_mut(), home) {
        journal::hand_off_claims(ledger, home, &released)?;
    }

    if let Some(ledger) = &ledger {
        ledger.save()?;
    }
    // Last of all, and only once every step has succeeded. This is the rule that
    // makes recovery re-runnable without a journal of its own. A journal bytes
    // were discarded from is kept: they may have been a frame that damage, not a
    // crash, cut short, and the file is the only record of what it hid.
    if torn {
        let aside = journal::set_aside(&path, lock)?;
        tracing::warn!(
            path = %path.display(),
            moved_to = %aside.display(),
            "the recovered journal ended in bytes that were not a whole frame; \
             it was kept rather than deleted",
        );
    } else {
        journal::unlink(&path)?;
    }

    Ok(if complete {
        tracing::info!(
            entries = resolved,
            "brought the ledger up to date after an interruption"
        );
        Outcome::Recorded { entries: resolved }
    } else {
        tracing::info!(undone = resolved, "rolled back an interrupted bx session");
        Outcome::RolledBack { undone: resolved }
    })
}

/// What recovery does about one intent.
enum Step {
    /// Rolling back, and the destination already holds what was there before.
    /// Only the directories a create invented are left to prune.
    Keep,
    /// Rolling back a create whose file is there: unlink it, then prune.
    Unlink,
    /// Rolling back over a file that existed: put these bytes back at this mode.
    Rewrite {
        /// The prior bytes, digest-verified.
        bytes: Vec<u8>,
        /// The mode they had.
        mode: Mode,
    },
    /// Bringing the ledger up to date for a write that landed.
    Record(NewEntry),
    /// Bringing the ledger up to date for a write that left nothing to own.
    Forget,
    /// A terminated journal's write that never landed: nothing to record.
    Skip,
    /// Not recovery's to resolve.
    Blocked,
}

/// Decide what recovery does about one intent, and what a report says about it.
///
/// The single decision site. [`pending`] reports the [`Unfinished`] and
/// [`resolve`] carries out the [`Step`], so what a read-only command says and
/// what a writing one does are one verdict — for a terminated journal as much
/// as an unterminated one. Each intent is judged on its own, which is sound
/// because no journal recovery believes writes a target twice
/// ([`journal::Error::Repeated`]).
///
/// `home` is `Some` for a terminated journal, whose ledger entries are rebuilt
/// with paths made portable against it, and `None` for an unterminated one,
/// which is rolled back. `ledger` is the ledger a rebuild would record into —
/// the saved one, for a report — and is only read for a terminated journal.
/// `landed` is whether a `Done` follows the intent.
///
/// # A rebuild over a ledger that was already saved
///
/// [`crate::journal::Session::finish`] saves the ledger and then unlinks the
/// journal, so a crash or a failed unlink between the two leaves a terminated
/// journal over a ledger that already holds its writes. Recording such an
/// intent a second time is not a no-op: its `before` is what was on disk a
/// moment before the write — bx's own previous output, for a target bx already
/// managed — and the ledger, which now says bx last wrote `after`, would take
/// those bytes for a third party's and adopt them as the prior, pushing the
/// user's original out of reach of `rm`.
///
/// So a write the ledger already holds is skipped. "Already holds" is the
/// stored entry being at the intent's `after` digest and mode while the ledger
/// the session opened was not at that digest ([`Intent::ledger_written`]). An
/// entry still at `after` that the session also found there is re-recorded,
/// which is idempotent: nothing in the stored entry turns on whether it was
/// saved. Matching `after` alone is not enough — a session that rewrites bx's
/// last output over a user's edit and dies before the save leaves the ledger
/// at `after` without the edit, and skipping that would lose it.
fn decide(
    state: &StateDir,
    intent: &Intent,
    home: Option<&Path>,
    ledger: Option<&LedgerView>,
    landed: bool,
) -> Result<(Step, Unfinished), Error> {
    let standing = standing(intent, &look(&intent.dest)?);
    let report = |resolvable: bool, note: String| Unfinished {
        target: intent.target.clone(),
        dest: intent.dest.clone(),
        standing,
        resolvable,
        note,
    };

    let Some(home) = home else {
        let rolls_back = || {
            let mut note =
                format!("interrupted, and {standing}; the next writing bx run rolls it back");
            if let Some(name) = stuck_temp(intent) {
                note.push_str(&format!(
                    "; its temporary file {name} cannot be removed, and is left for bx doctor"
                ));
            }
            note
        };
        return Ok(match (standing, &intent.before) {
            (Standing::Prior, _) => (Step::Keep, report(true, rolls_back())),
            (Standing::Written, Prior::Absent) => (Step::Unlink, report(true, rolls_back())),
            (Standing::Written, Prior::Existed(reference)) => match snapshot(state, reference)? {
                Ok(bytes) => (
                    Step::Rewrite {
                        bytes,
                        mode: reference.mode,
                    },
                    report(true, rolls_back()),
                ),
                Err(why) => (Step::Blocked, report(false, why)),
            },
            (Standing::Vanished | Standing::Diverged | Standing::Foreign, _) => {
                (Step::Blocked, report(false, note(intent, standing)))
            }
            // Neither state can be confirmed, and no undo can be written
            // through the parent: a human has to look, as for a file edited
            // since.
            (Standing::Unreachable, _) => (Step::Blocked, report(false, unreachable(intent))),
        });
    };

    // A terminated journal: every write that reached `Done` landed, and only the
    // bookkeeping is outstanding. What is at the destination now changes nothing
    // — a file edited since is the user's edit to a file bx manages, which
    // `plan` reports like any other — so no destination blocks this; only a
    // snapshot recovery cannot read does.
    if !landed {
        return Ok((
            Step::Skip,
            report(
                true,
                "was announced and never written; there is nothing to record".to_string(),
            ),
        ));
    }
    let recorded = || {
        format!(
            "was written, and {standing}; only bx's bookkeeping is pending, \
             and the next writing bx run records it"
        )
    };
    let (Written::Present { digest, mode }, Some(mechanism)) =
        (intent.after, intent.mechanism.clone())
    else {
        // A removal, or a target the session released: nothing for bx to own.
        let mut note = recorded();
        if intent.after == Written::Absent {
            let orphans = empty_claims(&intent.created_dirs, home);
            if !orphans.is_empty() {
                note.push_str(&format!(
                    "; the session ended before it removed {}, which stand empty and are \
                     left for bx doctor",
                    orphans.join(", "),
                ));
            }
        }
        return Ok((Step::Forget, report(true, note)));
    };
    if let Some(stored) = ledger.and_then(|ledger| ledger.get(&intent.target))
        && stored.written == digest
        && stored.mode == mode
        && intent.ledger_written != Some(digest)
    {
        return Ok((
            Step::Skip,
            report(
                true,
                "was written, and bx's bookkeeping for it was saved before the \
                 interruption; there is nothing left to record"
                    .to_string(),
            ),
        ));
    }
    let prior = match &intent.before {
        Prior::Absent => PriorBytes::Absent,
        Prior::Existed(reference) => match snapshot(state, reference)? {
            Ok(bytes) => PriorBytes::Bytes {
                bytes,
                mode: reference.mode,
            },
            Err(why) => return Ok((Step::Blocked, report(false, why))),
        },
    };
    let entry = NewEntry::new(intent.target.clone(), digest, mode, mechanism)
        .with_prior(prior)
        .with_created_dirs(
            intent
                .created_dirs
                .iter()
                .map(|dir| {
                    Portable::from_path(dir, home).map_err(|source| fs::Error::NotPortable {
                        path: dir.clone(),
                        source,
                    })
                })
                .collect::<Result<_, _>>()?,
        );
    // The ledger's own refusal is a verdict here, not an error: a rebuild that
    // would adopt a changed shared file as its prior is blocked, the stored
    // prior is kept, and the report says so before the recovery finds it.
    if let Some(Err(conflict)) = ledger.map(|ledger| ledger.check_record(&entry)) {
        return Ok((Step::Blocked, report(false, conflict.to_string())));
    }
    Ok((Step::Record(entry), report(true, recorded())))
}

/// The name of the temporary file `intent` names, when it is still there and
/// its directory will not let this process remove it.
///
/// A prediction, for the report: [`resolve`] tries the unlink and leaves the
/// file with a warning when it fails. Write and search permission on the
/// directory is what an unlink needs, and `access(2)` is asked for exactly
/// that, so a read-only filesystem is caught too.
fn stuck_temp(intent: &Intent) -> Option<String> {
    let temp = intent.temp.as_ref()?;
    let dir = temp.parent()?;
    std::fs::symlink_metadata(temp).ok()?;
    rustix::fs::access(
        dir,
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
    )
    .is_err()
    .then(|| {
        temp.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    })
}

/// The directories in `dirs` that are still empty directories, `~`-relative.
///
/// What a removal whose session died between its `End` frame and its prune
/// leaves behind. Recovery removes none of them — see [`resolve`] — so the
/// report names them. A path that is not a directory, or that holds anything,
/// is not one: it is not what the prune would have removed.
fn empty_claims(dirs: &[PathBuf], home: &Path) -> Vec<String> {
    dirs.iter()
        .filter(|dir| std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()))
        .filter(|dir| std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none()))
        .map(|dir| crate::paths::to_portable(dir, home))
        .collect()
}

/// The bytes a [`RestoreRef`] names, digest-verified, or why they cannot be had.
///
/// A missing or corrupt snapshot is a verdict — recovery will not guess at the
/// bytes a write displaced — and any other failure is an error.
fn snapshot(state: &StateDir, reference: &RestoreRef) -> Result<Result<Vec<u8>, String>, Error> {
    // `restore_bytes` reads the content-addressed blob and consults no entry, so
    // an empty view reads it exactly as the ledger would, and a read-only report
    // needs no lock to do it.
    match LedgerView::default().restore_bytes(state, reference) {
        Ok(bytes) => Ok(Ok(bytes)),
        Err(
            e @ (crate::state::Error::RestoreMissing { .. }
            | crate::state::Error::RestoreCorrupt { .. }),
        ) => Ok(Err(e.to_string())),
        Err(e) => Err(e.into()),
    }
}

/// The home a terminated journal's entries are rebuilt against, or `None` for an
/// unterminated journal, which is rolled back and needs none.
///
/// # Errors
///
/// [`Error::Headless`] for a terminated journal with no session header.
fn rebuild_home<'a>(
    loaded: &'a Loaded,
    complete: bool,
    path: &Path,
) -> Result<Option<&'a Path>, Error> {
    if !complete {
        return Ok(None);
    }
    loaded
        .begin()
        .map(|begin| Some(begin.home.as_path()))
        .ok_or_else(|| Error::Headless {
            path: path.to_path_buf(),
        })
}

/// What is at a destination right now, reduced to what recovery compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    Absent,
    File {
        digest: ContentHash,
        mode: Mode,
    },
    Foreign,
    /// Its parent does not resolve to a directory. [`fs::observe`] reports
    /// such a destination as absent, which it may not be.
    Unreachable,
}

/// Read a destination.
fn look(dest: &Path) -> Result<Found, Error> {
    let observed = fs::observe(dest)?;
    if observed
        .parent
        .as_ref()
        .is_some_and(|parent| parent.unusable().is_some())
    {
        return Ok(Found::Unreachable);
    }
    Ok(match (observed.kind, observed.digest(), observed.mode) {
        (Kind::Absent, _, _) => Found::Absent,
        (Kind::File, Some(digest), Some(mode)) => Found::File { digest, mode },
        _ => Found::Foreign,
    })
}

/// Classify a destination against the two states its intent permits.
///
/// The ground [`decide`] stands on for a rollback, and what every report names.
///
/// `before` is tested first, so a destination that is already where the rollback
/// wants it is a no-op even when the two states are identical — a write whose
/// only change was the mode, undone, is the same file.
fn standing(intent: &Intent, found: &Found) -> Standing {
    let before = expected(&intent.before);
    let after = match intent.after {
        Written::Absent => None,
        Written::Present { digest, mode } => Some((digest, mode)),
    };
    match *found {
        Found::Absent => {
            if before.is_none() {
                Standing::Prior
            } else if after.is_none() {
                Standing::Written
            } else {
                Standing::Vanished
            }
        }
        Found::File { digest, mode } => {
            let here = Some((digest, mode));
            if before == here {
                Standing::Prior
            } else if after == here {
                Standing::Written
            } else {
                Standing::Diverged
            }
        }
        Found::Foreign => Standing::Foreign,
        Found::Unreachable => Standing::Unreachable,
    }
}

/// The message a write whose destination cannot be reached carries: the
/// parent, `~`-relative, and the way out.
///
/// The parent is the target's own, spelled as the journal stores it, because
/// a rollback has no home to fold an absolute path against.
fn unreachable(intent: &Intent) -> String {
    let parent = intent
        .target
        .as_str()
        .rsplit_once('/')
        .map_or("its parent", |(parent, _)| parent);
    format!(
        "{}: {parent} does not resolve to a directory, so bx cannot tell what is \
         there and will not roll it back. Make {parent} a directory again, or \
         abandon the interrupted session to have bx report it as a conflict \
         instead.",
        Standing::Unreachable,
    )
}

/// The digest and mode a [`Prior`] names, or `None` for "there was no file".
fn expected(prior: &Prior) -> Option<(ContentHash, Mode)> {
    match prior {
        Prior::Absent => None,
        Prior::Existed(reference) => Some((reference.digest, reference.mode)),
    }
}

/// The message a blocked target carries: the file, both digests it could
/// legitimately hold, and the way out.
fn note(intent: &Intent, standing: Standing) -> String {
    let before = match &intent.before {
        Prior::Absent => "did not exist".to_string(),
        Prior::Existed(reference) => format!("held {}", reference.digest),
    };
    let after = match intent.after {
        Written::Absent => "was to be removed".to_string(),
        Written::Present { digest, .. } => format!("was being given {digest}"),
    };
    format!(
        "{standing}; before the interruption it {before}, and it {after}. \
         bx will not overwrite it. Put back either of those two states, or \
         abandon the interrupted session to have bx report it as a conflict \
         instead."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::{Command, Output};

    use crate::journal::tests::{
        WRITES_THROUGH_PERMISSIONS, cannot_build, crash_phases, finish_crash_phases, frame_starts,
        names_in, peek, permissions_refuse, plant_file, raw_journal, seal,
        state_beyond_set_aside_names, target, write_to,
    };
    use crate::journal::{Begin, Content, Done, End, Ownership, Record, Request, Session};
    use crate::state::{LedgerView, Mechanism, RestoreRef};
    use crate::testing::guarded_home;

    /// Run a session and abandon it without finishing, which is exactly the
    /// state a crash leaves: a journal that stands, and a ledger that does not
    /// yet know about any of it.
    fn interrupted(state: &StateDir, home: &Path, requests: Vec<Request>) {
        let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
        for request in requests {
            session.apply(request).expect("apply");
        }
        drop(session);
    }

    // ---------------------------------------------------------------------
    // The crash harness.
    //
    // The child is this very test binary, re-invoked, aborting at a chosen
    // write boundary. `abort` terminates without unwinding, without running a
    // destructor and without flushing a buffer, which is what process death
    // does and what an `Err` return does not. An in-process seam that returned
    // `Err` would test error handling; the failure this entry exists to survive
    // is the process ceasing to exist between two syscalls.
    //
    // What it models, and what it does not: killing a process models process
    // death at an arbitrary boundary. It does **not** model media loss, because
    // page-cache contents survive process death. Media loss is covered
    // structurally instead, by the `fsync` discipline in `Session::apply` and by
    // `the_intent_is_durable_before_the_destination_is_touched`, which pins the
    // ordering that discipline exists to guarantee.
    // ---------------------------------------------------------------------

    /// The home the crash child builds its fixture under.
    ///
    /// Passed per-command with `Command::env`: no test in this crate sets a
    /// variable in its own process.
    const CRASH_HOME: &str = "BX_CRASH_HOME";

    /// The variable the crash seam reads, once, at `Session::open`.
    const CRASH_AT: &str = "BX_CRASH_AT";

    /// The four requests the crash child makes, in the order it makes them: a
    /// modify at a non-default mode, a create in a directory bx must invent, a
    /// plain modify, and a removal of a private file from a private directory
    /// the removal claims as one bx created.
    fn crash_requests(home: &Path) -> Vec<Request> {
        vec![
            write_to(home, ".bxrc", "after bx\n", Mode::PRIVATE_FILE),
            write_to(
                home,
                ".config/bx-crash/made.conf",
                "made\n",
                Mode::DEFAULT_FILE,
            ),
            write_to(
                home,
                ".gitconfig",
                "[user]\n\tname = after\n",
                Mode::DEFAULT_FILE,
            ),
            {
                let (target, dest) = target(home, ".vault/gone.conf");
                // Observed when the request is built, as `write_to` observes.
                let planned = fs::observe(&dest).expect("plan's observation");
                Request {
                    target,
                    dest,
                    content: Content::Absent {
                        created_dirs: vec![home.join(".vault")],
                        planned,
                    },
                    mode: Mode::PRIVATE_FILE,
                    ownership: Ownership::Released,
                }
            },
        ]
    }

    /// What exists before the crashing session runs.
    fn plant_crash_fixture(home: &Path) {
        std::fs::create_dir_all(home).expect("the crash home");
        plant_file(&home.join(".bxrc"), "before bx\n", Mode::PRIVATE_FILE);
        plant_file(
            &home.join(".gitconfig"),
            "[user]\n\tname = before\n",
            Mode::DEFAULT_FILE,
        );
        plant_file(
            &home.join(".vault/gone.conf"),
            "bx made this\n",
            Mode::PRIVATE_FILE,
        );
        // A directory the user made private after bx created it: a rollback
        // that re-created it would do so at the default mode.
        fs::set_mode(&home.join(".vault"), Mode::PRIVATE_DIR).expect("chmod ~/.vault");
        // `~/.config` deliberately does not exist: the middle write has to
        // invent two directories, and a rollback has to remove both.
    }

    /// The bytes and mode at one destination, or `None` where nothing is.
    type FileState = Option<(Vec<u8>, Mode)>;

    /// What the crash harness compares before and after: bytes and mode at
    /// each destination, and the mode of each directory between a
    /// destination and the home — the ones a write invents and the ones a
    /// removal claims — or `None` where there is none.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Snapshot {
        files: Vec<(PathBuf, FileState)>,
        dirs: Vec<(PathBuf, Option<Mode>)>,
    }

    /// The mode of the directory at `path`, following no link, or `None`
    /// when no directory is there.
    fn dir_mode(path: &Path) -> Option<Mode> {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::symlink_metadata(path)
            .ok()
            .filter(std::fs::Metadata::is_dir)
            .map(|meta| Mode::from_bits(meta.permissions().mode() & 0o7777))
    }

    /// The crash harness's snapshot of `home`.
    fn crash_snapshot(home: &Path) -> Snapshot {
        let requests = crash_requests(home);
        let mut dirs: Vec<PathBuf> = requests
            .iter()
            .flat_map(|request| {
                request
                    .dest
                    .ancestors()
                    .skip(1)
                    .take_while(|dir| *dir != home)
                    .map(Path::to_path_buf)
                    .collect::<Vec<_>>()
            })
            .collect();
        dirs.sort();
        dirs.dedup();
        Snapshot {
            files: requests
                .into_iter()
                .map(|request| (request.dest.clone(), peek(&request.dest)))
                .collect(),
            dirs: dirs
                .into_iter()
                .map(|dir| {
                    let mode = dir_mode(&dir);
                    (dir, mode)
                })
                .collect(),
        }
    }

    /// Every path under `root`, files and directories alike.
    fn walk(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path.clone());
                }
                found.push(path);
            }
        }
        found.sort();
        found
    }

    /// Every leftover bx temporary file under `root`.
    fn leftover_temps(root: &Path) -> Vec<PathBuf> {
        walk(root)
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(fs::TEMP_PREFIX))
            })
            .collect()
    }

    /// Re-invoke this test binary, crashing at `phase` of write `index`.
    fn spawn_crash_child(home: &Path, index: usize, phase: &str) -> Output {
        spawn_child("recover::tests::crash_child", home, index, phase)
    }

    /// Re-invoke this test binary to run the ignored test `child`, crashing
    /// at `phase` of write `index`.
    fn spawn_child(child: &str, home: &Path, index: usize, phase: &str) -> Output {
        let exe = std::env::current_exe().expect("the test binary");
        Command::new(exe)
            .args(["--exact", "--ignored", "--nocapture", child])
            .env(CRASH_AT, format!("{index}:{phase}"))
            .env(CRASH_HOME, home)
            // cargo-llvm-cov points this at a pattern the parent owns. The child
            // is going to abort, so it would write no profile anyway; removing
            // it makes that independent of how coverage is configured.
            .env_remove("LLVM_PROFILE_FILE")
            .output()
            .expect("spawn the crash child")
    }

    /// The crashing half of the harness.
    ///
    /// Ignored, so an ordinary `cargo test` never runs it and never aborts the
    /// suite, and a bare `cargo test -- --ignored` finds no `BX_CRASH_HOME` and
    /// returns without doing anything. It is given its home explicitly, per
    /// process, and sets no variable of its own.
    #[test]
    #[ignore = "spawned by the crash harness; it aborts on purpose"]
    fn crash_child() {
        let Some(home) = std::env::var_os(CRASH_HOME) else {
            return;
        };
        let home = PathBuf::from(home);
        let state = StateDir::resolve(&home);
        let mut session =
            Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
        for request in crash_requests(&home) {
            session.apply(request).expect("apply");
        }
        session.finish().expect("finish");
    }

    /// The crashing half of [`a_killed_rm_rolls_back_into_the_directory_it_found`]:
    /// `rm` of `~/.vault/key.conf`, which bx created with `~/.vault`.
    #[test]
    #[ignore = "spawned by a crash test; it aborts on purpose"]
    fn rm_crash_child() {
        let Some(home) = std::env::var_os(CRASH_HOME) else {
            return;
        };
        let home = PathBuf::from(home);
        let state = StateDir::resolve(&home);
        let key = Portable::from_path(&home.join(".vault/key.conf"), &home).expect("portable");
        // Its outcome is the parent's to judge, from what the crash left.
        let _ = crate::restore::restore(&state, &home, &[key]);
    }

    #[test]
    fn a_killed_rm_rolls_back_into_the_directory_it_found() {
        // r3 round 2, P9R4-D2. A removal pruned the directories it claimed
        // before its session's `End`, so a rollback re-created `~/.vault` at
        // the default mode after the user had made it `0700`. Pruning now
        // waits for `End`; a crash between the two leaves the directory,
        // empty, for `bx doctor`.
        let guard = guarded_home();
        for (index, phase) in [
            (0, "after-intent"),
            (0, "after-publish"),
            (0, "after-done"),
            (1, "after-end"),
            (1, "after-save"),
        ] {
            let case = format!("{index}:{phase}");
            let home = guard.child(format!("rm-{index}-{phase}"));
            let state = StateDir::resolve(&home);
            let vault = home.join(".vault");
            let mut session =
                Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
            let request = write_to(&home, ".vault/key.conf", "secret\n", Mode::PRIVATE_FILE);
            let key = request.target.clone();
            session
                .apply(request)
                .expect("bx creates ~/.vault/key.conf");
            session.finish().expect("finish");
            fs::set_mode(&vault, Mode::PRIVATE_DIR).expect("the user makes ~/.vault private");

            let out = spawn_child("recover::tests::rm_crash_child", &home, index, phase);
            assert!(
                !out.status.success(),
                "{case}: the child was supposed to die; it said {}",
                String::from_utf8_lossy(&out.stdout),
            );
            let after_kill = dir_mode(&vault);
            let report = pending(&state).expect("pending").expect("a journal stands");
            assert!(report.blocked().next().is_none(), "{case}");
            let note = report.unfinished[0].note.clone();
            let outcome = recover(&state).expect("the next writing run");
            assert!(!state.journal().exists(), "{case}");
            let entry = LedgerView::read(&state, &home)
                .expect("read the ledger")
                .value
                .get(&key)
                .cloned();

            if index == 0 {
                assert_eq!(outcome, Outcome::RolledBack { undone: 1 }, "{case}");
                assert_eq!(
                    peek(&home.join(".vault/key.conf")),
                    Some((b"secret\n".to_vec(), Mode::PRIVATE_FILE)),
                    "{case}"
                );
                assert_eq!(
                    dir_mode(&vault),
                    Some(Mode::PRIVATE_DIR),
                    "{case}: rolled back into the directory the rm found, at its mode"
                );
                assert_eq!(
                    after_kill,
                    Some(Mode::PRIVATE_DIR),
                    "{case}: nothing is pruned before End"
                );
                assert!(entry.is_some(), "{case}: bx still manages it");
                assert!(!note.contains("bx doctor"), "{case}: {note}");
            } else if phase == "after-end" {
                assert_eq!(outcome, Outcome::Recorded { entries: 1 }, "{case}");
                assert_eq!(after_kill, Some(Mode::PRIVATE_DIR), "{case}");
                assert!(
                    note.contains(
                        "before it removed ~/.vault, which stand empty and are left for bx doctor"
                    ),
                    "{case}: {note}"
                );
                assert_eq!(
                    dir_mode(&vault),
                    Some(Mode::PRIVATE_DIR),
                    "{case}: recovery removes no directory"
                );
                assert_eq!(names_in(&vault), Vec::<String>::new(), "{case}");
                assert!(entry.is_none(), "{case}: the removal is recorded");
                assert!(
                    LedgerView::read(&state, &home)
                        .expect("read the ledger")
                        .value
                        .iter()
                        .all(|(_, entry)| entry.created_dirs.is_empty()),
                    "{case}: no entry claims the orphan"
                );
            } else {
                assert_eq!(outcome, Outcome::Recorded { entries: 1 }, "{case}");
                assert_eq!(after_kill, None, "{case}: pruned before the save");
                assert!(!note.contains("bx doctor"), "{case}: {note}");
                assert!(entry.is_none(), "{case}");
            }
            assert_eq!(recover(&state).expect("again"), Outcome::Nothing);
        }
    }

    #[test]
    fn the_intent_is_durable_before_the_destination_is_touched() {
        let guard = guarded_home();

        // Stopping one boundary *before* the intent: nothing is recorded, and
        // the destination is untouched.
        let early = guard.child("early");
        plant_crash_fixture(&early);
        assert!(!spawn_crash_child(&early, 0, "after-fill").status.success());
        let loaded = crate::journal::load(&StateDir::resolve(&early).journal()).expect("load");
        assert_eq!(
            loaded.intents().count(),
            0,
            "no intent had been written yet"
        );
        assert_eq!(
            peek(&early.join(".bxrc")).expect("the destination").0,
            b"before bx\n",
            "and the destination had not been touched",
        );

        // Stopping one boundary *after* it: the frame is on disk and fsynced,
        // and the destination is *still* untouched. The whole recoverability
        // argument lives in that gap.
        let late = guard.child("late");
        plant_crash_fixture(&late);
        assert!(!spawn_crash_child(&late, 0, "after-intent").status.success());
        let loaded = crate::journal::load(&StateDir::resolve(&late).journal()).expect("load");
        let intents: Vec<&Intent> = loaded.intents().collect();
        assert_eq!(intents.len(), 1, "the intent is durable");
        assert_eq!(intents[0].dest, late.join(".bxrc"));
        assert!(intents[0].temp.as_ref().expect("a staged temp").is_file());
        assert_eq!(
            peek(&late.join(".bxrc")).expect("the destination").0,
            b"before bx\n",
            "and the destination is still what it was",
        );
    }

    #[test]
    fn nothing_to_recover_is_not_an_error() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        assert!(pending(&state).expect("pending").is_none());
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert_eq!(recover(&state).expect("before"), Outcome::Nothing);
        assert_eq!(abandon(&state).expect("abandon"), None);
    }

    #[test]
    fn a_target_left_at_the_new_bytes_rolls_back_to_the_prior_bytes() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        assert_eq!(peek(&dest).expect("written").0, b"new\n");

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished.len(), 1);
        assert_eq!(interruption.unfinished[0].standing, Standing::Written);
        assert_eq!(interruption.kind, SessionKind::Apply);

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(
            peek(&dest).expect("restored"),
            (b"old\n".to_vec(), Mode::DEFAULT_FILE),
        );
        assert!(!state.journal().exists(), "the journal is unlinked last");
    }

    #[test]
    fn a_second_write_to_the_same_target_rolls_back_to_what_it_actually_displaced() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "the user's\n", Mode::DEFAULT_FILE);

        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(home.path(), ".conf", "one\n", Mode::DEFAULT_FILE))
            .expect("apply");
        first.finish().expect("finish");

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "two\n", Mode::DEFAULT_FILE)],
        );

        // Not "the user's", which is what the ledger's first-prior rule keeps:
        // a rollback returns the destination to the state the last *finished*
        // run left it in, so the next plan is computed against what the user
        // last saw converge.
        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished[0].standing, Standing::Written);
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(peek(&dest).expect("rolled back").0, b"one\n");

        // And `bx rm` still hands back what the user had before bx existed.
        assert!(matches!(
            crate::restore::restore(&state, home.path(), &[target(home.path(), ".conf").0])
                .expect("restore")
                .as_slice(),
            [crate::restore::Restored::Reverted { .. }],
        ));
        assert_eq!(peek(&dest).expect("restored").0, b"the user's\n");
    }

    #[test]
    fn roll_back_restores_the_prior_mode() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".ssh-config");
        plant_file(&dest, "Host *\n", Mode::PRIVATE_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                ".ssh-config",
                "Host *\n",
                Mode::DEFAULT_FILE,
            )],
        );
        assert_eq!(peek(&dest).expect("written").1, Mode::DEFAULT_FILE);

        recover(&state).expect("recover");
        assert_eq!(
            peek(&dest).expect("restored"),
            (b"Host *\n".to_vec(), Mode::PRIVATE_FILE),
            "the same bytes at a different mode is still a change to undo",
        );
    }

    #[test]
    fn a_target_left_at_the_prior_bytes_rolls_back_to_a_no_op() {
        let guard = guarded_home();
        let home = guard.child("crashed");
        plant_crash_fixture(&home);
        let before = crash_snapshot(&home);

        // Dying one boundary after the intent is durable: the destination has
        // not been replaced yet, so the rollback has nothing to write.
        assert!(
            !spawn_crash_child(&home, 0, "after-intent").status.success(),
            "the child was supposed to die",
        );
        let state = StateDir::resolve(&home);
        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished[0].standing, Standing::Prior);

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(crash_snapshot(&home), before);
    }

    #[test]
    fn a_target_the_session_created_is_removed_not_emptied_by_roll_back() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".config/deep/made.conf");

        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                ".config/deep/made.conf",
                "made\n",
                Mode::DEFAULT_FILE,
            )],
        );
        assert!(dest.is_file());

        recover(&state).expect("recover");
        assert!(!dest.exists(), "removed, never left as an empty file");
        assert!(!home.child(".config/deep").exists());
        assert!(
            !home.child(".config").exists(),
            "and the parents it invented",
        );
    }

    #[test]
    fn directories_the_session_created_are_removed_only_while_empty() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());

        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                ".config/deep/made.conf",
                "made\n",
                Mode::DEFAULT_FILE,
            )],
        );
        // The user put something of their own in the directory bx invented.
        std::fs::write(home.child(".config/deep/theirs"), "mine").expect("write");

        recover(&state).expect("recover");
        assert!(!home.child(".config/deep/made.conf").exists());
        assert!(
            home.child(".config/deep/theirs").is_file(),
            "a byte the user wrote is never removed",
        );
        assert!(home.child(".config/deep").is_dir());
        assert!(home.child(".config").is_dir(), "and the walk stopped there");
    }

    #[test]
    fn roll_back_undoes_completed_writes_too() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".one"), "one\n", Mode::DEFAULT_FILE);
        plant_file(&home.child(".two"), "two\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![
                write_to(home.path(), ".one", "ONE\n", Mode::DEFAULT_FILE),
                write_to(home.path(), ".two", "TWO\n", Mode::DEFAULT_FILE),
            ],
        );
        // Both reached `Done`; the journal is a transaction, not a tail.
        let loaded = crate::journal::load(&state.journal()).expect("load");
        assert_eq!(
            loaded
                .records()
                .iter()
                .filter(|record| matches!(record, Record::Done(_)))
                .count(),
            2,
        );

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 2 },
        );
        assert_eq!(peek(&home.child(".one")).expect("one").0, b"one\n");
        assert_eq!(peek(&home.child(".two")).expect("two").0, b"two\n");
    }

    #[test]
    fn a_removal_rolls_back_to_the_file_it_removed() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".config/deep/made.conf");
        plant_file(&dest, "bx wrote this\n", Mode::PRIVATE_FILE);

        interrupted(
            &state,
            home.path(),
            vec![Request {
                target: portable,
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: vec![home.child(".config/deep"), home.child(".config")],
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::PRIVATE_FILE,
                ownership: Ownership::Released,
            }],
        );
        assert!(!dest.exists(), "the removal completed");
        assert!(
            home.child(".config/deep").is_dir(),
            "nothing a removal claims is pruned before its session's End",
        );

        recover(&state).expect("recover");
        assert_eq!(
            peek(&dest).expect("restored"),
            (b"bx wrote this\n".to_vec(), Mode::PRIVATE_FILE),
            "an interrupted removal puts the file back, parents and all",
        );
    }

    #[test]
    fn a_leftover_temp_file_named_by_an_intent_is_removed() {
        let guard = guarded_home();
        let home = guard.child("crashed");
        plant_crash_fixture(&home);
        assert!(!spawn_crash_child(&home, 0, "after-intent").status.success());

        let state = StateDir::resolve(&home);
        let loaded = crate::journal::load(&state.journal()).expect("load");
        let temp = loaded
            .intents()
            .next()
            .expect("one intent")
            .temp
            .clone()
            .expect("a staged temp file");
        assert!(temp.is_file(), "the crash left it behind");
        let note = pending(&state)
            .expect("pending")
            .expect("interrupted")
            .unfinished[0]
            .note
            .clone();
        assert!(
            !note.contains("temporary file"),
            "it can be removed: {note}"
        );

        recover(&state).expect("recover");
        assert!(!temp.exists(), "and recovery removed exactly it");
        assert!(leftover_temps(&home).is_empty());
    }

    #[test]
    fn a_temp_file_no_intent_names_is_left_alone() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        // Named like bx's, but bx did not make it and cannot prove it did.
        let stray = home.child(".bx-not-mine.tmp");
        plant_file(&stray, "somebody else's", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        recover(&state).expect("recover");

        assert_eq!(
            peek(&stray).expect("still there").0,
            b"somebody else's",
            "recovery removes the one path the journal names, and nothing else",
        );
    }

    #[test]
    fn a_destination_edited_after_the_crash_is_reported_not_overwritten() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&dest, "the user's own edit\n", Mode::DEFAULT_FILE);

        let outcome = recover(&state).expect("recover");
        let Outcome::Blocked { conflicts } = &outcome else {
            panic!("got {outcome:?}")
        };
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].standing, Standing::Diverged);
        assert_eq!(conflicts[0].action(), Action::Conflict);
        assert!(conflicts[0].note.contains("will not overwrite"));
        assert!(!outcome.is_clear());
        assert_eq!(
            peek(&dest).expect("untouched").0,
            b"the user's own edit\n",
            "Invariant 1 does not lapse because a crash happened",
        );
    }

    #[test]
    fn a_vanished_destination_is_not_resurrected() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        std::fs::remove_file(&dest).expect("the user removed it");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a vanished destination blocks recovery")
        };
        assert_eq!(conflicts[0].standing, Standing::Vanished);
        assert!(
            !dest.exists(),
            "bx does not put back a file nobody asked for",
        );
    }

    #[test]
    fn a_destination_that_is_no_longer_a_file_blocks_recovery() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        std::fs::remove_file(&dest).expect("remove");
        std::fs::create_dir(&dest).expect("a directory in its place");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a foreign destination blocks recovery")
        };
        assert_eq!(conflicts[0].standing, Standing::Foreign);
        assert!(dest.is_dir());
    }

    #[test]
    fn a_missing_prior_blob_is_reported_not_guessed() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        let blob = state.restore().join(ContentHash::of(b"old\n").to_hex());
        std::fs::remove_file(&blob).expect("delete the snapshot");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a missing snapshot blocks recovery")
        };
        assert!(
            conflicts[0].note.contains("missing"),
            "{}",
            conflicts[0].note,
        );
        assert_eq!(
            peek(&home.child(".conf")).expect("untouched").0,
            b"new\n",
            "bx writes nothing rather than guessing at the bytes it displaced",
        );
    }

    #[test]
    fn a_prior_blob_whose_digest_does_not_match_is_refused() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        let blob = state.restore().join(ContentHash::of(b"old\n").to_hex());
        std::fs::write(&blob, "not what it claims to be").expect("corrupt the snapshot");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a corrupt snapshot blocks recovery")
        };
        assert!(
            conflicts[0].note.contains("does not match"),
            "{}",
            conflicts[0].note,
        );
    }

    #[test]
    fn the_journal_survives_a_blocked_recovery_and_writing_is_refused() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&dest, "edited\n", Mode::DEFAULT_FILE);

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. }
        ));
        assert!(state.journal().exists(), "the interruption still stands");

        let err = lock_for_writing(&state).expect_err("a writing command must refuse");
        let Error::Blocked { conflicts } = &err else {
            panic!("got {err}")
        };
        assert_eq!(conflicts.len(), 1);
        assert!(err.to_string().contains(&dest.display().to_string()));

        // And it is still standing after the refusal, run after run.
        assert!(matches!(
            recover(&state).expect("recover again"),
            Outcome::Blocked { .. }
        ));
        assert!(state.journal().exists());
    }

    #[test]
    fn a_blocked_recovery_reports_pending() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&home.child(".conf"), "edited\n", Mode::DEFAULT_FILE);

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.actions(), vec![Action::Conflict]);
        assert_eq!(interruption.exit(), Exit::Pending);
        assert_eq!(interruption.blocked().count(), 1);
        assert!(interruption.unfinished[0].describe().contains(".conf"));
        assert!(
            state.journal().exists(),
            "a read-only command writes nothing at all",
        );
    }

    #[test]
    fn an_interruption_that_named_nothing_still_exits_pending() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.unfinished.is_empty());
        assert_eq!(
            interruption.exit(),
            Exit::Pending,
            "the machine is still not converged, so somebody has to look",
        );
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 0 },
        );
    }

    #[test]
    fn abandoning_a_recovery_touches_no_destination() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&dest, "edited\n", Mode::DEFAULT_FILE);

        let aside = abandon(&state)
            .expect("abandon")
            .expect("a journal was there");
        assert_eq!(aside, StateDir::quarantine(&state.journal()));
        assert!(aside.is_file(), "the bytes are kept, never deleted");
        assert!(!state.journal().exists());
        assert_eq!(
            peek(&dest).expect("untouched").0,
            b"edited\n",
            "abandoning writes nothing to any destination",
        );

        // And the refusal is cleared: bx can write again.
        assert!(pending(&state).expect("pending").is_none());
        drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
    }

    #[test]
    fn recovery_run_twice_changes_nothing_the_second_time() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        assert_eq!(
            recover(&state).expect("first"),
            Outcome::RolledBack { undone: 1 },
        );
        let after_first = peek(&dest).expect("restored");
        assert_eq!(recover(&state).expect("second"), Outcome::Nothing);
        assert_eq!(peek(&dest).expect("still restored"), after_first);
        assert_eq!(recover(&state).expect("third"), Outcome::Nothing);
    }

    #[test]
    fn a_terminated_journal_brings_the_ledger_up_to_date_without_touching_a_file() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![
                write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE),
                write_to(
                    home.path(),
                    ".config/deep/made.conf",
                    "made\n",
                    Mode::PRIVATE_FILE,
                ),
            ],
        );
        // Every write landed; the process died between the End frame and the
        // ledger save, which is the one window `finish` leaves open.
        seal(&state.journal(), 2);
        assert!(!state.ledger().exists(), "the ledger never got saved");

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.complete);

        let before = (
            peek(&home.child(".conf")),
            peek(&home.child(".config/deep/made.conf")),
        );
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 2 },
        );
        assert_eq!(
            (
                peek(&home.child(".conf")),
                peek(&home.child(".config/deep/made.conf")),
            ),
            before,
            "no destination is touched: only the machine's own bookkeeping",
        );

        let ledger = LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value;
        let modified = ledger
            .get(&target(home.path(), ".conf").0)
            .expect("the modify");
        assert_eq!(modified.written, ContentHash::of(b"new\n"));
        assert_eq!(modified.mode, Mode::DEFAULT_FILE);
        assert_eq!(modified.mechanism, Mechanism::Own);
        let Prior::Existed(reference) = &modified.prior else {
            panic!("the prior bytes are recorded")
        };
        assert_eq!(reference.digest, ContentHash::of(b"old\n"));

        let created = ledger
            .get(&target(home.path(), ".config/deep/made.conf").0)
            .expect("the create");
        assert_eq!(created.prior, Prior::Absent);
        assert_eq!(created.mode, Mode::PRIVATE_FILE);
        assert_eq!(
            created
                .created_dirs
                .iter()
                .map(|dir| dir.render(home.path()))
                .collect::<Vec<_>>(),
            vec![home.child(".config/deep"), home.child(".config")],
        );

        assert!(!state.journal().exists());
        assert_eq!(recover(&state).expect("again"), Outcome::Nothing);
    }

    #[test]
    fn a_terminated_release_leaves_the_target_out_of_the_ledger() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "mine\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![Request {
                target: portable.clone(),
                content: Content::Bytes {
                    bytes: b"yours\n".to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                dest,
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            }],
        );
        seal(&state.journal(), 1);

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 },
        );
        assert!(
            LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .is_none()
        );
    }

    #[test]
    fn a_writing_command_holds_one_lock_across_its_recovery_and_its_session() {
        // r3 round 3, CL3. A recovery followed by `Session::open` drops
        // the state directory between the two, so a second bx could win it and
        // this one's session would refuse with `InProgress` naming a journal
        // that belongs to a live run rather than to an interruption.
        //
        // The one-lock property itself is the type's: `lock_for_writing`
        // returns the guard by value and `Session::open_locked` consumes it,
        // so there is no point at which a caller of the pair can be without
        // it. What this pins is the contract around that — the recovery runs
        // and reports, the returned guard is held, the session takes it over
        // rather than acquiring a second one, a finished session gives it
        // back, and a session refused for its scope gives it back too. It is
        // the last that would otherwise be unreached: `open_locked` owns the
        // guard, so an early return has to drop it.
        //
        // What it does *not* establish is that a writing command uses the
        // pair: nothing in the type system says so, and `restore` being the
        // only writing command at this revision is what makes it true today.
        // What narrows it is that `lock_for_writing` is now the only call that
        // refuses a blocked recovery — `before_writing`, which did the same
        // and released the lock, had no caller but a test and is gone
        // (`r3 round 5`, CL1).
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        let lock = lock_for_writing(&state).expect("recover and keep the lock");
        assert_eq!(
            peek(&dest).expect("rolled back").0,
            b"old\n",
            "the recovery ran under the guard that came back",
        );
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_none(),
            "the recovery did not release the lock",
        );

        let session =
            Session::open_locked(&state, SessionKind::Restore, home.path(), Vec::new(), lock)
                .expect("the session takes the guard");
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_none(),
            "and the session holds the same one",
        );
        assert_eq!(session.finish().expect("finish"), 0);
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_some(),
            "only the finished session releases it",
        );

        // A scope the loader would refuse is refused under the caller's lock
        // too, and releases it: `open_locked` owns the guard either way.
        let lock = lock_for_writing(&state).expect("nothing to recover");
        let absolute = Portable::try_from(dest.to_str().expect("utf-8").to_string())
            .expect("a well-formed absolute path");
        let err = Session::open_locked(
            &state,
            SessionKind::Restore,
            home.path(),
            vec![absolute],
            lock,
        )
        .expect_err("a scope entry the loader refuses");
        assert!(
            matches!(
                err,
                journal::Error::State(crate::state::Error::ForeignRecord { .. })
            ),
            "got {err}"
        );
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_some(),
            "the refused session released the lock",
        );
    }

    #[test]
    fn replaying_a_released_write_hands_on_the_directories_its_entry_claimed() {
        // r3 round 4, D1 and COV2. `Session::write` was repaired in round 3 to
        // stop discarding the entry `ledger.forget` returns; `resolve`'s
        // `Step::Forget` still discarded it, so the same `rm`, crashed between
        // its `End` frame and its save, lost the claims the live path keeps.
        // `hand_off_claims` documents the replay as running "the same hand-off
        // … so a crash between the `End` frame and the save loses no claim",
        // and nothing reached `Step::Forget` for a released write at all.
        //
        // A released write's Intent cannot stand in for the entry: it records
        // the directories *that write* invented, which for a write over a file
        // that is already there is none.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dir = home.child(".config/app");
        let claims = vec![home.child(".config"), home.child(".config/app")];

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        for rel in [".config/app/a.conf", ".config/app/heir.conf"] {
            session
                .apply(write_to(home.path(), rel, "bx\n", Mode::DEFAULT_FILE))
                .expect("apply");
        }
        session.finish().expect("finish");
        let (a, a_dest) = target(home.path(), ".config/app/a.conf");
        let (heir, _) = target(home.path(), ".config/app/heir.conf");
        let saved_claims = |what: &Portable| -> Vec<PathBuf> {
            let mut dirs = LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(what)
                .map(|entry| {
                    entry
                        .created_dirs
                        .iter()
                        .map(|d| d.render(home.path()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            dirs.sort();
            dirs
        };
        assert_eq!(saved_claims(&a), claims, "a.conf claims both directories");
        assert!(saved_claims(&heir).is_empty());

        // `rm a.conf` hands the file back and then dies between its `End`
        // frame and its ledger save: a terminated journal over a ledger that
        // still holds the entry.
        interrupted(
            &state,
            home.path(),
            vec![Request {
                target: a.clone(),
                dest: a_dest.clone(),
                content: Content::Bytes {
                    bytes: b"theirs\n".to_vec(),
                    planned: fs::observe(&a_dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            }],
        );
        seal(&state.journal(), 1);
        let intent = journal::load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .cloned()
            .expect("the released write's Intent");
        assert!(
            intent.created_dirs.is_empty(),
            "the Intent carries no claim of its own: {:?}",
            intent.created_dirs,
        );

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 },
        );
        assert!(saved_claims(&a).is_empty(), "the entry was handed back");
        assert_eq!(
            saved_claims(&heir),
            claims,
            "and its claims reached the entry still beneath them, as the live \
             path's do",
        );
        assert_eq!(peek(&a_dest).expect("handed back").0, b"theirs\n");
        assert!(dir.is_dir(), "nothing was pruned: no removal was announced");
    }

    #[test]
    fn a_blocked_recovery_hands_no_claim_on_and_leaves_the_saved_ledger_alone() {
        // r3 coverage COV4. One terminated journal holding both a blocked
        // intent and a released removal: the removal's claims must not reach
        // the entry beneath them while the run returns `Blocked`, and the
        // saved ledger must be exactly what it was. Once the conflict is
        // cleared, the same journal hands them on, which is what says the
        // first half is "not yet" rather than "never".
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let theirs = "theirs\n";
        plant_file(&home.child(".blocked"), theirs, Mode::DEFAULT_FILE);

        // bx makes ~/.config/app for gone.conf, which claims it and ~/.config;
        // heir.conf goes in beside it and claims nothing.
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        for rel in [".config/app/gone.conf", ".config/app/heir.conf"] {
            session
                .apply(write_to(home.path(), rel, "bx\n", Mode::DEFAULT_FILE))
                .expect("apply");
        }
        session.finish().expect("finish");
        let (gone, gone_dest) = target(home.path(), ".config/app/gone.conf");
        let (heir, _) = target(home.path(), ".config/app/heir.conf");
        let claims = vec![home.child(".config"), home.child(".config/app")];
        let saved_claims = |what: &Portable| -> Vec<PathBuf> {
            let mut dirs = LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(what)
                .map(|entry| {
                    entry
                        .created_dirs
                        .iter()
                        .map(|dir| dir.render(home.path()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            dirs.sort();
            dirs
        };
        assert_eq!(saved_claims(&gone), claims, "gone.conf claims both");
        assert!(saved_claims(&heir).is_empty(), "heir.conf claims neither");

        // The interrupted session removes gone.conf, releasing both claims,
        // and rewrites ~/.blocked, whose prior snapshot then goes missing.
        interrupted(
            &state,
            home.path(),
            vec![
                Request {
                    target: gone.clone(),
                    dest: gone_dest.clone(),
                    content: Content::Absent {
                        created_dirs: claims.iter().rev().cloned().collect(),
                        planned: fs::observe(&gone_dest).expect("plan's observation"),
                    },
                    mode: Mode::DEFAULT_FILE,
                    ownership: Ownership::Released,
                },
                write_to(home.path(), ".blocked", "bx\n", Mode::DEFAULT_FILE),
            ],
        );
        seal(&state.journal(), 2);
        let blob = state
            .restore()
            .join(ContentHash::of(theirs.as_bytes()).to_hex());
        std::fs::remove_file(&blob).expect("delete the snapshot");

        let outcome = recover(&state).expect("recover");
        assert!(
            matches!(&outcome, Outcome::Blocked { conflicts } if conflicts.len() == 1),
            "{outcome:?}"
        );
        assert!(state.journal().exists(), "the journal is kept");
        assert_eq!(
            saved_claims(&gone),
            claims,
            "a blocked run saves no ledger, so the removal's entry stands",
        );
        assert!(
            saved_claims(&heir).is_empty(),
            "and no claim was handed to the entry beneath them",
        );

        // Clear the conflict and run again: now the hand-off happens.
        std::fs::write(&blob, theirs).expect("put the snapshot back");
        let outcome = recover(&state).expect("recover again");
        assert!(
            matches!(outcome, Outcome::Recorded { entries: 2 }),
            "{outcome:?}"
        );
        assert!(saved_claims(&gone).is_empty(), "the removal is recorded");
        assert_eq!(
            saved_claims(&heir),
            claims,
            "and both claims reached the entry still beneath them",
        );
    }

    #[test]
    fn a_rebuild_over_a_ledger_at_the_same_digest_and_another_mode_records_the_mode() {
        // r3 coverage COV6. `decide`'s already-saved skip is "the stored entry
        // is at the intent's `after` digest *and mode*". No fixture differed
        // in mode alone, so deleting the mode conjunct passed: a terminated
        // journal whose write changed only the mode, over a ledger at that
        // digest at the old mode, would be skipped and the mode change lost.
        //
        // A ledger and a journal can disagree this way whenever the ledger is
        // not the one the session opened — an older ledger put back beside a
        // newer journal, or one rebuilt after a quarantine — so the journal is
        // built here rather than crashed out of a session.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let bytes = "bx\n";
        let digest = ContentHash::of(bytes.as_bytes());
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(home.path(), ".conf", bytes, Mode::DEFAULT_FILE))
            .expect("apply");
        session.finish().expect("finish");
        let (portable, dest) = target(home.path(), ".conf");
        let stored = |state: &StateDir| {
            LedgerView::read(state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .cloned()
                .expect("the entry")
        };
        assert_eq!(
            (stored(&state).written, stored(&state).mode),
            (digest, Mode::DEFAULT_FILE),
        );

        // The same bytes at a narrower mode, landed, with the ledger the
        // session opened holding nothing for the target.
        raw_journal(
            &state.journal(),
            &[
                Record::Begin(Begin {
                    kind: SessionKind::Apply,
                    home: home.path().to_path_buf(),
                    scope: Vec::new(),
                }),
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest: dest.clone(),
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Present {
                        digest,
                        mode: Mode::PRIVATE_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                }),
                Record::Done(Done {
                    target: portable.clone(),
                }),
                Record::End(End { written: 1 }),
            ],
        );

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 },
        );
        assert_eq!(
            (stored(&state).written, stored(&state).mode),
            (digest, Mode::PRIVATE_FILE),
            "the mode the journal records is the mode the ledger ends at",
        );
    }

    #[test]
    fn a_blocked_targets_note_names_both_states_it_could_legitimately_hold() {
        // r3 coverage COV7. `note`'s "held {digest}" and "was to be removed"
        // arms were never asserted, and they are the whole operator-facing
        // surface of a blocked recovery: the file, both legitimate digests,
        // and `abandon` as the way out.
        let home = guarded_home();
        let (portable, dest) = target(home.path(), ".conf");
        let old = ContentHash::of(b"old\n");
        let new = ContentHash::of(b"new\n");
        let base = Intent {
            target: portable,
            dest,
            temp: None,
            before: Prior::Absent,
            after: Written::Absent,
            created_dirs: Vec::new(),
            mechanism: Some(Mechanism::Own),
            ledger_written: None,
        };
        let tail = "bx will not overwrite it. Put back either of those two states, \
                    or abandon the interrupted session to have bx report it as a \
                    conflict instead.";

        let created = Intent {
            after: Written::Present {
                digest: new,
                mode: Mode::DEFAULT_FILE,
            },
            ..base.clone()
        };
        assert_eq!(
            note(&created, Standing::Diverged),
            format!(
                "was edited after the interruption; before the interruption it \
                 did not exist, and it was being given {new}. {tail}"
            ),
        );

        let modified = Intent {
            before: Prior::Existed(RestoreRef {
                digest: old,
                mode: Mode::DEFAULT_FILE,
                len: 4,
            }),
            ..created
        };
        assert_eq!(
            note(&modified, Standing::Diverged),
            format!(
                "was edited after the interruption; before the interruption it \
                 held {old}, and it was being given {new}. {tail}"
            ),
        );

        let removal = Intent {
            before: Prior::Existed(RestoreRef {
                digest: old,
                mode: Mode::DEFAULT_FILE,
                len: 4,
            }),
            mechanism: None,
            ..base
        };
        assert_eq!(
            note(&removal, Standing::Foreign),
            format!(
                "is not a regular file; before the interruption it held {old}, \
                 and it was to be removed. {tail}"
            ),
        );
    }

    #[test]
    fn a_terminated_journal_with_a_missing_blob_is_blocked() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        std::fs::remove_file(state.restore().join(ContentHash::of(b"old\n").to_hex()))
            .expect("delete the snapshot");

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. },
        ));
        assert!(state.journal().exists(), "and the journal is kept");
    }

    #[test]
    fn a_prior_snapshot_that_cannot_be_read_stops_recovery_as_an_error() {
        // r3 coverage C10. A missing or corrupt snapshot is a verdict; any
        // other failure to read one is an error, for the report and the
        // recovery alike, and nothing is changed.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        let blob = state.restore().join(ContentHash::of(b"old\n").to_hex());
        std::fs::remove_file(&blob).expect("remove the snapshot");
        std::fs::create_dir(&blob).expect("a directory where the snapshot was");

        let reported = pending(&state);
        assert!(
            matches!(
                reported,
                Err(Error::State(crate::state::Error::Read { .. }))
            ),
            "got {reported:?}"
        );
        let recovered = recover(&state);
        assert!(
            matches!(
                recovered,
                Err(Error::State(crate::state::Error::Read { .. }))
            ),
            "got {recovered:?}"
        );
        assert_eq!(peek(&dest).expect("untouched").0, b"new\n");
        assert!(state.journal().exists(), "the journal is kept");
    }

    #[test]
    fn a_journal_that_records_a_write_with_no_header_is_set_aside_not_replayed() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");

        let (portable, dest) = target(home.path(), ".conf");
        raw_journal(
            &state.journal(),
            &[
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest,
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Absent,
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                }),
                Record::Done(Done { target: portable }),
                Record::End(End { written: 1 }),
            ],
        );
        let bytes = std::fs::read(state.journal()).expect("the journal");

        // No header, so no home to check a single stored path against: bytes bx
        // never wrote, for a report and for recovery alike.
        assert!(
            pending(&state)
                .expect("pending")
                .expect("reported")
                .unreadable
        );
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            bytes,
        );
        assert!(!state.journal().exists());
    }

    #[test]
    fn a_terminated_journal_with_no_header_has_no_home_to_rebuild_against() {
        // r3 coverage C12. The loader refuses a journal whose first frame is
        // not its header, so no journal on disk reaches this. Pinned on a
        // hand-built value, so such a journal can only be refused, never rebuilt.
        let path = Path::new("/nonexistent/journal.mpk");
        let headless = Loaded::Terminated(vec![Record::End(End { written: 0 })]);
        assert!(
            matches!(rebuild_home(&headless, true, path), Err(Error::Headless { path: refused }) if refused == path),
        );
        assert!(matches!(rebuild_home(&headless, false, path), Ok(None)));
    }

    #[test]
    fn pending_never_moves_a_journal_aside_even_one_it_cannot_read() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"not a journal").expect("write");

        // `pending` takes no lock, so what it is reading may be a journal a live
        // session is in the middle of creating. It moves nothing, and it says
        // the journal is there.
        let report = pending(&state).expect("pending").expect("reported");
        assert!(report.unreadable);
        assert!(report.unfinished.is_empty());
        assert_eq!(report.exit(), Exit::Pending);
        assert_eq!(
            std::fs::read(state.journal()).expect("still in place"),
            b"not a journal",
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());

        // The locked path is the one that sets it aside, and keeps the bytes.
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert!(!state.journal().exists());
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            b"not a journal",
        );
    }

    #[test]
    fn a_journal_a_live_session_has_only_just_created_is_reported_and_left_in_place() {
        // The race a concurrent `plan` used to lose: it read the journal in the
        // instant `apply` had created it and not yet written a byte, called that
        // corruption, and renamed the live journal away.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"").expect("write");

        let interruption = pending(&state)
            .expect("pending")
            .expect("an empty journal is still a session");
        assert!(interruption.unfinished.is_empty());
        assert!(!interruption.complete);
        assert_eq!(interruption.exit(), Exit::Pending);
        assert!(state.journal().is_file(), "left exactly where it was");
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn an_intent_without_done_in_a_terminated_journal_records_nothing() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let (portable, dest) = target(home.path(), ".conf");

        raw_journal(
            &state.journal(),
            &[
                Record::Begin(Begin {
                    kind: SessionKind::Apply,
                    home: home.path().to_path_buf(),
                    scope: Vec::new(),
                }),
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest,
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Present {
                        digest: ContentHash::of(b"never landed\n"),
                        mode: Mode::DEFAULT_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                }),
                Record::End(End { written: 0 }),
            ],
        );

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.complete);
        assert_eq!(interruption.blocked().count(), 0);
        assert!(
            interruption.unfinished[0].note.contains("never written"),
            "{}",
            interruption.unfinished[0].note,
        );
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 0 },
        );
        assert!(
            LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .is_none(),
            "a write with no Done never landed, so bx does not own it",
        );
    }

    #[test]
    fn the_report_and_the_recovery_agree_for_every_kind_of_journal() {
        let guard = guarded_home();
        for terminated in [false, true] {
            for edited in [false, true] {
                let case = format!("terminated={terminated} edited={edited}");
                let home = guard.child(format!("t-{terminated}-e-{edited}"));
                let state = StateDir::resolve(&home);
                let dest = home.join(".conf");
                plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
                interrupted(
                    &state,
                    &home,
                    vec![write_to(&home, ".conf", "new\n", Mode::DEFAULT_FILE)],
                );
                if terminated {
                    seal(&state.journal(), 1);
                }
                if edited {
                    plant_file(&dest, "edited after the crash\n", Mode::DEFAULT_FILE);
                }

                let report = pending(&state).expect("pending").expect("interrupted");
                assert_eq!(report.complete, terminated, "{case}");
                let reported_blocked = report.blocked().next().is_some();
                let note = report.unfinished[0].note.clone();

                let outcome = recover(&state).expect("recover");
                assert_eq!(
                    reported_blocked,
                    !outcome.is_clear(),
                    "{case}: the report said blocked={reported_blocked}, recovery did {outcome:?}",
                );
                if terminated {
                    assert_eq!(outcome, Outcome::Recorded { entries: 1 }, "{case}");
                    assert!(note.contains("bookkeeping"), "{case}: {note}");
                    assert!(!note.contains("rolls it back"), "{case}: {note}");
                    assert!(!note.contains("abandon"), "{case}: {note}");
                } else if edited {
                    assert!(matches!(outcome, Outcome::Blocked { .. }), "{case}");
                    assert!(note.contains("will not overwrite"), "{case}: {note}");
                } else {
                    assert_eq!(outcome, Outcome::RolledBack { undone: 1 }, "{case}");
                    assert!(note.contains("rolls it back"), "{case}: {note}");
                }
            }
        }
    }

    #[test]
    fn abandoning_a_journal_that_cannot_be_moved_is_an_error_and_moves_nothing() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        // The session left its lock file, so taking the lock needs no write to
        // the directory; the rename does. Narrower than 0700 rather than wider,
        // so nothing tightens it back.
        fs::set_mode(state.root(), Mode::from_bits(0o500)).expect("make it read-only");
        if !permissions_refuse(state.root()) {
            fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");
            return cannot_build(
                "abandoning_a_journal_that_cannot_be_moved_is_an_error_and_moves_nothing",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let abandoned = abandon(&state);
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");

        let err = abandoned.expect_err("a rename in a read-only directory fails");
        assert!(
            matches!(err, Error::Journal(journal::Error::Io { .. })),
            "got {err}"
        );
        assert!(state.journal().is_file(), "the interruption still stands");
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn abandoning_in_a_state_directory_that_cannot_be_opened_moves_nothing() {
        // Write and search, no read: the rename would succeed and the directory
        // cannot be opened to fsync it. The open comes first, so the failure
        // leaves the journal where it was.
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        fs::set_mode(state.root(), Mode::from_bits(0o300)).expect("chmod");
        let abandoned = abandon(&state);
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it readable again");

        match abandoned {
            Err(Error::Journal(journal::Error::Io { path, source })) => {
                assert_eq!(path, state.root());
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected an io error naming the state directory, got {other:?}"),
        }
        assert!(state.journal().is_file(), "the interruption still stands");
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn the_intent_is_durable_before_a_removal_touches_the_destination() {
        let guard = guarded_home();
        let removal = crash_requests(guard.path())
            .iter()
            .position(|request| matches!(request.content, Content::Absent { .. }))
            .expect("the harness removes something");

        // One boundary before the removal's intent: nothing names it, and the
        // file is still there.
        let early = guard.child("early");
        plant_crash_fixture(&early);
        assert!(
            !spawn_crash_child(&early, removal, "before-stage")
                .status
                .success()
        );
        let loaded = crate::journal::load(&StateDir::resolve(&early).journal()).expect("load");
        assert!(
            loaded
                .intents()
                .all(|intent| intent.after != Written::Absent),
            "no removal had been announced yet",
        );
        assert!(early.join(".vault/gone.conf").is_file());

        // One boundary after it: the intent is durable and the file is *still*
        // there. Unlinking first would leave a window in which a crash removes a
        // file no journal frame names.
        let late = guard.child("late");
        plant_crash_fixture(&late);
        assert!(
            !spawn_crash_child(&late, removal, "after-intent")
                .status
                .success()
        );
        let loaded = crate::journal::load(&StateDir::resolve(&late).journal()).expect("load");
        let intent = loaded.intents().last().expect("the removal's intent");
        assert_eq!(intent.after, Written::Absent);
        assert_eq!(intent.dest, late.join(".vault/gone.conf"));
        assert_eq!(intent.temp, None);
        assert_eq!(
            peek(&late.join(".vault/gone.conf")).expect("still there"),
            (b"bx made this\n".to_vec(), Mode::PRIVATE_FILE),
            "and the destination is still what it was",
        );
    }

    #[test]
    fn the_standing_of_a_write_reads_the_same_for_a_report_and_for_an_undo() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        // One decision site: what a read-only command says and what a writing
        // one does cannot disagree, because the same function computes both.
        let reported = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(reported.unfinished[0].standing, Standing::Written);
        assert!(reported.unfinished[0].standing.is_resolvable());
        assert!(reported.unfinished[0].note.contains("rolls it back"));
        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { .. },
        ));
    }

    #[test]
    fn a_write_whose_two_states_are_identical_rolls_back_to_a_no_op() {
        // `standing` tests the prior state first, so a write that changed
        // nothing is a no-op rather than an ambiguity.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "same\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "same\n", Mode::DEFAULT_FILE)],
        );

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished[0].standing, Standing::Prior);
        recover(&state).expect("recover");
        assert_eq!(peek(&dest).expect("unchanged").0, b"same\n");
    }

    #[test]
    fn a_restore_snapshot_reference_names_its_blob() {
        // The journal stores A4's `RestoreRef` verbatim, so the blob a rollback
        // reads is the same file `bx rm` reads.
        let reference = RestoreRef {
            digest: ContentHash::of(b"old\n"),
            mode: Mode::DEFAULT_FILE,
            len: 4,
        };
        assert_eq!(reference.blob_name(), ContentHash::of(b"old\n").to_hex());
        assert_eq!(
            expected(&Prior::Existed(reference.clone())),
            Some((reference.digest, reference.mode)),
        );
        assert_eq!(expected(&Prior::Absent), None);
    }

    #[test]
    fn every_standing_renders_a_sentence() {
        // r3 coverage COV7. Non-empty was all this asserted, so any of the six
        // could have been swapped for another and the suite stayed green.
        // Each reads as the predicate of a sentence whose subject is the path,
        // which is how `note` and `unreachable` both use it.
        for (standing, sentence) in [
            (Standing::Prior, "holds the bytes that were there before"),
            (
                Standing::Written,
                "holds the bytes the interrupted session wrote",
            ),
            (Standing::Vanished, "is gone"),
            (Standing::Diverged, "was edited after the interruption"),
            (Standing::Foreign, "is not a regular file"),
            (Standing::Unreachable, "cannot be reached"),
        ] {
            assert_eq!(standing.to_string(), sentence);
        }
        assert_eq!(SessionKind::Apply.to_string(), "apply");
        assert_eq!(SessionKind::Restore.to_string(), "restore");
    }

    /// An intent to create `rel` under `home`, as a session would journal it.
    fn intent_for(home: &Path, rel: &str) -> Intent {
        let (target, dest) = target(home, rel);
        Intent {
            target,
            dest,
            temp: None,
            before: Prior::Absent,
            after: Written::Present {
                digest: ContentHash::of(b"bx\n"),
                mode: Mode::DEFAULT_FILE,
            },
            created_dirs: Vec::new(),
            mechanism: Some(Mechanism::Own),
            ledger_written: None,
        }
    }

    #[test]
    fn a_journal_whose_paths_are_not_its_targets_is_set_aside_and_touches_nothing() {
        // Review round 3, item 2. Each of these was believed: rollback acted on
        // the stored destination, temporary file and created directories with
        // nothing tying them to the intent's target, and a journal with no
        // header was checked against nothing at all.
        let guard = guarded_home();
        let evil = b"EVIL\n";
        let reference = RestoreRef {
            digest: ContentHash::of(evil),
            mode: Mode::DEFAULT_FILE,
            len: 5,
        };
        let theirs = Written::Present {
            digest: ContentHash::of(b"theirs\n"),
            mode: Mode::DEFAULT_FILE,
        };
        for case in [
            "a destination outside the home",
            "a destination that is another file",
            "a temporary file that is the user's",
            "a bx temporary file in another directory",
            "a created directory that is not a parent",
            "a created directory that is the home",
            "no header",
        ] {
            let root = guard.child(case.replace(' ', "-"));
            let home = root.join("home");
            let state = StateDir::resolve(&home);
            state.ensure().expect("ensure");
            std::fs::write(state.restore().join(reference.blob_name()), evil).expect("a blob");
            let outside = root.join("outside/victim.conf");
            let victim = home.join(".victim.conf");
            let stray = home.join("sub/.bx-theirs");
            let empty = home.join("empty");
            for file in [&outside, &victim, &stray] {
                plant_file(file, "theirs\n", Mode::DEFAULT_FILE);
            }
            std::fs::create_dir_all(&empty).expect("the user's empty directory");

            let mut intent = intent_for(&home, ".conf");
            match case {
                "a destination outside the home" => {
                    intent.dest.clone_from(&outside);
                    intent.before = Prior::Existed(reference.clone());
                    intent.after = theirs;
                }
                "a destination that is another file" => {
                    intent.dest.clone_from(&victim);
                    intent.after = theirs;
                }
                "a temporary file that is the user's" => intent.temp = Some(victim.clone()),
                "a bx temporary file in another directory" => intent.temp = Some(stray.clone()),
                "a created directory that is not a parent" => {
                    intent.created_dirs = vec![empty.clone()];
                }
                "a created directory that is the home" => intent.created_dirs = vec![home.clone()],
                _ => {
                    intent = intent_for(&home, ".victim.conf");
                    intent.after = theirs;
                }
            }
            let records = if case == "no header" {
                vec![Record::Intent(intent)]
            } else {
                vec![
                    Record::Begin(Begin {
                        kind: SessionKind::Apply,
                        home: home.clone(),
                        scope: Vec::new(),
                    }),
                    Record::Intent(intent),
                ]
            };
            raw_journal(&state.journal(), &records);
            let bytes = std::fs::read(state.journal()).expect("the journal");

            assert_eq!(
                crate::journal::load(&state.journal()).expect("load"),
                Loaded::Unreadable { moved_to: None },
                "{case}",
            );
            assert!(
                pending(&state)
                    .expect("pending")
                    .expect("reported")
                    .unreadable,
                "{case}"
            );
            assert_eq!(
                recover(&state).expect("recover"),
                Outcome::Nothing,
                "{case}"
            );
            assert_eq!(
                std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
                bytes,
                "{case}",
            );
            for file in [&outside, &victim, &stray] {
                assert_eq!(
                    peek(file).map(|(bytes, _)| bytes),
                    Some(b"theirs\n".to_vec()),
                    "{case}: {} was touched",
                    file.display(),
                );
            }
            assert!(
                empty.is_dir(),
                "{case}: the user's empty directory was removed"
            );
        }
    }

    #[test]
    fn a_target_written_twice_in_one_session_is_refused_so_report_and_recovery_agree() {
        // Review round 3, item 4. The second write used to land: the report then
        // judged the first intent against the second write's bytes and said
        // blocked, while the reverse-order rollback undid both and succeeded.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "B0\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(home.path(), ".conf", "B1\n", Mode::DEFAULT_FILE))
            .expect("the first write");
        let refused = session
            .apply(write_to(home.path(), ".conf", "B2\n", Mode::DEFAULT_FILE))
            .expect_err("the second write to the same target");
        assert!(
            matches!(refused, journal::Error::Repeated { .. }),
            "got {refused}"
        );
        assert_eq!(peek(&dest).expect("the first write").0, b"B1\n");
        assert!(matches!(
            session.finish(),
            Err(journal::Error::Poisoned { .. })
        ));

        let report = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(report.unfinished.len(), 1);
        assert!(report.blocked().next().is_none());
        let outcome = recover(&state).expect("recover");
        assert_eq!(outcome, Outcome::RolledBack { undone: 1 });
        assert_eq!(peek(&dest).expect("rolled back").0, b"B0\n");
    }

    #[test]
    fn recovery_under_another_spelling_of_the_home_refuses_and_moves_nothing() {
        // Stack integration of #7's round 3: a ledger storing a path the home
        // cannot use is `Error::ForeignPath`, never a reset. A terminated
        // journal's rebuild opens the ledger under the lock with the journal's
        // home, so it must stop there with the ledger and the journal in place.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let alias = home.child("alias");
        std::os::unix::fs::symlink(home.path(), &alias).expect("alias");
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        {
            // The ledger as a run under the other spelling left it: a target it
            // named absolutely, which this spelling folds into its home.
            let lock = ExclusiveLock::acquire(&state).expect("lock");
            let mut ledger = Ledger::open(&state, &lock, &alias).expect("open").value;
            let key = Portable::from_path(&home.child(".foo"), &alias).expect("portable");
            assert!(key.as_str().starts_with('/'), "{key}");
            ledger
                .record(NewEntry::new(
                    key,
                    ContentHash::of(b"bx"),
                    Mode::DEFAULT_FILE,
                    Mechanism::Own,
                ))
                .expect("record");
            ledger.save().expect("save");
        }
        let ledger = std::fs::read(state.ledger()).expect("the ledger");
        let journal = std::fs::read(state.journal()).expect("the journal");
        let dest = peek(&home.child(".conf"));

        let foreign =
            |err: &Error| matches!(err, Error::State(crate::state::Error::ForeignPath { .. }));
        let err = pending(&state).expect_err("the report stops too");
        assert!(foreign(&err), "got {err}");
        let err = recover(&state).expect_err("a mis-spelled home stops the run");
        assert!(foreign(&err), "got {err}");
        let err = lock_for_writing(&state).expect_err("and every writing command");
        assert!(foreign(&err), "got {err}");

        assert_eq!(std::fs::read(state.ledger()).expect("in place"), ledger);
        assert_eq!(std::fs::read(state.journal()).expect("in place"), journal);
        assert!(!StateDir::quarantine(&state.ledger()).exists());
        assert!(!StateDir::quarantine(&state.journal()).exists());
        assert_eq!(peek(&home.child(".conf")), dest);
    }

    /// `ledger.mpk` as a bx with a newer ledger format leaves it.
    fn ledger_from_a_newer_bx() -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Envelope {
            kind: &'static str,
            version: u16,
            payload: LedgerView,
        }
        rmp_serde::to_vec_named(&Envelope {
            kind: "bx.ledger",
            version: u16::MAX,
            payload: LedgerView::default(),
        })
        .expect("encode")
    }

    /// Whether `err` is the ledger's refusal of a newer format.
    fn is_future_version(err: &crate::state::Error) -> bool {
        matches!(
            err,
            crate::state::Error::FutureVersion { found, .. } if *found == u16::MAX
        )
    }

    #[test]
    fn a_rollback_over_a_ledger_from_a_newer_bx_reads_only_the_journal_and_renames_nothing() {
        // Stack integration of #7's round 4: a ledger a newer bx wrote is
        // `Error::FutureVersion` and is never quarantined. An unterminated
        // journal is rolled back from the journal and the restore blobs alone,
        // so the rollback still completes; the next command that opens the
        // ledger is what stops.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(home.path(), ".conf", "one\n", Mode::DEFAULT_FILE))
            .expect("apply");
        first.finish().expect("finish");
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "two\n", Mode::DEFAULT_FILE)],
        );
        let newer = ledger_from_a_newer_bx();
        std::fs::write(state.ledger(), &newer).expect("a newer bx's ledger");

        let interruption = pending(&state).expect("a rollback's report reads no ledger");
        let interruption = interruption.expect("interrupted");
        assert!(!interruption.complete && !interruption.unreadable);
        assert_eq!(interruption.unfinished.len(), 1);
        assert!(interruption.unfinished[0].resolvable);

        assert_eq!(
            recover(&state).expect("the rollback needs no ledger"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(peek(&dest).expect("rolled back").0, b"one\n");
        assert!(!state.journal().exists());
        assert_eq!(std::fs::read(state.ledger()).expect("in place"), newer);
        assert!(!StateDir::quarantine(&state.ledger()).exists());

        // The next writing command opens the ledger and stops there.
        let err = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect_err("a session needs the ledger");
        assert!(
            matches!(&err, crate::journal::Error::State(inner) if is_future_version(inner)),
            "got {err}"
        );
        let err = crate::restore::restore(&state, home.path(), &[portable])
            .expect_err("rm needs the ledger");
        assert!(
            matches!(
                &err,
                crate::restore::Error::Journal(crate::journal::Error::State(inner))
                    if is_future_version(inner)
            ),
            "got {err}"
        );
        assert!(!state.journal().exists(), "no session was opened");
        assert_eq!(std::fs::read(state.ledger()).expect("in place"), newer);
        assert!(!StateDir::quarantine(&state.ledger()).exists());
        assert_eq!(peek(&dest).expect("untouched").0, b"one\n");
    }

    #[test]
    fn a_terminated_journal_over_a_ledger_from_a_newer_bx_stops_and_quarantines_nothing() {
        // Stack integration of #7's round 4: a terminated journal's bookkeeping
        // writes the ledger, so it opens it, and a newer format stops the report,
        // the recovery and every writing command, with nothing moved.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        let newer = ledger_from_a_newer_bx();
        std::fs::write(state.ledger(), &newer).expect("a newer bx's ledger");
        let journal = std::fs::read(state.journal()).expect("the journal");
        let dest = peek(&home.child(".conf"));

        let future = |err: &Error| matches!(err, Error::State(inner) if is_future_version(inner));
        let err = pending(&state).expect_err("the report stops");
        assert!(future(&err), "got {err}");
        let err = recover(&state).expect_err("the recovery stops");
        assert!(future(&err), "got {err}");
        let err = lock_for_writing(&state).expect_err("and every writing command");
        assert!(future(&err), "got {err}");

        assert_eq!(std::fs::read(state.ledger()).expect("in place"), newer);
        assert_eq!(std::fs::read(state.journal()).expect("in place"), journal);
        assert!(!StateDir::quarantine(&state.ledger()).exists());
        assert!(!StateDir::quarantine(&state.journal()).exists());
        assert_eq!(peek(&home.child(".conf")), dest);
    }

    #[test]
    fn a_damaged_ledger_is_only_reported_without_the_lock_and_quarantined_under_it() {
        // Stack integration of #7's round 3: a lockless read returns
        // `Health::Damaged` and moves nothing; only the lock holder quarantines.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        std::fs::write(state.ledger(), b"not a ledger").expect("damage the ledger");

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.complete);
        assert!(interruption.unfinished.iter().all(|write| write.resolvable));
        assert_eq!(
            std::fs::read(state.ledger()).expect("left in place"),
            b"not a ledger"
        );
        assert!(!StateDir::quarantine(&state.ledger()).exists());

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 }
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.ledger())).expect("quarantined"),
            b"not a ledger",
        );
        let rebuilt = LedgerView::read(&state, home.path()).expect("read");
        assert_eq!(rebuilt.health, crate::state::Health::Loaded);
        assert_eq!(
            rebuilt
                .value
                .get(&target(home.path(), ".conf").0)
                .expect("the entry")
                .written,
            ContentHash::of(b"new\n"),
        );
    }

    #[test]
    fn a_damaged_ledger_that_cannot_be_moved_aside_stops_recovery_and_keeps_the_journal() {
        // Stack integration of #8 @62de0aa, which carries #7's r3 round 1:
        // `Ledger::open` refuses a damaged ledger it cannot move aside with
        // `state::Error::CannotQuarantine`. A terminated journal's bookkeeping
        // opens the ledger, so recovery must stop there: the ledger keeps its
        // bytes, and the journal stays for the run after the ledger is moved.
        let home = guarded_home();
        let made = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &made,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&made.journal(), 1);
        std::fs::write(made.ledger(), b"not a ledger").expect("damage the ledger");
        let journal = std::fs::read(made.journal()).expect("the journal");
        // Written where a session's names fit, then moved to where no
        // set-aside name does.
        let state = state_beyond_set_aside_names(&home);
        std::fs::create_dir_all(state.root().parent().expect("a parent")).expect("its parents");
        std::fs::rename(made.root(), state.root()).expect("move the state directory");

        let recovered = recover(&state);
        assert!(
            matches!(
                &recovered,
                Err(Error::State(crate::state::Error::CannotQuarantine {
                    path,
                    damage: crate::state::Damage::Malformed,
                    ..
                })) if *path == state.ledger()
            ),
            "got {recovered:?}"
        );
        assert_eq!(
            std::fs::read(state.ledger()).expect("kept"),
            b"not a ledger",
            "the damaged ledger's bytes are unchanged"
        );
        assert_eq!(
            std::fs::read(state.journal()).expect("kept"),
            journal,
            "the journal stays for the next run"
        );
        assert_eq!(
            names_in(state.root()),
            ["journal.mpk", "ledger.mpk", "lock", "restore", "shell"],
            "nothing was set aside or saved"
        );
        assert_eq!(
            peek(&home.child(".conf")).map(|(bytes, _)| bytes),
            Some(b"new\n".to_vec()),
            "a terminated session's write is not rolled back"
        );
    }

    #[test]
    fn a_rebuild_that_would_adopt_a_changed_shared_file_is_blocked_and_keeps_the_prior() {
        // Stack integration of #7's round 3: `record` refuses a changed Region
        // or Include file with `PriorConflict`. A rebuild must give that one
        // verdict from `pending` and `recover` — a blocked write — and never
        // lose or replace the stored prior.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".zshrc");
        let region = Mechanism::Region { comment: '#' };
        let bx1 = "user line\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
        let bx2 = "user line\n# >>> bx >>>\nBX2\n# <<< bx <<<\n";
        plant_file(&dest, "user line\n", Mode::DEFAULT_FILE);
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: bx1.as_bytes().to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Owned(region.clone()),
            })
            .expect("apply");
        first.finish().expect("finish");
        let saved = std::fs::read(state.ledger()).expect("the ledger");

        // A journal whose one write displaced a changed copy of the shared file,
        // and landed, and whose session died before its save.
        let edited = format!("{bx1}more\n");
        let displaced = ContentHash::of(edited.as_bytes());
        fs::write_atomically(
            &state.restore().join(displaced.to_hex()),
            edited.as_bytes(),
            Mode::PRIVATE_FILE,
        )
        .expect("the snapshot");
        plant_file(&dest, bx2, Mode::DEFAULT_FILE);
        raw_journal(
            &state.journal(),
            &[
                Record::Begin(Begin {
                    kind: SessionKind::Apply,
                    home: home.path().to_path_buf(),
                    scope: Vec::new(),
                }),
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest: dest.clone(),
                    temp: None,
                    before: Prior::Existed(RestoreRef {
                        digest: displaced,
                        mode: Mode::DEFAULT_FILE,
                        len: u64::try_from(edited.len()).expect("a length"),
                    }),
                    after: Written::Present {
                        digest: ContentHash::of(bx2.as_bytes()),
                        mode: Mode::DEFAULT_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(region),
                    ledger_written: Some(ContentHash::of(bx1.as_bytes())),
                }),
                Record::Done(Done {
                    target: portable.clone(),
                }),
                Record::End(End { written: 1 }),
            ],
        );
        let journal = std::fs::read(state.journal()).expect("the journal");

        let report = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(report.unfinished.len(), 1);
        assert!(
            !report.unfinished[0].resolvable,
            "{:?}",
            report.unfinished[0]
        );
        let outcome = recover(&state).expect("a conflict is a verdict, not an error");
        assert!(
            matches!(&outcome, Outcome::Blocked { conflicts } if conflicts.len() == 1),
            "{outcome:?}"
        );
        assert_eq!(std::fs::read(state.journal()).expect("kept"), journal);
        assert_eq!(std::fs::read(state.ledger()).expect("unchanged"), saved);
        let entry = LedgerView::read(&state, home.path())
            .expect("read")
            .value
            .get(&portable)
            .cloned()
            .expect("the entry");
        let Prior::Existed(original) = &entry.prior else {
            panic!("the user's original is still the prior");
        };
        assert_eq!(original.digest, ContentHash::of(b"user line\n"));
        assert_eq!(peek(&dest).expect("untouched").0, bx2.as_bytes());
    }

    #[test]
    fn two_successive_torn_journals_are_both_rolled_back_and_kept_and_bx_writes_afterwards() {
        // #9's round-3 review: the set-aside name was checked before the
        // rollback, so a second torn journal blocked recover, rm, abandon and
        // every session while the machine stayed half-applied. Recovery rolls
        // back first and sets the journal aside last, under the next free name.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut kept = Vec::new();
        for round in 0..2 {
            let (dest, mut bytes) = interrupted_modify(&state, home.path());
            // A different cut each round, so the two kept files differ.
            bytes.truncate(bytes.len() - 1 - round);
            std::fs::write(state.journal(), &bytes).expect("tear the last frame");
            assert_eq!(
                recover(&state).expect("recover"),
                Outcome::RolledBack { undone: 1 },
                "round {round}",
            );
            assert_eq!(
                peek(&dest).expect("rolled back").0,
                b"the user's original\n",
                "round {round}",
            );
            assert!(!state.journal().exists(), "round {round}");
            kept.push(bytes);
        }
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("the first"),
            kept[0],
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&state.journal(), 1)).expect("the second"),
            kept[1],
        );

        let mut session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect("bx writes again");
        session
            .apply(write_to(
                home.path(),
                ".conf",
                "bx new\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("apply");
        assert_eq!(session.finish().expect("finish"), 1);
        assert_eq!(peek(&home.child(".conf")).expect("written").0, b"bx new\n");
    }

    #[test]
    fn a_set_aside_that_fails_after_the_rollback_leaves_the_journal_in_place() {
        // The rollback comes first. If the torn journal then cannot be moved
        // aside, it stays where it is, and the next run repeats a rollback that
        // has nothing left to do before trying again.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (dest, mut bytes) = interrupted_modify(&state, home.path());
        bytes.truncate(bytes.len() - 1);
        std::fs::write(state.journal(), &bytes).expect("tear the last frame");

        // The rollback writes in the home; only the set-aside renames in the
        // state directory. Narrower than 0700, so nothing tightens it back.
        fs::set_mode(state.root(), Mode::from_bits(0o500)).expect("make it read-only");
        if !permissions_refuse(state.root()) {
            fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");
            return cannot_build(
                "a_set_aside_that_fails_after_the_rollback_leaves_the_journal_in_place",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let first = recover(&state);
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");

        let err = first.expect_err("the journal cannot be moved aside");
        assert!(
            matches!(err, Error::Journal(journal::Error::Io { .. })),
            "got {err}"
        );
        assert_eq!(
            peek(&dest).expect("rolled back").0,
            b"the user's original\n",
            "the rollback ran before the set-aside was tried",
        );
        assert_eq!(
            std::fs::read(state.journal()).expect("left in place"),
            bytes
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 }
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("set aside"),
            bytes,
        );
        assert_eq!(
            peek(&dest).expect("still rolled back").0,
            b"the user's original\n"
        );
    }

    #[test]
    fn abandoning_twice_keeps_both_set_aside_journals() {
        // Review round 3, item 5. The set-aside name was fixed, and the second
        // abandon renamed its journal over the first. Round 3 refused the
        // second abandon instead; since #7's numbered names integrated, it
        // succeeds and takes the next free name, and both journals survive.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut kept = Vec::new();
        for rel in [".one", ".two"] {
            let dest = home.child(rel);
            plant_file(&dest, "orig\n", Mode::DEFAULT_FILE);
            interrupted(
                &state,
                home.path(),
                vec![write_to(home.path(), rel, "bx\n", Mode::DEFAULT_FILE)],
            );
            plant_file(&dest, "user edit\n", Mode::DEFAULT_FILE);
            assert!(matches!(
                recover(&state).expect("recover"),
                Outcome::Blocked { .. }
            ));
            kept.push(std::fs::read(state.journal()).expect("the journal"));
            if kept.len() == 1 {
                abandon(&state).expect("abandon").expect("set aside");
            }
        }

        let second = abandon(&state)
            .expect("the second abandon succeeds")
            .expect("set aside");
        assert_eq!(second, StateDir::quarantine_nth(&state.journal(), 1));
        assert!(!state.journal().exists(), "the interruption is cleared");
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("the first"),
            kept[0],
        );
        assert_eq!(std::fs::read(&second).expect("the second"), kept[1]);
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
    }

    /// A session that modified `~/.conf` and died, and its journal's bytes.
    fn interrupted_modify(state: &StateDir, home: &Path) -> (PathBuf, Vec<u8>) {
        let dest = home.join(".conf");
        plant_file(&dest, "the user's original\n", Mode::DEFAULT_FILE);
        interrupted(
            state,
            home,
            vec![write_to(home, ".conf", "bx new\n", Mode::DEFAULT_FILE)],
        );
        (dest, std::fs::read(state.journal()).expect("the journal"))
    }

    #[test]
    fn a_damaged_frame_length_never_loses_the_journal() {
        // Review round 3, item 3. A length byte flipped in either frame read as
        // a torn tail: recovery rolled back nothing and unlinked the journal,
        // leaving the user's original only as a blob nothing named.
        let guard = guarded_home();
        for (case, frame) in [("the first frame", 0), ("a later frame", 1)] {
            let home = guard.child(case.replace(' ', "-"));
            let state = StateDir::resolve(&home);
            let (dest, mut bytes) = interrupted_modify(&state, &home);
            let start = frame_starts(&bytes)[frame];
            // About 8 MiB: under the frame bound, and past the end of the file.
            bytes[start + 2] = 0x80;
            std::fs::write(state.journal(), &bytes).expect("damage the journal");

            let report = pending(&state).expect("pending");
            let outcome = recover(&state).expect("recover");
            let report = report.expect("reported");
            assert!(report.unfinished.is_empty(), "{case}");
            if frame == 0 {
                assert!(report.unreadable, "{case}");
                assert_eq!(outcome, Outcome::Nothing, "{case}: not believed");
            } else {
                assert!(!report.unreadable, "{case}: a torn tail");
                assert_eq!(outcome, Outcome::RolledBack { undone: 0 }, "{case}");
            }
            assert!(!state.journal().exists(), "{case}");
            assert_eq!(
                std::fs::read(StateDir::quarantine(&state.journal()))
                    .expect("set aside, never unlinked"),
                bytes,
                "{case}",
            );
            assert_eq!(peek(&dest).expect("left as it is").0, b"bx new\n", "{case}");
        }
    }

    #[test]
    fn a_byte_flipped_inside_a_frame_is_not_believed() {
        // Review round 3, item 3. Without a checksum this still decoded, as the
        // mode the rollback then put the user's original back at.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (dest, mut bytes) = interrupted_modify(&state, home.path());
        let mode = bytes
            .windows(8)
            .position(|window| window == [0xa4, b'm', b'o', b'd', b'e', 0xcd, 0x01, 0xa4])
            .expect("the prior's mode, 0o644, as MessagePack");
        bytes[mode + 7] = 0xa5;
        std::fs::write(state.journal(), &bytes).expect("damage the journal");

        assert_eq!(
            crate::journal::load(&state.journal()).expect("load"),
            Loaded::Unreadable { moved_to: None },
        );
        assert!(
            pending(&state)
                .expect("pending")
                .expect("reported")
                .unreadable
        );
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            bytes,
        );
        assert_eq!(
            peek(&dest),
            Some((b"bx new\n".to_vec(), Mode::DEFAULT_FILE)),
        );
    }

    #[test]
    fn an_unreadable_journal_is_reported_by_plan_and_set_aside_by_the_next_session() {
        // Review round 4, item 2. `pending` said there was no session, and the
        // only word of the journal was a warning below the default log level,
        // so `plan` exited clean over a journal the next `apply` then set aside.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"GARBAGE!").expect("an unreadable journal");

        let report = pending(&state)
            .expect("pending")
            .expect("an unreadable journal is reported");
        assert_eq!(
            report,
            Interrupted {
                kind: SessionKind::Apply,
                journal: state.journal(),
                complete: false,
                unreadable: true,
                unfinished: Vec::new(),
            },
        );
        assert_eq!(report.exit(), Exit::Pending);
        assert_eq!(
            std::fs::read(state.journal()).expect("left in place"),
            b"GARBAGE!"
        );

        let session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect("a session opens over it");
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("set aside"),
            b"GARBAGE!",
        );
        assert_eq!(session.finish().expect("finish"), 0);
        assert_eq!(pending(&state).expect("pending"), None, "and it is gone");
    }

    #[test]
    fn a_zero_filled_tail_after_whole_frames_is_rolled_back_then_kept() {
        // Review round 4, item 1. A power loss that zero-fills the unsynced last
        // frame left bytes that fail its checksum. Round 3 read that as damage:
        // the journal was set aside with nothing rolled back, so `.a` kept bx's
        // bytes, the ledger had no entry for it, and `rm` called it unmanaged.
        let guard = guarded_home();
        for (case, zeroed_done_of_a) in [("the Intent of .b", false), ("the Done of .a", true)] {
            let home = guard.child(case.replace(' ', "-"));
            let state = StateDir::resolve(&home);
            let a = home.join(".a");
            let b = home.join(".b");
            plant_file(&a, "A0\n", Mode::DEFAULT_FILE);
            plant_file(&b, "B0\n", Mode::DEFAULT_FILE);
            let mut session =
                Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
            session
                .apply(write_to(&home, ".a", "A1\n", Mode::DEFAULT_FILE))
                .expect("apply .a");
            let after_a = std::fs::read(state.journal()).expect("the journal");
            session
                .apply(write_to(&home, ".b", "B1\n", Mode::DEFAULT_FILE))
                .expect("apply .b");
            let after_b = std::fs::read(state.journal()).expect("the journal");
            drop(session);
            // The frame that zero-filled was never synced, so the write it
            // announced, or the one after it, had not begun: `.b` is as it was.
            plant_file(&b, "B0\n", Mode::DEFAULT_FILE);
            let (bytes, kept) = if zeroed_done_of_a {
                let mut bytes = after_a;
                let done = frame_starts(&bytes)[2];
                bytes[done..].fill(0);
                (bytes, 2)
            } else {
                let starts = frame_starts(&after_b);
                let mut bytes = after_b[..starts[4]].to_vec();
                bytes[starts[3]..].fill(0);
                (bytes, 3)
            };
            std::fs::write(state.journal(), &bytes).expect("zero-fill the tail");

            let loaded = crate::journal::load(&state.journal()).expect("load");
            assert!(
                matches!(&loaded, Loaded::Torn { records, .. } if records.len() == kept),
                "{case}: {loaded:?}",
            );
            let report = pending(&state)
                .expect("pending")
                .expect("an interrupted session");
            assert_eq!(report.unfinished.len(), 1, "{case}");
            assert_eq!(
                recover(&state).expect("recover"),
                Outcome::RolledBack { undone: 1 },
                "{case}",
            );
            assert_eq!(peek(&a).expect("rolled back").0, b"A0\n", "{case}");
            assert_eq!(peek(&b).expect("untouched").0, b"B0\n", "{case}");
            assert!(!state.journal().exists(), "{case}");
            assert_eq!(
                std::fs::read(StateDir::quarantine(&state.journal())).expect("kept aside"),
                bytes,
                "{case}",
            );

            let (portable, _) = target(&home, ".a");
            crate::restore::restore(&state, &home, &[portable]).expect("rm");
            assert_eq!(peek(&a).expect("still the original").0, b"A0\n", "{case}");
        }
    }

    #[test]
    fn a_torn_journal_whose_first_set_aside_name_is_taken_is_recovered_and_kept_beside_it() {
        // Round 3 refused this recovery until the user moved the earlier file.
        // With #7's numbered names nothing is in the way: the rollback runs and
        // the torn journal takes the next free name, the earlier file intact.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (dest, mut bytes) = interrupted_modify(&state, home.path());
        bytes.truncate(bytes.len() - 1);
        std::fs::write(state.journal(), &bytes).expect("tear the last frame");
        let aside = StateDir::quarantine(&state.journal());
        std::fs::write(&aside, b"the first").expect("a journal set aside earlier");

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 }
        );
        assert_eq!(
            peek(&dest).expect("rolled back").0,
            b"the user's original\n"
        );
        assert!(!state.journal().exists());
        assert_eq!(std::fs::read(&aside).expect("kept"), b"the first");
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&state.journal(), 1)).expect("set aside"),
            bytes,
        );
    }

    #[test]
    fn a_blocked_write_keeps_its_temporary_file() {
        // Review round 3, item 2: the temporary file was unlinked before the
        // decision, so a blocked write lost it on every re-run.
        let guard = guarded_home();
        let home = guard.child("crashed");
        plant_crash_fixture(&home);
        assert!(!spawn_crash_child(&home, 0, "after-intent").status.success());
        let state = StateDir::resolve(&home);
        let temp = crate::journal::load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .expect("one intent")
            .temp
            .clone()
            .expect("a staged temp file");
        plant_file(
            &home.join(".bxrc"),
            "edited after the crash\n",
            Mode::PRIVATE_FILE,
        );

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. }
        ));
        assert!(temp.is_file(), "a blocked write is not recovery's to touch");
    }

    #[test]
    fn a_crash_inside_finish_is_recorded_and_rm_still_restores_the_originals() {
        // Review round 3, item 1. Every write has landed when `finish` runs, so
        // a crash there is bookkeeping, never a rollback. With an earlier apply
        // behind it, a crash after the ledger save and before the unlink is the
        // one that used to hand `rm` bx's first output instead of the user's
        // file.
        let guard = guarded_home();
        for phase in finish_crash_phases() {
            for earlier_apply in [false, true] {
                let case = format!("{phase}, earlier apply: {earlier_apply}");
                let home = guard.child(format!("finish-{phase}-{earlier_apply}"));
                plant_crash_fixture(&home);
                let before = crash_snapshot(&home);
                let state = StateDir::resolve(&home);
                let owned: Vec<Portable> = crash_requests(&home)
                    .into_iter()
                    .filter(|request| matches!(request.ownership, Ownership::Owned(_)))
                    .map(|request| request.target)
                    .collect();

                if earlier_apply {
                    let mut session =
                        Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
                    for request in crash_requests(&home) {
                        if matches!(request.ownership, Ownership::Owned(_)) {
                            let Content::Bytes { planned, .. } = request.content else {
                                unreachable!("an owned crash request writes bytes");
                            };
                            session
                                .apply(Request {
                                    content: Content::Bytes {
                                        bytes: b"bx one\n".to_vec(),
                                        planned,
                                    },
                                    ..request
                                })
                                .expect("the earlier apply");
                        }
                    }
                    session.finish().expect("finish the earlier apply");
                }

                let out = spawn_crash_child(&home, crash_requests(&home).len(), phase);
                assert!(
                    !out.status.success(),
                    "{case}: the child was supposed to die; it said {}",
                    String::from_utf8_lossy(&out.stdout),
                );

                // Every write landed.
                for request in crash_requests(&home) {
                    let found = peek(&request.dest);
                    match &request.content {
                        Content::Bytes { bytes: wanted, .. } => {
                            assert_eq!(found, Some((wanted.clone(), request.mode)), "{case}");
                        }
                        Content::Absent { .. } => assert_eq!(found, None, "{case}"),
                    }
                }

                let interrupted = pending(&state).expect("pending").expect("a journal stands");
                assert!(interrupted.complete, "{case}");
                assert!(interrupted.blocked().next().is_none(), "{case}");
                let removal_note = interrupted
                    .unfinished
                    .iter()
                    .find(|write| write.dest.ends_with(".vault/gone.conf"))
                    .expect("the removal is reported")
                    .note
                    .clone();
                // The claimed directory is pruned after `End`: a crash between
                // the two leaves it, empty and at its mode, as decision 11's
                // kind of orphan, and recovery removes it no more than it
                // removes an orphaned temporary file.
                let vault = home.join(".vault");
                let orphaned = phase == "after-end";
                assert_eq!(
                    dir_mode(&vault),
                    orphaned.then_some(Mode::PRIVATE_DIR),
                    "{case}"
                );
                assert_eq!(
                    removal_note.contains("~/.vault, which stand empty and are left for bx doctor"),
                    orphaned,
                    "{case}: {removal_note}"
                );
                let outcome = recover(&state).expect("recover");
                assert!(
                    matches!(outcome, Outcome::Recorded { .. }),
                    "{case}: {outcome:?}"
                );
                assert!(!state.journal().exists(), "{case}");
                assert_eq!(recover(&state).expect("again"), Outcome::Nothing, "{case}");
                assert_eq!(
                    dir_mode(&vault),
                    orphaned.then_some(Mode::PRIVATE_DIR),
                    "{case}: recovery leaves the orphan"
                );
                assert!(
                    LedgerView::read(&state, &home)
                        .expect("read the ledger")
                        .value
                        .iter()
                        .all(|(_, entry)| !entry
                            .created_dirs
                            .iter()
                            .any(|dir| dir.as_str() == "~/.vault")),
                    "{case}: no entry claims ~/.vault"
                );

                let restored = crate::restore::restore(&state, &home, &owned).expect("rm");
                assert!(
                    restored.iter().all(|done| !done.is_conflict()),
                    "{case}: {restored:?}"
                );
                for ((dest, was), (_, is)) in before.files.iter().zip(crash_snapshot(&home).files) {
                    if dest.ends_with(".vault/gone.conf") {
                        assert_eq!(is, None, "{case}: the session released and removed it");
                    } else {
                        assert_eq!(&is, was, "{case}: rm did not restore {}", dest.display());
                    }
                }
                assert!(!home.join(".config").exists(), "{case}");
            }
        }
    }

    #[test]
    fn a_crash_at_every_write_boundary_is_recoverable() {
        let guard = guarded_home();
        for index in 0..crash_requests(guard.path()).len() {
            for phase in crash_phases() {
                // A removal stages nothing, so it never reaches the two staging
                // boundaries and a child asked to die there would not.
                if matches!(
                    crash_requests(guard.path())[index].content,
                    Content::Absent { .. }
                ) && matches!(phase, "after-stage" | "after-fill")
                {
                    continue;
                }
                let home = guard.child(format!("crash-{index}-{phase}"));
                plant_crash_fixture(&home);
                let before = crash_snapshot(&home);

                let out = spawn_crash_child(&home, index, phase);
                assert!(
                    !out.status.success(),
                    "the child was supposed to die at {index}:{phase}; it said {}",
                    String::from_utf8_lossy(&out.stdout),
                );

                // 1. Old or new, never torn. This is what A5's atomic write
                //    buys, and this assertion is what proves it.
                for (dest, found) in crash_snapshot(&home).files {
                    let request = crash_requests(&home)
                        .into_iter()
                        .find(|candidate| candidate.dest == dest)
                        .expect("a fixture destination");
                    let was = before
                        .files
                        .iter()
                        .find(|(path, _)| *path == dest)
                        .and_then(|(_, state)| state.clone());
                    let is_new = match &request.content {
                        Content::Bytes { bytes: wanted, .. } => found
                            .as_ref()
                            .is_some_and(|(bytes, mode)| bytes == wanted && *mode == request.mode),
                        Content::Absent { .. } => found.is_none(),
                    };
                    assert!(
                        found == was || is_new,
                        "{} was torn by a crash at {index}:{phase}: {found:?}",
                        dest.display(),
                    );
                }

                // 2. The interruption is detected.
                let state = StateDir::resolve(&home);
                let interrupted = pending(&state)
                    .expect("pending")
                    .expect("a crash leaves an interrupted session");
                assert_eq!(interrupted.kind, SessionKind::Apply);
                assert!(!interrupted.complete);
                assert!(
                    interrupted.blocked().next().is_none(),
                    "nothing edited the destinations, so nothing is blocked",
                );

                // 3. Recovery rolls it back.
                let outcome = recover(&state).expect("recover");
                assert!(
                    matches!(outcome, Outcome::RolledBack { .. }),
                    "got {outcome:?} at {index}:{phase}",
                );

                // 4. Byte- and mode-identical to the pre-run snapshot, the
                //    directories included. At the two boundaries that can
                //    orphan a staged file (step 5), the directories stage
                //    invented for it may stand too — and only those: a
                //    directory that existed before is at its mode either way.
                let orphan_possible = matches!(phase, "after-stage" | "after-fill");
                let orphan_dest = crash_requests(&home)[index].dest.clone();
                let beside_orphans = |mut snapshot: Snapshot| {
                    if orphan_possible {
                        for (dir, mode) in &mut snapshot.dirs {
                            let invented = before
                                .dirs
                                .iter()
                                .any(|(was, prior)| was == dir && prior.is_none());
                            if invented && orphan_dest.starts_with(&*dir) {
                                *mode = None;
                            }
                        }
                    }
                    snapshot
                };
                assert_eq!(
                    beside_orphans(crash_snapshot(&home)),
                    before,
                    "rollback at {index}:{phase} did not restore the fixture",
                );

                // 5. Nothing bx staged is left — with one honest exception. A
                //    crash between `stage` and the intent that names the staged
                //    path leaves a temporary file the journal never recorded,
                //    and recovery removes only what the journal names:
                //    unlinking by pattern in a directory the user owns is a
                //    deletion bx cannot prove it is entitled to make. Such an
                //    orphan is empty or unpublished, is attributable by its
                //    `.bx-` prefix, and is `bx doctor`'s to report.
                let temps = leftover_temps(&home);
                if orphan_possible {
                    assert!(
                        temps.len() <= 1,
                        "at most the one staged file can be orphaned, got {temps:?}",
                    );
                    for temp in &temps {
                        assert_eq!(
                            temp.parent(),
                            crash_requests(&home)[index].dest.parent(),
                            "an orphan is beside its destination and nowhere else",
                        );
                    }
                } else {
                    assert!(
                        temps.is_empty(),
                        "a crash at {index}:{phase} left {temps:?}"
                    );
                    assert!(
                        !home.join(".config").exists(),
                        "the directories the session invented are gone too",
                    );
                }

                // 6. The journal is gone.
                assert!(!state.journal().exists());
                assert!(pending(&state).expect("pending").is_none());

                // 7. Recovery is idempotent.
                assert_eq!(recover(&state).expect("recover twice"), Outcome::Nothing);
                assert_eq!(beside_orphans(crash_snapshot(&home)), before);
            }
        }
    }

    #[test]
    fn a_stale_whole_frame_from_an_earlier_journal_in_the_tail_still_rolls_back_the_prefix() {
        // Review round 5, item 3. After a power loss the unsynced tail can hold
        // blocks of an earlier, deleted journal. A whole frame from it validated,
        // so the damaged last frame was read as mid-log damage: the journal was
        // set aside as unreadable and the half-applied `.a` was never rolled back.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (a, b) = (home.child(".a"), home.child(".b"));
        plant_file(&a, "A0\n", Mode::DEFAULT_FILE);
        plant_file(&b, "B0\n", Mode::DEFAULT_FILE);

        // An earlier session, finished and unlinked: its last frame is the stale block.
        let mut earlier =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        earlier
            .apply(write_to(home.path(), ".x", "X\n", Mode::DEFAULT_FILE))
            .expect("apply");
        let old = std::fs::read(state.journal()).expect("the earlier journal");
        earlier.finish().expect("finish");
        let old_done = old[*frame_starts(&old).last().expect("its Done frame")..].to_vec();

        interrupted(
            &state,
            home.path(),
            vec![
                write_to(home.path(), ".a", "A1\n", Mode::DEFAULT_FILE),
                write_to(home.path(), ".b", "B1\n", Mode::DEFAULT_FILE),
            ],
        );
        let whole = std::fs::read(state.journal()).expect("the journal");
        // `.b`'s Intent never reached the disk, so its write never began.
        plant_file(&b, "B0\n", Mode::DEFAULT_FILE);
        let starts = frame_starts(&whole);
        let (intent_b, done_b) = (starts[3], starts[4]);
        let mut bytes = whole[..done_b].to_vec();
        for (at, byte) in (0..=u8::MAX).cycle().zip(bytes[intent_b..].iter_mut()) {
            *byte = at.wrapping_mul(37).wrapping_add(11);
        }
        let place = intent_b + 16;
        assert!(
            place + old_done.len() <= bytes.len(),
            "the stale frame fits"
        );
        bytes[place..place + old_done.len()].copy_from_slice(&old_done);
        std::fs::write(state.journal(), &bytes).expect("the power-loss bytes");

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 }
        );
        assert_eq!(peek(&a).expect("rolled back").0, b"A0\n");
        assert_eq!(peek(&b).expect("untouched").0, b"B0\n");
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            bytes,
        );
    }

    #[test]
    fn a_journal_a_newer_bx_wrote_is_refused_and_nothing_is_set_aside_or_rolled_back() {
        // Review round 5, item 2. A newer format byte read as damage: the next
        // session set the journal aside with nothing rolled back, discarding a
        // newer bx's interrupted session.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let a = home.child(".a");
        plant_file(&a, "A0\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".a", "A1\n", Mode::DEFAULT_FILE)],
        );
        let mut bytes = std::fs::read(state.journal()).expect("the journal");
        bytes[7] += 1;
        std::fs::write(state.journal(), &bytes).expect("what a newer bx leaves");

        let future = |err: &journal::Error| matches!(err, journal::Error::FutureVersion { .. });
        let refused = |err: Error| matches!(&err, Error::Journal(inner) if future(inner));
        let loaded = crate::journal::load(&state.journal()).expect_err("load refuses");
        assert!(future(&loaded), "{loaded}");
        assert!(
            loaded.to_string().contains("run a bx at least as new"),
            "{loaded}"
        );
        assert!(refused(pending(&state).expect_err("pending refuses")));
        assert!(refused(recover(&state).expect_err("recover refuses")));
        assert!(refused(
            lock_for_writing(&state).expect_err("a writing command refuses")
        ));
        let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect_err("a session refuses");
        assert!(future(&opened), "{opened}");
        assert!(refused(abandon(&state).expect_err("abandon refuses")));

        assert_eq!(
            std::fs::read(state.journal()).expect("left in place"),
            bytes
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());
        assert_eq!(peek(&a).expect("not rolled back").0, b"A1\n");
    }

    #[test]
    fn a_rollback_removes_nested_created_directories_last_write_first() {
        // Coverage review round 5, item 1. Deleting the `!` before `complete`
        // survived: no rollback had two writes whose created directories nest.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        interrupted(
            &state,
            home.path(),
            vec![
                write_to(
                    home.path(),
                    ".config/deep/a.conf",
                    "a\n",
                    Mode::DEFAULT_FILE,
                ),
                write_to(
                    home.path(),
                    ".config/deep/nested/b.conf",
                    "b\n",
                    Mode::DEFAULT_FILE,
                ),
            ],
        );
        assert!(home.child(".config/deep/nested/b.conf").is_file());

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 2 }
        );
        assert!(
            !home.child(".config").exists(),
            "every directory bx created is gone"
        );
    }

    #[test]
    fn a_rollback_under_a_created_directory_replaced_with_a_symlink_completes() {
        // r3 round 1, D1. Pruning the created directory failed with ENOTDIR
        // after the unlink, so every writing run failed and the journal stood.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                "d/a.conf",
                "bx\n",
                Mode::DEFAULT_FILE,
            )],
        );
        std::fs::rename(home.child("d"), home.child("real")).expect("move the directory");
        std::os::unix::fs::symlink(home.child("real"), home.child("d")).expect("link it back");

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert!(!state.journal().exists());
        assert!(peek(&home.child("real/a.conf")).is_none());
        assert!(
            std::fs::symlink_metadata(home.child("d"))
                .expect("the link stays")
                .file_type()
                .is_symlink()
        );
        assert_eq!(recover(&state).expect("again"), Outcome::Nothing);
    }

    #[test]
    fn a_rebuild_whose_created_directory_cannot_be_made_portable_is_an_error() {
        // r3 coverage C3. The loader refuses a journal whose created directory
        // is not a parent of its destination below its UTF-8 home, so no
        // journal on disk reaches this. Pinned at `decide`, so such a directory
        // is never dropped from a rebuilt entry.
        use std::os::unix::ffi::OsStrExt as _;

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut intent = intent_for(home.path(), ".config/app/a.toml");
        intent.created_dirs = vec![home.path().join(std::ffi::OsStr::from_bytes(b"\xff"))];

        let err = match decide(&state, &intent, Some(home.path()), None, true) {
            Err(err) => err,
            Ok((_, report)) => panic!("rebuilt: {report:?}"),
        };
        assert!(
            matches!(&err, Error::Write(fs::Error::NotPortable { path, .. }) if *path == intent.created_dirs[0]),
            "got {err}"
        );
    }

    #[test]
    fn an_interrupted_removal_whose_parent_no_longer_resolves_is_blocked_not_an_error() {
        // r3 round 2, P9R4-D4. The destination under a dangling link read as
        // absent, so `pending` called the removal's rollback resolvable, and
        // every recovery then failed writing through the link with
        // UnusableParent, never naming `abandon`.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let request = write_to(home.path(), ".made/f.conf", "bx\n", Mode::DEFAULT_FILE);
        let key = request.target.clone();
        session.apply(request).expect("bx creates ~/.made/f.conf");
        session.finish().expect("finish");

        // rm's removal lands, and the process dies before its session ends.
        let entry = LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value
            .get(&key)
            .cloned()
            .expect("managed");
        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), vec![key.clone()])
                .expect("open");
        let crate::restore::Restoration::Remove {
            dest,
            created_dirs,
            planned,
        } = crate::restore::plan_restore(&entry, home.path()).expect("plan")
        else {
            panic!("bx created it, so rm removes it");
        };
        session
            .apply(Request {
                target: key,
                dest,
                content: Content::Absent {
                    created_dirs,
                    planned: *planned,
                },
                mode: entry.mode,
                ownership: Ownership::Released,
            })
            .expect("the removal");
        drop(session);

        // `~/.made` becomes a link to nowhere.
        let made = home.child(".made");
        if made.is_dir() {
            std::fs::remove_dir(&made).expect("rm the empty directory");
        }
        std::os::unix::fs::symlink(home.child("nowhere"), &made).expect("link");

        let report = pending(&state).expect("pending").expect("interrupted");
        let outcome = recover(&state);

        let Ok(Outcome::Blocked { conflicts }) = outcome else {
            panic!("recovery is blocked, not an error: {outcome:?}");
        };
        assert_eq!(
            conflicts, report.unfinished,
            "the report and the recovery agree"
        );
        let write = &report.unfinished[0];
        assert_eq!(write.standing, Standing::Unreachable);
        assert!(!write.resolvable, "{write:?}");
        assert!(
            write
                .note
                .starts_with("cannot be reached: ~/.made does not resolve to a directory"),
            "{}",
            write.note
        );
        assert!(report.blocked().next().is_some());
        assert!(write.note.contains("~/.made"), "{}", write.note);
        assert!(write.note.contains("abandon"), "{}", write.note);
        assert!(state.journal().exists(), "the journal is kept");
        assert!(matches!(
            lock_for_writing(&state),
            Err(Error::Blocked { .. })
        ));
        assert!(
            std::fs::symlink_metadata(&made)
                .expect("the link stays")
                .file_type()
                .is_symlink()
        );

        assert!(abandon(&state).expect("abandon").is_some());
        assert_eq!(recover(&state).expect("after abandon"), Outcome::Nothing);
    }

    #[test]
    fn a_created_file_changed_after_the_crash_is_blocked_saying_it_did_not_exist() {
        // r3 round 2, P9R4-CV3. `note`'s wording for a write that created its
        // file was never reached. A created file that is gone again reads as
        // `Prior`, so only an edit and a replacement block such a write.
        fn edited(dest: &Path) {
            plant_file(dest, "edited after the crash\n", Mode::DEFAULT_FILE);
        }
        fn replaced(dest: &Path) {
            std::fs::remove_file(dest).expect("rm");
            std::fs::create_dir(dest).expect("a directory in its place");
        }

        let guard = guarded_home();
        for (name, change, standing) in [
            ("edited", edited as fn(&Path), Standing::Diverged),
            ("replaced", replaced as fn(&Path), Standing::Foreign),
        ] {
            let home = guard.child(name);
            std::fs::create_dir_all(&home).expect("the home");
            let state = StateDir::resolve(&home);
            interrupted(
                &state,
                &home,
                vec![write_to(&home, ".new.conf", "bx\n", Mode::DEFAULT_FILE)],
            );
            change(&home.join(".new.conf"));

            let report = pending(&state).expect("pending").expect("interrupted");
            let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
                panic!("{name}: recovery is blocked");
            };
            assert_eq!(conflicts, report.unfinished, "{name}");
            assert_eq!(conflicts[0].standing, standing, "{name}");
            assert!(
                conflicts[0]
                    .note
                    .contains("before the interruption it did not exist, and it was being given"),
                "{name}: {}",
                conflicts[0].note
            );
        }
    }

    #[test]
    fn only_a_destination_in_a_recorded_state_is_resolvable() {
        for (standing, resolvable) in [
            (Standing::Prior, true),
            (Standing::Written, true),
            (Standing::Vanished, false),
            (Standing::Diverged, false),
            (Standing::Foreign, false),
            (Standing::Unreachable, false),
        ] {
            assert_eq!(standing.is_resolvable(), resolvable, "{standing:?}");
        }
    }
}
