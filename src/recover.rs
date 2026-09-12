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
//! [`before_writing`] first, which recovers and refuses to go on if it cannot. A
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
//! One ordering rule makes that hold: **the journal is unlinked last**, after
//! every step has succeeded. Crash before that and the next run repeats a
//! recovery that converges; crash after it and there was nothing left to do.
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
    /// The journal records a write with no session header before it, so the
    /// home its paths were rendered against is unknown.
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
/// Read-only, destinations and state directory alike. A journal it cannot read
/// is reported as no session and left exactly where it is: moving it aside is
/// the degradation `CLAUDE.md` requires of a machine-owned file, and the next
/// writing command does it, under the lock.
///
/// What it reports for each write is decided by the same function [`recover`]
/// acts on, so a report and the recovery that follows cannot disagree.
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
        Loaded::Absent | Loaded::Unreadable { .. } => return Ok(None),
        Loaded::Terminated(_) => true,
        Loaded::Unterminated(_) => false,
    };
    let home = rebuild_home(&loaded, complete, &path)?;

    let kind = loaded
        .begin()
        .map_or(SessionKind::Apply, |begin| begin.kind);
    let mut unfinished = Vec::new();
    for (intent, landed) in loaded.landed() {
        unfinished.push(decide(state, intent, home, landed)?.1);
    }
    Ok(Some(Interrupted {
        kind,
        journal: path,
        complete,
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

/// Recover, and refuse to continue if recovery is blocked.
///
/// The call every writing command makes before it writes anything.
///
/// # Errors
///
/// As [`recover`], plus [`Error::Blocked`] when a destination cannot be
/// accounted for. The escape from that is [`abandon`].
pub fn before_writing(state: &StateDir) -> Result<Outcome, Error> {
    match recover(state)? {
        Outcome::Blocked { conflicts } => Err(Error::Blocked { conflicts }),
        resolved => Ok(resolved),
    }
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
/// the journal cannot be moved.
pub fn abandon(state: &StateDir) -> Result<Option<PathBuf>, Error> {
    let _lock = ExclusiveLock::acquire(state)?;
    let path = state.journal();
    if !path.exists() {
        return Ok(None);
    }
    let aside = StateDir::quarantine(&path);
    std::fs::rename(&path, &aside).map_err(|source| journal::Error::Io {
        path: path.clone(),
        source,
    })?;
    if let Some(dir) = path.parent() {
        journal::fsync_dir(dir)?;
    }
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
        Loaded::Unterminated(_) => false,
    };
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

    let mut intents = loaded.landed();
    if !complete {
        // Reverse order, so a later write is undone before an earlier one it may
        // share a created directory with.
        intents.reverse();
    }
    for (intent, landed) in intents {
        // A temporary file the journal names is this write's, whatever is
        // decided below. One it does not name is never touched.
        if !complete && let Some(temp) = &intent.temp {
            journal::unlink(temp)?;
        }
        let (step, report) = decide(state, intent, home, landed)?;
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
                if let Some(ledger) = ledger.as_mut() {
                    ledger.forget(&intent.target);
                }
            }
        }
        resolved += 1;
    }

    if !conflicts.is_empty() {
        tracing::error!(
            blocked = conflicts.len(),
            journal = %path.display(),
            "recovery is blocked; the journal is kept and bx will not write until it is resolved",
        );
        return Ok(Outcome::Blocked { conflicts });
    }

    if let Some(ledger) = &ledger {
        ledger.save()?;
    }
    // Last of all, and only once every step has succeeded. This is the rule that
    // makes recovery re-runnable without a journal of its own.
    journal::unlink(&path)?;

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
/// what a writing one does cannot disagree — for a terminated journal as much as
/// an unterminated one.
///
/// `home` is `Some` for a terminated journal, whose ledger entries are rebuilt
/// with paths made portable against it, and `None` for an unterminated one,
/// which is rolled back. `landed` is whether a `Done` follows the intent.
fn decide(
    state: &StateDir,
    intent: &Intent,
    home: Option<&Path>,
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
        let rolls_back =
            || format!("interrupted, and {standing}; the next writing bx run rolls it back");
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
        return Ok((Step::Forget, report(true, recorded())));
    };
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
    Ok((Step::Record(entry), report(true, recorded())))
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
    File { digest: ContentHash, mode: Mode },
    Foreign,
}

/// Read a destination.
fn look(dest: &Path) -> Result<Found, Error> {
    let observed = fs::observe(dest)?;
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
    }
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
        crash_phases, peek, permissions_refuse, plant_file, raw_journal, seal, target, write_to,
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
    /// plain modify, and a removal of a private file.
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
                let (target, dest) = target(home, ".gone.conf");
                Request {
                    target,
                    dest,
                    content: Content::Absent {
                        created_dirs: Vec::new(),
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
            &home.join(".gone.conf"),
            "bx made this\n",
            Mode::PRIVATE_FILE,
        );
        // `~/.config` deliberately does not exist: the middle write has to
        // invent two directories, and a rollback has to remove both.
    }

    /// One destination and what is at it: the unit of the before-and-after
    /// comparison the crash harness makes.
    type Snapshot = Vec<(PathBuf, Option<(Vec<u8>, Mode)>)>;

    /// Bytes and mode at each destination, for the before-and-after comparison.
    fn crash_snapshot(home: &Path) -> Snapshot {
        crash_requests(home)
            .into_iter()
            .map(|request| (request.dest.clone(), peek(&request.dest)))
            .collect()
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
        let exe = std::env::current_exe().expect("the test binary");
        Command::new(exe)
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "recover::tests::crash_child",
            ])
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
        assert_eq!(before_writing(&state).expect("before"), Outcome::Nothing);
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
                },
                mode: Mode::PRIVATE_FILE,
                ownership: Ownership::Released,
            }],
        );
        assert!(!dest.exists(), "the removal completed");
        assert!(!home.child(".config").exists());

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

        let err = before_writing(&state).expect_err("a writing command must refuse");
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
                dest,
                content: Content::Bytes(b"yours\n".to_vec()),
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
    fn a_terminated_journal_that_records_a_write_with_no_header_is_an_error() {
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
                }),
                Record::Done(Done { target: portable }),
                Record::End(End { written: 1 }),
            ],
        );

        let err = pending(&state).expect_err("the report refuses it just as recovery does");
        assert!(matches!(err, Error::Headless { .. }), "got {err}");
        let err = recover(&state).expect_err("a headless journal cannot be replayed");
        assert!(matches!(err, Error::Headless { .. }), "got {err}");
        assert!(state.journal().exists());
    }

    #[test]
    fn pending_never_moves_a_journal_aside_even_one_it_cannot_read() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"not a journal").expect("write");

        // `pending` takes no lock, so what it is reading may be a journal a live
        // session is in the middle of creating. It moves nothing.
        assert!(pending(&state).expect("pending").is_none());
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
            return;
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
        assert!(early.join(".gone.conf").is_file());

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
        assert_eq!(intent.dest, late.join(".gone.conf"));
        assert_eq!(intent.temp, None);
        assert_eq!(
            peek(&late.join(".gone.conf")).expect("still there"),
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
        for standing in [
            Standing::Prior,
            Standing::Written,
            Standing::Vanished,
            Standing::Diverged,
            Standing::Foreign,
        ] {
            assert!(!standing.to_string().is_empty());
        }
        assert_eq!(SessionKind::Apply.to_string(), "apply");
        assert_eq!(SessionKind::Restore.to_string(), "restore");
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
                for (dest, found) in crash_snapshot(&home) {
                    let request = crash_requests(&home)
                        .into_iter()
                        .find(|candidate| candidate.dest == dest)
                        .expect("a fixture destination");
                    let was = before
                        .iter()
                        .find(|(path, _)| *path == dest)
                        .and_then(|(_, state)| state.clone());
                    let is_new = match &request.content {
                        Content::Bytes(wanted) => found
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

                // 4. Byte- and mode-identical to the pre-run snapshot.
                assert_eq!(
                    crash_snapshot(&home),
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
                let orphan_possible = matches!(phase, "after-stage" | "after-fill");
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
                assert_eq!(crash_snapshot(&home), before);
            }
        }
    }
}
