//! `plan` and `apply`: one traversal, one decision per target.
//!
//! Invariant 7 says `apply` must never do work `plan` did not announce. This
//! module keeps it by construction rather than by care:
//!
//! * [`run`] is the only entry point for both. It loads nothing itself —
//!   [`Inputs::load`] did that once — and it decides every target through the
//!   same private function whatever the [`Mode`].
//! * A decision is made from shared references only, and the write it produces
//!   carries the observation and the bytes it was made from. Nothing else can
//!   construct one, so the bytes `plan` diffed are the bytes `apply` writes.
//! * `plan` writes nothing, and does not even create the state directory.
//!   `apply` recovers an interrupted session before it decides anything, and
//!   makes every write through one journalled session.
//!
//! The one environment read in the whole path is
//! [`crate::env::Env::from_process`], and
//! the `PATH` a declared activation's tool and a generated file's `has:TOOL`
//! condition are looked up along, which [`Inputs::load`] takes once through
//! [`activation::System::from_env`], with the machine's facts a condition on
//! them is decided against, which it reads once through
//! [`crate::config::when::Machine::read`]; every other function takes what it
//! needs as an argument. The processes the path spawns — a declared activation's
//! command, and `git` for a declared external — inherit the rest of the
//! process environment, which bx itself never reads.

mod decide;
mod diff;
mod error;
mod execute;
pub(crate) mod external;
mod inputs;
mod interrupted;
mod links;
#[cfg(test)]
mod properties;
pub(crate) mod region;
mod track;

use std::collections::BTreeSet;

pub(crate) use decide::read_repo_file;
#[cfg(test)]
pub use diff::DiffKind;
pub(crate) use diff::unified;
pub use diff::{Diff, Palette, View, render, render_row};
pub use error::{Absence, Error};
pub use inputs::Inputs;

use crate::adopt::save::Save;
use crate::config::resolve::Resolution;
use crate::config::target::{Body, Direction, Gen, Target};
use crate::config::{self, Origin};
use crate::journal::{Session, SessionKind};
use crate::paths::{self, Portable};
use crate::recover::{self, Interrupted};
use crate::report::{Action, Exit};
use crate::shell::placement::Platform;
use crate::shell::{Shell, activation};
use crate::state::{
    self, ExclusiveLock, Fingerprints, LedgerView, Mechanism, SharedLock, StateDir,
};

/// Which half of the traversal is running.
///
/// Not the file mode: that is [`crate::fs::Mode`], and the two are never
/// imported into one scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Decide and report. Writes nothing.
    Plan,
    /// Recover, decide, report, and — once approved — write.
    Apply,
    /// [`Mode::Apply`], and also carry every tracked target this machine
    /// changed into the config repo: `bx sync`'s apply. Only this mode writes
    /// a tracked target's repo copy, so a bare `apply` never leaves the config
    /// repo modified.
    Sync,
}

impl Mode {
    /// Whether this run writes.
    const fn writes(self) -> bool {
        matches!(self, Self::Apply | Self::Sync)
    }
}

/// One row of a plan: a target and what happens to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The target, spelled portably. A string rather than a path because a
    /// blocked target is named by its key before substitution.
    pub target: String,
    /// Where the target was declared.
    pub origin: Origin,
    /// What happens to it.
    pub action: Action,
    /// What it would look like, for a row that is not unchanged or blocked.
    pub diff: Option<Diff>,
    /// The one-line explanation printed after the path.
    pub note: Option<String>,
}

/// Everything one run found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// One row per resolved target, in configuration order.
    pub changes: Vec<Change>,
    /// An interrupted session, when `plan` found one standing.
    pub interrupted: Option<Interrupted>,
    /// Whether an `apply` held the state directory while `plan` looked.
    pub apply_running: bool,
    /// Whether this run wrote.
    pub executed: bool,
    /// What recovery did, when an `apply` found an interrupted session, was
    /// approved, recovered it, and stopped there.
    pub recovered: Option<recover::Outcome>,
    /// The rows an executed `apply` stopped short of, by index into
    /// [`Report::changes`], in order. Each such row has been turned
    /// [`Action::Blocked`] with the reason as its note. Only a declared
    /// external can stop: its fetch can fail, and only the fetch shows whether
    /// its `rev` is a fast-forward.
    pub stopped: Vec<usize>,
    /// Every enabled `[[activation]]`, decided once by this run: what the
    /// interactive file was rendered with, and what an executed `apply`
    /// recorded in the fingerprint store.
    pub activations: activation::Plan,
    /// Each file bx owns whole whose bytes or mode were changed since bx wrote
    /// it, each region of bx's edited inside its markers, each symlink bx made
    /// that was retargeted since, and each file or symlink of those deleted
    /// since, in row order: the questions a
    /// writing run asks at a terminal. Its row is a conflict, or a deletion
    /// that stands, whose note says so in every mode.
    pub questions: Vec<Question>,
    /// Each row whose question was answered *keep* — by an earlier run, while
    /// both sides are still what they were then, or by this one — by index
    /// into [`Report::changes`], ascending. Its row is unchanged, says it was
    /// kept, and is shown in every view, as a deletion that stands is; it is
    /// not one of [`Report::questions`], and nothing waits on it.
    pub kept: Vec<usize>,
    /// Each row an executed run saved into the repo — answered *save mine to
    /// the repo* or *merge* — by index into [`Report::changes`], ascending.
    pub saved: Vec<usize>,
    /// Whether a writing run has work to write beside what its questions are
    /// answered with. Set before `approve` is asked, so it can tell whether
    /// to put the one confirmation once every question is answered *keep*.
    pub work: bool,
}

/// A file bx owns whole that was edited since bx wrote it, which a writing
/// run asks about: keep the edit, or take bx's bytes over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The row, by index into [`Report::changes`].
    pub row: usize,
    /// What bx last wrote there against what is on disk, then against what
    /// bx wants there; for a deleted target, what restoring it writes.
    /// `None` where there is no such view, and the row's own diff is all
    /// there is: the question then offers no view of its own.
    pub three_way: Option<Diff>,
    /// What changed since bx left the target, which the question is put
    /// about and its row's note is worded for.
    pub asked: Asked,
    /// What answering *save mine to the repo*, or *merge*, does: the save
    /// `bx add` would make, decided by the same function
    /// ([`crate::adopt::save`]). `None` where none can be made — a shape bx
    /// does not save into, a merge that conflicts — and in a run that does
    /// not write, which decides none.
    pub save: Option<Box<crate::adopt::save::Save>>,
}

/// What someone changed since bx left a target, which a [`Question`] asks
/// whether to keep. Each kind has its own wording: in the question, in the
/// note its row ends with, and in the note the row carries once answered
/// *take*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// A file bx owns whole, whose bytes were edited.
    Edited,
    /// A file bx owns whole, whose bytes are still bx's and whose mode was
    /// changed.
    Mode,
    /// A region of bx's, edited inside its markers.
    Region,
    /// A symlink bx made, retargeted.
    Retargeted,
    /// A file or symlink bx made, deleted.
    Deleted,
}

impl Asked {
    /// The note a row asked about ends with: what `apply` does about it.
    pub(crate) const fn ask(self) -> &'static str {
        match self {
            Self::Edited => decide::ASK,
            Self::Mode => decide::ASK_MODE,
            Self::Region => decide::ASK_REGION,
            Self::Retargeted => decide::ASK_RETARGETED,
            Self::Deleted => decide::ASK_DELETED,
        }
    }

    /// What takes [`Asked::ask`]'s place in the row's note once its answer
    /// took bx's.
    const fn taken(self) -> &'static str {
        match self {
            Self::Edited => TAKEN,
            Self::Mode => TAKEN_MODE,
            Self::Region => TAKEN_REGION,
            Self::Retargeted => TAKEN_RETARGETED,
            Self::Deleted => RESTORED,
        }
    }

    /// `note`, the row's, once its question was answered *take*: the
    /// question gives way to what the answer did, and every other part of
    /// the note — why it was asked, a mode change, a directory created —
    /// still holds and stays.
    /// A deletion that stood no longer does, so it is said as the deletion
    /// alone.
    fn answered(self, note: Option<&str>) -> String {
        let stood = note
            .filter(|_| self == Self::Deleted)
            .map(|note| note.replace(decide::DELETED, STOOD));
        Self::replaced(stood.as_deref().or(note), self.ask(), self.taken())
    }

    /// What takes [`Asked::ask`]'s place in the row's note while its
    /// question stands answered *keep*.
    const fn kept_as(self) -> &'static str {
        match self {
            Self::Edited => KEPT,
            Self::Mode => KEPT_MODE,
            Self::Region => KEPT_REGION,
            Self::Retargeted => KEPT_RETARGETED,
            Self::Deleted => KEPT_DELETED,
        }
    }

    /// `note`, the row's, while its question stands answered *keep*: the
    /// question gives way to the answer, and every other part of the note
    /// stays, as [`Asked::answered`] keeps it.
    pub(crate) fn kept(self, note: Option<&str>) -> String {
        Self::replaced(note, self.ask(), self.kept_as())
    }

    /// `note` with `ask` replaced by `with`, or `with` added where it does
    /// not say `ask`.
    fn replaced(note: Option<&str>, ask: &str, with: &str) -> String {
        match note {
            Some(note) if note.contains(ask) => note.replace(ask, with),
            Some(note) => format!("{note}; {with}"),
            None => with.to_string(),
        }
    }
}

/// What a writing run's `approve` answers: whether to write, and which edited
/// files to write bx's bytes over, by index into [`Report::changes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Approval {
    /// Whether to write.
    pub approved: bool,
    /// Each [`Question::row`] answered *take bx's*. A row not named here is
    /// skipped, as every conflict is.
    pub taken: BTreeSet<usize>,
    /// Each [`Question::row`] answered *keep*, which is remembered in the
    /// ledger so the question is not put again while both sides stay as
    /// they are — unless the run is declined, which remembers nothing. A row
    /// named in neither set was not answered, and is asked again.
    pub kept: BTreeSet<usize>,
    /// Each [`Question::row`] answered *save mine to the repo* or *merge*:
    /// its [`Question::save`] is made once the run is approved.
    pub saved: BTreeSet<usize>,
}

impl From<bool> for Approval {
    fn from(approved: bool) -> Self {
        Self {
            approved,
            ..Self::default()
        }
    }
}

/// What an edited file's row says once its answer took bx's bytes.
pub(crate) const TAKEN: &str = "you took bx's bytes, and bx rm restores yours";

/// What a file's row says once its answer took bx's mode back.
pub(crate) const TAKEN_MODE: &str = "you took bx's mode, and bx rm restores yours";

/// What an edited region's row says once its answer took bx's region.
pub(crate) const TAKEN_REGION: &str =
    "you took bx's region, and bx rm restores the file as you left it";

/// What a retargeted link's row says once its answer took bx's target.
pub(crate) const TAKEN_RETARGETED: &str = "you took bx's target, and bx rm restores yours";

/// What a deleted target's row says once its answer restored it.
pub(crate) const RESTORED: &str = "you restored bx's";

/// What an edited file's row says once its answer saved the edit into the
/// repo.
pub(crate) const SAVED: &str = "you saved your edit into the repo, and bx sync commits it";

/// What an edited file's row says once its answer merged the edit with the
/// repo's change.
pub(crate) const MERGED: &str = "you merged your edit with the repo's change, here and in the \
                                 repo; bx sync commits it, and bx rm restores yours";

/// What an edited file's row says while its answer *keep* stands.
pub(crate) const KEPT: &str =
    "you kept your edit, and bx asks again once it or what bx wants there changes";

/// What a file's row says while its answer *keep* about its mode stands.
pub(crate) const KEPT_MODE: &str =
    "you kept your mode, and bx asks again once it or what bx wants there changes";

/// What an edited region's row says while its answer *keep* stands.
pub(crate) const KEPT_REGION: &str = "you kept your edit to bx's region, and bx asks again once \
                                      the file or what bx wants there changes";

/// What a retargeted link's row says while its answer *keep* stands.
pub(crate) const KEPT_RETARGETED: &str =
    "you kept your target, and bx asks again once it or what bx wants there changes";

/// What a deleted target's row says while its answer *keep it deleted*
/// stands.
pub(crate) const KEPT_DELETED: &str = "you kept it deleted, and bx asks again once something is \
                                       there or what bx wants there changes";

/// What a pending link's child asked about says in place of its question:
/// its commit arrived only after this run's questions were put.
pub(crate) const ASK_NEXT: &str = "its commit arrived after this run's questions were put, so at a \
                                   terminal the next bx apply or bx sync asks about it";

/// What replaces [`decide::DELETED`] in a restored row's note: the deletion
/// no longer stands.
const STOOD: &str = "deleted since bx wrote it";

impl Report {
    /// Every row's action, in order, then every activation's.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        self.changes
            .iter()
            .map(|change| change.action)
            .chain(
                self.activations
                    .steps()
                    .iter()
                    .map(activation::Step::action),
            )
            .collect()
    }
}

/// Decide every target, report, and — in [`Mode::Apply`] or [`Mode::Sync`],
/// once `approve` says so — write.
///
/// An interrupted session comes first, in every mode, and is then all a run
/// does. Its rows are what recovery would do to each write the session
/// announced, and no configured target is decided against a disk recovery is
/// about to change: `plan` shows the rows, and `apply` refuses before any
/// recovery when a write cannot be accounted for, asks `approve` otherwise, and
/// once approved recovers and stops. The next run decides.
///
/// `approve` is shown the report and asked only when there is a write to make,
/// and never in [`Mode::Plan`]. Declining leaves the report unexecuted and
/// nothing written: nothing is rolled back, no session is opened and no journal
/// is created.
///
/// # Errors
///
/// Whatever recovery, loading the ledger, reading a body, observing a
/// destination, `approve`, or the session returns, and [`Error::Recover`] with
/// [`recover::Error::Blocked`] from `apply` over an interrupted write recovery
/// cannot account for. A failed write leaves its journal for the next writing
/// run to roll back.
pub fn run(
    inputs: &Inputs,
    mode: Mode,
    approve: &mut dyn FnMut(&Report) -> Result<bool, Error>,
) -> Result<Report, Error> {
    decide_and_write(inputs, mode, false, &mut |report| {
        approve(report).map(Approval::from)
    })
}

/// [`run`], with each edited file [`Report::questions`] names settled by what
/// `approve` answers.
///
/// The questions are part of the plan: each is decided with every other row,
/// its row says what `apply` asks, and the write an answer of *take bx's*
/// makes is the one the decision produced. An answer selects that write; it
/// never decides one. `approve` is asked when there is work to write or a
/// question to answer, and a run whose only work was its questions, all
/// answered *keep*, writes no target and opens no session.
///
/// An answer *keep* is remembered in the target's ledger entry, against
/// what both sides were when it was given, unless the run is declined: while
/// both are still exactly that, every later run's row says it was kept and
/// asks nothing. A row answered *take bx's* is written, and its write
/// clears any answer remembered there.
///
/// # Errors
///
/// As [`run`].
pub fn answered(
    inputs: &Inputs,
    mode: Mode,
    approve: &mut dyn FnMut(&Report) -> Result<Approval, Error>,
) -> Result<Report, Error> {
    decide_and_write(inputs, mode, true, approve)
}

/// [`answered`], which asks `approve` about a run whose only work is its
/// questions only when `asks`: [`run`] answers none, so it is asked only when
/// there is other work, as it always was.
fn decide_and_write(
    inputs: &Inputs,
    mode: Mode,
    asks: bool,
    approve: &mut dyn FnMut(&Report) -> Result<Approval, Error>,
) -> Result<Report, Error> {
    refuse_irregular_state_files(&inputs.state)?;
    let mut report = Report::default();
    look_at_state(inputs, &mut report)?;
    // A writing run refuses a held state directory here, before it decides
    // anything. `Session::open` refuses it too, but only after every target has
    // been decided against a disk the running `apply` is concurrently changing,
    // the whole plan has been rendered, and the user has answered a
    // confirmation prompt for work this run was never going to do. The refusal
    // is the same error `Session::open` would have raised, named by the same
    // holder — see [`Holder::of`].
    if mode.writes() && report.apply_running {
        return Err(state::Error::Locked {
            holder: state::Holder::of(&inputs.state),
            path: inputs.state.lock(),
        }
        .into());
    }
    if let Some(interrupted) = report.interrupted.clone() {
        report.changes = interrupted::interrupted_rows(inputs, &interrupted)?;
        if mode == Mode::Plan {
            return Ok(report);
        }
        // Recovery is the work an approval is asked for.
        report.work = true;
        // Refused on what `pending` found, before recovery runs at all, so a
        // blocked session rolls nothing back.
        let blocked: Vec<_> = interrupted.blocked().cloned().collect();
        if !blocked.is_empty() {
            return Err(recover::Error::Blocked { conflicts: blocked }.into());
        }
        if approve(&report)?.approved {
            // A session that became blocked between `pending` and here is
            // still refused: this run is a writing one, and `recover` hands
            // that verdict back as a value only for a caller that reports it.
            report.recovered = Some(match recover::recover(&inputs.state)? {
                recover::Outcome::Blocked { conflicts } => {
                    return Err(recover::Error::Blocked { conflicts }.into());
                }
                outcome => outcome,
            });
        }
        return Ok(report);
    }

    let ledger = LedgerView::read(&inputs.state, &inputs.home)?.value;
    let bases = track::bases(inputs)?;
    // Every declared activation is decided here, once, against the cache as
    // it stands, read without a lock: what the interactive file is rendered
    // with below is what `apply` records, and nothing decides them again. A
    // configuration declaring none never opens the cache at all.
    if !inputs.activations.is_empty() {
        let cache = Fingerprints::read(&inputs.state)?.value;
        report.activations =
            activation::plan(&inputs.activations, &cache, &inputs.roots, &inputs.host);
    }
    let ctx = decide::Ctx {
        ledger: &ledger,
        home: &inputs.home,
        repo: &inputs.repo,
        roots: &inputs.roots,
        secrets: &inputs.resolved.secrets,
        declared: &decide::Declared::new(),
        bases: &bases,
        host: &inputs.host,
        overlays: &inputs.resolved.overlays,
    };
    // A fragment bx wrote for a place no variable lands in any more is planned
    // empty, so switching a variable off takes it out of every shell.
    let mut targets: Vec<Resolution<Target>> = inputs
        .resolved
        .targets
        .iter()
        .map(|target| with_activations(target.clone(), &report.activations))
        .collect();
    // Each zsh activation's own file and its wordcode, which zsh's
    // interactive file sources, decided and written as any other file bx
    // owns whole, and taken back once no activation renders them.
    targets.extend(
        report
            .activations
            .targets()
            .into_iter()
            .map(Resolution::Ready),
    );
    let owned = |path: &paths::Portable| {
        ledger
            .get(path)
            .is_some_and(|entry| entry.mechanism == Mechanism::Own)
    };
    targets.extend(crate::shell::placement::vacated_fragments(
        &inputs.resolved.targets,
        owned,
        // bash's files sit where a `[[target]]` may have put a file bx owns
        // whole too, `~/.inputrc` above all, so only bytes that open with
        // the generator's own header say the generator wrote them.
        |path, header| {
            owned(path)
                && std::fs::read(path.render(&inputs.home))
                    .is_ok_and(|bytes| bytes.starts_with(header.as_bytes()))
        },
        &inputs.home,
        &inputs.state.ledger(),
    ));
    // Every declared external, in configuration order; reported after every
    // target, and decided first so a link is never read from a checkout that
    // stays where it is.
    let (rows, clones) = external::decide_all(
        &inputs.resolved.externals,
        &external::Ctx {
            ledger: &ledger,
            home: &inputs.home,
            git: &inputs.git,
            lock: &inputs.lock,
            committed: inputs.committed_externals(),
        },
    )?;
    // Every external's links, as symlink targets decided with the rest: each
    // child the commit holds, beside every path a target already declares.
    let mut expansion = {
        let declared: BTreeSet<&str> = targets.iter().map(declared_path).collect();
        links::expand(
            &inputs.resolved.externals,
            &inputs.lock,
            &inputs.home,
            &inputs.git,
            &declared,
            &|path| external::bx_clone(&ledger, path),
            &|at| matches!(rows[at].action, Action::Blocked | Action::Conflict),
        )
    };
    targets.append(&mut expansion.targets);
    let decided = decide::decide_all(&targets, &ctx)?;
    report.changes = decided.changes;
    report.kept = decided.kept;
    // What bx last wrote at each edited file, read back from where `apply`
    // kept it, is the base of the view its question offers.
    report.questions = decided
        .held
        .iter()
        .map(|(row, op)| {
            let entry = ledger.get(op.target());
            Question {
                row: *row,
                three_way: op.three_way(
                    entry
                        .and_then(|entry| {
                            state::restore::kept(&inputs.state, entry.written, track::Base::LIMIT)
                        })
                        .as_deref(),
                ),
                asked: op.asked(entry),
                save: if mode.writes() {
                    offered_save(inputs, &targets, op, entry)
                } else {
                    None
                },
            }
        })
        .collect();
    let mut held = decided.held;
    // A tracked target's repo copy is written by `sync` alone, after every
    // other write; a bare `apply` announces the row and leaves it.
    let mut ops = decided.ops;
    // Where a taken edit's write goes: after every other file's, before
    // anything carried or taken back.
    let taken_at = ops.len();
    if mode == Mode::Sync {
        ops.extend(decided.carries);
    }
    let agreed = decided.agreed;
    let first_external = report.changes.len();
    report.changes.extend(rows);
    // A child some other declaration holds, and each link whose commit is not
    // here yet, after the externals whose work brings it.
    let first_link = report.changes.len();
    report.changes.append(&mut expansion.rows);
    // Last, after every external, so the indices `stopped` is built from are
    // not moved: every file bx wrote that nothing declares any more. Taken
    // back after every other write, in the same session.
    let undeclared = undeclared_rows(inputs, &ledger, &targets, &expansion.held);
    let first_undeclared = report.changes.len();
    report.changes.extend(undeclared.rows);
    ops.extend(undeclared.ops);
    let released = undeclared.released;
    let undone_clones = undeclared.clones;

    match mode {
        Mode::Plan => Ok(report),
        Mode::Apply | Mode::Sync => {
            // A capture is work even when the file it renders into is already
            // right — a binary upgraded to one printing the same text — since
            // until it is recorded every `plan` runs the tool again.
            let captured = report
                .activations
                .steps()
                .iter()
                .any(|step| step.action().is_pending());
            report.work = !(ops.is_empty()
                && released.is_empty()
                && clones.is_empty()
                && undone_clones.is_empty()
                && expansion.pending.is_empty()
                && !captured);
            if !report.work && (report.questions.is_empty() || !asks) {
                track::agree(inputs, &bases, &agreed, mode, false)?;
                return Ok(report);
            }
            let approval = approve(&report)?;
            let mut tied = decided.tied;
            // A zsh activation's wordcode edited since bx wrote it is taken
            // only with its file, as its row says: taken alone, it is kept,
            // since zsh would read bx's compiled form in place of the file.
            let alone = |row: &usize| {
                tied.iter().any(|tied| {
                    tied.row == *row && tied.asked() && !approval.taken.contains(&tied.source)
                })
            };
            // Each question answered *keep*, with what both its sides were
            // when it was: remembered unless the run is declined.
            let keeps: Vec<Answered> = held
                .iter()
                .filter(|(row, _)| approval.kept.contains(row))
                .map(|(row, op)| Answered {
                    row: *row,
                    target: op.target().clone(),
                    both: op.kept(),
                    asked: op.asked(ledger.get(op.target())),
                })
                .collect();
            // Each edit answered *save* or *merge*, with the save its
            // question was put with and the write it was held with.
            let saves: Vec<(usize, Save, decide::Op)> = held
                .iter()
                .filter(|(row, _)| approval.saved.contains(row))
                .filter_map(|(row, op)| {
                    let question = report.questions.iter().find(|q| q.row == *row)?;
                    Some((*row, (**question.save.as_ref()?).clone(), op.clone()))
                })
                .collect();
            let taken: Vec<_> = held
                .drain(..)
                .filter(|(row, _)| approval.taken.contains(row) && !alone(row))
                .collect();
            if !report.work && taken.is_empty() && saves.is_empty() {
                remember_kept(inputs, &keeps, &mut tied, &mut report)?;
                track::agree(inputs, &bases, &agreed, mode, false)?;
                return Ok(report);
            }
            if !approval.approved {
                return Ok(report);
            }
            // Each edit answered *take bx's* becomes the write its row was
            // decided with, and its row the modify that write is.
            // A deleted target answered *restore* becomes the create it was
            // decided with. A zsh activation's wordcode tied to a taken file
            // is written right after it, so it is never the older of the two,
            // as the create or modify it was announced as; one asked about
            // itself and taken too is written by its own answer, whose row
            // follows its file's.
            let before = ops.len();
            for (row, op) in taken.into_iter().rev() {
                let asked = op.asked(ledger.get(op.target()));
                let change = &mut report.changes[row];
                change.action = if op.deleted() {
                    Action::Create
                } else {
                    Action::Modify
                };
                change.note = Some(asked.answered(change.note.as_deref()));
                if let Some(at) = tied.iter().position(|tied| tied.source == row) {
                    let wordcode = tied[at].row;
                    if let Some((write, action, note)) = tied.remove(at).into_write() {
                        report.changes[wordcode].action = action;
                        report.changes[wordcode].note = note;
                        ops.insert(taken_at, write);
                    }
                }
                ops.insert(taken_at, op);
            }
            // Each merge becomes the write its question was held with, made
            // with the merged bytes, checked below as a taken write is; a
            // save writes nothing here, and its row stays unchanged.
            for (row, save, op) in saves.iter().rev() {
                let asked = op.asked(ledger.get(op.target()));
                let change = &mut report.changes[row.to_owned()];
                let said = if save.writes_machine() {
                    change.action = Action::Modify;
                    ops.insert(taken_at, op.merged(save.bytes.clone(), save.mode));
                    MERGED
                } else {
                    change.action = Action::Unchanged;
                    change.diff = None;
                    SAVED
                };
                change.note = Some(Asked::replaced(change.note.as_deref(), asked.ask(), said));
            }
            // Every taken write checked against what plan saw before the
            // first write is made: a target changed while its question was
            // open refuses the run with nothing written, rather than once
            // every write queued ahead of it has landed. Any other write is
            // refused at its own turn, and rolled back with the session.
            for op in &ops[taken_at..taken_at + (ops.len() - before)] {
                op.refuse_moved()?;
            }
            // The repo side of every save before any target is written, as
            // `bx add` makes it: see [`save_edits`].
            if !saves.is_empty() {
                save_edits(inputs, &saves)?;
            }
            // What each file bx writes whole will hold, kept once the session
            // has landed it as the base a later edit is measured from. A run
            // stopped before then loses only that view.
            let kept: Vec<Vec<u8>> = ops
                .iter()
                .filter_map(decide::Op::base)
                .map(<[u8]>::to_vec)
                .collect();
            // Before the session, as `bx rm` removes one: a checkout's bytes
            // are git's, and no journal can roll its removal back.
            if !undone_clones.is_empty() {
                remove_clones(inputs, &undone_clones, first_undeclared, &mut report)?;
            }
            // Every target first, so a clone beneath a directory a target
            // creates is made inside it rather than before it. A file
            // released is forgotten in the same session, after every write.
            if !ops.is_empty() || !released.is_empty() {
                let scope = ops
                    .iter()
                    .map(|op| op.target().clone())
                    .chain(released.iter().cloned())
                    .collect();
                let mut session =
                    Session::open(&inputs.state, SessionKind::Apply, &inputs.home, scope)?;
                // Before the first write, so a file staged beneath a declared
                // directory is held to the directory's declared mode.
                for (dir, mode) in &decided.declared {
                    session.declare_dir(dir, *mode);
                }
                let progress = execute::progress(execute::steps(&ops, &released), inputs.progress);
                execute::execute(ops, &released, session, &progress)?;
                // Best effort: every write has landed, and a base that could
                // not be kept costs only the view, never the run.
                for base in &kept {
                    if let Err(error) = state::restore::keep(&inputs.state, base) {
                        tracing::warn!(%error, "the bytes bx wrote were not kept as a base");
                    }
                }
            }
            if !clones.is_empty() {
                inputs.state.ensure()?;
                let lock = ExclusiveLock::acquire(&inputs.state)?;
                let progress = execute::progress(clones.len(), inputs.progress);
                let stopped = external::execute(
                    clones,
                    &inputs.state,
                    &inputs.home,
                    &inputs.git,
                    &lock,
                    &progress,
                )?;
                for (at, note) in stopped {
                    let at = first_external + at;
                    report.changes[at].action = Action::Blocked;
                    report.changes[at].diff = None;
                    report.changes[at].note = Some(note);
                    report.stopped.push(at);
                }
            }
            // After the clones, which are what bring a pending link's commit.
            if !expansion.pending.is_empty() {
                let declared = targets
                    .iter()
                    .map(|target| declared_path(target).to_string())
                    .collect();
                link_pending(
                    inputs,
                    &bases,
                    &expansion.pending,
                    first_link,
                    declared,
                    &mut report,
                )?;
            }
            // Last, so a cache entry is never saved for output a failed write
            // left out of the file: losing it costs only a re-run.
            if !inputs.activations.is_empty() {
                record_activations(&inputs.state, &report.activations)?;
            }
            remember_kept(inputs, &keeps, &mut tied, &mut report)?;
            report.saved = saves.iter().map(|(row, _, _)| *row).collect();
            report.saved.sort_unstable();
            report.executed = true;
            track::agree(inputs, &bases, &agreed, mode, true)?;
            Ok(report)
        }
    }
}

/// The save a held file's question offers: the one `bx add` would make,
/// decided by the same function ([`crate::adopt::save`]), for a file bx owns
/// whole that is still there, and only where it is not a merge that
/// conflicts — writing conflict markers into the user's file is `bx add`'s,
/// confirmed on its own.
fn offered_save(
    inputs: &Inputs,
    targets: &[Resolution<Target>],
    op: &decide::Op,
    entry: Option<&state::LedgerEntry>,
) -> Option<Box<Save>> {
    use crate::adopt::save::{self, Decision, How};
    let (entry, wanted) = (entry?, op.whole()?);
    if op.deleted() {
        return None;
    }
    let target = targets.iter().find_map(|resolution| match resolution {
        Resolution::Ready(target) if target.path == *op.target() => Some(target),
        _ => None,
    })?;
    let sides = save::Sides {
        home: &inputs.home,
        repo: &inputs.repo,
        state: &inputs.state,
        git: &inputs.git,
        values: &inputs.resolved.values,
        targets: &inputs.resolved.targets,
    };
    match save::decide(&sides, target, entry, op.planned(), wanted) {
        Decision::Save(save) if save.how != How::Conflicted => Some(save),
        Decision::Save(_) | Decision::Refused(_) => None,
    }
}

/// Make the repo side of each save in `saves`, under the exclusive lock:
/// write each repo file it rewrites, record it for `bx sync` to commit, and,
/// for a save that leaves the machine file as it is, record in the ledger
/// that bx owns the bytes there, as `bx add` does. A merge's machine file is
/// written by the session, as its row's modify.
///
/// A file a save leaves as it is that changed while its question was open is
/// refused with nothing written, as a taken write is.
///
/// # Errors
///
/// What the state directory, the lock, a repo write or the ledger returns:
/// [`crate::fs::Error::Changed`] for a repo file or a machine file changed
/// since the save was decided.
fn save_edits(inputs: &Inputs, saves: &[(usize, Save, decide::Op)]) -> Result<(), Error> {
    for (_, save, _) in saves.iter().filter(|(_, save, _)| !save.writes_machine()) {
        let now = crate::fs::observe(&save.target.render(&inputs.home))?;
        crate::fs::refuse_moved(save.observed(), &now)?;
    }
    inputs.state.ensure()?;
    let lock = ExclusiveLock::acquire(&inputs.state)?;
    let mut written = Vec::new();
    for (_, save, _) in saves {
        for write in &save.repo {
            write.put()?;
            written.push(write.written());
        }
    }
    crate::sync::remember_saved(&inputs.state, &lock, &inputs.repo, &written);
    let mut ledger = state::Ledger::open(&inputs.state, &lock, &inputs.home)?.value;
    let mut recorded = Vec::new();
    for (_, save, _) in saves.iter().filter(|(_, save, _)| !save.writes_machine()) {
        ledger.record(save.record())?;
        recorded.push(save);
    }
    if !recorded.is_empty() {
        ledger.save()?;
        crate::adopt::save::keep_bases(&inputs.state, &recorded);
    }
    Ok(())
}

/// A question this run was answered *keep* about.
struct Answered {
    /// Its row, by index into [`Report::changes`].
    row: usize,
    /// The target it is about.
    target: Portable,
    /// What both its sides were when it was answered.
    both: state::Kept,
    /// What it asked.
    asked: Asked,
}

/// Remember each answer in `kept` in the ledger, under the exclusive lock,
/// and turn its row into the kept row the next run's plan shows, with any
/// wordcode tied to it: see [`decide::keep_rows`].
///
/// Bookkeeping only, as [`record_activations`] is: no target is touched, so
/// it is made outside any session, and a ledger already holding every answer
/// is not written. A record lost — a crash before the save, a ledger an
/// older bx saved since — costs only the question, put again.
fn remember_kept(
    inputs: &Inputs,
    kept: &[Answered],
    tied: &mut Vec<decide::Tied>,
    report: &mut Report,
) -> Result<(), Error> {
    if kept.is_empty() {
        return Ok(());
    }
    inputs.state.ensure()?;
    let lock = ExclusiveLock::acquire(&inputs.state)?;
    let mut ledger = state::Ledger::open(&inputs.state, &lock, &inputs.home)?.value;
    let mut changed = false;
    for answer in kept {
        changed |= ledger.keep(&answer.target, answer.both.clone());
    }
    if changed {
        ledger.save()?;
    }
    let answered: Vec<_> = kept
        .iter()
        .map(|answer| (answer.row, answer.asked))
        .collect();
    report
        .kept
        .extend(decide::keep_rows(&mut report.changes, tied, &answered));
    report.kept.sort_unstable();
    Ok(())
}

/// Remove each checkout nothing declares any more that `plan` announced as
/// [`Action::Undo`], through [`crate::restore::remove_clone`], as `bx rm`
/// removes one: crash-safe by the ledger alone, under the exclusive lock.
///
/// Each is decided again as it is removed, by the same function `plan` asked,
/// so a checkout that took on work since is left, never removed: its row, at
/// `first_row` plus its index, is stopped with why, as an external's is.
///
/// # Errors
///
/// Whatever the state directory, the ledger or the removal returns.
fn remove_clones(
    inputs: &Inputs,
    clones: &[(usize, state::LedgerEntry)],
    first_row: usize,
    report: &mut Report,
) -> Result<(), Error> {
    use crate::restore::{self, Restored};

    let error = |error: restore::Error| match error {
        restore::Error::Journal(error) => Error::Journal(error),
        restore::Error::Recover(error) => Error::Recover(error),
        restore::Error::State(error) => Error::State(error),
        restore::Error::Read(error) => Error::Fs(error),
    };
    inputs.state.ensure()?;
    let lock = ExclusiveLock::acquire(&inputs.state)?;
    let mut ledger = state::Ledger::open(&inputs.state, &lock, &inputs.home)?.value;
    for (at, entry) in clones {
        let removed =
            restore::remove_clone(&mut ledger, entry, &inputs.home, &inputs.git).map_err(error)?;
        if let Restored::Conflict { note, .. } = removed {
            let at = first_row + at;
            report.changes[at].action = Action::Blocked;
            report.changes[at].diff = None;
            report.changes[at].note = Some(note);
            report.stopped.push(at);
        }
    }
    Ok(())
}

/// The path a target declares: its own, or a held-back one's key.
fn declared_path(resolution: &Resolution<Target>) -> &str {
    match resolution {
        Resolution::Ready(target) => target.path.as_str(),
        Resolution::Blocked(entry) => entry.key.as_str(),
    }
}

/// Expand, decide and write every link `plan` announced as pending, now that
/// the clones have run, appending a row for each child.
///
/// A pending link's row turns unchanged once its children are listed — they
/// carry the work, each in a row of its own — and is stopped with why when
/// its commit is still not here — its
/// external was stopped, or reached no commit. Each child is decided against
/// the ledger as the clones left it, and written in a session of its own,
/// after the one the targets were written in. A child retargeted or deleted
/// since bx made it is not asked about: the questions were put before its
/// commit was here, so its row says the next run asks, and nothing is
/// written there.
///
/// # Errors
///
/// As [`decide::decide_all`] and [`execute::execute`].
fn link_pending(
    inputs: &Inputs,
    bases: &track::Bases,
    pending: &[links::Pending],
    first_row: usize,
    declared: BTreeSet<String>,
    report: &mut Report,
) -> Result<(), Error> {
    // As the clones left it: a clone this run made is bx's now.
    let ledger = LedgerView::read(&inputs.state, &inputs.home)?.value;
    let mut taken = declared;
    let mut targets = Vec::new();
    let mut conflicts = Vec::new();
    for pending in pending {
        let external = &inputs.resolved.externals[pending.external];
        let link = &external.links[pending.link];
        match links::expand_pending(
            external,
            link,
            &pending.rev,
            &inputs.home,
            &inputs.git,
            &mut taken,
            external::finished_clone(&ledger, &external.path),
        ) {
            Ok((children, taken_rows)) => {
                targets.extend(children);
                conflicts.extend(taken_rows);
                // Its children carry the work from here, each in a row of
                // its own; the rule itself writes nothing.
                report.changes[first_row + pending.row].action = Action::Unchanged;
            }
            Err(note) => {
                let at = first_row + pending.row;
                report.changes[at].action = Action::Blocked;
                report.changes[at].note = Some(note);
                report.stopped.push(at);
            }
        }
    }
    // Reported, never written: the first declaration keeps the path. Known
    // only now, so said with the rows apply stopped short of.
    for conflict in conflicts {
        report.stopped.push(report.changes.len());
        report.changes.push(conflict);
    }
    if targets.is_empty() {
        return Ok(());
    }
    let ctx = decide::Ctx {
        ledger: &ledger,
        home: &inputs.home,
        repo: &inputs.repo,
        roots: &inputs.roots,
        secrets: &inputs.resolved.secrets,
        declared: &decide::Declared::new(),
        bases,
        host: &inputs.host,
        overlays: &inputs.resolved.overlays,
    };
    let mut decided = decide::decide_all(&targets, &ctx)?;
    // A child retargeted or deleted since bx made it is a question, but this
    // run's questions were put before its commit was here: its row says the
    // next run asks it rather than promising this one does, and its write
    // is never made unanswered. A child is a symlink, so none is a zsh
    // activation's file with a wordcode tied to it.
    debug_assert!(decided.tied.is_empty(), "a link's child is never tied");
    for (row, op) in &decided.held {
        let ask = op.asked(ledger.get(op.target())).ask();
        let change = &mut decided.changes[*row];
        change.note = change
            .note
            .as_deref()
            .map(|note| note.replace(ask, ASK_NEXT));
    }
    // A child an earlier run was answered *keep* about is said kept, as any
    // target is, at the row it is appended as.
    let first = report.changes.len();
    report
        .kept
        .extend(decided.kept.iter().map(|row| first + row));
    for change in decided.changes {
        // A child that is a conflict or blocked was never shown as one, so
        // it is said with the rows apply stopped short of.
        if change.action.needs_attention() {
            report.stopped.push(report.changes.len());
        }
        report.changes.push(change);
    }
    if !decided.ops.is_empty() {
        let scope = decided.ops.iter().map(|op| op.target().clone()).collect();
        let session = Session::open(&inputs.state, SessionKind::Apply, &inputs.home, scope)?;
        let progress = execute::progress(decided.ops.len(), inputs.progress);
        execute::execute(decided.ops, &[], session, &progress)?;
    }
    Ok(())
}

/// One row per ledger entry that nothing this run decides names, in ascending
/// path order: a file bx wrote whose `[[target]]` was deleted or switched off,
/// or whose repo file a `tree` mirrored was removed.
///
/// A path is declared when `targets` names it — every enabled target, and
/// every generated fragment bx vacates, which is planned empty rather than
/// reported here — or an enabled external does. A target held back names the
/// path it was written with, so one blocked on a missing tool or an unanswered
/// value in its body still declares its file; one whose path itself waits on a
/// value cannot be matched, and its file is reported until the value is given.
/// A generated fragment held back on an unanswered value is named by its key,
/// which is its path, so it declares its file the same way.
///
/// A tracked target also declares its repo copy, which `sync` claims in the
/// ledger: the file in the repo its `file` names. A held-back tracked target's
/// `file` may itself wait on a value, so its copy cannot be named; while any
/// tracked target is held back, every ledger entry under the config repo
/// counts as declared — the conservative rule a blocked secret gets — rather
/// than advising `bx rm` on a copy the configuration may still declare.
///
/// Every entry beneath a directory in `held` — an external link's `to` whose
/// children this run cannot list — counts as declared too, by the same rule.
///
/// The rows are [`decide::decide_undeclared`]'s, and so is what `apply` does
/// about each: see [`Undeclared`]. A row that undoes nothing and releases
/// nothing keeps its entry, and the next `plan` shows the same row.
fn undeclared_rows(
    inputs: &Inputs,
    ledger: &LedgerView,
    targets: &[Resolution<Target>],
    held: &[Portable],
) -> Undeclared {
    let blocked = inputs
        .declared_targets()
        .filter(|(_, resolution)| matches!(resolution, Resolution::Blocked(_)))
        .map(|(declared, _)| declared.path.as_str());
    let tracking_held_back = inputs.declared_targets().any(|(declared, resolution)| {
        matches!(resolution, Resolution::Blocked(_)) && declared.direction == Direction::Track
    });
    let repo = paths::normalize(&inputs.repo);
    let copies: Vec<Portable> = inputs
        .resolved
        .targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) => Some(target),
            Resolution::Blocked(_) => None,
        })
        .filter(|target| target.direction == Direction::Track)
        .filter_map(|target| match &target.body {
            Body::File(rel) => Portable::from_path(&inputs.repo.join(rel), &inputs.home).ok(),
            _ => None,
        })
        .collect();
    let mut declared: BTreeSet<&str> = targets
        .iter()
        .map(|resolution| match resolution {
            Resolution::Ready(target) => target.path.as_str(),
            Resolution::Blocked(entry) => entry.key.as_str(),
        })
        .chain(blocked)
        .chain(copies.iter().map(Portable::as_str))
        .chain(
            inputs
                .resolved
                .externals
                .iter()
                .map(|external| external.path.as_str()),
        )
        .collect();
    declare_sourcing(&mut declared, Platform::HERE);
    let origin = Origin::unknown(&inputs.state.ledger());
    // A link's own directory is the user's, not bx's: only what lies beneath
    // one whose children this run cannot list is held.
    let held_beneath = |path: &Portable| {
        held.iter()
            .any(|dir| path.as_str().starts_with(&format!("{dir}/")))
    };
    let look = decide::Look {
        home: &inputs.home,
        state: &inputs.state,
        git: &inputs.git,
        repo: &repo,
        declares_any: inputs.declares_any(),
    };
    let mut undeclared = Undeclared::default();
    for (path, entry) in ledger
        .iter()
        .filter(|(path, _)| !declared.contains(path.as_str()))
        .filter(|(path, _)| !held_beneath(path))
        // Lexical, like every containment verdict bx makes.
        .filter(|(path, _)| {
            !(tracking_held_back && paths::normalize(&path.render(&inputs.home)).starts_with(&repo))
        })
    {
        let (row, undo) = decide::decide_undeclared(entry, &origin, &look);
        match undo {
            decide::Undo::Nothing => {}
            decide::Undo::Forget => undeclared.released.push(path.clone()),
            decide::Undo::Write(op) => undeclared.ops.push(*op),
            decide::Undo::Clone => undeclared
                .clones
                .push((undeclared.rows.len(), entry.clone())),
        }
        undeclared.rows.push(row);
    }
    // Deepest first, so a file goes before the directory bx made for it.
    undeclared.ops.reverse();
    undeclared
}

/// Every file bx wrote that nothing declares any more: its row, and what
/// `apply` does about it.
#[derive(Debug, Default)]
struct Undeclared {
    /// One row per entry, in ascending path order.
    rows: Vec<Change>,
    /// Every path whose ledger entry `apply` drops and whose file it leaves
    /// as it is: [`Action::Release`].
    released: Vec<Portable>,
    /// The writes that take a file back, deepest path first: each
    /// [`Action::Undo`] but a checkout's.
    ops: Vec<decide::Op>,
    /// Each checkout `apply` removes, outside the session as `bx rm` removes
    /// one, by index into [`Undeclared::rows`].
    clones: Vec<(usize, state::LedgerEntry)>,
}

/// Declare, for each generated file `declared` names, the startup files whose
/// regions source it on `platform`.
///
/// A startup file's region sources its fragment, and stays while the
/// fragment is planned — a vacated one included, which is left sourced and
/// empty — so it is declared by the fragment whether or not this run decides
/// it. On [`Platform::Macos`] bash's file is sourced from
/// [`crate::shell::bash::PROFILE`] too, so that region is declared with it.
fn declare_sourcing(declared: &mut BTreeSet<&str>, platform: Platform) {
    let profile = (platform == Platform::Macos).then_some(crate::shell::bash::PROFILE);
    let sourcing = config::env::Place::ALL
        .into_iter()
        .filter_map(|place| Some((place.fragment(), place.startup_file()?)))
        .chain([(crate::shell::bash::FILE, crate::shell::bash::STARTUP_FILE)])
        .chain(profile.map(|profile| (crate::shell::bash::FILE, profile)));
    for (fragment, startup) in sourcing {
        if declared.contains(fragment) {
            declared.insert(startup);
        }
    }
}

/// `target` as `plan` renders it: zsh's and bash's interactive files with
/// `activations` attached, each rendering its own shell's steps, and any
/// other target as it is.
fn with_activations(
    target: Resolution<Target>,
    activations: &activation::Plan,
) -> Resolution<Target> {
    match target {
        Resolution::Ready(mut ready) => {
            match &mut ready.body {
                Body::Generated(Gen::Interactive(file)) => {
                    **file = file
                        .as_ref()
                        .clone()
                        .with_activations(activations.rendered(Shell::Zsh));
                }
                Body::Generated(Gen::Bash(file)) => {
                    **file = file
                        .as_ref()
                        .clone()
                        .with_activations(activations.rendered(Shell::Bash));
                }
                _ => {}
            }
            Resolution::Ready(ready)
        }
        blocked @ Resolution::Blocked(_) => blocked,
    }
}

/// Record `activations` in the fingerprint store, under the exclusive lock.
///
/// The store is read again under the lock rather than reusing the copy
/// `plan` read without one, and [`activation::Plan::record`] touches only
/// the activation entries, so nothing another writer recorded is lost. An
/// unchanged store is not written, so an `apply` that captured nothing
/// leaves `fingerprints.mpk` byte-identical.
///
/// Called only for a configuration that declares an activation, so one that
/// declares none never touches the store; the entries of activations since
/// removed are forgotten by the next `apply` that records any.
fn record_activations(state: &StateDir, activations: &activation::Plan) -> Result<(), Error> {
    state.ensure()?;
    let lock = ExclusiveLock::acquire(state)?;
    let before = Fingerprints::open(state, &lock)?.value;
    let mut after = before.clone();
    activations.record(&mut after);
    if after != before {
        after.save(state, &lock)?;
    }
    Ok(())
}

/// The process status a report implies.
///
/// An executed `apply` has done its pending work, so only a row still needing
/// attention keeps it pending. An `apply` that wrote nothing — declined, or
/// with nothing to do — exits by its actions, so a declined prompt over pending
/// work exits 2.
///
/// # Decision 34: an unsettled state directory exits [`Exit::Pending`] in
/// either mode
///
/// Two states of the state directory settle the exit before the mode or the
/// rows are consulted, and both settle it the same way.
///
/// **A standing interruption.** The rule used to be keyed on the mode:
/// [`Mode::Plan`] over an interruption exited [`Exit::Pending`], and so did an
/// `apply` that *recovered* one, but an `apply` that saw the interruption and
/// was **declined** fell through to the rows — and over a session that wrote
/// everything but did not record it, every row is [`Action::Unchanged`], so it
/// exited [`Exit::Converged`]. `bx plan` and a declined `bx apply` therefore
/// disagreed about whether the same machine was converged, with an unrecovered
/// journal standing in both. Nothing about a decline makes the machine more
/// converged than the `plan` that preceded it, so the mode is not what the
/// answer depends on: while a journal stands, every configured target is
/// undecided, whoever is asking. The recovered case is not a second arm but the
/// same one — an `apply` that recovered stopped there, and the next `apply` is
/// what converges the machine.
///
/// **A running `apply`.** [`Mode::Apply`] never reaches here, having refused in
/// [`run`]. A `plan` does reach it, and its rows were decided against a state
/// directory the running `apply` is concurrently changing: they say what was
/// true at no single instant. Reporting [`Exit::Converged`] from them would let
/// a script move on from a machine it has not seen settled, and it would
/// contradict this run's own banner, which says what the other `apply` has not
/// finished yet is still to do.
#[must_use]
pub fn exit(report: &Report, mode: Mode) -> Exit {
    let actions = report.actions();
    if report.interrupted.is_some() || report.apply_running {
        return Exit::Pending;
    }
    match mode {
        Mode::Apply | Mode::Sync if report.executed => {
            if actions.iter().any(|action| action.needs_attention()) {
                Exit::Pending
            } else {
                Exit::Converged
            }
        }
        // A `sync` that wrote nothing — declined, or refused for want of a
        // terminal — left every carry it announced undone, and carrying is
        // `sync`'s own work, as it is not a bare `apply`'s.
        Mode::Sync if actions.contains(&Action::Sync) => Exit::Pending,
        Mode::Plan | Mode::Apply | Mode::Sync => Exit::from_actions(&actions),
    }
}

/// Refuse anything in the state directory that is neither a regular file nor a
/// directory, before any reader opens it: the first
/// [`StateDir::irregular_file`] finds.
fn refuse_irregular_state_files(state: &StateDir) -> Result<(), Error> {
    match state.irregular_file() {
        Some(path) => Err(Error::NotARegularFile { path }),
        None => Ok(()),
    }
}

/// What a read-only run learns from the state directory before deciding.
///
/// The lock is asked about through [`SharedLock::probe`], which creates,
/// narrows and writes nothing, so `plan` leaves the state directory exactly as
/// it found it — or absent. An `apply` holding the directory is reported as
/// running, and its journal is not an interruption.
fn look_at_state(inputs: &Inputs, report: &mut Report) -> Result<(), Error> {
    if SharedLock::probe(&inputs.state)?.is_held() {
        report.apply_running = true;
        return Ok(());
    }
    report.interrupted = recover::pending(&inputs.state)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
