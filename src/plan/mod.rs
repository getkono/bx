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
mod region;
mod track;

use std::collections::BTreeSet;

pub(crate) use decide::read_repo_file;
#[cfg(test)]
pub use diff::DiffKind;
pub use diff::{Diff, Palette, View, render};
pub use error::Error;
pub use inputs::Inputs;

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
}

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
        // Refused on what `pending` found, before recovery runs at all, so a
        // blocked session rolls nothing back.
        let blocked: Vec<_> = interrupted.blocked().cloned().collect();
        if !blocked.is_empty() {
            return Err(recover::Error::Blocked { conflicts: blocked }.into());
        }
        if approve(&report)? {
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
    };
    // A fragment bx wrote for a place no variable lands in any more is planned
    // empty, so switching a variable off takes it out of every shell.
    let mut targets: Vec<Resolution<Target>> = inputs
        .resolved
        .targets
        .iter()
        .map(|target| with_activations(target.clone(), &report.activations))
        .collect();
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
    // A tracked target's repo copy is written by `sync` alone, after every
    // other write; a bare `apply` announces the row and leaves it.
    let mut ops = decided.ops;
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
    // not moved: every file bx wrote that nothing declares any more.
    report
        .changes
        .extend(undeclared_rows(inputs, &ledger, &targets, &expansion.held));

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
            if ops.is_empty() && clones.is_empty() && expansion.pending.is_empty() && !captured {
                track::agree(inputs, &bases, &agreed, mode, false)?;
                return Ok(report);
            }
            if !approve(&report)? {
                return Ok(report);
            }
            // Every target first, so a clone beneath a directory a target
            // creates is made inside it rather than before it.
            if !ops.is_empty() {
                let scope = ops.iter().map(|op| op.target().clone()).collect();
                let mut session =
                    Session::open(&inputs.state, SessionKind::Apply, &inputs.home, scope)?;
                // Before the first write, so a file staged beneath a declared
                // directory is held to the directory's declared mode.
                for (dir, mode) in &decided.declared {
                    session.declare_dir(dir, *mode);
                }
                let progress = execute::progress(ops.len(), inputs.progress);
                execute::execute(ops, session, &progress)?;
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
            report.executed = true;
            track::agree(inputs, &bases, &agreed, mode, true)?;
            Ok(report)
        }
    }
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
/// after the one the targets were written in.
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
    };
    let decided = decide::decide_all(&targets, &ctx)?;
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
        execute::execute(decided.ops, session, &progress)?;
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
/// The rows are [`decide::decide_undeclared`]'s, which writes nothing, so they
/// produce no op: `apply` leaves the file and its ledger entry as they are,
/// and the next `plan` shows the same row.
fn undeclared_rows(
    inputs: &Inputs,
    ledger: &LedgerView,
    targets: &[Resolution<Target>],
    held: &[Portable],
) -> Vec<Change> {
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
    ledger
        .iter()
        .filter(|(path, _)| !declared.contains(path.as_str()))
        .filter(|(path, _)| !held_beneath(path))
        // Lexical, like every containment verdict bx makes.
        .filter(|(path, _)| {
            !(tracking_held_back && paths::normalize(&path.render(&inputs.home)).starts_with(&repo))
        })
        .map(|(_, entry)| decide::decide_undeclared(entry, &origin, &inputs.home))
        .collect()
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
