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
//! The one environment read in the whole path is [`Env::from_process`], and
//! the `PATH` a declared activation's tool is looked up along, which
//! [`Inputs::load`] takes once through [`activation::System::from_env`]; every
//! other function takes what it needs as an argument.

mod decide;
mod diff;
mod execute;
pub(crate) mod external;
mod region;

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

pub(crate) use decide::read_repo_file;
pub(crate) use diff::escape;
pub use diff::{Diff, DiffKind, Palette, TEXT_LIMIT, View, Why, render};

use crate::config::resolve::{self, Resolution, Resolved};
use crate::config::target::{Body, Gen, Target};
use crate::config::{self, Origin, layers, merge};
use crate::env_guard::RootSet;
use crate::journal::{self, Session, SessionKind};
use crate::paths;
use crate::recover::{self, Interrupted};
use crate::report::{Action, Exit};
use crate::shell::activation;
use crate::state::{
    self, ExclusiveLock, Fingerprints, LedgerView, Mechanism, SharedLock, StateDir,
};
use crate::sync::Git;

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
}

/// Everything bx takes from the process it runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    /// `$HOME`.
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`, which places the config repo.
    pub xdg_config_home: Option<OsString>,
    /// `$XDG_STATE_HOME`, which places the state directory.
    pub xdg_state_home: Option<OsString>,
    /// Whether `$NO_COLOR` is set to something other than the empty string.
    pub no_color: bool,
    /// Whether standard output is a terminal.
    pub stdout_tty: bool,
    /// Whether standard input is a terminal, so a confirmation can be asked.
    pub stdin_tty: bool,
    /// Whether standard error is a terminal, so progress can be drawn.
    pub stderr_tty: bool,
}

impl Env {
    /// Read the environment of this process. The only place in the `plan`
    /// path that does.
    ///
    /// # Errors
    ///
    /// [`Error::Home`] when `$HOME` is unset, empty or relative, and
    /// [`Error::HomeParentComponent`] when it has a `..` component.
    pub fn from_process() -> Result<Self, Error> {
        Ok(Self {
            home: usable_home(paths::home()?)?,
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            no_color: no_color(std::env::var_os("NO_COLOR").as_deref()),
            stdout_tty: std::io::stdout().is_terminal(),
            stdin_tty: std::io::stdin().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
        })
    }
}

/// `home`, refused when it has a `..` component.
///
/// Not normalised: `/a/..` is not `/` when `/a` is a symlink, and every path bx
/// writes is rendered against the home, so a home bx cannot name exactly is
/// refused here, naming `HOME`, rather than by the first target beneath it.
fn usable_home(home: PathBuf) -> Result<PathBuf, Error> {
    if home
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(Error::HomeParentComponent(home));
    }
    Ok(home)
}

/// Whether a `NO_COLOR` value asks for no colour: set, to anything but the
/// empty string.
fn no_color(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

/// What a run decides against, loaded once.
#[derive(Debug, Clone)]
pub struct Inputs {
    home: PathBuf,
    repo: PathBuf,
    state: StateDir,
    /// Every enabled target as the merged layers wrote it, before substitution:
    /// one per entry of `resolved.targets`, in the same order, so a blocked
    /// target's body is still known.
    declared: Vec<Target>,
    resolved: Resolved,
    roots: RootSet,
    progress: bool,
    /// The `git` a declared external is looked at and moved with: the user's
    /// own, seeing the home and config home this run resolved, and unable to
    /// ask anything.
    git: Git,
    /// Every enabled `[[activation]]`, in the merged configuration's order.
    activations: Vec<activation::ActivationDecl>,
    /// The machine an activation's tool is looked up and run on.
    host: activation::System,
}

impl Inputs {
    /// Locate the config repo and the state directory, and load, merge and
    /// resolve the layer set.
    ///
    /// Reads configuration files only; nothing is created.
    ///
    /// # Errors
    ///
    /// [`Error::RepoMissing`] when there is no config repo, and
    /// [`Error::Config`] for anything else the configuration refuses.
    pub fn load(env: &Env) -> Result<Self, Error> {
        let home = env.home.clone();
        let repo = paths::config_root_in(&home, env.xdg_config_home.as_deref());
        let state = StateDir::resolve_in(&home, env.xdg_state_home.as_deref());
        let layers = layers::load_layer_set(&repo, state.root(), &home)?;
        let merged = merge::merge(&layers, &home)?;
        let resolved = resolve::resolve(&merged, &home)?;
        let roots = RootSet::from_values(&resolved.values)
            .owning(&[state.root().to_path_buf()])
            .with_config_repos(std::slice::from_ref(&repo));
        Ok(Self {
            home,
            repo,
            state,
            declared: merged.targets,
            resolved,
            roots,
            progress: env.stderr_tty,
            git: Git::new(env).unattended(),
            activations: merged.activations,
            host: activation::System::from_env(),
        })
    }

    /// The same inputs, looking at externals through `git`.
    #[cfg(test)]
    pub(crate) fn with_git(mut self, git: Git) -> Self {
        self.git = git;
        self
    }

    /// The same inputs, running activations on `host`.
    #[cfg(test)]
    pub(crate) fn with_host(mut self, host: activation::System) -> Self {
        self.host = host;
        self
    }

    /// The resolved configuration.
    #[must_use]
    pub const fn resolved(&self) -> &Resolved {
        &self.resolved
    }

    /// Every enabled target as written, paired with its resolution, in
    /// configuration order.
    pub fn declared_targets(&self) -> impl Iterator<Item = (&Target, &Resolution<Target>)> {
        self.declared.iter().zip(&self.resolved.targets)
    }

    /// The account's home.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The config repo.
    #[must_use]
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// The state directory.
    #[must_use]
    pub const fn state(&self) -> &StateDir {
        &self.state
    }

    /// Every enabled target, ready or held back, in configuration order — the
    /// list `plan` decides, for a read-only command that looks at the same
    /// targets without deciding them.
    #[must_use]
    pub fn targets(&self) -> &[Resolution<Target>] {
        &self.resolved.targets
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

/// Everything that can stop a run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `$HOME` is not usable.
    #[error(transparent)]
    Home(#[from] paths::Error),
    /// `$HOME` climbs out of a directory and back in, so bx cannot name the
    /// home exactly.
    #[error(
        "HOME has a `..` component: {}; bx renders every path against HOME and will not guess \
         which directory it names. Set HOME without `..`",
        .0.display()
    )]
    HomeParentComponent(PathBuf),
    /// There is no config repo.
    #[error("no bx config repo at {}; run `bx init` to create one", .0.display())]
    RepoMissing(PathBuf),
    /// The configuration could not be loaded, merged or resolved.
    #[error(transparent)]
    Config(config::Error),
    /// A target's `file` body could not be read from the config repo.
    #[error("{origin}: reading the body {}: {source}", .path.display())]
    Body {
        /// Where the target was declared.
        origin: Origin,
        /// The file that could not be read.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The state directory failed, including another bx holding it.
    #[error(transparent)]
    State(state::Error),
    /// A state file bx reads is something other than a regular file — a FIFO,
    /// a device, a link — which a read could wait on forever or never finish.
    #[error(
        "{} is not a regular file, so bx will not read it; move it out of the way and run bx \
         again",
        .path.display()
    )]
    NotARegularFile {
        /// The state file.
        path: PathBuf,
    },
    /// An interrupted session could not be inspected or resolved, including a
    /// recovery that is blocked on files it cannot account for.
    #[error(transparent)]
    Recover(recover::Error),
    /// The session refused or failed a write.
    #[error(transparent)]
    Journal(journal::Error),
    /// A destination could not be observed.
    #[error(transparent)]
    Fs(#[from] crate::fs::Error),
    /// `apply` has something to write, was not given `--yes`, and has no
    /// terminal to ask on. The plan has been shown; nothing was written.
    #[error(
        "bx apply writes only what was confirmed, and there is no terminal to ask on; \
         nothing was written. Review the plan above and rerun with --yes"
    )]
    NeedsConfirmation,
    /// The confirmation prompt failed or was interrupted.
    #[error("asking for confirmation: {0}")]
    Prompt(#[source] inquire::InquireError),
    /// The rendering could not be written to its output.
    #[error("writing the plan: {0}")]
    Output(#[source] std::io::Error),
}

impl From<config::Error> for Error {
    fn from(error: config::Error) -> Self {
        match error {
            config::Error::RepoMissing(repo) => Self::RepoMissing(repo),
            other => Self::Config(other),
        }
    }
}

impl From<state::Error> for Error {
    fn from(error: state::Error) -> Self {
        Self::State(error)
    }
}

impl From<journal::Error> for Error {
    fn from(error: journal::Error) -> Self {
        match error {
            journal::Error::State(error) => Self::State(error),
            other => Self::Journal(other),
        }
    }
}

impl From<recover::Error> for Error {
    fn from(error: recover::Error) -> Self {
        match error {
            recover::Error::State(error) => Self::State(error),
            recover::Error::Journal(error) => error.into(),
            other => Self::Recover(other),
        }
    }
}

/// Decide every target, report, and — in [`Mode::Apply`], once `approve` says
/// so — write.
///
/// An interrupted session comes first, in both modes, and is then all a run
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
    if mode == Mode::Apply && report.apply_running {
        return Err(state::Error::Locked {
            holder: state::Holder::of(&inputs.state),
            path: inputs.state.lock(),
        }
        .into());
    }
    if let Some(interrupted) = report.interrupted.clone() {
        report.changes = interrupted_rows(inputs, &interrupted)?;
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
    targets.extend(resolve::vacated_fragments(
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
    let decided = decide::decide_all(&targets, &ctx)?;
    report.changes = decided.changes;
    let ops = decided.ops;
    // Every declared external after every target, in configuration order.
    let (rows, clones) = external::decide_all(
        &inputs.resolved.externals,
        &external::Ctx {
            ledger: &ledger,
            home: &inputs.home,
            git: &inputs.git,
        },
    )?;
    let first_external = report.changes.len();
    report.changes.extend(rows);
    // Last, after every external, so the indices `stopped` is built from are
    // not moved: every file bx wrote that nothing declares any more.
    report
        .changes
        .extend(undeclared_rows(inputs, &ledger, &targets));

    match mode {
        Mode::Plan => Ok(report),
        Mode::Apply => {
            // A capture is work even when the file it renders into is already
            // right — a binary upgraded to one printing the same text — since
            // until it is recorded every `plan` runs the tool again.
            let captured = report
                .activations
                .steps()
                .iter()
                .any(|step| step.action().is_pending());
            if (ops.is_empty() && clones.is_empty() && !captured) || !approve(&report)? {
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
            // Last, so a cache entry is never saved for output a failed write
            // left out of the file: losing it costs only a re-run.
            if !inputs.activations.is_empty() {
                record_activations(&inputs.state, &report.activations)?;
            }
            report.executed = true;
            Ok(report)
        }
    }
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
///
/// The rows are [`decide::decide_undeclared`]'s, which writes nothing, so they
/// produce no op: `apply` leaves the file and its ledger entry as they are,
/// and the next `plan` shows the same row.
fn undeclared_rows(
    inputs: &Inputs,
    ledger: &LedgerView,
    targets: &[Resolution<Target>],
) -> Vec<Change> {
    let blocked = inputs
        .declared_targets()
        .filter(|(_, resolution)| matches!(resolution, Resolution::Blocked(_)))
        .map(|(declared, _)| declared.path.as_str());
    let mut declared: std::collections::BTreeSet<&str> = targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) => Some(target.path.as_str()),
            Resolution::Blocked(_) => None,
        })
        .chain(blocked)
        .chain(
            inputs
                .resolved
                .externals
                .iter()
                .map(|external| external.path.as_str()),
        )
        .collect();
    // A startup file's region sources its fragment, and stays while the
    // fragment is planned — a vacated one included, which is left sourced and
    // empty — so it is declared by the fragment whether or not this run
    // decides it.
    let sourcing = config::env::Place::ALL
        .into_iter()
        .filter_map(|place| Some((place.fragment(), place.startup_file()?)))
        .chain([(crate::shell::bash::FILE, crate::shell::bash::STARTUP_FILE)]);
    for (fragment, startup) in sourcing {
        if declared.contains(fragment) {
            declared.insert(startup);
        }
    }
    let origin = Origin::unknown(&inputs.state.ledger());
    ledger
        .iter()
        .filter(|(path, _)| !declared.contains(path.as_str()))
        .map(|(_, entry)| decide::decide_undeclared(entry, &origin, &inputs.home))
        .collect()
}

/// `target` as `plan` renders it: the interactive file with `activations`
/// attached, and any other target as it is.
fn with_activations(
    target: Resolution<Target>,
    activations: &activation::Plan,
) -> Resolution<Target> {
    match target {
        Resolution::Ready(mut ready) => {
            if let Body::Generated(Gen::Interactive(file)) = &mut ready.body {
                **file = file.as_ref().clone().with_activations(activations.clone());
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
        Mode::Apply if report.executed => {
            if actions.iter().any(|action| action.needs_attention()) {
                Exit::Pending
            } else {
                Exit::Converged
            }
        }
        Mode::Plan | Mode::Apply => Exit::from_actions(&actions),
    }
}

/// Refuse anything in the state directory that is neither a regular file nor a
/// directory, before any reader opens it.
///
/// bx only ever leaves a state file by rename, and a FIFO, a device or a link
/// at one could make a read wait forever or never end: a FIFO blocks the open
/// until a writer that never comes, and a link to `/dev/zero` fills memory
/// without bound. Everything under the state root is bx's own, so nothing there
/// is legitimately either.
///
/// # Decision 33: the scope is the tree, not a list of names
///
/// The check used to name three files — the ledger, the fingerprints and the
/// journal — and its doc claimed that was every state file a run opens. It was
/// not. `bx plan` also reads `<state>/restore/<digest>` through
/// [`interrupted_rows`], with no file-type check anywhere on that path, and a
/// FIFO there hung `bx plan` — the read-only command — forever. The blob was
/// outside the guard by omission and not by judgement: decision 20's rationale
/// covers it word for word, and it is left by rename like the other three.
///
/// A fourth name would have been the same artefact with the same defect
/// waiting. A list of the state files a run reads has to be re-derived by hand
/// every time a reader is added, and nothing fails when it is not: the three
/// tests that exercised it mirrored the same three names, so the suite could
/// not find what the list had missed. So the list is gone. The scope is now
/// **everything under the state root**, walked from the filesystem, which is an
/// over-approximation of what any reader could open and therefore cannot be
/// short of it. A state file added tomorrow is covered on the day it is
/// written, by nobody having done anything.
///
/// Directories are descended into and are not themselves refused; the root is
/// not refused either, so an account that symlinks its whole state directory
/// elsewhere still works. An absent state directory is fine — there is nothing
/// to read — and so is an entry `lstat` cannot see, which the read then reports
/// itself.
///
/// # Decision 38: `<state>/local.toml` is the user's, and is not walked
///
/// The walk's premise — everything under the state root is bx's own and is
/// only ever left by rename — is false for exactly one path: the local layer,
/// `<state>/local.toml`, which the user writes and which the base supports as a
/// symbolic link ([`layers::layer_paths`], `state::dir`'s `check_local_layer`).
/// Refusing it there made `bx`, `bx plan` and `bx apply` exit 1 for every
/// account whose `local.toml` is linked. So that one path is skipped here,
/// neither judged nor descended into, and is left to the judgement that already
/// governs it: [`layers::layer_paths`] follows the link, loads it only when it
/// ends at a regular file, and skips anything else unread, so a FIFO or a link
/// to a device there is never opened. It was judged before this ran, by
/// [`Inputs::load`].
pub(crate) fn refuse_irregular_state_files(state: &StateDir) -> Result<(), Error> {
    fn walk(dir: &Path, local: &Path) -> Result<(), Error> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            // Unreadable or absent: there is nothing bx can enumerate here, and
            // whichever reader wants a file beneath it reports its own failure.
            return Ok(());
        };
        // Sorted, so a directory holding two irregular entries is always
        // refused naming the same one: `read_dir` yields in whatever order the
        // filesystem happens to hold, and an error message that varies between
        // identical runs is not one a test or a user can rely on.
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            if path == local {
                continue;
            }
            // `symlink_metadata`, so a symlink is judged as a symlink rather
            // than as whatever it points at. `entry.file_type()` would do on
            // Linux, but it is documented as possibly needing a stat, and this
            // one must not follow.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                walk(&path, local)?;
            } else if !meta.file_type().is_file() {
                return Err(Error::NotARegularFile { path });
            }
        }
        Ok(())
    }
    walk(state.root(), &layers::local_layer_path(state.root()))
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

/// The rows an interrupted session gives a run: what recovery would do to each
/// write the session announced, in the order it announced them.
///
/// A write in a session that did not finish, and that recovery can resolve on
/// its own, is rolled back. Its row is a modify with the diff from what is on
/// disk to what was there before — every line removed, for a file the session
/// created — and names the directories the session created that recovery
/// removes where empty. A write in a session that finished is only recorded,
/// which touches no file, so its row is unchanged. A write recovery cannot
/// account for is a conflict whose note names abandon.
///
/// The prior bytes a diff shows are read from the journal and its restore
/// snapshot, lockless, as `pending` read them. A snapshot that cannot be read
/// now leaves the row without a diff rather than guessing at one.
fn interrupted_rows(inputs: &Inputs, interrupted: &Interrupted) -> Result<Vec<Change>, Error> {
    let loaded = journal::load(&inputs.state.journal())?;
    let mut rows = Vec::with_capacity(interrupted.unfinished.len());
    for unfinished in &interrupted.unfinished {
        let target = unfinished.target.as_str();
        // The target as written, found by where it resolved to or, when its
        // resolution is blocked, by the path as written. Whether it is a
        // secret is read from the declared body, which a blocked resolution
        // still has.
        let configured = inputs
            .declared_targets()
            .find(|(declared, resolution)| match resolution {
                Resolution::Ready(ready) => ready.path.as_str() == target,
                Resolution::Blocked(_) => declared.path.as_str() == target,
            })
            .map(|(declared, _)| declared);
        let origin = configured.map_or_else(
            || Origin::unknown(&interrupted.journal),
            |declared| declared.origin.clone(),
        );
        // A secret's plaintext is on one side of its roll back, or both, and
        // is never shown here either. A write no declared target claims is
        // concealed too: the journal does not say whether it was a secret, and
        // a secret whose target was removed, whose path was edited, or whose
        // path now resolves elsewhere or waits on a value leaves exactly such
        // a write. Showing a secret's bytes is worse than hiding an ordinary
        // file's.
        let conceal = configured
            .is_none_or(|declared| matches!(declared.body, crate::config::target::Body::Secret(_)));
        let between = if conceal {
            Diff::concealed
        } else {
            Diff::between
        };
        let row = |action, diff, note: String| Change {
            target: target.to_string(),
            origin: origin.clone(),
            action,
            diff,
            note: Some(note),
        };

        if !unfinished.resolvable {
            let note = if unfinished.note.contains("abandon") {
                unfinished.note.clone()
            } else {
                format!(
                    "{}; recovery cannot put it back, so the interrupted session has to be \
                     abandoned",
                    unfinished.note
                )
            };
            rows.push(row(Action::Conflict, None, note));
            continue;
        }
        if interrupted.complete {
            rows.push(row(Action::Unchanged, None, unfinished.note.clone()));
            continue;
        }

        let intent = loaded
            .intents()
            .find(|intent| intent.target == unfinished.target);
        let observed = crate::fs::observe(&unfinished.dest)?;
        let written = unfinished.standing == recover::Standing::Written;
        let dir = intent.is_some_and(|intent| intent.dir);
        let link = intent.is_some_and(|intent| intent.link);
        let (diff, what) = match (written, intent.map(|intent| &intent.before)) {
            // A link's row shows its text on each side, as `plan` shows a
            // symlink target's: the link recovery puts back was stored as
            // its text.
            (true, Some(state::Prior::Existed(reference))) if link => {
                let prior = LedgerView::default()
                    .restore_bytes(&inputs.state, reference)
                    .ok()
                    .map(|bytes| {
                        PathBuf::from(<OsString as std::os::unix::ffi::OsStringExt>::from_vec(
                            bytes,
                        ))
                    });
                (
                    prior.map(|prior| Diff::link(observed.link.as_deref(), Some(&prior))),
                    "rolls back: puts back the link that was there before",
                )
            }
            (true, Some(state::Prior::Absent)) if link => (
                Some(Diff::link(observed.link.as_deref(), None)),
                "rolls back: removes the link the session made",
            ),
            // A directory has no bytes to diff: its row says what recovery
            // does to it, and a mode it puts back is shown as one.
            (true, Some(state::Prior::Existed(reference))) if dir => {
                match (observed.mode, intent.map(|intent| intent.after)) {
                    (Some(found), Some(journal::Written::Present { .. })) => (
                        Some(Diff::mode(found, reference.mode)),
                        "rolls back: puts back the mode it had",
                    ),
                    _ => (
                        None,
                        "rolls back: makes the directory the session removed again",
                    ),
                }
            }
            (true, Some(state::Prior::Absent)) if dir => (
                None,
                "rolls back: removes the directory the session created where empty",
            ),
            (true, Some(state::Prior::Existed(reference))) => {
                let prior = LedgerView::default()
                    .restore_bytes(&inputs.state, reference)
                    .ok();
                let mode = observed
                    .mode
                    .filter(|mode| *mode != reference.mode)
                    .map(|mode| (mode, reference.mode));
                (
                    prior
                        .and_then(|prior| between(target, observed.bytes.as_deref(), &prior, mode)),
                    "rolls back: puts back what was there before",
                )
            }
            (true, Some(state::Prior::Absent)) => (
                between(target, observed.bytes.as_deref(), b"", None),
                "rolls back: removes the file the session created",
            ),
            (true, None) => (None, "rolls back what the session wrote"),
            (false, _) => (None, "rolls back: it already holds what was there before"),
        };
        let dirs: Vec<String> = intent
            .map(|intent| {
                intent
                    .created_dirs
                    .iter()
                    .rev()
                    .filter(|dir| std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()))
                    .map(|dir| paths::to_portable(dir, &inputs.home))
                    .collect()
            })
            .unwrap_or_default();
        let note = if dirs.is_empty() {
            what.to_string()
        } else {
            format!("{what}; removes {} where empty", dirs.join(", "))
        };
        let action = if written || !dirs.is_empty() {
            Action::Modify
        } else {
            Action::Unchanged
        };
        rows.push(row(action, diff, note));
    }
    Ok(rows)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Output};

    use super::*;
    use crate::fs::{self, Mode as FileMode};
    use crate::journal::tests::{crash_phases, finish_crash_phases};
    use crate::journal::{Content, Ownership, Request};
    use crate::paths::Portable;
    use crate::state::{ExclusiveLock, Mechanism};
    use crate::testing::{GuardedHome, guarded_home};

    /// An environment with nothing overridden and no terminal.
    pub(crate) fn env(home: &Path) -> Env {
        Env {
            home: home.to_path_buf(),
            xdg_config_home: None,
            xdg_state_home: None,
            no_color: false,
            stdout_tty: false,
            stdin_tty: false,
            stderr_tty: false,
        }
    }

    /// Write `layer` as the repo's `bx.toml` under `home`.
    pub(crate) fn seed(home: &Path, layer: &str) {
        let repo = home.join(".config/bx");
        std::fs::create_dir_all(&repo).expect("the config repo");
        std::fs::write(repo.join("bx.toml"), layer).expect("bx.toml");
    }

    /// Load the inputs for `home`.
    fn load(home: &Path) -> Inputs {
        Inputs::load(&env(home)).expect("the inputs load")
    }

    /// Write `layer` as the repo's `bx.toml` and load it.
    pub(crate) fn inputs(home: &GuardedHome, layer: &str) -> Inputs {
        seed(home.path(), layer);
        load(home.path())
    }

    /// One inline target, as TOML. `content` is spelled as a TOML basic string.
    pub(crate) fn inline(path: &str, content: &str) -> String {
        format!("[[target]]\npath = \"{path}\"\ncontent = \"{content}\"\n")
    }

    fn plan(inputs: &Inputs) -> Report {
        run(inputs, Mode::Plan, &mut |_| panic!("plan never asks")).expect("plan runs")
    }

    fn apply(inputs: &Inputs) -> Report {
        run(inputs, Mode::Apply, &mut |_| Ok(true)).expect("apply runs")
    }

    /// Write `bytes` at `~/rel` through a journalled session, so bx owns it
    /// the way an `apply` would leave it.
    pub(crate) fn own(home: &Path, rel: &str, bytes: &[u8], mechanism: Mechanism) {
        let state = StateDir::resolve(home);
        let target = Portable::parse_in(&format!("~/{rel}"), home).expect("a portable target");
        let dest = home.join(rel);
        let planned = fs::observe(&dest).expect("observe");
        let mut session = Session::open(&state, SessionKind::Apply, home, vec![target.clone()])
            .expect("a session");
        session
            .apply(Request {
                target,
                dest,
                content: Content::Bytes {
                    bytes: bytes.to_vec(),
                    planned,
                },
                mode: FileMode::DEFAULT_FILE,
                ownership: Ownership::Owned(mechanism),
            })
            .expect("the write");
        session.finish().expect("finish");
    }

    fn text(change: &Change) -> &str {
        match change.diff.as_ref().map(|diff| &diff.kind) {
            Some(DiffKind::Text(text)) => text,
            other => panic!("expected a text diff, found {other:?}"),
        }
    }

    /// One path under a snapshot root: its bytes when it is a file, and its mode.
    type Entry = (PathBuf, Option<Vec<u8>>, u32);

    /// Every path under `root` except those beneath a `skip` prefix, with the
    /// bytes of each regular file and every mode.
    pub(crate) fn snapshot(root: &Path, skip: &[&str]) -> Vec<Entry> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read a directory") {
                let path = entry.expect("an entry").path();
                let rel = path.strip_prefix(root).expect("under root").to_path_buf();
                if skip.iter().any(|prefix| rel.starts_with(prefix)) {
                    continue;
                }
                let meta = std::fs::symlink_metadata(&path).expect("lstat");
                let bytes = meta
                    .is_file()
                    .then(|| std::fs::read(&path).expect("read a file"));
                if meta.is_dir() {
                    stack.push(path);
                }
                found.push((rel, bytes, meta.permissions().mode()));
            }
        }
        found.sort();
        found
    }

    /// What neither a rollback nor a restore puts back: bx's own records, and
    /// the repo.
    const OUTSIDE: [&str; 2] = [".local", ".config/bx"];

    #[test]
    fn t1_an_absent_target_is_a_create_with_the_whole_body_added() {
        let home = guarded_home();
        let inputs = inputs(&home, &inline("~/.a", "one\\ntwo\\n"));

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Create]);
        assert_eq!(report.changes[0].target, "~/.a");
        assert_eq!(
            text(&report.changes[0]),
            "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -0,0 +1,2 @@\n+one\n+two\n"
        );
        assert!(!home.child(".a").exists(), "plan wrote the target");
        assert!(
            !StateDir::resolve(home.path()).root().exists(),
            "plan created the state directory"
        );
        assert_eq!(exit(&report, Mode::Plan), Exit::Pending);
    }

    #[test]
    fn t2_an_owned_file_whose_content_differs_is_a_modify_with_the_exact_diff() {
        let home = guarded_home();
        own(home.path(), ".a", b"one\ntwo\nthree\n", Mechanism::Own);
        let inputs = inputs(&home, &inline("~/.a", "one\\nTWO\\nthree\\n"));

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Modify]);
        assert_eq!(report.changes[0].note, None);
        assert_eq!(
            text(&report.changes[0]),
            "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"
        );

        apply(&inputs);
        assert_eq!(
            std::fs::read(home.child(".a")).expect("the file"),
            b"one\nTWO\nthree\n"
        );
    }

    #[test]
    fn t3_a_present_file_bx_does_not_own_is_a_conflict_apply_does_not_overwrite() {
        let home = guarded_home();
        home.write(".a", "mine\n");
        let inputs = inputs(
            &home,
            &[inline("~/.a", "bx\\n"), inline("~/.b", "b\\n")].concat(),
        );

        let report = plan(&inputs);
        assert_eq!(report.actions(), vec![Action::Conflict, Action::Create]);
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some("exists and bx does not own it")
        );
        assert_eq!(
            text(&report.changes[0]),
            "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -1 +1 @@\n-mine\n+bx\n"
        );

        let applied = apply(&inputs);
        assert!(applied.executed);
        assert_eq!(exit(&applied, Mode::Apply), Exit::Pending);
        assert_eq!(std::fs::read(home.child(".a")).expect("mine"), b"mine\n");
        assert_eq!(std::fs::read(home.child(".b")).expect("created"), b"b\n");
    }

    #[test]
    fn t4_an_owned_file_edited_since_bx_wrote_it_is_a_conflict_not_overwritten() {
        let home = guarded_home();
        own(home.path(), ".a", b"bx\n", Mechanism::Own);
        std::fs::write(home.child(".a"), "edited\n").expect("the edit");
        let inputs = inputs(&home, &inline("~/.a", "new\\n"));

        let report = plan(&inputs);
        assert_eq!(report.actions(), vec![Action::Conflict]);
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some("edited since bx last wrote it")
        );

        let applied = apply(&inputs);
        assert!(!applied.executed, "nothing to write, so no session");
        assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
    }

    #[test]
    fn an_owned_file_already_holding_the_body_is_unchanged() {
        let home = guarded_home();
        own(home.path(), ".a", b"bx\n", Mechanism::Own);
        let inputs = inputs(&home, &inline("~/.a", "bx\\n"));

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Unchanged]);
        assert_eq!(report.changes[0].diff, None);
        assert_eq!(exit(&report, Mode::Plan), Exit::Converged);
    }

    #[test]
    fn a_file_bx_attached_to_another_way_is_a_conflict() {
        let home = guarded_home();
        own(
            home.path(),
            ".a",
            b"old\n",
            Mechanism::Region { comment: '#' },
        );
        let inputs = inputs(&home, &inline("~/.a", "new\\n"));

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Conflict]);
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some("bx attached to this file as a managed region")
        );
    }

    #[test]
    fn t5_a_symlink_a_directory_and_an_unusable_parent_are_conflicts() {
        let home = guarded_home();
        home.write("real", "x\n");
        std::os::unix::fs::symlink(home.child("real"), home.child(".link")).expect("a link");
        std::fs::create_dir(home.child(".dir")).expect("a directory");
        home.write(".file", "not a directory\n");
        let layer = [
            inline("~/.link", "x\\n"),
            inline("~/.dir", "x\\n"),
            inline("~/.file/inner", "x\\n"),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let report = plan(&inputs);

        assert_eq!(
            report.actions(),
            vec![Action::Conflict, Action::Conflict, Action::Conflict]
        );
        for change in &report.changes {
            assert!(change.note.is_some(), "{change:?}");
            assert_eq!(change.diff, None, "{change:?}");
        }
        assert!(
            report.changes[0]
                .note
                .as_deref()
                .is_some_and(|note| note.contains("symlink"))
        );
        assert!(
            report.changes[1]
                .note
                .as_deref()
                .is_some_and(|note| note.contains("directory"))
        );

        assert!(!apply(&inputs).executed);
        assert!(home.child(".dir").is_dir());
    }

    #[test]
    fn decision_9_every_unusable_parent_is_named_by_its_portable_path() {
        let home = guarded_home();
        home.write(".file", "not a directory\n");
        std::os::unix::fs::symlink(home.child("nowhere"), home.child(".dangling"))
            .expect("a dangling link");
        std::os::unix::fs::symlink(home.child(".loop"), home.child(".loop")).expect("a loop");
        let layer = [
            inline("~/.file/inner", "x\\n"),
            inline("~/.file/a/b", "x\\n"),
            inline("~/.dangling/x", "x\\n"),
            inline("~/.loop/x", "x\\n"),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let report = plan(&inputs);

        let notes: Vec<&str> = report
            .changes
            .iter()
            .map(|change| change.note.as_deref().expect("a note"))
            .collect();
        assert_eq!(
            notes[..3],
            [
                "~/.file is not a directory, so bx cannot write a file inside it",
                "~/.file does not resolve to a directory, so bx cannot create ~/.file/a inside it",
                "~/.dangling does not resolve to a directory, so bx cannot create ~/.dangling \
                 inside it",
            ]
        );
        assert!(
            notes[3].starts_with("~/.loop does not resolve to a directory (")
                && notes[3].ends_with("), so bx cannot write a file inside it"),
            "{}",
            notes[3]
        );
        let absolute = home.path().to_string_lossy().into_owned();
        for note in notes {
            assert!(!note.contains(&absolute), "{note}");
        }
        assert_eq!(report.actions(), vec![Action::Conflict; 4]);
    }

    #[test]
    fn t6_an_unset_required_value_blocks_its_target_with_the_init_hint() {
        let home = guarded_home();
        let layer = format!(
            "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\nrequired = true\n\
             is_root = true\n{}",
            inline("~/.env", "X={{scratch_root}}\\n")
        );
        let inputs = inputs(&home, &layer);

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Blocked]);
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some(config::values::init_hint(&["scratch_root"]).as_str())
        );
        assert_eq!(report.changes[0].diff, None);

        assert!(!apply(&inputs).executed);
        assert!(!home.child(".env").exists());
    }

    #[test]
    fn t7_rows_follow_the_configuration_order() {
        let home = guarded_home();
        let layer = [
            inline("~/.c", "c\\n"),
            inline("~/.a", "a\\n"),
            inline("~/.b", "b\\n"),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let report = plan(&inputs);

        let targets: Vec<&str> = report.changes.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(targets, ["~/.c", "~/.a", "~/.b"]);
    }

    #[test]
    fn a_file_body_is_read_from_the_config_repo_verbatim() {
        let home = guarded_home();
        home.write(".config/bx/files/gitconfig", "[user]\n\tname = ~/x\n");
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/gitconfig\"\n",
        );

        let report = plan(&inputs);
        assert_eq!(report.actions(), vec![Action::Create]);
        assert!(text(&report.changes[0]).ends_with("+[user]\n+\tname = ~/x\n"));

        apply(&inputs);
        assert_eq!(
            std::fs::read(home.child(".gitconfig")).expect("written"),
            b"[user]\n\tname = ~/x\n"
        );
    }

    #[test]
    fn a_missing_file_body_is_an_error_naming_its_origin() {
        let home = guarded_home();
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/absent\"\n",
        );

        let error = run(&inputs, Mode::Plan, &mut |_| Ok(false)).expect_err("a missing body");

        assert!(matches!(error, Error::Body { .. }), "{error:?}");
        assert!(error.to_string().contains("bx.toml:1"), "{error}");
    }

    /// A secret target for `~/.token`, its ciphertext at `secrets/token.age`.
    const SECRET_TARGET: &str =
        "[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n";

    /// Encrypt `plaintext` to `recipient` as the repo's `secrets/token.age`.
    fn seal(home: &GuardedHome, recipient: &str, plaintext: &[u8]) {
        let path = home.child(".config/bx/secrets/token.age");
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("secrets/");
        std::fs::write(path, crate::secret::tests::encrypt_to(recipient, plaintext))
            .expect("the ciphertext");
    }

    /// A fresh age identity, written where `local.toml` names it.
    fn age_identity(home: &GuardedHome) -> String {
        let key = age::x25519::Identity::generate();
        home.write(
            ".config/age/key.txt",
            age::secrecy::ExposeSecret::expose_secret(&key.to_string()),
        );
        home.write(
            ".local/state/bx/local.toml",
            "[secrets]\nidentity = \"~/.config/age/key.txt\"\n",
        );
        key.to_public().to_string()
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("the file")
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn d1_a_secret_is_decrypted_into_a_private_file_and_never_shown() {
        let home = guarded_home();
        let recipient = age_identity(&home);
        seal(&home, &recipient, b"hunter2\n");
        let inputs = inputs(&home, SECRET_TARGET);

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Create]);
        let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
        assert!(
            !shown.contains("hunter2"),
            "the plaintext was shown: {shown}"
        );
        assert!(
            shown.contains("secret, not shown: no file -> 8 bytes"),
            "{shown}"
        );

        let applied = apply(&inputs);
        assert!(applied.executed);
        assert_eq!(
            std::fs::read(home.child(".token")).expect("written"),
            b"hunter2\n"
        );
        assert_eq!(mode_of(&home.child(".token")), 0o600);
    }

    #[test]
    fn d1_applying_an_unchanged_secret_twice_writes_nothing_the_second_time() {
        let home = guarded_home();
        let recipient = age_identity(&home);
        seal(&home, &recipient, b"hunter2\n");
        let inputs = inputs(&home, SECRET_TARGET);
        apply(&inputs);

        let after = plan(&inputs);
        assert_eq!(after.actions(), vec![Action::Unchanged]);
        let written = snapshot(home.path(), &[".local/state/bx/lock"]);
        let second = run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve"))
            .expect("the second apply");
        assert!(!second.executed);
        assert_eq!(second.actions(), vec![Action::Unchanged]);
        assert_eq!(snapshot(home.path(), &[".local/state/bx/lock"]), written);

        // A new ciphertext is a modify, and still never shown.
        seal(&home, &recipient, b"hunter3\n");
        let changed = plan(&inputs);
        assert_eq!(changed.actions(), vec![Action::Modify]);
        let shown = render(&changed, View::Plan, Palette::PLAIN, home.path());
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(
            shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    #[test]
    fn d1_a_locked_identity_blocks_its_secret_and_nothing_asks() {
        let home = guarded_home();
        // The default identity, locked: plan and apply may not ask for it.
        home.write(".ssh/id_ed25519", crate::secret::tests::LOCKED_SSH_KEY);
        seal(&home, crate::secret::tests::LOCKED_SSH_PUB, b"x\n");
        let layer = [SECRET_TARGET, &inline("~/.a", "a\\n")].concat();
        let inputs = inputs(&home, &layer);

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Blocked, Action::Create]);
        let note = planned.changes[0].note.as_deref().expect("a note");
        assert!(
            note.contains("~/.ssh/id_ed25519 is locked by a passphrase"),
            "{note}"
        );
        assert!(
            note.contains("`identity` under [secrets] in local.toml"),
            "names the fix"
        );
        assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);

        let applied = apply(&inputs);
        assert!(applied.executed, "the rest of the plan stands");
        assert!(!home.child(".token").exists());
        assert!(home.child(".a").exists());
    }

    #[test]
    fn d1_a_secret_no_identity_opens_is_blocked_naming_why() {
        let home = guarded_home();
        seal(&home, crate::secret::tests::SSH_PUB, b"x\n");
        let inputs = inputs(&home, SECRET_TARGET);

        let none = plan(&inputs);
        assert_eq!(none.actions(), vec![Action::Blocked]);
        assert!(
            none.changes[0]
                .note
                .as_deref()
                .is_some_and(|note| note.contains("no identity at ~/.ssh/id_ed25519")),
            "{:?}",
            none.changes[0].note
        );

        age_identity(&home);
        let inputs = load(home.path());
        let wrong = plan(&inputs);
        assert_eq!(wrong.actions(), vec![Action::Blocked]);
        assert!(
            wrong.changes[0]
                .note
                .as_deref()
                .is_some_and(|note| note.contains("~/.config/age/key.txt is not one")),
            "{:?}",
            wrong.changes[0].note
        );
    }

    #[test]
    fn d1_a_missing_ciphertext_is_an_error_naming_its_origin() {
        let home = guarded_home();
        let inputs = inputs(&home, SECRET_TARGET);

        let error = run(&inputs, Mode::Plan, &mut |_| Ok(false)).expect_err("no ciphertext");
        assert!(matches!(error, Error::Body { .. }), "{error:?}");
        assert!(error.to_string().contains("token.age"), "{error}");
    }

    #[test]
    fn d1_a_secret_over_a_file_bx_does_not_own_is_a_conflict_shown_by_size_only() {
        let home = guarded_home();
        home.write(".token", "mine\n");
        let recipient = age_identity(&home);
        seal(&home, &recipient, b"hunter2\n");
        let inputs = inputs(&home, SECRET_TARGET);

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Conflict]);
        let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
        assert!(
            !shown.contains("mine") && !shown.contains("hunter2"),
            "{shown}"
        );
        assert!(
            shown.contains("secret, not shown: 5 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    #[test]
    fn a_missing_config_repo_says_to_run_bx_init() {
        let home = guarded_home();

        let error = Inputs::load(&env(home.path())).expect_err("no repo");

        assert!(matches!(error, Error::RepoMissing(_)), "{error:?}");
        assert!(error.to_string().contains("run `bx init`"), "{error}");
    }

    #[test]
    fn a_malformed_layer_is_a_config_error_not_a_missing_repo() {
        // P42R1-COV3. Only a missing repo becomes `RepoMissing`; everything
        // else the configuration refuses stays the configuration's error.
        let home = guarded_home();
        seed(home.path(), "[[target]\npath = \n");

        let error = Inputs::load(&env(home.path())).expect_err("a malformed layer");

        assert!(matches!(error, Error::Config(_)), "{error:?}");
        assert!(!error.to_string().contains("run `bx init`"), "{error}");
    }

    #[test]
    fn the_inputs_name_the_places_they_were_loaded_from() {
        let home = guarded_home();
        let inputs = inputs(&home, "");

        assert_eq!(inputs.home(), home.path());
        assert_eq!(inputs.repo(), home.child(".config/bx"));
        assert_eq!(inputs.state(), &StateDir::resolve(home.path()));
        assert!(!inputs.progress);
    }

    #[test]
    fn a_repo_the_environment_moved_is_the_repo_a_generated_fragment_may_not_name() {
        // The env guard's r3 round gave `RootSet` the config repo, derived
        // from the home unless a caller that read `XDG_CONFIG_HOME` names it.
        // The whole home is a declared root, so only the repo refuses it.
        let home = guarded_home();
        let xdg = home.child("cfg");
        let repo = xdg.join("bx");
        std::fs::create_dir_all(&repo).expect("the moved repo");
        std::fs::write(
            repo.join("bx.toml"),
            "[[value]]\nname = \"all\"\nkind = \"path\"\nis_root = true\ndefault = \"~\"\n",
        )
        .expect("bx.toml");
        let inputs = Inputs::load(&Env {
            xdg_config_home: Some(xdg.into_os_string()),
            ..env(home.path())
        })
        .expect("the inputs load");
        assert_eq!(inputs.repo(), repo);

        let fragment = format!("CARGO_HOME={}\n", repo.join("cargo").display());
        let note = decide::guard_fragment(&fragment, &inputs.roots).expect("refused");
        let inside = crate::env_guard::Reason::InsideConfigRepo.to_string();
        assert!(note.contains(&inside), "{note}");
    }

    #[test]
    fn decision_21_a_home_with_a_parent_component_is_refused_and_any_other_is_kept() {
        let climbing = "/var/home/../home/u";
        let refused = usable_home(PathBuf::from(climbing)).expect_err("a `..` home");
        assert!(
            matches!(&refused, Error::HomeParentComponent(path) if path == Path::new(climbing)),
            "{refused:?}"
        );
        assert!(
            refused
                .to_string()
                .starts_with("HOME has a `..` component: /var/home/../home/u;"),
            "{refused}"
        );

        // Kept exactly as spelled: bx does not normalise a home.
        for kept in ["/var/home/u", "/var/home/u/", "/var//home/./u"] {
            assert_eq!(
                usable_home(PathBuf::from(kept)).expect("kept"),
                PathBuf::from(kept)
            );
        }
    }

    #[test]
    fn no_color_is_asked_for_by_any_value_but_the_empty_string() {
        assert!(!no_color(None));
        assert!(!no_color(Some(OsStr::new(""))));
        assert!(no_color(Some(OsStr::new("1"))));
        assert!(no_color(Some(OsStr::new("0"))));
    }

    #[test]
    fn the_process_environment_is_read_as_it_is() {
        let env = Env::from_process();
        match std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            Some(home) if Path::new(&home).is_absolute() => {
                let env = env.expect("a usable HOME");
                assert_eq!(env.home, PathBuf::from(home));
                assert_eq!(env.xdg_state_home, std::env::var_os("XDG_STATE_HOME"));
                assert_eq!(env.xdg_config_home, std::env::var_os("XDG_CONFIG_HOME"));
                assert_eq!(
                    env.no_color,
                    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
                );
            }
            _ => assert!(matches!(env, Err(Error::Home(_)))),
        }
    }

    #[test]
    fn state_errors_are_one_variant_wherever_they_come_from() {
        let failure = || state::Error::NotADirectory {
            path: PathBuf::from("/x"),
        };
        assert!(matches!(Error::from(failure()), Error::State(_)));
        assert!(matches!(
            Error::from(recover::Error::State(failure())),
            Error::State(_)
        ));
        assert!(matches!(
            Error::from(journal::Error::State(failure())),
            Error::State(_)
        ));
        assert!(matches!(
            Error::from(recover::Error::Journal(journal::Error::State(failure()))),
            Error::State(_)
        ));
        assert!(matches!(
            Error::from(recover::Error::Journal(journal::Error::InProgress {
                path: PathBuf::from("/j")
            })),
            Error::Journal(_)
        ));
        assert!(matches!(
            Error::from(recover::Error::Blocked { conflicts: vec![] }),
            Error::Recover(_)
        ));
    }

    #[test]
    fn t9_apply_twice_converges_and_changes_nothing_the_second_time() {
        let home = guarded_home();
        own(home.path(), ".owned", b"v1\n", Mechanism::Own);
        let layer = [
            inline("~/.config/new/deep.conf", "deep\\n"),
            inline("~/.owned", "v2\\n"),
            "[[target]]\npath = \"~/.private\"\ncontent = \"secret\\n\"\nmode = \"0600\"\n"
                .to_string(),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let first = apply(&inputs);
        assert!(first.executed);
        assert_eq!(
            first.actions(),
            vec![Action::Create, Action::Modify, Action::Create]
        );
        assert_eq!(exit(&first, Mode::Apply), Exit::Converged);

        let after = plan(&inputs);
        assert_eq!(after.actions(), vec![Action::Unchanged; 3]);
        assert_eq!(exit(&after, Mode::Plan), Exit::Converged);

        let written = snapshot(home.path(), &[]);
        let second = run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve"))
            .expect("the second apply");
        assert!(!second.executed);
        assert_eq!(exit(&second, Mode::Apply), Exit::Converged);
        assert_eq!(
            snapshot(home.path(), &[".local/state/bx/lock"]),
            written
                .into_iter()
                .filter(|(path, _, _)| !path.starts_with(".local/state/bx/lock"))
                .collect::<Vec<_>>()
        );
        assert!(!StateDir::resolve(home.path()).journal().exists());
        assert_eq!(
            std::fs::metadata(home.child(".private"))
                .expect("private")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn t10_apply_announces_exactly_what_plan_announced_and_plan_changes_nothing() {
        let guard = guarded_home();
        let layer = [
            inline("~/.owned", "v2\\n"),
            inline("~/.new", "new\\n"),
            inline("~/.mine", "bx\\n"),
        ]
        .concat();
        let seeded = |name: &str| {
            let home = guard.child(name);
            std::fs::create_dir_all(&home).expect("a home");
            own(&home, ".owned", b"v1\n", Mechanism::Own);
            std::fs::write(home.join(".mine"), "mine\n").expect("mine");
            seed(&home, &layer);
            home
        };
        let planned_home = seeded("plan");
        let applied_home = seeded("apply");

        let before = snapshot(&planned_home, &[]);
        let planned = plan(&load(&planned_home));
        assert_eq!(
            snapshot(&planned_home, &[]),
            before,
            "plan changed the tree"
        );

        let mut shown = None;
        let applied = run(&load(&applied_home), Mode::Apply, &mut |report| {
            shown = Some(report.clone());
            Ok(true)
        })
        .expect("apply");
        let rows = |report: &Report| {
            report
                .changes
                .iter()
                .map(|c| (c.target.clone(), c.action, c.diff.clone(), c.note.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(rows(&applied), rows(&planned));
        assert_eq!(rows(&shown.expect("apply asked")), rows(&planned));
    }

    #[test]
    fn t11_a_mode_only_drift_is_a_journalled_modify_that_converges() {
        let home = guarded_home();
        own(home.path(), ".a", b"same\n", Mechanism::Own);
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.a\"\ncontent = \"same\\n\"\nmode = \"0600\"\n",
        );

        let report = plan(&inputs);
        assert_eq!(report.actions(), vec![Action::Modify]);
        // The comparison's own note leads; a parent wider than 0600 — the
        // tempdir home — adds its own after it.
        assert!(
            report.changes[0]
                .note
                .as_deref()
                .is_some_and(|note| note.starts_with("mode 0644 -> 0600")),
            "{:?}",
            report.changes[0].note
        );
        assert_eq!(
            report.changes[0].diff,
            Some(Diff {
                kind: DiffKind::Mode {
                    from: FileMode::DEFAULT_FILE,
                    to: FileMode::PRIVATE_FILE
                }
            })
        );

        assert!(apply(&inputs).executed);
        let meta = std::fs::metadata(home.child(".a")).expect("the file");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert_eq!(std::fs::read(home.child(".a")).expect("bytes"), b"same\n");
        assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
    }

    #[test]
    fn decision_22_a_mode_the_user_changed_on_a_file_bx_owns_is_a_conflict() {
        // P42R1-D7. A user's chmod narrowing a file bx owns was re-widened:
        // ownership compared the digest only.
        let home = guarded_home();
        own(home.path(), ".a", b"token\n", Mechanism::Own);
        std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
            .expect("the user's chmod");
        let inputs = inputs(&home, &inline("~/.a", "token\\n"));

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Conflict]);
        assert!(
            report.changes[0]
                .note
                .as_deref()
                .is_some_and(|note| note.starts_with("its mode changed since bx wrote it")),
            "{:?}",
            report.changes[0].note
        );
        let applied = apply(&inputs);
        assert!(!applied.executed, "nothing is written over the user's mode");
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("the file")
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode(&home.child(".a")), 0o600);

        // Declaring the mode the user chose is converged, not a conflict.
        let declared = inputs_for_mode(&home, "0600");
        assert_eq!(plan(&declared).actions(), vec![Action::Unchanged]);
    }

    /// `~/.a` holding `token\n` at the declared `mode`.
    fn inputs_for_mode(home: &GuardedHome, mode: &str) -> Inputs {
        inputs(
            home,
            &format!("[[target]]\npath = \"~/.a\"\ncontent = \"token\\n\"\nmode = \"{mode}\"\n"),
        )
    }

    #[test]
    fn decision_23_a_create_names_every_directory_apply_creates_with_its_mode() {
        // P42R1-D8. `apply` creates a target's missing parents, and no row
        // said so, so plan did not announce every write apply made.
        let home = guarded_home();
        let inputs = inputs(
            &home,
            &[
                inline("~/.config/made/deep/new.conf", "x\\n"),
                inline("~/.b", "b\\n"),
            ]
            .concat(),
        );

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Create, Action::Create]);
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some("creates ~/.config/made 0755, ~/.config/made/deep 0755")
        );
        assert_eq!(report.changes[1].note, None, "the home is already there");
        assert!(
            !home.child(".config/made").exists(),
            "plan created a parent"
        );

        assert!(apply(&inputs).executed);
        for dir in [".config/made", ".config/made/deep"] {
            let meta = std::fs::symlink_metadata(home.child(dir)).expect("created");
            assert!(meta.is_dir(), "{dir}");
            assert_eq!(meta.permissions().mode() & 0o7777, 0o755, "{dir}");
        }
    }

    #[test]
    fn t12_everything_apply_writes_is_reversed_exactly_by_restore() {
        let home = guarded_home();
        home.write("mine.txt", "user\n");
        let layer = [
            inline("~/.config/deep/er/new.conf", "new\\n"),
            inline("~/.b", "b\\n"),
            inline("~/.owned", "v2\\n"),
        ]
        .concat();
        seed(home.path(), &layer);
        let before = snapshot(home.path(), &OUTSIDE);
        own(home.path(), ".owned", b"v1\n", Mechanism::Own);
        let inputs = load(home.path());

        let applied = apply(&inputs);
        assert_eq!(
            applied.actions(),
            vec![Action::Create, Action::Create, Action::Modify]
        );
        assert_ne!(snapshot(home.path(), &OUTSIDE), before);

        let state = StateDir::resolve(home.path());
        let targets: Vec<Portable> = LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value
            .iter()
            .map(|(target, _)| target.clone())
            .collect();
        assert_eq!(targets.len(), 3);
        crate::restore::restore(&state, home.path(), &targets).expect("restore");

        assert_eq!(snapshot(home.path(), &OUTSIDE), before);
    }

    /// A stub tool at `~/bin/stub` that appends a line to `~/runs` each time
    /// it runs and prints a one-line activation, and the machine that finds
    /// it: `~/bin` is its whole `PATH`.
    fn stub_tool(home: &GuardedHome) -> activation::System {
        let bin = home.child("bin");
        std::fs::create_dir_all(&bin).expect("~/bin");
        let stub = bin.join("stub");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\necho ran >> '{}'\nprintf 'stub_hook() {{ :; }}\\n'\n",
                home.child("runs").display()
            ),
        )
        .expect("the stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        activation::System::new(bin.into_os_string(), activation::TIMEOUT)
    }

    /// How many times the stub tool has run.
    fn stub_runs(home: &GuardedHome) -> usize {
        std::fs::read_to_string(home.child("runs")).map_or(0, |runs| runs.lines().count())
    }

    const STUB: &str = "[[activation]]\nname = \"stub\"\ncommand = [\"stub\", \"init\", \"zsh\"]\n\
                        phase = \"completions\"\n";

    const INTERACTIVE: &str = ".local/share/bx/zshrc.zsh";

    #[test]
    fn a_declared_activation_is_run_once_cached_rendered_and_reversed() {
        let home = guarded_home();
        home.write(".zshrc", "user\n");
        seed(home.path(), STUB);
        let inputs = load(home.path()).with_host(stub_tool(&home));
        let state = StateDir::resolve(home.path());

        // `plan` runs it twice, shows the capture, and writes nothing.
        let planned = plan(&inputs);
        assert_eq!(stub_runs(&home), 2);
        assert_eq!(
            planned.actions(),
            vec![Action::Create, Action::Modify, Action::Create]
        );
        assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);
        let shown = render(
            &planned,
            View::Plan,
            Palette::resolve(true, false),
            home.path(),
        );
        assert!(
            shown.contains("  + activation `stub`: run twice, output agreed; cached\n"),
            "{shown}"
        );
        assert!(!state.fingerprints().exists());

        // `apply` renders the output into the interactive file and records it.
        let applied = apply(&inputs);
        assert!(applied.executed);
        assert_eq!(stub_runs(&home), 4, "one plan inside the apply, not two");
        assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
        let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
        assert!(
            file.contains(
                "\n# bx phase: completions\n# bx activation: stub\neval 'stub_hook() { :; }\n'\n"
            ),
            "{file}"
        );
        let cache = std::fs::read(state.fingerprints()).expect("the cache is saved");

        // On an unchanged machine nothing runs and nothing is written.
        let again = plan(&inputs);
        assert_eq!(stub_runs(&home), 4);
        assert_eq!(again.actions(), vec![Action::Unchanged; 3]);
        assert_eq!(exit(&again, Mode::Plan), Exit::Converged);
        let quiet = render(
            &again,
            View::Plan,
            Palette::resolve(true, false),
            home.path(),
        );
        assert!(!quiet.contains("activation"), "{quiet}");
        let status = render(
            &again,
            View::Status,
            Palette::resolve(true, false),
            home.path(),
        );
        assert!(
            status.contains("  = activation `stub`: cached output reused, nothing run\n"),
            "{status}"
        );
        let second = run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve"))
            .expect("the second apply");
        assert!(!second.executed);
        assert_eq!(stub_runs(&home), 4);
        assert_eq!(
            std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
            file
        );
        assert_eq!(
            std::fs::read(state.fingerprints()).expect("the cache"),
            cache
        );

        // Losing the cache costs a re-run, and nothing else: the file is
        // already right, and the cache comes back byte for byte.
        std::fs::remove_file(state.fingerprints()).expect("lose the cache");
        let lost = apply(&inputs);
        assert!(lost.executed);
        assert_eq!(
            lost.actions(),
            vec![Action::Unchanged, Action::Unchanged, Action::Create]
        );
        assert_eq!(stub_runs(&home), 6);
        assert_eq!(
            std::fs::read(state.fingerprints()).expect("the cache"),
            cache
        );
        assert_eq!(
            std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
            file
        );

        // `rm` puts back exactly what was there before.
        let targets: Vec<Portable> = LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value
            .iter()
            .map(|(target, _)| target.clone())
            .collect();
        crate::restore::restore(&state, home.path(), &targets).expect("restore");
        assert_eq!(
            std::fs::read_to_string(home.child(".zshrc")).expect(".zshrc"),
            "user\n"
        );
        assert!(!home.child(INTERACTIVE).exists());
    }

    #[test]
    fn a_capture_under_another_path_renders_the_same_file() {
        // D1: a tool that prints the PATH it ran with, as `mise activate`
        // does. Re-captured under a different PATH, the file does not change.
        let home = guarded_home();
        let bin = home.child("bin");
        std::fs::create_dir_all(&bin).expect("~/bin");
        let stub = bin.join("stub");
        std::fs::write(
            &stub,
            "#!/bin/sh\nprintf \"export PATH='/opt/stub/bin:%s'\\n\" \"$PATH\"\n",
        )
        .expect("the stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        seed(home.path(), STUB);
        let state = StateDir::resolve(home.path());
        let under = |path: String| {
            load(home.path()).with_host(activation::System::new(path, activation::TIMEOUT))
        };

        let applied = apply(&under(bin.display().to_string()));
        assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
        let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
        assert!(
            file.contains("eval 'export PATH='\\''/opt/stub/bin:'\\''\"$PATH\"\n'\n"),
            "{file}"
        );

        std::fs::remove_file(state.fingerprints()).expect("lose the cache");
        let elsewhere = under(format!("{}:/nonexistent", bin.display()));
        let planned = plan(&elsewhere);
        assert_eq!(
            planned.actions(),
            vec![Action::Unchanged, Action::Unchanged, Action::Create]
        );
        apply(&elsewhere);
        assert_eq!(
            std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
            file
        );
    }

    #[test]
    fn an_absent_tool_is_blocked_and_everything_else_is_still_written() {
        let home = guarded_home();
        seed(
            home.path(),
            &format!("{STUB}[[activation]]\nname = \"gone\"\ncommand = [\"gone\"]\n"),
        );
        let inputs = load(home.path()).with_host(stub_tool(&home));

        let planned = plan(&inputs);
        assert_eq!(
            planned.actions(),
            vec![
                Action::Create,
                Action::Create,
                Action::Create,
                Action::Blocked
            ]
        );
        let shown = render(
            &planned,
            View::Plan,
            Palette::resolve(true, false),
            home.path(),
        );
        assert!(
            shown.contains("  ? activation `gone`: omitted: `gone` is not on PATH\n"),
            "{shown}"
        );

        let applied = apply(&inputs);
        assert!(applied.executed);
        assert_eq!(exit(&applied, Mode::Apply), Exit::Pending);
        let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
        assert!(file.contains("# bx activation: stub\n"), "{file}");
        assert!(!file.contains("gone"), "{file}");
    }

    /// One symlink target, as TOML.
    fn symlink(path: &str, text: &str) -> String {
        format!("[[target]]\npath = \"{path}\"\nsymlink = \"{text}\"\n")
    }

    /// The two sides of a row's link diff.
    fn link(change: &Change) -> (Option<&str>, Option<&str>) {
        match change.diff.as_ref().map(|diff| &diff.kind) {
            Some(DiffKind::Link { from, to }) => (from.as_deref(), to.as_deref()),
            other => panic!("expected a link diff, found {other:?}"),
        }
    }

    /// The text of the link at `path`.
    fn text_of(path: &Path) -> PathBuf {
        std::fs::read_link(path).expect("a link")
    }

    #[test]
    fn a_symlink_and_an_empty_file_are_delivered_and_a_second_plan_is_empty() {
        let home = guarded_home();
        let layer = [
            symlink("~/.local/bin/tool", "../../src/tool/bin/tool"),
            symlink("~/.toolrc", "~/dotfiles/toolrc"),
            "[[target]]\npath = \"~/.hushlogin\"\ncontent = \"\"\nmode = \"0600\"\n".to_string(),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Create; 3]);
        assert_eq!(
            link(&planned.changes[0]),
            (None, Some("../../src/tool/bin/tool"))
        );
        let rendered = format!("{}/dotfiles/toolrc", home.path().display());
        assert_eq!(
            link(&planned.changes[1]),
            (None, Some(rendered.as_str())),
            "a leading `~` is the one thing rendered"
        );
        let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
        assert!(
            shown.contains("\n    + symlink ../../src/tool/bin/tool\n"),
            "{shown}"
        );

        let applied = apply(&inputs);
        assert!(applied.executed);
        assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
        let tool = home.child(".local/bin/tool");
        assert_eq!(text_of(&tool), Path::new("../../src/tool/bin/tool"));
        assert!(!tool.exists(), "made dangling, and never followed");
        assert_eq!(text_of(&home.child(".toolrc")), Path::new(&rendered));
        let empty = std::fs::symlink_metadata(home.child(".hushlogin")).expect("a file");
        assert!(empty.is_file());
        assert_eq!(empty.len(), 0, "an empty body is a zero-byte file");
        assert_eq!(empty.permissions().mode() & 0o7777, 0o600);

        let after = plan(&inputs);
        assert_eq!(after.actions(), vec![Action::Unchanged; 3]);
        assert_eq!(exit(&after, Mode::Plan), Exit::Converged);
        let written = snapshot(home.path(), &[".local/state/bx/lock"]);
        let second = run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve"))
            .expect("the second apply");
        assert!(!second.executed);
        assert_eq!(snapshot(home.path(), &[".local/state/bx/lock"]), written);
        assert_eq!(text_of(&tool), Path::new("../../src/tool/bin/tool"));
    }

    #[test]
    fn a_link_bx_made_is_retargeted_showing_the_old_and_new_text() {
        let home = guarded_home();
        apply(&inputs(&home, &symlink("~/.tool", "/opt/one")));
        let inputs = inputs(&home, &symlink("~/.tool", "/opt/two"));

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Modify]);
        assert_eq!(
            link(&planned.changes[0]),
            (Some("/opt/one"), Some("/opt/two"))
        );
        let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
        assert!(
            shown.contains("\n    - symlink /opt/one\n    + symlink /opt/two\n"),
            "{shown}"
        );

        apply(&inputs);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/two"));
        assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
    }

    #[test]
    fn a_path_bx_did_not_link_is_never_replaced_and_a_link_already_right_is_adopted() {
        let home = guarded_home();
        std::os::unix::fs::symlink("elsewhere", home.child(".a")).expect("the user's link");
        std::os::unix::fs::symlink("/opt/b", home.child(".b")).expect("the user's link");
        home.write(".c", "mine\n");
        std::fs::create_dir(home.child(".d")).expect("a directory");
        let layer = [
            symlink("~/.a", "/opt/a"),
            symlink("~/.b", "/opt/b"),
            symlink("~/.c", "/opt/c"),
            symlink("~/.d", "/opt/d"),
            symlink("~/.c/inner", "/opt/inner"),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let planned = plan(&inputs);
        assert_eq!(
            planned.actions(),
            vec![
                Action::Conflict,
                Action::Unchanged,
                Action::Conflict,
                Action::Conflict,
                Action::Conflict,
            ]
        );
        assert!(
            planned.changes[4]
                .note
                .as_deref()
                .is_some_and(|note| note.starts_with("~/.c ")),
            "an unusable parent is named portably: {:?}",
            planned.changes[4].note
        );
        let note = |at: usize| planned.changes[at].note.clone().unwrap_or_default();
        assert!(note(0).contains("a symlink bx did not make"), "{}", note(0));
        assert_eq!(
            link(&planned.changes[0]),
            (Some("elsewhere"), Some("/opt/a"))
        );
        assert!(note(2).contains("a regular file"), "{}", note(2));
        assert!(note(3).contains("a directory"), "{}", note(3));
        assert_eq!(planned.changes[2].diff, None);

        let applied = apply(&inputs);
        assert!(!applied.executed, "nothing to write");
        assert_eq!(text_of(&home.child(".a")), Path::new("elsewhere"));
        assert_eq!(std::fs::read(home.child(".c")).expect("kept"), b"mine\n");
        assert!(home.child(".d").is_dir());
        let ledger = LedgerView::read(inputs.state(), home.path())
            .expect("the ledger")
            .value;
        assert!(ledger.is_empty(), "an adopted link is recorded by no write");
    }

    #[test]
    fn link_text_that_differs_only_by_normalisation_is_different_text() {
        // `Path` equality would call each pair equal; the link text is compared
        // byte for byte, as it is stored exactly as written.
        let pairs = [
            ("/opt/x", "/opt/x/"),
            ("/opt/x/", "/opt/x"),
            ("a//b", "a/b"),
            ("a/./b", "a/b"),
        ];
        for (made, declared) in pairs {
            // A link bx made is retargeted to the declared text.
            let home = guarded_home();
            apply(&inputs(&home, &symlink("~/.tool", made)));
            let retarget = inputs(&home, &symlink("~/.tool", declared));
            let planned = plan(&retarget);
            assert_eq!(
                planned.actions(),
                vec![Action::Modify],
                "{made} -> {declared}"
            );
            assert_eq!(link(&planned.changes[0]), (Some(made), Some(declared)));
            apply(&retarget);
            assert_eq!(
                text_of(&home.child(".tool")).as_os_str(),
                std::ffi::OsStr::new(declared)
            );
            assert_eq!(plan(&retarget).actions(), vec![Action::Unchanged]);

            // A user's link with that text is theirs, not adopted.
            let home = guarded_home();
            std::os::unix::fs::symlink(made, home.child(".tool")).expect("the user's link");
            let theirs = inputs(&home, &symlink("~/.tool", declared));
            assert_eq!(
                plan(&theirs).actions(),
                vec![Action::Conflict],
                "{made} -> {declared}"
            );
            assert!(!apply(&theirs).executed);
            let os = std::fs::read_link(home.child(".tool")).expect("a link");
            assert_eq!(os.as_os_str(), std::ffi::OsStr::new(made));
        }
    }

    #[test]
    fn a_link_retargeted_since_bx_made_it_and_a_path_bx_owns_otherwise_are_conflicts() {
        let home = guarded_home();
        apply(&inputs(&home, &symlink("~/.tool", "/opt/one")));
        std::fs::remove_file(home.child(".tool")).expect("unlink");
        std::os::unix::fs::symlink("/opt/theirs", home.child(".tool")).expect("retarget");
        own(home.path(), ".f", b"bx\n", Mechanism::Own);
        std::fs::remove_file(home.child(".f")).expect("the user removes it");
        let inputs = inputs(
            &home,
            &[symlink("~/.tool", "/opt/two"), symlink("~/.f", "/opt/f")].concat(),
        );

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Conflict; 2]);
        assert_eq!(
            planned.changes[0].note.as_deref(),
            Some("retargeted since bx made it")
        );
        assert_eq!(
            planned.changes[1].note.as_deref(),
            Some("bx attached to this path as the whole file")
        );
        assert!(!apply(&inputs).executed);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/theirs"));
    }

    #[test]
    fn an_interrupted_link_is_shown_as_the_link_recovery_puts_back() {
        let home = guarded_home();
        apply(&inputs(&home, &symlink("~/.tool", "/opt/one")));
        let inputs = inputs(
            &home,
            &[
                symlink("~/.tool", "/opt/two"),
                symlink("~/.new", "/opt/new"),
            ]
            .concat(),
        );
        let mut session = Session::open(inputs.state(), SessionKind::Apply, home.path(), vec![])
            .expect("a session");
        session
            .apply(crate::journal::tests::link_to(
                home.path(),
                ".tool",
                "/opt/two",
            ))
            .expect("retarget");
        session
            .apply(crate::journal::tests::link_to(
                home.path(),
                ".new",
                "/opt/new",
            ))
            .expect("create");
        drop(session);

        let report = plan(&inputs);
        let row = |target: &str| {
            report
                .changes
                .iter()
                .find(|change| change.target == target)
                .expect("a row")
        };
        assert_eq!(row("~/.tool").action, Action::Modify);
        assert_eq!(link(row("~/.tool")), (Some("/opt/two"), Some("/opt/one")));
        assert_eq!(
            row("~/.tool").note.as_deref(),
            Some("rolls back: puts back the link that was there before")
        );
        assert_eq!(link(row("~/.new")), (Some("/opt/new"), None));
        assert_eq!(
            row("~/.new").note.as_deref(),
            Some("rolls back: removes the link the session made")
        );

        apply(&inputs);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/one"));
        assert!(std::fs::symlink_metadata(home.child(".new")).is_err());
        apply(&inputs);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/two"));
        assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged; 2]);
    }

    /// The home the crash child applies in. Passed per command.
    const CRASH_HOME: &str = "BX_PLAN_CRASH_HOME";

    /// Two writes: a create under a directory bx must invent, then a modify of
    /// a file bx owns.
    fn seed_crash(home: &Path) {
        std::fs::create_dir_all(home).expect("the crash home");
        own(home, ".owned", b"before\n", Mechanism::Own);
        seed(
            home,
            &[
                inline("~/.config/made/new.conf", "made\\n"),
                inline("~/.owned", "after\\n"),
            ]
            .concat(),
        );
    }

    /// How many writes [`seed_crash`]'s apply makes.
    const CRASH_WRITES: usize = 2;

    /// Re-run this test binary as an apply that aborts at `phase` of write
    /// `index`.
    fn spawn_crash_child(home: &Path, index: usize, phase: &str) -> Output {
        Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "plan::tests::apply_crash_child",
            ])
            .env("BX_CRASH_AT", format!("{index}:{phase}"))
            .env(CRASH_HOME, home)
            // The child aborts, so it writes no profile; removing the pattern
            // keeps that independent of how coverage is configured.
            .env_remove("LLVM_PROFILE_FILE")
            .output()
            .expect("spawn the crash child")
    }

    #[test]
    #[ignore = "spawned by the crash harness; it aborts on purpose"]
    fn apply_crash_child() {
        let Some(home) = std::env::var_os(CRASH_HOME) else {
            return;
        };
        let inputs = load(Path::new(&home));
        run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("the apply");
    }

    #[test]
    fn t13_an_apply_killed_at_any_journal_phase_recovers_to_the_clean_apply() {
        let guard = guarded_home();
        let clean = guard.child("clean");
        seed_crash(&clean);
        assert!(apply(&load(&clean)).executed);
        let want = snapshot(&clean, &OUTSIDE);

        let boundaries = (0..CRASH_WRITES)
            .flat_map(|index| crash_phases().map(move |phase| (index, phase)))
            .chain(finish_crash_phases().map(|phase| (CRASH_WRITES, phase)));
        let mut crossed = 0;
        for (index, phase) in boundaries {
            let at = format!("{index}:{phase}");
            let home = guard.child(format!("crash-{index}-{phase}"));
            seed_crash(&home);
            let output = spawn_crash_child(&home, index, phase);
            assert!(
                !output.status.success(),
                "{at}: the child did not stop: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let inputs = load(&home);
            let found = plan(&inputs);
            assert!(
                found.interrupted.is_some(),
                "{at}: no interruption reported"
            );
            assert_eq!(exit(&found, Mode::Plan), Exit::Pending, "{at}");

            // Decision 18: the first apply only recovers, and stops there.
            let recovering =
                run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("the recovering apply");
            assert!(
                recovering.recovered.is_some(),
                "{at}: nothing was recovered"
            );
            assert!(
                !recovering.executed,
                "{at}: the recovering apply also applied"
            );
            assert_eq!(exit(&recovering, Mode::Apply), Exit::Pending, "{at}");
            // The next apply decides against the recovered disk.
            run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("the apply after recovery");
            // The journal's one recorded exception, which its own crash harness
            // pins: a crash between `stage` and the Intent naming the staged
            // file orphans that one `.bx-` temporary, and recovery removes only
            // what the journal names. Nothing else may differ.
            let (orphans, rest): (Vec<Entry>, Vec<Entry>) = snapshot(&home, &OUTSIDE)
                .into_iter()
                .partition(|(path, _, _)| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(fs::TEMP_PREFIX))
                });
            let orphan_possible = matches!(phase, "after-stage" | "after-fill");
            assert!(
                orphans.len() <= usize::from(orphan_possible),
                "{at}: {orphans:?}"
            );
            assert_eq!(rest, want, "{at}");

            let after = plan(&inputs);
            assert_eq!(after.interrupted, None, "{at}");
            assert_eq!(after.actions(), vec![Action::Unchanged; 2], "{at}");
            assert!(!StateDir::resolve(&home).journal().exists(), "{at}");
            crossed += 1;
        }
        assert_eq!(crossed, CRASH_WRITES * 6 + 2);
    }

    #[test]
    fn decision_34_a_declined_apply_over_a_finished_session_reports_pending_like_plan() {
        // P42R2-D4, end to end, alongside decision_18's A2. A session whose
        // writes all landed but whose ledger save did not: the journal is
        // sealed with an End frame, so `pending` reports it complete and every
        // row is Unchanged — recording a write touches no file.
        //
        // At 5d1bba7 `bx plan` exited 2 and a DECLINED `bx apply` over the same
        // state exited 0, with the journal still standing: answering "no" on a
        // terminal reported the machine converged, and a driver keying on exit
        // 0 moved on.
        let guard = guarded_home();
        let home = guard.child("home");
        seed_crash(&home);
        let after_end = finish_crash_phases()[0];
        assert!(
            !spawn_crash_child(&home, CRASH_WRITES, after_end)
                .status
                .success()
        );
        let inputs = load(&home);

        let planned = plan(&inputs);
        let interrupted = planned.interrupted.as_ref().expect("an interruption");
        assert!(
            interrupted.complete,
            "the fixture is not a finished session"
        );
        assert_eq!(planned.actions(), vec![Action::Unchanged; CRASH_WRITES]);
        assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);

        let mut asked = 0;
        let declined = run(&inputs, Mode::Apply, &mut |_| {
            asked += 1;
            Ok(false)
        })
        .expect("a declined apply");

        assert_eq!(asked, 1, "the decline was never offered");
        assert!(!declined.executed);
        assert!(
            declined.recovered.is_none(),
            "a decline recovered something"
        );
        assert_eq!(declined.actions(), vec![Action::Unchanged; CRASH_WRITES]);
        assert!(
            StateDir::resolve(&home).journal().exists(),
            "the journal went on a declined apply"
        );
        assert_eq!(
            exit(&declined, Mode::Apply),
            Exit::Pending,
            "a declined apply reported converged over a standing journal"
        );
        assert_eq!(exit(&declined, Mode::Apply), exit(&planned, Mode::Plan));
    }

    #[test]
    fn decision_35_a_finished_sessions_rows_are_shown_in_the_plan_view() {
        // P42R2-CL3. `command::apply_with` renders its approval prompt with
        // View::Plan, which hides Unchanged rows — and over a finished session
        // every row IS Unchanged, so the user was asked to confirm a recovery
        // that named none of the files it was about to record.
        let guard = guarded_home();
        let home = guard.child("home");
        seed_crash(&home);
        assert!(
            !spawn_crash_child(&home, CRASH_WRITES, finish_crash_phases()[0])
                .status
                .success()
        );
        let loaded = load(&home);
        let report = plan(&loaded);
        assert_eq!(report.actions(), vec![Action::Unchanged; CRASH_WRITES]);

        let shown = render(&report, View::Plan, Palette::PLAIN, &home);

        for change in &report.changes {
            assert!(
                shown.contains(&change.target),
                "the approval prompt does not name {}: {shown}",
                change.target
            );
        }

        // The rule the exception is carved out of still holds: with no
        // interruption standing, an unchanged configured target stays hidden.
        let settled_home = guarded_home();
        let settled = inputs(&settled_home, &inline("~/.settled", "x\\n"));
        assert!(apply(&settled).executed);
        let converged = plan(&settled);
        assert_eq!(converged.interrupted, None);
        assert_eq!(converged.actions(), vec![Action::Unchanged]);
        assert!(
            !render(&converged, View::Plan, Palette::PLAIN, settled_home.path())
                .contains("~/.settled"),
            "an unchanged target is shown with no interruption standing"
        );
    }

    #[test]
    fn t14_a_standing_interruption_is_reported_as_its_roll_back_and_plan_writes_nothing() {
        // Decision 18 reverses this test's earlier expectation, that every
        // interrupted write is a conflict. A write recovery resolves on its own
        // is announced as the roll back `apply` makes, with its diff, and no
        // configured target is decided against the disk before it.
        let guard = guarded_home();
        let home = guard.child("home");
        seed_crash(&home);
        assert!(
            !spawn_crash_child(&home, 1, "after-publish")
                .status
                .success()
        );
        let before = snapshot(&home, &[]);

        let report = plan(&load(&home));

        let interrupted = report.interrupted.as_ref().expect("an interruption");
        assert_eq!(interrupted.unfinished.len(), CRASH_WRITES);
        assert_eq!(
            report.changes.len(),
            CRASH_WRITES,
            "a configured target was decided: {:?}",
            report.changes
        );
        for unfinished in &interrupted.unfinished {
            let change = report
                .changes
                .iter()
                .find(|change| change.target == unfinished.target.as_str())
                .expect("a row for every unfinished write");
            assert_eq!(change.action, Action::Modify, "{change:?}");
            assert!(
                change
                    .note
                    .as_deref()
                    .is_some_and(|note| note.starts_with("rolls back")),
                "{change:?}"
            );
            assert!(change.diff.is_some(), "{change:?}");
            // Each row keeps the origin of the target it rolls back.
            let line = if change.target == "~/.owned" { 4 } else { 1 };
            assert_eq!(change.origin.line, line, "{change:?}");
        }
        assert_eq!(exit(&report, Mode::Plan), Exit::Pending);
        assert_eq!(snapshot(&home, &[]), before, "plan changed the tree");

        // A target the configuration no longer names is still reported.
        seed(&home, "");
        let report = plan(&load(&home));
        assert_eq!(report.actions(), vec![Action::Modify; CRASH_WRITES]);
        assert_eq!(report.changes[0].origin.line, 0);
    }

    #[test]
    fn decision_14_an_unreadable_restore_snapshot_is_named_by_its_portable_path() {
        let home = guarded_home();
        home.write(".conf", "old\n");
        let inputs = inputs(&home, &inline("~/.conf", "new\\n"));
        // An apply that dies once its write is published: the journal stands
        // over "new\n", and rolling it back needs the snapshot of "old\n".
        let target = Portable::parse_in("~/.conf", home.path()).expect("a portable target");
        let dest = home.child(".conf");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"new\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::DEFAULT_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let digest = crate::state::ContentHash::of(b"old\n");
        let blob = inputs.state().restore().join(digest.to_hex());
        let portable = PathBuf::from(format!("~/.local/state/bx/restore/{}", digest.to_hex()));
        let absolute = home.path().to_string_lossy().into_owned();
        let corrupt = || std::fs::write(&blob, "not what it claims to be").expect("corrupt it");
        let remove = || std::fs::remove_file(&blob).expect("remove it");
        let cases: [(&dyn Fn(), state::Error); 2] = [
            (
                &corrupt,
                state::Error::RestoreCorrupt {
                    digest,
                    path: portable.clone(),
                },
            ),
            (
                &remove,
                state::Error::RestoreMissing {
                    digest,
                    path: portable,
                },
            ),
        ];
        for (damage, want) in cases {
            damage();

            let report = plan(&inputs);

            assert_eq!(report.actions(), vec![Action::Conflict]);
            let note = report.changes[0].note.as_deref().expect("a note");
            // Decision 18 adds that the session has to be abandoned.
            assert!(note.starts_with(&want.to_string()), "{note}");
            assert!(note.contains("abandon"), "{note}");
            let shown = diff::render(
                &report,
                View::Plan,
                Palette::resolve(true, false),
                home.path(),
            );
            assert!(shown.contains(note), "{shown}");
            assert!(!shown.contains(&absolute), "{shown}");

            // Decision 18: apply refuses on what `pending` found, before any
            // recovery runs, so it names the snapshot as plan does and writes
            // nothing.
            let error = run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect_err("blocked");
            assert!(
                matches!(error, Error::Recover(recover::Error::Blocked { .. })),
                "{error:?}"
            );
            assert!(error.to_string().contains(&want.to_string()), "{error}");
            assert_eq!(std::fs::read(&dest).expect("untouched"), b"new\n");
            assert!(inputs.state().journal().exists(), "the journal went");

            // Recovery's own error keeps the absolute path.
            let recovery = match recover::recover(inputs.state()).expect("recover") {
                recover::Outcome::Blocked { conflicts } => recover::Error::Blocked { conflicts },
                outcome => panic!("recovered: {outcome:?}"),
            };
            assert!(
                recovery.to_string().contains(&blob.display().to_string()),
                "{recovery}"
            );
            assert_eq!(std::fs::read(&dest).expect("untouched"), b"new\n");
        }
    }

    /// Make `path` a FIFO. Opening it to read waits for a writer that never
    /// comes, which is what any read of it that is not refused first does.
    fn fifo_at(path: &Path) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("the FIFO's directory");
        }
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
            0,
        )
        .expect("mkfifo");
    }

    /// The text of the error `run` in `mode` stops with, run on a thread so a
    /// read that waits fails the test instead of hanging it.
    fn refusal(inputs: &Inputs, mode: Mode) -> String {
        let (sent, received) = std::sync::mpsc::channel();
        let inputs = inputs.clone();
        std::thread::spawn(move || {
            let outcome = run(&inputs, mode, &mut |_| Ok(true))
                .map(|report| report.actions())
                .map_err(|error| error.to_string());
            let _ = sent.send(outcome);
        });
        match received.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(Err(message)) => message,
            Ok(Ok(actions)) => panic!("{mode:?} ran to completion: {actions:?}"),
            Err(_) => panic!("{mode:?} had not returned after 20 s: a read is waiting"),
        }
    }

    /// A FIFO where `file` names a state file: both modes stop at once with an
    /// error naming it, and nothing is written.
    fn a_fifo_state_file_is_refused(file: fn(&StateDir) -> PathBuf) {
        let home = guarded_home();
        let inputs = inputs(&home, &inline("~/.a", "a\\n"));
        let path = file(inputs.state());
        fifo_at(&path);

        for mode in [Mode::Plan, Mode::Apply] {
            let message = refusal(&inputs, mode);
            assert!(
                message.contains(&path.display().to_string()),
                "{mode:?}: {message}"
            );
            assert!(
                message.contains("not a regular file"),
                "{mode:?}: {message}"
            );
        }
        assert!(
            !home.child(".a").exists(),
            "written past a refused state file"
        );
    }

    #[test]
    fn decision_20_a_fifo_at_the_ledger_is_refused_without_waiting() {
        a_fifo_state_file_is_refused(StateDir::ledger);
    }

    #[test]
    fn decision_20_a_fifo_at_the_fingerprints_is_refused_without_waiting() {
        a_fifo_state_file_is_refused(StateDir::fingerprints);
    }

    #[test]
    fn decision_20_a_fifo_at_the_journal_is_refused_without_waiting() {
        a_fifo_state_file_is_refused(StateDir::journal);
    }

    /// Stage an apply that died once its write was published: the journal
    /// stands over `new\n`, and rolling it back needs the restore snapshot of
    /// `old\n`. This is the state in which `bx plan` reads a fourth state file.
    fn a_standing_write_over(home: &GuardedHome) -> Inputs {
        home.write(".conf", "old\n");
        let inputs = inputs(home, &inline("~/.conf", "new\\n"));
        let target = Portable::parse_in("~/.conf", home.path()).expect("a portable target");
        let dest = home.child(".conf");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"new\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::DEFAULT_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);
        inputs
    }

    #[test]
    fn decision_33_a_fifo_at_the_restore_snapshot_is_refused_without_waiting() {
        // P42R2-D3 and P42R2-COV3, the named case. `bx plan` reads
        // <state>/restore/<digest> through `interrupted_rows` ->
        // LedgerView::restore_bytes, which is a bare std::fs::read. The guard
        // named three state files and not this one, so at 5d1bba7 this test
        // does not merely fail: `run` never returns, and `refusal`'s deadline
        // is what turns the hang into a failure.
        let home = guarded_home();
        let inputs = a_standing_write_over(&home);
        let blob = inputs
            .state()
            .restore()
            .join(crate::state::ContentHash::of(b"old\n").to_hex());
        std::fs::remove_file(&blob).expect("the snapshot goes");
        fifo_at(&blob);

        for mode in [Mode::Plan, Mode::Apply] {
            let message = refusal(&inputs, mode);
            assert!(
                message.contains(&blob.display().to_string()),
                "{mode:?}: {message}"
            );
            assert!(
                message.contains("not a regular file"),
                "{mode:?}: {message}"
            );
        }
        assert_eq!(
            std::fs::read(home.child(".conf")).expect("untouched"),
            b"new\n",
            "a refused state file was written past"
        );
    }

    /// Every path under `state`, deepest first, as the filesystem holds them.
    ///
    /// Re-derived from disk on every run rather than written down: the point of
    /// [`refuse_irregular_state_files`] after decision 33 is that its scope is
    /// whatever is there, so a test that named the files would be the very
    /// artefact the decision removed.
    fn every_state_path(state: &StateDir) -> Vec<PathBuf> {
        fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            paths.sort();
            for path in paths {
                if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                    walk(&path, found);
                } else {
                    found.push(path);
                }
            }
        }
        let mut found = Vec::new();
        walk(state.root(), &mut found);
        found
    }

    #[test]
    fn decision_33_a_fifo_at_any_file_under_the_state_directory_is_refused_without_waiting() {
        // P42R2-D3 and P42R2-COV3. The guard used to name three files — the
        // ledger, the fingerprints and the journal — and the three tests that
        // exercised it mirrored that same list, so neither could find what the
        // list had missed: `bx plan` also reads <state>/restore/<digest>
        // through `interrupted_rows`, with no file-type check on that path, and
        // a FIFO there made `bx plan` — the read-only command — wait forever.
        //
        // This asks it of every file the state directory actually holds,
        // enumerated from disk at the head it runs against. A reader added
        // later brings its file with it and is covered the day it is written;
        // nobody has to remember to extend a list.
        let home = guarded_home();
        let inputs = a_standing_write_over(&home);

        let paths = every_state_path(inputs.state());
        let blob_dir = inputs.state().restore();
        assert!(
            paths.iter().any(|path| path.parent() == Some(&*blob_dir)),
            "the fixture holds no restore snapshot, so the case that hung is untested: {paths:?}"
        );
        assert!(
            paths.contains(&inputs.state().journal()),
            "the fixture holds no journal: {paths:?}"
        );

        for path in paths {
            let kept = std::fs::read(&path).expect("the file's bytes");
            std::fs::remove_file(&path).expect("make way for the FIFO");
            fifo_at(&path);

            // `refusal` runs on a thread with a deadline, so a read that waits
            // fails the test instead of hanging it.
            let message = refusal(&inputs, Mode::Plan);
            assert!(
                message.contains(&path.display().to_string()),
                "{}: {message}",
                path.display()
            );
            assert!(
                message.contains("not a regular file"),
                "{}: {message}",
                path.display()
            );

            std::fs::remove_file(&path).expect("the FIFO goes");
            std::fs::write(&path, kept).expect("the file comes back");
        }

        // With every file back as it was, the same run reports the
        // interruption rather than a refusal: the sweep left nothing behind.
        assert!(plan(&inputs).interrupted.is_some());
    }

    #[test]
    fn decision_20_a_link_to_a_device_at_the_ledger_is_refused_before_any_read() {
        // Asked of the guard itself, not of `run`: were the guard ever to let
        // it through, the ledger's reader would read `/dev/zero` into memory
        // until the host ran out. The FIFO tests show `run` asks the guard
        // before anything is read.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).expect("the state directory");
        std::os::unix::fs::symlink("/dev/zero", state.ledger()).expect("the link");

        let error = refuse_irregular_state_files(&state).expect_err("a link is refused");

        assert!(
            matches!(&error, Error::NotARegularFile { path } if *path == state.ledger()),
            "{error:?}"
        );
        assert!(error.to_string().contains("not a regular file"), "{error}");

        // Absent state files, and regular ones, are read as before.
        let other = guarded_home();
        let fresh = StateDir::resolve(other.path());
        assert!(refuse_irregular_state_files(&fresh).is_ok());
        std::fs::create_dir_all(fresh.root()).expect("the state directory");
        std::fs::write(fresh.ledger(), b"a ledger's bytes").expect("a regular ledger");
        assert!(refuse_irregular_state_files(&fresh).is_ok());
    }

    #[test]
    fn decision_38_a_linked_local_toml_is_the_users_layer_and_plan_and_apply_run() {
        // The walk refused every link under the state root, and the local
        // layer is the one file there the user writes and may link, so any
        // account with a linked `local.toml` could not run `bx` at all.
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let state = StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).expect("the state directory");
        std::fs::set_permissions(state.root(), std::fs::Permissions::from_mode(0o700))
            .expect("a private state directory");
        let real = home.write("dotfiles/local.toml", "[values]\n");
        let local = layers::local_layer_path(state.root());
        std::os::unix::fs::symlink(&real, &local).expect("the link");
        let inputs = load(home.path());

        assert!(refuse_irregular_state_files(inputs.state()).is_ok());
        assert_eq!(plan(&inputs).actions(), [Action::Create]);
        assert_eq!(apply(&inputs).actions(), [Action::Create]);
        assert_eq!(plan(&inputs).actions(), [Action::Unchanged]);
        assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");
        assert!(
            std::fs::symlink_metadata(&local).is_ok_and(|meta| meta.file_type().is_symlink()),
            "the user's link is left as it was"
        );

        // Only that one name is exempt: a link anywhere else under the state
        // root is still refused.
        std::os::unix::fs::symlink(&real, state.ledger().with_file_name("other.toml"))
            .expect("a second link");
        assert!(matches!(
            refuse_irregular_state_files(inputs.state()),
            Err(Error::NotARegularFile { .. })
        ));
    }

    #[test]
    fn decision_20_a_fifo_as_a_file_body_is_refused_without_waiting() {
        let home = guarded_home();
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.b\"\nfile = \"files/body\"\n",
        );
        let body = home.child(".config/bx/files/body");
        fifo_at(&body);

        for mode in [Mode::Plan, Mode::Apply] {
            let message = refusal(&inputs, mode);
            assert!(
                message.contains(&body.display().to_string()),
                "{mode:?}: {message}"
            );
            assert!(
                message.contains("not a regular file"),
                "{mode:?}: {message}"
            );
        }
        assert!(!home.child(".b").exists(), "written from a refused body");
    }

    #[test]
    fn an_interrupted_mode_only_write_is_rolled_back_to_the_mode_it_had() {
        // The mutation run found the roll back row's mode change unpinned.
        let home = guarded_home();
        own(home.path(), ".m", b"same\n", Mechanism::Own);
        let inputs = inputs(&home, &inline("~/.m", "same\\n"));
        let target = Portable::parse_in("~/.m", home.path()).expect("a portable target");
        let dest = home.child(".m");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"same\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::PRIVATE_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Modify]);
        assert_eq!(
            report.changes[0].diff,
            Some(Diff {
                kind: DiffKind::Mode {
                    from: FileMode::PRIVATE_FILE,
                    to: FileMode::DEFAULT_FILE
                }
            })
        );
    }

    #[test]
    fn d1_an_interrupted_secret_write_is_rolled_back_without_showing_either_side() {
        let home = guarded_home();
        let recipient = age_identity(&home);
        seal(&home, &recipient, b"hunter3\n");
        own(home.path(), ".token", b"hunter2\n", Mechanism::Own);
        std::fs::set_permissions(home.child(".token"), std::fs::Permissions::from_mode(0o600))
            .expect("private");
        let inputs = inputs(&home, SECRET_TARGET);
        let target = Portable::parse_in("~/.token", home.path()).expect("a portable target");
        let dest = home.child(".token");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"hunter3\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::PRIVATE_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let report = plan(&inputs);
        assert_eq!(report.actions(), vec![Action::Modify]);
        let shown = render(&report, View::Plan, Palette::PLAIN, home.path());
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(
            shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    /// Leave an interrupted write of `hunter3` over `~/.token`'s `hunter2`,
    /// then plan `layer` and render the plan.
    fn render_an_interrupted_token_write(layer: &str) -> String {
        let home = guarded_home();
        age_identity(&home);
        own(home.path(), ".token", b"hunter2\n", Mechanism::Own);
        let inputs = inputs(&home, layer);
        let target = Portable::parse_in("~/.token", home.path()).expect("a portable target");
        let dest = home.child(".token");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"hunter3\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::PRIVATE_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let report = plan(&inputs);
        render(&report, View::Plan, Palette::PLAIN, home.path())
    }

    const WHO: &str = "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n";

    #[test]
    fn d1_an_interrupted_write_of_a_blocked_secret_is_rolled_back_without_showing_it() {
        // The secret's body waits on an unanswered value, so its resolution is
        // blocked; the declared body still says it is a secret.
        let layer = format!(
            "{WHO}[[target]]\npath = \"~/.token\"\nsecret = \"secrets/{{{{who}}}}.age\"\n\
             mode = \"0600\"\n"
        );
        let shown = render_an_interrupted_token_write(&layer);
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(
            shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    #[test]
    fn d1_a_blocked_secret_path_conceals_a_write_no_target_claims() {
        // The secret's path waits on the value, so the write cannot be matched
        // to it; it is concealed rather than risk printing the secret.
        let layer = format!(
            "{WHO}[[target]]\npath = \"~/.{{{{who}}}}\"\nsecret = \"secrets/token.age\"\n\
             mode = \"0600\"\n"
        );
        let shown = render_an_interrupted_token_write(&layer);
        assert!(!shown.contains("hunter"), "{shown}");
    }

    #[test]
    fn d1_an_interrupted_secret_write_whose_path_was_edited_is_concealed() {
        // The secret now lives at `~/.other`, so no declared target claims the
        // write it left at `~/.token`, and nothing is blocked.
        let shown = render_an_interrupted_token_write(
            "[[target]]\npath = \"~/.other\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n",
        );
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(
            shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    #[test]
    fn d1_an_interrupted_secret_write_whose_path_resolves_elsewhere_is_concealed() {
        // `{{who}}` is answered, by its default, with something else than the
        // write was made under, so the ready target claims another path.
        let shown = render_an_interrupted_token_write(
            "[[value]]\nname = \"who\"\nkind = \"string\"\ndefault = \"other\"\n\
             [[target]]\npath = \"~/.{{who}}\"\nsecret = \"secrets/token.age\"\n\
             mode = \"0600\"\n",
        );
        assert!(!shown.contains("hunter"), "{shown}");
    }

    #[test]
    fn an_interrupted_write_no_target_claims_is_concealed_and_a_claimed_file_is_shown() {
        // The journal does not say whether an unclaimed write was a secret.
        let shown = render_an_interrupted_token_write(WHO);
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(shown.contains("secret, not shown"), "{shown}");

        // An ordinary target that claims the write still shows its diff.
        let shown = render_an_interrupted_token_write(
            "[[target]]\npath = \"~/.token\"\ncontent = \"hunter3\\n\"\n",
        );
        assert!(shown.contains("hunter"), "{shown}");
    }

    #[test]
    fn an_interrupted_write_already_put_back_names_only_what_recovery_still_removes() {
        // The mutation run found unpinned whether such a row is a modify or
        // unchanged: only the directories the session created are left to do.
        let guard = guarded_home();
        let home = guard.child("home");
        seed_crash(&home);
        assert!(
            !spawn_crash_child(&home, 1, "after-publish")
                .status
                .success()
        );
        std::fs::remove_file(home.join(".config/made/new.conf")).expect("put back the create");
        std::fs::write(home.join(".owned"), "before\n").expect("put back the modify");

        let report = plan(&load(&home));

        let row = |target: &str| {
            report
                .changes
                .iter()
                .find(|change| change.target == target)
                .unwrap_or_else(|| panic!("no row for {target}: {report:?}"))
        };
        let made = row("~/.config/made/new.conf");
        assert_eq!(made.action, Action::Modify, "{made:?}");
        assert_eq!(
            made.note.as_deref(),
            Some(
                "rolls back: it already holds what was there before; removes ~/.config/made \
                 where empty"
            )
        );
        let owned = row("~/.owned");
        assert_eq!(owned.action, Action::Unchanged, "{owned:?}");
        assert_eq!(
            owned.note.as_deref(),
            Some("rolls back: it already holds what was there before")
        );
    }

    #[test]
    fn t15_apply_refuses_a_held_state_directory_and_plan_reports_it_running() {
        let home = guarded_home();
        let inputs = inputs(&home, &inline("~/.a", "x\\n"));
        let held = ExclusiveLock::acquire(inputs.state()).expect("the lock");

        // P42R2-D5. The refusal comes before anything else the run would do.
        // It used to come from `Session::open`, at the end: every target was
        // decided against a state directory the running apply was concurrently
        // changing, the whole plan was rendered, and the user was asked to
        // confirm work this run was never going to be allowed to do.
        let mut asked = 0;
        let error = run(&inputs, Mode::Apply, &mut |_| {
            asked += 1;
            Ok(true)
        })
        .expect_err("locked");
        assert!(
            matches!(error, Error::State(state::Error::Locked { .. })),
            "{error:?}"
        );
        assert_eq!(asked, 0, "apply prompted before refusing the held lock");

        let report = plan(&inputs);
        assert!(report.apply_running);
        assert_eq!(report.interrupted, None);
        assert_eq!(report.actions(), vec![Action::Create]);
        assert!(!home.child(".a").exists());

        drop(held);
        let report = plan(&inputs);
        assert!(
            !report.apply_running,
            "a released lock is not a running apply"
        );
    }

    #[test]
    fn a_declined_apply_writes_nothing_and_opens_no_session() {
        let home = guarded_home();
        let inputs = inputs(&home, &inline("~/.a", "x\\n"));
        let mut asked = 0;

        let report = run(&inputs, Mode::Apply, &mut |report| {
            asked += 1;
            assert_eq!(report.actions(), vec![Action::Create]);
            Ok(false)
        })
        .expect("a declined apply");

        assert_eq!(asked, 1);
        assert!(!report.executed);
        assert_eq!(exit(&report, Mode::Apply), Exit::Pending);
        assert!(!home.child(".a").exists());
        assert!(!StateDir::resolve(home.path()).journal().exists());
    }

    #[test]
    fn an_approval_that_fails_stops_the_run() {
        let home = guarded_home();
        let inputs = inputs(&home, &inline("~/.a", "x\\n"));

        let error = run(&inputs, Mode::Apply, &mut |_| {
            Err(Error::RepoMissing(PathBuf::from("/refused")))
        })
        .expect_err("the approval's error");

        assert!(matches!(error, Error::RepoMissing(_)), "{error:?}");
        assert!(!home.child(".a").exists());
    }

    #[test]
    fn a_destination_changed_after_it_was_decided_is_not_replaced_and_is_rolled_back() {
        let home = guarded_home();
        let inputs = inputs(
            &home,
            &[inline("~/.b", "b\\n"), inline("~/.a", "bx\\n")].concat(),
        );
        let target = home.child(".a");

        let error = run(&inputs, Mode::Apply, &mut |_| {
            std::fs::write(&target, "raced\n").expect("the race");
            Ok(true)
        })
        .expect_err("the changed destination");

        assert!(
            matches!(
                error,
                Error::Journal(journal::Error::Write(crate::fs::Error::Changed { .. }))
            ),
            "{error:?}"
        );
        assert_eq!(std::fs::read(&target).expect("kept"), b"raced\n");
        assert!(StateDir::resolve(home.path()).journal().exists());

        // The next writing run only rolls the first write back (decision 18),
        // and the one after it decides.
        let recovering = apply(&inputs);
        assert!(recovering.recovered.is_some(), "{recovering:?}");
        assert!(!recovering.executed);
        assert!(!StateDir::resolve(home.path()).journal().exists());
        let next = apply(&inputs);
        assert_eq!(next.actions(), vec![Action::Create, Action::Conflict]);
    }

    fn report_of(actions: &[Action]) -> Report {
        Report {
            changes: actions
                .iter()
                .map(|&action| Change {
                    target: "~/.a".to_string(),
                    origin: Origin::unknown(Path::new("/repo/bx.toml")),
                    action,
                    diff: None,
                    note: None,
                })
                .collect(),
            ..Report::default()
        }
    }

    #[test]
    fn t20_exit_follows_the_mode_and_whether_apply_wrote() {
        use Action::{Blocked, Conflict, Create, Unchanged};

        assert_eq!(exit(&report_of(&[]), Mode::Plan), Exit::Converged);
        assert_eq!(exit(&report_of(&[Unchanged]), Mode::Plan), Exit::Converged);
        assert_eq!(exit(&report_of(&[Create]), Mode::Plan), Exit::Pending);

        // P42R2-D4 and P42R2-COV2. The table used to ask the interrupted report
        // under Mode::Plan only, and the unasked Mode::Apply cell was the wrong
        // one: a declined apply over a session that wrote everything but did
        // not record it has nothing but Unchanged rows, so it fell through to
        // them and reported the machine converged with the journal standing.
        // Decision 34 makes the answer mode-independent, so both cells are
        // asked, and `complete` — which is what makes every row Unchanged — is
        // varied rather than fixed.
        for complete in [false, true] {
            let mut interrupted = report_of(&[Unchanged]);
            interrupted.interrupted = Some(Interrupted {
                kind: SessionKind::Apply,
                journal: PathBuf::from("/state/journal"),
                complete,
                unreadable: !complete,
                unfinished: Vec::new(),
            });
            assert_eq!(exit(&interrupted, Mode::Plan), Exit::Pending, "{complete}");
            assert_eq!(exit(&interrupted, Mode::Apply), Exit::Pending, "{complete}");

            // An apply that recovered stopped there: the configured targets are
            // still undecided, so it is the same answer and not a second arm.
            let mut recovered = interrupted.clone();
            recovered.recovered = Some(recover::Outcome::Recorded { entries: 1 });
            assert_eq!(exit(&recovered, Mode::Apply), Exit::Pending, "{complete}");
        }

        // P42R2-D5. A run against another apply's held state directory decided
        // its rows against a directory that apply is concurrently changing.
        // Mode::Apply never reaches here — `run` refuses first — and a plan
        // that does must not contradict its own banner by reporting converged.
        let mut running = report_of(&[Unchanged]);
        running.apply_running = true;
        assert_eq!(exit(&running, Mode::Plan), Exit::Pending);

        let mut executed = report_of(&[Create, Unchanged]);
        executed.executed = true;
        assert_eq!(exit(&executed, Mode::Apply), Exit::Converged);
        let mut attention = report_of(&[Create, Blocked]);
        attention.executed = true;
        assert_eq!(exit(&attention, Mode::Apply), Exit::Pending);
        let mut conflict = report_of(&[Conflict]);
        conflict.executed = true;
        assert_eq!(exit(&conflict, Mode::Apply), Exit::Pending);

        assert_eq!(exit(&report_of(&[Create]), Mode::Apply), Exit::Pending);
        assert_eq!(exit(&report_of(&[Unchanged]), Mode::Apply), Exit::Converged);
    }

    mod undeclared {
        use super::*;

        /// Apply `~/.a` and `~/.b`, then load a configuration naming `~/.b`
        /// alone, as though `~/.a`'s `[[target]]` was deleted by hand.
        fn dropped(home: &GuardedHome) -> Inputs {
            let both = format!("{}{}", inline("~/.a", "a\\n"), inline("~/.b", "b\\n"));
            apply(&inputs(home, &both));
            inputs(home, &inline("~/.b", "b\\n"))
        }

        fn ledger(home: &GuardedHome) -> LedgerView {
            LedgerView::read(&StateDir::resolve(home.path()), home.path())
                .expect("the ledger")
                .value
        }

        #[test]
        fn a_file_whose_target_was_deleted_is_reported_naming_bx_rm() {
            let home = guarded_home();
            let inputs = dropped(&home);

            let report = plan(&inputs);
            assert_eq!(
                report.actions(),
                vec![Action::Unchanged, Action::Undeclared]
            );
            let row = &report.changes[1];
            assert_eq!(row.target, "~/.a");
            assert_eq!(row.diff, None);
            assert_eq!(
                row.note.as_deref(),
                Some(
                    "the configuration no longer declares it, so bx leaves it as it is; \
                     `bx rm ~/.a` releases it"
                )
            );
            assert_eq!(row.origin, Origin::unknown(&inputs.state().ledger()));
            assert_eq!(exit(&report, Mode::Plan), Exit::Converged);
        }

        #[test]
        fn apply_writes_nothing_for_it_and_the_next_plan_shows_it_again() {
            let home = guarded_home();
            let inputs = dropped(&home);
            let before = snapshot(home.path(), &[]);
            let owned = ledger(&home);

            let applied = apply(&inputs);
            assert!(!applied.executed, "nothing to write, so no session");
            assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
            assert_eq!(snapshot(home.path(), &[]), before);
            assert_eq!(ledger(&home), owned);
            assert_eq!(plan(&inputs).changes, applied.changes);
        }

        #[test]
        fn a_target_switched_off_is_reported_the_same_way() {
            let home = guarded_home();
            apply(&inputs(&home, &inline("~/.a", "a\\n")));
            let off = format!("{}enabled = false\n", inline("~/.a", "a\\n"));

            let report = plan(&inputs(&home, &off));
            assert_eq!(report.actions(), vec![Action::Undeclared]);
            assert_eq!(report.changes[0].target, "~/.a");
        }

        #[test]
        fn an_edited_file_is_a_conflict_that_still_names_bx_rm() {
            let home = guarded_home();
            let inputs = dropped(&home);
            std::fs::write(home.child(".a"), "edited\n").expect("the edit");

            let report = plan(&inputs);
            assert_eq!(report.actions(), vec![Action::Unchanged, Action::Conflict]);
            let note = report.changes[1].note.as_deref().expect("a note");
            // `bx rm` refuses to restore over an edit, so the note does not
            // promise that it releases the file.
            assert_eq!(
                note,
                "edited since bx last wrote it; the configuration no longer declares it, so bx \
                 leaves it as it is, and `bx rm ~/.a` will not restore over the change"
            );
            assert_eq!(exit(&report, Mode::Plan), Exit::Pending);

            assert!(!apply(&inputs).executed);
            assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
        }

        #[test]
        fn a_file_the_user_removed_is_reported_as_gone() {
            let home = guarded_home();
            let inputs = dropped(&home);
            std::fs::remove_file(home.child(".a")).expect("the removal");

            let report = plan(&inputs);
            assert_eq!(
                report.actions(),
                vec![Action::Unchanged, Action::Undeclared]
            );
            let note = report.changes[1].note.as_deref().expect("a note");
            assert!(note.starts_with("it is no longer on disk; "), "{note}");
            assert!(!apply(&inputs).executed);
            assert!(!home.child(".a").exists(), "nothing is written back");
        }

        #[test]
        fn a_target_held_back_still_declares_its_file() {
            let home = guarded_home();
            apply(&inputs(&home, &inline("~/.a", "a\\n")));
            let blocked = format!(
                "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n{}",
                inline("~/.a", "{{who}}\\n")
            );

            let report = plan(&inputs(&home, &blocked));
            assert_eq!(report.actions(), vec![Action::Blocked]);
        }

        #[test]
        fn the_plan_view_shows_the_row() {
            let home = guarded_home();
            let inputs = dropped(&home);

            let shown = render(&plan(&inputs), View::Plan, Palette::PLAIN, home.path());
            let ledger = paths::to_portable(&inputs.state().ledger(), home.path());
            assert_eq!(
                shown,
                format!(
                    "  * ~/.a  ({ledger}:0) the configuration no longer declares it, so bx \
                     leaves it as it is; `bx rm ~/.a` releases it\nPlan: 0 to create, 0 to \
                     modify, 0 conflict, 0 blocked, 1 undeclared, 1 unchanged.\n"
                )
            );
        }
    }
}
