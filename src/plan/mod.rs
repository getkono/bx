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
//! The one environment read in the whole path is [`Env::from_process`]; every
//! other function takes what it needs as an argument.

mod decide;
mod diff;
mod execute;

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

pub use diff::{Diff, DiffKind, Palette, TEXT_LIMIT, View, Why, render};

use crate::config::resolve::{self, Resolved};
use crate::config::{self, Origin, layers, merge};
use crate::env_guard::RootSet;
use crate::journal::{self, Session, SessionKind};
use crate::paths;
use crate::recover::{self, Interrupted};
use crate::report::{Action, Exit};
use crate::state::{self, LedgerView, SharedLock, StateDir};

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
    /// [`Error::Home`] when `$HOME` is unset, empty or relative.
    pub fn from_process() -> Result<Self, Error> {
        Ok(Self {
            home: paths::home()?,
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            no_color: no_color(std::env::var_os("NO_COLOR").as_deref()),
            stdout_tty: std::io::stdout().is_terminal(),
            stdin_tty: std::io::stdin().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
        })
    }
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
    resolved: Resolved,
    roots: RootSet,
    progress: bool,
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
            resolved,
            roots,
            progress: env.stderr_tty,
        })
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
}

impl Report {
    /// Every row's action, in order.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        self.changes.iter().map(|change| change.action).collect()
    }
}

/// Everything that can stop a run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `$HOME` is not usable.
    #[error(transparent)]
    Home(#[from] paths::Error),
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
/// `approve` is shown the report and asked only when there is a write to make,
/// and never in [`Mode::Plan`]. Declining leaves the report unexecuted and
/// nothing written: no session is opened and no journal is created.
///
/// # Errors
///
/// Whatever recovery, loading the ledger, reading a body, observing a
/// destination, `approve`, or the session returns. A failed write leaves its
/// journal for the next writing run to roll back.
pub fn run(
    inputs: &Inputs,
    mode: Mode,
    approve: &mut dyn FnMut(&Report) -> Result<bool, Error>,
) -> Result<Report, Error> {
    let mut report = Report::default();
    match mode {
        Mode::Plan => look_at_state(inputs, &mut report)?,
        Mode::Apply => {
            recover::before_writing(&inputs.state)?;
        }
    }

    let ledger = LedgerView::read(&inputs.state, &inputs.home)?.value;
    let ctx = decide::Ctx {
        ledger: &ledger,
        home: &inputs.home,
        repo: &inputs.repo,
        roots: &inputs.roots,
    };
    let mut ops = Vec::new();
    for resolution in &inputs.resolved.targets {
        let (change, op) = decide::decide(resolution, &ctx)?;
        report.changes.push(change);
        ops.extend(op);
    }

    match mode {
        Mode::Plan => {
            mark_interrupted(&mut report);
            Ok(report)
        }
        Mode::Apply => {
            if ops.is_empty() || !approve(&report)? {
                return Ok(report);
            }
            let scope = ops.iter().map(|op| op.target().clone()).collect();
            let session = Session::open(&inputs.state, SessionKind::Apply, &inputs.home, scope)?;
            let progress = execute::progress(ops.len(), inputs.progress);
            execute::execute(ops, session, &progress)?;
            report.executed = true;
            Ok(report)
        }
    }
}

/// The process status a report implies.
///
/// A read-only run exits [`Exit::Pending`] while an interruption stands, and by
/// its actions otherwise. An executed `apply` has done its pending work, so
/// only a row still needing attention keeps it pending. An `apply` that wrote
/// nothing — declined, or with nothing to do — exits by its actions, so a
/// declined prompt over pending work exits 2.
#[must_use]
pub fn exit(report: &Report, mode: Mode) -> Exit {
    let actions = report.actions();
    match mode {
        Mode::Plan if report.interrupted.is_some() => Exit::Pending,
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

/// Every target an interrupted session names is a conflict until a writing
/// run resolves it.
fn mark_interrupted(report: &mut Report) {
    let Some(interrupted) = &report.interrupted else {
        return;
    };
    for unfinished in &interrupted.unfinished {
        let found = report
            .changes
            .iter_mut()
            .find(|change| change.target == unfinished.target.as_str());
        match found {
            Some(change) => {
                change.action = unfinished.action();
                change.note = Some(unfinished.note.clone());
            }
            None => report.changes.push(Change {
                target: unfinished.target.as_str().to_string(),
                origin: Origin::unknown(&interrupted.journal),
                action: unfinished.action(),
                diff: None,
                note: Some(unfinished.note.clone()),
            }),
        }
    }
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
    fn snapshot(root: &Path, skip: &[&str]) -> Vec<Entry> {
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

            run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("the recovering apply");
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
    fn t14_a_standing_interruption_is_reported_as_conflicts_and_plan_writes_nothing() {
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
        for unfinished in &interrupted.unfinished {
            let change = report
                .changes
                .iter()
                .find(|change| change.target == unfinished.target.as_str())
                .expect("a row for every unfinished write");
            assert_eq!(change.action, Action::Conflict);
            assert_eq!(change.note.as_deref(), Some(unfinished.note.as_str()));
        }
        assert_eq!(exit(&report, Mode::Plan), Exit::Pending);
        assert_eq!(snapshot(&home, &[]), before, "plan changed the tree");

        // A target the configuration no longer names is still reported.
        seed(&home, "");
        let report = plan(&load(&home));
        assert_eq!(report.actions(), vec![Action::Conflict; CRASH_WRITES]);
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
            assert_eq!(note, want.to_string());
            let shown = diff::render(
                &report,
                View::Plan,
                Palette::resolve(true, false),
                home.path(),
            );
            assert!(shown.contains(note), "{shown}");
            assert!(!shown.contains(&absolute), "{shown}");

            // Recovery's own error keeps the absolute path.
            let error = run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect_err("blocked");
            assert!(
                matches!(error, Error::Recover(recover::Error::Blocked { .. })),
                "{error:?}"
            );
            assert!(
                error.to_string().contains(&blob.display().to_string()),
                "{error}"
            );
            assert_eq!(std::fs::read(&dest).expect("untouched"), b"new\n");
        }
    }

    #[test]
    fn t15_apply_refuses_a_held_state_directory_and_plan_reports_it_running() {
        let home = guarded_home();
        let inputs = inputs(&home, &inline("~/.a", "x\\n"));
        let held = ExclusiveLock::acquire(inputs.state()).expect("the lock");

        let error = run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect_err("locked");
        assert!(
            matches!(error, Error::State(state::Error::Locked { .. })),
            "{error:?}"
        );

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

        // The next writing run rolls the first write back before deciding.
        let next = apply(&inputs);
        assert_eq!(next.actions(), vec![Action::Create, Action::Conflict]);
        assert!(!StateDir::resolve(home.path()).journal().exists());
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

        let mut interrupted = report_of(&[Unchanged]);
        interrupted.interrupted = Some(Interrupted {
            kind: SessionKind::Apply,
            journal: PathBuf::from("/state/journal"),
            complete: false,
            unreadable: true,
            unfinished: Vec::new(),
        });
        assert_eq!(exit(&interrupted, Mode::Plan), Exit::Pending);

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
}
