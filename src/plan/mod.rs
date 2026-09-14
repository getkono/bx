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
//!
//! The one environment read in the whole path is [`Env::from_process`]; every
//! other function takes what it needs as an argument.

mod decide;
mod diff;

use std::ffi::OsString;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

pub use diff::{Diff, DiffKind, TEXT_LIMIT, Why};

use crate::config::resolve::{self, Resolved};
use crate::config::{self, Origin, layers, merge};
use crate::env_guard::RootSet;
use crate::paths;
use crate::recover::{self, Interrupted};
use crate::report::Action;
use crate::state::{self, LedgerView, SharedLock, StateDir};

/// Which half of the traversal is running.
///
/// Not the file mode: that is [`crate::fs::Mode`], and the two are never
/// imported into one scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Decide and report. Writes nothing.
    Plan,
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
            no_color: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            stdout_tty: std::io::stdout().is_terminal(),
            stdin_tty: std::io::stdin().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
        })
    }
}

/// What a run decides against, loaded once.
#[derive(Debug, Clone)]
pub struct Inputs {
    home: PathBuf,
    repo: PathBuf,
    state: StateDir,
    resolved: Resolved,
    roots: RootSet,
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
        let roots = RootSet::from_values(&resolved.values).owning(&[state.root().to_path_buf()]);
        Ok(Self {
            home,
            repo,
            state,
            resolved,
            roots,
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
    /// An interrupted session could not be inspected or resolved.
    #[error(transparent)]
    Recover(recover::Error),
    /// A destination could not be observed.
    #[error(transparent)]
    Fs(#[from] crate::fs::Error),
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

impl From<recover::Error> for Error {
    fn from(error: recover::Error) -> Self {
        match error {
            recover::Error::State(error) => Self::State(error),
            other => Self::Recover(other),
        }
    }
}

/// Decide every target, and report.
///
/// # Errors
///
/// Whatever loading the ledger, inspecting an interrupted session, reading a
/// body or observing a destination returns.
pub fn run(inputs: &Inputs, mode: Mode) -> Result<Report, Error> {
    let mut report = Report::default();
    match mode {
        Mode::Plan => look_at_state(inputs, &mut report)?,
    }

    let ledger = LedgerView::read(&inputs.state, &inputs.home)?.value;
    let ctx = decide::Ctx {
        ledger: &ledger,
        home: &inputs.home,
        repo: &inputs.repo,
        roots: &inputs.roots,
    };
    for resolution in &inputs.resolved.targets {
        report.changes.push(decide::decide(resolution, &ctx)?);
    }

    match mode {
        Mode::Plan => {
            mark_interrupted(&mut report);
            Ok(report)
        }
    }
}

/// What a read-only run learns from the state directory before deciding.
///
/// The lock is only asked about when its file already exists, so `plan` on a
/// fresh account creates nothing. An `apply` holding the directory is reported
/// as running, and its journal is not an interruption.
fn look_at_state(inputs: &Inputs, report: &mut Report) -> Result<(), Error> {
    if inputs.state.lock().symlink_metadata().is_ok()
        && SharedLock::try_acquire(&inputs.state)?.is_none()
    {
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
mod tests {
    use super::*;
    use crate::fs::{self, Mode as FileMode};
    use crate::journal::{Content, Ownership, Request, Session, SessionKind};
    use crate::paths::Portable;
    use crate::state::Mechanism;
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

    /// Write `layer` as the repo's `bx.toml` and load it.
    pub(crate) fn inputs(home: &GuardedHome, layer: &str) -> Inputs {
        home.write(".config/bx/bx.toml", layer);
        Inputs::load(&env(home.path())).expect("the inputs load")
    }

    /// One inline target, as TOML. `content` is spelled as a TOML basic string.
    pub(crate) fn inline(path: &str, content: &str) -> String {
        format!("[[target]]\npath = \"{path}\"\ncontent = \"{content}\"\n")
    }

    fn plan(inputs: &Inputs) -> Report {
        run(inputs, Mode::Plan).expect("plan runs")
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
    }

    #[test]
    fn t3_a_present_file_bx_does_not_own_is_a_conflict() {
        let home = guarded_home();
        home.write(".a", "mine\n");
        let inputs = inputs(&home, &inline("~/.a", "bx\\n"));

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Conflict]);
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some("exists and bx does not own it")
        );
        assert_eq!(
            text(&report.changes[0]),
            "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -1 +1 @@\n-mine\n+bx\n"
        );
    }

    #[test]
    fn t4_an_owned_file_edited_since_bx_wrote_it_is_a_conflict() {
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
    }

    #[test]
    fn an_owned_file_already_holding_the_body_is_unchanged() {
        let home = guarded_home();
        own(home.path(), ".a", b"bx\n", Mechanism::Own);
        let inputs = inputs(&home, &inline("~/.a", "bx\\n"));

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Unchanged]);
        assert_eq!(report.changes[0].diff, None);
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
    }

    #[test]
    fn a_missing_file_body_is_an_error_naming_its_origin() {
        let home = guarded_home();
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/absent\"\n",
        );

        let error = run(&inputs, Mode::Plan).expect_err("a missing body");

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
    fn the_inputs_name_the_places_they_were_loaded_from() {
        let home = guarded_home();
        let inputs = inputs(&home, "");

        assert_eq!(inputs.home(), home.path());
        assert_eq!(inputs.repo(), home.child(".config/bx"));
        assert_eq!(inputs.state(), &StateDir::resolve(home.path()));
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
    fn a_state_error_and_a_recovery_state_error_are_one_variant() {
        let lock = || state::Error::NotADirectory {
            path: PathBuf::from("/x"),
        };
        assert!(matches!(Error::from(lock()), Error::State(_)));
        assert!(matches!(
            Error::from(recover::Error::State(lock())),
            Error::State(_)
        ));
        assert!(matches!(
            Error::from(recover::Error::Blocked { conflicts: vec![] }),
            Error::Recover(_)
        ));
    }
}
