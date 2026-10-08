//! The user's own `git`, run as a child process in one repository.
//!
//! [`Git`] is every git operation bx makes: `bx sync`'s pull and push, a
//! declared external's clone and fetch, and `bx rm`'s checks on a checkout.
//! It runs the `git` on `PATH`, never a library of bx's own, so each of them
//! goes over whatever transport, credential helper, ssh agent and
//! configuration the user's clone already uses. Nothing here is on the
//! shell-startup path, so spawning a process costs nothing that Invariant 6
//! budgets.
//!
//! The child sees the same `HOME` and `XDG_CONFIG_HOME` bx resolved its own
//! paths from, so git reads the configuration of the account bx is serving,
//! and none of the variables that would point git at a *different* repository
//! (`GIT_DIR`, `GIT_WORK_TREE`, …) — a `bx sync` run from inside a git hook
//! must still sync the config repo, not the repository whose hook it is.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::env::Env;

/// Variables that make git operate on a repository other than the one it is
/// run in. Removed from every child, so `-C REPO` is what decides.
const REPOSITORY_VARIABLES: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
];

/// Why a `git` command gave no answer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `git` could not be started at all.
    #[error("running `git {args}`: {source}; bx sync needs git on PATH")]
    Spawn {
        /// The arguments it was given.
        args: String,
        /// Why it could not be started.
        #[source]
        source: std::io::Error,
    },
    /// `git` ran and failed.
    #[error("`git {args}` failed ({status}){}", stderr_suffix(.stderr))]
    Failed {
        /// The arguments it was given.
        args: String,
        /// How it exited.
        status: std::process::ExitStatus,
        /// What it said.
        stderr: String,
    },
}

/// `: STDERR` when git said anything, and nothing otherwise.
fn stderr_suffix(stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
}

/// The `git` program and the environment it runs with.
#[derive(Debug, Clone)]
pub struct Git {
    program: OsString,
    home: PathBuf,
    xdg_config_home: Option<OsString>,
    extra: Vec<(OsString, OsString)>,
}

impl Git {
    /// `git` on `PATH`, seeing the home and config home `env` resolved.
    #[must_use]
    pub fn new(env: &Env) -> Self {
        Self {
            program: OsString::from("git"),
            home: env.home.clone(),
            xdg_config_home: env.xdg_config_home.clone(),
            extra: Vec::new(),
        }
    }

    /// `git` on `PATH`, seeing `home` and git's own default for the config
    /// home.
    ///
    /// For a caller that has the home and not the whole [`Env`]: `bx rm`'s
    /// checks on a checkout, which read only that repository.
    #[must_use]
    pub fn at_home(home: &Path) -> Self {
        Self {
            program: OsString::from("git"),
            home: home.to_path_buf(),
            xdg_config_home: None,
            extra: Vec::new(),
        }
    }

    /// The same `git`, unable to ask anybody anything.
    ///
    /// A declared external is cloned and fetched with nobody necessarily at
    /// the terminal, so a missing credential has to fail rather than wait.
    /// Every child runs with its standard input closed, and:
    ///
    /// * `GIT_TERMINAL_PROMPT=0`, so git never asks on the terminal;
    /// * `GIT_ASKPASS` and `SSH_ASKPASS` set to `false`, and
    ///   `SSH_ASKPASS_REQUIRE=force`, so any question git or ssh would put —
    ///   a user name, a password, a key's passphrase, an unknown host key —
    ///   goes to a program that answers nothing and fails;
    /// * `GCM_INTERACTIVE=never`, so Git Credential Manager does not open a
    ///   window.
    ///
    /// A credential helper that answers without asking, an ssh agent, and the
    /// user's own ssh and git configuration all still work: nothing here
    /// replaces a program or a setting, it only takes the prompts away.
    #[must_use]
    pub fn unattended(self) -> Self {
        self.with_env("GIT_TERMINAL_PROMPT", "0")
            .with_env("GIT_ASKPASS", "false")
            .with_env("SSH_ASKPASS", "false")
            .with_env("SSH_ASKPASS_REQUIRE", "force")
            .with_env("GCM_INTERACTIVE", "never")
    }

    /// Set `name` to `value` in every child as well.
    #[must_use]
    pub fn with_env(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.extra.push((name.into(), value.into()));
        self
    }

    /// The same `git` environment, running `program` instead.
    #[cfg(test)]
    pub(crate) fn with_program(mut self, program: impl Into<OsString>) -> Self {
        self.program = program.into();
        self
    }

    /// A `git` command run in `repo`.
    fn command(&self, repo: &Path, args: &[&OsStr]) -> Command {
        let mut command = Command::new(&self.program);
        command.arg("-C").arg(repo).args(args);
        for name in REPOSITORY_VARIABLES {
            command.env_remove(name);
        }
        command.env("HOME", &self.home);
        match &self.xdg_config_home {
            Some(value) => command.env("XDG_CONFIG_HOME", value),
            None => command.env_remove("XDG_CONFIG_HOME"),
        };
        for (name, value) in &self.extra {
            command.env(name, value);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command
    }

    /// Run `git args` in `repo` and return what it printed, trimmed.
    ///
    /// `stdin` is inherited by a command that may talk to a remote, so a
    /// credential or host-key prompt has somewhere to be answered, and is
    /// closed for every other.
    fn output(&self, repo: &Path, args: &[&OsStr], stdin: Stdio) -> Result<String, Error> {
        let shown = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let output = self
            .command(repo, args)
            .stdin(stdin)
            .output()
            .map_err(|source| Error::Spawn {
                args: shown.clone(),
                source,
            })?;
        if !output.status.success() {
            return Err(Error::Failed {
                args: shown,
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Run `git args` in `repo` with its standard input closed: a read-only
    /// question, or any command that must not ask one.
    pub(crate) fn query(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.output(repo, &args, Stdio::null())
    }

    /// A command that may reach the remote.
    pub(crate) fn remote(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.output(repo, &args, Stdio::inherit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::env;
    use crate::sync::tests::git;
    use crate::testing::guarded_home;

    #[test]
    fn every_repository_variable_is_removed_from_the_child() {
        let home = guarded_home();
        let command = git(home.path()).command(home.path(), &[]);
        let removed: Vec<_> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_os_string())
            .collect();
        for name in REPOSITORY_VARIABLES {
            assert!(
                removed.contains(&OsString::from(name)),
                "{name} is not removed"
            );
        }
    }

    #[test]
    fn an_unattended_git_takes_every_prompt_away_and_closes_stdin() {
        let home = guarded_home();
        let command = git(home.path())
            .unattended()
            .command(home.path(), &[OsStr::new("status")]);
        let envs: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for (name, value) in [
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_ASKPASS", "false"),
            ("SSH_ASKPASS", "false"),
            ("SSH_ASKPASS_REQUIRE", "force"),
            ("GCM_INTERACTIVE", "never"),
        ] {
            assert!(
                envs.contains(&(name.to_string(), Some(value.to_string()))),
                "{name}: {envs:?}"
            );
        }
        // And with no helper to answer, asking git for a credential fails
        // rather than waits.
        let asked = git(home.path())
            .unattended()
            .query(home.path(), &["credential", "fill"]);
        assert!(asked.is_err(), "{asked:?}");
    }

    #[test]
    fn a_git_at_a_home_sees_that_home_and_no_config_home() {
        let home = guarded_home();
        let command = Git::at_home(home.path()).command(home.path(), &[]);
        let envs: Vec<_> = command.get_envs().collect();
        assert!(envs.contains(&(OsStr::new("HOME"), Some(home.path().as_os_str()))));
        assert!(envs.contains(&(OsStr::new("XDG_CONFIG_HOME"), None)));
    }

    #[test]
    fn a_git_that_cannot_be_started_is_a_spawn_error() {
        let home = guarded_home();
        let error = git(home.path())
            .with_program("/nonexistent/git")
            .query(home.path(), &["status"])
            .expect_err("no such program");
        assert!(matches!(error, Error::Spawn { .. }), "{error:?}");
        assert!(error.to_string().contains("needs git on PATH"), "{error}");
    }

    #[test]
    fn a_failing_git_says_what_git_said() {
        let home = guarded_home();
        let error = git(home.path())
            .query(home.path(), &["rev-parse", "--verify", "no-such-ref"])
            .expect_err("no such ref");
        assert!(matches!(error, Error::Failed { .. }), "{error:?}");
        assert!(
            error
                .to_string()
                .starts_with("`git rev-parse --verify no-such-ref` failed (")
        );
        assert_eq!(stderr_suffix("  \n"), "");
        assert_eq!(stderr_suffix("fatal: x\n"), ": fatal: x");
    }

    #[test]
    fn the_config_home_git_sees_is_the_one_bx_resolved() {
        let home = guarded_home();
        let with = Git::new(&Env {
            xdg_config_home: Some(OsString::from("/cfg")),
            ..env(home.path())
        });
        let envs: Vec<_> = with
            .command(home.path(), &[])
            .get_envs()
            .map(|(k, v)| (k.to_os_string(), v.map(OsStr::to_os_string)))
            .collect();
        assert!(envs.contains(&(
            OsString::from("XDG_CONFIG_HOME"),
            Some(OsString::from("/cfg"))
        )));
        assert!(envs.contains(&(
            OsString::from("HOME"),
            Some(home.path().as_os_str().to_os_string())
        )));
        let without = Git::new(&env(home.path()));
        assert!(
            without
                .command(home.path(), &[])
                .get_envs()
                .any(|(k, v)| k == "XDG_CONFIG_HOME" && v.is_none())
        );
    }
}
