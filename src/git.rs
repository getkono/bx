//! The user's own `git`, run as a child process in one repository.
//!
//! [`Git`] is every git operation bx makes: `bx sync`'s pull and push, a
//! declared external's clone and fetch, `bx update`'s look at a followed
//! branch and the `bx.lock` commit it makes, and `bx rm`'s checks on a
//! checkout.
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

pub(crate) mod checkout;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::env::Env;
use crate::process;
use crate::report::stderr_suffix;

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
    #[error("running `git {args}`: {source}; bx needs git on PATH")]
    Spawn {
        /// The arguments it was given.
        args: String,
        /// Why it could not be started.
        #[source]
        source: std::io::Error,
    },
    /// `git`, or a process it left holding its output after it exited, ran
    /// past the deadline it was given, and bx stopped waiting for it. A `git`
    /// still running is killed; a leftover process is killed only with
    /// [`Git::in_own_group`], and otherwise left to run on.
    #[error("`git {args}` did not finish in time, and bx stopped waiting for it")]
    TimedOut {
        /// The arguments it was given.
        args: String,
    },
    /// `git` ran and failed.
    #[error("`git {args}` failed ({status}){}", stderr_suffix(.stderr.as_bytes()))]
    Failed {
        /// The arguments it was given.
        args: String,
        /// How it exited.
        status: std::process::ExitStatus,
        /// What it said.
        stderr: String,
    },
}

/// The `git` program and the environment it runs with.
#[derive(Debug, Clone)]
pub struct Git {
    program: OsString,
    home: PathBuf,
    xdg_config_home: Option<OsString>,
    extra: Vec<(OsString, OsString)>,
    /// When every command must have finished, or `None` for no bound.
    deadline: Option<Instant>,
    /// Whether a bounded command leads a process group of its own.
    own_group: bool,
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
            deadline: None,
            own_group: false,
        }
    }

    /// `git` on `PATH`, seeing `home` and git's own default for the config
    /// home.
    ///
    /// For a caller that has the home and not the whole [`Env`]:
    /// [`crate::restore::plan_restore`], whose checks on a checkout read only
    /// that repository. `bx rm` itself asks through [`Git::new`].
    #[must_use]
    pub fn at_home(home: &Path) -> Self {
        Self {
            program: OsString::from("git"),
            home: home.to_path_buf(),
            xdg_config_home: None,
            extra: Vec::new(),
            deadline: None,
            own_group: false,
        }
    }

    /// The same `git`, unable to ask anybody anything.
    ///
    /// A declared external is cloned and fetched with nobody necessarily at
    /// the terminal, so a missing credential has to fail rather than wait.
    /// Every child an unattended `git` runs, the clone and fetch of a declared
    /// external included, goes through [`Git::query`] with standard input
    /// closed. Every child runs with:
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

    /// The same `git`, every command failed with [`Error::TimedOut`] once
    /// `deadline` passes, whether git is still running (it is killed) or its
    /// output is still being collected.
    ///
    /// For a question to a remote, whose network has to be bounded: one that
    /// accepts the connection and never answers would otherwise hold a person
    /// at `bx update`, or a background check, until the next boot.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// The same `git`, each bounded command run in a process group of its
    /// own, so its deadline also reaches the `ssh` or `git-remote-https` git
    /// starts.
    ///
    /// Only for a run nobody is at the terminal for — `bx update
    /// --background` — since a group of its own is also out of reach of the
    /// Ctrl-C a person presses. Without it a deadline kills git alone, and a
    /// transport git started that is waiting on a silent remote outlives it
    /// until the remote answers or closes: the price of Ctrl-C still reaching
    /// a person's `bx update`.
    #[must_use]
    pub const fn in_own_group(mut self) -> Self {
        self.own_group = true;
        self
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

    /// Run `git args` in `repo` and return what it printed, whole.
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
        let mut command = self.command(repo, args);
        command.stdin(stdin);
        let output = match self.deadline {
            None => command
                .output()
                .map(|output| process::Output {
                    status: output.status,
                    stdout: output.stdout,
                    stderr: output.stderr,
                })
                .map_err(process::Error::Spawn),
            Some(deadline) => {
                let options = process::Options {
                    own_group: self.own_group,
                    ..process::Options::default()
                };
                process::bounded(&mut command, deadline, options)
            }
        };
        let output = match output {
            Ok(output) => output,
            // Neither stream is capped, so nothing is ever too large.
            Err(process::Error::TimedOut | process::Error::TooLarge(_)) => {
                return Err(Error::TimedOut { args: shown });
            }
            Err(process::Error::Spawn(source) | process::Error::Wait(source)) => {
                return Err(Error::Spawn {
                    args: shown,
                    source,
                });
            }
        };
        if !output.status.success() {
            return Err(Error::Failed {
                args: shown,
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Run `git args` in `repo` with its standard input closed: a read-only
    /// question, or any command that must not ask one. What it printed is
    /// returned trimmed.
    pub(crate) fn query(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        self.query_whole(repo, args)
            .map(|printed| printed.trim().to_string())
    }

    /// [`Git::query`], returning what it printed untrimmed: for `-z` output,
    /// whose names may begin or end with whitespace that is part of them.
    pub(crate) fn query_whole(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.output(repo, &args, Stdio::null())
    }

    /// A `git commit`, with standard input inherited so the user's own hooks
    /// and signing can ask what they ask on any commit they make.
    pub(crate) fn commit(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        self.remote(repo, args)
    }

    /// A command that may reach the remote.
    pub(crate) fn remote(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.output(repo, &args, Stdio::inherit())
            .map(|printed| printed.trim().to_string())
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
        assert!(
            error.to_string().ends_with("; bx needs git on PATH"),
            "{error}"
        );
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
        assert_eq!(stderr_suffix(b"  \n"), "");
        assert_eq!(stderr_suffix(b"fatal: x\n"), ": fatal: x");
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

    #[test]
    fn a_bounded_git_in_its_own_group_leads_one_and_otherwise_shares_bxs() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        use rustix::process::{Pid, Signal, getpgid, getpgrp, kill_process};

        let home = guarded_home();
        // A stand-in for git that leaves a process behind, its pipes closed
        // so the command still returns, and prints that process's id.
        let program = home.path().join("git");
        std::fs::write(
            &program,
            "#!/bin/sh\nsleep 30 </dev/null >/dev/null 2>&1 &\necho $!\n",
        )
        .expect("write the stand-in");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("make it executable");
        for own_group in [false, true] {
            let git = git(home.path())
                .with_program(&program)
                .with_deadline(Instant::now() + Duration::from_secs(30));
            let git = if own_group { git.in_own_group() } else { git };
            // Another test thread that forks while the stand-in is open for
            // writing holds that descriptor until its child calls `exec`, and
            // running it inside that window fails with `ETXTBSY`. The window
            // closes on its own, so only that error is retried.
            let mut printed = None;
            for _ in 0..200 {
                match git.query(home.path(), &["status"]) {
                    Err(Error::Spawn { source, .. })
                        if source.kind() == std::io::ErrorKind::ExecutableFileBusy =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    answer => {
                        printed = Some(answer.expect("it runs"));
                        break;
                    }
                }
            }
            let printed = printed.expect("the stand-in stayed busy");
            let left = Pid::from_raw(printed.parse().expect("a pid")).expect("a positive pid");
            let group = getpgid(Some(left)).expect("the leftover is running");
            let _ = kill_process(left, Signal::KILL);
            assert_eq!(group != getpgrp(), own_group, "own_group {own_group}");
        }
    }

    #[test]
    fn a_git_past_its_deadline_did_not_finish_in_time() {
        let home = guarded_home();
        let error = git(home.path())
            .with_deadline(Instant::now())
            .query(home.path(), &["version"]);
        if let Err(error) = error {
            assert!(
                error.to_string().contains("did not finish in time"),
                "{error}"
            );
        }
    }
}
