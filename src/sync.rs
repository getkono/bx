//! `bx sync`: fast-forward the config repo from its upstream, converge this
//! machine to it, and push what this machine committed.
//!
//! This module holds the two halves around the apply — [`pull`] before it and
//! [`push`] after it — and [`may_push`], which reads the apply's report to
//! decide whether the second half runs. The apply itself is `bx apply`'s, in
//! [`crate::command`]: the same [`crate::plan::run`], the same rendering and
//! the same one confirmation, so the change list `sync` asks about is the one
//! every other command shows (Invariant 7), and an interrupted `sync` is
//! recovered by the next run exactly as an interrupted `apply` is.
//!
//! # Git is the user's own `git`
//!
//! Every git operation runs the `git` on `PATH`, in the config repo, never a
//! library of bx's own. `sync` fetches and pushes over whatever transport,
//! credential helper, ssh agent and configuration the user's clone already
//! uses, and a config repo that git can clone is one git can sync. Nothing
//! here is on the shell-startup path, so spawning a process costs nothing that
//! Invariant 6 budgets.
//!
//! The child sees the same `HOME` and `XDG_CONFIG_HOME` bx resolved its own
//! paths from, so git reads the configuration of the account bx is serving,
//! and none of the variables that would point git at a *different* repository
//! (`GIT_DIR`, `GIT_WORK_TREE`, …) — a `bx sync` run from inside a git hook
//! must still sync the config repo, not the repository whose hook it is.
//!
//! # Fast-forward only
//!
//! The branch is compared with its upstream after the fetch. Behind, it is
//! fast-forwarded; ahead, its commits are pushed once the apply is done; both,
//! and `sync` stops with [`Error::Diverged`] before it changes anything. It
//! never merges, rebases, resets or force-pushes: a diverged history is a
//! human's to reconcile, and `sync` is run again once they have.
//!
//! # State never leaves the machine
//!
//! The state directory holds this account's answers, the bytes bx displaced
//! and its journal — none of it publishable. Before anything is fetched,
//! [`pull`] refuses a state directory inside the config repo, where a commit
//! could pick it up; and before any commit is pushed, it refuses one that
//! carries a file named as a state file is: `local.toml`, `ledger.mpk`,
//! `journal.mpk`, or a content-addressed blob in a `restore/` directory. That
//! is a guard on four literal names, not a secret scanner.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::paths;
use crate::plan::{self, Env, Report};
use crate::state::StateDir;

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

/// Everything that stops `bx sync`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Loading, planning or applying failed, including a missing config repo.
    #[error(transparent)]
    Plan(#[from] plan::Error),
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
    Git {
        /// The arguments it was given.
        args: String,
        /// How it exited.
        status: std::process::ExitStatus,
        /// What it said.
        stderr: String,
    },
    /// The config repo is not a git repository of its own.
    #[error(
        "the config repo {} is not a git repository{}; bx sync pulls and pushes through git. \
         Run `git init` there and add a remote, or clone your config repo there",
        .repo.display(),
        .toplevel.as_ref().map_or_else(String::new, |top| format!(
            " (it is inside the git repository {})", top.display()
        ))
    )]
    NotARepo {
        /// The config repo.
        repo: PathBuf,
        /// The repository git found it inside, when there is one.
        toplevel: Option<PathBuf>,
    },
    /// `HEAD` is not a branch.
    #[error(
        "the config repo {} has no branch checked out; bx sync fast-forwards a branch. Check \
         one out and run bx sync again",
        .0.display()
    )]
    Detached(PathBuf),
    /// The branch has no upstream to pull from or push to.
    #[error(
        "the branch {branch} of the config repo has no upstream; set one with \
         `git -C {} branch --set-upstream-to=REMOTE/BRANCH` and run bx sync again",
        .repo.display()
    )]
    NoUpstream {
        /// The config repo.
        repo: PathBuf,
        /// The branch checked out there.
        branch: String,
    },
    /// Both the branch and its upstream have commits the other lacks.
    #[error(
        "{branch} and {upstream} have diverged ({ahead} commit(s) only here, {behind} only \
         there); bx sync only fast-forwards and changed nothing. Merge or rebase {branch} \
         yourself, then run bx sync again"
    )]
    Diverged {
        /// The branch.
        branch: String,
        /// Its upstream, as `REMOTE/BRANCH`.
        upstream: String,
        /// Commits on the branch the upstream lacks.
        ahead: u64,
        /// Commits on the upstream the branch lacks.
        behind: u64,
    },
    /// The state directory is inside the config repo, where a commit would
    /// publish it.
    #[error(
        "bx's state directory {} is inside the config repo {}, where a commit would publish \
         this account's answers and the bytes bx displaced; bx sync pushes nothing from such \
         a repo. Point XDG_STATE_HOME outside it",
        .state.display(),
        .repo.display()
    )]
    StateInRepo {
        /// The state directory.
        state: PathBuf,
        /// The config repo.
        repo: PathBuf,
    },
    /// A commit waiting to be pushed carries a file named as a state file is.
    #[error(
        "the commits bx sync would push to {upstream} carry {}, named as bx's state files are; \
         they belong to this machine and are never published. Nothing was pulled, applied \
         or pushed. Remove them from those commits and run bx sync again",
        .paths.join(", ")
    )]
    WouldPushState {
        /// Its upstream, as `REMOTE/BRANCH`.
        upstream: String,
        /// Each offending path, as git names it in the repo.
        paths: Vec<String>,
    },
    /// Git answered in a shape bx does not understand.
    #[error("`git {args}` answered {answer:?}, which bx does not understand")]
    Unexpected {
        /// The arguments it was given.
        args: String,
        /// What it printed.
        answer: String,
    },
    /// The output could not be written.
    #[error("writing the output: {0}")]
    Output(#[source] std::io::Error),
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

    /// Set `name` to `value` in every child as well.
    #[must_use]
    pub fn with_env(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.extra.push((name.into(), value.into()));
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
            return Err(Error::Git {
                args: shown,
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// A read-only question.
    fn query(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.output(repo, &args, Stdio::null())
    }

    /// A command that may reach the remote.
    fn remote(&self, repo: &Path, args: &[&str]) -> Result<String, Error> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.output(repo, &args, Stdio::inherit())
    }
}

/// The branch's upstream, as git's configuration names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The remote: `origin`, or `.` for a branch that tracks a local one.
    pub remote: String,
    /// The ref on that remote the branch merges from: `refs/heads/master`.
    pub remote_ref: String,
    /// How git abbreviates it: `origin/master`.
    pub short: String,
}

/// What [`pull`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    /// The config repo.
    pub repo: PathBuf,
    /// The branch checked out there.
    pub branch: String,
    /// Its upstream.
    pub upstream: Upstream,
    /// Commits on the branch its upstream lacks, which [`push`] publishes.
    pub ahead: u64,
    /// Commits the branch was fast-forwarded by.
    pub fast_forwarded: u64,
}

/// Fetch the config repo's upstream and fast-forward its branch to it.
///
/// In order, and stopping at the first refusal: the state directory must lie
/// outside the config repo; the config repo must be a git repository of its
/// own, on a branch with an upstream; the upstream is fetched; a branch that
/// has diverged from it is refused; a branch with commits to push is refused
/// when one carries a state file; and a branch that is behind is
/// fast-forwarded. Nothing is changed before the fast-forward, which git makes
/// only when the working tree allows it.
///
/// # Errors
///
/// [`plan::Error::RepoMissing`] when there is no config repo, and every other
/// [`Error`] as its step says.
pub fn pull(env: &Env, git: &Git) -> Result<Pulled, Error> {
    let repo = paths::config_root_in(&env.home, env.xdg_config_home.as_deref());
    if !repo.is_dir() {
        return Err(plan::Error::RepoMissing(repo).into());
    }
    let state = StateDir::resolve_in(&env.home, env.xdg_state_home.as_deref());
    refuse_state_in_repo(&repo, state.root())?;
    own_repository(git, &repo)?;

    let branch = git
        .query(&repo, &["symbolic-ref", "--quiet", "--short", "HEAD"])
        .map_err(|_| Error::Detached(repo.clone()))?;
    let upstream = upstream(git, &repo, &branch)?;

    git.remote(&repo, &["fetch", "--quiet", &upstream.remote])?;
    let (ahead, behind) = counts(git, &repo)?;
    if ahead > 0 && behind > 0 {
        return Err(Error::Diverged {
            branch,
            upstream: upstream.short,
            ahead,
            behind,
        });
    }
    if ahead > 0 {
        refuse_outgoing_state(git, &repo, &state, &upstream)?;
    }
    if behind > 0 {
        git.query(&repo, &["merge", "--ff-only", "--quiet", "@{upstream}"])?;
    }
    Ok(Pulled {
        repo,
        branch,
        upstream,
        ahead,
        fast_forwarded: behind,
    })
}

/// Push the branch [`pull`] found to its upstream, never forcing.
///
/// # Errors
///
/// [`Error::Git`] when git refuses, as it does when the upstream moved since
/// the fetch.
pub fn push(git: &Git, pulled: &Pulled) -> Result<(), Error> {
    let refspec = format!("HEAD:{}", pulled.upstream.remote_ref);
    git.remote(
        &pulled.repo,
        &["push", "--quiet", &pulled.upstream.remote, &refspec],
    )?;
    Ok(())
}

/// Whether the apply `report` describes left `sync` free to push: it wrote
/// everything it had to, or had nothing to write, and no interrupted session
/// stood. A declined apply pushes nothing, and neither does one that only
/// recovered, because the next `sync` has to apply what this one did not.
#[must_use]
pub fn may_push(report: &Report) -> bool {
    report.interrupted.is_none()
        && report.recovered.is_none()
        && (report.executed
            || !report
                .changes
                .iter()
                .any(|change| change.action.is_pending()))
}

/// Refuse a state directory that lies inside the config repo, lexically.
fn refuse_state_in_repo(repo: &Path, state: &Path) -> Result<(), Error> {
    let (repo, state) = (paths::normalize(repo), paths::normalize(state));
    if state.starts_with(&repo) {
        return Err(Error::StateInRepo { state, repo });
    }
    Ok(())
}

/// Refuse a config repo that is not the top of a git working tree: none at
/// all, or a directory inside some other repository, whose history `sync`
/// must not pull into or push from.
fn own_repository(git: &Git, repo: &Path) -> Result<(), Error> {
    let Ok(top) = git.query(repo, &["rev-parse", "--show-toplevel"]) else {
        return Err(Error::NotARepo {
            repo: repo.to_path_buf(),
            toplevel: None,
        });
    };
    let top = PathBuf::from(top);
    // Git names the top with symlinks resolved, so the repo is too.
    let same = std::fs::canonicalize(repo).is_ok_and(|repo| repo == top);
    if same {
        Ok(())
    } else {
        Err(Error::NotARepo {
            repo: repo.to_path_buf(),
            toplevel: Some(top),
        })
    }
}

/// The upstream `branch` is configured with.
fn upstream(git: &Git, repo: &Path, branch: &str) -> Result<Upstream, Error> {
    let answer = git.query(
        repo,
        &[
            "for-each-ref",
            "--format=%(upstream:remotename)%00%(upstream:remoteref)%00%(upstream:short)",
            &format!("refs/heads/{branch}"),
        ],
    )?;
    let fields: Vec<&str> = answer.split('\0').collect();
    match fields.as_slice() {
        [remote, remote_ref, short] if !remote.is_empty() && !remote_ref.is_empty() => {
            Ok(Upstream {
                remote: (*remote).to_string(),
                remote_ref: (*remote_ref).to_string(),
                short: (*short).to_string(),
            })
        }
        _ => Err(Error::NoUpstream {
            repo: repo.to_path_buf(),
            branch: branch.to_string(),
        }),
    }
}

/// Commits only on the branch, and commits only on its upstream.
fn counts(git: &Git, repo: &Path) -> Result<(u64, u64), Error> {
    let args = ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"];
    let answer = git.query(repo, &args)?;
    let unexpected = || Error::Unexpected {
        args: args.join(" "),
        answer: answer.clone(),
    };
    let (ahead, behind) = answer.split_once('\t').ok_or_else(unexpected)?;
    Ok((
        ahead.parse().map_err(|_| unexpected())?,
        behind.parse().map_err(|_| unexpected())?,
    ))
}

/// Refuse the push when a commit it would publish touches a path named as a
/// state file.
///
/// `log --name-only @{upstream}..HEAD` lists, for every outgoing commit, each
/// path it adds, changes or deletes — a merge against its first parent, so
/// what the merge itself brings in is listed too. Paths are what is checked,
/// not objects: an object list names each blob once, under the first path
/// that reaches it, and leaves out a blob the upstream already has, so a
/// state file whose bytes happen to exist elsewhere (an empty `local.toml`)
/// would pass unseen. A state file a later commit deleted again is still
/// listed by the commit that added it.
fn refuse_outgoing_state(
    git: &Git,
    repo: &Path,
    state: &StateDir,
    upstream: &Upstream,
) -> Result<(), Error> {
    let listed = git.query(
        repo,
        &[
            "log",
            "-z",
            "--name-only",
            "--format=",
            "--no-renames",
            "--diff-merges=first-parent",
            "@{upstream}..HEAD",
        ],
    )?;
    let names = StateNames::of(state);
    let mut paths: Vec<String> = listed
        .split('\0')
        .map(|path| path.trim_start_matches('\n'))
        .filter(|path| names.matches(path))
        .map(str::to_string)
        .collect();
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        Ok(())
    } else {
        Err(Error::WouldPushState {
            upstream: upstream.short.clone(),
            paths,
        })
    }
}

/// The names the state directory gives its files, taken from [`StateDir`] so
/// the guard and the layout cannot drift apart.
struct StateNames {
    files: [OsString; 3],
    restore: OsString,
}

impl StateNames {
    fn of(state: &StateDir) -> Self {
        let name = |path: PathBuf| {
            path.file_name()
                .expect("every state file has a name")
                .to_os_string()
        };
        Self {
            files: [
                name(state.local_toml()),
                name(state.ledger()),
                name(state.journal()),
            ],
            restore: name(state.restore()),
        }
    }

    /// Whether the repo path `path` is named as a state file: `local.toml`,
    /// the ledger or the journal anywhere, or a restore-store blob — a SHA-256
    /// digest in hex — directly inside a directory named as the store is.
    fn matches(&self, path: &str) -> bool {
        let mut parts = path.rsplit('/');
        let Some(last) = parts.next() else {
            return false;
        };
        if self.files.iter().any(|file| file == last) {
            return true;
        }
        parts.next().is_some_and(|parent| parent == self.restore)
            && last.len() == 64
            && last
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::plan::tests::{env, inline, seed};
    use crate::testing::{GuardedHome, guarded_home};

    /// `git` for a test: the tempdir home's configuration and nothing from the
    /// system's, so a developer's `/etc/gitconfig` cannot change the result.
    pub(crate) fn git(home: &Path) -> Git {
        Git::new(&env(home)).with_env("GIT_CONFIG_NOSYSTEM", "1")
    }

    /// Run `git args` in `dir` with the test identity, and return its output.
    pub(crate) fn run(home: &Path, dir: &Path, args: &[&str]) -> String {
        let mut all = vec![
            "-c",
            "user.name=bx test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ];
        all.extend_from_slice(args);
        git(home)
            .query(dir, &all)
            .unwrap_or_else(|error| panic!("git {args:?}: {error}"))
    }

    /// A config repo at `~/.config/bx` whose `bx.toml` is `layer`, committed
    /// on `master` and tracking `master` of a bare remote at `~/remote.git`.
    pub(crate) fn cloned(home: &GuardedHome, layer: &str) -> PathBuf {
        let remote = home.child("remote.git");
        std::fs::create_dir_all(&remote).expect("the remote");
        run(
            home.path(),
            &remote,
            &["init", "--quiet", "--bare", "-b", "master"],
        );
        seed(home.path(), layer);
        let repo = home.child(".config/bx");
        run(home.path(), &repo, &["init", "--quiet", "-b", "master"]);
        commit_all(home.path(), &repo, "seed");
        let url = remote.to_str().expect("a UTF-8 tempdir");
        run(home.path(), &repo, &["remote", "add", "origin", url]);
        run(
            home.path(),
            &repo,
            &["push", "--quiet", "-u", "origin", "master"],
        );
        repo
    }

    /// Stage everything in `dir` and commit it.
    pub(crate) fn commit_all(home: &Path, dir: &Path, message: &str) {
        run(home, dir, &["add", "-A"]);
        run(home, dir, &["commit", "--quiet", "-m", message]);
    }

    /// A second clone of the remote, at `~/other`, standing for another
    /// machine.
    pub(crate) fn other(home: &GuardedHome) -> PathBuf {
        let other = home.child("other");
        let url = home.child("remote.git");
        run(
            home.path(),
            home.path(),
            &[
                "clone",
                "--quiet",
                url.to_str().expect("UTF-8"),
                other.to_str().expect("UTF-8"),
            ],
        );
        other
    }

    /// The commit `rev` names in `dir`.
    pub(crate) fn rev(home: &Path, dir: &Path, rev: &str) -> String {
        run(home, dir, &["rev-parse", rev])
    }

    #[test]
    fn a_missing_repo_is_the_plan_error() {
        let home = guarded_home();
        let error = pull(&env(home.path()), &git(home.path())).expect_err("no repo");
        assert!(
            matches!(error, Error::Plan(plan::Error::RepoMissing(_))),
            "{error:?}"
        );
    }

    #[test]
    fn a_repo_that_is_not_a_git_repository_is_refused() {
        let home = guarded_home();
        seed(home.path(), "");
        let error = pull(&env(home.path()), &git(home.path())).expect_err("not git");
        assert!(
            matches!(&error, Error::NotARepo { toplevel: None, .. }),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("Run `git init` there"),
            "{error}"
        );
    }

    #[test]
    fn a_repo_inside_another_repository_is_refused_naming_it() {
        let home = guarded_home();
        seed(home.path(), "");
        run(
            home.path(),
            home.path(),
            &["init", "--quiet", "-b", "master"],
        );
        let error = pull(&env(home.path()), &git(home.path())).expect_err("nested");
        let Error::NotARepo {
            toplevel: Some(top),
            ..
        } = &error
        else {
            panic!("{error:?}");
        };
        assert_eq!(
            top,
            &std::fs::canonicalize(home.path()).expect("canonical home")
        );
        assert!(
            error
                .to_string()
                .contains("it is inside the git repository")
        );
    }

    #[test]
    fn a_detached_head_is_refused() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        run(home.path(), &repo, &["checkout", "--quiet", "--detach"]);
        let error = pull(&env(home.path()), &git(home.path())).expect_err("detached");
        assert!(matches!(error, Error::Detached(_)), "{error:?}");
    }

    #[test]
    fn a_branch_without_an_upstream_is_refused() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        run(
            home.path(),
            &repo,
            &["branch", "--quiet", "--unset-upstream"],
        );
        let error = pull(&env(home.path()), &git(home.path())).expect_err("no upstream");
        assert!(
            matches!(&error, Error::NoUpstream { branch, .. } if branch == "master"),
            "{error:?}"
        );
        assert!(error.to_string().contains("--set-upstream-to"), "{error}");
    }

    #[test]
    fn a_state_directory_inside_the_repo_is_refused_before_git_is_asked_anything() {
        let home = guarded_home();
        // Not even a git repository: the refusal comes first.
        seed(home.path(), "");
        let inside = Env {
            xdg_state_home: Some(home.child(".config/bx/state").into_os_string()),
            ..env(home.path())
        };
        let error = pull(&inside, &git(home.path())).expect_err("state in repo");
        assert!(matches!(error, Error::StateInRepo { .. }), "{error:?}");
        assert!(error.to_string().contains("XDG_STATE_HOME"), "{error}");
    }

    #[test]
    fn a_state_directory_beside_the_repo_is_not_inside_it() {
        assert!(
            refuse_state_in_repo(Path::new("/h/.config/bx"), Path::new("/h/.config/bx-state"))
                .is_ok()
        );
        assert!(
            refuse_state_in_repo(Path::new("/h/.config/bx"), Path::new("/h/.config/bx/../s"))
                .is_ok()
        );
        assert!(
            refuse_state_in_repo(Path::new("/h/.config/bx"), Path::new("/h/.config/bx/./s"))
                .is_err()
        );
        assert!(
            refuse_state_in_repo(Path::new("/h/.config/bx"), Path::new("/h/.config/bx")).is_err()
        );
    }

    #[test]
    fn a_converged_repo_pulls_nothing_and_has_nothing_to_push() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        let head = rev(home.path(), &repo, "HEAD");

        let pulled = pull(&env(home.path()), &git(home.path())).expect("pull");

        assert_eq!(pulled.branch, "master");
        assert_eq!(
            pulled.upstream,
            Upstream {
                remote: "origin".to_string(),
                remote_ref: "refs/heads/master".to_string(),
                short: "origin/master".to_string(),
            }
        );
        assert_eq!((pulled.ahead, pulled.fast_forwarded), (0, 0));
        assert_eq!(rev(home.path(), &repo, "HEAD"), head);
    }

    #[test]
    fn a_branch_behind_its_upstream_is_fast_forwarded() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        let other = other(&home);
        std::fs::write(other.join("bx.toml"), inline("~/.a", "a\\n")).expect("edit");
        commit_all(home.path(), &other, "add a");
        run(home.path(), &other, &["push", "--quiet"]);
        let theirs = rev(home.path(), &other, "HEAD");

        let pulled = pull(&env(home.path()), &git(home.path())).expect("pull");

        assert_eq!((pulled.ahead, pulled.fast_forwarded), (0, 1));
        assert_eq!(rev(home.path(), &repo, "HEAD"), theirs);
        assert_eq!(
            std::fs::read_to_string(repo.join("bx.toml")).expect("bx.toml"),
            inline("~/.a", "a\\n")
        );
    }

    #[test]
    fn a_diverged_branch_is_refused_and_left_exactly_where_it_was() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        let other = other(&home);
        std::fs::write(other.join("theirs.toml"), "").expect("theirs");
        commit_all(home.path(), &other, "theirs");
        run(home.path(), &other, &["push", "--quiet"]);
        std::fs::write(repo.join("mine.toml"), "").expect("mine");
        commit_all(home.path(), &repo, "mine");
        let mine = rev(home.path(), &repo, "HEAD");

        let error = pull(&env(home.path()), &git(home.path())).expect_err("diverged");

        assert!(
            matches!(
                &error,
                Error::Diverged {
                    ahead: 1,
                    behind: 1,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(error.to_string().contains("changed nothing"), "{error}");
        assert_eq!(rev(home.path(), &repo, "HEAD"), mine, "the branch moved");
        assert!(!repo.join("theirs.toml").exists());
    }

    #[test]
    fn a_branch_ahead_of_its_upstream_is_counted_and_pushed_without_force() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        std::fs::write(repo.join("mine.toml"), "").expect("mine");
        commit_all(home.path(), &repo, "mine");
        let mine = rev(home.path(), &repo, "HEAD");

        let pulled = pull(&env(home.path()), &git(home.path())).expect("pull");
        assert_eq!((pulled.ahead, pulled.fast_forwarded), (1, 0));
        push(&git(home.path()), &pulled).expect("push");

        let remote = home.child("remote.git");
        assert_eq!(rev(home.path(), &remote, "master"), mine);
    }

    #[test]
    fn a_push_the_upstream_moved_under_is_refused_by_git() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        std::fs::write(repo.join("mine.toml"), "").expect("mine");
        commit_all(home.path(), &repo, "mine");
        let pulled = pull(&env(home.path()), &git(home.path())).expect("pull");

        let other = other(&home);
        std::fs::write(other.join("theirs.toml"), "").expect("theirs");
        commit_all(home.path(), &other, "theirs");
        run(home.path(), &other, &["push", "--quiet"]);
        let theirs = rev(home.path(), &other, "HEAD");

        let error = push(&git(home.path()), &pulled).expect_err("not a fast-forward");
        assert!(matches!(error, Error::Git { .. }), "{error:?}");
        let remote = home.child("remote.git");
        assert_eq!(rev(home.path(), &remote, "master"), theirs, "forced");
    }

    #[test]
    fn every_state_file_name_in_an_outgoing_commit_refuses_the_push() {
        let digest = crate::state::ContentHash::of(b"prior\n").to_hex();
        for path in [
            "local.toml".to_string(),
            "nested/ledger.mpk".to_string(),
            "journal.mpk".to_string(),
            format!("state/restore/{digest}"),
        ] {
            let home = guarded_home();
            let repo = cloned(&home, "");
            let file = repo.join(&path);
            std::fs::create_dir_all(file.parent().expect("a parent")).expect("parents");
            std::fs::write(&file, "x").expect("the state file");
            commit_all(home.path(), &repo, "oops");
            let head = rev(home.path(), &repo, "HEAD");

            let error = pull(&env(home.path()), &git(home.path())).expect_err(&path);

            let Error::WouldPushState { paths, upstream } = &error else {
                panic!("{path}: {error:?}");
            };
            assert_eq!(paths, &vec![path.clone()]);
            assert_eq!(upstream, "origin/master");
            assert_eq!(rev(home.path(), &repo, "HEAD"), head);
        }
    }

    #[test]
    fn a_state_file_committed_and_then_deleted_is_still_refused() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        std::fs::write(repo.join("local.toml"), "[values]\n").expect("local.toml");
        commit_all(home.path(), &repo, "oops");
        std::fs::remove_file(repo.join("local.toml")).expect("remove");
        commit_all(home.path(), &repo, "undo");

        let error = pull(&env(home.path()), &git(home.path())).expect_err("still in history");
        assert!(matches!(error, Error::WouldPushState { .. }), "{error:?}");
    }

    #[test]
    fn a_state_file_whose_bytes_the_upstream_already_has_is_still_refused() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        // The seeded `bx.toml` is empty, so the upstream already has the
        // empty blob this `local.toml` is.
        assert_eq!(std::fs::read(repo.join("bx.toml")).expect("bx.toml"), b"");
        std::fs::write(repo.join("local.toml"), "").expect("local.toml");
        commit_all(home.path(), &repo, "oops");

        let error = pull(&env(home.path()), &git(home.path())).expect_err("empty local.toml");
        let Error::WouldPushState { paths, .. } = &error else {
            panic!("{error:?}");
        };
        assert_eq!(paths, &vec!["local.toml".to_string()]);
    }

    #[test]
    fn a_state_file_sharing_its_bytes_with_another_outgoing_path_is_still_refused() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        // `a.toml` sorts first, so an object list names the shared blob by it.
        std::fs::write(repo.join("a.toml"), "shared\n").expect("a.toml");
        std::fs::write(repo.join("journal.mpk"), "shared\n").expect("journal.mpk");
        commit_all(home.path(), &repo, "oops");

        let error = pull(&env(home.path()), &git(home.path())).expect_err("shared blob");
        let Error::WouldPushState { paths, .. } = &error else {
            panic!("{error:?}");
        };
        assert_eq!(paths, &vec!["journal.mpk".to_string()]);
    }

    #[test]
    fn a_state_file_in_any_of_several_outgoing_commits_is_refused() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        std::fs::write(repo.join("mine.toml"), "a\n").expect("mine");
        commit_all(home.path(), &repo, "mine");
        std::fs::create_dir_all(repo.join("sub")).expect("sub");
        std::fs::write(repo.join("sub/ledger.mpk"), "b\n").expect("ledger");
        commit_all(home.path(), &repo, "oops");
        std::fs::write(repo.join("mine.toml"), "c\n").expect("mine again");
        commit_all(home.path(), &repo, "later");

        let error = pull(&env(home.path()), &git(home.path())).expect_err("middle commit");
        let Error::WouldPushState { paths, .. } = &error else {
            panic!("{error:?}");
        };
        assert_eq!(paths, &vec!["sub/ledger.mpk".to_string()]);
    }

    #[test]
    fn names_near_a_state_file_are_not_state_files() {
        let home = guarded_home();
        let names = StateNames::of(&StateDir::resolve(home.path()));
        let digest = "a".repeat(64);
        assert!(names.matches(&format!("restore/{digest}")));
        for path in [
            "local.toml.example",
            "my-local.toml",
            "ledger",
            "journal",
            "restore",
            &format!("restore/{}", "A".repeat(64)),
            &format!("restore/{}", "a".repeat(63)),
            &format!("restore/{}g", "a".repeat(63)),
            &format!("other/{digest}"),
            "",
        ] {
            assert!(!names.matches(path), "{path}");
        }
    }

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
    fn a_git_that_cannot_be_started_is_a_spawn_error() {
        let home = guarded_home();
        let mut git = git(home.path());
        git.program = OsString::from("/nonexistent/git");
        let error = git
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
        assert!(matches!(error, Error::Git { .. }), "{error:?}");
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

    #[test]
    fn may_push_only_after_everything_was_written_or_nothing_was_pending() {
        use crate::config::Origin;
        use crate::report::Action;

        let row = |action| plan::Change {
            target: "~/.a".to_string(),
            origin: Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line: 1,
            },
            action,
            diff: None,
            note: None,
        };
        let pending = Report {
            changes: vec![row(Action::Create)],
            ..Report::default()
        };
        assert!(may_push(&Report::default()));
        assert!(may_push(&Report {
            changes: vec![row(Action::Conflict), row(Action::Unchanged)],
            ..Report::default()
        }));
        assert!(!may_push(&pending), "declined");
        assert!(may_push(&Report {
            executed: true,
            ..pending.clone()
        }));
        assert!(!may_push(&Report {
            recovered: Some(crate::recover::Outcome::Nothing),
            ..Report::default()
        }));
        assert!(!may_push(&Report {
            interrupted: Some(crate::recover::Interrupted {
                kind: crate::journal::SessionKind::Apply,
                journal: PathBuf::from("/state/journal.mpk"),
                complete: false,
                unreadable: false,
                unfinished: Vec::new(),
            }),
            ..Report::default()
        }));
    }
}
