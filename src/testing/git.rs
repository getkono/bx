//! Git fixtures for tests: a `git` that reads nothing from the system, and the
//! repositories `sync`, `update`, `doctor` and the planner's tests build with
//! it.

use std::path::{Path, PathBuf};

use crate::git::Git;
use crate::plan::tests::{env, seed};
use crate::testing::GuardedHome;

/// `git` for a test: the tempdir home's configuration and nothing from the
/// system's, so a developer's `/etc/gitconfig` cannot change the result.
pub(crate) fn git(home: &Path) -> Git {
    Git::new(&env(home))
        .with_env("GIT_CONFIG_NOSYSTEM", "1")
        // The identity a commit `sync` makes is the user's; the test's
        // is fixed here rather than read from a home that has none.
        .with_env("GIT_AUTHOR_NAME", "bx test")
        .with_env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .with_env("GIT_COMMITTER_NAME", "bx test")
        .with_env("GIT_COMMITTER_EMAIL", "test@example.invalid")
}

/// Run `git args` in `dir` with the test identity, and return its output.
///
/// Automatic maintenance is off: after a commit, git starts it detached,
/// and it can still hold `objects/maintenance.lock` when a test snapshots
/// the tree the commit was made in.
pub(crate) fn run(home: &Path, dir: &Path, args: &[&str]) -> String {
    let mut all = vec![
        "-c",
        "user.name=bx test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
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
