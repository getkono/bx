//! Questions about one git checkout on disk, asked of the user's own `git`.
//!
//! Each runs a read-only query through [`Git`] in a directory that a declared
//! `[[external]]` names: whether it is a checkout of its own, which commit it
//! has checked out, where `origin` points, and what it holds. A declared
//! external's plan and apply ([`crate::plan::external`]), `bx update`'s look at
//! a followed branch ([`crate::update`]) and a link into an external's
//! checkout (`plan::links`) all ask them, so they live here, beside
//! [`Git`], rather than in any one of them.

use std::path::Path;

use crate::git::{self, Git};

/// A git failure, in the words a row's note uses.
pub(crate) fn problem(error: &git::Error) -> String {
    match error {
        git::Error::Spawn { source, .. } => {
            format!("git could not be started: {source}; bx needs git on PATH")
        }
        git::Error::Failed { args, stderr, .. } => {
            let stderr = stderr.trim();
            if stderr.is_empty() {
                format!("`git {args}` failed")
            } else {
                format!("`git {args}` failed: {}", stderr.replace('\n', "; "))
            }
        }
        other @ git::Error::TimedOut { .. } => other.to_string(),
    }
}

/// Refuse a directory that is not the top of a git checkout of its own, so no
/// question is ever answered by a repository around it.
///
/// # Errors
///
/// The note for a row.
pub(crate) fn own_checkout(git: &Git, dest: &Path) -> Result<(), String> {
    let top = git
        .query(dest, &["rev-parse", "--show-toplevel"])
        .map_err(|error| format!("is not a git checkout bx can read: {}", problem(&error)))?;
    let same = std::fs::canonicalize(dest).is_ok_and(|dest| dest == Path::new(&top));
    if same {
        Ok(())
    } else {
        Err(format!(
            "is not a git checkout of its own (git answers from {top}); bx left it as it is"
        ))
    }
}

/// The commit checked out in `dest`.
pub(crate) fn head(git: &Git, dest: &Path) -> Result<String, git::Error> {
    git.query(dest, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
}

/// The url of `origin`, or `None` when there is no such remote.
pub(crate) fn origin_url(git: &Git, dest: &Path) -> Result<Option<String>, git::Error> {
    match git.query(dest, &["config", "--get", "remote.origin.url"]) {
        Ok(url) => Ok(Some(url)),
        Err(git::Error::Failed { status, .. }) if status.code() == Some(1) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether `rev` is a commit `dest` already holds.
pub(crate) fn has_commit(git: &Git, dest: &Path, rev: &str) -> bool {
    git.query(dest, &["cat-file", "-e", &format!("{rev}^{{commit}}")])
        .is_ok()
}

/// Whether `ancestor` is `descendant` or one of its ancestors.
pub(crate) fn is_ancestor(
    git: &Git,
    dest: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<bool, git::Error> {
    match git.query(dest, &["merge-base", "--is-ancestor", ancestor, descendant]) {
        Ok(_) => Ok(true),
        Err(git::Error::Failed { status, .. }) if status.code() == Some(1) => Ok(false),
        Err(error) => Err(error),
    }
}
