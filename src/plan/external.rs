//! Declared git externals: one decision per `[[external]]`, and the work it
//! announces.
//!
//! An external is a repository bx keeps checked out at one pinned commit. Its
//! configuration half is [`crate::config::external`]; this is the half that
//! looks at the machine and moves it.
//!
//! # One decision, shared by `plan` and `apply`
//!
//! [`decide_all`] turns each external into a row and, where there is work, an
//! [`Op`] whose fields are private to this module. [`execute`] is handed the
//! ops and does exactly what each one names, re-checking before it acts that
//! the checkout is still what the decision saw. It never decides anything new:
//! where the machine moved since `plan` looked, or where the fetch shows `rev`
//! is not a fast-forward, it stops that external and says why, which is less
//! than `plan` announced and never more (Invariant 7).
//!
//! # Git is the user's own `git`, and never asks
//!
//! Every operation runs the `git` on `PATH` through [`Git`], as `bx sync`
//! does, made [`Git::unattended`] so a missing credential fails rather than
//! waits. `plan` and an external already at its `rev` run nothing that reaches
//! the network: only `apply`, and only for a create or a fast-forward, fetches.
//!
//! # What bx owns
//!
//! A directory bx cloned, and nothing else. An existing directory at `path`
//! that the ledger does not record as bx's clone is a conflict: it is never
//! cloned into, overwritten or adopted. A clone bx did make is only ever
//! fetched and fast-forwarded with `checkout --detach`, which git refuses over
//! local changes; bx never resets, rebases, force-checks-out or discards a
//! commit. Uncommitted changes, local commits `rev` does not contain, and a
//! `rev` that is not a fast-forward all leave the checkout exactly as it is,
//! reported as blocked.
//!
//! # An interrupted clone is never mistaken for a finished one
//!
//! Before a clone's first byte lands, the ledger records the directory as
//! bx's with [`clone_written`] of `None` — *not yet a finished checkout* — and
//! saves. Only once the checkout is at `rev` is the entry recorded with the
//! commit. A run that stops in between leaves an entry the next decision reads
//! as interrupted: `plan` shows a create that removes what was left and clones
//! again, and `apply` does that. The directory is never reported as converged.

use std::path::{Path, PathBuf};

use super::{Change, Diff, Error};
use crate::config::external::External;
use crate::fs::{self, Kind};
use crate::journal;
use crate::paths::{self, Portable};
use crate::report::Action;
use crate::state::{
    self, ExclusiveLock, Ledger, LedgerEntry, LedgerView, Mechanism, NewEntry, PriorBytes,
    StateDir, clone_written,
};
use crate::sync::{self, Git};

/// What a decision may read: nothing it could change.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ctx<'a> {
    /// The ledger, as it was read once for the whole run.
    pub ledger: &'a LedgerView,
    /// The account's home, which every path renders against.
    pub home: &'a Path,
    /// The `git` every question is put to.
    pub git: &'a Git,
}

/// The work one decision announced. Only this module can make one.
#[derive(Debug)]
pub(super) struct Op {
    /// The row this op belongs to, counted among the externals' rows.
    at: usize,
    /// The external's path.
    target: Portable,
    /// Where it renders.
    dest: PathBuf,
    /// The remote.
    url: String,
    /// The commit to leave checked out.
    rev: String,
    /// What to do.
    work: Work,
}

/// The three kinds of work an external can need.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Work {
    /// Clone into a directory that is not there, first removing what an
    /// interrupted clone left when `replace` is set.
    Clone {
        /// Whether an interrupted clone's directory stands at the path.
        replace: bool,
        /// The directories above the path that are not there, deepest first.
        created_dirs: Vec<PathBuf>,
    },
    /// Fetch, and fast-forward from `from` to the op's `rev`.
    Advance {
        /// The commit the decision found checked out.
        from: String,
    },
    /// The checkout is already at `rev`; only the ledger does not say so yet.
    Record,
}

/// Decide every external, in configuration order.
///
/// # Errors
///
/// [`Error::Fs`] when a path cannot be observed at all.
pub(super) fn decide_all(
    externals: &[External],
    ctx: &Ctx<'_>,
) -> Result<(Vec<Change>, Vec<Op>), Error> {
    let mut rows = Vec::with_capacity(externals.len());
    let mut ops = Vec::new();
    for (at, external) in externals.iter().enumerate() {
        let (change, work) = decide(external, ctx)?;
        rows.push(change);
        if let Some(work) = work {
            ops.push(Op {
                at,
                target: external.path.clone(),
                dest: external.path.render(ctx.home),
                url: external.url.clone(),
                rev: external.rev.clone(),
                work,
            });
        }
    }
    Ok((rows, ops))
}

/// Decide one external: its row, and the work `apply` does for it.
fn decide(external: &External, ctx: &Ctx<'_>) -> Decision {
    let dest = external.path.render(ctx.home);
    let observed = fs::observe(&dest)?;
    let (url, rev) = (external.url.as_str(), external.rev.as_str());
    let row = |action, diff, note: Option<String>| Change {
        target: external.path.as_str().to_string(),
        origin: external.origin.clone(),
        action,
        diff,
        note,
    };
    let conflict =
        |note: String| -> Decision { Ok((row(Action::Conflict, None, Some(note)), None)) };
    let blocked = |note: String| -> Decision { Ok((row(Action::Blocked, None, Some(note)), None)) };

    if let Some(parent) = observed
        .parent
        .as_ref()
        .filter(|parent| parent.unusable().is_some())
    {
        return conflict(format!(
            "its parent {} does not resolve to a directory, so there is nowhere to clone it",
            paths::to_portable(&parent.path, ctx.home)
        ));
    }
    let entry = ctx.ledger.get(&external.path);
    if let Some(entry) = entry.filter(|entry| entry.mechanism != Mechanism::Clone) {
        return conflict(format!(
            "bx attached to this path as {}, not as a clone",
            super::decide::attached_as(&entry.mechanism)
        ));
    }
    let interrupted = entry.is_some_and(|entry| entry.written == clone_written(None));

    match observed.kind {
        Kind::Absent => {
            let created_dirs = match missing_dirs(&dest, ctx.home) {
                Ok(dirs) => dirs,
                Err(note) => return conflict(note),
            };
            let what = if interrupted {
                format!("completes an interrupted clone: clones {url} at {rev}")
            } else if entry.is_some() {
                format!("the checkout bx cloned is gone; clones {url} at {rev} again")
            } else {
                format!("clones {url} at {rev}")
            };
            let note = if created_dirs.is_empty() {
                what
            } else {
                let dirs: Vec<String> = created_dirs
                    .iter()
                    .rev()
                    .map(|dir| paths::to_portable(dir, ctx.home))
                    .collect();
                format!("{what}; creates {}", dirs.join(", "))
            };
            Ok((
                row(
                    Action::Create,
                    Some(Diff::checkout(None, rev, url)),
                    Some(note),
                ),
                Some(Work::Clone {
                    replace: false,
                    created_dirs,
                }),
            ))
        }
        Kind::Dir if interrupted => Ok((
            row(
                Action::Create,
                Some(Diff::checkout(None, rev, url)),
                Some(format!(
                    "removes what an interrupted clone left here and clones {url} at {rev} again"
                )),
            ),
            Some(Work::Clone {
                replace: true,
                created_dirs: Vec::new(),
            }),
        )),
        Kind::Dir => match entry {
            None => conflict(
                "exists and bx did not clone it; bx never clones into, overwrites or adopts a \
                 directory it did not create"
                    .to_string(),
            ),
            Some(entry) => decide_checkout(external, entry, &dest, ctx, &row, &blocked, &conflict),
        },
        kind => conflict(if entry.is_some() {
            format!("is {kind}, not the checkout bx cloned")
        } else {
            format!("is {kind}; bx clones only where nothing is")
        }),
    }
}

/// The outcome of a decision, as [`decide`] returns it.
type Decision = Result<(Change, Option<Work>), Error>;

/// [`decide`] for a checkout bx cloned and finished.
fn decide_checkout(
    external: &External,
    entry: &LedgerEntry,
    dest: &Path,
    ctx: &Ctx<'_>,
    row: &dyn Fn(Action, Option<Diff>, Option<String>) -> Change,
    blocked: &dyn Fn(String) -> Decision,
    conflict: &dyn Fn(String) -> Decision,
) -> Decision {
    let (git, url, rev) = (ctx.git, external.url.as_str(), external.rev.as_str());
    if let Err(note) = own_checkout(git, dest) {
        return conflict(note);
    }
    let head = match head(git, dest) {
        Ok(head) => head,
        Err(error) => return conflict(format!("git cannot read its commit: {}", problem(&error))),
    };
    match origin_url(git, dest) {
        Ok(Some(found)) if found == url => {}
        Ok(found) => {
            return blocked(format!(
                "its remote `origin` is {}, not {url}; bx fetches only from the url the \
                 configuration declares. Set it with `git -C {} remote set-url origin {url}`",
                found.unwrap_or_else(|| "not set".to_string()),
                paths::to_portable(dest, ctx.home),
            ));
        }
        Err(error) => return blocked(problem(&error)),
    }
    if head == rev {
        if entry.written == clone_written(Some(rev)) {
            return Ok((row(Action::Unchanged, None, None), None));
        }
        return Ok((
            row(
                Action::Modify,
                None,
                Some(format!(
                    "is already at {rev}; records that in the ledger, which an earlier apply \
                     stopped before doing"
                )),
            ),
            Some(Work::Record),
        ));
    }
    match dirty(git, dest) {
        Ok(false) => {}
        Ok(true) => {
            return blocked(format!(
                "has uncommitted changes; bx moves a checkout from {head} to {rev} only when \
                 `git status` shows none, and left it as it is"
            ));
        }
        Err(error) => return blocked(problem(&error)),
    }
    let forward = if has_commit(git, dest, rev) {
        match is_ancestor(git, dest, &head, rev) {
            Ok(true) => true,
            Ok(false) => {
                return blocked(not_forward(git, dest, &head, rev, entry));
            }
            Err(error) => return blocked(problem(&error)),
        }
    } else {
        false
    };
    let note = if forward {
        format!("fast-forwards from {head} to {rev}, fetching {url} first")
    } else {
        format!(
            "fetches {url} and fast-forwards from {head} to {rev}, if {rev} descends from {head}"
        )
    };
    Ok((
        row(
            Action::Modify,
            Some(Diff::checkout(Some(&head), rev, url)),
            Some(note),
        ),
        Some(Work::Advance { from: head }),
    ))
}

/// Why a checkout at `head` cannot be fast-forwarded to `rev`, which is
/// present locally and does not descend from it.
///
/// Commits `head` reaches that neither `rev` nor any remote-tracking branch
/// holds are the user's own: those are named. Otherwise the remote history
/// itself does not run from `head` to `rev`. The commit bx itself last left
/// checked out is never counted as the user's, even when it was fetched by
/// id and no branch holds it.
fn not_forward(git: &Git, dest: &Path, head: &str, rev: &str, entry: &LedgerEntry) -> String {
    let mut args = vec!["rev-list", "--count", "HEAD", "--not", rev, "--remotes"];
    if entry.written == clone_written(Some(head)) {
        args.push(head);
    }
    match git.query(dest, &args).map(|count| count.parse::<u64>()) {
        Ok(Ok(0)) => format!(
            "{rev} is not a fast-forward from its current commit {head}; bx left the checkout \
             as it is"
        ),
        Ok(Ok(count)) => format!(
            "has {count} local commit(s) not contained in {rev}; bx left the checkout as it is"
        ),
        Ok(Err(_)) => format!("{rev} is not a fast-forward from {head}; bx left it as it is"),
        Err(error) => problem(&error),
    }
}

/// The directories above `dest`, below `home`, that are not there, deepest
/// first.
///
/// # Errors
///
/// The note for a row when one of them cannot be made: something that is not
/// a directory stands where one would go, or a directory cannot be looked at.
fn missing_dirs(dest: &Path, home: &Path) -> Result<Vec<PathBuf>, String> {
    let mut missing = Vec::new();
    let mut dir = dest.parent();
    while let Some(at) = dir.filter(|at| *at != home && at.starts_with(home)) {
        match std::fs::symlink_metadata(at) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(at.to_path_buf());
                dir = at.parent();
            }
            Err(error) => {
                return Err(format!(
                    "{} cannot be looked at: {error}",
                    paths::to_portable(at, home)
                ));
            }
            Ok(_) if at.is_dir() => break,
            Ok(_) => {
                return Err(format!(
                    "{} is not a directory, so there is nowhere to clone it",
                    paths::to_portable(at, home)
                ));
            }
        }
    }
    Ok(missing)
}

/// Do every op, in order, under `lock`, and return the rows `apply` stopped
/// short of, each with why.
///
/// A stopped op changes nothing on disk and nothing in the ledger, except
/// that a clone which failed part way is removed again and its entry put back
/// as it was.
///
/// # Errors
///
/// [`Error::State`] when the ledger cannot be opened, recorded or saved, and
/// [`Error::Journal`] when a directory bx created cannot be pruned. What was
/// saved before the error stands, and every entry saved says truthfully what
/// is on disk, so the next run decides from it.
pub(super) fn execute(
    ops: Vec<Op>,
    state: &StateDir,
    home: &Path,
    git: &Git,
    lock: &ExclusiveLock,
    progress: &indicatif::ProgressBar,
) -> Result<Vec<(usize, String)>, Error> {
    let mut ledger = Ledger::open(state, lock, home)?.value;
    let mut stopped = Vec::new();
    for op in ops {
        progress.set_message(op.target.to_string());
        let outcome = match &op.work {
            Work::Clone {
                replace,
                created_dirs,
            } => clone(&op, *replace, created_dirs, &mut ledger, home, git)?,
            Work::Advance { from } => advance(&op, from, &mut ledger, git)?,
            Work::Record => record(&op, &mut ledger, git)?,
        };
        if let Err(note) = outcome {
            stopped.push((op.at, note));
        }
        progress.inc(1);
    }
    progress.finish_and_clear();
    Ok(stopped)
}

/// What one op came to: done, or stopped with the note for its row.
type Outcome = Result<(), String>;

/// Clone `op` into its path.
fn clone(
    op: &Op,
    replace: bool,
    created_dirs: &[PathBuf],
    ledger: &mut Ledger,
    home: &Path,
    git: &Git,
) -> Result<Outcome, Error> {
    let now = fs::observe(&op.dest)?;
    let interrupted = ledger
        .get(&op.target)
        .is_some_and(|entry| entry.written == clone_written(None));
    match (replace, now.kind) {
        (false, Kind::Absent) => {}
        (true, Kind::Dir) if interrupted => {
            std::fs::remove_dir_all(&op.dest).map_err(|source| journal::Error::Io {
                path: op.dest.clone(),
                source,
            })?;
        }
        (_, kind) => {
            return Ok(Err(format!(
                "is {kind} now, which is not what bx planned against; bx left it as it is"
            )));
        }
    }

    let mut made = Vec::new();
    for dir in created_dirs.iter().rev() {
        match std::fs::create_dir(dir) {
            Ok(()) => made.push(dir.clone()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                journal::prune_dirs(&deepest_first(&made))?;
                return Ok(Err(format!(
                    "{} cannot be created: {error}",
                    paths::to_portable(dir, home)
                )));
            }
        }
    }
    let made = deepest_first(&made);
    let portable = made
        .iter()
        .map(|dir| Portable::from_path(dir, home))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| {
            Error::Fs(fs::Error::NotPortable {
                path: op.dest.clone(),
                source,
            })
        })?;

    // Saved before the directory exists, so a run that stops from here on
    // leaves an entry that says the directory is bx's and unfinished.
    let before = ledger.withdrawal(&op.target);
    ledger.record(
        NewEntry::new(
            op.target.clone(),
            clone_written(None),
            fs::Mode::DEFAULT_DIR,
            Mechanism::Clone,
            PriorBytes::Absent,
        )
        .with_created_dirs(portable),
    )?;
    ledger.save()?;

    let cloned = std::fs::create_dir(&op.dest)
        .map_err(|error| format!("cannot be created: {error}"))
        .and_then(|()| populate(git, &op.dest, &op.url, &op.rev));
    match cloned {
        Ok(()) => {
            let mode = fs::observe(&op.dest)?.mode.unwrap_or(fs::Mode::DEFAULT_DIR);
            ledger.record(NewEntry::new(
                op.target.clone(),
                clone_written(Some(&op.rev)),
                mode,
                Mechanism::Clone,
                PriorBytes::Absent,
            ))?;
            ledger.save()?;
            Ok(Ok(()))
        }
        Err(note) => {
            // Everything under the path is what this run just put there.
            if std::fs::symlink_metadata(&op.dest).is_ok_and(|meta| meta.is_dir()) {
                std::fs::remove_dir_all(&op.dest).map_err(|source| journal::Error::Io {
                    path: op.dest.clone(),
                    source,
                })?;
            }
            let _ = ledger.withdraw(before);
            journal::prune_dirs(&made)?;
            ledger.save()?;
            Ok(Err(note))
        }
    }
}

/// `dirs`, deepest first.
fn deepest_first(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = dirs.to_vec();
    dirs.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    dirs
}

/// Fill the empty directory `dest` with a checkout of `rev` from `url`.
///
/// `init`, `remote add` and `fetch` rather than `clone`, so no local branch is
/// made: a branch bx created would carry commits past `rev` that `rm` could
/// not tell from the user's. The fetch takes every branch, as a clone would,
/// and then `rev` by id when no branch holds it.
///
/// The repository is made in the object format `rev` is written in, since git
/// refuses to fetch between formats: a 64-hex `rev` is SHA-256, and a 40-hex
/// one SHA-1 whatever the user's `init.defaultObjectFormat` says.
fn populate(git: &Git, dest: &Path, url: &str, rev: &str) -> Outcome {
    let run = |args: &[&str]| git.query(dest, args).map(drop).map_err(|e| problem(&e));
    run(&["init", "--quiet", object_format(rev)])?;
    run(&["remote", "add", "origin", url])?;
    fetch(git, dest, rev)?;
    run(&[
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "--quiet",
        "--detach",
        rev,
    ])?;
    match head(git, dest) {
        Ok(head) if head == rev => Ok(()),
        Ok(head) => Err(format!("git checked out {head}, not {rev}")),
        Err(error) => Err(problem(&error)),
    }
}

/// The `git init` option for the object format a full commit id `rev` is in.
fn object_format(rev: &str) -> &'static str {
    if rev.len() == 64 {
        "--object-format=sha256"
    } else {
        "--object-format=sha1"
    }
}

/// Fetch `origin`, then `rev` by id when it is still not here.
fn fetch(git: &Git, dest: &Path, rev: &str) -> Outcome {
    git.query(dest, &["fetch", "--quiet", "origin"])
        .map_err(|e| problem(&e))?;
    if !has_commit(git, dest, rev) {
        git.query(dest, &["fetch", "--quiet", "origin", rev])
            .map_err(|e| problem(&e))?;
    }
    if has_commit(git, dest, rev) {
        Ok(())
    } else {
        Err(format!("{rev} is not a commit the remote has"))
    }
}

/// Fetch, and fast-forward from `from` to `op.rev`.
fn advance(op: &Op, from: &str, ledger: &mut Ledger, git: &Git) -> Result<Outcome, Error> {
    let dest = &op.dest;
    match (head(git, dest), dirty(git, dest)) {
        (Ok(head), Ok(false)) if head == from => {}
        (Ok(head), Ok(false)) => {
            return Ok(Err(format!(
                "moved to {head} since bx planned against {from}; bx left it as it is"
            )));
        }
        (Ok(_), Ok(true)) => {
            return Ok(Err(
                "has uncommitted changes since bx planned; bx left it as it is".to_string(),
            ));
        }
        (Err(error), _) | (_, Err(error)) => return Ok(Err(problem(&error))),
    }
    if let Err(note) = fetch(git, dest, &op.rev) {
        return Ok(Err(note));
    }
    match is_ancestor(git, dest, from, &op.rev) {
        Ok(true) => {}
        Ok(false) => {
            let entry = ledger.get(&op.target).cloned();
            let note = entry.map_or_else(
                || format!("{} is not a fast-forward from {from}", op.rev),
                |entry| not_forward(git, dest, from, &op.rev, &entry),
            );
            return Ok(Err(note));
        }
        Err(error) => return Ok(Err(problem(&error))),
    }
    if let Err(error) = git.query(
        dest,
        &[
            "-c",
            "advice.detachedHead=false",
            "checkout",
            "--quiet",
            "--detach",
            &op.rev,
        ],
    ) {
        return Ok(Err(problem(&error)));
    }
    record_rev(op, ledger)?;
    Ok(Ok(()))
}

/// Record that the checkout is at `op.rev`, having checked it still is.
fn record(op: &Op, ledger: &mut Ledger, git: &Git) -> Result<Outcome, Error> {
    match head(git, &op.dest) {
        Ok(head) if head == op.rev => {}
        Ok(head) => {
            return Ok(Err(format!(
                "moved to {head} since bx planned; bx left it as it is"
            )));
        }
        Err(error) => return Ok(Err(problem(&error))),
    }
    record_rev(op, ledger)?;
    Ok(Ok(()))
}

/// Re-record `op`'s entry with its commit, keeping its created directories.
fn record_rev(op: &Op, ledger: &mut Ledger) -> Result<(), state::Error> {
    let mode = ledger
        .get(&op.target)
        .map_or(fs::Mode::DEFAULT_DIR, |entry| entry.mode);
    ledger.record(NewEntry::new(
        op.target.clone(),
        clone_written(Some(&op.rev)),
        mode,
        Mechanism::Clone,
        PriorBytes::Absent,
    ))?;
    ledger.save()
}

/// A git failure, in the words a row's note uses.
pub(crate) fn problem(error: &sync::Error) -> String {
    match error {
        sync::Error::Spawn { source, .. } => {
            format!("git could not be started: {source}; bx needs git on PATH")
        }
        sync::Error::Git { args, stderr, .. } => {
            let stderr = stderr.trim();
            if stderr.is_empty() {
                format!("`git {args}` failed")
            } else {
                format!("`git {args}` failed: {}", stderr.replace('\n', "; "))
            }
        }
        other => other.to_string(),
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
pub(crate) fn head(git: &Git, dest: &Path) -> Result<String, sync::Error> {
    git.query(dest, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
}

/// The url of `origin`, or `None` when there is no such remote.
fn origin_url(git: &Git, dest: &Path) -> Result<Option<String>, sync::Error> {
    match git.query(dest, &["config", "--get", "remote.origin.url"]) {
        Ok(url) => Ok(Some(url)),
        Err(sync::Error::Git { status, .. }) if status.code() == Some(1) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether a tracked file differs from the commit checked out, staged or not.
fn dirty(git: &Git, dest: &Path) -> Result<bool, sync::Error> {
    git.query(dest, &["status", "--porcelain", "--untracked-files=no"])
        .map(|status| !status.is_empty())
}

/// Whether `rev` is a commit `dest` already holds.
fn has_commit(git: &Git, dest: &Path, rev: &str) -> bool {
    git.query(dest, &["cat-file", "-e", &format!("{rev}^{{commit}}")])
        .is_ok()
}

/// Whether `ancestor` is `descendant` or one of its ancestors.
fn is_ancestor(
    git: &Git,
    dest: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<bool, sync::Error> {
    match git.query(dest, &["merge-base", "--is-ancestor", ancestor, descendant]) {
        Ok(_) => Ok(true),
        Err(sync::Error::Git { status, .. }) if status.code() == Some(1) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Why `rm` must leave the checkout at `dest`, or `None` when nothing in it
/// is anyone's but the remote's.
///
/// A file `git status` shows — changed, staged or untracked — and a commit
/// that no remote-tracking branch holds, on any ref or in the stash, are the
/// user's: removing the directory would lose them. The commit bx last left
/// checked out is not counted, since bx fetched it. A file the repository
/// ignores is not the user's either: the repository declares it disposable.
pub(crate) fn kept_by_rm(git: &Git, dest: &Path, entry: &LedgerEntry) -> Option<String> {
    if let Err(note) = own_checkout(git, dest) {
        return Some(note);
    }
    match git.query(dest, &["status", "--porcelain", "--untracked-files=all"]) {
        Ok(status) if status.is_empty() => {}
        Ok(_) => {
            return Some(
                "has uncommitted changes or untracked files that removing it would lose"
                    .to_string(),
            );
        }
        Err(error) => return Some(problem(&error)),
    }
    let head = match head(git, dest) {
        Ok(head) => head,
        Err(error) => return Some(problem(&error)),
    };
    let mut args = vec!["rev-list", "--count", "--all", "--not", "--remotes"];
    if entry.written == clone_written(Some(&head)) {
        args.push(&head);
    }
    match git.query(dest, &args).map(|count| count.parse::<u64>()) {
        Ok(Ok(0)) => None,
        Ok(Ok(count)) => Some(format!(
            "holds {count} commit(s) bx did not fetch, which removing it would lose"
        )),
        Ok(Err(_)) => Some("git did not say how many commits are only here".to_string()),
        Err(error) => Some(problem(&error)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Inputs, Mode, Report, run};
    use super::*;
    use crate::plan::DiffKind;
    use crate::plan::tests::inputs;
    use crate::restore::{self, Restored};
    use crate::sync::tests::{commit_all, run as git_run};
    use crate::testing::{GuardedHome, guarded_home};

    /// Where the external is checked out, relative to the home.
    const AT: &str = ".zsh/plugins/a";

    /// The url every test declares. `~/.gitconfig` rewrites it to the
    /// upstream on disk, since a declared url may not be a local path.
    const URL: &str = "https://example.invalid/upstream";

    /// The upstream's commits: `first` and `second` on `master`, and `side`
    /// on a branch of its own from `first`.
    struct Upstream {
        first: String,
        second: String,
        side: String,
    }

    /// `git` for a test: the tempdir home's configuration only, unattended.
    fn git(home: &Path) -> Git {
        crate::sync::tests::git(home).unattended()
    }

    /// An upstream repository at `~/upstream`, reachable as [`URL`].
    fn upstream(home: &GuardedHome) -> Upstream {
        let dir = home.child("upstream");
        std::fs::create_dir_all(&dir).expect("the upstream");
        std::fs::write(
            home.child(".gitconfig"),
            format!(
                "[url \"file://{}/\"]\n\tinsteadOf = https://example.invalid/\n",
                home.path().display()
            ),
        )
        .expect("~/.gitconfig");
        git_run(home.path(), &dir, &["init", "--quiet", "-b", "master"]);
        std::fs::write(dir.join("a.zsh"), "one\n").expect("a file");
        commit_all(home.path(), &dir, "first");
        let first = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
        std::fs::write(dir.join("a.zsh"), "two\n").expect("a file");
        commit_all(home.path(), &dir, "second");
        let second = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
        git_run(
            home.path(),
            &dir,
            &["checkout", "--quiet", "-b", "side", &first],
        );
        std::fs::write(dir.join("side.zsh"), "side\n").expect("a file");
        commit_all(home.path(), &dir, "side");
        let side = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
        git_run(home.path(), &dir, &["checkout", "--quiet", "master"]);
        Upstream {
            first,
            second,
            side,
        }
    }

    /// One `[[external]]` at [`AT`] from [`URL`] at `rev`.
    fn layer(rev: &str) -> String {
        format!("[[external]]\npath = \"~/{AT}\"\nurl = \"{URL}\"\nrev = \"{rev}\"\n")
    }

    /// The inputs for `layer`, seeing git as a test does.
    fn load(home: &GuardedHome, layer: &str) -> Inputs {
        inputs(home, layer).with_git(git(home.path()))
    }

    fn plan(home: &GuardedHome, layer: &str) -> Report {
        run(&load(home, layer), Mode::Plan, &mut |_| {
            panic!("plan never asks")
        })
        .expect("plan runs")
    }

    fn apply(home: &GuardedHome, layer: &str) -> Report {
        run(&load(home, layer), Mode::Apply, &mut |_| Ok(true)).expect("apply runs")
    }

    /// Apply `layer`, running `change` once the decision is made and before
    /// any of its work is done, as a user acting between the two would.
    fn apply_after(home: &GuardedHome, layer: &str, mut change: impl FnMut()) -> Report {
        run(&load(home, layer), Mode::Apply, &mut |_| {
            change();
            Ok(true)
        })
        .expect("apply runs")
    }

    /// The one row `applied` stopped short of, and its note.
    fn stopped_note(applied: &Report) -> String {
        assert_eq!(applied.stopped, [0], "{applied:?}");
        let row = only(applied);
        assert_eq!(row.action, Action::Blocked);
        row.note.clone().expect("a note")
    }

    /// The commit checked out at [`AT`].
    fn checked_out(home: &GuardedHome) -> String {
        git_run(home.path(), &home.child(AT), &["rev-parse", "HEAD"])
    }

    fn entry(home: &GuardedHome) -> Option<LedgerEntry> {
        let target = Portable::parse_in(&format!("~/{AT}"), home.path()).expect("a target");
        LedgerView::read(&StateDir::resolve(home.path()), home.path())
            .expect("the ledger")
            .value
            .get(&target)
            .cloned()
    }

    fn target(home: &GuardedHome) -> Portable {
        Portable::parse_in(&format!("~/{AT}"), home.path()).expect("a target")
    }

    fn rm(home: &GuardedHome) -> Vec<Restored> {
        restore::restore_with(
            &StateDir::resolve(home.path()),
            home.path(),
            &[target(home)],
            &git(home.path()),
        )
        .expect("rm")
    }

    fn only(report: &Report) -> &Change {
        assert_eq!(report.changes.len(), 1, "{:?}", report.changes);
        &report.changes[0]
    }

    #[test]
    fn an_absent_external_is_a_create_that_clones_at_rev_and_then_converges() {
        let home = guarded_home();
        let up = upstream(&home);

        let planned = plan(&home, &layer(&up.first));
        let row = only(&planned);
        assert_eq!(row.action, Action::Create);
        assert_eq!(row.target, format!("~/{AT}"));
        assert_eq!(
            row.diff.as_ref().map(|diff| &diff.kind),
            Some(&DiffKind::Checkout {
                from: None,
                to: up.first.clone(),
                url: URL.to_string(),
            })
        );
        let note = row.note.as_deref().expect("a note");
        assert!(
            note.contains(&format!("clones {URL} at {}", up.first)),
            "{note}"
        );
        assert!(note.contains("creates ~/.zsh, ~/.zsh/plugins"), "{note}");
        assert!(!home.child(".zsh").exists(), "plan writes nothing");

        let applied = apply(&home, &layer(&up.first));
        assert!(
            applied.executed && applied.stopped.is_empty(),
            "{applied:?}"
        );
        assert_eq!(checked_out(&home), up.first);
        assert_eq!(
            std::fs::read_to_string(home.child(AT).join("a.zsh")).expect("the checkout"),
            "one\n"
        );
        let recorded = entry(&home).expect("recorded");
        assert_eq!(recorded.mechanism, Mechanism::Clone);
        assert_eq!(recorded.written, clone_written(Some(&up.first)));
        assert_eq!(
            recorded
                .created_dirs
                .iter()
                .map(Portable::as_str)
                .collect::<Vec<_>>(),
            ["~/.zsh/plugins", "~/.zsh"]
        );
        assert!(
            git_run(
                home.path(),
                &home.child(AT),
                &["for-each-ref", "refs/heads"]
            )
            .is_empty(),
            "bx makes no local branch"
        );

        // Converged: the second plan is empty, and neither it nor a second
        // apply reaches the remote, which is gone.
        std::fs::rename(home.child("upstream"), home.child("gone")).expect("move the remote");
        assert_eq!(
            plan(&home, &layer(&up.first)).actions(),
            [Action::Unchanged]
        );
        let again = apply(&home, &layer(&up.first));
        assert_eq!(again.actions(), [Action::Unchanged]);
        assert!(!again.executed, "nothing to do");
    }

    #[test]
    fn a_clone_is_made_in_the_object_format_its_rev_is_written_in() {
        // A SHA-256 upstream: a 64-hex rev is cloned into a SHA-256 checkout.
        let home = guarded_home();
        let up = upstream(&home);
        let dir = home.child("upstream");
        std::fs::remove_dir_all(&dir).expect("the SHA-1 upstream");
        std::fs::create_dir(&dir).expect("the upstream");
        git_run(
            home.path(),
            &dir,
            &["init", "--quiet", "-b", "master", "--object-format=sha256"],
        );
        std::fs::write(dir.join("a.zsh"), "one\n").expect("a file");
        commit_all(home.path(), &dir, "first");
        let rev = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
        assert_eq!(rev.len(), 64);

        let applied = apply(&home, &layer(&rev));
        assert!(applied.stopped.is_empty(), "{applied:?}");
        assert_eq!(checked_out(&home), rev);
        assert_eq!(
            git_run(
                home.path(),
                &home.child(AT),
                &["rev-parse", "--show-object-format"]
            ),
            "sha256"
        );
        assert_eq!(plan(&home, &layer(&rev)).actions(), [Action::Unchanged]);
        drop(up);

        // A 40-hex rev is SHA-1 even where the user's git makes SHA-256.
        let home = guarded_home();
        let up = upstream(&home);
        let mut config = std::fs::read_to_string(home.child(".gitconfig")).expect("the config");
        config.push_str("[init]\n\tdefaultObjectFormat = sha256\n");
        std::fs::write(home.child(".gitconfig"), config).expect("~/.gitconfig");
        let applied = apply(&home, &layer(&up.first));
        assert!(applied.stopped.is_empty(), "{applied:?}");
        assert_eq!(checked_out(&home), up.first);
    }

    #[test]
    fn a_rev_that_moved_is_a_modify_naming_both_commits_and_apply_fast_forwards() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));

        let planned = plan(&home, &layer(&up.second));
        let row = only(&planned);
        assert_eq!(row.action, Action::Modify);
        assert_eq!(
            row.diff.as_ref().map(|diff| &diff.kind),
            Some(&DiffKind::Checkout {
                from: Some(up.first.clone()),
                to: up.second.clone(),
                url: URL.to_string(),
            })
        );
        let note = row.note.as_deref().expect("a note");
        assert!(
            note.contains(&up.first) && note.contains(&up.second),
            "{note}"
        );

        let applied = apply(&home, &layer(&up.second));
        assert!(applied.stopped.is_empty(), "{applied:?}");
        assert_eq!(checked_out(&home), up.second);
        assert_eq!(
            entry(&home).expect("recorded").written,
            clone_written(Some(&up.second))
        );
        assert_eq!(
            plan(&home, &layer(&up.second)).actions(),
            [Action::Unchanged]
        );
    }

    #[test]
    fn a_commit_fetched_only_at_apply_is_fast_forwarded_to() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        // A commit the checkout has never fetched.
        let dir = home.child("upstream");
        std::fs::write(dir.join("a.zsh"), "three\n").expect("a file");
        commit_all(home.path(), &dir, "third");
        let third = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);

        let planned = plan(&home, &layer(&third));
        let note = only(&planned).note.clone().expect("a note");
        assert!(note.starts_with(&format!("fetches {URL}")), "{note}");
        let applied = apply(&home, &layer(&third));
        assert!(applied.stopped.is_empty(), "{applied:?}");
        assert_eq!(checked_out(&home), third);
    }

    #[test]
    fn a_rev_that_is_not_a_fast_forward_is_blocked_and_the_checkout_is_left() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.second));

        let planned = plan(&home, &layer(&up.side));
        let row = only(&planned);
        assert_eq!(row.action, Action::Blocked);
        let note = row.note.as_deref().expect("a note");
        assert!(note.contains("is not a fast-forward"), "{note}");
        let applied = apply(&home, &layer(&up.side));
        assert_eq!(applied.actions(), [Action::Blocked]);
        assert_eq!(checked_out(&home), up.second, "left as it was");
    }

    #[test]
    fn a_rev_fetched_only_at_apply_that_is_not_a_fast_forward_stops_there() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        // A branch the checkout has never fetched, diverging from `second`.
        let dir = home.child("upstream");
        git_run(
            home.path(),
            &dir,
            &["checkout", "--quiet", "-b", "later", &up.second],
        );
        std::fs::write(dir.join("a.zsh"), "later\n").expect("a file");
        commit_all(home.path(), &dir, "later");
        let later = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
        // Move the checkout to `side` by hand, as a user might, then commit.
        let at = home.child(AT);
        git_run(
            home.path(),
            &at,
            &["checkout", "--quiet", "--detach", &up.side],
        );
        std::fs::write(at.join("mine.zsh"), "mine\n").expect("a file");
        commit_all(home.path(), &at, "mine");
        let mine = checked_out(&home);

        let planned = plan(&home, &layer(&later));
        assert_eq!(only(&planned).action, Action::Modify, "{planned:?}");
        let applied = apply(&home, &layer(&later));
        assert_eq!(applied.stopped, [0]);
        let row = only(&applied);
        assert_eq!(row.action, Action::Blocked);
        let note = row.note.as_deref().expect("a note");
        assert!(
            note.contains("has 1 local commit(s) not contained in"),
            "{note}"
        );
        assert_eq!(
            checked_out(&home),
            mine,
            "the user's commit is where it was"
        );
        assert_eq!(
            entry(&home).expect("recorded").written,
            clone_written(Some(&up.first)),
            "the ledger is unchanged"
        );
    }

    #[test]
    fn a_checkout_with_uncommitted_changes_or_local_commits_is_blocked() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        let at = home.child(AT);

        std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
        let row = only(&plan(&home, &layer(&up.second))).clone();
        assert_eq!(row.action, Action::Blocked);
        assert!(
            row.note
                .as_deref()
                .is_some_and(|n| n.contains("uncommitted changes")),
            "{row:?}"
        );
        apply(&home, &layer(&up.second));
        assert_eq!(
            std::fs::read_to_string(at.join("a.zsh")).expect("the edit"),
            "edited\n"
        );

        commit_all(home.path(), &at, "mine");
        let mine = checked_out(&home);
        let row = only(&plan(&home, &layer(&up.second))).clone();
        assert_eq!(row.action, Action::Blocked);
        assert!(
            row.note
                .as_deref()
                .is_some_and(|n| n.contains("has 1 local commit(s) not contained in")),
            "{row:?}"
        );
        apply(&home, &layer(&up.second));
        assert_eq!(checked_out(&home), mine);
    }

    #[test]
    fn a_directory_bx_did_not_clone_is_a_conflict_and_is_never_touched() {
        let home = guarded_home();
        let up = upstream(&home);
        std::fs::create_dir_all(home.child(AT)).expect("the user's directory");
        std::fs::write(home.child(AT).join("mine"), "mine\n").expect("the user's file");

        let row = only(&plan(&home, &layer(&up.first))).clone();
        assert_eq!(row.action, Action::Conflict);
        assert!(
            row.note
                .as_deref()
                .is_some_and(|n| n.contains("bx did not clone it")),
            "{row:?}"
        );
        let applied = apply(&home, &layer(&up.first));
        assert!(!applied.executed);
        assert!(!home.child(AT).join(".git").exists());
        assert!(entry(&home).is_none());

        // A file there is refused the same way.
        let home = guarded_home();
        let up = upstream(&home);
        std::fs::create_dir_all(home.child(".zsh/plugins")).expect("parents");
        std::fs::write(home.child(AT), "a file\n").expect("a file");
        assert_eq!(plan(&home, &layer(&up.first)).actions(), [Action::Conflict]);
    }

    #[test]
    fn a_remote_origin_other_than_the_declared_url_is_blocked() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        git_run(
            home.path(),
            &home.child(AT),
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/other",
            ],
        );
        let row = only(&plan(&home, &layer(&up.second))).clone();
        assert_eq!(row.action, Action::Blocked);
        assert!(
            row.note
                .as_deref()
                .is_some_and(|n| n.contains("its remote `origin` is https://example.invalid/other")),
            "{row:?}"
        );
    }

    #[test]
    fn a_failed_clone_is_blocked_and_leaves_nothing_behind() {
        let home = guarded_home();
        let up = upstream(&home);
        std::fs::rename(home.child("upstream"), home.child("gone")).expect("move the remote");

        let applied = apply(&home, &layer(&up.first));
        assert!(applied.executed);
        assert_eq!(applied.stopped, [0]);
        let row = only(&applied);
        assert_eq!(row.action, Action::Blocked);
        assert!(
            row.note.as_deref().is_some_and(|n| n.contains("git fetch")),
            "{row:?}"
        );
        assert!(
            !home.child(".zsh").exists(),
            "the clone and its parents are gone"
        );
        assert!(entry(&home).is_none(), "and so is its entry");
        assert_eq!(
            super::super::exit(&applied, Mode::Apply),
            crate::report::Exit::Pending
        );
    }

    #[test]
    fn an_interrupted_clone_is_removed_and_cloned_again() {
        let home = guarded_home();
        let up = upstream(&home);
        // What a clone that stopped part way leaves: an unfinished entry and a
        // half-populated directory.
        let state = StateDir::resolve(home.path());
        state.ensure().expect("the state directory");
        {
            let lock = ExclusiveLock::acquire(&state).expect("the lock");
            let mut ledger = Ledger::open(&state, &lock, home.path())
                .expect("open")
                .value;
            ledger
                .record(NewEntry::new(
                    target(&home),
                    clone_written(None),
                    fs::Mode::DEFAULT_DIR,
                    Mechanism::Clone,
                    PriorBytes::Absent,
                ))
                .expect("record");
            ledger.save().expect("save");
        }
        std::fs::create_dir_all(home.child(AT).join(".git")).expect("a partial clone");
        std::fs::write(home.child(AT).join("half"), "half\n").expect("a partial file");

        let row = only(&plan(&home, &layer(&up.first))).clone();
        assert_eq!(row.action, Action::Create);
        assert!(
            row.note
                .as_deref()
                .is_some_and(|n| n.contains("removes what an interrupted clone left")),
            "{row:?}"
        );
        let applied = apply(&home, &layer(&up.first));
        assert!(applied.stopped.is_empty(), "{applied:?}");
        assert!(!home.child(AT).join("half").exists());
        assert_eq!(checked_out(&home), up.first);
        assert_eq!(
            plan(&home, &layer(&up.first)).actions(),
            [Action::Unchanged]
        );

        // With the directory gone too, the entry alone still reads as
        // interrupted, and the next apply completes it.
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        std::fs::remove_dir_all(home.child(AT)).expect("the user removed it");
        let row = only(&plan(&home, &layer(&up.first))).clone();
        assert_eq!(row.action, Action::Create);
        assert!(
            row.note.as_deref().is_some_and(|n| n.contains("is gone")),
            "{row:?}"
        );
    }

    #[test]
    fn a_checkout_at_rev_the_ledger_does_not_record_is_recorded() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        // An apply that moved the checkout and stopped before saving.
        git_run(
            home.path(),
            &home.child(AT),
            &["fetch", "--quiet", "origin"],
        );
        git_run(
            home.path(),
            &home.child(AT),
            &["checkout", "--quiet", "--detach", &up.second],
        );

        let row = only(&plan(&home, &layer(&up.second))).clone();
        assert_eq!(row.action, Action::Modify);
        assert!(
            row.note
                .as_deref()
                .is_some_and(|n| n.contains("records that")),
            "{row:?}"
        );
        apply(&home, &layer(&up.second));
        assert_eq!(
            entry(&home).expect("recorded").written,
            clone_written(Some(&up.second))
        );
        assert_eq!(
            plan(&home, &layer(&up.second)).actions(),
            [Action::Unchanged]
        );
    }

    #[test]
    fn a_path_that_appears_after_plan_is_not_cloned_into() {
        let home = guarded_home();
        let up = upstream(&home);
        let applied = apply_after(&home, &layer(&up.first), || {
            std::fs::create_dir_all(home.child(AT)).expect("the user's directory");
            std::fs::write(home.child(AT).join("mine"), "mine\n").expect("the user's file");
        });
        let note = stopped_note(&applied);
        assert!(
            note.contains("is a directory now, which is not what bx planned against"),
            "{note}"
        );
        assert_eq!(
            std::fs::read_to_string(home.child(AT).join("mine")).expect("the user's file"),
            "mine\n"
        );
        assert!(!home.child(AT).join(".git").exists(), "nothing cloned");
        assert!(entry(&home).is_none(), "nothing recorded");
    }

    #[test]
    fn a_checkout_that_changed_after_plan_is_not_fast_forwarded() {
        // Edited between plan and apply.
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        let at = home.child(AT);
        let applied = apply_after(&home, &layer(&up.second), || {
            std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
        });
        let note = stopped_note(&applied);
        assert!(
            note.contains("has uncommitted changes since bx planned"),
            "{note}"
        );
        assert_eq!(checked_out(&home), up.first);
        assert_eq!(
            std::fs::read_to_string(at.join("a.zsh")).expect("the edit"),
            "edited\n"
        );
        assert_eq!(
            entry(&home).expect("recorded").written,
            clone_written(Some(&up.first))
        );

        // Moved to another commit between plan and apply.
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        let at = home.child(AT);
        let applied = apply_after(&home, &layer(&up.second), || {
            git_run(home.path(), &at, &["fetch", "--quiet", "origin"]);
            git_run(
                home.path(),
                &at,
                &["checkout", "--quiet", "--detach", &up.side],
            );
        });
        let note = stopped_note(&applied);
        assert!(
            note.contains(&format!(
                "moved to {} since bx planned against {}",
                up.side, up.first
            )),
            "{note}"
        );
        assert_eq!(checked_out(&home), up.side, "left where the user put it");
        assert_eq!(
            entry(&home).expect("recorded").written,
            clone_written(Some(&up.first))
        );
    }

    #[test]
    fn a_checkout_that_moved_after_plan_is_not_recorded_at_rev() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        let at = home.child(AT);
        // The stale ledger `Work::Record` exists for: at `second`, recorded
        // at `first`.
        git_run(home.path(), &at, &["fetch", "--quiet", "origin"]);
        git_run(
            home.path(),
            &at,
            &["checkout", "--quiet", "--detach", &up.second],
        );

        let applied = apply_after(&home, &layer(&up.second), || {
            git_run(
                home.path(),
                &at,
                &["checkout", "--quiet", "--detach", &up.first],
            );
        });
        let note = stopped_note(&applied);
        assert!(
            note.contains(&format!("moved to {} since bx planned", up.first)),
            "{note}"
        );
        assert_eq!(checked_out(&home), up.first);
        assert_eq!(
            entry(&home).expect("recorded").written,
            clone_written(Some(&up.first)),
            "the ledger still says what is there"
        );
    }

    #[test]
    fn a_path_bx_holds_another_way_or_under_a_file_is_a_conflict() {
        let home = guarded_home();
        let up = upstream(&home);
        std::fs::write(home.child(".zsh"), "a file\n").expect("a file where a parent goes");
        let row = only(&plan(&home, &layer(&up.first))).clone();
        assert_eq!(row.action, Action::Conflict, "{row:?}");

        let home = guarded_home();
        let up = upstream(&home);
        crate::plan::tests::own(home.path(), ".zsh-a", b"x", Mechanism::Own);
        let layer = format!(
            "[[external]]\npath = \"~/.zsh-a\"\nurl = \"{URL}\"\nrev = \"{}\"\n",
            up.first
        );
        let row = only(&plan(&home, &layer)).clone();
        assert_eq!(row.action, Action::Conflict);
        assert!(
            row.note
                .as_deref()
                .is_some_and(|n| n.contains("the whole file")),
            "{row:?}"
        );
    }

    #[test]
    fn rm_removes_a_clean_clone_and_the_directories_bx_created_for_it() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));

        let done = rm(&home);
        assert!(
            matches!(done.as_slice(), [Restored::Removed { .. }]),
            "{done:?}"
        );
        assert!(
            !home.child(".zsh").exists(),
            "the checkout and its parents are gone"
        );
        assert!(entry(&home).is_none());
        assert!(
            matches!(rm(&home).as_slice(), [Restored::Unmanaged { .. }]),
            "a second rm is a no-op"
        );
    }

    #[test]
    fn bx_rm_of_the_path_or_a_directory_above_it_removes_the_clone() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        let ctx = crate::adopt::Context::load(&crate::plan::tests::env(home.path()))
            .expect("the context");
        let above = Portable::parse_in("~/.zsh", home.path()).expect("a path");

        let removals = crate::adopt::rm(&ctx, &above).expect("rm");

        assert_eq!(removals.len(), 1, "{removals:?}");
        assert!(matches!(removals[0].restored, Restored::Removed { .. }));
        assert!(!home.child(AT).exists());
        assert!(entry(&home).is_none());
    }

    #[test]
    fn rm_leaves_a_clone_holding_anything_of_the_users() {
        for (what, change) in [
            ("an edit", "edit"),
            ("an untracked file", "untracked"),
            ("a local commit", "commit"),
            ("a stash", "stash"),
        ] {
            let home = guarded_home();
            let up = upstream(&home);
            apply(&home, &layer(&up.first));
            let at = home.child(AT);
            match change {
                "edit" => std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit"),
                "untracked" => std::fs::write(at.join("new"), "new\n").expect("a file"),
                "commit" => {
                    std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
                    commit_all(home.path(), &at, "mine");
                }
                _ => {
                    std::fs::write(at.join("a.zsh"), "edited\n").expect("an edit");
                    git_run(home.path(), &at, &["stash", "--quiet"]);
                }
            }

            let done = rm(&home);
            assert!(
                matches!(done.as_slice(), [Restored::Conflict { .. }]),
                "{what}: {done:?}"
            );
            assert!(at.join(".git").exists(), "{what}: the checkout stays");
            assert!(entry(&home).is_some(), "{what}: and so does its entry");
        }
    }

    #[test]
    fn rm_ignores_what_the_repository_ignores_and_counts_a_rev_fetched_by_id() {
        let home = guarded_home();
        let up = upstream(&home);
        let dir = home.child("upstream");
        std::fs::write(dir.join(".gitignore"), "*.zwc\n").expect("an ignore file");
        commit_all(home.path(), &dir, "ignore");
        // A commit no branch holds, which the clone has to fetch by id.
        git_run(home.path(), &dir, &["checkout", "--quiet", "--detach"]);
        std::fs::write(dir.join("a.zsh"), "loose\n").expect("a file");
        commit_all(home.path(), &dir, "loose");
        let loose = git_run(home.path(), &dir, &["rev-parse", "HEAD"]);
        git_run(home.path(), &dir, &["checkout", "--quiet", "master"]);
        git_run(
            home.path(),
            &dir,
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );

        let applied = apply(&home, &layer(&loose));
        assert!(applied.stopped.is_empty(), "{applied:?}");
        assert_eq!(checked_out(&home), loose);
        std::fs::write(home.child(AT).join("a.zsh.zwc"), "compiled").expect("an ignored file");

        let done = rm(&home);
        assert!(
            matches!(done.as_slice(), [Restored::Removed { .. }]),
            "{done:?}"
        );
        assert!(!home.child(AT).exists());
        let _ = up.second;
    }

    #[test]
    fn rm_removes_an_unfinished_clone_whole_and_forgets_one_already_gone() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        // An rm that stopped part way: the entry says unfinished, and the
        // checkout holds what would otherwise stop an rm.
        std::fs::write(home.child(AT).join("new"), "new\n").expect("a file");
        let state = StateDir::resolve(home.path());
        {
            let lock = ExclusiveLock::acquire(&state).expect("the lock");
            let mut ledger = Ledger::open(&state, &lock, home.path())
                .expect("open")
                .value;
            ledger
                .record(NewEntry::new(
                    target(&home),
                    clone_written(None),
                    fs::Mode::DEFAULT_DIR,
                    Mechanism::Clone,
                    PriorBytes::Absent,
                ))
                .expect("record");
            ledger.save().expect("save");
        }
        assert!(matches!(rm(&home).as_slice(), [Restored::Removed { .. }]));
        assert!(!home.child(".zsh").exists());

        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        std::fs::remove_dir_all(home.child(AT)).expect("the user removed it");
        assert!(matches!(
            rm(&home).as_slice(),
            [Restored::AlreadyGone { .. }]
        ));
        assert!(entry(&home).is_none());
        assert!(
            home.child(".zsh/plugins").is_dir(),
            "rm announced no removal of a parent, as for a file already gone"
        );
    }

    #[test]
    fn rm_leaves_something_that_is_not_the_checkout() {
        let home = guarded_home();
        let up = upstream(&home);
        apply(&home, &layer(&up.first));
        std::fs::remove_dir_all(home.child(AT)).expect("the user removed it");
        std::fs::write(home.child(AT), "a file\n").expect("and put a file there");
        assert!(matches!(rm(&home).as_slice(), [Restored::Conflict { .. }]));
        assert!(home.child(AT).is_file());
    }

    #[test]
    fn a_problem_names_what_git_said() {
        let home = guarded_home();
        let missing = Git::at_home(home.path()).with_env("PATH", "");
        let spawn = missing
            .query(home.path(), &["status"])
            .expect_err("no git on an empty PATH");
        assert!(problem(&spawn).contains("bx needs git on PATH"));
        let failed = git(home.path())
            .query(home.path(), &["rev-parse", "--verify", "no-such-ref"])
            .expect_err("no such ref");
        assert!(problem(&failed).starts_with("`git rev-parse --verify no-such-ref` failed"));
    }
}
