//! Declared git externals: one decision per `[[external]]`, and the work it
//! announces.
//!
//! An external is a repository bx keeps checked out at one commit, pinned by
//! `rev` or locked in `bx.lock`. Its
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
use crate::config::external::{External, Follow, Pin};
use crate::config::lock::{self, Lock, Locked, Lookup};
use crate::fs::{self, Kind};
use crate::git::checkout::{has_commit, head, is_ancestor, origin_url, own_checkout, problem};
use crate::git::{self, Git};
use crate::journal;
use crate::paths::{self, Portable};
use crate::report::Action;
use crate::state::{
    self, ExclusiveLock, Ledger, LedgerEntry, LedgerView, Mechanism, NewEntry, PriorBytes,
    StateDir, clone_written,
};

/// What a decision may read: nothing it could change.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ctx<'a> {
    /// The ledger, as it was read once for the whole run.
    pub ledger: &'a LedgerView,
    /// The account's home, which every path renders against.
    pub home: &'a Path,
    /// The `git` every question is put to.
    pub git: &'a Git,
    /// The commits followed externals are kept at.
    pub lock: &'a Lock,
    /// Every external the committed layers declare on their own, or `None`
    /// when that is unknown: what `bx update` locks a follow for.
    pub committed: Option<&'a [External]>,
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
        let rev = match rev(external, ctx.lock) {
            Ok(rev) => rev,
            Err((follow, stale)) => {
                let note = unlocked_note(external, follow, stale, ctx.committed, " yet");
                rows.push(Change {
                    target: external.path.as_str().to_string(),
                    origin: external.origin.clone(),
                    action: Action::Blocked,
                    diff: None,
                    note: Some(note),
                });
                continue;
            }
        };
        let (change, work) = decide(external, rev, ctx)?;
        rows.push(change);
        if let Some(work) = work {
            ops.push(Op {
                at,
                target: external.path.clone(),
                dest: external.path.render(ctx.home),
                url: external.url.clone(),
                rev: rev.to_string(),
                work,
            });
        }
    }
    Ok((rows, ops))
}

/// The commit `external` is kept at: its `rev`, or what `lock` holds for the
/// branch it follows.
///
/// # Errors
///
/// The branch followed, and what `lock` holds for another url or branch at
/// its path, if anything, when a followed external has no commit locked for
/// the url and branch it declares. Nothing is guessed: `plan` and `apply`
/// never ask a remote where a branch is, so only `bx update` can say.
pub(crate) fn rev<'a>(
    external: &'a External,
    lock: &'a Lock,
) -> Result<&'a str, (&'a Follow, Option<&'a Locked>)> {
    let follow = match &external.pin {
        Pin::Rev(rev) => return Ok(rev),
        Pin::Follow(follow) => follow,
    };
    match lock.lookup(external) {
        Lookup::Locked(rev) => Ok(rev),
        Lookup::Missing => Err((follow, None)),
        Lookup::Stale(locked) => Err((follow, Some(locked))),
    }
}

/// What a followed `external` that `bx.lock` does not hold says, in `plan`'s
/// blocked row and in `doctor`'s finding alike: it follows `follow`, and the
/// lock holds `stale` for it, or nothing ([`rev`]), where `missing` is what
/// the note says after "holds no commit for it".
///
/// `bx update` locks the follow, unless `local.toml` alone declares it or
/// points it elsewhere than `committed` does, which the shared `bx.lock`
/// never takes; the note then names what does lock it.
pub(crate) fn unlocked_note(
    external: &External,
    follow: &Follow,
    stale: Option<&Locked>,
    committed: Option<&[External]>,
    missing: &str,
) -> String {
    let remedy = lock::unshared_remedy(external, committed).map(|unshared| match unshared {
        lock::Unshared::Elsewhere => {
            "`bx update` locks the branch and url the committed configuration follows here, \
             not this one; pin it with `rev`"
        }
        lock::Unshared::NotCommitted => {
            "`bx update` locks only what the committed configuration follows; declare it in \
             a committed layer, or pin it with `rev`"
        }
    });
    match stale {
        None => format!(
            "follows `{}`, and {} holds no commit for it{missing}; {}",
            follow.branch,
            lock::FILE,
            remedy.unwrap_or("`bx update` locks one")
        ),
        Some(locked) => format!(
            "follows `{}` of {}, and {} locks it for `{}` of {}; {}",
            follow.branch,
            external.url,
            lock::FILE,
            locked.branch,
            locked.url,
            remedy.unwrap_or("`bx update` locks it again")
        ),
    }
}

/// Decide one external kept at `rev`: its row, and the work `apply` does for
/// it.
fn decide(external: &External, rev: &str, ctx: &Ctx<'_>) -> Decision {
    let dest = external.path.render(ctx.home);
    let observed = fs::observe(&dest)?;
    let url = external.url.as_str();
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
            Some(entry) => {
                decide_checkout((url, rev), entry, &dest, ctx, &row, &blocked, &conflict)
            }
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
    (url, rev): (&str, &str),
    entry: &LedgerEntry,
    dest: &Path,
    ctx: &Ctx<'_>,
    row: &dyn Fn(Action, Option<Diff>, Option<String>) -> Change,
    blocked: &dyn Fn(String) -> Decision,
    conflict: &dyn Fn(String) -> Decision,
) -> Decision {
    let git = ctx.git;
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
                fs::remove::prune_dirs(&deepest_first(&made)).map_err(journal::Error::from)?;
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
            fs::remove::prune_dirs(&made).map_err(journal::Error::from)?;
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

/// Whether the ledger records `path` as a clone bx made and finished: the one
/// kind of directory bx fetches into, or reads an external's children from.
#[must_use]
pub(crate) fn finished_clone(ledger: &LedgerView, path: &Portable) -> bool {
    finished_clone_entry(ledger, path).is_some()
}

/// The ledger's entry for `path` when it records a clone bx made and
/// finished, as [`finished_clone`] judges it; `None` otherwise.
#[must_use]
pub(crate) fn finished_clone_entry<'a>(
    ledger: &'a LedgerView,
    path: &Portable,
) -> Option<&'a LedgerEntry> {
    ledger
        .get(path)
        .filter(|entry| entry.mechanism == Mechanism::Clone && entry.written != clone_written(None))
}

/// Whether the ledger records `path` as a clone of bx's, finished or not: a
/// directory an apply clones into, or clones again, rather than someone
/// else's.
#[must_use]
pub(crate) fn bx_clone(ledger: &LedgerView, path: &Portable) -> bool {
    ledger
        .get(path)
        .is_some_and(|entry| entry.mechanism == Mechanism::Clone)
}

/// Whether a tracked file differs from the commit checked out, staged or not.
fn dirty(git: &Git, dest: &Path) -> Result<bool, git::Error> {
    git.query(dest, &["status", "--porcelain", "--untracked-files=no"])
        .map(|status| !status.is_empty())
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
mod tests;
