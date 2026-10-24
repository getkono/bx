//! `bx update`'s machinery: asking a followed external's remote where its
//! branch is, writing and committing `bx.lock`, and the stamps an interactive
//! shell reads to decide whether to ask.
//!
//! The command itself — pull, look, show the plan, confirm, lock, commit,
//! apply — is [`crate::command::update`], beside `apply` and `sync`, whose
//! rendering and confirmation it shares. What lives here is what is `bx
//! update`'s alone.
//!
//! # Looking
//!
//! [`look`] asks where a followed external's branch is now. A checkout bx
//! cloned, at the url declared, is fetched into — `git fetch origin
//! refs/heads/BRANCH`, which adds objects and moves no file in the working
//! tree — so the commit is then here, and the `plan` that follows can list
//! the children a link would make from it, and tell a fast-forward from a
//! rewritten branch, without reaching the network again. An external with no
//! checkout yet is asked with `git ls-remote`, which fetches nothing. Every
//! command is the user's own `git`, unattended
//! ([`crate::git::Git::unattended`]), so a missing credential fails rather
//! than waits.
//!
//! A branch that was rewritten, so its new tip does not descend from the
//! commit locked, is reported and **never locked**: following a branch is
//! consent to its new commits, not to whatever its history is replaced with.
//! Pin the external with `rev` to take such a commit deliberately.
//!
//! # Stamps
//!
//! An interactive shell decides whether to ask about updates by reading the
//! files in the state directory's `update/` with shell builtins, and starts
//! no process to do it (Invariant 6):
//!
//! | file        | holds                                                                 |
//! |-------------|-----------------------------------------------------------------------|
//! | `ask-due`   | when to next ask whether to check, in seconds since the epoch         |
//! | `check-due` | when to next check without asking, for `check = "auto"` externals     |
//! | `available` | `gen` and the offer's [`generation`], then one line per external a check found new commits for |
//! | `answered`  | the generation of the offer, or `ask` and the `ask-due` of the question, a shell last had answered |
//! | `waiting/`  | one file per shell waiting on a prompt, named by its pid               |
//! | `judged`    | the [`fingerprint`] of the `bx.lock` here when `available` was written |
//!
//! The first three, and `judged`, are written whole by [`Stamps`] and nothing
//! else; no shell reads `judged`. A
//! missing or unreadable `ask-due` or `check-due` is never due: a machine that
//! has not run `bx update` or `bx apply` since it began following a branch is
//! not asked, rather than asked at once.
//!
//! # Shells asking at once
//!
//! Every shell at a prompt sees the same offer, and the first answer settles
//! it for all of them. The shell answered writes `answered` with a builtin
//! redirect before it starts `bx update` or `bx update --snooze`, so a shell
//! opened a moment later is not asked while either still runs, and wakes each
//! shell in `waiting/` with the `kill` builtin's `SIGURG`, so one already
//! asking gives way at once rather than at its timeout. Nothing polls and
//! nothing watches: a waiting shell sleeps in its `read` until a key, the
//! signal or the timeout. [`Stamps::set`] wakes them too whenever it changes
//! what is offered or asked, so a `bx update` run by hand withdraws open
//! prompts, and clears `answered` with `available`, so the same commits are
//! offered again once the next interval's check finds them still unapplied.
//! A `bx update` that stops short — declined, abandoned at its question,
//! refused or failed — answers the offer instead ([`settled`]) and says why in
//! `last-check`, which `bx doctor` names when it failed or was refused, until
//! a `bx update` that finishes removes it ([`finished`]) or a background check
//! overwrites it with what it found ([`check`]); only one turned away
//! because another holds the stamps records nothing, as that one settles them.
//!
//! # Another machine's lock
//!
//! The config repo is shared, so another machine may already have locked the
//! commits a check finds. Every check, a person's `bx update --check` and the
//! background one alike, therefore fetches the config repo's upstream first —
//! objects and its remote-tracking ref, never the branch or the working tree
//! — and, when this machine's branch is only behind it, judges each external
//! against the `bx.lock` the upstream holds, which is the one `bx update`
//! would lock on top of after its pull. A commit the upstream already locks
//! is offered to nobody: the check says another machine updated it and
//! `bx sync` brings it in. A config repo that is not a git repository of its
//! own, has no upstream, cannot be fetched or has diverged is judged against
//! this machine's `bx.lock`, and the check says why: a background one in
//! `last-check`, always, and a person's on the terminal unless there is no
//! repository or no upstream at all, as then this machine's lock is the
//! only one. Either way, what the check exits with is decided by the
//! externals alone.
//!
//! An offer is only true of the `bx.lock` it was judged against, so `judged`
//! records which one that was. A `bx apply` or `bx sync` that applies another
//! `bx.lock` withdraws the offer ([`relocked`]) and makes the next prompt check
//! again; one that is declined leaves it standing. A check carries forward no
//! line an earlier check judged against another `bx.lock`.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::external::{Check, External, first_followed};
use crate::config::lock::{self, Lock, Locked, Unshared};
use crate::config::update::Interval;
use crate::fs::Mode;
use crate::git::checkout::{self, problem};
use crate::git::{self, Git};
use crate::paths::{self, Portable};
use crate::plan::external::finished_clone;
use crate::state::StateDir;
use crate::sync;

/// How long `bx update --background` may take, from start to finish:
/// counted from when [`check`] begins, before the configuration is loaded, so
/// a slow load leaves the remotes less time rather than the check more.
pub const BACKGROUND_BOUND: Duration = Duration::from_secs(30);

// A snooze that gives up waiting writes nothing, so a check still running
// would leave its offer standing; the snooze waits longer than any check may
// take, so it only gives up on a person's `bx update` or a `bx sync`.
const _: () = assert!(BACKGROUND_BOUND.as_secs() < SNOOZE_WAIT.as_secs());

/// How long a foreground `bx update` waits on one remote.
pub const LOOK_BOUND: Duration = Duration::from_secs(60);

/// The most commits a move lists by subject.
const LOG_LIMIT: usize = 20;

/// Everything that stops `bx update`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Loading, planning or applying failed.
    #[error(transparent)]
    Plan(#[from] crate::plan::Error),
    /// Pulling the config repo, or committing to it, failed.
    #[error(transparent)]
    Sync(#[from] sync::Error),
    /// `bx.lock` holds an edit nobody committed.
    #[error(
        "{} has changes that are not committed; bx update commits the lock it writes, and \
         would commit those with it. Commit or discard them, then run bx update again",
        .0.display()
    )]
    LockEdited(PathBuf),
    /// A path named on the command line is not a followed external.
    #[error(
        "`{0}` is not an [[external]] that follows a branch; bx update moves only those. Name \
         one by its `path`, or name none to update them all"
    )]
    NotFollowed(String),
    /// This machine's unpushed `bx update` commits and the upstream both
    /// changed `bx.lock`, or a tracked copy one of them carried.
    #[error(
        "this machine has {commits} unpushed bx update commit(s), and another machine pushed \
         its own bx.lock or tracked file over the same file; nothing was changed. To take the \
         other machine's, run `git -C {} reset --keep @{{upstream}}`, then bx update again; to \
         keep this one's, merge by hand and run bx sync",
        .repo.display()
    )]
    LockDiverged {
        /// How many of this machine's `bx update` commits are unpushed.
        commits: usize,
        /// The config repo.
        repo: PathBuf,
    },
    /// A rebase stands open in the config repo.
    #[error(
        "a rebase or `git am` is in progress in the config repo {}; finish it, or abort it \
         with `git -C {} rebase --abort` (or `am --abort`), then bx update again",
        .0.display(),
        .0.display()
    )]
    Rebasing(PathBuf),
    /// Another `bx update`, `bx sync` or check holds `update/check.lock`.
    #[error(
        "another bx update or bx sync is running, in this shell or another; let it finish, \
         then run bx update again"
    )]
    Busy,
    /// `bx.lock`, or a file under the state directory, could not be written.
    /// Every [`crate::fs::Error`] names its own path, so this adds none.
    #[error(transparent)]
    Write(crate::fs::Error),
    /// A file under the state directory could not be removed, or
    /// `update/check.lock` could not be opened or locked.
    #[error("{op} {}: {source}", .path.display())]
    Io {
        /// What was being done to the file: `removing`, `opening` or
        /// `locking`.
        op: &'static str,
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The state directory could not be made.
    #[error(transparent)]
    State(#[from] crate::state::Error),
    /// Writing to the output failed.
    #[error("writing output: {0}")]
    Output(#[source] std::io::Error),
}

/// A git command in the config repo failed: reported as `bx sync`'s own git
/// failures are.
impl From<git::Error> for Error {
    fn from(error: git::Error) -> Self {
        Self::Sync(error.into())
    }
}

/// What a remote says about one followed external, against its lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The external's path.
    pub path: Portable,
    /// The url declared.
    pub url: String,
    /// The branch it follows.
    pub branch: String,
    /// The commit `bx.lock` holds for it, when the entry matches.
    pub locked: Option<String>,
    /// What the branch's tip means for it.
    pub verdict: Verdict,
}

/// What a branch's tip means for the commit locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The tip is the commit locked.
    Current,
    /// The tip is a commit to lock: the first one, or one that descends from
    /// the commit locked.
    Moves {
        /// The tip.
        tip: String,
        /// The new commits' short ids and subjects, newest first, at most
        /// twenty of them; `None` when no checkout could list them.
        log: Option<Vec<String>>,
        /// How many new commits there are, when a checkout could count them.
        count: Option<u64>,
    },
    /// The tip does not descend from the commit locked.
    Rewritten {
        /// The tip.
        tip: String,
    },
    /// The tip differs from the commit locked, and with no checkout of bx's
    /// there is nothing to show it descends from it.
    Unproven {
        /// The tip.
        tip: String,
    },
    /// The remote could not be asked.
    Unreachable(String),
}

impl Found {
    /// The commit to lock, when there is one.
    #[must_use]
    pub fn moves_to(&self) -> Option<&str> {
        match &self.verdict {
            Verdict::Moves { tip, .. } => Some(tip),
            _ => None,
        }
    }

    /// One line saying what was found, as `bx update` prints it and the
    /// shell's question repeats it.
    #[must_use]
    pub fn summary(&self) -> String {
        let (path, branch) = (&self.path, &self.branch);
        match &self.verdict {
            Verdict::Current => format!("{path}: up to date with {branch}"),
            Verdict::Moves { tip, count, .. } => match (&self.locked, count) {
                (None, _) => format!("{path}: locks {branch} at {}", short(tip)),
                (Some(from), Some(count)) => format!(
                    "{path}: {count} new commit(s) on {branch}, {} -> {}",
                    short(from),
                    short(tip)
                ),
                (Some(from), None) => {
                    format!("{path}: {branch} moved, {} -> {}", short(from), short(tip))
                }
            },
            Verdict::Rewritten { tip } => format!(
                "{path}: {branch} was rewritten; its tip {} does not descend from {}, so it \
                 is not locked. Pin a commit with `rev` to take it",
                short(tip),
                self.locked.as_deref().map_or("the commit locked", short)
            ),
            Verdict::Unproven { tip } => format!(
                "{path}: {branch} is at {}, and with no checkout of bx's there is nothing to \
                 show it descends from {}, so it is not locked. Run `bx update` again once \
                 `bx apply` has cloned it",
                short(tip),
                self.locked.as_deref().map_or("the commit locked", short)
            ),
            Verdict::Unreachable(why) => format!("{path}: not checked: {why}"),
        }
    }
}

/// A commit id's first twelve digits.
fn short(rev: &str) -> &str {
    rev.get(..12).unwrap_or(rev)
}

/// Every followed external `names` selects, in configuration order: all of
/// them when `names` is empty.
///
/// # Errors
///
/// [`Error::NotFollowed`] for a name that is not a followed external's path.
pub fn select<'a>(
    externals: &'a [External],
    names: &[String],
    home: &Path,
) -> Result<Vec<&'a External>, Error> {
    let followed: Vec<&External> = externals.iter().filter(|e| e.follows().is_some()).collect();
    if names.is_empty() {
        return Ok(followed);
    }
    let mut chosen = Vec::new();
    for name in names {
        let path = Portable::parse_in(name, home)
            .or_else(|_| Portable::from_path(&paths::normalize(Path::new(name)), home))
            .map_err(|_| Error::NotFollowed(name.clone()))?;
        let external = followed
            .iter()
            .find(|external| external.path == path)
            .ok_or_else(|| Error::NotFollowed(name.clone()))?;
        if !chosen.iter().any(|c: &&External| c.path == external.path) {
            chosen.push(*external);
        }
    }
    Ok(chosen)
}

/// How long [`look_all`] lets `git` wait on the remotes it asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// Each remote on its own, for [`LOOK_BOUND`] from when it is asked: a
    /// person's check, or `bx update`, where one remote that never answers
    /// holds the question up for a minute rather than until Ctrl-C.
    EachRemote,
    /// Every remote together, until this deadline, each `git` in its own
    /// process group: the background check.
    Background(std::time::Instant),
}

/// [`look`] at each of `chosen`, with no prompt from `git` and its time
/// bounded by `bound`, in the order chosen.
///
/// Never fails, as [`look`] does not.
#[must_use]
pub fn look_all(
    git: &Git,
    bound: Bound,
    home: &Path,
    chosen: &[&External],
    lock: &Lock,
    ledger: &crate::state::LedgerView,
) -> Vec<Found> {
    chosen
        .iter()
        .map(|external| {
            let looker = git.clone().unattended();
            let looker = match bound {
                Bound::EachRemote => looker.with_deadline(std::time::Instant::now() + LOOK_BOUND),
                Bound::Background(deadline) => looker.with_deadline(deadline).in_own_group(),
            };
            look(&looker, home, external, lock, ledger)
        })
        .collect()
}

/// Ask where `external`'s branch is, against the commit `lock` holds.
///
/// Never fails: a remote that cannot be asked is
/// [`Verdict::Unreachable`], so one external offline does not keep the
/// others from being looked at.
///
/// Only a checkout the ledger records as bx's own finished clone is fetched
/// into: a directory the user made at the path — which `plan` reports as a
/// conflict — is never touched, and its remote is asked with `ls-remote`.
///
/// A new tip is a move only once it is shown to descend from the commit
/// locked. When the checkout lacks the locked commit it is fetched by id
/// first; when that fails — a force-push took it from the remote — or there
/// is no checkout to ask, nothing can show it, and the verdict is
/// [`Verdict::Unproven`] or [`Verdict::Rewritten`], never a lock.
///
/// # Panics
///
/// When `external` follows no branch: only a followed external is looked at,
/// and every caller selects those first.
#[must_use]
pub fn look(
    git: &Git,
    home: &Path,
    external: &External,
    lock: &Lock,
    ledger: &crate::state::LedgerView,
) -> Found {
    let follow = external
        .follows()
        .expect("only a followed external is looked at");
    let locked = match lock.lookup(external) {
        lock::Lookup::Locked(rev) => Some(rev.to_string()),
        lock::Lookup::Missing | lock::Lookup::Stale(_) => None,
    };
    let found = |verdict| Found {
        path: external.path.clone(),
        url: external.url.clone(),
        branch: follow.branch.clone(),
        locked: locked.clone(),
        verdict,
    };
    let dest = external.path.render(home);
    let reference = format!("refs/heads/{}", follow.branch);
    let ours = finished_clone(ledger, &external.path)
        && dest.is_dir()
        && checkout::own_checkout(git, &dest).is_ok()
        && matches!(checkout::origin_url(git, &dest), Ok(Some(url)) if url == external.url);

    let tip = if ours {
        git.query(
            &dest,
            &["fetch", "--quiet", "--no-tags", "origin", &reference],
        )
        .and_then(|_| {
            git.query(
                &dest,
                &["rev-parse", "--verify", "--quiet", "FETCH_HEAD^{commit}"],
            )
        })
        .map_err(|error| problem(&error))
    } else {
        remote_tip(git, home, &external.url, &reference)
    };
    let tip = match tip {
        Ok(tip) => tip,
        Err(why) => return found(Verdict::Unreachable(why)),
    };
    let Some(from) = locked.as_deref() else {
        return found(Verdict::Moves {
            tip,
            log: None,
            count: None,
        });
    };
    if from == tip {
        return found(Verdict::Current);
    }
    if !ours {
        return found(Verdict::Unproven { tip });
    }
    // Asked for by id whether or not it is here, which costs nothing when it
    // is; what decides is whether it is here afterwards.
    let _ = git.query(&dest, &["fetch", "--quiet", "--no-tags", "origin", from]);
    if !checkout::has_commit(git, &dest, from) {
        // The remote no longer has the commit locked: its branch was
        // rewritten past it, whatever the new tip says.
        return found(Verdict::Rewritten { tip });
    }
    match checkout::is_ancestor(git, &dest, from, &tip) {
        Ok(true) => {
            let range = format!("{from}..{tip}");
            let count = git
                .query(&dest, &["rev-list", "--count", &range])
                .ok()
                .and_then(|count| count.parse().ok());
            let limit = format!("--max-count={LOG_LIMIT}");
            let log = git
                .query(
                    &dest,
                    &["log", &limit, "--no-decorate", "--format=%h %s", &range],
                )
                .ok()
                .map(|log| log.lines().map(str::to_string).collect());
            found(Verdict::Moves { tip, log, count })
        }
        Ok(false) => found(Verdict::Rewritten { tip }),
        Err(error) => found(Verdict::Unreachable(problem(&error))),
    }
}

/// The commit `reference` names on the remote at `url`, asked with
/// `git ls-remote` from `home`, which needs no repository.
fn remote_tip(git: &Git, home: &Path, url: &str, reference: &str) -> Result<String, String> {
    match git.query(home, &["ls-remote", "--exit-code", url, reference]) {
        Ok(listed) => listed
            .lines()
            .find_map(|line| {
                let (rev, name) = line.split_once('\t')?;
                (name == reference).then(|| rev.to_string())
            })
            .ok_or_else(|| format!("{url} has no {reference}")),
        Err(git::Error::Failed { status, .. }) if status.code() == Some(2) => {
            Err(format!("{url} has no {reference}"))
        }
        Err(error) => Err(problem(&error)),
    }
}

/// `lock` with every move in `found` set, and every entry nothing follows
/// any more dropped.
///
/// `bx.lock` is committed and shared, while `externals` is this account's
/// merged configuration, `local.toml` included; `committed` is what the
/// committed layers alone declare, or `None` when they cannot be merged
/// without it. So an entry is kept while either follows its path — an
/// external one account switched off, or moved, in its own `local.toml` is
/// still another machine's — and a move is set only for what the committed
/// configuration follows from the same url and branch ([`unshared`]). A
/// follow `local.toml` alone declares, or points elsewhere, is never locked:
/// every other machine would drop the entry, and this one lock it again at
/// whatever tip it found, with nothing locked to check it against.
/// With `committed` unknown, no entry is dropped.
#[must_use]
pub fn proposed(
    lock: &Lock,
    found: &[Found],
    externals: &[External],
    committed: Option<&[External]>,
) -> Lock {
    let mut next = lock.clone();
    for found in found {
        if let Some(tip) = found.moves_to() {
            if unshared(found, committed) {
                continue;
            }
            next.set(
                found.path.clone(),
                Locked {
                    url: found.url.clone(),
                    branch: found.branch.clone(),
                    rev: tip.to_string(),
                },
            );
        }
    }
    next.retain(|path| kept(path, externals, committed));
    next
}

/// Whether [`proposed`] keeps the lock entry for `path`: while `externals`,
/// this account's merged configuration, or `committed`, the committed layers
/// alone, follows it, and always while `committed` is unknown.
#[must_use]
pub fn kept(path: &Portable, externals: &[External], committed: Option<&[External]>) -> bool {
    lock::followed(path, externals) || committed.is_none_or(|c| lock::followed(path, c))
}

/// Whether the committed configuration, where it is known, does not follow
/// `found`'s path from the url and branch this account's does: a follow that
/// `local.toml` alone declares, or points elsewhere, whose commit the shared
/// `bx.lock` does not take ([`lock::unshared_at`]).
#[must_use]
pub fn unshared(found: &Found, committed: Option<&[External]>) -> bool {
    lock::unshared_at(&found.path, &found.url, &found.branch, committed)
}

/// Why `found`'s follow is [`unshared`], or `None` when it is not.
#[must_use]
pub fn why_unshared(found: &Found, committed: Option<&[External]>) -> Option<Unshared> {
    lock::why_unshared_at(&found.path, &found.url, &found.branch, committed)
}

/// The commit message for moving `before` to `after`: what moved, by path,
/// and nothing about the machine, the account or the time.
#[must_use]
pub fn message(before: &Lock, after: &Lock) -> String {
    let mut lines = Vec::new();
    for (path, locked) in after.iter() {
        match before.get(path) {
            Some(old) if old == locked => {}
            Some(old) => lines.push(format!(
                "{path}: {} {} -> {}",
                locked.branch,
                short(&old.rev),
                short(&locked.rev)
            )),
            None => lines.push(format!(
                "{path}: {} at {}",
                locked.branch,
                short(&locked.rev)
            )),
        }
    }
    for (path, _) in before.iter() {
        if after.get(path).is_none() {
            lines.push(format!("{path}: no longer followed"));
        }
    }
    format!("{SUBJECT}\n\n{}\n", lines.join("\n"))
}

/// The subject of every commit `bx update` makes.
pub const SUBJECT: &str = "chore(bx): update bx.lock";

/// What opens the line [`settled`] writes to `last-check` when `bx update`
/// failed or the config repo refused it, before the error itself; `bx doctor`
/// names such a line.
pub const STOPPED: &str = "bx update stopped: ";

/// What [`replay_own_commits`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// A local commit is not one `bx update` made; nothing was touched.
    NotOwn,
    /// This many of `bx update`'s commits now sit on top of the upstream.
    Replayed(usize),
    /// The upstream changed a file they change too, so they could not be
    /// replayed; the branch is as it was.
    Conflicted(usize),
}

/// When the config repo's branch has diverged from its upstream only by
/// commits `bx update` makes, each with one parent — a lock commit, with
/// [`SUBJECT`] and touching `bx.lock` alone, or a carry of tracked copies,
/// with [`sync::CARRIED_SUBJECT`] and not touching `bx.lock` — replay them on
/// top of the upstream, as `git rebase` does. Every lock and copy they held
/// is kept, so nothing needs approving again. When the upstream changed one
/// of their files as well — anywhere in it, whether or not git could merge
/// the two — the replay is never started, and the branch is left exactly as
/// it was: which machine's lock or copy to keep is a person's call. Any other
/// local commit is left alone too.
///
/// # Errors
///
/// [`Error::Sync`] when git cannot list the commits, or a replay failed and
/// was put back, and [`Error::Rebasing`] when a replay that failed could not
/// be put back, so it stands open for a person to finish or abort.
pub fn replay_own_commits(git: &Git, repo: &Path) -> Result<Replay, Error> {
    let listed = git.query(
        repo,
        &["rev-list", "--format=%P%x00%s", "@{upstream}..HEAD"],
    )?;
    let mut commits = 0;
    let mut ours = std::collections::BTreeSet::new();
    for pair in listed.lines().collect::<Vec<_>>().chunks(2) {
        let [header, body] = pair else {
            return Ok(Replay::NotOwn);
        };
        let Some(commit) = header.strip_prefix("commit ") else {
            return Ok(Replay::NotOwn);
        };
        let (parents, subject) = body.split_once('\0').unwrap_or((body, ""));
        if parents.split_whitespace().count() != 1 {
            return Ok(Replay::NotOwn);
        }
        let touched = git.query(
            repo,
            &["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
        )?;
        let own = match subject {
            SUBJECT => touched == lock::FILE,
            // Tracked copies only: never the lock, which is a lock commit's.
            sync::CARRIED_SUBJECT => {
                !touched.is_empty() && !touched.lines().any(|path| path == lock::FILE)
            }
            _ => false,
        };
        if !own {
            return Ok(Replay::NotOwn);
        }
        ours.extend(touched.lines().map(str::to_string));
        commits += 1;
    }
    if commits == 0 {
        return Ok(Replay::NotOwn);
    }
    // Any file both sides changed to different bytes is refused before the
    // replay, not only one whose hunks overlap: git would merge edits to
    // different lines of it, and keep neither machine's lock or copy as it
    // was. One both changed alike is the upstream already holding it.
    let theirs = git.query(repo, &["diff", "--name-only", "HEAD...@{upstream}"])?;
    let apart = git.query(repo, &["diff", "--name-only", "HEAD", "@{upstream}"])?;
    if theirs
        .lines()
        .any(|path| ours.contains(path) && apart.lines().any(|differs| differs == path))
    {
        return Ok(Replay::Conflicted(commits));
    }
    // Through `commit`, so the user's own signing can ask what it asks.
    let replayed = git.commit(
        repo,
        &[
            "-c",
            "rebase.autoStash=false",
            "rebase",
            "--quiet",
            "--no-autosquash",
            "@{upstream}",
        ],
    );
    match replayed {
        // Counted again: a commit the upstream already holds is dropped.
        Ok(_) => Ok(Replay::Replayed(
            git.query(repo, &["rev-list", "--count", "@{upstream}..HEAD"])?
                .parse()
                .unwrap_or(0),
        )),
        // Never started — a working tree in the way, a refusing hook — and
        // nothing to undo: git's own words say why.
        Err(error) if !rebasing(git, repo) => Err(error.into()),
        Err(error) => {
            // Asked before the abort, and never in its way: a replay is
            // never left open by choice. One whose abort fails is open all
            // the same, and is named as one, as the next run would name it.
            let unmerged = git
                .query(repo, &["diff", "--name-only", "--diff-filter=U"])
                .unwrap_or_default();
            if git.query(repo, &["rebase", "--abort"]).is_err() {
                return Err(Error::Rebasing(repo.to_path_buf()));
            }
            if unmerged.is_empty() {
                // Stopped for something else, signing above all.
                Err(error.into())
            } else {
                Ok(Replay::Conflicted(commits))
            }
        }
    }
}

/// Whether a rebase stands open in the config repo at `repo`.
#[must_use]
pub fn rebasing(git: &Git, repo: &Path) -> bool {
    ["rebase-merge", "rebase-apply"].iter().any(|name| {
        git.query(repo, &["rev-parse", "--git-path", name])
            .is_ok_and(|path| repo.join(path).exists())
    })
}

/// Refuse a `bx.lock` with changes git has not committed, which a commit of
/// the lock would sweep up: one git has never seen among them, as a run
/// killed before its first lock was committed leaves it, or as one written by
/// hand is. A config repo git does not manage has nothing to refuse.
///
/// # Errors
///
/// [`Error::LockEdited`].
pub fn refuse_edited_lock(git: &Git, repo: &Path) -> Result<(), Error> {
    let path = Lock::path_in(repo);
    match git.query(
        repo,
        &[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            lock::FILE,
        ],
    ) {
        Ok(status) if !status.is_empty() => Err(Error::LockEdited(path)),
        _ => Ok(()),
    }
}

/// Write `lock` to the config repo at `repo`, and commit it there with
/// `message`, staging that one file. Returns whether a commit was made: none
/// when the repo is not a git repository of its own.
///
/// # Errors
///
/// [`Error::Write`] when the file cannot be written, and [`Error::Sync`] when
/// git refuses the commit, as a failing hook makes it.
///
/// A commit git refuses puts the file back as it was, and unstages it, so a
/// later `apply` never moves a checkout to a commit the repo does not name.
/// Only a run killed between the write and the commit can leave the new
/// bytes uncommitted, and the next `bx update` refuses to go on until they
/// are committed or discarded ([`refuse_edited_lock`]).
pub fn write_and_commit(git: &Git, repo: &Path, lock: &Lock, message: &str) -> Result<bool, Error> {
    let path = Lock::path_in(repo);
    let prior = std::fs::read(&path).ok();
    let write = |bytes: &[u8]| {
        crate::fs::write_atomically(&path, bytes, Mode::DEFAULT_FILE).map_err(Error::Write)
    };
    write(lock.render().as_bytes())?;
    if checkout::toplevel_is_self(git, repo).is_err() {
        return Ok(false);
    }
    let committed = git
        .query(repo, &["add", "--", lock::FILE])
        .and_then(|_| git.query(repo, &["diff", "--cached", "--name-only", "--", lock::FILE]))
        .and_then(|staged| {
            if staged.is_empty() {
                return Ok(false);
            }
            git.commit(
                repo,
                &["commit", "--quiet", "-m", message, "--", lock::FILE],
            )
            .map(|_| true)
        });
    match committed {
        Ok(made) => Ok(made),
        Err(error) => {
            let _ = git.query(repo, &["reset", "--quiet", "--", lock::FILE]);
            match &prior {
                Some(bytes) => write(bytes)?,
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
            Err(error.into())
        }
    }
}

/// The update stamps in a state directory's `update/`.
#[derive(Debug, Clone)]
pub struct Stamps {
    dir: PathBuf,
    state: StateDir,
}

/// When a stamp falls due, in seconds since the epoch.
type Epoch = u64;

impl Stamps {
    /// The stamps of `state`.
    #[must_use]
    pub fn of(state: &StateDir) -> Self {
        Self {
            dir: state.update(),
            state: state.clone(),
        }
    }

    /// `ask-due`.
    #[must_use]
    pub fn ask_due(&self) -> PathBuf {
        self.dir.join("ask-due")
    }

    /// `check-due`.
    #[must_use]
    pub fn check_due(&self) -> PathBuf {
        self.dir.join("check-due")
    }

    /// `available`.
    #[must_use]
    pub fn available(&self) -> PathBuf {
        self.dir.join("available")
    }

    /// `last-check`: what the last background check said, for a person
    /// wondering why a shell asked or did not.
    #[must_use]
    pub fn last_check(&self) -> PathBuf {
        self.dir.join("last-check")
    }

    /// `answered`: the generation of the offer, or `ask <epoch>` of the
    /// question, a shell last had answered, so no other shell asks it again.
    #[must_use]
    pub fn answered(&self) -> PathBuf {
        self.dir.join("answered")
    }

    /// `judged`: the [`fingerprint`] of the `bx.lock` this machine had when
    /// `available` was last written, which [`relocked`] compares with the one
    /// it has now.
    #[must_use]
    pub fn judged(&self) -> PathBuf {
        self.dir.join("judged")
    }

    /// `waiting/`: one file per shell whose prompt is waiting for an answer,
    /// named by its pid and non-empty while it waits.
    #[must_use]
    pub fn waiting(&self) -> PathBuf {
        self.dir.join("waiting")
    }

    /// Set `ask-due` to `now` plus `ask`, or removed when no external asks
    /// first; `check-due` to `now` plus `check`, or removed when no external
    /// checks on its own; and `available` to `available`'s lines under their
    /// [`generation`], or removed, with `answered` and `judged`, when there
    /// are none. A
    /// stamp given as `None` is left as it is. Once `available` or `ask-due`
    /// is written, every shell waiting on a prompt is woken ([`Stamps::wake`])
    /// to see whether what it asks still stands.
    ///
    /// # Errors
    ///
    /// [`Error::State`] when the directory cannot be made, [`Error::Write`]
    /// when a file cannot be written, and [`Error::Io`] when one cannot be
    /// removed.
    pub fn set(
        &self,
        now: Epoch,
        ask: Option<Option<Interval>>,
        check: Option<Option<Interval>>,
        available: Option<&[String]>,
    ) -> Result<(), Error> {
        self.state.ensure_update()?;
        // Made beside every stamp a shell asks from, so its prompt can
        // register with a redirect and start no process.
        if let Err(source) = std::fs::create_dir_all(self.waiting()) {
            return Err(Error::Io {
                op: "making",
                path: self.waiting(),
                source,
            });
        }
        for (path, interval) in [(self.ask_due(), ask), (self.check_due(), check)] {
            match interval {
                Some(Some(interval)) => {
                    self.write(&path, &format!("{}\n", now + interval.seconds()))?;
                }
                Some(None) => self.remove(&path)?,
                None => {}
            }
        }
        match available {
            Some([]) => {
                self.remove(&self.available())?;
                self.remove(&self.answered())?;
                self.remove(&self.judged())?;
            }
            Some(lines) => {
                let text: String = std::iter::once(format!("gen {}\n", generation(lines)))
                    .chain(lines.iter().map(|line| format!("{line}\n")))
                    .collect();
                self.write(&self.available(), &text)?;
            }
            None => {}
        }
        if available.is_some() || ask.is_some() {
            self.wake();
        }
        Ok(())
    }

    /// Wake every shell waiting on a prompt with `SIGURG`, so it reads the
    /// stamps again and gives way when what it asks was answered or
    /// replaced; and remove the file of every shell that is gone.
    ///
    /// Best effort: a shell this cannot reach still gives up at its prompt's
    /// timeout. A file whose pid is gone — `kill(pid, 0)` says no such
    /// process — or belongs to another account, which no shell of this one's
    /// is, is a shell that exited without letting go, and is removed. One
    /// whose pid a new process of this account took is signalled once more
    /// before it is removed in its turn, which costs nothing: `SIGURG` is
    /// ignored by any process that does not ask for it.
    pub fn wake(&self) {
        let Ok(entries) = std::fs::read_dir(self.waiting()) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .filter(|name| !name.starts_with('0') && name.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|name| name.parse().ok())
                .and_then(rustix::process::Pid::from_raw)
            else {
                continue;
            };
            match rustix::process::test_kill_process(pid) {
                Err(rustix::io::Errno::SRCH | rustix::io::Errno::PERM) => {
                    let _ = std::fs::remove_file(entry.path());
                }
                Ok(()) if entry.metadata().is_ok_and(|meta| meta.len() > 0) => {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::URG);
                }
                _ => {}
            }
        }
    }

    /// Whether the prompt hook ([`crate::shell::update_prompt`]) offers what
    /// `available` holds to a shell that has not yet asked about it, given
    /// `answered`: the stamps' bytes, either `None` where the file is absent.
    ///
    /// It reads them as the hook's `read -r` does: whole lines only, each less
    /// the spaces and tabs around it. A first line `gen G` is the offer's
    /// generation, and the lines after it are what is offered; one without it,
    /// as an older bx wrote it, is offered as it stands under the generation
    /// `old:` and its first line. Something is offered while there is a line to
    /// offer, unless the first line of `answered`, read the same way, is its
    /// generation.
    #[must_use]
    pub fn offers(available: Option<&[u8]>, answered: Option<&[u8]>) -> bool {
        let trim = |line: &[u8]| -> Vec<u8> {
            let blank = |byte: &u8| matches!(byte, b' ' | b'\t');
            let start = line.iter().position(|b| !blank(b)).unwrap_or(line.len());
            let stop = line
                .iter()
                .rposition(|b| !blank(b))
                .map_or(start, |l| l + 1);
            line[start..stop].to_vec()
        };
        let mut lines: Vec<Vec<u8>> = available
            .unwrap_or_default()
            .split_inclusive(|&byte| byte == b'\n')
            .filter_map(|line| line.strip_suffix(b"\n"))
            .map(trim)
            .collect();
        let generation = match lines.first() {
            Some(first) if first.starts_with(b"gen ") => lines.remove(0)[4..].to_vec(),
            Some(first) => [b"old:".as_slice(), first].concat(),
            None => Vec::new(),
        };
        let answered = answered
            .unwrap_or_default()
            .split(|&byte| byte == b'\n')
            .next()
            .map(trim)
            .unwrap_or_default();
        !lines.is_empty() && generation != answered
    }

    /// The epoch in `path`, or `None` when it is absent or holds none.
    ///
    /// A stamp holds a time exactly when the prompt hook
    /// ([`crate::shell::update_prompt`]) would read one from it: a first line
    /// ended by a newline that, less the spaces and tabs around it, is one or
    /// more ASCII digits. That is what the hook's `read -r` and its `<->` and
    /// `*[!0-9]*` tests accept, so `bx doctor` names a stamp as holding no time
    /// exactly when no shell asks from it — `+12`, `12\r` and a line with no
    /// newline included. A number past `u64` holds none here either, though a
    /// shell's arithmetic would wrap it; bx never writes one. The file is read
    /// as bytes, because the hook never looks past the first line: what
    /// follows it, valid UTF-8 or not, changes nothing.
    #[must_use]
    pub fn read(path: &Path) -> Option<Epoch> {
        let bytes = std::fs::read(path).ok()?;
        let end = bytes.iter().position(|&byte| byte == b'\n')?;
        let blank = |byte: &u8| matches!(byte, b' ' | b'\t');
        let line = &bytes[..end];
        let start = line.iter().position(|byte| !blank(byte)).unwrap_or(end);
        let stop = line
            .iter()
            .rposition(|byte| !blank(byte))
            .map_or(start, |last| last + 1);
        let digits = &line[start..stop];
        // `parse` alone would also take a leading `+`.
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    }

    /// Write `text` to `path` whole.
    ///
    /// # Errors
    ///
    /// [`Error::Write`].
    pub(crate) fn write(&self, path: &Path, text: &str) -> Result<(), Error> {
        crate::fs::write_atomically(path, text.as_bytes(), Mode::PRIVATE_FILE).map_err(Error::Write)
    }

    /// Remove `path` if it is there.
    fn remove(&self, path: &Path) -> Result<(), Error> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Io {
                op: "removing",
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

/// How often the externals in `externals` set to `check = "auto"` are
/// checked: the shortest of their intervals, each defaulting to `default`.
/// `None` when none is.
#[must_use]
pub fn check_interval(externals: &[External], default: Interval) -> Option<Interval> {
    externals
        .iter()
        .filter_map(|external| match external.follows()?.check {
            Check::Auto(interval) => Some(interval.unwrap_or(default)),
            Check::Ask => None,
        })
        .min()
}

/// How often a shell asks whether to check: `interval`, when an external in
/// `externals` follows a branch with `check = "ask"`, and `None` when every
/// one checks on its own, or none follows a branch.
#[must_use]
pub fn ask_interval(externals: &[External], interval: Interval) -> Option<Interval> {
    externals
        .iter()
        .any(|external| matches!(external.follows().map(|f| f.check), Some(Check::Ask)))
        .then_some(interval)
}

/// The time now, in seconds since the epoch.
#[must_use]
pub fn now() -> Epoch {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `bx update --check`, or with `background` `bx update --background`: look
/// for new commits and say what was found, changing nothing but the stamps
/// and the objects fetched into checkouts.
///
/// A foreground check looks at every followed external `names` selects, says
/// what it found, and counts as the check an interactive shell would have
/// asked about, so `ask-due` moves on too. A background check looks only at
/// the externals set to `check = "auto"`, runs only when no other one is, is
/// bounded by [`BACKGROUND_BOUND`], writes what it found to `last-check`
/// rather than to the terminal, and moves `check-due` on before it reaches
/// the network, so a check that fails is not retried at every prompt. Both
/// fetch the config repo's upstream and judge against the `bx.lock` that
/// holds when this machine is behind it ([`against_upstream`]), and say
/// which lock they judged against ([`said`]). Either way, every external with new commits gets a line in `available`, which the
/// next prompt offers to apply; lines for externals this check did not look
/// at are kept.
///
/// Exits [`crate::report::Exit::Pending`] when there is something to apply.
/// Otherwise a foreground check that could not check some external — its
/// remote unreachable, or without the branch it follows — exits
/// [`crate::report::Exit::Error`], so "could not look" never reads as "up to
/// date"; a background check exits [`crate::report::Exit::Converged`].
///
/// # Errors
///
/// As [`crate::plan::Inputs::load`], [`select`] and [`Stamps::set`], and,
/// for a foreground check, [`Error::Busy`] when another check or `bx update`
/// still holds `update/check.lock` after [`HOLD_WAIT`].
pub fn check(
    env: &crate::env::Env,
    names: &[String],
    background: bool,
    git: &Git,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
    // The whole background run shares one bound, counted from here so that
    // loading the configuration spends it too; a person's check bounds each
    // remote on its own.
    let bound = if background {
        Bound::Background(std::time::Instant::now() + BACKGROUND_BOUND)
    } else {
        Bound::EachRemote
    };
    let state = StateDir::resolve_in(&env.home, env.xdg_state_home.as_deref());
    let stamps = Stamps::of(&state);
    let now = now();
    let held = if background {
        stamps.try_hold()?
    } else {
        stamps.hold(HOLD_WAIT)?
    };
    let Some(_held) = held else {
        // A shell's check gives way to any other; a person's says why not.
        return if background {
            Ok(crate::report::Exit::Converged)
        } else {
            Err(Error::Busy)
        };
    };
    if !background {
        return looked(env, names, bound, git, &stamps, now, out);
    }
    // Before anything that can fail, so a configuration that does not load
    // is retried hourly, not at every new shell's first prompt.
    stamps.set(now, None, Some(Some(Interval::HOUR)), None)?;
    let result = looked(env, names, bound, git, &stamps, now, out);
    if let Err(error) = &result {
        stamps.write(
            &stamps.last_check(),
            &format!("the check failed: {error}\n"),
        )?;
    }
    result
}

/// [`check`], under `update/check.lock`.
fn looked(
    env: &crate::env::Env,
    names: &[String],
    bound: Bound,
    git: &Git,
    stamps: &Stamps,
    now: Epoch,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
    let background = matches!(bound, Bound::Background(_));
    let inputs = crate::plan::Inputs::load(env)?;
    let ledger = crate::state::LedgerView::read(inputs.state(), &env.home)
        .map_err(crate::plan::Error::from)?
        .value;
    let externals = &inputs.resolved().externals;
    let interval = inputs.resolved().update.interval();
    let auto = check_interval(externals, interval);
    if background {
        stamps.set(now, None, Some(auto), None)?;
    }
    let chosen: Vec<&External> = select(externals, names, &env.home)?
        .into_iter()
        .filter(|external| {
            !background
                || matches!(
                    external.follows().map(|follow| follow.check),
                    Some(Check::Auto(_))
                )
        })
        .collect();
    // Nothing to look at reaches no network, the config repo's included.
    let fetcher = git.clone().unattended();
    let against = match bound {
        _ if chosen.is_empty() => Against::Here,
        Bound::Background(deadline) => against_upstream(
            &fetcher.with_deadline(deadline).in_own_group(),
            inputs.repo(),
            &env.home,
            inputs.lock(),
        ),
        Bound::EachRemote => against_upstream(
            &fetcher.with_deadline(std::time::Instant::now() + LOOK_BOUND),
            inputs.repo(),
            &env.home,
            inputs.lock(),
        ),
    };
    let lock = match &against {
        Against::Upstream { lock, .. } => lock,
        Against::Here | Against::Alone(_) | Against::Unjudged(_) => inputs.lock(),
    };
    let found = look_all(git, bound, &env.home, &chosen, lock, &ledger);

    // What an earlier check offered is carried only while it was judged
    // against the bx.lock here: lines judged against another — a `git pull`
    // brought one in without an apply — would outlive the lock that made
    // them true, and `judged`, rewritten below, would no longer say so.
    let judged_here = std::fs::read_to_string(stamps.judged())
        .is_ok_and(|judged| judged.trim() == fingerprint(inputs.lock()));
    let previous = if judged_here {
        std::fs::read_to_string(stamps.available()).unwrap_or_default()
    } else {
        String::new()
    };
    let available = offered(&previous, &found);
    if background {
        stamps.set(now, None, None, Some(&available))?;
        stamps.write(&stamps.last_check(), &said(&against, inputs.lock(), &found))?;
    } else {
        let ask = ask_interval(externals, interval);
        stamps.set(now, Some(ask), Some(auto), Some(&available))?;
        // With no upstream at all, this machine's lock is the only one, and
        // saying so at every check would be noise.
        let shown = match &against {
            Against::Alone(_) => &Against::Here,
            against => against,
        };
        let said = said(shown, inputs.lock(), &found);
        out.write_all(said.as_bytes()).map_err(Error::Output)?;
        if chosen.is_empty() {
            writeln!(out, "No [[external]] follows a branch.").map_err(Error::Output)?;
        }
    }
    // Whichever lock the moves were judged against, the offer stands until
    // this machine's own changes ([`relocked`]).
    if !available.is_empty() {
        stamps.write(
            &stamps.judged(),
            &format!("{}\n", fingerprint(inputs.lock())),
        )?;
    }
    // A person's check that could not check some external — its remote
    // unreachable, or without the branch it follows — has not shown nothing
    // is new, so a script reading its status must not take it as up to date;
    // something new still wins, and the shell's own check stays quiet.
    Ok(if found.iter().any(|found| found.moves_to().is_some()) {
        crate::report::Exit::Pending
    } else if !background
        && found
            .iter()
            .any(|found| matches!(found.verdict, Verdict::Unreachable(_)))
    {
        crate::report::Exit::Error
    } else {
        crate::report::Exit::Converged
    })
}

/// The generation of an offer of `lines`: sixteen hex digits of their 64-bit
/// FNV-1a hash, each line ended by a newline.
///
/// A line names an external and the commits it moves from and to, so the same
/// moves always give the same generation, on every machine and in every
/// version: a check that finds again what a shell already had answered
/// cannot offer it again under a new name, and the bytes `available` holds
/// stay the same from one check to the next.
#[must_use]
pub fn generation(lines: &[String]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in lines.iter().flat_map(|line| line.bytes().chain(*b"\n")) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// What `available` holds after a check that found `found`: each line of
/// `previous` about an external it did not look at, then one line for each
/// external it found new commits for. `previous`'s generation line is not
/// one of them: [`Stamps::set`] writes the new one.
#[must_use]
pub fn offered(previous: &str, found: &[Found]) -> Vec<String> {
    // A remote this check could not reach says nothing new about it, so what
    // an earlier check offered stands.
    let looked: Vec<String> = found
        .iter()
        .filter(|f| !matches!(f.verdict, Verdict::Unreachable(_)))
        .map(|f| format!("{}: ", f.path))
        .collect();
    previous
        .lines()
        .filter(|line| !line.starts_with("gen "))
        .filter(|line| !looked.iter().any(|prefix| line.starts_with(prefix)))
        .map(str::to_string)
        .chain(
            found
                .iter()
                .filter(|found| found.moves_to().is_some())
                .map(Found::summary),
        )
        .collect()
}

/// Which `bx.lock` a check judges the externals against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Against {
    /// This machine's: the upstream has nothing it lacks, or holds the same
    /// lock.
    Here,
    /// The upstream's, which this machine's branch is only behind.
    Upstream {
        /// The lock the upstream holds.
        lock: Lock,
        /// The upstream, as `REMOTE/BRANCH`.
        upstream: String,
    },
    /// This machine's, because there is no upstream to judge — the config
    /// repo is no git repository of its own, or its branch tracks nothing —
    /// for the reason given. No other machine's lock can reach this one
    /// through it, so a person's check says nothing about it. A detached
    /// `HEAD` or an upstream that is gone is [`Against::Unjudged`]: another
    /// machine's lock may well be there.
    Alone(String),
    /// This machine's, because the upstream could not be judged, for the
    /// reason given.
    Unjudged(String),
}

/// Fetch the upstream of the config repo at `repo` through `git`, and say
/// which `bx.lock` a check judges against: the upstream's when this
/// machine's branch is behind it and not ahead, so the lock is the one a
/// `bx sync` or `bx update` here would fast-forward to, and it differs from
/// `here`, the lock this machine has.
///
/// The fetch adds objects and moves the remote-tracking ref, as `bx sync`'s
/// does, and never the branch or the working tree. Never fails: whatever
/// keeps the upstream from being judged is [`Against::Alone`] or
/// [`Against::Unjudged`], and the
/// check goes on against `here`.
#[must_use]
pub fn against_upstream(git: &Git, repo: &Path, home: &Path, here: &Lock) -> Against {
    if checkout::toplevel_is_self(git, repo).is_err() {
        return Against::Alone("the config repo is not a git repository of its own".to_string());
    }
    let Ok(branch) = git.query(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]) else {
        return Against::Unjudged("the config repo has no branch checked out".to_string());
    };
    let upstream = match sync::upstream(git, repo, &branch) {
        Ok(upstream) => upstream,
        Err(sync::Error::NoUpstream { .. }) => {
            return Against::Alone(format!("the config repo's {branch} has no upstream"));
        }
        Err(error) => return Against::Unjudged(error.to_string()),
    };
    let short = upstream.short.clone();
    if let Err(error) = git.query(repo, &["fetch", "--quiet", &upstream.remote]) {
        return Against::Unjudged(format!("{short} could not be fetched: {}", problem(&error)));
    }
    match sync::gone(git, repo, &branch) {
        Ok(false) => {}
        Ok(true) => {
            return Against::Unjudged(format!("{short}, which {branch} tracks, does not exist"));
        }
        Err(error) => return Against::Unjudged(error.to_string()),
    }
    let (ahead, behind) = match sync::counts(git, repo) {
        Ok(counts) => counts,
        Err(error) => return Against::Unjudged(error.to_string()),
    };
    if behind == 0 {
        return Against::Here;
    }
    if ahead > 0 {
        return Against::Unjudged(format!(
            "{branch} and {short} have diverged, so bx update would lock neither as it stands"
        ));
    }
    let spec = format!("@{{upstream}}:{}", lock::FILE);
    let theirs = match git.query(repo, &["rev-parse", "--verify", "--quiet", &spec]) {
        // The upstream holds no lock at all: every entry here is gone there.
        Err(git::Error::Failed { .. }) => Lock::default(),
        Err(error) => return Against::Unjudged(problem(&error)),
        Ok(blob) => match git.query_whole(repo, &["cat-file", "blob", &blob]) {
            Ok(text) => {
                let file = PathBuf::from(format!("{short}:{}", lock::FILE));
                match Lock::parse(&text, &file, home) {
                    Ok(theirs) => theirs,
                    Err(error) => return Against::Unjudged(error.to_string()),
                }
            }
            Err(error) => return Against::Unjudged(problem(&error)),
        },
    };
    if theirs == *here {
        Against::Here
    } else {
        Against::Upstream {
            lock: theirs,
            upstream: short,
        }
    }
}

/// What a check that judged against `against` says — a person's on the
/// terminal, a background one in `last-check`: a first line saying which lock it judged against when it
/// was not simply this machine's, then a line per external in `found`. One
/// the upstream already locks at its branch's tip, and `here` does not, is
/// named as another machine's update, which `bx sync` brings in.
#[must_use]
pub fn said(against: &Against, here: &Lock, found: &[Found]) -> String {
    let mut said = match against {
        Against::Here => String::new(),
        Against::Upstream { upstream, .. } => format!(
            "judged against bx.lock as {upstream} holds it: another machine updated it, and \
             `bx sync` brings it in\n"
        ),
        Against::Alone(why) | Against::Unjudged(why) => {
            format!("judged against this machine's bx.lock: {why}\n")
        }
    };
    for found in found {
        let theirs = matches!(against, Against::Upstream { lock, .. }
            if lock.get(&found.path) != here.get(&found.path));
        let line = match (&found.verdict, &found.locked) {
            (Verdict::Current, Some(rev)) if theirs => format!(
                "{}: another machine already locked {} at {}; `bx sync` brings it in",
                found.path,
                found.branch,
                short(rev)
            ),
            _ => found.summary(),
        };
        said.push_str(&line);
        said.push('\n');
    }
    said
}

/// The fingerprint `judged` holds of `lock`: the [`generation`] of its
/// bytes, so two machines' identical locks have the same one.
#[must_use]
pub fn fingerprint(lock: &Lock) -> String {
    generation(&[lock.render()])
}

/// Once `bx apply` or `bx sync` has applied `inputs` — approved, or with
/// nothing to apply — never when declined: when what `available`
/// offers was judged against another `bx.lock` than the one now here — a
/// sync or a `git pull` brought in another machine's — the offer is
/// withdrawn, every shell waiting on it is woken to see so, and `check-due`
/// is set to now when an external checks on its own, so the next prompt
/// checks again against this lock.
///
/// `answered` is kept: a check that finds the same moves again finds them
/// under the same generation, already answered. An `available` with no
/// `judged` beside it, as an older bx wrote it, is left alone.
///
/// Best effort: a stamp that cannot be changed costs a stale offer until the
/// next check, not the apply, so a failure is logged and nothing more.
pub fn relocked(inputs: &crate::plan::Inputs) {
    let stamps = Stamps::of(inputs.state());
    let Ok(judged) = std::fs::read_to_string(stamps.judged()) else {
        return;
    };
    if judged.trim() == fingerprint(inputs.lock()) {
        return;
    }
    let externals = &inputs.resolved().externals;
    let interval = inputs.resolved().update.interval();
    let result = stamps
        .remove(&stamps.available())
        .and_then(|()| stamps.remove(&stamps.judged()))
        .and_then(|()| match check_interval(externals, interval) {
            Some(_) => stamps.write(&stamps.check_due(), &format!("{}\n", now())),
            None => Ok(()),
        });
    stamps.wake();
    if let Err(error) = result {
        tracing::warn!(%error, "could not withdraw an offer judged against another bx.lock");
    }
}

/// `bx update --snooze`: put the next question off by one interval, and drop
/// what the last check offered. Reaches no network.
///
/// # Errors
///
/// As [`crate::plan::Inputs::load`] and [`Stamps::set`].
pub fn snooze(
    env: &crate::env::Env,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
    snooze_waiting(env, SNOOZE_WAIT, out)
}

/// [`snooze`], waiting at most `wait` for a running check to let go, and
/// giving up quietly once that wait runs out: it writes no stamp without the
/// lock.
///
/// Giving up loses no answer. The shell that answered wrote `answered`
/// before it started this, so no shell asks the same offer or question again
/// while it stands; a person's `bx update` holding the lock through its
/// question settles the stamps itself, and a `bx sync` holding it leaves them,
/// `answered` with them, as they are, but for an offer it withdraws
/// ([`relocked`]).
pub(crate) fn snooze_waiting(
    env: &crate::env::Env,
    wait: Duration,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
    let inputs = crate::plan::Inputs::load(env)?;
    // A check another shell is running would write its offer back after
    // this clears it; a snooze waits it out, as it runs detached anyway.
    let Some(_held) = Stamps::of(inputs.state()).hold(wait)? else {
        tracing::debug!("another bx update or bx sync holds the stamps; nothing snoozed");
        writeln!(
            out,
            "Another bx update or bx sync holds the update stamps; nothing was snoozed, and \
             the answer already given stands."
        )
        .map_err(Error::Output)?;
        return Ok(crate::report::Exit::Converged);
    };
    let interval = inputs.resolved().update.interval();
    let externals = &inputs.resolved().externals;
    let (ask, auto) = (
        ask_interval(externals, interval),
        check_interval(externals, interval),
    );
    Stamps::of(inputs.state()).set(now(), Some(ask), Some(auto), Some(&[]))?;
    writeln!(
        out,
        "bx will ask about updates again in {interval}; run `bx update` any time before."
    )
    .map_err(Error::Output)?;
    Ok(crate::report::Exit::Converged)
}

/// After a `bx update` that finished: every stamp starts a new interval,
/// nothing is offered until the next check finds something, and `last-check`
/// is removed, so neither what a check found nor why an earlier `bx update`
/// stopped outlives the update that took it in.
///
/// # Errors
///
/// As [`Stamps::set`], and [`Error::Io`] when `last-check` cannot be removed.
pub fn finished(inputs: &crate::plan::Inputs) -> Result<(), Error> {
    let interval = inputs.resolved().update.interval();
    let externals = &inputs.resolved().externals;
    let (ask, auto) = (
        ask_interval(externals, interval),
        check_interval(externals, interval),
    );
    let stamps = Stamps::of(inputs.state());
    stamps.set(now(), Some(ask), Some(auto), Some(&[]))?;
    stamps.remove(&stamps.last_check())
}

/// After a `bx update` that stopped short of [`finished`] — declined,
/// abandoned, refused or failed: what `available` offers is answered, so no
/// shell asks it again, and every shell waiting on it gives way; `ask-due` is
/// set to now plus `ask`, as [`Stamps::set`] does, so the question whether to
/// check waits an interval too; and `why` is written to `last-check` as one
/// line, its lines trimmed and joined by a space, so a reason that spans
/// several — git's stderr and its hints — is read whole by `bx doctor`, which
/// names that one line. The offer
/// itself stands, so a check that finds the same commits again offers nothing,
/// and one that finds others offers them under their own generation.
///
/// `answered` is written as the hook writes an offer's answer: the offer's
/// generation, then `ask` and the `ask-due` it settles, so the question due
/// with it is not asked either. With nothing offered, nothing is answered.
///
/// # Errors
///
/// As [`Stamps::set`] and [`Stamps::write`].
pub fn settled(state: &StateDir, ask: Option<Option<Interval>>, why: &str) -> Result<(), Error> {
    let stamps = Stamps::of(state);
    // Read before `set` moves it, as the hook reads it before it answers: the
    // question settled with the offer is the one due now, not the next one.
    let due = Stamps::read(&stamps.ask_due()).map(|due| due.to_string());
    stamps.set(now(), ask, None, None)?;
    let available = std::fs::read(stamps.available()).unwrap_or_default();
    let first = available
        .split(|&byte| byte == b'\n')
        .next()
        .map(|line| {
            String::from_utf8_lossy(line)
                .trim_matches([' ', '\t'])
                .to_string()
        })
        .unwrap_or_default();
    // As the hook names it: `gen G`'s `G`, or `old:` and the first line of an
    // `available` an older bx wrote.
    let generation = first
        .strip_prefix("gen ")
        .map_or_else(|| format!("old:{first}"), str::to_string);
    if Stamps::offers(Some(&available), None) {
        stamps.write(
            &stamps.answered(),
            &format!("{generation}\nask {}\n", due.unwrap_or_default()),
        )?;
    }
    stamps.write(&stamps.last_check(), &format!("{}\n", one_line(why)))?;
    stamps.wake();
    Ok(())
}

/// `text` on one line: each line trimmed, the empty ones dropped, the rest
/// joined by a space.
fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// After an `apply` that wrote: when an external follows a branch and no
/// stamp says when to ask, start the interval now, so a machine that began
/// following a branch by syncing a configuration is asked in due course.
///
/// Best effort: a stamp that cannot be written costs a question, not the
/// apply, so a failure is logged and nothing more.
pub fn seed(inputs: &crate::plan::Inputs) {
    let externals = &inputs.resolved().externals;
    if first_followed(externals).is_none() {
        return;
    }
    let stamps = Stamps::of(inputs.state());
    let interval = inputs.resolved().update.interval();
    let ask = ask_interval(externals, interval)
        .filter(|_| Stamps::read(&stamps.ask_due()).is_none())
        .map(Some);
    let check = check_interval(externals, interval)
        .filter(|_| Stamps::read(&stamps.check_due()).is_none())
        .map(Some);
    if ask.is_none() && check.is_none() {
        return;
    }
    if let Err(error) = stamps.set(now(), ask, check, None) {
        tracing::warn!(%error, "could not start the update interval");
    }
}

/// `update/check.lock`, held until this is dropped.
#[derive(Debug)]
#[must_use = "the lock is let go as soon as this is dropped"]
pub struct CheckLock(std::fs::File);

impl Drop for CheckLock {
    fn drop(&mut self) {
        // Unlocked explicitly rather than by the close: a process spawned
        // from another thread while the file is open has a copy of it until
        // it execs, and the close alone would leave the lock held by that
        // copy, so a check that gives way to a held lock would give way to
        // one nobody holds. A failure here has nowhere to go; the close
        // still lets go once every copy is closed.
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}

impl Stamps {
    /// Hold `update/check.lock` until the returned [`CheckLock`] is dropped,
    /// or `None` when another check holds it.
    ///
    /// # Errors
    ///
    /// [`Error::State`] when the directory cannot be made, and
    /// [`Error::Io`] when the lock file cannot be opened or locked.
    pub fn try_hold(&self) -> Result<Option<CheckLock>, Error> {
        self.state.ensure_update()?;
        let path = self.dir.join("check.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|source| Error::Io {
                op: "opening",
                path: path.clone(),
                source,
            })?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(CheckLock(file))),
            Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
            Err(errno) => Err(Error::Io {
                op: "locking",
                path,
                source: errno.into(),
            }),
        }
    }

    /// [`Stamps::try_hold`], trying again for up to `wait`: what a person's
    /// `bx update` does, so a check another shell is just finishing does not
    /// turn them away.
    ///
    /// # Errors
    ///
    /// As [`Stamps::try_hold`].
    pub fn hold(&self, wait: Duration) -> Result<Option<CheckLock>, Error> {
        let until = std::time::Instant::now() + wait;
        loop {
            if let Some(held) = self.try_hold()? {
                return Ok(Some(held));
            }
            if std::time::Instant::now() >= until {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// How long a person's `bx update` waits for another to let go.
pub const HOLD_WAIT: Duration = Duration::from_secs(2);

/// How long `bx update --snooze` waits for a running check to let go: longer
/// than [`BACKGROUND_BOUND`], which bounds the longest one.
pub const SNOOZE_WAIT: Duration = Duration::from_secs(35);

#[cfg(test)]
mod tests;
