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
//! An interactive shell decides whether to ask about updates by reading three
//! files in the state directory's `update/` with shell builtins, and starts
//! no process to do it (Invariant 6):
//!
//! | file        | holds                                                                 |
//! |-------------|-----------------------------------------------------------------------|
//! | `ask-due`   | when to next ask whether to check, in seconds since the epoch         |
//! | `check-due` | when to next check without asking, for `check = "auto"` externals     |
//! | `available` | one line per external a check found new commits for                   |
//!
//! Each is written whole by [`Stamps`] and nothing else. A missing or
//! unreadable `ask-due` or `check-due` is never due: a machine that has not
//! run `bx update` or `bx apply` since it began following a branch is not
//! asked, rather than asked at once.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::external::{Check, External, first_followed};
use crate::config::lock::{self, Lock, Locked};
use crate::config::update::Interval;
use crate::fs::Mode;
use crate::git::{self, Git};
use crate::paths::{self, Portable};
use crate::plan::external::{self as checkout, problem};
use crate::state::StateDir;
use crate::sync;

/// How long `bx update --background` may take, from start to finish.
pub const BACKGROUND_BOUND: Duration = Duration::from_secs(30);

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
    /// This machine's unpushed lock commits and the upstream both changed
    /// `bx.lock`.
    #[error(
        "this machine has {commits} unpushed bx.lock commit(s), and another machine pushed a \
         bx.lock of its own; nothing was changed. To take the other machine's, run \
         `git -C {} reset --keep @{{upstream}}`, then bx update again; to keep this one's, \
         merge by hand and run bx sync",
        .repo.display()
    )]
    LockDiverged {
        /// How many of this machine's lock commits are unpushed.
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
    /// Another `bx update` holds `update/check.lock`.
    #[error(
        "another bx update is running, in this shell or another; let it finish, then run \
         bx update again"
    )]
    Busy,
    /// A file under the state directory could not be written.
    #[error("{}: {source}", .path.display())]
    Write {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: crate::fs::Error,
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
    let ours = checkout::finished_clone(ledger, &external.path)
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
    followed(path, externals) || committed.is_none_or(|c| followed(path, c))
}

/// Whether any of `externals` follows a branch at `path`.
#[must_use]
pub fn followed(path: &Portable, externals: &[External]) -> bool {
    externals
        .iter()
        .any(|external| external.path == *path && external.follows().is_some())
}

/// Whether the committed configuration, where it is known, does not follow
/// `found`'s path from the url and branch this account's does: a follow that
/// `local.toml` alone declares, or points elsewhere, whose commit the shared
/// `bx.lock` does not take.
#[must_use]
pub fn unshared(found: &Found, committed: Option<&[External]>) -> bool {
    unshared_at(&found.path, &found.url, &found.branch, committed)
}

/// What `bx update` cannot do for `external`'s follow, which `local.toml`
/// alone declares or points elsewhere ([`unshared`]): the remedy that locks
/// it instead, or `None` for a follow `bx update` does lock, and for a pin.
///
/// A follow the committed configuration already declares elsewhere is not
/// told to declare it in a committed layer, as `bx update`'s own message for
/// that case does not: that would change what every account follows.
#[must_use]
pub fn unshared_remedy(
    external: &External,
    committed: Option<&[External]>,
) -> Option<&'static str> {
    let follow = external.follows()?;
    if !unshared_at(&external.path, &external.url, &follow.branch, committed) {
        return None;
    }
    Some(if committed.is_some_and(|c| followed(&external.path, c)) {
        "`bx update` locks the branch and url the committed configuration follows here, not \
         this one; pin it with `rev`"
    } else {
        "`bx update` locks only what the committed configuration follows; declare it in a \
         committed layer, or pin it with `rev`"
    })
}

/// [`unshared`], for the follow of `branch` of `url` at `path`.
fn unshared_at(path: &Portable, url: &str, branch: &str, committed: Option<&[External]>) -> bool {
    committed.is_some_and(|committed| {
        !committed.iter().any(|external| {
            external.path == *path
                && external.url == url
                && external
                    .follows()
                    .is_some_and(|follow| follow.branch == branch)
        })
    })
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

/// What [`replay_own_lock_commits`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// A local commit is not one `bx update` made; nothing was touched.
    NotOwn,
    /// This many of `bx update`'s commits now sit on top of the upstream.
    Replayed(usize),
    /// The upstream changed `bx.lock` too, so they could not be replayed;
    /// the branch is as it was.
    Conflicted(usize),
}

/// When the config repo's branch has diverged from its upstream only by
/// commits `bx update` made — each with [`SUBJECT`], one parent, and
/// touching `bx.lock` alone — replay them on top of the upstream, as
/// `git rebase` does. Every lock they held is kept, so nothing needs
/// approving again. When the upstream changed `bx.lock` as well, the replay
/// is abandoned and the branch left exactly as it was: which machine's lock
/// to keep is a person's call. Any other local commit is left alone too.
///
/// # Errors
///
/// [`Error::Sync`] when git cannot list the commits, or a replay failed and
/// was put back, and [`Error::Rebasing`] when a replay that failed could not
/// be put back, so it stands open for a person to finish or abort.
pub fn replay_own_lock_commits(git: &Git, repo: &Path) -> Result<Replay, Error> {
    let listed = git.query(
        repo,
        &["rev-list", "--format=%P%x00%s", "@{upstream}..HEAD"],
    )?;
    let mut commits = 0;
    for pair in listed.lines().collect::<Vec<_>>().chunks(2) {
        let [header, body] = pair else {
            return Ok(Replay::NotOwn);
        };
        let Some(commit) = header.strip_prefix("commit ") else {
            return Ok(Replay::NotOwn);
        };
        let (parents, subject) = body.split_once('\0').unwrap_or((body, ""));
        if parents.split_whitespace().count() != 1 || subject != SUBJECT {
            return Ok(Replay::NotOwn);
        }
        let touched = git.query(
            repo,
            &["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
        )?;
        if touched != lock::FILE {
            return Ok(Replay::NotOwn);
        }
        commits += 1;
    }
    if commits == 0 {
        return Ok(Replay::NotOwn);
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
        crate::fs::write_atomically(&path, bytes, Mode::DEFAULT_FILE).map_err(|source| {
            Error::Write {
                path: path.clone(),
                source,
            }
        })
    };
    write(lock.render().as_bytes())?;
    if sync::own_repository(git, repo).is_err() {
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

    /// Set `ask-due` to `now` plus `ask`, or removed when no external asks
    /// first; `check-due` to `now` plus `check`, or removed when no external
    /// checks on its own; and `available` to `available`'s lines, or removed
    /// when there are none. A stamp given as `None` is left as it is.
    ///
    /// # Errors
    ///
    /// [`Error::State`] when the directory cannot be made, and
    /// [`Error::Write`] when a file cannot be written or removed.
    pub fn set(
        &self,
        now: Epoch,
        ask: Option<Option<Interval>>,
        check: Option<Option<Interval>>,
        available: Option<&[String]>,
    ) -> Result<(), Error> {
        self.state.ensure_update()?;
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
            Some([]) => self.remove(&self.available())?,
            Some(lines) => {
                let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
                self.write(&self.available(), &text)?;
            }
            None => {}
        }
        Ok(())
    }

    /// The epoch in `path`, or `None` when it is absent or holds none.
    #[must_use]
    pub fn read(path: &Path) -> Option<Epoch> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    /// Write `text` to `path` whole.
    ///
    /// # Errors
    ///
    /// [`Error::Write`].
    pub(crate) fn write(&self, path: &Path, text: &str) -> Result<(), Error> {
        crate::fs::write_atomically(path, text.as_bytes(), Mode::PRIVATE_FILE).map_err(|source| {
            Error::Write {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    /// Remove `path` if it is there.
    fn remove(&self, path: &Path) -> Result<(), Error> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Write {
                path: path.to_path_buf(),
                source: crate::fs::Error::Write {
                    path: path.to_path_buf(),
                    source,
                },
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
/// the network, so a check that fails is not retried at every prompt. Either
/// way, every external with new commits gets a line in `available`, which the
/// next prompt offers to apply; lines for externals this check did not look
/// at are kept.
///
/// Exits [`crate::report::Exit::Pending`] when there is something to apply.
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
        return looked(env, names, false, git, &stamps, now, out);
    }
    // Before anything that can fail, so a configuration that does not load
    // is retried hourly, not at every new shell's first prompt.
    stamps.set(now, None, Some(Some(Interval::HOUR)), None)?;
    let result = looked(env, names, true, git, &stamps, now, out);
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
    background: bool,
    git: &Git,
    stamps: &Stamps,
    now: Epoch,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
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
    // The whole background run shares one bound; a person's check bounds each
    // remote on its own.
    let started = std::time::Instant::now();
    let git = |started: std::time::Instant| {
        if background {
            git.clone()
                .unattended()
                .with_deadline(started + BACKGROUND_BOUND)
                .in_own_group()
        } else {
            git.clone()
                .unattended()
                .with_deadline(std::time::Instant::now() + LOOK_BOUND)
        }
    };
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
    let found: Vec<Found> = chosen
        .iter()
        .map(|external| look(&git(started), &env.home, external, inputs.lock(), &ledger))
        .collect();

    let available = offered(
        &std::fs::read_to_string(stamps.available()).unwrap_or_default(),
        &found,
    );
    let summaries: String = found.iter().map(|f| format!("{}\n", f.summary())).collect();
    if background {
        stamps.set(now, None, None, Some(&available))?;
        stamps.write(&stamps.last_check(), &summaries)?;
    } else {
        let ask = ask_interval(externals, interval);
        stamps.set(now, Some(ask), Some(auto), Some(&available))?;
        out.write_all(summaries.as_bytes()).map_err(Error::Output)?;
        if chosen.is_empty() {
            writeln!(out, "No [[external]] follows a branch.").map_err(Error::Output)?;
        }
    }
    Ok(if found.iter().any(|found| found.moves_to().is_some()) {
        crate::report::Exit::Pending
    } else {
        crate::report::Exit::Converged
    })
}

/// What `available` holds after a check that found `found`: each line of
/// `previous` about an external it did not look at, then one line for each
/// external it found new commits for.
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
/// carrying on without the lock once that wait runs out.
pub(crate) fn snooze_waiting(
    env: &crate::env::Env,
    wait: Duration,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
    let inputs = crate::plan::Inputs::load(env)?;
    // A check another shell is running would write its offer back after
    // this clears it; a snooze waits it out, as it runs detached anyway.
    // A person's `bx update` can hold it through its question for as long as
    // they take; the answer given here is snoozed all the same, and the
    // latest write stands.
    let _held = Stamps::of(inputs.state()).hold(wait)?;
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

/// After a `bx update` that finished: every stamp starts a new interval, and
/// nothing is offered until the next check finds something.
///
/// # Errors
///
/// As [`Stamps::set`].
pub fn finished(inputs: &crate::plan::Inputs) -> Result<(), Error> {
    let interval = inputs.resolved().update.interval();
    let externals = &inputs.resolved().externals;
    let (ask, auto) = (
        ask_interval(externals, interval),
        check_interval(externals, interval),
    );
    Stamps::of(inputs.state()).set(now(), Some(ask), Some(auto), Some(&[]))
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
    /// [`Error::Write`] when the lock file cannot be opened.
    pub fn try_hold(&self) -> Result<Option<CheckLock>, Error> {
        self.state.ensure_update()?;
        let path = self.dir.join("check.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|source| Error::Write {
                path: path.clone(),
                source: crate::fs::Error::Write {
                    path: path.clone(),
                    source,
                },
            })?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(CheckLock(file))),
            Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
            Err(errno) => Err(Error::Write {
                path: path.clone(),
                source: crate::fs::Error::Write {
                    path,
                    source: errno.into(),
                },
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
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::config::external::{Follow, Pin};
    use crate::testing::guarded_home;

    const A: &str = "0e810e5afa27acbd074398eefbe28d13005dbc15";
    const B: &str = "85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5";

    fn home() -> PathBuf {
        PathBuf::from("/home/example")
    }

    fn portable(raw: &str) -> Portable {
        Portable::parse_in(raw, &home()).unwrap()
    }

    fn followed(path: &str, check: Check) -> External {
        External {
            path: portable(path),
            url: format!("https://h/o/{}", &path[2..]),
            pin: Pin::Follow(Follow {
                branch: "main".to_string(),
                check,
            }),
            links: Vec::new(),
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        }
    }

    fn pinned(path: &str) -> External {
        External {
            pin: Pin::Rev(A.to_string()),
            ..followed(path, Check::Ask)
        }
    }

    fn found(path: &str, locked: Option<&str>, verdict: Verdict) -> Found {
        Found {
            path: portable(path),
            url: format!("https://h/o/{}", &path[2..]),
            branch: "main".to_string(),
            locked: locked.map(str::to_string),
            verdict,
        }
    }

    fn moves(tip: &str) -> Verdict {
        Verdict::Moves {
            tip: tip.to_string(),
            log: None,
            count: None,
        }
    }

    #[test]
    fn select_takes_every_followed_external_or_the_ones_named() {
        let externals = [
            followed("~/a", Check::Ask),
            pinned("~/p"),
            followed("~/b", Check::Ask),
        ];
        let all: Vec<&str> = select(&externals, &[], &home())
            .unwrap()
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(all, ["~/a", "~/b"], "pinned ones are not updated");

        let named = select(
            &externals,
            &[
                "/home/example/b".to_string(),
                "~/b".to_string(),
                "~/./a".to_string(),
            ],
            &home(),
        )
        .unwrap();
        let named: Vec<&str> = named.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(named, ["~/b", "~/a"], "in the order named, once each");

        for name in ["~/p", "~/nowhere", "relative"] {
            assert!(
                matches!(
                    select(&externals, &[name.to_string()], &home()),
                    Err(Error::NotFollowed(n)) if n == name
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn proposed_sets_each_move_and_drops_what_nothing_follows() {
        let mut lock = Lock::default();
        let entry = |rev: &str| Locked {
            url: "https://h/o/a".to_string(),
            branch: "main".to_string(),
            rev: rev.to_string(),
        };
        lock.set(portable("~/a"), entry(A));
        lock.set(portable("~/gone"), entry(A));
        lock.set(portable("~/p"), entry(A));
        let externals = [
            followed("~/a", Check::Ask),
            pinned("~/p"),
            followed("~/c", Check::Ask),
        ];
        let next = proposed(
            &lock,
            &[
                found("~/a", Some(A), moves(B)),
                found("~/c", None, Verdict::Unreachable("offline".to_string())),
            ],
            &externals,
            Some(&externals),
        );
        assert_eq!(next.get(&portable("~/a")).unwrap().rev, B);
        assert!(
            next.get(&portable("~/c")).is_none(),
            "nothing found, nothing locked"
        );
        assert!(next.get(&portable("~/gone")).is_none());
        assert!(
            next.get(&portable("~/p")).is_none(),
            "a pinned external has no entry"
        );
        assert_eq!(
            proposed(
                &lock,
                &[found("~/a", Some(A), Verdict::Current)],
                &externals[..1],
                Some(&externals[..1])
            ),
            {
                let mut kept = Lock::default();
                kept.set(portable("~/a"), entry(A));
                kept
            }
        );
    }

    #[test]
    fn proposed_keeps_what_the_committed_configuration_follows() {
        let mut lock = Lock::default();
        let entry = |path: &str| Locked {
            url: format!("https://h/o/{}", &path[2..]),
            branch: "main".to_string(),
            rev: A.to_string(),
        };
        for path in ["~/off", "~/moved", "~/gone"] {
            lock.set(portable(path), entry(path));
        }
        // This account switched `~/off` off and points `~/moved` at another
        // branch in its `local.toml`; the committed layers follow both.
        let mut moved = followed("~/moved", Check::Ask);
        moved.pin = Pin::Follow(Follow {
            branch: "mine".to_string(),
            check: Check::Ask,
        });
        let externals = [moved];
        let committed = [
            followed("~/off", Check::Ask),
            followed("~/moved", Check::Ask),
        ];
        let away = Found {
            branch: "mine".to_string(),
            ..found("~/moved", None, moves(B))
        };
        assert!(unshared(&away, Some(&committed)));
        assert!(!unshared(&away, None));
        assert!(!unshared(
            &found("~/moved", Some(A), moves(B)),
            Some(&committed)
        ));
        let elsewhere = Found {
            url: "https://h/o/elsewhere".to_string(),
            ..found("~/moved", None, moves(B))
        };
        assert!(unshared(&elsewhere, Some(&committed)));

        let next = proposed(
            &lock,
            std::slice::from_ref(&away),
            &externals,
            Some(&committed),
        );
        assert_eq!(next.get(&portable("~/off")), Some(&entry("~/off")));
        assert_eq!(
            next.get(&portable("~/moved")),
            Some(&entry("~/moved")),
            "the committed one's commit stands"
        );
        assert!(next.get(&portable("~/gone")).is_none());

        // With the committed layers unknown, nothing is dropped.
        let next = proposed(&lock, &[], &[], None);
        assert_eq!(next, lock);
        let next = proposed(&lock, &[away], &externals, None);
        assert_eq!(next.get(&portable("~/moved")).unwrap().branch, "mine");
    }

    #[test]
    fn proposed_never_locks_a_follow_only_local_toml_declares() {
        // `~/mine` is followed by this account's `local.toml` alone; the
        // committed layers follow `~/shared`.
        let externals = [
            followed("~/shared", Check::Ask),
            followed("~/mine", Check::Ask),
        ];
        let committed = [followed("~/shared", Check::Ask)];
        let first = [
            found("~/shared", None, moves(A)),
            found("~/mine", None, moves(A)),
        ];
        assert!(unshared(&first[1], Some(&committed)));
        let next = proposed(&Lock::default(), &first, &externals, Some(&committed));
        assert_eq!(next.get(&portable("~/shared")).unwrap().rev, A);
        assert!(
            next.get(&portable("~/mine")).is_none(),
            "the shared lock holds only what the committed configuration follows"
        );

        // Another machine, whose configuration is the committed one alone,
        // proposes the same lock, so the two never take turns.
        let elsewhere = proposed(
            &next,
            &[found("~/shared", Some(A), Verdict::Current)],
            &committed,
            Some(&committed),
        );
        assert_eq!(elsewhere, next);
    }

    #[test]
    fn the_unshared_remedy_says_exactly_what_locks_the_follow_instead() {
        let mine = followed("~/mine", Check::Ask);
        let mut elsewhere = followed("~/mine", Check::Ask);
        elsewhere.pin = Pin::Follow(Follow {
            branch: "other".to_string(),
            check: Check::Ask,
        });
        assert_eq!(unshared_remedy(&pinned("~/mine"), Some(&[])), None, "a pin");
        assert_eq!(
            unshared_remedy(&mine, Some(std::slice::from_ref(&mine))),
            None,
            "a follow the committed configuration declares"
        );
        assert_eq!(unshared_remedy(&mine, None), None, "committed unknown");
        assert_eq!(
            unshared_remedy(&mine, Some(&[])),
            Some(
                "`bx update` locks only what the committed configuration follows; declare it \
                 in a committed layer, or pin it with `rev`"
            )
        );
        assert_eq!(
            unshared_remedy(&mine, Some(&[elsewhere])),
            Some(
                "`bx update` locks the branch and url the committed configuration follows \
                 here, not this one; pin it with `rev`"
            )
        );
    }

    #[test]
    fn the_message_names_what_moved_by_path_and_nothing_else() {
        let entry = |rev: &str| Locked {
            url: "https://h/o/a".to_string(),
            branch: "main".to_string(),
            rev: rev.to_string(),
        };
        let mut before = Lock::default();
        before.set(portable("~/a"), entry(A));
        before.set(portable("~/b"), entry(A));
        before.set(portable("~/z"), entry(A));
        let mut after = Lock::default();
        after.set(portable("~/a"), entry(B));
        after.set(portable("~/b"), entry(A));
        after.set(portable("~/new"), entry(B));
        assert_eq!(
            message(&before, &after),
            "chore(bx): update bx.lock\n\n\
             ~/a: main 0e810e5afa27 -> 85919cd1ffa7\n\
             ~/new: main at 85919cd1ffa7\n\
             ~/z: no longer followed\n"
        );
    }

    #[test]
    fn a_summary_says_what_was_found_in_one_line() {
        let cases = [
            (
                found("~/a", Some(A), Verdict::Current),
                "~/a: up to date with main",
            ),
            (
                found("~/a", None, moves(B)),
                "~/a: locks main at 85919cd1ffa7",
            ),
            (
                found(
                    "~/a",
                    Some(A),
                    Verdict::Moves {
                        tip: B.to_string(),
                        log: Some(Vec::new()),
                        count: Some(3),
                    },
                ),
                "~/a: 3 new commit(s) on main, 0e810e5afa27 -> 85919cd1ffa7",
            ),
            (
                found("~/a", Some(A), moves(B)),
                "~/a: main moved, 0e810e5afa27 -> 85919cd1ffa7",
            ),
            (
                found("~/a", Some(A), Verdict::Rewritten { tip: B.to_string() }),
                "~/a: main was rewritten; its tip 85919cd1ffa7 does not descend from 0e810e5afa27",
            ),
            (
                found("~/a", None, Verdict::Unreachable("no route".to_string())),
                "~/a: not checked: no route",
            ),
        ];
        for (found, says) in cases {
            assert!(found.summary().starts_with(says), "{}", found.summary());
            assert!(!found.summary().contains('\n'));
        }
        assert_eq!(found("~/a", None, moves(B)).moves_to(), Some(B));
        assert_eq!(found("~/a", Some(A), Verdict::Current).moves_to(), None);
    }

    #[test]
    fn a_check_replaces_only_the_lines_of_what_it_looked_at() {
        let previous = "~/a: 1 new commit(s) on main\n~/b: 2 new commit(s) on main\n";
        let looked = [
            found("~/a", Some(A), Verdict::Current),
            found("~/c", None, moves(B)),
        ];
        assert_eq!(
            offered(previous, &looked),
            [
                "~/b: 2 new commit(s) on main".to_string(),
                "~/c: locks main at 85919cd1ffa7".to_string(),
            ]
        );
        assert!(offered("", &[]).is_empty());
        let offline = [found(
            "~/b",
            Some(A),
            Verdict::Unreachable("no route".to_string()),
        )];
        assert_eq!(
            offered(previous, &offline),
            [
                "~/a: 1 new commit(s) on main".to_string(),
                "~/b: 2 new commit(s) on main".to_string(),
            ],
            "a remote not reached withdraws nothing"
        );
    }

    #[test]
    fn the_check_interval_is_the_shortest_auto_one() {
        let week = Interval::parse("7d").unwrap();
        let day = Interval::parse("1d").unwrap();
        assert_eq!(check_interval(&[followed("~/a", Check::Ask)], week), None);
        assert_eq!(
            check_interval(
                &[
                    followed("~/a", Check::Auto(None)),
                    followed("~/b", Check::Auto(Some(day))),
                    pinned("~/p"),
                ],
                week
            ),
            Some(day)
        );
        assert_eq!(
            check_interval(&[followed("~/a", Check::Auto(None))], week),
            Some(week)
        );
    }

    #[test]
    fn stamps_are_written_whole_read_back_and_removed() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let stamps = Stamps::of(&state);
        let day = Interval::parse("1d").unwrap();
        assert_eq!(Stamps::read(&stamps.ask_due()), None, "absent is never due");

        stamps
            .set(
                1000,
                Some(Some(day)),
                Some(Some(day)),
                Some(&["~/a: x".to_string()]),
            )
            .unwrap();
        assert_eq!(Stamps::read(&stamps.ask_due()), Some(1000 + 86_400));
        assert_eq!(Stamps::read(&stamps.check_due()), Some(1000 + 86_400));
        assert_eq!(
            std::fs::read_to_string(stamps.available()).unwrap(),
            "~/a: x\n"
        );
        let mode = std::fs::metadata(stamps.ask_due()).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );

        stamps.set(2000, None, Some(None), Some(&[])).unwrap();
        assert_eq!(Stamps::read(&stamps.ask_due()), Some(1000 + 86_400), "left");
        assert!(!stamps.check_due().exists());
        assert!(!stamps.available().exists());
        stamps.set(2000, None, Some(None), Some(&[])).unwrap();

        std::fs::write(stamps.ask_due(), "soon\n").unwrap();
        assert_eq!(
            Stamps::read(&stamps.ask_due()),
            None,
            "unreadable is never due"
        );

        // Only "already gone" is quietly fine when a stamp is removed.
        std::fs::create_dir(stamps.available()).unwrap();
        std::fs::write(stamps.available().join("x"), "x").unwrap();
        let err = stamps.set(2000, None, None, Some(&[])).unwrap_err();
        assert!(err.to_string().contains("available"), "{err}");

        let now = now();
        assert!(now > 1_700_000_000, "seconds since the epoch: {now}");
        assert!(now < 1_700_000_000 * 4, "{now}");
    }

    #[test]
    fn a_branch_the_remote_lacks_is_unreachable_not_an_error() {
        let home = guarded_home();
        let repo = home.child("upstream");
        std::fs::create_dir_all(&repo).unwrap();
        crate::sync::tests::run(home.path(), &repo, &["init", "--quiet", "-b", "main"]);
        std::fs::write(repo.join("f"), "f\n").unwrap();
        crate::sync::tests::commit_all(home.path(), &repo, "f");
        std::fs::write(
            home.child(".gitconfig"),
            format!(
                "[url \"file://{}/\"]\n\tinsteadOf = https://h/o/\n",
                home.path().display()
            ),
        )
        .unwrap();
        let git = crate::sync::tests::git(home.path()).unattended();
        let mut external = followed("~/upstream-clone", Check::Ask);
        external.path = Portable::parse_in("~/clone", home.path()).unwrap();
        external.url = "https://h/o/upstream".to_string();

        let tip = crate::sync::tests::rev(home.path(), &repo, "HEAD");
        let ledger = crate::state::LedgerView::default();
        let seen = look(&git, home.path(), &external, &Lock::default(), &ledger);
        assert_eq!(
            seen.moves_to(),
            Some(tip.as_str()),
            "ls-remote, with no checkout: a first lock needs no ancestry"
        );

        // A commit locked elsewhere, with no checkout here to show the tip
        // descends from it: nothing is locked.
        let mut lock = Lock::default();
        lock.set(
            external.path.clone(),
            Locked {
                url: external.url.clone(),
                branch: "main".to_string(),
                rev: A.to_string(),
            },
        );
        let seen = look(&git, home.path(), &external, &lock, &ledger);
        assert!(
            matches!(&seen.verdict, Verdict::Unproven { tip: t } if *t == tip),
            "{seen:?}"
        );
        assert_eq!(seen.moves_to(), None);
        assert!(
            seen.summary().contains("is not locked"),
            "{}",
            seen.summary()
        );

        // The user's own clone at the path is never fetched into: without a
        // ledger entry it is asked with ls-remote, and proves nothing.
        crate::sync::tests::run(
            home.path(),
            home.path(),
            &["clone", "--quiet", "https://h/o/upstream", "clone"],
        );
        let seen = look(&git, home.path(), &external, &lock, &ledger);
        assert!(matches!(seen.verdict, Verdict::Unproven { .. }), "{seen:?}");
        assert!(
            !home.child("clone/.git/FETCH_HEAD").exists(),
            "nothing was fetched into it"
        );

        external.pin = Pin::Follow(Follow {
            branch: "nope".to_string(),
            check: Check::Ask,
        });
        let seen = look(&git, home.path(), &external, &Lock::default(), &ledger);
        assert!(
            matches!(&seen.verdict, Verdict::Unreachable(why) if why.contains("has no refs/heads/nope")),
            "{seen:?}"
        );

        // A remote that is not there at all says what git said, not that a
        // branch is missing.
        external.url = "https://h/o/nowhere".to_string();
        let seen = look(&git, home.path(), &external, &Lock::default(), &ledger);
        assert!(
            matches!(&seen.verdict, Verdict::Unreachable(why) if why.contains("`git ls-remote") && !why.contains("has no")),
            "{seen:?}"
        );
    }

    #[test]
    fn a_held_check_lock_is_waited_on_for_the_whole_wait_and_taken_once_let_go() {
        let home = guarded_home();
        let stamps = Stamps::of(&StateDir::resolve(home.path()));
        let held = stamps.try_hold().expect("hold").expect("free");

        // Held throughout: `hold` keeps trying until `wait` is spent, then
        // gives up.
        let wait = Duration::from_millis(200);
        let started = std::time::Instant::now();
        assert!(stamps.hold(wait).expect("hold").is_none());
        assert!(started.elapsed() >= wait, "{:?}", started.elapsed());

        // Let go partway: the waiting `hold` takes it.
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(held);
        });
        assert!(
            stamps
                .hold(Duration::from_secs(30))
                .expect("hold")
                .is_some()
        );
        releaser.join().expect("released");
    }

    #[test]
    fn a_check_lock_let_go_is_free_while_a_copy_of_it_is_still_open() {
        let home = guarded_home();
        let stamps = Stamps::of(&StateDir::resolve(home.path()));
        let held = stamps.try_hold().expect("hold").expect("free");
        // What a process another thread spawns holds until it execs.
        let copy = held.0.try_clone().expect("a copy");
        assert!(stamps.try_hold().expect("busy").is_none(), "held");
        drop(held);
        assert!(
            stamps.try_hold().expect("hold").is_some(),
            "let go, though a copy is open"
        );
        drop(copy);
    }
}
