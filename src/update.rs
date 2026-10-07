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
//! ([`crate::sync::Git::unattended`]), so a missing credential fails rather
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

use crate::config::external::{Check, External};
use crate::config::lock::{self, Lock, Locked};
use crate::config::update::Interval;
use crate::fs::Mode;
use crate::paths::{self, Portable};
use crate::plan::external::{self as checkout, problem};
use crate::state::StateDir;
use crate::sync::{self, Git};

/// How long `bx update --background` may take, from start to finish.
pub const BACKGROUND_BOUND: Duration = Duration::from_secs(30);

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
        /// [`LOG_LIMIT`] of them; `None` when no checkout could list them.
        log: Option<Vec<String>>,
        /// How many new commits there are, when a checkout could count them.
        count: Option<u64>,
    },
    /// The tip does not descend from the commit locked.
    Rewritten {
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
#[must_use]
pub fn look(git: &Git, home: &Path, external: &External, lock: &Lock) -> Found {
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
    let ours = dest.is_dir()
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
    if !ours || !checkout::has_commit(git, &dest, from) {
        return found(Verdict::Moves {
            tip,
            log: None,
            count: None,
        });
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
        Err(sync::Error::Git { status, .. }) if status.code() == Some(2) => {
            Err(format!("{url} has no {reference}"))
        }
        Err(error) => Err(problem(&error)),
    }
}

/// `lock` with every move in `found` set, and every entry no followed
/// external in `externals` declares any more dropped.
#[must_use]
pub fn proposed(lock: &Lock, found: &[Found], externals: &[External]) -> Lock {
    let mut next = lock.clone();
    for found in found {
        if let Some(tip) = found.moves_to() {
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
    next.retain(|path| {
        externals
            .iter()
            .any(|external| external.path == *path && external.follows().is_some())
    });
    next
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
    format!("chore(bx): update bx.lock\n\n{}\n", lines.join("\n"))
}

/// Refuse a `bx.lock` with changes git has not committed, which a commit of
/// the lock would sweep up. A config repo git does not manage has nothing to
/// refuse.
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
            "--untracked-files=no",
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
pub fn write_and_commit(git: &Git, repo: &Path, lock: &Lock, message: &str) -> Result<bool, Error> {
    let path = Lock::path_in(repo);
    crate::fs::write_atomically(&path, lock.render().as_bytes(), Mode::DEFAULT_FILE).map_err(
        |source| Error::Write {
            path: path.clone(),
            source,
        },
    )?;
    if sync::own_repository(git, repo).is_err() {
        return Ok(false);
    }
    git.query(repo, &["add", "--", lock::FILE])?;
    let staged = git.query(repo, &["diff", "--cached", "--name-only", "--", lock::FILE])?;
    if staged.is_empty() {
        return Ok(false);
    }
    git.commit(
        repo,
        &["commit", "--quiet", "-m", message, "--", lock::FILE],
    )?;
    Ok(true)
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

    /// Set `ask-due` to `now` plus `ask`, `check-due` to `now` plus `check`
    /// or removed when no external checks on its own, and `available` to
    /// `available`'s lines, or removed when there are none. A stamp given as
    /// `None` is left as it is.
    ///
    /// # Errors
    ///
    /// [`Error::State`] when the directory cannot be made, and
    /// [`Error::Write`] when a file cannot be written or removed.
    pub fn set(
        &self,
        now: Epoch,
        ask: Option<Interval>,
        check: Option<Option<Interval>>,
        available: Option<&[String]>,
    ) -> Result<(), Error> {
        self.state.ensure_update()?;
        if let Some(ask) = ask {
            self.write(&self.ask_due(), &format!("{}\n", now + ask.seconds()))?;
        }
        match check {
            Some(Some(check)) => {
                self.write(&self.check_due(), &format!("{}\n", now + check.seconds()))?;
            }
            Some(None) => self.remove(&self.check_due())?,
            None => {}
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
    pub fn write(&self, path: &Path, text: &str) -> Result<(), Error> {
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
/// Exits [`Exit::Pending`] when there is something to apply.
///
/// # Errors
///
/// As [`crate::plan::Inputs::load`], [`select`] and [`Stamps::set`].
pub fn check(
    env: &crate::plan::Env,
    names: &[String],
    background: bool,
    git: &Git,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
    let inputs = crate::plan::Inputs::load(env)?;
    let stamps = Stamps::of(inputs.state());
    let externals = &inputs.resolved().externals;
    let interval = inputs.resolved().update.interval();
    let auto = check_interval(externals, interval);
    let now = now();
    let _held = if background {
        let Some(held) = stamps.try_hold()? else {
            return Ok(crate::report::Exit::Converged);
        };
        stamps.set(now, None, Some(auto), None)?;
        Some(held)
    } else {
        None
    };
    let git = if background {
        git.clone()
            .unattended()
            .with_deadline(std::time::Instant::now() + BACKGROUND_BOUND)
    } else {
        git.clone().unattended()
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
        .map(|external| look(&git, &env.home, external, inputs.lock()))
        .collect();

    let looked: Vec<String> = found.iter().map(|f| format!("{}: ", f.path)).collect();
    let mut available: Vec<String> = std::fs::read_to_string(stamps.available())
        .unwrap_or_default()
        .lines()
        .filter(|line| !looked.iter().any(|prefix| line.starts_with(prefix)))
        .map(str::to_string)
        .collect();
    available.extend(
        found
            .iter()
            .filter(|found| found.moves_to().is_some())
            .map(Found::summary),
    );
    let summaries: String = found.iter().map(|f| format!("{}\n", f.summary())).collect();
    if background {
        stamps.set(now, None, None, Some(&available))?;
        stamps.write(&stamps.last_check(), &summaries)?;
    } else {
        stamps.set(now, Some(interval), Some(auto), Some(&available))?;
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

/// `bx update --snooze`: put the next question off by one interval, and drop
/// what the last check offered. Reaches no network.
///
/// # Errors
///
/// As [`crate::plan::Inputs::load`] and [`Stamps::set`].
pub fn snooze(
    env: &crate::plan::Env,
    out: &mut dyn std::io::Write,
) -> Result<crate::report::Exit, Error> {
    let inputs = crate::plan::Inputs::load(env)?;
    let interval = inputs.resolved().update.interval();
    let auto = check_interval(&inputs.resolved().externals, interval);
    Stamps::of(inputs.state()).set(now(), Some(interval), Some(auto), Some(&[]))?;
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
    let auto = check_interval(&inputs.resolved().externals, interval);
    Stamps::of(inputs.state()).set(now(), Some(interval), Some(auto), Some(&[]))
}

/// After an `apply` that wrote: when an external follows a branch and no
/// stamp says when to ask, start the interval now, so a machine that began
/// following a branch by syncing a configuration is asked in due course.
///
/// Best effort: a stamp that cannot be written costs a question, not the
/// apply, so a failure is logged and nothing more.
pub fn seed(inputs: &crate::plan::Inputs) {
    let externals = &inputs.resolved().externals;
    if !externals
        .iter()
        .any(|external| external.follows().is_some())
    {
        return;
    }
    let stamps = Stamps::of(inputs.state());
    let interval = inputs.resolved().update.interval();
    let ask = Stamps::read(&stamps.ask_due())
        .is_none()
        .then_some(interval);
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

impl Stamps {
    /// Hold `update/check.lock` for as long as the returned file is open, or
    /// `None` when another check holds it.
    ///
    /// # Errors
    ///
    /// [`Error::State`] when the directory cannot be made, and
    /// [`Error::Write`] when the lock file cannot be opened.
    pub fn try_hold(&self) -> Result<Option<std::fs::File>, Error> {
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
            Ok(()) => Ok(Some(file)),
            Err(_) => Ok(None),
        }
    }
}

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
                &externals[..1]
            ),
            {
                let mut kept = Lock::default();
                kept.set(portable("~/a"), entry(A));
                kept
            }
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
                Some(day),
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
        let seen = look(&git, home.path(), &external, &Lock::default());
        assert_eq!(
            seen.moves_to(),
            Some(tip.as_str()),
            "ls-remote, with no checkout"
        );

        external.pin = Pin::Follow(Follow {
            branch: "nope".to_string(),
            check: Check::Ask,
        });
        let seen = look(&git, home.path(), &external, &Lock::default());
        assert!(
            matches!(&seen.verdict, Verdict::Unreachable(why) if why.contains("has no refs/heads/nope")),
            "{seen:?}"
        );
    }
}
