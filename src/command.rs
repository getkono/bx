//! The bodies of `bx`, `bx init`, `bx plan`, `bx apply`, `bx sync`,
//! `bx update`, `bx doctor`, `bx add`, `bx rm`, `bx secret list` and
//! `bx self-upgrade`, and the refusal of `bx shell-init` and `bx __complete`,
//! which have none yet.
//!
//! Each loads the configuration, runs the one traversal in [`crate::plan`] —
//! or, for `doctor`, the read-only checks in [`crate::doctor`], for `add` and
//! `rm`, [`crate::adopt`], for `init`, [`crate::init`] before the
//! traversal, for `sync`, [`crate::sync`] around it, and for `update`,
//! [`crate::update`] before it — writes the rendering
//! to the output it is
//! handed, and returns the exit status. `self-upgrade` reads no configuration:
//! it is [`crate::upgrade`] run for the binary that is running. `main` does
//! nothing but call one of them.

use std::io::Write;
use std::path::Path;

use crate::adopt::{self, Adoption, Removal};
use crate::config::lock::Unshared;
use crate::config::resolve::Resolution;
use crate::config::target::Body;
use crate::doctor::{self, Probes, systemd};
use crate::env::Env;
use crate::git::Git;
use crate::init;
use crate::paths;
use crate::plan::{self, Error, Inputs, Mode, Palette, Report, View};
use crate::report::{self, Action, Exit};
use crate::restore::Restored;
use crate::secret::{Passphrase, Unlock};
use crate::sync;
use crate::update;
use crate::upgrade;

/// `bx self-upgrade`: install the latest release over the running binary, as
/// a fresh install would, or with `check` only report whether there is one.
///
/// # Errors
///
/// Whatever [`upgrade::run`] returns, and [`upgrade::Error::CurrentExe`] when
/// the running binary cannot be found.
pub fn self_upgrade(check: bool, force: bool, out: &mut dyn Write) -> Result<Exit, upgrade::Error> {
    upgrade::run(
        upgrade::Request { check, force },
        crate::VERSION,
        &upgrade::install_dir()?,
        upgrade::INSTALLER_URL,
        &std::env::var_os("PATH").unwrap_or_default(),
        out,
    )
}

/// `bx doctor`: what a human should look at, changing nothing. Any finding
/// exits [`Exit::Pending`]; a note, such as what the last update check found,
/// is printed and never does.
///
/// # Errors
///
/// Whatever loading the configuration returns, and [`Error::Output`] when
/// `out` cannot be written. A check that cannot ask what it needs — systemd's
/// user session unreachable — is a finding, not an error.
pub fn doctor(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    doctor_with(
        env,
        out,
        &std::env::var_os("PATH").unwrap_or_default(),
        &systemd::Systemctl::default(),
        &Git::new(env),
    )
}

/// [`doctor`], looking for declared tools along `path`, asking systemd
/// through `systemd`, and asking `git` about the config repo.
fn doctor_with(
    env: &Env,
    out: &mut dyn Write,
    path: &std::ffi::OsStr,
    systemd: &dyn systemd::Query,
    git: &Git,
) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let unit_dir = paths::systemd_user_dir_in(&env.home, env.xdg_config_home.as_deref());
    let report = doctor::run(
        &inputs,
        &Probes {
            path,
            unit_dir: &unit_dir,
            systemd,
            launchd: &doctor::launchd::Launchctl::default(),
            bash: &doctor::bash::Version,
            login_shell: &doctor::login_shell::Account::default(),
            git,
        },
    );
    out.write_all(doctor::render(&report, &env.home).as_bytes())
        .map_err(Error::Output)?;
    Ok(doctor::exit(&report))
}

/// Bare `bx`: every target, unchanged ones included.
///
/// Writes nothing, but it is not free of processes: deciding the plan runs
/// each declared activation's command whose output is not cached yet, and asks
/// the user's `git` about each declared external's checkout.
///
/// # Errors
///
/// Whatever loading or deciding returns, and [`Error::Output`] when `out`
/// cannot be written.
pub fn status(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    show(env, View::Status, out)
}

/// `bx plan`: what `apply` would do, writing nothing.
///
/// Spawns what [`status`] spawns: uncached activation commands, and `git` for
/// declared externals.
///
/// # Errors
///
/// As [`status`].
pub fn plan(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    show(env, View::Plan, out)
}

/// `bx apply`: recover, show the plan, obtain approval, and write.
///
/// Approval is `yes`, or the answer to a prompt when standard input is a
/// terminal. With neither, the plan is shown and nothing is written: a piped
/// `bx apply` must not write what nobody confirmed.
///
/// # Errors
///
/// [`Error::NeedsConfirmation`] when there is something to write, no `yes`,
/// and no terminal to ask on; [`Error::Prompt`] when the prompt fails; and
/// otherwise as [`status`], plus whatever recovery and the session return. A
/// prompt abandoned with Esc or Ctrl-C is not an error: it is said in a line
/// and exits [`Exit::Canceled`].
pub fn apply(env: &Env, yes: bool, out: &mut dyn Write) -> Result<Exit, Error> {
    apply_with(env, yes, out, &mut confirm)
}

/// Ask on the terminal whether to write.
///
/// The default is **no**: a prompt answered with a bare newline, or one whose
/// terminal goes away mid-question, must not be read as approval. Everything
/// around this — `yes`, no terminal, declined, accepted, a failing prompt — is
/// decided in [`apply_with`] and tested through its `ask` seam; this wrapper
/// exists only to put the question.
fn confirm() -> Result<bool, Error> {
    inquire::Confirm::new("Apply these changes?")
        .with_default(false)
        .prompt()
        .map_err(confirmation_failed)
}

/// What a confirmation prompt's failure is: [`Error::Canceled`] when it was
/// [`init::abandoned`], [`Error::Prompt`] otherwise.
fn confirmation_failed(error: inquire::InquireError) -> Error {
    if init::abandoned(&error) {
        Error::Canceled
    } else {
        Error::Prompt(error)
    }
}

/// [`apply`], with the question asked through `ask`.
fn apply_with(
    env: &Env,
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, Error> {
    match converge(env, Mode::Apply, yes, out, ask) {
        Ok(report) => Ok(plan::exit(&report, Mode::Apply)),
        // The question comes before the first write, so walking away from it
        // leaves the plan as it was shown.
        Err(Error::Canceled) => {
            writeln!(out, "Canceled. Nothing was applied.").map_err(Error::Output)?;
            Ok(Exit::Canceled)
        }
        Err(other) => Err(other),
    }
}

/// `bx apply`'s body: load, show the plan, obtain approval, write, and say
/// what was done. Shared with [`sync`], so the change list `sync` asks about
/// is `apply`'s own; `sync` runs it in [`Mode::Sync`], which also carries each
/// tracked target this machine changed into the repo.
fn converge(
    env: &Env,
    mode: Mode,
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Report, Error> {
    let inputs = Inputs::load(env)?;
    let mut declined = false;
    let report = converge_inputs(&inputs, env, mode, yes, out, ask, &mut |_, approved| {
        declined = !approved;
        approved
    })?;
    // An offer judged against a bx.lock this machine no longer has — a sync
    // just brought in another machine's — is withdrawn and checked again, once
    // that lock is applied: approved, or with nothing to apply. A declined,
    // canceled or unconfirmed apply leaves the offer as it stood.
    if !declined {
        update::relocked(&inputs);
    }
    // A machine that just began following a branch starts its interval now,
    // so its shells ask once it has passed rather than never.
    if report.executed {
        update::seed(&inputs);
    }
    Ok(report)
}

/// [`converge`] over `inputs` already loaded, telling `decided` the answer to
/// the one question, with the report it was put about, as soon as it is
/// given, and writing only when it returns `true`: the seam `bx update`
/// commits its lock through, between the approval and the first write.
fn converge_inputs(
    inputs: &Inputs,
    env: &Env,
    mode: Mode,
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
    decided: &mut dyn FnMut(&Report, bool) -> bool,
) -> Result<Report, Error> {
    let mut shown = false;
    let report = plan::run(inputs, mode, &mut |report| {
        emit(out, report, View::Plan, env)?;
        // On screen before the question about it is put, whatever buffers
        // the output.
        out.flush().map_err(Error::Output)?;
        shown = true;
        let approved = if yes {
            true
        } else if env.stdin_tty {
            ask()?
        } else {
            return Err(Error::NeedsConfirmation);
        };
        Ok(decided(report, approved))
    })?;

    if !shown {
        emit(out, &report, View::Plan, env)?;
    } else if let Some(outcome) = &report.recovered {
        writeln!(out, "{}", recovered(&report, outcome)).map_err(Error::Output)?;
    } else if report.executed {
        // Every row and every activation it cached: an activation's pending
        // step is a cache entry written, as a row's is a file.
        let written = report
            .actions()
            .into_iter()
            .filter(|action| action.is_pending() || (mode == Mode::Sync && *action == Action::Sync))
            .count();
        writeln!(out, "Applied {written} change(s).").map_err(Error::Output)?;
        // A row apply stopped short of was announced as work and shown so; its
        // reason is known only now, so it is said now.
        for &at in &report.stopped {
            let change = &report.changes[at];
            writeln!(
                out,
                "  ! {}  stopped: {}",
                report::escape(&change.target),
                report::escape(change.note.as_deref().unwrap_or_default()),
            )
            .map_err(Error::Output)?;
        }
    } else {
        writeln!(out, "Nothing was applied.").map_err(Error::Output)?;
    }
    Ok(report)
}

/// `bx sync`: fast-forward the config repo from its upstream, apply exactly as
/// `bx apply` does, and push what this machine committed.
///
/// It holds `update/check.lock` throughout, as `bx update` does, so the two
/// never write the config repo at once: while another holds it, it waits
/// [`update::HOLD_WAIT`] and then stops with [`sync::Error::Busy`], before
/// it has pulled anything.
///
/// [`sync::pull`] runs first and refuses a diverged branch, a missing
/// upstream, and a push that would carry a state file, all before the apply
/// changes anything. It is not free of writes itself: before the fetch it
/// commits the tracked copies an interrupted sync wrote and never committed
/// ([`sync::commit_carried`]), so a refusal can follow that commit.
/// The apply is [`apply`]'s, with its one confirmation and its `yes`.
/// The apply runs in [`Mode::Sync`], so each tracked target this machine
/// changed is carried into the repo, and [`sync::commit_carried`] commits
/// those files in one commit before the push.
/// The push follows only when [`sync::may_push`] says the apply left nothing
/// undone: a declined apply, one that left a target in conflict or blocked,
/// or one that only recovered an interrupted session, pushes nothing, and the
/// next `sync` picks up where it stopped.
///
/// Exits as `bx apply` would over the same report, so a sync that applied
/// every pending change exits [`Exit::Converged`].
///
/// # Errors
///
/// Whatever [`sync::pull`] and [`sync::push`] return, and as [`apply`]; and
/// whatever [`sync::commit_carried`] returns after the apply, which leaves
/// what the apply wrote on disk and uncommitted for the next `sync` to commit;
/// [`sync::Error::Busy`] while another sync, update or check holds
/// `update/check.lock`, and [`sync::Error::Lock`] when it cannot be taken.
pub fn sync(env: &Env, yes: bool, out: &mut dyn Write) -> Result<Exit, sync::Error> {
    sync_with(env, yes, out, &Git::new(env), &mut confirm)
}

/// The line `sync` and `update` say after a pull that moved the branch.
fn fast_forwarded(pulled: &sync::Pulled) -> String {
    format!(
        "Fast-forwarded {} by {} commit(s) from {}.",
        pulled.branch, pulled.fast_forwarded, pulled.upstream.short
    )
}

/// The line `sync` and `update` say after [`sync::pull`] committed the
/// tracked copies an interrupted sync left uncommitted.
fn recovered_carry(pulled: &sync::Pulled) -> String {
    format!(
        "Committed {} tracked file(s) an interrupted bx sync carried into the repo.",
        pulled.recovered
    )
}

/// The line `sync` and `update` say after [`sync::commit_carried`] committed
/// the `carried` tracked copies this run's apply wrote.
fn committed_carry(carried: usize, pulled: &sync::Pulled) -> String {
    format!("Committed {carried} tracked file(s) to {}.", pulled.branch)
}

/// [`sync`], through `git`, with the question asked through `ask`.
fn sync_with(
    env: &Env,
    yes: bool,
    out: &mut dyn Write,
    git: &Git,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, sync::Error> {
    // Held to the end, so no `bx update` in another shell commits or pushes
    // between this pull and this push, and this never runs inside its own.
    let state = crate::state::StateDir::resolve_in(&env.home, env.xdg_state_home.as_deref());
    let _held = update::Stamps::of(&state)
        .hold(update::HOLD_WAIT)
        .map_err(|error| sync::Error::Lock(Box::new(error)))?
        .ok_or(sync::Error::Busy)?;
    let pulled = sync::pull(env, git)?;
    if pulled.fast_forwarded > 0 {
        writeln!(out, "{}", fast_forwarded(&pulled)).map_err(sync::Error::Output)?;
    }
    if pulled.recovered > 0 {
        writeln!(out, "{}", recovered_carry(&pulled)).map_err(sync::Error::Output)?;
    }
    let report = match converge(env, Mode::Sync, yes, out, ask) {
        Ok(report) => report,
        // Nothing was carried, so there is nothing to commit, and a push is
        // for an apply that left nothing undone.
        Err(Error::Canceled) => {
            writeln!(
                out,
                "Canceled. Nothing was applied or pushed; run `bx sync` again."
            )
            .map_err(sync::Error::Output)?;
            return Ok(Exit::Canceled);
        }
        Err(other) => return Err(other.into()),
    };
    let committed = sync::commit_carried(env, git, &pulled.repo)?;
    if committed > 0 {
        writeln!(out, "{}", committed_carry(committed, &pulled)).map_err(sync::Error::Output)?;
    }
    // Every carried file is in the one commit `commit_carried` made.
    let ahead = pulled.ahead + u64::from(committed > 0);
    if ahead > 0 {
        if sync::may_push(&report) {
            sync::push(git, &pulled)?;
            writeln!(
                out,
                "Pushed {ahead} commit(s) to {}.",
                pulled.upstream.short
            )
        } else {
            writeln!(
                out,
                "Pushed nothing: {ahead} commit(s) wait for an apply that leaves nothing undone; \
                 run `bx sync` again."
            )
        }
        .map_err(sync::Error::Output)?;
    }
    Ok(plan::exit(&report, Mode::Sync))
}

/// What `bx update` is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    /// Pull the config repo, look for new commits, show the plan, and on
    /// approval lock, commit and apply.
    Update {
        /// Approve without asking.
        yes: bool,
    },
    /// Look for new commits and say what was found; change nothing but the
    /// stamps and the objects fetched into checkouts.
    Check,
    /// [`UpdateMode::Check`] for the externals set to `check = "auto"`, from
    /// an interactive shell's prompt hook: quietly, bounded by
    /// [`update::BACKGROUND_BOUND`], and not at all while another runs.
    Background,
    /// Put off the next question by one interval.
    Snooze,
}

impl UpdateMode {
    /// The mode `bx update`'s flags ask for: `--background` over `--snooze`
    /// over `--check`, though the command line admits no two of them
    /// together; with none, an update, approved by `--yes`.
    #[must_use]
    pub const fn from_flags(yes: bool, check: bool, snooze: bool, background: bool) -> Self {
        if background {
            Self::Background
        } else if snooze {
            Self::Snooze
        } else if check {
            Self::Check
        } else {
            Self::Update { yes }
        }
    }
}

/// `bx update`: everything [`sync`] does, and move followed externals to their
/// branches' new commits.
///
/// [`UpdateMode::Update`] first brings the config repo level with its
/// upstream, as `bx sync` does, so the lock it writes is written on top of
/// every other machine's. It then asks each followed external's remote where
/// its branch is ([`update::look`]), says what it found, and shows the plan
/// for the lock that would follow — the same rendering and the same one
/// confirmation `bx apply` has. Once approved, `bx.lock` is written and
/// committed **before** any checkout moves, and then the plan is applied: the
/// work that runs is the work shown. Wherever `bx sync` would run — the pull
/// found an upstream — the apply is `bx sync`'s [`Mode::Sync`], so each
/// tracked target this machine changed is carried into the repo and
/// committed ([`sync::commit_carried`]) after the lock, and nothing is left
/// for a `bx sync` to do; with no upstream, or no repository, it is a bare
/// apply, as `bx sync` would refuse. Once applied, the branch is pushed to
/// its upstream, never forced, when [`sync::may_push`] allows it, so no other
/// machine's update diverges from this one's; a refused push is said and
/// leaves the commit for `bx sync`, or, when the upstream moved, for another
/// `bx update` to replay on top, as `bx sync` refuses the diverged branch;
/// a branch with no upstream, one that
/// is gone, or no repository pushes nothing. With nothing new it still pulls,
/// applies and pushes what was left unpushed, so the machine ends where the
/// configuration says.
///
/// Every way it ends settles what the stamps offer, so no shell asks it again:
/// run to the end, [`update::finished`] clears the offer and `last-check`;
/// declined, abandoned at the question, refused or failed, [`update::settled`]
/// answers it and says why in `last-check`. Only [`update::Error::Busy`] records nothing, as
/// the run holding the stamps settles them.
///
/// Without `yes` it needs a terminal to ask on, and refuses before reaching
/// the network.
///
/// # Errors
///
/// [`update::Error`] for a refused pull, an edited `bx.lock`, a name that is
/// not a followed external, a lock that cannot be written or committed, and
/// as [`apply`]; besides those, for [`UpdateMode::Update`]:
/// [`Error::NeedsConfirmation`] without `yes` and a terminal,
/// [`Error::RepoMissing`] with no config repo, [`update::Error::Busy`] while
/// another `bx update`, `bx sync` or check holds the stamps,
/// [`update::Error::Rebasing`]
/// while a rebase or `git am` stands open in the config repo, and
/// [`update::Error::LockDiverged`] when this machine's unpushed bx update commits
/// and the upstream both changed `bx.lock`, or a tracked copy one carried.
pub fn update(
    env: &Env,
    names: &[String],
    mode: UpdateMode,
    out: &mut dyn Write,
) -> Result<Exit, update::Error> {
    let git = Git::new(env);
    match mode {
        UpdateMode::Update { yes } => update_with(env, names, yes, out, &git, &mut confirm),
        UpdateMode::Check => update::check(env, names, false, &git, out),
        UpdateMode::Background => update::check(env, names, true, &git, out),
        UpdateMode::Snooze => update::snooze(env, out),
    }
}

/// [`update`]'s [`UpdateMode::Update`], through `git`, with the question
/// asked through `ask`.
fn update_with(
    env: &Env,
    names: &[String],
    yes: bool,
    out: &mut dyn Write,
    git: &Git,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, update::Error> {
    if !yes && !env.stdin_tty {
        return Err(Error::NeedsConfirmation.into());
    }
    let repo = paths::config_root_in(&env.home, env.xdg_config_home.as_deref());
    if !repo.is_dir() {
        return Err(Error::RepoMissing(repo).into());
    }
    // Held to the end, so two shells answering `y` at once, or a background
    // check fetching into a checkout this run moves, never overlap.
    // Busy records nothing: the run that holds it settles the offer.
    let state = crate::state::StateDir::resolve_in(&env.home, env.xdg_state_home.as_deref());
    let _held = update::Stamps::of(&state)
        .hold(update::HOLD_WAIT)?
        .ok_or(update::Error::Busy)?;
    // Every other way this ends settles the offer, so no shell asks it again.
    let why = match updating(env, names, yes, out, git, ask, &repo) {
        Ok(Updated::Finished(exit)) => return Ok(exit),
        Ok(Updated::Stopped(exit, why)) => Ok((exit, why.to_string())),
        Err(error) => Err(error),
    };
    let reason = match &why {
        Ok((_, why)) => why.clone(),
        Err(error) => format!("{}{error}", update::STOPPED),
    };
    let ask = Inputs::load(env).ok().map(|inputs| {
        update::ask_interval(
            &inputs.resolved().externals,
            inputs.resolved().update.interval(),
        )
    });
    if let Err(error) = update::settled(&state, ask, &reason) {
        tracing::warn!(%error, "could not settle what bx update was offered");
    }
    why.map(|(exit, _)| exit)
}

/// How [`updating`] ended.
enum Updated {
    /// It ran to the end, and [`update::finished`] started every interval.
    Finished(Exit),
    /// It stopped short, for the reason given, and changed no stamp.
    Stopped(Exit, &'static str),
}

/// [`update_with`], under `update/check.lock`, for the config repo `repo`.
fn updating(
    env: &Env,
    names: &[String],
    yes: bool,
    out: &mut dyn Write,
    git: &Git,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
    repo: &std::path::Path,
) -> Result<Updated, update::Error> {
    let say =
        |out: &mut dyn Write, text: &str| writeln!(out, "{text}").map_err(update::Error::Output);
    let repo = repo.to_path_buf();
    // One an interrupted replay left, or the user's own: theirs to finish.
    // Named first, since a replay left open leaves `bx.lock` changed too.
    if update::rebasing(git, &repo) {
        return Err(update::Error::Rebasing(repo));
    }
    update::refuse_edited_lock(git, &repo)?;
    // Diverged only by this machine's own unpushed bx update commits: those are
    // replayed on top of the upstream, keeping every lock and copy they hold.
    let pulled = match sync::pull(env, git) {
        Err(diverged @ sync::Error::Diverged { .. }) => {
            match update::replay_own_commits(git, &repo)? {
                update::Replay::Replayed(replayed) => {
                    say(
                        out,
                        &if replayed == 0 {
                            "This machine's unpushed bx update commits were already in what \
                             another machine pushed."
                                .to_string()
                        } else {
                            format!(
                                "Replayed {replayed} unpushed bx update commit(s) of this \
                                 machine's on top of what another machine pushed."
                            )
                        },
                    )?;
                    sync::pull(env, git)
                }
                update::Replay::Conflicted(commits) => {
                    return Err(update::Error::LockDiverged { commits, repo });
                }
                update::Replay::NotOwn => Err(diverged),
            }
        }
        other => other,
    };
    // Kept to push to once the lock is applied; with no upstream, one that is
    // gone, or no repository at all, there is nowhere to push.
    let pulled = match pulled {
        Ok(pulled) => {
            if pulled.fast_forwarded > 0 {
                say(out, &fast_forwarded(&pulled))?;
            }
            if pulled.recovered > 0 {
                say(out, &recovered_carry(&pulled))?;
            }
            Some(pulled)
        }
        Err(sync::Error::NoUpstream { branch, .. }) => {
            say(
                out,
                &format!(
                    "The config repo's {branch} has no upstream, so there is nothing to pull; \
                     bx update locks on top of it as it stands."
                ),
            )?;
            None
        }
        Err(sync::Error::UpstreamGone {
            branch, upstream, ..
        }) => {
            say(
                out,
                &format!(
                    "The config repo's {branch} tracks {upstream}, which does not exist, so \
                     there is nothing to pull; bx update locks on top of it as it stands."
                ),
            )?;
            None
        }
        Err(sync::Error::NotARepo { .. }) => {
            say(
                out,
                "The config repo is not a git repository, so there is nothing to pull or \
                 commit; bx update writes bx.lock there and commits nothing.",
            )?;
            None
        }
        Err(other) => return Err(other.into()),
    };

    let inputs = Inputs::load(env)?;
    let externals = &inputs.resolved().externals;
    let chosen = update::select(externals, names, &env.home)?;
    let ledger = crate::state::LedgerView::read(inputs.state(), &env.home)
        .map_err(Error::from)?
        .value;
    let found = update::look_all(
        git,
        update::Bound::EachRemote,
        &env.home,
        &chosen,
        inputs.lock(),
        &ledger,
    );
    for found in &found {
        say(out, &found.summary())?;
        if let update::Verdict::Moves { log: Some(log), .. } = &found.verdict {
            for line in log {
                say(out, &format!("    {}", report::escape(line)))?;
            }
        }
    }

    let before = inputs.lock().clone();
    let committed = inputs.committed_externals();
    let unshared: Vec<(&update::Found, Unshared)> = found
        .iter()
        .filter(|found| found.moves_to().is_some())
        .filter_map(|found| Some((found, update::why_unshared(found, committed)?)))
        .collect();
    for (found, unshared) in &unshared {
        let why = match unshared {
            Unshared::Elsewhere => {
                "and the committed configuration another branch or url; the shared bx.lock \
                 keeps the committed one's"
            }
            Unshared::NotCommitted => {
                "and the committed configuration does not follow it; the shared bx.lock holds \
                 only what the committed configuration follows. Declare it in a committed \
                 layer, or pin it with `rev`"
            }
        };
        say(
            out,
            &format!(
                "{}: this account follows `{}` of {}, {why}, so this is not locked",
                found.path, found.branch, found.url
            ),
        )?;
    }
    // Where `bx sync` would run, the apply is its own, carrying each tracked
    // target this machine changed into the repo; where `bx sync` would refuse
    // — no upstream to push to, or no repository to commit in — the apply is
    // a bare one, and the repo is left as it stands.
    let mode = if pulled.is_some() {
        Mode::Sync
    } else {
        Mode::Apply
    };
    let after = update::proposed(&before, &found, externals, committed);
    let message = update::message(&before, &after);
    let changed = after != before;
    let inputs = inputs.with_lock(after.clone());
    let mut asked = false;
    let mut recovering = false;
    let mut declined = false;
    let mut failed: Option<update::Error> = None;
    // Whether the lock was committed, so there is a commit to push.
    let made = std::cell::Cell::new(false);
    let lock = |failed: &mut Option<update::Error>| match update::write_and_commit(
        git, &repo, &after, &message,
    ) {
        Ok(commit) => {
            made.set(made.get() || commit);
            true
        }
        Err(error) => {
            *failed = Some(error);
            false
        }
    };
    let converged = converge_inputs(
        &inputs,
        env,
        mode,
        yes,
        out,
        ask,
        &mut |report, approved| {
            asked = true;
            if report.interrupted.is_some() {
                // The plan shown was recovery's alone, and never announced the
                // lock: recovery runs if approved, and nothing is locked.
                recovering = true;
                return approved;
            }
            declined = changed && !approved;
            // Committed before the first write, so a checkout never stands at a
            // commit the config repo does not name.
            approved && (!changed || lock(&mut failed))
        },
    );
    let report = match converged {
        Ok(report) => report,
        Err(Error::Canceled) => {
            say(out, "Canceled. Nothing was locked or applied.")?;
            return Ok(Updated::Stopped(Exit::Canceled, CANCELED));
        }
        Err(other) => return Err(other.into()),
    };
    if let Some(error) = failed {
        return Err(error);
    }
    if recovering {
        say(
            out,
            "Nothing was locked: an interrupted apply had to be dealt with first. Run bx update \
             again.",
        )?;
        let exit = match plan::exit(&report, mode) {
            Exit::Converged => Exit::Pending,
            exit => exit,
        };
        return Ok(Updated::Stopped(
            exit,
            "bx update dealt with an interrupted apply first, and locked nothing",
        ));
    }
    // A lock that moves nothing `apply` writes — an entry dropped, or a
    // checkout that is a conflict either way — is still the user's to approve.
    if changed && !asked {
        let approved = if yes {
            true
        } else {
            match ask() {
                Ok(approved) => approved,
                Err(Error::Canceled) => {
                    say(out, "Canceled. Nothing was locked.")?;
                    return Ok(Updated::Stopped(Exit::Canceled, CANCELED));
                }
                Err(other) => return Err(other.into()),
            }
        };
        declined = !approved;
        if approved && lock(&mut failed) {
            say(out, "Locked.")?;
        }
        if let Some(error) = failed {
            return Err(error);
        }
    }
    let attention = !unshared.is_empty()
        || found.iter().any(|found| {
            matches!(
                found.verdict,
                update::Verdict::Rewritten { .. }
                    | update::Verdict::Unproven { .. }
                    | update::Verdict::Unreachable(_)
            )
        });
    let exit = match plan::exit(&report, mode) {
        Exit::Converged if attention => Exit::Pending,
        exit => exit,
    };
    // Declined, what was found stays on offer, answered: the same commits
    // are not offered again, and newer ones are.
    if declined {
        return Ok(Updated::Stopped(
            exit,
            "bx update was declined, and locked nothing",
        ));
    }
    if let Some(pulled) = &pulled {
        // As `bx sync` does: every carried file in one commit, after the
        // lock's, and pushed with it.
        let carried = sync::commit_carried(env, git, &pulled.repo)?;
        if carried > 0 {
            say(out, &committed_carry(carried, pulled))?;
        }
        let committed = u64::from(made.get()) + u64::from(carried > 0);
        push_lock(git, pulled, committed, &report, out)?;
    }
    update::finished(&inputs)?;
    Ok(Updated::Finished(exit))
}

/// Publish what `bx update` leaves the config repo's branch ahead by: the
/// commits [`sync::pull`] found unpushed, and the `committed` ones this run
/// made — the lock's, and the one carrying tracked files back.
///
/// The push is [`sync::push`]'s, never forced, and runs only when
/// [`sync::may_push`] says the apply left nothing undone, as `bx sync`'s does.
/// A push the remote refuses — it moved since the pull, or cannot be reached
/// — is said, not raised: the commits stay here, the lock's or the carry's
/// or both, `bx sync` pushes them, and a `bx update` replays them first over
/// an upstream that moved.
fn push_lock(
    git: &Git,
    pulled: &sync::Pulled,
    committed: u64,
    report: &Report,
    out: &mut dyn Write,
) -> Result<(), update::Error> {
    let ahead = pulled.ahead + committed;
    if ahead == 0 {
        return Ok(());
    }
    let upstream = &pulled.upstream.short;
    let said = if !sync::may_push(report) {
        format!(
            "Pushed nothing: {ahead} commit(s) wait for an apply that leaves nothing undone; \
             run `bx sync` to push them."
        )
    } else {
        match sync::push(git, pulled) {
            Ok(()) => format!("Pushed {ahead} commit(s) to {upstream}."),
            Err(error) => {
                tracing::debug!(%error, "the push of the bx update commits was refused");
                format!(
                    "Pushed nothing: the push to {upstream} was refused ({error}). The \
                     {ahead} commit(s) stay committed here, and `bx sync` pushes them; if \
                     {upstream} moved, run `bx update` first, which replays them on top."
                )
            }
        }
    };
    writeln!(out, "{said}").map_err(update::Error::Output)
}

/// What `last-check` says after a `bx update` abandoned at its question.
const CANCELED: &str = "bx update was canceled, and locked nothing";

/// `bx init`: create the repo when there is none, answer this account's unset
/// values, offer the config already on the machine, then plan and apply
/// exactly as `bx apply` does.
///
/// Questions are asked only when standard input is a terminal and `yes` is
/// not given; see [`init::answer`]. The plan and its approval are
/// [`apply`]'s, so `yes` is the same approval, and without it or a terminal
/// nothing pending is written.
///
/// It says what it found and each thing it wrote as it writes it, before the
/// next question, and ends with where the machine stands. A question
/// abandoned with Esc or Ctrl-C ends it with [`Exit::Canceled`], keeping what
/// was already written: the next `init` picks up from there.
///
/// # Errors
///
/// Whatever [`init::answer`] and [`init::adopt_offered`] return, then as
/// [`apply`].
pub fn init(
    env: &Env,
    sets: &[String],
    yes: bool,
    out: &mut dyn Write,
) -> Result<Exit, init::Error> {
    init_with(env, sets, yes, out, &mut init::Terminal, &mut confirm)
}

/// [`init`], with its questions asked through `ask` and `confirm`.
fn init_with(
    env: &Env,
    sets: &[String],
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn init::Ask,
    confirm: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, init::Error> {
    let interactive = env.stdin_tty && !yes;
    let answered = match init::answer(env, sets, interactive, ask) {
        Ok(answered) => answered,
        // Answers are written only once every question is answered, so there
        // is nothing to pick up: the next run asks them all again.
        Err(init::Error::Canceled) => {
            return init_canceled(out, "Nothing was written; run `bx init` again when ready.");
        }
        Err(other) => return Err(other),
    };
    let repo = paths::to_portable(&answered.repo, &env.home);
    let mut text = if answered.created {
        format!("Created the config repo {repo} with bx.toml.\n")
    } else {
        format!("Using the config repo {repo}.\n")
    };
    if let Some(local) = &answered.saved {
        text.push_str(&format!(
            "Saved this account's answers to {}.\n",
            paths::to_portable(local, &env.home)
        ));
    }
    // Said before the next question is put, so someone who walks away from
    // it has already been told what this run wrote.
    say(out, &text)?;

    let mut adopted = 0_usize;
    if interactive {
        let deferred = init::adopt_offered(env, ask, &mut |row| {
            adopted += 1;
            say(out, &adoption_row(row))
        });
        match deferred {
            Ok(init::Deferred::No) => {}
            // A journal is all `adopt_offered` sees, and it may be a running
            // `apply`'s as well as an interrupted one's, so neither line says
            // which, nor that the plan will show it.
            Ok(init::Deferred::BeforeOffering) => say(
                out,
                "Offered nothing to adopt: a bx session is running or was interrupted, and \
                 adopting waits for it. Run `bx init` again once it has finished or been \
                 recovered.\n",
            )?,
            Ok(init::Deferred::AfterPicking) => say(
                out,
                "Adopted nothing more of what was picked: a bx session is running or was interrupted, and \
                 adopting waits for it. Run `bx init` again once it has finished or been \
                 recovered, and pick again.\n",
            )?,
            Err(init::Error::Canceled) => {
                return init_canceled(
                    out,
                    "Nothing was adopted. Run `bx init` again to pick up where this stopped.",
                );
            }
            Err(other) => return Err(other),
        }
    }

    let report = match converge(env, Mode::Apply, yes, out, confirm) {
        Ok(report) => report,
        Err(Error::Canceled) => {
            return init_canceled(
                out,
                "Nothing was applied. Run `bx init` again to pick up where this stopped.",
            );
        }
        Err(other) => return Err(other.into()),
    };
    let exit = plan::exit(&report, Mode::Apply);
    // A run that recovered has said so, with what to run next, and did
    // nothing else; a closing line would be a second, different instruction.
    if report.recovered.is_none() {
        let did = answered.created || answered.saved.is_some() || adopted > 0 || report.executed;
        say(out, init_closing(exit, did))?;
    }
    Ok(exit)
}

/// Write `text` and flush it, so it is on screen before a prompt waits.
fn say(out: &mut dyn Write, text: &str) -> Result<(), init::Error> {
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(init::Error::Output)
}

/// What `init` says when a question is walked away from: `then` is what that
/// question stood before, and what to do next. Everything earlier has
/// already been said.
fn init_canceled(out: &mut dyn Write, then: &str) -> Result<Exit, init::Error> {
    say(out, &format!("Canceled. {then}\n"))?;
    Ok(Exit::Canceled)
}

/// `init`'s last line: where the machine stands and what to run next. `did`
/// is whether this run wrote anything at all.
const fn init_closing(exit: Exit, did: bool) -> &'static str {
    match (exit, did) {
        // Not "nothing to answer": config left unmanaged is offered again on
        // every interactive run, so this may follow a question.
        (Exit::Converged, false) => {
            "Already set up: nothing to apply. Manage a file with `bx add PATH`; change an \
             answer with `bx init --set NAME=VALUE`.\n"
        }
        (Exit::Converged, true) => {
            "Set up. Manage a file with `bx add PATH`; change an answer with \
             `bx init --set NAME=VALUE`.\n"
        }
        (Exit::Pending, _) => {
            "Not finished: see the plan above, then run `bx init` or `bx apply` again.\n"
        }
        // Neither is an exit a plan produces.
        (Exit::Error | Exit::Canceled, _) => "",
    }
}

/// What an `apply` that recovered an interrupted session, and did nothing else,
/// says it did.
fn recovered(report: &Report, outcome: &crate::recover::Outcome) -> String {
    use crate::recover::Outcome;

    let done = match outcome {
        Outcome::RolledBack { undone } => {
            format!("Rolled back {undone} write(s) from an interrupted session")
        }
        Outcome::Recorded { entries } => {
            format!("Recorded {entries} write(s) an interrupted session made")
        }
        // A blocked recovery is an error, never an outcome `apply` reports.
        Outcome::Nothing | Outcome::Blocked { .. } => {
            if report
                .interrupted
                .as_ref()
                .is_some_and(|interrupted| interrupted.unreadable)
            {
                "Set aside the journal bx could not read".to_string()
            } else {
                "Found nothing left to recover".to_string()
            }
        }
    };
    format!("{done}; nothing else was applied; run `bx plan` again.")
}

/// `bx secret list`: every declared secret, its ciphertext, and whether this
/// account can decrypt it now.
///
/// The one command that may ask for an identity's passphrase, and only when
/// standard input is a terminal; without one a locked identity is reported as
/// locked. Each secret is checked on its own, so a locked identity is asked
/// for once per secret: nothing keeps a passphrase between them. Nothing is
/// written.
///
/// Exits [`Exit::Converged`] when every secret can be decrypted, and
/// [`Exit::Pending`] when one cannot.
///
/// # Errors
///
/// Whatever loading returns, and [`Error::Output`] when `out` cannot be
/// written. A secret that cannot be read or decrypted is a row, not an error.
pub fn secret_list(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    secret_list_with(env, out, &mut ask_passphrase)
}

/// Ask on the terminal for an identity's passphrase, masked. A prompt that
/// fails or is cancelled is no passphrase, and the identity stays locked.
fn ask_passphrase(shown: &str) -> Option<Passphrase> {
    inquire::Password::new(&format!("Passphrase for {shown}:"))
        .without_confirmation()
        .prompt()
        .ok()
        .map(Passphrase::from)
}

/// [`secret_list`], with the passphrase asked through `ask`.
fn secret_list_with(
    env: &Env,
    out: &mut dyn Write,
    ask: &mut dyn FnMut(&str) -> Option<Passphrase>,
) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let secrets = &inputs.resolved().secrets;
    let identity = secrets.identity_path(inputs.home());
    let shown = secrets.identity_spelling();

    let mut text = String::new();
    let mut all = true;
    for (declared, resolution) in inputs.declared_targets() {
        let Body::Secret(written) = &declared.body else {
            continue;
        };
        let (target, ciphertext, status) = match resolution {
            Resolution::Blocked(entry) => (
                entry.key.clone(),
                written.display().to_string(),
                Err(format!("blocked: {}", entry.hint)),
            ),
            Resolution::Ready(target) => {
                let Body::Secret(rel) = &target.body else {
                    unreachable!("substitution keeps a secret a secret");
                };
                let status = plan::read_repo_file(target, inputs.repo(), rel)
                    .map_err(|error| format!("unreadable: {error}"))
                    .and_then(|bytes| {
                        let unlock = if env.stdin_tty {
                            Unlock::Ask(&mut *ask)
                        } else {
                            Unlock::Never
                        };
                        crate::secret::decrypt(&bytes, &identity, shown, unlock)
                            .map_err(|refusal| format!("not decryptable: {refusal}"))
                    });
                (
                    target.path.as_str().to_string(),
                    rel.display().to_string(),
                    status.map(drop),
                )
            }
        };
        all &= status.is_ok();
        let status = status.map_or_else(|why| why, |()| "decryptable".to_string());
        text.push_str(&format!("  {target}  {ciphertext}  {status}\n"));
    }
    if text.is_empty() {
        text.push_str("No secrets are declared.\n");
    }
    out.write_all(text.as_bytes()).map_err(Error::Output)?;
    Ok(if all { Exit::Converged } else { Exit::Pending })
}

/// A command the binary parses and this release has no body for: says so on
/// `err`, in one line, and exits [`Exit::Error`].
///
/// `command` is the command as the user typed it, `bx shell-init`.
///
/// # Errors
///
/// [`Error::Output`] when `err` cannot be written.
pub fn not_built(command: &str, err: &mut dyn Write) -> Result<Exit, Error> {
    err.write_all(format!("{command} is not built yet in this release of bx.\n").as_bytes())
        .map_err(Error::Output)?;
    Ok(Exit::Error)
}

/// `bx add PATH`: adopt a file, or every regular file under a directory, byte
/// for byte.
///
/// Prints one row per path: `+` adopted, `=` already managed, `~` already
/// declared and now owned, `-` passed over inside a directory, `!` refused.
/// Exits 0 when everything named was adopted or already managed, and 2 when
/// something was refused.
///
/// # Errors
///
/// [`adopt::Error::NoPath`] without a path, and whatever locating, loading
/// or adopting returns.
pub fn add(
    env: &Env,
    cwd: &Path,
    path: Option<&str>,
    out: &mut dyn Write,
) -> Result<Exit, adopt::Error> {
    let path = path.ok_or(adopt::Error::NoPath("add"))?;
    let target = adopt::locate(path, cwd, &env.home)?;
    let ctx = adopt::Context::load(env)?;
    let rows = adopt::add(&ctx, &target)?;
    let mut text = String::new();
    for row in &rows {
        text.push_str(&adoption_row(row));
    }
    let adopted = rows
        .iter()
        .filter(|row| matches!(row, Adoption::Adopt { .. }))
        .count();
    text.push_str(&format!(
        "Adopted {adopted} file(s); run `bx plan` to see the machine against the repo.\n"
    ));
    out.write_all(text.as_bytes())
        .map_err(adopt::Error::Output)?;
    Ok(if rows.iter().any(Adoption::needs_attention) {
        Exit::Pending
    } else {
        Exit::Converged
    })
}

/// One `add` row, with its note and any warning on the lines below it.
fn adoption_row(row: &Adoption) -> String {
    let target = row.target();
    match row {
        Adoption::Adopt {
            body,
            reuse,
            warnings,
            ..
        } => {
            let how = if *reuse {
                "declared, reusing"
            } else {
                "copied to"
            };
            let mut line = format!("  + {target}  ({how} {})\n", body.display());
            for warning in warnings {
                line.push_str(&format!(
                    "    warning: {warning}; adopted as written, and bx will write it back as is\n"
                ));
            }
            line
        }
        Adoption::Own { .. } => format!("  ~ {target}  already declared; bx now owns it\n"),
        Adoption::Unchanged { .. } => format!("  = {target}  already managed\n"),
        Adoption::Skipped { note, .. } => format!("  - {target}  skipped: {note}\n"),
        Adoption::Refused { note, .. } => format!("  ! {target}  {note}\n"),
    }
}

/// `bx rm PATH`: stop managing a target, or every target beneath a directory,
/// restoring what bx displaced.
///
/// Exits 0 when everything was handed back, or nothing was managed there, and
/// 2 when a conflict left something as it was.
///
/// # Errors
///
/// [`adopt::Error::NoPath`] without a path, and whatever locating, loading
/// or restoring returns.
pub fn rm(
    env: &Env,
    cwd: &Path,
    path: Option<&str>,
    out: &mut dyn Write,
) -> Result<Exit, adopt::Error> {
    let path = path.ok_or(adopt::Error::NoPath("rm"))?;
    let target = adopt::locate(path, cwd, &env.home)?;
    let ctx = adopt::Context::load(env)?;
    let removals = adopt::rm(&ctx, &target)?;
    let mut text = String::new();
    if removals.is_empty() {
        text.push_str(&format!("{target} is not managed by bx; nothing to do.\n"));
    }
    for removal in &removals {
        text.push_str(&removal_row(removal, ctx.home()));
    }
    out.write_all(text.as_bytes())
        .map_err(adopt::Error::Output)?;
    Ok(
        if removals
            .iter()
            .any(|removal| removal.restored.is_conflict())
        {
            Exit::Pending
        } else {
            Exit::Converged
        },
    )
}

/// One `rm` row.
fn removal_row(removal: &Removal, home: &Path) -> String {
    let target = removal.restored.target();
    let did = match &removal.restored {
        Restored::Reverted { .. } => "put back the file bx replaced".to_string(),
        Restored::Removed { .. } => "removed the file bx created".to_string(),
        Restored::AlreadyGone { .. } => "was already gone".to_string(),
        Restored::Unmanaged { .. } => "left as it is; bx never wrote it".to_string(),
        Restored::Conflict { note, .. } => {
            return format!("  ! {target}  {note}; still managed\n");
        }
    };
    let mut line = format!("  - {target}  {did}");
    for layer in &removal.undeclared {
        line.push_str(&format!(
            "; no longer declared in {}",
            crate::paths::to_portable(layer, home)
        ));
    }
    for body in &removal.bodies {
        line.push_str(&format!("; {} stays in the repo", body.display()));
    }
    line.push('\n');
    line
}

/// Load, decide read-only, and show.
fn show(env: &Env, view: View, out: &mut dyn Write) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let report = plan::run(&inputs, Mode::Plan, &mut |_| Ok(false))?;
    emit(out, &report, view, env)?;
    Ok(plan::exit(&report, Mode::Plan))
}

/// Write the rendering of `report`, coloured as the environment allows.
fn emit(out: &mut dyn Write, report: &Report, view: View, env: &Env) -> Result<(), Error> {
    let palette = Palette::resolve(env.no_color, env.stdout_tty);
    out.write_all(plan::render(report, view, palette, &env.home).as_bytes())
        .map_err(Error::Output)
}

#[cfg(test)]
mod tests;
