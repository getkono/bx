//! The bodies of `bx`, `bx init`, `bx plan`, `bx apply`, `bx sync`,
//! `bx update`, `bx upgrade`, `bx doctor`, `bx add`, `bx rm`,
//! `bx secret list`, `bx abandon` and `bx self-upgrade`, and the refusal of
//! `bx shell-init` and `bx __complete`, which have none yet.
//!
//! Each loads the configuration, runs the one traversal in [`crate::plan`] —
//! or, for `doctor`, the read-only checks in [`crate::doctor`], for `add` and
//! `rm`, [`crate::adopt`], for `init`, [`crate::init`] before the
//! traversal, for `sync`, [`crate::sync`] around it, and for `update` and
//! `upgrade`, the run in `crate::update::run` around it, with
//! [`crate::pin`] beside that for `upgrade` — writes the rendering
//! to the output it is
//! handed, and returns the exit status. `self-upgrade` reads no configuration:
//! it is [`crate::upgrade`] run for the binary that is running. Nor does
//! `abandon`: it is [`crate::recover::abandon`] run for this home's state
//! directory. `main` does
//! nothing but call one of them.

use std::io::Write;
use std::path::Path;

use crate::adopt::{self, Adoption, Removal};
use crate::config::resolve::Resolution;
use crate::config::target::Body;
use crate::doctor::{self, Probes, systemd};
use crate::env::Env;
use crate::git::Git;
use crate::init;
use crate::paths;
use crate::pin;
use crate::plan::{self, Error, Inputs, Mode, Palette, Report, View};
use crate::report::{self, Action, Exit};
use crate::restore::Restored;
use crate::secret::{Passphrase, Unlock};
use crate::sync;
use crate::update::{self, run, run::Scope};
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
/// only discards what was typed ahead and puts the question.
///
/// Nothing typed before the question is shown answers it: the Enter after the
/// `y` that answered the shell's `bx: update now?` would otherwise be read
/// here as the default, and a `y` typed ahead as approval.
fn confirm() -> Result<bool, Error> {
    discard_typeahead(std::io::stdin());
    inquire::Confirm::new("Apply these changes?")
        .with_default(false)
        .prompt()
        .map_err(confirmation_failed)
}

/// Discard what was typed on `terminal` and not yet read. A refusal is only
/// logged: where `terminal` is not one, nothing can have been typed ahead on
/// it, and a terminal that refuses fails the prompt that follows, which
/// reports it.
fn discard_typeahead(terminal: impl std::os::fd::AsFd) {
    if let Err(error) = rustix::termios::tcflush(terminal, rustix::termios::QueueSelector::IFlush) {
        tracing::debug!(%error, "typeahead not discarded");
    }
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
pub(crate) fn converge_inputs(
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
pub(crate) fn fast_forwarded(pulled: &sync::Pulled) -> String {
    format!(
        "Fast-forwarded {} by {} commit(s) from {}.",
        pulled.branch, pulled.fast_forwarded, pulled.upstream.short
    )
}

/// The line `sync` and `update` say after [`sync::pull`] committed the
/// tracked copies an interrupted sync left uncommitted.
pub(crate) fn recovered_carry(pulled: &sync::Pulled) -> String {
    format!(
        "Committed {} tracked file(s) an interrupted bx sync carried into the repo.",
        pulled.recovered
    )
}

/// The line `sync` and `update` say after [`sync::commit_carried`] committed
/// the `carried` tracked copies this run's apply wrote.
pub(crate) fn committed_carry(carried: usize, pulled: &sync::Pulled) -> String {
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
    run::scoped(env, names, Scope::Followed, yes, out, git, ask)
}

/// `bx upgrade`: everything [`update`] does, and move each pinned external to
/// its newest release; then say whether bx itself has a newer release.
///
/// The followed externals are looked at and locked exactly as `bx update`
/// does. Each pinned one `names` selects — every one, with no names — is
/// looked at with [`pin::look`]; one that moves has its `rev` rewritten in
/// the layer whose entry won the merge, and that rewrite is shown as a diff
/// before the plan, which is decided against the new commits. Once approved,
/// the lock's commit and then one commit of the rewritten committed layers,
/// [`pin::SUBJECT`], are made **before** any checkout moves; `local.toml` is
/// rewritten and never committed. The apply, the carry and the push are
/// `bx update`'s, so the two commits are pushed with every other.
///
/// A pin commit whose push was refused is replayed by the next `bx update`
/// or `bx upgrade` over an upstream that moved, as a lock commit is
/// ([`update::replay_own_commits`]), unless the upstream changed the same
/// layer.
///
/// A pin is offered only once a checkout of bx's shows the new commit
/// descends from the one pinned, since `apply` moves a checkout only forward;
/// a fresh machine clones first, and offers it on the next run.
///
/// The binary is only reported on, with [`self_upgrade`]'s check: replacing
/// it is `bx self-upgrade`'s. A check that fails is said in one line, and
/// changes no exit status.
///
/// With `check`, it moves nothing: [`update::check`] for the followed
/// externals, [`pin::look`] for the pinned ones, and the binary's check.
/// It exits [`Exit::Pending`] when any of the three has something newer,
/// otherwise [`Exit::Error`] when one could not look, and otherwise
/// [`Exit::Converged`].
///
/// # Errors
///
/// As [`update`], with [`update::Error::NotExternal`] for a name that is no
/// external's path, [`update::Error::LayerEdited`] for a committed layer to
/// rewrite that holds changes nobody committed, and [`update::Error::Pin`]
/// for a layer that cannot be rewritten.
pub fn upgrade(
    env: &Env,
    names: &[String],
    yes: bool,
    check: bool,
    out: &mut dyn Write,
) -> Result<Exit, update::Error> {
    let mode = if check {
        Upgrading::Check
    } else {
        Upgrading::Upgrade { yes }
    };
    upgrade_with(
        env,
        names,
        mode,
        out,
        &Git::new(env),
        &mut confirm,
        &mut |out| self_upgrade(true, false, out),
    )
}

/// What `bx upgrade` is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Upgrading {
    /// Upgrade, approved without asking when `yes`.
    Upgrade { yes: bool },
    /// Only look and report.
    Check,
}

/// [`upgrade`], through `git`, with the question asked through `ask`, and
/// the binary checked by `binary`.
fn upgrade_with(
    env: &Env,
    names: &[String],
    mode: Upgrading,
    out: &mut dyn Write,
    git: &Git,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
    binary: &mut dyn FnMut(&mut dyn Write) -> Result<Exit, upgrade::Error>,
) -> Result<Exit, update::Error> {
    if let Upgrading::Upgrade { yes } = mode {
        let exit = run::scoped(env, names, Scope::FollowedAndPinned, yes, out, git, ask)?;
        if let Err(error) = binary(out) {
            writeln!(out, "bx itself: not checked: {error}").map_err(update::Error::Output)?;
        }
        return Ok(exit);
    }
    let inputs = Inputs::load(env)?;
    let (followed, pinned) = pin::select(&inputs.resolved().externals, names, &env.home)?;
    let mut exits = Vec::new();
    // Each followed one chosen, by name: with none, `bx update --check`
    // would look at every followed one instead.
    if !followed.is_empty() {
        let followed: Vec<String> = followed
            .iter()
            .map(|external| external.path.to_string())
            .collect();
        exits.push(update::check(env, &followed, false, git, out)?);
    }
    if !pinned.is_empty() {
        let state = crate::state::StateDir::resolve_in(&env.home, env.xdg_state_home.as_deref());
        let _held = update::Stamps::of(&state)
            .hold(update::HOLD_WAIT)?
            .ok_or(update::Error::Busy)?;
        let ledger = crate::state::LedgerView::read(inputs.state(), &env.home)
            .map_err(Error::from)?
            .value;
        for found in pin::look_all(git, &env.home, &pinned, &ledger) {
            writeln!(out, "{}", found.summary()).map_err(update::Error::Output)?;
            exits.push(match found.verdict {
                pin::Verdict::Moves { .. } => Exit::Pending,
                pin::Verdict::Unreachable(_) => Exit::Error,
                _ => Exit::Converged,
            });
        }
    }
    exits.push(binary(out).unwrap_or_else(|error| {
        let _ = writeln!(out, "bx itself: not checked: {error}");
        Exit::Error
    }));
    Ok(worst(&exits))
}

/// The exit of several checks: [`Exit::Pending`] when any has something
/// newer, then [`Exit::Error`] when any could not look, then
/// [`Exit::Converged`].
fn worst(exits: &[Exit]) -> Exit {
    [Exit::Pending, Exit::Error]
        .into_iter()
        .find(|exit| exits.contains(exit))
        .unwrap_or(Exit::Converged)
}

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
    let target = row.subject();
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
        Restored::Kept { .. } => {
            "left as you edited it; nothing declares it, so bx stops managing it".to_string()
        }
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

/// `bx abandon`: set aside an interrupted session's journal, touching no
/// other file, so a recovery that cannot account for a destination stops
/// refusing every writing command.
///
/// Reads no configuration: it is [`crate::recover::abandon`] run for this
/// home's state directory. What the session left behind is then the next
/// `plan`'s to judge, which reports a file bx cannot account for as a
/// conflict and never overwrites it. Exits 0 whether a journal was set aside
/// or there was none.
///
/// # Errors
///
/// Whatever [`crate::recover::abandon`] returns — the lock held by another
/// bx, a journal a newer bx wrote, a journal that cannot be moved — and
/// [`Error::Output`] when `out` cannot be written.
pub fn abandon(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    let state = crate::state::StateDir::resolve_in(&env.home, env.xdg_state_home.as_deref());
    let text = match crate::recover::abandon(&state)? {
        None => "No interrupted session to abandon.\n".to_string(),
        Some(aside) => format!(
            "Set the interrupted session aside in {}, touching no other file.\n\
             `bx plan` shows what it left; a file bx cannot account for is a conflict, \
             never overwritten.\n",
            paths::to_portable(aside.as_path(), &env.home),
        ),
    };
    out.write_all(text.as_bytes()).map_err(Error::Output)?;
    Ok(Exit::Converged)
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
