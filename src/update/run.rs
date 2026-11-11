//! The run `bx update` and `bx upgrade` share: refuse what stands in the
//! config repo, pull it — replaying this machine's own unpushed commits over
//! an upstream that moved — look at each external moved, show the plan,
//! commit the lock and the pins once approved, apply, carry, and push.
//!
//! [`crate::command::update`] and [`crate::command::upgrade`] are the entry
//! points; [`scoped`] is what both run, with the [`Scope`] that says which
//! externals move. The rendering and the one confirmation are
//! [`crate::command`]'s own, shared with `bx apply` and `bx sync`.

use std::io::Write;

use crate::command::{committed_carry, converge_inputs, fast_forwarded, recovered_carry};
use crate::config::lock::Unshared;
use crate::env::Env;
use crate::git::Git;
use crate::paths;
use crate::pin;
use crate::plan::{self, Error, Inputs, Mode, Report};
use crate::report::{self, Exit};
use crate::sync;
use crate::update;

/// What a `bx update` or a `bx upgrade` moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// `bx update`: followed externals, within their branches.
    Followed,
    /// `bx upgrade`: those, and each pinned external to its newest release.
    FollowedAndPinned,
}

impl Scope {
    /// The command, as `last-check` and the output name it.
    const fn command(self) -> &'static str {
        match self {
            Self::Followed => "bx update",
            Self::FollowedAndPinned => "bx upgrade",
        }
    }

    /// What `last-check` says after a run abandoned at its question.
    const fn canceled(self) -> &'static str {
        match self {
            Self::Followed => "bx update was canceled, and locked nothing",
            Self::FollowedAndPinned => "bx upgrade was canceled, and locked or upgraded nothing",
        }
    }

    /// What `last-check` says after a declined run.
    const fn declined(self) -> &'static str {
        match self {
            Self::Followed => "bx update was declined, and locked nothing",
            Self::FollowedAndPinned => "bx upgrade was declined, and locked or upgraded nothing",
        }
    }

    /// What `last-check` says after a run that recovered an interrupted
    /// apply instead.
    const fn recovered(self) -> &'static str {
        match self {
            Self::Followed => "bx update dealt with an interrupted apply first, and locked nothing",
            Self::FollowedAndPinned => {
                "bx upgrade dealt with an interrupted apply first, and locked or upgraded nothing"
            }
        }
    }
}

/// `bx update`'s [`crate::command::UpdateMode::Update`], moving what `scope`
/// names, through `git`, with the question asked through `ask`: shared by
/// `bx update` and `bx upgrade`, so the second does all of the first's work.
pub(crate) fn scoped(
    env: &Env,
    names: &[String],
    scope: Scope,
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
    let why = match updating(env, names, scope, yes, out, git, ask) {
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

/// [`scoped`], under `update/check.lock`.
fn updating(
    env: &Env,
    names: &[String],
    scope: Scope,
    yes: bool,
    out: &mut dyn Write,
    git: &Git,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Updated, update::Error> {
    let say =
        |out: &mut dyn Write, text: &str| writeln!(out, "{text}").map_err(update::Error::Output);
    let repo = paths::config_root_in(&env.home, env.xdg_config_home.as_deref());
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
            if pulled.fast_forwarded != 0 {
                say(out, &fast_forwarded(&pulled))?;
            }
            if pulled.recovered != 0 {
                say(out, &recovered_carry(&pulled))?;
            }
            Some(pulled)
        }
        Err(sync::Error::NoUpstream { branch, .. }) => {
            say(
                out,
                &format!(
                    "The config repo's {branch} has no upstream, so there is nothing to pull; \
                     {} locks on top of it as it stands.",
                    scope.command()
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
                     there is nothing to pull; {} locks on top of it as it stands.",
                    scope.command()
                ),
            )?;
            None
        }
        Err(sync::Error::NotARepo { .. }) => {
            say(
                out,
                &format!(
                    "The config repo is not a git repository, so there is nothing to pull or \
                     commit; {} writes there and commits nothing.",
                    scope.command()
                ),
            )?;
            None
        }
        Err(other) => return Err(other.into()),
    };

    let inputs = Inputs::load(env)?;
    let externals = &inputs.resolved().externals;
    let (chosen, pinned) = match scope {
        Scope::Followed => (update::select(externals, names, &env.home)?, Vec::new()),
        Scope::FollowedAndPinned => pin::select(externals, names, &env.home)?,
    };
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
    let upgraded = pin::look_all(git, &env.home, &pinned, &ledger);
    for found in &upgraded {
        say(out, &found.summary())?;
        if let pin::Verdict::Moves { log: Some(log), .. } = &found.verdict {
            for line in log {
                say(out, &format!("    {}", report::escape(line)))?;
            }
        }
    }
    let edits = pin::edits(&upgraded, &repo, &env.home)?;
    pin::refuse_edited(git, &repo, &edits)?;
    // The configuration rewritten, announced before the plan of the checkouts
    // it moves, so nothing is written that was not shown.
    for edit in &edits {
        out.write_all(pin::shown(edit, &env.home).as_bytes())
            .map_err(update::Error::Output)?;
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
    let relocks = after != before;
    let pins = pin::pins(&upgraded);
    let repins = !edits.is_empty();
    let pin_message = pin::message(&upgraded);
    let changed = relocks || repins;
    let inputs = inputs.with_lock(after.clone()).with_pins(&pins);
    let mut asked = false;
    let mut recovering = false;
    let mut declined = false;
    let mut failed: Option<update::Error> = None;
    // How many commits were made — the lock's, the pins' — so there is a
    // commit to push.
    let made = std::cell::Cell::new(0_u64);
    // The lock first, then the pins: a pin commit git refuses puts its layers
    // back, and leaves the lock's commit for the next run's apply.
    let commit = || -> Result<u64, update::Error> {
        let locked = relocks && update::write_and_commit(git, &repo, &after, &message)?;
        let pinned = repins && pin::write_and_commit(git, &repo, &edits, &pin_message)?;
        Ok(u64::from(locked) + u64::from(pinned))
    };
    let lock = |failed: &mut Option<update::Error>| match commit() {
        Ok(commits) => {
            made.set(made.get() + commits);
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
            return Ok(Updated::Stopped(Exit::Canceled, scope.canceled()));
        }
        Err(other) => return Err(other.into()),
    };
    if let Some(error) = failed {
        return Err(error);
    }
    if recovering {
        say(
            out,
            &format!(
                "Nothing was locked: an interrupted apply had to be dealt with first. Run {} \
                 again.",
                scope.command()
            ),
        )?;
        let exit = match plan::exit(&report, mode) {
            Exit::Converged => Exit::Pending,
            exit => exit,
        };
        return Ok(Updated::Stopped(exit, scope.recovered()));
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
                    return Ok(Updated::Stopped(Exit::Canceled, scope.canceled()));
                }
                Err(other) => return Err(other.into()),
            }
        };
        declined = !approved;
        if approved && lock(&mut failed) {
            say(out, if repins { "Upgraded." } else { "Locked." })?;
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
        })
        || upgraded.iter().any(|found| {
            matches!(
                found.verdict,
                pin::Verdict::Rewritten { .. }
                    | pin::Verdict::Unproven { .. }
                    | pin::Verdict::Unreachable(_)
            )
        });
    let exit = match plan::exit(&report, mode) {
        Exit::Converged if attention => Exit::Pending,
        exit => exit,
    };
    // Declined, what was found stays on offer, answered: the same commits
    // are not offered again, and newer ones are.
    if declined {
        return Ok(Updated::Stopped(exit, scope.declined()));
    }
    if let Some(pulled) = &pulled {
        // As `bx sync` does: every carried file in one commit, after the
        // lock's, and pushed with it.
        let carried = sync::commit_carried(env, git, &pulled.repo)?;
        let carry = carried != 0;
        if carry {
            say(out, &committed_carry(carried, pulled))?;
        }
        let committed = made.get() + u64::from(carry);
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
