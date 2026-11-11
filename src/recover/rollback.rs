//! Carrying out recovery: the steps [`super::inspect::decide`] chose, the
//! ledger they rebuild, and the journal last of all.

use std::path::PathBuf;

use super::inspect::{Spelling, Step, decide, rebuild_home};
use super::{Error, Outcome};
use crate::fs::{self, remove};
use crate::journal::{self, Loaded, Written};
use crate::state::{ExclusiveLock, Ledger, StateDir};

/// The body of [`recover`](super::recover), with the lock already held.
pub(super) fn resolve(state: &StateDir, lock: &ExclusiveLock) -> Result<Outcome, Error> {
    let path = state.journal();
    let loaded = journal::load_exclusive(&path, lock)?;
    let complete = match loaded {
        Loaded::Absent | Loaded::Unreadable { .. } => return Ok(Outcome::Nothing),
        Loaded::Terminated(_) => true,
        Loaded::Unterminated(_) | Loaded::Torn { .. } => false,
    };
    // A journal that lost bytes is set aside at the end rather than unlinked.
    // The set-aside name is always free — the number after the highest
    // present, past any name taken since, or, once the top number is
    // present, the lowest free one — so nothing needs checking before the
    // rollback.
    let torn = matches!(loaded, Loaded::Torn { .. });
    let home = rebuild_home(&loaded, complete, &path)?;

    // Only a terminated journal's bookkeeping touches the ledger, and it is the
    // one kind with a home to check the ledger's stored paths against. A roll
    // back leaves the saved ledger exactly as it was, so it opens nothing.
    let mut ledger = match home {
        Some(home) => Some(Ledger::open(state, lock, home)?.value),
        None => None,
    };
    let mut conflicts = Vec::new();
    let mut resolved = 0_usize;
    // Every directory a target the terminated session dropped from the ledger
    // claimed. The session prunes a removal's after its `End` frame, so a crash
    // between the two leaves them standing. Handing on what still stands is
    // bookkeeping its save may not have reached; recovery removes none of them,
    // because a terminated session is never rolled back or finished on its
    // behalf, and one no entry is beneath is left for `bx doctor`, as
    // decision 11 keeps an orphaned temporary file.
    //
    // Owned rather than borrowed from the intents, because a dropped entry's
    // own claims are rendered here and belong to nobody else.
    let mut released: Vec<PathBuf> = Vec::new();

    let mut intents = loaded.landed();
    if !complete {
        // Reverse order, so a later write is undone before an earlier one it may
        // share a created directory with.
        intents.reverse();
    }
    for (intent, landed) in intents {
        let (step, report) = decide(
            state,
            intent,
            home,
            ledger.as_deref(),
            landed,
            Spelling::Absolute,
        )?;
        // A temporary file the journal names is this write's, and goes once
        // recovery is acting on the write at all: a blocked write is not
        // recovery's to touch, its temporary file included. The loader has
        // already refused a journal whose temporary file is not a `.bx-` file
        // beside its destination, and one the journal does not name is never
        // touched.
        //
        // One that cannot be removed — its directory has since stopped
        // letting this process write — is left, with a warning, and the
        // rollback goes on. Recovery never needs it: it holds bytes no
        // destination was ever given, which makes it the same kind of orphan
        // decision 11 keeps for `bx doctor`, and stopping every writing
        // command over it would make a leftover bx does not need a reason to
        // write nothing. `pending` names it in the write's note.
        //
        // Whether it was there to remove is what shows the directories the
        // Intent names were made: see `fs::remove::prune_beneath`.
        let mut temp_removed = None;
        if !complete
            && !matches!(step, Step::Blocked)
            && let Some(temp) = &intent.temp
        {
            let present = std::fs::symlink_metadata(temp).is_ok();
            match remove::unlink(temp).map_err(journal::Error::from) {
                Ok(()) if present => temp_removed = Some(temp),
                Ok(()) => {}
                Err(error) => tracing::warn!(
                    temp = %temp.display(),
                    %error,
                    "an interrupted write's temporary file could not be removed; \
                     it is left for bx doctor, and the rollback goes on",
                ),
            }
        }
        match step {
            Step::Blocked => {
                conflicts.push(report);
                continue;
            }
            Step::Skip => continue,
            // The Intent names its directories before they are made, so a
            // crash before the stage leaves it naming directories bx never
            // made, and the user may have made one since. Only a directory
            // that held this write's own temporary file, or the next
            // directory in that chain, is bx's to prune; with no temporary
            // file removed there is nothing to show any of them was made,
            // and every one is left.
            Step::Keep => {
                if intent.creates()
                    && let Some(temp) = temp_removed
                {
                    remove::prune_beneath(temp, &intent.created_dirs)?;
                }
            }
            // Both act against the observation `decide` judged, never a fresh
            // one: a destination the user edited after that look holds
            // neither recorded state, and is refused with
            // [`fs::Error::Changed`] rather than removed or overwritten. The
            // journal is kept, so the next run judges the edit as `decide`
            // judges any other, and blocks on it. What stays open is the
            // window between the last look and the `unlink` or `rename`
            // itself, as for `Session::remove` and [`fs::Filled::publish`].
            // A directory the session created goes only while it is empty,
            // and its parents after it: bx never removes what is inside one,
            // so an edit inside it since `decide` looked is never lost. Its
            // parents go only in the chain above what this rollback removed,
            // as for `Step::Keep`.
            Step::Unlink { .. } if intent.dir => {
                if remove::remove_made_dir(&intent.dest)? {
                    remove::prune_beneath(&intent.dest, &intent.created_dirs)?;
                }
            }
            Step::Unlink { observed } => {
                #[cfg(test)]
                tests::before_act(&intent.dest);
                fs::refuse_moved(&observed, &fs::observe(&intent.dest)?)
                    .map_err(journal::Error::from)?;
                remove::unlink(&intent.dest)?;
                remove::prune_beneath(&intent.dest, &intent.created_dirs)?;
            }
            Step::Rewrite {
                bytes,
                mode,
                observed,
            } => {
                #[cfg(test)]
                tests::before_act(&intent.dest);
                fs::stage(&intent.dest, mode, &observed, &mut fs::CreatedDirs::new())?
                    .commit(&bytes)?;
            }
            Step::Relink { text, observed } => {
                #[cfg(test)]
                tests::before_act(&intent.dest);
                fs::stage_link(&intent.dest, &text, &observed, &mut fs::CreatedDirs::new())?
                    .publish()
                    .map_err(fs::Unpublished::into_error)?;
            }
            // A directory's rollback acts against the observation `decide`
            // judged too: one whose mode or presence changed since is refused
            // with [`fs::Error::Changed`] rather than chmod'd or made over it.
            Step::Chmod { mode, observed } => {
                fs::refuse_moved(&observed, &fs::observe(&intent.dest)?)
                    .map_err(journal::Error::from)?;
                fs::set_mode(&intent.dest, mode)?;
            }
            Step::MakeDir { mode, observed } => {
                fs::ensure_dir(&intent.dest, mode, &observed, &mut fs::CreatedDirs::new())?;
            }
            // Rebuilding the bookkeeping touches no destination, so it is not
            // work `plan` failed to announce: the ledger is machine state, not
            // the user's.
            Step::Record(entry) => {
                if let Some(ledger) = ledger.as_mut() {
                    ledger.record(entry)?;
                }
            }
            Step::Forget => {
                let dropped = ledger
                    .as_mut()
                    .and_then(|ledger| ledger.forget(&intent.target));
                if intent.after == Written::Absent {
                    released.extend(intent.created_dirs.iter().cloned());
                    // A directory target's removal released the directory
                    // itself too.
                    if intent.dir {
                        released.push(intent.dest.clone());
                    }
                }
                // The entry's *own* claims, which are not always the Intent's.
                // A removal's Intent carries them, because `plan_restore_with` takes
                // them from the entry; a released write's does not — it records
                // only the directories that write invented, which is none. The
                // replay path drops the same entry `Session::write` drops, so
                // it has to carry the same claim on, or a crash turns a
                // hand-off into a loss.
                if let (Some(dropped), Some(home)) = (dropped, home) {
                    released.extend(dropped.created_dirs.iter().map(|dir| dir.render(home)));
                }
            }
        }
        resolved += 1;
    }
    // Blocked first, and *before* the hand-off. A hand-off ahead of this
    // return would need a `conflicts.is_empty()` guard that no assertion can
    // see — a blocked run saves no ledger, so deleting the guard would change
    // nothing observable and its correctness would rest on the drop.
    // Returning first is the same behaviour with the ordering as the
    // guarantee: past this point there are no conflicts, so nothing has to say
    // so a second time.
    if !conflicts.is_empty() {
        tracing::error!(
            blocked = conflicts.len(),
            journal = %path.display(),
            "recovery is blocked; the journal is kept and bx will not write until it is resolved",
        );
        return Ok(Outcome::Blocked { conflicts });
    }

    if let (Some(ledger), Some(home)) = (ledger.as_mut(), home) {
        ledger
            .hand_off_claims(home, &released)
            .map_err(journal::Error::from)?;
    }

    if let Some(ledger) = &mut ledger {
        ledger.save()?;
    }
    // Last of all, and only once every step has succeeded. This is the rule that
    // makes recovery re-runnable without a journal of its own. A journal bytes
    // were discarded from is kept: they may have been a frame that damage, not a
    // crash, cut short, and the file is the only record of what it hid.
    if torn {
        let aside = journal::set_aside(&path, lock)?;
        tracing::warn!(
            path = %path.display(),
            moved_to = %aside.display(),
            "the recovered journal ended in bytes that were not a whole frame; \
             it was kept rather than deleted",
        );
    } else {
        remove::unlink(&path)?;
    }

    Ok(if complete {
        tracing::info!(
            entries = resolved,
            "brought the ledger up to date after an interruption"
        );
        Outcome::Recorded { entries: resolved }
    } else {
        tracing::info!(undone = resolved, "rolled back an interrupted bx session");
        Outcome::RolledBack { undone: resolved }
    })
}

#[cfg(test)]
mod tests;
