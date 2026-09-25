//! Checks 3 and 4: the state directory's own files, and the session a write
//! left behind.
//!
//! Both read the state directory the way `bx plan` does — lockless, through
//! the readers that move nothing aside ([`LedgerView::read`],
//! [`Fingerprints::read`], [`recover::pending`]) and the lock probe that
//! creates and writes nothing ([`SharedLock::probe`]) — so doctor runs beside
//! an `apply` that holds the lock and changes no byte under the state root.
//! A damaged file is left where it is: setting it aside is the next writing
//! command's, under the lock.
//!
//! Before either reads a file, the state tree is walked for anything that is
//! not a regular file or a directory, as `plan` walks it: a FIFO where a state
//! file belongs would block a read forever. One found is the finding, and
//! nothing else in the state directory is read.

use std::path::{Path, PathBuf};

use super::Finding;
use crate::paths;
use crate::plan;
use crate::recover::{self, Interrupted};
use crate::state::{
    self, Fingerprints, Health, LedgerView, Loaded, SharedLock, StateDir, Unlisted,
};

/// What reading the state directory found, split by the check that reports it.
#[derive(Debug, Default)]
pub struct Found {
    /// Check 3: damaged, unreadable or set-aside state files.
    pub damage: Vec<Finding>,
    /// Check 4: an interrupted session, or an `apply` running now.
    pub session: Vec<Finding>,
    /// The ledger as it was read: what survived of a damaged one, and empty
    /// when it could not be read at all, or when an irregular state file
    /// stopped every read. Check 8 asks it which targets bx has written.
    pub ledger: LedgerView,
}

/// Look at the state directory under `home` for both checks.
#[must_use]
pub fn check(state: &StateDir, home: &Path) -> Found {
    let at = |path: &Path| paths::to_portable(path, home);
    let mut found = Found::default();

    if let Err(error) = plan::refuse_irregular_state_files(state) {
        let finding = match error {
            plan::Error::NotARegularFile { path } => Finding {
                subject: at(&path),
                origin: None,
                note: "is not a regular file, so doctor read nothing in the state directory; \
                       move it out of the way"
                    .to_string(),
            },
            other => unread(at(state.root()), &other),
        };
        found.damage.push(finding);
        return found;
    }

    let mut unlisted: Option<Unlisted> = None;
    match LedgerView::read(state, home) {
        Ok(loaded) => {
            found.damage.extend(health(
                &at(&state.ledger()),
                &loaded.health,
                "the next `bx apply` sets it aside, and `bx rm` can then restore only what \
                 survived",
            ));
            found.damage.extend(quarantined(&loaded, &at));
            unlisted = unlisted.or(loaded.unlisted);
            found.ledger = loaded.value;
        }
        Err(error) => found.damage.push(unread(at(&state.ledger()), &error)),
    }
    match Fingerprints::read(state) {
        Ok(loaded) => {
            found.damage.extend(health(
                &at(&state.fingerprints()),
                &loaded.health,
                "it is a cache, and the next `bx apply` sets it aside and rebuilds it",
            ));
            found.damage.extend(quarantined(&loaded, &at));
            unlisted = unlisted.or(loaded.unlisted);
        }
        Err(error) => found.damage.push(unread(at(&state.fingerprints()), &error)),
    }
    // The journal has no lockless reader that lists its quarantines, and
    // `recover::pending` moves nothing aside, so the ones recovery made are
    // listed here directly.
    match state::quarantines(&state.journal()) {
        Ok(aside) => found.damage.extend(set_aside(&aside, &at)),
        Err(why) => {
            unlisted = unlisted.or(Some(Unlisted {
                path: state.root().to_path_buf(),
                kind: why.kind(),
                cause: why.to_string(),
            }));
        }
    }
    if let Some(unlisted) = unlisted {
        found.damage.push(Finding {
            subject: at(&unlisted.path),
            origin: None,
            note: format!(
                "could not be listed ({}), so doctor cannot say whether a damaged state file \
                 was set aside there",
                unlisted.cause
            ),
        });
    }

    found.session = session(state, home);
    found
}

/// The finding for a file, or a directory, that could not be read at all.
fn unread(subject: String, error: &dyn std::error::Error) -> Finding {
    Finding {
        subject,
        origin: None,
        note: format!("could not be read: {error}"),
    }
}

/// The finding a damaged file's health gives, if any.
fn health(subject: &str, health: &Health, then: &str) -> Option<Finding> {
    let damage = health.damage()?;
    let kept = if damage.is_partial() {
        "; every other entry in it is intact"
    } else {
        ""
    };
    Some(Finding {
        subject: subject.to_string(),
        origin: None,
        note: format!("is damaged: {damage}{kept}; {then}"),
    })
}

/// A finding for every copy of a damaged file that is standing aside.
fn quarantined<T>(loaded: &Loaded<T>, at: &dyn Fn(&Path) -> String) -> Vec<Finding> {
    set_aside(&loaded.quarantined, at)
}

/// A finding for each set-aside copy in `aside`.
fn set_aside(aside: &[PathBuf], at: &dyn Fn(&Path) -> String) -> Vec<Finding> {
    aside
        .iter()
        .map(|path: &PathBuf| Finding {
            subject: at(path),
            origin: None,
            note: "is a damaged state file bx set aside, and bx never deletes one; look at it, \
                   then move it out of the state directory"
                .to_string(),
        })
        .collect()
}

/// Check 4: whether a session is running now or was interrupted.
///
/// A held lock is an `apply` in flight, and its journal is not an
/// interruption; the probe says which before the journal is read, as `plan`
/// asks it.
fn session(state: &StateDir, home: &Path) -> Vec<Finding> {
    let journal = paths::to_portable(&state.journal(), home);
    match SharedLock::probe(state) {
        Err(error) => return vec![unread(paths::to_portable(&state.lock(), home), &error)],
        Ok(probe) if probe.is_held() => {
            return vec![Finding {
                subject: "bx apply".to_string(),
                origin: None,
                note: "is running now, so doctor cannot tell its journal from an interrupted \
                       one; run `bx doctor` again once it finishes"
                    .to_string(),
            }];
        }
        Ok(_) => {}
    }
    match recover::pending(state) {
        Ok(None) => Vec::new(),
        Ok(Some(interrupted)) => interruption(&journal, &interrupted),
        Err(error) => vec![unread(journal, &error)],
    }
}

/// The findings an interrupted session gives: the session, then each write
/// recovery cannot resolve on its own, in the order it was announced.
fn interruption(journal: &str, interrupted: &Interrupted) -> Vec<Finding> {
    let session = if interrupted.unreadable {
        "is a journal no bx session could have written; the next `bx apply` sets it aside and \
         rolls nothing back"
            .to_string()
    } else {
        let writes = interrupted.unfinished.len();
        let blocked = interrupted.blocked().count();
        let what = if interrupted.complete {
            "finished every write but did not record them; the next `bx apply` records them"
        } else {
            "stopped before it finished; the next `bx apply` rolls it back"
        };
        let held = if blocked == 0 {
            String::new()
        } else {
            format!(", once {blocked} write(s) recovery cannot account for are resolved by hand")
        };
        format!(
            "records an interrupted {} session of {writes} write(s) that {what}{held}; \
             `bx plan` shows what it would do",
            interrupted.kind
        )
    };
    let mut findings = vec![Finding {
        subject: journal.to_string(),
        origin: None,
        note: session,
    }];
    findings.extend(interrupted.blocked().map(|write| Finding {
        subject: write.target.as_str().to_string(),
        origin: None,
        note: write.note.clone(),
    }));
    findings
}
