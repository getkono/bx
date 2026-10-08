//! Judging one intent: what is at its destination, and what recovery does about it.

use std::path::{Path, PathBuf};

use super::{Error, Standing, Unfinished};
use crate::fs::{self, Kind, Mode};
use crate::journal::{Intent, Loaded, Written};
use crate::paths::Portable;
use crate::state::{ContentHash, LedgerView, NewEntry, Prior, PriorBytes, RestoreRef, StateDir};

/// What recovery does about one intent.
pub(super) enum Step {
    /// Rolling back, and the destination already holds what was there before.
    /// Only the directories a create invented are left to prune.
    Keep,
    /// Rolling back a create whose file is there: unlink it, then prune.
    Unlink {
        /// The destination [`decide`] judged to be the write's own. It is
        /// looked at again immediately before the unlink, as
        /// `Session::remove` does, so a file edited since is refused rather
        /// than removed.
        observed: fs::Observed,
    },
    /// Rolling back over a file that existed: put these bytes back at this mode.
    Rewrite {
        /// The prior bytes, digest-verified.
        bytes: Vec<u8>,
        /// The mode they had.
        mode: Mode,
        /// The destination [`decide`] judged to be the write's own, handed to
        /// [`fs::stage`] so a file edited since is refused rather than
        /// overwritten.
        observed: fs::Observed,
    },
    /// Rolling back over a link that existed: make it hold this text again.
    Relink {
        /// The link's earlier text, digest-verified.
        text: PathBuf,
        /// The destination [`decide`] judged to be the write's own, handed to
        /// [`fs::stage_link`] so a link retargeted since is refused rather
        /// than replaced.
        observed: fs::Observed,
    },
    /// Rolling back a directory's mode change: set it back to this mode.
    Chmod {
        /// The mode it had.
        mode: Mode,
        /// The directory [`decide`] judged to be the write's own, looked at
        /// again before the chmod so one changed since is refused.
        observed: fs::Observed,
    },
    /// Rolling back the removal of a directory: make it again at this mode.
    MakeDir {
        /// The mode it had.
        mode: Mode,
        /// The absence [`decide`] judged, handed to [`fs::ensure_dir`] so a
        /// path filled since is refused rather than made over.
        observed: fs::Observed,
    },
    /// Bringing the ledger up to date for a write that landed.
    Record(NewEntry),
    /// Bringing the ledger up to date for a write that left nothing to own.
    Forget,
    /// A terminated journal's write that never landed: nothing to record.
    Skip,
    /// Not recovery's to resolve.
    Blocked,
}

/// Decide what recovery does about one intent, and what a report says about it.
///
/// The single decision site. [`pending`] reports the [`Unfinished`] and
/// [`resolve`] carries out the [`Step`], so what a read-only command says and
/// what a writing one does are one verdict — for a terminated journal as much
/// as an unterminated one. Each intent is judged on its own, which is sound
/// because no journal recovery believes writes a target twice
/// ([`crate::journal::Error::Repeated`]).
///
/// `home` is `Some` for a terminated journal, whose ledger entries are rebuilt
/// with paths made portable against it, and `None` for an unterminated one,
/// which is rolled back. `ledger` is the ledger a rebuild would record into —
/// the saved one, for a report — and is only read for a terminated journal.
/// `landed` is whether a `Done` follows the intent. `spelling` is how a note
/// names a path: [`pending`] builds the rows `plan` prints, which spell paths
/// under the home portably, and [`resolve`] builds recovery's own report,
/// which keeps them absolute. The verdict never depends on it.
///
/// # A rebuild over a ledger that was already saved
///
/// [`crate::journal::Session::finish`] saves the ledger and then unlinks the
/// journal, so a crash or a failed unlink between the two leaves a terminated
/// journal over a ledger that already holds its writes. Recording such an
/// intent a second time is not a no-op: its `before` is what was on disk a
/// moment before the write — bx's own previous output, for a target bx already
/// managed — and the ledger, which now says bx last wrote `after`, would take
/// those bytes for a third party's and adopt them as the prior, pushing the
/// user's original out of reach of `rm`.
///
/// So a write the ledger already holds is skipped. "Already holds" is the
/// stored entry being at the intent's `after` digest and mode while the ledger
/// the session opened was not at that digest ([`Intent::ledger_written`]). An
/// entry still at `after` that the session also found there is re-recorded,
/// which is idempotent: nothing in the stored entry turns on whether it was
/// saved. Matching `after` alone is not enough — a session that rewrites bx's
/// last output over a user's edit and dies before the save leaves the ledger
/// at `after` without the edit, and skipping that would lose it.
///
/// [`pending`]: super::pending
/// [`resolve`]: super::rollback::resolve
pub(super) fn decide(
    state: &StateDir,
    intent: &Intent,
    home: Option<&Path>,
    ledger: Option<&LedgerView>,
    landed: bool,
    spelling: Spelling<'_>,
) -> Result<(Step, Unfinished), Error> {
    let (found, observed) = look(&intent.dest)?;
    let standing = standing(intent, &found);
    let report = |resolvable: bool, note: String| Unfinished {
        target: intent.target.clone(),
        dest: intent.dest.clone(),
        standing,
        resolvable,
        note,
    };

    let Some(home) = home else {
        let rolls_back = || {
            let mut note =
                format!("interrupted, and {standing}; the next writing bx run rolls it back");
            if let Some(name) = stuck_temp(intent) {
                note.push_str(&format!(
                    "; its temporary file {name} cannot be removed, and is left for bx doctor"
                ));
            }
            note
        };
        return Ok(match (standing, &intent.before) {
            (Standing::Prior, _) => (Step::Keep, report(true, rolls_back())),
            (Standing::Written, Prior::Absent) => {
                (Step::Unlink { observed }, report(true, rolls_back()))
            }
            // A directory's earlier state is a mode, and needs no snapshot:
            // one bx removed is made again at it, one bx changed is set back.
            (Standing::Written, Prior::Existed(reference)) if intent.dir => {
                let mode = reference.mode;
                let step = match intent.after {
                    Written::Absent => Step::MakeDir { mode, observed },
                    Written::Present { .. } => Step::Chmod { mode, observed },
                };
                (step, report(true, rolls_back()))
            }
            // A link's earlier state is its text, stored as a file's bytes
            // are, and is put back as a link: whether the session retargeted
            // it or `rm` removed it.
            (Standing::Written, Prior::Existed(reference)) if intent.link => {
                match snapshot(state, reference, spelling)? {
                    Ok(bytes) => (
                        Step::Relink {
                            text: PathBuf::from(
                                <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(
                                    bytes,
                                ),
                            ),
                            observed,
                        },
                        report(true, rolls_back()),
                    ),
                    Err(why) => (Step::Blocked, report(false, why)),
                }
            }
            (Standing::Written, Prior::Existed(reference)) => {
                match snapshot(state, reference, spelling)? {
                    Ok(bytes) => (
                        Step::Rewrite {
                            bytes,
                            mode: reference.mode,
                            observed,
                        },
                        report(true, rolls_back()),
                    ),
                    Err(why) => (Step::Blocked, report(false, why)),
                }
            }
            (Standing::Vanished | Standing::Diverged | Standing::Foreign, _) => {
                (Step::Blocked, report(false, note(intent, standing)))
            }
            // Neither state can be confirmed, and no undo can be written
            // through the parent: a human has to look, as for a file edited
            // since.
            (Standing::Unreachable, _) => (Step::Blocked, report(false, unreachable(intent))),
        });
    };

    // A terminated journal: every write that reached `Done` landed, and only the
    // bookkeeping is outstanding. What is at the destination now changes nothing
    // — a file edited since is the user's edit to a file bx manages, which
    // `plan` reports like any other — so no destination blocks this; only a
    // snapshot recovery cannot read does.
    if !landed {
        return Ok((
            Step::Skip,
            report(
                true,
                "was announced and never written; there is nothing to record".to_string(),
            ),
        ));
    }
    let recorded = || {
        format!(
            "was written, and {standing}; only bx's bookkeeping is pending, \
             and the next writing bx run records it"
        )
    };
    let (Written::Present { digest, mode }, Some(mechanism)) =
        (intent.after, intent.mechanism.clone())
    else {
        // A removal, or a target the session released: nothing for bx to own.
        let mut note = recorded();
        if intent.after == Written::Absent {
            let orphans = empty_claims(&intent.created_dirs, home);
            if !orphans.is_empty() {
                note.push_str(&format!(
                    "; the session ended before it removed {}, which stand empty and are \
                     left for bx doctor",
                    orphans.join(", "),
                ));
            }
        }
        return Ok((Step::Forget, report(true, note)));
    };
    if let Some(stored) = ledger.and_then(|ledger| ledger.get(&intent.target))
        && stored.written == digest
        && stored.mode == mode
        && intent.ledger_written != Some(digest)
    {
        return Ok((
            Step::Skip,
            report(
                true,
                "was written, and bx's bookkeeping for it was saved before the \
                 interruption; there is nothing left to record"
                    .to_string(),
            ),
        ));
    }
    let prior = match &intent.before {
        Prior::Absent => PriorBytes::Absent,
        // A directory's earlier state is its mode alone; there is no snapshot
        // to read.
        Prior::Existed(reference) if intent.dir => PriorBytes::Bytes {
            bytes: crate::state::DIR_BYTES.to_vec(),
            mode: reference.mode,
        },
        Prior::Existed(reference) => match snapshot(state, reference, spelling)? {
            Ok(bytes) => PriorBytes::Bytes {
                bytes,
                mode: reference.mode,
            },
            Err(why) => return Ok((Step::Blocked, report(false, why))),
        },
    };
    let entry = NewEntry::new(intent.target.clone(), digest, mode, mechanism, prior)
        .with_created_dirs(
            intent
                .created_dirs
                .iter()
                .map(|dir| {
                    Portable::from_path(dir, home).map_err(|source| fs::Error::NotPortable {
                        path: dir.clone(),
                        source,
                    })
                })
                .collect::<Result<_, _>>()?,
        );
    // The ledger's own refusal is a verdict here, not an error: a rebuild that
    // would adopt a changed shared file as its prior is blocked, the stored
    // prior is kept, and the report says so before the recovery finds it.
    if let Some(Err(conflict)) = ledger.map(|ledger| ledger.check_record(&entry)) {
        return Ok((Step::Blocked, report(false, conflict.to_string())));
    }
    Ok((Step::Record(entry), report(true, recorded())))
}

/// How a note [`decide`] builds spells a path it names.
#[derive(Debug, Clone, Copy)]
pub(super) enum Spelling<'a> {
    /// As it is. Recovery's own report, which its error and its log print.
    Absolute,
    /// `~/…` under this home and absolute outside it, as `plan` prints a row.
    Portable(&'a Path),
}

impl Spelling<'_> {
    /// `path`, spelled this way.
    fn path(self, path: PathBuf) -> PathBuf {
        match self {
            Self::Absolute => path,
            Self::Portable(home) => PathBuf::from(crate::paths::to_portable(&path, home)),
        }
    }
}

/// The name of the temporary file `intent` names, when it is still there and
/// its directory will not let this process remove it.
///
/// A prediction, for the report: [`resolve`] tries the unlink and leaves the
/// file with a warning when it fails. Write and search permission on the
/// directory is what an unlink needs, and `access(2)` is asked for exactly
/// that, so a read-only filesystem is caught too.
///
/// [`resolve`]: super::rollback::resolve
fn stuck_temp(intent: &Intent) -> Option<String> {
    let temp = intent.temp.as_ref()?;
    let dir = temp.parent()?;
    std::fs::symlink_metadata(temp).ok()?;
    rustix::fs::access(
        dir,
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
    )
    .is_err()
    .then(|| {
        temp.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    })
}

/// The directories in `dirs` that are still empty directories, `~`-relative.
///
/// What a removal whose session died between its `End` frame and its prune
/// leaves behind. Recovery removes none of them — see [`resolve`] — so the
/// report names them. A path that is not a directory, or that holds anything,
/// is not one: it is not what the prune would have removed.
///
/// [`resolve`]: super::rollback::resolve
fn empty_claims(dirs: &[PathBuf], home: &Path) -> Vec<String> {
    dirs.iter()
        .filter(|dir| std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()))
        .filter(|dir| std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none()))
        .map(|dir| crate::paths::to_portable(dir, home))
        .collect()
}

/// The bytes a [`RestoreRef`] names, digest-verified, or why they cannot be had.
///
/// A missing or corrupt snapshot is a verdict — recovery will not guess at the
/// bytes a write displaced — and any other failure is an error. The verdict's
/// text names the snapshot's path as `spelling` spells it, rebuilt from the
/// error's own path rather than from its text.
fn snapshot(
    state: &StateDir,
    reference: &RestoreRef,
    spelling: Spelling<'_>,
) -> Result<Result<Vec<u8>, String>, Error> {
    use crate::state::Error::{RestoreCorrupt, RestoreMissing};

    // `restore::read` reads the content-addressed blob and consults no entry,
    // so a read-only report needs no lock to do it.
    match crate::state::restore::read(state, reference) {
        Ok(bytes) => Ok(Ok(bytes)),
        Err(RestoreMissing { digest, path }) => Ok(Err(RestoreMissing {
            digest,
            path: spelling.path(path),
        }
        .to_string())),
        Err(RestoreCorrupt { digest, path }) => Ok(Err(RestoreCorrupt {
            digest,
            path: spelling.path(path),
        }
        .to_string())),
        Err(e) => Err(e.into()),
    }
}

/// The home a terminated journal's entries are rebuilt against, or `None` for an
/// unterminated journal, which is rolled back and needs none.
///
/// # Errors
///
/// [`Error::Headless`] for a terminated journal with no session header.
pub(super) fn rebuild_home<'a>(
    loaded: &'a Loaded,
    complete: bool,
    path: &Path,
) -> Result<Option<&'a Path>, Error> {
    if !complete {
        return Ok(None);
    }
    loaded
        .begin()
        .map(|begin| Some(begin.home.as_path()))
        .ok_or_else(|| Error::Headless {
            path: path.to_path_buf(),
        })
}

/// What is at a destination right now, reduced to what recovery compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    Absent,
    File {
        digest: ContentHash,
        mode: Mode,
    },
    Dir {
        mode: Mode,
    },
    /// A symlink, by the digest of its text.
    Link {
        digest: ContentHash,
        mode: Mode,
    },
    Foreign,
    /// Its parent does not resolve to a directory. [`fs::observe`] reports
    /// such a destination as absent, which it may not be.
    Unreachable,
}

/// Read a destination: what recovery compares, and the observation it was
/// reduced from, which a rollback acts against.
fn look(dest: &Path) -> Result<(Found, fs::Observed), Error> {
    let observed = fs::observe(dest)?;
    if observed
        .parent
        .as_ref()
        .is_some_and(|parent| parent.unusable().is_some())
    {
        return Ok((Found::Unreachable, observed));
    }
    let found = match (observed.kind, observed.digest(), observed.mode) {
        (Kind::Absent, _, _) => Found::Absent,
        (Kind::File, Some(digest), Some(mode)) => Found::File { digest, mode },
        (Kind::Dir, _, Some(mode)) => Found::Dir { mode },
        (Kind::Symlink, _, Some(mode)) => match observed.link_digest() {
            Some(digest) => Found::Link { digest, mode },
            None => Found::Foreign,
        },
        _ => Found::Foreign,
    };
    Ok((found, observed))
}

/// Classify a destination against the two states its intent permits.
///
/// The ground [`decide`] stands on for a rollback, and what every report names.
///
/// `before` is tested first, so a destination that is already where the rollback
/// wants it is a no-op even when the two states are identical — a write whose
/// only change was the mode, undone, is the same file.
fn standing(intent: &Intent, found: &Found) -> Standing {
    let before = expected(&intent.before);
    let after = match intent.after {
        Written::Absent => None,
        Written::Present { digest, mode } => Some((digest, mode)),
    };
    // A directory is compared by its mode, under the digest a directory is
    // recorded with, and a link by its text; a directory where a file was
    // written, a file where a link was, or any other pairing of the three is
    // neither state.
    let here = match (*found, intent.dir, intent.link) {
        (Found::Absent, _, _) => None,
        (Found::File { digest, mode }, false, false)
        | (Found::Link { digest, mode }, false, true) => Some((digest, mode)),
        (Found::Dir { mode }, true, false) => Some((crate::state::dir_digest(), mode)),
        (Found::File { .. } | Found::Dir { .. } | Found::Link { .. } | Found::Foreign, _, _) => {
            return Standing::Foreign;
        }
        (Found::Unreachable, _, _) => return Standing::Unreachable,
    };
    match here {
        None => {
            if before.is_none() {
                Standing::Prior
            } else if after.is_none() {
                Standing::Written
            } else {
                Standing::Vanished
            }
        }
        Some(_) => {
            if before == here {
                Standing::Prior
            } else if after == here {
                Standing::Written
            } else {
                Standing::Diverged
            }
        }
    }
}

/// The message a write whose destination cannot be reached carries: the
/// parent, `~`-relative, and the way out.
///
/// The parent is the target's own, spelled as the journal stores it, because
/// a rollback has no home to fold an absolute path against.
fn unreachable(intent: &Intent) -> String {
    let parent = intent
        .target
        .as_str()
        .rsplit_once('/')
        .map_or("its parent", |(parent, _)| parent);
    format!(
        "{}: {parent} does not resolve to a directory, so bx cannot tell what is \
         there and will not roll it back. Make {parent} a directory again, or \
         abandon the interrupted session to have bx report it as a conflict \
         instead.",
        Standing::Unreachable,
    )
}

/// The digest and mode a [`Prior`] names, or `None` for "there was no file".
fn expected(prior: &Prior) -> Option<(ContentHash, Mode)> {
    match prior {
        Prior::Absent => None,
        Prior::Existed(reference) => Some((reference.digest, reference.mode)),
    }
}

/// The message a blocked target carries: the file, both digests it could
/// legitimately hold, and the way out.
fn note(intent: &Intent, standing: Standing) -> String {
    let before = match &intent.before {
        Prior::Absent => "did not exist".to_string(),
        Prior::Existed(reference) => format!("held {}", reference.digest),
    };
    let after = match intent.after {
        Written::Absent => "was to be removed".to_string(),
        Written::Present { digest, .. } => format!("was being given {digest}"),
    };
    format!(
        "{standing}; before the interruption it {before}, and it {after}. \
         bx will not overwrite it. Put back either of those two states, or \
         abandon the interrupted session to have bx report it as a conflict \
         instead."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recover::fixtures::*;
    use crate::recover::*;

    use std::path::Path;

    use crate::fs::{self, Mode};
    use crate::journal::tests::{
        link_at, link_to, peek, plant_file, raw_journal, seal, target, write_to,
    };
    use crate::journal::{
        self, Begin, Content, Done, End, Intent, Loaded, Ownership, Record, Request, Session,
        SessionKind, Written,
    };

    use crate::report::{Action, Exit};
    use crate::state::{ContentHash, LedgerView, Mechanism, Prior, RestoreRef, StateDir};
    use crate::testing::guarded_home;

    #[test]
    fn a_link_retargeted_after_the_crash_is_blocked_not_replaced() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".tool");
        interrupted(
            &state,
            home.path(),
            vec![link_to(home.path(), ".tool", "ours")],
        );
        std::fs::remove_file(&dest).expect("unlink");
        std::os::unix::fs::symlink("theirs", &dest).expect("the user's link");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a link neither state names is not recovery's to touch");
        };
        assert_eq!(conflicts[0].standing, Standing::Diverged);
        assert_eq!(link_at(&dest).as_deref(), Some(Path::new("theirs")));

        // A file where the link was is neither state either.
        std::fs::remove_file(&dest).expect("unlink");
        plant_file(&dest, "a file\n", Mode::DEFAULT_FILE);
        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a file where a link was is foreign");
        };
        assert_eq!(conflicts[0].standing, Standing::Foreign);
    }

    #[test]
    fn a_link_whose_prior_text_is_missing_or_corrupt_is_blocked_not_guessed() {
        for (corrupt, words) in [(false, "missing"), (true, "does not match")] {
            let home = guarded_home();
            let state = StateDir::resolve(home.path());
            let dest = home.child(".tool");
            std::os::unix::fs::symlink("old", &dest).expect("the prior link");
            interrupted(
                &state,
                home.path(),
                vec![link_to(home.path(), ".tool", "new")],
            );
            let blob = state.restore().join(ContentHash::of(b"old").to_hex());
            if corrupt {
                std::fs::write(&blob, "elsewhere").expect("corrupt the snapshot");
            } else {
                std::fs::remove_file(&blob).expect("delete the snapshot");
            }

            let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
                panic!("a link's unreadable prior text blocks recovery ({words})");
            };
            assert!(conflicts[0].note.contains(words), "{}", conflicts[0].note);
            assert_eq!(
                link_at(&dest).as_deref(),
                Some(Path::new("new")),
                "bx relinks nothing rather than guessing the text it displaced"
            );
        }
    }

    #[test]
    fn a_destination_edited_after_the_crash_is_reported_not_overwritten() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&dest, "the user's own edit\n", Mode::DEFAULT_FILE);

        let outcome = recover(&state).expect("recover");
        let Outcome::Blocked { conflicts } = &outcome else {
            panic!("got {outcome:?}")
        };
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].standing, Standing::Diverged);
        assert_eq!(conflicts[0].action(), Action::Conflict);
        assert!(conflicts[0].note.contains("will not overwrite"));
        assert!(!outcome.is_clear());
        assert_eq!(
            peek(&dest).expect("untouched").0,
            b"the user's own edit\n",
            "Invariant 1 does not lapse because a crash happened",
        );
    }

    #[test]
    fn a_vanished_destination_is_not_resurrected() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        std::fs::remove_file(&dest).expect("the user removed it");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a vanished destination blocks recovery")
        };
        assert_eq!(conflicts[0].standing, Standing::Vanished);
        assert!(
            !dest.exists(),
            "bx does not put back a file nobody asked for",
        );
    }

    #[test]
    fn a_destination_that_is_no_longer_a_file_blocks_recovery() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        std::fs::remove_file(&dest).expect("remove");
        std::fs::create_dir(&dest).expect("a directory in its place");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a foreign destination blocks recovery")
        };
        assert_eq!(conflicts[0].standing, Standing::Foreign);
        assert!(dest.is_dir());
    }

    #[test]
    fn a_missing_prior_blob_is_reported_not_guessed() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        let blob = state.restore().join(ContentHash::of(b"old\n").to_hex());
        std::fs::remove_file(&blob).expect("delete the snapshot");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a missing snapshot blocks recovery")
        };
        assert!(
            conflicts[0].note.contains("missing"),
            "{}",
            conflicts[0].note,
        );
        assert_eq!(
            peek(&home.child(".conf")).expect("untouched").0,
            b"new\n",
            "bx writes nothing rather than guessing at the bytes it displaced",
        );
    }

    #[test]
    fn a_prior_blob_whose_digest_does_not_match_is_refused() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        let blob = state.restore().join(ContentHash::of(b"old\n").to_hex());
        std::fs::write(&blob, "not what it claims to be").expect("corrupt the snapshot");

        let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
            panic!("a corrupt snapshot blocks recovery")
        };
        assert!(
            conflicts[0].note.contains("does not match"),
            "{}",
            conflicts[0].note,
        );
    }

    #[test]
    fn a_blocked_recovery_reports_pending() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&home.child(".conf"), "edited\n", Mode::DEFAULT_FILE);

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.actions(), vec![Action::Conflict]);
        assert_eq!(interruption.exit(), Exit::Pending);
        assert_eq!(interruption.blocked().count(), 1);
        assert!(interruption.unfinished[0].describe().contains(".conf"));
        assert!(
            state.journal().exists(),
            "a read-only command writes nothing at all",
        );
    }

    #[test]
    fn an_interruption_that_named_nothing_still_exits_pending() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.unfinished.is_empty());
        assert_eq!(
            interruption.exit(),
            Exit::Pending,
            "the machine is still not converged, so somebody has to look",
        );
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 0 },
        );
    }

    #[test]
    fn a_rebuild_over_a_ledger_at_the_same_digest_and_another_mode_records_the_mode() {
        // r3 coverage COV6. `decide`'s already-saved skip is "the stored entry
        // is at the intent's `after` digest *and mode*". No fixture differed
        // in mode alone, so deleting the mode conjunct passed: a terminated
        // journal whose write changed only the mode, over a ledger at that
        // digest at the old mode, would be skipped and the mode change lost.
        //
        // A ledger and a journal can disagree this way whenever the ledger is
        // not the one the session opened — an older ledger put back beside a
        // newer journal, or one rebuilt after a quarantine — so the journal is
        // built here rather than crashed out of a session.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let bytes = "bx\n";
        let digest = ContentHash::of(bytes.as_bytes());
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(home.path(), ".conf", bytes, Mode::DEFAULT_FILE))
            .expect("apply");
        session.finish().expect("finish");
        let (portable, dest) = target(home.path(), ".conf");
        let stored = |state: &StateDir| {
            LedgerView::read(state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .cloned()
                .expect("the entry")
        };
        assert_eq!(
            (stored(&state).written, stored(&state).mode),
            (digest, Mode::DEFAULT_FILE),
        );

        // The same bytes at a narrower mode, landed, with the ledger the
        // session opened holding nothing for the target.
        raw_journal(
            &state.journal(),
            &[
                Record::Begin(Begin {
                    kind: SessionKind::Apply,
                    home: home.path().to_path_buf(),
                    scope: Vec::new(),
                }),
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest: dest.clone(),
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Present {
                        digest,
                        mode: Mode::PRIVATE_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                    dir: false,
                    link: false,
                }),
                Record::Done(Done {
                    target: portable.clone(),
                }),
                Record::End(End { written: 1 }),
            ],
        );

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 },
        );
        assert_eq!(
            (stored(&state).written, stored(&state).mode),
            (digest, Mode::PRIVATE_FILE),
            "the mode the journal records is the mode the ledger ends at",
        );
    }

    #[test]
    fn a_blocked_targets_note_names_both_states_it_could_legitimately_hold() {
        // r3 coverage COV7. `note`'s "held {digest}" and "was to be removed"
        // arms were never asserted, and they are the whole operator-facing
        // surface of a blocked recovery: the file, both legitimate digests,
        // and `abandon` as the way out.
        let home = guarded_home();
        let (portable, dest) = target(home.path(), ".conf");
        let old = ContentHash::of(b"old\n");
        let new = ContentHash::of(b"new\n");
        let base = Intent {
            target: portable,
            dest,
            temp: None,
            before: Prior::Absent,
            after: Written::Absent,
            created_dirs: Vec::new(),
            mechanism: Some(Mechanism::Own),
            ledger_written: None,
            dir: false,
            link: false,
        };
        let tail = "bx will not overwrite it. Put back either of those two states, \
                    or abandon the interrupted session to have bx report it as a \
                    conflict instead.";

        let created = Intent {
            after: Written::Present {
                digest: new,
                mode: Mode::DEFAULT_FILE,
            },
            ..base.clone()
        };
        assert_eq!(
            note(&created, Standing::Diverged),
            format!(
                "was edited after the interruption; before the interruption it \
                 did not exist, and it was being given {new}. {tail}"
            ),
        );

        let modified = Intent {
            before: Prior::Existed(RestoreRef {
                digest: old,
                mode: Mode::DEFAULT_FILE,
                len: 4,
            }),
            ..created
        };
        assert_eq!(
            note(&modified, Standing::Diverged),
            format!(
                "was edited after the interruption; before the interruption it \
                 held {old}, and it was being given {new}. {tail}"
            ),
        );

        let removal = Intent {
            before: Prior::Existed(RestoreRef {
                digest: old,
                mode: Mode::DEFAULT_FILE,
                len: 4,
            }),
            mechanism: None,
            ..base
        };
        assert_eq!(
            note(&removal, Standing::Foreign),
            format!(
                "is not a regular file; before the interruption it held {old}, \
                 and it was to be removed. {tail}"
            ),
        );
    }

    #[test]
    fn a_terminated_journal_with_a_missing_blob_is_blocked() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        std::fs::remove_file(state.restore().join(ContentHash::of(b"old\n").to_hex()))
            .expect("delete the snapshot");

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. },
        ));
        assert!(state.journal().exists(), "and the journal is kept");
    }

    #[test]
    fn a_prior_snapshot_that_cannot_be_read_stops_recovery_as_an_error() {
        // r3 coverage C10. A missing or corrupt snapshot is a verdict; any
        // other failure to read one is an error, for the report and the
        // recovery alike, and nothing is changed.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        let blob = state.restore().join(ContentHash::of(b"old\n").to_hex());
        std::fs::remove_file(&blob).expect("remove the snapshot");
        std::fs::create_dir(&blob).expect("a directory where the snapshot was");

        // The state layer refuses to read a snapshot that is not a regular
        // file, and that refusal is neither of the two verdicts.
        let reported = pending(&state);
        assert!(
            matches!(
                reported,
                Err(Error::State(crate::state::Error::RestoreNotAFile { .. }))
            ),
            "got {reported:?}"
        );
        let recovered = recover(&state);
        assert!(
            matches!(
                recovered,
                Err(Error::State(crate::state::Error::RestoreNotAFile { .. }))
            ),
            "got {recovered:?}"
        );
        assert_eq!(peek(&dest).expect("untouched").0, b"new\n");
        assert!(state.journal().exists(), "the journal is kept");
    }

    #[test]
    fn a_terminated_journal_with_no_header_has_no_home_to_rebuild_against() {
        // r3 coverage C12. The loader refuses a journal whose first frame is
        // not its header, so no journal on disk reaches this. Pinned on a
        // hand-built value, so such a journal can only be refused, never rebuilt.
        let path = Path::new("/nonexistent/journal.mpk");
        let headless = Loaded::Terminated(vec![Record::End(End { written: 0 })]);
        assert!(
            matches!(rebuild_home(&headless, true, path), Err(Error::Headless { path: refused }) if refused == path),
        );
        assert!(matches!(rebuild_home(&headless, false, path), Ok(None)));
    }

    #[test]
    fn an_intent_without_done_in_a_terminated_journal_records_nothing() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let (portable, dest) = target(home.path(), ".conf");

        raw_journal(
            &state.journal(),
            &[
                Record::Begin(Begin {
                    kind: SessionKind::Apply,
                    home: home.path().to_path_buf(),
                    scope: Vec::new(),
                }),
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest,
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Present {
                        digest: ContentHash::of(b"never landed\n"),
                        mode: Mode::DEFAULT_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                    dir: false,
                    link: false,
                }),
                Record::End(End { written: 0 }),
            ],
        );

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.complete);
        assert_eq!(interruption.blocked().count(), 0);
        assert!(
            interruption.unfinished[0].note.contains("never written"),
            "{}",
            interruption.unfinished[0].note,
        );
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 0 },
        );
        assert!(
            LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .is_none(),
            "a write with no Done never landed, so bx does not own it",
        );
    }

    #[test]
    fn the_report_and_the_recovery_agree_for_every_kind_of_journal() {
        let guard = guarded_home();
        for terminated in [false, true] {
            for edited in [false, true] {
                let case = format!("terminated={terminated} edited={edited}");
                let home = guard.child(format!("t-{terminated}-e-{edited}"));
                let state = StateDir::resolve(&home);
                let dest = home.join(".conf");
                plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
                interrupted(
                    &state,
                    &home,
                    vec![write_to(&home, ".conf", "new\n", Mode::DEFAULT_FILE)],
                );
                if terminated {
                    seal(&state.journal(), 1);
                }
                if edited {
                    plant_file(&dest, "edited after the crash\n", Mode::DEFAULT_FILE);
                }

                let report = pending(&state).expect("pending").expect("interrupted");
                assert_eq!(report.complete, terminated, "{case}");
                let reported_blocked = report.blocked().next().is_some();
                let note = report.unfinished[0].note.clone();

                let outcome = recover(&state).expect("recover");
                assert_eq!(
                    reported_blocked,
                    !outcome.is_clear(),
                    "{case}: the report said blocked={reported_blocked}, recovery did {outcome:?}",
                );
                if terminated {
                    assert_eq!(outcome, Outcome::Recorded { entries: 1 }, "{case}");
                    assert!(note.contains("bookkeeping"), "{case}: {note}");
                    assert!(!note.contains("rolls it back"), "{case}: {note}");
                    assert!(!note.contains("abandon"), "{case}: {note}");
                } else if edited {
                    assert!(matches!(outcome, Outcome::Blocked { .. }), "{case}");
                    assert!(note.contains("will not overwrite"), "{case}: {note}");
                } else {
                    assert_eq!(outcome, Outcome::RolledBack { undone: 1 }, "{case}");
                    assert!(note.contains("rolls it back"), "{case}: {note}");
                }
            }
        }
    }

    #[test]
    fn the_standing_of_a_write_reads_the_same_for_a_report_and_for_an_undo() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        // One decision site: what a read-only command says and what a writing
        // one does cannot disagree, because the same function computes both.
        let reported = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(reported.unfinished[0].standing, Standing::Written);
        assert!(reported.unfinished[0].standing.is_resolvable());
        assert!(reported.unfinished[0].note.contains("rolls it back"));
        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { .. },
        ));
    }

    #[test]
    fn a_write_whose_two_states_are_identical_rolls_back_to_a_no_op() {
        // `standing` tests the prior state first, so a write that changed
        // nothing is a no-op rather than an ambiguity.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "same\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "same\n", Mode::DEFAULT_FILE)],
        );

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished[0].standing, Standing::Prior);
        recover(&state).expect("recover");
        assert_eq!(peek(&dest).expect("unchanged").0, b"same\n");
    }

    #[test]
    fn a_restore_snapshot_reference_names_its_blob() {
        // The journal stores A4's `RestoreRef` verbatim, so the blob a rollback
        // reads is the same file `bx rm` reads.
        let reference = RestoreRef {
            digest: ContentHash::of(b"old\n"),
            mode: Mode::DEFAULT_FILE,
            len: 4,
        };
        assert_eq!(reference.blob_name(), ContentHash::of(b"old\n").to_hex());
        assert_eq!(
            expected(&Prior::Existed(reference.clone())),
            Some((reference.digest, reference.mode)),
        );
        assert_eq!(expected(&Prior::Absent), None);
    }

    #[test]
    fn every_standing_renders_a_sentence() {
        // r3 coverage COV7. Non-empty was all this asserted, so any of the six
        // could have been swapped for another and the suite stayed green.
        // Each reads as the predicate of a sentence whose subject is the path,
        // which is how `note` and `unreachable` both use it.
        for (standing, sentence) in [
            (Standing::Prior, "holds the bytes that were there before"),
            (
                Standing::Written,
                "holds the bytes the interrupted session wrote",
            ),
            (Standing::Vanished, "is gone"),
            (Standing::Diverged, "was edited after the interruption"),
            (Standing::Foreign, "is not a regular file"),
            (Standing::Unreachable, "cannot be reached"),
        ] {
            assert_eq!(standing.to_string(), sentence);
        }
        assert_eq!(SessionKind::Apply.to_string(), "apply");
        assert_eq!(SessionKind::Restore.to_string(), "restore");
    }

    #[test]
    fn a_target_written_twice_in_one_session_is_refused_so_report_and_recovery_agree() {
        // Review round 3, item 4. The second write used to land: the report then
        // judged the first intent against the second write's bytes and said
        // blocked, while the reverse-order rollback undid both and succeeded.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "B0\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(home.path(), ".conf", "B1\n", Mode::DEFAULT_FILE))
            .expect("the first write");
        let refused = session
            .apply(write_to(home.path(), ".conf", "B2\n", Mode::DEFAULT_FILE))
            .expect_err("the second write to the same target");
        assert!(
            matches!(refused, journal::Error::Repeated { .. }),
            "got {refused}"
        );
        assert_eq!(peek(&dest).expect("the first write").0, b"B1\n");
        assert!(matches!(
            session.finish(),
            Err(journal::Error::Poisoned { .. })
        ));

        let report = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(report.unfinished.len(), 1);
        assert!(report.blocked().next().is_none());
        let outcome = recover(&state).expect("recover");
        assert_eq!(outcome, Outcome::RolledBack { undone: 1 });
        assert_eq!(peek(&dest).expect("rolled back").0, b"B0\n");
    }

    #[test]
    fn a_rebuild_that_would_adopt_a_changed_shared_file_is_blocked_and_keeps_the_prior() {
        // Stack integration of #7's round 3: `record` refuses a changed Region
        // or Include file with `PriorConflict`. A rebuild must give that one
        // verdict from `pending` and `recover` — a blocked write — and never
        // lose or replace the stored prior.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".zshrc");
        let region = Mechanism::Region { comment: '#' };
        let bx1 = "user line\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
        let bx2 = "user line\n# >>> bx >>>\nBX2\n# <<< bx <<<\n";
        plant_file(&dest, "user line\n", Mode::DEFAULT_FILE);
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: bx1.as_bytes().to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Owned(region.clone()),
            })
            .expect("apply");
        first.finish().expect("finish");
        let saved = std::fs::read(state.ledger()).expect("the ledger");

        // A journal whose one write displaced a changed copy of the shared file,
        // and landed, and whose session died before its save.
        let edited = format!("{bx1}more\n");
        let displaced = ContentHash::of(edited.as_bytes());
        fs::write_atomically(
            &state.restore().join(displaced.to_hex()),
            edited.as_bytes(),
            Mode::PRIVATE_FILE,
        )
        .expect("the snapshot");
        plant_file(&dest, bx2, Mode::DEFAULT_FILE);
        raw_journal(
            &state.journal(),
            &[
                Record::Begin(Begin {
                    kind: SessionKind::Apply,
                    home: home.path().to_path_buf(),
                    scope: Vec::new(),
                }),
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest: dest.clone(),
                    temp: None,
                    before: Prior::Existed(RestoreRef {
                        digest: displaced,
                        mode: Mode::DEFAULT_FILE,
                        len: u64::try_from(edited.len()).expect("a length"),
                    }),
                    after: Written::Present {
                        digest: ContentHash::of(bx2.as_bytes()),
                        mode: Mode::DEFAULT_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(region),
                    ledger_written: Some(ContentHash::of(bx1.as_bytes())),
                    dir: false,
                    link: false,
                }),
                Record::Done(Done {
                    target: portable.clone(),
                }),
                Record::End(End { written: 1 }),
            ],
        );
        let journal = std::fs::read(state.journal()).expect("the journal");

        let report = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(report.unfinished.len(), 1);
        assert!(
            !report.unfinished[0].resolvable,
            "{:?}",
            report.unfinished[0]
        );
        let outcome = recover(&state).expect("a conflict is a verdict, not an error");
        assert!(
            matches!(&outcome, Outcome::Blocked { conflicts } if conflicts.len() == 1),
            "{outcome:?}"
        );
        assert_eq!(std::fs::read(state.journal()).expect("kept"), journal);
        assert_eq!(std::fs::read(state.ledger()).expect("unchanged"), saved);
        let entry = LedgerView::read(&state, home.path())
            .expect("read")
            .value
            .get(&portable)
            .cloned()
            .expect("the entry");
        let Prior::Existed(original) = &entry.prior else {
            panic!("the user's original is still the prior");
        };
        assert_eq!(original.digest, ContentHash::of(b"user line\n"));
        assert_eq!(peek(&dest).expect("untouched").0, bx2.as_bytes());
    }

    #[test]
    fn a_rebuild_whose_created_directory_cannot_be_made_portable_is_an_error() {
        // r3 coverage C3. The loader refuses a journal whose created directory
        // is not a parent of its destination below its UTF-8 home, so no
        // journal on disk reaches this. Pinned at `decide`, so such a directory
        // is never dropped from a rebuilt entry.
        use std::os::unix::ffi::OsStrExt as _;

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut intent = intent_for(home.path(), ".config/app/a.toml");
        intent.created_dirs = vec![home.path().join(std::ffi::OsStr::from_bytes(b"\xff"))];

        let err = match decide(
            &state,
            &intent,
            Some(home.path()),
            None,
            true,
            Spelling::Absolute,
        ) {
            Err(err) => err,
            Ok((_, report)) => panic!("rebuilt: {report:?}"),
        };
        assert!(
            matches!(&err, Error::Write(fs::Error::NotPortable { path, .. }) if *path == intent.created_dirs[0]),
            "got {err}"
        );
    }

    #[test]
    fn an_interrupted_removal_whose_parent_no_longer_resolves_is_blocked_not_an_error() {
        // r3 round 2, P9R4-D4. The destination under a dangling link read as
        // absent, so `pending` called the removal's rollback resolvable, and
        // every recovery then failed writing through the link with
        // UnusableParent, never naming `abandon`.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let request = write_to(home.path(), ".made/f.conf", "bx\n", Mode::DEFAULT_FILE);
        let key = request.target.clone();
        session.apply(request).expect("bx creates ~/.made/f.conf");
        session.finish().expect("finish");

        // rm's removal lands, and the process dies before its session ends.
        let entry = LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value
            .get(&key)
            .cloned()
            .expect("managed");
        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), vec![key.clone()])
                .expect("open");
        let crate::restore::Restoration::Remove {
            dest,
            created_dirs,
            planned,
        } = crate::restore::plan_restore(&entry, home.path()).expect("plan")
        else {
            panic!("bx created it, so rm removes it");
        };
        session
            .apply(Request {
                target: key,
                dest,
                content: Content::Absent {
                    created_dirs,
                    planned: *planned,
                },
                mode: entry.mode,
                ownership: Ownership::Released,
            })
            .expect("the removal");
        drop(session);

        // `~/.made` becomes a link to nowhere.
        let made = home.child(".made");
        if made.is_dir() {
            std::fs::remove_dir(&made).expect("rm the empty directory");
        }
        std::os::unix::fs::symlink(home.child("nowhere"), &made).expect("link");

        let report = pending(&state).expect("pending").expect("interrupted");
        let outcome = recover(&state);

        let Ok(Outcome::Blocked { conflicts }) = outcome else {
            panic!("recovery is blocked, not an error: {outcome:?}");
        };
        assert_eq!(
            conflicts, report.unfinished,
            "the report and the recovery agree"
        );
        let write = &report.unfinished[0];
        assert_eq!(write.standing, Standing::Unreachable);
        assert!(!write.resolvable, "{write:?}");
        assert!(
            write
                .note
                .starts_with("cannot be reached: ~/.made does not resolve to a directory"),
            "{}",
            write.note
        );
        assert!(report.blocked().next().is_some());
        assert!(write.note.contains("~/.made"), "{}", write.note);
        assert!(write.note.contains("abandon"), "{}", write.note);
        assert!(state.journal().exists(), "the journal is kept");
        assert!(matches!(
            lock_for_writing(&state),
            Err(Error::Blocked { .. })
        ));
        assert!(
            std::fs::symlink_metadata(&made)
                .expect("the link stays")
                .file_type()
                .is_symlink()
        );

        assert!(abandon(&state).expect("abandon").is_some());
        assert_eq!(recover(&state).expect("after abandon"), Outcome::Nothing);
    }

    #[test]
    fn a_created_file_changed_after_the_crash_is_blocked_saying_it_did_not_exist() {
        // r3 round 2, P9R4-CV3. `note`'s wording for a write that created its
        // file was never reached. A created file that is gone again reads as
        // `Prior`, so only an edit and a replacement block such a write.
        fn edited(dest: &Path) {
            plant_file(dest, "edited after the crash\n", Mode::DEFAULT_FILE);
        }
        fn replaced(dest: &Path) {
            std::fs::remove_file(dest).expect("rm");
            std::fs::create_dir(dest).expect("a directory in its place");
        }

        let guard = guarded_home();
        for (name, change, standing) in [
            ("edited", edited as fn(&Path), Standing::Diverged),
            ("replaced", replaced as fn(&Path), Standing::Foreign),
        ] {
            let home = guard.child(name);
            std::fs::create_dir_all(&home).expect("the home");
            let state = StateDir::resolve(&home);
            interrupted(
                &state,
                &home,
                vec![write_to(&home, ".new.conf", "bx\n", Mode::DEFAULT_FILE)],
            );
            change(&home.join(".new.conf"));

            let report = pending(&state).expect("pending").expect("interrupted");
            let Outcome::Blocked { conflicts } = recover(&state).expect("recover") else {
                panic!("{name}: recovery is blocked");
            };
            assert_eq!(conflicts, report.unfinished, "{name}");
            assert_eq!(conflicts[0].standing, standing, "{name}");
            assert!(
                conflicts[0]
                    .note
                    .contains("before the interruption it did not exist, and it was being given"),
                "{name}: {}",
                conflicts[0].note
            );
        }
    }

    #[test]
    fn only_a_destination_in_a_recorded_state_is_resolvable() {
        for (standing, resolvable) in [
            (Standing::Prior, true),
            (Standing::Written, true),
            (Standing::Vanished, false),
            (Standing::Diverged, false),
            (Standing::Foreign, false),
            (Standing::Unreachable, false),
        ] {
            assert_eq!(standing.is_resolvable(), resolvable, "{standing:?}");
        }
    }
}
