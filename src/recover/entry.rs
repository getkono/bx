//! The entry points: reporting an interrupted session, recovering it, and
//! abandoning it.

#[cfg(test)]
use std::path::PathBuf;

use super::inspect::{Spelling, decide, rebuild_home};
use super::rollback::resolve;
use super::{Error, Interrupted, Outcome};
use crate::journal::{self, Loaded, SessionKind};
use crate::state::{ExclusiveLock, LedgerView, StateDir};

/// Whether an interrupted session stands, and what it names.
///
/// Read-only, destinations and state directory alike. A journal it cannot
/// believe is reported, with [`Interrupted::unreadable`] set and no writes, and
/// left exactly where it is: moving it aside is the degradation `CLAUDE.md`
/// requires of a machine-owned file, and the next writing command does it,
/// under the lock.
///
/// What it reports for each write is decided by the same function [`recover`]
/// acts on, over the same journal, so a report and a recovery that find the
/// same destinations and the same saved ledger reach the same verdict. They
/// can still differ when something changes in between — this is a snapshot —
/// and a journal that writes one target twice, over which a per-intent report
/// and a reverse-order rollback would disagree, is refused by the loader and
/// never written by a session.
///
/// It takes **no lock**, deliberately, so `plan` stays usable while an `apply`
/// runs — and that means a journal it finds may belong to a session that is in
/// flight right now rather than to one that died. The two are told apart by the
/// state directory's lock, not by the journal: a caller that wants to say "an
/// apply is in progress" rather than "an apply was interrupted" asks
/// [`SharedLock::probe`](crate::state::SharedLock::probe) first, as `plan`
/// and `doctor` do, and reports a held lock as the live one. A session creates its journal whole, by rename, so the most
/// such a reader can see of one in flight is a torn tail frame, which it
/// discards.
///
/// # Errors
///
/// [`Error::Journal`] when the journal cannot be read, [`Error::Write`] when a
/// destination cannot be stat'd, [`Error::State`] when a prior snapshot cannot
/// be read, and [`Error::Headless`] for a terminated journal with no session
/// header — the same journal [`recover`] refuses.
pub fn pending(state: &StateDir) -> Result<Option<Interrupted>, Error> {
    let path = state.journal();
    let loaded = journal::load(&path)?;
    let complete = match loaded {
        Loaded::Absent => return Ok(None),
        Loaded::Unreadable { .. } => {
            return Ok(Some(Interrupted {
                kind: SessionKind::Apply,
                journal: path,
                complete: false,
                unreadable: true,
                unfinished: Vec::new(),
            }));
        }
        Loaded::Terminated(_) => true,
        Loaded::Unterminated(_) | Loaded::Torn { .. } => false,
    };
    let home = rebuild_home(&loaded, complete, &path)?;

    let kind = loaded
        .begin()
        .map_or(SessionKind::Apply, |begin| begin.kind);
    // A terminated journal's report depends on what the saved ledger already
    // holds, exactly as its rebuild does. Every state file is replaced by
    // rename, so this read needs no lock.
    let ledger = match home {
        // A mis-spelled home is `Error::ForeignPath` and stops the report, as
        // it stops the recovery. A damaged ledger is only reported here: a
        // reader without the lock moves nothing, and the recovery that holds
        // the lock quarantines it and rebuilds into an empty ledger, which is
        // the ledger this report judges against too.
        Some(home) => {
            let read = LedgerView::read(state, home)?;
            if let Some(damage) = read.health.damage() {
                tracing::warn!(
                    ?damage,
                    "the ledger is damaged; it is left in place, and the next writing bx run \
                     moves it aside before recovering",
                );
            }
            Some(read.value)
        }
        None => None,
    };
    // What this returns is what `plan` prints, so a note names a path the way
    // plan output does, against the home the session wrote against. A journal
    // with no header has no write to name.
    let spelling = loaded
        .begin()
        .map_or(Spelling::Absolute, |begin| Spelling::Portable(&begin.home));
    let mut unfinished = Vec::new();
    for (intent, landed) in loaded.landed() {
        unfinished.push(decide(state, intent, home, ledger.as_ref(), landed, spelling)?.1);
    }
    Ok(Some(Interrupted {
        kind,
        journal: path,
        complete,
        unreadable: false,
        unfinished,
    }))
}

/// Resolve an interrupted session, or report why it cannot be.
///
/// Takes the state directory's exclusive lock for the duration. Safe to run when
/// there is nothing to do — that is [`Outcome::Nothing`], which is also what a
/// journal no bx session could have written comes to once it is set aside —
/// and safe to run twice: the second run finds no journal.
///
/// # Errors
///
/// [`Error::Journal`], [`Error::State`] or [`Error::Write`] for a filesystem
/// failure, and [`Error::Headless`] for a journal that records a write with no
/// header. A destination bx cannot account for is [`Outcome::Blocked`], not an
/// error: nothing is going wrong, a human has to look.
pub fn recover(state: &StateDir) -> Result<Outcome, Error> {
    let lock = ExclusiveLock::acquire(state)?;
    #[cfg(test)]
    tests::after_lock(state);
    resolve(state, &lock)
}

/// [`lock_for_writing`]'s verdict, with the lock already held.
///
/// [`Outcome::Blocked`] becomes [`Error::Blocked`] here and nowhere else: a
/// command that is about to write must stop, while [`recover`] hands the same
/// verdict back as a value for a caller that only reports it.
fn resolved_or_blocked(state: &StateDir, lock: &ExclusiveLock) -> Result<Outcome, Error> {
    match resolve(state, lock)? {
        Outcome::Blocked { conflicts } => Err(Error::Blocked { conflicts }),
        resolved => Ok(resolved),
    }
}

/// Recover, refuse if it is blocked, and **keep the lock**.
///
/// The call every writing command makes. [`recover`] followed by
/// [`journal::Session::open`] releases the state directory between the two, so
/// a second bx can win it in between and this one's session then refuses with
/// [`journal::Error::InProgress`] naming a journal that belongs to a live run
/// rather than to an interruption. Handing the guard to
/// [`journal::Session::open_locked`] makes that error mean what it says: there
/// was an interruption this run could not resolve. See `r3 round 3`
/// decision 3.
///
/// Only the guard comes back. The recovery's [`Outcome`] is logged by
/// [`resolve`] and not returned: no writing command has a channel to report it
/// on yet, and a value every caller binds to `_` is a value the next reader has
/// to work out the point of. A command layer that grows such a channel adds it
/// back with a caller that reads it. Until then [`recover`] is the form that
/// answers "what did recovery do", for a caller that opens no session.
///
/// The caller opens the session itself, so a session's failure stays a
/// session's failure rather than becoming a recovery's.
///
/// # Errors
///
/// As [`recover`], plus [`Error::Blocked`] when a destination cannot be
/// accounted for — a command that is about to write must stop. The escape from
/// that is `abandon`.
pub fn lock_for_writing(state: &StateDir) -> Result<ExclusiveLock, Error> {
    state.ensure()?;
    let lock = ExclusiveLock::acquire(state)?;
    resolved_or_blocked(state, &lock)?;
    Ok(lock)
}

/// Move an unresolvable journal aside without touching any destination.
///
/// The escape hatch for a recovery that stays blocked: it clears the refusal so
/// bx can run again, and leaves every file on disk exactly as it is. Whatever bx
/// then finds it does not own is reported by `plan` as a conflict — skipped,
/// never overwritten — which is the same safe outcome a corrupt journal reaches.
///
/// Returns where the journal was kept, or `None` when there was none.
///
/// # Errors
///
/// [`Error::State`] when the lock cannot be taken and [`Error::Journal`] when
/// the journal cannot be moved, or with [`journal::Error::FutureVersion`] when
/// a newer bx wrote it, which is left exactly where it is. A journal abandoned earlier is never renamed
/// over: this one takes the next free set-aside name.
#[cfg(test)]
pub fn abandon(state: &StateDir) -> Result<Option<PathBuf>, Error> {
    let lock = ExclusiveLock::acquire(state)?;
    #[cfg(test)]
    tests::after_lock(state);
    let path = state.journal();
    // Looked at without following a link: a dangling one at the journal's
    // path is refused by every read (`journal::Error::NotAJournal`), so it
    // has to be something this can move aside.
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    // Refused here as everywhere else it is read: abandoning a newer bx's
    // journal from an older build discards a rollback only the newer bx can
    // make, and the way out is to run that bx. Any other failure to read is
    // left to the set-aside below, which reports its own.
    if let Err(future @ journal::Error::FutureVersion { .. }) = journal::load(&path) {
        return Err(future.into());
    }
    let aside = journal::set_aside(&path, &lock)?;
    tracing::warn!(
        path = %path.display(),
        moved_to = %aside.display(),
        "abandoned an interrupted bx session without touching any destination",
    );
    Ok(Some(aside))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recover::fixtures::*;
    use crate::recover::*;

    use crate::fs::{self, Mode};
    use crate::journal::tests::{
        WRITES_THROUGH_PERMISSIONS, cannot_build, frame_starts, names_in, peek, permissions_refuse,
        plant_file, raw_journal, seal, state_beyond_set_aside_names, target, write_to,
    };
    use crate::journal::{
        self, Begin, Done, End, Intent, Loaded, Record, Session, SessionKind, Written,
    };
    use crate::paths::Portable;
    use crate::report::Exit;
    use crate::state::{
        ContentHash, ExclusiveLock, Ledger, LedgerView, Mechanism, NewEntry, Prior, PriorBytes,
        RestoreRef, StateDir,
    };
    use crate::testing::guarded_home;

    thread_local! {
        /// The mode a test narrows the state directory to once the lock is
        /// held. Taking the lock sets the directory back to 0700 whatever it
        /// was, so a narrower mode set before it would not survive to the
        /// step under test. Per thread, so tests running in parallel never
        /// see each other's.
        static AFTER_LOCK: std::cell::Cell<Option<Mode>> =
            const { std::cell::Cell::new(None) };
    }

    /// The seam [`recover`] and `abandon` call once they hold the lock.
    pub(super) fn after_lock(state: &StateDir) {
        if let Some(mode) = AFTER_LOCK.with(std::cell::Cell::get) {
            fs::set_mode(state.root(), mode).expect("narrow the state directory");
        }
    }

    /// Run `f` with the state directory narrowed to `mode` from the moment
    /// the lock is taken, and put it back to 0700 afterwards.
    fn narrowed_after_lock<T>(state: &StateDir, mode: Mode, f: impl FnOnce() -> T) -> T {
        AFTER_LOCK.with(|cell| cell.set(Some(mode)));
        let out = f();
        AFTER_LOCK.with(|cell| cell.set(None));
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it usable again");
        out
    }

    #[test]
    fn nothing_to_recover_is_not_an_error() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        assert!(pending(&state).expect("pending").is_none());
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert_eq!(recover(&state).expect("before"), Outcome::Nothing);
        assert_eq!(abandon(&state).expect("abandon"), None);
    }

    #[test]
    fn the_journal_survives_a_blocked_recovery_and_writing_is_refused() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&dest, "edited\n", Mode::DEFAULT_FILE);

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. }
        ));
        assert!(state.journal().exists(), "the interruption still stands");

        let err = lock_for_writing(&state).expect_err("a writing command must refuse");
        let Error::Blocked { conflicts } = &err else {
            panic!("got {err}")
        };
        assert_eq!(conflicts.len(), 1);
        assert!(err.to_string().contains(&dest.display().to_string()));

        // And it is still standing after the refusal, run after run.
        assert!(matches!(
            recover(&state).expect("recover again"),
            Outcome::Blocked { .. }
        ));
        assert!(state.journal().exists());
    }

    #[test]
    fn abandoning_a_recovery_touches_no_destination() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        plant_file(&dest, "edited\n", Mode::DEFAULT_FILE);

        let aside = abandon(&state)
            .expect("abandon")
            .expect("a journal was there");
        assert_eq!(aside, StateDir::quarantine(&state.journal()));
        assert!(aside.is_file(), "the bytes are kept, never deleted");
        assert!(!state.journal().exists());
        assert_eq!(
            peek(&dest).expect("untouched").0,
            b"edited\n",
            "abandoning writes nothing to any destination",
        );

        // And the refusal is cleared: bx can write again.
        assert!(pending(&state).expect("pending").is_none());
        drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
    }

    #[test]
    fn a_writing_command_holds_one_lock_across_its_recovery_and_its_session() {
        // r3 round 3, CL3. A recovery followed by `Session::open` drops
        // the state directory between the two, so a second bx could win it and
        // this one's session would refuse with `InProgress` naming a journal
        // that belongs to a live run rather than to an interruption.
        //
        // The one-lock property itself is the type's: `lock_for_writing`
        // returns the guard by value and `Session::open_locked` consumes it,
        // so there is no point at which a caller of the pair can be without
        // it. What this pins is the contract around that — the recovery runs
        // and reports, the returned guard is held, the session takes it over
        // rather than acquiring a second one, a finished session gives it
        // back, and a session refused for its scope gives it back too. It is
        // the last that would otherwise be unreached: `open_locked` owns the
        // guard, so an early return has to drop it.
        //
        // What it does *not* establish is that a writing command uses the
        // pair: nothing in the type system says so, and `restore` being the
        // only writing command at this revision is what makes it true today.
        // What narrows it is that `lock_for_writing` is now the only call that
        // refuses a blocked recovery — `before_writing`, which did the same
        // and released the lock, had no caller but a test and is gone
        // (`r3 round 5`, CL1).
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        let lock = lock_for_writing(&state).expect("recover and keep the lock");
        assert_eq!(
            peek(&dest).expect("rolled back").0,
            b"old\n",
            "the recovery ran under the guard that came back",
        );
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_none(),
            "the recovery did not release the lock",
        );

        let session =
            Session::open_locked(&state, SessionKind::Restore, home.path(), Vec::new(), lock)
                .expect("the session takes the guard");
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_none(),
            "and the session holds the same one",
        );
        assert_eq!(session.finish().expect("finish"), 0);
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_some(),
            "only the finished session releases it",
        );

        // A scope the loader would refuse is refused under the caller's lock
        // too, and releases it: `open_locked` owns the guard either way.
        let lock = lock_for_writing(&state).expect("nothing to recover");
        let absolute = Portable::try_from(dest.to_str().expect("utf-8").to_string())
            .expect("a well-formed absolute path");
        let err = Session::open_locked(
            &state,
            SessionKind::Restore,
            home.path(),
            vec![absolute],
            lock,
        )
        .expect_err("a scope entry the loader refuses");
        assert!(
            matches!(
                err,
                journal::Error::State(crate::state::Error::ForeignRecord { .. })
            ),
            "got {err}"
        );
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_some(),
            "the refused session released the lock",
        );
    }

    #[test]
    fn a_journal_that_records_a_write_with_no_header_is_set_aside_not_replayed() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");

        let (portable, dest) = target(home.path(), ".conf");
        raw_journal(
            &state.journal(),
            &[
                Record::Intent(Intent {
                    target: portable.clone(),
                    dest,
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Absent,
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                    dir: false,
                    link: false,
                }),
                Record::Done(Done { target: portable }),
                Record::End(End { written: 1 }),
            ],
        );
        let bytes = std::fs::read(state.journal()).expect("the journal");

        // No header, so no home to check a single stored path against: bytes bx
        // never wrote, for a report and for recovery alike.
        assert!(
            pending(&state)
                .expect("pending")
                .expect("reported")
                .unreadable
        );
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            bytes,
        );
        assert!(!state.journal().exists());
    }

    #[test]
    fn pending_never_moves_a_journal_aside_even_one_it_cannot_read() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"not a journal").expect("write");

        // `pending` takes no lock, so what it is reading may be a journal a live
        // session is in the middle of creating. It moves nothing, and it says
        // the journal is there.
        let report = pending(&state).expect("pending").expect("reported");
        assert!(report.unreadable);
        assert!(report.unfinished.is_empty());
        assert_eq!(report.exit(), Exit::Pending);
        assert_eq!(
            std::fs::read(state.journal()).expect("still in place"),
            b"not a journal",
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());

        // The locked path is the one that sets it aside, and keeps the bytes.
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert!(!state.journal().exists());
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            b"not a journal",
        );
    }

    #[test]
    fn a_journal_a_live_session_has_only_just_created_is_reported_and_left_in_place() {
        // The race a concurrent `plan` used to lose: it read the journal in the
        // instant `apply` had created it and not yet written a byte, called that
        // corruption, and renamed the live journal away.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"").expect("write");

        let interruption = pending(&state)
            .expect("pending")
            .expect("an empty journal is still a session");
        assert!(interruption.unfinished.is_empty());
        assert!(!interruption.complete);
        assert_eq!(interruption.exit(), Exit::Pending);
        assert!(state.journal().is_file(), "left exactly where it was");
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn abandoning_a_journal_that_cannot_be_moved_is_an_error_and_moves_nothing() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        // Read-only once the lock is held, since taking it sets the directory
        // back to 0700: the rename needs a write to the directory.
        fs::set_mode(state.root(), Mode::from_bits(0o500)).expect("make it read-only");
        let refuses = permissions_refuse(state.root());
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");
        if !refuses {
            return cannot_build(
                "abandoning_a_journal_that_cannot_be_moved_is_an_error_and_moves_nothing",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let abandoned = narrowed_after_lock(&state, Mode::from_bits(0o500), || abandon(&state));

        let err = abandoned.expect_err("a rename in a read-only directory fails");
        assert!(
            matches!(err, Error::Journal(journal::Error::Io { .. })),
            "got {err}"
        );
        assert!(state.journal().is_file(), "the interruption still stands");
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn abandoning_in_a_state_directory_that_cannot_be_opened_moves_nothing() {
        // Write and search, no read: the rename would succeed and the directory
        // cannot be opened to fsync it. The open comes first, so the failure
        // leaves the journal where it was.
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        // Narrowed once the lock is held, since taking it sets the directory
        // back to 0700.
        let abandoned = narrowed_after_lock(&state, Mode::from_bits(0o300), || abandon(&state));

        match abandoned {
            Err(Error::Journal(journal::Error::Io { path, source })) => {
                assert_eq!(path, state.root());
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected an io error naming the state directory, got {other:?}"),
        }
        assert!(state.journal().is_file(), "the interruption still stands");
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn a_journal_whose_paths_are_not_its_targets_is_set_aside_and_touches_nothing() {
        // Review round 3, item 2. Each of these was believed: rollback acted on
        // the stored destination, temporary file and created directories with
        // nothing tying them to the intent's target, and a journal with no
        // header was checked against nothing at all.
        let guard = guarded_home();
        let evil = b"EVIL\n";
        let reference = RestoreRef {
            digest: ContentHash::of(evil),
            mode: Mode::DEFAULT_FILE,
            len: 5,
        };
        let theirs = Written::Present {
            digest: ContentHash::of(b"theirs\n"),
            mode: Mode::DEFAULT_FILE,
        };
        for case in [
            "a destination outside the home",
            "a destination that is another file",
            "a temporary file that is the user's",
            "a bx temporary file in another directory",
            "a created directory that is not a parent",
            "a created directory that is the home",
            "no header",
        ] {
            let root = guard.child(case.replace(' ', "-"));
            let home = root.join("home");
            let state = StateDir::resolve(&home);
            state.ensure().expect("ensure");
            std::fs::write(state.restore().join(reference.blob_name()), evil).expect("a blob");
            let outside = root.join("outside/victim.conf");
            let victim = home.join(".victim.conf");
            let stray = home.join("sub/.bx-theirs");
            let empty = home.join("empty");
            for file in [&outside, &victim, &stray] {
                plant_file(file, "theirs\n", Mode::DEFAULT_FILE);
            }
            std::fs::create_dir_all(&empty).expect("the user's empty directory");

            let mut intent = intent_for(&home, ".conf");
            match case {
                "a destination outside the home" => {
                    intent.dest.clone_from(&outside);
                    intent.before = Prior::Existed(reference.clone());
                    intent.after = theirs;
                }
                "a destination that is another file" => {
                    intent.dest.clone_from(&victim);
                    intent.after = theirs;
                }
                "a temporary file that is the user's" => intent.temp = Some(victim.clone()),
                "a bx temporary file in another directory" => intent.temp = Some(stray.clone()),
                "a created directory that is not a parent" => {
                    intent.created_dirs = vec![empty.clone()];
                }
                "a created directory that is the home" => intent.created_dirs = vec![home.clone()],
                _ => {
                    intent = intent_for(&home, ".victim.conf");
                    intent.after = theirs;
                }
            }
            let records = if case == "no header" {
                vec![Record::Intent(intent)]
            } else {
                vec![
                    Record::Begin(Begin {
                        kind: SessionKind::Apply,
                        home: home.clone(),
                        scope: Vec::new(),
                    }),
                    Record::Intent(intent),
                ]
            };
            raw_journal(&state.journal(), &records);
            let bytes = std::fs::read(state.journal()).expect("the journal");

            assert_eq!(
                crate::journal::load(&state.journal()).expect("load"),
                Loaded::Unreadable { moved_to: None },
                "{case}",
            );
            assert!(
                pending(&state)
                    .expect("pending")
                    .expect("reported")
                    .unreadable,
                "{case}"
            );
            assert_eq!(
                recover(&state).expect("recover"),
                Outcome::Nothing,
                "{case}"
            );
            assert_eq!(
                std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
                bytes,
                "{case}",
            );
            for file in [&outside, &victim, &stray] {
                assert_eq!(
                    peek(file).map(|(bytes, _)| bytes),
                    Some(b"theirs\n".to_vec()),
                    "{case}: {} was touched",
                    file.display(),
                );
            }
            assert!(
                empty.is_dir(),
                "{case}: the user's empty directory was removed"
            );
        }
    }

    #[test]
    fn recovery_under_another_spelling_of_the_home_refuses_and_moves_nothing() {
        // Stack integration of #7's round 3: a ledger storing a path the home
        // cannot use is `Error::ForeignPath`, never a reset. A terminated
        // journal's rebuild opens the ledger under the lock with the journal's
        // home, so it must stop there with the ledger and the journal in place.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let alias = home.child("alias");
        std::os::unix::fs::symlink(home.path(), &alias).expect("alias");
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        {
            // The ledger as a run under the other spelling left it: a target it
            // named absolutely, which this spelling folds into its home.
            let lock = ExclusiveLock::acquire(&state).expect("lock");
            let mut ledger = Ledger::open(&state, &lock, &alias).expect("open").value;
            let key = Portable::from_path(&home.child(".foo"), &alias).expect("portable");
            assert!(key.as_str().starts_with('/'), "{key}");
            ledger
                .record(NewEntry::new(
                    key,
                    ContentHash::of(b"bx"),
                    Mode::DEFAULT_FILE,
                    Mechanism::Own,
                    PriorBytes::Absent,
                ))
                .expect("record");
            ledger.save().expect("save");
        }
        let ledger = std::fs::read(state.ledger()).expect("the ledger");
        let journal = std::fs::read(state.journal()).expect("the journal");
        let dest = peek(&home.child(".conf"));

        let foreign =
            |err: &Error| matches!(err, Error::State(crate::state::Error::ForeignPath { .. }));
        let err = pending(&state).expect_err("the report stops too");
        assert!(foreign(&err), "got {err}");
        let err = recover(&state).expect_err("a mis-spelled home stops the run");
        assert!(foreign(&err), "got {err}");
        let err = lock_for_writing(&state).expect_err("and every writing command");
        assert!(foreign(&err), "got {err}");

        assert_eq!(std::fs::read(state.ledger()).expect("in place"), ledger);
        assert_eq!(std::fs::read(state.journal()).expect("in place"), journal);
        assert!(!StateDir::quarantine(&state.ledger()).exists());
        assert!(!StateDir::quarantine(&state.journal()).exists());
        assert_eq!(peek(&home.child(".conf")), dest);
    }

    /// `ledger.mpk` as a bx with a newer ledger format leaves it.
    fn ledger_from_a_newer_bx() -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Envelope {
            kind: &'static str,
            version: u16,
            payload: LedgerView,
        }
        rmp_serde::to_vec_named(&Envelope {
            kind: "bx.ledger",
            version: u16::MAX,
            payload: LedgerView::default(),
        })
        .expect("encode")
    }

    /// Whether `err` is the ledger's refusal of a newer format.
    fn is_future_version(err: &crate::state::Error) -> bool {
        matches!(
            err,
            crate::state::Error::FutureVersion { found, .. } if *found == u16::MAX
        )
    }

    #[test]
    fn a_rollback_over_a_ledger_from_a_newer_bx_reads_only_the_journal_and_renames_nothing() {
        // Stack integration of #7's round 4: a ledger a newer bx wrote is
        // `Error::FutureVersion` and is never quarantined. An unterminated
        // journal is rolled back from the journal and the restore blobs alone,
        // so the rollback still completes; the next command that opens the
        // ledger is what stops.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(home.path(), ".conf", "one\n", Mode::DEFAULT_FILE))
            .expect("apply");
        first.finish().expect("finish");
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "two\n", Mode::DEFAULT_FILE)],
        );
        let newer = ledger_from_a_newer_bx();
        std::fs::write(state.ledger(), &newer).expect("a newer bx's ledger");

        let interruption = pending(&state).expect("a rollback's report reads no ledger");
        let interruption = interruption.expect("interrupted");
        assert!(!interruption.complete && !interruption.unreadable);
        assert_eq!(interruption.unfinished.len(), 1);
        assert!(interruption.unfinished[0].resolvable);

        assert_eq!(
            recover(&state).expect("the rollback needs no ledger"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(peek(&dest).expect("rolled back").0, b"one\n");
        assert!(!state.journal().exists());
        assert_eq!(std::fs::read(state.ledger()).expect("in place"), newer);
        assert!(!StateDir::quarantine(&state.ledger()).exists());

        // The next writing command opens the ledger and stops there.
        let err = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect_err("a session needs the ledger");
        assert!(
            matches!(&err, crate::journal::Error::State(inner) if is_future_version(inner)),
            "got {err}"
        );
        let err = crate::restore::restore(&state, home.path(), &[portable])
            .expect_err("rm needs the ledger");
        assert!(
            matches!(
                &err,
                crate::restore::Error::Journal(crate::journal::Error::State(inner))
                    if is_future_version(inner)
            ),
            "got {err}"
        );
        assert!(!state.journal().exists(), "no session was opened");
        assert_eq!(std::fs::read(state.ledger()).expect("in place"), newer);
        assert!(!StateDir::quarantine(&state.ledger()).exists());
        assert_eq!(peek(&dest).expect("untouched").0, b"one\n");
    }

    #[test]
    fn a_terminated_journal_over_a_ledger_from_a_newer_bx_stops_and_quarantines_nothing() {
        // Stack integration of #7's round 4: a terminated journal's bookkeeping
        // writes the ledger, so it opens it, and a newer format stops the report,
        // the recovery and every writing command, with nothing moved.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        let newer = ledger_from_a_newer_bx();
        std::fs::write(state.ledger(), &newer).expect("a newer bx's ledger");
        let journal = std::fs::read(state.journal()).expect("the journal");
        let dest = peek(&home.child(".conf"));

        let future = |err: &Error| matches!(err, Error::State(inner) if is_future_version(inner));
        let err = pending(&state).expect_err("the report stops");
        assert!(future(&err), "got {err}");
        let err = recover(&state).expect_err("the recovery stops");
        assert!(future(&err), "got {err}");
        let err = lock_for_writing(&state).expect_err("and every writing command");
        assert!(future(&err), "got {err}");

        assert_eq!(std::fs::read(state.ledger()).expect("in place"), newer);
        assert_eq!(std::fs::read(state.journal()).expect("in place"), journal);
        assert!(!StateDir::quarantine(&state.ledger()).exists());
        assert!(!StateDir::quarantine(&state.journal()).exists());
        assert_eq!(peek(&home.child(".conf")), dest);
    }

    #[test]
    fn a_damaged_ledger_is_only_reported_without_the_lock_and_quarantined_under_it() {
        // Stack integration of #7's round 3: a lockless read returns
        // `Health::Damaged` and moves nothing; only the lock holder quarantines.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&state.journal(), 1);
        std::fs::write(state.ledger(), b"not a ledger").expect("damage the ledger");

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.complete);
        assert!(interruption.unfinished.iter().all(|write| write.resolvable));
        assert_eq!(
            std::fs::read(state.ledger()).expect("left in place"),
            b"not a ledger"
        );
        assert!(!StateDir::quarantine(&state.ledger()).exists());

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 }
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.ledger())).expect("quarantined"),
            b"not a ledger",
        );
        let rebuilt = LedgerView::read(&state, home.path()).expect("read");
        assert_eq!(rebuilt.health, crate::state::Health::Loaded);
        assert_eq!(
            rebuilt
                .value
                .get(&target(home.path(), ".conf").0)
                .expect("the entry")
                .written,
            ContentHash::of(b"new\n"),
        );
    }

    #[test]
    fn a_damaged_ledger_that_cannot_be_moved_aside_stops_recovery_and_keeps_the_journal() {
        // Stack integration of #8 @62de0aa, which carries #7's r3 round 1:
        // `Ledger::open` refuses a damaged ledger it cannot move aside with
        // `state::Error::CannotQuarantine`. A terminated journal's bookkeeping
        // opens the ledger, so recovery must stop there: the ledger keeps its
        // bytes, and the journal stays for the run after the ledger is moved.
        let home = guarded_home();
        let made = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &made,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        seal(&made.journal(), 1);
        std::fs::write(made.ledger(), b"not a ledger").expect("damage the ledger");
        let journal = std::fs::read(made.journal()).expect("the journal");
        // Written where a session's names fit, then moved to where no
        // set-aside name does.
        let state = state_beyond_set_aside_names(&home);
        std::fs::create_dir_all(state.root().parent().expect("a parent")).expect("its parents");
        std::fs::rename(made.root(), state.root()).expect("move the state directory");

        let recovered = recover(&state);
        assert!(
            matches!(
                &recovered,
                Err(Error::State(crate::state::Error::CannotQuarantine {
                    path,
                    damage: crate::state::Damage::Malformed,
                    ..
                })) if *path == state.ledger()
            ),
            "got {recovered:?}"
        );
        assert_eq!(
            std::fs::read(state.ledger()).expect("kept"),
            b"not a ledger",
            "the damaged ledger's bytes are unchanged"
        );
        assert_eq!(
            std::fs::read(state.journal()).expect("kept"),
            journal,
            "the journal stays for the next run"
        );
        assert_eq!(
            names_in(state.root()),
            ["journal.mpk", "ledger.mpk", "lock", "restore", "shell"],
            "nothing was set aside or saved"
        );
        assert_eq!(
            peek(&home.child(".conf")).map(|(bytes, _)| bytes),
            Some(b"new\n".to_vec()),
            "a terminated session's write is not rolled back"
        );
    }

    #[test]
    fn two_successive_torn_journals_are_both_rolled_back_and_kept_and_bx_writes_afterwards() {
        // #9's round-3 review: the set-aside name was checked before the
        // rollback, so a second torn journal blocked recover, rm, abandon and
        // every session while the machine stayed half-applied. Recovery rolls
        // back first and sets the journal aside last, under the next free name.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut kept = Vec::new();
        for round in 0..2 {
            let (dest, mut bytes) = interrupted_modify(&state, home.path());
            // A different cut each round, so the two kept files differ.
            bytes.truncate(bytes.len() - 1 - round);
            std::fs::write(state.journal(), &bytes).expect("tear the last frame");
            assert_eq!(
                recover(&state).expect("recover"),
                Outcome::RolledBack { undone: 1 },
                "round {round}",
            );
            assert_eq!(
                peek(&dest).expect("rolled back").0,
                b"the user's original\n",
                "round {round}",
            );
            assert!(!state.journal().exists(), "round {round}");
            kept.push(bytes);
        }
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("the first"),
            kept[0],
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&state.journal(), 1)).expect("the second"),
            kept[1],
        );

        let mut session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect("bx writes again");
        session
            .apply(write_to(
                home.path(),
                ".conf",
                "bx new\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("apply");
        assert_eq!(session.finish().expect("finish"), 1);
        assert_eq!(peek(&home.child(".conf")).expect("written").0, b"bx new\n");
    }

    #[test]
    fn a_set_aside_that_fails_after_the_rollback_leaves_the_journal_in_place() {
        // The rollback comes first. If the torn journal then cannot be moved
        // aside, it stays where it is, and the next run repeats a rollback that
        // has nothing left to do before trying again.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (dest, mut bytes) = interrupted_modify(&state, home.path());
        bytes.truncate(bytes.len() - 1);
        std::fs::write(state.journal(), &bytes).expect("tear the last frame");

        // The rollback writes in the home; only the set-aside renames in the
        // state directory. Read-only once the lock is held, since taking it
        // sets the directory back to 0700.
        fs::set_mode(state.root(), Mode::from_bits(0o500)).expect("make it read-only");
        let refuses = permissions_refuse(state.root());
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");
        if !refuses {
            return cannot_build(
                "a_set_aside_that_fails_after_the_rollback_leaves_the_journal_in_place",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let first = narrowed_after_lock(&state, Mode::from_bits(0o500), || recover(&state));

        let err = first.expect_err("the journal cannot be moved aside");
        assert!(
            matches!(err, Error::Journal(journal::Error::Io { .. })),
            "got {err}"
        );
        assert_eq!(
            peek(&dest).expect("rolled back").0,
            b"the user's original\n",
            "the rollback ran before the set-aside was tried",
        );
        assert_eq!(
            std::fs::read(state.journal()).expect("left in place"),
            bytes
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 }
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("set aside"),
            bytes,
        );
        assert_eq!(
            peek(&dest).expect("still rolled back").0,
            b"the user's original\n"
        );
    }

    #[test]
    fn abandoning_twice_keeps_both_set_aside_journals() {
        // Review round 3, item 5. The set-aside name was fixed, and the second
        // abandon renamed its journal over the first. Round 3 refused the
        // second abandon instead; since #7's numbered names integrated, it
        // succeeds and takes the next free name, and both journals survive.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut kept = Vec::new();
        for rel in [".one", ".two"] {
            let dest = home.child(rel);
            plant_file(&dest, "orig\n", Mode::DEFAULT_FILE);
            interrupted(
                &state,
                home.path(),
                vec![write_to(home.path(), rel, "bx\n", Mode::DEFAULT_FILE)],
            );
            plant_file(&dest, "user edit\n", Mode::DEFAULT_FILE);
            assert!(matches!(
                recover(&state).expect("recover"),
                Outcome::Blocked { .. }
            ));
            kept.push(std::fs::read(state.journal()).expect("the journal"));
            if kept.len() == 1 {
                abandon(&state).expect("abandon").expect("set aside");
            }
        }

        let second = abandon(&state)
            .expect("the second abandon succeeds")
            .expect("set aside");
        assert_eq!(second, StateDir::quarantine_nth(&state.journal(), 1));
        assert!(!state.journal().exists(), "the interruption is cleared");
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("the first"),
            kept[0],
        );
        assert_eq!(std::fs::read(&second).expect("the second"), kept[1]);
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
    }

    #[test]
    fn a_damaged_frame_length_never_loses_the_journal() {
        // Review round 3, item 3. A length byte flipped in either frame read as
        // a torn tail: recovery rolled back nothing and unlinked the journal,
        // leaving the user's original only as a blob nothing named.
        let guard = guarded_home();
        for (case, frame) in [("the first frame", 0), ("a later frame", 1)] {
            let home = guard.child(case.replace(' ', "-"));
            let state = StateDir::resolve(&home);
            let (dest, mut bytes) = interrupted_modify(&state, &home);
            let start = frame_starts(&bytes)[frame];
            // About 8 MiB: under the frame bound, and past the end of the file.
            bytes[start + 2] = 0x80;
            std::fs::write(state.journal(), &bytes).expect("damage the journal");

            let report = pending(&state).expect("pending");
            let outcome = recover(&state).expect("recover");
            let report = report.expect("reported");
            assert!(report.unfinished.is_empty(), "{case}");
            if frame == 0 {
                assert!(report.unreadable, "{case}");
                assert_eq!(outcome, Outcome::Nothing, "{case}: not believed");
            } else {
                assert!(!report.unreadable, "{case}: a torn tail");
                assert_eq!(outcome, Outcome::RolledBack { undone: 0 }, "{case}");
            }
            assert!(!state.journal().exists(), "{case}");
            assert_eq!(
                std::fs::read(StateDir::quarantine(&state.journal()))
                    .expect("set aside, never unlinked"),
                bytes,
                "{case}",
            );
            assert_eq!(peek(&dest).expect("left as it is").0, b"bx new\n", "{case}");
        }
    }

    #[test]
    fn a_byte_flipped_inside_a_frame_is_not_believed() {
        // Review round 3, item 3. Without a checksum this still decoded, as the
        // mode the rollback then put the user's original back at.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (dest, mut bytes) = interrupted_modify(&state, home.path());
        let mode = bytes
            .windows(8)
            .position(|window| window == [0xa4, b'm', b'o', b'd', b'e', 0xcd, 0x01, 0xa4])
            .expect("the prior's mode, 0o644, as MessagePack");
        bytes[mode + 7] = 0xa5;
        std::fs::write(state.journal(), &bytes).expect("damage the journal");

        assert_eq!(
            crate::journal::load(&state.journal()).expect("load"),
            Loaded::Unreadable { moved_to: None },
        );
        assert!(
            pending(&state)
                .expect("pending")
                .expect("reported")
                .unreadable
        );
        assert_eq!(recover(&state).expect("recover"), Outcome::Nothing);
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            bytes,
        );
        assert_eq!(
            peek(&dest),
            Some((b"bx new\n".to_vec(), Mode::DEFAULT_FILE)),
        );
    }

    #[test]
    fn an_unreadable_journal_is_reported_by_plan_and_set_aside_by_the_next_session() {
        // Review round 4, item 2. `pending` said there was no session, and the
        // only word of the journal was a warning below the default log level,
        // so `plan` exited clean over a journal the next `apply` then set aside.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"GARBAGE!").expect("an unreadable journal");

        let report = pending(&state)
            .expect("pending")
            .expect("an unreadable journal is reported");
        assert_eq!(
            report,
            Interrupted {
                kind: SessionKind::Apply,
                journal: state.journal(),
                complete: false,
                unreadable: true,
                unfinished: Vec::new(),
            },
        );
        assert_eq!(report.exit(), Exit::Pending);
        assert_eq!(
            std::fs::read(state.journal()).expect("left in place"),
            b"GARBAGE!"
        );

        let session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect("a session opens over it");
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("set aside"),
            b"GARBAGE!",
        );
        assert_eq!(session.finish().expect("finish"), 0);
        assert_eq!(pending(&state).expect("pending"), None, "and it is gone");
    }

    #[test]
    fn a_zero_filled_tail_after_whole_frames_is_rolled_back_then_kept() {
        // Review round 4, item 1. A power loss that zero-fills the unsynced last
        // frame left bytes that fail its checksum. Round 3 read that as damage:
        // the journal was set aside with nothing rolled back, so `.a` kept bx's
        // bytes, the ledger had no entry for it, and `rm` called it unmanaged.
        let guard = guarded_home();
        for (case, zeroed_done_of_a) in [("the Intent of .b", false), ("the Done of .a", true)] {
            let home = guard.child(case.replace(' ', "-"));
            let state = StateDir::resolve(&home);
            let a = home.join(".a");
            let b = home.join(".b");
            plant_file(&a, "A0\n", Mode::DEFAULT_FILE);
            plant_file(&b, "B0\n", Mode::DEFAULT_FILE);
            let mut session =
                Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
            session
                .apply(write_to(&home, ".a", "A1\n", Mode::DEFAULT_FILE))
                .expect("apply .a");
            let after_a = std::fs::read(state.journal()).expect("the journal");
            session
                .apply(write_to(&home, ".b", "B1\n", Mode::DEFAULT_FILE))
                .expect("apply .b");
            let after_b = std::fs::read(state.journal()).expect("the journal");
            drop(session);
            // The frame that zero-filled was never synced, so the write it
            // announced, or the one after it, had not begun: `.b` is as it was.
            plant_file(&b, "B0\n", Mode::DEFAULT_FILE);
            let (bytes, kept) = if zeroed_done_of_a {
                let mut bytes = after_a;
                let done = frame_starts(&bytes)[2];
                bytes[done..].fill(0);
                (bytes, 2)
            } else {
                let starts = frame_starts(&after_b);
                let mut bytes = after_b[..starts[4]].to_vec();
                bytes[starts[3]..].fill(0);
                (bytes, 3)
            };
            std::fs::write(state.journal(), &bytes).expect("zero-fill the tail");

            let loaded = crate::journal::load(&state.journal()).expect("load");
            assert!(
                matches!(&loaded, Loaded::Torn { records, .. } if records.len() == kept),
                "{case}: {loaded:?}",
            );
            let report = pending(&state)
                .expect("pending")
                .expect("an interrupted session");
            assert_eq!(report.unfinished.len(), 1, "{case}");
            assert_eq!(
                recover(&state).expect("recover"),
                Outcome::RolledBack { undone: 1 },
                "{case}",
            );
            assert_eq!(peek(&a).expect("rolled back").0, b"A0\n", "{case}");
            assert_eq!(peek(&b).expect("untouched").0, b"B0\n", "{case}");
            assert!(!state.journal().exists(), "{case}");
            assert_eq!(
                std::fs::read(StateDir::quarantine(&state.journal())).expect("kept aside"),
                bytes,
                "{case}",
            );

            let (portable, _) = target(&home, ".a");
            crate::restore::restore(&state, &home, &[portable]).expect("rm");
            assert_eq!(peek(&a).expect("still the original").0, b"A0\n", "{case}");
        }
    }

    #[test]
    fn a_torn_journal_whose_first_set_aside_name_is_taken_is_recovered_and_kept_beside_it() {
        // Round 3 refused this recovery until the user moved the earlier file.
        // With #7's numbered names nothing is in the way: the rollback runs and
        // the torn journal takes the next free name, the earlier file intact.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (dest, mut bytes) = interrupted_modify(&state, home.path());
        bytes.truncate(bytes.len() - 1);
        std::fs::write(state.journal(), &bytes).expect("tear the last frame");
        let aside = StateDir::quarantine(&state.journal());
        std::fs::write(&aside, b"the first").expect("a journal set aside earlier");

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 }
        );
        assert_eq!(
            peek(&dest).expect("rolled back").0,
            b"the user's original\n"
        );
        assert!(!state.journal().exists());
        assert_eq!(std::fs::read(&aside).expect("kept"), b"the first");
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&state.journal(), 1)).expect("set aside"),
            bytes,
        );
    }

    #[test]
    fn a_stale_whole_frame_from_an_earlier_journal_in_the_tail_still_rolls_back_the_prefix() {
        // Review round 5, item 3. After a power loss the unsynced tail can hold
        // blocks of an earlier, deleted journal. A whole frame from it validated,
        // so the damaged last frame was read as mid-log damage: the journal was
        // set aside as unreadable and the half-applied `.a` was never rolled back.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (a, b) = (home.child(".a"), home.child(".b"));
        plant_file(&a, "A0\n", Mode::DEFAULT_FILE);
        plant_file(&b, "B0\n", Mode::DEFAULT_FILE);

        // An earlier session, finished and unlinked: its last frame is the stale block.
        let mut earlier =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        earlier
            .apply(write_to(home.path(), ".x", "X\n", Mode::DEFAULT_FILE))
            .expect("apply");
        let old = std::fs::read(state.journal()).expect("the earlier journal");
        earlier.finish().expect("finish");
        let old_done = old[*frame_starts(&old).last().expect("its Done frame")..].to_vec();

        interrupted(
            &state,
            home.path(),
            vec![
                write_to(home.path(), ".a", "A1\n", Mode::DEFAULT_FILE),
                write_to(home.path(), ".b", "B1\n", Mode::DEFAULT_FILE),
            ],
        );
        let whole = std::fs::read(state.journal()).expect("the journal");
        // `.b`'s Intent never reached the disk, so its write never began.
        plant_file(&b, "B0\n", Mode::DEFAULT_FILE);
        let starts = frame_starts(&whole);
        let (intent_b, done_b) = (starts[3], starts[4]);
        let mut bytes = whole[..done_b].to_vec();
        for (at, byte) in (0..=u8::MAX).cycle().zip(bytes[intent_b..].iter_mut()) {
            *byte = at.wrapping_mul(37).wrapping_add(11);
        }
        let place = intent_b + 16;
        assert!(
            place + old_done.len() <= bytes.len(),
            "the stale frame fits"
        );
        bytes[place..place + old_done.len()].copy_from_slice(&old_done);
        std::fs::write(state.journal(), &bytes).expect("the power-loss bytes");

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 }
        );
        assert_eq!(peek(&a).expect("rolled back").0, b"A0\n");
        assert_eq!(peek(&b).expect("untouched").0, b"B0\n");
        assert_eq!(
            std::fs::read(StateDir::quarantine(&state.journal())).expect("kept"),
            bytes,
        );
    }

    #[test]
    fn a_journal_a_newer_bx_wrote_is_refused_and_nothing_is_set_aside_or_rolled_back() {
        // Review round 5, item 2. A newer format byte read as damage: the next
        // session set the journal aside with nothing rolled back, discarding a
        // newer bx's interrupted session.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let a = home.child(".a");
        plant_file(&a, "A0\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".a", "A1\n", Mode::DEFAULT_FILE)],
        );
        let mut bytes = std::fs::read(state.journal()).expect("the journal");
        bytes[7] += 1;
        std::fs::write(state.journal(), &bytes).expect("what a newer bx leaves");

        let future = |err: &journal::Error| matches!(err, journal::Error::FutureVersion { .. });
        let refused = |err: Error| matches!(&err, Error::Journal(inner) if future(inner));
        let loaded = crate::journal::load(&state.journal()).expect_err("load refuses");
        assert!(future(&loaded), "{loaded}");
        assert!(
            loaded.to_string().contains("run a bx at least as new"),
            "{loaded}"
        );
        assert!(refused(pending(&state).expect_err("pending refuses")));
        assert!(refused(recover(&state).expect_err("recover refuses")));
        assert!(refused(
            lock_for_writing(&state).expect_err("a writing command refuses")
        ));
        let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect_err("a session refuses");
        assert!(future(&opened), "{opened}");
        assert!(refused(abandon(&state).expect_err("abandon refuses")));

        assert_eq!(
            std::fs::read(state.journal()).expect("left in place"),
            bytes
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());
        assert_eq!(peek(&a).expect("not rolled back").0, b"A1\n");
    }
}
