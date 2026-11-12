//! A session a failure poisons: an append, a publish, a removal or the ledger
//! refused part-way, a prior or a destination changed under it, and the
//! rollback that recovery then makes without touching the user's edit.

use super::*;

// `/dev/full` is Linux's.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_append_poisons_the_session() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

    let mut session = apply_session(&state, home.path());
    let real = std::mem::replace(
        &mut session.journal.file,
        OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full"),
    );
    let err = session
        .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
        .expect_err("a full disk fails the Intent append");
    assert!(matches!(err, Error::Io { .. }), "got {err}");
    assert_eq!(
        peek(&home.child(".conf")).expect("untouched").0,
        b"old\n",
        "nothing is published without its Intent",
    );

    // The disk has room again. A torn frame may now sit at the journal's
    // tail, and anything appended after it would be hidden from recovery, so
    // the session must append nothing more at all.
    session.journal.file = real;
    let err = session
        .apply(write_to(home.path(), ".other", "x\n", Mode::DEFAULT_FILE))
        .expect_err("a poisoned session refuses another write");
    assert!(matches!(err, Error::Poisoned { .. }), "got {err}");
    assert!(err.to_string().contains("roll back"), "{err}");
    assert!(!home.child(".other").exists());

    let err = session.finish().expect_err("and refuses to finish");
    assert!(matches!(err, Error::Poisoned { .. }), "got {err}");
    assert!(state.journal().exists(), "the journal is left for recovery");
    assert!(!state.ledger().exists(), "and the ledger was never saved");
    assert!(matches!(
        load(&state.journal()).expect("load"),
        Loaded::Unterminated(_)
    ));
}

// `/dev/full` is Linux's.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_removal_intent_append_poisons_the_session_and_unlinks_nothing() {
    // The write path's failed append is pinned above; this pins the
    // removal's.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    let mut first = apply_session(&state, home.path());
    first
        .apply(write_to(
            home.path(),
            ".conf",
            "bx created\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("apply");
    first.finish().expect("finish");

    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    session.journal.file = OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full");
    let err = session
        .apply(remove_to(home.path(), ".conf", Vec::new()))
        .expect_err("a full disk fails the removal's Intent append");
    assert!(
        matches!(&err, Error::Io { path, .. } if *path == state.journal()),
        "got {err}"
    );
    assert_eq!(peek(&dest).expect("not unlinked").0, b"bx created\n");
    assert!(
        session.ledger().get(&portable).is_some(),
        "nothing was removed, so nothing is forgotten"
    );
    let finished = session
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
}

#[test]
fn a_failed_publish_poisons_the_session_and_records_nothing() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");

    let mut session = apply_session(&state, home.path());
    // Something occupies the destination between the Intent and the rename:
    // a directory with an entry in it, which no rename(2) replaces with a
    // file.
    session.before_publish = Some(|dest: &Path| {
        std::fs::create_dir_all(dest.join("occupied")).expect("occupy the destination");
    });
    let err = session
        .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
        .expect_err("the rename cannot land");
    assert!(matches!(err, Error::Write(_)), "got {err}");
    assert!(
        session.ledger().get(&portable).is_none(),
        "a write that never landed is not recorded, not even in memory",
    );

    let err = session
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(err, Error::Poisoned { .. }), "got {err}");
    assert!(!state.ledger().exists(), "no ledger entry was saved");
    let loaded = load(&state.journal()).expect("load");
    assert!(
        matches!(loaded, Loaded::Unterminated(_)),
        "no End frame: {loaded:?}"
    );
    assert!(
        !loaded
            .records()
            .iter()
            .any(|record| matches!(record, Record::Done(_))),
        "and no Done frame",
    );
    assert!(dest.is_dir());
}

#[test]
fn a_named_temp_recovery_cannot_unlink_is_left_and_the_rollback_goes_on() {
    // The directory loses write permission between the Intent and the
    // publish, so the publish fails and leaves the temporary file the
    // Intent names. Recovery cannot unlink it, and returning an Io error
    // for that would fail every writing run while `pending` called the
    // write resolvable.
    use std::os::unix::fs::PermissionsExt as _;

    fn lose_write(dest: &Path) {
        let dir = dest.parent().expect("a parent");
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).expect("chmod 0555");
    }

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dir = home.child(".ro");
    let dest = home.child(".ro/x.conf");
    plant_file(&dest, "user\n", Mode::DEFAULT_FILE);
    let mut session = apply_session(&state, home.path());
    session.before_publish = Some(lose_write);
    let applied = session.apply(write_to(
        home.path(),
        ".ro/x.conf",
        "bx\n",
        Mode::DEFAULT_FILE,
    ));
    drop(session);
    let writable = |dir: &Path| {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
    };
    if !permissions_refuse(&dir) {
        writable(&dir);
        return cannot_build(
            "a_named_temp_recovery_cannot_unlink_is_left_and_the_rollback_goes_on",
            WRITES_THROUGH_PERMISSIONS,
        );
    }
    let temp = load(&state.journal())
        .expect("load")
        .intents()
        .next()
        .expect("the Intent")
        .temp
        .clone()
        .expect("a staged temporary file");

    let report = crate::recover::pending(&state);
    let recovered = crate::recover::recover(&state);
    let temp_left = temp.is_file();
    writable(&dir);

    assert!(
        applied.is_err(),
        "the publish fails in a read-only directory"
    );
    assert_eq!(
        recovered.expect("the rollback goes on"),
        crate::recover::Outcome::RolledBack { undone: 1 },
    );
    assert!(temp_left, "the temporary file is left where it is");
    let report = report.expect("pending").expect("interrupted");
    assert!(report.blocked().next().is_none(), "{report:?}");
    let note = &report.unfinished[0].note;
    assert!(note.contains("rolls it back"), "{note}");
    let name = temp.file_name().expect("a name").to_string_lossy();
    assert!(
        note.contains(&format!(
            "its temporary file {name} cannot be removed, and is left for bx doctor"
        )),
        "{note}"
    );
    assert!(!state.journal().exists(), "and the session is resolved");
    assert_eq!(peek(&dest).expect("untouched").0, b"user\n");
    assert_eq!(
        crate::recover::recover(&state).expect("again"),
        crate::recover::Outcome::Nothing,
    );
}

#[test]
fn a_prior_conflict_poisons_the_session_before_anything_is_published() {
    // `Ledger::record` refuses a changed
    // file bx shares through a region with `PriorConflict`. The session
    // asked only after the rename, so the refusal arrived with bx's new
    // region already written over the user's edit.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".zshrc");
    let region = |body: &str| format!("user line\n# >>> bx >>>\n{body}\n# <<< bx <<<\n");
    let shared = |body: &str| Request {
        target: portable.clone(),
        dest: dest.clone(),
        content: Content::Bytes {
            bytes: region(body).into_bytes(),
            planned: fs::observe(&dest).expect("plan's observation"),
        },
        mode: Mode::DEFAULT_FILE,
        ownership: Ownership::Owned(Mechanism::Region { comment: '#' }),
    };
    plant_file(&dest, "user line\n", Mode::DEFAULT_FILE);
    let mut first = apply_session(&state, home.path());
    first.apply(shared("BX1")).expect("apply");
    first.finish().expect("finish");
    let saved = std::fs::read(state.ledger()).expect("the saved ledger");

    let edit = format!("{}more\n", region("BX1"));
    plant_file(&dest, &edit, Mode::DEFAULT_FILE);

    let mut second = apply_session(&state, home.path());
    let err = second
        .apply(shared("BX2"))
        .expect_err("a changed shared file is a conflict");
    assert!(
        matches!(err, Error::State(crate::state::Error::PriorConflict { .. })),
        "got {err}"
    );
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        edit.as_bytes(),
        "the user's edit is untouched: nothing was published",
    );
    assert!(!holds_a_temporary_file(home.path()));
    assert!(
        !state
            .restore()
            .join(ContentHash::of(edit.as_bytes()).to_hex())
            .exists(),
        "the changed bytes were not stored as a prior",
    );
    let stored = second.ledger().get(&portable).expect("the entry");
    assert_eq!(stored.written, ContentHash::of(region("BX1").as_bytes()));

    let again = second
        .apply(write_to(home.path(), ".other", "x\n", Mode::DEFAULT_FILE))
        .expect_err("poisoned");
    assert!(matches!(again, Error::Poisoned { .. }), "got {again}");
    let finished = second
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");

    // The journal is kept, like any poisoned session's, and announces no
    // write, so recovery has nothing to roll back.
    let loaded = load(&state.journal()).expect("load");
    assert!(matches!(loaded, Loaded::Unterminated(_)), "{loaded:?}");
    assert!(
        !loaded
            .records()
            .iter()
            .any(|record| matches!(record, Record::Intent(_))),
        "nothing was announced",
    );
    assert_eq!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::RolledBack { undone: 0 },
    );
    assert_eq!(std::fs::read(&dest).expect("read"), edit.as_bytes());
    assert_eq!(std::fs::read(state.ledger()).expect("the ledger"), saved);
    assert!(!state.journal().exists());
}

#[test]
fn an_edit_between_fill_and_publish_is_kept_and_recovery_rolls_nothing_back_over_it() {
    // `publish` re-checks the destination
    // and returns `fs::Error::Changed` before the rename. Inside a session
    // that poisons like any publish error, keeps the edit, and leaves
    // recovery nothing to put back over it.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

    let mut session = apply_session(&state, home.path());
    session.before_publish = Some(|dest: &Path| {
        std::fs::write(dest, "the user's edit\n").expect("an editor saves in place");
    });
    let err = session
        .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
        .expect_err("the destination changed");
    assert!(
        matches!(err, Error::Write(fs::Error::Changed { .. })),
        "got {err}"
    );
    assert!(session.ledger().get(&portable).is_none());
    let finished = session
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
    assert_eq!(std::fs::read(&dest).expect("read"), b"the user's edit\n");
    assert!(!holds_a_temporary_file(home.path()));

    // The Intent was durable before the publish was refused, so recovery
    // finds a destination holding neither recorded state. It is reported
    // and left alone, exactly as an edit after a crash is.
    let interruption = crate::recover::pending(&state)
        .expect("pending")
        .expect("interrupted");
    assert_eq!(interruption.unfinished.len(), 1);
    assert_eq!(
        interruption.unfinished[0].standing,
        crate::recover::Standing::Diverged
    );
    assert!(!interruption.unfinished[0].resolvable);
    let outcome = crate::recover::recover(&state).expect("recover");
    assert!(
        matches!(&outcome, crate::recover::Outcome::Blocked { conflicts } if conflicts.len() == 1),
        "{outcome:?}"
    );
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"the user's edit\n",
        "recovery rolled nothing back over the edit",
    );
    assert!(crate::recover::abandon(&state).expect("abandon").is_some());
    assert_eq!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::Nothing
    );
    assert_eq!(std::fs::read(&dest).expect("read"), b"the user's edit\n");
}

#[test]
fn an_edit_between_plan_and_the_sessions_stage_is_kept_poisons_and_recovery_touches_nothing() {
    // `stage` decides on the observation
    // plan compared, and a request carries it. An edit that lands after
    // plan and before the session stages is refused before anything is
    // staged, stored, announced or published.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
    // An earlier write in the same session, so recovery has one write of its
    // own to roll back and can be seen to leave `.conf` alone.
    let (_, other) = target(home.path(), ".other");
    plant_file(&other, "other before\n", Mode::DEFAULT_FILE);

    // Plan observes both destinations, then the user saves over one.
    let first = write_to(home.path(), ".other", "other after\n", Mode::DEFAULT_FILE);
    let second = write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE);
    std::fs::write(&dest, "the user's edit after plan\n").expect("an editor saves");

    let mut session = apply_session(&state, home.path());
    session
        .apply(first)
        .expect("the other destination is what plan saw");
    let err = session
        .apply(second)
        .expect_err("the destination changed since plan");
    assert!(
        matches!(err, Error::Write(fs::Error::Changed { .. })),
        "got {err}"
    );
    assert!(session.ledger().get(&portable).is_none());
    let again = session
        .apply(write_to(home.path(), ".third", "x\n", Mode::DEFAULT_FILE))
        .expect_err("the session is poisoned");
    assert!(matches!(again, Error::Poisoned { .. }), "got {again}");
    let finished = session
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"the user's edit after plan\n"
    );
    assert!(!holds_a_temporary_file(home.path()));
    assert!(!home.child(".third").exists());

    // Refused before its Intent frame: the journal names only the earlier write.
    let loaded = load(&state.journal()).expect("load");
    let named: Vec<&Portable> = loaded.intents().map(|intent| &intent.target).collect();
    assert_eq!(named.len(), 1, "{named:?}");
    assert_ne!(named[0], &portable);

    // Recovery rolls the earlier write back and touches nothing for `.conf`.
    let edited = peek(&dest);
    assert_eq!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::RolledBack { undone: 1 },
    );
    assert_eq!(peek(&other).expect("rolled back").0, b"other before\n");
    assert_eq!(peek(&dest), edited, "recovery touched nothing for the edit");
    assert!(!state.journal().exists());
}

#[test]
fn a_failed_removal_keeps_the_ledger_entry_and_poisons_the_session() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), "locked/made.conf");
    let mut first = apply_session(&state, home.path());
    first
        .apply(write_to(
            home.path(),
            "locked/made.conf",
            "made\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("apply");
    first.finish().expect("finish");

    let locked = home.child("locked");
    fs::set_mode(&locked, Mode::from_bits(0o555)).expect("make the directory read-only");
    if !permissions_refuse(&locked) {
        fs::set_mode(&locked, Mode::DEFAULT_DIR).expect("make it writable again");
        return cannot_build(
            "a_failed_removal_keeps_the_ledger_entry_and_poisons_the_session",
            WRITES_THROUGH_PERMISSIONS,
        );
    }
    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    let removed = session.apply(remove_to(
        home.path(),
        "locked/made.conf",
        vec![locked.clone()],
    ));
    let still_managed = session.ledger().get(&portable).is_some();
    let finished = session.finish();
    // Before any assertion, so the tempdir can be removed whatever happens.
    fs::set_mode(&locked, Mode::DEFAULT_DIR).expect("make it writable again");

    let err = removed.expect_err("an unlink in a read-only directory fails");
    assert!(matches!(err, Error::Io { .. }), "got {err}");
    assert!(
        still_managed,
        "a removal that did not happen does not drop the entry"
    );
    assert!(
        matches!(finished, Err(Error::Poisoned { .. })),
        "got {finished:?}"
    );
    assert!(dest.is_file());
    assert!(
        LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value
            .get(&portable)
            .is_some(),
        "the saved ledger still owns the file that is still there",
    );
}

#[test]
fn a_damaged_ledger_that_cannot_be_moved_aside_stops_a_session_before_its_journal() {
    // `Ledger::open` refuses a damaged ledger it cannot move aside with
    // `state::Error::CannotQuarantine` instead of resetting it. A session
    // opened over one must stop there, before its journal exists, so no
    // later save can write over the bytes.
    let home = guarded_home();
    let state = state_beyond_set_aside_names(&home);
    state.ensure().expect("ensure");
    std::fs::write(state.ledger(), b"not a ledger").expect("damage the ledger");

    let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new());
    assert!(
        matches!(
            &opened,
            Err(Error::State(crate::state::Error::CannotQuarantine {
                path,
                damage: crate::state::Damage::Malformed,
                source,
            })) if *path == state.ledger()
                && source.raw_os_error()
                    == Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
        ),
        "got {opened:?}"
    );
    assert_eq!(
        std::fs::read(state.ledger()).expect("kept"),
        b"not a ledger",
        "the damaged ledger's bytes are unchanged"
    );
    assert_eq!(
        names_in(state.root()),
        ["ledger.mpk", "lock", "restore", "shell"],
        "no journal, no set-aside and no saved ledger"
    );
    assert!(
        ExclusiveLock::try_acquire(&state).expect("try").is_some(),
        "the refused session released the lock"
    );
}

#[test]
fn an_edit_between_a_removals_intent_and_its_unlink_is_kept_and_recovery_touches_nothing() {
    // A `remove` that observed, made the snapshot and the Intent durable,
    // and unlinked with no second look would destroy an editor's save in
    // that window (18 of 300 racing runs did).
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    let mut first = apply_session(&state, home.path());
    first
        .apply(write_to(
            home.path(),
            ".conf",
            "bx created\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("apply");
    first.finish().expect("finish");

    let planned = fs::observe(&dest).expect("plan's observation");
    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    session.before_unlink = Some(|dest: &Path| {
        // An editor's save: a sibling renamed over the file.
        let sibling = dest.with_file_name(".conf.edit~");
        std::fs::write(&sibling, "the user's edit\n").expect("write the sibling");
        std::fs::rename(&sibling, dest).expect("rename it over");
    });
    let err = session
        .apply(Request {
            target: portable.clone(),
            dest: dest.clone(),
            content: Content::Absent {
                created_dirs: Vec::new(),
                planned,
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
        .expect_err("the destination changed after the Intent");
    assert!(
        matches!(err, Error::Write(fs::Error::Changed { .. })),
        "got {err}"
    );
    assert!(
        session.ledger().get(&portable).is_some(),
        "nothing was removed, so nothing is forgotten",
    );
    let finished = session
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
    assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's edit\n");

    let interruption = crate::recover::pending(&state)
        .expect("pending")
        .expect("interrupted");
    assert_eq!(interruption.unfinished.len(), 1);
    assert_eq!(
        interruption.unfinished[0].standing,
        crate::recover::Standing::Diverged
    );
    let outcome = crate::recover::recover(&state).expect("recover");
    assert!(
        matches!(&outcome, crate::recover::Outcome::Blocked { conflicts } if conflicts.len() == 1),
        "{outcome:?}"
    );
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"the user's edit\n",
        "recovery rolled nothing back over the edit",
    );
    assert!(crate::recover::abandon(&state).expect("abandon").is_some());
    assert_eq!(std::fs::read(&dest).expect("read"), b"the user's edit\n");
}

#[test]
fn a_ledger_that_refuses_after_a_publish_poisons_the_session_and_is_rolled_back() {
    // The sharpest of `Session::write`'s error paths past
    // the point of no return: the destination is published, the Intent is
    // durable, no `Done` follows, and the ledger refuses. Recovery must
    // roll a landed write back from a journal with no `Done`, and the
    // ledger must hold nothing for the target.
    // `Ledger::record` checks the lock file it was opened under and
    // `check_record` does not, so replacing the lock file mid-session fails
    // exactly the call after the publish.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);

    let mut session = apply_session(&state, home.path());
    std::fs::rename(state.lock(), home.child("moved-lock")).expect("an outside mv of the lock");
    let second = ExclusiveLock::acquire(&state).expect("a second writer takes the new lock");

    let err = session
        .apply(write_to(home.path(), ".conf", "bx\n", Mode::DEFAULT_FILE))
        .expect_err("the ledger refuses after the publish");
    assert!(
        matches!(err, Error::State(crate::state::Error::WrongLock { .. })),
        "got {err}"
    );
    assert_eq!(
        peek(&dest).expect("published").0,
        b"bx\n",
        "the write landed before the ledger refused",
    );
    let finished = session
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
    drop(second);

    let loaded = load(&state.journal()).expect("load");
    assert_eq!(loaded.intents().count(), 1, "the Intent is durable");
    assert!(
        !matches!(loaded, Loaded::Terminated(_)),
        "and no End followed it",
    );
    assert!(
        !frame_starts(&std::fs::read(state.journal()).expect("read")).is_empty(),
        "the journal holds whole frames",
    );

    let outcome = crate::recover::recover(&state).expect("the next writing run");
    assert!(
        matches!(outcome, crate::recover::Outcome::RolledBack { undone: 1 }),
        "{outcome:?}"
    );
    assert_eq!(
        peek(&dest).expect("rolled back").0,
        b"theirs\n",
        "the landed write was undone",
    );
    assert!(
        saved_ledger(&state, home.path()).get(&portable).is_none(),
        "and the ledger holds nothing for the target",
    );
}
