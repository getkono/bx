//! Requests whose mechanism is a directory or a link rather than a file.

use super::*;

#[test]
fn a_directory_request_creates_the_directory_and_records_the_parents_it_invented() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());

    applied(
        &state,
        home.path(),
        vec![dir_to(home.path(), ".a/b", Mode::PRIVATE_DIR)],
    );

    assert_eq!(mode_at(&home.child(".a/b")), Some(Mode::PRIVATE_DIR));
    assert_eq!(mode_at(&home.child(".a")), Some(Mode::DEFAULT_DIR));
    let ledger = LedgerView::read(&state, home.path()).expect("ledger").value;
    let entry = ledger
        .get(&target(home.path(), ".a/b").0)
        .expect("the directory is recorded");
    assert_eq!(entry.mechanism, Mechanism::Dir);
    assert_eq!(entry.written, dir_digest());
    assert_eq!(entry.mode, Mode::PRIVATE_DIR);
    assert_eq!(entry.prior, Prior::Absent);
    assert_eq!(
        entry
            .created_dirs
            .iter()
            .map(Portable::as_str)
            .collect::<Vec<_>>(),
        ["~/.a"],
        "the parent it invented, and never the directory itself",
    );
}

#[test]
fn a_directory_request_narrows_an_existing_directory_and_records_the_mode_it_had() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir(home.child(".d")).expect("the user's directory");
    home.write(".d/theirs", "kept\n");
    fs::set_mode(&home.child(".d"), Mode::DEFAULT_DIR).expect("chmod");

    applied(
        &state,
        home.path(),
        vec![dir_to(home.path(), ".d", Mode::PRIVATE_DIR)],
    );

    assert_eq!(mode_at(&home.child(".d")), Some(Mode::PRIVATE_DIR));
    assert_eq!(
        std::fs::read(home.child(".d/theirs")).expect("untouched"),
        b"kept\n"
    );
    let ledger = LedgerView::read(&state, home.path()).expect("ledger").value;
    let entry = ledger.get(&target(home.path(), ".d").0).expect("recorded");
    assert_eq!(entry.prior, dir_prior(Mode::DEFAULT_DIR));
    assert!(entry.created_dirs.is_empty());
    // The prior's blob is the empty one, so every reference the ledger
    // holds still names bytes on disk.
    let Prior::Existed(reference) = &entry.prior else {
        panic!("a prior mode");
    };
    assert_eq!(
        crate::state::restore::read(&state, reference).expect("the empty blob"),
        DIR_BYTES
    );
}

#[test]
fn a_directory_changed_since_plan_poisons_the_session_with_nothing_announced() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir(home.child(".d")).expect("the directory");
    fs::set_mode(&home.child(".d"), Mode::DEFAULT_DIR).expect("chmod");
    let request = dir_to(home.path(), ".d", Mode::PRIVATE_DIR);
    fs::set_mode(&home.child(".d"), Mode::from_bits(0o711)).expect("chmod after plan");

    let mut session = apply_session(&state, home.path());
    let err = session.apply(request).expect_err("the directory moved");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { .. })),
        "{err}"
    );
    assert_eq!(mode_at(&home.child(".d")), Some(Mode::from_bits(0o711)));
    let journal = session.journal().to_path_buf();
    drop(session);
    assert_eq!(load(&journal).expect("load").intents().count(), 0);
}

#[test]
fn a_directory_request_plan_saw_as_unchanged_is_refused() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir(home.child(".d")).expect("the directory");
    fs::set_mode(&home.child(".d"), Mode::PRIVATE_DIR).expect("chmod");

    let mut session = apply_session(&state, home.path());
    let err = session
        .apply(dir_to(home.path(), ".d", Mode::PRIVATE_DIR))
        .expect_err("nothing was announced");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { detail, .. })
                if detail.contains("announced nothing")),
        "{err}"
    );
}

#[test]
fn an_interrupted_directory_create_is_rolled_back_with_the_parents_it_invented() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session = apply_session(&state, home.path());
    session
        .apply(dir_to(home.path(), ".a/b", Mode::PRIVATE_DIR))
        .expect("apply");
    drop(session);

    assert_eq!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::RolledBack { undone: 1 }
    );
    assert!(!home.child(".a").exists(), "nothing bx made is left");
    assert!(
        LedgerView::read(&state, home.path())
            .expect("ledger")
            .value
            .is_empty()
    );
}

#[test]
fn an_interrupted_directory_create_leaves_a_directory_that_now_holds_something() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session = apply_session(&state, home.path());
    session
        .apply(dir_to(home.path(), ".d", Mode::PRIVATE_DIR))
        .expect("apply");
    drop(session);
    home.write(".d/theirs", "kept\n");

    assert!(crate::recover::recover(&state).expect("recover").is_clear());
    assert_eq!(
        std::fs::read(home.child(".d/theirs")).expect("kept"),
        b"kept\n"
    );
}

#[test]
fn an_interrupted_directory_mode_change_is_set_back() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir(home.child(".d")).expect("the directory");
    fs::set_mode(&home.child(".d"), Mode::DEFAULT_DIR).expect("chmod");
    let mut session = apply_session(&state, home.path());
    session
        .apply(dir_to(home.path(), ".d", Mode::PRIVATE_DIR))
        .expect("apply");
    drop(session);

    let interrupted = crate::recover::pending(&state)
        .expect("pending")
        .expect("a journal stands");
    assert_eq!(
        interrupted.unfinished[0].standing,
        crate::recover::Standing::Written
    );
    assert_eq!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::RolledBack { undone: 1 }
    );
    assert_eq!(mode_at(&home.child(".d")), Some(Mode::DEFAULT_DIR));
}

#[test]
fn a_file_where_a_directory_was_written_blocks_its_rollback() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session = apply_session(&state, home.path());
    session
        .apply(dir_to(home.path(), ".d", Mode::PRIVATE_DIR))
        .expect("apply");
    drop(session);
    std::fs::remove_dir(home.child(".d")).expect("rmdir");
    home.write(".d", "a file now\n");

    let outcome = crate::recover::recover(&state).expect("recover");
    let crate::recover::Outcome::Blocked { conflicts } = outcome else {
        panic!("a file is neither state: {outcome:?}");
    };
    assert_eq!(conflicts[0].standing, crate::recover::Standing::Foreign);
}

#[test]
fn a_terminated_directory_session_is_recorded_with_the_mode_it_displaced() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir(home.child(".d")).expect("the directory");
    fs::set_mode(&home.child(".d"), Mode::DEFAULT_DIR).expect("chmod");
    let mut session = apply_session(&state, home.path());
    session
        .apply(dir_to(home.path(), ".d", Mode::PRIVATE_DIR))
        .expect("apply");
    let journal = session.journal().to_path_buf();
    drop(session);
    seal(&journal, 1);

    assert_eq!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::Recorded { entries: 1 }
    );
    let ledger = LedgerView::read(&state, home.path()).expect("ledger").value;
    let entry = ledger.get(&target(home.path(), ".d").0).expect("recorded");
    assert_eq!(entry.mechanism, Mechanism::Dir);
    assert_eq!(entry.prior, dir_prior(Mode::DEFAULT_DIR));
    assert_eq!(mode_at(&home.child(".d")), Some(Mode::PRIVATE_DIR));
}

#[test]
fn a_link_write_is_journalled_and_recorded_under_its_text() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let request = link_to(home.path(), ".local/bin/tool", "../../src/tool");
    let portable = request.target.clone();
    let dest = request.dest.clone();

    let mut session = apply_session(&state, home.path());
    session.apply(request).expect("make the link");
    assert_eq!(
        link_at(&dest).as_deref(),
        Some(Path::new("../../src/tool")),
        "made verbatim, and dangling"
    );
    let intent = load(&state.journal())
        .expect("load")
        .intents()
        .next()
        .cloned()
        .expect("an intent");
    assert!(intent.link && !intent.dir);
    assert_eq!(intent.before, Prior::Absent);
    assert_eq!(
        intent.after,
        Written::Present {
            digest: fs::link::digest(Path::new("../../src/tool")),
            mode: Mode::LINK,
        }
    );
    // `~/.local` is there already: the state directory is under it.
    assert_eq!(intent.created_dirs, [home.child(".local/bin")]);
    session.finish().expect("finish");

    let entry = LedgerView::read(&state, home.path())
        .expect("ledger")
        .value
        .get(&portable)
        .cloned()
        .expect("recorded");
    assert_eq!(entry.mechanism, Mechanism::Link);
    assert_eq!(entry.written, fs::link::digest(Path::new("../../src/tool")));
    assert_eq!(entry.mode, Mode::LINK);
    assert_eq!(entry.prior, Prior::Absent);

    // A retarget stores the text it displaces, and keeps the first prior.
    let mut session = apply_session(&state, home.path());
    session
        .apply(link_to(home.path(), ".local/bin/tool", "/opt/tool"))
        .expect("retarget");
    let intent = load(&state.journal())
        .expect("load")
        .intents()
        .next()
        .cloned()
        .expect("an intent");
    let Prior::Existed(reference) = &intent.before else {
        panic!(
            "the earlier link is the rollback's prior: {:?}",
            intent.before
        );
    };
    assert_eq!(
        reference.digest,
        fs::link::digest(Path::new("../../src/tool"))
    );
    assert_eq!(reference.mode, Mode::LINK);
    assert_eq!(
        crate::state::restore::read(&state, reference).expect("the text is stored"),
        b"../../src/tool"
    );
    session.finish().expect("finish");
    let entry = LedgerView::read(&state, home.path())
        .expect("ledger")
        .value
        .get(&portable)
        .cloned()
        .expect("recorded");
    assert_eq!(entry.written, fs::link::digest(Path::new("/opt/tool")));
    assert_eq!(
        entry.prior,
        Prior::Absent,
        "bx made the link; rm removes it"
    );
    assert_eq!(link_at(&dest).as_deref(), Some(Path::new("/opt/tool")));
}

#[test]
fn a_link_is_never_written_over_a_file_and_a_link_removal_takes_only_a_link() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".tool");
    plant_file(&dest, "the user's\n", Mode::DEFAULT_FILE);

    let mut session = apply_session(&state, home.path());
    let err = session
        .apply(link_to(home.path(), ".tool", "x"))
        .expect_err("a file is not replaced by a link");
    assert!(
        matches!(err, Error::Write(fs::Error::NotALink { .. })),
        "{err}"
    );
    drop(session);
    assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's\n");
    crate::recover::recover(&state).expect("nothing was announced");

    let (target, dest) = target(home.path(), ".tool");
    let planned = fs::observe(&dest).expect("observe");
    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    let err = session
        .apply(Request {
            target,
            dest: dest.clone(),
            content: Content::LinkAbsent {
                created_dirs: Vec::new(),
                planned,
            },
            mode: Mode::LINK,
            ownership: Ownership::Released,
        })
        .expect_err("a file is not removed as a link");
    assert!(
        matches!(err, Error::Write(fs::Error::NotALink { .. })),
        "{err}"
    );
    drop(session);
    assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's\n");
}
