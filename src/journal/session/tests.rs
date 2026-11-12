use super::*;

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt as _;

use crate::journal::tests::{
    WRITES_THROUGH_PERMISSIONS, applied, apply_session, dir_to, frame_starts, link_at, link_to,
    mode_at, names_in, peek, permissions_refuse, plant_file, raw_journal, remove_to, saved_ledger,
    seal, state_beyond_set_aside_names, target, write_to,
};
use crate::journal::{Loaded, load};
use crate::testing::{cannot_build, guarded_home};

mod dir_and_link_requests;
mod made_directories;
mod poisoned;

#[test]
fn a_session_that_finishes_leaves_no_journal_and_a_saved_ledger() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session = apply_session(&state, home.path());
    assert!(
        state.journal().exists(),
        "the journal exists while in flight"
    );
    assert!(
        !state.ledger().exists(),
        "the ledger is not saved until the session ends",
    );

    session
        .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
        .expect("apply");
    assert_eq!(session.written(), 1);
    assert!(
        !state.ledger().exists(),
        "still not saved: a rollback must find the ledger as it was",
    );
    assert_eq!(session.finish().expect("finish"), 1);

    assert!(!state.journal().exists(), "unlinked last");
    assert_eq!(load(&state.journal()).expect("load"), Loaded::Absent);
    let ledger = LedgerView::read(&state, home.path())
        .expect("read the ledger")
        .value;
    let (portable, _) = target(home.path(), ".conf");
    assert_eq!(
        ledger.get(&portable).expect("an entry").mode,
        Mode::DEFAULT_FILE,
    );
}

#[test]
fn opening_a_session_over_an_unresolved_interruption_is_refused() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let session = apply_session(&state, home.path());
    drop(session);

    let err = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
        .expect_err("a session over an interruption must be refused");
    let Error::InProgress { path } = &err else {
        panic!("got {err}")
    };
    assert_eq!(path, &state.journal());
    assert!(err.to_string().contains("recovered"));
}

#[test]
fn a_session_holds_the_state_lock_for_its_whole_life() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let session = apply_session(&state, home.path());
    assert!(
        ExclusiveLock::try_acquire(&state).expect("try").is_none(),
        "the session holds the exclusive lock",
    );
    assert_eq!(session.state(), &state);
    assert_eq!(session.home(), home.path());
    assert_eq!(session.journal(), state.journal());
    drop(session);
    assert!(
        ExclusiveLock::try_acquire(&state).expect("try").is_some(),
        "dropping the session releases it",
    );
}

#[test]
fn two_identical_sessions_produce_journals_that_differ_only_in_temp_paths() {
    let home = guarded_home();
    let dest = home.child(".conf");

    let run = |root: &str| -> Vec<Record> {
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        let state = StateDir::new(home.child(root));
        let mut session = apply_session(&state, home.path());
        session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect("apply");
        drop(session);
        load(&state.journal()).expect("load").records().to_vec()
    };

    let mut first = run("one");
    let mut second = run("two");
    // The staged temporary file's name is random, by construction: entry A5
    // chooses it and the intent records the path it chose, so recovery can
    // remove exactly that file and nothing else. Everything else is fixed —
    // no timestamp, no identifier, no hash-map iteration order.
    for records in [&mut first, &mut second] {
        for record in records.iter_mut() {
            if let Record::Intent(intent) = record {
                let temp = intent.temp.take().expect("a write stages a temp file");
                assert!(
                    temp.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(fs::TEMP_PREFIX)),
                    "{} should be an attributable bx temporary file",
                    temp.display(),
                );
                assert_eq!(
                    temp.parent(),
                    dest.parent(),
                    "staged beside the destination"
                );
            }
        }
    }
    assert_eq!(first, second);
}

#[test]
fn a_write_records_the_prior_bytes_and_the_created_directories() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

    let mut session = apply_session(&state, home.path());
    session
        .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
        .expect("apply");
    session
        .apply(write_to(
            home.path(),
            ".config/deep/new.conf",
            "made\n",
            Mode::PRIVATE_FILE,
        ))
        .expect("apply");
    drop(session);

    let loaded = load(&state.journal()).expect("load");
    let intents: Vec<&Intent> = loaded.intents().collect();
    assert_eq!(intents.len(), 2);

    assert!(!intents[0].creates());
    let Prior::Existed(reference) = &intents[0].before else {
        panic!("the first write displaced a file")
    };
    assert_eq!(reference.digest, ContentHash::of(b"old\n"));
    assert_eq!(reference.mode, Mode::DEFAULT_FILE);
    assert_eq!(
        intents[0].after,
        Written::Present {
            digest: ContentHash::of(b"new\n"),
            mode: Mode::DEFAULT_FILE,
        },
    );
    assert!(intents[0].created_dirs.is_empty());
    assert_eq!(intents[0].mechanism, Some(Mechanism::Own));

    assert!(intents[1].creates());
    assert_eq!(
        intents[1].created_dirs,
        vec![home.child(".config/deep"), home.child(".config")],
        "deepest first, which is the order a reversal removes them in",
    );
    // The prior bytes are durable in `restore/` before the rename, so the
    // rollback a crash needs can always complete.
    assert!(
        state.restore().join(reference.digest.to_hex()).is_file(),
        "the displaced bytes are content-addressed in restore/",
    );
}

#[test]
fn a_repeat_write_records_the_bytes_it_displaced_not_the_ledgers_first_prior() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".conf"), "the user's\n", Mode::DEFAULT_FILE);
    let (portable, _) = target(home.path(), ".conf");

    let mut first = apply_session(&state, home.path());
    first
        .apply(write_to(home.path(), ".conf", "one\n", Mode::DEFAULT_FILE))
        .expect("apply");
    first.finish().expect("finish");

    let mut second = apply_session(&state, home.path());
    second
        .apply(write_to(home.path(), ".conf", "two\n", Mode::DEFAULT_FILE))
        .expect("apply");
    drop(second);

    // The ledger answers "what did the user have before bx?" and keeps the
    // first prior. The journal answers "what was on disk a moment ago?" and
    // must not, or a rollback would compare the destination against a state
    // it has not been in since the first apply.
    let entry = LedgerView::read(&state, home.path())
        .expect("read")
        .value
        .get(&portable)
        .cloned()
        .expect("managed");
    let Prior::Existed(first_prior) = &entry.prior else {
        panic!("the ledger keeps the user's original")
    };
    assert_eq!(first_prior.digest, ContentHash::of(b"the user's\n"));

    let loaded = load(&state.journal()).expect("load");
    let Prior::Existed(displaced) = &loaded.intents().next().expect("one intent").before else {
        panic!("the second write displaced a file")
    };
    assert_eq!(
        displaced.digest,
        ContentHash::of(b"one\n"),
        "the rollback snapshot is bx's own previous output",
    );
    assert!(
        state.restore().join(displaced.blob_name()).is_file(),
        "and it is durable, whatever the ledger decided to keep",
    );
}

#[test]
fn a_released_target_leaves_its_prior_bytes_behind_but_no_ledger_entry() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".conf"), "mine\n", Mode::DEFAULT_FILE);
    let (portable, dest) = target(home.path(), ".conf");

    let mut session = apply_session(&state, home.path());
    session
        .apply(Request {
            target: portable.clone(),
            content: Content::Bytes {
                bytes: b"yours\n".to_vec(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            dest,
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
        .expect("apply");
    assert!(session.ledger().get(&portable).is_none());
    session.finish().expect("finish");

    assert!(
        LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value
            .get(&portable)
            .is_none()
    );
    assert!(
        state
            .restore()
            .join(ContentHash::of(b"mine\n").to_hex())
            .is_file(),
        "the bytes an interrupted release would be rolled back to are durable",
    );
}

#[test]
fn a_removal_takes_the_file_and_the_directories_bx_created() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".config/deep/made.conf");
    plant_file(&dest, "bx wrote this\n", Mode::DEFAULT_FILE);

    let mut session = apply_session(&state, home.path());
    session
        .apply(remove_to(
            home.path(),
            ".config/deep/made.conf",
            vec![home.child(".config/deep"), home.child(".config")],
        ))
        .expect("apply");
    session.finish().expect("finish");

    assert!(!dest.exists(), "removed, not truncated");
    assert!(!home.child(".config/deep").exists());
    assert!(!home.child(".config").exists());
    assert!(
        state
            .restore()
            .join(ContentHash::of(b"bx wrote this\n").to_hex())
            .is_file(),
    );
}

#[test]
fn removing_a_destination_that_is_already_gone_is_not_an_error() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session = apply_session(&state, home.path());
    session
        .apply(remove_to(home.path(), ".never-there", Vec::new()))
        .expect("apply");
    drop(session);

    let loaded = load(&state.journal()).expect("load");
    let intents: Vec<&Intent> = loaded.intents().collect();
    assert_eq!(intents[0].before, Prior::Absent);
    assert_eq!(intents[0].after, Written::Absent);
}

#[test]
fn a_session_will_not_write_through_a_symlink_the_user_made() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child("real"), "real\n", Mode::DEFAULT_FILE);
    std::os::unix::fs::symlink(home.child("real"), home.child(".conf")).expect("symlink");

    let mut session = apply_session(&state, home.path());
    let err = session
        .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
        .expect_err("a symlink must be refused");
    assert!(
        matches!(err, Error::Write(fs::Error::Symlink(_))),
        "got {err}",
    );

    // A refused write poisons its session, so the removal is refused in a
    // session of its own.
    let other = StateDir::new(home.child("other-state"));
    let mut session = apply_session(&other, home.path());
    let err = session
        .apply(remove_to(home.path(), ".conf", Vec::new()))
        .expect_err("and so must a removal of one");
    assert!(
        matches!(err, Error::Write(fs::Error::NotAFile { .. })),
        "got {err}",
    );
}

#[test]
fn the_intent_is_synced_before_the_destination_is_renamed_over() {
    // The whole ordering rule, observed rather than asserted: the frame that
    // announces a write is durable before the rename makes the write, and
    // the frame that says it landed comes after.
    use crate::fs::durable::{Event, recording};

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
    let journal = state.journal();

    let mut session = apply_session(&state, home.path());
    let (applied, events) =
        recording(|| session.apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)));
    applied.expect("apply");
    session.finish().expect("finish");

    let journal_syncs: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event, Event::SyncFile(path) if *path == journal))
        .map(|(at, _)| at)
        .collect();
    let rename = events
        .iter()
        .position(|event| matches!(event, Event::Rename { to, .. } if *to == dest))
        .expect("the destination is renamed over");
    assert_eq!(
        journal_syncs.len(),
        2,
        "the Intent and the Done frames are each synced: {events:#?}",
    );
    assert!(
        journal_syncs[0] < rename,
        "the Intent is durable before the rename: {events:#?}",
    );
    assert!(
        journal_syncs[1] > rename,
        "the Done frame follows the rename: {events:#?}",
    );
}

#[test]
fn the_intent_is_synced_before_a_removal_unlinks_the_destination() {
    use crate::fs::durable::{Event, recording};

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let rel = ".config/made/x.conf";
    let dest = home.child(rel);
    let journal = state.journal();

    applied(
        &state,
        home.path(),
        vec![write_to(home.path(), rel, "x\n", Mode::DEFAULT_FILE)],
    );

    let mut second =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    let (removed, events) = recording(|| {
        second.apply(remove_to(
            home.path(),
            rel,
            vec![home.child(".config/made"), home.child(".config")],
        ))
    });
    removed.expect("remove");
    second.finish().expect("finish");

    let intent_sync = events
        .iter()
        .position(|event| matches!(event, Event::SyncFile(path) if *path == journal))
        .expect("the Intent frame is synced");
    let unlink = events
        .iter()
        .position(|event| matches!(event, Event::Unlink(path) if *path == dest))
        .expect("the destination is unlinked");
    let parent_sync = events
        .iter()
        .position(
            |event| matches!(event, Event::SyncDir(dir) if *dir == home.child(".config/made")),
        )
        .expect("the unlink is made durable");
    assert!(
        intent_sync < unlink,
        "the Intent is durable before the unlink: {events:#?}",
    );
    assert!(
        unlink < parent_sync,
        "the directory is synced after the unlink: {events:#?}",
    );
    assert!(!dest.exists());
}

#[test]
fn a_request_whose_destination_is_not_where_its_target_renders_is_refused() {
    // The loader refuses such a journal, so a
    // session that wrote one would leave an interruption nothing recovers.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut request = write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE);
    request.dest = home.child(".elsewhere");

    let mut session = apply_session(&state, home.path());
    let refused = session.apply(request).expect_err("refused");
    assert!(matches!(refused, Error::Misplaced { .. }), "got {refused}");
    assert!(!home.child(".elsewhere").exists());
    assert!(!home.child(".conf").exists());
    assert!(matches!(
        session.apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)),
        Err(Error::Poisoned { .. }),
    ));
    drop(session);
    assert_eq!(
        load(&state.journal()).expect("load").intents().count(),
        0,
        "nothing was journalled",
    );
}

/// Whether anything under `dir` is a writer's temporary file.
fn holds_a_temporary_file(dir: &Path) -> bool {
    std::fs::read_dir(dir).expect("list").any(|entry| {
        entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .starts_with(fs::TEMP_PREFIX)
    })
}

#[test]
fn a_session_keeps_one_set_of_the_directories_its_writes_created() {
    // A directory target applied after a
    // write beneath it is the `Create` plan announced only when both were
    // given one `fs::CreatedDirs`. The session holds that set for its life.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session = apply_session(&state, home.path());
    session
        .apply(write_to(
            home.path(),
            ".config/one/a.conf",
            "a\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("the first write");
    session
        .apply(write_to(
            home.path(),
            ".config/two/b.conf",
            "b\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("the second write");
    for dir in [".config", ".config/one", ".config/two"] {
        assert!(
            session.created.contains(&home.child(dir)),
            "{dir} is in the session's set"
        );
    }
    session.finish().expect("finish");
}

#[test]
fn a_scope_entry_the_loader_would_refuse_is_refused_before_the_journal_exists() {
    // `refusal` puts every `Begin.scope` entry through
    // `check_against(home)` and refuses the *whole* journal when one
    // fails, so a session that wrote one could never be rolled back: the
    // next load reads `Unreadable`, `recover::resolve` returns `Nothing`,
    // and half-applied writes survive with nothing undone. `restore`
    // forwards its caller's target list verbatim as the scope, and
    // `Portable::try_from` accepts `/<home>/.gitconfig`, so the caller
    // needed no mistake beyond spelling a target absolutely.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let absolute = Portable::try_from(
        home.child(".gitconfig")
            .to_str()
            .expect("utf-8")
            .to_string(),
    )
    .expect("a well-formed absolute path");
    assert!(
        absolute.check_against(home.path()).is_err(),
        "the fixture is a scope entry the loader refuses",
    );

    let err = Session::open(
        &state,
        SessionKind::Apply,
        home.path(),
        vec![target(home.path(), ".vimrc").0, absolute.clone()],
    )
    .expect_err("a scope entry the loader refuses");
    assert!(
        matches!(err, Error::State(crate::state::Error::ForeignRecord { .. })),
        "got {err}"
    );
    assert!(
        !state.journal().exists(),
        "and no journal was written for it to refuse",
    );

    // The same scope, written past the refusal, is what the refusal buys:
    // the loader disbelieves the whole file, so nothing in it is undone.
    let mut session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
        .expect("a well-formed scope opens");
    session
        .apply(write_to(home.path(), ".vimrc", "bx\n", Mode::DEFAULT_FILE))
        .expect("apply");
    let path = state.journal();
    let believed = std::fs::read(&path).expect("read");
    drop(session);
    assert!(
        matches!(
            load(&path).expect("load"),
            Loaded::Unterminated(_) | Loaded::Torn { .. }
        ),
        "the well-formed session's journal is believed",
    );
    raw_journal(
        &path,
        &[
            Record::Begin(Begin {
                kind: SessionKind::Apply,
                home: home.path().to_path_buf(),
                scope: vec![absolute],
            }),
            Record::Intent(Intent {
                target: target(home.path(), ".vimrc").0,
                dest: home.child(".vimrc"),
                temp: None,
                before: Prior::Absent,
                after: Written::Absent,
                created_dirs: Vec::new(),
                mechanism: None,
                ledger_written: None,
                dir: false,
                link: false,
            }),
        ],
    );
    assert!(
        matches!(load(&path).expect("load"), Loaded::Unreadable { .. }),
        "one unportable scope entry makes the whole journal unreadable",
    );
    assert_ne!(believed, std::fs::read(&path).expect("read"));
}

/// The directory the umask child does its two writes under.
const UMASK_CHILD_DIR: &str = "BX_TEST_UMASK_DIR";

#[test]
#[ignore = "spawned by a_directory_bx_will_not_remove_is_made_at_the_accounts_umask"]
fn umask_child() {
    // Not spawned by its parent: no instructions, nothing to do.
    let Some(under) = std::env::var_os(UMASK_CHILD_DIR) else {
        return;
    };
    let under = PathBuf::from(under);
    let mode = |path: &Path| {
        Mode::from_bits(std::os::unix::fs::PermissionsExt::mode(
            &std::fs::symlink_metadata(path).expect("stat").permissions(),
        ))
    };
    // `umask 077` is what the parent's shell set, so a directory made
    // under it and never chmod'd is 0o777 & !0o077.
    let shared = Mode::from_bits(0o700);

    // In the home: `~` itself is the directory bx must make and will not
    // remove. The two under it are bx's own, and keep bx's own mode.
    let home = under.join("in-home/home");
    let state = StateDir::resolve_in(&home, Some(under.join("in-home/state").as_os_str()));
    let mut session = apply_session(&state, &home);
    session
        .apply(write_to(
            &home,
            ".config/app/x.conf",
            "bx\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("apply");
    session.finish().expect("finish");
    assert_eq!(mode(&home), shared, "the home was made past the umask");
    for rel in [".config", ".config/app"] {
        assert_eq!(
            mode(&home.join(rel)),
            Mode::DEFAULT_DIR,
            "{rel} is bx's own"
        );
    }
    assert_eq!(
        entry_created_dirs(&state, &home, &target(&home, ".config/app/x.conf").0),
        vec![home.join(".config/app"), home.join(".config")],
        "bx claims what it made for its own target, and nothing above it",
    );

    // Beside the home: the directory bx must make is *above* the home,
    // and the home itself is never made, because nothing needs it.
    let beside_home = under.join("beside/home");
    let beside_state =
        StateDir::resolve_in(&beside_home, Some(under.join("beside-state").as_os_str()));
    let dest = under.join("beside/x.conf");
    let portable = Portable::try_from(dest.to_str().expect("utf-8").to_string())
        .expect("a well-formed absolute path");
    let mut session = apply_session(&beside_state, &beside_home);
    session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"bx\n".to_vec(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect("apply");
    session.finish().expect("finish");
    assert_eq!(
        mode(&under.join("beside")),
        shared,
        "a directory above the home was made past the umask",
    );
    assert!(!beside_home.exists(), "and the home itself was not made");
}

#[test]
fn a_directory_bx_will_not_remove_is_made_at_the_accounts_umask() {
    // A write whose home is missing must not create the user's own home
    // through `fs::stage`, which `chmod`s past
    // the `umask` on purpose — the right rule for a directory bx owns and
    // will remove again, and the wrong one for a directory bx neither
    // claims nor ever removes. `crate::state::dir::ensure_dir` already
    // documents the opposite rule for exactly this category of directory,
    // and bx's two ancestor-making paths must agree.
    //
    // `umask(2)` is process-global and this suite runs in parallel, so the
    // umask is set for a child rather than here: `sh -c 'umask 077; exec …'`,
    // which needs no `unsafe` and no shared lock.
    let guard = guarded_home();
    let exe = std::env::current_exe().expect("the test binary");
    crate::testing::run_ignored_child(
        std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"umask 077; exec "$1" --exact --ignored journal::session::tests::umask_child"#)
            .arg("sh")
            .arg(&exe)
            .env(UMASK_CHILD_DIR, guard.child("under")),
    );
}

/// What the saved ledger says `portable` claims, rendered.
fn entry_created_dirs(state: &StateDir, home: &Path, portable: &Portable) -> Vec<PathBuf> {
    crate::state::LedgerView::read(state, home)
        .expect("read the ledger")
        .value
        .get(portable)
        .map(|entry| {
            entry
                .created_dirs
                .iter()
                .map(|dir| dir.render(home))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_target_spelled_absolutely_under_the_home_is_refused_before_anything_is_touched() {
    // A caller holding a `Ledger` gets
    // its home check. `Session::admit` puts the target, spelled as the
    // request spells it, through the same `check_against` that
    // `Ledger::check_record` applies, before anything is observed, so a
    // target spelled `/<home>/…` is refused as `ForeignRecord`. That
    // target renders to itself and used to be admitted:
    // the ledger keyed it `~/.conf`, the same file under that spelling got
    // past `Repeated`, and a crash left a journal the loader refuses.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
    let absolute = Portable::try_from(dest.to_str().expect("utf-8").to_string())
        .expect("a well-formed absolute path");

    let mut session = apply_session(&state, home.path());
    let err = session
        .apply(Request {
            target: absolute,
            content: Content::Bytes {
                bytes: b"new\n".to_vec(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            dest: dest.clone(),
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect_err("the ledger's home check refuses the target");
    assert!(
        matches!(err, Error::State(crate::state::Error::ForeignRecord { .. })),
        "got {err}"
    );
    let again = session
        .apply(write_to(
            home.path(),
            ".conf",
            "again\n",
            Mode::DEFAULT_FILE,
        ))
        .expect_err("the session is poisoned");
    assert!(matches!(again, Error::Poisoned { .. }), "got {again}");
    let finished = session
        .finish()
        .expect_err("a poisoned session cannot finish");
    assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
    assert_eq!(peek(&dest).expect("untouched").0, b"old\n");
    assert!(!holds_a_temporary_file(home.path()));

    // Nothing was announced, so what the session leaves is a journal bx believes.
    let loaded = load(&state.journal()).expect("load");
    assert!(!matches!(loaded, Loaded::Unreadable { .. }), "{loaded:?}");
    assert_eq!(loaded.intents().count(), 0);
}

#[test]
fn a_hard_linked_decoy_at_a_blob_name_is_replaced_before_an_intent_names_it() {
    // A same-length file at
    // `restore/<digest>` that is a second hard link is not a blob bx wrote,
    // and the ledger's store stopped trusting one. The journal's own copy of
    // the length check still did, so an Intent named a blob holding the
    // decoy's bytes and the rollback could not put the original back. A
    // removal records nothing in the ledger, so only that copy runs here.
    use std::os::unix::fs::MetadataExt as _;

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    state.ensure().expect("ensure");
    let dest = home.child(".conf");
    plant_file(&dest, "the original\n", Mode::DEFAULT_FILE);
    let decoy = home.child("decoy");
    std::fs::write(&decoy, "ZZZZZZZZZZZZ\n").expect("a decoy of the same length");
    let blob = state
        .restore()
        .join(ContentHash::of(b"the original\n").to_hex());
    std::fs::hard_link(&decoy, &blob).expect("a second link at the blob name");

    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    session
        .apply(remove_to(home.path(), ".conf", Vec::new()))
        .expect("remove");
    drop(session);
    assert!(peek(&dest).is_none());

    let meta = std::fs::symlink_metadata(&blob).expect("stat");
    assert!(meta.file_type().is_file());
    assert_eq!(meta.nlink(), 1, "the decoy link was replaced, not trusted");
    assert_eq!(std::fs::read(&blob).expect("read"), b"the original\n");
    assert_eq!(
        std::fs::read(&decoy).expect("read"),
        b"ZZZZZZZZZZZZ\n",
        "and not written through",
    );

    assert_eq!(
        crate::recover::recover(&state).expect("recover"),
        crate::recover::Outcome::RolledBack { undone: 1 },
    );
    assert_eq!(
        peek(&dest),
        Some((b"the original\n".to_vec(), Mode::DEFAULT_FILE))
    );
}

#[test]
fn a_removal_names_how_its_destination_moved_since_plan() {
    // The third detail and the `planned.path != now.path` branch each need
    // a case of their own. That branch is
    // the one that stops a removal running against an observation of a
    // different file.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (gone, gone_dest) = target(home.path(), ".gone");
    plant_file(&gone_dest, "bx created\n", Mode::DEFAULT_FILE);
    let was_there = fs::observe(&gone_dest).expect("plan's observation");
    std::fs::remove_file(&gone_dest).expect("the user removes it");
    let (appeared, appeared_dest) = target(home.path(), ".appeared");
    let nothing = fs::observe(&appeared_dest).expect("plan's observation");
    plant_file(&appeared_dest, "the user's\n", Mode::DEFAULT_FILE);
    let (edited, edited_dest) = target(home.path(), ".edited");
    plant_file(&edited_dest, "bx created\n", Mode::DEFAULT_FILE);
    let as_written = fs::observe(&edited_dest).expect("plan's observation");
    plant_file(&edited_dest, "the user's edit\n", Mode::DEFAULT_FILE);
    // An observation of another file entirely, handed to a removal of
    // this one: the same shape a caller pairing the wrong plan with the
    // wrong target would produce.
    let (_elsewhere, elsewhere_dest) = target(home.path(), ".elsewhere");
    plant_file(&elsewhere_dest, "somebody else's\n", Mode::DEFAULT_FILE);
    let (mixed_up, mixed_up_dest) = target(home.path(), ".mixed-up");
    plant_file(&mixed_up_dest, "bx created\n", Mode::DEFAULT_FILE);
    let another_file = fs::observe(&elsewhere_dest).expect("plan's observation");
    let wrong_path = format!("plan observed {}, not this path", elsewhere_dest.display());

    for (portable, dest, planned, detail) in [
        (gone, gone_dest, was_there, "it has been removed"),
        (
            appeared,
            appeared_dest.clone(),
            nothing,
            "nothing was there, and something is now",
        ),
        (
            edited,
            edited_dest.clone(),
            as_written,
            "it has been modified or replaced",
        ),
        (
            mixed_up,
            mixed_up_dest.clone(),
            another_file,
            wrong_path.as_str(),
        ),
    ] {
        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
        let err = session
            .apply(Request {
                target: portable,
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: Vec::new(),
                    planned,
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect_err(detail);
        assert!(
            matches!(&err, Error::Write(fs::Error::Changed { path, detail: said }) if *path == dest && said.as_str() == detail),
            "got {err}"
        );
        drop(session);
        assert_eq!(
            load(&state.journal()).expect("load").intents().count(),
            0,
            "{detail}: refused before its Intent"
        );
        crate::recover::recover(&state).expect("clear the refused session");
    }
    assert_eq!(peek(&appeared_dest).expect("kept").0, b"the user's\n");
    assert_eq!(peek(&edited_dest).expect("kept").0, b"the user's edit\n");
    assert_eq!(peek(&mixed_up_dest).expect("kept").0, b"bx created\n");
    assert_eq!(
        peek(&elsewhere_dest).expect("kept").0,
        b"somebody else's\n",
        "and the file the wrong observation named is untouched",
    );
}

#[test]
fn a_directory_that_cannot_be_removed_for_another_reason_is_an_error() {
    // Only a directory that is gone or not empty is left quietly; any other
    // `rmdir` failure is returned.
    let dir = tempfile::tempdir().expect("a tempdir");
    let parent = dir.path().join("locked");
    let child = parent.join("made");
    std::fs::create_dir_all(&child).expect("create");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    if !permissions_refuse(&parent) {
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("chmod back");
        return cannot_build(
            "a_directory_that_cannot_be_removed_for_another_reason_is_an_error",
            WRITES_THROUGH_PERMISSIONS,
        );
    }
    let err = prune_dirs(std::slice::from_ref(&child)).map_err(Error::from);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).expect("chmod back");
    let err = err.expect_err("neither gone nor not empty");
    assert!(matches!(err, Error::Io { .. }), "got {err}");
    assert!(child.is_dir());
}

#[test]
fn a_claimed_directory_that_is_no_longer_a_directory_is_left_and_the_walk_goes_on() {
    // `rmdir` on a symlink or a file is ENOTDIR. Treated as an error, `rm`
    // would unlink the file through the link and then fail, and a rollback
    // would fail the same way on every run.
    let dir = tempfile::tempdir().expect("a tempdir");

    // A claimed directory the user replaced with a link to an empty one.
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("the real directory");
    let link = dir.path().join("d");
    std::os::unix::fs::symlink(&real, &link).expect("the link");
    prune_dirs(std::slice::from_ref(&link)).expect("a link is not bx's directory");
    LedgerView::default()
        .prune_claims(dir.path(), std::slice::from_ref(&link))
        .expect("nor is it a claim to remove");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("the link stays")
            .file_type()
            .is_symlink()
    );
    assert!(real.is_dir(), "and so does the directory it names");

    // A claimed ancestor replaced by a regular file: the claim beneath it
    // cannot be a directory either.
    let file = dir.path().join("a");
    std::fs::write(&file, "the user's\n").expect("a file where a directory was");
    let claims = [file.join("b"), file.clone()];
    prune_dirs(&claims).expect("prune");
    LedgerView::default()
        .prune_claims(dir.path(), &claims)
        .expect("prune the claims");
    assert_eq!(std::fs::read(&file).expect("kept"), b"the user's\n");
}

#[test]
fn a_removal_naming_a_directory_that_is_not_its_parent_is_refused_before_anything_is_touched() {
    // A session that checked a removal's destination but not its created
    // directories would prune an empty directory of the user's and write an
    // Intent the loader refuses: the journal would then be set aside, and
    // the removed file never put back.
    let guard = guarded_home();
    for case in [
        "an unrelated directory",
        "the home",
        "the destination itself",
        "a directory above the home",
    ] {
        let home = guard.child(case.replace(' ', "-"));
        std::fs::create_dir_all(&home).expect("the home");
        let state = StateDir::resolve(&home);
        let (portable, dest) = target(&home, ".conf");
        let mut first = apply_session(&state, &home);
        first
            .apply(write_to(&home, ".conf", "bx created\n", Mode::DEFAULT_FILE))
            .expect("apply");
        first.finish().expect("finish");
        let users = home.join("projects/empty");
        std::fs::create_dir_all(&users).expect("the user's empty directory");
        let stray = match case {
            "an unrelated directory" => users.clone(),
            "the home" => home.clone(),
            "the destination itself" => dest.clone(),
            _ => guard.path().to_path_buf(),
        };

        let mut session =
            Session::open(&state, SessionKind::Restore, &home, Vec::new()).expect("open");
        let err = session
            .apply(remove_to(&home, ".conf", vec![stray.clone()]))
            .expect_err(case);
        assert!(
            matches!(&err, Error::StrayCreatedDir { target, dir } if *target == portable && *dir == stray),
            "{case}: got {err}"
        );
        assert!(users.is_dir(), "{case}: the user's directory stays");
        assert_eq!(peek(&dest).expect("untouched").0, b"bx created\n", "{case}");
        let again = session
            .apply(write_to(&home, ".other", "x\n", Mode::DEFAULT_FILE))
            .expect_err("the session is poisoned");
        assert!(
            matches!(again, Error::Poisoned { .. }),
            "{case}: got {again}"
        );
        drop(session);

        let loaded = load(&state.journal()).expect("load");
        assert!(
            !matches!(loaded, Loaded::Unreadable { .. }),
            "{case}: {loaded:?}"
        );
        assert_eq!(loaded.intents().count(), 0, "{case}: nothing was announced");
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::RolledBack { undone: 0 },
            "{case}"
        );
        assert!(
            LedgerView::read(&state, &home)
                .expect("read the ledger")
                .value
                .get(&portable)
                .is_some(),
            "{case}: bx still manages the file"
        );
    }
}

#[test]
fn a_claim_that_cannot_be_made_portable_is_an_error_not_dropped() {
    // No admitted removal and no believed journal reaches this: every claim
    // is a parent of a destination rendered under an absolute UTF-8 home,
    // which the session checks, and every forgotten claim is a stored
    // `Portable` rendered under it. Pinned at the function, with a home
    // `Portable::from_path` refuses, so a claim is never silently lost.
    use std::os::unix::ffi::OsStrExt as _;

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    state.ensure().expect("ensure");
    let outside = tempfile::tempdir().expect("a directory outside the home");
    let dir = outside.path().join("made");
    std::fs::create_dir_all(&dir).expect("the claimed directory");
    let heir =
        Portable::from_path(&dir.join("heir.conf"), home.path()).expect("an absolute target");
    let lock = ExclusiveLock::acquire(&state).expect("lock");
    let mut ledger = Ledger::open(&state, &lock, home.path())
        .expect("open the ledger")
        .value;
    ledger
        .record(NewEntry::new(
            heir,
            ContentHash::of(b"x\n"),
            Mode::DEFAULT_FILE,
            Mechanism::Own,
            PriorBytes::Absent,
        ))
        .expect("an entry beneath the claim");
    let unusable = PathBuf::from(std::ffi::OsStr::from_bytes(b"/home/\xff"));

    let err = ledger
        .hand_off_claims(&unusable, [&dir])
        .expect_err("the claim cannot be made portable");
    assert!(
        matches!(
            &err,
            crate::state::Error::Write(fs::Error::NotPortable { path, .. }) if *path == dir
        ),
        "got {err}"
    );
}

#[test]
fn a_claim_the_heir_holds_is_not_recorded_again_and_a_refused_record_is_an_error() {
    // Both the skip for a claim the heir already holds and a `record` the
    // ledger refuses need a case to reach them. The ledger's
    // lock file is replaced, so every `record` through it is refused with
    // WrongLock: the skip is the only way the first case can succeed, and
    // the second must say so rather than drop the claim.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    state.ensure().expect("ensure");
    let dir = home.child(".config/app");
    std::fs::create_dir_all(&dir).expect("the claimed directory");
    let claim = Portable::from_path(&dir, home.path()).expect("portable");
    let heir = Portable::from_path(&dir.join("a.toml"), home.path()).expect("portable");
    for holds in [true, false] {
        let case = format!("the heir already holds the claim: {holds}");
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let mut ledger = Ledger::open(&state, &lock, home.path())
            .expect("open the ledger")
            .value;
        ledger
            .record(
                NewEntry::new(
                    heir.clone(),
                    ContentHash::of(b"x\n"),
                    Mode::DEFAULT_FILE,
                    Mechanism::Own,
                    PriorBytes::Absent,
                )
                .with_created_dirs(if holds {
                    vec![claim.clone()]
                } else {
                    Vec::new()
                }),
            )
            .expect("the heir");
        let before = ledger.get(&heir).cloned().expect("recorded");
        std::fs::rename(state.lock(), home.child(format!("moved-lock-{holds}")))
            .expect("an outside mv of the lock file");
        let second = ExclusiveLock::acquire(&state).expect("a second writer");

        let handed = ledger.hand_off_claims(home.path(), [&dir]);
        let after = ledger.get(&heir).cloned();
        drop(second);

        if holds {
            handed.expect("a claim the heir holds is not recorded again");
        } else {
            let err = handed.expect_err("a refused record is an error");
            assert!(
                matches!(err, crate::state::Error::WrongLock { .. }),
                "{case}: got {err}"
            );
        }
        assert_eq!(after, Some(before), "{case}: nothing half-recorded");
    }
}

#[test]
fn a_released_write_hands_on_the_directories_its_entry_claimed() {
    // `Session::write`'s released arm must carry on the `created_dirs` of
    // the entry `forget` returns, as `Session::remove` and
    // `Session::forget` both do. Dropped, a directory bx made would have no
    // claimant at all: no later `rm` could remove it, and recovery's
    // rebuild could not either.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dir = home.child(".config/app");
    let claims: Vec<PathBuf> = vec![dir.clone(), home.child(".config")];

    // bx makes both directories for a.conf, which claims them.
    let mut session = apply_session(&state, home.path());
    session
        .apply(write_to(
            home.path(),
            ".config/app/a.conf",
            "bx a\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("apply");
    session.finish().expect("finish");
    // An entry beneath the same directories that survives the hand-back.
    let mut session = apply_session(&state, home.path());
    session
        .apply(write_to(
            home.path(),
            ".config/app/heir.conf",
            "bx heir\n",
            Mode::DEFAULT_FILE,
        ))
        .expect("apply");
    session.finish().expect("finish");

    let (a, a_dest) = target(home.path(), ".config/app/a.conf");
    let (heir, _) = target(home.path(), ".config/app/heir.conf");
    let ledger = saved_ledger(&state, home.path());
    assert_eq!(
        ledger
            .get(&a)
            .expect("a.conf")
            .created_dirs
            .iter()
            .map(|dir| dir.render(home.path()))
            .collect::<Vec<_>>(),
        claims,
        "a.conf claims both directories bx made",
    );
    assert!(ledger.get(&heir).expect("heir").created_dirs.is_empty());
    drop(ledger);

    // `rm` hands a.conf back: the entry goes, the file stays as the
    // user's. Both claims must reach the surviving entry beneath them.
    let mut session =
        Session::open(&state, SessionKind::Restore, home.path(), vec![a.clone()]).expect("open");
    session
        .apply(Request {
            target: a.clone(),
            dest: a_dest.clone(),
            content: Content::Bytes {
                bytes: b"theirs\n".to_vec(),
                planned: fs::observe(&a_dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
        .expect("hand it back");
    session.finish().expect("finish");

    let ledger = saved_ledger(&state, home.path());
    assert!(ledger.get(&a).is_none(), "the entry was handed back");
    assert_eq!(
        ledger
            .get(&heir)
            .expect("heir")
            .created_dirs
            .iter()
            .map(|dir| dir.render(home.path()))
            .collect::<Vec<_>>(),
        claims,
        "and its claims reached the entry still beneath them",
    );
    drop(ledger);
    assert_eq!(peek(&a_dest).expect("handed back").0, b"theirs\n");
    assert!(dir.is_dir(), "nothing was pruned: no removal was announced");
}

#[test]
fn a_prior_already_in_the_restore_store_is_not_written_again() {
    // The skip arm keeps a repeat write from replacing a
    // blob another entry's prior or superseded snapshot already points at,
    // and keeps every `apply` from churning `restore/`. Only the rewrite
    // side was pinned; a mutant that always wrote passed the suite.
    use std::os::unix::fs::MetadataExt as _;

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    state.ensure().expect("ensure");
    let dest = home.child(".conf");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let observed = fs::observe(&dest).expect("observe");

    let Prior::Existed(reference) = store_prior(&state, &observed).expect("store") else {
        panic!("a file that is there has an `Existed` prior");
    };
    let blob = state.restore().join(reference.blob_name());
    let first = std::fs::symlink_metadata(&blob).expect("the blob");

    assert_eq!(
        store_prior(&state, &observed).expect("store again"),
        Prior::Existed(reference),
    );
    let second = std::fs::symlink_metadata(&blob).expect("the blob");
    assert_eq!(
        (first.dev(), first.ino()),
        (second.dev(), second.ino()),
        "the second store wrote nothing: `write_atomically` renames a new \
             inode into place, so a rewrite cannot keep this one",
    );
    assert_eq!(std::fs::read(&blob).expect("read"), b"theirs\n");

    // And the arm is a length test, not a presence test: a blob of the
    // wrong length is replaced.
    std::fs::write(&blob, b"short\n").expect("truncate the blob");
    store_prior(&state, &observed).expect("store over a wrong-length blob");
    assert_eq!(std::fs::read(&blob).expect("read"), b"theirs\n");
}

#[test]
fn a_home_the_loader_would_refuse_never_reaches_a_begin_frame() {
    // `Session::open_locked` checks `Begin.scope` against the home but
    // never checks the home itself. That is not merely inert: the
    // session never opens. `Ledger::open` applies the same rule the loader
    // applies to `Begin.home` — absolute, and UTF-8 — and it runs *before*
    // `Journal::create`, so no header naming such a home is ever written.
    // Pinned here because that guarantee is an ordering, and an ordering
    // can be changed by accident.
    let guard = guarded_home();
    let unusable = {
        use std::os::unix::ffi::OsStrExt as _;
        PathBuf::from(std::ffi::OsStr::from_bytes(b"/home/\xff"))
    };
    for (name, home) in [
        ("relative", PathBuf::from("relative/home")),
        ("tilde", PathBuf::from("~/tilde")),
        ("not utf-8", unusable),
    ] {
        let state = StateDir::new(guard.child(format!("state-{name}")));
        let err = Session::open(&state, SessionKind::Apply, &home, Vec::new())
            .expect_err("a home the loader would refuse");
        assert!(matches!(err, Error::State(_)), "{name}: got {err}");
        assert!(
            !state.journal().exists(),
            "{name}: no header was written for it to refuse",
        );
    }
}

#[test]
fn a_session_counts_every_write_it_published() {
    // `written` is the count `finish` reports, so it must count every write.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session = apply_session(&state, home.path());
    for rel in [".one", ".two", ".three"] {
        session
            .apply(write_to(home.path(), rel, "x\n", Mode::DEFAULT_FILE))
            .expect("apply");
    }
    assert_eq!(session.written(), 3);
    assert_eq!(session.finish().expect("finish"), 3);
}
