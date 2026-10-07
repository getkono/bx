use super::*;

use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt as _;

use crate::fs::remove::{prune_beneath, remove_made_dir};
use crate::journal::tests::{
    WRITES_THROUGH_PERMISSIONS, applied, cannot_build, dir_to, frame_starts, link_at, link_to,
    mode_at, names_in, peek, permissions_refuse, plant_file, raw_journal, saved_ledger, seal,
    state_beyond_set_aside_names, target, write_to,
};
use crate::journal::{Loaded, load};
use crate::testing::guarded_home;

#[test]
fn a_session_that_finishes_leaves_no_journal_and_a_saved_ledger() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

    let mut first =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    first
        .apply(write_to(home.path(), ".conf", "one\n", Mode::DEFAULT_FILE))
        .expect("apply");
    first.finish().expect("finish");

    let mut second =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let (portable, dest) = target(home.path(), ".config/deep/made.conf");
    plant_file(&dest, "bx wrote this\n", Mode::DEFAULT_FILE);

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Absent {
                created_dirs: vec![home.child(".config/deep"), home.child(".config")],
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
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
    let (portable, dest) = target(home.path(), ".never-there");

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Absent {
                created_dirs: Vec::new(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
        .expect("apply");
    drop(session);

    let loaded = load(&state.journal()).expect("load");
    let intents: Vec<&Intent> = loaded.intents().collect();
    assert_eq!(intents[0].before, Prior::Absent);
    assert_eq!(intents[0].after, Written::Absent);
}

#[test]
fn a_directory_that_is_not_empty_stops_the_pruning() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let deep = dir.path().join("a/b/c");
    std::fs::create_dir_all(&deep).expect("mkdir");
    std::fs::write(dir.path().join("a/b/kept"), "the user's").expect("write");

    prune_dirs(&[deep.clone(), dir.path().join("a/b"), dir.path().join("a")]).expect("prune");

    assert!(!deep.exists(), "the empty leaf went");
    assert!(dir.path().join("a/b").is_dir(), "the non-empty one stayed");
    assert!(dir.path().join("a").is_dir(), "and the walk stopped there");
}

#[test]
fn pruning_beneath_follows_only_the_chain_above_what_was_removed() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let root = dir.path();
    let chain = [root.join("a/b"), root.join("a")];
    std::fs::create_dir_all(&chain[0]).expect("mkdir");

    // Removed from `a/b`: both go.
    prune_beneath(&chain[0].join(".bx-0"), &chain).expect("prune");
    assert!(!root.join("a").exists(), "the whole chain went");

    // An absent directory breaks the chain: `a` stands empty and is not
    // shown made by anything beneath it.
    std::fs::create_dir(root.join("a")).expect("the user's");
    prune_beneath(&chain[0].join(".bx-0"), &chain).expect("prune");
    assert!(root.join("a").is_dir(), "never made, so never pruned");

    // So does a directory that is not the parent of what was removed.
    std::fs::create_dir(&chain[0]).expect("mkdir");
    prune_beneath(&root.join("elsewhere/.bx-0"), &chain).expect("prune");
    assert!(chain[0].is_dir(), "not beneath it");

    // And one that is not empty.
    std::fs::write(chain[0].join("kept"), "the user's").expect("write");
    prune_beneath(&chain[0].join(".bx-0"), &chain).expect("prune");
    assert!(chain[0].is_dir() && root.join("a").is_dir());
}

#[test]
fn a_made_directory_is_removed_only_when_it_is_there_and_empty() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let made = dir.path().join("made");
    assert!(
        !remove_made_dir(&made).expect("absent"),
        "nothing to remove"
    );
    std::fs::write(&made, "a file").expect("write");
    assert!(!remove_made_dir(&made).expect("a file"), "not a directory");
    std::fs::remove_file(&made).expect("rm");
    std::fs::create_dir(&made).expect("mkdir");
    assert!(remove_made_dir(&made).expect("empty"));
    assert!(!made.exists());
}

#[test]
fn pruning_a_directory_that_is_already_gone_is_not_an_error() {
    let dir = tempfile::tempdir().expect("a tempdir");
    prune_dirs(&[dir.path().join("never-existed")]).expect("prune");
    unlink(&dir.path().join("never-there")).expect("unlink");
    // Opening the directory first must not turn a missing one into an error.
    unlink(&dir.path().join("gone/never-there")).expect("unlink in a missing directory");
}

#[test]
fn a_removal_opens_its_directory_before_the_unlink_and_syncs_it_after() {
    // The order `fs::write_atomically` keeps for a rename, observed: the
    // directory handle exists before the file goes, and the sync follows.
    use crate::fs::durable::{Event, recording};

    let dir = tempfile::tempdir().expect("a tempdir");
    let file = dir.path().join("f");
    plant_file(&file, "x\n", Mode::DEFAULT_FILE);

    let (removed, events) = recording(|| unlink(&file));
    removed.expect("unlink");

    assert_eq!(
        events,
        [
            Event::OpenDir(dir.path().to_path_buf()),
            Event::Unlink(file.clone()),
            Event::SyncDir(dir.path().to_path_buf()),
        ],
    );
    assert!(!file.exists());
}

#[test]
fn a_directory_that_cannot_be_opened_fails_a_removal_before_the_file_goes() {
    if rustix::process::geteuid().is_root() {
        // Root ignores the permission bits, so there is nothing to assert.
        return;
    }
    let dir = tempfile::tempdir().expect("a tempdir");
    let file = dir.path().join("f");
    plant_file(&file, "the user's\n", Mode::DEFAULT_FILE);
    // Write and search, no read: the file can be unlinked, and the directory
    // cannot be opened to fsync the unlink.
    fs::set_mode(dir.path(), Mode::from_bits(0o300)).expect("chmod");

    let result = unlink(&file).map_err(Error::from);
    fs::set_mode(dir.path(), Mode::PRIVATE_DIR).expect("unlock for cleanup");

    match result {
        Err(Error::Io { path, source }) => {
            assert_eq!(path, dir.path());
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected an io error naming the directory, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(&file).expect("the file is still there"),
        b"the user's\n",
        "an Err means the removal did not happen",
    );
}

#[test]
fn a_session_will_not_write_through_a_symlink_the_user_made() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child("real"), "real\n", Mode::DEFAULT_FILE);
    std::os::unix::fs::symlink(home.child("real"), home.child(".conf")).expect("symlink");

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&other, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    let err = session
        .apply(Request {
            target: target(home.path(), ".conf").0,
            dest: home.child(".conf"),
            content: Content::Absent {
                created_dirs: Vec::new(),
                planned: fs::observe(&home.child(".conf")).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

    let mut first =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    first
        .apply(write_to(home.path(), rel, "x\n", Mode::DEFAULT_FILE))
        .expect("apply");
    first.finish().expect("finish");

    let mut second =
        Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
    let (removed, events) = recording(|| {
        second.apply(Request {
            target: target(home.path(), rel).0,
            dest: dest.clone(),
            content: Content::Absent {
                created_dirs: vec![home.child(".config/made"), home.child(".config")],
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
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
    // Review round 3, item 2. The loader refuses such a journal, so a
    // session that wrote one would leave an interruption nothing recovers.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut request = write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE);
    request.dest = home.child(".elsewhere");

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

#[test]
fn a_failed_append_poisons_the_session() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

#[test]
fn a_failed_removal_intent_append_poisons_the_session_and_unlinks_nothing() {
    // r3 coverage C7. The write path's failed append is pinned above; the
    // removal's was not.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    let mut first =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
        .apply(Request {
            target: portable.clone(),
            dest: dest.clone(),
            content: Content::Absent {
                created_dirs: Vec::new(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
fn a_named_temp_recovery_cannot_unlink_is_left_and_the_rollback_goes_on() {
    // r3 round 2, P9R4-D3. The directory lost write permission between
    // the Intent and the publish, so the publish failed and left the
    // temporary file the Intent names. Recovery could not unlink it and
    // returned an Io error on every writing run, while `pending` called
    // the write resolvable.
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    // Stack integration of #7's round 3: `Ledger::record` refuses a changed
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
    let mut first =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    first.apply(shared("BX1")).expect("apply");
    first.finish().expect("finish");
    let saved = std::fs::read(state.ledger()).expect("the saved ledger");

    let edit = format!("{}more\n", region("BX1"));
    plant_file(&dest, &edit, Mode::DEFAULT_FILE);

    let mut second =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    // Stack integration of #8's round 3: `publish` re-checks the destination
    // and returns `fs::Error::Changed` before the rename. Inside a session
    // that poisons like any publish error, keeps the edit, and leaves
    // recovery nothing to put back over it.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    // Stack integration of #8's round 4: `stage` decides on the observation
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
fn a_session_keeps_one_set_of_the_directories_its_writes_created() {
    // Stack integration of #8's round 4: a directory target applied after a
    // write beneath it is the `Create` plan announced only when both were
    // given one `fs::CreatedDirs`. The session holds that set for its life.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    // r3 round 3, D1. `refusal` puts every `Begin.scope` entry through
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
    // As `skips_allowed_child`: no instructions, nothing to do.
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
    let mut session = Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
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
    let mut session =
        Session::open(&beside_state, SessionKind::Apply, &beside_home, Vec::new()).expect("open");
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
    // r3 round 6, D1/COV4/CL1/CL2. The path r3 round 5 made succeed
    // created the user's own home through `fs::stage`, which `chmod`s past
    // the `umask` on purpose — the right rule for a directory bx owns and
    // will remove again, and the wrong one for a directory bx neither
    // claims nor ever removes. `crate::state::dir::ensure_dir` already
    // documents the opposite rule for exactly this category of directory,
    // so bx's two ancestor-making paths disagreed.
    //
    // `umask(2)` is process-global and this suite runs in parallel, so the
    // umask is set for a child rather than here: `sh -c 'umask 077; exec …'`,
    // which needs no `unsafe` and no shared lock.
    let guard = guarded_home();
    let exe = std::env::current_exe().expect("the test binary");
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(r#"umask 077; exec "$1" --exact --ignored journal::session::tests::umask_child"#)
        .arg("sh")
        .arg(&exe)
        .env(UMASK_CHILD_DIR, guard.child("under"))
        .output()
        .expect("spawn the umask child");
    assert!(
        out.status.success(),
        "the umask child failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn a_stage_that_made_other_directories_than_its_intent_named_is_refused() {
    // #119. The Intent names the parents read from disk before the stage;
    // a disk that changed in between makes the two differ, and the write
    // is refused rather than carried on with a ledger claim the journal
    // does not share. What the home or above adds is dropped from both
    // sides alike, so it alone is no difference.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    let dest = home.child(".config/app/x.conf");
    let (app, config) = (home.child(".config/app"), home.child(".config"));
    let announced = [app.clone(), config.clone()];

    session
        .refuse_unannounced(&dest, &announced, &announced)
        .expect("the same set");
    session
        .refuse_unannounced(
            &dest,
            &announced,
            &[app.clone(), config.clone(), home.path().to_path_buf()],
        )
        .expect("the home is claimed by neither");
    for made in [vec![app.clone()], vec![], vec![config.clone(), app.clone()]] {
        let err = session
            .refuse_unannounced(&dest, &announced, &made)
            .expect_err("a different set");
        assert!(
            matches!(&err, Error::Write(fs::Error::Changed { path, .. }) if *path == dest),
            "{made:?}: {err:?}"
        );
    }
}

/// Lose the parent of the destination's parent between the prediction
/// and the stage: `.config` existed when the Intent was written, so it
/// names only `.config/app`, and the stage then makes both.
fn lose_config(dest: &Path) {
    let config = dest
        .parent()
        .and_then(Path::parent)
        .expect("the destination's grandparent");
    std::fs::remove_dir(config).expect("the user removes it, empty");
}

#[test]
fn a_write_refused_for_an_unannounced_directory_removes_what_it_made() {
    // D2. The stage made `.config` again, which the Intent never named and
    // the refused write leaves in no ledger: no rollback or `rm` would ever
    // remove it, so the refusal itself does, with `.config/app` under it.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let config = home.child(".config");
    std::fs::create_dir(&config).expect("the user's, at prediction");
    let (portable, dest) = target(home.path(), ".config/app/x.conf");

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    session.after_intent = Some(lose_config);
    let err = session
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
        .expect_err("the stage made a directory the Intent did not name");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { path, .. }) if *path == dest),
        "got {err}"
    );
    assert!(!config.exists(), "what the stage made is gone again");
    assert!(
        std::fs::read_dir(home.path())
            .expect("the home")
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".bx-")),
        "and so is the temporary file",
    );
}

#[test]
fn a_link_refused_for_an_unannounced_directory_removes_what_it_made() {
    // D2, the link path.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let config = home.child(".config");
    std::fs::create_dir(&config).expect("the user's, at prediction");
    let (portable, dest) = target(home.path(), ".config/app/link");

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    session.after_intent = Some(lose_config);
    let err = session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Link {
                text: PathBuf::from("elsewhere"),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::LINK,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect_err("the stage made a directory the Intent did not name");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { path, .. }) if *path == dest),
        "got {err}"
    );
    assert!(!config.exists(), "what the stage made is gone again");
}

#[test]
fn a_claim_that_appears_after_the_directory_is_lost_is_still_dropped() {
    // r3 round 7, CL1/COV1. The `r3 round 6` fix makes the home before
    // `fs::stage` looks, so `stage` stops inventing it and the claim
    // filter stops firing — and nothing constrained the filter at all:
    // mutating it left the suite green at 1064 passed, and the "pair"
    // witness only showed that deleting the fix *and* the filter together
    // fails, which deleting the fix alone already does.
    //
    // The filter's one live trigger is the race the fix created: the
    // directory going away between the two calls. `before_stage` produces
    // it, so the branch a race would take is taken here on purpose.
    let guard = guarded_home();
    let home = guard.child("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");

    let mut session = Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
    session.before_stage = Some(|dir| {
        std::fs::remove_dir(dir).expect("lose the directory before stage looks");
    });
    session
        .apply(Request {
            target: portable.clone(),
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"bx\n".to_vec(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect("stage makes the directory again");
    assert!(home.is_dir(), "`stage` made it the second time");

    // `stage` invented the home this time, so the filter is the only thing
    // between that and an Intent the loader refuses.
    let intent = load(&state.journal())
        .expect("load")
        .intents()
        .next()
        .cloned()
        .expect("the Intent");
    assert!(
        intent.created_dirs.is_empty(),
        "the claim on the home was dropped, not recorded: {:?}",
        intent.created_dirs,
    );
    assert!(
        !matches!(
            load(&state.journal()).expect("load"),
            Loaded::Unreadable { .. }
        ),
        "so the journal is still one the loader believes",
    );
    session.finish().expect("finish");
    assert!(
        entry_created_dirs(&state, &home, &portable).is_empty(),
        "and the entry claims none of it either",
    );
}

#[test]
fn a_refused_write_makes_no_directory_at_all() {
    // r3 round 7, D1/COV3. The `create_dir_all` sat ahead of `fs::stage`'s
    // plan-verdict refusals, whose own comment is "before creating
    // anything, so a refusal leaves nothing behind" — so a write refused
    // because the destination changed since plan left the user's home
    // created. Nothing pinned what a refused write leaves on disk.
    let guard = guarded_home();
    let home = guard.child("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");
    std::fs::create_dir_all(&home).expect("the home, for now");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let planned = fs::observe(&dest).expect("plan's observation");
    // Everything plan looked at is gone by the time apply runs.
    std::fs::remove_dir_all(guard.child("account")).expect("the user removes the tree");

    let mut session = Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
    let err = session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"bx\n".to_vec(),
                planned,
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect_err("the destination is not what plan observed");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { detail, .. })
                if detail == "it has been removed"),
        "got {err}"
    );
    assert!(
        !guard.child("account").exists(),
        "a refusal leaves nothing behind — not the home, and not its parent",
    );
    drop(session);
    assert_eq!(
        load(&state.journal()).expect("load").intents().count(),
        0,
        "and nothing was announced",
    );
}

#[test]
fn a_shared_directory_that_cannot_be_made_is_the_write_that_names_it() {
    // r3 round 7, COV2. `create_dir_all`'s error mapping had no test.
    let guard = guarded_home();
    let under = guard.child("locked");
    std::fs::create_dir(&under).expect("mkdir");
    let home = under.join("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");
    fs::set_mode(&under, Mode::from_bits(0o555)).expect("make it read-only");
    if !permissions_refuse(&under) {
        fs::set_mode(&under, Mode::DEFAULT_DIR).expect("make it writable again");
        return cannot_build(
            "a_shared_directory_that_cannot_be_made_is_the_write_that_names_it",
            WRITES_THROUGH_PERMISSIONS,
        );
    }

    let mut session = Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
    let applied = session.apply(Request {
        target: portable,
        dest: dest.clone(),
        content: Content::Bytes {
            bytes: b"bx\n".to_vec(),
            planned: fs::observe(&dest).expect("plan's observation"),
        },
        mode: Mode::DEFAULT_FILE,
        ownership: Ownership::Owned(Mechanism::Own),
    });
    // Before any assertion, so the tempdir can be removed whatever happens.
    fs::set_mode(&under, Mode::DEFAULT_DIR).expect("make it writable again");

    let err = applied.expect_err("the shared directory cannot be made");
    // The path named is the one bx asked for, not the component that
    // refused: `create_dir_all` does not say which that was, and
    // `state::dir::ensure_dir` maps its own the same way.
    assert!(
        matches!(&err, Error::Write(fs::Error::Write { path, .. }) if *path == home),
        "got {err}"
    );
}

#[test]
fn a_destination_behind_a_directory_bx_cannot_search_is_a_read_not_a_write() {
    // r3 round 7, D2. `shared_ancestor` read "cannot look" as "not there",
    // so an `EACCES` on the way up became a failed `create_dir_all` and
    // surfaced as `Error::Write` — where looking at the destination
    // surfaces the same permission as `Error::Read`. Since the verdict now
    // comes first, `fs::observe` walks that chain before anything is made,
    // so the read error is what a caller sees; the refined predicate keeps
    // that true if the order ever moves.
    let guard = guarded_home();
    let under = guard.child("sealed");
    std::fs::create_dir(&under).expect("mkdir");
    let home = under.join("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");
    // No search bit, so nothing under it can be looked at at all.
    fs::set_mode(&under, Mode::from_bits(0o600)).expect("seal it");
    if std::fs::symlink_metadata(under.join("account"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        fs::set_mode(&under, Mode::DEFAULT_DIR).expect("unseal");
        return cannot_build(
            "a_destination_behind_a_directory_bx_cannot_search_is_a_read_not_a_write",
            WRITES_THROUGH_PERMISSIONS,
        );
    }

    let mut session = Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
    let applied = session.apply(Request {
        target: portable,
        dest: dest.clone(),
        content: Content::Bytes {
            bytes: b"bx\n".to_vec(),
            planned: fs::Observed {
                path: dest.clone(),
                ..fs::observe(&guard.child("elsewhere")).expect("some observation")
            },
        },
        mode: Mode::DEFAULT_FILE,
        ownership: Ownership::Owned(Mechanism::Own),
    });
    // Before any assertion, so the tempdir can be removed whatever happens.
    fs::set_mode(&under, Mode::DEFAULT_DIR).expect("unseal");

    let err = applied.expect_err("bx cannot look at the destination");
    // `observe` reports the path it could not read, which is the deepest
    // one the walk reached — the home here, not the destination beyond it.
    assert!(
        matches!(&err, Error::Write(fs::Error::Read { path, .. }) if *path == home),
        "a permission bx cannot pass is a read, not a write: got {err}"
    );
}

#[test]
fn a_write_makes_the_home_it_needs_and_claims_none_of_it() {
    // r3 round 4 D2, repaired again in r3 round 5 (D1, COV3, CL4).
    //
    // `admit` sees `&[]` for a `Content::Bytes` request — a write's claims
    // do not exist until `fs::stage` has made the parents — so an Intent's
    // `created_dirs` never went through the `stray_created_dir` rule the
    // loader applies to it. At 8e0abc3 the write landed and left an
    // `Unreadable` journal. Round 4 refused it instead, which turned
    // silent corruption into a permanent refusal naming the user's own
    // home: the in-home case below is a *first write to `~/.bashrc`*, and
    // there is nothing the user could do about it.
    //
    // Neither is right. The directory is made — it has to be, to reach the
    // destination — and claimed by nobody: not by the Intent, so the
    // journal stays readable and a rollback's `prune_dirs` cannot reach
    // the home; not by the ledger entry, so a later `rm`'s `prune_claims`
    // cannot either.
    //
    // Both arms need the home absent when the write runs, which needs the
    // state directory elsewhere — `$XDG_STATE_HOME`, as a service account
    // with state under `/var/lib` would have it — since otherwise
    // `state.ensure()` makes the home on its way past.
    for (case, made) in [
        ("in the home", "account/home"),
        ("beside the home", "account"),
    ] {
        let guard = guarded_home();
        let home = guard.child("account/home");
        let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
        assert!(!home.exists(), "{case}: the home is not there yet");
        // In the home the target is `~`-rooted, which is the only spelling
        // the ledger's home check admits; beside it, it is absolute.
        let (portable, dest) = if case == "in the home" {
            target(&home, ".bashrc")
        } else {
            let dest = guard.child("account/beside.conf");
            (
                Portable::try_from(dest.to_str().expect("utf-8").to_string())
                    .expect("a well-formed absolute path"),
                dest,
            )
        };
        let made = guard.child(made);

        let mut session =
            Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
        assert!(!made.exists(), "{case}: the write makes {}", made.display());
        session
            .apply(Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"bx\n".to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .unwrap_or_else(|e| panic!("{case}: a write bx can make: {e}"));
        assert!(made.is_dir(), "{case}: and it made it");
        assert_eq!(peek(&dest).expect("published").0, b"bx\n", "{case}");

        // The Intent claims none of it, so the journal is one bx believes
        // and a rollback prunes nothing.
        let intent = load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .cloned()
            .unwrap_or_else(|| panic!("{case}: the Intent"));
        assert!(
            intent.created_dirs.is_empty(),
            "{case}: claimed {:?}",
            intent.created_dirs,
        );
        assert!(
            !matches!(
                load(&state.journal()).expect("load"),
                Loaded::Unreadable { .. }
            ),
            "{case}: the journal is one the loader believes",
        );
        session.finish().unwrap_or_else(|e| panic!("{case}: {e}"));

        // And neither does the ledger entry, so `rm` leaves the home.
        let claimed = entry_created_dirs(&state, &home, &portable);
        assert!(claimed.is_empty(), "{case}: the entry claimed {claimed:?}");
        let done = crate::restore::restore(&state, &home, std::slice::from_ref(&portable))
            .unwrap_or_else(|e| panic!("{case}: rm: {e}"));
        assert_eq!(done.len(), 1, "{case}: {done:?}");
        assert!(peek(&dest).is_none(), "{case}: bx's file is gone");
        assert!(made.is_dir(), "{case}: and {} still stands", made.display());
    }
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
    // Stack integration of #7's round 4: a caller holding a `Ledger` gets
    // its home check. `new_entry` folds the destination into `~/…`, so the
    // check inside `Ledger::check_record` cannot see a target spelled
    // `/<home>/…`. That target renders to itself and used to be admitted:
    // the ledger keyed it `~/.conf`, the same file under that spelling got
    // past `Repeated`, and a crash left a journal the loader refuses.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dest = home.child(".conf");
    plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
    let absolute = Portable::try_from(dest.to_str().expect("utf-8").to_string())
        .expect("a well-formed absolute path");

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    // Stack integration of #7's round 3: a same-length file at
    // `restore/<digest>` that is a second hard link is not a blob bx wrote,
    // and the ledger's store stopped trusting one. The journal's own copy of
    // the length check still did, so an Intent named a blob holding the
    // decoy's bytes and the rollback could not put the original back. A
    // removal records nothing in the ledger, so only that copy runs here.
    use std::os::unix::fs::MetadataExt as _;

    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    state.ensure().expect("ensure");
    let (portable, dest) = target(home.path(), ".conf");
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
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Absent {
                created_dirs: Vec::new(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        })
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
fn a_failed_removal_keeps_the_ledger_entry_and_poisons_the_session() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), "locked/made.conf");
    let mut first =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let removed = session.apply(Request {
        target: portable.clone(),
        dest: dest.clone(),
        content: Content::Absent {
            created_dirs: vec![locked.clone()],
            planned: fs::observe(&dest).expect("plan's observation"),
        },
        mode: Mode::DEFAULT_FILE,
        ownership: Ownership::Released,
    });
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
    // Stack integration of #8 @62de0aa, which carries #7's r3 round 1:
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
    // Review round 5, item 1. `remove` observed, made the snapshot and the
    // Intent durable, and unlinked with no second look, so an editor's save
    // in that window was destroyed (18 of 300 racing runs).
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".conf");
    let mut first =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
fn a_removal_names_how_its_destination_moved_since_plan() {
    // r3 coverage C2, extended for r3 coverage COV5: the third detail and
    // the `planned.path != now.path` branch had no case. That branch is
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
    // Coverage review round 5, non-blocking.
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
    // r3 round 1, D1. `rmdir` on a symlink or a file is ENOTDIR, which was
    // an error: `rm` unlinked the file through the link and then failed,
    // and a rollback failed the same way on every run.
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
    // r3 round 1, D2. The session checked a removal's destination but not
    // its created directories, so it pruned an empty directory of the user's
    // and wrote an Intent the loader refuses: the journal was then set
    // aside, and the removed file was never put back.
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
        let mut first = Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
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
            .apply(Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: vec![stray.clone()],
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
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
    // r3 coverage C3. No admitted removal and no believed journal reaches
    // this since D2: every claim is a parent of a destination rendered
    // under an absolute UTF-8 home, and every forgotten claim is a stored
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
    // r3 round 2, P9R4-CV2. Neither the skip for a claim the heir already
    // holds nor a `record` the ledger refuses was reached. The ledger's
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
    // r3 round 3, D2 and CL2. `Session::write`'s released arm dropped the
    // entry `forget` returns, and with it the entry's `created_dirs`, while
    // `Session::remove` and `Session::forget` both carry theirs on. A
    // directory bx made then had no claimant at all: no later `rm` could
    // remove it, and recovery's rebuild could not either.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let dir = home.child(".config/app");
    let claims: Vec<PathBuf> = vec![dir.clone(), home.child(".config")];

    // bx makes both directories for a.conf, which claims them.
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    // r3 coverage COV2. The skip arm keeps a repeat write from replacing a
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
fn a_ledger_that_refuses_after_a_publish_poisons_the_session_and_is_rolled_back() {
    // r3 coverage COV8. The sharpest of `Session::write`'s error paths past
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

#[test]
fn a_home_the_loader_would_refuse_never_reaches_a_begin_frame() {
    // r3 round 4. The round-1 panel noted that `Session::open_locked`
    // checks `Begin.scope` against the home but never checks the home
    // itself, and declined to report it. It is not merely inert: the
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
    // Coverage review round 5, non-blocking.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
    for rel in [".one", ".two", ".three"] {
        session
            .apply(write_to(home.path(), rel, "x\n", Mode::DEFAULT_FILE))
            .expect("apply");
    }
    assert_eq!(session.written(), 3);
    assert_eq!(session.finish().expect("finish"), 3);
}

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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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

    let mut session =
        Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
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
