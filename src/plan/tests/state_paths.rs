//! What stands at the state directory's paths: a FIFO or a link to a device
//! refused without waiting, a linked `local.toml` read as the user's layer,
//! and a held state directory that apply refuses and plan reports running.

use super::*;

/// Make `path` a FIFO. Opening it to read waits for a writer that never
/// comes, which is what any read of it that is not refused first does.
fn fifo_at(path: &Path) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("the FIFO's directory");
    }
    crate::testing::mkfifo(path);
}

/// The text of the error `run` in `mode` stops with, run on a thread so a
/// read that waits fails the test instead of hanging it.
fn refusal(inputs: &Inputs, mode: Mode) -> String {
    let (sent, received) = std::sync::mpsc::channel();
    let inputs = inputs.clone();
    std::thread::spawn(move || {
        let outcome = run(&inputs, mode, &mut |_| Ok(true))
            .map(|report| report.actions())
            .map_err(|error| error.to_string());
        let _ = sent.send(outcome);
    });
    match received.recv_timeout(std::time::Duration::from_secs(20)) {
        Ok(Err(message)) => message,
        Ok(Ok(actions)) => panic!("{mode:?} ran to completion: {actions:?}"),
        Err(_) => panic!("{mode:?} had not returned after 20 s: a read is waiting"),
    }
}

/// Stage an apply that died once its write was published: the journal
/// stands over `new\n`, and rolling it back needs the restore snapshot of
/// `old\n`. This is the state in which `bx plan` reads a fourth state file.
fn a_standing_write_over(home: &GuardedHome) -> Inputs {
    home.write(".conf", "old\n");
    let inputs = inputs(home, &inline("~/.conf", "new\\n"));
    let target = Portable::parse_in("~/.conf", home.path()).expect("a portable target");
    let dest = home.child(".conf");
    let mut session = Session::open(
        inputs.state(),
        SessionKind::Apply,
        home.path(),
        vec![target.clone()],
    )
    .expect("a session");
    session
        .apply(Request {
            target,
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"new\n".to_vec(),
                planned: fs::observe(&dest).expect("observe"),
            },
            mode: FileMode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect("the write");
    drop(session);
    inputs
}

/// Every path under `state`, deepest first, as the filesystem holds them.
///
/// Re-derived from disk on every run rather than written down: the point of
/// [`refuse_irregular_state_files`] after decision 33 is that its scope is
/// whatever is there, so a test that named the files would be the very
/// artefact the decision removed.
fn every_state_path(state: &StateDir) -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                walk(&path, found);
            } else {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(state.root(), &mut found);
    found
}

#[test]
fn decision_33_a_fifo_at_any_file_under_the_state_directory_is_refused_without_waiting() {
    // The guard used to name three files — the
    // ledger, the fingerprints and the journal — and the three tests that
    // exercised it mirrored that same list, so neither could find what the
    // list had missed: `bx plan` also reads <state>/restore/<digest>
    // through `interrupted_rows`, with no file-type check on that path, and
    // a FIFO there made `bx plan` — the read-only command — wait forever.
    //
    // This asks it of every file the state directory actually holds,
    // enumerated from disk at the head it runs against. A reader added
    // later brings its file with it and is covered the day it is written;
    // nobody has to remember to extend a list.
    let home = guarded_home();
    // A finished apply and a saved fingerprint cache first, so a saved
    // ledger and the fingerprints are among the files swept, beside the
    // standing journal's snapshot.
    own(home.path(), ".owned", b"owned\n", Mechanism::Own);
    let state = StateDir::resolve(home.path());
    let lock = ExclusiveLock::try_acquire(&state)
        .expect("try the lock")
        .expect("nothing holds it");
    let mut cache = crate::state::Fingerprints::default();
    cache.set("tracked", crate::state::Fingerprint::raw(b"seen".to_vec()));
    cache.save(&state, &lock).expect("save the fingerprints");
    drop(lock);
    let inputs = a_standing_write_over(&home);

    let paths = every_state_path(inputs.state());
    let blob_dir = inputs.state().restore();
    assert!(
        paths.contains(&inputs.state().ledger()),
        "the fixture holds no ledger: {paths:?}"
    );
    assert!(
        paths.contains(&inputs.state().fingerprints()),
        "the fixture holds no fingerprints: {paths:?}"
    );
    assert!(
        paths.iter().any(|path| path.parent() == Some(&*blob_dir)),
        "the fixture holds no restore snapshot, so the case that hung is untested: {paths:?}"
    );
    assert!(
        paths.contains(&inputs.state().journal()),
        "the fixture holds no journal: {paths:?}"
    );

    for path in paths {
        let kept = std::fs::read(&path).expect("the file's bytes");
        std::fs::remove_file(&path).expect("make way for the FIFO");
        fifo_at(&path);

        // `refusal` runs on a thread with a deadline, so a read that waits
        // fails the test instead of hanging it.
        for mode in [Mode::Plan, Mode::Apply] {
            let message = refusal(&inputs, mode);
            assert!(
                message.contains(&path.display().to_string()),
                "{mode:?} {}: {message}",
                path.display()
            );
            assert!(
                message.contains("not a regular file"),
                "{mode:?} {}: {message}",
                path.display()
            );
        }

        std::fs::remove_file(&path).expect("the FIFO goes");
        std::fs::write(&path, kept).expect("the file comes back");
    }

    // No refused apply wrote past its refusal.
    assert_eq!(
        std::fs::read(home.child(".conf")).expect("untouched"),
        b"new\n"
    );
    // With every file back as it was, the same run reports the
    // interruption rather than a refusal: the sweep left nothing behind.
    assert!(plan(&inputs).interrupted.is_some());
}

#[test]
fn decision_20_a_link_to_a_device_at_the_ledger_is_refused_before_any_read() {
    // Asked of the guard itself, not of `run`: were the guard ever to let
    // it through, the ledger's reader would read `/dev/zero` into memory
    // until the host ran out. The FIFO tests show `run` asks the guard
    // before anything is read.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    std::fs::create_dir_all(state.root()).expect("the state directory");
    std::os::unix::fs::symlink("/dev/zero", state.ledger()).expect("the link");

    let error = refuse_irregular_state_files(&state).expect_err("a link is refused");

    assert!(
        matches!(&error, Error::NotARegularFile { path } if *path == state.ledger()),
        "{error:?}"
    );
    assert!(error.to_string().contains("not a regular file"), "{error}");

    // Absent state files, and regular ones, are read as before.
    let other = guarded_home();
    let fresh = StateDir::resolve(other.path());
    assert!(refuse_irregular_state_files(&fresh).is_ok());
    std::fs::create_dir_all(fresh.root()).expect("the state directory");
    std::fs::write(fresh.ledger(), b"a ledger's bytes").expect("a regular ledger");
    assert!(refuse_irregular_state_files(&fresh).is_ok());
}

#[test]
fn decision_38_a_linked_local_toml_is_the_users_layer_and_plan_and_apply_run() {
    // The walk refused every link under the state root, and the local
    // layer is the one file there the user writes and may link, so any
    // account with a linked `local.toml` could not run `bx` at all.
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let state = StateDir::resolve(home.path());
    std::fs::create_dir_all(state.root()).expect("the state directory");
    std::fs::set_permissions(state.root(), std::fs::Permissions::from_mode(0o700))
        .expect("a private state directory");
    let real = home.write("dotfiles/local.toml", "[values]\n");
    let local = paths::local_layer_path(state.root());
    std::os::unix::fs::symlink(&real, &local).expect("the link");
    let inputs = load(home.path());

    assert!(refuse_irregular_state_files(inputs.state()).is_ok());
    assert_eq!(plan(&inputs).actions(), [Action::Create]);
    assert_eq!(apply(&inputs).actions(), [Action::Create]);
    assert_eq!(plan(&inputs).actions(), [Action::Unchanged]);
    assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");
    assert!(
        std::fs::symlink_metadata(&local).is_ok_and(|meta| meta.file_type().is_symlink()),
        "the user's link is left as it was"
    );

    // Only that one name is exempt: a link anywhere else under the state
    // root is still refused.
    std::os::unix::fs::symlink(&real, state.ledger().with_file_name("other.toml"))
        .expect("a second link");
    assert!(matches!(
        refuse_irregular_state_files(inputs.state()),
        Err(Error::NotARegularFile { .. })
    ));
}

#[test]
fn decision_20_a_fifo_as_a_file_body_is_refused_without_waiting() {
    let home = guarded_home();
    let inputs = inputs(
        &home,
        "[[target]]\npath = \"~/.b\"\nfile = \"files/body\"\n",
    );
    let body = home.child(".config/bx/files/body");
    fifo_at(&body);

    for mode in [Mode::Plan, Mode::Apply] {
        let message = refusal(&inputs, mode);
        assert!(
            message.contains(&body.display().to_string()),
            "{mode:?}: {message}"
        );
        assert!(
            message.contains("not a regular file"),
            "{mode:?}: {message}"
        );
    }
    assert!(!home.child(".b").exists(), "written from a refused body");
}

#[test]
fn t15_apply_refuses_a_held_state_directory_and_plan_reports_it_running() {
    let home = guarded_home();
    let inputs = inputs(&home, &inline("~/.a", "x\\n"));
    let held = ExclusiveLock::acquire(inputs.state()).expect("the lock");

    // The refusal comes before anything else the run would do.
    // It used to come from `Session::open`, at the end: every target was
    // decided against a state directory the running apply was concurrently
    // changing, the whole plan was rendered, and the user was asked to
    // confirm work this run was never going to be allowed to do.
    let mut asked = 0;
    let error = run(&inputs, Mode::Apply, &mut |_| {
        asked += 1;
        Ok(true)
    })
    .expect_err("locked");
    assert!(
        matches!(error, Error::State(state::Error::Locked { .. })),
        "{error:?}"
    );
    assert_eq!(asked, 0, "apply prompted before refusing the held lock");

    let report = plan(&inputs);
    assert!(report.apply_running);
    assert_eq!(report.interrupted, None);
    assert_eq!(report.actions(), vec![Action::Create]);
    assert!(!home.child(".a").exists());

    drop(held);
    let report = plan(&inputs);
    assert!(
        !report.apply_running,
        "a released lock is not a running apply"
    );
}
