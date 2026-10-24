use super::*;

/// One tracked target per name: `~/.NAME`, whose repo copy is
/// `files/NAME`.
fn layer(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| {
            format!(
                "[[target]]\npath = \"~/.{name}\"\nfile = \"files/{name}\"\n\
                         direction = \"track\"\n"
            )
        })
        .collect()
}

fn machine(home: &Path, name: &str) -> PathBuf {
    home.join(format!(".{name}"))
}

fn copy(home: &Path, name: &str) -> PathBuf {
    home.join(".config/bx/files").join(name)
}

fn put(path: &Path, bytes: &str) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("parents");
    std::fs::write(path, bytes).expect("write");
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn sync(inputs: &Inputs) -> Report {
    run(inputs, Mode::Sync, &mut |_| Ok(true)).expect("sync runs")
}

/// A home tracking `~/.lock`, whose copy here and in the repo are
/// both `agreed`, after a first apply that records the agreement.
fn agreed_home(agreed: &str) -> (GuardedHome, Inputs) {
    let home = guarded_home();
    put(&machine(home.path(), "lock"), agreed);
    put(&copy(home.path(), "lock"), agreed);
    let inputs = inputs(&home, &layer(&["lock"]));
    let first =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("the first apply");
    assert_eq!(first.actions(), vec![Action::Unchanged]);
    assert!(!first.executed);
    (home, inputs)
}

fn kept(home: &Path, name: &str) -> Option<crate::plan::track::Base> {
    let cache = Fingerprints::read(&StateDir::resolve(home))
        .expect("the cache")
        .value;
    let fingerprint = cache.get(&format!("track:~/.{name}"))?;
    Some(crate::plan::track::Base::from_fingerprint(fingerprint).expect("an agreement bx wrote"))
}

fn base(home: &Path, name: &str) -> Option<Vec<u8>> {
    match kept(home, name)? {
        crate::plan::track::Base::Bytes(bytes) => Some(bytes),
        crate::plan::track::Base::Digest(_) => panic!("a small agreement is kept whole"),
    }
}

fn cache_bytes(home: &Path) -> Vec<u8> {
    std::fs::read(StateDir::resolve(home).fingerprints()).expect("the cache file")
}

#[test]
fn an_agreement_is_kept_whole_up_to_the_bound_and_as_a_digest_above_it() {
    let whole = vec![b'a'; crate::plan::track::Base::KEPT_WHOLE];
    let mut large = whole.clone();
    large.push(b'a');
    assert_eq!(
        crate::plan::track::Base::of(&whole),
        crate::plan::track::Base::Bytes(whole.clone())
    );
    let digest = crate::plan::track::Base::of(&large);
    assert_eq!(
        digest,
        crate::plan::track::Base::Digest(*crate::state::ContentHash::of(&large).as_bytes())
    );
    assert!(digest.holds(&large));
    assert!(!digest.holds(&whole));
    assert!(crate::plan::track::Base::of(&whole).holds(&whole));
    assert!(!crate::plan::track::Base::of(&whole).holds(&large));
    for base in [
        crate::plan::track::Base::of(b""),
        crate::plan::track::Base::of(&whole),
        digest,
    ] {
        assert_eq!(
            crate::plan::track::Base::from_fingerprint(&base.fingerprint()),
            Some(base.clone())
        );
    }
    assert_eq!(
        crate::plan::track::Base::of(b"ab").fingerprint().as_bytes(),
        b"=ab",
        "a tag, then the bytes"
    );
    // Anything bx does not write reads as no agreement: a question,
    // never an overwrite.
    let mut overlong = vec![b'='];
    overlong.extend_from_slice(&large);
    for foreign in [&b""[..], b"ab", b"#short", &overlong, &[b'#'; 34][..]] {
        assert_eq!(
            crate::plan::track::Base::from_fingerprint(&crate::state::Fingerprint::raw(foreign)),
            None,
            "{foreign:?}"
        );
    }
}

#[test]
fn a_large_tracked_file_is_agreed_by_digest_and_its_conflict_shows_the_two_sides() {
    let large = "x\n".repeat(crate::plan::track::Base::KEPT_WHOLE);
    let (home, inputs) = agreed_home(&large);
    let Some(crate::plan::track::Base::Digest(_)) = kept(home.path(), "lock") else {
        panic!("a large agreement is kept as a digest");
    };
    assert!(
        cache_bytes(home.path()).len() < 1024,
        "the cache does not hold the file"
    );

    // One side moved: the digest says which.
    put(&machine(home.path(), "lock"), &format!("{large}mine\n"));
    assert_eq!(plan(&inputs).actions(), vec![Action::Sync]);

    put(&copy(home.path(), "lock"), &format!("{large}theirs\n"));
    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    let diff = planned.changes[0].diff.as_ref().expect("a diff");
    assert!(
        !matches!(diff.kind, DiffKind::Texts(_)),
        "no last-sync bytes to diff from: {diff:?}"
    );
    let rendered = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        rendered.contains("+++ ~/.lock (this machine)"),
        "{rendered}"
    );
    assert!(rendered.contains("-theirs"), "{rendered}");
    assert!(rendered.contains("+mine"), "{rendered}");
}

#[test]
fn an_agreement_is_forgotten_once_its_target_is_no_longer_tracked() {
    let home = guarded_home();
    for name in ["lock", "gone"] {
        put(&machine(home.path(), name), "a\n");
        put(&copy(home.path(), name), "a\n");
    }
    let both = inputs(&home, &layer(&["lock", "gone"]));
    apply(&both);
    assert!(base(home.path(), "gone").is_some());

    // While a target is blocked, what it declares cannot be read, so
    // nothing is forgotten.
    let blocked = inputs(
        &home,
        &format!(
            "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n{}{}",
            layer(&["lock"]),
            inline("~/.b", "{{who}}\\n")
        ),
    );
    assert!(
        blocked
            .resolved
            .targets
            .iter()
            .any(|target| matches!(target, Resolution::Blocked(_))),
        "the layer blocks a target"
    );
    apply(&blocked);
    assert!(base(home.path(), "gone").is_some(), "kept while blocked");

    let one = inputs(&home, &layer(&["lock"]));
    let before = cache_bytes(home.path());
    assert!(!apply(&one).executed);
    assert!(base(home.path(), "gone").is_none(), "forgotten");
    assert_eq!(base(home.path(), "lock").as_deref(), Some(&b"a\n"[..]));
    let forgotten = cache_bytes(home.path());
    assert_ne!(forgotten, before);
    apply(&one);
    assert_eq!(
        cache_bytes(home.path()),
        forgotten,
        "a second apply writes nothing"
    );

    // Plan never writes the cache, even with an agreement to forget.
    let none = inputs(&home, "");
    plan(&none);
    assert_eq!(cache_bytes(home.path()), forgotten);
    apply(&none);
    assert!(base(home.path(), "lock").is_none());
}

#[test]
fn a_bare_apply_announces_the_carry_writes_no_repo_copy_and_exits_converged() {
    let (home, inputs) = agreed_home("a\n");
    assert_eq!(base(home.path(), "lock").as_deref(), Some(&b"a\n"[..]));
    put(&machine(home.path(), "lock"), "b\n");

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Sync]);
    assert_eq!(exit(&planned, Mode::Plan), Exit::Converged);
    assert_eq!(
        text(&planned.changes[0]),
        "--- ~/.lock (repo)\n+++ ~/.lock (this machine)\n@@ -1 +1 @@\n-a\n+b\n"
    );
    let rendered = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(rendered.contains("  < ~/.lock  ("), "{rendered}");
    assert!(
        rendered.ends_with("0 unchanged, 1 to sync.\n"),
        "{rendered}"
    );

    let applied = run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("apply");
    assert!(!applied.executed);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    assert_eq!(read(&copy(home.path(), "lock")).as_deref(), Some("a\n"));
    assert_eq!(read(&machine(home.path(), "lock")).as_deref(), Some("b\n"));
    assert_eq!(base(home.path(), "lock").as_deref(), Some(&b"a\n"[..]));
}

#[test]
fn sync_carries_the_machine_copy_into_the_repo_and_claims_only_the_copy() {
    let (home, inputs) = agreed_home("a\n");
    put(&machine(home.path(), "lock"), "b\n");

    let synced = sync(&inputs);
    assert!(synced.executed);
    assert_eq!(exit(&synced, Mode::Sync), Exit::Converged);
    assert_eq!(read(&copy(home.path(), "lock")).as_deref(), Some("b\n"));
    assert_eq!(base(home.path(), "lock").as_deref(), Some(&b"b\n"[..]));

    let ledger = LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("the ledger")
        .value;
    let copy_key = Portable::parse_in("~/.config/bx/files/lock", home.path()).expect("a path");
    let entry = ledger.get(&copy_key).expect("the repo copy is bx's");
    assert_eq!(entry.mechanism, Mechanism::Own);
    let machine_key = Portable::parse_in("~/.lock", home.path()).expect("a path");
    assert!(
        ledger.get(&machine_key).is_none(),
        "the machine's copy is the tool's"
    );

    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
    assert!(!sync(&inputs).executed, "a second sync has nothing to do");
}

#[test]
fn a_repo_change_is_written_onto_the_machine_by_a_bare_apply_unclaimed() {
    let (home, inputs) = agreed_home("a\n");
    put(&copy(home.path(), "lock"), "c\n");

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Modify]);
    assert!(
        planned.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.starts_with("the repo's copy changed")),
        "{:?}",
        planned.changes[0].note
    );
    assert!(apply(&inputs).executed);
    assert_eq!(read(&machine(home.path(), "lock")).as_deref(), Some("c\n"));
    assert_eq!(base(home.path(), "lock").as_deref(), Some(&b"c\n"[..]));
    let ledger = LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("the ledger")
        .value;
    assert!(ledger.is_empty(), "nothing is claimed: {ledger:?}");

    // The tool rewrites it: that is this machine's change, not an edit
    // of a file bx owns.
    put(&machine(home.path(), "lock"), "d\n");
    assert_eq!(plan(&inputs).actions(), vec![Action::Sync]);
}

#[test]
fn both_sides_changed_is_a_conflict_showing_both_diffs_and_nothing_is_written() {
    let (home, inputs) = agreed_home("a\nkeep\n");
    put(&machine(home.path(), "lock"), "mine\nkeep\n");
    put(&copy(home.path(), "lock"), "theirs\nkeep\n");

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);
    let Some(DiffKind::Texts(texts)) = planned.changes[0].diff.as_ref().map(|d| &d.kind) else {
        panic!("both sides' diffs: {:?}", planned.changes[0].diff);
    };
    assert_eq!(
        texts,
        &vec![
            "--- ~/.lock (last sync)\n+++ ~/.lock (this machine)\n@@ -1,2 +1,2 @@\n\
                     -a\n+mine\n keep\n"
                .to_string(),
            "--- ~/.lock (last sync)\n+++ ~/.lock (repo)\n@@ -1,2 +1,2 @@\n\
                     -a\n+theirs\n keep\n"
                .to_string(),
        ]
    );
    let rendered = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(rendered.contains("+mine"), "{rendered}");
    assert!(rendered.contains("+theirs"), "{rendered}");

    let synced = run(&inputs, Mode::Sync, &mut |_| panic!("nothing to approve")).expect("sync");
    assert!(!synced.executed);
    assert_eq!(exit(&synced, Mode::Sync), Exit::Pending);
    assert_eq!(
        read(&machine(home.path(), "lock")).as_deref(),
        Some("mine\nkeep\n")
    );
    assert_eq!(
        read(&copy(home.path(), "lock")).as_deref(),
        Some("theirs\nkeep\n")
    );
    assert_eq!(
        base(home.path(), "lock").as_deref(),
        Some(&b"a\nkeep\n"[..])
    );

    // Made the same by hand, the two agree again.
    put(&copy(home.path(), "lock"), "mine\nkeep\n");
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_difference_with_no_agreement_recorded_is_a_conflict_never_a_guess() {
    let home = guarded_home();
    put(&machine(home.path(), "lock"), "mine\n");
    put(&copy(home.path(), "lock"), "theirs\n");
    let inputs = inputs(&home, &layer(&["lock"]));

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    assert_eq!(
        text(&planned.changes[0]),
        "--- ~/.lock (repo)\n+++ ~/.lock (this machine)\n@@ -1 +1 @@\n-theirs\n+mine\n"
    );
    assert!(
        planned.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("no sync on this machine has recorded")),
    );
    assert!(!sync(&inputs).executed);
    assert_eq!(
        read(&copy(home.path(), "lock")).as_deref(),
        Some("theirs\n")
    );
}

#[test]
fn a_missing_side_is_filled_from_the_other_and_nothing_on_either_is_unchanged() {
    let home = guarded_home();
    put(&copy(home.path(), "fresh"), "repo\n");
    put(&machine(home.path(), "new"), "machine\n");
    let inputs = inputs(&home, &layer(&["fresh", "new", "none"]));

    let planned = plan(&inputs);
    assert_eq!(
        planned.actions(),
        vec![Action::Create, Action::Sync, Action::Unchanged]
    );
    assert_eq!(
        planned.changes[2].note.as_deref(),
        Some("neither this machine nor the repo has it yet")
    );

    // A bare apply writes the machine's copy and leaves the repo alone.
    assert!(apply(&inputs).executed);
    assert_eq!(
        read(&machine(home.path(), "fresh")).as_deref(),
        Some("repo\n")
    );
    assert_eq!(read(&copy(home.path(), "new")), None);
    // Only what the apply wrote is agreed: the carry it left undone
    // is not.
    assert_eq!(base(home.path(), "fresh").as_deref(), Some(&b"repo\n"[..]));
    assert_eq!(base(home.path(), "new"), None);
    assert_eq!(
        plan(&inputs).actions(),
        vec![Action::Unchanged, Action::Sync, Action::Unchanged]
    );

    let synced = sync(&inputs);
    assert!(synced.executed);
    assert_eq!(
        read(&copy(home.path(), "new")).as_deref(),
        Some("machine\n")
    );
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged; 3]);
}

#[test]
fn a_side_that_is_not_a_regular_file_is_a_conflict() {
    let home = guarded_home();
    std::fs::create_dir_all(machine(home.path(), "dir")).expect("a directory");
    put(&copy(home.path(), "dir"), "x\n");
    let inputs = inputs(&home, &layer(&["dir"]));
    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    assert_eq!(
        planned.changes[0].note.as_deref(),
        Some("this machine's copy is not a regular file, so bx cannot track it")
    );
}

#[test]
fn a_side_whose_directory_cannot_hold_it_is_a_conflict_with_no_write() {
    let home = guarded_home();
    // This machine's copy would go inside a file.
    put(&home.child(".blocked"), "a file\n");
    put(&copy(home.path(), "in"), "repo\n");
    // The repo's copy would go inside a file.
    put(&home.child(".config/bx/stuck"), "a file\n");
    put(&home.child(".out"), "machine\n");
    let inputs = inputs(
        &home,
        "[[target]]\npath = \"~/.blocked/in\"\nfile = \"files/in\"\n\
                 direction = \"track\"\n\
                 [[target]]\npath = \"~/.out\"\nfile = \"stuck/out\"\ndirection = \"track\"\n",
    );
    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict; 2]);
    for change in &planned.changes {
        assert!(
            change
                .note
                .as_deref()
                .is_some_and(|n| n.contains("not a directory") || n.contains("cannot")),
            "{change:?}"
        );
    }
    assert!(!sync(&inputs).executed);
}

/// The home the sync crash child runs in. Passed per command.
const SYNC_CRASH_HOME: &str = "BX_PLAN_SYNC_CRASH_HOME";

/// Two tracked targets this machine changed since they agreed, so a
/// sync carries both.
fn seed_sync_crash(home: &Path) {
    std::fs::create_dir_all(home).expect("the crash home");
    for name in ["one", "two"] {
        put(&machine(home, name), "old\n");
        put(&copy(home, name), "old\n");
    }
    seed(home, &layer(&["one", "two"]));
    run(&load(home), Mode::Apply, &mut |_| {
        panic!("nothing to approve")
    })
    .expect("the agreeing apply");
    for name in ["one", "two"] {
        put(&machine(home, name), "new\n");
    }
}

#[test]
#[ignore = "spawned by the crash harness; it aborts on purpose"]
fn sync_crash_child() {
    let Some(home) = std::env::var_os(SYNC_CRASH_HOME) else {
        return;
    };
    sync(&load(Path::new(&home)));
}

#[test]
fn a_sync_killed_at_any_journal_phase_leaves_the_repo_copies_all_old_or_all_new() {
    let guard = guarded_home();
    let boundaries = (0..2)
        .flat_map(|index| crash_phases().map(move |phase| (index, phase)))
        .chain(finish_crash_phases().map(|phase| (2, phase)));
    let mut crossed = 0;
    for (index, phase) in boundaries {
        let at = format!("{index}:{phase}");
        let home = guard.child(format!("crash-{index}-{phase}"));
        seed_sync_crash(&home);
        let output = crate::testing::ignored_child("plan::tests::track::sync_crash_child")
            .env("BX_CRASH_AT", &at)
            .env(SYNC_CRASH_HOME, &home)
            .env_remove("LLVM_PROFILE_FILE")
            .output()
            .expect("spawn the crash child");
        assert!(!output.status.success(), "{at}: the child did not stop");

        let inputs = load(&home);
        let recovering = sync(&inputs);
        assert!(
            recovering.recovered.is_some(),
            "{at}: nothing was recovered"
        );
        let copies: Vec<Option<String>> =
            ["one", "two"].map(|name| read(&copy(&home, name))).into();
        assert!(
            copies == [Some("old\n".into()), Some("old\n".into())]
                || copies == [Some("new\n".into()), Some("new\n".into())],
            "{at}: half old, half new: {copies:?}"
        );
        // The next sync finishes what the interrupted one began.
        sync(&inputs);
        assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged; 2], "{at}");
        for name in ["one", "two"] {
            assert_eq!(read(&copy(&home, name)).as_deref(), Some("new\n"), "{at}");
            assert_eq!(
                read(&machine(&home, name)).as_deref(),
                Some("new\n"),
                "{at}"
            );
        }
        crossed += 1;
    }
    assert_eq!(
        crossed,
        2 * crash_phases().len() + finish_crash_phases().len()
    );
}
