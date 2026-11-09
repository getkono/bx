use super::*;

/// Apply `~/.a` and `~/.b`, then load a configuration naming `~/.b`
/// alone, as though `~/.a`'s `[[target]]` was deleted by hand.
fn dropped(home: &GuardedHome) -> Inputs {
    let both = format!("{}{}", inline("~/.a", "a\\n"), inline("~/.b", "b\\n"));
    apply(&inputs(home, &both));
    inputs(home, &inline("~/.b", "b\\n"))
}

fn ledger(home: &GuardedHome) -> LedgerView {
    LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("the ledger")
        .value
}

#[test]
fn a_file_whose_target_was_deleted_is_announced_as_undone() {
    let home = guarded_home();
    let inputs = dropped(&home);

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Unchanged, Action::Undo]);
    let row = &report.changes[1];
    assert_eq!(row.target, "~/.a");
    // Concealed: nothing says any more whether it was a secret.
    assert_eq!(
        row.diff.as_ref().map(|diff| &diff.kind),
        Some(&DiffKind::Summary {
            before: Some(2),
            after: 0,
            why: crate::plan::diff::Why::Secret,
        })
    );
    assert_eq!(
        row.note.as_deref(),
        Some("bx created it; the configuration no longer declares it, so apply removes it")
    );
    assert_eq!(row.origin, Origin::unknown(&inputs.state().ledger()));
    assert_eq!(exit(&report, Mode::Plan), Exit::Pending);
}

#[test]
fn apply_removes_it_as_rm_would_and_the_next_plan_is_empty() {
    let home = guarded_home();
    // The home before `~/.a` was ever declared, but for bx's own records.
    let before = snapshot(home.path(), &[]);
    let inputs = dropped(&home);
    let a = Portable::parse_in("~/.a", home.path()).expect("a path");

    let planned = plan(&inputs);
    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(
        applied.changes, planned.changes,
        "apply does what plan said"
    );
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    assert!(!home.child(".a").exists(), "removed");
    assert_eq!(std::fs::read(home.child(".b")).expect("kept"), b"b\n");
    assert!(ledger(&home).get(&a).is_none(), "its entry is gone");
    assert!(!StateDir::resolve(home.path()).journal().exists());

    let again = plan(&inputs);
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert_eq!(exit(&again, Mode::Plan), Exit::Converged);
    // Nothing but `~/.b`, bx's records and the repo, with the directory
    // the repo sits in, changed.
    let skip = [".local", ".config", ".b"];
    assert_eq!(
        snapshot(home.path(), &skip),
        before
            .into_iter()
            .filter(|(rel, ..)| !skip.iter().any(|prefix| rel.starts_with(prefix)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn sync_takes_it_back_as_apply_does() {
    let home = guarded_home();
    let inputs = dropped(&home);

    let synced = run(&inputs, Mode::Sync, &mut |_| Ok(true)).expect("sync");
    assert!(synced.executed);
    assert_eq!(synced.actions(), vec![Action::Unchanged, Action::Undo]);
    assert!(!home.child(".a").exists());
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_target_switched_off_is_taken_back_the_same_way() {
    let home = guarded_home();
    let both = format!("{}{}", inline("~/.a", "a\\n"), inline("~/.b", "b\\n"));
    apply(&inputs(&home, &both));
    let off = format!(
        "{}enabled = false\n{}",
        inline("~/.a", "a\\n"),
        inline("~/.b", "b\\n")
    );

    let report = plan(&inputs(&home, &off));
    assert_eq!(report.actions(), vec![Action::Unchanged, Action::Undo]);
    assert_eq!(report.changes[1].target, "~/.a");
}

#[test]
fn a_configuration_declaring_nothing_takes_back_nothing() {
    let home = guarded_home();
    apply(&inputs(&home, &inline("~/.a", "a\\n")));
    let owned = ledger(&home);
    // Switched off, it is all the configuration says: nothing is declared.
    let off = format!("{}enabled = false\n", inline("~/.a", "a\\n"));

    for layer in ["", off.as_str()] {
        let inputs = inputs(&home, layer);
        let report = plan(&inputs);
        assert_eq!(report.actions(), vec![Action::Undeclared], "{layer:?}");
        let note = report.changes[0].note.as_deref().expect("a note");
        assert!(
            note.starts_with("the configuration declares nothing at all"),
            "{note}"
        );
        assert!(note.ends_with("`bx rm ~/.a` releases it"), "{note}");
        assert_eq!(exit(&report, Mode::Plan), Exit::Converged);
        assert!(!apply(&inputs).executed, "{layer:?}");
        assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"a\n");
        assert_eq!(ledger(&home), owned);
    }
}

#[test]
fn a_file_bx_replaced_gets_its_earlier_bytes_and_mode_back() {
    let home = guarded_home();
    // Claimed as it was found at 0600, then changed by the repo.
    home.write(".a", "bx\n");
    fs::set_mode(&home.child(".a"), FileMode::PRIVATE_FILE).expect("chmod");
    let claim = "[[target]]\npath = \"~/.a\"\ncontent = \"bx\\n\"\nmode = \"0600\"\n";
    apply(&inputs(&home, claim));
    let changed = "[[target]]\npath = \"~/.a\"\ncontent = \"v2\\n\"\nmode = \"0644\"\n";
    apply(&inputs(&home, changed));
    assert_eq!(std::fs::read(home.child(".a")).expect("changed"), b"v2\n");
    let inputs = inputs(&home, &inline("~/.b", "b\\n"));

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Create, Action::Undo]);
    assert_eq!(
        planned.changes[1].note.as_deref(),
        Some(
            "bx replaced the file that was here; the configuration no longer declares it, so \
             apply puts that file back"
        )
    );
    assert_eq!(
        planned.changes[1].diff.as_ref().map(|diff| &diff.kind),
        Some(&DiffKind::Summary {
            before: Some(3),
            after: 3,
            why: crate::plan::diff::Why::Secret,
        })
    );

    let applied = apply(&inputs);
    assert_eq!(applied.changes, planned.changes);
    assert_eq!(std::fs::read(home.child(".a")).expect("restored"), b"bx\n");
    assert_eq!(mode_of(&home.child(".a")), 0o600);
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_file_claimed_as_it_was_found_stays_and_is_only_forgotten() {
    let home = guarded_home();
    home.write(".a", "bx\n");
    apply(&inputs(&home, &inline("~/.a", "bx\\n")));
    let inputs = inputs(&home, &inline("~/.b", "b\\n"));

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Create, Action::Release]);
    assert_eq!(planned.changes[1].diff, None);
    assert_eq!(
        planned.changes[1].note.as_deref(),
        Some(
            "it already holds what was here before bx wrote it; the configuration no longer \
             declares it, so bx leaves it as it is and stops managing it"
        )
    );
    apply(&inputs);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"bx\n");
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_file_dropped_from_a_tree_is_taken_back_alone_with_the_directories_bx_made() {
    let home = guarded_home();
    home.write(".config/bx/files/t/keep", "k\n");
    home.write(".config/bx/files/t/deep/gone", "g\n");
    let tree = "[[target]]\npath = \"~/.t\"\ntree = \"files/t\"\n";
    apply(&inputs(&home, tree));
    assert!(home.child(".t/deep/gone").exists());
    std::fs::remove_dir_all(home.child(".config/bx/files/t/deep")).expect("the removal");
    let inputs = inputs(&home, tree);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Unchanged, Action::Undo]);
    assert_eq!(planned.changes[1].target, "~/.t/deep/gone");
    apply(&inputs);
    assert!(
        !home.child(".t/deep").exists(),
        "the directory bx made goes"
    );
    assert_eq!(std::fs::read(home.child(".t/keep")).expect("kept"), b"k\n");
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_directory_and_a_link_bx_made_are_taken_back() {
    let home = guarded_home();
    let made = format!(
        "[[target]]\npath = \"~/.d\"\ndir = true\n{}{}",
        super::symlink("~/.l", "there"),
        inline("~/.b", "b\\n")
    );
    apply(&inputs(&home, &made));
    assert!(home.child(".d").is_dir());
    let inputs = inputs(&home, &inline("~/.b", "b\\n"));

    let planned = plan(&inputs);
    assert_eq!(
        planned.actions(),
        vec![Action::Unchanged, Action::Undo, Action::Undo]
    );
    assert_eq!(
        super::link(&planned.changes[2]),
        (Some("there"), None),
        "{:?}",
        planned.changes
    );
    apply(&inputs);
    assert!(!home.child(".d").exists());
    assert!(std::fs::symlink_metadata(home.child(".l")).is_err());
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_directory_bx_narrowed_gets_its_earlier_mode_back() {
    let home = guarded_home();
    std::fs::create_dir(home.child(".d")).expect("the user's directory");
    fs::set_mode(&home.child(".d"), FileMode::DEFAULT_DIR).expect("chmod");
    let narrowed = format!(
        "[[target]]\npath = \"~/.d\"\ndir = true\nmode = \"0700\"\n{}",
        inline("~/.b", "b\\n")
    );
    apply(&inputs(&home, &narrowed));
    assert_eq!(mode_of(&home.child(".d")), 0o700);
    let inputs = inputs(&home, &inline("~/.b", "b\\n"));

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Unchanged, Action::Undo]);
    assert_eq!(
        planned.changes[1].diff.as_ref().map(|diff| &diff.kind),
        Some(&DiffKind::Mode {
            from: FileMode::PRIVATE_DIR,
            to: FileMode::DEFAULT_DIR,
        })
    );
    apply(&inputs);
    assert!(home.child(".d").is_dir(), "the user's directory stays");
    assert_eq!(mode_of(&home.child(".d")), 0o755);
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

/// Seed `home` so its apply takes `~/.a` back: one write.
fn seed_undo(home: &Path) {
    std::fs::create_dir_all(home).expect("the home");
    seed(home, &inline("~/.a", "a\\n"));
    assert!(apply(&load(home)).executed);
    seed(home, &inline("~/.b", "b\\n"));
    own(home, ".b", b"b\n", Mechanism::Own);
}

#[test]
fn an_undo_killed_at_any_journal_phase_recovers_to_the_clean_apply() {
    let guard = guarded_home();
    let clean = guard.child("clean");
    seed_undo(&clean);
    assert!(apply(&load(&clean)).executed);
    let want = snapshot(&clean, &[".local", ".config/bx"]);
    assert!(!clean.join(".a").exists());

    let boundaries = crate::journal::tests::crash_phases()
        .map(|phase| (0, phase))
        .into_iter()
        .chain(crate::journal::tests::finish_crash_phases().map(|phase| (1, phase)));
    let mut crossed = 0;
    for (index, phase) in boundaries {
        let at = format!("{index}:{phase}");
        let home = guard.child(format!("crash-{index}-{phase}"));
        seed_undo(&home);
        let output = super::spawn_crash_child(&home, index, phase);
        let inputs = load(&home);
        // A removal stages nothing, so the phases between staging and
        // publishing are never reached: the child finishes.
        if output.status.success() {
            assert_eq!(snapshot(&home, &[".local", ".config/bx"]), want, "{at}");
            continue;
        }
        crossed += 1;
        assert!(plan(&inputs).interrupted.is_some(), "{at}");
        let recovering = apply(&inputs);
        assert!(recovering.recovered.is_some(), "{at}");
        apply(&inputs);
        assert_eq!(snapshot(&home, &[".local", ".config/bx"]), want, "{at}");
        assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged], "{at}");
    }
    assert!(crossed >= 4, "only {crossed} phases were crossed");
}

#[test]
fn an_edited_file_is_announced_as_released_and_apply_keeps_it_and_forgets_it() {
    let home = guarded_home();
    let inputs = dropped(&home);
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    let a = Portable::parse_in("~/.a", home.path()).expect("a path");
    let b = Portable::parse_in("~/.b", home.path()).expect("a path");

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Unchanged, Action::Release]);
    assert_eq!(report.changes[1].target, "~/.a");
    assert_eq!(report.changes[1].diff, None);
    assert_eq!(
        report.changes[1].note.as_deref(),
        Some(
            "edited since bx last wrote it; the configuration no longer declares it, so the \
             edits are yours: bx keeps the file as it is and stops managing it"
        )
    );
    // Pending work, announced before `apply` does it.
    assert_eq!(exit(&report, Mode::Plan), Exit::Pending);
    assert!(ledger(&home).get(&a).is_some(), "plan forgets nothing");

    // Everything but the state directory, whose ledger is what changes.
    let before = snapshot(home.path(), &[".local/state/bx"]);
    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(applied.changes, report.changes, "apply does what plan said");
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    assert_eq!(
        snapshot(home.path(), &[".local/state/bx"]),
        before,
        "not a byte of the home written"
    );
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
    assert!(ledger(&home).get(&a).is_none(), "its entry is gone");
    assert!(ledger(&home).get(&b).is_some(), "the rest stay");

    let again = plan(&inputs);
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert_eq!(exit(&again, Mode::Plan), Exit::Converged);
}

#[test]
fn a_declined_apply_forgets_nothing() {
    let home = guarded_home();
    let inputs = dropped(&home);
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    let owned = ledger(&home);

    let declined = run(&inputs, Mode::Apply, &mut |_| Ok(false)).expect("apply");
    assert!(!declined.executed);
    assert_eq!(declined.actions(), vec![Action::Unchanged, Action::Release]);
    assert_eq!(ledger(&home), owned);
}

#[test]
fn a_release_is_made_beside_the_writes_in_one_session() {
    let home = guarded_home();
    dropped(&home);
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    std::fs::write(home.child(".b"), "drift\n").expect("a declared change");
    // `~/.b` was edited too, but it is still declared: a conflict, never a
    // release. A new target is written in the same session as `~/.a` goes.
    let more = format!("{}{}", inline("~/.b", "b\\n"), inline("~/.c", "c\\n"));
    let inputs = inputs(&home, &more);

    let applied = apply(&inputs);
    assert_eq!(
        applied.actions(),
        vec![Action::Conflict, Action::Create, Action::Release]
    );
    assert!(applied.executed);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Pending, "the conflict");
    assert_eq!(std::fs::read(home.child(".c")).expect("made"), b"c\n");
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
    assert_eq!(std::fs::read(home.child(".b")).expect("kept"), b"drift\n");
    let a = Portable::parse_in("~/.a", home.path()).expect("a path");
    let b = Portable::parse_in("~/.b", home.path()).expect("a path");
    assert!(ledger(&home).get(&a).is_none());
    assert!(
        ledger(&home).get(&b).is_some(),
        "a conflict forgets nothing"
    );
}

#[test]
fn a_file_whose_mode_alone_changed_is_still_a_conflict_bx_rm_releases() {
    let home = guarded_home();
    let inputs = dropped(&home);
    std::fs::set_permissions(
        home.child(".a"),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .expect("chmod");

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Unchanged, Action::Conflict]);
    let note = report.changes[1].note.as_deref().expect("a note");
    assert!(note.ends_with("`bx rm ~/.a` releases it"), "{note}");
    assert!(!apply(&inputs).executed);
}

#[test]
fn a_file_the_user_removed_is_only_forgotten() {
    let home = guarded_home();
    let inputs = dropped(&home);
    std::fs::remove_file(home.child(".a")).expect("the removal");

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Unchanged, Action::Release]);
    let note = report.changes[1].note.as_deref().expect("a note");
    assert!(note.starts_with("it is no longer on disk; "), "{note}");
    assert!(apply(&inputs).executed);
    assert!(!home.child(".a").exists(), "nothing is written back");
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_target_held_back_still_declares_its_file() {
    let home = guarded_home();
    apply(&inputs(&home, &inline("~/.a", "a\\n")));
    let blocked = format!(
        "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n{}",
        inline("~/.a", "{{who}}\\n")
    );

    let report = plan(&inputs(&home, &blocked));
    assert_eq!(report.actions(), vec![Action::Blocked]);
}

/// Track `~/.lock` against `files/lock`, then change this machine's
/// copy and sync, so the ledger claims the repo copy.
fn synced_repo_copy(home: &GuardedHome) {
    let copy = home.child(".config/bx/files/lock");
    std::fs::create_dir_all(copy.parent().expect("a parent")).expect("parents");
    std::fs::write(&copy, "a\n").expect("the repo copy");
    std::fs::write(home.child(".lock"), "a\n").expect("the machine copy");
    let tracked = inputs(
        home,
        "[[target]]\npath = \"~/.lock\"\nfile = \"files/lock\"\ndirection = \"track\"\n",
    );
    apply(&tracked);
    std::fs::write(home.child(".lock"), "b\n").expect("the change");
    assert!(
        run(&tracked, Mode::Sync, &mut |_| Ok(true))
            .expect("sync")
            .executed
    );
    let key = Portable::parse_in("~/.config/bx/files/lock", home.path()).expect("a path");
    assert!(
        ledger(home).get(&key).is_some(),
        "sync claims the repo copy"
    );
}

#[test]
fn a_tracked_target_held_back_keeps_its_synced_repo_copy_declared() {
    // Its `file` waits on the value, so the copy cannot be named; and
    // its path waits on it, so neither side can.
    for target in [
        "[[target]]\npath = \"~/.lock\"\nfile = \"files/{{who}}\"\ndirection = \"track\"\n",
        "[[target]]\npath = \"~/.{{who}}\"\nfile = \"files/lock\"\ndirection = \"track\"\n",
    ] {
        let home = guarded_home();
        synced_repo_copy(&home);
        let blocked =
            format!("[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n{target}");
        let report = plan(&inputs(&home, &blocked));
        assert_eq!(report.actions(), vec![Action::Blocked], "{target}");
    }
}

#[test]
fn a_synced_repo_copy_is_released_once_no_tracked_target_is_held_back() {
    let home = guarded_home();
    synced_repo_copy(&home);
    let report = plan(&inputs(&home, &inline("~/.b", "b\\n")));
    // The machine's copy was there before bx, so only the repo's is bx's;
    // the repo is git's to keep, and apply never changes it.
    assert_eq!(report.actions(), vec![Action::Create, Action::Release]);
    assert_eq!(report.changes[1].target, "~/.config/bx/files/lock");

    // A held-back target that is not tracked declares no repo copy.
    let blocked = format!(
        "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n{}",
        inline("~/.b", "{{who}}\\n")
    );
    let report = plan(&inputs(&home, &blocked));
    assert_eq!(report.actions(), vec![Action::Blocked, Action::Release]);
    assert_eq!(report.changes[1].target, "~/.config/bx/files/lock");
}

#[test]
fn a_fragment_held_back_on_an_unanswered_value_still_declares_its_file() {
    let home = guarded_home();
    let env = |value: &str| {
        format!("[[env]]\nname = \"EDITOR\"\nvalue = \"{value}\"\nkind = \"interactive\"\n")
    };
    apply(&inputs(&home, &env("nvim")));
    let fragment = config::env::Place::Zshrc.fragment();
    assert!(
        ledger(&home)
            .iter()
            .any(|(path, _)| path.as_str() == fragment),
        "the fragment is bx's"
    );
    let held = format!(
        "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n{}",
        env("{{who}}")
    );

    let report = plan(&inputs(&home, &held));
    assert!(
        !report.actions().contains(&Action::Undeclared),
        "{:?}",
        report.changes
    );
    assert!(report.actions().contains(&Action::Blocked));

    // Edited by hand while held back, it is still not a conflict
    // telling the user to `bx rm` a file the configuration declares.
    let path = home.path().join(fragment.trim_start_matches("~/"));
    std::fs::write(&path, "edited\n").expect("the edit");
    let report = plan(&inputs(&home, &held));
    assert!(
        !report.actions().contains(&Action::Conflict),
        "{:?}",
        report.changes
    );
    assert!(
        report
            .changes
            .iter()
            .filter_map(|change| change.note.as_deref())
            .all(|note| !note.contains("bx rm")),
        "{:?}",
        report.changes
    );
}

#[test]
fn the_plan_view_shows_the_row() {
    let home = guarded_home();
    let inputs = dropped(&home);

    let shown = render(&plan(&inputs), View::Plan, Palette::PLAIN, home.path());
    let ledger = paths::to_portable(&inputs.state().ledger(), home.path());
    assert_eq!(
        shown,
        format!(
            "  - ~/.a  ({ledger}:0) bx created it; the configuration no longer declares it, \
             so apply removes it\n    secret, not shown: 2 bytes -> 0 bytes\nPlan: 0 to \
             create, 0 to modify, 0 conflict, 0 blocked, 1 unchanged, 1 to undo.\n"
        )
    );
}
