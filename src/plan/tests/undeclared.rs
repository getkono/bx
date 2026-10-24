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
fn a_file_whose_target_was_deleted_is_reported_naming_bx_rm() {
    let home = guarded_home();
    let inputs = dropped(&home);

    let report = plan(&inputs);
    assert_eq!(
        report.actions(),
        vec![Action::Unchanged, Action::Undeclared]
    );
    let row = &report.changes[1];
    assert_eq!(row.target, "~/.a");
    assert_eq!(row.diff, None);
    assert_eq!(
        row.note.as_deref(),
        Some(
            "the configuration no longer declares it, so bx leaves it as it is; \
                     `bx rm ~/.a` releases it"
        )
    );
    assert_eq!(row.origin, Origin::unknown(&inputs.state().ledger()));
    assert_eq!(exit(&report, Mode::Plan), Exit::Converged);
}

#[test]
fn apply_writes_nothing_for_it_and_the_next_plan_shows_it_again() {
    let home = guarded_home();
    let inputs = dropped(&home);
    let before = snapshot(home.path(), &[]);
    let owned = ledger(&home);

    let applied = apply(&inputs);
    assert!(!applied.executed, "nothing to write, so no session");
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    assert_eq!(snapshot(home.path(), &[]), before);
    assert_eq!(ledger(&home), owned);
    assert_eq!(plan(&inputs).changes, applied.changes);
}

#[test]
fn a_target_switched_off_is_reported_the_same_way() {
    let home = guarded_home();
    apply(&inputs(&home, &inline("~/.a", "a\\n")));
    let off = format!("{}enabled = false\n", inline("~/.a", "a\\n"));

    let report = plan(&inputs(&home, &off));
    assert_eq!(report.actions(), vec![Action::Undeclared]);
    assert_eq!(report.changes[0].target, "~/.a");
}

#[test]
fn an_edited_file_is_a_conflict_that_still_names_bx_rm() {
    let home = guarded_home();
    let inputs = dropped(&home);
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");

    let report = plan(&inputs);
    assert_eq!(report.actions(), vec![Action::Unchanged, Action::Conflict]);
    let note = report.changes[1].note.as_deref().expect("a note");
    // `bx rm` refuses to restore over an edit, so the note does not
    // promise that it releases the file.
    assert_eq!(
        note,
        "edited since bx last wrote it; the configuration no longer declares it, so bx \
                 leaves it as it is, and `bx rm ~/.a` will not restore over the change"
    );
    assert_eq!(exit(&report, Mode::Plan), Exit::Pending);

    assert!(!apply(&inputs).executed);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
}

#[test]
fn a_file_the_user_removed_is_reported_as_gone() {
    let home = guarded_home();
    let inputs = dropped(&home);
    std::fs::remove_file(home.child(".a")).expect("the removal");

    let report = plan(&inputs);
    assert_eq!(
        report.actions(),
        vec![Action::Unchanged, Action::Undeclared]
    );
    let note = report.changes[1].note.as_deref().expect("a note");
    assert!(note.starts_with("it is no longer on disk; "), "{note}");
    assert!(!apply(&inputs).executed);
    assert!(!home.child(".a").exists(), "nothing is written back");
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
fn a_synced_repo_copy_is_undeclared_once_no_tracked_target_is_held_back() {
    let home = guarded_home();
    synced_repo_copy(&home);
    let report = plan(&inputs(&home, &inline("~/.b", "b\\n")));
    assert_eq!(report.actions(), vec![Action::Create, Action::Undeclared]);
    assert_eq!(report.changes[1].target, "~/.config/bx/files/lock");

    // A held-back target that is not tracked declares no repo copy.
    let blocked = format!(
        "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n{}",
        inline("~/.b", "{{who}}\\n")
    );
    let report = plan(&inputs(&home, &blocked));
    assert_eq!(report.actions(), vec![Action::Blocked, Action::Undeclared]);
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
            "  * ~/.a  ({ledger}:0) the configuration no longer declares it, so bx \
                     leaves it as it is; `bx rm ~/.a` releases it\nPlan: 0 to create, 0 to \
                     modify, 0 conflict, 0 blocked, 1 undeclared, 1 unchanged.\n"
        )
    );
}
