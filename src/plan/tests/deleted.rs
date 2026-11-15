//! A file bx owns whole, or a symlink bx made, deleted since bx made it,
//! settled as git settles a deletion against its base: the deletion stands
//! while bx still wants what it made there, and is a modify/delete conflict
//! once it wants something else. Either way it is a question a writing run
//! asks, *keep it deleted* changes nothing, and *restore* writes the create
//! the row was decided with.

use super::*;

/// `~/.a` written by bx as `bx\n`, then deleted by hand, with the
/// configuration now wanting `body`.
fn deleted(home: &GuardedHome, body: &str) -> Inputs {
    let written = inputs(home, &inline("~/.a", "bx\\n"));
    assert!(apply(&written).executed, "bx writes the file");
    std::fs::remove_file(home.child(".a")).expect("the deletion");
    inputs(home, &inline("~/.a", body))
}

/// `~/.l` made by bx as a link to `bx`, then deleted by hand, with the
/// configuration now wanting it to hold `text`.
fn unlinked(home: &GuardedHome, text: &str) -> Inputs {
    let made = inputs(home, &symlink("~/.l", "bx"));
    assert!(apply(&made).executed, "bx makes the link");
    std::fs::remove_file(home.child(".l")).expect("the deletion");
    inputs(home, &symlink("~/.l", text))
}

/// An `apply` approved, answering *restore* for each of `taken`.
fn answer(inputs: &Inputs, taken: &[usize]) -> Report {
    answered(inputs, Mode::Apply, &mut |_| {
        Ok(Approval {
            approved: true,
            taken: taken.iter().copied().collect(),
        })
    })
    .expect("apply runs")
}

/// The one question `report` asks, which is about a deletion.
fn the_question(report: &Report) -> &Question {
    assert_eq!(report.questions.len(), 1, "{:?}", report.questions);
    let question = &report.questions[0];
    assert!(question.deleted, "{question:?}");
    question
}

/// Answering *keep it deleted* writes nothing, applying again asks the same
/// question and writes nothing, and the deletion is still there.
fn keeping_writes_nothing_twice(home: &GuardedHome, inputs: &Inputs, path: &str, row: Action) {
    let before = snapshot(home.path(), &[".local/state/bx/lock"]);
    for _ in 0..2 {
        let kept = answer(inputs, &[]);
        assert!(!kept.executed, "only the question was work");
        assert_eq!(kept.actions(), vec![row]);
        assert_eq!(snapshot(home.path(), &[".local/state/bx/lock"]), before);
        assert!(std::fs::symlink_metadata(home.child(path)).is_err());
    }
}

#[test]
fn a_file_deleted_while_bx_still_wants_what_it_wrote_stands_and_is_not_pending() {
    let home = guarded_home();
    let inputs = deleted(&home, "bx\\n");

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Unchanged]);
    assert_eq!(
        exit(&planned, Mode::Plan),
        Exit::Converged,
        "nothing pending"
    );
    assert_eq!(the_question(&planned).row, 0);
    let note = planned.changes[0].note.as_deref().expect("a note");
    assert!(note.starts_with(decide::DELETED), "{note}");
    assert!(note.ends_with(decide::ASK_DELETED), "{note}");
    assert_eq!(
        planned.changes[0].diff, None,
        "a deletion that stands shows nothing"
    );
    // Unchanged, and still said, as `git status` says a deletion.
    let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
    assert!(shown.contains("  = ~/.a "), "{shown}");
    assert!(shown.contains(decide::DELETED), "{shown}");

    keeping_writes_nothing_twice(&home, &inputs, ".a", Action::Unchanged);
    let unasked =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("apply runs");
    assert!(!unasked.executed);
    assert!(
        !home.child(".a").exists(),
        "no run without an answer restores it"
    );
}

#[test]
fn restoring_a_deletion_that_stands_writes_bx_bytes_and_converges() {
    let home = guarded_home();
    let inputs = deleted(&home, "bx\\n");
    let planned = plan(&inputs);
    let view = the_question(&planned).three_way.clone().expect("a view");
    assert_eq!(
        view.kind,
        DiffKind::Text("--- ~/.a (deleted)\n+++ ~/.a (bx's)\n@@ -0,0 +1 @@\n+bx\n".to_string()),
        "what restoring writes"
    );

    let restored = answer(&inputs, &[0]);

    assert!(restored.executed);
    assert_eq!(restored.actions(), vec![Action::Create]);
    assert_eq!(std::fs::read(home.child(".a")).expect("restored"), b"bx\n");
    let again = plan(&inputs);
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert!(again.questions.is_empty(), "the second plan is empty");

    // `bx rm` takes it back: bx created it, so it goes again.
    let state = StateDir::resolve(home.path());
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("rm");
    assert!(!home.child(".a").exists());
}

#[test]
fn a_file_deleted_while_bx_wants_something_else_is_a_modify_delete_conflict() {
    let home = guarded_home();
    let inputs = deleted(&home, "new\\n");

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    let note = planned.changes[0].note.as_deref().expect("a note");
    assert!(note.starts_with(decide::DELETED_CHANGED), "{note}");
    assert!(note.ends_with(decide::ASK_DELETED), "{note}");
    assert_eq!(
        text(&planned.changes[0]),
        "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -0,0 +1 @@\n+new\n",
        "what bx wants there"
    );
    let view = the_question(&planned).three_way.clone().expect("a view");
    assert_eq!(
        view.kind,
        DiffKind::Text(
            "--- ~/.a (bx wrote)\n+++ ~/.a (bx wants)\n@@ -1 +1 @@\n-bx\n+new\n".to_string()
        ),
        "measured from what bx last wrote"
    );

    keeping_writes_nothing_twice(&home, &inputs, ".a", Action::Conflict);

    let restored = answer(&inputs, &[0]);
    assert_eq!(restored.actions(), vec![Action::Create]);
    assert_eq!(std::fs::read(home.child(".a")).expect("restored"), b"new\n");
    assert_eq!(exit(&restored, Mode::Apply), Exit::Converged);
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
}

#[test]
fn a_mode_change_alone_makes_a_deletion_a_conflict() {
    let home = guarded_home();
    let written = inputs(&home, &inline("~/.a", "bx\\n"));
    assert!(apply(&written).executed);
    std::fs::remove_file(home.child(".a")).expect("the deletion");
    let inputs = inputs(
        &home,
        &format!("{}mode = \"0600\"\n", inline("~/.a", "bx\\n")),
    );
    assert_eq!(plan(&inputs).actions(), vec![Action::Conflict]);
}

#[test]
fn rm_after_a_deletion_that_stands_puts_back_what_bx_replaced() {
    let home = guarded_home();
    std::fs::write(home.child(".a"), "mine\n").expect("the user's file");
    std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
        .expect("its mode");
    let private = |body: &str| format!("{}mode = \"0600\"\n", inline("~/.a", body));
    let inputs = inputs(&home, &private("mine\\n"));
    // Claimed, so bx owns it from here, with the user's bytes as its prior.
    assert!(apply(&inputs).executed);
    let inputs = super::inputs(&home, &private("bx\\n"));
    assert!(apply(&inputs).executed);
    std::fs::remove_file(home.child(".a")).expect("the deletion");
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);

    let state = StateDir::resolve(home.path());
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("rm");
    assert_eq!(std::fs::read(home.child(".a")).expect("back"), b"mine\n");
    assert_eq!(mode_of(&home.child(".a")), 0o600);
}

#[test]
fn a_file_bx_never_wrote_is_created_as_before() {
    let home = guarded_home();
    let inputs = inputs(&home, &inline("~/.a", "bx\\n"));
    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Create]);
    assert!(planned.questions.is_empty());
}

#[test]
fn a_link_deleted_while_bx_still_wants_its_text_stands_and_restore_remakes_it() {
    let home = guarded_home();
    let inputs = unlinked(&home, "bx");

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Unchanged]);
    assert_eq!(exit(&planned, Mode::Plan), Exit::Converged);
    assert_eq!(the_question(&planned).row, 0);
    let note = planned.changes[0].note.as_deref().expect("a note");
    assert!(note.ends_with(decide::ASK_DELETED), "{note}");
    assert_eq!(
        the_question(&planned).three_way.as_ref().map(|d| &d.kind),
        Some(&DiffKind::Link {
            from: None,
            to: Some("bx".to_string())
        })
    );
    keeping_writes_nothing_twice(&home, &inputs, ".l", Action::Unchanged);

    let restored = answer(&inputs, &[0]);
    assert_eq!(restored.actions(), vec![Action::Create]);
    assert_eq!(text_of(&home.child(".l")), Path::new("bx"));
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
    assert!(plan(&inputs).questions.is_empty());
}

#[test]
fn a_link_deleted_while_bx_wants_other_text_is_a_conflict() {
    let home = guarded_home();
    let inputs = unlinked(&home, "other");

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    assert_eq!(link(&planned.changes[0]), (None, Some("other")));
    the_question(&planned);
    keeping_writes_nothing_twice(&home, &inputs, ".l", Action::Conflict);

    let restored = answer(&inputs, &[0]);
    assert_eq!(restored.actions(), vec![Action::Create]);
    assert_eq!(text_of(&home.child(".l")), Path::new("other"));
}

#[test]
fn restoring_into_a_deleted_directory_announces_the_directory_it_creates() {
    let home = guarded_home();
    let written = inputs(&home, &inline("~/.config/tool/a", "bx\\n"));
    assert!(apply(&written).executed);
    std::fs::remove_dir_all(home.child(".config/tool")).expect("the deletion");

    let planned = plan(&written);
    assert_eq!(planned.actions(), vec![Action::Unchanged]);
    let note = planned.changes[0].note.as_deref().expect("a note");
    assert!(note.ends_with("creates ~/.config/tool 0755"), "{note}");

    let restored = answer(&written, &[0]);
    assert_eq!(restored.actions(), vec![Action::Create]);
    assert_eq!(
        std::fs::read(home.child(".config/tool/a")).expect("restored"),
        b"bx\n"
    );
}

#[test]
fn restoring_a_link_into_a_deleted_directory_announces_the_directory_it_creates() {
    let home = guarded_home();
    let made = inputs(&home, &symlink("~/.config/tool/l", "bx"));
    assert!(apply(&made).executed);
    std::fs::remove_dir_all(home.child(".config/tool")).expect("the deletion");

    let planned = plan(&made);
    assert_eq!(planned.actions(), vec![Action::Unchanged]);
    the_question(&planned);
    let note = planned.changes[0].note.as_deref().expect("a note");
    assert!(note.ends_with("creates ~/.config/tool 0755"), "{note}");

    let restored = answer(&made, &[0]);
    assert_eq!(restored.actions(), vec![Action::Create]);
    assert_eq!(text_of(&home.child(".config/tool/l")), Path::new("bx"));
}

/// A deletion whose restore could not land, because the directory it would
/// be made in denies its owner write, is asked nothing and announces no
/// directory: it stands, and is said to.
#[test]
fn a_deletion_beneath_a_directory_apply_cannot_write_is_not_asked_about() {
    let home = guarded_home();
    let declared = format!(
        "{}{}",
        inline("~/.config/tool/a", "bx\\n"),
        symlink("~/.config/tool/l", "bx")
    );
    let inputs = inputs(&home, &declared);
    assert!(apply(&inputs).executed);
    std::fs::remove_dir_all(home.child(".config/tool")).expect("the deletion");
    let config = home.child(".config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o555)).expect("lock");

    let planned = plan(&inputs);

    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).expect("unlock");
    assert_eq!(
        planned.actions(),
        vec![Action::Unchanged, Action::Unchanged]
    );
    assert!(planned.questions.is_empty(), "{:?}", planned.questions);
    for change in &planned.changes {
        let note = change.note.as_deref().expect("a note");
        assert!(note.starts_with(decide::DELETED), "{note}");
        assert!(!note.contains(decide::ASK_DELETED), "{note}");
        assert!(!note.contains("creates"), "{note}");
    }
}

/// A file bx generates outside its own data directory is the user's to
/// delete, as any file bx owns whole is.
#[cfg(target_os = "linux")]
#[test]
fn a_generated_file_outside_bx_s_data_directory_follows_the_deletion_rule() {
    let home = guarded_home();
    let declared = "[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"gui\"\n".to_string();
    let inputs = inputs(&home, &declared);
    assert!(apply(&inputs).executed);
    let path = config::env::ENVIRONMENT_D;
    std::fs::remove_file(home.child(&path[2..])).expect("the deletion");

    let planned = plan(&inputs);
    let row = planned
        .changes
        .iter()
        .find(|change| change.target == path)
        .expect("the file's row");
    assert_eq!(row.action, Action::Unchanged, "{:?}", row.note);
    assert!(the_question(&planned).deleted);
}

#[test]
fn a_file_bx_generates_in_its_own_data_directory_is_recreated_not_asked_about() {
    let home = guarded_home();
    let env = |value: &str| {
        format!("[[env]]\nname = \"EDITOR\"\nvalue = \"{value}\"\nkind = \"interactive\"\n")
    };
    let generated = [
        config::env::Place::Zshrc.fragment(),
        crate::shell::bash::FILE,
    ];
    let file = |path: &str| home.child(path.strip_prefix("~/").expect("under home"));
    assert!(apply(&inputs(&home, &env("nvim"))).executed);
    // Deleted while bx still wants what it wrote, and while it wants more.
    for value in ["nvim", "vim"] {
        for path in generated {
            std::fs::remove_file(file(path)).expect("the deletion");
        }
        let inputs = inputs(&home, &env(value));

        let planned = plan(&inputs);
        assert!(planned.questions.is_empty(), "{:?}", planned.questions);
        for path in generated {
            let row = planned
                .changes
                .iter()
                .find(|change| change.target == path)
                .expect("the file's row");
            assert_eq!(row.action, Action::Create, "{path}: {:?}", row.note);
        }

        // Approved with no answer, as `--yes` is: the files come back.
        assert!(answer(&inputs, &[]).executed);
        for path in generated {
            assert!(file(path).exists(), "{path} is recreated");
        }
        let again = plan(&inputs);
        assert!(
            again.actions().iter().all(|a| *a == Action::Unchanged),
            "{:?}",
            again.actions()
        );
        assert!(again.questions.is_empty());
    }
}
