//! `bx apply` and `bx sync` over a file bx owns whole that was edited since
//! bx wrote it, answered *save mine to the repo* or *merge*: the save
//! `bx add` makes, decided by the same function and carried out only once
//! confirmed.

use super::*;

/// `~/.a` written by bx from the repo file `files/a`, holding `body`,
/// through a real apply, so its base is kept.
fn applied(body: &str) -> crate::testing::GuardedHome {
    let home = guarded_home();
    seed(
        home.path(),
        "[[target]]\npath = \"~/.a\"\nfile = \"files/a\"\n",
    );
    let files = home.child(".config/bx/files");
    std::fs::create_dir_all(&files).expect("files");
    std::fs::write(files.join("a"), body).expect("the body");
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("bx writes it");
    home
}

fn tty(home: &Path) -> Env {
    Env {
        stdin_tty: true,
        ..env(home)
    }
}

fn repo_body(home: &crate::testing::GuardedHome) -> String {
    std::fs::read_to_string(home.child(".config/bx/files/a")).expect("the body")
}

/// Apply at a terminal, answering every question with `answer` and the
/// confirmation with `confirm`, and return the exit, the output and every
/// question's choices.
fn answering(
    home: &Path,
    answer: Answer,
    confirm: bool,
) -> (Exit, String, Vec<Vec<(&'static str, Answer)>>) {
    let mut out = Vec::new();
    let mut offered = Vec::new();
    let exit = apply_answering(
        &tty(home),
        false,
        &mut out,
        &mut || Ok(confirm),
        Some(&mut |_, choices| {
            offered.push(choices.to_vec());
            Ok(answer)
        }),
    )
    .expect("apply");
    (exit, text(&out).to_string(), offered)
}

#[test]
fn an_edit_only_this_machine_made_offers_save_and_saving_empties_the_next_plan() {
    let home = applied("bx\n");
    std::fs::write(home.child(".a"), "mine\n").expect("the edit");

    let (exit, shown, offered) = answering(home.path(), Answer::Save, true);

    assert_eq!(
        offered,
        vec![vec![CHOICES[0], CHOICES[1], SAVE, SHOW_THREE_WAY]],
        "{shown}"
    );
    assert_eq!(exit, Exit::Converged, "{shown}");
    assert!(
        shown.contains("+mine"),
        "what saving writes is shown: {shown}"
    );
    assert!(
        shown.ends_with("Saved 1 edit(s) into the repo; bx sync commits and pushes them.\n"),
        "{shown}"
    );
    assert_eq!(repo_body(&home), "mine\n");
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"mine\n");

    let mut out = Vec::new();
    let exit = crate::command::plan(&env(home.path()), &mut out).expect("plan");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
}

#[test]
fn a_save_declined_at_the_confirmation_writes_nothing() {
    let home = applied("bx\n");
    std::fs::write(home.child(".a"), "mine\n").expect("the edit");

    let (exit, _, _) = answering(home.path(), Answer::Save, false);

    assert_eq!(exit, Exit::Pending);
    assert_eq!(repo_body(&home), "bx\n");
}

#[test]
fn both_sides_changed_offers_a_clean_merge_and_writes_it_to_both() {
    let home = applied("one\ntwo\nthree\n");
    std::fs::write(home.child(".a"), "ONE\ntwo\nthree\n").expect("the edit");
    std::fs::write(home.child(".config/bx/files/a"), "one\ntwo\nTHREE\n").expect("theirs");

    let (exit, shown, offered) = answering(home.path(), Answer::Save, true);

    assert_eq!(offered[0][2], MERGE, "{shown}");
    assert_eq!(exit, Exit::Converged, "{shown}");
    assert!(shown.contains("Applied 1 change(s)."), "{shown}");
    assert_eq!(repo_body(&home), "ONE\ntwo\nTHREE\n");
    assert_eq!(
        std::fs::read(home.child(".a")).expect("merged"),
        b"ONE\ntwo\nTHREE\n"
    );
    let mut out = Vec::new();
    let exit = crate::command::plan(&env(home.path()), &mut out).expect("plan");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
}

#[test]
fn a_merge_that_conflicts_is_not_offered_at_the_question() {
    let home = applied("one\n");
    std::fs::write(home.child(".a"), "mine\n").expect("the edit");
    std::fs::write(home.child(".config/bx/files/a"), "theirs\n").expect("theirs");

    let (_, _, offered) = answering(home.path(), Answer::Keep, false);

    assert_eq!(offered, vec![vec![CHOICES[0], CHOICES[1], SHOW_THREE_WAY]]);
}

#[test]
fn a_saved_row_says_so_and_a_merged_row_is_the_modify_it_wrote() {
    for (theirs, action, said) in [
        (None, crate::report::Action::Unchanged, crate::plan::SAVED),
        (
            Some("one\ntwo\nTHREE\n"),
            crate::report::Action::Modify,
            crate::plan::MERGED,
        ),
    ] {
        let home = applied("one\ntwo\nthree\n");
        std::fs::write(home.child(".a"), "ONE\ntwo\nthree\n").expect("the edit");
        if let Some(theirs) = theirs {
            std::fs::write(home.child(".config/bx/files/a"), theirs).expect("theirs");
        }
        let inputs = crate::plan::Inputs::load(&env(home.path())).expect("inputs");

        let report = crate::plan::answered(&inputs, crate::plan::Mode::Apply, &mut |report| {
            assert!(report.questions[0].save.is_some(), "a save is offered");
            Ok(crate::plan::Approval {
                approved: true,
                saved: std::collections::BTreeSet::from([0]),
                ..Default::default()
            })
        })
        .expect("apply");

        assert!(report.executed);
        assert_eq!(report.saved, vec![0]);
        assert_eq!(report.changes[0].action, action);
        let note = report.changes[0].note.as_deref().unwrap_or_default();
        assert!(note.contains(said), "{note}");
        assert!(
            !note.contains("at a terminal"),
            "the question gave way: {note}"
        );
    }
}

#[test]
fn plan_alone_decides_no_save_so_it_merges_nothing() {
    let home = applied("bx\n");
    std::fs::write(home.child(".a"), "mine\n").expect("the edit");
    let inputs = crate::plan::Inputs::load(&env(home.path())).expect("inputs");

    let report = crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| {
        panic!("plan never asks")
    })
    .expect("plan");

    assert_eq!(report.questions.len(), 1);
    assert!(report.questions[0].save.is_none(), "plan merges nothing");
}

#[test]
fn a_save_whose_machine_or_repo_file_changed_while_its_question_was_open_writes_nothing() {
    for moved in [".a", ".config/bx/files/a"] {
        let home = applied("bx\n");
        std::fs::write(home.child(".a"), "mine\n").expect("the edit");
        let inputs = crate::plan::Inputs::load(&env(home.path())).expect("inputs");
        let state = crate::state::StateDir::resolve(home.path());
        let ledger = std::fs::read(state.ledger()).expect("the ledger");

        let refused = crate::plan::answered(&inputs, crate::plan::Mode::Apply, &mut |report| {
            assert!(report.questions[0].save.is_some(), "a save is offered");
            std::fs::write(home.child(moved), "changed meanwhile\n").expect("the change");
            Ok(crate::plan::Approval {
                approved: true,
                saved: std::collections::BTreeSet::from([0]),
                ..Default::default()
            })
        });

        assert!(
            matches!(
                refused,
                Err(crate::plan::Error::Fs(crate::fs::Error::Changed { ref path, .. }))
                    if path == &home.child(moved)
            ),
            "{moved}: {refused:?}"
        );
        let (machine, repo) = if moved == ".a" {
            ("changed meanwhile\n", "bx\n")
        } else {
            ("mine\n", "changed meanwhile\n")
        };
        assert_eq!(repo_body(&home), repo, "{moved}: the repo is as it was");
        assert_eq!(
            std::fs::read_to_string(home.child(".a")).expect("the file"),
            machine,
            "{moved}"
        );
        assert!(
            !state.root().join("saved.mpk").exists(),
            "{moved}: nothing is recorded for bx sync to commit"
        );
        assert_eq!(
            std::fs::read(state.ledger()).expect("the ledger"),
            ledger,
            "{moved}: the ledger is as it was"
        );
    }
}
