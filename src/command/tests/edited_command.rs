//! `bx apply` and `bx sync` over a file bx owns whole that was edited since
//! bx wrote it: asked about through the `settle` seam at a terminal, and
//! never without one or under `--yes`.

use super::*;

/// `~/.a` written by bx as `bx\n` through a real apply, so its base is kept,
/// then edited by hand, with the configuration now wanting `new\n`.
fn edited_home() -> crate::testing::GuardedHome {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "bx\\n"));
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("bx writes it");
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    seed(home.path(), &inline("~/.a", "new\\n"));
    home
}

fn tty(home: &Path) -> Env {
    Env {
        stdin_tty: true,
        ..env(home)
    }
}

#[test]
fn keep_mine_at_a_terminal_writes_nothing_and_puts_no_confirmation() {
    let home = edited_home();
    let mut out = Vec::new();
    let mut asked = Vec::new();

    let exit = apply_answering(
        &tty(home.path()),
        false,
        &mut out,
        &mut never,
        Some(&mut |q, _| {
            asked.push(q.to_string());
            Ok(Answer::Keep)
        }),
    )
    .expect("apply");

    assert_eq!(exit, Exit::Pending, "the conflict still needs a human");
    assert_eq!(
        asked,
        vec!["~/.a was edited since bx last wrote it. Keep your edit, or take bx's bytes?"]
    );
    assert!(text(&out).starts_with("  ! ~/.a"), "{}", text(&out));
    assert!(
        text(&out).ends_with("Nothing was applied.\n"),
        "{}",
        text(&out)
    );
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
}

#[test]
fn show_draws_the_three_way_view_and_asks_again_then_take_writes_once_confirmed() {
    let home = edited_home();
    let mut out = Vec::new();
    // Popped from the end: show first, then take.
    let mut answers = vec![Answer::Take, Answer::Show];
    let mut confirmed = 0;

    let exit = apply_answering(
        &tty(home.path()),
        false,
        &mut out,
        &mut || {
            confirmed += 1;
            Ok(true)
        },
        Some(&mut |_, _| Ok(answers.pop().expect("asked no more than answered"))),
    )
    .expect("apply");

    assert!(answers.is_empty(), "asked again after the view");
    assert_eq!(confirmed, 1, "the one confirmation follows the questions");
    assert_eq!(exit, Exit::Converged);
    let shown = text(&out);
    assert!(shown.contains("(bx wrote → on disk)"), "{shown}");
    assert!(shown.contains("(bx wrote → bx wants)"), "{shown}");
    assert!(shown.contains("Applied 1 change(s)."), "{shown}");
    assert_eq!(std::fs::read(home.child(".a")).expect("bx's"), b"new\n");
}

#[test]
fn take_declined_at_the_confirmation_writes_nothing() {
    let home = edited_home();

    let exit = apply_answering(
        &tty(home.path()),
        false,
        &mut Vec::new(),
        &mut || Ok(false),
        Some(&mut |_, _| Ok(Answer::Take)),
    )
    .expect("apply");

    assert_eq!(exit, Exit::Pending);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
}

#[test]
fn yes_and_no_terminal_ask_nothing_and_keep_the_edit() {
    let home = edited_home();
    let never_settled = &mut |_: &str, _: &Choices| -> Result<Answer, Error> {
        panic!("nothing should have been asked")
    };

    let mut out = Vec::new();
    let exit = apply_answering(
        &tty(home.path()),
        true,
        &mut out,
        &mut never,
        Some(&mut *never_settled),
    )
    .expect("apply --yes");
    assert_eq!(exit, Exit::Pending);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");

    let mut out = Vec::new();
    let exit = apply_answering(
        &env(home.path()),
        false,
        &mut out,
        &mut never,
        Some(never_settled),
    )
    .expect("apply with no terminal");
    assert_eq!(exit, Exit::Pending);
    assert!(text(&out).starts_with("  ! ~/.a"), "{}", text(&out));
    assert!(
        !text(&out).contains("Nothing was applied."),
        "no question, no apply: {}",
        text(&out)
    );
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
}

#[test]
fn walking_away_from_the_question_is_a_cancel() {
    let home = edited_home();
    let mut out = Vec::new();

    let exit = apply_answering(
        &tty(home.path()),
        false,
        &mut out,
        &mut never,
        Some(&mut |_, _| Err(Error::Canceled)),
    )
    .expect("a cancel is no error");

    assert_eq!(exit, Exit::Canceled);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
}

#[test]
fn every_answer_is_offered_and_keep_is_the_default() {
    assert_eq!(CHOICES[0].1, Answer::Keep);
    let answers: Vec<Answer> = CHOICES.iter().map(|(_, answer)| *answer).collect();
    assert_eq!(answers, vec![Answer::Keep, Answer::Take, Answer::Show]);
}

#[test]
fn a_deleted_file_is_asked_whether_to_keep_it_deleted_and_restore_writes_it() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "bx\\n"));
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("bx writes it");
    std::fs::remove_file(home.child(".a")).expect("the deletion");
    let mut asked = Vec::new();
    let mut offered = Vec::new();

    // Kept deleted: nothing pending, so nothing is confirmed or written.
    let exit = apply_answering(
        &tty(home.path()),
        false,
        &mut Vec::new(),
        &mut never,
        Some(&mut |q, choices| {
            asked.push(q.to_string());
            offered.push(*choices);
            Ok(Answer::Keep)
        }),
    )
    .expect("apply");
    assert_eq!(
        exit,
        Exit::Converged,
        "a deletion that stands is not pending"
    );
    assert_eq!(
        asked,
        vec!["~/.a was deleted since bx last wrote it. Keep it deleted, or restore bx's?"]
    );
    assert_eq!(offered, vec![DELETED_CHOICES]);
    assert!(!home.child(".a").exists());

    let exit = apply_answering(
        &tty(home.path()),
        false,
        &mut Vec::new(),
        &mut || Ok(true),
        Some(&mut |_, _| Ok(Answer::Take)),
    )
    .expect("apply");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(std::fs::read(home.child(".a")).expect("restored"), b"bx\n");
}

#[test]
fn keeping_a_deletion_is_the_default() {
    let answers: Vec<Answer> = DELETED_CHOICES.iter().map(|(_, answer)| *answer).collect();
    assert_eq!(answers, vec![Answer::Keep, Answer::Take, Answer::Show]);
}
