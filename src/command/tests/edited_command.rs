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
fn an_edit_with_a_three_way_view_offers_it_and_keep_is_the_default() {
    let home = edited_home();
    let mut offered = Vec::new();

    apply_answering(
        &tty(home.path()),
        false,
        &mut Vec::new(),
        &mut never,
        Some(&mut |_, choices| {
            offered.push(choices.to_vec());
            Ok(Answer::Keep)
        }),
    )
    .expect("apply");

    assert_eq!(
        offered,
        vec![vec![CHOICES[0], CHOICES[1], SHOW_THREE_WAY]],
        "keep first, so a bare Enter keeps the edit"
    );
    assert_eq!(CHOICES[0].1, Answer::Keep);
}

/// The one question `apply` over `home`'s current configuration puts at a
/// terminal, and the answers it offers, answered *keep*, with any other work
/// declined.
fn the_question_put(home: &Path) -> (String, Vec<(&'static str, Answer)>) {
    let mut put = Vec::new();
    apply_answering(
        &tty(home),
        false,
        &mut Vec::new(),
        &mut || Ok(false),
        Some(&mut |q, choices| {
            put.push((q.to_string(), choices.to_vec()));
            Ok(Answer::Keep)
        }),
    )
    .expect("apply");
    assert_eq!(put.len(), 1, "{put:?}");
    put.remove(0)
}

/// Each answer *show* in `choices`, by its label.
fn shows(choices: &[(&'static str, Answer)]) -> Vec<&'static str> {
    choices
        .iter()
        .filter(|(_, answer)| *answer == Answer::Show)
        .map(|(label, _)| *label)
        .collect()
}

#[test]
fn an_edit_with_no_view_of_its_own_offers_the_row_diff_again() {
    let home = guarded_home();
    // Written by a session alone, so no base is kept to measure it from.
    own(home.path(), ".a", b"bx\n", Mechanism::Own);
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    seed(home.path(), &inline("~/.a", "new\\n"));

    let (_, choices) = the_question_put(home.path());

    assert_eq!(shows(&choices), vec![SHOW_AGAIN.0]);
}

#[test]
fn a_mode_change_is_asked_about_its_mode_and_offers_no_view() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "bx\\n"));
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("bx writes it");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
        .expect("the user's chmod");

    let (asked, choices) = the_question_put(home.path());

    assert_eq!(
        asked,
        "~/.a had its mode changed since bx set it. Keep your mode, or take bx's?"
    );
    // The bytes are bx's, so there is no diff to show: only the mode line,
    // already drawn above the question.
    assert_eq!(shows(&choices), vec![SHOW_AGAIN.0]);
}

#[test]
fn a_retargeted_link_is_asked_about_its_target() {
    let home = guarded_home();
    let link = |text: &str| format!("[[target]]\npath = \"~/.tool\"\nsymlink = \"{text}\"\n");
    seed(home.path(), &link("/opt/one"));
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("bx makes it");
    std::fs::remove_file(home.child(".tool")).expect("unlink");
    std::os::unix::fs::symlink("/opt/theirs", home.child(".tool")).expect("retarget");
    seed(home.path(), &link("/opt/two"));

    let (asked, choices) = the_question_put(home.path());

    assert_eq!(
        asked,
        "~/.tool was retargeted since bx made it. Keep your target, or take bx's?"
    );
    assert_eq!(shows(&choices), vec![SHOW_AGAIN.0]);
}

#[test]
fn a_region_edited_inside_is_asked_about_bx_s_region() {
    let home = guarded_home();
    let old = "mine\n# >>> bx >>>\nsource ~/.old\n# <<< bx <<<\n";
    own(
        home.path(),
        ".zshrc",
        old.as_bytes(),
        Mechanism::Region { comment: '#' },
    );
    std::fs::write(
        home.child(".zshrc"),
        old.replace("source ~/.old\n", "source ~/.old\nedited\n"),
    )
    .expect("the edit");
    seed(
        home.path(),
        "[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n",
    );

    let (asked, choices) = the_question_put(home.path());

    assert_eq!(
        asked,
        "bx's region in ~/.zshrc was edited since bx last wrote it. Keep your edit, or take \
         bx's region?"
    );
    assert_eq!(shows(&choices), vec![SHOW_AGAIN.0]);
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
            offered.push(choices.to_vec());
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
    assert_eq!(
        offered,
        vec![vec![DELETED_CHOICES[0], DELETED_CHOICES[1], SHOW_RESTORED]]
    );
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
    assert_eq!(answers, vec![Answer::Keep, Answer::Take]);
}

#[test]
fn show_on_a_deletion_draws_what_restoring_writes() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "bx\\n"));
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("bx writes it");
    std::fs::remove_file(home.child(".a")).expect("the deletion");
    seed(home.path(), &inline("~/.a", "new\\n"));
    let mut out = Vec::new();
    // Popped from the end: show first, then keep.
    let mut answers = vec![Answer::Keep, Answer::Show];

    apply_answering(
        &tty(home.path()),
        false,
        &mut out,
        &mut never,
        Some(&mut |_, _| Ok(answers.pop().expect("asked no more than answered"))),
    )
    .expect("apply");

    let shown = text(&out);
    assert!(shown.contains("(deleted → bx's)"), "{shown}");
    assert!(!shown.contains("(bx wrote → bx wants)"), "{shown}");
}
