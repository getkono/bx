//! Secret targets: decrypted into a private file and never shown, blocked
//! when no identity opens them, and judged by size alone over a file bx does
//! not own.

use super::*;

#[test]
fn d1_a_secret_is_decrypted_into_a_private_file_and_never_shown() {
    let home = guarded_home();
    let recipient = age_identity(&home);
    seal(&home, &recipient, b"hunter2\n");
    let inputs = inputs(&home, SECRET_TARGET);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Create]);
    let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
    assert!(
        !shown.contains("hunter2"),
        "the plaintext was shown: {shown}"
    );
    assert!(
        shown.contains("secret, not shown: no file -> 8 bytes"),
        "{shown}"
    );

    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(
        std::fs::read(home.child(".token")).expect("written"),
        b"hunter2\n"
    );
    assert_eq!(mode_of(&home.child(".token")), 0o600);
}

#[test]
fn d1_applying_an_unchanged_secret_twice_writes_nothing_the_second_time() {
    let home = guarded_home();
    let recipient = age_identity(&home);
    seal(&home, &recipient, b"hunter2\n");
    let inputs = inputs(&home, SECRET_TARGET);
    apply(&inputs);

    let after = plan(&inputs);
    assert_eq!(after.actions(), vec![Action::Unchanged]);
    let written = snapshot(home.path(), &[".local/state/bx/lock"]);
    let second =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("the second apply");
    assert!(!second.executed);
    assert_eq!(second.actions(), vec![Action::Unchanged]);
    assert_eq!(snapshot(home.path(), &[".local/state/bx/lock"]), written);

    // A new ciphertext is a modify, and still never shown.
    seal(&home, &recipient, b"hunter3\n");
    let changed = plan(&inputs);
    assert_eq!(changed.actions(), vec![Action::Modify]);
    let shown = render(&changed, View::Plan, Palette::PLAIN, home.path());
    assert!(!shown.contains("hunter"), "{shown}");
    assert!(
        shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
        "{shown}"
    );
}

#[test]
fn d1_a_locked_identity_blocks_its_secret_and_nothing_asks() {
    let home = guarded_home();
    // The default identity, locked: plan and apply may not ask for it.
    home.write(".ssh/id_ed25519", crate::secret::tests::LOCKED_SSH_KEY);
    seal(&home, crate::secret::tests::LOCKED_SSH_PUB, b"x\n");
    let layer = [SECRET_TARGET, &inline("~/.a", "a\\n")].concat();
    let inputs = inputs(&home, &layer);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Blocked, Action::Create]);
    let note = planned.changes[0].note.as_deref().expect("a note");
    assert!(
        note.contains("~/.ssh/id_ed25519 is locked by a passphrase"),
        "{note}"
    );
    assert!(
        note.contains("`identity` under [secrets] in local.toml"),
        "names the fix"
    );
    assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);

    let applied = apply(&inputs);
    assert!(applied.executed, "the rest of the plan stands");
    assert!(!home.child(".token").exists());
    assert!(home.child(".a").exists());
}

#[test]
fn d1_a_secret_no_identity_opens_is_blocked_naming_why() {
    let home = guarded_home();
    seal(&home, crate::secret::tests::SSH_PUB, b"x\n");
    let inputs = inputs(&home, SECRET_TARGET);

    let none = plan(&inputs);
    assert_eq!(none.actions(), vec![Action::Blocked]);
    assert!(
        none.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("no identity at ~/.ssh/id_ed25519")),
        "{:?}",
        none.changes[0].note
    );

    age_identity(&home);
    let inputs = load(home.path());
    let wrong = plan(&inputs);
    assert_eq!(wrong.actions(), vec![Action::Blocked]);
    assert!(
        wrong.changes[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("~/.config/age/key.txt is not one")),
        "{:?}",
        wrong.changes[0].note
    );
}

#[test]
fn d1_a_missing_ciphertext_is_an_error_naming_its_origin() {
    let home = guarded_home();
    let inputs = inputs(&home, SECRET_TARGET);

    let error = run(&inputs, Mode::Plan, &mut |_| Ok(false)).expect_err("no ciphertext");
    assert!(matches!(error, Error::Body { .. }), "{error:?}");
    assert!(error.to_string().contains("token.age"), "{error}");
}

#[test]
fn d1_a_secret_over_a_file_bx_does_not_own_is_a_conflict_shown_by_size_only() {
    let home = guarded_home();
    home.write(".token", "mine\n");
    let recipient = age_identity(&home);
    seal(&home, &recipient, b"hunter2\n");
    let inputs = inputs(&home, SECRET_TARGET);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
    assert!(
        !shown.contains("mine") && !shown.contains("hunter2"),
        "{shown}"
    );
    assert!(
        shown.contains("secret, not shown: 5 bytes -> 8 bytes"),
        "{shown}"
    );
}
