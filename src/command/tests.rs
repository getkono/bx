use super::*;
use crate::plan::tests::{env, inline, seed};
use crate::testing::{guarded_home, ignored_child, run_ignored_child};

fn text(out: &[u8]) -> &str {
    std::str::from_utf8(out).expect("UTF-8 output")
}

fn never() -> Result<bool, Error> {
    panic!("nothing should have been asked")
}

/// Set on the child that actually puts every terminal prompt.
const PROMPTS_CHILD: &str = "BX_TEST_PROMPTS_CHILD";

#[test]
#[ignore = "spawned by the test below; it must run with a stdin that is not a terminal"]
fn prompts_child() {
    use crate::init::Ask as _;
    use inquire::InquireError::NotTTY;

    // Without the variable this is someone running `--ignored` by hand,
    // possibly from a terminal, where `prompt` would block on a question
    // nobody is there to answer. Do nothing rather than hang.
    if std::env::var_os(PROMPTS_CHILD).is_none() {
        return;
    }
    let answer = confirm();
    // `Ok(_)` is what both surviving mutants return, so this is the
    // assertion that kills them: with no terminal there is no answer, and
    // a wrapper that invents one would approve a write nobody confirmed.
    assert!(matches!(answer, Err(Error::Prompt(NotTTY))), "{answer:?}");
    assert!(
        ask_passphrase("~/.ssh/id_ed25519").is_none(),
        "a prompt with no terminal is no passphrase"
    );
    // `init`'s questions: a value, asked afresh or again after a
    // problem, and the files to adopt.
    let decl = crate::config::parse_str(
        "[[value]]\nname = \"a\"\nkind = \"string\"\n",
        Path::new("bx.toml"),
        Path::new("/"),
    )
    .expect("a declaration")
    .values
    .remove(0);
    for problem in [None, Some("no")] {
        let answer = crate::init::Terminal.value(&decl, problem);
        assert!(
            matches!(answer, Err(crate::init::Error::Prompt(NotTTY))),
            "{problem:?}: {answer:?}"
        );
    }
    let offered = [crate::paths::Portable::parse_in("~/.a", Path::new("/h")).expect("portable")];
    let picked = crate::init::Terminal.adopt(&offered);
    assert!(
        matches!(picked, Err(crate::init::Error::Prompt(NotTTY))),
        "{picked:?}"
    );
}

#[test]
fn esc_and_ctrl_c_at_the_confirmation_are_a_cancel_and_every_other_failure_is_an_error() {
    use inquire::InquireError;

    for key in [
        InquireError::OperationCanceled,
        InquireError::OperationInterrupted,
    ] {
        assert!(matches!(confirmation_failed(key), Error::Canceled));
    }
    assert!(matches!(
        confirmation_failed(InquireError::NotTTY),
        Error::Prompt(InquireError::NotTTY)
    ));
}

#[test]
fn every_prompt_without_a_terminal_is_a_prompt_error_and_never_an_answer() {
    // P42R1 "Untested line: the `inquire` confirmation call". `cargo
    // mutants` reported `confirm -> Ok(true)` and `-> Ok(false)` as missed.
    // The earlier round recorded it as needing a pseudo-terminal and a
    // dependency this pull request does not add, and left it. It does not:
    // the question is what `confirm` does when there is NO terminal, and
    // that is reachable by giving it one that certainly is not.
    //
    // Run in a child rather than here, because `inquire` reads the
    // process's stdin and a test must not depend on how `cargo test` was
    // invoked. In CI stdin is already not a terminal; on a developer's
    // machine it is, and this test would hang waiting for an answer. The
    // child's stdin is `/dev/null` either way, which is the same seam
    // `plan::tests`'s crash harness uses to fix a child's environment.
    run_ignored_child(
        ignored_child("command::tests::prompts_child")
            .env(PROMPTS_CHILD, "1")
            .stdin(std::process::Stdio::null()),
    );
}

#[test]
fn plan_exits_zero_when_converged_and_two_when_pending() {
    let home = guarded_home();
    seed(home.path(), "");
    let mut out = Vec::new();
    let exit = plan(&env(home.path()), &mut out).expect("plan");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(
        text(&out),
        "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
    );

    seed(home.path(), &inline("~/.a", "a\\n"));
    let mut out = Vec::new();
    let exit = plan(&env(home.path()), &mut out).expect("plan");
    assert_eq!(exit, Exit::Pending);
    assert!(text(&out).starts_with("  + ~/.a  (~/.config/bx/bx.toml:1)\n"));
    assert!(!home.child(".a").exists());
}

#[test]
fn status_shows_what_plan_hides() {
    let home = guarded_home();
    home.write(".a", "a\n");
    seed(home.path(), &inline("~/.a", "a\\n"));

    let mut shown = Vec::new();
    let exit = status(&env(home.path()), &mut shown).expect("status");
    assert_eq!(exit, Exit::Converged);
    assert!(text(&shown).contains("  = ~/.a  ("), "{}", text(&shown));

    let mut hidden = Vec::new();
    let exit = plan(&env(home.path()), &mut hidden).expect("plan");
    assert_eq!(exit, Exit::Converged);
    assert!(!text(&hidden).contains("~/.a"), "{}", text(&hidden));
}

#[test]
fn decision_4_apply_with_yes_writes_without_asking() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let mut out = Vec::new();

    let exit = apply_with(&env(home.path()), true, &mut out, &mut never).expect("apply");

    assert_eq!(exit, Exit::Converged);
    assert!(text(&out).starts_with("  + ~/.a"), "{}", text(&out));
    assert!(
        text(&out).ends_with("Applied 1 change(s).\n"),
        "{}",
        text(&out)
    );
    assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");

    let exit = plan(&env(home.path()), &mut Vec::new()).expect("plan");
    assert_eq!(exit, Exit::Converged);
}

#[test]
fn applied_counts_an_activation_capture_as_a_change() {
    // V1: the interactive file, its `~/.zshrc` region, and the capture.
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    let stub = home.child("stub");
    std::fs::write(&stub, "#!/bin/sh\nprintf 'stub_hook() { :; }\\n'\n").expect("the stub");
    std::fs::set_permissions(
        &stub,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .expect("executable");
    seed(
        home.path(),
        &format!(
            "[[activation]]\nname = \"stub\"\ncommand = [\"{}\"]\n",
            stub.display()
        ),
    );
    let mut out = Vec::new();

    let exit = apply_with(&env(home.path()), true, &mut out, &mut never).expect("apply");

    assert_eq!(exit, Exit::Converged);
    assert!(
        text(&out).contains("  + activation `stub`: run twice, output agreed; cached\n"),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).ends_with("Applied 3 change(s).\n"),
        "{}",
        text(&out)
    );

    // Recorded, so the next apply has nothing to count.
    let mut again = Vec::new();
    let exit = apply_with(&env(home.path()), true, &mut again, &mut never).expect("apply");
    assert_eq!(exit, Exit::Converged);
    assert!(!text(&again).contains("Applied"), "{}", text(&again));
}

#[test]
fn an_external_apply_stopped_short_of_is_named_with_why_and_exits_pending() {
    let home = guarded_home();
    // The declared url leads nowhere that can be fetched from.
    std::fs::write(
        home.child(".gitconfig"),
        format!(
            "[url \"file://{}/nowhere/\"]\n\tinsteadOf = https://example.invalid/\n",
            home.path().display()
        ),
    )
    .expect("~/.gitconfig");
    seed(
        home.path(),
        "[[external]]\npath = \"~/.x\"\nurl = \"https://example.invalid/x\"\n\
             rev = \"0e810e5afa27acbd074398eefbe28d13005dbc15\"\n",
    );
    let mut out = Vec::new();

    let exit = apply_with(&env(home.path()), true, &mut out, &mut never).expect("apply");

    assert_eq!(exit, Exit::Pending);
    let shown = text(&out);
    assert!(
        shown.contains("Applied 0 change(s).\n  ! ~/.x  stopped: "),
        "{shown}"
    );
    assert!(!home.child(".x").exists());
}

#[test]
fn decision_4_apply_without_yes_or_a_terminal_shows_the_plan_and_refuses() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let mut out = Vec::new();

    let error =
        apply_with(&env(home.path()), false, &mut out, &mut never).expect_err("no confirmation");

    assert!(matches!(error, Error::NeedsConfirmation), "{error:?}");
    assert!(error.to_string().contains("rerun with --yes"), "{error}");
    assert!(text(&out).starts_with("  + ~/.a"), "the plan was not shown");
    assert!(!home.child(".a").exists(), "written without confirmation");
}

#[test]
fn decision_4_apply_on_a_terminal_asks_and_honours_the_answer() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    let mut asked = 0;
    let exit = apply_with(&tty, false, &mut out, &mut || {
        asked += 1;
        Ok(false)
    })
    .expect("a declined apply");
    assert_eq!(exit, Exit::Pending, "a declined apply is still pending");
    assert_eq!(asked, 1);
    assert!(
        text(&out).ends_with("Nothing was applied.\n"),
        "{}",
        text(&out)
    );
    assert!(!home.child(".a").exists());

    let exit = apply_with(&tty, false, &mut Vec::new(), &mut || Ok(true)).expect("apply");
    assert_eq!(exit, Exit::Converged);
    assert!(home.child(".a").exists());
}

#[test]
fn apply_with_nothing_to_write_asks_nothing_and_needs_no_confirmation() {
    let home = guarded_home();
    home.write(".mine", "mine\n");
    seed(home.path(), &inline("~/.mine", "bx\\n"));
    let mut out = Vec::new();

    let exit = apply_with(&env(home.path()), false, &mut out, &mut never).expect("apply");

    assert_eq!(exit, Exit::Pending, "a conflict still needs a human");
    assert!(text(&out).starts_with("  ! ~/.mine"), "{}", text(&out));
    assert!(text(&out).ends_with(" unchanged.\n"), "{}", text(&out));
    assert_eq!(std::fs::read(home.child(".mine")).expect("kept"), b"mine\n");
}

#[test]
fn a_failing_question_stops_apply() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let error = apply_with(&tty, false, &mut Vec::new(), &mut || {
        Err(Error::NeedsConfirmation)
    })
    .expect_err("the question failed");

    assert!(matches!(error, Error::NeedsConfirmation), "{error:?}");
    assert!(!home.child(".a").exists());
}

#[test]
fn a_confirmation_walked_away_from_is_a_cancel_that_applies_nothing() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut out = Vec::new();

    let exit = apply_with(&tty, false, &mut out, &mut || Err(Error::Canceled))
        .expect("a cancel is not an error");

    assert_eq!(exit, Exit::Canceled);
    assert!(
        text(&out).ends_with(" unchanged.\nCanceled. Nothing was applied.\n"),
        "{}",
        text(&out)
    );
    assert!(!home.child(".a").exists());
    assert!(matches!(
        apply_with(&tty, false, &mut Refusing, &mut || Err(Error::Canceled)),
        Err(Error::Output(_))
    ));
}

#[test]
fn init_walked_away_from_at_a_question_is_a_cancel() {
    use crate::init::tests::WalksAway;

    let home = guarded_home();
    seed(
        home.path(),
        "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n",
    );
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut out = Vec::new();

    let exit = init_with(&tty, &[], false, &mut out, &mut WalksAway, &mut never)
        .expect("a cancel is not an error");

    assert_eq!(exit, Exit::Canceled);
    assert_eq!(
        text(&out),
        "Canceled. Nothing was written; run `bx init` again when ready.\n"
    );
    assert!(!home.child(".local/state/bx").exists());
    assert!(matches!(
        init_with(&tty, &[], false, &mut Refusing, &mut WalksAway, &mut never),
        Err(init::Error::Output(_))
    ));
}

#[test]
fn init_walked_away_from_at_the_confirmation_is_apply_s_cancel() {
    use crate::init::tests::Silent;

    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut out = Vec::new();

    let exit = init_with(&tty, &[], false, &mut out, &mut Silent, &mut || {
        Err(Error::Canceled)
    })
    .expect("a cancel is not an error");

    assert_eq!(exit, Exit::Canceled);
    assert!(
        text(&out).ends_with(
            " unchanged.\nCanceled. Nothing was applied. Run `bx init` again to pick up \
                 where this stopped.\n"
        ),
        "{}",
        text(&out)
    );
    assert!(!home.child(".a").exists());
}

#[test]
fn init_walked_away_from_at_the_offer_has_already_said_what_it_wrote() {
    use crate::init::tests::WalksAway;

    // The reported case: a fresh machine, Esc at "Manage which of these".
    let home = guarded_home();
    home.write(".zshrc", "z\n");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut out = Vec::new();

    let exit = init_with(&tty, &[], false, &mut out, &mut WalksAway, &mut never)
        .expect("a cancel is not an error");

    assert_eq!(exit, Exit::Canceled);
    assert_eq!(
        text(&out),
        "Created the config repo ~/.config/bx with bx.toml.\n\
             Canceled. Nothing was adopted. Run `bx init` again to pick up where this stopped.\n"
    );
    assert!(home.child(".config/bx/bx.toml").exists());
    assert!(!home.child(".config/bx/files").exists());

    // And the next run does pick up: the repo is found, the offer is made.
    let mut out = Vec::new();
    let exit = init_with(&tty, &[], false, &mut out, &mut WalksAway, &mut never)
        .expect("a cancel is not an error");
    assert_eq!(exit, Exit::Canceled);
    assert!(
        text(&out).starts_with("Using the config repo ~/.config/bx.\nCanceled."),
        "{}",
        text(&out)
    );
}

#[test]
fn a_cancel_at_the_confirmation_keeps_the_adoptions_already_said() {
    use crate::init::tests::Script;

    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    home.write(".zshrc", "z\n");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut script = Script {
        pick: vec!["~/.zshrc"],
        ..Script::default()
    };
    let mut out = Vec::new();

    let exit = init_with(&tty, &[], false, &mut out, &mut script, &mut || {
        Err(Error::Canceled)
    })
    .expect("a cancel is not an error");

    assert_eq!(exit, Exit::Canceled);
    assert!(
        text(&out).starts_with(
            "Using the config repo ~/.config/bx.\n  + ~/.zshrc  (copied to files/.zshrc)\n"
        ),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).ends_with(
            "Canceled. Nothing was applied. Run `bx init` again to pick up where this \
                 stopped.\n"
        ),
        "{}",
        text(&out)
    );
}

#[test]
fn init_ends_by_saying_where_the_machine_stands() {
    const NEXT: &str =
        "Manage a file with `bx add PATH`; change an answer with `bx init --set NAME=VALUE`.\n";
    assert_eq!(
        init_closing(Exit::Converged, false),
        format!("Already set up: nothing to apply. {NEXT}")
    );
    assert_eq!(
        init_closing(Exit::Converged, true),
        format!("Set up. {NEXT}")
    );
    for did in [false, true] {
        assert_eq!(
            init_closing(Exit::Pending, did),
            "Not finished: see the plan above, then run `bx init` or `bx apply` again.\n"
        );
        assert_eq!(init_closing(Exit::Error, did), "");
        assert_eq!(init_closing(Exit::Canceled, did), "");
    }
}

#[test]
fn a_declined_init_is_not_finished_and_keeps_what_it_already_wrote() {
    use crate::init::tests::Silent;

    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut out = Vec::new();

    let exit = init_with(&tty, &[], false, &mut out, &mut Silent, &mut || Ok(false))
        .expect("a declined init");

    assert_eq!(exit, Exit::Pending);
    assert!(
        text(&out).starts_with("Using the config repo ~/.config/bx.\n  + ~/.a"),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).ends_with(
            "Nothing was applied.\nNot finished: see the plan above, then run `bx init` or \
                 `bx apply` again.\n"
        ),
        "{}",
        text(&out)
    );
}

#[test]
fn init_on_a_fresh_machine_creates_the_repo_applies_and_converges_on_a_second_run() {
    use crate::init::tests::Silent;

    let home = guarded_home();
    let mut out = Vec::new();
    let exit = init_with(
        &env(home.path()),
        &[],
        false,
        &mut out,
        &mut Silent,
        &mut never,
    )
    .expect("init");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(
        text(&out),
        "Created the config repo ~/.config/bx with bx.toml.\n\
             Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n\
             Set up. Manage a file with `bx add PATH`; change an answer with \
             `bx init --set NAME=VALUE`.\n"
    );

    let mut out = Vec::new();
    let exit = init_with(
        &env(home.path()),
        &[],
        false,
        &mut out,
        &mut Silent,
        &mut never,
    )
    .expect("init");
    assert_eq!(exit, Exit::Converged);
    let second = text(&out).to_string();
    assert_eq!(
        second,
        "Using the config repo ~/.config/bx.\n\
             Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n\
             Already set up: nothing to apply. Manage a file with `bx add PATH`; change an \
             answer with `bx init --set NAME=VALUE`.\n"
    );

    // Invariant 3: a third run says exactly what the second did.
    let mut out = Vec::new();
    init_with(
        &env(home.path()),
        &[],
        false,
        &mut out,
        &mut Silent,
        &mut never,
    )
    .expect("init");
    assert_eq!(text(&out), second);
}

#[test]
fn init_answers_adopts_then_applies_with_apply_s_approval_rule() {
    use crate::init::tests::Script;

    let home = guarded_home();
    seed(
        home.path(),
        &format!(
            "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n\n{}",
            inline("~/.greeting", "hi {{who}}\\n")
        ),
    );
    home.write(".zshrc", "z\n");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut script = Script {
        answers: vec!["there"],
        pick: vec!["~/.zshrc"],
        ..Script::default()
    };

    let mut out = Vec::new();
    let mut asked = 0;
    let exit = init_with(&tty, &[], false, &mut out, &mut script, &mut || {
        asked += 1;
        Ok(true)
    })
    .expect("init");

    assert_eq!(exit, Exit::Converged);
    assert_eq!(asked, 1, "the plan was confirmed once, as bx apply asks");
    assert!(
        text(&out).starts_with(
            "Using the config repo ~/.config/bx.\n\
                 Saved this account's answers to ~/.local/state/bx/local.toml.\n  + ~/.zshrc  \
                 (copied to files/.zshrc)\n  + ~/.greeting"
        ),
        "{}",
        text(&out)
    );
    assert!(
            text(&out).ends_with("Applied 1 change(s).\nSet up. Manage a file with `bx add PATH`; change an answer with `bx init --set NAME=VALUE`.\n"),
            "{}",
            text(&out)
        );
    assert_eq!(
        std::fs::read(home.child(".greeting")).expect("applied"),
        b"hi there\n"
    );

    let exit = init_with(
        &tty,
        &[],
        false,
        &mut Vec::new(),
        &mut Script::default(),
        &mut || panic!("nothing to confirm"),
    )
    .expect("init");
    assert_eq!(exit, Exit::Converged);
}

#[test]
fn init_says_it_left_adoption_for_later_while_a_session_is_interrupted() {
    use crate::init::tests::Silent;
    use crate::journal::{Session, SessionKind};

    let home = guarded_home();
    seed(home.path(), "");
    home.write(".zshrc", "z\n");
    let state = crate::state::StateDir::resolve(home.path());
    drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    init_with(&tty, &[], false, &mut out, &mut Silent, &mut || Ok(true)).expect("init");

    assert!(
        text(&out).starts_with(
            "Using the config repo ~/.config/bx.\nOffered nothing to adopt: a bx session is \
                 running or was interrupted, and adopting waits for it. Run `bx init` again \
                 once it has finished or been recovered.\n"
        ),
        "{}",
        text(&out)
    );
    // The recovery says what to run next; no closing line contradicts it.
    assert!(
        text(&out).ends_with("nothing else was applied; run `bx plan` again.\n"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_run_that_only_adopted_is_set_up_and_not_already_set_up() {
    use crate::init::tests::Script;

    // The repo is there, nothing is answered, and adopting leaves the plan
    // with nothing to apply: the adoption is all this run did.
    let home = guarded_home();
    seed(home.path(), "");
    home.write(".zshrc", "z\n");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut script = Script {
        pick: vec!["~/.zshrc"],
        ..Script::default()
    };
    let mut out = Vec::new();

    let exit = init_with(&tty, &[], false, &mut out, &mut script, &mut never).expect("init");

    assert_eq!(exit, Exit::Converged);
    assert!(text(&out).contains("  + ~/.zshrc  (copied to files/.zshrc)\n"));
    assert!(
        text(&out).ends_with(init_closing(Exit::Converged, true)),
        "{}",
        text(&out)
    );
}

#[test]
fn init_says_what_was_left_when_a_session_is_interrupted_after_the_pick() {
    use crate::init::tests::InterruptedWhileAsking;

    let home = guarded_home();
    seed(home.path(), "");
    home.write(".zshrc", "z\n");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    init_with(
        &tty,
        &[],
        false,
        &mut out,
        &mut InterruptedWhileAsking(&home),
        &mut || Ok(true),
    )
    .expect("init");

    assert!(
            text(&out).starts_with(
                "Using the config repo ~/.config/bx.\nAdopted nothing more of what was picked: a \
                 bx session is running or was interrupted, and adopting waits for it. Run `bx init` again \
                 once it has finished or been recovered, and pick again.\n"
            ),
            "{}",
            text(&out)
        );
}

/// Output that is visible only once flushed, shared with whoever asks.
#[derive(Default, Clone)]
struct Screen {
    pending: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
    shown: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
}

impl Write for Screen {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pending.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let pending = std::mem::take(&mut *self.pending.borrow_mut());
        self.shown.borrow_mut().extend(pending);
        Ok(())
    }
}

/// Picks `~/.zshrc`, noting what was on the screen when each question was
/// put.
struct Looks(Screen, Vec<String>);

impl init::Ask for Looks {
    fn value(
        &mut self,
        decl: &crate::config::values::ValueDecl,
        _: Option<&str>,
    ) -> Result<String, init::Error> {
        panic!("asked for {}", decl.name)
    }

    fn adopt(&mut self, offered: &[paths::Portable]) -> Result<Vec<paths::Portable>, init::Error> {
        self.1
            .push(String::from_utf8_lossy(&self.0.shown.borrow()).into_owned());
        Ok(offered.to_vec())
    }
}

#[test]
fn init_has_said_what_it_wrote_before_each_question_is_put() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    home.write(".zshrc", "z\n");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let screen = Screen::default();
    let mut looks = Looks(screen.clone(), Vec::new());
    let mut at_confirm = String::new();

    init_with(
        &tty,
        &[],
        false,
        &mut screen.clone(),
        &mut looks,
        &mut || {
            at_confirm = String::from_utf8_lossy(&screen.shown.borrow()).into_owned();
            Ok(false)
        },
    )
    .expect("init");

    assert_eq!(looks.1, ["Using the config repo ~/.config/bx.\n"]);
    assert!(
        at_confirm.starts_with(
            "Using the config repo ~/.config/bx.\n  + ~/.zshrc  (copied to files/.zshrc)\n"
        ) && at_confirm.ends_with(" unchanged.\n"),
        "the plan is on screen when it is put to the question: {at_confirm}"
    );
}

#[test]
fn init_without_yes_or_a_terminal_shows_the_plan_and_writes_nothing_pending() {
    use crate::init::tests::Silent;

    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));

    let error = init_with(
        &env(home.path()),
        &[],
        false,
        &mut Vec::new(),
        &mut Silent,
        &mut never,
    )
    .expect_err("no confirmation");
    assert!(
        matches!(error, init::Error::Plan(Error::NeedsConfirmation)),
        "{error:?}"
    );
    assert!(!home.child(".a").exists());

    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let exit = init_with(&tty, &[], true, &mut Vec::new(), &mut Silent, &mut never)
        .expect("--yes asks nothing, on a terminal too");
    assert_eq!(exit, Exit::Converged);
    assert!(home.child(".a").exists());

    let fresh = guarded_home();
    assert!(matches!(
        init_with(
            &env(fresh.path()),
            &[],
            true,
            &mut Refusing,
            &mut Silent,
            &mut never
        ),
        Err(init::Error::Output(_))
    ));
}

#[test]
fn decision_18_an_apply_that_only_recovered_says_what_it_did() {
    use crate::recover::{Interrupted, Outcome};

    let report = Report::default();
    assert_eq!(
        recovered(&report, &Outcome::RolledBack { undone: 2 }),
        "Rolled back 2 write(s) from an interrupted session; nothing else was applied; \
             run `bx plan` again."
    );
    assert_eq!(
        recovered(&report, &Outcome::Recorded { entries: 1 }),
        "Recorded 1 write(s) an interrupted session made; nothing else was applied; run \
             `bx plan` again."
    );
    assert!(recovered(&report, &Outcome::Nothing).starts_with("Found nothing left to recover;"));

    let unreadable = Report {
        interrupted: Some(Interrupted {
            kind: crate::journal::SessionKind::Apply,
            journal: std::path::PathBuf::from("/state/journal.mpk"),
            complete: false,
            unreadable: true,
            unfinished: Vec::new(),
        }),
        ..Report::default()
    };
    assert!(
        recovered(&unreadable, &Outcome::Nothing)
            .starts_with("Set aside the journal bx could not read;")
    );
}

#[test]
fn a_missing_repo_is_an_error_for_every_command() {
    let home = guarded_home();
    let env = env(home.path());

    assert!(matches!(
        status(&env, &mut Vec::new()),
        Err(Error::RepoMissing(_))
    ));
    assert!(matches!(
        plan(&env, &mut Vec::new()),
        Err(Error::RepoMissing(_))
    ));
    assert!(matches!(
        apply(&env, true, &mut Vec::new()),
        Err(Error::RepoMissing(_))
    ));
}

/// A secret target at `~/{name}` whose ciphertext is `secrets/{name}.age`.
fn secret_target(name: &str) -> String {
    format!("[[target]]\npath = \"~/{name}\"\nsecret = \"secrets/{name}.age\"\nmode = \"0600\"\n")
}

/// Encrypt `plaintext` to `recipient` as the repo's `secrets/{name}.age`.
fn seal(home: &crate::testing::GuardedHome, name: &str, recipient: &str) {
    let path = home.child(format!(".config/bx/secrets/{name}.age"));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("secrets/");
    std::fs::write(path, crate::secret::tests::encrypt_to(recipient, b"x\n"))
        .expect("the ciphertext");
}

fn no_passphrase(_: &str) -> Option<Passphrase> {
    panic!("nothing should have asked for a passphrase")
}

#[test]
fn d1_secret_list_reports_each_secret_and_whether_it_decrypts() {
    use crate::secret::tests::{LOCKED_SSH_PUB, SSH_KEY, SSH_PUB};

    let home = guarded_home();
    home.write(".ssh/id_ed25519", SSH_KEY);
    seal(&home, "one", SSH_PUB);
    seal(&home, "two", LOCKED_SSH_PUB);
    let layer = [
        secret_target("one"),
        inline("~/.plain", "a\\n"),
        secret_target("two"),
        secret_target("absent"),
        "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n\
             [[target]]\npath = \"~/.w\"\nsecret = \"secrets/{{who}}.age\"\nmode = \"0600\"\n"
            .to_string(),
    ]
    .concat();
    seed(home.path(), &layer);

    let mut out = Vec::new();
    let exit = secret_list_with(&env(home.path()), &mut out, &mut no_passphrase).expect("listed");

    assert_eq!(exit, Exit::Pending);
    let lines: Vec<&str> = text(&out).lines().collect();
    assert_eq!(lines.len(), 4, "{}", text(&out));
    assert_eq!(lines[0], "  ~/one  secrets/one.age  decryptable");
    assert!(
        lines[1].starts_with(
            "  ~/two  secrets/two.age  not decryptable: the identity ~/.ssh/id_ed25519 is \
                 not one this secret is encrypted to"
        ),
        "{}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("  ~/absent  secrets/absent.age  unreadable: "),
        "{}",
        lines[2]
    );
    assert!(
        lines[3].starts_with("  ~/.w  secrets/{{who}}.age  blocked: "),
        "{}",
        lines[3]
    );
    assert!(!text(&out).contains("x\n  "), "no plaintext is printed");
}

#[test]
fn d1_secret_list_asks_for_a_locked_identity_only_on_a_terminal_and_per_secret() {
    use crate::secret::tests::{LOCKED_PASSPHRASE, LOCKED_SSH_KEY, LOCKED_SSH_PUB};

    let home = guarded_home();
    home.write(".ssh/id_ed25519", LOCKED_SSH_KEY);
    seal(&home, "one", LOCKED_SSH_PUB);
    seal(&home, "two", LOCKED_SSH_PUB);
    seed(
        home.path(),
        &[secret_target("one"), secret_target("two")].concat(),
    );

    let mut out = Vec::new();
    let exit = secret_list_with(&env(home.path()), &mut out, &mut no_passphrase).expect("listed");
    assert_eq!(
        exit,
        Exit::Pending,
        "no terminal: locked, and nothing asked"
    );
    assert!(
        text(&out).contains(
            "  ~/one  secrets/one.age  not decryptable: the identity \
                 ~/.ssh/id_ed25519 is locked by a passphrase"
        ),
        "{}",
        text(&out)
    );

    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut asked = Vec::new();
    let mut out = Vec::new();
    let exit = secret_list_with(&tty, &mut out, &mut |shown| {
        asked.push(shown.to_string());
        Some(Passphrase::from(LOCKED_PASSPHRASE))
    })
    .expect("listed");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert_eq!(
        text(&out),
        "  ~/one  secrets/one.age  decryptable\n  ~/two  secrets/two.age  decryptable\n"
    );
    assert_eq!(
        asked,
        ["~/.ssh/id_ed25519", "~/.ssh/id_ed25519"],
        "asked once per secret: nothing keeps a passphrase"
    );
}

#[test]
fn d1_secret_list_with_no_secrets_says_so_and_converges() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let mut out = Vec::new();
    let exit = secret_list(&env(home.path()), &mut out).expect("listed");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(text(&out), "No secrets are declared.\n");

    assert!(matches!(
        secret_list(&env(home.path()), &mut Refusing),
        Err(Error::Output(_))
    ));
}

#[test]
fn a_command_with_no_body_is_refused_in_one_line_and_exits_one() {
    let mut err = Vec::new();
    let exit = not_built("bx shell-init", &mut err).expect("refused");
    assert_eq!(exit, Exit::Error);
    assert_eq!(
        text(&err),
        "bx shell-init is not built yet in this release of bx.\n"
    );

    assert!(matches!(
        not_built("bx shell-init", &mut Refusing),
        Err(Error::Output(_))
    ));
}

/// A writer that refuses every byte.
struct Refusing;

impl Write for Refusing {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("refused"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_output_that_cannot_be_written_is_an_error() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));

    assert!(matches!(
        plan(&env(home.path()), &mut Refusing),
        Err(Error::Output(_))
    ));
    assert!(matches!(
        apply_with(&env(home.path()), true, &mut Refusing, &mut never),
        Err(Error::Output(_))
    ));
    assert!(!home.child(".a").exists(), "written with no plan shown");
}

/// A systemd whose every unit is loaded, enabled and failed.
struct AllFailed;

impl systemd::Query for AllFailed {
    fn show(&self, names: &[String]) -> Result<Vec<systemd::State>, systemd::Unreachable> {
        Ok(vec![
            systemd::State {
                load: "loaded".into(),
                active: "failed".into(),
                file: "enabled".into(),
                need_reload: false,
            };
            names.len()
        ])
    }
}

#[test]
fn doctor_checks_written_units_in_the_xdg_unit_directory() {
    let home = guarded_home();
    let xdg = home.child("xdg");
    let env = Env {
        xdg_config_home: Some(xdg.clone().into_os_string()),
        ..env(home.path())
    };
    std::fs::create_dir_all(xdg.join("bx")).expect("the config repo");
    std::fs::write(
        xdg.join("bx/bx.toml"),
        "[[target]]\npath = \"~/xdg/systemd/user/a.service\"\ncontent = \"x\"\n\n\
             [[target]]\npath = \"~/.config/systemd/user/b.service\"\ncontent = \"x\"\n\
             when = \"os:linux\"\n",
    )
    .expect("bx.toml");
    home.write("xdg/systemd/user/a.service", "x");
    home.write(".config/systemd/user/b.service", "x");

    let mut out = Vec::new();
    let exit = doctor_with(
        &env,
        &mut out,
        std::ffi::OsStr::new(""),
        &AllFailed,
        &Git::new(&env),
    )
    .expect("doctor");

    assert_eq!(exit, Exit::Pending);
    assert_eq!(
        text(&out),
        "  ! ~/xdg/systemd/user/a.service  (~/xdg/bx/bx.toml:1) has failed; see `systemctl \
             --user status a.service`\nDoctor: 1 finding(s).\n",
        "only the unit in $XDG_CONFIG_HOME/systemd/user is checked"
    );
}

#[test]
fn doctor_with_nothing_to_check_is_converged_and_needs_no_systemd() {
    let home = guarded_home();
    seed(
        home.path(),
        &format!(
            "{}when = \"os:linux\"\n",
            inline("~/.config/systemd/user/a.service", "x")
        ),
    );

    let mut out = Vec::new();
    let exit = doctor(&env(home.path()), &mut out).expect("doctor");

    assert_eq!(exit, Exit::Converged);
    assert_eq!(text(&out), "Doctor: 0 finding(s).\n");
}

#[test]
fn doctor_without_a_repo_or_an_output_is_an_error() {
    let home = guarded_home();
    assert!(matches!(
        doctor(&env(home.path()), &mut Vec::new()),
        Err(Error::RepoMissing(_))
    ));

    seed(home.path(), "");
    assert!(matches!(
        doctor(&env(home.path()), &mut Refusing),
        Err(Error::Output(_))
    ));
}

#[test]
fn colour_follows_the_terminal_and_no_color() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.a", "a\\n"));
    let rendered = |env: &Env| {
        let mut out = Vec::new();
        plan(env, &mut out).expect("plan");
        String::from_utf8(out).expect("UTF-8")
    };
    let terminal = Env {
        stdout_tty: true,
        ..env(home.path())
    };
    let no_color = Env {
        no_color: true,
        ..terminal.clone()
    };

    assert!(rendered(&terminal).contains('\x1b'));
    assert!(!rendered(&no_color).contains('\x1b'));
    assert!(!rendered(&env(home.path())).contains('\x1b'));
}

mod doctor_command;
mod sync_command;
mod update_command;
mod update_sync_command;
mod upgrade_command;
