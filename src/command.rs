//! The bodies of `bx`, `bx plan`, `bx apply` and `bx doctor`.
//!
//! Each loads the configuration, runs the one traversal in [`crate::plan`] —
//! or, for `doctor`, the read-only checks in [`crate::doctor`] — writes the
//! rendering to the output it is handed, and returns the exit status. `main`
//! does nothing but call one of them.

use std::io::Write;

use crate::doctor::{self, Probes, systemd};
use crate::paths;
use crate::plan::{self, Env, Error, Inputs, Mode, Palette, Report, View};
use crate::report::Exit;

/// `bx doctor`: what a human should look at, changing nothing.
///
/// # Errors
///
/// Whatever loading the configuration returns, and [`Error::Output`] when
/// `out` cannot be written. A check that cannot ask what it needs — systemd's
/// user session unreachable — is a finding, not an error.
pub fn doctor(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    doctor_with(env, out, &systemd::Systemctl::default())
}

/// [`doctor`], asking systemd through `systemd`.
fn doctor_with(
    env: &Env,
    out: &mut dyn Write,
    systemd: &dyn systemd::Query,
) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let unit_dir = paths::systemd_user_dir_in(&env.home, env.xdg_config_home.as_deref());
    let report = doctor::run(
        &inputs,
        &Probes {
            unit_dir: &unit_dir,
            systemd,
        },
    );
    out.write_all(doctor::render(&report, &env.home).as_bytes())
        .map_err(Error::Output)?;
    Ok(doctor::exit(&report))
}

/// Bare `bx`: every target, unchanged ones included.
///
/// # Errors
///
/// Whatever loading or deciding returns, and [`Error::Output`] when `out`
/// cannot be written.
pub fn status(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    show(env, View::Status, out)
}

/// `bx plan`: what `apply` would do, writing nothing.
///
/// # Errors
///
/// As [`status`].
pub fn plan(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    show(env, View::Plan, out)
}

/// `bx apply`: recover, show the plan, obtain approval, and write.
///
/// Approval is `yes`, or the answer to a prompt when standard input is a
/// terminal. With neither, the plan is shown and nothing is written: a piped
/// `bx apply` must not write what nobody confirmed.
///
/// # Errors
///
/// [`Error::NeedsConfirmation`] when there is something to write, no `yes`,
/// and no terminal to ask on; [`Error::Prompt`] when the prompt fails; and
/// otherwise as [`status`], plus whatever recovery and the session return.
pub fn apply(env: &Env, yes: bool, out: &mut dyn Write) -> Result<Exit, Error> {
    apply_with(env, yes, out, &mut confirm)
}

/// Ask on the terminal whether to write.
///
/// The default is **no**: a prompt answered with a bare newline, or one whose
/// terminal goes away mid-question, must not be read as approval. Everything
/// around this — `yes`, no terminal, declined, accepted, a failing prompt — is
/// decided in [`apply_with`] and tested through its `ask` seam; this wrapper
/// exists only to put the question.
fn confirm() -> Result<bool, Error> {
    inquire::Confirm::new("Apply these changes?")
        .with_default(false)
        .prompt()
        .map_err(Error::Prompt)
}

/// [`apply`], with the question asked through `ask`.
fn apply_with(
    env: &Env,
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let mut shown = false;
    let report = plan::run(&inputs, Mode::Apply, &mut |report| {
        emit(out, report, View::Plan, env)?;
        shown = true;
        if yes {
            Ok(true)
        } else if env.stdin_tty {
            ask()
        } else {
            Err(Error::NeedsConfirmation)
        }
    })?;

    if !shown {
        emit(out, &report, View::Plan, env)?;
    } else if let Some(outcome) = &report.recovered {
        writeln!(out, "{}", recovered(&report, outcome)).map_err(Error::Output)?;
    } else if report.executed {
        let written = report
            .changes
            .iter()
            .filter(|change| change.action.is_pending())
            .count();
        writeln!(out, "Applied {written} change(s).").map_err(Error::Output)?;
    } else {
        writeln!(out, "Nothing was written.").map_err(Error::Output)?;
    }
    Ok(plan::exit(&report, Mode::Apply))
}

/// What an `apply` that recovered an interrupted session, and did nothing else,
/// says it did.
fn recovered(report: &Report, outcome: &crate::recover::Outcome) -> String {
    use crate::recover::Outcome;

    let done = match outcome {
        Outcome::RolledBack { undone } => {
            format!("Rolled back {undone} write(s) from an interrupted session")
        }
        Outcome::Recorded { entries } => {
            format!("Recorded {entries} write(s) an interrupted session made")
        }
        // A blocked recovery is an error, never an outcome `apply` reports.
        Outcome::Nothing | Outcome::Blocked { .. } => {
            if report
                .interrupted
                .as_ref()
                .is_some_and(|interrupted| interrupted.unreadable)
            {
                "Set aside the journal bx could not read".to_string()
            } else {
                "Found nothing left to recover".to_string()
            }
        }
    };
    format!("{done}; nothing else was applied; run `bx plan` again.")
}

/// Load, decide read-only, and show.
fn show(env: &Env, view: View, out: &mut dyn Write) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let report = plan::run(&inputs, Mode::Plan, &mut |_| Ok(false))?;
    emit(out, &report, view, env)?;
    Ok(plan::exit(&report, Mode::Plan))
}

/// Write the rendering of `report`, coloured as the environment allows.
fn emit(out: &mut dyn Write, report: &Report, view: View, env: &Env) -> Result<(), Error> {
    let palette = Palette::resolve(env.no_color, env.stdout_tty);
    out.write_all(plan::render(report, view, palette, &env.home).as_bytes())
        .map_err(Error::Output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::{env, inline, seed};
    use crate::testing::guarded_home;

    fn text(out: &[u8]) -> &str {
        std::str::from_utf8(out).expect("UTF-8 output")
    }

    fn never() -> Result<bool, Error> {
        panic!("nothing should have been asked")
    }

    /// Set on the child that actually calls [`confirm`].
    const CONFIRM_CHILD: &str = "BX_TEST_CONFIRM_CHILD";

    #[test]
    #[ignore = "spawned by the test below; it must run with a stdin that is not a terminal"]
    fn confirm_child() {
        // Without the variable this is someone running `--ignored` by hand,
        // possibly from a terminal, where `prompt` would block on a question
        // nobody is there to answer. Do nothing rather than hang.
        if std::env::var_os(CONFIRM_CHILD).is_none() {
            return;
        }
        let answer = confirm();
        // `Ok(_)` is what both surviving mutants return, so this is the
        // assertion that kills them: with no terminal there is no answer, and
        // a wrapper that invents one would approve a write nobody confirmed.
        assert!(
            matches!(answer, Err(Error::Prompt(inquire::InquireError::NotTTY))),
            "{answer:?}"
        );
    }

    #[test]
    fn confirm_without_a_terminal_is_a_prompt_error_and_never_an_answer() {
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
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "command::tests::confirm_child",
            ])
            .env(CONFIRM_CHILD, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn the confirmation child");

        assert!(
            output.status.success(),
            "the child's assertion failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        // The child really ran the case, rather than being filtered out and
        // reporting success over an empty run.
        let ran = String::from_utf8_lossy(&output.stdout);
        assert!(
            ran.contains("1 passed") && ran.contains("0 failed"),
            "the child ran no test: {ran}"
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
    fn decision_4_apply_without_yes_or_a_terminal_shows_the_plan_and_refuses() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let mut out = Vec::new();

        let error = apply_with(&env(home.path()), false, &mut out, &mut never)
            .expect_err("no confirmation");

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
            text(&out).ends_with("Nothing was written.\n"),
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
        assert!(
            recovered(&report, &Outcome::Nothing).starts_with("Found nothing left to recover;")
        );

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
             [[target]]\npath = \"~/.config/systemd/user/b.service\"\ncontent = \"x\"\n",
        )
        .expect("bx.toml");
        home.write("xdg/systemd/user/a.service", "x");
        home.write(".config/systemd/user/b.service", "x");

        let mut out = Vec::new();
        let exit = doctor_with(&env, &mut out, &AllFailed).expect("doctor");

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
            &inline("~/.config/systemd/user/a.service", "x"),
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
}
