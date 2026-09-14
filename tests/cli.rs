//! The binary's surface for `bx`, `bx plan` and `bx apply`: exit codes, what
//! reaches standard output, and what is written.
//!
//! Every invocation gets its home per command, from a guarded tempdir; nothing
//! here sets a variable in this process.

use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use bx::testing::guarded_home;

/// `bx` against `home`, with nothing else in the environment placing the repo
/// or the state directory, and standard input not a terminal.
fn bx(home: &Path, args: &[&str]) -> Output {
    Command::cargo_bin("bx")
        .expect("the bx binary")
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("NO_COLOR")
        .output()
        .expect("run bx")
}

fn seed(home: &Path, layer: &str) {
    let repo = home.join(".config/bx");
    std::fs::create_dir_all(&repo).expect("the config repo");
    std::fs::write(repo.join("bx.toml"), layer).expect("bx.toml");
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).expect("UTF-8 stdout")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const A_TARGET: &str = "[[target]]\npath = \"~/.a\"\ncontent = \"a\\n\"\n";

#[test]
fn t21_plan_exits_zero_when_converged_and_two_when_pending() {
    let home = guarded_home();
    seed(home.path(), "");
    let converged = bx(home.path(), &["plan"]);
    assert_eq!(converged.status.code(), Some(0), "{}", stderr(&converged));
    assert_eq!(
        stdout(&converged),
        "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
    );

    seed(home.path(), A_TARGET);
    let pending = bx(home.path(), &["plan"]);
    assert_eq!(pending.status.code(), Some(2), "{}", stderr(&pending));
    assert!(
        stdout(&pending).starts_with("  + ~/.a  (~/.config/bx/bx.toml:1)\n"),
        "{}",
        stdout(&pending)
    );
    assert!(!stdout(&pending).contains('\x1b'), "coloured into a pipe");
    assert!(!home.child(".a").exists(), "plan wrote");
}

#[test]
fn t22_apply_with_yes_then_plan_is_converged() {
    let home = guarded_home();
    seed(home.path(), A_TARGET);

    let applied = bx(home.path(), &["apply", "--yes"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(stdout(&applied).ends_with("Applied 1 change(s).\n"));
    assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");

    let planned = bx(home.path(), &["plan"]);
    assert_eq!(planned.status.code(), Some(0), "{}", stdout(&planned));

    let status = bx(home.path(), &[]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    assert!(
        stdout(&status).starts_with("  = ~/.a"),
        "{}",
        stdout(&status)
    );
}

#[test]
fn t23_plan_without_a_config_repo_exits_one_and_says_what_to_run() {
    let home = guarded_home();

    let output = bx(home.path(), &["plan"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("run `bx init`"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn decision_4_apply_without_yes_and_no_terminal_exits_one_having_shown_the_plan() {
    let home = guarded_home();
    seed(home.path(), A_TARGET);

    let output = bx(home.path(), &["apply"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stdout(&output).starts_with("  + ~/.a"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("rerun with --yes"),
        "{}",
        stderr(&output)
    );
    assert!(!home.child(".a").exists(), "written without confirmation");
}

#[test]
fn apply_over_a_damaged_ledger_it_cannot_move_aside_exits_one_and_writes_nothing() {
    // `state::Error::CannotQuarantine`, from the state directory's r3 round:
    // the session's locked ledger read refuses a damaged ledger it cannot move
    // aside, so apply must stop with an error before anything is written.
    let home = guarded_home();
    seed(home.path(), A_TARGET);
    // A state directory 4080 bytes long: `ledger.mpk` still fits in
    // `PATH_MAX`, and every name it could be moved aside to does not.
    const ROOT: usize = 4080;
    let mut xdg_state = home.path().join("s").into_os_string();
    let xdg_len = ROOT - "/bx".len();
    while xdg_len - xdg_state.len() > 256 {
        xdg_state.push(format!("/{}", "d".repeat(200)));
    }
    xdg_state.push(format!("/{}", "b".repeat(xdg_len - xdg_state.len() - 1)));
    let state = Path::new(&xdg_state).join("bx");
    assert_eq!(state.as_os_str().len(), ROOT);
    std::fs::create_dir_all(&state).expect("the state directory");
    let ledger = state.join("ledger.mpk");
    std::fs::write(&ledger, b"not a ledger").expect("damage the ledger");

    let output = Command::cargo_bin("bx")
        .expect("the bx binary")
        .args(["apply", "--yes"])
        .env("HOME", home.path())
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_STATE_HOME", &xdg_state)
        .env_remove("NO_COLOR")
        .output()
        .expect("run bx");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("could not move it aside"),
        "{}",
        stderr(&output)
    );
    assert_eq!(std::fs::read(&ledger).expect("kept"), b"not a ledger");
    assert!(!home.child(".a").exists(), "written over a refused ledger");
    assert!(!state.join("journal.mpk").exists(), "a session began");
}

#[test]
fn bare_bx_is_the_status_view_with_plan_exit_codes() {
    let home = guarded_home();
    seed(home.path(), A_TARGET);

    let output = bx(home.path(), &[]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stdout(&output).starts_with("  + ~/.a"),
        "{}",
        stdout(&output)
    );
}
