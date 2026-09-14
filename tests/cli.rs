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
fn decision_21_a_home_spelled_with_a_parent_component_is_refused_naming_home() {
    // P42R1-D6. A raw HOME that climbs out and back in failed every plan and
    // apply with an error about the target's path, never about HOME.
    let home = guarded_home();
    seed(home.path(), A_TARGET);
    let parent = home.path().parent().expect("the tempdir's parent");
    let spelled = parent
        .join("..")
        .join(parent.file_name().expect("the parent's name"))
        .join(home.path().file_name().expect("the home's name"));
    let before = snapshot(home.path());

    for args in [&["plan"][..], &["apply", "--yes"]] {
        let output = bx(&spelled, args);

        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(
            stderr(&output).contains("HOME has a `..` component"),
            "{}",
            stderr(&output)
        );
    }
    assert_eq!(
        snapshot(home.path()),
        before,
        "a refused HOME changed the home"
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

/// What one path is: a directory, a file and its bytes, a link and what it
/// names, or anything else.
#[derive(Debug, PartialEq, Eq)]
enum Shape {
    Dir,
    File(Vec<u8>),
    Link(std::path::PathBuf),
    Other,
}

/// Every path under `root`, `root` itself included, with its shape and its
/// permission bits, in path order.
fn snapshot(root: &Path) -> Vec<(std::path::PathBuf, Shape, u32)> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let meta = std::fs::symlink_metadata(&path).expect("lstat");
        let kind = meta.file_type();
        let shape = if kind.is_dir() {
            for entry in std::fs::read_dir(&path).expect("read a directory") {
                stack.push(entry.expect("an entry").path());
            }
            Shape::Dir
        } else if kind.is_symlink() {
            Shape::Link(std::fs::read_link(&path).expect("readlink"))
        } else if kind.is_file() {
            Shape::File(std::fs::read(&path).expect("read a file"))
        } else {
            Shape::Other
        };
        found.push((path, shape, meta.permissions().mode() & 0o7777));
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Set `path`'s permission bits.
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

#[test]
fn plan_with_no_state_directory_creates_nothing() {
    let home = guarded_home();
    seed(home.path(), A_TARGET);
    let state = home.child(".local/state/bx");
    let before = snapshot(home.path());

    let output = bx(home.path(), &["plan"]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(snapshot(home.path()), before, "plan changed the home");
    assert!(!state.exists(), "plan created the state directory");
    assert!(
        !home.child(".local").exists(),
        "plan created a parent of it"
    );
}

#[test]
fn plan_leaves_a_wide_state_directory_and_its_lock_file_exactly_as_they_are() {
    // Decision 8: `plan` asked the lock through `SharedLock::try_acquire`,
    // which tightened the state directory to 0700 and the lock file to 0600.
    let home = guarded_home();
    seed(home.path(), A_TARGET);
    let state = home.child(".local/state/bx");
    std::fs::create_dir_all(&state).expect("the state directory");
    chmod(&state, 0o755);
    std::fs::write(state.join("lock"), b"").expect("the lock file");
    chmod(&state.join("lock"), 0o644);
    let before = snapshot(home.path());

    let output = bx(home.path(), &["plan"]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(snapshot(home.path()), before, "plan changed the home");
}

#[test]
fn plan_over_a_damaged_state_directory_elsewhere_changes_neither_it_nor_the_home() {
    // Every read `plan` makes of the state directory — the lock, the journal,
    // the ledger — against files a writing run would move aside or narrow.
    let home = guarded_home();
    let elsewhere = guarded_home();
    seed(home.path(), A_TARGET);
    let state = elsewhere.child("bx");
    std::fs::create_dir_all(&state).expect("the state directory");
    for (name, bytes) in [
        ("lock", &b"4242 bx\n"[..]),
        ("journal.mpk", b"not a journal"),
        ("ledger.mpk", b"not a ledger"),
        ("fingerprints.mpk", b"not fingerprints"),
    ] {
        std::fs::write(state.join(name), bytes).expect("a state file");
        chmod(&state.join(name), 0o644);
    }
    chmod(&state, 0o755);
    let before = (snapshot(home.path()), snapshot(elsewhere.path()));

    let output = Command::cargo_bin("bx")
        .expect("the bx binary")
        .arg("plan")
        .env("HOME", home.path())
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_STATE_HOME", elsewhere.path())
        .env_remove("NO_COLOR")
        .output()
        .expect("run bx");

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stdout(&output).starts_with("An interrupted bx session left a journal"),
        "{}",
        stdout(&output)
    );
    assert_eq!(
        (snapshot(home.path()), snapshot(elsewhere.path())),
        before,
        "plan changed the home or the state directory"
    );
}

#[test]
fn plan_and_apply_name_an_unusable_parent_by_its_portable_path() {
    // Decision 9: the note was the observation's own text, which spells the
    // parent by its absolute path.
    let home = guarded_home();
    home.write(".x", "a file, not a directory\n");
    seed(
        home.path(),
        "[[target]]\npath = \"~/.x/y\"\ncontent = \"y\\n\"\n",
    );
    let row = "  ! ~/.x/y  (~/.config/bx/bx.toml:1) ~/.x is not a directory, so bx cannot write \
               a file inside it\n";
    let absolute = home.path().to_string_lossy().into_owned();

    for args in [&["plan"][..], &["apply", "--yes"]] {
        let output = bx(home.path(), args);

        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(stdout(&output).starts_with(row), "{}", stdout(&output));
        assert!(!stdout(&output).contains(&absolute), "{}", stdout(&output));
    }
    assert_eq!(
        std::fs::read(home.child(".x")).expect("kept"),
        b"a file, not a directory\n"
    );
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
