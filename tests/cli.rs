//! The binary's surface for `bx`, `bx init`, `bx plan`, `bx apply`, `bx add`
//! and `bx rm`:
//! exit codes, what reaches standard output, and what is written.
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

/// The layer the interrupted session in [`crashed`] was applying.
const CRASHED_LAYER: &str = "[[target]]\npath = \"~/.config/made/new.conf\"\ncontent = \"made\\n\"\n\
                             [[target]]\npath = \"~/.owned\"\ncontent = \"after\\n\"\n";

/// Leave `home` as an `apply` that died mid-session leaves it: bx owns
/// `~/.owned` holding `before`, and a session that created
/// `~/.config/made/new.conf` and rewrote `~/.owned` to `after` never finished.
fn crashed(home: &Path) {
    seed(
        home,
        "[[target]]\npath = \"~/.owned\"\ncontent = \"before\\n\"\n",
    );
    let seeded = bx(home, &["apply", "--yes"]);
    assert_eq!(seeded.status.code(), Some(0), "{}", stderr(&seeded));
    seed(home, CRASHED_LAYER);

    let state = bx::state::StateDir::resolve(home);
    let mut session =
        bx::journal::Session::open(&state, bx::journal::SessionKind::Apply, home, Vec::new())
            .expect("a session");
    for (rel, bytes) in [(".config/made/new.conf", "made\n"), (".owned", "after\n")] {
        let dest = home.join(rel);
        session
            .apply(bx::journal::Request {
                target: bx::paths::Portable::parse_in(&format!("~/{rel}"), home)
                    .expect("a portable target"),
                dest: dest.clone(),
                content: bx::journal::Content::Bytes {
                    bytes: bytes.as_bytes().to_vec(),
                    planned: bx::fs::observe(&dest).expect("observe"),
                },
                mode: bx::fs::Mode::DEFAULT_FILE,
                ownership: bx::journal::Ownership::Owned(bx::state::Mechanism::Own),
            })
            .expect("the write");
    }
    drop(session);
}

#[test]
fn decision_18_plan_over_an_interrupted_session_announces_the_roll_back_and_nothing_else() {
    // P42R1-D2 (A1). Plan showed conflict rows with no diff, and apply then
    // rolled back and created and modified the targets it had not shown.
    let home = guarded_home();
    crashed(home.path());
    let before = snapshot(home.path());

    let output = bx(home.path(), &["plan"]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let shown = stdout(&output);
    assert!(shown.contains("  ~ ~/.owned  ("), "{shown}");
    assert!(shown.contains("    -after\n    +before\n"), "{shown}");
    assert!(shown.contains("  ~ ~/.config/made/new.conf  ("), "{shown}");
    assert!(shown.contains("    -made\n"), "{shown}");
    assert!(
        shown.contains("run `bx plan` again after `bx apply` rolls these back"),
        "{shown}"
    );
    assert!(
        !shown.contains("  + ~/.config/made/new.conf"),
        "a target was decided against the disk before the roll back: {shown}"
    );
    assert_eq!(snapshot(home.path()), before, "plan changed the home");
}

#[test]
fn decision_18_an_apply_that_is_not_confirmed_rolls_nothing_back() {
    // P42R1-D1 (A2). The recovery ran before the question, so a refused apply
    // had already rewritten ~/.owned and deleted new.conf.
    let home = guarded_home();
    crashed(home.path());
    let before = snapshot(home.path());

    let output = bx(home.path(), &["apply"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("    -after\n    +before\n"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("rerun with --yes"),
        "{}",
        stderr(&output)
    );
    assert_eq!(snapshot(home.path()), before, "an unconfirmed apply wrote");
}

#[test]
fn decision_18_a_confirmed_apply_rolls_back_then_stops_and_the_next_apply_converges() {
    // P42R1-D1 (A3). The recovering apply went on to write the targets.
    let home = guarded_home();
    crashed(home.path());

    let recovered = bx(home.path(), &["apply", "--yes"]);

    assert_eq!(recovered.status.code(), Some(2), "{}", stderr(&recovered));
    assert!(
        stdout(&recovered).contains(
            "Rolled back 2 write(s) from an interrupted session; nothing else was applied"
        ),
        "{}",
        stdout(&recovered)
    );
    assert_eq!(
        std::fs::read(home.child(".owned")).expect("put back"),
        b"before\n"
    );
    assert!(
        !home.child(".config/made").exists(),
        "the created directory stayed"
    );
    assert!(
        !home.child(".local/state/bx/journal.mpk").exists(),
        "the journal stayed"
    );

    let planned = bx(home.path(), &["plan"]);
    assert_eq!(planned.status.code(), Some(2), "{}", stderr(&planned));
    assert!(
        stdout(&planned).contains("  + ~/.config/made/new.conf  ("),
        "{}",
        stdout(&planned)
    );
    assert!(
        stdout(&planned).contains("  ~ ~/.owned  ("),
        "{}",
        stdout(&planned)
    );

    let applied = bx(home.path(), &["apply", "--yes"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(stdout(&applied).ends_with("Applied 2 change(s).\n"));
    assert_eq!(bx(home.path(), &["plan"]).status.code(), Some(0));
}

#[test]
fn decision_18_an_apply_over_a_blocked_interruption_refuses_before_rolling_anything_back() {
    // P42R1-D4 (B). The banner said apply refuses, but apply rolled back the
    // resolvable writes first — deleting new.conf — and then refused.
    let home = guarded_home();
    crashed(home.path());
    std::fs::write(home.child(".owned"), "user edit\n").expect("the user's edit");

    let planned = bx(home.path(), &["plan"]);
    assert_eq!(planned.status.code(), Some(2), "{}", stderr(&planned));
    assert!(stdout(&planned).contains("abandon"), "{}", stdout(&planned));

    let before = snapshot(home.path());
    let refused = bx(home.path(), &["apply", "--yes"]);

    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("cannot account for"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(snapshot(home.path()), before, "a refused apply wrote");
    assert!(home.child(".config/made/new.conf").exists());
}

#[test]
fn d1_a_secret_is_listed_planned_without_its_plaintext_and_applied_private() {
    use age::secrecy::ExposeSecret as _;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let home = guarded_home();
    let key = age::x25519::Identity::generate();
    std::fs::create_dir_all(home.child(".config/age")).expect("~/.config/age");
    std::fs::write(
        home.child(".config/age/key.txt"),
        key.to_string().expose_secret(),
    )
    .expect("the identity");
    std::fs::create_dir_all(home.child(".local/state/bx")).expect("the state directory");
    std::fs::write(
        home.child(".local/state/bx/local.toml"),
        "[secrets]\nidentity = \"~/.config/age/key.txt\"\n",
    )
    .expect("local.toml");

    let recipient = key.to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as _)).expect("a recipient");
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).expect("the output");
    writer.write_all(b"hunter2\n").expect("the plaintext");
    writer.finish().expect("the stream");
    std::fs::create_dir_all(home.child(".config/bx/secrets")).expect("secrets/");
    std::fs::write(home.child(".config/bx/secrets/token.age"), ciphertext).expect("ciphertext");
    seed(
        home.path(),
        "[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n",
    );

    let listed = bx(home.path(), &["secret", "list"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert_eq!(
        stdout(&listed),
        "  ~/.token  secrets/token.age  decryptable\n"
    );

    let planned = bx(home.path(), &["plan"]);
    assert_eq!(planned.status.code(), Some(2), "{}", stderr(&planned));
    assert!(
        !stdout(&planned).contains("hunter2"),
        "{}",
        stdout(&planned)
    );

    let applied = bx(home.path(), &["apply", "--yes"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(
        !stdout(&applied).contains("hunter2"),
        "{}",
        stdout(&applied)
    );
    assert_eq!(
        std::fs::read(home.child(".token")).expect("written"),
        b"hunter2\n"
    );
    let mode = std::fs::metadata(home.child(".token"))
        .expect("the secret")
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o600);

    let again = bx(home.path(), &["plan"]);
    assert_eq!(again.status.code(), Some(0), "{}", stdout(&again));
}

#[test]
fn add_then_rm_round_trips_the_file_and_the_layer_through_the_binary() {
    let home = guarded_home();
    seed(home.path(), "# mine\n");
    std::fs::write(home.child(".tool.rc"), b"one\r\ntwo").expect("the file");

    let added = bx(home.path(), &["add", "~/.tool.rc"]);
    assert_eq!(added.status.code(), Some(0), "{}", stderr(&added));
    assert!(
        stdout(&added).starts_with("  + ~/.tool.rc  (copied to files/.tool.rc)\n"),
        "{}",
        stdout(&added)
    );
    assert_eq!(
        std::fs::read(home.child(".config/bx/files/.tool.rc")).expect("the copy"),
        b"one\r\ntwo"
    );
    let planned = bx(home.path(), &["plan"]);
    assert_eq!(planned.status.code(), Some(0), "{}", stdout(&planned));

    let removed = bx(home.path(), &["rm", "~/.tool.rc"]);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert_eq!(
        std::fs::read(home.child(".tool.rc")).expect("still there"),
        b"one\r\ntwo"
    );
    assert_eq!(
        std::fs::read_to_string(home.child(".config/bx/bx.toml")).expect("bx.toml"),
        "# mine\n"
    );

    let unnamed = bx(home.path(), &["add"]);
    assert_eq!(unnamed.status.code(), Some(1));
    assert!(stderr(&unnamed).contains("name the file or directory to add"));
}

#[test]
fn init_on_a_fresh_machine_creates_the_repo_and_a_second_init_writes_nothing() {
    let home = guarded_home();
    home.write(".zshrc", "z\n");

    let first = bx(home.path(), &["init", "--yes"]);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert!(
        stdout(&first).starts_with("Created the config repo ~/.config/bx with bx.toml.\n"),
        "{}",
        stdout(&first)
    );
    assert_eq!(
        std::fs::read_to_string(home.child(".config/bx/bx.toml")).expect("bx.toml"),
        bx::init::HEADER
    );
    assert!(
        !home.child(".config/bx/files").exists(),
        "a non-interactive init adopts nothing"
    );

    let before = snapshot(home.path());
    for args in [&["init", "--yes"][..], &["init"]] {
        let again = bx(home.path(), args);
        assert_eq!(again.status.code(), Some(0), "{args:?}: {}", stderr(&again));
        assert_eq!(
            stdout(&again),
            "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
        );
        assert_eq!(snapshot(home.path()), before, "{args:?} wrote");
    }
    let planned = bx(home.path(), &["plan"]);
    assert_eq!(planned.status.code(), Some(0), "{}", stdout(&planned));
}

#[test]
fn init_without_a_terminal_names_each_unset_value_and_its_flag_and_writes_nothing() {
    let home = guarded_home();
    seed(
        home.path(),
        "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n\n\
         [[value]]\nname = \"mail\"\nkind = \"email\"\nrequired = true\n\n\
         [[target]]\npath = \"~/.greeting\"\ncontent = \"hi {{who}} at {{mail}}\\n\"\n",
    );
    let before = snapshot(home.path());

    for args in [
        &["init"][..],
        &["init", "--yes"],
        &["init", "--yes", "--set", "who=x"],
    ] {
        let output = bx(home.path(), args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let said = stderr(&output);
        assert!(
            said.contains("bx init --set mail=VALUE"),
            "{args:?}: {said}"
        );
        assert!(said.contains("nothing was written"), "{args:?}: {said}");
        assert_eq!(snapshot(home.path()), before, "{args:?} wrote");
    }

    let bad = bx(home.path(), &["init", "--yes", "--set", "mail=nope"]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(stderr(&bad).contains("--set mail"), "{}", stderr(&bad));
    assert_eq!(snapshot(home.path()), before);

    let answered = bx(
        home.path(),
        &[
            "init",
            "--yes",
            "--set",
            "mail=a@b.invalid",
            "--set",
            "who=there",
        ],
    );
    assert_eq!(answered.status.code(), Some(0), "{}", stderr(&answered));
    assert!(
        stdout(&answered)
            .starts_with("Saved this account's answers to ~/.local/state/bx/local.toml.\n"),
        "{}",
        stdout(&answered)
    );
    assert_eq!(
        std::fs::read(home.child(".greeting")).expect("applied"),
        b"hi there at a@b.invalid\n"
    );
    let local = home.child(".local/state/bx/local.toml");
    assert!(
        std::fs::read_to_string(&local)
            .expect("local.toml")
            .ends_with("[values]\nwho = \"there\"\nmail = \"a@b.invalid\"\n"),
        "answers are written in declaration order"
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&local)
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o600);
    }
    assert!(
        !std::fs::read_to_string(home.child(".config/bx/bx.toml"))
            .expect("bx.toml")
            .contains("there"),
        "no answer reaches the repo"
    );

    let converged = snapshot(home.path());
    let again = bx(home.path(), &["init"]);
    assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
    assert_eq!(snapshot(home.path()), converged, "a second init wrote");
}

#[test]
fn init_with_pending_work_and_no_yes_or_terminal_refuses_as_apply_does() {
    let home = guarded_home();
    seed(home.path(), A_TARGET);

    let output = bx(home.path(), &["init"]);

    assert_eq!(output.status.code(), Some(1));
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
    assert!(!home.child(".a").exists());
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
