//! The starter configuration in `examples/starter`, copied as the README says
//! and applied by the real binary to a throwaway home.
//!
//! Nothing else exercises this example: the acceptance suite and the bench both
//! use `bench/fixtures/bx`. So the invariants a reader is promised by copying it
//! are held here, along with the two ways a first run differs from a tidy one:
//! a prompt config already on the machine, and starship not installed.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bx::testing::{GuardedHome, guarded_home};

/// Where the system's own programs are, so a shell and `ls` can be found.
const SYSTEM_PATH: &str = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin";

/// What `~/.zshrc` holds before bx sees it.
const ZSHRC: &str = "# this account's own line\nexport MINE=1\n";

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/starter")
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("the destination directory");
    for entry in std::fs::read_dir(from).expect("the source directory") {
        let source = entry.expect("an entry").path();
        let dest = to.join(source.file_name().expect("a name"));
        if source.is_dir() {
            copy_tree(&source, &dest);
        } else {
            std::fs::copy(&source, &dest).expect("the copied file");
        }
    }
}

/// A throwaway home holding the example as its config repo.
struct Machine {
    home: GuardedHome,
    /// Holds the stub tool, when this machine has starship.
    stubs: tempfile::TempDir,
}

impl Machine {
    /// A machine with starship installed, here the bench's stub of it.
    fn with_starship() -> Self {
        let machine = Self::without_starship();
        machine.install_starship();
        machine
    }

    /// Put the stub on this machine's `PATH`. It prints what `gen.sh`, beside
    /// it, generates.
    fn install_starship(&self) {
        for name in ["starship", "gen.sh"] {
            let stub = self.stubs.path().join(name);
            std::fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("bench/stubs")
                    .join(name),
                &stub,
            )
            .expect("the stub");
            common::chmod(&stub, 0o755);
        }
    }

    fn without_starship() -> Self {
        let home = guarded_home();
        copy_tree(&example(), &home.child(".config/bx"));
        home.write(".zshrc", ZSHRC);
        // Where bx keeps its state, there first so that `rm` has no parent
        // directory of it to leave behind.
        std::fs::create_dir_all(home.child(".local/state/bx")).expect("the state directory");
        Self {
            home,
            stubs: tempfile::tempdir().expect("a tempdir for the stubs"),
        }
    }

    fn path(&self) -> &Path {
        self.home.path()
    }

    /// A command with this machine's environment and nothing else.
    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = common::isolated(program);
        command
            .env("HOME", self.path())
            .env(
                "PATH",
                format!("{}:{SYSTEM_PATH}", self.stubs.path().display()),
            )
            .env("TERM", "dumb")
            .current_dir(self.path());
        command
    }

    fn bx(&self, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_bx"))
            .args(args)
            .output()
            .expect("bx runs")
    }

    /// Run `bx ARGS`, holding it to exit 0.
    fn converged(&self, args: &[&str]) -> String {
        let output = self.bx(args);
        assert!(output.status.success(), "bx {args:?}: {output:#?}");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Every file and directory in the home that is the account's rather than
    /// bx's, each with its bytes.
    fn the_accounts(&self) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        let mut found = BTreeMap::new();
        walk(self.path(), self.path(), &mut found);
        found
    }
}

fn walk(root: &Path, dir: &Path, found: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
    for entry in std::fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        let relative = path.strip_prefix(root).expect("under the root").to_owned();
        if relative == Path::new(".config/bx") || relative == Path::new(".local/state/bx") {
            continue;
        }
        if path.is_dir() {
            found.insert(relative, None);
            walk(root, &path, found);
        } else {
            found.insert(relative, Some(std::fs::read(&path).expect("a file")));
        }
    }
}

/// Start an interactive zsh running `script`, holding it to a clean start.
fn zsh_starts_cleanly(machine: &Machine, script: &str) {
    let output = machine
        .command("zsh")
        .args(["-i", "-c", script])
        .output()
        .expect("zsh runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "zsh: {output:#?}");
    assert!(
        [
            "not found",
            "error",
            "invalid",
            "bad substitution",
            "no such",
            "permission denied",
        ]
        .iter()
        .all(|complaint| !stderr.contains(complaint)),
        "zsh complained starting up:\n{stderr}"
    );
}

#[test]
fn applying_delivers_the_prompt_config_and_keeps_the_accounts_zshrc() {
    let machine = Machine::with_starship();
    machine.converged(&["apply", "--yes"]);

    assert_eq!(
        std::fs::read(machine.home.child(".config/starship.toml")).expect("the delivered config"),
        std::fs::read(example().join("home/.config/starship.toml")).expect("the example's config"),
    );
    let zshrc = std::fs::read_to_string(machine.home.child(".zshrc")).expect("~/.zshrc");
    assert!(zshrc.starts_with(ZSHRC), "{zshrc}");
    assert!(zshrc.contains(">>> bx"), "no region in:\n{zshrc}");
}

#[test]
fn a_second_apply_has_nothing_to_do() {
    let machine = Machine::with_starship();
    machine.converged(&["apply", "--yes"]);
    let applied = machine.the_accounts();

    let plan = machine.converged(&["plan"]);
    assert!(
        plan.contains("Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, "),
        "{plan}"
    );
    machine.converged(&["apply", "--yes"]);
    assert_eq!(applied, machine.the_accounts());
}

#[test]
fn rm_on_everything_applied_restores_the_home() {
    let machine = Machine::with_starship();
    let before = machine.the_accounts();
    machine.converged(&["apply", "--yes"]);
    assert_ne!(before, machine.the_accounts(), "apply wrote nothing");

    let top_level: Vec<PathBuf> = std::fs::read_dir(machine.path())
        .expect("the home")
        .map(|entry| PathBuf::from(entry.expect("an entry").file_name()))
        .collect();
    for path in top_level {
        machine.converged(&["rm", path.to_str().expect("a plain name")]);
    }
    assert_eq!(before, machine.the_accounts());
}

#[test]
fn zsh_gets_the_declarations_and_the_prompt() {
    let machine = Machine::with_starship();
    machine.converged(&["apply", "--yes"]);
    zsh_starts_cleanly(
        &machine,
        "alias ll >/dev/null && [[ -n ${__bench_starship_loaded-} ]]",
    );
    let zsh = std::fs::read_to_string(machine.home.child(".local/share/bx/zshrc.zsh"))
        .expect("the generated zsh file");
    assert!(zsh.contains("beginning-of-line"), "{zsh}");
    assert!(zsh.contains("end-of-line"), "{zsh}");
}

#[test]
fn bash_gets_the_alias_and_the_keybindings_but_not_the_prompt() {
    let machine = Machine::with_starship();
    machine.converged(&["apply", "--yes"]);

    let bash = machine
        .command("bash")
        .args([
            "-i",
            "-c",
            "alias ll >/dev/null && [[ -z ${__bench_starship_loaded-} ]]",
        ])
        .output()
        .expect("bash runs");
    assert!(bash.status.success(), "bash: {bash:#?}");
    let inputrc = std::fs::read_to_string(machine.home.child(".inputrc")).expect("~/.inputrc");
    assert!(inputrc.contains("beginning-of-line"), "{inputrc}");
}

#[test]
fn an_inputrc_already_there_is_not_overwritten() {
    let machine = Machine::with_starship();
    let mine = "set editing-mode vi\n";
    machine.home.write(".inputrc", mine);

    let applied = machine.bx(&["apply", "--yes"]);
    assert_eq!(
        std::fs::read_to_string(machine.home.child(".inputrc")).expect("~/.inputrc"),
        mine,
        "{applied:#?}"
    );
    assert_eq!(applied.status.code(), Some(2), "{applied:#?}");
    let stdout = String::from_utf8_lossy(&applied.stdout);
    assert!(stdout.contains("1 conflict"), "{stdout}");

    // The way out the README gives: delete the [keybindings] from the copy.
    // It is the manifest's last section.
    let manifest = std::fs::read_to_string(machine.home.child(".config/bx/bx.toml"))
        .expect("the copied manifest");
    let (kept, _) = manifest
        .split_once("[keybindings]")
        .expect("the example declares keybindings");
    machine.home.write(".config/bx/bx.toml", kept);
    machine.converged(&["apply", "--yes"]);
    assert_eq!(
        std::fs::read_to_string(machine.home.child(".inputrc")).expect("~/.inputrc"),
        mine
    );
}

#[test]
fn installing_starship_later_and_applying_brings_the_prompt() {
    let machine = Machine::without_starship();
    let blocked = machine
        .command(env!("CARGO_BIN_EXE_bx"))
        .args(["apply", "--yes"])
        .env("PATH", machine.stubs.path())
        .output()
        .expect("bx runs");
    assert_eq!(blocked.status.code(), Some(2), "{blocked:#?}");

    machine.install_starship();
    machine.converged(&["apply", "--yes"]);
    zsh_starts_cleanly(&machine, "[[ -n ${__bench_starship_loaded-} ]]");
}

#[test]
fn a_long_history_already_there_keeps_every_line() {
    let machine = Machine::with_starship();
    let lines: String = (0..30_000).map(|n| format!("echo {n}\n")).collect();
    machine.home.write(".bash_history", &lines);
    machine.home.write(".zsh_history", &lines);
    machine
        .home
        .write(".bashrc", "HISTSIZE=100000\nHISTFILESIZE=100000\n");
    let zshrc = format!("{ZSHRC}HISTFILE=~/.zsh_history\nHISTSIZE=100000\nSAVEHIST=100000\n");
    machine.home.write(".zshrc", &zshrc);
    machine.converged(&["apply", "--yes"]);

    for shell in ["bash", "zsh"] {
        let output = machine
            .command(shell)
            .args(["-i", "-c", "exit"])
            .output()
            .expect("the shell runs");
        assert!(output.status.success(), "{shell}: {output:#?}");
    }
    for file in [".bash_history", ".zsh_history"] {
        let kept = std::fs::read_to_string(machine.home.child(file)).expect("the history");
        assert!(
            kept.lines().count() >= 30_000,
            "{file} kept {} lines",
            kept.lines().count()
        );
    }
}

#[test]
fn the_prompt_config_is_valid_toml() {
    let text = std::fs::read_to_string(example().join("home/.config/starship.toml"))
        .expect("the example's config");
    text.parse::<toml_edit::DocumentMut>().expect("valid TOML");
}

#[test]
fn a_machine_without_starship_still_starts_zsh() {
    let machine = Machine::without_starship();
    // Only the empty stub directory on `PATH`, so a starship the developer has
    // installed cannot answer.
    let applied = machine
        .command(env!("CARGO_BIN_EXE_bx"))
        .args(["apply", "--yes"])
        .env("PATH", machine.stubs.path())
        .output()
        .expect("bx runs");
    let stdout = String::from_utf8_lossy(&applied.stdout);
    assert_eq!(applied.status.code(), Some(2), "{applied:#?}");
    assert!(stdout.contains("1 blocked"), "{stdout}");
    assert!(stdout.contains("activation `starship`"), "{stdout}");
    assert!(
        machine.home.child(".config/starship.toml").exists(),
        "{stdout}"
    );
    zsh_starts_cleanly(&machine, "alias ll >/dev/null");
}

#[test]
fn init_keeps_the_copied_repo_and_applies_it() {
    let machine = Machine::with_starship();
    let manifest = machine.home.child(".config/bx/bx.toml");
    let copied = std::fs::read(&manifest).expect("the copied manifest");

    machine.converged(&["init", "--yes"]);

    assert_eq!(copied, std::fs::read(&manifest).expect("the manifest"));
    assert!(machine.home.child(".config/starship.toml").exists());
}

#[test]
fn a_prompt_config_already_there_is_not_overwritten() {
    let machine = Machine::with_starship();
    let mine = "add_newline = true\n";
    machine.home.write(".config/starship.toml", mine);

    let applied = machine.bx(&["apply", "--yes"]);
    assert_eq!(
        std::fs::read_to_string(machine.home.child(".config/starship.toml")).expect("the config"),
        mine,
        "{applied:#?}"
    );
    assert_eq!(applied.status.code(), Some(2), "{applied:#?}");
    let stdout = String::from_utf8_lossy(&applied.stdout);
    assert!(stdout.contains("1 conflict"), "{stdout}");
}

#[test]
fn the_example_names_no_account_machine_or_key() {
    let mut forbidden: Vec<String> = [
        "/home/",
        "/Users/",
        "/mnt/",
        "/media/",
        "ssh-ed25519 ",
        "ssh-rsa ",
        "PRIVATE KEY",
        "AGE-SECRET-KEY-",
        "ghp_",
        "@",
    ]
    .map(str::to_string)
    .to_vec();
    if let Some(user) = std::env::var_os("USER") {
        let user = user.to_string_lossy().into_owned();
        // The prompt config has `style_root` and `style_user`, which name
        // neither an account nor a machine.
        if user.len() >= 4 && user != "root" && user != "user" {
            forbidden.push(user);
        }
    }

    let mut files = BTreeMap::new();
    walk(&example(), &example(), &mut files);
    assert!(files.contains_key(Path::new("bx.toml")));
    for (path, bytes) in &files {
        let Some(bytes) = bytes else { continue };
        let text = String::from_utf8_lossy(bytes);
        for needle in &forbidden {
            assert!(
                !text.contains(needle.as_str()),
                "{} names {needle:?}",
                path.display()
            );
        }
    }
}
