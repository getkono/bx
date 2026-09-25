//! The acceptance suite: the shipped example configuration, applied by the real
//! `bx` binary to a throwaway home, held to the invariants end to end.
//!
//! Every test here drives the built binary as a user would — `bx apply`,
//! `bx plan`, `bx rm`, `bx add`, `bx doctor` — against a home the
//! [`bx::testing`] guard hands out, with the example configuration from
//! `bench/fixtures/bx` copied in as the config repo. Nothing is called through
//! the library: a property that holds only for the library's own entry points
//! and not for the binary a user runs is not the property the invariants ask
//! for.
//!
//! The machine each test builds is hermetic but for the system's own programs:
//!
//! * the environment is cleared, and `PATH` is the bench's stub tools ahead of
//!   the system directories, so the four activations the example declares run
//!   the stubs and nothing the developer installed;
//! * the external's url is redirected, through `url.<base>.insteadOf` in the
//!   home's own `~/.gitconfig`, to a repository the test makes in a tempdir —
//!   the same seam `bx`'s own external tests use, since the configuration
//!   refuses a local url outright. The repository's commit cannot be the
//!   published one the example pins, so the copy's `rev` is rewritten to it;
//! * the secret is encrypted, in the copy, to an age identity generated for the
//!   run, which `local.toml` names. The example ships no ciphertext, because a
//!   committed one is either decryptable by a committed key or by nobody.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bx::testing::{GuardedHome, guarded_home};

/// The pinned commit the example's `[[external]]` names, which the copy
/// replaces with the local upstream's.
const PINNED: &str = "e52ee8ca55bcc56a17c828767a3f98f22a68d4eb";

/// The system directories the machine's `PATH` holds after the stubs: where
/// `git`, `zsh` and `bash` are.
const SYSTEM_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The signal the kernel sends a process that writes past its file-size limit.
const SIGXFSZ: i32 = 25;

/// The plaintext of the example's secret.
const SSH_CONFIG: &str = "Host example\n  HostName example.invalid\n  User nobody\n";

/// The answers `local.toml` gives the example's two required values.
const ANSWERS: &str =
    "[values]\ngit_name = \"Example Person\"\ngit_email = \"person@example.invalid\"\n";

/// The account's own `~/.zshrc` before bx: a line bx must carry through.
const ZSHRC: &str = "# my own zshrc\nautoload -Uz compinit && compinit -i\n";

/// The account's own `~/.bashrc` before bx.
const BASHRC: &str = "# my own bashrc\nshopt -s globstar\n";

/// Every path in the home a `bx rm` releases the example's targets from:
/// together, everything the example declares.
const MANAGED: [&str; 8] = [
    ".bashrc",
    ".config",
    ".hushlogin",
    ".inputrc",
    ".local",
    ".ssh",
    ".zshenv",
    ".zshrc",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The example configuration as the repository ships it.
fn example() -> PathBuf {
    repo_root().join("bench/fixtures/bx")
}

/// One throwaway machine: a guarded home holding the example as its config
/// repo, and the upstream its external clones from.
struct Machine {
    home: GuardedHome,
    /// Holds the upstream repository for as long as the machine lives.
    _upstream: tempfile::TempDir,
}

impl Machine {
    /// A machine with every value answered.
    fn answered() -> Self {
        Self::new(ANSWERS)
    }

    /// A machine whose `local.toml` holds `values` and names the identity.
    fn new(values: &str) -> Self {
        let home = guarded_home();
        let upstream = tempfile::tempdir().expect("a tempdir for the upstream");
        let rev = make_upstream(upstream.path());

        let repo = home.child(".config/bx");
        copy_tree(&example(), &repo);
        let externals = repo.join("modules/externals.toml");
        let text = std::fs::read_to_string(&externals).expect("modules/externals.toml");
        assert!(text.contains(PINNED), "the example pins {PINNED}");
        std::fs::write(&externals, text.replace(PINNED, &rev)).expect("the rewritten rev");

        let key = age::x25519::Identity::generate();
        let identity = home.write(
            ".config/age/key.txt",
            &format!(
                "{}\n",
                age::secrecy::ExposeSecret::expose_secret(&key.to_string())
            ),
        );
        std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600))
            .expect("a private identity");
        std::fs::create_dir_all(repo.join("secrets")).expect("the secrets directory");
        std::fs::write(
            repo.join("secrets/ssh_config.age"),
            encrypt(&key.to_public(), SSH_CONFIG.as_bytes()),
        )
        .expect("the secret's ciphertext");

        home.write(
            ".local/state/bx/local.toml",
            &format!("{values}\n[secrets]\nidentity = \"~/.config/age/key.txt\"\n"),
        );
        home.write(
            ".gitconfig",
            &format!(
                "[url \"file://{}/\"]\n\tinsteadOf = https://github.com/zsh-users/\n",
                upstream.path().display()
            ),
        );
        home.write(".zshrc", ZSHRC);
        home.write(".bashrc", BASHRC);

        Self {
            home,
            _upstream: upstream,
        }
    }

    fn path(&self) -> &Path {
        self.home.path()
    }

    /// `PATH` for everything the machine runs: the bench's stubs first.
    fn search_path() -> String {
        format!(
            "{}:{SYSTEM_PATH}",
            repo_root().join("bench/stubs").display()
        )
    }

    /// A command with this machine's environment and nothing else.
    ///
    /// But for where a coverage build writes its profile: `cargo llvm-cov`
    /// names the file in `LLVM_PROFILE_FILE`, and an instrumented `bx` without
    /// it writes one into its working directory — the home, where every
    /// comparison here would find it.
    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("HOME", self.path())
            .env("PATH", Self::search_path())
            .current_dir(self.path());
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        command
    }

    /// Run `bx ARGS`.
    fn bx(&self, args: &[&str]) -> Run {
        Run::of(
            self.command(env!("CARGO_BIN_EXE_bx"))
                .args(args)
                .output()
                .expect("bx runs"),
            format!("bx {}", args.join(" ")),
        )
    }

    /// `bx apply --yes`, which must converge.
    fn apply(&self) -> Run {
        self.bx(&["apply", "--yes"]).converged()
    }

    /// `bx rm` on every path the example declares, each of which must hand
    /// back everything under it.
    fn rm_everything(&self) {
        for path in MANAGED {
            self.bx(&["rm", path]).converged();
        }
    }

    /// The machine's state directory.
    fn state(&self) -> PathBuf {
        self.home.child(".local/state/bx")
    }

    /// Every entry in the home.
    fn everything(&self) -> Snapshot {
        Snapshot::of(self.path(), &[])
    }

    /// Every entry in the home but the config repo, which `bx rm` edits, and
    /// the state directory, which is bx's own.
    fn the_accounts(&self) -> Snapshot {
        Snapshot::of(self.path(), &[".config/bx", ".local/state/bx"])
    }
}

/// A finished `bx` run, and what the assertions about it print.
struct Run {
    output: Output,
    what: String,
}

impl Run {
    fn of(output: Output, what: String) -> Self {
        Self { output, what }
    }

    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }

    fn code(&self) -> Option<i32> {
        self.output.status.code()
    }

    /// Hold the run to an exit code.
    fn exits(self, code: i32) -> Self {
        assert_eq!(
            self.code(),
            Some(code),
            "{} exited {:?}, not {code}\nstdout:\n{}\nstderr:\n{}",
            self.what,
            self.output.status,
            self.stdout(),
            self.stderr()
        );
        self
    }

    /// Exit 0: converged, nothing left to do.
    fn converged(self) -> Self {
        self.exits(0)
    }
}

/// An upstream repository for the example's external, at `root`'s
/// `zsh-autosuggestions`, with one commit; returns the commit's id.
fn make_upstream(root: &Path) -> String {
    let dir = root.join("zsh-autosuggestions");
    std::fs::create_dir_all(&dir).expect("the upstream");
    std::fs::write(
        dir.join("zsh-autosuggestions.zsh"),
        "typeset -g EXAMPLE_PLUGIN_LOADED=1\n",
    )
    .expect("the plugin file");
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .env_clear()
            .env("PATH", SYSTEM_PATH)
            .env("HOME", root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .current_dir(&dir)
            .args(args)
            .output()
            .expect("git runs");
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).expect("UTF-8")
    };
    git(&["init", "--quiet", "-b", "master"]);
    git(&["add", "--all"]);
    git(&["commit", "--quiet", "-m", "the plugin"]);
    git(&["rev-parse", "HEAD"]).trim().to_string()
}

/// `plaintext` encrypted to `recipient`.
fn encrypt(recipient: &age::x25519::Recipient, plaintext: &[u8]) -> Vec<u8> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .expect("a recipient");
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).expect("the output");
    writer.write_all(plaintext).expect("the plaintext");
    writer.finish().expect("the stream");
    out
}

/// Copy the directory `from` to `to`, recursively, files and links alike.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("the destination directory");
    let mut entries: Vec<_> = std::fs::read_dir(from)
        .expect("the source directory")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    entries.sort();
    for source in entries {
        let dest = to.join(source.file_name().expect("a name"));
        let meta = std::fs::symlink_metadata(&source).expect("metadata");
        if meta.is_dir() {
            copy_tree(&source, &dest);
        } else if meta.file_type().is_symlink() {
            let text = std::fs::read_link(&source).expect("the link");
            std::os::unix::fs::symlink(text, &dest).expect("the copied link");
        } else {
            std::fs::copy(&source, &dest).expect("the copied file");
        }
    }
}

/// One entry of a directory walk: what a byte-for-byte comparison compares.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir { mode: u32 },
    File { mode: u32, bytes: Vec<u8> },
    Link { text: PathBuf },
}

/// Every entry beneath a root, by its path relative to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot(BTreeMap<PathBuf, Entry>);

impl Snapshot {
    /// Walk `root`, leaving out each relative path in `skip` and everything
    /// beneath it.
    fn of(root: &Path, skip: &[&str]) -> Self {
        let mut entries = BTreeMap::new();
        walk(root, Path::new(""), skip, &mut entries);
        Self(entries)
    }

    /// The paths whose entries differ between `self` and `other`, for a
    /// failure message that says where rather than dumping both.
    fn differences(&self, other: &Self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self
            .0
            .keys()
            .chain(other.0.keys())
            .filter(|path| self.0.get(*path) != other.0.get(*path))
            .cloned()
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

fn walk(root: &Path, rel: &Path, skip: &[&str], entries: &mut BTreeMap<PathBuf, Entry>) {
    let dir = root.join(rel);
    for entry in std::fs::read_dir(&dir).expect("a directory") {
        let name = entry.expect("an entry").file_name();
        let rel = rel.join(&name);
        if skip.iter().any(|skipped| rel == Path::new(skipped)) {
            continue;
        }
        let path = root.join(&rel);
        let meta = std::fs::symlink_metadata(&path).expect("metadata");
        let mode = meta.permissions().mode() & 0o7777;
        if meta.file_type().is_symlink() {
            let text = std::fs::read_link(&path).expect("the link");
            entries.insert(rel, Entry::Link { text });
        } else if meta.is_dir() {
            entries.insert(rel.clone(), Entry::Dir { mode });
            walk(root, &rel, skip, entries);
        } else {
            let bytes = std::fs::read(&path).expect("the file");
            entries.insert(rel, Entry::File { mode, bytes });
        }
    }
}

/// Assert two snapshots are the same, naming the paths that are not.
#[track_caller]
fn assert_same(before: &Snapshot, after: &Snapshot, what: &str) {
    let differences = before.differences(after);
    assert!(differences.is_empty(), "{what}: {differences:#?}");
}

#[test]
fn applying_the_example_twice_changes_nothing_the_second_time() {
    let machine = Machine::answered();

    let first = machine.apply();
    assert!(
        first.stdout().contains(" 0 conflict, 0 blocked"),
        "{}",
        first.stdout()
    );
    let applied = machine.everything();

    let plan = machine.bx(&["plan"]).converged();
    assert!(
        plan.stdout()
            .contains("Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, "),
        "{}",
        plan.stdout()
    );
    assert_same(&applied, &machine.everything(), "plan wrote something");

    let second = machine.apply();
    assert!(!second.stdout().contains("Applied"), "{}", second.stdout());
    assert_same(
        &applied,
        &machine.everything(),
        "the second apply changed the home or the state directory",
    );
}

#[test]
fn the_example_lands_every_kind_of_target_it_declares() {
    let machine = Machine::answered();
    machine.apply();
    let home = machine.path();

    // An owned file, byte for byte.
    assert_eq!(
        std::fs::read(home.join(".config/starship.toml")).expect("starship.toml"),
        std::fs::read(example().join("home/.config/starship.toml")).expect("the body")
    );
    // A tree, file by file, leaving out what it excludes.
    assert!(home.join(".config/nvim/lua/config/options.lua").is_file());
    assert!(!home.join(".config/nvim/README.md").exists());
    // A directory with its declared mode, and an empty file.
    let ssh = std::fs::metadata(home.join(".ssh")).expect("~/.ssh");
    assert_eq!(ssh.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::read(home.join(".hushlogin")).expect("~/.hushlogin"),
        b""
    );
    // A symlink holding its text as written.
    assert_eq!(
        std::fs::read_link(home.join(".local/bin/vim")).expect("the link"),
        Path::new("nvim")
    );
    // The secret, decrypted, private.
    assert_eq!(
        std::fs::read_to_string(home.join(".ssh/config")).expect("~/.ssh/config"),
        SSH_CONFIG
    );
    let secret = std::fs::metadata(home.join(".ssh/config")).expect("~/.ssh/config");
    assert_eq!(secret.permissions().mode() & 0o777, 0o600);
    // The declared values, substituted.
    assert_eq!(
        std::fs::read_to_string(home.join(".config/git/identity")).expect("the identity"),
        "[user]\n\tname = Example Person\n\temail = person@example.invalid\n"
    );
    // The external, checked out.
    assert!(
        home.join(".local/share/zsh/zsh-autosuggestions/zsh-autosuggestions.zsh")
            .is_file()
    );
    // The account's own startup files, carried through around bx's region.
    let zshrc = std::fs::read_to_string(home.join(".zshrc")).expect("~/.zshrc");
    assert!(zshrc.starts_with(ZSHRC), "{zshrc}");
    assert!(zshrc.contains("# >>> bx >>>\n"), "{zshrc}");
    let bashrc = std::fs::read_to_string(home.join(".bashrc")).expect("~/.bashrc");
    assert!(bashrc.starts_with(BASHRC), "{bashrc}");
    assert!(bashrc.contains("# >>> bx >>>\n"), "{bashrc}");
}

#[test]
fn rm_on_every_target_restores_the_home_exactly() {
    let machine = Machine::answered();
    let before = machine.the_accounts();

    machine.apply();
    assert_ne!(before, machine.the_accounts(), "apply wrote nothing");
    machine.rm_everything();

    assert_same(
        &before,
        &machine.the_accounts(),
        "rm left the home different from before apply",
    );
    // Nothing is left for a later rm to release.
    for path in MANAGED {
        let again = machine.bx(&["rm", path]).converged();
        assert!(
            again
                .stdout()
                .contains("is not managed by bx; nothing to do."),
            "{}",
            again.stdout()
        );
    }
}

#[test]
fn an_edit_outside_a_region_survives_and_an_edit_inside_one_is_a_conflict() {
    let machine = Machine::answered();
    machine.apply();
    let home = machine.path();

    // A line the account adds after bx's region is theirs.
    let zshrc = home.join(".zshrc");
    let mut text = std::fs::read_to_string(&zshrc).expect("~/.zshrc");
    text.push_str("alias mine='echo mine'\n");
    std::fs::write(&zshrc, &text).expect("the account's edit");
    machine.bx(&["plan"]).converged();
    machine.apply();
    assert_eq!(std::fs::read_to_string(&zshrc).expect("~/.zshrc"), text);

    // An edit inside the region, or to a file bx owns whole, is reported and
    // never overwritten.
    let bashrc = home.join(".bashrc");
    let edited_region = std::fs::read_to_string(&bashrc)
        .expect("~/.bashrc")
        .replace("# <<< bx <<<\n", "echo edited\n# <<< bx <<<\n");
    std::fs::write(&bashrc, &edited_region).expect("an edit inside the region");
    let starship = home.join(".config/starship.toml");
    std::fs::write(&starship, "add_newline = true\n").expect("an edit to an owned file");

    let plan = machine.bx(&["plan"]).exits(2);
    assert!(plan.stdout().contains("  ! ~/.bashrc"), "{}", plan.stdout());
    assert!(
        plan.stdout().contains("  ! ~/.config/starship.toml"),
        "{}",
        plan.stdout()
    );
    assert!(plan.stdout().contains(" 2 conflict, "), "{}", plan.stdout());
    machine.bx(&["apply", "--yes"]).exits(2);
    assert_eq!(
        std::fs::read_to_string(&bashrc).expect("~/.bashrc"),
        edited_region
    );
    assert_eq!(
        std::fs::read_to_string(&starship).expect("starship.toml"),
        "add_newline = true\n"
    );
}

#[test]
fn unanswered_values_hold_back_exactly_the_targets_that_name_them() {
    let machine = Machine::new("");
    let identity = machine.path().join(".config/git/identity");

    let plan = machine.bx(&["plan"]).exits(2);
    let shown = plan.stdout();
    let blocked: Vec<&str> = shown
        .lines()
        .filter(|line| line.starts_with("  ? "))
        .collect();
    assert_eq!(blocked.len(), 1, "{}", plan.stdout());
    assert!(
        blocked[0].starts_with("  ? ~/.config/git/identity "),
        "{blocked:?}"
    );

    // Everything else still applies.
    let apply = machine.bx(&["apply", "--yes"]).exits(2);
    assert!(
        apply.stdout().contains(" 0 conflict, 1 blocked, "),
        "{}",
        apply.stdout()
    );
    assert!(!identity.exists());
    assert!(machine.path().join(".config/git/config").is_file());
    assert!(machine.path().join(".ssh/config").is_file());

    // Answering them releases exactly that target.
    machine.home.write(
        ".local/state/bx/local.toml",
        &format!("{ANSWERS}\n[secrets]\nidentity = \"~/.config/age/key.txt\"\n"),
    );
    let plan = machine.bx(&["plan"]).exits(2);
    assert!(
        plan.stdout()
            .contains("Plan: 1 to create, 0 to modify, 0 conflict, 0 blocked, "),
        "{}",
        plan.stdout()
    );
    assert!(
        plan.stdout().contains("  + ~/.config/git/identity "),
        "{}",
        plan.stdout()
    );
    machine.apply();
    assert!(identity.is_file());
    machine.bx(&["plan"]).converged();
}

#[test]
fn an_interrupted_apply_is_detected_and_rolled_back() {
    let machine = Machine::answered();
    let before = machine.the_accounts();

    // A file-size limit the generated interactive files exceed: the kernel
    // stops bx with SIGXFSZ partway through its session, after the smaller
    // files before them are already in place — a crash at a point no test
    // hook chose.
    let output = machine
        .command("sh")
        .args([
            "-c",
            "ulimit -f 8 && exec \"$0\" apply --yes",
            env!("CARGO_BIN_EXE_bx"),
        ])
        .output()
        .expect("sh runs");
    assert_eq!(
        output.status.signal(),
        Some(SIGXFSZ),
        "bx was not stopped by SIGXFSZ: {output:?}"
    );
    assert!(
        machine.state().join("journal.mpk").is_file(),
        "the interrupted session left no journal"
    );
    assert_ne!(before, machine.the_accounts(), "the session wrote nothing");

    // A read-only command reports it and changes nothing.
    let interrupted = machine.everything();
    let plan = machine.bx(&["plan"]);
    assert!(
        format!("{}{}", plan.stdout(), plan.stderr()).contains("interrupted"),
        "{}\n{}",
        plan.stdout(),
        plan.stderr()
    );
    assert_same(&interrupted, &machine.everything(), "plan wrote something");

    // The next writing command rolls it back, exactly, and does nothing else.
    let rollback = machine.bx(&["apply", "--yes"]).exits(2);
    assert!(
        rollback
            .stdout()
            .contains("from an interrupted session; nothing else was applied"),
        "{}",
        rollback.stdout()
    );
    assert!(!machine.state().join("journal.mpk").exists());
    // Nothing is left behind: every write journals its temporary file and the
    // directories it will make before it makes them, so wherever the limit
    // stops bx — in a fill, or in the journal's own append — the rollback
    // removes the one and prunes the others (#119). No `.bx-` orphan
    // survives it, so `bx doctor` names none.
    assert_same(
        &before,
        &machine.the_accounts(),
        "the rollback left the home different from before the session",
    );
    doctor_names(&machine, &[]);

    // The one after it converges.
    machine.apply();
    machine.bx(&["plan"]).converged();

    // And what it converged to is recorded exactly: rm still restores the
    // home as it was before the interrupted run.
    machine.rm_everything();
    assert_same(
        &before,
        &machine.the_accounts(),
        "rm after a recovered apply left the home different",
    );
}

/// Assert `bx doctor` names each of `orphans`, home-relative paths, as an
/// orphaned temporary file, and names no other.
#[track_caller]
fn doctor_names(machine: &Machine, orphans: &[PathBuf]) {
    let doctor = machine.bx(&["doctor"]);
    let stdout = doctor.stdout();
    let named: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains(" is a temporary file a bx write left "))
        .collect();
    let expected: Vec<String> = orphans
        .iter()
        .map(|orphan| {
            format!(
                "  ! ~/{} is a temporary file a bx write left ",
                orphan.display()
            )
        })
        .collect();
    assert_eq!(
        named.len(),
        expected.len(),
        "doctor named {named:?}, not {orphans:?}"
    );
    for (line, prefix) in named.iter().zip(&expected) {
        assert!(
            line.starts_with(prefix.as_str()),
            "{line:?} is not {prefix:?}"
        );
    }
}

/// Run `shell -i -c SCRIPT` on the machine.
fn interactive(machine: &Machine, shell: &str, script: &str) -> Output {
    machine
        .command(shell)
        .args(["-i", "-c", script])
        .env("TERM", "dumb")
        .output()
        .expect("the shell runs")
}

#[test]
fn zsh_and_bash_start_cleanly_with_what_bx_generated() {
    let machine = Machine::answered();
    machine.apply();

    for shell in ["zsh", "bash"] {
        let output = interactive(&machine, shell, "exit");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{shell}: {output:?}");
        assert!(
            !stderr.contains("not found") && !stderr.contains("error"),
            "{shell} complained starting up:\n{stderr}"
        );
    }

    // The declarations reached each shell.
    let zsh = interactive(
        &machine,
        "zsh",
        "alias g >/dev/null && typeset -f mkcd >/dev/null && [[ $HISTSIZE == 10000 ]] \
         && [[ $EDITOR == nvim ]] && [[ -n ${__bench_mise_loaded-} ]] \
         && [[ -n ${EXAMPLE_PLUGIN_LOADED-} ]]",
    );
    assert!(zsh.status.success(), "zsh: {zsh:?}");
    let bash = interactive(
        &machine,
        "bash",
        "alias g >/dev/null && type mkcd >/dev/null && [[ $HISTSIZE == 10000 ]] \
         && [[ $EDITOR == nvim ]] && [[ -n ${__bench_mise_loaded-} ]] \
         && ! type pane_title >/dev/null 2>&1",
    );
    assert!(bash.status.success(), "bash: {bash:?}");
}

#[test]
fn adopting_a_file_takes_it_verbatim_and_rm_hands_it_back() {
    let machine = Machine::answered();
    machine.apply();
    let tmux = machine
        .home
        .write(".config/tmux/tmux.conf", "set -g mouse on\n");
    let before = machine.the_accounts();

    machine.bx(&["add", ".config/tmux/tmux.conf"]).converged();
    assert_eq!(
        std::fs::read(
            machine
                .home
                .child(".config/bx/files/.config/tmux/tmux.conf")
        )
        .expect("the adopted copy"),
        b"set -g mouse on\n"
    );
    assert_same(&before, &machine.the_accounts(), "add wrote to the home");
    machine.bx(&["plan"]).converged();

    machine.bx(&["rm", ".config/tmux/tmux.conf"]).converged();
    assert_eq!(
        std::fs::read(&tmux).expect("tmux.conf"),
        b"set -g mouse on\n"
    );
    assert_same(
        &before,
        &machine.the_accounts(),
        "rm changed the adopted file",
    );
}

#[test]
fn doctor_looks_at_the_applied_example_and_changes_nothing() {
    let machine = Machine::answered();
    machine.apply();
    let before = machine.everything();

    let doctor = machine.bx(&["doctor"]);
    assert!(
        matches!(doctor.code(), Some(0 | 2)),
        "doctor failed: {}\n{}",
        doctor.stdout(),
        doctor.stderr()
    );
    assert_same(&before, &machine.everything(), "doctor wrote something");
}

#[test]
fn the_example_names_no_account_machine_or_key() {
    // What an operator's own configuration would leak: a home or mount path, an
    // email address outside the reserved example domains, a public or private
    // key, and the account and machine this suite runs on.
    let mut forbidden: Vec<String> = [
        "/home/",
        "/Users/",
        "/mnt/",
        "/media/",
        "/var/scratch",
        "ssh-ed25519 ",
        "ssh-rsa ",
        "ecdsa-sha2-",
        "PRIVATE KEY",
        "AGE-SECRET-KEY-",
    ]
    .map(str::to_string)
    .to_vec();
    for name in ["USER", "LOGNAME"] {
        if let Some(value) = std::env::var_os(name) {
            let value = value.to_string_lossy().into_owned();
            if value.len() >= 4 {
                forbidden.push(value);
            }
        }
    }
    if let Ok(host) = std::fs::read_to_string("/etc/hostname") {
        let host = host.trim().to_string();
        if host.len() >= 4 {
            forbidden.push(host);
        }
    }

    let files = Snapshot::of(&example(), &[]);
    assert!(files.0.len() > 10, "the walk found the example");
    for (path, entry) in &files.0 {
        let Entry::File { bytes, .. } = entry else {
            continue;
        };
        let text = String::from_utf8_lossy(bytes);
        for needle in &forbidden {
            assert!(
                !text.contains(needle.as_str()),
                "{} names {needle:?}",
                path.display()
            );
        }
        // An age recipient, `age1` and 58 lowercase bech32 characters.
        assert!(
            !text
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|word| {
                    word.len() == 62
                        && word.starts_with("age1")
                        && word
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                }),
            "{} names an age recipient",
            path.display()
        );
        for word in text.split(|c: char| c.is_whitespace() || "\"'<>(),;".contains(c)) {
            if let Some((_, domain)) = word.split_once('@') {
                let domain = domain.trim_end_matches(['.', '}']);
                assert!(
                    !domain.contains('.')
                        || domain.ends_with("example.com")
                        || domain.ends_with(".invalid")
                        || domain.ends_with("example.org"),
                    "{} names the address {word:?}",
                    path.display()
                );
            }
        }
    }
}
