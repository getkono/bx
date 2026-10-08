//! The guard held to real programs: each shell bx writes for, and the tools
//! whose reading of a value a refusal rests on, run against what the guard
//! approves and refuses.

use std::collections::HashMap;

use super::*;
use crate::env_guard::table::SHELL_NAMES;
use crate::paths;

#[test]
fn bun_reads_a_backslash_as_a_separator_and_the_guard_refuses_it() {
    // The mechanism behind the character allowlist, held to a real bun when
    // one is installed. Everything is in a temporary directory, the home
    // included, and `bun pm cache` only prints where the cache would be.
    let Some(bun) = installed("bun") else {
        return;
    };
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let root = scratch.path().join("r");
    let home = scratch.path().join("h");
    let state = home.join(".local/state/bx");
    std::fs::create_dir_all(root.join("a")).expect("the root");
    std::fs::create_dir_all(&state).expect("a stand-in state directory");
    std::fs::write(
        scratch.path().join("package.json"),
        "{\"name\":\"p\",\"version\":\"0.0.0\"}\n",
    )
    .expect("a package to run bun in");
    let value = format!(r"{}/a\..\..\h\.local\state\bx", root.display());
    let output = std::process::Command::new(bun)
        .args(["pm", "cache"])
        .current_dir(scratch.path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/nonexistent")
        .env("BUN_INSTALL_CACHE_DIR", &value)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("an installed bun runs");
    let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(
        paths::normalize(Path::new(&printed)),
        paths::normalize(&state),
        "bun read {value:?} as {printed:?} ({}; stderr {:?})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let roots = RootSet::new(&home, std::slice::from_ref(&root));
    assert_eq!(
        reason_of(&check(
            "BUN_INSTALL_CACHE_DIR",
            &format!("'{value}'"),
            &roots
        )),
        Some(Reason::UnlistedCharacter('\\'))
    );
}

#[test]
fn uv_puts_executables_beside_its_data_home_and_the_guard_refuses_a_root() {
    // The mechanism behind `DeclaredRootItself`, held to a real uv when one
    // is installed. `dir --bin` only prints where executables would go, and
    // the home, the root and anything uv writes are in a temporary
    // directory.
    let Some(uv) = installed("uv") else {
        return;
    };
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let root = scratch.path().join("r");
    let home = scratch.path().join("h");
    std::fs::create_dir_all(&root).expect("the root");
    std::fs::create_dir_all(&home).expect("the home");
    let roots = RootSet::new(&home, std::slice::from_ref(&root));
    let bin_dir = |data_home: &Path, args: &[&str]| {
        let output = std::process::Command::new(&uv)
            .args(args)
            .current_dir(scratch.path())
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/nonexistent")
            .env("UV_NO_CONFIG", "1")
            .env("XDG_DATA_HOME", data_home)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("an installed uv runs");
        let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(
            output.status.success() && !printed.is_empty(),
            "uv {args:?} printed {printed:?} ({}; stderr {:?})",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        paths::normalize(Path::new(&printed))
    };
    for args in [["tool", "dir", "--bin"], ["python", "dir", "--bin"]] {
        let beside = bin_dir(&root, &args);
        assert_eq!(
            beside,
            paths::normalize(&scratch.path().join("bin")),
            "{args:?}"
        );
        assert!(!roots.contains(&beside), "{args:?}");
        let beneath = bin_dir(&root.join("share"), &args);
        assert_eq!(beneath, paths::normalize(&root.join("bin")), "{args:?}");
        assert!(roots.contains(&beneath), "{args:?}");
    }
    assert_eq!(
        reason_of(&check("XDG_DATA_HOME", &root.display().to_string(), &roots)),
        Some(Reason::DeclaredRootItself)
    );
    assert_eq!(
        check(
            "XDG_DATA_HOME",
            &root.join("share").display().to_string(),
            &roots
        ),
        Verdict::Allowed
    );
}

#[test]
fn bash_truncates_the_history_file_when_a_fragment_assigns_histfilesize() {
    // The mechanism behind reserving `HISTFILESIZE`: bash truncates the
    // history file the moment the name is assigned, in a non-interactive
    // shell too, so a fragment that set it would destroy bytes the user
    // wrote (invariant 1). Run against a history file in a temporary
    // directory, never a real one.
    let Some(bash) = installed("bash") else {
        return;
    };
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let history = scratch.path().join("history");
    std::fs::write(&history, "echo one\necho two\n").expect("a history file");
    std::process::Command::new(bash)
        .args(["--norc", "--noprofile", "-c", "HISTFILESIZE=0"])
        .current_dir(scratch.path())
        .env_clear()
        .env("HOME", HOME)
        .env("PATH", "/nonexistent")
        .env("HISTFILE", &history)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("an installed shell runs");
    assert_eq!(std::fs::read(&history).expect("the history file"), b"");
    assert_eq!(
        reasons("export HISTFILESIZE=0\n", &rooted()),
        vec![(1, Reason::ReservedName)]
    );
}

/// A shell the guard is held to, and how to make it report every variable
/// it holds when it exits. The report runs from an exit trap, so it still
/// reports after a fragment that stops the shell with an error. zsh also
/// reports arrays, joined with `:`, because `NAME[1,-1]=value` on an unset
/// name makes one — and so every element is judged as a list entry.
struct Shell {
    program: &'static str,
    flags: &'static [&'static str],
    report: &'static str,
}

const SHELLS: &[Shell] = &[
    Shell {
        program: "bash",
        flags: &["--norc", "--noprofile"],
        report: "__bx_report() { local __bx_n; for __bx_n in $(compgen -v); do \
                     printf '%s=%s\\0' \"$__bx_n\" \"${!__bx_n}\"; done; }; trap __bx_report EXIT",
    },
    Shell {
        program: "zsh",
        flags: &["-f"],
        report: "__bx_report() { local __bx_n; for __bx_n in ${(k)parameters}; do \
                     [[ ${parameters[$__bx_n]} == (scalar|array)* ]] && \
                     printf '%s=%s\\0' \"$__bx_n\" \"${(j.:.)${(P)__bx_n}}\"; done; }; \
                     trap __bx_report EXIT",
    },
];

/// The variable that excuses a machine from supplying the programs these
/// checks are held against.
///
/// Differential agreement with real bash, zsh, bun and uv is this module's
/// strongest evidence, and a check that quietly asserts nothing is worse
/// than no check at all. Skipping therefore has to be asked for by name,
/// from outside the suite, and every other run fails instead.
const WITHOUT_SHELLS: &str = "BX_TEST_WITHOUT_SHELLS";

/// The variable every continuous-integration runner sets.
const ON_A_RUNNER: &str = "CI";

/// Announce a skip where a passing test's output is still read.
///
/// `cargo test` captures what a test prints and shows it only for a test
/// that *fails*, so an `eprintln!` from a skip — which passes — is
/// announced to nobody. That is the silent skip [`WITHOUT_SHELLS`] exists
/// to prevent, reintroduced by the notice meant to make it visible.
/// Writing to the process's own stderr goes around the capture, so an
/// opted-in skip is seen.
fn announce(message: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{message}");
}

/// Whether an excuse that was `asked` for is honoured on a machine that
/// `is_ci` says is a continuous-integration runner.
///
/// **A runner may not excuse itself**, and that is decided here rather
/// than in a workflow file. A CI step asserting the variable were unset
/// would bind this repository's own workflow and nothing else, and the
/// edit that set the variable could drop the step in the same breath.
/// Here, a runner that asks fails the suite it is running — whatever the
/// workflow says, and on any runner, not only this repository's.
///
/// This is not hypothetical: the uv check landed with no job installing
/// uv, and both test jobs failed. Had either carried [`WITHOUT_SHELLS`],
/// they would have passed with the differential sweeps never run.
fn excuse_honoured(asked: bool, is_ci: bool) -> bool {
    assert!(
        !(asked && is_ci),
        "{WITHOUT_SHELLS} is set and so is {ON_A_RUNNER}: a runner may not \
             excuse itself from the differential checks, which are this \
             module's strongest evidence. Install the missing program on the \
             runner instead."
    );
    asked
}

/// Whether this machine has been excused from supplying the programs.
fn shells_are_excused() -> bool {
    excuse_honoured(
        std::env::var_os(WITHOUT_SHELLS).is_some(),
        std::env::var_os(ON_A_RUNNER).is_some(),
    )
}

#[test]
fn a_runner_may_not_excuse_itself_from_the_differential_checks() {
    // Off a runner the excuse is honoured, and it is never invented.
    assert!(excuse_honoured(true, false));
    assert!(!excuse_honoured(false, false));
    assert!(!excuse_honoured(false, true));
}

#[test]
#[should_panic(expected = "a runner may not excuse itself")]
fn a_runner_that_asks_to_be_excused_fails_instead() {
    excuse_honoured(true, true);
}

/// The installed program `program` resolves to.
///
/// A program that is not installed fails the check it would have run,
/// unless [`WITHOUT_SHELLS`] excuses this machine — which, per
/// [`excuse_honoured`], no runner may be.
fn installed(program: &str) -> Option<PathBuf> {
    match crate::detect::locate_in_env(program) {
        crate::detect::Presence::Present { path } => Some(path),
        _ => {
            assert!(
                shells_are_excused(),
                "{program} is not installed, so every check held against it \
                     would assert nothing — install it, or set {WITHOUT_SHELLS} \
                     to skip those checks on purpose"
            );
            announce(&format!(
                "skipping the {program} checks: {WITHOUT_SHELLS} is set"
            ));
            None
        }
    }
}

/// Run `script` in `shell` with an empty environment and `home`, and
/// return what it printed. Nothing in this process's environment is
/// touched: the child's is built per command.
///
/// Some of the fragments these tests run are deliberately broken shell,
/// and a stray `>` in one is a redirection. So the child runs in a fresh
/// temporary directory, where a relative redirection lands, and with a
/// `PATH` that finds no program, so a word that becomes a command runs
/// nothing. An *absolute* redirection is kept inside a temporary directory
/// too, by [`Shells`] rewriting every fixed path a fragment names.
fn run_script(shell: &Path, flags: &[&str], home: &Path, script: &str) -> Vec<u8> {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    std::process::Command::new(shell)
        .args(flags)
        .arg("-c")
        .arg(script)
        .current_dir(scratch.path())
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/nonexistent")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .expect("an installed shell runs")
        .stdout
}

/// Every scalar variable `shell` holds after running `content` with `home`.
fn variables_after(
    shell: &Shell,
    path: &Path,
    home: &Path,
    content: &str,
) -> HashMap<String, String> {
    let script = format!("{}\n{content}", shell.report);
    run_script(path, shell.flags, home, &script)
        .split(|&byte| byte == 0)
        .filter_map(|entry| {
            let entry = String::from_utf8_lossy(entry);
            let (name, value) = entry.split_once('=')?;
            (!name.starts_with("__bx_")).then(|| (name.to_string(), value.to_string()))
        })
        .collect()
}

/// The installed shells, the variables each holds running nothing, and the
/// temporary directory their fragments are rewritten into.
///
/// The fragments below name [`HOME`] and [`ROOT`] literally, and some of
/// them are deliberately broken shell in which a stray `>` is a redirection
/// into the value. A test may write nowhere but a temporary directory, so
/// both names are rewritten to a directory under one before a shell — or
/// the guard the shell is compared against — sees the fragment. That is
/// why these checks no longer skip themselves when `ROOT` happens to exist
/// on the machine: the earlier form gated on that fixed absolute path, and
/// a scratch mount under `/var/mnt/scratch` is the very layout this change
/// is motivated by, so the strongest checks in the module switched
/// themselves off exactly where they mattered most.
struct Shells {
    dir: tempfile::TempDir,
    found: Vec<(&'static Shell, PathBuf, HashMap<String, String>)>,
}

impl Shells {
    /// Every shell in [`SHELLS`] — or none, when [`WITHOUT_SHELLS`]
    /// excuses the machine from having them.
    fn found() -> Self {
        let dir = tempfile::tempdir().expect("a sandbox directory");
        let home = dir.path().join("home");
        let root = dir.path().join("scratch/example");
        std::fs::create_dir_all(&home).expect("a sandbox home");
        std::fs::create_dir_all(&root).expect("a sandbox root");
        let found: Vec<_> = SHELLS
            .iter()
            .filter_map(|shell| {
                let path = installed(shell.program)?;
                let baseline = variables_after(shell, &path, &home, "");
                Some((shell, path, baseline))
            })
            .collect();
        assert!(
            !found.is_empty() || shells_are_excused(),
            "no shell ran, so every check held against one asserted nothing"
        );
        Self { dir, found }
    }

    /// The home the shells run with, standing in for [`HOME`].
    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    /// The scratch root the fragments are written against, standing in for
    /// [`ROOT`].
    fn root(&self) -> PathBuf {
        self.dir.path().join("scratch/example")
    }

    /// `content` with both fixed paths rewritten into the sandbox.
    fn rewrite(&self, content: &str) -> String {
        content
            .replace(ROOT, &self.root().to_string_lossy())
            .replace(HOME, &self.home().to_string_lossy())
    }

    /// [`rooted`] in the sandbox: the scratch root declared, the home not.
    fn rooted(&self) -> RootSet {
        RootSet::new(&self.home(), &[self.root()])
    }

    /// The sandbox's home declared as the one root.
    fn home_rooted(&self) -> RootSet {
        RootSet::new(&self.home(), &[PathBuf::from("~")])
    }
}

/// Whether a shell that ended holding `name=value` — and the variables
/// `after` — has been pointed somewhere the roots do not admit.
///
/// Decided independently of the guard's emit table and ownership rules, so
/// it cannot share a blind spot with them. Every entry shaped like a path —
/// containing `/`, beginning `~` or `=`, or `.` or `..` — makes the whole
/// value one the roots must admit, for any name; so does any value of a
/// name the round-5 review saw a tool read as a location. bx's state
/// directory is worked out here from `home` — the sandbox home the shell
/// actually ran with, which is not always the root set's, since some of
/// these fragments are judged against [`RootSet::strict`] — and the
/// shell's own `XDG_STATE_HOME`, and an `XDG_CONFIG_HOME` whose `/bx`
/// lands in it escapes. The names the shell manages are its own business.
/// The commands, search lists and socket written out below need no root: a
/// command escapes with a second word or a relative or owned path, a
/// command line with a relative or owned program or an argument naming an
/// owned path, options with a word naming one, and a list or socket with
/// any relative or owned entry.
fn escapes(
    name: &str,
    value: &str,
    roots: &RootSet,
    after: &HashMap<String, String>,
    home: &Path,
) -> bool {
    if SHELL_NAMES.contains(&name) {
        return false;
    }
    // bx's state directory, worked out here rather than asked of the
    // guard: under the home the shell ran with, or wherever the shell's own
    // absolute `XDG_STATE_HOME` moved it.
    // bx's config repo counts as well: a tool pointed into it writes into a
    // committed tree, or runs what was committed there.
    let mut owned = vec![home.join(".local/state/bx"), home.join(".config/bx")];
    if let Some(state) = after
        .get("XDG_STATE_HOME")
        .filter(|state| Path::new(state).is_absolute())
    {
        owned.push(Path::new(state).join("bx"));
    }
    // A leading `=` is zsh's `=cmd`, which expands to a program's path.
    let pathish = |entry: &str| {
        entry.contains('/') || entry.starts_with(['~', '=']) || entry == "." || entry == ".."
    };
    let unanchored = |entry: &str| {
        let path = paths::normalize(Path::new(entry));
        !path.is_absolute() || owned.iter().any(|dir| path.starts_with(dir))
    };
    // A location whose tool clears it clears whatever it contains.
    let holds_bx = |entry: &str| {
        let path = paths::normalize(Path::new(entry));
        path.is_absolute() && owned.iter().any(|dir| dir.starts_with(&path))
    };
    // An argument escapes when a path in it — from its first `/`, or
    // from a leading `~`, in a whole word or in a piece of one — lands
    // inside bx's directories, or when it names `HOME`, an `XDG_` name or
    // one the round-5 review saw a tool read as a location, which a shell
    // assigns with an `=` or without one (`for HOME in`, `read HOME`).
    // Quotes join words, so they are dropped first.
    let argument_escapes = |text: &str| {
        let text: String = text.chars().filter(|c| !matches!(c, '\'' | '"')).collect();
        let assigns_location = text.split(|c: char| " \t;|&<>()=".contains(c)).any(|word| {
            word == "HOME"
                || word.starts_with("XDG_")
                || R5_READ_AS_LOCATIONS.iter().any(|(known, _)| *known == word)
        });
        // A path's own directories may hold `=` or `:`, so each word a
        // shell splits is read whole as well as in pieces.
        let words = text.split(|c: char| " \t;|&<>()".contains(c));
        assigns_location
            || text
                .split(|c: char| " \t;|&<>()=:".contains(c))
                .chain(words)
                .any(|word| {
                    let path = match word.strip_prefix('~') {
                        Some(rest) => format!("{}{rest}", home.display()),
                        None => match word.find('/') {
                            Some(at) => word[at..].to_string(),
                            None => return false,
                        },
                    };
                    let path = paths::normalize(Path::new(&path));
                    owned.iter().any(|dir| path.starts_with(dir))
                })
    };
    let entries: Vec<&str> = value.split(':').collect();
    if TEST_SEARCHED_OR_REACHED.contains(&name) {
        entries.iter().any(|entry| unanchored(entry))
    } else if TEST_RUN_AS_COMMAND_LINES.contains(&name) {
        // A tool hands the value to a shell, so its first word is a
        // program and the rest are that program's arguments.
        let (program, rest) = value.split_once([' ', '\t']).unwrap_or((value, ""));
        (pathish(program) && unanchored(program)) || argument_escapes(rest)
    } else if TEST_READ_AS_OPTIONS.contains(&name) {
        argument_escapes(value)
    } else if TEST_RUN_AS_COMMANDS.contains(&name) {
        // A tool runs the value through a shell, so a second word is an
        // argument no check looked at.
        value.split([' ', '\t']).count() > 1
            || (pathish(value) && unanchored(value))
            || entries
                .iter()
                .any(|entry| pathish(entry) && unanchored(entry))
    } else {
        let read_as_location = R5_READ_AS_LOCATIONS.iter().any(|(known, _)| *known == name);
        let repo_lands_in_state = name == "XDG_CONFIG_HOME" && unanchored(&format!("{value}/bx"));
        // A tool that reads one path reads the whole value, `:` and all.
        let whole_escapes = !TEST_COLON_LISTS.contains(&name)
            && (read_as_location || pathish(value))
            && (unanchored(value) || holds_bx(value) || !roots.contains(Path::new(value)));
        repo_lands_in_state
            || whole_escapes
            || ((read_as_location || entries.iter().any(|entry| pathish(entry)))
                && entries.iter().any(|entry| {
                    unanchored(entry) || holds_bx(entry) || !roots.contains(Path::new(entry))
                }))
    }
}

#[test]
fn the_oracle_reads_a_whole_argument_the_guards_split_would_miss() {
    // With `:` or `=` in the home's own name, a piece split at them is
    // never inside bx's directories; only the whole word is. The oracle
    // and the guard must both see it, and agree on what stays outside.
    for home in ["/tmp/a:b", "/tmp/a=b"] {
        let roots = RootSet::new(Path::new(home), &[PathBuf::from("~")]);
        let after = HashMap::new();
        for (name, value, owned) in [
            (
                "EDITOR",
                format!("nvim {home}/.local/state/bx/ledger"),
                true,
            ),
            (
                "PAGER",
                format!("less --log-file={home}/.config/bx/x"),
                true,
            ),
            ("LESS", format!("-R -o{home}/.local/state/bx/log"), true),
            ("EDITOR", format!("nvim {home}/notes/todo.md"), false),
            ("LESS", format!("-R -o{home}/log"), false),
        ] {
            assert_eq!(
                escapes(name, &value, &roots, &after, Path::new(home)),
                owned,
                "{name}={value}"
            );
            let quoted = format!("\"{value}\"");
            assert_eq!(
                check(name, &quoted, &roots) != Verdict::Allowed,
                owned,
                "{name}={quoted}"
            );
        }
    }
}

/// Names a tool runs as a command, written out here independently of the
/// guard's table: a value escapes when it has a second word, or when a
/// path in it is relative or inside bx's state directory.
const TEST_RUN_AS_COMMANDS: &[&str] = &["BROWSER", "RUSTC_WRAPPER", "TERMINAL"];

/// Names a tool hands to a shell as a whole command line, written out here
/// independently of the guard's table: a value escapes when its first word
/// is a relative or owned path, or when an argument names a path inside
/// bx's directories.
const TEST_RUN_AS_COMMAND_LINES: &[&str] = &["EDITOR", "MANPAGER", "PAGER", "VISUAL"];

/// Names a tool reads as its own options, written out here independently
/// of the guard's table: a value escapes when a word names a path inside
/// bx's directories.
const TEST_READ_AS_OPTIONS: &[&str] = &["LESS"];

/// Lists a shell or a tool searches, and a socket it connects to, written
/// out independently of the guard's table: every entry must be absolute
/// and outside bx's state directory, and no root is needed.
const TEST_SEARCHED_OR_REACHED: &[&str] = &["INFOPATH", "PATH", "SSH_AUTH_SOCK"];

/// Lists of locations their tool splits at `:`, written out independently
/// of the guard's table. Every other value is also read as one whole path.
const TEST_COLON_LISTS: &[&str] = &["GOPATH"];

impl Shells {
    /// Run `content` in every installed shell and hold the guard to what each
    /// shell did. The guard must never approve a fragment after which any
    /// variable [`escapes`] — holds a path outside `roots` or inside bx's own
    /// directory, for any name; and where the guard read every line, what it
    /// learned must be exactly what the shell set. Returns, per shell, whether
    /// the shell relocated anything outside the roots.
    ///
    /// `content` is rewritten into the sandbox first, and so must `roots` have
    /// been — [`Shells::rooted`] and [`Shells::home_rooted`] are the two sets
    /// these checks pass.
    fn agree(&self, content: &str, roots: &RootSet) -> Vec<bool> {
        let content = &self.rewrite(content);
        let home = self.home();
        let (found, scope) = pass(content, roots, false);
        let mut escaped_in = Vec::new();
        for (shell, path, baseline) in &self.found {
            let after = variables_after(shell, path, &home, content);
            let changed: Vec<(&String, &String)> = after
                .iter()
                .filter(|(name, value)| baseline.get(*name) != Some(*value))
                .collect();
            let escaped: Vec<_> = changed
                .iter()
                .filter(|(name, value)| escapes(name, value, roots, &after, &home))
                .collect();
            assert!(
                escaped.is_empty() || !found.is_empty(),
                "{}: the guard approved {content:?}, after which {escaped:?}",
                shell.program
            );
            escaped_in.push(!escaped.is_empty());
            if scope.lost {
                continue;
            }
            for (name, value) in &changed {
                if is_reserved(name) {
                    continue;
                }
                match scope.learned.get(*name) {
                    Some(Ok(learned)) => assert_eq!(
                        learned, *value,
                        "{}: {content:?} gives {name} a different value",
                        shell.program
                    ),
                    Some(Err(_)) => {}
                    None => panic!(
                        "{}: {content:?} sets {name}={value:?}, which the guard did not learn",
                        shell.program
                    ),
                }
            }
            for (name, learned) in &scope.learned {
                if let Ok(learned) = learned {
                    assert_eq!(
                        after.get(name),
                        Some(learned),
                        "{}: {content:?} does not give {name} what the guard learned",
                        shell.program
                    );
                }
            }
        }
        escaped_in
    }
}

/// Fragments the grammar reads line for line, some approved and some
/// judged a violation, whose learned values the shells must reproduce.
const READABLE_FRAGMENTS: &[&str] = &[
    OPERATOR_FRAGMENT,
    "X=/var/mnt/scratch/example\nexport CARGO_HOME=${X}:h\nexport RUSTUP_HOME=\"${X}[1]\"\n",
    "export MAKEFLAGS=\"-j8 V=1\"\nexport GRADLE_USER_HOME=\"/var/mnt/scratch/example/a b=c/gradle\"\n",
    "X=/etc\nY='$X'\nexport CARGO_HOME=/var/mnt/scratch/example/$Y\n",
    "export CARGO_HOME=~/x\nexport RUSTUP_HOME=~\nexport GOPATH=\"~/x\"\nexport GOCACHE='~'\n",
    "export KUBECONFIG=/var/mnt/scratch/example/k:/etc/evil/config\n",
    "export EDITOR=nvim # a comment\n  \texport  PAGER=less\t# another\n\n# only a comment\n",
    "X=a,b@c%d+e-f.g:h\nY=\nZ=''\nW=\"\"\nexport V=$X$X\n",
    "X=/var/mnt/scratch/example\nX=$X/b\nexport CARGO_HOME=$X/cargo\n",
    "export PATH=\"$HOME/.local/bin:/usr/bin\"\n",
    "export PATH=/a:$PATH\nexport PATH=/b:$PATH\n",
    // zsh's own forms, the removal last: bash cannot read it, and stops.
    "export PATH=/a:$PATH\n\
         [[ -d /var/mnt/scratch/example ]] && export PATH=/var/mnt/scratch/example/bin:$PATH\n\
         [[ -d /var/mnt/scratch/example/none ]] && export PATH=/b:$PATH\n\
         path=(${path:#/a})\n",
    // bash's removal, which both shells read alike.
    "export PATH=/a:/b:/a:/a:$PATH\n\
         PATH=:${PATH//:/::}:; PATH=${PATH//\":/a:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
         export PATH=/a:$PATH\n",
    "export XDG_STATE_HOME=~/.local/state/bx\n",
    "export npm_config_cache=/etc/evil\nexport TMPDIR=/tmp\n",
    "X=\"it's\"\nY='say \"hi\"'\nZ='a\\b'\nW='$(echo pwned)'\nV=\"{a,b} *\"\n",
    "X=${HOME}x\nY=\"$HOME\"\nZ=$HOME$HOME\nexport export=1\nexportX=2\n",
];

#[test]
fn the_shells_read_every_readable_fragment_as_the_guard_does() {
    let shells = Shells::found();
    for content in READABLE_FRAGMENTS {
        for roots in [shells.rooted(), shells.home_rooted()] {
            assert!(
                !pass(&shells.rewrite(content), &roots, false).1.lost,
                "{content:?}"
            );
            shells.agree(content, &roots);
        }
    }
}

#[test]
fn the_path_lines_bx_writes_are_approved_and_give_zsh_the_declared_order() {
    use crate::config::env::{Fragment, Syntax, Var};
    use crate::config::path::{PathEntry, Position, shell_spelling};
    let shells = Shells::found();
    let Some((shell, program, _)) = shells
        .found
        .iter()
        .find(|(shell, _, _)| shell.program == "zsh")
    else {
        return;
    };
    let home = shells.home();
    let root = shells.root();
    for dir in ["bin", "opt/bin", ".cargo/bin"] {
        std::fs::create_dir_all(home.join(dir)).expect("a sandbox directory");
    }
    let entry = |dir: &str, position, if_exists| PathEntry {
        dir: dir.to_string(),
        shell: shell_spelling(dir).expect("a PATH entry"),
        position,
        if_exists,
        enabled: true,
        shells: crate::shell::Shells::EVERY,
        origin: crate::config::Origin::unknown(Path::new("bx.toml")),
    };
    let cargo = root.join("cargo");
    let fragment = Fragment {
        syntax: Syntax::Zsh,
        vars: vec![Var::always("CARGO_HOME", cargo.display().to_string())],
        path: vec![
            entry("/opt/tool/bin", Position::Append, false),
            entry("~/bin", Position::Prepend, false),
            entry("~/.local/bin", Position::Prepend, true),
            entry("$HOME/opt/bin", Position::Prepend, true),
            entry("${CARGO_HOME}/bin", Position::Prepend, false),
            entry("~/.cargo/bin", Position::Remove, false),
        ],
    }
    .render(&|_| unreachable!("nothing is gated on a tool"));
    assert_eq!(scan_with(&fragment, &shells.rooted()), vec![]);

    // An inherited PATH holding the stale install and a declared entry
    // out of place, then the fragment read once, and read again as a
    // nested shell reads it.
    let h = home.display();
    let inherited = format!("export PATH={h}/.cargo/bin:/usr/bin:{h}/bin\n");
    let once = format!("{inherited}{fragment}");
    let twice = format!("{once}{fragment}");
    let expected = format!(
        "{h}/bin:{h}/opt/bin:{}/bin:/usr/bin:/opt/tool/bin",
        cargo.display()
    );
    for content in [&once, &twice] {
        let after = variables_after(shell, program, &home, content);
        assert_eq!(after.get("PATH"), Some(&expected), "{content}");
    }
}

#[test]
fn bash_s_path_lines_are_approved_and_give_bash_the_declared_order_once_even_after_zsh() {
    use crate::config::env::{Fragment, Syntax, Var};
    use crate::config::path::{self, PathEntry, Position, shell_spelling};
    let shells = Shells::found();
    let find = |name: &str| {
        shells
            .found
            .iter()
            .find(|(shell, _, _)| shell.program == name)
    };
    let Some((bash, bash_program, _)) = find("bash") else {
        return;
    };
    let home = shells.home();
    let root = shells.root();
    for dir in ["bin", "opt/bin", ".cargo/bin"] {
        std::fs::create_dir_all(home.join(dir)).expect("a sandbox directory");
    }
    let entry = |dir: &str, position, if_exists| PathEntry {
        dir: dir.to_string(),
        shell: shell_spelling(dir).expect("a PATH entry"),
        position,
        if_exists,
        enabled: true,
        shells: crate::shell::Shells::EVERY,
        origin: crate::config::Origin::unknown(Path::new("bx.toml")),
    };
    let cargo = root.join("cargo");
    let entries = vec![
        entry("/opt/tool/bin", Position::Append, false),
        entry("~/bin", Position::Prepend, false),
        entry("~/.local/bin", Position::Prepend, true),
        entry("$HOME/opt/bin", Position::Prepend, true),
        entry("${CARGO_HOME}/bin", Position::Prepend, false),
        entry("~/.cargo/bin", Position::Remove, false),
    ];
    let fragment = format!(
        "export CARGO_HOME={}\n{}",
        cargo.display(),
        path::render(&entries, crate::shell::Shell::Bash)
    );
    assert_eq!(scan_with(&fragment, &shells.rooted()), vec![]);

    // An inherited PATH holding the stale install twice, a declared entry
    // out of place and repeated side by side, and an empty entry; then
    // the lines read once, and again as a nested bash reads them. Every
    // copy of an entry taken out goes, and nothing else moves.
    let h = home.display();
    let inherited =
        format!("export PATH={h}/.cargo/bin:{h}/bin:{h}/bin:/usr/bin::{h}/.cargo/bin\n");
    let once = format!("{inherited}{fragment}");
    let twice = format!("{once}{fragment}");
    let expected = format!(
        "{h}/bin:{h}/opt/bin:{}/bin:/usr/bin::/opt/tool/bin",
        cargo.display()
    );
    for content in [&once, &twice] {
        let after = variables_after(bash, bash_program, &home, content);
        assert_eq!(after.get("PATH"), Some(&expected), "{content}");
    }

    // A bash started from a zsh that read zsh's lines for the same
    // entries finds every entry already where it goes, and repeats none.
    let Some((zsh, zsh_program, _)) = find("zsh") else {
        return;
    };
    let zsh_fragment = Fragment {
        syntax: Syntax::Zsh,
        vars: vec![Var::always("CARGO_HOME", cargo.display().to_string())],
        path: entries,
    }
    .render(&|_| unreachable!("nothing is gated on a tool"));
    let inherited = format!("export PATH={h}/.cargo/bin:/usr/bin:{h}/bin\n");
    let from_zsh = variables_after(
        zsh,
        zsh_program,
        &home,
        &format!("{inherited}{zsh_fragment}"),
    )
    .remove("PATH")
    .expect("zsh exports PATH");
    let after = variables_after(
        bash,
        bash_program,
        &home,
        &format!("export PATH={from_zsh}\n{fragment}"),
    );
    assert_eq!(after.get("PATH"), Some(&from_zsh), "{fragment}");
}

#[test]
fn a_path_block_ending_on_a_missing_gated_directory_is_approved_and_survives_err_exit() {
    use crate::config::env::{Fragment, Syntax};
    use crate::config::path::{PathEntry, Position, shell_spelling};
    let shells = Shells::found();
    let Some((shell, program, _)) = shells
        .found
        .iter()
        .find(|(shell, _, _)| shell.program == "zsh")
    else {
        return;
    };
    let home = shells.home();
    let entry = |dir: &str, position| PathEntry {
        dir: dir.to_string(),
        shell: shell_spelling(dir).expect("a PATH entry"),
        position,
        if_exists: true,
        enabled: true,
        shells: crate::shell::Shells::EVERY,
        origin: crate::config::Origin::unknown(Path::new("bx.toml")),
    };
    // The first-declared prepend is written last, and its directory does
    // not exist; so does the lone append's.
    for path in [
        vec![entry("~/missing/bin", Position::Prepend)],
        vec![entry("~/missing/bin", Position::Append)],
    ] {
        let fragment = Fragment {
            syntax: Syntax::Zsh,
            vars: vec![],
            path,
        }
        .render(&|_| unreachable!("nothing is gated on a tool"));
        assert_eq!(scan_with(&fragment, &shells.rooted()), vec![]);
        let file = home.join("fragment.zsh");
        std::fs::write(&file, &fragment).expect("the fragment is written");
        let mut flags = shell.flags.to_vec();
        flags.push("-e");
        let script = format!("source {}\nprint -rn reached\n", file.display());
        let out = run_script(program, &flags, &home, &script);
        assert_eq!(out, b"reached", "{fragment}");
    }
}

#[test]
fn nothing_a_shell_runs_names_a_path_outside_the_sandbox() {
    // What replaced the old skip. The fragments these checks run are
    // deliberately broken shell, and a stray `>` in one is a redirection
    // into the path the fragment names, while a test may write nowhere but
    // a temporary directory. The old form bought that by refusing to run
    // at all when `ROOT` existed on the machine — which silently switched
    // the module's strongest checks off on exactly the machines this
    // change is written for, and said so only through an `eprintln!` that
    // `cargo test` hides. The rewrite buys it instead, and this holds the
    // rewrite to it.
    let shells = Shells::found();
    assert!(shells.root().starts_with(shells.dir.path()));
    assert!(shells.home().starts_with(shells.dir.path()));
    let forms = ASSIGNING_FORMS.iter().map(|form| {
        form.replace("{N}", "CARGO_HOME")
            .replace("{V}", "/var/mnt/scratch/example/x")
    });
    for content in READABLE_FRAGMENTS
        .iter()
        .map(|content| (*content).to_string())
        .chain(forms)
    {
        let rewritten = shells.rewrite(&content);
        assert!(!rewritten.contains(ROOT), "{content:?}");
        assert!(!rewritten.contains(HOME), "{content:?}");
    }
    // And the rewrite is a rename, not a redaction: the operator's own
    // fragment names the root on every line, and is approved after it.
    let rewritten = shells.rewrite(OPERATOR_FRAGMENT);
    assert!(rewritten.contains(&*shells.root().to_string_lossy()));
    assert_eq!(scan_with(&rewritten, &shells.rooted()), vec![]);
}

#[test]
fn every_review_falsifier_relocates_in_a_real_shell_and_is_refused() {
    let shells = Shells::found();
    let rooted = shells.rooted();
    let home_rooted = shells.home_rooted();
    for form in ASSIGNING_FORMS {
        let content = form
            .replace("{N}", "CARGO_HOME")
            .replace("{V}", "/etc/evil");
        assert_ne!(
            scan_with(&shells.rewrite(&content), &rooted),
            vec![],
            "{content:?}"
        );
        shells.agree(&content, &rooted);
    }
    // The review's own list, each run for real: every one but the alias
    // (neither shell expands an alias defined in the same `-c` string)
    // relocates outside the roots in at least one installed shell.
    let falsifiers = [
        ("\\export CARGO_HOME=/etc/evil", rooted.clone()),
        ("\"export\" CARGO_HOME=/etc/evil", rooted.clone()),
        ("e''xport CARGO_HOME=/etc/evil", rooted.clone()),
        (": '\n'; export CARGO_HOME=/etc/evil #'", rooted.clone()),
        ("ex\\\nport CARGO_HOME=/etc/evil", rooted.clone()),
        (
            "export CARGO_HOME=/var/mnt/scratch/example/cargo\nCARGO_\\\nHOME=/etc/evil",
            rooted.clone(),
        ),
        ("for CARGO_HOME in /etc/evil; do :; done", rooted.clone()),
        ("read -r CARGO_HOME <<< /etc/evil", rooted.clone()),
        ("printf -v CARGO_HOME /etc/evil", rooted.clone()),
        ("CARGO_HOME[1,-1]=/etc/evil", rooted.clone()),
        (": ${CARGO_HOME::=/etc/evil}", rooted.clone()),
        ("set -a\n: ${CARGO_HOME:=/etc/evil}", rooted.clone()),
        (
            "R=/var/mnt/scratch/example\nunset R\nexport CARGO_HOME=$R/etc/evil",
            rooted.clone(),
        ),
        (
            "CARGO_HOME=/var/mnt/scratch/example/$@/$@/$@/$@/../../../../etc/evil",
            rooted.clone(),
        ),
        ("HOME=/etc/evil\nCARGO_HOME=~/cargo", home_rooted.clone()),
        ("eval \"export CARGO_HOME=/etc/evil\"", rooted.clone()),
        (
            "source /dev/stdin <<< 'export CARGO_HOME=/etc/evil'",
            rooted.clone(),
        ),
        ("UV_PROJECT==ls", rooted.clone()),
        (
            "KUBECONFIG=/var/mnt/scratch/example/k:/etc/evil/config",
            rooted.clone(),
        ),
        (
            "GOPATH=/var/mnt/scratch/example/go:/etc/evil",
            rooted.clone(),
        ),
        ("npm_config_cache=/etc/evil", rooted.clone()),
        ("ZDOTDIR=/etc/evil", rooted.clone()),
        // Round 4: names no list held, a state directory the fragment
        // moved, a history file, and a search list with a relative entry.
        ("export RIPGREP_CONFIG_PATH=/etc/evil", rooted.clone()),
        ("export GIT_CONFIG_SYSTEM=/etc/evil", rooted.clone()),
        ("export CARGO_TARGET_DIR=/etc/evil", rooted.clone()),
        ("export XDG_CONFIG_DIRS=/etc/evil", rooted.clone()),
        ("SOMETHING=build/cache", rooted.clone()),
        (
            "export XDG_STATE_HOME=/var/mnt/scratch/example/state\n\
                 export CARGO_HOME=/var/mnt/scratch/example/state/bx",
            rooted.clone(),
        ),
        ("export HISTFILE=/etc/evil", rooted.clone()),
        ("export PATH=.:/usr/bin", rooted.clone()),
        ("export EDITOR=./nvim", rooted.clone()),
        // Round 5: a bare word a tool reads as a path, a program given
        // arguments, a state directory a later line moves, a URL-shaped
        // relative path, bx's default state directory with no home, and a
        // config repo landing on the state directory.
        (
            "export EDITOR=\"/usr/bin/touch /var/home/example/.local/state/bx/written-by-editor\"",
            rooted.clone(),
        ),
        (
            "export EDITOR=\"/usr/bin/env XDG_CONFIG_HOME=/etc/evil nvim\"",
            RootSet::strict(),
        ),
        // Review of #113: a shell assigns a name without an `=` too.
        (
            "export EDITOR=\"sh -c 'for XDG_CONFIG_HOME in /etc/evil; do export XDG_CONFIG_HOME; nvim; done'\"",
            rooted.clone(),
        ),
        (
            "export EDITOR=\"sh -c 'read HOME </etc/h; export HOME; nvim'\"",
            rooted.clone(),
        ),
        // `PAGER` is a command line since #112, so the program given an
        // argument is `RUSTC_WRAPPER`, which cargo runs as one word.
        (
            "export RUSTC_WRAPPER=\"/usr/bin/less --lesskey-file=/etc/evil/lesskey\"",
            rooted.clone(),
        ),
        (
            "export CARGO_HOME=/var/mnt/scratch/example/state/bx\n\
                 export XDG_STATE_HOME=/var/mnt/scratch/example/state",
            rooted.clone(),
        ),
        ("export EDITOR=x://ed", rooted.clone()),
        ("export RIPGREP_CONFIG_PATH=cfg://rc", rooted.clone()),
        (
            "export GIT_CONFIG_SYSTEM=https://x:/etc/evil",
            rooted.clone(),
        ),
        (
            "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
            RootSet::strict(),
        ),
        (
            "export VISUAL=/var/home/example/.local/state/bx/nvim",
            RootSet::strict(),
        ),
        (
            "export SSH_AUTH_SOCK=/var/home/example/.local/state/bx/agent.sock",
            RootSet::strict(),
        ),
        ("export XDG_CONFIG_HOME=~/.local/state", home_rooted.clone()),
        // r3 round 2: a location that contains bx's state directory.
        ("export UV_CACHE_DIR=~/.local/state", home_rooted.clone()),
        // Round 6: a tool pointed into bx's config repo.
        ("export CARGO_HOME=~/.config/bx/cargo", home_rooted.clone()),
        // Round 6: a location whose entries are inside the root and whose
        // whole value, which cargo reads, is not.
        (
            "export CARGO_HOME=/var/mnt/scratch/example/x:/../../../var/mnt/scratch/example/y",
            rooted.clone(),
        ),
    ];
    let bare_words: Vec<String> = R5_READ_AS_LOCATIONS
        .iter()
        .map(|(name, value)| format!("export {name}={value}"))
        .collect();
    let falsifiers: Vec<(&str, RootSet)> = falsifiers
        .iter()
        .map(|(content, roots)| (*content, roots.clone()))
        .chain(
            bare_words
                .iter()
                .map(|content| (content.as_str(), rooted.clone())),
        )
        .collect();
    for (content, roots) in &falsifiers {
        let escaped = shells.agree(content, roots);
        assert_ne!(
            scan_with(&shells.rewrite(content), roots),
            vec![],
            "{content:?}"
        );
        // Only a machine `WITHOUT_SHELLS` excuses runs on fewer than all
        // of them, and some of these relocate in one shell alone.
        assert!(
            escaped.contains(&true) || shells.found.len() < SHELLS.len(),
            "{content:?} relocated nothing in any shell"
        );
    }
}

/// Every variant of `base` with one of the characters or sequences a shell
/// treats specially inserted at each of a few positions on its last line.
fn variants(base: &str) -> Vec<String> {
    const INSERTS: &[&str] = &[
        "\\",
        "'",
        "\"",
        "`",
        "$",
        "$@",
        "$1",
        "${",
        "}",
        "(",
        ")",
        "{",
        "[1]",
        ":h",
        "<",
        ">",
        "|",
        "&",
        ";",
        "*",
        "?",
        "!",
        "#",
        " #",
        "~",
        ":~/",
        "=",
        "==",
        ":=",
        "^",
        " ",
        "\t",
        "\n",
        "\\\n",
        "\r",
        "..",
        "/../../../..",
        "$(printf /etc)",
    ];
    let last = base.rfind('\n').map_or(0, |at| at + 1);
    let equals = last + base[last..].find('=').expect("an assignment");
    let mut positions = vec![
        last,
        equals,
        equals + 1,
        equals + 2,
        base.len() - 3,
        base.len(),
    ];
    if base[last..].starts_with("export ") {
        positions.extend([last + 6, last + 7]);
    }
    let mut out = Vec::new();
    for at in positions {
        for insert in INSERTS {
            out.push(format!("{}{insert}{}", &base[..at], &base[at..]));
        }
    }
    out
}

#[test]
fn no_single_special_character_makes_the_guard_approve_what_a_shell_reads_otherwise() {
    let shells = Shells::found();
    let rooted = shells.rooted();
    for base in [
        "export CARGO_HOME=/var/mnt/scratch/example/cargo",
        "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME=\"$SCRATCH_HOME/cargo\"",
        "SCRATCH_HOME=/var/mnt/scratch/example\nGOPATH=${SCRATCH_HOME}/go:$SCRATCH_HOME/b",
    ] {
        assert_eq!(
            scan_with(&shells.rewrite(base), &rooted),
            vec![],
            "{base:?}"
        );
        for content in variants(base) {
            shells.agree(&content, &rooted);
        }
    }
}

#[test]
fn the_shells_define_no_name_a_fragment_may_assign_except_path() {
    let home = tempfile::tempdir().expect("a sandbox home");
    let mut ran = 0;
    for (program, flags, list) in [
        ("bash", &["--norc", "--noprofile"][..], "compgen -v"),
        (
            "zsh",
            &["-f"][..],
            "for __bx_m in $module_path[1]/zsh/**/*.so(N); do \
                 __bx_n=${__bx_m#$module_path[1]/}; zmodload ${__bx_n%.so} >/dev/null 2>&1; \
                 done; print -l ${(k)parameters}",
        ),
    ] {
        let Some(path) = installed(program) else {
            continue;
        };
        ran += 1;
        let listed = run_script(&path, flags, home.path(), list);
        let unreserved: Vec<String> = String::from_utf8_lossy(&listed)
            .lines()
            .filter(|name| is_variable_name(name) && !name.starts_with("__bx_"))
            .filter(|name| *name != "PATH" && !SHELL_NAMES.contains(name))
            .map(str::to_string)
            .collect();
        assert_eq!(unreserved, Vec::<String>::new(), "{program}");
    }
    assert!(
        ran > 0 || shells_are_excused(),
        "no shell ran, so this check asserted nothing"
    );
}
