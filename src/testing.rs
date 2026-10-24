//! Test support: a throwaway home directory, and a guard that aborts otherwise.
//!
//! `CLAUDE.md` requires that anything touching a home directory run against a
//! tempdir home, behind a guard that **aborts** — panics, never skips — if that
//! home is not a tempdir. This module is that guard.
//!
//! # It hands the home out; it does not set `$HOME`
//!
//! An earlier shape of this module repointed the process's `$HOME` at the
//! tempdir, under a crate-wide mutex. That was unsound. `std::env::set_var` and
//! `remove_var` are `unsafe` in edition 2024 because their precondition is
//! **process-wide** — no other thread may be reading or writing the environment,
//! including through `getenv` inside libc and inside `std` itself. A mutex this
//! module owns cannot establish that: `std::env::temp_dir()` reads `TMPDIR` on
//! every `TempDir::new()`, and `crate::detect::locate_in_env` reads `PATH`, and
//! `cargo test` runs all of it concurrently in one process. glibc's `unsetenv`
//! shifts `environ` in place, so a concurrent `getenv` can read a stale pointer.
//! The symptom would have been a flaky failure in a test that has nothing to do
//! with home directories.
//!
//! So the mutation is gone rather than serialised, and the crate now contains no
//! `unsafe` at all. Every library function that needs a home takes it as an
//! argument — [`crate::paths::home_in`], [`crate::paths::xdg_base`] and
//! [`crate::paths::config_root_in`] are the parameterised forms, and
//! [`crate::paths::home`] is the one-line wrapper that reads the real
//! environment and is tested by agreeing with it.
//!
//! # The rule for every test
//!
//! * A test that reads or writes anything under a home directory opens with
//!   `let home = bx::testing::guarded_home();` and passes `home.path()` down.
//! * A test that does not touch a home directory uses design-by-parameter, the
//!   way [`crate::detect`] and [`crate::paths`] already do.
//! * **No test sets `HOME`, or any other variable, in this process.** To give a
//!   *child* process a home, pass it per-command — `Command::env("HOME", …)` —
//!   which mutates nothing here.
//!
//! That last rule is not a convention: `Cargo.toml` sets
//! `[lints.rust] unsafe_code = "forbid"`, which the compiler applies to the
//! library, the binary, `build.rs` and every integration test in `tests/`, and
//! which no module can re-allow. An earlier shape of this rule was a test that
//! grepped `src/` for the keyword; it covered neither `tests/` — where someone
//! reaching for `set_var` would actually write it — nor `build.rs`, it exempted
//! a file it could not read, and it could be defeated by a line break.
//!
//! A guard mutates nothing global, so taking two of them, or nesting them, is
//! fine and a shared fixture helper may take one of its own.
//!
//! The module is compiled unconditionally rather than under `#[cfg(test)]` so an
//! integration test in `tests/` can reach it. It is `#[doc(hidden)]`: it is
//! support, not surface.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// Canonicalise if possible, and fall back to the path as given.
///
/// `/tmp` is frequently a symlink and `env::temp_dir()` honours `TMPDIR`, so the
/// containment checks below must compare resolved paths. A path that does not
/// exist cannot be resolved, and comparing it literally is the safe reading.
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Abort unless `candidate` is a genuine throwaway home.
///
/// Panics — never skips — when `candidate` is not under the system temp
/// directory, or when `candidate` and the real `$HOME` contain each other. The
/// second case is real: a developer whose `TMPDIR` points inside their own home
/// would otherwise get a "tempdir" home that guards nothing.
fn check_is_a_throwaway_home(candidate: &Path, real_home: Option<&Path>) {
    let system_temp = canonical(&std::env::temp_dir());
    let candidate = canonical(candidate);

    assert!(
        candidate.starts_with(&system_temp),
        "refusing to hand out {} as a home: it is not under the system temp directory {}",
        candidate.display(),
        system_temp.display(),
    );

    if let Some(real_home) = real_home {
        let real_home = canonical(real_home);
        assert!(
            !candidate.starts_with(&real_home),
            "refusing to hand out {} as a home: it is inside the real home {} \
             (TMPDIR under $HOME makes the guard guard nothing)",
            candidate.display(),
            real_home.display(),
        );
        assert!(
            !real_home.starts_with(&candidate),
            "refusing to hand out {} as a home: the real home {} is inside it",
            candidate.display(),
            real_home.display(),
        );
    }
}

/// A fresh tempdir to use as a home directory, for the guard's lifetime.
///
/// Reads `$HOME` — a read, never a write — only to check that the tempdir it
/// hands out is not entangled with the developer's real home.
///
/// # Panics
///
/// Aborts, rather than skipping, if the tempdir cannot be created, if it is not
/// under the system temp directory, or if it and the real `$HOME` contain each
/// other. A silent pass is the one outcome a safety guard may not produce.
///
/// The home handed out is the tempdir's canonical path. macOS puts the
/// system temp directory under `/var`, a symlink to `/private/var`, and a
/// path the code under test resolves must compare equal to the home it was
/// given.
#[must_use]
pub fn guarded_home() -> GuardedHome {
    let real_home = std::env::var_os("HOME").map(PathBuf::from);
    let dir = TempDir::new().expect("a tempdir for the guarded home");
    check_is_a_throwaway_home(dir.path(), real_home.as_deref());
    let path = dir
        .path()
        .canonicalize()
        .expect("the guarded home's canonical path");

    GuardedHome { _dir: dir, path }
}

/// A throwaway home directory, removed when the guard drops.
///
/// Created by [`guarded_home`]. Holds no lock and mutates nothing global, so it
/// nests freely.
pub struct GuardedHome {
    /// Held for its `Drop`, which removes the directory.
    _dir: TempDir,
    /// The tempdir's canonical path.
    path: PathBuf,
}

impl GuardedHome {
    /// The home directory to hand to the code under test.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path under the guarded home. Creates nothing.
    #[must_use]
    pub fn child(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.path.join(rel)
    }

    /// Write `contents` to a path under the guarded home, creating its parents.
    ///
    /// # Panics
    ///
    /// If the parents or the file cannot be created. A test whose fixture did
    /// not materialise is not a test that passed.
    pub fn write(&self, rel: impl AsRef<Path>, contents: &str) -> PathBuf {
        let path = self.child(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("creating {}: {e}", parent.display()));
        }
        std::fs::write(&path, contents)
            .unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
        path
    }
}

/// The variable that opts a run into skipping a case this process cannot build.
///
/// Some tests need an `EACCES` that a process holding `CAP_DAC_READ_SEARCH` —
/// root, or a user namespace from `unshare -r` — never sees; others need an
/// unprivileged user namespace with subordinate ids, which `unshare` from
/// util-linux builds. No CI job runs without them, so a silent skip there
/// would be a branch nothing exercises and a suite that goes green with the
/// assertions never run. Instead such a run fails, unless this variable is
/// set to `1` by name. It is the one such policy in the crate.
pub const ALLOW_UNCONSTRUCTIBLE_CASES: &str = "BX_ALLOW_UNCONSTRUCTIBLE_CASES";

/// What to do about a case this process cannot construct, given the opt-in.
///
/// `Ok` carries the announcement to write before skipping; `Err` carries the
/// message to fail with. Only the exact value `1` opts in, so an empty or a
/// `0` setting cannot be mistaken for consent.
fn unconstructible_verdict(
    opt_in: Option<&std::ffi::OsStr>,
    reason: &str,
) -> Result<String, String> {
    if opt_in.is_some_and(|v| v == "1") {
        Ok(format!(
            "skipped ({ALLOW_UNCONSTRUCTIBLE_CASES}=1): {reason}"
        ))
    } else {
        Err(format!(
            "{reason}; the assertions of this test cannot run in this process. \
             Run it as an unprivileged user without CAP_DAC_READ_SEARCH, on a kernel \
             with unprivileged user namespaces and with util-linux present, or set \
             {ALLOW_UNCONSTRUCTIBLE_CASES}=1 to skip it deliberately"
        ))
    }
}

/// Skip a case this process cannot construct, but only if asked to by name.
///
/// Call it where the test is about to return early, after any cleanup. It
/// returns only when [`ALLOW_UNCONSTRUCTIBLE_CASES`] is `1`, and then it has
/// announced the skip through the stderr handle rather than `eprintln!`:
/// libtest captures the print macros and discards the capture for a test that
/// passes, so a macro would tell nobody. A direct write survives that capture.
///
/// Reads the environment, never writes it.
///
/// # Panics
///
/// When the opt-in is not set to `1`, so an ordinary run that cannot build
/// the case fails loudly instead of passing with nothing checked.
pub fn skip_unconstructible(reason: &str) {
    let opt_in = std::env::var_os(ALLOW_UNCONSTRUCTIBLE_CASES);
    skip_unconstructible_to(opt_in.as_deref(), reason, &mut std::io::stderr());
}

/// [`skip_unconstructible`] with the opt-in and the stderr handle passed in.
fn skip_unconstructible_to(
    opt_in: Option<&std::ffi::OsStr>,
    reason: &str,
    stderr: &mut impl std::io::Write,
) {
    match unconstructible_verdict(opt_in, reason) {
        Ok(announcement) => {
            let _ = writeln!(stderr, "{announcement}");
        }
        Err(message) => panic!("{message}"),
    }
}

/// Put a FIFO at `path`, mode `0600`.
///
/// Runs `mkfifo(1)`: rustix offers `mknodat` and `mkfifoat` on Linux only,
/// and calling `libc` directly would take the `unsafe` this crate forbids.
///
/// # Panics
///
/// If `mkfifo` cannot be run or does not make the FIFO. A test whose fixture
/// did not materialise is not a test that passed.
pub fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("running mkfifo for {}: {e}", path.display()));
    assert!(status.success(), "mkfifo {}: {status}", path.display());
}

/// [`skip_unconstructible`] for the test `name`, whose case cannot be built
/// here because of `why`.
#[cfg(test)]
pub(crate) fn cannot_build(name: &str, why: &str) {
    skip_unconstructible(&format!("{name} could not be run on this machine: {why}"));
}

/// This test binary, set to run exactly the `#[ignore]`d test `test` and
/// nothing else, with its output uncaptured so a parent can read what it
/// prints.
///
/// For a case that needs a process of its own: a stdin that is not a
/// terminal, a `umask`, a crash, or a lock held by another pid. The capture
/// is turned off through `RUST_TEST_NOCAPTURE`, so a parent that needs the
/// child capturing removes that variable.
#[cfg(test)]
pub(crate) fn ignored_child(test: &str) -> std::process::Command {
    let mut child = std::process::Command::new(std::env::current_exe().expect("the test binary"));
    child
        .args(["--exact", "--ignored", test])
        .env("RUST_TEST_NOCAPTURE", "1");
    child
}

/// Run `child`, an [`ignored_child`], and assert that it passed exactly one
/// test: a filter that matched nothing would otherwise report success over
/// an empty run.
#[cfg(test)]
#[track_caller]
pub(crate) fn run_ignored_child(child: &mut std::process::Command) -> std::process::Output {
    let output = child.output().expect("spawn the child test");
    let (stdout, stderr) = (
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.status.success(),
        "the child failed:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed") && stdout.contains("0 failed"),
        "the child ran no test:\n{stdout}"
    );
    output
}

/// A [`guarded_home`] and the state directory bx would use under it, not yet
/// created.
#[cfg(test)]
pub(crate) fn guarded_state() -> (GuardedHome, crate::state::StateDir) {
    let home = guarded_home();
    let state = crate::state::StateDir::resolve(home.path());
    (home, state)
}

/// The home the tests that touch no file name: deliberately non-standard,
/// so nothing may name a real account or assume `/home/<user>`.
#[cfg(test)]
pub(crate) fn example_home() -> &'static Path {
    Path::new("/var/home/example")
}

/// Assert that `message` mentions every one of `parts`.
#[cfg(test)]
#[track_caller]
pub(crate) fn assert_mentions(message: &str, parts: &[&str]) {
    for part in parts {
        assert!(
            message.contains(part),
            "{part:?} is missing from: {message}"
        );
    }
}

/// The permission bits of `path`, symlinks followed.
#[cfg(test)]
pub(crate) fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

/// Set the permission bits of `path` to `mode`.
#[cfg(test)]
pub(crate) fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

impl std::fmt::Debug for GuardedHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedHome")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Every `.rs` file under `root`, recursively, sorted by path.
#[cfg(test)]
pub(crate) fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The crate's `src/` directory, read by the tests that hold a property of
/// the source text itself.
#[cfg(test)]
pub(crate) fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every source file of the crate module `module` (`"config"`,
/// `"config::values::local"`), as its path beneath `src/` and its text,
/// sorted by path.
///
/// A module's source is its own file — `src/a/b.rs` — and every `.rs` file
/// beneath `src/a/b/`, which is where its `mod.rs` and its submodules live.
/// Reading the module rather than a list of file names is what keeps a test
/// that scans source holding its property when the module is split into
/// submodules: the new files are read because they are where Rust requires
/// them to be, not because someone remembered to list them.
///
/// # Panics
///
/// When the module has no source file, so a renamed module fails the scan
/// that reads it instead of leaving it scanning nothing.
#[cfg(test)]
pub(crate) fn module_sources(module: &str) -> Vec<(PathBuf, String)> {
    let src = src_root();
    let relative: PathBuf = module.split("::").collect();
    let mut files = Vec::new();
    let own = src.join(&relative).with_extension("rs");
    if own.is_file() {
        files.push(own);
    }
    let dir = src.join(&relative);
    if dir.is_dir() {
        files.extend(rust_sources(&dir));
    }
    assert!(
        !files.is_empty(),
        "the module `{module}` has no source file under {}",
        src.display()
    );
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            let beneath = path.strip_prefix(&src).expect("beneath src").to_path_buf();
            (beneath, text)
        })
        .collect()
}

/// The shipped half of the source file at `path` (beneath `src/`), whose text
/// is `source`: the one rule every test that scans source uses to tell the
/// code a release builds from the code only its tests build.
///
/// A file named `tests.rs`, or beneath a directory named `tests/`, is wholly
/// test code, so its shipped half is empty. Any other file is shipped up to
/// its inline `#[cfg(test)]` `mod tests {` block, which runs to the end of the
/// file. Only that block is cut: a `#[cfg(test)]` item above production code
/// is a single item, and the code after it is still shipped and still read.
#[cfg(test)]
pub(crate) fn shipped_source<'a>(path: &Path, source: &'a str) -> &'a str {
    if path.file_stem().is_some_and(|stem| stem == "tests")
        || path
            .parent()
            .is_some_and(|dir| dir.components().any(|c| c.as_os_str() == "tests"))
    {
        return "";
    }
    source
        .find("#[cfg(test)]\nmod tests {")
        .map_or(source, |end| &source[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_is_read_from_its_file_and_its_directory() {
        // `config` is a directory module; `config::values` is both a file and
        // a directory, so its submodule is read with it.
        let paths = |module: &str| -> Vec<PathBuf> {
            module_sources(module)
                .into_iter()
                .map(|(path, _)| path)
                .collect()
        };
        let config = paths("config");
        assert!(
            config.contains(&PathBuf::from("config/mod.rs")),
            "{config:?}"
        );
        assert!(
            config.contains(&PathBuf::from("config/values/local.rs")),
            "{config:?}"
        );
        assert_eq!(
            paths("config::values"),
            vec![
                PathBuf::from("config/values/local.rs"),
                PathBuf::from("config/values/tests.rs"),
                PathBuf::from("config/values.rs"),
            ],
            "sorted by path component, so a directory sorts before its sibling file"
        );
        assert_eq!(paths("paths"), vec![PathBuf::from("paths.rs")]);
    }

    #[test]
    #[should_panic(expected = "has no source file")]
    fn a_module_with_no_source_is_refused() {
        let _ = module_sources("no_such_module");
    }

    #[test]
    fn shipped_source_cuts_only_at_the_test_module() {
        let source = "fn a() {}\n#[cfg(test)]\nstatic X: u8 = 0;\nfn b() {}\n\
                      #[cfg(test)]\nmod tests {\n    fn c() {}\n}\n";
        assert_eq!(
            shipped_source(Path::new("a/b.rs"), source),
            "fn a() {}\n#[cfg(test)]\nstatic X: u8 = 0;\nfn b() {}\n",
            "a #[cfg(test)] item above production code hides none of it"
        );
        assert_eq!(
            shipped_source(Path::new("a.rs"), "fn a() {}\n"),
            "fn a() {}\n"
        );
        for test_file in ["a/tests.rs", "a/tests/b.rs", "tests/b/c.rs"] {
            assert_eq!(
                shipped_source(Path::new(test_file), source),
                "",
                "{test_file}"
            );
        }
        // The rule holds on the file that motivated it: `when.rs` declares a
        // test-only `static` above `Machine::read`.
        let (path, when) = module_sources("config::when")
            .into_iter()
            .find(|(path, _)| path == Path::new("config/when.rs"))
            .expect("config/when.rs");
        assert!(when.contains("#[cfg(test)]\nstatic UNKNOWN"));
        assert!(shipped_source(&path, &when).contains("pub fn read("));
    }

    #[test]
    fn the_guard_hands_out_a_tempdir() {
        let home = guarded_home();

        assert!(home.path().is_dir());
        assert!(home.path().starts_with(canonical(&std::env::temp_dir())));
    }

    #[test]
    fn the_guard_mutates_no_environment_variable() {
        // The property that replaces the old restore-on-drop: there is nothing
        // to restore, because nothing was changed. Reading before and after is
        // race-free precisely because no test in this crate writes.
        let before = std::env::var_os("HOME");
        let home = guarded_home();

        assert_eq!(std::env::var_os("HOME"), before);
        assert_ne!(
            std::env::var_os("HOME").map(PathBuf::from).as_deref(),
            Some(home.path()),
            "the guard hands the home out; it never installs it"
        );

        drop(home);
        assert_eq!(std::env::var_os("HOME"), before);
    }

    #[test]
    fn a_dropped_guard_takes_its_tempdir_with_it() {
        let path = {
            let home = guarded_home();
            home.write("a/b.txt", "x");
            home.path().to_path_buf()
        };

        assert!(!path.exists(), "the tempdir outlived its guard");
    }

    #[test]
    fn two_guards_nest_without_deadlocking() {
        // A mutex-holding guard could not do this, and a shared fixture helper
        // that takes its own guard is the natural shape once thirty entries
        // have test support of their own.
        let outer = guarded_home();
        let inner = guarded_home();

        assert_ne!(outer.path(), inner.path());
        assert!(outer.path().is_dir());
        assert!(inner.path().is_dir());
    }

    #[test]
    fn a_guard_survives_a_panic_in_a_test_that_holds_one() {
        // The old guard held a mutex, so a panic here poisoned it for every
        // later test. With no shared state there is nothing to poison.
        let panicked = std::thread::spawn(|| {
            let _home = guarded_home();
            panic!("deliberately panicking while a guard is alive");
        })
        .join();
        assert!(panicked.is_err(), "the helper thread should have panicked");

        let home = guarded_home();
        assert!(home.path().is_dir());
    }

    #[test]
    fn a_guard_names_its_tempdir_when_debugged() {
        // Later entries will read this in an `expect` message.
        let home = guarded_home();
        let rendered = format!("{home:?}");

        assert!(rendered.contains("GuardedHome"), "{rendered}");
        assert!(
            rendered.contains(&home.path().display().to_string()),
            "{rendered}"
        );
    }

    #[test]
    fn the_guard_writes_children_with_their_parents() {
        let home = guarded_home();
        let written = home.write(".config/bx/bx.toml", "# empty\n");

        assert_eq!(written, home.child(".config/bx/bx.toml"));
        assert_eq!(std::fs::read_to_string(&written).unwrap(), "# empty\n");
        assert!(home.child(".config/bx").is_dir());
    }

    #[test]
    fn an_unconstructible_case_fails_unless_the_skip_is_asked_for_by_name() {
        use std::ffi::OsStr;

        // Nothing but exactly `1` is a spelling of "yes": an empty value, a
        // `0` or a `true` left over from another tool's convention must not
        // turn the suite's own failures off.
        let spellings = ["", "0", "true", "yes", "1 ", " 1"];
        for opt_in in std::iter::once(None).chain(spellings.map(|s| Some(OsStr::new(s)))) {
            let message = unconstructible_verdict(opt_in, "no EACCES here")
                .expect_err("an ordinary run must fail, not skip");
            assert!(message.starts_with("no EACCES here"), "{message}");
            assert!(
                message.contains("BX_ALLOW_UNCONSTRUCTIBLE_CASES=1"),
                "the failure names the opt-in: {message}"
            );
            assert!(
                message.contains("unprivileged"),
                "the failure names the environment: {message}"
            );
        }
    }

    /// What the parent tells [`skip_child`] to expect of the opt-in.
    const EXPECT_SKIP: &str = "BX_TEST_EXPECT_SKIP";

    /// What [`skip_child`] writes with `eprintln!`, which libtest captures.
    const CAPTURED_MARKER: &str = "bx-eprintln-is-swallowed";

    #[test]
    #[ignore = "spawned by the_opt_in_is_read_from_the_environment_and_announced_past_the_capture"]
    fn skip_child() {
        let Some(expected) = std::env::var_os(EXPECT_SKIP) else {
            return;
        };
        let skipped = std::panic::catch_unwind(|| skip_unconstructible("a probe")).is_ok();
        assert_eq!(skipped, expected == "yes", "the opt-in was misread");
        eprintln!("{CAPTURED_MARKER}");
    }

    #[test]
    fn the_opt_in_is_read_from_the_environment_and_announced_past_the_capture() {
        // A child can be given any state of the variable, where this process
        // cannot set one. It runs captured, so its `eprintln!` reaches
        // nowhere, and an opted-in skip's announcement still reaches its
        // stderr: a skip announced through the capture would tell nobody.
        for (set, expect) in [(None, "no"), (Some("1"), "yes"), (Some("0"), "no")] {
            let mut child = ignored_child("testing::tests::skip_child");
            child
                .env(EXPECT_SKIP, expect)
                .env_remove("RUST_TEST_NOCAPTURE");
            match set {
                Some(value) => child.env(ALLOW_UNCONSTRUCTIBLE_CASES, value),
                None => child.env_remove(ALLOW_UNCONSTRUCTIBLE_CASES),
            };
            let out = run_ignored_child(&mut child);
            let err = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                err.contains("skipped (BX_ALLOW_UNCONSTRUCTIBLE_CASES=1): a probe"),
                expect == "yes",
                "{set:?}: {err}"
            );
            assert!(!err.contains(CAPTURED_MARKER), "{set:?}: {err}");
        }

        // A value that is not `1`, set in the belief that it turns the
        // opt-in off, leaves every unbuildable case failing while whoever
        // set it thinks otherwise, and that is worth a red suite.
        if let Some(value) = std::env::var_os(ALLOW_UNCONSTRUCTIBLE_CASES) {
            assert!(
                value == "1",
                "{ALLOW_UNCONSTRUCTIBLE_CASES} is set to {value:?}, which is not a \
                 spelling of the opt-in. Unset it, or set it to exactly 1."
            );
        }
    }

    #[test]
    fn an_unconstructible_case_is_skipped_and_announced_when_opted_into() {
        let announcement =
            unconstructible_verdict(Some(std::ffi::OsStr::new("1")), "no EACCES here")
                .expect("the opt-in skips");
        assert_eq!(
            announcement,
            "skipped (BX_ALLOW_UNCONSTRUCTIBLE_CASES=1): no EACCES here"
        );
    }

    #[test]
    fn an_opted_in_skip_writes_its_announcement_to_the_handle() {
        let mut stderr = Vec::new();
        skip_unconstructible_to(
            Some(std::ffi::OsStr::new("1")),
            "no EACCES here",
            &mut stderr,
        );
        assert_eq!(
            String::from_utf8(stderr).expect("utf-8"),
            "skipped (BX_ALLOW_UNCONSTRUCTIBLE_CASES=1): no EACCES here\n"
        );
    }

    #[test]
    #[should_panic(expected = "set BX_ALLOW_UNCONSTRUCTIBLE_CASES=1 to skip it deliberately")]
    fn a_skip_that_was_not_asked_for_panics() {
        let mut stderr = Vec::new();
        skip_unconstructible_to(None, "no EACCES here", &mut stderr);
    }

    #[test]
    #[should_panic(expected = "\"x\" is missing from: abc")]
    fn a_message_missing_a_part_fails_assert_mentions() {
        assert_mentions("abc", &["a", "bc"]);
        assert_mentions("abc", &["b", "x"]);
    }

    #[test]
    #[should_panic(expected = "not under the system temp directory")]
    fn the_guard_rejects_a_home_outside_the_system_temp_dir() {
        check_is_a_throwaway_home(Path::new("/var/home/example/work"), None);
    }

    #[test]
    #[should_panic(expected = "it is inside the real home")]
    fn the_guard_rejects_a_temp_dir_inside_the_real_home() {
        // A TMPDIR under the developer's own home: the candidate passes the
        // system-temp check and still guards nothing.
        let real_home = canonical(&std::env::temp_dir());
        let candidate = real_home.join("tmp/bx-fake");
        check_is_a_throwaway_home(&candidate, Some(&real_home));
    }

    #[test]
    #[should_panic(expected = "is inside it")]
    fn the_guard_rejects_a_temp_dir_that_contains_the_real_home() {
        let candidate = canonical(&std::env::temp_dir());
        let real_home = candidate.join("someone");
        check_is_a_throwaway_home(&candidate, Some(&real_home));
    }

    /// How a forbidden needle is matched.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Rule {
        /// Anywhere in the text, boundaries included.
        ///
        /// For a **path**. A path cannot occur inside an English word, so it
        /// needs no word boundary — and demanding one would miss the spelling
        /// that matters most: a home under a symlinked mount is written
        /// `/var/<home>` once resolved, where the home is preceded by `r`.
        Anywhere,
        /// Only where neither neighbour is an alphanumeric character.
        ///
        /// For an **account name**, which does occur inside ordinary words.
        /// Both sides count because the name is whatever the machine running
        /// the test says it is, and a short name is the start of many words.
        WholeWord,
    }

    /// The shortest account name worth hunting for. A shorter one is the
    /// whole of too many ordinary words for a match to mean anything.
    const SHORTEST_ACCOUNT_NAME: usize = 4;

    /// The fewest named components a path needs to identify someone: `/root`
    /// and `/` name a system account or nothing, `/home/<name>` names a person.
    const FEWEST_PATH_COMPONENTS: usize = 2;

    /// Every user-specific needle on a machine with this account name, home
    /// directory and checkout path, with the rule that matches each.
    ///
    /// Derived from the machine running the test rather than stored in the
    /// repository, because a stored list of someone's account names and paths
    /// is itself the user-specific data invariant 5 forbids. On CI the account,
    /// home and checkout are a hosted runner's, which identify nobody and whose
    /// generic account name occurs in ordinary prose, so there are none.
    fn user_specific_needles(
        on_ci: bool,
        account: Option<&str>,
        home: Option<&Path>,
        checkout: Option<&Path>,
    ) -> Vec<(String, Rule)> {
        if on_ci {
            return Vec::new();
        }
        let mut needles = Vec::new();
        if let Some(account) = account.map(str::to_ascii_lowercase)
            && account.len() >= SHORTEST_ACCOUNT_NAME
        {
            needles.push((account, Rule::WholeWord));
        }
        for path in [home, checkout].into_iter().flatten() {
            let named = path
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .count();
            if named >= FEWEST_PATH_COMPONENTS {
                // Rebuilt from its components, so a trailing `/` is dropped.
                let path: PathBuf = path.components().collect();
                needles.push((path.to_string_lossy().to_ascii_lowercase(), Rule::Anywhere));
            }
        }
        needles
    }

    /// The needles of the machine running this test.
    fn machine_needles() -> Vec<(String, Rule)> {
        let account = std::env::var("USER").ok();
        let home = std::env::var_os("HOME").map(PathBuf::from);
        user_specific_needles(
            std::env::var_os("CI").is_some_and(|ci| !ci.is_empty()),
            account.as_deref(),
            home.as_deref(),
            Some(Path::new(env!("CARGO_MANIFEST_DIR"))),
        )
    }

    /// Every needle of `needles` that `text` names. `text` is expected
    /// lowercased.
    fn user_specific_offences(text: &str, needles: &[(String, Rule)]) -> Vec<String> {
        needles
            .iter()
            .filter(|(needle, rule)| match rule {
                Rule::Anywhere => text.contains(needle.as_str()),
                Rule::WholeWord => contains_token(text, needle),
            })
            .map(|(needle, _)| needle.clone())
            .collect()
    }

    /// A machine no developer has: every needle the tests below match against.
    fn synthetic_needles() -> Vec<(String, Rule)> {
        user_specific_needles(
            false,
            Some("Quillon"),
            Some(Path::new("/home/quillon/")),
            Some(Path::new("/srv/build/quillon/bx")),
        )
    }

    #[test]
    fn the_needles_are_the_account_the_home_and_the_checkout() {
        assert_eq!(
            synthetic_needles(),
            vec![
                ("quillon".to_owned(), Rule::WholeWord),
                ("/home/quillon".to_owned(), Rule::Anywhere),
                ("/srv/build/quillon/bx".to_owned(), Rule::Anywhere),
            ]
        );
    }

    #[test]
    fn a_needle_too_short_to_identify_anyone_is_skipped() {
        assert!(
            user_specific_needles(false, Some("bob"), Some(Path::new("/root")), None).is_empty()
        );
        assert!(user_specific_needles(false, None, Some(Path::new("/")), None).is_empty());
        assert_eq!(
            user_specific_needles(false, Some("anna"), None, Some(Path::new("/w/bx"))),
            vec![
                ("anna".to_owned(), Rule::WholeWord),
                ("/w/bx".to_owned(), Rule::Anywhere),
            ]
        );
    }

    #[test]
    fn a_ci_runner_has_no_needles() {
        let needles = user_specific_needles(
            true,
            Some("quillon"),
            Some(Path::new("/home/quillon")),
            Some(Path::new("/home/quillon/work/bx")),
        );
        assert!(needles.is_empty(), "{needles:?}");
    }

    #[test]
    fn a_user_specific_path_is_an_offence_wherever_it_appears() {
        let needles = synthetic_needles();
        let offences = |text: &str| user_specific_offences(text, &needles);
        // The paths alone, so a path is seen to be caught by its own rule and
        // not by the account name inside it.
        let paths: Vec<_> = needles
            .iter()
            .filter(|(_, rule)| *rule == Rule::Anywhere)
            .cloned()
            .collect();

        // A home under a symlinked mount, as it reads once resolved: the path
        // is preceded by `r`, so a word-boundary rule would exempt it.
        assert_eq!(
            user_specific_offences("/var/home/quillon/dev/x", &paths),
            ["/home/quillon"]
        );
        assert_eq!(
            user_specific_offences("cd /srv/build/quillon/bx/src", &paths),
            ["/srv/build/quillon/bx"]
        );
        // The bare account name.
        assert_eq!(offences("home = quillon"), ["quillon"]);
        assert_eq!(
            offences("by Quillon.".to_ascii_lowercase().as_str()),
            ["quillon"]
        );
        // An account name inside an ordinary word, on either side, is not.
        assert!(offences("an amalquillon of prose").is_empty());
        assert!(offences("a quillonite of prose").is_empty());

        // The path rule needs a negative case of its own, or a rule that
        // reported every string would pass this test and still be useless. A
        // path sharing a needle's leading directories, but not the
        // account-specific tail, is not an offence.
        assert!(
            offences("/home/shared/dev/x").is_empty(),
            "only the account-specific tail makes the path a literal"
        );
        assert!(
            offences("/var/home/example/.ssh/config").is_empty(),
            "the placeholder home every test in this crate uses is not an offence"
        );
    }

    /// Every git-tracked file under `root`, as an absolute path.
    fn tracked_files(root: &Path) -> Vec<PathBuf> {
        use std::os::unix::ffi::OsStrExt;

        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["ls-files", "-z"])
            .output()
            .unwrap_or_else(|e| panic!("running git ls-files in {}: {e}", root.display()));
        assert!(
            out.status.success(),
            "git ls-files in {} failed: {}",
            root.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
            .split(|&b| b == 0)
            .filter(|name| !name.is_empty())
            .map(|name| root.join(std::ffi::OsStr::from_bytes(name)))
            .collect()
    }

    /// The text of tracked file `file` the guard reads, lowercased.
    ///
    /// `Cargo.toml`'s `authors` field names a person on purpose: authorship
    /// metadata is a legitimate exception, and a guard that fired on it would
    /// be deleted rather than obeyed. That line, and nothing else, is left out.
    fn scanned_text(root: &Path, file: &Path, bytes: &[u8]) -> String {
        let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if file != root.join("Cargo.toml") {
            return text;
        }
        text.lines()
            .filter(|line| !line.trim_start().starts_with("authors"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn only_the_authors_line_of_the_manifest_is_exempt() {
        let root = Path::new("/srv/build/quillon/bx");
        let manifest = b"[package]\nauthors = [\"Quillon\"]\nname = \"bx\"\n";
        let needles = synthetic_needles();
        let read = |file: &str| scanned_text(root, &root.join(file), manifest);

        assert!(user_specific_offences(&read("Cargo.toml"), &needles).is_empty());
        assert_eq!(
            user_specific_offences(&read("README.md"), &needles),
            ["quillon"]
        );
        assert!(read("Cargo.toml").contains("name = \"bx\""));
    }

    /// Invariant 5 has no exception, and a one-time fix without a regression
    /// guard is not enforcement. Every tracked file is read, this one included:
    /// the needles are the running machine's, so no file has to hold them.
    #[test]
    fn no_user_specific_literal_survives_in_a_tracked_file() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let needles = machine_needles();

        let mut offences = Vec::new();
        for file in tracked_files(root) {
            // A tracked file deleted in the working tree has nothing to read.
            if !file.is_file() {
                continue;
            }
            let bytes =
                std::fs::read(&file).unwrap_or_else(|e| panic!("reading {}: {e}", file.display()));
            for needle in user_specific_offences(&scanned_text(root, &file, &bytes), &needles) {
                offences.push(format!("{} names {needle}", file.display()));
            }
        }

        assert!(
            offences.is_empty(),
            "nothing user-specific may live in the repository:\n  {}",
            offences.join("\n  ")
        );
    }

    /// `haystack` contains `needle` with no alphanumeric character on either
    /// side.
    ///
    /// The boundary matters: an account name is often the start or the middle
    /// of an ordinary word, and a guard that fires on ordinary English is a
    /// guard someone deletes.
    fn contains_token(haystack: &str, needle: &str) -> bool {
        let alphanumeric = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
        haystack.match_indices(needle).any(|(at, _)| {
            !alphanumeric(haystack[..at].chars().next_back())
                && !alphanumeric(haystack[at + needle.len()..].chars().next())
        })
    }
}
