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
//! every `TempDir::new()`, and [`crate::detect::locate_in_env`] reads `PATH`, and
//! `cargo test` runs all of it concurrently in one process. glibc's `unsetenv`
//! shifts `environ` in place, so a concurrent `getenv` can read a stale pointer.
//! The symptom would have been a flaky failure in a test that has nothing to do
//! with home directories.
//!
//! So the mutation is gone rather than serialised, and the crate now contains no
//! `unsafe` at all. Every library function that needs a home takes it as an
//! argument — [`crate::paths::home_in`], [`crate::paths::xdg_base`] and
//! [`crate::paths::config_root_in`] are the parameterised forms, and
//! [`crate::paths::home`] and [`crate::paths::config_root`] are one-line wrappers
//! that read the real environment and are tested by agreeing with it.
//!
//! # The rule for every later entry
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
#[must_use]
pub fn guarded_home() -> GuardedHome {
    let real_home = std::env::var_os("HOME").map(PathBuf::from);
    let dir = TempDir::new().expect("a tempdir for the guarded home");
    check_is_a_throwaway_home(dir.path(), real_home.as_deref());

    GuardedHome { dir }
}

/// A throwaway home directory, removed when the guard drops.
///
/// Created by [`guarded_home`]. Holds no lock and mutates nothing global, so it
/// nests freely.
pub struct GuardedHome {
    dir: TempDir,
}

impl GuardedHome {
    /// The home directory to hand to the code under test.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A path under the guarded home. Creates nothing.
    #[must_use]
    pub fn child(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.dir.path().join(rel)
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

impl std::fmt::Debug for GuardedHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedHome")
            .field("path", &self.dir.path())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[derive(Clone, Copy)]
    enum Rule {
        /// Anywhere in the text, boundaries included.
        ///
        /// For a **path** fragment. A path cannot occur inside an English word,
        /// so it needs no leading word boundary — and demanding one is what made
        /// this guard miss the very spelling it was written to catch: the real
        /// directory is `/var/<fragment>`, where the fragment is preceded by
        /// `r`, so the canonical path was not reported.
        Anywhere,
        /// Only where it is not preceded by an alphanumeric character.
        ///
        /// For an **account name**, which does occur inside ordinary words.
        WholeWord,
    }

    /// Every user-specific needle, with the rule that matches it.
    ///
    /// Assembled from fragments at runtime so this file is not its own
    /// counter-example.
    fn user_specific_needles() -> Vec<(String, Rule)> {
        vec![
            (["/m", "nt/sc", "ratch/go", "lem"].concat(), Rule::Anywhere),
            (["jus", "tin"].concat(), Rule::WholeWord),
            (["jus", "ty"].concat(), Rule::WholeWord),
            (["go", "lem"].concat(), Rule::WholeWord),
        ]
    }

    /// Every forbidden needle `text` names. `text` is expected lowercased.
    fn user_specific_offences(text: &str) -> Vec<String> {
        user_specific_needles()
            .into_iter()
            .filter(|(needle, rule)| match rule {
                Rule::Anywhere => text.contains(needle.as_str()),
                Rule::WholeWord => contains_token(text, needle),
            })
            .map(|(needle, _)| needle)
            .collect()
    }

    #[test]
    fn a_user_specific_path_is_an_offence_wherever_it_appears() {
        let fragment = ["/m", "nt/sc", "ratch/go", "lem"].concat();
        let account = ["go", "lem"].concat();

        // The canonical spelling on the machine this repository lives on. The
        // fragment is preceded by `r`, so the word-boundary rule exempted it and
        // the primary case went unreported.
        assert!(!user_specific_offences(&format!("/var{fragment}/dev/x")).is_empty());
        assert!(!user_specific_offences(&format!("{fragment}/dev/x")).is_empty());
        // The bare account name, which was not a needle at all.
        assert!(!user_specific_offences(&format!("/home/{account}")).is_empty());
        assert!(!user_specific_offences(&format!("home = {account}")).is_empty());
        // And an account name inside an ordinary word still is not an offence.
        assert!(user_specific_offences(&format!("an amal{account} of prose")).is_empty());

        // The path rule needs a negative case of its own, or a rule that
        // reported every string would pass this test and still be useless. A
        // path sharing the fragment's leading directories, but not the
        // account-specific tail, is not an offence.
        let prefix = ["/m", "nt/sc", "ratch/"].concat();
        assert!(
            user_specific_offences(&format!("{prefix}shared/dev/x")).is_empty(),
            "only the account-specific tail makes the path a literal"
        );
        assert!(
            user_specific_offences("/var/home/example/.ssh/config").is_empty(),
            "the placeholder home every test in this crate uses is not an offence"
        );
    }

    /// Invariant 5 has no exception, and a one-time fix without a regression
    /// guard is not enforcement. This file is skipped, because the needles it
    /// hunts for have to appear in it somewhere.
    ///
    /// The blast radius is `src/` only. `Cargo.toml`'s `authors` field names a
    /// person on purpose: authorship metadata is a legitimate exception, and a
    /// guard that fired on it would be deleted rather than obeyed.
    #[test]
    fn no_user_specific_literal_survives_under_src() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let self_path = root.join("testing.rs");

        let mut offences = Vec::new();
        for file in rust_sources(&root) {
            if file == self_path {
                continue;
            }
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("reading {}: {e}", file.display()))
                .to_ascii_lowercase();
            for needle in user_specific_offences(&text) {
                offences.push(format!("{} names {needle}", file.display()));
            }
        }

        assert!(
            offences.is_empty(),
            "nothing user-specific may live under src/:\n  {}",
            offences.join("\n  ")
        );
    }

    /// Every `.rs` file under `root`, recursively, in no particular order.
    fn rust_sources(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
            for entry in entries {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        out
    }

    /// `haystack` contains `needle` not preceded by an alphanumeric character.
    ///
    /// The boundary matters: "adjusting" contains one of the usernames as a
    /// substring, and a guard that fires on ordinary English is a guard someone
    /// deletes.
    fn contains_token(haystack: &str, needle: &str) -> bool {
        haystack.match_indices(needle).any(|(at, _)| {
            haystack[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric())
        })
    }
}
