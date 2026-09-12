//! Test support: a `$HOME` that is a tempdir, and a guard that aborts otherwise.
//!
//! `CLAUDE.md` requires that anything touching a home directory run against a
//! tempdir `$HOME`, behind a guard that **aborts** — panics, never skips — when
//! `$HOME` is not a tempdir. This module is that guard, and it is the only place
//! in the crate that mutates the process environment.
//!
//! The rule for every later entry:
//!
//! * A test that reads or writes anything under a home directory opens with
//!   `let home = bx::testing::guarded_home();` and passes `home.path()` down.
//! * A test that does not touch a home directory uses design-by-parameter, the
//!   way [`crate::detect`] and [`crate::paths`] already do: build the input from
//!   a tempdir and hand it in.
//! * **No test sets `HOME` itself.** `std::env::set_var` is `unsafe` in edition
//!   2024 precisely because the environment is process-wide, and `cargo test`
//!   runs tests in threads of one process. The guard holds a crate-wide mutex
//!   for its whole lifetime, and that lock is what makes the mutation sound. A
//!   test that mutates the environment outside the guard races with every other
//!   test in the binary.
//!
//! The module is compiled unconditionally rather than under `#[cfg(test)]` so an
//! integration test in `tests/` can reach it. It is `#[doc(hidden)]`: it is
//! support, not surface.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tempfile::TempDir;

/// The variables the guard captures and restores.
///
/// `HOME` is repointed at the tempdir. The four XDG overrides are *cleared*, so
/// a developer's own XDG settings cannot leak into a test and change where the
/// code under test decides the config repo or the state directory lives.
const GUARDED: [&str; 5] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
];

/// Serialises every environment mutation this module performs.
static HOME_LOCK: Mutex<()> = Mutex::new(());

/// Take the environment lock, recovering from poisoning.
///
/// A test that panics while holding the lock would otherwise cascade into every
/// later test in the binary. The data the lock protects is the process
/// environment, which the guard restores on unwind, so there is no invariant a
/// poisoned lock could be protecting.
fn lock() -> MutexGuard<'static, ()> {
    HOME_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read the current value of every guarded variable.
fn capture() -> Vec<(&'static str, Option<OsString>)> {
    GUARDED
        .iter()
        .map(|&name| (name, std::env::var_os(name)))
        .collect()
}

/// Put every captured variable back, restoring unset-ness as unset.
fn restore(saved: &[(&'static str, Option<OsString>)]) {
    for (name, value) in saved {
        set_raw(name, value.as_deref());
    }
}

/// Set or remove one variable.
fn set_raw(name: &str, value: Option<&OsStr>) {
    // SAFETY: every caller reaches this function while holding `HOME_LOCK`, so
    // no other thread in this process is reading or writing the environment
    // through this module at the same time.
    unsafe {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
}

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
/// would otherwise get a "tempdir" `$HOME` that guards nothing.
fn check_is_a_throwaway_home(candidate: &Path, real_home: Option<&Path>) {
    let system_temp = canonical(&std::env::temp_dir());
    let candidate = canonical(candidate);

    assert!(
        candidate.starts_with(&system_temp),
        "refusing to point HOME at {}: it is not under the system temp directory {}",
        candidate.display(),
        system_temp.display(),
    );

    if let Some(real_home) = real_home {
        let real_home = canonical(real_home);
        assert!(
            !candidate.starts_with(&real_home),
            "refusing to point HOME at {}: it is inside the real home {} \
             (TMPDIR under $HOME makes the guard guard nothing)",
            candidate.display(),
            real_home.display(),
        );
        assert!(
            !real_home.starts_with(&candidate),
            "refusing to point HOME at {}: the real home {} is inside it",
            candidate.display(),
            real_home.display(),
        );
    }
}

/// Point `$HOME` at a fresh tempdir for the lifetime of the returned guard.
///
/// Clears `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` and
/// `XDG_CACHE_HOME` for the same lifetime, and restores every one of them —
/// including its unset-ness — when the guard drops.
///
/// # Panics
///
/// Aborts, rather than skipping, if the tempdir cannot be created, if it is not
/// under the system temp directory, or if it and the real `$HOME` contain each
/// other. A silent pass is the one outcome a safety guard may not produce.
#[must_use]
pub fn guarded_home() -> GuardedHome {
    let lock = lock();
    let saved = capture();
    let real_home = std::env::var_os("HOME");

    let dir = TempDir::new().expect("a tempdir for the guarded HOME");
    check_is_a_throwaway_home(dir.path(), real_home.as_deref().map(Path::new));

    set_raw("HOME", Some(dir.path().as_os_str()));
    for name in &GUARDED[1..] {
        set_raw(name, None);
    }

    GuardedHome {
        dir,
        saved,
        _lock: lock,
    }
}

/// A tempdir `$HOME`, held for as long as the guard lives.
///
/// Created by [`guarded_home`]. Dropping it restores the environment and removes
/// the tempdir.
pub struct GuardedHome {
    dir: TempDir,
    saved: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl GuardedHome {
    /// The tempdir `$HOME` points at.
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

    /// Override one of the variables this guard already captured.
    ///
    /// `None` removes it. The change is undone when the guard drops, like every
    /// other mutation the guard makes, which is why only captured variables may
    /// be set through it.
    ///
    /// # Panics
    ///
    /// If `name` is not one of the guarded variables — setting anything else
    /// would leave the process environment dirty after the guard drops.
    pub fn set(&self, name: &str, value: Option<&OsStr>) {
        assert!(
            GUARDED.contains(&name),
            "{name} is not a variable this guard captured, so it could not be restored",
        );
        set_raw(name, value);
    }
}

impl Drop for GuardedHome {
    fn drop(&mut self) {
        restore(&self.saved);
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
    fn the_guard_points_home_at_a_tempdir() {
        let home = guarded_home();
        assert_eq!(
            std::env::var_os("HOME").as_deref(),
            Some(home.path().as_os_str())
        );
        assert!(home.path().is_dir());
    }

    #[test]
    fn the_guard_clears_xdg_overrides() {
        let home = guarded_home();
        for name in &GUARDED[1..] {
            assert_eq!(std::env::var_os(name), None, "{name} should be cleared");
        }
        // And the guard can put one back for a test that wants to exercise it.
        let explicit = home.child("xdg");
        home.set("XDG_CONFIG_HOME", Some(explicit.as_os_str()));
        assert_eq!(
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
            Some(explicit.as_os_str())
        );
    }

    #[test]
    #[should_panic(expected = "is not a variable this guard captured")]
    fn the_guard_refuses_to_set_a_variable_it_cannot_restore() {
        let home = guarded_home();
        home.set("PATH", Some(OsStr::new("/nowhere")));
    }

    #[test]
    fn the_guard_restores_the_previous_home() {
        // Runs the capture/restore pair Drop is made of, under the same lock, so
        // it observes a restoration end to end without racing another guard.
        let _lock = lock();
        let sentinel = std::env::temp_dir().join("bx-sentinel-home");
        set_raw("HOME", Some(sentinel.as_os_str()));

        let saved = capture();
        let dir = TempDir::new().expect("a tempdir");
        set_raw("HOME", Some(dir.path().as_os_str()));
        assert_eq!(
            std::env::var_os("HOME").as_deref(),
            Some(dir.path().as_os_str())
        );

        restore(&saved);
        assert_eq!(std::env::var_os("HOME"), Some(sentinel.into_os_string()));
    }

    #[test]
    fn the_guard_restores_an_unset_variable_as_unset() {
        let _lock = lock();
        set_raw("XDG_STATE_HOME", None);

        let saved = capture();
        set_raw("XDG_STATE_HOME", Some(OsStr::new("/var/tmp/somewhere")));
        assert!(std::env::var_os("XDG_STATE_HOME").is_some());

        restore(&saved);
        assert_eq!(
            std::env::var_os("XDG_STATE_HOME"),
            None,
            "an unset variable must come back unset, not empty"
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

    #[test]
    fn a_poisoned_lock_does_not_disable_the_guard() {
        let poisoned = std::thread::spawn(|| {
            let _held = lock();
            panic!("deliberately poisoning the guard's lock");
        })
        .join();
        assert!(poisoned.is_err(), "the helper thread should have panicked");

        let home = guarded_home();
        assert_eq!(
            std::env::var_os("HOME").as_deref(),
            Some(home.path().as_os_str())
        );
    }

    /// Invariant 5 has no exception, and a one-time fix without a regression
    /// guard is not enforcement. The needles are assembled from fragments at
    /// runtime so this file is not its own counter-example, and this file is
    /// skipped for the same reason.
    #[test]
    fn no_user_specific_literal_survives_under_src() {
        let needles = [
            ["/m", "nt/sc", "ratch/go", "lem"].concat(),
            ["jus", "tin"].concat(),
            ["jus", "ty"].concat(),
        ];
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
            for needle in &needles {
                if contains_token(&text, needle) {
                    offences.push(format!("{} names {needle}", file.display()));
                }
            }
        }

        assert!(
            offences.is_empty(),
            "nothing user-specific may live in this repository:\n  {}",
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

    #[test]
    fn a_username_inside_an_ordinary_word_is_not_an_offence() {
        assert!(!contains_token("adjusting the margin", "justin"));
        assert!(contains_token("home = justin", "justin"));
        assert!(contains_token("justin", "justin"));
        assert!(contains_token("/home/justin", "justin"));
    }
}
