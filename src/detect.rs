//! Whether a tool bx configures is actually usable on this machine.
//!
//! bx generates configuration *for* other tools, and some of them — sccache
//! most of all — are configured entirely by environment, so bx's output is a
//! shell fragment naming a binary. That output does not degrade gracefully when
//! the binary is absent: `RUSTC_WRAPPER=/usr/bin/sccache` on a machine without
//! sccache breaks every `cargo build`, not just sccache's own behaviour.
//! [`env_guard`](crate::env_guard) cannot catch it: it checks *where* a value
//! points, never *whether what it points at exists*, because a verdict that
//! consulted the filesystem would not be reproducible.
//!
//! Resolution is by `stat` and `access` alone. bx never runs `tool --version`
//! to find out whether a tool is there: spawning a process to answer a question
//! this cheap would put the cost on every caller. It is still filesystem I/O,
//! so this module must never be reached from the shell-start path, which has a
//! 5 ms budget and spawns nothing.
//!
//! Two rules keep the answer from depending on where the user was standing when
//! they ran the command, which invariant 3 requires — a `plan` that differs by
//! working directory is not idempotent:
//!
//! * an empty `PATH` entry is skipped rather than read as `.`, and
//! * a relative path is not resolved at all.
//!
//! [`locate`] also takes `PATH` as an argument rather than reading it, so it is
//! a pure function of its inputs and the filesystem: tests supply their own
//! search path instead of mutating the process environment, which is shared
//! mutable state under a threaded test runner.

use rustix::fs::Access;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// What bx found when it looked for a tool.
///
/// "Present but not executable" is a distinct answer rather than a flavour of
/// missing because it is the one the user can act on differently: the tool is
/// installed, and something about the install is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// Found, and executable by this user. The only state bx configures for.
    Present {
        /// Where it was found, in `PATH` order.
        path: PathBuf,
    },
    /// A file with the right name is there, but this user cannot execute it.
    NotExecutable {
        /// The first such file found, in `PATH` order.
        path: PathBuf,
    },
    /// Nothing with that name is on the search path.
    Missing,
}

impl Presence {
    /// Whether bx may generate configuration that depends on this tool.
    ///
    /// This is the seam between detection and [`Action`](crate::report::Action):
    /// a target whose tool is not usable plans as
    /// [`Action::Blocked`](crate::report::Action::Blocked).
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    /// The path bx found, if it found anything at all.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Present { path } | Self::NotExecutable { path } => Some(path),
            Self::Missing => None,
        }
    }
}

/// Look for `tool` along `path_var`.
///
/// An *absolute* `tool` is resolved directly, without consulting `path_var` —
/// the `command -v` rule, and the case that matters here, since the values bx
/// writes into shell fragments are absolute paths. A *relative* path is not
/// resolved: its meaning depends on the working directory, and
/// [`paths::render`](crate::paths::render) hands out absolute paths precisely so
/// that nothing downstream has to guess. Such a `tool` is [`Presence::Missing`].
///
/// Otherwise directories are tried in `path_var` order and the first executable
/// match wins. A match this user cannot execute does not stop the search: a
/// broken copy early on the path should not mask a working one later. If the
/// search ends without an executable match but did pass an inexecutable one,
/// that is reported instead of [`Presence::Missing`], because it is a different
/// problem with a different fix.
///
/// `tool` is an [`OsStr`], not a `str`: a Linux path is bytes, and a caller
/// holding a [`PathBuf`] should not have to risk `to_str().unwrap()` to ask this
/// question.
#[must_use]
pub fn locate(tool: impl AsRef<OsStr>, path_var: impl AsRef<OsStr>) -> Presence {
    let tool = tool.as_ref();

    if tool.as_encoded_bytes().contains(&b'/') {
        return if Path::new(tool).is_absolute() {
            classify(Path::new(tool))
        } else {
            Presence::Missing
        };
    }

    let mut first_unusable: Option<PathBuf> = None;
    for dir in std::env::split_paths(path_var.as_ref()) {
        // POSIX reads an empty `PATH` entry as the working directory. bx does
        // not: it would let a file in any directory the user happens to `cd`
        // into shadow a real tool.
        if dir.as_os_str().is_empty() {
            continue;
        }
        match classify(&dir.join(tool)) {
            found @ Presence::Present { .. } => return found,
            Presence::NotExecutable { path } => {
                first_unusable.get_or_insert(path);
            }
            Presence::Missing => {}
        }
    }

    first_unusable.map_or(Presence::Missing, |path| Presence::NotExecutable { path })
}

/// [`locate`], against the `PATH` this process inherited.
///
/// The edge of the module: everything below it is pure. An unset `PATH` is
/// treated as an empty one rather than an error, so an absolute `tool` still
/// resolves — it never needed a search path.
#[must_use]
pub fn locate_in_env(tool: impl AsRef<OsStr>) -> Presence {
    locate(tool, std::env::var_os("PATH").unwrap_or_default())
}

/// Classify one concrete candidate path.
fn classify(candidate: &Path) -> Presence {
    // `metadata` follows symlinks, which is what we want both ways round: a
    // symlink to a real binary is a find, and a dangling one is a miss.
    let Ok(meta) = std::fs::metadata(candidate) else {
        return Presence::Missing;
    };
    // A directory named `sccache` on the path is not sccache — and a directory
    // would pass the executability check below, since `x` means "traversable"
    // on one.
    if !meta.is_file() {
        return Presence::Missing;
    }
    let path = candidate.to_path_buf();
    // Not `mode & 0o111`: Linux consults exactly one permission triplet, the
    // first of owner/group/other that applies to the caller, so a file can
    // carry an execute bit that this user can never use. A root-owned 0700
    // binary is executable by nobody else, and answering `Present` for it would
    // produce config that breaks every build — the harm this module exists to
    // prevent. `access` is the same question the user's shell asks. bx is not
    // setuid, so its real and effective ids agree and the real-id check that
    // `access` performs is the right one.
    if rustix::fs::access(&path, Access::EXEC_OK).is_err() {
        return Presence::NotExecutable { path };
    }
    Presence::Present { path }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Nothing here touches `$HOME` or the process environment: every search
    /// path is built from tempdirs and passed in.
    fn bin(dir: &TempDir, name: &str, mode: u32) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn path_of(dirs: &[&TempDir]) -> OsString {
        std::env::join_paths(dirs.iter().map(|d| d.path())).unwrap()
    }

    #[test]
    fn an_absolute_path_to_an_executable_is_found() {
        let dir = TempDir::new().unwrap();
        let exe = bin(&dir, "sccache", 0o755);
        assert_eq!(locate(&exe, ""), Presence::Present { path: exe });
    }

    #[test]
    fn an_absolute_path_to_a_non_executable_file_is_reported_as_such() {
        let dir = TempDir::new().unwrap();
        let file = bin(&dir, "sccache", 0o644);
        assert_eq!(locate(&file, ""), Presence::NotExecutable { path: file });
    }

    #[test]
    fn an_absolute_path_that_does_not_exist_is_missing() {
        let dir = TempDir::new().unwrap();
        assert_eq!(locate(dir.path().join("sccache"), ""), Presence::Missing);
    }

    #[test]
    fn an_absolute_path_is_never_backed_by_a_path_search() {
        let on_path = TempDir::new().unwrap();
        let elsewhere = TempDir::new().unwrap();
        // `sccache` *is* on the search path, so an implementation that fell
        // back to searching after the direct miss would answer `Present`.
        bin(&on_path, "sccache", 0o755);
        assert_eq!(
            locate(elsewhere.path().join("sccache"), path_of(&[&on_path])),
            Presence::Missing
        );
    }

    #[test]
    fn a_relative_path_is_not_resolved_against_the_working_directory() {
        // cargo runs tests with the package root as the working directory, so
        // Cargo.toml is there. Its *mode* is deliberately irrelevant here: a
        // runner that copies the tree without preserving modes — cargo-mutants
        // does — must still get the same answer.
        assert!(
            Path::new("Cargo.toml").is_file(),
            "fixture: the working directory should be the package root"
        );
        // Resolving it would answer `NotExecutable`; the answer must not depend
        // on where the caller was standing.
        assert_eq!(locate("./Cargo.toml", ""), Presence::Missing);
    }

    #[test]
    fn a_bare_name_is_found_on_the_path() {
        let dir = TempDir::new().unwrap();
        let exe = bin(&dir, "sccache", 0o755);
        assert_eq!(
            locate("sccache", path_of(&[&dir])),
            Presence::Present { path: exe }
        );
    }

    #[test]
    fn later_directories_are_searched_when_earlier_ones_miss() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let exe = bin(&second, "sccache", 0o755);
        assert_eq!(
            locate("sccache", path_of(&[&first, &second])),
            Presence::Present { path: exe }
        );
    }

    #[test]
    fn the_first_directory_on_the_path_wins() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let shadowing = bin(&first, "sccache", 0o755);
        bin(&second, "sccache", 0o755);
        assert_eq!(
            locate("sccache", path_of(&[&first, &second])),
            Presence::Present { path: shadowing }
        );
    }

    #[test]
    fn a_directory_with_the_tools_name_is_not_a_match() {
        let dir = TempDir::new().unwrap();
        // A directory carries `x` for "traversable", so this is also the case
        // that would slip past the executability check on its own.
        fs::create_dir(dir.path().join("sccache")).unwrap();
        assert_eq!(locate("sccache", path_of(&[&dir])), Presence::Missing);
    }

    #[test]
    fn a_non_executable_earlier_on_the_path_does_not_mask_a_working_one() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        bin(&first, "sccache", 0o644);
        let working = bin(&second, "sccache", 0o755);
        assert_eq!(
            locate("sccache", path_of(&[&first, &second])),
            Presence::Present { path: working }
        );
    }

    #[test]
    fn a_non_executable_match_is_reported_when_nothing_better_is_found() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let broken = bin(&first, "sccache", 0o644);
        bin(&second, "sccache", 0o600);
        // The first one found is the one reported, matching the search order.
        assert_eq!(
            locate("sccache", path_of(&[&first, &second])),
            Presence::NotExecutable { path: broken }
        );
    }

    #[test]
    fn an_owner_executable_file_is_present() {
        let dir = TempDir::new().unwrap();
        let exe = bin(&dir, "sccache", 0o700);
        assert_eq!(
            locate("sccache", path_of(&[&dir])),
            Presence::Present { path: exe }
        );
    }

    #[test]
    fn a_file_with_no_execute_bit_anywhere_is_not_executable() {
        let dir = TempDir::new().unwrap();
        let file = bin(&dir, "sccache", 0o600);
        // Holds for every caller, root included: `X_OK` fails when no execute
        // bit is set at all.
        assert_eq!(
            locate("sccache", path_of(&[&dir])),
            Presence::NotExecutable { path: file }
        );
    }

    #[test]
    fn an_execute_bit_this_user_cannot_reach_does_not_count() {
        let dir = TempDir::new().unwrap();
        // 0o611: group and other may execute, the owner may not — and the owner
        // is this test process. Linux consults only the first triplet that
        // applies to the caller, so the file is unusable here even though
        // `mode & 0o111` is non-zero. That gap is the whole reason this module
        // asks `access` instead of reading the mode.
        let file = bin(&dir, "sccache", 0o611);
        let expected = if rustix::process::geteuid().is_root() {
            // root is the exception, and correctly so: `X_OK` succeeds for root
            // whenever any execute bit is set, which is what root can do.
            Presence::Present { path: file }
        } else {
            Presence::NotExecutable { path: file }
        };
        assert_eq!(locate("sccache", path_of(&[&dir])), expected);
    }

    #[test]
    fn an_empty_path_entry_is_not_the_working_directory() {
        assert!(
            Path::new("Cargo.toml").is_file(),
            "fixture: the working directory should be the package root"
        );
        // An implementation honouring the POSIX "an empty entry means `.`" rule
        // would find Cargo.toml and report it inexecutable.
        assert_eq!(locate("Cargo.toml", ":"), Presence::Missing);
    }

    #[test]
    fn an_empty_path_finds_nothing() {
        assert_eq!(locate("sccache", ""), Presence::Missing);
    }

    #[test]
    fn an_empty_tool_name_finds_nothing() {
        let dir = TempDir::new().unwrap();
        // `<dir>/` is a directory, not a file, so it is rejected like any other
        // non-regular candidate.
        assert_eq!(locate("", path_of(&[&dir])), Presence::Missing);
    }

    #[test]
    fn a_non_utf8_tool_name_is_accepted() {
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let name = OsStr::from_bytes(b"scc\xffache");
        let path = dir.path().join(name);
        fs::write(&path, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        // A `&str` parameter could not express this call at all.
        assert_eq!(locate(name, path_of(&[&dir])), Presence::Present { path });
    }

    #[test]
    fn a_symlink_to_an_executable_is_followed() {
        let target_dir = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        let real = bin(&target_dir, "sccache-real", 0o755);
        let link = dir.path().join("sccache");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // The link's own path is reported, not the target's: that is where the
        // tool is reachable from, which is what a caller writing a config value
        // needs.
        assert_eq!(
            locate("sccache", path_of(&[&dir])),
            Presence::Present { path: link }
        );
    }

    #[test]
    fn a_dangling_symlink_is_not_a_match() {
        let dir = TempDir::new().unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("sccache")).unwrap();
        assert_eq!(locate("sccache", path_of(&[&dir])), Presence::Missing);
    }

    #[test]
    fn only_a_present_tool_is_usable() {
        let path = PathBuf::from("/usr/bin/sccache");
        assert!(Presence::Present { path: path.clone() }.is_usable());
        assert!(!Presence::NotExecutable { path }.is_usable());
        assert!(!Presence::Missing.is_usable());
    }

    #[test]
    fn the_path_is_reported_for_everything_that_was_found() {
        let found = Path::new("/usr/bin/sccache");
        assert_eq!(
            Presence::Present {
                path: found.to_path_buf()
            }
            .path(),
            Some(found)
        );
        assert_eq!(
            Presence::NotExecutable {
                path: found.to_path_buf()
            }
            .path(),
            Some(found)
        );
        assert_eq!(Presence::Missing.path(), None);
    }

    #[test]
    fn locate_in_env_reads_the_process_path() {
        // Linux-only tool: `sh` is on the path of any machine that can run bx.
        assert!(locate_in_env("sh").is_usable());
        assert_eq!(
            locate_in_env("bx-a-tool-that-is-definitely-not-installed"),
            Presence::Missing
        );
    }
}
