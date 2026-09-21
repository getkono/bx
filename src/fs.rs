//! Filesystem primitives: file modes, and the one atomic write in the crate.
//!
//! Every byte bx puts on disk goes through [`write_atomically`]. A write that
//! is interrupted — by a crash, a full disk, or a `SIGKILL` — must leave the
//! previous file exactly as it was, because an additive tool that half-rewrites
//! a file the user wrote has destroyed something. The sequence is the one
//! `CLAUDE.md` prescribes: a temporary file **in the destination directory**,
//! the content written and `fsync`ed, then `rename`, then an `fsync` of the
//! destination *directory* so the rename itself survives a power loss.
//!
//! The temporary file lives in the destination directory rather than in
//! `$TMPDIR` for two reasons: `rename` is only atomic within one filesystem,
//! and a `/tmp` on a different mount would turn the atomic rename into a
//! copy-then-delete with a visible half-written window.
//!
//! [`Mode`] is the permission type this crate's filesystem layer uses. It
//! carries the twelve meaningful bits of a POSIX mode and nothing else — no
//! file type, no `umask` interaction — so a mode read from a ledger entry means
//! the same thing as a mode written into one.
//!
//! It is **not** the crate's only permission type today:
//! [`crate::config::target::Mode`] is a second one, declared where the config
//! schema needed it first, and the two re-derive `0644` and `0755`
//! independently. See [`Mode`]'s own documentation for what the collapse needs
//! and who owns it.

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode as RawMode, OFlags};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

/// Everything that can go wrong writing a file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The destination has no parent directory, so there is nowhere to put the
    /// temporary file the atomic write needs.
    #[error("{} has no parent directory to write into", .0.display())]
    NoParent(PathBuf),
    /// A write, `fsync` or `rename` failed.
    #[error("writing {}: {source}", .path.display())]
    Write {
        /// The path being written, or the directory the temporary file was to
        /// be created in when the failure happened before the file existed.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// The path the failure is about.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::NoParent(path) | Self::Write { path, .. } => path,
        }
    }
}

/// A POSIX file mode: the permission and set-id bits, and nothing else.
///
/// Constructed from raw bits, compared by value, and rendered as four octal
/// digits so an error message reads the way `chmod` does. The file-type bits a
/// `stat` returns are deliberately not carried: bx sets permissions, it never
/// changes what a path *is*.
///
/// # This is the address, not yet the only definition
///
/// [`crate::config::target::Mode`] is the same concept, declared where the
/// config schema needed it first, and its own documentation names `bx::fs::Mode`
/// as the address its body is to be relocated to. This is that address. Both
/// types exist in this crate now, and both declare `0644` and `0755`
/// independently, so the two constants can drift.
///
/// The collapse cannot be finished from this file: `config::target::Mode`'s
/// field is private to its module, so the raw-`stat`-bits constructor the
/// ledger needs — and the [`Deserialize`] that masks through it — cannot be
/// written outside `config/target.rs`. The orphan rule is not what stops it;
/// the private field is. One `pub const fn from_bits` there is the whole of
/// what is missing, and the entry that owns `config/target.rs` is the one that
/// adds it. Until it does, nothing may re-export one of these as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Mode(u32);

impl<'de> Deserialize<'de> for Mode {
    /// Decoded through [`Mode::from_bits`], so a stored mode means the same
    /// thing as one read from a `stat`.
    ///
    /// Hand-written rather than derived, because a derived transparent
    /// `Deserialize` masks nothing: one flipped byte in `ledger.mpk` yields
    /// `Mode(0o100_644)`, which decodes cleanly — not `Damage::Malformed` —
    /// renders as `0644` and converts to `0644`, but compares unequal to the
    /// `Mode::from_bits(stat_bits)` a `plan` reads off the disk. A `plan`
    /// comparing the two then reports a permanent difference between two
    /// values it prints identically, and `apply` never converges: Invariant 3
    /// broken with no diagnostic that could explain it. The comparison is
    /// derived over the field, so the field is what has to be canonical.
    ///
    /// `paths::Portable` validates in its own `Deserialize` for the same
    /// reason; this masks rather than refuses, because [`Mode::from_bits`] is
    /// already the crate's answer to "what do the extra bits mean" — nothing.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self::from_bits)
    }
}

impl Mode {
    /// `0644` — the mode bx gives a generated file with no mode of its own.
    pub const DEFAULT_FILE: Self = Self(0o644);
    /// `0755` — the mode bx gives a directory it creates for a target.
    pub const DEFAULT_DIR: Self = Self(0o755);
    /// `0600` — owner-only. Every file bx writes inside the state directory.
    pub const PRIVATE_FILE: Self = Self(0o600);
    /// `0700` — owner-only. The state directory and everything under it.
    pub const PRIVATE_DIR: Self = Self(0o700);

    /// A mode from raw bits. Anything above the twelve permission bits is
    /// discarded, so a `stat` result can be handed over directly.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & 0o7777)
    }

    /// The twelve permission bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0 & 0o7777
    }

    /// Whether any group or other bit is set.
    ///
    /// The question the state directory asks before tightening itself: a
    /// directory holding prior copies of the user's private files must not be
    /// readable by anyone else.
    #[must_use]
    pub const fn is_shared(self) -> bool {
        self.bits() & 0o077 != 0
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04o}", self.bits())
    }
}

impl From<crate::config::target::Mode> for Mode {
    /// The config schema's mode, as the mode bx writes with.
    ///
    /// The one direction that is expressible from here, and the one the pipeline
    /// needs: a target declares a mode, and the writer and the ledger record it.
    fn from(mode: crate::config::target::Mode) -> Self {
        Self::from_bits(mode.bits())
    }
}

impl From<Mode> for RawMode {
    fn from(mode: Mode) -> Self {
        Self::from_bits_truncate(mode.bits())
    }
}

/// Replace `path` with `bytes`, atomically, at `mode`.
///
/// After this returns `Ok`, `path` holds all of `bytes`, and the rename is
/// durable: a power loss after the call cannot resurrect the previous content.
/// After it returns an error, `path` holds exactly what it held before — with
/// one exception. The destination directory is opened before the temporary
/// file is created, so failing to open it fails the write with nothing
/// changed; but its `fsync` is the last step, after the rename, and a failing
/// directory `fsync` is returned with `path` already holding `bytes`, their
/// durability not established. No temporary file is left behind in any case.
///
/// The parent directory must already exist; this function creates no
/// directories, because the decision of what mode a new directory gets belongs
/// to the caller that knows what the directory is for.
///
/// # What the tests here do and do not establish
///
/// The *observable* half is tested: the temporary file is created in the
/// destination directory, a failed write leaves the previous file and no
/// temporary behind, and a successful one leaves only the destination.
///
/// The durability half — that `sync_all` happens before the `rename` and that
/// the directory `fsync` happens after it — is **not** pinned by any test. Both
/// calls could be deleted, or reordered after `persist`, and the suite would
/// still pass, because their effect is only visible to a reader that survives a
/// power loss. Closing it needs a harness that observes the syscalls rather than
/// their results: an `LD_PRELOAD` shim, `strace -e` over a child, or a fault
/// injector between the write and the rename. Until then the ordering is held by
/// this comment and by review, and the crash-safety claim for this function is
/// asserted rather than established.
///
/// # Errors
///
/// [`Error::NoParent`] if `path` has no parent component, and [`Error::Write`]
/// wrapping the first failing syscall otherwise.
pub fn write_atomically(path: &Path, bytes: &[u8], mode: Mode) -> Result<(), Error> {
    let dir = parent_of(path)?;
    // Opened before anything is created, so a directory that cannot be opened
    // for its fsync fails the write while the previous file is still in place.
    let dir_fd = open_dir(dir)?;
    let mut temp = new_temp(dir)?;

    let write = |source| Error::Write {
        path: path.to_path_buf(),
        source,
    };
    temp.write_all(bytes).map_err(write)?;
    // Order matters: the mode is set *before* the fsync, so the fsync covers
    // the metadata as well as the content. A file that survives a crash with
    // the wrong permissions is still a defect.
    rustix::fs::fchmod(temp.as_file(), mode.into()).map_err(|e| write(e.into()))?;
    temp.as_file().sync_all().map_err(write)?;
    temp.persist(path).map_err(|e| write(e.error))?;
    rustix::fs::fsync(&dir_fd).map_err(|source| Error::Write {
        path: dir.to_path_buf(),
        source: source.into(),
    })
}

/// The directory `path` will be written into.
fn parent_of(path: &Path) -> Result<&Path, Error> {
    match path.parent() {
        // A bare file name has an empty parent, which names the working
        // directory; `NamedTempFile::new_in("")` would fail on it.
        Some(dir) if dir.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(dir) => Ok(dir),
        None => Err(Error::NoParent(path.to_path_buf())),
    }
}

/// A temporary file **in `dir`**, which is what makes the later rename atomic.
fn new_temp(dir: &Path) -> Result<NamedTempFile, Error> {
    NamedTempFile::new_in(dir).map_err(|source| Error::Write {
        path: dir.to_path_buf(),
        source,
    })
}

/// Open `dir` for the `fsync` that makes a rename inside it survive a power
/// loss.
fn open_dir(dir: &Path) -> Result<OwnedFd, Error> {
    rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        RawMode::empty(),
    )
    .map_err(|source| Error::Write {
        path: dir.to_path_buf(),
        source: source.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    fn mode_of(path: &Path) -> Mode {
        Mode::from_bits(std::fs::metadata(path).expect("stat").permissions().mode())
    }

    #[test]
    fn a_mode_keeps_only_the_permission_bits() {
        // 0o100644 is what `stat` reports for a regular file at 0644.
        assert_eq!(Mode::from_bits(0o100_644), Mode::DEFAULT_FILE);
        assert_eq!(Mode::DEFAULT_FILE.bits(), 0o644);
    }

    #[test]
    fn a_mode_renders_as_four_octal_digits() {
        assert_eq!(Mode::PRIVATE_FILE.to_string(), "0600");
        assert_eq!(Mode::DEFAULT_DIR.to_string(), "0755");
        assert_eq!(Mode::from_bits(0o7).to_string(), "0007");
    }

    #[test]
    fn a_mode_knows_whether_anyone_else_can_reach_it() {
        assert!(!Mode::PRIVATE_DIR.is_shared());
        assert!(!Mode::PRIVATE_FILE.is_shared());
        assert!(Mode::DEFAULT_DIR.is_shared());
        assert!(Mode::from_bits(0o710).is_shared());
    }

    #[test]
    fn a_declared_mode_becomes_the_mode_bx_writes() {
        let declared = crate::config::target::Mode::parse_octal("0600").expect("a valid mode");
        assert_eq!(Mode::from(declared), Mode::PRIVATE_FILE);
        assert_eq!(
            Mode::from(crate::config::target::Mode::DEFAULT_DIR),
            Mode::DEFAULT_DIR,
        );
    }

    #[test]
    fn a_mode_round_trips_through_messagepack() {
        let bytes = rmp_serde::to_vec_named(&Mode::PRIVATE_FILE).expect("encode");
        let back: Mode = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(back, Mode::PRIVATE_FILE);
    }

    #[test]
    fn a_decoded_mode_carries_only_the_permission_bits() {
        // r4 round 1 (D4, COV4): the derived transparent `Deserialize` masked
        // nothing, and the round-trip above was tested only with a canonical
        // value. One flipped byte in `ledger.mpk` gave a `Mode` that renders,
        // converts and chmods as `0644` but compares unequal to the `0644` a
        // `plan` reads off the disk — two values printed identically that
        // never converge.
        let wire = rmp_serde::to_vec_named(&0o100_644_u32).expect("encode");
        let back: Mode = rmp_serde::from_slice(&wire).expect("decode");
        assert_eq!(back, Mode::DEFAULT_FILE, "equal to the mode a stat gives");
        assert_eq!(back.bits(), 0o644);
        assert_eq!(back.to_string(), "0644");

        // Every bit `from_bits` keeps survives the round trip, set-id and
        // sticky included: `0o7777`, not `0o777`.
        for bits in [0o4755, 0o2755, 0o1777, 0o7777] {
            let mode = Mode::from_bits(bits);
            let wire = rmp_serde::to_vec_named(&mode).expect("encode");
            assert_eq!(
                rmp_serde::from_slice::<Mode>(&wire).expect("decode"),
                mode,
                "{bits:04o}",
            );
        }
    }

    #[test]
    fn the_set_id_and_sticky_bits_reach_the_chmod() {
        // r4 round 1 (COV4): every test and every call site used 0644, 0755,
        // 0600 or 0700, so `from_bits_truncate` dropping `0o7000` in the
        // conversion `fchmod` uses would have been invisible — precisely the
        // four bits the `0o7777` mask in `from_bits` exists to preserve.
        for bits in [0o4755, 0o2755, 0o1777, 0o7777] {
            assert_eq!(
                RawMode::from(Mode::from_bits(bits)).bits(),
                bits,
                "{bits:04o}",
            );
        }
    }

    #[test]
    fn a_write_creates_the_file_at_the_requested_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f");
        write_atomically(&path, b"hello", Mode::PRIVATE_FILE).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"hello");
        assert_eq!(mode_of(&path), Mode::PRIVATE_FILE);
    }

    #[test]
    fn a_write_over_an_existing_file_replaces_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f");
        std::fs::write(&path, b"before").expect("seed");
        write_atomically(&path, b"after", Mode::DEFAULT_FILE).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"after");
        assert_eq!(mode_of(&path), Mode::DEFAULT_FILE);
    }

    #[test]
    fn a_write_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_atomically(&dir.path().join("f"), b"x", Mode::DEFAULT_FILE).expect("write");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("f")]);
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A directory cannot be replaced by a rename from a regular file, so
        // `persist` fails after the temporary file has been written in full.
        let path = dir.path().join("f");
        std::fs::create_dir(&path).expect("occupy");
        let err = write_atomically(&path, b"x", Mode::DEFAULT_FILE).expect_err("must fail");
        assert_eq!(err.path(), path);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("f")]);
    }

    #[test]
    fn a_directory_that_cannot_be_opened_fails_the_write_before_the_rename() {
        // r3 round 1 (O2): the directory was opened for its fsync only after
        // the rename, so a directory that permits creating and renaming a file
        // but not opening it returned an error with the new bytes in place.
        if rustix::process::geteuid().is_root() {
            // Mode bits deny nothing to root, so the condition cannot be staged.
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("d");
        std::fs::create_dir(&root).expect("root");
        let path = root.join("f");
        std::fs::write(&path, b"before").expect("seed");
        // Writable and searchable, so a temporary file could be created and
        // renamed; not readable, so it cannot be opened `O_RDONLY`.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300)).expect("chmod");
        let result = write_atomically(&path, b"after", Mode::DEFAULT_FILE);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("restore");

        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"before",
            "a failed write leaves the previous file exactly as it was",
        );
        let err = result.expect_err("an unopenable directory fails the write");
        assert!(
            matches!(&err, Error::Write { path: at, source }
                if *at == root && source.kind() == std::io::ErrorKind::PermissionDenied),
            "got {err}",
        );
        let names: Vec<_> = std::fs::read_dir(&root)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("f")]);
    }

    #[test]
    fn a_directory_that_opens_but_refuses_the_temporary_file_fails_the_write_naming_it() {
        // r3 round 2b (P7R4-COV1): every earlier failure was before the
        // directory opened or after the temporary file existed, so the
        // temporary file's own creation failing was never reached.
        if rustix::process::geteuid().is_root() {
            // Mode bits deny nothing to root, so the condition cannot be staged.
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("d");
        std::fs::create_dir(&root).expect("root");
        let path = root.join("f");
        std::fs::write(&path, b"before").expect("seed");
        // Readable and searchable, so it opens `O_RDONLY | O_DIRECTORY`; not
        // writable, so no temporary file can be created in it.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        let result = write_atomically(&path, b"after", Mode::DEFAULT_FILE);
        let names: Vec<_> = std::fs::read_dir(&root)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("restore");

        let err = result.expect_err("a directory refusing the temporary file fails the write");
        assert!(
            matches!(&err, Error::Write { path: at, source }
                if *at == root && source.kind() == std::io::ErrorKind::PermissionDenied),
            "got {err}",
        );
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"before",
            "a failed write leaves the previous file exactly as it was",
        );
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("f")],
            "no temporary file"
        );
    }

    #[test]
    fn the_destination_directory_is_opened_as_a_directory_and_closed_on_exec() {
        // r3 round 1, mutation run: dropping `O_DIRECTORY`, or `O_DIRECTORY`
        // and `O_CLOEXEC`, from the directory open left every test green. A
        // file opens without `O_DIRECTORY`, and a descriptor without
        // `O_CLOEXEC` is inherited by a child another thread spawns while the
        // write is under way.
        let dir = tempfile::tempdir().expect("tempdir");
        let fd = open_dir(dir.path()).expect("a directory opens");
        let flags = rustix::io::fcntl_getfd(&fd).expect("F_GETFD");
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC), "{flags:?}");

        let file = dir.path().join("f");
        std::fs::write(&file, b"x").expect("seed");
        let err = open_dir(&file).expect_err("a file is not a directory");
        assert!(
            matches!(&err, Error::Write { path, source }
                if *path == file
                    && source.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error())),
            "got {err}",
        );
    }

    #[test]
    fn the_temporary_file_is_created_in_the_destination_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let temp = new_temp(dir.path()).expect("temp");
        assert_eq!(temp.path().parent(), Some(dir.path()));
    }

    #[test]
    fn a_write_into_a_missing_directory_names_that_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope");
        let err =
            write_atomically(&missing.join("f"), b"x", Mode::DEFAULT_FILE).expect_err("must fail");
        assert_eq!(err.path(), missing);
    }

    #[test]
    fn a_path_with_no_parent_is_refused() {
        let err =
            write_atomically(Path::new("/"), b"x", Mode::DEFAULT_FILE).expect_err("must fail");
        assert!(matches!(err, Error::NoParent(_)));
    }

    #[test]
    fn a_bare_file_name_writes_into_the_working_directory() {
        assert_eq!(parent_of(Path::new("f")).expect("parent"), Path::new("."));
    }
}
