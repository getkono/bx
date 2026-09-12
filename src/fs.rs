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
//! [`Mode`] is the crate's single permission type, and [`Kind`] is what a
//! destination turned out to be. Both live in [`mode`] and are re-exported
//! here, so `bx::fs::Mode` names the one file mode in the crate wherever it is
//! used — including from `config::target`, which re-exports it again under the
//! name architecture §4 fixed.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode as RawMode, OFlags};
use tempfile::NamedTempFile;

pub mod mode;

pub use mode::{Kind, Mode, ModeError};

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

/// Replace `path` with `bytes`, atomically, at `mode`.
///
/// After this returns, `path` holds either all of `bytes` or — if the write
/// failed — exactly what it held before. No temporary file is left behind in
/// either case, and the rename is durable: a power loss after the call cannot
/// resurrect the previous content.
///
/// The parent directory must already exist; this function creates no
/// directories, because the decision of what mode a new directory gets belongs
/// to the caller that knows what the directory is for.
///
/// # Errors
///
/// [`Error::NoParent`] if `path` has no parent component, and [`Error::Write`]
/// wrapping the first failing syscall otherwise.
pub fn write_atomically(path: &Path, bytes: &[u8], mode: Mode) -> Result<(), Error> {
    let dir = parent_of(path)?;
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
    fsync_dir(dir)
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

/// `fsync` a directory, so a rename inside it survives a power loss.
fn fsync_dir(dir: &Path) -> Result<(), Error> {
    let fail = |source: rustix::io::Errno| Error::Write {
        path: dir.to_path_buf(),
        source: source.into(),
    };
    let fd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        RawMode::empty(),
    )
    .map_err(fail)?;
    rustix::fs::fsync(&fd).map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    fn mode_of(path: &Path) -> Mode {
        Mode::from_bits(std::fs::metadata(path).expect("stat").permissions().mode())
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
