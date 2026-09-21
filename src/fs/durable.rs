//! The durability calls, in one place, where a test can see them happen.
//!
//! An `fsync` has no effect a test can read back: its only witness is a reader
//! that survives a power loss. Deleting one leaves every assertion about bytes,
//! modes and names still true, so a suite that only inspects results cannot tell
//! a durable write from one that merely looks finished. The calls are therefore
//! routed through the functions here, and each one notes itself — *inside* the
//! function, next to the syscall — to a per-thread recorder that exists only in
//! the test build. A test runs the code under `recording` and asserts the
//! sequence it gets back, including where the `fsync`s fall relative to the
//! `rename`.
//!
//! In the product build the note is compiled out: there is no recorder, no
//! branch and no allocation, and each function is the syscall and nothing else.
//! That is `cfg(test)`, not a feature gate — no configuration of the binary
//! differs from another.
//!
//! What this establishes and what it does not: it pins that the calls are
//! **made**, on which path, and in what order. It does not observe the kernel,
//! so each function's own one-line body — `sync_all`, `fsync`, `rename` — is
//! still held by review. That is a much smaller thing to trust than "every call
//! site remembered to sync", and it is the part a mutation of a caller cannot
//! reach.
//!
//! Every durability call bx makes belongs here, not only the writer's. A later
//! write-ahead journal appends and `fsync`s in place; routing that `sync_all`
//! through [`sync_file`] makes its ordering against the rename it guards
//! assertable by the same `recording` call.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use rustix::fs::{Mode as RawMode, OFlags};
use tempfile::NamedTempFile;

/// `fsync` an open file's data and metadata.
///
/// `path` names the file for the recorder only; the call itself uses `file`.
pub(crate) fn sync_file(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(test)]
    probe::note(Event::SyncFile(path.to_path_buf()));
    #[cfg(not(test))]
    let _ = path;
    file.sync_all()
}

/// A directory opened so that a rename or unlink inside it can be made durable.
///
/// Opened **before** the operation it will make durable, not after. Opening
/// a directory needs read permission on it, and renaming into it does not, so
/// in a `0300` directory an open-after-rename fails with the new content
/// already in place — an error returned from a write that did happen. Opening
/// first fails while the destination is still untouched.
#[derive(Debug)]
pub(crate) struct Dir {
    fd: OwnedFd,
    /// The directory, as it was named — for the recorder only, so it does not
    /// exist in the product build.
    #[cfg(test)]
    path: PathBuf,
}

impl Dir {
    /// Open `path` read-only as a directory.
    ///
    /// Both `|` here are surviving mutants under `cargo mutants`, and both are
    /// equivalent by arithmetic rather than by anything a test could arrange.
    /// `RDONLY` is `0`, the identity element of `|` and of `^` alike, so
    /// `RDONLY | x` and `RDONLY ^ x` are the same value for every `x`;
    /// `DIRECTORY` and `CLOEXEC` are distinct single-bit flags sharing no bit,
    /// so `|` and `^` agree on them too. Every mutant hands `open` the same
    /// bitmask. There is no behaviour to distinguish, and the flags themselves
    /// *are* pinned — dropping either fails
    /// `the_destination_directory_is_opened_as_a_directory_and_closed_on_exec`.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            RawMode::empty(),
        )?;
        #[cfg(test)]
        probe::note(Event::OpenDir(path.to_path_buf()));
        Ok(Self {
            fd,
            #[cfg(test)]
            path: path.to_path_buf(),
        })
    }

    /// `fsync` the directory, so the entries changed inside it survive a power
    /// loss.
    pub(crate) fn sync(&self) -> io::Result<()> {
        #[cfg(test)]
        probe::note(Event::SyncDir(self.path.clone()));
        rustix::fs::fsync(&self.fd).map_err(io::Error::from)
    }
}

/// `rename` a temporary file onto `dest`, replacing whatever is there.
///
/// # Errors
///
/// The failed `rename`. The temporary file is dropped with the error — see
/// [`crate::fs::atomic::Staged`] for what that is worth, because the unlink
/// needs a permission on the destination directory that a failing rename may
/// mean it no longer grants.
pub(crate) fn rename(temp: NamedTempFile, dest: &Path) -> Result<(), tempfile::PersistError> {
    #[cfg(test)]
    let from = temp.path().to_path_buf();
    temp.persist(dest)?;
    #[cfg(test)]
    probe::note(Event::Rename {
        from,
        to: dest.to_path_buf(),
    });
    Ok(())
}

/// One durability call, as the recorder saw it.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// [`sync_file`] on the file at this path.
    SyncFile(PathBuf),
    /// [`Dir::open`] on this directory.
    OpenDir(PathBuf),
    /// [`Dir::sync`] on this directory.
    SyncDir(PathBuf),
    /// A successful [`rename`].
    Rename {
        /// The temporary file.
        from: PathBuf,
        /// The destination it replaced.
        to: PathBuf,
    },
}

/// Run `f` and return what it returned, with every durability call it made on
/// this thread, in order.
///
/// Per thread, so tests running concurrently in one process cannot see each
/// other's calls. A call made outside any `recording` is discarded.
#[cfg(test)]
pub(crate) fn recording<R>(f: impl FnOnce() -> R) -> (R, Vec<Event>) {
    probe::start();
    // Stop on unwind too, so a panicking test leaves the thread clean.
    struct Stop;
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = probe::stop();
        }
    }
    let guard = Stop;
    let result = f();
    let events = probe::stop();
    std::mem::forget(guard);
    (result, events)
}

#[cfg(test)]
mod probe {
    use std::cell::RefCell;

    use super::Event;

    thread_local! {
        static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
    }

    pub(super) fn note(event: Event) {
        EVENTS.with_borrow_mut(|events| {
            if let Some(events) = events {
                events.push(event);
            }
        });
    }

    pub(super) fn start() {
        EVENTS.with_borrow_mut(|events| *events = Some(Vec::new()));
    }

    pub(super) fn stop() -> Vec<Event> {
        EVENTS.with_borrow_mut(Option::take).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;

    #[test]
    fn nothing_is_recorded_outside_a_recording() {
        let dir = tempfile::tempdir().expect("tempdir");
        Dir::open(dir.path()).expect("open").sync().expect("sync");

        let ((), events) = recording(|| {});
        assert_eq!(events, [], "a call made before recording began is not kept");
    }

    #[test]
    fn each_call_is_recorded_in_the_order_it_was_made() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("f");

        let (result, events) = recording(|| -> io::Result<PathBuf> {
            let mut temp = NamedTempFile::new_in(dir.path())?;
            temp.write_all(b"x")?;
            let temp_path = temp.path().to_path_buf();
            sync_file(temp.as_file(), &temp_path)?;
            let handle = Dir::open(dir.path())?;
            rename(temp, &dest).map_err(|e| e.error)?;
            handle.sync()?;
            Ok(temp_path)
        });
        let temp_path = result.expect("the sequence");

        assert_eq!(
            events,
            [
                Event::SyncFile(temp_path.clone()),
                Event::OpenDir(dir.path().to_path_buf()),
                Event::Rename {
                    from: temp_path,
                    to: dest.clone(),
                },
                Event::SyncDir(dir.path().to_path_buf()),
            ],
        );
        assert_eq!(std::fs::read(&dest).expect("read"), b"x");
    }

    #[test]
    fn a_failed_call_records_no_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (result, events) = recording(|| {
            let missing = Dir::open(&dir.path().join("missing")).map(|_| ());
            let temp = NamedTempFile::new_in(dir.path()).expect("temp");
            let onto_a_dir = rename(temp, dir.path()).map_err(|e| e.error);
            (missing, onto_a_dir)
        });
        assert!(result.0.is_err());
        assert!(result.1.is_err());
        assert_eq!(
            events,
            [],
            "neither an open nor a rename that failed happened"
        );
    }

    #[test]
    fn the_destination_directory_is_opened_as_a_directory_and_closed_on_exec() {
        // Dropping `O_DIRECTORY`, or `O_DIRECTORY` and `O_CLOEXEC`, from the
        // directory open left every other test green. A file opens without
        // `O_DIRECTORY`, and a descriptor without `O_CLOEXEC` is inherited by a
        // child another thread spawns while the write is under way.
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = Dir::open(dir.path()).expect("a directory opens");
        let flags = rustix::io::fcntl_getfd(&handle.fd).expect("F_GETFD");
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC), "{flags:?}");

        let file = dir.path().join("f");
        std::fs::write(&file, b"x").expect("seed");
        let err = Dir::open(&file).expect_err("a file is not a directory");
        assert_eq!(
            err.raw_os_error(),
            Some(rustix::io::Errno::NOTDIR.raw_os_error()),
            "got {err}",
        );
    }

    #[test]
    fn a_panic_inside_a_recording_leaves_the_thread_clean() {
        let caught = std::panic::catch_unwind(|| {
            recording(|| panic!("inside"));
        });
        assert!(caught.is_err());

        let dir = tempfile::tempdir().expect("tempdir");
        Dir::open(dir.path()).expect("open").sync().expect("sync");
        let ((), events) = recording(|| {});
        assert_eq!(events, []);
    }
}
