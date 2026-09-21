//! The advisory lock over the whole state directory.
//!
//! Two mutating `bx` processes must not interleave: one would record a ledger
//! entry the other has already replaced, and an interrupted `apply` would become
//! unrecoverable. A single `flock(2)` on `<state>/lock` prevents it.
//!
//! `flock`, not `fcntl` record locks. A POSIX record lock is associated with the
//! *process* and is released when **any** descriptor on the file is closed
//! anywhere in it — a trap for a tool that opens many files under the directory
//! it just locked. `flock` is associated with the open file description: it is
//! released when the last descriptor of that description closes, and the kernel
//! releases it when the process dies, which is exactly the crash behaviour bx
//! needs.
//!
//! Acquisition never blocks. A CLI that hangs with no output is worse than one
//! that says who holds the lock, so a refused exclusive acquisition reports the
//! holder's pid and program, read from the lock file's body.

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, FlockOperation, Mode as RawMode, OFlags};
use rustix::io::Errno;

use super::Error;
use super::dir::{StateDir, ensure_dir};
use crate::fs::Mode;

/// How much of the lock file's body is read when reporting a holder.
const BODY: usize = 256;

/// Whoever holds the lock, as far as the lock file's body says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    /// The holder's process id, or `0` when the body could not be read.
    pub pid: i32,
    /// The holder's program name, or a placeholder.
    pub program: String,
}

impl Holder {
    /// The holder bx reports when the lock file says nothing usable.
    ///
    /// An empty or unreadable body is not an error: the kernel is the authority
    /// on who holds the lock, and the body is only a courtesy. This is the
    /// honest answer whenever the holder is a *reader* — readers write no
    /// identity, because several of them can hold the lock at once and there is
    /// no single body for them to share — and whenever a writer released the
    /// lock cleanly, since [`ExclusiveLock::drop`] truncates the body before
    /// unlocking precisely so that no released pid is ever reported as current.
    ///
    /// A pid that *is* reported can still be stale in one case: a writer killed
    /// outright leaves its line behind, because the kernel releases the lock and
    /// nothing runs in the dead process to clear it. Naming a pid that has
    /// just died is a smaller error than naming one that released normally
    /// minutes ago, and both are bounded by the kernel remaining the authority.
    fn unknown() -> Self {
        Self {
            pid: 0,
            program: "another bx process".to_string(),
        }
    }

    /// Parse the one line [`identify`] writes.
    fn parse(body: &str) -> Self {
        let mut parts = body.split_whitespace();
        match (parts.next().and_then(|p| p.parse().ok()), parts.next()) {
            (Some(pid), Some(program)) => Self {
                pid,
                program: program.to_string(),
            },
            _ => Self::unknown(),
        }
    }
}

impl fmt::Display for Holder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pid == 0 {
            f.write_str(&self.program)
        } else {
            write!(f, "pid {} ({})", self.pid, self.program)
        }
    }
}

/// An exclusive lock on the state directory, held for as long as this lives.
///
/// Only one of these exists across all processes at a time. Holding one is the
/// precondition for every write to the state directory, and
/// [`super::Ledger::open`] demands a reference to one so that `&mut Ledger` is
/// itself the proof the lock was taken.
///
/// # One thread of control at a time
///
/// Each guard locks its own open file description, so it excludes every other
/// guard: another process's, and a second one this process acquires. It cannot
/// exclude two threads sharing *this* guard. Both would hold the proof, both
/// could judge the same damaged file, and the second's move aside would find
/// the name already gone and report a failure that did not happen. So the
/// guard is not [`Sync`]: a `&ExclusiveLock` cannot reach another thread, and
/// exclusion holds per thread of control by type. It is still [`Send`], so the
/// guard itself can move to a thread, which then holds it alone.
///
/// ```compile_fail
/// fn shared_between_threads<T: Sync>() {}
/// shared_between_threads::<bx::state::ExclusiveLock>();
/// ```
///
/// ```
/// fn moved_to_a_thread<T: Send>() {}
/// moved_to_a_thread::<bx::state::ExclusiveLock>();
/// ```
#[derive(Debug)]
pub struct ExclusiveLock {
    /// Kept open for the lock's lifetime; closing it releases the lock.
    fd: OwnedFd,
    /// The lock file this locked: its path, for error messages, and its
    /// identity, for [`ExclusiveLock::guards`].
    held: HeldLock,
    /// Makes the guard `!Sync`, so it cannot be shared between threads: see
    /// "One thread of control at a time" above.
    not_sync: PhantomData<Cell<()>>,
}

/// The lock file an [`ExclusiveLock`] locked: its path, and its device and
/// inode as they were when it was locked.
///
/// Kept by a [`super::Ledger`], which does not keep the guard, so every write
/// through it can ask again whether the lock file it was opened under is still
/// the one at the lock path. An outside `mv` or `rm` of a held lock file lets a
/// second bx create and lock a new file at the same path, and the first guard
/// then excludes nobody.
#[derive(Debug, Clone)]
pub(crate) struct HeldLock {
    /// The lock file's path.
    path: PathBuf,
    /// Its `stat` when it was locked. Only `st_dev` and `st_ino` are compared.
    stat: rustix::fs::Stat,
}

impl HeldLock {
    /// The lock file's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this is still the lock file of the state directory at `root`.
    ///
    /// Decided by identity — the device and inode that were locked against
    /// those of `root`'s lock file now — never by spelling. A directory reached
    /// through a symlink is still recognised, and a lock file replaced since it
    /// was locked, or one that is not there, is not.
    pub(crate) fn guards(&self, root: &Path) -> bool {
        let Ok(there) = rustix::fs::lstat(StateDir::new(root.to_path_buf()).lock()) else {
            return false;
        };
        self.stat.st_dev == there.st_dev && self.stat.st_ino == there.st_ino
    }
}

/// A shared lock on the state directory, held for as long as this lives.
///
/// Readers take one so that they can *notice* an apply in progress, not because
/// they need it for correctness: every state file is replaced by `rename`, so a
/// reader sees a whole file or the previous whole file, never a torn one. A
/// `plan` printed while an `apply` runs is stale the moment it is printed, and
/// printing it without saying so is the kind of surprise bx exists to prevent.
#[derive(Debug)]
pub struct SharedLock {
    /// Kept open for the lock's lifetime; closing it releases the lock.
    fd: OwnedFd,
    /// The lock file, for error messages.
    path: PathBuf,
}

impl ExclusiveLock {
    /// Take the exclusive lock, or report who has it.
    ///
    /// # Errors
    ///
    /// [`Error::Locked`], naming the holder, when another process holds either
    /// lock. [`Error::CreateDir`] or [`Error::Lock`] if the lock file cannot be
    /// created or locked.
    pub fn acquire(dir: &StateDir) -> Result<Self, Error> {
        let path = dir.lock();
        let (fd, stat) = open_lock_file(dir, &path)?;
        take(&fd, &path, FlockOperation::NonBlockingLockExclusive)?;
        identify(&fd);
        Ok(Self {
            fd,
            held: HeldLock { path, stat },
            not_sync: PhantomData,
        })
    }

    /// Take the exclusive lock, or return `None` if it is held.
    ///
    /// # Errors
    ///
    /// As [`ExclusiveLock::acquire`], minus [`Error::Locked`].
    pub fn try_acquire(dir: &StateDir) -> Result<Option<Self>, Error> {
        optional(Self::acquire(dir))
    }

    /// The lock file this guard holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.held.path
    }

    /// The lock file this guard locked: what decides, by identity, whether
    /// this guard is the lock of a given state directory — see
    /// [`HeldLock::guards`] — and what a caller keeps to check that again after
    /// handing the guard back.
    pub(crate) fn held(&self) -> &HeldLock {
        &self.held
    }
}

impl SharedLock {
    /// Take a shared lock, or report who holds the exclusive one.
    ///
    /// # Errors
    ///
    /// As [`ExclusiveLock::acquire`].
    pub fn acquire(dir: &StateDir) -> Result<Self, Error> {
        let path = dir.lock();
        let (fd, _) = open_lock_file(dir, &path)?;
        take(&fd, &path, FlockOperation::NonBlockingLockShared)?;
        Ok(Self { fd, path })
    }

    /// Take a shared lock, or return `None` while an apply holds the directory.
    ///
    /// This is the call `plan` and `doctor` make: `None` means "an apply is in
    /// progress", which they report and then carry on read-only.
    ///
    /// # Errors
    ///
    /// As [`ExclusiveLock::acquire`], minus [`Error::Locked`].
    pub fn try_acquire(dir: &StateDir) -> Result<Option<Self>, Error> {
        optional(Self::acquire(dir))
    }

    /// The lock file this guard holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Turn a refusal into `None`, keeping every other failure.
fn optional<T>(result: Result<T, Error>) -> Result<Option<T>, Error> {
    match result {
        Ok(lock) => Ok(Some(lock)),
        Err(Error::Locked { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Open — creating if needed — the lock file at `0600`.
///
/// The body of this file is truncated on every exclusive acquisition, so what
/// is opened must be the file bx created and never a file the user wrote
/// (Invariant 1). It is opened with `O_NOFOLLOW`, so a symlink at `lock` — to
/// `~/.bashrc`, say, or to a path that does not exist yet — is refused rather
/// than followed and truncated or created. The descriptor must then be a
/// regular file with exactly one link, so a hard link to a user's file, a FIFO
/// or a device is refused too.
///
/// A lock file whose mode is anything but `0600` is set to it — not only one
/// that is readable beyond its owner. The `0600` argument to `open` is masked
/// by the process `umask`, so a `umask` with owner bits in it (`0277`, say)
/// leaves the file this call just created at `0400`. Run 1 still succeeds,
/// because `open` skips the permission check for a file it creates; every run
/// after it fails `Permission denied` on a file bx owns and could repair, and
/// `is_shared` cannot see it, because `0400` shares nothing. Repairing on
/// inequality rather than on sharing is what makes the check able to notice.
///
/// Returns the descriptor and its `stat`, whose device and inode identify the
/// file locked through it.
fn open_lock_file(dir: &StateDir, path: &Path) -> Result<(OwnedFd, rustix::fs::Stat), Error> {
    ensure_dir(dir.root(), Mode::PRIVATE_DIR)?;
    let failed = |source: Errno| Error::Lock {
        path: path.to_path_buf(),
        source: source.into(),
    };
    let not_a_file = || Error::LockNotAFile {
        path: path.to_path_buf(),
    };
    let fd = match rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::PRIVATE_FILE.into(),
    ) {
        Ok(fd) => fd,
        // `ELOOP`: a symlink, refused by `O_NOFOLLOW`. `EISDIR`: a directory,
        // which `O_RDWR` cannot open. Either is something to move aside.
        Err(Errno::LOOP | Errno::ISDIR) => return Err(not_a_file()),
        Err(source) => return Err(failed(source)),
    };
    let stat = rustix::fs::fstat(&fd).map_err(failed)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err(not_a_file());
    }
    let found = Mode::from_bits(stat.st_mode);
    if found != Mode::PRIVATE_FILE {
        tracing::warn!(
            path = %path.display(),
            found = %found,
            set_to = %Mode::PRIVATE_FILE,
            "the bx lock file was not 0600; setting it",
        );
        rustix::fs::fchmod(&fd, Mode::PRIVATE_FILE.into()).map_err(failed)?;
    }
    Ok((fd, stat))
}

/// Attempt one non-blocking `flock`.
fn take(fd: &OwnedFd, path: &Path, operation: FlockOperation) -> Result<(), Error> {
    match rustix::fs::flock(fd, operation) {
        Ok(()) => Ok(()),
        Err(Errno::WOULDBLOCK) => Err(Error::Locked {
            holder: read_holder(path),
            path: path.to_path_buf(),
        }),
        Err(source) => Err(Error::Lock {
            path: path.to_path_buf(),
            source: source.into(),
        }),
    }
}

/// Write this process's identity into the lock file's body.
///
/// Plain text, one line, `"<pid> <program>\n"` — a human-facing diagnostic to be
/// read with `cat` during an incident, so not MessagePack. Best effort: failing
/// to write it costs a better error message and nothing else, and the lock is
/// already held by the time it runs.
fn identify(fd: &OwnedFd) {
    let program = std::env::args()
        .next()
        .and_then(|arg0| {
            Path::new(&arg0)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "bx".to_string());
    let line = format!("{} {program}\n", rustix::process::getpid().as_raw_nonzero());
    let _ = rustix::fs::ftruncate(fd, 0);
    let _ = rustix::io::pwrite(fd, line.as_bytes(), 0);
}

/// Read the holder's identity out of the lock file, best effort.
fn read_holder(path: &Path) -> Holder {
    // Opened separately rather than through the refused descriptor: this runs
    // on the error path, where clarity beats saving one `open`.
    //
    // `O_NONBLOCK` because opening by path reaches whatever is at the path
    // *now*, which need not be the regular file `open_lock_file` validated —
    // `sudo bx` against a user-owned `$HOME` lets the unprivileged owner win
    // that race. Opening a FIFO for reading blocks until a writer appears, and
    // the module's headline promise is that acquisition never blocks. The flag
    // changes nothing for a regular file, and turns a FIFO into
    // [`Holder::unknown`] at once.
    let Ok(fd) = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        RawMode::empty(),
    ) else {
        return Holder::unknown();
    };
    let mut buf = [0_u8; BODY];
    let Ok(read) = rustix::io::pread(fd, &mut buf[..], 0) else {
        return Holder::unknown();
    };
    match std::str::from_utf8(&buf[..read]) {
        Ok(body) => Holder::parse(body),
        Err(_) => Holder::unknown(),
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        // The body is truncated *before* the unlock, while this process is
        // still the only one that can be writing it. Otherwise the identity
        // line outlives the lock, and the next refusal — by a reader, which
        // writes no body of its own — would name a released pid that may
        // belong to an unrelated process by then. A user acting on that
        // message acts on the wrong process.
        let _ = released("truncate", rustix::fs::ftruncate(&self.fd, 0));
        // Closing the descriptor would release it anyway; the explicit unlock
        // makes the release immediate and independent of any dup that may exist.
        // A failure here has nowhere to go and nothing to fix.
        let _ = released(
            "unlock",
            rustix::fs::flock(&self.fd, FlockOperation::Unlock),
        );
    }
}

/// Hand back the result of one call [`ExclusiveLock::drop`] makes, noting the
/// call on this thread first when a test is recording.
///
/// The note travels in the call's own statement, so the order recorded is the
/// order the calls ran: both of their effects are visible only once the drop
/// is over, and nothing else can tell a truncate after the unlock from one
/// before it.
fn released<T>(call: &'static str, result: T) -> T {
    #[cfg(test)]
    release_recording::note(call);
    #[cfg(not(test))]
    let _ = call;
    result
}

/// A test-only, per-thread record of the calls [`ExclusiveLock::drop`] makes.
#[cfg(test)]
mod release_recording {
    use std::cell::RefCell;

    thread_local! {
        static CALLS: RefCell<Option<Vec<&'static str>>> = const { RefCell::new(None) };
    }

    /// Note `call`, if this thread is recording.
    pub(super) fn note(call: &'static str) {
        CALLS.with(|calls| {
            if let Some(calls) = calls.borrow_mut().as_mut() {
                calls.push(call);
            }
        });
    }

    /// The calls noted on this thread while `f` ran, in order. Recording
    /// stops afterwards even if `f` panics.
    pub(super) fn record(f: impl FnOnce()) -> Vec<&'static str> {
        struct Stop;
        impl Drop for Stop {
            fn drop(&mut self) {
                CALLS.with(|calls| calls.borrow_mut().take());
            }
        }
        CALLS.with(|calls| *calls.borrow_mut() = Some(Vec::new()));
        let _stop = Stop;
        f();
        CALLS.with(|calls| calls.borrow_mut().take().unwrap_or_default())
    }
}

impl Drop for SharedLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.fd, FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use crate::testing::guarded_home;

    /// Run this test binary again, in a new process, attempting the lock.
    fn child(dir: &StateDir) -> String {
        let exe = std::env::current_exe().expect("the test binary");
        let out = Command::new(exe)
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "state::lock::tests::child_attempts_the_lock",
            ])
            .env("BX_TEST_LOCK_DIR", dir.root())
            .output()
            .expect("spawn the child");
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The child half of the cross-process lock tests.
    ///
    /// Ignored, so an ordinary `cargo test` never runs it, and a bare
    /// `cargo test -- --ignored` finds no `BX_TEST_LOCK_DIR` and returns.
    #[test]
    #[ignore = "spawned by the cross-process lock tests"]
    fn child_attempts_the_lock() {
        let Some(root) = std::env::var_os("BX_TEST_LOCK_DIR") else {
            return;
        };
        let dir = StateDir::new(PathBuf::from(root));
        match ExclusiveLock::acquire(&dir) {
            Ok(lock) => {
                println!("acquired");
                // Leak the guard: the process is about to exit, and the point
                // of the test is that the *kernel* releases the lock when it
                // does, not that `Drop` ran.
                std::mem::forget(lock);
            }
            Err(Error::Locked { holder, .. }) => {
                println!("busy pid={} {}", holder.pid, holder.program)
            }
            Err(e) => panic!("unexpected failure: {e}"),
        }
    }

    #[test]
    fn the_lock_file_is_created_at_0600() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");
        let mode = Mode::from_bits(
            std::fs::metadata(lock.path())
                .expect("stat")
                .permissions()
                .mode(),
        );
        assert_eq!(mode, Mode::PRIVATE_FILE);
        assert_eq!(lock.path(), dir.lock());
    }

    #[test]
    fn a_lock_guards_its_own_directory_by_identity_and_no_other() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");
        assert!(lock.held().guards(dir.root()));

        // The same directory spelled through a link is the same directory.
        let alias = home.child("alias");
        std::os::unix::fs::symlink(dir.root(), &alias).expect("alias");
        assert!(lock.held().guards(&alias));

        // Another directory, with or without a lock file of its own, is not.
        let other = StateDir::new(home.child("other"));
        assert!(!lock.held().guards(other.root()));
        drop(ExclusiveLock::acquire(&other).expect("the other lock file"));
        assert!(!lock.held().guards(other.root()));
    }

    #[test]
    fn acquiring_creates_the_state_directory() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        assert!(!dir.root().exists());
        let _lock = ExclusiveLock::acquire(&dir).expect("acquire");
        assert!(dir.root().is_dir());
    }

    #[test]
    fn a_holder_is_never_read_through_a_symlink_at_the_lock_path() {
        // Coverage review, round 5: dropping `read_holder`'s own `O_NOFOLLOW`
        // left every lock test green. Acquisition refuses a link at the lock
        // path when it opens it, before a refused lock reads any holder, so the
        // reader is called on the swapped path directly: it must not report
        // the bytes of whatever the link names.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");
        let err = ExclusiveLock::acquire(&dir).expect_err("a second acquisition is refused");
        assert!(
            matches!(&err, Error::Locked { holder, .. } if holder.pid != 0),
            "got {err}"
        );

        let decoy = home.child("decoy");
        std::fs::write(&decoy, "4242 impostor\n").expect("a plausible holder line");
        std::fs::rename(dir.lock(), home.child("moved-lock")).expect("move the lock file");
        std::os::unix::fs::symlink(&decoy, dir.lock()).expect("symlink");

        let err = ExclusiveLock::acquire(&dir).expect_err("still refused");
        assert!(matches!(err, Error::LockNotAFile { .. }), "got {err}");
        assert_eq!(read_holder(&dir.lock()), Holder::unknown());
        drop(lock);
    }

    #[test]
    fn a_lock_refused_for_anything_but_contention_is_an_error_naming_the_file() {
        // r3 round 1 (C2): a `flock` failure other than `EWOULDBLOCK` was
        // never reached, so reading it as success went unnoticed.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        std::fs::write(dir.lock(), b"").expect("seed");
        // An `O_PATH` descriptor names the file but cannot lock it: `EBADF`.
        let fd = rustix::fs::open(dir.lock(), OFlags::PATH | OFlags::CLOEXEC, RawMode::empty())
            .expect("an O_PATH descriptor");
        for operation in [
            FlockOperation::NonBlockingLockExclusive,
            FlockOperation::NonBlockingLockShared,
        ] {
            let err = take(&fd, &dir.lock(), operation).expect_err("EBADF is not a lock");
            assert!(
                matches!(&err, Error::Lock { path, source }
                    if *path == dir.lock()
                        && source.raw_os_error() == Some(Errno::BADF.raw_os_error())),
                "got {err}",
            );
        }
    }

    #[test]
    fn a_holder_line_that_cannot_be_read_is_an_unknown_holder() {
        // r3 round 1 (C2): a failing `pread` was never reached. A directory
        // opens `O_RDONLY`, and reading it fails with `EISDIR`.
        let home = guarded_home();
        let unreadable = home.child("a-directory");
        std::fs::create_dir_all(&unreadable).expect("mkdir");
        assert_eq!(read_holder(&unreadable), Holder::unknown());
    }

    #[test]
    fn a_second_exclusive_acquisition_is_refused() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let _first = ExclusiveLock::acquire(&dir).expect("first");
        let err = ExclusiveLock::acquire(&dir).expect_err("second must be refused");
        assert!(matches!(err, Error::Locked { .. }), "got {err}");
        assert!(ExclusiveLock::try_acquire(&dir).expect("try").is_none());
    }

    #[test]
    fn a_refusal_names_the_pid_and_program_of_the_holder() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let _held = ExclusiveLock::acquire(&dir).expect("acquire");
        let err = ExclusiveLock::acquire(&dir).expect_err("must be refused");
        let Error::Locked { holder, path } = &err else {
            panic!("got {err}")
        };
        assert_eq!(
            holder.pid,
            i32::try_from(std::process::id()).expect("a pid fits in i32"),
        );
        assert!(!holder.program.is_empty());
        assert_eq!(path, &dir.lock());
        assert!(err.to_string().contains(&holder.pid.to_string()));
    }

    #[test]
    fn an_unreadable_lock_body_still_yields_a_usable_message() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let held = ExclusiveLock::acquire(&dir).expect("acquire");
        // Overwrite the identity line with something that is not one.
        std::fs::write(held.path(), b"\xff\xfe not utf-8").expect("clobber");
        let err = ExclusiveLock::acquire(&dir).expect_err("must be refused");
        let Error::Locked { holder, .. } = &err else {
            panic!("got {err}")
        };
        assert_eq!(holder, &Holder::unknown());
        assert!(err.to_string().contains("another bx process"));
    }

    #[test]
    fn an_empty_lock_body_still_yields_a_usable_message() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let held = ExclusiveLock::acquire(&dir).expect("acquire");
        std::fs::write(held.path(), b"").expect("clobber");
        let err = ExclusiveLock::acquire(&dir).expect_err("must be refused");
        assert!(err.to_string().contains("another bx process"), "got {err}");
    }

    #[test]
    fn a_holder_line_is_parsed_and_rendered() {
        assert_eq!(
            Holder::parse("1234 bx\n"),
            Holder {
                pid: 1234,
                program: "bx".to_string(),
            },
        );
        assert_eq!(Holder::parse("1234 bx\n").to_string(), "pid 1234 (bx)");
        assert_eq!(Holder::parse("not-a-pid bx"), Holder::unknown());
        assert_eq!(Holder::parse("1234"), Holder::unknown());
        assert_eq!(Holder::unknown().to_string(), "another bx process");
    }

    #[test]
    fn releasing_the_lock_lets_the_next_acquisition_succeed() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let first = ExclusiveLock::acquire(&dir).expect("first");
        drop(first);
        let _second = ExclusiveLock::acquire(&dir).expect("second");
    }

    #[test]
    fn two_readers_share_the_lock() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let _a = SharedLock::acquire(&dir).expect("first reader");
        let b = SharedLock::acquire(&dir).expect("second reader");
        assert_eq!(b.path(), dir.lock());
        assert!(SharedLock::try_acquire(&dir).expect("try").is_some());
    }

    #[test]
    fn a_reader_does_not_block_on_a_writer_and_reports_the_holder() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let _writer = ExclusiveLock::acquire(&dir).expect("writer");
        assert!(SharedLock::try_acquire(&dir).expect("try").is_none());
        let err = SharedLock::acquire(&dir).expect_err("must be refused");
        assert!(matches!(err, Error::Locked { .. }), "got {err}");
    }

    #[test]
    fn a_writer_is_refused_while_a_reader_holds_the_lock() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let _reader = SharedLock::acquire(&dir).expect("reader");
        let err = ExclusiveLock::acquire(&dir).expect_err("must be refused");
        assert!(matches!(err, Error::Locked { .. }), "got {err}");
    }

    #[test]
    fn a_refusal_never_names_a_writer_that_has_already_released() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        // A writer runs and finishes, leaving its identity behind unless the
        // drop clears it.
        let writer = ExclusiveLock::acquire(&dir).expect("writer");
        assert_eq!(
            std::fs::read_to_string(dir.lock()).expect("read"),
            format!("{} {}\n", std::process::id(), program_name()),
        );
        drop(writer);
        assert_eq!(
            std::fs::read(dir.lock()).expect("read"),
            Vec::<u8>::new(),
            "a released writer must not leave a pid behind",
        );

        // Now a reader holds it, and writes no identity of its own. The
        // refusal must not attribute the lock to the writer that has gone.
        let _reader = SharedLock::acquire(&dir).expect("reader");
        let err = ExclusiveLock::acquire(&dir).expect_err("must be refused");
        let Error::Locked { holder, .. } = &err else {
            panic!("got {err}");
        };
        assert_eq!(
            holder,
            &Holder::unknown(),
            "a reader-held lock must report an unknown holder, not a stale pid",
        );
        assert_eq!(holder.pid, 0);
    }

    #[test]
    fn a_released_writer_clears_its_line_before_it_unlocks() {
        // r3 round 1 (C3): the order was held by a comment. Unlocking first
        // leaves a window in which a reader can take the lock and be refused
        // naming the released pid, and afterwards the file is empty either
        // way, so swapping the two calls left every test green.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let writer = ExclusiveLock::acquire(&dir).expect("writer");
        let calls = release_recording::record(|| drop(writer));
        assert_eq!(calls, ["truncate", "unlock"]);
        assert_eq!(std::fs::read(dir.lock()).expect("read"), Vec::<u8>::new());
    }

    /// The program name [`identify`] writes, derived the same way it derives it.
    fn program_name() -> String {
        std::env::args()
            .next()
            .and_then(|arg0| {
                Path::new(&arg0)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "bx".to_string())
    }

    #[test]
    fn the_lock_is_exclusive_across_two_processes() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let held = ExclusiveLock::acquire(&dir).expect("acquire");

        let refused = child(&dir);
        assert!(
            refused.contains(&format!("busy pid={}", std::process::id())),
            "the child should have been refused, got: {refused}",
        );

        drop(held);
        let taken = child(&dir);
        assert!(
            taken.contains("acquired"),
            "the child should have acquired the released lock, got: {taken}",
        );
    }

    #[test]
    fn a_lock_held_by_a_dead_process_is_acquirable() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        // The child acquires and leaks the guard, so nothing in user space
        // releases the lock: only the kernel, when the process exits.
        let taken = child(&dir);
        assert!(taken.contains("acquired"), "got: {taken}");
        let _mine = ExclusiveLock::acquire(&dir).expect("the dead holder's lock must be free");
    }

    #[test]
    fn the_lock_file_is_never_unlinked() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let path = dir.lock();
        {
            let _lock = ExclusiveLock::acquire(&dir).expect("acquire");
            assert!(path.exists());
        }
        assert!(
            path.exists(),
            "unlinking races: another process may hold a descriptor on the old inode",
        );
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
    }

    #[test]
    fn a_symlink_at_the_lock_path_is_refused_and_never_truncates_what_it_names() {
        // Review round 3: the lock file was opened RDWR|CREATE following
        // symlinks and then truncated, so `<state>/lock -> ~/.bashrc` emptied
        // the user's file.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        home.write(".bashrc", "the user wrote this\n");
        let before = mode_of(&home.child(".bashrc"));
        std::os::unix::fs::symlink(home.child(".bashrc"), dir.lock()).expect("symlink");

        let err = ExclusiveLock::acquire(&dir).expect_err("must refuse");
        assert!(
            matches!(&err, Error::LockNotAFile { path } if *path == dir.lock()),
            "got {err}",
        );
        assert!(err.to_string().contains("not a plain file"), "{err}");
        assert!(matches!(
            SharedLock::acquire(&dir),
            Err(Error::LockNotAFile { .. })
        ));
        assert!(ExclusiveLock::try_acquire(&dir).is_err());
        assert_eq!(
            std::fs::read(home.child(".bashrc")).expect("read"),
            b"the user wrote this\n",
        );
        assert_eq!(mode_of(&home.child(".bashrc")), before);
    }

    #[test]
    fn a_dangling_symlink_at_the_lock_path_creates_nothing_through_it() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        std::os::unix::fs::symlink(home.child("elsewhere"), dir.lock()).expect("symlink");

        let err = ExclusiveLock::acquire(&dir).expect_err("must refuse");
        assert!(matches!(err, Error::LockNotAFile { .. }), "got {err}");
        assert!(!home.child("elsewhere").exists());
    }

    #[test]
    fn a_hard_link_or_a_fifo_at_the_lock_path_is_refused() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        home.write(".profile", "the user wrote this too\n");
        std::fs::hard_link(home.child(".profile"), dir.lock()).expect("hard link");

        let err = ExclusiveLock::acquire(&dir).expect_err("a second link is not bx's file");
        assert!(matches!(err, Error::LockNotAFile { .. }), "got {err}");
        assert_eq!(
            std::fs::read(home.child(".profile")).expect("read"),
            b"the user wrote this too\n",
        );

        std::fs::remove_file(dir.lock()).expect("unlink the link");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.lock(),
            FileType::Fifo,
            RawMode::from_bits_truncate(0o600),
            0,
        )
        .expect("mkfifo");
        let err = ExclusiveLock::acquire(&dir).expect_err("a fifo is not a lock file");
        assert!(matches!(err, Error::LockNotAFile { .. }), "got {err}");
    }

    #[test]
    fn a_lock_file_readable_beyond_its_owner_is_narrowed_to_0600() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        std::fs::write(dir.lock(), b"").expect("seed");
        std::fs::set_permissions(dir.lock(), std::fs::Permissions::from_mode(0o666))
            .expect("widen");

        drop(SharedLock::acquire(&dir).expect("reader"));
        assert_eq!(mode_of(&dir.lock()), 0o600, "a reader narrows it too");

        std::fs::set_permissions(dir.lock(), std::fs::Permissions::from_mode(0o640))
            .expect("widen again");
        let _lock = ExclusiveLock::acquire(&dir).expect("writer");
        assert_eq!(mode_of(&dir.lock()), 0o600);
    }

    #[test]
    fn a_lock_file_whose_mode_is_not_0600_is_set_to_it_even_when_it_shares_nothing() {
        // r4 round 1 (D2): the repair fired only on `is_shared`, which is
        // `mode & 0o077` — structurally unable to see a mode wrong in the OWNER
        // bits. `0700` shares nothing with anybody, so the old condition left
        // it; the file bx promises at `0600` was not at `0600`.
        for wrong in [0o700, 0o606, 0o644] {
            let home = guarded_home();
            let dir = StateDir::resolve(home.path());
            dir.ensure().expect("ensure");
            std::fs::write(dir.lock(), b"").expect("seed");
            std::fs::set_permissions(dir.lock(), std::fs::Permissions::from_mode(wrong))
                .expect("set");

            drop(SharedLock::acquire(&dir).expect("reader"));
            assert_eq!(mode_of(&dir.lock()), 0o600, "from {wrong:04o}, a reader");

            std::fs::set_permissions(dir.lock(), std::fs::Permissions::from_mode(wrong))
                .expect("set again");
            drop(ExclusiveLock::acquire(&dir).expect("writer"));
            assert_eq!(mode_of(&dir.lock()), 0o600, "from {wrong:04o}, a writer");
        }
    }

    /// Run this test binary again, under `umask`, creating a state directory
    /// and taking the lock in it. Prints the two modes it ends up with.
    fn child_under_umask(dir: &StateDir, umask: u32) -> String {
        let exe = std::env::current_exe().expect("the test binary");
        let out = Command::new(exe)
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "state::lock::tests::child_creates_the_state_directory_under_a_umask",
            ])
            .env("BX_TEST_UMASK_DIR", dir.root())
            .env("BX_TEST_UMASK", format!("{umask:o}"))
            .output()
            .expect("spawn the child");
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The child half of [`an_unusual_umask_does_not_leave_bx_unusable`].
    ///
    /// A separate process because `umask(2)` is process-global and `cargo test`
    /// runs every test in threads of one process: setting it here would change
    /// the mode of files other tests create, at whatever moment they ran.
    #[test]
    #[ignore = "spawned by the umask test"]
    fn child_creates_the_state_directory_under_a_umask() {
        let (Some(root), Some(mask)) = (
            std::env::var_os("BX_TEST_UMASK_DIR"),
            std::env::var("BX_TEST_UMASK").ok(),
        ) else {
            return;
        };
        let mask = u32::from_str_radix(&mask, 8).expect("an octal umask");
        let dir = StateDir::new(PathBuf::from(root));
        let was = rustix::process::umask(RawMode::from_bits_truncate(mask));
        let made = (|| {
            dir.ensure()?;
            let lock = ExclusiveLock::acquire(&dir)?;
            Ok::<_, Error>((mode_of(dir.root()), mode_of(lock.path())))
        })();
        // Put the mask back before anything else in this process writes a
        // file — the coverage instrumentation writes its profile at exit, and
        // a mask that denied the owner would leave it unreadable.
        rustix::process::umask(was);
        let (root_mode, lock_mode) = made.expect("the state directory, under the mask");
        println!("dir={root_mode:04o} lock={lock_mode:04o}");
    }

    #[test]
    fn an_unusual_umask_does_not_leave_bx_unusable() {
        // r4 round 1 (COV1, D2): `mkdir(0700)` and `open(…, 0600)` are both
        // masked by the process `umask`, and no test in the repository set one.
        // Under every `umask` a developer runs — 022, 002, 077 — the mask takes
        // away only bits that were not asked for, so the post-create `chmod` in
        // `ensure_dir` and the repair here were both unreachable by any test
        // that could make them matter, and deleting either left the suite green.
        if rustix::process::geteuid().is_root() {
            return;
        }
        for mask in [0o500, 0o277, 0o377] {
            let home = guarded_home();
            let dir = StateDir::new(home.child("state"));
            let said = child_under_umask(&dir, mask);
            assert!(
                said.contains("dir=0700 lock=0600"),
                "under umask {mask:04o}: {said}",
            );
            // And a second process, with no unusual mask, can still use it —
            // the failure the stripped bits actually cause.
            dir.ensure().expect("a second run");
            drop(ExclusiveLock::acquire(&dir).expect("a second run takes the lock"));
        }
    }

    #[test]
    fn a_fifo_at_the_lock_path_does_not_block_the_holder_report() {
        // r4 round 1 (D7): `read_holder` re-opens the lock path rather than
        // reading through the descriptor `open_lock_file` validated, so what
        // it opens need not be the regular file that was checked — `sudo bx`
        // against a user-owned $HOME lets the owner win that race. Opening a
        // FIFO for reading blocks until a writer appears, and the module's
        // headline promise is that acquisition never blocks.
        let home = guarded_home();
        let path = home.child("lock");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            FileType::Fifo,
            RawMode::from_bits_truncate(0o600),
            0,
        )
        .expect("fifo");

        // In a thread with a deadline: the failure is a hang, and a test that
        // hangs reports nothing. The thread is abandoned if it does.
        let (tx, rx) = std::sync::mpsc::channel();
        let for_thread = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_holder(&for_thread));
        });
        let holder = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("read_holder blocked on a FIFO");
        assert_eq!(holder, Holder::unknown());
    }

    #[test]
    fn a_directory_at_the_lock_path_is_refused_with_a_remedy() {
        // Review round 4: a directory there was a bare `Error::Lock` carrying
        // EISDIR, which says what failed and not what to do.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        std::fs::create_dir(dir.lock()).expect("occupy");
        std::fs::write(dir.lock().join("keep"), b"x").expect("occupy");

        for err in [
            ExclusiveLock::acquire(&dir).expect_err("must fail"),
            SharedLock::acquire(&dir).expect_err("must fail"),
        ] {
            assert!(
                matches!(&err, Error::LockNotAFile { path } if *path == dir.lock()),
                "got {err}",
            );
            let message = err.to_string();
            assert!(message.contains("a directory"), "{message}");
            assert!(message.contains("Move it aside"), "{message}");
        }
        assert!(ExclusiveLock::try_acquire(&dir).is_err());
        assert_eq!(std::fs::read(dir.lock().join("keep")).expect("kept"), b"x");
    }

    #[test]
    fn a_lock_file_that_cannot_be_opened_is_reported() {
        if rustix::process::geteuid().is_root() {
            // `0000` denies nothing to root, so the condition cannot be staged.
            return;
        }
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        std::fs::write(dir.lock(), b"").expect("seed");
        std::fs::set_permissions(dir.lock(), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let err = ExclusiveLock::acquire(&dir).expect_err("must fail");
        assert!(matches!(err, Error::Lock { .. }), "got {err}");
        assert!(ExclusiveLock::try_acquire(&dir).is_err());
    }
}
