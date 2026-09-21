//! The state directory's location and layout.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, RenameFlags};
use rustix::io::Errno;

use super::Error;
use super::lock::{ExclusiveLock, HeldLock};
use super::store::leads_nowhere;
use crate::fs::Mode;

/// `$XDG_STATE_HOME/bx` — bx's machine-owned half.
///
/// Every path name in the state directory appears in exactly one place in the
/// crate: here. Nothing else joins `ledger.mpk`, `restore/` or `lock` onto a
/// root, so a rename is one edit rather than a search.
///
/// Holding a `StateDir` says nothing about whether the directory exists; call
/// [`StateDir::ensure`] for that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// The state directory for `home`, with no `$XDG_STATE_HOME` override.
    ///
    /// This reads no environment variable, which is the point: two tests with
    /// two tempdir homes get two independent state directories, and neither can
    /// be redirected by whatever the process environment happens to hold.
    ///
    /// A caller that must honour the user's `$XDG_STATE_HOME` — the binary,
    /// once — passes it to [`StateDir::resolve_in`] instead.
    #[must_use]
    pub fn resolve(home: &Path) -> Self {
        Self::resolve_in(home, None)
    }

    /// The state directory for `home`, honouring an `$XDG_STATE_HOME` value.
    ///
    /// The resolution itself is [`crate::config::layers::state_dir`]'s, not this
    /// module's, and this delegates to it rather than repeating the XDG rule.
    /// The local layer and the ledger have to agree about which directory they
    /// are in; two resolvers that agree today are two resolvers that can
    /// disagree tomorrow.
    #[must_use]
    pub fn resolve_in(home: &Path, xdg_state_home: Option<&OsStr>) -> Self {
        Self::new(crate::config::layers::state_dir(home, xdg_state_home))
    }

    /// A state directory at an already-known path.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `local.toml` — this account's own layer, which is never committed.
    ///
    /// Delegates to [`crate::config::layers::local_layer_path`], so the layer
    /// loader and the state directory cannot name two different files.
    #[must_use]
    pub fn local_toml(&self) -> PathBuf {
        crate::config::layers::local_layer_path(&self.root)
    }

    /// `ledger.mpk` — what bx wrote, and what it displaced.
    #[must_use]
    pub fn ledger(&self) -> PathBuf {
        self.root.join("ledger.mpk")
    }

    /// `fingerprints.mpk` — the cache-invalidation store.
    #[must_use]
    pub fn fingerprints(&self) -> PathBuf {
        self.root.join("fingerprints.mpk")
    }

    /// `journal.mpk` — the write-ahead journal.
    ///
    /// Named here so the layout stays in one place. Its contents belong to the
    /// recovery entry; nothing in this module reads or writes it.
    #[must_use]
    pub fn journal(&self) -> PathBuf {
        self.root.join("journal.mpk")
    }

    /// `restore/` — content-addressed copies of the bytes bx displaced.
    #[must_use]
    pub fn restore(&self) -> PathBuf {
        self.root.join("restore")
    }

    /// `shell/` — generated shell fragments, sourced at startup.
    #[must_use]
    pub fn shell(&self) -> PathBuf {
        self.root.join("shell")
    }

    /// `lock` — the advisory lock file. Created once and never unlinked.
    #[must_use]
    pub fn lock(&self) -> PathBuf {
        self.root.join("lock")
    }

    /// The first quarantine path for a damaged state file: `<name>.corrupt`.
    ///
    /// A later quarantine of the same file never reuses an occupied name:
    /// [`move_aside`] takes the number after the highest of `<name>.corrupt`,
    /// `<name>.corrupt.1`, `<name>.corrupt.2`, … present, so it does not refill
    /// a gap and the last is the newest — until the top number,
    /// `<name>.corrupt.<u64::MAX>`, is present, whoever made it. That number has
    /// no successor, so while it is present each quarantine takes the lowest
    /// free number instead: gaps are refilled and the numbers no longer say
    /// which quarantine is newest. Numbered rather than timestamped, so the name
    /// a given sequence of damage produces is deterministic; and never over an
    /// earlier one, because the earlier one may be the only index there is to
    /// the user's restore blobs.
    #[must_use]
    pub(crate) fn quarantine(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(".corrupt");
        PathBuf::from(name)
    }

    /// The `n`th quarantine path: [`StateDir::quarantine`] for `0`, then
    /// `<name>.corrupt.<n>`.
    #[must_use]
    pub(crate) fn quarantine_nth(path: &Path, n: u64) -> PathBuf {
        let mut name = Self::quarantine(path).into_os_string();
        if n > 0 {
            name.push(format!(".{n}"));
        }
        PathBuf::from(name)
    }

    /// Create the state directory and its subdirectories, at `0700`.
    ///
    /// Idempotent: running it twice changes nothing and fails on nothing.
    ///
    /// Missing **ancestors** (`~/.local`, `~/.local/state`) are created with the
    /// process `umask`, because they are shared with every other XDG-aware tool
    /// and are not bx's to tighten. The directories bx invents — `bx/`,
    /// `bx/restore/`, `bx/shell/` — are created at `0700` and set back to
    /// `0700` whenever they are found at anything else, because they hold
    /// `local.toml`, the age identity, and prior copies of the user's private
    /// files. See [`tighten`] for why a directory already there is repaired
    /// whoever made it, why a linked one is refused rather than changed, and
    /// what ownership is checked.
    ///
    /// **No command calls this yet.** On this branch every caller is a test;
    /// `apply` is the entry that will call it. A read-only command still
    /// creates the state *root*, because `bx plan` and `bx doctor` take the
    /// shared lock and a lock needs a file — but that goes through
    /// [`ensure_dir`] on the root alone, not through here, so `restore/` and
    /// `shell/` are not created by a read. Invariant 1 forbids rewriting a byte
    /// the *user* wrote, and none of these paths is one; see the
    /// [`super::lock`] module documentation for the argument.
    ///
    /// # Errors
    ///
    /// [`Error::NotADirectory`] when something that is not a directory occupies
    /// one of those paths, naming the path to clear,
    /// [`Error::UnwritableAncestor`] when a directory above one of them cannot
    /// be written in, and [`Error::CreateDir`] for any other failure.
    pub fn ensure(&self) -> Result<(), Error> {
        ensure_dir(&self.root, Mode::PRIVATE_DIR)?;
        ensure_dir(&self.restore(), Mode::PRIVATE_DIR)?;
        ensure_dir(&self.shell(), Mode::PRIVATE_DIR)
    }
}

/// Create `path` at exactly `mode`, or verify and tighten an existing one.
///
/// Missing **ancestors** are created with the process `umask`: they are shared
/// with every other XDG-aware tool and are not bx's to tighten. Only `path`
/// itself gets `mode`.
///
/// The explicit `chmod` after `mkdir` is not redundant: `mkdir` applies the
/// process `umask`, so an unusual `umask` would otherwise leave a directory bx
/// promised at `0700` at something else.
///
/// # A `umask` that strips the owner's own bits
///
/// The ancestors get the process `umask`, and a `umask` with owner bits in it
/// — `0277`, `0377`, `0500` — leaves the `~/.local` this call just created at
/// `0500`, which this account cannot write in. The `mkdir` of the next
/// component then fails `EACCES` inside a directory bx made one statement
/// earlier, and "creating ~/.local/state/bx: Permission denied" names neither
/// the directory that is in the way nor the `umask` that made it. So an
/// `EACCES` or `EPERM` is turned into [`Error::UnwritableAncestor`], which
/// names the ancestor, its mode, and the `chmod` that clears it (r4 round 2,
/// D4). The ancestor mode itself is left alone: it is shared with every other
/// XDG-aware tool and is not bx's to widen behind the user's `umask`.
pub(crate) fn ensure_dir(path: &Path, mode: Mode) -> Result<(), Error> {
    let create_failed = |source: std::io::Error| {
        blame_ancestor(path, &source).unwrap_or(Error::CreateDir {
            path: path.to_path_buf(),
            source,
        })
    };
    // No parent only for `/` or an empty path: never a resolved root, `restore/` or `shell/`.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| {
            blame_ancestor(parent, &source).unwrap_or(Error::CreateDir {
                path: parent.to_path_buf(),
                source,
            })
        })?;
    }
    match rustix::fs::mkdir(path, mode.into()) {
        Ok(()) => rustix::fs::chmod(path, mode.into()).map_err(|s| create_failed(s.into())),
        Err(Errno::EXIST) => tighten(path, mode),
        Err(source) => Err(create_failed(source.into())),
    }
}

/// [`Error::UnwritableAncestor`] when `source` is a permission failure and a
/// directory above `path` is one this account cannot write in.
///
/// Only the deepest existing ancestor is named: it is the one the failing
/// `mkdir` was inside, and the one a `chmod` has to reach for. `None` when the
/// failure is not a permission failure, or when every ancestor that exists is
/// writable — then the original error is the honest one, and inventing a
/// diagnosis from a race would be worse than the errno.
fn blame_ancestor(path: &Path, source: &std::io::Error) -> Option<Error> {
    if source.kind() != std::io::ErrorKind::PermissionDenied {
        return None;
    }
    let ancestor = path.ancestors().skip(1).find(|a| a.exists())?;
    let found = Mode::from_bits(std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(ancestor).ok()?.permissions(),
    ));
    // `W_OK | X_OK` for the invoking account, asked of the kernel rather than
    // inferred from the bits: ownership, group membership and root all change
    // the answer, and only `access` knows all three.
    if rustix::fs::access(
        ancestor,
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
    )
    .is_ok()
    {
        return None;
    }
    Some(Error::UnwritableAncestor {
        path: path.to_path_buf(),
        ancestor: ancestor.to_path_buf(),
        mode: found,
    })
}

/// Move a damaged state file aside, to the quarantine number after the highest
/// one present.
///
/// Demands the exclusive lock, because a rename by path moves whatever is at
/// the path *now*: only while no writer can save is that still the file whose
/// bytes were judged damaged.
///
/// The number is the one after the highest `<name>.corrupt[.<n>]` present —
/// `<name>.corrupt` itself when there is none — and never a gap a deleted
/// quarantine left. So the quarantines present are numbered in the order they
/// were made, and the last is the newest, whichever a human has removed — until
/// the top number, `<name>.corrupt.<u64::MAX>`, is present. Whoever made it — a
/// crafted file, or bx itself when a crafted `<name>.corrupt.<u64::MAX - 1>` was
/// the highest — it has no successor, so while it is present each quarantine
/// takes the lowest free number: a gap is refilled, the numbers stop following
/// the order the quarantines were made, and the newest can be the lowest. A
/// crafted name can end that order, but it never blocks a quarantine.
///
/// The rename is `RENAME_NOREPLACE`, so an existing quarantine is never
/// destroyed — not by an earlier bx's leftovers, and not by a race; a name
/// taken since the listing is skipped for the next. A filesystem that does not
/// support the flag (`EINVAL`) falls back to checking for the name first and
/// renaming second, which the lock makes sound against every other bx.
///
/// The lock must be the one of the directory holding `path` — see
/// [`check_lock`] — or nothing is renamed.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] for another directory's lock, the
/// failure to list the directory, and otherwise the first failure that is not
/// "that name is taken".
pub(crate) fn move_aside(path: &Path, lock: &ExclusiveLock) -> std::io::Result<PathBuf> {
    check_lock(path, lock).map_err(|refused| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, refused.to_string())
    })?;
    let mut n: u64 = match numbered(path)?.last() {
        // Only the top number — `<name>.corrupt.<u64::MAX>`, crafted, or made
        // by bx after a crafted `<u64::MAX - 1>` — has no number after it. Refusing there would let one crafted file block
        // every later quarantine, so the count starts again at `0` instead and
        // skips every taken name below, which lands on the lowest free number:
        // a directory cannot hold 2^64 entries, so one always exists.
        Some(highest) => highest.checked_add(1).unwrap_or(0),
        None => 0,
    };
    loop {
        let candidate = StateDir::quarantine_nth(path, n);
        match rename_noreplace(path, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(Errno::EXIST) => {}
            Err(Errno::INVAL) if std::fs::symlink_metadata(&candidate).is_err() => {
                std::fs::rename(path, &candidate)?;
                return Ok(candidate);
            }
            Err(Errno::INVAL) => {}
            Err(source) => return Err(source.into()),
        }
        n = n
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("no free quarantine name"))?;
    }
}

/// `renameat2(from, to, RENAME_NOREPLACE)`.
///
/// One call site, so a test can make it answer as a filesystem without the flag
/// does — see [`noreplace_seam`] — and reach [`move_aside`]'s check-then-rename
/// fallback, which no filesystem a test can create would exercise.
fn rename_noreplace(from: &Path, to: &Path) -> rustix::io::Result<()> {
    #[cfg(test)]
    if noreplace_seam::unsupported(to) {
        return Err(Errno::INVAL);
    }
    rustix::fs::renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE)
}

/// A test-only, per-thread switch that makes [`rename_noreplace`] report
/// `EINVAL`, as a filesystem that does not support `RENAME_NOREPLACE` does.
#[cfg(test)]
pub(crate) mod noreplace_seam {
    use std::cell::RefCell;
    use std::path::Path;

    /// Called with each rename's destination; `true` reports `EINVAL`.
    type Seam = Box<dyn FnMut(&Path) -> bool>;

    thread_local! {
        static SEAM: RefCell<Option<Seam>> = const { RefCell::new(None) };
    }

    /// Whether the seam installed on this thread says `RENAME_NOREPLACE` is
    /// unsupported for `to`. With none installed, it is supported.
    pub(super) fn unsupported(to: &Path) -> bool {
        SEAM.with(|slot| match slot.borrow_mut().as_mut() {
            Some(seam) => seam(to),
            None => false,
        })
    }

    /// Run `f` with `seam` installed on this thread, removing it afterwards
    /// even if `f` panics.
    pub(crate) fn with<T>(seam: impl FnMut(&Path) -> bool + 'static, f: impl FnOnce() -> T) -> T {
        struct Remove;
        impl Drop for Remove {
            fn drop(&mut self) {
                SEAM.with(|slot| slot.borrow_mut().take());
            }
        }
        SEAM.with(|slot| *slot.borrow_mut() = Some(Box::new(seam)));
        let _remove = Remove;
        f()
    }
}

/// Every quarantine of `path` present now, ascending by number:
/// `<name>.corrupt`, then `<name>.corrupt.1`, `<name>.corrupt.2`, …. That is
/// the order [`move_aside`] made them until the top number is present, and
/// only by number after it — see [`move_aside`].
///
/// Found by listing the directory, not by probing names until one is missing,
/// so a gap — `.corrupt` deleted, `.corrupt.1` kept — hides nothing after it.
/// Only a name [`StateDir::quarantine_nth`] would give is counted.
///
/// # Errors
///
/// The listing failure itself if the directory exists and cannot be listed: an
/// empty list there would be a guess. The `io::Error` is handed back rather
/// than wrapped, because the only caller reports the *kind* as well as the
/// text — `EACCES` is a `chmod` the user can make and `EIO` is not — and
/// wrapping it here threw that away (r4 round 2, CL5).
pub(crate) fn quarantines(path: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    Ok(numbered(path)?
        .into_iter()
        .map(|n| StateDir::quarantine_nth(path, n))
        .collect())
}

/// The number of every quarantine of `path` present now, ascending: `0` for
/// `<name>.corrupt`, `n` for `<name>.corrupt.<n>`.
///
/// A missing directory holds none.
fn numbered(path: &Path) -> std::io::Result<Vec<u64>> {
    // Every state file StateDir names is `root.join(<UTF-8 name>)`, so the else arm is unreachable.
    let (Some(root), Some(name)) = (path.parent(), path.file_name().and_then(OsStr::to_str)) else {
        return Ok(Vec::new());
    };
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(source),
    };
    let prefix = format!("{name}.corrupt");
    let mut found = Vec::new();
    for entry in entries {
        let file = entry?.file_name();
        let Some(rest) = file.to_str().and_then(|file| file.strip_prefix(&prefix)) else {
            continue;
        };
        let n = match rest.strip_prefix('.').map(str::parse::<u64>) {
            None if rest.is_empty() => 0,
            Some(Ok(n)) if n > 0 && rest == format!(".{n}") => n,
            _ => continue,
        };
        found.push(n);
    }
    found.sort_unstable();
    Ok(found)
}

/// Refuse `lock` unless it is the lock of the state directory holding `path`.
///
/// Every operation that demands an [`ExclusiveLock`] demands it for one
/// directory. A quarantine or a save under another directory's lock is as
/// unguarded as one under none: another bx holding *this* directory's lock can
/// be saving the very file being moved.
///
/// # Errors
///
/// [`Error::WrongLock`], naming both lock files — or the one, when it is this
/// directory's lock file that was replaced while held.
pub(crate) fn check_lock(path: &Path, lock: &ExclusiveLock) -> Result<(), Error> {
    check_held(path, lock.held())
}

/// [`check_lock`], against the lock file a guard locked, for a caller that
/// kept that rather than the guard.
///
/// # Errors
///
/// As [`check_lock`].
pub(crate) fn check_held(path: &Path, held: &HeldLock) -> Result<(), Error> {
    let root = path.parent().unwrap_or_else(|| Path::new(""));
    if held.guards(root) {
        return Ok(());
    }
    Err(Error::WrongLock {
        held: held.path().to_path_buf(),
        needed: StateDir::new(root.to_path_buf()).lock(),
    })
}

/// Whether users other than the owner can read or write a directory of `mode`
/// — the question asked of a linked directory bx may not `chmod`.
///
/// Search permission alone is not counted. It lets another user open a name
/// they already know, and every file bx writes in the state directory is
/// `0600`, so `0711` exposes none of them and refusing it would be untrue. The
/// one file bx does not write there, `local.toml`, is [`check_local_layer`]'s.
///
/// Group permission is counted even when the group is a user-private one, as
/// on Fedora's default `umask 002`. Whether a group has exactly one member is
/// a question for the account database, which bx does not consult, so a
/// group-readable or group-writable target is refused.
fn open_beyond_owner(mode: Mode) -> bool {
    mode.bits() & 0o066 != 0
}

/// Refuse a linked directory of `mode` that others can search while
/// `local.toml` in it is readable or writable beyond its owner.
///
/// The rule every state directory bx accepts keeps: **no other account can
/// open `local.toml`.** A directory bx created is narrowed to `0700`, which
/// protects the file whatever its mode. A linked directory is never narrowed,
/// and search permission on it exposes no file bx writes — but `local.toml` is
/// written by the user, with their own `umask`, under a name nobody has to
/// guess. So a searchable linked directory is accepted only while that file is
/// absent or private, and bx changes neither mode itself.
///
/// Checked on every [`ensure_dir`] of the directory, so a `local.toml` created
/// or widened later is refused the next time bx runs.
///
/// A `local.toml` that is a symbolic link is judged where the file is. A link
/// that leads nowhere — to nothing, round a loop, through a file — or to
/// something that is not a regular file exposes nothing, and is the layer
/// loader's to report. A link to a regular file exposes it only if the
/// directory holding that file can be searched by others too; otherwise no
/// other account can open it, whatever its mode.
///
/// # One component, and why that is the whole question
///
/// Only the immediate parent of the resolved file is judged, not the whole
/// ancestor chain, and that is conservative in **both** directions (r4 round 2,
/// CL9). Traversal needs search permission on every component, so a parent
/// another account cannot search makes the file unreachable whatever the
/// components above it are: the early `Ok` cannot be wrong. And a parent that
/// others *can* search is only assumed reachable — an ancestor above it may
/// close the path — so the refusal that follows can over-refuse and never
/// under-refuse. Decision 34's rule, "no state directory bx accepts lets
/// another account open `local.toml`", is therefore kept by one `stat` rather
/// than by walking to the root of a filesystem bx did not lay out.
///
/// # Errors
///
/// [`Error::ExposedLocalLayer`], and [`Error::Read`] if the file, or the
/// directory a link leads to, cannot be examined.
fn check_local_layer(dir: &Path, mode: Mode) -> Result<(), Error> {
    if mode.bits() & 0o011 == 0 {
        return Ok(());
    }
    let file = crate::config::layers::local_layer_path(dir);
    let meta = match std::fs::symlink_metadata(&file) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(Error::Read { path: file, source }),
    };
    let meta = if meta.file_type().is_symlink() {
        let target = match std::fs::metadata(&file) {
            Ok(target) if target.is_file() => target,
            Ok(_) => return Ok(()),
            Err(e) if leads_nowhere(&e) => return Ok(()),
            Err(source) => return Err(Error::Read { path: file, source }),
        };
        let real = std::fs::canonicalize(&file).map_err(|source| Error::Read {
            path: file.clone(),
            source,
        })?;
        let holder = real.parent().unwrap_or_else(|| Path::new("/"));
        let holder_meta = std::fs::metadata(holder).map_err(|source| Error::Read {
            path: holder.to_path_buf(),
            source,
        })?;
        if std::os::unix::fs::PermissionsExt::mode(&holder_meta.permissions()) & 0o011 == 0 {
            return Ok(());
        }
        target
    } else {
        meta
    };
    let file_mode = Mode::from_bits(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
    if open_beyond_owner(file_mode) {
        return Err(Error::ExposedLocalLayer {
            path: dir.to_path_buf(),
            // Resolved only once refused, for the remedy: the verdict above
            // does not depend on it, and a link gone since stands for itself.
            target: std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf()),
            mode,
            file,
            file_mode,
        });
    }
    Ok(())
}

/// Refuse `path` unless `uid` is this process's effective uid.
///
/// The one component of "is this ours" the module used to omit. It validates
/// file type, link-ness, `nlink` and mode precisely to establish that a state
/// directory or a lock file is bx's own; a directory owned by another account
/// at `0700` was accepted as bx's regardless, and bx would then write the
/// user's displaced private bytes into a directory that account controls.
///
/// Reachable rather than theoretical: `state/mod.rs` contemplates the
/// `EACCES` a `sudo bx` leaves behind, which is the same mixed-uid situation
/// arriving one run later.
///
/// # Errors
///
/// [`Error::ForeignOwner`], naming both uids.
pub(crate) fn check_owner(path: &Path, uid: u32) -> Result<(), Error> {
    let ours = rustix::process::geteuid().as_raw();
    if uid == ours {
        return Ok(());
    }
    Err(Error::ForeignOwner {
        path: path.to_path_buf(),
        owner: uid,
        ours,
    })
}

/// Check that an existing `path` is a directory owned by this account, and set
/// it to `mode` if it is at anything else.
///
/// # One rule for both objects bx promises a mode for
///
/// A directory bx created at its own state path is repaired on **inequality**,
/// exactly as [`open_lock_file`][super::lock] repairs the lock file: the
/// object bx promises at `0700` was not at `0700`. Sharing alone is not the
/// test, because `mode & 0o077` is structurally unable to see a mode wrong in
/// the owner bits — and a state directory left at `0500`, by a crash between
/// the `mkdir` and the `chmod` below, by an exotic `umask`, or by the user's
/// own hand, makes every later write fail `EACCES` with no repair and no
/// diagnostic. Two rules for the same question was the round-1 defect on the
/// lock file; one rule for both is the answer (r4 round 2, CL3).
///
/// Narrowing and widening are sanctioned by different arguments, and both
/// hold here. Narrowing is the privacy argument below. Widening is not bx
/// dictating a layout: it applies only to the three directories bx creates at
/// its own state path and promises at `0700`, and it is logged.
///
/// # Why a pre-existing directory is repaired at all
///
/// bx narrows a directory found at its own state path, whoever made it,
/// because that directory holds `restore/` — verbatim copies of the user's
/// private files — and a `0755` state directory exposes every one of them.
/// Provenance cannot gate it: nothing records which process created the
/// directory, and inferring it from mode or mtime is a guess. Reporting and
/// refusing instead would leave those copies world-readable while bx talks
/// about it, which is the worse failure for the concern Invariant 5 names.
/// Ownership is checked, which is the part that can be established.
///
/// # Why a linked directory is refused rather than narrowed
///
/// A directory reached through a symlink is never narrowed: it is refused if
/// [`open_beyond_owner`], and otherwise left exactly as it is. What is at the
/// other end of a link the user made is not bx's to re-permission — it is a
/// directory bx did not create and may be shared with other users — so the
/// only answers left are to accept it as it is or to refuse and say why.
fn tighten(path: &Path, mode: Mode) -> Result<(), Error> {
    let read_failed = |source| Error::Read {
        path: path.to_path_buf(),
        source,
    };
    let linked = std::fs::symlink_metadata(path)
        .map_err(read_failed)?
        .file_type()
        .is_symlink();
    // `metadata` follows symlinks on purpose: a state directory the user has
    // symlinked onto other storage is theirs to arrange, and refusing it would
    // be bx dictating a layout.
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        // A link that leads nowhere is not a directory that cannot be read.
        // `mkdir` returned `EEXIST` because the link occupies the name, and
        // "reading ~/.local/state/bx: No such file or directory" would then
        // be untrue on its face — the user can see the thing it names — and
        // would name no remedy. `store::leads_nowhere` and
        // `Damage::DanglingLink` already draw this distinction for state
        // *files*; this is the same distinction for the directories.
        Err(e) if linked && leads_nowhere(&e) => {
            return Err(Error::DanglingStateDir {
                path: path.to_path_buf(),
                target: std::fs::read_link(path).unwrap_or_else(|_| PathBuf::from("?")),
            });
        }
        Err(source) => return Err(read_failed(source)),
    };
    if !meta.is_dir() {
        return Err(Error::NotADirectory {
            path: path.to_path_buf(),
        });
    }

    check_owner(path, std::os::unix::fs::MetadataExt::uid(&meta))?;
    let found = Mode::from_bits(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
    if linked {
        // Never `chmod` through a link: the directory it names is not one bx
        // created, and may be shared with other users. Leaving it open would
        // put prior copies of private files where others can list or replace
        // them, so the only answer left is to refuse and say why.
        if open_beyond_owner(found) {
            return Err(Error::SharedLinkedDir {
                path: path.to_path_buf(),
                mode: found,
            });
        }
        return check_local_layer(path, found);
    }
    if found != mode {
        tracing::warn!(
            path = %path.display(),
            found = %found,
            set_to = %mode,
            "the bx state directory was {found}, not {mode}{}; setting it",
            if found.is_shared() {
                ", and was reachable beyond its owner"
            } else {
                ""
            },
        );
        rustix::fs::chmod(path, mode.into()).map_err(|source| Error::CreateDir {
            path: path.to_path_buf(),
            source: source.into(),
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    use crate::testing::guarded_home;

    fn mode_of(path: &Path) -> Mode {
        Mode::from_bits(std::fs::metadata(path).expect("stat").permissions().mode())
    }

    #[test]
    fn the_layout_matches_the_specification() {
        let dir = StateDir::new(PathBuf::from("/s/bx"));
        let cases: [(PathBuf, &str); 8] = [
            (dir.root().to_path_buf(), "/s/bx"),
            (dir.local_toml(), "/s/bx/local.toml"),
            (dir.ledger(), "/s/bx/ledger.mpk"),
            (dir.fingerprints(), "/s/bx/fingerprints.mpk"),
            (dir.journal(), "/s/bx/journal.mpk"),
            (dir.restore(), "/s/bx/restore"),
            (dir.shell(), "/s/bx/shell"),
            (dir.lock(), "/s/bx/lock"),
        ];
        for (got, want) in cases {
            assert_eq!(got, PathBuf::from(want));
        }
    }

    #[test]
    fn the_default_location_is_under_local_state() {
        let dir = StateDir::resolve(Path::new("/home/someone"));
        assert_eq!(dir.root(), Path::new("/home/someone/.local/state/bx"));
    }

    #[test]
    fn an_absolute_xdg_state_home_is_honoured() {
        let dir = StateDir::resolve_in(Path::new("/home/someone"), Some(OsStr::new("/srv/state")));
        assert_eq!(dir.root(), Path::new("/srv/state/bx"));
    }

    #[test]
    fn a_relative_or_empty_xdg_state_home_is_ignored() {
        for bogus in ["", "relative/state"] {
            let dir = StateDir::resolve_in(Path::new("/home/someone"), Some(OsStr::new(bogus)));
            assert_eq!(dir.root(), Path::new("/home/someone/.local/state/bx"));
        }
    }

    #[test]
    fn the_layer_loader_and_the_state_directory_agree() {
        // The local layer and the ledger must be in the same directory, and
        // `local.toml` must be one file with one name. Both are delegated
        // rather than repeated; this is the test that says so.
        let home = Path::new("/home/someone");
        for xdg in [None, Some(OsStr::new("/srv/state"))] {
            let dir = StateDir::resolve_in(home, xdg);
            let resolved = crate::config::layers::state_dir(home, xdg);
            assert_eq!(dir.root(), resolved);
            assert_eq!(
                dir.local_toml(),
                crate::config::layers::local_layer_path(&resolved),
            );
        }
    }

    #[test]
    fn two_homes_resolve_to_two_state_directories() {
        let a = StateDir::resolve(Path::new("/tmp/a"));
        let b = StateDir::resolve(Path::new("/tmp/b"));
        assert_ne!(a.root(), b.root());
        assert!(a.root().starts_with("/tmp/a"));
        assert!(b.root().starts_with("/tmp/b"));
    }

    #[test]
    fn resolution_ignores_the_process_environment() {
        let home = guarded_home();
        // Whatever `$XDG_STATE_HOME` holds in this process — and the suite
        // mutates no environment variable, so it holds whatever the developer's
        // shell set — `resolve` reads none of it and answers under the home it
        // was given. The only way the value reaches resolution is as an
        // argument, which is what lets two tempdir homes get two independent
        // state directories.
        assert_eq!(
            StateDir::resolve(home.path()).root(),
            home.child(".local/state/bx"),
        );
        assert_eq!(
            StateDir::resolve_in(home.path(), Some(OsStr::new("/somewhere/else"))).root(),
            Path::new("/somewhere/else/bx"),
        );
    }

    #[test]
    fn the_state_directory_is_never_inside_the_config_repo() {
        let home = Path::new("/home/someone");
        let state = StateDir::resolve(home);
        let config = crate::paths::config_root_in(home, None);
        assert!(!state.root().starts_with(&config));
        assert!(!config.starts_with(state.root()));
    }

    #[test]
    fn ensure_creates_the_state_directory_at_0700() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        assert!(dir.root().is_dir());
        assert_eq!(mode_of(dir.root()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_creates_restore_and_shell_at_0700() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        assert_eq!(mode_of(&dir.restore()), Mode::PRIVATE_DIR);
        assert_eq!(mode_of(&dir.shell()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_is_idempotent() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("first");
        let before: Vec<_> = std::fs::read_dir(dir.root())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        dir.ensure().expect("second");
        let after: Vec<_> = std::fs::read_dir(dir.root())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(before, after);
        assert_eq!(mode_of(dir.root()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_tightens_a_group_readable_state_directory() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("first");
        std::fs::set_permissions(dir.root(), std::fs::Permissions::from_mode(0o755))
            .expect("widen");
        std::fs::set_permissions(dir.restore(), std::fs::Permissions::from_mode(0o750))
            .expect("widen");
        dir.ensure().expect("second");
        assert_eq!(mode_of(dir.root()), Mode::PRIVATE_DIR);
        assert_eq!(mode_of(&dir.restore()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn repairing_a_directorys_mode_says_so_through_tracing() {
        // r4 round 2 (COV1): round 1's repair reached `store.rs` only. No test
        // in the repository installed a subscriber reachable from here, so
        // this warning's argument expressions ran zero times and deleting the
        // macro whole left the suite green — and this is the only signal a
        // user gets that bx narrowed a directory they own, which is what
        // decision 50 was sanctioned on.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("first");
        std::fs::set_permissions(dir.root(), std::fs::Permissions::from_mode(0o755))
            .expect("widen");
        let (result, said) = crate::state::store::capture::capturing(|| dir.ensure());
        result.expect("second");
        assert!(
            said.contains("the bx state directory was 0755, not 0700"),
            "{said}"
        );
        assert!(said.contains("reachable beyond its owner"), "{said}");
        assert!(said.contains(&dir.root().display().to_string()), "{said}");

        // A mode wrong only in the owner bits is repaired too, and says so
        // without claiming anyone else could reach it.
        std::fs::set_permissions(dir.root(), std::fs::Permissions::from_mode(0o500))
            .expect("narrow");
        let (result, said) = crate::state::store::capture::capturing(|| dir.ensure());
        result.expect("third");
        assert!(
            said.contains("the bx state directory was 0500, not 0700"),
            "{said}"
        );
        assert!(!said.contains("reachable beyond its owner"), "{said}");
    }

    #[test]
    fn ensure_sets_a_directory_that_is_not_0700_back_to_it() {
        // r4 round 2 (CL3): the repair fired on `is_shared` — `mode & 0o077` —
        // which is structurally unable to see a mode wrong in the OWNER bits,
        // so a `0500` state directory was deliberately left, and every later
        // write into it failed `EACCES` with no repair and no diagnostic. The
        // lock file is repaired on inequality for exactly this reason; one
        // rule now governs both.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("first");
        for wrong in [0o500, 0o600, 0o755, 0o770] {
            std::fs::set_permissions(dir.shell(), std::fs::Permissions::from_mode(wrong))
                .expect("set");
            dir.ensure().expect("second");
            assert_eq!(mode_of(&dir.shell()), Mode::PRIVATE_DIR, "from {wrong:04o}",);
        }
    }

    #[test]
    fn ensure_creates_missing_ancestors_without_tightening_them() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");

        // The umask is whatever the test runner's is, so the assertion is
        // relative: an ancestor gets the same mode an ordinary `mkdir` would.
        let control = home.child("control");
        std::fs::create_dir(&control).expect("control");
        assert_eq!(mode_of(&home.child(".local")), mode_of(&control));
        assert_eq!(mode_of(&home.child(".local/state")), mode_of(&control));
    }

    #[test]
    fn ensure_reports_a_file_occupying_the_state_directory_path() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        home.write(".local/state/bx", "not a directory");
        let err = dir.ensure().expect_err("must fail");
        assert!(
            matches!(&err, Error::NotADirectory { path } if path == dir.root()),
            "unexpected error: {err}",
        );
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn ensure_reports_a_file_occupying_a_subdirectory_path() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        home.write(".local/state/bx/restore", "not a directory");
        let err = dir.ensure().expect_err("must fail");
        assert!(
            matches!(&err, Error::NotADirectory { path } if *path == dir.restore()),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn ensure_reports_an_uncreatable_directory() {
        let home = guarded_home();
        // A file, not a directory, in the ancestor chain: `create_dir_all`
        // cannot descend through it.
        home.write(".local", "not a directory");
        let dir = StateDir::resolve(home.path());
        let err = dir.ensure().expect_err("must fail");
        assert!(matches!(err, Error::CreateDir { .. }), "got {err}");
    }

    #[test]
    fn a_directory_mkdir_refuses_is_reported_naming_it() {
        // r3 round 1 (C6): every earlier failure was in the ancestors, so a
        // `mkdir` of the directory itself failing was never reached, and
        // reading it as success survived mutation.
        let dir = tempfile::tempdir().expect("tempdir");
        let long = dir.path().join("d".repeat(256));
        let err = ensure_dir(&long, Mode::PRIVATE_DIR).expect_err("a 256-byte name");
        assert!(
            matches!(&err, Error::CreateDir { path, source }
                if *path == long
                    && source.raw_os_error() == Some(Errno::NAMETOOLONG.raw_os_error())),
            "got {err}",
        );
    }

    #[test]
    fn a_shared_directory_that_refuses_to_be_narrowed_is_reported_naming_it() {
        // r3 round 2b (P7R4-COV3): `tighten`'s `chmod` failing was never
        // reached. procfs refuses every mode change on a process's own
        // directory, to root as well, and that directory is `0555`: shared, so
        // `tighten` tries to narrow it, and nothing about it can change.
        let own = std::fs::canonicalize("/proc/self").expect("this process's /proc directory");
        let found = mode_of(&own);
        assert!(found.is_shared(), "{own:?} is {found}");

        let err = tighten(&own, Mode::PRIVATE_DIR).expect_err("procfs refuses the chmod");
        assert!(
            matches!(&err, Error::CreateDir { path, source }
                if *path == own && source.raw_os_error() == Some(Errno::PERM.raw_os_error())),
            "got {err}",
        );
        assert_eq!(mode_of(&own), found, "left as it was");
    }

    #[test]
    fn a_quarantine_name_appends_rather_than_replacing_the_extension() {
        assert_eq!(
            StateDir::quarantine(Path::new("/s/bx/ledger.mpk")),
            PathBuf::from("/s/bx/ledger.mpk.corrupt"),
        );
        assert_eq!(
            StateDir::quarantine_nth(Path::new("/s/bx/ledger.mpk"), 0),
            PathBuf::from("/s/bx/ledger.mpk.corrupt"),
        );
        assert_eq!(
            StateDir::quarantine_nth(Path::new("/s/bx/ledger.mpk"), 12),
            PathBuf::from("/s/bx/ledger.mpk.corrupt.12"),
        );
    }

    #[test]
    fn without_rename_noreplace_the_fallback_skips_a_taken_name_and_replaces_no_quarantine() {
        // Coverage review, round 5: the check-then-rename fallback for a
        // filesystem that rejects `RENAME_NOREPLACE` with `EINVAL` never ran,
        // and both mutants of its occupied-name guard survived. The listing
        // already counts every occupied name, so the guard matters only for a
        // name taken between the listing and the rename: the seam reports
        // `EINVAL` for every rename, and takes the first candidate it is
        // offered, the way a racing writer would.
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
        let path = dir.path().join("v.mpk");
        let earlier = StateDir::quarantine_nth(&path, 1);
        std::fs::write(&earlier, b"an earlier quarantine").expect("seed");
        std::fs::write(&path, b"damaged").expect("seed");

        let raced = StateDir::quarantine_nth(&path, 2);
        let taken = raced.clone();
        let mut calls = 0;
        let aside = noreplace_seam::with(
            move |candidate| {
                calls += 1;
                assert!(calls <= 8, "the fallback never settled on a name");
                if candidate == taken.as_path() && !taken.exists() {
                    std::fs::write(&taken, b"taken after the listing").expect("race");
                }
                true
            },
            || move_aside(&path, &lock),
        )
        .expect("moved aside through the fallback");

        assert_eq!(aside, StateDir::quarantine_nth(&path, 3));
        assert_eq!(std::fs::read(&aside).expect("moved"), b"damaged");
        assert_eq!(
            std::fs::read(&raced).expect("kept"),
            b"taken after the listing"
        );
        assert_eq!(
            std::fs::read(&earlier).expect("kept"),
            b"an earlier quarantine"
        );
        assert!(std::fs::symlink_metadata(&path).is_err(), "the file moved");

        // Without the seam, the same directory takes the next number natively.
        std::fs::write(&path, b"damaged again").expect("seed");
        assert_eq!(
            move_aside(&path, &lock).expect("moved aside"),
            StateDir::quarantine_nth(&path, 4),
        );
    }

    #[test]
    fn a_quarantine_number_that_cannot_be_followed_leaves_the_lowest_free_one() {
        // r3 round 1 (L1a): a crafted top number, `<name>.corrupt.<u64::MAX>`,
        // left no number after the highest, so every later quarantine of the
        // file failed with "no free quarantine name".
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
        let path = dir.path().join("v.mpk");
        let crafted = StateDir::quarantine_nth(&path, u64::MAX);
        std::fs::write(&crafted, b"crafted").expect("seed");

        std::fs::write(&path, b"damaged").expect("seed");
        let aside = move_aside(&path, &lock).expect("a free name exists");
        assert_eq!(aside, StateDir::quarantine(&path));
        assert_eq!(std::fs::read(&aside).expect("moved"), b"damaged");

        std::fs::write(&path, b"damaged again").expect("seed");
        let aside = move_aside(&path, &lock).expect("a free name exists");
        assert_eq!(aside, StateDir::quarantine_nth(&path, 1));
        assert_eq!(std::fs::read(&crafted).expect("kept"), b"crafted");
    }

    #[test]
    fn another_directorys_lock_moves_nothing_aside() {
        // Review round 4: `move_aside` ignored which directory its lock
        // guarded, so A's lock quarantined B's ledger while B's own bx could be
        // saving it.
        let a = guarded_home();
        let b = guarded_home();
        let lock_a = ExclusiveLock::acquire(&StateDir::resolve(a.path())).expect("A's lock");
        let dir_b = StateDir::resolve(b.path());
        dir_b.ensure().expect("ensure");
        std::fs::write(dir_b.ledger(), b"damaged").expect("seed");

        let err = move_aside(&dir_b.ledger(), &lock_a).expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("not the lock"), "{err}");
        assert_eq!(std::fs::read(dir_b.ledger()).expect("in place"), b"damaged");
        assert!(!StateDir::quarantine(&dir_b.ledger()).exists());

        let lock_b = ExclusiveLock::acquire(&dir_b).expect("B's lock");
        let aside = move_aside(&dir_b.ledger(), &lock_b).expect("B's own lock moves it");
        assert_eq!(aside, StateDir::quarantine(&dir_b.ledger()));
    }

    #[test]
    fn a_linked_state_directory_is_refused_for_read_or_write_beyond_its_owner_and_nothing_else() {
        // Review round 4: the refusal counted execute bits, so a `0711` target
        // was refused as "readable beyond its owner", which is untrue.
        fn link_to(mode: u32) -> (crate::testing::GuardedHome, PathBuf, StateDir) {
            let home = guarded_home();
            let target = home.child("elsewhere");
            std::fs::create_dir_all(&target).expect("target");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
            std::os::unix::fs::symlink(&target, home.child(".local/state/bx")).expect("symlink");
            let dir = StateDir::resolve(home.path());
            (home, target, dir)
        }

        // Search permission exposes no name nobody knows and no 0600 file.
        for mode in [0o700, 0o711, 0o701, 0o710] {
            let (_home, target, dir) = link_to(mode);
            dir.ensure()
                .unwrap_or_else(|e| panic!("{mode:04o} refused: {e}"));
            assert_eq!(mode_of(&target), Mode::from_bits(mode), "never chmodded");
            assert_eq!(mode_of(&dir.restore()), Mode::PRIVATE_DIR);
        }

        // Group or other read or write is refused — group included, whether or
        // not the group is a user-private one. 0775 is Fedora's umask-002 default.
        for mode in [0o775, 0o770, 0o750, 0o720, 0o705, 0o703] {
            let (_home, target, dir) = link_to(mode);
            let err = dir.ensure().expect_err("must refuse");
            assert!(
                matches!(&err, Error::SharedLinkedDir { mode: found, .. }
                    if *found == Mode::from_bits(mode)),
                "{mode:04o}: got {err}",
            );
            let message = err.to_string();
            assert!(message.contains(&format!("{mode:04o}")), "{message}");
            assert!(message.contains("read or write"), "{message}");
            assert_eq!(mode_of(&target), Mode::from_bits(mode), "never chmodded");
            assert!(!target.join("restore").exists(), "nothing was put in it");
        }
    }

    #[test]
    fn a_linked_state_directory_others_can_search_is_refused_while_local_toml_is_not_private() {
        // Review round 5: a linked `0711` directory was accepted on the ground
        // that every file in it is `0600`, but `local.toml` is hand-written and
        // has a name anyone knows; an unlinked `0711` directory is narrowed.
        fn linked(
            dir_mode: u32,
            local: Option<u32>,
        ) -> (crate::testing::GuardedHome, PathBuf, StateDir) {
            let home = guarded_home();
            let target = home.child("elsewhere");
            std::fs::create_dir_all(&target).expect("target");
            if let Some(file_mode) = local {
                let file = target.join("local.toml");
                std::fs::write(&file, "[vars]\n").expect("local.toml");
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(file_mode))
                    .expect("chmod file");
            }
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(dir_mode))
                .expect("chmod dir");
            std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
            std::os::unix::fs::symlink(&target, home.child(".local/state/bx")).expect("symlink");
            let dir = StateDir::resolve(home.path());
            (home, target, dir)
        }

        for (dir_mode, file_mode) in [
            (0o711, 0o644),
            (0o701, 0o604),
            (0o710, 0o640),
            (0o711, 0o622),
        ] {
            let (_home, target, dir) = linked(dir_mode, Some(file_mode));
            let err = dir
                .ensure()
                .expect_err(&format!("{dir_mode:04o} with {file_mode:04o}"));
            assert!(
                matches!(
                    &err,
                    Error::ExposedLocalLayer { path, mode, file, file_mode: found, .. }
                        if path == dir.root() && *mode == Mode::from_bits(dir_mode)
                            && *file == dir.local_toml()
                            && *found == Mode::from_bits(file_mode)
                ),
                "got {err}",
            );
            let message = err.to_string();
            for needle in [
                "local.toml".to_string(),
                format!("{dir_mode:04o}"),
                format!("{file_mode:04o}"),
                "chmod 600".to_string(),
                "chmod go-x".to_string(),
            ] {
                assert!(message.contains(&needle), "missing {needle:?}: {message}");
            }
            assert_eq!(
                mode_of(&target),
                Mode::from_bits(dir_mode),
                "never chmodded"
            );
            assert_eq!(
                mode_of(&target.join("local.toml")),
                Mode::from_bits(file_mode),
                "never chmodded",
            );
            assert!(!target.join("restore").exists(), "nothing was put in it");
        }

        // No search permission, a private `local.toml`, or none at all.
        for (dir_mode, local) in [
            (0o700, Some(0o644)),
            (0o711, Some(0o600)),
            (0o711, Some(0o400)),
            (0o711, None),
        ] {
            let (_home, target, dir) = linked(dir_mode, local);
            dir.ensure()
                .unwrap_or_else(|e| panic!("{dir_mode:04o} with {local:?} refused: {e}"));
            assert_eq!(
                mode_of(&target),
                Mode::from_bits(dir_mode),
                "never chmodded"
            );
        }
    }

    /// A home whose state directory is a link to `elsewhere/` at `mode`.
    fn linked_state(mode: u32) -> (crate::testing::GuardedHome, PathBuf, StateDir) {
        let home = guarded_home();
        let target = home.child("elsewhere");
        std::fs::create_dir_all(&target).expect("target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).expect("chmod");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&target, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());
        (home, target, dir)
    }

    #[test]
    fn a_linked_local_toml_is_judged_where_the_file_is() {
        // r3 round 1 (L2): the file a `local.toml` link names was judged by
        // its mode alone, so a `0644` file in a `0700` directory no other
        // account can reach was refused.
        for (layers_mode, exposed) in [
            (0o700, false),
            (0o500, false),
            (0o755, true),
            (0o710, true),
            (0o701, true),
        ] {
            let (home, _target, dir) = linked_state(0o711);
            let layers = home.child("layers");
            std::fs::create_dir_all(&layers).expect("layers");
            let real = layers.join("local.toml");
            std::fs::write(&real, "[values]\n").expect("local.toml");
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644))
                .expect("chmod file");
            std::fs::set_permissions(&layers, std::fs::Permissions::from_mode(layers_mode))
                .expect("chmod layers");
            std::os::unix::fs::symlink(&real, dir.local_toml()).expect("symlink");

            let result = dir.ensure();
            std::fs::set_permissions(&layers, std::fs::Permissions::from_mode(0o700))
                .expect("restore");
            if exposed {
                let err = result.expect_err(&format!("{layers_mode:04o}: others can open it"));
                assert!(
                    matches!(
                        &err,
                        Error::ExposedLocalLayer { path, mode, file, file_mode, .. }
                            if path == dir.root() && *mode == Mode::from_bits(0o711)
                                && *file == dir.local_toml()
                                && *file_mode == Mode::from_bits(0o644)
                    ),
                    "{layers_mode:04o}: got {err}",
                );
            } else {
                result.unwrap_or_else(|e| panic!("{layers_mode:04o}: refused: {e}"));
                drop(ExclusiveLock::acquire(&dir).expect("acquire"));
            }
            assert_eq!(mode_of(&real), Mode::from_bits(0o644), "never chmodded");
        }
    }

    #[test]
    fn an_exposed_local_toml_behind_a_private_ancestor_is_refused_without_claiming_anyone_can_open_it()
     {
        // r3 round 2b (decision 47): the refusal judges only the linked
        // directory and the file, which is conservative; but its message said
        // "anyone who knows its name can open it", which is false when an
        // ancestor no other account can search stands in the way.
        let home = guarded_home();
        let private = home.child("private");
        let target = private.join("state");
        std::fs::create_dir_all(&target).expect("target");
        let file = target.join("local.toml");
        std::fs::write(&file, "[vars]\n").expect("local.toml");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
            .expect("chmod file");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o711))
            .expect("chmod dir");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("chmod parent");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&target, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());
        let real = std::fs::canonicalize(&target).expect("canonical target");

        let err = dir.ensure().expect_err("the refusal stays");
        assert!(
            matches!(
                &err,
                Error::ExposedLocalLayer { path, target, mode, file, file_mode }
                    if path == dir.root() && *target == real
                        && *mode == Mode::from_bits(0o711)
                        && *file == dir.local_toml()
                        && *file_mode == Mode::from_bits(0o644)
            ),
            "got {err}",
        );
        let message = err.to_string();
        assert!(
            !message.contains("anyone who knows its name can open it"),
            "claims anyone can open it: {message}",
        );
        for needle in [
            "0711".to_string(),
            "0644".to_string(),
            format!("chmod 600 {}", dir.local_toml().display()),
            format!("chmod go-x {}", real.display()),
        ] {
            assert!(message.contains(&needle), "missing {needle:?}: {message}");
        }
        assert_eq!(mode_of(&target), Mode::from_bits(0o711), "never chmodded");
        assert_eq!(mode_of(&file), Mode::from_bits(0o644), "never chmodded");
        assert!(!target.join("restore").exists(), "nothing was put in it");
    }

    #[test]
    fn a_local_toml_link_that_leads_to_no_file_exposes_nothing() {
        // r3 round 1 (L2): `metadata` followed the link, so one that loops or
        // runs through a file was `Error::Read` from every `ensure`, lock and
        // save, and one to a directory was judged by the directory's mode. The
        // layer loader reports a looping or dangling `local.toml` itself.
        for case in ["loop", "dangling", "through a file", "a directory"] {
            let (home, _target, dir) = linked_state(0o711);
            let far = match case {
                "loop" => dir.local_toml(),
                "dangling" => home.child("nowhere.toml"),
                "through a file" => {
                    home.write("a-file", "not a directory");
                    home.child("a-file/local.toml")
                }
                _ => {
                    let open = home.child("a-dir");
                    std::fs::create_dir_all(&open).expect("a-dir");
                    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))
                        .expect("chmod");
                    open
                }
            };
            std::os::unix::fs::symlink(&far, dir.local_toml()).expect("symlink");

            dir.ensure()
                .unwrap_or_else(|e| panic!("{case}: ensure refused: {e}"));
            drop(ExclusiveLock::acquire(&dir).unwrap_or_else(|e| panic!("{case}: {e}")));
            drop(super::super::SharedLock::acquire(&dir).unwrap_or_else(|e| panic!("{case}: {e}")));
            assert_eq!(
                std::fs::read_link(dir.local_toml()).expect("link"),
                far,
                "{case}: left as it was",
            );
        }
    }

    #[test]
    fn a_local_toml_that_cannot_be_examined_is_an_error_naming_it() {
        // r3 round 1 (C1): a failure other than "no such file" was unreached,
        // and reading it as "no file" survived mutation.
        if rustix::process::geteuid().is_root() {
            // Mode bits deny nothing to root, so the condition cannot be staged.
            return;
        }
        // Others can search the directory, and its owner cannot.
        let (_home, target, dir) = linked_state(0o611);
        let result = dir.ensure();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).expect("restore");
        let err = result.expect_err("the file cannot be looked for");
        assert!(
            matches!(&err, Error::Read { path, .. } if *path == dir.local_toml()),
            "got {err}",
        );

        // A link to a file in a directory nobody can search.
        let (home, _target, dir) = linked_state(0o711);
        let sealed = home.child("sealed");
        std::fs::create_dir_all(&sealed).expect("sealed");
        std::fs::write(sealed.join("local.toml"), "[values]\n").expect("local.toml");
        std::os::unix::fs::symlink(sealed.join("local.toml"), dir.local_toml()).expect("symlink");
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).expect("seal");
        let result = dir.ensure();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).expect("restore");
        let err = result.expect_err("the linked file cannot be examined");
        assert!(
            matches!(&err, Error::Read { path, .. } if *path == dir.local_toml()),
            "got {err}",
        );
    }

    #[test]
    fn a_linked_local_toml_whose_real_path_cannot_be_resolved_is_an_error_naming_it() {
        // r3 round 2b (P7R4-COV2): resolving a linked `local.toml` to find the
        // directory that holds it failing was never reached. A link the kernel
        // follows, to a file whose real path is longer than `PATH_MAX`, can be
        // examined but not resolved.
        //
        // The over-long real path is staged as a *chain* of short links: each
        // one names a single 200-byte component under the link before it, so
        // no symlink target grows past ~204 bytes and no path handed to a
        // syscall is long either. A filesystem that caps one symlink target
        // well below `PATH_MAX` — XFS caps it at 1024 bytes — stages this as
        // readily as any other. The chain grows until `canonicalize` of the
        // cursor itself is the failure under test, so the length that is
        // enough is measured here rather than assumed.
        let (home, _target, dir) = linked_state(0o711);
        let part = "d".repeat(200);
        std::fs::create_dir(home.child("deep")).expect("deep");
        let mut cursor = PathBuf::from("deep");
        let mut links = 0_u32;
        loop {
            match std::fs::canonicalize(home.child(&cursor)) {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(Errno::NAMETOOLONG.raw_os_error()) => break,
                Err(e) => panic!("staging the chain at {}: {e}", cursor.display()),
            }
            // The kernel refuses more than 40 nested links, and each step here
            // costs one. A real path over `PATH_MAX` needs ~21 of them, so
            // failing to get there is a surprise worth reporting, not a skip.
            assert!(links < 32, "no real path over PATH_MAX after {links} links");
            let next = cursor.join(&part);
            std::fs::create_dir(home.child(&next)).expect("one component deeper");
            let link = PathBuf::from(format!("s{links}"));
            std::os::unix::fs::symlink(&next, home.child(&link)).expect("a short link to it");
            cursor = link;
            links += 1;
        }
        let near = home.child(&cursor);
        std::fs::write(near.join("local.toml"), "[values]\n").expect("local.toml");
        std::os::unix::fs::symlink(near.join("local.toml"), dir.local_toml()).expect("symlink");
        assert!(
            std::fs::metadata(dir.local_toml()).is_ok_and(|meta| meta.is_file()),
            "the link can be followed",
        );

        let err = dir
            .ensure()
            .expect_err("the linked file cannot be resolved");
        assert!(
            matches!(&err, Error::Read { path, source }
                if *path == dir.local_toml()
                    && source.raw_os_error() == Some(Errno::NAMETOOLONG.raw_os_error())),
            "got {err}",
        );
    }

    #[test]
    fn a_symlinked_state_directory_is_accepted() {
        let home = guarded_home();
        let real = home.child("elsewhere");
        std::fs::create_dir_all(&real).expect("real");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("private");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&real, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        assert!(real.join("restore").is_dir());
        assert_eq!(mode_of(&real.join("restore")), Mode::PRIVATE_DIR);
    }

    #[test]
    fn a_state_directory_owned_by_another_account_is_refused_naming_both_uids() {
        // r4 round 1 (CL5): the module established "this is ours" from file
        // type, link-ness, nlink and mode, and never from the owner, so a
        // `~/.local/state/bx` owned by another uid at 0700 was accepted as
        // bx's own — and bx would write the user's displaced private bytes
        // into a directory that account controls.
        let ours = rustix::process::geteuid().as_raw();
        assert!(check_owner(Path::new("/s/bx"), ours).is_ok(), "our own");

        let err = check_owner(Path::new("/s/bx"), ours.wrapping_add(1)).expect_err("another uid");
        assert!(
            matches!(&err, Error::ForeignOwner { path, owner, ours: mine }
                if path == Path::new("/s/bx")
                    && *owner == ours.wrapping_add(1)
                    && *mine == ours),
            "got {err}",
        );
        assert!(err.to_string().contains("Move it aside"), "{err}");

        // r4 round 2 (COV6): the call site used to be reached only when this
        // process was unprivileged, so on a root CI runner nothing exercised
        // `tighten`'s `check_owner` at all and a mutant deleting the call
        // survived there. Root is the case that can *stage* a foreign owner
        // rather than the case that cannot, so it gets its own staging.
        let home = guarded_home();
        let (foreign, owner) = if rustix::process::geteuid().is_root() {
            // `/` is this process's own directory now, so one is made and
            // given away — which only root can do.
            let made = home.child("theirs");
            std::fs::create_dir(&made).expect("mkdir");
            let nobody = rustix::fs::Uid::from_raw(65_534);
            rustix::fs::chown(&made, Some(nobody), None).expect("chown");
            (made, 65_534)
        } else {
            // `/` is a real directory this account does not own, and `tighten`
            // used to judge it by its mode alone: 0755 is shared, so it would
            // reach for the `chmod` and report whatever that failed with.
            (PathBuf::from("/"), 0)
        };
        let before = mode_of(&foreign);
        let err = tighten(&foreign, Mode::PRIVATE_DIR).expect_err("not ours");
        assert!(
            matches!(&err, Error::ForeignOwner { path, owner: uid, .. }
                if *path == foreign && *uid == owner),
            "got {err}",
        );
        assert_eq!(mode_of(&foreign), before, "untouched");
    }

    #[test]
    fn a_state_directory_that_is_a_link_to_nowhere_names_the_link_and_its_target() {
        // r4 round 1 (D6): `tighten`'s `metadata` follows the link, so a
        // dangling one was reported as `Error::Read{ENOENT}` — "reading
        // ~/.local/state/bx: No such file or directory" — which is untrue of a
        // path the user can see, and names no remedy. Reachable whenever the
        // state directory is a link to storage that is not mounted.
        let home = guarded_home();
        let gone = home.child("unmounted");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&gone, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());

        let err = dir.ensure().expect_err("must refuse");
        assert!(
            matches!(&err, Error::DanglingStateDir { path, target }
                if path == dir.root() && *target == gone),
            "got {err}",
        );
        assert!(err.to_string().contains("remove the link"), "{err}");

        // A loop, and a link whose path runs through a file, are the same
        // condition and must read the same way — and `restore/` inside a real
        // state directory is judged by the same code.
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        std::fs::create_dir_all(dir.root()).expect("root");
        home.write("a-file", "not a directory");
        std::os::unix::fs::symlink(home.child("a-file/under-it"), dir.restore())
            .expect("through a file");
        let err = dir.ensure().expect_err("must refuse");
        assert!(
            matches!(&err, Error::DanglingStateDir { path, .. } if *path == dir.restore()),
            "got {err}",
        );
    }

    #[test]
    fn a_symlinked_state_directory_onto_a_shared_directory_is_refused_not_chmodded() {
        // Review round 3: `tighten` followed the link and narrowed the
        // directory it named — one bx did not create, and may share with others.
        let home = guarded_home();
        let shared = home.child("shared");
        std::fs::create_dir_all(&shared).expect("shared");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).expect("wide");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&shared, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());

        let err = dir.ensure().expect_err("must refuse");
        assert!(
            matches!(
                &err,
                Error::SharedLinkedDir { path, mode }
                    if path == dir.root() && *mode == Mode::from_bits(0o755)
            ),
            "got {err}",
        );
        assert!(err.to_string().contains("chmod go-rw"), "{err}");
        assert_eq!(mode_of(&shared), Mode::from_bits(0o755), "left as it was");
        assert!(!shared.join("restore").exists(), "nothing was put in it");
    }
}
