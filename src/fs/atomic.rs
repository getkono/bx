//! The one place a byte reaches the filesystem.
//!
//! Every write bx performs goes through here, and the sequence is fixed:
//!
//! 1. [`observe`] the destination with `symlink_metadata`, capturing what is
//!    there, its mode, and its bytes. One read, reused by `plan`'s comparison
//!    and by the prior state a reversal needs — so there is one decision site
//!    rather than a `plan` one and an `apply` one.
//! 2. a temporary file **in the destination directory**, so the later `rename`
//!    is same-filesystem and therefore atomic. A `/tmp` on another mount would
//!    turn it into a copy-then-delete with a visible half-written window.
//! 3. the mode set with `fchmod` **before any content is written** — all of it
//!    but a declared setuid or setgid bit, which a write would clear.
//! 4. the content written, the set-id bits added if declared, then `fsync`ed.
//! 5. the prior state recorded — [`Filled::new_entry`] assembles it and
//!    [`crate::state::Ledger::record`] makes it durable — **before** the
//!    rename, so a crash after the rename still has a recoverable prior state.
//! 6. the destination `lstat`ed again and compared with what step 1 saw, and
//!    the write refused if it changed.
//! 7. `rename`.
//! 8. an `fsync` of the **destination directory**, so the rename itself
//!    survives a power loss. This is the step implementations omit, and without
//!    it the directory entry can be lost even though the file's data was
//!    synced.
//!
//! # Why the mode is set before the content
//!
//! Not tidiness: a decrypted secret is written through [`Staged::commit`], and
//! its plaintext must never exist at a wider mode than its final one, not even
//! for the microseconds between `write` and `fchmod`.
//!
//! `fchmod` is also the only call that makes a declared mode *authoritative*.
//! `tempfile`'s `Builder::permissions` routes the mode through
//! `OpenOptions::mode()`, which the kernel masks with the process `umask`, so a
//! target declared `0644` under `umask 077` would be created `0600` and stay
//! there. `fchmod(2)` is not masked. `tempfile` creates at `0600` and a `umask`
//! can only narrow that, so the temporary file is never *wider* than its final
//! mode at any instant either.
//!
//! The one exception is a declared setuid or setgid bit. The kernel clears
//! both on a write by a process without `CAP_FSETID`, so a set-id bit set
//! before the content would be gone after it: the second `plan` would read
//! `Modify`, and the ledger would record a mode that is not on disk. [`stage`]
//! sets every other bit, and [`Staged::fill`] adds the set-id bits after the
//! content and before the `fsync`. The empty file is therefore *narrower* than
//! its declared mode, never wider, and the content is at exactly that mode
//! before it is durable or visible at the destination.
//!
//! # Why the write is staged rather than one call
//!
//! [`stage`] → [`Staged::fill`] → [`Filled::publish`] exposes the boundary
//! between the `fsync` of the temporary file and the `rename`. A write-ahead
//! journal records its intent exactly there — before that point a crash leaves
//! the destination untouched, after it the destination is already replaced — and
//! it identifies a leftover temporary file by the path [`Staged::temp_path`]
//! reports. An opaque `write(dest, bytes, mode)` cannot express that boundary,
//! and it cannot let a test observe the mode of the temporary file while it is
//! still empty. [`Staged::commit`] is the shorthand for callers with nothing to
//! interpose.
//!
//! # What is checked before the rename, and what is not
//!
//! Staging widens the gap between looking at the destination and replacing
//! it: the content is written and synced, the ledger records the prior, and a
//! journal appends its intent, all in between. An editor that saves in that gap
//! would lose the save to the rename, and the prior bx recorded would predate
//! it, so `rm` could not bring it back either. [`observe`] therefore records a
//! [`Stamp`] — device, inode, size, and modification and status-change times to
//! the nanosecond — and [`Filled::publish`] `lstat`s the destination again as
//! the last step before the rename, refusing with [`Error::Changed`] unless it
//! is the same file, unchanged, or still absent.
//!
//! That narrows the gap to the distance between one `lstat` and one
//! `rename(2)`; it does not close it. A change landing in those microseconds is
//! still replaced. Closing it needs `renameat2(RENAME_EXCHANGE)`, a check of
//! what came out, and an exchange back on a mismatch — which would publish bx's
//! content for an instant even when refusing, and is not done. A timestamp
//! that does not move is also not seen: on a filesystem with coarse timestamps,
//! an in-place edit of the same length within one clock tick of the
//! observation leaves the stamp identical. Kernels with multigrain timestamps
//! give a fine-grained time to a change made just after the file's times were
//! queried, which is exactly what `observe` did.
//!
//! # What "restores exactly" covers
//!
//! The prior state is the displaced file's **bytes and its twelve mode bits**,
//! and that is what `rm` restores. Replacing a file creates a new inode, and
//! nothing else of the old one is carried over or recorded: not its extended
//! attributes (`user.*`), not its POSIX ACL (`system.posix_acl_access`), and
//! not its SELinux label, owner and group, or timestamps. A file bx replaced,
//! and a file `rm` restored, has none of them.
//!
//! Deliberately. Copying an ACL onto the replacement would grant access the
//! declared mode does not — a named-user entry survives a `0640` — and a
//! declared mode is authoritative. Recording any of it needs a field in the
//! ledger's prior, which belongs to the state directory rather than to the
//! writer. `a_replaced_file_keeps_neither_its_xattrs_nor_its_acl` pins the
//! behaviour, so changing it is a decision rather than an accident.
//!
//! # What the tests here do and do not establish
//!
//! The *observable* half is pinned throughout: the temporary file is in the
//! destination directory and at its final mode while still empty, an abandoned
//! or failed write leaves the previous file and no temporary behind, a
//! published one leaves only the destination, and the prior state a reversal
//! needs is in the ledger before the rename.
//!
//! The **durability half** has no observable result — an `fsync`'s only
//! witness is a reader that survives a power loss — so it is pinned through
//! the calls instead. Every `fsync` and the `rename` go through
//! `fs::durable`, which notes each call to a per-thread recorder in the
//! test build only. The tests assert that [`Staged::fill`] syncs the temporary
//! file before it returns, and that [`Filled::publish`] opens the directory,
//! renames, and only then syncs the directory, in that order. Deleting either
//! sync, or moving it across the rename, fails a test.
//!
//! What remains held by review is the one-line body of each function in
//! `durable` — that `sync_file` really calls `sync_all` — because nothing in
//! a unit test observes the kernel. That is a far smaller claim than "every
//! call site remembered to sync", and it is not one a change to this file can
//! break.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rustix::io::Errno;
use tempfile::NamedTempFile;

use super::durable;
use super::mode::{Kind, Mode};
use crate::paths::Portable;
use crate::report::Action;
use crate::state::{ContentHash, Mechanism, NewEntry, PriorBytes};

/// The prefix every temporary file bx creates in a destination directory
/// carries.
///
/// Reserved: an orphan left by a crash is attributable to bx rather than
/// anonymous, which is what lets recovery and `doctor` find one. Nothing else
/// in bx may use this prefix for a different purpose.
pub const TEMP_PREFIX: &str = ".bx-";

/// Everything that can go wrong writing a file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The destination has no parent directory, so there is nowhere to put the
    /// temporary file the atomic write needs.
    #[error("{} has no parent directory to write into", .0.display())]
    NoParent(PathBuf),
    /// The destination exists and is not a regular file, so writing bytes to it
    /// would mean replacing something that is not a file.
    #[error("{path} is {kind}, not a file bx can write", path = .path.display())]
    NotAFile {
        /// The destination.
        path: PathBuf,
        /// What is actually there.
        kind: Kind,
    },
    /// The destination is a symlink the user created.
    ///
    /// `rename(2)` onto a link's path replaces **the link itself**, so writing
    /// "through" one would silently convert a link the user made into a regular
    /// file. bx refuses instead.
    #[error(
        "{} is a symlink; bx will not replace a link you created. \
         Point the target at the file the link resolves to, or remove the link",
        .0.display()
    )]
    Symlink(PathBuf),
    /// The destination's parent is on the filesystem but does not resolve to a
    /// directory: a dangling symlink, a symlink loop, or a non-directory.
    ///
    /// Distinct from a parent that is simply missing, which bx creates.
    /// `mkdir` cannot create a directory through a dangling link, so this is
    /// announced as a [`Action::Conflict`] by `compare` rather than left for
    /// `apply` to discover as an `ENOENT` naming a temporary file.
    #[error("{reason}")]
    UnusableParent {
        /// The parent directory, as it was named.
        path: PathBuf,
        /// What is wrong with it, in the same words `plan` prints.
        reason: String,
    },
    /// A read failed.
    #[error("reading {}: {source}", .path.display())]
    Read {
        /// The path being read.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A write, `chmod`, `fsync` or `rename` failed.
    #[error("writing {}: {source}", .path.display())]
    Write {
        /// The path being written, or the directory the temporary file was to
        /// be created in when the failure happened before the file existed.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// What is at the path is no longer what bx observed there, so acting on
    /// the observation would replace or change something bx never looked at.
    ///
    /// Raised by [`Filled::publish`] when the destination changed between
    /// [`stage`] and the rename — an editor saving, a symlink swapped in, a
    /// file appearing where there was none — and by [`ensure_dir`] when a
    /// directory target is no longer what `plan` saw. Nothing is replaced: the
    /// temporary file is removed and the path keeps what is there now.
    #[error(
        "{} changed after bx looked at it ({detail}); nothing was replaced. Run plan again",
        .path.display()
    )]
    Changed {
        /// The path that changed.
        path: PathBuf,
        /// What bx saw, and what is there now.
        detail: String,
    },
    /// A path the ledger would record cannot be made portable against the
    /// home: it is not valid UTF-8, or the home is not absolute.
    ///
    /// [`crate::paths::Portable::from_path`] refuses rather than renaming such
    /// a path, so the entry is refused rather than recorded under a key that
    /// names a different file.
    #[error("{} cannot be recorded: {source}", .path.display())]
    NotPortable {
        /// The path that could not be made portable.
        path: PathBuf,
        /// Why.
        #[source]
        source: crate::paths::Error,
    },
}

impl Error {
    /// The path the failure is about.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::NoParent(path)
            | Self::Symlink(path)
            | Self::NotAFile { path, .. }
            | Self::UnusableParent { path, .. }
            | Self::Read { path, .. }
            | Self::Write { path, .. }
            | Self::Changed { path, .. }
            | Self::NotPortable { path, .. } => path,
        }
    }
}

/// What is at a destination right now.
///
/// Captured once, by [`observe`], and reused: `plan` compares against it and a
/// reversal restores from it. `bytes` is `None` for anything that is not a
/// regular file, because there is nothing to compare or restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The destination, as it was named. Not canonicalised.
    pub path: PathBuf,
    /// What is there.
    pub kind: Kind,
    /// Its mode, or `None` when nothing is there.
    pub mode: Option<Mode>,
    /// Its bytes, for a regular file only.
    pub bytes: Option<Vec<u8>>,
    /// The destination's immediate parent directory.
    pub parent: Option<Parent>,
    /// Which file this was and when it last changed, or `None` when nothing is
    /// there.
    ///
    /// What [`Filled::publish`] checks the destination against immediately
    /// before the rename, so a file that changed after it was observed is not
    /// replaced, and a prior state recorded from this observation is never
    /// older than the file it displaces.
    pub stamp: Option<Stamp>,
}

impl Observed {
    /// The prior state, in the shape [`crate::state::Ledger::record`] takes.
    ///
    /// The conversion lives here rather than in the ledger because this is the
    /// only place that knows how the prior state was captured — one
    /// `symlink_metadata` and one read, before anything was touched.
    ///
    /// Anything that is not a regular file becomes [`PriorBytes::Absent`]. That
    /// is not a loss: a write only ever proceeds over a regular file or nothing
    /// at all, so the other kinds never reach a `record` call.
    #[must_use]
    pub fn prior_bytes(&self) -> PriorBytes {
        match (&self.bytes, self.mode) {
            (Some(bytes), Some(mode)) => PriorBytes::Bytes {
                bytes: bytes.clone(),
                mode,
            },
            _ => PriorBytes::Absent,
        }
    }

    /// The digest of the bytes that are there now, for a regular file.
    ///
    /// What a mode-only change records as `written`: the content is not being
    /// replaced, so the bytes bx leaves behind are the bytes already there.
    #[must_use]
    pub fn digest(&self) -> Option<ContentHash> {
        self.bytes.as_deref().map(ContentHash::of)
    }
}

/// Which file a path named, and when that file last changed, as one `lstat`
/// reported it.
///
/// Device and inode say *which* file: an editor that saves by writing a new
/// file and renaming it over the old one, or a symlink swapped in, changes
/// them. Size, and the modification and status-change times to the
/// nanosecond, say whether that file changed *in place*: a write moves `mtime`,
/// and a `chmod`, a `chown`, a new hard link or an extended attribute moves
/// `ctime`. Compared whole and never interpreted, so there is no field a
/// caller could compare on its own and get a different answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    /// The stamp of the file `meta` describes.
    fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

/// A destination's immediate parent directory.
///
/// Carried because a `0600` file inside a `0755` directory is a defect worth
/// reporting, and the mode of a directory bx is about to invent is knowable
/// before it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    /// The directory, as it was named. Not canonicalised.
    pub path: PathBuf,
    /// What resolving it found.
    pub state: ParentState,
    /// Where the directory really is, when `path` itself is a symlink to it.
    ///
    /// Only for reporting. bx writes *through* a symlinked parent but will not
    /// chmod a directory through one — [`ensure_dir`] refuses a link — so the
    /// only remedy for a wide one is to change the directory at the far end,
    /// and a report that does not name it gives the user nothing to act on.
    /// `None` for a parent that is not a link, and for one that does not
    /// resolve.
    pub resolved: Option<PathBuf>,
}

/// What a destination's parent turned out to be.
///
/// "Absent" and "there but unresolvable" are separated deliberately. They look
/// identical to a single `metadata` call — both report `ENOENT` — and treating
/// them alike made `plan` announce a `Create` that `apply` could not perform,
/// because `mkdir` cannot create a directory through a dangling symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentState {
    /// A directory, at this mode. A symlinked parent reports the mode of the
    /// directory it resolves to — see [`observe_parent`].
    Present(Mode),
    /// Nothing is on the path at all. bx would create it at this mode.
    Absent(Mode),
    /// Something is on the path and it does not resolve to a directory: a
    /// dangling symlink, a symlink loop, or a non-directory. The string is the
    /// cause, in the words `plan` prints and the error message `apply` returns.
    Unusable(String),
}

impl Parent {
    /// The mode that governs a file in this directory, once there is one.
    ///
    /// `None` when the parent does not resolve, because there is then no
    /// directory whose mode could govern anything.
    #[must_use]
    pub const fn mode(&self) -> Option<Mode> {
        match self.state {
            ParentState::Present(mode) | ParentState::Absent(mode) => Some(mode),
            ParentState::Unusable(_) => None,
        }
    }

    /// Whether the directory is already there.
    #[must_use]
    pub const fn exists(&self) -> bool {
        matches!(self.state, ParentState::Present(_))
    }

    /// Why the parent cannot be written into, when it cannot.
    #[must_use]
    pub fn unusable(&self) -> Option<&str> {
        match &self.state {
            ParentState::Unusable(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Read what is at `dest`, following no symlink.
///
/// `symlink_metadata`, never `canonicalize`: a symlink is reported as a
/// [`Kind::Symlink`] rather than as whatever it points at, and `plan` therefore
/// never depends on resolving a path beyond the one the target declared.
///
/// # Errors
///
/// [`Error::NoParent`] when `dest` has no parent component, and [`Error::Read`]
/// when the destination or its parent exists but cannot be read.
pub fn observe(dest: &Path) -> Result<Observed, Error> {
    let dir = parent_of(dest)?;
    let observed_parent = observe_parent(dir)?;

    // A parent that does not resolve leaves nothing to learn from the
    // destination: stat'ing it would fail with the parent's error rather than
    // the file's, and the verdict is the parent's either way.
    if observed_parent.unusable().is_some() {
        return Ok(Observed {
            path: dest.to_path_buf(),
            kind: Kind::Absent,
            mode: None,
            bytes: None,
            parent: Some(observed_parent),
            stamp: None,
        });
    }
    let parent = Some(observed_parent);

    let Some(meta) = optional_metadata(dest)? else {
        return Ok(Observed {
            path: dest.to_path_buf(),
            kind: Kind::Absent,
            mode: None,
            bytes: None,
            parent,
            stamp: None,
        });
    };

    let kind = Kind::from(meta.file_type());
    let bytes = if kind == Kind::File {
        Some(std::fs::read(dest).map_err(|source| Error::Read {
            path: dest.to_path_buf(),
            source,
        })?)
    } else {
        None
    };

    Ok(Observed {
        path: dest.to_path_buf(),
        kind,
        mode: Some(mode_of(&meta)),
        bytes,
        parent,
        // From the `lstat` taken before the read, so a change that lands
        // between the two makes the stamp older than the bytes, and the check
        // before the rename refuses rather than trusting either.
        stamp: Some(Stamp::of(&meta)),
    })
}

/// What bx wants at a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desired<'a> {
    /// The content.
    pub bytes: &'a [u8],
    /// The mode, already resolved — see [`Mode::resolve`].
    pub mode: Mode,
}

/// The difference between what is at a destination and what bx wants there.
///
/// One function produces this for both `plan` and `apply`, which is how `apply`
/// is prevented from doing work `plan` did not announce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// What bx will do.
    pub action: Action,
    /// Whether the bytes on disk differ from the bytes bx wants there.
    ///
    /// `true` for an absent destination, including when the desired content is
    /// empty: "there is no file" and "there is an empty file" are different
    /// states and the ledger records them differently, so they are not equal
    /// here either. `false` for a conflict, where there are no comparable bytes.
    pub content_drift: bool,
    /// The mode found and the mode wanted, when they differ.
    pub mode_drift: Option<(Mode, Mode)>,
    /// The one-line explanation `plan` prints after the path.
    ///
    /// For a mode drift this is exactly `mode 0644 -> 0600`, so a renderer
    /// needs no mode-specific knowledge of its own.
    pub note: Option<String>,
    /// A parent directory that grants more than the declared mode does.
    ///
    /// Reported, never corrected: an existing directory is the user's, and bx
    /// surfaces drift rather than resolving it behind their back. The remedy is
    /// to declare the directory as a target with the mode it should have —
    /// except when the parent is a symlink, which a directory target refuses.
    /// Then the note names the directory the link resolves to and says to
    /// `chmod` that directory itself.
    pub parent_note: Option<String>,
}

/// Compare what is at a destination with what bx wants there.
///
/// Reads nothing: it works entirely from an [`Observed`] captured earlier, so
/// `plan` and `apply` reach the same verdict from the same bytes.
///
/// * [`Action::Unchanged`] — kind, bytes and mode all match.
/// * [`Action::Create`] — nothing is there.
/// * [`Action::Modify`] — a regular file whose bytes **or** mode differ. A mode
///   difference alone is still a `Modify`, with `content_drift == false`, and
///   `apply` closes it with [`set_mode`] rather than by rewriting the file.
/// * [`Action::Conflict`] — a directory, a symlink, or anything else that is
///   not a regular file.
#[must_use]
pub fn compare(observed: &Observed, desired: &Desired<'_>) -> Outcome {
    // A parent that does not resolve settles the verdict on its own: there is
    // no directory to write into and none bx can create, so announcing
    // anything but a conflict would announce work `apply` cannot do.
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return Outcome {
            action: Action::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(reason.to_string()),
            parent_note: None,
        };
    }

    let parent_note = observed.parent.as_ref().and_then(|parent| {
        let mode = parent.mode()?;
        if !mode.is_wider_than(desired.mode) {
            return None;
        }
        if let Some(resolved) = &parent.resolved {
            // Declaring the link as a directory target would be refused, so
            // the report names the directory that can actually be narrowed.
            return Some(format!(
                "{} is a symlink to {}, which is {mode}, wider than the {} this file declares; \
                 bx will not chmod a directory through a link, so chmod {} itself",
                parent.path.display(),
                resolved.display(),
                desired.mode,
                resolved.display(),
            ));
        }
        let verb = if parent.exists() {
            "is"
        } else {
            "will be created at"
        };
        Some(format!(
            "{} {verb} {mode}, wider than the {} this file declares",
            parent.path.display(),
            desired.mode,
        ))
    });

    let (action, content_drift, mode_drift, note) = match observed.kind {
        Kind::Absent => (Action::Create, true, None, None),
        Kind::File => {
            let content_drift = observed.bytes.as_deref() != Some(desired.bytes);
            let mode_drift = observed
                .mode
                .filter(|found| *found != desired.mode)
                .map(|found| (found, desired.mode));
            let action = if content_drift || mode_drift.is_some() {
                Action::Modify
            } else {
                Action::Unchanged
            };
            let note = mode_drift.map(|(found, wanted)| format!("mode {found} -> {wanted}"));
            (action, content_drift, mode_drift, note)
        }
        Kind::Dir => (
            Action::Conflict,
            false,
            None,
            Some("a directory, where the target declares a file".to_string()),
        ),
        Kind::Symlink => (
            Action::Conflict,
            false,
            None,
            Some("a symlink; bx will not replace a link you created".to_string()),
        ),
        Kind::Other => (
            Action::Conflict,
            false,
            None,
            Some("not a regular file".to_string()),
        ),
    };

    Outcome {
        action,
        content_drift,
        mode_drift,
        note,
        parent_note,
    }
}

/// A write that has a temporary file at its final mode and no content yet.
///
/// Created by [`stage`]. Dropping it removes the temporary file and leaves the
/// destination exactly as it was.
#[derive(Debug)]
pub struct Staged(Pending);

/// A write whose content is on disk and `fsync`ed, and which has not yet
/// replaced the destination.
///
/// The boundary a write-ahead journal records its intent at: before
/// [`Filled::publish`] the destination is untouched, after it the destination
/// is already the new content. Dropping this removes the temporary file and
/// leaves the destination exactly as it was.
#[derive(Debug)]
pub struct Filled {
    pending: Pending,
    /// The digest of the bytes now in the temporary file. Not optional: a
    /// `Filled` cannot exist without them, so no accessor on it can fail.
    written: ContentHash,
}

/// The state both phases carry. Deliberately not public: the phase is the API.
#[derive(Debug)]
struct Pending {
    temp: NamedTempFile,
    dest: PathBuf,
    mode: Mode,
    prior: Observed,
    /// Parent directories this write invented, deepest first, so a reversal can
    /// remove them in order and leave nothing behind.
    created_dirs: Vec<PathBuf>,
}

impl Pending {
    fn temp_path(&self) -> &Path {
        self.temp.path()
    }
}

/// Begin a write: a temporary file in the destination directory, at `mode`,
/// with no content.
///
/// A declared setuid or setgid bit is the exception: it is left off until
/// [`Staged::fill`] has written the content, because the write would clear it.
///
/// Missing parent directories are created at [`Mode::DEFAULT_DIR`] — a target
/// deep under `~/.config` must not need a directory declaration for every
/// component. An *existing* directory is never chmod'd: it is the user's. When
/// that leaves a parent wider than the declared mode, [`compare`] reports it,
/// and the remedy is to declare the directory as a target of its own — or, for
/// a parent that is a symlink, to `chmod` the directory it resolves to, which
/// the report names.
///
/// A directory created here and then abandoned — because the temporary file
/// could not be made, or because the write was never committed — is left in
/// place. It is empty and at the mode a `mkdir` would have given it, the next
/// attempt reuses it, and removing it would race any other write that had
/// already begun using it.
///
/// # Errors
///
/// [`Error::Symlink`] when the destination is a symlink, [`Error::NotAFile`]
/// when it is a directory or a device node, [`Error::NoParent`] when it has no
/// parent component, and [`Error::Write`] when the parent cannot be created or
/// the temporary file cannot be made.
pub fn stage(dest: &Path, mode: Mode) -> Result<Staged, Error> {
    let prior = observe(dest)?;
    // The parent first: it is the verdict `compare` announced, and refusing
    // here is what keeps `apply` from doing anything `plan` did not say.
    if let Some(parent) = prior.parent.as_ref()
        && let Some(reason) = parent.unusable()
    {
        return Err(Error::UnusableParent {
            path: parent.path.clone(),
            reason: reason.to_string(),
        });
    }
    if !prior.kind.is_writable_destination() {
        return Err(match prior.kind {
            Kind::Symlink => Error::Symlink(dest.to_path_buf()),
            kind => Error::NotAFile {
                path: dest.to_path_buf(),
                kind,
            },
        });
    }

    let dir = parent_of(dest)?;
    let created_dirs = create_missing_dirs(dir, Mode::DEFAULT_DIR)?;

    let temp = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(dir)
        .map_err(|source| Error::Write {
            path: dir.to_path_buf(),
            source,
        })?;

    // Before any content. `tempfile` creates at 0600 and `fchmod` is not masked
    // by the umask, so the file is at its final permission bits while it is
    // still empty and was never wider than them at any instant. The set-id bits
    // wait for `fill`: the write clears them — see `SET_ID`.
    fchmod(temp.as_file(), without_set_id(mode), temp.path())?;

    Ok(Staged(Pending {
        temp,
        dest: dest.to_path_buf(),
        mode,
        prior,
        created_dirs,
    }))
}

impl Staged {
    /// The destination this write will replace.
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.0.dest
    }

    /// The temporary file, in the destination directory, at its final mode.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.0.temp_path()
    }

    /// The mode this write declares.
    ///
    /// The temporary file already has it, except for a setuid or setgid bit,
    /// which [`Staged::fill`] adds after the content.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.0.mode
    }

    /// What was at the destination before this write — the prior state a
    /// reversal restores from.
    #[must_use]
    pub const fn prior(&self) -> &Observed {
        &self.0.prior
    }

    /// Write the content and `fsync` it, without touching the destination.
    ///
    /// # Errors
    ///
    /// [`Error::Write`] wrapping the first failing syscall.
    pub fn fill(mut self, bytes: &[u8]) -> Result<Filled, Error> {
        let temp_path = self.0.temp.path().to_path_buf();
        let fail = |source| Error::Write {
            path: temp_path.clone(),
            source,
        };
        self.0.temp.write_all(bytes).map_err(&fail)?;
        // After the content and before the sync, so the sync covers it. A
        // set-id bit set earlier would already be gone: the kernel clears
        // S_ISUID, and S_ISGID alongside group execute, on a write by a process
        // without CAP_FSETID.
        if self.0.mode.bits() & SET_ID != 0 {
            fchmod(self.0.temp.as_file(), self.0.mode, &temp_path)?;
        }
        durable::sync_file(self.0.temp.as_file(), &temp_path).map_err(&fail)?;
        let written = ContentHash::of(bytes);
        Ok(Filled {
            pending: self.0,
            written,
        })
    }

    /// Fill and publish in one step, for a caller with nothing to interpose.
    ///
    /// # Errors
    ///
    /// Whatever [`Staged::fill`] or [`Filled::publish`] returns.
    pub fn commit(self, bytes: &[u8]) -> Result<(), Error> {
        self.fill(bytes)?.publish()
    }

    /// Discard the write. The temporary file is removed and the destination is
    /// untouched. Identical to dropping it; named so a caller can say so.
    pub fn abandon(self) {
        drop(self);
    }
}

impl Filled {
    /// The destination this write will replace.
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.pending.dest
    }

    /// The temporary file, holding the final content at the final mode.
    ///
    /// The path a journal records, so a leftover temporary file found after a
    /// crash is identifiable as this write's rather than some other one's.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.pending.temp_path()
    }

    /// The mode the content is already at.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.pending.mode
    }

    /// What was at the destination before this write.
    #[must_use]
    pub const fn prior(&self) -> &Observed {
        &self.pending.prior
    }

    /// The digest of the bytes now in the temporary file.
    ///
    /// Computed while filling rather than re-read afterwards, so the ledger
    /// records the digest of what was actually written rather than the digest of
    /// whatever is at the path by the time somebody looks.
    #[must_use]
    pub const fn written(&self) -> ContentHash {
        self.written
    }

    /// The parent directories this write invented, deepest first.
    ///
    /// Empty when every component already existed. A reversal removes these in
    /// order, so a target that created `~/.config/a/b` leaves nothing behind.
    #[must_use]
    pub fn created_dirs(&self) -> &[PathBuf] {
        &self.pending.created_dirs
    }

    /// The ledger entry for this write, assembled from what the writer knows.
    ///
    /// The writer supplies the prior bytes and their mode, the digest of what it
    /// wrote, the mode it set, and the directories it invented. The caller
    /// supplies the two facts only it has: the home directory to make the paths
    /// portable against, and how bx attached to the file.
    ///
    /// Call it **before** [`Filled::publish`] and hand the result to
    /// [`crate::state::Ledger::record`], which fsyncs the prior bytes into
    /// `restore/` before it returns. A crash after the rename is then
    /// recoverable, because the bytes that were displaced are already durable.
    ///
    /// # Errors
    ///
    /// [`Error::NotPortable`] if the destination or a created directory is not
    /// valid UTF-8, or `home` is not absolute: such a path has no key the
    /// ledger could record it under without naming a different file.
    pub fn new_entry(&self, home: &Path, mechanism: Mechanism) -> Result<NewEntry, Error> {
        let portable = |path: &Path| {
            Portable::from_path(path, home).map_err(|source| Error::NotPortable {
                path: path.to_path_buf(),
                source,
            })
        };
        Ok(NewEntry::new(
            portable(&self.pending.dest)?,
            self.written(),
            self.pending.mode,
            mechanism,
        )
        .with_prior(self.pending.prior.prior_bytes())
        .with_created_dirs(
            self.pending
                .created_dirs
                .iter()
                .map(|dir| portable(dir))
                .collect::<Result<_, _>>()?,
        ))
    }

    /// `rename` the temporary file onto the destination, then `fsync` the
    /// destination directory so the rename itself is durable.
    ///
    /// A hard link to the destination is **not** followed: the destination is
    /// replaced by name, so any other link to the old inode keeps the old
    /// content. That is inherent to an atomic rename and is why a mode-only
    /// change goes through [`set_mode`] instead.
    ///
    /// The destination directory is opened **before** the rename and `fsync`ed
    /// after it. Opening a directory needs read permission on it and renaming
    /// into it does not, so in a `0300` directory an open placed after the
    /// rename would fail with the new content already in place. Opened first,
    /// that failure happens while the destination is still untouched, which is
    /// what [`write_atomically`]'s contract promises for an `Err`.
    ///
    /// Immediately before the rename the destination is `lstat`ed again and
    /// compared with the [`Stamp`] [`stage`] observed. Anything else there — an
    /// edit saved in place or by rename, a symlink swapped in, a file where
    /// there was none, a file removed — is refused rather than replaced, so a
    /// write never destroys bytes bx did not observe and the recorded prior is
    /// never older than what it displaces. The window between that `lstat` and
    /// the `rename(2)` remains; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`Error::Changed`] when the destination is no longer what [`stage`]
    /// observed; nothing is replaced. [`Error::Write`] wrapping the failing
    /// `open` of the directory, `rename`, or `fsync`. The temporary file is
    /// removed either way. Only a failing `fsync` of the directory is returned
    /// after the destination was replaced.
    pub fn publish(self) -> Result<(), Error> {
        let Self {
            pending:
                Pending {
                    temp,
                    dest,
                    mode,
                    prior,
                    ..
                },
            ..
        } = self;

        let dir = parent_of(&dest)?;
        let dir_fail = |source| Error::Write {
            path: dir.to_path_buf(),
            source,
        };
        let handle = durable::Dir::open(dir).map_err(dir_fail)?;
        // The last thing before the rename, so the window it leaves open is as
        // narrow as it can be. Refusing drops `temp`, which removes it.
        verify_unchanged(&prior)?;
        durable::rename(temp, &dest).map_err(|e| Error::Write {
            path: dest.clone(),
            source: e.error,
        })?;
        handle.sync().map_err(dir_fail)?;

        tracing::debug!(dest = %dest.display(), %mode, "wrote a file atomically");
        Ok(())
    }

    /// Discard the write. The temporary file is removed and the destination is
    /// untouched. Identical to dropping it; named so a caller can say so.
    pub fn abandon(self) {
        drop(self);
    }
}

/// Replace `path` with `bytes`, atomically, at `mode`.
///
/// After this returns, `path` holds either all of `bytes` or — if the write
/// failed — exactly what it held before, or, for [`Error::Changed`], whatever
/// changed it after bx looked. No temporary file is left behind in
/// either case, and the rename is durable: a power loss after the call cannot
/// resurrect the previous content.
///
/// The shorthand for [`stage`] + [`Staged::commit`]. A caller that must record
/// something between the `fsync` and the `rename` uses the phases directly.
///
/// # Errors
///
/// Whatever [`stage`] or [`Staged::commit`] returns.
pub fn write_atomically(path: &Path, bytes: &[u8], mode: Mode) -> Result<(), Error> {
    stage(path, mode)?.commit(bytes)
}

/// Set the mode of an existing file or directory, in place.
///
/// This is how a mode-only drift is closed. A rewrite would be wrong twice
/// over: it replaces the inode, breaking any hard link the user made and any
/// process holding the file open, and it would announce a `Modify` whose diff
/// is empty, which `plan` cannot render honestly. `chmod` is the minimal
/// operation that closes the drift, and it is fully reversible from the mode
/// recorded before it.
///
/// # Errors
///
/// [`Error::Symlink`] when `path` is a symlink — bx does not change the mode of
/// a link's target through the link — and [`Error::Write`] when the `chmod`
/// fails.
pub fn set_mode(path: &Path, mode: Mode) -> Result<(), Error> {
    // chmod(2) follows symlinks and Linux has no AT_SYMLINK_NOFOLLOW for it, so
    // the link is excluded by looking first. The remaining window is a race with
    // the invoking user against their own home directory, which is not a
    // boundary bx defends: they can chmod their own files directly.
    if let Some(meta) = optional_metadata(path)?
        && Kind::from(meta.file_type()) == Kind::Symlink
    {
        return Err(Error::Symlink(path.to_path_buf()));
    }

    rustix::fs::chmod(path, mode.into()).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    tracing::debug!(path = %path.display(), %mode, "set a file mode");
    Ok(())
}

/// Compare what is at a **declared directory** target with the mode bx wants
/// it at — the `plan` half of a directory target.
///
/// Reads nothing, exactly like [`compare`]: `plan` for a directory target is
/// [`observe`] then this, and nothing on disk changes. The parent is classified
/// by the same [`ParentState`] a file's is, so a dangling symlink, a loop or a
/// non-directory anywhere above the path is a conflict here, not an `ENOENT`
/// for `apply` to discover.
///
/// * [`Action::Unchanged`] — a directory at `mode`.
/// * [`Action::Create`] — nothing is there; `path` will be created at `mode`
///   and any missing ancestor at [`Mode::DEFAULT_DIR`].
/// * [`Action::Modify`] — a directory at another mode, closed by [`set_mode`].
///   The note reads exactly `mode 0755 -> 0700`, as for a file.
/// * [`Action::Conflict`] — anything that is not a directory, including a
///   symlink to one: bx does not chmod a directory through a link.
#[must_use]
pub fn compare_dir(observed: &Observed, mode: Mode) -> Outcome {
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return Outcome {
            action: Action::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(reason.to_string()),
            parent_note: None,
        };
    }

    let conflict = |note: &str| (Action::Conflict, None, Some(note.to_string()));
    let (action, mode_drift, note) = match observed.kind {
        Kind::Absent => (Action::Create, None, None),
        Kind::Dir => match observed.mode.filter(|found| *found != mode) {
            None => (Action::Unchanged, None, None),
            Some(found) => (
                Action::Modify,
                Some((found, mode)),
                Some(format!("mode {found} -> {mode}")),
            ),
        },
        Kind::File => conflict("a file, where the target declares a directory"),
        Kind::Symlink => conflict("a symlink; bx will not change a directory through a link"),
        Kind::Other => conflict("not a directory"),
    };

    Outcome {
        action,
        // A directory has no content to drift.
        content_drift: false,
        mode_drift,
        note,
        parent_note: None,
    }
}

/// Make `path` the directory at `mode` that [`compare_dir`] announced — the
/// `apply` half of a declared directory target.
///
/// `planned` is the observation `plan` compared — the [`Observed`] it handed to
/// [`compare_dir`]. `ensure_dir` observes the path again and refuses with
/// [`Error::Changed`] unless [`compare_dir`] reaches the same verdict from both:
/// the same action, the same mode found for a `Modify`, the same cause for a
/// `Conflict`. A directory chmod'd after `plan` printed `Unchanged`, a directory
/// that appeared after `plan` printed `Create`, and a file that took the path
/// are refused rather than acted on, so `apply` never does work `plan` did not
/// announce. The refusal also covers a path taken between that second
/// observation and the `mkdir`: a `Create` succeeds only when this call is the
/// one that created the directory.
///
/// On agreement it performs **exactly** that action: nothing for `Unchanged`;
/// `mkdir` for `Create`, with `path` at `mode` and missing ancestors at
/// [`Mode::DEFAULT_DIR`]; [`set_mode`] for `Modify`; and nothing at all for
/// `Conflict`, which is reported rather than raised because it is a verdict
/// `plan` already printed. `plan` must use [`observe`] + [`compare_dir`], not
/// this.
///
/// It returns what a ledger needs to reverse it: the action, the observation
/// it acted on — so the mode a `Modify` overwrote is `prior.mode` — and the
/// directories it created, deepest first.
///
/// Two windows remain. A `chmod` landing between the second observation and
/// the [`set_mode`] is overwritten, as for any mode change (decision 6). And
/// when a `Create` is refused because the path was taken after the second
/// observation, an ancestor this call had already created is left in place,
/// empty, exactly as [`stage`] leaves one for an abandoned write.
///
/// # Errors
///
/// [`Error::Changed`] when the path is no longer what `plan` saw;
/// [`Error::Read`] when the path or its parent cannot be stat'd; and
/// [`Error::Write`] when a directory cannot be created or chmod'd.
pub fn ensure_dir(path: &Path, mode: Mode, planned: &Observed) -> Result<EnsuredDir, Error> {
    let fresh = observe(path)?;
    act_on_dir(path, mode, planned, fresh)
}

/// What [`ensure_dir`] did, and what a ledger needs to reverse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsuredDir {
    /// The action performed — the one `plan` announced.
    pub action: Action,
    /// What was at the path immediately before, which is what `plan` saw. For
    /// a `Modify` its `mode` is the mode that was overwritten.
    pub prior: Observed,
    /// The directories this call created, deepest first — the path itself
    /// and any ancestor it had to invent — which is the order a reversal
    /// removes them in. Empty unless `action` is `Create`.
    pub created_dirs: Vec<PathBuf>,
}

/// The half of [`ensure_dir`] after its own observation, separate so a test can
/// change the disk between the two.
fn act_on_dir(
    path: &Path,
    mode: Mode,
    planned: &Observed,
    fresh: Observed,
) -> Result<EnsuredDir, Error> {
    let announced = compare_dir(planned, mode);
    let outcome = compare_dir(&fresh, mode);
    // Equal outcomes are equal verdicts: the action, the mode found for a
    // `Modify`, and the cause of a `Conflict` are all part of one.
    if outcome != announced {
        return Err(Error::Changed {
            path: path.to_path_buf(),
            detail: format!("plan saw {}, and it is now {}", seen(planned), seen(&fresh)),
        });
    }

    let mut created_dirs = Vec::new();
    match outcome.action {
        Action::Create => {
            created_dirs = create_missing_dirs(path, mode)?;
            // The path itself is the deepest entry when this call made it. When
            // it is not there, something took the path between the observation
            // and the `mkdir` — somebody else's directory, or not a directory at
            // all — and neither is the create `plan` announced.
            if created_dirs.first().map(PathBuf::as_path) != Some(path) {
                let now = optional_metadata(path)?
                    .map_or(Kind::Absent, |meta| Kind::from(meta.file_type()));
                return Err(Error::Changed {
                    path: path.to_path_buf(),
                    detail: format!(
                        "plan saw nothing, and {now} took the path before bx could create it"
                    ),
                });
            }
            tracing::debug!(path = %path.display(), %mode, "created a directory");
        }
        Action::Modify => set_mode(path, mode)?,
        _ => {}
    }
    Ok(EnsuredDir {
        action: outcome.action,
        prior: fresh,
        created_dirs,
    })
}

/// What an observation of a directory target found, in the words a refusal
/// uses.
fn seen(observed: &Observed) -> String {
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return format!("a parent that does not resolve ({reason})");
    }
    match (observed.kind, observed.mode) {
        (Kind::Dir, Some(mode)) => format!("a directory at {mode}"),
        (kind, _) => kind.to_string(),
    }
}

/// Refuse unless `prior.path` is still what [`observe`] found there: the same
/// file with the same [`Stamp`], or still nothing at all.
///
/// # Errors
///
/// [`Error::Changed`] naming what moved, and [`Error::Read`] when the path can
/// no longer be stat'd.
fn verify_unchanged(prior: &Observed) -> Result<(), Error> {
    let now = optional_metadata(&prior.path)?
        .map(|meta| (Kind::from(meta.file_type()), Stamp::of(&meta)));
    let then = prior.stamp.map(|stamp| (prior.kind, stamp));
    if now == then {
        return Ok(());
    }
    let detail = match (then, now) {
        (_, None) => "it has been removed",
        (None, Some(_)) => "nothing was there, and something is now",
        (Some(_), Some(_)) => "it has been modified or replaced",
    };
    Err(Error::Changed {
        path: prior.path.clone(),
        detail: detail.to_string(),
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

/// `symlink_metadata`, with "nothing is there" as a value rather than an error.
///
/// Follows no symlink: for a destination, a link is a thing in its own right.
fn optional_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Whether a failed lookup means "this path does not lead anywhere" — nothing
/// there, a non-directory in the way, or a symlink loop — rather than "bx was
/// not allowed to look".
fn unresolvable_path(e: &std::io::Error) -> bool {
    // By errno rather than `ErrorKind`: `ErrorKind::FilesystemLoop` is not
    // stable, and one comparison for all three keeps them visibly alike.
    [Errno::NOENT, Errno::NOTDIR, Errno::LOOP]
        .iter()
        .any(|errno| e.raw_os_error() == Some(errno.raw_os_error()))
}

/// The mode bits out of a `stat` result.
fn mode_of(meta: &std::fs::Metadata) -> Mode {
    use std::os::unix::fs::PermissionsExt as _;

    Mode::from_bits(meta.permissions().mode())
}

/// The destination's parent, and the mode it has or would be created at.
///
/// Stat'd with `metadata`, which **follows symlinks** — deliberately the
/// opposite of the `symlink_metadata` [`observe`] uses for the destination
/// itself. The asymmetry is the policy rather than an oversight, and each half
/// follows from what bx does at that component:
///
/// * a symlink at the **final** component is refused, so the link itself is
///   what bx is deciding about and its own bits are the ones to report;
/// * a symlink at a **parent** component is written *through* — decision 2 —
///   so the directory that actually governs the write is the one the link
///   resolves to.
///
/// A symlink's own mode is always `0777` on Linux, so stat'ing the parent
/// without following would report a correctly hardened `~/.ssh` reached through
/// a dotfiles symlink as world-writable, and report it identically to a
/// genuinely world-writable one.
fn observe_parent(dir: &Path) -> Result<Parent, Error> {
    let state = parent_state(dir)?;
    // Resolved only for a parent that is itself a link to a directory. The
    // verdict never depends on it — `state` is already settled — so a
    // `realpath` that races and fails costs the report its far-end name and
    // nothing else.
    let resolved = match state {
        ParentState::Present(_)
            if std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink()) =>
        {
            std::fs::canonicalize(dir).ok()
        }
        _ => None,
    };
    Ok(Parent {
        path: dir.to_path_buf(),
        state,
        resolved,
    })
}

/// Resolve `dir`, separating "nothing is there" from "something is there that
/// does not resolve to a directory".
///
/// The separation is the point. `metadata` reports `ENOENT` for both a path
/// with nothing on it and a path that ends at a dangling symlink, and a
/// directory bx can create from one it cannot are not the same announcement.
fn parent_state(dir: &Path) -> Result<ParentState, Error> {
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => return Ok(ParentState::Present(mode_of(&meta))),
        Ok(_) => {
            return Ok(ParentState::Unusable(format!(
                "{} is not a directory, so bx cannot write a file inside it",
                dir.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            // The kernel refused to resolve the path — a symlink loop, most
            // often. If the component is readable as a link then the defect is
            // bx's to report. If it is not, the refusal may come from a
            // component further up, which the walk below finds; anything else
            // is a genuine read error.
            match std::fs::symlink_metadata(dir) {
                Ok(_) => {
                    return Ok(ParentState::Unusable(format!(
                        "{} does not resolve to a directory ({source}), so bx cannot write a file inside it",
                        dir.display()
                    )));
                }
                Err(e) if unresolvable_path(&e) => {}
                Err(_) => {
                    return Err(Error::Read {
                        path: dir.to_path_buf(),
                        source,
                    });
                }
            }
        }
    }

    // Nothing resolves at `dir`. That is ordinarily a directory bx will create,
    // but it is also what a dangling symlink, a symlink loop or a non-directory
    // anywhere along the path reports, and `mkdir` cannot create a directory
    // through any of them. The deepest component that is present at all
    // settles which it is. `ENOTDIR` and `ELOOP` on a component mean the
    // obstruction is further up, so the walk continues past them exactly as it
    // does past `ENOENT`.
    for ancestor in dir.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Err(e) if unresolvable_path(&e) => {}
            Err(source) => {
                return Err(Error::Read {
                    path: ancestor.to_path_buf(),
                    source,
                });
            }
            Ok(_) => {
                let resolves_to_a_directory =
                    std::fs::metadata(ancestor).is_ok_and(|meta| meta.is_dir());
                return if resolves_to_a_directory {
                    Ok(ParentState::Absent(Mode::DEFAULT_DIR))
                } else {
                    Ok(ParentState::Unusable(format!(
                        "{} does not resolve to a directory, so bx cannot create {} inside it",
                        ancestor.display(),
                        dir.display(),
                    )))
                };
            }
        }
    }
    Ok(ParentState::Absent(Mode::DEFAULT_DIR))
}

/// Create every missing component of `dir`: the ancestors bx had to invent at
/// [`Mode::DEFAULT_DIR`], and `dir` itself at `leaf_mode`.
///
/// Returns what it created, **deepest first**, which is the order a reversal
/// removes them in.
fn create_missing_dirs(dir: &Path, leaf_mode: Mode) -> Result<Vec<PathBuf>, Error> {
    // `ancestors` yields deepest first, so the collected prefix is already in
    // removal order; reversing it gives shallowest-first creation order.
    let missing: Vec<PathBuf> = dir
        .ancestors()
        // `ancestors` on a *relative* path ends with `""`, which names the
        // working directory. `symlink_metadata("")` reports `ENOENT` for it, so
        // without this it enters `missing` and `mkdir("")` fails naming the
        // empty path — an error message with no path in it, from a call that
        // had nothing to create. The working directory is always there and is
        // never bx's to invent.
        .filter(|path| !path.as_os_str().is_empty())
        .take_while(|path| matches!(optional_metadata(path), Ok(None)))
        .map(Path::to_path_buf)
        .collect();

    // Only what bx actually created goes in the list. A directory that appeared
    // between the stat and the `mkdir` is somebody else's, and a reversal that
    // removed it would be deleting a directory another tool made — Invariant 1,
    // with no way to notice afterwards, because the wrong list is durable on
    // disk by the time `bx rm` reads it.
    let mut created = Vec::with_capacity(missing.len());
    for path in missing.iter().rev() {
        let mode = if path == dir {
            leaf_mode
        } else {
            Mode::DEFAULT_DIR
        };
        if create_dir_at(path, mode)? {
            created.push(path.clone());
        }
    }
    // The walk above is shallowest first; a reversal wants deepest first.
    created.reverse();
    Ok(created)
}

/// `mkdir` one directory at exactly `mode`.
///
/// The mode is passed to `mkdir(2)` itself and then `chmod`'d, and both steps
/// are load-bearing in opposite directions. `mkdir`'s argument is masked by the
/// `umask`, so it can only ever produce something *narrower* than `mode` —
/// which is what keeps the directory from existing, even for an instant, at
/// bits wider than the ones declared for it. The `chmod` afterwards is not
/// masked, so it is what makes the declared mode authoritative.
///
/// `std::fs::create_dir` cannot do the first half: it issues
/// `mkdir(path, 0o777)` unconditionally, so under a default `umask` the
/// directory exists at `0755` until the `chmod` lands. The exposure is not the
/// contents — the directory is empty — it is the **descriptor**: a process that
/// opens it inside that window holds a handle whose access checks have already
/// passed, and the later `chmod` does not revoke it.
fn create_dir_at(path: &Path, mode: Mode) -> Result<bool, Error> {
    match rustix::fs::mkdir(path, mode.into()) {
        Ok(()) => {}
        // Somebody else created it between the stat and the mkdir. It is not
        // bx's directory then, so its mode is not bx's to set — and it is not
        // bx's to record as one it invented, because a reversal removes those.
        Err(Errno::EXIST) => return Ok(false),
        Err(source) => {
            return Err(Error::Write {
                path: path.to_path_buf(),
                source: source.into(),
            });
        }
    }
    // `mkdir`'s mode argument is masked by the umask; `chmod` is not.
    set_mode(path, mode)?;
    Ok(true)
}

/// The setuid and setgid bits.
///
/// The only mode bits a write can take away. The kernel clears S_ISUID, and
/// S_ISGID when group execute is set, on the first write to a file by a process
/// without `CAP_FSETID`, so a set-id mode applied before the content is gone
/// once the content lands. [`stage`] leaves them off the empty file and
/// [`Staged::fill`] adds them after the content and before the `fsync`, which
/// keeps both promises: never wider than the declared mode while empty, and
/// exactly the declared mode by the time anything can see the content.
const SET_ID: u32 = 0o6000;

/// `mode` without its setuid and setgid bits — see [`SET_ID`].
const fn without_set_id(mode: Mode) -> Mode {
    Mode::from_bits(mode.bits() & !SET_ID)
}

/// `fchmod`, so the mode is the declared one and not the declared one masked by
/// the process `umask`.
fn fchmod(file: &std::fs::File, mode: Mode, path: &Path) -> Result<(), Error> {
    rustix::fs::fchmod(file, mode.into()).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source: source.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::Mutex;

    use crate::state::{ExclusiveLock, Ledger, Prior, StateDir};
    use crate::testing::{GuardedHome, guarded_home};

    /// Serialises the one test that mutates the process `umask`.
    ///
    /// Held in addition to whatever lock the home guard takes, so the
    /// serialisation does not depend on the guard continuing to take one.
    /// Nothing else in the suite depends on the `umask` anyway — every write
    /// `fchmod`s and every directory bx creates is `chmod`'d — so a leak could
    /// not flip another assertion even without this.
    static UMASK: Mutex<()> = Mutex::new(());

    /// Serialises the one test that mutates the process working directory.
    ///
    /// Every other test in the suite addresses its files absolutely, so a leak
    /// could not flip another assertion; the lock is here so the two relative
    /// writes cannot race each other or a future third.
    static CWD: Mutex<()> = Mutex::new(());

    /// The mode on disk, following no symlink.
    fn mode_of_path(path: &Path) -> Mode {
        mode_of(&std::fs::symlink_metadata(path).expect("stat"))
    }

    /// Every name in a directory, sorted, so an orphan is visible.
    fn names_in(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        names.sort();
        names
    }

    /// A file seeded at an exact mode, the umask notwithstanding.
    fn seed(path: &Path, bytes: &[u8], mode: Mode) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("seed parent");
        }
        std::fs::write(path, bytes).expect("seed");
        set_mode(path, mode).expect("seed mode");
    }

    /// What bx wants, for the comparison tests.
    fn desired(bytes: &[u8], mode: Mode) -> Desired<'_> {
        Desired { bytes, mode }
    }

    /// The outcome for a destination under a guarded home.
    fn outcome_for(home: &GuardedHome, rel: &str, bytes: &[u8], mode: Mode) -> Outcome {
        let path = home.child(rel);
        let observed = observe(&path).expect("observe");
        compare(&observed, &desired(bytes, mode))
    }

    #[test]
    fn an_absent_destination_is_a_create() {
        let home = guarded_home();
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Create);
        assert!(outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
    }

    #[test]
    fn identical_content_and_mode_is_unchanged() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Unchanged);
        assert!(!outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
        assert!(!outcome.action.is_pending(), "a second plan must be empty");
    }

    #[test]
    fn identical_content_with_the_wrong_mode_is_a_modify() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"x", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Modify);
        assert!(
            !outcome.content_drift,
            "the bytes match; only the mode drifted",
        );
        assert_eq!(
            outcome.mode_drift,
            Some((Mode::DEFAULT_FILE, Mode::PRIVATE_FILE)),
        );
    }

    #[test]
    fn the_ssh_config_mode_drift_renders_the_operator_s_line() {
        let home = guarded_home();
        // The worked example: a config faithfully reproduced at 0644 that ssh
        // will not accept, declared 0600.
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Modify);
        assert_eq!(outcome.note.as_deref(), Some("mode 0644 -> 0600"));
        assert_eq!(outcome.action.symbol(), '~');
    }

    #[test]
    fn changed_content_with_a_matching_mode_is_a_modify() {
        let home = guarded_home();
        seed(&home.child("f"), b"old", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"new", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Modify);
        assert!(outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
    }

    #[test]
    fn a_directory_where_a_file_is_declared_is_a_conflict() {
        let home = guarded_home();
        std::fs::create_dir(home.child("f")).expect("occupy");
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert!(outcome.action.needs_attention());
        assert!(
            outcome
                .note
                .as_deref()
                .is_some_and(|n| n.contains("directory")),
            "{:?}",
            outcome.note,
        );
    }

    #[test]
    fn a_device_node_where_a_file_is_declared_is_a_conflict() {
        let home = guarded_home();
        let path = home.child("f");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            Mode::PRIVATE_FILE.into(),
            0,
        )
        .expect("mkfifo");
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert_eq!(outcome.note.as_deref(), Some("not a regular file"));
    }

    #[test]
    fn a_parent_wider_than_the_declared_mode_is_reported() {
        let home = guarded_home();
        // ~/.ssh at 0755 holding a 0600 config: exactly what the source
        // material produces, and exactly what ssh refuses to work with.
        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::DEFAULT_DIR).expect("chmod");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Unchanged, "the file itself is fine");
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(note.contains(".ssh"), "{note}");
        assert!(note.contains("is 0755"), "{note}");
        assert!(note.contains("wider than the 0600"), "{note}");
    }

    #[test]
    fn an_ordinary_parent_of_an_ordinary_file_is_not_reported() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".config")).expect("mkdir");
        set_mode(&home.child(".config"), Mode::DEFAULT_DIR).expect("chmod");
        seed(&home.child(".config/f"), b"x", Mode::DEFAULT_FILE);

        let outcome = outcome_for(&home, ".config/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.parent_note, None, "0755 over 0644 is not a finding");
    }

    #[test]
    fn a_parent_bx_has_yet_to_create_is_reported_before_it_exists() {
        let home = guarded_home();
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Create);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(note.contains("will be created at 0755"), "{note}");
    }

    #[test]
    fn a_symlinked_parent_reports_the_directory_it_resolves_to() {
        let home = guarded_home();
        // The mainstream dotfiles layout: ~/.ssh is a link into a repository,
        // and the directory at the far end is already hardened.
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::PRIVATE_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let observed = observe(&home.child(".ssh/config")).expect("observe");
        let parent = observed.parent.as_ref().expect("a parent");
        assert_eq!(
            parent.state,
            ParentState::Present(Mode::PRIVATE_DIR),
            "the resolved directory's 0700, not the link's own 0777",
        );

        let outcome = compare(&observed, &desired(b"Host *\n", Mode::PRIVATE_FILE));
        assert_eq!(outcome.parent_note, None, "a hardened parent is no finding");

        // The asymmetry, stated as an assertion: the *destination* is still
        // stat'd without following, so a link there is a link.
        assert_eq!(mode_of_path(&home.child(".ssh")).bits(), 0o777);
    }

    #[test]
    fn a_symlinked_parent_that_is_genuinely_wide_is_still_reported() {
        let home = guarded_home();
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(note.contains("is 0755"), "{note}");
        assert!(note.contains("wider than the 0600"), "{note}");
    }

    #[test]
    fn a_dangling_symlink_parent_is_a_conflict_rather_than_a_create() {
        let home = guarded_home();
        // ~/.config is a link into a dotfiles repository that is not checked
        // out yet. `metadata` reports ENOENT for it exactly as it would for a
        // directory that is simply missing.
        std::os::unix::fs::symlink("nowhere", home.child(".config")).expect("symlink");

        let outcome = outcome_for(&home, ".config/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(
            outcome.action,
            Action::Conflict,
            "a create bx cannot perform is not a create",
        );
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains(".config"), "{note}");
        assert!(note.contains("does not resolve to a directory"), "{note}");
        assert_eq!(outcome.parent_note, None);

        // And `apply` refuses the same way, naming the parent rather than a
        // temporary path the user cannot interpret.
        let err = write_atomically(&home.child(".config/f"), b"x", Mode::DEFAULT_FILE)
            .expect_err("must refuse");
        let Error::UnusableParent { path, .. } = &err else {
            panic!("expected UnusableParent, got {err:?}");
        };
        assert_eq!(path, &home.child(".config"));
        assert_eq!(err.to_string(), note);
        assert!(
            std::fs::symlink_metadata(home.child("nowhere")).is_err(),
            "nothing was created at the far end",
        );
    }

    #[test]
    fn a_dangling_symlink_above_the_parent_is_a_conflict_too() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child(".config")).expect("symlink");

        // The link is two components up, so the immediate parent is absent for
        // a second reason and `mkdir` cannot reach it either.
        let outcome = outcome_for(&home, ".config/bx/init.sh", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains(".config"), "{note}");

        let err = write_atomically(&home.child(".config/bx/init.sh"), b"x", Mode::DEFAULT_FILE)
            .expect_err("must refuse");
        assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
    }

    #[test]
    fn a_symlink_loop_at_a_parent_is_a_conflict() {
        let home = guarded_home();
        std::os::unix::fs::symlink("loop", home.child("loop")).expect("symlink");

        let outcome = outcome_for(&home, "loop/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains("loop"), "{note}");
        assert!(note.contains("does not resolve to a directory"), "{note}");

        let err =
            write_atomically(&home.child("loop/f"), b"x", Mode::DEFAULT_FILE).expect_err("refuse");
        assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
    }

    #[test]
    fn a_parent_that_is_a_regular_file_is_a_conflict() {
        let home = guarded_home();
        seed(&home.child("notadir"), b"a file", Mode::DEFAULT_FILE);

        let outcome = outcome_for(&home, "notadir/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert!(
            outcome
                .note
                .as_deref()
                .is_some_and(|note| note.contains("is not a directory")),
            "{:?}",
            outcome.note,
        );

        let err = write_atomically(&home.child("notadir/f"), b"x", Mode::DEFAULT_FILE)
            .expect_err("must refuse");
        assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
        assert_eq!(
            std::fs::read(home.child("notadir")).expect("read"),
            b"a file",
            "the file that was in the way is untouched",
        );
    }

    #[test]
    fn a_private_parent_is_not_reported() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::PRIVATE_DIR).expect("chmod");
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.parent_note, None);
    }

    #[test]
    fn observe_does_not_follow_a_symlink() {
        let home = guarded_home();
        seed(&home.child("real"), b"real", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        let observed = observe(&home.child("link")).expect("observe");
        assert_eq!(observed.kind, Kind::Symlink);
        assert_eq!(observed.bytes, None, "a link has no content of its own");
    }

    #[test]
    fn the_temporary_file_is_created_in_the_destination_directory() {
        let home = guarded_home();
        let dest = home.child("f");
        let staged = stage(&dest, Mode::DEFAULT_FILE).expect("stage");

        assert_eq!(staged.temp_path().parent(), dest.parent());
        assert_eq!(staged.dest(), dest);
        let name = staged
            .temp_path()
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .to_string();
        assert!(name.starts_with(TEMP_PREFIX), "{name}");
        assert!(
            names_in(home.path()).contains(&OsString::from(&name)),
            "the temporary file is in the destination directory, not $TMPDIR",
        );
    }

    #[test]
    fn the_mode_is_final_before_any_content_exists() {
        let home = guarded_home();
        let staged = stage(&home.child("secret"), Mode::PRIVATE_FILE).expect("stage");

        // Observable on the temporary file, while it is still empty: this is
        // the property a decrypted secret depends on.
        let meta = std::fs::symlink_metadata(staged.temp_path()).expect("stat");
        assert_eq!(mode_of(&meta), Mode::PRIVATE_FILE);
        assert_eq!(meta.len(), 0, "the mode is set before any content");
        assert_eq!(staged.mode(), Mode::PRIVATE_FILE);
    }

    #[test]
    fn the_temporary_file_is_never_wider_than_its_final_mode() {
        let home = guarded_home();
        // tempfile creates at 0600 and the declared mode only narrows it, so
        // there is no instant at which the file is wider than 0600.
        let staged = stage(&home.child("secret"), Mode::from_bits(0o400)).expect("stage");
        assert_eq!(mode_of_path(staged.temp_path()), Mode::from_bits(0o400));
        let filled = staged.fill(b"plaintext").expect("fill");
        assert_eq!(mode_of_path(filled.temp_path()), Mode::from_bits(0o400));
        filled.publish().expect("publish");
        assert_eq!(mode_of_path(&home.child("secret")), Mode::from_bits(0o400));
    }

    #[test]
    fn a_declared_setuid_or_setgid_bit_survives_the_write_that_fills_the_file() {
        // The kernel clears S_ISUID, and S_ISGID alongside group execute, on the
        // first write to a file by a process without CAP_FSETID. A mode set
        // before the content therefore loses those bits the moment the content
        // lands: the second plan reads `Modify`, and the ledger records a mode
        // that is not on disk. Under root the bits survive either way, so this
        // cannot fail there — which is not a reason to skip it.
        for bits in [0o4755, 0o2755, 0o6755] {
            let home = guarded_home();
            let dest = home.child("tool");
            let mode = Mode::from_bits(bits);

            let staged = stage(&dest, mode).expect("stage");
            assert_eq!(
                mode_of_path(staged.temp_path()).bits() & !mode.bits(),
                0,
                "{mode}: the empty temporary file is never wider than the declared mode",
            );
            let filled = staged.fill(b"#!/bin/sh\nexit 0\n").expect("fill");
            assert_eq!(mode_of_path(filled.temp_path()), mode, "{mode}: after fill");
            assert_eq!(filled.mode(), mode);
            filled.publish().expect("publish");

            assert_eq!(mode_of_path(&dest), mode, "{mode}: on disk");
            let observed = observe(&dest).expect("observe");
            assert_eq!(
                compare(&observed, &desired(b"#!/bin/sh\nexit 0\n", mode)).action,
                Action::Unchanged,
                "{mode}: the second plan is empty",
            );
        }
    }

    #[test]
    fn a_declared_mode_beats_the_process_umask() {
        let _serialised = UMASK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = guarded_home();
        let previous = rustix::process::umask(Mode::from_bits(0o077).into());

        let dest = home.child("wide/f");
        let result = write_atomically(&dest, b"x", Mode::DEFAULT_FILE);

        rustix::process::umask(previous);
        result.expect("write");

        assert_eq!(
            mode_of_path(&dest),
            Mode::DEFAULT_FILE,
            "OpenOptions::mode is masked by the umask; fchmod is not",
        );
        assert_eq!(
            mode_of_path(&home.child("wide")),
            Mode::DEFAULT_DIR,
            "mkdir's mode is masked by the umask too; the directory is chmod'd",
        );
    }

    #[test]
    fn a_directory_bx_creates_is_never_wider_than_its_declared_mode() {
        let _serialised = UMASK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = guarded_home();
        // umask 0 so the assertion means the same thing whatever the developer
        // or the runner happens to have set. Without it, a umask of 077 would
        // narrow `mkdir(0o777)` for free and the test would pass against the
        // defect it exists to catch.
        let previous = rustix::process::umask(Mode::from_bits(0).into());

        let path = home.child("restore");
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));

        let watcher = {
            let (path, done, seen) = (path.clone(), done.clone(), seen.clone());
            std::thread::spawn(move || {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok(meta) = std::fs::symlink_metadata(&path) {
                        let mode = mode_of(&meta);
                        let mut seen = seen
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if seen.last() != Some(&mode) {
                            seen.push(mode);
                        }
                    }
                }
            })
        };

        let result = create_dir_at(&path, Mode::PRIVATE_DIR);
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        watcher.join().expect("the watcher thread");
        rustix::process::umask(previous);
        result.expect("mkdir");

        // The exposure a `mkdir(0o777)` followed by a `chmod` opens is the
        // descriptor, not the contents: a process that opens the directory
        // inside the window keeps a handle whose access checks already passed,
        // and the later `chmod` does not revoke it. So the assertion is about
        // every instant, not about the end state.
        let seen = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for mode in seen.iter() {
            assert!(
                mode.bits() & !Mode::PRIVATE_DIR.bits() == 0,
                "the directory was {mode} at some instant, wider than the 0700 declared for it; \
                 every mode observed was {seen:?}",
            );
        }
        assert_eq!(mode_of_path(&path), Mode::PRIVATE_DIR);
    }

    #[test]
    fn an_abandoned_stage_leaves_the_original_intact() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        let staged = stage(&dest, Mode::PRIVATE_FILE).expect("stage");
        let temp = staged.temp_path().to_path_buf();
        staged.abandon();

        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        assert!(!temp.exists(), "no .bx- orphan survives an abandoned write");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
    }

    #[test]
    fn an_abandoned_filled_write_leaves_the_original_intact() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        // The crash phase that matters: the content is on disk and fsynced, and
        // the rename has not happened.
        let filled = stage(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"v2")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();
        assert_eq!(std::fs::read(&temp).expect("read temp"), b"v2");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        filled.abandon();

        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        assert!(!temp.exists());
    }

    #[test]
    fn the_filled_phase_is_the_seam_a_journal_interposes_at() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        let filled = stage(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"v2")
            .expect("fill");

        // Everything a journal needs to record its intent, before the rename.
        assert_eq!(filled.dest(), dest);
        assert_eq!(filled.temp_path().parent(), dest.parent());
        assert_eq!(filled.mode(), Mode::PRIVATE_FILE);
        assert_eq!(filled.prior().kind, Kind::File);
        assert_eq!(filled.prior().bytes.as_deref(), Some(&b"v1"[..]));
        assert_eq!(filled.prior().mode, Some(Mode::DEFAULT_FILE));

        filled.publish().expect("publish");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v2");
    }

    #[test]
    fn a_staged_write_carries_the_prior_state_a_reversal_needs() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::from_bits(0o640));

        let staged = stage(&dest, Mode::PRIVATE_FILE).expect("stage");
        let prior = staged.prior().clone();
        staged.commit(b"v2").expect("commit");

        // Restoring from the prior state alone must reproduce v1 exactly,
        // including its mode.
        assert_eq!(prior.path, dest);
        write_atomically(
            &prior.path,
            prior.bytes.as_deref().expect("prior bytes"),
            prior.mode.expect("prior mode"),
        )
        .expect("restore");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        assert_eq!(mode_of_path(&dest), Mode::from_bits(0o640));
    }

    #[test]
    fn a_commit_replaces_content_and_mode_together() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);
        write_atomically(&dest, b"v2", Mode::PRIVATE_FILE).expect("write");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v2");
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
    }

    #[test]
    fn a_write_creates_the_file_at_the_requested_mode() {
        let home = guarded_home();
        let dest = home.child("f");
        write_atomically(&dest, b"hello", Mode::PRIVATE_FILE).expect("write");
        assert_eq!(std::fs::read(&dest).expect("read"), b"hello");
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
    }

    #[test]
    fn a_second_commit_of_identical_bytes_is_byte_identical() {
        let home = guarded_home();
        let dest = home.child("f");
        write_atomically(&dest, b"same\n", Mode::DEFAULT_FILE).expect("first");
        let first = std::fs::read(&dest).expect("read");
        write_atomically(&dest, b"same\n", Mode::DEFAULT_FILE).expect("second");

        assert_eq!(std::fs::read(&dest).expect("read"), first);
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        let observed = observe(&dest).expect("observe");
        assert_eq!(
            compare(&observed, &desired(b"same\n", Mode::DEFAULT_FILE)).action,
            Action::Unchanged,
            "the second plan is empty",
        );
    }

    #[test]
    fn a_write_does_not_disturb_its_siblings() {
        let home = guarded_home();
        let sibling = home.child("sibling");
        seed(&sibling, b"untouched", Mode::from_bits(0o640));
        let sibling_ino = std::fs::metadata(&sibling).expect("stat").ino();

        write_atomically(&home.child("f"), b"x", Mode::DEFAULT_FILE).expect("write");

        assert_eq!(std::fs::read(&sibling).expect("read"), b"untouched");
        assert_eq!(mode_of_path(&sibling), Mode::from_bits(0o640));
        assert_eq!(
            std::fs::metadata(&sibling).expect("stat").ino(),
            sibling_ino
        );
        assert_eq!(
            names_in(home.path()),
            vec![OsString::from("f"), OsString::from("sibling")],
        );
    }

    #[test]
    fn a_write_leaves_no_temporary_file_behind() {
        let home = guarded_home();
        write_atomically(&home.child("f"), b"x", Mode::DEFAULT_FILE).expect("write");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
    }

    #[test]
    fn a_failed_publish_leaves_no_temporary_file_behind() {
        let home = guarded_home();
        let dest = home.child("f");
        let staged = stage(&dest, Mode::DEFAULT_FILE).expect("stage");
        // Something occupies the destination after it was observed, so the
        // publish fails after the temporary file has been written in full —
        // refused by the check before the rename, which is the one a rename
        // over a directory would also have failed.
        std::fs::create_dir(&dest).expect("occupy");

        let err = staged.commit(b"x").expect_err("must fail");
        assert_eq!(err.path(), dest);
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
    }

    #[test]
    fn a_destination_edited_between_fill_and_publish_is_refused_and_keeps_the_edit() {
        // The window a journal widens: between the observation `stage` takes
        // and the rename, an editor saves. Replacing the file then destroys the
        // save, and the prior bx recorded predates it, so `rm` cannot bring it
        // back either — Invariant 1 and Invariant 4 at once.
        let in_place: fn(&Path) = |dest| {
            std::fs::write(dest, b"the user's edit\n").expect("the user saves in place");
        };
        let by_rename: fn(&Path) = |dest| {
            // Same length as what was there, so only which file it is changed.
            let saved = dest.with_file_name("editor-swap");
            std::fs::write(&saved, b"v2\n").expect("the editor writes its copy");
            std::fs::rename(&saved, dest).expect("and renames it over the original");
        };

        for (how, save) in [("in place", in_place), ("by rename", by_rename)] {
            let home = guarded_home();
            let dest = home.child(".conf");
            seed(&dest, b"v1\n", Mode::DEFAULT_FILE);

            let filled = stage(&dest, Mode::DEFAULT_FILE)
                .expect("stage")
                .fill(b"bx\n")
                .expect("fill");
            let temp = filled.temp_path().to_path_buf();
            save(&dest);
            let saved = std::fs::read(&dest).expect("read the save");

            let err = filled
                .publish()
                .expect_err("a destination that changed after it was observed is not replaced");
            assert!(matches!(err, Error::Changed { .. }), "{how}: {err:?}");
            assert_eq!(err.path(), dest, "{how}");
            assert_eq!(
                std::fs::read(&dest).expect("read"),
                saved,
                "{how}: the user's save survives",
            );
            assert!(!temp.exists(), "{how}: the temporary file is removed");
            assert_eq!(
                names_in(home.path()),
                vec![OsString::from(".conf")],
                "{how}"
            );
        }
    }

    #[test]
    fn a_symlink_swapped_in_between_fill_and_publish_is_refused_and_survives() {
        let home = guarded_home();
        let dest = home.child(".conf");
        let other = home.child("elsewhere");
        seed(&dest, b"v1\n", Mode::DEFAULT_FILE);
        seed(&other, b"the link's target\n", Mode::DEFAULT_FILE);

        let filled = stage(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"bx\n")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();
        // Decision 2 refuses a link at the final component; observing a file
        // there first must not turn into replacing a link that arrived later.
        std::fs::remove_file(&dest).expect("rm");
        std::os::unix::fs::symlink("elsewhere", &dest).expect("symlink");

        let err = filled
            .publish()
            .expect_err("the link is not bx's to replace");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert!(
            std::fs::symlink_metadata(&dest)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the link is intact",
        );
        assert_eq!(
            std::fs::read_link(&dest).expect("readlink"),
            Path::new("elsewhere")
        );
        assert_eq!(std::fs::read(&other).expect("read"), b"the link's target\n");
        assert!(!temp.exists());
    }

    #[test]
    fn a_file_that_appears_where_there_was_none_is_not_replaced() {
        let home = guarded_home();
        let dest = home.child(".conf");

        let filled = stage(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"bx\n")
            .expect("fill");
        assert_eq!(filled.prior().stamp, None, "nothing was there to stamp");
        std::fs::write(&dest, b"another tool's\n").expect("another tool creates it");

        let err = filled
            .publish()
            .expect_err("bx announced a create, and there is now a file to replace");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(std::fs::read(&dest).expect("read"), b"another tool's\n");
        assert_eq!(names_in(home.path()), vec![OsString::from(".conf")]);
    }

    /// A POSIX ACL in the kernel's `system.posix_acl_access` encoding: version
    /// 2, then `(tag, perm, id)` per entry, little-endian, sorted by tag.
    fn posix_acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut encoded = 2_u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            encoded.extend(tag.to_le_bytes());
            encoded.extend(perm.to_le_bytes());
            encoded.extend(id.to_le_bytes());
        }
        encoded
    }

    #[test]
    fn a_replaced_file_keeps_neither_its_xattrs_nor_its_acl() {
        // A documented exclusion from "restores exactly", pinned so that
        // changing it is a decision: see the module documentation.
        use rustix::fs::{XattrFlags, getxattr, setxattr};

        const USER_ATTR: &str = "user.bx-test";
        const ACL_ACCESS: &str = "system.posix_acl_access";
        const UNDEFINED_ID: u32 = u32::MAX;

        let home = guarded_home();
        let dest = home.child(".conf");
        seed(&dest, b"v1\n", Mode::DEFAULT_FILE);

        // What this filesystem can hold decides what there is to pin. An ACL
        // naming uid 65534 is refused with EINVAL where that uid is unmapped.
        let has_user_attr =
            match setxattr(dest.as_path(), USER_ATTR, b"theirs", XattrFlags::empty()) {
                Ok(()) => true,
                Err(e) if e == Errno::OPNOTSUPP => false,
                Err(e) => panic!("setxattr {USER_ATTR}: {e}"),
            };
        let acl = posix_acl(&[
            (0x01, 6, UNDEFINED_ID), // user::rw-
            (0x02, 4, 65534),        // user:nobody:r--
            (0x04, 4, UNDEFINED_ID), // group::r--
            (0x10, 4, UNDEFINED_ID), // mask::r--
            (0x20, 4, UNDEFINED_ID), // other::r--
        ]);
        let has_acl = match setxattr(dest.as_path(), ACL_ACCESS, &acl, XattrFlags::empty()) {
            Ok(()) => true,
            Err(e) if e == Errno::OPNOTSUPP || e == Errno::INVAL => false,
            Err(e) => panic!("setxattr {ACL_ACCESS}: {e}"),
        };
        let attrs: Vec<&str> = [(USER_ATTR, has_user_attr), (ACL_ACCESS, has_acl)]
            .into_iter()
            .filter_map(|(name, set)| set.then_some(name))
            .collect();
        if attrs.is_empty() {
            // Neither can exist here, so neither can be lost.
            return;
        }

        let attr = |name: &str| -> Option<Vec<u8>> {
            let mut buf = [0_u8; 256];
            match getxattr(dest.as_path(), name, &mut buf) {
                Ok(len) => Some(buf[..len].to_vec()),
                Err(e) if e == Errno::NODATA => None,
                Err(e) => panic!("getxattr {name}: {e}"),
            }
        };
        for name in &attrs {
            assert!(attr(name).is_some(), "{name} is on the user's file");
        }

        let staged = stage(&dest, Mode::DEFAULT_FILE).expect("stage");
        let prior = staged.prior().clone();
        staged.commit(b"bx\n").expect("commit");
        for name in &attrs {
            assert_eq!(
                attr(name),
                None,
                "{name} is not carried onto the replacement"
            );
        }

        // The prior is bytes and mode, so restoring from it brings the bytes
        // and the mode back, and nothing else.
        write_atomically(
            &dest,
            prior.bytes.as_deref().expect("prior bytes"),
            prior.mode.expect("prior mode"),
        )
        .expect("restore");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v1\n");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        for name in &attrs {
            assert_eq!(attr(name), None, "{name} is not restored either");
        }
    }

    #[test]
    fn a_symlink_destination_is_refused_and_writes_nothing() {
        let home = guarded_home();
        let other = home.child("other");
        seed(&other, b"the link's target", Mode::DEFAULT_FILE);
        let dest = home.child("link");
        std::os::unix::fs::symlink("other", &dest).expect("symlink");

        let err = write_atomically(&dest, b"replacement", Mode::DEFAULT_FILE)
            .expect_err("a link the user made is not bx's to replace");
        assert!(matches!(err, Error::Symlink(_)), "{err:?}");
        assert_eq!(err.path(), dest);

        // The link survives, still pointing where it pointed, and its target is
        // untouched.
        assert!(
            std::fs::symlink_metadata(&dest)
                .expect("stat")
                .file_type()
                .is_symlink(),
        );
        assert_eq!(
            std::fs::read_link(&dest).expect("readlink"),
            Path::new("other"),
        );
        assert_eq!(std::fs::read(&other).expect("read"), b"the link's target");

        // And `plan` says the same thing rather than something else.
        let outcome = outcome_for(&home, "link", b"replacement", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert_eq!(
            outcome.note.as_deref(),
            Some("a symlink; bx will not replace a link you created"),
        );
    }

    #[test]
    fn a_symlink_in_a_parent_component_is_written_through() {
        let home = guarded_home();
        // The kernel resolves a parent symlink, the temporary file lands in the
        // real directory, and the rename stays inside that one directory. Only
        // the final component is bx's business.
        std::fs::create_dir(home.child("real")).expect("mkdir");
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        write_atomically(&home.child("link/f"), b"x", Mode::DEFAULT_FILE).expect("write");

        assert_eq!(std::fs::read(home.child("real/f")).expect("read"), b"x");
        assert!(
            std::fs::symlink_metadata(home.child("link"))
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the link survives",
        );
    }

    #[test]
    fn a_missing_parent_directory_is_created_at_the_default_dir_mode() {
        let home = guarded_home();
        let dest = home.child("a/b/c/f");
        write_atomically(&dest, b"x", Mode::PRIVATE_FILE).expect("write");

        assert_eq!(std::fs::read(&dest).expect("read"), b"x");
        for rel in ["a", "a/b", "a/b/c"] {
            assert_eq!(
                mode_of_path(&home.child(rel)),
                Mode::DEFAULT_DIR,
                "{rel} is an implicit parent, created at 0755",
            );
        }
    }

    #[test]
    fn a_parent_created_for_an_abandoned_write_is_left_in_place() {
        let home = guarded_home();
        let dest = home.child(".ssh/config");
        let staged = stage(&dest, Mode::PRIVATE_FILE).expect("stage");
        let temp = staged.temp_path().to_path_buf();
        staged.abandon();

        // Documented behaviour, not an oversight: the directory is empty and at
        // the mode a mkdir would have given it, the next attempt reuses it, and
        // removing it would race any other write already using it.
        assert!(home.child(".ssh").is_dir());
        assert_eq!(mode_of_path(&home.child(".ssh")), Mode::DEFAULT_DIR);
        assert_eq!(names_in(&home.child(".ssh")), Vec::<OsString>::new());
        assert!(!temp.exists());
        assert!(!dest.exists());
    }

    #[test]
    fn an_existing_parent_directory_is_never_chmod_d() {
        let home = guarded_home();
        std::fs::create_dir(home.child("shared")).expect("mkdir");
        set_mode(&home.child("shared"), Mode::from_bits(0o770)).expect("chmod");

        write_atomically(&home.child("shared/f"), b"x", Mode::PRIVATE_FILE).expect("write");

        assert_eq!(
            mode_of_path(&home.child("shared")),
            Mode::from_bits(0o770),
            "a directory bx did not create is the user's",
        );
    }

    #[test]
    fn an_unwritable_parent_directory_surfaces_a_typed_error() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let dir = home.child("locked");
        std::fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

        let dest = dir.join("f");
        let err = write_atomically(&dest, b"x", Mode::DEFAULT_FILE).expect_err("must fail");
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(err.path(), dir, "the error names the directory");
        assert!(!dest.exists());

        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");
    }

    #[test]
    fn a_parent_that_cannot_be_stat_ed_is_an_error_not_an_absent_directory() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let locked = home.child("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        // No execute bit, so nothing below it can be stat'd at all.
        set_mode(&locked, Mode::from_bits(0o000)).expect("chmod");

        // The third `ENOENT`-adjacent case, and the one that must *not* become
        // a directory bx invents: the parent may well be there, and bx cannot
        // see. A read error is the only honest answer.
        let err = observe(&locked.join("sub/f")).expect_err("must fail");
        let Error::Read { path, .. } = &err else {
            panic!("expected a read error, got {err:?}");
        };
        assert_eq!(path, &locked.join("sub"));

        set_mode(&locked, Mode::PRIVATE_DIR).expect("unlock for cleanup");
    }

    #[test]
    fn a_path_with_no_parent_is_refused() {
        let err =
            write_atomically(Path::new("/"), b"x", Mode::DEFAULT_FILE).expect_err("must fail");
        assert!(matches!(err, Error::NoParent(_)), "{err:?}");
        assert_eq!(err.path(), Path::new("/"));
    }

    #[test]
    fn a_bare_file_name_writes_into_the_working_directory() {
        assert_eq!(parent_of(Path::new("f")).expect("parent"), Path::new("."));
    }

    #[test]
    fn a_relative_destination_writes_under_the_working_directory() {
        let _serialised = CWD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = guarded_home();
        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(home.path()).expect("chdir");

        // A bare name, which `parent_of` resolves to `.` — the contract it goes
        // out of its way to support, and which nothing had ever exercised
        // through an actual write.
        let bare = write_atomically(Path::new("bare"), b"x", Mode::DEFAULT_FILE);
        // And a relative path more than one component deep, where `ancestors`
        // ends with `""`.
        let deep = write_atomically(Path::new("a/b/c.txt"), b"y", Mode::PRIVATE_FILE);

        std::env::set_current_dir(&previous).expect("restore the working directory");
        bare.expect("a bare relative name");
        deep.expect("a relative path two directories deep");

        assert_eq!(std::fs::read(home.child("bare")).expect("read"), b"x");
        assert_eq!(std::fs::read(home.child("a/b/c.txt")).expect("read"), b"y");
        for rel in ["a", "a/b"] {
            assert_eq!(mode_of_path(&home.child(rel)), Mode::DEFAULT_DIR, "{rel}");
        }
    }

    #[test]
    fn set_mode_closes_a_mode_drift_without_replacing_the_inode() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);
        let link = home.child("hardlink");
        std::fs::hard_link(&dest, &link).expect("hard link");
        let before = std::fs::metadata(&dest).expect("stat").ino();

        set_mode(&dest, Mode::PRIVATE_FILE).expect("chmod");

        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"v1",
            "content is untouched"
        );
        assert_eq!(
            std::fs::metadata(&dest).expect("stat").ino(),
            before,
            "a chmod keeps the inode; a rewrite would not",
        );
        assert_eq!(
            mode_of_path(&link),
            Mode::PRIVATE_FILE,
            "the user's hard link still points at the same file",
        );
    }

    #[test]
    fn set_mode_refuses_a_symlink() {
        let home = guarded_home();
        seed(&home.child("real"), b"x", Mode::DEFAULT_FILE);
        let link = home.child("link");
        std::os::unix::fs::symlink("real", &link).expect("symlink");

        let err = set_mode(&link, Mode::PRIVATE_FILE).expect_err("must fail");
        assert!(matches!(err, Error::Symlink(_)), "{err:?}");
        assert_eq!(
            mode_of_path(&home.child("real")),
            Mode::DEFAULT_FILE,
            "the link's target keeps its mode",
        );
    }

    #[test]
    fn set_mode_names_a_path_that_is_not_there() {
        let home = guarded_home();
        let err = set_mode(&home.child("nope"), Mode::PRIVATE_FILE).expect_err("must fail");
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(err.path(), home.child("nope"));
    }

    /// The `plan` verdict for a declared directory target.
    fn dir_outcome_for(home: &GuardedHome, rel: &str, mode: Mode) -> Outcome {
        compare_dir(&observe(&home.child(rel)).expect("observe"), mode)
    }

    /// `plan` for a directory target, then `apply` on what that plan saw, with
    /// nothing changing in between.
    fn apply_dir(path: &Path, mode: Mode) -> Result<EnsuredDir, Error> {
        let planned = observe(path).expect("plan observes");
        ensure_dir(path, mode, &planned)
    }

    #[test]
    fn ensure_dir_refuses_a_mode_changed_after_plan_saw_nothing_to_do() {
        let home = guarded_home();
        let dir = home.child(".ssh");
        std::fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, Mode::PRIVATE_DIR).expect("chmod");
        let planned = observe(&dir).expect("plan observes");
        assert_eq!(
            compare_dir(&planned, Mode::PRIVATE_DIR).action,
            Action::Unchanged,
        );

        set_mode(&dir, Mode::DEFAULT_DIR).expect("somebody widens it after plan");

        let err = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned)
            .expect_err("plan announced nothing, so apply may do nothing");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(err.path(), dir);
        assert_eq!(
            mode_of_path(&dir),
            Mode::DEFAULT_DIR,
            "apply did not chmod a directory plan never said it would touch",
        );
    }

    #[test]
    fn ensure_dir_refuses_a_directory_that_appeared_after_plan_announced_a_create() {
        let home = guarded_home();
        let dir = home.child("shared");
        let planned = observe(&dir).expect("plan observes");
        assert_eq!(
            compare_dir(&planned, Mode::PRIVATE_DIR).action,
            Action::Create
        );

        std::fs::create_dir(&dir).expect("another tool makes it");
        set_mode(&dir, Mode::from_bits(0o777)).expect("at its own mode");

        let err = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned)
            .expect_err("plan announced a create, not a chmod of somebody else's directory");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(mode_of_path(&dir), Mode::from_bits(0o777));
    }

    #[test]
    fn ensure_dir_refuses_a_file_that_took_the_path_before_its_mkdir() {
        let home = guarded_home();
        let dir = home.child("d");
        let planned = observe(&dir).expect("plan observes");
        // Apply's own observation agrees with plan's...
        let fresh = observe(&dir).expect("apply observes");
        assert_eq!(
            compare_dir(&fresh, Mode::PRIVATE_DIR),
            compare_dir(&planned, Mode::PRIVATE_DIR),
        );
        // ...and then a file lands before the mkdir does.
        seed(&dir, b"a file\n", Mode::DEFAULT_FILE);

        let err = act_on_dir(&dir, Mode::PRIVATE_DIR, &planned, fresh)
            .expect_err("a file where a directory was to be created is not a create");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(std::fs::read(&dir).expect("read"), b"a file\n");
        assert_eq!(mode_of_path(&dir), Mode::DEFAULT_FILE);
    }

    #[test]
    fn ensure_dir_returns_what_it_overwrote_and_what_it_created() {
        let home = guarded_home();
        let dir = home.child("a/b/c");

        let created = apply_dir(&dir, Mode::PRIVATE_DIR).expect("create");
        assert_eq!(created.action, Action::Create);
        assert_eq!(created.prior.kind, Kind::Absent);
        assert_eq!(
            created.created_dirs,
            [home.child("a/b/c"), home.child("a/b"), home.child("a")],
            "deepest first, the path itself included, for a reversal to remove",
        );

        set_mode(&dir, Mode::DEFAULT_DIR).expect("widen");
        let closed = apply_dir(&dir, Mode::PRIVATE_DIR).expect("modify");
        assert_eq!(closed.action, Action::Modify);
        assert_eq!(
            closed.prior.mode,
            Some(Mode::DEFAULT_DIR),
            "the mode it overwrote, for the ledger to restore",
        );
        assert!(closed.created_dirs.is_empty());

        let unchanged = apply_dir(&dir, Mode::PRIVATE_DIR).expect("unchanged");
        assert_eq!(unchanged.action, Action::Unchanged);
        assert_eq!(unchanged.prior.mode, Some(Mode::PRIVATE_DIR));
        assert!(unchanged.created_dirs.is_empty());
    }

    #[test]
    fn ensure_dir_creates_at_the_declared_mode_and_closes_the_drift_plan_announced() {
        let home = guarded_home();
        let dir = home.child(".ssh");

        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("create").action,
            Action::Create,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Idempotence: the second call changes nothing and reports nothing.
        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("again").action,
            Action::Unchanged,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Drift is announced by plan, which changes nothing...
        set_mode(&dir, Mode::DEFAULT_DIR).expect("widen");
        let planned = dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR);
        assert_eq!(planned.action, Action::Modify);
        assert_eq!(planned.note.as_deref(), Some("mode 0755 -> 0700"));
        assert_eq!(
            planned.mode_drift,
            Some((Mode::DEFAULT_DIR, Mode::PRIVATE_DIR))
        );
        assert!(!planned.content_drift);
        assert_eq!(
            mode_of_path(&dir),
            Mode::DEFAULT_DIR,
            "plan changed nothing"
        );

        // ...and closed by apply, which does exactly that and nothing else.
        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("drift").action,
            planned.action,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);
        assert_eq!(
            dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR).action,
            Action::Unchanged,
            "the second plan is empty",
        );
    }

    #[test]
    fn planning_a_directory_target_creates_nothing() {
        let home = guarded_home();

        let outcome = dir_outcome_for(&home, "declared/dir", Mode::PRIVATE_DIR);
        assert_eq!(outcome.action, Action::Create);
        assert_eq!(outcome.note, None);
        assert_eq!(outcome.parent_note, None);
        assert!(!outcome.content_drift);
        assert_eq!(
            names_in(home.path()),
            Vec::<OsString>::new(),
            "neither the directory nor its missing ancestor exists after plan",
        );

        // And apply performs the create plan announced.
        assert_eq!(
            apply_dir(&home.child("declared/dir"), Mode::PRIVATE_DIR)
                .expect("apply")
                .action,
            outcome.action,
        );
        assert_eq!(mode_of_path(&home.child("declared/dir")), Mode::PRIVATE_DIR);
        assert_eq!(mode_of_path(&home.child("declared")), Mode::DEFAULT_DIR);
    }

    #[test]
    fn a_dangling_link_above_a_directory_target_is_a_conflict_at_plan_time() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child("d")).expect("symlink");

        let outcome = dir_outcome_for(&home, "d/a", Mode::PRIVATE_DIR);
        assert_eq!(outcome.action, Action::Conflict);
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains("does not resolve to a directory"), "{note}");

        // A dangling link *at* the path is a link, and a conflict too.
        assert_eq!(
            dir_outcome_for(&home, "d", Mode::PRIVATE_DIR).action,
            Action::Conflict,
        );
        assert_eq!(
            apply_dir(&home.child("d"), Mode::PRIVATE_DIR)
                .expect("a verdict")
                .action,
            Action::Conflict,
        );
        assert!(std::fs::symlink_metadata(home.child("nowhere")).is_err());
    }

    #[test]
    fn a_directory_target_occupied_by_something_else_names_what_is_there() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        std::fs::create_dir(home.child("real")).expect("mkdir");
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            home.child("fifo"),
            rustix::fs::FileType::Fifo,
            Mode::PRIVATE_FILE.into(),
            0,
        )
        .expect("mkfifo");

        for (rel, expected) in [
            ("f", "a file, where the target declares a directory"),
            (
                "link",
                "a symlink; bx will not change a directory through a link",
            ),
            ("fifo", "not a directory"),
        ] {
            let outcome = dir_outcome_for(&home, rel, Mode::PRIVATE_DIR);
            assert_eq!(outcome.action, Action::Conflict, "{rel}");
            assert_eq!(outcome.note.as_deref(), Some(expected), "{rel}");
        }
    }

    #[test]
    fn fill_syncs_the_temporary_file_before_it_returns() {
        let home = guarded_home();
        let staged = stage(&home.child("f"), Mode::DEFAULT_FILE).expect("stage");
        let temp = staged.temp_path().to_path_buf();

        let (filled, events) = durable::recording(|| staged.fill(b"x"));
        let filled = filled.expect("fill");

        assert_eq!(
            events,
            [durable::Event::SyncFile(temp)],
            "the content is fsynced inside fill, so a journal recording its intent \
             after fill returns is recording durable bytes",
        );
        filled.abandon();
    }

    #[test]
    fn publish_syncs_the_directory_only_after_the_rename() {
        let home = guarded_home();
        let dest = home.child(".config/f");
        let filled = stage(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();

        let (published, events) = durable::recording(|| filled.publish());
        published.expect("publish");

        let dir = home.child(".config");
        assert_eq!(
            events,
            [
                durable::Event::OpenDir(dir.clone()),
                durable::Event::Rename {
                    from: temp,
                    to: dest.clone(),
                },
                durable::Event::SyncDir(dir),
            ],
            "the directory is opened before the rename and fsynced after it",
        );
    }

    #[test]
    fn write_atomically_makes_every_durability_call_in_order() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        let (result, events) =
            durable::recording(|| write_atomically(&dest, b"v2", Mode::DEFAULT_FILE));
        result.expect("write");

        let [
            durable::Event::SyncFile(synced),
            durable::Event::OpenDir(opened),
            durable::Event::Rename { from, to },
            durable::Event::SyncDir(dir_synced),
        ] = events.as_slice()
        else {
            panic!("expected sync, open, rename, sync; got {events:?}");
        };
        assert_eq!(synced, from, "the file synced is the file renamed");
        assert_eq!(to, &dest);
        assert_eq!(opened, home.path());
        assert_eq!(dir_synced, home.path());
    }

    #[test]
    fn a_failed_rename_syncs_no_directory() {
        let home = guarded_home();
        let dest = home.child("f");
        let filled = stage(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");
        std::fs::create_dir(&dest).expect("occupy");

        let (published, events) = durable::recording(|| filled.publish());
        published.expect_err("a directory is in the way");
        assert_eq!(events, [durable::Event::OpenDir(home.path().to_path_buf())]);
    }

    #[test]
    fn ensure_dir_creates_implicit_ancestors_at_the_default_dir_mode() {
        let home = guarded_home();
        assert_eq!(
            apply_dir(&home.child("a/b/c"), Mode::PRIVATE_DIR)
                .expect("create")
                .action,
            Action::Create,
        );
        assert_eq!(mode_of_path(&home.child("a")), Mode::DEFAULT_DIR);
        assert_eq!(mode_of_path(&home.child("a/b")), Mode::DEFAULT_DIR);
        assert_eq!(mode_of_path(&home.child("a/b/c")), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_dir_refuses_a_path_a_file_occupies() {
        let home = guarded_home();
        let path = home.child("f");
        seed(&path, b"x", Mode::DEFAULT_FILE);
        assert_eq!(
            apply_dir(&path, Mode::PRIVATE_DIR).expect("report").action,
            Action::Conflict,
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"x");
        assert_eq!(mode_of_path(&path), Mode::DEFAULT_FILE);
    }

    #[test]
    fn ensure_dir_refuses_a_symlink_where_a_directory_is_declared() {
        let home = guarded_home();
        std::fs::create_dir(home.child("real")).expect("mkdir");
        set_mode(&home.child("real"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        assert_eq!(
            apply_dir(&home.child("link"), Mode::PRIVATE_DIR)
                .expect("report")
                .action,
            Action::Conflict,
        );
        assert_eq!(
            mode_of_path(&home.child("real")),
            Mode::DEFAULT_DIR,
            "the link's target keeps its mode",
        );
        assert!(
            std::fs::symlink_metadata(home.child("link"))
                .expect("stat")
                .file_type()
                .is_symlink(),
        );
    }

    #[test]
    fn observe_refuses_a_path_with_no_parent() {
        let err = observe(Path::new("/")).expect_err("must fail");
        assert!(matches!(err, Error::NoParent(_)), "{err:?}");
    }

    #[test]
    fn an_entry_that_cannot_be_made_portable_is_refused_not_recorded() {
        // `Portable::from_path` refuses rather than renaming a path it cannot
        // represent, so the entry is an error rather than a ledger key that
        // names a different file.
        let home = guarded_home();
        let dest = home.child(".config/tool/x.conf");
        let filled = stage(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");

        let err = filled
            .new_entry(Path::new("relative/home"), Mechanism::Own)
            .expect_err("a relative home makes nothing portable");
        assert!(
            matches!(
                &err,
                Error::NotPortable {
                    source: crate::paths::Error::HomeNotAbsolute(_),
                    ..
                }
            ),
            "{err:?}",
        );
        assert_eq!(err.path(), dest);
        assert!(err.to_string().contains("cannot be recorded"), "{err}");

        // Under the real home the same write yields its entry.
        let entry = filled
            .new_entry(home.path(), Mechanism::Own)
            .expect("portable under the real home");
        assert_eq!(entry.path.as_str(), "~/.config/tool/x.conf");
    }

    /// A locked, writable ledger for a guarded home.
    fn ledger_for(home: &GuardedHome) -> (StateDir, ExclusiveLock, Ledger) {
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure the state directory");
        let lock = ExclusiveLock::acquire(&dir).expect("acquire the lock");
        let ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        (dir, lock, ledger)
    }

    #[test]
    fn the_prior_bytes_are_recordable_before_the_rename_and_restore_exactly() {
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host old\n", Mode::from_bits(0o640));

        let filled = stage(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"Host new\n")
            .expect("fill");

        // The recording point: the new content is durable, the destination is
        // still the old content, and the entry describes both.
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host old\n");
        let recorded = ledger
            .record(
                filled
                    .new_entry(home.path(), Mechanism::Own)
                    .expect("a portable entry"),
            )
            .expect("record")
            .clone();
        filled.publish().expect("publish");

        assert_eq!(recorded.path.as_str(), "~/.ssh/config");
        assert_eq!(recorded.written, ContentHash::of(b"Host new\n"));
        assert_eq!(recorded.mode, Mode::PRIVATE_FILE);
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host new\n");
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);

        // Reversibility: the ledger alone reproduces the displaced file, byte
        // for byte and mode for mode.
        let Prior::Existed(reference) = &recorded.prior else {
            panic!("the prior state must be Existed, got {:?}", recorded.prior);
        };
        assert_eq!(reference.mode, Mode::from_bits(0o640));
        assert_eq!(reference.len, 9);
        let bytes = ledger
            .restore_bytes(&dir, reference)
            .expect("the blob is durable by the time record returns");
        write_atomically(&dest, &bytes, reference.mode).expect("restore");
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host old\n");
        assert_eq!(mode_of_path(&dest), Mode::from_bits(0o640));
    }

    #[test]
    fn re_applying_after_an_edit_keeps_every_byte_the_user_wrote() {
        // The ordinary case, not an edge one: a user applies, edits the result,
        // and applies again. The second apply displaces the user's edit, so the
        // edit is what the user last had and becomes the prior `bx rm` restores
        // (#7, decision 13); the original file it replaces as the prior is not
        // dropped but kept in `superseded`. Losing either set of bytes, or
        // letting a later `PriorBytes::Absent` — which is what a writer over an
        // *absent* destination supplies — turn the prior into "unlink it",
        // turns Invariant 4 into its opposite, and the writer is the side that
        // supplies the prior, so the writer's tests are a place this has to be
        // pinned.
        //
        // This test used to be `..._still_restores_the_user_s_original_file`
        // and assert decision 7's first-prior-wins rule, under which rm wrote
        // `Host theirs` over the user's `Host edited` and the edit existed
        // nowhere.
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host theirs\n", Mode::from_bits(0o640));

        for content in [b"Host v1\n", b"Host v2\n"] {
            let filled = stage(&dest, Mode::PRIVATE_FILE)
                .expect("stage")
                .fill(content)
                .expect("fill");
            ledger
                .record(
                    filled
                        .new_entry(home.path(), Mechanism::Own)
                        .expect("a portable entry"),
                )
                .expect("record");
            filled.publish().expect("publish");
            // The user edits what bx wrote, so the second apply's `observe`
            // finds neither the user's original nor bx's output.
            std::fs::write(&dest, b"Host edited\n").expect("the user edits it");
        }

        let recorded = ledger
            .record(
                NewEntry::new(
                    Portable::from_path(&dest, home.path()).expect("portable"),
                    ContentHash::of(b"Host v2\n"),
                    Mode::PRIVATE_FILE,
                    Mechanism::Own,
                )
                .with_prior(PriorBytes::Absent),
            )
            .expect("record")
            .clone();

        let Prior::Existed(reference) = &recorded.prior else {
            panic!(
                "an absent incoming prior may not turn a snapshot into an unlink, got {:?}",
                recorded.prior
            );
        };
        // The edit was written over bx's 0600 output, so it carries that mode.
        assert_eq!(reference.mode, Mode::PRIVATE_FILE);
        assert_eq!(
            ledger
                .restore_bytes(&dir, reference)
                .expect("restore bytes"),
            b"Host edited\n",
            "the prior is what the user last had: the edit the second apply displaced",
        );

        assert_eq!(
            recorded.superseded.len(),
            1,
            "the original is kept, once: {:?}",
            recorded.superseded,
        );
        let original = &recorded.superseded[0];
        assert_eq!(original.mode, Mode::from_bits(0o640));
        assert_eq!(
            ledger
                .restore_bytes(&dir, original)
                .expect("restore the original"),
            b"Host theirs\n",
            "the file the user had before bx ever touched it is still restorable",
        );
    }

    #[test]
    fn a_prior_mode_is_recordable_for_a_mode_only_change() {
        let home = guarded_home();
        let (_dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host *\n", Mode::DEFAULT_FILE);

        // The one read, shared by the comparison and the record.
        let observed = observe(&dest).expect("observe");
        let outcome = compare(&observed, &desired(b"Host *\n", Mode::PRIVATE_FILE));
        assert_eq!(outcome.action, Action::Modify);
        assert!(!outcome.content_drift);

        let recorded = ledger
            .record(
                NewEntry::new(
                    Portable::from_path(&dest, home.path()).expect("portable"),
                    observed.digest().expect("a regular file has a digest"),
                    Mode::PRIVATE_FILE,
                    Mechanism::Own,
                )
                .with_prior(observed.prior_bytes()),
            )
            .expect("record")
            .clone();
        set_mode(&dest, Mode::PRIVATE_FILE).expect("close the drift");

        let Prior::Existed(reference) = &recorded.prior else {
            panic!("the prior state must be Existed, got {:?}", recorded.prior);
        };
        assert_eq!(reference.mode, Mode::DEFAULT_FILE);
        assert_eq!(
            recorded.written,
            ContentHash::of(b"Host *\n"),
            "a mode-only change leaves the content it found",
        );

        // Reversing it is a chmod back, and the content never moved.
        set_mode(&dest, reference.mode).expect("reverse");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host *\n");
    }

    #[test]
    fn the_directories_a_write_invented_are_recorded_deepest_first() {
        let home = guarded_home();
        let dest = home.child(".config/a/b/f");
        let filled = stage(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");

        assert_eq!(
            filled.created_dirs(),
            [
                home.child(".config/a/b"),
                home.child(".config/a"),
                home.child(".config"),
            ],
            "deepest first, which is the order a reversal removes them in",
        );
        let entry = filled
            .new_entry(home.path(), Mechanism::Own)
            .expect("a portable entry");
        assert_eq!(
            entry
                .created_dirs
                .iter()
                .map(Portable::as_str)
                .collect::<Vec<_>>(),
            ["~/.config/a/b", "~/.config/a", "~/.config"],
        );
        assert_eq!(
            entry.prior,
            PriorBytes::Absent,
            "nothing was displaced, and that is not the same as empty bytes",
        );
        filled.publish().expect("publish");
    }

    #[test]
    fn a_directory_that_was_already_there_is_not_recorded_as_one_bx_invented() {
        let home = guarded_home();
        let path = home.child("theirs");
        std::fs::create_dir(&path).expect("mkdir");
        set_mode(&path, Mode::DEFAULT_DIR).expect("chmod");

        // The race `create_missing_dirs` cannot design away: the stat said
        // nothing was there, and by the time the `mkdir` ran another tool had
        // made it. It is that tool's directory, and `bx rm` removing it would
        // be deleting something bx did not create.
        assert!(
            !create_dir_at(&path, Mode::PRIVATE_DIR).expect("create_dir_at"),
            "an existing directory was not created by this call",
        );
        assert_eq!(
            mode_of_path(&path),
            Mode::DEFAULT_DIR,
            "and its mode is not bx's to take either",
        );

        assert!(
            create_dir_at(&home.child("ours"), Mode::PRIVATE_DIR).expect("create_dir_at"),
            "a directory bx made is reported as bx's",
        );
        assert_eq!(mode_of_path(&home.child("ours")), Mode::PRIVATE_DIR);
    }

    #[test]
    fn a_write_over_nothing_records_that_nothing_was_there() {
        let home = guarded_home();
        let dest = home.child("f");
        let filled = stage(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");
        assert_eq!(filled.prior().prior_bytes(), PriorBytes::Absent);
        assert_eq!(filled.prior().digest(), None);
        assert!(filled.created_dirs().is_empty());
        assert_eq!(filled.written(), ContentHash::of(b"x"));
    }

    #[test]
    fn a_non_file_destination_has_no_prior_bytes_to_record() {
        let home = guarded_home();
        std::fs::create_dir(home.child("d")).expect("mkdir");
        std::os::unix::fs::symlink("d", home.child("l")).expect("symlink");

        for rel in ["d", "l"] {
            let observed = observe(&home.child(rel)).expect("observe");
            assert_eq!(observed.prior_bytes(), PriorBytes::Absent, "{rel}");
            assert_eq!(observed.digest(), None, "{rel}");
        }
    }

    #[test]
    fn ensure_dir_under_a_dangling_link_is_a_conflict_not_a_write_error() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child("d")).expect("symlink");

        assert_eq!(
            apply_dir(&home.child("d/a"), Mode::PRIVATE_DIR)
                .expect("a verdict, not an error")
                .action,
            Action::Conflict,
        );
        assert!(
            std::fs::symlink_metadata(home.child("nowhere")).is_err(),
            "nothing was created at the far end",
        );
    }

    #[test]
    fn a_non_directory_further_up_is_a_conflict_not_a_read_error() {
        let home = guarded_home();
        seed(&home.child("f"), b"a file", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink("loop", home.child("loop")).expect("symlink");
        std::os::unix::fs::symlink("f", home.child("l")).expect("symlink");

        for (rel, culprit) in [("f/sub/x", "f"), ("loop/a/x", "loop"), ("l/a/x", "l")] {
            let outcome = outcome_for(&home, rel, b"x", Mode::DEFAULT_FILE);
            assert_eq!(outcome.action, Action::Conflict, "{rel}");
            let note = outcome.note.expect("the cause must be named");
            assert!(
                note.contains(&home.child(culprit).display().to_string()),
                "{rel}: {note}",
            );

            let err = write_atomically(&home.child(rel), b"x", Mode::DEFAULT_FILE)
                .expect_err("must refuse");
            assert!(
                matches!(err, Error::UnusableParent { .. }),
                "{rel}: {err:?}"
            );
        }
        assert_eq!(std::fs::read(home.child("f")).expect("read"), b"a file");
    }

    #[test]
    fn a_directory_that_cannot_be_opened_for_its_fsync_fails_before_the_rename() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let dir = home.child("dropbox");
        let dest = dir.join("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);
        // Write and search, no read: a temporary file can be created and renamed
        // here, and the directory cannot be opened to fsync the rename.
        set_mode(&dir, Mode::from_bits(0o300)).expect("chmod");

        let result = write_atomically(&dest, b"v2", Mode::DEFAULT_FILE);
        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");

        let err = result.expect_err("the rename cannot be made durable");
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(err.path(), dir);
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"v1",
            "an Err means the destination holds exactly what it held before",
        );
        assert_eq!(names_in(&dir), vec![OsString::from("f")]);
    }

    #[test]
    fn a_wide_symlinked_parent_names_the_directory_to_chmod() {
        let home = guarded_home();
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        let note = outcome.parent_note.expect("the parent must be reported");
        let resolved = std::fs::canonicalize(home.child("dotfiles/dot_ssh")).expect("realpath");
        assert!(
            note.contains(&resolved.display().to_string()),
            "the note names the directory the link resolves to: {note}",
        );
        assert!(note.contains("chmod"), "{note}");
    }
}
