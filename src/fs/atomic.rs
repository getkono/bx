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
//! 3. the mode set with `fchmod` **before any content is written**.
//! 4. the content written, then `fsync`ed.
//! 5. the prior state recorded — [`Filled::new_entry`] assembles it and
//!    [`crate::state::Ledger::record`] makes it durable — **before** the
//!    rename, so a crash after the rename still has a recoverable prior state.
//! 6. `rename`.
//! 7. an `fsync` of the **destination directory**, so the rename itself
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

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode as RawMode, OFlags};
use rustix::io::Errno;
use tempfile::NamedTempFile;

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
            | Self::Write { path, .. } => path,
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
    /// to declare the directory as a target with the mode it should have.
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
/// Missing parent directories are created at [`Mode::DEFAULT_DIR`] — a target
/// deep under `~/.config` must not need a directory declaration for every
/// component. An *existing* directory is never chmod'd: it is the user's. When
/// that leaves a parent wider than the declared mode, [`compare`] reports it,
/// and the remedy is to declare the directory as a target of its own.
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
    // by the umask, so the file is at its final mode while it is still empty and
    // was never wider than that at any instant.
    fchmod(temp.as_file(), mode, temp.path())?;

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

    /// The mode the temporary file already has.
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
        self.0.temp.as_file().sync_all().map_err(&fail)?;
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
    #[must_use]
    pub fn new_entry(&self, home: &Path, mechanism: Mechanism) -> NewEntry {
        NewEntry::new(
            Portable::from_path(&self.pending.dest, home),
            self.written(),
            self.pending.mode,
            mechanism,
        )
        .with_prior(self.pending.prior.prior_bytes())
        .with_created_dirs(
            self.pending
                .created_dirs
                .iter()
                .map(|dir| Portable::from_path(dir, home))
                .collect(),
        )
    }

    /// `rename` the temporary file onto the destination, then `fsync` the
    /// destination directory so the rename itself is durable.
    ///
    /// A hard link to the destination is **not** followed: the destination is
    /// replaced by name, so any other link to the old inode keeps the old
    /// content. That is inherent to an atomic rename and is why a mode-only
    /// change goes through [`set_mode`] instead.
    ///
    /// # Errors
    ///
    /// [`Error::Write`] wrapping the failing `rename` or `fsync`. The temporary
    /// file is removed either way.
    pub fn publish(self) -> Result<(), Error> {
        let Self {
            pending: Pending {
                temp, dest, mode, ..
            },
            ..
        } = self;

        let dir = parent_of(&dest)?;
        temp.persist(&dest).map_err(|e| Error::Write {
            path: dest.clone(),
            source: e.error,
        })?;
        fsync_dir(dir)?;

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
/// failed — exactly what it held before. No temporary file is left behind in
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

/// Make sure `path` is a directory at `mode`, creating it if it is absent.
///
/// The entry point for a **declared** directory target. Missing ancestors are
/// created at [`Mode::DEFAULT_DIR`]; `path` itself is created at `mode`.
///
/// An existing directory whose mode differs is reported as
/// [`Action::Modify`] and **is not changed here**: `plan` announces it and
/// `apply` closes it with [`set_mode`], so the two never disagree. A directory
/// bx did not create is the user's, and a mode it did not ask for is not
/// silently taken from it.
///
/// # Errors
///
/// [`Error::Write`] when a directory cannot be created, and [`Error::Read`]
/// when `path` cannot be stat'd.
pub fn ensure_dir(path: &Path, mode: Mode) -> Result<Action, Error> {
    let Some(meta) = optional_metadata(path)? else {
        create_missing_dirs(path, mode)?;
        tracing::debug!(path = %path.display(), %mode, "created a directory");
        return Ok(Action::Create);
    };

    match Kind::from(meta.file_type()) {
        Kind::Dir if mode_of(&meta) == mode => Ok(Action::Unchanged),
        Kind::Dir => Ok(Action::Modify),
        _ => Ok(Action::Conflict),
    }
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
    Ok(Parent {
        path: dir.to_path_buf(),
        state: parent_state(dir)?,
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
            // bx's to report; otherwise the failure is a genuine read error.
            return match std::fs::symlink_metadata(dir) {
                Ok(_) => Ok(ParentState::Unusable(format!(
                    "{} does not resolve to a directory ({source}), so bx cannot write a file inside it",
                    dir.display()
                ))),
                Err(_) => Err(Error::Read {
                    path: dir.to_path_buf(),
                    source,
                }),
            };
        }
    }

    // Nothing resolves at `dir`. That is ordinarily a directory bx will create,
    // but it is also what a dangling symlink anywhere along the path reports,
    // and `mkdir` cannot create a directory through one. The deepest component
    // that is present at all settles which of the two it is.
    for ancestor in dir.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
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
        .take_while(|path| matches!(optional_metadata(path), Ok(None)))
        .map(Path::to_path_buf)
        .collect();

    for path in missing.iter().rev() {
        let mode = if path == dir {
            leaf_mode
        } else {
            Mode::DEFAULT_DIR
        };
        create_dir_at(path, mode)?;
    }
    Ok(missing)
}

/// `mkdir` one directory at exactly `mode`.
fn create_dir_at(path: &Path, mode: Mode) -> Result<(), Error> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        // Somebody else created it between the stat and the mkdir. It is not
        // bx's directory then, so its mode is not bx's to set.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(source) => {
            return Err(Error::Write {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    // `mkdir`'s mode argument is masked by the umask; `chmod` is not.
    set_mode(path, mode)
}

/// `fchmod`, so the mode is the declared one and not the declared one masked by
/// the process `umask`.
fn fchmod(file: &std::fs::File, mode: Mode, path: &Path) -> Result<(), Error> {
    rustix::fs::fchmod(file, mode.into()).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source: source.into(),
    })
}

/// `fsync` a directory, so a rename inside it survives a power loss.
fn fsync_dir(dir: &Path) -> Result<(), Error> {
    let fail = |source: Errno| Error::Write {
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
        // A directory cannot be replaced by a rename from a regular file, so
        // `persist` fails after the temporary file has been written in full.
        std::fs::create_dir(&dest).expect("occupy");

        let err = staged.commit(b"x").expect_err("must fail");
        assert_eq!(err.path(), dest);
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
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

    #[test]
    fn ensure_dir_creates_at_the_declared_mode_and_reports_drift() {
        let home = guarded_home();
        let dir = home.child(".ssh");

        assert_eq!(
            ensure_dir(&dir, Mode::PRIVATE_DIR).expect("create"),
            Action::Create,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Idempotence: the second call changes nothing and reports nothing.
        assert_eq!(
            ensure_dir(&dir, Mode::PRIVATE_DIR).expect("again"),
            Action::Unchanged,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Drift is reported and not resolved behind the user's back.
        set_mode(&dir, Mode::DEFAULT_DIR).expect("widen");
        assert_eq!(
            ensure_dir(&dir, Mode::PRIVATE_DIR).expect("drift"),
            Action::Modify,
        );
        assert_eq!(
            mode_of_path(&dir),
            Mode::DEFAULT_DIR,
            "ensure_dir reports the drift; apply closes it with set_mode",
        );

        set_mode(&dir, Mode::PRIVATE_DIR).expect("close the drift");
        assert_eq!(
            ensure_dir(&dir, Mode::PRIVATE_DIR).expect("converged"),
            Action::Unchanged,
        );
    }

    #[test]
    fn ensure_dir_creates_implicit_ancestors_at_the_default_dir_mode() {
        let home = guarded_home();
        assert_eq!(
            ensure_dir(&home.child("a/b/c"), Mode::PRIVATE_DIR).expect("create"),
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
            ensure_dir(&path, Mode::PRIVATE_DIR).expect("report"),
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
            ensure_dir(&home.child("link"), Mode::PRIVATE_DIR).expect("report"),
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

    /// A locked, writable ledger for a guarded home.
    fn ledger_for(home: &GuardedHome) -> (StateDir, ExclusiveLock, Ledger) {
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure the state directory");
        let lock = ExclusiveLock::acquire(&dir).expect("acquire the lock");
        let ledger = Ledger::open(&dir, &lock).expect("open").value;
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
            .record(filled.new_entry(home.path(), Mechanism::Own))
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
                    Portable::from_path(&dest, home.path()),
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
        let entry = filled.new_entry(home.path(), Mechanism::Own);
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
}
