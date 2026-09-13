//! The state directory — `$XDG_STATE_HOME/bx`, default `~/.local/state/bx`.
//!
//! bx's layout has two halves. The *config repo* is a git working tree the user
//! owns, commits and publishes. The **state directory** is the other half: it is
//! never a git working tree, never published, and holds only what the machine
//! needs to know about this account — what bx wrote, what it replaced, and what
//! it can skip recomputing.
//!
//! Three things live here, and this module builds all three:
//!
//! * [`Ledger`] — what bx last wrote to each target, the digest of those bytes,
//!   and the prior bytes it displaced. This is what makes `bx rm` exact, and
//!   what lets `bx plan` tell *modified by bx* from *modified by someone else*.
//! * [`Fingerprints`] — an opaque cache keyed by an opaque string, so expensive
//!   work is skipped when its inputs have not changed.
//! * [`ExclusiveLock`] / [`SharedLock`] — one advisory `flock` over the whole
//!   directory, so two mutating `bx` processes cannot interleave.
//!
//! # Every file here is reconstructible from bad bytes — not from no bytes
//!
//! A machine-owned file that becomes an error the user cannot clear is a defect,
//! so damaged *contents* are never fatal. A truncated, garbled or wrong-kind
//! file is reported through `tracing::warn!` and replaced by the empty default. A holder of the [`ExclusiveLock`] also moves it aside, to
//! the first free `<name>.corrupt`, `<name>.corrupt.1`, … — never over an earlier
//! quarantine — and the next save writes a clean file. A lockless reader moves
//! nothing ([`Health::Damaged`]): a rename by path could move aside a file a
//! writer saved after the read. The damaged bytes are kept, never deleted, so a
//! human or `bx doctor` can still look at them. See [`Damage`] and [`Health`].
//! Every load lists the quarantines present in [`Loaded::quarantined`],
//! whatever its health, so a run that quarantined a file and stopped before its
//! save does not leave the next one looking at [`Health::Fresh`] and nothing
//! else.
//!
//! A stored value refused for a reason that says nothing about its bytes — a
//! ledger checked against a home spelled differently from the one it was
//! written under — is not damage either: [`Error::ForeignPath`] reaches the
//! caller, and nothing is renamed.
//!
//! Nor is a file written by a **newer bx**, when it is one recomputation cannot
//! rebuild. After a rollback to an older bx the ledger is almost certainly
//! intact and merely in a format this build cannot read; resetting it would
//! record bx's own output as every prior, and every rollback would add another
//! quarantine. So a newer ledger is [`Error::FutureVersion`], and nothing is
//! renamed. A newer fingerprint cache is still damage: losing it costs a
//! recomputation.
//!
//! A file that **cannot be read** is a different thing and is handled the
//! opposite way. `EACCES` left behind by a `sudo bx`, `EIO` from a failing
//! disk, `EMFILE` from fd exhaustion — in none of those is anything known about
//! the file's contents, and the bytes a quarantine would move aside may be a
//! perfectly good ledger. So nothing is renamed, nothing is replaced, and
//! [`Error::Read`] is returned: [`Ledger::open`], [`LedgerView::read`] and
//! [`Fingerprints::read`] are fallible for exactly this reason. The ledger is
//! the one state file recomputation cannot rebuild — discarding it loses the
//! prior bytes `bx rm` restores, permanently — so an access failure has to stop
//! bx rather than silently reset it.
//!
//! # Resolution takes an explicit home
//!
//! [`StateDir::resolve`] takes the home directory as an argument and reads no
//! environment variable. Two tests with two tempdir `$HOME`s therefore get two
//! independent state directories. The XDG rule itself lives in exactly one place
//! — [`crate::paths::xdg_base`] — and a caller that has an `$XDG_STATE_HOME`
//! value to honour passes it to [`StateDir::resolve_in`].
//!
//! # A note on network filesystems
//!
//! The lock is `flock(2)`. On a home directory mounted over NFS with `nolock`,
//! `flock` silently provides no exclusion at all. bx's state directory is
//! per-account local storage by design, so this is documented rather than
//! handled.

mod dir;
mod fingerprint;
mod hash;
mod ledger;
mod lock;
mod store;

use std::path::PathBuf;

use crate::fs::Mode;

pub use dir::StateDir;
pub use fingerprint::{Fingerprint, Fingerprints};
pub use hash::ContentHash;
pub use ledger::RestoreRef;
pub use ledger::{Ledger, LedgerEntry, LedgerView, Mechanism, NewEntry, Prior, PriorBytes};
pub use lock::{ExclusiveLock, Holder, SharedLock};
pub use store::{Damage, Health, Loaded};

/// Everything that can go wrong in the state directory.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file occupies a path the state directory needs to be a directory.
    #[error("{} exists and is not a directory; move or remove it", .path.display())]
    NotADirectory {
        /// The offending path.
        path: PathBuf,
    },
    /// A directory could not be created.
    #[error("creating {}: {source}", .path.display())]
    CreateDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
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
    /// A write failed.
    #[error(transparent)]
    Write(#[from] crate::fs::Error),
    /// A value could not be encoded as MessagePack. Only reachable for a type
    /// that cannot round-trip, which is a bug rather than a user condition.
    #[error("encoding {kind}: {source}")]
    Encode {
        /// The envelope kind being written — `bx.ledger`, `bx.fingerprints`.
        kind: &'static str,
        /// The underlying failure.
        #[source]
        source: rmp_serde::encode::Error,
    },
    /// Another process holds the state directory lock.
    #[error("another bx process is already running: {holder} (lock file {})", .path.display())]
    Locked {
        /// Who holds it, as far as the lock file says.
        holder: Holder,
        /// The lock file.
        path: PathBuf,
    },
    /// Something other than the plain file bx creates occupies the lock path.
    ///
    /// A directory, a symlink, a second hard link, a FIFO or a device. The lock
    /// file's body is truncated on every exclusive acquisition, so opening any
    /// of these could empty a file the user wrote; bx refuses, names the path,
    /// and says what to do.
    #[error(
        "{} is not a plain file bx created (a directory, a symlink, a hard link or a special \
         file); bx will not open it. Move it aside and run bx again",
        .path.display()
    )]
    LockNotAFile {
        /// The lock path.
        path: PathBuf,
    },
    /// The lock file could not be opened or locked.
    #[error("locking {}: {source}", .path.display())]
    Lock {
        /// The lock file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// The exclusive lock presented is not the lock of the state directory the
    /// operation would change.
    ///
    /// The caller's defect. A rename or a save under another directory's lock
    /// is as unguarded as one under no lock at all, so nothing is read,
    /// renamed or written.
    #[error(
        "the lock held, {}, is not the lock of the state directory being changed, {}; nothing \
         was read, renamed or written. Take the lock of that state directory",
        .held.display(),
        .needed.display()
    )]
    WrongLock {
        /// The lock file the presented guard holds.
        held: PathBuf,
        /// The lock file of the directory the operation needed.
        needed: PathBuf,
    },
    /// The home a stored document's paths are to be checked against is not a
    /// home this crate can answer for.
    ///
    /// The caller's defect, not the document's, so it is reported before the
    /// file is read: an intact ledger is never quarantined because it was
    /// handed a bad home.
    #[error("checking stored paths against the home {}: {source}", .home.display())]
    Home {
        /// The home that was passed.
        home: PathBuf,
        /// Why it was refused.
        #[source]
        source: crate::paths::Error,
    },
    /// A stored path cannot be used with the home it was checked against.
    ///
    /// Almost always the same account with its home spelled another way — a
    /// `/home` → `/var/home` alias, or `HOME=/` — rather than a damaged file,
    /// so it is refused rather than degraded. Nothing is renamed or reset: the
    /// ledger is left exactly where it is, and bx stops, because proceeding
    /// against an empty ledger would record bx's own output as every prior.
    #[error(
        "{} stores the path {stored}, which cannot be used with the home {}: {source}. \
         Nothing was changed; run bx with the home spelled as it was when bx wrote it",
        .path.display(),
        .home.display()
    )]
    ForeignPath {
        /// The state file holding the path.
        path: PathBuf,
        /// The home it was checked against.
        home: PathBuf,
        /// The path as it is stored.
        stored: String,
        /// Why it cannot be used with that home.
        #[source]
        source: Box<crate::paths::Error>,
    },
    /// A state file recomputation cannot rebuild — the ledger — was written by
    /// a newer bx than this one.
    ///
    /// Not damage: the likeliest cause is an older bx run after a newer one,
    /// and the file is intact in a format this build cannot read. Discarding
    /// it would make the next apply record bx's own output as every prior, so
    /// it is refused, and nothing is renamed or reset.
    #[error(
        "{} was written by a newer bx: it is format version {found}, and this bx understands up \
         to {supported}. Nothing was changed; run a bx at least as new as the one that wrote it",
        .path.display()
    )]
    FutureVersion {
        /// The state file.
        path: PathBuf,
        /// The format version on disk.
        found: u16,
        /// The newest format version this build understands.
        supported: u16,
    },
    /// A target handed to [`Ledger::record`] names a path that cannot be used
    /// with the home the ledger was opened under.
    ///
    /// [`Error::ForeignPath`] is the same rule, applied when a ledger is read.
    /// Recording such a path would leave a ledger every later open under that
    /// home refuses, with no way back, so `record` refuses it first. Nothing is
    /// recorded and nothing is stored.
    #[error(
        "bx will not record {stored}, which cannot be used with the home {}: {source}. Nothing \
         was recorded",
        .home.display()
    )]
    ForeignRecord {
        /// The home the ledger was opened under.
        home: PathBuf,
        /// The path as the entry names it.
        stored: String,
        /// Why it cannot be used with that home.
        #[source]
        source: Box<crate::paths::Error>,
    },
    /// The ledger's path is a symbolic link to something that does not exist.
    ///
    /// Not "no state": the likeliest cause is state kept on storage that is not
    /// there right now, and reading it as fresh would let the next save replace
    /// the link — and the priors behind it — with an empty ledger.
    ///
    /// Only the ledger is refused. A dangling link at the fingerprint cache is
    /// [`Damage::DanglingLink`], and degrades to recomputation like any other
    /// damage to a cache.
    #[error(
        "{} is a symbolic link to something that does not exist; bx will not read that as \
         having no state. Restore what it points at, or remove the link",
        .path.display()
    )]
    DanglingLink {
        /// The state file.
        path: PathBuf,
    },
    /// The state directory is a symbolic link to a directory that users other
    /// than its owner can read or write.
    ///
    /// bx narrows a directory it created, but never changes the mode of one it
    /// reached through a link, which may be shared with other users; and it will
    /// not keep prior copies of private files where others can list or replace
    /// them. Search permission alone is not refused: `0711` exposes nothing.
    /// Group permission is, even for a user-private group, which bx cannot
    /// confirm without reading the account database.
    #[error(
        "{} is a symbolic link to a directory that users other than its owner can read or write \
         (mode {mode}); bx will not change the mode of a directory it did not create, nor keep \
         your files in it. Remove group and other read and write permission from it \
         (chmod go-rw), or replace the link",
        .path.display()
    )]
    SharedLinkedDir {
        /// The linked directory.
        path: PathBuf,
        /// The mode of the directory the link names.
        mode: Mode,
    },
    /// A ledger entry references a restore snapshot that is not on disk.
    #[error("the restore snapshot {digest} is missing from {}", .path.display())]
    RestoreMissing {
        /// The digest the ledger recorded.
        digest: ContentHash,
        /// Where the snapshot should have been.
        path: PathBuf,
    },
    /// A restore snapshot's bytes do not hash to the digest that named them.
    #[error("the restore snapshot {} does not match its digest {digest}", .path.display())]
    RestoreCorrupt {
        /// The digest the ledger recorded.
        digest: ContentHash,
        /// The snapshot that failed to match it.
        path: PathBuf,
    },
    /// Someone other than bx changed a file bx shares with the user — through
    /// a managed region or an include line — and a record would have adopted
    /// the changed file, bx's own lines included, as what the user last had.
    ///
    /// Nothing is recorded and nothing is stored. See [`Ledger::record`].
    #[error(
        "{target} changed since bx last wrote it, and bx shares that file through a managed \
         region or an include line, so it still holds bx's own lines; bx will not record it \
         as your original. Nothing was recorded"
    )]
    PriorConflict {
        /// The target, as the ledger keys it.
        target: String,
        /// The digest of the changed bytes that were not adopted.
        displaced: ContentHash,
    },
}
