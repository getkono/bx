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
//! so damaged *contents* are never fatal. A truncated, garbled, wrong-kind or
//! future-versioned file is reported through `tracing::warn!` and replaced by
//! the empty default. A holder of the [`ExclusiveLock`] also moves it aside, to
//! the first free `<name>.corrupt`, `<name>.corrupt.1`, … — never over an earlier
//! quarantine — and the next save writes a clean file. A lockless reader moves
//! nothing ([`Health::Damaged`]): a rename by path could move aside a file a
//! writer saved after the read. The damaged bytes are kept, never deleted, so a
//! human or `bx doctor` can still look at them. See [`Damage`] and [`Health`].
//!
//! A stored value refused for a reason that says nothing about its bytes — a
//! ledger checked against a home spelled differently from the one it was
//! written under — is not damage either: [`Error::ForeignPath`] reaches the
//! caller, and nothing is renamed.
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
    /// A symlink, a second hard link, a FIFO or a device. The lock file's body
    /// is truncated on every exclusive acquisition, so opening any of these
    /// could empty a file the user wrote; bx refuses and names the path.
    #[error(
        "{} is not a plain file bx created (a symlink, a hard link or a special file); \
         bx will not open it. Move it aside and run bx again",
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
    /// A state file's path is a symbolic link to something that does not exist.
    ///
    /// Not "no state": the likeliest cause is state kept on storage that is not
    /// there right now, and reading it as fresh would let the next save replace
    /// the link — and the priors behind it — with an empty ledger.
    #[error(
        "{} is a symbolic link to something that does not exist; bx will not read that as \
         having no state. Restore what it points at, or remove the link",
        .path.display()
    )]
    DanglingLink {
        /// The state file.
        path: PathBuf,
    },
    /// The state directory is a symbolic link to a directory readable beyond
    /// its owner.
    ///
    /// bx narrows a directory it created, but never changes the mode of one it
    /// reached through a link, which may be shared with other users; and it will
    /// not keep prior copies of private files in a directory others can read.
    #[error(
        "{} is a symbolic link to a directory readable beyond its owner; bx will not change \
         the mode of a directory it did not create, nor keep your files in it. Make the \
         target 0700, or replace the link",
        .path.display()
    )]
    SharedLinkedDir {
        /// The linked directory.
        path: PathBuf,
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
