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
//! file is reported through `tracing::warn!` and replaced by what survived it —
//! the empty default, or the rows that check out when the damage is confined to
//! rows and [`Damage::is_partial`] says so. A holder of the [`ExclusiveLock`] also moves it aside, to
//! the quarantine number after the highest present — `<name>.corrupt`, then
//! `<name>.corrupt.1`, … — never over an earlier quarantine, and not into a
//! gap one left until the top number, `<name>.corrupt.<u64::MAX>`, is present,
//! whoever made it (from then on, the lowest free number) — and the next save
//! writes a clean file. A lockless
//! reader moves nothing ([`Health::Damaged`]): a rename by path could move
//! aside a file a writer saved after the read. The damaged bytes are kept,
//! never deleted, so a human or `bx doctor` can still look at them. See
//! [`Damage`] and [`Health`].
//!
//! The one damaged file that stops bx is one the lock holder cannot move
//! aside — a state directory it cannot write, a name too long for a
//! quarantine suffix. Resetting it would leave the damaged bytes at the name
//! the next save writes, so that is [`Error::CannotQuarantine`], and nothing
//! is renamed, reset or written.
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
//! # `sudo bx` is refused, on purpose
//!
//! [`StateDir::ensure`] and the lock path compare the state directory's owner
//! against the *effective* uid, so a `~/.local/state/bx` owned by the ordinary
//! user is [`Error::ForeignOwner`] to a root process and `sudo bx` stops there.
//! That is the intended consequence and not an oversight (r4 round 2, CL8): the
//! directory holds verbatim copies of the user's private files, and a root run
//! writing into a directory an unprivileged account controls is a directory
//! that account can swap under it. The message says "run bx as the account that
//! owns it", which is the supported way to run it.
//!
//! A file that **cannot be read** is a different thing and is handled the
//! opposite way. `EACCES` on a state file — left in a directory an earlier root
//! run created — `EIO` from a failing
//! disk, `EMFILE` from fd exhaustion: in none of those is anything known about
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

use std::path::{Path, PathBuf};

use crate::fs::Mode;

pub use dir::StateDir;
pub use fingerprint::{Fingerprint, Fingerprints};
pub use hash::ContentHash;
pub use ledger::RestoreRef;
pub use ledger::{
    Ledger, LedgerEntry, LedgerView, Mechanism, NewEntry, Prior, PriorBytes, Withdrawal,
};
pub use lock::{ExclusiveLock, Holder, SharedLock};
pub use store::{Damage, Health, Loaded, MAX_STATE_FILE, Unlisted};

/// Everything that can go wrong in the state directory.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file occupies a path the state directory needs to be a directory.
    #[error("{} exists and is not a directory; move or remove it", .path.display())]
    NotADirectory {
        /// The offending path.
        path: PathBuf,
    },
    /// A directory could not be created because a directory above it cannot be
    /// written in by this account.
    ///
    /// Usually a `umask` with owner bits in it — `0277`, `0377`, `0500` — met
    /// on a home with no `~/.local/state` yet: the ancestors bx creates take
    /// the process `umask`, and one at `0500` is a directory this account can
    /// read and search and not write. Reported separately from
    /// [`Error::CreateDir`] because "Permission denied" alone names neither the
    /// directory in the way nor the `umask` that made it.
    #[error(
        "creating {}: {} is {mode}, and this account cannot write in it. If your umask strips \
         the owner's write or execute bit, that is what made it. Run `chmod u+wx {}` and run bx \
         again",
        .path.display(),
        .ancestor.display(),
        .ancestor.display()
    )]
    UnwritableAncestor {
        /// The directory bx was trying to create.
        path: PathBuf,
        /// The deepest directory above it that exists, and cannot be written.
        ancestor: PathBuf,
        /// That directory's mode.
        mode: Mode,
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
    /// Usually the caller's defect: a rename or a save under another
    /// directory's lock is as unguarded as one under no lock at all, so nothing
    /// is read, renamed or written.
    ///
    /// When `held` and `needed` are the same path, it is not: the lock file was
    /// replaced or removed while it was held — an outside `mv` or `rm` — so a
    /// second bx may have locked a new file at that path. The message then says
    /// so, and names the path once. [`Ledger::record`],
    /// [`Ledger::adopt_current_as_prior`] and [`Ledger::save`] check for this
    /// before they write.
    #[error("{}", wrong_lock(.held, .needed))]
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
    /// A state file recomputation cannot rebuild — the ledger — says it was
    /// written by a newer bx than this one.
    ///
    /// Not damage: the likeliest cause is an older bx run after a newer one,
    /// and the file is intact in a format this build cannot read. Discarding
    /// it would make the next apply record bx's own output as every prior, so
    /// it is refused, and nothing is renamed or reset.
    ///
    /// It can also be one flipped bit in the version number of an intact
    /// file, which no newer bx will ever read. So the message always names the
    /// way out a human can take — move the file aside, and what that costs —
    /// and says the version number may be damaged when the rest of the file
    /// reads as this build's format ([`Error::FutureVersion::payload_readable`]).
    #[error("{}", future_version(.path, *.found, *.supported, *.payload_readable))]
    FutureVersion {
        /// The state file.
        path: PathBuf,
        /// The format version on disk.
        found: u16,
        /// The newest format version this build understands.
        supported: u16,
        /// Whether everything but the version also decodes as the newest
        /// format this build understands.
        ///
        /// A newer bx that changed nothing this build decodes is possible, so
        /// this is not proof of damage — but a newer format that reshaped the
        /// payload would not decode, and a flipped bit in the version would.
        payload_readable: bool,
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
    /// The ledger's path is a symbolic link that leads nowhere: to something
    /// that does not exist, round a loop of links (`ELOOP`), or through a file
    /// (`ENOTDIR`).
    ///
    /// Not "no state": the likeliest cause is state kept on storage that is not
    /// there right now, and reading it as fresh would let the next save replace
    /// the link — and the priors behind it — with an empty ledger.
    ///
    /// Only the ledger is refused. The same link at the fingerprint cache is
    /// [`Damage::DanglingLink`], and degrades to recomputation like any other
    /// damage to a cache.
    #[error(
        "{} is a symbolic link to something that does not exist, or that cannot be followed \
         (the links loop, or the path runs through a file); bx will not read that as having no \
         state. Restore what it points at, or remove the link",
        .path.display()
    )]
    DanglingLink {
        /// The state file.
        path: PathBuf,
    },
    /// The ledger's path — itself, or through a symbolic link — names
    /// something other than a regular file or a directory: a FIFO, a device or
    /// a socket. A directory is [`Error::Read`], as it always was.
    ///
    /// Nothing is read from it: a FIFO would block until a writer appeared,
    /// and a device such as `/dev/zero` would never end. Nothing is renamed
    /// either, because nothing is known about what it holds. The same thing at
    /// the fingerprint cache is [`Damage::NotAFile`], and degrades to
    /// recomputation.
    #[error(
        "{} is not a regular file (a FIFO, a device or a socket, or a symbolic link to one); bx will not read it as the ledger. Put the ledger back, or move it aside",
        .path.display()
    )]
    StateNotAFile {
        /// The state file.
        path: PathBuf,
    },
    /// The ledger is longer than [`MAX_STATE_FILE`], a length no ledger bx
    /// writes comes near.
    ///
    /// At most one byte past the limit is read, so the refusal costs a bounded
    /// allocation. Nothing is renamed. The same length at the fingerprint cache
    /// is [`Damage::TooLarge`], and degrades to recomputation.
    #[error(
        "{} is longer than {MAX_STATE_FILE} bytes, which no ledger bx writes comes near; bx will \
         not read it. If it is a symbolic link, check what it points at",
        .path.display()
    )]
    StateTooLarge {
        /// The state file.
        path: PathBuf,
    },
    /// An entry handed to [`Ledger::record`] names a directory bx created that
    /// is not an ancestor of the target.
    ///
    /// The stored list is ordered by depth, and depth alone orders it only
    /// because every entry is an ancestor of one path. A directory that is not
    /// would be sorted among them by a number that says nothing about it, and
    /// `bx rm` would then try to remove, in that order, a directory it never
    /// created for this target. Nothing is recorded and nothing is stored.
    #[error(
        "bx will not record {dir} as a directory it created for {target}: it is not an ancestor \
         of it. Nothing was recorded"
    )]
    UnrelatedCreatedDir {
        /// The target, as the entry names it.
        target: String,
        /// The directory that is not an ancestor of it.
        dir: String,
    },
    /// The state directory, or its lock file, is owned by another account.
    ///
    /// The module validates file type, link-ness, `nlink` and mode precisely
    /// to establish "this is ours"; owner is the component of that judgement
    /// that can be established rather than guessed. A `~/.local/state/bx`
    /// owned by another uid at `0700` would otherwise be accepted as bx's own,
    /// and bx would write the user's displaced private bytes into a directory
    /// that account controls — and lock against a file it can replace.
    #[error(
        "{} is owned by uid {owner}, and bx is running as uid {ours}; bx will not keep your \
         files in a directory another account owns, nor lock against a file it owns. Move it \
         aside, or run bx as the account that owns it",
        .path.display()
    )]
    ForeignOwner {
        /// The directory or lock file.
        path: PathBuf,
        /// The uid that owns it.
        owner: u32,
        /// This process's effective uid.
        ours: u32,
    },
    /// A directory the state directory needs is a symbolic link that leads
    /// nowhere: to nothing, round a loop of links (`ELOOP`), or through a file
    /// (`ENOTDIR`).
    ///
    /// The state directory itself, `restore/` or `shell/`. `mkdir` returns
    /// `EEXIST` for such a link, because the link occupies the name, so
    /// without this the user was told the directory they can see cannot be
    /// read. [`Error::DanglingLink`] is the same condition for a state *file*.
    #[error(
        "{} is a symbolic link to {}, which does not exist or cannot be followed (the links \
         loop, or the path runs through a file). Restore what it points at, or remove the link",
        .path.display(),
        .target.display()
    )]
    DanglingStateDir {
        /// The link.
        path: PathBuf,
        /// What it names, as the link spells it.
        target: PathBuf,
    },
    /// The state directory is a symbolic link to a directory that users other
    /// than its owner can read or write.
    ///
    /// bx narrows a directory it created, but never changes the mode of one it
    /// reached through a link, which may be shared with other users; and it will
    /// not keep prior copies of private files where others can list or replace
    /// them. Search permission alone is not refused here: `0711` exposes no file
    /// bx writes — see [`Error::ExposedLocalLayer`] for the one it does not.
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
    /// The state directory is a symbolic link to a directory users other than
    /// its owner can search, and `local.toml` in it is readable or writable by
    /// them.
    ///
    /// Search permission exposes only a name someone already knows, and every
    /// file bx writes in the state directory is `0600`. `local.toml` is the
    /// exception: the user writes it, with whatever `umask` they have, under a
    /// name nobody has to guess. A directory bx created is narrowed to `0700`,
    /// which protects the file whatever its mode; a linked one is never
    /// narrowed, so while it is searchable bx requires the file to be private,
    /// and changes neither mode itself.
    ///
    /// A `local.toml` that is itself a link is judged where the file is: the
    /// mode reported is that file's, and it is refused only while the directory
    /// holding it can be searched by others too. A link that leads to no
    /// regular file exposes nothing here.
    ///
    /// The refusal judges those two modes and no ancestor, so it is
    /// conservative: a private ancestor can already keep every other account
    /// out. The message therefore states the modes and says the file can be
    /// reached wherever its directories allow, never that anyone can open it,
    /// and its remedy names the directory the link resolves to, whose mode is
    /// the one to change.
    #[error(
        "{} is a symbolic link to {}, a directory whose mode lets users other than its owner \
         search it (mode {mode}), and {} in it has a mode that lets them read or write it (mode \
         {file_mode}), so it can be reached by other accounts wherever its directories allow. \
         bx will not change the mode of a directory it did not create, nor of a file you wrote. \
         Make the file private (chmod 600 {}), or remove search permission from the linked \
         directory (chmod go-x {})",
        .path.display(),
        .target.display(),
        .file.display(),
        .file.display(),
        .target.display()
    )]
    ExposedLocalLayer {
        /// The linked directory.
        path: PathBuf,
        /// The directory the link resolves to, or the link itself if it no
        /// longer resolves by the time the refusal is reported.
        target: PathBuf,
        /// The mode of the directory the link names.
        mode: Mode,
        /// `local.toml` inside it.
        file: PathBuf,
        /// That file's mode.
        file_mode: Mode,
    },
    /// A state file is damaged, and the holder of the exclusive lock could not
    /// move it aside.
    ///
    /// Damage degrades to the empty default only once the damaged bytes are
    /// kept under a quarantine name; reporting [`Health::Reset`] with the file
    /// still in place would let the next save write over it. So nothing is
    /// renamed, reset or written, and bx stops: the file may be the only index
    /// there is to the user's restore blobs.
    #[error(
        "{} is damaged ({damage}), and bx could not move it aside: {source}. Nothing was \
         changed. Move it aside by hand, to {}.corrupt (or {}.corrupt.<n> if that is taken), \
         and run bx again",
        .path.display(),
        .path.display(),
        .path.display()
    )]
    CannotQuarantine {
        /// The damaged state file, left where it is.
        path: PathBuf,
        /// What is wrong with it.
        damage: Damage,
        /// Why it could not be moved aside.
        #[source]
        source: std::io::Error,
    },
    /// A ledger entry references a restore snapshot that is not on disk.
    #[error("the restore snapshot {digest} is missing from {}", .path.display())]
    RestoreMissing {
        /// The digest the ledger recorded.
        digest: ContentHash,
        /// Where the snapshot should have been.
        path: PathBuf,
    },
    /// Something other than the plain file bx wrote occupies a restore
    /// snapshot's name.
    ///
    /// A symlink, a directory, a FIFO or a device. Reading one of these would
    /// block forever on a FIFO, or allocate without bound through a link to
    /// `/dev/zero`, so the read side refuses anything but a regular file.
    ///
    /// A second hard link is **not** one of them: see
    /// [`LedgerView::restore_bytes`] for why the write side's `nlink` test is
    /// not repeated on the read side.
    #[error(
        "the restore snapshot {digest} is not the plain file bx wrote: {} is a symbolic link, a \
         directory or a special file. Move it aside and run bx again",
        .path.display()
    )]
    RestoreNotAFile {
        /// The digest the ledger recorded.
        digest: ContentHash,
        /// The name it should have been at.
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
    ///
    /// Any edit outside bx's lines raises this, and re-recording converges
    /// nowhere, so the message names the two ways out, and what the second
    /// leaves behind. Putting the file back needs nothing from bx. Accepting the
    /// file as it is now is [`Ledger::adopt_current_as_prior`], which the
    /// command that reports the conflict must offer. Afterwards `bx rm`
    /// restores the file exactly as it was accepted — bx's region or include
    /// line in it as it was then, stale and no longer managed, for the user to
    /// remove by hand — and what was there before bx stays in the ledger's
    /// history: the original in [`LedgerEntry::superseded`], or, for a file bx
    /// created, [`LedgerEntry::superseded_absent`].
    #[error(
        "{target} changed since bx last wrote it, and bx shares that file through a managed \
         region or an include line, so it still holds bx's own lines; bx will not record it \
         as your original. Nothing was recorded. To go on, either put the file back as bx last \
         wrote it, or accept the file as it is now as the version `bx rm` restores. Accepting \
         keeps bx's lines as they are in it now: `bx rm` will write them back stale, bx no \
         longer manages them there, and you remove them by hand. What was there before bx, the \
         original file or that there was none, stays in the ledger's history"
    )]
    PriorConflict {
        /// The target, as the ledger keys it.
        target: String,
        /// The digest of the changed bytes that were not adopted.
        displaced: ContentHash,
    },
}

/// [`Error::WrongLock`]'s message: a lock file replaced while held when both
/// paths are the same, and another directory's lock otherwise.
fn wrong_lock(held: &Path, needed: &Path) -> String {
    if held == needed {
        format!(
            "the lock file {} was replaced or removed while bx held it, so another bx may be \
             changing this state directory; nothing was read, renamed or written. Let any other \
             bx finish, then run bx again",
            held.display()
        )
    } else {
        format!(
            "the lock held, {}, is not the lock of the state directory being changed, {}; nothing \
             was read, renamed or written. Take the lock of that state directory",
            held.display(),
            needed.display()
        )
    }
}

/// [`Error::FutureVersion`]'s message, which always names the way out a human
/// can take and what it costs.
fn future_version(path: &Path, found: u16, supported: u16, payload_readable: bool) -> String {
    let path = path.display();
    let damaged = if payload_readable {
        format!(
            " Its contents also read as format {supported}, so the version number itself may be \
             damaged rather than newer."
        )
    } else {
        String::new()
    };
    format!(
        "{path} says it was written by a newer bx: it is format version {found}, and this bx \
         understands up to {supported}. Nothing was changed.{damaged} Run a bx at least as new as \
         the one that wrote it. If no newer bx has run on this account, move it aside yourself, \
         to {path}.corrupt (or {path}.corrupt.<n> if that is taken): bx then starts an empty \
         ledger, and `bx rm` can no longer restore any file bx changed before; the copies in \
         restore/ are kept"
    )
}
