//! One MessagePack envelope, and one degradation policy for every state file.
//!
//! `CLAUDE.md` requires every machine-owned file to be *reconstructible*, so a
//! corrupt one degrades to recomputation rather than to an error the user cannot
//! clear. That requirement is met here, once, for every file in the state
//! directory: [`load`] returns the stored value, or — for damaged *contents* —
//! what survived the damage, having moved the damaged bytes aside to the next
//! `<name>.corrupt`, `<name>.corrupt.1`, … and warned about it. That is the
//! empty default for damage the decoder finds, and the rows that check out for
//! damage a loader's `check` can confine to rows; [`Damage::is_partial`] tells
//! a caller which it is holding.
//!
//! # Damage that cannot be moved aside is refused
//!
//! The empty default is safe only once the damaged bytes are kept under a
//! quarantine name, because the next save writes the file's own name. So a
//! holder of the lock that cannot move the file aside — a state directory it
//! cannot write, a name with no room for the suffix — returns
//! [`Error::CannotQuarantine`], naming the file and what is wrong with it,
//! and renames, resets and writes nothing.
//!
//! # Only the holder of the exclusive lock moves a file
//!
//! A quarantine is a rename **by path**, and a path names whatever is there when
//! the rename runs, not what was there when the bytes were read. A lockless
//! reader that read a damaged file, and then renamed the path, would move aside
//! the fresh file a writer saved in between. So [`load`] renames only when it is
//! handed an [`ExclusiveLock`] — no writer can save while that is held — and a
//! lockless reader reports [`Health::Damaged`] and touches nothing. The next
//! holder of the lock does the quarantine.
//!
//! A quarantine never renames over an earlier one. It takes the number after
//! the highest quarantine present, with `RENAME_NOREPLACE`, so a second damaged
//! ledger cannot destroy the first — which may be the only index there is to the
//! user's restore blobs — and a gap left by a deleted one is not refilled, so
//! the numbers present are in the order the quarantines were made. Those last
//! two promises end once the top number, `<name>.corrupt.<u64::MAX>`, is
//! present, whoever made it: a crafted file, or bx itself after a crafted
//! `<name>.corrupt.<u64::MAX - 1>`. It has no successor, so from then on each
//! quarantine takes the lowest free number, refilling gaps, and a crafted name
//! never blocks a quarantine. No quarantine is ever renamed over, either way.
//!
//! # A refusal is not damage
//!
//! A decoded value can also be *refused* by the file's loader for a reason that
//! says nothing about its bytes — a ledger checked against a home spelled
//! differently from the one it was written under. That is [`Rejected::Refused`]:
//! the error reaches the caller and nothing is renamed, exactly as for a file
//! that could not be read.
//!
//! # A newer format is damage only for a file recomputation rebuilds
//!
//! An envelope whose version is newer than this build's was written by a newer
//! bx, and is most likely intact. For a cache that is still [`Damage`]: losing
//! it costs a recomputation. For the ledger it is not — see [`Loss::Permanent`]
//! — so it is [`Error::FutureVersion`] and nothing is renamed. The kind and
//! version are read **before** the payload is decoded, because a newer format
//! may have changed the payload's shape, and a payload that fails to decode
//! for that reason says nothing about damage.
//!
//! # Damage is a decode failure, never an access failure
//!
//! The degradation applies to a file whose **bytes were read and are bad**. A
//! file that could not be read at all — `EACCES` because a `sudo bx` left the
//! ledger root-owned, `EIO` from a failing disk, `EMFILE` from fd exhaustion —
//! is not damaged: nothing whatever is known about its contents, and the
//! quarantined bytes would be a perfectly good ledger. [`load`] therefore
//! returns [`Error::Read`] for an access failure and **never renames a file
//! whose bytes it has not read**.
//!
//! That distinction is load-bearing for Invariant 4 rather than cosmetic. The
//! ledger is the one state file that is *not* reconstructible by recomputation:
//! nothing can recover the prior bytes of a target once the record of them is
//! discarded, so silently degrading to an empty ledger would make `bx rm`
//! restore bx's own generated content over the user's files. Losing a cache is
//! a delay; losing the ledger is permanent.
//!
//! Three conditions of the *name* rather than the bytes are the exception, and
//! only for a cache: a symbolic link that leads nowhere
//! ([`Damage::DanglingLink`]), a name that leads to something other than a
//! regular file ([`Damage::NotAFile`]), and a file longer than
//! [`MAX_STATE_FILE`] ([`Damage::TooLarge`]). None of them can be read as a
//! cache bx wrote, so a cache degrades and the name is moved aside, never what
//! a link names. For the ledger each is refused and nothing is renamed.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::Error;
use super::dir::{check_lock, ensure_dir, move_aside, quarantines};
use super::lock::ExclusiveLock;
use crate::fs::{Mode, write_atomically};

/// The longest state file [`load`] reads: 256 MiB.
///
/// Far beyond anything bx writes — the ledger indexes restore blobs rather
/// than holding their bytes, and the fingerprint cache holds one hash per
/// target — and small enough that reading one is a bounded allocation. A
/// symbolic link at a state file to some large file elsewhere is otherwise
/// read whole before the decoder can say it is not a state file.
pub const MAX_STATE_FILE: u64 = 256 * 1024 * 1024;

/// What every state file is wrapped in.
///
/// The `kind` tag is what turns "a fingerprint file copied over the ledger" from
/// a baffling decode error into [`Damage::WrongKind`], and `version` is what
/// lets a future release change the payload's shape without an older bx
/// misreading it.
#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    /// `bx.ledger`, `bx.fingerprints`.
    kind: String,
    /// The payload's format version.
    version: u16,
    /// The value itself.
    payload: T,
}

/// An envelope's kind and version, read without decoding its payload.
#[derive(Deserialize)]
struct Header {
    /// As [`Envelope::kind`].
    kind: String,
    /// As [`Envelope::version`].
    version: u16,
}

/// What losing a state file costs, which decides how far a file that cannot
/// be believed is allowed to degrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Loss {
    /// A cache: recomputation rebuilds it, so anything wrong with it degrades
    /// to the empty default.
    Recomputable,
    /// The ledger: nothing rebuilds the priors it indexes, so a condition that
    /// says the file may be intact — a newer format — is refused rather than
    /// degraded.
    Permanent,
}

/// What was wrong with a state file that had to be discarded.
///
/// Every variant but [`Damage::DanglingLink`], [`Damage::NotAFile`] and
/// [`Damage::TooLarge`] is a decode failure: the bytes were read, and they are
/// not a usable envelope. Those three are what is at the name rather than what
/// is in it, and are damage only for a [`Loss::Recomputable`] file. A file
/// that could not be read is not represented here — see [`Error::Read`] and the
/// module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Damage {
    /// The bytes are not a well-formed envelope.
    Malformed,
    /// A whole envelope decoded, and then there were more bytes.
    TrailingBytes,
    /// The envelope is a different kind of state file.
    WrongKind {
        /// The kind the file claims to be.
        found: String,
    },
    /// The envelope was written by a newer bx than this one. Only ever the
    /// health of a [`Loss::Recomputable`] file; for the ledger this is
    /// [`Error::FutureVersion`].
    FutureVersion {
        /// The version on disk.
        found: u16,
        /// The newest version this build understands.
        supported: u16,
    },
    /// The file's path is a symbolic link that leads nowhere: to something
    /// that does not exist, round a loop of links, or through a file.
    ///
    /// Only ever the health of a [`Loss::Recomputable`] file, where losing
    /// what the link named costs a recomputation; for the ledger this is
    /// [`Error::DanglingLink`]. Nothing is read through the link, and the
    /// quarantine moves the link itself, never what it names.
    DanglingLink,
    /// What the file's path names — itself, or through a symbolic link — is
    /// not a regular file or a directory: a FIFO, a device or a socket. A
    /// directory is [`Error::Read`], as it always was.
    ///
    /// Only ever the health of a [`Loss::Recomputable`] file; for the ledger
    /// this is [`Error::StateNotAFile`]. Nothing is read from it — a FIFO
    /// would block the read until a writer appeared, and a link to
    /// `/dev/zero` would never end — and the quarantine moves the name, never
    /// what a link names.
    NotAFile,
    /// The file is longer than [`MAX_STATE_FILE`], a length no state file bx
    /// writes comes near.
    ///
    /// Only ever the health of a [`Loss::Recomputable`] file; for the ledger
    /// this is [`Error::StateTooLarge`]. At most one byte past the limit is
    /// read, so an oversized file costs a bounded allocation rather than
    /// whatever its length is.
    TooLarge,
    /// The envelope decoded, and a ledger entry names a different path from
    /// the key it is stored under.
    ///
    /// `record` stores every entry under its own path, so a mismatch is not
    /// something bx wrote: it is damage, whatever home the ledger is read with.
    KeyMismatch {
        /// Every damaged row, as `(key, the path its entry names)`, in the
        /// order the file stores them. Never empty.
        rows: Vec<(String, String)>,
    },
    /// The envelope decoded, and a ledger entry lists a directory among the
    /// ones bx created on the way to its target that is not an ancestor of
    /// that target.
    ///
    /// `record` refuses one on the way in, so a stored one is not something bx
    /// wrote. Left in place it would be sorted among real ancestors by a depth
    /// that says nothing about it, and `bx rm` would remove a directory it
    /// never created for that target.
    ///
    /// The **directory** is what is dropped, not the entry: the entry, its
    /// prior and its history are loaded, less the directories named here.
    UnrelatedCreatedDirs {
        /// Every directory dropped, as `(target, the directory that is not its
        /// ancestor)`, in the order the file stores them — ascending by
        /// target, and within a target in the entry's own list order. Never
        /// empty.
        rows: Vec<(String, String)>,
    },
}

/// Why a file's loader did not accept a value that decoded.
///
/// There is no whole-file damage variant. Whole-file damage is what `decode`
/// finds, before any `check` runs; a `check` looks at rows, removes the ones
/// it rejects, and reports them — even when it rejects every row, which leaves
/// the empty default and is [`Rejected::PartialDamage`] with nothing left. A
/// `Damage` variant here was constructed by nothing in the crate, so its `From`
/// impl and both of its arms in [`judge`] were branches no input could take and
/// no test could pin, and the `Loss::Permanent` guard it carried was a second
/// copy of the one on the decode path with nothing able to establish the two
/// agreed (r4 round 2, D8).
#[derive(Debug)]
pub(crate) enum Rejected {
    /// The rows the check rejected, which it has already removed from the
    /// value; the value holds the rest, and may hold nothing.
    ///
    /// The file is quarantined exactly as for damage `decode` found, so nothing
    /// is lost — but the caller gets the rows that do check out rather than an
    /// empty default. For the ledger that is the difference between losing one
    /// target's restore index and losing every target's: `CLAUDE.md` requires a
    /// corrupt machine-owned file to degrade to recomputation, and the ledger
    /// is the one file recomputation cannot rebuild, so the degradation has to
    /// be as small as the damage.
    ///
    /// The [`Damage`] carried must be one [`Damage::is_partial`] accepts, so
    /// that a caller reading the health can tell partial survival from a total
    /// reset. A `debug_assert` in [`judge`] holds a `check` to it.
    ///
    /// **A `check` therefore cannot report whole-file damage** — the variant
    /// that could was deleted in r4 round 2 (D8) because nothing constructed
    /// it, and this is the consequence, recorded rather than left to be
    /// discovered (r4 round 3, CL1). Clearing the value and returning a
    /// non-row `Damage` here is not a way round it: the `debug_assert` refuses
    /// exactly that, because `is_partial` would then say the rows named are
    /// the whole loss when nothing was named and everything was lost. A check
    /// that genuinely needs it — one that can tell the whole file is
    /// unusable from something `decode` cannot see — should restore the
    /// `Rejected::Damage` variant and the two `judge` arms it needs. Nothing
    /// in the crate has that shape today: every check here looks at rows.
    PartialDamage(Damage),
    /// The contents may be intact, and the context they were checked against is
    /// what is wrong. Returned to the caller; nothing is renamed.
    Refused(Error),
}

impl Damage {
    /// Whether this damage is confined to what its rows name, leaving the rest
    /// of the file's contents loaded.
    ///
    /// This is what tells a caller holding a [`Health::Reset`] or a
    /// [`Health::Damaged`] whether the value beside it is the empty default or
    /// what survived. Row-shaped damage is found by a loader's `check`, which
    /// drops what the rows name and keeps everything else; every other variant
    /// is found by `decode`, before there is a value at all, and costs the
    /// whole file.
    ///
    /// A `true` here does **not** promise the value is non-empty: a file whose
    /// every row was damaged keeps none. It promises that what the rows name
    /// is the whole of what was lost (r4 round 2, D2 and CL4) — which is why a
    /// `check` that finds two kinds of row damage at once reports one and acts
    /// on only that one, leaving the other for the next load
    /// (r4 round 3, D1).
    ///
    /// What a row costs is the variant's own business: a
    /// [`Damage::KeyMismatch`] row costs its whole entry, and a
    /// [`Damage::UnrelatedCreatedDirs`] row costs one directory out of an
    /// entry that is otherwise loaded.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        match self {
            Self::KeyMismatch { .. } | Self::UnrelatedCreatedDirs { .. } => true,
            Self::Malformed
            | Self::TrailingBytes
            | Self::WrongKind { .. }
            | Self::FutureVersion { .. }
            | Self::DanglingLink
            | Self::NotAFile
            | Self::TooLarge => false,
        }
    }
}

impl std::fmt::Display for Damage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("it is not valid MessagePack"),
            Self::TrailingBytes => f.write_str("it has unexpected bytes after the end"),
            Self::WrongKind { found } => write!(f, "it is a {found} file"),
            Self::FutureVersion { found, supported } => write!(
                f,
                "it is version {found}, and this bx understands up to {supported}",
            ),
            Self::DanglingLink => f.write_str(
                "it is a symbolic link to something that does not exist, or that cannot be \
                 followed",
            ),
            Self::NotAFile => f.write_str(
                "it is not a regular file (a FIFO, a device or a socket), so it was not read",
            ),
            Self::TooLarge => write!(
                f,
                "it is longer than {MAX_STATE_FILE} bytes, which no state file bx writes comes \
                 near",
            ),
            Self::KeyMismatch { rows } => {
                let named = rows
                    .iter()
                    .map(|(key, path)| {
                        format!("its entry for {key} names a different path, {path}")
                    })
                    .collect::<Vec<_>>();
                f.write_str(&named.join("; "))
            }
            Self::UnrelatedCreatedDirs { rows } => {
                let named = rows
                    .iter()
                    .map(|(target, dir)| {
                        format!("its entry for {target} lists {dir}, which is not above it")
                    })
                    .collect::<Vec<_>>();
                f.write_str(&named.join("; "))
            }
        }
    }
}

/// Where a loaded value came from.
///
/// # What survived is the value, not the variant
///
/// [`Health::Reset`] and [`Health::Damaged`] say *the file was damaged and how
/// bx responded*. They do not say the value is empty: a loader that finds
/// row-shaped damage removes the rows it names and keeps the rest, and the
/// value then holds every row that checked out. [`Damage::is_partial`] is what
/// tells the two apart, and `health.damage().is_some_and(Damage::is_partial)`
/// is the question a `plan` or a `doctor` has to ask before it tells a user
/// that nothing bx wrote survived (r4 round 2, D2 and CL4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// There was no file. The value is the empty default, and nothing is wrong.
    Fresh,
    /// The file was read and decoded.
    Loaded,
    /// The file was damaged and has been quarantined. The value is what
    /// survived the damage: the empty default unless [`Damage::is_partial`],
    /// and the rows that checked out if it is.
    Reset(Damage),
    /// The file is damaged, and was **left where it is**, because the reader
    /// holds no exclusive lock. The value is what survived, as for
    /// [`Health::Reset`]. The next holder of the lock quarantines it.
    Damaged(Damage),
}

impl Health {
    /// Whether the damaged file has been moved aside, and the value beside this
    /// is what was recovered from it rather than what it held.
    ///
    /// **Not** "nothing survived": see the type's own documentation. A caller
    /// that means *nothing bx wrote is left* must ask
    /// `health.damage().is_some_and(Damage::is_partial)` as well, or look at
    /// the value.
    #[must_use]
    pub fn is_reset(&self) -> bool {
        matches!(self, Self::Reset(_))
    }

    /// The damage, whether or not the file has been moved aside yet.
    #[must_use]
    pub fn damage(&self) -> Option<&Damage> {
        match self {
            Self::Reset(damage) | Self::Damaged(damage) => Some(damage),
            _ => None,
        }
    }
}

/// A value, and how it came to be.
///
/// Damage is not a failure, so it travels with the value rather than in the
/// `Err` arm: a caller that wants to tell the user "your ledger was corrupt and
/// has been reset" reads [`Loaded::health`]; a caller that only wants the value
/// reads the `value` field and ignores it. The `Err` arm is reserved for a file
/// that could not be read, where there is no value to return and no health to
/// describe, and for damage the lock holder could not set aside
/// ([`Error::CannotQuarantine`]), where an empty value would be saved over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded<T> {
    /// The loaded — or default — value.
    pub value: T,
    /// Where it came from.
    pub health: Health,
    /// Every quarantine of this file in the state directory now, ascending by
    /// number — `<name>.corrupt`, `<name>.corrupt.1`, … — including one this
    /// load made. A new quarantine takes the number after the highest present
    /// and does not refill a gap, so this is the order they were made and the
    /// last is the newest — until the top number, `<name>.corrupt.<u64::MAX>`,
    /// is present, whoever made it. From then on each new quarantine takes the
    /// lowest free number, so the newest can be listed anywhere, first included.
    ///
    /// Independent of [`Loaded::health`]. A run that quarantined the file and
    /// stopped before its save leaves the next load [`Health::Fresh`], and this
    /// is what still shows that damaged bytes were set aside. They may be the
    /// only index there is to the user's restore blobs, so `plan` and `doctor`
    /// should name every one until a human moves it; bx never deletes them.
    pub quarantined: Vec<PathBuf>,
    /// The state directory, when it could not be listed, so
    /// [`Loaded::quarantined`] is what is *known* rather than what is there.
    ///
    /// `None` whenever the listing succeeded, a listing that found none
    /// included. `Some` says the load itself finished — the value and the
    /// health are what they say, and a quarantine this load made was
    /// completed and its bytes are safe — and only the listing failed. An
    /// empty `quarantined` alongside a `Some` therefore means nothing is
    /// known, never that nothing is there.
    ///
    /// A directory bx cannot list is reported this way rather than as
    /// [`Error::Read`] because the two are different facts. `Error::Read` from
    /// a load means *the file's bytes were never seen*, and a caller matching
    /// on it expects the state file's own path; a listing failure would have
    /// named the directory, and would have discarded a rename that had already
    /// happened. A state directory left at `0300` — searchable and writable,
    /// not readable — used to fail every `LedgerView::read` and
    /// `Fingerprints::read` with no remedy named, though each file in it read
    /// perfectly well.
    ///
    /// The cause travels with it: `EACCES` is a `chmod` the user can make, and
    /// `EIO` or `EMFILE` are not, and a caller that only logs would otherwise
    /// have to say "could not be listed" and stop there (r4 round 2, CL5).
    pub unlisted: Option<Unlisted>,
}

/// A state directory that could not be listed, and why.
///
/// Not an `io::Error`: [`Loaded`] is `Clone` and `PartialEq`, and `io::Error`
/// is neither. [`std::io::ErrorKind`] is both, and is the part a caller
/// branches on; the rendered cause is kept beside it for the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlisted {
    /// The directory that could not be listed.
    pub path: PathBuf,
    /// What kind of failure it was — `PermissionDenied` is the remediable one.
    pub kind: std::io::ErrorKind,
    /// The failure as it renders, for a message.
    pub cause: String,
}

impl<T> Loaded<T> {
    /// Apply `f` to the value, keeping the health.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Loaded<U> {
        Loaded {
            value: f(self.value),
            health: self.health,
            quarantined: self.quarantined,
            unlisted: self.unlisted,
        }
    }
}

/// Read a state file, degrading to `T::default()` for damaged contents.
///
/// A missing file is [`Health::Fresh`]. Damaged contents yield the default and
/// a `tracing::warn!`. With `lock`, the file is also moved to the next
/// quarantine name and the health is [`Health::Reset`]; the next [`save`] writes
/// a clean file over the original name, so the condition clears itself. Without
/// it, nothing is renamed and the health is [`Health::Damaged`].
///
/// # Errors
///
/// [`Error::Read`] if the file exists and cannot be read. That is an access
/// failure, not damage: the bytes were never seen, so they are neither
/// quarantined nor discarded, and the caller must treat it as fatal rather than
/// carry on against an empty default.
///
/// [`Error::FutureVersion`] for a [`Loss::Permanent`] file written by a newer
/// bx; nothing is renamed.
///
/// [`Error::StateNotAFile`] and [`Error::StateTooLarge`] for a
/// [`Loss::Permanent`] file whose name leads to something other than a regular
/// file, or to one longer than [`MAX_STATE_FILE`]; nothing is renamed.
///
/// [`Error::WrongLock`] if `lock` is not the lock of the directory holding
/// `path`; nothing is read.
///
/// [`Error::CannotQuarantine`] if, with `lock`, the file is damaged and cannot
/// be moved aside; nothing is renamed or reset, and the file is left in place.
pub(crate) fn load<T: DeserializeOwned + Default>(
    path: &Path,
    kind: &'static str,
    version: u16,
    loss: Loss,
    lock: Option<&ExclusiveLock>,
) -> Result<Loaded<T>, Error> {
    load_checked(path, kind, version, loss, lock, |_: &mut T| Ok(()))
}

/// [`load`], with a check on the decoded value that decoding alone cannot make.
///
/// `check` runs only on a value that decoded whole, and takes it by `&mut` so
/// that it can *remove* what it rejects. [`Rejected::PartialDamage`]
/// quarantines the file exactly as damage found by `decode` does, and keeps
/// whatever `check` left in the value — which may be nothing, when every row
/// was damaged. [`Rejected::Refused`] is returned as the error and renames
/// nothing: a value refused against context the decoder did not have — the
/// account's home — is never believed, and never discarded either.
///
/// # Errors
///
/// As [`load`], and whatever `check` refuses with.
pub(crate) fn load_checked<T: DeserializeOwned + Default>(
    path: &Path,
    kind: &'static str,
    version: u16,
    loss: Loss,
    lock: Option<&ExclusiveLock>,
    check: impl FnOnce(&mut T) -> Result<(), Rejected>,
) -> Result<Loaded<T>, Error> {
    let mut loaded = judge(path, kind, version, loss, lock, check)?;
    // Listed after any quarantine this load made, and whatever the health: an
    // earlier run's quarantine must not hide behind `Fresh`.
    //
    // A listing that fails does not fail the load. `judge` may already have
    // renamed the damaged file, and returning `Error::Read` here would report
    // a completed quarantine as a read that never happened — and would brick
    // every read of a state directory that is persistently unlistable, though
    // the file itself read perfectly. The load stands, and the unknown is
    // reported in `Loaded::unlisted`.
    match quarantines(path) {
        Ok(found) => loaded.quarantined = found,
        Err(why) => {
            let dir = path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
            tracing::warn!(
                path = %path.display(),
                directory = %dir.display(),
                "listing {}: {why}. {} was read; the quarantines of it that are present are not \
                 known.",
                dir.display(),
                path.display(),
            );
            loaded.unlisted = Some(Unlisted {
                path: dir,
                kind: why.kind(),
                cause: why.to_string(),
            });
        }
    }
    Ok(loaded)
}

/// [`load_checked`], less the listing of quarantines.
fn judge<T: DeserializeOwned + Default>(
    path: &Path,
    kind: &'static str,
    version: u16,
    loss: Loss,
    lock: Option<&ExclusiveLock>,
    check: impl FnOnce(&mut T) -> Result<(), Rejected>,
) -> Result<Loaded<T>, Error> {
    // A lock presented for another directory guards nothing here, and is
    // refused before anything is read.
    if let Some(lock) = lock {
        check_lock(path, lock)?;
    }
    let bytes = match read_state_file(path) {
        Ok(StateRead::Bytes(bytes)) => bytes,
        // Neither was read, so neither can be called intact or damaged. The
        // ledger is refused, as for a dangling link; a cache is moved aside
        // like any other damage, and recomputed.
        Ok(StateRead::NotAFile) => {
            return match loss {
                Loss::Permanent => Err(Error::StateNotAFile {
                    path: path.to_path_buf(),
                }),
                Loss::Recomputable => degrade(path, Damage::NotAFile, lock, T::default()),
            };
        }
        Ok(StateRead::TooLarge) => {
            return match loss {
                Loss::Permanent => Err(Error::StateTooLarge {
                    path: path.to_path_buf(),
                }),
                Loss::Recomputable => degrade(path, Damage::TooLarge, lock, T::default()),
            };
        }
        Err(source) => {
            // `read` follows a symlink, so a link to nothing reads as no file,
            // a link that loops as `ELOOP`, and a link whose path runs through
            // a file as `ENOTDIR`. None of those is "no state" — it is usually
            // state on storage that is not there right now. For the ledger it
            // is refused, and nothing is renamed. A cache degrades like any
            // other damage: under the lock the link itself is moved aside, so
            // the next save can write a clean file where it was.
            if leads_nowhere(&source)
                && std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
            {
                return match loss {
                    Loss::Permanent => Err(Error::DanglingLink {
                        path: path.to_path_buf(),
                    }),
                    Loss::Recomputable => degrade(path, Damage::DanglingLink, lock, T::default()),
                };
            }
            if source.kind() == std::io::ErrorKind::NotFound {
                return Ok(Loaded {
                    value: T::default(),
                    health: Health::Fresh,
                    quarantined: Vec::new(),
                    unlisted: None,
                });
            }
            // `ENOTDIR` with no link at `path` means a component above the file
            // is not a directory — a plain file at `~/.local/state/bx`, say.
            // "reading ~/.local/state/bx/ledger.mpk: Not a directory" names a
            // file inside a file and no remedy, while `Error::NotADirectory`
            // says exactly the right thing and, until now, was raised only from
            // `ensure_dir` — which a lockless read never calls (r4 round 2, D5).
            if source.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error())
                && let Some(blocking) = not_a_directory_above(path)
            {
                return Err(Error::NotADirectory { path: blocking });
            }
            return Err(Error::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    // A newer format of a file nothing can rebuild is not believed and not
    // discarded: it is intact as far as anyone knows.
    let future_version = |found, supported| {
        // One flipped bit in the version number also makes an intact file
        // "newer". Whether the rest of it reads as this build's format is what
        // the message can honestly say about that.
        let payload_readable = rmp_serde::from_slice::<Envelope<T>>(&bytes).is_ok();
        Err(Error::FutureVersion {
            path: path.to_path_buf(),
            found,
            supported,
            payload_readable,
        })
    };
    let mut value = match decode::<T>(&bytes, kind, version) {
        Ok(value) => value,
        Err(Damage::FutureVersion { found, supported }) if loss == Loss::Permanent => {
            return future_version(found, supported);
        }
        // Quarantine happens only here: after `read` succeeded and `decode` or
        // `check` found damage, so the bytes being moved aside are known to be
        // unusable — and only under the lock, so they are still the bytes read.
        Err(damage) => return degrade(path, damage, lock, T::default()),
    };
    match check(&mut value) {
        Ok(()) => Ok(Loaded {
            value,
            health: Health::Loaded,
            quarantined: Vec::new(),
            unlisted: None,
        }),
        // The same quarantine, so nothing is lost, and the rows that did check
        // out rather than the empty default. `check` has already removed the
        // damaged ones from `value`.
        Err(Rejected::PartialDamage(damage)) => {
            debug_assert!(
                damage.is_partial(),
                "a check's damage must be one `Damage::is_partial` accepts, or the health \
                 reports a total reset for a file that kept rows",
            );
            degrade(path, damage, lock, value)
        }
        Err(Rejected::Refused(error)) => Err(error),
    }
}

/// What [`read_state_file`] found at a state file's path.
#[derive(Debug)]
enum StateRead {
    /// A regular file of at most [`MAX_STATE_FILE`] bytes, and its bytes.
    Bytes(Vec<u8>),
    /// Something other than a regular file. Nothing was read from it.
    NotAFile,
    /// A regular file longer than [`MAX_STATE_FILE`]. At most one byte past
    /// the limit was read.
    TooLarge,
}

/// Read a state file, following a symbolic link, but only if what it names is
/// a regular file, and only up to [`MAX_STATE_FILE`] bytes.
///
/// Plain `std::fs::read` accepted anything that opens: a FIFO at the ledger's
/// name blocked `bx` forever in `open`, and a link to `/dev/zero` allocated
/// until the process was killed. The restore blobs and the lock file were
/// already guarded against both; this is the same guard for the state files.
///
/// A symbolic link is still followed, unlike for a restore blob: a state file
/// kept elsewhere and linked into the state directory is a layout this module
/// supports, and [`Error::DanglingLink`] exists for the one that leads
/// nowhere. So the question asked is what the descriptor is, not what the name
/// is. `O_NONBLOCK` is what keeps `open` from blocking on a FIFO before there
/// is a descriptor to ask; on a regular file it changes nothing.
///
/// The length is bounded twice: by `st_size` before anything is allocated, and
/// by reading at most one byte past the limit, so a file that grows after the
/// `fstat` is still refused rather than read whole.
///
/// # Errors
///
/// The `open`, `fstat` or read failure, with its `errno`, so the caller's
/// dangling-link and not-a-directory judgements see what `std::fs::read` gave
/// them.
fn read_state_file(path: &Path) -> std::io::Result<StateRead> {
    use rustix::fs::{FileType, Mode as RawMode, OFlags};
    use std::io::Read as _;
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        RawMode::empty(),
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => {}
        // What `std::fs::read` gave for a directory, and what the caller has
        // always reported as a read failure rather than damage: a directory
        // neither blocks nor runs forever, and moving one aside as a damaged
        // cache would be a stranger act than naming it.
        FileType::Directory => return Err(rustix::io::Errno::ISDIR.into()),
        _ => return Ok(StateRead::NotAFile),
    }
    if u64::try_from(stat.st_size).map_or(true, |size| size > MAX_STATE_FILE) {
        return Ok(StateRead::TooLarge);
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(MAX_STATE_FILE + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_STATE_FILE) {
        return Ok(StateRead::TooLarge);
    }
    Ok(StateRead::Bytes(bytes))
}

/// The shallowest component of `path`'s own directory chain that exists and is
/// not a directory.
///
/// What an `ENOTDIR` from a read is actually about: the read names a file, and
/// the thing in the way is one of the directories it was to be found in.
/// `None` when every ancestor is a directory — the `ENOTDIR` then came from
/// somewhere else, and inventing a cause would be worse than the errno.
fn not_a_directory_above(path: &Path) -> Option<PathBuf> {
    let mut chain: Vec<_> = path.ancestors().skip(1).collect();
    chain.reverse();
    chain
        .into_iter()
        .find(|a| std::fs::metadata(a).is_ok_and(|m| !m.is_dir()))
        .map(Path::to_path_buf)
}

/// Whether a failed `read` is one that following a symbolic link to nowhere
/// gives: `ENOENT` for a link to nothing, `ELOOP` for links that loop, and
/// `ENOTDIR` for a link whose path runs through a file.
///
/// Only meaningful once the path itself is known to be a link: without one,
/// `ENOENT` is simply no file, and `ENOTDIR` a state directory that is not a
/// directory.
pub(super) fn leads_nowhere(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || error.raw_os_error().is_some_and(|code| {
            code == rustix::io::Errno::LOOP.raw_os_error()
                || code == rustix::io::Errno::NOTDIR.raw_os_error()
        })
}

/// Decode one envelope, rejecting anything that is not exactly one.
fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    kind: &'static str,
    version: u16,
) -> Result<T, Damage> {
    // The header first, skipping the payload: a newer bx may have changed the
    // payload's shape, so whether this build can read the version has to be
    // known before a payload decode failure can be called damage.
    let mut de = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
    let header = Header::deserialize(&mut de).map_err(|_| Damage::Malformed)?;
    // `rmp_serde::from_slice` stops at the end of the first value and ignores
    // whatever follows. A file that grew garbage at the end is damaged, not
    // half-readable, so the position is checked rather than trusted.
    if usize::try_from(de.position()).unwrap_or(usize::MAX) != bytes.len() {
        return Err(Damage::TrailingBytes);
    }
    if header.kind != kind {
        return Err(Damage::WrongKind { found: header.kind });
    }
    if header.version > version {
        return Err(Damage::FutureVersion {
            found: header.version,
            supported: version,
        });
    }
    let envelope: Envelope<T> = rmp_serde::from_slice(bytes).map_err(|_| Damage::Malformed)?;
    Ok(envelope.payload)
}

/// Return `value` — what survived a damaged file — moving the file aside only
/// under the lock.
///
/// `value` is `T::default()` for damage the decoder found, and the rows a
/// `check` left behind for damage it could confine to rows.
///
/// # Errors
///
/// [`Error::CannotQuarantine`] if the lock is held and the file cannot be
/// moved aside. [`Health::Reset`] promises the bytes were kept, and the next
/// save writes the file's name, so a file left in place is refused rather than
/// reset.
fn degrade<T>(
    path: &Path,
    damage: Damage,
    lock: Option<&ExclusiveLock>,
    value: T,
) -> Result<Loaded<T>, Error> {
    let Some(lock) = lock else {
        tracing::warn!(
            path = %path.display(),
            "{} is damaged: {damage}. It was left in place; the next bx that holds \
             the state directory lock moves it aside.",
            path.display(),
        );
        return Ok(Loaded {
            value,
            health: Health::Damaged(damage),
            quarantined: Vec::new(),
            unlisted: None,
        });
    };
    let quarantine = move_aside(path, lock).map_err(|source| Error::CannotQuarantine {
        path: path.to_path_buf(),
        damage: damage.clone(),
        source,
    })?;
    tracing::warn!(
        path = %path.display(),
        moved_to = %quarantine.display(),
        "discarding {}: {damage}. The bytes were kept, not deleted.",
        path.display(),
    );
    Ok(Loaded {
        value,
        health: Health::Reset(damage),
        quarantined: Vec::new(),
        unlisted: None,
    })
}

/// Write a state file atomically, at `0600`, creating its directory at `0700`.
///
/// # `T` must encode the same value to the same bytes, every time
///
/// Invariant 3 requires a generated file to be byte-identical between runs,
/// with "no nondeterministic iteration order". That is a constraint on the
/// payload type, and this function cannot impose it: `Serialize` says nothing
/// about iteration order, and Rust's type system has no bound that does — a
/// marker trait would be as easy to implement wrongly as the convention it
/// replaced. Every payload here uses `BTreeMap` for that reason, and
/// `HashMap`, `HashSet` and anything iterating over them are the shapes that
/// break it.
///
/// So part of the constraint is carried by a check **inside this function**,
/// by [`reencodes_identically`]: the bytes are decoded back into `T`
/// and re-encoded, [`REENCODES`] times, and every encoding must equal the
/// first. Each decode builds every `HashMap` in the payload afresh, with its
/// own `RandomState`, so a map that iterates in hash order comes back in a
/// different order and the save fails where it is made. That is why `T` is
/// bound by [`DeserializeOwned`] as well as [`Serialize`] — every state payload
/// is loadable anyway.
///
/// **It is here rather than at a call site because three call-site shapes in a
/// row satisfied the obligation while proving nothing** (r4 rounds 1, 2 and 3):
/// a value saved twice instead of built twice; a constructor that cloned; and a
/// constructor that built the old fields and left a new one empty. Each fix
/// closed the hole it was shown. A check a caller can write in a way that
/// passes vacuously is not a constraint, and the call site is where the
/// vacuity lives — so this half of the constraint moved to the one place every
/// payload type has to go through to write a file.
///
/// # Exactly what this catches, and what it does not
///
/// The check is `#[cfg(test)]` **at its call site**, so what it binds is
/// *every save a test makes* — not every payload type. A payload type whose
/// tests read and check but never save is not reached by it at all
/// (r4 round 4, CL3, correcting a stronger claim this paragraph used to make).
/// [`assert_saves_identically`] is what such a type's test module still has to
/// call, and the two together are the obligation.
///
/// **Catches:** a map at any depth holding two or more keys and iterating in
/// hash order — *with high probability, not with certainty*, and the
/// probability is what [`REENCODES`] is for. **Does not catch, at all:**
///
/// * A collection no test and no production path ever fills with two entries.
///   Not a gap in Invariant 3 — an empty or one-entry map encodes identically
///   however it iterates, so a field nothing fills cannot make a generated file
///   differ between runs. It becomes catchable the moment anything fills it.
/// * **An order-dependent *sequence*.** A `Vec<String>` built by draining a
///   `HashSet` is in hash order, and two independent builds of it differ — a
///   real Invariant 3 breach — but a `Vec` decodes in its stored order and
///   re-encodes identically, so no number of re-encodings here can see it. A
///   64-element case was accepted 20 saves out of 20 (r4 round 4, D1).
///   [`assert_saves_identically`] catches it, because it builds twice, and
///   `the_two_construction_assertion_refuses_an_order_dependent_sequence`
///   pins that it does. This is the class that makes the second mechanism
///   necessary rather than redundant.
///
/// # The one class neither mechanism catches
///
/// **An order-dependent sequence in a field the helper's `make` leaves at its
/// default.** It is the intersection of the two residuals above, and it is
/// stated here, once, rather than delegated: this function's list used to send
/// sequences to [`assert_saves_identically`] while that function's list sent
/// default-left fields back here, so a reader following either arrived at the
/// other and the intersection was named nowhere (r4 round 5, COV3).
///
/// It **is** reachable and it **does** break Invariant 3: a `Vec` drained from
/// a `HashSet` differs between two runs, and leaving it at its default in the
/// fixture means neither the re-encoding here nor the two constructions there
/// ever looks at a populated one. Both mechanisms report green.
///
/// No third mechanism closes it, and that is a property of dynamic testing
/// rather than of this design: no check can constrain the contents of a field
/// nothing ever puts contents into. What closes it is a fixture that populates
/// every field, and the obligation on whoever adds a payload field is
/// therefore to extend `make` as well as the struct. Stated so it can be
/// obeyed, not delegated so it can be lost.
///
/// # Errors
///
/// [`Error::Encode`] if the value cannot be encoded — a bug, not a user
/// condition — and [`Error::CreateDir`] or [`Error::Write`] for a filesystem
/// failure. A failure leaves the previous file exactly as it was, except a
/// failing `fsync` of the directory after the rename, which is returned with
/// the new file already in place — see [`write_atomically`].
pub(crate) fn save<T: Serialize + DeserializeOwned>(
    path: &Path,
    kind: &'static str,
    version: u16,
    value: &T,
) -> Result<(), Error> {
    let envelope = Envelope {
        kind: kind.to_string(),
        version,
        payload: value,
    };
    // Named (map) encoding, not compact (array) encoding: with named fields and
    // `#[serde(default)]` a file written by an older bx still loads when a field
    // is added, whereas a positional encoding would fail on the length change
    // and turn every schema addition into a forced quarantine of the ledger.
    // Both are deterministic; only one is evolvable.
    let bytes =
        rmp_serde::to_vec_named(&envelope).map_err(|source| Error::Encode { kind, source })?;
    #[cfg(test)]
    assert!(
        reencodes_identically::<T>(&bytes, kind),
        "{kind} does not encode the same value to the same bytes: decoding it and encoding it \
         again gives different bytes, which means something in the payload iterates in hash \
         order. Invariant 3 forbids it — use a BTreeMap, not a HashMap",
    );
    // Every state file StateDir names is `root.join(<name>)`, so a parent always exists.
    if let Some(parent) = path.parent() {
        ensure_dir(parent, Mode::PRIVATE_DIR)?;
    }
    write_atomically(path, &bytes, Mode::PRIVATE_FILE)?;
    Ok(())
}

/// How many times [`reencodes_identically`] decodes and re-encodes.
///
/// One decode is not enough, and saying it was is what made [`save`]'s
/// documented catch boundary false (r4 round 4, D1). A `HashMap` of *n* keys
/// built twice iterates the same way often enough to matter at small *n*:
/// measured over 3000 independent constructions per size, two builds are
/// **detected as differing** 0/3000 times at one key, 1321/3000 at two,
/// 2263/3000 at three, 2746/3000 at four, and 3000/3000 at eight and sixteen.
/// So one comparison of a two-key map misses 56% of the time — and a red run
/// would turn green on a re-run, which is worse than no check.
///
/// Each decode draws a fresh `RandomState`, so *k* comparisons miss
/// `0.56^k`. At 32 that is about `8.75e-9` for the worst case, two keys, and
/// smaller for every other size; a one-key map is undetectable at any *k* and
/// is also harmless, since one entry encodes identically in any order.
///
/// The cost is *k* decodes and encodes of a small in-memory payload on every
/// save a test makes, and only in a test build.
#[cfg(test)]
const REENCODES: usize = 32;

/// Whether `bytes`, decoded into `T` and encoded again, is `bytes` — every
/// one of [`REENCODES`] times over.
///
/// Half of [`save`]'s determinism obligation, made where a call site cannot
/// write it vacuously. A verdict rather than an assertion, so that
/// `the_re_encode_count_is_what_makes_detection_certain` can measure the
/// detection rate [`REENCODES`] buys without catching sixty-four panics. The decode is what gives it teeth: it builds every
/// `HashMap` in the payload afresh, with its own `RandomState`, so a map that
/// iterates in hash order comes back in a different order and the re-encoding
/// differs. A `BTreeMap` comes back in key order every time, as do struct
/// fields, which `to_vec_named` emits in declaration order.
///
/// A decode failure is a failure too, and a real one: [`load`] would refuse
/// the file this `save` is about to write, which is a payload type whose
/// `Serialize` and `Deserialize` disagree.
///
/// What it cannot see at all is an order-dependent *sequence* — see [`save`].
///
/// Test-only. The property is about the *type*, so one process establishing it
/// for every payload the suite saves establishes it for every run; paying this
/// on every production save would buy nothing.
#[cfg(test)]
fn reencodes_identically<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    kind: &'static str,
) -> bool {
    for _ in 0..REENCODES {
        // Decoded from the original bytes each time, so each round draws a new
        // `RandomState` and the rounds are independent.
        let decoded: Envelope<T> = match rmp_serde::from_slice(bytes) {
            Ok(decoded) => decoded,
            Err(why) => panic!("{kind} does not decode the bytes it just encoded: {why}"),
        };
        if rmp_serde::to_vec_named(&decoded).expect("re-encoding a decoded envelope") != bytes {
            return false;
        }
    }
    true
}

/// Assert that a value built twice saves to the same bytes — [`save`]'s
/// stated obligation on every payload type, in one place.
///
/// Called from each payload type's own test module. Invariant 3's
/// byte-identical guarantee rests on each of them choosing `BTreeMap`, and
/// `save` can impose no bound that says so: `Serialize` says nothing about
/// iteration order. A shared assertion is what a later payload type has to
/// pass rather than remember (r4 round 1, CL9).
///
/// `make` is called twice, rather than one value being saved twice, and that
/// is what gives the assertion its teeth. One `HashMap` iterates the same way
/// however often it is encoded in one process; *two* with the same contents do
/// not, because `RandomState` gives each its own hash keys. Building the value
/// twice is therefore the in-process stand-in for "between runs", which is
/// what Invariant 3 actually says.
///
/// This is an obligation on the **caller**, not only on this function: `make`
/// must construct, never clone. `HashMap::clone` copies the hasher and the
/// bucket layout along with the contents, so two clones of one value iterate
/// identically and a hash-ordered payload passes — which is exactly how both
/// real call sites defeated this assertion when they read `|| value.clone()`
/// (r4 round 2, D1). Build enough keys, too: two independently built maps are
/// detected as differing 1321 times in 3000 at two keys, 2746 at four, and
/// 3000 at eight and sixteen (r4 round 4), so a fixture below eight keys is
/// a flaky assertion rather than a strong one.
///
/// # What this does *not* establish, and what does
///
/// It proves nothing about a field `make` leaves empty. A constructor that
/// builds the fields it knew about and leaves a newly added `HashMap` at its
/// default satisfies this assertion while saying nothing about it — the third
/// way a call site has satisfied the obligation vacuously (r4 round 3, D3).
/// For a **map**, [`save`]'s own re-encoding check covers it the moment
/// anything populates the field. For a **sequence**, nothing does: a
/// default-left order-dependent sequence is caught by neither mechanism, is a
/// real Invariant 3 breach, and is stated in full under [`save`]'s heading
/// "The one class neither mechanism catches" — which is the single place it is
/// written down, because two lists delegating to each other is how it went
/// unnamed until r4 round 5 (COV3).
///
/// What this adds, and the reason it stays rather than being subsumed: `save`'s
/// check works on **one** value, and this works on **two independently built**
/// ones. That is the in-process stand-in for "between runs", and one value
/// cannot make it however often it is re-encoded. The class that separates
/// them is an order-dependent sequence — a `Vec` drained from a `HashSet` —
/// which `save` cannot see at any number of re-encodings and this catches.
/// Each mechanism has a test that fails when **only that one** is removed:
/// `a_hash_ordered_payload_is_refused_by_saves_own_check` for `save`'s, and
/// `the_two_construction_assertion_refuses_an_order_dependent_sequence` for
/// this one (r4 round 4, COV1).
///
/// [`save`] itself is called, rather than the encoder, so the property pinned
/// is the one the file on disk has.
#[cfg(test)]
pub(crate) fn assert_saves_identically<T: Serialize + DeserializeOwned>(
    kind: &'static str,
    version: u16,
    make: impl Fn() -> T,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("twice.mpk");
    save(&path, kind, version, &make()).expect("first");
    let first = std::fs::read(&path).expect("read");
    save(&path, kind, version, &make()).expect("second");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        first,
        "{kind} encodes two independently built values with the same contents to different \
         bytes; Invariant 3 requires a generated file to be byte-identical between runs, and \
         anything that iterates in hash order breaks it — a HashMap or HashSet, or a sequence \
         built by draining one",
    );
}

/// A `tracing` sink that captures this thread's diagnostics, for the tests
/// of every module that raises one.
///
/// Beside [`assert_saves_identically`] and for the same reason: the harness
/// was private to `store.rs`'s own test module, so the `tracing::warn!` in
/// `dir::tighten` and the one in `lock::open_lock_file` could be deleted
/// whole and the suite stayed green (r4 round 2, COV1).
#[cfg(test)]
pub(crate) mod capture {
    /// A `tracing` sink that keeps what was written to it.
    ///
    /// No test in the repository installed a subscriber, so every
    /// `tracing::warn!` in `state` had its *argument expressions* executed
    /// zero times: the enabled-check ran, found no subscriber, and the body
    /// never did. Deleting a warning whose text the module documentation and
    /// `state/mod.rs` both state as part of the contract left the whole suite
    /// green (r4 round 1, COV2).
    struct Sink;

    thread_local! {
        /// Where this thread's diagnostics go, when it is capturing.
        static CAPTURED: std::cell::RefCell<Option<std::sync::Arc<std::sync::Mutex<Vec<u8>>>>> =
            const { std::cell::RefCell::new(None) };
    }

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            CAPTURED.with(|slot| {
                if let Some(into) = slot.borrow().as_ref() {
                    into.lock().expect("the sink").extend_from_slice(buf);
                }
            });
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            Self
        }
    }

    /// Run `f` and return what it produced alongside the diagnostics it
    /// emitted on this thread.
    ///
    /// The subscriber is installed **globally**, once, and routes to a
    /// per-thread buffer, so a test captures only its own output however many
    /// tests run at once. A thread-local subscriber would not do: `tracing`
    /// caches each callsite's interest process-wide, so a thread with no
    /// subscriber installed can cache "never" for a callsite another thread is
    /// about to use, and the capture comes back empty at random.
    pub(crate) fn capturing<T>(f: impl FnOnce() -> T) -> (T, String) {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(Sink)
                    .with_ansi(false)
                    .with_max_level(tracing::Level::WARN)
                    .finish(),
            )
            .expect("no other global subscriber");
        });

        struct Stop;
        impl Drop for Stop {
            fn drop(&mut self) {
                CAPTURED.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let into = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        CAPTURED.with(|slot| *slot.borrow_mut() = Some(into.clone()));
        let _stop = Stop;

        let out = f();
        let bytes = into.lock().expect("the sink").clone();
        (out, String::from_utf8(bytes).expect("utf-8 diagnostics"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use super::capture::capturing;
    use crate::state::StateDir;

    const KIND: &str = "bx.test";
    const OTHER: &str = "bx.other";
    const VERSION: u16 = 3;

    type Value = BTreeMap<String, u32>;

    /// [`load`] under the exclusive lock of `path`'s directory, as a writer does.
    fn locked_load<T: DeserializeOwned + Default>(path: &Path) -> Result<Loaded<T>, Error> {
        let dir = StateDir::new(path.parent().expect("a parent").to_path_buf());
        let lock = ExclusiveLock::acquire(&dir).expect("lock");
        load(path, KIND, VERSION, Loss::Recomputable, Some(&lock))
    }

    /// Every name in `dir` but the lock file, sorted.
    fn names_but_the_lock(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|name| name != "lock")
            .collect();
        names.sort();
        names
    }

    fn sample() -> Value {
        let mut map = Value::new();
        map.insert("alpha".into(), 1);
        map.insert("beta".into(), 2);
        map
    }

    fn encoded(kind: &str, version: u16, payload: &Value) -> Vec<u8> {
        rmp_serde::to_vec_named(&Envelope {
            kind: kind.to_string(),
            version,
            payload,
        })
        .expect("encode")
    }

    #[test]
    fn a_missing_file_loads_as_fresh_and_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let loaded: Loaded<Value> = locked_load(&dir.path().join("nope.mpk")).expect("load");
        assert_eq!(loaded.health, Health::Fresh);
        assert!(loaded.value.is_empty());
        assert!(!loaded.health.is_reset());
        assert_eq!(loaded.health.damage(), None);
    }

    #[test]
    fn a_round_trip_returns_the_same_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        save(&path, KIND, VERSION, &sample()).expect("save");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Loaded);
        assert_eq!(loaded.value, sample());
    }

    #[test]
    fn saving_the_same_value_twice_produces_identical_bytes() {
        assert_saves_identically(KIND, VERSION, sample);
    }

    // The determinism obligation is carried by two mechanisms, and each of the
    // three tests below fails when *only its own* mechanism is removed. Until
    // r4 round 4 one test stood for both: its 128-key `HashMap` payload tripped
    // inside `save` before the helper's comparison ran, so neutering either
    // mechanism alone left the suite green and only their disjunction was
    // tested (r4 round 4, COV1).

    #[test]
    fn the_re_encode_count_is_what_makes_detection_certain() {
        // r4 round 5 (COV1): `REENCODES` was a constant nothing defended. The
        // suite was green at `REENCODES = 1`, where a two-key `HashMap` is
        // missed 56% of the time — so the intermittency the previous round
        // removed was one edit from coming back, and the 300/300 measurement
        // that justified 32 lived in a report rather than in the suite.
        //
        // This measures instead of restating. Each trial encodes a freshly
        // built two-key map — the worst case, and the only size where one
        // comparison is close to a coin toss — and asks the verdict function
        // whether it looks deterministic. For a `HashMap` the honest answer is
        // always "no", so every `true` is a miss.
        //
        // Why it is not flaky, and why it fails at 1. A round misses with
        // probability 0.56, and the rounds are independent because each decodes
        // the original bytes afresh. At `REENCODES = 32` a trial misses with
        // `0.56^32` ≈ 8.75e-9, so 64 trials fail this assertion with
        // probability about 5.6e-7 — once in two million runs. At
        // `REENCODES = 1` a trial misses with probability 0.56, so 64 trials
        // pass with probability `0.44^64` ≈ 1e-23: it fails every time.
        const TRIALS: usize = 64;
        let mut missed = 0;
        for _ in 0..TRIALS {
            let two: std::collections::HashMap<String, u32> =
                [("a".to_string(), 1), ("b".to_string(), 2)]
                    .into_iter()
                    .collect();
            let bytes = rmp_serde::to_vec_named(&Envelope {
                kind: KIND.to_string(),
                version: VERSION,
                payload: &two,
            })
            .expect("encode");
            if reencodes_identically::<std::collections::HashMap<String, u32>>(&bytes, KIND) {
                missed += 1;
            }
        }
        assert_eq!(
            missed, 0,
            "{missed} of {TRIALS} two-key hash-ordered payloads went undetected; REENCODES is \
             {REENCODES} and has to be large enough that they do not",
        );
    }

    #[test]
    #[should_panic(expected = "decoding it and encoding it again gives different bytes")]
    fn a_hash_ordered_payload_is_refused_by_saves_own_check() {
        // `save` alone, with no helper in the picture: one value, saved once.
        // The helper cannot make this pass or fail.
        let dir = tempfile::tempdir().expect("tempdir");
        let hashed: std::collections::HashMap<String, u32> =
            (0..128_u32).map(|n| (format!("k{n}"), n)).collect();
        let _ = save(&dir.path().join("v.mpk"), KIND, VERSION, &hashed);
    }

    #[test]
    #[should_panic(expected = "two independently built values")]
    fn the_two_construction_assertion_refuses_an_order_dependent_sequence() {
        // The helper alone: a payload `save`'s check *accepts* and two
        // independent builds differ on. A `Vec` drained from a `HashSet` is in
        // hash order, but it decodes in its stored order and re-encodes
        // identically, so no number of re-encodings inside `save` can see it —
        // while two builds of it are two different orders, which is the
        // Invariant 3 breach. This is the class that makes the second
        // mechanism necessary rather than redundant (r4 round 4, D1).
        #[derive(Serialize, Deserialize)]
        struct Ordered {
            order: Vec<String>,
        }
        assert_saves_identically(KIND, VERSION, || Ordered {
            order: (0..64_u32)
                .map(|n| format!("k{n}"))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect(),
        });
    }

    #[test]
    #[should_panic(expected = "does not decode the bytes it just encoded")]
    fn a_payload_whose_encoding_it_cannot_read_back_is_refused() {
        // r4 round 4 (COV3): the decode arm of `save`'s own check was reached
        // by nothing, so a mutant turning the panic into a silent `return`
        // survived. A type whose `Serialize` and `Deserialize` disagree is what
        // reaches it, and it is a real condition: `load` would refuse the file
        // the save is about to write.
        struct Mismatched;
        impl Serialize for Mismatched {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str("not a number")
            }
        }
        impl<'de> Deserialize<'de> for Mismatched {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                u32::deserialize(d).map(|_| Self)
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let _ = save(&dir.path().join("v.mpk"), KIND, VERSION, &Mismatched);
    }

    #[test]
    fn insertion_order_does_not_change_the_bytes() {
        let mut forwards = Value::new();
        forwards.insert("alpha".into(), 1);
        forwards.insert("beta".into(), 2);
        let mut backwards = Value::new();
        backwards.insert("beta".into(), 2);
        backwards.insert("alpha".into(), 1);
        assert_eq!(
            encoded(KIND, VERSION, &forwards),
            encoded(KIND, VERSION, &backwards),
        );
    }

    #[test]
    fn an_older_version_still_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, encoded(KIND, VERSION - 1, &sample())).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Loaded);
        assert_eq!(loaded.value, sample());
    }

    #[test]
    fn a_truncated_file_degrades_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let bytes = encoded(KIND, VERSION, &sample());
        std::fs::write(&path, &bytes[..bytes.len() / 2]).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
    }

    #[test]
    fn garbage_bytes_degrade_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"this is certainly not MessagePack").expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
    }

    #[test]
    fn trailing_bytes_are_damage_not_a_silent_half_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let mut bytes = encoded(KIND, VERSION, &sample());
        bytes.extend_from_slice(b"\x00\x00leftovers");
        std::fs::write(&path, &bytes).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::TrailingBytes));
        assert!(loaded.value.is_empty());
    }

    #[test]
    fn a_future_version_degrades_and_names_the_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, encoded(KIND, VERSION + 5, &sample())).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(
            loaded.health,
            Health::Reset(Damage::FutureVersion {
                found: VERSION + 5,
                supported: VERSION,
            }),
        );
        assert!(loaded.value.is_empty());
        let message = loaded.health.damage().expect("damage").to_string();
        assert!(message.contains("version 8"), "got {message}");
        assert!(message.contains("up to 3"), "got {message}");
    }

    /// An envelope of `version` whose payload is a shape [`Value`] is not, as
    /// a newer format that changed the payload would write.
    fn reshaped(version: u16) -> Vec<u8> {
        rmp_serde::to_vec_named(&Envelope {
            kind: KIND.to_string(),
            version,
            payload: vec!["a shape", "this build has never seen"],
        })
        .expect("encode")
    }

    #[test]
    fn a_newer_version_is_judged_before_its_payload_is_decoded() {
        // Review round 4: the payload was decoded before the version was
        // looked at, so a newer format with a changed payload read as
        // `Malformed` — damage — whatever the file's loss.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, reshaped(VERSION + 1)).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(
            loaded.health,
            Health::Reset(Damage::FutureVersion {
                found: VERSION + 1,
                supported: VERSION,
            }),
        );

        // The same shape at a version this build reads is damage.
        std::fs::write(&path, reshaped(VERSION)).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
    }

    #[test]
    fn a_newer_version_of_a_permanent_file_is_refused_and_nothing_is_renamed() {
        // Review round 4: after a rollback to an older bx, an intact ledger
        // was moved aside as damage, even under the lock.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
        // Review round 5: whether the rest of the file reads as this format is
        // reported, so the message can say the version itself may be damaged.
        for (seed, readable) in [
            (encoded(KIND, VERSION + 1, &sample()), true),
            (reshaped(VERSION + 1), false),
        ] {
            std::fs::write(&path, &seed).expect("seed");
            for held in [None, Some(&lock)] {
                let err = load::<Value>(&path, KIND, VERSION, Loss::Permanent, held)
                    .expect_err("a newer permanent file is refused");
                assert!(
                    matches!(
                        &err,
                        Error::FutureVersion { path: at, found, supported, payload_readable }
                            if *at == path && *found == VERSION + 1 && *supported == VERSION
                                && *payload_readable == readable
                    ),
                    "got {err}",
                );
                let message = err.to_string();
                assert_eq!(message.contains("may be damaged"), readable, "{message}");
                assert!(message.contains("newer bx"), "{message}");
                assert!(message.contains("version 4"), "{message}");
                assert!(message.contains("up to 3"), "{message}");
                assert_eq!(std::fs::read(&path).expect("in place"), seed);
                assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
            }
        }

        // Every other damage to a permanent file still degrades under the lock.
        std::fs::write(&path, b"garbage").expect("seed");
        let loaded: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Permanent, Some(&lock)).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
    }

    #[test]
    fn every_damage_says_what_is_wrong_with_the_file() {
        // r3 round 1 (C4): two of the six texts were never asserted, and
        // the others only in part, so an empty rendering survived mutation.
        let cases = [
            (Damage::Malformed, "it is not valid MessagePack"),
            (
                Damage::TrailingBytes,
                "it has unexpected bytes after the end",
            ),
            (
                Damage::WrongKind {
                    found: OTHER.to_string(),
                },
                "it is a bx.other file",
            ),
            (
                Damage::FutureVersion {
                    found: 8,
                    supported: 3,
                },
                "it is version 8, and this bx understands up to 3",
            ),
            (
                Damage::DanglingLink,
                "it is a symbolic link to something that does not exist, or that cannot be \
                 followed",
            ),
            (
                Damage::NotAFile,
                "it is not a regular file (a FIFO, a device or a socket), so it was not read",
            ),
            (
                Damage::TooLarge,
                "it is longer than 268435456 bytes, which no state file bx writes comes near",
            ),
            (
                Damage::KeyMismatch {
                    rows: vec![("~/.aaaa".to_string(), "~/.bbbb".to_string())],
                },
                "its entry for ~/.aaaa names a different path, ~/.bbbb",
            ),
            (
                Damage::KeyMismatch {
                    rows: vec![
                        ("~/.aaaa".to_string(), "~/.bbbb".to_string()),
                        ("~/.cccc".to_string(), "~/.dddd".to_string()),
                    ],
                },
                "its entry for ~/.aaaa names a different path, ~/.bbbb; its entry for ~/.cccc \
                 names a different path, ~/.dddd",
            ),
        ];
        for (damage, text) in cases {
            assert_eq!(damage.to_string(), text, "{damage:?}");
        }
    }

    #[test]
    fn a_file_of_the_wrong_kind_is_not_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, encoded(OTHER, VERSION, &sample())).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(
            loaded.health,
            Health::Reset(Damage::WrongKind {
                found: OTHER.to_string(),
            }),
        );
        let message = loaded.health.damage().expect("damage").to_string();
        assert!(message.contains(OTHER), "got {message}");
    }

    #[test]
    fn damaged_bytes_are_quarantined_not_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"garbage").expect("seed");
        let _: Loaded<Value> = locked_load(&path).expect("load");
        assert!(!path.exists(), "the damaged file must be moved aside");
        let quarantine = StateDir::quarantine(&path);
        assert_eq!(std::fs::read(&quarantine).expect("read"), b"garbage");
    }

    #[test]
    fn quarantining_a_symlinked_state_file_moves_the_link_not_its_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A state file that is a symlink to somewhere else — a hand-made link,
        // or a restored backup. What it points at may be a file the user wrote,
        // so the degradation must not reach through it.
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"whatever is at the far end").expect("seed");
        let path = dir.path().join("v.mpk");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");

        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));

        // `rename` acts on the link itself, never on what it names.
        assert_eq!(
            std::fs::read(&elsewhere).expect("read"),
            b"whatever is at the far end",
        );
        assert!(std::fs::symlink_metadata(&path).is_err(), "the link moved");
        let quarantine = StateDir::quarantine(&path);
        assert!(
            std::fs::symlink_metadata(&quarantine)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the quarantined entry is the link, not a copy of the target",
        );
        assert_eq!(
            std::fs::read_link(&quarantine).expect("readlink"),
            elsewhere
        );
    }

    #[test]
    fn saving_over_a_symlinked_state_file_replaces_the_link_not_its_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"the user wrote this").expect("seed");
        let path = dir.path().join("v.mpk");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");

        save(&path, KIND, VERSION, &sample()).expect("save");

        // Invariant 1: the atomic write renames over the link, so nothing is
        // written through it to a file bx does not own.
        assert_eq!(
            std::fs::read(&elsewhere).expect("read"),
            b"the user wrote this",
        );
        assert!(
            !std::fs::symlink_metadata(&path)
                .expect("stat")
                .file_type()
                .is_symlink(),
        );
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.value, sample());
    }

    #[test]
    fn successive_quarantines_keep_every_earlier_one() {
        // Review round 3: a fixed `<name>.corrupt` was renamed over, so a
        // second damaged ledger destroyed the first — which may be the only
        // index there is to the user's restore blobs.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        for body in [&b"first"[..], b"second", b"third"] {
            std::fs::write(&path, body).expect("seed");
            let loaded: Loaded<Value> = locked_load(&path).expect("load");
            assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        }

        assert_eq!(
            names_but_the_lock(dir.path()),
            vec!["v.mpk.corrupt", "v.mpk.corrupt.1", "v.mpk.corrupt.2"],
        );
        for (n, body) in [(0, &b"first"[..]), (1, b"second"), (2, b"third")] {
            assert_eq!(
                std::fs::read(StateDir::quarantine_nth(&path, n)).expect("kept"),
                body,
            );
        }
    }

    #[test]
    fn a_new_quarantine_takes_the_number_after_the_highest_and_never_refills_a_gap() {
        // Review round 5: `move_aside` took the lowest free number, so once a
        // human deleted `.corrupt` the next quarantine refilled it, and
        // `Loaded::quarantined` listed the newest first.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        for body in [&b"first"[..], b"second", b"third"] {
            std::fs::write(&path, body).expect("seed");
            let _: Loaded<Value> = locked_load(&path).expect("load");
        }
        std::fs::remove_file(StateDir::quarantine(&path)).expect("a human removes the first");

        std::fs::write(&path, b"fourth").expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert!(loaded.health.is_reset());
        let newest = StateDir::quarantine_nth(&path, 3);
        assert_eq!(
            loaded.quarantined,
            vec![
                StateDir::quarantine_nth(&path, 1),
                StateDir::quarantine_nth(&path, 2),
                newest.clone(),
            ],
            "creation order, newest last",
        );
        assert_eq!(std::fs::read(&newest).expect("the newest"), b"fourth");
        assert!(
            !StateDir::quarantine(&path).exists(),
            "the gap is not refilled"
        );

        // Once every quarantine is gone, numbering starts again at the first.
        for n in 1..=3 {
            std::fs::remove_file(StateDir::quarantine_nth(&path, n)).expect("remove");
        }
        std::fs::write(&path, b"fifth").expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.quarantined, vec![StateDir::quarantine(&path)]);
    }

    #[test]
    fn a_quarantine_number_with_no_successor_does_not_block_the_next_quarantine() {
        // r3 round 1 (L1a): with `v.mpk.corrupt.18446744073709551615` present,
        // the number after the highest overflowed, nothing was moved aside,
        // and the load still said the file had been quarantined.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let crafted = StateDir::quarantine_nth(&path, u64::MAX);
        std::fs::write(&crafted, b"crafted").expect("seed");
        std::fs::write(&path, b"garbage").expect("seed");

        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        let first = StateDir::quarantine(&path);
        assert_eq!(std::fs::read(&first).expect("moved aside"), b"garbage");
        assert_eq!(std::fs::read(&crafted).expect("left alone"), b"crafted");
        assert_eq!(loaded.quarantined, vec![first, crafted]);
        assert!(std::fs::symlink_metadata(&path).is_err(), "the file moved");
    }

    #[test]
    fn once_the_top_quarantine_number_is_present_gaps_are_refilled_and_the_last_is_not_the_newest()
    {
        // r3 round 2 (P7R4-D1): the docs still said the quarantines listed are
        // in the order they were made, the last the newest, and that bx never
        // makes `<name>.corrupt.<u64::MAX>`. Both stop being true once the top
        // number is present; the docs now say so, and this pins what they say.
        let nth = StateDir::quarantine_nth;

        // A crafted top number, three quarantines, the first removed by a
        // human, then a fourth damaged load.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let top = nth(&path, u64::MAX);
        std::fs::write(&top, b"crafted").expect("seed");
        for body in [&b"first"[..], b"second", b"third"] {
            std::fs::write(&path, body).expect("seed");
            let loaded: Loaded<Value> = locked_load(&path).expect("load");
            assert!(loaded.health.is_reset());
        }
        std::fs::remove_file(nth(&path, 0)).expect("a human removes the first");
        std::fs::write(&path, b"fourth").expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert!(loaded.health.is_reset());
        assert_eq!(
            loaded.quarantined,
            vec![nth(&path, 0), nth(&path, 1), nth(&path, 2), top.clone()],
            "ascending by number, the refilled gap included",
        );
        assert_eq!(
            std::fs::read(&loaded.quarantined[0]).expect("the refilled gap"),
            b"fourth",
            "the newest is listed first",
        );
        assert_eq!(
            std::fs::read(loaded.quarantined.last().expect("a last")).expect("the top"),
            b"crafted",
            "the last is not the newest",
        );

        // A crafted `<u64::MAX - 1>`: bx itself makes the top number, and
        // then takes the lowest free numbers.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let below_top = nth(&path, u64::MAX - 1);
        std::fs::write(&below_top, b"crafted").expect("seed");
        let mut made = Vec::new();
        for body in [&b"first"[..], b"second", b"third"] {
            std::fs::write(&path, body).expect("seed");
            let loaded: Loaded<Value> = locked_load(&path).expect("load");
            assert!(loaded.health.is_reset());
            made.push(loaded.quarantined);
        }
        assert_eq!(
            made,
            vec![
                vec![below_top.clone(), nth(&path, u64::MAX)],
                vec![nth(&path, 0), below_top.clone(), nth(&path, u64::MAX)],
                vec![
                    nth(&path, 0),
                    nth(&path, 1),
                    below_top.clone(),
                    nth(&path, u64::MAX),
                ],
            ],
            "the top number, then `.corrupt`, then `.corrupt.1`",
        );
        for (n, body) in [(u64::MAX, &b"first"[..]), (0, b"second"), (1, b"third")] {
            assert_eq!(std::fs::read(nth(&path, n)).expect("kept"), body);
        }
    }

    #[test]
    fn a_quarantine_left_by_an_earlier_run_is_reported_on_every_load() {
        // Review round 4: a quarantine followed by a crash before the save left
        // the next reader and writer looking at `Health::Fresh`, with the
        // `.corrupt` file orphaned and reported nowhere.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let first = StateDir::quarantine(&path);

        let absent: Loaded<Value> = load(
            &dir.path().join("absent/v.mpk"),
            KIND,
            VERSION,
            Loss::Recomputable,
            None,
        )
        .expect("a missing directory lists nothing");
        assert!(absent.quarantined.is_empty());
        // r4 round 2 (COV4): "no directory, so none — *known*" is the whole
        // distinction `unlisted` exists to draw, and nothing pinned it here.
        // It holds because `numbered`'s `NotFound` arm returns an empty list
        // rather than a listing failure; without that this would be `Some`,
        // and an empty `quarantined` beside it would mean nothing is known.
        assert_eq!(absent.unlisted, None, "absent is known, not unknown");

        std::fs::write(&path, b"garbage").expect("seed");
        let reset: Loaded<Value> = locked_load(&path).expect("load");
        assert!(reset.health.is_reset());
        assert_eq!(
            reset.quarantined,
            vec![first.clone()],
            "the quarantining load"
        );

        // The crash: no save. The next reader and writer both see Fresh, and
        // both are told what was set aside.
        let lockless: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, None).expect("load");
        assert_eq!(lockless.health, Health::Fresh);
        assert_eq!(lockless.quarantined, vec![first.clone()]);
        let writer: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(writer.health, Health::Fresh);
        assert_eq!(writer.quarantined, vec![first.clone()]);

        // A clean save does not hide it either. A gap hides nothing after it,
        // and names that are not this file's quarantines are not listed.
        save(&path, KIND, VERSION, &sample()).expect("save");
        let third = StateDir::quarantine_nth(&path, 2);
        std::fs::write(&third, b"after a gap").expect("seed");
        for decoy in [
            "v.mpk.corrupt.01",
            "v.mpk.corrupt.0",
            "v.mpk.corrupt.+3",
            "v.mpk.corrupt.x",
            "v.mpk.corrupt.",
            "v.mpk.corrupted",
            "w.mpk.corrupt",
        ] {
            std::fs::write(dir.path().join(decoy), b"not a quarantine").expect("decoy");
        }
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Loaded);
        assert_eq!(loaded.quarantined, vec![first, third]);
    }

    #[test]
    fn a_state_directory_that_cannot_be_listed_leaves_the_quarantines_unknown() {
        // r4 round 1 (D8): the listing failure was returned as `Error::Read`,
        // whose documented meaning is "the file's bytes were never seen" — and
        // whose path was the directory, not the state file a caller matches
        // on. It also discarded a quarantine `judge` had already completed,
        // and a persistently unlistable directory (0300: searchable and
        // writable, not readable) failed every `LedgerView::read` and
        // `Fingerprints::read` with no remedy, though each file read perfectly.
        if rustix::process::geteuid().is_root() {
            // Mode bits deny nothing to root, so the condition cannot be staged.
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("state");
        std::fs::create_dir(&root).expect("root");
        let path = root.join("v.mpk");
        save(&path, KIND, VERSION, &sample()).expect("seed");
        // Searchable, so the file itself reads; not readable, so it cannot be
        // listed. Reporting no quarantines there would be a guess, so the load
        // says it does not know rather than saying there are none.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300)).expect("chmod");
        let (loaded, said) =
            capturing(|| load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("restore");

        let loaded = loaded.expect("the file itself read perfectly");
        assert_eq!(loaded.value, sample(), "the load stands");
        assert_eq!(loaded.health, Health::Loaded);
        let unlisted = loaded
            .unlisted
            .clone()
            .expect("the directory it could not list");
        assert_eq!(unlisted.path, root);
        // r4 round 2 (CL5): the cause used to be logged and dropped, so a
        // caller could not tell a remediable `chmod` from a failing disk.
        assert_eq!(unlisted.kind, std::io::ErrorKind::PermissionDenied);
        assert!(unlisted.cause.contains("Permission denied"), "{unlisted:?}");
        assert!(
            loaded.quarantined.is_empty(),
            "empty because nothing is known",
        );
        assert!(said.contains("Permission denied"), "{said}");
        assert!(said.contains(&root.display().to_string()), "{said}");

        // A listing that succeeds says so, whatever it found.
        let (fine, _) = capturing(|| load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None));
        assert_eq!(fine.expect("load").unlisted, None);
    }

    #[test]
    fn a_damaged_file_is_reported_through_tracing_whether_or_not_it_is_moved() {
        // r4 round 1 (COV2): neither `tracing::warn!` body in this module had
        // ever been executed, because no library test installed a subscriber.
        // Both texts are stated as part of the contract — by this module's
        // `load` doc and by `state/mod.rs` — and deleting either macro passed
        // the entire suite.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"garbage").expect("seed");

        // The lockless reader: told what is wrong, and told who will move it.
        let (lockless, said) =
            capturing(|| load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None));
        assert_eq!(
            lockless.expect("load").health,
            Health::Damaged(Damage::Malformed),
        );
        assert!(said.contains(&path.display().to_string()), "{said}");
        assert!(said.contains("is damaged"), "{said}");
        assert!(
            said.contains("the next bx that holds the state directory lock moves it aside"),
            "{said}",
        );

        // The lock holder: told what was discarded, and *where the bytes went*
        // — the only place the numbered quarantine name reaches the log.
        let (writer, said) = capturing(|| locked_load::<Value>(&path));
        assert!(writer.expect("load").health.is_reset());
        let quarantine = StateDir::quarantine(&path);
        assert!(said.contains("discarding"), "{said}");
        assert!(
            said.contains(&format!("moved_to={}", quarantine.display())),
            "{said}",
        );
        assert!(said.contains("The bytes were kept, not deleted."), "{said}",);
    }

    #[test]
    fn a_save_that_cannot_be_written_is_reported_naming_the_directory() {
        // r4 round 1 (COV7): `save`'s `Error::Write` propagation from
        // `write_atomically` was reached by no test at all — region count
        // zero — so the whole arm could be replaced by `Ok(())` undetected.
        if rustix::process::geteuid().is_root() {
            // Mode bits deny nothing to root, so the condition cannot be staged.
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        // A *linked* state directory at `0500`. `ensure_dir` never `chmod`s
        // through a link — see `dir::tighten` — so this is the one shape it
        // leaves unwritable, and the atomic write's temporary file cannot be
        // created in it. An unlinked `0500` would be set back to `0700` and
        // the write would succeed (r4 round 2, CL3).
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("real");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        let root = dir.path().join("state");
        std::os::unix::fs::symlink(&real, &root).expect("link");
        let result = save(&root.join("v.mpk"), KIND, VERSION, &sample());
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("restore");

        let err = result.expect_err("must fail");
        assert!(
            matches!(&err, Error::Write(inner) if inner.path() == root),
            "got {err}",
        );
        assert_eq!(
            names_but_the_lock(&root),
            Vec::<String>::new(),
            "nothing left"
        );
    }

    #[test]
    fn a_file_where_the_state_directory_should_be_is_named_as_such_on_a_lockless_read() {
        // r4 round 2 (D5): `LedgerView::read` and `Fingerprints::read` never
        // call `ensure`, so the only code that raised `Error::NotADirectory`
        // was out of reach on the read path. With a plain file at
        // `~/.local/state/bx`, the read failed `ENOTDIR` and reported
        // "reading ~/.local/state/bx/ledger.mpk: Not a directory" — a file
        // inside a file, with no remedy — while the right error existed and
        // said exactly the right thing.
        let dir = tempfile::tempdir().expect("tempdir");
        let blocking = dir.path().join("bx");
        std::fs::write(&blocking, b"not a directory").expect("seed");

        let err = load::<Value>(
            &blocking.join("v.mpk"),
            KIND,
            VERSION,
            Loss::Recomputable,
            None,
        )
        .expect_err("must fail");
        assert!(
            matches!(&err, Error::NotADirectory { path } if *path == blocking),
            "got {err}",
        );
        assert!(err.to_string().contains("move or remove it"), "{err}");

        // Deeper, too: the component in the way is named, not the leaf.
        let err = load::<Value>(
            &blocking.join("restore/v.mpk"),
            KIND,
            VERSION,
            Loss::Recomputable,
            None,
        )
        .expect_err("must fail");
        assert!(
            matches!(&err, Error::NotADirectory { path } if *path == blocking),
            "got {err}",
        );
    }

    #[test]
    fn a_lockless_reader_reports_damage_and_moves_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"garbage").expect("seed");

        let loaded: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, None).expect("load");
        assert_eq!(loaded.health, Health::Damaged(Damage::Malformed));
        assert!(!loaded.health.is_reset(), "nothing was moved aside");
        assert_eq!(loaded.health.damage(), Some(&Damage::Malformed));
        assert!(loaded.value.is_empty());
        assert_eq!(std::fs::read(&path).expect("in place"), b"garbage");
        assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
    }

    #[test]
    fn a_writer_saving_inside_a_lockless_readers_window_keeps_its_file() {
        // Review round 3's falsifier: the reader has read and judged the bytes,
        // a writer saves a fresh file, and the reader then acts on the path.
        // A rename by path there moved the writer's fresh file aside.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        save(&path, KIND, VERSION, &Value::new()).expect("seed");

        let loaded: Loaded<Value> =
            load_checked(&path, KIND, VERSION, Loss::Recomputable, None, |_| {
                save(&path, KIND, VERSION, &sample()).expect("the writer saves");
                Err(Rejected::PartialDamage(Damage::KeyMismatch {
                    rows: vec![("k".to_string(), "other".to_string())],
                }))
            })
            .expect("load");
        assert!(loaded.health.damage().is_some_and(Damage::is_partial));

        let now: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, None).expect("reload");
        assert_eq!(now.health, Health::Loaded);
        assert_eq!(
            now.value,
            sample(),
            "the writer's file is where it saved it"
        );
        assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
    }

    #[test]
    #[cfg_attr(not(debug_assertions), ignore = "the guard is a debug_assert")]
    #[should_panic(expected = "`Damage::is_partial` accepts")]
    fn a_check_reporting_whole_file_damage_as_partial_is_refused() {
        // r4 round 3 (COV2): the guard that holds `Rejected::PartialDamage` to
        // row-shaped damage was reached by no test, so the body's claim that
        // the two "cannot drift" rested on an assertion nothing exercised.
        // `Damage::Malformed` is what `decode` produces for a whole file, and
        // a check answering with it would make `is_partial` say the rows named
        // are the whole loss when nothing was named.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        save(&path, KIND, VERSION, &sample()).expect("seed");
        let _ = load_checked::<Value>(&path, KIND, VERSION, Loss::Recomputable, None, |value| {
            value.clear();
            Err(Rejected::PartialDamage(Damage::Malformed))
        });
    }

    #[test]
    fn a_refused_value_is_the_error_and_nothing_is_renamed_even_under_the_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        save(&path, KIND, VERSION, &sample()).expect("seed");
        let intact = std::fs::read(&path).expect("read");
        let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");

        let err = load_checked::<Value>(
            &path,
            KIND,
            VERSION,
            Loss::Recomputable,
            Some(&lock),
            |_| {
                Err(Rejected::Refused(Error::NotADirectory {
                    path: PathBuf::from("/refused"),
                }))
            },
        )
        .expect_err("a refusal is an error");
        assert!(
            matches!(&err, Error::NotADirectory { path } if path == Path::new("/refused")),
            "got {err}",
        );
        assert_eq!(std::fs::read(&path).expect("in place"), intact);
        assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
    }

    #[test]
    fn a_degraded_store_writes_a_clean_file_on_the_next_save() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"garbage").expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert!(loaded.health.is_reset());

        save(&path, KIND, VERSION, &sample()).expect("save");
        let again: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(again.health, Health::Loaded);
        assert_eq!(again.value, sample());
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_not_damage() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A directory where a file should be: `read` fails with EISDIR, which
        // is neither NotFound nor a statement about any bytes.
        let path = dir.path().join("v.mpk");
        std::fs::create_dir(&path).expect("seed");
        let err = locked_load::<Value>(&path).expect_err("must fail");
        assert!(
            matches!(&err, Error::Read { path: at, .. } if *at == path),
            "got {err}",
        );
    }

    /// Put a FIFO at `path`.
    fn mkfifo(path: &Path) {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
            0,
        )
        .expect("mkfifo");
    }

    #[test]
    fn a_state_file_that_is_not_a_regular_file_is_never_read() {
        // r5 (D1): `judge` read state files with plain `std::fs::read`, so a
        // FIFO at the name blocked in `open` until a writer appeared, and a
        // link to `/dev/zero` allocated until the process was killed. Both
        // return at once now, whether the name is the thing or a link to it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
        let fifo = || mkfifo(&path);
        let to_zero = || std::os::unix::fs::symlink("/dev/zero", &path).expect("symlink");
        for (stage, seed) in [("fifo", &fifo as &dyn Fn()), ("/dev/zero", &to_zero)] {
            seed();
            // The ledger is refused, lock or no lock, and nothing is renamed.
            for held in [None, Some(&lock)] {
                let err = load::<Value>(&path, KIND, VERSION, Loss::Permanent, held)
                    .expect_err("a permanent file that is not a file is refused");
                assert!(
                    matches!(&err, Error::StateNotAFile { path: at } if *at == path),
                    "{stage}: got {err}",
                );
                assert!(err.to_string().contains("not a regular file"), "{err}");
                assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"], "{stage}");
            }
            // A cache is reported without the lock, and moved aside with it.
            let read: Loaded<Value> =
                load(&path, KIND, VERSION, Loss::Recomputable, None).expect("lockless");
            assert_eq!(read.health, Health::Damaged(Damage::NotAFile), "{stage}");
            let opened: Loaded<Value> =
                load(&path, KIND, VERSION, Loss::Recomputable, Some(&lock)).expect("locked");
            assert_eq!(opened.health, Health::Reset(Damage::NotAFile), "{stage}");
            assert!(opened.value.is_empty(), "{stage}");
            assert!(std::fs::symlink_metadata(&path).is_err(), "{stage}: moved");
            std::fs::remove_file(StateDir::quarantine(&path)).expect("clear");
        }
    }

    #[test]
    fn a_state_file_longer_than_the_limit_is_never_read_whole() {
        // r5 (D1): the length was not bounded at all. A sparse file one byte
        // past the limit costs nothing to make and is refused before any of
        // it is allocated.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
        let seed = || {
            std::fs::File::create(&path)
                .expect("create")
                .set_len(MAX_STATE_FILE + 1)
                .expect("set_len");
        };
        seed();
        for held in [None, Some(&lock)] {
            let err = load::<Value>(&path, KIND, VERSION, Loss::Permanent, held)
                .expect_err("an oversized permanent file is refused");
            assert!(
                matches!(&err, Error::StateTooLarge { path: at } if *at == path),
                "got {err}",
            );
            assert!(err.to_string().contains("268435456 bytes"), "{err}");
            assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
        }
        let read: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, None).expect("lockless");
        assert_eq!(read.health, Health::Damaged(Damage::TooLarge));
        let opened: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, Some(&lock)).expect("locked");
        assert_eq!(opened.health, Health::Reset(Damage::TooLarge));
        assert!(!path.exists(), "moved aside");

        // Exactly the limit is still read, and judged on its bytes.
        std::fs::File::create(&path)
            .expect("create")
            .set_len(MAX_STATE_FILE)
            .expect("set_len");
        let at_limit: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, None).expect("lockless");
        assert!(
            !matches!(at_limit.health.damage(), Some(Damage::TooLarge)),
            "{:?}",
            at_limit.health,
        );
    }

    #[test]
    fn an_intact_file_that_cannot_be_read_is_left_exactly_where_it_is() {
        if rustix::process::geteuid().is_root() {
            // `0000` denies nothing to root, so the condition cannot be staged.
            // The root-independent half of this property is pinned by
            // `a_file_that_cannot_be_read_is_an_error_not_damage`.
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        save(&path, KIND, VERSION, &sample()).expect("save");
        let intact = std::fs::read(&path).expect("read");
        // What a `sudo bx` leaves behind: a perfectly good state file this
        // account cannot open. Nothing is known about its bytes, so nothing may
        // be renamed and nothing may be reset.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let err = locked_load::<Value>(&path).expect_err("must fail");
        assert!(matches!(err, Error::Read { .. }), "got {err}");
        assert!(path.exists(), "the file must not be moved aside");
        assert!(
            !StateDir::quarantine(&path).exists(),
            "a file whose bytes were never read must never be quarantined",
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Loaded);
        assert_eq!(loaded.value, sample());
        assert_eq!(std::fs::read(&path).expect("read"), intact);
    }

    #[test]
    fn a_file_that_cannot_be_moved_aside_is_refused_and_left_in_place() {
        // r3 round 1 (L1b): a failed move aside was logged and reported as
        // `Health::Reset` — "has been quarantined" — with the damaged file
        // still at its name, so the next save overwrote the bytes that
        // `Reset` and the module both promise are kept.
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
        // A name at the 255-byte limit: every quarantine name is longer, so
        // each rename fails with ENAMETOOLONG rather than finding a free name.
        let path = dir.path().join("v".repeat(255));
        for loss in [Loss::Recomputable, Loss::Permanent] {
            std::fs::write(&path, b"garbage").expect("seed");
            let result = load::<Value>(&path, KIND, VERSION, loss, Some(&lock));
            assert_eq!(
                std::fs::read(&path).expect("in place"),
                b"garbage",
                "{loss:?}: the damaged bytes are where they were",
            );
            assert_eq!(names_but_the_lock(dir.path()), vec!["v".repeat(255)]);
            let err = result.expect_err("a file that cannot be moved aside is refused");
            assert!(
                matches!(
                    &err,
                    Error::CannotQuarantine { path: at, damage: Damage::Malformed, source }
                        if *at == path
                            && source.raw_os_error()
                                == Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
                ),
                "{loss:?}: got {err}",
            );
            let message = err.to_string();
            for needle in [
                path.to_string_lossy().as_ref(),
                "not valid MessagePack",
                "by hand",
            ] {
                assert!(
                    message.contains(needle),
                    "{loss:?}: missing {needle:?}: {message}"
                );
            }
        }

        // A cache link that leads nowhere is the other damage moved aside.
        std::fs::remove_file(&path).expect("remove");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &path).expect("symlink");
        let err = load::<Value>(&path, KIND, VERSION, Loss::Recomputable, Some(&lock))
            .expect_err("a link that cannot be moved aside is refused");
        assert!(
            matches!(
                &err,
                Error::CannotQuarantine { path: at, damage: Damage::DanglingLink, .. }
                    if *at == path
            ),
            "got {err}",
        );
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(
            std::fs::symlink_metadata(&path).is_ok(),
            "the link is in place"
        );

        // A lockless reader still reports the damage and moves nothing.
        std::fs::remove_file(&path).expect("remove");
        std::fs::write(&path, b"garbage").expect("seed");
        let loaded = load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None).expect("load");
        assert_eq!(loaded.health, Health::Damaged(Damage::Malformed));
    }

    #[test]
    fn an_occupied_quarantine_name_is_skipped_not_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"garbage").expect("seed");
        // Whatever holds the first name — a directory here — is left alone.
        let first = StateDir::quarantine(&path);
        std::fs::create_dir(&first).expect("occupy");
        std::fs::write(first.join("keep"), b"x").expect("occupy");

        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert!(loaded.health.is_reset());
        assert_eq!(std::fs::read(first.join("keep")).expect("kept"), b"x");
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&path, 1)).expect("moved"),
            b"garbage",
        );
    }

    #[test]
    fn state_files_are_written_at_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        save(&path, KIND, VERSION, &sample()).expect("save");
        let mode = Mode::from_bits(std::fs::metadata(&path).expect("stat").permissions().mode());
        assert_eq!(mode, Mode::PRIVATE_FILE);
    }

    #[test]
    fn saving_creates_the_state_directory_at_0700() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("bx");
        save(&root.join("v.mpk"), KIND, VERSION, &sample()).expect("save");
        let mode = Mode::from_bits(std::fs::metadata(&root).expect("stat").permissions().mode());
        assert_eq!(mode, Mode::PRIVATE_DIR);
    }

    #[test]
    fn a_save_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        save(&dir.path().join("v.mpk"), KIND, VERSION, &sample()).expect("save");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("v.mpk")]);
    }

    #[test]
    fn a_save_into_an_impossible_directory_reports_rather_than_panics() {
        let dir = tempfile::tempdir().expect("tempdir");
        let occupied = dir.path().join("file");
        std::fs::write(&occupied, b"x").expect("seed");
        let err = save(&occupied.join("v.mpk"), KIND, VERSION, &sample()).expect_err("must fail");
        assert!(
            matches!(&err, Error::NotADirectory { path } if *path == occupied),
            "got {err}",
        );
    }

    #[test]
    fn a_loaded_value_can_be_mapped_without_losing_its_health() {
        let loaded = Loaded {
            value: 1_u32,
            health: Health::Reset(Damage::Malformed),
            quarantined: vec![PathBuf::from("/s/v.mpk.corrupt")],
            unlisted: Some(Unlisted {
                path: PathBuf::from("/s"),
                kind: std::io::ErrorKind::PermissionDenied,
                cause: "Permission denied".to_string(),
            }),
        };
        let mapped = loaded.map(|v| v + 1);
        assert_eq!(mapped.value, 2);
        assert_eq!(mapped.health, Health::Reset(Damage::Malformed));
        assert_eq!(mapped.quarantined, vec![PathBuf::from("/s/v.mpk.corrupt")]);
        assert_eq!(mapped.unlisted.map(|u| u.path), Some(PathBuf::from("/s")),);
    }
}
