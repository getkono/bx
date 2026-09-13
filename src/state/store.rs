//! One MessagePack envelope, and one degradation policy for every state file.
//!
//! `CLAUDE.md` requires every machine-owned file to be *reconstructible*, so a
//! corrupt one degrades to recomputation rather than to an error the user cannot
//! clear. That requirement is met here, once, for every file in the state
//! directory: [`load`] returns the stored value, or — for damaged *contents* —
//! the empty default, having moved the damaged bytes aside to the next
//! `<name>.corrupt`, `<name>.corrupt.1`, … and warned about it.
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
//! user's restore blobs — and a gap left by a deleted one is never refilled, so
//! the numbers present are always in the order the quarantines were made.
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

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::Error;
use super::dir::{check_lock, ensure_dir, move_aside, quarantines};
use super::lock::ExclusiveLock;
use crate::fs::{Mode, write_atomically};

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
/// Every variant but [`Damage::DanglingLink`] is a decode failure: the bytes
/// were read, and they are not a usable envelope. A file that could not be read
/// is not represented here — see [`Error::Read`] and the module documentation.
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
    /// The envelope decoded, and a ledger entry names a different path from
    /// the key it is stored under.
    ///
    /// `record` stores every entry under its own path, so a mismatch is not
    /// something bx wrote: it is damage, whatever home the ledger is read with.
    KeyMismatch {
        /// The key the entry is stored under.
        key: String,
        /// The path the entry itself names.
        path: String,
    },
}

/// Why a file's loader did not accept a value that decoded.
#[derive(Debug)]
pub(crate) enum Rejected {
    /// The contents are damaged. Quarantined under the lock, reported without.
    Damage(Damage),
    /// The contents may be intact, and the context they were checked against is
    /// what is wrong. Returned to the caller; nothing is renamed.
    Refused(Error),
}

impl From<Damage> for Rejected {
    fn from(damage: Damage) -> Self {
        Self::Damage(damage)
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
            Self::KeyMismatch { key, path } => {
                write!(f, "its entry for {key} names a different path, {path}")
            }
        }
    }
}

/// Where a loaded value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// There was no file. The value is the empty default, and nothing is wrong.
    Fresh,
    /// The file was read and decoded.
    Loaded,
    /// The file was damaged, has been quarantined, and the value is the empty
    /// default.
    Reset(Damage),
    /// The file is damaged, and was **left where it is**, because the reader
    /// holds no exclusive lock. The value is the empty default. The next holder
    /// of the lock quarantines it.
    Damaged(Damage),
}

impl Health {
    /// Whether the caller is looking at recovered-from-nothing state that has
    /// been moved aside.
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
/// describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded<T> {
    /// The loaded — or default — value.
    pub value: T,
    /// Where it came from.
    pub health: Health,
    /// Every quarantine of this file in the state directory now, in the order
    /// they were made — `<name>.corrupt`, `<name>.corrupt.1`, … — including
    /// one this load made. A new quarantine always takes the number after the
    /// highest present and never refills a gap, so the last is the newest.
    ///
    /// Independent of [`Loaded::health`]. A run that quarantined the file and
    /// stopped before its save leaves the next load [`Health::Fresh`], and this
    /// is what still shows that damaged bytes were set aside. They may be the
    /// only index there is to the user's restore blobs, so `plan` and `doctor`
    /// should name every one until a human moves it; bx never deletes them.
    pub quarantined: Vec<PathBuf>,
}

impl<T> Loaded<T> {
    /// Apply `f` to the value, keeping the health.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Loaded<U> {
        Loaded {
            value: f(self.value),
            health: self.health,
            quarantined: self.quarantined,
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
/// [`Error::WrongLock`] if `lock` is not the lock of the directory holding
/// `path`; nothing is read.
pub(crate) fn load<T: DeserializeOwned + Default>(
    path: &Path,
    kind: &'static str,
    version: u16,
    loss: Loss,
    lock: Option<&ExclusiveLock>,
) -> Result<Loaded<T>, Error> {
    load_checked(path, kind, version, loss, lock, |_| Ok(()))
}

/// [`load`], with a check on the decoded value that decoding alone cannot make.
///
/// `check` runs only on a value that decoded whole. [`Rejected::Damage`] is
/// handled like any other decode failure. [`Rejected::Refused`] is returned as
/// the error and renames nothing: a value refused against context the decoder
/// did not have — the account's home — is never believed, and never discarded
/// either.
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
    check: impl FnOnce(&T) -> Result<(), Rejected>,
) -> Result<Loaded<T>, Error> {
    let mut loaded = judge(path, kind, version, loss, lock, check)?;
    // Listed after any quarantine this load made, and whatever the health: an
    // earlier run's quarantine must not hide behind `Fresh`.
    loaded.quarantined = quarantines(path)?;
    Ok(loaded)
}

/// [`load_checked`], less the listing of quarantines.
fn judge<T: DeserializeOwned + Default>(
    path: &Path,
    kind: &'static str,
    version: u16,
    loss: Loss,
    lock: Option<&ExclusiveLock>,
    check: impl FnOnce(&T) -> Result<(), Rejected>,
) -> Result<Loaded<T>, Error> {
    // A lock presented for another directory guards nothing here, and is
    // refused before anything is read.
    if let Some(lock) = lock {
        check_lock(path, lock)?;
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
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
                    Loss::Recomputable => Ok(degrade(path, Damage::DanglingLink, lock)),
                };
            }
            if source.kind() == std::io::ErrorKind::NotFound {
                return Ok(Loaded {
                    value: T::default(),
                    health: Health::Fresh,
                    quarantined: Vec::new(),
                });
            }
            return Err(Error::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let checked = decode::<T>(&bytes, kind, version)
        .map_err(Rejected::Damage)
        .and_then(|value| check(&value).map(|()| value));
    match checked {
        Ok(value) => Ok(Loaded {
            value,
            health: Health::Loaded,
            quarantined: Vec::new(),
        }),
        // A newer format of a file nothing can rebuild is not believed and not
        // discarded: it is intact as far as anyone knows.
        Err(Rejected::Damage(Damage::FutureVersion { found, supported }))
            if loss == Loss::Permanent =>
        {
            // One flipped bit in the version number also makes an intact file
            // "newer". Whether the rest of it reads as this build's format is
            // what the message can honestly say about that.
            let payload_readable = rmp_serde::from_slice::<Envelope<T>>(&bytes).is_ok();
            Err(Error::FutureVersion {
                path: path.to_path_buf(),
                found,
                supported,
                payload_readable,
            })
        }
        // Quarantine happens only here: after `read` succeeded and `decode` or
        // `check` found damage, so the bytes being moved aside are known to be
        // unusable — and only under the lock, so they are still the bytes read.
        Err(Rejected::Damage(damage)) => Ok(degrade(path, damage, lock)),
        Err(Rejected::Refused(error)) => Err(error),
    }
}

/// Whether a failed `read` is one that following a symbolic link to nowhere
/// gives: `ENOENT` for a link to nothing, `ELOOP` for links that loop, and
/// `ENOTDIR` for a link whose path runs through a file.
///
/// Only meaningful once the path itself is known to be a link: without one,
/// `ENOENT` is simply no file, and `ENOTDIR` a state directory that is not a
/// directory.
fn leads_nowhere(error: &std::io::Error) -> bool {
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

/// Return the empty default for a damaged file, moving it aside only under the
/// lock.
fn degrade<T: Default>(path: &Path, damage: Damage, lock: Option<&ExclusiveLock>) -> Loaded<T> {
    let Some(lock) = lock else {
        tracing::warn!(
            path = %path.display(),
            "{} is damaged: {damage}. It was left in place; the next bx that holds \
             the state directory lock moves it aside.",
            path.display(),
        );
        return Loaded {
            value: T::default(),
            health: Health::Damaged(damage),
            quarantined: Vec::new(),
        };
    };
    match move_aside(path, lock) {
        Ok(quarantine) => tracing::warn!(
            path = %path.display(),
            moved_to = %quarantine.display(),
            "discarding {}: {damage}. The bytes were kept, not deleted.",
            path.display(),
        ),
        Err(source) => tracing::warn!(
            path = %path.display(),
            %source,
            "discarding {}: {damage}. It could not be moved aside.",
            path.display(),
        ),
    }
    Loaded {
        value: T::default(),
        health: Health::Reset(damage),
        quarantined: Vec::new(),
    }
}

/// Write a state file atomically, at `0600`, creating its directory at `0700`.
///
/// # Errors
///
/// [`Error::Encode`] if the value cannot be encoded — a bug, not a user
/// condition — and [`Error::CreateDir`] or [`Error::Write`] for a filesystem
/// failure. A failure leaves the previous file exactly as it was.
pub(crate) fn save<T: Serialize>(
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
    if let Some(parent) = path.parent() {
        ensure_dir(parent, Mode::PRIVATE_DIR)?;
    }
    write_atomically(path, &bytes, Mode::PRIVATE_FILE)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

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
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        save(&path, KIND, VERSION, &sample()).expect("first");
        let first = std::fs::read(&path).expect("read");
        save(&path, KIND, VERSION, &sample()).expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), first);
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
    fn a_state_directory_that_cannot_be_listed_is_an_error_not_an_empty_list() {
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
        // listed. Reporting no quarantines there would be a guess.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300)).expect("chmod");
        let result = load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("restore");
        let err = result.expect_err("an unlistable directory is not an empty one");
        assert!(
            matches!(&err, Error::Read { path: at, .. } if *at == root),
            "got {err}"
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
                Err(Damage::Malformed.into())
            })
            .expect("load");
        assert_eq!(loaded.health, Health::Damaged(Damage::Malformed));

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
    fn a_file_that_cannot_be_moved_aside_still_degrades() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A name at the 255-byte limit: every quarantine name is longer, so
        // each rename fails with ENAMETOOLONG rather than finding a free name.
        let path = dir.path().join("v".repeat(255));
        std::fs::write(&path, b"garbage").expect("seed");

        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert!(loaded.health.is_reset());
        assert!(loaded.value.is_empty());
        assert_eq!(
            std::fs::read(&path).expect("in place"),
            b"garbage",
            "the damaged bytes survive a failed rename",
        );
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
        };
        let mapped = loaded.map(|v| v + 1);
        assert_eq!(mapped.value, 2);
        assert_eq!(mapped.health, Health::Reset(Damage::Malformed));
        assert_eq!(mapped.quarantined, vec![PathBuf::from("/s/v.mpk.corrupt")]);
        assert_eq!(mapped.value, 2);
    }
}
