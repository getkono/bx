//! One MessagePack envelope, and one degradation policy for every state file.
//!
//! `CLAUDE.md` requires every machine-owned file to be *reconstructible*, so a
//! corrupt one degrades to recomputation rather than to an error the user cannot
//! clear. That requirement is met here, once, for every file in the state
//! directory: [`load`] returns the stored value, or — for damaged *contents* —
//! the empty default, having first moved the damaged bytes aside to
//! `<name>.corrupt` and warned about it.
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

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::Error;
use super::dir::{StateDir, ensure_dir};
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

/// What was wrong with the *contents* of a state file that had to be discarded.
///
/// Every variant is a decode failure: the bytes were read, and they are not a
/// usable envelope. A file that could not be read is not represented here —
/// see [`Error::Read`] and the module documentation.
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
    /// The envelope was written by a newer bx than this one.
    FutureVersion {
        /// The version on disk.
        found: u16,
        /// The newest version this build understands.
        supported: u16,
    },
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
}

impl Health {
    /// Whether the caller is looking at recovered-from-nothing state.
    #[must_use]
    pub fn is_reset(&self) -> bool {
        matches!(self, Self::Reset(_))
    }

    /// The damage, if this is a reset.
    #[must_use]
    pub fn damage(&self) -> Option<&Damage> {
        match self {
            Self::Reset(damage) => Some(damage),
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
}

impl<T> Loaded<T> {
    /// Apply `f` to the value, keeping the health.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Loaded<U> {
        Loaded {
            value: f(self.value),
            health: self.health,
        }
    }
}

/// Read a state file, degrading to `T::default()` for damaged contents.
///
/// A missing file is [`Health::Fresh`]. Damaged contents move the file to
/// `<name>.corrupt`, emit a `tracing::warn!`, and yield the default; the next
/// [`save`] writes a clean file over the original name, so the condition clears
/// itself.
///
/// # Errors
///
/// [`Error::Read`] if the file exists and cannot be read. That is an access
/// failure, not damage: the bytes were never seen, so they are neither
/// quarantined nor discarded, and the caller must treat it as fatal rather than
/// carry on against an empty default.
pub(crate) fn load<T: DeserializeOwned + Default>(
    path: &Path,
    kind: &'static str,
    version: u16,
) -> Result<Loaded<T>, Error> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Loaded {
                value: T::default(),
                health: Health::Fresh,
            });
        }
        Err(source) => {
            return Err(Error::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    match decode::<T>(&bytes, kind, version) {
        Ok(value) => Ok(Loaded {
            value,
            health: Health::Loaded,
        }),
        // Quarantine happens only here: after `read` succeeded and `decode`
        // failed, so the bytes being moved aside are known to be unusable.
        Err(damage) => Ok(reset(path, &damage)),
    }
}

/// Decode one envelope, rejecting anything that is not exactly one.
fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    kind: &'static str,
    version: u16,
) -> Result<T, Damage> {
    let mut de = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
    let envelope: Envelope<T> =
        serde::Deserialize::deserialize(&mut de).map_err(|_| Damage::Malformed)?;
    // `rmp_serde::from_slice` stops at the end of the first value and ignores
    // whatever follows. A file that grew garbage at the end is damaged, not
    // half-readable, so the position is checked rather than trusted.
    if usize::try_from(de.position()).unwrap_or(usize::MAX) != bytes.len() {
        return Err(Damage::TrailingBytes);
    }
    if envelope.kind != kind {
        return Err(Damage::WrongKind {
            found: envelope.kind,
        });
    }
    if envelope.version > version {
        return Err(Damage::FutureVersion {
            found: envelope.version,
            supported: version,
        });
    }
    Ok(envelope.payload)
}

/// Move a damaged file aside and return the empty default.
fn reset<T: Default>(path: &Path, damage: &Damage) -> Loaded<T> {
    let quarantine = StateDir::quarantine(path);
    match std::fs::rename(path, &quarantine) {
        Ok(()) => tracing::warn!(
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
        health: Health::Reset(damage.clone()),
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

    const KIND: &str = "bx.test";
    const OTHER: &str = "bx.other";
    const VERSION: u16 = 3;

    type Value = BTreeMap<String, u32>;

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
        let loaded: Loaded<Value> =
            load(&dir.path().join("nope.mpk"), KIND, VERSION).expect("load");
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        assert_eq!(loaded.health, Health::Loaded);
        assert_eq!(loaded.value, sample());
    }

    #[test]
    fn a_truncated_file_degrades_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let bytes = encoded(KIND, VERSION, &sample());
        std::fs::write(&path, &bytes[..bytes.len() / 2]).expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
    }

    #[test]
    fn garbage_bytes_degrade_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"this is certainly not MessagePack").expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::TrailingBytes));
        assert!(loaded.value.is_empty());
    }

    #[test]
    fn a_future_version_degrades_and_names_the_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, encoded(KIND, VERSION + 5, &sample())).expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
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

    #[test]
    fn a_file_of_the_wrong_kind_is_not_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, encoded(OTHER, VERSION, &sample())).expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
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
        let _: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
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

        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        assert_eq!(loaded.value, sample());
    }

    #[test]
    fn a_second_quarantine_reuses_the_same_fixed_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"first").expect("seed");
        let _: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        std::fs::write(&path, b"second").expect("seed again");
        let _: Loaded<Value> = load(&path, KIND, VERSION).expect("load");

        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("v.mpk.corrupt")]);
        assert_eq!(
            std::fs::read(StateDir::quarantine(&path)).expect("read"),
            b"second",
        );
    }

    #[test]
    fn a_degraded_store_writes_a_clean_file_on_the_next_save() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"garbage").expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        assert!(loaded.health.is_reset());

        save(&path, KIND, VERSION, &sample()).expect("save");
        let again: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
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
        let err = load::<Value>(&path, KIND, VERSION).expect_err("must fail");
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

        let err = load::<Value>(&path, KIND, VERSION).expect_err("must fail");
        assert!(matches!(err, Error::Read { .. }), "got {err}");
        assert!(path.exists(), "the file must not be moved aside");
        assert!(
            !StateDir::quarantine(&path).exists(),
            "a file whose bytes were never read must never be quarantined",
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        assert_eq!(loaded.health, Health::Loaded);
        assert_eq!(loaded.value, sample());
        assert_eq!(std::fs::read(&path).expect("read"), intact);
    }

    #[test]
    fn a_file_that_cannot_be_moved_aside_still_degrades() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sub").join("v.mpk");
        std::fs::create_dir(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"garbage").expect("seed");
        // Quarantining renames within the directory; occupying the target with
        // a non-empty directory makes the rename fail.
        let quarantine = StateDir::quarantine(&path);
        std::fs::create_dir(&quarantine).expect("occupy");
        std::fs::write(quarantine.join("keep"), b"x").expect("occupy");

        let loaded: Loaded<Value> = load(&path, KIND, VERSION).expect("load");
        assert!(loaded.health.is_reset());
        assert!(loaded.value.is_empty());
        assert!(path.exists(), "the damaged bytes survive a failed rename");
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
        };
        let mapped = loaded.map(|v| v + 1);
        assert_eq!(mapped.value, 2);
        assert_eq!(mapped.health, Health::Reset(Damage::Malformed));
        assert_eq!(mapped.value, 2);
    }
}
