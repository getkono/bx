//! One MessagePack envelope, and one degradation policy for every state file.
//!
//! `CLAUDE.md` requires every machine-owned file to be *reconstructible*, so a
//! corrupt one degrades to recomputation rather than to an error the user cannot
//! clear. That requirement is met here, once, for every file in the state
//! directory: [`load`] never fails. It returns the stored value, or — for any
//! damage at all — the empty default, having first moved the damaged bytes aside
//! to `<name>.corrupt` and warned about it.

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

/// What was wrong with a state file that had to be discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Damage {
    /// The file exists but could not be read.
    Unreadable,
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
            Self::Unreadable => f.write_str("it could not be read"),
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
/// Loading never fails, so the health travels with the value rather than in a
/// `Result`. A caller that wants to tell the user "your ledger was corrupt and
/// has been reset" reads [`Loaded::health`]; a caller that only wants the value
/// calls [`Loaded::value`] and ignores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded<T> {
    /// The loaded — or default — value.
    pub value: T,
    /// Where it came from.
    pub health: Health,
}

impl<T> Loaded<T> {
    /// The value, discarding the health.
    #[must_use]
    pub fn value(self) -> T {
        self.value
    }
}

/// Read a state file, degrading to `T::default()` for any damage.
///
/// Never fails. Any damage moves the file to `<name>.corrupt`, emits a
/// `tracing::warn!`, and yields the default; the next [`save`] writes a clean
/// file over the original name, so the condition clears itself.
pub(crate) fn load<T: DeserializeOwned + Default>(
    path: &Path,
    kind: &'static str,
    version: u16,
) -> Loaded<T> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Loaded {
                value: T::default(),
                health: Health::Fresh,
            };
        }
        Err(_) => return reset(path, &Damage::Unreadable),
    };

    match decode::<T>(&bytes, kind, version) {
        Ok(value) => Loaded {
            value,
            health: Health::Loaded,
        },
        Err(damage) => reset(path, &damage),
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
        let loaded: Loaded<Value> = load(&dir.path().join("nope.mpk"), KIND, VERSION);
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
        assert_eq!(loaded.health, Health::Loaded);
        assert_eq!(loaded.value, sample());
    }

    #[test]
    fn a_truncated_file_degrades_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        let bytes = encoded(KIND, VERSION, &sample());
        std::fs::write(&path, &bytes[..bytes.len() / 2]).expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
    }

    #[test]
    fn garbage_bytes_degrade_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"this is certainly not MessagePack").expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
        assert_eq!(loaded.health, Health::Reset(Damage::TrailingBytes));
        assert!(loaded.value.is_empty());
    }

    #[test]
    fn a_future_version_degrades_and_names_the_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, encoded(KIND, VERSION + 5, &sample())).expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
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
        let _: Loaded<Value> = load(&path, KIND, VERSION);
        assert!(!path.exists(), "the damaged file must be moved aside");
        let quarantine = StateDir::quarantine(&path);
        assert_eq!(std::fs::read(&quarantine).expect("read"), b"garbage");
    }

    #[test]
    fn a_second_quarantine_reuses_the_same_fixed_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.mpk");
        std::fs::write(&path, b"first").expect("seed");
        let _: Loaded<Value> = load(&path, KIND, VERSION);
        std::fs::write(&path, b"second").expect("seed again");
        let _: Loaded<Value> = load(&path, KIND, VERSION);

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
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
        assert!(loaded.health.is_reset());

        save(&path, KIND, VERSION, &sample()).expect("save");
        let again: Loaded<Value> = load(&path, KIND, VERSION);
        assert_eq!(again.health, Health::Loaded);
        assert_eq!(again.value, sample());
    }

    #[test]
    fn an_unreadable_file_degrades_rather_than_failing() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A directory where a file should be: `read` fails with EISDIR, which
        // is neither NotFound nor decodable.
        let path = dir.path().join("v.mpk");
        std::fs::create_dir(&path).expect("seed");
        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
        assert_eq!(loaded.health, Health::Reset(Damage::Unreadable));
        assert!(loaded.value.is_empty());
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

        let loaded: Loaded<Value> = load(&path, KIND, VERSION);
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
}
