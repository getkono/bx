//! The cache-invalidation store.
//!
//! A fingerprint answers one question: *have the inputs to this piece of work
//! changed since the last time bx did it?* The key is an opaque string the
//! caller composes, the value is opaque bytes the caller composes, and this
//! module knows the meaning of neither. That is deliberate — the alternative is
//! a store that has to be extended every time something new wants caching.
//!
//! Losing a fingerprint costs a recomputation and nothing else, which is why
//! this is one type rather than the ledger's read-only and writable pair: no
//! consumer needs the write capability expressed in the type, and a
//! `Fingerprints` value is not itself proof of anything.
//!
//! The lock is therefore demanded where it is actually needed — at
//! [`Fingerprints::save`], the only call that writes — rather than at a
//! constructor that would take a guard and drop it. [`Fingerprints::read`] is
//! lockless and says so.

use std::collections::BTreeMap;
use std::collections::btree_map::Iter;
use std::fmt;

use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use super::Error;
use super::dir::StateDir;
use super::hash::ContentHash;
use super::lock::ExclusiveLock;
use super::store::{self, Loaded};

/// The envelope tag for `fingerprints.mpk`.
const KIND: &str = "bx.fingerprints";

/// The newest fingerprint format this build writes and understands.
const VERSION: u16 = 1;

/// An opaque fingerprint of whatever its writer decided the inputs were.
///
/// Stored as MessagePack's native binary type, so a digest costs 32 bytes rather
/// than 64 hex characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(Vec<u8>);

impl Fingerprint {
    /// A fingerprint that *is* these bytes, stored verbatim.
    ///
    /// For an input that is already short and already canonical — a version
    /// string, a modification time, an inode number.
    #[must_use]
    pub fn raw(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The SHA-256 of these bytes. The usual case: the inputs are long, and
    /// only whether they changed matters.
    #[must_use]
    pub fn hashed(bytes: &[u8]) -> Self {
        Self(ContentHash::of(bytes).as_bytes().to_vec())
    }

    /// The stored bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({} bytes)", self.0.len())
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_byte_buf(FingerprintVisitor)
    }
}

/// Accepts any run of bytes: a fingerprint's length is its writer's business.
struct FingerprintVisitor;

impl Visitor<'_> for FingerprintVisitor {
    type Value = Fingerprint;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an opaque fingerprint")
    }

    fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(Fingerprint(value.to_vec()))
    }

    fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(Fingerprint(value))
    }
}

/// Every fingerprint this account has recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprints {
    /// A `BTreeMap`, so the serialised order is the key order and a save is
    /// byte-identical between runs.
    #[serde(default)]
    entries: BTreeMap<String, Fingerprint>,
}

impl Fingerprints {
    /// Read the cache without taking a lock.
    ///
    /// A damaged `fingerprints.mpk` is quarantined and this returns an empty
    /// cache. Losing a cache costs a recomputation, which is exactly what a
    /// cache is allowed to cost.
    ///
    /// # Errors
    ///
    /// [`Error::Read`] if `fingerprints.mpk` exists and cannot be read. A file
    /// whose bytes were never seen is not damaged and is never quarantined; a
    /// caller is free to treat the failure as a cache miss, but it has to
    /// decide that itself rather than have a rename decide it.
    pub fn read(dir: &StateDir) -> Result<Loaded<Self>, Error> {
        store::load(&dir.fingerprints(), KIND, VERSION)
    }

    /// The fingerprint recorded under `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Fingerprint> {
        self.entries.get(key)
    }

    /// Record `fingerprint` under `key`, returning whatever it replaced.
    pub fn set(&mut self, key: impl Into<String>, fingerprint: Fingerprint) -> Option<Fingerprint> {
        self.entries.insert(key.into(), fingerprint)
    }

    /// Whether `key` is already recorded with exactly this fingerprint.
    ///
    /// An unknown key is `false`. A missing fingerprint must invalidate rather
    /// than validate: the cost of recomputing is a delay, and the cost of
    /// wrongly skipping is a stale environment.
    #[must_use]
    pub fn matches(&self, key: &str, fingerprint: &Fingerprint) -> bool {
        self.get(key) == Some(fingerprint)
    }

    /// Forget `key`.
    pub fn remove(&mut self, key: &str) -> Option<Fingerprint> {
        self.entries.remove(key)
    }

    /// Every fingerprint, in ascending key order.
    pub fn iter(&self) -> Iter<'_, String, Fingerprint> {
        self.entries.iter()
    }

    /// How many fingerprints are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether anything is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Write the cache out, atomically, under the exclusive lock.
    ///
    /// The guard is required rather than merely documented: this is the only
    /// call in the module that writes the state directory, so this is the only
    /// signature that can carry the requirement honestly. It is not stored —
    /// presenting it is the point.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`], [`Error::CreateDir`] or [`Error::Write`]. A failure
    /// leaves the previous cache exactly as it was.
    pub fn save(&self, dir: &StateDir, _lock: &ExclusiveLock) -> Result<(), Error> {
        store::save(&dir.fingerprints(), KIND, VERSION, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::state::{Damage, Health};
    use crate::testing::guarded_home;

    #[test]
    fn a_fingerprint_holds_whatever_bytes_it_was_given() {
        let raw = Fingerprint::raw(vec![0, 1, 2, 255]);
        assert_eq!(raw.as_bytes(), &[0, 1, 2, 255]);
        assert_eq!(Fingerprint::raw(b"abc".to_vec()).as_bytes(), b"abc");
        assert_eq!(format!("{raw:?}"), "Fingerprint(4 bytes)");
    }

    #[test]
    fn a_hashed_fingerprint_is_the_digest_of_its_input() {
        let fingerprint = Fingerprint::hashed(b"rustc 1.90.0");
        assert_eq!(
            fingerprint.as_bytes(),
            ContentHash::of(b"rustc 1.90.0").as_bytes(),
        );
    }

    #[test]
    fn a_changed_input_produces_a_different_fingerprint() {
        assert_ne!(Fingerprint::hashed(b"v1"), Fingerprint::hashed(b"v2"));
        assert_eq!(Fingerprint::hashed(b"v1"), Fingerprint::hashed(b"v1"));
    }

    #[test]
    fn an_unknown_key_never_matches() {
        let fingerprints = Fingerprints::default();
        assert!(!fingerprints.matches("activation:rustup", &Fingerprint::hashed(b"v1")));
        assert!(fingerprints.get("activation:rustup").is_none());
        assert!(fingerprints.is_empty());
        assert_eq!(fingerprints.len(), 0);
    }

    #[test]
    fn setting_replaces_and_returns_the_previous_value() {
        let mut fingerprints = Fingerprints::default();
        assert!(fingerprints.set("k", Fingerprint::hashed(b"v1")).is_none());
        assert!(fingerprints.matches("k", &Fingerprint::hashed(b"v1")));

        let previous = fingerprints.set("k", Fingerprint::hashed(b"v2"));
        assert_eq!(previous, Some(Fingerprint::hashed(b"v1")));
        assert!(!fingerprints.matches("k", &Fingerprint::hashed(b"v1")));
        assert!(fingerprints.matches("k", &Fingerprint::hashed(b"v2")));
        assert_eq!(fingerprints.len(), 1);

        assert_eq!(fingerprints.remove("k"), Some(Fingerprint::hashed(b"v2")));
        assert_eq!(fingerprints.remove("k"), None);
    }

    #[test]
    fn fingerprints_round_trip_and_iterate_in_key_order() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");

        let mut fingerprints = Fingerprints::read(&dir).expect("read").value;
        for key in ["activation:uv", "activation:mise", "activation:rustup"] {
            fingerprints.set(key, Fingerprint::hashed(key.as_bytes()));
        }
        fingerprints.save(&dir, &lock).expect("save");

        let reloaded = Fingerprints::read(&dir).expect("read");
        assert_eq!(reloaded.health, Health::Loaded);
        let keys: Vec<_> = reloaded.value.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["activation:mise", "activation:rustup", "activation:uv"],
        );
        assert!(
            reloaded
                .value
                .matches("activation:uv", &Fingerprint::hashed(b"activation:uv"))
        );
    }

    #[test]
    fn saving_the_same_cache_twice_produces_identical_bytes() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");
        let mut fingerprints = Fingerprints::default();
        fingerprints.set("b", Fingerprint::raw(vec![2]));
        fingerprints.set("a", Fingerprint::raw(vec![1]));
        fingerprints.save(&dir, &lock).expect("first");
        let first = std::fs::read(dir.fingerprints()).expect("read");
        fingerprints.save(&dir, &lock).expect("second");
        assert_eq!(std::fs::read(dir.fingerprints()).expect("read"), first);
    }

    #[test]
    fn a_fingerprint_is_stored_as_messagepack_binary() {
        let encoded = rmp_serde::to_vec_named(&Fingerprint::raw(vec![1, 2, 3])).expect("encode");
        assert_eq!(encoded, vec![0xc4, 3, 1, 2, 3]);
        let back: Fingerprint = rmp_serde::from_slice(&encoded).expect("decode");
        assert_eq!(back.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn an_empty_fingerprint_round_trips() {
        let encoded = rmp_serde::to_vec_named(&Fingerprint::raw(Vec::new())).expect("encode");
        let back: Fingerprint = rmp_serde::from_slice(&encoded).expect("decode");
        assert!(back.as_bytes().is_empty());
    }

    #[test]
    fn a_corrupt_fingerprint_file_degrades_to_an_empty_cache() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");
        std::fs::write(dir.fingerprints(), b"\x00\x01 not an envelope").expect("seed");

        let loaded = Fingerprints::read(&dir).expect("read");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
        assert!(dir.root().join("fingerprints.mpk.corrupt").exists());

        // The point of a cache: the next save writes a clean file and nothing
        // the user has to clear is left behind.
        loaded.value.save(&dir, &lock).expect("save");
        assert_eq!(
            Fingerprints::read(&dir).expect("read").health,
            Health::Loaded
        );
    }

    #[test]
    fn a_ledger_file_is_not_accepted_as_a_fingerprint_cache() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        // Write a well-formed envelope of another kind into this slot, the way
        // a misplaced copy or a botched restore would.
        store::save(
            &dir.fingerprints(),
            "bx.ledger",
            1,
            &BTreeMap::<String, u32>::new(),
        )
        .expect("seed");

        let loaded = Fingerprints::read(&dir).expect("read");
        assert_eq!(
            loaded.health,
            Health::Reset(Damage::WrongKind {
                found: "bx.ledger".to_string(),
            }),
        );
        assert!(loaded.value.is_empty());
    }
}
