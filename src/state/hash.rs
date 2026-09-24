//! The crate's one content digest.

use std::fmt;
use std::io::Read as _;
use std::path::Path;

use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use super::Error;

/// The width of a SHA-256 digest.
const LEN: usize = 32;

/// How much of a file is read at a time when digesting it.
const CHUNK: usize = 64 * 1024;

/// A SHA-256 digest of some content.
///
/// One digest type for the whole crate, one hash function, one rendering. It is
/// the digest of a target's bytes in a ledger entry, the name of a restore
/// snapshot, and the body of a fingerprint — deliberately the same type in all
/// three, so nothing has to explain which digest it means.
///
/// The name is not `Digest` because [`sha2::Digest`] is a trait that is in scope
/// wherever hashing happens, and two `Digest`s one `use` apart is a collision
/// waiting to be introduced.
///
/// # Encoding
///
/// It serialises as MessagePack's **native binary** type — a `bin` marker and 32
/// raw bytes — not as a 32-element array and not as hex. That is the reason
/// `CLAUDE.md` chose MessagePack over JSON for machine-owned state, so it is
/// worth the hand-written `Serialize`/`Deserialize` below: a derived impl on
/// `[u8; 32]` would emit an array and quietly cost a third of the file.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash([u8; LEN]);

impl ContentHash {
    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut out = [0_u8; LEN];
        out.copy_from_slice(&Sha256::digest(bytes));
        Self(out)
    }

    /// The digest of a file's contents, read in chunks rather than at once.
    ///
    /// # Errors
    ///
    /// [`Error::Read`] if the file cannot be opened or read.
    pub fn of_file(path: &Path) -> Result<Self, Error> {
        let fail = |source| Error::Read {
            path: path.to_path_buf(),
            source,
        };
        let mut file = std::fs::File::open(path).map_err(fail)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0_u8; CHUNK];
        loop {
            let read = file.read(&mut buf).map_err(fail)?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }
        let mut out = [0_u8; LEN];
        out.copy_from_slice(&hasher.finalize());
        Ok(Self(out))
    }

    /// The raw digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; LEN] {
        &self.0
    }

    /// The digest as 64 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(LEN * 2);
        for byte in self.0 {
            out.push(nibble(byte >> 4));
            out.push(nibble(byte & 0x0f));
        }
        out
    }

    /// Parse the form [`ContentHash::to_hex`] produces.
    ///
    /// Returns `None` for anything that is not exactly 64 hex digits, so a
    /// stray file in `restore/` cannot be mistaken for a snapshot.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != LEN * 2 {
            return None;
        }
        let mut out = [0_u8; LEN];
        let (pairs, rest) = text.as_bytes().as_chunks::<2>();
        debug_assert!(rest.is_empty(), "the length was checked above");
        for (byte, pair) in out.iter_mut().zip(pairs) {
            *byte = (unnibble(pair[0])? << 4) | unnibble(pair[1])?;
        }
        Some(Self(out))
    }
}

/// The lowercase hex character for the low four bits of `value`.
///
/// A table lookup rather than `char::from_digit(..).unwrap_or('0')`: the
/// callers only ever pass four bits, so the fallback was unreachable by
/// construction — which is another way of saying no test could reach it and a
/// mutant changing the character it produced survived the whole suite
/// (r4 round 1, COV7). Indexing a 16-entry table with four bits has no arm to
/// leave unreached.
fn nibble(value: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(value & 0x0f)])
}

/// The value of one lowercase-or-uppercase hex character.
///
/// Spelled out rather than `to_digit(16).and_then(|d| u8::try_from(d).ok())`,
/// whose `try_from` could not fail — `to_digit(16)` returns less than 16 — so
/// the `None` it would have produced was unreachable and unpinnable.
fn unnibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_hex())
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(ContentHashVisitor)
    }
}

/// Accepts exactly 32 bytes and nothing else.
///
/// No `visit_byte_buf` override. `deserialize_bytes` never dispatches to it —
/// serde's default forwards to [`Visitor::visit_bytes`], which is where the
/// length check lives — so an override was a second copy of nothing, reachable
/// through no decode path in the crate and pinnable by no test: a mutant
/// returning a zero digest from it survived the whole suite (r4 round 1,
/// COV7).
struct ContentHashVisitor;

impl Visitor<'_> for ContentHashVisitor {
    type Value = ContentHash;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a {LEN}-byte SHA-256 digest")
    }

    fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        let bytes: [u8; LEN] = value
            .try_into()
            .map_err(|_| E::invalid_length(value.len(), &self))?;
        Ok(ContentHash(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published SHA-256 vector for the empty input.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// The published SHA-256 vector for `"abc"`.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn a_content_hash_is_sha256_of_the_bytes() {
        assert_eq!(ContentHash::of(b"").to_hex(), EMPTY);
        assert_eq!(ContentHash::of(b"abc").to_hex(), ABC);
    }

    #[test]
    fn hashing_a_file_matches_hashing_its_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Larger than one read chunk, so the streaming path is actually taken.
        let body: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
        let path = dir.path().join("big");
        std::fs::write(&path, &body).expect("write");
        assert_eq!(
            ContentHash::of_file(&path).expect("hash"),
            ContentHash::of(&body),
        );
    }

    #[test]
    fn hashing_an_empty_file_matches_the_empty_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty");
        std::fs::write(&path, b"").expect("write");
        assert_eq!(ContentHash::of_file(&path).expect("hash").to_hex(), EMPTY);
    }

    #[test]
    fn hashing_a_missing_file_names_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nope");
        let err = ContentHash::of_file(&path).expect_err("must fail");
        assert!(err.to_string().contains("nope"), "got {err}");
    }

    #[test]
    fn a_content_hash_round_trips_through_hex() {
        let hash = ContentHash::of(b"round trip");
        assert_eq!(ContentHash::from_hex(&hash.to_hex()), Some(hash));
        assert_eq!(hash.to_string(), hash.to_hex());
        assert_eq!(hash.as_bytes().len(), LEN);
    }

    #[test]
    fn every_hex_character_is_the_one_chmod_and_ls_would_show() {
        // r4 round 1 (COV7): `nibble`'s fallback was unreachable by
        // construction, so a mutant changing the character it produced
        // survived the whole suite — and the digests the tests compare against
        // exercise only the sixteen characters between them by luck. Pin all
        // sixteen, in both directions.
        let bytes: [u8; LEN] = std::array::from_fn(|i| u8::try_from(i * 8 % 256).expect("a byte"));
        let hash = ContentHash::from_hex(&ContentHash(bytes).to_hex()).expect("round trip");
        assert_eq!(hash.as_bytes(), &bytes);
        assert_eq!(
            ContentHash(std::array::from_fn(
                |i| u8::try_from(i % 256).expect("a byte")
            ))
            .to_hex(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        // And uppercase parses to the same value, as `from_hex`'s doc says.
        let upper = ContentHash::of(b"case").to_hex().to_uppercase();
        assert_eq!(
            ContentHash::from_hex(&upper),
            Some(ContentHash::of(b"case"))
        );
    }

    #[test]
    fn a_digest_decodes_from_a_stream_as_well_as_a_slice() {
        // r4 round 1 (COV7): the crate decodes only from slices, so nothing
        // pinned what a stream does — including that the length check still
        // applies there. It reaches `visit_bytes` too, which is why the
        // `visit_byte_buf` override this visitor used to carry was unreachable
        // and has gone.
        let hash = ContentHash::of(b"owned");
        let encoded = rmp_serde::to_vec_named(&hash).expect("encode");
        assert_eq!(
            rmp_serde::from_read::<_, ContentHash>(encoded.as_slice()).expect("decode"),
            hash,
        );
        // And the length check holds on that path too.
        struct ShortBytes;
        impl Serialize for ShortBytes {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(b"too short")
            }
        }
        let short = rmp_serde::to_vec_named(&ShortBytes).expect("encode");
        assert!(rmp_serde::from_read::<_, ContentHash>(short.as_slice()).is_err());
    }

    #[test]
    fn an_invalid_hex_string_is_rejected() {
        let valid = ContentHash::of(b"x").to_hex();
        assert_eq!(ContentHash::from_hex(""), None);
        assert_eq!(ContentHash::from_hex(&valid[..62]), None);
        assert_eq!(ContentHash::from_hex(&format!("{valid}00")), None);
        let bad = format!("zz{}", &valid[2..]);
        assert_eq!(ContentHash::from_hex(&bad), None);
    }

    #[test]
    fn a_bad_low_nibble_after_a_good_high_one_is_rejected() {
        // r3 round 1 (C9): every earlier bad pair failed on its high nibble,
        // so the low nibble's check was never reached on its own.
        let low = format!("0z{}", "0".repeat(62));
        assert_eq!(ContentHash::from_hex(&low), None);
        let last = format!("{}0z", "0".repeat(62));
        assert_eq!(ContentHash::from_hex(&last), None);
    }

    #[test]
    fn hex_is_lowercase_but_uppercase_parses() {
        let hash = ContentHash::of(b"case");
        let upper = hash.to_hex().to_uppercase();
        assert_eq!(ContentHash::from_hex(&upper), Some(hash));
        assert!(hash.to_hex().chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn a_content_hash_serialises_as_messagepack_binary() {
        let encoded = rmp_serde::to_vec_named(&ContentHash::of(b"abc")).expect("encode");
        // 0xc4 is MessagePack's `bin 8`: one marker byte, one length byte, then
        // the 32 raw bytes. An array encoding would be 33 bytes of a different
        // shape, and would defeat the reason MessagePack was chosen.
        assert_eq!(encoded[0], 0xc4);
        assert_eq!(encoded[1], 32);
        assert_eq!(encoded.len(), 34);
        assert_eq!(&encoded[2..], ContentHash::of(b"abc").as_bytes());
    }

    #[test]
    fn a_content_hash_round_trips_through_messagepack() {
        let hash = ContentHash::of(b"payload");
        let encoded = rmp_serde::to_vec_named(&hash).expect("encode");
        let back: ContentHash = rmp_serde::from_slice(&encoded).expect("decode");
        assert_eq!(back, hash);
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused() {
        let encoded = rmp_serde::to_vec_named(&serde_bytes_stub(&[1, 2, 3])).expect("encode");
        let back: Result<ContentHash, _> = rmp_serde::from_slice(&encoded);
        assert!(back.is_err(), "a 3-byte digest must not decode");
    }

    /// A helper that serialises a byte slice the way a digest field would be
    /// written, so the length check has something wrong to reject.
    fn serde_bytes_stub(bytes: &[u8]) -> impl Serialize + '_ {
        struct Raw<'a>(&'a [u8]);
        impl Serialize for Raw<'_> {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(self.0)
            }
        }
        Raw(bytes)
    }

    #[test]
    fn the_expectation_message_names_the_width() {
        let encoded = rmp_serde::to_vec_named(&serde_bytes_stub(&[1, 2, 3])).expect("encode");
        let err = rmp_serde::from_slice::<ContentHash>(&encoded).expect_err("must fail");
        assert!(err.to_string().contains("32-byte"), "got {err}");
    }

    #[test]
    fn digests_order_by_their_bytes() {
        // r4 round 2 (COV3): this sorted the array and asserted it was sorted,
        // which holds for any total order — a reversed `Ord` included — so the
        // impl was executed and constrained by nothing. The expected
        // permutation is asserted instead, against the digests' own bytes.
        let (a, b, c) = (
            ContentHash::of(b"a"),
            ContentHash::of(b"b"),
            ContentHash::of(b"c"),
        );
        // SHA-256 of "a", "b" and "c" begin 0xca, 0x3e and 0x2e: by their
        // bytes the order is c, then b, then a — which is neither the input
        // order nor its reverse, so a mutant flipping the comparison fails.
        assert_eq!(a.as_bytes()[0], 0xca);
        assert_eq!(b.as_bytes()[0], 0x3e);
        assert_eq!(c.as_bytes()[0], 0x2e);

        let mut all = [c, a, b];
        all.sort_unstable();
        assert_eq!(all, [c, b, a]);
        assert!(format!("{:?}", all[0]).starts_with("ContentHash("));
    }
}
