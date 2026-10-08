//! The bytes on disk: a header naming the format and the session's nonce,
//! then length-prefixed, checksummed frames, each holding one [`Record`].

use std::fs::File;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::Error;
use crate::fs::Mode;
use crate::paths::Portable;
use crate::state::{ContentHash, Mechanism, Prior};

/// The seven bytes every journal starts with.
pub(super) const MAGIC: &[u8; 7] = b"BXJRNL\0";

/// The newest journal format this build writes and understands.
pub(super) const FORMAT: u8 = 1;

/// The width of the per-session nonce every frame's checksum covers.
pub(super) const NONCE: usize = 16;

/// The header's width: [`MAGIC`], one version byte, and the session's nonce.
pub(super) const HEADER: usize = MAGIC.len() + 1 + NONCE;

/// The width of a frame's checksum. See the [`crate::journal`] documentation.
const CHECK: usize = 4;

/// The widest frame body that will be written or read.
///
/// A bound, not a budget: it is what stops four bytes of garbage from asking for
/// a gigabyte allocation. Records hold digests, modes and paths, never file
/// content, so the largest legitimate frame is a [`Begin`] naming every target
/// in the run.
pub(super) const MAX_FRAME: usize = 16 * 1024 * 1024;

/// What a session is for.
///
/// Reporting only: recovery behaves identically for both, and reads only the
/// [`Intent`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKind {
    /// `apply`, `sync`, `init`, `add` — bx writing what the config declares.
    Apply,
    /// `rm` — bx putting back what it displaced.
    Restore,
}

impl std::fmt::Display for SessionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Apply => "apply",
            Self::Restore => "restore",
        })
    }
}

/// One frame of the journal.
///
/// Every variant carries a struct payload, so a record always encodes as a
/// container and no single scalar byte can decode as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Record {
    /// The session opened.
    Begin(Begin),
    /// A write is about to be published.
    Intent(Intent),
    /// A write was published.
    Done(Done),
    /// Every write in the session was published. Only the bookkeeping may be
    /// outstanding.
    End(End),
}

/// The session header, always the first frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Begin {
    /// What the session is for.
    pub kind: SessionKind,
    /// The home directory the session's paths were rendered against.
    pub home: PathBuf,
    /// What the session may touch.
    ///
    /// **Reporting-only, but load-bearing.** Recovery never consults it to
    /// decide what is undone — the [`Intent`] records alone do that — so a
    /// caller may pass the announced pending set or the whole resolved target
    /// list as a superset and recovery behaves identically either way. An
    /// under-set is a reporting inaccuracy, not a safety defect.
    ///
    /// What it is *not* is free-form. `load::refusal` puts every entry through
    /// [`Portable::check_against`] with the header's home, and one entry that
    /// fails makes the whole journal unreadable — so a session that wrote an
    /// unportable scope entry could never be rolled back.
    /// [`Session::open_locked`](super::Session::open_locked) therefore refuses the same entries the loader
    /// refuses, before the journal exists: see `r3 round 3` decision R3R3-1.
    pub scope: Vec<Portable>,
}

/// What the destination holds after a write.
///
/// The counterpart of [`Prior`], which is what it held before. Two named states
/// rather than an `Option`, for the same reason [`Prior::Absent`] is a variant:
/// "there is no file" and "there is an empty file" need opposite undos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Written {
    /// No file. A removal — the `bx rm` half.
    Absent,
    /// These bytes at this mode.
    Present {
        /// The digest of the bytes the write leaves behind.
        digest: ContentHash,
        /// The mode it leaves them at.
        mode: Mode,
    },
}

/// One write, recorded durably before it is made.
///
/// The load-bearing shape is `before`/`after`: an intent states the two states
/// the destination is permitted to be in and the digest of each, so recovery is
/// one function — *make the destination equal `before`* — and finds anything
/// else in the way without having to guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// The target, home-relative. The ledger's key.
    pub target: Portable,
    /// The destination, rendered absolute, so recovery needs no configuration.
    pub dest: PathBuf,
    /// The staging path [`crate::fs::temp_beside`] chose before the write
    /// staged anything, or `None` for a removal. It may not exist: a session
    /// stopped between this Intent and the stage never made it.
    ///
    /// Recorded rather than recomputed: recovery unlinks the one path the
    /// journal names and can therefore never remove a file bx cannot prove it
    /// created. A journal whose temporary file is not a `.bx-` file beside
    /// `dest` is not believed at all. Deleting by pattern in a directory the user owns is the wrong
    /// default for a tool whose first invariant is never to destroy a byte the
    /// user wrote.
    pub temp: Option<PathBuf>,
    /// What the destination held before, and where those bytes now live.
    pub before: Prior,
    /// What the write leaves there.
    pub after: Written,
    /// Parent directories this write invents, deepest first — the order a
    /// reversal removes them in. Named before they are made, so one may not
    /// exist yet; a reversal removes each only where it stands empty.
    pub created_dirs: Vec<PathBuf>,
    /// How bx attached to the target, or `None` when the session is *releasing*
    /// it: the restore half of `bx rm` leaves nothing for bx to own.
    pub mechanism: Option<Mechanism>,
    /// What the saved ledger said bx last wrote to this target when the intent
    /// was made, or `None` when bx did not own it.
    ///
    /// The one fact a terminated journal cannot otherwise tell recovery: whether
    /// the ledger save in [`Session::finish`](super::Session::finish) happened before the process died.
    /// A save that happened leaves the target recorded at [`Intent::after`]; one
    /// that did not leaves it at this digest. Recovery rebuilds only the second,
    /// because re-recording the first hands the ledger bx's own earlier output
    /// as if a third party had written it. See [`crate::recover`].
    pub ledger_written: Option<ContentHash>,
    /// Whether the destination is a directory rather than a file.
    ///
    /// A directory has no bytes, so its two states are told apart by mode
    /// alone: [`Intent::before`] and [`Intent::after`] name it with the digest
    /// of [`DIR_BYTES`](crate::state::DIR_BYTES), and recovery compares a directory found there by its
    /// mode. A directory intent has no temporary file, and its
    /// [`Intent::created_dirs`] are the parents it invented, never the
    /// directory itself: [`Intent::creates`] says whether that was invented
    /// too. `false` for every intent a journal written before directory
    /// targets holds.
    #[serde(default)]
    pub dir: bool,
    /// Whether the destination is a symlink rather than a file.
    ///
    /// A link's content is its text, so [`Intent::before`] and
    /// [`Intent::after`] name it by the digest of that text at
    /// [`crate::fs::Mode::LINK`], and a `before` that existed is a link whose
    /// text is stored under `restore/` like a file's bytes. Recovery compares a
    /// link found there by its text, and puts an earlier one back as a link.
    /// Never set with [`Intent::dir`]. `false` for every intent a journal
    /// written before symlink targets holds.
    ///
    /// A bx that predates this field reads a link intent as a file's, finds a
    /// symlink where it expects a file, and blocks the rollback rather than
    /// acting on it.
    #[serde(default)]
    pub link: bool,
}

impl Intent {
    /// Whether this write creates a destination that did not exist.
    #[must_use]
    pub const fn creates(&self) -> bool {
        matches!(self.before, Prior::Absent)
    }
}

/// A write that was published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Done {
    /// Which one.
    pub target: Portable,
}

/// The session's writes all landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct End {
    /// How many.
    pub written: usize,
}

/// Why there is no whole record at an offset.
pub(super) enum Damage {
    /// The bytes stop before the frame does: a write a crash cut short, or a
    /// length that was damaged.
    Torn,
    /// The frame is all there, and it is not what bx wrote: its checksum or its
    /// decoding fails, or its length is past the bound.
    Invalid,
}

/// Decode the frame at `at`: a little-endian `u32` length, a [`CHECK`]-byte
/// checksum under the session's `nonce`, and a MessagePack body of that length.
pub(super) fn frame(
    bytes: &[u8],
    at: usize,
    nonce: &[u8; NONCE],
) -> Result<(Record, usize), Damage> {
    let prefix_end = at.checked_add(size_of::<u32>()).ok_or(Damage::Invalid)?;
    let body_start = prefix_end.checked_add(CHECK).ok_or(Damage::Invalid)?;
    let prefix: [u8; 4] = bytes
        .get(at..prefix_end)
        .ok_or(Damage::Torn)?
        .try_into()
        .map_err(|_| Damage::Torn)?;
    let sum = bytes.get(prefix_end..body_start).ok_or(Damage::Torn)?;
    let len = usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| Damage::Invalid)?;
    // Past the bound is garbage however many bytes follow, and is what stops four
    // bytes of garbage asking for a gigabyte.
    //
    // Zero is refused here rather than left to the checksum, and that is a cost
    // rule, not a correctness one: an empty body's checksum is not four NUL
    // bytes and an empty slice never decodes, so a zero length was already
    // `Invalid` twice over. But both of those refusals come *after*
    // `checksum`, and a zero length is the one length every offset of a
    // zero-filled tail carries, so `whole_frame_after` would hash once per
    // byte — a SHA-256 per byte of a power-loss tail, on the lock-free path
    // every read-only command takes. A record body is never empty: every
    // `Record` variant encodes at least a MessagePack tag.
    // `a_run_of_nul_bytes_is_not_a_valid_frame` pins the verdict and
    // `a_zero_length_frame_is_refused_before_its_checksum_is_taken` pins that
    // it is reached without hashing.
    if len == 0 || len > MAX_FRAME {
        return Err(Damage::Invalid);
    }
    let end = body_start.checked_add(len).ok_or(Damage::Invalid)?;
    let body = bytes.get(body_start..end).ok_or(Damage::Torn)?;
    if checksum(nonce, prefix, body).as_slice() != sum {
        return Err(Damage::Invalid);
    }
    let record = rmp_serde::from_slice::<Record>(body).map_err(|_| Damage::Invalid)?;
    Ok((record, end))
}

/// Whether a whole frame of this session — checksum under its `nonce` and
/// decoding both good — starts anywhere after `at`.
///
/// Every offset is tried, because the damaged frame's own length cannot be
/// trusted to say where the next one starts. An offset hashes only when its
/// four length bytes read as a non-zero length that is both within
/// [`MAX_FRAME`] and inside the file — every other offset is refused by
/// [`frame`]'s comparisons alone. A zero-filled tail therefore hashes not at
/// all (zero is refused), and a random tail hashes at about one offset in 256
/// for a journal large enough for the length to fit; only bytes crafted to be
/// all plausible lengths hash much, and a journal is not a file anyone else
/// writes.
///
/// A whole frame an earlier journal left in reused blocks fails here, because
/// its checksum was taken under that journal's nonce.
pub(super) fn whole_frame_after(bytes: &[u8], at: usize, nonce: &[u8; NONCE]) -> bool {
    (at + 1..bytes.len()).any(|start| frame(bytes, start, nonce).is_ok())
}

#[cfg(test)]
thread_local! {
    /// How many times this thread has taken a frame [`checksum`], so a test
    /// can pin that scanning a zero-filled tail does not hash once per byte.
    /// Thread-local rather than global so that a parallel suite cannot make
    /// one test's count another's.
    pub(crate) static CHECKSUMS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The checksum a frame carries: the first [`CHECK`] bytes of the SHA-256 of
/// the session's nonce, the frame's length prefix, and its body.
fn checksum(nonce: &[u8; NONCE], prefix: [u8; 4], body: &[u8]) -> [u8; CHECK] {
    #[cfg(test)]
    CHECKSUMS.with(|taken| taken.set(taken.get() + 1));
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(nonce);
    hasher.update(prefix);
    hasher.update(body);
    let mut sum = [0; CHECK];
    sum.copy_from_slice(&hasher.finalize()[..CHECK]);
    sum
}

/// One record as a frame: its length as a little-endian `u32`, its checksum
/// under the session's `nonce`, then its MessagePack encoding.
pub(super) fn encode(record: &Record, nonce: &[u8; NONCE]) -> Result<Vec<u8>, Error> {
    let payload = rmp_serde::to_vec_named(record).map_err(|source| Error::Encode { source })?;
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_FRAME)
        .ok_or(Error::FrameTooLarge { len: payload.len() })?;
    let prefix = len.to_le_bytes();
    let mut frame = Vec::with_capacity(size_of::<u32>() + CHECK + payload.len());
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&checksum(nonce, prefix, &payload));
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// A nonce no other journal is expected to share.
///
/// It guards against damage, not an adversary, so it needs to differ between
/// sessions, not to be secret. The kernel's random bytes are the source; the
/// process's own hash seed, its id, a per-process counter and the clock are
/// mixed in too, so a system without `/dev/urandom` still gets a nonce that
/// differs from every earlier session's, and creating a journal never fails
/// for want of one. The journal is machine state that exists only while a
/// session is in flight, so a value that differs per run breaks no
/// byte-identical output.
pub(super) fn fresh_nonce() -> [u8; NONCE] {
    use sha2::Digest as _;
    use std::hash::BuildHasher as _;
    use std::io::Read as _;

    static SESSIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut hasher = sha2::Sha256::new();
    let mut random = [0_u8; 32];
    if File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .is_ok()
    {
        hasher.update(random);
    }
    let count = SESSIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    hasher.update(
        std::collections::hash_map::RandomState::new()
            .hash_one(count)
            .to_le_bytes(),
    );
    hasher.update(count.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        hasher.update(now.as_nanos().to_le_bytes());
    }
    let mut nonce = [0; NONCE];
    nonce.copy_from_slice(&hasher.finalize()[..NONCE]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::journal::tests::{frame_starts, nonce_of, some_begin};
    use crate::journal::{Journal, Loaded, load};

    #[test]
    fn a_record_round_trips_through_a_frame() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let begin = Begin {
            kind: SessionKind::Restore,
            home: PathBuf::from("/home/someone"),
            scope: vec![Portable::try_from("~/.bashrc".to_string()).expect("portable")],
        };
        let done = Record::Done(Done {
            target: Portable::try_from("~/.bashrc".to_string()).expect("portable"),
        });

        let mut journal = Journal::create(&path, begin.clone()).expect("create");
        journal.append(&done).expect("append");
        drop(journal);

        let loaded = load(&path).expect("load");
        assert_eq!(
            loaded,
            Loaded::Unterminated(vec![Record::Begin(begin), done])
        );
    }

    #[test]
    fn a_zero_length_frame_is_refused_before_its_checksum_is_taken() {
        // r3 round 3, D3. A zero length passes the `MAX_FRAME` bound, and an
        // empty body is always inside the file, so without the `len == 0`
        // refusal `frame` reaches `checksum` at every offset of a zero-filled
        // tail: one SHA-256 per byte, on the lock-free path every read-only
        // command takes. The verdict is the same either way, so only the cost
        // can be pinned.
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT);
        let nonce = fresh_nonce();
        bytes.extend_from_slice(&nonce);
        bytes.extend(encode(&Record::Begin(some_begin()), &nonce).expect("encode"));
        let tail = 64 * 1024;
        bytes.extend(std::iter::repeat_n(0_u8, tail));

        let before = CHECKSUMS.with(std::cell::Cell::get);
        assert!(
            !whole_frame_after(&bytes, HEADER, &nonce),
            "a zero-filled tail holds no whole frame",
        );
        let taken = CHECKSUMS.with(std::cell::Cell::get) - before;
        // Scanning the tail must not hash per byte. The header and the one
        // whole Begin frame are the only offsets that can carry a plausible
        // length here, so the bound is generous and still far below `tail`.
        assert!(
            taken < tail / 64,
            "scanning {tail} zero bytes took {taken} checksums",
        );
    }

    #[test]
    fn every_frame_carries_a_checksum_of_its_nonce_length_and_body() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        drop(Journal::create(&path, some_begin()).expect("create"));
        let bytes = std::fs::read(&path).expect("read");
        let nonce = nonce_of(&bytes);

        let prefix: [u8; 4] = bytes[HEADER..HEADER + 4].try_into().expect("a length");
        let body = &bytes[HEADER + 4 + CHECK..];
        assert_eq!(
            usize::try_from(u32::from_le_bytes(prefix)).expect("small"),
            body.len()
        );
        assert_eq!(
            &bytes[HEADER + 4..HEADER + 4 + CHECK],
            checksum(&nonce, prefix, body)
        );
        let mut whole = [0; 32];
        whole.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(
            [nonce.as_slice(), prefix.as_slice(), body].concat(),
        ));
        assert_eq!(checksum(&nonce, prefix, body), whole[..CHECK]);
        assert_ne!(
            nonce,
            nonce_of(&{
                drop(Journal::create(&path, some_begin()).expect("create again"));
                std::fs::read(&path).expect("read")
            }),
            "a second session over the same header draws a different nonce",
        );
    }

    #[test]
    fn a_frame_copied_from_another_sessions_journal_does_not_validate() {
        // Review round 5, item 3. Two sessions with the same header wrote
        // byte-identical frames, so a frame from one validated in the other.
        let dir = tempfile::tempdir().expect("a tempdir");
        let (one, two) = (dir.path().join("one.mpk"), dir.path().join("two.mpk"));
        let done = Record::Done(Done {
            target: Portable::try_from("~/.a".to_string()).expect("portable"),
        });
        let mut journal = Journal::create(&one, some_begin()).expect("create");
        journal.append(&done).expect("append");
        drop(journal);
        drop(Journal::create(&two, some_begin()).expect("create"));

        let from_one = std::fs::read(&one).expect("read");
        assert_eq!(
            load(&one).expect("load"),
            Loaded::Unterminated(vec![Record::Begin(some_begin()), done]),
        );
        let copied = &from_one[frame_starts(&from_one)[1]..];
        let mut bytes = std::fs::read(&two).expect("read");
        bytes.extend_from_slice(copied);
        std::fs::write(&two, &bytes).expect("write");
        assert_eq!(
            load(&two).expect("load"),
            Loaded::Torn {
                records: vec![Record::Begin(some_begin())],
                discarded: copied.len(),
            },
        );
    }

    #[test]
    fn a_frame_length_is_bounded_at_max_frame_inclusive() {
        // Coverage review round 5, item 5.
        let nonce = [7; NONCE];
        let prefix = |len: usize| {
            let mut bytes = u32::try_from(len).expect("fits").to_le_bytes().to_vec();
            bytes.extend_from_slice(&[0; CHECK]);
            bytes
        };
        assert!(
            matches!(
                frame(&prefix(MAX_FRAME + 1), 0, &nonce),
                Err(Damage::Invalid)
            ),
            "past the bound is garbage however many bytes follow",
        );
        assert!(
            matches!(frame(&prefix(MAX_FRAME), 0, &nonce), Err(Damage::Torn)),
            "at the bound it is a length, and the body is missing",
        );
    }

    #[test]
    fn the_search_for_a_whole_frame_after_damage_starts_past_the_damaged_frame() {
        // Coverage review round 5, item 6.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut journal = Journal::create(&path, some_begin()).expect("create");
        journal
            .append(&Record::Done(Done {
                target: Portable::try_from("~/.a".to_string()).expect("portable"),
            }))
            .expect("append");
        drop(journal);
        let bytes = std::fs::read(&path).expect("read");
        let nonce = nonce_of(&bytes);
        let last = frame_starts(&bytes)[1];

        assert!(
            frame(&bytes, last, &nonce).is_ok(),
            "a whole frame starts exactly there"
        );
        assert!(
            !whole_frame_after(&bytes, last, &nonce),
            "the frame at the damage is not after it"
        );
        assert!(
            whole_frame_after(&bytes, last - 1, &nonce),
            "one byte earlier, it is"
        );
    }
}
