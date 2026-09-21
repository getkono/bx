//! The write-ahead journal, and the session every write bx makes goes through.
//!
//! `CLAUDE.md` Invariant 4 has two halves: every write is recorded with the
//! prior bytes, so `rm` restores exactly, and **an interrupted `apply` must be
//! detectable and recoverable**. This module is the second half's foundation —
//! [`crate::recover`] is the detection and the undo, [`crate::restore`] is the
//! `rm` path, and both read what is written here.
//!
//! # The ordering, which is the whole point
//!
//! [`Session::apply`] is the only place a byte reaches a user's filesystem, and
//! the sequence is fixed:
//!
//! 1. [`crate::fs::stage`] makes a temporary file in the destination directory,
//!    at the final mode, with no content. The destination is untouched. It is
//!    staged against the [`crate::fs::Observed`] the request's plan compared, so
//!    a destination that changed since plan is refused here, before anything is
//!    stored, announced or published.
//! 2. [`crate::fs::Staged::fill`] writes the content and `fsync`s it. The
//!    destination is still untouched.
//! 3. the **prior** bytes are copied into `restore/` and `fsync`ed, so the
//!    bytes a rollback needs are durable before anything can displace them.
//! 4. the [`Intent`] frame is appended and `fsync`ed.
//! 5. **only then** [`crate::fs::Filled::publish`] renames the temporary file
//!    into place and `fsync`s the directory.
//! 6. the in-memory ledger is told — only now, so a publish that fails leaves no
//!    record of a write that never happened.
//! 7. a [`Done`] frame is appended and `fsync`ed.
//!
//! At every instant `journal.mpk` either does not exist — no session is in
//! flight — or describes, durably, a superset of the destinations that may have
//! been touched. The window between "the intent is durable" and "the destination
//! is touched" is one `fsync` return: before it the destination is untouched,
//! after it the intent is recoverable. A tail frame lost to a crash is therefore
//! always safe to discard, which is what makes [`load`] correct: if the frame's
//! `fsync` had returned, the frame is on disk; if it had not, the write it
//! announces had not begun.
//!
//! That holds for a tail frame that stops short, and for one that is all there
//! but fails its checksum, which is what a power loss that zero-fills unsynced
//! bytes leaves: with no whole frame after it, it is the tail, and it is
//! discarded the same way. A damaged frame with a whole frame after it is not a
//! tail, and the journal is not believed.
//!
//! Safe to discard is not safe to forget. Bytes that stop short of a whole frame
//! are also what a damaged length looks like, and that would hide every frame
//! after it, so a journal [`load`] discarded anything from is [`Loaded::Torn`],
//! and recovery sets it aside rather than unlinking it.
//!
//! # The on-disk ledger does not move until the session ends
//!
//! [`crate::state::Ledger::record`] only mutates the ledger in memory, and
//! [`Session::finish`] is the sole caller of [`crate::state::Ledger::save`]. So
//! for a session's whole life the *saved* ledger still describes the state the
//! destinations are being rolled back to, and a rollback has no bookkeeping to
//! repair. The one window left is between the [`End`] frame and the save, and
//! [`crate::recover`] closes it by rebuilding the entries from the journal's own
//! intents.
//!
//! # The rollback snapshot is not the ledger's snapshot
//!
//! The ledger keeps the **first** prior it was ever given for a target, because
//! what `bx rm` owes the user is the file as it was before bx ever touched it. A
//! rollback owes them something else: whatever was on disk a moment ago, which
//! for a target bx already manages is bx's own previous output. So the session
//! stores the snapshot recovery needs itself — see [`store_prior`] — and the
//! two never contend. Both are content-addressed under the same
//! `restore/<digest>` name, so identical bytes are one file.
//!
//! # Why explicit framing on top of MessagePack
//!
//! MessagePack self-delimits a *single* value, which is all the ledger and the
//! fingerprint cache need. A log needs one thing more: the loader has to tell
//! "clean end of log" from "final record torn by a crash", and it has to do so
//! from data the format guarantees rather than from a decoder's error kind. So
//! every record is preceded by its length as a little-endian `u32`:
//! classification becomes an arithmetic comparison, the truncate-at-every-offset
//! test is exact rather than probabilistic, and a run of NUL bytes left by a
//! filesystem cannot decode as a record.
//!
//! A length tells a torn frame from a whole one. It cannot tell a whole frame
//! from a damaged one, and a byte flipped inside a MessagePack body usually
//! still decodes — as a different mode, digest or path, which a rollback would
//! then act on. So each frame also carries a checksum between its length and
//! its body: the first four bytes of the SHA-256 of both. SHA-256 because the
//! restore store already hashes with it, so nothing is added to the build; four
//! bytes because it guards against damage, where a one-in-four-billion miss is
//! enough. A journal written to mislead is refused by what it says, not by how
//! it is framed.
//!
//! A checksum of the frame alone would validate a frame from any journal, and
//! after a power loss the unsynced tail of this one can hold blocks of an
//! earlier, deleted one. So every journal's header carries a nonce chosen when
//! the session opens, and the hash covers it too: a frame another session wrote
//! never validates here, so a stale frame in a damaged tail cannot pass for a
//! whole frame bx wrote after the damage.
//!
//! A journal in a *newer* format is not damage at all. It is refused as
//! [`Error::FutureVersion`], and nothing is rolled back or set aside, because
//! only the bx that wrote it can recover it.
//!
//! # Created through [`crate::fs::atomic`], appended to in place
//!
//! A journal comes into existence whole. Its header and its [`Begin`] frame are
//! written to a temporary file in the state directory, `fsync`ed, and renamed
//! into place by [`crate::fs::write_atomically`], like every other file bx
//! writes. No reader ever sees a journal that is empty or half a header, which
//! matters because [`crate::recover::pending`] reads it without the lock while a
//! session may be starting. A crash before the rename leaves a `.bx-` temporary
//! file in the state directory — bx's own directory, holding no byte of the
//! user's — and no journal.
//!
//! After that a write-ahead log cannot go through a rename: it is *appended* to
//! and `fsync`ed in place, and replacing it would discard the frames it exists to
//! keep. It is appended to with one `write` call per frame so a torn frame can
//! only ever be the file's last bytes, and unlinked — last of all — when the
//! session ends.
//!
//! # A failed write ends the session
//!
//! The first write in a session that returns an error *poisons* it: every later
//! [`Session::apply`] and [`Session::finish`] is refused, so the journal stays
//! for recovery to roll back. A failed append may have left a torn frame at the
//! tail, and a frame appended after it would make the journal unreadable to
//! [`load`] — an Intent recovery could never act on. A failed publish leaves an Intent with no
//! Done, which an `End` frame and a ledger save would close out as though it
//! had landed.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs::{self, Mode, Observed};
use crate::paths::Portable;
use crate::state::{
    ContentHash, ExclusiveLock, Ledger, LedgerView, Mechanism, NewEntry, Prior, PriorBytes,
    RestoreRef, StateDir,
};

/// The seven bytes every journal starts with.
const MAGIC: &[u8; 7] = b"BXJRNL\0";

/// The newest journal format this build writes and understands.
const FORMAT: u8 = 1;

/// The width of the per-session nonce every frame's checksum covers.
const NONCE: usize = 16;

/// The header's width: [`MAGIC`], one version byte, and the session's nonce.
const HEADER: usize = MAGIC.len() + 1 + NONCE;

/// The width of a frame's checksum. See the module documentation.
const CHECK: usize = 4;

/// The widest frame body that will be written or read.
///
/// A bound, not a budget: it is what stops four bytes of garbage from asking for
/// a gigabyte allocation. Records hold digests, modes and paths, never file
/// content, so the largest legitimate frame is a [`Begin`] naming every target
/// in the run.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Everything that can go wrong journalling a write.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A read, write, `fsync` or `unlink` of the journal itself failed.
    #[error("journalling to {}: {source}", .path.display())]
    Io {
        /// The path the failure is about.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A record could not be encoded. Only reachable for a value that cannot
    /// round-trip — a non-UTF-8 path — which is a condition, not a bug.
    #[error("encoding a journal record: {source}")]
    Encode {
        /// The underlying failure.
        #[source]
        source: rmp_serde::encode::Error,
    },
    /// A record encoded to more than [`MAX_FRAME`] bytes.
    #[error("a journal record of {len} bytes exceeds the {MAX_FRAME}-byte frame limit")]
    FrameTooLarge {
        /// How big it was.
        len: usize,
    },
    /// The journal was written in a newer format than this build understands.
    ///
    /// Not damage: the likeliest cause is an older bx run after a newer one was
    /// interrupted, and the journal is intact in a format this build cannot
    /// read. Setting it aside would discard the rollback only the newer bx can
    /// make, so it is refused wherever it is read: nothing is rolled back, set
    /// aside or changed.
    #[error(
        "{} was written by a newer bx: it is journal format {found}, and this bx understands \
         up to {supported}. Nothing was rolled back, set aside or changed; run a bx at least as \
         new as the one that wrote it",
        .path.display()
    )]
    FutureVersion {
        /// The journal.
        path: PathBuf,
        /// The format byte on disk.
        found: u8,
        /// The newest format this build understands.
        supported: u8,
    },
    /// A journal bx cannot believe could not be moved aside.
    ///
    /// Refused rather than read as absent: a session opened over it creates
    /// its own journal by renaming over these bytes, and a recovery that went
    /// on would clear the way for one. The bytes are left exactly where they
    /// are, and every writing command refuses until they can be moved.
    ///
    /// It is the journal's counterpart of
    /// [`crate::state::Error::CannotQuarantine`], which stops bx the same way
    /// for a damaged ledger or fingerprint store: both are the one
    /// `state::move_aside` failing, for the same causes — a state
    /// directory bx cannot write, or a path with no room for the `.corrupt`
    /// suffix — and neither renames, resets or writes anything.
    #[error(
        "the write-ahead journal {} cannot be read and could not be set aside ({source}); \
         it was left in place, and bx will not write until it can be moved",
        .path.display()
    )]
    CannotSetAside {
        /// The journal.
        path: PathBuf,
        /// Why it could not be moved.
        #[source]
        source: std::io::Error,
    },
    /// What stands at the journal's path is not a regular file: a FIFO, a
    /// device, a socket, a directory, or a symlink, dangling or not.
    ///
    /// Refused before anything opens it. Reading a FIFO blocks until
    /// something writes to it, and a device such as `/dev/zero` never ends,
    /// so every command that looks for an interrupted session would hang —
    /// and no session writes one: [`Journal::create`] renames a regular file
    /// into place. It is left exactly where it is, never set aside by a
    /// recovery, and [`crate::recover::abandon`] moves it aside.
    #[error(
        "the write-ahead journal {} is {kind}; bx reads a journal only from a regular file, \
         so it did not open it, and will not write until it is moved",
        .path.display()
    )]
    NotAJournal {
        /// The journal's path.
        path: PathBuf,
        /// What is there instead.
        kind: crate::fs::Kind,
    },
    /// A session was asked to start while an unresolved interruption stands.
    ///
    /// The escape is [`crate::recover::recover`], which every writing command
    /// runs first, or [`crate::recover::abandon`] when recovery is blocked.
    #[error(
        "an interrupted bx session is still recorded in {}; \
         it must be recovered before anything else is written",
        .path.display()
    )]
    InProgress {
        /// The journal that stands.
        path: PathBuf,
    },
    /// A write in this session already failed, so the session may neither
    /// write again nor finish.
    #[error(
        "an earlier write in this bx session failed; the session cannot go on, \
         and {} is left for recovery to roll back",
        .path.display()
    )]
    Poisoned {
        /// The journal that records the session.
        path: PathBuf,
    },
    /// A request's destination is not where its target renders against the
    /// session's home.
    ///
    /// Refused because a journal recording it could never be believed: recovery
    /// acts only on a destination that is exactly its target's.
    #[error(
        "bx will not write {} for {}, which renders to {}",
        .dest.display(),
        .target.as_str(),
        .rendered.display()
    )]
    Misplaced {
        /// The target the request named.
        target: Portable,
        /// The destination it asked for.
        dest: PathBuf,
        /// Where the target renders.
        rendered: PathBuf,
    },
    /// A session was asked to write a target it has already written.
    ///
    /// One write per target per session is what lets a report judge each
    /// [`Intent`] against the destination on its own while a rollback undoes
    /// them in reverse: with two, the report compares the destination against
    /// the first write's states after the second has replaced them.
    #[error(
        "{} was already written in this bx session, and a session writes a target once",
        .target.as_str()
    )]
    Repeated {
        /// The target written twice.
        target: Portable,
    },
    /// A removal named, as a directory bx created for its target, a path that
    /// is not a parent of the target's destination below the home.
    ///
    /// Refused because the journal recording it could never be believed —
    /// [`load`] applies the same rule — and because pruning it could remove a
    /// directory that is not bx's. Nothing is observed, stored or touched.
    #[error(
        "bx will not remove {} for {}: it is not a parent directory of the target below the home",
        .dir.display(),
        .target.as_str()
    )]
    StrayCreatedDir {
        /// The target the removal named.
        target: Portable,
        /// The directory it named.
        dir: PathBuf,
    },
    /// The state directory failed.
    #[error(transparent)]
    State(#[from] crate::state::Error),
    /// A destination could not be written.
    #[error(transparent)]
    Write(#[from] crate::fs::Error),
}

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
    /// What it is *not* is free-form. [`refusal`] puts every entry through
    /// [`Portable::check_against`] with the header's home, and one entry that
    /// fails makes the whole journal unreadable — so a session that wrote an
    /// unportable scope entry could never be rolled back.
    /// [`Session::open_locked`] therefore refuses the same entries the loader
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
    /// The staging path [`crate::fs::stage`] chose, or `None` for a removal.
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
    /// Parent directories this write invented, deepest first — the order a
    /// reversal removes them in.
    pub created_dirs: Vec<PathBuf>,
    /// How bx attached to the target, or `None` when the session is *releasing*
    /// it: the restore half of `bx rm` leaves nothing for bx to own.
    pub mechanism: Option<Mechanism>,
    /// What the saved ledger said bx last wrote to this target when the intent
    /// was made, or `None` when bx did not own it.
    ///
    /// The one fact a terminated journal cannot otherwise tell recovery: whether
    /// the ledger save in [`Session::finish`] happened before the process died.
    /// A save that happened leaves the target recorded at [`Intent::after`]; one
    /// that did not leaves it at this digest. Recovery rebuilds only the second,
    /// because re-recording the first hands the ledger bx's own earlier output
    /// as if a third party had written it. See [`crate::recover`].
    pub ledger_written: Option<ContentHash>,
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

/// What was found at a journal's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// There is no journal: no session is in flight.
    Absent,
    /// The journal ends with [`End`], so every write in it was published and
    /// only the ledger may be behind.
    Terminated(Vec<Record>),
    /// The journal has no [`End`]: the session was interrupted.
    Unterminated(Vec<Record>),
    /// The journal has no [`End`], and ends in bytes that are not a whole
    /// frame, with no whole frame after them: the session was interrupted while
    /// it appended one. The bytes either stop short of a frame, as a killed
    /// process leaves them, or fail their checksum, as a power loss that
    /// zero-fills an unsynced tail leaves them.
    ///
    /// The whole frames before them are what [`Loaded::Unterminated`] would
    /// hold, and recovery rolls them back the same way. The difference is what
    /// becomes of the file. A frame a crash tore announces a write that had not
    /// begun, but bytes that stop short are also what a damaged length looks
    /// like, and that would hide every frame after it. So once recovery is done
    /// with a journal it discarded anything from, it sets the file aside rather
    /// than unlinking it.
    Torn {
        /// The whole frames, in the order they were written.
        records: Vec<Record>,
        /// How many bytes after them were not a whole frame.
        discarded: usize,
    },
    /// The bytes are not a journal a bx session could have written: a wrong
    /// header or an older format, a first frame that is not whole, a later frame whose
    /// checksum or decoding fails with a whole frame after it, bytes after its
    /// [`End`], or a record that stores a path its session could not have
    /// written. See [`load`].
    ///
    /// It is not believed, so recovery rolls nothing back and a session opens
    /// over it as over [`Loaded::Absent`]; [`crate::recover::pending`] still
    /// reports it, so a read-only command does not hide it. [`load_exclusive`]
    /// moves the bytes aside — never deletes them, and never over a journal set
    /// aside earlier — and [`load`], which runs without the lock, leaves them
    /// where they are. What the write may have completed is then recomputed by
    /// `plan`, which reports a file bx wrote but never recorded as a conflict:
    /// skipped, never overwritten. A journal [`load_exclusive`] cannot move
    /// aside is never this value, but [`Error::CannotSetAside`].
    Unreadable {
        /// Where the bytes were kept, or `None` if they were not moved because
        /// the read held no lock.
        moved_to: Option<PathBuf>,
    },
}

impl Loaded {
    /// Every [`Intent`], in the order it was written.
    pub fn intents(&self) -> impl DoubleEndedIterator<Item = &Intent> {
        self.records().iter().filter_map(|record| match record {
            Record::Intent(intent) => Some(intent),
            _ => None,
        })
    }

    /// Every [`Intent`], in the order it was written, with whether it was
    /// published.
    ///
    /// A session appends an Intent's [`Done`] as the very next frame, and a
    /// session whose write fails appends nothing more at all, so "the next frame
    /// is its `Done`" is exactly "it landed".
    #[must_use]
    pub fn landed(&self) -> Vec<(&Intent, bool)> {
        let records = self.records();
        records
            .iter()
            .enumerate()
            .filter_map(|(at, record)| match record {
                Record::Intent(intent) => Some((
                    intent,
                    matches!(
                        records.get(at + 1),
                        Some(Record::Done(done)) if done.target == intent.target
                    ),
                )),
                _ => None,
            })
            .collect()
    }

    /// The session header, if the journal has one.
    #[must_use]
    pub fn begin(&self) -> Option<&Begin> {
        self.records().iter().find_map(|record| match record {
            Record::Begin(begin) => Some(begin),
            _ => None,
        })
    }

    /// The frames, which is nothing at all for the two empty outcomes.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        match self {
            Self::Terminated(records)
            | Self::Unterminated(records)
            | Self::Torn { records, .. } => records,
            Self::Absent | Self::Unreadable { .. } => &[],
        }
    }

    /// Whether a session is unresolved: recorded, and not known to be cleared.
    #[must_use]
    pub const fn is_interrupted(&self) -> bool {
        matches!(
            self,
            Self::Terminated(_) | Self::Unterminated(_) | Self::Torn { .. }
        )
    }
}

/// Read a journal, classifying anything a crash can leave behind, and move
/// nothing.
///
/// A torn *tail* — bytes after the last whole frame, with no whole frame after
/// them — is discarded and reported as [`Loaded::Torn`]. That covers bytes that
/// stop short of a frame, which is what a process killed mid-append leaves, and
/// a frame that is all there but fails its checksum or its decoding, which is
/// what a power loss that zero-fills an unsynced tail leaves. Either way the
/// ordering discipline in [`Session::apply`] means a frame whose `fsync` had not
/// returned announces a write that had not begun, and every frame before it is
/// checksum-verified. A file that is only a prefix of a header, or a header
/// alone, is a session that wrote nothing: [`Loaded::Unterminated`] with no
/// records.
///
/// Everything else that is not whole frames is [`Loaded::Unreadable`]: a wrong
/// magic or an older format; a first frame that is torn or damaged, which no crash
/// leaves, because [`Journal::create`] renames the header and the first frame
/// into place together; a frame whose checksum or decoding fails **with a whole
/// frame after it**, which no crash leaves either, because only the last frame
/// can be unsynced; and bytes after an [`End`]. That is damage bx cannot place,
/// and it is not believed.
///
/// One case stays a torn tail though it may be damage: a length damaged to
/// point past the end of the file hides the frames after it inside its own
/// claimed extent. Its whole frames before it are rolled back, which undoes
/// nothing the hidden frames announced, and the file is kept.
///
/// This is the read [`crate::recover::pending`] makes without the state lock,
/// so it never renames, unlinks or writes: the journal it is looking at may
/// belong to a session running right now. Setting an unreadable journal aside
/// is [`load_exclusive`]'s, and only the lock holder's.
///
/// # Errors
///
/// [`Error::Io`] when the file exists and cannot be read at all. Damage is a
/// value, not an error; only a failure to look is. [`Error::FutureVersion`]
/// for a journal a newer bx wrote, which is not damage and is never set aside.
/// [`Error::NotAJournal`] for a path that is not a regular file, which is
/// never opened.
pub fn load(path: &Path) -> Result<Loaded, Error> {
    Ok(match inspect(path)? {
        Ok(loaded) => loaded,
        Err(why) => {
            tracing::warn!(
                path = %path.display(),
                "the write-ahead journal {} is unreadable: {why}. It is left in \
                 place for the next writing bx run to set aside.",
                path.display(),
            );
            Loaded::Unreadable { moved_to: None }
        }
    })
}

/// [`load`], and move an unreadable journal aside, to the number after the
/// highest of `journal.mpk.corrupt`, `journal.mpk.corrupt.1`, … present — or,
/// once the top number, `journal.mpk.corrupt.<u64::MAX>`, is present, the
/// lowest free one.
///
/// The [`ExclusiveLock`] is the proof that no session can be creating or
/// appending to the journal while it is moved. A reader without it could rename
/// a live journal out from under the session writing it, which is why [`load`]
/// does not. A journal set aside earlier is never renamed over: see
/// [`crate::state::StateDir::quarantine`].
///
/// # Errors
///
/// As [`load`], and [`Error::CannotSetAside`] for an unreadable journal that
/// cannot be moved aside, which is left in place. It is not reported as
/// [`Loaded::Unreadable`]: every caller treats that as nothing standing, and
/// [`Session::open`] would create its own journal over the bytes.
pub fn load_exclusive(path: &Path, lock: &ExclusiveLock) -> Result<Loaded, Error> {
    match inspect(path)? {
        Ok(loaded) => Ok(loaded),
        Err(why) => quarantine(path, why, lock),
    }
}

/// Classify the bytes at `path`: what a session, or a crash of one, left there,
/// or why it is neither.
fn inspect(path: &Path) -> Result<Result<Loaded, &'static str>, Error> {
    // Looked at before it is opened, following no link. See
    // `Error::NotAJournal`.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(Error::NotAJournal {
                path: path.to_path_buf(),
                kind: fs::Kind::from(meta.file_type()),
            });
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Ok(Loaded::Absent)),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    // A journal unlinked since that look — `pending` takes no lock, and a
    // session may just have finished — is as absent as one never there.
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Ok(Loaded::Absent)),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    if bytes.len() <= MAGIC.len() {
        // A prefix of the magic is a header a crash tore.
        return Ok(if MAGIC.starts_with(&bytes) {
            Ok(Loaded::Unterminated(Vec::new()))
        } else {
            Err("it does not start with a bx journal header")
        });
    }
    if &bytes[..MAGIC.len()] != MAGIC.as_slice() {
        return Ok(Err("it does not start with a bx journal header"));
    }
    let found = bytes[MAGIC.len()];
    // Before anything else is classified: a newer format is not damage, and
    // nothing this build could decide about its bytes is believable.
    if found > FORMAT {
        return Err(Error::FutureVersion {
            path: path.to_path_buf(),
            found,
            supported: FORMAT,
        });
    }
    if found != FORMAT {
        return Ok(Err("it is a journal format this bx cannot read"));
    }
    // A header cut inside its nonce is still a header a crash tore.
    let Some(nonce) = bytes
        .get(MAGIC.len() + 1..HEADER)
        .and_then(|nonce| <[u8; NONCE]>::try_from(nonce).ok())
    else {
        return Ok(Ok(Loaded::Unterminated(Vec::new())));
    };

    let mut records = Vec::new();
    let mut at = HEADER;
    let mut discarded = 0;
    while at < bytes.len() {
        match frame(&bytes, at, &nonce) {
            Ok((record, next)) => {
                records.push(record);
                at = next;
            }
            // The header and the first frame are renamed into place together,
            // so no crash leaves the one without the other whole.
            Err(_) if records.is_empty() => {
                return Ok(Err("its first frame is not a whole record"));
            }
            Err(_) if matches!(records.last(), Some(Record::End(_))) => {
                return Ok(Err("bytes follow the end of its session"));
            }
            // Every append is one `fsync`ed write of a whole frame at the end of
            // the file, so a crash only ever damages the last frame: a process
            // killed mid-write cuts it short, and a power loss can zero-fill or
            // leave stale blocks in its unsynced bytes. A frame that fails with a
            // whole frame bx wrote after it is none of those. It is damage in the
            // middle of the log, and the frames it hides are not believed either.
            Err(Damage::Invalid) if whole_frame_after(&bytes, at, &nonce) => {
                return Ok(Err(
                    "a frame after its first is damaged, and a whole frame follows it",
                ));
            }
            Err(_) => {
                discarded = bytes.len() - at;
                tracing::warn!(
                    path = %path.display(),
                    discarded,
                    "the write-ahead journal ends in bytes that are not a whole frame; \
                     the whole frames before them are rolled back, and the file is set \
                     aside rather than deleted once it is recovered",
                );
                break;
            }
        }
    }

    if let Some(why) = refusal(&records) {
        return Ok(Err(why));
    }

    Ok(Ok(if matches!(records.last(), Some(Record::End(_))) {
        Loaded::Terminated(records)
    } else if discarded > 0 {
        Loaded::Torn { records, discarded }
    } else {
        Loaded::Unterminated(records)
    }))
}

/// Why the journal could not have been written by a bx session, if it could
/// not.
///
/// A journal is believed only as far as a session could have written it,
/// because everything recovery does with one — unlink a temporary file, rewrite
/// or unlink a destination, remove directories — is done to the paths it
/// stores. A journal that fails any rule below is bytes bx never wrote, and the
/// caller treats it as unreadable: [`load`] leaves it in place and
/// [`load_exclusive`] sets it aside. It is never believed, so it can never
/// drive a rollback.
///
/// * **A header first, and only first.** Every other rule needs the home, and
///   the home is the [`Begin`]'s. A session writes exactly one, as the file's
///   first frame, and writes nothing after its [`End`].
/// * **Portable paths.** Decoding a [`Portable`] applies every rule that needs
///   no home. The one that does cannot run in a decoder: `/<home>/.gitconfig`
///   is well-formed, and on the account whose home that is, a second key for
///   `~/.gitconfig`. So the header's home, its scope, and each [`Intent`]'s and
///   [`Done`]'s target go through [`Portable::check_against`].
/// * **An intent's paths are its target's.** The destination is exactly where
///   the target renders, which [`Session::apply`] also refuses to break; the
///   temporary file is a `.bx-` file beside the destination, the only place
///   [`crate::fs::stage`] puts one; and each created directory is a parent of
///   the destination that is neither the home nor above it.
/// * **One write per target.** See [`Error::Repeated`].
fn refusal(records: &[Record]) -> Option<&'static str> {
    let (first, rest) = records.split_first()?;
    let Record::Begin(begin) = first else {
        return Some("it records a session with no header before it");
    };
    if let Err(error) = Portable::parse_in("~", &begin.home) {
        tracing::warn!(%error, "the journal's session header names an unusable home");
        return Some("its session header names a home that is not an absolute UTF-8 path");
    }
    let home = begin.home.as_path();
    if let Some(refused) = records
        .iter()
        .flat_map(|record| match record {
            Record::Begin(begin) => begin.scope.iter().collect::<Vec<_>>(),
            Record::Intent(intent) => vec![&intent.target],
            Record::Done(done) => vec![&done.target],
            Record::End(_) => Vec::new(),
        })
        .find_map(|portable| portable.check_against(home).err())
    {
        tracing::warn!(error = %refused, "a journal record stores a path its session's home refuses");
        return Some("it records a path that is not portable against its session's home");
    }
    let mut targets = std::collections::HashSet::new();
    for (at, record) in rest.iter().enumerate() {
        match record {
            Record::Begin(_) => return Some("it has a second session header"),
            Record::End(_) if at + 1 < rest.len() => {
                return Some("a record follows the end of its session");
            }
            Record::Intent(intent) => {
                if let Some(why) = misplaced(intent, home) {
                    return Some(why);
                }
                if !targets.insert(&intent.target) {
                    return Some("it records two writes to one target");
                }
            }
            Record::Done(_) | Record::End(_) => {}
        }
    }
    None
}

/// Why an intent stores a path its own target could not have, if it does.
fn misplaced(intent: &Intent, home: &Path) -> Option<&'static str> {
    let dest = &intent.dest;
    if *dest != intent.target.render(home) {
        return Some("an intent's destination is not where its target renders");
    }
    if let Some(temp) = &intent.temp {
        let staged = temp != dest
            && temp.parent() == dest.parent()
            && temp
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(fs::TEMP_PREFIX));
        if !staged {
            return Some(
                "an intent's temporary file is not a bx temporary file beside its destination",
            );
        }
    }
    if stray_created_dir(dest, home, &intent.created_dirs).is_some() {
        return Some(
            "an intent's created directory is not a parent of its destination below the home",
        );
    }
    None
}

/// The first of `dirs` that is not a strict parent of `dest` below `home`, if
/// one is not.
///
/// The one rule for a directory bx may claim it created for a destination,
/// shared by the loader, which refuses a journal breaking it, and by
/// [`Session::apply`], which refuses a removal that would write such a journal.
fn stray_created_dir<'a>(dest: &Path, home: &Path, dirs: &'a [PathBuf]) -> Option<&'a PathBuf> {
    dirs.iter()
        .find(|dir| *dir == dest || !dest.starts_with(dir) || home.starts_with(dir))
}

/// Why there is no whole record at an offset.
enum Damage {
    /// The bytes stop before the frame does: a write a crash cut short, or a
    /// length that was damaged.
    Torn,
    /// The frame is all there, and it is not what bx wrote: its checksum or its
    /// decoding fails, or its length is past the bound.
    Invalid,
}

/// Decode the frame at `at`: a little-endian `u32` length, a [`CHECK`]-byte
/// checksum under the session's `nonce`, and a MessagePack body of that length.
fn frame(bytes: &[u8], at: usize, nonce: &[u8; NONCE]) -> Result<(Record, usize), Damage> {
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
fn whole_frame_after(bytes: &[u8], at: usize, nonce: &[u8; NONCE]) -> bool {
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

/// Move a journal that carries no information aside, and say so.
///
/// The name is the number after the highest set-aside name present — or,
/// once the top number is present, the lowest free one — taken with
/// `RENAME_NOREPLACE` by [`crate::state::move_aside`], so an earlier
/// set-aside journal is never replaced.
///
/// # Errors
///
/// [`Error::CannotSetAside`] when the move fails. The journal is left where it
/// is, and it is an error rather than a value its caller could read as
/// "nothing stands": [`Session::open`] would then create its own journal over
/// the bytes by rename.
fn quarantine(path: &Path, why: &str, lock: &ExclusiveLock) -> Result<Loaded, Error> {
    match crate::state::move_aside(path, lock) {
        Ok(aside) => {
            tracing::error!(
                path = %path.display(),
                moved_to = %aside.display(),
                "discarding the write-ahead journal {}: {why}. \
                 The bytes were kept, not deleted. Run `bx plan`: a file bx \
                 wrote but never recorded is reported as a conflict, never \
                 overwritten.",
                path.display(),
            );
            Ok(Loaded::Unreadable {
                moved_to: Some(aside),
            })
        }
        Err(source) => {
            tracing::error!(
                path = %path.display(),
                %source,
                "the write-ahead journal {} cannot be believed: {why}. \
                 It could not be moved aside, so it is left in place and \
                 nothing is written over it.",
                path.display(),
            );
            Err(Error::CannotSetAside {
                path: path.to_path_buf(),
                source,
            })
        }
    }
}

/// The append-only log itself.
///
/// [`Session`] is the supported way to write one; this is public so recovery can
/// be exercised against journals a crash could produce but a correct session
/// never writes.
#[derive(Debug)]
pub struct Journal {
    file: File,
    path: PathBuf,
    /// The nonce in this journal's header, which every frame's checksum covers.
    nonce: [u8; NONCE],
}

impl Journal {
    /// Create the journal whole — header and [`Begin`] frame — through
    /// [`crate::fs::write_atomically`], then open it for appending.
    ///
    /// Whatever was at `path` is replaced by `rename`, never truncated in place,
    /// so an unlocked reader sees either the file that was there or the new
    /// journal with its `Begin`, and never an empty or half-written one. The
    /// temporary file is `fsync`ed before the rename and the directory after it,
    /// and the journal is at `0600` from its first instant.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`] or [`Error::FrameTooLarge`] for a `Begin` that cannot be
    /// framed, [`Error::Write`] when the file cannot be written, and
    /// [`Error::Io`] when it cannot be reopened for appending.
    pub fn create(path: &Path, begin: Begin) -> Result<Self, Error> {
        let nonce = fresh_nonce();
        let mut bytes = Vec::with_capacity(HEADER);
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&encode(&Record::Begin(begin), &nonce)?);
        fs::write_atomically(path, &bytes, Mode::PRIVATE_FILE)?;

        let file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|source| Error::Io {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            nonce,
        })
    }

    /// The journal's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and `fsync` it.
    ///
    /// Returns once the frame is durable, which is the guarantee the ordering in
    /// [`Session::apply`] rests on.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`] for a record that cannot be encoded,
    /// [`Error::FrameTooLarge`] for one that is absurdly big, and [`Error::Io`]
    /// wrapping the failing `write` or `fsync`.
    pub fn append(&mut self, record: &Record) -> Result<(), Error> {
        // One buffer and one `write_all`, so a frame torn by a crash can only
        // ever be the last bytes of the file.
        let frame = encode(record, &self.nonce)?;
        self.emit(&frame)
    }

    /// Write bytes at the end of the journal and `fsync` the file.
    ///
    /// The `fsync` goes through [`crate::fs::durable::sync_file`], so a test can
    /// see that it happens, and where it falls against the rename or unlink the
    /// frame announces.
    fn emit(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let fail = |source| Error::Io {
            path: self.path.clone(),
            source,
        };
        self.file.write_all(bytes).map_err(fail)?;
        crate::fs::durable::sync_file(&self.file, &self.path).map_err(fail)
    }
}

/// One record as a frame: its length as a little-endian `u32`, its checksum
/// under the session's `nonce`, then its MessagePack encoding.
fn encode(record: &Record, nonce: &[u8; NONCE]) -> Result<Vec<u8>, Error> {
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
fn fresh_nonce() -> [u8; NONCE] {
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

/// A transaction over the state directory: the lock, the ledger, the journal.
///
/// Every byte bx writes to a user's filesystem passes through one of these. It
/// holds the state directory's exclusive lock for its whole life, so no second
/// `bx` can interleave, and it is the *only* caller of
/// [`crate::state::Ledger::save`] — which is what keeps the saved ledger
/// describing the state a rollback returns to.
///
/// Dropping a session without [`Session::finish`] deliberately leaves the
/// journal in place. An abandoned session *is* an interrupted session, and the
/// next invocation must see it.
#[derive(Debug)]
pub struct Session {
    journal: Journal,
    state: StateDir,
    ledger: Ledger,
    home: PathBuf,
    written: usize,
    /// Set by the first write that fails. See [`Session::apply`].
    poisoned: bool,
    /// Every target a request has been admitted for, so none is written twice.
    touched: std::collections::HashSet<Portable>,
    /// Every directory a write in this session created. One set for the whole
    /// session, because [`crate::fs::ensure_dir`] reads it to tell a directory
    /// an earlier write made from one somebody else made since plan.
    created: fs::CreatedDirs,
    /// Every directory a target this session removed claimed. Pruned, as one
    /// union, once the session's `End` is durable, and handed on.
    released: std::collections::BTreeSet<PathBuf>,
    /// Every directory claimed by a target this session dropped from the ledger
    /// without announcing a removal: one [`Session::forget`] dropped, and one a
    /// [`Ownership::Released`] write handed back. Handed on when the session
    /// finishes, and never pruned — no removal was announced, so there is
    /// nothing `plan` promised to remove.
    forgotten: std::collections::BTreeSet<PathBuf>,
    crash: Crash,
    /// Called with the destination just before a write is published, so a test
    /// can make the publish fail the way a concurrent change to the destination
    /// would.
    #[cfg(test)]
    before_publish: Option<fn(&Path)>,
    /// Called with the destination after a removal's Intent is durable and
    /// before its last look, so a test can save over it the way a racing editor
    /// would.
    #[cfg(test)]
    before_unlink: Option<fn(&Path)>,
    /// Held, never read: dropping it releases the state directory.
    _lock: ExclusiveLock,
}

/// What a caller asks a session to make true at one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The target, home-relative. The ledger's key.
    pub target: Portable,
    /// Where it goes, rendered absolute.
    pub dest: PathBuf,
    /// What should be there afterwards.
    pub content: Content,
    /// The mode the content is written at, already resolved. Ignored for
    /// [`Content::Absent`].
    pub mode: Mode,
    /// Whether bx owns the result.
    pub ownership: Ownership,
}

/// What a request leaves at the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// These bytes, at [`Request::mode`].
    Bytes {
        /// The whole content.
        bytes: Vec<u8>,
        /// What plan observed at the destination when it compared these bytes
        /// with it, from [`crate::fs::observe`]. The write is staged against
        /// it: a destination whose kind or stamp is no longer this is refused
        /// with [`crate::fs::Error::Changed`], which poisons the session with
        /// nothing staged, announced or published.
        planned: fs::Observed,
    },
    /// No file at all.
    ///
    /// The destination is unlinked, and when the session finishes, after its
    /// `End` frame, `created_dirs` are removed, deepest first, while they are
    /// empty directories and no entry the ledger still holds names them; one
    /// that is no longer a directory is left. Absence is not emptiness: a file
    /// bx created is removed, never truncated. The target is always dropped
    /// from the ledger — there is nothing left for bx to own. A claimed
    /// directory that still stands then is handed to a surviving entry beneath
    /// it: see [`Session::finish`].
    Absent {
        /// Directories bx created for the target, deepest first.
        created_dirs: Vec<PathBuf>,
        /// What plan observed at the destination when it decided on the
        /// removal, from [`crate::fs::observe`]. A destination whose path, kind
        /// or stamp is no longer this is refused with
        /// [`crate::fs::Error::Changed`] — before anything is stored or
        /// announced, and again immediately before the unlink — which poisons
        /// the session with nothing unlinked.
        planned: fs::Observed,
    },
}

/// Whether bx owns what the write leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// bx manages the target from now on, attached this way.
    Owned(Mechanism),
    /// bx is handing the target back — the restore half of `bx rm`. The prior
    /// bytes are still copied into `restore/`, because that is what an
    /// interrupted restore is rolled back from; only the ledger entry goes,
    /// and the directories that entry claimed are handed to a surviving entry
    /// beneath them when the session finishes rather than dropped.
    Released,
}

impl Session {
    /// Open a session: take the lock, refuse over an unresolved interruption,
    /// and write the header and the [`Begin`] frame.
    ///
    /// # Errors
    ///
    /// [`Error::InProgress`] when a journal already stands — recover first.
    /// [`Error::FutureVersion`] when the journal that stands was written by a
    /// newer bx: nothing is set aside. [`Error::NotAJournal`] when what stands
    /// at the journal's path is not a regular file: it is never opened.
    /// [`Error::CannotSetAside`] when the
    /// journal that stands cannot be believed and cannot be moved aside: it is
    /// left in place, never replaced. [`Error::State`] with
    /// [`crate::state::Error::ForeignRecord`] when a scope entry is one the
    /// loader would refuse. [`Error::State`] when the directory
    /// cannot be made or locked, and [`Error::Io`] when the journal cannot be
    /// written.
    pub fn open(
        state: &StateDir,
        kind: SessionKind,
        home: &Path,
        scope: Vec<Portable>,
    ) -> Result<Self, Error> {
        state.ensure()?;
        // The lock first, so the check inside cannot race a second bx.
        let lock = ExclusiveLock::acquire(state)?;
        Self::open_locked(state, kind, home, scope, lock)
    }

    /// Open a session under a lock the caller already holds.
    ///
    /// The one-lock form: a writing command takes the lock, resolves any
    /// interruption under it, and hands the same guard here, so no second bx
    /// can win the directory in between and be reported as an interruption.
    /// [`crate::recover::lock_for_writing`] hands out that guard.
    ///
    /// # Errors
    ///
    /// As [`Session::open`], minus the acquisition of the lock.
    pub fn open_locked(
        state: &StateDir,
        kind: SessionKind,
        home: &Path,
        scope: Vec<Portable>,
        lock: ExclusiveLock,
    ) -> Result<Self, Error> {
        state.ensure()?;
        // Before the journal exists, because the loader refuses the *whole*
        // journal over one unportable scope entry: a session that wrote one
        // could never be rolled back. The same rule `admit` applies to a
        // request's target, at the one other place a path enters the journal.
        for entry in &scope {
            entry
                .check_against(home)
                .map_err(|source| crate::state::Error::ForeignRecord {
                    home: home.to_path_buf(),
                    stored: entry.as_str().to_string(),
                    source: Box::new(source),
                })?;
        }
        let path = state.journal();
        if load_exclusive(&path, &lock)?.is_interrupted() {
            return Err(Error::InProgress { path });
        }

        let ledger = Ledger::open(state, &lock, home)?.value;
        let journal = Journal::create(
            &path,
            Begin {
                kind,
                home: home.to_path_buf(),
                scope,
            },
        )?;
        tracing::debug!(%kind, home = %home.display(), "opened a journalled session");

        Ok(Self {
            journal,
            state: state.clone(),
            ledger,
            home: home.to_path_buf(),
            written: 0,
            poisoned: false,
            touched: std::collections::HashSet::new(),
            created: fs::CreatedDirs::new(),
            released: std::collections::BTreeSet::new(),
            forgotten: std::collections::BTreeSet::new(),
            crash: Crash::from_env(),
            #[cfg(test)]
            before_publish: None,
            #[cfg(test)]
            before_unlink: None,
            _lock: lock,
        })
    }

    /// The ledger as this session has it so far.
    #[must_use]
    pub fn ledger(&self) -> &LedgerView {
        &self.ledger
    }

    /// The state directory the session is against.
    #[must_use]
    pub fn state(&self) -> &StateDir {
        &self.state
    }

    /// The home the session's paths are rendered against.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The journal this session is appending to.
    #[must_use]
    pub fn journal(&self) -> &Path {
        self.journal.path()
    }

    /// How many writes the session has published.
    #[must_use]
    pub const fn written(&self) -> usize {
        self.written
    }

    /// Drop a target from the ledger without touching the filesystem.
    ///
    /// For the one case `bx rm` has where there is nothing to write: bx created
    /// the file, and the file is already gone.
    ///
    /// Not journalled, because there is no write to undo. The cost is that a
    /// session interrupted between its [`End`] frame and its save leaves the
    /// entry standing, since recovery rebuilds the ledger from the journal's
    /// intents and this made none. That self-heals: the next `rm` finds the
    /// file still absent, reaches this same call, and finishes.
    ///
    /// The directories the entry claimed are handed to a surviving entry
    /// beneath them when the session finishes, and never removed here: plan
    /// announced no removal.
    pub fn forget(&mut self, target: &Portable) {
        if let Some(entry) = self.ledger.forget(target) {
            self.forgotten
                .extend(entry.created_dirs.iter().map(|dir| dir.render(&self.home)));
        }
    }

    /// Make `request` true at its destination, durably and recoverably.
    ///
    /// The one place the ordering discipline this module documents is expressed,
    /// and therefore the only place it can be got wrong.
    ///
    /// # A failed write poisons the session
    ///
    /// Any error here leaves the session refusing every later `apply` and
    /// [`Session::finish`], so its journal stays for recovery to roll back —
    /// whatever failed, and however early. A caller that wants to skip a target
    /// and go on decides that before calling, the way [`crate::restore`] asks
    /// [`crate::restore::plan_restore`] first.
    ///
    /// # Errors
    ///
    /// [`Error::Misplaced`] when the request's destination is not where its
    /// target renders, [`Error::State`] with
    /// [`crate::state::Error::ForeignRecord`] when the target is spelled
    /// absolutely under the home, [`Error::StrayCreatedDir`] when a removal names a
    /// created directory that is not a parent of its destination below the home,
    /// [`Error::Repeated`] when this session already wrote the target, [`Error::Write`] when the destination cannot be written, is not
    /// a file bx may replace, or is no longer what the request's plan observed
    /// ([`crate::fs::Error::Changed`]), [`Error::State`] when the prior bytes
    /// cannot be stored or recorded, [`Error::Io`] when the journal cannot be
    /// appended to, and [`Error::Poisoned`] when an earlier write in this
    /// session failed.
    pub fn apply(&mut self, request: Request) -> Result<(), Error> {
        if self.poisoned {
            return Err(self.poisoned_error());
        }
        let index = self.written;
        let Request {
            target,
            dest,
            content,
            mode,
            ownership,
        } = request;
        let claimed: &[PathBuf] = match &content {
            Content::Bytes { .. } => &[],
            Content::Absent { created_dirs, .. } => created_dirs,
        };
        if let Err(e) = self.admit(&target, &dest, claimed) {
            self.poisoned = true;
            return Err(e);
        }
        self.crash.reached(index, Phase::BeforeStage);
        let applied = match content {
            Content::Bytes { bytes, planned } => {
                self.write(target, dest, &bytes, &planned, mode, &ownership)
            }
            Content::Absent {
                created_dirs,
                planned,
            } => self.remove(index, target, dest, created_dirs, &planned),
        };
        if let Err(e) = applied {
            self.poisoned = true;
            return Err(e);
        }
        self.written += 1;
        Ok(())
    }

    /// Refuse a request no journal bx believes could describe.
    ///
    /// [`load`] refuses a journal whose intent's destination is not where its
    /// target renders, or that writes one target twice, so a session never
    /// writes either. A refusal poisons the session like any other failed
    /// write — decision 7 of the pull request that introduced the rule — though
    /// nothing has been touched: the rule does not depend on where in the
    /// sequence an error came from.
    ///
    /// A target spelled absolutely under the home renders to itself, so it
    /// passes the destination check, but it is the path the ledger's home check
    /// refuses: [`load`] would refuse the Intent naming it, the ledger would key
    /// it under its `~` spelling, and the same file under that spelling would
    /// pass [`Error::Repeated`]. It is refused as
    /// [`crate::state::Error::ForeignRecord`] before anything is touched.
    ///
    /// A removal's `created_dirs` are what it prunes and what its Intent
    /// records, so each must be a strict parent of the destination below the
    /// home — the loader's rule — or the removal is [`Error::StrayCreatedDir`],
    /// before anything is observed, stored or touched.
    fn admit(
        &mut self,
        target: &Portable,
        dest: &Path,
        created_dirs: &[PathBuf],
    ) -> Result<(), Error> {
        let rendered = target.render(&self.home);
        if dest != rendered {
            return Err(Error::Misplaced {
                target: target.clone(),
                dest: dest.to_path_buf(),
                rendered,
            });
        }
        target
            .check_against(&self.home)
            .map_err(|source| crate::state::Error::ForeignRecord {
                home: self.home.clone(),
                stored: target.as_str().to_string(),
                source: Box::new(source),
            })?;
        if let Some(dir) = stray_created_dir(dest, &self.home, created_dirs) {
            return Err(Error::StrayCreatedDir {
                target: target.clone(),
                dir: dir.clone(),
            });
        }
        if !self.touched.insert(target.clone()) {
            return Err(Error::Repeated {
                target: target.clone(),
            });
        }
        Ok(())
    }

    /// The refusal a poisoned session gives.
    fn poisoned_error(&self) -> Error {
        Error::Poisoned {
            path: self.journal.path().to_path_buf(),
        }
    }

    /// The write path: stage, fill, record, journal, publish, done.
    ///
    /// Staged against `planned`, the observation plan compared, and with the
    /// session's one set of created directories, so every later write in the
    /// session knows a directory an earlier one made.
    fn write(
        &mut self,
        target: Portable,
        dest: PathBuf,
        bytes: &[u8],
        planned: &fs::Observed,
        mode: Mode,
        ownership: &Ownership,
    ) -> Result<(), Error> {
        // `written` moves only once a write has succeeded, so it is this
        // write's index.
        let index = self.written;
        let staged = fs::stage(&dest, mode, planned, &mut self.created)?;
        let temp = staged.temp_path().to_path_buf();
        self.crash.reached(index, Phase::AfterStage);

        let filled = staged.fill(bytes)?;
        self.crash.reached(index, Phase::AfterFill);

        let created_dirs = filled.created_dirs().to_vec();
        // Assembled now, while the writer still holds the prior, and handed to
        // the ledger only once the write has landed. `None` is the restore half
        // of `bx rm`: bx is handing the target back, so there is nothing left for
        // it to own.
        let (entry, mechanism) = match ownership {
            Ownership::Owned(mechanism) => (
                Some(filled.new_entry(&self.home, mechanism.clone())?),
                Some(mechanism.clone()),
            ),
            Ownership::Released => (None, None),
        };
        // The ledger's refusal is asked before anything is stored, announced or
        // published. `record` after the rename would refuse a changed shared
        // file only once bx's new bytes were already over it; asked here, the
        // refusal poisons the session with the destination untouched and no
        // Intent for recovery to act on.
        if let Some(entry) = &entry {
            self.ledger.check_record(entry)?;
        }
        // Durable before the Intent frame that names it, and therefore before
        // anything can displace it.
        let before = store_prior(&self.state, filled.prior())?;

        let ledger_written = self.ledger.get(&target).map(|entry| entry.written);
        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest,
            temp: Some(temp),
            before,
            after: Written::Present {
                digest: filled.written(),
                mode: filled.mode(),
            },
            created_dirs,
            mechanism,
            ledger_written,
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        #[cfg(test)]
        if let Some(meddle) = self.before_publish {
            meddle(filled.dest());
        }
        filled.publish()?;
        // Only now is there something to own, or to stop owning. Told any
        // earlier, the ledger would describe a write whose publish then failed.
        match entry {
            Some(entry) => {
                self.ledger.record(entry)?;
            }
            // The restore half of `bx rm`. The entry goes, but the directories
            // it claimed still stand and bx still made them, so its claims are
            // handed to a surviving entry beneath them when the session
            // finishes — exactly as `Session::forget` and `Session::remove`
            // hand theirs on. Dropped here instead, no entry would claim them
            // and no later `rm` could remove them: see `r3 round 3` decision 2.
            // `self.forgotten`, not `self.released`, because this write
            // announced no removal and so prunes nothing.
            None => {
                if let Some(dropped) = self.ledger.forget(&target) {
                    self.forgotten.extend(
                        dropped
                            .created_dirs
                            .iter()
                            .map(|dir| dir.render(&self.home)),
                    );
                }
            }
        }
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// The removal path: check, record, journal, check again, unlink, done. The
    /// directories the target claimed are pruned when the session finishes.
    ///
    /// Checked against `planned`, the observation plan decided on, twice. First
    /// before the prior is stored or the Intent announced, so a destination
    /// that changed since plan is refused with nothing written anywhere. Then
    /// immediately before the unlink, as [`crate::fs::Filled::publish`] checks
    /// before its rename, so an edit that lands while the snapshot and the
    /// Intent are made durable is refused rather than unlinked; recovery then
    /// finds a destination holding neither recorded state and leaves it alone.
    /// What stays open is the window between that last look and the `unlink`
    /// call itself.
    fn remove(
        &mut self,
        index: usize,
        target: Portable,
        dest: PathBuf,
        created_dirs: Vec<PathBuf>,
        planned: &Observed,
    ) -> Result<(), Error> {
        let observed = fs::observe(&dest)?;
        refuse_moved(planned, &observed)?;
        if !observed.kind.is_writable_destination() {
            return Err(fs::Error::NotAFile {
                path: dest,
                kind: observed.kind,
            }
            .into());
        }

        // Same as in `write`: the bytes the removal is about to displace are
        // made durable before the Intent frame that names them.
        let before = store_prior(&self.state, &observed)?;

        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: None,
            before,
            after: Written::Absent,
            created_dirs: created_dirs.clone(),
            mechanism: None,
            ledger_written: self.ledger.get(&target).map(|entry| entry.written),
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        #[cfg(test)]
        if let Some(meddle) = self.before_unlink {
            meddle(&dest);
        }
        // The last look before the unlink: storing the snapshot and the Intent
        // took two `fsync`s, and an editor may have saved in between.
        refuse_moved(planned, &fs::observe(&dest)?)?;
        unlink(&dest)?;
        // Pruned only once the session's `End` is durable: see
        // `Session::finish`.
        self.released.extend(created_dirs);
        // As in `write`: the entry goes only once the file has.
        self.ledger.forget(&target);
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// Prune the union of the directories released targets claimed, and hand
    /// what still stands to the entries beneath it.
    ///
    /// A removal prunes nothing itself: a directory removed before the
    /// session's `End` would have to be re-created by a rollback, which cannot
    /// know the mode it had. Deferring the prune costs no later target in the
    /// session anything, because a directory an entry the ledger still holds
    /// names is never pruned, so no later target can need a claimed directory
    /// gone. By the time the session finishes every removal has run, so each
    /// claimed directory is tried once, deepest first. Nothing is assumed
    /// about which entry claimed it: it is removed when it is empty and no
    /// entry the ledger still holds names it. A claim still standing — a
    /// released one, or one of a target this session dropped from the ledger
    /// without announcing a removal ([`Session::forget`], or a
    /// [`Ownership::Released`] write) — is
    /// given to a surviving entry beneath it, so the `rm` that removes that
    /// entry removes the directory too.
    fn settle_claims(&mut self) -> Result<(), Error> {
        let released = std::mem::take(&mut self.released);
        prune_claims(&self.ledger, &self.home, &released)?;
        let forgotten = std::mem::take(&mut self.forgotten);
        hand_off_claims(
            &mut self.ledger,
            &self.home,
            released.iter().chain(&forgotten),
        )
    }

    /// End the session: [`End`], settle the claimed directories, save the
    /// ledger, and unlink the journal last.
    ///
    /// The directories released targets claimed are settled only after the
    /// `End` frame is durable: see [`Session::settle_claims`]. Until then no
    /// directory a removal claimed is removed, so a crash before `End` rolls
    /// the session back into the very directories it found, at the modes they
    /// had — never into one re-created at the default mode. A crash between
    /// `End` and the prune leaves those directories standing, empty, and
    /// claimed by no entry once recovery has recorded the session: the same
    /// kind of orphan decision 11 keeps, which recovery leaves where it is and
    /// [`crate::recover::pending`] names.
    ///
    /// The order is the ordering rule that makes recovery idempotent. The `End`
    /// frame goes down first, so a crash before the save is a *terminated*
    /// journal that recovery finishes as bookkeeping and no destination is
    /// touched. The journal is unlinked last, so a crash — or a failed unlink —
    /// after the save leaves a terminated journal over a ledger that already
    /// holds every write in it; recovery recognises those entries by
    /// [`Intent::ledger_written`] and leaves them exactly as they are.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], [`Error::State`] or [`Error::Write`]. The journal is left
    /// in place on any failure, so the session stays recoverable.
    /// [`Error::Poisoned`] when a write in the session failed: nothing is
    /// appended, nothing is saved, and the journal is left for recovery.
    pub fn finish(mut self) -> Result<usize, Error> {
        if self.poisoned {
            return Err(self.poisoned_error());
        }
        let written = self.written;
        self.journal.append(&Record::End(End { written }))?;
        self.crash.reached(written, Phase::AfterEnd);
        self.settle_claims()?;
        self.ledger.save()?;
        self.crash.reached(written, Phase::AfterSave);
        unlink(self.journal.path())?;
        tracing::debug!(written, "closed a journalled session");
        Ok(written)
    }
}

/// The boundaries [`Session::apply`] and [`Session::finish`] cross, named so a
/// test can stop at one.
///
/// Six in `apply`, and each is a real durability boundary rather than a
/// convenient line: before anything exists; after a temporary file exists at
/// its final mode but holds nothing; after its content is `fsync`ed but the
/// destination is untouched; after the intent is durable; after the destination
/// is replaced; after the completion is durable. Two in `finish`, where every
/// write has landed: after the `End` frame is durable and before the claimed
/// directories are pruned, and after the ledger is saved. A `finish` boundary
/// is reached with the number of writes as its index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    BeforeStage,
    AfterStage,
    AfterFill,
    AfterIntent,
    AfterPublish,
    AfterDone,
    AfterEnd,
    AfterSave,
}

/// Every phase of a write, in the order [`Session::apply`] passes them.
#[cfg(test)]
const PHASES: [Phase; 6] = [
    Phase::BeforeStage,
    Phase::AfterStage,
    Phase::AfterFill,
    Phase::AfterIntent,
    Phase::AfterPublish,
    Phase::AfterDone,
];

/// Every phase of [`Session::finish`], in the order it passes them.
#[cfg(test)]
const FINISH_PHASES: [Phase; 2] = [Phase::AfterEnd, Phase::AfterSave];

/// The environment variable a test child reads to choose where to stop.
#[cfg(test)]
const CRASH_AT: &str = "BX_CRASH_AT";

/// The crash seam: where, if anywhere, this process is to stop existing.
///
/// The field is `cfg(test)`-gated, so outside a test build this is a zero-sized
/// value whose [`Crash::reached`] compiles to nothing. No shipped binary can
/// read `BX_CRASH_AT` and no shipped binary can abort itself; the only process
/// that can honour the variable is a test binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Crash {
    #[cfg(test)]
    at: Option<(usize, Phase)>,
}

impl Crash {
    /// Read `BX_CRASH_AT` once, at [`Session::open`].
    ///
    /// The format is `<intent-index>:<phase>`; anything else is ignored, so a
    /// stray value cannot silently turn into "crash somewhere else".
    fn from_env() -> Self {
        Self {
            #[cfg(test)]
            at: std::env::var(CRASH_AT)
                .ok()
                .as_deref()
                .and_then(Self::parse),
        }
    }

    /// Stop existing, if this is the chosen boundary.
    ///
    /// `abort` rather than `panic` or `exit`: it terminates without unwinding,
    /// without running a destructor, and without flushing a buffer, which is
    /// what a crash does and what an `Err` return does not.
    fn reached(self, index: usize, phase: Phase) {
        #[cfg(test)]
        if self.at == Some((index, phase)) {
            std::process::abort();
        }
        #[cfg(not(test))]
        let _ = (self, index, phase);
    }

    /// Parse `<intent-index>:<phase>`, where the phase is a [`Crash::name`].
    #[cfg(test)]
    fn parse(raw: &str) -> Option<(usize, Phase)> {
        let (index, phase) = raw.split_once(':')?;
        let index = index.parse().ok()?;
        let phase = PHASES
            .iter()
            .chain(&FINISH_PHASES)
            .copied()
            .find(|candidate| Self::name(*candidate) == phase)?;
        Some((index, phase))
    }

    /// The spelling of one phase.
    #[cfg(test)]
    fn name(phase: Phase) -> &'static str {
        match phase {
            Phase::BeforeStage => "before-stage",
            Phase::AfterStage => "after-stage",
            Phase::AfterFill => "after-fill",
            Phase::AfterIntent => "after-intent",
            Phase::AfterPublish => "after-publish",
            Phase::AfterDone => "after-done",
            Phase::AfterEnd => "after-end",
            Phase::AfterSave => "after-save",
        }
    }
}

/// Copy the bytes a write is about to displace into `restore/`, durably, and
/// describe where they went.
///
/// Deliberately **not** [`crate::state::Ledger::record`], which answers a
/// different question. The ledger keeps the *first* prior it was ever given for
/// a target, and that is right: what `bx rm` owes the user is the file as it was
/// before bx ever touched it. A rollback owes them something else — whatever was
/// on disk a moment ago, which for a target bx already manages is bx's own
/// previous output. Asking `record` for that would hand back the original and
/// leave recovery comparing the destination against a state it has not been in
/// since the first `apply`, so every repeat write would look like a conflict
/// after a crash.
///
/// Nothing is duplicated on disk. Both copies are content-addressed under the
/// same `restore/<digest>` name, so identical bytes are one file, and a write
/// that displaces bytes the ledger already holds stores nothing at all.
///
/// # Errors
///
/// [`Error::Write`] when the snapshot cannot be stored. It is `fsync`ed, along
/// with the directory entry naming it, before this returns.
fn store_prior(state: &StateDir, observed: &Observed) -> Result<Prior, Error> {
    let PriorBytes::Bytes { bytes, mode } = observed.prior_bytes() else {
        return Ok(Prior::Absent);
    };
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let reference = RestoreRef {
        digest: ContentHash::of(&bytes),
        mode,
        len,
    };
    let path = state.restore().join(reference.blob_name());
    // The ledger's own blob store's test, the same function: a content-addressed
    // name holding the right number of bytes, as a one-link regular file, already
    // holds these bytes.
    if crate::state::blob_len(&path) != Some(len) {
        fs::write_atomically(&path, &bytes, Mode::PRIVATE_FILE)?;
    }
    Ok(Prior::Existed(reference))
}

/// Remove `path` if it is there, and `fsync` the directory it was in.
///
/// Absence is success: the whole recovery path is re-runnable, and a second run
/// finds what the first removed already gone. A missing directory is the same
/// absence, since nothing can be in it.
///
/// The directory is opened **before** the unlink and `fsync`ed after it, the
/// order `fs::write_atomically` keeps for a rename. Removing an entry needs
/// write and search permission on its directory, and opening the directory
/// needs read, so in a `0300` directory an open placed after the unlink fails
/// with the file already gone: an `Err` from a removal that happened. Opened
/// first, that failure happens while the file is still in place.
///
/// # Errors
///
/// [`Error::Io`] wrapping the failing `open` of the directory, `unlink`, or
/// `fsync`. Only a failing `fsync` is returned after the file was removed.
pub(crate) fn unlink(path: &Path) -> Result<(), Error> {
    // `Path::parent` of a bare name is the empty path, which names the current
    // directory the unlink resolves against, not a directory that is absent.
    let dir = path.parent().map(|dir| {
        if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        }
    });
    let opened = match dir {
        None => None,
        Some(dir) => match crate::fs::durable::Dir::open(dir) {
            Ok(handle) => Some((dir, handle)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(Error::Io {
                    path: dir.to_path_buf(),
                    source,
                });
            }
        },
    };
    match crate::fs::durable::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    if let Some((dir, handle)) = &opened {
        sync_dir(handle, dir)?;
    }
    Ok(())
}

/// Move a journal aside, durably, and never over one set aside earlier.
///
/// The name is the number after the highest of `journal.mpk.corrupt`,
/// `journal.mpk.corrupt.1`, … present — or, once the top number is present,
/// the lowest free one — taken with `RENAME_NOREPLACE` by
/// [`crate::state::move_aside`] under the state directory's
/// [`ExclusiveLock`]. A second set-aside therefore succeeds, and every earlier
/// one survives intact.
///
/// # Errors
///
/// [`Error::Io`] for the failing `open` of the directory, `rename` or `fsync`.
/// Only a failing `fsync` is returned after the journal was moved.
pub(crate) fn set_aside(path: &Path, lock: &ExclusiveLock) -> Result<PathBuf, Error> {
    // Opened before the rename, as `unlink` opens before its unlink: in a
    // directory that can be written but not read, an open placed after the
    // rename fails with the journal already moved aside.
    let dir = path
        .parent()
        .map(|dir| open_dir(dir).map(|handle| (dir, handle)))
        .transpose()?;
    let aside = crate::state::move_aside(path, lock).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some((dir, handle)) = &dir {
        sync_dir(handle, dir)?;
    }
    Ok(aside)
}

/// Remove directories bx created, deepest first, stopping at the first that is
/// not empty.
///
/// The stop is the point: a directory that has acquired anything else is no
/// longer only bx's, and removing it would delete something bx did not put
/// there. One that is no longer a directory at all stops the walk the same way.
///
/// # Errors
///
/// [`Error::Io`] for a failure that is neither "already gone", "not empty" nor
/// "not a directory".
pub(crate) fn prune_dirs(dirs: &[PathBuf]) -> Result<(), Error> {
    for dir in dirs {
        if !remove_if_empty(dir)? {
            break;
        }
    }
    Ok(())
}

/// Remove a directory bx created if it is empty, and say whether it is gone.
///
/// A path that is no longer a directory — a symlink the user put in its
/// place, or a file where it or one of its parents was — still stands, and is
/// no longer bx's: it is left, as [`hand_off_claims`] leaves it. `rmdir` never
/// follows its last component, so that is decided by the one call that would
/// otherwise remove it, with no window between a look and the removal.
///
/// # Errors
///
/// [`Error::Io`] for a failure that is neither "already gone", "not empty" nor
/// "not a directory".
fn remove_if_empty(dir: &Path) -> Result<bool, Error> {
    match std::fs::remove_dir(dir) {
        Ok(()) => {
            tracing::debug!(dir = %dir.display(), "removed a directory bx created");
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        // `ENOTEMPTY` and `EEXIST` are both permitted spellings of "it is
        // not empty", and `std::io::ErrorKind` maps neither stably.
        Err(e)
            if matches!(
                e.raw_os_error().map(rustix::io::Errno::from_raw_os_error),
                Some(rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST)
            ) =>
        {
            Ok(false)
        }
        Err(e)
            if e.raw_os_error().map(rustix::io::Errno::from_raw_os_error)
                == Some(rustix::io::Errno::NOTDIR) =>
        {
            tracing::debug!(
                dir = %dir.display(),
                "left a directory bx created that is no longer a directory",
            );
            Ok(false)
        }
        Err(source) => Err(Error::Io {
            path: dir.to_path_buf(),
            source,
        }),
    }
}

/// Remove each of `dirs` that is empty and that no entry `ledger` holds names,
/// deepest first.
///
/// `dirs` are claims — possibly several targets' — so unlike [`prune_dirs`] a
/// directory that is not empty does not stop the walk: it is skipped and the
/// rest are tried. Its parents are not empty either, so they stay too. A claim
/// that is no longer a directory is skipped the same way, and dropped with its
/// target. A directory an entry names is somebody's target, whoever claimed
/// it, and is never removed here.
///
/// # Errors
///
/// [`Error::Io`] for a failure that is neither "already gone", "not empty" nor
/// "not a directory".
pub(crate) fn prune_claims<'a>(
    ledger: &LedgerView,
    home: &Path,
    dirs: impl IntoIterator<Item = &'a PathBuf>,
) -> Result<(), Error> {
    let named: std::collections::HashSet<PathBuf> =
        ledger.iter().map(|(path, _)| path.render(home)).collect();
    let mut dirs: Vec<&PathBuf> = dirs.into_iter().collect();
    dirs.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| a.cmp(b))
    });
    dirs.dedup();
    for dir in dirs {
        if !named.contains(dir) {
            remove_if_empty(dir)?;
        }
    }
    Ok(())
}

/// Give each claimed directory that still stands to an entry `ledger` holds
/// beneath it, so the `rm` that removes that entry prunes it.
///
/// The heir is the first entry, in the ledger's own order, whose target is
/// strictly inside the directory. A directory no entry is beneath — one only
/// the user's files keep — is claimed by nobody from here on, and stays. The
/// claim is merged by [`crate::state::Ledger::record`] with the heir's digest,
/// mode and mechanism as they are and no prior, which keeps the stored prior
/// and every superseded snapshot.
///
/// Bookkeeping only: no destination is touched. [`crate::recover`] runs the
/// same hand-off when it rebuilds a terminated journal's ledger, so a crash
/// between the `End` frame and the save loses no claim.
///
/// # Errors
///
/// [`Error::State`] when the ledger refuses the re-record, and
/// [`Error::Write`] for a directory that cannot be made portable.
pub(crate) fn hand_off_claims<'a>(
    ledger: &mut Ledger,
    home: &Path,
    dirs: impl IntoIterator<Item = &'a PathBuf>,
) -> Result<(), Error> {
    let mut dirs: Vec<&PathBuf> = dirs.into_iter().collect();
    dirs.sort();
    dirs.dedup();
    for dir in dirs {
        if !std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()) {
            continue;
        }
        let Some(heir) = ledger
            .iter()
            .find(|(path, _)| {
                let at = path.render(home);
                at != *dir && at.starts_with(dir)
            })
            .map(|(_, entry)| entry.clone())
        else {
            continue;
        };
        let claim = Portable::from_path(dir, home).map_err(|source| fs::Error::NotPortable {
            path: dir.clone(),
            source,
        })?;
        if heir.created_dirs.contains(&claim) {
            continue;
        }
        tracing::debug!(
            dir = %dir.display(),
            heir = %heir.path,
            "handed a directory bx created to an entry still beneath it",
        );
        ledger.record(
            NewEntry::new(heir.path, heir.written, heir.mode, heir.mechanism)
                .with_created_dirs(vec![claim]),
        )?;
    }
    Ok(())
}

/// Refuse unless `now` is still what `planned` observed: the same path, the
/// same kind and the same stamp, or still nothing at all.
///
/// # Errors
///
/// [`Error::Write`] with [`crate::fs::Error::Changed`] naming what moved.
fn refuse_moved(planned: &Observed, now: &Observed) -> Result<(), Error> {
    if planned.path != now.path {
        return Err(fs::Error::Changed {
            path: now.path.clone(),
            detail: format!("plan observed {}, not this path", planned.path.display()),
        }
        .into());
    }
    if (planned.kind, planned.stamp) == (now.kind, now.stamp) {
        return Ok(());
    }
    let detail = match (planned.stamp, now.stamp) {
        (_, None) => "it has been removed",
        (None, Some(_)) => "nothing was there, and something is now",
        (Some(_), Some(_)) => "it has been modified or replaced",
    };
    Err(fs::Error::Changed {
        path: now.path.clone(),
        detail: detail.to_string(),
    }
    .into())
}

/// Open a directory so that a rename or an unlink inside it can be made
/// durable.
///
/// Call it **before** that operation and [`sync_dir`] after, never the two
/// together afterwards: an open that fails after the operation reports an
/// error for a change that has already happened. See [`unlink`].
///
/// # Errors
///
/// [`Error::Io`] naming `dir` for the failing `open`.
pub(crate) fn open_dir(dir: &Path) -> Result<crate::fs::durable::Dir, Error> {
    crate::fs::durable::Dir::open(dir).map_err(|source| Error::Io {
        path: dir.to_path_buf(),
        source,
    })
}

/// `fsync` a directory [`open_dir`] opened, so a rename or an unlink made
/// inside it since survives a power loss.
///
/// # Errors
///
/// [`Error::Io`] naming `dir` for the failing `fsync`.
pub(crate) fn sync_dir(handle: &crate::fs::durable::Dir, dir: &Path) -> Result<(), Error> {
    handle.sync().map_err(|source| Error::Io {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    use crate::state::{LedgerView, Prior};
    use crate::testing::guarded_home;

    /// A target under `home`, both halves of it.
    pub(crate) fn target(home: &Path, rel: &str) -> (Portable, PathBuf) {
        let dest = home.join(rel);
        (Portable::from_path(&dest, home).expect("portable"), dest)
    }

    /// A write request for `rel` under `home`, carrying what is there now as
    /// plan's observation.
    pub(crate) fn write_to(home: &Path, rel: &str, bytes: &str, mode: Mode) -> Request {
        let (target, dest) = target(home, rel);
        // Observed when the request is built, as plan observes before anything
        // is applied.
        let planned = fs::observe(&dest).expect("plan's observation");
        Request {
            target,
            dest,
            content: Content::Bytes {
                bytes: bytes.as_bytes().to_vec(),
                planned,
            },
            mode,
            ownership: Ownership::Owned(Mechanism::Own),
        }
    }

    /// Create a file at exactly `mode`, parents included.
    pub(crate) fn plant_file(path: &Path, bytes: &str, mode: Mode) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("the fixture's parents");
        }
        std::fs::write(path, bytes).expect("the fixture");
        fs::set_mode(path, mode).expect("the fixture's mode");
    }

    /// The bytes and mode at `path`, or `None` when nothing is there.
    pub(crate) fn peek(path: &Path) -> Option<(Vec<u8>, Mode)> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        let bytes = std::fs::read(path).expect("a readable fixture");
        Some((bytes, Mode::from_bits(meta.permissions().mode())))
    }

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
    fn the_journal_is_created_whole_at_0600_and_replaces_whatever_was_there() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        plant_file(&path, "not a journal at all", Mode::DEFAULT_FILE);

        let journal = Journal::create(&path, some_begin()).expect("create");
        assert_eq!(journal.path(), path);
        let (bytes, mode) = peek(&path).expect("the journal");
        assert_eq!(mode, Mode::PRIVATE_FILE);
        assert!(bytes.starts_with(MAGIC), "the previous bytes are gone");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unterminated(vec![Record::Begin(some_begin())]),
            "and it exists whole, header and Begin, from its first instant",
        );
    }

    #[test]
    fn a_fresh_state_directory_has_no_session() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        assert_eq!(load(&state.journal()).expect("load"), Loaded::Absent);
    }

    #[test]
    fn a_journal_with_a_bad_header_is_moved_aside_by_the_lock_holder_and_read_as_absent() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        plant_file(&path, "GARBAGE!", Mode::PRIVATE_FILE);

        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None },
            "a read without the lock moves nothing",
        );
        assert!(path.is_file());

        let loaded = load_exclusive(&path, &lock).expect("load");
        let Loaded::Unreadable { moved_to } = &loaded else {
            panic!("expected Unreadable, got {loaded:?}")
        };
        let aside = moved_to.as_ref().expect("it should have been moved aside");
        assert_eq!(aside, &StateDir::quarantine(&path));
        assert!(!path.exists(), "the damaged journal is out of the way");
        assert_eq!(
            std::fs::read(aside).expect("the quarantined bytes"),
            b"GARBAGE!",
            "the bytes are kept, never deleted",
        );
        assert!(loaded.records().is_empty());
        assert!(!loaded.is_interrupted(), "it is read exactly as absent");
    }

    #[test]
    fn a_short_journal_that_is_not_the_start_of_a_header_is_unreadable() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        // Too short for a header, like a torn one, but not a prefix of one.
        plant_file(&path, "BY", Mode::PRIVATE_FILE);
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unreadable { .. }
        ));
    }

    #[test]
    fn a_journal_from_a_future_format_is_refused_and_never_moved_aside() {
        // Review round 5, item 2. It read as `Unreadable`, and the lock holder
        // set it aside with nothing rolled back.
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        drop(Journal::create(&path, some_begin()).expect("create"));
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[MAGIC.len()] = FORMAT + 1;
        std::fs::write(&path, &bytes).expect("write");

        for (how, loaded) in [
            ("load", load(&path)),
            ("load_exclusive", load_exclusive(&path, &lock)),
        ] {
            let err = loaded.expect_err(how);
            let Error::FutureVersion {
                path: named,
                found,
                supported,
            } = &err
            else {
                panic!("{how}: {err}")
            };
            assert_eq!((named, *found, *supported), (&path, FORMAT + 1, FORMAT));
            assert!(
                err.to_string().contains("run a bx at least as new"),
                "{err}"
            );
        }
        assert_eq!(std::fs::read(&path).expect("left in place"), bytes);
        assert!(!StateDir::quarantine(&path).exists());
    }

    #[test]
    fn a_journal_from_an_older_format_is_unreadable() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT - 1);
        bytes.extend_from_slice(&[0; NONCE]);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_run_of_nul_bytes_is_not_a_valid_frame() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT);
        bytes.extend(std::iter::repeat_n(0_u8, 4096));
        std::fs::write(&path, &bytes).expect("write");

        // Nothing decodes, so the journal carries no information at all.
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unreadable { .. }
        ));
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
    fn nul_bytes_after_a_whole_frame_are_a_torn_tail() {
        // Review round 4, item 1. A filesystem that zero-fills an unsynced tail
        // after a power loss leaves them. Round 3 read that as damage and set
        // the journal aside with nothing rolled back; with no whole frame after
        // them they are the tail, and the whole frames before are kept.
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        drop(Journal::create(&path, some_begin()).expect("create"));

        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend(std::iter::repeat_n(0_u8, 512));
        std::fs::write(&path, &bytes).expect("write");

        let torn = Loaded::Torn {
            records: vec![Record::Begin(some_begin())],
            discarded: 512,
        };
        assert_eq!(load(&path).expect("load"), torn);
        assert_eq!(load_exclusive(&path, &lock).expect("load"), torn);
        assert_eq!(
            std::fs::read(&path).expect("left for recovery"),
            bytes,
            "the lock holder does not set a torn journal aside before recovery rolls it back",
        );
    }

    #[test]
    fn a_damaged_frame_is_a_torn_tail_only_when_no_whole_frame_follows_it() {
        // Review round 4, item 1. Only the last frame can be unsynced, so a
        // damaged last frame is what a power loss leaves, and a damaged frame
        // with a whole one after it is what no crash leaves.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let done = |rel: &str| {
            Record::Done(Done {
                target: Portable::try_from(format!("~/{rel}")).expect("portable"),
            })
        };
        let mut journal = Journal::create(&path, some_begin()).expect("create");
        journal.append(&done(".a")).expect("append");
        journal.append(&done(".b")).expect("append");
        drop(journal);
        let whole = std::fs::read(&path).expect("read");
        let starts = frame_starts(&whole);
        let last = starts[2];

        // The last frame's body, one byte flipped: its checksum fails.
        let mut flipped = whole.clone();
        flipped[whole.len() - 1] ^= 0x01;
        // The last frame zero-filled in place, length and checksum included.
        let mut zeroed = whole.clone();
        zeroed[last..].fill(0);
        for (case, bytes) in [("flipped", flipped), ("zeroed", zeroed)] {
            std::fs::write(&path, &bytes).expect("write");
            assert_eq!(
                load(&path).expect("load"),
                Loaded::Torn {
                    records: vec![Record::Begin(some_begin()), done(".a")],
                    discarded: whole.len() - last,
                },
                "{case}",
            );
        }

        // The middle frame's body, one byte flipped: `.b` is whole after it.
        let mut middle = whole.clone();
        middle[last - 1] ^= 0x01;
        std::fs::write(&path, &middle).expect("write");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_header_with_nothing_after_it_is_an_empty_interrupted_session() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut header = MAGIC.to_vec();
        header.push(FORMAT);
        std::fs::write(&path, &header).expect("write");
        assert_eq!(load(&path).expect("load"), Loaded::Unterminated(Vec::new()));
    }

    #[test]
    fn a_journal_without_an_end_record_is_an_interrupted_session() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect("apply");
        // Dropped, never finished: an abandoned session *is* an interrupted one.
        drop(session);

        let loaded = load(&state.journal()).expect("load");
        assert!(loaded.is_interrupted());
        assert!(matches!(loaded, Loaded::Unterminated(_)));
        assert_eq!(loaded.intents().count(), 1);
        assert_eq!(loaded.begin().expect("a header").kind, SessionKind::Apply);
    }

    #[test]
    fn a_session_that_finishes_leaves_no_journal_and_a_saved_ledger() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        assert!(
            state.journal().exists(),
            "the journal exists while in flight"
        );
        assert!(
            !state.ledger().exists(),
            "the ledger is not saved until the session ends",
        );

        session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect("apply");
        assert_eq!(session.written(), 1);
        assert!(
            !state.ledger().exists(),
            "still not saved: a rollback must find the ledger as it was",
        );
        assert_eq!(session.finish().expect("finish"), 1);

        assert!(!state.journal().exists(), "unlinked last");
        assert_eq!(load(&state.journal()).expect("load"), Loaded::Absent);
        let ledger = LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value;
        let (portable, _) = target(home.path(), ".conf");
        assert_eq!(
            ledger.get(&portable).expect("an entry").mode,
            Mode::DEFAULT_FILE,
        );
    }

    #[test]
    fn a_journal_truncated_at_any_byte_offset_keeps_every_whole_frame() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let source = dir.path().join("source.mpk");
        let records = [
            Record::Begin(Begin {
                kind: SessionKind::Apply,
                home: PathBuf::from("/home/someone"),
                scope: vec![Portable::try_from("~/.a".to_string()).expect("portable")],
            }),
            Record::Done(Done {
                target: Portable::try_from("~/.a".to_string()).expect("portable"),
            }),
            Record::Done(Done {
                target: Portable::try_from("~/.b".to_string()).expect("portable"),
            }),
            Record::End(End { written: 2 }),
        ];

        // Record the file length after each frame, so "every whole frame" is an
        // exact expectation rather than an approximation.
        let Record::Begin(begin) = &records[0] else {
            unreachable!("the first record is the header")
        };
        let mut journal = Journal::create(&source, begin.clone()).expect("create");
        let mut boundaries: Vec<usize> = Vec::new();
        for (at, record) in records.iter().enumerate() {
            if at > 0 {
                journal.append(record).expect("append");
            }
            boundaries.push(
                std::fs::metadata(&source)
                    .expect("stat")
                    .len()
                    .try_into()
                    .expect("a small journal"),
            );
        }
        drop(journal);
        let whole: Vec<u8> = std::fs::read(&source).expect("read");

        for cut in 0..=whole.len() {
            let path = dir.path().join(format!("cut-{cut}.mpk"));
            std::fs::write(&path, &whole[..cut]).expect("write");
            let loaded = load(&path).expect("load");

            // A cut inside the header is a session that wrote nothing. A cut
            // inside the Begin is damage no crash leaves, because the journal is
            // created whole. A cut anywhere later keeps every whole frame, and
            // says how much it discarded.
            let kept: usize = boundaries.iter().filter(|end| **end <= cut).count();
            let expected = if cut <= HEADER {
                Loaded::Unterminated(Vec::new())
            } else if kept == 0 {
                Loaded::Unreadable { moved_to: None }
            } else if kept == records.len() {
                Loaded::Terminated(records.to_vec())
            } else if boundaries[kept - 1] == cut {
                Loaded::Unterminated(records[..kept].to_vec())
            } else {
                Loaded::Torn {
                    records: records[..kept].to_vec(),
                    discarded: cut - boundaries[kept - 1],
                }
            };
            assert_eq!(loaded, expected, "cut at {cut}");
        }
    }

    #[test]
    fn opening_a_session_over_an_unresolved_interruption_is_refused() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        drop(session);

        let err = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect_err("a session over an interruption must be refused");
        let Error::InProgress { path } = &err else {
            panic!("got {err}")
        };
        assert_eq!(path, &state.journal());
        assert!(err.to_string().contains("recovered"));
    }

    #[test]
    fn a_session_holds_the_state_lock_for_its_whole_life() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_none(),
            "the session holds the exclusive lock",
        );
        assert_eq!(session.state(), &state);
        assert_eq!(session.home(), home.path());
        assert_eq!(session.journal(), state.journal());
        drop(session);
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_some(),
            "dropping the session releases it",
        );
    }

    #[test]
    fn two_identical_sessions_produce_journals_that_differ_only_in_temp_paths() {
        let home = guarded_home();
        let dest = home.child(".conf");

        let run = |root: &str| -> Vec<Record> {
            plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
            let state = StateDir::new(home.child(root));
            let mut session =
                Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
            session
                .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
                .expect("apply");
            drop(session);
            load(&state.journal()).expect("load").records().to_vec()
        };

        let mut first = run("one");
        let mut second = run("two");
        // The staged temporary file's name is random, by construction: entry A5
        // chooses it and the intent records the path it chose, so recovery can
        // remove exactly that file and nothing else. Everything else is fixed —
        // no timestamp, no identifier, no hash-map iteration order.
        for records in [&mut first, &mut second] {
            for record in records.iter_mut() {
                if let Record::Intent(intent) = record {
                    let temp = intent.temp.take().expect("a write stages a temp file");
                    assert!(
                        temp.file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.starts_with(fs::TEMP_PREFIX)),
                        "{} should be an attributable bx temporary file",
                        temp.display(),
                    );
                    assert_eq!(
                        temp.parent(),
                        dest.parent(),
                        "staged beside the destination"
                    );
                }
            }
        }
        assert_eq!(first, second);
    }

    #[test]
    fn a_write_records_the_prior_bytes_and_the_created_directories() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect("apply");
        session
            .apply(write_to(
                home.path(),
                ".config/deep/new.conf",
                "made\n",
                Mode::PRIVATE_FILE,
            ))
            .expect("apply");
        drop(session);

        let loaded = load(&state.journal()).expect("load");
        let intents: Vec<&Intent> = loaded.intents().collect();
        assert_eq!(intents.len(), 2);

        assert!(!intents[0].creates());
        let Prior::Existed(reference) = &intents[0].before else {
            panic!("the first write displaced a file")
        };
        assert_eq!(reference.digest, ContentHash::of(b"old\n"));
        assert_eq!(reference.mode, Mode::DEFAULT_FILE);
        assert_eq!(
            intents[0].after,
            Written::Present {
                digest: ContentHash::of(b"new\n"),
                mode: Mode::DEFAULT_FILE,
            },
        );
        assert!(intents[0].created_dirs.is_empty());
        assert_eq!(intents[0].mechanism, Some(Mechanism::Own));

        assert!(intents[1].creates());
        assert_eq!(
            intents[1].created_dirs,
            vec![home.child(".config/deep"), home.child(".config")],
            "deepest first, which is the order a reversal removes them in",
        );
        // The prior bytes are durable in `restore/` before the rename, so the
        // rollback a crash needs can always complete.
        assert!(
            state.restore().join(reference.digest.to_hex()).is_file(),
            "the displaced bytes are content-addressed in restore/",
        );
    }

    #[test]
    fn a_repeat_write_records_the_bytes_it_displaced_not_the_ledgers_first_prior() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "the user's\n", Mode::DEFAULT_FILE);
        let (portable, _) = target(home.path(), ".conf");

        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(home.path(), ".conf", "one\n", Mode::DEFAULT_FILE))
            .expect("apply");
        first.finish().expect("finish");

        let mut second =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        second
            .apply(write_to(home.path(), ".conf", "two\n", Mode::DEFAULT_FILE))
            .expect("apply");
        drop(second);

        // The ledger answers "what did the user have before bx?" and keeps the
        // first prior. The journal answers "what was on disk a moment ago?" and
        // must not, or a rollback would compare the destination against a state
        // it has not been in since the first apply.
        let entry = LedgerView::read(&state, home.path())
            .expect("read")
            .value
            .get(&portable)
            .cloned()
            .expect("managed");
        let Prior::Existed(first_prior) = &entry.prior else {
            panic!("the ledger keeps the user's original")
        };
        assert_eq!(first_prior.digest, ContentHash::of(b"the user's\n"));

        let loaded = load(&state.journal()).expect("load");
        let Prior::Existed(displaced) = &loaded.intents().next().expect("one intent").before else {
            panic!("the second write displaced a file")
        };
        assert_eq!(
            displaced.digest,
            ContentHash::of(b"one\n"),
            "the rollback snapshot is bx's own previous output",
        );
        assert!(
            state.restore().join(displaced.blob_name()).is_file(),
            "and it is durable, whatever the ledger decided to keep",
        );
    }

    #[test]
    fn a_released_target_leaves_its_prior_bytes_behind_but_no_ledger_entry() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "mine\n", Mode::DEFAULT_FILE);
        let (portable, dest) = target(home.path(), ".conf");

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(Request {
                target: portable.clone(),
                content: Content::Bytes {
                    bytes: b"yours\n".to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                dest,
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect("apply");
        assert!(session.ledger().get(&portable).is_none());
        session.finish().expect("finish");

        assert!(
            LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .is_none()
        );
        assert!(
            state
                .restore()
                .join(ContentHash::of(b"mine\n").to_hex())
                .is_file(),
            "the bytes an interrupted release would be rolled back to are durable",
        );
    }

    #[test]
    fn a_removal_takes_the_file_and_the_directories_bx_created() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".config/deep/made.conf");
        plant_file(&dest, "bx wrote this\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(Request {
                target: portable,
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: vec![home.child(".config/deep"), home.child(".config")],
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect("apply");
        session.finish().expect("finish");

        assert!(!dest.exists(), "removed, not truncated");
        assert!(!home.child(".config/deep").exists());
        assert!(!home.child(".config").exists());
        assert!(
            state
                .restore()
                .join(ContentHash::of(b"bx wrote this\n").to_hex())
                .is_file(),
        );
    }

    #[test]
    fn removing_a_destination_that_is_already_gone_is_not_an_error() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".never-there");

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(Request {
                target: portable,
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: Vec::new(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect("apply");
        drop(session);

        let loaded = load(&state.journal()).expect("load");
        let intents: Vec<&Intent> = loaded.intents().collect();
        assert_eq!(intents[0].before, Prior::Absent);
        assert_eq!(intents[0].after, Written::Absent);
    }

    #[test]
    fn a_directory_that_is_not_empty_stops_the_pruning() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let deep = dir.path().join("a/b/c");
        std::fs::create_dir_all(&deep).expect("mkdir");
        std::fs::write(dir.path().join("a/b/kept"), "the user's").expect("write");

        prune_dirs(&[deep.clone(), dir.path().join("a/b"), dir.path().join("a")]).expect("prune");

        assert!(!deep.exists(), "the empty leaf went");
        assert!(dir.path().join("a/b").is_dir(), "the non-empty one stayed");
        assert!(dir.path().join("a").is_dir(), "and the walk stopped there");
    }

    #[test]
    fn pruning_a_directory_that_is_already_gone_is_not_an_error() {
        let dir = tempfile::tempdir().expect("a tempdir");
        prune_dirs(&[dir.path().join("never-existed")]).expect("prune");
        unlink(&dir.path().join("never-there")).expect("unlink");
        // Opening the directory first must not turn a missing one into an error.
        unlink(&dir.path().join("gone/never-there")).expect("unlink in a missing directory");
    }

    #[test]
    fn a_removal_opens_its_directory_before_the_unlink_and_syncs_it_after() {
        // The order `fs::write_atomically` keeps for a rename, observed: the
        // directory handle exists before the file goes, and the sync follows.
        use crate::fs::durable::{Event, recording};

        let dir = tempfile::tempdir().expect("a tempdir");
        let file = dir.path().join("f");
        plant_file(&file, "x\n", Mode::DEFAULT_FILE);

        let (removed, events) = recording(|| unlink(&file));
        removed.expect("unlink");

        assert_eq!(
            events,
            [
                Event::OpenDir(dir.path().to_path_buf()),
                Event::Unlink(file.clone()),
                Event::SyncDir(dir.path().to_path_buf()),
            ],
        );
        assert!(!file.exists());
    }

    #[test]
    fn a_directory_that_cannot_be_opened_fails_a_removal_before_the_file_goes() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let dir = tempfile::tempdir().expect("a tempdir");
        let file = dir.path().join("f");
        plant_file(&file, "the user's\n", Mode::DEFAULT_FILE);
        // Write and search, no read: the file can be unlinked, and the directory
        // cannot be opened to fsync the unlink.
        fs::set_mode(dir.path(), Mode::from_bits(0o300)).expect("chmod");

        let result = unlink(&file);
        fs::set_mode(dir.path(), Mode::PRIVATE_DIR).expect("unlock for cleanup");

        match result {
            Err(Error::Io { path, source }) => {
                assert_eq!(path, dir.path());
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected an io error naming the directory, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&file).expect("the file is still there"),
            b"the user's\n",
            "an Err means the removal did not happen",
        );
    }

    #[test]
    fn a_session_will_not_write_through_a_symlink_the_user_made() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child("real"), "real\n", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink(home.child("real"), home.child(".conf")).expect("symlink");

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let err = session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect_err("a symlink must be refused");
        assert!(
            matches!(err, Error::Write(fs::Error::Symlink(_))),
            "got {err}",
        );

        // A refused write poisons its session, so the removal is refused in a
        // session of its own.
        let other = StateDir::new(home.child("other-state"));
        let mut session =
            Session::open(&other, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let err = session
            .apply(Request {
                target: target(home.path(), ".conf").0,
                dest: home.child(".conf"),
                content: Content::Absent {
                    created_dirs: Vec::new(),
                    planned: fs::observe(&home.child(".conf")).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect_err("and so must a removal of one");
        assert!(
            matches!(err, Error::Write(fs::Error::NotAFile { .. })),
            "got {err}",
        );
    }

    #[test]
    fn the_intent_is_synced_before_the_destination_is_renamed_over() {
        // The whole ordering rule, observed rather than asserted: the frame that
        // announces a write is durable before the rename makes the write, and
        // the frame that says it landed comes after.
        use crate::fs::durable::{Event, recording};

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        let journal = state.journal();

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let (applied, events) = recording(|| {
            session.apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
        });
        applied.expect("apply");
        session.finish().expect("finish");

        let journal_syncs: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| matches!(event, Event::SyncFile(path) if *path == journal))
            .map(|(at, _)| at)
            .collect();
        let rename = events
            .iter()
            .position(|event| matches!(event, Event::Rename { to, .. } if *to == dest))
            .expect("the destination is renamed over");
        assert_eq!(
            journal_syncs.len(),
            2,
            "the Intent and the Done frames are each synced: {events:#?}",
        );
        assert!(
            journal_syncs[0] < rename,
            "the Intent is durable before the rename: {events:#?}",
        );
        assert!(
            journal_syncs[1] > rename,
            "the Done frame follows the rename: {events:#?}",
        );
    }

    #[test]
    fn the_intent_is_synced_before_a_removal_unlinks_the_destination() {
        use crate::fs::durable::{Event, recording};

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let rel = ".config/made/x.conf";
        let dest = home.child(rel);
        let journal = state.journal();

        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(home.path(), rel, "x\n", Mode::DEFAULT_FILE))
            .expect("apply");
        first.finish().expect("finish");

        let mut second =
            Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
        let (removed, events) = recording(|| {
            second.apply(Request {
                target: target(home.path(), rel).0,
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: vec![home.child(".config/made"), home.child(".config")],
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
        });
        removed.expect("remove");
        second.finish().expect("finish");

        let intent_sync = events
            .iter()
            .position(|event| matches!(event, Event::SyncFile(path) if *path == journal))
            .expect("the Intent frame is synced");
        let unlink = events
            .iter()
            .position(|event| matches!(event, Event::Unlink(path) if *path == dest))
            .expect("the destination is unlinked");
        let parent_sync = events
            .iter()
            .position(
                |event| matches!(event, Event::SyncDir(dir) if *dir == home.child(".config/made")),
            )
            .expect("the unlink is made durable");
        assert!(
            intent_sync < unlink,
            "the Intent is durable before the unlink: {events:#?}",
        );
        assert!(
            unlink < parent_sync,
            "the directory is synced after the unlink: {events:#?}",
        );
        assert!(!dest.exists());
    }

    /// A journal header for a session under `home`.
    fn begin_under(home: &Path, scope: Vec<Portable>) -> Record {
        Record::Begin(Begin {
            kind: SessionKind::Apply,
            home: home.to_path_buf(),
            scope,
        })
    }

    /// `rel` under `home`, spelled absolutely: well-formed, so it decodes.
    fn absolute_under(home: &Path, rel: &str) -> Portable {
        Portable::from_path(&home.join(rel), Path::new("/nonexistent/other/home"))
            .expect("an absolute portable path")
    }

    #[test]
    fn a_journal_naming_an_absolute_path_under_its_home_never_drives_a_rollback() {
        // #4's decision R3-1, for the journal. Believed, this journal says bx
        // created `.gitconfig` and the file there is bx's: an unterminated
        // session, so recovery would unlink the user's file.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let dest = home.child(".gitconfig");
        plant_file(&dest, "[user]\n", Mode::DEFAULT_FILE);
        let path = state.journal();
        let foreign = absolute_under(home.path(), ".gitconfig");
        raw_journal(
            &path,
            &[
                begin_under(home.path(), Vec::new()),
                Record::Intent(Intent {
                    target: foreign,
                    dest: dest.clone(),
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Present {
                        digest: ContentHash::of(b"[user]\n"),
                        mode: Mode::DEFAULT_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                }),
            ],
        );
        let bytes = std::fs::read(&path).expect("the journal");

        // Unlocked: unreadable, and left exactly where it is.
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
        assert_eq!(std::fs::read(&path).expect("still there"), bytes);
        assert!(
            crate::recover::pending(&state)
                .expect("pending")
                .expect("reported")
                .unreadable
        );

        // Under the lock: set aside with its bytes kept, and nothing rolled back.
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::Nothing,
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine(&path)).expect("kept, not deleted"),
            bytes
        );
        assert!(!path.exists());
        assert_eq!(
            peek(&dest),
            Some((b"[user]\n".to_vec(), Mode::DEFAULT_FILE)),
            "the user's file is untouched",
        );
    }

    #[test]
    fn every_stored_path_in_a_journal_is_checked_against_its_home() {
        let home = guarded_home();
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let ours = target(home.path(), ".conf").0;
        let foreign = absolute_under(home.path(), ".conf");

        for (why, records) in [
            (
                "a scope entry",
                vec![begin_under(home.path(), vec![foreign.clone()])],
            ),
            (
                "a Done target",
                vec![
                    begin_under(home.path(), Vec::new()),
                    Record::Done(Done {
                        target: foreign.clone(),
                    }),
                ],
            ),
            (
                "the header's own home",
                vec![begin_under(Path::new("relative/home"), vec![ours.clone()])],
            ),
        ] {
            raw_journal(&path, &records);
            assert_eq!(
                load(&path).expect("load"),
                Loaded::Unreadable { moved_to: None },
                "{why}",
            );
        }

        // A path genuinely outside the home, and the ~/ spelling, still load.
        let outside = Portable::try_from("/etc/bx-example.conf".to_string()).expect("absolute");
        let records = vec![
            begin_under(home.path(), vec![ours.clone(), outside.clone()]),
            Record::Done(Done { target: outside }),
            Record::Done(Done { target: ours }),
        ];
        raw_journal(&path, &records);
        assert_eq!(load(&path).expect("load"), Loaded::Unterminated(records));
    }

    #[test]
    fn a_request_whose_destination_is_not_where_its_target_renders_is_refused() {
        // Review round 3, item 2. The loader refuses such a journal, so a
        // session that wrote one would leave an interruption nothing recovers.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut request = write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE);
        request.dest = home.child(".elsewhere");

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let refused = session.apply(request).expect_err("refused");
        assert!(matches!(refused, Error::Misplaced { .. }), "got {refused}");
        assert!(!home.child(".elsewhere").exists());
        assert!(!home.child(".conf").exists());
        assert!(matches!(
            session.apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)),
            Err(Error::Poisoned { .. }),
        ));
        drop(session);
        assert_eq!(
            load(&state.journal()).expect("load").intents().count(),
            0,
            "nothing was journalled",
        );
    }

    #[test]
    fn a_journal_that_writes_one_target_twice_is_unreadable() {
        let home = guarded_home();
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let (target, dest) = target(home.path(), ".conf");
        let intent = Intent {
            target: target.clone(),
            dest,
            temp: None,
            before: Prior::Absent,
            after: Written::Absent,
            created_dirs: Vec::new(),
            mechanism: None,
            ledger_written: None,
        };
        let once = vec![
            Record::Begin(Begin {
                kind: SessionKind::Apply,
                home: home.path().to_path_buf(),
                scope: Vec::new(),
            }),
            Record::Intent(intent.clone()),
            Record::Done(Done {
                target: target.clone(),
            }),
        ];
        raw_journal(&path, &once);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unterminated(once.clone())
        );

        let mut twice = once;
        twice.push(Record::Intent(intent));
        raw_journal(&path, &twice);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_journal_with_a_second_session_header_is_unreadable() {
        // r3 coverage C5.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let begin = Record::Begin(some_begin());
        raw_journal(&path, &[begin.clone(), begin]);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn an_unreadable_journal_is_never_set_aside_over_an_earlier_one() {
        // Review round 3, item 5. The set-aside name was fixed, and opening a
        // session renamed the unreadable journal over the earlier one. Round 3
        // refused the session instead; since #7's numbered names integrated,
        // the journal takes the next free name and the session opens.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let aside = StateDir::quarantine(&state.journal());
        std::fs::write(&aside, b"the first").expect("a journal set aside earlier");
        std::fs::write(state.journal(), b"GARBAGE!").expect("an unreadable journal");

        let session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect("the unreadable journal is set aside and the session opens");
        assert_eq!(std::fs::read(&aside).expect("kept"), b"the first");
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&state.journal(), 1)).expect("set aside"),
            b"GARBAGE!",
        );
        drop(session);
    }

    #[test]
    fn a_crash_point_round_trips_through_its_spelling() {
        // The spellings are the seam's whole interface: the harness that drives
        // it passes `<index>:<phase>` to a child process, so a rename that broke
        // this would make the harness silently stop crashing anything.
        for (index, phase) in crash_phases().iter().enumerate() {
            assert_eq!(
                Crash::parse(&format!("{index}:{phase}")),
                Some((index, PHASES[index])),
            );
        }
        for (index, phase) in finish_crash_phases().iter().enumerate() {
            assert_eq!(
                Crash::parse(&format!("{index}:{phase}")),
                Some((index, FINISH_PHASES[index])),
            );
        }
        assert_eq!(Crash::parse("not a crash point"), None);
        assert_eq!(Crash::parse("0:no-such-phase"), None);
        assert_eq!(Crash::parse("x:after-fill"), None);
        // Nothing set this process's variable, so a session here never aborts.
        assert_eq!(Crash::from_env(), Crash { at: None });
    }

    #[test]
    fn a_journal_that_ends_with_an_end_record_is_terminated() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let begin = Record::Begin(some_begin());
        drop(Journal::create(&path, some_begin()).expect("create"));
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unterminated(_)
        ));

        seal(&path, 0);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Terminated(vec![begin, Record::End(End { written: 0 })]),
        );
    }

    #[test]
    fn a_zero_byte_journal_is_an_empty_interrupted_session_and_stays_in_place() {
        // What a crash between creating the file and writing its header used to
        // leave. It records no write, so it is an empty interrupted session -
        // never corruption - even for the lock holder, the only reader that
        // could move it.
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        std::fs::write(&path, b"").expect("write");

        assert_eq!(
            load_exclusive(&path, &lock).expect("load"),
            Loaded::Unterminated(Vec::new()),
        );
        assert!(path.is_file(), "left exactly where it was");
        assert!(
            !StateDir::quarantine(&path).exists(),
            "and nothing was set aside",
        );
    }

    #[test]
    fn a_torn_header_is_an_empty_session_and_a_torn_first_frame_is_set_aside() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().join("state"));
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let whole = dir.path().join("whole.mpk");
        drop(Journal::create(&whole, some_begin()).expect("create"));
        let bytes = std::fs::read(&whole).expect("read");

        // Every cut short of the first whole frame. Inside the header it is a
        // session that wrote nothing. Past the header it is damage: the header
        // and the first frame are renamed into place together, so no crash
        // leaves the one without the other whole.
        for cut in 0..bytes.len() {
            let path = state.root().join(format!("torn-{cut}.mpk"));
            std::fs::write(&path, &bytes[..cut]).expect("write");
            let aside = StateDir::quarantine(&path);
            let loaded = load_exclusive(&path, &lock).expect("load");
            if cut <= HEADER {
                assert_eq!(loaded, Loaded::Unterminated(Vec::new()), "a cut at {cut}");
                assert!(path.is_file(), "a cut at {cut} stays in place");
                assert!(!aside.exists());
            } else {
                assert_eq!(
                    loaded,
                    Loaded::Unreadable {
                        moved_to: Some(aside.clone())
                    },
                    "a cut at {cut}",
                );
                assert!(!path.exists(), "a cut at {cut} is set aside");
                assert_eq!(std::fs::read(&aside).expect("kept"), &bytes[..cut]);
            }
        }
    }

    #[test]
    fn creating_a_journal_replaces_its_name_and_never_truncates_a_file_in_place() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        plant_file(&path, "the previous file\n", Mode::PRIVATE_FILE);

        // A reader that opened the previous file before the create - `bx plan`
        // running unlocked beside an `apply` - goes on reading whole bytes. An
        // in-place truncate would hand it an emptied file instead.
        let mut earlier = File::open(&path).expect("open the previous file");
        let journal = Journal::create(&path, some_begin()).expect("create");
        let mut seen = String::new();
        std::io::Read::read_to_string(&mut earlier, &mut seen).expect("read");
        assert_eq!(seen, "the previous file\n");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unterminated(vec![Record::Begin(some_begin())]),
            "and the name holds the whole new journal, Begin and all",
        );
        drop(journal);
    }

    #[test]
    fn a_frame_appended_after_a_torn_one_is_hidden_from_recovery() {
        // Why a failed append has to end the session: a frame torn mid-write
        // stops the loader, so anything appended after it is invisible to
        // recovery - including the Intent for a write that then lands.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut journal = Journal::create(&path, some_begin()).expect("create");
        let after_begin = std::fs::read(&path).expect("read").len();
        journal
            .append(&Record::Done(Done {
                target: Portable::try_from("~/.torn".to_string()).expect("portable"),
            }))
            .expect("append");
        let after_torn = std::fs::read(&path).expect("read").len();
        journal
            .append(&Record::Done(Done {
                target: Portable::try_from("~/.hidden".to_string()).expect("portable"),
            }))
            .expect("append");
        drop(journal);

        let whole = std::fs::read(&path).expect("read");
        let mut torn = whole[..after_begin + (after_torn - after_begin) / 2].to_vec();
        torn.extend_from_slice(&whole[after_torn..]);
        std::fs::write(&path, &torn).expect("write");

        // With a checksum on every frame the loader also sees that what follows
        // the torn frame is not a frame: the later one stays invisible, and the
        // journal is unreadable rather than silently short.
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_failed_append_poisons_the_session() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let real = std::mem::replace(
            &mut session.journal.file,
            OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full"),
        );
        let err = session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect_err("a full disk fails the Intent append");
        assert!(matches!(err, Error::Io { .. }), "got {err}");
        assert_eq!(
            peek(&home.child(".conf")).expect("untouched").0,
            b"old\n",
            "nothing is published without its Intent",
        );

        // The disk has room again. A torn frame may now sit at the journal's
        // tail, and anything appended after it would be hidden from recovery, so
        // the session must append nothing more at all.
        session.journal.file = real;
        let err = session
            .apply(write_to(home.path(), ".other", "x\n", Mode::DEFAULT_FILE))
            .expect_err("a poisoned session refuses another write");
        assert!(matches!(err, Error::Poisoned { .. }), "got {err}");
        assert!(err.to_string().contains("roll back"), "{err}");
        assert!(!home.child(".other").exists());

        let err = session.finish().expect_err("and refuses to finish");
        assert!(matches!(err, Error::Poisoned { .. }), "got {err}");
        assert!(state.journal().exists(), "the journal is left for recovery");
        assert!(!state.ledger().exists(), "and the ledger was never saved");
        assert!(matches!(
            load(&state.journal()).expect("load"),
            Loaded::Unterminated(_)
        ));
    }

    #[test]
    fn a_failed_removal_intent_append_poisons_the_session_and_unlinks_nothing() {
        // r3 coverage C7. The write path's failed append is pinned above; the
        // removal's was not.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(
                home.path(),
                ".conf",
                "bx created\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("apply");
        first.finish().expect("finish");

        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
        session.journal.file = OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full");
        let err = session
            .apply(Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: Vec::new(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect_err("a full disk fails the removal's Intent append");
        assert!(
            matches!(&err, Error::Io { path, .. } if *path == state.journal()),
            "got {err}"
        );
        assert_eq!(peek(&dest).expect("not unlinked").0, b"bx created\n");
        assert!(
            session.ledger().get(&portable).is_some(),
            "nothing was removed, so nothing is forgotten"
        );
        let finished = session
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
    }

    #[test]
    fn a_failed_publish_poisons_the_session_and_records_nothing() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        // Something occupies the destination between the Intent and the rename:
        // a directory with an entry in it, which no rename(2) replaces with a
        // file.
        session.before_publish = Some(|dest: &Path| {
            std::fs::create_dir_all(dest.join("occupied")).expect("occupy the destination");
        });
        let err = session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect_err("the rename cannot land");
        assert!(matches!(err, Error::Write(_)), "got {err}");
        assert!(
            session.ledger().get(&portable).is_none(),
            "a write that never landed is not recorded, not even in memory",
        );

        let err = session
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(err, Error::Poisoned { .. }), "got {err}");
        assert!(!state.ledger().exists(), "no ledger entry was saved");
        let loaded = load(&state.journal()).expect("load");
        assert!(
            matches!(loaded, Loaded::Unterminated(_)),
            "no End frame: {loaded:?}"
        );
        assert!(
            !loaded
                .records()
                .iter()
                .any(|record| matches!(record, Record::Done(_))),
            "and no Done frame",
        );
        assert!(dest.is_dir());
    }

    /// Whether anything under `dir` is a writer's temporary file.
    fn holds_a_temporary_file(dir: &Path) -> bool {
        std::fs::read_dir(dir).expect("list").any(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(fs::TEMP_PREFIX)
        })
    }

    #[test]
    fn a_named_temp_recovery_cannot_unlink_is_left_and_the_rollback_goes_on() {
        // r3 round 2, P9R4-D3. The directory lost write permission between
        // the Intent and the publish, so the publish failed and left the
        // temporary file the Intent names. Recovery could not unlink it and
        // returned an Io error on every writing run, while `pending` called
        // the write resolvable.
        use std::os::unix::fs::PermissionsExt as _;

        fn lose_write(dest: &Path) {
            let dir = dest.parent().expect("a parent");
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555))
                .expect("chmod 0555");
        }

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dir = home.child(".ro");
        let dest = home.child(".ro/x.conf");
        plant_file(&dest, "user\n", Mode::DEFAULT_FILE);
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session.before_publish = Some(lose_write);
        let applied = session.apply(write_to(
            home.path(),
            ".ro/x.conf",
            "bx\n",
            Mode::DEFAULT_FILE,
        ));
        drop(session);
        let writable = |dir: &Path| {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
                .expect("chmod back");
        };
        if !permissions_refuse(&dir) {
            writable(&dir);
            return cannot_build(
                "a_named_temp_recovery_cannot_unlink_is_left_and_the_rollback_goes_on",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let temp = load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .expect("the Intent")
            .temp
            .clone()
            .expect("a staged temporary file");

        let report = crate::recover::pending(&state);
        let recovered = crate::recover::before_writing(&state);
        let temp_left = temp.is_file();
        writable(&dir);

        assert!(
            applied.is_err(),
            "the publish fails in a read-only directory"
        );
        assert_eq!(
            recovered.expect("the rollback goes on"),
            crate::recover::Outcome::RolledBack { undone: 1 },
        );
        assert!(temp_left, "the temporary file is left where it is");
        let report = report.expect("pending").expect("interrupted");
        assert!(report.blocked().next().is_none(), "{report:?}");
        let note = &report.unfinished[0].note;
        assert!(note.contains("rolls it back"), "{note}");
        let name = temp.file_name().expect("a name").to_string_lossy();
        assert!(
            note.contains(&format!(
                "its temporary file {name} cannot be removed, and is left for bx doctor"
            )),
            "{note}"
        );
        assert!(!state.journal().exists(), "and the session is resolved");
        assert_eq!(peek(&dest).expect("untouched").0, b"user\n");
        assert_eq!(
            crate::recover::before_writing(&state).expect("again"),
            crate::recover::Outcome::Nothing,
        );
    }

    #[test]
    fn a_prior_conflict_poisons_the_session_before_anything_is_published() {
        // Stack integration of #7's round 3: `Ledger::record` refuses a changed
        // file bx shares through a region with `PriorConflict`. The session
        // asked only after the rename, so the refusal arrived with bx's new
        // region already written over the user's edit.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".zshrc");
        let region = |body: &str| format!("user line\n# >>> bx >>>\n{body}\n# <<< bx <<<\n");
        let shared = |body: &str| Request {
            target: portable.clone(),
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: region(body).into_bytes(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Region { comment: '#' }),
        };
        plant_file(&dest, "user line\n", Mode::DEFAULT_FILE);
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first.apply(shared("BX1")).expect("apply");
        first.finish().expect("finish");
        let saved = std::fs::read(state.ledger()).expect("the saved ledger");

        let edit = format!("{}more\n", region("BX1"));
        plant_file(&dest, &edit, Mode::DEFAULT_FILE);

        let mut second =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let err = second
            .apply(shared("BX2"))
            .expect_err("a changed shared file is a conflict");
        assert!(
            matches!(err, Error::State(crate::state::Error::PriorConflict { .. })),
            "got {err}"
        );
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            edit.as_bytes(),
            "the user's edit is untouched: nothing was published",
        );
        assert!(!holds_a_temporary_file(home.path()));
        assert!(
            !state
                .restore()
                .join(ContentHash::of(edit.as_bytes()).to_hex())
                .exists(),
            "the changed bytes were not stored as a prior",
        );
        let stored = second.ledger().get(&portable).expect("the entry");
        assert_eq!(stored.written, ContentHash::of(region("BX1").as_bytes()));

        let again = second
            .apply(write_to(home.path(), ".other", "x\n", Mode::DEFAULT_FILE))
            .expect_err("poisoned");
        assert!(matches!(again, Error::Poisoned { .. }), "got {again}");
        let finished = second
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");

        // The journal is kept, like any poisoned session's, and announces no
        // write, so recovery has nothing to roll back.
        let loaded = load(&state.journal()).expect("load");
        assert!(matches!(loaded, Loaded::Unterminated(_)), "{loaded:?}");
        assert!(
            !loaded
                .records()
                .iter()
                .any(|record| matches!(record, Record::Intent(_))),
            "nothing was announced",
        );
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::RolledBack { undone: 0 },
        );
        assert_eq!(std::fs::read(&dest).expect("read"), edit.as_bytes());
        assert_eq!(std::fs::read(state.ledger()).expect("the ledger"), saved);
        assert!(!state.journal().exists());
    }

    #[test]
    fn an_edit_between_fill_and_publish_is_kept_and_recovery_rolls_nothing_back_over_it() {
        // Stack integration of #8's round 3: `publish` re-checks the destination
        // and returns `fs::Error::Changed` before the rename. Inside a session
        // that poisons like any publish error, keeps the edit, and leaves
        // recovery nothing to put back over it.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session.before_publish = Some(|dest: &Path| {
            std::fs::write(dest, "the user's edit\n").expect("an editor saves in place");
        });
        let err = session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect_err("the destination changed");
        assert!(
            matches!(err, Error::Write(fs::Error::Changed { .. })),
            "got {err}"
        );
        assert!(session.ledger().get(&portable).is_none());
        let finished = session
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
        assert_eq!(std::fs::read(&dest).expect("read"), b"the user's edit\n");
        assert!(!holds_a_temporary_file(home.path()));

        // The Intent was durable before the publish was refused, so recovery
        // finds a destination holding neither recorded state. It is reported
        // and left alone, exactly as an edit after a crash is.
        let interruption = crate::recover::pending(&state)
            .expect("pending")
            .expect("interrupted");
        assert_eq!(interruption.unfinished.len(), 1);
        assert_eq!(
            interruption.unfinished[0].standing,
            crate::recover::Standing::Diverged
        );
        assert!(!interruption.unfinished[0].resolvable);
        let outcome = crate::recover::recover(&state).expect("recover");
        assert!(
            matches!(&outcome, crate::recover::Outcome::Blocked { conflicts } if conflicts.len() == 1),
            "{outcome:?}"
        );
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"the user's edit\n",
            "recovery rolled nothing back over the edit",
        );
        assert!(crate::recover::abandon(&state).expect("abandon").is_some());
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::Nothing
        );
        assert_eq!(std::fs::read(&dest).expect("read"), b"the user's edit\n");
    }

    #[test]
    fn an_edit_between_plan_and_the_sessions_stage_is_kept_poisons_and_recovery_touches_nothing() {
        // Stack integration of #8's round 4: `stage` decides on the observation
        // plan compared, and a request carries it. An edit that lands after
        // plan and before the session stages is refused before anything is
        // staged, stored, announced or published.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        // An earlier write in the same session, so recovery has one write of its
        // own to roll back and can be seen to leave `.conf` alone.
        let (_, other) = target(home.path(), ".other");
        plant_file(&other, "other before\n", Mode::DEFAULT_FILE);

        // Plan observes both destinations, then the user saves over one.
        let first = write_to(home.path(), ".other", "other after\n", Mode::DEFAULT_FILE);
        let second = write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE);
        std::fs::write(&dest, "the user's edit after plan\n").expect("an editor saves");

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(first)
            .expect("the other destination is what plan saw");
        let err = session
            .apply(second)
            .expect_err("the destination changed since plan");
        assert!(
            matches!(err, Error::Write(fs::Error::Changed { .. })),
            "got {err}"
        );
        assert!(session.ledger().get(&portable).is_none());
        let again = session
            .apply(write_to(home.path(), ".third", "x\n", Mode::DEFAULT_FILE))
            .expect_err("the session is poisoned");
        assert!(matches!(again, Error::Poisoned { .. }), "got {again}");
        let finished = session
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"the user's edit after plan\n"
        );
        assert!(!holds_a_temporary_file(home.path()));
        assert!(!home.child(".third").exists());

        // Refused before its Intent frame: the journal names only the earlier write.
        let loaded = load(&state.journal()).expect("load");
        let named: Vec<&Portable> = loaded.intents().map(|intent| &intent.target).collect();
        assert_eq!(named.len(), 1, "{named:?}");
        assert_ne!(named[0], &portable);

        // Recovery rolls the earlier write back and touches nothing for `.conf`.
        let edited = peek(&dest);
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(peek(&other).expect("rolled back").0, b"other before\n");
        assert_eq!(peek(&dest), edited, "recovery touched nothing for the edit");
        assert!(!state.journal().exists());
    }

    #[test]
    fn a_session_keeps_one_set_of_the_directories_its_writes_created() {
        // Stack integration of #8's round 4: a directory target applied after a
        // write beneath it is the `Create` plan announced only when both were
        // given one `fs::CreatedDirs`. The session holds that set for its life.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(
                home.path(),
                ".config/one/a.conf",
                "a\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("the first write");
        session
            .apply(write_to(
                home.path(),
                ".config/two/b.conf",
                "b\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("the second write");
        for dir in [".config", ".config/one", ".config/two"] {
            assert!(
                session.created.contains(&home.child(dir)),
                "{dir} is in the session's set"
            );
        }
        session.finish().expect("finish");
    }

    #[test]
    fn a_scope_entry_the_loader_would_refuse_is_refused_before_the_journal_exists() {
        // r3 round 3, D1. `refusal` puts every `Begin.scope` entry through
        // `check_against(home)` and refuses the *whole* journal when one
        // fails, so a session that wrote one could never be rolled back: the
        // next load reads `Unreadable`, `recover::resolve` returns `Nothing`,
        // and half-applied writes survive with nothing undone. `restore`
        // forwards its caller's target list verbatim as the scope, and
        // `Portable::try_from` accepts `/<home>/.gitconfig`, so the caller
        // needed no mistake beyond spelling a target absolutely.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let absolute = Portable::try_from(
            home.child(".gitconfig")
                .to_str()
                .expect("utf-8")
                .to_string(),
        )
        .expect("a well-formed absolute path");
        assert!(
            absolute.check_against(home.path()).is_err(),
            "the fixture is a scope entry the loader refuses",
        );

        let err = Session::open(
            &state,
            SessionKind::Apply,
            home.path(),
            vec![target(home.path(), ".vimrc").0, absolute.clone()],
        )
        .expect_err("a scope entry the loader refuses");
        assert!(
            matches!(err, Error::State(crate::state::Error::ForeignRecord { .. })),
            "got {err}"
        );
        assert!(
            !state.journal().exists(),
            "and no journal was written for it to refuse",
        );

        // The same scope, written past the refusal, is what the refusal buys:
        // the loader disbelieves the whole file, so nothing in it is undone.
        let mut session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect("a well-formed scope opens");
        session
            .apply(write_to(home.path(), ".vimrc", "bx\n", Mode::DEFAULT_FILE))
            .expect("apply");
        let path = state.journal();
        let believed = std::fs::read(&path).expect("read");
        drop(session);
        assert!(
            matches!(
                load(&path).expect("load"),
                Loaded::Unterminated(_) | Loaded::Torn { .. }
            ),
            "the well-formed session's journal is believed",
        );
        raw_journal(
            &path,
            &[
                Record::Begin(Begin {
                    kind: SessionKind::Apply,
                    home: home.path().to_path_buf(),
                    scope: vec![absolute],
                }),
                Record::Intent(Intent {
                    target: target(home.path(), ".vimrc").0,
                    dest: home.child(".vimrc"),
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Absent,
                    created_dirs: Vec::new(),
                    mechanism: None,
                    ledger_written: None,
                }),
            ],
        );
        assert!(
            matches!(load(&path).expect("load"), Loaded::Unreadable { .. }),
            "one unportable scope entry makes the whole journal unreadable",
        );
        assert_ne!(believed, std::fs::read(&path).expect("read"));
    }

    #[test]
    fn a_target_spelled_absolutely_under_the_home_is_refused_before_anything_is_touched() {
        // Stack integration of #7's round 4: a caller holding a `Ledger` gets
        // its home check. `new_entry` folds the destination into `~/…`, so the
        // check inside `Ledger::check_record` cannot see a target spelled
        // `/<home>/…`. That target renders to itself and used to be admitted:
        // the ledger keyed it `~/.conf`, the same file under that spelling got
        // past `Repeated`, and a crash left a journal the loader refuses.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        let absolute = Portable::try_from(dest.to_str().expect("utf-8").to_string())
            .expect("a well-formed absolute path");

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        let err = session
            .apply(Request {
                target: absolute,
                content: Content::Bytes {
                    bytes: b"new\n".to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                dest: dest.clone(),
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect_err("the ledger's home check refuses the target");
        assert!(
            matches!(err, Error::State(crate::state::Error::ForeignRecord { .. })),
            "got {err}"
        );
        let again = session
            .apply(write_to(
                home.path(),
                ".conf",
                "again\n",
                Mode::DEFAULT_FILE,
            ))
            .expect_err("the session is poisoned");
        assert!(matches!(again, Error::Poisoned { .. }), "got {again}");
        let finished = session
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
        assert_eq!(peek(&dest).expect("untouched").0, b"old\n");
        assert!(!holds_a_temporary_file(home.path()));

        // Nothing was announced, so what the session leaves is a journal bx believes.
        let loaded = load(&state.journal()).expect("load");
        assert!(!matches!(loaded, Loaded::Unreadable { .. }), "{loaded:?}");
        assert_eq!(loaded.intents().count(), 0);
    }

    #[test]
    fn a_hard_linked_decoy_at_a_blob_name_is_replaced_before_an_intent_names_it() {
        // Stack integration of #7's round 3: a same-length file at
        // `restore/<digest>` that is a second hard link is not a blob bx wrote,
        // and the ledger's store stopped trusting one. The journal's own copy of
        // the length check still did, so an Intent named a blob holding the
        // decoy's bytes and the rollback could not put the original back. A
        // removal records nothing in the ledger, so only that copy runs here.
        use std::os::unix::fs::MetadataExt as _;

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "the original\n", Mode::DEFAULT_FILE);
        let decoy = home.child("decoy");
        std::fs::write(&decoy, "ZZZZZZZZZZZZ\n").expect("a decoy of the same length");
        let blob = state
            .restore()
            .join(ContentHash::of(b"the original\n").to_hex());
        std::fs::hard_link(&decoy, &blob).expect("a second link at the blob name");

        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
        session
            .apply(Request {
                target: portable,
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: Vec::new(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect("remove");
        drop(session);
        assert!(peek(&dest).is_none());

        let meta = std::fs::symlink_metadata(&blob).expect("stat");
        assert!(meta.file_type().is_file());
        assert_eq!(meta.nlink(), 1, "the decoy link was replaced, not trusted");
        assert_eq!(std::fs::read(&blob).expect("read"), b"the original\n");
        assert_eq!(
            std::fs::read(&decoy).expect("read"),
            b"ZZZZZZZZZZZZ\n",
            "and not written through",
        );

        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(
            peek(&dest),
            Some((b"the original\n".to_vec(), Mode::DEFAULT_FILE))
        );
    }

    #[test]
    fn a_failed_removal_keeps_the_ledger_entry_and_poisons_the_session() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), "locked/made.conf");
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(
                home.path(),
                "locked/made.conf",
                "made\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("apply");
        first.finish().expect("finish");

        let locked = home.child("locked");
        fs::set_mode(&locked, Mode::from_bits(0o555)).expect("make the directory read-only");
        if !permissions_refuse(&locked) {
            fs::set_mode(&locked, Mode::DEFAULT_DIR).expect("make it writable again");
            return cannot_build(
                "a_failed_removal_keeps_the_ledger_entry_and_poisons_the_session",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
        let removed = session.apply(Request {
            target: portable.clone(),
            dest: dest.clone(),
            content: Content::Absent {
                created_dirs: vec![locked.clone()],
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Released,
        });
        let still_managed = session.ledger().get(&portable).is_some();
        let finished = session.finish();
        // Before any assertion, so the tempdir can be removed whatever happens.
        fs::set_mode(&locked, Mode::DEFAULT_DIR).expect("make it writable again");

        let err = removed.expect_err("an unlink in a read-only directory fails");
        assert!(matches!(err, Error::Io { .. }), "got {err}");
        assert!(
            still_managed,
            "a removal that did not happen does not drop the entry"
        );
        assert!(
            matches!(finished, Err(Error::Poisoned { .. })),
            "got {finished:?}"
        );
        assert!(dest.is_file());
        assert!(
            LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .is_some(),
            "the saved ledger still owns the file that is still there",
        );
    }

    #[test]
    fn a_journal_that_cannot_be_moved_aside_is_an_error_and_stays_in_place() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        std::fs::write(state.journal(), b"GARBAGE!").expect("write");

        // No root here, so a directory without write permission refuses the
        // rename. Narrower than 0700 rather than wider, so nothing tightens it.
        fs::set_mode(state.root(), Mode::from_bits(0o500)).expect("make it read-only");
        if !permissions_refuse(state.root()) {
            fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");
            return cannot_build(
                "a_journal_that_cannot_be_moved_aside_is_an_error_and_stays_in_place",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let loaded = load_exclusive(&state.journal(), &lock);
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");

        let err = loaded.expect_err("a journal that cannot be moved aside is refused");
        assert!(
            matches!(&err, Error::CannotSetAside { path, .. } if *path == state.journal()),
            "got {err}"
        );
        assert_eq!(
            std::fs::read(state.journal()).expect("still in place"),
            b"GARBAGE!",
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn an_unreadable_journal_that_cannot_be_set_aside_is_refused_and_never_replaced() {
        // r3, routed from #7's repair planning. `load_exclusive` reported a
        // journal it could not move aside as `Unreadable { moved_to: None }`,
        // which is not an interruption, so `Session::open` created its own
        // journal over it by rename and the bytes were gone.
        let home = guarded_home();
        // Every set-aside name is longer than the kernel accepts, so the move
        // fails with no permission bit involved, and a session could write.
        // (A crafted `journal.mpk.corrupt.<u64::MAX>` no longer blocks it:
        // `move_aside` takes the lowest free name past that number.)
        let state = state_beyond_set_aside_names(&home);
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"GARBAGE!").expect("an unreadable journal");

        let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new());
        assert_eq!(
            std::fs::read(state.journal()).expect("kept"),
            b"GARBAGE!",
            "the unreadable journal's bytes are still at its path"
        );
        assert!(
            matches!(
                &opened,
                Err(Error::CannotSetAside { source, .. })
                    if source.raw_os_error()
                        == Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
            ),
            "got {opened:?}"
        );

        let recovered = crate::recover::before_writing(&state);
        assert!(
            matches!(
                recovered,
                Err(crate::recover::Error::Journal(Error::CannotSetAside { .. }))
            ),
            "got {recovered:?}"
        );
        assert_eq!(std::fs::read(state.journal()).expect("kept"), b"GARBAGE!");
        assert!(
            crate::recover::pending(&state)
                .expect("pending")
                .expect("still reported")
                .unreadable
        );
        assert_eq!(
            names_in(state.root()),
            ["journal.mpk", "lock", "restore", "shell"],
            "nothing was set aside and no session wrote"
        );
    }

    #[test]
    fn a_damaged_ledger_that_cannot_be_moved_aside_stops_a_session_before_its_journal() {
        // Stack integration of #8 @62de0aa, which carries #7's r3 round 1:
        // `Ledger::open` refuses a damaged ledger it cannot move aside with
        // `state::Error::CannotQuarantine` instead of resetting it. A session
        // opened over one must stop there, before its journal exists, so no
        // later save can write over the bytes.
        let home = guarded_home();
        let state = state_beyond_set_aside_names(&home);
        state.ensure().expect("ensure");
        std::fs::write(state.ledger(), b"not a ledger").expect("damage the ledger");

        let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new());
        assert!(
            matches!(
                &opened,
                Err(Error::State(crate::state::Error::CannotQuarantine {
                    path,
                    damage: crate::state::Damage::Malformed,
                    source,
                })) if *path == state.ledger()
                    && source.raw_os_error()
                        == Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
            ),
            "got {opened:?}"
        );
        assert_eq!(
            std::fs::read(state.ledger()).expect("kept"),
            b"not a ledger",
            "the damaged ledger's bytes are unchanged"
        );
        assert_eq!(
            names_in(state.root()),
            ["ledger.mpk", "lock", "restore", "shell"],
            "no journal, no set-aside and no saved ledger"
        );
        assert!(
            ExclusiveLock::try_acquire(&state).expect("try").is_some(),
            "the refused session released the lock"
        );
    }

    /// Whether a directory without write permission refuses this process.
    ///
    /// It does not refuse root, so a test that needs a refused rename or
    /// unlink cannot produce one there. A caller that finds `false` restores
    /// whatever it broke and then calls [`cannot_build`], which fails unless
    /// the skip was opted into.
    pub(crate) fn permissions_refuse(dir: &Path) -> bool {
        let probe = dir.join("permission-probe");
        if std::fs::write(&probe, b"").is_err() {
            return true;
        }
        std::fs::remove_file(&probe).expect("remove the probe");
        false
    }

    /// Why a test that needs a refused write cannot run as this user.
    pub(crate) const WRITES_THROUGH_PERMISSIONS: &str = "this process writes through file or directory permissions, so the \
         failure cannot be produced";

    /// The variable that turns a scenario this machine cannot build from a
    /// failure into a skip.
    ///
    /// r3 round 3, COV1. A test that prints a line and passes when it could
    /// not run is not a test: the arms it is the only cover for go unverified
    /// while the suite reports green, and nobody reads the line. So an
    /// unbuildable scenario **fails**, and the only way to have it skip is to
    /// say so in the environment — which is a decision a human takes, and
    /// which the gate report then has to carry.
    pub(crate) const ALLOW_SKIPS: &str = "BX_ALLOW_UNBUILDABLE_SCENARIOS";

    /// Fail because `name`'s scenario cannot be built here, or skip loudly if
    /// [`ALLOW_SKIPS`] says to.
    pub(crate) fn cannot_build(name: &str, why: &str) {
        assert!(
            std::env::var_os(ALLOW_SKIPS).is_some_and(|allow| allow == "1"),
            "{name} could not be run on this machine: {why}.\n\
             That is a failure, not a skip: everything this test is the only \
             cover for is now unverified. Run the suite as an unprivileged \
             user, on a kernel with unprivileged user namespaces and with \
             util-linux present; or set {ALLOW_SKIPS}=1 to accept the gap, \
             which leaves it unverified and makes the suite say so.",
        );
        eprintln!("SKIPPED, opted out with {ALLOW_SKIPS}=1 — {name}: {why}");
    }

    /// A state directory, not yet created, whose files' paths fit Linux's
    /// `PATH_MAX` and whose set-aside names do not.
    ///
    /// Every [`crate::state::move_aside`] of its journal or ledger then fails
    /// with ENAMETOOLONG, whoever the process runs as — "a name too long for a
    /// quarantine suffix", as `state` puts it — while each can still be read,
    /// written and locked. `fingerprints.mpk` is the one state file out of
    /// reach.
    pub(crate) fn state_beyond_set_aside_names(home: &crate::testing::GuardedHome) -> StateDir {
        /// `PATH_MAX`, which counts the terminating NUL.
        const PATH_MAX: usize = 4096;
        const ROOT: usize = 4080;
        let mut root = home.path().as_os_str().to_os_string();
        assert!(root.len() < ROOT - 256, "a home short enough to extend");
        while ROOT - root.len() > 256 {
            root.push(format!("/{}", "d".repeat(200)));
        }
        root.push(format!("/{}", "b".repeat(ROOT - root.len() - 1)));
        let state = StateDir::new(PathBuf::from(root));
        assert_eq!(state.root().as_os_str().len(), ROOT);
        for file in [state.journal(), state.ledger()] {
            assert!(file.as_os_str().len() < PATH_MAX, "{} fits", file.display());
            assert!(
                StateDir::quarantine(&file).as_os_str().len() >= PATH_MAX,
                "its set-aside name does not"
            );
        }
        state
    }

    /// The names in `dir`, sorted.
    pub(crate) fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// A session header for a journal that needs one and does not care what it
    /// says.
    fn some_begin() -> Begin {
        Begin {
            kind: SessionKind::Apply,
            home: PathBuf::from("/home/someone"),
            scope: Vec::new(),
        }
    }

    /// Where each whole frame in a journal's bytes starts.
    pub(crate) fn frame_starts(bytes: &[u8]) -> Vec<usize> {
        let nonce = nonce_of(bytes);
        let mut starts = Vec::new();
        let mut at = HEADER;
        while let Ok((_, next)) = frame(bytes, at, &nonce) {
            starts.push(at);
            at = next;
        }
        starts
    }

    /// The nonce in a journal's header.
    pub(crate) fn nonce_of(bytes: &[u8]) -> [u8; NONCE] {
        bytes[MAGIC.len() + 1..HEADER]
            .try_into()
            .expect("a whole header")
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

    /// Write a journal exactly as given: a header, then each record as a frame.
    ///
    /// For journals no session writes - one with no `Begin`, or one whose `End`
    /// follows an Intent that has no `Done` - so recovery can be tested against
    /// what damage or an earlier bx could leave behind.
    pub(crate) fn raw_journal(path: &Path, records: &[Record]) {
        let nonce = fresh_nonce();
        let mut header = MAGIC.to_vec();
        header.push(FORMAT);
        header.extend_from_slice(&nonce);
        std::fs::write(path, &header).expect("write the header");
        let mut journal = Journal {
            file: OpenOptions::new()
                .append(true)
                .open(path)
                .expect("reopen the journal"),
            path: path.to_path_buf(),
            nonce,
        };
        for record in records {
            journal.append(record).expect("append");
        }
    }

    /// Append an `End` frame to an existing journal.
    ///
    /// What [`Session::finish`] does *before* it saves the ledger — the one
    /// window in which a crash leaves a terminated journal and a ledger that is
    /// behind it.
    pub(crate) fn seal(path: &Path, written: usize) {
        let mut journal = Journal {
            file: OpenOptions::new()
                .append(true)
                .open(path)
                .expect("reopen the journal"),
            path: path.to_path_buf(),
            nonce: nonce_of(&std::fs::read(path).expect("read the journal")),
        };
        journal
            .append(&Record::End(End { written }))
            .expect("append the End frame");
    }

    /// Every boundary the child can stop at, as `BX_CRASH_AT` spells it.
    ///
    /// Spellings rather than [`Phase`] values, so the harness that drives this
    /// can live in the module whose behaviour it is testing without the crash
    /// seam having to become part of this module's surface.
    pub(crate) fn crash_phases() -> [&'static str; PHASES.len()] {
        PHASES.map(Crash::name)
    }

    /// Every boundary inside [`Session::finish`], as `BX_CRASH_AT` spells it.
    pub(crate) fn finish_crash_phases() -> [&'static str; FINISH_PHASES.len()] {
        FINISH_PHASES.map(Crash::name)
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
    fn an_edit_between_a_removals_intent_and_its_unlink_is_kept_and_recovery_touches_nothing() {
        // Review round 5, item 1. `remove` observed, made the snapshot and the
        // Intent durable, and unlinked with no second look, so an editor's save
        // in that window was destroyed (18 of 300 racing runs).
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(
                home.path(),
                ".conf",
                "bx created\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("apply");
        first.finish().expect("finish");

        let planned = fs::observe(&dest).expect("plan's observation");
        let mut session =
            Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
        session.before_unlink = Some(|dest: &Path| {
            // An editor's save: a sibling renamed over the file.
            let sibling = dest.with_file_name(".conf.edit~");
            std::fs::write(&sibling, "the user's edit\n").expect("write the sibling");
            std::fs::rename(&sibling, dest).expect("rename it over");
        });
        let err = session
            .apply(Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: Vec::new(),
                    planned,
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect_err("the destination changed after the Intent");
        assert!(
            matches!(err, Error::Write(fs::Error::Changed { .. })),
            "got {err}"
        );
        assert!(
            session.ledger().get(&portable).is_some(),
            "nothing was removed, so nothing is forgotten",
        );
        let finished = session
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
        assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's edit\n");

        let interruption = crate::recover::pending(&state)
            .expect("pending")
            .expect("interrupted");
        assert_eq!(interruption.unfinished.len(), 1);
        assert_eq!(
            interruption.unfinished[0].standing,
            crate::recover::Standing::Diverged
        );
        let outcome = crate::recover::recover(&state).expect("recover");
        assert!(
            matches!(&outcome, crate::recover::Outcome::Blocked { conflicts } if conflicts.len() == 1),
            "{outcome:?}"
        );
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"the user's edit\n",
            "recovery rolled nothing back over the edit",
        );
        assert!(crate::recover::abandon(&state).expect("abandon").is_some());
        assert_eq!(std::fs::read(&dest).expect("read"), b"the user's edit\n");
    }

    #[test]
    fn a_removal_names_how_its_destination_moved_since_plan() {
        // r3 coverage C2, extended for r3 coverage COV5: the third detail and
        // the `planned.path != now.path` branch had no case. That branch is
        // the one that stops a removal running against an observation of a
        // different file.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (gone, gone_dest) = target(home.path(), ".gone");
        plant_file(&gone_dest, "bx created\n", Mode::DEFAULT_FILE);
        let was_there = fs::observe(&gone_dest).expect("plan's observation");
        std::fs::remove_file(&gone_dest).expect("the user removes it");
        let (appeared, appeared_dest) = target(home.path(), ".appeared");
        let nothing = fs::observe(&appeared_dest).expect("plan's observation");
        plant_file(&appeared_dest, "the user's\n", Mode::DEFAULT_FILE);
        let (edited, edited_dest) = target(home.path(), ".edited");
        plant_file(&edited_dest, "bx created\n", Mode::DEFAULT_FILE);
        let as_written = fs::observe(&edited_dest).expect("plan's observation");
        plant_file(&edited_dest, "the user's edit\n", Mode::DEFAULT_FILE);
        // An observation of another file entirely, handed to a removal of
        // this one: the same shape a caller pairing the wrong plan with the
        // wrong target would produce.
        let (_elsewhere, elsewhere_dest) = target(home.path(), ".elsewhere");
        plant_file(&elsewhere_dest, "somebody else's\n", Mode::DEFAULT_FILE);
        let (mixed_up, mixed_up_dest) = target(home.path(), ".mixed-up");
        plant_file(&mixed_up_dest, "bx created\n", Mode::DEFAULT_FILE);
        let another_file = fs::observe(&elsewhere_dest).expect("plan's observation");
        let wrong_path = format!("plan observed {}, not this path", elsewhere_dest.display());

        for (portable, dest, planned, detail) in [
            (gone, gone_dest, was_there, "it has been removed"),
            (
                appeared,
                appeared_dest.clone(),
                nothing,
                "nothing was there, and something is now",
            ),
            (
                edited,
                edited_dest.clone(),
                as_written,
                "it has been modified or replaced",
            ),
            (
                mixed_up,
                mixed_up_dest.clone(),
                another_file,
                wrong_path.as_str(),
            ),
        ] {
            let mut session =
                Session::open(&state, SessionKind::Restore, home.path(), Vec::new()).expect("open");
            let err = session
                .apply(Request {
                    target: portable,
                    dest: dest.clone(),
                    content: Content::Absent {
                        created_dirs: Vec::new(),
                        planned,
                    },
                    mode: Mode::DEFAULT_FILE,
                    ownership: Ownership::Released,
                })
                .expect_err(detail);
            assert!(
                matches!(&err, Error::Write(fs::Error::Changed { path, detail: said }) if *path == dest && said.as_str() == detail),
                "got {err}"
            );
            drop(session);
            assert_eq!(
                load(&state.journal()).expect("load").intents().count(),
                0,
                "{detail}: refused before its Intent"
            );
            crate::recover::recover(&state).expect("clear the refused session");
        }
        assert_eq!(peek(&appeared_dest).expect("kept").0, b"the user's\n");
        assert_eq!(peek(&edited_dest).expect("kept").0, b"the user's edit\n");
        assert_eq!(peek(&mixed_up_dest).expect("kept").0, b"bx created\n");
        assert_eq!(
            peek(&elsewhere_dest).expect("kept").0,
            b"somebody else's\n",
            "and the file the wrong observation named is untouched",
        );
    }

    /// An Intent that says bx created `dest` holding `bytes`.
    fn created(target: &Portable, dest: &Path, bytes: &[u8]) -> Record {
        Record::Intent(Intent {
            target: target.clone(),
            dest: dest.to_path_buf(),
            temp: None,
            before: Prior::Absent,
            after: Written::Present {
                digest: ContentHash::of(bytes),
                mode: Mode::DEFAULT_FILE,
            },
            created_dirs: Vec::new(),
            mechanism: Some(Mechanism::Own),
            ledger_written: None,
        })
    }

    #[test]
    fn a_whole_record_after_the_end_of_a_session_is_unreadable_and_nothing_rolls_back() {
        // Coverage review round 5, item 2. Believed, the trailing Intent made
        // this an unterminated session, and both files would be unlinked.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let (first, first_dest) = target(home.path(), ".first");
        let (second, second_dest) = target(home.path(), ".second");
        plant_file(&first_dest, "first\n", Mode::DEFAULT_FILE);
        plant_file(&second_dest, "second\n", Mode::DEFAULT_FILE);
        raw_journal(
            &state.journal(),
            &[
                begin_under(home.path(), Vec::new()),
                created(&first, &first_dest, b"first\n"),
                Record::Done(Done {
                    target: first.clone(),
                }),
                Record::End(End { written: 1 }),
                created(&second, &second_dest, b"second\n"),
            ],
        );

        assert_eq!(
            load(&state.journal()).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::Nothing
        );
        assert_eq!(peek(&first_dest).expect("kept").0, b"first\n");
        assert_eq!(peek(&second_dest).expect("kept").0, b"second\n");
        assert!(StateDir::quarantine(&state.journal()).is_file());
    }

    #[test]
    fn bytes_after_the_end_of_a_session_are_unreadable_not_terminated() {
        // Coverage review round 5, item 3.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut journal = Journal::create(&path, some_begin()).expect("create");
        journal
            .append(&Record::End(End { written: 0 }))
            .expect("append");
        drop(journal);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Terminated(vec![
                Record::Begin(some_begin()),
                Record::End(End { written: 0 })
            ]),
        );

        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend_from_slice(&[0xab; 32]);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_journal_path_that_cannot_be_looked_at_is_an_error_not_an_absent_journal() {
        // r3 round 2, restricted mutants on P42R1-D5. The look before the read
        // treats only NotFound as "no journal": any other failure — here
        // ENOTDIR, a state directory that is a file, which no permission
        // setting can bypass — is an error, as the read's was before it.
        let dir = tempfile::tempdir().expect("a tempdir");
        let file = dir.path().join("not-a-directory");
        plant_file(
            &file,
            "a file where the state directory should be\n",
            Mode::DEFAULT_FILE,
        );
        let path = file.join("journal.mpk");

        let err = load(&path).expect_err("a path that cannot be looked at is not absent");
        assert!(
            matches!(&err, Error::Io { path: at, .. } if *at == path),
            "got {err}"
        );
    }

    #[test]
    fn a_journal_that_cannot_be_read_is_an_error_and_a_session_does_not_replace_it() {
        // Coverage review round 5, item 4. Read as absent, it would be replaced
        // by the next session's journal without ever being examined.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
        let path = state.journal();
        let bytes = std::fs::read(&path).expect("read");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::fs::read(&path).is_ok() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod back");
            return cannot_build(
                "a_journal_that_cannot_be_read_is_an_error_and_a_session_does_not_replace_it",
                WRITES_THROUGH_PERMISSIONS,
            );
        }

        let loaded = load(&path).expect_err("an unreadable journal is not an absent one");
        assert!(matches!(loaded, Error::Io { .. }), "got {loaded}");
        let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect_err("a session refuses");
        assert!(matches!(opened, Error::Io { .. }), "got {opened}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod back");
        assert_eq!(
            std::fs::read(&path).expect("read"),
            bytes,
            "and it was not replaced"
        );
    }

    /// The home a journal-read child finds its state directory under.
    const READ_CHILD_HOME: &str = "BX_JOURNAL_READ_HOME";

    /// Which read a journal-read child makes: `load`, `open` or `recover`.
    const READ_CHILD_CALL: &str = "BX_JOURNAL_READ_CALL";

    /// The reading half of
    /// [`a_journal_that_is_not_a_regular_file_is_refused_without_being_read`].
    ///
    /// Run in a child so a read that never returns can be killed, and with its
    /// address space capped, so a read of `/dev/zero` aborts on its first
    /// gigabyte instead of taking the host's memory with it.
    #[test]
    #[ignore = "spawned by a_journal_that_is_not_a_regular_file_is_refused_without_being_read"]
    fn journal_read_child() {
        let (Some(home), Ok(call)) = (
            std::env::var_os(READ_CHILD_HOME),
            std::env::var(READ_CHILD_CALL),
        ) else {
            return;
        };
        rustix::process::setrlimit(
            rustix::process::Resource::As,
            rustix::process::Rlimit {
                current: Some(1 << 30),
                maximum: None,
            },
        )
        .expect("cap the address space");
        let home = PathBuf::from(home);
        let state = StateDir::resolve(&home);
        let path = state.journal();
        let named = |e: &Error| matches!(e, Error::NotAJournal { path: at, .. } if *at == path);
        let refusal = match call.as_str() {
            "load" => load(&path)
                .map(|_| ())
                .map_err(|e| (named(&e), e.to_string())),
            "open" => Session::open(&state, SessionKind::Apply, &home, Vec::new())
                .map(|_| ())
                .map_err(|e| (named(&e), e.to_string())),
            "recover" => crate::recover::recover(&state).map(|_| ()).map_err(|e| {
                let refused = matches!(&e, crate::recover::Error::Journal(inner) if named(inner));
                (refused, e.to_string())
            }),
            other => panic!("no such read: {other}"),
        };
        println!("{call}: {refusal:?}");
        let (refused, message) =
            refusal.expect_err("a journal that is not a regular file is refused");
        assert!(refused, "refused as NotAJournal: {message}");
        assert!(
            message.contains(&path.display().to_string()),
            "the refusal names the journal: {message}"
        );
        assert!(message.contains("only from a regular file"), "{message}");
    }

    #[test]
    fn a_journal_that_is_not_a_regular_file_is_refused_without_being_read() {
        // P42R1-D5 (journal part). The journal was read whole with a blocking
        // read and no look at its type, so a FIFO at `journal.mpk` blocked
        // load, Session::open and recovery forever, and a link to /dev/zero
        // read without end.
        fn fifo(path: &Path) {
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                path,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .expect("mkfifo");
        }
        fn device_link(path: &Path) {
            std::os::unix::fs::symlink("/dev/zero", path).expect("link to /dev/zero");
        }
        fn dangling_link(path: &Path) {
            std::os::unix::fs::symlink(path.with_file_name("nowhere"), path)
                .expect("a link to nothing");
        }

        let guard = guarded_home();
        // Every case is run before any is judged, so one read that hangs
        // does not hide what the others do.
        let mut failures = Vec::new();
        for (name, plant, kind) in [
            ("fifo", fifo as fn(&Path), fs::Kind::Other),
            ("device-link", device_link as fn(&Path), fs::Kind::Symlink),
            (
                "dangling-link",
                dangling_link as fn(&Path),
                fs::Kind::Symlink,
            ),
        ] {
            for call in ["load", "open", "recover"] {
                let case = format!("{name} read by {call}");
                let home = guard.child(format!("{name}-{call}"));
                let state = StateDir::resolve(&home);
                state.ensure().expect("the state directory");
                plant(&state.journal());

                let mut child =
                    std::process::Command::new(std::env::current_exe().expect("the test binary"))
                        .args([
                            "--exact",
                            "--ignored",
                            "--nocapture",
                            "journal::tests::journal_read_child",
                        ])
                        .env(READ_CHILD_HOME, &home)
                        .env(READ_CHILD_CALL, call)
                        // Inherited, unlike the crash harness's: this child
                        // exits normally and writes a profile, which belongs
                        // where coverage put the parent's, not in the working
                        // directory under a default name.
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .expect("spawn the reading child");
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                let finished = loop {
                    if child.try_wait().expect("wait").is_some() {
                        break true;
                    }
                    if std::time::Instant::now() > deadline {
                        child.kill().expect("kill the reading child");
                        break false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                };
                let out = child.wait_with_output().expect("the child's output");
                let said = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if !finished {
                    failures.push(format!("{case}: still reading after 60 s: {said}"));
                    continue;
                }
                if !out.status.success() {
                    failures.push(format!("{case}: {} {said}", out.status));
                    continue;
                }

                let meta = std::fs::symlink_metadata(state.journal()).expect("left in place");
                assert_eq!(
                    fs::Kind::from(meta.file_type()),
                    kind,
                    "{case}: never replaced"
                );
                assert!(
                    std::fs::symlink_metadata(StateDir::quarantine(&state.journal())).is_err(),
                    "{case}: never set aside"
                );

                // The way out: `abandon` moves it aside without opening it,
                // and bx writes again.
                let aside = crate::recover::abandon(&state)
                    .expect("abandon")
                    .expect("something stood at the journal's path");
                assert_eq!(
                    fs::Kind::from(std::fs::symlink_metadata(&aside).expect("kept").file_type()),
                    kind,
                    "{case}: moved, not replaced"
                );
                assert_eq!(
                    crate::recover::before_writing(&state).expect("bx writes again"),
                    crate::recover::Outcome::Nothing,
                    "{case}"
                );
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
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

    #[test]
    fn a_directory_that_cannot_be_removed_for_another_reason_is_an_error() {
        // Coverage review round 5, non-blocking.
        let dir = tempfile::tempdir().expect("a tempdir");
        let parent = dir.path().join("locked");
        let child = parent.join("made");
        std::fs::create_dir_all(&child).expect("create");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        if !permissions_refuse(&parent) {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
                .expect("chmod back");
            return cannot_build(
                "a_directory_that_cannot_be_removed_for_another_reason_is_an_error",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let err = prune_dirs(std::slice::from_ref(&child));
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("chmod back");
        let err = err.expect_err("neither gone nor not empty");
        assert!(matches!(err, Error::Io { .. }), "got {err}");
        assert!(child.is_dir());
    }

    #[test]
    fn a_claimed_directory_that_is_no_longer_a_directory_is_left_and_the_walk_goes_on() {
        // r3 round 1, D1. `rmdir` on a symlink or a file is ENOTDIR, which was
        // an error: `rm` unlinked the file through the link and then failed,
        // and a rollback failed the same way on every run.
        let dir = tempfile::tempdir().expect("a tempdir");

        // A claimed directory the user replaced with a link to an empty one.
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("the real directory");
        let link = dir.path().join("d");
        std::os::unix::fs::symlink(&real, &link).expect("the link");
        prune_dirs(std::slice::from_ref(&link)).expect("a link is not bx's directory");
        prune_claims(
            &LedgerView::default(),
            dir.path(),
            std::slice::from_ref(&link),
        )
        .expect("nor is it a claim to remove");
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("the link stays")
                .file_type()
                .is_symlink()
        );
        assert!(real.is_dir(), "and so does the directory it names");

        // A claimed ancestor replaced by a regular file: the claim beneath it
        // cannot be a directory either.
        let file = dir.path().join("a");
        std::fs::write(&file, "the user's\n").expect("a file where a directory was");
        let claims = [file.join("b"), file.clone()];
        prune_dirs(&claims).expect("prune");
        prune_claims(&LedgerView::default(), dir.path(), &claims).expect("prune the claims");
        assert_eq!(std::fs::read(&file).expect("kept"), b"the user's\n");
    }

    #[test]
    fn a_removal_naming_a_directory_that_is_not_its_parent_is_refused_before_anything_is_touched() {
        // r3 round 1, D2. The session checked a removal's destination but not
        // its created directories, so it pruned an empty directory of the user's
        // and wrote an Intent the loader refuses: the journal was then set
        // aside, and the removed file was never put back.
        let guard = guarded_home();
        for case in [
            "an unrelated directory",
            "the home",
            "the destination itself",
            "a directory above the home",
        ] {
            let home = guard.child(case.replace(' ', "-"));
            std::fs::create_dir_all(&home).expect("the home");
            let state = StateDir::resolve(&home);
            let (portable, dest) = target(&home, ".conf");
            let mut first =
                Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
            first
                .apply(write_to(&home, ".conf", "bx created\n", Mode::DEFAULT_FILE))
                .expect("apply");
            first.finish().expect("finish");
            let users = home.join("projects/empty");
            std::fs::create_dir_all(&users).expect("the user's empty directory");
            let stray = match case {
                "an unrelated directory" => users.clone(),
                "the home" => home.clone(),
                "the destination itself" => dest.clone(),
                _ => guard.path().to_path_buf(),
            };

            let mut session =
                Session::open(&state, SessionKind::Restore, &home, Vec::new()).expect("open");
            let err = session
                .apply(Request {
                    target: portable.clone(),
                    dest: dest.clone(),
                    content: Content::Absent {
                        created_dirs: vec![stray.clone()],
                        planned: fs::observe(&dest).expect("plan's observation"),
                    },
                    mode: Mode::DEFAULT_FILE,
                    ownership: Ownership::Released,
                })
                .expect_err(case);
            assert!(
                matches!(&err, Error::StrayCreatedDir { target, dir } if *target == portable && *dir == stray),
                "{case}: got {err}"
            );
            assert!(users.is_dir(), "{case}: the user's directory stays");
            assert_eq!(peek(&dest).expect("untouched").0, b"bx created\n", "{case}");
            let again = session
                .apply(write_to(&home, ".other", "x\n", Mode::DEFAULT_FILE))
                .expect_err("the session is poisoned");
            assert!(
                matches!(again, Error::Poisoned { .. }),
                "{case}: got {again}"
            );
            drop(session);

            let loaded = load(&state.journal()).expect("load");
            assert!(
                !matches!(loaded, Loaded::Unreadable { .. }),
                "{case}: {loaded:?}"
            );
            assert_eq!(loaded.intents().count(), 0, "{case}: nothing was announced");
            assert_eq!(
                crate::recover::recover(&state).expect("recover"),
                crate::recover::Outcome::RolledBack { undone: 0 },
                "{case}"
            );
            assert!(
                LedgerView::read(&state, &home)
                    .expect("read the ledger")
                    .value
                    .get(&portable)
                    .is_some(),
                "{case}: bx still manages the file"
            );
        }
    }

    #[test]
    fn a_claim_that_cannot_be_made_portable_is_an_error_not_dropped() {
        // r3 coverage C3. No admitted removal and no believed journal reaches
        // this since D2: every claim is a parent of a destination rendered
        // under an absolute UTF-8 home, and every forgotten claim is a stored
        // `Portable` rendered under it. Pinned at the function, with a home
        // `Portable::from_path` refuses, so a claim is never silently lost.
        use std::os::unix::ffi::OsStrExt as _;

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let outside = tempfile::tempdir().expect("a directory outside the home");
        let dir = outside.path().join("made");
        std::fs::create_dir_all(&dir).expect("the claimed directory");
        let heir =
            Portable::from_path(&dir.join("heir.conf"), home.path()).expect("an absolute target");
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let mut ledger = Ledger::open(&state, &lock, home.path())
            .expect("open the ledger")
            .value;
        ledger
            .record(NewEntry::new(
                heir,
                ContentHash::of(b"x\n"),
                Mode::DEFAULT_FILE,
                Mechanism::Own,
            ))
            .expect("an entry beneath the claim");
        let unusable = PathBuf::from(std::ffi::OsStr::from_bytes(b"/home/\xff"));

        let err = hand_off_claims(&mut ledger, &unusable, [&dir])
            .expect_err("the claim cannot be made portable");
        assert!(
            matches!(&err, Error::Write(fs::Error::NotPortable { path, .. }) if *path == dir),
            "got {err}"
        );
    }

    #[test]
    fn a_claim_the_heir_holds_is_not_recorded_again_and_a_refused_record_is_an_error() {
        // r3 round 2, P9R4-CV2. Neither the skip for a claim the heir already
        // holds nor a `record` the ledger refuses was reached. The ledger's
        // lock file is replaced, so every `record` through it is refused with
        // WrongLock: the skip is the only way the first case can succeed, and
        // the second must say so rather than drop the claim.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let dir = home.child(".config/app");
        std::fs::create_dir_all(&dir).expect("the claimed directory");
        let claim = Portable::from_path(&dir, home.path()).expect("portable");
        let heir = Portable::from_path(&dir.join("a.toml"), home.path()).expect("portable");
        for holds in [true, false] {
            let case = format!("the heir already holds the claim: {holds}");
            let lock = ExclusiveLock::acquire(&state).expect("lock");
            let mut ledger = Ledger::open(&state, &lock, home.path())
                .expect("open the ledger")
                .value;
            ledger
                .record(
                    NewEntry::new(
                        heir.clone(),
                        ContentHash::of(b"x\n"),
                        Mode::DEFAULT_FILE,
                        Mechanism::Own,
                    )
                    .with_created_dirs(if holds {
                        vec![claim.clone()]
                    } else {
                        Vec::new()
                    }),
                )
                .expect("the heir");
            let before = ledger.get(&heir).cloned().expect("recorded");
            std::fs::rename(state.lock(), home.child(format!("moved-lock-{holds}")))
                .expect("an outside mv of the lock file");
            let second = ExclusiveLock::acquire(&state).expect("a second writer");

            let handed = hand_off_claims(&mut ledger, home.path(), [&dir]);
            let after = ledger.get(&heir).cloned();
            drop(second);

            if holds {
                handed.expect("a claim the heir holds is not recorded again");
            } else {
                let err = handed.expect_err("a refused record is an error");
                assert!(
                    matches!(err, Error::State(crate::state::Error::WrongLock { .. })),
                    "{case}: got {err}"
                );
            }
            assert_eq!(after, Some(before), "{case}: nothing half-recorded");
        }
    }

    /// The ledger as it stands on disk under `state`.
    fn saved_ledger(state: &StateDir, home: &Path) -> Ledger {
        let lock = ExclusiveLock::acquire(state).expect("lock");
        Ledger::open(state, &lock, home)
            .expect("open the ledger")
            .value
    }

    #[test]
    fn a_released_write_hands_on_the_directories_its_entry_claimed() {
        // r3 round 3, D2 and CL2. `Session::write`'s released arm dropped the
        // entry `forget` returns, and with it the entry's `created_dirs`, while
        // `Session::remove` and `Session::forget` both carry theirs on. A
        // directory bx made then had no claimant at all: no later `rm` could
        // remove it, and recovery's rebuild could not either.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dir = home.child(".config/app");
        let claims: Vec<PathBuf> = vec![dir.clone(), home.child(".config")];

        // bx makes both directories for a.conf, which claims them.
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(
                home.path(),
                ".config/app/a.conf",
                "bx a\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("apply");
        session.finish().expect("finish");
        // An entry beneath the same directories that survives the hand-back.
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(
                home.path(),
                ".config/app/heir.conf",
                "bx heir\n",
                Mode::DEFAULT_FILE,
            ))
            .expect("apply");
        session.finish().expect("finish");

        let (a, a_dest) = target(home.path(), ".config/app/a.conf");
        let (heir, _) = target(home.path(), ".config/app/heir.conf");
        let ledger = saved_ledger(&state, home.path());
        assert_eq!(
            ledger
                .get(&a)
                .expect("a.conf")
                .created_dirs
                .iter()
                .map(|dir| dir.render(home.path()))
                .collect::<Vec<_>>(),
            claims,
            "a.conf claims both directories bx made",
        );
        assert!(ledger.get(&heir).expect("heir").created_dirs.is_empty());
        drop(ledger);

        // `rm` hands a.conf back: the entry goes, the file stays as the
        // user's. Both claims must reach the surviving entry beneath them.
        let mut session = Session::open(&state, SessionKind::Restore, home.path(), vec![a.clone()])
            .expect("open");
        session
            .apply(Request {
                target: a.clone(),
                dest: a_dest.clone(),
                content: Content::Bytes {
                    bytes: b"theirs\n".to_vec(),
                    planned: fs::observe(&a_dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect("hand it back");
        session.finish().expect("finish");

        let ledger = saved_ledger(&state, home.path());
        assert!(ledger.get(&a).is_none(), "the entry was handed back");
        assert_eq!(
            ledger
                .get(&heir)
                .expect("heir")
                .created_dirs
                .iter()
                .map(|dir| dir.render(home.path()))
                .collect::<Vec<_>>(),
            claims,
            "and its claims reached the entry still beneath them",
        );
        drop(ledger);
        assert_eq!(peek(&a_dest).expect("handed back").0, b"theirs\n");
        assert!(dir.is_dir(), "nothing was pruned: no removal was announced");
    }

    #[test]
    fn a_prior_already_in_the_restore_store_is_not_written_again() {
        // r3 coverage COV2. The skip arm keeps a repeat write from replacing a
        // blob another entry's prior or superseded snapshot already points at,
        // and keeps every `apply` from churning `restore/`. Only the rewrite
        // side was pinned; a mutant that always wrote passed the suite.
        use std::os::unix::fs::MetadataExt as _;

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let dest = home.child(".conf");
        plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
        let observed = fs::observe(&dest).expect("observe");

        let Prior::Existed(reference) = store_prior(&state, &observed).expect("store") else {
            panic!("a file that is there has an `Existed` prior");
        };
        let blob = state.restore().join(reference.blob_name());
        let first = std::fs::symlink_metadata(&blob).expect("the blob");

        assert_eq!(
            store_prior(&state, &observed).expect("store again"),
            Prior::Existed(reference),
        );
        let second = std::fs::symlink_metadata(&blob).expect("the blob");
        assert_eq!(
            (first.dev(), first.ino()),
            (second.dev(), second.ino()),
            "the second store wrote nothing: `write_atomically` renames a new \
             inode into place, so a rewrite cannot keep this one",
        );
        assert_eq!(std::fs::read(&blob).expect("read"), b"theirs\n");

        // And the arm is a length test, not a presence test: a blob of the
        // wrong length is replaced.
        std::fs::write(&blob, b"short\n").expect("truncate the blob");
        store_prior(&state, &observed).expect("store over a wrong-length blob");
        assert_eq!(std::fs::read(&blob).expect("read"), b"theirs\n");
    }

    #[test]
    fn a_ledger_that_refuses_after_a_publish_poisons_the_session_and_is_rolled_back() {
        // r3 coverage COV8. The sharpest of `Session::write`'s error paths past
        // the point of no return: the destination is published, the Intent is
        // durable, no `Done` follows, and the ledger refuses. Recovery must
        // roll a landed write back from a journal with no `Done`, and the
        // ledger must hold nothing for the target.
        // `Ledger::record` checks the lock file it was opened under and
        // `check_record` does not, so replacing the lock file mid-session fails
        // exactly the call after the publish.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        std::fs::rename(state.lock(), home.child("moved-lock")).expect("an outside mv of the lock");
        let second = ExclusiveLock::acquire(&state).expect("a second writer takes the new lock");

        let err = session
            .apply(write_to(home.path(), ".conf", "bx\n", Mode::DEFAULT_FILE))
            .expect_err("the ledger refuses after the publish");
        assert!(
            matches!(err, Error::State(crate::state::Error::WrongLock { .. })),
            "got {err}"
        );
        assert_eq!(
            peek(&dest).expect("published").0,
            b"bx\n",
            "the write landed before the ledger refused",
        );
        let finished = session
            .finish()
            .expect_err("a poisoned session cannot finish");
        assert!(matches!(finished, Error::Poisoned { .. }), "got {finished}");
        drop(second);

        let loaded = load(&state.journal()).expect("load");
        assert_eq!(loaded.intents().count(), 1, "the Intent is durable");
        assert!(
            !matches!(loaded, Loaded::Terminated(_)),
            "and no End followed it",
        );
        assert!(
            !frame_starts(&std::fs::read(state.journal()).expect("read")).is_empty(),
            "the journal holds whole frames",
        );

        let outcome = crate::recover::before_writing(&state).expect("the next writing run");
        assert!(
            matches!(outcome, crate::recover::Outcome::RolledBack { undone: 1 }),
            "{outcome:?}"
        );
        assert_eq!(
            peek(&dest).expect("rolled back").0,
            b"theirs\n",
            "the landed write was undone",
        );
        assert!(
            saved_ledger(&state, home.path()).get(&portable).is_none(),
            "and the ledger holds nothing for the target",
        );
    }

    #[test]
    fn a_session_counts_every_write_it_published() {
        // Coverage review round 5, non-blocking.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        for rel in [".one", ".two", ".three"] {
            session
                .apply(write_to(home.path(), rel, "x\n", Mode::DEFAULT_FILE))
                .expect("apply");
        }
        assert_eq!(session.written(), 3);
        assert_eq!(session.finish().expect("finish"), 3);
    }
}
