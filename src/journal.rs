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
//! 2. [`crate::fs::atomic::Staged::fill`] writes the content and `fsync`s it. The
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
//! always safe to discard, which is what makes [`load`](fn@load) correct: if the frame's
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
//! after it, so a journal [`load`](fn@load) discarded anything from is [`Loaded::Torn`],
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
//! stores the snapshot recovery needs itself — see `session::store_prior` — and the
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
//! [`load`](fn@load) — an Intent recovery could never act on. A failed publish leaves an Intent with no
//! Done, which an `End` frame and a ledger save would close out as though it
//! had landed.

//!
//! # Where each part lives
//!
//! - `format` — the bytes on disk: the header, the framing and its checksum,
//!   and the records a frame holds.
//! - `writer` — [`Journal`], the file a session creates whole and then appends
//!   to in place.
//! - `load` — reading a journal back, judging what it says against the home it
//!   names, and setting aside one that cannot be believed.
//! - `session` — [`Session`], the ordering above for every kind of request,
//!   and what ends or poisons it.
//! - `crash` — the test build's seam that stops a session at a named boundary.
//!
//! Each part's tests sit beside it. `tests` holds the fixtures they share with
//! one another and with the recovery, restore and plan suites, and the tests
//! that pin those fixtures.

mod crash;
mod format;
mod load;
mod session;
#[cfg(test)]
pub(crate) mod tests;
mod writer;

use std::path::PathBuf;

use crate::fs;
use crate::paths::Portable;
use format::MAX_FRAME;

pub use format::{Begin, Done, End, Intent, Record, SessionKind, Written};
pub(crate) use load::set_aside;
pub use load::{Loaded, load, load_exclusive};
pub use session::{Content, Ownership, Request, Session};
pub use writer::Journal;

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
    /// recovery, and `crate::recover::abandon` moves it aside.
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
    /// runs first, or `crate::recover::abandon` when recovery is blocked.
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
    /// [`load`](fn@load) applies the same rule — and because pruning it could remove a
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

/// A durable removal that failed is reported as one of the session's own:
/// [`Error::Io`], naming the path.
impl From<fs::remove::Error> for Error {
    fn from(error: fs::remove::Error) -> Self {
        let fs::remove::Error { path, source } = error;
        Self::Io { path, source }
    }
}
