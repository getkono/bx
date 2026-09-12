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
//!    at the final mode, with no content. The destination is untouched.
//! 2. [`crate::fs::Staged::fill`] writes the content and `fsync`s it. The
//!    destination is still untouched.
//! 3. the **prior** bytes are copied into `restore/` and `fsync`ed, so the
//!    bytes a rollback needs are durable before anything can displace them.
//! 4. the [`Intent`] frame is appended and `fsync`ed.
//! 5. **only then** [`crate::fs::Filled::publish`] renames the temporary file
//!    into place and `fsync`s the directory.
//! 6. a [`Done`] frame is appended and `fsync`ed.
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
//! # Why the journal is not written through [`crate::fs::atomic`]
//!
//! Everything else in bx reaches the filesystem through one atomic write —
//! temporary file, `fsync`, `rename`. A write-ahead log cannot: it is *appended*
//! to and `fsync`ed in place, and replacing it by `rename` would discard the
//! frames it exists to keep. It is opened once per session, appended to with one
//! `write` call per frame so a torn frame can only ever be the file's last
//! bytes, and unlinked — last of all — when the session ends.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode as RawMode, OFlags};
use serde::{Deserialize, Serialize};

use crate::fs::{self, Mode, Observed};
use crate::paths::Portable;
use crate::state::{
    ContentHash, ExclusiveLock, Ledger, LedgerView, Mechanism, Prior, PriorBytes, RestoreRef,
    StateDir,
};

/// The seven bytes every journal starts with.
const MAGIC: &[u8; 7] = b"BXJRNL\0";

/// The newest journal format this build writes and understands.
const FORMAT: u8 = 1;

/// The header's width: [`MAGIC`] plus one version byte.
const HEADER: usize = MAGIC.len() + 1;

/// The widest frame that will be written or read.
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
    /// **Advisory and reporting-only.** Recovery never consults it: the
    /// [`Intent`] records alone decide what is undone. A caller may pass the
    /// announced pending set or the whole resolved target list as a superset,
    /// and recovery behaves identically either way — an under-set is a reporting
    /// inaccuracy, not a safety defect.
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
    /// created. Deleting by pattern in a directory the user owns is the wrong
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
    /// The header, or the first frame after it, is not a bx journal.
    ///
    /// It carries no information, so there is nothing to recover and nothing
    /// recovery could damage. The bytes are moved aside — never deleted — and
    /// the caller treats this exactly as [`Loaded::Absent`]. What the write may
    /// have completed is then recomputed by `plan`, which reports a file bx
    /// wrote but never recorded as a conflict: skipped, never overwritten.
    Unreadable {
        /// Where the bytes were kept, or `None` if they could not be moved.
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
            Self::Terminated(records) | Self::Unterminated(records) => records,
            Self::Absent | Self::Unreadable { .. } => &[],
        }
    }

    /// Whether a session is unresolved: recorded, and not known to be cleared.
    #[must_use]
    pub const fn is_interrupted(&self) -> bool {
        matches!(self, Self::Terminated(_) | Self::Unterminated(_))
    }
}

/// Read a journal, classifying anything a crash can leave behind.
///
/// A torn *tail* frame is discarded: the ordering discipline in
/// [`Session::apply`] means a frame whose `fsync` had not returned announces a
/// write that had not begun. A bad *header*, or garbage where the first frame
/// should be, is [`Loaded::Unreadable`] — quarantined to `journal.mpk.corrupt`
/// and reported at `error`.
///
/// # Errors
///
/// [`Error::Io`] when the file exists and cannot be read at all. Damage is a
/// value, not an error; only a failure to look is.
pub fn load(path: &Path) -> Result<Loaded, Error> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::Absent),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    if bytes.len() < HEADER || &bytes[..MAGIC.len()] != MAGIC.as_slice() {
        return Ok(quarantine(
            path,
            "it does not start with a bx journal header",
        ));
    }
    if bytes[MAGIC.len()] != FORMAT {
        return Ok(quarantine(
            path,
            "it is a journal format this bx cannot read",
        ));
    }

    let mut records = Vec::new();
    let mut at = HEADER;
    while let Some((record, next)) = frame(&bytes, at) {
        records.push(record);
        at = next;
    }

    // A header with bytes after it that yield no whole record is garbage rather
    // than a clean, empty log. A header with *nothing* after it is the real
    // state a crash between creating the file and appending `Begin` leaves.
    if records.is_empty() && at < bytes.len() {
        return Ok(quarantine(path, "no whole record follows the header"));
    }
    if at < bytes.len() {
        tracing::debug!(
            path = %path.display(),
            discarded = bytes.len() - at,
            "discarding a torn trailing journal frame",
        );
    }

    Ok(if matches!(records.last(), Some(Record::End(_))) {
        Loaded::Terminated(records)
    } else {
        Loaded::Unterminated(records)
    })
}

/// Decode the frame at `at`, or `None` for anything that is not a whole one.
fn frame(bytes: &[u8], at: usize) -> Option<(Record, usize)> {
    let body = at.checked_add(size_of::<u32>())?;
    let len: [u8; 4] = bytes.get(at..body)?.try_into().ok()?;
    let len = usize::try_from(u32::from_le_bytes(len)).ok()?;
    // Zero is not a length any record can have — an encoded container is at
    // least one byte — so a run of NUL bytes ends the log rather than decoding.
    if len == 0 || len > MAX_FRAME {
        return None;
    }
    let end = body.checked_add(len)?;
    let record = rmp_serde::from_slice::<Record>(bytes.get(body..end)?).ok()?;
    Some((record, end))
}

/// Move a journal that carries no information aside, and say so.
fn quarantine(path: &Path, why: &str) -> Loaded {
    let aside = StateDir::quarantine(path);
    match std::fs::rename(path, &aside) {
        Ok(()) => {
            tracing::error!(
                path = %path.display(),
                moved_to = %aside.display(),
                "discarding the write-ahead journal {}: {why}. \
                 The bytes were kept, not deleted. Run `bx plan`: a file bx \
                 wrote but never recorded is reported as a conflict, never \
                 overwritten.",
                path.display(),
            );
            Loaded::Unreadable {
                moved_to: Some(aside),
            }
        }
        Err(source) => {
            tracing::error!(
                path = %path.display(),
                %source,
                "discarding the write-ahead journal {}: {why}. \
                 It could not be moved aside.",
                path.display(),
            );
            Loaded::Unreadable { moved_to: None }
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
}

impl Journal {
    /// Truncate-and-create the journal, write its header, and `fsync` both the
    /// file and the directory holding it.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] wrapping the first failing syscall.
    pub fn create(path: &Path) -> Result<Self, Error> {
        let fail = |source| Error::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(Mode::PRIVATE_FILE.bits())
            .open(path)
            .map_err(fail)?;
        // `OpenOptions::mode` is masked by the process umask; `fchmod` is not.
        rustix::fs::fchmod(&file, Mode::PRIVATE_FILE.into())
            .map_err(|source| fail(source.into()))?;

        let mut journal = Self {
            file,
            path: path.to_path_buf(),
        };
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(MAGIC);
        header.push(FORMAT);
        journal.emit(&header)?;
        if let Some(dir) = path.parent() {
            fsync_dir(dir)?;
        }
        Ok(journal)
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
        let payload = rmp_serde::to_vec_named(record).map_err(|source| Error::Encode { source })?;
        let len = u32::try_from(payload.len())
            .ok()
            .filter(|_| payload.len() <= MAX_FRAME)
            .ok_or(Error::FrameTooLarge { len: payload.len() })?;
        // One buffer and one `write_all`, so a frame torn by a crash can only
        // ever be the last bytes of the file.
        let mut frame = Vec::with_capacity(size_of::<u32>() + payload.len());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&payload);
        self.emit(&frame)
    }

    /// Write bytes at the end of the journal and `fsync` the file.
    fn emit(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let fail = |source| Error::Io {
            path: self.path.clone(),
            source,
        };
        self.file.write_all(bytes).map_err(fail)?;
        self.file.sync_all().map_err(fail)
    }
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
    crash: Crash,
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
    Bytes(Vec<u8>),
    /// No file at all.
    ///
    /// The destination is unlinked and `created_dirs` are removed, deepest
    /// first, for as long as they are empty. Absence is not emptiness: a file bx
    /// created is removed, never truncated. The target is always dropped from
    /// the ledger — there is nothing left for bx to own.
    Absent {
        /// Directories bx created for the target, deepest first.
        created_dirs: Vec<PathBuf>,
    },
}

/// Whether bx owns what the write leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// bx manages the target from now on, attached this way.
    Owned(Mechanism),
    /// bx is handing the target back — the restore half of `bx rm`. The prior
    /// bytes are still copied into `restore/`, because that is what an
    /// interrupted restore is rolled back from; only the ledger entry goes.
    Released,
}

impl Session {
    /// Open a session: take the lock, refuse over an unresolved interruption,
    /// and write the header and the [`Begin`] frame.
    ///
    /// # Errors
    ///
    /// [`Error::InProgress`] when a journal already stands — recover first.
    /// [`Error::State`] when the directory cannot be made or locked, and
    /// [`Error::Io`] when the journal cannot be written.
    pub fn open(
        state: &StateDir,
        kind: SessionKind,
        home: &Path,
        scope: Vec<Portable>,
    ) -> Result<Self, Error> {
        state.ensure()?;
        // The lock first, so the check below cannot race a second bx.
        let lock = ExclusiveLock::acquire(state)?;
        let path = state.journal();
        if load(&path)?.is_interrupted() {
            return Err(Error::InProgress { path });
        }

        let ledger = Ledger::open(state, &lock)?.value;
        let mut journal = Journal::create(&path)?;
        journal.append(&Record::Begin(Begin {
            kind,
            home: home.to_path_buf(),
            scope,
        }))?;
        tracing::debug!(%kind, home = %home.display(), "opened a journalled session");

        Ok(Self {
            journal,
            state: state.clone(),
            ledger,
            home: home.to_path_buf(),
            written: 0,
            crash: Crash::from_env(),
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
    pub fn forget(&mut self, target: &Portable) {
        self.ledger.forget(target);
    }

    /// Make `request` true at its destination, durably and recoverably.
    ///
    /// The one place the ordering discipline this module documents is expressed,
    /// and therefore the only place it can be got wrong.
    ///
    /// # Errors
    ///
    /// [`Error::Write`] when the destination cannot be written or is not a file
    /// bx may replace, [`Error::State`] when the prior bytes cannot be stored,
    /// and [`Error::Io`] when the journal cannot be appended to.
    pub fn apply(&mut self, request: Request) -> Result<(), Error> {
        let index = self.written;
        let Request {
            target,
            dest,
            content,
            mode,
            ownership,
        } = request;
        self.crash.reached(index, Phase::BeforeStage);
        match content {
            Content::Bytes(bytes) => self.write(index, target, dest, &bytes, mode, &ownership)?,
            Content::Absent { created_dirs } => {
                self.remove(index, target, dest, created_dirs)?;
            }
        }
        self.written += 1;
        Ok(())
    }

    /// The write path: stage, fill, record, journal, publish, done.
    fn write(
        &mut self,
        index: usize,
        target: Portable,
        dest: PathBuf,
        bytes: &[u8],
        mode: Mode,
        ownership: &Ownership,
    ) -> Result<(), Error> {
        let staged = fs::stage(&dest, mode)?;
        let temp = staged.temp_path().to_path_buf();
        self.crash.reached(index, Phase::AfterStage);

        let filled = staged.fill(bytes)?;
        self.crash.reached(index, Phase::AfterFill);

        let created_dirs = filled.created_dirs().to_vec();
        // Durable before the Intent frame that names it, and therefore before
        // anything can displace it.
        let before = store_prior(&self.state, filled.prior())?;
        let mechanism = match ownership {
            Ownership::Owned(mechanism) => {
                self.ledger
                    .record(filled.new_entry(&self.home, mechanism.clone()))?;
                Some(mechanism.clone())
            }
            // The restore half of `bx rm`: bx is handing the target back, so
            // there is nothing left for it to own.
            Ownership::Released => {
                self.ledger.forget(&target);
                None
            }
        };

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
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        filled.publish()?;
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// The removal path: record, journal, unlink, prune, done.
    fn remove(
        &mut self,
        index: usize,
        target: Portable,
        dest: PathBuf,
        created_dirs: Vec<PathBuf>,
    ) -> Result<(), Error> {
        let observed = fs::observe(&dest)?;
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
        self.ledger.forget(&target);

        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: None,
            before,
            after: Written::Absent,
            created_dirs: created_dirs.clone(),
            mechanism: None,
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        unlink(&dest)?;
        prune_dirs(&created_dirs)?;
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// End the session: [`End`], save the ledger, and unlink the journal last.
    ///
    /// The order is the ordering rule that makes recovery idempotent. The `End`
    /// frame goes down first, so a crash before the save is a *terminated*
    /// journal that recovery finishes as bookkeeping and no destination is
    /// touched; the journal is unlinked last, so a crash before that simply
    /// repeats a recovery that had nothing left to do.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], [`Error::State`] or [`Error::Write`]. The journal is left
    /// in place on any failure, so the session stays recoverable.
    pub fn finish(mut self) -> Result<usize, Error> {
        let written = self.written;
        self.journal.append(&Record::End(End { written }))?;
        self.ledger.save()?;
        unlink(self.journal.path())?;
        tracing::debug!(written, "closed a journalled session");
        Ok(written)
    }
}

/// The boundaries [`Session::apply`] crosses, named so a test can stop at one.
///
/// Six, and each is a real durability boundary rather than a convenient line:
/// before anything exists; after a temporary file exists at its final mode but
/// holds nothing; after its content is `fsync`ed but the destination is
/// untouched; after the intent is durable; after the destination is replaced;
/// after the completion is durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    BeforeStage,
    AfterStage,
    AfterFill,
    AfterIntent,
    AfterPublish,
    AfterDone,
}

/// Every phase, in the order [`Session::apply`] passes them.
#[cfg(test)]
const PHASES: [Phase; 6] = [
    Phase::BeforeStage,
    Phase::AfterStage,
    Phase::AfterFill,
    Phase::AfterIntent,
    Phase::AfterPublish,
    Phase::AfterDone,
];

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
    // The same test the ledger's own blob store makes: a content-addressed name
    // holding the right number of bytes already holds these bytes.
    if blob_len(&path) != Some(len) {
        fs::write_atomically(&path, &bytes, Mode::PRIVATE_FILE)?;
    }
    Ok(Prior::Existed(reference))
}

/// The length of an existing restore blob, or `None` if there is no file there.
fn blob_len(path: &Path) -> Option<u64> {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|meta| meta.len())
}

/// Remove `path` if it is there, and `fsync` the directory it was in.
///
/// Absence is success: the whole recovery path is re-runnable, and a second run
/// finds what the first removed already gone.
///
/// # Errors
///
/// [`Error::Io`] wrapping the failing `unlink` or `fsync`.
pub(crate) fn unlink(path: &Path) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    if let Some(dir) = path.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}

/// Remove directories bx created, deepest first, stopping at the first that is
/// not empty.
///
/// The stop is the point: a directory that has acquired anything else is no
/// longer only bx's, and removing it would delete something bx did not put
/// there.
///
/// # Errors
///
/// [`Error::Io`] for a failure that is neither "already gone" nor "not empty".
pub(crate) fn prune_dirs(dirs: &[PathBuf]) -> Result<(), Error> {
    for dir in dirs {
        match std::fs::remove_dir(dir) {
            Ok(()) => tracing::debug!(dir = %dir.display(), "removed a directory bx created"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            // `ENOTEMPTY` and `EEXIST` are both permitted spellings of "it is
            // not empty", and `std::io::ErrorKind` maps neither stably.
            Err(e)
                if matches!(
                    e.raw_os_error().map(rustix::io::Errno::from_raw_os_error),
                    Some(rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST)
                ) =>
            {
                break;
            }
            Err(source) => {
                return Err(Error::Io {
                    path: dir.clone(),
                    source,
                });
            }
        }
    }
    Ok(())
}

/// `fsync` a directory, so a rename or an unlink inside it survives a power
/// loss.
///
/// # Errors
///
/// [`Error::Io`] wrapping the failing `open` or `fsync`.
pub(crate) fn fsync_dir(dir: &Path) -> Result<(), Error> {
    let fail = |source: rustix::io::Errno| Error::Io {
        path: dir.to_path_buf(),
        source: source.into(),
    };
    let fd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        RawMode::empty(),
    )
    .map_err(fail)?;
    rustix::fs::fsync(&fd).map_err(fail)
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
        (Portable::from_path(&dest, home), dest)
    }

    /// A write request for `rel` under `home`.
    pub(crate) fn write_to(home: &Path, rel: &str, bytes: &str, mode: Mode) -> Request {
        let (target, dest) = target(home, rel);
        Request {
            target,
            dest,
            content: Content::Bytes(bytes.as_bytes().to_vec()),
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
        let begin = Record::Begin(Begin {
            kind: SessionKind::Restore,
            home: PathBuf::from("/home/someone"),
            scope: vec![Portable::parse("~/.bashrc").expect("portable")],
        });
        let done = Record::Done(Done {
            target: Portable::parse("~/.bashrc").expect("portable"),
        });

        let mut journal = Journal::create(&path).expect("create");
        journal.append(&begin).expect("append");
        journal.append(&done).expect("append");
        drop(journal);

        let loaded = load(&path).expect("load");
        assert_eq!(loaded, Loaded::Unterminated(vec![begin, done]));
    }

    #[test]
    fn the_journal_is_created_at_0600_and_replaces_whatever_was_there() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        plant_file(&path, "not a journal at all", Mode::DEFAULT_FILE);

        let journal = Journal::create(&path).expect("create");
        assert_eq!(journal.path(), path);
        let (bytes, mode) = peek(&path).expect("the journal");
        assert_eq!(mode, Mode::PRIVATE_FILE);
        assert_eq!(bytes.len(), HEADER, "truncated to just the header");
    }

    #[test]
    fn a_fresh_state_directory_has_no_session() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        assert_eq!(load(&state.journal()).expect("load"), Loaded::Absent);
    }

    #[test]
    fn a_journal_with_a_bad_header_is_moved_aside_and_read_as_absent() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        plant_file(&path, "GARBAGE!", Mode::PRIVATE_FILE);

        let loaded = load(&path).expect("load");
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
    fn a_journal_too_short_to_hold_a_header_is_unreadable() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        plant_file(&path, "BX", Mode::PRIVATE_FILE);
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unreadable { .. }
        ));
    }

    #[test]
    fn a_journal_from_a_future_format_is_moved_aside() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT + 1);
        std::fs::write(&path, &bytes).expect("write");
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unreadable { .. }
        ));
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
    fn nul_bytes_after_a_whole_frame_end_the_log_rather_than_decoding() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let begin = Record::Begin(Begin {
            kind: SessionKind::Apply,
            home: PathBuf::from("/home/someone"),
            scope: Vec::new(),
        });
        let mut journal = Journal::create(&path).expect("create");
        journal.append(&begin).expect("append");
        drop(journal);

        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend(std::iter::repeat_n(0_u8, 512));
        std::fs::write(&path, &bytes).expect("write");

        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unterminated(vec![begin])
        );
    }

    #[test]
    fn a_header_with_nothing_after_it_is_an_empty_interrupted_session() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        drop(Journal::create(&path).expect("create"));
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
        let ledger = LedgerView::read(&state).expect("read the ledger").value;
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
        let records = vec![
            Record::Begin(Begin {
                kind: SessionKind::Apply,
                home: PathBuf::from("/home/someone"),
                scope: vec![Portable::parse("~/.a").expect("portable")],
            }),
            Record::Done(Done {
                target: Portable::parse("~/.a").expect("portable"),
            }),
            Record::Done(Done {
                target: Portable::parse("~/.b").expect("portable"),
            }),
            Record::End(End { written: 2 }),
        ];

        // Record the file length after each frame, so "every whole frame" is an
        // exact expectation rather than an approximation.
        let mut journal = Journal::create(&source).expect("create");
        let mut boundaries: Vec<usize> = Vec::new();
        for record in &records {
            journal.append(record).expect("append");
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

            let kept: usize = boundaries.iter().filter(|end| **end <= cut).count();
            if cut < HEADER || (kept == 0 && cut > HEADER) {
                assert!(
                    matches!(loaded, Loaded::Unreadable { .. }),
                    "cut at {cut} should carry no information, got {loaded:?}",
                );
                continue;
            }
            assert_eq!(
                loaded.records(),
                &records[..kept],
                "cut at {cut} should keep exactly {kept} whole frame(s)",
            );
            assert_eq!(
                matches!(loaded, Loaded::Terminated(_)),
                kept == records.len(),
                "cut at {cut} is terminated only once the End frame is whole",
            );
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
        let entry = LedgerView::read(&state)
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
                dest,
                content: Content::Bytes(b"yours\n".to_vec()),
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            })
            .expect("apply");
        assert!(session.ledger().get(&portable).is_none());
        session.finish().expect("finish");

        assert!(
            LedgerView::read(&state)
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
                dest,
                content: Content::Absent {
                    created_dirs: Vec::new(),
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

        let err = session
            .apply(Request {
                target: target(home.path(), ".conf").0,
                dest: home.child(".conf"),
                content: Content::Absent {
                    created_dirs: Vec::new(),
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
        let begin = Record::Begin(Begin {
            kind: SessionKind::Apply,
            home: PathBuf::from("/home/someone"),
            scope: Vec::new(),
        });
        let mut journal = Journal::create(&path).expect("create");
        journal.append(&begin).expect("append");
        drop(journal);
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
}
