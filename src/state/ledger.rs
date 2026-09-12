//! What bx wrote, and what it displaced.
//!
//! The ledger is the record Invariant 4 rests on. For every target bx has
//! written it holds the digest of the bytes bx left there, the mode it set, how
//! it attached to the file, and — content-addressed in `restore/` — the exact
//! bytes that were there before, or the explicit fact that nothing was.
//!
//! Two types, deliberately:
//!
//! * [`LedgerView`] is read-only and takes no lock. `plan` uses it. A state file
//!   is always replaced by `rename`, so a reader sees a whole file or the
//!   previous whole file, never a torn one.
//! * [`Ledger`] is writable and can only be obtained by presenting an
//!   [`ExclusiveLock`], so `&mut Ledger` is itself the proof that the state
//!   directory is locked and no second `bx` is writing to it.

use std::collections::BTreeMap;
use std::collections::btree_map::Iter;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Error;
use super::dir::{StateDir, ensure_dir};
use super::hash::ContentHash;
use super::lock::ExclusiveLock;
use super::store::{self, Loaded};
use crate::fs::{Mode, write_atomically};

/// The envelope tag for `ledger.mpk`.
const KIND: &str = "bx.ledger";

/// The newest ledger format this build writes and understands.
const VERSION: u16 = 1;

/// How bx attached itself to a target file.
///
/// A ledger-owned enum rather than a reference to the configuration model: the
/// on-disk record must stay readable when the configuration changes shape, and
/// `bx rm` must be able to restore a target whose configuration entry has since
/// been deleted — at which point there is no configuration value left to
/// deserialise into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mechanism {
    /// bx owns the whole file, because the user said so.
    Own,
    /// bx owns a delimited region inside a file the user also writes.
    Region {
        /// The comment character the region markers use.
        comment: char,
    },
    /// bx added one line that sources a file it owns elsewhere.
    Include {
        /// The exact line bx added.
        line: String,
    },
}

/// A pointer to the bytes that were at a target before bx wrote it.
///
/// The blob is stored under its own digest, so two targets that displaced
/// identical bytes share one copy and re-recording the same bytes writes
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRef {
    /// The digest of the prior bytes, and the name of the blob holding them.
    pub digest: ContentHash,
    /// The mode the file had before bx touched it.
    pub mode: Mode,
    /// How many bytes it was. Redundant with the blob, and cheap: it lets
    /// `plan` describe a restore without reading the blob at all.
    pub len: u64,
}

impl RestoreRef {
    /// The file name of this snapshot inside `restore/`.
    #[must_use]
    pub fn blob_name(&self) -> String {
        self.digest.to_hex()
    }
}

/// What was at a target before bx wrote it.
///
/// [`Prior::Absent`] is a variant rather than `Option::None` or an empty blob
/// because "the file did not exist" and "the file existed and was empty" need
/// opposite restores — unlink, versus write zero bytes — and Invariant 4 says
/// *exactly*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prior {
    /// There was no file. `bx rm` unlinks rather than truncating.
    Absent,
    /// There was a file, and these are its bytes.
    Existed(RestoreRef),
}

/// One target, as bx last left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// The target. Home-relative, so the ledger survives a home that moves.
    pub path: crate::paths::Portable,
    /// The digest of the target's **whole** bytes as bx last left them.
    ///
    /// Whole-file, not just bx's contribution, because that is the only digest
    /// that decides the question `plan` has to answer for a file bx shares with
    /// the user: if the bytes on disk still hash to this, nobody but bx has
    /// touched the file and a rewrite is a `Modify`; if they do not, someone
    /// else has, and it is a `Conflict`.
    pub written: ContentHash,
    /// The mode bx set on the target.
    pub mode: Mode,
    /// How bx attached to it.
    pub mechanism: Mechanism,
    /// What was there before — or that nothing was.
    pub prior: Prior,
    /// Directories bx created on the way to the target, deepest first, so
    /// `bx rm` can remove them in order and leave nothing behind.
    #[serde(default)]
    pub created_dirs: Vec<crate::paths::Portable>,
}

/// The bytes a target held before bx wrote it, as handed to [`Ledger::record`].
///
/// The writing half of [`Prior`]: the caller supplies bytes, `record` turns them
/// into a durable blob and a [`RestoreRef`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorBytes {
    /// There was no file.
    Absent,
    /// There was a file with these bytes and this mode.
    Bytes {
        /// Its contents, verbatim.
        bytes: Vec<u8>,
        /// Its mode.
        mode: Mode,
    },
}

/// A target to record, before its prior bytes have been stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEntry {
    /// The target.
    pub path: crate::paths::Portable,
    /// The digest of the whole bytes bx just wrote there.
    pub written: ContentHash,
    /// The mode bx set.
    pub mode: Mode,
    /// How bx attached to it.
    pub mechanism: Mechanism,
    /// What was there before.
    pub prior: PriorBytes,
    /// Directories bx created for it, deepest first.
    pub created_dirs: Vec<crate::paths::Portable>,
}

impl NewEntry {
    /// A new entry for a target bx created where nothing existed.
    ///
    /// The prior defaults to [`PriorBytes::Absent`] — *there was no file* —
    /// which is only true for a target bx created. Use
    /// [`NewEntry::with_prior`] whenever there were bytes to displace.
    ///
    /// Defaulting is safe on a re-record: [`Ledger::record`] keeps the prior
    /// already stored for a path and ignores the one on the incoming entry, so
    /// an omitted prior can never overwrite the user's snapshot with
    /// "unlink it".
    #[must_use]
    pub fn new(
        path: crate::paths::Portable,
        written: ContentHash,
        mode: Mode,
        mechanism: Mechanism,
    ) -> Self {
        Self {
            path,
            written,
            mode,
            mechanism,
            prior: PriorBytes::Absent,
            created_dirs: Vec::new(),
        }
    }

    /// Record what the target held before.
    #[must_use]
    pub fn with_prior(mut self, prior: PriorBytes) -> Self {
        self.prior = prior;
        self
    }

    /// Record the directories bx created on the way, deepest first.
    #[must_use]
    pub fn with_created_dirs(mut self, dirs: Vec<crate::paths::Portable>) -> Self {
        self.created_dirs = dirs;
        self
    }
}

/// The ledger, read-only.
///
/// Takes no lock. Every state file is replaced by `rename`, so the worst a
/// reader can see is the previous whole file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerView {
    /// Keyed by target. A `BTreeMap`, never a `HashMap`: iteration order is the
    /// serialised order, and Invariant 3 forbids hash-map order in anything
    /// generated.
    #[serde(default)]
    entries: BTreeMap<crate::paths::Portable, LedgerEntry>,
}

impl LedgerView {
    /// Read the ledger without taking a lock.
    ///
    /// A damaged `ledger.mpk` is quarantined and this returns an empty ledger,
    /// with [`super::Health::Reset`] saying so.
    ///
    /// # Errors
    ///
    /// [`Error::Read`] if `ledger.mpk` exists and cannot be read. An unreadable
    /// ledger is not a damaged one: the reversibility record may be perfectly
    /// intact behind the failure, so it is neither quarantined nor replaced,
    /// and the caller must stop rather than proceed against an empty ledger.
    pub fn read(dir: &StateDir) -> Result<Loaded<Self>, Error> {
        store::load(&dir.ledger(), KIND, VERSION)
    }

    /// The entry for `path`, if bx has written it.
    #[must_use]
    pub fn get(&self, path: &crate::paths::Portable) -> Option<&LedgerEntry> {
        self.entries.get(path)
    }

    /// Every entry, in ascending path order.
    pub fn iter(&self) -> Iter<'_, crate::paths::Portable, LedgerEntry> {
        self.entries.iter()
    }

    /// How many targets bx has written.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether bx has written anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The bytes a restore snapshot holds.
    ///
    /// The digest is recomputed and checked. Silently restoring corrupted
    /// content over a file the user wrote would be worse than refusing, so this
    /// refuses.
    ///
    /// # Errors
    ///
    /// [`Error::RestoreMissing`] if the blob is gone, [`Error::RestoreCorrupt`]
    /// if its bytes do not hash to `reference.digest`, and [`Error::Read`] for
    /// any other read failure.
    pub fn restore_bytes(&self, dir: &StateDir, reference: &RestoreRef) -> Result<Vec<u8>, Error> {
        let path = blob_path(dir, &reference.digest);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::RestoreMissing {
                    digest: reference.digest,
                    path,
                });
            }
            Err(source) => return Err(Error::Read { path, source }),
        };
        if ContentHash::of(&bytes) == reference.digest {
            Ok(bytes)
        } else {
            Err(Error::RestoreCorrupt {
                digest: reference.digest,
                path,
            })
        }
    }
}

/// The ledger, writable.
///
/// Obtainable only through [`Ledger::open`], which demands an [`ExclusiveLock`].
/// A `&mut Ledger` is therefore the capability to write the state directory, and
/// no separate guard has to be threaded alongside it.
///
/// The guarantee is *the lock was held when this was opened*, not *the lock is
/// held now*: a caller could drop the guard and keep the `Ledger`. Expressing
/// the stronger property would mean a lifetime parameter on every signature that
/// names a ledger, which is the threading this design exists to avoid.
#[derive(Debug)]
pub struct Ledger {
    /// Where it lives, so `record` and `save` need no further arguments.
    dir: StateDir,
    /// The entries themselves.
    view: LedgerView,
}

impl Deref for Ledger {
    type Target = LedgerView;

    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

impl Ledger {
    /// Open the ledger for writing.
    ///
    /// The lock is not stored; requiring it here is what makes a `Ledger` proof
    /// that one was taken.
    ///
    /// A damaged `ledger.mpk` is quarantined and this returns an empty ledger,
    /// with [`super::Health::Reset`] saying so.
    ///
    /// # Errors
    ///
    /// [`Error::Read`], as [`LedgerView::read`]. This is the path that matters
    /// most: opening for *writing* against an empty ledger that only appeared
    /// empty because it could not be read would record bx's own output as every
    /// target's prior and discard the user's, so the failure is returned rather
    /// than degraded.
    pub fn open(dir: &StateDir, _lock: &ExclusiveLock) -> Result<Loaded<Self>, Error> {
        let dir = dir.clone();
        Ok(LedgerView::read(&dir)?.map(|view| Self { dir, view }))
    }

    /// The state directory this ledger was opened from.
    #[must_use]
    pub fn dir(&self) -> &StateDir {
        &self.dir
    }

    /// Record a target, replacing any entry for the same path — **except its
    /// prior, which is kept.**
    ///
    /// # First prior wins
    ///
    /// When an entry already exists for `entry.path`, the [`Prior`] stored on
    /// it is kept and `entry.prior` is ignored — no blob is written for it. The
    /// first prior is the only one that answers Invariant 4's question: it is
    /// what the *user* had before bx ever touched the file. On every later
    /// apply the bytes on disk are bx's own previous output, so a second
    /// snapshot would record bx's generated content as the thing `bx rm`
    /// restores, and `PriorBytes::Absent` — what [`NewEntry::new`] defaults to —
    /// would rewrite "restore the user's file" into "unlink it".
    ///
    /// Re-adoption, when a target genuinely has a new prior worth snapshotting,
    /// is [`Ledger::forget`] followed by `record`: two calls, so discarding a
    /// prior is always something a caller asked for.
    ///
    /// The prior bytes are written to `restore/` and **fsynced, along with the
    /// directory entry naming them, before this returns** — so by the time the
    /// caller has a [`RestoreRef`], the bytes behind it are durable and a later
    /// ledger entry referencing them cannot outlive them. The ledger itself is
    /// not written until [`Ledger::save`].
    ///
    /// A blob whose digest already names a file **of the same length** is left
    /// alone; anything else at that name is rewritten. The name is evidence of
    /// the content, not proof of it, and the guarantee this function owes its
    /// caller is that the bytes behind the returned [`RestoreRef`] are on disk.
    ///
    /// # Errors
    ///
    /// [`Error::CreateDir`] or [`Error::Write`] if the snapshot cannot be
    /// stored. The ledger is left unchanged when that happens.
    pub fn record(&mut self, entry: NewEntry) -> Result<&LedgerEntry, Error> {
        let key = entry.path.clone();
        let prior = match self.view.entries.get(&key) {
            // First prior wins. The incoming prior is dropped without being
            // stored, so re-recording never leaves an orphan blob behind.
            Some(existing) => existing.prior.clone(),
            None => self.store_prior(entry.prior)?,
        };
        self.view.entries.insert(
            key.clone(),
            LedgerEntry {
                path: entry.path,
                written: entry.written,
                mode: entry.mode,
                mechanism: entry.mechanism,
                prior,
                created_dirs: entry.created_dirs,
            },
        );
        Ok(&self.view.entries[&key])
    }

    /// Drop a target from the ledger, returning the entry that was there.
    ///
    /// This is also half of re-adoption: `forget` then [`Ledger::record`] is
    /// how a caller deliberately replaces a prior that [`Ledger::record`] alone
    /// would have kept.
    ///
    /// The restore blob is deliberately left in place: it may be shared with
    /// another entry, and content-addressed bytes cost far less than a wrong
    /// deletion. Reclaiming unreferenced blobs is not implemented.
    pub fn forget(&mut self, path: &crate::paths::Portable) -> Option<LedgerEntry> {
        self.view.entries.remove(path)
    }

    /// Turn caller-supplied prior bytes into a durable [`Prior`].
    fn store_prior(&self, prior: PriorBytes) -> Result<Prior, Error> {
        match prior {
            PriorBytes::Absent => Ok(Prior::Absent),
            PriorBytes::Bytes { bytes, mode } => {
                let digest = ContentHash::of(&bytes);
                self.store_blob(digest, &bytes)?;
                Ok(Prior::Existed(RestoreRef {
                    digest,
                    mode,
                    len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                }))
            }
        }
    }

    /// Write the ledger out, atomically.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`], [`Error::CreateDir`] or [`Error::Write`]. A failure
    /// leaves the previous ledger exactly as it was.
    pub fn save(&self) -> Result<(), Error> {
        store::save(&self.dir.ledger(), KIND, VERSION, &self.view)
    }

    /// Write `bytes` to `restore/<digest>`, durably, unless the bytes are
    /// already there.
    ///
    /// The skip is guarded by the blob's *length*, not merely by its existence.
    /// A name proves content only while nothing has damaged the file, and this
    /// design already accepts that a blob can stop matching its name — that is
    /// what [`Error::RestoreCorrupt`] is for. Checking when the bytes are in
    /// hand costs one `stat` and repairs the blob; checking only in
    /// [`LedgerView::restore_bytes`] discovers the loss when the target has
    /// already been overwritten and the original bytes exist nowhere.
    ///
    /// A `stat` rather than a re-hash: it keeps the common repeat path O(1),
    /// and the two ways a blob is plausibly lost — a truncated write and an
    /// empty file left by an interrupted one — both change the length.
    fn store_blob(&self, digest: ContentHash, bytes: &[u8]) -> Result<(), Error> {
        let restore = self.dir.restore();
        ensure_dir(&restore, Mode::PRIVATE_DIR)?;
        let path = restore.join(digest.to_hex());
        if blob_len(&path) == Some(u64::try_from(bytes.len()).unwrap_or(u64::MAX)) {
            return Ok(());
        }
        // `write_atomically` fsyncs the blob and then `restore/` itself, which
        // is what makes the snapshot durable before this function returns.
        write_atomically(&path, bytes, Mode::PRIVATE_FILE)?;
        Ok(())
    }
}

/// The length of the file at `path`, or `None` if it is not a readable file.
///
/// `None` means *rewrite it*: a blob that cannot be stat'ed is not a blob whose
/// content has been established.
fn blob_len(path: &Path) -> Option<u64> {
    let metadata = std::fs::metadata(path).ok()?;
    metadata.is_file().then_some(metadata.len())
}

/// Where a snapshot with this digest lives.
fn blob_path(dir: &StateDir, digest: &ContentHash) -> PathBuf {
    dir.restore().join(digest.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::Path;

    use crate::paths::Portable;
    use crate::state::{Damage, Fingerprint, Fingerprints, Health};
    use crate::testing::{GuardedHome, guarded_home};

    fn target(name: &str) -> Portable {
        Portable::parse(name).expect("a portable path")
    }

    fn locked(home: &GuardedHome) -> (StateDir, ExclusiveLock) {
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");
        (dir, lock)
    }

    fn entry(path: &str, body: &[u8]) -> NewEntry {
        NewEntry::new(
            target(path),
            ContentHash::of(body),
            Mode::DEFAULT_FILE,
            Mechanism::Own,
        )
    }

    fn mode_of(path: &Path) -> Mode {
        Mode::from_bits(std::fs::metadata(path).expect("stat").permissions().mode())
    }

    #[test]
    fn recording_a_target_stores_the_digest_mode_mechanism_and_prior_snapshot() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        let stored = ledger
            .record(
                entry("~/.config/tool.toml", b"new")
                    .with_prior(PriorBytes::Bytes {
                        bytes: b"old".to_vec(),
                        mode: Mode::from_bits(0o640),
                    })
                    .with_created_dirs(vec![target("~/.config/tool")]),
            )
            .expect("record")
            .clone();

        assert_eq!(stored.path, target("~/.config/tool.toml"));
        assert_eq!(stored.written, ContentHash::of(b"new"));
        assert_eq!(stored.mode, Mode::DEFAULT_FILE);
        assert_eq!(stored.mechanism, Mechanism::Own);
        assert_eq!(stored.created_dirs, vec![target("~/.config/tool")]);
        let Prior::Existed(reference) = &stored.prior else {
            panic!("expected a prior snapshot, got {:?}", stored.prior)
        };
        assert_eq!(reference.digest, ContentHash::of(b"old"));
        assert_eq!(reference.mode, Mode::from_bits(0o640));
        assert_eq!(reference.len, 3);
        assert_eq!(reference.blob_name(), ContentHash::of(b"old").to_hex());
        assert_eq!(ledger.len(), 1);
        assert!(!ledger.is_empty());
    }

    #[test]
    fn the_prior_blob_is_durable_before_record_returns() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"new").with_prior(PriorBytes::Bytes {
                bytes: b"prior bytes".to_vec(),
                mode: Mode::PRIVATE_FILE,
            }))
            .expect("record");

        // No `save` has happened. The blob must already be on disk.
        let blob = dir.restore().join(ContentHash::of(b"prior bytes").to_hex());
        assert_eq!(std::fs::read(&blob).expect("read"), b"prior bytes");
        assert_eq!(mode_of(&blob), Mode::PRIVATE_FILE);
        assert!(!dir.ledger().exists(), "the ledger itself is not yet saved");
    }

    #[test]
    fn re_recording_a_target_replaces_in_place_and_keeps_the_first_prior() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        // Apply #1: the user's own file is displaced and snapshotted.
        ledger
            .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
                bytes: b"the user wrote this".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("first");
        // Apply #2: the natural call, with no prior — what is on disk now is
        // bx's own output from apply #1, so there is nothing to snapshot.
        ledger
            .record(entry("~/.bashrc", b"second"))
            .expect("second");

        assert_eq!(ledger.len(), 1);
        let stored = ledger.get(&target("~/.bashrc")).expect("entry");
        assert_eq!(stored.written, ContentHash::of(b"second"));
        let Prior::Existed(reference) = &stored.prior else {
            panic!(
                "the first prior must survive a re-record, got {:?}",
                stored.prior
            );
        };
        assert_eq!(reference.digest, ContentHash::of(b"the user wrote this"));
        assert_eq!(
            ledger.restore_bytes(&dir, reference).expect("restore"),
            b"the user wrote this",
        );
    }

    #[test]
    fn a_re_record_neither_stores_nor_adopts_the_incoming_prior() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
                bytes: b"the user wrote this".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("first");
        ledger
            .record(entry("~/.bashrc", b"second").with_prior(PriorBytes::Bytes {
                bytes: b"bx generated this".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("second");

        let stored = ledger.get(&target("~/.bashrc")).expect("entry");
        let Prior::Existed(reference) = &stored.prior else {
            panic!("expected the first prior");
        };
        assert_eq!(reference.digest, ContentHash::of(b"the user wrote this"));
        // The ignored prior is never written, so re-recording leaves no orphan.
        let blobs: Vec<_> = std::fs::read_dir(dir.restore())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            blobs,
            vec![std::ffi::OsString::from(
                ContentHash::of(b"the user wrote this").to_hex()
            )],
        );
    }

    #[test]
    fn forget_then_record_re_adopts_a_target_with_a_new_prior() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
                bytes: b"the user wrote this".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("first");
        let dropped = ledger.forget(&target("~/.bashrc")).expect("forget");
        assert_eq!(dropped.written, ContentHash::of(b"first"));

        ledger
            .record(entry("~/.bashrc", b"second").with_prior(PriorBytes::Bytes {
                bytes: b"and then the user wrote that".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("re-adopt");
        let stored = ledger.get(&target("~/.bashrc")).expect("entry");
        let Prior::Existed(reference) = &stored.prior else {
            panic!("expected the re-adopted prior");
        };
        assert_eq!(
            reference.digest,
            ContentHash::of(b"and then the user wrote that"),
        );
    }

    #[test]
    fn a_re_record_cannot_turn_a_snapshot_into_an_unlink() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
                bytes: b"the user wrote this".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("first");
        for _ in 0..3 {
            ledger
                .record(entry("~/.bashrc", b"again"))
                .expect("re-record");
            assert_ne!(
                ledger.get(&target("~/.bashrc")).expect("entry").prior,
                Prior::Absent,
                "re-recording must never rewrite a restore into an unlink",
            );
        }
    }

    #[test]
    fn a_file_bx_created_records_explicit_non_existence() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        let stored = ledger.record(entry("~/.config/new", b"x")).expect("record");
        assert_eq!(stored.prior, Prior::Absent);
    }

    #[test]
    fn an_empty_prior_file_is_distinguishable_from_no_prior_file() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/empty", b"x").with_prior(PriorBytes::Bytes {
                bytes: Vec::new(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
        ledger.record(entry("~/absent", b"x")).expect("record");

        let empty = ledger.get(&target("~/empty")).expect("entry");
        let absent = ledger.get(&target("~/absent")).expect("entry");
        assert_eq!(absent.prior, Prior::Absent);
        let Prior::Existed(reference) = &empty.prior else {
            panic!("an empty file is not an absent one")
        };
        assert_eq!(reference.len, 0);
        assert_eq!(
            ledger.restore_bytes(&dir, reference).expect("restore"),
            Vec::<u8>::new(),
        );
    }

    #[test]
    fn prior_bytes_round_trip_byte_identically() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        let body: Vec<u8> = (0..=255_u8)
            .chain(b"\n\0trailing".iter().copied())
            .collect();
        ledger
            .record(entry("~/.binary", b"x").with_prior(PriorBytes::Bytes {
                bytes: body.clone(),
                mode: Mode::PRIVATE_FILE,
            }))
            .expect("record");
        ledger.save().expect("save");

        let reloaded = LedgerView::read(&dir).expect("read").value;
        let Prior::Existed(reference) = &reloaded.get(&target("~/.binary")).expect("entry").prior
        else {
            panic!("expected a snapshot")
        };
        assert_eq!(
            reloaded.restore_bytes(&dir, reference).expect("restore"),
            body,
        );
    }

    #[test]
    fn a_prior_mode_survives_the_round_trip() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        // `~/.ssh/config` at 0600 is the case this exists for: restoring it at
        // 0644 would be a security regression dressed up as a restore.
        ledger
            .record(entry("~/.ssh/config", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"Host *\n".to_vec(),
                mode: Mode::PRIVATE_FILE,
            }))
            .expect("record");
        ledger.save().expect("save");

        let reloaded = LedgerView::read(&dir).expect("read").value;
        let Prior::Existed(reference) = &reloaded.get(&target("~/.ssh/config")).expect("e").prior
        else {
            panic!("expected a snapshot")
        };
        assert_eq!(reference.mode, Mode::PRIVATE_FILE);
    }

    #[test]
    fn the_written_digest_identifies_a_file_nothing_has_touched() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let path = home.write(".config/untouched", "as bx left it");
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/.config/untouched", b"as bx left it"))
            .expect("record");

        let on_disk = ContentHash::of_file(&path).expect("hash");
        assert_eq!(
            ledger
                .get(&target("~/.config/untouched"))
                .expect("entry")
                .written,
            on_disk,
        );
    }

    #[test]
    fn the_written_digest_detects_a_file_changed_since_bx_wrote_it() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let path = home.write(".config/edited", "as bx left it");
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/.config/edited", b"as bx left it"))
            .expect("record");

        std::fs::write(&path, "a human edited this").expect("edit");
        let on_disk = ContentHash::of_file(&path).expect("hash");
        assert_ne!(
            ledger
                .get(&target("~/.config/edited"))
                .expect("entry")
                .written,
            on_disk,
        );
    }

    #[test]
    fn two_targets_with_identical_prior_bytes_share_one_blob() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        for name in ["~/a", "~/b"] {
            ledger
                .record(entry(name, b"x").with_prior(PriorBytes::Bytes {
                    bytes: b"same".to_vec(),
                    mode: Mode::DEFAULT_FILE,
                }))
                .expect("record");
        }
        let blobs: Vec<_> = std::fs::read_dir(dir.restore())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(blobs.len(), 1, "content addressing means one copy");
    }

    #[test]
    fn recording_the_same_prior_bytes_twice_writes_the_blob_once() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        let prior = PriorBytes::Bytes {
            bytes: b"unchanged".to_vec(),
            mode: Mode::DEFAULT_FILE,
        };
        ledger
            .record(entry("~/a", b"x").with_prior(prior.clone()))
            .expect("first");
        let blob = dir.restore().join(ContentHash::of(b"unchanged").to_hex());
        let first = std::fs::metadata(&blob).expect("stat");

        // A second, distinct target displacing identical bytes: the skip is
        // reached through `store_blob` rather than through first-prior-wins.
        ledger
            .record(entry("~/b", b"y").with_prior(prior))
            .expect("second");
        let second = std::fs::metadata(&blob).expect("stat");
        assert_eq!(
            first.ino(),
            second.ino(),
            "a blob of the right name and length already holds these bytes",
        );
    }

    #[test]
    fn a_blob_of_the_wrong_length_is_rewritten_rather_than_trusted() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        // An orphan left by an interrupted write: the right name, the wrong
        // bytes. Trusting the name here loses the user's file, because `record`
        // returns `Ok` and the target is overwritten straight afterwards.
        ensure_dir(&dir.restore(), Mode::PRIVATE_DIR).expect("restore dir");
        let blob = dir
            .restore()
            .join(ContentHash::of(b"the user wrote this").to_hex());
        std::fs::write(&blob, b"").expect("seed an empty orphan");

        let stored = ledger
            .record(
                entry("~/.bashrc", b"bx wrote this").with_prior(PriorBytes::Bytes {
                    bytes: b"the user wrote this".to_vec(),
                    mode: Mode::DEFAULT_FILE,
                }),
            )
            .expect("record");
        let Prior::Existed(reference) = stored.prior.clone() else {
            panic!("expected a snapshot");
        };

        assert_eq!(
            std::fs::read(&blob).expect("read"),
            b"the user wrote this",
            "the blob must be repaired before `record` returns Ok",
        );
        assert_eq!(
            ledger.restore_bytes(&dir, &reference).expect("restore"),
            b"the user wrote this",
        );
    }

    #[test]
    fn a_truncated_blob_is_repaired_by_the_next_record_of_those_bytes() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        let prior = PriorBytes::Bytes {
            bytes: b"the user wrote all of this".to_vec(),
            mode: Mode::DEFAULT_FILE,
        };
        ledger
            .record(entry("~/a", b"x").with_prior(prior.clone()))
            .expect("first");
        let blob = dir
            .restore()
            .join(ContentHash::of(b"the user wrote all of this").to_hex());
        std::fs::write(&blob, b"the user wrote").expect("truncate");

        ledger
            .record(entry("~/b", b"y").with_prior(prior))
            .expect("second");
        assert_eq!(
            std::fs::read(&blob).expect("read"),
            b"the user wrote all of this",
        );
    }

    #[test]
    fn a_tampered_restore_blob_is_refused_rather_than_returned() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"original".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
        let blob = dir.restore().join(ContentHash::of(b"original").to_hex());
        std::fs::write(&blob, b"tampered").expect("tamper");

        let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
            panic!("expected a snapshot")
        };
        let err = ledger
            .restore_bytes(&dir, reference)
            .expect_err("must refuse");
        assert!(matches!(err, Error::RestoreCorrupt { .. }), "got {err}");
    }

    #[test]
    fn a_missing_restore_blob_is_reported_by_digest() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"gone".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
        let digest = ContentHash::of(b"gone");
        std::fs::remove_file(dir.restore().join(digest.to_hex())).expect("remove");

        let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
            panic!("expected a snapshot")
        };
        let err = ledger
            .restore_bytes(&dir, reference)
            .expect_err("must report");
        assert!(matches!(err, Error::RestoreMissing { .. }), "got {err}");
        assert!(err.to_string().contains(&digest.to_hex()));
    }

    #[test]
    fn an_unreadable_restore_blob_is_reported() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"body".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
        let digest = ContentHash::of(b"body");
        let blob = dir.restore().join(digest.to_hex());
        std::fs::remove_file(&blob).expect("remove");
        std::fs::create_dir(&blob).expect("occupy");

        let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
            panic!("expected a snapshot")
        };
        let err = ledger
            .restore_bytes(&dir, reference)
            .expect_err("must report");
        assert!(matches!(err, Error::Read { .. }), "got {err}");
    }

    #[test]
    fn every_mechanism_round_trips() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mechanisms = [
            Mechanism::Own,
            Mechanism::Region { comment: '#' },
            Mechanism::Region { comment: '"' },
            Mechanism::Include {
                line: "source ~/.local/state/bx/shell/init.zsh".to_string(),
            },
        ];
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        for (index, mechanism) in mechanisms.iter().enumerate() {
            let mut new = entry(&format!("~/m{index}"), b"x");
            new.mechanism = mechanism.clone();
            ledger.record(new).expect("record");
        }
        ledger.save().expect("save");

        let reloaded = LedgerView::read(&dir).expect("read").value;
        for (index, mechanism) in mechanisms.iter().enumerate() {
            assert_eq!(
                &reloaded
                    .get(&target(&format!("~/m{index}")))
                    .expect("entry")
                    .mechanism,
                mechanism,
            );
        }
    }

    #[test]
    fn the_ledger_survives_a_save_and_reload() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger.record(entry("~/a", b"x")).expect("record");
        ledger.save().expect("save");

        let reopened = Ledger::open(&dir, &lock).expect("open");
        assert_eq!(reopened.health, Health::Loaded);
        assert_eq!(reopened.value.len(), 1);
        assert_eq!(reopened.value.dir(), &dir);
    }

    #[test]
    fn saving_the_ledger_twice_produces_identical_bytes() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger.record(entry("~/b", b"x")).expect("record");
        ledger.record(entry("~/a", b"y")).expect("record");
        ledger.save().expect("first");
        let first = std::fs::read(dir.ledger()).expect("read");
        ledger.save().expect("second");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), first);
    }

    #[test]
    fn entries_iterate_in_ascending_portable_order() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        for name in ["~/z", "~/a", "~/m"] {
            ledger.record(entry(name, b"x")).expect("record");
        }
        let order: Vec<_> = ledger.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(order, vec!["~/a", "~/m", "~/z"]);
    }

    #[test]
    fn forgetting_a_target_leaves_its_restore_blob_in_place() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"kept".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
        let forgotten = ledger.forget(&target("~/a")).expect("an entry to forget");
        assert_eq!(forgotten.path, target("~/a"));
        assert!(ledger.is_empty());
        assert!(ledger.forget(&target("~/a")).is_none());
        assert!(
            dir.restore()
                .join(ContentHash::of(b"kept").to_hex())
                .exists(),
        );
    }

    #[test]
    fn directories_bx_created_are_recorded_deepest_first() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        let dirs = vec![target("~/.config/tool/sub"), target("~/.config/tool")];
        ledger
            .record(entry("~/.config/tool/sub/f", b"x").with_created_dirs(dirs.clone()))
            .expect("record");
        ledger.save().expect("save");

        let reloaded = LedgerView::read(&dir).expect("read").value;
        assert_eq!(
            reloaded
                .get(&target("~/.config/tool/sub/f"))
                .expect("entry")
                .created_dirs,
            dirs,
        );
    }

    #[test]
    fn an_entry_without_created_dirs_still_loads() {
        // The `serde(default)` guarantee that justifies named encoding: a
        // ledger written before the field existed still loads.
        #[derive(Serialize)]
        struct Old {
            path: Portable,
            written: ContentHash,
            mode: Mode,
            mechanism: Mechanism,
            prior: Prior,
        }
        #[derive(Serialize)]
        struct OldView {
            entries: BTreeMap<Portable, Old>,
        }

        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        let mut entries = BTreeMap::new();
        entries.insert(
            target("~/a"),
            Old {
                path: target("~/a"),
                written: ContentHash::of(b"x"),
                mode: Mode::DEFAULT_FILE,
                mechanism: Mechanism::Own,
                prior: Prior::Absent,
            },
        );
        store::save(&dir.ledger(), KIND, VERSION, &OldView { entries }).expect("save");

        let loaded = LedgerView::read(&dir).expect("read");
        assert_eq!(loaded.health, Health::Loaded);
        assert!(
            loaded
                .value
                .get(&target("~/a"))
                .expect("entry")
                .created_dirs
                .is_empty(),
        );
    }

    #[test]
    fn a_read_only_view_opens_with_no_lock_held() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger.record(entry("~/a", b"x")).expect("record");
        ledger.save().expect("save");

        // The exclusive lock is still held, and the reader is unaffected.
        let view = LedgerView::read(&dir).expect("read");
        assert_eq!(view.health, Health::Loaded);
        assert_eq!(view.value.len(), 1);
    }

    #[test]
    fn a_corrupt_ledger_degrades_to_an_empty_one() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        dir.ensure().expect("ensure");
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");

        let loaded = Ledger::open(&dir, &lock).expect("open");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
        assert!(dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn an_unreadable_ledger_stops_bx_instead_of_resetting_it() {
        if rustix::process::geteuid().is_root() {
            // `0000` denies nothing to root; see the note in `state::store`.
            return;
        }
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(
                entry("~/.bashrc", b"bx wrote this").with_prior(PriorBytes::Bytes {
                    bytes: b"the user wrote this".to_vec(),
                    mode: Mode::DEFAULT_FILE,
                }),
            )
            .expect("record");
        ledger.save().expect("save");
        let intact = std::fs::read(dir.ledger()).expect("read");

        std::fs::set_permissions(dir.ledger(), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");

        // Opening for writing must fail. Degrading here would record bx's own
        // output as every target's prior on the next apply, and `bx rm` would
        // then write bx's generated content over the user's files.
        let err = Ledger::open(&dir, &lock).expect_err("must fail");
        assert!(matches!(err, Error::Read { .. }), "got {err}");
        assert!(LedgerView::read(&dir).is_err(), "the reader must fail too");
        assert!(
            !dir.root().join("ledger.mpk.corrupt").exists(),
            "an unreadable ledger must never be quarantined",
        );

        std::fs::set_permissions(dir.ledger(), std::fs::Permissions::from_mode(0o600))
            .expect("restore");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), intact);
        let reopened = Ledger::open(&dir, &lock).expect("open");
        assert_eq!(reopened.health, Health::Loaded);
        let stored = reopened.value.get(&target("~/.bashrc")).expect("entry");
        let Prior::Existed(reference) = &stored.prior else {
            panic!("the user's prior must have survived");
        };
        assert_eq!(reference.digest, ContentHash::of(b"the user wrote this"));
    }

    #[test]
    fn nothing_outside_the_state_directory_is_created() {
        let home = guarded_home();
        let before = walk(home.path());

        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        let lock = ExclusiveLock::acquire(&dir).expect("acquire");
        let mut ledger = Ledger::open(&dir, &lock).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"prior".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
        ledger.save().expect("save");
        let mut fingerprints = Fingerprints::open(&dir, &lock).expect("open").value;
        fingerprints.set("activation:rustup", Fingerprint::hashed(b"v1"));
        fingerprints.save(&dir).expect("save");

        for path in walk(home.path()) {
            if before.contains(&path) {
                continue;
            }
            assert!(
                path.starts_with(home.child(".local")),
                "{} was created outside the state directory",
                path.display(),
            );
        }
    }

    /// Every path under `root`, recursively.
    fn walk(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            }
            out.push(path);
        }
        out.sort();
        out
    }
}
