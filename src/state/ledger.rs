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

use rustix::fs::{FileType, Mode as RawMode, OFlags};
use serde::{Deserialize, Serialize};

use super::Error;
use super::dir::{StateDir, ensure_dir};
use super::hash::ContentHash;
use super::lock::ExclusiveLock;
use super::store::{self, Loaded, Loss, Rejected};
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
    /// What the user last had there before bx's current bytes — or that there
    /// was nothing. This is what `bx rm` restores. See [`Ledger::record`] for
    /// how a re-record decides it.
    pub prior: Prior,
    /// Directories bx created on the way to the target, deepest first, so
    /// `bx rm` can remove them in order and leave nothing behind.
    ///
    /// Accumulated across re-records, never replaced: a later apply finds the
    /// parents already there and reports none created, and forgetting the ones
    /// an earlier apply invented would leave them behind on `bx rm`.
    #[serde(default)]
    pub created_dirs: Vec<crate::paths::Portable>,
    /// Earlier priors the user has since replaced, in the order they were
    /// replaced.
    ///
    /// When the user writes over a file bx manages and a later apply displaces
    /// those bytes, they become the [`LedgerEntry::prior`], because they are
    /// what the user last had. The snapshot they replace is not dropped: its
    /// reference moves here, so every blob `record` ever stored for a live
    /// target is still reachable from that target's entry, and nothing a user
    /// wrote becomes an unindexed orphan in `restore/`.
    #[serde(default)]
    pub superseded: Vec<RestoreRef>,
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
    /// Defaulting is safe on a re-record: [`Ledger::record`] never lets an
    /// incoming [`PriorBytes::Absent`] replace the prior already stored for a
    /// path, so an omitted prior can never overwrite the user's snapshot with
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
    /// A damaged `ledger.mpk` yields an empty ledger with
    /// [`super::Health::Damaged`] saying so, and is **left where it is**: a
    /// reader holding no lock cannot know that the path still names the bytes
    /// it read, so it renames nothing. [`Ledger::open`], under the lock, is what
    /// quarantines.
    ///
    /// # Every stored path is checked against `home`
    ///
    /// Decoding a [`crate::paths::Portable`] refuses everything that needs no
    /// home to refuse. It cannot refuse `/var/home/me/.gitconfig`, which is
    /// well-formed and on this account a second key for `~/.gitconfig`: one file
    /// with two entries, two priors, and a `bx rm` that restores whichever it
    /// meets last. So every stored path — each key, each entry's `path`, and
    /// each of its `created_dirs` — goes through
    /// [`crate::paths::Portable::check_against`], and a ledger holding one that
    /// fails is **refused**, never believed and never discarded.
    ///
    /// Refused rather than degraded because the likeliest cause is not a
    /// damaged ledger but the same account with its home spelled another way —
    /// a `/home` → `/var/home` alias, or `HOME=/` — and resetting a good ledger
    /// for that would make the next apply record bx's own output as every prior.
    ///
    /// An entry stored under a key that is not its own `path` is different: bx
    /// never writes one, whatever the home, so that is
    /// [`super::Damage::KeyMismatch`].
    ///
    /// # Errors
    ///
    /// [`Error::Read`] if `ledger.mpk` exists and cannot be read. An unreadable
    /// ledger is not a damaged one: the reversibility record may be perfectly
    /// intact behind the failure, so it is neither quarantined nor replaced,
    /// and the caller must stop rather than proceed against an empty ledger.
    ///
    /// [`Error::ForeignPath`] if a stored path cannot be used with `home`. The
    /// ledger is left exactly as it is.
    ///
    /// [`Error::Home`] if `home` is not absolute or not UTF-8. That is checked
    /// before the file is touched, so a bad home never quarantines a ledger.
    ///
    /// [`Error::FutureVersion`] if a newer bx wrote `ledger.mpk`. The ledger is
    /// left exactly as it is; see [`Ledger::open`].
    pub fn read(dir: &StateDir, home: &Path) -> Result<Loaded<Self>, Error> {
        Self::load(dir, home, None)
    }

    /// Read the ledger, quarantining damage only when `lock` is held.
    fn load(
        dir: &StateDir,
        home: &Path,
        lock: Option<&ExclusiveLock>,
    ) -> Result<Loaded<Self>, Error> {
        crate::paths::Portable::parse_in("~", home).map_err(|source| Error::Home {
            home: home.to_path_buf(),
            source,
        })?;
        let path = dir.ledger();
        store::load_checked(
            &path,
            KIND,
            VERSION,
            Loss::Permanent,
            lock,
            |view: &Self| view.check_paths(&path, home),
        )
    }

    /// Reject a ledger bx could not have written, or cannot use with `home`.
    ///
    /// Damage is looked for across every entry before any path is checked
    /// against the home, so a damaged ledger is never reported as a home
    /// problem. `home` has already been accepted, so the only home failure left
    /// is [`crate::paths::Error::AbsoluteUnderHome`].
    fn check_paths(&self, file: &Path, home: &Path) -> Result<(), Rejected> {
        for (key, entry) in &self.entries {
            if *key != entry.path {
                return Err(Rejected::Damage(super::Damage::KeyMismatch {
                    key: key.as_str().to_string(),
                    path: entry.path.as_str().to_string(),
                }));
            }
        }
        for (key, entry) in &self.entries {
            for stored in std::iter::once(key).chain(&entry.created_dirs) {
                stored.check_against(home).map_err(|source| {
                    Rejected::Refused(Error::ForeignPath {
                        path: file.to_path_buf(),
                        home: home.to_path_buf(),
                        stored: stored.as_str().to_string(),
                        source: Box::new(source),
                    })
                })?;
            }
        }
        Ok(())
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
    /// The home it was opened under, so `record` refuses exactly the paths the
    /// next `open` under that home would refuse.
    home: PathBuf,
    /// The entries themselves.
    view: LedgerView,
}

impl Deref for Ledger {
    type Target = LedgerView;

    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

impl LedgerView {
    /// The refusal [`Ledger::record`] would give `entry`, decided without
    /// storing or changing anything.
    ///
    /// For a caller that must not act before it knows the record will be
    /// accepted: a journalled session before it publishes, and a rebuild
    /// before it reports. [`Ledger::record`] applies the same rule.
    ///
    /// # Errors
    ///
    /// [`Error::PriorConflict`] for a changed file bx shares with the user.
    pub fn check_record(&self, entry: &NewEntry) -> Result<(), Error> {
        self.entries.get(&entry.path).map_or(Ok(()), |existing| {
            prior_conflict(existing, &entry.mechanism, &entry.prior)
        })
    }
}

/// [`Error::PriorConflict`] when re-recording `existing` with `incoming` would
/// adopt a changed file bx shares through a region or an include line.
///
/// The one statement of the rule [`Ledger::record`] documents, so the check a
/// caller makes first and the refusal `record` gives cannot disagree.
fn prior_conflict(
    existing: &LedgerEntry,
    mechanism: &Mechanism,
    incoming: &PriorBytes,
) -> Result<(), Error> {
    let PriorBytes::Bytes { bytes, .. } = incoming else {
        return Ok(());
    };
    let digest = ContentHash::of(bytes);
    if digest != existing.written
        && (existing.mechanism != Mechanism::Own || *mechanism != Mechanism::Own)
    {
        return Err(Error::PriorConflict {
            target: existing.path.as_str().to_string(),
            displaced: digest,
        });
    }
    Ok(())
}

impl Ledger {
    /// Open the ledger for writing.
    ///
    /// The lock is not stored; requiring it here is what makes a `Ledger` proof
    /// that one was taken.
    ///
    /// A damaged `ledger.mpk` is moved aside to the first free quarantine name
    /// and this returns an empty ledger, with [`super::Health::Reset`] saying
    /// so. The lock is what makes that rename safe: no writer can have saved
    /// since the bytes were read.
    ///
    /// # Errors
    ///
    /// [`Error::Read`], as [`LedgerView::read`]. This is the path that matters
    /// most: opening for *writing* against an empty ledger that only appeared
    /// empty because it could not be read would record bx's own output as every
    /// target's prior and discard the user's, so the failure is returned rather
    /// than degraded.
    ///
    /// [`Error::ForeignPath`] and [`Error::Home`], as [`LedgerView::read`],
    /// which checks every stored path against `home` the same way. The same
    /// reasoning applies: a ledger written under another spelling of the home
    /// is refused, not reset.
    ///
    /// [`Error::FutureVersion`] if a newer bx wrote `ledger.mpk` — an older bx
    /// run after a newer one. Its format is not damage: quarantining it would
    /// let the next apply record bx's own output as every prior, and every
    /// rollback would add another quarantine. Nothing is renamed.
    ///
    /// [`Error::WrongLock`] if `lock` is not `dir`'s own lock. It is checked
    /// before the ledger is read, so another directory's lock never
    /// quarantines this one.
    pub fn open(dir: &StateDir, lock: &ExclusiveLock, home: &Path) -> Result<Loaded<Self>, Error> {
        let dir = dir.clone();
        Ok(LedgerView::load(&dir, home, Some(lock))?.map(|view| Self {
            dir,
            home: home.to_path_buf(),
            view,
        }))
    }

    /// The state directory this ledger was opened from.
    #[must_use]
    pub fn dir(&self) -> &StateDir {
        &self.dir
    }

    /// The refusal [`Ledger::record`] would give `entry`, decided without
    /// storing or changing anything.
    ///
    /// Everything [`LedgerView::check_record`] checks, and also that every
    /// path `entry` names can be used with the home this ledger was opened
    /// under — the check [`Ledger::open`] makes of every stored path. Method
    /// resolution picks this over the view's for any caller holding a
    /// `Ledger`, so a journalled session and a rebuild refuse what `record`
    /// refuses.
    ///
    /// # Errors
    ///
    /// [`Error::ForeignRecord`] for a path the next open under this home would
    /// refuse, and [`Error::PriorConflict`] for a changed file bx shares with
    /// the user.
    pub fn check_record(&self, entry: &NewEntry) -> Result<(), Error> {
        self.check_new_paths(entry)?;
        self.view.check_record(entry)
    }

    /// Refuse an entry naming a path that [`LedgerView::read`] would refuse
    /// under this ledger's home once it had been saved.
    fn check_new_paths(&self, entry: &NewEntry) -> Result<(), Error> {
        for path in std::iter::once(&entry.path).chain(&entry.created_dirs) {
            path.check_against(&self.home)
                .map_err(|source| Error::ForeignRecord {
                    home: self.home.clone(),
                    stored: path.as_str().to_string(),
                    source: Box::new(source),
                })?;
        }
        Ok(())
    }

    /// Record a target, replacing any entry for the same path — **except its
    /// prior, which is replaced only by bytes a third party wrote.**
    ///
    /// # The prior is what the user last had
    ///
    /// Invariant 4 needs two things of a re-record: no byte the user wrote is
    /// ever lost, and `bx rm` restores what the user last had. When an entry
    /// already exists for `entry.path`, the incoming prior is one of three
    /// things, and the entry's own `written` digest — the whole file as bx last
    /// left it — tells them apart:
    ///
    /// * [`PriorBytes::Absent`] — the stored prior is kept. It is also what
    ///   [`NewEntry::new`] defaults to, so it cannot be trusted to mean "there
    ///   is no file", and it carries no bytes that keeping the stored prior
    ///   could lose. A stored snapshot is therefore never rewritten into
    ///   "unlink it".
    /// * bytes that hash to the stored `written` — bx's own previous output,
    ///   untouched. The stored prior is kept and nothing is written: snapshotting
    ///   these would make `bx rm` restore bx's generated content.
    /// * bytes that do **not** hash to `written` — someone other than bx wrote
    ///   the file since bx last did, and this apply is about to displace those
    ///   bytes. They are stored in `restore/`, durably, and become the prior. A
    ///   stored [`Prior::Existed`] they replace moves to
    ///   [`LedgerEntry::superseded`] rather than being dropped, and a stored
    ///   [`Prior::Absent`] they replace had no bytes to keep.
    ///
    ///   **Only for a file bx owns whole.** When the stored or the incoming
    ///   [`Mechanism`] is a `Region` or an `Include`, those bytes hold bx's own
    ///   previous region or include line as well as the user's edit, and
    ///   adopting them would make `bx rm` write bx's stale lines back into the
    ///   user's file. Stripping them needs the grammar the writer uses — the
    ///   region's delimiter lines, and where an include line is placed — and no
    ///   such writer exists yet, so `record` refuses with
    ///   [`Error::PriorConflict`], stores nothing, and leaves the entry exactly
    ///   as it was. `plan` reports the same target as a conflict from `written`
    ///   alone, so an apply that shares its function never reaches this call.
    ///   The way out that loses no byte is [`Ledger::adopt_current_as_prior`],
    ///   run only because the user chose it.
    ///
    /// The comparison is on content only. A file whose bytes still match
    /// `written` but whose mode the user changed is treated as bx's own output,
    /// because snapshotting it would record bx's generated content as the
    /// user's file.
    ///
    /// [`Ledger::forget`] followed by `record` remains the way to discard a
    /// stored prior deliberately.
    ///
    /// # The inference needs every published write journalled
    ///
    /// *Bytes that do not hash to `written` were written by a third party* is
    /// true only if `written` is recorded for every write bx publishes. This
    /// type alone cannot promise that: a crash after a target is published and
    /// before [`Ledger::save`] leaves the old `written` on disk, and a retry
    /// would read bx's own new output as a third party's and adopt it as the
    /// prior. The write-ahead journal (entry A6, `journal`/`recover`) closes the
    /// window — it stores the prior and an intent before publishing, and
    /// recovery rolls the ledger forward or the target back before another
    /// apply can open the ledger — so this rule is sound only for writes that go
    /// through it.
    ///
    /// # Created directories accumulate
    ///
    /// `entry.created_dirs` is merged into the stored list rather than replacing
    /// it — deduplicated, and re-sorted deepest first so `bx rm` can still
    /// remove them in order. A second apply creates no parents, because the
    /// first one did; replacing the list would forget them.
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
    /// stored, and [`Error::PriorConflict`] for a changed file bx shares with
    /// the user. The ledger is left unchanged when either happens.
    ///
    /// [`Error::ForeignRecord`] if `entry.path` or one of its `created_dirs`
    /// cannot be used with the home the ledger was opened under. That is
    /// checked before anything is stored: once saved, such a path would make
    /// every later open under the same home refuse the ledger, with no way back.
    pub fn record(&mut self, entry: NewEntry) -> Result<&LedgerEntry, Error> {
        self.check_new_paths(&entry)?;
        let key = entry.path.clone();
        let (prior, superseded, created_dirs) = match self.view.entries.get(&key) {
            None => (
                self.store_prior(entry.prior)?,
                Vec::new(),
                entry.created_dirs,
            ),
            Some(existing) => {
                let (prior, superseded) =
                    self.carry_prior(existing, &entry.mechanism, entry.prior)?;
                (
                    prior,
                    superseded,
                    merge_created_dirs(&existing.created_dirs, entry.created_dirs),
                )
            }
        };
        self.view.entries.insert(
            key.clone(),
            LedgerEntry {
                path: entry.path,
                written: entry.written,
                mode: entry.mode,
                mechanism: entry.mechanism,
                prior,
                created_dirs,
                superseded,
            },
        );
        Ok(&self.view.entries[&key])
    }

    /// Decide the prior and the superseded list for a re-record of `existing`.
    ///
    /// The rule is documented on [`Ledger::record`]. Any bytes that are to be
    /// adopted are durable in `restore/` before this returns.
    fn carry_prior(
        &self,
        existing: &LedgerEntry,
        mechanism: &Mechanism,
        incoming: PriorBytes,
    ) -> Result<(Prior, Vec<RestoreRef>), Error> {
        // A shared file's changed bytes still hold bx's own region or include
        // line. Refused before anything is stored: see `record`.
        prior_conflict(existing, mechanism, &incoming)?;
        let kept = || (existing.prior.clone(), existing.superseded.clone());
        let PriorBytes::Bytes { bytes, mode } = incoming else {
            return Ok(kept());
        };
        let digest = ContentHash::of(&bytes);
        if digest == existing.written {
            return Ok(kept());
        }

        // A third party wrote these bytes and this apply displaces them: they
        // reach `restore/` before anything else is decided.
        let adopted = self.store_restore(digest, &bytes, mode)?;
        let superseded = supersede(existing, &adopted);
        tracing::info!(
            path = %existing.path,
            digest = %adopted.digest,
            "the file changed since bx last wrote it; keeping the displaced bytes as its prior",
        );
        Ok((Prior::Existed(adopted), superseded))
    }

    /// Drop a target from the ledger, returning the entry that was there.
    ///
    /// This is also how a caller deliberately discards a stored prior: `forget`
    /// then [`Ledger::record`] records the incoming prior as though bx had
    /// never written the target.
    ///
    /// The restore blob is deliberately left in place: it may be shared with
    /// another entry, and content-addressed bytes cost far less than a wrong
    /// deletion. Reclaiming unreferenced blobs is not implemented.
    pub fn forget(&mut self, path: &crate::paths::Portable) -> Option<LedgerEntry> {
        self.view.entries.remove(path)
    }

    /// Accept a target as it is now as the version `bx rm` restores — the way
    /// out of [`Error::PriorConflict`] that loses no byte.
    ///
    /// `bytes` and `mode` are the target as it is on disk now. When the bytes
    /// hash to the entry's `written`, nothing has changed and nothing is done.
    /// Otherwise they are stored in `restore/`, durably, and become the prior;
    /// the prior they replace moves to [`LedgerEntry::superseded`], exactly as
    /// a re-record of an `Own` target moves it, so no snapshot is dropped.
    /// `written` becomes their digest: the next `plan` sees the file as bx
    /// last accepted it, and the next apply's re-record keeps this prior
    /// instead of conflicting again.
    ///
    /// For a `Region` or `Include` target this is on purpose what `record`
    /// refuses to do by itself. The accepted bytes hold bx's own lines, and
    /// `bx rm` will write them back, so it must run only because the user chose
    /// it. Restoring the user's edit without bx's lines needs the region
    /// writer's delimiter grammar, which does not exist yet.
    ///
    /// Returns `Ok(None)`, changing nothing, when bx records no entry for
    /// `path`.
    ///
    /// # Errors
    ///
    /// [`Error::CreateDir`] or [`Error::Write`] if the bytes cannot be stored.
    /// The entry is left unchanged.
    pub fn adopt_current_as_prior(
        &mut self,
        path: &crate::paths::Portable,
        bytes: &[u8],
        mode: Mode,
    ) -> Result<Option<&LedgerEntry>, Error> {
        let Some(existing) = self.view.entries.get(path) else {
            return Ok(None);
        };
        let digest = ContentHash::of(bytes);
        if digest == existing.written {
            return Ok(self.view.entries.get(path));
        }
        let adopted = self.store_restore(digest, bytes, mode)?;
        let superseded = supersede(existing, &adopted);
        if let Some(entry) = self.view.entries.get_mut(path) {
            tracing::info!(
                path = %entry.path,
                digest = %adopted.digest,
                "accepting the file as it is now as the version bx rm restores",
            );
            entry.prior = Prior::Existed(adopted);
            entry.superseded = superseded;
            entry.written = digest;
        }
        Ok(self.view.entries.get(path))
    }

    /// Turn caller-supplied prior bytes into a durable [`Prior`].
    fn store_prior(&self, prior: PriorBytes) -> Result<Prior, Error> {
        match prior {
            PriorBytes::Absent => Ok(Prior::Absent),
            PriorBytes::Bytes { bytes, mode } => Ok(Prior::Existed(self.store_restore(
                ContentHash::of(&bytes),
                &bytes,
                mode,
            )?)),
        }
    }

    /// Store `bytes`, already hashed to `digest`, and return the reference.
    fn store_restore(
        &self,
        digest: ContentHash,
        bytes: &[u8],
        mode: Mode,
    ) -> Result<RestoreRef, Error> {
        self.store_blob(digest, bytes)?;
        Ok(RestoreRef {
            digest,
            mode,
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        })
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
    ///
    /// The `stat` is of the name itself, never of what it links to: see
    /// [`blob_len`]. A symlink or a second hard link of the right length is not
    /// a blob bx wrote, so it is never trusted. A second hard link is rewritten.
    /// A symlink is refused: [`write_atomically`] never replaces a link, so
    /// this returns [`Error::Write`] carrying [`crate::fs::Error::Symlink`] and
    /// leaves the link and what it names alone.
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

/// `existing`'s superseded list once `adopted` becomes its prior.
///
/// The prior it replaces is appended unless it is already there, so every blob
/// stored for a live target stays indexed; and a snapshot the user has put back
/// is the prior again, not history.
fn supersede(existing: &LedgerEntry, adopted: &RestoreRef) -> Vec<RestoreRef> {
    let mut superseded = existing.superseded.clone();
    if let Prior::Existed(previous) = &existing.prior
        && !superseded.contains(previous)
    {
        superseded.push(previous.clone());
    }
    superseded.retain(|reference| reference != adopted);
    superseded
}

/// The directories an earlier record created, plus any a later one did.
///
/// Every entry is an ancestor of the same target, so depth alone orders them:
/// the result is deduplicated and sorted deepest first, with ties — which two
/// distinct ancestors of one path cannot produce — kept in first-seen order.
fn merge_created_dirs(
    existing: &[crate::paths::Portable],
    incoming: Vec<crate::paths::Portable>,
) -> Vec<crate::paths::Portable> {
    let mut merged = existing.to_vec();
    for dir in incoming {
        if !merged.contains(&dir) {
            merged.push(dir);
        }
    }
    merged.sort_by_key(|dir| std::cmp::Reverse(dir.as_str().split('/').count()));
    merged
}

/// The length of the blob at `path`, or `None` unless it is bx's own file.
///
/// `None` means *rewrite it*: a blob that cannot be stat'ed is not a blob whose
/// content has been established.
///
/// The name is opened `O_PATH | O_NOFOLLOW` and the descriptor is checked, so
/// what is measured is the entry in `restore/` and never what a symlink there
/// names: a decoy link to a same-length file elsewhere used to satisfy the
/// check with none of the user's bytes behind it. It must be a regular file
/// with exactly one link. `O_PATH` reads nothing and cannot block on a FIFO.
/// The rewrite goes through [`write_atomically`]: its rename replaces a second
/// hard link, and it refuses a symlink outright, so a link is never written
/// through.
///
/// Crate-visible because the journal's own snapshot store asks the same
/// question before an Intent names a blob, and one rule means a decoy the
/// ledger refuses to trust is not trusted there either.
pub(crate) fn blob_len(path: &Path) -> Option<u64> {
    let fd = rustix::fs::open(
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        RawMode::empty(),
    )
    .ok()?;
    let stat = rustix::fs::fstat(&fd).ok()?;
    let own = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_nlink == 1;
    own.then(|| u64::try_from(stat.st_size).ok()).flatten()
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
        Portable::try_from(name.to_string()).expect("a portable path")
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
    fn a_re_record_over_bxs_own_output_neither_stores_nor_adopts_it() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
                bytes: b"the user wrote this".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("first");
        // What is on disk is exactly what the first record said bx wrote.
        ledger
            .record(entry("~/.bashrc", b"second").with_prior(PriorBytes::Bytes {
                bytes: b"first".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("second");

        let stored = ledger.get(&target("~/.bashrc")).expect("entry");
        let Prior::Existed(reference) = &stored.prior else {
            panic!("expected the first prior");
        };
        assert_eq!(reference.digest, ContentHash::of(b"the user wrote this"));
        assert!(stored.superseded.is_empty());
        // bx's own output is never written, so re-recording leaves no orphan.
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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

    /// Bytes as a prior, at `mode`.
    fn prior(body: &[u8], mode: u32) -> PriorBytes {
        PriorBytes::Bytes {
            bytes: body.to_vec(),
            mode: Mode::from_bits(mode),
        }
    }

    /// Whether `restore/` holds a blob for `body`.
    fn has_blob(dir: &StateDir, body: &[u8]) -> bool {
        dir.restore().join(ContentHash::of(body).to_hex()).is_file()
    }

    /// Every blob name in `restore/`, sorted.
    fn blob_names(dir: &StateDir) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(dir.restore()) else {
            return Vec::new();
        };
        let mut names: Vec<_> = entries
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// What `bx rm` does with an entry, reduced to the prior: unlink for
    /// `Absent`, write the snapshot back for `Existed`.
    fn simulate_rm(dir: &StateDir, home: &GuardedHome, name: &str) {
        let view = LedgerView::read(dir, home.path()).expect("read").value;
        let stored = view.get(&target(name)).expect("entry");
        let dest = stored.path.render(home.path());
        match &stored.prior {
            Prior::Absent => std::fs::remove_file(&dest).expect("unlink"),
            Prior::Existed(reference) => {
                let bytes = view.restore_bytes(dir, reference).expect("restore bytes");
                write_atomically(&dest, &bytes, reference.mode).expect("restore");
            }
        }
    }

    /// One apply of `body` to `rel`, as the writer does it: observe what is
    /// there, record it as the prior, then replace the file.
    fn apply(dir: &StateDir, lock: &ExclusiveLock, home: &GuardedHome, rel: &str, body: &[u8]) {
        let dest = home.child(rel);
        let observed = match std::fs::read(&dest) {
            Ok(bytes) => PriorBytes::Bytes {
                bytes,
                mode: mode_of(&dest),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PriorBytes::Absent,
            Err(e) => panic!("observing {}: {e}", dest.display()),
        };
        let mut ledger = Ledger::open(dir, lock, home.path()).expect("open").value;
        ledger
            .record(entry(&format!("~/{rel}"), body).with_prior(observed))
            .expect("record");
        std::fs::create_dir_all(dest.parent().expect("a parent")).expect("parents");
        write_atomically(&dest, body, Mode::DEFAULT_FILE).expect("write the target");
        ledger.save().expect("save");
    }

    #[test]
    fn a_file_the_user_creates_between_two_applies_is_restored_by_rm_not_unlinked() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let rel = ".config/tool.toml";
        let users: &[u8] = b"[user]\nname = \"mine\"\ntheme = \"dark\"\n";
        assert_eq!(users.len(), 36);

        // Apply #1: nothing is there, so bx creates the file and the prior is
        // "there was no file".
        apply(&dir, &lock, &home, rel, b"# bx v1\n");
        // Between applies the user replaces bx's file with 36 bytes of their own.
        std::fs::write(home.child(rel), users).expect("the user writes");
        // Apply #2 displaces those bytes.
        apply(&dir, &lock, &home, rel, b"# bx v2\n");

        assert!(
            has_blob(&dir, users),
            "the displaced bytes must be in restore/, found {:?}",
            blob_names(&dir),
        );
        simulate_rm(&dir, &home, "~/.config/tool.toml");
        assert_eq!(
            std::fs::read(home.child(rel)).expect("rm must leave the user's file"),
            users,
        );
    }

    #[test]
    fn a_user_edit_between_two_applies_is_what_rm_restores() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let rel = ".ssh/config";
        home.write(rel, "Host theirs\n");
        std::fs::set_permissions(home.child(rel), std::fs::Permissions::from_mode(0o640))
            .expect("chmod");

        apply(&dir, &lock, &home, rel, b"Host v1\n");
        std::fs::write(home.child(rel), b"Host edited\n").expect("the user edits");
        apply(&dir, &lock, &home, rel, b"Host v2\n");

        simulate_rm(&dir, &home, "~/.ssh/config");
        assert_eq!(
            std::fs::read(home.child(rel)).expect("read"),
            b"Host edited\n",
            "rm restores what the user last had, not what bx displaced first",
        );
        assert!(has_blob(&dir, b"Host theirs\n"), "the original is kept too");
        let view = LedgerView::read(&dir, home.path()).expect("read").value;
        let stored = view.get(&target("~/.ssh/config")).expect("entry");
        assert_eq!(stored.superseded.len(), 1, "the original stays indexed");
        assert_eq!(
            view.restore_bytes(&dir, &stored.superseded[0])
                .expect("restore"),
            b"Host theirs\n",
        );
        assert_eq!(stored.superseded[0].mode, Mode::from_bits(0o640));
    }

    #[test]
    fn repeated_user_edits_are_superseded_in_order_and_an_untouched_apply_adds_nothing() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let rel = ".gitconfig";
        home.write(rel, "original\n");

        apply(&dir, &lock, &home, rel, b"bx 1\n");
        std::fs::write(home.child(rel), b"edit 1\n").expect("edit");
        apply(&dir, &lock, &home, rel, b"bx 2\n");
        let after_edit = std::fs::read(dir.ledger()).expect("read");
        // Nobody touches the file and bx writes the same bytes again: the
        // ledger must come out byte-identical, with no new prior and no history.
        apply(&dir, &lock, &home, rel, b"bx 2\n");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), after_edit);
        std::fs::write(home.child(rel), b"edit 2\n").expect("edit");
        apply(&dir, &lock, &home, rel, b"bx 3\n");

        let view = LedgerView::read(&dir, home.path()).expect("read").value;
        let stored = view.get(&target("~/.gitconfig")).expect("entry");
        assert_eq!(
            stored.prior,
            Prior::Existed(reference(b"edit 2\n", 0o644)),
            "the prior is the last thing the user had",
        );
        let history: Vec<Vec<u8>> = stored
            .superseded
            .iter()
            .map(|r| view.restore_bytes(&dir, r).expect("restore"))
            .collect();
        assert_eq!(history, vec![b"original\n".to_vec(), b"edit 1\n".to_vec()]);

        // The user puts the first edit back; it is the prior again, not history.
        std::fs::write(home.child(rel), b"edit 1\n").expect("edit");
        apply(&dir, &lock, &home, rel, b"bx 4\n");
        let view = LedgerView::read(&dir, home.path()).expect("read").value;
        let stored = view.get(&target("~/.gitconfig")).expect("entry");
        assert_eq!(stored.prior, Prior::Existed(reference(b"edit 1\n", 0o644)));
        assert_eq!(
            stored.superseded,
            vec![
                reference(b"original\n", 0o644),
                reference(b"edit 2\n", 0o644),
            ],
        );
    }

    /// What a cell's stored prior is.
    #[derive(Debug, Clone, Copy)]
    enum Stored {
        Absent,
        Existed,
    }

    /// What a cell's second record is handed.
    #[derive(Debug, Clone, Copy)]
    enum Incoming {
        /// No file on disk, or a caller that supplied no prior.
        Absent,
        /// The bytes bx left there, untouched.
        BxsOwnOutput,
        /// Bytes nobody but the user could have written.
        UserChanged,
        /// The user put their original bytes back.
        OriginalPutBack,
    }

    const ORIGINAL: &[u8] = b"the user's original\n";
    const BX_V1: &[u8] = b"bx v1\n";
    const BX_V2: &[u8] = b"bx v2\n";
    const EDIT: &[u8] = b"the user's later edit\n";

    /// Record `stored`, then re-record with `incoming`, and return the entry and
    /// the blobs on disk.
    fn run_cell(stored: Stored, incoming: Incoming) -> (LedgerEntry, Vec<String>) {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        let first = match stored {
            Stored::Absent => entry("~/t", BX_V1),
            Stored::Existed => entry("~/t", BX_V1).with_prior(prior(ORIGINAL, 0o640)),
        };
        ledger.record(first).expect("first");
        let second = entry("~/t", BX_V2);
        let second = match incoming {
            Incoming::Absent => second,
            Incoming::BxsOwnOutput => second.with_prior(prior(BX_V1, 0o644)),
            Incoming::UserChanged => second.with_prior(prior(EDIT, 0o600)),
            Incoming::OriginalPutBack => second.with_prior(prior(ORIGINAL, 0o640)),
        };
        let stored = ledger.record(second).expect("second").clone();
        ledger.save().expect("save");
        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
        assert_eq!(reloaded.get(&target("~/t")), Some(&stored), "round trip");
        (stored, blob_names(&dir))
    }

    fn hex(body: &[u8]) -> String {
        ContentHash::of(body).to_hex()
    }

    fn reference(body: &[u8], mode: u32) -> RestoreRef {
        RestoreRef {
            digest: ContentHash::of(body),
            mode: Mode::from_bits(mode),
            len: u64::try_from(body.len()).expect("len"),
        }
    }

    fn sorted(mut names: Vec<String>) -> Vec<String> {
        names.sort();
        names
    }

    #[test]
    fn a_re_record_keeps_or_adopts_the_prior_in_every_cell_of_the_matrix() {
        let cells = [
            (
                Stored::Absent,
                Incoming::Absent,
                Prior::Absent,
                vec![],
                vec![],
            ),
            (
                Stored::Absent,
                Incoming::BxsOwnOutput,
                Prior::Absent,
                vec![],
                vec![],
            ),
            (
                Stored::Absent,
                Incoming::UserChanged,
                Prior::Existed(reference(EDIT, 0o600)),
                vec![],
                vec![hex(EDIT)],
            ),
            (
                Stored::Existed,
                Incoming::Absent,
                Prior::Existed(reference(ORIGINAL, 0o640)),
                vec![],
                vec![hex(ORIGINAL)],
            ),
            (
                Stored::Existed,
                Incoming::BxsOwnOutput,
                Prior::Existed(reference(ORIGINAL, 0o640)),
                vec![],
                vec![hex(ORIGINAL)],
            ),
            (
                Stored::Existed,
                Incoming::UserChanged,
                Prior::Existed(reference(EDIT, 0o600)),
                vec![reference(ORIGINAL, 0o640)],
                sorted(vec![hex(ORIGINAL), hex(EDIT)]),
            ),
            (
                Stored::Existed,
                Incoming::OriginalPutBack,
                Prior::Existed(reference(ORIGINAL, 0o640)),
                vec![],
                vec![hex(ORIGINAL)],
            ),
        ];
        for (stored, incoming, want_prior, want_superseded, want_blobs) in cells {
            let (entry, blobs) = run_cell(stored, incoming);
            let cell = format!("{stored:?} x {incoming:?}");
            assert_eq!(entry.prior, want_prior, "{cell}: prior");
            assert_eq!(entry.superseded, want_superseded, "{cell}: superseded");
            assert_eq!(blobs, want_blobs, "{cell}: restore/");
            // Every blob on disk is reachable from the entry: nothing orphaned.
            let mut reachable: Vec<String> = entry
                .superseded
                .iter()
                .chain(match &entry.prior {
                    Prior::Existed(reference) => Some(reference),
                    Prior::Absent => None,
                })
                .map(RestoreRef::blob_name)
                .collect();
            reachable.sort();
            reachable.dedup();
            assert_eq!(reachable, blobs, "{cell}: every blob is indexed");
            assert_eq!(entry.written, ContentHash::of(BX_V2), "{cell}: written");
        }
    }

    #[test]
    fn a_file_bx_created_records_explicit_non_existence() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        let stored = ledger.record(entry("~/.config/new", b"x")).expect("record");
        assert_eq!(stored.prior, Prior::Absent);
    }

    #[test]
    fn an_empty_prior_file_is_distinguishable_from_no_prior_file() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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

        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        // `~/.ssh/config` at 0600 is the case this exists for: restoring it at
        // 0644 would be a security regression dressed up as a restore.
        ledger
            .record(entry("~/.ssh/config", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"Host *\n".to_vec(),
                mode: Mode::PRIVATE_FILE,
            }))
            .expect("record");
        ledger.save().expect("save");

        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
    fn a_decoy_link_at_a_blob_name_is_refused_and_a_decoy_hard_link_replaced_never_trusted() {
        // Review round 3: `blob_len` followed a symlink, so a link at
        // `restore/<digest>` to any file of the same length made `record`
        // return Ok with none of the user's bytes on disk — found only at rm,
        // as RestoreCorrupt. A second hard link was trusted the same way.
        //
        // Stack integration with #8: the writer refuses to replace a symlink
        // anywhere (`fs::Error::Symlink`), state files included. So a symlink
        // decoy is refused, not replaced: `record` fails, stores nothing, and
        // neither the link nor what it names is touched. A hard link is a
        // regular file to the writer, and is still replaced.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        home.write("decoy", "ZZZZZ");
        home.write("other", "YYYYY");
        let link = dir.restore().join(hex(b"prior"));
        std::os::unix::fs::symlink(home.child("decoy"), &link).expect("symlink");
        std::fs::hard_link(home.child("other"), dir.restore().join(hex(b"third")))
            .expect("hard link");

        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;

        let err = ledger
            .record(entry("~/.a", b"bx").with_prior(prior(b"prior", 0o644)))
            .expect_err("a symlink at the blob name is never trusted");
        assert!(
            matches!(&err, Error::Write(crate::fs::Error::Symlink(path)) if *path == link),
            "{err:?}",
        );
        assert!(
            ledger.get(&target("~/.a")).is_none(),
            "nothing was recorded"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the link is left where it is",
        );
        assert_eq!(
            std::fs::read_link(&link).expect("readlink"),
            home.child("decoy")
        );

        let stored = ledger
            .record(entry("~/.b", b"bx").with_prior(prior(b"third", 0o644)))
            .expect("record")
            .clone();
        let Prior::Existed(reference) = &stored.prior else {
            panic!("expected a snapshot");
        };
        assert_eq!(
            ledger.restore_bytes(&dir, reference).expect("restore"),
            b"third"
        );
        let blob = dir.restore().join(hex(b"third"));
        let meta = std::fs::symlink_metadata(&blob).expect("stat");
        assert!(meta.file_type().is_file(), "the hard link was replaced");
        assert_eq!(meta.nlink(), 1);

        // Neither decoy was written through.
        assert_eq!(std::fs::read(home.child("decoy")).expect("read"), b"ZZZZZ");
        assert_eq!(std::fs::read(home.child("other")).expect("read"), b"YYYYY");
    }

    #[test]
    fn a_tampered_restore_blob_is_refused_rather_than_returned() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        for (index, mechanism) in mechanisms.iter().enumerate() {
            let mut new = entry(&format!("~/m{index}"), b"x");
            new.mechanism = mechanism.clone();
            ledger.record(new).expect("record");
        }
        ledger.save().expect("save");

        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
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
    fn written_is_the_whole_file_for_a_shared_file_not_bxs_contribution() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;

        // Under `Own` these two are the same bytes by construction, so the
        // property is only visible for a mechanism where bx writes part of a
        // file the user also writes.
        let users_line = "export EDITOR=hx\n";
        let region = "# >>> bx >>>\nexport PATH=\"$HOME/.local/bin:$PATH\"\n# <<< bx <<<\n";
        let whole = format!("{users_line}{region}");
        let include = "source ~/.local/state/bx/shell/init.zsh\n";
        let whole_with_include = format!("{users_line}{include}");

        for (name, mechanism, contents, contribution) in [
            (
                "~/.bashrc",
                Mechanism::Region { comment: '#' },
                whole.as_str(),
                region,
            ),
            (
                "~/.zshrc",
                Mechanism::Include {
                    line: include.trim_end().to_string(),
                },
                whole_with_include.as_str(),
                include,
            ),
        ] {
            let mut new = NewEntry::new(
                target(name),
                ContentHash::of(contents.as_bytes()),
                Mode::DEFAULT_FILE,
                mechanism,
            );
            new = new.with_prior(PriorBytes::Bytes {
                bytes: users_line.as_bytes().to_vec(),
                mode: Mode::DEFAULT_FILE,
            });
            let stored = ledger.record(new).expect("record");
            assert_eq!(stored.written, ContentHash::of(contents.as_bytes()));
            assert_ne!(
                stored.written,
                ContentHash::of(contribution.as_bytes()),
                "`written` must cover the user's bytes too, or `plan` cannot \
                 tell a file the user edited from one only bx wrote",
            );
        }
        ledger.save().expect("save");

        // The distinction has to survive the round trip, because `plan` reads
        // it back rather than recomputing it.
        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
        let bashrc = reloaded.get(&target("~/.bashrc")).expect("entry");
        assert_eq!(bashrc.written, ContentHash::of(whole.as_bytes()));
        assert_eq!(bashrc.mechanism, Mechanism::Region { comment: '#' });
        assert_eq!(
            reloaded.get(&target("~/.zshrc")).expect("entry").written,
            ContentHash::of(whole_with_include.as_bytes()),
        );
    }

    #[test]
    fn record_refuses_a_path_the_next_open_under_the_same_home_would_refuse() {
        // Review round 4's falsifier: `record` accepted `/<home>/.gitconfig`
        // built through `Portable::try_from`, `save` wrote it, and every later
        // `open` under that home refused the ledger, with no way back.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"bx").with_prior(prior(b"mine", 0o644)))
            .expect("an ordinary record");
        ledger.save().expect("save");
        let saved = std::fs::read(dir.ledger()).expect("read");
        let blobs = blob_names(&dir);

        let foreign_key = absolute_under(&home, ".gitconfig");
        let foreign_dir = absolute_under(&home, ".config/tool");
        let cases = [
            (
                NewEntry::new(
                    foreign_key.clone(),
                    ContentHash::of(b"bx"),
                    Mode::DEFAULT_FILE,
                    Mechanism::Own,
                )
                .with_prior(prior(b"the user's gitconfig", 0o644)),
                foreign_key,
            ),
            (
                entry("~/.config/tool/x.conf", b"bx")
                    .with_prior(prior(b"the user's tool config", 0o644))
                    .with_created_dirs(vec![foreign_dir.clone()]),
                foreign_dir,
            ),
        ];
        for (new, refused) in cases {
            let checked = ledger.check_record(&new).expect_err("check refuses");
            let recorded = ledger.record(new).expect_err("record refuses");
            for err in [checked, recorded] {
                assert!(
                    matches!(
                        &err,
                        Error::ForeignRecord { home: at, stored, .. }
                            if at == home.path() && *stored == refused.as_str()
                    ),
                    "got {err}",
                );
                assert!(err.to_string().contains("Nothing was recorded"), "{err}");
            }
        }

        // Nothing entered the ledger, nothing reached `restore/`, and the
        // ledger still opens under the home it was opened with.
        assert_eq!(ledger.len(), 1);
        assert_eq!(blob_names(&dir), blobs);
        ledger.save().expect("save");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), saved);
        let reopened = Ledger::open(&dir, &lock, home.path()).expect("still opens");
        assert_eq!(reopened.health, Health::Loaded);
    }

    #[test]
    fn check_record_refuses_exactly_what_record_refuses_and_stores_nothing() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let region = Mechanism::Region { comment: '#' };
        let bx1: &[u8] = b"user\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
        let at = |written: &[u8], before: &[u8]| {
            NewEntry::new(
                target("~/.bashrc"),
                ContentHash::of(written),
                Mode::DEFAULT_FILE,
                region.clone(),
            )
            .with_prior(prior(before, 0o644))
        };
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .check_record(&at(bx1, b"user\n"))
            .expect("a new target");
        ledger.record(at(bx1, b"user\n")).expect("record");
        let blobs = blob_names(&dir);

        let edited = at(b"BX2", b"user\n# >>> bx >>>\nBX1\n# <<< bx <<<\nedit\n");
        let err = (*ledger)
            .check_record(&edited)
            .expect_err("the view refuses");
        assert!(matches!(err, Error::PriorConflict { .. }), "got {err}");
        let err = ledger
            .check_record(&edited)
            .expect_err("the ledger refuses");
        assert!(matches!(err, Error::PriorConflict { .. }), "got {err}");
        let err = ledger.record(edited).expect_err("record refuses");
        assert!(matches!(err, Error::PriorConflict { .. }), "got {err}");
        assert_eq!(blob_names(&dir), blobs, "nothing was stored");

        ledger
            .check_record(&at(b"BX2", bx1))
            .expect("bx's own output");
        ledger.record(at(b"BX2", bx1)).expect("record");
    }

    #[test]
    fn accepting_a_changed_shared_file_converges_and_keeps_the_first_original() {
        // Review round 4: `PriorConflict` fires on any edit outside bx's
        // region, its message named no remedy, and re-recording converged
        // nowhere.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let region = Mechanism::Region { comment: '#' };
        let original: &[u8] = b"user line 1\n";
        let bx1: &[u8] = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
        let edited: &[u8] = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\nuser line 2\n";
        let bx2: &[u8] = b"user line 1\n# >>> bx >>>\nBX2\n# <<< bx <<<\nuser line 2\n";
        let apply = |written: &[u8], before: &[u8]| {
            NewEntry::new(
                target("~/.bashrc"),
                ContentHash::of(written),
                Mode::DEFAULT_FILE,
                region.clone(),
            )
            .with_prior(prior(before, 0o644))
        };
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger.record(apply(bx1, original)).expect("first apply");

        // The edit: a conflict, every time, whose message names both ways out.
        for _ in 0..2 {
            let message = ledger
                .record(apply(bx2, edited))
                .expect_err("a conflict")
                .to_string();
            assert!(message.contains("put the file back"), "{message}");
            assert!(
                message.contains("accept the file as it is now"),
                "{message}"
            );
        }

        // The user accepts the file as it is now.
        let accepted = ledger
            .adopt_current_as_prior(&target("~/.bashrc"), edited, Mode::from_bits(0o640))
            .expect("adopt")
            .expect("an entry")
            .clone();
        assert_eq!(accepted.written, ContentHash::of(edited));
        assert_eq!(accepted.prior, Prior::Existed(reference(edited, 0o640)));
        assert_eq!(
            accepted.superseded,
            vec![reference(original, 0o644)],
            "the first original is kept, not dropped",
        );
        assert_eq!(accepted.mechanism, region);
        assert!(has_blob(&dir, edited) && has_blob(&dir, original));

        // Accepting the same file again changes nothing.
        ledger
            .adopt_current_as_prior(&target("~/.bashrc"), edited, Mode::from_bits(0o640))
            .expect("adopt again");
        assert_eq!(ledger.get(&target("~/.bashrc")), Some(&accepted));

        // The next apply converges: no conflict, and the accepted prior stands.
        let stored = ledger
            .record(apply(bx2, edited))
            .expect("the next apply records")
            .clone();
        assert_eq!(stored.written, ContentHash::of(bx2));
        assert_eq!(stored.prior, accepted.prior);
        assert_eq!(stored.superseded, accepted.superseded);
        ledger.save().expect("save");
        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
        assert_eq!(reloaded.get(&target("~/.bashrc")), Some(&stored));

        // A target bx does not record is not invented.
        assert!(
            ledger
                .adopt_current_as_prior(&target("~/.zshrc"), edited, Mode::DEFAULT_FILE)
                .expect("adopt")
                .is_none()
        );
        assert!(ledger.get(&target("~/.zshrc")).is_none());
    }

    #[test]
    fn a_changed_shared_file_is_a_conflict_not_a_prior_holding_bxs_own_lines() {
        // Review round 3. Region BX1, the user adds a line outside it, and the
        // next apply hands `record` the whole file. Adopting it stored BX1's
        // region as the user's original, and `bx rm` then wrote bx's stale
        // region back into the user's file.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let original = b"user line 1\n";
        let bx1 = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
        let mut edited = bx1.to_vec();
        edited.extend_from_slice(b"user line 2\n");
        let region = Mechanism::Region { comment: '#' };
        let include = Mechanism::Include {
            line: "source ~/.local/state/bx/shell/init.sh".to_string(),
        };
        // Either side of the re-record being shared is enough: the bytes on disk
        // hold what the stored mechanism wrote, and the prior is read back
        // under the incoming one.
        let cases = [
            (region.clone(), region.clone()),
            (include.clone(), include),
            (Mechanism::Own, region.clone()),
            (region, Mechanism::Own),
        ];
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        for (index, (first, second)) in cases.into_iter().enumerate() {
            let name = format!("~/.rc{index}");
            ledger
                .record(
                    NewEntry::new(
                        target(&name),
                        ContentHash::of(bx1),
                        Mode::DEFAULT_FILE,
                        first,
                    )
                    .with_prior(prior(original, 0o644)),
                )
                .expect("first apply");
            ledger.save().expect("save");
            let saved = std::fs::read(dir.ledger()).expect("read");
            let blobs = blob_names(&dir);

            let err = ledger
                .record(
                    NewEntry::new(
                        target(&name),
                        ContentHash::of(b"BX2"),
                        Mode::DEFAULT_FILE,
                        second,
                    )
                    .with_prior(prior(&edited, 0o644)),
                )
                .expect_err("a changed shared file is a conflict");
            assert!(
                matches!(
                    &err,
                    Error::PriorConflict { target: at, displaced }
                        if *at == name && *displaced == ContentHash::of(&edited)
                ),
                "case {index}: got {err}",
            );
            assert!(err.to_string().contains(&name), "{err}");

            // Nothing was adopted or stored, and the prior holds no bx region.
            let stored = ledger.get(&target(&name)).expect("entry");
            assert_eq!(stored.written, ContentHash::of(bx1));
            assert!(stored.superseded.is_empty());
            let Prior::Existed(reference) = &stored.prior else {
                panic!("case {index}: the original prior must stand");
            };
            assert_eq!(
                ledger.restore_bytes(&dir, reference).expect("restore"),
                original,
            );
            assert!(!has_blob(&dir, &edited), "case {index}");
            assert_eq!(blob_names(&dir), blobs, "case {index}");
            ledger.save().expect("save");
            assert_eq!(std::fs::read(dir.ledger()).expect("read"), saved);
        }
    }

    #[test]
    fn an_untouched_shared_file_still_re_records_and_keeps_its_prior() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let bx1 = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        let region = Mechanism::Region { comment: '#' };
        ledger
            .record(
                NewEntry::new(
                    target("~/.bashrc"),
                    ContentHash::of(bx1),
                    Mode::DEFAULT_FILE,
                    region.clone(),
                )
                .with_prior(prior(b"user line 1\n", 0o644)),
            )
            .expect("first");
        let stored = ledger
            .record(
                NewEntry::new(
                    target("~/.bashrc"),
                    ContentHash::of(b"BX2"),
                    Mode::DEFAULT_FILE,
                    region,
                )
                .with_prior(prior(bx1, 0o644)),
            )
            .expect("bx's own output is not a conflict")
            .clone();
        assert_eq!(stored.written, ContentHash::of(b"BX2"));
        assert_eq!(
            stored.prior,
            Prior::Existed(reference(b"user line 1\n", 0o644))
        );
    }

    #[test]
    fn the_ledger_survives_a_save_and_reload() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger.record(entry("~/a", b"x")).expect("record");
        ledger.save().expect("save");

        let reopened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(reopened.health, Health::Loaded);
        assert_eq!(reopened.value.len(), 1);
        assert_eq!(reopened.value.dir(), &dir);
    }

    #[test]
    fn saving_the_ledger_twice_produces_identical_bytes() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        let dirs = vec![target("~/.config/tool/sub"), target("~/.config/tool")];
        ledger
            .record(entry("~/.config/tool/sub/f", b"x").with_created_dirs(dirs.clone()))
            .expect("record");
        ledger.save().expect("save");

        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
        assert_eq!(
            reloaded
                .get(&target("~/.config/tool/sub/f"))
                .expect("entry")
                .created_dirs,
            dirs,
        );
    }

    #[test]
    fn a_re_record_keeps_the_directories_an_earlier_apply_created() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        let file = "~/.config/newdir/x.conf";
        let dirs = vec![target("~/.config/newdir"), target("~/.config")];

        // Apply #1 invents both parents.
        ledger
            .record(entry(file, b"v1").with_created_dirs(dirs.clone()))
            .expect("first");
        // Apply #2: the parents exist now, so the writer reports none created.
        ledger.record(entry(file, b"v2")).expect("second");
        assert_eq!(
            ledger.get(&target(file)).expect("entry").created_dirs,
            dirs,
            "`bx rm` must still know which directories bx invented",
        );

        // Apply #3 re-creates one it had already recorded: no duplicate.
        ledger
            .record(entry(file, b"v3").with_created_dirs(vec![target("~/.config/newdir")]))
            .expect("third");
        assert_eq!(ledger.get(&target(file)).expect("entry").created_dirs, dirs);

        ledger.save().expect("save");
        let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
        assert_eq!(
            reloaded.get(&target(file)).expect("entry").created_dirs,
            dirs
        );
    }

    #[test]
    fn directories_merged_across_re_records_stay_deepest_first() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        let file = "~/.config/newdir/x.conf";

        // Apply #1 invents only `~/.config`; `newdir` was there already.
        ledger
            .record(entry(file, b"v1").with_created_dirs(vec![target("~/.config")]))
            .expect("first");
        // Later `newdir` is gone and apply #2 invents it: deeper than the one
        // already recorded, so appending it would break the removal order.
        ledger
            .record(entry(file, b"v2").with_created_dirs(vec![target("~/.config/newdir")]))
            .expect("second");
        assert_eq!(
            ledger.get(&target(file)).expect("entry").created_dirs,
            vec![target("~/.config/newdir"), target("~/.config")],
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

        let loaded = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(loaded.health, Health::Loaded);
        assert!(
            loaded
                .value
                .get(&target("~/a"))
                .expect("entry")
                .created_dirs
                .is_empty(),
        );
        assert!(
            loaded
                .value
                .get(&target("~/a"))
                .expect("entry")
                .superseded
                .is_empty(),
            "a ledger written before `superseded` existed still loads",
        );
    }

    #[test]
    fn a_read_only_view_opens_with_no_lock_held() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger.record(entry("~/a", b"x")).expect("record");
        ledger.save().expect("save");

        // The exclusive lock is still held, and the reader is unaffected.
        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Loaded);
        assert_eq!(view.value.len(), 1);
    }

    #[test]
    fn a_corrupt_ledger_degrades_to_an_empty_one() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        dir.ensure().expect("ensure");
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");

        let loaded = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
        assert!(dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_dangling_ledger_symlink_stops_bx_instead_of_reading_as_fresh() {
        // Review round 3: a `ledger.mpk` link to storage that is not mounted
        // read as `Health::Fresh`, and the next save replaced the link.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let far = home.child("unmounted/ledger.mpk");
        std::os::unix::fs::symlink(&far, dir.ledger()).expect("symlink");

        let err = LedgerView::read(&dir, home.path()).expect_err("must refuse");
        assert!(
            matches!(&err, Error::DanglingLink { path } if *path == dir.ledger()),
            "got {err}",
        );
        assert!(err.to_string().contains("does not exist"), "{err}");
        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
        assert!(matches!(err, Error::DanglingLink { .. }), "got {err}");
        assert_eq!(std::fs::read_link(dir.ledger()).expect("still a link"), far);
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_ledger_from_a_newer_bx_is_refused_and_left_exactly_where_it_is() {
        // Review round 4: a newer format version was damage, so after a
        // rollback to an older bx `Ledger::open` moved an intact ledger aside,
        // the next apply recorded bx's output as every prior, and each rollback
        // added another `.corrupt.N`.
        #[derive(Serialize)]
        struct Newer<T> {
            kind: &'static str,
            version: u16,
            payload: T,
        }
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let newer = VERSION + 1;
        // A payload this build could decode, and one a newer format reshaped.
        let seeds = [
            rmp_serde::to_vec_named(&Newer {
                kind: KIND,
                version: newer,
                payload: LedgerView::default(),
            })
            .expect("encode"),
            rmp_serde::to_vec_named(&Newer {
                kind: KIND,
                version: newer,
                payload: ["entries", "reshaped"],
            })
            .expect("encode"),
        ];
        for seed in seeds {
            std::fs::write(dir.ledger(), &seed).expect("seed");
            let refused = |err: &Error| {
                matches!(
                    err,
                    Error::FutureVersion { path, found, supported }
                        if *path == dir.ledger() && *found == newer && *supported == VERSION
                )
            };

            let err = LedgerView::read(&dir, home.path()).expect_err("the reader refuses");
            assert!(refused(&err), "got {err}");
            // Every rollback opens the ledger again; none of them moves it.
            for _ in 0..3 {
                let err = Ledger::open(&dir, &lock, home.path()).expect_err("open refuses");
                assert!(refused(&err), "got {err}");
                assert!(err.to_string().contains("newer bx"), "{err}");
            }
            assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seed);
            let quarantines: Vec<_> = std::fs::read_dir(dir.root())
                .expect("read_dir")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("ledger.mpk."))
                .collect();
            assert!(quarantines.is_empty(), "{quarantines:?}");
        }
    }

    #[test]
    fn a_lockless_view_of_a_damaged_ledger_leaves_it_for_the_lock_holder() {
        // Review round 3: `LedgerView::read` renamed by path with no lock, so a
        // writer's save between the read and the rename lost its ledger.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Damaged(Damage::Malformed));
        assert!(view.value.is_empty());
        assert_eq!(
            std::fs::read(dir.ledger()).expect("left in place"),
            b"not messagepack",
        );
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());

        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(opened.health, Health::Reset(Damage::Malformed));
        assert!(!dir.ledger().exists());
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("quarantined"),
            b"not messagepack",
        );
    }

    #[test]
    fn a_lock_on_another_state_directory_opens_nothing_and_quarantines_nothing() {
        // Review round 4: `Ledger::open` and `Fingerprints::open` accepted any
        // `ExclusiveLock`, so A's lock quarantined B's damaged ledger while B's
        // own bx, holding B's lock, could be saving it.
        let a = guarded_home();
        let b = guarded_home();
        let (dir_a, lock_a) = locked(&a);
        let dir_b = StateDir::resolve(b.path());
        dir_b.ensure().expect("ensure");
        std::fs::write(dir_b.ledger(), b"not messagepack").expect("seed");
        std::fs::write(dir_b.fingerprints(), b"not messagepack").expect("seed");
        let wrong = |err: &Error| {
            matches!(
                err,
                Error::WrongLock { held, needed }
                    if *held == dir_a.lock() && *needed == dir_b.lock()
            )
        };

        let err = Ledger::open(&dir_b, &lock_a, b.path()).expect_err("A's lock is not B's");
        assert!(wrong(&err), "got {err}");
        assert!(err.to_string().contains("Take the lock"), "{err}");
        let err = Fingerprints::open(&dir_b, &lock_a).expect_err("A's lock is not B's");
        assert!(wrong(&err), "got {err}");
        let err = Fingerprints::default()
            .save(&dir_b, &lock_a)
            .expect_err("A's lock is not B's");
        assert!(wrong(&err), "got {err}");

        for file in [dir_b.ledger(), dir_b.fingerprints()] {
            assert_eq!(std::fs::read(&file).expect("in place"), b"not messagepack");
            assert!(!StateDir::quarantine(&file).exists());
        }
    }

    #[test]
    fn a_quarantine_orphaned_by_a_crash_before_the_save_stays_visible() {
        // Review round 4's falsifier: `Ledger::open` quarantined a damaged
        // ledger, bx stopped before `save`, and the next reader and writer saw
        // `Health::Fresh` with the `.corrupt` file reported nowhere.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");
        let first = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert!(first.health.is_reset());
        let aside = vec![StateDir::quarantine(&dir.ledger())];
        assert_eq!(first.quarantined, aside);
        drop(first);

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Fresh);
        assert_eq!(view.quarantined, aside);
        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(opened.health, Health::Fresh);
        assert_eq!(opened.quarantined, aside);
    }

    #[test]
    fn a_second_damaged_ledger_never_replaces_the_first_quarantine() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        std::fs::write(dir.ledger(), b"first damaged ledger").expect("seed");
        Ledger::open(&dir, &lock, home.path()).expect("first open");
        std::fs::write(dir.ledger(), b"second damaged ledger").expect("seed again");
        Ledger::open(&dir, &lock, home.path()).expect("second open");

        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("first kept"),
            b"first damaged ledger",
        );
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt.1")).expect("second kept"),
            b"second damaged ledger",
        );
    }

    /// `home/<rel>` as the absolute `Portable` a hand-edited or foreign ledger
    /// would hold: well-formed, so it decodes, and under this home.
    fn absolute_under(home: &GuardedHome, rel: &str) -> Portable {
        Portable::from_path(&home.child(rel), Path::new("/nonexistent/other/home"))
            .expect("an absolute portable path")
    }

    /// A one-entry ledger for `key`, saved without going through `record`.
    fn seed_ledger(dir: &StateDir, key: Portable, created_dirs: Vec<Portable>) -> Vec<u8> {
        let mut entries = BTreeMap::new();
        entries.insert(
            key.clone(),
            LedgerEntry {
                path: key,
                written: ContentHash::of(b"bx wrote this"),
                mode: Mode::DEFAULT_FILE,
                mechanism: Mechanism::Own,
                prior: Prior::Absent,
                created_dirs,
                superseded: Vec::new(),
            },
        );
        store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");
        std::fs::read(dir.ledger()).expect("read the seed")
    }

    #[test]
    fn a_ledger_keyed_by_an_absolute_path_under_the_home_is_refused_not_reset() {
        // Decision R3-1 of #4: `/…/home/.gitconfig` decodes, because a decoder
        // has no home, and on this account it is a second key for
        // `~/.gitconfig`. The loader is where the home is, so the loader
        // refuses — and, since review round 3, renames nothing.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let key = absolute_under(&home, ".gitconfig");
        assert!(key.as_str().starts_with('/'), "{key}");
        let seeded = seed_ledger(&dir, key.clone(), Vec::new());

        let err = LedgerView::read(&dir, home.path()).expect_err("must refuse");
        let Error::ForeignPath {
            path,
            home: checked,
            stored,
            source,
        } = &err
        else {
            panic!("a foreign key must be refused, got {err}");
        };
        assert_eq!(path, &dir.ledger());
        assert_eq!(checked, home.path());
        assert_eq!(stored, key.as_str());
        assert!(source.to_string().contains("~/.gitconfig"), "{source}");
        assert!(err.to_string().contains(key.as_str()), "names the path");
        assert!(err.to_string().contains("Nothing was changed"), "{err}");

        // Opening for writing goes through the same check, and refuses too.
        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
        assert!(matches!(err, Error::ForeignPath { .. }), "got {err}");

        // Neither call touched the ledger.
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_home_spelled_through_an_alias_stops_bx_and_leaves_the_ledger_in_place() {
        // Review round 3's falsifier. An apply under one spelling of the home —
        // `/var/home/me`, reached through a `/home/me` alias — records a target
        // named by the other spelling as an absolute path. The next run, under
        // the other spelling, folds that path into its home. That used to
        // quarantine a good ledger, after which the next apply recorded bx's own
        // output as every prior.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let alias = home.child("alias");
        std::os::unix::fs::symlink(home.path(), &alias).expect("alias");

        let mut ledger = Ledger::open(&dir, &lock, &alias).expect("open").value;
        let key = Portable::from_path(&home.child(".foo"), &alias).expect("portable");
        assert!(key.as_str().starts_with('/'), "{key}");
        ledger
            .record(
                NewEntry::new(
                    key,
                    ContentHash::of(b"bx"),
                    Mode::DEFAULT_FILE,
                    Mechanism::Own,
                )
                .with_prior(prior(b"the user wrote this", 0o644)),
            )
            .expect("record");
        ledger.save().expect("save");
        let seeded = std::fs::read(dir.ledger()).expect("read");

        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
        assert!(matches!(err, Error::ForeignPath { .. }), "got {err}");
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());

        // The ledger is intact: under the spelling it was written with, it loads.
        let reopened = Ledger::open(&dir, &lock, &alias).expect("reopen");
        assert_eq!(reopened.health, Health::Loaded);
        assert_eq!(reopened.value.len(), 1);
    }

    #[test]
    fn a_root_home_refuses_rather_than_resetting() {
        // `HOME=/` folds every absolute path into the home.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let outside = Portable::try_from("/etc/bx-example.conf".to_string()).expect("absolute");
        let seeded = seed_ledger(&dir, outside, Vec::new());

        let err = Ledger::open(&dir, &lock, Path::new("/")).expect_err("must refuse");
        assert!(matches!(err, Error::ForeignPath { .. }), "got {err}");
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
    }

    #[test]
    fn a_created_directory_spelled_absolutely_under_the_home_is_refused() {
        // Every stored Portable, not only the keys: `bx rm` removes these.
        let home = guarded_home();
        let (dir, _lock) = locked(&home);
        let seeded = seed_ledger(
            &dir,
            target("~/.config/tool/x.conf"),
            vec![target("~/.config/tool"), absolute_under(&home, ".config")],
        );

        let err = LedgerView::read(&dir, home.path()).expect_err("must refuse");
        assert!(
            matches!(
                &err,
                Error::ForeignPath { stored, .. }
                    if *stored == absolute_under(&home, ".config").as_str()
            ),
            "got {err}",
        );
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
    }

    /// A one-entry ledger whose entry names `path` but is stored under `key`.
    fn seed_mismatched(dir: &StateDir, key: Portable, path: Portable) -> Vec<u8> {
        let mut entries = BTreeMap::new();
        entries.insert(
            key,
            LedgerEntry {
                path,
                written: ContentHash::of(b"x"),
                mode: Mode::DEFAULT_FILE,
                mechanism: Mechanism::Own,
                prior: Prior::Absent,
                created_dirs: Vec::new(),
                superseded: Vec::new(),
            },
        );
        store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");
        std::fs::read(dir.ledger()).expect("read the seed")
    }

    #[test]
    fn an_entry_stored_under_a_key_that_is_not_its_path_is_damage() {
        // Review round 3: `check_paths` never compared the two, so an entry for
        // `~/.bbbb` filed under `~/.aaaa` loaded, and `get(~/.aaaa)` answered
        // with another target's record.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let seeded = seed_mismatched(&dir, target("~/.aaaa"), target("~/.bbbb"));
        let damage = Damage::KeyMismatch {
            key: "~/.aaaa".to_string(),
            path: "~/.bbbb".to_string(),
        };

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Damaged(damage.clone()));
        assert!(view.value.is_empty());
        assert!(damage.to_string().contains("~/.bbbb"), "{damage}");

        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(opened.health, Health::Reset(damage));
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("quarantined"),
            seeded,
        );
    }

    #[test]
    fn a_mismatched_entry_is_damage_before_it_is_a_home_problem() {
        // A key under the home and an entry path spelled absolutely under it:
        // both wrong, and the mismatch is what bx never writes.
        let home = guarded_home();
        let (dir, _lock) = locked(&home);
        seed_mismatched(
            &dir,
            target("~/.gitconfig"),
            absolute_under(&home, ".gitconfig"),
        );

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert!(
            matches!(view.health, Health::Damaged(Damage::KeyMismatch { .. })),
            "{:?}",
            view.health,
        );
    }

    #[test]
    fn an_absolute_path_outside_the_home_is_still_trusted() {
        let home = guarded_home();
        let (dir, _lock) = locked(&home);
        let outside = Portable::try_from("/etc/bx-example.conf".to_string()).expect("absolute");
        seed_ledger(&dir, outside.clone(), vec![target("~/.config")]);

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Loaded);
        assert!(view.value.get(&outside).is_some());
    }

    #[test]
    fn a_home_the_ledger_cannot_be_checked_against_quarantines_nothing() {
        // A bad home is the caller's defect. Reading it as damage would move an
        // intact ledger aside and let the next apply record over nothing.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let seeded = seed_ledger(&dir, target("~/.gitconfig"), Vec::new());

        let err = LedgerView::read(&dir, Path::new("relative/home")).expect_err("must fail");
        assert!(matches!(err, Error::Home { .. }), "got {err}");
        assert!(err.to_string().contains("relative/home"), "{err}");
        let err = Ledger::open(&dir, &lock, Path::new("relative/home")).expect_err("must fail");
        assert!(matches!(err, Error::Home { .. }), "got {err}");
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
        assert_eq!(std::fs::read(dir.ledger()).expect("intact"), seeded);
    }

    #[test]
    fn an_unreadable_ledger_stops_bx_instead_of_resetting_it() {
        if rustix::process::geteuid().is_root() {
            // `0000` denies nothing to root; see the note in `state::store`.
            return;
        }
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
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
        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must fail");
        assert!(matches!(err, Error::Read { .. }), "got {err}");
        assert!(
            LedgerView::read(&dir, home.path()).is_err(),
            "the reader must fail too"
        );
        assert!(
            !dir.root().join("ledger.mpk.corrupt").exists(),
            "an unreadable ledger must never be quarantined",
        );

        std::fs::set_permissions(dir.ledger(), std::fs::Permissions::from_mode(0o600))
            .expect("restore");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), intact);
        let reopened = Ledger::open(&dir, &lock, home.path()).expect("open");
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
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .record(entry("~/.bashrc", b"x").with_prior(PriorBytes::Bytes {
                bytes: b"prior".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
        ledger.save().expect("save");
        let mut fingerprints = Fingerprints::read(&dir).expect("read").value;
        fingerprints.set("activation:rustup", Fingerprint::hashed(b"v1"));
        fingerprints.save(&dir, &lock).expect("save");

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
