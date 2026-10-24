//! The ledger, writable: recording, withdrawing, adopting and saving under
//! the lock.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use super::entry::{
    History, LedgerEntry, Mechanism, NewEntry, Prior, PriorBytes, RestoreRef, Withdrawal,
    check_created_dirs, is_ancestor, prior_conflict,
};
use super::view::LedgerView;
use super::{KIND, VERSION};
use crate::fs::Mode;
use crate::hash::ContentHash;
use crate::state::Error;
use crate::state::dir::{StateDir, ensure_dir};
use crate::state::lock::{ExclusiveLock, HeldLock};
use crate::state::restore;
use crate::state::store::{self, Loaded};

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
///
/// What is checked again, before every write — [`Ledger::record`], the
/// test-only `Ledger::adopt_current_as_prior` and [`Ledger::save`] — is that the lock
/// file this was opened under is still the file at the lock path. An outside
/// `mv` or `rm` of a held lock file lets a second bx lock a new one, and a
/// ledger that went on writing would be writing beside it.
#[derive(Debug)]
pub struct Ledger {
    /// Where it lives, so `record` and `save` need no further arguments.
    dir: StateDir,
    /// The home it was opened under, so `record` refuses exactly the paths the
    /// next `open` under that home would refuse.
    home: PathBuf,
    /// The lock file it was opened under, so a write can refuse once that file
    /// has been replaced.
    lock: HeldLock,
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
    /// A damaged `ledger.mpk` is moved aside to the next quarantine name and
    /// this returns what survived it, with [`crate::state::Health::Reset`] saying so —
    /// the empty ledger for damage the decoder found, and the rows that check
    /// out for damage confined to rows; see [`LedgerView::read`]. The lock is
    /// what makes that rename safe: no writer can have saved since the bytes
    /// were read.
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
    ///
    /// [`Error::CannotQuarantine`] if `ledger.mpk` is damaged and cannot be
    /// moved aside. It is left exactly where it is and nothing is reset, so no
    /// later [`Ledger::save`] can write over the only record of the priors.
    pub fn open(dir: &StateDir, lock: &ExclusiveLock, home: &Path) -> Result<Loaded<Self>, Error> {
        let dir = dir.clone();
        Ok(LedgerView::load(&dir, home, Some(lock))?.map(|view| Self {
            dir,
            home: home.to_path_buf(),
            lock: lock.held().clone(),
            view,
        }))
    }

    /// The state directory this ledger was opened from.
    #[cfg(test)]
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
    /// refuse, [`Error::UnrelatedCreatedDir`] for a `created_dirs` entry that
    /// is not an ancestor of the target, and [`Error::PriorConflict`] for a
    /// changed file bx shares with the user.
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
    /// * [`PriorBytes::Absent`] — the stored prior is kept. A caller states it
    ///   rather than omitting it ([`NewEntry::new`] takes it), so it does mean
    ///   "there was no file" — but it carries no bytes that keeping the stored
    ///   prior could lose, and the stored prior is what the user last had. A
    ///   stored snapshot is therefore never rewritten into "unlink it".
    /// * bytes that hash to the stored `written` — bx's own previous output,
    ///   untouched. The stored prior is kept and nothing is written: snapshotting
    ///   these would make `bx rm` restore bx's generated content.
    /// * bytes that do **not** hash to `written` — someone other than bx wrote
    ///   the file since bx last did, and this apply is about to displace those
    ///   bytes. They are stored in `restore/`, durably, and become the prior. A
    ///   stored [`Prior::Existed`] they replace moves to
    ///   [`LedgerEntry::superseded`] rather than being dropped, and a stored
    ///   [`Prior::Absent`] they replace sets
    ///   [`LedgerEntry::superseded_absent`]: it had no bytes to keep, but that
    ///   there was no file before bx is still part of the history.
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
    ///   The way out that loses no byte is `Ledger::adopt_current_as_prior`,
    ///   run only because the user chose it; no command offers it yet.
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
    ///
    /// [`Error::UnrelatedCreatedDir`] if a `created_dirs` entry is not an
    /// ancestor of the target; nothing is stored.
    ///
    /// [`Error::WrongLock`] if the lock file this ledger was opened under has
    /// been replaced or removed since; nothing is stored.
    pub fn record(&mut self, entry: NewEntry) -> Result<&LedgerEntry, Error> {
        self.check_lock()?;
        self.check_new_paths(&entry)?;
        check_created_dirs(&entry)?;
        let key = entry.path.clone();
        let (prior, history, created_dirs) = match self.view.entries.get(&key) {
            None => (
                Self::store_prior(&self.dir, entry.prior)?,
                History::default(),
                // Normalised on a first record exactly as `merge_created_dirs`
                // normalises on a re-record. Storing the list verbatim here
                // trusted `with_created_dirs`'s documented order and validated
                // it nowhere, so a caller handing them over shallowest-first
                // had the fault silently corrected from the second apply on
                // and not the first — and `bx rm` left a directory behind for
                // targets applied exactly once.
                merge_created_dirs(&key, &[], entry.created_dirs),
            ),
            Some(existing) => {
                let (prior, history) = self.carry_prior(existing, &entry.mechanism, entry.prior)?;
                (
                    prior,
                    history,
                    merge_created_dirs(&key, &existing.created_dirs, entry.created_dirs),
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
                superseded: history.superseded,
                superseded_absent: history.absent,
            },
        );
        Ok(&self.view.entries[&key])
    }

    /// Decide the prior and the history for a re-record of `existing`.
    ///
    /// The rule is documented on [`Ledger::record`]. Any bytes that are to be
    /// adopted are durable in `restore/` before this returns.
    fn carry_prior(
        &self,
        existing: &LedgerEntry,
        mechanism: &Mechanism,
        incoming: PriorBytes,
    ) -> Result<(Prior, History), Error> {
        // A shared file's changed bytes still hold bx's own region or include
        // line. Refused before anything is stored: see `record`.
        prior_conflict(existing, mechanism, &incoming)?;
        let kept = || (existing.prior.clone(), History::of(existing));
        let PriorBytes::Bytes { bytes, mode } = incoming else {
            return Ok(kept());
        };
        let digest = ContentHash::of(&bytes);
        if digest == existing.written {
            return Ok(kept());
        }

        // A third party wrote these bytes and this apply displaces them: they
        // reach `restore/` before anything else is decided.
        let adopted = Self::store_restore(&self.dir, digest, &bytes, mode)?;
        let history = supersede(existing, &adopted);
        tracing::info!(
            path = %existing.path,
            digest = %adopted.digest,
            "the file changed since bx last wrote it; keeping the displaced bytes as its prior",
        );
        Ok((Prior::Existed(adopted), history))
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
    ///
    /// It is **not** how a record whose write was then refused is undone:
    /// on any apply after the first there was an entry before that record, and
    /// dropping it loses the prior the user had before bx, which is Invariant 4
    /// inverted. [`Ledger::withdraw`] puts back exactly what was there.
    #[must_use = "the entry removed is the only record of what was there; drop it deliberately"]
    pub fn forget(&mut self, path: &crate::paths::Portable) -> Option<LedgerEntry> {
        self.view.entries.remove(path)
    }

    /// Undo a [`Ledger::record`] whose write never landed, by putting back the
    /// entry `withdrawal` captured before it — or no entry, when there was none.
    ///
    /// Take the [`Withdrawal`] with [`LedgerView::withdrawal`] **before** the
    /// `record`, keep it across the publish, and hand it here when the publish
    /// is refused. The entry comes back exactly as it was: its prior, its
    /// history and its created directories, not only its key. Returns the
    /// entry the refused record had left, if any.
    ///
    /// Any blob that `record` stored in `restore/` stays there: blobs are
    /// content-addressed and may be shared, as [`Ledger::forget`] says.
    #[must_use = "the entry withdrawn describes a write that never landed; drop it deliberately"]
    pub fn withdraw(&mut self, withdrawal: Withdrawal) -> Option<LedgerEntry> {
        let Withdrawal { path, before } = withdrawal;
        match before {
            Some(entry) => self.view.entries.insert(path, entry),
            None => self.view.entries.remove(&path),
        }
    }

    /// Accept a target as it is now as the version `bx rm` restores — the way
    /// out of [`Error::PriorConflict`] that loses no byte.
    ///
    /// `bytes` and `mode` are the target as it is on disk now. When the bytes
    /// hash to the entry's `written`, nothing has changed and nothing is done.
    /// Otherwise they are stored in `restore/`, durably, and become the prior;
    /// the prior they replace joins the history exactly as a re-record of an
    /// `Own` target moves it — a snapshot to [`LedgerEntry::superseded`], a
    /// [`Prior::Absent`] to [`LedgerEntry::superseded_absent`] — so nothing
    /// that was there before bx is lost from the ledger, not even that there
    /// was nothing. `written` becomes their digest: the next `plan` sees the
    /// file as bx last accepted it, and the next apply's re-record keeps this
    /// prior instead of conflicting again.
    ///
    /// For a `Region` or `Include` target this is on purpose what `record`
    /// refuses to do by itself, and what it leaves behind has to be said
    /// plainly. The accepted bytes hold bx's own region or include line as it
    /// is now, and `bx rm` restores exactly those bytes: bx's lines go back
    /// into the file stale, bx no longer manages or removes them there, and
    /// the user removes them by hand. That holds for a file bx created too —
    /// `bx rm` then leaves the file, bx's line in it, rather than removing it.
    /// So it must run only because the user chose it, and
    /// [`Error::PriorConflict`]'s message says the same. Restoring the user's
    /// edit without bx's lines needs the region writer's delimiter grammar,
    /// which does not exist yet.
    ///
    /// Returns `Ok(None)`, changing nothing, when bx records no entry for
    /// `path`.
    ///
    /// # Errors
    ///
    /// [`Error::CreateDir`] or [`Error::Write`] if the bytes cannot be stored.
    /// The entry is left unchanged.
    ///
    /// [`Error::WrongLock`] if the lock file this ledger was opened under has
    /// been replaced or removed since; nothing is stored.
    ///
    /// No command offers it yet, so only tests call it.
    #[cfg(test)]
    pub fn adopt_current_as_prior(
        &mut self,
        path: &crate::paths::Portable,
        bytes: &[u8],
        mode: Mode,
    ) -> Result<Option<&LedgerEntry>, Error> {
        self.check_lock()?;
        // The entry is fetched **once**, mutably, and the blob is stored
        // through the directory rather than through `&self`. Fetching it again
        // after the store — which a `&self` store forced — left an `if let
        // Some(..)` whose `else` no input could take, so a mutant emptying the
        // body survived the suite (r4 round 2, COV7).
        let Ledger { view, dir, .. } = &mut *self;
        let Some(entry) = view.entries.get_mut(path) else {
            return Ok(None);
        };
        let digest = ContentHash::of(bytes);
        if digest == entry.written {
            return Ok(Some(entry));
        }
        let adopted = Self::store_restore(dir, digest, bytes, mode)?;
        let history = supersede(entry, &adopted);
        tracing::info!(
            path = %entry.path,
            digest = %adopted.digest,
            "accepting the file as it is now as the version bx rm restores",
        );
        entry.prior = Prior::Existed(adopted);
        entry.superseded = history.superseded;
        entry.superseded_absent = history.absent;
        entry.written = digest;
        Ok(Some(entry))
    }

    /// Turn caller-supplied prior bytes into a durable [`Prior`].
    ///
    /// Takes the directory rather than `&self` so that a caller holding a
    /// `&mut` borrow of the entries can still store a blob: see
    /// `Ledger::adopt_current_as_prior`, where the re-fetch that borrow
    /// used to force was a branch no input could take (r4 round 2, COV7).
    fn store_prior(dir: &StateDir, prior: PriorBytes) -> Result<Prior, Error> {
        match prior {
            PriorBytes::Absent => Ok(Prior::Absent),
            PriorBytes::Bytes { bytes, mode } => Ok(Prior::Existed(Self::store_restore(
                dir,
                ContentHash::of(&bytes),
                &bytes,
                mode,
            )?)),
        }
    }

    /// Store `bytes`, already hashed to `digest`, through
    /// [`restore::store_bytes`], creating `restore/` first, and return the
    /// reference.
    fn store_restore(
        dir: &StateDir,
        digest: ContentHash,
        bytes: &[u8],
        mode: Mode,
    ) -> Result<RestoreRef, Error> {
        ensure_dir(&dir.restore(), Mode::PRIVATE_DIR)?;
        Ok(restore::store_bytes(dir, digest, bytes, mode)?)
    }

    /// Write the ledger out, atomically.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`], [`Error::CreateDir`] or [`Error::Write`]. A failure
    /// leaves the previous ledger exactly as it was, except a failing `fsync`
    /// of the state directory after the rename, which is returned with the new
    /// ledger already in place — see [`crate::fs::write_atomically`].
    ///
    /// [`Error::WrongLock`] if the lock file this ledger was opened under has
    /// been replaced or removed since; nothing is written.
    ///
    /// # No stray `created_dirs` reaches the file
    ///
    /// A load that found a key mismatch reports and acts on that alone, and
    /// leaves a stray `created_dirs` entry in a surviving row for the next
    /// load to strip — see [`LedgerView::check_paths`]. Saving the view
    /// verbatim would put it on disk, and the next read would report
    /// `UnrelatedCreatedDirs` on a file bx had just written. So this strips
    /// them here too, and warns.
    ///
    /// [`merge_created_dirs`] does the same on the `record` path, and both are
    /// needed rather than one: `record` hands the entry back to its caller
    /// before any save, so a caller acting on what it returns must not see a
    /// stray either. "The write path" means **every** write, which is what
    /// this round settled (r4 round 5, D1 and CL1) — the previous round put
    /// the rule on `record` alone and claimed it covered the whole exposure.
    pub fn save(&mut self) -> Result<(), Error> {
        self.check_lock()?;
        for (target, dir) in self.view.strip_unrelated_created_dirs() {
            tracing::warn!(
                target = %target,
                dir = %dir,
                "{dir} is not above {target}; dropping it rather than writing it out",
            );
        }
        store::save(&self.dir.ledger(), KIND, VERSION, &self.view)
    }

    /// Refuse to write through this ledger once the lock file it was opened
    /// under is no longer the one at the lock path.
    ///
    /// An outside `mv` or `rm` of a held lock file lets a second bx lock a new
    /// file there, and from then on this ledger's writes are unguarded. This
    /// cannot tell that the guard is still alive — see [`Ledger`] — only that
    /// the file it locked is still the lock file.
    fn check_lock(&self) -> Result<(), Error> {
        crate::state::dir::check_held(&self.dir.ledger(), &self.lock)
    }

    /// Give each claimed directory that still stands to an entry this ledger
    /// holds beneath it, so the `rm` that removes that entry prunes it.
    ///
    /// The heir is the first entry, in the ledger's own order, whose target is
    /// strictly inside the directory. A directory no entry is beneath — one only
    /// the user's files keep — is claimed by nobody from here on, and stays. The
    /// claim is merged by [`Ledger::record`] with the heir's digest, mode and
    /// mechanism as they are and no prior, which keeps the stored prior and
    /// every superseded snapshot.
    ///
    /// Bookkeeping only: no destination is touched. [`crate::recover`] runs the
    /// same hand-off when it rebuilds a terminated journal's ledger, so a crash
    /// between the `End` frame and the save loses no claim.
    ///
    /// # Errors
    ///
    /// What [`Ledger::record`] returns when it refuses the re-record, and
    /// [`Error::Write`] with [`crate::fs::Error::NotPortable`] for a directory
    /// that cannot be made portable.
    pub(crate) fn hand_off_claims<'a>(
        &mut self,
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
            let Some(heir) = self
                .iter()
                .find(|(path, _)| {
                    let at = path.render(home);
                    at != *dir && at.starts_with(dir)
                })
                .map(|(_, entry)| entry.clone())
            else {
                continue;
            };
            let claim = crate::paths::Portable::from_path(dir, home).map_err(|source| {
                crate::fs::Error::NotPortable {
                    path: dir.clone(),
                    source,
                }
            })?;
            if heir.created_dirs.contains(&claim) {
                continue;
            }
            tracing::debug!(
                dir = %dir.display(),
                heir = %heir.path,
                "handed a directory bx created to an entry still beneath it",
            );
            // `Absent` states no prior, and on a re-record `record` never lets an
            // incoming `Absent` replace the stored one, so the heir keeps its own.
            self.record(
                NewEntry::new(
                    heir.path,
                    heir.written,
                    heir.mode,
                    heir.mechanism,
                    PriorBytes::Absent,
                )
                .with_created_dirs(vec![claim]),
            )?;
        }
        Ok(())
    }
}

/// `existing`'s history once `adopted` becomes its prior.
///
/// A snapshot it replaces is appended to the superseded list unless it is
/// already there, so every blob stored for a live target stays indexed; a
/// [`Prior::Absent`] it replaces sets [`LedgerEntry::superseded_absent`], so
/// that there was no file before bx is not lost either; and a snapshot the user
/// has put back is the prior again, not history.
fn supersede(existing: &LedgerEntry, adopted: &RestoreRef) -> History {
    let mut history = History::of(existing);
    match &existing.prior {
        Prior::Existed(previous) => {
            if !history.superseded.contains(previous) {
                history.superseded.push(previous.clone());
            }
        }
        Prior::Absent => history.absent = true,
    }
    history.superseded.retain(|reference| reference != adopted);
    history
}

/// The directories an earlier record created, plus any a later one did.
///
/// Every entry is an ancestor of the same target, so depth alone orders them:
/// the result is deduplicated and sorted deepest first, with ties — which two
/// distinct ancestors of one path cannot produce — kept in first-seen order.
///
/// # The stored side is checked too, not only the incoming one
///
/// [`check_created_dirs`] refuses a stray in the entry the caller hands over,
/// before anything is stored. It says nothing about the list already in the
/// ledger — and since r4 round 3 that list can hold a stray: a load that found
/// a key mismatch reports and acts on that alone, and leaves a stray
/// `created_dirs` entry in a surviving row for the next load to strip. Merging
/// it through would write it back, and the next read would report
/// `UnrelatedCreatedDirs` **on a file bx had just written** — bx producing a
/// file it refuses (r4 round 4, D2).
///
/// So a stored directory that is not above `target` is dropped here, with a
/// warning: the load that let it through already quarantined the file it came
/// from, so the bytes are kept and there is nothing to lose by not carrying it
/// forward. `record` still *refuses* an incoming stray rather than dropping it
/// — a caller handing one over has a bug, where a stored one is damage bx has
/// already reported.
fn merge_created_dirs(
    target: &crate::paths::Portable,
    existing: &[crate::paths::Portable],
    incoming: Vec<crate::paths::Portable>,
) -> Vec<crate::paths::Portable> {
    let mut merged = Vec::with_capacity(existing.len() + incoming.len());
    for dir in existing {
        if is_ancestor(dir, target) {
            // The stored list is deduplicated as the incoming one is: bx never
            // writes a duplicate, so one here is tampering, and carrying it
            // forward would make the result the doc promises false (r5, C2).
            if !merged.contains(dir) {
                merged.push(dir.clone());
            }
        } else {
            tracing::warn!(
                target = %target,
                dir = %dir,
                "{dir} is not above {target}; dropping it rather than recording it again",
            );
        }
    }
    for dir in incoming {
        if !merged.contains(&dir) {
            merged.push(dir);
        }
    }
    merged.sort_by_key(|dir| std::cmp::Reverse(dir.as_str().split('/').count()));
    merged
}

#[cfg(test)]
mod tests;
