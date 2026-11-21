//! One target's record: how bx attached to it, what it displaced, and the
//! rules every record of it must keep.

#[cfg(test)]
use std::path::Path;

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use super::{Ledger, LedgerView};
#[cfg(test)]
use crate::fs::Filled;
use crate::fs::{Mode, Observed};
use crate::hash::ContentHash;
use crate::state::Error;

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
    /// bx owns a directory: its mode, and the directory itself when bx
    /// created it. Never its contents.
    ///
    /// A directory has no bytes, so an entry attached this way records the
    /// digest of the empty string as [`LedgerEntry::written`], and a
    /// [`Prior::Existed`] names the directory's earlier mode against the empty
    /// blob. [`DIR_BYTES`] is that convention's one spelling.
    Dir,
    /// bx owns a symlink it made: the link itself, never what it points at.
    ///
    /// A link's content is its text, so an entry attached this way records
    /// the digest of that text as [`LedgerEntry::written`] — see
    /// [`crate::fs::link::digest`] — at [`crate::fs::Mode::LINK`], and a
    /// [`Prior::Existed`] names an earlier link's text stored as a blob like
    /// any file's bytes. Added last, so every entry an earlier bx saved still
    /// decodes as the variant it was written as.
    Link,
    /// bx cloned a declared git external into a directory it created: the
    /// directory and everything git put in it, never a directory that was
    /// already there.
    ///
    /// A checkout has no one digest bx could compare, so an entry attached
    /// this way records, as [`LedgerEntry::written`], the digest of the
    /// commit id bx last left checked out, spelled as `git rev-parse` prints
    /// it — see [`clone_written`]. Its prior is always [`Prior::Absent`]: bx
    /// never clones into or over anything, so there was nothing there.
    ///
    /// While bx is still populating the directory, `written` is
    /// [`clone_written`] of `None`, the digest of the empty string, which no
    /// commit id has. The entry is saved so before the first byte of a clone
    /// lands, so a run that stops part way leaves an entry that says the
    /// directory is bx's and not a finished checkout: everything in it is
    /// what bx put there, so the next `apply` removes it and clones again, and
    /// the next `rm` removes it.
    ///
    /// While bx is removing a finished checkout, `written` is
    /// [`clone_removing`] instead, saved before the first byte of the removal
    /// goes. What a stopped removal leaves was the user's to add to in the
    /// meantime, so the next run asks git about it again, as it would about
    /// a finished checkout, and removes it only when nothing in it is
    /// anyone's but the remote's.
    ///
    /// A unit variant, like [`Mechanism::Dir`], so the commit lives in the
    /// digest and every [`Mechanism`] stays the size it was. Added after
    /// [`Mechanism::Link`], so every entry an earlier bx saved still decodes
    /// as the variant it was written as.
    Clone,
}

/// What a [`Mechanism::Clone`] entry records as [`LedgerEntry::written`]: the
/// digest of `rev`, or of the empty string while no finished checkout stands.
#[must_use]
pub fn clone_written(rev: Option<&str>) -> ContentHash {
    ContentHash::of(rev.unwrap_or_default().as_bytes())
}

/// What a [`Mechanism::Clone`] entry records as [`LedgerEntry::written`] while
/// bx removes a finished checkout: the digest of `removing`, which neither a
/// commit id nor the empty string [`clone_written`] digests is.
#[must_use]
pub fn clone_removing() -> ContentHash {
    ContentHash::of(b"removing")
}

/// What a [`Mechanism::Own`] entry records as [`LedgerEntry::written`] once
/// bx removed the file and kept the entry: [`ContentHash::ZERO`], which no
/// file's bytes hash to.
///
/// A tracked target deleted on one side since the last sync, while the other
/// side still holds what the two agreed on, has its deletion carried to the
/// other side: that removal is bx's write, so the entry stays, with the bytes
/// it removed as its prior unless bx itself created that copy, and `bx rm`
/// puts them back; a copy bx itself created keeps its prior
/// [`Prior::Absent`], so `bx rm` restores nothing there. What is on disk there
/// is then what bx left while nothing is, and a file found there since is
/// someone else's, as any edit of a file bx owns is.
#[must_use]
pub const fn removed_written() -> ContentHash {
    ContentHash::ZERO
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
    #[cfg(test)]
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
    /// else has, and it is a `Conflict` — unless [`LedgerEntry::region`] says
    /// the edit was beside bx's region rather than in it.
    ///
    /// [`removed_written`] where bx removed the file and kept the entry.
    pub written: ContentHash,
    /// For a [`Mechanism::Region`], the digest of the region bx last wrote,
    /// delimiters included.
    ///
    /// A region is bx's and the bytes around it are the user's, so an edit
    /// around it is no reason to leave the region stale: while the region on
    /// disk still hashes to this, the edit was outside it, and bx rewrites its
    /// region and nothing else. When it does not, the edit was inside it, and
    /// that is a conflict.
    ///
    /// `None` for every other mechanism, and for a region entry written before
    /// the field existed or rebuilt by recovery, which records the digest of
    /// what it finds and not the bytes: such an entry is judged by
    /// [`LedgerEntry::written`] alone, as every region was before, and gains
    /// the digest the next time bx writes the region. Written only when set, so
    /// a ledger holding none saves byte-identically to one written before the
    /// field, and a build that predates it ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<ContentHash>,
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
    /// Whether a [`Prior::Absent`] has been superseded: before bx first wrote
    /// the target there was no file, and that is no longer the prior.
    ///
    /// Kept beside [`LedgerEntry::superseded`] rather than in it, so that list
    /// stays the list of snapshots callers already read. No order is lost:
    /// `Absent` is only ever the prior of an entry's first record — a re-record
    /// never lets an incoming `Absent` replace a stored prior — so once it is
    /// superseded it is the oldest point in the history, before every snapshot
    /// in `superseded`.
    ///
    /// Written only when `true`. A ledger in which this never happened saves
    /// byte-identically to one written before the field existed, and a build
    /// that predates the field ignores it rather than refusing the ledger —
    /// losing only this fact, at its next save.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub superseded_absent: bool,
    /// The answer *keep* a writing run was last given about this target, with
    /// what both sides were when it was given: see [`Kept`].
    ///
    /// Cleared by every [`Ledger::record`], since a write leaves bytes the
    /// answer was not about. A record that no longer matches what is on disk
    /// and what bx wants there is never consulted, so a stale one only means
    /// the question is put again.
    ///
    /// Written only when set, so a ledger that holds none saves
    /// byte-identically to one written before the field existed, and a build
    /// that predates it ignores it: losing the record, at worst, puts the
    /// question again. That is all the record is worth, and why it needs no
    /// new format version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept: Option<Kept>,
}

/// An answer *keep* about a target edited, retargeted, re-moded or deleted
/// since bx left it, and what was there on both sides when it was given.
///
/// While what is on disk and what bx wants there are still exactly these,
/// the answer stands: the target's row says it was kept and is not asked
/// about again. Once either side changes the question is put again, about
/// what it changed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    /// The digest of what was on disk: a regular file's bytes, a symlink's
    /// text as [`crate::fs::link::digest`] spells it, or [`ContentHash::ZERO`]
    /// where nothing was.
    pub found: ContentHash,
    /// The mode of what was on disk, or `None` where nothing was.
    pub found_mode: Option<Mode>,
    /// The digest of what bx wanted there instead: the whole file it would
    /// have written, or the text of the link it would have made.
    pub wanted: ContentHash,
    /// The mode bx wanted it at.
    pub mode: Mode,
}

/// What an entry keeps of the priors it no longer restores: the two history
/// fields of [`LedgerEntry`], moved together.
#[derive(Debug, Default)]
pub(super) struct History {
    /// As [`LedgerEntry::superseded`].
    pub(super) superseded: Vec<RestoreRef>,
    /// As [`LedgerEntry::superseded_absent`].
    pub(super) absent: bool,
}

impl History {
    /// `entry`'s history as it stands.
    pub(super) fn of(entry: &LedgerEntry) -> Self {
        Self {
            superseded: entry.superseded.clone(),
            absent: entry.superseded_absent,
        }
    }
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

impl PriorBytes {
    /// What `observed` held, in the shape [`Ledger::record`] takes.
    ///
    /// Anything that is not a regular file becomes [`PriorBytes::Absent`]. That
    /// is not a loss: a write only ever proceeds over a regular file or nothing
    /// at all, so the other kinds never reach a `record` call.
    #[must_use]
    pub fn of(observed: &Observed) -> Self {
        match (&observed.bytes, observed.mode) {
            (Some(bytes), Some(mode)) => Self::Bytes {
                bytes: bytes.clone(),
                mode,
            },
            _ => Self::Absent,
        }
    }
}

/// The bytes a directory stands for in a record: none.
///
/// A directory target's ledger entry and journal intents name it by the digest
/// of these bytes and by its mode, so the shapes that describe a file describe
/// a directory without a second vocabulary. The [`Mechanism`] or
/// [`crate::journal::Intent::dir`] beside them says which is meant.
pub const DIR_BYTES: &[u8] = b"";

/// The digest a directory is recorded under: that of [`DIR_BYTES`].
#[must_use]
pub fn dir_digest() -> ContentHash {
    ContentHash::of(DIR_BYTES)
}

/// A directory's earlier state at `mode`, in the shape a [`Prior`] takes.
///
/// No blob is stored for it: a directory's rollback is a `chmod` or a
/// `mkdir`, which reads no bytes. [`Ledger::record`] stores the empty blob
/// itself when the ledger adopts this as an entry's prior.
#[must_use]
pub fn dir_prior(mode: Mode) -> Prior {
    Prior::Existed(RestoreRef {
        digest: dir_digest(),
        mode,
        len: 0,
    })
}

/// A target to record, before its prior bytes have been stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEntry {
    /// The target.
    pub path: crate::paths::Portable,
    /// The digest of the whole bytes bx just wrote there.
    pub written: ContentHash,
    /// For a region, the digest of the region in those bytes: see
    /// [`LedgerEntry::region`]. `None` unless [`NewEntry::with_region`] sets it.
    pub region: Option<ContentHash>,
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
    /// A new entry for a target, stating what was there before it.
    ///
    /// `prior` is not defaulted, and that is the point. Invariant 4 makes the
    /// prior the reversibility record, and [`PriorBytes::Absent`] is its
    /// destructive reading — *there was no file*, so `bx rm` unlinks. A
    /// default would make the dangerous value the one a caller reaches by
    /// saying nothing, on the one record where nothing stored can correct it:
    /// [`Ledger::record`] protects a *re*-record, by never letting an incoming
    /// `Absent` replace a stored prior, and a first record has nothing to fall
    /// back on. So a caller states it. Pass [`PriorBytes::Absent`] for a target
    /// bx created where nothing existed.
    #[must_use]
    pub fn new(
        path: crate::paths::Portable,
        written: ContentHash,
        mode: Mode,
        mechanism: Mechanism,
        prior: PriorBytes,
    ) -> Self {
        Self {
            path,
            written,
            mode,
            mechanism,
            prior,
            created_dirs: Vec::new(),
            region: None,
        }
    }

    /// Record the digest of the region in `bytes`, the whole file bx writes,
    /// when this entry attaches as a [`Mechanism::Region`] and `bytes` holds
    /// exactly one; any other entry is left without one.
    #[must_use]
    pub fn with_region(mut self, bytes: &[u8]) -> Self {
        self.region = region_of(&self.mechanism, bytes);
        self
    }

    /// Replace what this entry says the target held before.
    #[cfg(test)]
    #[must_use]
    pub fn with_prior(mut self, prior: PriorBytes) -> Self {
        self.prior = prior;
        self
    }

    /// Record the directories bx created on the way.
    ///
    /// Any order: [`Ledger::record`] deduplicates them and sorts them deepest
    /// first, on a first record exactly as on a re-record, and refuses one
    /// that is not an ancestor of the target.
    #[must_use]
    pub fn with_created_dirs(mut self, dirs: Vec<crate::paths::Portable>) -> Self {
        self.created_dirs = dirs;
        self
    }

    /// The entry for a staged write, assembled from what the writer knows.
    ///
    /// The write supplies the prior bytes and their mode, the digest of what it
    /// wrote, the mode it set, and the directories it invented. The caller
    /// supplies the two facts only it has: the home directory to make the paths
    /// portable against, and how bx attached to the file.
    ///
    /// Call it **before** [`Filled::publish`] and hand the result to
    /// [`Ledger::record`], which fsyncs the prior bytes into `restore/` before
    /// it returns. A crash after the rename is then recoverable, because the
    /// bytes that were displaced are already durable.
    ///
    /// # The entry is owed a withdrawal if the publish is refused
    ///
    /// That ordering is not a preference: the displaced bytes must be durable
    /// before anything can displace them, so the record has to precede a rename
    /// that may still fail. An entry recorded here therefore describes a write
    /// that has not happened yet, and [`Filled::publish`] can refuse — a
    /// destination changed after `stage` looked, a directory that cannot be
    /// opened, a `rename` out of space.
    ///
    /// So a caller that records an entry **must withdraw it when the publish is
    /// refused**, before it saves the ledger: take [`LedgerView::withdrawal`]
    /// for the entry's path before the `record`, and hand it to
    /// [`Ledger::withdraw`] on refusal. That puts back the entry as it was
    /// before the record — on a re-record, with the prior the user had before
    /// bx — rather than dropping the key, which [`Ledger::forget`] would do and
    /// which loses that prior. [`crate::fs::Unpublished`] names the destination
    /// the entry is keyed on, because `publish` consumes the `Filled`. A
    /// durable entry for a write that never landed makes `bx rm` restore the
    /// recorded prior over content bx never replaced, which is Invariant 4
    /// inverted.
    ///
    /// Pinned by
    /// `a_ledger_entry_for_a_refused_publish_is_withdrawn_through_what_the_refusal_names`
    /// for a first record, and by
    /// `a_refused_re_record_is_withdrawn_to_the_entry_it_replaced` for a
    /// re-record.
    ///
    /// # Errors
    ///
    /// [`crate::fs::Error::NotPortable`] if the destination or a created
    /// directory is not valid UTF-8, or `home` is not absolute: such a path has
    /// no key the ledger could record it under without naming a different file.
    ///
    /// Only tests call it: the shipped `apply` records an entry after its
    /// publish lands, through the journal, so it has nothing to withdraw.
    #[cfg(test)]
    pub fn for_write(
        filled: &Filled,
        home: &Path,
        mechanism: Mechanism,
    ) -> Result<Self, crate::fs::Error> {
        let portable = |path: &Path| {
            crate::paths::Portable::from_path(path, home).map_err(|source| {
                crate::fs::Error::NotPortable {
                    path: path.to_path_buf(),
                    source,
                }
            })
        };
        Ok(Self::new(
            portable(filled.dest())?,
            filled.written(),
            filled.mode(),
            mechanism,
            PriorBytes::of(filled.prior()),
        )
        .with_created_dirs(
            filled
                .created_dirs()
                .iter()
                .map(|dir| portable(dir))
                .collect::<Result<_, _>>()?,
        ))
    }
}

/// A target's entry as it was before a [`Ledger::record`], kept so that a
/// record whose write never landed can be undone with [`Ledger::withdraw`].
///
/// Taken by [`LedgerView::withdrawal`]. A record is made before the write it
/// describes is published, and the publish can still be refused; on a
/// re-record the entry it replaced holds the prior `bx rm` restores, so
/// undoing the record means putting that entry back, not dropping the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    /// The target the record is keyed on.
    pub(super) path: crate::paths::Portable,
    /// Its entry before the record, or `None` when it had none.
    pub(super) before: Option<LedgerEntry>,
}

/// Refuse a `created_dirs` entry that is not an ancestor of the target.
///
/// The ordering `merge_created_dirs` gives is by *depth*, and depth alone
/// orders the list only because every entry is an ancestor of one path. A
/// directory that is not would be sorted among them by a number that means
/// nothing about it, and `bx rm` would then try to remove, in that order, a
/// directory it never created for this target. The contract was documented
/// and checked nowhere.
pub(super) fn check_created_dirs(entry: &NewEntry) -> Result<(), Error> {
    match unrelated_created_dir(&entry.path, &entry.created_dirs) {
        None => Ok(()),
        Some(dir) => Err(Error::UnrelatedCreatedDir {
            target: entry.path.as_str().to_string(),
            dir,
        }),
    }
}

/// Whether `dir` is a lexical ancestor of `target`.
///
/// The one statement of the rule, so the refusal `record` gives on the way in
/// and the damage a load finds on the way out cannot disagree. Lexical, and it
/// may be: a [`crate::paths::Portable`] is normalised at construction and on
/// deserialisation, so no `..`, `.`, `//` or trailing slash reaches here. The
/// `'/'` test is what keeps `~/.config` from being read as an ancestor of
/// `~/.config.bak`, and a path is not its own ancestor.
pub(super) fn is_ancestor(dir: &crate::paths::Portable, target: &crate::paths::Portable) -> bool {
    let (dir, target) = (dir.as_str(), target.as_str());
    target.starts_with(dir) && target[dir.len()..].starts_with('/')
}

/// The first of `dirs` that is not an ancestor of `target`, if any.
fn unrelated_created_dir(
    target: &crate::paths::Portable,
    dirs: &[crate::paths::Portable],
) -> Option<String> {
    dirs.iter()
        .find(|dir| !is_ancestor(dir, target))
        .map(|dir| dir.as_str().to_string())
}

/// [`Error::PriorConflict`] when re-recording `existing` with `incoming` would
/// adopt a changed file bx shares through a region or an include line.
///
/// The one statement of the rule [`Ledger::record`] documents, so the check a
/// caller makes first and the refusal `record` gives cannot disagree.
///
/// A region whose own bytes are still the ones bx wrote is the exception: the
/// change is all outside it, and [`outside_region`] gives what the user has
/// there without bx's lines. So are a symlink bx made, whose displaced text is
/// the user's whole, and a region edited inside its markers
/// ([`inside_region`]), whose displaced bytes are the user's edit of it: both
/// are adopted whole, because `plan` writes over either only once the user
/// answered *take bx's* about it.
pub(super) fn prior_conflict(
    existing: &LedgerEntry,
    mechanism: &Mechanism,
    incoming: &PriorBytes,
) -> Result<(), Error> {
    let PriorBytes::Bytes { bytes, .. } = incoming else {
        return Ok(());
    };
    let digest = ContentHash::of(bytes);
    let whole = |shared: &Mechanism| matches!(shared, Mechanism::Own | Mechanism::Link);
    if digest != existing.written
        && !(existing.mechanism == *mechanism && whole(mechanism))
        && outside_region(existing, mechanism, bytes).is_none()
        && !inside_region(existing, mechanism, bytes)
    {
        return Err(Error::PriorConflict {
            target: existing.path.as_str().to_string(),
            displaced: digest,
        });
    }
    Ok(())
}

/// The digest of the region in `bytes` that an entry attached as `mechanism`
/// records: see [`LedgerEntry::region`].
#[must_use]
pub fn region_of(mechanism: &Mechanism, bytes: &[u8]) -> Option<ContentHash> {
    match mechanism {
        Mechanism::Region { comment } => crate::plan::region::digest(bytes, *comment),
        _ => None,
    }
}

/// `displaced` without bx's region, when every change in it since bx last
/// wrote `existing` lies outside that region: the bytes the user has there
/// now, which a re-record adopts as the prior so `bx rm` keeps their edit and
/// takes only bx's lines.
///
/// `None` — the change cannot be told apart from bx's own lines — unless both
/// the stored and the incoming mechanism are the same [`Mechanism::Region`],
/// the entry records its region's digest, and the region in `displaced` still
/// hashes to it.
pub(super) fn outside_region(
    existing: &LedgerEntry,
    mechanism: &Mechanism,
    displaced: &[u8],
) -> Option<Vec<u8>> {
    let Mechanism::Region { comment } = existing.mechanism else {
        return None;
    };
    let recorded = existing.region?;
    if *mechanism != existing.mechanism
        || crate::plan::region::digest(displaced, comment) != Some(recorded)
    {
        return None;
    }
    crate::plan::region::without(displaced, comment)
}

/// Whether `displaced` holds bx's region edited inside its markers since bx
/// last wrote `existing`: both the stored and the incoming mechanism are the
/// same [`Mechanism::Region`], the entry records its region's digest, and
/// `displaced` holds one whole region that no longer hashes to it.
///
/// `plan` reports such a file as a conflict and asks about it, and writes
/// over it only on an answer of *take bx's*, so the displaced bytes are the
/// user's edit, kept whole: `bx rm` puts back the file exactly as they had it,
/// their region text and its markers with it. A region entry with no digest
/// of its own cannot tell an edit inside from one beside, and a file with no
/// region or a damaged one holds no edit of bx's lines to keep: neither is
/// this.
pub(super) fn inside_region(
    existing: &LedgerEntry,
    mechanism: &Mechanism,
    displaced: &[u8],
) -> bool {
    let Mechanism::Region { comment } = existing.mechanism else {
        return false;
    };
    *mechanism == existing.mechanism
        && existing.region.is_some()
        && crate::plan::region::digest(displaced, comment)
            .is_some_and(|region| Some(region) != existing.region)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use serde::Deserialize;

    use crate::paths::Portable;
    use crate::state::dir::StateDir;
    use crate::state::ledger::fixtures::*;
    use crate::state::ledger::*;
    use crate::state::{Health, restore, store};
    use crate::testing::guarded_home;

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
            restore::read(&dir, reference).expect("restore"),
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
        assert_eq!(restore::read(&dir, reference).expect("restore"), body,);
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
            Mechanism::Dir,
            Mechanism::Link,
            Mechanism::Clone,
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
                PriorBytes::Absent,
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
    fn a_ledger_that_never_superseded_an_absent_prior_saves_as_it_did_before_the_field() {
        // `superseded_absent` came after the format. It is written only when
        // true, so every other ledger keeps its bytes (Invariant 3), and a
        // build that predates the field reads one where it is set.
        #[derive(Serialize, Deserialize)]
        struct Before {
            path: Portable,
            written: ContentHash,
            mode: Mode,
            mechanism: Mechanism,
            prior: Prior,
            created_dirs: Vec<Portable>,
            superseded: Vec<RestoreRef>,
        }
        #[derive(Serialize, Deserialize)]
        struct BeforeView {
            entries: BTreeMap<Portable, Before>,
        }
        #[derive(Deserialize)]
        struct BeforeEnvelope {
            payload: BeforeView,
        }
        let before = |ledger: &Ledger| BeforeView {
            entries: ledger
                .iter()
                .map(|(key, entry)| {
                    (
                        key.clone(),
                        Before {
                            path: entry.path.clone(),
                            written: entry.written,
                            mode: entry.mode,
                            mechanism: entry.mechanism.clone(),
                            prior: entry.prior.clone(),
                            created_dirs: entry.created_dirs.clone(),
                            superseded: entry.superseded.clone(),
                        },
                    )
                })
                .collect(),
        };

        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .record(entry("~/.ssh/config", b"v1").with_prior(prior(b"theirs", 0o640)))
            .expect("record");
        ledger
            .record(entry("~/.ssh/config", b"v2").with_prior(prior(b"edited", 0o644)))
            .expect("a user edit is superseded");
        ledger
            .record(entry("~/new", b"x"))
            .expect("an absent prior");
        ledger.save().expect("save");
        let now = std::fs::read(dir.ledger()).expect("read");

        let old_shape = dir.root().join("before.mpk");
        store::save(&old_shape, KIND, VERSION, &before(&ledger)).expect("save the old shape");
        assert_eq!(std::fs::read(&old_shape).expect("read"), now);
        let mut reopened = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        reopened.save().expect("save again");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), now);

        // Once set, the flag is written, and the old shape still decodes.
        ledger
            .record(entry("~/new", b"y").with_prior(prior(b"the user's own", 0o644)))
            .expect("the absent prior is superseded");
        ledger.save().expect("save");
        let flagged = std::fs::read(dir.ledger()).expect("read");
        assert_ne!(flagged, now);
        let old: BeforeEnvelope =
            rmp_serde::from_slice(&flagged).expect("an older build decodes it");
        assert_eq!(old.payload.entries.len(), 2);

        // `region` came after it, under the same rule: a region's digest is
        // written once a write records one, an older build still decodes the
        // ledger, and an entry without it reads back as having none.
        let region = Mechanism::Region { comment: '#' };
        let whole = b"mine\n# >>> bx >>>\nbx\n# <<< bx <<<\n";
        let mut with = entry("~/.zshrc", whole).with_region(whole);
        assert_eq!(with.region, None, "an `Own` entry has no region");
        with.mechanism = region.clone();
        ledger.record(with.with_region(whole)).expect("record");
        let mut without = entry("~/.bashrc", whole);
        without.mechanism = region;
        ledger.record(without).expect("record");
        ledger.save().expect("save");
        let old: BeforeEnvelope =
            rmp_serde::from_slice(&std::fs::read(dir.ledger()).expect("read"))
                .expect("an older build decodes it");
        assert_eq!(old.payload.entries.len(), 4);
        let reread = LedgerView::read(&dir, home.path()).expect("read").value;
        assert_eq!(
            reread.get(&target("~/.zshrc")).expect("entry").region,
            Some(ContentHash::of(b"# >>> bx >>>\nbx\n# <<< bx <<<\n"))
        );
        assert_eq!(
            reread.get(&target("~/.bashrc")).expect("entry").region,
            None
        );
    }

    #[test]
    fn a_kept_answer_is_remembered_until_the_next_record_and_an_older_build_ignores_it() {
        #[derive(Deserialize)]
        struct Before {
            written: ContentHash,
        }
        #[derive(Deserialize)]
        struct BeforeEnvelope {
            payload: BeforeView,
        }
        #[derive(Deserialize)]
        struct BeforeView {
            entries: BTreeMap<Portable, Before>,
        }
        let kept = Kept {
            found: ContentHash::of(b"edited"),
            found_mode: Some(Mode::DEFAULT_FILE),
            wanted: ContentHash::of(b"new"),
            mode: Mode::DEFAULT_FILE,
        };
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger.record(entry("~/.a", b"bx")).expect("record");
        ledger.save().expect("save");
        let without = std::fs::read(dir.ledger()).expect("read");

        assert!(
            !ledger.keep(&target("~/.b"), kept.clone()),
            "no entry, no question to remember"
        );
        assert!(ledger.keep(&target("~/.a"), kept.clone()));
        assert!(
            !ledger.keep(&target("~/.a"), kept.clone()),
            "the same answer again changes nothing"
        );
        ledger.save().expect("save");
        let with = std::fs::read(dir.ledger()).expect("read");
        assert_ne!(with, without, "the answer is written");

        // Reconstructible: a build that predates the field reads the ledger,
        // and what it loses is only the answer, so the question is put again.
        let old: BeforeEnvelope = rmp_serde::from_slice(&with).expect("an older build decodes it");
        assert_eq!(
            old.payload.entries[&target("~/.a")].written,
            ContentHash::of(b"bx")
        );
        let reread = LedgerView::read(&dir, home.path()).expect("read").value;
        assert_eq!(reread.get(&target("~/.a")).expect("entry").kept, Some(kept));

        // A write leaves bytes the answer was not about, and the ledger
        // saves as it did before any answer was given.
        ledger.record(entry("~/.a", b"bx")).expect("record again");
        assert_eq!(ledger.get(&target("~/.a")).expect("entry").kept, None);
        ledger.save().expect("save");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), without);
    }

    #[test]
    fn a_created_directory_that_is_not_an_ancestor_of_the_target_is_refused() {
        // The stored list is ordered by depth, and depth
        // alone orders it only because every entry is an ancestor of one path.
        // A directory that is not would be sorted among them by a number that
        // says nothing about it, and `bx rm` would try to remove it in that
        // order. This test is where that contract is checked.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        for stray in [
            // A sibling, and the prefix trap: `~/.config/tool` is a textual
            // prefix of `~/.config/tool.toml` and an ancestor of nothing.
            "~/.local/share",
            "~/.config/tool",
            // The target itself is not an ancestor of itself.
            "~/.config/tool.toml",
        ] {
            let new = entry("~/.config/tool.toml", b"x")
                .with_created_dirs(vec![target("~/.config"), target(stray)]);
            // The pre-check a journalled session makes and the refusal
            // `record` gives must agree.
            let checked = ledger.check_record(&new).expect_err("check refuses");
            let recorded = ledger.record(new).expect_err("record refuses");
            for err in [checked, recorded] {
                assert!(
                    matches!(&err, Error::UnrelatedCreatedDir { target: t, dir: d }
                        if t == "~/.config/tool.toml" && d == stray),
                    "got {err}",
                );
                assert!(err.to_string().contains("Nothing was recorded"), "{err}");
            }
            assert!(ledger.is_empty(), "nothing was recorded for {stray}");
        }
    }

    #[test]
    fn an_entry_without_created_dirs_still_loads() {
        // The `serde(default)` guarantee that justifies named encoding: a
        // ledger written before the field existed still loads.
        #[derive(Serialize, Deserialize)]
        struct Old {
            path: Portable,
            written: ContentHash,
            mode: Mode,
            mechanism: Mechanism,
            prior: Prior,
        }
        // `Deserialize` too, because `store::save` decodes its own bytes and
        // re-encodes them to establish the payload iterates deterministically.
        #[derive(Serialize, Deserialize)]
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
}
