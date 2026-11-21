//! `bx add` over a file bx manages that was edited on this machine: saving
//! the edit into the config repo, as `git add` stages a working-tree edit.
//!
//! # One decision, two callers
//!
//! `decide` is the only place a save is decided. `bx add` calls it for a
//! declared file whose bytes or mode differ from what the repo declares, and
//! `bx apply`'s question about an edited file calls it to tell whether *save
//! mine to the repo* (or *merge*) can be offered, and carries out exactly the
//! [`Save`] it returned. Nothing is decided at the moment of writing: the
//! bytes shown are the bytes written (Invariant 7).
//!
//! # What is saved, and where
//!
//! A save needs the ledger to prove what bx last wrote there
//! ([`LedgerEntry::written`]), so the two sides can be told apart:
//!
//! * **Only the machine changed.** The edit is written into the declared
//!   body: a `file = "…"` body is the repo file, replaced atomically; an
//!   inline `content = "…"` is edited in the layer that declares it, through
//!   the same stamped layer write `add` and `rm` make, so a layer an editor
//!   saved meanwhile is refused and kept. A mode the user set is written as
//!   the target's `mode`.
//! * **Both changed.** The base is the copy `apply` kept of what it last
//!   wrote (`state::restore::kept`), and the user's own `git merge-file`
//!   merges the edit with the repo's change. A clean merge is written to the
//!   repo body and to the machine file, whose bytes the user wrote: that is
//!   done only on their confirmation, through a journalled session, so the
//!   ledger keeps them for `bx rm`. A conflicted merge writes nothing to the
//!   repo; confirmed, it writes the conflict-marked result to the machine
//!   file, through the same session, for them to resolve and `bx add`
//!   again. Every line of theirs is in it, between the markers or merged,
//!   and since it is not bx's last write, `bx rm` leaves it untouched as a
//!   conflict, as it leaves any edited file. With no base kept — a secret, a file over the bound
//!   bases are kept under — there is nothing to merge from, and the save is
//!   refused.
//!
//! The ledger is then recorded as if bx had written the saved bytes, so the
//! next `plan` is empty; a conflicted merge's entry keeps what bx last wrote,
//! so the marked file stays an edit `plan` asks about and no `apply` writes
//! over it unasked.
//!
//! # Refused
//!
//! A secret (its declared bytes are ciphertext, and a plaintext never enters
//! the repo), a generated body (bx writes it, nobody edits its source), a
//! region or an include line (part of a file), a tracked target (`bx sync`
//! already carries it), an inline content with a `{{name}}` bx substituted
//! (saving it would write this account's answer over the placeholder), an
//! inline content the edit is not UTF-8 for, a repo file another target
//! also delivers, since saving into it would change those too, and a repo
//! file holding changes git has not committed that no save of bx's left
//! there: saving would overwrite the user's work in a body file, and
//! `bx sync` commits a saved file whole, so the commit would carry bytes no
//! diff showed.

use std::path::{Path, PathBuf};

use toml_edit::{Document, Item};

use super::{declared_path, open_layer};
use crate::config::resolve::Resolution;
use crate::config::target::{Attach, Body, Direction, Format, Target};
use crate::config::values::ResolvedValues;
use crate::fs::{self, Kind, Mode, Observed};
use crate::git::{self, Git};
use crate::journal::{Content, Ownership, Request, Session, SessionKind};
use crate::paths::{self, Portable};
use crate::state::{
    self, ContentHash, ExclusiveLock, LedgerEntry, Mechanism, NewEntry, PriorBytes, StateDir,
};

#[cfg(test)]
mod tests;

/// The largest base `apply` keeps of a file it wrote, as a length on disk:
/// the bound its three-way view is read back under.
const BASE_LIMIT: u64 = 64 * 1024;

/// Labels `git merge-file` writes into a conflict's markers, in the order it
/// takes the three files: this machine's, the base, the repo's.
const LABELS: [&str; 3] = ["yours", "bx last wrote", "the repo"];

/// What [`decide`] needs besides the target and its two sides.
pub(crate) struct Sides<'a> {
    /// The account's home.
    pub home: &'a Path,
    /// The config repo.
    pub repo: &'a Path,
    /// The state directory, where `apply` kept the base of each file.
    pub state: &'a StateDir,
    /// The user's own `git`, which merges.
    pub git: &'a Git,
    /// The values a layer's `{{name}}` paths resolve against.
    pub values: &'a ResolvedValues,
    /// Every resolved target, to find another that shares a body file.
    pub targets: &'a [Resolution<Target>],
}

/// How a save settles the two sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// Only this machine changed: its file is written into the repo.
    Save,
    /// Both changed, and merged cleanly: the merge is written to both.
    Merged,
    /// Both changed, and the merge conflicts: the conflict-marked result is
    /// written to the machine file only, for the user to resolve.
    Conflicted,
}

/// A file in the repo a save rewrites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoWrite {
    /// The file.
    pub(crate) path: PathBuf,
    /// What was there when the save was decided, which the write is stamped
    /// against.
    read: Observed,
    /// What is written: for a layer, the edit is made again against the text
    /// it holds then, which must still be `read`.
    edit: Edit,
}

/// What is written to one repo file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Edit {
    /// A body file, replaced whole, at this mode.
    File(Vec<u8>, Mode),
    /// A layer, with the target's `[[target]]` table given this content
    /// and this mode where they are set, and left otherwise.
    Layer {
        /// The layer's new text.
        text: String,
    },
}

/// What saving one edited file does, decided by `decide`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Save {
    /// The target.
    pub target: Portable,
    /// How the two sides are settled.
    pub how: How,
    /// The repo files it rewrites: a body file, a layer, or both. Empty for
    /// a conflicted merge.
    pub(crate) repo: Vec<RepoWrite>,
    /// What the machine file holds afterwards, and what bx records it wrote.
    pub(crate) bytes: Vec<u8>,
    /// Its mode afterwards.
    pub(crate) mode: Mode,
    /// What was on the machine when the save was decided: what a merge's
    /// write is staged against, and what a save records as the file `bx rm`
    /// gives back.
    pub(crate) observed: Observed,
    /// What bx last wrote there, and the mode it set, which a conflicted
    /// merge's entry keeps.
    pub(crate) base: (ContentHash, Mode),
    /// The diffs to show before it is confirmed: each repo file, then the
    /// machine file for a merge.
    pub diffs: Vec<String>,
}

impl Save {
    /// Whether carrying it out writes the machine file: a merge.
    #[must_use]
    pub const fn writes_machine(&self) -> bool {
        matches!(self.how, How::Merged | How::Conflicted)
    }

    /// What was on the machine when the save was decided.
    pub(crate) const fn observed(&self) -> &Observed {
        &self.observed
    }

    /// Each repo file it rewrites, as a person reads it.
    #[must_use]
    pub fn repo_files(&self, home: &Path) -> Vec<String> {
        self.repo
            .iter()
            .map(|write| shown(&write.path, home))
            .collect()
    }

    /// The ledger record a save that leaves the machine file as it is makes:
    /// bx owns the bytes there now, which the repo holds too.
    ///
    /// The prior is those bytes, as `add` records a file it adopts: bx wrote
    /// nothing here, and `bx rm` must hand back the file the user left. They
    /// are not what bx last wrote, so the ledger keeps them as the prior and
    /// moves the one it held to its history (see
    /// [`crate::state::Ledger::record`]).
    pub(crate) fn record(&self) -> NewEntry {
        NewEntry::new(
            self.target.clone(),
            ContentHash::of(&self.bytes),
            self.mode,
            Mechanism::Own,
            PriorBytes::Bytes {
                bytes: self.bytes.clone(),
                mode: self.observed.mode.unwrap_or(self.mode),
            },
        )
    }

    /// The journal request that writes a merge to the machine file, staged
    /// against the file as it was when the merge was decided.
    fn request(&self, home: &Path) -> Request {
        Request {
            target: self.target.clone(),
            dest: self.target.render(home),
            content: Content::Bytes {
                bytes: self.bytes.clone(),
                planned: self.observed.clone(),
            },
            mode: self.mode,
            ownership: Ownership::Owned(Mechanism::Own),
        }
    }
}

/// Write each merge in `saves` to its machine file, through one journalled
/// session under `lock`, and keep what each save leaves there as the base a
/// later edit is merged from.
///
/// The session keeps the bytes each write displaces, the user's own, as the
/// prior `bx rm` restores. A conflicted merge's entry is recorded at what bx
/// last wrote in that same session, saved with its write under the one lock,
/// so the marked file is an edit `plan` asks about rather than bytes of bx's
/// an `apply` would replace.
///
/// # Errors
///
/// What the session, the lock and the ledger return. Keeping a base is best
/// effort: losing one costs only a later merge.
pub(crate) fn write_machines(
    state: &StateDir,
    home: &Path,
    lock: ExclusiveLock,
    saves: &[&Save],
) -> Result<(), super::Error> {
    let merges: Vec<&&Save> = saves.iter().filter(|save| save.writes_machine()).collect();
    if merges.is_empty() {
        drop(lock);
    } else {
        let scope = merges.iter().map(|save| save.target.clone()).collect();
        let mut session = Session::open_locked(state, SessionKind::Apply, home, scope, lock)?;
        for save in &merges {
            session.apply(save.request(home))?;
        }
        // In the same session, so the ledger is saved once, under the one
        // lock, never claiming the marked file as bx's.
        for save in merges.iter().filter(|save| save.how == How::Conflicted) {
            let (written, mode) = save.base;
            session.record(NewEntry::new(
                save.target.clone(),
                written,
                mode,
                Mechanism::Own,
                // Kept: the write already took the user's bytes as the
                // prior, and an absent prior never replaces a stored one.
                PriorBytes::Absent,
            ))?;
        }
        session.finish()?;
    }
    keep_bases(state, saves);
    Ok(())
}

/// Keep what each save in `saves` leaves on the machine as the base a later
/// edit of it is merged from, as `apply` keeps what it writes. Best effort:
/// losing one costs only a later merge. A conflicted merge keeps none: what
/// bx last wrote stays the base.
pub(crate) fn keep_bases(state: &StateDir, saves: &[&Save]) {
    for save in saves.iter().filter(|save| save.how != How::Conflicted) {
        if save.bytes.len() as u64 <= BASE_LIMIT
            && let Err(error) = state::restore::keep(state, &save.bytes)
        {
            tracing::warn!(%error, "the bytes bx saved were not kept as a base");
        }
    }
}

/// What `decide` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The edit can be saved, as this says.
    Save(Box<Save>),
    /// It cannot, for this reason.
    Refused(String),
}

/// Decide what saving `target`'s file on this machine into the repo does.
///
/// `entry` is the ledger's record of what bx last left there, `observed` the
/// file now, and `wanted` the bytes the repo declares. Reads the repo body,
/// the layer and the kept base, and runs `git merge-file` in a scratch
/// directory under the state directory when both sides changed; writes
/// nothing else.
pub(crate) fn decide(
    sides: &Sides<'_>,
    target: &Target,
    entry: &LedgerEntry,
    observed: &Observed,
    wanted: &[u8],
) -> Decision {
    match decided(sides, target, entry, observed, wanted) {
        Ok(save) => Decision::Save(Box::new(save)),
        Err(why) => Decision::Refused(why),
    }
}

/// [`decide`], refusing with the reason.
fn decided(
    sides: &Sides<'_>,
    target: &Target,
    entry: &LedgerEntry,
    observed: &Observed,
    wanted: &[u8],
) -> Result<Save, String> {
    let origin = &target.origin;
    shape(target)?;
    if entry.mechanism != Mechanism::Own {
        return Err(format!(
            "is already declared at {origin}, and differs from what it declares; `bx plan` \
             shows how"
        ));
    }
    let (Kind::File, Some(disk), Some(disk_mode)) =
        (observed.kind, observed.bytes.as_deref(), observed.mode)
    else {
        return Err("is not a regular file bx can save".to_string());
    };
    let declared_mode = Mode::resolve(target.mode, Kind::File);
    let disk_moved = ContentHash::of(disk) != entry.written;
    let repo_moved = ContentHash::of(wanted) != entry.written;
    let mode_moved = disk_mode != entry.mode;
    if !disk_moved && !mode_moved {
        return Err(format!(
            "is as bx last wrote it, and the repo has changed since; `bx apply` takes the \
             repo's (declared at {origin})"
        ));
    }
    // The mode the user set wins where they set one: they confirm it.
    let mode = if mode_moved { disk_mode } else { declared_mode };
    // A save leaves the machine file as it is, so what bx records it wrote
    // is what is there; only a merge writes it.
    let (how, bytes) = if !disk_moved || disk == wanted || !repo_moved {
        (How::Save, disk.to_vec())
    } else {
        merged(sides, entry, disk, wanted)?
    };
    let mut repo = Vec::new();
    let mut diffs = Vec::new();
    if how != How::Conflicted {
        // Bytes that are still what bx last wrote are not an edit to save,
        // even where the repo has moved on from them.
        let content = (disk_moved && bytes != wanted).then_some(bytes.as_slice());
        let new_mode = (mode != declared_mode).then_some(mode);
        let (file, layer) = repo_writes(sides, target, content, new_mode)?;
        for write in file.into_iter().chain(layer) {
            uncommitted(sides, &write)?;
            diffs.push(write.diff(sides.home));
            repo.push(write);
        }
    }
    if how != How::Save {
        diffs.push(unified(
            target.path.as_str(),
            ("on disk", "merged"),
            disk,
            &bytes,
        ));
    }
    Ok(Save {
        target: target.path.clone(),
        how,
        repo,
        bytes,
        mode,
        observed: observed.clone(),
        base: (entry.written, entry.mode),
        diffs,
    })
}

/// Why a declared target's shape is one bx does not save into, when it is.
fn shape(target: &Target) -> Result<(), String> {
    let origin = &target.origin;
    if target.direction == Direction::Track {
        return Err(format!(
            "is already declared at {origin} as tracked; bx sync carries it into the repo"
        ));
    }
    if !matches!(
        (&target.attach, &target.format),
        (Attach::Own, Format::Opaque)
    ) {
        return Err(format!(
            "is already declared at {origin} as part of a file; bx add saves whole files"
        ));
    }
    match &target.body {
        Body::File(_) | Body::Inline(_) => Ok(()),
        Body::Secret(_) => Err(format!(
            "is declared at {origin} as a secret; a plaintext never enters the repo, so bx \
             add will not save it there. Encrypt it again with age and replace the ciphertext"
        )),
        Body::Generated(_) => Err(format!(
            "is generated by bx from what {origin} declares; change that declaration rather \
             than the file"
        )),
        Body::Dir | Body::Symlink(_) => Err(format!(
            "is already declared at {origin} with a body bx add does not save into"
        )),
    }
}

/// Merge the edit on this machine with the repo's change, from the base
/// `apply` kept of what it last wrote.
fn merged(
    sides: &Sides<'_>,
    entry: &LedgerEntry,
    disk: &[u8],
    wanted: &[u8],
) -> Result<(How, Vec<u8>), String> {
    let Some(base) = state::restore::kept(sides.state, entry.written, BASE_LIMIT) else {
        return Err(
            "was edited here and changed in the repo, and bx kept no copy of what it last \
             wrote to merge the two from (it keeps none of a secret or of a file over 64 KiB); \
             `bx plan` shows both sides"
                .to_string(),
        );
    };
    merge_file(sides.git, sides.state, disk, &base, wanted)
}

/// `git merge-file` of `ours` and `theirs` from `base`, in a scratch
/// directory under the state directory, which is private to the account.
///
/// Its exit status is the number of conflicts, and anything it cannot merge
/// — a binary file above all — is a refusal naming what git said.
fn merge_file(
    git: &Git,
    state: &StateDir,
    ours: &[u8],
    base: &[u8],
    theirs: &[u8],
) -> Result<(How, Vec<u8>), String> {
    let failed = |why: String| format!("could not be merged: {why}");
    state.ensure().map_err(|e| failed(e.to_string()))?;
    let scratch = tempfile::Builder::new()
        .prefix(".bx-merge-")
        .tempdir_in(state.root())
        .map_err(|e| failed(e.to_string()))?;
    let dir = scratch.path();
    for (name, bytes) in [("yours", ours), ("base", base), ("repo", theirs)] {
        std::fs::write(dir.join(name), bytes).map_err(|e| failed(e.to_string()))?;
    }
    let args = [
        "merge-file",
        "-L",
        LABELS[0],
        "-L",
        LABELS[1],
        "-L",
        LABELS[2],
        "yours",
        "base",
        "repo",
    ];
    let how = match git.query(dir, &args) {
        Ok(_) => How::Merged,
        Err(git::Error::Failed { status, .. })
            if status.code().is_some_and(|code| (1..=127).contains(&code)) =>
        {
            How::Conflicted
        }
        Err(git::Error::Failed { stderr, .. }) => return Err(failed(stderr.trim().to_string())),
        Err(other) => return Err(failed(other.to_string())),
    };
    let result = std::fs::read(dir.join("yours")).map_err(|e| failed(e.to_string()))?;
    Ok((how, result))
}

/// The repo writes that make the declared body hold `content` and declare
/// `mode`, each `None` where it already does: the body file, then the layer.
fn repo_writes(
    sides: &Sides<'_>,
    target: &Target,
    content: Option<&[u8]>,
    mode: Option<Mode>,
) -> Result<(Option<RepoWrite>, Option<RepoWrite>), String> {
    let (file, inline) = match (&target.body, content) {
        (Body::File(rel), Some(bytes)) => {
            (Some(body_write(sides, target, rel, bytes, mode)?), None)
        }
        (Body::Inline(resolved), Some(bytes)) => {
            let text = std::str::from_utf8(bytes).map_err(|_| {
                format!(
                    "is not UTF-8 text, which the inline content at {} cannot hold; declare \
                     it with a `file` body to save it",
                    target.origin
                )
            })?;
            (None, Some((resolved.as_str(), text)))
        }
        _ => (None, None),
    };
    let layer = if inline.is_some() || mode.is_some() {
        layer_write(sides, target, inline, mode)?
    } else {
        None
    };
    Ok((file, layer))
}

/// Refuse `write` where its file holds a change git has not committed that
/// no save of bx's left there: the user's own work in the repo. Saving over
/// a body file would lose it, and `bx sync` commits a saved file whole, so
/// either way bytes the user never saw shown would leave under bx's commit.
///
/// A file git does not answer for — a repo that is not a git checkout, or a
/// `git` that cannot run — is not refused: nothing commits it there.
fn uncommitted(sides: &Sides<'_>, write: &RepoWrite) -> Result<(), String> {
    let Some(path) = write.path.to_str() else {
        return Ok(());
    };
    let args = [
        "status",
        "--porcelain",
        "-z",
        "--untracked-files=all",
        "--",
        path,
    ];
    let Ok(status) = sides.git.query_whole(sides.repo, &args) else {
        return Ok(());
    };
    let now = write.read.bytes.as_deref().unwrap_or_default();
    if status.is_empty() || crate::sync::saved_holds(sides.state, sides.repo, &write.path, now) {
        return Ok(());
    }
    let file = shown(&write.path, sides.home);
    Err(format!(
        "would be saved into {file}, which holds changes git has not committed; commit or \
         discard them first, so the commit bx sync makes holds only the save"
    ))
}

/// The write that replaces the repo file `rel` with `bytes`.
fn body_write(
    sides: &Sides<'_>,
    target: &Target,
    rel: &Path,
    bytes: &[u8],
    mode: Option<Mode>,
) -> Result<RepoWrite, String> {
    let path = sides.repo.join(rel);
    let normal = paths::normalize(&path);
    let shared: Vec<&str> = sides
        .targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(other) if other.path != target.path => Some(other),
            _ => None,
        })
        .filter(|other| match &other.body {
            Body::File(theirs) | Body::Secret(theirs) => {
                paths::normalize(&sides.repo.join(theirs)) == normal
            }
            _ => false,
        })
        .map(|other| other.path.as_str())
        .collect();
    if !shared.is_empty() {
        return Err(format!(
            "has its body in {}, which {} also deliver(s); saving into it would change those \
             too, so give this target a body of its own",
            rel.display(),
            shared.join(", ")
        ));
    }
    let read = fs::observe(&path).map_err(|e| e.to_string())?;
    if read.kind != Kind::File {
        return Err(format!(
            "has its body in {}, which is {}, not a file bx can save into",
            rel.display(),
            read.kind
        ));
    }
    // At the mode the user set, as `add` adopts a file at its own, so a
    // private file is not readable by other accounts while it sits in the
    // repo; otherwise the copy keeps the mode it has.
    let mode = mode
        .or(read.mode)
        .unwrap_or(Mode::resolve(target.mode, Kind::File));
    Ok(RepoWrite {
        path,
        read,
        edit: Edit::File(bytes.to_vec(), mode),
    })
}

/// The write that edits the layer declaring `target`: its inline content
/// from `resolved` to the new text, its mode to `mode`.
fn layer_write(
    sides: &Sides<'_>,
    target: &Target,
    content: Option<(&str, &str)>,
    mode: Option<Mode>,
) -> Result<Option<RepoWrite>, String> {
    let path = target.origin.file.clone();
    let opened = open_layer(&path).map_err(|e| e.to_string())?;
    let text = edit_layer(sides, target, &opened.text, content, mode)?;
    Ok(Some(RepoWrite {
        path,
        read: opened.read,
        edit: Edit::Layer { text },
    }))
}

/// `text` with the `[[target]]` table declaring `target` given the new
/// content and mode, every other byte as it was.
///
/// Edited as text at the spans the parse gives, as `rm` undeclares a table,
/// so nothing else in the layer is re-serialised. The result is parsed back
/// as the loader parses it, and refused unless it declares exactly the
/// content and mode asked for.
fn edit_layer(
    sides: &Sides<'_>,
    target: &Target,
    text: &str,
    content: Option<(&str, &str)>,
    mode: Option<Mode>,
) -> Result<String, String> {
    let file = &target.origin.file;
    let shown_file = shown(file, sides.home);
    let doc = Document::parse(text.to_string()).map_err(|e| format!("{shown_file}: {e}"))?;
    let table = doc
        .get("target")
        .and_then(Item::as_array_of_tables)
        .and_then(|tables| {
            tables
                .iter()
                .find(|table| declared_path(table, sides.values).is_some_and(|p| p == target.path))
        })
        .ok_or_else(|| {
            format!("has no `[[target]]` table in {shown_file} that bx can edit to save it")
        })?;
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    if let Some((resolved, new)) = content {
        let item = table.get("content");
        if item.and_then(Item::as_str) != Some(resolved) {
            return Err(format!(
                "has an inline content at {} with a `{{{{name}}}}` bx substituted; saving \
                 would write this account's answer over it, so edit it there",
                target.origin
            ));
        }
        let span = item.and_then(Item::span).ok_or_else(|| {
            format!("has an inline content in {shown_file} that bx cannot locate")
        })?;
        edits.push((span, toml_string(new)));
    }
    if let Some(mode) = mode {
        let repr = toml_string(&mode.to_string());
        match table.get("mode").and_then(Item::span) {
            Some(span) => edits.push((span, repr)),
            None => {
                let last = table
                    .iter()
                    .filter_map(|(_, item)| item.span())
                    .map(|span| span.end)
                    .max()
                    .ok_or_else(|| {
                        format!("has a `[[target]]` table in {shown_file} that bx cannot locate")
                    })?;
                let end = text[last..]
                    .find('\n')
                    .map_or(text.len(), |at| last + at + 1);
                let lead = if text[..end].ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                edits.push((end..end, format!("{lead}mode = {repr}\n")));
            }
        }
    }
    edits.sort_by_key(|(span, _)| std::cmp::Reverse(span.start));
    let mut edited = text.to_string();
    for (span, with) in edits {
        edited.replace_range(span, &with);
    }
    let parsed = crate::config::parse_str(&edited, file, sides.home)
        .map_err(|e| format!("bx's edit of {shown_file} would not load, so it is not made: {e}"))?;
    let landed = parsed
        .targets
        .iter()
        .find(|t| resolved_raw(t, sides.values) == Some(target.path.clone()));
    let holds = landed.is_some_and(|t| {
        content.is_none_or(|(_, new)| t.body == Body::Inline(new.to_string()))
            && mode.is_none_or(|mode| t.mode == Some(mode))
    });
    if !holds {
        return Err(format!(
            "could not be saved into {shown_file}: bx's edit did not declare what it saves"
        ));
    }
    Ok(edited)
}

/// The path a parsed target names once its values are substituted.
fn resolved_raw(target: &Target, values: &ResolvedValues) -> Option<Portable> {
    super::resolved_path(target.path.as_str(), values)
}

/// `text` as a TOML string, the form `toml_edit` writes it in.
fn toml_string(text: &str) -> String {
    toml_edit::Value::from(text).decorated("", "").to_string()
}

impl RepoWrite {
    /// What this write changes, as a diff.
    fn diff(&self, home: &Path) -> String {
        let name = shown(&self.path, home);
        let before = self.read.bytes.as_deref().unwrap_or_default();
        match &self.edit {
            Edit::File(bytes, _) => unified(&name, ("in the repo", "saved"), before, bytes),
            Edit::Layer { text } => {
                unified(&name, ("in the repo", "saved"), before, text.as_bytes())
            }
        }
    }

    /// The file, and the digest of the bytes the write leaves: what
    /// `bx sync` commits ([`crate::sync::remember_saved`]).
    pub(crate) fn written(&self) -> (PathBuf, ContentHash) {
        let digest = match &self.edit {
            Edit::File(bytes, _) => ContentHash::of(bytes),
            Edit::Layer { text } => ContentHash::of(text.as_bytes()),
        };
        (self.path.clone(), digest)
    }

    /// Make this write, unless the file changed since the save was decided.
    ///
    /// # Errors
    ///
    /// [`super::Error::Layer`] naming the file when it changed since, with
    /// nothing written, and otherwise what the write returns.
    pub(crate) fn write(&self) -> Result<(), super::Error> {
        self.put().map_err(|error| match error {
            fs::Error::Changed { .. } => super::Error::Layer {
                path: self.path.clone(),
                why: "changed after bx read it, so bx's edit was not made and the file is as it \
                      was saved; run the command again"
                    .to_string(),
            },
            error => super::Error::from(error),
        })
    }

    /// [`RepoWrite::write`], failing with what the write returns: for a file
    /// changed since, [`fs::Error::Changed`], with nothing written. A layer's
    /// text was parsed back as the loader parses it when the save was
    /// decided, so what is written is a layer that loads.
    ///
    /// # Errors
    ///
    /// What [`fs::write_over`] returns.
    pub(crate) fn put(&self) -> Result<(), fs::Error> {
        let (bytes, mode) = match &self.edit {
            Edit::File(bytes, mode) => (bytes.as_slice(), *mode),
            Edit::Layer { text } => (
                text.as_bytes(),
                self.read.mode.unwrap_or(Mode::DEFAULT_FILE),
            ),
        };
        fs::write_over(&self.read, bytes, mode)
    }
}

/// A path as a person reads it: `~`-relative inside the home.
fn shown(path: &Path, home: &Path) -> String {
    Portable::from_path(path, home).map_or_else(|_| path.display().to_string(), |p| p.to_string())
}

/// A unified diff of `old` against `new`, or a line saying how their sizes
/// differ where either is not text.
fn unified(name: &str, labels: (&str, &str), old: &[u8], new: &[u8]) -> String {
    match (std::str::from_utf8(old), std::str::from_utf8(new)) {
        (Ok(old), Ok(new)) => crate::plan::unified(name, labels, old, new),
        _ => format!(
            "{name}: binary, {} byte(s) {} {} byte(s) {}\n",
            old.len(),
            labels.0,
            new.len(),
            labels.1
        ),
    }
}
