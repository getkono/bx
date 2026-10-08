//! One decision per target: the only code that turns configuration into work.
//!
//! [`decide`] reads the target's body, observes its destination, compares the
//! two with [`crate::fs::compare`], and consults the ledger for ownership. It
//! is handed shared references only and knows nothing of the mode it runs in,
//! so `plan` and `apply` cannot reach different verdicts from one input.
//!
//! An [`Op`] is the write a decision produced. Its fields are private to this
//! module, so no other code can make one, and it carries the observation and
//! the bytes the decision was made on: what `apply` writes is what `plan`
//! diffed.
//!
//! [`decide_all`] decides a whole configuration. Directory targets go first,
//! shallowest first, and their writes are made first, so a file is decided
//! against — and published into — a directory already at the mode its target
//! declares, whichever order the two were declared in.
//!
//! The submodules hold what a decision consults: [`parent`] whether `apply`
//! can write inside the directory a destination is in, [`dir`] and [`link`]
//! the decisions for directory and symlink targets, [`guard`] Invariant 2's
//! judgement of a generated body, and [`undeclared`] the row for a file bx
//! wrote that nothing declares any more.

mod dir;
mod guard;
mod link;
mod parent;
mod undeclared;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use self::dir::decide_dir;
#[cfg(test)]
pub(super) use self::guard::guard_fragment;
use self::guard::guard_generated;
use self::link::decide_link;
use self::parent::{Write, created_dirs, locked_parent, parent_note};
pub(super) use self::undeclared::decide_undeclared;
use super::track::{Agreed, Base, Bases, When};
use super::{Change, Diff, Error, region};
use crate::config::resolve::Resolution;
use crate::config::secrets::Secrets;
use crate::config::target::{Attach, Body, Direction, Format, Target};
use crate::env_guard::RootSet;
use crate::fs::{self, Desired, Kind, Mode, Observed};
use crate::journal::{Content, Ownership, Request};
use crate::paths::{self, Portable};
use crate::report::Action;
use crate::shell::activation::{self, Host as _};
use crate::state::{LedgerEntry, LedgerView, Mechanism};

/// What a decision may read: nothing it could change.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ctx<'a> {
    /// The ledger, as it was read once for the whole run.
    pub ledger: &'a LedgerView,
    /// The account's home, which every target path renders against.
    pub home: &'a Path,
    /// The config repo, which a `file` body is read from.
    pub repo: &'a Path,
    /// The roots a generated environment fragment is judged against.
    pub roots: &'a RootSet,
    /// The `[secrets]` table, which names the identity a secret is decrypted
    /// with.
    pub secrets: &'a Secrets,
    /// The directories decided so far that apply leaves at a declared mode.
    pub declared: &'a Declared,
    /// The bytes each tracked target's two sides last agreed on.
    pub bases: &'a Bases,
    /// The machine a generated file's `has:TOOL` condition looks the tool up
    /// on: the `PATH` [`super::Inputs::load`] read once.
    pub host: &'a activation::System,
}

/// The directories whose targets apply leaves at a declared mode — created,
/// set to it, or already there at it — each with that mode, keyed by the
/// destination as [`crate::fs::observe`] spells it.
///
/// Every write `apply` makes to a directory runs before any write to a file,
/// so this is the mode a file beneath one will meet, whatever is on disk while
/// `plan` looks.
pub(super) type Declared = BTreeMap<PathBuf, Mode>;

/// Everything [`decide_all`] decided.
#[derive(Debug)]
pub(super) struct Decided {
    /// One row per target, in configuration order.
    pub changes: Vec<Change>,
    /// The writes, in the order `apply` makes them: every directory first,
    /// shallowest first, then every file in configuration order.
    pub ops: Vec<Op>,
    /// The writes only `sync` makes, after every one of [`Decided::ops`]:
    /// each tracked target's copy on this machine carried into the repo, in
    /// configuration order.
    pub carries: Vec<Op>,
    /// What each tracked target's two sides will agree on, in configuration
    /// order.
    pub agreed: Vec<Agreed>,
    /// The directories the session is to declare before its first write.
    pub declared: Declared,
}

/// Decide every target of a configuration.
///
/// Directory targets are decided first, shallowest first, each against the
/// directories above it already decided, and the rest after them in
/// configuration order. A directory apply will leave at its declared mode is
/// entered in [`Ctx::declared`], so a later decision reads the mode `apply`
/// will have left rather than the one on disk now. That is what lets a file
/// declared before its directory be decided, and written, exactly as one
/// declared after it.
///
/// # Errors
///
/// As [`decide`].
pub(super) fn decide_all(
    resolutions: &[Resolution<Target>],
    ctx: &Ctx<'_>,
) -> Result<Decided, Error> {
    let mut declared = Declared::new();
    let mut rows: Vec<Option<Change>> = vec![None; resolutions.len()];
    let mut dirs: Vec<(usize, &Target)> = resolutions
        .iter()
        .enumerate()
        .filter_map(|(at, resolution)| match resolution {
            Resolution::Ready(target) if target.body == Body::Dir => Some((at, target)),
            _ => None,
        })
        .collect();
    dirs.sort_by(|(_, a), (_, b)| {
        let depth = |target: &Target| target.path.render(ctx.home).components().count();
        depth(a)
            .cmp(&depth(b))
            .then_with(|| a.path.as_str().cmp(b.path.as_str()))
    });

    let mut ops = Vec::new();
    for (at, target) in dirs {
        let (change, op) = decide(
            &resolutions[at],
            &Ctx {
                declared: &declared,
                ..*ctx
            },
        )?;
        if matches!(
            change.action,
            Action::Create | Action::Modify | Action::Unchanged
        ) {
            declared.insert(
                target.path.render(ctx.home).components().collect(),
                Mode::resolve(target.mode, Kind::Dir),
            );
        }
        rows[at] = Some(change);
        ops.extend(op);
    }

    let files = Ctx {
        declared: &declared,
        ..*ctx
    };
    let mut carries = Vec::new();
    let mut agreed = Vec::new();
    for (at, resolution) in resolutions.iter().enumerate() {
        if rows[at].is_some() {
            continue;
        }
        if let Resolution::Ready(target) = resolution
            && target.direction == Direction::Track
        {
            let (change, op, agreement) = decide_track(target, &files)?;
            rows[at] = Some(change);
            match op {
                Some(op) if op.carry => carries.push(op),
                op => ops.extend(op),
            }
            agreed.extend(agreement);
            continue;
        }
        let (change, op) = decide(resolution, &files)?;
        rows[at] = Some(change);
        ops.extend(op);
    }
    Ok(Decided {
        changes: rows.into_iter().flatten().collect(),
        ops,
        carries,
        agreed,
        declared,
    })
}

/// One write a decision produced.
///
/// A mode-only change is an `Op` too: the same bytes rewritten at the new
/// mode, journalled like any other write, so `rm` can put the old mode back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Op {
    target: Portable,
    dest: PathBuf,
    made: Made,
    planned: Observed,
    mode: Mode,
    /// Whether bx owns what it leaves. Every write does but one: the repo's
    /// copy of a tracked target written over a copy this machine already had
    /// and bx never claimed, which stays the tool's — journalled like any
    /// write, so an interruption is rolled back, and recorded in no ledger
    /// entry, so `rm` never touches it. See [`track_onto_machine`].
    claimed: bool,
    /// Whether this is a tracked target's copy on this machine carried into
    /// the repo, which only `sync` writes.
    carry: bool,
}

/// What an [`Op`] leaves at its destination.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Made {
    /// A file holding these bytes, owned whole.
    Bytes(Vec<u8>),
    /// A file holding these bytes, whole, of which bx owns the one region
    /// delimited with this comment character.
    Region(Vec<u8>, char),
    /// A directory, created or set to the op's mode.
    Dir,
    /// A symlink holding this text, made or retargeted.
    Link(PathBuf),
}

impl Op {
    /// The target the write is for.
    pub(super) const fn target(&self) -> &Portable {
        &self.target
    }

    /// The journal request that makes this write: bx owning the whole file,
    /// a region of it, or the directory.
    ///
    /// A region is written as the whole file it sits in, so the journal holds
    /// the bytes it displaces whole and a roll back restores every one of them.
    pub(super) fn into_request(self) -> Request {
        let (content, mechanism) = match self.made {
            Made::Bytes(bytes) => (
                Content::Bytes {
                    bytes,
                    planned: self.planned,
                },
                Mechanism::Own,
            ),
            Made::Region(bytes, comment) => (
                Content::Bytes {
                    bytes,
                    planned: self.planned,
                },
                Mechanism::Region { comment },
            ),
            Made::Dir => (
                Content::Dir {
                    planned: self.planned,
                },
                Mechanism::Dir,
            ),
            Made::Link(text) => (
                Content::Link {
                    text,
                    planned: self.planned,
                },
                Mechanism::Link,
            ),
        };
        Request {
            target: self.target,
            dest: self.dest,
            content,
            mode: self.mode,
            ownership: if self.claimed {
                Ownership::Owned(mechanism)
            } else {
                Ownership::Released
            },
        }
    }
}

/// Decide what to do about one resolved target: its row, and the write it
/// needs when it needs one.
///
/// # Errors
///
/// [`Error::Body`] when a `file` body cannot be read from the config repo, and
/// [`Error::Fs`] when the destination cannot be observed.
pub(super) fn decide(
    resolution: &Resolution<Target>,
    ctx: &Ctx<'_>,
) -> Result<(Change, Option<Op>), Error> {
    let target = match resolution {
        Resolution::Ready(target) => target,
        Resolution::Blocked(entry) => {
            let change = Change {
                target: entry.key.clone(),
                origin: entry.origin.clone(),
                action: Action::Blocked,
                diff: None,
                note: Some(entry.hint.clone()),
            };
            return Ok((change, None));
        }
    };
    if target.direction == Direction::Track {
        let (change, op, _) = decide_track(target, ctx)?;
        return Ok((change, op));
    }
    // A generator may hold part of its content back, and every row of its
    // target says so, whatever the row's action.
    let held = match &target.body {
        Body::Generated(generator) => generator.note(),
        _ => None,
    };
    let row = |action, diff, note| Change {
        target: target.path.as_str().to_string(),
        origin: target.origin.clone(),
        action,
        diff,
        note: join([note, held.clone()]),
    };

    let bytes = match wanted(target, ctx)? {
        Wanted::Bytes(bytes) => bytes,
        Wanted::Dir => return decide_dir(target, ctx, row),
        Wanted::Link(text) => return decide_link(target, text, ctx, row),
        Wanted::Blocked(note) => return Ok((row(Action::Blocked, None, Some(note)), None)),
    };

    let dest = target.path.render(ctx.home);
    let observed = fs::observe(&dest)?;
    let (bytes, mode) = match target.attach {
        Attach::Region { comment } => match placed_in_region(&observed, comment, &bytes, target) {
            Ok(placed) => placed,
            Err(why) => {
                let note = format!(
                    "bx's region in this file is damaged: {why}. Leave one `{comment} >>> bx \
                     >>>` line and one `{comment} <<< bx <<<` line after it, or none"
                );
                return Ok((row(Action::Conflict, None, Some(note)), None));
            }
        },
        _ => (bytes, Mode::resolve(target.mode, Kind::File)),
    };
    let outcome = fs::compare(
        &observed,
        &Desired {
            bytes: &bytes,
            mode,
        },
        ctx.home,
    );
    // An unusable parent's reason is the comparison's note, spelled with
    // absolute paths; the row names them the way plan output names paths.
    let note = observed
        .parent
        .as_ref()
        .and_then(|parent| {
            let reason = parent.unusable()?;
            Some(portable_reason(&parent.path, reason, ctx.home))
        })
        .or(outcome.note);
    let note = join([
        note,
        parent_note(&observed, mode, ctx).unwrap_or(outcome.parent_note),
    ]);
    let entry = ctx.ledger.get(&target.path);
    let (action, note) = match target.attach {
        Attach::Region { comment } => {
            region_ownership(outcome.drift.into(), &observed, entry, comment, note)
        }
        _ => ownership(outcome.drift.into(), &observed, entry, note),
    };

    // A write into a directory its owner cannot write or search is refused
    // here, so `apply` never reaches `stage` for it. A row with no write is
    // left as it is: there is nothing to refuse.
    let (action, note) = match (
        action.is_pending(),
        locked_parent(&observed, ctx.home, ctx.declared, Write::File),
    ) {
        (true, Some(why)) => (Action::Conflict, join([Some(why), note])),
        _ => (action, note),
    };

    // Only a regular file has a side to show: a directory, a link or an
    // unusable parent is explained by the note alone.
    let shown = match action {
        Action::Create | Action::Modify => true,
        Action::Conflict => observed.kind == Kind::File,
        // Only a tracked target is carried into the repo, and it is decided
        // by `decide_track`.
        Action::Unchanged | Action::Sync | Action::Undeclared | Action::Blocked => false,
    };
    // A secret's plaintext, and whatever is on disk where it goes, are never
    // shown: the plan is printed, piped and pasted.
    let secret = matches!(target.body, Body::Secret(_));
    let diff = shown
        .then(|| {
            let between = if secret {
                Diff::concealed
            } else {
                Diff::between
            };
            between(
                target.path.as_str(),
                observed.bytes.as_deref(),
                &bytes,
                outcome.mode_drift,
            )
        })
        .flatten();
    // A create makes every missing parent on the way to its target, and the
    // row names each, so plan announces every directory apply creates.
    let note = match action {
        Action::Create => join([created_dirs(&observed, ctx.home, ctx.declared), note]),
        _ => note,
    };
    let change = row(action, diff, note);
    let op = action.is_pending().then(|| Op {
        target: target.path.clone(),
        dest,
        made: match target.attach {
            Attach::Region { comment } => Made::Region(bytes, comment),
            _ => Made::Bytes(bytes),
        },
        planned: observed,
        mode,
        claimed: true,
        carry: false,
    });
    Ok((change, op))
}

/// The whole file a region target leaves, and the mode it leaves it at.
///
/// Every byte outside the region is the file's own, carried through. The mode
/// is the target's when it declares one, and otherwise the file's own, so
/// attaching to a file the user keeps at `0600` never widens it; a file bx
/// creates gets the default.
///
/// # Errors
///
/// Why the file's delimiters do not make one region.
fn placed_in_region(
    observed: &Observed,
    comment: char,
    body: &[u8],
    target: &Target,
) -> Result<(Vec<u8>, Mode), &'static str> {
    let file = observed
        .bytes
        .as_deref()
        .filter(|_| observed.kind == Kind::File);
    let whole = region::splice(file, comment, body)?;
    let mode = match (target.mode, file.and(observed.mode)) {
        (Some(declared), _) => declared,
        (None, Some(own)) => own,
        (None, None) => Mode::resolve(None, Kind::File),
    };
    Ok((whole, mode))
}

/// Settle what the comparison found for a region target against the ledger.
///
/// The region is bx's and the rest of the file is the user's, so an edit
/// outside the region is never a conflict: while the region holds what bx
/// wants the comparison finds nothing to do, and a region appended to a file
/// the user wrote is additive. What is refused is a rewrite that would undo
/// the user's own act on bx's lines:
///
/// * the ledger says bx attached to this file some other way;
/// * bx wrote a region here and it is gone — the user removed it;
/// * a region is there that bx has no record of writing;
/// * the region differs from what bx wants and the file is not as bx last
///   left it. Whether the edit was inside the region or beside it cannot be
///   told from a whole-file record, so the region is left as it is.
///
/// A rewrite of a region bx wrote, in a file nobody else has touched since, is
/// a modify, as a file bx owns whole is.
fn region_ownership(
    action: Action,
    observed: &Observed,
    entry: Option<&LedgerEntry>,
    comment: char,
    note: Option<String>,
) -> (Action, Option<String>) {
    let conflict = |why: &str| {
        (
            Action::Conflict,
            join([Some(why.to_string()), note.clone()]),
        )
    };
    if let (Action::Create | Action::Modify, Some(entry)) = (action, entry)
        && entry.mechanism != (Mechanism::Region { comment })
    {
        return conflict(&format!(
            "bx attached to this file as {}",
            attached_as(&entry.mechanism)
        ));
    }
    let (Action::Modify, Some(bytes)) = (action, observed.bytes.as_deref()) else {
        return (action, note);
    };
    match (region::find(bytes, comment), entry) {
        (region::Found::Absent, None) => (action, note),
        (region::Found::Absent, Some(_)) => conflict("bx's region was removed since bx wrote it"),
        (_, None) => conflict("it holds a bx region bx has no record of writing"),
        (_, Some(entry)) if observed.digest() != Some(entry.written) => {
            conflict("edited since bx last wrote it, and bx's region differs from what bx wants")
        }
        _ => (action, note),
    }
}

/// The bytes a target wants, or why it cannot have any yet.
#[derive(Debug, PartialEq, Eq)]
enum Wanted {
    /// The whole content.
    Bytes(Vec<u8>),
    /// A directory, which has none.
    Dir,
    /// A symlink holding this text, already rendered against the home.
    Link(PathBuf),
    /// The note a blocked row carries.
    Blocked(String),
}

/// Produce a target's desired bytes.
///
/// A shape this entry does not write is blocked before anything is read.
/// Bodies are written verbatim: an inline body was substituted by `resolve`,
/// and a file body is the repo's bytes.
///
/// Not a pure read of the repo, in `plan` as in `apply`: a secret body is
/// decrypted here with the account's identity, never prompting, and a
/// generated body's `has:TOOL` conditions are decided by looking each tool up
/// along the `PATH` [`Inputs`](super::Inputs) took.
fn wanted(target: &Target, ctx: &Ctx<'_>) -> Result<Wanted, Error> {
    if let Some(note) = unsupported(target) {
        return Ok(Wanted::Blocked(note.to_string()));
    }
    let bytes = match &target.body {
        Body::Inline(content) => content.clone().into_bytes(),
        Body::File(rel) => read_repo_file(target, ctx.repo, rel)?,
        // Decrypted here, in the one function `plan` and `apply` share, so the
        // plaintext `apply` writes is the plaintext `plan` compared. Never with
        // a prompt: a locked identity is a blocked row naming the fix.
        Body::Secret(rel) => {
            let ciphertext = read_repo_file(target, ctx.repo, rel)?;
            let identity = ctx.secrets.identity_path(ctx.home);
            match crate::secret::decrypt(
                &ciphertext,
                &identity,
                ctx.secrets.identity_spelling(),
                crate::secret::Unlock::Never,
            ) {
                Ok(plaintext) => plaintext,
                Err(refusal) => return Ok(Wanted::Blocked(refusal.to_string())),
            }
        }
        // A `has:TOOL` condition is decided here, by looking the tool up on
        // this machine, so the generated shell carries no `command -v`.
        Body::Generated(generator) => {
            let present = |tool: &str| ctx.host.locate(tool).is_usable();
            let content = generator.render(&present);
            if let Some(note) = guard_generated(generator, &content, ctx.roots, &present) {
                return Ok(Wanted::Blocked(note));
            }
            content.into_bytes()
        }
        // A declared directory mode reaches disk before any file beneath it
        // is written, which [`locked_parent`] reads as a declaration.
        Body::Dir => return Ok(Wanted::Dir),
        // The text as the link will hold it: only a leading `~` is rendered,
        // and nothing is resolved.
        Body::Symlink(text) => {
            return Ok(Wanted::Link(crate::config::target::link_text(
                text, ctx.home,
            )));
        }
    };
    Ok(Wanted::Bytes(bytes))
}

/// Read a file the config repo holds: a `file` body, or a secret's ciphertext.
///
/// # Errors
///
/// [`Error::Body`] naming the file when it cannot be read.
pub(crate) fn read_repo_file(target: &Target, repo: &Path, rel: &Path) -> Result<Vec<u8>, Error> {
    let path = repo.join(rel);
    let body = |source| Error::Body {
        origin: target.origin.clone(),
        path: path.clone(),
        source,
    };
    // Followed through a link, since a body the repo links to is the user's
    // layout. Anything but a regular file at the end of it — a FIFO, a device —
    // would block the read or never end it.
    if std::fs::metadata(&path).is_ok_and(|meta| !meta.is_file()) {
        return Err(body(std::io::Error::other("not a regular file")));
    }
    std::fs::read(&path).map_err(body)
}

/// Why a target's attachment, direction or format cannot be written yet.
///
/// A region is written for a generated body only. The placement graph's
/// regions hold fixed text, so a rewrite of one is never a question of whose
/// edit wins; a region a config author fills with a body of their own changes
/// whenever the body does, and deciding that against an edit beside it is
/// entry C1's.
fn unsupported(target: &Target) -> Option<&'static str> {
    match (&target.attach, target.direction, &target.format) {
        (Attach::Region { .. }, _, _) if !matches!(target.body, Body::Generated(_)) => {
            Some("a managed region is not supported until entry C1")
        }
        (Attach::Include { .. }, _, _) => Some("an include line is not supported until entry C1"),
        (_, _, Format::Jsonc { .. }) => Some("owning JSONC keys is not supported until entry C3"),
        (Attach::Region { .. }, Direction::Track, _) | (_, Direction::Track, Format::EnvD) => {
            Some(TRACK_SHAPE)
        }
        (
            Attach::Own | Attach::Region { .. },
            Direction::Apply | Direction::Track,
            Format::Opaque | Format::EnvD,
        ) => None,
    }
}

/// Why a tracked target of any shape but a whole file is blocked.
const TRACK_SHAPE: &str = "track mode carries this machine's whole file into the config repo, \
                           so it needs a `file` body, attach = \"own\" and format = \"opaque\"";

/// Decide one tracked target: the machine's copy leads, and the repo's
/// follows.
///
/// # Decision: both sides are compared with what they last agreed on
///
/// A tracked target has two copies — this machine's, at its path, which the
/// tool rewrites, and the repo's, at its `file` body — and [`Ctx::bases`]
/// holds the bytes the two last agreed on. Which one moved decides the row:
///
/// | this machine | the repo | row |
/// | --- | --- | --- |
/// | the same bytes as the repo | | unchanged, and they now agree |
/// | nothing | nothing | unchanged: there is nothing to track yet |
/// | nothing | a copy | create: `apply` writes the repo's copy here |
/// | a copy | nothing | sync: `sync` carries this machine's copy into the repo |
/// | changed since they agreed | as they agreed | sync |
/// | as they agreed | changed since they agreed | modify: `apply` writes the repo's copy here |
/// | changed since they agreed | changed since they agreed | conflict, with both sides' diffs (the one diff between them past [`Base::KEPT_WHOLE`]) |
/// | differs from the repo, with no agreement recorded | | conflict |
///
/// A conflict waits for a human: bx never merges the two, and never picks one
/// over the other when it cannot tell which one moved. With no agreement
/// recorded — the first sync on this machine, or a fingerprint cache that was
/// lost — that is every difference, which is what makes losing the cache safe:
/// it costs a question, never an overwrite.
///
/// # Decision: the machine's copy is compared with the agreement, never the ledger
///
/// The tool rewrites the file as it pleases, so a rewrite is this machine's
/// change to carry, never "edited since bx last wrote it": the machine's copy
/// is compared with the agreement alone, whatever the ledger holds for it.
///
/// What the ledger holds is decided by [`track_onto_machine`]: the copy `apply`
/// writes where this machine had none is claimed, so `rm` can take it away
/// again; one written over a copy the tool already had is not, and `rm` leaves
/// it alone.
///
/// The repo's copy is the other way round: `sync` claims it as a whole file
/// owned by bx, so the ledger keeps the bytes it held before tracking began,
/// and `rm` puts them back.
fn decide_track(
    target: &Target,
    ctx: &Ctx<'_>,
) -> Result<(Change, Option<Op>, Option<Agreed>), Error> {
    let row = |action, diff, note: Option<String>| Change {
        target: target.path.as_str().to_string(),
        origin: target.origin.clone(),
        action,
        diff,
        note,
    };
    let blocked = |note: &str| {
        Ok((
            row(Action::Blocked, None, Some(note.to_string())),
            None,
            None,
        ))
    };
    if let Some(note) = unsupported(target) {
        return blocked(note);
    }
    let Body::File(rel) = &target.body else {
        return blocked(TRACK_SHAPE);
    };
    let copy_dest = ctx.repo.join(rel);
    let copy =
        Portable::from_path(&copy_dest, ctx.home).map_err(|source| fs::Error::NotPortable {
            path: copy_dest.clone(),
            source,
        })?;
    let dest = target.path.render(ctx.home);
    let machine = fs::observe(&dest)?;
    let repo = fs::observe(&copy_dest)?;
    let shown = target.path.as_str();
    let conflict = |why: String, diff| Ok((row(Action::Conflict, diff, Some(why)), None, None));

    for (side, observed) in [
        ("this machine's copy", &machine),
        ("the repo's copy", &repo),
    ] {
        if !matches!(observed.kind, Kind::File | Kind::Absent) {
            return conflict(
                format!("{side} is not a regular file, so bx cannot track it"),
                None,
            );
        }
    }
    let agreed = |bytes: &[u8], when| {
        Some(Agreed {
            target: target.path.clone(),
            bytes: bytes.to_vec(),
            when,
        })
    };
    let (machine_bytes, repo_bytes) = (machine.bytes.as_deref(), repo.bytes.as_deref());
    let (m, r) = match (machine_bytes, repo_bytes) {
        (None, None) => {
            let note = "neither this machine nor the repo has it yet".to_string();
            return Ok((row(Action::Unchanged, None, Some(note)), None, None));
        }
        (Some(m), Some(r)) if m == r => {
            return Ok((
                row(Action::Unchanged, None, None),
                None,
                agreed(m, When::Now),
            ));
        }
        (None, Some(r)) => {
            let (change, op) = track_onto_machine(target, &machine, r, ctx, row)?;
            let agreement = op.is_some().then(|| agreed(r, When::Applied)).flatten();
            return Ok((change, op, agreement));
        }
        (Some(m), None) => {
            let (change, op) =
                track_into_repo(shown, rel, (copy, &repo), m, machine.mode, ctx, row)?;
            let agreement = op.is_some().then(|| agreed(m, When::Synced)).flatten();
            return Ok((change, op, agreement));
        }
        (Some(m), Some(r)) => (m, r),
    };
    match ctx.bases.get(&target.path) {
        Some(base) if base.holds(r) => {
            let (change, op) =
                track_into_repo(shown, rel, (copy, &repo), m, machine.mode, ctx, row)?;
            let agreement = op.is_some().then(|| agreed(m, When::Synced)).flatten();
            Ok((change, op, agreement))
        }
        Some(base) if base.holds(m) => {
            let (change, op) = track_onto_machine(target, &machine, r, ctx, row)?;
            let agreement = op.is_some().then(|| agreed(r, When::Applied)).flatten();
            Ok((change, op, agreement))
        }
        Some(base) => {
            let why = "this machine and the repo both changed it since the last sync; bx merges \
                       neither. Make the two copies the same by hand, and bx tracks it again";
            let diff = match base {
                Base::Bytes(base) => Some(Diff::diverged(shown, base, m, r)),
                // Too large to have been kept whole: the one diff between the
                // two sides is all there is to show.
                Base::Digest(_) => {
                    Diff::labelled(shown, ("repo", "this machine"), Some(r), m, None)
                }
            };
            conflict(why.to_string(), diff)
        }
        None => conflict(
            format!(
                "differs from the repo's copy at {}, and no sync on this machine has recorded \
                 which one changed; make the two the same by hand, and bx tracks it from there",
                rel.display()
            ),
            Diff::labelled(shown, ("repo", "this machine"), Some(r), m, None),
        ),
    }
}

/// The row, and the write, that puts the repo's copy `bytes` of a tracked
/// target onto this machine, where `observed` is: a create where there is
/// nothing, and otherwise a modify at the mode the file already has, since
/// the file is the tool's.
///
/// # Decision: `apply` claims the machine copy it creates
///
/// Where this machine has no copy, the write is claimed: the ledger records
/// that nothing was there, and the directories the write made, so `rm`
/// removes the file and those directories while the file still holds what bx
/// wrote (Invariant 4). Once the tool has rewritten it, `rm` refuses to
/// destroy those bytes, as it refuses over any edited file.
///
/// Where the ledger already holds an entry for the target — this machine got
/// its copy from bx, or bx wrote it before it was tracked — the write is
/// claimed too, so the entry, and the prior it keeps, survives the write
/// rather than being dropped by it.
///
/// A write over a copy the tool already had, with no entry, is not claimed:
/// the file was the tool's before bx wrote to it, and is left the tool's.
/// The journal still holds its prior bytes, so an interruption is rolled back.
fn track_onto_machine(
    target: &Target,
    observed: &Observed,
    bytes: &[u8],
    ctx: &Ctx<'_>,
    row: impl Fn(Action, Option<Diff>, Option<String>) -> Change,
) -> Result<(Change, Option<Op>), Error> {
    let mode = observed
        .mode
        .unwrap_or_else(|| Mode::resolve(target.mode, Kind::File));
    let outcome = fs::compare(observed, &Desired { bytes, mode }, ctx.home);
    let unusable = observed.parent.as_ref().and_then(|parent| {
        let reason = parent.unusable()?;
        Some(portable_reason(&parent.path, reason, ctx.home))
    });
    let action = if observed.kind == Kind::Absent {
        Action::Create
    } else {
        Action::Modify
    };
    let why = match (unusable, outcome.drift) {
        (Some(reason), _) => Some(reason),
        (None, fs::Drift::Conflict) => Some(outcome.note.unwrap_or_default()),
        (None, _) => locked_parent(observed, ctx.home, ctx.declared, Write::File),
    };
    if let Some(why) = why {
        return Ok((row(Action::Conflict, None, Some(why)), None));
    }
    let diff = Diff::labelled(
        target.path.as_str(),
        ("this machine", "repo"),
        observed.bytes.as_deref(),
        bytes,
        None,
    );
    let note = match action {
        Action::Create => join([
            Some("this machine has no copy; apply writes the repo's".to_string()),
            created_dirs(observed, ctx.home, ctx.declared),
            outcome.parent_note,
        ]),
        _ => join([
            Some("the repo's copy changed since the last sync; apply writes it here".to_string()),
            outcome.parent_note,
        ]),
    };
    let op = Op {
        target: target.path.clone(),
        dest: observed.path.clone(),
        made: Made::Bytes(bytes.to_vec()),
        planned: observed.clone(),
        mode,
        claimed: observed.kind == Kind::Absent || ctx.ledger.get(&target.path).is_some(),
        carry: false,
    };
    Ok((row(action, diff, note), Some(op)))
}

/// The row, and the write only `sync` makes, that carries this machine's copy
/// `bytes`, at `machine_mode`, of a tracked target into the repo's copy at
/// `rel`: `copy` is that copy's ledger key and what is there now.
///
/// A copy the repo already has keeps its mode; a new one takes the mode of
/// this machine's, so a private file is not made readable in the repo.
fn track_into_repo(
    shown: &str,
    rel: &Path,
    (copy, repo): (Portable, &Observed),
    bytes: &[u8],
    machine_mode: Option<Mode>,
    ctx: &Ctx<'_>,
    row: impl Fn(Action, Option<Diff>, Option<String>) -> Change,
) -> Result<(Change, Option<Op>), Error> {
    let mode = repo.mode.or(machine_mode).unwrap_or(Mode::DEFAULT_FILE);
    let outcome = fs::compare(repo, &Desired { bytes, mode }, ctx.home);
    let unusable = repo.parent.as_ref().and_then(|parent| {
        let reason = parent.unusable()?;
        Some(portable_reason(&parent.path, reason, ctx.home))
    });
    let why = match (unusable, outcome.drift) {
        (Some(reason), _) => Some(reason),
        (None, fs::Drift::Conflict) => Some(outcome.note.unwrap_or_default()),
        (None, _) => locked_parent(repo, ctx.home, ctx.declared, Write::File),
    };
    if let Some(why) = why {
        return Ok((row(Action::Conflict, None, Some(why)), None));
    }
    let diff = Diff::labelled(
        shown,
        ("repo", "this machine"),
        repo.bytes.as_deref(),
        bytes,
        None,
    );
    let note = format!(
        "this machine changed it; bx sync carries it into {} and commits it",
        rel.display()
    );
    let op = Op {
        target: copy,
        dest: repo.path.clone(),
        made: Made::Bytes(bytes.to_vec()),
        planned: repo.clone(),
        mode,
        claimed: true,
        carry: true,
    };
    Ok((row(Action::Sync, diff, Some(note)), Some(op)))
}

/// Settle what the comparison found against what the ledger says bx owns.
///
/// Only a file bx wrote whole, and that still holds exactly what bx last left,
/// may be modified. Everything else in the way is a conflict: reported and
/// skipped.
fn ownership(
    action: Action,
    observed: &Observed,
    entry: Option<&LedgerEntry>,
    note: Option<String>,
) -> (Action, Option<String>) {
    let conflict = |why: String| (Action::Conflict, join([Some(why), note.clone()]));
    match (action, entry) {
        (Action::Create | Action::Modify, Some(entry)) if entry.mechanism != Mechanism::Own => {
            conflict(format!(
                "bx attached to this file as {}",
                attached_as(&entry.mechanism)
            ))
        }
        (Action::Modify, None) => conflict("exists and bx does not own it".to_string()),
        (Action::Modify, Some(entry)) if observed.digest() != Some(entry.written) => {
            conflict("edited since bx last wrote it".to_string())
        }
        // The bytes are bx's, and the mode is not the one bx set: the user
        // changed it, and a rewrite would undo that. A change to the declared
        // mode alone leaves the disk at the ledger's mode and stays a modify.
        (Action::Modify, Some(entry)) if observed.mode != Some(entry.mode) => {
            conflict("its mode changed since bx wrote it".to_string())
        }
        _ => (action, note),
    }
}

/// How a ledger mechanism reads in a note.
pub(super) const fn attached_as(mechanism: &Mechanism) -> &'static str {
    match mechanism {
        Mechanism::Own => "the whole file",
        Mechanism::Region { .. } => "a managed region",
        Mechanism::Include { .. } => "an include line",
        Mechanism::Dir => "a directory",
        Mechanism::Link => "a symlink",
        Mechanism::Clone => "a git checkout",
    }
}

/// Why the parent `dir` cannot hold a file, with every path in `reason`
/// spelled as plan output spells paths: `~/…` under `home`, absolute outside.
///
/// The observation writes `reason` from structure it holds: the absolute
/// spelling of `dir`, or of the ancestor of `dir` that stops it, leads, and a
/// reason about an ancestor ends by naming `dir` as what cannot be created.
/// Those two spellings are put back through [`paths::to_portable`] from the
/// paths themselves — `dir` and its ancestors, never the home's text — and
/// nothing else in the reason is touched. A reason in any other shape is
/// replaced by one naming `dir` alone, so no absolute home reaches a row.
fn portable_reason(dir: &Path, reason: &str, home: &Path) -> String {
    let named = dir.ancestors().find_map(|ancestor| {
        reason
            .strip_prefix(&format!("{} ", ancestor.display()))
            .map(|rest| (ancestor, rest))
    });
    let Some((ancestor, rest)) = named else {
        return format!(
            "{} does not resolve to a directory, so bx cannot write a file inside it",
            paths::to_portable(dir, home)
        );
    };
    let rest = match rest.strip_suffix(&format!("create {} inside it", dir.display())) {
        Some(head) => format!("{head}create {} inside it", paths::to_portable(dir, home)),
        None => rest.to_string(),
    };
    format!("{} {rest}", paths::to_portable(ancestor, home))
}

/// The present parts, joined with `; `, or `None` when there are none.
fn join(parts: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    let parts: Vec<String> = parts.into_iter().flatten().collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// What the filesystem found, as the action the plan announces before the
/// ledger is consulted: the ownership rules above settle what bx then does
/// about it.
impl From<fs::Drift> for Action {
    fn from(drift: fs::Drift) -> Self {
        match drift {
            fs::Drift::Unchanged => Self::Unchanged,
            fs::Drift::Create => Self::Create,
            fs::Drift::Modify => Self::Modify,
            fs::Drift::Conflict => Self::Conflict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_drift_is_announced_as_the_action_of_the_same_name() {
        for (drift, action) in [
            (fs::Drift::Unchanged, Action::Unchanged),
            (fs::Drift::Create, Action::Create),
            (fs::Drift::Modify, Action::Modify),
            (fs::Drift::Conflict, Action::Conflict),
        ] {
            assert_eq!(Action::from(drift), action, "{drift:?}");
        }
    }
    use crate::config::Origin;
    use crate::config::target::{Gen, KeyPath};
    use crate::testing::guarded_home;

    pub(super) fn a_target(home: &Path, path: &str) -> Target {
        Target {
            path: Portable::parse_in(path, home).expect("a portable path"),
            body: Body::Inline("x\n".to_string()),
            mode: None,
            attach: Attach::Own,
            direction: Direction::Apply,
            format: Format::Opaque,
            requires: Vec::new(),
            references: Vec::new(),
            enabled: true,
            origin: Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line: 3,
            },
        }
    }

    #[test]
    fn decision_3_an_unsupported_shape_is_blocked_with_no_write() {
        let home = guarded_home();
        let ledger = LedgerView::default();
        let roots = RootSet::strict();
        let ctx = Ctx {
            ledger: &ledger,
            home: home.path(),
            repo: &home.child(".config/bx"),
            roots: &roots,
            secrets: &Secrets::default(),
            declared: &Declared::new(),
            bases: &Bases::new(),
            host: &activation::System::from_env(),
        };
        let shaped = |change: fn(&mut Target)| {
            let mut target = a_target(home.path(), "~/.a");
            // A body that cannot be read, so a read before the block would err.
            target.body = Body::File(PathBuf::from("absent"));
            change(&mut target);
            target
        };
        // An env.d fragment is written since entry B1, and a region around a
        // generated body; a region around a body a config author wrote is not.
        let cases: [(Target, &str); 4] = [
            (
                shaped(|t| t.attach = Attach::Region { comment: '#' }),
                "entry C1",
            ),
            (
                shaped(|t| {
                    t.attach = Attach::Include {
                        line: "x".to_string(),
                    };
                }),
                "entry C1",
            ),
            (
                shaped(|t| {
                    t.format = Format::Jsonc {
                        owns: vec![KeyPath::parse("a.b").expect("a key path")],
                    };
                }),
                "entry C3",
            ),
            // A tracked target is refused its JSONC keys for the same reason,
            // before track mode reads anything.
            (
                shaped(|t| {
                    t.direction = Direction::Track;
                    t.format = Format::Jsonc {
                        owns: vec![KeyPath::parse("a.b").expect("a key path")],
                    };
                }),
                "entry C3",
            ),
        ];

        for (target, entry) in cases {
            let (change, op) = decide(&Resolution::Ready(target.clone()), &ctx).expect("no read");
            assert_eq!(change.action, Action::Blocked, "{target:?}");
            assert_eq!(op, None, "{target:?}");
            assert_eq!(change.diff, None);
            let note = change.note.expect("a note");
            assert!(
                note.ends_with(&format!("not supported until {entry}")),
                "{note}"
            );
            assert_eq!(change.target, "~/.a");
            assert_eq!(change.origin.line, 3);
        }
        assert!(!home.child(".a").exists());
    }

    #[test]
    fn a_tracked_target_that_is_not_a_whole_file_is_blocked_before_anything_is_read() {
        let home = guarded_home();
        let ledger = LedgerView::default();
        let roots = RootSet::strict();
        let ctx = Ctx {
            ledger: &ledger,
            home: home.path(),
            repo: &home.child(".config/bx"),
            roots: &roots,
            secrets: &Secrets::default(),
            declared: &Declared::new(),
            bases: &Bases::new(),
            host: &activation::System::from_env(),
        };
        let tracked = |change: fn(&mut Target)| {
            let mut target = a_target(home.path(), "~/.a");
            target.direction = Direction::Track;
            change(&mut target);
            target
        };
        for target in [
            tracked(|t| t.body = Body::Dir),
            tracked(|t| t.body = Body::Inline("x\n".to_string())),
            tracked(|t| t.body = Body::Symlink("~/.b".to_string())),
            tracked(|t| {
                t.body = Body::File(PathBuf::from("absent"));
                t.format = Format::EnvD;
            }),
            tracked(|t| {
                t.body = Body::Generated(Gen::Source(
                    Portable::parse_in("~/.env", Path::new("/h")).expect("a path"),
                ));
                t.attach = Attach::Region { comment: '#' };
            }),
        ] {
            let (change, op) = decide(&Resolution::Ready(target.clone()), &ctx).expect("no read");
            assert_eq!(change.action, Action::Blocked, "{target:?}");
            assert_eq!(op, None);
            assert_eq!(change.note.as_deref(), Some(TRACK_SHAPE), "{target:?}");
        }
    }

    #[test]
    fn only_a_create_or_a_modify_produces_a_write_and_it_is_the_decided_one() {
        let home = guarded_home();
        home.write(".mine", "user\n");
        let ledger = LedgerView::default();
        let roots = RootSet::strict();
        let ctx = Ctx {
            ledger: &ledger,
            home: home.path(),
            repo: &home.child(".config/bx"),
            roots: &roots,
            secrets: &Secrets::default(),
            declared: &Declared::new(),
            bases: &Bases::new(),
            host: &activation::System::from_env(),
        };

        let (change, op) =
            decide(&Resolution::Ready(a_target(home.path(), "~/.new")), &ctx).expect("decide");
        assert_eq!(change.action, Action::Create);
        let op = op.expect("a create writes");
        assert_eq!(op.target().as_str(), "~/.new");
        let request = op.into_request();
        assert_eq!(request.dest, home.child(".new"));
        assert_eq!(request.mode, Mode::DEFAULT_FILE);
        assert_eq!(request.ownership, Ownership::Owned(Mechanism::Own));
        match request.content {
            Content::Bytes { bytes, planned } => {
                assert_eq!(bytes, b"x\n");
                assert_eq!(planned.kind, Kind::Absent);
            }
            _ => panic!("a create is bytes"),
        }

        let (change, op) =
            decide(&Resolution::Ready(a_target(home.path(), "~/.mine")), &ctx).expect("decide");
        assert_eq!(change.action, Action::Conflict);
        assert_eq!(op, None);
    }

    #[test]
    fn an_absent_target_bx_attached_to_another_way_is_a_conflict_not_a_create() {
        // P42R1-COV2. The ledger still names the file as one bx attached to as
        // a region or an include line, and the file is gone. Creating it whole
        // would make bx the owner of a file it never owned whole.
        for (mechanism, words) in [
            (Mechanism::Region { comment: '#' }, "a managed region"),
            (
                Mechanism::Include {
                    line: "x".to_string(),
                },
                "an include line",
            ),
        ] {
            let home = guarded_home();
            crate::plan::tests::own(home.path(), ".a", b"old\n", mechanism);
            std::fs::remove_file(home.child(".a")).expect("the file goes");
            let state = crate::state::StateDir::resolve(home.path());
            let ledger = LedgerView::read(&state, home.path())
                .expect("the ledger")
                .value;
            let roots = RootSet::strict();
            let ctx = Ctx {
                ledger: &ledger,
                home: home.path(),
                repo: &home.child(".config/bx"),
                roots: &roots,
                secrets: &Secrets::default(),
                declared: &Declared::new(),
                bases: &Bases::new(),
                host: &activation::System::from_env(),
            };

            let (change, op) =
                decide(&Resolution::Ready(a_target(home.path(), "~/.a")), &ctx).expect("decide");

            assert_eq!(change.action, Action::Conflict, "{words}");
            assert_eq!(
                change.note.as_deref(),
                Some(format!("bx attached to this file as {words}").as_str())
            );
            assert_eq!(op, None, "{words}");
            assert!(!home.child(".a").exists(), "{words}");
        }
    }

    // What the tests of `parent` and `dir` share: both decide directories
    // through a whole `plan` or `apply`.

    /// A directory target at `~/.d` declared `mode`, then `children`.
    pub(super) fn a_directory_target(mode: &str, children: &str) -> String {
        format!("[[target]]\npath = \"~/.d\"\ndir = true\nmode = \"{mode}\"\n{children}")
    }

    /// The row `plan` gives `target` in `report`.
    pub(super) fn row_for<'r>(report: &'r crate::plan::Report, target: &str) -> &'r Change {
        report
            .changes
            .iter()
            .find(|change| change.target == target)
            .unwrap_or_else(|| panic!("no row for {target}: {report:?}"))
    }

    /// A directory at `~/rel`, made at `mode`, reopened to its owner when the
    /// returned guard drops so the tempdir home can still be cleaned up.
    pub(super) fn locked_dir_at(home: &Path, rel: &str, mode: u32) -> impl Drop {
        struct Unlock(PathBuf);
        impl Drop for Unlock {
            fn drop(&mut self) {
                let _ = fs::set_mode(&self.0, Mode::from_bits(0o700));
            }
        }
        let dir = home.join(rel);
        std::fs::create_dir_all(&dir).expect("the directory");
        fs::set_mode(&dir, Mode::from_bits(mode)).expect("chmod");
        Unlock(dir)
    }

    /// `plan`, over `inputs`.
    pub(super) fn plan_of(inputs: &crate::plan::Inputs) -> crate::plan::Report {
        crate::plan::run(inputs, crate::plan::Mode::Plan, &mut |_| Ok(false)).expect("plan")
    }

    /// `apply`, approved, over `inputs`.
    pub(super) fn apply_of(inputs: &crate::plan::Inputs) -> crate::plan::Report {
        crate::plan::run(inputs, crate::plan::Mode::Apply, &mut |_| Ok(true)).expect("apply")
    }

    /// The mode on disk at `~/rel`.
    pub(super) fn mode_on_disk(home: &Path, rel: &str) -> Option<Mode> {
        crate::journal::tests::mode_at(&home.join(rel))
    }

    #[test]
    fn the_supported_shape_is_not_unsupported() {
        let home = guarded_home();
        assert_eq!(unsupported(&a_target(home.path(), "~/.a")), None);
    }

    #[test]
    fn decision_9_an_unusable_parent_reason_names_its_paths_portably() {
        let home = Path::new("/var/home/u s");
        let reason = |dir: &Path, rest: &str| format!("{} {rest}", dir.display());

        // The parent itself, under the home.
        let dir = home.join(".x");
        assert_eq!(
            portable_reason(
                &dir,
                &reason(
                    &dir,
                    "is not a directory, so bx cannot write a file inside it"
                ),
                home
            ),
            "~/.x is not a directory, so bx cannot write a file inside it"
        );

        // An ancestor that stops it, and the parent it cannot create — with a
        // space in a name, so the leading spelling is matched as a path.
        let dir = home.join("a b/c");
        let stops = home.join("a b");
        assert_eq!(
            portable_reason(
                &dir,
                &format!(
                    "{} does not resolve to a directory, so bx cannot create {} inside it",
                    stops.display(),
                    dir.display()
                ),
                home
            ),
            "~/a b does not resolve to a directory, so bx cannot create ~/a b/c inside it"
        );

        // A tail naming a directory other than the parent is left as written.
        let other = Path::new("/elsewhere/d");
        assert_eq!(
            portable_reason(
                &dir,
                &format!(
                    "{} does not resolve, so bx cannot create {} inside it",
                    stops.display(),
                    other.display()
                ),
                home
            ),
            "~/a b does not resolve, so bx cannot create /elsewhere/d inside it"
        );

        // The source text in the middle is kept.
        let dir = home.join(".loop");
        assert_eq!(
            portable_reason(
                &dir,
                &reason(
                    &dir,
                    "does not resolve to a directory (os error 40), so bx cannot write a file \
                     inside it"
                ),
                home
            ),
            "~/.loop does not resolve to a directory (os error 40), so bx cannot write a file \
             inside it"
        );

        // Outside the home every path stays absolute.
        let dir = Path::new("/srv/x/y");
        let stops = Path::new("/srv/x");
        let outside = format!(
            "{} does not resolve to a directory, so bx cannot create {} inside it",
            stops.display(),
            dir.display()
        );
        assert_eq!(portable_reason(dir, &outside, home), outside);

        // A reason in any other shape names the parent alone.
        assert_eq!(
            portable_reason(
                &home.join(".z"),
                "something went wrong at /var/home/u s/.z",
                home
            ),
            "~/.z does not resolve to a directory, so bx cannot write a file inside it"
        );
    }

    #[test]
    fn notes_join_what_is_present() {
        assert_eq!(join([None, None]), None);
        assert_eq!(join([Some("a".to_string()), None]), Some("a".to_string()));
        assert_eq!(
            join([Some("a".to_string()), Some("b".to_string())]),
            Some("a; b".to_string())
        );
    }

    #[test]
    fn every_mechanism_has_its_own_words() {
        assert_eq!(attached_as(&Mechanism::Own), "the whole file");
        assert_eq!(
            attached_as(&Mechanism::Include {
                line: "x".to_string()
            }),
            "an include line"
        );
        assert_eq!(attached_as(&Mechanism::Clone), "a git checkout");
    }
}
