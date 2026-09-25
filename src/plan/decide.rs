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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{Change, Diff, Error, region};
use crate::config::Origin;
use crate::config::env::Syntax;
use crate::config::resolve::Resolution;
use crate::config::secrets::Secrets;
use crate::config::target::{Attach, Body, Direction, Format, Gen, Target};
use crate::detect;
use crate::env_guard::{self, RootSet};
use crate::fs::{self, Desired, Kind, Mode, Observed};
use crate::journal::{Content, Ownership, Request};
use crate::paths::{self, Portable};
use crate::report::Action;
use crate::state::{ContentHash, Fingerprint, LedgerEntry, LedgerView, Mechanism};

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
}

/// What each tracked target's copy on this machine and copy in the repo last
/// agreed on, keyed by the target: what "changed since the last sync" is
/// measured from. Read from the fingerprint cache — see [`super::bases`].
pub(super) type Bases = BTreeMap<Portable, Base>;

/// What a tracked target's two sides last agreed on, as the fingerprint cache
/// keeps it: the bytes themselves while they are small, and otherwise only
/// their digest. See [`Base::fingerprint`] for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Base {
    /// The agreed bytes, kept whole so a conflict can show each side's diff
    /// from them.
    Bytes(Vec<u8>),
    /// The SHA-256 of agreed bytes larger than [`Base::KEPT_WHOLE`].
    Digest([u8; 32]),
}

impl Base {
    /// The largest agreement kept whole, in bytes.
    pub(super) const KEPT_WHOLE: usize = 64 * 1024;

    /// The tag of an agreement kept whole.
    const BYTES: u8 = b'=';

    /// The tag of an agreement kept as a digest.
    const DIGEST: u8 = b'#';

    /// The agreement on `bytes`, as it is kept.
    pub(super) fn of(bytes: &[u8]) -> Self {
        if bytes.len() <= Self::KEPT_WHOLE {
            Self::Bytes(bytes.to_vec())
        } else {
            Self::Digest(*ContentHash::of(bytes).as_bytes())
        }
    }

    /// Whether `bytes` are what was agreed on.
    pub(super) fn holds(&self, bytes: &[u8]) -> bool {
        match self {
            Self::Bytes(agreed) => agreed == bytes,
            Self::Digest(digest) => digest == ContentHash::of(bytes).as_bytes(),
        }
    }

    /// The fingerprint-cache entry this agreement is kept as: a tag byte, then
    /// the bytes or the digest.
    ///
    /// # Decision: small agreements are kept whole, large ones as a digest
    ///
    /// Deciding which side moved needs only a comparison, which a digest
    /// answers. Showing a conflict does not: issue #32 asks for *both sides'
    /// diffs*, each measured from the last agreement, and a diff needs the
    /// bytes it is measured from. Nothing else holds them — the repo's copy
    /// may have been rewritten by another machine since, and the machine's by
    /// the tool — so the cache keeps them.
    ///
    /// The fingerprint cache is for short inputs, so what it keeps is bounded:
    /// an agreement of at most [`Base::KEPT_WHOLE`] bytes is kept whole, and a
    /// larger one only as its digest, whose conflict shows the one diff
    /// between the two sides instead. A plugin manager's lock file, the
    /// target track mode exists for, is a few kilobytes.
    pub(super) fn fingerprint(&self) -> Fingerprint {
        let mut kept = Vec::new();
        match self {
            Self::Bytes(bytes) => {
                kept.push(Self::BYTES);
                kept.extend_from_slice(bytes);
            }
            Self::Digest(digest) => {
                kept.push(Self::DIGEST);
                kept.extend_from_slice(digest);
            }
        }
        Fingerprint::raw(kept)
    }

    /// The agreement a fingerprint-cache entry keeps, or `None` for one in no
    /// shape [`Base::fingerprint`] writes — which reads as no agreement, and
    /// so costs a question rather than an overwrite.
    pub(super) fn from_fingerprint(fingerprint: &Fingerprint) -> Option<Self> {
        match fingerprint.as_bytes().split_first()? {
            (&Self::BYTES, bytes) if bytes.len() <= Self::KEPT_WHOLE => {
                Some(Self::Bytes(bytes.to_vec()))
            }
            (&Self::DIGEST, digest) => Some(Self::Digest(digest.try_into().ok()?)),
            _ => None,
        }
    }
}

/// When the bytes a tracked target's two sides hold become the bytes they
/// last agreed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum When {
    /// Already: both sides hold them.
    Now,
    /// Once `apply` has written the repo's copy onto this machine.
    Applied,
    /// Once `sync` has carried this machine's copy into the repo.
    Synced,
}

/// What a tracked target's two sides will agree on, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Agreed {
    /// The tracked target.
    pub target: Portable,
    /// The bytes both sides hold once [`Agreed::when`] has happened.
    pub bytes: Vec<u8>,
    /// What has to happen first.
    pub when: When,
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

/// Why a write to a destination is refused, read from the mode **on disk** of
/// the directory `apply` would have to write into.
///
/// # Decision 32, revising decision 24: the basis is the observed mode
///
/// The first form of this rule was keyed on the declared mode of `dir = true`
/// targets: `plan` built a list of the directory targets whose declared mode
/// denied their owner write or search, and refused every destination beneath
/// one. That list was wrong in both directions, and each direction is a
/// separate defect the list could not see:
///
/// * It **missed** the case that occurs in real homes. A directory already on
///   disk at `0500` is declared by nothing, so it was in no list, and `plan`
///   announced a `Create` that `apply` then failed with `EACCES` — Invariant 7
///   broken by the very rule written to uphold it. [`crate::fs::compare`] does
///   not catch it either: its parent note fires only when the parent is *wider*
///   than the file's desired mode, and `0500` is not wider than `0644`.
/// * It **fired where nothing was wrong**. A `dir = true` target declared
///   `0555` whose directory does not exist made every file beneath it a
///   conflict, with a note saying `apply` could not write there — untrue then,
///   since every `Body::Dir` target was blocked, so no declared directory mode
///   reached disk at all and the parent was created at [`Mode::DEFAULT_DIR`].
///   Now that directory targets are written, a declared mode does reach disk
///   first, and is read as one: see the last section.
///
/// A declaration is a statement about what the user asked for; this rule needs
/// a fact about what `apply` will meet. So the basis is the observation the
/// comparison already holds. Nothing can opt out of it: there is no list to be
/// absent from, and a directory's mode is read from the filesystem whether or
/// not any target names it.
///
/// The directory that governs the write is the destination's parent when it is
/// already there, and otherwise the deepest ancestor of it that is — the
/// directory `create_missing_dirs` makes its first `mkdir` in. Every directory
/// between that one and the parent is one `apply` creates itself, at
/// [`Mode::DEFAULT_DIR`], which denies its owner nothing.
///
/// An unusable parent is not this rule's to report: [`crate::fs::compare`] has
/// already settled it as a conflict with its own reason.
///
/// Owner bits are the test, because bx writes as the account that owns its own
/// home. A directory owned by somebody else is a different refusal, and `stage`
/// reports it.
///
/// # Why **write** is the whole test, and search is not a second case
///
/// The rule this replaces distinguished three denials — write, search, and
/// both — and named each in its note. Only one of the three can arrive here,
/// and the reason is not that the others are rare:
///
/// A directory bx cannot **search** is one [`crate::fs::observe`] could not
/// read through. Reaching this function at all means `observe` returned, and
/// `observe` stats the destination with `optional_metadata`, which turns
/// `ENOENT` into "absent" and every other failure — `EACCES` among them — into
/// [`crate::fs::Error::Read`]. So a present parent that denies its owner search
/// stops the run before any target is decided. A parent that is *absent* is
/// reached the same way: `parent_state` reports `Absent` only when `metadata`
/// on it returned `ENOENT`, which needs search on everything above it, and
/// [`deepest_existing`] walks no further than that.
///
/// Every mode on disk that denies search is therefore unreachable here,
/// whether or not it denies write, and every mode on disk that reaches here and
/// denies write allows search. `a_parent_bx_cannot_search_stops_the_run_before
/// _any_decision` is the witness, and it asserts the failure rather than
/// describing it, so the argument is recomputed on every run rather than taken
/// on trust.
///
/// # A declared directory is read at its declared mode
///
/// Once directory targets are written, the argument above holds only for the
/// disk. A directory a target declares is made or set to its mode before any
/// file is written — see [`decide_all`] — so the mode a write beneath it meets
/// is the declared one, and that one was never observed: a `0600` declaration
/// denies its owner search, and `observe` never saw it do so. So a declared
/// directory is read from [`Ctx::declared`] in place of the disk, and both
/// owner bits are tested, write first. Walking up from the parent, the first
/// directory that is declared or already there governs the write; every one
/// between it and the parent is made by `apply` at [`Mode::DEFAULT_DIR`], or
/// is declared itself and would have governed. A declared directory further up
/// is searched on the way, so each one above the governing directory is tested
/// for owner search as well: see [`unreachable_beneath`].
///
/// `write` says what `apply` does inside the parent. A directory whose mode
/// alone changes is chmod'd in place, which needs search on the parent and not
/// write, so for it only search is tested; the directory is already there, so
/// its parent is too and governs the change.
fn locked_parent(
    observed: &Observed,
    home: &Path,
    declared: &Declared,
    write: Write<'_>,
) -> Option<String> {
    let parent = observed.parent.as_ref()?;
    if parent.unusable().is_some() {
        return None;
    }
    let (dir, mode, is_declared) = governing(&parent.path, declared)?;
    let needs_write = !matches!(write, Write::Chmod(_));
    let denied = if needs_write && mode.bits() & 0o200 == 0 {
        "write"
    } else if mode.bits() & 0o100 == 0 {
        "search"
    } else {
        return unreachable_beneath(dir, &parent.path, home, declared);
    };
    let shown = paths::to_portable(dir, home);
    let basis = if is_declared {
        format!("{shown} is declared {mode}")
    } else {
        format!("{shown} is {mode} on disk")
    };
    let what = match (dir == parent.path, write) {
        (true, Write::File) => "write a file".to_string(),
        (true, Write::Create(made)) => format!("create {}", paths::to_portable(made, home)),
        (true, Write::Chmod(changed)) => {
            format!("change the mode of {}", paths::to_portable(changed, home))
        }
        (false, _) => format!("create {}", paths::to_portable(&parent.path, home)),
    };
    Some(format!(
        "{basis}, which denies its owner {denied}, so apply could not {what} inside it"
    ))
}

/// Why the parent of a write cannot be reached: a declared directory above the
/// one that governs the write, `governing`, that denies its owner search.
///
/// Every directory on the way to the parent is searched to reach it, not only
/// the one that governs the write. One on disk that denies search already
/// stopped [`crate::fs::observe`], and one `apply` makes is made at
/// [`Mode::DEFAULT_DIR`], but a declared one is set to its declared mode before
/// any write beneath it and was never observed at that mode. So each declared
/// ancestor of `governing` is tested here, the nearest first.
fn unreachable_beneath(
    governing: &Path,
    parent: &Path,
    home: &Path,
    declared: &Declared,
) -> Option<String> {
    governing.ancestors().skip(1).find_map(|dir| {
        let mode = *declared.get(dir)?;
        (mode.bits() & 0o100 == 0).then(|| {
            format!(
                "{} is declared {mode}, which denies its owner search, so apply could not \
                 reach {} beneath it",
                paths::to_portable(dir, home),
                paths::to_portable(parent, home)
            )
        })
    })
}

/// What `apply` does inside the parent [`locked_parent`] tests.
#[derive(Debug, Clone, Copy)]
enum Write<'a> {
    /// Writes a file.
    File,
    /// Makes the directory named.
    Create(&'a Path),
    /// Sets the mode of the directory named, which is already there.
    Chmod(&'a Path),
}

/// The directory that governs a write into `dir`: `dir` or the deepest
/// ancestor of it that is declared or already a directory, with the mode the
/// write will meet there and whether that mode is a declaration.
///
/// On disk it is read with `metadata`, which follows symlinks, because a
/// symlinked parent is written *through* — decision 2 — so the directory that
/// governs the write is the one the link resolves to, exactly as
/// [`crate::fs::observe`] reads it.
fn governing<'a>(dir: &'a Path, declared: &Declared) -> Option<(&'a Path, Mode, bool)> {
    use std::os::unix::fs::PermissionsExt as _;

    dir.ancestors()
        .filter(|path| !path.as_os_str().is_empty())
        .find_map(|path| {
            if let Some(mode) = declared.get(path) {
                return Some((path, *mode, true));
            }
            let meta = std::fs::metadata(path).ok()?;
            meta.is_dir()
                .then(|| (path, Mode::from_bits(meta.permissions().mode()), false))
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
    /// copy of a tracked target written onto this machine, which stays the
    /// tool's — journalled like any write, so an interruption is rolled back,
    /// and recorded in no ledger entry, so `rm` never touches it.
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
            region_ownership(outcome.action, &observed, entry, comment, note)
        }
        _ => ownership(outcome.action, &observed, entry, note),
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

/// Decide a directory target: create it, set its mode, leave it, or refuse.
///
/// The verdict is [`crate::fs::compare_dir`]'s, the one [`crate::fs::ensure_dir`]
/// checks again before it acts, settled against the ledger by
/// [`dir_ownership`]. A create is also refused when the directory it would be
/// made in denies its owner write or search, as a file's write is, and a mode
/// change when the directory it is in denies its owner search. Only the
/// directory is decided, never what is inside it, and a mode change is shown
/// as one: there are no bytes to diff.
fn decide_dir(
    target: &Target,
    ctx: &Ctx<'_>,
    row: impl Fn(Action, Option<Diff>, Option<String>) -> Change,
) -> Result<(Change, Option<Op>), Error> {
    let dest = target.path.render(ctx.home);
    if dest.parent().is_none() {
        let note = "the filesystem root is not a directory bx can create or change";
        return Ok((row(Action::Blocked, None, Some(note.to_string())), None));
    }
    let observed = fs::observe(&dest)?;
    let mode = Mode::resolve(target.mode, Kind::Dir);
    let outcome = fs::compare_dir(&observed, mode);
    let note = observed
        .parent
        .as_ref()
        .and_then(|parent| {
            let reason = parent.unusable()?;
            Some(portable_reason(&parent.path, reason, ctx.home))
        })
        .or(outcome.note);
    let (action, note) = dir_ownership(
        outcome.action,
        &observed,
        ctx.ledger.get(&target.path),
        note,
    );
    // Both writes are refused when the parent will deny them, as a file's
    // is: a create needs write and search there, a mode change search.
    let write = match action {
        Action::Create => Some(Write::Create(&dest)),
        Action::Modify => Some(Write::Chmod(&dest)),
        _ => None,
    };
    let (action, note) =
        match write.and_then(|write| locked_parent(&observed, ctx.home, ctx.declared, write)) {
            Some(why) => (Action::Conflict, join([Some(why), note])),
            None => (action, note),
        };

    let diff = match (action, outcome.mode_drift) {
        (Action::Modify, Some((from, to))) => Some(Diff::mode(from, to)),
        _ => None,
    };
    let note = match action {
        Action::Create => {
            let parents = missing_parents(&dest, ctx.declared);
            let named = parents
                .iter()
                .map(|dir| {
                    format!(
                        "{} {}",
                        paths::to_portable(dir, ctx.home),
                        Mode::DEFAULT_DIR
                    )
                })
                .chain([format!("{} {mode}", paths::to_portable(&dest, ctx.home))])
                .collect::<Vec<_>>();
            join([Some(format!("creates {}", named.join(", "))), note])
        }
        _ => note,
    };
    let change = row(action, diff, note);
    let op = action.is_pending().then(|| Op {
        target: target.path.clone(),
        dest,
        made: Made::Dir,
        planned: observed,
        mode,
        claimed: true,
        carry: false,
    });
    Ok((change, op))
}

/// Settle what [`crate::fs::compare_dir`] found against what the ledger says
/// bx owns.
///
/// A directory bx does not record yet is created where nothing is there, and
/// set to its declared mode where it is: its mode is all bx changes, and the
/// mode it had is recorded so `rm` puts it back. What is refused is a
/// directory the ledger says bx attached to some other way, and one bx set
/// whose mode has changed since — the user's change, which a write would
/// undo.
fn dir_ownership(
    action: Action,
    observed: &Observed,
    entry: Option<&LedgerEntry>,
    note: Option<String>,
) -> (Action, Option<String>) {
    let conflict = |why: String| (Action::Conflict, join([Some(why), note.clone()]));
    match (action, entry) {
        (Action::Create | Action::Modify, Some(entry)) if entry.mechanism != Mechanism::Dir => {
            conflict(format!(
                "bx attached to this path as {}",
                attached_as(&entry.mechanism)
            ))
        }
        (Action::Modify, Some(entry)) if observed.mode != Some(entry.mode) => conflict(format!(
            "its mode changed since bx set it to {}",
            entry.mode
        )),
        _ => (action, note),
    }
}

/// Decide a symlink target: make the link, retarget one bx made, leave it, or
/// refuse.
///
/// A link is compared by its text alone, read with `readlink` and never
/// resolved, so whether anything is at the far end changes nothing: a
/// dangling link is created and kept like any other. What is at the
/// destination decides the rest:
///
/// * nothing is a create, and a link already holding the text is unchanged —
///   adopted as it stands, with nothing written or recorded, as a file already
///   holding a file target's bytes is;
/// * a link holding other text is a modify only when bx made it and it still
///   holds what bx left there, settled by [`link_ownership`];
/// * a regular file, a directory or anything else is never replaced by a link.
///
/// A modify is shown as the old and new text, never as a content diff.
fn decide_link(
    target: &Target,
    text: PathBuf,
    ctx: &Ctx<'_>,
    row: impl Fn(Action, Option<Diff>, Option<String>) -> Change,
) -> Result<(Change, Option<Op>), Error> {
    let dest = target.path.render(ctx.home);
    let observed = fs::observe(&dest)?;
    let (action, note) = match (
        observed.parent.as_ref().and_then(|p| p.unusable()),
        observed.kind,
    ) {
        (Some(reason), _) => {
            let parent = observed.parent.as_ref().map_or(dest.as_path(), |p| &p.path);
            (
                Action::Conflict,
                Some(portable_reason(parent, reason, ctx.home)),
            )
        }
        (None, Kind::Absent) => (Action::Create, None),
        // Byte for byte: `Path` equality compares normalised components, so
        // `/opt/x/` would equal `/opt/x` and a retarget that changes how the
        // link resolves would never be delivered.
        (None, Kind::Symlink)
            if observed.link.as_deref().map(Path::as_os_str) == Some(text.as_os_str()) =>
        {
            (Action::Unchanged, None)
        }
        (None, Kind::Symlink) => (Action::Modify, None),
        (None, Kind::File) => (
            Action::Conflict,
            Some("a regular file, where the target declares a symlink".to_string()),
        ),
        (None, Kind::Dir) => (
            Action::Conflict,
            Some("a directory, where the target declares a symlink".to_string()),
        ),
        (None, Kind::Other) => (Action::Conflict, Some("not a symlink".to_string())),
    };
    let (action, note) = link_ownership(action, &observed, ctx.ledger.get(&target.path), note);
    // Making a link writes an entry in its parent, as a file's write does.
    let (action, note) = match (
        action.is_pending(),
        locked_parent(&observed, ctx.home, ctx.declared, Write::File),
    ) {
        (true, Some(why)) => (Action::Conflict, join([Some(why), note])),
        _ => (action, note),
    };
    // A link on either side has text to show; anything else is explained by
    // the note alone.
    let diff = match action {
        Action::Create | Action::Modify => Some(Diff::link(observed.link.as_deref(), Some(&text))),
        Action::Conflict if observed.kind == Kind::Symlink => {
            Some(Diff::link(observed.link.as_deref(), Some(&text)))
        }
        Action::Conflict
        | Action::Unchanged
        | Action::Sync
        | Action::Undeclared
        | Action::Blocked => None,
    };
    let note = match action {
        Action::Create => join([created_dirs(&observed, ctx.home, ctx.declared), note]),
        _ => note,
    };
    let change = row(action, diff, note);
    let op = action.is_pending().then(|| Op {
        target: target.path.clone(),
        dest,
        made: Made::Link(text),
        planned: observed,
        mode: Mode::LINK,
        claimed: true,
        carry: false,
    });
    Ok((change, op))
}

/// Settle what [`decide_link`] found against what the ledger says bx owns.
///
/// Only a link bx made, still holding the text bx left in it, is retargeted:
/// a link bx did not make is the user's, and one bx made that holds other text
/// now was retargeted by somebody else, whose change a write would undo. A
/// path the ledger says bx attached to some other way is refused as well.
fn link_ownership(
    action: Action,
    observed: &Observed,
    entry: Option<&LedgerEntry>,
    note: Option<String>,
) -> (Action, Option<String>) {
    let conflict = |why: String| (Action::Conflict, join([Some(why), note.clone()]));
    match (action, entry) {
        (Action::Create | Action::Modify, Some(entry)) if entry.mechanism != Mechanism::Link => {
            conflict(format!(
                "bx attached to this path as {}",
                attached_as(&entry.mechanism)
            ))
        }
        (Action::Modify, None) => {
            conflict("a symlink bx did not make; bx will not retarget a link you created".into())
        }
        (Action::Modify, Some(entry)) if observed.link_digest() != Some(entry.written) => {
            conflict("retargeted since bx made it".to_string())
        }
        _ => (action, note),
    }
}

/// The parent note a file gets when its parent is a declared directory: the
/// declared mode is the one the file will sit in, whatever is on disk now.
///
/// `None` when the parent is not declared, so the comparison's own note
/// stands; `Some(None)` when the declared mode is not wider than the file's.
fn parent_note(observed: &Observed, mode: Mode, ctx: &Ctx<'_>) -> Option<Option<String>> {
    let parent = observed.parent.as_ref()?;
    let declared = *ctx.declared.get(&parent.path)?;
    Some(declared.is_wider_than(mode).then(|| {
        format!(
            "{} is declared {declared}, wider than the {mode} this file declares",
            paths::to_portable(&parent.path, ctx.home)
        )
    }))
}

/// The directories a write to `observed` creates, shallowest first — the order
/// `apply` makes them in — each with the mode it is made at, or `None` when
/// the parent is already there or a directory target makes every one missing.
///
/// The observation says whether the parent is absent and the mode it would be
/// made at. A missing directory a directory target makes — the declared one,
/// or one on the way to it — is that target's row to name, since its write
/// runs first. Which ancestors are missing is read here with the walk `stage`
/// makes before creating them.
fn created_dirs(observed: &Observed, home: &Path, declared: &Declared) -> Option<String> {
    let parent = observed.parent.as_ref()?;
    let crate::fs::ParentState::Absent(mode) = &parent.state else {
        return None;
    };
    let mut missing = missing_parents(&observed.path, declared);
    missing.reverse();
    (!missing.is_empty()).then(|| {
        let named: Vec<String> = missing
            .iter()
            .map(|dir| format!("{} {mode}", paths::to_portable(dir, home)))
            .collect();
        format!("creates {}", named.join(", "))
    })
}

/// The ancestors of `path` that are not there, deepest first, less any a
/// declared directory's write makes: the declared directory itself, or one on
/// the way to it.
fn missing_parents<'a>(path: &'a Path, declared: &Declared) -> Vec<&'a Path> {
    path.ancestors()
        .skip(1)
        .filter(|dir| !dir.as_os_str().is_empty())
        .take_while(|dir| {
            matches!(
                std::fs::symlink_metadata(dir),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            )
        })
        .filter(|dir| !declared.keys().any(|made| made.starts_with(dir)))
        .collect()
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
            let present = |tool: &str| detect::locate_in_env(tool).is_usable();
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
/// # Decision: the machine's copy is never bx's
///
/// Where `apply` writes the repo's copy onto this machine, the write is
/// journalled — an interruption is rolled back like any other — but claimed in
/// no ledger entry. The tool rewrites the file as it pleases, and an entry
/// would turn its next rewrite into "edited since bx last wrote it" and make
/// `rm` put back bytes the tool has long replaced. So the machine's copy is
/// compared with the agreement, never with the ledger, and `rm` leaves it
/// alone.
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
    let why = match (unusable, outcome.action) {
        (Some(reason), _) => Some(reason),
        (None, Action::Conflict) => Some(outcome.note.unwrap_or_default()),
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
        claimed: false,
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
    let why = match (unusable, outcome.action) {
        (Some(reason), _) => Some(reason),
        (None, Action::Conflict) => Some(outcome.note.unwrap_or_default()),
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

/// Judge a generated body against Invariant 2, as what it is.
///
/// An environment fragment goes through the guard in its own syntax. The line
/// a region sources a fragment with sets nothing, so it is not a fragment:
/// the guard's grammar would refuse it as unreadable, and `env_guard`'s tests
/// hold its bytes to carrying no assignment instead.
///
/// The interactive file is judged by its `env` phase alone, rendered with the
/// same `present` as the file, since that phase is its one environment
/// fragment; every other phase holds plugin and alias lines that set nothing,
/// and function definitions whose registrations assign only zsh's hook
/// arrays, which the guard's grammar would refuse as unreadable. The tests of
/// [`crate::config::target::Interactive`] hold the plugin and alias lines to
/// carrying no assignment, and those of [`crate::shell::function`] and this
/// module hold the `functions` phase to changing no parameter but a hook
/// array.
/// A line number in the note is still the file's own: the phase is found in
/// the file's bytes, and each line is counted from the top of the file.
///
/// bash's interactive file is judged the same way: by its `env` and `path`
/// phases, its one environment fragment, and the history file it names. Its alias lines
/// set nothing, its functions and sources are held to what zsh's are, its
/// activations to the relocation rule, and its `options` phase assigns only
/// bash's own history variables, unexported, which [`crate::shell::bash`]'s
/// tests hold it to.
/// `~/.inputrc` is readline's syntax and names no variable.
fn guard_generated(
    generator: &Gen,
    content: &str,
    roots: &RootSet,
    present: &dyn Fn(&str) -> bool,
) -> Option<String> {
    match generator {
        Gen::Env(fragment) => match fragment.syntax {
            Syntax::Zsh => guard_fragment(content, roots),
            Syntax::EnvironmentD => guard_environment_d(content, roots),
        },
        Gen::Interactive(file) => {
            let env = file.env().render(present);
            let before = content
                .find(&env)
                .map_or(0, |at| content[..at].matches('\n').count());
            join([
                guard_fragment_after(&env, roots, before),
                guard_history_file("zsh", file.history().zsh_file.as_ref(), roots),
            ])
        }
        // The fragment is the file's first bytes, so its lines are numbered
        // as the file's own.
        Gen::Bash(file) => {
            let env = file.env(present);
            join([
                guard_fragment(&env, roots),
                guard_history_file("bash", file.history().bash_file.as_ref(), roots),
            ])
        }
        Gen::Source(_) | Gen::Inputrc(_) => None,
    }
}

/// Judge a declared history file against Invariant 2: the one path an
/// interactive file's `options` phase names, for `shell`.
///
/// zsh keeps no history file unless one is named, and bash's default is its
/// own, so naming one moves nothing and needs no root; but the shell writes
/// every command line typed into it, so it may not lie inside a directory bx
/// owns, nor inside the config repo, where it would be committed. Rendered
/// against the set's home, the same home `${HOME}` is at shell start.
fn guard_history_file(shell: &str, file: Option<&Portable>, roots: &RootSet) -> Option<String> {
    let file = file?;
    let path = roots
        .home()
        .map_or_else(|| PathBuf::from(file.as_str()), |home| file.render(home));
    env_guard::refuses_bx_location(&path, roots)
        .map(|reason| format!("[history] {shell} file {file} {reason}"))
}

/// Judge a generated environment fragment against Invariant 2.
///
/// `None` when every assignment is one bx may write; otherwise one note naming
/// each violation as `line N: NAME <reason>`. Applied to generated bodies only:
/// the guard's grammar admits nothing but assignments, and a file the user
/// wrote is not bx's output to judge.
pub(super) fn guard_fragment(content: &str, roots: &RootSet) -> Option<String> {
    guard_fragment_after(content, roots, 0)
}

/// [`guard_fragment`] for a fragment that is one part of a file, preceded in
/// it by `before` lines, so each line the note names is the file's own.
fn guard_fragment_after(content: &str, roots: &RootSet, before: usize) -> Option<String> {
    violations(&env_guard::scan_with(content, roots), before)
}

/// [`guard_fragment`] for an `environment.d` fragment, where every line is
/// exported although none says `export`.
fn guard_environment_d(content: &str, roots: &RootSet) -> Option<String> {
    violations(&env_guard::scan_exported(content, roots), 0)
}

/// One note naming each violation as `line N: NAME <reason>`, each line moved
/// down by the `before` lines the scanned content is preceded by in its file.
fn violations(found: &[env_guard::Violation], before: usize) -> Option<String> {
    join(
        found
            .iter()
            .map(|v| Some(format!("line {}: {} {}", v.line + before, v.name, v.reason))),
    )
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

/// The row for a ledger entry no enabled target or external declares: a file
/// bx wrote whose declaration is gone, reported and never acted on.
///
/// The row is [`Action::Undeclared`] while what is on disk is still what bx
/// left, or nothing at all, and names `bx rm` as the way to release it. When
/// the destination has drifted since — edited, retargeted, its mode changed,
/// or something of another kind in its place — it is an [`Action::Conflict`]
/// saying why, as drift is for a declared target, and nothing is overwritten
/// either way. `bx rm` refuses to restore over the same drift, so such a note
/// says so rather than promising a release; a file whose mode alone changed
/// is still one `bx rm` hands back. A checkout's commit is git's to read, so a
/// clone is judged by whether its directory is there alone, and `bx rm` says
/// itself when a checkout holds work it will not remove.
///
/// No diff: bx no longer knows what it would write, and it writes nothing.
/// A destination that cannot be observed is reported as undeclared with the
/// reason, rather than stopping a run over a file nothing declares.
pub(super) fn decide_undeclared(entry: &LedgerEntry, origin: &Origin, home: &Path) -> Change {
    let path = entry.path.as_str();
    let rm = rm_argument(path);
    let undeclared = "the configuration no longer declares it, so bx leaves it as it is";
    let release = format!("{undeclared}; `bx rm {rm}` releases it");
    let (action, why, release) = match fs::observe(&entry.path.render(home)) {
        Err(error) => (
            Action::Undeclared,
            Some(format!("bx cannot look at it now: {error}")),
            release,
        ),
        Ok(observed) => match drift(entry, &observed) {
            Some(Drift { why, released }) => (
                Action::Conflict,
                Some(why),
                if released {
                    release
                } else {
                    format!("{undeclared}, and `bx rm {rm}` will not restore over the change")
                },
            ),
            None if observed.kind == Kind::Absent => (
                Action::Undeclared,
                Some("it is no longer on disk".to_string()),
                release,
            ),
            None => (Action::Undeclared, None, release),
        },
    };
    Change {
        target: path.to_string(),
        origin: origin.clone(),
        action,
        diff: None,
        note: join([why, Some(release)]),
    }
}

/// How a destination differs from what its ledger entry says bx left there.
struct Drift {
    /// Why it is not what bx left, as a row says it.
    why: String,
    /// Whether `bx rm` still hands it back: only when a file bx owns whole
    /// still holds bx's bytes, and its mode alone changed.
    released: bool,
}

/// How `observed` differs from what `entry` says bx left there, or `None`
/// when it is still bx's, or gone.
fn drift(entry: &LedgerEntry, observed: &Observed) -> Option<Drift> {
    let refused = |why: String| {
        Some(Drift {
            why,
            released: false,
        })
    };
    let expected = match entry.mechanism {
        Mechanism::Dir | Mechanism::Clone => Kind::Dir,
        Mechanism::Link => Kind::Symlink,
        Mechanism::Own | Mechanism::Region { .. } | Mechanism::Include { .. } => Kind::File,
    };
    match observed.kind {
        Kind::Absent => return None,
        kind if kind != expected => {
            return refused(format!(
                "bx left {} here, and something else is there now",
                attached_as(&entry.mechanism)
            ));
        }
        _ => {}
    }
    match entry.mechanism {
        Mechanism::Own | Mechanism::Region { .. } | Mechanism::Include { .. }
            if observed.digest() != Some(entry.written) =>
        {
            refused("edited since bx last wrote it".to_string())
        }
        Mechanism::Own if observed.mode != Some(entry.mode) => Some(Drift {
            why: "its mode changed since bx wrote it".to_string(),
            released: true,
        }),
        Mechanism::Dir if observed.mode != Some(entry.mode) => refused(format!(
            "its mode changed since bx set it to {}",
            entry.mode
        )),
        Mechanism::Link if observed.link_digest() != Some(entry.written) => {
            refused("retargeted since bx made it".to_string())
        }
        _ => None,
    }
}

/// `path` as one word a shell passes to `bx rm` unchanged: bare when it holds
/// nothing a shell would read, single-quoted otherwise. A leading `~/` stays
/// inside the quotes, which `bx rm` reads as the home itself.
fn rm_argument(path: &str) -> std::borrow::Cow<'_, str> {
    let plain = |c: char| c.is_ascii_alphanumeric() || "~/._-+,@%=:".contains(c);
    if !path.is_empty() && path.chars().all(plain) && !path[1..].contains('~') {
        std::borrow::Cow::Borrowed(path)
    } else {
        std::borrow::Cow::Owned(crate::shell::alias::quote(path))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::config::target::KeyPath;
    use crate::testing::guarded_home;

    fn a_target(home: &Path, path: &str) -> Target {
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

    mod undeclared {
        use std::os::unix::fs::PermissionsExt as _;

        use super::*;
        use crate::state::{ContentHash, Prior};
        use crate::testing::GuardedHome;

        /// An entry saying bx left `written` at `~/rel`, attached as
        /// `mechanism`, at `mode`.
        fn entry(
            home: &GuardedHome,
            rel: &str,
            written: &[u8],
            mode: u32,
            mechanism: Mechanism,
        ) -> LedgerEntry {
            LedgerEntry {
                path: Portable::parse_in(&format!("~/{rel}"), home.path()).expect("portable"),
                written: ContentHash::of(written),
                mode: Mode::from_bits(mode),
                mechanism,
                prior: Prior::Absent,
                created_dirs: Vec::new(),
                superseded: Vec::new(),
                superseded_absent: false,
            }
        }

        fn decided(home: &GuardedHome, entry: &LedgerEntry) -> (Action, String) {
            let change = decide_undeclared(entry, &Origin::unknown(Path::new("/l")), home.path());
            assert_eq!(change.diff, None, "an undeclared row never has a diff");
            (change.action, change.note.expect("a note"))
        }

        fn why(home: &GuardedHome, entry: &LedgerEntry) -> (Action, String) {
            let (action, note) = decided(home, entry);
            let why = note
                .split_once("; the configuration")
                .map_or_else(String::new, |(why, _)| why.to_string());
            (action, why)
        }

        #[test]
        fn a_region_is_judged_by_the_whole_file_and_not_its_mode() {
            let home = guarded_home();
            home.write(".r", "mine\n");
            std::fs::set_permissions(home.child(".r"), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
            let region = Mechanism::Region { comment: '#' };
            let kept = entry(&home, ".r", b"mine\n", 0o644, region.clone());
            assert_eq!(why(&home, &kept), (Action::Undeclared, String::new()));

            let edited = entry(&home, ".r", b"other\n", 0o600, region);
            assert_eq!(
                why(&home, &edited),
                (
                    Action::Conflict,
                    "edited since bx last wrote it".to_string()
                )
            );
        }

        #[test]
        fn a_file_whose_mode_changed_is_a_conflict() {
            let home = guarded_home();
            home.write(".a", "a\n");
            std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
            let owned = entry(&home, ".a", b"a\n", 0o644, Mechanism::Own);
            assert_eq!(
                why(&home, &owned),
                (
                    Action::Conflict,
                    "its mode changed since bx wrote it".to_string()
                )
            );
            // `bx rm` hands back a file whose bytes are still bx's, whatever
            // its mode, so the note still says it does.
            let (_, note) = decided(&home, &owned);
            assert!(note.ends_with("`bx rm ~/.a` releases it"), "{note}");
        }

        #[test]
        fn a_directory_is_judged_by_its_mode() {
            let home = guarded_home();
            std::fs::create_dir(home.child("d")).expect("mkdir");
            std::fs::set_permissions(home.child("d"), std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
            let same = entry(&home, "d", b"", 0o700, Mechanism::Dir);
            assert_eq!(why(&home, &same), (Action::Undeclared, String::new()));

            let set = entry(&home, "d", b"", 0o755, Mechanism::Dir);
            assert_eq!(
                why(&home, &set),
                (
                    Action::Conflict,
                    "its mode changed since bx set it to 0755".to_string()
                )
            );
        }

        #[test]
        fn a_link_is_judged_by_its_text() {
            let home = guarded_home();
            std::os::unix::fs::symlink("there", home.child("l")).expect("a link");
            let same = entry(&home, "l", b"there", 0o777, Mechanism::Link);
            assert_eq!(why(&home, &same), (Action::Undeclared, String::new()));

            let moved = entry(&home, "l", b"elsewhere", 0o777, Mechanism::Link);
            assert_eq!(
                why(&home, &moved),
                (Action::Conflict, "retargeted since bx made it".to_string())
            );
        }

        #[test]
        fn a_checkout_is_judged_by_whether_its_directory_is_there() {
            let home = guarded_home();
            std::fs::create_dir(home.child("c")).expect("mkdir");
            let clone = entry(&home, "c", b"any commit", 0o755, Mechanism::Clone);
            assert_eq!(why(&home, &clone), (Action::Undeclared, String::new()));
        }

        #[test]
        fn something_of_another_kind_in_its_place_is_a_conflict() {
            let home = guarded_home();
            std::fs::create_dir(home.child(".a")).expect("mkdir");
            let owned = entry(&home, ".a", b"a\n", 0o644, Mechanism::Own);
            assert_eq!(
                why(&home, &owned),
                (
                    Action::Conflict,
                    "bx left the whole file here, and something else is there now".to_string()
                )
            );
        }

        #[test]
        fn a_destination_bx_cannot_look_at_is_reported_with_the_reason() {
            let home = guarded_home();
            home.write(".f", "a file\n");
            let beneath = entry(&home, ".f/x", b"x\n", 0o644, Mechanism::Own);
            let (action, note) = decided(&home, &beneath);
            // Observing beneath a regular file either fails, which is named,
            // or finds nothing there; neither stops the run or is a conflict.
            assert_eq!(action, Action::Undeclared, "{note}");
            assert!(note.ends_with("`bx rm ~/.f/x` releases it"), "{note}");
        }

        #[test]
        fn the_rm_argument_is_quoted_only_where_a_shell_would_read_it() {
            assert_eq!(rm_argument("~/.config/x-y_z.toml"), "~/.config/x-y_z.toml");
            assert_eq!(rm_argument("~/a b"), "'~/a b'");
            assert_eq!(rm_argument("~/it's"), r"'~/it'\''s'");
            assert_eq!(rm_argument("~/a~b"), "'~/a~b'");
            assert_eq!(rm_argument("~/$HOME"), "'~/$HOME'");
            assert_eq!(rm_argument(""), "''");
        }
    }

    #[test]
    fn t8_the_fragment_guard_names_the_line_and_admits_what_it_allows() {
        let note = guard_fragment("CARGO_HOME=/elsewhere\n", &RootSet::strict())
            .expect("a relocation with no root is a violation");
        assert!(note.starts_with("line 1: CARGO_HOME "), "{note}");

        let two = guard_fragment(
            "export EDITOR=nvim\nCARGO_HOME=/a\nRUSTUP_HOME=/b\n",
            &RootSet::strict(),
        )
        .expect("two violations");
        assert!(two.contains("line 2: CARGO_HOME "), "{two}");
        assert!(two.contains("; line 3: RUSTUP_HOME "), "{two}");

        assert_eq!(
            guard_fragment("export EDITOR=nvim\n", &RootSet::strict()),
            None
        );
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

    /// A directory target at `~/.d` declared `mode`, then `children`.
    fn a_directory_target(mode: &str, children: &str) -> String {
        format!("[[target]]\npath = \"~/.d\"\ndir = true\nmode = \"{mode}\"\n{children}")
    }

    /// The row `plan` gives `target` in `report`.
    fn row_for<'r>(report: &'r crate::plan::Report, target: &str) -> &'r Change {
        report
            .changes
            .iter()
            .find(|change| change.target == target)
            .unwrap_or_else(|| panic!("no row for {target}: {report:?}"))
    }

    /// A directory at `~/rel`, made at `mode`, reopened to its owner when the
    /// returned guard drops so the tempdir home can still be cleaned up.
    fn locked_dir_at(home: &Path, rel: &str, mode: u32) -> impl Drop {
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

    #[test]
    fn decision_24_a_file_whose_existing_parent_denies_its_owner_write_is_a_conflict() {
        // P42R2-D1 and P42R2-COV1. The parent is on disk at a mode that denies
        // its owner write, and NO directory target declares it — the case the
        // declared-mode rule this replaces could not see, and the one that
        // occurs in real homes. At 5d1bba7 `plan` printed `Create` with no note
        // at all, `apply` failed with EACCES part-way through, the journal was
        // left standing, and the next `plan` reported an interruption with zero
        // rows: every configured target undecided.
        //
        // 0500 denies write and allows search; 0100 denies read as well. Both
        // reach the rule. A mode denying *search* cannot — see
        // `a_parent_bx_cannot_search_stops_the_run_before_any_decision`.
        for mode in [0o500_u32, 0o100] {
            let home = guarded_home();
            let inputs = crate::plan::tests::inputs(
                &home,
                &crate::plan::tests::inline("~/locked/conf", "x\\n"),
            );
            let _unlock = locked_dir_at(home.path(), "locked", mode);

            let report = crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false))
                .expect("plan");

            let file = row_for(&report, "~/locked/conf");
            assert!(
                !file.action.is_pending(),
                "{mode:04o}: plan announced work apply cannot do: {file:?}"
            );
            assert_eq!(file.action, Action::Conflict, "{mode:04o}: {file:?}");
            let note = file.note.as_deref().expect("a note");
            assert!(
                note.contains("~/locked")
                    && note.contains(&format!("{mode:04o}"))
                    && note.contains("denies its owner write"),
                "{mode:04o}: {note}"
            );

            // Invariant 7: apply does exactly what plan announced, which here
            // is nothing. It must not fail, and must leave no journal standing.
            let applied = crate::plan::run(&inputs, crate::plan::Mode::Apply, &mut |_| Ok(true))
                .expect("apply must not fail on a row plan refused");
            assert!(!applied.executed, "{mode:04o}: apply wrote");
            assert!(
                !crate::state::StateDir::resolve(home.path())
                    .journal()
                    .exists(),
                "{mode:04o}: apply left a journal standing"
            );
            assert!(
                !home.child("locked/conf").exists(),
                "{mode:04o}: apply created the file"
            );
        }
    }

    #[test]
    fn decision_24_an_absent_parent_beneath_an_unwritable_one_names_what_cannot_be_created() {
        // The parent itself is absent, so the directory that governs the write
        // is the deepest ancestor that is there: the one `apply` would make its
        // first `mkdir` in.
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(
            &home,
            &crate::plan::tests::inline("~/locked/a/b/conf", "x\\n"),
        );
        let _unlock = locked_dir_at(home.path(), "locked", 0o500);

        let report =
            crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false)).expect("plan");

        let file = row_for(&report, "~/locked/a/b/conf");
        assert_eq!(file.action, Action::Conflict, "{file:?}");
        let note = file.note.as_deref().expect("a note");
        assert!(
            note.contains("~/locked is 0500 on disk")
                && note.contains("could not create ~/locked/a/b inside it"),
            "{note}"
        );
        assert!(!home.child("locked/a").exists(), "a directory was made");
    }

    #[test]
    fn a_parent_bx_cannot_search_stops_the_run_before_any_decision() {
        // The witness for `locked_parent`'s argument that search denial cannot
        // reach it. Asserted rather than described, so it is recomputed every
        // run: were `observe` ever to tolerate EACCES, this fails and the
        // argument in that doc comment has to be reopened.
        //
        // 0600 denies search and ALLOWS write — the one combination that would
        // need a note `locked_parent` does not write.
        let home = guarded_home();
        let inputs =
            crate::plan::tests::inputs(&home, &crate::plan::tests::inline("~/locked/conf", "x\\n"));
        let _unlock = locked_dir_at(home.path(), "locked", 0o600);

        let error = crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false))
            .expect_err("a parent bx cannot search stops the run");

        assert!(
            matches!(&error, crate::plan::Error::Fs(fs::Error::Read { .. })),
            "{error:?}"
        );
    }

    /// `plan`, over `inputs`.
    fn plan_of(inputs: &crate::plan::Inputs) -> crate::plan::Report {
        crate::plan::run(inputs, crate::plan::Mode::Plan, &mut |_| Ok(false)).expect("plan")
    }

    /// `apply`, approved, over `inputs`.
    fn apply_of(inputs: &crate::plan::Inputs) -> crate::plan::Report {
        crate::plan::run(inputs, crate::plan::Mode::Apply, &mut |_| Ok(true)).expect("apply")
    }

    /// The mode on disk at `~/rel`.
    fn mode_on_disk(home: &Path, rel: &str) -> Option<Mode> {
        crate::journal::tests::mode_at(&home.join(rel))
    }

    #[test]
    fn a_file_beneath_a_directory_declared_without_owner_write_is_a_conflict() {
        // The declared 0555 now reaches disk before the file would be written,
        // so the file is refused in plan rather than failing apply with
        // EACCES. The control arm is the same file with no directory target:
        // its parent is made at 0755 and it is written.
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(
            &home,
            &a_directory_target("0555", &crate::plan::tests::inline("~/.d/f", "x\\n")),
        );

        let report = plan_of(&inputs);
        assert_eq!(row_for(&report, "~/.d").action, Action::Create);
        let file = row_for(&report, "~/.d/f");
        assert_eq!(file.action, Action::Conflict, "{report:?}");
        assert_eq!(
            file.note.as_deref(),
            Some(
                "~/.d is declared 0555, which denies its owner write, so apply could not write \
                 a file inside it"
            )
        );

        let applied = apply_of(&inputs);
        assert!(applied.executed);
        assert_eq!(
            mode_on_disk(home.path(), ".d"),
            Some(Mode::from_bits(0o555))
        );
        assert!(!home.child(".d/f").exists());
        assert!(
            !crate::state::StateDir::resolve(home.path())
                .journal()
                .exists(),
            "apply did exactly what plan announced, and finished"
        );

        let control = guarded_home();
        let inputs =
            crate::plan::tests::inputs(&control, &crate::plan::tests::inline("~/.d/f", "x\\n"));
        assert_eq!(row_for(&plan_of(&inputs), "~/.d/f").action, Action::Create);
        assert!(apply_of(&inputs).executed);
        assert_eq!(mode_on_disk(control.path(), ".d"), Some(Mode::DEFAULT_DIR));
    }

    #[test]
    fn a_symlink_whose_parent_denies_its_owner_write_or_search_is_a_conflict() {
        // Making a link writes an entry in its parent, so `decide_link` asks
        // `locked_parent` as a file's write does: one parent on disk that
        // denies write, and one declared at a mode that denies search.
        let link = |path: &str| format!("[[target]]\npath = \"{path}\"\nsymlink = \"/opt/x\"\n");
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(&home, &link("~/locked/tool"));
        let _unlock = locked_dir_at(home.path(), "locked", 0o500);

        let row = row_for(&plan_of(&inputs), "~/locked/tool").clone();
        assert_eq!(row.action, Action::Conflict, "{row:?}");
        assert_eq!(
            row.note.as_deref(),
            Some(
                "~/locked is 0500 on disk, which denies its owner write, so apply could not \
                 write a file inside it"
            )
        );
        assert!(!apply_of(&inputs).executed, "apply wrote");
        assert!(std::fs::symlink_metadata(home.child("locked/tool")).is_err());

        let home = guarded_home();
        let inputs =
            crate::plan::tests::inputs(&home, &a_directory_target("0600", &link("~/.d/tool")));
        let row = row_for(&plan_of(&inputs), "~/.d/tool").clone();
        assert_eq!(row.action, Action::Conflict, "{row:?}");
        assert!(
            row.note
                .as_deref()
                .is_some_and(|note| note.contains("denies its owner search")),
            "{row:?}"
        );
    }

    #[test]
    fn a_file_beneath_a_directory_declared_without_owner_search_is_a_conflict() {
        // A mode on disk that denies search stops `observe`, but a declared one
        // was never observed: it has to be read as a declaration.
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(
            &home,
            &a_directory_target("0600", &crate::plan::tests::inline("~/.d/f", "x\\n")),
        );

        let file = plan_of(&inputs).changes[1].clone();
        assert_eq!(file.action, Action::Conflict, "{file:?}");
        assert!(
            file.note
                .as_deref()
                .is_some_and(|note| note.contains("denies its owner search")),
            "{file:?}"
        );
    }

    #[test]
    fn a_directory_target_is_created_at_every_mode_it_can_declare_and_then_left_alone() {
        for (layer, mode) in [
            (a_directory_target("0755", ""), 0o755),
            (a_directory_target("0700", ""), 0o700),
            (a_directory_target("0555", ""), 0o555),
            (a_directory_target("0444", ""), 0o444),
            (
                "[[target]]\npath = \"~/.d\"\ndir = true\n".to_string(),
                0o755,
            ),
        ] {
            let home = guarded_home();
            let inputs = crate::plan::tests::inputs(&home, &layer);
            let mode = Mode::from_bits(mode);

            let report = plan_of(&inputs);
            let row = row_for(&report, "~/.d");
            assert_eq!(row.action, Action::Create, "{layer}");
            assert_eq!(row.note, Some(format!("creates ~/.d {mode}")), "{layer}");
            assert_eq!(row.diff, None, "a directory has no bytes to show");
            assert!(!home.child(".d").exists(), "{layer}: plan made it");

            assert!(apply_of(&inputs).executed, "{layer}");
            assert_eq!(mode_on_disk(home.path(), ".d"), Some(mode), "{layer}");

            // Invariant 3: a second plan has nothing to do.
            assert_eq!(
                plan_of(&inputs).actions(),
                vec![Action::Unchanged],
                "{layer}"
            );
            assert!(!apply_of(&inputs).executed, "{layer}");
            assert_eq!(mode_on_disk(home.path(), ".d"), Some(mode), "{layer}");
        }
    }

    #[test]
    fn a_file_declared_before_or_after_its_directory_is_written_into_it_at_the_declared_mode() {
        let file =
            "[[target]]\npath = \"~/.ssh/config\"\ncontent = \"Host *\\n\"\nmode = \"0600\"\n";
        let dir = "[[target]]\npath = \"~/.ssh\"\ndir = true\nmode = \"0700\"\n";
        for layer in [format!("{file}{dir}"), format!("{dir}{file}")] {
            let home = guarded_home();
            let inputs = crate::plan::tests::inputs(&home, &layer);

            let report = plan_of(&inputs);
            assert_eq!(
                row_for(&report, "~/.ssh").note.as_deref(),
                Some("creates ~/.ssh 0700")
            );
            let config = row_for(&report, "~/.ssh/config");
            assert_eq!(config.action, Action::Create, "{report:?}");
            assert_eq!(
                config.note, None,
                "the directory's row announces the directory: {report:?}"
            );

            assert!(apply_of(&inputs).executed);
            assert_eq!(mode_on_disk(home.path(), ".ssh"), Some(Mode::PRIVATE_DIR));
            assert_eq!(
                mode_on_disk(home.path(), ".ssh/config"),
                Some(Mode::PRIVATE_FILE)
            );
            let state = crate::state::StateDir::resolve(home.path());
            let ledger = LedgerView::read(&state, home.path()).expect("ledger").value;
            let config = ledger
                .get(&Portable::parse_in("~/.ssh/config", home.path()).expect("portable"))
                .expect("the file is recorded");
            assert!(
                config.created_dirs.is_empty(),
                "the directory is its own target's to claim"
            );
            assert_eq!(
                plan_of(&inputs).actions(),
                vec![Action::Unchanged, Action::Unchanged]
            );
        }
    }

    #[test]
    fn an_existing_wide_directory_is_narrowed_before_a_file_is_written_into_it() {
        // The remedy `compare`'s parent note names: declare the directory.
        // Without the directory's write first, `stage` refuses the file with
        // `DirectoryTargetPending` and apply fails after plan said Create.
        let home = guarded_home();
        std::fs::create_dir(home.child(".ssh")).expect("the user's ~/.ssh");
        fs::set_mode(&home.child(".ssh"), Mode::DEFAULT_DIR).expect("chmod");
        home.write(".ssh/known_hosts", "theirs\n");
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/.ssh/config\"\ncontent = \"Host *\\n\"\nmode = \"0600\"\n\
             [[target]]\npath = \"~/.ssh\"\ndir = true\nmode = \"0700\"\n",
        );

        let report = plan_of(&inputs);
        let dir = row_for(&report, "~/.ssh");
        assert_eq!(dir.action, Action::Modify, "{report:?}");
        assert_eq!(
            dir.diff,
            Some(Diff::mode(Mode::DEFAULT_DIR, Mode::PRIVATE_DIR))
        );
        let config = row_for(&report, "~/.ssh/config");
        assert_eq!(config.action, Action::Create);
        assert_eq!(
            config.note, None,
            "the directory will not be wider than the file: {report:?}"
        );
        let rendered = crate::plan::render(
            &report,
            crate::plan::View::Plan,
            crate::plan::Palette::PLAIN,
            home.path(),
        );
        assert!(rendered.contains("mode 0755 -> 0700"), "{rendered}");

        assert!(apply_of(&inputs).executed);
        assert_eq!(mode_on_disk(home.path(), ".ssh"), Some(Mode::PRIVATE_DIR));
        assert_eq!(
            std::fs::read(home.child(".ssh/known_hosts")).expect("kept"),
            b"theirs\n"
        );
        assert_eq!(
            plan_of(&inputs).actions(),
            vec![Action::Unchanged, Action::Unchanged]
        );

        // `rm` puts the mode back and removes only the file bx wrote.
        let state = crate::state::StateDir::resolve(home.path());
        let targets = ["~/.ssh/config", "~/.ssh"]
            .map(|path| Portable::parse_in(path, home.path()).expect("portable"));
        crate::restore::restore(&state, home.path(), &targets).expect("rm");
        assert_eq!(mode_on_disk(home.path(), ".ssh"), Some(Mode::DEFAULT_DIR));
        assert!(!home.child(".ssh/config").exists());
        assert!(home.child(".ssh/known_hosts").exists());
    }

    #[test]
    fn a_directory_whose_mode_changed_since_bx_set_it_is_a_conflict() {
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(&home, &a_directory_target("0700", ""));
        assert!(apply_of(&inputs).executed);
        fs::set_mode(&home.child(".d"), Mode::from_bits(0o750)).expect("the user's chmod");

        let report = plan_of(&inputs);
        let row = row_for(&report, "~/.d");
        assert_eq!(row.action, Action::Conflict, "{report:?}");
        assert_eq!(
            row.note.as_deref(),
            Some("its mode changed since bx set it to 0700; mode 0750 -> 0700")
        );
        assert!(!apply_of(&inputs).executed);
        assert_eq!(
            mode_on_disk(home.path(), ".d"),
            Some(Mode::from_bits(0o750))
        );
    }

    #[test]
    fn a_directory_bx_set_is_set_again_when_its_declaration_changes() {
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(&home, &a_directory_target("0700", ""));
        assert!(apply_of(&inputs).executed);
        let inputs = crate::plan::tests::inputs(&home, &a_directory_target("0750", ""));

        let report = plan_of(&inputs);
        assert_eq!(report.actions(), vec![Action::Modify], "{report:?}");
        assert!(apply_of(&inputs).executed);
        assert_eq!(
            mode_on_disk(home.path(), ".d"),
            Some(Mode::from_bits(0o750))
        );
    }

    #[test]
    fn nested_directory_targets_are_made_shallowest_first_whatever_their_order() {
        let outer = "[[target]]\npath = \"~/a\"\ndir = true\nmode = \"0700\"\n";
        let inner = "[[target]]\npath = \"~/a/b/c\"\ndir = true\nmode = \"0750\"\n";
        for layer in [format!("{inner}{outer}"), format!("{outer}{inner}")] {
            let home = guarded_home();
            let inputs = crate::plan::tests::inputs(&home, &layer);

            let report = plan_of(&inputs);
            assert_eq!(
                row_for(&report, "~/a/b/c").note.as_deref(),
                Some("creates ~/a/b 0755, ~/a/b/c 0750"),
                "~/a is its own target's to name: {report:?}"
            );
            assert!(apply_of(&inputs).executed);
            assert_eq!(mode_on_disk(home.path(), "a"), Some(Mode::PRIVATE_DIR));
            assert_eq!(mode_on_disk(home.path(), "a/b"), Some(Mode::DEFAULT_DIR));
            assert_eq!(
                mode_on_disk(home.path(), "a/b/c"),
                Some(Mode::from_bits(0o750))
            );
            let state = crate::state::StateDir::resolve(home.path());
            let ledger = LedgerView::read(&state, home.path()).expect("ledger").value;
            let inner = ledger
                .get(&Portable::parse_in("~/a/b/c", home.path()).expect("portable"))
                .expect("recorded");
            assert_eq!(
                inner
                    .created_dirs
                    .iter()
                    .map(Portable::as_str)
                    .collect::<Vec<_>>(),
                ["~/a/b"]
            );
        }
    }

    #[test]
    fn a_directory_inside_a_directory_declared_without_owner_write_is_a_conflict() {
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/a\"\ndir = true\nmode = \"0500\"\n\
             [[target]]\npath = \"~/a/b\"\ndir = true\n",
        );

        let report = plan_of(&inputs);
        let inner = row_for(&report, "~/a/b");
        assert_eq!(inner.action, Action::Conflict, "{report:?}");
        assert!(
            inner.note.as_deref().is_some_and(|note| note.starts_with(
                "~/a is declared 0500, which denies its owner write, so apply could not create \
                 ~/a/b inside it"
            )),
            "{report:?}"
        );
        assert!(apply_of(&inputs).executed);
        assert!(!home.child("a/b").exists());
    }

    #[test]
    fn a_directory_whose_mode_changes_inside_one_declared_without_owner_search_is_a_conflict() {
        // Both directories are already there. `~/a` is chmod'd first, to 0600,
        // and from then on `~/a/b` cannot be reached: its mode change is
        // refused in plan rather than failing apply with EACCES.
        let home = guarded_home();
        let _unlock = locked_dir_at(home.path(), "a", 0o700);
        let _inner = locked_dir_at(home.path(), "a/b", 0o755);
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/a\"\ndir = true\nmode = \"0600\"\n\
             [[target]]\npath = \"~/a/b\"\ndir = true\nmode = \"0700\"\n",
        );

        let report = plan_of(&inputs);
        assert_eq!(row_for(&report, "~/a").action, Action::Modify, "{report:?}");
        let inner = row_for(&report, "~/a/b");
        assert_eq!(inner.action, Action::Conflict, "{report:?}");
        assert!(
            inner.note.as_deref().is_some_and(|note| note.starts_with(
                "~/a is declared 0600, which denies its owner search, so apply could not change \
                 the mode of ~/a/b inside it"
            )),
            "{report:?}"
        );
        assert_eq!(inner.diff, None, "{report:?}");
    }

    #[test]
    fn writes_beneath_a_declared_grandparent_without_owner_search_are_conflicts() {
        // `~/a/b` and `~/a/c` are already there and undeclared, so each
        // governs the write inside it and allows it. But `~/a` is chmod'd to
        // 0600 first, and nothing beneath it can be reached from then on: a
        // file created in `~/a/b` and a mode change of `~/a/c/d` are refused in
        // plan, and apply does exactly what plan announced.
        let home = guarded_home();
        let _b = locked_dir_at(home.path(), "a/b", 0o755);
        let _d = locked_dir_at(home.path(), "a/c/d", 0o755);
        let _a = locked_dir_at(home.path(), "a", 0o700);
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/a\"\ndir = true\nmode = \"0600\"\n\
             [[target]]\npath = \"~/a/c/d\"\ndir = true\nmode = \"0700\"\n\
             [[target]]\npath = \"~/a/b/f\"\ncontent = \"x\\n\"\n",
        );

        let report = plan_of(&inputs);
        assert_eq!(row_for(&report, "~/a").action, Action::Modify, "{report:?}");
        for (target, parent) in [("~/a/b/f", "~/a/b"), ("~/a/c/d", "~/a/c")] {
            let row = row_for(&report, target);
            assert_eq!(row.action, Action::Conflict, "{report:?}");
            assert!(
                row.note
                    .as_deref()
                    .is_some_and(|note| note.starts_with(&format!(
                        "~/a is declared 0600, which denies its owner search, so apply could not \
                     reach {parent} beneath it"
                    ))),
                "{report:?}"
            );
        }

        // Invariant 7: apply makes only the change plan announced, and fails
        // on nothing.
        assert!(apply_of(&inputs).executed);
        assert_eq!(mode_on_disk(home.path(), "a"), Some(Mode::from_bits(0o600)));
        fs::set_mode(&home.path().join("a"), Mode::from_bits(0o700)).expect("unlock");
        assert!(!home.child("a/b/f").exists());
        assert_eq!(mode_on_disk(home.path(), "a/c/d"), Some(Mode::DEFAULT_DIR));
    }

    #[test]
    fn a_directory_whose_mode_changes_inside_one_declared_without_owner_write_is_changed() {
        // A mode change needs search on the parent, not write: 0500 allows it,
        // so the row stands and apply makes it.
        let home = guarded_home();
        let _unlock = locked_dir_at(home.path(), "a", 0o700);
        let _inner = locked_dir_at(home.path(), "a/b", 0o755);
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/a\"\ndir = true\nmode = \"0500\"\n\
             [[target]]\npath = \"~/a/b\"\ndir = true\nmode = \"0700\"\n",
        );

        let report = plan_of(&inputs);
        assert_eq!(
            row_for(&report, "~/a/b").action,
            Action::Modify,
            "{report:?}"
        );
        assert!(apply_of(&inputs).executed);
        assert_eq!(mode_on_disk(home.path(), "a"), Some(Mode::from_bits(0o500)));
        assert_eq!(mode_on_disk(home.path(), "a/b"), Some(Mode::PRIVATE_DIR));
        assert!(
            plan_of(&inputs)
                .actions()
                .iter()
                .all(|action| *action == Action::Unchanged)
        );
    }

    #[test]
    fn a_file_inside_a_declared_directory_wider_than_it_is_noted() {
        // The note reads the declared mode, not the disk's: `~/.d` is made at
        // 0755 by its own target, which is wider than the 0600 file.
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(
            &home,
            &a_directory_target(
                "0755",
                "[[target]]\npath = \"~/.d/conf\"\ncontent = \"x\\n\"\nmode = \"0600\"\n",
            ),
        );

        let report = plan_of(&inputs);
        let file = row_for(&report, "~/.d/conf");
        assert_eq!(file.action, Action::Create, "{report:?}");
        assert_eq!(
            file.note.as_deref(),
            Some("~/.d is declared 0755, wider than the 0600 this file declares"),
            "{report:?}"
        );
    }

    #[test]
    fn a_directory_target_whose_parent_is_not_a_directory_is_a_conflict_and_is_left() {
        let home = guarded_home();
        home.write(".x", "the user's file\n");
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/.x/d\"\ndir = true\nmode = \"0700\"\n",
        );

        let report = plan_of(&inputs);
        assert_eq!(report.actions(), vec![Action::Conflict], "{report:?}");
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some("~/.x is not a directory, so bx cannot write a file inside it"),
            "{report:?}"
        );
        assert_eq!(report.changes[0].diff, None, "{report:?}");
        apply_of(&inputs);
        assert_eq!(
            std::fs::read(home.child(".x")).expect("kept"),
            b"the user's file\n"
        );
    }

    #[test]
    fn a_file_where_a_directory_is_declared_is_a_conflict_and_is_left() {
        let home = guarded_home();
        home.write(".d", "the user's file\n");
        let inputs = crate::plan::tests::inputs(&home, &a_directory_target("0700", ""));

        let report = plan_of(&inputs);
        assert_eq!(report.actions(), vec![Action::Conflict]);
        assert_eq!(
            report.changes[0].note.as_deref(),
            Some("a file, where the target declares a directory")
        );
        assert!(!apply_of(&inputs).executed);
        assert_eq!(
            std::fs::read(home.child(".d")).expect("kept"),
            b"the user's file\n"
        );
    }

    #[test]
    fn the_filesystem_root_as_a_directory_target_is_blocked() {
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
        };
        let mut target = a_target(home.path(), "/");
        target.body = Body::Dir;

        let (change, op) = decide(&Resolution::Ready(target), &ctx).expect("decide");

        assert_eq!(change.action, Action::Blocked);
        assert_eq!(op, None);
    }

    #[test]
    fn a_directory_target_bx_holds_as_a_file_is_a_conflict_and_the_reverse() {
        let observed = |kind| Observed {
            path: PathBuf::from("/h/.d"),
            kind,
            mode: Some(Mode::DEFAULT_DIR),
            bytes: None,
            link: None,
            parent: None,
            stamp: None,
        };
        let entry = |mechanism| LedgerEntry {
            path: Portable::try_from("~/.d".to_string()).expect("portable"),
            written: crate::journal::dir_digest(),
            mode: Mode::DEFAULT_DIR,
            mechanism,
            prior: crate::state::Prior::Absent,
            created_dirs: Vec::new(),
            superseded: Vec::new(),
            superseded_absent: false,
        };

        let (action, note) = dir_ownership(
            Action::Create,
            &observed(Kind::Absent),
            Some(&entry(Mechanism::Own)),
            None,
        );
        assert_eq!(action, Action::Conflict);
        assert_eq!(
            note.as_deref(),
            Some("bx attached to this path as the whole file")
        );

        let (action, note) = ownership(
            Action::Create,
            &observed(Kind::Absent),
            Some(&entry(Mechanism::Dir)),
            None,
        );
        assert_eq!(action, Action::Conflict);
        assert_eq!(
            note.as_deref(),
            Some("bx attached to this file as a directory")
        );

        // A directory bx does not hold yet is set to its declared mode.
        assert_eq!(
            dir_ownership(Action::Modify, &observed(Kind::Dir), None, None),
            (Action::Modify, None)
        );
    }

    #[test]
    fn an_interrupted_directory_write_is_shown_as_what_recovery_does() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".d")).expect("the directory");
        fs::set_mode(&home.child(".d"), Mode::DEFAULT_DIR).expect("chmod");
        let inputs = crate::plan::tests::inputs(&home, &a_directory_target("0700", ""));
        let state = crate::state::StateDir::resolve(home.path());
        for rel in [".d", ".made"] {
            let mut session = crate::journal::Session::open(
                &state,
                crate::journal::SessionKind::Apply,
                home.path(),
                Vec::new(),
            )
            .expect("open");
            session
                .apply(crate::journal::tests::dir_to(
                    home.path(),
                    rel,
                    Mode::PRIVATE_DIR,
                ))
                .expect("apply");
            drop(session);
            let report = plan_of(&inputs);
            let row = &report.changes[0];
            if rel == ".d" {
                assert_eq!(
                    row.note.as_deref(),
                    Some("rolls back: puts back the mode it had")
                );
                assert_eq!(
                    row.diff,
                    Some(Diff::mode(Mode::PRIVATE_DIR, Mode::DEFAULT_DIR))
                );
            } else {
                assert_eq!(
                    row.note.as_deref(),
                    Some("rolls back: removes the directory the session created where empty")
                );
                assert_eq!(row.diff, None);
            }
            assert!(crate::recover::recover(&state).expect("recover").is_clear());
        }
        assert_eq!(mode_on_disk(home.path(), ".d"), Some(Mode::DEFAULT_DIR));
        assert!(!home.child(".made").exists());
    }

    #[test]
    fn decision_24_a_file_beneath_a_directory_its_owner_can_write_is_decided_as_before() {
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(
            &home,
            &a_directory_target("0755", &crate::plan::tests::inline("~/.d/f", "x\\n")),
        );

        let report =
            crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false)).expect("plan");

        assert_eq!(
            row_for(&report, "~/.d/f").action,
            Action::Create,
            "{report:?}"
        );
    }

    #[test]
    fn decision_24_only_what_the_unwritable_directory_actually_holds_is_refused() {
        // The mutation run found unpinned that a file BESIDE the unwritable
        // directory, and a file whose own declared mode is narrow, are not
        // refused. Both still hold with the observed-mode rule, and the
        // directory is now one on disk rather than one a target declares.
        let home = guarded_home();
        let layer = [
            crate::plan::tests::inline("~/locked/conf", "x\\n"),
            crate::plan::tests::inline("~/beside", "x\\n"),
            "[[target]]\npath = \"~/narrow\"\ncontent = \"x\\n\"\nmode = \"0444\"\n".to_string(),
        ]
        .concat();
        let inputs = crate::plan::tests::inputs(&home, &layer);
        let _unlock = locked_dir_at(home.path(), "locked", 0o500);

        let report =
            crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false)).expect("plan");

        assert_eq!(
            row_for(&report, "~/locked/conf").action,
            Action::Conflict,
            "{report:?}"
        );
        // Beside it, not beneath it: the home is writable and the row stands.
        assert_eq!(
            row_for(&report, "~/beside").action,
            Action::Create,
            "{report:?}"
        );
        // A file's own narrow mode is not its parent's: `locked_parent` reads
        // the directory, never the file the target declares.
        let narrow = row_for(&report, "~/narrow");
        assert_eq!(narrow.action, Action::Create, "{report:?}");
        assert!(
            narrow
                .note
                .as_deref()
                .is_none_or(|note| !note.contains("denies its owner write")),
            "{report:?}"
        );
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

    mod env_placement {
        //! The `[[env]]` placement graph, decided and applied end to end.

        use std::os::unix::fs::PermissionsExt as _;

        use super::super::super::{Mode as RunMode, Report, run};
        use super::*;
        use crate::plan::tests::{inputs, own};
        use crate::testing::GuardedHome;

        /// One `[[env]]` entry, as TOML.
        fn env(name: &str, value: &str, kind: &str) -> String {
            format!("[[env]]\nname = \"{name}\"\nvalue = \"{value}\"\nkind = \"{kind}\"\n")
        }

        /// One variable of each kind, none of which needs a root.
        fn every_kind() -> String {
            [
                env("LANG", "C.UTF-8", "environment"),
                env("BROWSER", "firefox", "gui"),
                env("PAGER", "less", "login"),
                env("EDITOR", "nvim", "interactive"),
            ]
            .concat()
        }

        const ZSHRC_REGION: &str = "# >>> bx >>>\n\
             [[ -r ~/.local/share/bx/zshrc.zsh ]] && source ~/.local/share/bx/zshrc.zsh\n\
             # <<< bx <<<\n";

        /// The interactive file's bytes with `env` in its `env` phase: the
        /// phase assembly's header, then the phase, when `env` holds anything.
        fn interactive(env: &str) -> String {
            let header = "# Generated by bx. Edit the config repo, not this file.\n";
            if env.is_empty() {
                header.to_string()
            } else {
                format!("{header}\n# bx phase: env\n{env}")
            }
        }

        fn plan(home: &GuardedHome, layer: &str) -> Report {
            run(&inputs(home, layer), RunMode::Plan, &mut |_| {
                panic!("plan never asks")
            })
            .expect("plan runs")
        }

        fn apply(home: &GuardedHome, layer: &str) -> Report {
            run(&inputs(home, layer), RunMode::Apply, &mut |_| Ok(true)).expect("apply runs")
        }

        /// Each row as `(target, action)`.
        fn rows(report: &Report) -> Vec<(&str, Action)> {
            report
                .changes
                .iter()
                .map(|change| (change.target.as_str(), change.action))
                .collect()
        }

        /// The row for `target`.
        fn row<'a>(report: &'a Report, target: &str) -> &'a Change {
            report
                .changes
                .iter()
                .find(|change| change.target == target)
                .unwrap_or_else(|| panic!("no row for {target}: {:?}", rows(report)))
        }

        fn read(home: &GuardedHome, rel: &str) -> String {
            std::fs::read_to_string(home.child(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
        }

        #[test]
        fn a_variable_switched_off_or_moved_leaves_its_old_fragment_empty() {
            // PR #75 note D1: a place no variable lands in any more emits no
            // target, so the fragment bx wrote for it stayed sourced with no
            // plan row. While the ledger records it, it is planned empty.
            let home = guarded_home();
            let before = [
                env("PAGER", "less", "login"),
                env("EDITOR", "nvim", "interactive"),
            ]
            .concat();
            apply(&home, &before);

            // PAGER moves to `interactive`, and EDITOR is switched off.
            let after = format!(
                "{}[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n\
                 enabled = false\n",
                env("PAGER", "less", "interactive")
            );
            let moved = plan(&home, &after);
            assert_eq!(
                row(&moved, "~/.local/share/bx/zprofile.zsh").action,
                Action::Modify
            );
            assert_eq!(
                row(&moved, "~/.local/share/bx/zshrc.zsh").action,
                Action::Modify
            );
            apply(&home, &after);
            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            assert_eq!(read(&home, ".local/share/bx/zprofile.zsh"), header);
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                interactive(&format!("{header}export PAGER=less\n"))
            );
            let second = plan(&home, &after);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );

            // Every variable gone: both fragments are left empty, and the
            // regions stay, sourcing them.
            let none = "";
            apply(&home, none);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), interactive(""));
            assert_eq!(read(&home, ".local/share/bx/zprofile.zsh"), header);
            assert_eq!(read(&home, ".zshrc"), ZSHRC_REGION);
            let settled = plan(&home, none);
            assert_eq!(
                rows(&settled),
                vec![
                    ("~/.local/share/bx/zprofile.zsh", Action::Unchanged),
                    ("~/.local/share/bx/zshrc.zsh", Action::Unchanged),
                    ("~/.local/share/bx/bashrc.bash", Action::Unchanged),
                ]
            );
        }

        #[test]
        fn a_fragment_bx_never_wrote_is_not_planned_empty() {
            let home = guarded_home();
            let report = plan(&home, &env("EDITOR", "nvim", "interactive"));
            assert_eq!(
                rows(&report),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Create),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
        }

        /// The lines an interactive file holding a plugin closes with.
        const SETTLED: &str = "\n# bx: done, whichever plugins were found\ntrue\n";

        /// One `[[plugin]]` entry, as TOML.
        fn plugin(name: &str, source: &str, terminal: bool) -> String {
            format!("[[plugin]]\nname = \"{name}\"\nsource = \"{source}\"\nterminal = {terminal}\n")
        }

        #[test]
        fn declared_plugins_reach_the_interactive_file_in_phase_order_and_rm_restores_it() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            // One plugin that is installed, by absolute path, and two that are
            // not: each still gets its guarded line.
            let installed = home.child("opt/installed.zsh");
            std::fs::create_dir_all(installed.parent().expect("a parent")).expect("mkdir");
            std::fs::write(&installed, "print -r -- installed-loaded\n").expect("write");
            let installed = installed.to_str().expect("a UTF-8 path");
            let layer = [
                // Declared out of load order: the terminal claimant first.
                plugin("highlight", "~/.zsh/highlight/highlight.zsh", true),
                env("EDITOR", "nvim", "interactive"),
                plugin("installed", installed, false),
                plugin("absent", "~/.zsh/absent/absent.zsh", false),
            ]
            .concat();

            let first = apply(&home, &layer);
            // The variable reaches bash too; the plugins are zsh's alone.
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: plugins\n\
                     [[ -r {installed} ]] && source {installed}\n\
                     [[ -r ~/.zsh/absent/absent.zsh ]] && source ~/.zsh/absent/absent.zsh\n\
                     \n# bx phase: terminal\n\
                     [[ -r ~/.zsh/highlight/highlight.zsh ]] && \
                     source ~/.zsh/highlight/highlight.zsh\n{SETTLED}",
                    interactive(
                        "# Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                         export EDITOR=nvim\n"
                    )
                )
            );

            // The shell starts with the absent plugins, even under ERR_EXIT,
            // having sourced the installed one: the file is sourced the way
            // the `~/.zshrc` region sources it, and returns 0.
            if let Some(zsh) = crate::shell::testing::installed("zsh") {
                let file = home.child(".local/share/bx/zshrc.zsh");
                let file = file.to_str().expect("a UTF-8 path");
                let out = crate::shell::testing::run(
                    &zsh,
                    &["-f", "-e"],
                    &format!("[[ -r {file} ]] && source {file}\nprint -r -- started\n"),
                );
                assert_eq!(
                    String::from_utf8(out).expect("utf-8"),
                    "installed-loaded\nstarted\n"
                );
            }

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, &layer).executed);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), written);

            // A plugin alone still places the file, with no `env` phase.
            let alone = plugin("absent", "~/.zsh/absent/absent.zsh", false);
            apply(&home, &alone);
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                format!(
                    "{}\n# bx phase: plugins\n\
                     [[ -r ~/.zsh/absent/absent.zsh ]] && source ~/.zsh/absent/absent.zsh\n\
                     {SETTLED}",
                    interactive("")
                )
            );

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
        }

        /// The source configuration's history and shell options.
        const HISTORY: &str = "[history]\nsize = 10000\nduplicates = \"all\"\nshare = true\n\
             [history.file]\nzsh = \"~/.zsh_history\"\n\
             [shell-options]\nhistappend = true\ncheckwinsize = true\n";

        #[test]
        fn declared_history_reaches_the_interactive_file_twice_alike_and_rm_restores_it() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let first = apply(&home, HISTORY);
            // bash's file carries the same declaration in bash's names.
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: options\n\
                     HISTFILE=\"${{HOME}}/.zsh_history\"\n\
                     HISTSIZE=10000\nSAVEHIST=10000\n\
                     typeset -g +x HISTFILE HISTSIZE SAVEHIST\n\
                     setopt HIST_IGNORE_ALL_DUPS SHARE_HISTORY\n",
                    interactive("")
                )
            );
            // The interactive file, which every interactive zsh sources —
            // not the login-only one, which bx does not write here at all.
            assert!(!home.child(".local/share/bx/zprofile.zsh").exists());
            assert!(!home.child(".zprofile").exists());
            // bash's option is bash's alone, and reaches no zsh file.
            assert!(!written.contains("histappend"), "{written}");

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, HISTORY);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, HISTORY).executed);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), written);

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = [
                "~/.local/share/bx/zshrc.zsh",
                "~/.zshrc",
                "~/.local/share/bx/bashrc.bash",
                "~/.bashrc",
            ]
            .iter()
            .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
            .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            assert!(!home.child(".local/share/bx/bashrc.bash").exists());
            assert!(!home.child(".bashrc").exists());
        }

        #[test]
        fn declared_keybindings_reach_the_interactive_file_twice_alike_and_rm_restores_it() {
            const KEYBINDINGS: &str = "[keybindings]\nalt-b = \"backward-word\"\n\
                                       home = \"beginning-of-line\"\n";
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let first = apply(&home, KEYBINDINGS);
            // readline gets the same bindings in `~/.inputrc`.
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.inputrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: keybindings\n\
                     if [[ -n ${{terminfo[khome]-}} ]]; then \
                     bindkey -- \"${{terminfo[khome]}}\" beginning-of-line; fi\n\
                     bindkey -- '^[[H' beginning-of-line\n\
                     bindkey -- '^[b' backward-word\n",
                    interactive("")
                )
            );

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, KEYBINDINGS);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, KEYBINDINGS).executed);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), written);

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc", "~/.inputrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            assert!(!home.child(".inputrc").exists());
        }

        #[test]
        fn binding_no_key_places_nothing_and_an_unknown_one_fails_the_load() {
            let home = guarded_home();
            assert_eq!(rows(&plan(&home, "[keybindings]\n")), vec![]);
            for (layer, needle) in [
                (
                    "[keybindings]\nctrl-a = \"beginning-of-line\"\n",
                    "unknown key `ctrl-a` in [keybindings]",
                ),
                (
                    "[keybindings]\nhome = \"kill-line\"\n",
                    "found \"kill-line\"",
                ),
            ] {
                crate::plan::tests::seed(home.path(), layer);
                let err = crate::plan::Inputs::load(&crate::plan::tests::env(home.path()))
                    .expect_err(layer)
                    .to_string();
                assert!(err.contains(needle), "{layer}: {err}");
            }
        }

        #[test]
        fn declaring_no_history_zsh_reads_places_nothing() {
            let home = guarded_home();
            assert_eq!(rows(&plan(&home, "[history]\n[shell-options]\n")), vec![]);
            // What only bash reads places bash's file alone.
            let layer =
                "[history.file]\nbash = \"~/.bash_history\"\n[shell-options]\nhistappend = true\n";
            assert_eq!(
                rows(&plan(&home, layer)),
                vec![
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
        }

        #[test]
        fn a_zsh_history_file_bx_owns_or_would_commit_blocks_the_file() {
            let home = guarded_home();
            for (file, reason) in [
                (
                    "~/.local/state/bx/history",
                    "points inside a directory bx owns",
                ),
                (
                    "~/.local/share/bx/history",
                    "points inside a directory bx owns",
                ),
                ("~/.config/bx/history", "points inside bx's config repo"),
            ] {
                let layer = format!("[history.file]\nzsh = \"{file}\"\n");
                let report = plan(&home, &layer);
                let row = row(&report, "~/.local/share/bx/zshrc.zsh");
                assert_eq!(row.action, Action::Blocked, "{file}");
                let note = row.note.as_deref().expect("a note");
                assert!(
                    note.contains(&format!("[history] zsh file {file} {reason}")),
                    "{note}"
                );
            }
            // Anywhere else in the home, or outside it, is the user's choice.
            for file in [
                "~/.zsh_history",
                "~/.local/state/zsh/history",
                "/srv/history",
            ] {
                let layer = format!("[history.file]\nzsh = \"{file}\"\n");
                let report = plan(&home, &layer);
                assert_eq!(
                    row(&report, "~/.local/share/bx/zshrc.zsh").action,
                    Action::Create,
                    "{file}"
                );
            }
        }

        #[test]
        fn a_second_terminal_claimant_fails_the_load_naming_both() {
            let home = guarded_home();
            let layer = [
                plugin("zsh-syntax-highlighting", "~/a.zsh", true),
                plugin("fast-syntax-highlighting", "~/b.zsh", true),
            ]
            .concat();
            crate::plan::tests::seed(home.path(), &layer);
            let err = crate::plan::Inputs::load(&crate::plan::tests::env(home.path()))
                .expect_err("two terminal claimants fail the load")
                .to_string();
            assert!(err.contains("`fast-syntax-highlighting`"), "{err}");
            assert!(
                err.contains("plugin `zsh-syntax-highlighting` already claims at "),
                "{err}"
            );
            assert!(err.contains("bx.toml:1"), "{err}");
        }

        /// The `aliases` phase of an interactive file's bytes: from its
        /// heading up to the next phase's, headings excluded.
        fn aliases_phase(written: &str) -> &str {
            let heading = "# bx phase: aliases\n";
            let start = written.find(heading).expect("an aliases phase") + heading.len();
            let rest = &written[start..];
            rest.find("\n# bx phase: ")
                .map_or(rest, |end| &rest[..=end])
        }

        #[test]
        fn declared_aliases_arrive_as_their_tool_does_and_set_no_variable() {
            use std::os::unix::fs::PermissionsExt as _;
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            // A tool bx does not find yet, by absolute path so no `PATH` is
            // consulted.
            let tool = home.child("opt/bat");
            std::fs::create_dir_all(tool.parent().expect("a parent")).expect("mkdir");
            let tool = tool.to_str().expect("a UTF-8 path").to_string();
            let layer = format!(
                "[aliases]\nll = \"ls -la\"\nsudo = \"sudo \"\n\
                 [[alias]]\nname = \"cat\"\ncommand = \"bat --paging=never\"\n\
                 when = \"has:{tool}\"\n\
                 [[alias]]\nname = \"x\"\ncommand = \"export X=1\"\nwhen = \"env:TMUX\"\n\
                 [[alias]]\nname = \"off\"\ncommand = \"y\"\nenabled = false\n"
            );

            // Aliases alone place the file, and the region that sources it,
            // and bash's.
            let first = apply(&home, &layer);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            let runtime = "if [[ -n ${TMUX+x} ]]; then\n  alias x='export X=1'\nfi\n";
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: aliases\nalias ll='ls -la'\nalias sudo='sudo '\n{runtime}",
                    interactive("")
                )
            );

            // Idempotent while the tool is missing.
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );

            // Installing the tool is a change the next plan shows, and the
            // alias arrives, written plainly, with no `command -v`.
            std::fs::write(&tool, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let installed = plan(&home, &layer);
            assert_eq!(
                row(&installed, "~/.local/share/bx/zshrc.zsh").action,
                Action::Modify
            );
            assert_eq!(row(&installed, "~/.zshrc").action, Action::Unchanged);
            assert_eq!(
                row(&installed, "~/.local/share/bx/bashrc.bash").action,
                Action::Modify
            );
            assert_eq!(row(&installed, "~/.bashrc").action, Action::Unchanged);
            apply(&home, &layer);
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            let phase = aliases_phase(&written);
            assert_eq!(
                phase,
                format!(
                    "alias ll='ls -la'\nalias sudo='sudo '\n\
                     alias cat='bat --paging=never'\n{runtime}"
                )
            );
            assert!(!written.contains("command -v"), "{written}");
            assert!(!written.contains("off"), "{written}");
            let settled = plan(&home, &layer);
            assert!(
                settled
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&settled)
            );

            // Invariant 2: the written `aliases` phase is not an environment
            // fragment, so sourcing its bytes, with its runtime condition
            // true, changes no parameter and exports nothing.
            if let Some(zsh) = crate::shell::testing::installed("zsh") {
                let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                            [[ ${parameters[$n]} == *special* ]] || \
                            print -r -- \"$n=${(P)n}\"; \
                            done; print -r -- ---; export; print -r -- ---; }\n";
                let dumps = |body: &str| {
                    let script =
                        format!("TMUX=1\n{dump}__bx_dump >/dev/null\n__bx_dump\n{body}__bx_dump\n");
                    let got = String::from_utf8(crate::shell::testing::run(&zsh, &["-f"], &script))
                        .expect("utf-8");
                    got.split("---\n").map(str::to_string).collect::<Vec<_>>()
                };
                let parts = dumps(phase);
                assert_eq!(parts[1], parts[3], "nothing is exported");
                assert_eq!(parts[0], parts[2], "no parameter changes");
                // The aliases were defined, so the phase ran at all.
                let defined = crate::shell::testing::run(
                    &zsh,
                    &["-f"],
                    &format!("TMUX=1\n{phase}print -r -- \"${{aliases[x]}}\"\n"),
                );
                assert_eq!(defined, b"export X=1\n");
                // The dump does see an assignment, so the equalities mean
                // something.
                let parts = dumps("Z=1\n");
                assert_ne!(parts[2], parts[0]);
            }

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
        }

        #[test]
        fn bash_gets_its_file_a_fixed_region_and_an_inputrc_twice_alike_and_rm_restores_them() {
            const SHARED: &str = "[aliases]\nll = \"ls -la\"\n\
                                  [history]\nsize = 500\nignore_space = true\n\
                                  [shell-options]\nhistappend = true\n\
                                  [keybindings]\nalt-f = \"forward-word\"\n";
            let bashrc = "# a distribution's own ~/.bashrc\n\
                          [ -z \"$PS1\" ] && return\nPS1='\\u@\\h \\w\\$ '\n";
            let home = guarded_home();
            home.write(".bashrc", bashrc);
            let first = apply(&home, SHARED);
            assert_eq!(
                rows(&first)
                    .into_iter()
                    .filter(|(path, _)| !path.contains("zsh"))
                    .collect::<Vec<_>>(),
                vec![
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Modify),
                    ("~/.inputrc", Action::Create),
                ]
            );
            // The region is appended, and every byte around it is the user's.
            let region = "# >>> bx >>>\n\
                          [[ -r ~/.local/share/bx/bashrc.bash ]] && \
                          source ~/.local/share/bx/bashrc.bash\n\
                          # <<< bx <<<\n";
            assert_eq!(read(&home, ".bashrc"), format!("{bashrc}{region}"));
            let file = read(&home, ".local/share/bx/bashrc.bash");
            assert_eq!(
                file,
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: aliases\nalias ll='ls -la'\n\
                 \n# bx phase: options\nHISTSIZE=500\nHISTFILESIZE=500\n\
                 HISTCONTROL=ignorespace\nexport -n HISTSIZE HISTFILESIZE HISTCONTROL\n\
                 shopt -s histappend\n"
            );
            let inputrc = read(&home, ".inputrc");
            assert!(
                inputrc.ends_with("$include /etc/inputrc\n\"\\ef\": forward-word\n"),
                "{inputrc}"
            );

            // bash reads the region, and through it the file.
            if let Some(bash) = crate::shell::testing::installed("bash") {
                // The region names the file under `~`, so run under this home.
                let script = format!(
                    "HOME={}\nPS1=x\nsource ~/.bashrc\n\
                     printf '%s|' \"${{BASH_ALIASES[ll]}}\" \"$HISTSIZE\"\n",
                    home.path().display()
                );
                let out = crate::shell::testing::run(&bash, &["--norc", "--noprofile"], &script);
                assert_eq!(String::from_utf8(out).expect("utf-8"), "ls -la|500|");
            }

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, SHARED);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, SHARED).executed);
            assert_eq!(read(&home, ".local/share/bx/bashrc.bash"), file);
            assert_eq!(read(&home, ".bashrc"), format!("{bashrc}{region}"));
            assert_eq!(read(&home, ".inputrc"), inputrc);

            // Declaring nothing any more leaves bash's files planned empty,
            // and the region as it is.
            let vacated = plan(&home, "");
            for path in ["~/.local/share/bx/bashrc.bash", "~/.inputrc"] {
                assert_eq!(row(&vacated, path).action, Action::Modify, "{path}");
            }
            assert!(
                vacated
                    .changes
                    .iter()
                    .all(|change| change.target != "~/.bashrc"),
                "{:?}",
                rows(&vacated)
            );

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = [
                "~/.local/share/bx/zshrc.zsh",
                "~/.zshrc",
                "~/.local/share/bx/bashrc.bash",
                "~/.bashrc",
                "~/.inputrc",
            ]
            .iter()
            .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
            .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert_eq!(read(&home, ".bashrc"), bashrc);
            assert!(!home.child(".local/share/bx/bashrc.bash").exists());
            assert!(!home.child(".inputrc").exists());
        }

        #[test]
        fn an_inputrc_a_dropped_target_wrote_is_left_alone() {
            // PR #102 note D1: the ledger records a `[[target]]`'s file as
            // owned whole, as it does the inputrc bx generates, so dropping
            // the target planned `~/.inputrc` rewritten with no bindings. It
            // is reported as undeclared instead (#100), and never written.
            let bindings = "set editing-mode vi\n";
            let target =
                "[[target]]\npath = \"~/.inputrc\"\ncontent = \"set editing-mode vi\\n\"\n";
            let home = guarded_home();
            assert_eq!(
                row(&apply(&home, target), "~/.inputrc").action,
                Action::Create
            );
            assert_eq!(read(&home, ".inputrc"), bindings);

            let dropped = plan(&home, "");
            assert_eq!(rows(&dropped), [("~/.inputrc", Action::Undeclared)]);
            assert!(!apply(&home, "").executed);
            assert_eq!(read(&home, ".inputrc"), bindings);
        }

        #[test]
        fn an_inputrc_bx_did_not_write_is_a_conflict_left_as_it_is() {
            let home = guarded_home();
            home.write(".inputrc", "set bell-style none\n");
            let report = apply(&home, "[keybindings]\nhome = \"beginning-of-line\"\n");
            assert_eq!(row(&report, "~/.inputrc").action, Action::Conflict);
            assert_eq!(read(&home, ".inputrc"), "set bell-style none\n");
        }

        #[test]
        fn a_bash_history_file_bx_owns_blocks_bash_s_file() {
            let home = guarded_home();
            let layer = "[history.file]\nbash = \"~/.local/state/bx/history\"\n";
            let report = plan(&home, layer);
            let file = row(&report, "~/.local/share/bx/bashrc.bash");
            assert_eq!(file.action, Action::Blocked);
            let note = file.note.as_deref().expect("a note");
            assert!(
                note.contains(
                    "[history] bash file ~/.local/state/bx/history \
                     points inside a directory bx owns"
                ),
                "{note}"
            );
            let layer = "[history.file]\nbash = \"~/.bash_history\"\n";
            assert_eq!(
                row(&plan(&home, layer), "~/.local/share/bx/bashrc.bash").action,
                Action::Create
            );
        }

        /// The `functions` phase of an interactive file's bytes: from its
        /// heading up to the next phase's, headings excluded.
        fn functions_phase(written: &str) -> &str {
            let heading = "# bx phase: functions\n";
            let start = written.find(heading).expect("a functions phase") + heading.len();
            let rest = &written[start..];
            rest.find("\n# bx phase: ")
                .map_or(rest, |end| &rest[..=end])
        }

        #[test]
        fn a_declared_function_arrives_once_its_value_is_answered_and_sets_only_hook_arrays() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let layer = "[[value]]\nname = \"proj\"\nkind = \"string\"\n\n\
                         [[function]]\nname = \"mkcd\"\n\
                         body = '''\nmkdir -p -- \"$1\" && cd -- \"$1\"\n'''\n\
                         [[function]]\nname = \"goproj\"\nbody = \"cd -- {{proj}}\"\n\
                         [[function]]\nname = \"track\"\nbody = \"return 0\"\nhook = \"chpwd\"\n\
                         shells = [\"zsh\"]\n\
                         [[function]]\nname = \"off\"\nbody = \"x\"\nenabled = false\n";
            let registration = "(( ${+chpwd_functions} )) && \
                                (( ${chpwd_functions[(Ie)__bx_hook_track]} )) || \
                                chpwd_functions+=(__bx_hook_track)\n";
            let ready = format!(
                "function mkcd {{\nmkdir -p -- \"$1\" && cd -- \"$1\"\n}}\n\
                 function __bx_hook_track {{\nreturn 0\n}}\n{registration}"
            );

            // Functions alone place the file and its region. The one waiting
            // on `proj` is held back, named in the file's row, and every
            // other function is written.
            let first = apply(&home, layer);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            // bash defines what reaches it, and its row names the function
            // held back and the one kept to zsh.
            let bash_note = row(&first, "~/.local/share/bx/bashrc.bash")
                .note
                .as_deref()
                .expect("a note");
            assert!(
                bash_note.contains("function `goproj` held back: "),
                "{bash_note}"
            );
            assert!(
                bash_note.ends_with("; not in bash: function `track`"),
                "{bash_note}"
            );
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: functions\n\
                 function mkcd {\nmkdir -p -- \"$1\" && cd -- \"$1\"\n}\n"
            );
            let note = row(&first, "~/.local/share/bx/zshrc.zsh")
                .note
                .as_deref()
                .expect("a note naming the held-back function");
            assert!(note.contains("function `goproj` held back: "), "{note}");
            assert!(note.contains("proj"), "{note}");
            assert!(note.contains("bx init"), "{note}");
            assert_eq!(row(&first, "~/.zshrc").note, None);
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!("{}\n# bx phase: functions\n{ready}", interactive(""))
            );
            assert!(!written.contains("goproj"), "{written}");
            assert!(!written.contains("off"), "{written}");

            // Idempotent while the value is unanswered: nothing to write, and
            // the row still says why the function is missing.
            let second = plan(&home, layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            let held = row(&second, "~/.local/share/bx/zshrc.zsh")
                .note
                .as_deref()
                .expect("the held-back function is still named");
            assert!(held.starts_with("function `goproj` held back: "), "{held}");
            assert!(note.ends_with(held), "{note}");

            // Answering the value is a change the next plan shows, and the
            // function arrives with it substituted, in declaration order.
            home.write(
                ".local/state/bx/local.toml",
                "[values]\nproj = \"src/bx\"\n",
            );
            let answered = plan(&home, layer);
            let file = row(&answered, "~/.local/share/bx/zshrc.zsh");
            assert_eq!(file.action, Action::Modify);
            assert_eq!(file.note, None, "nothing is held back");
            assert_eq!(row(&answered, "~/.zshrc").action, Action::Unchanged);
            apply(&home, layer);
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            let phase = functions_phase(&written);
            assert_eq!(
                phase,
                format!(
                    "function mkcd {{\nmkdir -p -- \"$1\" && cd -- \"$1\"\n}}\n\
                     function goproj {{\ncd -- src/bx\n}}\n\
                     function __bx_hook_track {{\nreturn 0\n}}\n{registration}"
                )
            );
            let settled = plan(&home, layer);
            assert!(
                settled
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&settled)
            );

            // Invariant 2: sourcing the written `functions` phase exports
            // nothing and changes no parameter but zsh's hook arrays.
            if let Some(zsh) = crate::shell::testing::installed("zsh") {
                let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                            [[ ${parameters[$n]} == *special* ]] || \
                            print -r -- \"$n=${(P)n}\"; \
                            done; print -r -- ---; export; print -r -- ---; }\n";
                let dumps = |body: &str| {
                    let script =
                        format!("{dump}__bx_dump >/dev/null\n__bx_dump\n{body}__bx_dump\n");
                    let got = String::from_utf8(crate::shell::testing::run(&zsh, &["-f"], &script))
                        .expect("utf-8");
                    got.split("---\n").map(str::to_string).collect::<Vec<_>>()
                };
                let parts = dumps(phase);
                assert_eq!(parts[1], parts[3], "nothing is exported");
                let hooks: Vec<String> = crate::shell::function::Hook::ALL
                    .iter()
                    .map(|hook| hook.array())
                    .collect();
                let kept = |dump: &str| {
                    dump.lines()
                        .filter(|line| {
                            let name = line.split('=').next().unwrap_or_default();
                            !hooks.iter().any(|hook| hook == name)
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                assert_eq!(kept(&parts[2]), kept(&parts[0]), "only hook arrays change");
                assert!(
                    parts[2]
                        .lines()
                        .any(|line| line == "chpwd_functions=__bx_hook_track"),
                    "{}",
                    parts[2]
                );
                // The functions were defined, so the phase ran at all.
                let defined = crate::shell::testing::run(
                    &zsh,
                    &["-f"],
                    &format!("{phase}print -r -- ${{+functions[goproj]}} ${{+functions[mkcd]}}\n"),
                );
                assert_eq!(defined, b"1 1\n");
                // The dump does see an assignment, so the equalities mean
                // something.
                let parts = dumps("Z=1\n");
                assert_ne!(kept(&parts[2]), kept(&parts[0]));
            }

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
        }

        #[test]
        fn a_declared_source_arrives_guarded_in_its_phase_whether_or_not_its_file_exists() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let layer = "[[value]]\nname = \"host\"\nkind = \"string\"\n\n\
                         [[source]]\nname = \"keychain\"\npath = \"~/.keychain/{{host}}-sh\"\n\
                         phase = \"activations\"\n\
                         [[source]]\nname = \"fzf\"\npath = \"~/.fzf.zsh\"\n\
                         [[source]]\nname = \"off\"\npath = \"~/off\"\nenabled = false\n";
            let settle = "\n# bx: done, whichever plugins were found\ntrue\n";

            // Sources alone place the file and its region. The one waiting on
            // `host` is held back and named in the file's row; the other is
            // written as its guarded line, and the file settles to 0.
            let first = apply(&home, layer);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            // bash sources the same line, and settles the same way.
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                format!(
                    "# Generated by bx. Edit the config repo, not this file.\n\
                     \n# bx phase: plugins\n[[ -r ~/.fzf.zsh ]] && source ~/.fzf.zsh\n{settle}"
                )
            );
            let note = row(&first, "~/.local/share/bx/zshrc.zsh")
                .note
                .as_deref()
                .expect("a note naming the held-back source");
            assert!(note.contains("source `keychain` held back: "), "{note}");
            assert!(note.contains("bx init"), "{note}");
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                format!(
                    "{}\n# bx phase: plugins\n[[ -r ~/.fzf.zsh ]] && source ~/.fzf.zsh\n{settle}",
                    interactive("")
                )
            );

            // The file's presence is never an input: creating it changes no
            // plan, and nothing bx wrote reads it.
            home.write(".fzf.zsh", "print -r -- fzf\n");
            let present = plan(&home, layer);
            assert!(
                present
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&present)
            );

            // Answering the value is a change the next plan shows, and the
            // source arrives substituted, in the phase it names.
            home.write(".local/state/bx/local.toml", "[values]\nhost = \"box-1\"\n");
            let answered = plan(&home, layer);
            let file = row(&answered, "~/.local/share/bx/zshrc.zsh");
            assert_eq!(file.action, Action::Modify);
            assert_eq!(file.note, None, "nothing is held back");
            apply(&home, layer);
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                format!(
                    "{}\n# bx phase: activations\n\
                     [[ -r ~/.keychain/box-1-sh ]] && source ~/.keychain/box-1-sh\n\
                     \n# bx phase: plugins\n[[ -r ~/.fzf.zsh ]] && source ~/.fzf.zsh\n{settle}",
                    interactive("")
                )
            );
            let settled = plan(&home, layer);
            assert!(
                settled
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&settled)
            );

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            assert_eq!(
                read(&home, ".fzf.zsh"),
                "print -r -- fzf\n",
                "never touched"
            );
        }

        #[test]
        fn each_kind_lands_only_in_its_native_files_and_a_second_plan_is_empty() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let layer = every_kind();

            let first = apply(&home, &layer);
            assert!(first.executed);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Create),
                    ("~/.config/environment.d/50-bx.conf", Action::Create),
                    ("~/.local/share/bx/zprofile.zsh", Action::Create),
                    ("~/.zprofile", Action::Create),
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            // bash reads every variable a zsh would, in zsh's load order,
            // a login one only in a login shell; the GUI one is not a shell's.
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: env\n\
                 export LANG=C.UTF-8\n\
                 if shopt -q login_shell; then\n  export PAGER=less\nfi\n\
                 export EDITOR=nvim\n"
            );

            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                format!("{header}export LANG=C.UTF-8\n")
            );
            assert_eq!(
                read(&home, ".config/environment.d/50-bx.conf"),
                format!("{header}LANG=C.UTF-8\nBROWSER=firefox\n")
            );
            assert_eq!(
                read(&home, ".local/share/bx/zprofile.zsh"),
                format!("{header}export PAGER=less\n")
            );
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                interactive(&format!("{header}export EDITOR=nvim\n"))
            );
            // The user's own lines come first, byte for byte, then the region.
            assert_eq!(
                read(&home, ".zshrc"),
                format!("alias ll='ls -l'\n{ZSHRC_REGION}")
            );
            for (file, fragment) in [(".zshenv", "zshenv"), (".zprofile", "zprofile")] {
                assert_eq!(
                    read(&home, file),
                    format!(
                        "# >>> bx >>>\n[[ -r ~/.local/share/bx/{fragment}.zsh ]] && source \
                         ~/.local/share/bx/{fragment}.zsh\n# <<< bx <<<\n"
                    )
                );
            }

            let written: Vec<String> = [
                ".local/share/bx/zshenv.zsh",
                ".config/environment.d/50-bx.conf",
                ".local/share/bx/zprofile.zsh",
                ".local/share/bx/zshrc.zsh",
                ".zshenv",
                ".zprofile",
                ".zshrc",
            ]
            .iter()
            .map(|rel| read(&home, rel))
            .collect();
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            let again = apply(&home, &layer);
            assert!(!again.executed);
            let rewritten: Vec<String> = [
                ".local/share/bx/zshenv.zsh",
                ".config/environment.d/50-bx.conf",
                ".local/share/bx/zprofile.zsh",
                ".local/share/bx/zshrc.zsh",
                ".zshenv",
                ".zprofile",
                ".zshrc",
            ]
            .iter()
            .map(|rel| read(&home, rel))
            .collect();
            assert_eq!(rewritten, written);
        }

        #[test]
        fn an_edit_outside_the_region_is_never_a_conflict() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            apply(&home, &every_kind());

            // Above the region, below it, and the file's own mode.
            home.write(
                ".zshrc",
                &format!("export FOO=1\nalias ll='ls -l'\n{ZSHRC_REGION}bindkey -v\n"),
            );
            let edited = plan(&home, &every_kind());
            assert_eq!(row(&edited, "~/.zshrc").action, Action::Unchanged);

            // A change of declaration rewrites bx's fragment, and the region's
            // bytes, which never vary, stay as they are.
            let more = format!("{}{}", every_kind(), env("VISUAL", "nvim", "interactive"));
            let changed = apply(&home, &more);
            assert_eq!(
                row(&changed, "~/.local/share/bx/zshrc.zsh").action,
                Action::Modify
            );
            assert_eq!(row(&changed, "~/.zshrc").action, Action::Unchanged);
            assert!(read(&home, ".local/share/bx/zshrc.zsh").ends_with("export VISUAL=nvim\n"));
            assert_eq!(
                read(&home, ".zshrc"),
                format!("export FOO=1\nalias ll='ls -l'\n{ZSHRC_REGION}bindkey -v\n")
            );
        }

        #[test]
        fn an_unset_value_holds_back_only_the_fragment_it_would_join() {
            let home = guarded_home();
            let layer = format!(
                "[[value]]\nname = \"editor\"\nkind = \"string\"\n\n{}{}{}",
                env("LANG", "C.UTF-8", "environment"),
                env("EDITOR", "{{editor}}", "interactive"),
                crate::plan::tests::inline("~/.other", "x\\n"),
            );
            let report = plan(&home, &layer);
            assert_eq!(
                rows(&report),
                vec![
                    ("~/.other", Action::Create),
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Create),
                    ("~/.config/environment.d/50-bx.conf", Action::Create),
                    ("~/.local/share/bx/zshrc.zsh", Action::Blocked),
                    ("~/.zshrc", Action::Create),
                    // bash's file holds EDITOR too, so it waits with zsh's.
                    ("~/.local/share/bx/bashrc.bash", Action::Blocked),
                    ("~/.bashrc", Action::Create),
                ]
            );
            for file in [
                "~/.local/share/bx/zshrc.zsh",
                "~/.local/share/bx/bashrc.bash",
            ] {
                let note = row(&report, file).note.as_deref().expect("a hint");
                assert!(note.contains("editor"), "{note}");
                assert!(note.contains("bx init"), "{note}");
            }
        }

        /// One `[[env]]` entry gated on `when`.
        fn gated(name: &str, value: &str, kind: &str, when: &str) -> String {
            format!("{}when = \"{when}\"\n", env(name, value, kind))
        }

        #[test]
        fn a_gated_variable_is_written_as_decided_and_a_second_plan_is_empty() {
            use std::os::unix::fs::PermissionsExt as _;
            let home = guarded_home();
            // A tool bx finds, by absolute path so no `PATH` is consulted, and
            // one it does not.
            let tool = home.child("opt/tool");
            std::fs::create_dir_all(tool.parent().expect("a parent")).expect("mkdir");
            std::fs::write(&tool, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let tool = tool.to_str().expect("a UTF-8 path");
            let missing = home.child("opt/missing");
            let missing = missing.to_str().expect("a UTF-8 path");
            let layer = [
                gated("PAGER", "less", "login", "ssh"),
                gated("LANG", "C.UTF-8", "environment", &format!("has:{tool}")),
                gated("BROWSER", "firefox", "gui", &format!("has:{missing}")),
                gated("EDITOR", "nvim", "interactive", "env:TMUX"),
            ]
            .concat();

            apply(&home, &layer);
            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            assert_eq!(
                read(&home, ".local/share/bx/zprofile.zsh"),
                format!(
                    "{header}if [[ -n ${{SSH_CONNECTION-}} ]]; then\n  export PAGER=less\nfi\n"
                )
            );
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                interactive(&format!(
                    "{header}if [[ -n ${{TMUX+x}} ]]; then\n  export EDITOR=nvim\nfi\n"
                ))
            );
            // Decided while planning: present is written plainly, missing is
            // left out, and neither asks the shell.
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                format!("{header}export LANG=C.UTF-8\n")
            );
            assert_eq!(
                read(&home, ".config/environment.d/50-bx.conf"),
                format!("{header}LANG=C.UTF-8\n")
            );

            // Unchanged machine, unchanged bytes.
            let again = plan(&home, &layer);
            assert!(
                again
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&again)
            );

            // Installing the missing tool is a change the next plan shows.
            std::fs::write(missing, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(missing, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            let installed = plan(&home, &layer);
            let change = row(&installed, "~/.config/environment.d/50-bx.conf");
            assert_eq!(change.action, Action::Modify);
        }

        #[test]
        fn a_relocating_export_behind_a_condition_is_still_held_back() {
            let home = guarded_home();
            let layer = [
                env("EDITOR", "nvim", "interactive"),
                gated("CARGO_HOME", "/elsewhere/cargo", "interactive", "ssh"),
            ]
            .concat();
            let report = plan(&home, &layer);
            let change = row(&report, "~/.local/share/bx/zshrc.zsh");
            assert_eq!(change.action, Action::Blocked);
            let note = change.note.as_deref().expect("a note");
            // The file's own line: the assembly's header, a blank and the
            // `env` phase's heading come before the fragment's four lines.
            assert!(note.starts_with("line 7: CARGO_HOME "), "{note}");
            let written = interactive(
                "# Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                 export EDITOR=nvim\nif [[ -n ${SSH_CONNECTION-} ]]; then\n  \
                 export CARGO_HOME=/elsewhere/cargo\nfi\n",
            );
            assert!(
                written
                    .lines()
                    .nth(6)
                    .is_some_and(|line| line.contains("CARGO_HOME")),
                "{written}"
            );
        }

        #[test]
        fn a_fragment_the_guard_refuses_is_held_back_naming_the_line() {
            let home = guarded_home();
            let layer = [
                env("LANG", "C.UTF-8", "environment"),
                env("CARGO_HOME", "/elsewhere/cargo", "environment"),
                env("EDITOR", "nvim", "interactive"),
            ]
            .concat();
            let report = plan(&home, &layer);
            for fragment in [
                "~/.local/share/bx/zshenv.zsh",
                "~/.config/environment.d/50-bx.conf",
            ] {
                let change = row(&report, fragment);
                assert_eq!(change.action, Action::Blocked, "{fragment}");
                let note = change.note.as_deref().expect("a note");
                assert!(note.starts_with("line 3: CARGO_HOME "), "{note}");
            }
            // bash's file holds the same line, judged the same way, named by
            // its own line in that file.
            let bash = row(&report, "~/.local/share/bx/bashrc.bash");
            assert_eq!(bash.action, Action::Blocked);
            let note = bash.note.as_deref().expect("a note");
            assert!(note.starts_with("line 5: CARGO_HOME "), "{note}");
            // Nothing else is held back by it.
            assert_eq!(
                row(&report, "~/.local/share/bx/zshrc.zsh").action,
                Action::Create
            );
            assert_eq!(row(&report, "~/.zshenv").action, Action::Create);
        }

        #[test]
        fn an_environment_d_line_is_judged_as_exported() {
            // environment.d says no `export`, and every line of it reaches the
            // environment: an anchor there is held to what an exported one is.
            // Judged as a line of shell that does not say `export`, it would
            // pass.
            let home = guarded_home();
            let layer = format!(
                "[[value]]\nname = \"home_root\"\nkind = \"path\"\nis_root = true\n\
                 default = \"~\"\n\n{}",
                env("SCRATCH_HOME", "{{home_root}}", "gui")
            );
            let report = plan(&home, &layer);
            let change = row(&report, "~/.config/environment.d/50-bx.conf");
            assert_eq!(change.action, Action::Blocked, "{change:?}");
            let note = change.note.as_deref().expect("a note");
            assert!(note.starts_with("line 2: SCRATCH_HOME "), "{note}");
            // The same line, read as shell that keeps it out of the
            // environment, is allowed: the syntax is what refused it.
            let roots = RootSet::new(home.path(), &[PathBuf::from("~")]);
            let line = format!("SCRATCH_HOME={}\n", home.path().display());
            assert_eq!(guard_fragment(&line, &roots), None);
            assert!(guard_environment_d(&line, &roots).is_some());
        }

        /// The `~/.zshrc` row an interactive declaration gets over `bytes`,
        /// with bx having left `recorded` there as a region when it is given.
        fn zshrc_row(bytes: Option<&str>, recorded: Option<&[u8]>) -> Change {
            let home = guarded_home();
            if let Some(recorded) = recorded {
                own(
                    home.path(),
                    ".zshrc",
                    recorded,
                    Mechanism::Region { comment: '#' },
                );
            }
            if let Some(bytes) = bytes {
                home.write(".zshrc", bytes);
            }
            let report = plan(&home, &env("EDITOR", "nvim", "interactive"));
            row(&report, "~/.zshrc").clone()
        }

        #[test]
        fn a_region_is_rewritten_only_while_the_file_is_as_bx_left_it() {
            let old = "top\n# >>> bx >>>\nsource ~/.old\n# <<< bx <<<\n";
            // bx's own older region, in a file nobody has touched since.
            let change = zshrc_row(None, Some(old.as_bytes()));
            assert_eq!(change.action, Action::Modify, "{change:?}");
            // The same, after the user edited the file.
            let change = zshrc_row(Some(&format!("{old}more\n")), Some(old.as_bytes()));
            assert_eq!(change.action, Action::Conflict, "{change:?}");
            assert!(
                change
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("edited since")),
                "{change:?}"
            );
        }

        #[test]
        fn a_region_the_user_removed_or_bx_never_recorded_is_left_alone() {
            let recorded = format!("top\n{ZSHRC_REGION}");
            let removed = zshrc_row(Some("top\n"), Some(recorded.as_bytes()));
            assert_eq!(removed.action, Action::Conflict);
            assert!(
                removed
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("was removed")),
                "{removed:?}"
            );

            let foreign = zshrc_row(
                Some("# >>> bx >>>\nsource ~/.elsewhere\n# <<< bx <<<\n"),
                None,
            );
            assert_eq!(foreign.action, Action::Conflict);
            assert!(
                foreign
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("no record")),
                "{foreign:?}"
            );

            // A region already holding what bx wants is unchanged either way.
            assert_eq!(
                zshrc_row(Some(&format!("mine\n{ZSHRC_REGION}")), None).action,
                Action::Unchanged
            );
        }

        #[test]
        fn a_region_in_a_file_bx_owns_another_way_or_with_damaged_delimiters_is_a_conflict() {
            let home = guarded_home();
            own(home.path(), ".zshrc", b"whole\n", Mechanism::Own);
            let report = plan(&home, &env("EDITOR", "nvim", "interactive"));
            let change = row(&report, "~/.zshrc");
            assert_eq!(change.action, Action::Conflict);
            assert!(
                change
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("the whole file")),
                "{change:?}"
            );

            let damaged = zshrc_row(Some("# >>> bx >>>\nno end\n"), None);
            assert_eq!(damaged.action, Action::Conflict);
            assert_eq!(damaged.diff, None);
            let note = damaged.note.expect("a note");
            assert!(note.contains("damaged"), "{note}");
            assert!(note.contains("no closing one"), "{note}");
        }

        #[test]
        fn a_region_keeps_the_mode_of_the_file_it_joins() {
            let home = guarded_home();
            let rc = home.write(".zshrc", "mine\n");
            std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            let applied = apply(&home, &env("EDITOR", "nvim", "interactive"));
            assert_eq!(row(&applied, "~/.zshrc").action, Action::Modify);
            let mode = std::fs::metadata(&rc).expect("stat").permissions().mode() & 0o7777;
            assert_eq!(mode, 0o600);
            // A file bx creates for a region gets the default.
            let zshenv = apply(&home, &env("LANG", "C", "environment"));
            assert_eq!(row(&zshenv, "~/.zshenv").action, Action::Create);
            let mode = std::fs::metadata(home.child(".zshenv"))
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, Mode::DEFAULT_FILE.bits());
        }

        #[test]
        fn rm_puts_every_file_the_placement_graph_wrote_back_exactly() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let applied = apply(&home, &every_kind());
            assert!(applied.executed);

            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = LedgerView::read(&state, home.path())
                .expect("the ledger")
                .value
                .iter()
                .map(|(target, _)| target.clone())
                .collect();
            assert_eq!(targets.len(), 9);
            crate::restore::restore(&state, home.path(), &targets).expect("restore");

            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            for rel in [
                ".zshenv",
                ".zprofile",
                ".bashrc",
                ".config/environment.d",
                ".local/share/bx",
            ] {
                assert!(!home.child(rel).exists(), "{rel} is left behind");
            }
        }

        /// A `[path]` section: a prepend, a gated prepend, one reading an
        /// `[[env]]` variable, an append, and a removal.
        const PATH_SECTION: &str = "[path]\n\
             prepend = [\"~/bin\", { dir = \"~/.local/bin\", if_exists = true }, \
             \"$CARGO_HOME/bin\"]\n\
             append = [\"/opt/tool/bin\"]\n\
             remove = [\"~/.cargo/bin\"]\n";

        /// The lines [`PATH_SECTION`] puts in the `zshenv` fragment.
        const PATH_LINES: &str = "# [path]\n\
             path=(${path:#${CARGO_HOME}/bin})\n\
             export PATH=${CARGO_HOME}/bin:${PATH}\n\
             path=(${path:#${HOME}/.local/bin})\n\
             [[ -d ${HOME}/.local/bin ]] && export PATH=${HOME}/.local/bin:${PATH}\n\
             path=(${path:#${HOME}/bin})\n\
             export PATH=${HOME}/bin:${PATH}\n\
             path=(${path:#/opt/tool/bin})\n\
             export PATH=${PATH}:/opt/tool/bin\n\
             path=(${path:#${HOME}/.cargo/bin})\n";

        /// The lines [`PATH_SECTION`] puts in bash's file's `path` phase:
        /// zsh's, each removal in bash's words.
        const BASH_PATH_LINES: &str = "# [path]\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${CARGO_HOME}/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             export PATH=${CARGO_HOME}/bin:${PATH}\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/.local/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             [[ -d ${HOME}/.local/bin ]] && export PATH=${HOME}/.local/bin:${PATH}\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             export PATH=${HOME}/bin:${PATH}\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":/opt/tool/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             export PATH=${PATH}:/opt/tool/bin\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/.cargo/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n";

        /// [`PATH_SECTION`] with the variable it reads, under a declared
        /// root.
        fn with_path() -> String {
            format!(
                "[[value]]\nname = \"scratch\"\nkind = \"path\"\nis_root = true\n\
                 default = \"/var/mnt/scratch/example\"\n\n{}{}{}{PATH_SECTION}",
                env("LANG", "C.UTF-8", "environment"),
                env("CARGO_HOME", "{{scratch}}/cargo", "environment"),
                env("EDITOR", "nvim", "interactive"),
            )
        }

        #[test]
        fn path_entries_land_once_in_the_zshenv_fragment_and_bash_s_file_after_their_variables() {
            let home = guarded_home();
            home.write(".zshenv", "# my own\nexport FOO=1\n");
            let layer = with_path();

            let first = apply(&home, &layer);
            assert!(first.executed);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Modify),
                    ("~/.config/environment.d/50-bx.conf", Action::Create),
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Create),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            // The file every zsh reads, login or not: the variables it
            // exports, then the PATH lines that read them.
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                format!(
                    "{header}export LANG=C.UTF-8\n\
                     export CARGO_HOME=/var/mnt/scratch/example/cargo\n{PATH_LINES}"
                )
            );
            // bash's file: its variables, then the same PATH lines in its
            // own words.
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                format!(
                    "# Generated by bx. Edit the config repo, not this file.\n\
                     \n# bx phase: env\nexport LANG=C.UTF-8\n\
                     export CARGO_HOME=/var/mnt/scratch/example/cargo\n\
                     export EDITOR=nvim\n\
                     \n# bx phase: path\n{BASH_PATH_LINES}"
                )
            );
            // And nowhere else.
            for rel in [
                ".config/environment.d/50-bx.conf",
                ".local/share/bx/zshrc.zsh",
            ] {
                assert!(!read(&home, rel).contains("PATH"), "{rel}");
            }
            // The user's own lines survive, byte for byte, ahead of the region.
            assert_eq!(
                read(&home, ".zshenv"),
                "# my own\nexport FOO=1\n# >>> bx >>>\n[[ -r ~/.local/share/bx/zshenv.zsh ]] \
                 && source ~/.local/share/bx/zshenv.zsh\n# <<< bx <<<\n"
            );

            // Applying twice: an empty second plan, and the same bytes.
            let written = read(&home, ".local/share/bx/zshenv.zsh");
            let bash_written = read(&home, ".local/share/bx/bashrc.bash");
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, &layer).executed);
            assert_eq!(read(&home, ".local/share/bx/zshenv.zsh"), written);
            assert_eq!(read(&home, ".local/share/bx/bashrc.bash"), bash_written);

            // A line the user adds beside the region is theirs, and a change
            // of entries rewrites only bx's fragment.
            home.write(
                ".zshenv",
                &format!("{}bindkey -e\n", read(&home, ".zshenv")),
            );
            let fewer = layer.replace(", \"$CARGO_HOME/bin\"", "");
            let changed = apply(&home, &fewer);
            assert_eq!(
                row(&changed, "~/.local/share/bx/zshenv.zsh").action,
                Action::Modify
            );
            assert_eq!(row(&changed, "~/.zshenv").action, Action::Unchanged);
            assert!(read(&home, ".zshenv").starts_with("# my own\nexport FOO=1\n"));
            assert!(read(&home, ".zshenv").ends_with("# <<< bx <<<\nbindkey -e\n"));
            assert!(!read(&home, ".local/share/bx/zshenv.zsh").contains("CARGO_HOME}/bin"));
        }

        #[test]
        fn a_path_section_alone_places_the_zshenv_fragment_bash_s_file_and_their_regions() {
            let home = guarded_home();
            let layer = "[path]\nprepend = [\"~/bin\"]\n";
            let report = plan(&home, layer);
            assert_eq!(
                rows(&report),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Create),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            apply(&home, layer);
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                "# Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                 # [path]\npath=(${path:#${HOME}/bin})\nexport PATH=${HOME}/bin:${PATH}\n"
            );
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: path\n# [path]\n\
                 PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/bin:\"/}; PATH=${PATH//::/:}; \
                 PATH=${PATH#:}; PATH=${PATH%:}\nexport PATH=${HOME}/bin:${PATH}\n"
            );
            // Taking the section out leaves both files setting nothing.
            let emptied = apply(&home, "");
            assert_eq!(
                rows(&emptied),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Modify),
                ]
            );
            assert!(!read(&home, ".local/share/bx/zshenv.zsh").contains("PATH"));
            assert!(!read(&home, ".local/share/bx/bashrc.bash").contains("PATH"));
        }

        #[test]
        fn an_entry_kept_to_one_shell_reaches_only_its_file_and_the_other_row_names_it() {
            let home = guarded_home();
            let layer = "[path]\nprepend = [\"~/both\", { dir = \"~/z\", shells = [\"zsh\"] }, \
                         { dir = \"~/b\", shells = [\"bash\"] }]\n";
            let report = apply(&home, layer);
            let zshenv = read(&home, ".local/share/bx/zshenv.zsh");
            let bashrc = read(&home, ".local/share/bx/bashrc.bash");
            assert!(zshenv.contains("${HOME}/both") && bashrc.contains("${HOME}/both"));
            assert!(zshenv.contains("${HOME}/z:") && !bashrc.contains("${HOME}/z"));
            assert!(bashrc.contains("${HOME}/b:") && !zshenv.contains("${HOME}/b:"));
            let note = row(&report, "~/.local/share/bx/bashrc.bash")
                .note
                .clone()
                .expect("a note");
            assert!(note.ends_with("; not in bash: path `~/z`"), "{note}");
            // An entry kept to bash alone places bash's file and not zsh's.
            let home = guarded_home();
            let only_bash = "[path]\nappend = [{ dir = \"/opt/b\", shells = [\"bash\"] }]\n";
            assert_eq!(
                rows(&plan(&home, only_bash)),
                vec![
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
        }

        #[test]
        fn a_reference_bash_s_file_cannot_read_holds_it_back_naming_its_own_line() {
            let home = guarded_home();
            let layer = format!(
                "{}[path]\nprepend = [\"${{NOWHERE}}/bin\"]\n",
                env("LANG", "C.UTF-8", "environment"),
            );
            let report = plan(&home, &layer);
            let change = row(&report, "~/.local/share/bx/bashrc.bash");
            assert_eq!(change.action, Action::Blocked);
            let note = change.note.as_deref().expect("a note");
            // The header, the env phase's heading and variable, the path
            // phase's heading and comment, then the removal on line 8.
            assert!(note.starts_with("line 8: PATH "), "{note}");
        }

        #[test]
        fn a_reference_to_a_variable_the_file_has_not_exported_holds_the_fragment_back() {
            // EDITOR is exported, but only to interactive shells, from another
            // file; NOWHERE is declared nowhere. Neither is set where the
            // PATH line would read it, so the fragment is held back naming
            // the line, and no other target is.
            for dir in ["$EDITOR/bin", "${NOWHERE}/bin"] {
                let home = guarded_home();
                let layer = format!(
                    "{}{}[path]\nprepend = [\"{dir}\"]\n",
                    env("LANG", "C.UTF-8", "environment"),
                    env("EDITOR", "nvim", "interactive"),
                );
                let report = plan(&home, &layer);
                let change = row(&report, "~/.local/share/bx/zshenv.zsh");
                assert_eq!(change.action, Action::Blocked, "{dir}");
                let note = change.note.as_deref().expect("a note");
                assert!(note.starts_with("line 4: PATH "), "{dir}: {note}");
                assert_eq!(row(&report, "~/.zshenv").action, Action::Create);
                assert_eq!(
                    row(&report, "~/.local/share/bx/zshrc.zsh").action,
                    Action::Create
                );
            }
        }
    }
}
