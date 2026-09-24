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

use std::path::{Path, PathBuf};

use super::{Change, Diff, Error};
use crate::config::resolve::Resolution;
use crate::config::target::{Attach, Body, Direction, Format, Gen, Target};
use crate::env_guard::{self, RootSet};
use crate::fs::{self, Desired, Kind, Mode, Observed};
use crate::journal::{Content, Ownership, Request};
use crate::paths::{self, Portable};
use crate::report::Action;
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
///   conflict, with a note saying `apply` could not write there — untrue, since
///   every `Body::Dir` target is blocked in [`wanted`], so no declared
///   directory mode reaches disk at all and the parent is created at
///   [`Mode::DEFAULT_DIR`].
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
/// Every mode that denies search is therefore unreachable here, whether or not
/// it denies write, and every mode that reaches here and denies write allows
/// search. One bit decides it. `a_parent_bx_cannot_search_stops_the_run_before
/// _any_decision` is the witness, and it asserts the failure rather than
/// describing it, so the argument is recomputed on every run rather than taken
/// on trust.
fn locked_parent(observed: &Observed, home: &Path) -> Option<String> {
    let parent = observed.parent.as_ref()?;
    let (dir, mode) = match parent.state {
        crate::fs::ParentState::Present(mode) => (parent.path.as_path(), mode),
        crate::fs::ParentState::Absent(_) => deepest_existing(&parent.path)?,
        crate::fs::ParentState::Unusable(_) => return None,
    };
    if mode.bits() & 0o200 != 0 {
        return None;
    }
    let shown = paths::to_portable(dir, home);
    Some(if dir == parent.path {
        format!(
            "{shown} is {mode} on disk, which denies its owner write, so apply could not write \
             a file inside it"
        )
    } else {
        format!(
            "{shown} is {mode} on disk, which denies its owner write, so apply could not create \
             {} inside it",
            paths::to_portable(&parent.path, home)
        )
    })
}

/// The deepest ancestor of `dir` that resolves to a directory, with its mode.
///
/// Read with `metadata`, which follows symlinks, because a symlinked parent is
/// written *through* — decision 2 — so the directory that governs the write is
/// the one the link resolves to, exactly as [`crate::fs::observe`] reads it.
fn deepest_existing(dir: &Path) -> Option<(&Path, Mode)> {
    use std::os::unix::fs::PermissionsExt as _;

    dir.ancestors()
        .filter(|path| !path.as_os_str().is_empty())
        .find_map(|path| {
            let meta = std::fs::metadata(path).ok()?;
            meta.is_dir()
                .then(|| (path, Mode::from_bits(meta.permissions().mode())))
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
    bytes: Vec<u8>,
    planned: Observed,
    mode: Mode,
}

impl Op {
    /// The target the write is for.
    pub(super) const fn target(&self) -> &Portable {
        &self.target
    }

    /// The journal request that makes this write, bx owning the whole file.
    pub(super) fn into_request(self) -> Request {
        Request {
            target: self.target,
            dest: self.dest,
            content: Content::Bytes {
                bytes: self.bytes,
                planned: self.planned,
            },
            mode: self.mode,
            ownership: Ownership::Owned(Mechanism::Own),
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
    let row = |action, diff, note| Change {
        target: target.path.as_str().to_string(),
        origin: target.origin.clone(),
        action,
        diff,
        note,
    };

    let bytes = match wanted(target, ctx)? {
        Wanted::Bytes(bytes) => bytes,
        Wanted::Blocked(note) => return Ok((row(Action::Blocked, None, Some(note)), None)),
    };

    let dest = target.path.render(ctx.home);
    let observed = fs::observe(&dest)?;
    let mode = Mode::resolve(target.mode, Kind::File);
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
    let (action, note) = ownership(
        outcome.action,
        &observed,
        ctx.ledger.get(&target.path),
        join([note, outcome.parent_note]),
    );

    // A write into a directory its owner cannot write or search is refused
    // here, so `apply` never reaches `stage` for it. A row with no write is
    // left as it is: there is nothing to refuse.
    let (action, note) = match (action.is_pending(), locked_parent(&observed, ctx.home)) {
        (true, Some(why)) => (Action::Conflict, join([Some(why), note])),
        _ => (action, note),
    };

    // Only a regular file has a side to show: a directory, a link or an
    // unusable parent is explained by the note alone.
    let shown = match action {
        Action::Create | Action::Modify => true,
        Action::Conflict => observed.kind == Kind::File,
        Action::Unchanged | Action::Blocked => false,
    };
    let diff = shown
        .then(|| {
            Diff::between(
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
        Action::Create => join([created_dirs(&observed, ctx.home), note]),
        _ => note,
    };
    let change = row(action, diff, note);
    let op = action.is_pending().then(|| Op {
        target: target.path.clone(),
        dest,
        bytes,
        planned: observed,
        mode,
    });
    Ok((change, op))
}

/// The directories a write to `observed` creates, shallowest first — the order
/// `apply` makes them in — each with the mode it is made at, or `None` when
/// the parent is already there.
///
/// The observation says whether the parent is absent and the mode it would be
/// made at, and nothing declares a directory's mode in this entry, so every
/// missing ancestor is made at that mode. Which ancestors are missing is read
/// here with the walk `stage` makes before creating them.
fn created_dirs(observed: &Observed, home: &Path) -> Option<String> {
    let parent = observed.parent.as_ref()?;
    let crate::fs::ParentState::Absent(mode) = &parent.state else {
        return None;
    };
    let mut missing: Vec<&Path> = parent
        .path
        .ancestors()
        .filter(|dir| !dir.as_os_str().is_empty())
        .take_while(|dir| {
            matches!(
                std::fs::symlink_metadata(dir),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            )
        })
        .collect();
    missing.reverse();
    (!missing.is_empty()).then(|| {
        let named: Vec<String> = missing
            .iter()
            .map(|dir| format!("{} {mode}", paths::to_portable(dir, home)))
            .collect();
        format!("creates {}", named.join(", "))
    })
}

/// The bytes a target wants, or why it cannot have any yet.
#[derive(Debug, PartialEq, Eq)]
enum Wanted {
    /// The whole content.
    Bytes(Vec<u8>),
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
        Body::File(rel) => {
            let path = ctx.repo.join(rel);
            let body = |source| Error::Body {
                origin: target.origin.clone(),
                path: path.clone(),
                source,
            };
            // Followed through a link, since a body the repo links to is the
            // user's layout. Anything but a regular file at the end of it — a
            // FIFO, a device — would block the read or never end it.
            if std::fs::metadata(&path).is_ok_and(|meta| !meta.is_file()) {
                return Err(body(std::io::Error::other("not a regular file")));
            }
            std::fs::read(&path).map_err(body)?
        }
        Body::Generated(generator) => {
            let content = generate(generator);
            if let Some(note) = guard_fragment(&content, ctx.roots) {
                return Ok(Wanted::Blocked(note));
            }
            content.into_bytes()
        }
        // Decision 16: directory targets are declared by the configuration and
        // written by no entry in this stack, and issue #43 ("plan and apply:
        // deliver directory targets (`dir = true`) end to end") owns closing
        // that. It is the entry F1 (#37) needs, and it is open. The note stays
        // generic rather than naming #43, because a note is user-facing text
        // and an issue number is a fact about this repository's backlog.
        //
        // Every rule that reads a directory's mode depends on this arm: while
        // it stands, no declared directory mode reaches disk, which is the
        // argument [`locked_parent`] rests on. The entry that removes this arm
        // has to revisit that function in the same change.
        Body::Dir => {
            return Ok(Wanted::Blocked(
                "a directory target is not supported until a later entry".to_string(),
            ));
        }
    };
    Ok(Wanted::Bytes(bytes))
}

/// Why a target's attachment, direction or format cannot be written yet.
fn unsupported(target: &Target) -> Option<&'static str> {
    match (&target.attach, target.direction, &target.format) {
        (Attach::Region { .. }, _, _) => Some("a managed region is not supported until entry C1"),
        (Attach::Include { .. }, _, _) => Some("an include line is not supported until entry C1"),
        (_, Direction::Track, _) => Some("track mode is not supported until entry C4"),
        (_, _, Format::Jsonc { .. }) => Some("owning JSONC keys is not supported until entry C3"),
        (_, _, Format::EnvD) => Some("an env.d fragment is not supported until entry B1"),
        (Attach::Own, Direction::Apply, Format::Opaque) => None,
    }
}

/// The content a generator produces.
///
/// [`Gen`] has no variants yet, so this cannot be called. It exists so the one
/// route from a generated body to bytes already passes through
/// [`guard_fragment`]: the first generator adds its arm here.
///
/// # Decision 36: `generate -> String::new()` is an equivalent mutant
///
/// `cargo mutants` reports that mutant as missed, and no test can kill it:
/// `Gen` is uninhabited, so no `Body::Generated` value exists and this function
/// is unreachable. The entry that adds the first `Gen` variant makes the arm
/// reachable, and must test its generated body end to end through
/// [`guard_fragment`]; the mutant becomes killable by that entry's tests.
const fn generate(generator: &Gen) -> String {
    match *generator {}
}

/// Judge a generated environment fragment against Invariant 2.
///
/// `None` when every assignment is one bx may write; otherwise one note naming
/// each violation as `line N: NAME <reason>`. Applied to generated bodies only:
/// the guard's grammar admits nothing but assignments, and a file the user
/// wrote is not bx's output to judge.
pub(super) fn guard_fragment(content: &str, roots: &RootSet) -> Option<String> {
    join(
        env_guard::scan_with(content, roots)
            .iter()
            .map(|v| Some(format!("line {}: {} {}", v.line, v.name, v.reason))),
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

/// How a ledger mechanism reads in a note.
const fn attached_as(mechanism: &Mechanism) -> &'static str {
    match mechanism {
        Mechanism::Own => "the whole file",
        Mechanism::Region { .. } => "a managed region",
        Mechanism::Include { .. } => "an include line",
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
        };
        let shaped = |change: fn(&mut Target)| {
            let mut target = a_target(home.path(), "~/.a");
            // A body that cannot be read, so a read before the block would err.
            target.body = Body::File(PathBuf::from("absent"));
            change(&mut target);
            target
        };
        let cases: [(Target, &str); 6] = [
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
            (shaped(|t| t.direction = Direction::Track), "entry C4"),
            (
                shaped(|t| {
                    t.format = Format::Jsonc {
                        owns: vec![KeyPath::parse("a.b").expect("a key path")],
                    };
                }),
                "entry C3",
            ),
            (shaped(|t| t.format = Format::EnvD), "entry B1"),
            (shaped(|t| t.body = Body::Dir), "a later entry"),
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
            Content::Absent { .. } => panic!("a create is bytes"),
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

    #[test]
    fn decision_24_a_declared_directory_mode_decides_nothing_beneath_it() {
        // P42R2-D2. A `dir = true` target declared 0555 whose directory is
        // absent used to turn every file beneath it into a Conflict whose note
        // said apply could not write there. That was untrue: every directory
        // target is Blocked in `wanted`, so the declared mode never reaches
        // disk and `create_missing_dirs` makes the parent at DEFAULT_DIR. The
        // control arm is the identical layer with the directory target removed
        // — it always applied cleanly, and the two now agree.
        for layer in [
            a_directory_target("0555", &crate::plan::tests::inline("~/.d/f", "x\\n")),
            crate::plan::tests::inline("~/.d/f", "x\\n"),
        ] {
            let home = guarded_home();
            let inputs = crate::plan::tests::inputs(&home, &layer);

            let report = crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false))
                .expect("plan");
            assert_eq!(
                row_for(&report, "~/.d/f").action,
                Action::Create,
                "{report:?}"
            );

            let applied = crate::plan::run(&inputs, crate::plan::Mode::Apply, &mut |_| Ok(true))
                .expect("apply");
            assert!(applied.executed, "{report:?}");
            assert_eq!(std::fs::read(home.child(".d/f")).expect("written"), b"x\n");
            assert_eq!(
                fs::observe(&home.child(".d")).expect("observe").mode,
                Some(Mode::DEFAULT_DIR),
                "the declared 0555 reached disk"
            );
        }
    }

    #[test]
    fn decision_3_a_directory_target_is_blocked_at_every_mode_it_can_declare() {
        // P42R2-COV5 replaces a test whose name claimed a childless locked
        // directory target "keeps any declared mode" while its only assertion
        // was that one such target is Blocked — true of every directory target
        // at every mode, so the name was evidence of a distinction the code
        // never drew. Mode-independence is the property that does hold, so the
        // mode is what varies, and declaring none is one of the cases.
        for layer in [
            a_directory_target("0755", ""),
            a_directory_target("0555", ""),
            a_directory_target("0444", ""),
            "[[target]]\npath = \"~/.d\"\ndir = true\n".to_string(),
        ] {
            let home = guarded_home();
            let inputs = crate::plan::tests::inputs(&home, &layer);

            let report = crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false))
                .expect("plan");

            assert_eq!(
                report.actions(),
                vec![Action::Blocked],
                "{layer}: {report:?}"
            );
            assert!(
                !home.child(".d").exists(),
                "{layer}: the directory was made"
            );
        }
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
    }
}
