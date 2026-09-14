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
            std::fs::read(&path).map_err(|source| Error::Body {
                origin: target.origin.clone(),
                path,
                source,
            })?
        }
        Body::Generated(generator) => {
            let content = generate(generator);
            if let Some(note) = guard_fragment(&content, ctx.roots) {
                return Ok(Wanted::Blocked(note));
            }
            content.into_bytes()
        }
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
