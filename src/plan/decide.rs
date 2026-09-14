//! One decision per target: the only code that turns configuration into work.
//!
//! [`decide`] reads the target's body, observes its destination, compares the
//! two with [`crate::fs::compare`], and consults the ledger for ownership. It
//! is handed shared references only and knows nothing of the mode it runs in,
//! so `plan` and `apply` cannot reach different verdicts from one input.

use std::path::Path;

use super::{Change, Diff, Error};
use crate::config::resolve::Resolution;
use crate::config::target::{Attach, Body, Direction, Format, Gen, Target};
use crate::env_guard::{self, RootSet};
use crate::fs::{self, Desired, Kind, Mode, Observed};
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

/// Decide what to do about one resolved target.
///
/// # Errors
///
/// [`Error::Body`] when a `file` body cannot be read from the config repo, and
/// [`Error::Fs`] when the destination cannot be observed.
pub(super) fn decide(resolution: &Resolution<Target>, ctx: &Ctx<'_>) -> Result<Change, Error> {
    let target = match resolution {
        Resolution::Ready(target) => target,
        Resolution::Blocked(entry) => {
            return Ok(Change {
                target: entry.key.clone(),
                origin: entry.origin.clone(),
                action: Action::Blocked,
                diff: None,
                note: Some(entry.hint.clone()),
            });
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
        Wanted::Blocked(note) => return Ok(row(Action::Blocked, None, Some(note))),
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
    );
    let (action, note) = ownership(
        outcome.action,
        &observed,
        ctx.ledger.get(&target.path),
        join([outcome.note, outcome.parent_note]),
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
    Ok(row(action, diff, note))
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

/// The present parts, joined with `; `, or `None` when there are none.
fn join(parts: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    let parts: Vec<String> = parts.into_iter().flatten().collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::Origin;
    use crate::config::target::KeyPath;
    use crate::paths::Portable;
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
    fn decision_3_an_unsupported_shape_is_blocked_before_anything_is_read() {
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
            let change = decide(&Resolution::Ready(target.clone()), &ctx).expect("no read");
            assert_eq!(change.action, Action::Blocked, "{target:?}");
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
    fn the_supported_shape_is_not_unsupported() {
        let home = guarded_home();
        assert_eq!(unsupported(&a_target(home.path(), "~/.a")), None);
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
