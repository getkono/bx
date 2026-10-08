//! The decision for a directory target, which bx creates or sets the mode of
//! and never looks inside.

use super::parent::{Write, locked_parent, missing_parents};
use super::{Ctx, Made, Op, attached_as, join, portable_reason};
use crate::config::target::Target;
use crate::fs::{self, Kind, Mode, Observed};
use crate::paths;
use crate::plan::{Change, Diff, Error};
use crate::report::Action;
use crate::state::{LedgerEntry, Mechanism};

/// Decide a directory target: create it, set its mode, leave it, or refuse.
///
/// The verdict is [`crate::fs::compare_dir`]'s, the one [`crate::fs::ensure_dir`]
/// checks again before it acts, settled against the ledger by
/// [`dir_ownership`]. A create is also refused when the directory it would be
/// made in denies its owner write or search, as a file's write is, and a mode
/// change when the directory it is in denies its owner search. Only the
/// directory is decided, never what is inside it, and a mode change is shown
/// as one: there are no bytes to diff.
pub(super) fn decide_dir(
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
        outcome.drift.into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::decide::tests::{
        a_directory_target, a_target, apply_of, locked_dir_at, mode_on_disk, plan_of, row_for,
    };
    use crate::plan::decide::*;
    use crate::testing::guarded_home;

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
            host: &activation::System::from_env(),
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
            written: crate::state::dir_digest(),
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
}
