//! The directory a write lands in: whether `apply` can write inside it, the
//! note a file gets for the declared directory it sits in, and the directories
//! a create makes on the way to it.

use std::path::Path;

use super::{Ctx, Declared};
use crate::fs::{Mode, Observed};
use crate::paths;

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
/// file is written — see [`super::decide_all`] — so the mode a write beneath it meets
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
pub(super) fn locked_parent(
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
pub(super) enum Write<'a> {
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

/// The parent note a file gets when its parent is a declared directory: the
/// declared mode is the one the file will sit in, whatever is on disk now.
///
/// `None` when the parent is not declared, so the comparison's own note
/// stands; `Some(None)` when the declared mode is not wider than the file's.
pub(super) fn parent_note(
    observed: &Observed,
    mode: Mode,
    ctx: &Ctx<'_>,
) -> Option<Option<String>> {
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
pub(super) fn created_dirs(
    observed: &Observed,
    home: &Path,
    declared: &Declared,
) -> Option<String> {
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
pub(super) fn missing_parents<'a>(path: &'a Path, declared: &Declared) -> Vec<&'a Path> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::decide::tests::{
        a_directory_target, apply_of, locked_dir_at, mode_on_disk, plan_of, row_for,
    };
    use crate::plan::decide::*;
    use crate::testing::guarded_home;

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
    fn a_symlink_create_names_every_directory_apply_creates_for_it() {
        let home = guarded_home();
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/.tool/deep/link\"\nsymlink = \"/opt/x\"\n",
        );

        let row = row_for(&plan_of(&inputs), "~/.tool/deep/link").clone();
        assert_eq!(row.action, Action::Create, "{row:?}");
        assert_eq!(
            row.note.as_deref(),
            Some("creates ~/.tool 0755, ~/.tool/deep 0755"),
            "plan announces every directory apply makes for the link"
        );
        assert!(!home.child(".tool").exists(), "plan created a parent");
    }

    #[test]
    fn a_tracked_copy_put_onto_this_machine_names_every_directory_apply_creates() {
        let home = guarded_home();
        home.write(".config/bx/files/tool.conf", "x\n");
        let inputs = crate::plan::tests::inputs(
            &home,
            "[[target]]\npath = \"~/.tool/deep/tool.conf\"\nfile = \"files/tool.conf\"\n\
             direction = \"track\"\n",
        );

        let row = row_for(&plan_of(&inputs), "~/.tool/deep/tool.conf").clone();
        assert_eq!(row.action, Action::Create, "{row:?}");
        assert_eq!(
            row.note.as_deref(),
            Some(
                "this machine has no copy; apply writes the repo's; \
                 creates ~/.tool 0755, ~/.tool/deep 0755"
            ),
            "plan announces every directory apply makes for the copy"
        );
        assert!(!home.child(".tool").exists(), "plan created a parent");
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
}
