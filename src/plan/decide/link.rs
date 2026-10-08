//! The decision for a symlink target, which is compared by its text alone.

use std::path::{Path, PathBuf};

use super::parent::{Write, created_dirs, locked_parent};
use super::{Ctx, Made, Op, attached_as, join, portable_reason};
use crate::config::target::Target;
use crate::fs::{self, Kind, Mode, Observed};
use crate::plan::{Change, Diff, Error};
use crate::report::Action;
use crate::state::{LedgerEntry, Mechanism};

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
pub(super) fn decide_link(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    use crate::plan::tests::{apply, inputs, link, own, plan, snapshot, symlink, text_of};
    use crate::plan::{Mode, Palette, View, exit, render, run};
    use crate::report::Exit;
    use crate::state::LedgerView;
    use crate::testing::guarded_home;

    #[test]
    fn a_symlink_and_an_empty_file_are_delivered_and_a_second_plan_is_empty() {
        let home = guarded_home();
        let layer = [
            symlink("~/.local/bin/tool", "../../src/tool/bin/tool"),
            symlink("~/.toolrc", "~/dotfiles/toolrc"),
            "[[target]]\npath = \"~/.hushlogin\"\ncontent = \"\"\nmode = \"0600\"\n".to_string(),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Create; 3]);
        assert_eq!(
            link(&planned.changes[0]),
            (None, Some("../../src/tool/bin/tool"))
        );
        let rendered = format!("{}/dotfiles/toolrc", home.path().display());
        assert_eq!(
            link(&planned.changes[1]),
            (None, Some(rendered.as_str())),
            "a leading `~` is the one thing rendered"
        );
        let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
        assert!(
            shown.contains("\n    + symlink ../../src/tool/bin/tool\n"),
            "{shown}"
        );

        let applied = apply(&inputs);
        assert!(applied.executed);
        assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
        let tool = home.child(".local/bin/tool");
        assert_eq!(text_of(&tool), Path::new("../../src/tool/bin/tool"));
        assert!(!tool.exists(), "made dangling, and never followed");
        assert_eq!(text_of(&home.child(".toolrc")), Path::new(&rendered));
        let empty = std::fs::symlink_metadata(home.child(".hushlogin")).expect("a file");
        assert!(empty.is_file());
        assert_eq!(empty.len(), 0, "an empty body is a zero-byte file");
        assert_eq!(empty.permissions().mode() & 0o7777, 0o600);

        let after = plan(&inputs);
        assert_eq!(after.actions(), vec![Action::Unchanged; 3]);
        assert_eq!(exit(&after, Mode::Plan), Exit::Converged);
        let written = snapshot(home.path(), &[".local/state/bx/lock"]);
        let second = run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve"))
            .expect("the second apply");
        assert!(!second.executed);
        assert_eq!(snapshot(home.path(), &[".local/state/bx/lock"]), written);
        assert_eq!(text_of(&tool), Path::new("../../src/tool/bin/tool"));
    }

    #[test]
    fn a_link_bx_made_is_retargeted_showing_the_old_and_new_text() {
        let home = guarded_home();
        apply(&inputs(&home, &symlink("~/.tool", "/opt/one")));
        let inputs = inputs(&home, &symlink("~/.tool", "/opt/two"));

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Modify]);
        assert_eq!(
            link(&planned.changes[0]),
            (Some("/opt/one"), Some("/opt/two"))
        );
        let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
        assert!(
            shown.contains("\n    - symlink /opt/one\n    + symlink /opt/two\n"),
            "{shown}"
        );

        apply(&inputs);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/two"));
        assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
    }

    #[test]
    fn a_path_bx_did_not_link_is_never_replaced_and_a_link_already_right_is_adopted() {
        let home = guarded_home();
        std::os::unix::fs::symlink("elsewhere", home.child(".a")).expect("the user's link");
        std::os::unix::fs::symlink("/opt/b", home.child(".b")).expect("the user's link");
        home.write(".c", "mine\n");
        std::fs::create_dir(home.child(".d")).expect("a directory");
        let layer = [
            symlink("~/.a", "/opt/a"),
            symlink("~/.b", "/opt/b"),
            symlink("~/.c", "/opt/c"),
            symlink("~/.d", "/opt/d"),
            symlink("~/.c/inner", "/opt/inner"),
        ]
        .concat();
        let inputs = inputs(&home, &layer);

        let planned = plan(&inputs);
        assert_eq!(
            planned.actions(),
            vec![
                Action::Conflict,
                Action::Unchanged,
                Action::Conflict,
                Action::Conflict,
                Action::Conflict,
            ]
        );
        assert!(
            planned.changes[4]
                .note
                .as_deref()
                .is_some_and(|note| note.starts_with("~/.c ")),
            "an unusable parent is named portably: {:?}",
            planned.changes[4].note
        );
        let note = |at: usize| planned.changes[at].note.clone().unwrap_or_default();
        assert!(note(0).contains("a symlink bx did not make"), "{}", note(0));
        assert_eq!(
            link(&planned.changes[0]),
            (Some("elsewhere"), Some("/opt/a"))
        );
        assert!(note(2).contains("a regular file"), "{}", note(2));
        assert!(note(3).contains("a directory"), "{}", note(3));
        assert_eq!(planned.changes[2].diff, None);

        let applied = apply(&inputs);
        assert!(!applied.executed, "nothing to write");
        assert_eq!(text_of(&home.child(".a")), Path::new("elsewhere"));
        assert_eq!(std::fs::read(home.child(".c")).expect("kept"), b"mine\n");
        assert!(home.child(".d").is_dir());
        let ledger = LedgerView::read(inputs.state(), home.path())
            .expect("the ledger")
            .value;
        assert!(ledger.is_empty(), "an adopted link is recorded by no write");
    }

    #[test]
    fn link_text_that_differs_only_by_normalisation_is_different_text() {
        // `Path` equality would call each pair equal; the link text is compared
        // byte for byte, as it is stored exactly as written.
        let pairs = [
            ("/opt/x", "/opt/x/"),
            ("/opt/x/", "/opt/x"),
            ("a//b", "a/b"),
            ("a/./b", "a/b"),
        ];
        for (made, declared) in pairs {
            // A link bx made is retargeted to the declared text.
            let home = guarded_home();
            apply(&inputs(&home, &symlink("~/.tool", made)));
            let retarget = inputs(&home, &symlink("~/.tool", declared));
            let planned = plan(&retarget);
            assert_eq!(
                planned.actions(),
                vec![Action::Modify],
                "{made} -> {declared}"
            );
            assert_eq!(link(&planned.changes[0]), (Some(made), Some(declared)));
            apply(&retarget);
            assert_eq!(
                text_of(&home.child(".tool")).as_os_str(),
                std::ffi::OsStr::new(declared)
            );
            assert_eq!(plan(&retarget).actions(), vec![Action::Unchanged]);

            // A user's link with that text is theirs, not adopted.
            let home = guarded_home();
            std::os::unix::fs::symlink(made, home.child(".tool")).expect("the user's link");
            let theirs = inputs(&home, &symlink("~/.tool", declared));
            assert_eq!(
                plan(&theirs).actions(),
                vec![Action::Conflict],
                "{made} -> {declared}"
            );
            assert!(!apply(&theirs).executed);
            let os = std::fs::read_link(home.child(".tool")).expect("a link");
            assert_eq!(os.as_os_str(), std::ffi::OsStr::new(made));
        }
    }

    #[test]
    fn a_link_retargeted_since_bx_made_it_and_a_path_bx_owns_otherwise_are_conflicts() {
        let home = guarded_home();
        apply(&inputs(&home, &symlink("~/.tool", "/opt/one")));
        std::fs::remove_file(home.child(".tool")).expect("unlink");
        std::os::unix::fs::symlink("/opt/theirs", home.child(".tool")).expect("retarget");
        own(home.path(), ".f", b"bx\n", Mechanism::Own);
        std::fs::remove_file(home.child(".f")).expect("the user removes it");
        let inputs = inputs(
            &home,
            &[symlink("~/.tool", "/opt/two"), symlink("~/.f", "/opt/f")].concat(),
        );

        let planned = plan(&inputs);
        assert_eq!(planned.actions(), vec![Action::Conflict; 2]);
        assert_eq!(
            planned.changes[0].note.as_deref(),
            Some("retargeted since bx made it")
        );
        assert_eq!(
            planned.changes[1].note.as_deref(),
            Some("bx attached to this path as the whole file")
        );
        assert!(!apply(&inputs).executed);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/theirs"));
    }
}
