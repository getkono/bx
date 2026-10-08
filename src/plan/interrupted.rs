//! What a run shows over an interrupted session: one row per write the
//! session announced, saying what recovery does to it.

use std::path::PathBuf;

use super::{Change, Diff, Error, Inputs};
use crate::config::Origin;
use crate::config::resolve::Resolution;
use crate::paths;
use crate::recover::{self, Interrupted};
use crate::report::Action;
use crate::{journal, state};

/// The rows an interrupted session gives a run: what recovery would do to each
/// write the session announced, in the order it announced them.
///
/// A write in a session that did not finish, and that recovery can resolve on
/// its own, is rolled back. Its row is a modify with the diff from what is on
/// disk to what was there before — every line removed, for a file the session
/// created — and names the directories the session created that recovery
/// removes where empty. A write in a session that finished is only recorded,
/// which touches no file, so its row is unchanged. A write recovery cannot
/// account for is a conflict whose note names abandon.
///
/// The prior bytes a diff shows are read from the journal and its restore
/// snapshot, lockless, as `pending` read them. A snapshot that cannot be read
/// now leaves the row without a diff rather than guessing at one.
pub(super) fn interrupted_rows(
    inputs: &Inputs,
    interrupted: &Interrupted,
) -> Result<Vec<Change>, Error> {
    let loaded = journal::load(&inputs.state.journal())?;
    let mut rows = Vec::with_capacity(interrupted.unfinished.len());
    for unfinished in &interrupted.unfinished {
        let target = unfinished.target.as_str();
        // The target as written, found by where it resolved to or, when its
        // resolution is blocked, by the path as written. Whether it is a
        // secret is read from the declared body, which a blocked resolution
        // still has.
        let configured = inputs
            .declared_targets()
            .find(|(declared, resolution)| match resolution {
                Resolution::Ready(ready) => ready.path.as_str() == target,
                Resolution::Blocked(_) => declared.path.as_str() == target,
            })
            .map(|(declared, _)| declared);
        let origin = configured.map_or_else(
            || Origin::unknown(&interrupted.journal),
            |declared| declared.origin.clone(),
        );
        // A secret's plaintext is on one side of its roll back, or both, and
        // is never shown here either. A write no declared target claims is
        // concealed too: the journal does not say whether it was a secret, and
        // a secret whose target was removed, whose path was edited, or whose
        // path now resolves elsewhere or waits on a value leaves exactly such
        // a write. Showing a secret's bytes is worse than hiding an ordinary
        // file's.
        let conceal = configured
            .is_none_or(|declared| matches!(declared.body, crate::config::target::Body::Secret(_)));
        let between = if conceal {
            Diff::concealed
        } else {
            Diff::between
        };
        let row = |action, diff, note: String| Change {
            target: target.to_string(),
            origin: origin.clone(),
            action,
            diff,
            note: Some(note),
        };

        if !unfinished.resolvable {
            let note = if unfinished.note.contains("abandon") {
                unfinished.note.clone()
            } else {
                format!(
                    "{}; recovery cannot put it back, so the interrupted session has to be \
                     abandoned",
                    unfinished.note
                )
            };
            rows.push(row(Action::Conflict, None, note));
            continue;
        }
        if interrupted.complete {
            rows.push(row(Action::Unchanged, None, unfinished.note.clone()));
            continue;
        }

        let intent = loaded
            .intents()
            .find(|intent| intent.target == unfinished.target);
        let observed = crate::fs::observe(&unfinished.dest)?;
        let written = unfinished.standing == recover::Standing::Written;
        let dir = intent.is_some_and(|intent| intent.dir);
        let link = intent.is_some_and(|intent| intent.link);
        let (diff, what) = match (written, intent.map(|intent| &intent.before)) {
            // A link's row shows its text on each side, as `plan` shows a
            // symlink target's: the link recovery puts back was stored as
            // its text.
            (true, Some(state::Prior::Existed(reference))) if link => {
                let prior = state::restore::read(&inputs.state, reference)
                    .ok()
                    .map(|bytes| {
                        PathBuf::from(
                            <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(
                                bytes,
                            ),
                        )
                    });
                (
                    prior.map(|prior| Diff::link(observed.link.as_deref(), Some(&prior))),
                    "rolls back: puts back the link that was there before",
                )
            }
            (true, Some(state::Prior::Absent)) if link => (
                Some(Diff::link(observed.link.as_deref(), None)),
                "rolls back: removes the link the session made",
            ),
            // A directory has no bytes to diff: its row says what recovery
            // does to it, and a mode it puts back is shown as one.
            (true, Some(state::Prior::Existed(reference))) if dir => {
                match (observed.mode, intent.map(|intent| intent.after)) {
                    (Some(found), Some(journal::Written::Present { .. })) => (
                        Some(Diff::mode(found, reference.mode)),
                        "rolls back: puts back the mode it had",
                    ),
                    _ => (
                        None,
                        "rolls back: makes the directory the session removed again",
                    ),
                }
            }
            (true, Some(state::Prior::Absent)) if dir => (
                None,
                "rolls back: removes the directory the session created where empty",
            ),
            (true, Some(state::Prior::Existed(reference))) => {
                let prior = state::restore::read(&inputs.state, reference).ok();
                let mode = observed
                    .mode
                    .filter(|mode| *mode != reference.mode)
                    .map(|mode| (mode, reference.mode));
                (
                    prior
                        .and_then(|prior| between(target, observed.bytes.as_deref(), &prior, mode)),
                    "rolls back: puts back what was there before",
                )
            }
            (true, Some(state::Prior::Absent)) => (
                between(target, observed.bytes.as_deref(), b"", None),
                "rolls back: removes the file the session created",
            ),
            (true, None) => (None, "rolls back what the session wrote"),
            (false, _) => (None, "rolls back: it already holds what was there before"),
        };
        let dirs: Vec<String> = intent
            .map(|intent| {
                intent
                    .created_dirs
                    .iter()
                    .rev()
                    .filter(|dir| std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()))
                    .map(|dir| paths::to_portable(dir, &inputs.home))
                    .collect()
            })
            .unwrap_or_default();
        let note = if dirs.is_empty() {
            what.to_string()
        } else {
            format!("{what}; removes {} where empty", dirs.join(", "))
        };
        let action = if written || !dirs.is_empty() {
            Action::Modify
        } else {
            Action::Unchanged
        };
        rows.push(row(action, diff, note));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;
    use crate::fs::{self, Mode as FileMode};
    use crate::journal::tests::finish_crash_phases;
    use crate::journal::{Content, Ownership, Request, Session, SessionKind};
    use crate::paths::Portable;
    use crate::plan::diff;
    use crate::plan::tests::{
        CRASH_WRITES, SECRET_TARGET, age_identity, apply, inline, inputs, link, load, own, plan,
        seal, seed, seed_crash, snapshot, spawn_crash_child, symlink, text_of,
    };
    use crate::plan::{DiffKind, Mode, Palette, View, exit, render, run};
    use crate::report::Exit;
    use crate::state::Mechanism;
    use crate::testing::guarded_home;

    #[test]
    fn an_interrupted_link_is_shown_as_the_link_recovery_puts_back() {
        let home = guarded_home();
        apply(&inputs(&home, &symlink("~/.tool", "/opt/one")));
        let inputs = inputs(
            &home,
            &[
                symlink("~/.tool", "/opt/two"),
                symlink("~/.new", "/opt/new"),
            ]
            .concat(),
        );
        let mut session = Session::open(inputs.state(), SessionKind::Apply, home.path(), vec![])
            .expect("a session");
        session
            .apply(crate::journal::tests::link_to(
                home.path(),
                ".tool",
                "/opt/two",
            ))
            .expect("retarget");
        session
            .apply(crate::journal::tests::link_to(
                home.path(),
                ".new",
                "/opt/new",
            ))
            .expect("create");
        drop(session);

        let report = plan(&inputs);
        let row = |target: &str| {
            report
                .changes
                .iter()
                .find(|change| change.target == target)
                .expect("a row")
        };
        assert_eq!(row("~/.tool").action, Action::Modify);
        assert_eq!(link(row("~/.tool")), (Some("/opt/two"), Some("/opt/one")));
        assert_eq!(
            row("~/.tool").note.as_deref(),
            Some("rolls back: puts back the link that was there before")
        );
        assert_eq!(link(row("~/.new")), (Some("/opt/new"), None));
        assert_eq!(
            row("~/.new").note.as_deref(),
            Some("rolls back: removes the link the session made")
        );

        apply(&inputs);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/one"));
        assert!(std::fs::symlink_metadata(home.child(".new")).is_err());
        apply(&inputs);
        assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/two"));
        assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged; 2]);
    }

    #[test]
    fn decision_35_a_finished_sessions_rows_are_shown_in_the_plan_view() {
        // P42R2-CL3. `command::apply_with` renders its approval prompt with
        // View::Plan, which hides Unchanged rows — and over a finished session
        // every row IS Unchanged, so the user was asked to confirm a recovery
        // that named none of the files it was about to record.
        let guard = guarded_home();
        let home = guard.child("home");
        seed_crash(&home);
        assert!(
            !spawn_crash_child(&home, CRASH_WRITES, finish_crash_phases()[0])
                .status
                .success()
        );
        let loaded = load(&home);
        let report = plan(&loaded);
        assert_eq!(report.actions(), vec![Action::Unchanged; CRASH_WRITES]);

        let shown = render(&report, View::Plan, Palette::PLAIN, &home);

        for change in &report.changes {
            assert!(
                shown.contains(&change.target),
                "the approval prompt does not name {}: {shown}",
                change.target
            );
        }

        // The rule the exception is carved out of still holds: with no
        // interruption standing, an unchanged configured target stays hidden.
        let settled_home = guarded_home();
        let settled = inputs(&settled_home, &inline("~/.settled", "x\\n"));
        assert!(apply(&settled).executed);
        let converged = plan(&settled);
        assert_eq!(converged.interrupted, None);
        assert_eq!(converged.actions(), vec![Action::Unchanged]);
        assert!(
            !render(&converged, View::Plan, Palette::PLAIN, settled_home.path())
                .contains("~/.settled"),
            "an unchanged target is shown with no interruption standing"
        );
    }

    #[test]
    fn t14_a_standing_interruption_is_reported_as_its_roll_back_and_plan_writes_nothing() {
        // Decision 18 reverses this test's earlier expectation, that every
        // interrupted write is a conflict. A write recovery resolves on its own
        // is announced as the roll back `apply` makes, with its diff, and no
        // configured target is decided against the disk before it.
        let guard = guarded_home();
        let home = guard.child("home");
        seed_crash(&home);
        assert!(
            !spawn_crash_child(&home, 1, "after-publish")
                .status
                .success()
        );
        let before = snapshot(&home, &[]);

        let report = plan(&load(&home));

        let interrupted = report.interrupted.as_ref().expect("an interruption");
        assert_eq!(interrupted.unfinished.len(), CRASH_WRITES);
        assert_eq!(
            report.changes.len(),
            CRASH_WRITES,
            "a configured target was decided: {:?}",
            report.changes
        );
        for unfinished in &interrupted.unfinished {
            let change = report
                .changes
                .iter()
                .find(|change| change.target == unfinished.target.as_str())
                .expect("a row for every unfinished write");
            assert_eq!(change.action, Action::Modify, "{change:?}");
            assert!(
                change
                    .note
                    .as_deref()
                    .is_some_and(|note| note.starts_with("rolls back")),
                "{change:?}"
            );
            assert!(change.diff.is_some(), "{change:?}");
            // Each row keeps the origin of the target it rolls back.
            let line = if change.target == "~/.owned" { 4 } else { 1 };
            assert_eq!(change.origin.line, line, "{change:?}");
        }
        assert_eq!(exit(&report, Mode::Plan), Exit::Pending);
        assert_eq!(snapshot(&home, &[]), before, "plan changed the tree");

        // A target the configuration no longer names is still reported.
        seed(&home, "");
        let report = plan(&load(&home));
        assert_eq!(report.actions(), vec![Action::Modify; CRASH_WRITES]);
        assert_eq!(report.changes[0].origin.line, 0);
    }

    #[test]
    fn decision_14_an_unreadable_restore_snapshot_is_named_by_its_portable_path() {
        let home = guarded_home();
        home.write(".conf", "old\n");
        let inputs = inputs(&home, &inline("~/.conf", "new\\n"));
        // An apply that dies once its write is published: the journal stands
        // over "new\n", and rolling it back needs the snapshot of "old\n".
        let target = Portable::parse_in("~/.conf", home.path()).expect("a portable target");
        let dest = home.child(".conf");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"new\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::DEFAULT_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let digest = crate::state::ContentHash::of(b"old\n");
        let blob = inputs.state().restore().join(digest.to_hex());
        let portable = PathBuf::from(format!("~/.local/state/bx/restore/{}", digest.to_hex()));
        let absolute = home.path().to_string_lossy().into_owned();
        let corrupt = || std::fs::write(&blob, "not what it claims to be").expect("corrupt it");
        let remove = || std::fs::remove_file(&blob).expect("remove it");
        let cases: [(&dyn Fn(), state::Error); 2] = [
            (
                &corrupt,
                state::Error::RestoreCorrupt {
                    digest,
                    path: portable.clone(),
                },
            ),
            (
                &remove,
                state::Error::RestoreMissing {
                    digest,
                    path: portable,
                },
            ),
        ];
        for (damage, want) in cases {
            damage();

            let report = plan(&inputs);

            assert_eq!(report.actions(), vec![Action::Conflict]);
            let note = report.changes[0].note.as_deref().expect("a note");
            // Decision 18 adds that the session has to be abandoned.
            assert!(note.starts_with(&want.to_string()), "{note}");
            assert!(note.contains("abandon"), "{note}");
            let shown = diff::render(
                &report,
                View::Plan,
                Palette::resolve(true, false),
                home.path(),
            );
            assert!(shown.contains(note), "{shown}");
            assert!(!shown.contains(&absolute), "{shown}");

            // Decision 18: apply refuses on what `pending` found, before any
            // recovery runs, so it names the snapshot as plan does and writes
            // nothing.
            let error = run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect_err("blocked");
            assert!(
                matches!(error, Error::Recover(recover::Error::Blocked { .. })),
                "{error:?}"
            );
            assert!(error.to_string().contains(&want.to_string()), "{error}");
            assert_eq!(std::fs::read(&dest).expect("untouched"), b"new\n");
            assert!(inputs.state().journal().exists(), "the journal went");

            // Recovery's own error keeps the absolute path.
            let recovery = match recover::recover(inputs.state()).expect("recover") {
                recover::Outcome::Blocked { conflicts } => recover::Error::Blocked { conflicts },
                outcome => panic!("recovered: {outcome:?}"),
            };
            assert!(
                recovery.to_string().contains(&blob.display().to_string()),
                "{recovery}"
            );
            assert_eq!(std::fs::read(&dest).expect("untouched"), b"new\n");
        }
    }

    #[test]
    fn an_interrupted_mode_only_write_is_rolled_back_to_the_mode_it_had() {
        // The mutation run found the roll back row's mode change unpinned.
        let home = guarded_home();
        own(home.path(), ".m", b"same\n", Mechanism::Own);
        let inputs = inputs(&home, &inline("~/.m", "same\\n"));
        let target = Portable::parse_in("~/.m", home.path()).expect("a portable target");
        let dest = home.child(".m");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"same\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::PRIVATE_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let report = plan(&inputs);

        assert_eq!(report.actions(), vec![Action::Modify]);
        assert_eq!(
            report.changes[0].diff,
            Some(Diff {
                kind: DiffKind::Mode {
                    from: FileMode::PRIVATE_FILE,
                    to: FileMode::DEFAULT_FILE
                }
            })
        );
    }

    #[test]
    fn d1_an_interrupted_secret_write_is_rolled_back_without_showing_either_side() {
        let home = guarded_home();
        let recipient = age_identity(&home);
        seal(&home, &recipient, b"hunter3\n");
        own(home.path(), ".token", b"hunter2\n", Mechanism::Own);
        std::fs::set_permissions(home.child(".token"), std::fs::Permissions::from_mode(0o600))
            .expect("private");
        let inputs = inputs(&home, SECRET_TARGET);
        let target = Portable::parse_in("~/.token", home.path()).expect("a portable target");
        let dest = home.child(".token");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"hunter3\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::PRIVATE_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let report = plan(&inputs);
        assert_eq!(report.actions(), vec![Action::Modify]);
        let shown = render(&report, View::Plan, Palette::PLAIN, home.path());
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(
            shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    /// Leave an interrupted write of `hunter3` over `~/.token`'s `hunter2`,
    /// then plan `layer` and render the plan.
    fn render_an_interrupted_token_write(layer: &str) -> String {
        let home = guarded_home();
        age_identity(&home);
        own(home.path(), ".token", b"hunter2\n", Mechanism::Own);
        let inputs = inputs(&home, layer);
        let target = Portable::parse_in("~/.token", home.path()).expect("a portable target");
        let dest = home.child(".token");
        let mut session = Session::open(
            inputs.state(),
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .expect("a session");
        session
            .apply(Request {
                target,
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"hunter3\n".to_vec(),
                    planned: fs::observe(&dest).expect("observe"),
                },
                mode: FileMode::PRIVATE_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .expect("the write");
        drop(session);

        let report = plan(&inputs);
        render(&report, View::Plan, Palette::PLAIN, home.path())
    }

    const WHO: &str = "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n";

    #[test]
    fn d1_an_interrupted_write_of_a_blocked_secret_is_rolled_back_without_showing_it() {
        // The secret's body waits on an unanswered value, so its resolution is
        // blocked; the declared body still says it is a secret.
        let layer = format!(
            "{WHO}[[target]]\npath = \"~/.token\"\nsecret = \"secrets/{{{{who}}}}.age\"\n\
             mode = \"0600\"\n"
        );
        let shown = render_an_interrupted_token_write(&layer);
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(
            shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    #[test]
    fn d1_a_blocked_secret_path_conceals_a_write_no_target_claims() {
        // The secret's path waits on the value, so the write cannot be matched
        // to it; it is concealed rather than risk printing the secret.
        let layer = format!(
            "{WHO}[[target]]\npath = \"~/.{{{{who}}}}\"\nsecret = \"secrets/token.age\"\n\
             mode = \"0600\"\n"
        );
        let shown = render_an_interrupted_token_write(&layer);
        assert!(!shown.contains("hunter"), "{shown}");
    }

    #[test]
    fn d1_an_interrupted_secret_write_whose_path_was_edited_is_concealed() {
        // The secret now lives at `~/.other`, so no declared target claims the
        // write it left at `~/.token`, and nothing is blocked.
        let shown = render_an_interrupted_token_write(
            "[[target]]\npath = \"~/.other\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n",
        );
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(
            shown.contains("secret, not shown: 8 bytes -> 8 bytes"),
            "{shown}"
        );
    }

    #[test]
    fn d1_an_interrupted_secret_write_whose_path_resolves_elsewhere_is_concealed() {
        // `{{who}}` is answered, by its default, with something else than the
        // write was made under, so the ready target claims another path.
        let shown = render_an_interrupted_token_write(
            "[[value]]\nname = \"who\"\nkind = \"string\"\ndefault = \"other\"\n\
             [[target]]\npath = \"~/.{{who}}\"\nsecret = \"secrets/token.age\"\n\
             mode = \"0600\"\n",
        );
        assert!(!shown.contains("hunter"), "{shown}");
    }

    #[test]
    fn an_interrupted_write_no_target_claims_is_concealed_and_a_claimed_file_is_shown() {
        // The journal does not say whether an unclaimed write was a secret.
        let shown = render_an_interrupted_token_write(WHO);
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(shown.contains("secret, not shown"), "{shown}");

        // An ordinary target that claims the write still shows its diff.
        let shown = render_an_interrupted_token_write(
            "[[target]]\npath = \"~/.token\"\ncontent = \"hunter3\\n\"\n",
        );
        assert!(shown.contains("hunter"), "{shown}");
    }

    #[test]
    fn an_interrupted_write_already_put_back_names_only_what_recovery_still_removes() {
        // The mutation run found unpinned whether such a row is a modify or
        // unchanged: only the directories the session created are left to do.
        let guard = guarded_home();
        let home = guard.child("home");
        seed_crash(&home);
        assert!(
            !spawn_crash_child(&home, 1, "after-publish")
                .status
                .success()
        );
        std::fs::remove_file(home.join(".config/made/new.conf")).expect("put back the create");
        std::fs::write(home.join(".owned"), "before\n").expect("put back the modify");

        let report = plan(&load(&home));

        let row = |target: &str| {
            report
                .changes
                .iter()
                .find(|change| change.target == target)
                .unwrap_or_else(|| panic!("no row for {target}: {report:?}"))
        };
        let made = row("~/.config/made/new.conf");
        assert_eq!(made.action, Action::Modify, "{made:?}");
        assert_eq!(
            made.note.as_deref(),
            Some(
                "rolls back: it already holds what was there before; removes ~/.config/made \
                 where empty"
            )
        );
        let owned = row("~/.owned");
        assert_eq!(owned.action, Action::Unchanged, "{owned:?}");
        assert_eq!(
            owned.note.as_deref(),
            Some("rolls back: it already holds what was there before")
        );
    }
}
