//! A file bx owns whole that was edited since bx wrote it: the row says
//! `apply` asks, an answer of *keep* changes nothing, an answer of *take*
//! writes the write the row was decided with and keeps the edit for `bx rm`,
//! and a file already holding what bx wants is recorded again, not reported
//! as edited.

use std::collections::BTreeSet;

use super::*;
use crate::hash::ContentHash;

/// `~/.a` written by bx as `bx\n`, then edited by hand to `edited\n` at
/// `0600`, with the configuration now wanting `body`.
fn edited(home: &GuardedHome, body: &str) -> Inputs {
    let written = inputs(home, &inline("~/.a", "bx\\n"));
    assert!(apply(&written).executed, "bx writes the file");
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
        .expect("the user's mode");
    inputs(home, &inline("~/.a", body))
}

/// An `apply` approved, answering *take* for each of `taken`.
fn answer(inputs: &Inputs, approved: bool, taken: &[usize]) -> Report {
    answered(inputs, Mode::Apply, &mut |_| {
        Ok(Approval {
            approved,
            taken: taken.iter().copied().collect(),
        })
    })
    .expect("apply runs")
}

/// The ledger's entry for `~/.a`.
fn entry(home: &GuardedHome) -> Option<crate::state::LedgerEntry> {
    let state = StateDir::resolve(home.path());
    let target = Portable::parse_in("~/.a", home.path()).expect("portable");
    LedgerView::read(&state, home.path())
        .expect("the ledger")
        .value
        .get(&target)
        .cloned()
}

#[test]
fn an_edited_file_is_a_question_whose_answer_keep_changes_nothing() {
    let home = guarded_home();
    let inputs = edited(&home, "new\\n");
    let before = snapshot(home.path(), &[]);
    let ledger = entry(&home);

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    assert_eq!(
        planned.questions.iter().map(|q| q.row).collect::<Vec<_>>(),
        vec![0]
    );
    let shown = render(&planned, View::Plan, Palette::PLAIN, home.path());
    assert!(shown.contains(decide::ASK), "{shown}");

    let kept = answer(&inputs, true, &[]);
    assert!(
        !kept.executed,
        "only the question was work, so nothing runs"
    );
    assert_eq!(kept.actions(), vec![Action::Conflict]);
    assert_eq!(snapshot(home.path(), &[]), before, "nothing on disk moved");
    assert_eq!(entry(&home), ledger, "nor in the ledger");
}

#[test]
fn run_without_answers_never_asks_about_an_edited_file_alone() {
    let home = guarded_home();
    let inputs = edited(&home, "new\\n");
    let report =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("apply runs");
    assert!(!report.executed);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"edited\n");
}

#[test]
fn a_take_declined_at_the_confirmation_writes_nothing() {
    let home = guarded_home();
    let inputs = edited(&home, "new\\n");
    let before = snapshot(home.path(), &[]);

    let declined = answer(&inputs, false, &[0]);

    assert!(!declined.executed);
    assert_eq!(snapshot(home.path(), &[]), before);
}

#[test]
fn take_writes_bx_bytes_and_rm_restores_the_edit_and_its_mode_exactly() {
    let home = guarded_home();
    let inputs = edited(&home, "new\\n");

    let planned = plan(&inputs);
    assert_eq!(planned.questions[0].asked, Asked::Edited);
    let taken = answer(&inputs, true, &[0]);

    assert!(taken.executed);
    assert_eq!(taken.actions(), vec![Action::Modify]);
    // What the row said stays — the mode bx puts back with it above all —
    // and what the answer did takes the question's place.
    assert_eq!(
        planned.changes[0].note.as_deref(),
        Some(
            format!(
                "edited since bx last wrote it; mode 0600 -> 0644; {}",
                decide::ASK
            )
            .as_str()
        )
    );
    assert_eq!(
        taken.changes[0].note.as_deref(),
        Some(
            format!(
                "edited since bx last wrote it; mode 0600 -> 0644; {}",
                super::super::TAKEN
            )
            .as_str()
        )
    );
    assert_eq!(exit(&taken, Mode::Apply), Exit::Converged);
    assert_eq!(std::fs::read(home.child(".a")).expect("bx's"), b"new\n");
    assert_eq!(mode_of(&home.child(".a")), 0o644);
    // Applying twice converges: the second plan is empty.
    let again = plan(&inputs);
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert!(again.questions.is_empty());

    let state = StateDir::resolve(home.path());
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("rm");
    assert_eq!(
        std::fs::read(home.child(".a")).expect("the edit is back"),
        b"edited\n"
    );
    assert_eq!(mode_of(&home.child(".a")), 0o600, "and its mode");
}

#[test]
fn the_three_way_view_is_measured_from_the_bytes_bx_last_wrote() {
    let home = guarded_home();
    let inputs = edited(&home, "new\\n");

    let planned = plan(&inputs);
    let view = planned.questions[0].three_way.clone().expect("a view");
    let DiffKind::Texts(texts) = view.kind else {
        panic!("two diffs: {view:?}");
    };
    assert_eq!(
        texts,
        vec![
            "--- ~/.a (bx wrote)\n+++ ~/.a (on disk)\n@@ -1 +1 @@\n-bx\n+edited\n".to_string(),
            "--- ~/.a (bx wrote)\n+++ ~/.a (bx wants)\n@@ -1 +1 @@\n-bx\n+new\n".to_string(),
        ]
    );
    let row = render_row(
        &planned.changes[0],
        planned.questions[0].three_way.as_ref(),
        Palette::PLAIN,
        home.path(),
    );
    assert!(row.contains("(bx wrote → on disk)"), "{row}");
    assert!(row.contains("(bx wrote → bx wants)"), "{row}");
}

#[test]
fn an_edit_of_a_body_that_stayed_as_it_was_shows_only_the_edit() {
    let home = guarded_home();
    let inputs = edited(&home, "bx\\n");

    let planned = plan(&inputs);

    let view = planned.questions[0].three_way.clone().expect("a view");
    assert_eq!(
        view.kind,
        DiffKind::Texts(vec![
            "--- ~/.a (bx wrote)\n+++ ~/.a (on disk)\n@@ -1 +1 @@\n-bx\n+edited\n".to_string()
        ])
    );
}

#[test]
fn without_the_bytes_bx_wrote_the_row_diff_is_all_there_is() {
    let home = guarded_home();
    // Written by a session alone, as before bx kept what it wrote.
    own(home.path(), ".a", b"bx\n", Mechanism::Own);
    std::fs::write(home.child(".a"), "edited\n").expect("the edit");
    let inputs = inputs(&home, &inline("~/.a", "new\\n"));

    let planned = plan(&inputs);

    assert_eq!(planned.questions.len(), 1);
    assert_eq!(planned.questions[0].three_way, None);
    let row = render_row(&planned.changes[0], None, Palette::PLAIN, home.path());
    assert!(row.contains("(on disk → bx)"), "{row}");
}

#[test]
fn a_secret_keeps_no_base_and_shows_no_view() {
    let home = guarded_home();
    let recipient = age_identity(&home);
    seal(&home, &recipient, b"hunter2\n");
    let inputs = inputs(&home, SECRET_TARGET);
    assert!(apply(&inputs).executed);
    let state = StateDir::resolve(home.path());
    assert_eq!(
        crate::state::restore::kept(&state, ContentHash::of(b"hunter2\n"), u64::MAX),
        None,
        "no plaintext is kept"
    );
    std::fs::write(home.child(".token"), "mine\n").expect("the edit");

    let planned = plan(&inputs);

    assert_eq!(planned.questions.len(), 1);
    assert_eq!(planned.questions[0].three_way, None);
}

#[test]
fn a_file_bx_wrote_whole_keeps_its_bytes_as_the_base() {
    let home = guarded_home();
    assert!(apply(&inputs(&home, &inline("~/.a", "bx\\n"))).executed);
    let state = StateDir::resolve(home.path());
    let written = entry(&home).expect("bx's").written;
    assert_eq!(written, ContentHash::of(b"bx\n"));
    assert_eq!(
        crate::state::restore::kept(&state, written, crate::plan::track::Base::LIMIT),
        Some(b"bx\n".to_vec())
    );
    assert_eq!(
        crate::state::restore::kept(&state, written, 2),
        None,
        "past the limit nothing is read"
    );
}

#[test]
fn a_file_already_holding_what_bx_wants_is_recorded_again_not_edited() {
    let home = guarded_home();
    own(home.path(), ".a", b"old\n", Mechanism::Own);
    // Brought to the new body by hand, before the configuration said so.
    std::fs::write(home.child(".a"), "new\n").expect("the edit");
    let inputs = inputs(&home, &inline("~/.a", "new\\n"));

    let planned = plan(&inputs);
    assert_eq!(planned.actions(), vec![Action::Modify]);
    assert_eq!(planned.changes[0].note.as_deref(), Some(decide::REFRESH));
    assert_eq!(planned.changes[0].diff, None);

    assert!(apply(&inputs).executed);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"new\n");
    assert_eq!(
        entry(&home).expect("bx's").written,
        ContentHash::of(b"new\n")
    );
    assert_eq!(plan(&inputs).actions(), vec![Action::Unchanged]);
    // The next change to the body is bx's to make, not an edit.
    let next = inputs_after(&home, "newer\\n");
    assert_eq!(plan(&next).actions(), vec![Action::Modify]);
}

/// The inputs once the configuration wants `body` at `~/.a`.
fn inputs_after(home: &GuardedHome, body: &str) -> Inputs {
    inputs(home, &inline("~/.a", body))
}

/// The home the take crash child applies in.
const TAKE_CRASH_HOME: &str = "BX_PLAN_TAKE_CRASH_HOME";

#[test]
#[ignore = "spawned by the take crash harness; it aborts on purpose"]
fn take_crash_child() {
    let Some(home) = std::env::var_os(TAKE_CRASH_HOME) else {
        return;
    };
    let inputs = load(Path::new(&home));
    answered(&inputs, Mode::Apply, &mut |_| {
        Ok(Approval {
            approved: true,
            taken: BTreeSet::from([0]),
        })
    })
    .expect("the apply");
}

#[test]
fn a_take_killed_at_any_journal_phase_recovers_like_any_session() {
    let guard = guarded_home();
    for phase in crash_phases() {
        let home = guard.child(format!("crash-{phase}"));
        std::fs::create_dir_all(&home).expect("the home");
        own(&home, ".a", b"bx\n", Mechanism::Own);
        std::fs::write(home.join(".a"), "edited\n").expect("the edit");
        seed(&home, &inline("~/.a", "new\\n"));

        let output = crate::testing::ignored_child("plan::tests::edited::take_crash_child")
            .env("BX_CRASH_AT", format!("0:{phase}"))
            .env(TAKE_CRASH_HOME, &home)
            .env_remove("LLVM_PROFILE_FILE")
            .output()
            .expect("spawn the crash child");
        assert!(!output.status.success(), "{phase}: the child did not stop");

        let inputs = load(&home);
        assert!(plan(&inputs).interrupted.is_some(), "{phase}");
        let recovering = apply(&inputs);
        assert!(recovering.recovered.is_some(), "{phase}");
        // Rolled back, the edit is asked about again; rolled forward, bx's
        // bytes stand and `bx rm` gives the edit back. Never lost either way.
        let again = plan(&inputs);
        if std::fs::read(home.join(".a")).expect("the file") == b"edited\n" {
            assert_eq!(again.actions(), vec![Action::Conflict], "{phase}");
            assert_eq!(again.questions.len(), 1, "{phase}");
        } else {
            assert_eq!(again.actions(), vec![Action::Unchanged], "{phase}");
            let state = StateDir::resolve(&home);
            let targets = ledger_targets(&state, &home);
            crate::restore::restore(&state, &home, &targets).expect("rm");
            assert_eq!(
                std::fs::read(home.join(".a")).expect("the edit is back"),
                b"edited\n",
                "{phase}"
            );
        }
    }
}
