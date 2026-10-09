use super::*;
use crate::sync;
use crate::sync::tests::{cloned, commit_all, git, other, rev, run};

/// Commit `layer` as `bx.toml` on a second machine and push it.
fn publish_elsewhere(home: &crate::testing::GuardedHome, layer: &str) -> String {
    let other = other(home);
    std::fs::write(other.join("bx.toml"), layer).expect("bx.toml");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    rev(home.path(), &other, "HEAD")
}

#[test]
fn sync_fast_forwards_applies_and_converges_then_a_second_run_does_nothing() {
    let home = guarded_home();
    let repo = cloned(&home, "");
    let theirs = publish_elsewhere(&home, &inline("~/.a", "a\\n"));
    let env = env(home.path());

    let mut out = Vec::new();
    let exit = sync_with(&env, true, &mut out, &git(home.path()), &mut never).expect("sync");

    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out)
            .starts_with("Fast-forwarded master by 1 commit(s) from origin/master.\n  + ~/.a"),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).ends_with("Applied 1 change(s).\n"),
        "{}",
        text(&out)
    );
    assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");
    assert_eq!(rev(home.path(), &repo, "HEAD"), theirs);

    let mut again = Vec::new();
    let exit =
        sync_with(&env, false, &mut again, &git(home.path()), &mut never).expect("a second sync");
    assert_eq!(exit, Exit::Converged);
    assert!(!text(&again).contains("Fast-forwarded"), "{}", text(&again));
    assert!(!text(&again).contains("Pushed"), "{}", text(&again));
    assert!(!text(&again).contains("Applied"), "{}", text(&again));
    assert_eq!(rev(home.path(), &repo, "HEAD"), theirs);
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        theirs
    );
}

#[test]
fn sync_applies_on_confirmation_and_pushes_what_this_machine_committed() {
    let home = guarded_home();
    let repo = cloned(&home, "");
    std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
    commit_all(home.path(), &repo, "mine");
    let mine = rev(home.path(), &repo, "HEAD");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    let mut asked = 0;
    let exit = sync_with(&tty, false, &mut out, &git(home.path()), &mut || {
        asked += 1;
        Ok(true)
    })
    .expect("sync");

    assert_eq!(exit, Exit::Converged);
    assert_eq!(asked, 1, "sync asks once");
    assert!(
        text(&out).ends_with("Applied 1 change(s).\nPushed 1 commit(s) to origin/master.\n"),
        "{}",
        text(&out)
    );
    assert_eq!(rev(home.path(), &home.child("remote.git"), "master"), mine);
}

#[test]
fn a_sync_walked_away_from_is_a_cancel_that_applies_and_pushes_nothing() {
    let home = guarded_home();
    let repo = cloned(&home, "");
    std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
    commit_all(home.path(), &repo, "mine");
    let before = rev(home.path(), &home.child("remote.git"), "master");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    let exit = sync_with(&tty, false, &mut out, &git(home.path()), &mut || {
        Err(Error::Canceled)
    })
    .expect("a cancel is not an error");

    assert_eq!(exit, Exit::Canceled);
    assert!(
        text(&out).ends_with("Canceled. Nothing was applied or pushed; run `bx sync` again.\n"),
        "{}",
        text(&out)
    );
    assert!(!home.child(".a").exists());
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        before
    );
    assert!(matches!(
        sync_with(&tty, false, &mut Refusing, &git(home.path()), &mut || {
            Err(Error::Canceled)
        }),
        Err(sync::Error::Plan(Error::Output(_)))
    ));
}

#[test]
fn a_declined_sync_writes_nothing_and_pushes_nothing() {
    let home = guarded_home();
    let repo = cloned(&home, "");
    std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
    commit_all(home.path(), &repo, "mine");
    let before = rev(home.path(), &home.child("remote.git"), "master");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    let exit = sync_with(&tty, false, &mut out, &git(home.path()), &mut || Ok(false))
        .expect("a declined sync");

    assert_eq!(exit, Exit::Pending);
    assert!(
        text(&out).ends_with(
            "Nothing was applied.\nPushed nothing: 1 commit(s) wait for an apply that \
                     leaves nothing undone; run `bx sync` again.\n"
        ),
        "{}",
        text(&out)
    );
    assert!(!home.child(".a").exists());
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        before
    );
}

#[test]
fn a_sync_that_leaves_a_conflict_pushes_nothing() {
    let home = guarded_home();
    let repo = cloned(&home, "");
    home.write(".mine", "mine\n");
    std::fs::write(repo.join("bx.toml"), inline("~/.mine", "bx\\n")).expect("bx.toml");
    commit_all(home.path(), &repo, "mine");
    let before = rev(home.path(), &home.child("remote.git"), "master");

    let mut out = Vec::new();
    let exit = sync_with(
        &env(home.path()),
        true,
        &mut out,
        &git(home.path()),
        &mut never,
    )
    .expect("a sync with a conflict");

    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(text(&out).starts_with("  ! ~/.mine"), "{}", text(&out));
    assert!(
        text(&out).ends_with(
            "Pushed nothing: 1 commit(s) wait for an apply that leaves nothing undone; \
                     run `bx sync` again.\n"
        ),
        "{}",
        text(&out)
    );
    assert!(!text(&out).contains("Pushed 1"), "{}", text(&out));
    assert_eq!(std::fs::read(home.child(".mine")).expect("kept"), b"mine\n");
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        before
    );
}

#[test]
fn sync_without_yes_or_a_terminal_writes_and_pushes_nothing_pending() {
    let home = guarded_home();
    let repo = cloned(&home, "");
    std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
    commit_all(home.path(), &repo, "mine");
    let before = rev(home.path(), &home.child("remote.git"), "master");

    let error = sync_with(
        &env(home.path()),
        false,
        &mut Vec::new(),
        &git(home.path()),
        &mut never,
    )
    .expect_err("no confirmation");

    assert!(
        matches!(error, sync::Error::Plan(Error::NeedsConfirmation)),
        "{error:?}"
    );
    assert!(!home.child(".a").exists());
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        before
    );
}

#[test]
fn an_interrupted_sync_is_recovered_by_the_next_and_pushes_only_after_it() {
    use crate::journal::{Session, SessionKind};

    let home = guarded_home();
    let repo = cloned(&home, "");
    std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
    commit_all(home.path(), &repo, "mine");
    let mine = rev(home.path(), &repo, "HEAD");
    let before = rev(home.path(), &home.child("remote.git"), "master");
    let state = crate::state::StateDir::resolve(home.path());
    drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
    let env = env(home.path());

    let mut out = Vec::new();
    let exit = sync_with(&env, true, &mut out, &git(home.path()), &mut never)
        .expect("the recovering sync");
    assert_eq!(exit, Exit::Pending);
    assert!(
        text(&out).contains("nothing else was applied"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("Pushed nothing"), "{}", text(&out));
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        before
    );
    assert!(!home.child(".a").exists());

    let mut out = Vec::new();
    let exit =
        sync_with(&env, true, &mut out, &git(home.path()), &mut never).expect("the next sync");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(home.child(".a").exists());
    assert_eq!(rev(home.path(), &home.child("remote.git"), "master"), mine);
}

#[test]
fn a_refused_pull_applies_nothing() {
    let home = guarded_home();
    let repo = cloned(&home, &inline("~/.a", "a\\n"));
    std::fs::write(repo.join("local.toml"), "[values]\n").expect("local.toml");
    commit_all(home.path(), &repo, "oops");

    let mut out = Vec::new();
    let error = sync_with(
        &env(home.path()),
        true,
        &mut out,
        &git(home.path()),
        &mut never,
    )
    .expect_err("state in an outgoing commit");

    assert!(
        matches!(error, sync::Error::WouldPushState { .. }),
        "{error:?}"
    );
    assert!(out.is_empty(), "{}", text(&out));
    assert!(!home.child(".a").exists());
}

#[test]
fn a_sync_that_cannot_write_its_output_is_an_output_error() {
    let home = guarded_home();
    cloned(&home, "");
    publish_elsewhere(&home, "# changed elsewhere\n");
    assert!(matches!(
        sync_with(
            &env(home.path()),
            true,
            &mut Refusing,
            &git(home.path()),
            &mut never
        ),
        Err(sync::Error::Output(_))
    ));
}

/// `~/.lock`, tracked, with its repo copy at `files/lock`.
const TRACKED: &str =
    "[[target]]\npath = \"~/.lock\"\nfile = \"files/lock\"\ndirection = \"track\"\n";

/// A config repo tracking `~/.lock`, both copies `a\n` and pushed, and
/// a first sync that records their agreement.
fn tracking(home: &crate::testing::GuardedHome) -> std::path::PathBuf {
    let repo = cloned(home, TRACKED);
    std::fs::create_dir_all(repo.join("files")).expect("files");
    std::fs::write(repo.join("files/lock"), "a\n").expect("the repo copy");
    commit_all(home.path(), &repo, "track");
    run(home.path(), &repo, &["push", "--quiet"]);
    home.write(".lock", "a\n");
    let exit = sync_with(
        &env(home.path()),
        true,
        &mut Vec::new(),
        &git(home.path()),
        &mut never,
    )
    .expect("the agreeing sync");
    assert_eq!(exit, Exit::Converged);
    repo
}

fn clean(home: &crate::testing::GuardedHome, repo: &Path) -> bool {
    run(home.path(), repo, &["status", "--porcelain"]).is_empty()
}

#[test]
fn a_tracked_change_is_left_by_apply_and_committed_once_and_pushed_by_sync() {
    let home = guarded_home();
    let repo = tracking(&home);
    home.write(".lock", "b\n");

    let mut out = Vec::new();
    let exit = apply_with(&env(home.path()), true, &mut out, &mut never).expect("apply");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(text(&out).contains("  < ~/.lock"), "{}", text(&out));
    assert!(clean(&home, &repo), "a bare apply left the repo modified");

    let before = rev(home.path(), &repo, "HEAD");
    let mut out = Vec::new();
    let exit = sync_with(
        &env(home.path()),
        true,
        &mut out,
        &git(home.path()),
        &mut never,
    )
    .expect("sync");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).ends_with(
            "Applied 1 change(s).\nCommitted 1 tracked file(s) to master.\n\
                     Pushed 1 commit(s) to origin/master.\n"
        ),
        "{}",
        text(&out)
    );
    assert!(clean(&home, &repo));
    assert_eq!(
        run(home.path(), &repo, &["rev-parse", "HEAD~1"]),
        before,
        "one commit"
    );
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%B"]),
        "chore: carry tracked files back from bx sync\n\nfiles/lock"
    );
    assert_eq!(run(home.path(), &repo, &["show", "HEAD:files/lock"]), "b");
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        rev(home.path(), &repo, "HEAD")
    );

    let mut again = Vec::new();
    sync_with(
        &env(home.path()),
        true,
        &mut again,
        &git(home.path()),
        &mut never,
    )
    .expect("a second sync");
    assert!(!text(&again).contains("Committed"), "{}", text(&again));
}

#[test]
fn a_declined_sync_over_only_a_carry_writes_nothing_and_pushes_nothing() {
    let home = guarded_home();
    let repo = tracking(&home);
    std::fs::write(repo.join("notes"), "mine\n").expect("a local commit");
    commit_all(home.path(), &repo, "mine");
    let before = rev(home.path(), &home.child("remote.git"), "master");
    home.write(".lock", "b\n");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    let mut asked = 0;
    let exit = sync_with(&tty, false, &mut out, &git(home.path()), &mut || {
        asked += 1;
        Ok(false)
    })
    .expect("a declined sync");

    assert_eq!(asked, 1, "the carry is asked about");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(text(&out).contains("  < ~/.lock"), "{}", text(&out));
    assert!(
        text(&out).ends_with(
            "Nothing was applied.\nPushed nothing: 1 commit(s) wait for an apply that \
                     leaves nothing undone; run `bx sync` again.\n"
        ),
        "{}",
        text(&out)
    );
    assert_eq!(
        std::fs::read(repo.join("files/lock")).expect("the repo copy"),
        b"a\n"
    );
    assert!(clean(&home, &repo));
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        before
    );
}

#[test]
fn two_machines_that_both_changed_a_tracked_target_are_a_conflict_and_push_nothing() {
    let home = guarded_home();
    tracking(&home);
    let other = other(&home);
    std::fs::write(other.join("files/lock"), "theirs\n").expect("their copy");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let theirs = rev(home.path(), &other, "HEAD");
    home.write(".lock", "mine\n");

    let mut out = Vec::new();
    let exit = sync_with(
        &env(home.path()),
        true,
        &mut out,
        &git(home.path()),
        &mut never,
    )
    .expect("a sync with a conflict");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("  ! ~/.lock"), "{shown}");
    assert!(shown.contains("+++ ~/.lock (this machine)"), "{shown}");
    assert!(shown.contains("+mine"), "{shown}");
    assert!(shown.contains("+++ ~/.lock (repo)"), "{shown}");
    assert!(shown.contains("+theirs"), "{shown}");
    assert!(!shown.contains("Committed"), "{shown}");
    assert_eq!(std::fs::read(home.child(".lock")).expect("kept"), b"mine\n");
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        theirs
    );
}

#[test]
fn copies_an_interrupted_sync_wrote_and_never_committed_are_committed_first() {
    let home = guarded_home();
    let repo = tracking(&home);
    home.write(".lock", "b\n");
    // A sync that wrote the copy and stopped before its commit.
    let inputs = crate::plan::Inputs::load(&env(home.path())).expect("inputs");
    assert!(
        plan::run(&inputs, Mode::Sync, &mut |_| Ok(true))
            .expect("the carrying run")
            .executed
    );
    assert!(!clean(&home, &repo));
    // Something the user left in the working tree is not bx's to commit.
    std::fs::write(repo.join("notes"), "mine\n").expect("notes");

    let mut out = Vec::new();
    let exit = sync_with(
        &env(home.path()),
        true,
        &mut out,
        &git(home.path()),
        &mut never,
    )
    .expect("the recovering sync");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with(
            "Committed 1 tracked file(s) an interrupted bx sync carried into the repo.\n"
        ),
        "{}",
        text(&out)
    );
    assert!(text(&out).ends_with("Pushed 1 commit(s) to origin/master.\n"));
    assert_eq!(
        run(home.path(), &repo, &["status", "--porcelain"]),
        "?? notes"
    );
    assert_eq!(
        run(
            home.path(),
            &home.child("remote.git"),
            &["show", "master:files/lock"]
        ),
        "b"
    );
}
