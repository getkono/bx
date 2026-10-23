//! `bx update` does all of `bx sync`'s work, and its check judges against
//! what the upstream holds.

use super::update_command::{AT, layer, locked_elsewhere, publish, pushed_and_moved, upstream};
use super::*;
use crate::sync::tests::{cloned, commit_all, git, rev, run};
use crate::testing::GuardedHome;
use crate::update::Stamps;

/// A tracked target, beside the followed external of [`layer`].
const TRACKED: &str =
    "[[target]]\npath = \"~/.lock\"\nfile = \"files/lock\"\ndirection = \"track\"\n";

fn update(home: &GuardedHome, out: &mut Vec<u8>) -> Result<Exit, update::Error> {
    update_with(
        &env(home.path()),
        &[],
        true,
        out,
        &git(home.path()),
        &mut never,
    )
}

/// A config repo following [`layer`] and tracking `~/.lock`, both copies
/// `a\n`, and a first update that locks, records their agreement and pushes.
fn tracking(home: &GuardedHome) -> std::path::PathBuf {
    upstream(home, &["skills/a/SKILL.md"]);
    let repo = cloned(home, &format!("{}{TRACKED}", layer()));
    std::fs::create_dir_all(repo.join("files")).expect("files");
    std::fs::write(repo.join("files/lock"), "a\n").expect("the repo copy");
    commit_all(home.path(), &repo, "track");
    run(home.path(), &repo, &["push", "--quiet"]);
    home.write(".lock", "a\n");
    let mut out = Vec::new();
    let exit = update(home, &mut out).expect("the first update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    repo
}

fn clean(home: &GuardedHome, repo: &Path) -> bool {
    run(home.path(), repo, &["status", "--porcelain"]).is_empty()
}

#[test]
fn an_update_carries_a_tracked_change_and_pushes_it_with_the_lock() {
    let home = guarded_home();
    let repo = tracking(&home);
    home.write(".lock", "b\n");
    publish(&home, &["skills/b/SKILL.md"]);
    let before = rev(home.path(), &repo, "HEAD");

    let mut out = Vec::new();
    let exit = update(&home, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(text(&out).contains("  < ~/.lock"), "{}", text(&out));
    assert!(
        text(&out).ends_with(
            "Committed 1 tracked file(s) to master.\nPushed 2 commit(s) to origin/master.\n"
        ),
        "{}",
        text(&out)
    );
    assert!(clean(&home, &repo), "nothing is left for bx sync");
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%B", "HEAD~1"])
            .lines()
            .next(),
        Some(update::SUBJECT),
        "the lock is committed first"
    );
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%B"]),
        "chore: carry tracked files back from bx sync\n\nfiles/lock"
    );
    assert_eq!(run(home.path(), &repo, &["rev-parse", "HEAD~2"]), before);
    assert_eq!(run(home.path(), &repo, &["show", "HEAD:files/lock"]), "b");
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        rev(home.path(), &repo, "HEAD"),
        "both commits are the upstream's"
    );

    let mut again = Vec::new();
    update(&home, &mut again).expect("a second update");
    assert!(!text(&again).contains("Committed"), "{}", text(&again));
    assert!(!text(&again).contains("Pushed"), "{}", text(&again));
}

#[test]
fn an_update_with_nothing_new_still_carries_a_tracked_change() {
    let home = guarded_home();
    let repo = tracking(&home);
    home.write(".lock", "b\n");

    let mut out = Vec::new();
    let exit = update(&home, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).ends_with(
            "Committed 1 tracked file(s) to master.\nPushed 1 commit(s) to origin/master.\n"
        ),
        "{}",
        text(&out)
    );
    assert_eq!(run(home.path(), &repo, &["show", "HEAD:files/lock"]), "b");
}

#[test]
fn an_update_with_no_upstream_carries_nothing_as_bx_sync_would_refuse() {
    let home = guarded_home();
    let repo = tracking(&home);
    run(home.path(), &repo, &["branch", "--unset-upstream"]);
    home.write(".lock", "b\n");
    let head = rev(home.path(), &repo, "HEAD");

    let mut out = Vec::new();
    let exit = update(&home, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(text(&out).contains("has no upstream"), "{}", text(&out));
    assert!(!text(&out).contains("Committed"), "{}", text(&out));
    assert!(clean(&home, &repo), "a bare apply writes no repo copy");
    assert_eq!(rev(home.path(), &repo, "HEAD"), head);
}

#[test]
fn a_persons_check_offers_nothing_another_machine_already_locked() {
    let home = guarded_home();
    let (repo, second) = pushed_and_moved(&home);
    locked_elsewhere(&home, &second);
    let head = rev(home.path(), &repo, "HEAD");
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));

    let mut out = Vec::new();
    let exit =
        update::check(&env(home.path()), &[], false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert_eq!(
        text(&out),
        format!(
            "judged against bx.lock as origin/master holds it: another machine updated it, and \
             `bx sync` brings it in\n~/{AT}: another machine already locked master at {}; \
             `bx sync` brings it in\n",
            &second[..12]
        )
    );
    assert!(!stamps.available().exists(), "nothing is offered");
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "the branch stays");
    assert!(clean(&home, &repo), "the working tree stays");
}

#[test]
fn a_persons_check_says_why_it_could_not_judge_the_upstream() {
    let home = guarded_home();
    let (_, _) = pushed_and_moved(&home);
    std::fs::rename(home.child("remote.git"), home.child("moved.git")).expect("the remote");

    let mut out = Vec::new();
    let exit =
        update::check(&env(home.path()), &[], false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).starts_with(
            "judged against this machine's bx.lock: origin/master could not be fetched: "
        ),
        "{}",
        text(&out)
    );
}

#[test]
fn a_persons_check_with_no_upstream_at_all_says_only_what_it_found() {
    let home = guarded_home();
    let (repo, second) = pushed_and_moved(&home);
    run(home.path(), &repo, &["branch", "--unset-upstream"]);

    let mut out = Vec::new();
    let exit =
        update::check(&env(home.path()), &[], false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).starts_with(&format!("~/{AT}: ")),
        "no line about the lock judged: {}",
        text(&out)
    );
    assert!(text(&out).contains(&second[..12]), "{}", text(&out));
}

/// Refuse every push from the config repo at `repo` until the hook it
/// returns is removed.
fn refusing_pushes(repo: &Path) -> std::path::PathBuf {
    let hook = repo.join(".git/hooks/pre-push");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").expect("a hook");
    crate::fs::set_mode(&hook, crate::fs::Mode::from_bits(0o755)).expect("executable");
    hook
}

/// Another machine commits `file` holding `body` and pushes it.
fn pushed_elsewhere(home: &GuardedHome, file: &str, body: &str) {
    let other = crate::sync::tests::other(home);
    let path = other.join(file);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a dir");
    std::fs::write(path, body).expect("the other machine's file");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
}

#[test]
fn a_refused_push_of_a_lock_and_a_carry_is_replayed_by_the_next_update() {
    let home = guarded_home();
    let repo = tracking(&home);
    let hook = refusing_pushes(&repo);
    home.write(".lock", "b\n");
    publish(&home, &["skills/b/SKILL.md"]);
    let mut out = Vec::new();
    update(&home, &mut out).expect("committed, and not pushed");
    assert!(text(&out).contains("was refused"), "{}", text(&out));
    std::fs::remove_file(hook).expect("the hook");
    pushed_elsewhere(&home, "notes", "theirs\n");

    let mut out = Vec::new();
    let exit = update(&home, &mut out).expect("replayed and pushed");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with("Replayed 2 unpushed bx update commit(s)")
            && text(&out).ends_with("Pushed 2 commit(s) to origin/master.\n"),
        "{}",
        text(&out)
    );
    run(home.path(), &repo, &["fetch", "--quiet"]);
    let counts = ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"];
    assert_eq!(run(home.path(), &repo, &counts), "0\t0");
    assert_eq!(run(home.path(), &repo, &["show", "HEAD:files/lock"]), "b");
    assert_eq!(run(home.path(), &repo, &["show", "HEAD:notes"]), "theirs");
}

#[test]
fn a_carry_another_machine_changed_too_is_left_for_a_person() {
    let home = guarded_home();
    let repo = tracking(&home);
    let hook = refusing_pushes(&repo);
    home.write(".lock", "b\n");
    update(&home, &mut Vec::new()).expect("committed, and not pushed");
    std::fs::remove_file(hook).expect("the hook");
    pushed_elsewhere(&home, "files/lock", "c\n");
    let head = rev(home.path(), &repo, "HEAD");

    let error = update(&home, &mut Vec::new()).expect_err("both changed the copy");
    assert!(
        matches!(error, update::Error::LockDiverged { commits: 1, .. }),
        "{error}"
    );
    assert_eq!(
        rev(home.path(), &repo, "HEAD"),
        head,
        "the branch is as it was"
    );
    assert!(!update::rebasing(&git(home.path()), &repo));
    assert!(clean(&home, &repo));
}

#[test]
fn a_declined_update_over_only_a_carry_writes_and_pushes_nothing() {
    let home = guarded_home();
    let repo = tracking(&home);
    home.write(".lock", "b\n");
    let head = rev(home.path(), &repo, "HEAD");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    let mut decline = || Ok(false);
    let exit =
        update_with(&tty, &[], false, &mut out, &git(home.path()), &mut decline).expect("declined");
    assert_eq!(
        exit,
        Exit::Pending,
        "the carry is still to do: {}",
        text(&out)
    );
    assert!(clean(&home, &repo));
    assert_eq!(rev(home.path(), &repo, "HEAD"), head);
    assert!(!text(&out).contains("Pushed"), "{}", text(&out));
}
