use super::*;
use crate::config::lock::Lock;
use crate::sync::tests::{cloned, commit_all, git, rev, run};
use crate::testing::GuardedHome;
use crate::update::Stamps;

/// Where the followed external is checked out, relative to the home.
const AT: &str = ".local/share/skills";

/// The url every test declares; `~/.gitconfig` rewrites it to the
/// repository at `~/upstream`.
const URL: &str = "https://example.invalid/upstream";

/// The followed external, linking each skill into `~/.claude/skills`.
fn layer() -> String {
    format!(
        "[[external]]\npath = \"~/{AT}\"\nurl = \"{URL}\"\nbranch = \"master\"\n\
                 [[external.link]]\nfrom = \"skills/*\"\nto = \"~/.claude/skills/*\"\n\
                 require = \"SKILL.md\"\n"
    )
}

/// An upstream at `~/upstream` reachable as [`URL`], holding `files`.
fn upstream(home: &GuardedHome, files: &[&str]) -> String {
    let dir = home.child("upstream");
    std::fs::create_dir_all(&dir).expect("the upstream");
    std::fs::write(
        home.child(".gitconfig"),
        format!(
            "[url \"file://{}/\"]\n\tinsteadOf = https://example.invalid/\n",
            home.path().display()
        ),
    )
    .expect("~/.gitconfig");
    run(home.path(), &dir, &["init", "--quiet", "-b", "master"]);
    publish(home, files)
}

/// Commit `files` on the upstream's `master`, and return the commit.
fn publish(home: &GuardedHome, files: &[&str]) -> String {
    let dir = home.child("upstream");
    for file in files {
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a dir");
        std::fs::write(path, format!("{file}\n")).expect("a file");
    }
    commit_all(home.path(), &dir, "skills");
    rev(home.path(), &dir, "HEAD")
}

fn update(home: &GuardedHome, yes: bool, out: &mut Vec<u8>) -> Result<Exit, update::Error> {
    update_with(
        &env(home.path()),
        &[],
        yes,
        out,
        &git(home.path()),
        &mut never,
    )
}

fn locked(home: &GuardedHome) -> Option<String> {
    let lock = Lock::read(&home.child(".config/bx"), home.path()).expect("bx.lock");
    lock.iter().next().map(|(_, locked)| locked.rev.clone())
}

#[test]
fn update_locks_commits_and_applies_then_finds_nothing_new() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md", "skills/notes/x"]);
    let repo = cloned(&home, &layer());

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with(&format!("~/{AT}: locks master at {}\n", &first[..12])),
        "{}",
        text(&out)
    );
    assert_eq!(locked(&home).as_deref(), Some(first.as_str()));
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%s"]),
        "chore(bx): update bx.lock"
    );
    assert_eq!(run(home.path(), &repo, &["status", "--porcelain"]), "");
    assert_eq!(rev(home.path(), &home.child(AT), "HEAD"), first);
    assert!(home.child(".claude/skills/a/SKILL.md").is_file());
    assert!(!home.child(".claude/skills/notes").exists());
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    assert!(
        Stamps::read(&stamps.ask_due()).is_some(),
        "the interval starts"
    );

    let head = rev(home.path(), &repo, "HEAD");
    let mut again = Vec::new();
    // At a terminal, and never asked: there is nothing to approve.
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let exit = update_with(&tty, &[], false, &mut again, &git(home.path()), &mut never)
        .expect("a second update");
    assert_eq!(exit, Exit::Converged, "{}", text(&again));
    assert!(
        text(&again).starts_with(&format!("~/{AT}: up to date with master\n")),
        "{}",
        text(&again)
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing to commit");

    let second = publish(&home, &["skills/b/SKILL.md"]);
    let mut moved = Vec::new();
    let exit = update(&home, true, &mut moved).expect("a third update");
    assert_eq!(exit, Exit::Converged, "{}", text(&moved));
    assert!(
        text(&moved).contains(&format!(
            "~/{AT}: 1 new commit(s) on master, {} -> {}\n    {} skills\n",
            &first[..12],
            &second[..12],
            &second[..7]
        )),
        "{}",
        text(&moved)
    );
    assert!(
        text(&moved).contains("+ ~/.claude/skills/*"),
        "the link, waiting for its checkout to move: {}",
        text(&moved)
    );
    assert_eq!(locked(&home).as_deref(), Some(second.as_str()));
    assert_eq!(rev(home.path(), &home.child(AT), "HEAD"), second);
    assert!(home.child(".claude/skills/b/SKILL.md").is_file());
    let message = run(home.path(), &repo, &["log", "-1", "--format=%B"]);
    assert!(
        message.contains(&format!(
            "~/{AT}: master {} -> {}",
            &first[..12],
            &second[..12]
        )),
        "{message}"
    );
}

#[test]
fn update_commits_the_lock_before_it_moves_anything() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    let second = publish(&home, &["skills/b/SKILL.md"]);
    let hook = repo.join(".git/hooks/pre-commit");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").expect("a hook");
    crate::fs::set_mode(&hook, crate::fs::Mode::from_bits(0o755)).expect("executable");

    let error = update(&home, true, &mut Vec::new()).expect_err("the hook refuses");
    assert!(matches!(error, update::Error::Sync(_)), "{error:?}");
    assert_eq!(
        rev(home.path(), &home.child(AT), "HEAD"),
        first,
        "the checkout stays at the commit the repo names"
    );
    assert!(!home.child(".claude/skills/b").exists());
    assert_eq!(
        locked(&home).as_deref(),
        Some(first.as_str()),
        "put back as it was, so a later apply moves nothing"
    );
    assert_eq!(run(home.path(), &repo, &["status", "--porcelain"]), "");
    std::fs::remove_file(&hook).expect("the hook");
    let mut out = Vec::new();
    update(&home, true, &mut out).expect("update");
    assert_eq!(
        locked(&home).as_deref(),
        Some(second.as_str()),
        "{}",
        text(&out)
    );
}

#[test]
fn a_force_push_past_a_commit_the_checkout_lacks_is_never_locked() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    // Another machine locked a commit this checkout never fetched,
    // and the branch was then rewritten past it.
    let dir = home.child("upstream");
    let elsewhere = publish(&home, &["skills/b/SKILL.md"]);
    let mut lock = Lock::read(&repo, home.path()).expect("bx.lock");
    let path = lock
        .iter()
        .next()
        .map(|(path, _)| path.clone())
        .expect("an entry");
    let mut entry = lock.get(&path).cloned().expect("an entry");
    entry.rev = elsewhere.clone();
    lock.set(path, entry);
    std::fs::write(repo.join("bx.lock"), lock.render()).expect("bx.lock");
    commit_all(home.path(), &repo, "locked elsewhere");
    run(home.path(), &dir, &["reset", "--quiet", "--hard", &first]);
    run(
        home.path(),
        &dir,
        &["reflog", "expire", "--expire=now", "--all"],
    );
    run(home.path(), &dir, &["gc", "--quiet", "--prune=now"]);
    let rewritten = publish(&home, &["skills/z/SKILL.md"]);

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains(&format!("its tip {} does not descend", &rewritten[..12])),
        "{}",
        text(&out)
    );
    assert_eq!(locked(&home).as_deref(), Some(elsewhere.as_str()));
}

#[test]
fn two_links_naming_one_child_converge_in_one_apply() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md", "skills/b/SKILL.md"]);
    let twice = format!(
        "{}[[external.link]]\nfrom = \"skills/*\"\nto = \"~/.claude/skills/*\"\n",
        layer()
    );
    cloned(&home, &twice);
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("one apply");
    assert_eq!(exit, Exit::Pending, "the second link's children conflict");
    assert!(
        text(&out).contains("! ~/.claude/skills/a  stopped: a child of `skills/*`"),
        "{}",
        text(&out)
    );
    assert!(home.child(".claude/skills/a/SKILL.md").is_file());
    let mut plan_out = Vec::new();
    plan(&env(home.path()), &mut plan_out).expect("plan");
    let shown = text(&plan_out);
    assert!(
        !shown.contains("  + ") && !shown.contains("  ~ "),
        "{shown}"
    );
}

#[test]
fn update_without_yes_or_a_terminal_reaches_nothing() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    let error = update(&home, false, &mut Vec::new()).expect_err("no terminal");
    assert!(
        matches!(error, update::Error::Plan(Error::NeedsConfirmation)),
        "{error:?}"
    );
    assert_eq!(locked(&home), None);
    assert!(!home.child(AT).exists());
}

#[test]
fn update_refuses_a_lock_with_uncommitted_edits() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    std::fs::write(repo.join("bx.lock"), "# mine\n").expect("an edit");
    let error = update(&home, true, &mut Vec::new()).expect_err("edited");
    assert!(matches!(error, update::Error::LockEdited(_)), "{error:?}");
    assert_eq!(
        std::fs::read_to_string(repo.join("bx.lock")).expect("kept"),
        "# mine\n"
    );
}

#[test]
fn an_interrupted_apply_is_recovered_and_nothing_is_locked_under_its_approval() {
    use crate::journal::{Session, SessionKind};

    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    let head = rev(home.path(), &repo, "HEAD");
    let state = crate::state::StateDir::resolve(home.path());
    drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
    let stamps = Stamps::of(&state);
    stamps
        .set(0, None, None, Some(&["offered".to_string()]))
        .expect("an offer");

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("the recovering update");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains("Nothing was locked: an interrupted apply"),
        "{}",
        text(&out)
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing committed");
    assert_eq!(locked(&home), None);
    assert!(!home.child(AT).exists(), "nothing applied");
    assert!(stamps.available().exists(), "the offer stands");

    let exit = update(&home, true, &mut Vec::new()).expect("the next update");
    assert_eq!(exit, Exit::Converged);
    assert!(locked(&home).is_some());
}

#[test]
fn update_refuses_a_lock_git_has_never_seen() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    // As a run killed between writing its first lock and committing
    // it leaves the file, or as one written by hand is.
    std::fs::write(repo.join("bx.lock"), "# mine\n").expect("untracked");
    let head = rev(home.path(), &repo, "HEAD");
    let error = update(&home, true, &mut Vec::new()).expect_err("untracked");
    assert!(matches!(error, update::Error::LockEdited(_)), "{error:?}");
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing committed");
    assert_eq!(
        std::fs::read_to_string(repo.join("bx.lock")).expect("kept"),
        "# mine\n"
    );
}

#[test]
fn a_rewritten_branch_is_reported_and_never_locked() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    let dir = home.child("upstream");
    run(
        home.path(),
        &dir,
        &["checkout", "--quiet", "--orphan", "fresh"],
    );
    let rewritten = publish(&home, &["skills/z/SKILL.md"]);
    run(home.path(), &dir, &["branch", "--quiet", "-M", "master"]);

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains(&format!(
            "master was rewritten; its tip {}",
            &rewritten[..12]
        )),
        "{}",
        text(&out)
    );
    assert_eq!(locked(&home).as_deref(), Some(first.as_str()));
}

#[test]
fn check_offers_what_it_found_and_snooze_puts_it_off() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    publish(&home, &["skills/b/SKILL.md"]);
    let env = env(home.path());
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));

    let mut out = Vec::new();
    let exit = update::check(&env, &[], false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Pending);
    let offered = std::fs::read_to_string(stamps.available()).expect("offered");
    assert!(
        offered.starts_with(&format!("~/{AT}: 1 new commit(s)")),
        "{offered}"
    );
    assert_eq!(text(&out), offered, "what it says is what it offers");
    assert!(!home.child(".claude/skills/b").exists(), "nothing applied");

    let mut quiet = Vec::new();
    let exit = update::check(&env, &[], true, &git(home.path()), &mut quiet).expect("background");
    assert_eq!(exit, Exit::Converged, "no external checks on its own");
    assert!(quiet.is_empty());
    assert_eq!(
        std::fs::read_to_string(stamps.available()).expect("kept"),
        offered,
        "a background check keeps lines it did not look at"
    );

    update::snooze(&env, &mut Vec::new()).expect("snooze");
    assert!(!stamps.available().exists());
    let due = Stamps::read(&stamps.ask_due()).expect("ask-due");
    assert!(due >= update::now() + 7 * 24 * 60 * 60 - 60, "{due}");
}

#[test]
fn a_background_check_looks_at_auto_externals_only_and_never_twice_at_once() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(
        &home,
        &layer().replace(
            "branch = \"master\"\n",
            "branch = \"master\"\ncheck = \"auto\"\ninterval = \"1d\"\n",
        ),
    );
    update(&home, true, &mut Vec::new()).expect("update");
    publish(&home, &["skills/b/SKILL.md"]);
    let env = env(home.path());
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));

    let held = stamps.try_hold().expect("hold").expect("free");
    let exit = update::check(&env, &[], true, &git(home.path()), &mut Vec::new()).expect("busy");
    assert_eq!(exit, Exit::Converged);
    assert!(!stamps.available().exists(), "another check holds it");
    drop(held);

    let exit =
        update::check(&env, &[], true, &git(home.path()), &mut Vec::new()).expect("background");
    assert_eq!(exit, Exit::Pending);
    assert!(stamps.available().exists());
    let last = std::fs::read_to_string(stamps.last_check()).expect("last-check");
    assert!(last.contains("1 new commit(s)"), "{last}");
    let due = Stamps::read(&stamps.check_due()).expect("check-due");
    assert!(
        due <= update::now() + 24 * 60 * 60,
        "its own interval: {due}"
    );
}

#[test]
fn an_apply_on_a_machine_that_never_ran_update_starts_the_interval() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    std::fs::remove_dir_all(home.child(".local/state/bx/update")).expect("a new machine");
    std::fs::remove_file(home.child(".claude/skills/a")).expect("one write to make");
    apply(&env(home.path()), true, &mut Vec::new()).expect("apply");
    assert!(Stamps::read(&stamps.ask_due()).is_some(), "seeded");
    assert!(!stamps.check_due().exists(), "nothing checks on its own");
}

#[test]
fn an_auto_only_configuration_is_never_asked_whether_to_check() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(
        &home,
        &layer().replace(
            "branch = \"master\"\n",
            "branch = \"master\"\ncheck = \"auto\"\n",
        ),
    );
    update(&home, true, &mut Vec::new()).expect("update");
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    assert!(!stamps.ask_due().exists());
    assert!(Stamps::read(&stamps.check_due()).is_some());
}

#[test]
fn a_config_repo_with_no_upstream_is_locked_as_it_stands() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    run(
        home.path(),
        &repo,
        &["branch", "--quiet", "--unset-upstream"],
    );
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with("The config repo's master has no upstream"),
        "{}",
        text(&out)
    );
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%s"]),
        "chore(bx): update bx.lock"
    );
}

#[test]
fn a_branch_diverged_only_by_unpushed_lock_commits_catches_up_and_locks_again() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    run(home.path(), &repo, &["push", "--quiet"]);
    // This machine locks a new commit and never pushes it; another
    // machine pushes a change of its own.
    publish(&home, &["skills/b/SKILL.md"]);
    update(&home, true, &mut Vec::new()).expect("a local lock commit");
    let other = crate::sync::tests::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let third = publish(&home, &["skills/c/SKILL.md"]);

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("caught up");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with("Replayed 1 unpushed bx.lock commit(s)"),
        "{}",
        text(&out)
    );
    assert_eq!(locked(&home).as_deref(), Some(third.as_str()));
    assert_eq!(
        run(home.path(), &repo, &["log", "--format=%s", "-3"]),
        "chore(bx): update bx.lock\nchore(bx): update bx.lock\nelsewhere",
        "kept, on top of the upstream"
    );
    assert!(home.child(".claude/skills/c/SKILL.md").is_file());
}

/// A config repo whose branch has one unpushed lock commit of this
/// machine's, and an upstream another machine pushed `notes` to.
fn diverged(home: &GuardedHome) -> std::path::PathBuf {
    upstream(home, &["skills/a/SKILL.md"]);
    let repo = cloned(home, &layer());
    update(home, true, &mut Vec::new()).expect("update");
    run(home.path(), &repo, &["push", "--quiet"]);
    publish(home, &["skills/b/SKILL.md"]);
    update(home, true, &mut Vec::new()).expect("a local lock commit");
    let other = crate::sync::tests::other(home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    repo
}

#[test]
fn a_replay_that_cannot_start_says_why_and_changes_nothing() {
    let home = guarded_home();
    let repo = diverged(&home);
    // Declaring a dependency is an edit to a layer, made first.
    let layer_text = std::fs::read_to_string(repo.join("bx.toml")).expect("bx.toml");
    std::fs::write(repo.join("bx.toml"), format!("{layer_text}# soon\n")).expect("an edit");
    let head = rev(home.path(), &repo, "HEAD");
    let error = update(&home, true, &mut Vec::new()).expect_err("in the way");
    let shown = error.to_string();
    assert!(matches!(error, update::Error::Sync(_)), "{error:?}");
    assert!(!shown.contains("no rebase in progress"), "{shown}");
    assert!(!shown.contains("another machine pushed"), "{shown}");
    assert_eq!(rev(home.path(), &repo, "HEAD"), head);
    assert!(!update::rebasing(&git(home.path()), &repo));
    assert!(
        std::fs::read_to_string(repo.join("bx.toml"))
            .expect("kept")
            .ends_with("# soon\n")
    );
}

#[test]
fn a_replay_that_stops_for_signing_is_not_called_a_conflict() {
    let home = guarded_home();
    let repo = diverged(&home);
    for (key, value) in [
        ("commit.gpgsign", "true"),
        ("gpg.format", "ssh"),
        ("user.signingkey", "/nonexistent/bx-test-key"),
    ] {
        run(home.path(), &repo, &["config", key, value]);
    }
    let head = rev(home.path(), &repo, "HEAD");
    let error = update(&home, true, &mut Vec::new()).expect_err("cannot sign");
    assert!(matches!(error, update::Error::Sync(_)), "{error:?}");
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "put back");
    assert!(
        !update::rebasing(&git(home.path()), &repo),
        "no replay left open"
    );
}

#[test]
fn a_replay_the_upstream_already_holds_says_so() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    run(home.path(), &repo, &["push", "--quiet"]);
    publish(&home, &["skills/b/SKILL.md"]);
    update(&home, true, &mut Vec::new()).expect("a local lock commit");
    // Another machine locked the very same commit and pushed it.
    let other = crate::sync::tests::other(&home);
    std::fs::copy(repo.join("bx.lock"), other.join("bx.lock")).expect("bx.lock");
    commit_all(home.path(), &other, update::SUBJECT);
    run(home.path(), &other, &["push", "--quiet"]);
    let mut out = Vec::new();
    update(&home, true, &mut out).expect("caught up");
    assert!(
        text(&out).starts_with("This machine's unpushed bx.lock commits were already in"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_rebase_left_open_in_the_config_repo_is_named() {
    let home = guarded_home();
    let repo = diverged(&home);
    std::fs::create_dir_all(repo.join(".git/rebase-merge")).expect("an open rebase");
    let error = update(&home, true, &mut Vec::new()).expect_err("open");
    assert!(matches!(error, update::Error::Rebasing(_)), "{error:?}");
    assert!(error.to_string().contains("rebase --abort"), "{error}");
}

#[test]
fn a_move_nothing_here_can_check_exits_pending() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    publish(&home, &["skills/b/SKILL.md"]);
    // A machine with the configuration and none of its checkouts.
    std::fs::remove_dir_all(home.child(AT)).expect("no checkout");
    std::fs::remove_dir_all(home.child(".local/state/bx")).expect("no state");
    let before = locked(&home);
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(text(&out).contains("is not locked"), "{}", text(&out));
    assert_eq!(locked(&home), before);
    assert!(home.child(AT).is_dir(), "cloned at the commit locked");
}

#[test]
fn a_snooze_while_a_check_holds_on_still_puts_the_question_off() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    std::fs::write(stamps.ask_due(), "1\n").expect("due");
    stamps
        .write(&stamps.available(), "~/x: y\n")
        .expect("offered");
    // Held throughout, past the snooze's wait: it gives up waiting
    // and writes anyway.
    let _held = stamps.try_hold().expect("hold").expect("free");
    update::snooze_waiting(
        &env(home.path()),
        std::time::Duration::from_millis(50),
        &mut Vec::new(),
    )
    .expect("snoozed");
    assert!(Stamps::read(&stamps.ask_due()).expect("ask-due") > 1);
    assert!(!stamps.available().exists());
}

#[test]
fn lock_commits_both_machines_made_are_left_for_a_person() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    run(home.path(), &repo, &["push", "--quiet"]);
    publish(&home, &["skills/b/SKILL.md"]);
    update(&home, true, &mut Vec::new()).expect("a local lock commit");
    // The other machine locked a commit of its own on the same line.
    let other = crate::sync::tests::other(&home);
    let theirs = std::fs::read_to_string(other.join("bx.lock"))
        .expect("bx.lock")
        .replace(&first, &"d".repeat(40));
    std::fs::write(other.join("bx.lock"), theirs).expect("bx.lock");
    commit_all(home.path(), &other, update::SUBJECT);
    run(home.path(), &other, &["push", "--quiet"]);
    let head = rev(home.path(), &repo, "HEAD");

    let error = update(&home, true, &mut Vec::new()).expect_err("both changed it");
    assert!(
        matches!(error, update::Error::LockDiverged { commits: 1, .. }),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("reset --keep @{upstream}"),
        "{error}"
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing moved");
    assert_eq!(run(home.path(), &repo, &["status", "--porcelain"]), "");
    assert!(
        !repo.join(".git/rebase-merge").exists(),
        "no replay left open"
    );
}

#[test]
fn a_branch_diverged_by_a_persons_commit_is_left_for_them() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    run(home.path(), &repo, &["push", "--quiet"]);
    // A person's own edit, to bx.lock alone: theirs all the same.
    let edited = std::fs::read_to_string(repo.join("bx.lock")).expect("bx.lock");
    std::fs::write(repo.join("bx.lock"), format!("{edited}# mine\n")).expect("an edit");
    commit_all(home.path(), &repo, "mine");
    let other = crate::sync::tests::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let head = rev(home.path(), &repo, "HEAD");

    let error = update(&home, true, &mut Vec::new()).expect_err("diverged");
    assert!(
        matches!(error, update::Error::Sync(sync::Error::Diverged { .. })),
        "{error:?}"
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing moved");
}

#[test]
fn a_lock_change_apply_writes_nothing_for_is_still_asked_about() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    // An entry for an external nothing follows any more.
    let mut lock = Lock::read(&repo, home.path()).expect("bx.lock");
    let entry = lock
        .iter()
        .next()
        .map(|(_, l)| l.clone())
        .expect("an entry");
    lock.set(
        crate::paths::Portable::parse_in("~/gone", home.path()).expect("a path"),
        entry,
    );
    std::fs::write(repo.join("bx.lock"), lock.render()).expect("bx.lock");
    commit_all(home.path(), &repo, "an orphan");
    let orphaned = std::fs::read_to_string(repo.join("bx.lock")).expect("bx.lock");

    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut out = Vec::new();
    update_with(&tty, &[], false, &mut out, &git(home.path()), &mut || {
        Ok(false)
    })
    .expect("declined");
    assert!(!text(&out).contains("Locked."), "{}", text(&out));
    assert_eq!(
        std::fs::read_to_string(repo.join("bx.lock")).expect("bx.lock"),
        orphaned,
        "declined: kept"
    );

    let mut out = Vec::new();
    update_with(&tty, &[], false, &mut out, &git(home.path()), &mut || {
        Ok(true)
    })
    .expect("approved");
    assert!(text(&out).contains("Locked."), "{}", text(&out));
    let now = std::fs::read_to_string(repo.join("bx.lock")).expect("bx.lock");
    assert!(!now.contains("~/gone"), "{now}");
    assert!(
        run(home.path(), &repo, &["log", "-1", "--format=%B"])
            .contains("~/gone: no longer followed")
    );
}

#[test]
fn a_remote_refusing_a_commit_by_id_still_lets_a_checkout_holding_it_move() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    let next = publish(&home, &["skills/b/SKILL.md"]);
    // A remote that refuses a commit asked for by id, as protocol v0
    // servers do by default: a checkout already holding the commit
    // locked must not need to.
    let config = home.child(".gitconfig");
    let mut text_now = std::fs::read_to_string(&config).expect("~/.gitconfig");
    text_now.push_str("[protocol]\n\tversion = 0\n");
    std::fs::write(&config, text_now).expect("~/.gitconfig");
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert_eq!(
        locked(&home).as_deref(),
        Some(next.as_str()),
        "{}",
        text(&out)
    );
}

#[test]
fn a_person_s_update_waits_briefly_then_says_another_runs() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    let _held = stamps.try_hold().expect("hold").expect("free");
    let error = update(&home, true, &mut Vec::new()).expect_err("busy");
    assert!(matches!(error, update::Error::Busy), "{error:?}");
    let error = update::check(
        &env(home.path()),
        &[],
        false,
        &git(home.path()),
        &mut Vec::new(),
    )
    .expect_err("busy");
    assert!(matches!(error, update::Error::Busy), "{error:?}");
    assert_eq!(locked(&home), None, "nothing looked at or locked");
}

#[test]
fn a_background_check_that_fails_says_why_and_waits_an_hour() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    std::fs::write(repo.join("bx.toml"), "[[external]\n").expect("a broken layer");
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    let before = update::now();
    update::check(
        &env(home.path()),
        &[],
        true,
        &git(home.path()),
        &mut Vec::new(),
    )
    .expect_err("the configuration does not load");
    let last = std::fs::read_to_string(stamps.last_check()).expect("last-check");
    assert!(last.starts_with("the check failed: "), "{last}");
    let due = Stamps::read(&stamps.check_due()).expect("check-due");
    assert!(
        (before + 3600..=update::now() + 3600).contains(&due),
        "an hour on: {due}"
    );
}

#[test]
fn a_config_repo_git_does_not_manage_gets_its_lock_uncommitted() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    crate::plan::tests::seed(home.path(), &layer());
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with("The config repo is not a git repository"),
        "{}",
        text(&out)
    );
    assert_eq!(locked(&home).as_deref(), Some(first.as_str()));
}

#[test]
fn a_refused_first_lock_commit_leaves_no_lock_behind() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    let hook = repo.join(".git/hooks/pre-commit");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").expect("a hook");
    crate::fs::set_mode(&hook, crate::fs::Mode::from_bits(0o755)).expect("executable");
    update(&home, true, &mut Vec::new()).expect_err("the hook refuses");
    assert!(!repo.join("bx.lock").exists());
    assert_eq!(run(home.path(), &repo, &["status", "--porcelain"]), "");
    assert!(!home.child(AT).exists());
}

#[test]
fn each_flag_asks_for_its_mode() {
    use UpdateMode::{Background, Check, Snooze, Update};
    assert_eq!(
        UpdateMode::from_flags(false, false, false, false),
        Update { yes: false }
    );
    assert_eq!(
        UpdateMode::from_flags(true, false, false, false),
        Update { yes: true }
    );
    assert_eq!(UpdateMode::from_flags(false, true, false, false), Check);
    assert_eq!(UpdateMode::from_flags(false, false, true, false), Snooze);
    assert_eq!(
        UpdateMode::from_flags(false, false, false, true),
        Background
    );
    assert_eq!(UpdateMode::from_flags(true, true, true, true), Background);
    assert_eq!(UpdateMode::from_flags(false, true, true, false), Snooze);
}

#[test]
fn update_says_it_fast_forwarded_and_declining_locks_nothing() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &layer());
    update(&home, true, &mut Vec::new()).expect("update");
    // Pushed, as `bx sync` would; then another machine pushed too.
    run(home.path(), &repo, &["push", "--quiet"]);
    let other = crate::sync::tests::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    publish(&home, &["skills/b/SKILL.md"]);
    let before = locked(&home);
    let head = rev(home.path(), &repo, "HEAD");

    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut out = Vec::new();
    update_with(&tty, &[], false, &mut out, &git(home.path()), &mut || {
        Ok(false)
    })
    .expect("declined");
    assert!(
        text(&out).starts_with("Fast-forwarded master by 1 commit(s) from origin/master.\n"),
        "{}",
        text(&out)
    );
    assert_eq!(locked(&home), before, "declined: nothing locked");
    assert_ne!(rev(home.path(), &repo, "HEAD"), head, "but the pull stands");
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%s"]),
        "elsewhere",
        "no lock commit"
    );
    assert!(!home.child(".claude/skills/b").exists());
}

#[test]
fn a_name_that_is_not_a_followed_external_is_refused() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &layer());
    let error = update_with(
        &env(home.path()),
        &["~/elsewhere".to_string()],
        true,
        &mut Vec::new(),
        &git(home.path()),
        &mut never,
    )
    .expect_err("not followed");
    assert!(matches!(error, update::Error::NotFollowed(_)), "{error:?}");
}
