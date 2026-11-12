use super::*;
use crate::config::lock::Lock;
use crate::testing::GuardedHome;
use crate::testing::git::{cloned, commit_all, git, rev, run};
use crate::update::Stamps;

/// Where the followed external is checked out, relative to the home.
pub(super) const AT: &str = ".local/share/skills";

/// The url every test declares; `~/.gitconfig` rewrites it to the
/// repository at `~/upstream`.
pub(super) const URL: &str = "https://example.invalid/upstream";

/// The followed external, linking each skill into `~/.claude/skills`.
pub(super) fn layer() -> String {
    format!(
        "[[external]]\npath = \"~/{AT}\"\nurl = \"{URL}\"\nbranch = \"master\"\n\
                 [[external.link]]\nfrom = \"skills/*\"\nto = \"~/.claude/skills/*\"\n\
                 require = \"SKILL.md\"\n"
    )
}

/// An upstream at `~/upstream` reachable as [`URL`], holding `files`.
pub(super) fn upstream(home: &GuardedHome, files: &[&str]) -> String {
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
pub(super) fn publish(home: &GuardedHome, files: &[&str]) -> String {
    let dir = home.child("upstream");
    for file in files {
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a dir");
        std::fs::write(path, format!("{file}\n")).expect("a file");
    }
    commit_all(home.path(), &dir, "skills");
    rev(home.path(), &dir, "HEAD")
}

/// A config repo following [`layer`]'s external from an [`upstream`]
/// holding one skill. Returns the repo and the upstream's commit.
pub(super) fn following(home: &GuardedHome) -> (std::path::PathBuf, String) {
    let first = upstream(home, &["skills/a/SKILL.md"]);
    (cloned(home, &layer()), first)
}

/// [`following`], once `bx update` has locked the upstream's commit.
pub(super) fn locked_once(home: &GuardedHome) -> (std::path::PathBuf, String) {
    let followed = following(home);
    update(home, true, &mut Vec::new()).expect("update");
    followed
}

pub(super) fn update(
    home: &GuardedHome,
    yes: bool,
    out: &mut Vec<u8>,
) -> Result<Exit, update::Error> {
    update_with(
        &env(home.path()),
        &[],
        yes,
        out,
        &git(home.path()),
        &mut never,
    )
}

pub(super) fn locked(home: &GuardedHome) -> Option<String> {
    let lock = Lock::read(&home.child(".config/bx"), home.path()).expect("bx.lock");
    lock.iter().next().map(|(_, locked)| locked.rev.clone())
}

/// `bx update` on a machine whose push is refused, so the lock commit it
/// makes stays on this machine's branch alone.
pub(super) fn update_unpushed(home: &GuardedHome) {
    let hook = home.child(".config/bx/.git/hooks/pre-push");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").expect("a hook");
    crate::fs::set_mode(&hook, crate::fs::Mode::from_bits(0o755)).expect("executable");
    let mut out = Vec::new();
    update(home, true, &mut out).expect("a local lock commit");
    assert!(text(&out).contains("was refused"), "{}", text(&out));
    std::fs::remove_file(&hook).expect("the hook");
}

/// Commits only on the config repo's branch, and only on its upstream, as
/// git last saw the upstream.
fn ahead_behind(home: &GuardedHome, repo: &std::path::Path) -> String {
    run(
        home.path(),
        repo,
        &["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
    )
}

/// The upstream still at `pushed`, and nothing said about a push.
fn assert_nowhere_pushed(home: &GuardedHome, pushed: &str, out: &[u8]) {
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        pushed
    );
    assert!(!text(out).contains("Pushed"), "{}", text(out));
}

#[test]
fn update_pushes_its_lock_commit_to_the_upstream() {
    let home = guarded_home();
    let (repo, _) = following(&home);

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).ends_with("Pushed 1 commit(s) to origin/master.\n"),
        "{}",
        text(&out)
    );
    run(home.path(), &repo, &["fetch", "--quiet"]);
    assert_eq!(ahead_behind(&home, &repo), "0\t0");
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        rev(home.path(), &repo, "HEAD"),
        "the lock commit is the upstream's"
    );

    let mut again = Vec::new();
    update(&home, true, &mut again).expect("a second update");
    assert!(
        !text(&again).contains("Pushed"),
        "nothing left to push: {}",
        text(&again)
    );
}

#[test]
fn a_push_refused_because_the_upstream_moved_keeps_the_lock_and_names_bx_sync() {
    let home = guarded_home();
    let (repo, _) = following(&home);
    // Another machine's commit, pushed aside; the hook moves the upstream to
    // it once the lock is committed, after the pull.
    let other = crate::testing::git::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(
        home.path(),
        &other,
        &["push", "--quiet", "origin", "HEAD:side"],
    );
    let hook = repo.join(".git/hooks/post-commit");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nunset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE\nexec git --git-dir='{}' \
             update-ref refs/heads/master refs/heads/side\n",
            home.child("remote.git").display()
        ),
    )
    .expect("a hook");
    crate::fs::set_mode(&hook, crate::fs::Mode::from_bits(0o755)).expect("executable");

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("refused, and still an update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    let said = text(&out);
    assert!(
        said.contains("Pushed nothing: the push to origin/master was refused")
            && said.contains("The 1 commit(s) stay committed here, and `bx sync` pushes them"),
        "{said}"
    );
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%s"]),
        "chore(bx): update bx.lock",
        "the lock commit is kept"
    );
    assert!(home.child(".claude/skills/a/SKILL.md").is_file(), "applied");

    std::fs::remove_file(&hook).expect("the hook");
    let mut again = Vec::new();
    update(&home, true, &mut again).expect("replayed and pushed");
    assert!(
        text(&again).starts_with("Replayed 1 unpushed bx update commit(s)")
            && text(&again).ends_with("Pushed 1 commit(s) to origin/master.\n"),
        "{}",
        text(&again)
    );
    assert_eq!(ahead_behind(&home, &repo), "0\t0");
}

#[test]
fn a_lock_whose_apply_leaves_a_conflict_is_committed_and_not_pushed() {
    let home = guarded_home();
    let (repo, _) = following(&home);
    let pushed = rev(home.path(), &home.child("remote.git"), "master");
    // A file of the user's where the link would go.
    std::fs::create_dir_all(home.child(".claude/skills")).expect("a dir");
    std::fs::write(home.child(".claude/skills/a"), "mine\n").expect("a file");

    let mut out = Vec::new();
    update(&home, true, &mut out).expect("update");
    assert!(
        text(&out).contains("Pushed nothing: 1 commit(s) wait for an apply"),
        "{}",
        text(&out)
    );
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%s"]),
        "chore(bx): update bx.lock"
    );
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        pushed
    );
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
    let (repo, first) = locked_once(&home);
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
    let (repo, first) = locked_once(&home);
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
    following(&home);
    let error = update(&home, false, &mut Vec::new()).expect_err("no terminal");
    assert!(
        matches!(error, update::Error::Plan(Error::NeedsConfirmation)),
        "{error:?}"
    );
    assert_eq!(locked(&home), None);
    assert!(!home.child(AT).exists());
}

#[test]
fn an_external_one_account_switches_off_keeps_its_shared_lock_entry() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let other = format!(
        "[[external]]\npath = \"~/.local/share/other\"\nurl = \"{URL}\"\nbranch = \"master\"\n"
    );
    cloned(&home, &format!("{}{other}", layer()));
    update(&home, true, &mut Vec::new()).expect("both locked");
    let lock = || Lock::read(&home.child(".config/bx"), home.path()).expect("bx.lock");
    let entry = |lock: &Lock, at: &str| {
        lock.iter()
            .find(|(path, _)| path.as_str() == at)
            .map(|(_, locked)| locked.rev.clone())
    };
    let before = entry(&lock(), "~/.local/share/other").expect("locked");

    home.write(
        ".local/state/bx/local.toml",
        "[[external]]\npath = \"~/.local/share/other\"\nenabled = false\n",
    );
    let next = publish(&home, &["skills/b/SKILL.md"]);
    let mut out = Vec::new();
    update(&home, true, &mut out).expect("update");
    assert_eq!(
        entry(&lock(), &format!("~/{AT}")).as_deref(),
        Some(next.as_str()),
        "{}",
        text(&out)
    );
    assert_eq!(
        entry(&lock(), "~/.local/share/other").as_deref(),
        Some(before.as_str()),
        "another machine's entry stands"
    );

    // Pointed at another branch in `local.toml`: said, and not locked.
    run(home.path(), &home.child("upstream"), &["branch", "mine"]);
    home.write(
        ".local/state/bx/local.toml",
        &format!(
            "[[external]]\npath = \"~/.local/share/other\"\nurl = \"{URL}\"\nbranch = \"mine\"\n"
        ),
    );
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains(
            "~/.local/share/other: this account follows `mine` of https://example.invalid/upstream, \
             and the committed configuration another branch or url"
        ),
        "{}",
        text(&out)
    );
    let said = "~/.local/share/other: this account follows `mine` of \
                https://example.invalid/upstream, and the committed configuration another \
                branch or url; the shared bx.lock keeps the committed one's, so this is not \
                locked";
    assert!(
        text(&out).lines().any(|line| line == said),
        "{}",
        text(&out)
    );
    let kept = lock();
    let shared = kept
        .iter()
        .find(|(path, _)| path.as_str() == "~/.local/share/other")
        .expect("kept")
        .1;
    assert_eq!(
        (shared.branch.as_str(), shared.rev.as_str()),
        ("master", before.as_str())
    );
}

#[test]
fn an_external_only_local_toml_follows_is_never_locked_in_the_shared_lock() {
    let home = guarded_home();
    following(&home);
    home.write(
        ".local/state/bx/local.toml",
        &format!(
            "[[external]]\npath = \"~/.local/share/mine\"\nurl = \"{URL}\"\nbranch = \"master\"\n"
        ),
    );
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains(
            "~/.local/share/mine: this account follows `master` of \
             https://example.invalid/upstream, and the committed configuration does not follow it"
        ),
        "{}",
        text(&out)
    );
    let said = "~/.local/share/mine: this account follows `master` of \
                https://example.invalid/upstream, and the committed configuration does not \
                follow it; the shared bx.lock holds only what the committed configuration \
                follows. Declare it in a committed layer, or pin it with `rev`, so this is \
                not locked";
    assert!(
        text(&out).lines().any(|line| line == said),
        "{}",
        text(&out)
    );
    let lock = Lock::read(&home.child(".config/bx"), home.path()).expect("bx.lock");
    let paths: Vec<&str> = lock.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, [format!("~/{AT}").as_str()], "{}", text(&out));
}

#[test]
fn update_refuses_a_lock_with_uncommitted_edits() {
    let home = guarded_home();
    let (repo, _) = locked_once(&home);
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
    let (repo, _) = following(&home);
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
    let (repo, _) = following(&home);
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
    let (_, first) = locked_once(&home);
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
fn a_config_repo_with_no_upstream_is_locked_as_it_stands() {
    let home = guarded_home();
    let (repo, _) = following(&home);
    run(
        home.path(),
        &repo,
        &["branch", "--quiet", "--unset-upstream"],
    );
    let pushed = rev(home.path(), &home.child("remote.git"), "master");
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
    assert_nowhere_pushed(&home, &pushed, &out);
}

#[test]
fn a_config_repo_whose_upstream_is_gone_is_locked_as_it_stands() {
    let home = guarded_home();
    let (repo, _) = following(&home);
    run(
        home.path(),
        &repo,
        &["config", "branch.master.merge", "refs/heads/gone"],
    );
    let pushed = rev(home.path(), &home.child("remote.git"), "master");
    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("update");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with("The config repo's master tracks origin/gone, which does not"),
        "{}",
        text(&out)
    );
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%s"]),
        "chore(bx): update bx.lock"
    );
    assert_nowhere_pushed(&home, &pushed, &out);
}

#[test]
fn a_branch_diverged_only_by_unpushed_lock_commits_catches_up_and_locks_again() {
    let home = guarded_home();
    let (repo, _) = locked_once(&home);
    run(home.path(), &repo, &["push", "--quiet"]);
    // This machine locks a new commit and never pushes it; another
    // machine pushes a change of its own.
    publish(&home, &["skills/b/SKILL.md"]);
    update_unpushed(&home);
    let other = crate::testing::git::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let third = publish(&home, &["skills/c/SKILL.md"]);

    let mut out = Vec::new();
    let exit = update(&home, true, &mut out).expect("caught up");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with("Replayed 1 unpushed bx update commit(s)"),
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
pub(super) fn diverged(home: &GuardedHome) -> std::path::PathBuf {
    upstream(home, &["skills/a/SKILL.md"]);
    let repo = cloned(home, &layer());
    update(home, true, &mut Vec::new()).expect("update");
    run(home.path(), &repo, &["push", "--quiet"]);
    publish(home, &["skills/b/SKILL.md"]);
    update_unpushed(home);
    let other = crate::testing::git::other(home);
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
fn a_replay_that_cannot_be_put_back_is_named_as_an_open_rebase() {
    let home = guarded_home();
    let repo = diverged(&home);
    for (key, value) in [
        ("commit.gpgsign", "true"),
        ("gpg.format", "ssh"),
        ("user.signingkey", "/nonexistent/bx-test-key"),
    ] {
        run(home.path(), &repo, &["config", key, value]);
    }
    // git, except that `rebase --abort` fails.
    let wrapper = home.child("bin/git");
    std::fs::create_dir_all(wrapper.parent().expect("a parent")).expect("bin");
    std::fs::write(
        &wrapper,
        "#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = --abort ] && exit 1; done\nexec git \"$@\"\n",
    )
    .expect("the wrapper");
    std::fs::set_permissions(
        &wrapper,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("executable");
    let error = update_with(
        &env(home.path()),
        &[],
        true,
        &mut Vec::new(),
        &git(home.path()).with_program(&wrapper),
        &mut never,
    )
    .expect_err("left open");
    assert!(matches!(error, update::Error::Rebasing(_)), "{error:?}");
    assert!(update::rebasing(&git(home.path()), &repo), "open, as named");
    let again = update(&home, true, &mut Vec::new()).expect_err("still open");
    assert!(matches!(again, update::Error::Rebasing(_)), "{again:?}");
}

#[test]
fn a_replay_the_upstream_already_holds_says_so() {
    let home = guarded_home();
    let (repo, _) = locked_once(&home);
    run(home.path(), &repo, &["push", "--quiet"]);
    publish(&home, &["skills/b/SKILL.md"]);
    update_unpushed(&home);
    // Another machine locked the very same commit and pushed it.
    let other = crate::testing::git::other(&home);
    std::fs::copy(repo.join("bx.lock"), other.join("bx.lock")).expect("bx.lock");
    commit_all(home.path(), &other, update::SUBJECT);
    run(home.path(), &other, &["push", "--quiet"]);
    let mut out = Vec::new();
    update(&home, true, &mut out).expect("caught up");
    assert!(
        text(&out).starts_with("This machine's unpushed bx update commits were already in"),
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
    locked_once(&home);
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
fn lock_commits_both_machines_made_are_left_for_a_person() {
    let home = guarded_home();
    let (repo, first) = locked_once(&home);
    run(home.path(), &repo, &["push", "--quiet"]);
    publish(&home, &["skills/b/SKILL.md"]);
    update_unpushed(&home);
    // The other machine locked a commit of its own on the same line.
    let other = crate::testing::git::other(&home);
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
    let (repo, _) = locked_once(&home);
    run(home.path(), &repo, &["push", "--quiet"]);
    // A person's own edit, to bx.lock alone: theirs all the same.
    let edited = std::fs::read_to_string(repo.join("bx.lock")).expect("bx.lock");
    std::fs::write(repo.join("bx.lock"), format!("{edited}# mine\n")).expect("an edit");
    commit_all(home.path(), &repo, "mine");
    let other = crate::testing::git::other(&home);
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
fn a_remote_refusing_a_commit_by_id_still_lets_a_checkout_holding_it_move() {
    let home = guarded_home();
    locked_once(&home);
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
    following(&home);
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

/// [`layer`], checked on its own once a day.
fn auto() -> String {
    layer().replace(
        "branch = \"master\"\n",
        "branch = \"master\"\ncheck = \"auto\"\ninterval = \"1d\"\n",
    )
}

/// A config repo following [`auto`], locked at the upstream's first commit
/// and pushed, and a second commit published upstream that nothing locks
/// yet: the commit.
pub(super) fn pushed_and_moved(home: &GuardedHome) -> (std::path::PathBuf, String) {
    upstream(home, &["skills/a/SKILL.md"]);
    let repo = cloned(home, &auto());
    update(home, true, &mut Vec::new()).expect("update");
    run(home.path(), &repo, &["push", "--quiet"]);
    (repo, publish(home, &["skills/b/SKILL.md"]))
}

/// Another machine locks the external at `tip` and pushes it.
pub(super) fn locked_elsewhere(home: &GuardedHome, tip: &str) {
    let other = crate::testing::git::other(home);
    let lock = std::fs::read_to_string(other.join("bx.lock")).expect("bx.lock");
    let from = locked(home).expect("locked here");
    std::fs::write(other.join("bx.lock"), lock.replace(&from, tip)).expect("bx.lock");
    commit_all(home.path(), &other, update::SUBJECT);
    run(home.path(), &other, &["push", "--quiet"]);
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
    let (repo, _) = following(&home);
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
    let (repo, _) = locked_once(&home);
    // Pushed, as `bx sync` would; then another machine pushed too.
    run(home.path(), &repo, &["push", "--quiet"]);
    let other = crate::testing::git::other(&home);
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
    following(&home);
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

#[test]
fn a_lock_that_cannot_be_written_is_named_once() {
    let home = guarded_home();
    let repo = home.child("repo");
    let path = Lock::path_in(&repo);
    std::fs::create_dir_all(&path).expect("a directory where bx.lock goes");
    let error = update::write_and_commit(&git(home.path()), &repo, &Lock::default(), "lock")
        .expect_err("a directory is not written over");
    assert_eq!(
        error.to_string(),
        format!("{} is a directory, not a file bx can write", path.display())
    );
}
