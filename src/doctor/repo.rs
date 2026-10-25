//! Check 14: the config repo's local state, and local work in a followed
//! external's checkout.
//!
//! Each of these is otherwise found only once `bx sync`, `bx update`, `apply`
//! or `rm` stops on it. For the config repo, one finding for each of:
//!
//! * a rebase or `git am` left in progress;
//! * a detached `HEAD` (none while a rebase is in progress, which detaches
//!   it on purpose);
//! * uncommitted changes or untracked files;
//! * a branch with no upstream, or one whose upstream has no ref here;
//! * commits the upstream lacks, saying how many are `bx update`'s `bx.lock`
//!   commits; commits the branch lacks; or both, a branch that has diverged.
//!
//! Ahead and behind are counted against the remote-tracking ref as the last
//! fetch left it. Doctor never fetches: it asks no remote anything, and the
//! note says when that fetch was, from `FETCH_HEAD`'s modification time.
//!
//! For each followed external whose checkout the ledger records as bx's own
//! finished clone, local work in it — what [`kept_by_rm`] would keep `bx rm`
//! from removing — is a finding.
//!
//! A config repo that is not a git repository at all (it holds no `.git`) is
//! no finding, and nothing is asked: bx works without git, and `bx sync` says
//! what it needs when it is run. Every note quotes the command that clears it
//! and runs none. Every question is read-only, and git is run with
//! `GIT_OPTIONAL_LOCKS=0`, so `git status` does not refresh the index either:
//! doctor still writes nothing.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::Finding;
use crate::config::external::External;
use crate::git::checkout::{own_checkout, problem};
use crate::git::{self, Git};
use crate::paths;
use crate::plan::external::{finished_clone_entry, kept_by_rm};
use crate::state::LedgerView;
use crate::sync;
use crate::update::SUBJECT;

/// Every finding about the config repo at `repo`, then one for each followed
/// external in `externals`, in configuration order, that holds local work.
#[must_use]
pub fn check(
    repo: &Path,
    externals: &[External],
    ledger: &LedgerView,
    home: &Path,
    git: &Git,
) -> Vec<Finding> {
    // `git status` would otherwise take the index lock and rewrite the index
    // to refresh its stat data.
    let git = git.clone().with_env("GIT_OPTIONAL_LOCKS", "0");
    let mut findings = config_repo(repo, home, &git);
    findings.extend(followed(externals, ledger, home, &git));
    findings
}

/// The findings about the config repo, as the module lists them.
fn config_repo(repo: &Path, home: &Path, git: &Git) -> Vec<Finding> {
    if std::fs::symlink_metadata(repo.join(".git")).is_err() {
        return Vec::new();
    }
    let at = paths::to_portable(repo, home);
    let finding = |note: String| Finding {
        subject: at.clone(),
        origin: None,
        note,
    };
    if let Err(note) = own_checkout(git, repo) {
        return vec![finding(note)];
    }
    let mut findings = Vec::new();
    let files = match GitFiles::of(git, repo) {
        Ok(files) => files,
        Err(error) => return vec![finding(problem(&error))],
    };
    let operation = files.operation();
    if let Some((what, command)) = operation {
        findings.push(finding(format!(
            "has {what} in progress, so `bx sync` cannot fast-forward it; `git -C {at} \
             status` says where it stands, and `git -C {at} {command} --continue` or `--abort` \
             finishes it"
        )));
    }
    match git.query(repo, &["status", "--porcelain", "--untracked-files=all"]) {
        Ok(status) if status.is_empty() => {}
        Ok(status) => findings.push(finding(format!(
            "has {} uncommitted change(s) or untracked file(s), which only this machine \
             holds; `git -C {at} status` shows them",
            status.lines().count()
        ))),
        Err(error) => findings.push(finding(problem(&error))),
    }
    let branch = match git.query(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]) {
        Ok(branch) => branch,
        Err(error @ git::Error::Spawn { .. }) => {
            findings.push(finding(problem(&error)));
            return findings;
        }
        Err(_) => {
            if operation.is_none() {
                findings.push(finding(format!(
                    "has no branch checked out (its HEAD is detached), so `bx sync` and \
                     `bx update` refuse it; `git -C {at} switch BRANCH` checks one out"
                )));
            }
            return findings;
        }
    };
    if let Err(note) = branch_state(git, repo, &at, &branch, files.fetched()) {
        findings.push(finding(note));
    }
    findings
}

/// `Err` with the note for `branch` against its upstream: none, gone, or
/// ahead, behind or both. `Ok` when it is level with its upstream.
fn branch_state(
    git: &Git,
    repo: &Path,
    at: &str,
    branch: &str,
    fetched: Option<String>,
) -> Result<(), String> {
    let upstream = sync::upstream(git, repo, branch).map_err(|error| match error {
        sync::Error::NoUpstream { .. } => format!(
            "is on {branch}, which has no upstream, so `bx sync` has nowhere to pull from or \
             push to; `git -C {at} branch --set-upstream-to=REMOTE/BRANCH` sets one"
        ),
        other => note(&other),
    })?;
    let short = &upstream.short;
    let as_of = fetched.map_or_else(
        || "as of the clone or the last push, since nothing has fetched here".to_string(),
        |when| format!("as of the last fetch, at {when}"),
    );
    if sync::gone(git, repo, branch).map_err(|error| note(&error))? {
        return Err(format!(
            "is on {branch}, which tracks {short}, and {short} has no ref here {as_of}: it was \
             deleted, or never pushed, so `bx sync` refuses it; `git -C {at} push \
             --set-upstream {remote} {branch}` publishes it, or `git -C {at} branch \
             --set-upstream-to=REMOTE/BRANCH` sets another",
            remote = upstream.remote
        ));
    }
    let (ahead, behind) = sync::counts(git, repo).map_err(|error| note(&error))?;
    match (ahead, behind) {
        (0, 0) => Ok(()),
        (0, behind) => Err(format!(
            "is on {branch}, {behind} commit(s) behind {short} {as_of}; `bx sync` \
             fast-forwards it"
        )),
        (ahead, 0) => Err(format!(
            "is on {branch}, with {ahead} commit(s) {short} lacks {as_of}, {}; `bx sync` \
             pushes them",
            lock_commits(git, repo, ahead)
        )),
        (ahead, behind) => Err(format!(
            "is on {branch}, which has diverged from {short} {as_of}: {ahead} commit(s) only \
             here, {behind} only there; `bx sync` only fast-forwards, so merge or rebase \
             {branch} yourself, as `git -C {at} status` shows"
        )),
    }
}

/// How many of the `ahead` commits on the branch alone are `bx update`'s
/// `bx.lock` commits, in words.
fn lock_commits(git: &Git, repo: &Path, ahead: u64) -> String {
    let Ok(subjects) = git.query(repo, &["log", "--format=%s", "@{upstream}..HEAD"]) else {
        return "and git did not say which they are".to_string();
    };
    let locks = subjects
        .lines()
        .filter(|subject| *subject == SUBJECT)
        .count() as u64;
    match locks {
        0 => "none of them a `bx update` lock commit".to_string(),
        all if all == ahead => "every one a `bx update` lock commit".to_string(),
        some => format!("{some} of them `bx update` lock commits"),
    }
}

/// What a `sync` question's failure says, in a finding's words.
fn note(error: &sync::Error) -> String {
    match error {
        sync::Error::Git(error) => problem(error),
        other => other.to_string(),
    }
}

/// The files git keeps for the config repo that doctor reads: where each of
/// them is, whether or not it exists.
struct GitFiles {
    fetch_head: PathBuf,
    rebase_merge: PathBuf,
    rebase_apply: PathBuf,
}

impl GitFiles {
    /// Ask git where they are, so a linked worktree's are found too.
    fn of(git: &Git, repo: &Path) -> Result<Self, git::Error> {
        let answer = git.query(
            repo,
            &[
                "rev-parse",
                "--git-path",
                "FETCH_HEAD",
                "--git-path",
                "rebase-merge",
                "--git-path",
                "rebase-apply",
            ],
        )?;
        let mut lines = answer.lines().map(|line| repo.join(line));
        let mut next = || lines.next().unwrap_or_default();
        Ok(Self {
            fetch_head: next(),
            rebase_merge: next(),
            rebase_apply: next(),
        })
    }

    /// The operation left in progress, and the git command that finishes it.
    fn operation(&self) -> Option<(&'static str, &'static str)> {
        if self.rebase_merge.is_dir() {
            Some(("a rebase", "rebase"))
        } else if self.rebase_apply.join("applying").exists() {
            Some(("a `git am`", "am"))
        } else if self.rebase_apply.is_dir() {
            Some(("a rebase", "rebase"))
        } else {
            None
        }
    }

    /// When the last fetch was, or `None` when nothing has fetched.
    fn fetched(&self) -> Option<String> {
        let modified = std::fs::metadata(&self.fetch_head).ok()?.modified().ok()?;
        let seconds = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
        Some(crate::version::utc(seconds))
    }
}

/// A finding for each followed external, in configuration order, whose
/// checkout bx cloned and finished and that holds work of the user's.
fn followed(externals: &[External], ledger: &LedgerView, home: &Path, git: &Git) -> Vec<Finding> {
    let mut findings = Vec::new();
    for external in externals {
        let Some(follow) = external.follows() else {
            continue;
        };
        let Some(entry) = finished_clone_entry(ledger, &external.path) else {
            continue;
        };
        let dest = external.path.render(home);
        if !dest.is_dir() {
            continue;
        }
        if let Some(why) = kept_by_rm(git, &dest, entry) {
            findings.push(Finding {
                subject: external.path.to_string(),
                origin: Some(external.origin.clone()),
                note: format!(
                    "follows `{}` and {why}; `git -C {} status` shows what is only here",
                    follow.branch, external.path
                ),
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::config::external::{Check, Follow, Pin};
    use crate::paths::Portable;
    use crate::plan::tests::seed;
    use crate::state::{ExclusiveLock, Ledger, Mechanism, NewEntry, PriorBytes, StateDir};
    use crate::sync::tests::{cloned, commit_all, git as test_git, other, rev, run};
    use crate::testing::{GuardedHome, guarded_home};

    /// The notes doctor finds in `home`'s config repo, with no externals.
    fn notes(home: &GuardedHome) -> Vec<String> {
        notes_of(home, &[])
    }

    /// The notes doctor finds in `home`, with `externals` declared.
    fn notes_of(home: &GuardedHome, externals: &[External]) -> Vec<String> {
        let state = StateDir::resolve(home.path());
        let ledger = LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value;
        check(
            &home.child(".config/bx"),
            externals,
            &ledger,
            home.path(),
            &test_git(home.path()),
        )
        .into_iter()
        .map(|finding| format!("{} {}", finding.subject, finding.note))
        .collect()
    }

    /// Commit an empty commit with `message` in `dir`.
    fn empty_commit(home: &GuardedHome, dir: &Path, message: &str) {
        run(
            home.path(),
            dir,
            &["commit", "--quiet", "--allow-empty", "-m", message],
        );
    }

    /// Push a commit from another clone, and fetch it here.
    fn behind(home: &GuardedHome, repo: &Path) {
        let other = other(home);
        empty_commit(home, &other, "elsewhere");
        run(home.path(), &other, &["push", "--quiet"]);
        run(home.path(), repo, &["fetch", "--quiet"]);
    }

    #[test]
    fn a_clean_repo_level_with_its_upstream_is_no_finding() {
        let home = guarded_home();
        cloned(&home, "");
        assert_eq!(notes(&home), Vec::<String>::new());
    }

    #[test]
    fn a_config_repo_that_is_not_a_git_repository_is_no_finding() {
        let home = guarded_home();
        seed(home.path(), "");
        // A git that cannot be started proves nothing was asked.
        let state = StateDir::resolve(home.path());
        let ledger = LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value;
        let git = test_git(home.path()).with_program(home.child("no-such-git"));
        assert_eq!(
            check(&home.child(".config/bx"), &[], &ledger, home.path(), &git),
            Vec::new()
        );
    }

    #[test]
    fn a_git_that_cannot_be_started_is_a_finding() {
        let home = guarded_home();
        cloned(&home, "");
        let state = StateDir::resolve(home.path());
        let ledger = LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value;
        let git = test_git(home.path()).with_program(home.child("no-such-git"));

        let found = check(&home.child(".config/bx"), &[], &ledger, home.path(), &git);

        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].note.contains("git could not be started"),
            "{found:?}"
        );
    }

    #[test]
    fn uncommitted_and_untracked_changes_are_one_finding() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        std::fs::write(repo.join("bx.toml"), "# edited\n").unwrap();
        std::fs::write(repo.join("new.toml"), "").unwrap();

        assert_eq!(
            notes(&home),
            [
                "~/.config/bx has 2 uncommitted change(s) or untracked file(s), which only this \
              machine holds; `git -C ~/.config/bx status` shows them"
            ]
        );
    }

    #[test]
    fn unpushed_commits_say_how_many_are_lock_commits() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        empty_commit(&home, &repo, SUBJECT);
        let as_of = "as of the clone or the last push, since nothing has fetched here";

        assert_eq!(
            notes(&home),
            [format!(
                "~/.config/bx is on master, with 1 commit(s) origin/master lacks {as_of}, every \
                 one a `bx update` lock commit; `bx sync` pushes them"
            )]
        );

        empty_commit(&home, &repo, "mine");
        assert_eq!(
            notes(&home),
            [format!(
                "~/.config/bx is on master, with 2 commit(s) origin/master lacks {as_of}, 1 of \
                 them `bx update` lock commits; `bx sync` pushes them"
            )]
        );
    }

    #[test]
    fn an_unpushed_commit_of_the_users_is_no_lock_commit() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        empty_commit(&home, &repo, "mine");

        let found = notes(&home);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("none of them a `bx update` lock commit"),
            "{found:?}"
        );
    }

    #[test]
    fn behind_is_counted_as_of_the_last_fetch_and_names_when_it_was() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        behind(&home, &repo);
        let fetch_head = repo.join(".git/FETCH_HEAD");
        let file = std::fs::File::options()
            .write(true)
            .open(&fetch_head)
            .unwrap();
        file.set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
            .unwrap();

        assert_eq!(
            notes(&home),
            [
                "~/.config/bx is on master, 1 commit(s) behind origin/master as of the last \
              fetch, at 2023-11-14T22:13:20Z; `bx sync` fast-forwards it"
            ]
        );
    }

    #[test]
    fn what_was_pushed_since_the_last_fetch_is_not_seen() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        let other = other(&home);
        empty_commit(&home, &other, "elsewhere");
        run(home.path(), &other, &["push", "--quiet"]);

        assert_eq!(notes(&home), Vec::<String>::new(), "doctor never fetches");
        assert_ne!(
            rev(home.path(), &repo, "origin/master"),
            rev(home.path(), &other, "HEAD")
        );
    }

    #[test]
    fn a_diverged_branch_is_one_finding() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        behind(&home, &repo);
        empty_commit(&home, &repo, "mine");

        let found = notes(&home);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0]
                .starts_with("~/.config/bx is on master, which has diverged from origin/master"),
            "{found:?}"
        );
        assert!(
            found[0].contains("1 commit(s) only here, 1 only there"),
            "{found:?}"
        );
    }

    #[test]
    fn a_branch_with_no_upstream_or_a_gone_one_is_a_finding() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        run(home.path(), &repo, &["switch", "--quiet", "-c", "local"]);
        assert_eq!(
            notes(&home),
            [
                "~/.config/bx is on local, which has no upstream, so `bx sync` has nowhere to \
              pull from or push to; `git -C ~/.config/bx branch --set-upstream-to=REMOTE/BRANCH` \
              sets one"
            ]
        );

        run(
            home.path(),
            &repo,
            &["branch", "--quiet", "--set-upstream-to=origin/master"],
        );
        run(
            home.path(),
            &repo,
            &["update-ref", "-d", "refs/remotes/origin/master"],
        );
        let found = notes(&home);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with(
                "~/.config/bx is on local, which tracks origin/master, and origin/master has no \
                 ref here"
            ),
            "{found:?}"
        );
        assert!(
            found[0].contains("`git -C ~/.config/bx push --set-upstream origin local`"),
            "{found:?}"
        );
    }

    #[test]
    fn a_detached_head_is_a_finding() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        run(home.path(), &repo, &["switch", "--quiet", "--detach"]);

        assert_eq!(
            notes(&home),
            [
                "~/.config/bx has no branch checked out (its HEAD is detached), so `bx sync` and \
              `bx update` refuse it; `git -C ~/.config/bx switch BRANCH` checks one out"
            ]
        );
    }

    #[test]
    fn a_rebase_or_am_in_progress_is_a_finding_and_no_detached_head() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        let git_dir = repo.join(".git");

        run(home.path(), &repo, &["switch", "--quiet", "--detach"]);
        std::fs::create_dir(git_dir.join("rebase-merge")).unwrap();
        assert_eq!(
            notes(&home),
            [
                "~/.config/bx has a rebase in progress, so `bx sync` cannot fast-forward it; \
              `git -C ~/.config/bx status` says where it stands, and `git -C ~/.config/bx \
              rebase --continue` or `--abort` finishes it"
            ]
        );
        std::fs::remove_dir(git_dir.join("rebase-merge")).unwrap();
        run(home.path(), &repo, &["switch", "--quiet", "master"]);

        std::fs::create_dir(git_dir.join("rebase-apply")).unwrap();
        std::fs::write(git_dir.join("rebase-apply/applying"), "").unwrap();
        let found = notes(&home);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("~/.config/bx has a `git am` in progress"),
            "{found:?}"
        );
        assert!(
            found[0].contains("`git -C ~/.config/bx am --continue`"),
            "{found:?}"
        );

        std::fs::remove_file(git_dir.join("rebase-apply/applying")).unwrap();
        let found = notes(&home);
        assert!(
            found[0].starts_with("~/.config/bx has a rebase in progress"),
            "{found:?}"
        );
    }

    /// An external at `~/ext` following `main`, cloned by bx and recorded
    /// as its finished clone at the commit checked out.
    fn followed_clone(home: &GuardedHome) -> (External, PathBuf) {
        let path = Portable::parse_in("~/ext", home.path()).unwrap();
        let dest = home.child("ext");
        let remote = home.child("remote.git");
        run(
            home.path(),
            home.path(),
            &[
                "clone",
                "--quiet",
                remote.to_str().unwrap(),
                dest.to_str().unwrap(),
            ],
        );
        let head = rev(home.path(), &dest, "HEAD");
        let state = StateDir::resolve(home.path());
        let lock = ExclusiveLock::acquire(&state).unwrap();
        let mut ledger = Ledger::open(&state, &lock, home.path()).unwrap().value;
        ledger
            .record(NewEntry::new(
                path.clone(),
                crate::state::clone_written(Some(&head)),
                crate::fs::Mode::DEFAULT_DIR,
                Mechanism::Clone,
                PriorBytes::Absent,
            ))
            .unwrap();
        ledger.save().unwrap();
        let external = External {
            path,
            url: remote.to_str().unwrap().to_string(),
            pin: Pin::Follow(Follow {
                branch: "main".to_string(),
                check: Check::Ask,
            }),
            links: Vec::new(),
            enabled: true,
            origin: Origin::unknown(&home.child(".config/bx/bx.toml")),
        };
        (external, dest)
    }

    #[test]
    fn local_work_in_a_followed_checkout_is_a_finding() {
        let home = guarded_home();
        cloned(&home, "");
        let (external, dest) = followed_clone(&home);
        let externals = [external];
        assert_eq!(notes_of(&home, &externals), Vec::<String>::new());

        std::fs::write(dest.join("scratch"), "").unwrap();
        assert_eq!(
            notes_of(&home, &externals),
            [
                "~/ext follows `main` and has uncommitted changes or untracked files that removing \
              it would lose; `git -C ~/ext status` shows what is only here"
            ]
        );

        commit_all(home.path(), &dest, "mine");
        assert_eq!(
            notes_of(&home, &externals),
            [
                "~/ext follows `main` and holds 1 commit(s) bx did not fetch, which removing it \
              would lose; `git -C ~/ext status` shows what is only here"
            ]
        );
    }

    #[test]
    fn a_finished_clone_whose_directory_is_gone_is_not_looked_into() {
        let home = guarded_home();
        cloned(&home, "");
        let (external, dest) = followed_clone(&home);
        std::fs::remove_dir_all(&dest).unwrap();
        // A git that cannot be started proves the checkout was not asked about.
        let state = StateDir::resolve(home.path());
        let ledger = LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value;
        let git = test_git(home.path()).with_program(home.child("no-such-git"));

        assert_eq!(
            followed(&[external], &ledger, home.path(), &git),
            Vec::new()
        );
    }

    /// The notes doctor finds in `home`'s config repo through a git that runs
    /// `body`, a shell script, before it runs the real git. Git is started as
    /// `git -C REPO ARGS`, so `$3` is the subcommand.
    fn notes_through(home: &GuardedHome, body: &str) -> Vec<String> {
        let wrapper = home.child("bin/git");
        std::fs::create_dir_all(wrapper.parent().expect("a parent")).expect("bin");
        std::fs::write(&wrapper, format!("#!/bin/sh\n{body}\nexec git \"$@\"\n"))
            .expect("the wrapper");
        std::fs::set_permissions(
            &wrapper,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("executable");
        // Another test thread that forks while the wrapper is open for
        // writing holds that descriptor until its child calls `exec`, and
        // running the wrapper inside that window fails with `ETXTBSY`, which
        // doctor would report as a git it cannot start. The window closes on
        // its own, so the wrapper is run once here, retrying only that error,
        // before doctor runs it. `--version` leaves `$3` empty, so no body
        // reacts to the warm-up.
        let mut warmed = false;
        for _ in 0..200 {
            match std::process::Command::new(&wrapper)
                .arg("--version")
                .stdin(std::process::Stdio::null())
                .output()
            {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("the wrapper would not run: {e}"),
                Ok(_) => {
                    warmed = true;
                    break;
                }
            }
        }
        assert!(warmed, "the wrapper stayed busy");
        let state = StateDir::resolve(home.path());
        let ledger = LedgerView::read(&state, home.path())
            .expect("the ledger")
            .value;
        let git = test_git(home.path()).with_program(&wrapper);
        check(&home.child(".config/bx"), &[], &ledger, home.path(), &git)
            .into_iter()
            .map(|finding| format!("{} {}", finding.subject, finding.note))
            .collect()
    }

    #[test]
    fn a_git_that_stops_starting_at_the_branch_question_is_a_finding() {
        let home = guarded_home();
        cloned(&home, "");
        // git answers `status`, then removes itself, so the next question,
        // which branch is checked out, cannot start it.
        let found = notes_through(
            &home,
            "if [ \"$3\" = status ]; then git \"$@\"; s=$?; rm -f \"$0\"; exit $s; fi",
        );

        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("~/.config/bx git could not be started"),
            "{found:?}"
        );
    }

    #[test]
    fn a_git_that_fails_a_question_about_the_upstream_is_a_finding() {
        let home = guarded_home();
        cloned(&home, "");
        for (question, quoted) in [
            ("for-each-ref", "`git for-each-ref"),
            (
                "rev-list",
                "`git rev-list --left-right --count HEAD...@{upstream}`",
            ),
        ] {
            let found = notes_through(
                &home,
                &format!("[ \"$3\" = {question} ] && {{ echo refused >&2; exit 1; }}"),
            );

            assert_eq!(found.len(), 1, "{question}: {found:?}");
            assert!(
                found[0].starts_with(&format!("~/.config/bx {quoted}")),
                "{question}: {found:?}"
            );
            assert!(
                found[0].ends_with("failed: refused"),
                "{question}: {found:?}"
            );
        }
    }

    #[test]
    fn a_checkout_bx_did_not_clone_or_a_pinned_external_is_not_looked_into() {
        let home = guarded_home();
        cloned(&home, "");
        let (mut external, dest) = followed_clone(&home);
        std::fs::write(dest.join("scratch"), "").unwrap();
        external.pin = Pin::Rev(rev(home.path(), &dest, "HEAD"));
        assert_eq!(notes_of(&home, &[external.clone()]), Vec::<String>::new());

        external.path = Portable::parse_in("~/elsewhere", home.path()).unwrap();
        external.pin = Pin::Follow(Follow {
            branch: "main".to_string(),
            check: Check::Ask,
        });
        assert_eq!(notes_of(&home, &[external]), Vec::<String>::new());
    }

    #[test]
    fn doctor_leaves_the_index_as_it_found_it() {
        let home = guarded_home();
        let repo = cloned(&home, "");
        // A stat change with the same bytes, which `git status` would
        // otherwise refresh the index for.
        std::fs::File::options()
            .write(true)
            .open(repo.join("bx.toml"))
            .unwrap()
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
            .unwrap();
        let index = repo.join(".git/index");
        let before = std::fs::read(&index).unwrap();

        notes(&home);

        assert_eq!(std::fs::read(&index).unwrap(), before);
    }
}
