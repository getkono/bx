//! `bx update --check`, its background run and `--snooze`: what a check
//! offers, when the next one and the next question are due, and how an
//! `update` answers or withdraws an offer.

use super::update_command::{
    AT, URL, diverged, following, layer, locked, locked_elsewhere, locked_once, publish,
    pushed_and_moved, update, update_unpushed, upstream,
};
use super::*;
use crate::config::lock::Lock;
use crate::testing::GuardedHome;
use crate::testing::git::{cloned, commit_all, git, rev, run};
use crate::update::Stamps;

#[test]
fn check_offers_what_it_found_and_snooze_puts_it_off() {
    let home = guarded_home();
    locked_once(&home);
    publish(&home, &["skills/b/SKILL.md"]);
    let env = env(home.path());
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));

    let mut out = Vec::new();
    let exit = update::check(&env, &[], false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Pending);
    let offered = std::fs::read_to_string(stamps.available()).expect("offered");
    let (generation, lines) = offered.split_once('\n').expect("a generation line");
    assert!(
        lines.starts_with(&format!("~/{AT}: 1 new commit(s)")),
        "{offered}"
    );
    assert_eq!(text(&out), lines, "what it says is what it offers");
    let lines: Vec<String> = lines.lines().map(str::to_string).collect();
    assert_eq!(generation, format!("gen {}", update::generation(&lines)));
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

/// Whether a shell's prompt would offer what `stamps` hold now.
fn offers(stamps: &Stamps) -> bool {
    Stamps::offers(
        std::fs::read(stamps.available()).ok().as_deref(),
        std::fs::read(stamps.answered()).ok().as_deref(),
    )
}

#[test]
fn an_answered_offer_found_again_is_not_offered_and_a_new_one_is() {
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
    publish(&home, &["skills/b/SKILL.md"]);
    let env = env(home.path());
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    let background =
        || update::check(&env, &[], true, &git(home.path()), &mut Vec::new()).expect("background");

    assert_eq!(background(), Exit::Pending);
    assert!(offers(&stamps));
    let offered = std::fs::read_to_string(stamps.available()).expect("offered");
    // As the shell answered writes it, before its `bx update --snooze` has
    // started, let alone taken the lock.
    let generation = offered.lines().next().expect("a line").strip_prefix("gen ");
    std::fs::write(stamps.answered(), format!("{}\n", generation.expect("gen"))).expect("answered");
    assert!(!offers(&stamps), "answered in some shell");

    // A check that was already running finds the same commits again.
    assert_eq!(background(), Exit::Pending);
    assert_eq!(
        std::fs::read_to_string(stamps.available()).expect("offered"),
        offered,
        "the same bytes"
    );
    assert!(!offers(&stamps), "the answer stands");

    publish(&home, &["skills/c/SKILL.md"]);
    assert_eq!(background(), Exit::Pending);
    assert!(offers(&stamps), "new commits are a new offer");

    update::snooze(&env, &mut Vec::new()).expect("snooze");
    assert!(!stamps.available().exists());
    assert!(
        !stamps.answered().exists(),
        "next interval, the same commits are offered again"
    );
}

/// One day, in seconds.
const DAY: u64 = 24 * 60 * 60;

#[test]
fn a_foreground_check_starts_a_new_ask_interval() {
    let home = guarded_home();
    locked_once(&home);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    std::fs::write(stamps.ask_due(), "1\n").expect("due long ago");

    let before = update::now();
    update::check(
        &env(home.path()),
        &[],
        false,
        &git(home.path()),
        &mut Vec::new(),
    )
    .expect("check");
    let after = update::now();
    let due = Stamps::read(&stamps.ask_due()).expect("ask-due");
    assert!(
        (before + 7 * DAY..=after + 7 * DAY).contains(&due),
        "the default interval from now: {due}"
    );
    assert!(!stamps.check_due().exists(), "nothing checks on its own");
}

#[test]
fn a_check_that_could_not_look_is_not_up_to_date() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    // A second followed external whose url leads nowhere.
    let gone = "~/.local/share/gone";
    let auto = "branch = \"master\"\ncheck = \"auto\"\ninterval = \"1d\"\n";
    cloned(
        &home,
        &format!(
            "{}[[external]]\npath = \"{gone}\"\nurl = \"https://example.invalid/gone\"\n{auto}",
            layer().replace("branch = \"master\"\n", auto)
        ),
    );
    let env = env(home.path());
    let names = [gone.to_string()];

    let mut out = Vec::new();
    let exit = update::check(&env, &names, false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Error, "{}", text(&out));
    assert!(
        text(&out).starts_with(&format!("{gone}: not checked: ")),
        "{}",
        text(&out)
    );

    let mut out = Vec::new();
    let exit = update::check(&env, &[], false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Pending, "something new wins: {}", text(&out));

    let mut quiet = Vec::new();
    let exit =
        update::check(&env, &names, true, &git(home.path()), &mut quiet).expect("background");
    assert_eq!(exit, Exit::Converged, "the shell's own check stays quiet");
    assert!(quiet.is_empty());
}

#[test]
fn a_background_check_sets_check_due_to_the_auto_interval_exactly() {
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
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));

    let before = update::now();
    update::check(
        &env(home.path()),
        &[],
        true,
        &git(home.path()),
        &mut Vec::new(),
    )
    .expect("background");
    let after = update::now();
    let due = Stamps::read(&stamps.check_due()).expect("check-due");
    assert!(
        (before + DAY..=after + DAY).contains(&due),
        "the external's own interval, not the hour a failure waits: {due}"
    );
}

#[test]
fn an_apply_leaves_an_existing_ask_due_and_check_due_alone() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let auto = format!(
        "[[external]]\npath = \"~/.local/share/other\"\nurl = \"{URL}\"\nbranch = \"master\"\n\
         check = \"auto\"\n"
    );
    cloned(&home, &format!("{}{auto}", layer()));
    update(&home, true, &mut Vec::new()).expect("update");
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    std::fs::write(stamps.ask_due(), "5\n").expect("ask-due");
    std::fs::write(stamps.check_due(), "6\n").expect("check-due");
    std::fs::remove_file(home.child(".claude/skills/a")).expect("one write to make");

    apply(&env(home.path()), true, &mut Vec::new()).expect("apply");
    assert!(home.child(".claude/skills/a").exists(), "the apply wrote");
    assert_eq!(
        std::fs::read_to_string(stamps.ask_due()).expect("ask-due"),
        "5\n"
    );
    assert_eq!(
        std::fs::read_to_string(stamps.check_due()).expect("check-due"),
        "6\n"
    );
}

#[test]
fn a_check_with_nothing_followed_says_so_and_converges() {
    let home = guarded_home();
    crate::plan::tests::seed(home.path(), "");
    let mut out = Vec::new();
    let exit =
        update::check(&env(home.path()), &[], false, &git(home.path()), &mut out).expect("check");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(text(&out), "No [[external]] follows a branch.\n");
}

#[test]
fn an_apply_on_a_machine_that_never_ran_update_starts_the_interval() {
    let home = guarded_home();
    locked_once(&home);
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
fn a_snooze_that_cannot_take_the_lock_writes_no_stamp_and_the_answer_stands() {
    let home = guarded_home();
    locked_once(&home);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    std::fs::write(stamps.ask_due(), "1\n").expect("due");
    stamps
        .write(&stamps.available(), "gen 8323ea2e82044071\n~/x: y\n")
        .expect("offered");
    // As the shell answered writes it, before it starts the snooze.
    std::fs::write(stamps.answered(), "8323ea2e82044071\nask 1\n").expect("answered");
    let before: Vec<_> = [stamps.ask_due(), stamps.available(), stamps.answered()]
        .iter()
        .map(|path| std::fs::read(path).expect("a stamp"))
        .collect();
    // Held throughout, past the snooze's wait, as a person's `bx update` or a
    // `bx sync` holds it: the snooze gives up and writes nothing.
    let _held = stamps.try_hold().expect("hold").expect("free");
    let mut out = Vec::new();
    let exit = update::snooze_waiting(
        &env(home.path()),
        std::time::Duration::from_millis(50),
        &mut out,
    )
    .expect("gave up quietly");
    assert_eq!(exit, Exit::Converged);
    assert!(text(&out).contains("nothing was snoozed"), "{}", text(&out));
    let after: Vec<_> = [stamps.ask_due(), stamps.available(), stamps.answered()]
        .iter()
        .map(|path| std::fs::read(path).expect("a stamp"))
        .collect();
    assert_eq!(after, before, "no stamp written without the lock");
    assert!(
        !offers(&stamps),
        "a new shell is still not asked: `answered` stands"
    );
}

/// A config repo in `home` whose `bx.lock` holds an entry nothing follows,
/// so `bx update` would change a lock `apply` writes nothing for; and that
/// lock's text.
fn orphaned_lock(home: &GuardedHome) -> (std::path::PathBuf, String) {
    upstream(home, &["skills/a/SKILL.md"]);
    let repo = cloned(home, &layer());
    update(home, true, &mut Vec::new()).expect("update");
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
    (repo, orphaned)
}

#[test]
fn a_lock_change_apply_writes_nothing_for_is_still_asked_about() {
    let home = guarded_home();
    let (repo, orphaned) = orphaned_lock(&home);
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
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
    settled(&stamps, &generation, since, "declined");

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
fn a_lock_change_apply_writes_nothing_for_abandoned_at_its_question_answers_the_offer() {
    let home = guarded_home();
    let (repo, orphaned) = orphaned_lock(&home);
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
    let mut out = Vec::new();
    let exit = update_with(&tty, &[], false, &mut out, &git(home.path()), &mut || {
        Err(Error::Canceled)
    })
    .expect("canceled");
    assert_eq!(exit, Exit::Canceled);
    assert!(
        text(&out)
            .lines()
            .any(|line| line == "Canceled. Nothing was locked."),
        "the lock's own question: {}",
        text(&out)
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("bx.lock")).expect("bx.lock"),
        orphaned,
        "canceled: kept"
    );
    settled(&stamps, &generation, since, "canceled");
}

#[test]
fn a_background_check_that_fails_says_why_and_waits_an_hour() {
    let home = guarded_home();
    let (repo, _) = following(&home);
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

/// A background check, and what it wrote to `last-check`.
fn background(home: &GuardedHome) -> (Exit, String) {
    let exit = update::check(
        &env(home.path()),
        &[],
        true,
        &git(home.path()),
        &mut Vec::new(),
    )
    .expect("background");
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    let last = std::fs::read_to_string(stamps.last_check()).expect("last-check");
    (exit, last)
}

#[test]
fn a_background_check_offers_nothing_another_machine_already_locked() {
    let home = guarded_home();
    let (repo, second) = pushed_and_moved(&home);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Pending, "{last}");
    assert!(offers(&stamps), "found here first");
    assert!(stamps.judged().is_file());

    locked_elsewhere(&home, &second);
    let head = rev(home.path(), &repo, "HEAD");
    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Converged, "{last}");
    assert!(!stamps.available().exists(), "{last}");
    assert!(!stamps.judged().exists());
    assert_eq!(
        last,
        format!(
            "judged against bx.lock as origin/master holds it: another machine updated it, and \
             `bx sync` brings it in\n~/{AT}: another machine already locked master at {}; \
             `bx sync` brings it in\n",
            &second[..12]
        )
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "the branch stays");
    assert_eq!(run(home.path(), &repo, &["status", "--porcelain"]), "");
    assert_eq!(
        locked(&home).as_deref(),
        Some(rev(home.path(), &home.child(AT), "HEAD").as_str()),
        "nothing moved here"
    );
}

#[test]
fn a_background_check_judges_what_the_upstream_has_not_locked_against_its_lock() {
    let home = guarded_home();
    let (_, second) = pushed_and_moved(&home);
    locked_elsewhere(&home, &second);
    let third = publish(&home, &["skills/c/SKILL.md"]);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Pending, "{last}");
    let offered = std::fs::read_to_string(stamps.available()).expect("offered");
    assert!(
        offered.ends_with(&format!(
            "~/{AT}: 1 new commit(s) on master, {} -> {}\n",
            &second[..12],
            &third[..12]
        )),
        "from what the upstream locks: {offered}"
    );
    assert!(
        last.starts_with("judged against bx.lock as origin/master holds it"),
        "{last}"
    );
}

#[test]
fn a_background_check_behind_an_upstream_with_the_same_lock_judges_its_own() {
    let home = guarded_home();
    let (repo, _) = pushed_and_moved(&home);
    let other = crate::testing::git::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Pending, "{last}");
    assert!(
        last.starts_with(&format!("~/{AT}: 1 new commit(s)")),
        "{last}"
    );
    assert!(!repo.join("notes").exists(), "fetched, never merged");
}

#[test]
fn a_background_check_with_no_upstream_to_judge_falls_back_to_this_machine_s_lock() {
    for (break_it, why) in [
        (
            &["branch", "--quiet", "--unset-upstream"][..],
            "the config repo's master has no upstream",
        ),
        (
            &["remote", "set-url", "origin", "/nonexistent/remote.git"][..],
            "origin/master could not be fetched: ",
        ),
        (
            &["config", "branch.master.merge", "refs/heads/gone"][..],
            "origin/gone, which master tracks, does not exist",
        ),
    ] {
        let home = guarded_home();
        let (repo, _) = pushed_and_moved(&home);
        run(home.path(), &repo, break_it);
        let (exit, last) = background(&home);
        assert_eq!(exit, Exit::Pending, "{last}");
        assert!(
            last.starts_with(&format!("judged against this machine's bx.lock: {why}")),
            "{last}"
        );
        assert!(
            last.contains(&format!("\n~/{AT}: 1 new commit(s)")),
            "{last}"
        );
    }
}

#[test]
fn a_background_check_diverged_from_its_upstream_judges_its_own_lock() {
    let home = guarded_home();
    let (repo, _) = pushed_and_moved(&home);
    std::fs::write(repo.join("mine"), "x\n").expect("a note");
    commit_all(home.path(), &repo, "mine");
    let other = crate::testing::git::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Pending, "{last}");
    assert!(
        last.starts_with(
            "judged against this machine's bx.lock: master and origin/master have diverged"
        ),
        "{last}"
    );
}

#[test]
fn a_background_check_with_nothing_on_auto_never_fetches_the_config_repo() {
    let home = guarded_home();
    let (repo, _) = locked_once(&home);
    run(home.path(), &repo, &["push", "--quiet"]);
    let tracked = rev(home.path(), &repo, "origin/master");
    let other = crate::testing::git::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);

    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Converged, "{last}");
    assert!(!last.contains("judged against"), "{last}");
    assert_eq!(
        rev(home.path(), &repo, "origin/master"),
        tracked,
        "no remote reached"
    );
}

#[test]
fn a_sync_that_brings_in_another_lock_withdraws_the_offer_and_checks_again() {
    let home = guarded_home();
    let (_, second) = pushed_and_moved(&home);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    background(&home);
    assert!(offers(&stamps));
    let offered = std::fs::read(stamps.available()).expect("offered");

    // The lock here is the one the offer was judged against.
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("apply");
    assert_eq!(
        std::fs::read(stamps.available()).expect("still offered"),
        offered
    );

    locked_elsewhere(&home, &second);
    let mut out = Vec::new();
    sync_with(
        &env(home.path()),
        true,
        &mut out,
        &git(home.path()),
        &mut never,
    )
    .expect("sync");
    assert!(!stamps.available().exists(), "{}", text(&out));
    assert!(!stamps.judged().exists());
    let due = Stamps::read(&stamps.check_due()).expect("check-due");
    assert!(due <= update::now(), "due at once: {due}");
    assert_eq!(rev(home.path(), &home.child(AT), "HEAD"), second);

    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Converged, "{last}");
    assert_eq!(last, format!("~/{AT}: up to date with master\n"));
    assert!(!stamps.available().exists());
}

#[test]
fn an_apply_of_another_lock_declined_or_unconfirmed_keeps_the_offer() {
    let home = guarded_home();
    let (repo, second) = pushed_and_moved(&home);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    background(&home);
    let offered = std::fs::read(stamps.available()).expect("offered");
    let due = std::fs::read(stamps.check_due()).expect("check-due");
    locked_elsewhere(&home, &second);
    run(home.path(), &repo, &["pull", "--quiet", "--ff-only"]);
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let kept = |why: &str| {
        assert_eq!(
            std::fs::read(stamps.available()).expect("still offered"),
            offered,
            "{why}"
        );
        assert!(stamps.judged().is_file(), "{why}");
        assert_eq!(
            std::fs::read(stamps.check_due()).expect("check-due"),
            due,
            "{why}"
        );
    };

    let exit = apply_with(&tty, false, &mut Vec::new(), &mut || Ok(false)).expect("declined");
    assert_ne!(exit, Exit::Converged);
    kept("declined");
    let exit =
        apply_with(&tty, false, &mut Vec::new(), &mut || Err(Error::Canceled)).expect("canceled");
    assert_eq!(exit, Exit::Canceled);
    kept("canceled");
    let unconfirmed = apply_with(&env(home.path()), false, &mut Vec::new(), &mut never);
    assert!(
        matches!(unconfirmed, Err(Error::NeedsConfirmation)),
        "{unconfirmed:?}"
    );
    kept("unconfirmed");

    apply_with(&tty, false, &mut Vec::new(), &mut || Ok(true)).expect("approved");
    assert!(!stamps.available().exists(), "approved: withdrawn");
    assert!(!stamps.judged().exists());
}

#[test]
fn a_check_carries_no_line_judged_against_an_older_lock() {
    let home = guarded_home();
    let (repo, second) = pushed_and_moved(&home);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    background(&home);
    assert!(offers(&stamps));
    // Another machine's lock, pulled by hand and never applied; then a check
    // that cannot look at the external again.
    locked_elsewhere(&home, &second);
    run(home.path(), &repo, &["pull", "--quiet", "--ff-only"]);
    std::fs::rename(home.child("upstream"), home.child("elsewhere")).expect("unreachable");
    let (exit, last) = background(&home);
    assert_eq!(exit, Exit::Converged, "{last}");
    assert!(last.contains("not checked"), "{last}");
    assert!(!stamps.available().exists(), "{last}");
    assert!(!stamps.judged().exists());
}

#[test]
fn an_offer_an_older_bx_wrote_without_its_lock_is_left_to_the_next_check() {
    let home = guarded_home();
    let (_, second) = pushed_and_moved(&home);
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    stamps
        .write(&stamps.available(), &format!("~/{AT}: y\n"))
        .expect("an older offer");
    locked_elsewhere(&home, &second);
    sync_with(
        &env(home.path()),
        true,
        &mut Vec::new(),
        &git(home.path()),
        &mut never,
    )
    .expect("sync");
    assert_eq!(
        std::fs::read_to_string(stamps.available()).expect("kept"),
        format!("~/{AT}: y\n")
    );
}

#[test]
fn a_stamp_that_cannot_be_written_is_named_once() {
    let home = guarded_home();
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    std::fs::create_dir_all(stamps.available()).expect("a directory where a stamp goes");
    let error = stamps
        .set(0, None, None, Some(&["offered".to_string()]))
        .expect_err("a directory is not written over");
    assert_eq!(
        error.to_string(),
        format!(
            "{} is a directory, not a file bx can write",
            stamps.available().display()
        )
    );
}

#[test]
fn a_stamp_that_cannot_be_removed_says_removing() {
    let home = guarded_home();
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    std::fs::create_dir_all(stamps.ask_due()).expect("a directory where a stamp goes");
    let error = stamps
        .set(0, Some(None), None, None)
        .expect_err("a directory is not removed");
    // `unlink(2)` of a directory is `EISDIR` on Linux and `EPERM` on macOS.
    let refused = std::io::Error::from_raw_os_error(if cfg!(target_os = "linux") {
        rustix::io::Errno::ISDIR.raw_os_error()
    } else {
        rustix::io::Errno::PERM.raw_os_error()
    });
    assert_eq!(
        error.to_string(),
        format!("removing {}: {refused}", stamps.ask_due().display())
    );
}

#[test]
fn a_check_lock_that_cannot_be_opened_says_opening() {
    let home = guarded_home();
    let state = crate::state::StateDir::resolve(home.path());
    let path = state.update().join("check.lock");
    std::fs::create_dir_all(&path).expect("a directory where check.lock goes");
    let error = Stamps::of(&state)
        .try_hold()
        .expect_err("a directory is not opened for writing");
    // `open(2)` of a directory for writing is `EISDIR` on Linux and macOS.
    let refused = std::io::Error::from_raw_os_error(rustix::io::Errno::ISDIR.raw_os_error());
    let expected = format!("opening {}: {refused}", path.display());
    assert_eq!(error.to_string(), expected);
}

/// `ask-due` as [`on_offer`] leaves it: a question already due.
const ASK_DUE: u64 = 1;

/// The offer a check left in `home`'s stamps, as the prompt hook shows it,
/// with the question at [`ASK_DUE`] due alongside it, and its generation.
fn on_offer(home: &GuardedHome) -> (Stamps, String) {
    let stamps = Stamps::of(&crate::state::StateDir::resolve(home.path()));
    let lines = vec![format!("~/{AT}: 1 new commit(s) on master")];
    stamps
        .set(update::now(), None, None, Some(&lines))
        .expect("offered");
    stamps
        .write(&stamps.ask_due(), &format!("{ASK_DUE}\n"))
        .expect("ask-due");
    assert!(offers(&stamps));
    (stamps, update::generation(&lines))
}

/// That `stamps` hold the offer of `generation` answered along with the
/// question that was due with it ([`ASK_DUE`]), `ask-due` an interval from a
/// time in `since..=now`, and `last-check` saying `why`.
fn settled(stamps: &Stamps, generation: &str, since: u64, why: &str) {
    let available = std::fs::read_to_string(stamps.available()).expect("still offered");
    assert!(
        available.starts_with(&format!("gen {generation}\n")),
        "{available}"
    );
    let due = Stamps::read(&stamps.ask_due()).expect("ask-due");
    let week = crate::config::update::DEFAULT_INTERVAL.seconds();
    assert!(
        (since + week..=update::now() + week).contains(&due),
        "{due}"
    );
    assert_eq!(
        std::fs::read_to_string(stamps.answered()).expect("answered"),
        format!("{generation}\nask {ASK_DUE}\n"),
        "the offer, and the question due with it, not the next one, which a shell \
         still asks at {due}"
    );
    assert!(!offers(stamps), "no shell asks it again");
    let last = std::fs::read_to_string(stamps.last_check()).expect("last-check");
    assert!(last.contains(why), "{last}");
}

/// Run `bx update` at a terminal, with every question answered by `answer`.
fn answering(
    home: &GuardedHome,
    answer: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, update::Error> {
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    update_with(&tty, &[], false, &mut Vec::new(), &git(home.path()), answer)
}

#[test]
fn an_update_abandoned_at_its_question_answers_the_offer() {
    let home = guarded_home();
    locked_once(&home);
    publish(&home, &["skills/b/SKILL.md"]);
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
    let exit = answering(&home, &mut || Err(Error::Canceled)).expect("canceled");
    assert_eq!(exit, Exit::Canceled);
    settled(&stamps, &generation, since, "canceled");
}

#[test]
fn an_update_declined_answers_the_offer_rather_than_withdrawing_it() {
    let home = guarded_home();
    let (_, first) = locked_once(&home);
    publish(&home, &["skills/b/SKILL.md"]);
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
    answering(&home, &mut || Ok(false)).expect("declined");
    assert_eq!(locked(&home).as_deref(), Some(first.as_str()));
    settled(&stamps, &generation, since, "declined");
}

#[test]
fn an_update_another_holds_records_nothing() {
    let home = guarded_home();
    following(&home);
    let (stamps, _) = on_offer(&home);
    std::fs::write(stamps.ask_due(), "1\n").expect("due");
    let available = std::fs::read(stamps.available()).expect("offered");
    let _held = stamps.try_hold().expect("hold").expect("free");
    let error = update(&home, true, &mut Vec::new()).expect_err("busy");
    assert!(matches!(error, update::Error::Busy), "{error:?}");
    assert_eq!(
        std::fs::read(stamps.available()).expect("offered"),
        available
    );
    assert!(!stamps.answered().exists(), "the other run settles it");
    assert_eq!(Stamps::read(&stamps.ask_due()), Some(1));
    assert!(!stamps.last_check().exists());
}

#[test]
fn an_update_a_diverged_config_repo_refuses_answers_the_offer_and_says_why() {
    let home = guarded_home();
    let (repo, _) = locked_once(&home);
    run(home.path(), &repo, &["push", "--quiet"]);
    let edited = std::fs::read_to_string(repo.join("bx.lock")).expect("bx.lock");
    std::fs::write(repo.join("bx.lock"), format!("{edited}# mine\n")).expect("an edit");
    commit_all(home.path(), &repo, "mine");
    let other = crate::testing::git::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
    let error = update(&home, true, &mut Vec::new()).expect_err("diverged");
    assert!(
        matches!(error, update::Error::Sync(sync::Error::Diverged { .. })),
        "{error:?}"
    );
    settled(&stamps, &generation, since, &error.to_string());
}

#[test]
fn an_update_both_machines_locked_answers_the_offer_and_says_why() {
    let home = guarded_home();
    let (repo, first) = locked_once(&home);
    run(home.path(), &repo, &["push", "--quiet"]);
    publish(&home, &["skills/b/SKILL.md"]);
    update_unpushed(&home);
    let other = crate::testing::git::other(&home);
    let theirs = std::fs::read_to_string(other.join("bx.lock"))
        .expect("bx.lock")
        .replace(&first, &"d".repeat(40));
    std::fs::write(other.join("bx.lock"), theirs).expect("bx.lock");
    commit_all(home.path(), &other, update::SUBJECT);
    run(home.path(), &other, &["push", "--quiet"]);
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
    let error = update(&home, true, &mut Vec::new()).expect_err("both changed it");
    assert!(
        matches!(error, update::Error::LockDiverged { .. }),
        "{error:?}"
    );
    settled(&stamps, &generation, since, "reset --keep @{upstream}");
}

#[test]
fn an_update_a_rebase_left_open_stops_answers_the_offer_and_says_why() {
    let home = guarded_home();
    let repo = diverged(&home);
    std::fs::create_dir_all(repo.join(".git/rebase-merge")).expect("an open rebase");
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
    let error = update(&home, true, &mut Vec::new()).expect_err("open");
    assert!(matches!(error, update::Error::Rebasing(_)), "{error:?}");
    settled(&stamps, &generation, since, "rebase --abort");
}

#[test]
fn an_update_whose_pull_cannot_reach_the_remote_answers_the_offer_and_says_why() {
    let home = guarded_home();
    locked_once(&home);
    std::fs::rename(home.child("remote.git"), home.child("gone.git")).expect("unreachable");
    let (stamps, generation) = on_offer(&home);
    let since = update::now();
    let error = update(&home, true, &mut Vec::new()).expect_err("unreachable");
    assert!(matches!(error, update::Error::Sync(_)), "{error:?}");
    settled(&stamps, &generation, since, update::STOPPED);
}

#[test]
fn an_update_that_finishes_withdraws_the_offer() {
    let home = guarded_home();
    locked_once(&home);
    publish(&home, &["skills/b/SKILL.md"]);
    let (stamps, _) = on_offer(&home);
    // Why an earlier run stopped, which `bx doctor` names until one finishes.
    std::fs::write(
        stamps.last_check(),
        format!("{}the remote was unreachable\n", update::STOPPED),
    )
    .expect("last-check");
    update(&home, true, &mut Vec::new()).expect("update");
    assert!(!stamps.available().exists());
    assert!(!stamps.answered().exists());
    assert!(!stamps.last_check().exists());
    assert!(!offers(&stamps));
}

#[test]
fn a_reason_that_spans_several_lines_is_written_as_one() {
    let home = guarded_home();
    let state = crate::state::StateDir::resolve(home.path());
    let reason = format!(
        "{}git fetch failed: ssh: connect to host h port 22: refused\n  \
         fatal: Could not read from remote repository.\n\n\
         Please make sure you have the correct access rights\n",
        update::STOPPED
    );
    update::settled(&state, None, &reason).expect("settled");
    assert_eq!(
        std::fs::read_to_string(Stamps::of(&state).last_check()).expect("last-check"),
        format!(
            "{}git fetch failed: ssh: connect to host h port 22: refused fatal: Could not \
             read from remote repository. Please make sure you have the correct access \
             rights\n",
            update::STOPPED
        ),
        "one line, so `bx doctor`, which names the line, names all of it"
    );
}

#[test]
fn a_settled_offer_an_older_bx_wrote_is_answered_by_its_first_line() {
    let home = guarded_home();
    let state = crate::state::StateDir::resolve(home.path());
    let stamps = Stamps::of(&state);
    update::settled(&state, None, "why").expect("nothing offered");
    assert!(!stamps.answered().exists(), "nothing to answer");
    assert_eq!(
        std::fs::read_to_string(stamps.last_check()).expect("last-check"),
        "why\n"
    );
    stamps
        .write(&stamps.available(), "~/x: y\n")
        .expect("offered");
    update::settled(&state, None, "why").expect("settled");
    assert_eq!(
        std::fs::read_to_string(stamps.answered()).expect("answered"),
        "old:~/x: y\nask \n"
    );
    assert!(!offers(&stamps));
}
