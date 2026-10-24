//! `bx upgrade`: all of `bx update`'s work, and each pinned external moved to
//! its newest release by rewriting the `rev` that pins it.

use super::update_command::{AT, layer, publish, upstream};
use super::*;
use crate::sync::tests::{cloned, commit_all, git, rev, run};
use crate::testing::{GuardedHome, mode_of};

/// Where the pinned external is checked out, relative to the home.
const PINNED: &str = ".local/share/pinned";

/// The pinned external, at `rev`, from the same upstream as [`layer`].
fn pinned(rev: &str) -> String {
    format!(
        "[[external]]\npath = \"~/{PINNED}\"\nurl = \"https://example.invalid/upstream\"\n\
         rev = \"{rev}\" # pinned by hand\n"
    )
}

/// Tag the upstream's `master` as `tag`, annotated when `annotated`.
fn tag(home: &GuardedHome, tag: &str, annotated: bool) {
    let dir = home.child("upstream");
    if annotated {
        run(home.path(), &dir, &["tag", "-a", tag, "-m", tag]);
    } else {
        run(home.path(), &dir, &["tag", tag]);
    }
}

/// A binary check that finds bx up to date.
fn current(out: &mut dyn Write) -> Result<Exit, upgrade::Error> {
    writeln!(out, "bx v0.0.0 is the latest release.").map_err(upgrade::Error::Output)?;
    Ok(Exit::Converged)
}

/// A binary check that cannot look.
fn unchecked(_: &mut dyn Write) -> Result<Exit, upgrade::Error> {
    Err(upgrade::Error::NoFetcher)
}

fn upgrade(
    home: &GuardedHome,
    names: &[String],
    mode: Upgrading,
    out: &mut Vec<u8>,
) -> Result<Exit, update::Error> {
    upgrade_with(
        &env(home.path()),
        names,
        mode,
        out,
        &git(home.path()),
        &mut never,
        &mut current,
    )
}

/// A config repo following [`layer`] and pinning [`pinned`] at the upstream's
/// first commit, tagged `v1.0.0`; a first upgrade locks the follow and clones
/// both, and the upstream then gains a commit tagged `v1.1.0`, annotated.
/// Returns the config repo, the first commit and the second.
fn released(home: &GuardedHome) -> (std::path::PathBuf, String, String) {
    let first = upstream(home, &["skills/a/SKILL.md"]);
    tag(home, "v1.0.0", false);
    let repo = cloned(home, &format!("{}{}", layer(), pinned(&first)));
    let mut out = Vec::new();
    let exit =
        upgrade(home, &[], Upgrading::Upgrade { yes: true }, &mut out).expect("the first upgrade");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).contains(&format!(
            "~/{PINNED}: pinned at v1.0.0, the newest release\n"
        )),
        "{}",
        text(&out)
    );
    let second = publish(home, &["skills/b/SKILL.md"]);
    tag(home, "v1.1.0", true);
    (repo, first, second)
}

fn subjects(home: &GuardedHome, repo: &Path, count: usize) -> Vec<String> {
    run(
        home.path(),
        repo,
        &["log", &format!("-{count}"), "--format=%s"],
    )
    .lines()
    .map(str::to_string)
    .collect()
}

#[test]
fn an_upgrade_moves_the_follow_and_the_pin_in_two_commits_then_finds_nothing() {
    let home = guarded_home();
    let (repo, first, second) = released(&home);

    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut out).expect("upgrade");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    let said = text(&out);
    assert!(
        said.contains(&format!(
            "~/{PINNED}: v1.0.0 -> v1.1.0, 1 new commit(s), {} -> {}\n",
            &first[..12],
            &second[..12]
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!(
            "-rev = \"{first}\" # pinned by hand\n+rev = \"{second}\" # pinned by hand\n"
        )),
        "the layer's rewrite is shown: {said}"
    );
    assert!(
        said.contains("Pushed 2 commit(s) to origin/master.\n"),
        "{said}"
    );
    assert!(
        said.ends_with("bx v0.0.0 is the latest release.\n"),
        "{said}"
    );
    assert_eq!(
        subjects(&home, &repo, 2),
        [pin::SUBJECT, update::SUBJECT],
        "the lock's commit, then the pins'"
    );
    assert_eq!(
        run(home.path(), &repo, &["log", "-1", "--format=%b"]),
        format!(
            "~/{PINNED}: v1.0.0 -> v1.1.0 ({} -> {})",
            &first[..12],
            &second[..12]
        )
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("bx.toml")).expect("bx.toml"),
        format!("{}{}", layer(), pinned(&second)),
        "only the rev changed"
    );
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), second);
    assert_eq!(rev(home.path(), &home.child(AT), "HEAD"), second);
    assert_eq!(run(home.path(), &repo, &["status", "--porcelain"]), "");

    let head = rev(home.path(), &repo, "HEAD");
    let mut again = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut again)
        .expect("a second upgrade");
    assert_eq!(exit, Exit::Converged, "{}", text(&again));
    assert!(
        text(&again).contains(&format!(
            "~/{PINNED}: pinned at v1.1.0, the newest release\n"
        )),
        "{}",
        text(&again)
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing to commit");
    let mut plan = Vec::new();
    assert_eq!(
        show(&env(home.path()), View::Plan, &mut plan).expect("plan"),
        Exit::Converged,
        "{}",
        text(&plan)
    );
}

#[test]
fn a_check_moves_nothing_and_exits_by_the_worst_it_found() {
    let home = guarded_home();
    let (repo, first, _) = released(&home);
    let head = rev(home.path(), &repo, "HEAD");

    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Check, &mut out).expect("check");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains(&format!("~/{PINNED}: v1.0.0 -> v1.1.0")),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).contains(&format!("~/{AT}: 1 new commit(s) on master")),
        "the follow is checked as bx update --check checks it: {}",
        text(&out)
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head);
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), first);
    assert!(
        std::fs::read_to_string(repo.join("bx.toml"))
            .expect("bx.toml")
            .contains(&first)
    );

    // Something newer outranks a binary that could not be checked.
    let names = [format!("~/{PINNED}")];
    let mut named = Vec::new();
    let exit = upgrade_with(
        &env(home.path()),
        &names,
        Upgrading::Check,
        &mut named,
        &git(home.path()),
        &mut never,
        &mut unchecked,
    )
    .expect("check");
    assert_eq!(exit, Exit::Pending, "{}", text(&named));
    assert!(
        !text(&named).contains(AT),
        "a pinned name looks at no follow: {}",
        text(&named)
    );
    assert!(text(&named).ends_with("bx itself: not checked: neither curl nor wget is on PATH; one is needed to fetch the installer\n"), "{}", text(&named));

    upgrade(
        &home,
        &[],
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect("upgrade");
    let mut current = Vec::new();
    assert_eq!(
        upgrade(&home, &[], Upgrading::Check, &mut current).expect("check"),
        Exit::Converged,
        "{}",
        text(&current)
    );
    let mut blind = Vec::new();
    let exit = upgrade_with(
        &env(home.path()),
        &[],
        Upgrading::Check,
        &mut blind,
        &git(home.path()),
        &mut never,
        &mut unchecked,
    )
    .expect("check");
    assert_eq!(
        exit,
        Exit::Error,
        "could not look is not up to date: {}",
        text(&blind)
    );
}

#[test]
fn a_pin_whose_remote_cannot_be_asked_is_an_error_to_a_check() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    let gone = pinned(&first).replace("invalid/upstream", "invalid/gone");
    cloned(&home, &gone);

    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Check, &mut out).expect("check");
    assert_eq!(exit, Exit::Error, "{}", text(&out));
    assert!(
        text(&out).contains(&format!("~/{PINNED}: not checked: ")),
        "{}",
        text(&out)
    );
    assert!(!text(&out).contains("follows a branch"), "{}", text(&out));
}

#[test]
fn an_upgrade_with_no_upstream_names_itself_and_rewrites_the_pin() {
    let home = guarded_home();
    let (repo, _, second) = released(&home);
    run(home.path(), &repo, &["branch", "--unset-upstream"]);

    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut out).expect("upgrade");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with(
            "The config repo's master has no upstream, so there is nothing to pull; bx upgrade \
             locks on top of it as it stands.\n"
        ),
        "{}",
        text(&out)
    );
    assert_eq!(subjects(&home, &repo, 1), [pin::SUBJECT]);
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), second);
}

#[test]
fn an_interrupted_apply_is_recovered_and_nothing_is_upgraded_under_its_approval() {
    use crate::journal::{Session, SessionKind};

    let home = guarded_home();
    let (repo, first, _) = released(&home);
    let head = rev(home.path(), &repo, "HEAD");
    let state = crate::state::StateDir::resolve(home.path());
    drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));

    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut out)
        .expect("the recovering upgrade");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains(
            "Nothing was locked: an interrupted apply had to be dealt with first. Run bx \
             upgrade again."
        ),
        "{}",
        text(&out)
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing committed");
    assert!(
        std::fs::read_to_string(repo.join("bx.toml"))
            .expect("bx.toml")
            .contains(&first)
    );
    assert_eq!(
        std::fs::read_to_string(update::Stamps::of(&state).last_check()).expect("last-check"),
        "bx upgrade dealt with an interrupted apply first, and locked or upgraded nothing\n"
    );
}

#[test]
fn an_untagged_pin_past_the_newest_release_has_nothing_newer() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    tag(&home, "v1.0.0", false);
    let second = publish(&home, &["skills/b/SKILL.md"]);
    cloned(&home, &pinned(&second));
    let names = [format!("~/{PINNED}")];
    upgrade(
        &home,
        &names,
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect("clones it");

    let mut out = Vec::new();
    let exit = upgrade(&home, &names, Upgrading::Check, &mut out).expect("check");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).contains(&format!(
            "~/{PINNED}: pinned at {}; nothing newer is released\n",
            &second[..12]
        )),
        "{}",
        text(&out)
    );
}

#[test]
fn a_pin_past_the_default_branch_with_no_release_has_nothing_newer() {
    let home = guarded_home();
    upstream(&home, &["skills/a/SKILL.md"]);
    let dir = home.child("upstream");
    run(home.path(), &dir, &["checkout", "--quiet", "-b", "ahead"]);
    let ahead = publish(&home, &["skills/b/SKILL.md"]);
    run(home.path(), &dir, &["checkout", "--quiet", "master"]);
    cloned(&home, &pinned(&ahead));
    let names = [format!("~/{PINNED}")];
    upgrade(
        &home,
        &names,
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect("clones it");

    let mut out = Vec::new();
    let exit = upgrade(&home, &names, Upgrading::Check, &mut out).expect("check");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).contains(&format!(
            "~/{PINNED}: pinned at {}; nothing newer is released\n",
            &ahead[..12]
        )),
        "{}",
        text(&out)
    );
}

#[test]
fn a_pin_subject_on_a_commit_that_touches_no_layer_is_not_replayed() {
    let home = guarded_home();
    let (repo, _, _) = released(&home);
    std::fs::write(repo.join("notes"), "mine\n").expect("a note");
    commit_all(home.path(), &repo, pin::SUBJECT);
    let other = crate::sync::tests::other(&home);
    std::fs::write(other.join("theirs"), "x\n").expect("a file");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);
    let head = rev(home.path(), &repo, "HEAD");

    let error = upgrade(
        &home,
        &[],
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect_err("diverged");
    assert!(
        matches!(error, update::Error::Sync(sync::Error::Diverged { .. })),
        "{error:?}"
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing moved");
}

#[test]
fn a_declined_upgrade_rewrites_and_commits_nothing() {
    let home = guarded_home();
    let (repo, first, _) = released(&home);
    let head = rev(home.path(), &repo, "HEAD");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };

    let mut out = Vec::new();
    let exit = upgrade_with(
        &tty,
        &[],
        Upgrading::Upgrade { yes: false },
        &mut out,
        &git(home.path()),
        &mut || Ok(false),
        &mut current,
    )
    .expect("declined");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert_eq!(rev(home.path(), &repo, "HEAD"), head);
    assert!(
        std::fs::read_to_string(repo.join("bx.toml"))
            .expect("bx.toml")
            .contains(&first)
    );
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), first);
    let state = crate::state::StateDir::resolve(home.path());
    assert_eq!(
        std::fs::read_to_string(update::Stamps::of(&state).last_check()).expect("last-check"),
        "bx upgrade was declined, and locked or upgraded nothing\n"
    );
}

#[test]
fn a_layer_with_uncommitted_changes_is_refused_before_anything_moves() {
    let home = guarded_home();
    let (repo, first, _) = released(&home);
    let layer_file = repo.join("bx.toml");
    let edited = format!(
        "{}# mine\n",
        std::fs::read_to_string(&layer_file).expect("bx.toml")
    );
    std::fs::write(&layer_file, &edited).expect("an edit");

    let error = upgrade(
        &home,
        &[],
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect_err("refused");
    assert!(
        matches!(&error, update::Error::LayerEdited(file) if *file == layer_file),
        "{error}"
    );
    assert_eq!(
        std::fs::read_to_string(&layer_file).expect("bx.toml"),
        edited
    );
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), first);
}

#[test]
fn a_pin_commit_git_refuses_puts_the_layer_back_and_moves_no_checkout() {
    let home = guarded_home();
    let (repo, first, _) = released(&home);
    let hook = repo.join(".git/hooks/commit-msg");
    std::fs::write(
        &hook,
        "#!/bin/sh\ngrep -q 'upgrade pinned' \"$1\" && exit 1\nexit 0\n",
    )
    .expect("a hook");
    crate::fs::set_mode(&hook, crate::fs::Mode::from_bits(0o755)).expect("executable");
    let layer = std::fs::read_to_string(repo.join("bx.toml")).expect("bx.toml");
    let shared = crate::fs::Mode::from_bits(0o664);
    crate::fs::set_mode(&repo.join("bx.toml"), shared).expect("a group-writable layer");

    let error = upgrade(
        &home,
        &[],
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect_err("refused");
    assert!(matches!(error, update::Error::Sync(_)), "{error}");
    assert_eq!(
        std::fs::read_to_string(repo.join("bx.toml")).expect("bx.toml"),
        layer
    );
    assert_eq!(
        mode_of(&repo.join("bx.toml")),
        shared.bits(),
        "put back as it was"
    );
    assert_eq!(run(home.path(), &repo, &["status", "--porcelain"]), "");
    assert_eq!(
        subjects(&home, &repo, 1),
        [update::SUBJECT],
        "the lock's commit stands"
    );
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), first);

    std::fs::remove_file(&hook).expect("the hook");
    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut out).expect("upgrade");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(text(&out).contains("Pushed 2 commit(s)"), "{}", text(&out));
    assert_eq!(
        mode_of(&repo.join("bx.toml")),
        shared.bits(),
        "rewritten as it was"
    );
}

#[test]
fn a_layer_edited_while_the_question_waits_is_kept_and_nothing_moves() {
    let home = guarded_home();
    let (repo, first, _) = released(&home);
    let layer_file = repo.join("bx.toml");
    let head = rev(home.path(), &repo, "HEAD");
    let tty = Env {
        stdin_tty: true,
        ..env(home.path())
    };
    let mut edited = String::new();
    let mut ask = || {
        edited = format!(
            "{}# mine\n",
            std::fs::read_to_string(&layer_file).expect("bx.toml")
        );
        std::fs::write(&layer_file, &edited).expect("an edit");
        Ok(true)
    };

    let error = upgrade_with(
        &tty,
        &[],
        Upgrading::Upgrade { yes: false },
        &mut Vec::new(),
        &git(home.path()),
        &mut ask,
        &mut current,
    )
    .expect_err("refused");
    assert!(
        matches!(&error, update::Error::LayerEdited(file) if *file == layer_file),
        "{error}"
    );
    assert_eq!(
        std::fs::read_to_string(&layer_file).expect("bx.toml"),
        edited
    );
    assert_eq!(
        subjects(&home, &repo, 1),
        [update::SUBJECT],
        "the lock's commit, and no pin commit"
    );
    assert_ne!(rev(home.path(), &repo, "HEAD"), head);
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), first);
}

#[test]
fn a_pin_commit_whose_push_was_refused_is_replayed_over_another_machines_push() {
    let home = guarded_home();
    let (repo, _, second) = released(&home);
    let hook = repo.join(".git/hooks/pre-push");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").expect("a hook");
    crate::fs::set_mode(&hook, crate::fs::Mode::from_bits(0o755)).expect("executable");
    let mut refused = Vec::new();
    upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut refused).expect("upgrade");
    assert!(text(&refused).contains("was refused"), "{}", text(&refused));
    std::fs::remove_file(&hook).expect("the hook");
    let other = crate::sync::tests::other(&home);
    std::fs::write(other.join("notes"), "x\n").expect("a note");
    commit_all(home.path(), &other, "elsewhere");
    run(home.path(), &other, &["push", "--quiet"]);

    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut out).expect("replayed");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).starts_with("Replayed 2 unpushed bx update commit(s)"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("Pushed 2 commit(s)"), "{}", text(&out));
    assert_eq!(
        rev(home.path(), &home.child("remote.git"), "master"),
        rev(home.path(), &repo, "HEAD")
    );
    assert!(repo.join("notes").is_file());
    assert!(
        std::fs::read_to_string(repo.join("bx.toml"))
            .expect("bx.toml")
            .contains(&second)
    );
}

#[test]
fn a_pin_local_toml_declares_is_rewritten_there_and_never_committed() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    tag(&home, "v1.0.0", false);
    let repo = cloned(&home, &layer());
    let local = crate::state::StateDir::resolve(home.path()).local_toml();
    std::fs::create_dir_all(local.parent().expect("the state dir")).expect("the state dir");
    std::fs::write(&local, pinned(&first)).expect("local.toml");
    crate::fs::set_mode(&local, crate::fs::Mode::PRIVATE_FILE).expect("as `bx init` writes it");
    let second = publish(&home, &["skills/b/SKILL.md"]);
    tag(&home, "2.0.0", false);

    // With no checkout yet, nothing shows the release descends from the pin:
    // the first run clones at the pin, and offers nothing.
    let mut cloning = Vec::new();
    let exit =
        upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut cloning).expect("upgrade");
    assert_eq!(exit, Exit::Pending, "{}", text(&cloning));
    assert!(
        text(&cloning).contains(&format!(
            "~/{PINNED}: 2.0.0 is at {}, and with no checkout of bx's there is nothing to show \
             it descends from {}",
            &second[..12],
            &first[..12]
        )),
        "{}",
        text(&cloning)
    );
    assert_eq!(
        std::fs::read_to_string(&local).expect("local.toml"),
        pinned(&first)
    );
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), first);

    let mut out = Vec::new();
    let exit = upgrade(&home, &[], Upgrading::Upgrade { yes: true }, &mut out).expect("upgrade");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert!(
        text(&out).contains(&format!("~/{PINNED}: v1.0.0 -> 2.0.0, 1 new commit(s)")),
        "{}",
        text(&out)
    );
    assert_eq!(
        std::fs::read_to_string(&local).expect("local.toml"),
        pinned(&second)
    );
    assert_eq!(mode_of(&local), crate::fs::Mode::PRIVATE_FILE.bits());
    assert_eq!(
        subjects(&home, &repo, 1),
        [update::SUBJECT],
        "no pin commit"
    );
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), second);
}

#[test]
fn a_name_that_is_no_external_is_refused_and_update_still_refuses_a_pin() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    cloned(&home, &format!("{}{}", layer(), pinned(&first)));

    let error = upgrade(
        &home,
        &["~/nowhere".to_string()],
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect_err("refused");
    assert!(
        matches!(&error, update::Error::NotExternal(name) if name == "~/nowhere"),
        "{error}"
    );
    let error = update_with(
        &env(home.path()),
        &[format!("~/{PINNED}")],
        true,
        &mut Vec::new(),
        &git(home.path()),
        &mut never,
    )
    .expect_err("refused");
    assert!(matches!(error, update::Error::NotFollowed(_)), "{error}");
}

#[test]
fn with_no_release_the_default_branch_moves_a_pin_only_forward() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    let repo = cloned(&home, &pinned(&first));
    let names = [format!("~/{PINNED}")];
    let mut out = Vec::new();
    upgrade(&home, &names, Upgrading::Upgrade { yes: true }, &mut out).expect("clones it");
    assert!(
        text(&out).contains(&format!(
            "~/{PINNED}: pinned at {}; nothing newer",
            &first[..12]
        )),
        "{}",
        text(&out)
    );

    let second = publish(&home, &["skills/b/SKILL.md"]);
    let mut moved = Vec::new();
    upgrade(&home, &names, Upgrading::Upgrade { yes: true }, &mut moved).expect("upgrade");
    assert!(
        text(&moved).contains(&format!(
            "~/{PINNED}: no release; the default branch moved, 1 new commit(s), {} -> {}",
            &first[..12],
            &second[..12]
        )),
        "{}",
        text(&moved)
    );
    assert!(
        std::fs::read_to_string(repo.join("bx.toml"))
            .expect("bx.toml")
            .contains(&second)
    );

    // Rewritten past the pin: not offered.
    let dir = home.child("upstream");
    run(
        home.path(),
        &dir,
        &["checkout", "--quiet", "--orphan", "fresh"],
    );
    commit_all(home.path(), &dir, "fresh");
    run(
        home.path(),
        &dir,
        &["branch", "--quiet", "-M", "fresh", "master"],
    );
    let head = rev(home.path(), &repo, "HEAD");
    let mut rewritten = Vec::new();
    let exit = upgrade(
        &home,
        &names,
        Upgrading::Upgrade { yes: true },
        &mut rewritten,
    )
    .expect("upgrade");
    assert_eq!(exit, Exit::Pending, "{}", text(&rewritten));
    assert!(
        text(&rewritten).contains("does not descend from"),
        "{}",
        text(&rewritten)
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing committed");
}

#[test]
fn a_newer_release_off_the_pinned_line_is_said_and_not_offered() {
    let home = guarded_home();
    let first = upstream(&home, &["skills/a/SKILL.md"]);
    tag(&home, "v1.0.0", false);
    let repo = cloned(&home, &pinned(&first));
    let names = [format!("~/{PINNED}")];
    upgrade(
        &home,
        &names,
        Upgrading::Upgrade { yes: true },
        &mut Vec::new(),
    )
    .expect("clones it");
    let dir = home.child("upstream");
    run(
        home.path(),
        &dir,
        &["checkout", "--quiet", "--orphan", "two"],
    );
    commit_all(home.path(), &dir, "two");
    tag(&home, "v2.0.0", true);
    // Neither a pre-release nor a name that is no version is a release.
    run(home.path(), &dir, &["tag", "v3.0.0-rc.1"]);
    run(home.path(), &dir, &["tag", "latest"]);
    let two = rev(home.path(), &dir, "HEAD");

    let head = rev(home.path(), &repo, "HEAD");

    let mut out = Vec::new();
    let exit = upgrade(&home, &names, Upgrading::Upgrade { yes: true }, &mut out).expect("upgrade");
    assert_eq!(exit, Exit::Pending, "{}", text(&out));
    assert!(
        text(&out).contains(&format!(
            "~/{PINNED}: the newest release, v2.0.0, is at {}, which does not descend from {}; \
             bx moves a checkout only forward, so it is not upgraded\n",
            &two[..12],
            &first[..12]
        )),
        "{}",
        text(&out)
    );
    assert_eq!(rev(home.path(), &repo, "HEAD"), head, "nothing committed");
    assert_eq!(rev(home.path(), &home.child(PINNED), "HEAD"), first);
}
