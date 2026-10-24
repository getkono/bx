use super::*;
use crate::config::Origin;
use crate::config::external::{Follow, Pin};
use crate::config::lock::unshared_remedy;
use crate::testing::guarded_home;

const A: &str = "0e810e5afa27acbd074398eefbe28d13005dbc15";
const B: &str = "85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5";

use crate::testing::example_home as home;

fn portable(raw: &str) -> Portable {
    Portable::parse_in(raw, home()).unwrap()
}

fn followed(path: &str, check: Check) -> External {
    External {
        path: portable(path),
        url: format!("https://h/o/{}", &path[2..]),
        pin: Pin::Follow(Follow {
            branch: "main".to_string(),
            check,
        }),
        links: Vec::new(),
        enabled: true,
        origin: Origin::unknown(Path::new("bx.toml")),
    }
}

fn pinned(path: &str) -> External {
    External {
        pin: Pin::Rev(A.to_string()),
        ..followed(path, Check::Ask)
    }
}

fn found(path: &str, locked: Option<&str>, verdict: Verdict) -> Found {
    Found {
        path: portable(path),
        url: format!("https://h/o/{}", &path[2..]),
        branch: "main".to_string(),
        locked: locked.map(str::to_string),
        verdict,
    }
}

fn moves(tip: &str) -> Verdict {
    Verdict::Moves {
        tip: tip.to_string(),
        log: None,
        count: None,
    }
}

#[test]
fn a_layer_is_bx_toml_or_a_toml_directly_in_modules() {
    for (path, layer) in [
        ("bx.toml", true),
        ("modules/a.toml", true),
        ("modules/a/b.toml", false),
        ("modules/a.txt", false),
        ("modulesa.toml", false),
        ("other/bx.toml", false),
        ("bx.lock", false),
    ] {
        assert_eq!(is_layer(path), layer, "{path}");
    }
}

#[test]
fn select_takes_every_followed_external_or_the_ones_named() {
    let externals = [
        followed("~/a", Check::Ask),
        pinned("~/p"),
        followed("~/b", Check::Ask),
    ];
    let all: Vec<&str> = select(&externals, &[], home())
        .unwrap()
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(all, ["~/a", "~/b"], "pinned ones are not updated");

    let named = select(
        &externals,
        &[
            "/var/home/example/b".to_string(),
            "~/b".to_string(),
            "~/./a".to_string(),
        ],
        home(),
    )
    .unwrap();
    let named: Vec<&str> = named.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(named, ["~/b", "~/a"], "in the order named, once each");

    for name in ["~/p", "~/nowhere", "relative"] {
        assert!(
            matches!(
                select(&externals, &[name.to_string()], home()),
                Err(Error::NotFollowed(n)) if n == name
            ),
            "{name}"
        );
    }
}

#[test]
fn proposed_sets_each_move_and_drops_what_nothing_follows() {
    let mut lock = Lock::default();
    let entry = |rev: &str| Locked {
        url: "https://h/o/a".to_string(),
        branch: "main".to_string(),
        rev: rev.to_string(),
    };
    lock.set(portable("~/a"), entry(A));
    lock.set(portable("~/gone"), entry(A));
    lock.set(portable("~/p"), entry(A));
    let externals = [
        followed("~/a", Check::Ask),
        pinned("~/p"),
        followed("~/c", Check::Ask),
    ];
    let next = proposed(
        &lock,
        &[
            found("~/a", Some(A), moves(B)),
            found("~/c", None, Verdict::Unreachable("offline".to_string())),
        ],
        &externals,
        Some(&externals),
    );
    assert_eq!(next.get(&portable("~/a")).unwrap().rev, B);
    assert!(
        next.get(&portable("~/c")).is_none(),
        "nothing found, nothing locked"
    );
    assert!(next.get(&portable("~/gone")).is_none());
    assert!(
        next.get(&portable("~/p")).is_none(),
        "a pinned external has no entry"
    );
    assert_eq!(
        proposed(
            &lock,
            &[found("~/a", Some(A), Verdict::Current)],
            &externals[..1],
            Some(&externals[..1])
        ),
        {
            let mut kept = Lock::default();
            kept.set(portable("~/a"), entry(A));
            kept
        }
    );
}

#[test]
fn proposed_keeps_what_the_committed_configuration_follows() {
    let mut lock = Lock::default();
    let entry = |path: &str| Locked {
        url: format!("https://h/o/{}", &path[2..]),
        branch: "main".to_string(),
        rev: A.to_string(),
    };
    for path in ["~/off", "~/moved", "~/gone"] {
        lock.set(portable(path), entry(path));
    }
    // This account switched `~/off` off and points `~/moved` at another
    // branch in its `local.toml`; the committed layers follow both.
    let mut moved = followed("~/moved", Check::Ask);
    moved.pin = Pin::Follow(Follow {
        branch: "mine".to_string(),
        check: Check::Ask,
    });
    let externals = [moved];
    let committed = [
        followed("~/off", Check::Ask),
        followed("~/moved", Check::Ask),
    ];
    let away = Found {
        branch: "mine".to_string(),
        ..found("~/moved", None, moves(B))
    };
    assert!(unshared(&away, Some(&committed)));
    assert!(!unshared(&away, None));
    assert!(!unshared(
        &found("~/moved", Some(A), moves(B)),
        Some(&committed)
    ));
    let elsewhere = Found {
        url: "https://h/o/elsewhere".to_string(),
        ..found("~/moved", None, moves(B))
    };
    assert!(unshared(&elsewhere, Some(&committed)));

    let next = proposed(
        &lock,
        std::slice::from_ref(&away),
        &externals,
        Some(&committed),
    );
    assert_eq!(next.get(&portable("~/off")), Some(&entry("~/off")));
    assert_eq!(
        next.get(&portable("~/moved")),
        Some(&entry("~/moved")),
        "the committed one's commit stands"
    );
    assert!(next.get(&portable("~/gone")).is_none());

    // With the committed layers unknown, nothing is dropped.
    let next = proposed(&lock, &[], &[], None);
    assert_eq!(next, lock);
    let next = proposed(&lock, &[away], &externals, None);
    assert_eq!(next.get(&portable("~/moved")).unwrap().branch, "mine");
}

#[test]
fn proposed_never_locks_a_follow_only_local_toml_declares() {
    // `~/mine` is followed by this account's `local.toml` alone; the
    // committed layers follow `~/shared`.
    let externals = [
        followed("~/shared", Check::Ask),
        followed("~/mine", Check::Ask),
    ];
    let committed = [followed("~/shared", Check::Ask)];
    let first = [
        found("~/shared", None, moves(A)),
        found("~/mine", None, moves(A)),
    ];
    assert!(unshared(&first[1], Some(&committed)));
    let next = proposed(&Lock::default(), &first, &externals, Some(&committed));
    assert_eq!(next.get(&portable("~/shared")).unwrap().rev, A);
    assert!(
        next.get(&portable("~/mine")).is_none(),
        "the shared lock holds only what the committed configuration follows"
    );

    // Another machine, whose configuration is the committed one alone,
    // proposes the same lock, so the two never take turns.
    let elsewhere = proposed(
        &next,
        &[found("~/shared", Some(A), Verdict::Current)],
        &committed,
        Some(&committed),
    );
    assert_eq!(elsewhere, next);
}

#[test]
fn the_unshared_remedy_says_why_the_shared_lock_does_not_take_the_follow() {
    let mine = followed("~/mine", Check::Ask);
    let mut elsewhere = followed("~/mine", Check::Ask);
    elsewhere.pin = Pin::Follow(Follow {
        branch: "other".to_string(),
        check: Check::Ask,
    });
    assert_eq!(unshared_remedy(&pinned("~/mine"), Some(&[])), None, "a pin");
    assert_eq!(
        unshared_remedy(&mine, Some(std::slice::from_ref(&mine))),
        None,
        "a follow the committed configuration declares"
    );
    assert_eq!(unshared_remedy(&mine, None), None, "committed unknown");
    assert_eq!(
        unshared_remedy(&mine, Some(&[])),
        Some(Unshared::NotCommitted)
    );
    assert_eq!(
        unshared_remedy(&mine, Some(std::slice::from_ref(&elsewhere))),
        Some(Unshared::Elsewhere)
    );
    let looked = found("~/mine", Some(A), Verdict::Current);
    assert_eq!(why_unshared(&looked, None), None, "committed unknown");
    assert_eq!(
        why_unshared(&looked, Some(std::slice::from_ref(&mine))),
        None,
        "a follow the committed configuration declares"
    );
    assert_eq!(
        why_unshared(&looked, Some(&[])),
        Some(Unshared::NotCommitted)
    );
    assert_eq!(
        why_unshared(&looked, Some(&[elsewhere])),
        Some(Unshared::Elsewhere)
    );
}

#[test]
fn the_message_names_what_moved_by_path_and_nothing_else() {
    let entry = |rev: &str| Locked {
        url: "https://h/o/a".to_string(),
        branch: "main".to_string(),
        rev: rev.to_string(),
    };
    let mut before = Lock::default();
    before.set(portable("~/a"), entry(A));
    before.set(portable("~/b"), entry(A));
    before.set(portable("~/z"), entry(A));
    let mut after = Lock::default();
    after.set(portable("~/a"), entry(B));
    after.set(portable("~/b"), entry(A));
    after.set(portable("~/new"), entry(B));
    assert_eq!(
        message(&before, &after),
        "chore(bx): update bx.lock\n\n\
             ~/a: main 0e810e5afa27 -> 85919cd1ffa7\n\
             ~/new: main at 85919cd1ffa7\n\
             ~/z: no longer followed\n"
    );
}

#[test]
fn a_summary_says_what_was_found_in_one_line() {
    let cases = [
        (
            found("~/a", Some(A), Verdict::Current),
            "~/a: up to date with main",
        ),
        (
            found("~/a", None, moves(B)),
            "~/a: locks main at 85919cd1ffa7",
        ),
        (
            found(
                "~/a",
                Some(A),
                Verdict::Moves {
                    tip: B.to_string(),
                    log: Some(Vec::new()),
                    count: Some(3),
                },
            ),
            "~/a: 3 new commit(s) on main, 0e810e5afa27 -> 85919cd1ffa7",
        ),
        (
            found("~/a", Some(A), moves(B)),
            "~/a: main moved, 0e810e5afa27 -> 85919cd1ffa7",
        ),
        (
            found("~/a", Some(A), Verdict::Rewritten { tip: B.to_string() }),
            "~/a: main was rewritten; its tip 85919cd1ffa7 does not descend from 0e810e5afa27",
        ),
        (
            found("~/a", None, Verdict::Unreachable("no route".to_string())),
            "~/a: not checked: no route",
        ),
    ];
    for (found, says) in cases {
        assert!(found.summary().starts_with(says), "{}", found.summary());
        assert!(!found.summary().contains('\n'));
    }
    assert_eq!(found("~/a", None, moves(B)).moves_to(), Some(B));
    assert_eq!(found("~/a", Some(A), Verdict::Current).moves_to(), None);
}

#[test]
fn a_check_replaces_only_the_lines_of_what_it_looked_at() {
    let previous = "~/a: 1 new commit(s) on main\n~/b: 2 new commit(s) on main\n";
    let looked = [
        found("~/a", Some(A), Verdict::Current),
        found("~/c", None, moves(B)),
    ];
    assert_eq!(
        offered(previous, &looked),
        [
            "~/b: 2 new commit(s) on main".to_string(),
            "~/c: locks main at 85919cd1ffa7".to_string(),
        ]
    );
    assert!(offered("", &[]).is_empty());
    assert_eq!(
        offered(&format!("gen 0123456789abcdef\n{previous}"), &looked),
        offered(previous, &looked),
        "the generation is not something offered"
    );
    let offline = [found(
        "~/b",
        Some(A),
        Verdict::Unreachable("no route".to_string()),
    )];
    assert_eq!(
        offered(previous, &offline),
        [
            "~/a: 1 new commit(s) on main".to_string(),
            "~/b: 2 new commit(s) on main".to_string(),
        ],
        "a remote not reached withdraws nothing"
    );
}

#[test]
fn the_check_interval_is_the_shortest_auto_one() {
    let week = Interval::parse("7d").unwrap();
    let day = Interval::parse("1d").unwrap();
    assert_eq!(check_interval(&[followed("~/a", Check::Ask)], week), None);
    assert_eq!(
        check_interval(
            &[
                followed("~/a", Check::Auto(None)),
                followed("~/b", Check::Auto(Some(day))),
                pinned("~/p"),
            ],
            week
        ),
        Some(day)
    );
    assert_eq!(
        check_interval(&[followed("~/a", Check::Auto(None))], week),
        Some(week)
    );
}

#[test]
fn stamps_are_written_whole_read_back_and_removed() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let stamps = Stamps::of(&state);
    let day = Interval::parse("1d").unwrap();
    assert_eq!(Stamps::read(&stamps.ask_due()), None, "absent is never due");

    stamps
        .set(
            1000,
            Some(Some(day)),
            Some(Some(day)),
            Some(&["~/a: x".to_string()]),
        )
        .unwrap();
    assert_eq!(Stamps::read(&stamps.ask_due()), Some(1000 + 86_400));
    assert_eq!(Stamps::read(&stamps.check_due()), Some(1000 + 86_400));
    assert_eq!(
        std::fs::read_to_string(stamps.available()).unwrap(),
        "gen 8323ea2e82044071\n~/a: x\n",
        "the generation first, then what is offered"
    );
    assert!(stamps.waiting().is_dir(), "made beside the offer");
    let mode = std::fs::metadata(stamps.ask_due()).unwrap();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
        0o600
    );

    std::fs::write(stamps.answered(), "8323ea2e82044071\n").unwrap();
    stamps
        .set(1500, None, None, Some(&["~/a: x".to_string()]))
        .unwrap();
    assert!(
        stamps.answered().exists(),
        "an offer written again keeps its answer"
    );
    stamps.set(2000, None, Some(None), Some(&[])).unwrap();
    assert_eq!(Stamps::read(&stamps.ask_due()), Some(1000 + 86_400), "left");
    assert!(!stamps.check_due().exists());
    assert!(!stamps.available().exists());
    assert!(
        !stamps.answered().exists(),
        "nothing offered, so nothing answered: the same commits are offered again"
    );
    stamps.set(2000, None, Some(None), Some(&[])).unwrap();

    std::fs::write(stamps.ask_due(), "soon\n").unwrap();
    assert_eq!(
        Stamps::read(&stamps.ask_due()),
        None,
        "unreadable is never due"
    );
    // What the prompt hook reads a time from, and what it does not.
    // What follows the first line is never read, valid UTF-8 or not.
    for (text, epoch) in [
        (&b" 12\t\n"[..], Some(12)),
        (b"012\nlater\n", Some(12)),
        (b"12\n\xff", Some(12)),
        (b"\xff\n", None),
        (b"+12\n", None),
        (b"-12\n", None),
        (b"12\r\n", None),
        (b"12", None),
        (b" \t\n", None),
        (b"\n12\n", None),
        (b"18446744073709551616\n", None),
    ] {
        std::fs::write(stamps.ask_due(), text).unwrap();
        assert_eq!(
            Stamps::read(&stamps.ask_due()),
            epoch,
            "{:?}",
            text.escape_ascii().to_string()
        );
    }

    // Only "already gone" is quietly fine when a stamp is removed.
    std::fs::create_dir(stamps.available()).unwrap();
    std::fs::write(stamps.available().join("x"), "x").unwrap();
    let err = stamps.set(2000, None, None, Some(&[])).unwrap_err();
    assert!(err.to_string().contains("available"), "{err}");

    let now = now();
    assert!(now > 1_700_000_000, "seconds since the epoch: {now}");
    assert!(now < 1_700_000_000 * 4, "{now}");
}

#[test]
fn the_same_moves_always_have_the_same_generation() {
    let lines = |text: &str| -> Vec<String> { text.lines().map(str::to_string).collect() };
    let one = lines("~/a: 1 new commit(s) on main, 0e810e5afa27 -> 85919cd1ffa7");
    assert_eq!(generation(&one), generation(&one.clone()));
    // Pinned, so a change of hash is a change every machine sees.
    assert_eq!(generation(&[]), "cbf29ce484222325");
    assert_eq!(generation(&lines("~/a: x")), "8323ea2e82044071");
    for other in [
        lines("~/a: 1 new commit(s) on main, 0e810e5afa27 -> 0e810e5afa28"),
        lines("~/b: 1 new commit(s) on main, 0e810e5afa27 -> 85919cd1ffa7"),
        lines("~/a: 1 new commit(s) on main,\n0e810e5afa27 -> 85919cd1ffa7"),
    ] {
        assert_ne!(generation(&one), generation(&other), "{other:?}");
    }
    assert_ne!(
        generation(&lines("a\nb")),
        generation(&lines("b\na")),
        "order is part of it"
    );
}

#[test]
fn an_offer_stands_until_its_generation_is_answered() {
    let offers = |available: &str, answered: Option<&str>| {
        Stamps::offers(Some(available.as_bytes()), answered.map(str::as_bytes))
    };
    assert!(offers("gen g\n~/a: x\n", None));
    assert!(offers("gen g\n~/a: x\n", Some("h\n")));
    assert!(!offers("gen g\n~/a: x\n", Some("g\n")));
    assert!(
        !offers("gen g\n~/a: x\n", Some(" g\t")),
        "read as the hook does"
    );
    assert!(!offers("gen g\n", None), "nothing to offer");
    assert!(!offers("~/a: x", None), "no whole line");
    assert!(
        offers("~/a: x\n", Some("~/a: x\n")),
        "no generation: offered"
    );
    assert!(
        !offers("~/a: x\n~/b: y\n", Some("old:~/a: x\n")),
        "an older bx's offer is settled under its first line"
    );
    assert!(offers("~/a: x\n", Some("old:~/b: y\n")));
    assert!(
        offers("gen  g\n~/a: x\n", Some("g\n")),
        "its generation is ` g`"
    );
    assert!(!Stamps::offers(None, Some(b"g\n")));
}

#[test]
fn waking_prunes_shells_that_are_gone_and_signals_the_rest() {
    let home = guarded_home();
    let stamps = Stamps::of(&StateDir::resolve(home.path()));
    std::fs::create_dir_all(stamps.waiting()).unwrap();
    // A child that has exited and been reaped: its pid names no process.
    let mut gone = std::process::Command::new("true").spawn().unwrap();
    gone.wait().unwrap();
    // The same pid written with a leading zero is no name a shell writes.
    let padded = stamps.waiting().join(format!("0{}", gone.id()));
    std::fs::write(&padded, "g\n").unwrap();
    let gone = stamps.waiting().join(gone.id().to_string());
    std::fs::write(&gone, "g\n").unwrap();
    // A process still running, which ignores `SIGURG` as every one does
    // that does not ask for it.
    let mut alive = std::process::Command::new("sleep")
        .arg("5")
        .spawn()
        .unwrap();
    let waiting = stamps.waiting().join(alive.id().to_string());
    std::fs::write(&waiting, "g\n").unwrap();
    let idle = stamps.waiting().join("0");
    std::fs::write(&idle, "g\n").unwrap();
    stamps.wake();
    let survived = alive.try_wait().unwrap();
    alive.kill().unwrap();
    alive.wait().unwrap();
    assert!(!gone.exists(), "a shell that is gone is pruned");
    assert!(waiting.exists(), "a live one is kept");
    assert!(idle.exists(), "a name that is no pid is not touched");
    assert!(padded.exists(), "a pid with a leading zero is not touched");
    assert_eq!(survived, None, "SIGURG harms nothing that ignores it");
    std::fs::remove_dir_all(stamps.waiting()).unwrap();
    stamps.wake();
}

#[test]
fn waking_signals_only_a_shell_that_is_asking() {
    let home = guarded_home();
    let stamps = Stamps::of(&StateDir::resolve(home.path()));
    std::fs::create_dir_all(stamps.waiting()).unwrap();
    // A process that exits 7 at `SIGURG`, once it says it has the trap.
    let ready = home.child("ready");
    let mut asker = std::process::Command::new("sh")
        .arg("-c")
        .arg("trap 'exit 7' URG; : > \"$1\"; while :; do sleep 0.05; done")
        .arg("sh")
        .arg(&ready)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(ready.exists(), "the trap is set");
    let waiting = stamps.waiting().join(asker.id().to_string());
    // An empty file is a shell that is not asking now.
    std::fs::write(&waiting, "").unwrap();
    stamps.wake();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let idle = asker.try_wait().unwrap();
    std::fs::write(&waiting, "g\n").unwrap();
    stamps.wake();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut woken = asker.try_wait().unwrap();
    while woken.is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
        woken = asker.try_wait().unwrap();
    }
    if woken.is_none() {
        asker.kill().unwrap();
        asker.wait().unwrap();
    }
    assert_eq!(idle, None, "a shell not asking is not signalled");
    assert_eq!(woken.and_then(|status| status.code()), Some(7), "woken");
    assert!(waiting.exists(), "a live shell's file is kept");
}

#[test]
fn a_branch_the_remote_lacks_is_unreachable_not_an_error() {
    let home = guarded_home();
    let repo = home.child("upstream");
    std::fs::create_dir_all(&repo).unwrap();
    crate::sync::tests::run(home.path(), &repo, &["init", "--quiet", "-b", "main"]);
    std::fs::write(repo.join("f"), "f\n").unwrap();
    crate::sync::tests::commit_all(home.path(), &repo, "f");
    std::fs::write(
        home.child(".gitconfig"),
        format!(
            "[url \"file://{}/\"]\n\tinsteadOf = https://h/o/\n",
            home.path().display()
        ),
    )
    .unwrap();
    let git = crate::sync::tests::git(home.path()).unattended();
    let mut external = followed("~/upstream-clone", Check::Ask);
    external.path = Portable::parse_in("~/clone", home.path()).unwrap();
    external.url = "https://h/o/upstream".to_string();

    let tip = crate::sync::tests::rev(home.path(), &repo, "HEAD");
    let ledger = crate::state::LedgerView::default();
    let seen = look(&git, home.path(), &external, &Lock::default(), &ledger);
    assert_eq!(
        seen.moves_to(),
        Some(tip.as_str()),
        "ls-remote, with no checkout: a first lock needs no ancestry"
    );

    // A commit locked elsewhere, with no checkout here to show the tip
    // descends from it: nothing is locked.
    let mut lock = Lock::default();
    lock.set(
        external.path.clone(),
        Locked {
            url: external.url.clone(),
            branch: "main".to_string(),
            rev: A.to_string(),
        },
    );
    let seen = look(&git, home.path(), &external, &lock, &ledger);
    assert!(
        matches!(&seen.verdict, Verdict::Unproven { tip: t } if *t == tip),
        "{seen:?}"
    );
    assert_eq!(seen.moves_to(), None);
    assert!(
        seen.summary().contains("is not locked"),
        "{}",
        seen.summary()
    );

    // The user's own clone at the path is never fetched into: without a
    // ledger entry it is asked with ls-remote, and proves nothing.
    crate::sync::tests::run(
        home.path(),
        home.path(),
        &["clone", "--quiet", "https://h/o/upstream", "clone"],
    );
    let seen = look(&git, home.path(), &external, &lock, &ledger);
    assert!(matches!(seen.verdict, Verdict::Unproven { .. }), "{seen:?}");
    assert!(
        !home.child("clone/.git/FETCH_HEAD").exists(),
        "nothing was fetched into it"
    );

    external.pin = Pin::Follow(Follow {
        branch: "nope".to_string(),
        check: Check::Ask,
    });
    let seen = look(&git, home.path(), &external, &Lock::default(), &ledger);
    assert!(
        matches!(&seen.verdict, Verdict::Unreachable(why) if why.contains("has no refs/heads/nope")),
        "{seen:?}"
    );

    // A remote that is not there at all says what git said, not that a
    // branch is missing.
    external.url = "https://h/o/nowhere".to_string();
    let seen = look(&git, home.path(), &external, &Lock::default(), &ledger);
    assert!(
        matches!(&seen.verdict, Verdict::Unreachable(why) if why.contains("`git ls-remote") && !why.contains("has no")),
        "{seen:?}"
    );
}

#[test]
fn a_held_check_lock_is_waited_on_for_the_whole_wait_and_taken_once_let_go() {
    let home = guarded_home();
    let stamps = Stamps::of(&StateDir::resolve(home.path()));
    let held = stamps.try_hold().expect("hold").expect("free");

    // Held throughout: `hold` keeps trying until `wait` is spent, then
    // gives up.
    let wait = Duration::from_millis(200);
    let started = std::time::Instant::now();
    assert!(stamps.hold(wait).expect("hold").is_none());
    assert!(started.elapsed() >= wait, "{:?}", started.elapsed());

    // Let go partway: the waiting `hold` takes it.
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
    });
    assert!(
        stamps
            .hold(Duration::from_secs(30))
            .expect("hold")
            .is_some()
    );
    releaser.join().expect("released");
}

#[test]
fn a_check_lock_let_go_is_free_while_a_copy_of_it_is_still_open() {
    let home = guarded_home();
    let stamps = Stamps::of(&StateDir::resolve(home.path()));
    let held = stamps.try_hold().expect("hold").expect("free");
    // What a process another thread spawns holds until it execs.
    let copy = held.0.try_clone().expect("a copy");
    assert!(stamps.try_hold().expect("busy").is_none(), "held");
    drop(held);
    assert!(
        stamps.try_hold().expect("hold").is_some(),
        "let go, though a copy is open"
    );
    drop(copy);
}
