//! Check 10: externals that follow a branch, against `bx.lock` and the update
//! stamps.
//!
//! Four things, read from files and nothing else — no remote is asked, and
//! no checkout is looked into:
//!
//! * a followed external `bx.lock` holds no commit for, or holds one for
//!   another url or branch than the one declared: `apply` leaves it as it is
//!   until `bx update` locks it, or, for a follow `local.toml` alone declares,
//!   which `bx update` never locks, until a committed layer declares it or a
//!   `rev` pins it, and for one `local.toml` points elsewhere than the
//!   committed layers, until a `rev` pins it;
//! * an entry in `bx.lock` for a path no `[[external]]` follows any more,
//!   which the next `bx update` drops;
//! * an update stamp that holds no time, so an interactive shell never asks
//!   about updates until `bx update` writes it again;
//! * a `last-check` line saying `bx update` stopped — it failed, or the config
//!   repo refused it — which stands until a `bx update` finishes. What else
//!   `last-check` holds — what a check found, or that `bx update` was
//!   declined or canceled — is no finding: doctor has no severity, and a
//!   finding would leave every machine whose shell checked `Pending`.
//!
//! The last two only while an external follows a branch, as nothing asks
//! about updates otherwise.

use std::path::Path;

use super::Finding;
use crate::config::Origin;
use crate::config::external::{External, first_followed};
use crate::config::lock::{self, Lock, Lookup};
use crate::plan::external::unlocked_note;
use crate::state::StateDir;
use crate::update::{STOPPED, Stamps, kept};

/// A finding for every followed external the lock does not hold, then every
/// lock entry nothing follows, then every unreadable stamp, then every line of
/// `last-check` that says `bx update` stopped.
///
/// `externals` is this account's merged configuration and `committed` the
/// committed layers' alone, as [`crate::update::proposed`] takes them: an
/// entry either follows is one the next `bx update` keeps.
#[must_use]
pub fn check(
    externals: &[External],
    committed: Option<&[External]>,
    lock: &Lock,
    repo: &Path,
    state: &StateDir,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for external in externals {
        let Some(follow) = external.follows() else {
            continue;
        };
        let stale = match lock.lookup(external) {
            Lookup::Locked(_) => continue,
            Lookup::Missing => None,
            Lookup::Stale(locked) => Some(locked),
        };
        let note = unlocked_note(
            external,
            follow,
            stale,
            committed,
            ", so apply leaves it as it is",
        );
        findings.push(Finding {
            subject: external.path.to_string(),
            origin: Some(external.origin.clone()),
            note,
        });
    }
    for (path, locked) in lock.iter() {
        if !kept(path, externals, committed) {
            findings.push(Finding {
                subject: path.to_string(),
                origin: Some(Origin::unknown(&Lock::path_in(repo))),
                note: format!(
                    "{} locks it at {} on `{}`, and no [[external]] follows it; the next \
                     `bx update` drops the entry",
                    lock::FILE,
                    locked.rev,
                    locked.branch
                ),
            });
        }
    }
    if first_followed(externals).is_some() {
        let stamps = Stamps::of(state);
        for stamp in [stamps.ask_due(), stamps.check_due()] {
            if stamp.exists() && Stamps::read(&stamp).is_none() {
                findings.push(Finding {
                    subject: "bx update".to_string(),
                    origin: None,
                    note: format!(
                        "{} holds no time, so no shell asks about updates; `bx update` or \
                         `bx update --snooze` writes it again",
                        stamp.display()
                    ),
                });
            }
        }
        let last = stamps.last_check();
        let text = std::fs::read(&last).unwrap_or_default();
        for line in String::from_utf8_lossy(&text).lines() {
            if line.starts_with(STOPPED) {
                findings.push(Finding {
                    subject: "bx update".to_string(),
                    origin: None,
                    note: format!(
                        "{} says `{line}`; `bx update` tries again, and removes it once it \
                         finishes",
                        last.display()
                    ),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::external::{Check, Follow, Pin};
    use crate::config::lock::Locked;
    use crate::paths::Portable;
    use crate::testing::guarded_home;

    const REV: &str = "0e810e5afa27acbd074398eefbe28d13005dbc15";

    fn external(home: &Path, path: &str, pin: Pin) -> External {
        External {
            path: Portable::parse_in(path, home).unwrap(),
            url: "https://h/o/a".to_string(),
            pin,
            links: Vec::new(),
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        }
    }

    fn follow(branch: &str) -> Pin {
        Pin::Follow(Follow {
            branch: branch.to_string(),
            check: Check::Ask,
        })
    }

    #[test]
    fn an_unlocked_a_stale_and_an_orphaned_entry_are_each_a_finding() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let mut lock = Lock::default();
        let locked = |branch: &str| Locked {
            url: "https://h/o/a".to_string(),
            branch: branch.to_string(),
            rev: REV.to_string(),
        };
        let portable = |raw: &str| Portable::parse_in(raw, home.path()).unwrap();
        lock.set(portable("~/fine"), locked("main"));
        lock.set(portable("~/stale"), locked("old"));
        lock.set(portable("~/gone"), locked("main"));
        let externals = [
            external(home.path(), "~/fine", follow("main")),
            external(home.path(), "~/stale", follow("main")),
            external(home.path(), "~/new", follow("main")),
            external(home.path(), "~/pinned", Pin::Rev(REV.to_string())),
        ];
        let findings = check(&externals, Some(&externals), &lock, home.path(), &state);
        let subjects: Vec<&str> = findings.iter().map(|f| f.subject.as_str()).collect();
        assert_eq!(subjects, ["~/stale", "~/new", "~/gone"]);
        // Followed by the committed configuration, though not by this
        // account's, or with that unknown: kept, so no finding.
        let committed = [external(home.path(), "~/gone", follow("main"))];
        for committed in [Some(&committed[..]), None] {
            let findings = check(&externals, committed, &lock, home.path(), &state);
            assert!(
                findings.iter().all(|f| f.subject != "~/gone"),
                "{findings:?}"
            );
        }
        assert!(
            findings[0].note.contains("locks it for `old`"),
            "{}",
            findings[0].note
        );
        assert!(
            findings[1].note.contains("holds no commit"),
            "{}",
            findings[1].note
        );
        assert_eq!(
            findings[0].note,
            "follows `main` of https://h/o/a, and bx.lock locks it for `old` of https://h/o/a; \
             `bx update` locks it again"
        );
        assert_eq!(
            findings[1].note,
            "follows `main`, and bx.lock holds no commit for it, so apply leaves it as it is; \
             `bx update` locks one"
        );
        assert!(
            findings[2].note.contains("drops the entry"),
            "{}",
            findings[2].note
        );
        assert_eq!(
            findings[2].origin.as_ref().unwrap().file,
            home.path().join("bx.lock")
        );
    }

    #[test]
    fn a_follow_bx_update_never_locks_names_a_committed_layer_or_a_rev() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let remedy = "declare it in a committed layer, or pin it with `rev`";
        let mut lock = Lock::default();
        let portable = |raw: &str| Portable::parse_in(raw, home.path()).unwrap();
        lock.set(
            portable("~/stale"),
            Locked {
                url: "https://h/o/a".to_string(),
                branch: "old".to_string(),
                rev: REV.to_string(),
            },
        );
        let externals = [
            external(home.path(), "~/stale", follow("main")),
            external(home.path(), "~/new", follow("main")),
        ];
        // Committed as this account declares them: `bx update` locks both.
        for committed in [Some(&externals[..]), None] {
            let findings = check(&externals, committed, &lock, home.path(), &state);
            assert!(findings[0].note.ends_with("`bx update` locks it again"));
            assert!(findings[1].note.ends_with("`bx update` locks one"));
        }
        // `local.toml` alone follows `~/new`, and points `~/stale` at another
        // branch than the committed layers do: `bx update` locks neither.
        let committed = [
            external(home.path(), "~/stale", follow("old")),
            external(home.path(), "~/new", Pin::Rev(REV.to_string())),
        ];
        let findings = check(&externals, Some(&committed), &lock, home.path(), &state);
        let subjects: Vec<&str> = findings.iter().map(|f| f.subject.as_str()).collect();
        assert_eq!(subjects, ["~/stale", "~/new"]);
        let elsewhere = "the committed configuration follows here, not this one; pin it with `rev`";
        assert!(
            findings[0].note.ends_with(elsewhere),
            "{}",
            findings[0].note
        );
        assert!(
            !findings[0].note.contains("committed layer"),
            "{}",
            findings[0].note
        );
        assert!(findings[1].note.ends_with(remedy), "{}", findings[1].note);
        assert_eq!(
            findings[0].note,
            "follows `main` of https://h/o/a, and bx.lock locks it for `old` of https://h/o/a; \
             `bx update` locks the branch and url the committed configuration follows here, \
             not this one; pin it with `rev`"
        );
        assert_eq!(
            findings[1].note,
            "follows `main`, and bx.lock holds no commit for it, so apply leaves it as it is; \
             `bx update` locks only what the committed configuration follows; declare it in a \
             committed layer, or pin it with `rev`"
        );
        for finding in &findings {
            assert!(!finding.note.contains("locks one"), "{}", finding.note);
        }
    }

    #[test]
    fn a_stamp_that_holds_no_time_is_a_finding_only_while_something_follows() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let stamps = Stamps::of(&state);
        state.ensure_update().unwrap();
        std::fs::write(stamps.ask_due(), "later\n").unwrap();
        std::fs::write(stamps.check_due(), "12\n").unwrap();
        let followed = [external(home.path(), "~/a", follow("main"))];
        let mut lock = Lock::default();
        lock.set(
            followed[0].path.clone(),
            Locked {
                url: "https://h/o/a".to_string(),
                branch: "main".to_string(),
                rev: REV.to_string(),
            },
        );
        let findings = check(&followed, Some(&followed), &lock, home.path(), &state);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].note.contains("ask-due holds no time"),
            "{}",
            findings[0].note
        );

        let pinned = [external(home.path(), "~/a", Pin::Rev(REV.to_string()))];
        assert!(
            check(
                &pinned,
                Some(&pinned),
                &Lock::default(),
                home.path(),
                &state
            )
            .is_empty()
        );
    }

    /// A followed external `bx.lock` holds at its branch, so only what
    /// `last-check` says can be a finding.
    fn locked_follow(home: &Path) -> ([External; 1], Lock) {
        let followed = [external(home, "~/a", follow("main"))];
        let mut lock = Lock::default();
        lock.set(
            followed[0].path.clone(),
            Locked {
                url: "https://h/o/a".to_string(),
                branch: "main".to_string(),
                rev: REV.to_string(),
            },
        );
        (followed, lock)
    }

    #[test]
    fn a_last_check_saying_bx_update_stopped_is_a_finding_while_something_follows() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let stamps = Stamps::of(&state);
        state.ensure_update().unwrap();
        let stopped = format!("{STOPPED}the config repo has diverged from its upstream");
        std::fs::write(stamps.last_check(), format!("{stopped}\n")).unwrap();
        let (followed, lock) = locked_follow(home.path());
        let findings = check(&followed, Some(&followed), &lock, home.path(), &state);
        assert_eq!(
            findings,
            [Finding {
                subject: "bx update".to_string(),
                origin: None,
                note: format!(
                    "{} says `{stopped}`; `bx update` tries again, and removes it once it \
                     finishes",
                    stamps.last_check().display()
                ),
            }]
        );
        let report = super::super::Report { findings };
        assert_eq!(super::super::exit(&report), crate::report::Exit::Pending);

        // Nothing follows a branch: nothing asks about updates, so nothing.
        let pinned = [external(home.path(), "~/a", Pin::Rev(REV.to_string()))];
        let findings = check(
            &pinned,
            Some(&pinned),
            &Lock::default(),
            home.path(),
            &state,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_last_check_that_says_nothing_stopped_or_none_at_all_is_no_finding() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let stamps = Stamps::of(&state);
        let (followed, lock) = locked_follow(home.path());
        assert!(!stamps.last_check().exists());
        let findings = check(&followed, Some(&followed), &lock, home.path(), &state);
        assert!(findings.is_empty(), "{findings:?}");

        state.ensure_update().unwrap();
        for said in [
            "~/a: 1 new commit(s) on main, 0e810e5 -> 1f921f6\n",
            "~/a: up to date with main\n",
            "the check failed: no config repo\n",
            "bx update was declined, and locked nothing\n",
            "bx update was canceled, and locked nothing\n",
            // Not at the start of its line: not what `settled` writes.
            " bx update stopped: indented\n",
            "",
        ] {
            std::fs::write(stamps.last_check(), said).unwrap();
            let findings = check(&followed, Some(&followed), &lock, home.path(), &state);
            assert!(findings.is_empty(), "{said:?}: {findings:?}");
        }
    }
}
