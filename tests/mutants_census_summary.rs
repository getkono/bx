//! `scripts/mutants-census-summary` merges a sharded mutation census and
//! fails unless every mutant dealt to a shard has exactly one outcome.
//!
//! Every scenario lays shards out in a guarded tempdir as the census workflow
//! downloads them: `census-N/` holding `sha.txt`, `listed.txt` and
//! `mutants.out/*.txt`, whose lines are the mutant names cargo-mutants prints.

use std::process::{Command, Output};

use bx::testing::{GuardedHome, guarded_home};

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scripts/mutants-census-summary"
);

const SHA: &str = "3bf7dfb0000000000000000000000000000000000";

const GT: &str = "src/a.rs:1:32: replace > with >= in big";
const TRUE: &str = "src/a.rs:1:30: replace big -> bool with true";
const MINUS: &str = "src/b/c.rs:9:5: replace + with - in sum";
const UNIT: &str = "src/b/c.rs:12:5: replace go with ()";

/// One shard as downloaded: its commit, what it was dealt, and its outcomes.
#[derive(Default)]
struct Shard<'a> {
    sha: Option<&'a str>,
    listed: &'a [&'a str],
    caught: &'a [&'a str],
    missed: &'a [&'a str],
    timeout: &'a [&'a str],
    unviable: &'a [&'a str],
    /// The shard uploaded no `listed.txt`.
    unlisted: bool,
    /// The shard uploaded no `mutants.out`: it stopped before any outcome.
    untested: bool,
}

impl<'a> Shard<'a> {
    fn at(listed: &'a [&'a str]) -> Self {
        Self {
            sha: Some(SHA),
            listed,
            ..Self::default()
        }
    }
}

fn lines(names: &[&str]) -> String {
    names.iter().map(|name| format!("{name}\n")).collect()
}

/// Lays out `shards` (a `None` is a shard that never uploaded) and runs the
/// script over them, returning its output and the home holding `out/`.
fn summarize(shards: &[Option<Shard<'_>>]) -> (Output, GuardedHome) {
    let home = guarded_home();
    for (n, shard) in shards.iter().enumerate() {
        let Some(shard) = shard else { continue };
        let dir = format!("shards/census-{n}");
        if let Some(sha) = shard.sha {
            home.write(format!("{dir}/sha.txt"), &format!("{sha}\n"));
        }
        if !shard.unlisted {
            home.write(format!("{dir}/listed.txt"), &lines(shard.listed));
        }
        if shard.untested {
            continue;
        }
        for (outcome, names) in [
            ("caught", shard.caught),
            ("missed", shard.missed),
            ("timeout", shard.timeout),
            ("unviable", shard.unviable),
        ] {
            home.write(format!("{dir}/mutants.out/{outcome}.txt"), &lines(names));
        }
    }
    let output = Command::new(SCRIPT)
        .arg(home.child("shards"))
        .arg(shards.len().to_string())
        .arg(home.child("out"))
        .output()
        .expect("run the summary");
    (output, home)
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8")
}

fn merged(home: &GuardedHome, list: &str) -> String {
    std::fs::read_to_string(home.child(format!("out/{list}.txt"))).expect("merged list")
}

#[test]
fn a_whole_census_merges_sorted_and_counts_each_outcome_by_file() {
    let (output, home) = summarize(&[
        Some(Shard {
            caught: &[MINUS],
            missed: &[GT],
            ..Shard::at(&[GT, MINUS])
        }),
        Some(Shard {
            timeout: &[UNIT],
            unviable: &[TRUE],
            ..Shard::at(&[UNIT, TRUE])
        }),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(merged(&home, "listed"), lines(&[TRUE, GT, UNIT, MINUS]));
    assert_eq!(merged(&home, "missed"), lines(&[GT]));
    assert_eq!(merged(&home, "timeout"), lines(&[UNIT]));
    assert_eq!(merged(&home, "unaccounted"), "");
    let summary = stdout(&output);
    assert!(
        summary.contains(&format!("Commit: `{SHA}`, 2 shards.")),
        "{summary}"
    );
    for row in [
        "| dealt | 4 |",
        "| caught | 1 |",
        "| missed | 1 |",
        "| timeout | 1 |",
        "| unviable | 1 |",
        "| unaccounted | 0 |",
        "| `src/a.rs` | 1 | 0 |\n| `src/b/c.rs` | 0 | 1 |",
    ] {
        assert!(summary.contains(row), "{row:?} in {summary}");
    }
    assert!(!summary.contains("not whole"), "{summary}");
}

#[test]
fn a_census_with_nothing_missed_says_so() {
    let (output, _home) = summarize(&[Some(Shard {
        caught: &[GT],
        ..Shard::at(&[GT])
    })]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(stdout(&output).contains("## Missed and timed out, by file\n\nNone.\n"));
}

#[test]
fn a_shard_that_never_uploaded_fails_the_census() {
    let (output, _home) = summarize(&[
        Some(Shard {
            caught: &[GT],
            ..Shard::at(&[GT])
        }),
        None,
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).contains("- shard 1 is missing"));
}

#[test]
fn a_mutant_dealt_with_no_outcome_is_unaccounted_and_fails_the_census() {
    let (output, home) = summarize(&[Some(Shard {
        caught: &[GT],
        ..Shard::at(&[GT, MINUS])
    })]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(merged(&home, "unaccounted"), lines(&[MINUS]));
    let summary = stdout(&output);
    assert!(summary.contains("| unaccounted | 1 |"), "{summary}");
    assert!(
        summary.contains("- mutants dealt with no outcome: 1 (unaccounted.txt)"),
        "{summary}"
    );
}

#[test]
fn shards_at_different_commits_fail_the_census() {
    let (output, _home) = summarize(&[
        Some(Shard {
            caught: &[GT],
            ..Shard::at(&[GT])
        }),
        Some(Shard {
            sha: Some("feedface"),
            caught: &[MINUS],
            ..Shard::at(&[MINUS])
        }),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).contains("- the shards tested different commits"));
}

#[test]
fn a_shard_with_no_commit_is_missing() {
    let (output, _home) = summarize(&[Some(Shard {
        sha: None,
        caught: &[GT],
        ..Shard::at(&[GT])
    })]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).contains("- shard 0 is missing"));
}

#[test]
fn a_shard_with_no_listing_is_missing() {
    let (output, _home) = summarize(&[Some(Shard {
        unlisted: true,
        caught: &[GT],
        ..Shard::at(&[GT])
    })]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).contains("- shard 0 is missing"));
}

#[test]
fn a_shard_stopped_before_any_outcome_leaves_its_mutants_unaccounted() {
    let (output, home) = summarize(&[
        Some(Shard {
            caught: &[GT],
            ..Shard::at(&[GT])
        }),
        Some(Shard {
            untested: true,
            ..Shard::at(&[MINUS])
        }),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(merged(&home, "unaccounted"), lines(&[MINUS]));
    assert_eq!(merged(&home, "caught"), lines(&[GT]));
}

#[test]
fn a_mutant_dealt_twice_fails_the_census() {
    let (output, _home) = summarize(&[
        Some(Shard {
            caught: &[GT],
            ..Shard::at(&[GT])
        }),
        Some(Shard::at(&[GT])),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).contains(&format!("- dealt twice: {GT}")));
}

#[test]
fn a_mutant_with_two_outcomes_fails_the_census() {
    let (output, _home) = summarize(&[Some(Shard {
        caught: &[GT],
        missed: &[GT],
        ..Shard::at(&[GT])
    })]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).contains(&format!("- more than one outcome: {GT}")));
}

#[test]
fn an_outcome_nobody_was_dealt_fails_the_census() {
    let (output, _home) = summarize(&[Some(Shard {
        caught: &[GT, MINUS],
        ..Shard::at(&[GT])
    })]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).contains(&format!("- an outcome nobody was dealt: {MINUS}")));
}

#[test]
fn a_wrong_argument_count_is_a_usage_error() {
    let output = Command::new(SCRIPT).output().expect("run the summary");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn a_shard_count_that_is_not_a_positive_integer_is_a_usage_error() {
    let home = guarded_home();
    for shards in ["0", "abc", "", "-1", "08"] {
        let output = Command::new(SCRIPT)
            .arg(home.child("shards"))
            .arg(shards)
            .arg(home.child("out"))
            .output()
            .expect("run the summary");
        assert_eq!(output.status.code(), Some(2), "{shards:?}: {output:?}");
    }
}
