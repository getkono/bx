//! `scripts/line-check` holds every tracked text file to its limit, against a
//! baseline that only shrinks and a limit that only goes down.
//!
//! Every scenario is a real repository in a guarded tempdir: a base commit,
//! tagged `base`, and a working tree changed on top of it. The script under
//! test is this checkout's, run inside that repository, so its own `LIMIT` is
//! the one judged; the base commit's `scripts/line-check` only carries the
//! base's `LIMIT` for it to compare against.

use std::process::Command;

use bx::testing::{GuardedHome, guarded_home};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/line-check");
const BASELINE: &str = "scripts/line-check-baseline";

/// The script's own `LIMIT`, so no scenario restates the number.
fn limit() -> usize {
    let script = std::fs::read_to_string(SCRIPT).expect("read the script");
    script
        .lines()
        .find_map(|line| line.strip_prefix("LIMIT="))
        .expect("a LIMIT= line")
        .parse()
        .expect("LIMIT is a number")
}

/// `n` lines, each ending in `eol`.
fn long(n: usize, eol: &str) -> String {
    format!("x{eol}").repeat(n)
}

/// A file as written: its path and its contents.
type Tree<'a> = &'a [(&'a str, String)];

/// A repository whose base commit holds `base`, and whose `LIMIT` at base is
/// `base_limit` where one is given.
struct Repo {
    home: GuardedHome,
}

impl Repo {
    fn new(base_limit: Option<usize>, base: Tree<'_>) -> Self {
        let repo = Self {
            home: guarded_home(),
        };
        repo.git(&["init", "--quiet", "-b", "master"]);
        if let Some(base_limit) = base_limit {
            repo.home.write(
                "scripts/line-check",
                &format!("#!/bin/sh\nLIMIT={base_limit}\n"),
            );
        }
        repo.write(base);
        repo.git(&["commit", "--quiet", "--allow-empty", "-m", "base"]);
        repo.git(&["tag", "base"]);
        repo
    }

    /// Write `tree` into the working tree and track it.
    fn write(&self, tree: Tree<'_>) {
        for (path, contents) in tree {
            self.home.write(path, contents);
        }
        self.git(&["add", "--all"]);
    }

    fn remove(&self, path: &str) {
        std::fs::remove_file(self.home.child(path)).expect("remove");
    }

    fn git(&self, args: &[&str]) -> String {
        let output = self
            .command("git")
            .args([
                "-c",
                "user.name=bx test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8")
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE");
        command
    }

    /// Whether the check passed against `base`, and what it wrote to stderr.
    fn check(&self, base: Option<&str>) -> (bool, String) {
        let output = self
            .command(SCRIPT)
            .args(base)
            .output()
            .expect("run the line check");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8");
        (output.status.success(), stderr)
    }

    /// The check against `base`, asserting it passes.
    fn passes(&self) {
        let (passed, stderr) = self.check(Some("base"));
        assert!(passed, "expected a pass:\n{stderr}");
    }

    /// The check against `base`, asserting it fails and says `needle`.
    fn fails_with(&self, needle: &str) {
        let (passed, stderr) = self.check(Some("base"));
        assert!(!passed, "expected a failure:\n{stderr}");
        assert!(stderr.contains(needle), "expected {needle:?} in:\n{stderr}");
    }
}

fn baseline(paths: &[&str]) -> (&'static str, String) {
    let mut contents = String::from("# the files over the limit\n\n");
    for path in paths {
        contents.push_str(path);
        contents.push('\n');
    }
    (BASELINE, contents)
}

#[test]
fn a_file_at_the_limit_passes_and_one_line_more_fails() {
    let limit = limit();
    let repo = Repo::new(Some(limit), &[]);
    repo.write(&[("at.txt", long(limit, "\n"))]);
    repo.passes();

    repo.write(&[("src/over.rs", long(limit + 1, "\n"))]);
    repo.fails_with(&format!(
        "src/over.rs has {} lines, over the {limit}-line limit",
        limit + 1
    ));
}

#[test]
fn a_final_line_without_a_newline_is_counted() {
    let limit = limit();
    let repo = Repo::new(Some(limit), &[]);
    let mut at = long(limit - 1, "\n");
    at.push('x');
    repo.write(&[("at.txt", at.clone())]);
    repo.passes();

    repo.write(&[("over.txt", format!("x\n{at}"))]);
    repo.fails_with(&format!("over.txt has {} lines", limit + 1));
}

#[test]
fn crlf_lines_count_once() {
    let limit = limit();
    let repo = Repo::new(Some(limit), &[]);
    repo.write(&[("at.txt", long(limit, "\r\n"))]);
    repo.passes();

    repo.write(&[("over.txt", long(limit + 1, "\r\n"))]);
    repo.fails_with(&format!("over.txt has {} lines", limit + 1));
}

#[test]
fn a_path_git_would_quote_is_still_counted() {
    let limit = limit();
    for path in [
        "quo\"te.txt",
        "back\\slash.txt",
        "tab\there.txt",
        "a=b.txt",
        "ünï.txt",
    ] {
        let repo = Repo::new(Some(limit), &[]);
        repo.write(&[(path, long(limit + 1, "\n"))]);
        repo.fails_with(&format!("{path} has {} lines", limit + 1));
    }
}

#[test]
fn fixtures_cargo_lock_and_binaries_are_not_counted() {
    let limit = limit();
    let mut binary = long(limit + 1, "\n");
    binary.push('\0');
    let repo = Repo::new(Some(limit), &[]);
    repo.write(&[
        ("tests/fixtures/captured.txt", long(limit + 1, "\n")),
        ("Cargo.lock", long(limit + 1, "\n")),
        ("blob.bin", binary),
    ]);
    repo.passes();
}

#[test]
fn a_listed_file_may_stay_over_and_change_under_its_entry() {
    let limit = limit();
    let repo = Repo::new(
        Some(limit),
        &[("big.rs", long(limit + 1, "\n")), baseline(&["big.rs"])],
    );
    repo.write(&[("big.rs", long(limit + 50, "\n"))]);
    repo.passes();
}

#[test]
fn a_stale_baseline_entry_fails() {
    let limit = limit();
    let tree = [
        ("big.rs", long(limit + 1, "\n")),
        ("gone.rs", long(limit + 1, "\n")),
        baseline(&["big.rs", "gone.rs"]),
    ];

    let repo = Repo::new(Some(limit), &tree);
    repo.write(&[("big.rs", long(limit, "\n"))]);
    repo.fails_with(&format!(
        "big.rs is no longer over {limit} lines; delete it from {BASELINE}"
    ));

    let repo = Repo::new(Some(limit), &tree);
    repo.remove("gone.rs");
    repo.fails_with("gone.rs is no longer over");
}

#[test]
fn an_unsorted_or_repeated_baseline_fails() {
    let limit = limit();
    for paths in [&["b.rs", "a.rs"][..], &["a.rs", "a.rs", "b.rs"][..]] {
        let repo = Repo::new(
            Some(limit),
            &[
                ("a.rs", long(limit + 1, "\n")),
                ("b.rs", long(limit + 1, "\n")),
                baseline(&["a.rs", "b.rs"]),
            ],
        );
        repo.write(&[baseline(paths)]);
        repo.fails_with("must be sorted (LC_ALL=C) with no repeated path");
    }
}

#[test]
fn a_file_grown_onto_the_baseline_fails() {
    let limit = limit();
    // At the same limit, and below a lowered one: growing past the limit
    // never earns an entry, only having been over it at the base does.
    for base_limit in [limit, limit + 100] {
        let repo = Repo::new(
            Some(base_limit),
            &[("grown.rs", long(limit, "\n")), baseline(&[])],
        );
        repo.write(&[("grown.rs", long(limit + 1, "\n")), baseline(&["grown.rs"])]);
        repo.fails_with(&format!(
            "{BASELINE} gained grown.rs, which base does not list"
        ));
    }
}

#[test]
fn a_file_already_over_at_the_base_may_join_only_when_the_limit_falls() {
    let limit = limit();
    let tree = [("long.rs", long(limit + 50, "\n")), baseline(&[])];

    // The limit fell from above the file's length to below it.
    let repo = Repo::new(Some(limit + 100), &tree);
    repo.write(&[baseline(&["long.rs"])]);
    repo.passes();

    // The limit did not fall, so the file was over it unlisted already; an
    // entry is still refused.
    let repo = Repo::new(Some(limit), &tree);
    repo.write(&[baseline(&["long.rs"])]);
    repo.fails_with("gained long.rs");

    // A file new since the base was never over anything there.
    let repo = Repo::new(Some(limit + 100), &[baseline(&[])]);
    repo.write(&[("new.rs", long(limit + 1, "\n")), baseline(&["new.rs"])]);
    repo.fails_with("gained new.rs");
}

#[test]
fn a_raised_limit_fails() {
    let limit = limit();
    let repo = Repo::new(Some(limit - 1), &[]);
    repo.fails_with(&format!(
        "LIMIT is {limit}, above base's {}; the limit only goes down",
        limit - 1
    ));
}

#[test]
fn a_base_without_a_limit_or_baseline_is_named_and_skipped() {
    let repo = Repo::new(None, &[]);
    let (passed, stderr) = repo.check(Some("base"));
    assert!(passed, "expected a pass:\n{stderr}");
    assert!(
        stderr.contains("base has no LIMIT in scripts/line-check yet"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("base has no {BASELINE} yet")),
        "{stderr}"
    );
}

#[test]
fn an_absent_base_is_named_and_an_unresolvable_one_fails() {
    let limit = limit();
    // A lower limit at the base would fail the check, were it compared.
    let repo = Repo::new(Some(limit - 1), &[]);

    let (passed, stderr) = repo.check(None);
    assert!(passed, "expected a pass:\n{stderr}");
    assert!(stderr.contains("no base to compare"), "{stderr}");

    let (passed, stderr) = repo.check(Some("no-such-ref"));
    assert!(!passed, "expected a failure:\n{stderr}");
    assert!(
        stderr.contains("base no-such-ref does not resolve to a commit"),
        "{stderr}"
    );
}

#[test]
fn origin_head_is_the_default_base() {
    let limit = limit();
    let repo = Repo::new(Some(limit - 1), &[]);
    let head = repo.git(&["rev-parse", "HEAD"]);
    repo.git(&["update-ref", "refs/remotes/origin/master", head.trim()]);
    repo.git(&[
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/master",
    ]);
    let (passed, stderr) = repo.check(None);
    assert!(!passed, "expected a failure:\n{stderr}");
    assert!(stderr.contains("above origin/HEAD's"), "{stderr}");
}
