//! `scripts/mutants-diff-filter` takes the moved lines out of a diff and
//! leaves the lines it writes.
//!
//! Every scenario is a real repository: two commits in a guarded tempdir, and
//! the diff between them as CI takes it, `git diff HEAD^1 HEAD`. The filtered
//! diff is held to what cargo-mutants reads from it: the lines it marks as
//! added and removed, and that it is well formed against both trees — each
//! hunk's counts match its body, its new-side lines are the new file's at the
//! numbers its header gives, its old-side lines the old file's, and the hunks
//! of a file are in order without overlap, which cargo-mutants' parser
//! refuses otherwise.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};

use bx::testing::{GuardedHome, guarded_home};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/mutants-diff-filter");

/// A function long enough that moving it is a move.
const BETA: &str = "\
fn beta(items: &[u32]) -> u32 {
    let total: u32 = items.iter().copied().sum();
    if total > 100 { total - 100 } else { total + 1 }
}
";

const ALPHA: &str = "\
fn alpha(value: u32) -> bool {
    value % 2 == 0 && value > 10
}
";

/// A file, as of one commit: its path and its contents, or `None` once gone.
type Tree<'a> = &'a [(&'a str, Option<&'a str>)];

/// A repository with `old` committed and then `new`, in a guarded home.
struct Repo {
    home: GuardedHome,
}

impl Repo {
    fn new(old: Tree<'_>, new: Tree<'_>) -> Self {
        let repo = Self {
            home: guarded_home(),
        };
        repo.git(&["init", "--quiet", "-b", "master"]);
        for tree in [old, new] {
            for (path, contents) in tree {
                match contents {
                    Some(contents) => {
                        repo.home.write(path, contents);
                    }
                    None => std::fs::remove_file(repo.home.child(path)).expect("remove"),
                }
            }
            repo.git(&["add", "--all"]);
            repo.git(&["commit", "--quiet", "--allow-empty", "-m", "step"]);
        }
        repo
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.home.path())
            .args([
                "-c",
                "user.name=bx test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8")
    }

    /// The diff CI takes.
    fn diff(&self) -> String {
        self.git(&["diff", "HEAD^1", "HEAD"])
    }

    /// `path`'s lines at `rev`, or none where it does not exist there.
    fn lines(&self, rev: &str, path: &str) -> Vec<String> {
        if path == "/dev/null" {
            return Vec::new();
        }
        let listed = self.git(&["ls-tree", "--name-only", rev, "--", path]);
        if listed.trim().is_empty() {
            return Vec::new();
        }
        let blob = self.git(&["show", &format!("{rev}:{path}")]);
        blob.lines().map(str::to_string).collect()
    }
}

/// The filter's stdout and stderr for `diff`, asserting it succeeds.
fn filter(diff: &str) -> (String, String) {
    let mut child = Command::new(SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run the filter");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(diff.as_bytes())
        .expect("write the diff");
    let output = child.wait_with_output().expect("the filter's output");
    assert!(output.status.success(), "the filter failed: {output:?}");
    (
        String::from_utf8(output.stdout).expect("UTF-8"),
        String::from_utf8(output.stderr).expect("UTF-8"),
    )
}

/// The lines a diff adds and removes: by new path the new-side numbers of its
/// added lines, and by old path the old-side numbers of its removed lines.
#[derive(Debug, Default, PartialEq, Eq)]
struct Changed {
    added: BTreeMap<String, Vec<usize>>,
    removed: BTreeMap<String, Vec<usize>>,
}

/// `start[,count]` from a hunk header's range, without its sign.
fn range(spec: &str) -> (usize, usize) {
    let spec = &spec[1..];
    match spec.split_once(',') {
        Some((start, count)) => (start.parse().unwrap(), count.parse().unwrap()),
        None => (spec.parse().unwrap(), 1),
    }
}

/// Parse `diff` against `repo`'s two commits, asserting it is well formed, and
/// return what it changes.
fn checked(repo: &Repo, diff: &str) -> Changed {
    let mut changed = Changed::default();
    let (mut old_path, mut new_path) = (String::new(), String::new());
    let (mut old_file, mut new_file) = (Vec::new(), Vec::new());
    let (mut old_end, mut new_end) = (0, 0);
    let mut lines = diff.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some(path) = line.strip_prefix("--- ") {
            old_path = path.strip_prefix("a/").unwrap_or(path).to_string();
            old_file = repo.lines("HEAD^1", &old_path);
            (old_end, new_end) = (0, 0);
            continue;
        }
        if let Some(path) = line.strip_prefix("+++ ") {
            new_path = path.strip_prefix("b/").unwrap_or(path).to_string();
            new_file = repo.lines("HEAD", &new_path);
            continue;
        }
        let Some(header) = line.strip_prefix("@@ ") else {
            continue;
        };
        let mut specs = header.split(' ');
        let (old_start, old_count) = range(specs.next().unwrap());
        let (new_start, new_count) = range(specs.next().unwrap());
        assert!(
            old_end <= old_start && new_end <= new_start,
            "hunk out of order: {line}"
        );
        (old_end, new_end) = (old_start + old_count, new_start + new_count);
        let (mut old, mut new) = (old_start, new_start);
        let (mut olds, mut news) = (0, 0);
        while olds < old_count || news < new_count {
            let body = lines.next().unwrap_or_else(|| panic!("{line} ends early"));
            let (sign, text) = body.split_at(1);
            if sign == "-" || sign == " " {
                assert_eq!(old_file.get(old - 1).map(String::as_str), Some(text));
                if sign == "-" {
                    changed
                        .removed
                        .entry(old_path.clone())
                        .or_default()
                        .push(old);
                }
                old += 1;
                olds += 1;
            }
            if sign == "+" || sign == " " {
                assert_eq!(new_file.get(new - 1).map(String::as_str), Some(text));
                if sign == "+" {
                    changed.added.entry(new_path.clone()).or_default().push(new);
                }
                new += 1;
                news += 1;
            }
            assert!(sign != "\\", "a marker inside {line}'s counts");
        }
        assert!(olds == old_count && news == new_count, "{line} overruns");
        while lines.peek().is_some_and(|next| next.starts_with('\\')) {
            lines.next();
        }
    }
    changed
}

/// The filter's output for `repo`, checked well formed, and what it changes.
fn scoped(repo: &Repo) -> (String, Changed) {
    let (out, _) = filter(&repo.diff());
    let changed = checked(repo, &out);
    (out, changed)
}

fn at(path: &str, lines: &[usize]) -> BTreeMap<String, Vec<usize>> {
    BTreeMap::from([(path.to_string(), lines.to_vec())])
}

#[test]
fn a_function_moved_between_files_leaves_nothing() {
    let old = format!("{ALPHA}{BETA}");
    let repo = Repo::new(
        &[("src/a.rs", Some(&old))],
        &[("src/a.rs", Some(ALPHA)), ("src/b.rs", Some(BETA))],
    );
    let (out, stderr) = filter(&repo.diff());
    assert_eq!(out, "");
    assert_eq!(
        stderr,
        "mutants-diff-filter: dropped 4 moved added lines and 4 moved removed lines\n"
    );
}

#[test]
fn a_function_moved_and_reindented_into_a_module_leaves_nothing() {
    let old = format!("{ALPHA}\n{BETA}");
    let indented: String = BETA.lines().map(|l| format!("    {l}\n")).collect();
    let new = format!("{ALPHA}\nmod inner {{\n{indented}}}\n");
    let repo = Repo::new(&[("src/a.rs", Some(&old))], &[("src/a.rs", Some(&new))]);
    let (out, changed) = scoped(&repo);
    // The module's own line is new and the function's are not. git keeps the
    // old closing brace as context for the module's, so the function's own
    // closing brace is added with nothing removed to match it, and stays.
    assert_eq!(changed.added, at("src/a.rs", &[5, 9]));
    assert!(changed.removed.is_empty(), "{out}");
}

#[test]
fn an_edit_in_place_passes_through_unchanged() {
    let new = ALPHA.replace("value > 10", "value >= 10");
    let repo = Repo::new(&[("src/a.rs", Some(ALPHA))], &[("src/a.rs", Some(&new))]);
    let diff = repo.diff();
    assert_eq!(filter(&diff).0, diff);
}

#[test]
fn new_logic_passes_through_unchanged() {
    let new = format!("{ALPHA}\n{BETA}");
    let repo = Repo::new(&[("src/a.rs", Some(ALPHA))], &[("src/a.rs", Some(&new))]);
    let diff = repo.diff();
    assert_eq!(filter(&diff).0, diff);
}

#[test]
fn short_lines_shared_by_chance_are_not_a_move() {
    // `}`, `Ok(())` and a blank line are removed in one place and written in
    // another, but hold too few characters to be anything but coincidence.
    let old = format!("fn gone() -> Result<(), ()> {{\n    Ok(())\n}}\n\n{ALPHA}");
    let new = format!("{ALPHA}\nfn fresh() -> Result<(), ()> {{\n    Ok(())\n}}\n");
    let repo = Repo::new(&[("src/a.rs", Some(&old))], &[("src/a.rs", Some(&new))]);
    let diff = repo.diff();
    assert_eq!(filter(&diff).0, diff);
}

#[test]
fn an_edit_inside_moved_code_is_all_that_stays() {
    // `beta` moves into the place of a constant the change deletes, with one
    // line edited on the way. Left added are the edit and the closing brace
    // after it, a block too short to be a move on its own; left removed are
    // the constant, and the edited line's old text with the brace after it.
    // The cut leaves a hunk with no old line right after one that has some,
    // and the two stay in order.
    let gone = "const GONE: u8 = 1;\n";
    let old_a = format!("{ALPHA}\n{gone}");
    let edited = BETA.replace("total - 100", "total - 99");
    let new_a = format!("{ALPHA}\n{edited}");
    let repo = Repo::new(
        &[("src/a.rs", Some(&old_a)), ("src/b.rs", Some(BETA))],
        &[("src/a.rs", Some(&new_a)), ("src/b.rs", None)],
    );
    let (out, changed) = scoped(&repo);
    assert_eq!(changed.added, at("src/a.rs", &[7, 8]), "{out}");
    let mut removed = at("src/a.rs", &[5]);
    removed.insert("src/b.rs".to_string(), vec![3, 4]);
    assert_eq!(changed.removed, removed, "{out}");
}

#[test]
fn a_moved_last_line_without_a_newline_takes_its_marker_along() {
    let old = format!("{ALPHA}{}", BETA.trim_end());
    let repo = Repo::new(
        &[("src/a.rs", Some(&old))],
        &[
            ("src/a.rs", Some(ALPHA)),
            ("src/b.rs", Some(BETA.trim_end())),
        ],
    );
    let (out, changed) = scoped(&repo);
    assert_eq!(out, "");
    assert_eq!(changed, Changed::default());
}

#[test]
fn a_kept_last_line_without_a_newline_keeps_its_marker() {
    let new = ALPHA.trim_end().replace("value > 10", "value >= 10");
    let repo = Repo::new(&[("src/a.rs", Some(ALPHA))], &[("src/a.rs", Some(&new))]);
    let diff = repo.diff();
    assert!(diff.contains("\\ No newline at end of file"), "{diff}");
    assert_eq!(filter(&diff).0, diff);
}

#[test]
fn a_file_section_without_hunks_passes_through() {
    // A pure rename beside a move: the rename has no hunk to cut, so it is
    // kept as git wrote it, and the move is dropped.
    let old = format!("{ALPHA}{BETA}");
    let repo = Repo::new(
        &[
            ("src/a.rs", Some(&old)),
            ("src/c.rs", Some("const C: u8 = 3;\n")),
        ],
        &[
            ("src/a.rs", Some(ALPHA)),
            ("src/b.rs", Some(BETA)),
            ("src/c.rs", None),
            ("src/d.rs", Some("const C: u8 = 3;\n")),
        ],
    );
    let (out, _) = filter(&repo.diff());
    assert_eq!(
        out,
        "diff --git a/src/c.rs b/src/d.rs\n\
         similarity index 100%\n\
         rename from src/c.rs\n\
         rename to src/d.rs\n"
    );
}

#[test]
fn the_same_diff_always_gives_the_same_output() {
    let old = format!("{ALPHA}\n{BETA}\n{BETA}");
    let new = format!("{BETA}\n{ALPHA}\n{}", BETA.replace("100", "200"));
    let repo = Repo::new(&[("src/a.rs", Some(&old))], &[("src/a.rs", Some(&new))]);
    let diff = repo.diff();
    let first = filter(&diff);
    checked(&repo, &first.0);
    assert_eq!(filter(&diff), first);
}

#[test]
fn an_empty_diff_gives_an_empty_output() {
    assert_eq!(
        filter(""),
        (
            String::new(),
            "mutants-diff-filter: dropped 0 moved added lines and 0 moved removed lines\n"
                .to_string()
        )
    );
}
