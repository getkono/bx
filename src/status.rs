//! `bx status`: where this machine stands against the configuration, said
//! the way `git status` says where a working tree stands.
//!
//! The rows come from the one traversal every command shares,
//! [`crate::plan::run`] in [`crate::plan::Mode::Plan`], so `status` spawns
//! only what `plan` spawns and announces nothing `plan` would not (Invariant
//! 7). Beside it, [`Facts::gather`] asks the config repo's own `git` what
//! only this machine knows: the branch and how it stands against its
//! upstream as the last fetch left it, and the copies bx carried into the
//! repo that no commit has taken yet ([`crate::sync::uncommitted`]). Nothing
//! is fetched, and git runs with `GIT_OPTIONAL_LOCKS=0`, so `status` writes
//! nothing, not even the index.
//!
//! The long form ([`long`]) groups the rows into sections, each left out
//! when empty and each with the command that moves it on; the short form
//! ([`short`]) is one line per row that is not unchanged. Every path is
//! portable, and neither form shows a diff: that is `bx plan`'s.

use std::fmt::Write as _;
use std::path::Path;

use crate::git::checkout::{own_checkout, problem};
use crate::git::{self, Git};
use crate::paths;
use crate::plan::{Asked, Change, Inputs, Report};
use crate::report::{Action, escape};
use crate::shell::activation;
use crate::sync::{self, Carry, Uncommitted};
use crate::update::{self, Stamps};

/// Where the config repo's branch stands, as the last fetch left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Branch {
    /// The config repo is not a git repository: bx works without one, and
    /// nothing is said.
    NotGit,
    /// git could not say, in a sentence that says why.
    Unknown(String),
    /// No branch is checked out.
    Detached,
    /// On `name`, which has no upstream.
    NoUpstream {
        /// The branch.
        name: String,
    },
    /// On `name`, whose upstream has no ref here.
    Gone {
        /// The branch.
        name: String,
        /// Its upstream, as `REMOTE/BRANCH`.
        upstream: String,
    },
    /// On `name`, tracking `upstream`.
    Tracking {
        /// The branch.
        name: String,
        /// Its upstream, as `REMOTE/BRANCH`.
        upstream: String,
        /// Commits only on the branch.
        ahead: u64,
        /// Commits only on the upstream.
        behind: u64,
    },
}

/// What `status` says beside the plan's rows: facts only this machine's
/// config repo and state directory hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The config repo, spelled portably.
    pub repo: String,
    /// Its branch.
    pub branch: Branch,
    /// The repo files bx wrote that no commit has taken yet.
    pub uncommitted: Vec<Uncommitted>,
    /// Why git could not say which those are, when it could not.
    pub unasked: Option<String>,
    /// Whether a followed external's update check, or the question whether
    /// to run one, has fallen due.
    pub due: bool,
}

impl Facts {
    /// Ask `git` about the config repo `inputs` loaded, and read the state
    /// directory's update stamps, changing nothing.
    #[must_use]
    pub fn gather(inputs: &Inputs, git: &Git) -> Self {
        let git = git.clone().with_env("GIT_OPTIONAL_LOCKS", "0");
        let (repo, home) = (inputs.repo(), inputs.home());
        let at = paths::to_portable(repo, home);
        let branch = branch(&git, repo, &at);
        // git's answers name paths from the top of the checkout it found,
        // which is the repo only where the repo is a checkout of its own:
        // where git could not say even that, nothing more is asked.
        let (uncommitted, unasked) = match &branch {
            Branch::Unknown(_) => (Vec::new(), None),
            _ => match sync::uncommitted(inputs.state(), home, &git, repo) {
                Ok(found) => (found, None),
                Err(error) => (Vec::new(), Some(sync_note(&error))),
            },
        };
        let stamps = Stamps::of(inputs.state());
        let now = update::now();
        let due = [stamps.ask_due(), stamps.check_due()]
            .iter()
            .any(|stamp| Stamps::read(stamp).is_some_and(|due| due <= now));
        Self {
            repo: at,
            branch,
            uncommitted,
            unasked,
            due,
        }
    }
}

/// A `sync` question's failure, in a sentence's words.
fn sync_note(error: &sync::Error) -> String {
    match error {
        sync::Error::Git(error) => problem(error),
        other => other.to_string(),
    }
}

/// Where the branch of the config repo at `repo`, spelled `at`, stands.
fn branch(git: &Git, repo: &Path, at: &str) -> Branch {
    if std::fs::symlink_metadata(repo.join(".git")).is_err() {
        return Branch::NotGit;
    }
    if let Err(note) = own_checkout(git, repo) {
        return Branch::Unknown(format!("The config repo {at} {note}."));
    }
    let unknown =
        |note: String| Branch::Unknown(format!("git could not say where {at} stands: {note}."));
    let name = match git.query(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]) {
        Ok(name) => name,
        Err(error @ git::Error::Spawn { .. }) => return unknown(problem(&error)),
        Err(_) => return Branch::Detached,
    };
    let upstream = match sync::upstream(git, repo, &name) {
        Ok(upstream) => upstream.short,
        Err(sync::Error::NoUpstream { .. }) => return Branch::NoUpstream { name },
        Err(error) => return unknown(sync_note(&error)),
    };
    match sync::gone(git, repo, &name) {
        Ok(true) => return Branch::Gone { name, upstream },
        Ok(false) => {}
        Err(error) => return unknown(sync_note(&error)),
    }
    match sync::counts(git, repo) {
        Ok((ahead, behind)) => Branch::Tracking {
            name,
            upstream,
            ahead,
            behind,
        },
        Err(error) => unknown(sync_note(&error)),
    }
}

/// The columns a row's label is padded to, its colon included.
const LABEL: usize = 10;
/// The indentation of a section's hint.
const HINT: &str = "  ";
/// The indentation of a section's row.
const ROW: &str = "        ";

/// One row: `subject` labelled `label`, its label padded as `git status`
/// pads one, followed by `note` in parentheses.
fn row(label: &str, subject: &str, note: Option<&str>) -> String {
    let tag = format!("{label}:");
    let pad = LABEL.saturating_sub(tag.len()).max(1);
    let mut row = format!("{ROW}{tag}{:pad$}{}", "", escape(subject));
    if let Some(note) = note {
        let _ = write!(row, "  ({})", escape(note));
    }
    row
}

/// One section of the long form: its heading, its hints, and its rows.
struct Section {
    heading: &'static str,
    hints: Vec<&'static str>,
    rows: Vec<String>,
}

impl Section {
    const fn new(heading: &'static str, hints: Vec<&'static str>) -> Self {
        Self {
            heading,
            hints,
            rows: Vec::new(),
        }
    }

    /// Add `subject` labelled `label`, followed by `note` in parentheses.
    fn push(&mut self, label: &str, subject: &str, note: Option<&str>) {
        self.rows.push(row(label, subject, note));
    }

    /// The section as text, or `None` when it holds no row.
    fn text(&self) -> Option<String> {
        if self.rows.is_empty() {
            return None;
        }
        let mut out = format!("{}\n", self.heading);
        for hint in &self.hints {
            let _ = writeln!(out, "{HINT}{hint}");
        }
        for row in &self.rows {
            let _ = writeln!(out, "{row}");
        }
        Some(out)
    }
}

/// The long form: the branch, then each section that holds a row, then a
/// closing line when nothing is left to apply.
#[must_use]
pub fn long(report: &Report, facts: &Facts, home: &Path) -> String {
    let mut blocks: Vec<String> = Vec::new();
    blocks.extend(branch_text(facts));
    if let Some(text) = interrupted_text(report) {
        blocks.push(text);
        return blocks.join("\n");
    }
    let mut apply = Section::new(
        "Changes to apply:",
        vec![r#"(use "bx apply" to write them, "bx plan" to see the diffs)"#],
    );
    let mut edited = Section::new(
        "Edited on this machine since bx wrote them:",
        vec![
            r#"(use "bx add <path>" to save your edit into the config repo)"#,
            r#"(use "bx apply" to choose between yours and bx's)"#,
        ],
    );
    let mut carry = Section::new(
        "Tracked files to carry:",
        vec![r#"(use "bx sync" to commit and push them)"#],
    );
    let mut gone = Section::new(
        "No longer declared:",
        vec![r#"(use "bx apply" to take them back)"#],
    );
    let mut attention = Section::new("Needs attention:", Vec::new());
    for (at, change) in report.changes.iter().enumerate() {
        if let Some(question) = report.questions.iter().find(|question| question.row == at) {
            edited.push(asked_label(question.asked), &change.target, None);
        } else if report.kept.contains(&at) {
            edited.push("kept", &change.target, None);
        } else {
            place(change, &mut apply, &mut carry, &mut gone, &mut attention);
        }
    }
    for step in report.activations.steps() {
        let action = step.action();
        let subject = activation_subject(step);
        if action.is_pending() {
            apply.push(&action.to_string(), &subject, None);
        } else if action.needs_attention() {
            // The step's own line, but for the symbol and subject the row
            // already says.
            let line = step.line();
            let said = format!("{} {subject}: ", action.symbol());
            let why = line.strip_prefix(&said).unwrap_or(&line);
            attention.push(&action.to_string(), &subject, Some(why));
        }
    }
    for found in &facts.uncommitted {
        let label = match found.carry {
            Carry::Copy => "carried",
            Carry::Removal => "removed",
            Carry::Save => "saved",
        };
        carry.push(label, &paths::to_portable(&found.path, home), None);
    }
    if gone
        .rows
        .iter()
        .any(|row| row.trim_start().starts_with("undeclared:"))
    {
        gone.hints
            .push(r#"(use "bx rm <path>" to stop managing one apply leaves alone)"#);
    }
    // A kept answer and an undeclared file are rows `apply` leaves alone, so
    // neither stops the machine matching; every other row is work or a
    // question.
    let only = |section: &Section, label: &str| {
        section
            .rows
            .iter()
            .all(|row| row.trim_start().starts_with(label))
    };
    let settled = apply.rows.is_empty()
        && attention.rows.is_empty()
        && only(&edited, "kept:")
        && only(&gone, "undeclared:");
    for section in [&apply, &edited, &carry, &gone, &attention] {
        blocks.extend(section.text());
    }
    if let Some(unasked) = &facts.unasked {
        blocks.push(format!(
            "git could not say which files bx carried into {} are uncommitted: {unasked}.\n",
            facts.repo
        ));
    }
    if facts.due {
        blocks.push("Externals due for an update check (use \"bx update\")\n".to_string());
    }
    if settled {
        blocks.push("nothing to apply, this machine matches the configuration\n".to_string());
    }
    blocks.join("\n")
}

/// Put `change`, a row no question is about, in the section it belongs to.
fn place(
    change: &Change,
    apply: &mut Section,
    carry: &mut Section,
    gone: &mut Section,
    attention: &mut Section,
) {
    let deletion = change
        .note
        .as_deref()
        .is_some_and(|note| note.starts_with("deleted:"));
    let target = &change.target;
    match change.action {
        Action::Unchanged => {}
        Action::Create => apply.push("create", target, None),
        Action::Modify if deletion => apply.push("delete", target, None),
        Action::Modify => apply.push("modify", target, None),
        Action::Undo => gone.push("undo", target, None),
        Action::Release => gone.push("release", target, None),
        Action::Undeclared => gone.push("undeclared", target, None),
        Action::Sync if deletion => carry.push("deleted", target, None),
        Action::Sync => carry.push("changed", target, None),
        Action::Conflict | Action::Blocked => {
            attention.push(&change.action.to_string(), target, change.note.as_deref());
        }
    }
}

/// The label of a row a question stands about.
const fn asked_label(asked: Asked) -> &'static str {
    match asked {
        Asked::Edited => "edited",
        Asked::Mode => "mode",
        Asked::Region => "region",
        Asked::Retargeted => "retargeted",
        Asked::Deleted => "deleted",
    }
}

/// What an activation step is called in a row.
fn activation_subject(step: &activation::Step) -> String {
    let shell = match step.shell {
        crate::shell::Shell::Zsh => "",
        crate::shell::Shell::Bash => " for bash",
    };
    format!("activation `{}`{shell}", step.decl.name)
}

/// The block about the config repo's branch, when it is a git repository.
fn branch_text(facts: &Facts) -> Option<String> {
    let at = &facts.repo;
    let commits = |n: u64| if n == 1 { "commit" } else { "commits" };
    Some(match &facts.branch {
        Branch::NotGit => return None,
        Branch::Unknown(why) => format!("{why}\n"),
        Branch::Detached => format!(
            "HEAD detached in {at}\n{HINT}(use \"git -C {at} switch <branch>\" to check one \
             out; \"bx sync\" needs one)\n"
        ),
        Branch::NoUpstream { name } => format!(
            "On branch {name}\nYour branch has no upstream.\n{HINT}(use \"git -C {at} branch \
             --set-upstream-to=<remote>/<branch>\" to set one; \"bx sync\" needs one)\n"
        ),
        Branch::Gone { name, upstream } => format!(
            "On branch {name}\nYour branch is based on '{upstream}', but the upstream is \
             gone.\n{HINT}(use \"git -C {at} push --set-upstream\" to publish it)\n"
        ),
        Branch::Tracking {
            name,
            upstream,
            ahead,
            behind,
        } => {
            let state = match (ahead, behind) {
                (0, 0) => format!("Your branch is up to date with '{upstream}'."),
                (ahead, 0) => format!(
                    "Your branch is ahead of '{upstream}' by {ahead} {}.\n{HINT}(use \"bx \
                     sync\" to publish them)",
                    commits(*ahead)
                ),
                (0, behind) => format!(
                    "Your branch is behind '{upstream}' by {behind} {}.\n{HINT}(use \"bx \
                     sync\" to fast-forward it)",
                    commits(*behind)
                ),
                (ahead, behind) => format!(
                    "Your branch and '{upstream}' have diverged,\nand have {ahead} and {behind} \
                     different commits each, respectively.\n{HINT}(\"bx sync\" only \
                     fast-forwards: merge or rebase it with git)"
                ),
            };
            format!("On branch {name}\n{state}\n")
        }
    })
}

/// The block about an interrupted session, or a running apply, with every
/// row the session left: while one stands, no configured target is decided.
fn interrupted_text(report: &Report) -> Option<String> {
    if report.apply_running {
        return Some(format!(
            "A bx apply is running.\n{HINT}(use \"bx status\" once it finishes)\n"
        ));
    }
    let interrupted = report.interrupted.as_ref()?;
    let kind = interrupted.kind;
    let mut out = if interrupted.unreadable {
        format!(
            "An interrupted bx session left a journal bx cannot read.\n{HINT}(use \"bx apply\" \
             to set it aside)\n"
        )
    } else if interrupted.blocked().next().is_some() {
        format!(
            "An interrupted bx {kind} left files bx cannot account for.\n{HINT}(use \"bx \
             plan\" to see them, \"bx abandon\" to set the session aside)\n"
        )
    } else if interrupted.complete {
        format!(
            "An interrupted bx {kind} wrote everything but did not record it.\n{HINT}(use \"bx \
             apply\" to record it)\n"
        )
    } else {
        format!("An interrupted bx {kind} was found.\n{HINT}(use \"bx apply\" to roll it back)\n")
    };
    for change in &report.changes {
        let _ = writeln!(
            out,
            "{}",
            row(&change.action.to_string(), &change.target, None)
        );
    }
    Some(out)
}

/// The short form: one line for each row that is not unchanged, its
/// [`Action::symbol`] and then its target, in row order, activations last.
#[must_use]
pub fn short(report: &Report) -> String {
    let mut out = String::new();
    for change in &report.changes {
        if change.action != Action::Unchanged {
            let _ = writeln!(out, "{} {}", change.action.symbol(), escape(&change.target));
        }
    }
    for step in report.activations.steps() {
        let action = step.action();
        if action != Action::Unchanged {
            let _ = writeln!(
                out,
                "{} {}",
                action.symbol(),
                escape(&activation_subject(step))
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::Origin;
    use crate::journal::SessionKind;
    use crate::paths::Portable;
    use crate::plan::Question;
    use crate::recover::{Interrupted, Standing, Unfinished};

    const HOME: &str = "/home/u";

    fn change(target: &str, action: Action, note: Option<&str>) -> Change {
        Change {
            target: target.to_string(),
            origin: Origin {
                file: PathBuf::from(HOME).join(".config/bx/bx.toml"),
                line: 1,
            },
            action,
            diff: None,
            note: note.map(str::to_string),
        }
    }

    fn facts(branch: Branch) -> Facts {
        Facts {
            repo: "~/.config/bx".to_string(),
            branch,
            uncommitted: Vec::new(),
            unasked: None,
            due: false,
        }
    }

    fn question(row: usize, asked: Asked) -> Question {
        Question {
            row,
            three_way: None,
            asked,
            save: None,
        }
    }

    fn long_of(report: &Report, facts: &Facts) -> String {
        long(report, facts, Path::new(HOME))
    }

    #[test]
    fn a_converged_machine_outside_git_says_only_that_it_matches() {
        let report = Report {
            changes: vec![change("~/.a", Action::Unchanged, None)],
            ..Report::default()
        };
        assert_eq!(
            long_of(&report, &facts(Branch::NotGit)),
            "nothing to apply, this machine matches the configuration\n"
        );
        assert_eq!(short(&report), "", "an unchanged row is not a line");
    }

    #[test]
    fn every_section_is_said_in_git_status_form_with_the_command_that_moves_it() {
        let report = Report {
            changes: vec![
                change("~/.config/starship.toml", Action::Create, None),
                change("~/.gitconfig", Action::Modify, None),
                change("~/.zshrc", Action::Conflict, Some("edited since; asked")),
                change("~/.config/foo", Action::Unchanged, Some("deleted: asked")),
                change("~/.bashrc", Action::Unchanged, Some("kept")),
                change("~/.config/nvim/lazy-lock.json", Action::Sync, Some("carry")),
                change("~/.old", Action::Undo, None),
                change(
                    "~/.config/x",
                    Action::Conflict,
                    Some("exists and bx does not own it"),
                ),
                change("~/.y", Action::Blocked, Some("needs git")),
                change("~/.z", Action::Unchanged, None),
            ],
            questions: vec![question(2, Asked::Edited), question(3, Asked::Deleted)],
            kept: vec![4],
            ..Report::default()
        };
        let facts = Facts {
            uncommitted: vec![Uncommitted {
                path: PathBuf::from(HOME).join(".config/bx/files/rc"),
                carry: Carry::Save,
            }],
            due: true,
            ..facts(Branch::Tracking {
                name: "main".to_string(),
                upstream: "origin/main".to_string(),
                ahead: 2,
                behind: 0,
            })
        };
        assert_eq!(
            long_of(&report, &facts),
            r#"On branch main
Your branch is ahead of 'origin/main' by 2 commits.
  (use "bx sync" to publish them)

Changes to apply:
  (use "bx apply" to write them, "bx plan" to see the diffs)
        create:   ~/.config/starship.toml
        modify:   ~/.gitconfig

Edited on this machine since bx wrote them:
  (use "bx add <path>" to save your edit into the config repo)
  (use "bx apply" to choose between yours and bx's)
        edited:   ~/.zshrc
        deleted:  ~/.config/foo
        kept:     ~/.bashrc

Tracked files to carry:
  (use "bx sync" to commit and push them)
        changed:  ~/.config/nvim/lazy-lock.json
        saved:    ~/.config/bx/files/rc

No longer declared:
  (use "bx apply" to take them back)
        undo:     ~/.old

Needs attention:
        conflict: ~/.config/x  (exists and bx does not own it)
        blocked:  ~/.y  (needs git)

Externals due for an update check (use "bx update")
"#
        );
        assert_eq!(
            short(&report),
            "+ ~/.config/starship.toml\n~ ~/.gitconfig\n! ~/.zshrc\n\
             < ~/.config/nvim/lazy-lock.json\n- ~/.old\n! ~/.config/x\n? ~/.y\n"
        );
    }

    #[test]
    fn a_deletion_is_labelled_as_one_and_an_undeclared_file_names_bx_rm() {
        let report = Report {
            changes: vec![
                change("~/.a", Action::Modify, Some("deleted: the repo's copy")),
                change("~/.b", Action::Sync, Some("deleted: this machine's copy")),
                change("~/.c", Action::Release, None),
                change("~/.d", Action::Undeclared, Some("bx rm releases it")),
                change("~/.e", Action::Unchanged, None),
                change("~/.f", Action::Unchanged, None),
                change("~/.g", Action::Unchanged, None),
                change("~/.h", Action::Unchanged, None),
            ],
            questions: vec![
                question(4, Asked::Mode),
                question(5, Asked::Region),
                question(6, Asked::Retargeted),
            ],
            ..Report::default()
        };
        let facts = Facts {
            uncommitted: vec![
                Uncommitted {
                    path: PathBuf::from(HOME).join(".config/bx/lock"),
                    carry: Carry::Copy,
                },
                Uncommitted {
                    path: PathBuf::from(HOME).join(".config/bx/gone"),
                    carry: Carry::Removal,
                },
            ],
            ..facts(Branch::NotGit)
        };
        let shown = long_of(&report, &facts);
        for line in [
            "        delete:   ~/.a\n",
            "        deleted:  ~/.b\n",
            "        release:  ~/.c\n",
            "        undeclared: ~/.d\n",
            "        mode:     ~/.e\n",
            "        region:   ~/.f\n",
            "        retargeted: ~/.g\n",
            "        carried:  ~/.config/bx/lock\n",
            "        removed:  ~/.config/bx/gone\n",
            "  (use \"bx rm <path>\" to stop managing one apply leaves alone)\n",
        ] {
            assert!(shown.contains(line), "{line:?} in {shown}");
        }
        assert!(!shown.contains("~/.h"), "an unchanged row is not said");
        assert!(!shown.contains("nothing to apply"), "{shown}");
    }

    #[test]
    fn only_carrying_left_still_matches_the_configuration() {
        let report = Report {
            changes: vec![change("~/.lock", Action::Sync, None)],
            ..Report::default()
        };
        let shown = long_of(&report, &facts(Branch::NotGit));
        assert!(
            shown.ends_with(
                "        changed:  ~/.lock\n\n\
                 nothing to apply, this machine matches the configuration\n"
            ),
            "{shown}"
        );
    }

    #[test]
    fn a_kept_answer_or_an_undeclared_file_still_matches_the_configuration() {
        let report = Report {
            changes: vec![
                change("~/.bashrc", Action::Unchanged, Some("kept")),
                change("~/.d", Action::Undeclared, Some("bx rm releases it")),
            ],
            kept: vec![0],
            ..Report::default()
        };
        let shown = long_of(&report, &facts(Branch::NotGit));
        for line in [
            "        kept:     ~/.bashrc\n",
            "        undeclared: ~/.d\n",
        ] {
            assert!(shown.contains(line), "{line:?} in {shown}");
        }
        assert!(
            shown.ends_with("nothing to apply, this machine matches the configuration\n"),
            "{shown}"
        );
    }

    #[test]
    fn a_target_s_control_characters_are_spelled_out() {
        let report = Report {
            changes: vec![change("~/.a\x1b[31m", Action::Blocked, Some("b\nc"))],
            ..Report::default()
        };
        let shown = long_of(&report, &facts(Branch::NotGit));
        assert!(
            shown.contains("        blocked:  ~/.a\\x1b[31m  (b\\nc)\n"),
            "{shown}"
        );
        assert_eq!(short(&report), "? ~/.a\\x1b[31m\n");
    }

    #[test]
    fn the_branch_is_said_as_git_says_it() {
        let tracking = |ahead, behind| Branch::Tracking {
            name: "main".to_string(),
            upstream: "origin/main".to_string(),
            ahead,
            behind,
        };
        let first = |branch: Branch| {
            let shown = long_of(&Report::default(), &facts(branch));
            let (head, rest) = shown.split_once("\n\n").expect("a branch block");
            assert_eq!(
                rest, "nothing to apply, this machine matches the configuration\n",
                "{shown}"
            );
            head.to_string()
        };
        assert_eq!(
            first(tracking(0, 0)),
            "On branch main\nYour branch is up to date with 'origin/main'."
        );
        assert_eq!(
            first(tracking(1, 0)),
            "On branch main\nYour branch is ahead of 'origin/main' by 1 commit.\n  \
             (use \"bx sync\" to publish them)"
        );
        assert_eq!(
            first(tracking(0, 1)),
            "On branch main\nYour branch is behind 'origin/main' by 1 commit.\n  \
             (use \"bx sync\" to fast-forward it)"
        );
        assert_eq!(
            first(tracking(0, 3)),
            "On branch main\nYour branch is behind 'origin/main' by 3 commits.\n  \
             (use \"bx sync\" to fast-forward it)"
        );
        assert_eq!(
            first(tracking(2, 3)),
            "On branch main\nYour branch and 'origin/main' have diverged,\nand have 2 and 3 \
             different commits each, respectively.\n  (\"bx sync\" only fast-forwards: merge \
             or rebase it with git)"
        );
        assert_eq!(
            first(Branch::NoUpstream {
                name: "main".to_string()
            }),
            "On branch main\nYour branch has no upstream.\n  (use \"git -C ~/.config/bx \
             branch --set-upstream-to=<remote>/<branch>\" to set one; \"bx sync\" needs one)"
        );
        assert_eq!(
            first(Branch::Gone {
                name: "main".to_string(),
                upstream: "origin/main".to_string()
            }),
            "On branch main\nYour branch is based on 'origin/main', but the upstream is \
             gone.\n  (use \"git -C ~/.config/bx push --set-upstream\" to publish it)"
        );
        assert_eq!(
            first(Branch::Detached),
            "HEAD detached in ~/.config/bx\n  (use \"git -C ~/.config/bx switch <branch>\" \
             to check one out; \"bx sync\" needs one)"
        );
        assert_eq!(first(Branch::Unknown("why.".to_string())), "why.");
    }

    #[test]
    fn a_sync_question_s_failure_is_said_in_a_sentence_s_words() {
        let spawn = sync::Error::Git(git::Error::Spawn {
            args: "status".to_string(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        });
        assert!(
            sync_note(&spawn).starts_with("git could not be started: "),
            "{}",
            sync_note(&spawn)
        );
        let other = sync::Error::NoUpstream {
            repo: PathBuf::from(HOME).join(".config/bx"),
            branch: "main".to_string(),
        };
        assert_eq!(sync_note(&other), other.to_string());
        assert!(!sync_note(&other).is_empty());
    }

    #[test]
    fn git_that_cannot_say_what_is_uncommitted_is_said() {
        let facts = Facts {
            unasked: Some("git could not be started".to_string()),
            ..facts(Branch::NotGit)
        };
        let shown = long_of(&Report::default(), &facts);
        assert!(
            shown.starts_with(
                "git could not say which files bx carried into ~/.config/bx are uncommitted: \
                 git could not be started.\n"
            ),
            "{shown}"
        );
    }

    fn unfinished(resolvable: bool) -> Unfinished {
        Unfinished {
            target: Portable::parse_in("~/.a", Path::new(HOME)).expect("portable"),
            dest: PathBuf::from(HOME).join(".a"),
            standing: if resolvable {
                Standing::Written
            } else {
                Standing::Diverged
            },
            resolvable,
            note: "note".to_string(),
        }
    }

    #[test]
    fn an_interrupted_session_is_all_that_is_said_beside_the_branch() {
        let session = |complete, unreadable, resolvable| Report {
            changes: vec![change("~/.a", Action::Undo, None)],
            interrupted: Some(Interrupted {
                kind: SessionKind::Apply,
                journal: PathBuf::from(HOME).join(".local/state/bx/journal"),
                complete,
                unreadable,
                unfinished: vec![unfinished(resolvable)],
            }),
            ..Report::default()
        };
        let shown = |report: &Report| long_of(report, &facts(Branch::NotGit));
        assert_eq!(
            shown(&session(false, false, true)),
            "An interrupted bx apply was found.\n  (use \"bx apply\" to roll it back)\n        \
             undo:     ~/.a\n"
        );
        assert!(shown(&session(true, false, true)).starts_with(
            "An interrupted bx apply wrote everything but did not record it.\n  (use \"bx \
                 apply\" to record it)\n"
        ));
        assert!(shown(&session(false, true, true)).starts_with(
            "An interrupted bx session left a journal bx cannot read.\n  (use \"bx apply\" \
                 to set it aside)\n"
        ));
        assert!(shown(&session(false, false, false)).starts_with(
            "An interrupted bx apply left files bx cannot account for.\n  (use \"bx plan\" \
                 to see them, \"bx abandon\" to set the session aside)\n"
        ));
        let running = Report {
            changes: vec![change("~/.a", Action::Create, None)],
            apply_running: true,
            ..Report::default()
        };
        assert_eq!(
            long_of(
                &running,
                &facts(Branch::Tracking {
                    name: "main".to_string(),
                    upstream: "origin/main".to_string(),
                    ahead: 0,
                    behind: 0,
                })
            ),
            "On branch main\nYour branch is up to date with 'origin/main'.\n\nA bx apply is \
             running.\n  (use \"bx status\" once it finishes)\n"
        );
    }
}
