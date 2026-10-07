//! `[[external.link]]`: an external's children, linked by name into a
//! directory beneath the home.
//!
//! A link names a directory in the checkout, and every child directory of it
//! in the commit the external is kept at becomes one symlink target: the
//! child's name in the link's `to`, holding the child's path in the checkout.
//! Once expanded, a link's targets are ordinary symlink targets — decided,
//! written, recorded and released by `bx rm` exactly as a `[[target]]` with
//! `symlink = …` is — so this module only says which children there are.
//!
//! # Read from the commit, never the working tree
//!
//! The children are listed from the commit itself, `git ls-tree` over the
//! checkout's object store, rather than by reading the directory on disk. That
//! is what lets `plan` list the children of a commit the checkout has fetched
//! but not yet moved to — which `bx update` always arranges before it shows a
//! plan — and what keeps an untracked directory someone left in the checkout
//! from being linked as if the external shipped it. Only directories are
//! children: a file, a symlink or a submodule beside them is not linked, and
//! neither is a child whose name begins with `.`, which is how a repository
//! keeps its own machinery (`.github`) out of sight.
//!
//! # When the commit is not here yet
//!
//! A checkout that is not cloned, or that does not hold the commit yet, cannot
//! say what its children are without reaching the network, which `plan` never
//! does. Such a link is **pending**: `plan` shows one row for the rule, naming
//! the commit its children will be read from, and `apply` expands it once the
//! external's own work has fetched that commit, then decides and writes those
//! links as one more step. The children are a function of the commit `plan`
//! named, so `apply` does what the row announced and nothing beyond it
//! (Invariant 7), and the next `plan` lists every child, unchanged
//! (Invariant 3). While a link is pending or its external is blocked, every
//! file bx recorded beneath its `to` counts as declared, so a link already
//! made is not reported as one nothing declares just because this run cannot
//! list it.
//!
//! # Collisions
//!
//! A child whose path a `[[target]]`, or an earlier link, already declares is
//! a conflict row and is not written: the first declaration keeps the path.

use std::collections::BTreeSet;
use std::path::Path;

use super::Change;
use crate::config::external::{External, Link};
use crate::config::lock::Lock;
use crate::config::resolve::Resolution;
use crate::config::target::{Attach, Body, Direction, Format, Target};
use crate::paths::Portable;
use crate::report::Action;
use crate::sync::Git;

/// Every link of every external, as far as this run can expand them.
#[derive(Debug, Default)]
pub(super) struct Expansion {
    /// One symlink target per child of every link whose commit is here, in
    /// external, then link, then child-name order.
    pub targets: Vec<Resolution<Target>>,
    /// A conflict row for every child some other declaration already holds,
    /// then a row for every pending rule.
    pub rows: Vec<Change>,
    /// The rules whose commit is not here yet, which `apply` expands once it
    /// is.
    pub pending: Vec<Pending>,
    /// Every link's `to` whose children this run cannot list: what is beneath
    /// them stays declared.
    pub held: Vec<Portable>,
}

/// A link whose children `apply` lists once its external's commit is here.
#[derive(Debug, Clone)]
pub(super) struct Pending {
    /// Its row, counted among [`Expansion::rows`].
    pub row: usize,
    /// The external's index in the resolved configuration.
    pub external: usize,
    /// The link's index in that external.
    pub link: usize,
    /// The commit the children are read from.
    pub rev: String,
}

/// Expand every link of `externals`.
///
/// `declared` is every path a target already declares, which a child may not
/// take.
pub(super) fn expand(
    externals: &[External],
    lock: &Lock,
    home: &Path,
    git: &Git,
    declared: &BTreeSet<&str>,
) -> Expansion {
    let mut expansion = Expansion::default();
    let mut taken: BTreeSet<String> = declared.iter().map(|path| (*path).to_string()).collect();
    let mut pending_rows = Vec::new();
    for (at, external) in externals.iter().enumerate() {
        let Ok(rev) = super::external::rev(external, lock) else {
            // The external's own row says why; nothing beneath its links is
            // reported for it in the meantime.
            expansion
                .held
                .extend(external.links.iter().map(|link| link.to.clone()));
            continue;
        };
        let dest = external.path.render(home);
        for (index, link) in external.links.iter().enumerate() {
            let Some(children) = children(git, &dest, rev, link) else {
                expansion.held.push(link.to.clone());
                pending_rows.push((
                    Pending {
                        row: 0,
                        external: at,
                        link: index,
                        rev: rev.to_string(),
                    },
                    pending_row(external, link, rev),
                ));
                continue;
            };
            for child in children {
                match link_target(external, link, &child, home) {
                    Some(target) if taken.insert(target.path.as_str().to_string()) => {
                        expansion.targets.push(Resolution::Ready(target));
                    }
                    Some(target) => expansion.rows.push(Change {
                        target: target.path.as_str().to_string(),
                        origin: link.origin.clone(),
                        action: Action::Conflict,
                        diff: None,
                        note: Some(format!(
                            "a child of `{}` in {}, which another declaration already puts \
                             here; the first one keeps it",
                            from_shown(link),
                            external.path
                        )),
                    }),
                    None => {}
                }
            }
        }
    }
    for (mut pending, row) in pending_rows {
        pending.row = expansion.rows.len();
        expansion.rows.push(row);
        expansion.pending.push(pending);
    }
    expansion
}

/// The targets of one pending link, now that its commit should be here, or
/// the note for its row when it still is not.
///
/// `declared` is every path already decided this run.
pub(super) fn expand_pending(
    external: &External,
    link: &Link,
    rev: &str,
    home: &Path,
    git: &Git,
    declared: &BTreeSet<String>,
) -> Result<Vec<Resolution<Target>>, String> {
    let dest = external.path.render(home);
    let children = children(git, &dest, rev, link).ok_or_else(|| {
        format!(
            "the checkout at {} does not hold {rev}, so the children of `{}` were not linked",
            external.path,
            from_shown(link)
        )
    })?;
    Ok(children
        .iter()
        .filter_map(|child| link_target(external, link, child, home))
        .filter(|target| !declared.contains(target.path.as_str()))
        .map(Resolution::Ready)
        .collect())
}

/// The row a pending link shows.
fn pending_row(external: &External, link: &Link, rev: &str) -> Change {
    Change {
        target: link.key(),
        origin: link.origin.clone(),
        action: Action::Create,
        diff: None,
        note: Some(format!(
            "links each child directory of `{}`{} in {} at {rev} here, once the checkout \
             holds that commit",
            from_shown(link),
            link.require
                .as_ref()
                .map_or_else(String::new, |file| format!(" holding `{file}`")),
            external.path
        )),
    }
}

/// A link's `from` as it was written.
fn from_shown(link: &Link) -> String {
    if link.from.is_empty() {
        "*".to_string()
    } else {
        format!("{}/*", link.from)
    }
}

/// The names of `link`'s children in commit `rev` of the checkout at `dest`,
/// sorted, or `None` when the checkout does not hold `rev`.
fn children(git: &Git, dest: &Path, rev: &str, link: &Link) -> Option<Vec<String>> {
    if !dest.is_dir() || super::external::own_checkout(git, dest).is_err() {
        return None;
    }
    let commit = format!("{rev}^{{commit}}");
    git.query(dest, &["cat-file", "-e", &commit]).ok()?;
    let mut args = vec!["ls-tree", "-r", "-z", "--name-only", "--full-tree", rev];
    if !link.from.is_empty() {
        args.extend(["--", link.from.as_str()]);
    }
    let listed = git.query(dest, &args).ok()?;
    let prefix = if link.from.is_empty() {
        String::new()
    } else {
        format!("{}/", link.from)
    };
    let mut children = BTreeSet::new();
    for path in listed.split('\0') {
        let Some(rest) = path.strip_prefix(&prefix) else {
            continue;
        };
        // A child is a directory: something lies beneath it.
        let Some((child, inner)) = rest.split_once('/') else {
            continue;
        };
        if !usable_name(child) {
            continue;
        }
        let wanted = link.require.as_deref().is_none_or(|file| inner == file);
        if wanted {
            children.insert(child.to_string());
        }
    }
    Some(children.into_iter().collect())
}

/// Whether `name` may become a link's name: not hidden, and nothing a path
/// or a terminal would read as more than a name.
fn usable_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.contains("{{")
        && !name
            .chars()
            .any(|c| c.is_control() || c == char::REPLACEMENT_CHARACTER)
}

/// The symlink target for `child` of `link`, or `None` when its path is not
/// one a target can have.
fn link_target(external: &External, link: &Link, child: &str, home: &Path) -> Option<Target> {
    let path = Portable::parse_in(&format!("{}/{child}", link.to), home).ok()?;
    let text = if link.from.is_empty() {
        format!("{}/{child}", external.path)
    } else {
        format!("{}/{}/{child}", external.path, link.from)
    };
    Some(Target {
        path,
        body: Body::Symlink(text),
        mode: None,
        attach: Attach::Own,
        direction: Direction::Apply,
        format: Format::Opaque,
        requires: Vec::new(),
        references: Vec::new(),
        enabled: true,
        origin: link.origin.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::config::external::Pin;
    use crate::sync::tests::{commit_all, run as git_run};
    use crate::testing::{GuardedHome, guarded_home};

    fn git(home: &Path) -> Git {
        crate::sync::tests::git(home).unattended()
    }

    /// A repository at `~/src/a` holding `files`, committed; its commit.
    fn checkout(home: &GuardedHome, files: &[&str]) -> String {
        let dir = home.child("src/a");
        std::fs::create_dir_all(&dir).unwrap();
        git_run(home.path(), &dir, &["init", "--quiet", "-b", "master"]);
        for file in files {
            let path = dir.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x\n").unwrap();
        }
        commit_all(home.path(), &dir, "files");
        git_run(home.path(), &dir, &["rev-parse", "HEAD"])
    }

    fn external(home: &GuardedHome, rev: &str, links: Vec<Link>) -> External {
        External {
            path: Portable::parse_in("~/src/a", home.path()).unwrap(),
            url: "https://h/o/a".to_string(),
            pin: Pin::Rev(rev.to_string()),
            links,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        }
    }

    fn link(home: &GuardedHome, from: &str, to: &str, require: Option<&str>) -> Link {
        Link {
            from: from.to_string(),
            to: Portable::parse_in(to, home.path()).unwrap(),
            require: require.map(str::to_string),
            origin: Origin::unknown(Path::new("bx.toml")),
        }
    }

    /// Each ready target's path and link text.
    fn links(expansion: &Expansion) -> Vec<(String, String)> {
        expansion
            .targets
            .iter()
            .map(|resolution| match resolution {
                Resolution::Ready(Target {
                    path,
                    body: Body::Symlink(text),
                    ..
                }) => (path.as_str().to_string(), text.clone()),
                other => panic!("not a link: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn every_child_directory_holding_the_required_file_is_linked_by_name() {
        let home = guarded_home();
        let rev = checkout(
            &home,
            &[
                "skills/b/SKILL.md",
                "skills/a/SKILL.md",
                "skills/a/references/x.md",
                "skills/notes/README.md",
                "skills/.hidden/SKILL.md",
                "skills/file.md",
                "skills/deep/er/SKILL.md",
                "README.md",
            ],
        );
        let ext = external(
            &home,
            &rev,
            vec![link(&home, "skills", "~/.claude/skills", Some("SKILL.md"))],
        );
        let expansion = expand(
            &[ext],
            &Lock::default(),
            home.path(),
            &git(home.path()),
            &BTreeSet::new(),
        );
        assert_eq!(
            links(&expansion),
            [
                (
                    "~/.claude/skills/a".to_string(),
                    "~/src/a/skills/a".to_string()
                ),
                (
                    "~/.claude/skills/b".to_string(),
                    "~/src/a/skills/b".to_string()
                ),
            ],
            "sorted; not a file, a hidden child, one without SKILL.md or a deeper one"
        );
        assert!(expansion.pending.is_empty() && expansion.rows.is_empty());
        assert!(expansion.held.is_empty());
    }

    #[test]
    fn without_require_every_child_directory_is_linked_and_from_may_be_the_root() {
        let home = guarded_home();
        let rev = checkout(&home, &["bin/x", "lib/y/z", "README.md"]);
        let ext = external(&home, &rev, vec![link(&home, "", "~/opt", None)]);
        let expansion = expand(
            &[ext],
            &Lock::default(),
            home.path(),
            &git(home.path()),
            &BTreeSet::new(),
        );
        assert_eq!(
            links(&expansion),
            [
                ("~/opt/bin".to_string(), "~/src/a/bin".to_string()),
                ("~/opt/lib".to_string(), "~/src/a/lib".to_string()),
            ]
        );
    }

    #[test]
    fn a_child_already_declared_is_a_conflict_the_first_declaration_keeps() {
        let home = guarded_home();
        let rev = checkout(&home, &["s/a/f", "s/b/f"]);
        let ext = external(
            &home,
            &rev,
            vec![link(&home, "s", "~/x", None), link(&home, "s", "~/x", None)],
        );
        let declared = BTreeSet::from(["~/x/a"]);
        let expansion = expand(
            &[ext],
            &Lock::default(),
            home.path(),
            &git(home.path()),
            &declared,
        );
        assert_eq!(
            links(&expansion),
            [("~/x/b".to_string(), "~/src/a/s/b".to_string())]
        );
        let conflicts: Vec<&str> = expansion
            .rows
            .iter()
            .map(|row| {
                assert_eq!(row.action, Action::Conflict);
                row.target.as_str()
            })
            .collect();
        assert_eq!(conflicts, ["~/x/a", "~/x/a", "~/x/b"]);
    }

    #[test]
    fn a_link_whose_commit_is_not_here_is_pending_and_holds_its_directory() {
        let home = guarded_home();
        let rev = checkout(&home, &["s/a/f"]);
        let absent = "b".repeat(40);
        let elsewhere = External {
            path: Portable::parse_in("~/src/none", home.path()).unwrap(),
            ..external(&home, &rev, vec![link(&home, "s", "~/y", None)])
        };
        let ext = external(&home, &absent, vec![link(&home, "s", "~/x", None)]);
        let expansion = expand(
            &[ext.clone(), elsewhere],
            &Lock::default(),
            home.path(),
            &git(home.path()),
            &BTreeSet::new(),
        );
        assert!(expansion.targets.is_empty());
        let held: Vec<&str> = expansion.held.iter().map(Portable::as_str).collect();
        assert_eq!(held, ["~/x", "~/y"]);
        assert_eq!(expansion.pending.len(), 2);
        let row = &expansion.rows[expansion.pending[0].row];
        assert_eq!(row.action, Action::Create);
        assert_eq!(row.target, "~/x/*");
        let note = row.note.as_deref().unwrap();
        assert!(
            note.contains(&format!("`s/*` in ~/src/a at {absent}")),
            "{note}"
        );

        let err = expand_pending(
            &ext,
            &ext.links[0],
            &absent,
            home.path(),
            &git(home.path()),
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert!(err.contains("does not hold"), "{err}");
        let now = expand_pending(
            &ext,
            &ext.links[0],
            &rev,
            home.path(),
            &git(home.path()),
            &BTreeSet::from(["~/x/z".to_string()]),
        )
        .unwrap();
        assert_eq!(now.len(), 1);
    }

    #[test]
    fn an_unlocked_external_holds_its_links_without_a_row() {
        let home = guarded_home();
        let mut ext = external(&home, "", vec![link(&home, "s", "~/x", Some("F"))]);
        ext.pin = Pin::Follow(crate::config::external::Follow {
            branch: "main".to_string(),
            check: crate::config::external::Check::Ask,
        });
        let expansion = expand(
            &[ext],
            &Lock::default(),
            home.path(),
            &git(home.path()),
            &BTreeSet::new(),
        );
        assert!(expansion.rows.is_empty() && expansion.targets.is_empty());
        assert_eq!(expansion.held.len(), 1);
    }

    #[test]
    fn a_name_a_link_could_not_carry_is_not_one() {
        for name in ["a", "a b", "a.b", "-a"] {
            assert!(usable_name(name), "{name}");
        }
        for name in ["", ".a", "a\nb", "{{x}}", "a\u{FFFD}"] {
            assert!(!usable_name(name), "{name:?}");
        }
    }
}
