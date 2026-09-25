//! Expanding a `tree = "…"` target into one target per file.
//!
//! A tree names a directory in the config repo, and what it declares is every
//! file beneath it. That list is only known by reading the repo, which the
//! parser never does, so [`super::parse_str`] records each tree as written and
//! [`expand`] turns it into targets as [`super::load_layer`] loads the layer.
//! From there on an expanded file is an ordinary target: it merges by its path,
//! a later layer's `[[target]]` for that path replaces it and a later toggle
//! flips it, and `plan` and `apply` decide it as they decide any other.
//!
//! # Order
//!
//! Every entry beneath the root is listed, and the list is sorted by the bytes
//! of each path relative to the root — the order `filename_bytes` gives the
//! module layers, applied to whole relative paths rather than names, so `a.b`
//! sorts before `a/x` however the directory happens to list them. The
//! expanded targets take the tree's place among its layer's targets in that
//! order, so the plan and every record written from it are the same on every
//! run and every machine.
//!
//! # What each entry becomes
//!
//! - A regular file: a `file` body naming it, at the tree's `mode`, or with no
//!   `mode` at `0755` when its owner may execute it and `0644` otherwise.
//! - A symlink: a `symlink` body holding the link's text as written, never
//!   followed, so a link to a directory is a link and not a subtree.
//! - A directory: nothing of its own; its entries are listed. An empty one
//!   expands to nothing, and a directory the files need is made as any
//!   target's parent is, at the default mode unless a `dir = true` target
//!   declares it.
//! - Anything else — a FIFO, a socket, a device — is a load error naming it.
//!
//! An entry `exclude` matches is left out, and a directory it matches is not
//! listed. A name that is not UTF-8, or that holds a `{{`, which resolution
//! would read as a placeholder, is a load error naming it.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::target::{Attach, Body, Format, Mode, Target, Tree};
use super::{Config, Error};
use crate::paths::Portable;

/// One pattern of a tree's `exclude`.
///
/// `*` matches any run of characters within one path component and `?` any
/// one character; `**` as a whole component matches any number of components,
/// none included. A pattern with no `/` is matched against an entry's name, so
/// `*.md` leaves out every Markdown file at any depth; a pattern with a `/` is
/// matched against the whole path relative to the tree's root, so
/// `docs/*.md` leaves out only those directly in `docs`. A pattern that
/// matches a directory leaves out everything beneath it. A pattern that
/// matches nothing is not an error.
///
/// The rest of glob syntax is refused rather than read literally: `[`, `]`,
/// `{`, `}`, `\` and a leading `!` each mean something in some glob dialect,
/// and taking one literally now would change what an existing pattern matches
/// the day it is supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob(String);

impl Glob {
    /// Parse one pattern as written.
    ///
    /// # Errors
    ///
    /// A message naming what is wrong with it.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let refuse = |why: &str| Err(format!("`exclude` pattern {raw:?} {why}"));
        if raw.is_empty() {
            return refuse("is empty, and matches no entry");
        }
        if raw.starts_with('!') {
            return refuse(
                "starts with `!`; a tree has no re-include, so drop the pattern instead",
            );
        }
        if let Some(bad) = raw
            .chars()
            .find(|c| matches!(c, '[' | ']' | '{' | '}' | '\\'))
        {
            return refuse(&format!(
                "holds `{bad}`, which bx does not support in a pattern: use `*`, `?` and `**`"
            ));
        }
        if raw.starts_with('/') || raw.ends_with('/') {
            return refuse(
                "starts or ends with `/`; a pattern is relative to the tree's root and names \
                 an entry, file or directory alike",
            );
        }
        for part in raw.split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return refuse("has an empty, `.` or `..` component");
            }
            if part.contains("**") && part != "**" {
                return refuse("uses `**` inside a component; `**` stands alone between `/`s");
            }
        }
        Ok(Self(raw.to_string()))
    }

    /// Whether the entry at `rel`, relative to the tree's root, is left out.
    #[must_use]
    pub fn matches(&self, rel: &str) -> bool {
        let pattern: Vec<&str> = self.0.split('/').collect();
        if let [one] = pattern.as_slice() {
            let name = rel.rsplit('/').next().unwrap_or(rel);
            return component(one.as_bytes(), name.as_bytes());
        }
        let path: Vec<&str> = rel.split('/').collect();
        components(&pattern, &path)
    }
}

impl std::fmt::Display for Glob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether the components of a pattern match those of a path, `**` matching
/// any number of them.
fn components(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|skip| components(rest, &path[skip..])),
        Some((first, rest)) => path.split_first().is_some_and(|(name, tail)| {
            component(first.as_bytes(), name.as_bytes()) && components(rest, tail)
        }),
    }
}

/// Whether one pattern component matches one name, `*` matching any run of
/// characters and `?` any one.
///
/// On bytes, with `?` taking one whole UTF-8 character, so a name's multi-byte
/// character is one `?`.
fn component(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len())
            .filter(|at| name.get(*at).is_none_or(|byte| !is_continuation(*byte)))
            .any(|at| component(rest, &name[at..])),
        Some((b'?', rest)) => name.first().is_some_and(|_| {
            let width = 1 + name[1..]
                .iter()
                .take_while(|byte| is_continuation(**byte))
                .count();
            component(rest, &name[width..])
        }),
        Some((byte, rest)) => name.first() == Some(byte) && component(rest, &name[1..]),
    }
}

/// Whether `byte` continues a UTF-8 character rather than starting one.
const fn is_continuation(byte: u8) -> bool {
    byte & 0b1100_0000 == 0b1000_0000
}

/// The mode a tree gives a regular file its owner may execute, when the tree
/// declares none.
const EXECUTABLE: Mode = Mode::from_bits(0o755);

/// What one listed entry is.
enum Found {
    /// A regular file, and whether its owner may execute it.
    File { executable: bool },
    /// A symlink, and its text.
    Link(String),
}

/// Replace every tree in `config` with the targets it expands to, each in the
/// tree's place among the layer's targets.
///
/// # Errors
///
/// [`Error::BadValue`] at the tree's entry when its root is not a directory in
/// `repo`, or when an entry beneath it cannot be a target, naming the entry;
/// [`Error::Io`] naming the path that could not be read.
pub fn expand(config: &mut Config, repo: &Path, home: &Path) -> Result<(), Error> {
    let trees = std::mem::take(&mut config.trees);
    // Last first, so an earlier tree's place is not moved by a later one's
    // files. Two trees with one place keep their written order: the later is
    // inserted first and the earlier lands ahead of it.
    for tree in trees.iter().rev() {
        let files = expand_one(tree, repo, home)?;
        let at = tree.at.min(config.targets.len());
        config.targets.splice(at..at, files);
    }
    Ok(())
}

/// The targets one tree expands to, in order.
fn expand_one(tree: &Tree, repo: &Path, home: &Path) -> Result<Vec<Target>, Error> {
    let bad = |message: String| Error::BadValue {
        origin: tree.origin.clone(),
        message,
    };
    let base = repo.join(&tree.root);
    match std::fs::symlink_metadata(&base) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(bad(format!(
                "tree = {:?} names {}, which is not a directory; a tree mirrors a directory \
                 in the config repo, and a symlink to one is not followed",
                tree.root.display(),
                base.display()
            )));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(bad(format!(
                "tree = {:?} names {}, which does not exist",
                tree.root.display(),
                base.display()
            )));
        }
        Err(source) => return Err(Error::Io { path: base, source }),
    }

    let mut found = Vec::new();
    walk(tree, &base, "", &mut found)?;
    found.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

    found
        .into_iter()
        .map(|(rel, what)| {
            let shown = format!("{}/{rel}", tree.root.display());
            let raw = format!("{}/{rel}", tree.path.as_str());
            let path = Portable::parse_in(&raw, home)
                .map_err(|e| bad(format!("{shown} cannot be a target: {e}")))?;
            let (body, mode) = match what {
                Found::File { executable } => (
                    Body::File(tree.root.join(&rel)),
                    Some(tree.mode.unwrap_or(if executable {
                        EXECUTABLE
                    } else {
                        Mode::DEFAULT_FILE
                    })),
                ),
                Found::Link(text) => {
                    super::target::check_link_text(&text).map_err(|message| {
                        bad(format!("{shown} is a symlink bx cannot make: {message}"))
                    })?;
                    (Body::Symlink(text), None)
                }
            };
            super::target::refuse_file_at_home_or_above(&raw, &path, &body, home)
                .map_err(|message| bad(format!("{shown}: {message}")))?;
            Ok(Target {
                path,
                body,
                mode,
                attach: Attach::Own,
                direction: tree.direction,
                format: Format::Opaque,
                requires: tree.requires.clone(),
                references: Vec::new(),
                enabled: tree.enabled,
                origin: tree.origin.clone(),
            })
        })
        .collect()
}

/// List every entry beneath `dir`, whose path relative to the tree's root is
/// `prefix`, into `found`, leaving out what `exclude` matches.
fn walk(
    tree: &Tree,
    dir: &Path,
    prefix: &str,
    found: &mut Vec<(String, Found)>,
) -> Result<(), Error> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| Error::Io { path, source }
    };
    let bad = |message: String| Error::BadValue {
        origin: tree.origin.clone(),
        message,
    };
    for entry in std::fs::read_dir(dir).map_err(io(dir))? {
        let entry = entry.map_err(io(dir))?;
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(bad(format!(
                "{} has a name that is not UTF-8, which no target path can spell",
                path.display()
            )));
        };
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if tree.exclude.iter().any(|glob| glob.matches(&rel)) {
            continue;
        }
        if rel.contains("{{") {
            return Err(bad(format!(
                "{} holds `{{{{` in its name, which bx would read as a placeholder; rename \
                 it or exclude it",
                path.display()
            )));
        }
        let meta = std::fs::symlink_metadata(&path).map_err(io(&path))?;
        let kind = meta.file_type();
        if kind.is_dir() {
            walk(tree, &path, &rel, found)?;
        } else if kind.is_file() {
            let executable = meta.permissions().mode() & 0o100 != 0;
            found.push((rel, Found::File { executable }));
        } else if kind.is_symlink() {
            let text = std::fs::read_link(&path).map_err(io(&path))?;
            let Ok(text) = text.into_os_string().into_string() else {
                return Err(bad(format!(
                    "{} is a symlink whose text is not UTF-8, which bx cannot carry",
                    path.display()
                )));
            };
            if text.contains("{{") {
                return Err(bad(format!(
                    "{} is a symlink whose text holds `{{{{`, which bx would read as a \
                     placeholder; exclude it or declare the link as its own target",
                    path.display()
                )));
            }
            found.push((rel, Found::Link(text)));
        } else {
            return Err(bad(format!(
                "{} is neither a regular file, a directory nor a symlink, so a tree cannot \
                 mirror it; exclude it",
                path.display()
            )));
        }
    }
    Ok(())
}
