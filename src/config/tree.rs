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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::config::target::Direction;
    use crate::config::{Layer, load_layer, load_layers, merge};
    use crate::report::Action;

    fn home() -> &'static Path {
        Path::new("/var/home/example")
    }

    /// A config repo holding `files`, each `(relative path, contents)`, with
    /// the executable ones at `0755`.
    fn repo(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().expect("a tempdir");
        for (rel, contents) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("parents");
            std::fs::write(&path, contents).expect("write");
        }
        dir
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// Load `bx.toml` from `repo`, trees expanded.
    fn load(repo: &TempDir) -> Result<Layer, Error> {
        load_layer(&repo.path().join("bx.toml"), repo.path(), home())
    }

    fn paths(layer: &Layer) -> Vec<&str> {
        layer
            .config
            .targets
            .iter()
            .map(|t| t.path.as_str())
            .collect()
    }

    fn glob(raw: &str) -> Glob {
        Glob::parse(raw).expect("a pattern")
    }

    const TREE: &str = "[[target]]\npath = \"~/.config/x\"\ntree = \"files/x\"\n";

    #[test]
    fn a_pattern_without_a_slash_matches_a_name_at_any_depth() {
        let md = glob("*.md");
        assert!(md.matches("README.md"));
        assert!(md.matches("docs/deep/notes.md"));
        assert!(!md.matches("README.mdx"));
        assert!(!md.matches("md/file"));
        assert!(glob("?.lua").matches("lua/a.lua"));
        assert!(!glob("?.lua").matches("ab.lua"));
        assert!(glob("?.txt").matches("é.txt"), "one `?` is one character");
        assert!(glob("*é").matches("café"));
        assert!(glob("cache").matches("sub/cache"));
    }

    #[test]
    fn a_pattern_with_a_slash_matches_the_whole_relative_path() {
        let docs = glob("docs/*.md");
        assert!(docs.matches("docs/a.md"));
        assert!(!docs.matches("docs/sub/a.md"), "`*` stays in one component");
        assert!(!docs.matches("other/docs/a.md"));

        let deep = glob("docs/**/*.md");
        assert!(deep.matches("docs/a.md"), "`**` matches no component too");
        assert!(deep.matches("docs/x/y/a.md"));
        assert!(!deep.matches("docs/x/y/a.lua"));
        assert!(glob("**/a").matches("x/y/a"));
        assert!(glob("a/**").matches("a/b/c"));
        assert!(!glob("a/b").matches("a"));
    }

    #[test]
    fn a_pattern_outside_the_supported_syntax_is_refused() {
        for raw in [
            "", "!keep", "[ab]", "{a,b}", "a\\b", "/abs", "dir/", "a//b", "./a", "a/../b", "a**",
            "x/**b",
        ] {
            let message = Glob::parse(raw).expect_err(raw);
            assert!(message.contains(&format!("{raw:?}")), "{raw}: {message}");
        }
        assert_eq!(glob("a/b").to_string(), "a/b");
    }

    #[test]
    fn a_tree_expands_in_byte_order_of_relative_paths() {
        let repo = repo(&[
            (
                "bx.toml",
                &format!(
                    "{}\n[[target]]\npath = \"~/.after\"\ncontent = \"\"\n",
                    TREE
                ),
            ),
            ("files/x/b", "b"),
            ("files/x/a/x", "ax"),
            ("files/x/a.b", "ab"),
            ("files/x/A", "A"),
        ]);

        let layer = load(&repo).expect("loads");
        assert_eq!(
            paths(&layer),
            [
                "~/.config/x/A",
                "~/.config/x/a.b",
                "~/.config/x/a/x",
                "~/.config/x/b",
                "~/.after",
            ],
            "`a.b` before `a/x`, and the tree's files where the tree was written"
        );
        assert!(layer.config.trees.is_empty());
        let first = &layer.config.targets[0];
        assert_eq!(first.body, Body::File(PathBuf::from("files/x/A")));
        assert_eq!(first.origin.line, 1);
        assert_eq!(first.attach, Attach::Own);
        assert_eq!(first.format, Format::Opaque);
        assert!(first.enabled);
    }

    #[test]
    fn trees_keep_their_written_place_among_targets() {
        let text = "[[target]]\npath = \"~/.first\"\ncontent = \"\"\n\n\
                    [[target]]\npath = \"~/one\"\ntree = \"one\"\n\n\
                    [[target]]\npath = \"~/two\"\ntree = \"two\"\n\n\
                    [[target]]\npath = \"~/.last\"\ncontent = \"\"\n";
        let repo = repo(&[("bx.toml", text), ("one/f", ""), ("two/f", "")]);

        let layer = load(&repo).expect("loads");
        assert_eq!(paths(&layer), ["~/.first", "~/one/f", "~/two/f", "~/.last"]);
    }

    #[test]
    fn a_file_carries_its_executable_bit_unless_the_tree_declares_a_mode() {
        let repo = repo(&[("bx.toml", TREE), ("files/x/run", ""), ("files/x/conf", "")]);
        chmod(&repo.path().join("files/x/run"), 0o744);
        chmod(&repo.path().join("files/x/conf"), 0o611);

        let layer = load(&repo).expect("loads");
        let modes: Vec<Option<Mode>> = layer.config.targets.iter().map(|t| t.mode).collect();
        assert_eq!(modes, [Some(Mode::DEFAULT_FILE), Some(EXECUTABLE)]);

        std::fs::write(
            repo.path().join("bx.toml"),
            format!("{TREE}mode = \"0600\"\ndirection = \"track\"\nrequires = [\"nvim\"]\n"),
        )
        .expect("rewrite");
        let layer = load(&repo).expect("loads");
        for target in &layer.config.targets {
            assert_eq!(target.mode, Some(Mode::PRIVATE_FILE));
            assert_eq!(target.direction, Direction::Track);
            assert_eq!(target.requires, ["nvim"]);
        }
    }

    #[test]
    fn a_symlink_in_the_tree_is_a_symlink_target_holding_its_text() {
        let repo = repo(&[
            ("bx.toml", &format!("{TREE}mode = \"0600\"\n")),
            ("files/x/sub/f", ""),
        ]);
        symlink("../elsewhere", repo.path().join("files/x/link")).expect("a link");
        symlink("sub", repo.path().join("files/x/dirlink")).expect("a link to a directory");

        let layer = load(&repo).expect("loads");
        assert_eq!(
            paths(&layer),
            [
                "~/.config/x/dirlink",
                "~/.config/x/link",
                "~/.config/x/sub/f"
            ],
            "a link to a directory is not followed"
        );
        let link = &layer.config.targets[1];
        assert_eq!(link.body, Body::Symlink("../elsewhere".to_string()));
        assert_eq!(
            link.mode, None,
            "a link has no mode, whatever the tree declares"
        );
    }

    #[test]
    fn a_link_bx_cannot_make_is_a_load_error_naming_it() {
        let repo = repo(&[("bx.toml", TREE), ("files/x/f", "")]);
        symlink("~other/x", repo.path().join("files/x/bad")).expect("a link");

        let message = load(&repo).expect_err("refused").to_string();
        assert!(message.contains("files/x/bad"), "{message}");
        assert!(message.contains("bx.toml:1"), "{message}");
    }

    #[test]
    fn a_fifo_in_the_tree_is_a_load_error_naming_it() {
        let repo = repo(&[("bx.toml", TREE), ("files/x/f", "")]);
        let fifo = repo.path().join("files/x/pipe");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .expect("a fifo");

        let message = load(&repo).expect_err("refused").to_string();
        assert!(message.contains(&fifo.display().to_string()), "{message}");

        std::fs::write(
            repo.path().join("bx.toml"),
            format!("{TREE}exclude = [\"pipe\"]\n"),
        )
        .expect("rewrite");
        assert_eq!(paths(&load(&repo).expect("excluded")), ["~/.config/x/f"]);
    }

    #[test]
    fn exclude_leaves_out_files_and_whole_directories() {
        let text = format!("{TREE}exclude = [\"*.md\", \"cache\", \"nothing-matches\"]\n");
        let repo = repo(&[
            ("bx.toml", &text),
            ("files/x/README.md", ""),
            ("files/x/docs/a.md", ""),
            ("files/x/init.lua", ""),
            ("files/x/cache/pipe-would-fail", ""),
            ("files/x/lua/cache", ""),
        ]);

        let layer = load(&repo).expect("loads");
        assert_eq!(paths(&layer), ["~/.config/x/init.lua"]);
    }

    #[test]
    fn an_empty_tree_expands_to_nothing() {
        let repo = repo(&[("bx.toml", TREE)]);
        std::fs::create_dir_all(repo.path().join("files/x/empty")).expect("dirs");

        assert!(load(&repo).expect("loads").config.targets.is_empty());
    }

    #[test]
    fn a_root_that_is_not_a_directory_is_a_load_error() {
        let missing = repo(&[("bx.toml", TREE)]);
        let message = load(&missing).expect_err("missing").to_string();
        assert!(message.contains("does not exist"), "{message}");
        assert!(message.contains("bx.toml:1"), "{message}");

        let file = repo(&[("bx.toml", TREE), ("files/x", "")]);
        let message = load(&file).expect_err("a file").to_string();
        assert!(message.contains("not a directory"), "{message}");

        let linked = repo(&[("bx.toml", TREE), ("files/real/f", "")]);
        symlink("real", linked.path().join("files/x")).expect("a link");
        let message = load(&linked).expect_err("a link").to_string();
        assert!(message.contains("not followed"), "{message}");
    }

    #[test]
    fn a_name_holding_a_placeholder_is_a_load_error() {
        let repo = repo(&[("bx.toml", TREE), ("files/x/{{a}}", "")]);
        let message = load(&repo).expect_err("refused").to_string();
        assert!(message.contains("{{a}}"), "{message}");

        let link = self::repo(&[("bx.toml", TREE), ("files/x/f", "")]);
        symlink("{{a}}", link.path().join("files/x/l")).expect("a link");
        let message = load(&link).expect_err("refused").to_string();
        assert!(message.contains("placeholder"), "{message}");
    }

    #[test]
    fn a_tree_at_the_home_expands_beneath_it() {
        let repo = repo(&[
            ("bx.toml", "[[target]]\npath = \"~\"\ntree = \"home\"\n"),
            ("home/.zshrc", ""),
        ]);

        assert_eq!(paths(&load(&repo).expect("loads")), ["~/.zshrc"]);
    }

    /// The layers of `repo`, `bx.toml` then `modules/`, merged.
    fn merged(repo: &TempDir) -> Result<Config, Error> {
        merge::merge(&load_layers(repo.path(), home())?, home())
    }

    #[test]
    fn a_later_layer_overrides_or_toggles_one_expanded_file() {
        let over = "[[target]]\npath = \"~/.config/x/b\"\nfile = \"files/x/b\"\n\
                    direction = \"track\"\n\n\
                    [[target]]\npath = \"~/.config/x/c\"\nenabled = false\n";
        let repo = repo(&[
            ("bx.toml", TREE),
            ("modules/10-over.toml", over),
            ("files/x/a", ""),
            ("files/x/b", ""),
            ("files/x/c", ""),
        ]);
        chmod(&repo.path().join("files/x/b"), 0o755);

        let config = merged(&repo).expect("merges");
        let targets: Vec<(&str, Direction, Option<Mode>)> = config
            .targets
            .iter()
            .map(|t| (t.path.as_str(), t.direction, t.mode))
            .collect();
        assert_eq!(
            targets,
            [
                ("~/.config/x/a", Direction::Apply, Some(Mode::DEFAULT_FILE)),
                ("~/.config/x/b", Direction::Track, None),
            ],
            "the override replaces the one file whole, and the toggle drops another"
        );
        assert_eq!(
            config.targets[1].origin.file,
            repo.path().join("modules/10-over.toml")
        );
    }

    /// `plan` or `apply` the repo seeded under `home`, one row per target.
    fn run(home: &crate::testing::GuardedHome, mode: crate::plan::Mode) -> Vec<(String, Action)> {
        let inputs = crate::plan::Inputs::load(&crate::plan::tests::env(home.path()))
            .expect("the inputs load");
        crate::plan::run(&inputs, mode, &mut |_| Ok(true))
            .expect("the run")
            .changes
            .into_iter()
            .map(|change| (change.target, change.action))
            .collect()
    }

    #[test]
    fn a_tree_applies_converges_and_follows_the_repo() {
        use crate::plan::Mode::{Apply, Plan};

        let home = crate::testing::guarded_home();
        crate::plan::tests::seed(home.path(), TREE);
        let files = home.child(".config/bx/files/x");
        std::fs::create_dir_all(files.join("lua")).expect("the tree");
        std::fs::write(files.join("init.lua"), "init\n").expect("a file");
        std::fs::write(files.join("lua/run"), "run\n").expect("a file");
        chmod(&files.join("lua/run"), 0o755);
        symlink("init.lua", files.join("alias")).expect("a link");

        let created = run(&home, Apply);
        assert_eq!(
            created,
            [
                ("~/.config/x/alias".to_string(), Action::Create),
                ("~/.config/x/init.lua".to_string(), Action::Create),
                ("~/.config/x/lua/run".to_string(), Action::Create),
            ]
        );
        let dest = home.child(".config/x");
        assert_eq!(
            std::fs::read_to_string(dest.join("init.lua")).expect("read"),
            "init\n"
        );
        let mode = |rel: &str| {
            std::fs::symlink_metadata(dest.join(rel))
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("init.lua"), 0o644);
        assert_eq!(mode("lua/run"), 0o755);
        assert_eq!(
            mode("lua"),
            0o755,
            "an intermediate directory at the default mode"
        );
        assert_eq!(
            std::fs::read_link(dest.join("alias")).expect("a link"),
            PathBuf::from("init.lua")
        );

        let again = run(&home, Plan);
        assert!(
            again.iter().all(|(_, action)| *action == Action::Unchanged),
            "{again:?}"
        );

        std::fs::write(files.join("added"), "new\n").expect("a new repo file");
        let added = run(&home, Plan);
        assert_eq!(
            added
                .iter()
                .filter(|(_, action)| *action != Action::Unchanged)
                .collect::<Vec<_>>(),
            [&("~/.config/x/added".to_string(), Action::Create)]
        );

        std::fs::remove_file(files.join("init.lua")).expect("a removed repo file");
        std::fs::remove_file(files.join("added")).expect("a removed repo file");
        let removed = run(&home, Apply);
        assert_eq!(
            removed
                .iter()
                .filter(|(target, _)| target.ends_with("init.lua"))
                .collect::<Vec<_>>(),
            [&("~/.config/x/init.lua".to_string(), Action::Undeclared)],
            "reported, as a file bx wrote that nothing declares any more"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("init.lua")).expect("still there"),
            "init\n",
            "a file the repo no longer holds is not deleted"
        );
    }

    #[test]
    fn one_layer_naming_an_expanded_file_again_is_a_duplicate() {
        let text = format!("{TREE}\n[[target]]\npath = \"~/.config/x/a\"\ncontent = \"\"\n");
        let repo = repo(&[("bx.toml", &text), ("files/x/a", "")]);

        let message = merged(&repo).expect_err("a duplicate").to_string();
        assert!(message.contains("~/.config/x/a"), "{message}");
    }
}
