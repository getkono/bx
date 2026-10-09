//! `bx.lock`: the commit each followed `[[external]]` is kept at.
//!
//! An external that follows a branch ([`super::external::Pin::Follow`]) names
//! no commit in the configuration. Its commit is here, in a file beside
//! `bx.toml` that is committed with the rest of the config repo, so every
//! machine syncing the repo checks out the same commit, and the history of
//! what moved, and when, is the repo's own `git log`.
//!
//! # Format
//!
//! ```toml
//! # Written by `bx update`. …
//!
//! [[external]]
//! path   = "~/.local/share/skills"
//! url    = "https://github.com/o/skills"
//! branch = "master"
//! rev    = "d93f06d…"
//! ```
//!
//! One entry per followed external, sorted by `path`, each holding the `url`
//! and `branch` it was locked for. The bytes are a function of the entries
//! alone, so writing the same lock twice changes nothing (Invariant 3).
//!
//! # Who writes it
//!
//! `bx update`, and nothing else. `plan` and `apply` only read it: an entry
//! whose `url` or `branch` no longer matches the declaration, or a followed
//! external with no entry at all, is a row blocked on `bx update`, never a
//! guess. An entry for a path no external follows any more is left alone by
//! `apply` and dropped by the next `bx update`.
//!
//! `bx update` locks only a follow the committed layers declare, since the
//! file is shared by every account: one that `local.toml` alone declares, or
//! points at another url or branch than they do, is never locked. It stays
//! blocked until a `rev` pins it or, for one `local.toml` alone declares, a
//! committed layer declares it ([`crate::update`]).
//!
//! The file is TOML rather than MessagePack, the format of bx's other
//! machine-written files, because it is committed: a lock is reviewed in a
//! diff before it is pushed. A file that does not parse is a load error naming
//! its line, like any layer file, rather than something bx recomputes: which
//! commit to keep is a decision someone made, not a cache.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};

use super::external::{self, External};
use super::{Ctx, Error};
use crate::paths::Portable;

/// The lock's file name, at the top of the config repo.
pub const FILE: &str = "bx.lock";

/// The section header, as messages spell it.
const SECTION: &str = "[[external]] in bx.lock";

/// Every key an entry carries, each required.
const KEYS: [&str; 4] = ["path", "url", "branch", "rev"];

/// The comment the file opens with.
const HEADER: &str = "\
# Written by `bx update`: the commit each [[external]] that follows a branch
# is kept at. Commit it with the configuration. To follow a different branch,
# change the [[external]] declaration and run `bx update`; to hold a commit,
# pin the declaration with `rev` instead.
";

/// What one entry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locked {
    /// The url the commit was fetched from.
    pub url: String,
    /// The branch it was the tip of.
    pub branch: String,
    /// The full commit id.
    pub rev: String,
}

/// Every entry in `bx.lock`, keyed by the external's path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lock {
    entries: BTreeMap<Portable, Locked>,
}

/// What the lock says about one followed external.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// The commit locked for this url and branch.
    Locked(&'a str),
    /// No entry for the path.
    Missing,
    /// An entry for another url or branch: the declaration changed since the
    /// lock was written.
    Stale(&'a Locked),
}

impl Lock {
    /// The lock in the config repo at `repo`, or an empty one when there is no
    /// file.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the file is there and cannot be read, and the
    /// parse errors [`Lock::parse`] names.
    pub fn read(repo: &Path, home: &Path) -> Result<Self, Error> {
        let path = repo.join(FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text, &path, home),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(Error::Io { path, source }),
        }
    }

    /// Parse the text of a lock file at `file`.
    ///
    /// # Errors
    ///
    /// [`Error::Syntax`] for text that is not TOML, and an error at the line
    /// for a section other than `[[external]]`, an unknown or missing key, a
    /// path that is not one an external could have, a url or a branch an
    /// external would be refused for, a `rev` that is not a full commit id,
    /// and a path written twice.
    pub fn parse(text: &str, file: &Path, home: &Path) -> Result<Self, Error> {
        let doc = text
            .parse::<DocumentMut>()
            .map_err(|source| Error::Syntax {
                file: file.to_path_buf(),
                source: Box::new(source),
            })?;
        let mut entries = BTreeMap::new();
        for (name, item) in doc.as_table() {
            let origin = || {
                doc.as_table()
                    .key(name)
                    .and_then(toml_edit::Key::span)
                    .map_or_else(
                        || super::Origin::unknown(file),
                        |s| super::Origin::at(file, text, &s),
                    )
            };
            let Some(tables) = item.as_array_of_tables().filter(|_| name == "external") else {
                return Err(Error::UnknownSection {
                    origin: origin(),
                    section: name.to_string(),
                });
            };
            for table in tables {
                let (path, locked) = parse_entry(table, file, text, home)?;
                if entries.contains_key(&path) {
                    return Err(Ctx::new(table, file, text, SECTION).bad(
                        table,
                        "path",
                        format!("`{path}` is locked twice; one entry per external"),
                    ));
                }
                entries.insert(path, locked);
            }
        }
        Ok(Self { entries })
    }

    /// What the lock holds for `external`, judged against its declaration.
    #[must_use]
    pub fn lookup(&self, external: &External) -> Lookup<'_> {
        let Some(follow) = external.follows() else {
            return Lookup::Missing;
        };
        match self.entries.get(&external.path) {
            None => Lookup::Missing,
            Some(locked) if locked.url == external.url && locked.branch == follow.branch => {
                Lookup::Locked(&locked.rev)
            }
            Some(locked) => Lookup::Stale(locked),
        }
    }

    /// The entry for `path`, whatever it was locked for.
    #[must_use]
    pub fn get(&self, path: &Portable) -> Option<&Locked> {
        self.entries.get(path)
    }

    /// Lock `path` at `locked`, replacing any entry it had.
    pub fn set(&mut self, path: Portable, locked: Locked) {
        self.entries.insert(path, locked);
    }

    /// Drop every entry whose path `keep` refuses.
    pub fn retain(&mut self, keep: impl Fn(&Portable) -> bool) {
        self.entries.retain(|path, _| keep(path));
    }

    /// Every entry, in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&Portable, &Locked)> {
        self.entries.iter()
    }

    /// Whether the lock holds no entry.
    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The file's bytes: the header, then every entry in path order.
    #[must_use]
    pub fn render(&self) -> String {
        let mut doc = DocumentMut::new();
        let mut tables = ArrayOfTables::new();
        for (path, locked) in &self.entries {
            let mut table = Table::new();
            table.insert("path", value(path.as_str()));
            table.insert("url", value(locked.url.as_str()));
            table.insert("branch", value(locked.branch.as_str()));
            table.insert("rev", value(locked.rev.as_str()));
            tables.push(table);
        }
        if !tables.is_empty() {
            doc.insert("external", Item::ArrayOfTables(tables));
        }
        let body = doc.to_string();
        if body.is_empty() {
            HEADER.to_string()
        } else {
            format!("{HEADER}\n{body}")
        }
    }

    /// Where the lock of the config repo at `repo` lives.
    #[must_use]
    pub fn path_in(repo: &Path) -> PathBuf {
        repo.join(FILE)
    }
}

/// One `[[external]]` entry of the lock.
fn parse_entry(
    table: &Table,
    file: &Path,
    text: &str,
    home: &Path,
) -> Result<(Portable, Locked), Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;
    let raw = ctx.required_str(table, "path")?;
    let path =
        external::parse_path(raw, home).map_err(|message| ctx.bad(table, "path", message))?;
    let url = ctx.required_str(table, "url")?;
    if let Some(problem) = external::unusable_url(url) {
        return Err(ctx.bad(table, "url", format!("`{path}`: {problem}")));
    }
    let branch = ctx.required_str(table, "branch")?;
    if let Some(problem) = external::unusable_branch(branch) {
        return Err(ctx.bad(table, "branch", format!("`{path}`: {problem}")));
    }
    let rev = ctx.required_str(table, "rev")?;
    if let Some(problem) = external::unusable_rev(rev) {
        return Err(ctx.bad(table, "rev", format!("`{path}`: {problem}")));
    }
    Ok((
        path,
        Locked {
            url: url.to_string(),
            branch: branch.to_string(),
            rev: rev.to_string(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::config::external::{Check, Follow, Pin};

    const REV: &str = "0e810e5afa27acbd074398eefbe28d13005dbc15";
    const OTHER: &str = "85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5";

    fn home() -> PathBuf {
        PathBuf::from("/home/example")
    }

    fn portable(raw: &str) -> Portable {
        Portable::parse_in(raw, &home()).unwrap()
    }

    fn locked(url: &str, branch: &str, rev: &str) -> Locked {
        Locked {
            url: url.to_string(),
            branch: branch.to_string(),
            rev: rev.to_string(),
        }
    }

    fn parse(text: &str) -> Result<Lock, String> {
        Lock::parse(text, Path::new("/repo/bx.lock"), &home()).map_err(|e| e.to_string())
    }

    fn followed(path: &str, url: &str, branch: &str) -> External {
        External {
            path: portable(path),
            url: url.to_string(),
            pin: Pin::Follow(Follow {
                branch: branch.to_string(),
                check: Check::Ask,
            }),
            links: Vec::new(),
            enabled: true,
            origin: Origin::unknown(Path::new("/repo/bx.toml")),
        }
    }

    #[test]
    fn render_sorts_by_path_and_parses_back_to_the_same_lock() {
        let mut lock = Lock::default();
        lock.set(portable("~/z"), locked("https://h/o/z", "main", REV));
        lock.set(portable("~/a"), locked("git@h:o/a.git", "release/1", OTHER));
        let text = lock.render();
        assert!(text.starts_with(HEADER), "{text}");
        let a = text.find("~/a").unwrap();
        let z = text.find("~/z").unwrap();
        assert!(a < z, "sorted by path: {text}");
        assert_eq!(parse(&text).unwrap(), lock);
        assert_eq!(parse(&text).unwrap().render(), text, "byte-identical");

        assert_eq!(Lock::default().render(), HEADER);
        assert_eq!(parse(HEADER).unwrap(), Lock::default());
    }

    #[test]
    fn lookup_holds_an_entry_to_the_url_and_branch_declared() {
        let mut lock = Lock::default();
        lock.set(portable("~/a"), locked("https://h/o/a", "main", REV));
        assert_eq!(
            lock.lookup(&followed("~/a", "https://h/o/a", "main")),
            Lookup::Locked(REV)
        );
        assert!(matches!(
            lock.lookup(&followed("~/a", "https://h/o/a", "dev")),
            Lookup::Stale(entry) if entry.branch == "main"
        ));
        assert!(matches!(
            lock.lookup(&followed("~/a", "https://h/o/b", "main")),
            Lookup::Stale(_)
        ));
        assert_eq!(
            lock.lookup(&followed("~/b", "https://h/o/a", "main")),
            Lookup::Missing
        );
        let mut pinned = followed("~/a", "https://h/o/a", "main");
        pinned.pin = Pin::Rev(REV.to_string());
        assert_eq!(lock.lookup(&pinned), Lookup::Missing, "a pin reads no lock");
    }

    #[test]
    fn retain_drops_every_entry_it_refuses_and_keeps_the_rest() {
        let mut lock = Lock::default();
        lock.set(portable("~/a"), locked("https://h/o/a", "main", REV));
        lock.set(portable("~/b"), locked("https://h/o/b", "main", REV));
        lock.retain(|path| path.as_str() == "~/a");
        assert_eq!(
            lock.iter()
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>(),
            [portable("~/a")]
        );
        assert!(lock.get(&portable("~/a")).is_some());
        assert!(lock.get(&portable("~/b")).is_none());
        assert!(!lock.is_empty());
        assert_eq!(lock.iter().count(), 1);
        lock.retain(|_| false);
        assert!(lock.is_empty());
        assert!(Lock::default().is_empty());
    }

    #[test]
    fn a_lock_that_is_not_one_is_a_load_error_at_its_line() {
        let entry = |extra: &str| {
            format!(
                "[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\nbranch = \"main\"\n\
                 rev = \"{REV}\"\n{extra}"
            )
        };
        for (text, says) in [
            ("[[external]\n".to_string(), "bx.lock"),
            ("[locks]\n".to_string(), "unknown section"),
            ("external = 1\n".to_string(), "unknown section"),
            (entry("extra = 1\n"), "unknown key `extra`"),
            (
                entry("").replace("rev = ", "commit = "),
                "unknown key `commit`",
            ),
            (entry("").replace(REV, "main"), "not a commit id"),
            (entry("").replace("\"main\"", "\"-x\""), "option"),
            (entry("").replace("https://h/o/a", "file:///a"), "transport"),
            (entry("").replace("~/a", "/opt/a"), "beneath the home"),
            (format!("{}\n{}", entry(""), entry("")), "locked twice"),
        ] {
            let err = parse(&text).unwrap_err();
            assert!(err.contains(says), "{text:?}: {err}");
        }
        let err = parse(&entry("").replace("branch = \"main\"\n", "")).unwrap_err();
        assert!(err.contains("missing the required key `branch`"), "{err}");
    }

    #[test]
    fn each_lock_error_names_the_file_and_no_line_yet() {
        let entry = |extra: &str| {
            format!(
                "[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\nbranch = \"main\"\n\
                 rev = \"{REV}\"\n{extra}"
            )
        };
        // Text that is not TOML at all is named as the parser places it, as
        // in any layer file.
        let err = parse("[[external]\n").unwrap_err();
        assert!(
            err.starts_with("/repo/bx.lock: TOML parse error at line 1, column 12"),
            "{err}"
        );
        // Every other error names the file and line 0, "position unknown":
        // the lock is parsed into a `DocumentMut`, which keeps no spans
        // (#220). Each case carries the line it should name instead.
        for (text, line) in [
            ("[locks]\n".to_string(), 1),
            ("\nexternal = 1\n".to_string(), 2),
            (entry("extra = 1\n"), 6),
            (entry("").replace("rev = ", "commit = "), 5),
            (entry("").replace(REV, "main"), 5),
            (entry("").replace("\"main\"", "\"-x\""), 4),
            (entry("").replace("https://h/o/a", "file:///a"), 3),
            (entry("").replace("~/a", "/opt/a"), 2),
            (format!("{}\n{}", entry(""), entry("")), 8),
            (entry("").replace("branch = \"main\"\n", ""), 1),
        ] {
            let err = parse(&text).unwrap_err();
            assert!(
                err.starts_with("/repo/bx.lock:0: "),
                "{text:?}, whose error belongs at line {line}: {err}"
            );
        }
    }

    /// Any lock an `[[external]]` could be given: zero to five entries, each
    /// at a path under the home, with an https or scp-style url, a branch of
    /// one or two parts and a full commit id.
    fn any_lock() -> impl proptest::strategy::Strategy<Value = Lock> {
        use proptest::prelude::*;
        let url = prop_oneof![
            "[a-z0-9]{1,8}".prop_map(|repo| format!("https://h/o/{repo}")),
            "[a-z]{1,8}".prop_map(|repo| format!("git@h:o/{repo}.git")),
        ];
        let entry = (
            "[a-z][a-z0-9]{0,6}(/[a-z][a-z0-9]{0,6})?",
            url,
            "[a-z][a-z0-9]{0,6}(/[a-z][a-z0-9]{0,6})?",
            "[0-9a-f]{40}",
        );
        proptest::collection::vec(entry, 0..5).prop_map(|entries| {
            let mut lock = Lock::default();
            for (path, url, branch, rev) in entries {
                lock.set(portable(&format!("~/{path}")), locked(&url, &branch, &rev));
            }
            lock
        })
    }

    proptest::proptest! {
        #[test]
        fn any_lock_renders_parses_and_renders_byte_identically(lock in any_lock()) {
            let text = lock.render();
            let parsed = parse(&text).map_err(proptest::test_runner::TestCaseError::fail)?;
            proptest::prop_assert_eq!(&parsed, &lock);
            proptest::prop_assert_eq!(parsed.render(), text);
        }
    }

    #[test]
    fn read_is_empty_without_a_file_and_names_one_it_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Lock::read(dir.path(), &home()).unwrap(), Lock::default());
        std::fs::create_dir(dir.path().join(FILE)).unwrap();
        let err = Lock::read(dir.path(), &home()).unwrap_err().to_string();
        assert!(err.contains("bx.lock"), "{err}");
        assert_eq!(Lock::path_in(dir.path()), dir.path().join(FILE));
    }
}
