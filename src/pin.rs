//! Pinned externals: the newest release of each, and the `rev` that names it.
//!
//! A pinned `[[external]]` is kept at the full commit id its `rev` names until
//! the configuration says another, so nothing moves it but an edit of that
//! `rev`. `bx upgrade` makes that edit: [`look`] asks the remote for its
//! release tags — `vMAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH`, as
//! [`crate::upgrade::Version`] reads them, so a pre-release is never one —
//! and finds the newest; [`rewrite`] replaces the `rev` in the layer whose
//! entry won the merge with that tag's commit, keeping every other byte.
//!
//! The version number is what orders releases, but `apply` moves a checkout
//! only forward, so a newest release that does not descend from the commit
//! pinned — a new major line cut from another branch — is said and not
//! offered: pinning it would leave a `rev` no apply can reach. A remote with
//! no release tag at all offers its default branch's tip instead, on the same
//! terms, as `bx update` takes a followed branch's.
//!
//! The new `rev` is always the full commit id, which the schema requires; the
//! tag appears only in what is said and in the commit message, and the next
//! look works the current release out again from the tags.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::external::{External, Pin};
use crate::fs::Mode;
use crate::git::checkout::{self, problem};
use crate::git::{self, Git};
use crate::paths::Portable;
use crate::upgrade::Version;

/// The subject of the commit `bx upgrade` makes for the pins it moves.
pub const SUBJECT: &str = "chore(bx): upgrade pinned externals";

/// The most commits a move lists by subject.
const LOG_LIMIT: usize = 20;

/// Why a pin could not be rewritten.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The layer could not be read.
    #[error("reading {}: {source}", .file.display())]
    Read {
        /// The layer.
        file: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The layer is no longer TOML.
    #[error("{} no longer parses as TOML: {source}", .file.display())]
    Parse {
        /// The layer.
        file: PathBuf,
        /// Why.
        #[source]
        source: toml_edit::TomlError,
    },
    /// The layer holds no `[[external]]` at the path with a `rev`.
    #[error("{} declares no [[external]] at `{path}` with a `rev`", .file.display())]
    Missing {
        /// The layer.
        file: PathBuf,
        /// The external's path.
        path: String,
    },
}

/// What a remote's releases say about one pinned external.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The external's path.
    pub path: Portable,
    /// The url declared.
    pub url: String,
    /// The commit pinned.
    pub rev: String,
    /// The layer whose entry won the merge, which holds the `rev`.
    pub file: PathBuf,
    /// What its releases mean for it.
    pub verdict: Verdict,
}

/// What a remote's newest release means for the commit pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing newer: the commit pinned is the newest release, or past it, or
    /// with no release, the default branch's tip.
    Current {
        /// The release tag at the commit pinned, when there is one.
        tag: Option<String>,
    },
    /// A commit to pin instead.
    Moves {
        /// The commit.
        tip: String,
        /// The release tag at the commit pinned, when there is one.
        from: Option<String>,
        /// The release tag at the new commit; `None` for the default
        /// branch's tip, on a remote with no release.
        to: Option<String>,
        /// The new commits' short ids and subjects, newest first, at most
        /// twenty of them; `None` when no checkout could list them.
        log: Option<Vec<String>>,
        /// How many new commits there are, when a checkout could count them.
        count: Option<u64>,
    },
    /// A newer commit that nothing shows is newer: with no release tag at the
    /// commit pinned and no checkout of bx's to order the two. Not offered.
    Unproven {
        /// The commit.
        tip: String,
        /// Its release tag, or `None` for the default branch's tip.
        to: Option<String>,
    },
    /// A newer commit that does not descend from the commit pinned, which
    /// `apply` could never move the checkout to. Not offered.
    Rewritten {
        /// The commit.
        tip: String,
        /// Its release tag, or `None` for the default branch's tip.
        to: Option<String>,
    },
    /// The remote could not be asked.
    Unreachable(String),
}

impl Found {
    /// The commit to pin, when there is one.
    #[must_use]
    pub fn moves_to(&self) -> Option<&str> {
        match &self.verdict {
            Verdict::Moves { tip, .. } => Some(tip),
            _ => None,
        }
    }

    /// One line saying what was found, as `bx upgrade` prints it.
    #[must_use]
    pub fn summary(&self) -> String {
        let path = &self.path;
        let rev = short(&self.rev);
        match &self.verdict {
            Verdict::Current { tag: Some(tag) } => {
                format!("{path}: pinned at {tag}, the newest release")
            }
            Verdict::Current { tag: None } => {
                format!("{path}: pinned at {rev}; nothing newer is released")
            }
            Verdict::Moves {
                tip,
                from,
                to,
                count,
                ..
            } => {
                let from = from.as_deref().unwrap_or(rev);
                let moved = match to {
                    Some(to) => format!("{path}: {from} -> {to}"),
                    None => format!("{path}: no release; the default branch moved"),
                };
                let count =
                    count.map_or_else(String::new, |count| format!(", {count} new commit(s)"));
                format!("{moved}{count}, {rev} -> {}", short(tip))
            }
            Verdict::Unproven { tip, to } => format!(
                "{path}: {} is at {}, and with no checkout of bx's there is nothing to show it \
                 descends from {rev}, so it is not upgraded. Run `bx upgrade` again once \
                 `bx apply` has cloned it",
                to.as_deref().unwrap_or("the default branch"),
                short(tip)
            ),
            Verdict::Rewritten { tip, to } => {
                let tip = short(tip);
                let found = to.as_deref().map_or_else(
                    || format!("no release, and the default branch's tip {tip} does not"),
                    |to| format!("the newest release, {to}, is at {tip}, which does not"),
                );
                format!(
                    "{path}: {found} descend from {rev}; bx moves a checkout only forward, so \
                     it is not upgraded"
                )
            }
            Verdict::Unreachable(why) => format!("{path}: not checked: {why}"),
        }
    }
}

/// A commit id's first twelve digits.
fn short(rev: &str) -> &str {
    rev.get(..12).unwrap_or(rev)
}

/// Every external `names` selects, in configuration order, split into the
/// followed and the pinned: all of them when `names` is empty.
///
/// # Errors
///
/// [`crate::update::Error::NotExternal`] for a name that is no external's
/// path.
pub fn select<'a>(
    externals: &'a [External],
    names: &[String],
    home: &Path,
) -> Result<(Vec<&'a External>, Vec<&'a External>), crate::update::Error> {
    let mut chosen: Vec<&External> = Vec::new();
    if names.is_empty() {
        chosen.extend(externals);
    }
    for name in names {
        let external = crate::update::named(name, home)
            .and_then(|path| externals.iter().find(|external| external.path == path))
            .ok_or_else(|| crate::update::Error::NotExternal(name.clone()))?;
        if !chosen.iter().any(|c| c.path == external.path) {
            chosen.push(external);
        }
    }
    Ok(chosen
        .into_iter()
        .partition(|external| external.follows().is_some()))
}

/// [`look`] at each of `chosen`, with no prompt from `git` and each remote
/// bounded by [`crate::update::LOOK_BOUND`], in the order chosen.
#[must_use]
pub fn look_all(
    git: &Git,
    home: &Path,
    chosen: &[&External],
    ledger: &crate::state::LedgerView,
) -> Vec<Found> {
    chosen
        .iter()
        .map(|external| {
            let looker = git
                .clone()
                .unattended()
                .with_deadline(std::time::Instant::now() + crate::update::LOOK_BOUND);
            look(&looker, home, external, ledger)
        })
        .collect()
}

/// One release tag on a remote.
#[derive(Debug, Clone)]
struct Release {
    version: Version,
    name: String,
    commit: String,
}

/// Ask `external`'s remote for its newest release, against the commit its
/// `rev` pins.
///
/// Never fails: a remote that cannot be asked is [`Verdict::Unreachable`].
/// Only a checkout the ledger records as bx's own finished clone is fetched
/// into, as [`crate::update::look`] fetches; without one, the tags are listed
/// with `ls-remote` and nothing is fetched.
///
/// # Panics
///
/// When `external` is not pinned: only a pinned external is looked at, and
/// every caller selects those first.
#[must_use]
pub fn look(
    git: &Git,
    home: &Path,
    external: &External,
    ledger: &crate::state::LedgerView,
) -> Found {
    let Pin::Rev(rev) = &external.pin else {
        panic!("only a pinned external is looked at");
    };
    let found = |verdict| Found {
        path: external.path.clone(),
        url: external.url.clone(),
        rev: rev.clone(),
        file: external.origin.file.clone(),
        verdict,
    };
    let dest = external.path.render(home);
    let ours = crate::update::owned(git, ledger, external, &dest);
    let releases = match releases(git, home, &external.url) {
        Ok(releases) => releases,
        Err(why) => return found(Verdict::Unreachable(why)),
    };
    let Some(newest) = releases.iter().max_by_key(|release| release.version) else {
        return found(default_branch(git, home, external, rev, ours, &dest));
    };
    let current = releases
        .iter()
        .filter(|release| release.commit == *rev)
        .max_by_key(|release| release.version);
    let tag = current.map(|release| release.name.clone());
    if current.is_some_and(|c| c.version >= newest.version) {
        return found(Verdict::Current { tag });
    }
    let tip = newest.commit.clone();
    let to = Some(newest.name.clone());
    // A version number orders releases, but only history says whether every
    // other machine's checkout can be moved there.
    if !ours {
        return found(Verdict::Unproven { tip, to });
    }
    let reference = format!("refs/tags/{}", newest.name);
    if let Err(error) = git.query(
        &dest,
        &["fetch", "--quiet", "--no-tags", "origin", &reference],
    ) {
        return found(Verdict::Unreachable(problem(&error)));
    }
    found(match checkout::is_ancestor(git, &dest, rev, &tip) {
        Ok(true) => descended(git, &dest, rev, tip, tag, to),
        // Pinned past the newest release, on its line: nothing newer.
        Ok(false) if checkout::is_ancestor(git, &dest, &tip, rev).unwrap_or(false) => {
            Verdict::Current { tag }
        }
        Ok(false) => Verdict::Rewritten { tip, to },
        Err(error) => Verdict::Unreachable(problem(&error)),
    })
}

/// A move to `tip`, which descends from `rev`, with the commits between them
/// counted and listed from the checkout at `dest`.
fn descended(
    git: &Git,
    dest: &Path,
    rev: &str,
    tip: String,
    from: Option<String>,
    to: Option<String>,
) -> Verdict {
    let range = format!("{rev}..{tip}");
    let count = git
        .query(dest, &["rev-list", "--count", &range])
        .ok()
        .and_then(|count| count.parse().ok());
    let limit = format!("--max-count={LOG_LIMIT}");
    let log = git
        .query(
            dest,
            &["log", &limit, "--no-decorate", "--format=%h %s", &range],
        )
        .ok()
        .map(|log| log.lines().map(str::to_string).collect());
    Verdict::Moves {
        tip,
        from,
        to,
        log,
        count,
    }
}

/// With no release on the remote: its default branch's tip, offered only
/// once a checkout of bx's at `dest` shows it descends from `rev`.
fn default_branch(
    git: &Git,
    home: &Path,
    external: &External,
    rev: &str,
    ours: bool,
    dest: &Path,
) -> Verdict {
    let tip = match crate::update::remote_tip(git, home, &external.url, "HEAD") {
        Ok(tip) => tip,
        Err(why) => return Verdict::Unreachable(why),
    };
    if tip == rev {
        return Verdict::Current { tag: None };
    }
    if !ours {
        return Verdict::Unproven { tip, to: None };
    }
    if let Err(error) = git.query(dest, &["fetch", "--quiet", "--no-tags", "origin", "HEAD"]) {
        return Verdict::Unreachable(problem(&error));
    }
    match checkout::is_ancestor(git, dest, rev, &tip) {
        Ok(true) => descended(git, dest, rev, tip, None, None),
        Ok(false) if checkout::is_ancestor(git, dest, &tip, rev).unwrap_or(false) => {
            Verdict::Current { tag: None }
        }
        Ok(false) => Verdict::Rewritten { tip, to: None },
        Err(error) => Verdict::Unreachable(problem(&error)),
    }
}

/// Every release tag at `url`, asked with `git ls-remote` from `home`, each
/// at the commit it names: an annotated tag's peeled commit.
fn releases(git: &Git, home: &Path, url: &str) -> Result<Vec<Release>, String> {
    let listed = git
        .query(home, &["ls-remote", "--tags", url])
        .map_err(|error| problem(&error))?;
    let mut commits: BTreeMap<&str, &str> = BTreeMap::new();
    for line in listed.lines() {
        let Some((commit, name)) = line.split_once('\t') else {
            continue;
        };
        let Some(name) = name.strip_prefix("refs/tags/") else {
            continue;
        };
        match name.strip_suffix("^{}") {
            Some(tag) => {
                commits.insert(tag, commit);
            }
            None => {
                commits.entry(name).or_insert(commit);
            }
        }
    }
    Ok(commits
        .into_iter()
        .filter_map(|(name, commit)| {
            Some(Release {
                version: Version::parse(name).ok()?,
                name: name.to_string(),
                commit: commit.to_string(),
            })
        })
        .collect())
}

/// `text`, the layer `file`, with the `rev` of its `[[external]]` at `path`
/// replaced by `rev`, keeping every other byte: the value's own spacing and
/// comment, and the rest of the document.
///
/// # Errors
///
/// [`Error::Parse`] for text that is not TOML, and [`Error::Missing`] when no
/// `[[external]]` at `path` has a `rev`.
pub fn rewrite(
    text: &str,
    file: &Path,
    path: &Portable,
    home: &Path,
    rev: &str,
) -> Result<String, Error> {
    let missing = || Error::Missing {
        file: file.to_path_buf(),
        path: path.to_string(),
    };
    let mut document: toml_edit::DocumentMut = text.parse().map_err(|source| Error::Parse {
        file: file.to_path_buf(),
        source,
    })?;
    let entries = document
        .get_mut("external")
        .and_then(toml_edit::Item::as_array_of_tables_mut)
        .ok_or_else(missing)?;
    let entry = entries
        .iter_mut()
        .find(|entry| {
            entry
                .get("path")
                .and_then(toml_edit::Item::as_str)
                .and_then(|raw| Portable::parse_in(raw, home).ok())
                .is_some_and(|raw| raw == *path)
        })
        .ok_or_else(missing)?;
    let value = entry
        .get_mut("rev")
        .and_then(toml_edit::Item::as_value_mut)
        .filter(|value| value.is_str())
        .ok_or_else(missing)?;
    let decor = value.decor().clone();
    *value = toml_edit::Value::from(rev);
    *value.decor_mut() = decor;
    Ok(document.to_string())
}

/// One layer `bx upgrade` rewrites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// The layer.
    pub file: PathBuf,
    /// Its bytes now.
    pub before: String,
    /// Its bytes once every pin it holds is moved.
    pub after: String,
    /// Whether it is in the config repo, so committed; `local.toml` is not.
    pub committed: bool,
}

/// The layer edits that move every pin in `found` that moves, one per layer,
/// in the order the layers are first named; `repo` is the config repo.
///
/// # Errors
///
/// [`Error::Read`] for a layer that cannot be read, and as [`rewrite`].
pub fn edits(found: &[Found], repo: &Path, home: &Path) -> Result<Vec<Edit>, Error> {
    let mut edits: Vec<Edit> = Vec::new();
    for found in found {
        let Some(tip) = found.moves_to() else {
            continue;
        };
        let at = match edits.iter().position(|edit| edit.file == found.file) {
            Some(at) => at,
            None => {
                let before =
                    std::fs::read_to_string(&found.file).map_err(|source| Error::Read {
                        file: found.file.clone(),
                        source,
                    })?;
                edits.push(Edit {
                    file: found.file.clone(),
                    after: before.clone(),
                    before,
                    committed: found.file.starts_with(repo),
                });
                edits.len() - 1
            }
        };
        let edit = &mut edits[at];
        edit.after = rewrite(&edit.after, &edit.file, &found.path, home, tip)?;
    }
    Ok(edits)
}

/// What `edit` changes, as a unified diff headed by the layer's path, `~/`
/// for the home: shown before the plan, so the configuration bx rewrites is
/// announced as the checkouts it moves are.
#[must_use]
pub fn shown(edit: &Edit, home: &Path) -> String {
    let file = Portable::from_path(&edit.file, home)
        .map_or_else(|_| edit.file.display().to_string(), |file| file.to_string());
    crate::plan::unified(&file, ("now", "upgraded"), &edit.before, &edit.after)
}

/// Every pin in `found` that moves, at the commit it moves to: what the plan
/// is decided against before the layers are rewritten.
#[must_use]
pub fn pins(found: &[Found]) -> BTreeMap<Portable, String> {
    found
        .iter()
        .filter_map(|found| Some((found.path.clone(), found.moves_to()?.to_string())))
        .collect()
}

/// The commit message for the pins in `found` that move: what moved, by path,
/// and nothing about the machine, the account or the time.
#[must_use]
pub fn message(found: &[Found]) -> String {
    let lines: Vec<String> = found
        .iter()
        .filter_map(|found| {
            let Verdict::Moves { tip, from, to, .. } = &found.verdict else {
                return None;
            };
            let rev = short(&found.rev);
            Some(match (from, to) {
                (Some(from), Some(to)) => {
                    format!("{}: {from} -> {to} ({rev} -> {})", found.path, short(tip))
                }
                (None, Some(to)) => format!("{}: {to} ({rev} -> {})", found.path, short(tip)),
                (_, None) => format!("{}: {rev} -> {}", found.path, short(tip)),
            })
        })
        .collect();
    format!("{SUBJECT}\n\n{}\n", lines.join("\n"))
}

/// Refuse a committed layer in `edits` with changes git has not committed,
/// which the commit of the rewritten pins would sweep up. A config repo git
/// does not manage has nothing to refuse.
///
/// # Errors
///
/// [`crate::update::Error::LayerEdited`].
pub fn refuse_edited(git: &Git, repo: &Path, edits: &[Edit]) -> Result<(), crate::update::Error> {
    for edit in edits.iter().filter(|edit| edit.committed) {
        let status = git.query(
            repo,
            &[
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                &edit.file.to_string_lossy(),
            ],
        );
        if status.is_ok_and(|status| !status.is_empty()) {
            return Err(crate::update::Error::LayerEdited(edit.file.clone()));
        }
    }
    Ok(())
}

/// Write each of `edits`, and commit the committed ones in the config repo at
/// `repo` with `message`, staging those files alone. Returns whether a commit
/// was made: none when only `local.toml` changed, or the repo is not a git
/// repository of its own.
///
/// # Errors
///
/// [`crate::update::Error::Write`] when a layer cannot be written, and
/// [`crate::update::Error::Sync`] when git refuses the commit, as a failing
/// hook makes it. A commit git refuses puts every layer back as it was, and
/// unstages it, so a later `apply` never moves a checkout to a commit the
/// configuration does not name.
pub fn write_and_commit(
    git: &Git,
    repo: &Path,
    edits: &[Edit],
    message: &str,
) -> Result<bool, crate::update::Error> {
    // `local.toml` keeps the private mode `bx init` writes it with.
    let write = |edit: &Edit, bytes: &str| {
        let mode = if edit.committed {
            Mode::DEFAULT_FILE
        } else {
            Mode::PRIVATE_FILE
        };
        crate::fs::write_atomically(&edit.file, bytes.as_bytes(), mode)
            .map_err(crate::update::Error::Write)
    };
    // What was shown is what is replaced: a layer edited since — while the
    // question waited — is the user's, and none is written.
    for edit in edits {
        if std::fs::read_to_string(&edit.file).ok().as_deref() != Some(edit.before.as_str()) {
            return Err(crate::update::Error::LayerEdited(edit.file.clone()));
        }
    }
    for (at, edit) in edits.iter().enumerate() {
        if let Err(error) = write(edit, &edit.after) {
            for written in &edits[..at] {
                let _ = write(written, &written.before);
            }
            return Err(error);
        }
    }
    let files: Vec<String> = edits
        .iter()
        .filter(|edit| edit.committed)
        .map(|edit| edit.file.to_string_lossy().into_owned())
        .collect();
    if files.is_empty() || checkout::toplevel_is_self(git, repo).is_err() {
        return Ok(false);
    }
    fn with<'a>(verb: &[&'a str], files: &'a [String]) -> Vec<&'a str> {
        let mut args = verb.to_vec();
        args.push("--");
        args.extend(files.iter().map(String::as_str));
        args
    }
    let committed = git
        .query(repo, &with(&["add"], &files))
        .and_then(|_| git.commit(repo, &with(&["commit", "--quiet", "-m", message], &files)))
        .map(|_| true);
    committed.map_err(|error: git::Error| {
        let _ = git.query(repo, &with(&["reset", "--quiet"], &files));
        // Put back as far as it goes; git's refusal is what is said.
        for edit in edits {
            let _ = write(edit, &edit.before);
        }
        error.into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::origin::Origin;

    const HOME: &str = "/home/someone";
    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";

    fn portable(raw: &str) -> Portable {
        Portable::parse_in(raw, Path::new(HOME)).expect("a portable path")
    }

    fn external(path: &str, pin: Pin) -> External {
        External {
            path: portable(path),
            url: "https://example.invalid/x".to_string(),
            pin,
            links: Vec::new(),
            enabled: true,
            origin: Origin::unknown(Path::new("/repo/bx.toml")),
        }
    }

    fn found(path: Portable, file: &Path, verdict: Verdict) -> Found {
        Found {
            path,
            url: "https://example.invalid/x".to_string(),
            rev: OLD.to_string(),
            file: file.to_path_buf(),
            verdict,
        }
    }

    fn moves(from: Option<&str>, to: Option<&str>) -> Verdict {
        Verdict::Moves {
            tip: NEW.to_string(),
            from: from.map(str::to_string),
            to: to.map(str::to_string),
            log: None,
            count: None,
        }
    }

    #[test]
    fn a_rewrite_changes_only_the_rev_of_the_entry_named_and_is_idempotent() {
        let text = format!(
            "# mine\n[[external]]\npath = \"~/a\"\nurl = \"u\"\nrev   =   \"{OLD}\"   # kept\n\n\
             [[external]]\npath = \"~/b\"\nurl = \"u\"\nrev = \"{OLD}\"\n"
        );
        let file = Path::new("/repo/bx.toml");
        let home = Path::new(HOME);
        let b = rewrite(&text, file, &portable("~/b"), home, NEW).expect("b");
        let (kept, last) = text.rsplit_once(OLD).expect("b's rev");
        assert_eq!(b, format!("{kept}{NEW}{last}"));
        assert_eq!(
            rewrite(&b, file, &portable("~/b"), home, NEW).expect("again"),
            b
        );
        let a = rewrite(&text, file, &portable("~/a"), home, NEW).expect("a");
        assert_eq!(
            a,
            text.replacen(OLD, NEW, 1),
            "its spacing and comment kept"
        );
    }

    #[test]
    fn a_rewrite_with_no_pinned_entry_at_the_path_is_refused() {
        let file = Path::new("/repo/bx.toml");
        let home = Path::new(HOME);
        for text in [
            String::new(),
            "[[external]]\npath = \"~/a\"\nurl = \"u\"\nbranch = \"main\"\n".to_string(),
            format!("[[external]]\npath = \"~/b\"\nurl = \"u\"\nrev = \"{OLD}\"\n"),
        ] {
            let error =
                rewrite(&text, file, &portable("~/a"), home, NEW).expect_err("nothing to rewrite");
            assert_eq!(
                error.to_string(),
                "/repo/bx.toml declares no [[external]] at `~/a` with a `rev`"
            );
        }
        assert!(matches!(
            rewrite("[[external]\n", file, &portable("~/a"), home, NEW),
            Err(Error::Parse { .. })
        ));
    }

    #[test]
    fn edits_rewrite_each_layer_once_for_every_pin_it_holds() {
        let home = crate::testing::guarded_home();
        let repo = home.child(".config/bx");
        let layer = format!(
            "[[external]]\npath = \"~/a\"\nurl = \"u\"\nrev = \"{OLD}\"\n\
             [[external]]\npath = \"~/b\"\nurl = \"u\"\nrev = \"{OLD}\"\n"
        );
        let file = home.write(".config/bx/bx.toml", &layer);
        let local = home.write(".local/state/bx/local.toml", &layer);
        let at = |path: &str, file: &Path, verdict| {
            found(
                Portable::parse_in(path, home.path()).expect("a path"),
                file,
                verdict,
            )
        };
        let found = [
            at("~/a", &file, moves(None, Some("v2.0.0"))),
            at("~/b", &file, moves(None, Some("v2.0.0"))),
            at("~/a", &local, Verdict::Current { tag: None }),
            at("~/b", &local, moves(None, None)),
        ];
        let edits = edits(&found, &repo, home.path()).expect("edits");
        assert_eq!(edits.len(), 2);
        assert_eq!(
            (edits[0].file.as_path(), edits[0].committed),
            (file.as_path(), true)
        );
        assert_eq!(edits[0].after, layer.replace(OLD, NEW));
        assert_eq!(
            (edits[1].file.as_path(), edits[1].committed),
            (local.as_path(), false)
        );
        let (kept, last) = layer.rsplit_once(OLD).expect("b's rev");
        assert_eq!(edits[1].after, format!("{kept}{NEW}{last}"));
        assert!(
            shown(&edits[0], home.path()).starts_with(
                "--- ~/.config/bx/bx.toml (now)\n+++ ~/.config/bx/bx.toml (upgraded)\n"
            ),
            "{}",
            shown(&edits[0], home.path())
        );
    }

    #[test]
    fn the_message_names_each_pin_that_moves_by_path_and_tag() {
        let file = Path::new("/repo/bx.toml");
        let found = [
            found(portable("~/a"), file, moves(Some("v1.0.0"), Some("v1.1.0"))),
            found(portable("~/b"), file, moves(None, Some("2.0.0"))),
            found(portable("~/c"), file, moves(None, None)),
            found(portable("~/d"), file, Verdict::Current { tag: None }),
        ];
        assert_eq!(
            message(&found),
            "chore(bx): upgrade pinned externals\n\n\
             ~/a: v1.0.0 -> v1.1.0 (111111111111 -> 222222222222)\n\
             ~/b: 2.0.0 (111111111111 -> 222222222222)\n\
             ~/c: 111111111111 -> 222222222222\n"
        );
        let expected: BTreeMap<Portable, String> =
            [portable("~/a"), portable("~/b"), portable("~/c")]
                .into_iter()
                .map(|path| (path, NEW.to_string()))
                .collect();
        assert_eq!(pins(&found), expected);
    }

    #[test]
    fn a_summary_says_what_was_found_in_one_line() {
        let cases = [
            (
                Verdict::Current {
                    tag: Some("v1.0.0".to_string()),
                },
                "~/a: pinned at v1.0.0, the newest release",
            ),
            (
                Verdict::Unproven {
                    tip: NEW.to_string(),
                    to: Some("v2.0.0".to_string()),
                },
                "~/a: v2.0.0 is at 222222222222, and with no checkout of bx's there is nothing \
                 to show it descends from 111111111111, so it is not upgraded. Run `bx upgrade` \
                 again once `bx apply` has cloned it",
            ),
            (
                Verdict::Rewritten {
                    tip: NEW.to_string(),
                    to: None,
                },
                "~/a: no release, and the default branch's tip 222222222222 does not descend \
                 from 111111111111; bx moves a checkout only forward, so it is not upgraded",
            ),
            (
                Verdict::Unreachable("offline".to_string()),
                "~/a: not checked: offline",
            ),
        ];
        for (verdict, said) in cases {
            assert_eq!(
                found(portable("~/a"), Path::new("/repo/bx.toml"), verdict).summary(),
                said
            );
        }
    }

    #[test]
    fn select_splits_the_followed_from_the_pinned_and_refuses_what_is_no_external() {
        let follow = Pin::Follow(crate::config::external::Follow {
            branch: "main".to_string(),
            check: crate::config::external::Check::Ask,
        });
        let externals = [
            external("~/a", Pin::Rev(OLD.to_string())),
            external("~/b", follow),
            external("~/c", Pin::Rev(OLD.to_string())),
        ];
        let paths = |chosen: &[&External]| -> Vec<String> {
            chosen
                .iter()
                .map(|external| external.path.to_string())
                .collect()
        };
        let home = Path::new(HOME);
        let (followed, pinned) = select(&externals, &[], home).expect("all");
        assert_eq!(paths(&followed), ["~/b"]);
        assert_eq!(paths(&pinned), ["~/a", "~/c"]);
        let names = ["~/c".to_string(), format!("{HOME}/c")];
        let (followed, pinned) = select(&externals, &names, home).expect("one, once");
        assert!(followed.is_empty());
        assert_eq!(paths(&pinned), ["~/c"]);
        assert!(matches!(
            select(&externals, &["~/z".to_string()], home),
            Err(crate::update::Error::NotExternal(name)) if name == "~/z"
        ));
    }
}
