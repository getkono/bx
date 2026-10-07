//! Declared git externals: a repository bx keeps checked out at one commit
//! under the home directory, either pinned in the configuration or following
//! a branch through `bx.lock`.
//!
//! # The `[[external]]` schema
//!
//! ```toml
//! [[external]]
//! path    = "~/.local/share/zsh/zsh-autosuggestions"          # required; the natural key
//! url     = "https://github.com/zsh-users/zsh-autosuggestions" # required; https or ssh
//! rev     = "0e810e5afa27acbd074398eefbe28d13005dbc15"         # a full commit id, or…
//! branch  = "master"                                           # …a branch to follow
//! check   = "ask"                                              # followed only: ask | auto
//! interval = "1d"                                              # with `check = "auto"` only
//! enabled = true                                               # default true
//!
//! [[external.link]]                                            # any number
//! from    = "skills/*"            # every child directory of `skills/` in the checkout
//! to      = "~/.claude/skills/*"  # becomes a symlink of the same name here
//! require = "SKILL.md"            # optional: only children holding this file
//! ```
//!
//! This module is the configuration half: what an entry may say, and what it
//! is refused for saying. It reads nothing from disk and runs no `git`.
//!
//! # Pinned or followed
//!
//! An entry says exactly one of `rev` and `branch`, and the one it says is the
//! only place its commit comes from:
//!
//! * **Pinned** — `rev`. The checkout is kept at that commit, and moves only
//!   when someone edits `rev`. `bx update` never proposes moving it and no
//!   shell ever asks about it: the form for code that is reviewed before it
//!   runs.
//! * **Followed** — `branch`. The commit is the one `bx.lock`
//!   ([`super::lock`]) holds for the entry, which only `bx update` writes, and
//!   only after it has shown what moves and been told to. `plan` and `apply`
//!   read the lock and never the branch, so they reach no network and two
//!   machines sharing the config repo check out the same commit.
//!
//! Both together are refused rather than one taking precedence: two places a
//! commit could come from is one too many to read at a glance.
//!
//! # `check` and `interval`
//!
//! A followed entry is `check = "ask"` by default: an interactive shell asks
//! whether to look for updates once the `[update]` interval
//! ([`super::update`]) has passed, and nothing reaches the network until
//! someone answers yes. `check = "auto"` looks without asking, from a shell
//! that is interactive, once its own `interval` (the `[update]` one when
//! unset) has passed, and asks only whether to *apply* what it found. Neither
//! ever moves a checkout without an answer. A pinned entry takes neither key.
//!
//! # `[[external.link]]`
//!
//! Each link puts the checkout's children where a tool looks for them: every
//! child directory of `from` in the commit the external is kept at becomes a
//! symlink of the same name in the directory `to` names, pointing into the
//! checkout. `require` keeps only the children holding a file of that name.
//! Both `from` and `to` end in `/*`, which is the only pattern there is: a
//! link names a directory whose children it links, one level deep. `from` is
//! relative to the checkout and stays inside it; `to` is beneath the home.
//! The symlinks are ordinary symlink targets once expanded — owned, recorded
//! and released by `bx rm` like any other.
//!
//! # `path`
//!
//! A [`Portable`] path strictly beneath the home: `~/…`. The home itself, and
//! anywhere outside it, are refused — a clone is a directory bx creates and may
//! later remove, and neither is a directory bx could ever remove.
//!
//! # `url`
//!
//! One of the two transports a pinned clone needs and nothing else:
//!
//! * `https://host/…`, with **no** user information. A token written into the
//!   url is a cleartext secret in a committed file, which Invariant 5 forbids,
//!   and a bare user name is the same shape one keystroke away from it. A
//!   private https remote takes its credential from git's own helper.
//! * `ssh://[user@]host[:port]/…`, or git's scp-like `[user@]host:path`, with
//!   no password.
//!
//! `http://`, `git://`, `file://`, a local path and git's `ext::` transport are
//! refused: the first two are unauthenticated, and the rest reach the machine
//! the clone runs on rather than a remote. A host that begins with `-` is
//! refused too, since `git` and `ssh` would read it as an option.
//!
//! # `rev`
//!
//! A full commit id exactly as `git rev-parse` prints it: forty lowercase hex
//! digits for a SHA-1 repository, sixty-four for a SHA-256 one. A branch name,
//! a tag and an abbreviated id are refused, because each names a different
//! commit depending on when it is read, and a pinned external moves only when
//! the configuration's `rev` changes; following a branch is what `branch` is
//! for. Uppercase is refused rather than folded, so the id written is the id
//! every later comparison sees.
//!
//! # `branch`
//!
//! A branch name as git would accept it for `refs/heads/…`, judged by its
//! spelling alone: no leading `-` or `.`, no `..`, `@{`, `//`, control
//! character, space or any of `~^:?*[\`, and no trailing `/`, `.` or `.lock`.
//! A full `refs/…` name is refused too: the branch is always a branch.
//!
//! # No placeholders
//!
//! Nothing in an external is substituted, like a `[[plugin]]`'s `source`. A
//! `{{` in `path` or `url` is refused rather than kept as literal text, so
//! adding substitution later changes the meaning of no configuration written
//! today.

use std::path::Path;

use toml_edit::Table;

use super::update::Interval;
use super::{Ctx, Error, Origin};
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[external]]";

/// A link's section header, as messages spell it.
const LINK_SECTION: &str = "[[external.link]]";

/// Every key an `[[external]]` entry may carry.
const KEYS: [&str; 8] = [
    "path", "url", "rev", "branch", "check", "interval", "link", "enabled",
];

/// Every key an `[[external.link]]` may carry.
const LINK_KEYS: [&str; 3] = ["from", "to", "require"];

/// The one pattern a link's `from` and `to` end in.
const CHILDREN: &str = "/*";

/// One `[[external]]` entry, as written.
///
/// Its natural key is [`External::path`], so a later layer whose entry has a
/// path already present replaces that entry in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External {
    /// The checkout's directory, strictly beneath the home.
    pub path: Portable,
    /// The remote it is cloned from.
    pub url: String,
    /// Where the commit it is kept at comes from.
    pub pin: Pin,
    /// Where its children are linked, in the order written.
    pub links: Vec<Link>,
    /// `false` in any layer removes the external from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

impl External {
    /// The branch it follows, or `None` when it is pinned.
    #[must_use]
    pub const fn follows(&self) -> Option<&Follow> {
        match &self.pin {
            Pin::Rev(_) => None,
            Pin::Follow(follow) => Some(follow),
        }
    }
}

/// Where an external's commit comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// `rev`: this full commit id, until the configuration says another.
    Rev(String),
    /// `branch`: the commit `bx.lock` holds, which `bx update` moves.
    Follow(Follow),
}

/// A followed branch, and how bx looks for its new commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Follow {
    /// The branch, as `refs/heads/` would hold it.
    pub branch: String,
    /// Whether a shell asks before looking.
    pub check: Check,
}

/// How bx looks for a followed branch's new commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// An interactive shell asks before anything reaches the network.
    Ask,
    /// An interactive shell looks without asking, this often (the `[update]`
    /// interval when `None`), and asks only before applying.
    Auto(Option<Interval>),
}

/// One `[[external.link]]`: the children of a directory in the checkout,
/// linked by name into a directory beneath the home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The directory in the checkout whose children are linked, relative and
    /// normalised: `skills` for `from = "skills/*"`, empty for `from = "*"`.
    pub from: String,
    /// The directory the links are made in.
    pub to: Portable,
    /// A file a child must hold to be linked.
    pub require: Option<String>,
    /// Where the link was written.
    pub origin: Origin,
}

impl Link {
    /// The key a report names this link by: its `to`, as written.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}{CHILDREN}", self.to)
    }
}

/// Parse one `[[external]]` entry.
///
/// `text` is the whole layer file, because spans index into it, and `home` is
/// the account's home, because a path under it has exactly one spelling.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_external(
    table: &Table,
    file: &Path,
    text: &str,
    home: &Path,
) -> Result<External, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let raw_path = ctx.required_str(table, "path")?;
    let path = parse_path(raw_path, home).map_err(|message| ctx.bad(table, "path", message))?;

    let url = ctx.required_str(table, "url")?;
    if let Some(problem) = unusable_url(url) {
        return Err(ctx.bad(table, "url", format!("`{path}`: {problem}")));
    }

    let pin = parse_pin(&ctx, table, &path)?;
    let links = match table.get("link") {
        None => Vec::new(),
        Some(item) => item
            .as_array_of_tables()
            .ok_or_else(|| Error::WrongType {
                origin: ctx.key_origin(table, "link"),
                key: "link".to_string(),
                expected: "a repeated section `[[external.link]]`",
                found: item.type_name(),
            })?
            .iter()
            .map(|link| parse_link(link, file, text, home, &path))
            .collect::<Result<_, _>>()?,
    };

    Ok(External {
        path,
        url: url.to_string(),
        pin,
        links,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// An entry's `rev`, or its `branch` with `check` and `interval`.
fn parse_pin(ctx: &Ctx<'_>, table: &Table, path: &Portable) -> Result<Pin, Error> {
    let rev = ctx.str_at(table, "rev")?;
    let branch = ctx.str_at(table, "branch")?;
    let check = ctx.str_at(table, "check")?;
    let interval = ctx.str_at(table, "interval")?;
    match (rev, branch) {
        (Some(_), Some(_)) => Err(ctx.bad(
            table,
            "branch",
            format!(
                "`{path}` declares both `rev` and `branch`: a pinned external is kept at `rev`, \
                 a followed one at the commit `bx update` locks for `branch`; keep the one \
                 you mean"
            ),
        )),
        (None, None) => Err(ctx.bad(
            table,
            "path",
            format!(
                "`{path}` declares neither `rev` nor `branch`: pin it to a full commit id with \
                 `rev`, or follow a branch with `branch`"
            ),
        )),
        (Some(rev), None) => {
            if let Some(problem) = unusable_rev(rev) {
                return Err(ctx.bad(table, "rev", format!("`{path}`: {problem}")));
            }
            for key in ["check", "interval"] {
                if table.contains_key(key) {
                    return Err(ctx.bad(
                        table,
                        key,
                        format!(
                            "`{path}` is pinned with `rev`, which nothing checks for updates: \
                             `{key}` applies only to an external that follows a `branch`"
                        ),
                    ));
                }
            }
            Ok(Pin::Rev(rev.to_string()))
        }
        (None, Some(branch)) => {
            if let Some(problem) = unusable_branch(branch) {
                return Err(ctx.bad(table, "branch", format!("`{path}`: {problem}")));
            }
            let interval = interval
                .map(|raw| {
                    Interval::parse(raw).map_err(|message| {
                        ctx.bad(table, "interval", format!("`{path}`: {message}"))
                    })
                })
                .transpose()?;
            let check = match (check, interval) {
                (None | Some("ask"), None) => Check::Ask,
                (Some("auto"), interval) => Check::Auto(interval),
                (None | Some("ask"), Some(_)) => {
                    return Err(ctx.bad(
                        table,
                        "interval",
                        format!(
                            "`{path}`: `interval` paces the checks bx makes without asking, so \
                             it needs `check = \"auto\"`; how often a shell asks is \
                             `[update] interval`"
                        ),
                    ));
                }
                (Some(other), _) => {
                    return Err(ctx.bad(
                        table,
                        "check",
                        format!("`{path}`: `check = {other:?}` is neither \"ask\" nor \"auto\""),
                    ));
                }
            };
            Ok(Pin::Follow(Follow {
                branch: branch.to_string(),
                check,
            }))
        }
    }
}

/// Parse one `[[external.link]]` of the external at `external`.
fn parse_link(
    table: &Table,
    file: &Path,
    text: &str,
    home: &Path,
    external: &Portable,
) -> Result<Link, Error> {
    let ctx = Ctx::new(table, file, text, LINK_SECTION);
    ctx.reject_unknown_keys(table, &LINK_KEYS)?;

    let raw_from = ctx.required_str(table, "from")?;
    let from = parse_from(raw_from)
        .map_err(|message| ctx.bad(table, "from", format!("`{external}`: {message}")))?;

    let raw_to = ctx.required_str(table, "to")?;
    let to = parse_to(raw_to, home)
        .map_err(|message| ctx.bad(table, "to", format!("`{external}`: {message}")))?;
    if to == *external || to.as_str().starts_with(&format!("{external}/")) {
        return Err(ctx.bad(
            table,
            "to",
            format!(
                "`{external}`: `to = {raw_to:?}` is inside the checkout itself; a link puts \
                 the checkout's children somewhere a tool looks, outside it"
            ),
        ));
    }

    let require = ctx
        .str_at(table, "require")?
        .map(|raw| {
            if raw.is_empty()
                || raw.contains('/')
                || raw == "."
                || raw == ".."
                || raw.contains("{{")
                || raw.chars().any(char::is_control)
            {
                Err(ctx.bad(
                    table,
                    "require",
                    format!(
                        "`{external}`: `require = {raw:?}` must be one file name, as a child \
                         directory would hold it"
                    ),
                ))
            } else {
                Ok(raw.to_string())
            }
        })
        .transpose()?;

    Ok(Link {
        from,
        to,
        require,
        origin: ctx.origin().clone(),
    })
}

/// A link's `from`, without its `/*`: a relative directory in the checkout,
/// normalised, or empty for the checkout itself.
fn parse_from(raw: &str) -> Result<String, String> {
    let Some(dir) = raw.strip_suffix('*') else {
        return Err(format!(
            "`from = {raw:?}` must end in `{CHILDREN}`: a link names the directory whose \
             children it links"
        ));
    };
    if dir.is_empty() {
        return Ok(String::new());
    }
    let Some(dir) = dir.strip_suffix('/') else {
        return Err(format!("`from = {raw:?}` must end in `{CHILDREN}`"));
    };
    let mut parts = Vec::new();
    for part in dir.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                return Err(format!(
                    "`from = {raw:?}` climbs out of the checkout with `..`; it names a \
                     directory inside it"
                ));
            }
            part if part.contains(['*', '?', '[', '\\']) || part.contains("{{") => {
                return Err(format!(
                    "`from = {raw:?}` holds a pattern before its last `{CHILDREN}`; the \
                     only pattern is the one at the end"
                ));
            }
            part if part.chars().any(char::is_control) => {
                return Err(format!("`from = {raw:?}` holds a control character"));
            }
            part => parts.push(part),
        }
    }
    if dir.starts_with('/') || dir.starts_with('~') {
        return Err(format!(
            "`from = {raw:?}` is not relative to the checkout; write the directory as it \
             sits inside it, such as \"skills/*\""
        ));
    }
    Ok(parts.join("/"))
}

/// A link's `to`, without its `/*`: a directory beneath the home.
fn parse_to(raw: &str, home: &Path) -> Result<Portable, String> {
    let Some(dir) = raw.strip_suffix(CHILDREN) else {
        return Err(format!(
            "`to = {raw:?}` must end in `{CHILDREN}`: each child is linked by its own name \
             into the directory before it"
        ));
    };
    if dir.contains("{{") || dir.contains(['*', '?', '[']) {
        return Err(format!(
            "`to = {raw:?}` holds a placeholder or a pattern before its last `{CHILDREN}`"
        ));
    }
    let to = Portable::parse_in(dir, home).map_err(|e| e.to_string())?;
    if !to.under_home() {
        return Err(format!(
            "`to = {raw:?}` must name a directory beneath the home, spelled `~/…{CHILDREN}`"
        ));
    }
    Ok(to)
}

/// Why `branch` is not a branch name git would take, or `None` when it is.
///
/// git's `check-ref-format` rules for one branch, judged on the spelling.
pub(crate) fn unusable_branch(branch: &str) -> Option<String> {
    let refuse = |why: &str| Some(format!("`branch = {branch:?}` {why}"));
    if branch.is_empty() {
        return refuse("is empty");
    }
    if branch.starts_with("refs/") {
        return refuse(
            "is a full ref; write the branch's own name, such as \"main\" for refs/heads/main",
        );
    }
    if branch.starts_with('-') {
        return refuse("begins with `-`, which git would read as an option");
    }
    if branch == "HEAD" || branch == "@" {
        return refuse("names no branch; write the branch HEAD points at on the remote");
    }
    let bad_char = branch
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c));
    let bad_part = branch
        .split('/')
        .any(|part| part.is_empty() || part.starts_with('.') || part.ends_with(".lock"));
    if bad_char
        || bad_part
        || branch.contains("..")
        || branch.contains("@{")
        || branch.ends_with('.')
        || branch.contains("{{")
    {
        return refuse("is not a branch name git accepts");
    }
    None
}

/// An external's `path`, as its one normalised spelling.
///
/// Shared by a full entry and a toggle, so a toggle written `~/a/./b` reaches
/// the entry written `~/a/b`.
///
/// # Errors
///
/// The message to report at the key: a spelling [`Portable::parse_in`]
/// refuses, a placeholder, or a path that is not strictly beneath the home.
pub(crate) fn parse_path(raw: &str, home: &Path) -> Result<Portable, String> {
    if raw.contains("{{") {
        return Err(format!(
            "`path = {raw:?}`: an external takes no `{{{{name}}}}` placeholder"
        ));
    }
    let path = Portable::parse_in(raw, home).map_err(|e| e.to_string())?;
    if !path.under_home() || path.as_str() == "~" {
        return Err(format!(
            "`path = {raw:?}` must name a directory beneath the home, spelled `~/…`: \
             a clone is a directory bx creates and may later remove"
        ));
    }
    Ok(path)
}

/// Why `url` cannot be cloned from, or `None` when it can.
pub(crate) fn unusable_url(url: &str) -> Option<String> {
    let refuse = |why: &str| Some(format!("`url = {url:?}` {why}"));

    if url.contains("{{") {
        return refuse("holds a placeholder; an external takes no `{{name}}` placeholder");
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return refuse("holds whitespace or a control character");
    }

    let (authority, rest) = if let Some(rest) = url.strip_prefix("https://") {
        let (authority, rest) = split_authority(rest);
        if authority.contains('@') {
            return refuse(
                "carries user information; a credential written into a committed url is \
                 a cleartext secret, so a private https remote takes it from git's \
                 credential helper instead",
            );
        }
        (authority, rest)
    } else if let Some(rest) = url.strip_prefix("ssh://") {
        let (authority, rest) = split_authority(rest);
        if authority
            .rsplit_once('@')
            .is_some_and(|(user, _)| user.contains(':'))
        {
            return refuse("carries a password; an ssh remote authenticates with a key");
        }
        (authority, rest)
    } else if url.contains("://") || url.starts_with("ext::") {
        return refuse(
            "uses a transport an external does not take; use `https://`, `ssh://` or \
             the scp-like `host:path`",
        );
    } else {
        // git's scp-like syntax: `[user@]host:path`, with no `/` before the
        // first `:`. Anything else is a local path.
        match url.split_once(':') {
            Some((authority, rest)) if !authority.contains('/') => {
                // git ends the host at the first `:`, so `user:secret@host:path`
                // is host `user` and a path holding the secret. Refused by its
                // shape: an `@` or a second `:` before the path's first `/`.
                let head = rest.split('/').next().unwrap_or_default();
                if head.contains('@') || head.contains(':') {
                    return refuse(
                        "reads as carrying a password; an ssh remote authenticates with a key",
                    );
                }
                (authority, rest)
            }
            _ => {
                return refuse(
                    "is not a remote: use `https://`, `ssh://` or the scp-like `host:path`",
                );
            }
        }
    };

    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.is_empty() || host.starts_with(':') {
        return refuse("names no host");
    }
    if host.starts_with('-') || authority.starts_with('-') {
        return refuse("begins its host with `-`, which git and ssh would read as an option");
    }
    if rest.trim_matches('/').is_empty() {
        return refuse("names no repository on its host");
    }
    None
}

/// A url's authority and what follows it, split at the first `/`.
fn split_authority(rest: &str) -> (&str, &str) {
    rest.split_once('/').unwrap_or((rest, ""))
}

/// Why `rev` is not a full commit id, or `None` when it is.
pub(crate) fn unusable_rev(rev: &str) -> Option<String> {
    let hex = rev.chars().all(|c| c.is_ascii_hexdigit());
    if hex && matches!(rev.len(), 40 | 64) {
        if rev.chars().any(|c| c.is_ascii_uppercase()) {
            return Some(format!(
                "`rev = {rev:?}` must be written in lowercase, as `git rev-parse` prints it: \
                 `{}`",
                rev.to_ascii_lowercase()
            ));
        }
        return None;
    }
    let what = if hex && !rev.is_empty() && rev.len() < 40 {
        "an abbreviated commit id"
    } else {
        "not a commit id; a branch or a tag names a different commit depending on when it \
         is read, and following a branch is `branch = …`"
    };
    Some(format!(
        "`rev = {rev:?}` is {what}: an external is pinned to a full commit id, forty hex \
         digits (sixty-four in a SHA-256 repository), so it moves only when `rev` changes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use toml_edit::Document;

    /// A commit id that is well formed.
    const REV: &str = "0e810e5afa27acbd074398eefbe28d13005dbc15";

    fn home() -> PathBuf {
        PathBuf::from("/home/example")
    }

    /// Every `[[external]]` entry in `text`, parsed.
    fn parse(text: &str) -> Result<Vec<External>, String> {
        let doc = Document::parse(text).map_err(|e| format!("{e}"))?;
        let tables = doc
            .get("external")
            .and_then(|item| item.as_array_of_tables())
            .ok_or("no [[external]]")?;
        tables
            .iter()
            .map(|table| parse_external(table, Path::new("/repo/bx.toml"), text, &home()))
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }

    /// One entry with `url` and `rev` substituted in.
    fn entry(path: &str, url: &str, rev: &str) -> String {
        format!("[[external]]\npath = \"{path}\"\nurl = \"{url}\"\nrev = \"{rev}\"\n")
    }

    #[test]
    fn a_full_entry_parses_every_key() {
        let parsed = parse(&format!(
            "{}enabled = false\n",
            entry("~/.zsh/./plugins/a", "https://github.com/o/a", REV)
        ))
        .unwrap();
        assert_eq!(parsed.len(), 1);
        let external = &parsed[0];
        assert_eq!(external.path.as_str(), "~/.zsh/plugins/a", "normalised");
        assert_eq!(external.url, "https://github.com/o/a");
        assert_eq!(external.pin, Pin::Rev(REV.to_string()));
        assert_eq!(external.follows(), None);
        assert!(external.links.is_empty());
        assert!(!external.enabled);
        assert_eq!(external.origin.file, Path::new("/repo/bx.toml"));
        assert_eq!(external.origin.line, 1);

        let defaulted = parse(&entry("~/a", "https://github.com/o/a", REV)).unwrap();
        assert!(defaulted[0].enabled, "enabled defaults to true");
    }

    #[test]
    fn a_sha256_commit_id_is_accepted() {
        let rev = "a".repeat(64);
        assert!(parse(&entry("~/a", "https://h/o/a", &rev)).is_ok());
    }

    #[test]
    fn a_key_beyond_the_schema_is_refused() {
        let err = parse(&format!(
            "{}tag = \"v1\"\n",
            entry("~/a", "https://h/o/a", REV)
        ))
        .unwrap_err();
        assert!(err.contains("unknown key `tag` in [[external]]"), "{err}");

        let err = parse(&format!(
            "{}[[external.link]]\nfrom = \"*\"\nto = \"~/b/*\"\nas = \"x\"\n",
            entry("~/a", "https://h/o/a", REV)
        ))
        .unwrap_err();
        assert!(
            err.contains("unknown key `as` in [[external.link]]"),
            "{err}"
        );
    }

    #[test]
    fn each_required_key_is_named_when_missing() {
        for (text, key) in [
            (
                format!("[[external]]\nurl = \"https://h/o/a\"\nrev = \"{REV}\"\n"),
                "path",
            ),
            (
                format!("[[external]]\npath = \"~/a\"\nrev = \"{REV}\"\n"),
                "url",
            ),
            (
                format!(
                    "{}[[external.link]]\nto = \"~/b/*\"\n",
                    entry("~/a", "https://h/o/a", REV)
                ),
                "from",
            ),
            (
                format!(
                    "{}[[external.link]]\nfrom = \"*\"\n",
                    entry("~/a", "https://h/o/a", REV)
                ),
                "to",
            ),
        ] {
            let err = parse(&text).unwrap_err();
            assert!(
                err.contains(&format!("missing the required key `{key}`")),
                "{err}"
            );
        }
    }

    /// One followed entry, with `extra` lines after its `branch`.
    fn followed(branch: &str, extra: &str) -> String {
        format!(
            "[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\nbranch = \"{branch}\"\n{extra}"
        )
    }

    #[test]
    fn exactly_one_of_rev_and_branch_says_where_the_commit_comes_from() {
        let parsed = parse(&followed("main", "")).unwrap();
        let follow = parsed[0].follows().expect("followed");
        assert_eq!(follow.branch, "main");
        assert_eq!(follow.check, Check::Ask, "ask is the default");

        let err = parse(&format!(
            "{}branch = \"main\"\n",
            entry("~/a", "https://h/o/a", REV)
        ))
        .unwrap_err();
        assert!(err.contains("both `rev` and `branch`"), "{err}");
        assert!(err.starts_with("/repo/bx.toml:5:"), "at `branch`: {err}");

        let err = parse("[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\n").unwrap_err();
        assert!(err.contains("neither `rev` nor `branch`"), "{err}");
    }

    #[test]
    fn check_and_interval_pace_a_followed_entry_only() {
        let parsed = parse(&followed("main", "check = \"auto\"\ninterval = \"1d\"\n")).unwrap();
        assert_eq!(
            parsed[0].follows().unwrap().check,
            Check::Auto(Some(Interval::parse("1d").unwrap()))
        );
        let parsed = parse(&followed("main", "check = \"auto\"\n")).unwrap();
        assert_eq!(parsed[0].follows().unwrap().check, Check::Auto(None));
        let parsed = parse(&followed("main", "check = \"ask\"\n")).unwrap();
        assert_eq!(parsed[0].follows().unwrap().check, Check::Ask);

        for (extra, says) in [
            ("interval = \"1d\"\n", "needs `check = \"auto\"`"),
            (
                "check = \"ask\"\ninterval = \"1d\"\n",
                "needs `check = \"auto\"`",
            ),
            ("check = \"never\"\n", "neither \"ask\" nor \"auto\""),
            ("check = \"auto\"\ninterval = \"1w\"\n", "not an interval"),
        ] {
            let err = parse(&followed("main", extra)).unwrap_err();
            assert!(err.contains(says), "{extra:?}: {err}");
        }
        for key in ["check = \"ask\"\n", "interval = \"1d\"\n"] {
            let err = parse(&format!("{}{key}", entry("~/a", "https://h/o/a", REV))).unwrap_err();
            assert!(err.contains("is pinned with `rev`"), "{key:?}: {err}");
        }
    }

    #[test]
    fn a_branch_git_would_refuse_is_refused_by_its_spelling() {
        for branch in ["main", "release/1.x", "feat/a-b_c", "v2"] {
            assert!(parse(&followed(branch, "")).is_ok(), "{branch}");
        }
        for (branch, says) in [
            ("", "is empty"),
            ("refs/heads/main", "full ref"),
            ("-main", "option"),
            ("HEAD", "names no branch"),
            ("a b", "not a branch name"),
            ("a..b", "not a branch name"),
            ("a/.b", "not a branch name"),
            ("a//b", "not a branch name"),
            ("a/", "not a branch name"),
            ("a.lock", "not a branch name"),
            ("a.", "not a branch name"),
            ("a@{1}", "not a branch name"),
            ("a~1", "not a branch name"),
            ("a^", "not a branch name"),
            ("a:b", "not a branch name"),
            ("a*", "not a branch name"),
            ("{{x}}", "not a branch name"),
        ] {
            let err = parse(&followed(branch, "")).unwrap_err();
            assert!(err.contains(says), "{branch:?}: {err}");
            assert!(err.starts_with("/repo/bx.toml:4:"), "{branch:?}: {err}");
        }
    }

    /// A pinned entry with one link of `from`, `to` and `extra`.
    fn linked(from: &str, to: &str, extra: &str) -> Result<Vec<External>, String> {
        parse(&format!(
            "{}[[external.link]]\nfrom = \"{from}\"\nto = \"{to}\"\n{extra}",
            entry("~/src/a", "https://h/o/a", REV)
        ))
    }

    #[test]
    fn a_link_names_a_directory_in_the_checkout_and_one_beneath_the_home() {
        let parsed = linked(
            "./skills//*",
            "~/.claude/./skills/*",
            "require = \"SKILL.md\"\n",
        )
        .unwrap();
        let link = &parsed[0].links[0];
        assert_eq!(link.from, "skills", "normalised, without its pattern");
        assert_eq!(link.to.as_str(), "~/.claude/skills");
        assert_eq!(link.require.as_deref(), Some("SKILL.md"));
        assert_eq!(link.key(), "~/.claude/skills/*");
        assert_eq!(link.origin.line, 5);

        let parsed = linked("*", "~/bin/*", "").unwrap();
        assert_eq!(parsed[0].links[0].from, "", "the checkout itself");
        assert_eq!(parsed[0].links[0].require, None);

        let two = parse(&format!(
            "{}[[external.link]]\nfrom = \"a/*\"\nto = \"~/x/*\"\n\
             [[external.link]]\nfrom = \"b/*\"\nto = \"~/y/*\"\n",
            entry("~/src/a", "https://h/o/a", REV)
        ))
        .unwrap();
        let froms: Vec<&str> = two[0].links.iter().map(|l| l.from.as_str()).collect();
        assert_eq!(froms, ["a", "b"], "in the order written");
    }

    #[test]
    fn a_link_that_escapes_patterns_or_points_into_the_checkout_is_refused() {
        for (from, to, extra, says) in [
            ("skills", "~/x/*", "", "must end in `/*`"),
            ("skills*", "~/x/*", "", "must end in `/*`"),
            ("../skills/*", "~/x/*", "", "climbs out"),
            ("a/*/b/*", "~/x/*", "", "pattern before"),
            ("/abs/*", "~/x/*", "", "not relative"),
            ("~/a/*", "~/x/*", "", "not relative"),
            ("skills/*", "~/x", "", "must end in `/*`"),
            ("skills/*", "/opt/x/*", "", "beneath the home"),
            ("skills/*", "~/{{v}}/*", "", "placeholder"),
            ("skills/*", "~/src/a/*", "", "inside the checkout"),
            ("skills/*", "~/src/a/sub/*", "", "inside the checkout"),
            ("skills/*", "~/x/*", "require = \"a/b\"\n", "one file name"),
            ("skills/*", "~/x/*", "require = \"\"\n", "one file name"),
            ("skills/*", "~/x/*", "require = \"..\"\n", "one file name"),
        ] {
            let err = linked(from, to, extra).unwrap_err();
            assert!(err.contains(says), "{from:?} {to:?} {extra:?}: {err}");
        }
        assert!(linked("skills/*", "~/src/ab/*", "").is_ok(), "a sibling");

        let err = parse(&format!(
            "{}link = \"x\"\n",
            entry("~/a", "https://h/o/a", REV)
        ))
        .unwrap_err();
        assert!(err.contains("[[external.link]]"), "{err}");
    }

    #[test]
    fn a_rev_that_is_not_a_full_commit_id_is_a_load_error() {
        for (rev, says) in [
            ("main", "not a commit id"),
            ("v1.2.3", "not a commit id"),
            ("", "not a commit id"),
            ("0e810e5", "an abbreviated commit id"),
            (&REV[..39], "an abbreviated commit id"),
            (&format!("{REV}0"), "not a commit id"),
            (&format!("{}g", &REV[..39]), "not a commit id"),
        ] {
            let err = parse(&entry("~/a", "https://h/o/a", rev)).unwrap_err();
            assert!(err.contains(says), "{rev:?}: {err}");
            assert!(err.contains("full commit id"), "{rev:?}: {err}");
            assert!(err.starts_with("/repo/bx.toml:4:"), "{rev:?}: {err}");
        }

        let err = parse(&entry("~/a", "https://h/o/a", &REV.to_ascii_uppercase())).unwrap_err();
        assert!(err.contains("lowercase"), "{err}");
        assert!(err.contains(REV), "names the spelling to write: {err}");
    }

    #[test]
    fn a_path_outside_or_at_the_home_is_refused() {
        for path in [
            "~",
            "/opt/a",
            "/home/example/a",
            "relative/a",
            "~/../a",
            "~/{{x}}/a",
        ] {
            let err = parse(&entry(path, "https://h/o/a", REV)).unwrap_err();
            assert!(err.starts_with("/repo/bx.toml:2:"), "{path}: {err}");
        }
    }

    #[test]
    fn https_ssh_and_scp_like_urls_are_accepted() {
        for url in [
            "https://github.com/o/a",
            "https://github.com/o/a.git",
            "https://git.example.com:8443/group/sub/a",
            "ssh://git@github.com/o/a.git",
            "ssh://github.com:22/o/a",
            "git@github.com:o/a.git",
            "github.com:o/a",
        ] {
            assert!(parse(&entry("~/a", url, REV)).is_ok(), "{url}");
        }
    }

    #[test]
    fn a_url_bx_cannot_clone_from_safely_is_refused() {
        for (url, says) in [
            ("http://github.com/o/a", "transport"),
            ("git://github.com/o/a", "transport"),
            ("file:///srv/a", "transport"),
            ("ext::sh -c touch% /tmp/x", "whitespace"),
            ("ext::sh", "transport"),
            ("/srv/git/a", "is not a remote"),
            ("./a", "is not a remote"),
            ("dir/sub:a", "is not a remote"),
            ("https://token@github.com/o/a", "user information"),
            ("https://u:p@github.com/o/a", "user information"),
            ("ssh://u:p@github.com/o/a", "password"),
            ("u:p@github.com:o/a", "password"),
            ("https:///o/a", "no host"),
            ("ssh://git@/o/a", "no host"),
            (":o/a", "no host"),
            ("https://github.com", "no repository"),
            ("https://github.com/", "no repository"),
            ("github.com:", "no repository"),
            ("-oProxyCommand=x:a", "option"),
            ("ssh://-oProxyCommand=x/a", "option"),
            ("https://h/{{x}}", "placeholder"),
            ("https://h/o/a\t", "whitespace"),
        ] {
            let err = parse(&entry("~/a", url, REV)).unwrap_err();
            assert!(err.contains(says), "{url:?}: {err}");
            assert!(err.starts_with("/repo/bx.toml:3:"), "{url:?}: {err}");
        }
    }

    #[test]
    fn parse_path_is_the_spelling_a_toggle_is_matched_by() {
        assert_eq!(
            parse_path("~/a/./b//c", &home()).unwrap().as_str(),
            "~/a/b/c"
        );
        assert!(parse_path("/opt/a", &home()).is_err());
    }
}
