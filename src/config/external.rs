//! Declared git externals: a repository bx keeps checked out at one pinned
//! commit under the home directory.
//!
//! # The `[[external]]` schema
//!
//! ```toml
//! [[external]]
//! path    = "~/.local/share/zsh/zsh-autosuggestions"          # required; the natural key
//! url     = "https://github.com/zsh-users/zsh-autosuggestions" # required; https or ssh
//! rev     = "0e810e5afa27acbd074398eefbe28d13005dbc15"         # required; a full commit id
//! enabled = true                                               # default true
//! ```
//!
//! This module is the configuration half: what an entry may say, and what it
//! is refused for saying. It reads nothing from disk and runs no `git`.
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
//! commit depending on when it is read, and an external moves only when the
//! configuration's `rev` changes. Uppercase is refused rather than folded, so
//! the id written is the id every later comparison sees.
//!
//! # No placeholders
//!
//! Nothing in an external is substituted, like a `[[plugin]]`'s `source`. A
//! `{{` in `path` or `url` is refused rather than kept as literal text, so
//! adding substitution later changes the meaning of no configuration written
//! today.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[external]]";

/// Every key an `[[external]]` entry may carry.
const KEYS: [&str; 4] = ["path", "url", "rev", "enabled"];

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
    /// The full commit id it is kept at.
    pub rev: String,
    /// `false` in any layer removes the external from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
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

    let rev = ctx.required_str(table, "rev")?;
    if let Some(problem) = unusable_rev(rev) {
        return Err(ctx.bad(table, "rev", format!("`{path}`: {problem}")));
    }

    Ok(External {
        path,
        url: url.to_string(),
        rev: rev.to_string(),
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
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
fn unusable_url(url: &str) -> Option<String> {
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
fn unusable_rev(rev: &str) -> Option<String> {
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
         is read"
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
        assert_eq!(external.rev, REV);
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
    fn a_key_beyond_path_url_rev_and_enabled_is_refused() {
        let err = parse(&format!(
            "{}branch = \"main\"\n",
            entry("~/a", "https://h/o/a", REV)
        ))
        .unwrap_err();
        assert!(
            err.contains("unknown key `branch` in [[external]]"),
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
                "[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\n".to_string(),
                "rev",
            ),
        ] {
            let err = parse(&text).unwrap_err();
            assert!(
                err.contains(&format!("missing the required key `{key}`")),
                "{err}"
            );
        }
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
