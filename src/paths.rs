//! Home-relative paths, so a config repo moves between machines.
//!
//! A home directory is not necessarily `/home/<user>`: an ostree system puts it
//! under `/var/home`, and an account whose home lives on scratch storage puts it
//! somewhere else again. Any absolute path committed to a config repo therefore
//! breaks the moment the repo is used anywhere else. bx stores paths *portably*
//! — `~`-prefixed — and renders them against the local `$HOME` at apply time.
//!
//! Substitution is **leading-position only**. A `~` in the middle of a line is
//! ordinary content (a shell glob, a backup filename, prose) and is left alone,
//! so rendering can never corrupt a file's body. That restriction is what lets
//! bx avoid a template language entirely.
//!
//! This module also holds the crate's **one** home-resolution mechanism.
//! [`home`] is the only function that reads `$HOME`, and [`xdg_base`] is the
//! whole XDG base-directory rule in one place, taking its environment as an
//! argument so it is testable and so a caller that already knows the home does
//! not read the process environment a second time. Every other module that
//! needs a base directory calls [`xdg_base`]; nothing adds a second resolver.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Rewrite `path` as `~`-relative if it lies under `home`.
///
/// Paths outside `home` are returned unchanged: they are genuinely absolute
/// (`/usr/bin/sccache`), and pretending otherwise would break them.
#[must_use]
pub fn to_portable(path: &Path, home: &Path) -> String {
    let raw = path.to_string_lossy();
    if path == home {
        return "~".to_string();
    }
    match path.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.to_string_lossy()),
        Err(_) => raw.into_owned(),
    }
}

/// Resolve a portable path against `home`.
///
/// Only a leading `~` or `~/` is expanded. `~user` is *not*: bx manages the
/// invoking user's environment, and silently resolving another user's home
/// would be a surprise of exactly the kind this tool exists to prevent.
#[must_use]
pub fn render(portable: &str, home: &Path) -> PathBuf {
    match portable {
        "~" => home.to_path_buf(),
        _ => match portable.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(portable),
        },
    }
}

/// Expand leading `~/` on every line of repo content.
///
/// Applied to file bodies bx writes out of the repo. Leading whitespace is
/// preserved, so indented config keeps its shape.
#[must_use]
pub fn render_content(content: &str, home: &Path) -> String {
    let home = home.to_string_lossy();
    let mut out = String::with_capacity(content.len());
    // split_inclusive keeps each line's newline attached, so the terminator is
    // carried through untouched and a missing trailing newline stays missing.
    for line in content.split_inclusive('\n') {
        let indent_len = line.len() - line.trim_start().len();
        let (indent, rest) = line.split_at(indent_len);
        out.push_str(indent);
        match rest.strip_prefix("~/") {
            Some(tail) => {
                out.push_str(&home);
                out.push('/');
                out.push_str(tail);
            }
            None => out.push_str(rest),
        }
    }
    out
}

/// Everything that can go wrong resolving a path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `$HOME` is unset or empty.
    #[error("HOME is not set; bx manages a user environment and has no home to manage")]
    HomeUnset,
    /// `$HOME` is set to something that is not an absolute path.
    #[error("HOME is not an absolute path: {}", .0.display())]
    HomeNotAbsolute(PathBuf),
    /// A string that should have been a portable path is neither `~`- nor
    /// `/`-rooted.
    #[error("a portable path must start with `~` or `/`, got {0}")]
    NotPortable(String),
}

/// The invoking user's home directory, from `$HOME`.
///
/// The **only** read of `$HOME` in the crate. bx does not fall back to
/// `getpwuid`: `$HOME` is what every shell, every tool bx configures, and the
/// user's own dotfiles already agree on, and silently disagreeing with them is
/// exactly the surprise this tool exists to prevent.
///
/// An empty `$HOME` is treated as unset, because an empty home would make every
/// `~`-rooted path resolve to a bare relative path.
///
/// # Errors
///
/// [`Error::HomeUnset`] when `$HOME` is absent or empty, and
/// [`Error::HomeNotAbsolute`] when it is set to a relative path.
pub fn home() -> Result<PathBuf, Error> {
    let raw = std::env::var_os("HOME").ok_or(Error::HomeUnset)?;
    if raw.is_empty() {
        return Err(Error::HomeUnset);
    }
    let home = PathBuf::from(raw);
    if !home.is_absolute() {
        return Err(Error::HomeNotAbsolute(home));
    }
    Ok(home)
}

/// Resolve one XDG base directory.
///
/// The whole rule, in one place. `explicit` is the `XDG_*_HOME` value if the
/// caller has one. The base-directory specification says such a value is honoured
/// only when it is **non-empty and absolute**; anything else is invalid and the
/// default applies. `fallback_rel` is that default, relative to `home` —
/// `".config"`, `".local/state"`, `".local/share"`, `".cache"`.
///
/// Taking the environment as an argument rather than reading it is what lets the
/// state directory (entry A4) reuse this function instead of adding a second
/// mechanism that could drift from this one.
#[must_use]
pub fn xdg_base(explicit: Option<&OsStr>, home: &Path, fallback_rel: &str) -> PathBuf {
    match explicit {
        Some(value) if !value.is_empty() && Path::new(value).is_absolute() => PathBuf::from(value),
        _ => home.join(fallback_rel),
    }
}

/// The config repo root — `$XDG_CONFIG_HOME/bx`, default `~/.config/bx`.
///
/// A git working tree, safe to publish, holding only committed and
/// account-independent material.
#[must_use]
pub fn config_root_in(home: &Path, xdg_config_home: Option<&OsStr>) -> PathBuf {
    xdg_base(xdg_config_home, home, ".config").join("bx")
}

/// The config repo root, resolved from the process environment.
///
/// # Errors
///
/// Whatever [`home`] returns.
pub fn config_root() -> Result<PathBuf, Error> {
    let home = home()?;
    Ok(config_root_in(
        &home,
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
    ))
}

/// A path as the config repo stores it: `~`-rooted, or absolute.
///
/// The natural key of a [`crate::config::target::Target`], and the key entry
/// A4's ledger and entry A6's journal are written against — which is why it
/// derives `Ord`, `Hash` and serde here rather than being newtyped again in
/// each of them.
///
/// A `~user` string is *accepted* and never expanded, matching [`render`]: bx
/// manages the invoking user's environment, and resolving someone else's home
/// would be a surprise. [`Portable::under_home`] is how a caller asks whether a
/// portable path is one of the invoking user's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Portable(String);

impl Portable {
    /// Make `path` portable against `home`.
    ///
    /// `path` is expected to be absolute. [`to_portable`] leaves anything
    /// outside `home` exactly as it was, so a relative `path` yields a relative
    /// `Portable`; use [`Portable::parse`] when the input is untrusted.
    #[must_use]
    pub fn from_path(path: &Path, home: &Path) -> Self {
        Self(to_portable(path, home))
    }

    /// Parse a portable path written by a human.
    ///
    /// # Errors
    ///
    /// [`Error::NotPortable`] if `raw` is neither `~`- nor `/`-rooted. A
    /// relative path has no defined meaning in a config repo: it would depend on
    /// the working directory bx happened to be invoked from.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        if raw.starts_with('~') || raw.starts_with('/') {
            Ok(Self(raw.to_string()))
        } else {
            Err(Error::NotPortable(raw.to_string()))
        }
    }

    /// The stored string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Resolve against `home`.
    #[must_use]
    pub fn render(&self, home: &Path) -> PathBuf {
        render(&self.0, home)
    }

    /// Whether this path lies under the invoking user's home.
    ///
    /// `~user/...` is not: it is another account's home, and bx never expands it.
    #[must_use]
    pub fn under_home(&self) -> bool {
        self.0 == "~" || self.0.starts_with("~/")
    }
}

impl std::fmt::Display for Portable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::guarded_home;

    fn home() -> PathBuf {
        // A deliberately non-standard home: nothing here may name a real
        // account, and nothing here may assume `/home/<user>`.
        PathBuf::from("/var/home/example")
    }

    #[test]
    fn a_path_under_home_becomes_tilde_relative() {
        assert_eq!(
            to_portable(Path::new("/var/home/example/.gitconfig"), &home()),
            "~/.gitconfig"
        );
    }

    #[test]
    fn a_nested_path_keeps_its_tail() {
        assert_eq!(
            to_portable(
                Path::new("/var/home/example/.ssh/config.d/10-hosts.conf"),
                &home()
            ),
            "~/.ssh/config.d/10-hosts.conf"
        );
    }

    #[test]
    fn home_itself_is_a_bare_tilde() {
        assert_eq!(to_portable(&home(), &home()), "~");
    }

    #[test]
    fn a_path_outside_home_is_left_absolute() {
        assert_eq!(
            to_portable(Path::new("/usr/bin/sccache"), &home()),
            "/usr/bin/sccache"
        );
    }

    #[test]
    fn a_prefix_that_is_not_a_path_component_does_not_match() {
        // /var/home/example-backup is not inside /var/home/example.
        assert_eq!(
            to_portable(Path::new("/var/home/example-backup/x"), &home()),
            "/var/home/example-backup/x"
        );
    }

    #[test]
    fn rendering_reverses_portability() {
        let original = Path::new("/var/home/example/.config/starship.toml");
        assert_eq!(render(&to_portable(original, &home()), &home()), original);
    }

    #[test]
    fn the_same_repo_renders_against_a_different_home() {
        // The whole point: one repo, two machines.
        assert_eq!(
            render("~/.gitconfig", Path::new("/home/other")),
            Path::new("/home/other/.gitconfig")
        );
        assert_eq!(
            render("~/.gitconfig", &home()),
            Path::new("/var/home/example/.gitconfig")
        );
    }

    #[test]
    fn a_bare_tilde_renders_to_home() {
        assert_eq!(render("~", &home()), home());
    }

    #[test]
    fn an_absolute_path_renders_unchanged() {
        assert_eq!(
            render("/usr/bin/sccache", &home()),
            Path::new("/usr/bin/sccache")
        );
    }

    #[test]
    fn another_users_home_is_never_expanded() {
        assert_eq!(
            render("~other/.linuxbrew", &home()),
            Path::new("~other/.linuxbrew")
        );
    }

    #[test]
    fn content_expands_a_leading_tilde_per_line() {
        let rendered = render_content("~/.cargo/bin\n~/.local/bin\n", &home());
        assert_eq!(
            rendered,
            "/var/home/example/.cargo/bin\n/var/home/example/.local/bin\n"
        );
    }

    #[test]
    fn content_preserves_indentation() {
        let rendered = render_content("  ~/.ssh/config.d/*.conf\n", &home());
        assert_eq!(rendered, "  /var/home/example/.ssh/config.d/*.conf\n");
    }

    #[test]
    fn a_tilde_that_is_not_leading_is_content() {
        // Rendering must never corrupt a file body: these are all real config.
        let body = "path = a~b\nignore = *~\nbackup=~/x is not leading\n";
        assert_eq!(render_content(body, &home()), body);
    }

    #[test]
    fn content_without_a_trailing_newline_is_preserved() {
        assert_eq!(
            render_content("~/.gitconfig", &home()),
            "/var/home/example/.gitconfig"
        );
    }

    #[test]
    fn empty_content_stays_empty() {
        assert_eq!(render_content("", &home()), "");
    }

    // --- the XDG rule -----------------------------------------------------

    #[test]
    fn the_config_root_defaults_to_dot_config_under_home() {
        assert_eq!(
            config_root_in(&home(), None),
            Path::new("/var/home/example/.config/bx")
        );
    }

    #[test]
    fn an_absolute_xdg_config_home_wins() {
        assert_eq!(
            config_root_in(&home(), Some(OsStr::new("/etc/xdg-for-this-account"))),
            Path::new("/etc/xdg-for-this-account/bx")
        );
    }

    #[test]
    fn an_empty_xdg_config_home_falls_back_to_the_default() {
        // The base-directory specification calls an empty value invalid.
        assert_eq!(
            config_root_in(&home(), Some(OsStr::new(""))),
            Path::new("/var/home/example/.config/bx")
        );
    }

    #[test]
    fn a_relative_xdg_config_home_is_invalid_and_falls_back() {
        assert_eq!(
            config_root_in(&home(), Some(OsStr::new("relative/config"))),
            Path::new("/var/home/example/.config/bx")
        );
    }

    #[test]
    fn a_non_utf8_xdg_config_home_is_honoured() {
        use std::os::unix::ffi::OsStrExt;

        let raw = OsStr::from_bytes(b"/var/tmp/xdg\xff");
        assert_eq!(
            config_root_in(&home(), Some(raw)),
            Path::new(OsStr::from_bytes(b"/var/tmp/xdg\xff")).join("bx")
        );
    }

    #[test]
    fn the_state_base_uses_the_same_rule() {
        // Entry A4 builds the state root this way rather than adding a second
        // resolver; this test is what pins that for it.
        assert_eq!(
            xdg_base(None, &home(), ".local/state").join("bx"),
            Path::new("/var/home/example/.local/state/bx")
        );
        assert_eq!(
            xdg_base(Some(OsStr::new("/var/state")), &home(), ".local/state").join("bx"),
            Path::new("/var/state/bx")
        );
    }

    // --- reading the process environment ---------------------------------

    #[test]
    fn the_config_root_is_read_from_the_process_environment() {
        let guard = guarded_home();

        assert_eq!(super::home().unwrap(), guard.path());
        assert_eq!(config_root().unwrap(), guard.child(".config/bx"));

        let explicit = guard.child("xdg-config");
        guard.set("XDG_CONFIG_HOME", Some(explicit.as_os_str()));
        assert_eq!(config_root().unwrap(), explicit.join("bx"));
    }

    #[test]
    fn an_unset_home_is_an_error() {
        let guard = guarded_home();

        guard.set("HOME", None);
        assert_eq!(super::home(), Err(Error::HomeUnset));
        assert_eq!(config_root(), Err(Error::HomeUnset));

        guard.set("HOME", Some(OsStr::new("")));
        assert_eq!(
            super::home(),
            Err(Error::HomeUnset),
            "an empty HOME would make every ~ path relative"
        );
    }

    #[test]
    fn a_relative_home_is_an_error() {
        let guard = guarded_home();

        guard.set("HOME", Some(OsStr::new("not/absolute")));
        assert_eq!(
            super::home(),
            Err(Error::HomeNotAbsolute(PathBuf::from("not/absolute")))
        );
    }

    #[test]
    fn every_path_error_says_what_is_wrong() {
        assert!(Error::HomeUnset.to_string().contains("HOME is not set"));
        assert_eq!(
            Error::HomeNotAbsolute(PathBuf::from("rel")).to_string(),
            "HOME is not an absolute path: rel"
        );
        assert_eq!(
            Error::NotPortable("rel/x".to_string()).to_string(),
            "a portable path must start with `~` or `/`, got rel/x"
        );
    }

    // --- Portable ---------------------------------------------------------

    #[test]
    fn a_portable_round_trips_through_the_newtype() {
        let original = Path::new("/var/home/example/.config/starship.toml");
        let portable = Portable::from_path(original, &home());

        assert_eq!(portable.as_str(), "~/.config/starship.toml");
        assert_eq!(portable.to_string(), "~/.config/starship.toml");
        assert_eq!(portable.render(&home()), original);
        assert!(portable.under_home());
    }

    #[test]
    fn a_portable_outside_home_stays_absolute_and_is_not_under_home() {
        let portable = Portable::from_path(Path::new("/usr/bin/sccache"), &home());

        assert_eq!(portable.as_str(), "/usr/bin/sccache");
        assert!(!portable.under_home());
        assert_eq!(portable.render(&home()), Path::new("/usr/bin/sccache"));
    }

    #[test]
    fn another_users_home_is_portable_but_not_under_home() {
        let portable = Portable::parse("~other/.linuxbrew").unwrap();

        assert!(!portable.under_home());
        assert_eq!(portable.render(&home()), Path::new("~other/.linuxbrew"));
    }

    #[test]
    fn a_bare_tilde_is_under_home() {
        assert!(Portable::parse("~").unwrap().under_home());
    }

    #[test]
    fn a_relative_portable_is_rejected() {
        assert_eq!(
            Portable::parse("files/starship.toml"),
            Err(Error::NotPortable("files/starship.toml".to_string()))
        );
        assert_eq!(
            Portable::parse(""),
            Err(Error::NotPortable(String::new())),
            "an empty path is not a path"
        );
    }

    #[test]
    fn a_portable_is_ordered_by_its_string() {
        // Target's natural key is its path, so the ordering has to be total and
        // has to be the obvious one.
        let mut paths = [
            Portable::parse("~/.zshrc").unwrap(),
            Portable::parse("/usr/bin/sccache").unwrap(),
            Portable::parse("~/.config/bx").unwrap(),
        ];
        paths.sort();

        let rendered: Vec<&str> = paths.iter().map(Portable::as_str).collect();
        assert_eq!(rendered, ["/usr/bin/sccache", "~/.config/bx", "~/.zshrc"]);
    }

    #[test]
    fn a_portable_survives_a_serde_round_trip() {
        // A4's ledger and A6's journal are keyed on it, in MessagePack.
        let portable = Portable::parse("~/.ssh/config").unwrap();
        let encoded = rmp_serde::to_vec(&portable).unwrap();
        let decoded: Portable = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded, portable);
    }
}
