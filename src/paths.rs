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
//! This module also holds the crate's **one** home-resolution mechanism. Every
//! rule in it takes its environment as an argument — [`home_in`], [`xdg_base`],
//! [`config_root_in`] — and [`home`] and [`config_root`] are one-line wrappers
//! that read the process environment and nothing more. The crate never *writes*
//! to the process environment: `std::env::set_var` is `unsafe` in edition 2024
//! because its precondition is process-wide, and under `cargo test` no code can
//! establish it. Design-by-parameter is how the rules stay testable without it.
//!
//! Every other module that needs a base directory calls [`xdg_base`]; nothing
//! adds a second resolver.

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
///
/// Anything else is returned exactly as written, which for an unrooted string
/// means a **relative** path. [`Portable`] is the checked entry point and can
/// never hold such a value — it rejects every root this function cannot expand
/// — so [`Portable::render`] never reaches that arm.
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
    /// A `~`-rooted path whose `..` segments climb out of the home it is
    /// relative to.
    #[error("a portable path may not climb out of the home it is rooted in: {0}")]
    EscapesRoot(String),
    /// A `~`-prefixed string whose root is neither `~` nor `~/` — `~other`, or
    /// a `~.config/x` that lost its slash.
    ///
    /// [`render`] expands only `~` and `~/`, so such a value would reach the
    /// filesystem verbatim and resolve against whatever directory bx happened
    /// to be invoked from.
    #[error(
        "bx expands only `~` and `~/…`, so {0} would resolve against whatever directory \
         bx was invoked from; write `~/…` or an absolute path"
    )]
    UnknownRoot(String),
}

/// Normalise a rooted path lexically, without touching the filesystem.
///
/// Collapses `//` and `.`, and resolves `..` textually. Lexical and not
/// `canonicalize`, because a portable path names a destination that need not
/// exist yet, and because resolving symlinks would make the result depend on the
/// machine — which is the one thing a *portable* path may not do.
///
/// An absolute path clamps at `/`, as the kernel does: `/a/../..` is `/`. A
/// `~`-rooted path does not clamp, because `~/..` is a real location outside the
/// home and silently reading it as the home would be the surprise.
fn normalise(raw: &str) -> Result<String, Error> {
    let Some((root, rest)) = split_root(raw) else {
        return Err(if raw.starts_with('~') {
            Error::UnknownRoot(raw.to_string())
        } else {
            Error::NotPortable(raw.to_string())
        });
    };

    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() && !root.is_empty() {
                    return Err(Error::EscapesRoot(raw.to_string()));
                }
            }
            named => parts.push(named),
        }
    }

    Ok(match (root, parts.is_empty()) {
        ("", _) => format!("/{}", parts.join("/")),
        (root, true) => root.to_string(),
        (root, false) => format!("{root}/{}", parts.join("/")),
    })
}

/// Split a rooted path into its root token and the rest.
///
/// The root is `""` for an absolute path and `"~"` for the invoking user's home.
/// Those are the only two roots [`render`] expands, so they are the only two a
/// [`Portable`] may hold; `None` for anything else, a `~name` token included.
///
/// Treating every `~`-prefixed string as rooted, with the bytes up to the first
/// `/` as its root, is what let `~.config/starship.toml` — one missing slash —
/// parse as a root named `~.config` that `render` then handed to the filesystem
/// as a relative path.
fn split_root(raw: &str) -> Option<(&str, &str)> {
    if let Some(rest) = raw.strip_prefix('/') {
        return Some(("", rest));
    }
    if raw == "~" {
        return Some(("~", ""));
    }
    raw.strip_prefix("~/").map(|rest| ("~", rest))
}

/// The home-directory rule, given what `$HOME` holds.
///
/// The whole of the rule lives here rather than in [`home`], so a test can
/// exercise an unset, empty or relative home by passing one rather than by
/// mutating the process environment. `std::env::set_var` is `unsafe` in edition
/// 2024 because its precondition is process-wide — no other thread reading the
/// environment, including through `getenv` inside libc — and `cargo test` cannot
/// establish that. Design-by-parameter is how this crate avoids needing to.
///
/// bx does not fall back to `getpwuid`: `$HOME` is what every shell, every tool
/// bx configures, and the user's own dotfiles already agree on, and silently
/// disagreeing with them is exactly the surprise this tool exists to prevent.
///
/// An empty value is treated as unset, because an empty home would make every
/// `~`-rooted path resolve to a bare relative path.
///
/// # Errors
///
/// [`Error::HomeUnset`] when `raw` is `None` or empty, and
/// [`Error::HomeNotAbsolute`] when it is a relative path.
pub fn home_in(raw: Option<&OsStr>) -> Result<PathBuf, Error> {
    let raw = raw.ok_or(Error::HomeUnset)?;
    if raw.is_empty() {
        return Err(Error::HomeUnset);
    }
    let home = PathBuf::from(raw);
    if !home.is_absolute() {
        return Err(Error::HomeNotAbsolute(home));
    }
    Ok(home)
}

/// The invoking user's home directory, from `$HOME`.
///
/// The **only** read of `$HOME` in the crate, and a read is all it is: nothing
/// here or anywhere in this crate writes to the process environment. The rule it
/// applies is [`home_in`]'s.
///
/// # Errors
///
/// Whatever [`home_in`] returns for the current `$HOME`.
pub fn home() -> Result<PathBuf, Error> {
    home_in(std::env::var_os("HOME").as_deref())
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
/// There are exactly two shapes: `~`-rooted, and absolute. A `~name` string is
/// **rejected**, because [`render`] expands only `~` and `~/` — storing one
/// would leave a value that renders to a bare relative path, and a relative
/// destination depends on the directory bx happened to be invoked from. That is
/// the same reason [`Portable::parse`] rejects a relative path outright.
///
/// # Every `Portable` is lexically normalised
///
/// `//` and `.` are collapsed and `..` is resolved when the value is built, and
/// a `~`-rooted path that climbs out of `~` is rejected outright. Two things
/// depend on that and neither is optional:
///
/// * Its `Ord` and `Hash` are over the stored string, and it is the key of a
///   target, of entry A4's ledger and of entry A6's journal. Without
///   normalisation `~/.ssh/config` and `~/.ssh/./config` are two keys for one
///   file, so one file acquires two ledger rows and Invariant 4 fails at the key
///   rather than at the writer.
/// * [`Portable::under_home`] is a claim about *location*. Without
///   normalisation `~/../../etc/passwd` is "under home" and renders to a path
///   the kernel resolves to `/etc/passwd`, so a caller gating a write on it
///   gates on nothing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Portable(String);

impl Portable {
    /// Make `path` portable against `home`.
    ///
    /// Both arguments are normalised lexically first, so a `..` inside `path`
    /// is resolved *before* the home prefix is stripped — otherwise
    /// `/home/a/../../etc` under home `/home/a` would become the escaping
    /// `~/../../etc`.
    ///
    /// `path` is expected to be absolute. [`to_portable`] leaves anything
    /// outside `home` exactly as it was, so a relative `path` yields a relative
    /// `Portable`; use [`Portable::parse`] when the input is untrusted.
    #[must_use]
    pub fn from_path(path: &Path, home: &Path) -> Self {
        let path = normalised_or_given(path);
        let home = normalised_or_given(home);
        Self(to_portable(Path::new(&path), Path::new(&home)))
    }

    /// Parse a portable path written by a human.
    ///
    /// The result is lexically normalised: `//` and `.` collapse and `..`
    /// resolves, so one file has exactly one spelling.
    ///
    /// # Errors
    ///
    /// [`Error::NotPortable`] if `raw` is neither `~`- nor `/`-rooted. A
    /// relative path has no defined meaning in a config repo: it would depend on
    /// the working directory bx happened to be invoked from.
    ///
    /// [`Error::EscapesRoot`] if `raw` is `~`-rooted and its `..` segments climb
    /// out of the home. `~/../x` is not a home-relative path, and treating it as
    /// one is how a check on [`Portable::under_home`] becomes a check on
    /// nothing.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        normalise(raw).map(Self)
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
    /// A true statement about location, because a `Portable` is normalised when
    /// it is built and one that climbs out of `~` never exists.
    ///
    /// The two shapes are exhaustive: a `Portable` is `~`-rooted, and under the
    /// home, or absolute, and not.
    #[must_use]
    pub fn under_home(&self) -> bool {
        self.0 == "~" || self.0.starts_with("~/")
    }
}

/// Normalise a path lexically, keeping it as it was if it has no root.
fn normalised_or_given(path: &Path) -> String {
    let raw = path.to_string_lossy();
    normalise(&raw).unwrap_or_else(|_| raw.into_owned())
}

impl std::fmt::Display for Portable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- the home rule, and reading it from the environment ---------------

    #[test]
    fn an_unset_home_is_an_error() {
        assert_eq!(home_in(None), Err(Error::HomeUnset));
        assert_eq!(
            home_in(Some(OsStr::new(""))),
            Err(Error::HomeUnset),
            "an empty HOME would make every ~ path relative"
        );
    }

    #[test]
    fn a_relative_home_is_an_error() {
        assert_eq!(
            home_in(Some(OsStr::new("not/absolute"))),
            Err(Error::HomeNotAbsolute(PathBuf::from("not/absolute")))
        );
        assert_eq!(
            home_in(Some(OsStr::new("."))),
            Err(Error::HomeNotAbsolute(PathBuf::from(".")))
        );
    }

    #[test]
    fn an_absolute_home_is_taken_as_given() {
        assert_eq!(home_in(Some(OsStr::new("/var/home/example"))), Ok(home()));
    }

    #[test]
    fn a_non_utf8_home_is_honoured() {
        use std::os::unix::ffi::OsStrExt;

        let raw = OsStr::from_bytes(b"/var/home/exa\xffmple");
        assert_eq!(home_in(Some(raw)), Ok(PathBuf::from(raw)));
    }

    #[test]
    fn the_process_home_is_read_and_never_written() {
        // The wrapper is one line, and this pins it without mutating anything:
        // reading $HOME agrees with the rule applied to $HOME. Mutating the
        // environment here would be unsound -- see `home_in` and `testing`.
        let raw = std::env::var_os("HOME");
        let before = raw.clone();

        assert_eq!(super::home(), home_in(raw.as_deref()));
        assert_eq!(
            std::env::var_os("HOME"),
            before,
            "resolving a home must not change one"
        );
    }

    #[test]
    fn the_config_root_is_read_from_the_process_environment() {
        let expected = super::home()
            .map(|home| config_root_in(&home, std::env::var_os("XDG_CONFIG_HOME").as_deref()));

        assert_eq!(config_root(), expected);
    }

    #[test]
    fn the_config_root_fails_exactly_when_the_home_does() {
        // `config_root` is `home` composed with `config_root_in`, so its error
        // path is the composition's and is pinned at the parameterised end.
        assert_eq!(
            home_in(None).map(|home| config_root_in(&home, None)),
            Err(Error::HomeUnset)
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
        let unknown_root = Error::UnknownRoot("~.config/x".to_string()).to_string();
        assert!(unknown_root.contains("~.config/x"), "{unknown_root}");
        assert!(
            unknown_root.contains("expands only"),
            "the message must say what bx does expand: {unknown_root}"
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
    fn a_tilde_root_bx_cannot_expand_is_rejected() {
        // `render` expands `~` and `~/` and nothing else, so any other `~` root
        // would be handed to the filesystem verbatim -- that is, relative to
        // whatever directory bx was invoked from. `~.config/starship.toml` is
        // the realistic one: a config author dropping a single slash would
        // otherwise get a directory literally named `~.config` created wherever
        // `bx apply` ran, and `bx rm` from elsewhere would restore a different
        // file.
        for raw in [
            "~.config/starship.toml",
            "~other/x",
            "~other/.linuxbrew",
            "~other",
            "~~/x",
            "~ /x",
        ] {
            assert_eq!(
                Portable::parse(raw),
                Err(Error::UnknownRoot(raw.to_string())),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_portable_always_renders_to_an_absolute_path() {
        // The property the rejection above exists to establish: no value this
        // type can hold renders to a path that depends on the working
        // directory.
        for raw in ["~", "~/.ssh/config", "/usr/bin/sccache", "/", "/a/../b"] {
            let rendered = Portable::parse(raw).unwrap().render(&home());
            assert!(
                rendered.is_absolute(),
                "{raw} rendered {}",
                rendered.display()
            );
        }
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
    fn a_portable_is_lexically_normalised() {
        // One file, one spelling. Ord and Hash are over this string, and it is
        // the key of a target, of the ledger and of the journal.
        for (written, stored) in [
            ("~/.ssh/./config", "~/.ssh/config"),
            ("~/.ssh//config", "~/.ssh/config"),
            ("~/.ssh/", "~/.ssh"),
            ("~/.ssh/keys/../config", "~/.ssh/config"),
            ("~/./", "~"),
            ("/usr//bin/./sccache", "/usr/bin/sccache"),
        ] {
            assert_eq!(
                Portable::parse(written).unwrap().as_str(),
                stored,
                "{written}"
            );
        }
    }

    #[test]
    fn differently_spelled_paths_are_one_key() {
        use std::collections::HashSet;

        let spellings = ["~/.ssh/config", "~/.ssh/./config", "~/.ssh//config"];
        let keys: HashSet<Portable> = spellings
            .iter()
            .map(|raw| Portable::parse(raw).unwrap())
            .collect();

        assert_eq!(keys.len(), 1, "one file must not acquire three ledger rows");
    }

    #[test]
    fn a_portable_that_climbs_out_of_home_is_rejected() {
        // under_home() is a claim about location, so this may not parse.
        for escaping in ["~/..", "~/../../etc/passwd", "~/.ssh/../../etc"] {
            assert_eq!(
                Portable::parse(escaping),
                Err(Error::EscapesRoot(escaping.to_string())),
                "{escaping}"
            );
        }
        assert_eq!(
            Error::EscapesRoot("~/..".to_string()).to_string(),
            "a portable path may not climb out of the home it is rooted in: ~/.."
        );
    }

    #[test]
    fn an_absolute_portable_clamps_at_the_root() {
        // The kernel resolves /.. to /, and so does this.
        assert_eq!(Portable::parse("/..").unwrap().as_str(), "/");
        assert_eq!(Portable::parse("/a/../..").unwrap().as_str(), "/");
        assert_eq!(Portable::parse("/a/../b").unwrap().as_str(), "/b");
        assert_eq!(Portable::parse("/").unwrap().as_str(), "/");
    }

    #[test]
    fn from_path_normalises_before_it_makes_portable() {
        // Stripping the home prefix first would turn this into `~/../../etc`,
        // which is exactly the escaping value parse() refuses.
        let portable = Portable::from_path(
            Path::new("/var/home/example/.ssh/../../../../etc/passwd"),
            &home(),
        );

        assert_eq!(portable.as_str(), "/etc/passwd");
        assert!(!portable.under_home());
        assert_eq!(portable.render(&home()), Path::new("/etc/passwd"));
    }

    #[test]
    fn from_path_collapses_redundant_segments() {
        assert_eq!(
            Portable::from_path(Path::new("/var/home/example/.ssh/./config"), &home()).as_str(),
            "~/.ssh/config"
        );
        assert_eq!(
            Portable::from_path(Path::new("/var/home/example/a/../b"), &home()).as_str(),
            "~/b"
        );
    }

    #[test]
    fn from_path_leaves_a_relative_path_alone() {
        // Documented fallback: a relative input has no root to normalise
        // against, and parse() is what a caller uses on untrusted input.
        assert_eq!(
            Portable::from_path(Path::new("files/starship.toml"), &home()).as_str(),
            "files/starship.toml"
        );
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
