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

use std::path::{Component, Path, PathBuf};

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

/// Normalise a path **lexically**: no `.`, no `..`, no repeated or trailing
/// separator — and without touching the filesystem.
///
/// The filesystem is deliberately not consulted. `plan` must describe the same
/// change whether or not the paths it names exist yet, so `canonicalize` — which
/// fails on a missing path and resolves symlinks against whatever happens to be
/// mounted — is not available here. The architecture fixes that rule for the
/// `env_guard` root comparison, and a declared `path` value is normalised with
/// this same function so that a root and a value can be compared at all.
///
/// `..` never walks above the root: `/..` is `/`, because on Linux the root's
/// parent is the root. In a *relative* path a leading `..` is preserved, since
/// there is no earlier component for it to cancel and dropping it would change
/// which directory the path names.
///
/// An empty result normalises to `.`, the shortest path naming the same place.
#[must_use]
pub fn normalize(path: &Path) -> PathBuf {
    let mut out: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            // `Components` already elides an interior `.`; a *leading* one in a
            // relative path survives, and is what this arm removes.
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // `/..` is `/`. Anything else — an empty stack, or one whose
                // last entry is itself a `..` — has nothing to cancel, so the
                // `..` is kept.
                Some(Component::RootDir) => {}
                _ => out.push(component),
            },
            other => out.push(other),
        }
    }
    if out.is_empty() {
        return PathBuf::from(".");
    }
    out.into_iter().collect()
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

    #[test]
    fn normalize_removes_dot_and_dotdot() {
        assert_eq!(
            normalize(Path::new("/var/mnt/scratch/./one/../example/cache")),
            Path::new("/var/mnt/scratch/example/cache")
        );
        assert_eq!(normalize(Path::new("./a/b")), Path::new("a/b"));
    }

    #[test]
    fn normalize_collapses_repeated_and_trailing_slashes() {
        assert_eq!(
            normalize(Path::new("/var//mnt///scratch/")),
            Path::new("/var/mnt/scratch")
        );
    }

    #[test]
    fn normalize_does_not_walk_above_the_root() {
        // The root's parent is the root, so a `..` chain cannot escape it and
        // cannot be used to smuggle a path out of a declared root.
        assert_eq!(normalize(Path::new("/../../..")), Path::new("/"));
        assert_eq!(normalize(Path::new("/a/../../b")), Path::new("/b"));
    }

    #[test]
    fn normalize_keeps_a_leading_dotdot_in_a_relative_path() {
        // Nothing precedes it, so dropping it would name a different directory.
        assert_eq!(normalize(Path::new("../../a")), Path::new("../../a"));
        assert_eq!(normalize(Path::new("a/../../b")), Path::new("../b"));
    }

    #[test]
    fn normalize_reduces_an_empty_result_to_dot() {
        assert_eq!(normalize(Path::new("")), Path::new("."));
        assert_eq!(normalize(Path::new(".")), Path::new("."));
        assert_eq!(normalize(Path::new("a/..")), Path::new("."));
    }

    #[test]
    fn normalize_never_touches_the_filesystem() {
        // Normalising a path that does not exist succeeds and leaves it alone,
        // which `canonicalize` could not do.
        let absent = Path::new("/var/mnt/scratch/example/does/not/exist");
        assert_eq!(normalize(absent), absent);
    }

    #[test]
    fn normalize_is_idempotent() {
        let once = normalize(Path::new("/a/./b/../c//d/"));
        assert_eq!(normalize(&once), once);
    }
}
