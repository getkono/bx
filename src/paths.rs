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

use std::path::{Path, PathBuf};

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
}
