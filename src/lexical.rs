//! Lexical predicates the config parsers and the environment guard share.
//!
//! A leaf: it reads no configuration and judges no fragment, so the parsers
//! that check what a config author wrote and [`crate::env_guard`], which
//! judges what bx generates from it, can both ask it without either reaching
//! into the other. One predicate here is one answer everywhere, so the parser
//! and the guard cannot disagree on it.

/// Whether `name` is a variable name every shell and `environment.d` read the
/// same way: `[A-Za-z_][A-Za-z0-9_]*`.
///
/// The `[[env]]` parser checks a declared name with this same predicate, so
/// the parser and the guard cannot disagree on what a variable name is.
pub(crate) fn is_variable_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether the normalised path `path` is `root` or lies beneath it, judged on
/// the text alone: `~/Library/x` is within `~/Library`, `~/Libraryx` is not.
///
/// Both must already be lexically normalised — `.` and `..` resolved, no
/// doubled or trailing `/` — as a [`crate::paths::Portable`] is. Nothing is
/// read from the filesystem, so a symlink into `root` is not seen; the same
/// limit the environment guard's containment states.
pub(crate) fn is_within(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_within_its_root_and_what_lies_beneath_it_only() {
        assert!(is_within("~/Library", "~/Library"));
        assert!(is_within("~/Library/Preferences/x.plist", "~/Library"));
        assert!(!is_within("~/Libraryx", "~/Library"));
        assert!(!is_within("~/Libraryx/y", "~/Library"));
        assert!(!is_within("~", "~/Library"));
        assert!(!is_within("~/.config/systemd", "~/.config/systemd/user"));
    }
}
