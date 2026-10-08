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
