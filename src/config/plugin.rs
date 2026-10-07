//! Reading `[[plugin]]` into [`PluginDecl`]s, and the rule every path a
//! guarded `source` line is written with must keep.
//!
//! The line itself, and the phases a plugin loads in, are
//! [`crate::shell::plugin`]'s.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error};
use crate::shell::plugin::PluginDecl;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[plugin]]";

/// Every key a `[[plugin]]` entry may carry.
const KEYS: [&str; 4] = ["name", "source", "terminal", "enabled"];

/// Parse one `[[plugin]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_plugin(table: &Table, file: &Path, text: &str) -> Result<PluginDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not a plugin name: a name is non-empty and on one line"),
        ));
    }

    let source = ctx.required_str(table, "source")?.to_string();
    if let Some(problem) = unsourceable("source", &source) {
        return Err(ctx.bad(table, "source", format!("`{name}`: {problem}")));
    }

    Ok(PluginDecl {
        name,
        source,
        terminal: ctx.bool_at(table, "terminal")?.unwrap_or(false),
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Why `source` cannot be written bare into a guarded line, or `None` when it
/// can. `key` is the field the path was written under (`source` for a plugin,
/// `path` for a source), so the message names the key the user wrote.
pub(crate) fn unsourceable(key: &str, source: &str) -> Option<String> {
    if !(source.starts_with("~/") || source.starts_with('/')) {
        return Some(format!(
            "`{key} = {source:?}` must open with `~/` or `/`: a relative path would be \
             read from whatever directory the shell starts in"
        ));
    }
    // The leading `~` is the one zsh expands; anywhere else a `~` is a glob
    // operator under `extended_glob`, so it is refused with the rest.
    let rest = source.strip_prefix('~').unwrap_or(source);
    rest.chars()
        .find(|c| !(c.is_ascii_alphanumeric() || "_./,:@%+-".contains(*c)))
        .map(|c| {
            format!(
                "`{key} = {source:?}` is written unquoted, so after a leading `~` it may hold \
                 only ASCII letters, digits and `_./,:@%+-`; found {c:?}"
            )
        })
}
