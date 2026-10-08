//! Reading `[[plugin]]` into [`PluginDecl`]s, the one-claimant rule for the
//! terminal slot, and the rule every path a guarded `source` line is written
//! with must keep.
//!
//! The line itself is [`crate::shell::plugin`]'s.

use std::path::Path;

use toml_edit::Table;

use super::shells::Phase;
use super::{Ctx, Error, Origin};

/// One `[[plugin]]` entry, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDecl {
    /// The plugin's name, its natural key.
    pub name: String,
    /// The file sourced, as written.
    pub source: String,
    /// Whether it claims the terminal slot.
    pub terminal: bool,
    /// `false` in any layer removes the plugin from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

impl PluginDecl {
    /// The phase the plugin loads in.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        if self.terminal {
            Phase::Terminal
        } else {
            Phase::Plugins
        }
    }
}

/// Refuse a second enabled plugin that claims the terminal slot.
///
/// Run once the layers are merged, over the plugins that survived it, so a
/// claim a later layer switched off does not count.
///
/// # Errors
///
/// [`Error::BadValue`] at the second claimant's origin, naming both plugins and
/// where the first was declared.
pub fn check_terminal(plugins: &[PluginDecl]) -> Result<(), Error> {
    let mut claimants = plugins.iter().filter(|p| p.enabled && p.terminal);
    let Some(first) = claimants.next() else {
        return Ok(());
    };
    match claimants.next() {
        None => Ok(()),
        Some(second) => Err(Error::BadValue {
            origin: second.origin.clone(),
            message: format!(
                "plugin `{}` claims the terminal slot, which plugin `{}` already claims at {}; \
                 only one plugin can load after everything else, so set `terminal = false` \
                 on one of them",
                second.name, first.name, first.origin
            ),
        }),
    }
}

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
