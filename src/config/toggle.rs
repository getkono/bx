//! Toggles: a keyed list entry that restates only its key and `enabled`.
//!
//! Read while a layer is parsed, before anything is merged, so it lives apart
//! from [`super::merge`], which applies the toggles a layer holds.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};

/// Which keyed list an entry belongs to.
///
/// An enum rather than the section's name, because [`Toggle`],
/// [`super::Config`], [`super::Layer`] and [`super::merge::merge`] are all
/// public: a section string with no arm in the merge would panic a library
/// call, and a `&str` match has no exhaustiveness checking to stop one being
/// written. The later entries that add keyed sections are exactly the callers
/// that would have hit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// `[[target]]`, keyed by `path`.
    Target,
    /// `[[value]]`, keyed by `name`.
    Value,
    /// `[[env]]`, keyed by `name`.
    Env,
    /// `[[alias]]`, keyed by `name`. The flat `[aliases]` table holds no
    /// toggle, since its entries have no `enabled` key to hold.
    Alias,
    /// `[[function]]`, keyed by `name`.
    Function,
    /// `[[plugin]]`, keyed by `name`.
    Plugin,
    /// `[[source]]`, keyed by `name`.
    Source,
    /// `[[activation]]`, keyed by `name`.
    Activation,
    /// `[[external]]`, keyed by `path`.
    External,
    /// `[[tool]]`, keyed by `name`.
    Tool,
}

impl Section {
    /// The TOML key the section is written under.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Value => "value",
            Self::Env => "env",
            Self::Alias => "alias",
            Self::Function => "function",
            Self::Plugin => "plugin",
            Self::Source => "source",
            Self::Activation => "activation",
            Self::Tool => "tool",
            Self::External => "external",
        }
    }

    /// The section header, as messages spell it.
    #[must_use]
    pub fn header(self) -> &'static str {
        match self {
            Self::Target => super::target::SECTION,
            Self::Value => super::values::DECL_SECTION,
            Self::Env => super::env::SECTION,
            Self::Alias => super::alias::SECTION,
            Self::Function => super::function::SECTION,
            Self::Plugin => super::plugin::SECTION,
            Self::Source => super::source::SECTION,
            Self::Activation => super::activation::SECTION,
            Self::Tool => super::tool::SECTION,
            Self::External => super::external::SECTION,
        }
    }

    /// The natural key an entry in this section merges by.
    #[must_use]
    pub fn natural_key(self) -> &'static str {
        match self {
            Self::Target | Self::External => "path",
            Self::Value
            | Self::Env
            | Self::Alias
            | Self::Function
            | Self::Plugin
            | Self::Source
            | Self::Activation
            | Self::Tool => "name",
        }
    }

    /// What a *full* entry in this section still needs.
    ///
    /// For the one message that has to cover both readings of a toggle-shaped
    /// table: a toggle naming an entry nothing introduced, or an entry somebody
    /// meant to write in full and left incomplete.
    pub(super) fn a_full_entry_needs(self) -> &'static str {
        match self {
            Self::Target => "one of `file`, `content`, `generated` or `dir`",
            Self::Value => "a `kind`",
            Self::Env => "a `value` and a `kind`",
            Self::Alias => "a `command`",
            Self::Function => "a `body`",
            Self::Plugin => "a `source`",
            Self::Source => "a `path`",
            Self::Activation => "a `command`",
            Self::Tool => "an `install`",
            Self::External => "a `url` and a `rev`",
        }
    }
}

/// A list entry that restates only its key and its `enabled` flag.
///
/// Parsed rather than resolved: which list it belongs to is carried as a
/// [`Section`] so one representation serves every keyed section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toggle {
    /// The section it appeared in.
    pub section: Section,
    /// The natural key of the entry it flips.
    pub key: String,
    /// What to flip it to.
    pub enabled: bool,
    /// Where the toggle was written.
    pub origin: Origin,
}

/// Read `table` as a toggle, if that is its whole shape.
///
/// A table whose keys are exactly the natural key and `enabled` is a toggle;
/// anything else is a full entry and is handed to its own parser. The types are
/// checked here rather than deferred, so `enabled = "false"` is reported as the
/// wrong type for `enabled` rather than as a target with no body.
///
/// # Errors
///
/// [`Error::WrongType`] when the two keys are present but not as a string and a
/// boolean.
pub(crate) fn toggle_of(
    table: &Table,
    section: Section,
    file: &Path,
    text: &str,
) -> Result<Option<Toggle>, Error> {
    let natural_key = section.natural_key();
    let keys: Vec<&str> = table.iter().map(|(key, _)| key).collect();
    if keys.len() != 2 || !keys.contains(&natural_key) || !keys.contains(&"enabled") {
        return Ok(None);
    }

    let ctx = Ctx::new(table, file, text, section.header());
    let key = ctx.required_str(table, natural_key)?;
    let enabled = ctx
        .bool_at(table, "enabled")?
        .ok_or_else(|| Error::WrongType {
            origin: ctx.key_origin(table, "enabled"),
            key: "enabled".to_string(),
            expected: "a boolean",
            found: "nothing",
        })?;

    Ok(Some(Toggle {
        section,
        key: key.to_string(),
        enabled,
        origin: ctx.origin().clone(),
    }))
}
