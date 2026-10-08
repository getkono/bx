//! Reading `[keybindings]` into [`Keybindings`].
//!
//! The keys and actions are [`crate::shell::keybindings`]'s closed sets, and
//! it renders them for zsh and readline; this is the parser that holds a
//! layer to them.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error};
use crate::shell::keybindings::{Action, Key, Keybindings};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[keybindings]";

/// Parse a `[keybindings]` table.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key name this version does not know,
/// [`Error::WrongType`] for an action that is not a string, and
/// [`Error::BadValue`] for an action name this version does not know.
pub fn parse_keybindings(table: &Table, file: &Path, text: &str) -> Result<Keybindings, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    let names = Key::ALL.map(Key::name);
    ctx.reject_unknown_keys(table, &names)?;
    let mut keybindings = Keybindings::default();
    for key in Key::ALL {
        let Some(raw) = ctx.str_at(table, key.name())? else {
            continue;
        };
        let action = Action::ALL
            .into_iter()
            .find(|action| action.name() == raw)
            .ok_or_else(|| {
                let known = Action::ALL
                    .map(|action| format!("{:?}", action.name()))
                    .join(", ");
                ctx.bad(
                    table,
                    key.name(),
                    format!("`{}` must be one of {known}; found {raw:?}", key.name()),
                )
            })?;
        keybindings = keybindings.bind(key, action);
    }
    if !keybindings.is_empty() {
        keybindings.origin = Some(ctx.origin().clone());
    }
    Ok(keybindings)
}
