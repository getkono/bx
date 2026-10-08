//! `[keybindings]`: the closed sets of keys and actions a binding may name,
//! the [`Keybindings`] a table declares, and the parser that holds a layer to
//! them.
//!
//! Rendering them for zsh and readline is [`crate::shell::keybindings`]'s.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[keybindings]";

/// A key a binding may name.
///
/// Declared in the order the bindings are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// Home.
    Home,
    /// End.
    End,
    /// Alt and the right arrow.
    AltRight,
    /// Alt and `f`.
    AltF,
    /// Alt and the left arrow.
    AltLeft,
    /// Alt and `b`.
    AltB,
}

impl Key {
    /// Every key, in the order the bindings are rendered.
    pub const ALL: [Self; 6] = [
        Self::Home,
        Self::End,
        Self::AltRight,
        Self::AltF,
        Self::AltLeft,
        Self::AltB,
    ];

    /// The key's name, as `[keybindings]` spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::End => "end",
            Self::AltRight => "alt-right",
            Self::AltF => "alt-f",
            Self::AltLeft => "alt-left",
            Self::AltB => "alt-b",
        }
    }
}

/// A line-editing action a key may be bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Move to the start of the line.
    BeginningOfLine,
    /// Move to the end of the line.
    EndOfLine,
    /// Move forward one word.
    ForwardWord,
    /// Move back one word.
    BackwardWord,
}

impl Action {
    /// Every action.
    pub const ALL: [Self; 4] = [
        Self::BeginningOfLine,
        Self::EndOfLine,
        Self::ForwardWord,
        Self::BackwardWord,
    ];

    /// The action's name: `[keybindings]`'s spelling, zsh's widget and
    /// readline's function alike.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeginningOfLine => "beginning-of-line",
            Self::EndOfLine => "end-of-line",
            Self::ForwardWord => "forward-word",
            Self::BackwardWord => "backward-word",
        }
    }
}

/// What one layer's `[keybindings]` table says, or what the merged layers say.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Keybindings {
    /// Each key's action, indexed by the key's position in [`Key::ALL`].
    bindings: [Option<Action>; 6],
    /// Where the table that last bound a key was written.
    pub origin: Option<Origin>,
}

impl Keybindings {
    /// The declaration with `key` bound to `action`.
    #[must_use]
    pub const fn bind(mut self, key: Key, action: Action) -> Self {
        self.bindings[key as usize] = Some(action);
        self
    }

    /// The action `key` is bound to, if any.
    #[must_use]
    pub const fn get(&self, key: Key) -> Option<Action> {
        self.bindings[key as usize]
    }

    /// Whether no key is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.iter().all(Option::is_none)
    }

    /// Each binding, in [`Key::ALL`]'s order.
    pub fn declared(&self) -> impl Iterator<Item = (Key, Action)> + '_ {
        Key::ALL
            .into_iter()
            .filter_map(|key| self.get(key).map(|action| (key, action)))
    }

    /// Fold a later layer's table over this one, key by key, the later layer
    /// winning.
    pub(crate) fn absorb(&mut self, later: &Self) {
        for key in Key::ALL {
            if let Some(action) = later.get(key) {
                self.bindings[key as usize] = Some(action);
            }
        }
        if let Some(origin) = &later.origin {
            self.origin = Some(origin.clone());
        }
    }
}

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
