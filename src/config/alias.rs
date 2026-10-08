//! Reading `[aliases]` and `[[alias]]` into [`AliasDecl`]s.
//!
//! What a name and a body may hold, and why, is
//! [`crate::shell::alias`]'s to say, beside the quoting that makes a body
//! inert; this is the parser that holds a layer to it.

use std::path::Path;

use toml_edit::{Item, Table};

use super::when::When;
use super::{Ctx, Error};
use crate::shell::alias::AliasDecl;

/// The conditional list's header, as messages spell it.
pub(crate) const SECTION: &str = "[[alias]]";

/// The flat list's header, as messages spell it.
pub(crate) const FLAT_SECTION: &str = "[aliases]";

/// Every key a `[[alias]]` entry may carry.
const KEYS: [&str; 4] = ["name", "command", "when", "enabled"];

/// Parse the flat `[aliases]` table: each key a name, each value its body.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// [`Error::WrongType`] for a value that is not a string, and
/// [`Error::BadValue`] for a name or body [`parse_alias`] would refuse too.
/// Every one carries the key's origin.
pub fn parse_aliases(table: &Table, file: &Path, text: &str) -> Result<Vec<AliasDecl>, Error> {
    let ctx = Ctx::new(table, file, text, FLAT_SECTION);
    let mut aliases = Vec::new();
    for (name, item) in table.iter() {
        let command = match item {
            Item::Value(value) => value.as_str(),
            _ => None,
        }
        .ok_or_else(|| Error::WrongType {
            origin: ctx.key_origin(table, name),
            key: name.to_string(),
            expected: "a string",
            found: item.type_name(),
        })?;
        check(name, command).map_err(|problem| ctx.bad(table, name, problem))?;
        aliases.push(AliasDecl {
            name: name.to_string(),
            command: command.to_string(),
            when: None,
            enabled: true,
            origin: ctx.key_origin(table, name),
        });
    }
    Ok(aliases)
}

/// Parse one `[[alias]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_alias(table: &Table, file: &Path, text: &str) -> Result<AliasDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if let Some(problem) = unnameable(&name) {
        return Err(ctx.bad(table, "name", problem));
    }
    let command = ctx.required_str(table, "command")?.to_string();
    if let Some(problem) = unwritable(&command) {
        return Err(ctx.bad(table, "command", format!("alias `{name}`: {problem}")));
    }
    let when = match ctx.str_at(table, "when")? {
        None => None,
        Some(raw) => Some(When::parse(raw).map_err(|problem| ctx.bad(table, "when", problem))?),
    };

    Ok(AliasDecl {
        name,
        command,
        when,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Both checks a flat entry needs, as one message.
fn check(name: &str, command: &str) -> Result<(), String> {
    if let Some(problem) = unnameable(name) {
        return Err(problem);
    }
    unwritable(command).map_or(Ok(()), |problem| Err(format!("alias `{name}`: {problem}")))
}

/// Why `name` cannot be written bare before an alias's `=`, or `None` when it
/// can.
fn unnameable(name: &str) -> Option<String> {
    let bare = |c: char| c.is_ascii_alphanumeric() || "_.+:@%,-".contains(c);
    (name.is_empty() || name.starts_with(['-', '+']) || !name.chars().all(bare)).then(|| {
        format!(
            "{name:?} is not an alias name: a name is written bare, so it is non-empty, holds \
             only ASCII letters, digits and `_.+:@%,-`, and does not open with `-` or `+`"
        )
    })
}

/// Why `command` cannot be an alias body, or `None` when it can.
fn unwritable(command: &str) -> Option<String> {
    if command.is_empty() {
        return Some("the body is empty; an alias expands to something".to_string());
    }
    if let Some(c) = command.chars().find(|c| c.is_control()) {
        return Some(format!(
            "an alias body is one line and holds no control character; found {c:?}"
        ));
    }
    command.contains("{{").then(|| {
        "an alias body holds no `{{`: bodies are written exactly as given and are not \
         templates"
            .to_string()
    })
}
