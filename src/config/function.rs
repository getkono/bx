//! Reading `[[function]]` into [`FunctionDecl`]s, and the rule every body a
//! function is defined with must keep.
//!
//! Substituting a body, the hook points, and rendering the definition and its
//! registration are [`crate::shell::function`]'s.

use std::path::Path;

use toml_edit::Table;

use super::shells::Shell;
use super::values;
use super::when::{self, When};
use super::{Ctx, Error};
use crate::shell::function::{FunctionDecl, Hook};

/// The section's header, as messages spell it.
pub(crate) const SECTION: &str = "[[function]]";

/// Every key a `[[function]]` entry may carry.
const KEYS: [&str; 8] = [
    "name", "body", "bash", "tool", "hook", "when", "shells", "enabled",
];

/// The prefix of every name bx gives a function itself.
const RESERVED: &str = "__bx_";

/// Parse one `[[function]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_function(table: &Table, file: &Path, text: &str) -> Result<FunctionDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if let Some(problem) = unnameable(&name) {
        return Err(ctx.bad(table, "name", problem));
    }
    let body = ctx.required_str(table, "body")?.to_string();
    let checked = |key: &str, body: &str| {
        if let Some(problem) = unwritable(body) {
            return Err(ctx.bad(table, key, format!("function `{name}`: {problem}")));
        }
        if let Err(problem) = values::placeholders(body) {
            return Err(ctx.bad(table, key, format!("function `{name}`: {problem}")));
        }
        Ok(())
    };
    checked("body", &body)?;
    let bash = ctx.str_at(table, "bash")?.map(str::to_string);
    if let Some(bash) = &bash {
        checked("bash", bash)?;
    }
    let shells = ctx.shells_at(table, &format!("function `{name}`"))?;
    if bash.is_some() && !shells.includes(Shell::Bash) {
        return Err(ctx.bad(
            table,
            "bash",
            format!(
                "function `{name}`: `bash` is the body bash's file defines, and `shells` keeps \
                 the function out of bash; drop one"
            ),
        ));
    }
    let tool = match ctx.str_at(table, "tool")? {
        None => None,
        Some(tool) => match when::unfindable(tool) {
            Some(problem) => {
                return Err(ctx.bad(
                    table,
                    "tool",
                    format!("function `{name}`: `tool` names a tool as `has:` does: {problem}"),
                ));
            }
            None => Some(tool.to_string()),
        },
    };
    let hook = match ctx.str_at(table, "hook")? {
        None => None,
        Some(raw) => Some(Hook::parse(raw).map_err(|problem| ctx.bad(table, "hook", problem))?),
    };
    let when = match ctx.str_at(table, "when")? {
        None => None,
        Some(raw) => Some(When::parse(raw).map_err(|problem| ctx.bad(table, "when", problem))?),
    };
    if when.is_some() && hook.is_none() {
        return Err(ctx.bad(
            table,
            "when",
            format!(
                "function `{name}`: `when` gates only a hook's registration, and a function's \
                 definition is always written; give it a `hook`, or remove `when`"
            ),
        ));
    }
    if let Some(hook) = hook
        && shells.includes(Shell::Bash)
        && bash.is_none()
    {
        return Err(ctx.bad(
            table,
            "hook",
            format!(
                "function `{name}`: `hook = {:?}` is one of zsh's own hook points, which bash \
                 has no equivalent of; keep the function to zsh with `shells = [\"zsh\"]`, or \
                 give bash its own body with `bash = '''…'''`",
                hook.name()
            ),
        ));
    }

    Ok(FunctionDecl {
        name,
        body,
        bash,
        tool,
        hook,
        when,
        shells,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Why `name` cannot name a function bx defines, or `None` when it can.
fn unnameable(name: &str) -> Option<String> {
    let first = |c: char| c.is_ascii_alphabetic() || c == '_';
    let rest = |c: char| c.is_ascii_alphanumeric() || "_.:-".contains(c);
    let shaped = name.starts_with(first) && name.chars().all(rest);
    if !shaped {
        return Some(format!(
            "{name:?} is not a function name: a name opens with an ASCII letter or `_` and \
             holds only ASCII letters, digits and `_.:-`"
        ));
    }
    name.starts_with(RESERVED).then(|| {
        format!(
            "{name:?} is not a function name: `{RESERVED}` opens the names bx gives hooked \
             functions, so no declared name may open with it"
        )
    })
}

/// Why `body` cannot be a function body, or `None` when it can.
pub(crate) fn unwritable(body: &str) -> Option<String> {
    if body.trim().is_empty() {
        return Some("the body is empty; a function does something".to_string());
    }
    body.chars()
        .find(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        .map(|c| {
            format!(
                "a function body holds no control character but a newline or a tab; found {c:?}"
            )
        })
}
