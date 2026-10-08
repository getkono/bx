//! Reading `[[function]]` into [`FunctionDecl`]s, the hook points one may
//! register on, and the rule every body a function is defined with must keep.
//!
//! Substituting a body, and rendering the definition and its registration,
//! are [`crate::shell::function`]'s.

use std::path::Path;

use toml_edit::Table;

use super::shells::{Shell, Shells};
use super::values;
use super::when::{self, When};
use super::{Ctx, Error, Origin};

/// One of zsh's own hook points: the closed set a function may register on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hook {
    /// The working directory changed.
    Chpwd,
    /// Every `$PERIOD` seconds, just before a prompt.
    Periodic,
    /// Before each prompt.
    Precmd,
    /// After a command line is read, before it runs.
    Preexec,
    /// Before a line is added to history.
    Zshaddhistory,
    /// As the shell exits.
    Zshexit,
    /// Dynamic named directories.
    ZshDirectoryName,
}

impl Hook {
    /// Every hook point, in the order messages list them.
    pub const ALL: [Self; 7] = [
        Self::Chpwd,
        Self::Periodic,
        Self::Precmd,
        Self::Preexec,
        Self::Zshaddhistory,
        Self::Zshexit,
        Self::ZshDirectoryName,
    ];

    /// The hook's name, as zsh and `bx.toml` spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chpwd => "chpwd",
            Self::Periodic => "periodic",
            Self::Precmd => "precmd",
            Self::Preexec => "preexec",
            Self::Zshaddhistory => "zshaddhistory",
            Self::Zshexit => "zshexit",
            Self::ZshDirectoryName => "zsh_directory_name",
        }
    }

    /// Read a `hook` string a config author wrote.
    ///
    /// # Errors
    ///
    /// Why `raw` is not one of zsh's hook points, listing them.
    pub fn parse(raw: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|hook| hook.name() == raw)
            .ok_or_else(|| {
                let names: Vec<String> = Self::ALL
                    .iter()
                    .map(|h| format!("{:?}", h.name()))
                    .collect();
                format!(
                    "`hook` must be one of zsh's own hook points, {}; got {raw:?}",
                    names.join(", ")
                )
            })
    }
}

/// One declared function, as written: its body not yet substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDecl {
    /// The function's name, its natural key.
    pub name: String,
    /// The body as written, `{{name}}` references and all.
    pub body: String,
    /// bash's own body, when it differs from `body`: written in bash's file in
    /// its place, and the bash equivalent of a hooked function.
    pub bash: Option<String>,
    /// The tool the body runs, if the author named one. Never a gate.
    pub tool: Option<String>,
    /// The hook point the function registers on, if any.
    pub hook: Option<Hook>,
    /// The condition the registration is gated on. Only with `hook`.
    pub when: Option<When>,
    /// The shells whose generated file defines it.
    pub shells: Shells,
    /// `false` in any layer removes the function from the resolved configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// One function ready to write: its body substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// The name it was declared under.
    pub name: String,
    /// The substituted body.
    pub body: String,
    /// The hook point it registers on, if any.
    pub hook: Option<Hook>,
    /// The condition the registration is gated on.
    pub when: Option<When>,
}

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
