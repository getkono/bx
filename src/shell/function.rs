//! Declared shell functions: data in `bx.toml`, their bodies substituted from
//! declared values, rendered into the `functions` phase, and optionally
//! registered on one of zsh's hook points.
//!
//! ```toml
//! [[function]]
//! name    = "mkcd"                # required; the natural key
//! body    = '''
//! mkdir -p -- "$1" && cd -- "$1"
//! '''                             # required; `{{value}}` is substituted
//! tool    = "fzf"                 # optional; the tool the body runs, never a gate
//! hook    = "chpwd"               # optional; one of zsh's own hook points
//! when    = "interactive"         # optional, only with `hook`; gates the registration
//! enabled = true                  # default true
//! ```
//!
//! Entries are listed in the order written, keyed by `name`. A name declared
//! twice in one layer fails the load, naming both lines; a later layer's entry
//! with the same name replaces the earlier one in place, and a `[[function]]`
//! holding only `name` and `enabled` is a toggle.
//!
//! # The body
//!
//! The body is opaque text. bx does not parse it as shell: it substitutes every
//! `{{name}}` from the declared values, exactly as a target's text is
//! substituted, and splices the result verbatim between `function NAME {` and
//! `}`. `{{{{` writes a literal `{{`. A body is not indented, so a heredoc in
//! it keeps its terminator at the start of a line. It may span any number of
//! lines and hold tabs, and holds no other control character, whether written
//! in the body or brought in by a value.
//!
//! A body that references a value this account has not answered, has switched
//! off, or answered unusably is **held back**: that one function is left out
//! of the generated file, and [`contribute`] returns it so the file's plan row
//! can name it with what would release it ([`note`]). Every other function is
//! still written. A reference to a value no layer declares, or a malformed
//! placeholder, is a defect in the committed repo and fails the load.
//!
//! # `tool` never gates
//!
//! A function that wraps a tool is written whether or not the tool is
//! installed. Invoking it where the tool is missing fails the way the shell
//! fails any missing command — `command not found` from inside the function —
//! and never leaves the shell half-started. `tool` records which tool that
//! is; nothing is decided from it here.
//!
//! # Definitions
//!
//! Every function is defined with the `function NAME {` form rather than
//! `NAME() {`: zsh expands an alias in the word before `()`, so an alias of the
//! same name defined earlier — the `aliases` phase loads first — would turn the
//! definition into a syntax error. The word after `function` is never
//! alias-expanded.
//!
//! A name opens with an ASCII letter or `_` and holds only ASCII letters,
//! digits and `_.:-`. It may not open with `__bx_`, the prefix bx keeps for
//! the names it gives hooked functions. Shadowing a real command is the config
//! author's choice and is not refused.
//!
//! # Hooks
//!
//! `hook` names one of zsh's own hook points — `chpwd`, `periodic`, `precmd`,
//! `preexec`, `zshaddhistory`, `zshexit` or `zsh_directory_name` — and no
//! other. A hooked function is defined as `__bx_hook_NAME`, never `NAME`, so
//! it cannot overwrite a plugin's function or the user's own — a `precmd` a
//! prompt theme defined, say — and a later definition of `NAME` elsewhere
//! cannot silently unhook it. Its definition is always written.
//!
//! Registration appends the renamed function to the hook's array —
//! `precmd_functions` for `precmd` — which is zsh's own mechanism for many
//! functions on one hook, and what `add-zsh-hook` does. Appending never
//! replaces what a plugin or another function registered, and an entry
//! already present is not appended again, so sourcing the file twice
//! registers each function once. The line is written without
//! `autoload add-zsh-hook`, so it reads no function file at startup, and is
//! safe under `setopt nounset`.
//!
//! `when` is the one condition registration waits on, from the closed set
//! [`crate::config::when`] defines, and it gates only the registration: the
//! definition is written either way. `has:TOOL` is decided while `plan`
//! renders, dropping the registration line when the tool is missing, and any
//! other condition wraps the line in a guarded block. `when` without `hook`
//! is refused when the config loads, since it would have nothing to gate.
//!
//! # Invariant 2
//!
//! The `functions` phase is generated shell content that is not an
//! environment fragment, so it carries no environment assignment. Defining a
//! function runs nothing in its body. Registration assigns one thing, a hook
//! array, which is a shell array zsh cannot export, and which says what runs
//! at a hook rather than where any tool's files live.
//! `rendering_functions_changes_only_the_hook_arrays` runs the rendered bytes
//! in zsh and holds them to exactly that.

use std::path::Path;

use toml_edit::Table;

use super::{Assembly, Phase};
use crate::config::resolve::{BlockReason, BlockedEntry, Resolution};
use crate::config::values::{self, ResolvedValues, Unresolved};
use crate::config::when::{self, Gate, When};
use crate::config::{Ctx, Error, Origin};

/// The section's header, as messages spell it.
pub(crate) const SECTION: &str = "[[function]]";

/// Every key a `[[function]]` entry may carry.
const KEYS: [&str; 6] = ["name", "body", "tool", "hook", "when", "enabled"];

/// The prefix of every name bx gives a function itself.
const RESERVED: &str = "__bx_";

/// The prefix a hooked function is defined under.
const HOOKED: &str = "__bx_hook_";

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

    /// The array zsh runs every function of at this hook.
    #[must_use]
    pub fn array(self) -> String {
        format!("{}_functions", self.name())
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
    /// The tool the body runs, if the author named one. Never a gate.
    pub tool: Option<String>,
    /// The hook point the function registers on, if any.
    pub hook: Option<Hook>,
    /// The condition the registration is gated on. Only with `hook`.
    pub when: Option<When>,
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

impl Function {
    /// The name the function is defined under: its own, or, for a hooked
    /// function, `__bx_hook_` and its own, so it collides with nothing
    /// defined outside bx.
    #[must_use]
    pub fn defined_name(&self) -> String {
        match self.hook {
            None => self.name.clone(),
            Some(_) => format!("{HOOKED}{}", self.name),
        }
    }

    /// The function's definition.
    #[must_use]
    pub fn definition(&self) -> String {
        let newline = if self.body.ends_with('\n') { "" } else { "\n" };
        format!(
            "function {} {{\n{}{newline}}}\n",
            self.defined_name(),
            self.body
        )
    }

    /// The line that registers the function on its hook, or `None` for one
    /// with no hook.
    ///
    /// Appends only when the array does not already hold the name. `${+…}`
    /// asks whether the array is set without reading it, so the line is safe
    /// under `setopt nounset`.
    #[must_use]
    pub fn registration(&self) -> Option<String> {
        let hook = self.hook?;
        let (array, name) = (hook.array(), self.defined_name());
        Some(format!(
            "(( ${{+{array}}} )) && (( ${{{array}[(Ie){name}]}} )) || {array}+=({name})\n"
        ))
    }

    /// What the function contributes to the file: its definition, then its
    /// registration — plain, inside a guarded block, or left out when `when`
    /// is `has:TOOL` and the tool is missing.
    ///
    /// `present` answers whether a `has:TOOL` tool is usable on this machine,
    /// asked while `plan` and `apply` render, never by the generated shell.
    /// The definition never asks it.
    #[must_use]
    pub fn render(&self, present: &dyn Fn(&str) -> bool) -> String {
        let mut out = self.definition();
        if let Some(line) = self.registration() {
            match self.when.as_ref().map(|when| when.gate(present)) {
                None | Some(Gate::Always) => out.push_str(&line),
                Some(Gate::Never) => {}
                Some(Gate::Test(test)) => {
                    out.push_str(&format!(
                        "{}\n  {line}{}\n",
                        when::opener(&test),
                        when::CLOSER
                    ));
                }
            }
        }
        out
    }
}

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
    if let Some(problem) = unwritable(&body) {
        return Err(ctx.bad(table, "body", format!("function `{name}`: {problem}")));
    }
    if let Err(problem) = values::placeholders(&body) {
        return Err(ctx.bad(table, "body", format!("function `{name}`: {problem}")));
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

    Ok(FunctionDecl {
        name,
        body,
        tool,
        hook,
        when,
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
fn unwritable(body: &str) -> Option<String> {
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

/// Substitute every enabled function's body, or explain why it cannot be.
///
/// Each function resolves on its own: one whose body needs a value this
/// account has not answered, has switched off, or answered unusably is
/// [`Resolution::Blocked`] in its own position, keyed by its name, and every
/// other function resolves.
///
/// # Errors
///
/// [`Error::BadValue`] for a repo defect: a malformed placeholder, a
/// reference to a value no layer declares, or a committed `default` that
/// puts a control character a body cannot hold into it.
pub fn resolve(
    decls: &[FunctionDecl],
    values: &ResolvedValues,
) -> Result<Vec<Resolution<Function>>, Error> {
    decls
        .iter()
        .filter(|decl| decl.enabled)
        .map(|decl| resolve_one(decl, values))
        .collect()
}

/// One function's resolution. See [`resolve`].
fn resolve_one(
    decl: &FunctionDecl,
    values: &ResolvedValues,
) -> Result<Resolution<Function>, Error> {
    let block = |reason, hint| {
        Ok(Resolution::Blocked(BlockedEntry {
            key: decl.name.clone(),
            origin: decl.origin.clone(),
            reason,
            hint,
        }))
    };
    fn spelled(names: &[String]) -> Vec<&str> {
        names.iter().map(String::as_str).collect()
    }
    match values.substitute(&decl.body) {
        Ok(body) => {
            let Some(problem) = unwritable(&body) else {
                return Ok(Resolution::Ready(Function {
                    name: decl.name.clone(),
                    body,
                    hook: decl.hook,
                    when: decl.when.clone(),
                }));
            };
            // Checked as written at parse, so the character came in through a
            // value: an account's answer, whose line the hint names, or a
            // committed `default` alone, which no answer can clear.
            let problem = format!("function `{}`: {problem}", decl.name);
            let causes = values.account_inputs(&decl.body);
            if causes.is_empty() {
                return Err(Error::BadValue {
                    origin: decl.origin.clone(),
                    message: problem,
                });
            }
            let names = values.in_declaration_order(causes);
            let hint = values.answers_hint(&problem, &[decl.body.as_str()], &names);
            block(BlockReason::InvalidValue { names }, hint)
        }
        Err(Unresolved::Unset { names }) => {
            let hint = values::init_hint(&spelled(&names));
            block(BlockReason::UnsetValue { names }, hint)
        }
        Err(Unresolved::Disabled { names }) => {
            let hint = values::disabled_hint(&spelled(&names));
            block(BlockReason::DisabledValue { names }, hint)
        }
        Err(Unresolved::Invalid { names }) => {
            let hint = values.invalid_hint(&names);
            block(BlockReason::InvalidValue { names }, hint)
        }
        Err(defect) => Err(Error::BadValue {
            origin: decl.origin.clone(),
            message: format!("function `{}`: {defect}", decl.name),
        }),
    }
}

/// Add every ready function to `assembly`'s `functions` phase, in declaration
/// order, and return the ones held back, in the same order.
///
/// A held-back function contributes nothing at all, its registration
/// included; every other function is written whether or not the tool it runs
/// is installed.
pub fn contribute<'a>(
    assembly: &mut Assembly,
    functions: &'a [Resolution<Function>],
    present: &dyn Fn(&str) -> bool,
) -> Vec<&'a BlockedEntry> {
    let mut held = Vec::new();
    for function in functions {
        match function {
            Resolution::Ready(function) => {
                // The functions phase is not the terminal slot, so it never
                // refuses.
                let _ = assembly.contribute(
                    Phase::Functions,
                    function.name.clone(),
                    function.render(present),
                );
            }
            Resolution::Blocked(entry) => held.push(entry),
        }
    }
    held
}

/// The note the generated file's plan row carries for the functions held
/// back from it: each named, with what would release it. `None` when nothing
/// was held back.
#[must_use]
pub fn note(held: &[&BlockedEntry]) -> Option<String> {
    (!held.is_empty()).then(|| {
        held.iter()
            .map(|entry| format!("function `{}` held back: {}", entry.key, entry.hint))
            .collect::<Vec<_>>()
            .join("; ")
    })
}
