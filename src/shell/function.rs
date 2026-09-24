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
//! environment fragment, so the bx-derived content in it — each `function
//! NAME {` line, its closing `}`, and each registration line — carries no
//! environment assignment. Defining a function runs nothing in its body.
//! Registration assigns one thing, a hook array, which is a shell array zsh
//! cannot export, and which says what runs at a hook rather than where any
//! tool's files live. `rendering_functions_changes_only_the_hook_arrays` runs
//! the rendered bytes in zsh and holds them to exactly that.
//!
//! The body is not bx-derived content. It is code the user wrote verbatim in
//! their own config repo, and bx transports it byte for byte, deriving nothing
//! from it, exactly as an owned `file` target may hold anything its author
//! wrote. Invariant 2 governs what bx itself emits or relocates, so it does
//! not judge a body, hooked or not — even though a hooked body runs at every
//! firing of its hook without the user invoking it, and may set any variable
//! the user chose to set there. Passing bodies through [`crate::env_guard`]
//! would refuse ordinary user shell code.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::shell::testing::{installed, run};
    use std::path::PathBuf;

    const FILE: &str = "/repo/bx.toml";

    fn load(text: &str) -> Result<crate::config::Config, String> {
        parse_str(text, Path::new(FILE), Path::new("/home/u")).map_err(|e| e.to_string())
    }

    /// Parse `text` as one layer, resolve its values, and resolve its
    /// functions against them.
    fn resolved(text: &str) -> Result<Vec<Resolution<Function>>, String> {
        let config = load(text)?;
        let values = ResolvedValues::resolve(
            config.values,
            &config.value_assignments,
            Path::new("/home/u"),
        )
        .map_err(|e| e.to_string())?;
        resolve(&config.functions, &values).map_err(|e| e.to_string())
    }

    fn function(name: &str, body: &str, hook: Option<Hook>, when: Option<When>) -> Function {
        Function {
            name: name.to_string(),
            body: body.to_string(),
            hook,
            when,
        }
    }

    fn render_all(functions: &[Resolution<Function>], present: &dyn Fn(&str) -> bool) -> String {
        let mut assembly = Assembly::new();
        contribute(&mut assembly, functions, present);
        assembly.render()
    }

    #[test]
    fn an_entry_parses_every_key() {
        let config = load(
            "[[function]]\nname = \"venv\"\nbody = '''\nsource .venv/bin/activate\n'''\n\
             tool = \"python3\"\nhook = \"chpwd\"\nwhen = \"interactive\"\n\
             [[function]]\nname = \"x\"\nbody = \"y\"\nenabled = false\n",
        )
        .expect("parses");
        let file = PathBuf::from(FILE);
        assert_eq!(
            config.functions,
            vec![
                FunctionDecl {
                    name: "venv".to_string(),
                    body: "source .venv/bin/activate\n".to_string(),
                    tool: Some("python3".to_string()),
                    hook: Some(Hook::Chpwd),
                    when: Some(When::Interactive),
                    enabled: true,
                    origin: Origin {
                        file: file.clone(),
                        line: 1
                    },
                },
                FunctionDecl {
                    name: "x".to_string(),
                    body: "y".to_string(),
                    tool: None,
                    hook: None,
                    when: None,
                    enabled: false,
                    origin: Origin { file, line: 9 },
                },
            ]
        );
    }

    #[test]
    fn every_hook_point_parses_and_names_its_array() {
        for hook in Hook::ALL {
            assert_eq!(Hook::parse(hook.name()), Ok(hook));
            assert_eq!(hook.array(), format!("{}_functions", hook.name()));
        }
        let err = Hook::parse("prompt").expect_err("not a hook point");
        assert!(err.contains("\"zsh_directory_name\""), "{err}");
        assert!(err.contains("got \"prompt\""), "{err}");
    }

    #[test]
    fn a_name_declared_twice_in_one_file_fails_the_load() {
        for text in [
            "[[function]]\nname = \"f\"\nbody = \"a\"\n[[function]]\nname = \"f\"\nbody = \"b\"\n",
            "[[function]]\nname = \"f\"\nbody = \"a\"\n[[function]]\nname = \"f\"\nenabled = false\n",
        ] {
            let err = load(text).expect_err(text);
            assert!(err.contains("duplicate function `f`"), "{text}: {err}");
            assert!(err.contains("first declared at /repo/bx.toml:1"), "{err}");
        }
    }

    #[test]
    fn a_malformed_function_is_refused_naming_why() {
        for (text, needle) in [
            ("[[function]]\nbody = \"a\"\n", "`name`"),
            ("[[function]]\nname = \"f\"\n", "`body`"),
            (
                "[[function]]\nname = \"f\"\nbody = 1\n",
                "`body` must be a string",
            ),
            (
                "[[function]]\nname = \"\"\nbody = \"a\"\n",
                "not a function name",
            ),
            (
                "[[function]]\nname = \"1f\"\nbody = \"a\"\n",
                "not a function name",
            ),
            (
                "[[function]]\nname = \"-f\"\nbody = \"a\"\n",
                "not a function name",
            ),
            (
                "[[function]]\nname = \"f g\"\nbody = \"a\"\n",
                "not a function name",
            ),
            (
                "[[function]]\nname = \"f()\"\nbody = \"a\"\n",
                "not a function name",
            ),
            (
                "[[function]]\nname = \"f$\"\nbody = \"a\"\n",
                "not a function name",
            ),
            (
                "[[function]]\nname = \"__bx_x\"\nbody = \"a\"\n",
                "`__bx_` opens",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \" \\n\\t\"\n",
                "the body is empty",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\\rb\"\n",
                "control character",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\\u0000\"\n",
                "control character",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"{{x\"\n",
                "unterminated placeholder",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"{{X}}\"\n",
                "not a value name",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\"\ntool = \"$(id)\"\n",
                "`tool` names a tool",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\"\nhook = \"prompt\"\n",
                "zsh's own hook points",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\"\nhook = \"chpwd\"\nwhen = \"tty\"\n",
                "`when` must be one of",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\"\nwhen = \"interactive\"\n",
                "give it a `hook`",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\"\nenabled = \"no\"\n",
                "a boolean",
            ),
            (
                "[[function]]\nname = \"f\"\nbody = \"a\"\ncommand = \"y\"\n",
                "unknown key `command`",
            ),
            ("function = \"x\"\n", "a repeated section"),
        ] {
            let err = load(text).expect_err(text);
            assert!(err.contains(needle), "{text}: {err}");
            assert!(err.starts_with("/repo/bx.toml:"), "{text}: {err}");
        }
    }

    #[test]
    fn a_body_is_substituted_and_spliced_verbatim() {
        let functions = resolved(
            "[[value]]\nname = \"scratch\"\nkind = \"string\"\n\
             [values]\nscratch = \"/scratch/me\"\n\
             [[function]]\nname = \"s\"\nbody = '''\ncd {{scratch}}/\"$1\" && echo {{{{x}}\n\
             cat <<EOF\n  kept\nEOF\n'''\n",
        )
        .expect("resolves");
        let [Resolution::Ready(ready)] = functions.as_slice() else {
            panic!("{functions:?}");
        };
        assert_eq!(
            ready.definition(),
            "function s {\ncd /scratch/me/\"$1\" && echo {{x}}\ncat <<EOF\n  kept\nEOF\n}\n"
        );
        // A body with no trailing newline still closes on a line of its own.
        assert_eq!(
            function("f", "a", None, None).definition(),
            "function f {\na\n}\n"
        );
    }

    #[test]
    fn an_unanswered_value_holds_back_only_its_function_and_the_note_names_it() {
        let text = "[[value]]\nname = \"a\"\nkind = \"string\"\ndefault = \"x\"\n\
                    [[value]]\nname = \"b\"\nkind = \"string\"\n\
                    [[function]]\nname = \"first\"\nbody = \"echo {{a}}\"\n\
                    [[function]]\nname = \"needs_b\"\nbody = \"echo {{b}}\"\nhook = \"precmd\"\n\
                    [[function]]\nname = \"last\"\nbody = \"echo plain\"\n";
        let functions = resolved(text).expect("an unset value is not a load error");
        let rendered = render_all(&functions, &|_| true);
        assert!(
            rendered.contains("function first {\necho x\n}\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("function last {\necho plain\n}\n"),
            "{rendered}"
        );
        assert!(!rendered.contains("needs_b"), "{rendered}");
        assert!(!rendered.contains("precmd"), "{rendered}");

        let mut assembly = Assembly::new();
        let held = contribute(&mut assembly, &functions, &|_| true);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].key, "needs_b");
        assert_eq!(
            held[0].reason,
            BlockReason::UnsetValue {
                names: vec!["b".to_string()]
            }
        );
        assert_eq!(
            note(&held).as_deref(),
            Some("function `needs_b` held back: run `bx init` to set b")
        );
        assert_eq!(note(&[]), None);

        // Answered, it arrives.
        let answered = resolved(&format!("{text}[values]\nb = \"y\"\n")).expect("resolves");
        assert!(answered.iter().all(|f| matches!(f, Resolution::Ready(_))));
    }

    #[test]
    fn a_switched_off_or_unusable_value_holds_the_function_back_too() {
        let off = resolved(
            "[[value]]\nname = \"a\"\nkind = \"string\"\ndefault = \"x\"\nenabled = false\n\
             [[function]]\nname = \"f\"\nbody = \"echo {{a}}\"\n",
        )
        .expect("resolves");
        let [Resolution::Blocked(entry)] = off.as_slice() else {
            panic!("{off:?}");
        };
        assert!(matches!(entry.reason, BlockReason::DisabledValue { .. }));
        assert!(entry.hint.contains("re-enable a"), "{}", entry.hint);

        let unusable = resolved(
            "[[value]]\nname = \"root\"\nkind = \"path\"\n\
             [values]\nroot = \"relative\"\n\
             [[function]]\nname = \"f\"\nbody = \"cd {{root}}\"\n",
        )
        .expect("resolves");
        let [Resolution::Blocked(entry)] = unusable.as_slice() else {
            panic!("{unusable:?}");
        };
        assert!(matches!(entry.reason, BlockReason::InvalidValue { .. }));

        // An answer that brings a control character into the body blocks it,
        // naming the answer's line.
        let carriage = resolved(
            "[[value]]\nname = \"a\"\nkind = \"string\"\n\
             [values]\na = \"x\\ry\"\n\
             [[function]]\nname = \"f\"\nbody = \"echo {{a}}\"\n",
        )
        .expect("resolves");
        let [Resolution::Blocked(entry)] = carriage.as_slice() else {
            panic!("{carriage:?}");
        };
        assert!(matches!(entry.reason, BlockReason::InvalidValue { .. }));
        assert!(entry.hint.contains("control character"), "{}", entry.hint);
        assert!(
            entry.hint.contains("the answer to `a` at /repo/bx.toml:5"),
            "{}",
            entry.hint
        );
    }

    #[test]
    fn a_repo_defect_in_a_body_fails_the_load() {
        let err = resolved("[[function]]\nname = \"f\"\nbody = \"echo {{nobody}}\"\n")
            .expect_err("an undeclared value");
        assert!(err.contains("function `f`"), "{err}");
        assert!(err.contains("`nobody`"), "{err}");
        // A committed default alone brings the control character in.
        let err = resolved(
            "[[value]]\nname = \"a\"\nkind = \"string\"\ndefault = \"x\\ry\"\n\
             [[function]]\nname = \"f\"\nbody = \"echo {{a}}\"\n",
        )
        .expect_err("no answer can clear it");
        assert!(err.contains("control character"), "{err}");
    }

    #[test]
    fn a_disabled_function_resolves_to_nothing() {
        let functions =
            resolved("[[function]]\nname = \"f\"\nbody = \"echo {{nobody}}\"\nenabled = false\n")
                .expect("a disabled body is not read");
        assert!(functions.is_empty());
    }

    #[test]
    fn a_named_tool_never_gates_the_function() {
        let functions =
            resolved("[[function]]\nname = \"pick\"\nbody = \"fzf --multi\"\ntool = \"fzf\"\n")
                .expect("resolves");
        let rendered = render_all(&functions, &|_| panic!("the tool is never looked up"));
        assert!(
            rendered.ends_with("\n# bx phase: functions\nfunction pick {\nfzf --multi\n}\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_hooked_function_is_renamed_and_only_its_registration_is_gated() {
        let hooked = function("venv", "echo v", Some(Hook::Chpwd), None);
        assert_eq!(hooked.defined_name(), "__bx_hook_venv");
        let definition = "function __bx_hook_venv {\necho v\n}\n";
        let registration = "(( ${+chpwd_functions} )) && \
                            (( ${chpwd_functions[(Ie)__bx_hook_venv]} )) || \
                            chpwd_functions+=(__bx_hook_venv)\n";
        assert_eq!(
            hooked.render(&|_| false),
            format!("{definition}{registration}")
        );

        let has = Function {
            when: Some(When::Has("direnv".to_string())),
            ..hooked.clone()
        };
        assert_eq!(
            has.render(&|tool| tool == "direnv"),
            format!("{definition}{registration}")
        );
        assert_eq!(has.render(&|_| false), definition);

        let ssh = Function {
            when: Some(When::Ssh),
            ..hooked
        };
        assert_eq!(
            ssh.render(&|_| unreachable!("a runtime test asks for no tool")),
            format!("{definition}if [[ -n ${{SSH_CONNECTION-}} ]]; then\n  {registration}fi\n")
        );

        let plain = function("f", "x", None, None);
        assert_eq!(plain.defined_name(), "f");
        assert_eq!(plain.registration(), None);
    }

    #[test]
    fn re_resolving_and_re_rendering_is_byte_identical_and_in_declared_order() {
        let text = "[[value]]\nname = \"a\"\nkind = \"string\"\ndefault = \"x\"\n\
                    [[function]]\nname = \"zz\"\nbody = \"echo {{a}}\"\nhook = \"precmd\"\n\
                    [[function]]\nname = \"aa\"\nbody = \"echo a\"\nhook = \"precmd\"\n\
                    when = \"interactive\"\n\
                    [[function]]\nname = \"mm\"\nbody = \"echo m\"\n";
        let render = || render_all(&resolved(text).expect("resolves"), &|_| true);
        let first = render();
        assert_eq!(first, render());
        let zz = first.find("__bx_hook_zz {").expect("zz");
        let aa = first.find("__bx_hook_aa {").expect("aa");
        let mm = first.find("function mm {").expect("mm");
        assert!(zz < aa && aa < mm, "{first}");
    }

    /// Run `script` in `zsh -f`, returning what it printed.
    fn zsh(script: &str) -> Option<String> {
        let zsh = installed("zsh")?;
        Some(String::from_utf8(run(&zsh, &["-f"], script)).expect("utf-8"))
    }

    fn rendered_phase(functions: &[Function]) -> String {
        let ready: Vec<Resolution<Function>> =
            functions.iter().cloned().map(Resolution::Ready).collect();
        render_all(&ready, &|_| true)
    }

    #[test]
    fn co_registrants_all_run_and_nothing_outside_bx_is_clobbered() {
        let ours = rendered_phase(&[
            function("one", "print -r -- one", Some(Hook::Chpwd), None),
            function("two", "print -r -- two", Some(Hook::Chpwd), None),
        ]);
        // A plugin defined its own `chpwd` and a function named as one of ours,
        // and registered a hook of its own, before the functions phase; the
        // user defines `one` again after it.
        let script = format!(
            "setopt nounset\n\
             chpwd() {{ print -r -- plugin-chpwd }}\n\
             one() {{ print -r -- plugin-one }}\n\
             plugin_hook() {{ print -r -- plugin-hook }}\n\
             chpwd_functions=(plugin_hook)\n\
             {ours}{ours}\
             one() {{ print -r -- user-one }}\n\
             cd /\n\
             print -r -- ${{(j:,:)chpwd_functions}}\n\
             one\n"
        );
        let Some(got) = zsh(&script) else {
            return;
        };
        assert_eq!(
            got,
            "plugin-chpwd\nplugin-hook\none\ntwo\n\
             plugin_hook,__bx_hook_one,__bx_hook_two\n\
             user-one\n"
        );
    }

    #[test]
    fn registration_is_safe_on_an_unset_array_under_nounset() {
        let ours = rendered_phase(&[function("one", "print -r -- one", Some(Hook::Chpwd), None)]);
        let Some(got) = zsh(&format!("setopt nounset\n{ours}cd /\n")) else {
            return;
        };
        assert_eq!(got, "one\n");
    }

    #[test]
    fn a_function_is_defined_past_an_alias_of_its_name_and_a_missing_tool_fails_only_its_call() {
        let ours = rendered_phase(&[function(
            "ll",
            "definitely-not-installed-bx-tool \"$@\"",
            None,
            None,
        )]);
        let script = format!(
            "alias ll='ls -la'\n{ours}unalias ll\n\
             ll x 2>/dev/null\nprint -r -- status=$?\nprint -r -- still-running\n"
        );
        let Some(got) = zsh(&script) else {
            return;
        };
        assert_eq!(got, "status=127\nstill-running\n");
    }

    #[test]
    fn rendering_functions_changes_only_the_hook_arrays() {
        // Invariant 2: the functions phase is not an environment fragment.
        // Defining functions, and registering them, must leave every
        // parameter as it was but the hook arrays, and export nothing. The
        // hooked bodies decline to act, since zsh may call one of them — the
        // directory-name hook — while the dump reads parameters; the unhooked
        // one would export, were defining it to run it.
        let mut functions: Vec<Function> = Hook::ALL
            .iter()
            .map(|hook| {
                function(
                    &format!("on_{}", hook.name()),
                    "return 1",
                    Some(*hook),
                    None,
                )
            })
            .collect();
        functions.push(function(
            "plain",
            "export XDG_CONFIG_HOME=/elsewhere\nZ=3",
            None,
            None,
        ));
        functions.push(function(
            "gated",
            "true",
            Some(Hook::Precmd),
            Some(When::Interactive),
        ));
        let ours = rendered_phase(&functions);
        let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                    [[ ${parameters[$n]} == *special* ]] || print -r -- \"$n=${(P)n}\"; \
                    done; print -r -- ---; export; print -r -- ---; }\n";
        let script = format!("{dump}__bx_dump >/dev/null\n__bx_dump\n{ours}__bx_dump\n");
        let Some(got) = zsh(&script) else {
            return;
        };
        let parts: Vec<&str> = got.split("---\n").collect();
        let (before, exported_before, after, exported_after) =
            (parts[0], parts[1], parts[2], parts[3]);
        assert_eq!(exported_after, exported_before, "nothing is exported");
        let arrays: Vec<String> = Hook::ALL.iter().map(|hook| hook.array()).collect();
        let changed = |line: &&str| {
            let name = line.split('=').next().unwrap_or_default();
            !arrays.iter().any(|array| array == name)
        };
        let kept = |dump: &str| dump.lines().filter(changed).collect::<Vec<_>>().join("\n");
        assert_eq!(kept(after), kept(before));
        for hook in Hook::ALL {
            let expected = format!("{}=__bx_hook_on_{}", hook.array(), hook.name());
            assert!(
                after.lines().any(|line| line == expected),
                "{expected}: {after}"
            );
        }
        // The dump does see an assignment, so the equality above means
        // something.
        let script = format!("{dump}__bx_dump >/dev/null\n__bx_dump\nZ=1\n__bx_dump\n");
        let got = zsh(&script).expect("zsh is installed");
        let parts: Vec<&str> = got.split("---\n").collect();
        assert_ne!(parts[2], parts[0]);
    }
}
