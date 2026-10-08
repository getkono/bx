//! Reading `[[activation]]` into [`ActivationDecl`]s.
//!
//! Running a tool's command, caching what it printed, and judging that output
//! are [`crate::shell::activation`]'s; this is the parser, and the rule a
//! command must keep to be looked up and run at all.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error};
use crate::shell::activation::ActivationDecl;
use crate::shell::{Phase, Shell};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[activation]]";

/// Every key an `[[activation]]` entry may carry.
const KEYS: [&str; 7] = [
    "name", "command", "zsh", "bash", "shells", "phase", "enabled",
];

/// The characters a word may hold and still be written bare.
const BARE: &str = "_./,:@%+-";

/// The phases an activation may land in, as a config author spells them.
const PHASES: [(&str, Phase); 2] = [
    ("activations", Phase::Activations),
    ("completions", Phase::Completions),
];

/// Whether `c` may appear in a word written bare.
fn is_bare(c: char) -> bool {
    c.is_ascii_alphanumeric() || BARE.contains(c)
}

/// Parse one `[[activation]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_activation(table: &Table, file: &Path, text: &str) -> Result<ActivationDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not an activation name: a name is non-empty and on one line"),
        ));
    }

    if ["command", "zsh", "bash"]
        .iter()
        .all(|key| table.get(key).is_none())
    {
        return Err(Error::MissingKey {
            origin: ctx.origin().clone(),
            section: SECTION,
            key: "command",
        });
    }
    let shells = ctx.shells_at(table, &format!("`{name}`"))?;
    let checked = |key: &str, shell: Option<Shell>| -> Result<Option<Vec<String>>, Error> {
        if table.get(key).is_none() {
            return Ok(None);
        }
        if let Some(shell) = shell.filter(|shell| !shells.includes(*shell)) {
            return Err(ctx.bad(
                table,
                key,
                format!(
                    "`{name}`: `{key}` is the command {} runs, and `shells` keeps the \
                     activation out of {}; drop one",
                    shell.name(),
                    shell.name()
                ),
            ));
        }
        // Checked as written: the tool's name holds no `{`, so no placeholder
        // spells it, and spelling one in an argument adds no NUL.
        let command = ctx.str_array_at(table, key)?;
        match unrunnable(&command) {
            Some(problem) => Err(ctx.bad(table, key, format!("`{name}`: {problem}"))),
            None => Ok(Some(command)),
        }
    };
    let command = checked("command", None)?.unwrap_or_default();
    let zsh = checked("zsh", Some(Shell::Zsh))?;
    let bash = checked("bash", Some(Shell::Bash))?;

    let phase = match ctx.str_at(table, "phase")? {
        None => Phase::Activations,
        Some(raw) => PHASES
            .iter()
            .find_map(|(spelling, phase)| (*spelling == raw).then_some(*phase))
            .ok_or_else(|| {
                ctx.bad(
                    table,
                    "phase",
                    format!(
                        "`{name}`: {raw:?} is not a phase an activation may land in; \
                         use \"activations\" or \"completions\""
                    ),
                )
            })?,
    };

    Ok(ActivationDecl {
        name,
        command,
        zsh,
        bash,
        shells,
        phase,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Why `command` cannot be run and rendered, or `None` when it can.
fn unrunnable(command: &[String]) -> Option<String> {
    let Some(program) = command.first() else {
        return Some("`command` is empty; it names at least the tool to run".to_string());
    };
    let shape = if let Some(rest) = program.strip_prefix('/') {
        !rest.is_empty() && rest.chars().all(is_bare)
    } else {
        !program.is_empty()
            && !program.starts_with('-')
            && program
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.+-".contains(c))
    };
    if !shape {
        return Some(format!(
            "`command[0] = {program:?}` must be a program name of ASCII letters, digits and \
             `_.+-`, or an absolute path of those and `/,:@%`, so it can be looked up"
        ));
    }
    command.iter().find(|word| word.contains('\0')).map(|word| {
        format!("{word:?} holds a NUL byte, which no argument passed to a program can hold")
    })
}
