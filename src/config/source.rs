//! Reading `[[source]]` into [`SourceDecl`]s.
//!
//! Substituting a path and rendering its guarded line are
//! [`crate::shell::source`]'s; this is the parser, and the phases a config
//! author may name.

use std::path::Path;

use toml_edit::Table;

use super::plugin::unsourceable;
use super::shells::{Phase, Shells};
use super::values;
use super::when::When;
use super::{Ctx, Error, Origin};

/// One `[[source]]` entry, as written: its path not yet substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDecl {
    /// The source's name, its natural key.
    pub name: String,
    /// The path as written, `{{name}}` references and all.
    pub path: String,
    /// The phase it loads in.
    pub phase: Phase,
    /// The condition it is gated on, if any.
    pub when: Option<When>,
    /// The shells whose generated file sources it.
    pub shells: Shells,
    /// `false` in any layer removes the source from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// One source ready to write: its path substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The name it was declared under.
    pub name: String,
    /// The substituted path, as the line spells it.
    pub path: String,
    /// The phase it loads in.
    pub phase: Phase,
    /// The condition it is gated on, if any.
    pub when: Option<When>,
    /// Where the entry was written.
    pub origin: Origin,
}

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[source]]";

/// Every key a `[[source]]` entry may carry.
const KEYS: [&str; 6] = ["name", "path", "phase", "when", "shells", "enabled"];

/// The phases a source may load in, in load order.
pub const PHASES: [Phase; 7] = [
    Phase::Activations,
    Phase::Completions,
    Phase::Plugins,
    Phase::Aliases,
    Phase::Functions,
    Phase::Keybindings,
    Phase::Options,
];

/// The phase a source loads in when it names none.
pub const DEFAULT_PHASE: Phase = Phase::Plugins;

/// Read a `phase` string a config author wrote.
///
/// # Errors
///
/// Why `raw` is not a phase a source may load in, listing the ones it may.
pub fn parse_phase(raw: &str) -> Result<Phase, String> {
    if let Some(phase) = PHASES.into_iter().find(|phase| phase.name() == raw) {
        return Ok(phase);
    }
    let names: Vec<String> = PHASES.iter().map(|p| format!("{:?}", p.name())).collect();
    let why = match Phase::ALL.into_iter().find(|phase| phase.name() == raw) {
        Some(Phase::Terminal) => {
            "; `terminal` is the single slot one plugin may claim, and a source never claims it"
        }
        Some(Phase::Env | Phase::Path) => {
            "; that phase holds only environment fragments bx judges, and a source is not one"
        }
        Some(Phase::Completion) => "; that phase is the completion system's own setup",
        _ => "",
    };
    Err(format!(
        "`phase` must be one of {}; got {raw:?}{why}",
        names.join(", ")
    ))
}

/// Parse one `[[source]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_source(table: &Table, file: &Path, text: &str) -> Result<SourceDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not a source name: a name is non-empty and on one line"),
        ));
    }

    let path = ctx.required_str(table, "path")?.to_string();
    match values::placeholders(&path) {
        Err(problem) => return Err(ctx.bad(table, "path", format!("source `{name}`: {problem}"))),
        // Nothing to substitute, so the path is final and is checked now.
        Ok(names) if names.is_empty() => {
            if let Some(problem) = unsourceable("path", &path) {
                return Err(ctx.bad(table, "path", format!("source `{name}`: {problem}")));
            }
        }
        Ok(_) => {}
    }

    let phase = match ctx.str_at(table, "phase")? {
        None => DEFAULT_PHASE,
        Some(raw) => parse_phase(raw).map_err(|problem| ctx.bad(table, "phase", problem))?,
    };
    let when = match ctx.str_at(table, "when")? {
        None => None,
        Some(raw) => Some(When::parse(raw).map_err(|problem| ctx.bad(table, "when", problem))?),
    };

    let shells = ctx.shells_at(table, &format!("source `{name}`"))?;

    Ok(SourceDecl {
        name,
        path,
        phase,
        when,
        shells,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}
