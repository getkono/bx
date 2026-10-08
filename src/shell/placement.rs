//! zsh's placement graph: which files the shell declarations land in.
//!
//! The counterpart of [`super::bash::place`]; [`place`] is both together.
//! Resolution ([`crate::config::resolve::resolve`]) is handed [`place`] by its
//! caller and appends what it derives after every declared target, and `plan`
//! asks [`vacated_fragments`] for the fragments a configuration no longer
//! places.

use std::path::Path;

use crate::config::env::{self, EnvDecl, Fragment, Place, Syntax, Var};
use crate::config::history::History;
use crate::config::path::PathEntry;
use crate::config::resolution::{BlockReason, BlockedEntry, Resolution};
use crate::config::target::{Attach, Body, Direction, Format, Gen, Interactive, Target};
use crate::config::values::{self, ResolvedValues, Unresolved};
use crate::config::{Config, Error, Origin};
use crate::paths::Portable;

use super::Shell;
use super::alias::AliasDecl;
use super::function::FunctionDecl;
use super::keybindings::Keybindings;
use super::plugin::PluginDecl;
use super::source::SourceDecl;

/// Every target the shell declarations of `merged` place: zsh's
/// ([`place_envs`]), then bash's ([`super::bash::place`]).
///
/// What a caller of [`crate::config::resolve::resolve`] hands it, so the
/// placed targets are refused for sharing a file or overlapping an external
/// alongside the declared ones.
///
/// # Errors
///
/// Whatever [`place_envs`] or [`super::bash::place`] returns.
pub fn place(merged: &Config, values: &ResolvedValues) -> Result<Vec<Resolution<Target>>, Error> {
    let mut placed = place_envs(merged, values)?;
    placed.extend(super::bash::place(merged, values)?);
    Ok(placed)
}

/// The targets the `[[env]]` placement graph derives, after every declared
/// target.
///
/// For each [`Place`] at least one variable lands in, in [`Place::ALL`]'s
/// order: the fragment bx owns whole, and for a shell place the fixed region
/// in the user's startup file that sources it. A fragment is held back when
/// any variable it holds is — naming every value it waits on — and that costs
/// that fragment alone: every other fragment, every region and every declared
/// target still resolve. A region is never held back: its bytes name the
/// fragment and nothing else, and it sources the fragment only once one is
/// there to read. A place no variable lands in emits nothing here; a fragment
/// bx wrote there earlier is planned empty by [`vacated_fragments`].
///
/// The `[path]` entries land in the `zshenv` fragment, after its variables,
/// which is emitted when either is declared. Nothing in an entry is
/// substituted, so an entry never holds a fragment back; a variable the
/// fragment holds back holds its entries back with it.
///
/// The enabled `[[plugin]]` entries land in the `zshrc` fragment, which is
/// the interactive shell file and is rendered through the phase assembly
/// ([`Interactive`]), and it is emitted when either an interactive variable or
/// a plugin is declared. Nothing in a plugin is substituted either, so a
/// plugin never holds the file back; a variable that holds it back holds its
/// plugins back with it.
///
/// The `[history]` declaration lands in the same file's `options` phase, in
/// zsh's names, and a history that says anything zsh reads places the file on
/// its own too. It holds no placeholder either, so it never holds the file
/// back, and a variable that does holds the history back with it.
///
/// The declared `[keybindings]` land in that file's `keybindings` phase, and
/// binding any key places the file on its own, as a history does. A binding
/// holds no placeholder, and a variable that holds the file back holds its
/// keybindings back with it.
///
/// The enabled `[aliases]` and `[[alias]]` entries land in that file's
/// `aliases` phase, and an enabled alias places the file on its own as a
/// plugin does. Its `when = "has:TOOL"` is decided when the file is rendered,
/// with the `present` the plan decides every other `has:TOOL` through, so an
/// alias gated on a missing tool still places the file and adds no line to
/// it. Nothing in an alias is substituted, and a variable that holds the file
/// back holds its aliases back with it.
///
/// The enabled `[[function]]` entries land in that file's `functions` phase,
/// each body substituted from the same values every target is, and an enabled
/// function places the file on its own as an alias does. A function whose
/// body waits on a value is held back alone: the file is still written with
/// every other function in it, and its plan row names each held-back one
/// ([`Interactive::note`]). A variable that holds the file back holds its
/// functions back with it.
///
/// The enabled `[[source]]` entries land in that file too, each in the phase
/// it names, its path substituted from the same values, and an enabled source
/// places the file on its own as a function does. A source whose path waits
/// on a value is held back alone and named in the plan row, as a function is.
///
/// An enabled `[[activation]]` places that file on its own too, as a source
/// does. What it adds is not known here — resolution runs no tool — so the
/// file is placed without it, and `plan` attaches the activations it decided
/// ([`Interactive::with_activations`]) before rendering. Nothing in an
/// activation is substituted, and a variable that holds the file back holds
/// its activations back with it.
///
/// # Errors
///
/// [`Error::BadValue`] for a variable, a function body or a source path whose
/// value is a repo defect: a malformed placeholder, a reference to a value no
/// layer declares, or a committed `default` that puts a character no fragment
/// line, function body or source path can hold into it; and for a second
/// enabled plugin claiming the terminal slot.
pub(crate) fn place_envs(
    merged: &Config,
    values: &ResolvedValues,
) -> Result<Vec<Resolution<Target>>, Error> {
    // Only what reaches zsh: a declaration kept to bash is bash's file's.
    let path: Vec<PathEntry> = merged
        .path
        .iter()
        .filter(|entry| entry.shells.includes(Shell::Zsh))
        .cloned()
        .collect();
    let (envs, path, plugins, history): (&[EnvDecl], &[PathEntry], &[PluginDecl], &History) =
        (&merged.envs, &path, &merged.plugins, &merged.history);
    let functions: Vec<FunctionDecl> = merged
        .functions
        .iter()
        .filter(|f| f.shells.includes(Shell::Zsh))
        .cloned()
        .collect();
    let sources: Vec<SourceDecl> = merged
        .sources
        .iter()
        .filter(|s| s.shells.includes(Shell::Zsh))
        .cloned()
        .collect();
    let (aliases, functions, sources): (&[AliasDecl], &[FunctionDecl], &[SourceDecl]) =
        (&merged.aliases, &functions, &sources);
    let keybindings: &Keybindings = &merged.keybindings;
    // The history's origin, when it says anything zsh reads, or else the
    // keybindings', when any key is bound: what places the interactive file
    // when nothing else does.
    let table_origin = history
        .origin
        .as_ref()
        .filter(|_| !history.render_zsh().is_empty())
        .or_else(|| {
            keybindings
                .origin
                .as_ref()
                .filter(|_| !keybindings.is_empty())
        });
    // The first enabled activation's origin: what places the interactive
    // file when nothing at all but an activation is declared.
    let activation_origin = merged
        .activations
        .iter()
        .find(|a| a.enabled && a.command_for(Shell::Zsh).is_some())
        .map(|a| &a.origin);
    let resolved = envs
        .iter()
        .map(|decl| Ok((decl, resolve_env(decl, values)?)))
        .collect::<Result<Vec<_>, Error>>()?;
    let bodies = super::function::resolve(functions, values)?;
    let sourced = super::source::resolve(sources, values)?;

    let mut placed = Vec::new();
    for place in Place::ALL {
        let here: Vec<&(&EnvDecl, Resolution<Var>)> = resolved
            .iter()
            // A variable that lands in `environment.d` carries no `shells`
            // (the load refuses one), so this keeps only the other shell's
            // variables out of zsh's files.
            .filter(|(decl, _)| {
                decl.kind.places().contains(&place) && decl.shells.includes(Shell::Zsh)
            })
            .collect();
        let entries = if place == Place::Zshenv { path } else { &[] };
        let (interactive, declared, defined, optional) = if place == Place::Zshrc {
            (plugins, aliases, functions, sources)
        } else {
            (&[][..], &[][..], &[][..], &[][..])
        };
        let plugin = interactive.iter().find(|p| p.enabled);
        let alias = declared.iter().find(|a| a.enabled);
        let function = defined.iter().find(|f| f.enabled);
        let table_here = table_origin.filter(|_| place == Place::Zshrc);
        let source = optional.iter().find(|s| s.enabled);
        let origin = match (
            here.first(),
            entries.first(),
            plugin,
            alias,
            function,
            table_here,
            source,
        ) {
            (Some((first, _)), ..) => first.origin.clone(),
            (None, Some(entry), ..) => entry.origin.clone(),
            (None, None, Some(plugin), ..) => plugin.origin.clone(),
            (None, None, None, Some(alias), ..) => alias.origin.clone(),
            (None, None, None, None, Some(function), ..) => function.origin.clone(),
            (None, None, None, None, None, Some(table), _) => table.clone(),
            (None, None, None, None, None, None, Some(source)) => source.origin.clone(),
            (None, None, None, None, None, None, None) => {
                match activation_origin.filter(|_| place == Place::Zshrc) {
                    Some(origin) => origin.clone(),
                    None => continue,
                }
            }
        };
        let portable = |raw: &str| {
            Portable::parse_in(raw, values.home()).map_err(|source| Error::BadValue {
                origin: origin.clone(),
                message: format!("`{raw}` cannot be placed under this home: {source}"),
            })
        };
        let fragment = portable(place.fragment())?;
        let held: Vec<&BlockedEntry> = here
            .iter()
            .filter_map(|(_, resolution)| match resolution {
                Resolution::Blocked(entry) => Some(entry),
                Resolution::Ready(_) => None,
            })
            .collect();
        placed.push(if held.is_empty() {
            let vars = here
                .iter()
                .filter_map(|(_, resolution)| match resolution {
                    Resolution::Ready(var) => Some(var.clone()),
                    Resolution::Blocked(_) => None,
                })
                .collect();
            let generator = match fragment_gen(place, vars, entries.to_vec()) {
                Gen::Interactive(file) => Gen::Interactive(Box::new(
                    file.with_plugins(interactive)?
                        .with_history(history.clone())
                        .with_keybindings(keybindings.clone())
                        .with_aliases(declared)
                        .with_functions(bodies.clone())
                        .with_sources(sourced.clone())
                        .with_omitted(super::omitted(Shell::Zsh, merged)),
                )),
                other => other,
            };
            Resolution::Ready(fragment_target(place, fragment.clone(), generator, &origin))
        } else {
            let (reason, hint) = held_together(&held, values);
            Resolution::Blocked(BlockedEntry {
                key: fragment.to_string(),
                origin: origin.clone(),
                reason,
                hint,
            })
        });
        if let Some(file) = place.startup_file() {
            placed.push(Resolution::Ready(placed_target(
                portable(file)?,
                Gen::Source(fragment),
                Attach::Region { comment: '#' },
                Format::Opaque,
                &origin,
            )));
        }
    }
    Ok(placed)
}

/// What produces the fragment at `place`, holding `vars` and then `entries`:
/// an environment fragment, or at the interactive place the file the phase
/// assembly renders, with the fragment in its `env` phase and no plugin yet.
fn fragment_gen(place: Place, vars: Vec<Var>, entries: Vec<PathEntry>) -> Gen {
    let fragment = Fragment {
        syntax: place.syntax(),
        vars,
        path: entries,
    };
    match place {
        Place::Zshrc => Gen::Interactive(Box::new(Interactive::new(fragment))),
        Place::Zshenv | Place::EnvironmentD | Place::Zprofile => Gen::Env(fragment),
    }
}

/// The fragment bx owns whole at `place`, produced by `generator`.
fn fragment_target(place: Place, path: Portable, generator: Gen, origin: &Origin) -> Target {
    let format = match place.syntax() {
        Syntax::EnvironmentD => Format::EnvD,
        Syntax::Zsh => Format::Opaque,
    };
    placed_target(path, generator, Attach::Own, format, origin)
}

/// A header-only fragment for each place the placement graph no longer puts a
/// variable in, but whose fragment bx wrote earlier.
///
/// [`place_envs`] emits nothing for a place no enabled variable lands in, so a
/// variable switched off, removed, or moved to another `kind` would otherwise
/// leave the fragment bx wrote for it in place — `export EDITOR=…` still
/// sourced by every shell, with no plan row saying so. `recorded` answers
/// whether bx has written a path as a file it owns whole, which only the
/// ledger knows; resolution itself stays a pure function of the layers and the
/// home. While it is recorded, the fragment is planned with no variable in it,
/// so the change shows as a `modify` row and `apply` writes the empty
/// fragment; the startup file's region is left as it is, sourcing a fragment
/// that sets nothing, and `bx rm` restores both from the ledger.
///
/// A place `placed` already names — ready, or held back under the fragment's
/// path — is left to it. Each vacated fragment is attributed to `ledger`, the
/// record that put it in the plan. bash's generated file and `~/.inputrc`
/// follow, vacated the same way ([`super::bash::vacated`]), but only
/// where `generated` says their own generator wrote them.
#[must_use]
pub fn vacated_fragments(
    placed: &[Resolution<Target>],
    recorded: impl Fn(&Portable) -> bool,
    generated: impl Fn(&Portable, &str) -> bool,
    home: &Path,
    ledger: &Path,
) -> Vec<Resolution<Target>> {
    let origin = Origin {
        file: ledger.to_path_buf(),
        line: 0,
    };
    let bash = super::bash::vacated(placed, &generated, home, &origin);
    Place::ALL
        .into_iter()
        .filter_map(|place| {
            let path = Portable::parse_in(place.fragment(), home).ok()?;
            let named = placed.iter().any(|resolution| match resolution {
                Resolution::Ready(target) => target.path == path,
                Resolution::Blocked(entry) => entry.key == path.to_string(),
            });
            (!named && recorded(&path)).then(|| {
                Resolution::Ready(fragment_target(
                    place,
                    path,
                    fragment_gen(place, Vec::new(), Vec::new()),
                    &origin,
                ))
            })
        })
        .chain(bash)
        .collect()
}

/// A target the placement graph derives, attributed to the first variable
/// that put it there.
fn placed_target(
    path: Portable,
    generator: Gen,
    attach: Attach,
    format: Format,
    origin: &Origin,
) -> Target {
    Target {
        path,
        body: Body::Generated(generator),
        mode: None,
        attach,
        direction: Direction::Apply,
        format,
        requires: Vec::new(),
        references: Vec::new(),
        enabled: true,
        origin: origin.clone(),
    }
}

/// Substitute one variable's value, or explain why it cannot be — in the
/// vocabulary a target is held back in, keyed by the variable's name.
///
/// # Errors
///
/// [`Error::BadValue`] for a repo defect, as [`place_envs`] lists.
pub(crate) fn resolve_env(
    decl: &EnvDecl,
    values: &ResolvedValues,
) -> Result<Resolution<Var>, Error> {
    let block = |reason, hint| {
        Ok(Resolution::Blocked(BlockedEntry {
            key: decl.name.clone(),
            origin: decl.origin.clone(),
            reason,
            hint,
        }))
    };
    let names_of = |names: Vec<String>| values.in_declaration_order(names);
    match values.substitute(&decl.value) {
        Ok(value) => {
            let Some(problem) = env::unwritable(&value) else {
                return Ok(Resolution::Ready(Var {
                    name: decl.name.clone(),
                    value,
                    when: decl.when.clone(),
                }));
            };
            // Checked as written at parse, so the character came in through a
            // value: an account's answer, whose line the hint names, or a
            // committed `default` alone, which no answer can clear.
            let problem = format!("env `{}`: {problem}", decl.name);
            let causes = values.account_inputs(&decl.value);
            if causes.is_empty() {
                return Err(Error::BadValue {
                    origin: decl.origin.clone(),
                    message: problem,
                });
            }
            let names = names_of(causes);
            let hint = values.answers_hint(&problem, &[decl.value.as_str()], &names);
            block(BlockReason::InvalidValue { names }, hint)
        }
        Err(Unresolved::Disabled { names }) => {
            let names = names_of(names);
            let hint = values::disabled_hint(&names.iter().map(String::as_str).collect::<Vec<_>>());
            block(BlockReason::DisabledValue { names }, hint)
        }
        Err(Unresolved::Invalid { names }) => {
            let names = names_of(names);
            let hint = values.invalid_hint(&names);
            block(BlockReason::InvalidValue { names }, hint)
        }
        Err(Unresolved::Unset { names }) => {
            let names = names_of(names);
            let hint = values::init_hint(&names.iter().map(String::as_str).collect::<Vec<_>>());
            block(BlockReason::UnsetValue { names }, hint)
        }
        Err(defect) => Err(Error::BadValue {
            origin: decl.origin.clone(),
            message: format!("env `{}`: {defect}", decl.name),
        }),
    }
}

/// One reason and one hint for a fragment several held-back variables share,
/// ranked as `config::resolve` ranks one target's: a switched-off declaration
/// first, then an unusable answer, then an unanswered value. Every name of the
/// winning class is named, in declaration order.
pub(crate) fn held_together(
    held: &[&BlockedEntry],
    values: &ResolvedValues,
) -> (BlockReason, String) {
    let mut disabled = Vec::new();
    let mut invalid = Vec::new();
    let mut invalid_hints: Vec<&str> = Vec::new();
    let mut unset = Vec::new();
    for entry in held {
        match &entry.reason {
            BlockReason::DisabledValue { names } => disabled.extend(names.iter().cloned()),
            BlockReason::InvalidValue { names } => {
                invalid.extend(names.iter().cloned());
                if !invalid_hints.contains(&entry.hint.as_str()) {
                    invalid_hints.push(&entry.hint);
                }
            }
            BlockReason::UnsetValue { names } => unset.extend(names.iter().cloned()),
        }
    }
    fn spelled(names: &[String]) -> Vec<&str> {
        names.iter().map(String::as_str).collect()
    }
    if !disabled.is_empty() {
        let names = values.in_declaration_order(disabled);
        let hint = values::disabled_hint(&spelled(&names));
        (BlockReason::DisabledValue { names }, hint)
    } else if !invalid.is_empty() {
        let names = values.in_declaration_order(invalid);
        (
            BlockReason::InvalidValue { names },
            invalid_hints.join("; "),
        )
    } else {
        let names = values.in_declaration_order(unset);
        let hint = values::init_hint(&spelled(&names));
        (BlockReason::UnsetValue { names }, hint)
    }
}
