//! zsh's placement graph: which files the shell declarations land in.
//!
//! The counterpart of [`super::bash::place`]; [`place`] is both together.
//! Resolution ([`crate::config::resolve::resolve`]) is handed [`place`] by its
//! caller and appends what it derives after every declared target, and `plan`
//! asks [`vacated_fragments`] for the fragments a configuration no longer
//! places.

use std::path::Path;

use crate::config::env::{self, EnvDecl, Fragment, Place, Syntax, Var};
use crate::config::external::first_followed;
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

/// The platform whose login shells the placement answers for: what each
/// reads at login, and in what order, is the one thing about the shells that
/// differs between them.
///
/// On macOS a login shell runs `path_helper` from `/etc/zprofile` (zsh) or
/// `/etc/profile` (bash) after `~/.zshenv` and before `~/.zprofile` or
/// `~/.bash_profile`, and it rebuilds `PATH` with the system's directories
/// first, so every directory `~/.zshenv` prepended lands behind `/usr/bin`.
/// Terminal and iTerm start a login shell for every window, so a login bash
/// reads `~/.bash_profile` and not `~/.bashrc`. On macOS, then:
///
/// - the `zprofile` fragment repeats the `[path]` entries that reach zsh,
///   after its own variables, so a login zsh puts them back where they were
///   declared; each added entry is taken out before it is put back, so the
///   second pass moves it rather than repeating it;
/// - bash's file gets a second region, in [`super::bash::PROFILE`], which
///   sources it unless `~/.bash_profile` already had `~/.bashrc` source it
///   ([`super::bash::profile_line`]).
///
/// Linux reads none of these differently, so on Linux the placement is what
/// it always was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux.
    Linux,
    /// macOS, where a login shell runs `path_helper` and Terminal starts
    /// login shells.
    Macos,
}

impl Platform {
    /// The platform this binary was built for, and so runs on.
    ///
    /// The library's own tests pin it to Linux, so the bytes they expect of
    /// every placement are the same on every runner; what macOS places is
    /// tested through [`place_on`] with [`Platform::Macos`], and end to end
    /// by the acceptance suite, which runs the real binary.
    pub const HERE: Self = if cfg!(target_os = "macos") && !cfg!(test) {
        Self::Macos
    } else {
        Self::Linux
    };
}

/// Every target the shell declarations of `merged` place on this platform:
/// [`place_on`] for [`Platform::HERE`].
///
/// What a caller of [`crate::config::resolve::resolve`] hands it, so the
/// placed targets are refused for sharing a file or overlapping an external
/// alongside the declared ones.
///
/// # Errors
///
/// Whatever [`place_on`] returns.
pub fn place(merged: &Config, values: &ResolvedValues) -> Result<Vec<Resolution<Target>>, Error> {
    place_on(merged, values, Platform::HERE)
}

/// Every target the shell declarations of `merged` place on `platform`:
/// zsh's ([`place_envs`]), then bash's ([`super::bash::place`]).
///
/// # Errors
///
/// Whatever [`place_envs`] or [`super::bash::place`] returns.
pub fn place_on(
    merged: &Config,
    values: &ResolvedValues,
    platform: Platform,
) -> Result<Vec<Resolution<Target>>, Error> {
    let mut placed = place_envs(merged, values, platform)?;
    placed.extend(super::bash::place(merged, values, platform)?);
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
/// fragment holds back holds its entries back with it. On
/// [`Platform::Macos`] they land in the `zprofile` fragment too, after its
/// variables, which places it and its region on their own; that fragment
/// inherits the `zshenv` fragment's variables, so an entry that refers to one
/// is judged against it.
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
    platform: Platform,
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
    // The first external that follows a branch: the interactive file asks
    // about its updates, and is placed for that alone when nothing else is.
    let followed_origin = first_followed(&merged.externals).map(|external| &external.origin);
    let resolved = envs
        .iter()
        .map(|decl| Ok((decl, resolve_env(decl, values)?)))
        .collect::<Result<Vec<_>, Error>>()?;
    let bodies = super::function::resolve(functions, values)?;
    let sourced = super::source::resolve(sources, values)?;

    let lands_in = |place: Place| {
        resolved
            .iter()
            // A variable that lands in `environment.d` carries no `shells`
            // (the load refuses one), so this keeps only the other shell's
            // variables out of zsh's files.
            .filter(move |(decl, _)| {
                decl.kind.places().contains(&place) && decl.shells.includes(Shell::Zsh)
            })
    };
    // What the `zshenv` fragment exports: what a login zsh has read by the
    // time it reads the `zprofile` fragment, whose repeated `[path]` entries
    // may refer to it.
    let exported: Vec<Var> = lands_in(Place::Zshenv)
        .filter_map(|(_, resolution)| match resolution {
            Resolution::Ready(var) => Some(var.clone()),
            Resolution::Blocked(_) => None,
        })
        .collect();

    let mut placed = Vec::new();
    for place in Place::ALL {
        let here: Vec<&(&EnvDecl, Resolution<Var>)> = lands_in(place).collect();
        let repeats_path = place == Place::Zprofile && platform == Platform::Macos;
        let entries = if place == Place::Zshenv || repeats_path {
            path
        } else {
            &[]
        };
        let inherited = if repeats_path && !path.is_empty() {
            exported.clone()
        } else {
            Vec::new()
        };
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
                match activation_origin
                    .or(followed_origin)
                    .filter(|_| place == Place::Zshrc)
                {
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
            let generator = match fragment_gen(place, vars, entries.to_vec(), inherited) {
                Gen::Interactive(file) => Gen::Interactive(Box::new(
                    file.with_plugins(interactive)?
                        .with_history(history.clone())
                        .with_keybindings(keybindings.clone())
                        .with_aliases(declared)
                        .with_functions(bodies.clone())
                        .with_sources(sourced.clone())
                        .with_omitted(super::omitted(Shell::Zsh, merged))
                        .with_update_prompt(followed_origin.is_some()),
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

/// What produces the fragment at `place`, holding `vars` and then `entries`
/// and read after `inherited`: an environment fragment, or at the
/// interactive place the file the phase assembly renders, with the fragment
/// in its `env` phase and no plugin yet.
fn fragment_gen(place: Place, vars: Vec<Var>, entries: Vec<PathEntry>, inherited: Vec<Var>) -> Gen {
    let fragment = Fragment {
        syntax: place.syntax(),
        vars,
        path: entries,
        inherited,
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
                    fragment_gen(place, Vec::new(), Vec::new(), Vec::new()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::config::when::tools;

    const HOME: &str = "/var/home/example";

    /// What `text` places for zsh on `platform`: each ready target's path,
    /// its bytes on a machine with every tool, and its fragment's inherited
    /// variables' names.
    fn zsh_on(text: &str, platform: Platform) -> Vec<(String, String, Vec<String>)> {
        let config = parse_str(text, Path::new("/repo/bx.toml"), Path::new(HOME)).expect("parses");
        let values = ResolvedValues::resolve(
            config.values.clone(),
            &config.value_assignments,
            Path::new(HOME),
        )
        .expect("values");
        place_envs(&config, &values, platform)
            .expect("places")
            .into_iter()
            .map(|resolution| match resolution {
                Resolution::Ready(target) => {
                    let Body::Generated(generator) = &target.body else {
                        panic!("generated: {target:?}");
                    };
                    let inherited = match generator {
                        Gen::Env(fragment) => {
                            fragment.inherited.iter().map(|v| v.name.clone()).collect()
                        }
                        _ => Vec::new(),
                    };
                    (
                        target.path.to_string(),
                        generator.render(&tools(&|_| true)),
                        inherited,
                    )
                }
                Resolution::Blocked(entry) => panic!("held back: {entry:?}"),
            })
            .collect()
    }

    const PATHS: &str = "[[env]]\nname = \"LANG\"\nvalue = \"C.UTF-8\"\nkind = \"environment\"\n\n\
                         [path]\nprepend = [\"~/bin\"]\nappend = [\"/opt/tool/bin\"]\n";

    #[test]
    fn on_macos_the_zprofile_fragment_puts_the_path_entries_back_after_path_helper() {
        let linux = zsh_on(PATHS, Platform::Linux);
        let paths: Vec<&str> = linux.iter().map(|(p, ..)| p.as_str()).collect();
        let shared = [
            Place::Zshenv.fragment(),
            "~/.zshenv",
            Place::EnvironmentD.fragment(),
        ];
        assert_eq!(paths, shared);

        let macos = zsh_on(PATHS, Platform::Macos);
        let paths: Vec<&str> = macos.iter().map(|(p, ..)| p.as_str()).collect();
        assert_eq!(
            paths,
            [
                shared[0],
                shared[1],
                shared[2],
                Place::Zprofile.fragment(),
                "~/.zprofile"
            ]
        );
        // What Linux writes is written alike.
        assert_eq!(macos[..3], linux[..]);
        // The `zprofile` fragment holds the same `[path]` lines and no
        // variable, and inherits the `zshenv` fragment's.
        let zshenv_path = linux[0].1.split_once("# [path]\n").expect("a path block").1;
        let (head, zprofile_path) = macos[3].1.split_once("# [path]\n").expect("a path block");
        assert_eq!(zprofile_path, zshenv_path);
        assert!(!head.contains("export "), "{head}");
        assert_eq!(macos[3].2, ["LANG"]);
        assert_eq!(
            macos[4].1,
            format!("[[ -r {0} ]] && source {0}\n", Place::Zprofile.fragment())
        );
    }

    #[test]
    fn on_macos_a_login_variable_comes_before_the_repeated_path_entries() {
        let login =
            format!("{PATHS}\n[[env]]\nname = \"PAGER\"\nvalue = \"less\"\nkind = \"login\"\n");
        let macos = zsh_on(&login, Platform::Macos);
        let zprofile = &macos
            .iter()
            .find(|(p, ..)| p == Place::Zprofile.fragment())
            .expect("the zprofile fragment")
            .1;
        let pager = zprofile
            .find("export PAGER=less")
            .expect("the login variable");
        let path = zprofile.find("# [path]").expect("the path block");
        assert!(pager < path, "{zprofile}");
        // Without a `[path]` entry nothing is repeated, and nothing is
        // inherited for it.
        let alone = zsh_on(
            "[[env]]\nname = \"PAGER\"\nvalue = \"less\"\nkind = \"login\"\n",
            Platform::Macos,
        );
        assert_eq!(
            alone,
            zsh_on(
                "[[env]]\nname = \"PAGER\"\nvalue = \"less\"\nkind = \"login\"\n",
                Platform::Linux,
            )
        );
        assert!(
            alone
                .iter()
                .all(|(_, body, inherited)| !body.contains("PATH") && inherited.is_empty())
        );
    }

    #[test]
    fn an_entry_kept_to_bash_is_not_repeated_for_zsh() {
        let bash_only = "[path]\nprepend = [{ dir = \"~/bin\", shells = [\"bash\"] }]\n";
        assert!(zsh_on(bash_only, Platform::Macos).is_empty());
    }

    #[test]
    fn the_platform_here_is_linux_in_the_library_s_tests() {
        assert_eq!(Platform::HERE, Platform::Linux);
    }
}
