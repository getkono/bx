//! bash's two files: a generated interactive file sourced from a fixed region
//! in `~/.bashrc`, and `~/.inputrc`.
//!
//! bash gets the declarations it shares with zsh, each in its own words, and
//! nothing else. The rest of a distribution's bash setup — its prompt, its
//! terminal title, its completion — stays the distribution's: bx adds one
//! region to `~/.bashrc` and never ports or replaces a byte around it.
//!
//! | file                                  | holds                                          | attached as          |
//! |---------------------------------------|------------------------------------------------|----------------------|
//! | [`FILE`], `~/.local/share/bx/bashrc.bash` | the variables, activations, sources, aliases, functions, `[history]` and `[shell-options]` | a file bx owns whole |
//! | [`STARTUP_FILE`], `~/.bashrc`         | the one line that sources [`FILE`]              | a fixed region       |
//! | [`INPUTRC`], `~/.inputrc`             | `[keybindings]`, in readline's syntax           | a file bx owns whole |
//!
//! # The interactive file
//!
//! [`Bash::render`] assembles it through the same [`Assembly`] zsh's file is,
//! in the same phases, from the same declarations; a declaration's
//! `shells` ([`super::Shells`]) is what keeps one to zsh, and the file's plan
//! row names every declaration kept out of it ([`super::omitted`]).
//!
//! - `env` holds every `[[env]]` variable a zsh reads — `environment`, then
//!   `login`, then `interactive`, zsh's own load order — as the
//!   `export NAME=VALUE` line zsh's fragments hold, its `when` asked in
//!   bash's words. bash reads no `~/.zprofile`, so a `login` variable is
//!   written inside a block bash's login test guards, joined to its own
//!   condition when it has one ([`crate::config::when::login_opener_bash`]).
//!   A `gui` variable is `environment.d`'s alone. `[path]` is not here: its
//!   lines are zsh's words, and bash inherits a `PATH` zsh or the session
//!   exported.
//! - `activations` and `completions` hold every declared activation's bash
//!   command's output, cached apart from zsh's
//!   ([`super::activation`]'s *One command per shell*), and any source there.
//! - `aliases` holds every enabled alias as [`AliasDecl::render_bash`]
//!   renders it: the same line zsh gets, a `has:TOOL` decided while `plan`
//!   renders exactly as zsh's is, and a runtime condition asked in bash's
//!   words.
//! - `functions` holds every function bash defines, from its `bash` body when
//!   it declares one ([`super::function::resolve_bash`]); bash has no hook
//!   points, so nothing registers.
//! - `options` holds the declared `[history]` as [`History::render_bash`]
//!   renders it, then the declared `[shell-options]` as
//!   [`ShellOptions::render_bash`] renders them.
//! - Every `[[source]]` bash reads lands in the phase it names, after that
//!   phase's own declarations, as the guarded line zsh's file holds.
//!
//! The file is placed when anything above reaches bash: a variable, an
//! enabled alias — gated on a missing tool or not, as zsh's is — a history or
//! shell option bash reads, a function, a source, or an activation with a
//! bash command. Its region in `~/.bashrc` is the one [`crate::config::env`]
//! attaches to every zsh startup file: the region's delimiters around one
//! line that sources the file only when it is readable. Its bytes name the
//! file and nothing else, so they are the same for every declaration and
//! every account.
//!
//! A variable waiting on a value holds the whole file back, as it holds
//! zsh's; a function or a source waiting on one is held back alone and named
//! in the row.
//!
//! # `~/.inputrc`
//!
//! Readline reads `~/.inputrc` in place of the system's `/etc/inputrc`
//! whenever the first exists, so the file bx writes opens by including the
//! system's — a missing one is skipped silently — and then binds the declared
//! keys ([`Keybindings::render_readline`]), which therefore win. Its header
//! says the bindings reach every program linked against readline, not only
//! bash. It is placed when any key is bound, and it is a file bx owns whole:
//! an `~/.inputrc` bx did not write is a conflict the plan reports, never
//! overwritten.
//!
//! # When a declaration goes away
//!
//! [`vacated`] plans the file and `~/.inputrc` with nothing declared in them
//! once nothing places either but bx's generator for it wrote it before, as
//! [`crate::config::resolve::vacated_fragments`] does for zsh's fragments; the
//! region is left sourcing a file that sets nothing, and `bx rm` restores
//! each file from the ledger.
//!
//! # Invariant 2
//!
//! The interactive file is judged as zsh's is: its `env` phase is its one
//! environment fragment, which the plan passes through the guard
//! ([`Bash::env`]), every opener in it one the guard reads. The `aliases`
//! phase defines aliases and nothing else; the `functions` phase defines
//! functions, whose bodies are the user's templates as zsh's are; source
//! lines test a file and source it; the activation phases hold a tool's
//! output under the relocation rule [`super::activation`] applies to zsh's;
//! the `options` phase assigns only bash's own history variables and then
//! unexports them, and `shopt` assigns nothing. The history file is the other
//! path it names, and the plan judges it against bx's own directories as it
//! judges zsh's. An inputrc is readline's syntax, which has no variable of
//! the environment's at all.
//! `bash_defines_the_aliases_and_changes_only_its_history_variables` and
//! `bash_sets_the_declared_variables_as_zsh_would_and_nothing_else` run the
//! rendered file in bash and hold it to that.

use std::path::Path;

use super::alias::AliasDecl;
use super::function::Function;
use super::keybindings::Keybindings;
use super::source::{Source, SourceDecl};
use super::{Assembly, Phase, Shell, activation};
use crate::config::env::{EnvDecl, EnvKind, Var, assignment};
use crate::config::history::{self, History};
use crate::config::resolve::{BlockedEntry, Resolution, held_together, resolve_env};
use crate::config::shell_options::{self, ShellOptions};
use crate::config::target::{Attach, Body, Direction, Format, Gen, SETTLE, Target};
use crate::config::values::ResolvedValues;
use crate::config::when::{self, Gate, When};
use crate::config::{Config, Error, Origin};
use crate::paths::Portable;

/// bash's generated interactive file, which bx owns whole.
pub const FILE: &str = "~/.local/share/bx/bashrc.bash";

/// The user's startup file whose region sources [`FILE`].
pub const STARTUP_FILE: &str = "~/.bashrc";

/// Readline's own file, which bx owns whole once a key is bound.
pub const INPUTRC: &str = "~/.inputrc";

/// The lines `~/.inputrc` opens with: whose it is, and whom it reaches.
const INPUTRC_HEADER: &str = "# Generated by bx from [keybindings]. Edit the config repo, not this \
                              file.\n# Readline reads these bindings in every program linked \
                              against it, not only bash.\n";

/// The line that keeps the system's bindings, which readline would otherwise
/// stop reading once `~/.inputrc` exists. Readline skips an include it cannot
/// open.
const INCLUDE_SYSTEM: &str = "$include /etc/inputrc\n";

/// One variable bash's `env` phase holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashVar {
    /// The variable, its value substituted.
    pub var: Var,
    /// Whether only a login shell sets it: a `kind = "login"` variable, which
    /// zsh reads from `~/.zprofile`.
    pub login: bool,
}

impl BashVar {
    /// The variable's lines: `export NAME=VALUE`, plain, left out, or alone
    /// inside one guarded block, as its kind and `when` decide.
    ///
    /// A login variable is guarded by bash's login test, joined to its own
    /// runtime condition when it has one, so it is never a block nested in
    /// another.
    fn render(&self, present: &dyn Fn(&str) -> bool) -> String {
        let line = format!("export {}", assignment(&self.var));
        let block = |opener: String| format!("{opener}\n  {line}{}\n", when::CLOSER);
        let gate = self.var.when.as_ref().map(|when| when.gate_bash(present));
        match (self.login, gate) {
            (_, Some(Gate::Never)) => String::new(),
            (false, None | Some(Gate::Always)) => line.clone(),
            (false, Some(Gate::Test(test))) => block(when::opener(&test)),
            (true, None | Some(Gate::Always)) => block(when::login_opener_bash(None)),
            // A login variable gated on the login test needs it once.
            (true, Some(Gate::Test(_))) if self.var.when == Some(When::Login) => {
                block(when::login_opener_bash(None))
            }
            (true, Some(Gate::Test(test))) => block(when::login_opener_bash(Some(&test))),
        }
    }
}

/// What bash's generated interactive file holds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bash {
    /// The variables, `environment` then `login` then `interactive`, each
    /// kind in the merged configuration's order.
    env: Vec<BashVar>,
    /// The enabled aliases, in the merged configuration's order.
    aliases: Vec<AliasDecl>,
    /// The declared history, rendered in bash's names.
    history: History,
    /// The declared shell options.
    options: ShellOptions,
    /// The enabled functions bash defines, each resolved or held back.
    functions: Vec<Resolution<Function>>,
    /// The enabled sources bash reads, each resolved or held back.
    sources: Vec<Resolution<Source>>,
    /// The declared tool activations, as `plan` decided them; only the bash
    /// steps render. Empty until the plan attaches them.
    activations: activation::Plan,
    /// What the file's plan row says of the declarations that do not reach
    /// bash ([`super::omitted`]).
    omitted: Option<String>,
}

impl Bash {
    /// The file holding `aliases` — the disabled ones dropped — `history` and
    /// `options`, and nothing else yet.
    #[must_use]
    pub fn new(aliases: &[AliasDecl], history: History, options: ShellOptions) -> Self {
        Self {
            aliases: aliases.iter().filter(|a| a.enabled).cloned().collect(),
            history,
            options,
            ..Self::default()
        }
    }

    /// The file with `env` in its `env` phase.
    #[must_use]
    pub fn with_env(mut self, env: Vec<BashVar>) -> Self {
        self.env = env;
        self
    }

    /// The file with `functions` in its `functions` phase, as
    /// [`super::function::resolve_bash`] resolved them.
    #[must_use]
    pub fn with_functions(mut self, functions: Vec<Resolution<Function>>) -> Self {
        self.functions = functions;
        self
    }

    /// The file with `sources`, each in the phase it names.
    #[must_use]
    pub fn with_sources(mut self, sources: Vec<Resolution<Source>>) -> Self {
        self.sources = sources;
        self
    }

    /// The file with `activations`' bash steps in their phases.
    #[must_use]
    pub fn with_activations(mut self, activations: activation::Plan) -> Self {
        self.activations = activations;
        self
    }

    /// The file with `omitted` as what its plan row says of the declarations
    /// that do not reach bash.
    #[must_use]
    pub fn with_omitted(mut self, omitted: Option<String>) -> Self {
        self.omitted = omitted;
        self
    }

    /// The declared history, whose bash file the plan judges.
    #[must_use]
    pub const fn history(&self) -> &History {
        &self.history
    }

    /// The `env` phase's lines, which the plan judges as the file's one
    /// environment fragment. Empty when no variable is written.
    #[must_use]
    pub fn env(&self, present: &dyn Fn(&str) -> bool) -> String {
        self.env.iter().map(|var| var.render(present)).collect()
    }

    /// The note the file's plan row carries: every function held back from
    /// it, then every source, then the declarations that do not reach bash;
    /// `None` when there is none of them.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        fn held<T>(resolutions: &[Resolution<T>]) -> Vec<&BlockedEntry> {
            resolutions
                .iter()
                .filter_map(|resolution| match resolution {
                    Resolution::Blocked(entry) => Some(entry),
                    Resolution::Ready(_) => None,
                })
                .collect()
        }
        let notes: Vec<String> = [
            super::function::note(&held(&self.functions)),
            super::source::note(&held(&self.sources)),
            self.omitted.clone(),
        ]
        .into_iter()
        .flatten()
        .collect();
        (!notes.is_empty()).then(|| notes.join("; "))
    }

    /// The file's bytes.
    ///
    /// `present` answers whether a `has:TOOL` tool is usable on this machine,
    /// as it does for zsh's file. A phase with nothing in it is left out, so
    /// the bytes are a function of the declarations, the activations the plan
    /// attached and `present` alone. The phases fill as zsh's do: within one,
    /// an activation before a source, and a source after the phase's own
    /// declarations. A file holding a source line or an activation closes with
    /// the line zsh's does, for the reason zsh's does.
    #[must_use]
    pub fn render(&self, present: &dyn Fn(&str) -> bool) -> String {
        // No phase here is the terminal slot, so no contribution is refused.
        let mut assembly = Assembly::new();
        let _ = assembly.contribute(Phase::Env, crate::config::env::SECTION, self.env(present));
        for alias in &self.aliases {
            let body = alias.render_bash(present);
            if !body.is_empty() {
                let _ = assembly.contribute(Phase::Aliases, alias.name.clone(), body);
            }
        }
        super::function::contribute(&mut assembly, &self.functions, present);
        let _ = assembly.contribute(Phase::Options, history::SECTION, self.history.render_bash());
        let _ = assembly.contribute(
            Phase::Options,
            shell_options::SECTION,
            self.options.render_bash(),
        );
        let _ = self.activations.contribute(&mut assembly, Shell::Bash);
        let sourced = super::source::contribute(&mut assembly, &self.sources, Shell::Bash, present);
        let mut out = assembly.render();
        if sourced || self.activations.renders(Shell::Bash) {
            out.push_str(SETTLE);
        }
        out
    }
}

/// `~/.inputrc`'s bytes: the header, the system's bindings included, then
/// the declared ones.
#[must_use]
pub fn render_inputrc(keybindings: &Keybindings) -> String {
    format!(
        "{INPUTRC_HEADER}{INCLUDE_SYSTEM}{}",
        keybindings.render_readline()
    )
}

/// The targets bash's files make: [`FILE`] and its region in
/// [`STARTUP_FILE`] when anything places the file, and [`INPUTRC`] when a key
/// is bound. Each is attributed to the declaration that placed it.
///
/// The file is held back, whole, when a variable it holds waits on a value,
/// as zsh's interactive file is; its region is still placed. A function or a
/// source that waits on one is held back alone and named in the file's row.
///
/// # Errors
///
/// [`Error::BadValue`] when the home cannot hold the files' paths, and for a
/// variable, a function body or a source path whose value is a repo defect,
/// as [`crate::config::resolve::resolve`] lists.
pub fn place(merged: &Config, values: &ResolvedValues) -> Result<Vec<Resolution<Target>>, Error> {
    let home = values.home();
    // zsh's load order: `~/.zshenv`'s variables, then `~/.zprofile`'s, then
    // the interactive file's.
    let envs: Vec<&EnvDecl> = [EnvKind::Environment, EnvKind::Login, EnvKind::Interactive]
        .into_iter()
        .flat_map(|kind| {
            merged
                .envs
                .iter()
                .filter(move |e| e.enabled && e.kind == kind && e.shells.includes(Shell::Bash))
        })
        .collect();
    let resolved = envs
        .iter()
        .map(|decl| Ok((*decl, resolve_env(decl, values)?)))
        .collect::<Result<Vec<_>, Error>>()?;
    let sources: Vec<SourceDecl> = merged
        .sources
        .iter()
        .filter(|s| s.shells.includes(Shell::Bash))
        .cloned()
        .collect();
    let functions = super::function::resolve_bash(&merged.functions, values)?;
    let sources = super::source::resolve(&sources, values)?;
    let activation = merged
        .activations
        .iter()
        .find(|a| a.enabled && a.command_for(Shell::Bash).is_some());

    let bash = Bash::new(
        &merged.aliases,
        merged.history.clone(),
        merged.shell_options.clone(),
    );
    // What places the file: the first variable, else the first enabled
    // alias, else the history when it says anything bash reads, else the
    // shell options when they do, else the first function, source or
    // activation bash gets.
    let origin = envs
        .first()
        .map(|e| &e.origin)
        .or_else(|| bash.aliases.first().map(|alias| &alias.origin))
        .or_else(|| {
            bash.history
                .origin
                .as_ref()
                .filter(|_| !bash.history.render_bash().is_empty())
        })
        .or_else(|| {
            bash.options
                .origin
                .as_ref()
                .filter(|_| !bash.options.render_bash().is_empty())
        })
        .or_else(|| {
            merged
                .functions
                .iter()
                .find(|f| f.enabled && f.shells.includes(Shell::Bash))
                .map(|f| &f.origin)
        })
        .or_else(|| {
            merged
                .sources
                .iter()
                .find(|s| s.enabled && s.shells.includes(Shell::Bash))
                .map(|s| &s.origin)
        })
        .or_else(|| activation.map(|a| &a.origin))
        .cloned();

    let mut placed = Vec::new();
    if let Some(origin) = origin {
        let file = portable(FILE, home, &origin)?;
        let region = portable(STARTUP_FILE, home, &origin)?;
        let held: Vec<&BlockedEntry> = resolved
            .iter()
            .filter_map(|(_, resolution)| match resolution {
                Resolution::Blocked(entry) => Some(entry),
                Resolution::Ready(_) => None,
            })
            .collect();
        placed.push(if held.is_empty() {
            let env = resolved
                .into_iter()
                .filter_map(|(decl, resolution)| match resolution {
                    Resolution::Ready(var) => Some(BashVar {
                        var,
                        login: decl.kind == EnvKind::Login,
                    }),
                    Resolution::Blocked(_) => None,
                })
                .collect();
            let bash = bash
                .with_env(env)
                .with_functions(functions)
                .with_sources(sources)
                .with_omitted(super::omitted(Shell::Bash, merged));
            Resolution::Ready(target(
                file.clone(),
                Gen::Bash(Box::new(bash)),
                Attach::Own,
                &origin,
            ))
        } else {
            let (reason, hint) = held_together(&held, values);
            Resolution::Blocked(BlockedEntry {
                key: file.to_string(),
                origin: origin.clone(),
                reason,
                hint,
            })
        });
        placed.push(Resolution::Ready(target(
            region,
            Gen::Source(file),
            Attach::Region { comment: '#' },
            &origin,
        )));
    }
    let keybindings = &merged.keybindings;
    if let Some(origin) = keybindings
        .origin
        .as_ref()
        .filter(|_| !keybindings.is_empty())
    {
        placed.push(Resolution::Ready(target(
            portable(INPUTRC, home, origin)?,
            Gen::Inputrc(keybindings.clone()),
            Attach::Own,
            origin,
        )));
    }
    Ok(placed)
}

/// [`FILE`] and [`INPUTRC`] with nothing declared in them, for each one
/// `placed` does not name but `generated` says bx wrote with the generator
/// that makes it, attributed to `origin`.
///
/// Without it, removing every alias would leave them defined in every bash
/// that starts, and unbinding every key would leave the keys bound, with no
/// plan row saying so.
///
/// `generated(path, header)` answers whether bx wrote `path` as a file it
/// owns whole and the bytes there open with `header`, the line that file's
/// generator writes first. Owning the file whole is not enough: a
/// `[[target]]` the user once declared at `~/.inputrc` is owned whole too,
/// and once dropped it is left alone as every dropped target is, never
/// rewritten to an inputrc with no bindings in it.
#[must_use]
pub fn vacated(
    placed: &[Resolution<Target>],
    generated: &dyn Fn(&Portable, &str) -> bool,
    home: &Path,
    origin: &Origin,
) -> Vec<Resolution<Target>> {
    [
        (FILE, super::HEADER, Gen::Bash(Box::default())),
        (
            INPUTRC,
            INPUTRC_HEADER,
            Gen::Inputrc(Keybindings::default()),
        ),
    ]
    .into_iter()
    .filter_map(|(raw, header, generator)| {
        let path = Portable::parse_in(raw, home).ok()?;
        let named = placed.iter().any(|resolution| match resolution {
            Resolution::Ready(target) => target.path == path,
            Resolution::Blocked(entry) => entry.key == path.to_string(),
        });
        (!named && generated(&path, header))
            .then(|| Resolution::Ready(target(path, generator, Attach::Own, origin)))
    })
    .collect()
}

/// `raw` under `home`, or the error naming `origin` when it cannot be.
fn portable(raw: &str, home: &Path, origin: &Origin) -> Result<Portable, Error> {
    Portable::parse_in(raw, home).map_err(|source| Error::BadValue {
        origin: origin.clone(),
        message: format!("`{raw}` cannot be placed under this home: {source}"),
    })
}

/// A target bash's files make, produced by `generator`.
fn target(path: Portable, generator: Gen, attach: Attach, origin: &Origin) -> Target {
    Target {
        path,
        body: Body::Generated(generator),
        mode: None,
        attach,
        direction: Direction::Apply,
        format: Format::Opaque,
        requires: Vec::new(),
        references: Vec::new(),
        enabled: true,
        origin: origin.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::shell::testing::{installed, run};
    use std::path::PathBuf;

    const HOME: &str = "/var/home/example";

    fn load(text: &str) -> Config {
        parse_str(text, Path::new("/repo/bx.toml"), Path::new(HOME)).expect("parses")
    }

    /// What `config` places, its values resolved against [`HOME`].
    fn placed_by(config: &Config) -> Result<Vec<Resolution<Target>>, Error> {
        let values = ResolvedValues::resolve(
            config.values.clone(),
            &config.value_assignments,
            Path::new(HOME),
        )?;
        place(config, &values)
    }

    fn bash_of(config: &Config) -> Bash {
        Bash::new(
            &config.aliases,
            config.history.clone(),
            config.shell_options.clone(),
        )
    }

    /// Each target's path, how it is attached, and its bytes on a machine
    /// with every tool.
    fn described(placed: &[Resolution<Target>]) -> Vec<(String, Attach, String)> {
        placed
            .iter()
            .map(|resolution| match resolution {
                Resolution::Ready(target) => {
                    let Body::Generated(generator) = &target.body else {
                        panic!("a generated body: {target:?}");
                    };
                    (
                        target.path.to_string(),
                        target.attach.clone(),
                        generator.render(&|_| true),
                    )
                }
                Resolution::Blocked(entry) => panic!("nothing is held back: {entry:?}"),
            })
            .collect()
    }

    /// The source configuration's shared declarations.
    const SOURCE: &str = "[aliases]\nll = \"ls -la\"\nsudo = \"sudo \"\n\n\
                          [[alias]]\nname = \"cat\"\ncommand = \"bat --paging=never\"\n\
                          when = \"has:bat\"\n\n\
                          [[alias]]\nname = \"off\"\ncommand = \"x\"\nenabled = false\n\n\
                          [history]\nsize = 10000\nduplicates = \"all\"\n\
                          ignore_space = true\nshare = true\n\n\
                          [history.file]\nzsh = \"~/.zsh_history\"\nbash = \"~/.bash_history\"\n\n\
                          [shell-options]\nhistappend = true\ncheckwinsize = true\n\n\
                          [keybindings]\nhome = \"beginning-of-line\"\nalt-b = \"backward-word\"\n";

    const RENDERED: &str = "# Generated by bx. Edit the config repo, not this file.\n\
                            \n# bx phase: aliases\n\
                            alias ll='ls -la'\nalias sudo='sudo '\n\
                            alias cat='bat --paging=never'\n\
                            \n# bx phase: options\n\
                            HISTFILE=\"${HOME}/.bash_history\"\n\
                            HISTSIZE=10000\nHISTFILESIZE=10000\n\
                            HISTCONTROL=ignorespace:erasedups\n\
                            export -n HISTFILE HISTSIZE HISTFILESIZE HISTCONTROL\n\
                            shopt -s checkwinsize histappend\n";

    #[test]
    fn the_file_holds_the_aliases_then_history_and_shell_options_in_bash_words() {
        let bash = bash_of(&load(SOURCE));
        assert_eq!(bash.render(&|_| true), RENDERED);
        // Twice, the same bytes.
        assert_eq!(bash.render(&|_| true), bash.render(&|_| true));
        // A missing tool leaves its alias out, and asks the shell nothing.
        let without_bat = bash.render(&|tool| tool != "bat");
        assert_eq!(
            without_bat,
            RENDERED.replace("alias cat='bat --paging=never'\n", "")
        );
        assert!(!without_bat.contains("command -v"), "{without_bat}");
        // A runtime condition is asked in bash's words.
        let gated = bash_of(&load(
            "[[alias]]\nname = \"g\"\ncommand = \"git\"\nwhen = \"login\"\n",
        ));
        assert!(
            gated
                .render(&|_| true)
                .ends_with("if shopt -q login_shell; then\n  alias g='git'\nfi\n"),
            "{}",
            gated.render(&|_| true)
        );
        // Nothing declared: the header alone.
        assert_eq!(
            Bash::default().render(&|_| true),
            "# Generated by bx. Edit the config repo, not this file.\n"
        );
    }

    #[test]
    fn the_inputrc_includes_the_system_file_then_binds_the_declared_keys() {
        let keybindings = load(SOURCE).keybindings;
        assert_eq!(
            render_inputrc(&keybindings),
            "# Generated by bx from [keybindings]. Edit the config repo, not this file.\n\
             # Readline reads these bindings in every program linked against it, not only \
             bash.\n\
             $include /etc/inputrc\n\
             \"\\e[H\": beginning-of-line\n\
             \"\\eb\": backward-word\n"
        );
        assert_eq!(
            render_inputrc(&Keybindings::default()),
            format!("{INPUTRC_HEADER}{INCLUDE_SYSTEM}")
        );
    }

    #[test]
    fn every_declaration_places_the_file_its_region_and_the_inputrc() {
        let placed = placed_by(&load(SOURCE)).expect("places");
        let described = described(&placed);
        assert_eq!(
            described,
            vec![
                (FILE.to_string(), Attach::Own, RENDERED.to_string()),
                (
                    STARTUP_FILE.to_string(),
                    Attach::Region { comment: '#' },
                    format!("[[ -r {FILE} ]] && source {FILE}\n"),
                ),
                (
                    INPUTRC.to_string(),
                    Attach::Own,
                    render_inputrc(&load(SOURCE).keybindings),
                ),
            ]
        );
        // The file and its region are attributed to the first alias, the
        // inputrc to its table.
        let lines: Vec<usize> = placed
            .iter()
            .map(|resolution| match resolution {
                Resolution::Ready(target) => target.origin.line,
                Resolution::Blocked(_) => unreachable!(),
            })
            .collect();
        assert_eq!(lines, [2, 2, 29]);
    }

    #[test]
    fn each_declaration_places_the_file_on_its_own_and_only_bash_s_words_count() {
        let paths = |text: &str| -> Vec<String> {
            placed_by(&load(text))
                .expect("places")
                .iter()
                .map(|resolution| match resolution {
                    Resolution::Ready(target) => {
                        format!("{}@{}", target.path, target.origin.line)
                    }
                    Resolution::Blocked(_) => unreachable!(),
                })
                .collect()
        };
        let file = |line: usize| vec![format!("{FILE}@{line}"), format!("{STARTUP_FILE}@{line}")];
        assert_eq!(paths("[aliases]\nll = \"ls\"\n"), file(2));
        // Gated on a tool, the alias still places the file, as zsh's does.
        assert_eq!(
            paths("[[alias]]\nname = \"c\"\ncommand = \"bat\"\nwhen = \"has:bat\"\n"),
            file(1)
        );
        assert_eq!(paths("[history]\nsize = 5\n"), file(1));
        assert_eq!(paths("\n[shell-options]\nhistappend = false\n"), file(2));
        assert_eq!(
            paths("[keybindings]\nend = \"end-of-line\"\n"),
            [format!("{INPUTRC}@1")]
        );
        // What bash does not read places nothing.
        for text in [
            "",
            "[[alias]]\nname = \"off\"\ncommand = \"x\"\nenabled = false\n",
            "[history]\nshare = true\n",
            "[history.file]\nzsh = \"~/.zsh_history\"\n",
            "[shell-options]\n",
            "[keybindings]\n",
        ] {
            assert!(paths(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn a_file_bx_wrote_that_nothing_places_any_more_is_planned_empty() {
        let home = Path::new(HOME);
        let origin = Origin {
            file: PathBuf::from("/state/ledger"),
            line: 0,
        };
        let every = vacated(&[], &|_, _| true, home, &origin);
        assert_eq!(
            described(&every),
            vec![
                (
                    FILE.to_string(),
                    Attach::Own,
                    Bash::default().render(&|_| true)
                ),
                (
                    INPUTRC.to_string(),
                    Attach::Own,
                    render_inputrc(&Keybindings::default())
                ),
            ]
        );
        // Never one bx did not write, and never one still placed.
        assert!(vacated(&[], &|_, _| false, home, &origin).is_empty());
        let placed = placed_by(&load(SOURCE)).expect("places");
        assert!(vacated(&placed, &|_, _| true, home, &origin).is_empty());
        // Each file is asked after with its own generator's header, so one
        // bx owns whole but some other declaration wrote is left alone.
        let inputrc_only = |path: &Portable, header: &str| {
            path.as_str() == INPUTRC && render_inputrc(&Keybindings::default()).starts_with(header)
        };
        assert_eq!(
            described(&vacated(&[], &inputrc_only, home, &origin))
                .into_iter()
                .map(|(path, _, _)| path)
                .collect::<Vec<_>>(),
            vec![INPUTRC.to_string()]
        );
        let bash_only = |path: &Portable, header: &str| {
            path.as_str() == FILE && Bash::default().render(&|_| true).starts_with(header)
        };
        assert_eq!(
            described(&vacated(&[], &bash_only, home, &origin))
                .into_iter()
                .map(|(path, _, _)| path)
                .collect::<Vec<_>>(),
            vec![FILE.to_string()]
        );
    }

    /// Every shared declaration but aliases, history and keybindings, with
    /// one of each restricted to a single shell.
    const SHARED: &str = "[[value]]\nname = \"host\"\nkind = \"string\"\ndefault = \"h\"\n\n\
                          [[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n\
                          [[env]]\nname = \"LANG\"\nvalue = \"C.UTF-8\"\nkind = \"environment\"\n\
                          [[env]]\nname = \"PAGER\"\nvalue = \"less\"\nkind = \"login\"\n\
                          [[env]]\nname = \"SSHY\"\nvalue = \"1\"\nkind = \"login\"\n\
                          when = \"ssh\"\n\
                          [[env]]\nname = \"ZONLY\"\nvalue = \"1\"\nkind = \"interactive\"\n\
                          shells = [\"zsh\"]\n\
                          [[env]]\nname = \"BROWSER\"\nvalue = \"firefox\"\nkind = \"gui\"\n\
                          [[function]]\nname = \"mkcd\"\nbody = \"mkdir -p -- \\\"$1\\\"\"\n\
                          [[function]]\nname = \"hooked\"\nbody = \"z\"\nhook = \"chpwd\"\n\
                          shells = [\"zsh\"]\n\
                          [[source]]\nname = \"keychain\"\npath = \"~/.keychain/{{host}}-sh\"\n\
                          phase = \"activations\"\n\
                          [[source]]\nname = \"zplug\"\npath = \"~/.zplug\"\nshells = [\"zsh\"]\n\
                          [[activation]]\nname = \"starship\"\n\
                          command = [\"starship\", \"init\", \"{shell}\"]\nphase = \"completions\"\n\
                          [[activation]]\nname = \"mise\"\ncommand = [\"mise\", \"activate\", \"zsh\"]\n";

    #[test]
    fn every_shared_declaration_reaches_bash_in_zsh_s_order_and_the_row_names_the_rest() {
        let placed = placed_by(&load(SHARED)).expect("places");
        let [Resolution::Ready(file), Resolution::Ready(region)] = placed.as_slice() else {
            panic!("the file and its region: {placed:?}");
        };
        assert_eq!(file.path.as_str(), FILE);
        assert_eq!(region.path.as_str(), STARTUP_FILE);
        // Attributed to the first variable bash reads, in load order.
        assert_eq!(file.origin.line, 10);
        let Body::Generated(Gen::Bash(bash)) = &file.body else {
            panic!("{:?}", file.body);
        };
        assert_eq!(
            bash.render(&|_| true),
            "# Generated by bx. Edit the config repo, not this file.\n\
             \n# bx phase: env\n\
             export LANG=C.UTF-8\n\
             if shopt -q login_shell; then\n  export PAGER=less\nfi\n\
             if shopt -q login_shell && [[ -n ${SSH_CONNECTION-} ]]; then\n  export SSHY=1\nfi\n\
             export EDITOR=nvim\n\
             \n# bx phase: activations\n\
             [[ -r ~/.keychain/h-sh ]] && source ~/.keychain/h-sh\n\
             \n# bx phase: functions\n\
             function mkcd {\nmkdir -p -- \"$1\"\n}\n\
             \n# bx: done, whichever plugins were found\ntrue\n"
        );
        assert_eq!(
            Gen::Bash(bash.clone()).note().as_deref(),
            Some(
                "not in bash: env `ZONLY`, function `hooked`, source `zplug`; activation \
                 `mise` declares no bash command, so it is not run for bash"
            )
        );
        // Twice, the same bytes.
        assert_eq!(bash.render(&|_| true), bash.render(&|_| true));
    }

    #[test]
    fn a_login_variable_is_one_block_whatever_its_own_condition() {
        let var = |when: Option<When>, login| BashVar {
            var: Var {
                name: "X".to_string(),
                value: "1".to_string(),
                when,
            },
            login,
        };
        let cases = [
            (None, false, "export X=1\n"),
            (
                Some(When::Interactive),
                false,
                "if [[ $- == *i* ]]; then\n  export X=1\nfi\n",
            ),
            (Some(When::Has("t".to_string())), false, "export X=1\n"),
            (Some(When::Has("gone".to_string())), false, ""),
            (
                None,
                true,
                "if shopt -q login_shell; then\n  export X=1\nfi\n",
            ),
            (
                Some(When::Login),
                true,
                "if shopt -q login_shell; then\n  export X=1\nfi\n",
            ),
            (
                Some(When::Has("t".to_string())),
                true,
                "if shopt -q login_shell; then\n  export X=1\nfi\n",
            ),
            (Some(When::Has("gone".to_string())), true, ""),
            (
                Some(When::EnvSet("Y".to_string())),
                true,
                "if shopt -q login_shell && [[ -n ${Y+x} ]]; then\n  export X=1\nfi\n",
            ),
        ];
        for (when, login, expected) in cases {
            let var = var(when, login);
            assert_eq!(var.render(&|tool| tool == "t"), expected, "{var:?}");
            // Every opener it writes is one the guard reads.
            for line in expected.lines().filter(|l| l.starts_with("if ")) {
                assert!(when::is_opener(line), "{line}");
            }
        }
    }

    #[test]
    fn bash_sets_the_declared_variables_as_zsh_would_and_nothing_else() {
        let Some(bash) = installed("bash") else {
            return;
        };
        let placed = placed_by(&load(SHARED)).expect("places");
        let Resolution::Ready(file) = &placed[0] else {
            panic!("{placed:?}");
        };
        let Body::Generated(generator) = &file.body else {
            panic!("{:?}", file.body);
        };
        let rendered = generator.render(&|_| true);
        let probe = "printf '%s|' \"$LANG\" \"${PAGER-unset}\" \"${SSHY-unset}\" \"$EDITOR\" \
                     \"${ZONLY-unset}\" \"${BROWSER-unset}\"; declare -F mkcd hooked; \
                     declare -p LANG EDITOR PAGER 2>/dev/null; true\n";
        let script = format!("{rendered}{probe}");
        // Not a login shell: the login variables stay unset, and what is set
        // is exported, as zsh's `export` lines do.
        let got =
            String::from_utf8(run(&bash, &["--norc", "--noprofile"], &script)).expect("utf-8");
        assert_eq!(
            got,
            "C.UTF-8|unset|unset|nvim|unset|unset|mkcd\n\
             declare -x LANG=\"C.UTF-8\"\ndeclare -x EDITOR=\"nvim\"\n"
        );
        // A login shell reads them; SSHY waits on its own condition too.
        let got = String::from_utf8(run(&bash, &["--norc", "--noprofile", "-l"], &script))
            .expect("utf-8");
        assert_eq!(
            got,
            "C.UTF-8|less|unset|nvim|unset|unset|mkcd\n\
             declare -x LANG=\"C.UTF-8\"\ndeclare -x EDITOR=\"nvim\"\ndeclare -x PAGER=\"less\"\n"
        );
    }

    #[test]
    fn bash_defines_the_aliases_and_changes_only_its_history_variables() {
        let Some(bash) = installed("bash") else {
            return;
        };
        let rendered = bash_of(&load(SOURCE)).render(&|_| true);
        let flags = ["--norc", "--noprofile"];
        let probe = "printf '%s|' \"${BASH_ALIASES[ll]}\" \"${BASH_ALIASES[sudo]}\" \
                     \"${BASH_ALIASES[cat]}\" \"$HISTSIZE\" \"$HISTCONTROL\"; \
                     shopt -p checkwinsize histappend\n";
        let got =
            String::from_utf8(run(&bash, &flags, &format!("{rendered}{probe}"))).expect("utf-8");
        assert_eq!(
            got,
            "ls -la|sudo |bat --paging=never|10000|ignorespace:erasedups|\
             shopt -s checkwinsize\nshopt -s histappend\n"
        );

        // Invariant 2: only the history variables change, and nothing is
        // exported, even what an exported parent set. `BASHOPTS` is bash's
        // report of its options, which `shopt` is declared to change.
        let dump = "__bx_dump() { local n; for n in $(compgen -v); do case $n in \
                    BASH_*|BASHOPTS|FUNCNAME|_|n|LINENO|RANDOM|SECONDS|SRANDOM|EPOCH*|\
                    PIPESTATUS) continue;; esac; printf '%s=%s\\n' \"$n\" \"${!n}\"; done; \
                    printf 'exported: %s\\n' $(compgen -e); printf -- '---\\n'; }\n";
        let dumps = |body: &str| {
            let script = format!("export HISTSIZE=1\n{dump}__bx_dump\n{body}__bx_dump\n");
            let got = String::from_utf8(run(&bash, &flags, &script)).expect("utf-8");
            let (before, after) = got.split_once("---\n").expect("two dumps");
            (
                before.to_string(),
                after.trim_end_matches("---\n").to_string(),
            )
        };
        let (before, after) = dumps(&rendered);
        let mut changed: Vec<&str> = after
            .lines()
            .filter(|line| !before.lines().any(|was| was == *line))
            .map(|line| line.split('=').next().expect("a name"))
            .collect();
        changed.sort_unstable();
        assert_eq!(
            changed,
            ["HISTCONTROL", "HISTFILE", "HISTFILESIZE", "HISTSIZE"],
            "{before}\n---\n{after}"
        );
        assert!(before.contains("exported: HISTSIZE"), "{before}");
        assert!(!after.contains("exported: HIST"), "{after}");
        // The dump does see an assignment, so the comparison means something.
        let (before, after) = dumps("Z=1\n");
        assert_ne!(after, before);
    }

    #[test]
    fn readline_reads_the_inputrc_as_the_declared_bindings() {
        let Some(bash) = installed("bash") else {
            return;
        };
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let inputrc = scratch.path().join("inputrc");
        std::fs::write(&inputrc, render_inputrc(&load(SOURCE).keybindings)).expect("write");
        let script = format!(
            "bind -f {}\nbind -q beginning-of-line\nbind -q backward-word\n",
            inputrc.display()
        );
        let got = String::from_utf8(run(&bash, &["--norc", "--noprofile", "-i"], &script))
            .expect("utf-8");
        // Readline spells an escape-prefixed sequence `\M-` where
        // `convert-meta` is on and `\e` where it is off. The inputrc includes
        // the system's, which decides that setting (Fedora's turns it off,
        // Ubuntu's leaves it on), and both spellings name the same keys.
        let got = got.replace("\\M-", "\\e");
        assert!(
            got.contains("beginning-of-line can be invoked via") && got.contains("\"\\e[H\""),
            "{got}"
        );
        assert!(
            got.contains("backward-word can be invoked via") && got.contains("\"\\eb\""),
            "{got}"
        );
    }
}
