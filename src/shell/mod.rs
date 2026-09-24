//! The generated interactive shell file, assembled in a fixed load order.
//!
//! Everything bx generates for an interactive shell lands in one file, and the
//! order its parts load in is bx's to decide, never the order the code that
//! produced them happened to run in. That order is the eleven [`Phase`]s, each
//! a named section of the file:
//!
//! | phase           | holds                                                       |
//! |-----------------|-------------------------------------------------------------|
//! | `env`           | environment variables                                       |
//! | `path`          | `PATH` edits                                                |
//! | `activations`   | tool activations that put a tool on `PATH` or `fpath`       |
//! | `completion`    | the completion system's own setup                           |
//! | `completions`   | tool integrations that register a completion or a widget    |
//! | `plugins`       | plugins, each sourced only once it is readable              |
//! | `aliases`       | aliases                                                     |
//! | `functions`     | functions, and the hooks they register                      |
//! | `keybindings`   | keybindings                                                 |
//! | `options`       | shell options and history settings                          |
//! | `terminal`      | the one plugin that must load after everything else         |
//!
//! The completion system is set up after `PATH` and every activation — which
//! is what puts a tool's completion functions on `fpath` — and before the first
//! phase that can register a completion, which is what it needs to work at
//! all. The terminal slot is the one place order is a claim rather than a
//! convention: a plugin such as a syntax highlighter wraps every widget defined
//! before it, so it works only when nothing loads after it, and two plugins
//! that each need that cannot both have it. [`Assembly`] therefore holds at
//! most one terminal claimant and refuses a second, naming both.
//!
//! # Determinism
//!
//! [`Assembly::render`] emits the phases in [`Phase::ALL`]'s order whatever
//! order the contributions arrived in, and within one phase in the order they
//! were contributed — which is each contributor's declaration order, itself a
//! function of the merged configuration. A phase nobody contributed to emits
//! nothing, not even its heading. The bytes are a function of the
//! contributions alone: no timestamp, no map iteration order.
//!
//! # Invariant 2
//!
//! Invariant 2 is about relocation: nothing bx writes may move a tool's config,
//! data or cache outside a root the configuration declares. How each phase is
//! held to it depends on who wrote its bytes.
//!
//! The `env` and `path` phases hold bx's own environment assignments, and what
//! lands in them must be an environment fragment the plan judges through
//! [`crate::env_guard`]. The `activations` and `completions` phases hold a
//! tool's cached activation output, judged as the next paragraph says. Every
//! other phase is generated shell content that is not an environment fragment,
//! and the bx-derived content in it must carry no assignment at all. A
//! declared function's body is a template the user wrote. bx only substitutes
//! declared values into it and does not judge it, because the invariant
//! governs what bx itself emits or relocates. The scaffolding this module adds
//! — the header and one comment per phase — sets nothing, and the plugin lines
//! [`plugin`] renders only test a file and source it; the tests below establish
//! both of the bytes actually emitted. The alias lines [`alias`] renders define
//! an alias and nothing else, and its tests run them in zsh to establish that
//! too. The `functions` phase [`function`] renders defines functions and
//! appends to zsh's hook arrays — shell arrays zsh cannot export, which name
//! what runs at a hook and relocate nothing — and its tests run it in zsh to
//! establish that those arrays are the only parameters it changes. A declared
//! optional source [`source`] renders is the same guarded line a plugin is, in
//! whichever phase between `activations` and `options` it names — never `env`,
//! `path`, `completion` or the terminal slot — and its tests hold it to a test
//! and a `source` word for word.
//!
//! A tool's activation output assigns variables of its own — `MISE_SHELL`,
//! `STARSHIP_SHELL`, a function's locals, ZLE's `BUFFER` — and none of those
//! moves a file, so it is held to the relocation rule rather than to "no
//! assignment": [`activation::relocations`] searches the whole output for
//! every name [`crate::env_guard::is_relocating`] knows, judges each
//! occurrence in an assigning position through [`crate::env_guard::check`]
//! when its value is a readable literal, and refuses it when it is not, and
//! [`activation::plan`] writes none of an output with a refusal. Every other
//! line passes untouched. bx's own bytes there are one `eval` of a
//! single-quoted literal holding the output, which set nothing. What the
//! output's code runs later — `eval "$(mise hook-env)"` — is the tool's own
//! behaviour at runtime, outside what bx emits.
//!
//! # Activations
//!
//! A tool's own shell integration — `brew shellenv`, `mise activate zsh`,
//! `starship init zsh` — is run by [`activation::plan`] rather than at every
//! shell start, trusted once two runs agree, and cached against the content
//! of the tool's binary, so the `activations` and `completions` phases hold
//! text and start no process. There is no form that runs a tool at shell
//! start.

pub mod activation;
pub mod alias;
pub mod function;
pub mod plugin;
pub mod source;

/// Running generated shell text in a real shell, for the submodules' tests.
#[cfg(test)]
pub(crate) mod testing {
    use std::path::{Path, PathBuf};

    /// The installed shell `program`, or `None` on a machine excused from
    /// supplying it. A runner may not excuse itself, as `env_guard`'s
    /// differential checks rule.
    pub(crate) fn installed(program: &str) -> Option<PathBuf> {
        if let crate::detect::Presence::Present { path } = crate::detect::locate_in_env(program) {
            return Some(path);
        }
        let excused = std::env::var_os("BX_TEST_WITHOUT_SHELLS").is_some();
        assert!(
            excused && std::env::var_os("CI").is_none(),
            "{program} is not installed, so the shell checks held against it would assert \
             nothing — install it, or set BX_TEST_WITHOUT_SHELLS off a runner"
        );
        None
    }

    /// Run `script` in `shell` with `flags` and an empty environment, and
    /// return what it printed.
    ///
    /// The script is a file rather than `-c`, because zsh parses a `-c`
    /// string whole, before any `alias` in it has run, and a startup file is
    /// read the way a script file is: each line parsed once the ones before
    /// it have run.
    pub(crate) fn run(shell: &Path, flags: &[&str], script: &str) -> Vec<u8> {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let file = scratch.path().join("script");
        std::fs::write(&file, script).expect("the script is written");
        let output = std::process::Command::new(shell)
            .args(flags)
            .arg(&file)
            .current_dir(scratch.path())
            .env_clear()
            .env("HOME", scratch.path())
            .env("PATH", "/nonexistent")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("an installed shell runs");
        assert!(output.status.success(), "{script}: {output:?}");
        output.stdout
    }
}

/// One named section of the generated interactive shell file.
///
/// Declared in load order, so the derived `Ord` is the load order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// Environment variables.
    Env,
    /// `PATH` edits.
    Path,
    /// Tool activations that put a tool on `PATH` or `fpath`.
    Activations,
    /// The completion system's own setup.
    Completion,
    /// Tool integrations that register a completion or a widget.
    Completions,
    /// Plugins, each sourced only once it is readable.
    Plugins,
    /// Aliases.
    Aliases,
    /// Functions, and the hooks they register.
    Functions,
    /// Keybindings.
    Keybindings,
    /// Shell options and history settings.
    Options,
    /// The single slot that loads after everything else.
    Terminal,
}

impl Phase {
    /// Every phase, in load order.
    pub const ALL: [Self; 11] = [
        Self::Env,
        Self::Path,
        Self::Activations,
        Self::Completion,
        Self::Completions,
        Self::Plugins,
        Self::Aliases,
        Self::Functions,
        Self::Keybindings,
        Self::Options,
        Self::Terminal,
    ];

    /// The phase's name, as its heading in the generated file spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Path => "path",
            Self::Activations => "activations",
            Self::Completion => "completion",
            Self::Completions => "completions",
            Self::Plugins => "plugins",
            Self::Aliases => "aliases",
            Self::Functions => "functions",
            Self::Keybindings => "keybindings",
            Self::Options => "options",
            Self::Terminal => "terminal",
        }
    }

    /// Whether the phase may hold an environment assignment: only `env` and
    /// `path`, whose content must be an environment fragment the plan judges.
    #[must_use]
    pub const fn assigns(self) -> bool {
        matches!(self, Self::Env | Self::Path)
    }
}

/// Why a contribution cannot be assembled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A second contribution claims the single terminal slot.
    #[error(
        "`{second}` claims the terminal slot, which `{first}` already holds; \
         only one thing can load after everything else"
    )]
    TerminalClaimed {
        /// The contribution that holds the slot.
        first: String,
        /// The one refused.
        second: String,
    },
}

/// The line every assembled file opens with. Fixed, so the file's bytes are a
/// function of its contributions alone.
const HEADER: &str = "# Generated by bx. Edit the config repo, not this file.\n";

/// The comment that opens a phase's section.
fn heading(phase: Phase) -> String {
    format!("\n# bx phase: {}\n", phase.name())
}

/// One contribution: who made it, and the shell text it adds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Contribution {
    /// Who contributed it, for messages.
    owner: String,
    /// The text, each line ending in a newline.
    body: String,
}

/// The generated interactive shell file, collected phase by phase.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Assembly {
    /// Each phase's contributions, in contribution order, indexed by the
    /// phase's position in [`Phase::ALL`].
    phases: [Vec<Contribution>; 11],
}

impl Assembly {
    /// An assembly nothing has contributed to.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `body` to `phase`, on behalf of `owner`.
    ///
    /// A `body` that does not end in a newline gets one, so one contribution
    /// can never run into the next.
    ///
    /// # Errors
    ///
    /// [`Error::TerminalClaimed`] when `phase` is [`Phase::Terminal`] and
    /// something already holds it. The assembly is left as it was.
    pub fn contribute(
        &mut self,
        phase: Phase,
        owner: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<(), Error> {
        let owner = owner.into();
        let slot = &mut self.phases[phase as usize];
        if phase == Phase::Terminal
            && let Some(first) = slot.first()
        {
            return Err(Error::TerminalClaimed {
                first: first.owner.clone(),
                second: owner,
            });
        }
        let mut body = body.into();
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        slot.push(Contribution { owner, body });
        Ok(())
    }

    /// Whether nothing with any content has been contributed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.phases.iter().flatten().all(|c| c.body.is_empty())
    }

    /// The file's bytes: the header, then each phase that holds content, in
    /// [`Phase::ALL`]'s order, under its heading.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from(HEADER);
        for phase in Phase::ALL {
            let contributions = &self.phases[phase as usize];
            if contributions.iter().all(|c| c.body.is_empty()) {
                continue;
            }
            out.push_str(&heading(phase));
            for contribution in contributions {
                out.push_str(&contribution.body);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every contribution below, one per phase, in load order.
    fn one_per_phase() -> Vec<(Phase, String, String)> {
        Phase::ALL
            .iter()
            .map(|&phase| {
                (
                    phase,
                    format!("{}-owner", phase.name()),
                    format!(": {}\n", phase.name()),
                )
            })
            .collect()
    }

    fn assemble(contributions: &[(Phase, String, String)]) -> String {
        let mut assembly = Assembly::new();
        for (phase, owner, body) in contributions {
            assembly
                .contribute(*phase, owner.clone(), body.clone())
                .expect("one terminal claimant");
        }
        assembly.render()
    }

    #[test]
    fn there_are_eleven_phases_in_load_order_each_named_once() {
        assert_eq!(Phase::ALL.len(), 11);
        for (index, phase) in Phase::ALL.iter().enumerate() {
            assert_eq!(*phase as usize, index, "{phase:?}");
        }
        assert!(Phase::ALL.is_sorted());
        let mut names: Vec<_> = Phase::ALL.iter().map(|p| p.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 11);
        assert_eq!(Phase::ALL[0], Phase::Env);
        assert_eq!(Phase::ALL[10], Phase::Terminal);
    }

    #[test]
    fn completion_is_set_up_after_path_and_before_anything_that_registers_one() {
        let completion = Phase::Completion;
        for before in [Phase::Env, Phase::Path, Phase::Activations] {
            assert!(before < completion, "{before:?}");
        }
        for after in [
            Phase::Completions,
            Phase::Plugins,
            Phase::Aliases,
            Phase::Functions,
            Phase::Keybindings,
            Phase::Options,
            Phase::Terminal,
        ] {
            assert!(completion < after, "{after:?}");
        }
    }

    #[test]
    fn only_env_and_path_may_assign() {
        for phase in Phase::ALL {
            assert_eq!(
                phase.assigns(),
                matches!(phase, Phase::Env | Phase::Path),
                "{phase:?}"
            );
        }
    }

    #[test]
    fn the_file_is_assembled_in_phase_order_whatever_order_it_was_contributed_in() {
        let ordered = one_per_phase();
        let expected = assemble(&ordered);
        let mut at = 0;
        for phase in Phase::ALL {
            let heading = heading(phase);
            let found = expected[at..].find(&heading).expect("heading present") + at;
            let body = format!("{}: {}\n", heading, phase.name());
            assert_eq!(&expected[found..found + body.len()], body, "{phase:?}");
            at = found + body.len();
        }
        assert!(expected.starts_with(HEADER));

        // Reversed, and every rotation: the same bytes each time.
        let mut reversed = ordered.clone();
        reversed.reverse();
        assert_eq!(assemble(&reversed), expected);
        for shift in 1..ordered.len() {
            let mut rotated = ordered.clone();
            rotated.rotate_left(shift);
            assert_eq!(assemble(&rotated), expected, "rotated by {shift}");
        }
    }

    #[test]
    fn within_a_phase_contributions_keep_their_order() {
        let mut assembly = Assembly::new();
        assembly
            .contribute(Phase::Aliases, "b", "alias b=x\n")
            .unwrap();
        assembly
            .contribute(Phase::Env, "e", "export E=1\n")
            .unwrap();
        assembly
            .contribute(Phase::Aliases, "a", "alias a=y")
            .unwrap();
        assert_eq!(
            assembly.render(),
            format!(
                "{HEADER}\n# bx phase: env\nexport E=1\n\
                 \n# bx phase: aliases\nalias b=x\nalias a=y\n"
            )
        );
    }

    #[test]
    fn a_phase_with_no_content_emits_nothing() {
        let mut assembly = Assembly::new();
        assert!(assembly.is_empty());
        assert_eq!(assembly.render(), HEADER);
        assembly.contribute(Phase::Options, "o", "").unwrap();
        assert!(assembly.is_empty());
        assert_eq!(assembly.render(), HEADER);
        assembly
            .contribute(Phase::Options, "p", "setopt autocd\n")
            .unwrap();
        assert!(!assembly.is_empty());
        assert_eq!(
            assembly.render(),
            format!("{HEADER}\n# bx phase: options\nsetopt autocd\n")
        );
    }

    #[test]
    fn a_second_terminal_claimant_is_refused_naming_both() {
        let mut assembly = Assembly::new();
        assembly
            .contribute(Phase::Terminal, "zsh-syntax-highlighting", "source a\n")
            .unwrap();
        let before = assembly.clone();
        let err = assembly
            .contribute(Phase::Terminal, "fast-syntax-highlighting", "source b\n")
            .expect_err("the slot is taken");
        assert_eq!(
            err,
            Error::TerminalClaimed {
                first: "zsh-syntax-highlighting".to_string(),
                second: "fast-syntax-highlighting".to_string(),
            }
        );
        let message = err.to_string();
        assert!(message.contains("`zsh-syntax-highlighting`"), "{message}");
        assert!(message.contains("`fast-syntax-highlighting`"), "{message}");
        assert_eq!(assembly, before, "a refused claim changes nothing");
        // Every other phase takes any number of contributions.
        for phase in Phase::ALL.into_iter().filter(|p| *p != Phase::Terminal) {
            assembly.contribute(phase, "x", ": x\n").unwrap();
            assembly.contribute(phase, "y", ": y\n").unwrap();
        }
    }

    #[test]
    fn two_renders_of_the_same_contributions_are_byte_identical() {
        let contributions = one_per_phase();
        assert_eq!(assemble(&contributions), assemble(&contributions));
    }

    #[test]
    fn the_scaffolding_sets_nothing() {
        // Invariant 2: generated shell content that is not an environment
        // fragment carries no assignment. The header and each heading are the
        // bytes this module adds on its own; each is a comment or a blank.
        let scaffolding = Phase::ALL.iter().fold(HEADER.to_string(), |mut out, p| {
            out.push_str(&heading(*p));
            out
        });
        for line in scaffolding.lines() {
            assert!(line.is_empty() || line.starts_with("# "), "{line:?}");
        }
    }
}
