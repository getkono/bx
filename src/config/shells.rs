//! The shell vocabulary a declaration is written in: which shells bx
//! generates for ([`Shell`]), which of them one declaration reaches
//! ([`Shells`]), and the named sections of the generated interactive file a
//! declaration can land in ([`Phase`]).
//!
//! The words are the configuration's, because a config author writes them:
//! `shells = ["zsh"]` and `phase = "completions"` are keys of `bx.toml`. What
//! the generated files are made of, and in what order, is
//! [`crate::shell`]'s, which reads these values and never the other way round.

/// A shell bx generates configuration for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Shell {
    /// zsh.
    Zsh,
    /// bash.
    Bash,
}

impl Shell {
    /// Every shell, in the order messages list them.
    pub const ALL: [Self; 2] = [Self::Zsh, Self::Bash];

    /// The shell's name, as `bx.toml` and its own `init` commands spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Zsh => "zsh",
            Self::Bash => "bash",
        }
    }

    /// The shell a config author spelled, if it is one.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|shell| shell.name() == raw)
    }
}

/// The shells one declaration renders into.
///
/// # The `shells` key
///
/// `[[env]]`, `[[function]]`, `[[source]]` and `[[activation]]` entries, and
/// a `[path]` entry written as an inline table, each take an optional
/// `shells = ["zsh"]`, naming the shells the declaration is
/// kept to. Without it a declaration reaches every shell, so zsh and bash are
/// configured alike from one declaration. A name that is not a shell bx
/// generates for, or an empty list, fails the load; a declaration restricted
/// away from a shell is named on that shell's generated file's plan row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Shells {
    /// Whether it reaches zsh.
    zsh: bool,
    /// Whether it reaches bash.
    bash: bool,
}

impl Default for Shells {
    fn default() -> Self {
        Self::EVERY
    }
}

impl Shells {
    /// Every shell: what a declaration with no `shells` key reaches.
    pub const EVERY: Self = Self {
        zsh: true,
        bash: true,
    };

    /// The key, as a config author writes it.
    pub const KEY: &'static str = "shells";

    /// Whether the declaration reaches `shell`.
    #[must_use]
    pub const fn includes(self, shell: Shell) -> bool {
        match shell {
            Shell::Zsh => self.zsh,
            Shell::Bash => self.bash,
        }
    }

    /// The shells `names` spell.
    ///
    /// # Errors
    ///
    /// Why the list names no shell, or names one bx does not generate for.
    pub fn from_names(names: &[String]) -> Result<Self, String> {
        let known = || {
            Shell::ALL
                .iter()
                .map(|shell| format!("{:?}", shell.name()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        if names.is_empty() {
            return Err(format!(
                "`shells` names no shell; list one or more of {}, or set `enabled = false`",
                known()
            ));
        }
        let mut shells = Self {
            zsh: false,
            bash: false,
        };
        for name in names {
            match Shell::parse(name) {
                Some(Shell::Zsh) => shells.zsh = true,
                Some(Shell::Bash) => shells.bash = true,
                None => {
                    return Err(format!(
                        "{name:?} is not a shell bx generates for; `shells` lists {}",
                        known()
                    ));
                }
            }
        }
        Ok(shells)
    }
}

/// One named section of the generated interactive shell file.
///
/// Declared in load order, so the derived `Ord` is the load order. What each
/// phase holds, and why in that order, is [`crate::shell`]'s to say.
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
}

// Only tests ask these, so they sit last, beside them: the source scans that
// read everything above the first `#[cfg(test)]` as this module's shipped code
// still read all of it.
#[cfg(test)]
impl Shells {
    /// Only `shell`.
    #[must_use]
    pub const fn only(shell: Shell) -> Self {
        Self {
            zsh: matches!(shell, Shell::Zsh),
            bash: matches!(shell, Shell::Bash),
        }
    }
}

#[cfg(test)]
impl Phase {
    /// Whether the phase may hold an environment assignment: only `env` and
    /// `path`, whose content must be an environment fragment the plan judges.
    #[must_use]
    pub const fn assigns(self) -> bool {
        matches!(self, Self::Env | Self::Path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
