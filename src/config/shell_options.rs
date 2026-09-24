//! Declared shell options: the `[shell-options]` table.
//!
//! ```toml
//! [shell-options]
//! histappend   = true   # append to the history file rather than overwrite it
//! checkwinsize = true   # update LINES and COLUMNS after each command
//! ```
//!
//! Both keys are bash's own options, set with `shopt -s` when `true` and unset
//! with `shopt -u` when `false`; a key left out is left to bash. zsh has no
//! counterpart to either that is off by default — it appends to its history
//! file unless told otherwise and tracks the window size itself — so neither
//! renders anything for zsh, and the vocabulary is exactly these two keys: a
//! key this version does not know is a load error, as everywhere else.
//!
//! The table merges key by key, the last layer that sets a key winning.
//! [`ShellOptions::render_bash`] is the declaration in bash's words, for the
//! entry that generates bash's own interactive file to place.
//!
//! # Invariant 2
//!
//! `shopt` changes how bash behaves and assigns nothing; the test runs the
//! rendered bytes in bash and holds them to that.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[shell-options]";

/// Every key a `[shell-options]` table may carry, each a bash option, in the
/// order they are rendered.
const KEYS: [&str; 2] = ["checkwinsize", "histappend"];

/// What one layer's `[shell-options]` table says, or what the merged layers
/// say.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShellOptions {
    /// bash's `checkwinsize`.
    pub checkwinsize: Option<bool>,
    /// bash's `histappend`.
    pub histappend: Option<bool>,
}

impl ShellOptions {
    /// Fold a later layer's table over this one, key by key, the later layer
    /// winning.
    pub(crate) fn absorb(&mut self, later: &Self) {
        if let Some(on) = later.checkwinsize {
            self.checkwinsize = Some(on);
        }
        if let Some(on) = later.histappend {
            self.histappend = Some(on);
        }
    }

    /// Each declared option with its name, in [`KEYS`]'s order.
    fn declared(&self) -> impl Iterator<Item = (&'static str, bool)> {
        [(KEYS[0], self.checkwinsize), (KEYS[1], self.histappend)]
            .into_iter()
            .filter_map(|(name, on)| on.map(|on| (name, on)))
    }

    /// The declaration in bash's words: one `shopt -s` line and one
    /// `shopt -u` line, or nothing when nothing is declared.
    #[must_use]
    pub fn render_bash(&self) -> String {
        let mut out = String::new();
        for (flag, wanted) in [("-s", true), ("-u", false)] {
            let names: Vec<&str> = self
                .declared()
                .filter(|(_, on)| *on == wanted)
                .map(|(name, _)| name)
                .collect();
            if !names.is_empty() {
                out.push_str(&format!("shopt {flag} {}\n", names.join(" ")));
            }
        }
        out
    }
}

/// Parse a `[shell-options]` table.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key this version does not know, and
/// [`Error::WrongType`] for a value that is not a boolean.
pub fn parse_shell_options(table: &Table, file: &Path, text: &str) -> Result<ShellOptions, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;
    Ok(ShellOptions {
        checkwinsize: ctx.bool_at(table, "checkwinsize")?,
        histappend: ctx.bool_at(table, "histappend")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::shell::testing::{installed, run};

    fn parse(text: &str) -> Result<ShellOptions, Error> {
        parse_str(text, Path::new("/repo/bx.toml"), Path::new("/home/u"))
            .map(|config| config.shell_options)
    }

    #[test]
    fn both_keys_parse_and_render_for_bash_in_a_fixed_order() {
        let options =
            parse("[shell-options]\nhistappend = true\ncheckwinsize = true\n").expect("parses");
        assert_eq!(
            options,
            ShellOptions {
                checkwinsize: Some(true),
                histappend: Some(true),
            }
        );
        assert_eq!(options.render_bash(), "shopt -s checkwinsize histappend\n");
        let mixed = ShellOptions {
            checkwinsize: Some(false),
            histappend: Some(true),
        };
        assert_eq!(
            mixed.render_bash(),
            "shopt -s histappend\nshopt -u checkwinsize\n"
        );
    }

    #[test]
    fn declaring_nothing_renders_nothing() {
        for text in ["", "[shell-options]\n"] {
            let options = parse(text).expect(text);
            assert_eq!(options, ShellOptions::default());
            assert_eq!(options.render_bash(), "");
        }
    }

    #[test]
    fn an_unknown_option_or_a_non_boolean_is_refused() {
        for (text, needle) in [
            (
                "[shell-options]\nglobstar = true\n",
                "unknown key `globstar` in [shell-options]",
            ),
            (
                "[shell-options]\nhistappend = \"on\"\n",
                "`histappend` must be a boolean",
            ),
            ("shell-options = 1\n", "a table `[shell-options]`"),
        ] {
            let err = parse(text).expect_err(text).to_string();
            assert!(err.contains(needle), "{text}: {err}");
            assert!(err.starts_with("/repo/bx.toml:"), "{text}: {err}");
        }
    }

    #[test]
    fn a_later_layer_wins_key_by_key() {
        let mut merged = ShellOptions {
            checkwinsize: Some(true),
            histappend: Some(true),
        };
        merged.absorb(&ShellOptions {
            histappend: Some(false),
            ..ShellOptions::default()
        });
        assert_eq!(
            merged,
            ShellOptions {
                checkwinsize: Some(true),
                histappend: Some(false),
            }
        );
    }

    #[test]
    fn bash_sets_the_declared_options_and_no_variable() {
        let Some(bash) = installed("bash") else {
            return;
        };
        let options = ShellOptions {
            checkwinsize: Some(false),
            histappend: Some(true),
        };
        // `shopt -p` fails when any option it prints is off.
        let probe = "shopt -p checkwinsize histappend || :\n";
        let wanted = "shopt -u checkwinsize\nshopt -s histappend\n";
        let before = run(
            &bash,
            &["--norc", "--noprofile"],
            &format!("shopt -s checkwinsize\n{probe}"),
        );
        assert_ne!(String::from_utf8(before).expect("utf-8"), wanted);
        let after = run(
            &bash,
            &["--norc", "--noprofile"],
            &format!("shopt -s checkwinsize\n{}{probe}", options.render_bash()),
        );
        assert_eq!(String::from_utf8(after).expect("utf-8"), wanted);

        // Invariant 2: the same variables, with the same values, before and
        // after. `BASHOPTS` is bash's own read-only report of the options,
        // which is what changing one changes, and `BASHPID` differs in each
        // pipeline's subshell.
        let dump = "compgen -v | while read -r n; do case $n in \
                    BASH*|FUNCNAME|_|LINENO|RANDOM|SECONDS|SRANDOM|EPOCH*|PIPESTATUS|n) continue;; \
                    esac; printf '%s=%s\\n' \"$n\" \"${!n}\"; done; printf -- '---\\n'\n";
        let dumps = |body: &str| {
            let got = String::from_utf8(run(
                &bash,
                &["--norc", "--noprofile"],
                &format!("{dump}{body}{dump}"),
            ))
            .expect("utf-8");
            let (before, after) = got.split_once("---\n").expect("two dumps");
            (
                before.to_string(),
                after.trim_end_matches("---\n").to_string(),
            )
        };
        let (before, after) = dumps(&options.render_bash());
        assert_eq!(after, before);
        // The dump does see an assignment, so the equality means something.
        let (before, after) = dumps("Z=1\n");
        assert_ne!(after, before);
    }
}
