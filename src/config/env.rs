//! Declared environment variables, and the startup files each one lands in.
//!
//! # The `[[env]]` schema
//!
//! ```toml
//! [[env]]
//! name    = "SCCACHE_DIR"                  # required; the natural key
//! value   = "{{scratch_root}}/sccache"     # required; placeholders substitute
//! kind    = "environment"                  # environment | gui | login | interactive
//! enabled = true                           # default true
//! ```
//!
//! # Placement is derived from when a variable must be visible
//!
//! A variable is declared by **when it has to be visible**, never by which shell
//! file it goes in. The placement graph turns that into the native file:
//!
//! | kind          | visible to                          | lands in                              |
//! |---------------|-------------------------------------|---------------------------------------|
//! | `environment` | every zsh, and GUI-launched programs | `~/.zshenv` and `environment.d`       |
//! | `gui`         | GUI-launched programs only          | `environment.d`                       |
//! | `login`       | login shells only                   | `~/.zprofile`                         |
//! | `interactive` | interactive shells only             | the generated interactive file        |
//!
//! `environment.d` is a fragment bx owns whole,
//! [`ENVIRONMENT_D`]. Every shell startup file is the user's, so bx never
//! writes a declaration into one: it attaches a **fixed three-line region**
//! whose one line sources a fragment bx owns whole, beneath
//! [`FRAGMENT_DIR`]. The region's bytes are the same for every declaration and
//! every account, so an edit the user makes anywhere else in the file is never
//! bx's business, and a change of declaration rewrites only bx's own file.
//!
//! Every fragment is an environment fragment in the guard's grammar, and the
//! plan judges it against the declared roots before it is written. A fragment
//! for which a declared value has no usable answer is held back on its own —
//! the other fragments, and every other target, still resolve.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};
use crate::env_guard::is_variable_name;
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[env]]";

/// Every key an `[[env]]` entry may carry.
const KEYS: [&str; 4] = ["name", "value", "kind", "enabled"];

/// The directory bx's generated shell fragments live in.
pub const FRAGMENT_DIR: &str = "~/.local/share/bx";

/// The `environment.d` fragment every `environment` and `gui` variable lands
/// in. `50-` puts it in the middle of the order systemd reads the directory
/// in, so a fragment the user numbers lower or higher still decides whether it
/// comes before or after bx's.
pub const ENVIRONMENT_D: &str = "~/.config/environment.d/50-bx.conf";

/// When a declared variable has to be visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvKind {
    /// Everywhere: every zsh, login or not, and every GUI-launched program.
    Environment,
    /// Only to programs the graphical session launches.
    Gui,
    /// Only to login shells.
    Login,
    /// Only to interactive shells.
    Interactive,
}

impl EnvKind {
    /// Every kind, as a config author spells it.
    const SPELLINGS: [(&'static str, Self); 4] = [
        ("environment", Self::Environment),
        ("gui", Self::Gui),
        ("login", Self::Login),
        ("interactive", Self::Interactive),
    ];

    /// The kind a config author spelled, if it is one.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::SPELLINGS
            .iter()
            .find_map(|(spelling, kind)| (*spelling == raw).then_some(*kind))
    }

    /// The places a variable of this kind lands in.
    #[must_use]
    pub const fn places(self) -> &'static [Place] {
        match self {
            Self::Environment => &[Place::Zshenv, Place::EnvironmentD],
            Self::Gui => &[Place::EnvironmentD],
            Self::Login => &[Place::Zprofile],
            Self::Interactive => &[Place::Zshrc],
        }
    }
}

/// One `[[env]]` entry, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvDecl {
    /// The variable's name.
    pub name: String,
    /// Its value, placeholders unsubstituted.
    pub value: String,
    /// When it has to be visible.
    pub kind: EnvKind,
    /// `false` in any layer removes the variable from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// Parse one `[[env]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_env(table: &Table, file: &Path, text: &str) -> Result<EnvDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if !is_variable_name(&name) {
        return Err(ctx.bad(
            table,
            "name",
            format!(
                "`{name}` is not an environment variable name: a name starts with a letter or \
                 `_` and holds only ASCII letters, digits and `_`"
            ),
        ));
    }

    let value = ctx.required_str(table, "value")?.to_string();
    if let Some(problem) = unwritable(&value) {
        return Err(ctx.bad(table, "value", format!("`{name}`: {problem}")));
    }

    let raw_kind = ctx.required_str(table, "kind")?;
    let kind = EnvKind::parse(raw_kind).ok_or_else(|| {
        ctx.bad(
            table,
            "kind",
            format!(
                "`kind` must be one of {}, got {raw_kind:?}",
                EnvKind::SPELLINGS
                    .iter()
                    .map(|(spelling, _)| format!("{spelling:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;

    Ok(EnvDecl {
        name,
        value,
        kind,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Why `value` cannot be written as one value on one line of a fragment, or
/// `None` when it can.
///
/// A control character — a newline above all — would end the line and start a
/// second assignment nobody declared, and a `"`, `\` or `` ` `` cannot sit
/// inside the double quotes a value is written in. Checked on the value as
/// written, and again once substituted, since an answer can carry one in.
#[must_use]
pub fn unwritable(value: &str) -> Option<String> {
    value
        .chars()
        .find(|c| c.is_control() || matches!(c, '"' | '\\' | '`'))
        .map(|c| {
            format!(
                "a value is written on one line, inside double quotes where it needs them, \
                 so it may not hold a control character, `\"`, `\\` or `` ` ``; found {c:?}"
            )
        })
}

/// A place a variable can land in.
///
/// Listed in the order the placement graph emits them, which is the order
/// `plan` reports them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Place {
    /// `~/.zshenv`, read by every zsh.
    Zshenv,
    /// The `environment.d` fragment, read by the systemd user manager.
    EnvironmentD,
    /// `~/.zprofile`, read by login zsh.
    Zprofile,
    /// `~/.zshrc`, read by interactive zsh.
    Zshrc,
}

impl Place {
    /// Every place, in the order the placement graph emits them.
    pub const ALL: [Self; 4] = [
        Self::Zshenv,
        Self::EnvironmentD,
        Self::Zprofile,
        Self::Zshrc,
    ];

    /// The fragment bx owns whole for this place.
    #[must_use]
    pub const fn fragment(self) -> &'static str {
        match self {
            Self::Zshenv => "~/.local/share/bx/zshenv.zsh",
            Self::EnvironmentD => ENVIRONMENT_D,
            Self::Zprofile => "~/.local/share/bx/zprofile.zsh",
            Self::Zshrc => "~/.local/share/bx/zshrc.zsh",
        }
    }

    /// The user's startup file that sources the fragment, for a shell place.
    ///
    /// `None` for `environment.d`, which systemd reads by itself.
    #[must_use]
    pub const fn startup_file(self) -> Option<&'static str> {
        match self {
            Self::Zshenv => Some("~/.zshenv"),
            Self::Zprofile => Some("~/.zprofile"),
            Self::Zshrc => Some("~/.zshrc"),
            Self::EnvironmentD => None,
        }
    }

    /// The syntax the fragment is written in.
    #[must_use]
    pub const fn syntax(self) -> Syntax {
        match self {
            Self::EnvironmentD => Syntax::EnvironmentD,
            Self::Zshenv | Self::Zprofile | Self::Zshrc => Syntax::Zsh,
        }
    }
}

/// The syntax an environment fragment is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Syntax {
    /// `export NAME=VALUE`, sourced by zsh.
    Zsh,
    /// `NAME=VALUE`, read by systemd's `environment.d`, where every line is
    /// exported.
    EnvironmentD,
}

/// An environment fragment: the variables one place holds, substituted and in
/// declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// The syntax it is written in.
    pub syntax: Syntax,
    /// `(name, value)`, each value already substituted.
    pub vars: Vec<(String, String)>,
}

/// The line every fragment opens with. Fixed, so the fragment's bytes are a
/// function of its variables alone.
const HEADER: &str = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";

impl Fragment {
    /// The fragment's bytes.
    ///
    /// Each value is written with every `:`-separated entry that opens with
    /// `~` spelled `$HOME` instead, since `environment.d` expands no `~` and a
    /// shell expands one only at the start of a word, and bare when every
    /// character is one a bare word holds, double-quoted otherwise.
    #[must_use]
    pub fn render(&self) -> String {
        let export = match self.syntax {
            Syntax::Zsh => "export ",
            Syntax::EnvironmentD => "",
        };
        let mut out = String::from(HEADER);
        for (name, value) in &self.vars {
            out.push_str(export);
            out.push_str(name);
            out.push('=');
            out.push_str(&quoted(&home_spelled(value)));
            out.push('\n');
        }
        out
    }
}

/// `value` with every `:`-separated entry that is `~` or opens with `~/`
/// spelled with `$HOME`.
fn home_spelled(value: &str) -> String {
    value
        .split(':')
        .map(|entry| match entry.strip_prefix('~') {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("$HOME{rest}"),
            _ => entry.to_string(),
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// `value` bare when every character is one a bare word holds in both
/// syntaxes, and in double quotes otherwise.
fn quoted(value: &str) -> String {
    let bare = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./,:@%+-${}".contains(c));
    if bare {
        value.to_string()
    } else {
        format!("\"{value}\"")
    }
}

/// The line a fixed region carries: source `fragment` when it is readable.
///
/// Sets nothing and reads no variable, so it is generated shell content that is
/// not an environment fragment, and carries no assignment at all.
#[must_use]
pub fn source_line(fragment: &Portable) -> String {
    let path = fragment.as_str();
    format!("[[ -r {path} ]] && source {path}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use std::path::PathBuf;

    fn home() -> PathBuf {
        PathBuf::from("/var/home/example")
    }

    fn parse(text: &str) -> Result<Vec<EnvDecl>, String> {
        parse_str(text, Path::new("/repo/bx.toml"), &home())
            .map(|config| config.envs)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn an_env_entry_parses_every_key() {
        let envs = parse(
            "[[env]]\nname = \"SCCACHE_DIR\"\nvalue = \"{{scratch}}/sccache\"\n\
             kind = \"environment\"\nenabled = false\n",
        )
        .expect("parses");
        assert_eq!(
            envs,
            vec![EnvDecl {
                name: "SCCACHE_DIR".to_string(),
                value: "{{scratch}}/sccache".to_string(),
                kind: EnvKind::Environment,
                enabled: false,
                origin: Origin {
                    file: PathBuf::from("/repo/bx.toml"),
                    line: 1,
                },
            }]
        );
    }

    #[test]
    fn every_kind_is_spelled_and_lands_where_its_visibility_needs() {
        for (spelling, kind, places) in [
            (
                "environment",
                EnvKind::Environment,
                &[Place::Zshenv, Place::EnvironmentD][..],
            ),
            ("gui", EnvKind::Gui, &[Place::EnvironmentD][..]),
            ("login", EnvKind::Login, &[Place::Zprofile][..]),
            ("interactive", EnvKind::Interactive, &[Place::Zshrc][..]),
        ] {
            assert_eq!(EnvKind::parse(spelling), Some(kind));
            assert_eq!(kind.places(), places, "{spelling}");
        }
        assert_eq!(EnvKind::parse("Environment"), None);
    }

    #[test]
    fn a_malformed_entry_is_refused_naming_its_key() {
        for (body, needle) in [
            ("value = \"x\"\nkind = \"gui\"\n", "`name`"),
            ("name = \"X\"\nkind = \"gui\"\n", "`value`"),
            ("name = \"X\"\nvalue = \"x\"\n", "`kind`"),
            (
                "name = \"X\"\nvalue = \"x\"\nkind = \"shell\"\n",
                "\"environment\", \"gui\", \"login\", \"interactive\"",
            ),
            (
                "name = \"1X\"\nvalue = \"x\"\nkind = \"gui\"\n",
                "not an environment variable name",
            ),
            (
                "name = \"A-B\"\nvalue = \"x\"\nkind = \"gui\"\n",
                "not an environment variable name",
            ),
            (
                "name = \"X\"\nvalue = \"a\\nexport B=c\"\nkind = \"gui\"\n",
                "control character",
            ),
            (
                "name = \"X\"\nvalue = \"a\\\"b\"\nkind = \"gui\"\n",
                "control character",
            ),
            (
                "name = \"X\"\nvalue = \"x\"\nkind = \"gui\"\nshell = \"zsh\"\n",
                "shell",
            ),
        ] {
            let err = parse(&format!("[[env]]\n{body}")).expect_err(body);
            assert!(err.contains(needle), "{body}: {err}");
        }
    }

    #[test]
    fn a_name_is_letters_digits_and_underscores_not_opening_with_a_digit() {
        for good in ["X", "_x", "SCCACHE_DIR", "a1"] {
            assert!(is_variable_name(good), "{good}");
        }
        for bad in ["", "1a", "A-B", "A B", "Ä"] {
            assert!(!is_variable_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_value_that_cannot_sit_on_one_line_is_unwritable() {
        assert_eq!(unwritable("/a/b c:$HOME"), None);
        for bad in ["a\nb", "a\tb", "a\"b", "a\\b", "a`b`", "\u{7f}"] {
            assert!(unwritable(bad).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn a_fragment_renders_each_syntax_deterministically() {
        let vars = vec![
            ("CARGO_HOME".to_string(), "~/.cargo".to_string()),
            ("PATH".to_string(), "~/bin:~:$PATH:/x~/y".to_string()),
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
            ("EDITOR".to_string(), "code --wait".to_string()),
            ("EMPTY".to_string(), String::new()),
            ("USER_ISH".to_string(), "~other".to_string()),
        ];
        let zsh = Fragment {
            syntax: Syntax::Zsh,
            vars: vars.clone(),
        };
        assert_eq!(
            zsh.render(),
            format!(
                "{HEADER}export CARGO_HOME=$HOME/.cargo\n\
                 export PATH=\"$HOME/bin:$HOME:$PATH:/x~/y\"\n\
                 export LANG=en_US.UTF-8\n\
                 export EDITOR=\"code --wait\"\n\
                 export EMPTY=\n\
                 export USER_ISH=\"~other\"\n"
            )
        );
        let env_d = Fragment {
            syntax: Syntax::EnvironmentD,
            vars,
        };
        assert!(env_d.render().contains("\nCARGO_HOME=$HOME/.cargo\n"));
        assert!(!env_d.render().contains("export"));
        assert_eq!(zsh.render(), zsh.render());
    }

    #[test]
    fn every_place_names_its_fragment_and_its_startup_file() {
        for place in Place::ALL {
            let fragment = place.fragment();
            match place.startup_file() {
                Some(file) => {
                    assert!(fragment.starts_with(FRAGMENT_DIR), "{place:?}");
                    assert_eq!(place.syntax(), Syntax::Zsh);
                    assert!(file.starts_with("~/.z"), "{file}");
                }
                None => {
                    assert_eq!(fragment, ENVIRONMENT_D);
                    assert_eq!(place.syntax(), Syntax::EnvironmentD);
                }
            }
            Portable::parse_in(fragment, &home()).expect("a portable fragment path");
        }
    }

    #[test]
    fn the_source_line_tests_then_sources_the_one_fragment() {
        let fragment = Portable::parse_in(Place::Zshrc.fragment(), &home()).expect("portable");
        assert_eq!(
            source_line(&fragment),
            "[[ -r ~/.local/share/bx/zshrc.zsh ]] && source ~/.local/share/bx/zshrc.zsh\n"
        );
    }
}
