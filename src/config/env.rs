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
//! when    = "has:sccache"                  # optional; see below
//! shells  = ["zsh"]                        # optional; default every shell
//! ```
//!
//! `shells` keeps the variable to the shells it lists
//! ([`crate::shell::Shells`]). `environment.d` is no shell's: every program
//! the session starts inherits what it sets, whichever shell that is. So a
//! variable that lands there — `kind = "environment"` or `"gui"` — may not
//! carry `shells`; keep one shell's variable out of the other with
//! `kind = "login"` or `"interactive"`.
//!
//! `when` gates the variable on one condition from the closed set
//! [`super::when`] defines. A runtime condition wraps the variable's line in a
//! guarded block; `has:TOOL` is decided while `plan` renders the fragment. A
//! variable that lands in `environment.d` — `kind = "environment"` or `"gui"` —
//! may be gated only on `has:TOOL`, since `environment.d` runs no test.
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
//! That table is zsh's, and Linux's: on macOS `environment.d` is a
//! LaunchAgent, as below. bash reads every `environment`, `login` and
//! `interactive` variable from its own generated interactive file, in that
//! order, a `login` one only in a login shell; see [`crate::shell::bash`].
//!
//! `environment.d` is a fragment bx owns whole,
//! [`ENVIRONMENT_D`]. macOS has no `environment.d`: there the same
//! [`Place::EnvironmentD`] is a LaunchAgent bx owns whole, [`LAUNCH_AGENT`],
//! which runs `launchctl setenv` once at login with every variable the
//! fragment would hold ([`LaunchAgent`]). The declaration is the same on
//! both; only the file differs, and what this module says of `environment.d`
//! holds of the LaunchAgent too. `apply` writes it and loads nothing, so it
//! takes effect at the next login, and `bx doctor` says when launchd has not
//! loaded it ([`crate::doctor::launchd`]). Every shell startup file is the user's, so bx never
//! writes a declaration into one: it attaches a **fixed three-line region**
//! whose one line sources a fragment bx owns whole, beneath
//! [`FRAGMENT_DIR`]. The region's bytes are the same for every declaration and
//! every account, so an edit the user makes anywhere else in the file is never
//! bx's business, and a change of declaration rewrites only bx's own file.
//!
//! The `zshenv` fragment also carries the `[path]` entries, after its
//! variables, so a `${NAME}` in one reads a variable the file has already
//! exported; see [`super::path`].
//!
//! Every fragment but the interactive file is an environment fragment in the
//! guard's grammar, and the plan judges it against the declared roots before it
//! is written. The interactive file, `zshrc.zsh`, is assembled from phases, and
//! the plan judges it by its `env` phase alone: that phase is its one
//! environment fragment, and every other phase holds lines that set nothing.
//! A fragment for which a declared value has no usable answer is held back on
//! its own — the other fragments, and every other target, still resolve.

use std::path::{Path, PathBuf};

use toml_edit::Table;

use super::path::{self, PathEntry};
use super::shells::{Shell, Shells};
use super::when::{self, Decide, Gate, When};
use super::{Ctx, Error, Origin};
use crate::lexical::is_variable_name;
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[env]]";

/// Every key an `[[env]]` entry may carry.
const KEYS: [&str; 6] = ["name", "value", "kind", "enabled", "when", "shells"];

/// The directory bx's generated shell fragments live in.
pub const FRAGMENT_DIR: &str = "~/.local/share/bx";

/// The `environment.d` fragment every `environment` and `gui` variable lands
/// in. `50-` puts it in the middle of the order systemd reads the directory
/// in, so a fragment the user numbers lower or higher still decides whether it
/// comes before or after bx's.
pub const ENVIRONMENT_D: &str = "~/.config/environment.d/50-bx.conf";

/// The label launchd knows bx's LaunchAgent by. A reverse-DNS name in bx's own
/// namespace, so it names no account and no other program's agent.
pub const LAUNCH_AGENT_LABEL: &str = "dev.bx.environment";

/// The LaunchAgent every `environment` and `gui` variable lands in on macOS,
/// in place of [`ENVIRONMENT_D`]. Named by its label, as launchd expects.
pub const LAUNCH_AGENT: &str = "~/Library/LaunchAgents/dev.bx.environment.plist";

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
    /// The one condition it is gated on, if any.
    pub when: Option<When>,
    /// The shells whose startup files it lands in. `environment.d` is no
    /// shell's, so a variable landing there lands there whatever this says.
    pub shells: Shells,
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

    let when = when::at(&ctx, table)?;
    if let Some(runtime) = when.as_ref().and_then(When::runtime)
        && kind.places().contains(&Place::EnvironmentD)
    {
        let raw = runtime.to_string();
        return Err(ctx.bad(
            table,
            "when",
            format!(
                "`{name}`: `when` holds {raw:?}, a test the shell runs, and a variable of \
                 `kind = {raw_kind:?}` lands in `environment.d`, which runs none; gate it only \
                 on conditions bx decides — `has:`, `os:`, `arch:`, `host:`, `user:` or \
                 `distro:` — or give it `kind = \"login\"` or `\"interactive\"`"
            ),
        ));
    }

    let shells = ctx.shells_at(table, &format!("`{name}`"))?;
    if kind.places().contains(&Place::EnvironmentD) && table.get(Shells::KEY).is_some() {
        return Err(ctx.bad(
            table,
            Shells::KEY,
            format!(
                "`{name}`: a variable of `kind = {raw_kind:?}` lands in `environment.d`, which \
                 is no shell's: every program the session starts inherits it, whichever shell \
                 it is, so it cannot be kept to one; drop `shells`, or give it \
                 `kind = \"login\"` or `\"interactive\"`"
            ),
        ));
    }

    Ok(EnvDecl {
        name,
        value,
        kind,
        when,
        shells,
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
    /// The `environment.d` fragment, read by the systemd user manager; on
    /// macOS, the LaunchAgent [`LAUNCH_AGENT`] in its place.
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

/// One variable a fragment holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Var {
    /// The variable's name.
    pub name: String,
    /// Its value, already substituted.
    pub value: String,
    /// The condition it is gated on, if any.
    pub when: Option<When>,
}

/// An environment fragment: the variables one place holds, substituted and in
/// declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// The syntax it is written in.
    pub syntax: Syntax,
    /// Each variable, value already substituted.
    pub vars: Vec<Var>,
    /// The `[path]` entries, written after every variable in zsh's words.
    /// Only the `zshenv` fragment holds any, and only those that reach zsh;
    /// see [`super::path`] — and on macOS the `zprofile` fragment too, which
    /// writes them again after `path_helper` has reordered `PATH`
    /// ([`crate::shell::placement::Platform`]).
    pub path: Vec<PathEntry>,
    /// The variables a file the shell reads before this one has already
    /// exported, which this fragment's lines may refer to but never writes:
    /// the `zshenv` fragment's, for the `zprofile` fragment that repeats the
    /// `[path]` entries on macOS. Not part of the bytes; the guard judges the
    /// fragment as if they came first ([`Fragment::inherited_render`]).
    pub inherited: Vec<Var>,
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
    ///
    /// A gated variable is decided through [`When::gate`]: `decide` answers
    /// whether a `has:TOOL` tool is usable and what the machine's facts are,
    /// so the line is written plainly or left out, and a runtime condition
    /// writes the line alone inside a block its test guards — never inlined
    /// beside the assignment, so the guard reads the assignment as the
    /// statement it is. The bytes are a function of the variables and
    /// `decide`'s answers alone.
    #[must_use]
    pub fn render(&self, decide: &dyn Decide) -> String {
        let export = match self.syntax {
            Syntax::Zsh => "export ",
            Syntax::EnvironmentD => "",
        };
        let mut out = String::from(HEADER);
        for var in &self.vars {
            let line = format!("{export}{}", assignment(var));
            match var.when.as_ref().map(|when| when.gate(decide)) {
                None | Some(Gate::Always) => out.push_str(&line),
                Some(Gate::Never) => {}
                Some(Gate::Test(test)) => {
                    out.push_str(&when::opener(&test));
                    out.push_str("\n  ");
                    out.push_str(&line);
                    out.push_str(when::CLOSER);
                    out.push('\n');
                }
            }
        }
        out.push_str(&path::render(&self.path, Shell::Zsh));
        out
    }

    /// The bytes of the fragment the [`Fragment::inherited`] variables come
    /// from, as far as they go — what the shell has read before this one —
    /// or an empty string when there are none. What the guard reads ahead of
    /// this fragment's own bytes, so a `[path]` entry that refers to one of
    /// them is judged against the value it expands to.
    #[must_use]
    pub fn inherited_render(&self, decide: &dyn Decide) -> String {
        if self.inherited.is_empty() {
            return String::new();
        }
        Self {
            syntax: self.syntax,
            vars: self.inherited.clone(),
            path: Vec::new(),
            inherited: Vec::new(),
        }
        .render(decide)
    }
}

/// The LaunchAgent [`Place::EnvironmentD`] is on macOS: a property list
/// launchd runs once at login, setting every variable the place holds for
/// every program the session starts.
///
/// It holds the place's [`Fragment`], in `environment.d`'s syntax, and the
/// home it is written under. The plan judges the fragment exactly as it
/// judges `environment.d`'s, and the property list hands launchd each value
/// the guard expanded while judging it ([`crate::env_guard::expand_exported`]):
/// `launchctl setenv` expands nothing, so a `~`, a `$HOME` or a reference to
/// a variable named earlier is written as what it stands for. A value the
/// guard cannot expand is refused before the file is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchAgent {
    /// The variables, as the `environment.d` fragment would hold them.
    pub env: Fragment,
    /// The home `~` and `$HOME` stand for.
    pub home: PathBuf,
}

/// The property list's opening, up to its program's arguments. Fixed, so the
/// file's bytes are a function of the variables, their values and the home
/// alone: no timestamp, nothing read from the machine.
const PLIST_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<!-- Generated by bx from [[env]]. Edit the config repo, not this file. -->\n\
<plist version=\"1.0\">\n<dict>\n\
\t<key>Label</key>\n\t<string>dev.bx.environment</string>\n\
\t<key>ProgramArguments</key>\n\t<array>\n";

/// The property list's close, after its program's arguments: run once, when
/// the agent is loaded at login, and never again.
const PLIST_TAIL: &str = "\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n</dict>\n</plist>\n";

impl LaunchAgent {
    /// The property list's bytes.
    ///
    /// The one program is `/bin/launchctl setenv`, given every variable as a
    /// name and its expanded value, sorted by name so the bytes do not
    /// depend on the order the layers declared them in; or `/usr/bin/true`
    /// when no variable is left, since `launchctl setenv` with no pair is an
    /// error. No shell reads the file, so nothing in it is a statement; a
    /// value is escaped for XML and nothing else.
    #[must_use]
    pub fn render(&self, decide: &dyn Decide) -> String {
        let roots = crate::env_guard::RootSet::new(&self.home, &[]);
        let mut pairs: Vec<(String, String)> =
            crate::env_guard::expand_exported(&self.env.render(decide), &roots)
                .into_iter()
                // A value that does not expand is refused by the guard before
                // a byte is written, so what stands in for it is never read.
                .map(|expanded| (expanded.name, expanded.value.unwrap_or_default()))
                .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let mut words = Vec::new();
        if pairs.is_empty() {
            words.push("/usr/bin/true".to_string());
        } else {
            words.push("/bin/launchctl".to_string());
            words.push("setenv".to_string());
            for (name, value) in pairs {
                words.push(name);
                words.push(value);
            }
        }
        let mut out = String::from(PLIST_HEAD);
        for word in words {
            out.push_str("\t\t<string>");
            out.push_str(&xml_escaped(&word));
            out.push_str("</string>\n");
        }
        out.push_str(PLIST_TAIL);
        out
    }
}

/// `text` with every character XML gives a meaning in character data
/// escaped.
fn xml_escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `NAME=VALUE` and a newline for `var`, its value spelled and quoted as
/// [`Fragment::render`] writes it: the words zsh and bash read alike.
#[must_use]
pub fn assignment(var: &Var) -> String {
    format!("{}={}\n", var.name, quoted(&home_spelled(&var.value)))
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

// Only tests build a `Var` by hand, so this sits last, beside them: the source
// scans that read everything above the first `#[cfg(test)]` as this module's
// shipped code still read all of it.
#[cfg(test)]
impl Var {
    /// A variable written unconditionally.
    #[must_use]
    pub fn always(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            when: None,
        }
    }
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
                when: None,
                shells: Shells::EVERY,
                enabled: false,
                origin: Origin {
                    file: PathBuf::from("/repo/bx.toml"),
                    line: 1,
                },
            }]
        );
    }

    #[test]
    fn shells_restricts_a_variable_and_an_unknown_shell_fails_the_load() {
        let envs = parse(
            "[[env]]\nname = \"A\"\nvalue = \"1\"\nkind = \"interactive\"\nshells = [\"zsh\"]\n\
             [[env]]\nname = \"B\"\nvalue = \"1\"\nkind = \"login\"\nshells = [\"bash\", \"zsh\"]\n",
        )
        .expect("parses");
        assert_eq!(envs[0].shells, Shells::only(Shell::Zsh));
        assert_eq!(envs[1].shells, Shells::EVERY);
        for (shells, expected) in [
            ("[\"fish\"]", "\"fish\" is not a shell bx generates for"),
            ("[]", "`shells` names no shell"),
        ] {
            let err = parse(&format!(
                "[[env]]\nname = \"A\"\nvalue = \"1\"\nkind = \"interactive\"\nshells = {shells}\n"
            ))
            .expect_err("refused");
            assert!(err.contains(expected), "{err}");
            assert!(err.contains("`A`"), "{err}");
        }
        // A variable that lands in `environment.d` reaches every shell the
        // session starts, so it cannot be kept to one.
        for kind in ["gui", "environment"] {
            let err = parse(&format!(
                "[[env]]\nname = \"A\"\nvalue = \"1\"\nkind = \"{kind}\"\nshells = [\"bash\"]\n"
            ))
            .expect_err("refused");
            assert!(
                err.contains(&format!("`kind = \"{kind}\"` lands in `environment.d`")),
                "{err}"
            );
            assert!(err.contains("drop `shells`"), "{err}");
        }
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
            Var::always("CARGO_HOME", "~/.cargo"),
            Var::always("PATH", "~/bin:~:$PATH:/x~/y"),
            Var::always("LANG", "en_US.UTF-8"),
            Var::always("EDITOR", "code --wait"),
            Var::always("EMPTY", ""),
            Var::always("USER_ISH", "~other"),
        ];
        let zsh = Fragment {
            syntax: Syntax::Zsh,
            vars: vars.clone(),
            path: Vec::new(),
            inherited: Vec::new(),
        };
        let render = |fragment: &Fragment| {
            fragment.render(&when::tools(&|_| unreachable!("nothing is gated")))
        };
        assert_eq!(
            render(&zsh),
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
            path: Vec::new(),
            inherited: Vec::new(),
        };
        assert!(render(&env_d).contains("\nCARGO_HOME=$HOME/.cargo\n"));
        assert!(!render(&env_d).contains("export"));
        assert_eq!(render(&zsh), render(&zsh));
    }

    #[test]
    fn the_inherited_render_is_the_earlier_fragment_s_variables_alone() {
        let decide = when::tools(&|_| unreachable!("nothing is gated"));
        let own = vec![Var::always("PAGER", "less")];
        let none = Fragment {
            syntax: Syntax::Zsh,
            vars: own.clone(),
            path: Vec::new(),
            inherited: Vec::new(),
        };
        assert_eq!(none.inherited_render(&decide), "");
        let after = Fragment {
            inherited: vec![Var::always("CARGO_HOME", "~/.cargo")],
            ..none
        };
        // What the earlier fragment wrote, under its header, and none of
        // this fragment's own lines.
        assert_eq!(
            after.inherited_render(&decide),
            format!("{HEADER}export CARGO_HOME=$HOME/.cargo\n")
        );
    }

    fn gated(name: &str, value: &str, when: &str) -> Var {
        Var {
            name: name.to_string(),
            value: value.to_string(),
            when: Some(When::parse(when).expect(when)),
        }
    }

    #[test]
    fn a_gated_variable_renders_as_a_guarded_block_or_by_what_bx_found() {
        let zsh = Fragment {
            syntax: Syntax::Zsh,
            vars: vec![
                Var::always("LANG", "C.UTF-8"),
                gated("EDITOR", "nvim", "interactive"),
                gated("PAGER", "less", "login"),
                gated("BROWSER", "w3m", "ssh"),
                gated("COLORTERM", "truecolor", "env:TMUX"),
                gated("TERM", "xterm-256color", "env:TERM_PROGRAM=WezTerm"),
                gated("RUSTC_WRAPPER", "sccache", "has:sccache"),
                gated("VISUAL", "hx", "has:hx"),
            ],
            path: Vec::new(),
            inherited: Vec::new(),
        };
        let asked = std::cell::RefCell::new(Vec::new());
        let present = |tool: &str| {
            asked.borrow_mut().push(tool.to_string());
            tool == "sccache"
        };
        assert_eq!(
            zsh.render(&when::tools(&present)),
            format!(
                "{HEADER}export LANG=C.UTF-8\n\
                 if [[ -o interactive ]]; then\n  export EDITOR=nvim\nfi\n\
                 if [[ -o login ]]; then\n  export PAGER=less\nfi\n\
                 if [[ -n ${{SSH_CONNECTION-}} ]]; then\n  export BROWSER=w3m\nfi\n\
                 if [[ -n ${{TMUX+x}} ]]; then\n  export COLORTERM=truecolor\nfi\n\
                 if [[ ${{TERM_PROGRAM-}} == \"WezTerm\" ]]; then\n  \
                 export TERM=xterm-256color\nfi\n\
                 export RUSTC_WRAPPER=sccache\n"
            )
        );
        // Each tool is asked about once per render, and only a `has:` asks.
        assert_eq!(*asked.borrow(), ["sccache", "hx"]);
        let rendered = zsh.render(&when::tools(&present));
        assert!(!rendered.contains("command -v"), "{rendered}");
        assert_eq!(
            rendered,
            zsh.render(&when::tools(&present)),
            "byte-identical"
        );
    }

    #[test]
    fn a_variable_gated_on_the_machine_is_written_or_left_out_by_its_facts() {
        let fragment = |syntax| Fragment {
            syntax,
            vars: vec![
                gated("A", "1", "os:linux"),
                gated("B", "2", "os:macos"),
                gated("C", "3", "host:box"),
                Var {
                    name: "D".to_string(),
                    value: "4".to_string(),
                    when: Some(When::parse_all(&["user:me", "ssh"]).expect("all of")),
                },
            ],
            path: Vec::new(),
            inherited: Vec::new(),
        };
        let machine = |host: &str| when::Machine {
            os: "linux".to_string(),
            host: Some(host.to_string()),
            user: Some("me".to_string()),
            ..when::Machine::default()
        };
        let render = |fragment: &Fragment, machine: &when::Machine| {
            fragment.render(&when::Facts {
                machine,
                present: &|_| unreachable!(),
            })
        };
        let zsh = fragment(Syntax::Zsh);
        let here = machine("BOX");
        assert_eq!(
            render(&zsh, &here),
            format!(
                "{HEADER}export A=1\nexport C=3\n\
                 if [[ -n ${{SSH_CONNECTION-}} ]]; then\n  export D=4\nfi\n"
            )
        );
        assert_eq!(render(&zsh, &here), render(&zsh, &here), "byte-identical");
        // A renamed host takes its line out, and nothing else.
        assert_eq!(
            render(&zsh, &machine("other")),
            format!(
                "{HEADER}export A=1\n\
                 if [[ -n ${{SSH_CONNECTION-}} ]]; then\n  export D=4\nfi\n"
            )
        );
        let env_d = Fragment {
            vars: zsh.vars[..3].to_vec(),
            ..fragment(Syntax::EnvironmentD)
        };
        assert_eq!(render(&env_d, &here), format!("{HEADER}A=1\nC=3\n"));
    }

    #[test]
    fn a_when_parses_and_an_unknown_spelling_fails_the_load() {
        let envs = parse(
            "[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n\
             when = \"ssh\"\n\
             [[env]]\nname = \"RUSTC_WRAPPER\"\nvalue = \"sccache\"\nkind = \"gui\"\n\
             when = \"has:sccache\"\n",
        )
        .expect("parses");
        assert_eq!(envs[0].when, Some(When::Ssh));
        assert_eq!(envs[1].when, Some(When::Has("sccache".to_string())));

        let envs = parse(
            "[[env]]\nname = \"X\"\nvalue = \"x\"\nkind = \"login\"\n\
             when = [\"os:macos\", \"arch:aarch64\"]\n",
        )
        .expect("parses");
        assert_eq!(
            envs[0].when,
            Some(When::All(vec![When::Os("macos"), When::Arch("aarch64")]))
        );

        for (when, needle) in [
            ("\"tty\"", "`when` must be one of"),
            ("\"env:1X\"", "not an environment variable name"),
            ("true", "a string or an array of strings"),
            ("[\"ssh\", 1]", "a string or an array of strings"),
            ("[]", "lists no condition"),
            ("[\"ssh\", \"login\"]", "at most one"),
            ("[\"os:windows\"]", "`os:` names one of"),
        ] {
            let body =
                format!("[[env]]\nname = \"X\"\nvalue = \"x\"\nkind = \"login\"\nwhen = {when}\n");
            let err = parse(&body).expect_err(&body);
            assert!(err.contains(needle), "{body}: {err}");
        }
    }

    #[test]
    fn a_runtime_when_on_a_variable_environment_d_holds_fails_the_load() {
        for kind in ["environment", "gui"] {
            for when in [
                "\"interactive\"",
                "\"login\"",
                "\"ssh\"",
                "\"env:TMUX\"",
                "\"env:TERM_PROGRAM=WezTerm\"",
                "[\"os:linux\", \"ssh\"]",
            ] {
                let body = format!(
                    "[[env]]\nname = \"X\"\nvalue = \"x\"\nkind = \"{kind}\"\nwhen = {when}\n"
                );
                let err = parse(&body).expect_err(&body);
                assert!(err.contains("`environment.d`"), "{body}: {err}");
                assert!(err.contains("`has:`, `os:`"), "{body}: {err}");
            }
            // What bx decides is allowed there: it renders no test.
            for when in [
                "\"os:linux\"",
                "\"arch:x86_64\"",
                "\"host:box\"",
                "\"user:me\"",
                "\"distro:fedora\"",
                "[\"os:linux\", \"has:sccache\"]",
            ] {
                let body = format!(
                    "[[env]]\nname = \"X\"\nvalue = \"x\"\nkind = \"{kind}\"\nwhen = {when}\n"
                );
                parse(&body).expect(&body);
            }
        }
        for kind in ["login", "interactive"] {
            let body = format!(
                "[[env]]\nname = \"X\"\nvalue = \"x\"\nkind = \"{kind}\"\nwhen = \"ssh\"\n"
            );
            parse(&body).expect(&body);
        }
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

    fn agent(vars: Vec<Var>) -> LaunchAgent {
        LaunchAgent {
            env: Fragment {
                syntax: Syntax::EnvironmentD,
                vars,
                path: Vec::new(),
                inherited: Vec::new(),
            },
            home: home(),
        }
    }

    #[test]
    fn the_launch_agent_is_named_and_labelled_alike() {
        let file = Path::new(LAUNCH_AGENT);
        assert_eq!(
            file.file_stem().and_then(|s| s.to_str()),
            Some(LAUNCH_AGENT_LABEL)
        );
        assert_eq!(file.extension().and_then(|s| s.to_str()), Some("plist"));
        assert!(LAUNCH_AGENT.starts_with("~/Library/LaunchAgents/"));
        assert!(
            PLIST_HEAD.contains(&format!(
                "<key>Label</key>\n\t<string>{LAUNCH_AGENT_LABEL}</string>\n"
            )),
            "{PLIST_HEAD}"
        );
        Portable::parse_in(LAUNCH_AGENT, &home()).expect("a portable path");
    }

    #[test]
    fn the_launch_agent_hands_launchd_every_value_expanded_and_sorted() {
        let decide = when::tools(&|tool| tool == "sccache");
        let launch = agent(vec![
            Var::always("PAGER", "less -R"),
            Var::always("CARGO_HOME", "~/.cargo"),
            Var::always("RUSTUP_HOME", "$HOME/.rustup"),
            Var::always("CARGO_TARGET_DIR", "${CARGO_HOME}/target"),
            Var::always("LESS", "-F<&>"),
            gated("RUSTC_WRAPPER", "sccache", "has:sccache"),
            gated("VISUAL", "hx", "has:hx"),
        ]);
        let body = launch.render(&decide);
        assert_eq!(
            body,
            format!(
                "{PLIST_HEAD}\
                 \t\t<string>/bin/launchctl</string>\n\
                 \t\t<string>setenv</string>\n\
                 \t\t<string>CARGO_HOME</string>\n\
                 \t\t<string>/var/home/example/.cargo</string>\n\
                 \t\t<string>CARGO_TARGET_DIR</string>\n\
                 \t\t<string>/var/home/example/.cargo/target</string>\n\
                 \t\t<string>LESS</string>\n\
                 \t\t<string>-F&lt;&amp;&gt;</string>\n\
                 \t\t<string>PAGER</string>\n\
                 \t\t<string>less -R</string>\n\
                 \t\t<string>RUSTC_WRAPPER</string>\n\
                 \t\t<string>sccache</string>\n\
                 \t\t<string>RUSTUP_HOME</string>\n\
                 \t\t<string>/var/home/example/.rustup</string>\n\
                 {PLIST_TAIL}"
            )
        );
        // A function of the variables, the home and what bx found alone.
        assert_eq!(body, launch.render(&decide), "byte-identical");
        let mut reordered = launch.clone();
        reordered.env.vars.reverse();
        // Reversed, the reference comes before what it names, so leave it out.
        reordered.env.vars.retain(|v| v.name != "CARGO_TARGET_DIR");
        let mut without = launch.clone();
        without.env.vars.retain(|v| v.name != "CARGO_TARGET_DIR");
        assert_eq!(reordered.render(&decide), without.render(&decide));
        // No shell reads it: nothing in it is a statement, and its one
        // program is `launchctl setenv`.
        assert!(!body.contains('$') && !body.contains('~'), "{body}");
        assert_eq!(body.matches("<string>/").count(), 4, "{body}");
    }

    #[test]
    fn an_empty_launch_agent_runs_a_program_that_sets_nothing() {
        let decide = when::tools(&|_| false);
        for launch in [
            agent(Vec::new()),
            agent(vec![gated("RUSTC_WRAPPER", "sccache", "has:sccache")]),
        ] {
            assert_eq!(
                launch.render(&decide),
                format!("{PLIST_HEAD}\t\t<string>/usr/bin/true</string>\n{PLIST_TAIL}")
            );
        }
    }
}
