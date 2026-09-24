//! Declared shell plugins: a file sourced, if it is readable, in the `plugins`
//! phase — or, for at most one of them, in the terminal slot.
//!
//! # The `[[plugin]]` schema
//!
//! ```toml
//! [[plugin]]
//! name     = "zsh-syntax-highlighting"                                        # required; the natural key
//! source   = "~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh"   # required
//! terminal = true                                                             # default false
//! enabled  = true                                                             # default true
//! ```
//!
//! A plugin is a file some other tool installs; bx never reads, copies or
//! manages it, and only ever tests that it is readable before sourcing it, so a
//! plugin package that is not installed yet costs nothing but itself and never
//! breaks the shell.
//!
//! `source` is a path that opens with `~/` or `/` and holds only characters a
//! bare shell word holds, so it is written unquoted — which is what lets zsh
//! expand the `~` — and no character in it can end the test or start a second
//! command.
//!
//! `terminal = true` claims the single slot that loads after everything else.
//! At most one enabled plugin may claim it: [`check_terminal`] refuses a second
//! at load, naming both.
//!
//! A plugin takes no `when` key, unlike `[[env]]`: an unknown key is refused,
//! so adding one later breaks no configuration written today. The readability
//! test already gates each plugin on being installed, a `has:TOOL` gate is
//! decided by the loader wiring this module does not yet have, and a
//! conditional terminal claimant would need [`check_terminal`] to reason about
//! which conditions can hold together.

use std::path::Path;

use toml_edit::Table;

use super::{Assembly, Phase};
use crate::config::{Ctx, Error, Origin};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[plugin]]";

/// Every key a `[[plugin]]` entry may carry.
const KEYS: [&str; 4] = ["name", "source", "terminal", "enabled"];

/// One `[[plugin]]` entry, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDecl {
    /// The plugin's name, its natural key.
    pub name: String,
    /// The file sourced, as written.
    pub source: String,
    /// Whether it claims the terminal slot.
    pub terminal: bool,
    /// `false` in any layer removes the plugin from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

impl PluginDecl {
    /// The phase the plugin loads in.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        if self.terminal {
            Phase::Terminal
        } else {
            Phase::Plugins
        }
    }

    /// The one line that sources the plugin when it is readable.
    #[must_use]
    pub fn line(&self) -> String {
        let path = &self.source;
        format!("[[ -r {path} ]] && source {path}\n")
    }
}

/// Parse one `[[plugin]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_plugin(table: &Table, file: &Path, text: &str) -> Result<PluginDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not a plugin name: a name is non-empty and on one line"),
        ));
    }

    let source = ctx.required_str(table, "source")?.to_string();
    if let Some(problem) = unsourceable(&source) {
        return Err(ctx.bad(table, "source", format!("`{name}`: {problem}")));
    }

    Ok(PluginDecl {
        name,
        source,
        terminal: ctx.bool_at(table, "terminal")?.unwrap_or(false),
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Why `source` cannot be written bare into the plugin's line, or `None` when
/// it can.
fn unsourceable(source: &str) -> Option<String> {
    if !(source.starts_with("~/") || source.starts_with('/')) {
        return Some(format!(
            "`source = {source:?}` must open with `~/` or `/`: a relative path would be \
             read from whatever directory the shell starts in"
        ));
    }
    // The leading `~` is the one zsh expands; anywhere else a `~` is a glob
    // operator under `extended_glob`, so it is refused with the rest.
    let rest = source.strip_prefix('~').unwrap_or(source);
    rest.chars()
        .find(|c| !(c.is_ascii_alphanumeric() || "_./,:@%+-".contains(*c)))
        .map(|c| {
            format!(
                "`source = {source:?}` is written unquoted, so after a leading `~` it may hold \
                 only ASCII letters, digits and `_./,:@%+-`; found {c:?}"
            )
        })
}

/// Refuse a second enabled plugin that claims the terminal slot.
///
/// Run once the layers are merged, over the plugins that survived it, so a
/// claim a later layer switched off does not count.
///
/// # Errors
///
/// [`Error::BadValue`] at the second claimant's origin, naming both plugins and
/// where the first was declared.
pub fn check_terminal(plugins: &[PluginDecl]) -> Result<(), Error> {
    let mut claimants = plugins.iter().filter(|p| p.enabled && p.terminal);
    let Some(first) = claimants.next() else {
        return Ok(());
    };
    match claimants.next() {
        None => Ok(()),
        Some(second) => Err(Error::BadValue {
            origin: second.origin.clone(),
            message: format!(
                "plugin `{}` claims the terminal slot, which plugin `{}` already claims at {}; \
                 only one plugin can load after everything else, so set `terminal = false` \
                 on one of them",
                second.name, first.name, first.origin
            ),
        }),
    }
}

/// Add every enabled plugin to `assembly`, in declaration order, each in its
/// phase.
///
/// # Errors
///
/// [`super::Error::TerminalClaimed`] when two enabled plugins claim the
/// terminal slot — which [`check_terminal`] refuses at load, so a caller that
/// ran it never sees this.
pub fn contribute(assembly: &mut Assembly, plugins: &[PluginDecl]) -> Result<(), super::Error> {
    for plugin in plugins.iter().filter(|p| p.enabled) {
        assembly.contribute(plugin.phase(), plugin.name.clone(), plugin.line())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use toml_edit::Document;

    /// Every `[[plugin]]` entry in `text`, parsed.
    fn parse(text: &str) -> Result<Vec<PluginDecl>, String> {
        let doc = Document::parse(text).map_err(|e| format!("{e}"))?;
        let tables = doc
            .get("plugin")
            .and_then(|item| item.as_array_of_tables())
            .ok_or("no [[plugin]]")?;
        tables
            .iter()
            .map(|table| parse_plugin(table, Path::new("/repo/bx.toml"), text))
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }

    fn plugin(name: &str, terminal: bool, line: usize) -> PluginDecl {
        PluginDecl {
            name: name.to_string(),
            source: format!("~/.zsh/{name}/{name}.zsh"),
            terminal,
            enabled: true,
            origin: Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line,
            },
        }
    }

    #[test]
    fn a_plugin_entry_parses_every_key() {
        let plugins = parse(
            "[[plugin]]\nname = \"zsh-syntax-highlighting\"\n\
             source = \"~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh\"\n\
             terminal = true\nenabled = false\n\
             [[plugin]]\nname = \"autosuggest\"\nsource = \"/usr/share/zsh/a.zsh\"\n",
        )
        .expect("parses");
        assert_eq!(
            plugins,
            vec![
                PluginDecl {
                    name: "zsh-syntax-highlighting".to_string(),
                    source: "~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh"
                        .to_string(),
                    terminal: true,
                    enabled: false,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 1,
                    },
                },
                PluginDecl {
                    name: "autosuggest".to_string(),
                    source: "/usr/share/zsh/a.zsh".to_string(),
                    terminal: false,
                    enabled: true,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 6,
                    },
                },
            ]
        );
    }

    #[test]
    fn a_malformed_entry_is_refused_naming_its_key() {
        for (body, needle) in [
            ("source = \"~/a.zsh\"\n", "`name`"),
            ("name = \"a\"\n", "`source`"),
            ("name = \"\"\nsource = \"~/a.zsh\"\n", "not a plugin name"),
            (
                "name = \"a\\nb\"\nsource = \"~/a.zsh\"\n",
                "not a plugin name",
            ),
            ("name = \"a\"\nsource = \"a.zsh\"\n", "must open with"),
            ("name = \"a\"\nsource = \"~a.zsh\"\n", "must open with"),
            ("name = \"a\"\nsource = \"~/a b.zsh\"\n", "found ' '"),
            ("name = \"a\"\nsource = \"~/a;rm.zsh\"\n", "found ';'"),
            ("name = \"a\"\nsource = \"~/$X/a.zsh\"\n", "found '$'"),
            ("name = \"a\"\nsource = \"~/a]].zsh\"\n", "found ']'"),
            (
                "name = \"a\"\nsource = \"~/a.zsh\"\nterminal = \"yes\"\n",
                "a boolean",
            ),
            (
                "name = \"a\"\nsource = \"~/a.zsh\"\nwhen = \"ssh\"\n",
                "unknown key `when`",
            ),
        ] {
            let err = parse(&format!("[[plugin]]\n{body}")).expect_err(body);
            assert!(err.contains(needle), "{body}: {err}");
        }
    }

    #[test]
    fn a_plugin_is_sourced_only_once_it_is_readable() {
        let plain = plugin("zsh-autosuggestions", false, 1);
        assert_eq!(
            plain.line(),
            "[[ -r ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh ]] && \
             source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh\n"
        );
        assert_eq!(plain.phase(), Phase::Plugins);
        assert_eq!(plugin("h", true, 1).phase(), Phase::Terminal);
    }

    #[test]
    fn a_second_terminal_claimant_fails_the_load_naming_both() {
        let plugins = [
            plugin("zsh-syntax-highlighting", true, 3),
            plugin("zsh-autosuggestions", false, 7),
            plugin("fast-syntax-highlighting", true, 11),
        ];
        let err = check_terminal(&plugins).expect_err("two claimants");
        let message = err.to_string();
        assert!(message.starts_with("/repo/bx.toml:11: "), "{message}");
        assert!(
            message.contains("plugin `fast-syntax-highlighting` claims the terminal slot"),
            "{message}"
        );
        assert!(
            message.contains("plugin `zsh-syntax-highlighting` already claims at /repo/bx.toml:3"),
            "{message}"
        );

        // One claimant, none, or a second one switched off: all fine.
        check_terminal(&plugins[..2]).expect("one claimant");
        check_terminal(&plugins[1..2]).expect("no claimant");
        check_terminal(&[]).expect("no plugin");
        let mut off = plugins.clone();
        off[0].enabled = false;
        check_terminal(&off).expect("the first claim is switched off");
    }

    #[test]
    fn plugins_land_in_their_phases_in_declaration_order() {
        let mut disabled = plugin("off", false, 9);
        disabled.enabled = false;
        let plugins = [
            plugin("zsh-syntax-highlighting", true, 1),
            plugin("b", false, 2),
            disabled,
            plugin("a", false, 3),
        ];
        let mut assembly = Assembly::new();
        contribute(&mut assembly, &plugins).expect("one terminal claimant");
        let rendered = assembly.render();
        let at = |needle: &str| rendered.find(needle).expect(needle);
        assert!(at("# bx phase: plugins") < at("/b/b.zsh"));
        assert!(at("/b/b.zsh") < at("/a/a.zsh"));
        assert!(at("/a/a.zsh") < at("# bx phase: terminal"));
        assert!(at("# bx phase: terminal") < at("zsh-syntax-highlighting.zsh"));
        assert!(!rendered.contains("/off/"), "{rendered}");
        let mut again = Assembly::new();
        contribute(&mut again, &plugins).expect("one terminal claimant");
        assert_eq!(again.render(), rendered, "byte-identical");

        let two = [plugin("h1", true, 1), plugin("h2", true, 2)];
        assert_eq!(
            contribute(&mut Assembly::new(), &two),
            Err(super::super::Error::TerminalClaimed {
                first: "h1".to_string(),
                second: "h2".to_string(),
            })
        );
    }

    #[test]
    fn a_plugin_line_sets_nothing() {
        // Invariant 2: a plugin line is generated shell content that is not an
        // environment fragment, so it must carry no assignment. It is a test
        // and a `source`, and every character the path may hold is one that
        // can neither assign nor end the test: no `=`, blank, `;`, `&`, `|`,
        // quote, `$` or bracket.
        let line = plugin("p", false, 1).line();
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            words,
            [
                "[[",
                "-r",
                "~/.zsh/p/p.zsh",
                "]]",
                "&&",
                "source",
                "~/.zsh/p/p.zsh"
            ]
        );
        assert!(!line.contains('='), "{line}");
        for c in "= \t;&|'\"$`[](){}<>\\*?!#~^".chars() {
            assert!(
                unsourceable(&format!("~/a{c}b")).is_some(),
                "{c:?} would be written bare"
            );
        }
    }
}
