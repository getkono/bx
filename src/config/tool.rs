//! The declared tool inventory: the programs this configuration expects, each
//! with the command that would install it — printed, never run.
//!
//! ```toml
//! [[tool]]
//! name    = "rg"                               # required; the natural key
//! install = "sudo dnf install ripgrep"         # optional; printed, never run
//! enabled = true                               # default true
//! ```
//!
//! `name` is the program's file name, the word a shell looks up on `PATH`, and
//! it is the only thing `bx doctor` checks: a tool is present when an
//! executable of that name is on `PATH`, and missing otherwise, whatever
//! package manager may say it installed under another file name. bx says what
//! it can honestly check, not what it cannot. So a name is one bare word — no
//! `/`, no whitespace, no control character, and neither `.` nor `..`.
//!
//! `install` is text for a human. bx never runs it, splits it or substitutes
//! anything into it: `bx doctor` prints it beside a missing tool, and that is
//! all. It is one line, so the finding it is printed in stays one line.
//!
//! Entries are listed in the order written, keyed by `name`. A name declared
//! twice in one layer fails the load, naming both lines; a later layer's entry
//! with the same name replaces the earlier one in place, and a `[[tool]]`
//! holding only `name` and `enabled` is a toggle, so an account can drop a
//! tool it does not want from its own `local.toml`.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[tool]]";

/// Every key a `[[tool]]` entry may carry.
const KEYS: [&str; 3] = ["name", "install", "enabled"];

/// One `[[tool]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDecl {
    /// The program's file name, looked up on `PATH`: the natural key.
    pub name: String,
    /// The command a human would run to install it. Printed, never run.
    pub install: Option<String>,
    /// `false` in any layer removes the tool from the resolved configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// Why `name` cannot name a program on `PATH`, or `None` when it can.
fn unnamed(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        Some("a tool name is not empty")
    } else if name == "." || name == ".." {
        Some("`.` and `..` are directories, not programs")
    } else if name.contains('/') {
        Some("a tool is named by the file name `PATH` finds, so it holds no `/`")
    } else if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        Some("a tool name is one word, with no whitespace or control character")
    } else {
        None
    }
}

/// Parse one `[[tool]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_tool(table: &Table, file: &Path, text: &str) -> Result<ToolDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if let Some(problem) = unnamed(&name) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not a tool name: {problem}"),
        ));
    }

    let install = match ctx.str_at(table, "install")? {
        None => None,
        Some(raw) if raw.trim().is_empty() => {
            return Err(ctx.bad(
                table,
                "install",
                format!("tool `{name}`: `install` is empty; leave it out instead"),
            ));
        }
        Some(raw) if raw.chars().any(char::is_control) => {
            return Err(ctx.bad(
                table,
                "install",
                format!(
                    "tool `{name}`: `install` is printed on one line, so it holds no newline \
                     or control character"
                ),
            ));
        }
        Some(raw) => Some(raw.to_string()),
    };

    Ok(ToolDecl {
        name,
        install,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::parse_str;

    fn parse(text: &str) -> Result<Vec<ToolDecl>, String> {
        parse_str(text, Path::new("/repo/bx.toml"), Path::new("/home/u"))
            .map(|config| config.tools)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn a_tool_entry_parses_every_key() {
        let tools = parse(
            "[[tool]]\nname = \"rg\"\ninstall = \"sudo dnf install ripgrep\"\n\
             [[tool]]\nname = \"fd\"\nenabled = false\ninstall = \"cargo install fd-find\"\n\
             [[tool]]\nname = \"git\"\n",
        )
        .unwrap();

        assert_eq!(
            tools,
            vec![
                ToolDecl {
                    name: "rg".into(),
                    install: Some("sudo dnf install ripgrep".into()),
                    enabled: true,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 1,
                    },
                },
                ToolDecl {
                    name: "fd".into(),
                    install: Some("cargo install fd-find".into()),
                    enabled: false,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 4,
                    },
                },
                ToolDecl {
                    name: "git".into(),
                    install: None,
                    enabled: true,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 8,
                    },
                },
            ]
        );
    }

    #[test]
    fn a_name_that_is_not_one_bare_word_is_refused() {
        for (name, why) in [
            ("", "is not empty"),
            (".", "not programs"),
            ("..", "not programs"),
            ("/usr/bin/rg", "holds no `/`"),
            ("bin/rg", "holds no `/`"),
            ("rip grep", "one word"),
            // A TOML escape, so the name holds a real tab.
            ("rg\\t", "one word"),
        ] {
            let text = format!("[[tool]]\nname = \"{name}\"\n");
            let message = parse(&text).map_or_else(|e| e, |_| String::new());
            assert!(message.contains(why), "{name:?}: {message}");
            assert!(
                message.contains("is not a tool name"),
                "{name:?}: {message}"
            );
        }
    }

    #[test]
    fn a_later_layer_replaces_a_tool_in_place_and_a_toggle_drops_one() {
        use crate::config::{Layer, LayerKind, merge};

        let home = Path::new("/home/u");
        let layer = |file: &str, kind, text: &str| Layer {
            file: PathBuf::from(file),
            kind,
            config: parse_str(text, Path::new(file), home).unwrap(),
        };
        let merged = merge::merge(
            &[
                layer(
                    "bx.toml",
                    LayerKind::Global,
                    "[[tool]]\nname = \"rg\"\n[[tool]]\nname = \"fd\"\n[[tool]]\nname = \"jq\"\n",
                ),
                layer(
                    "local.toml",
                    LayerKind::Local,
                    "[[tool]]\nname = \"rg\"\ninstall = \"brew install ripgrep\"\n\
                     [[tool]]\nname = \"fd\"\nenabled = false\n",
                ),
            ],
            home,
        )
        .unwrap();

        let tools: Vec<(&str, Option<&str>, &str)> = merged
            .tools
            .iter()
            .map(|t| {
                (
                    t.name.as_str(),
                    t.install.as_deref(),
                    t.origin.file.to_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            tools,
            vec![
                ("rg", Some("brew install ripgrep"), "local.toml"),
                ("jq", None, "bx.toml"),
            ]
        );
    }

    #[test]
    fn an_install_command_is_one_non_empty_line() {
        let empty = parse("[[tool]]\nname = \"rg\"\ninstall = \" \"\n").unwrap_err();
        assert!(empty.contains("`install` is empty"), "{empty}");

        let two = parse("[[tool]]\nname = \"rg\"\ninstall = \"a\\nb\"\n").unwrap_err();
        assert!(two.contains("on one line"), "{two}");
    }

    #[test]
    fn an_unknown_key_or_a_missing_name_is_refused() {
        let unknown = parse("[[tool]]\nname = \"rg\"\nrun = \"rg --version\"\n").unwrap_err();
        assert!(unknown.contains("run"), "{unknown}");

        let nameless = parse("[[tool]]\ninstall = \"x\"\n").unwrap_err();
        assert!(nameless.contains("name"), "{nameless}");
    }

    #[test]
    fn a_name_declared_twice_in_one_layer_is_refused() {
        let twice = parse("[[tool]]\nname = \"rg\"\n[[tool]]\nname = \"rg\"\ninstall = \"x\"\n")
            .unwrap_err();
        assert!(twice.contains("duplicate tool `rg`"), "{twice}");
    }
}
