//! Declared shell aliases: data in `bx.toml`, rendered into the `aliases`
//! phase with one quoting rule that holds for every body.
//!
//! # Two representations, one list
//!
//! ```toml
//! [aliases]                       # the flat list: name = body
//! ll      = "ls -la"
//! sudo    = "sudo "               # the trailing space is load-bearing
//! ".."    = "cd .."
//!
//! [[alias]]                       # the conditional list
//! name    = "cat"                 # required; the natural key
//! command = "bat --paging=never"  # required
//! when    = "has:bat"             # optional; see `config::when`
//! enabled = true                  # default true
//! ```
//!
//! Both land in one list, [`AliasDecl`], keyed by `name`, in the order they
//! are written in the file. A name declared twice in one layer — twice in
//! `[aliases]`, twice in `[[alias]]`, or once in each — fails the load, naming
//! both lines. A later layer's alias with the same name replaces the earlier
//! one in place, whichever table either is written in, and a `[[alias]]`
//! holding only `name` and `enabled` is a toggle.
//!
//! # Quoting
//!
//! Every body is written inside single quotes, and each `'` in it as `'\''`:
//! close the quote, a backslash-escaped quote, reopen. Inside single quotes
//! the shell gives no character a meaning, so a trailing space, a `$`, a
//! backtick, a `"`, a `\`, a `!` and a glob all reach the alias exactly as
//! written, and nothing in the body runs or expands while the alias is being
//! defined. A variable a body names is expanded each time the alias is used,
//! never frozen at shell startup the way `alias x="…$VAR…"` freezes it. The
//! tests hold real zsh and bash to both claims, byte for byte.
//!
//! A body is one line with no control character, and holds no `{{`: bodies
//! are not templates, and refusing the spelling now keeps it free for a
//! substitution rule later without changing what an existing body means.
//!
//! # Names
//!
//! A name is written bare, before the `=`, so it holds only characters no
//! shell gives a meaning to there: ASCII letters, digits and `_.+:@%,-`, and
//! it does not open with `-`, which `alias` would read as an option. Shadowing
//! a real command is the config author's choice and is not refused.
//!
//! # `when`
//!
//! A `[[alias]]` may be gated on one condition from the closed set
//! [`crate::config::when`] defines. `has:TOOL` is decided while `plan`
//! renders: the alias is written plainly when the tool is usable and left out
//! of the file entirely when it is not, and no `command -v` is ever written.
//! A runtime condition wraps the alias's line in a guarded block, as an
//! `[[env]]` variable's is.
//!
//! # Invariant 2
//!
//! The `aliases` phase is generated shell content that is not an environment
//! fragment, so it carries no assignment. An alias line is the `alias`
//! builtin given one word; the body, being single-quoted, is inert until the
//! alias is used, and what it does then is the command the user asked for.
//! `rendering_an_alias_sets_no_variable` runs the rendered bytes in zsh and
//! holds them to that.

use std::path::Path;

use toml_edit::{Item, Table};

use super::{Assembly, Phase};
use crate::config::when::{self, Gate, When};
use crate::config::{Ctx, Error, Origin};

/// The conditional list's header, as messages spell it.
pub(crate) const SECTION: &str = "[[alias]]";

/// The flat list's header, as messages spell it.
pub(crate) const FLAT_SECTION: &str = "[aliases]";

/// Every key a `[[alias]]` entry may carry.
const KEYS: [&str; 4] = ["name", "command", "when", "enabled"];

/// One declared alias, from either table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasDecl {
    /// The alias's name, its natural key.
    pub name: String,
    /// What it expands to, exactly as written.
    pub command: String,
    /// The condition it is gated on, if any. Always `None` from `[aliases]`.
    pub when: Option<When>,
    /// `false` in any layer removes the alias from the resolved configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

impl AliasDecl {
    /// The line that defines the alias.
    #[must_use]
    pub fn line(&self) -> String {
        format!("alias {}={}\n", self.name, quote(&self.command))
    }

    /// What the alias contributes to the file: its line, the line inside a
    /// guarded block, or nothing.
    ///
    /// `present` answers whether a `has:TOOL` tool is usable on this machine,
    /// asked while `plan` and `apply` render, never by the generated shell.
    #[must_use]
    pub fn render(&self, present: &dyn Fn(&str) -> bool) -> String {
        let line = self.line();
        match self.when.as_ref().map(|when| when.gate(present)) {
            None | Some(Gate::Always) => line,
            Some(Gate::Never) => String::new(),
            Some(Gate::Test(test)) => {
                format!("{}\n  {line}{}\n", when::opener(&test), when::CLOSER)
            }
        }
    }
}

/// `body` as one single-quoted shell word that means exactly `body`.
///
/// Each `'` becomes `'\''`; nothing else is touched, because nothing else has
/// a meaning inside single quotes.
#[must_use]
pub fn quote(body: &str) -> String {
    format!("'{}'", body.replace('\'', r"'\''"))
}

/// Parse the flat `[aliases]` table: each key a name, each value its body.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// [`Error::WrongType`] for a value that is not a string, and
/// [`Error::BadValue`] for a name or body [`parse_alias`] would refuse too.
/// Every one carries the key's origin.
pub fn parse_aliases(table: &Table, file: &Path, text: &str) -> Result<Vec<AliasDecl>, Error> {
    let ctx = Ctx::new(table, file, text, FLAT_SECTION);
    let mut aliases = Vec::new();
    for (name, item) in table.iter() {
        let command = match item {
            Item::Value(value) => value.as_str(),
            _ => None,
        }
        .ok_or_else(|| Error::WrongType {
            origin: ctx.key_origin(table, name),
            key: name.to_string(),
            expected: "a string",
            found: item.type_name(),
        })?;
        check(name, command).map_err(|problem| ctx.bad(table, name, problem))?;
        aliases.push(AliasDecl {
            name: name.to_string(),
            command: command.to_string(),
            when: None,
            enabled: true,
            origin: ctx.key_origin(table, name),
        });
    }
    Ok(aliases)
}

/// Parse one `[[alias]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_alias(table: &Table, file: &Path, text: &str) -> Result<AliasDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if let Some(problem) = unnameable(&name) {
        return Err(ctx.bad(table, "name", problem));
    }
    let command = ctx.required_str(table, "command")?.to_string();
    if let Some(problem) = unwritable(&command) {
        return Err(ctx.bad(table, "command", format!("alias `{name}`: {problem}")));
    }
    let when = match ctx.str_at(table, "when")? {
        None => None,
        Some(raw) => Some(When::parse(raw).map_err(|problem| ctx.bad(table, "when", problem))?),
    };

    Ok(AliasDecl {
        name,
        command,
        when,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Both checks a flat entry needs, as one message.
fn check(name: &str, command: &str) -> Result<(), String> {
    if let Some(problem) = unnameable(name) {
        return Err(problem);
    }
    unwritable(command).map_or(Ok(()), |problem| Err(format!("alias `{name}`: {problem}")))
}

/// Why `name` cannot be written bare before an alias's `=`, or `None` when it
/// can.
fn unnameable(name: &str) -> Option<String> {
    let bare = |c: char| c.is_ascii_alphanumeric() || "_.+:@%,-".contains(c);
    (name.is_empty() || name.starts_with('-') || !name.chars().all(bare)).then(|| {
        format!(
            "{name:?} is not an alias name: a name is written bare, so it is non-empty, holds \
             only ASCII letters, digits and `_.+:@%,-`, and does not open with `-`"
        )
    })
}

/// Why `command` cannot be an alias body, or `None` when it can.
fn unwritable(command: &str) -> Option<String> {
    if command.is_empty() {
        return Some("the body is empty; an alias expands to something".to_string());
    }
    if let Some(c) = command.chars().find(|c| c.is_control()) {
        return Some(format!(
            "an alias body is one line and holds no control character; found {c:?}"
        ));
    }
    command.contains("{{").then(|| {
        "an alias body holds no `{{`: bodies are written exactly as given and are not \
         templates"
            .to_string()
    })
}

/// Add every enabled alias to `assembly`'s `aliases` phase, in declaration
/// order.
///
/// An alias gated on a missing tool contributes nothing at all.
pub fn contribute(assembly: &mut Assembly, aliases: &[AliasDecl], present: &dyn Fn(&str) -> bool) {
    for alias in aliases.iter().filter(|a| a.enabled) {
        let body = alias.render(present);
        if !body.is_empty() {
            // The aliases phase is not the terminal slot, so it never refuses.
            let _ = assembly.contribute(Phase::Aliases, alias.name.clone(), body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use std::path::PathBuf;

    const FILE: &str = "/repo/bx.toml";

    fn load(text: &str) -> Result<Vec<AliasDecl>, String> {
        parse_str(text, Path::new(FILE), Path::new("/home/u"))
            .map(|config| config.aliases)
            .map_err(|e| e.to_string())
    }

    fn alias(name: &str, command: &str, when: Option<When>) -> AliasDecl {
        AliasDecl {
            name: name.to_string(),
            command: command.to_string(),
            when,
            enabled: true,
            origin: Origin {
                file: PathBuf::from(FILE),
                line: 1,
            },
        }
    }

    /// The bodies the source material's aliases need, and every character a
    /// shell would otherwise act on.
    const BODIES: &[&str] = &[
        "ls -la",
        "sudo ",
        "echo $HOME",
        "echo ${PWD}",
        "echo `date`",
        "echo $(date)",
        "echo \"quoted\" word",
        "it's",
        "'",
        "''",
        "a'b'c",
        "printf '%s\\n' x",
        "back\\slash\\",
        "echo !! !$",
        "ls *.rs ?[ab]",
        "cd ~",
        "a; b && c || d | e > f < g &",
        "#not a comment",
        "  leading and trailing  ",
        "émoji ✓",
        "\t",
    ];

    #[test]
    fn both_tables_parse_in_file_order() {
        let aliases = load(
            "[aliases]\nll = \"ls -la\"\n\"..\" = \"cd ..\"\n\
             [[alias]]\nname = \"cat\"\ncommand = \"bat\"\nwhen = \"has:bat\"\n\
             [[alias]]\nname = \"x\"\ncommand = \"y\"\nenabled = false\n",
        )
        .expect("parses");
        let file = PathBuf::from(FILE);
        assert_eq!(
            aliases,
            vec![
                AliasDecl {
                    origin: Origin {
                        file: file.clone(),
                        line: 2
                    },
                    ..alias("ll", "ls -la", None)
                },
                AliasDecl {
                    origin: Origin {
                        file: file.clone(),
                        line: 3
                    },
                    ..alias("..", "cd ..", None)
                },
                AliasDecl {
                    origin: Origin {
                        file: file.clone(),
                        line: 4
                    },
                    ..alias("cat", "bat", Some(When::Has("bat".to_string())))
                },
                AliasDecl {
                    enabled: false,
                    origin: Origin { file, line: 8 },
                    ..alias("x", "y", None)
                },
            ]
        );
    }

    #[test]
    fn a_name_declared_twice_in_one_file_fails_the_load_in_either_table() {
        // Twice in `[aliases]` is already a TOML error, which fails the load
        // before any alias is read.
        let err = load("[aliases]\nll = \"a\"\n\"ll\" = \"b\"\n").expect_err("a TOML error");
        assert!(err.contains("duplicate key"), "{err}");
        for text in [
            "[[alias]]\nname = \"ll\"\ncommand = \"a\"\n[[alias]]\nname = \"ll\"\ncommand = \"b\"\n",
            "[aliases]\nll = \"a\"\n[[alias]]\nname = \"ll\"\ncommand = \"b\"\n",
            "[[alias]]\nname = \"ll\"\ncommand = \"b\"\n[aliases]\nll = \"a\"\n",
            "[aliases]\nll = \"a\"\n[[alias]]\nname = \"ll\"\nenabled = false\n",
        ] {
            let err = load(text).expect_err(text);
            assert!(err.contains("duplicate alias `ll`"), "{text}: {err}");
            assert!(err.contains("first declared at /repo/bx.toml:"), "{err}");
        }
    }

    #[test]
    fn a_malformed_alias_is_refused_naming_why() {
        for (text, needle) in [
            ("[aliases]\nll = 1\n", "`ll` must be a string"),
            ("[aliases]\nll = [\"a\"]\n", "`ll` must be a string"),
            ("[aliases]\nll.x = \"a\"\n", "`ll` must be a string"),
            ("[aliases]\n\"\" = \"a\"\n", "not an alias name"),
            ("[aliases]\n\"-x\" = \"a\"\n", "not an alias name"),
            ("[aliases]\n\"a b\" = \"a\"\n", "not an alias name"),
            ("[aliases]\n\"a=b\" = \"a\"\n", "not an alias name"),
            ("[aliases]\n\"a*\" = \"a\"\n", "not an alias name"),
            ("[aliases]\n\"a'\" = \"a\"\n", "not an alias name"),
            ("[aliases]\n\"$a\" = \"a\"\n", "not an alias name"),
            ("[aliases]\n\"~a\" = \"a\"\n", "not an alias name"),
            ("[aliases]\nll = \"\"\n", "the body is empty"),
            ("[aliases]\nll = \"a\\nb\"\n", "control character"),
            ("[aliases]\nll = \"a\\rb\"\n", "control character"),
            ("[aliases]\nll = \"{{x}}\"\n", "not templates"),
            ("[aliases]\n[aliases.ll]\n", "`ll` must be a string"),
            ("[[alias]]\ncommand = \"a\"\n", "`name`"),
            ("[[alias]]\nname = \"a\"\n", "`command`"),
            (
                "[[alias]]\nname = \"a b\"\ncommand = \"a\"\n",
                "not an alias name",
            ),
            (
                "[[alias]]\nname = \"a\"\ncommand = \"x\\ny\"\n",
                "control character",
            ),
            (
                "[[alias]]\nname = \"a\"\ncommand = \"x\"\nwhen = \"tty\"\n",
                "`when` must be one of",
            ),
            (
                "[[alias]]\nname = \"a\"\ncommand = \"x\"\nwhen = \"has:$(id)\"\n",
                "`has:`",
            ),
            (
                "[[alias]]\nname = \"a\"\ncommand = \"x\"\nenabled = \"no\"\n",
                "a boolean",
            ),
            (
                "[[alias]]\nname = \"a\"\ncommand = \"x\"\nbody = \"y\"\n",
                "unknown key `body`",
            ),
            ("aliases = \"x\"\n", "a table `[aliases]`"),
            ("alias = \"x\"\n", "a repeated section"),
        ] {
            let err = load(text).expect_err(text);
            assert!(err.contains(needle), "{text}: {err}");
            assert!(err.starts_with("/repo/bx.toml:"), "{text}: {err}");
        }
    }

    #[test]
    fn every_body_is_one_single_quoted_word() {
        assert_eq!(quote("ls -la"), "'ls -la'");
        assert_eq!(quote("sudo "), "'sudo '");
        assert_eq!(quote("echo $HOME"), "'echo $HOME'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("'"), r"''\'''");
        assert_eq!(alias("sudo", "sudo ", None).line(), "alias sudo='sudo '\n");
        for body in BODIES {
            let quoted = quote(body);
            assert_eq!(unquote(&quoted).as_deref(), Some(*body), "{quoted}");
        }
    }

    /// Read `word` back the way a POSIX shell reads it, accepting nothing
    /// outside single quotes but a backslash-escaped `'`: `None` for any
    /// other character there, which the shell would give a meaning to.
    fn unquote(word: &str) -> Option<String> {
        let mut out = String::new();
        let mut chars = word.chars();
        while let Some(c) = chars.next() {
            match c {
                '\'' => loop {
                    match chars.next()? {
                        '\'' => break,
                        inner => out.push(inner),
                    }
                },
                '\\' if chars.next()? == '\'' => out.push('\''),
                _ => return None,
            }
        }
        Some(out)
    }

    #[test]
    fn the_reader_refuses_what_a_shell_would_act_on() {
        for word in ["a", "'a'b", "'a", "\\a", "'a'$x", "'a' 'b'"] {
            assert_eq!(unquote(word), None, "{word}");
        }
        assert_eq!(unquote("''\\'''").as_deref(), Some("'"));
    }

    #[test]
    fn a_gate_decides_whether_and_how_the_alias_is_written() {
        let has = alias("cat", "bat", Some(When::Has("bat".to_string())));
        assert_eq!(has.render(&|tool| tool == "bat"), "alias cat='bat'\n");
        assert_eq!(has.render(&|_| false), "");
        let ssh = alias("x", "y", Some(When::Ssh));
        assert_eq!(
            ssh.render(&|_| unreachable!("a runtime test asks for no tool")),
            "if [[ -n ${SSH_CONNECTION-} ]]; then\n  alias x='y'\nfi\n"
        );
        assert_eq!(alias("x", "y", None).render(&|_| false), "alias x='y'\n");
    }

    #[test]
    fn a_missing_tool_leaves_the_alias_out_of_the_file_entirely() {
        let aliases = [
            alias("ll", "ls -la", None),
            alias(
                "cat",
                "bat --paging=never",
                Some(When::Has("bat".to_string())),
            ),
            alias("ls", "eza", Some(When::Has("eza".to_string()))),
        ];
        let mut assembly = Assembly::new();
        contribute(&mut assembly, &aliases, &|tool| tool == "eza");
        let rendered = assembly.render();
        assert!(rendered.contains("alias ll='ls -la'\n"), "{rendered}");
        assert!(rendered.contains("alias ls='eza'\n"), "{rendered}");
        assert!(!rendered.contains("cat"), "{rendered}");
        assert!(!rendered.contains("bat"), "{rendered}");
        assert!(!rendered.contains("command -v"), "{rendered}");

        // Every alias gated off: the phase is not even headed.
        let mut none = Assembly::new();
        contribute(&mut none, &aliases[1..2], &|_| false);
        assert!(none.is_empty());
    }

    #[test]
    fn rendering_is_byte_identical_and_in_declared_order() {
        let mut off = alias("off", "x", None);
        off.enabled = false;
        let aliases = [
            alias("zz", "last-declared-first", None),
            off,
            alias("aa", "a", None),
            alias("mm", "m", Some(When::Interactive)),
        ];
        let render = || {
            let mut assembly = Assembly::new();
            contribute(&mut assembly, &aliases, &|_| true);
            assembly.render()
        };
        let first = render();
        assert_eq!(first, render());
        assert!(first.ends_with(
            "\n# bx phase: aliases\n\
             alias zz='last-declared-first'\n\
             alias aa='a'\n\
             if [[ -o interactive ]]; then\n  alias mm='m'\nfi\n"
        ));
        assert!(!first.contains("off"), "{first}");
    }

    /// The installed shell `program`, or `None` on a machine excused from
    /// supplying it. A runner may not excuse itself, as `env_guard`'s
    /// differential checks rule.
    fn installed(program: &str) -> Option<PathBuf> {
        if let crate::detect::Presence::Present { path } = crate::detect::locate_in_env(program) {
            return Some(path);
        }
        let excused = std::env::var_os("BX_TEST_WITHOUT_SHELLS").is_some();
        assert!(
            excused && std::env::var_os("CI").is_none(),
            "{program} is not installed, so the alias checks held against it would assert \
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
    fn run(shell: &Path, flags: &[&str], script: &str) -> Vec<u8> {
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

    #[test]
    fn zsh_and_bash_hold_every_body_exactly_as_written() {
        let script = |reader: &str| {
            BODIES
                .iter()
                .enumerate()
                .map(|(index, body)| {
                    let line = alias(&format!("a{index}"), body, None).line();
                    format!("{line}{}\n", reader.replace("NAME", &format!("a{index}")))
                })
                .collect::<String>()
        };
        let expected: Vec<u8> = BODIES
            .iter()
            .flat_map(|body| body.bytes().chain([0]))
            .collect();
        if let Some(zsh) = installed("zsh") {
            let got = run(
                &zsh,
                &["-f"],
                &script("print -rn -- \"${aliases[NAME]}\"; print -n '\\0'"),
            );
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&expected)
            );
        }
        if let Some(bash) = installed("bash") {
            let got = run(
                &bash,
                &["--norc", "--noprofile"],
                &script("printf '%s\\0' \"${BASH_ALIASES[NAME]}\""),
            );
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&expected)
            );
        }
    }

    #[test]
    fn a_variable_in_a_body_is_read_when_the_alias_runs_not_when_it_is_defined() {
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let line = alias("show", "print -r -- $X", None).line();
        let got = run(&zsh, &["-f"], &format!("X=early\n{line}X=late\nshow\n"));
        assert_eq!(got, b"late\n");
        // The double-quoted spelling the source material used freezes it.
        let frozen = run(
            &zsh,
            &["-f"],
            "X=early\nalias show=\"print -r -- $X\"\nX=late\nshow\n",
        );
        assert_eq!(frozen, b"early\n");
    }

    #[test]
    fn a_trailing_space_still_expands_the_next_word_as_an_alias() {
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let lines = [
            alias("p", "print -r -- ", None),
            alias("w", "expanded", None),
        ]
        .iter()
        .map(AliasDecl::line)
        .collect::<String>();
        assert_eq!(run(&zsh, &["-f"], &format!("{lines}p w\n")), b"expanded\n");
    }

    #[test]
    fn rendering_an_alias_sets_no_variable() {
        // Invariant 2: the aliases phase is not an environment fragment, so
        // defining the aliases, gated blocks included, must leave every
        // variable as it was.
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let mut aliases: Vec<AliasDecl> = BODIES
            .iter()
            .enumerate()
            .map(|(index, body)| alias(&format!("a{index}"), body, None))
            .collect();
        aliases.push(alias("g", "export X=1", Some(When::Interactive)));
        aliases.push(alias("h", "Y=2", Some(When::EnvSet("HOME".to_string()))));
        let mut assembly = Assembly::new();
        contribute(&mut assembly, &aliases, &|_| true);
        // Every parameter zsh does not maintain itself, with its value. The
        // loop variable is local to the function, so it is in both dumps.
        let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                    [[ ${parameters[$n]} == *special* ]] || print -r -- \"$n=${(P)n}\"; \
                    done; print -r -- ---; }\n";
        let dumps = |body: &str| {
            // A first, discarded dump reads every autoloaded parameter, which
            // loads the modules behind them and the parameters those bring.
            let script = format!("{dump}__bx_dump >/dev/null\n__bx_dump\n{body}__bx_dump\n");
            let got = String::from_utf8(run(&zsh, &["-f"], &script)).expect("utf-8");
            let (before, after) = got.split_once("---\n").expect("two dumps");
            (
                before.to_string(),
                after.trim_end_matches("---\n").to_string(),
            )
        };
        let (before, after) = dumps(&assembly.render());
        assert_eq!(after, before);
        // The dump does see an assignment, so the equality above means
        // something.
        let (before, after) = dumps("Z=1\n");
        assert_ne!(after, before);
        assert!(after.contains("Z=1\n"), "{after}");
    }
}
