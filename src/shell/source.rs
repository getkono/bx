//! Declared optional sources: a file some other tool writes, sourced into the
//! interactive shell file only once it is readable, in the phase it names.
//!
//! ```toml
//! [[source]]
//! name    = "keychain"                          # required; the natural key
//! path    = "~/.keychain/{{hostname}}-sh"       # required; `{{value}}` is substituted
//! phase   = "activations"                       # default "plugins"
//! when    = "interactive"                       # optional; gates the line
//! shells  = ["zsh"]                             # optional; default every shell
//! enabled = true                                # default true
//! ```
//!
//! A source lands in zsh's and bash's generated files alike, the same line in
//! the same phase, unless `shells` keeps it to some — a zsh plugin manager's
//! file, say, is `shells = ["zsh"]`.
//!
//! This is the escape hatch for the `[ -f FILE ] && source FILE` lines a shell
//! configuration otherwise scatters about — a tool's own completion file, an
//! account's untracked `~/.aliases`, and a tool whose output must be fresh in
//! every shell, such as keychain's `~/.keychain/<host>-sh`, which no
//! activation cache may hold. Every one of them renders the same way: one line
//! that tests the file is readable and only then sources it, so a missing file
//! costs nothing and never breaks the shell.
//!
//! Entries are listed in the order written, keyed by `name`. A name declared
//! twice in one layer fails the load, naming both lines; a later layer's entry
//! with the same name replaces the earlier one in place, and a `[[source]]`
//! holding only `name` and `enabled` is a toggle.
//!
//! # The path
//!
//! `path` is substituted from the declared values exactly as a target's text
//! is, so a path that names this account — a home directory spelled out, a
//! host name — is written once as a `{{value}}` and answered per account. The
//! substituted path opens with `~/` or `/` and holds only characters a bare
//! shell word holds, as a plugin's `source` does: it is written unquoted, which
//! is what lets zsh expand the `~`, and nothing in it can end the test or start
//! a second command. A path with no placeholder is checked when the config
//! loads; one with a placeholder, once it is substituted.
//!
//! A path that references a value this account has not answered, has switched
//! off, or answered unusably is **held back**: that one source is left out of
//! the generated file, and the file's plan row names it with what would
//! release it ([`note`]). A reference to a value no layer declares, or a
//! committed `default` that makes the path unwritable, is a defect in the
//! committed repo and fails the load.
//!
//! bx never reads, copies or inspects the sourced file: rendering asks nothing
//! of the filesystem, and [`missing`] asks only whether each file is readable,
//! through a question its caller answers.
//!
//! # Placement
//!
//! `phase` names where the line loads, from the phases whose content is not an
//! environment fragment and that nothing but bx's own setup owns:
//! `activations`, `completions`, `plugins`, `aliases`, `functions`,
//! `keybindings` and `options` ([`PHASES`]). `env` and `path` are refused
//! because they hold only fragments the environment guard judges, `completion`
//! because it is the completion system's own setup, and `terminal` because it
//! is the single slot one plugin may claim, which a source never does. Within
//! its phase a source loads after that phase's own declarations, in
//! declaration order.
//!
//! `when` is one condition from the closed set [`crate::config::when`]
//! defines, and it gates the line: `has:TOOL` is decided while `plan` renders,
//! dropping the line when the tool is missing, and any other condition wraps
//! it in a guarded block, its test in the words of the shell whose file it
//! is.
//!
//! # Invariant 2
//!
//! A source line is generated shell content that is not an environment
//! fragment, and it carries no assignment: it is a test and a `source`, and no
//! character the path may hold can assign or end the test. What the sourced
//! file does when it runs is that file's own behaviour, written by the tool or
//! the user that wrote it, as a plugin's is.

use std::path::{Path, PathBuf};

use toml_edit::Table;

use super::plugin::{guarded, unsourceable};
use super::{Assembly, Phase, Shell, Shells};
use crate::config::resolve::{BlockReason, BlockedEntry, Resolution};
use crate::config::values::{self, ResolvedValues, Unresolved};
use crate::config::when::{self, Gate, When};
use crate::config::{Ctx, Error, Origin};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[source]]";

/// Every key a `[[source]]` entry may carry.
const KEYS: [&str; 6] = ["name", "path", "phase", "when", "shells", "enabled"];

/// The phases a source may load in, in load order.
pub const PHASES: [Phase; 7] = [
    Phase::Activations,
    Phase::Completions,
    Phase::Plugins,
    Phase::Aliases,
    Phase::Functions,
    Phase::Keybindings,
    Phase::Options,
];

/// The phase a source loads in when it names none.
pub const DEFAULT_PHASE: Phase = Phase::Plugins;

/// One `[[source]]` entry, as written: its path not yet substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDecl {
    /// The source's name, its natural key.
    pub name: String,
    /// The path as written, `{{name}}` references and all.
    pub path: String,
    /// The phase it loads in.
    pub phase: Phase,
    /// The condition it is gated on, if any.
    pub when: Option<When>,
    /// The shells whose generated file sources it.
    pub shells: Shells,
    /// `false` in any layer removes the source from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// One source ready to write: its path substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The name it was declared under.
    pub name: String,
    /// The substituted path, as the line spells it.
    pub path: String,
    /// The phase it loads in.
    pub phase: Phase,
    /// The condition it is gated on, if any.
    pub when: Option<When>,
    /// Where the entry was written.
    pub origin: Origin,
}

impl Source {
    /// The one line that sources the file when it is readable.
    #[must_use]
    pub fn line(&self) -> String {
        guarded(&self.path)
    }

    /// What the source contributes to the file: its line, the line inside a
    /// guarded block, or nothing when `when` is `has:TOOL` and the tool is
    /// missing.
    ///
    /// `present` answers whether a `has:TOOL` tool is usable on this machine,
    /// asked while `plan` and `apply` render, never by the generated shell.
    #[must_use]
    pub fn render(&self, present: &dyn Fn(&str) -> bool) -> String {
        self.render_in(Shell::Zsh, present)
    }

    /// [`Source::render`] for `shell`: the same line, and a runtime condition
    /// asked in that shell's words ([`When::test_bash`] for bash).
    #[must_use]
    pub fn render_in(&self, shell: Shell, present: &dyn Fn(&str) -> bool) -> String {
        let line = self.line();
        let gate = |when: &When| match shell {
            Shell::Zsh => when.gate(present),
            Shell::Bash => when.gate_bash(present),
        };
        match self.when.as_ref().map(gate) {
            None | Some(Gate::Always) => line,
            Some(Gate::Never) => String::new(),
            Some(Gate::Test(test)) => {
                format!("{}\n  {line}{}\n", when::opener(&test), when::CLOSER)
            }
        }
    }

    /// The file the line tests, with a leading `~/` read against `home`.
    ///
    /// Decided from the path alone; nothing on disk is consulted.
    #[must_use]
    pub fn location(&self, home: &Path) -> PathBuf {
        self.path
            .strip_prefix("~/")
            .map_or_else(|| PathBuf::from(&self.path), |rest| home.join(rest))
    }
}

/// Read a `phase` string a config author wrote.
///
/// # Errors
///
/// Why `raw` is not a phase a source may load in, listing the ones it may.
pub fn parse_phase(raw: &str) -> Result<Phase, String> {
    if let Some(phase) = PHASES.into_iter().find(|phase| phase.name() == raw) {
        return Ok(phase);
    }
    let names: Vec<String> = PHASES.iter().map(|p| format!("{:?}", p.name())).collect();
    let why = match Phase::ALL.into_iter().find(|phase| phase.name() == raw) {
        Some(Phase::Terminal) => {
            "; `terminal` is the single slot one plugin may claim, and a source never claims it"
        }
        Some(Phase::Env | Phase::Path) => {
            "; that phase holds only environment fragments bx judges, and a source is not one"
        }
        Some(Phase::Completion) => "; that phase is the completion system's own setup",
        _ => "",
    };
    Err(format!(
        "`phase` must be one of {}; got {raw:?}{why}",
        names.join(", ")
    ))
}

/// Parse one `[[source]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_source(table: &Table, file: &Path, text: &str) -> Result<SourceDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not a source name: a name is non-empty and on one line"),
        ));
    }

    let path = ctx.required_str(table, "path")?.to_string();
    match values::placeholders(&path) {
        Err(problem) => return Err(ctx.bad(table, "path", format!("source `{name}`: {problem}"))),
        // Nothing to substitute, so the path is final and is checked now.
        Ok(names) if names.is_empty() => {
            if let Some(problem) = unsourceable("path", &path) {
                return Err(ctx.bad(table, "path", format!("source `{name}`: {problem}")));
            }
        }
        Ok(_) => {}
    }

    let phase = match ctx.str_at(table, "phase")? {
        None => DEFAULT_PHASE,
        Some(raw) => parse_phase(raw).map_err(|problem| ctx.bad(table, "phase", problem))?,
    };
    let when = match ctx.str_at(table, "when")? {
        None => None,
        Some(raw) => Some(When::parse(raw).map_err(|problem| ctx.bad(table, "when", problem))?),
    };

    let shells = Shells::parse_in(&ctx, table, &format!("source `{name}`"))?;

    Ok(SourceDecl {
        name,
        path,
        phase,
        when,
        shells,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Substitute every enabled source's path, or explain why it cannot be.
///
/// Each source resolves on its own: one whose path needs a value this account
/// has not answered, has switched off, or answered unusably is
/// [`Resolution::Blocked`] in its own position, keyed by its name, and every
/// other source resolves.
///
/// # Errors
///
/// [`Error::BadValue`] for a repo defect: a reference to a value no layer
/// declares, or a committed `default` that makes the path one a guarded line
/// cannot hold.
pub fn resolve(
    decls: &[SourceDecl],
    values: &ResolvedValues,
) -> Result<Vec<Resolution<Source>>, Error> {
    decls
        .iter()
        .filter(|decl| decl.enabled)
        .map(|decl| resolve_one(decl, values))
        .collect()
}

/// One source's resolution. See [`resolve`].
fn resolve_one(decl: &SourceDecl, values: &ResolvedValues) -> Result<Resolution<Source>, Error> {
    let block = |reason, hint| {
        Ok(Resolution::Blocked(BlockedEntry {
            key: decl.name.clone(),
            origin: decl.origin.clone(),
            reason,
            hint,
        }))
    };
    fn spelled(names: &[String]) -> Vec<&str> {
        names.iter().map(String::as_str).collect()
    }
    match values.substitute(&decl.path) {
        Ok(path) => {
            let Some(problem) = unsourceable("path", &path) else {
                return Ok(Resolution::Ready(Source {
                    name: decl.name.clone(),
                    path,
                    phase: decl.phase,
                    when: decl.when.clone(),
                    origin: decl.origin.clone(),
                }));
            };
            // An account's answer, whose line the hint names, or a committed
            // `default` alone, which no answer can clear.
            let problem = format!("source `{}`: {problem}", decl.name);
            let causes = values.account_inputs(&decl.path);
            if causes.is_empty() {
                return Err(Error::BadValue {
                    origin: decl.origin.clone(),
                    message: problem,
                });
            }
            let names = values.in_declaration_order(causes);
            let hint = values.answers_hint(&problem, &[decl.path.as_str()], &names);
            block(BlockReason::InvalidValue { names }, hint)
        }
        Err(Unresolved::Unset { names }) => {
            let hint = values::init_hint(&spelled(&names));
            block(BlockReason::UnsetValue { names }, hint)
        }
        Err(Unresolved::Disabled { names }) => {
            let hint = values::disabled_hint(&spelled(&names));
            block(BlockReason::DisabledValue { names }, hint)
        }
        Err(Unresolved::Invalid { names }) => {
            let hint = values.invalid_hint(&names);
            block(BlockReason::InvalidValue { names }, hint)
        }
        Err(defect) => Err(Error::BadValue {
            origin: decl.origin.clone(),
            message: format!("source `{}`: {defect}", decl.name),
        }),
    }
}

/// Add every ready source to `assembly`, each in its phase, in declaration
/// order, and say whether any line was written.
///
/// A held-back source contributes nothing; nor does one gated on a missing
/// tool.
pub fn contribute(
    assembly: &mut Assembly,
    sources: &[Resolution<Source>],
    shell: Shell,
    present: &dyn Fn(&str) -> bool,
) -> bool {
    let mut wrote = false;
    for source in sources {
        if let Resolution::Ready(source) = source {
            let body = source.render_in(shell, present);
            if !body.is_empty() {
                // No source loads in the terminal slot, so this never refuses.
                let _ = assembly.contribute(source.phase, source.name.clone(), body);
                wrote = true;
            }
        }
    }
    wrote
}

/// The note the generated file's plan row carries for the sources held back
/// from it: each named, with what would release it. `None` when nothing was
/// held back.
#[must_use]
pub fn note(held: &[&BlockedEntry]) -> Option<String> {
    (!held.is_empty()).then(|| {
        held.iter()
            .map(|entry| format!("source `{}` held back: {}", entry.key, entry.hint))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

/// Every declared source whose file is not readable, in declaration order.
///
/// `sources` are the enabled sources as [`resolve`] resolved them; a held-back
/// one has no path yet and is the plan note's to name, so it is skipped.
/// `readable` answers whether a file is readable. This function asks nothing
/// of the filesystem itself, and never opens a file: it is the check
/// `bx doctor` calls, with `readable` the one question it puts to the disk.
#[must_use]
pub fn missing<'a>(
    sources: &'a [Resolution<Source>],
    home: &Path,
    readable: &dyn Fn(&Path) -> bool,
) -> Vec<&'a Source> {
    sources
        .iter()
        .filter_map(|source| match source {
            Resolution::Ready(source) => Some(source),
            Resolution::Blocked(_) => None,
        })
        .filter(|source| !readable(&source.location(home)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::shell::testing::{installed, run};

    const FILE: &str = "/repo/bx.toml";
    const HOME: &str = "/home/u";

    fn load(text: &str) -> Result<crate::config::Config, String> {
        parse_str(text, Path::new(FILE), Path::new(HOME)).map_err(|e| e.to_string())
    }

    /// Parse `text` as one layer, resolve its values, and resolve its sources
    /// against them.
    fn resolved(text: &str) -> Result<Vec<Resolution<Source>>, String> {
        let config = load(text)?;
        let values =
            ResolvedValues::resolve(config.values, &config.value_assignments, Path::new(HOME))
                .map_err(|e| e.to_string())?;
        resolve(&config.sources, &values).map_err(|e| e.to_string())
    }

    fn origin(line: usize) -> Origin {
        Origin {
            file: PathBuf::from(FILE),
            line,
        }
    }

    fn source(name: &str, path: &str, phase: Phase, when: Option<&str>) -> Source {
        Source {
            name: name.to_string(),
            path: path.to_string(),
            phase,
            when: when.map(|w| When::parse(w).expect("a condition")),
            origin: origin(1),
        }
    }

    fn render_all(sources: &[Resolution<Source>], present: &dyn Fn(&str) -> bool) -> String {
        let mut assembly = Assembly::new();
        contribute(&mut assembly, sources, Shell::Zsh, present);
        assembly.render()
    }

    #[test]
    fn an_entry_parses_every_key() {
        let config = load(
            "[[source]]\nname = \"keychain\"\npath = \"~/.keychain/{{host}}-sh\"\n\
             phase = \"activations\"\nwhen = \"interactive\"\n\
             [[source]]\nname = \"fzf\"\npath = \"~/.fzf.zsh\"\nenabled = false\n\
             shells = [\"zsh\"]\n",
        )
        .expect("parses");
        assert_eq!(
            config.sources,
            vec![
                SourceDecl {
                    name: "keychain".to_string(),
                    path: "~/.keychain/{{host}}-sh".to_string(),
                    phase: Phase::Activations,
                    when: Some(When::Interactive),
                    shells: Shells::EVERY,
                    enabled: true,
                    origin: origin(1),
                },
                SourceDecl {
                    name: "fzf".to_string(),
                    path: "~/.fzf.zsh".to_string(),
                    phase: DEFAULT_PHASE,
                    when: None,
                    shells: Shells::only(Shell::Zsh),
                    enabled: false,
                    origin: origin(6),
                },
            ]
        );
        assert_eq!(DEFAULT_PHASE, Phase::Plugins);
    }

    #[test]
    fn every_admitted_phase_parses_and_every_other_is_refused_saying_why() {
        for phase in Phase::ALL {
            let parsed = parse_phase(phase.name());
            if PHASES.contains(&phase) {
                assert_eq!(parsed, Ok(phase));
                assert!(!phase.assigns(), "{phase:?}");
            } else {
                let err = parsed.expect_err(phase.name());
                assert!(err.contains("\"activations\""), "{err}");
                assert!(err.contains("\"options\""), "{err}");
                assert!(!err.contains("\"terminal\","), "{err}");
            }
        }
        assert!(PHASES.is_sorted());
        for (raw, why) in [
            ("terminal", "a source never claims it"),
            ("env", "environment fragments"),
            ("path", "environment fragments"),
            ("completion", "completion system's own setup"),
        ] {
            let err = parse_phase(raw).expect_err(raw);
            assert!(err.contains(why), "{raw}: {err}");
        }
        let err = parse_phase("early").expect_err("not a phase");
        assert!(err.ends_with("got \"early\""), "{err}");
    }

    #[test]
    fn a_name_declared_twice_in_one_file_fails_the_load() {
        for text in [
            "[[source]]\nname = \"s\"\npath = \"~/a\"\n[[source]]\nname = \"s\"\npath = \"~/b\"\n",
            "[[source]]\nname = \"s\"\npath = \"~/a\"\n[[source]]\nname = \"s\"\nenabled = false\n",
        ] {
            let err = load(text).expect_err(text);
            assert!(err.contains("duplicate source `s`"), "{text}: {err}");
            assert!(err.contains("first declared at /repo/bx.toml:1"), "{err}");
        }
    }

    #[test]
    fn a_malformed_source_is_refused_naming_why() {
        for (body, needle) in [
            ("path = \"~/a\"\n", "`name`"),
            ("name = \"s\"\n", "`path`"),
            ("name = \"\"\npath = \"~/a\"\n", "not a source name"),
            ("name = \"a\\nb\"\npath = \"~/a\"\n", "not a source name"),
            ("name = \"s\"\npath = 1\n", "`path` must be a string"),
            (
                "name = \"s\"\npath = \"a.zsh\"\n",
                "`path = \"a.zsh\"` must open with",
            ),
            ("name = \"s\"\npath = \"~a.zsh\"\n", "must open with"),
            ("name = \"s\"\npath = \"~/a b\"\n", "found ' '"),
            ("name = \"s\"\npath = \"~/a;id\"\n", "found ';'"),
            ("name = \"s\"\npath = \"~/$HOST-sh\"\n", "found '$'"),
            (
                "name = \"s\"\npath = \"~/{{x\"\n",
                "unterminated placeholder",
            ),
            ("name = \"s\"\npath = \"~/{{X}}\"\n", "not a value name"),
            (
                "name = \"s\"\npath = \"~/a\"\nphase = \"terminal\"\n",
                "never claims",
            ),
            ("name = \"s\"\npath = \"~/a\"\nphase = 1\n", "a string"),
            (
                "name = \"s\"\npath = \"~/a\"\nwhen = \"tty\"\n",
                "`when` must be one of",
            ),
            (
                "name = \"s\"\npath = \"~/a\"\nenabled = \"no\"\n",
                "a boolean",
            ),
            (
                "name = \"s\"\npath = \"~/a\"\nsource = \"~/b\"\n",
                "unknown key `source`",
            ),
        ] {
            let text = format!("[[source]]\n{body}");
            let err = load(&text).expect_err(body);
            assert!(err.contains(needle), "{body}: {err}");
            // A source's file is its `path`; the message never names the
            // `source` key `[[source]]` refuses.
            assert!(!err.contains("`source = "), "{body}: {err}");
            assert!(err.starts_with("/repo/bx.toml:"), "{body}: {err}");
        }
    }

    #[test]
    fn an_account_specific_path_is_a_declared_value_substituted_into_it() {
        let sources = resolved(
            "[[value]]\nname = \"bun_home\"\nkind = \"path\"\n\
             [[value]]\nname = \"host\"\nkind = \"string\"\n\
             [values]\nbun_home = \"~/.bun\"\nhost = \"box-1\"\n\
             [[source]]\nname = \"bun\"\npath = \"{{bun_home}}/_bun\"\nphase = \"completions\"\n\
             [[source]]\nname = \"keychain\"\npath = \"~/.keychain/{{host}}-sh\"\n",
        )
        .expect("resolves");
        let [Resolution::Ready(bun), Resolution::Ready(keychain)] = sources.as_slice() else {
            panic!("{sources:?}");
        };
        assert_eq!(bun.path, "/home/u/.bun/_bun");
        assert_eq!(bun.phase, Phase::Completions);
        assert_eq!(
            bun.line(),
            "[[ -r /home/u/.bun/_bun ]] && source /home/u/.bun/_bun\n"
        );
        assert_eq!(keychain.path, "~/.keychain/box-1-sh");
        assert_eq!(
            keychain.location(Path::new(HOME)),
            Path::new("/home/u/.keychain/box-1-sh")
        );
        assert_eq!(
            bun.location(Path::new(HOME)),
            Path::new("/home/u/.bun/_bun")
        );
    }

    #[test]
    fn an_unanswered_value_holds_back_only_its_source_and_the_note_names_it() {
        let text = "[[value]]\nname = \"host\"\nkind = \"string\"\n\
                    [[source]]\nname = \"first\"\npath = \"~/.fzf.zsh\"\n\
                    [[source]]\nname = \"keychain\"\npath = \"~/.keychain/{{host}}-sh\"\n\
                    [[source]]\nname = \"last\"\npath = \"~/.aliases\"\n";
        let sources = resolved(text).expect("an unset value is not a load error");
        let rendered = render_all(&sources, &|_| true);
        assert!(rendered.contains("source ~/.fzf.zsh\n"), "{rendered}");
        assert!(rendered.contains("source ~/.aliases\n"), "{rendered}");
        assert!(!rendered.contains("keychain"), "{rendered}");
        let held: Vec<&BlockedEntry> = sources
            .iter()
            .filter_map(|s| match s {
                Resolution::Blocked(entry) => Some(entry),
                Resolution::Ready(_) => None,
            })
            .collect();
        assert_eq!(
            held[0].reason,
            BlockReason::UnsetValue {
                names: vec!["host".to_string()]
            }
        );
        assert_eq!(
            note(&held).as_deref(),
            Some("source `keychain` held back: run `bx init` to set host")
        );
        assert_eq!(note(&[]), None);

        let answered = resolved(&format!("{text}[values]\nhost = \"h\"\n")).expect("resolves");
        assert!(answered.iter().all(|s| matches!(s, Resolution::Ready(_))));
    }

    #[test]
    fn a_switched_off_or_unusable_value_holds_the_source_back_too() {
        let off = resolved(
            "[[value]]\nname = \"h\"\nkind = \"string\"\ndefault = \"x\"\nenabled = false\n\
             [[source]]\nname = \"s\"\npath = \"~/{{h}}\"\n",
        )
        .expect("resolves");
        let [Resolution::Blocked(entry)] = off.as_slice() else {
            panic!("{off:?}");
        };
        assert!(matches!(entry.reason, BlockReason::DisabledValue { .. }));

        let unusable = resolved(
            "[[value]]\nname = \"root\"\nkind = \"path\"\n\
             [values]\nroot = \"relative\"\n\
             [[source]]\nname = \"s\"\npath = \"{{root}}/a\"\n",
        )
        .expect("resolves");
        let [Resolution::Blocked(entry)] = unusable.as_slice() else {
            panic!("{unusable:?}");
        };
        assert!(matches!(entry.reason, BlockReason::InvalidValue { .. }));

        // An answer that brings a blank into the path blocks it, naming the
        // answer's line.
        let blank = resolved(
            "[[value]]\nname = \"h\"\nkind = \"string\"\n\
             [values]\nh = \"my box\"\n\
             [[source]]\nname = \"s\"\npath = \"~/.keychain/{{h}}-sh\"\n",
        )
        .expect("resolves");
        let [Resolution::Blocked(entry)] = blank.as_slice() else {
            panic!("{blank:?}");
        };
        assert!(matches!(entry.reason, BlockReason::InvalidValue { .. }));
        assert!(entry.hint.contains("found ' '"), "{}", entry.hint);
        assert!(
            entry.hint.contains("`path = \"~/.keychain/my box-sh\"`"),
            "{}",
            entry.hint
        );
        assert!(
            entry.hint.contains("the answer to `h` at /repo/bx.toml:5"),
            "{}",
            entry.hint
        );
    }

    #[test]
    fn a_repo_defect_in_a_path_fails_the_load() {
        let err = resolved("[[source]]\nname = \"s\"\npath = \"~/{{nobody}}\"\n")
            .expect_err("an undeclared value");
        assert!(err.contains("source `s`"), "{err}");
        assert!(err.contains("`nobody`"), "{err}");
        // A committed default alone makes the path unwritable.
        let err = resolved(
            "[[value]]\nname = \"h\"\nkind = \"string\"\ndefault = \"a;b\"\n\
             [[source]]\nname = \"s\"\npath = \"~/{{h}}\"\n",
        )
        .expect_err("no answer can clear it");
        assert!(err.contains("found ';'"), "{err}");
        assert!(err.contains("`path = \"~/a;b\"`"), "{err}");
        // A disabled source is not read at all.
        let none = resolved("[[source]]\nname = \"s\"\npath = \"~/{{nobody}}\"\nenabled = false\n")
            .expect("a disabled path is not read");
        assert!(none.is_empty());
    }

    #[test]
    fn each_source_is_one_guarded_line_in_its_phase_in_declaration_order() {
        let sources = [
            Resolution::Ready(source("b", "~/b.zsh", Phase::Plugins, None)),
            Resolution::Ready(source("k", "~/.keychain/h-sh", Phase::Activations, None)),
            Resolution::Ready(source("a", "/opt/a.zsh", Phase::Plugins, None)),
            Resolution::Ready(source("ssh", "~/s", Phase::Options, Some("ssh"))),
            Resolution::Ready(source("bat", "~/bat", Phase::Aliases, Some("has:bat"))),
        ];
        let mut assembly = Assembly::new();
        assert!(contribute(&mut assembly, &sources, Shell::Zsh, &|_| false));
        let rendered = assembly.render();
        // bash reads the same lines, and asks a runtime condition in its own
        // words.
        let mut bash = Assembly::new();
        assert!(contribute(&mut bash, &sources, Shell::Bash, &|_| false));
        assert_eq!(bash.render(), rendered);
        let login = [Resolution::Ready(source(
            "l",
            "~/l",
            Phase::Plugins,
            Some("login"),
        ))];
        let mut bash = Assembly::new();
        contribute(&mut bash, &login, Shell::Bash, &|_| false);
        assert!(
            bash.render()
                .ends_with("if shopt -q login_shell; then\n  [[ -r ~/l ]] && source ~/l\nfi\n"),
            "{}",
            bash.render()
        );
        assert_eq!(
            rendered,
            "# Generated by bx. Edit the config repo, not this file.\n\
             \n# bx phase: activations\n\
             [[ -r ~/.keychain/h-sh ]] && source ~/.keychain/h-sh\n\
             \n# bx phase: plugins\n\
             [[ -r ~/b.zsh ]] && source ~/b.zsh\n\
             [[ -r /opt/a.zsh ]] && source /opt/a.zsh\n\
             \n# bx phase: options\n\
             if [[ -n ${SSH_CONNECTION-} ]]; then\n  [[ -r ~/s ]] && source ~/s\nfi\n"
        );
        let with_bat = render_all(&sources, &|tool| tool == "bat");
        assert!(
            with_bat.contains("\n# bx phase: aliases\n[[ -r ~/bat ]] && source ~/bat\n"),
            "{with_bat}"
        );

        // Nothing written: every source held back or gated off.
        let gated = [Resolution::Ready(source(
            "bat",
            "~/bat",
            Phase::Plugins,
            Some("has:bat"),
        ))];
        let mut empty = Assembly::new();
        assert!(!contribute(&mut empty, &gated, Shell::Zsh, &|_| false));
        assert!(empty.is_empty());
    }

    #[test]
    fn rendering_twice_is_byte_identical_whether_or_not_the_files_exist() {
        let text = "[[source]]\nname = \"a\"\npath = \"~/a.zsh\"\n\
                    [[source]]\nname = \"b\"\npath = \"/b.zsh\"\nphase = \"functions\"\n";
        let sources = resolved(text).expect("resolves");
        let once = render_all(&sources, &|_| true);
        assert_eq!(render_all(&sources, &|_| true), once);

        // In zsh, with the files absent and then present: the same bytes load
        // either way, and only a present file's own code runs.
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let file = scratch.path().join("present.zsh");
        let decl = format!("[[source]]\nname = \"p\"\npath = \"{}\"\n", file.display());
        let sources = resolved(&decl).expect("resolves");
        let bytes = render_all(&sources, &|_| true);
        let absent = run(&zsh, &["-f"], &format!("{bytes}print -r -- after\n"));
        assert_eq!(absent, b"after\n");
        std::fs::write(&file, "print -r -- sourced\n").expect("written");
        assert_eq!(
            render_all(&sources, &|_| true),
            bytes,
            "the bytes follow no file"
        );
        let present = run(&zsh, &["-f"], &format!("{bytes}print -r -- after\n"));
        assert_eq!(present, b"sourced\nafter\n");
    }

    #[test]
    fn the_missing_check_names_each_unreadable_source_in_order_and_touches_nothing() {
        let held = Resolution::Blocked(BlockedEntry {
            key: "held".to_string(),
            origin: origin(9),
            reason: BlockReason::UnsetValue {
                names: vec!["host".to_string()],
            },
            hint: "run `bx init` to set host".to_string(),
        });
        let sources = [
            Resolution::Ready(source("z", "~/z", Phase::Plugins, None)),
            Resolution::Ready(source("there", "/etc/there", Phase::Plugins, None)),
            held,
            Resolution::Ready(source("a", "/opt/a", Phase::Options, Some("has:gone"))),
        ];
        let asked = std::cell::RefCell::new(Vec::new());
        let readable = |path: &Path| {
            asked.borrow_mut().push(path.to_path_buf());
            path == Path::new("/etc/there")
        };
        let missing = missing(&sources, Path::new("/nonexistent-home"), &readable);
        let names: Vec<&str> = missing.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["z", "a"],
            "declaration order, the readable one left out"
        );
        assert_eq!(
            *asked.borrow(),
            [
                PathBuf::from("/nonexistent-home/z"),
                PathBuf::from("/etc/there"),
                PathBuf::from("/opt/a"),
            ],
            "only ready sources are asked about, and only through `readable`"
        );
        assert!(super::missing(&[], Path::new(HOME), &|_| panic!("nothing to ask")).is_empty());
    }

    #[test]
    fn a_source_line_sets_nothing() {
        // Invariant 2: a source line is generated shell content that is not
        // an environment fragment. It is a test and a `source`, word for word.
        let line = source("s", "~/.keychain/h-sh", Phase::Activations, None).line();
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            words,
            [
                "[[",
                "-r",
                "~/.keychain/h-sh",
                "]]",
                "&&",
                "source",
                "~/.keychain/h-sh"
            ]
        );
        assert!(!line.contains('='), "{line}");
    }
}
