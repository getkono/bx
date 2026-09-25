//! The closed set of conditions a declaration may be gated on.
//!
//! A declared line — an environment variable today, an alias or a function
//! later — may say **when** it applies with one `when = "…"` string. The set is
//! closed and fixed: six spellings, each of which renders to a plain shell test
//! that spawns nothing, or is decided by bx itself and vanishes from the
//! generated shell entirely.
//!
//! | spelling           | holds when                                  | renders as                          |
//! |--------------------|---------------------------------------------|-------------------------------------|
//! | `interactive`      | the shell is interactive                    | `[[ -o interactive ]]`              |
//! | `login`            | the shell is a login shell                  | `[[ -o login ]]`                    |
//! | `ssh`              | the session came in over SSH                | `[[ -n ${SSH_CONNECTION-} ]]`       |
//! | `env:NAME`         | `NAME` is set, to anything, empty included  | `[[ -n ${NAME+x} ]]`                |
//! | `env:NAME=VALUE`   | `NAME` is set to exactly `VALUE`            | `[[ ${NAME-} == "VALUE" ]]`         |
//! | `has:TOOL`         | `TOOL` is installed and executable          | nothing: decided at `plan`/`apply`  |
//!
//! `has:TOOL` is never a runtime `command -v`: bx looks the tool up once, when
//! `plan` or `apply` renders the fragment, through [`crate::detect`], and the
//! gated line is written unconditionally when the tool is usable and left out
//! when it is not. Installing the tool later makes the next `plan` show the
//! line arriving.
//!
//! Every other spelling is a runtime test, and a runtime-gated line is always
//! written as a **guarded block** — an `if TEST; then` line, the assignment on
//! its own line, and `fi` — never inlined as `TEST && export …`. The guard
//! ([`crate::env_guard`]) reads the opener and the `fi` as statements of their
//! own and judges the assignment between them exactly as it judges any other,
//! so a relocating export hidden behind a condition is still refused.
//!
//! `environment.d` cannot run a test, so a variable that lands there may be
//! gated only on `has:TOOL`; any other `when` is refused when the config loads.
//!
//! One condition per declaration: there is no `and`, `or` or `not`.

use crate::env_guard::is_variable_name;

/// Every spelling, as an error message lists them.
const SPELLINGS: &str = "\"interactive\", \"login\", \"ssh\", \"env:NAME\", \"env:NAME=VALUE\" \
                         or \"has:TOOL\"";

/// A condition a declaration is gated on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum When {
    /// The shell is interactive.
    Interactive,
    /// The shell is a login shell.
    Login,
    /// The session came in over SSH.
    Ssh,
    /// The named variable is set, to anything.
    EnvSet(String),
    /// The named variable is set to exactly this value.
    EnvEquals {
        /// The variable's name.
        name: String,
        /// The value it must hold, compared literally.
        value: String,
    },
    /// The named tool is installed: a bare name looked up on `PATH`, or an
    /// absolute path. Decided by bx, never by the shell.
    Has(String),
}

/// What a condition comes to once bx has decided everything it can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// Write the line unconditionally.
    Always,
    /// Leave the line out.
    Never,
    /// Write the line inside a block guarded by this shell test.
    Test(String),
}

impl When {
    /// Read a `when` string a config author wrote.
    ///
    /// # Errors
    ///
    /// Why `raw` is not one of the six spellings, or why its operand is not
    /// one the rendered test can hold.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let unknown = || format!("`when` must be one of {SPELLINGS}, got {raw:?}");
        match raw {
            "interactive" => return Ok(Self::Interactive),
            "login" => return Ok(Self::Login),
            "ssh" => return Ok(Self::Ssh),
            _ => {}
        }
        if let Some(operand) = raw.strip_prefix("env:") {
            let (name, value) = match operand.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (operand, None),
            };
            if !is_variable_name(name) {
                return Err(format!(
                    "`when = {raw:?}`: `{name}` is not an environment variable name: a name \
                     starts with a letter or `_` and holds only ASCII letters, digits and `_`"
                ));
            }
            return match value {
                None => Ok(Self::EnvSet(name.to_string())),
                Some(value) => match uncomparable(value) {
                    Some(problem) => Err(format!("`when = {raw:?}`: {problem}")),
                    None => Ok(Self::EnvEquals {
                        name: name.to_string(),
                        value: value.to_string(),
                    }),
                },
            };
        }
        if let Some(tool) = raw.strip_prefix("has:") {
            return match unfindable(tool) {
                Some(problem) => Err(format!("`when = {raw:?}`: {problem}")),
                None => Ok(Self::Has(tool.to_string())),
            };
        }
        Err(unknown())
    }

    /// Whether the condition is a test the shell runs, rather than one bx
    /// decides while it plans.
    #[must_use]
    pub const fn is_runtime(&self) -> bool {
        !matches!(self, Self::Has(_))
    }

    /// The shell test a runtime condition renders to, or `None` for one bx
    /// decides itself.
    #[must_use]
    pub fn test(&self) -> Option<String> {
        Some(match self {
            Self::Interactive => "[[ -o interactive ]]".to_string(),
            Self::Login => "[[ -o login ]]".to_string(),
            Self::Ssh => "[[ -n ${SSH_CONNECTION-} ]]".to_string(),
            Self::EnvSet(name) => format!("[[ -n ${{{name}+x}} ]]"),
            Self::EnvEquals { name, value } => format!("[[ ${{{name}-}} == \"{value}\" ]]"),
            Self::Has(_) => return None,
        })
    }

    /// The test a runtime condition renders to in bash, or `None` for one bx
    /// decides itself.
    ///
    /// bash's `[[ -o NAME ]]` tests only `set -o` options, and neither
    /// `interactive` nor `login` is one, so those two are asked the way bash
    /// answers them: `$-` holds `i` in an interactive shell, and
    /// `login_shell` is the read-only option bash sets for a login shell.
    /// Every other test is the one [`When::test`] writes, which bash reads
    /// alike.
    #[must_use]
    pub fn test_bash(&self) -> Option<String> {
        match self {
            Self::Interactive => Some("[[ $- == *i* ]]".to_string()),
            Self::Login => Some("shopt -q login_shell".to_string()),
            other => other.test(),
        }
    }

    /// Decide what bx can: a tool's presence through `present`, asked once
    /// per call, and nothing about the shell, which is left as a test.
    #[must_use]
    pub fn gate(&self, present: &dyn Fn(&str) -> bool) -> Gate {
        self.gate_with(present, Self::test)
    }

    /// [`When::gate`], leaving the shell a test in bash's words
    /// ([`When::test_bash`]).
    #[must_use]
    pub fn gate_bash(&self, present: &dyn Fn(&str) -> bool) -> Gate {
        self.gate_with(present, Self::test_bash)
    }

    /// Decide a tool's presence through `present`, and render any other
    /// condition through `test`.
    fn gate_with(&self, present: &dyn Fn(&str) -> bool, test: fn(&Self) -> Option<String>) -> Gate {
        match self {
            Self::Has(tool) => {
                if present(tool) {
                    Gate::Always
                } else {
                    Gate::Never
                }
            }
            runtime => Gate::Test(test(runtime).unwrap_or_default()),
        }
    }
}

/// The line that opens a block guarded by `test`.
#[must_use]
pub fn opener(test: &str) -> String {
    format!("if {test}; then")
}

/// The line that closes a guarded block.
pub const CLOSER: &str = "fi";

/// Whether `line`, stripped of its indentation, is the opener of a block one
/// of the runtime conditions renders — exactly, byte for byte.
///
/// The guard asks this of every line it reads, so the only openers it accepts
/// are the ones [`When::test`] can produce: the test is read back into a
/// condition and rendered again, and anything that does not come back
/// identical is not an opener.
#[must_use]
pub fn is_opener(line: &str) -> bool {
    line.strip_prefix("if ")
        .and_then(|rest| rest.strip_suffix("; then"))
        .and_then(read_test)
        .is_some()
}

/// The runtime condition `test` is the rendering of, if it is one.
fn read_test(test: &str) -> Option<When> {
    let inner = test.strip_prefix("[[ ")?.strip_suffix(" ]]")?;
    let candidate = match inner {
        "-o interactive" => When::Interactive,
        "-o login" => When::Login,
        "-n ${SSH_CONNECTION-}" => When::Ssh,
        _ => {
            if let Some(name) = inner
                .strip_prefix("-n ${")
                .and_then(|rest| rest.strip_suffix("+x}"))
            {
                When::EnvSet(name.to_string())
            } else {
                let (lhs, rhs) = inner.split_once(" == ")?;
                let name = lhs.strip_prefix("${")?.strip_suffix("-}")?;
                let value = rhs.strip_prefix('"')?.strip_suffix('"')?;
                When::EnvEquals {
                    name: name.to_string(),
                    value: value.to_string(),
                }
            }
        }
    };
    let valid = match &candidate {
        When::EnvSet(name) => is_variable_name(name),
        When::EnvEquals { name, value } => is_variable_name(name) && uncomparable(value).is_none(),
        _ => true,
    };
    (valid && candidate.test().as_deref() == Some(test)).then_some(candidate)
}

/// Why `value` cannot be compared against inside the double quotes the test
/// writes it in, or `None` when it can.
///
/// Printable ASCII only, and none of the characters a double-quoted word gives
/// meaning to: `"`, `\`, `` ` ``, `$` and `!`. Empty is refused too, since
/// `env:NAME=` reads as a typo for `env:NAME`.
fn uncomparable(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(
            "the value to compare against is empty; write `env:NAME` to test only that the \
             variable is set"
                .to_string(),
        );
    }
    value
        .chars()
        .find(|c| !(' '..='~').contains(c) || matches!(c, '"' | '\\' | '`' | '$' | '!'))
        .map(|c| {
            format!(
                "the value to compare against is written inside double quotes, so it holds \
                 only printable ASCII other than `\"`, `\\`, `` ` ``, `$` and `!`; found {c:?}"
            )
        })
}

/// Why `tool` is not a tool detection could find, or `None` when it is.
///
/// A bare name of ASCII letters, digits, `.`, `_`, `+` and `-`, not made only
/// of dots, or an absolute path of such segments.
pub(crate) fn unfindable(tool: &str) -> Option<String> {
    let segment = |s: &str| {
        !s.is_empty()
            && s.chars().any(|c| c != '.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
    };
    let findable = match tool.strip_prefix('/') {
        Some(path) => path.split('/').all(segment),
        None => segment(tool),
    };
    (!findable).then(|| {
        format!(
            "`has:` names a tool by a bare name to look up on `PATH`, or by an absolute path, \
             of ASCII letters, digits, `.`, `_`, `+` and `-`; got {tool:?}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_parses_and_renders_its_documented_test() {
        for (raw, when, test) in [
            (
                "interactive",
                When::Interactive,
                Some("[[ -o interactive ]]"),
            ),
            ("login", When::Login, Some("[[ -o login ]]")),
            ("ssh", When::Ssh, Some("[[ -n ${SSH_CONNECTION-} ]]")),
            (
                "env:TMUX",
                When::EnvSet("TMUX".to_string()),
                Some("[[ -n ${TMUX+x} ]]"),
            ),
            (
                "env:TERM_PROGRAM=WezTerm 2",
                When::EnvEquals {
                    name: "TERM_PROGRAM".to_string(),
                    value: "WezTerm 2".to_string(),
                },
                Some("[[ ${TERM_PROGRAM-} == \"WezTerm 2\" ]]"),
            ),
            ("has:sccache", When::Has("sccache".to_string()), None),
            (
                "has:/usr/bin/sccache",
                When::Has("/usr/bin/sccache".to_string()),
                None,
            ),
        ] {
            let parsed = When::parse(raw).expect(raw);
            assert_eq!(parsed, when, "{raw}");
            assert_eq!(parsed.test().as_deref(), test, "{raw}");
            assert_eq!(parsed.is_runtime(), test.is_some(), "{raw}");
            if let Some(test) = test {
                assert!(is_opener(&opener(test)), "{raw}");
                assert_eq!(
                    parsed.gate(&|_| unreachable!()),
                    Gate::Test(test.to_string())
                );
            }
        }
    }

    #[test]
    fn an_unrecognised_spelling_is_refused_listing_all_six() {
        for raw in [
            "",
            "Interactive",
            "tty",
            "has",
            "env",
            "interactive && login",
            "not:ssh",
        ] {
            let err = When::parse(raw).expect_err(raw);
            assert!(err.contains(SPELLINGS), "{raw}: {err}");
        }
    }

    #[test]
    fn a_bad_operand_is_refused_naming_why() {
        for (raw, needle) in [
            ("env:", "not an environment variable name"),
            ("env:1X", "not an environment variable name"),
            ("env:A-B=x", "not an environment variable name"),
            ("env:X=", "empty"),
            ("env:X=a\"b", "double quotes"),
            ("env:X=$HOME", "double quotes"),
            ("env:X=a`id`", "double quotes"),
            ("env:X=a\\b", "double quotes"),
            ("env:X=a!b", "double quotes"),
            ("env:X=a\nb", "double quotes"),
            ("env:X=é", "double quotes"),
            ("has:", "`has:`"),
            ("has:..", "`has:`"),
            ("has:bin/tool", "`has:`"),
            ("has:/usr//bin/x", "`has:`"),
            ("has:/usr/bin/", "`has:`"),
            ("has:to ol", "`has:`"),
            ("has:$(id)", "`has:`"),
            ("has:{{tool}}", "`has:`"),
        ] {
            let err = When::parse(raw).expect_err(raw);
            assert!(err.contains(needle), "{raw}: {err}");
        }
    }

    #[test]
    fn tool_presence_is_decided_by_the_caller_and_never_rendered() {
        let has = When::Has("sccache".to_string());
        assert_eq!(has.gate(&|tool| tool == "sccache"), Gate::Always);
        assert_eq!(has.gate(&|_| false), Gate::Never);
        assert_eq!(has.test(), None);
        assert_eq!(has.gate_bash(&|tool| tool == "sccache"), Gate::Always);
        assert_eq!(has.gate_bash(&|_| false), Gate::Never);
        assert_eq!(has.test_bash(), None);
    }

    #[test]
    fn bash_asks_interactive_and_login_its_own_way_and_the_rest_alike() {
        for (when, test) in [
            (When::Interactive, "[[ $- == *i* ]]"),
            (When::Login, "shopt -q login_shell"),
        ] {
            assert_eq!(when.test_bash().as_deref(), Some(test), "{when:?}");
            assert_ne!(when.test(), when.test_bash(), "{when:?}");
            assert_eq!(
                when.gate_bash(&|_| unreachable!()),
                Gate::Test(test.to_string())
            );
        }
        for when in [
            When::Ssh,
            When::EnvSet("TMUX".to_string()),
            When::EnvEquals {
                name: "T".to_string(),
                value: "a b".to_string(),
            },
        ] {
            assert_eq!(when.test_bash(), when.test(), "{when:?}");
        }
    }

    #[test]
    fn bash_answers_each_runtime_test_as_the_condition_means() {
        let Some(bash) = crate::shell::testing::installed("bash") else {
            return;
        };
        let probe = |flags: &[&str], when: &When, setup: &str| {
            let test = when.test_bash().expect("a runtime test");
            let script = format!("{setup}if {test}; then echo yes; else echo no; fi\n");
            String::from_utf8(crate::shell::testing::run(&bash, flags, &script)).expect("utf-8")
        };
        assert_eq!(probe(&["--norc", "-i"], &When::Interactive, ""), "yes\n");
        assert_eq!(probe(&[], &When::Interactive, ""), "no\n");
        assert_eq!(probe(&["--noprofile", "-l"], &When::Login, ""), "yes\n");
        assert_eq!(probe(&[], &When::Login, ""), "no\n");
        let tmux = When::EnvSet("TMUX".to_string());
        assert_eq!(probe(&[], &tmux, "TMUX=\n"), "yes\n");
        assert_eq!(probe(&[], &tmux, ""), "no\n");
        let term = When::EnvEquals {
            name: "T".to_string(),
            value: "a *".to_string(),
        };
        assert_eq!(probe(&[], &term, "T='a *'\n"), "yes\n");
        assert_eq!(probe(&[], &term, "T='a b'\n"), "no\n");
    }

    #[test]
    fn only_an_exact_rendering_is_an_opener() {
        for line in [
            "if [[ -o interactive ]]; then",
            "if [[ -n ${SSH_CONNECTION-} ]]; then",
            "if [[ -n ${X+x} ]]; then",
            "if [[ ${X-} == \"a b\" ]]; then",
        ] {
            assert!(is_opener(line), "{line}");
        }
        for line in [
            "if [[ -o interactive ]]; then :",
            "if [[ -o interactive ]] ; then",
            "if [[ -o  login ]]; then",
            "if [[ -o monitor ]]; then",
            "if [[ -n ${X+y} ]]; then",
            "if [[ -n ${1X+x} ]]; then",
            "if [[ -n $(id) ]]; then",
            "if [[ ${X-} == \"$(id)\" ]]; then",
            "if [[ ${X-} == \"\" ]]; then",
            "if [[ ${X-} == \"a\" || -o login ]]; then",
            "if [[ ${X-} == a ]]; then",
            "if [[ ${X:-} == \"a\" ]]; then",
            "if command -v sccache; then",
            "if true; then",
            "[[ -o interactive ]] && export X=y",
            "fi",
        ] {
            assert!(!is_opener(line), "{line}");
        }
    }
}
