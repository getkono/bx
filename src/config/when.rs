//! The closed set of conditions a declaration may be gated on.
//!
//! A declared line — an environment variable, an alias, a source or a
//! function's hook — may say **when** it applies with a `when = "…"` string.
//! The set is closed and fixed: each spelling renders to a plain shell test
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
//! | `os:OS`            | the running OS is `linux` or `macos`        | nothing: decided at `plan`/`apply`  |
//! | `arch:ARCH`        | the CPU is `x86_64` or `aarch64`            | nothing: decided at `plan`/`apply`  |
//! | `host:NAME`        | the short hostname is `NAME`, in any case   | nothing: decided at `plan`/`apply`  |
//! | `user:NAME`        | the account is `NAME` (`$USER`, `$LOGNAME`) | nothing: decided at `plan`/`apply`  |
//! | `distro:ID`        | os-release's `ID` or `ID_LIKE` names `ID`   | nothing: decided at `plan`/`apply`  |
//!
//! `has:TOOL` is never a runtime `command -v`: bx looks the tool up once, when
//! `plan` or `apply` renders the fragment, through [`crate::detect`], and the
//! gated line is written unconditionally when the tool is usable and left out
//! when it is not. Installing the tool later makes the next `plan` show the
//! line arriving.
//!
//! The machine's facts — `os:`, `arch:`, `host:`, `user:` and `distro:` — are
//! decided the same way, against the [`Machine`] `plan::Inputs::load` reads
//! once: the OS and architecture bx was built for, the kernel's node name cut
//! at its first `.`, `$USER` (or `$LOGNAME`), and `/etc/os-release` (or
//! `/usr/lib/os-release`), which is read on Linux only. A fact that changes —
//! a renamed host — makes the next `plan` show the line arriving or leaving.
//!
//! Every other spelling is a runtime test, and a runtime-gated line is always
//! written as a **guarded block** — an `if TEST; then` line, the assignment on
//! its own line, and `fi` — never inlined as `TEST && export …`. The guard
//! ([`crate::env_guard`]) reads the opener and the `fi` as statements of their
//! own and judges the assignment between them exactly as it judges any other,
//! so a relocating export hidden behind a condition is still refused.
//!
//! `environment.d` cannot run a test, so a variable that lands there may be
//! gated only on conditions bx decides; a runtime test is refused when the
//! config loads.
//!
//! An array is **all of** its conditions: `when = ["os:macos",
//! "arch:aarch64"]` holds only where both do. Within one array the conditions
//! bx decides fold first, so any that does not hold leaves the line out, and
//! **at most one** runtime test may remain — two are refused when the config
//! loads — so a guarded block keeps the single opener the guard already
//! reads. There is no `or` and no `not`.
//!
//! # Gating a whole declaration, or a whole module
//!
//! A `[[target]]`, a `[path]` entry, a `[[plugin]]`, an `[[activation]]`, an
//! `[[external]]` and a `[[tool]]` take `when` too, and so does a file in
//! `modules/`, as a top-level key that gates everything in it — say
//! `modules/macos.toml` opening with `when = "os:macos"`. These are not
//! lines in a generated file but whole declarations, kept or left out as
//! `plan` loads the configuration ([`super::layers::gate`]), so only the
//! conditions bx decides may gate them; a runtime test there, and a
//! top-level `when` in `bx.toml` or `local.toml`, which apply on every
//! machine, are refused when the config loads. Where the condition does not
//! hold the declaration is not declared on this machine: it replaces no
//! earlier layer's entry, and a later toggle naming it flips nothing. A gated
//! module may not declare a `[[value]]`, which every layer refers to by name.

use std::fmt;

use toml_edit::{Table, Value};

use super::{Ctx, Error};
use crate::lexical::is_variable_name;

/// Every spelling, as an error message lists them.
const SPELLINGS: &str = "\"interactive\", \"login\", \"ssh\", \"env:NAME\", \"env:NAME=VALUE\", \
                         \"has:TOOL\", \"os:OS\", \"arch:ARCH\", \"host:NAME\", \"user:NAME\" \
                         or \"distro:ID\"";

/// Every OS `os:` may name, as [`std::env::consts::OS`] spells it.
pub const OSES: [&str; 2] = ["linux", "macos"];

/// Every architecture `arch:` may name, as [`std::env::consts::ARCH`] spells
/// it.
pub const ARCHES: [&str; 2] = ["x86_64", "aarch64"];

/// The key a declaration's condition is written under.
pub(crate) const KEY: &str = "when";

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
    /// The running OS is this one of [`OSES`]. Decided by bx.
    Os(&'static str),
    /// The CPU architecture is this one of [`ARCHES`]. Decided by bx.
    Arch(&'static str),
    /// The short hostname is this, compared ASCII case-insensitively.
    /// Decided by bx.
    Host(String),
    /// The account is this one. Decided by bx.
    User(String),
    /// os-release's `ID` is this, or its `ID_LIKE` lists it. Decided by bx.
    Distro(String),
    /// Every one of these holds: what a `when` array spells.
    ///
    /// Built only by [`When::parse_all`], so it holds two or more
    /// conditions, none of them an `All`, and at most one runtime test.
    All(Vec<When>),
}

/// The facts about the machine a `when` condition bx decides is decided
/// against, read once by `plan::Inputs::load` ([`Machine::read`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Machine {
    /// The OS, as [`std::env::consts::OS`] spells it.
    pub os: String,
    /// The CPU architecture, as [`std::env::consts::ARCH`] spells it.
    pub arch: String,
    /// The kernel's node name, cut at its first `.`; `None` when it could
    /// not be read.
    pub host: Option<String>,
    /// The account's name, from `$USER`, else `$LOGNAME`.
    pub user: Option<String>,
    /// What os-release says the distribution is; `None` off Linux, or when
    /// it could not be read.
    pub distro: Option<Distro>,
}

/// What os-release says the distribution is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Distro {
    /// `ID`.
    pub id: String,
    /// `ID_LIKE`, split on whitespace.
    pub id_like: Vec<String>,
}

/// A machine nothing is known about: every fact is unknown, so no condition
/// on one holds.
#[cfg(test)]
static UNKNOWN: Machine = Machine {
    os: String::new(),
    arch: String::new(),
    host: None,
    user: None,
    distro: None,
};

impl Machine {
    /// This machine: the OS and architecture bx was built for, the kernel's
    /// node name, `user` (the `$USER` or `$LOGNAME` the caller read), and,
    /// on Linux, os-release.
    #[must_use]
    pub fn read(user: Option<String>) -> Self {
        let os = std::env::consts::OS;
        let distro = if os == "linux" {
            ["/etc/os-release", "/usr/lib/os-release"]
                .iter()
                .find_map(|path| std::fs::read_to_string(path).ok())
                .and_then(|text| Distro::parse(&text))
        } else {
            None
        };
        let uname = rustix::system::uname();
        Self {
            os: os.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            host: uname.nodename().to_str().ok().and_then(short_host),
            user: user.filter(|user| !user.is_empty()),
            distro,
        }
    }
}

/// `nodename` cut at its first `.`, or `None` when nothing is left.
fn short_host(nodename: &str) -> Option<String> {
    let short = nodename.split('.').next().unwrap_or_default();
    (!short.is_empty()).then(|| short.to_string())
}

impl Distro {
    /// Read `ID` and `ID_LIKE` from an os-release file's text, or `None`
    /// when it names no `ID`.
    ///
    /// Each line is `KEY=VALUE`, the value bare or quoted, as
    /// `os-release(5)` writes it; a line that is not is skipped.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut id = None;
        let mut id_like = Vec::new();
        for line in text.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            let value = unquote(value);
            match key {
                "ID" => id = Some(value),
                "ID_LIKE" => id_like = value.split_whitespace().map(str::to_string).collect(),
                _ => {}
            }
        }
        id.filter(|id| !id.is_empty())
            .map(|id| Self { id, id_like })
    }
}

/// An os-release value without its quotes and the backslashes that escape
/// a character inside them.
fn unquote(value: &str) -> String {
    let quoted = ['"', '\''].into_iter().find_map(|quote| {
        value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
    });
    let Some(inner) = quoted else {
        return value.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// What bx decides a condition against: whether a tool is usable here, and
/// the [`Machine`]'s facts.
pub trait Decide {
    /// Whether `tool`, as a `has:` condition names it, is usable here.
    fn has(&self, tool: &str) -> bool;

    /// The facts about this machine.
    fn machine(&self) -> &Machine;
}

/// A [`Decide`] answering a tool's presence through `present` and every
/// other fact from `machine`.
pub struct Facts<'a> {
    /// The facts about this machine.
    pub machine: &'a Machine,
    /// Whether a tool is usable here.
    pub present: &'a dyn Fn(&str) -> bool,
}

impl Decide for Facts<'_> {
    fn has(&self, tool: &str) -> bool {
        (self.present)(tool)
    }

    fn machine(&self) -> &Machine {
        self.machine
    }
}

/// Facts for a test that asks only about tools: `present` answers them, on a
/// machine nothing is known about, so no condition on a fact holds.
#[cfg(test)]
pub fn tools<'a>(present: &'a dyn Fn(&str) -> bool) -> Facts<'a> {
    Facts {
        machine: &UNKNOWN,
        present,
    }
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
    /// Why `raw` is not one of the spellings, or why its operand is not one
    /// the rendered test can hold or bx can decide.
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
        if let Some(os) = raw.strip_prefix("os:") {
            return one_of(&OSES, os)
                .map(Self::Os)
                .ok_or_else(|| format!("`when = {raw:?}`: `os:` names one of {}", listed(&OSES)));
        }
        if let Some(arch) = raw.strip_prefix("arch:") {
            if arch == "arm64" {
                return Err(format!(
                    "`when = {raw:?}`: bx names this architecture as the kernel does; write \
                     `arch:aarch64`"
                ));
            }
            return one_of(&ARCHES, arch).map(Self::Arch).ok_or_else(|| {
                format!("`when = {raw:?}`: `arch:` names one of {}", listed(&ARCHES))
            });
        }
        for (prefix, problem, build) in [
            (
                "host:",
                unhostable as fn(&str) -> Option<&'static str>,
                Self::Host as fn(String) -> Self,
            ),
            ("user:", unaccountable, Self::User),
            ("distro:", undistributable, Self::Distro),
        ] {
            if let Some(operand) = raw.strip_prefix(prefix) {
                return match problem(operand) {
                    Some(problem) => Err(format!("`when = {raw:?}`: {problem}; got {operand:?}")),
                    None => Ok(build(operand.to_string())),
                };
            }
        }
        Err(unknown())
    }

    /// Read a `when` array a config author wrote: all of its conditions.
    ///
    /// One condition is that condition, as a string would be.
    ///
    /// # Errors
    ///
    /// Why a member does not parse, why the array is empty, or that it holds
    /// more than one runtime test.
    pub fn parse_all<S: AsRef<str>>(raws: &[S]) -> Result<Self, String> {
        let mut all = raws
            .iter()
            .map(|raw| Self::parse(raw.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        if all.len() <= 1 {
            return all.pop().ok_or_else(|| {
                "`when = []` lists no condition; remove `when`, or name at least one".to_string()
            });
        }
        let runtime: Vec<String> = all
            .iter()
            .filter(|when| when.is_runtime())
            .map(|when| format!("{:?}", when.to_string()))
            .collect();
        if runtime.len() > 1 {
            return Err(format!(
                "`when` lists {} tests the shell runs ({}), and a list may hold at most one, \
                 beside any number of conditions bx decides",
                runtime.len(),
                runtime.join(", ")
            ));
        }
        Ok(Self::All(all))
    }

    /// Whether the condition is a test the shell runs, rather than one bx
    /// decides while it plans; for an array, whether it holds one.
    #[must_use]
    pub fn is_runtime(&self) -> bool {
        self.runtime().is_some()
    }

    /// The one runtime test this condition holds: itself, for a runtime
    /// condition; an array's runtime member, if it has one; and `None` for a
    /// condition bx decides.
    #[must_use]
    pub fn runtime(&self) -> Option<&Self> {
        match self {
            Self::Interactive
            | Self::Login
            | Self::Ssh
            | Self::EnvSet(_)
            | Self::EnvEquals { .. } => Some(self),
            Self::All(all) => all.iter().find_map(Self::runtime),
            Self::Has(_)
            | Self::Os(_)
            | Self::Arch(_)
            | Self::Host(_)
            | Self::User(_)
            | Self::Distro(_) => None,
        }
    }

    /// Whether every condition bx decides holds against `decide`; a runtime
    /// test is the shell's to decide, and counts as holding here.
    fn holds(&self, decide: &dyn Decide) -> bool {
        let machine = || decide.machine();
        match self {
            Self::Has(tool) => decide.has(tool),
            Self::Os(os) => machine().os == *os,
            Self::Arch(arch) => machine().arch == *arch,
            Self::Host(name) => machine()
                .host
                .as_deref()
                .is_some_and(|host| host.eq_ignore_ascii_case(name)),
            Self::User(name) => machine().user.as_deref() == Some(name.as_str()),
            Self::Distro(id) => machine()
                .distro
                .as_ref()
                .is_some_and(|distro| distro.id == *id || distro.id_like.contains(id)),
            Self::All(all) => all.iter().all(|when| when.holds(decide)),
            Self::Interactive
            | Self::Login
            | Self::Ssh
            | Self::EnvSet(_)
            | Self::EnvEquals { .. } => true,
        }
    }

    /// The shell test a runtime condition renders to, or `None` for one bx
    /// decides itself. An array renders its runtime member's.
    #[must_use]
    pub fn test(&self) -> Option<String> {
        Some(match self.runtime()? {
            Self::Interactive => "[[ -o interactive ]]".to_string(),
            Self::Login => "[[ -o login ]]".to_string(),
            Self::Ssh => "[[ -n ${SSH_CONNECTION-} ]]".to_string(),
            Self::EnvSet(name) => format!("[[ -n ${{{name}+x}} ]]"),
            Self::EnvEquals { name, value } => format!("[[ ${{{name}-}} == \"{value}\" ]]"),
            _ => return None,
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
    /// alike. An array renders its runtime member's.
    #[must_use]
    pub fn test_bash(&self) -> Option<String> {
        match self.runtime()? {
            Self::Interactive => Some("[[ $- == *i* ]]".to_string()),
            Self::Login => Some("shopt -q login_shell".to_string()),
            other => other.test(),
        }
    }

    /// Decide what bx can — a tool's presence and the machine's facts,
    /// through `decide`, each asked at most once per call — and nothing
    /// about the shell, which is left as a test.
    #[must_use]
    pub fn gate(&self, decide: &dyn Decide) -> Gate {
        self.gate_with(decide, Self::test)
    }

    /// Decide what bx can through `decide`, and render the runtime test that
    /// remains through `test`: [`When::test`] for zsh, and
    /// [`When::test_bash`] for bash ([`crate::shell::bash::gate`]).
    ///
    /// Any condition bx decides that does not hold leaves the line out,
    /// whatever the shell would say.
    pub(crate) fn gate_with(&self, decide: &dyn Decide, test: fn(&Self) -> Option<String>) -> Gate {
        if !self.holds(decide) {
            return Gate::Never;
        }
        match self.runtime() {
            Some(runtime) => Gate::Test(test(runtime).unwrap_or_default()),
            None => Gate::Always,
        }
    }
}

/// The spelling a config author writes: the string for one condition, and
/// a TOML array of them for [`When::All`].
impl fmt::Display for When {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interactive => f.write_str("interactive"),
            Self::Login => f.write_str("login"),
            Self::Ssh => f.write_str("ssh"),
            Self::EnvSet(name) => write!(f, "env:{name}"),
            Self::EnvEquals { name, value } => write!(f, "env:{name}={value}"),
            Self::Has(tool) => write!(f, "has:{tool}"),
            Self::Os(os) => write!(f, "os:{os}"),
            Self::Arch(arch) => write!(f, "arch:{arch}"),
            Self::Host(name) => write!(f, "host:{name}"),
            Self::User(name) => write!(f, "user:{name}"),
            Self::Distro(id) => write!(f, "distro:{id}"),
            Self::All(all) => {
                let spelled: Vec<String> = all
                    .iter()
                    .map(|when| format!("{:?}", when.to_string()))
                    .collect();
                write!(f, "[{}]", spelled.join(", "))
            }
        }
    }
}

/// Read the `when` key of a declaration's `table`: one condition as a
/// string, all of several as an array of strings, or `None` when it is
/// absent.
///
/// # Errors
///
/// [`Error::WrongType`] for a value that is neither, and
/// [`Error::BadValue`] naming why a condition, or the array, is refused.
pub(crate) fn at(ctx: &Ctx<'_>, table: &Table) -> Result<Option<When>, Error> {
    let Some(item) = table.get(KEY) else {
        return Ok(None);
    };
    read(item.as_value(), item.type_name())
        .map(Some)
        .map_err(|refusal| refusal.at(ctx.key_origin(table, KEY)))
}

/// Read the `when` key of a declaration bx decides as a whole — a
/// `[[target]]`, a `[path]` entry, a `[[plugin]]`, an `[[activation]]`, an
/// `[[external]]` or a `[[tool]]` — or `None` when it is absent.
///
/// Such a declaration is kept or left out when bx plans, so a test the shell
/// would run has nothing to guard and is refused.
///
/// # Errors
///
/// Whatever [`at`] refuses, and [`Error::BadValue`] for a condition, or an
/// array holding one, that only the shell can decide.
pub(crate) fn decided_at(ctx: &Ctx<'_>, table: &Table) -> Result<Option<When>, Error> {
    let Some(when) = at(ctx, table)? else {
        return Ok(None);
    };
    only_decided(when)
        .map(Some)
        .map_err(|problem| ctx.bad(table, KEY, problem))
}

/// [`decided_at`] for a value that is not a table's key: a `[path]` entry's
/// inline table, or a module's top-level `when`. `None` reads as absent;
/// `type_name` names the item for a message when it is not a value.
///
/// # Errors
///
/// The [`Refusal`] to place at the key's origin.
pub(crate) fn decided(value: Option<&Value>, type_name: &'static str) -> Result<When, Refusal> {
    only_decided(read(value, type_name)?).map_err(Refusal::Bad)
}

/// `when`, unless it holds a test the shell runs.
fn only_decided(when: When) -> Result<When, String> {
    match when.runtime() {
        None => Ok(when),
        Some(runtime) => Err(format!(
            "`when = {:?}` is a test the shell runs, and this is kept or left out when bx \
             plans, before any shell starts; gate it on a condition bx decides: {DECIDED}",
            runtime.to_string()
        )),
    }
}

/// Every spelling bx decides, as an error message lists them.
const DECIDED: &str = "\"has:TOOL\", \"os:OS\", \"arch:ARCH\", \"host:NAME\", \"user:NAME\" or \
                       \"distro:ID\"";

/// Why a `when` value was refused, before it has an origin to be placed at.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// It is not a string or an array of strings; this is what it is.
    WrongType(&'static str),
    /// It is, and this is why its conditions are refused.
    Bad(String),
}

impl Refusal {
    /// The error, placed at `origin`.
    pub(crate) fn at(self, origin: super::Origin) -> Error {
        match self {
            Self::WrongType(found) => Error::WrongType {
                origin,
                key: KEY.to_string(),
                expected: "a string or an array of strings",
                found,
            },
            Self::Bad(message) => Error::BadValue { origin, message },
        }
    }
}

/// Read one `when` value: a string, or an array of strings. `None` is an
/// item that is not a value at all, which `type_name` names.
fn read(value: Option<&Value>, type_name: &'static str) -> Result<When, Refusal> {
    let value = value.ok_or(Refusal::WrongType(type_name))?;
    if let Some(raw) = value.as_str() {
        return When::parse(raw).map_err(Refusal::Bad);
    }
    let array = value
        .as_array()
        .ok_or_else(|| Refusal::WrongType(value.type_name()))?;
    let raws = array
        .iter()
        .map(|member| {
            member
                .as_str()
                .ok_or_else(|| Refusal::WrongType(member.type_name()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    When::parse_all(&raws).map_err(Refusal::Bad)
}

/// A condition bx decides, beside the declaration it gates.
///
/// Held by the layer it was written in rather than by the declaration, and
/// found again by the declaration's [`Origin`](super::Origin): every
/// declaration records where its entry was written, and no two entries in one
/// layer were written in one place. A tree's files all carry the tree's
/// origin, so the tree's gate reaches every one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// Where the gated entry was written; for a module's own `when`, where
    /// the key was.
    pub origin: super::Origin,
    /// The condition, which holds no test the shell runs.
    pub when: When,
}

impl Condition {
    /// Whether the condition leaves its declaration out on the machine
    /// `decide` describes.
    #[must_use]
    pub fn excludes(&self, decide: &dyn Decide) -> bool {
        self.when.gate(decide) == Gate::Never
    }
}

/// The member of `closed` that is `operand`, if one is.
fn one_of(closed: &[&'static str], operand: &str) -> Option<&'static str> {
    closed.iter().copied().find(|member| *member == operand)
}

/// `closed`, quoted and joined for a message.
fn listed(closed: &[&str]) -> String {
    closed
        .iter()
        .map(|member| format!("`{member}`"))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// Why `name` is not a short hostname `host:` can compare against, or
/// `None` when it is.
fn unhostable(name: &str) -> Option<&'static str> {
    let fine = !name.is_empty()
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    (!fine).then_some(
        "`host:` names a short hostname, the part before the first `.`: ASCII letters, digits \
         and `-`, not starting with `-`",
    )
}

/// Why `name` is not an account name `user:` can compare against, or `None`
/// when it is.
fn unaccountable(name: &str) -> Option<&'static str> {
    let fine = !name.is_empty()
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    (!fine).then_some(
        "`user:` names an account: ASCII letters, digits, `.`, `_` and `-`, not starting with \
         `-`",
    )
}

/// Why `id` is not an os-release `ID` `distro:` can compare against, or
/// `None` when it is.
fn undistributable(id: &str) -> Option<&'static str> {
    let fine = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c));
    (!fine).then_some(
        "`distro:` names an os-release `ID`: lowercase ASCII letters, digits, `.`, `_` and `-`",
    )
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
/// are the ones [`When::test`] or [`When::test_bash`] can produce, and the
/// one [`crate::shell::bash::login_opener`] writes: the test is read back
/// into a condition and rendered again, and anything that does not come back
/// identical is not an opener.
#[must_use]
pub fn is_opener(line: &str) -> bool {
    line.strip_prefix("if ")
        .and_then(|rest| rest.strip_suffix("; then"))
        .map(|test| test.strip_prefix(LOGIN_AND_BASH).unwrap_or(test))
        .and_then(read_test)
        .is_some()
}

/// What opens bash's test of a login shell joined to one more test
/// ([`crate::shell::bash::login_opener`]).
pub(crate) const LOGIN_AND_BASH: &str = "shopt -q login_shell && ";

/// The runtime condition `test` is the rendering of, in either shell's
/// words, if it is one.
fn read_test(test: &str) -> Option<When> {
    if let Some(bash) = [When::Interactive, When::Login]
        .into_iter()
        .find(|when| when.test_bash().as_deref() == Some(test))
    {
        return Some(bash);
    }
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
                    parsed.gate(&tools(&|_| unreachable!())),
                    Gate::Test(test.to_string())
                );
            }
        }
    }

    /// A machine that is `linux` on `x86_64`, host `box`, account `me`, a
    /// Fedora that is like Red Hat.
    fn fedora() -> Machine {
        Machine {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            host: Some("box".to_string()),
            user: Some("me".to_string()),
            distro: Some(Distro {
                id: "fedora".to_string(),
                id_like: vec!["rhel".to_string(), "centos".to_string()],
            }),
        }
    }

    fn on(machine: &Machine, when: &When) -> Gate {
        when.gate(&Facts {
            machine,
            present: &|tool| tool == "sccache",
        })
    }

    #[test]
    fn every_machine_fact_parses_renders_nothing_and_spells_itself_back() {
        for (raw, when) in [
            ("os:linux", When::Os("linux")),
            ("os:macos", When::Os("macos")),
            ("arch:x86_64", When::Arch("x86_64")),
            ("arch:aarch64", When::Arch("aarch64")),
            ("host:Box-1", When::Host("Box-1".to_string())),
            ("user:j.doe_2", When::User("j.doe_2".to_string())),
            (
                "distro:opensuse-tumbleweed",
                When::Distro("opensuse-tumbleweed".to_string()),
            ),
        ] {
            let parsed = When::parse(raw).expect(raw);
            assert_eq!(parsed, when, "{raw}");
            assert!(!parsed.is_runtime(), "{raw}");
            assert_eq!(parsed.test(), None, "{raw}");
            assert_eq!(parsed.test_bash(), None, "{raw}");
            assert_eq!(parsed.to_string(), raw);
        }
    }

    #[test]
    fn a_machine_fact_is_decided_against_the_facts_and_nothing_else() {
        let here = fedora();
        for (raw, gate) in [
            ("os:linux", Gate::Always),
            ("os:macos", Gate::Never),
            ("arch:x86_64", Gate::Always),
            ("arch:aarch64", Gate::Never),
            ("host:box", Gate::Always),
            ("host:BOX", Gate::Always),
            ("host:box2", Gate::Never),
            ("user:me", Gate::Always),
            ("user:Me", Gate::Never),
            ("distro:fedora", Gate::Always),
            ("distro:rhel", Gate::Always),
            ("distro:centos", Gate::Always),
            ("distro:debian", Gate::Never),
        ] {
            let when = When::parse(raw).expect(raw);
            assert_eq!(on(&here, &when), gate, "{raw}");
            assert_eq!(
                crate::shell::bash::gate(
                    &when,
                    &Facts {
                        machine: &here,
                        present: &|_| false
                    }
                ),
                gate,
                "{raw}"
            );
        }
        // A fact that could not be read holds for no condition on it.
        for raw in [
            "os:linux",
            "arch:x86_64",
            "host:box",
            "user:me",
            "distro:fedora",
        ] {
            let when = When::parse(raw).expect(raw);
            assert_eq!(on(&Machine::default(), &when), Gate::Never, "{raw}");
        }
    }

    #[test]
    fn a_bad_machine_operand_is_refused_naming_why() {
        for (raw, needle) in [
            ("os:", "`os:` names one of `linux` or `macos`"),
            ("os:windows", "`os:` names one of `linux` or `macos`"),
            ("os:Linux", "`os:` names one of"),
            ("os:darwin", "`os:` names one of"),
            ("arch:", "`arch:` names one of `x86_64` or `aarch64`"),
            ("arch:i686", "`arch:` names one of"),
            ("arch:arm64", "write `arch:aarch64`"),
            ("host:", "short hostname"),
            ("host:box.example.com", "short hostname"),
            ("host:-box", "short hostname"),
            ("host:b_x", "short hostname"),
            ("user:", "`user:` names an account"),
            ("user:-u", "`user:` names an account"),
            ("user:a b", "`user:` names an account"),
            ("user:$(id)", "`user:` names an account"),
            ("distro:", "os-release `ID`"),
            ("distro:Fedora", "os-release `ID`"),
            ("distro:arch linux", "os-release `ID`"),
        ] {
            let err = When::parse(raw).expect_err(raw);
            assert!(err.contains(needle), "{raw}: {err}");
        }
    }

    #[test]
    fn an_array_is_all_of_its_conditions_with_at_most_one_test() {
        let here = fedora();
        let all = |raws: &[&str]| When::parse_all(raws).expect("parses");

        // One condition is that condition.
        assert_eq!(all(&["ssh"]), When::Ssh);

        let both = all(&["os:linux", "arch:x86_64"]);
        assert_eq!(
            both,
            When::All(vec![When::Os("linux"), When::Arch("x86_64")])
        );
        assert!(!both.is_runtime());
        assert_eq!(on(&here, &both), Gate::Always);
        assert_eq!(on(&here, &all(&["os:linux", "arch:aarch64"])), Gate::Never);
        assert_eq!(on(&here, &all(&["has:sccache", "host:box"])), Gate::Always);
        assert_eq!(on(&here, &all(&["has:missing", "host:box"])), Gate::Never);

        // The one runtime test is what remains once the rest holds.
        let tested = all(&["os:linux", "interactive", "user:me"]);
        assert!(tested.is_runtime());
        assert_eq!(tested.runtime(), Some(&When::Interactive));
        assert_eq!(tested.test().as_deref(), Some("[[ -o interactive ]]"));
        assert_eq!(tested.test_bash().as_deref(), Some("[[ $- == *i* ]]"));
        assert_eq!(
            on(&here, &tested),
            Gate::Test("[[ -o interactive ]]".to_string())
        );
        assert_eq!(
            crate::shell::bash::gate(
                &tested,
                &Facts {
                    machine: &here,
                    present: &|_| false
                }
            ),
            Gate::Test("[[ $- == *i* ]]".to_string())
        );
        // ... and a decided condition that does not hold drops the line
        // whatever the shell would say.
        assert_eq!(on(&here, &all(&["os:macos", "ssh"])), Gate::Never);
        assert_eq!(
            all(&["os:macos", "env:X=a b"]).to_string(),
            "[\"os:macos\", \"env:X=a b\"]"
        );

        for (raws, needle) in [
            (&[][..], "lists no condition"),
            (
                &["ssh", "login"][..],
                "lists 2 tests the shell runs (\"ssh\", \"login\")",
            ),
            (&["os:linux", "env:A", "env:B=c"][..], "at most one"),
            (&["os:linux", "tty"][..], "`when` must be one of"),
            (&["os:beos"][..], "`os:` names one of"),
        ] {
            let err = When::parse_all(raws).expect_err(needle);
            assert!(err.contains(needle), "{raws:?}: {err}");
        }
    }

    #[test]
    fn a_whole_declaration_takes_only_conditions_bx_decides() {
        let value = |raw: &str| raw.parse::<Value>().expect("a TOML value");
        let decided_of = |raw: &str| decided(Some(&value(raw)), "value");

        assert_eq!(
            decided_of("\"os:macos\"").expect("decided"),
            When::Os("macos")
        );
        let both = decided_of("[\"has:sccache\", \"host:box\"]").expect("decided");
        let here = fedora();
        let box_with = |present: &dyn Fn(&str) -> bool| {
            Condition {
                origin: super::super::Origin::unknown(std::path::Path::new("m.toml")),
                when: both.clone(),
            }
            .excludes(&Facts {
                machine: &here,
                present,
            })
        };
        assert!(!box_with(&|tool| tool == "sccache"));
        assert!(box_with(&|_| false));

        for (raw, needle) in [
            ("\"ssh\"", "`when = \"ssh\"` is a test the shell runs"),
            (
                "[\"os:linux\", \"env:TMUX\"]",
                "`when = \"env:TMUX\"` is a test the shell runs",
            ),
            ("\"interactive\"", DECIDED),
            ("\"os:beos\"", "`os:` names one of"),
        ] {
            match decided_of(raw) {
                Err(Refusal::Bad(message)) => assert!(message.contains(needle), "{raw}: {message}"),
                other => panic!("{raw}: {other:?}"),
            }
        }
        for (raw, found) in [("true", "boolean"), ("[1]", "integer")] {
            match decided_of(raw) {
                Err(Refusal::WrongType(name)) => assert_eq!(name, found, "{raw}"),
                other => panic!("{raw}: {other:?}"),
            }
        }
        assert!(matches!(
            decided(None, "table"),
            Err(Refusal::WrongType("table"))
        ));
    }

    #[test]
    fn os_release_is_read_as_os_release_5_writes_it() {
        let text = "NAME=\"Fedora Linux\"\n# a comment\nID=fedora\n\
                    ID_LIKE=\"rhel  centos\"\nVERSION_ID=40\nnot a pair\n";
        assert_eq!(
            Distro::parse(text),
            Some(Distro {
                id: "fedora".to_string(),
                id_like: vec!["rhel".to_string(), "centos".to_string()],
            })
        );
        assert_eq!(
            Distro::parse("ID='debian'\n"),
            Some(Distro {
                id: "debian".to_string(),
                id_like: Vec::new(),
            })
        );
        assert_eq!(
            Distro::parse("ID=\"a\\\"b\"\n").map(|d| d.id),
            Some("a\"b".to_string())
        );
        assert_eq!(Distro::parse("ID=\n"), None);
        assert_eq!(Distro::parse("NAME=x\n"), None);
        assert_eq!(unquote("\"unterminated"), "\"unterminated");
    }

    #[test]
    fn the_short_host_is_the_node_name_before_its_first_dot() {
        assert_eq!(short_host("box.example.com").as_deref(), Some("box"));
        assert_eq!(short_host("box").as_deref(), Some("box"));
        assert_eq!(short_host(".hidden"), None);
        assert_eq!(short_host(""), None);
    }

    #[test]
    fn this_machine_is_read_as_it_is() {
        let here = Machine::read(Some("me".to_string()));
        assert_eq!(here.os, std::env::consts::OS);
        assert_eq!(here.arch, std::env::consts::ARCH);
        assert_eq!(here.user.as_deref(), Some("me"));
        assert!(here.host.as_deref().is_none_or(|host| !host.contains('.')));
        assert_eq!(Machine::read(Some(String::new())).user, None);
        assert_eq!(Machine::read(None).user, None);
        let os_release = ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| Distro::parse(&text));
        let distro = if here.os == "linux" { os_release } else { None };
        assert_eq!(here.distro, distro);
    }

    #[test]
    fn an_unrecognised_spelling_is_refused_listing_them_all() {
        for raw in [
            "",
            "Interactive",
            "tty",
            "has",
            "env",
            "os",
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
        assert_eq!(has.gate(&tools(&|tool| tool == "sccache")), Gate::Always);
        assert_eq!(has.gate(&tools(&|_| false)), Gate::Never);
        assert_eq!(has.test(), None);
        assert_eq!(
            crate::shell::bash::gate(&has, &tools(&|tool| tool == "sccache")),
            Gate::Always
        );
        assert_eq!(
            crate::shell::bash::gate(&has, &tools(&|_| false)),
            Gate::Never
        );
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
                crate::shell::bash::gate(&when, &tools(&|_| unreachable!())),
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
            // bash's words for the two tests bash asks differently.
            "if [[ $- == *i* ]]; then",
            "if shopt -q login_shell; then",
            // bash's login block, joined to one more test.
            "if shopt -q login_shell && [[ -n ${SSH_CONNECTION-} ]]; then",
            "if shopt -q login_shell && [[ $- == *i* ]]; then",
        ] {
            assert!(is_opener(line), "{line}");
        }
        assert_eq!(
            crate::shell::bash::login_opener(None),
            "if shopt -q login_shell; then".to_string()
        );
        let ssh = When::Ssh.test_bash().expect("a runtime test");
        assert!(is_opener(&crate::shell::bash::login_opener(Some(&ssh))));
        for line in [
            "if shopt -q login_shell && true; then",
            "if shopt -q login_shell &&  [[ -o login ]]; then",
            "if [[ -o login ]] && shopt -q login_shell; then",
            "if shopt -q extglob; then",
            "if [[ $- == *x* ]]; then",
            "if shopt -q login_shell && shopt -q login_shell && [[ -o login ]]; then",
        ] {
            assert!(!is_opener(line), "{line}");
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
