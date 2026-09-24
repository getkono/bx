//! Declared tool activations, run once at `plan` time and cached, so a shell
//! that used to fork a process per tool at every start sources cached text
//! instead.
//!
//! # The `[[activation]]` schema
//!
//! ```toml
//! [[activation]]
//! name    = "starship"                        # required; the natural key
//! command = ["starship", "init", "zsh"]       # required; argv, run without a shell
//! phase   = "completions"                     # activations | completions; default activations
//! cache   = true                              # default true; false = never cacheable
//! enabled = true                              # default true
//! ```
//!
//! `command[0]` is the tool: a bare program name looked up on `PATH`, or an
//! absolute path. Either way it holds only characters a bare shell word holds,
//! so the guard a never-cacheable activation renders can name it unquoted. The
//! rest of `command` is quoted wherever a word needs it.
//!
//! `phase` is the load-order phase the output lands in: `activations` for a
//! tool that puts itself on `PATH` or `fpath` (brew, mise), `completions` for
//! one that registers a completion, a widget or a prompt (starship, zoxide,
//! fzf, uv). Nothing else may be claimed; see [`super::Phase`].
//!
//! # What is cached, and when it is reused
//!
//! [`plan`] resolves `command[0]` against `PATH` and hashes the **content** of
//! the binary it finds. The cache entry — [`Fingerprints`] key
//! `activation:<name>` — pairs a digest of that content, the resolved path and
//! the whole command with the output they produced. While the digest matches,
//! the output is reused verbatim and **no process is started**. A binary that
//! was upgraded, replaced or moved changes the digest, whatever its
//! modification time says, and the command runs again.
//!
//! A command bx has not cached for these inputs runs **twice**, and its output
//! is trusted only if both runs agree byte for byte. Output that differs is
//! omitted with a note and never cached, so the next `plan` tries again. A
//! tool whose output depends on something other than its own binary — its own
//! config, the time, the working directory — is declared `cache = false`
//! instead: it is rendered as a guarded, quoted `eval "$(…)"` every time,
//! which is the one case that still spawns at shell start, because the author
//! said so.
//!
//! An activation whose tool is absent, not executable, unreadable, fails, runs
//! past [`TIMEOUT`], prints more than [`LIMIT`] bytes or prints something that
//! is not text is **omitted** — the step says why — and every other
//! activation, and every other phase, still renders. Its cache entry is
//! dropped, so a later `plan` starts from nothing rather than reusing output a
//! different binary produced.
//!
//! Commands run in bx's own process environment, with no input. bx does not
//! build the environment the interactive shell will have before running one.
//!
//! # Plan and apply
//!
//! [`plan`] is the one function: it decides every activation, runs whatever
//! has to run, and returns [`Step`]s that say which were reused, captured,
//! rendered plain or omitted. `apply` does not decide again. It hands the same
//! [`Plan`] to [`Plan::contribute`], which renders the file, and to
//! [`Plan::record`], which writes the captures into the cache it then saves. A
//! second `plan` against an unchanged machine therefore reuses every entry,
//! starts no process, and renders the same bytes.
//!
//! # Invariant 2
//!
//! The activations and completions phases are generated shell content that is
//! not an environment fragment, so bx's own bytes there set nothing. A cached
//! activation is rendered as **one `eval` statement whose single argument is a
//! single-quoted literal** holding the tool's output: the file's own grammar
//! holds a command and a string, never an assignment, exactly as the
//! uncached `eval "$(tool init zsh)"` line it replaces does. What that string
//! sets when it runs is the tool's own documented activation — the same text
//! the uncached line would have evaluated at the same moment — relayed byte
//! for byte and never composed, edited or added to by bx. The single quotes
//! also keep a malformed output from reaching the rest of the file: it fails
//! inside its own `eval`, as it would have uncached.
//! `a_rendered_activation_is_one_eval_of_a_literal_and_sets_nothing_itself`
//! holds the rendered bytes to that.

use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use toml_edit::Table;

use super::{Assembly, Phase};
use crate::config::{Ctx, Error, Origin};
use crate::detect::{self, Presence};
use crate::report::Action;
use crate::state::{ContentHash, Fingerprint, Fingerprints};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[activation]]";

/// Every key an `[[activation]]` entry may carry.
const KEYS: [&str; 5] = ["name", "command", "phase", "cache", "enabled"];

/// The prefix of every cache key this module owns.
pub const KEY_PREFIX: &str = "activation:";

/// How long one run of an activation's command may take.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The most output one run may print, in bytes.
pub const LIMIT: usize = 1 << 20;

/// How much of a failing command's standard error a note quotes.
const STDERR_KEPT: usize = 512;

/// The characters a word may hold and still be written bare.
const BARE: &str = "_./,:@%+-";

/// The phases an activation may land in, as a config author spells them.
const PHASES: [(&str, Phase); 2] = [
    ("activations", Phase::Activations),
    ("completions", Phase::Completions),
];

/// One `[[activation]]` entry, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationDecl {
    /// The activation's name, its natural key.
    pub name: String,
    /// The command, `command[0]` being the tool. Never empty.
    pub command: Vec<String>,
    /// The phase its output lands in.
    pub phase: Phase,
    /// `false` renders the plain invocation every time, never cached.
    pub cache: bool,
    /// `false` in any layer removes the activation from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

impl ActivationDecl {
    /// The [`Fingerprints`] key the activation's cache entry lives under.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{KEY_PREFIX}{}", self.name)
    }

    /// The tool, `command[0]`.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.command[0]
    }

    /// The never-cacheable rendering: `eval` of the command's output, run only
    /// when the tool is there at shell start.
    #[must_use]
    pub fn invocation(&self) -> String {
        let program = self.program();
        let guard = if program.starts_with('/') {
            format!("[[ -x {program} ]]")
        } else {
            format!("(( $+commands[{program}] ))")
        };
        let words: Vec<String> = self.command.iter().map(|w| quote(w)).collect();
        format!("{guard} && eval \"$({})\"\n", words.join(" "))
    }
}

/// `word`, bare where every character is one a bare shell word holds, and
/// single-quoted otherwise.
fn quote(word: &str) -> String {
    if !word.is_empty() && word.chars().all(is_bare) {
        word.to_string()
    } else {
        literal(word)
    }
}

/// Whether `c` may appear in a word written bare.
fn is_bare(c: char) -> bool {
    c.is_ascii_alphanumeric() || BARE.contains(c)
}

/// `text` as one single-quoted shell literal, whatever it holds.
fn literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Parse one `[[activation]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_activation(table: &Table, file: &Path, text: &str) -> Result<ActivationDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not an activation name: a name is non-empty and on one line"),
        ));
    }

    if table.get("command").is_none() {
        return Err(Error::MissingKey {
            origin: ctx.origin().clone(),
            section: SECTION,
            key: "command",
        });
    }
    let command = ctx.str_array_at(table, "command")?;
    if let Some(problem) = unrunnable(&command) {
        return Err(ctx.bad(table, "command", format!("`{name}`: {problem}")));
    }

    let phase = match ctx.str_at(table, "phase")? {
        None => Phase::Activations,
        Some(raw) => PHASES
            .iter()
            .find_map(|(spelling, phase)| (*spelling == raw).then_some(*phase))
            .ok_or_else(|| {
                ctx.bad(
                    table,
                    "phase",
                    format!(
                        "`{name}`: {raw:?} is not a phase an activation may land in; \
                         use \"activations\" or \"completions\""
                    ),
                )
            })?,
    };

    Ok(ActivationDecl {
        name,
        command,
        phase,
        cache: ctx.bool_at(table, "cache")?.unwrap_or(true),
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Why `command` cannot be run and rendered, or `None` when it can.
fn unrunnable(command: &[String]) -> Option<String> {
    let Some(program) = command.first() else {
        return Some("`command` is empty; it names at least the tool to run".to_string());
    };
    let shape = if let Some(rest) = program.strip_prefix('/') {
        !rest.is_empty() && rest.chars().all(is_bare)
    } else {
        !program.is_empty()
            && !program.starts_with('-')
            && program
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.+-".contains(c))
    };
    if !shape {
        return Some(format!(
            "`command[0] = {program:?}` must be a program name of ASCII letters, digits and \
             `_.+-`, or an absolute path of those and `/,:@%`, so it can be looked up and \
             named unquoted"
        ));
    }
    command.iter().find(|word| word.contains('\0')).map(|word| {
        format!("{word:?} holds a NUL byte, which no argument passed to a program can hold")
    })
}

/// Why running an activation's command produced no usable output.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// The process could not be started or waited for.
    #[error("could not run it: {0}")]
    Spawn(String),
    /// It exited unsuccessfully.
    #[error("it exited with {status}{}", stderr_suffix(.stderr))]
    Exited {
        /// The exit status, as the standard library renders it.
        status: String,
        /// The start of what it printed on standard error.
        stderr: String,
    },
    /// It ran longer than it may.
    #[error("it was still running after {} s and was stopped", .0.as_secs())]
    TimedOut(Duration),
    /// It printed more than it may.
    #[error("it printed more than {0} bytes")]
    TooLarge(usize),
}

/// `: <stderr>` when there is any, and nothing otherwise.
fn stderr_suffix(stderr: &str) -> String {
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
}

/// What [`plan`] asks of the machine. [`System`] is the machine itself; a
/// test supplies its own.
pub trait Host {
    /// Where `program` is, as [`detect::locate`] answers it.
    fn locate(&self, program: &str) -> Presence;

    /// The digest of the file at `path`'s contents.
    ///
    /// # Errors
    ///
    /// Why it could not be read, as a sentence.
    fn hash(&self, path: &Path) -> Result<ContentHash, String>;

    /// Run `program` with `args` and return what it printed on standard output.
    ///
    /// # Errors
    ///
    /// [`RunError`] when it did not run to a successful exit within its bounds.
    fn run(&self, program: &Path, args: &[String]) -> Result<Vec<u8>, RunError>;
}

/// The machine bx is running on, searched along one `PATH`.
#[derive(Debug, Clone)]
pub struct System {
    /// The search path `command[0]` is looked up along.
    path: OsString,
    /// How long one run may take.
    timeout: Duration,
}

impl System {
    /// The machine, searched along the `PATH` this process inherited, each run
    /// bounded by [`TIMEOUT`].
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(std::env::var_os("PATH").unwrap_or_default(), TIMEOUT)
    }

    /// The machine, searched along `path`, each run bounded by `timeout`.
    #[must_use]
    pub fn new(path: impl Into<OsString>, timeout: Duration) -> Self {
        Self {
            path: path.into(),
            timeout,
        }
    }
}

impl Host for System {
    fn locate(&self, program: &str) -> Presence {
        detect::locate(program, &self.path)
    }

    fn hash(&self, path: &Path) -> Result<ContentHash, String> {
        ContentHash::of_file(path).map_err(|e| e.to_string())
    }

    fn run(&self, program: &Path, args: &[String]) -> Result<Vec<u8>, RunError> {
        let deadline = Instant::now() + self.timeout;
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RunError::Spawn(e.to_string()))?;

        // Each stream is drained on its own thread, so a child that fills one
        // pipe while bx waits on the other cannot stall. Standard output is
        // read only one byte past its bound: a child that keeps writing then
        // finds its pipe closed rather than bx's memory growing. Standard error
        // is read to its end and only its start kept, so a tool that warns at
        // length is never killed by a closed pipe for it.
        let stdout = drain(child.stdout.take(), LIMIT + 1, false);
        let stderr = drain(child.stderr.take(), STDERR_KEPT, true);

        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::TimedOut(self.timeout));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::Spawn(e.to_string()));
                }
            }
        };

        // A process the command left behind may still hold the pipe open, so
        // collecting the output is bounded by the same deadline.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let out = stdout
            .recv_timeout(remaining)
            .map_err(|_| RunError::TimedOut(self.timeout))?;
        if out.len() > LIMIT {
            return Err(RunError::TooLarge(LIMIT));
        }
        if !status.success() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let err = stderr.recv_timeout(remaining).unwrap_or_default();
            let err = String::from_utf8_lossy(&err);
            return Err(RunError::Exited {
                status: status.to_string(),
                stderr: err.lines().next().unwrap_or("").trim().to_string(),
            });
        }
        Ok(out)
    }
}

/// Read the first `limit` bytes of `stream` on a thread of its own, and when
/// `to_end`, read and discard the rest until the writer closes it.
fn drain(
    stream: Option<impl Read + Send + 'static>,
    limit: usize,
    to_end: bool,
) -> mpsc::Receiver<Vec<u8>> {
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut stream) = stream {
            let _ = (&mut stream).take(limit as u64).read_to_end(&mut buf);
            if to_end {
                let _ = std::io::copy(&mut stream, &mut std::io::sink());
            }
        }
        let _ = send.send(buf);
    });
    receive
}

/// Why an activation is left out of the generated file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Omission {
    /// Nothing named `command[0]` is on the search path.
    Absent {
        /// The tool, as declared.
        program: String,
    },
    /// The file found cannot be executed by this account.
    NotExecutable {
        /// Where it was found.
        path: PathBuf,
    },
    /// The binary could not be read, so its content cannot be hashed.
    Unreadable {
        /// Why.
        reason: String,
    },
    /// The command did not run to a successful exit.
    Failed(RunError),
    /// The command printed something that is not UTF-8 text free of NUL bytes.
    NotText,
    /// Two consecutive runs printed different output.
    Unstable,
}

impl fmt::Display for Omission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent { program } => write!(f, "`{program}` is not on PATH"),
            Self::NotExecutable { path } => {
                write!(f, "{} is not executable by this account", path.display())
            }
            Self::Unreadable { reason } => write!(f, "its binary cannot be hashed: {reason}"),
            Self::Failed(error) => write!(f, "{error}"),
            Self::NotText => f.write_str("it printed something that is not text"),
            Self::Unstable => f.write_str(
                "two consecutive runs printed different output, so it is not cached; \
                 the next plan runs it again, or declare it `cache = false`",
            ),
        }
    }
}

/// What [`plan`] decided for one activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The cache entry matches the binary: its output is reused, and nothing
    /// ran.
    Reused {
        /// The cached output.
        output: String,
    },
    /// The command ran twice and agreed: its output is rendered, and cached by
    /// [`Plan::record`].
    Captured {
        /// What it printed.
        output: String,
        /// The cache entry that records it.
        entry: Fingerprint,
        /// Whether it replaces an entry a different binary or command produced.
        replaces: bool,
    },
    /// Declared never cacheable: rendered as the plain invocation.
    Plain,
    /// Left out, for the reason given.
    Omitted(Omission),
}

/// One activation, decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The declaration.
    pub decl: ActivationDecl,
    /// What was decided.
    pub outcome: Outcome,
}

impl Step {
    /// What the step is, in the vocabulary `plan` and `apply` share: a reuse
    /// or a plain invocation is converged, a first capture creates a cache
    /// entry and a re-capture modifies one, and an omission is blocked until
    /// the tool behaves.
    #[must_use]
    pub const fn action(&self) -> Action {
        match &self.outcome {
            Outcome::Reused { .. } | Outcome::Plain => Action::Unchanged,
            Outcome::Captured {
                replaces: false, ..
            } => Action::Create,
            Outcome::Captured { replaces: true, .. } => Action::Modify,
            Outcome::Omitted(_) => Action::Blocked,
        }
    }

    /// The step as one line of `plan` output.
    #[must_use]
    pub fn line(&self) -> String {
        let what = match &self.outcome {
            Outcome::Reused { .. } => "cached output reused, nothing run".to_string(),
            Outcome::Captured {
                replaces: false, ..
            } => "run twice, output agreed; cached".to_string(),
            Outcome::Captured { replaces: true, .. } => {
                "binary or command changed; run twice, output agreed; cache replaced".to_string()
            }
            Outcome::Plain => "never cached; runs at every shell start".to_string(),
            Outcome::Omitted(why) => format!("omitted: {why}"),
        };
        format!(
            "{} activation `{}`: {what}",
            self.action().symbol(),
            self.decl.name
        )
    }

    /// The text the step adds to its phase, if any.
    #[must_use]
    pub fn body(&self) -> Option<String> {
        let comment = format!("# bx activation: {}\n", self.decl.name);
        match &self.outcome {
            Outcome::Reused { output } | Outcome::Captured { output, .. } => {
                Some(format!("{comment}eval {}\n", literal(output)))
            }
            Outcome::Plain => Some(format!("{comment}{}", self.decl.invocation())),
            Outcome::Omitted(_) => None,
        }
    }
}

/// Every enabled activation, decided in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// One step per enabled activation.
    steps: Vec<Step>,
}

impl Plan {
    /// The steps, in declaration order.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Add every step that renders anything to its phase, in declaration
    /// order.
    ///
    /// # Errors
    ///
    /// Whatever [`Assembly::contribute`] refuses. An activation lands only in
    /// `activations` or `completions`, neither of which refuses anything.
    pub fn contribute(&self, assembly: &mut Assembly) -> Result<(), super::Error> {
        for step in &self.steps {
            if let Some(body) = step.body() {
                assembly.contribute(step.decl.phase, step.decl.name.clone(), body)?;
            }
        }
        Ok(())
    }

    /// Bring `cache` up to date with the plan: record every capture, and
    /// forget every activation entry nothing reused or captured — an omitted
    /// one, a never-cacheable one, and one no enabled declaration names any
    /// more — so an omission is retried from nothing. Entries this module
    /// does not own are left alone.
    pub fn record(&self, cache: &mut Fingerprints) {
        let mut kept = Vec::new();
        for step in &self.steps {
            let key = step.decl.key();
            match &step.outcome {
                Outcome::Reused { .. } => kept.push(key),
                Outcome::Captured { entry, .. } => {
                    cache.set(key.clone(), entry.clone());
                    kept.push(key);
                }
                Outcome::Plain | Outcome::Omitted(_) => {}
            }
        }
        let stale: Vec<String> = cache
            .iter()
            .map(|(key, _)| key)
            .filter(|key| key.starts_with(KEY_PREFIX) && !kept.contains(key))
            .cloned()
            .collect();
        for key in stale {
            cache.remove(&key);
        }
    }
}

/// A cache entry: the inputs that produced an output, and the output.
#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    /// [`inputs`]' digest.
    inputs: ContentHash,
    /// What the command printed.
    output: String,
}

impl Entry {
    /// The entry stored as `fingerprint`, if it decodes. One that does not is
    /// a miss: a cache entry is only ever worth a recomputation.
    fn decode(fingerprint: &Fingerprint) -> Option<Self> {
        rmp_serde::from_slice(fingerprint.as_bytes()).ok()
    }

    /// The entry as a fingerprint.
    fn encode(&self) -> Fingerprint {
        // An `Entry` is a digest and a string, which MessagePack always
        // encodes; an empty fingerprint would decode as a miss regardless.
        Fingerprint::raw(rmp_serde::to_vec_named(self).unwrap_or_default())
    }
}

/// The digest of everything an activation's output is a function of: the
/// binary's content, where it was found, and the command.
fn inputs(content: &ContentHash, binary: &Path, command: &[String]) -> ContentHash {
    let mut bytes = b"bx.activation.v1\0".to_vec();
    let mut field = |value: &[u8]| {
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value);
    };
    field(content.as_bytes());
    field(binary.as_os_str().as_encoded_bytes());
    for word in command {
        field(word.as_bytes());
    }
    ContentHash::of(&bytes)
}

/// Decide every enabled activation in `decls`, in declaration order, against
/// `cache`, running on `host` only what the cache cannot answer.
///
/// `cache` is read, never written: [`Plan::record`] is what applies the
/// decisions to it.
#[must_use]
pub fn plan(decls: &[ActivationDecl], cache: &Fingerprints, host: &impl Host) -> Plan {
    let steps = decls
        .iter()
        .filter(|decl| decl.enabled)
        .map(|decl| Step {
            decl: decl.clone(),
            outcome: decide(decl, cache, host),
        })
        .collect();
    Plan { steps }
}

/// Decide one activation.
fn decide(decl: &ActivationDecl, cache: &Fingerprints, host: &impl Host) -> Outcome {
    if !decl.cache {
        return Outcome::Plain;
    }
    let binary = match host.locate(decl.program()) {
        Presence::Present { path } => path,
        Presence::NotExecutable { path } => {
            return Outcome::Omitted(Omission::NotExecutable { path });
        }
        Presence::Missing => {
            return Outcome::Omitted(Omission::Absent {
                program: decl.program().to_string(),
            });
        }
    };
    let content = match host.hash(&binary) {
        Ok(content) => content,
        Err(reason) => return Outcome::Omitted(Omission::Unreadable { reason }),
    };
    let inputs = inputs(&content, &binary, &decl.command);

    let previous = cache.get(&decl.key());
    if let Some(entry) = previous.and_then(Entry::decode)
        && entry.inputs == inputs
    {
        return Outcome::Reused {
            output: entry.output,
        };
    }

    let args = &decl.command[1..];
    let first = match host.run(&binary, args) {
        Ok(out) => out,
        Err(e) => return Outcome::Omitted(Omission::Failed(e)),
    };
    let second = match host.run(&binary, args) {
        Ok(out) => out,
        Err(e) => return Outcome::Omitted(Omission::Failed(e)),
    };
    if first != second {
        return Outcome::Omitted(Omission::Unstable);
    }
    let output = match String::from_utf8(first) {
        Ok(text) if !text.contains('\0') => text,
        _ => return Outcome::Omitted(Omission::NotText),
    };
    let entry = Entry {
        inputs,
        output: output.clone(),
    }
    .encode();
    Outcome::Captured {
        output,
        entry,
        replaces: previous.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use toml_edit::Document;

    /// Every `[[activation]]` entry in `text`, parsed.
    fn parse(text: &str) -> Result<Vec<ActivationDecl>, String> {
        let doc = Document::parse(text).map_err(|e| format!("{e}"))?;
        let tables = doc
            .get("activation")
            .and_then(|item| item.as_array_of_tables())
            .ok_or("no [[activation]]")?;
        tables
            .iter()
            .map(|table| parse_activation(table, Path::new("/repo/bx.toml"), text))
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }

    fn decl(name: &str, command: &[&str]) -> ActivationDecl {
        ActivationDecl {
            name: name.to_string(),
            command: command.iter().map(ToString::to_string).collect(),
            phase: Phase::Activations,
            cache: true,
            enabled: true,
            origin: Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line: 1,
            },
        }
    }

    /// What each run of each path prints, in order.
    type Outputs = BTreeMap<PathBuf, VecDeque<Result<Vec<u8>, RunError>>>;

    /// A machine whose tools, binaries and outputs a test decides, and which
    /// counts every run.
    #[derive(Default)]
    struct Fake {
        /// Each tool's resolved path and binary content.
        tools: BTreeMap<String, (PathBuf, Vec<u8>)>,
        /// Tools found but not executable.
        inexecutable: Vec<String>,
        /// Tools whose binary cannot be read.
        unreadable: Vec<String>,
        /// What each run of a path prints, in order; the last one repeats.
        outputs: RefCell<Outputs>,
        /// Every run, in order.
        runs: RefCell<Vec<PathBuf>>,
    }

    impl Fake {
        fn tool(mut self, name: &str, binary: &[u8], outputs: &[&str]) -> Self {
            let path = PathBuf::from(format!("/usr/bin/{name}"));
            self.tools
                .insert(name.to_string(), (path.clone(), binary.to_vec()));
            self.outputs.borrow_mut().insert(
                path,
                outputs.iter().map(|o| Ok(o.as_bytes().to_vec())).collect(),
            );
            self
        }

        fn failing(self, name: &str, error: RunError) -> Self {
            let fake = self.tool(name, b"bin", &[]);
            fake.outputs
                .borrow_mut()
                .get_mut(Path::new(&format!("/usr/bin/{name}")))
                .unwrap()
                .push_back(Err(error));
            fake
        }

        fn upgrade(&mut self, name: &str, binary: &[u8], outputs: &[&str]) {
            self.tools.get_mut(name).unwrap().1 = binary.to_vec();
            let path = self.tools[name].0.clone();
            self.outputs.borrow_mut().insert(
                path,
                outputs.iter().map(|o| Ok(o.as_bytes().to_vec())).collect(),
            );
        }

        fn runs(&self) -> usize {
            self.runs.borrow().len()
        }
    }

    impl Host for Fake {
        fn locate(&self, program: &str) -> Presence {
            if self.inexecutable.iter().any(|p| p == program) {
                return Presence::NotExecutable {
                    path: PathBuf::from(format!("/usr/bin/{program}")),
                };
            }
            self.tools
                .get(program)
                .map_or(Presence::Missing, |(path, _)| Presence::Present {
                    path: path.clone(),
                })
        }

        fn hash(&self, path: &Path) -> Result<ContentHash, String> {
            let (name, (_, content)) = self
                .tools
                .iter()
                .find(|(_, (p, _))| p == path)
                .expect("hashed a located path");
            if self.unreadable.contains(name) {
                return Err("permission denied".to_string());
            }
            Ok(ContentHash::of(content))
        }

        fn run(&self, program: &Path, _args: &[String]) -> Result<Vec<u8>, RunError> {
            self.runs.borrow_mut().push(program.to_path_buf());
            let mut outputs = self.outputs.borrow_mut();
            let queue = outputs.get_mut(program).expect("ran a known tool");
            if queue.len() > 1 {
                queue.pop_front().unwrap()
            } else {
                queue.front().cloned().expect("an output")
            }
        }
    }

    /// Plan, render and record, as `apply` does; the rendered file.
    fn apply(decls: &[ActivationDecl], cache: &mut Fingerprints, host: &Fake) -> (Plan, String) {
        let plan = plan(decls, cache, host);
        let mut assembly = Assembly::new();
        plan.contribute(&mut assembly)
            .expect("activations never claim the terminal slot");
        plan.record(cache);
        (plan, assembly.render())
    }

    #[test]
    fn an_activation_entry_parses_every_key() {
        let decls = parse(
            "[[activation]]\nname = \"starship\"\ncommand = [\"starship\", \"init\", \"zsh\"]\n\
             phase = \"completions\"\ncache = false\nenabled = false\n\
             [[activation]]\nname = \"brew\"\n\
             command = [\"/home/linuxbrew/.linuxbrew/bin/brew\", \"shellenv\"]\n",
        )
        .expect("parses");
        assert_eq!(
            decls,
            vec![
                ActivationDecl {
                    name: "starship".to_string(),
                    command: vec!["starship".into(), "init".into(), "zsh".into()],
                    phase: Phase::Completions,
                    cache: false,
                    enabled: false,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 1,
                    },
                },
                ActivationDecl {
                    name: "brew".to_string(),
                    command: vec![
                        "/home/linuxbrew/.linuxbrew/bin/brew".into(),
                        "shellenv".into()
                    ],
                    phase: Phase::Activations,
                    cache: true,
                    enabled: true,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 7,
                    },
                },
            ]
        );
        assert_eq!(decls[0].key(), "activation:starship");
    }

    #[test]
    fn a_malformed_entry_is_refused_naming_its_key() {
        for (body, needle) in [
            ("command = [\"a\"]\n", "`name`"),
            ("name = \"a\"\n", "`command`"),
            ("name = \"\"\ncommand = [\"a\"]\n", "not an activation name"),
            (
                "name = \"a\\nb\"\ncommand = [\"a\"]\n",
                "not an activation name",
            ),
            ("name = \"a\"\ncommand = []\n", "is empty"),
            ("name = \"a\"\ncommand = \"a\"\n", "an array of strings"),
            ("name = \"a\"\ncommand = [1]\n", "an array of strings"),
            (
                "name = \"a\"\ncommand = [\"a b\"]\n",
                "must be a program name",
            ),
            ("name = \"a\"\ncommand = [\"\"]\n", "must be a program name"),
            (
                "name = \"a\"\ncommand = [\"-a\"]\n",
                "must be a program name",
            ),
            (
                "name = \"a\"\ncommand = [\"bin/a\"]\n",
                "must be a program name",
            ),
            (
                "name = \"a\"\ncommand = [\"a]\"]\n",
                "must be a program name",
            ),
            (
                "name = \"a\"\ncommand = [\"/\"]\n",
                "must be a program name",
            ),
            (
                "name = \"a\"\ncommand = [\"/a b\"]\n",
                "must be a program name",
            ),
            ("name = \"a\"\ncommand = [\"a\", \"x\\u0000\"]\n", "NUL"),
            (
                "name = \"a\"\ncommand = [\"a\"]\nphase = \"terminal\"\n",
                "not a phase",
            ),
            ("name = \"a\"\ncommand = [\"a\"]\nphase = 1\n", "a string"),
            (
                "name = \"a\"\ncommand = [\"a\"]\ncache = \"no\"\n",
                "a boolean",
            ),
            (
                "name = \"a\"\ncommand = [\"a\"]\nwhen = \"ssh\"\n",
                "unknown key `when`",
            ),
        ] {
            let err = parse(&format!("[[activation]]\n{body}")).expect_err(body);
            assert!(err.contains(needle), "{body}: {err}");
        }
    }

    #[test]
    fn a_never_cacheable_activation_is_a_guarded_quoted_invocation() {
        let mut plain = decl("fzf", &["fzf", "--zsh"]);
        plain.cache = false;
        assert_eq!(
            plain.invocation(),
            "(( $+commands[fzf] )) && eval \"$(fzf --zsh)\"\n"
        );
        let absolute = decl(
            "brew",
            &[
                "/opt/brew/bin/brew",
                "shell env",
                "it's",
                "",
                "{a,b}",
                "x=1",
            ],
        );
        assert_eq!(
            absolute.invocation(),
            "[[ -x /opt/brew/bin/brew ]] && eval \"$(/opt/brew/bin/brew 'shell env' \
             'it'\\''s' '' '{a,b}' 'x=1')\"\n"
        );
        // Every character a bare word may not hold is quoted.
        for c in "= \t\n;&|'\"$`[](){}<>\\*?!#~^".chars() {
            assert_ne!(quote(&format!("a{c}b")), format!("a{c}b"), "{c:?}");
        }
        assert_eq!(quote("--init=zsh"), "'--init=zsh'");
        assert_eq!(quote("a_./,:@%+-b"), "a_./,:@%+-b");

        // Rendered every time, and never cached, even with nothing installed.
        let host = Fake::default();
        let mut cache = Fingerprints::default();
        cache.set("activation:fzf", Fingerprint::raw(vec![1]));
        let (plan, file) = apply(&[plain.clone()], &mut cache, &host);
        assert_eq!(plan.steps()[0].outcome, Outcome::Plain);
        assert_eq!(plan.steps()[0].action(), Action::Unchanged);
        assert!(
            file.ends_with(
                "\n# bx phase: activations\n# bx activation: fzf\n\
                 (( $+commands[fzf] )) && eval \"$(fzf --zsh)\"\n"
            ),
            "{file}"
        );
        assert_eq!(host.runs(), 0);
        assert!(cache.get("activation:fzf").is_none(), "never cached");
    }

    #[test]
    fn a_second_apply_on_an_unchanged_machine_runs_nothing_and_renders_the_same_bytes() {
        let host = Fake::default()
            .tool(
                "starship",
                b"starship 1.0",
                &["export STARSHIP_SHELL=zsh\n"],
            )
            .tool("zoxide", b"zoxide 0.9", &["z() { :; }\n"]);
        let mut completions = decl("starship", &["starship", "init", "zsh"]);
        completions.phase = Phase::Completions;
        let decls = [completions, decl("zoxide", &["zoxide", "init", "zsh"])];
        let mut cache = Fingerprints::default();

        let (first, file) = apply(&decls, &mut cache, &host);
        assert_eq!(host.runs(), 4, "each new capture runs twice");
        for step in first.steps() {
            assert_eq!(step.action(), Action::Create, "{step:?}");
        }
        assert_eq!(cache.len(), 2);
        assert!(
            file.contains("eval 'export STARSHIP_SHELL=zsh\n'\n"),
            "{file}"
        );
        assert!(
            file.find("# bx phase: activations").unwrap()
                < file.find("# bx phase: completions").unwrap()
        );

        let saved = cache.clone();
        let (second, again) = apply(&decls, &mut cache, &host);
        assert_eq!(host.runs(), 4, "the second apply starts no process");
        assert_eq!(again, file, "byte-identical");
        assert_eq!(cache, saved, "the cache is unchanged");
        for step in second.steps() {
            assert!(matches!(step.outcome, Outcome::Reused { .. }), "{step:?}");
            assert_eq!(step.action(), Action::Unchanged);
        }
    }

    #[test]
    fn only_a_change_in_the_binarys_content_or_the_command_runs_it_again() {
        let mut host = Fake::default().tool("mise", b"mise 1", &["v1\n"]);
        let decls = [decl("mise", &["mise", "activate", "zsh"])];
        let mut cache = Fingerprints::default();
        apply(&decls, &mut cache, &host);
        assert_eq!(host.runs(), 2);

        // The same content at the same path is reused, whatever else changed.
        host.upgrade("mise", b"mise 1", &["ignored\n"]);
        let (plan, file) = apply(&decls, &mut cache, &host);
        assert_eq!(host.runs(), 2);
        assert!(file.contains("eval 'v1\n'"), "{file}");
        assert_eq!(plan.steps()[0].action(), Action::Unchanged);

        // New content runs it again and replaces the entry.
        host.upgrade("mise", b"mise 2", &["v2\n"]);
        let (plan, file) = apply(&decls, &mut cache, &host);
        assert_eq!(host.runs(), 4);
        assert!(file.contains("eval 'v2\n'"), "{file}");
        assert_eq!(plan.steps()[0].action(), Action::Modify);
        assert!(plan.steps()[0].line().contains("cache replaced"));

        // So does a changed command.
        let changed = [decl("mise", &["mise", "activate", "bash"])];
        apply(&changed, &mut cache, &host);
        assert_eq!(host.runs(), 6);
    }

    #[test]
    fn the_cache_key_covers_the_binarys_content_its_path_and_the_command() {
        let content = ContentHash::of(b"a");
        let base = inputs(&content, Path::new("/bin/a"), &["a".into(), "x".into()]);
        assert_eq!(
            base,
            inputs(&content, Path::new("/bin/a"), &["a".into(), "x".into()])
        );
        for other in [
            inputs(
                &ContentHash::of(b"b"),
                Path::new("/bin/a"),
                &["a".into(), "x".into()],
            ),
            inputs(&content, Path::new("/opt/a"), &["a".into(), "x".into()]),
            inputs(&content, Path::new("/bin/a"), &["a".into(), "y".into()]),
            // Length-prefixed, so words cannot run together.
            inputs(&content, Path::new("/bin/a"), &["ax".into()]),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn output_that_differs_between_two_runs_is_omitted_uncached_and_retried() {
        let host = Fake::default().tool("uv", b"uv", &["one\n", "two\n", "two\n"]);
        let decls = [decl("uv", &["uv", "generate-shell-completion", "zsh"])];
        let mut cache = Fingerprints::default();

        let (plan, file) = apply(&decls, &mut cache, &host);
        assert_eq!(
            plan.steps()[0].outcome,
            Outcome::Omitted(Omission::Unstable)
        );
        assert_eq!(plan.steps()[0].action(), Action::Blocked);
        assert!(
            plan.steps()[0]
                .line()
                .contains("omitted: two consecutive runs")
        );
        assert!(!file.contains("activation: uv"), "{file}");
        assert!(cache.is_empty(), "never cached");

        // Retried at the next plan, and trusted once two runs agree.
        let (plan, file) = apply(&decls, &mut cache, &host);
        assert!(matches!(plan.steps()[0].outcome, Outcome::Captured { .. }));
        assert!(file.contains("eval 'two\n'"), "{file}");
        assert_eq!(host.runs(), 4);
    }

    #[test]
    fn an_absent_or_misbehaving_tool_is_omitted_and_everything_else_renders() {
        let mut host = Fake::default()
            .tool("ok", b"ok", &["ok\n"])
            .tool("binary", b"bin", &["\u{0}\n"])
            .failing(
                "fails",
                RunError::Exited {
                    status: "exit status: 3".into(),
                    stderr: "boom".into(),
                },
            )
            .failing("slow", RunError::TimedOut(TIMEOUT))
            .tool("locked", b"locked", &["x\n"])
            .tool("noexec", b"noexec", &["x\n"]);
        host.unreadable.push("locked".into());
        host.inexecutable.push("noexec".into());
        host.outputs.borrow_mut().insert(
            PathBuf::from("/usr/bin/latin1"),
            VecDeque::from([Ok(vec![0xff])]),
        );
        host.tools
            .insert("latin1".into(), ("/usr/bin/latin1".into(), b"l".to_vec()));

        let decls: Vec<_> = [
            "absent", "binary", "fails", "slow", "locked", "noexec", "latin1", "ok",
        ]
        .iter()
        .map(|name| decl(name, &[name]))
        .collect();
        let mut cache = Fingerprints::default();
        for decl in &decls {
            cache.set(decl.key(), Fingerprint::raw(vec![0]));
        }
        let (plan, file) = apply(&decls, &mut cache, &host);

        let notes: Vec<String> = plan.steps().iter().map(Step::line).collect();
        assert_eq!(
            notes,
            [
                "? activation `absent`: omitted: `absent` is not on PATH",
                "? activation `binary`: omitted: it printed something that is not text",
                "? activation `fails`: omitted: it exited with exit status: 3: boom",
                "? activation `slow`: omitted: it was still running after 10 s and was stopped",
                "? activation `locked`: omitted: its binary cannot be hashed: permission denied",
                "? activation `noexec`: omitted: /usr/bin/noexec is not executable by this account",
                "? activation `latin1`: omitted: it printed something that is not text",
                "~ activation `ok`: binary or command changed; run twice, output agreed; \
                 cache replaced",
            ]
        );
        assert!(
            file.contains("# bx activation: ok\neval 'ok\n'\n"),
            "{file}"
        );
        assert_eq!(file.matches("# bx activation:").count(), 1, "{file}");
        let keys: Vec<&String> = cache.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["activation:ok"], "an omission forgets its entry");
    }

    #[test]
    fn recording_forgets_only_activation_entries_nothing_uses() {
        let host = Fake::default().tool("a", b"a", &["a\n"]);
        let mut off = decl("b", &["b"]);
        off.enabled = false;
        let decls = [decl("a", &["a"]), off];
        let mut cache = Fingerprints::default();
        cache.set("activation:b", Fingerprint::raw(vec![1]));
        cache.set("activation:gone", Fingerprint::raw(vec![1]));
        cache.set("other:thing", Fingerprint::raw(vec![1]));
        let (plan, _) = apply(&decls, &mut cache, &host);
        assert_eq!(
            plan.steps().len(),
            1,
            "a disabled activation is not planned"
        );
        let keys: Vec<&String> = cache.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["activation:a", "other:thing"]);
    }

    #[test]
    fn an_entry_that_does_not_decode_is_a_miss() {
        let host = Fake::default().tool("a", b"a", &["a\n"]);
        let decls = [decl("a", &["a"])];
        let mut cache = Fingerprints::default();
        cache.set(
            "activation:a",
            Fingerprint::raw(b"not messagepack".to_vec()),
        );
        let (plan, _) = apply(&decls, &mut cache, &host);
        assert_eq!(plan.steps()[0].action(), Action::Modify);
        assert_eq!(host.runs(), 2);
        let entry = Entry::decode(cache.get("activation:a").unwrap()).expect("decodes");
        assert_eq!(entry.output, "a\n");
    }

    #[test]
    fn a_rendered_activation_is_one_eval_of_a_literal_and_sets_nothing_itself() {
        // Invariant 2: the phase is not an environment fragment. The tool's
        // text, however hostile, is the single-quoted argument of one `eval`;
        // stripping that literal leaves bx's own bytes, which set nothing.
        let output = "export A='1'\nB=2; echo \"$(x)\" '\\''\n}\n'unterminated\n";
        let step = Step {
            decl: decl("t", &["t"]),
            outcome: Outcome::Reused {
                output: output.to_string(),
            },
        };
        let body = step.body().expect("renders");
        let rest = body
            .strip_prefix("# bx activation: t\neval '")
            .and_then(|b| b.strip_suffix("'\n"))
            .expect("one eval of one literal");
        // Inside the literal, a quote appears only as the `'\''` escape, so the
        // literal never ends early and the text round-trips.
        assert_eq!(rest.replace(r"'\''", "'"), output);
        assert!(!rest.replace(r"'\''", "").contains('\''), "{rest}");

        let mut plain = decl("p", &["p", "--x=1"]);
        plain.cache = false;
        let plain = Step {
            decl: plain,
            outcome: Outcome::Plain,
        }
        .body()
        .expect("renders");
        for line in plain.lines() {
            // Outside quotes, nothing assigns: the only `=` is quoted.
            let unquoted: String = line.split('\'').step_by(2).collect();
            assert!(!unquoted.contains('='), "{line}");
        }

        assert_eq!(
            Step {
                decl: decl("o", &["o"]),
                outcome: Outcome::Omitted(Omission::NotText),
            }
            .body(),
            None
        );
    }

    #[test]
    fn zsh_runs_a_cached_activation_as_the_tool_wrote_it_and_contains_a_broken_one() {
        let Some(zsh) = installed_zsh() else { return };
        let step = |name: &str, output: &str| Step {
            decl: decl(name, &[name]),
            outcome: Outcome::Reused {
                output: output.to_string(),
            },
        };
        let steps = vec![
            step(
                "quoted",
                "export X='a'\\''b $HOME' W=\"$HOME/w\"\nz() { print -r -- zed; }\n",
            ),
            step("broken", "echo 'never closed\n"),
            step("after", "export Y=ok\n"),
        ];
        let mut assembly = Assembly::new();
        Plan { steps }
            .contribute(&mut assembly)
            .expect("contributes");
        let dir = tempfile::TempDir::new().expect("tempdir");
        let file = dir.path().join("zshrc.zsh");
        std::fs::write(&file, assembly.render()).expect("write");
        let out = Command::new(zsh)
            .args([
                "-f",
                "-c",
                "source \"$1\"; print -r -- \"$X|$W|$Y|$(z)\"",
                "zsh",
            ])
            .arg(&file)
            .env_clear()
            .env("HOME", dir.path())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("zsh runs");
        let home = dir.path().display();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("a'b $HOME|{home}/w|ok|zed\n")
        );
    }

    /// Where zsh is, or `None` where this machine is excused from having it —
    /// the excuse `env_guard`'s differential checks honour, which no runner
    /// may take.
    fn installed_zsh() -> Option<PathBuf> {
        match detect::locate_in_env("zsh") {
            Presence::Present { path } => Some(path),
            _ => {
                let excused = std::env::var_os("BX_TEST_WITHOUT_SHELLS").is_some()
                    && std::env::var_os("CI").is_none();
                assert!(
                    excused,
                    "zsh is not installed; install it, or set BX_TEST_WITHOUT_SHELLS off a runner"
                );
                None
            }
        }
    }

    /// A tool named `tool` on a search path of its own: a link to `sh`, so the
    /// test starts a real process without writing an executable.
    fn linked_sh() -> (tempfile::TempDir, System) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::os::unix::fs::symlink("/bin/sh", dir.path().join("tool")).expect("link");
        let system = System::new(dir.path().as_os_str(), Duration::from_secs(5));
        (dir, system)
    }

    #[test]
    fn the_system_runs_the_resolved_binary_and_caches_what_it_printed() {
        let (dir, system) = linked_sh();
        let decls = [decl("tool", &["tool", "-c", "printf 'export X=1\\n'"])];
        let mut cache = Fingerprints::default();
        let plan_one = plan(&decls, &cache, &system);
        assert_eq!(
            plan_one.steps()[0].body().expect("captured"),
            "# bx activation: tool\neval 'export X=1\n'\n"
        );
        plan_one.record(&mut cache);
        let plan_two = plan(&decls, &cache, &system);
        assert!(matches!(
            plan_two.steps()[0].outcome,
            Outcome::Reused { .. }
        ));
        assert_eq!(
            system.locate("tool"),
            Presence::Present {
                path: dir.path().join("tool")
            }
        );
        assert_eq!(system.locate("absent-tool"), Presence::Missing);
        assert!(system.hash(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn the_system_reports_a_failing_slow_or_noisy_command() {
        let (dir, system) = linked_sh();
        let sh = dir.path().join("tool");
        let run = |system: &System, script: &str| {
            system.run(&sh, &["-c".to_string(), script.to_string()])
        };
        assert_eq!(run(&system, "printf ok"), Ok(b"ok".to_vec()));
        // A tool that warns at length still succeeds.
        assert_eq!(
            run(&system, "head -c 1000000 /dev/zero >&2; printf ok"),
            Ok(b"ok".to_vec())
        );
        assert_eq!(
            run(&system, "echo first >&2; echo second >&2; exit 3"),
            Err(RunError::Exited {
                status: "exit status: 3".to_string(),
                stderr: "first".to_string(),
            })
        );
        assert_eq!(
            run(&system, "exit 4").unwrap_err().to_string(),
            "it exited with exit status: 4"
        );
        let quick = System::new(dir.path().as_os_str(), Duration::from_millis(200));
        assert_eq!(
            run(&quick, "sleep 5"),
            Err(RunError::TimedOut(Duration::from_millis(200)))
        );
        // A child left holding the pipe bounds the read by the same deadline.
        assert_eq!(
            run(&quick, "sleep 5 & exit 0"),
            Err(RunError::TimedOut(Duration::from_millis(200)))
        );
        assert_eq!(
            run(&system, &format!("head -c {} /dev/zero", LIMIT + 1)),
            Err(RunError::TooLarge(LIMIT))
        );
        assert_eq!(
            run(&system, &format!("head -c {LIMIT} /dev/zero")).map(|o| o.len()),
            Ok(LIMIT)
        );
        assert!(matches!(
            system.run(&dir.path().join("absent"), &[]),
            Err(RunError::Spawn(_))
        ));
        assert!(System::from_env().timeout == TIMEOUT);
    }
}
