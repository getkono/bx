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
//! enabled = true                              # default true
//! ```
//!
//! `command[0]` is the tool: a bare program name looked up on `PATH`, or an
//! absolute path. Either way it holds only characters a bare shell word holds.
//!
//! There is no never-cacheable form. A shell start spawns no process
//! (invariant 6), so an activation that must be fresh in every shell is not an
//! `eval "$(tool …)"` at all: it is a guarded, optional source of a file the
//! tool maintains itself, such as keychain's `~/.keychain/<host>-sh`.
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
//! omitted with a note and never cached, so the next `plan` tries again.
//!
//! An activation whose tool is absent, not executable, unreadable, fails, runs
//! past [`TIMEOUT`], prints more than [`LIMIT`] bytes, prints something that
//! is not text, or prints an assignment the environment guard refuses is
//! **omitted** — the step says why — and every other
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
//! has to run, and returns [`Step`]s that say which were reused, captured or
//! omitted. `apply` does not decide again. It hands the same
//! [`Plan`] to [`Plan::contribute`], which renders the file, and to
//! [`Plan::record`], which writes the captures into the cache it then saves. A
//! second `plan` against an unchanged machine therefore reuses every entry,
//! starts no process, and renders the same bytes.
//!
//! # Invariant 2
//!
//! Invariant 2 forbids moving a tool's config, data or cache outside a root
//! the configuration declares. A tool's activation output is the tool's own
//! shell code: it assigns variables of its own — `MISE_SHELL`,
//! `STARSHIP_SHELL`, a function's locals, ZLE's `BUFFER` — defines functions
//! and registers hooks, and none of that moves a file. So it is held to the
//! relocation rule, not to the environment-fragment grammar: **every
//! assignment it makes to a variable that relocates a tool is judged by
//! [`env_guard::check`] before it is written**, against the same [`RootSet`]
//! every environment fragment is judged against, and an output with one the
//! guard refuses, or one bx cannot value, is omitted as a blocked step naming
//! the variable. Nothing it would have set reaches the file.
//!
//! [`relocations`] is that judgement. It searches the whole output for every
//! name [`env_guard::is_relocating`] knows — the emit table's locations and
//! anchors, the `XDG_*_HOME` family, and the tool homes the guard lists — and
//! judges each occurrence that stands in an assigning position: a readable
//! `NAME=WORD` goes to [`env_guard::check`], and every other form that assigns
//! or may — `NAME+=`, an array, a quoted `NAME=`, an operand of `export`,
//! `typeset`, `local`, `read` and the other assigning builtins, an arithmetic
//! assignment, `${NAME:=…}`, the name given as a value an indirect assignment
//! could use — is refused as [`Reason::Unreadable`]. Every other line of the
//! output passes untouched, so the real outputs of mise, starship, zoxide, fzf
//! and uv are cached and rendered; `the_real_outputs_of_common_tools_render`
//! holds that against captured outputs in `tests/fixtures/activation/`.
//!
//! What the output's code does when it runs — `mise activate zsh`'s
//! `eval "$(mise hook-env)"` at every prompt — is the tool's own behaviour at
//! runtime, not bytes bx emits, and is outside this judgement.
//!
//! What passes is rendered as **one `eval` statement whose single argument is
//! a single-quoted literal** holding the tool's output byte for byte, so bx's
//! own bytes set nothing and a malformed output fails inside its own `eval`
//! rather than swallowing the rest of the file.
//! `a_rendered_activation_is_one_eval_of_a_literal_and_sets_nothing_itself`
//! holds the rendered bytes to that, and
//! `every_assignment_to_a_relocating_variable_is_judged_by_the_guard` holds
//! the search.

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
use crate::env_guard::{self, Reason, RootSet, Verdict, Violation};
use crate::report::Action;
use crate::state::{ContentHash, Fingerprint, Fingerprints};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[activation]]";

/// Every key an `[[activation]]` entry may carry.
const KEYS: [&str; 4] = ["name", "command", "phase", "enabled"];

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
             `_.+-`, or an absolute path of those and `/,:@%`, so it can be looked up"
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
    /// The environment guard refuses an assignment the output makes.
    Refused {
        /// The first refusal, its line counted within the output.
        first: Violation,
        /// How many more the output holds.
        more: usize,
    },
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
                 the next plan runs it again",
            ),
            Self::Refused { first, more } => {
                write!(
                    f,
                    "the environment guard refuses its output: `{}` at line {} {}",
                    first.name, first.line, first.reason
                )?;
                match more {
                    0 => Ok(()),
                    1 => f.write_str("; 1 more assignment is refused"),
                    n => write!(f, "; {n} more assignments are refused"),
                }
            }
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
    /// is converged, a first capture creates a cache entry and a re-capture
    /// modifies one, and an omission is blocked until the tool behaves.
    #[must_use]
    pub const fn action(&self) -> Action {
        match &self.outcome {
            Outcome::Reused { .. } => Action::Unchanged,
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
    /// one, a refused one, and one no enabled declaration names any more — so an omission is retried from nothing. Entries this module
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
                Outcome::Omitted(_) => {}
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
/// `cache`, running on `host` only what the cache cannot answer, and judging
/// every output — reused or captured — against `roots`.
///
/// `cache` is read, never written: [`Plan::record`] is what applies the
/// decisions to it.
#[must_use]
pub fn plan(
    decls: &[ActivationDecl],
    cache: &Fingerprints,
    roots: &RootSet,
    host: &impl Host,
) -> Plan {
    let steps = decls
        .iter()
        .filter(|decl| decl.enabled)
        .map(|decl| {
            let outcome = decide(decl, cache, host);
            let refused = match &outcome {
                Outcome::Reused { output } | Outcome::Captured { output, .. } => {
                    judged(output, roots)
                }
                Outcome::Omitted(_) => None,
            };
            Step {
                decl: decl.clone(),
                outcome: refused.map_or(outcome, Outcome::Omitted),
            }
        })
        .collect();
    Plan { steps }
}

/// Why the guard keeps `output` out of the file, or `None` when it refuses
/// none of its assignments to a relocating variable.
fn judged(output: &str, roots: &RootSet) -> Option<Omission> {
    let mut refused = relocations(output, roots).into_iter();
    refused.next().map(|first| Omission::Refused {
        first,
        more: refused.len(),
    })
}

/// Decide one activation, before the guard judges its output.
fn decide(decl: &ActivationDecl, cache: &Fingerprints, host: &impl Host) -> Outcome {
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

/// Commands and keywords whose operands may be names they assign, by value or
/// indirectly: an occurrence of a relocating name among the operands of a
/// command whose command word is one of these is refused, whatever else
/// surrounds it.
/// `unset` is not one: it takes a name back to its tool's native default.
const ASSIGNERS: [&str; 30] = [
    "alias",
    "compadd",
    "declare",
    "emulate",
    "eval",
    "export",
    "float",
    "for",
    "foreach",
    "getopts",
    "integer",
    "let",
    "local",
    "pcre_match",
    "print",
    "printf",
    "private",
    "read",
    "readonly",
    "select",
    "set",
    "strftime",
    "sysread",
    "trap",
    "typeset",
    "vared",
    "zparseopts",
    "zregexparse",
    "zselect",
    "zstat",
];

/// What ends the command an occurrence stands in, searching back from it: a
/// newline no backslash continues, a list or pipeline separator, a brace
/// group's edge, or a backtick substitution's.
const COMMAND_EDGES: [char; 7] = ['\n', ';', '&', '|', '{', '}', '`'];

/// Every assignment `output` makes to a relocating variable that
/// [`env_guard::check`] refuses under `roots`, or that bx cannot value, in the
/// order they occur, each numbered by its line within the output. An output
/// is written only when this is empty.
///
/// This is a search, not a reading of the whole output as shell. Every
/// occurrence of a name [`env_guard::is_relocating`] knows is found, wherever
/// it stands, and classified by what surrounds it:
///
/// * `$NAME`, and `${NAME…}` with any operator but an assigning one, read the
///   variable and pass;
/// * a line that begins with `#` is a comment, and passes;
/// * `NAME=WORD`, with nothing quoting or escaping the name, is judged by
///   [`env_guard::check`] when `WORD` is one shell word whose quotes close —
///   the check itself refuses one it cannot read, a substitution included;
/// * every other assigning form is refused as [`Reason::Unreadable`]:
///   `NAME+=`, a subscript, an array, a quoted or escaped `NAME=` (it is text
///   something else may run), `${NAME=…}` and its kin, an arithmetic
///   assignment or increment, the name given as the value of an assignment or
///   an array element (it may name the variable an indirect assignment
///   writes), and the name anywhere among the operands of a builtin or
///   keyword that assigns its operands — `export NAME`, `read NAME`,
///   `print -v NAME`, `for NAME in`, `eval "NAME…"`, `alias`, `trap` and the
///   rest of `ASSIGNERS`;
/// * a relocating name spelled in quoted or escaped pieces — `'CARGO'_HOME`,
///   `CARGO\_HOME`, `CARGO""_HOME` — is refused as [`Reason::Unreadable`]
///   wherever it stands, because quote removal hands whatever command it
///   reaches the whole name;
/// * anything else — the name in a string, a pattern or another command's
///   operand — passes.
///
/// A name that is not relocating is never looked at, so a tool's own
/// variables, functions and hooks pass untouched. The command word is found
/// by searching back from the occurrence, not by parsing, so a name that
/// follows an assigning word at the start of a line of a multi-line string
/// is refused: the search fails closed.
#[must_use]
pub fn relocations(output: &str, roots: &RootSet) -> Vec<Violation> {
    let chars: Vec<char> = output.chars().collect();
    let mut found = Vec::new();
    let mut k = 0;
    while k < chars.len() {
        if !is_name_char(chars[k]) {
            k += 1;
            continue;
        }
        let start = k;
        while chars.get(k).copied().is_some_and(is_name_char) {
            k += 1;
        }
        let name: String = chars[start..k].iter().collect();
        if name.starts_with(|c: char| c.is_ascii_digit()) || !env_guard::is_relocating(&name) {
            continue;
        }
        let refused = match occurrence(&chars, start, k) {
            Use::Reads => None,
            Use::Assigns(value) => match env_guard::check(&name, &value, roots) {
                Verdict::Allowed => None,
                Verdict::Violation(refused) => Some(refused),
            },
            Use::Unreadable => Some(Violation {
                line: 0,
                name: name.clone(),
                value: line_of(&chars, start).trim().to_string(),
                reason: Reason::Unreadable,
            }),
        };
        if let Some(refused) = refused {
            found.push((start, refused));
        }
    }
    for (start, name) in assembled(&chars) {
        found.push((
            start,
            Violation {
                line: 0,
                name,
                value: line_of(&chars, start).trim().to_string(),
                reason: Reason::Unreadable,
            },
        ));
    }
    found.sort_by_key(|(start, _)| *start);
    found
        .into_iter()
        .map(|(start, mut refused)| {
            refused.line = chars[..start].iter().filter(|c| **c == '\n').count() + 1;
            refused
        })
        .collect()
}

/// Whether `c` can be part of a variable name.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every relocating name `chars` spells only once quotes and escapes are
/// removed — `'CARGO'_HOME`, `CARGO\_HOME`, `CARGO""_HOME`, `$'CARGO'_HOME` —
/// with where the word it is spelled by starts.
///
/// The word is read as the shell's quote removal would leave it: a run of
/// name characters, quotes, and backslashes that escape a name character.
/// It is a relocating name split by quoting when what remains is exactly
/// that name and a quote or escape stands between two of its characters. A
/// word whose quotes only surround the name is left to the search for the
/// unbroken name, and a word that begins as `$NAME` is an expansion, not a
/// name. Such a word is refused wherever it stands, since `export`,
/// `typeset` and every other assigning command see the name it spells.
fn assembled(chars: &[char]) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut k = 0;
    while k < chars.len() {
        let start = k;
        let mut name = String::new();
        // Whether a quote or escape stands since the last name character.
        let mut quoted = false;
        let mut split = false;
        while let Some(&c) = chars.get(k) {
            if is_name_char(c) {
                split |= quoted && !name.is_empty();
                quoted = false;
                name.push(c);
            } else if c == '\''
                || c == '"'
                || (c == '\\' && chars.get(k + 1).is_some_and(|n| is_name_char(*n)))
            {
                quoted = true;
            } else {
                break;
            }
            k += 1;
        }
        if k == start {
            k += 1;
            continue;
        }
        let expands = start > 0 && chars[start - 1] == '$' && is_name_char(chars[start]);
        let comment = line_of(chars, start).trim_start().starts_with('#');
        if !split || expands || comment {
            continue;
        }
        if name.starts_with(|c: char| c.is_ascii_digit()) || !env_guard::is_relocating(&name) {
            continue;
        }
        found.push((start, name));
    }
    found
}

/// What one occurrence of a relocating name does.
enum Use {
    /// It reads the variable, or is only text.
    Reads,
    /// It assigns the variable this word, as written.
    Assigns(String),
    /// It assigns, or may, a value that cannot be read.
    Unreadable,
}

/// What the name occupying `chars[start..end]` does, from what surrounds it.
fn occurrence(chars: &[char], start: usize, end: usize) -> Use {
    let before = &chars[..start];
    let line = line_of(chars, start);
    if line.trim_start().starts_with('#') {
        return Use::Reads;
    }
    if let Some(reads) = expansion(before, &chars[end..]) {
        return if reads { Use::Reads } else { Use::Unreadable };
    }

    // What follows the name: a subscript, then an operator.
    let mut after = end;
    let subscript = chars.get(after) == Some(&'[');
    if subscript {
        match chars[after..].iter().position(|c| *c == ']') {
            Some(p) => after += p + 1,
            None => return Use::Unreadable,
        }
    }
    let rest = &chars[after..];
    let quoted = before
        .last()
        .is_some_and(|c| matches!(c, '\'' | '"' | '\\' | '`'));
    if rest.first() == Some(&'=') && !matches!(rest.get(1), Some('=' | '~')) {
        if subscript || quoted || rest.get(1) == Some(&'(') {
            return Use::Unreadable;
        }
        return word(&rest[1..]).map_or(Use::Unreadable, Use::Assigns);
    }
    if rest.starts_with(&['+', '=']) || rest.starts_with(&['\\', '=']) {
        return Use::Unreadable;
    }
    if arithmetic(before, rest) {
        return Use::Unreadable;
    }

    // Where the name is a value or an operand, what it is given to.
    let preceding: String = before
        .iter()
        .rev()
        .take_while(|c| matches!(c, '\'' | '"'))
        .collect();
    if before[..start - preceding.len()].last() == Some(&'=') {
        return Use::Unreadable;
    }
    let command = command_before(before, &COMMAND_EDGES);
    let in_array = command
        .rfind("=(")
        .is_some_and(|open| !command[open..].contains(')'));
    // The command word, read both across parentheses — `local x=$(y) NAME` —
    // and within them — `case $a in b) export NAME`.
    let grouped = command_before(before, &[&COMMAND_EDGES[..], &['(', ')']].concat());
    let assigner = [command.as_str(), grouped.as_str()]
        .into_iter()
        .filter_map(command_word)
        .any(|word| ASSIGNERS.contains(&word));
    if in_array || assigner {
        Use::Unreadable
    } else {
        Use::Reads
    }
}

/// Words that leave the next word in command position.
const PRECOMMANDS: [&str; 14] = [
    "if",
    "then",
    "elif",
    "else",
    "while",
    "until",
    "do",
    "time",
    "builtin",
    "command",
    "exec",
    "noglob",
    "nocorrect",
    "-",
];

/// The word of `command` in command position, past any precommand, keyword
/// or prefix assignment, with the quotes, escapes and openers that can wrap
/// a command name taken off.
fn command_word(command: &str) -> Option<&str> {
    // The quote a prefix assignment's value left open, whose blanks do not
    // end the value.
    let mut open: Option<char> = None;
    for raw in command.split_whitespace() {
        if let Some(quote) = open {
            if raw.matches(quote).count() % 2 == 1 {
                open = None;
            }
            continue;
        }
        let word = raw
            .trim_start_matches(['\\', '\'', '"', '(', '!', '$'])
            .trim_end_matches(['\'', '"']);
        if word.is_empty() || PRECOMMANDS.contains(&word) {
            continue;
        }
        if let Some((name, value)) = raw.split_once('=')
            && !name.is_empty()
            && name.chars().all(is_name_char)
        {
            open = ['"', '\'']
                .into_iter()
                .find(|quote| value.matches(*quote).count() % 2 == 1);
            continue;
        }
        return Some(word);
    }
    None
}

/// Whether the name that `before` ends at and `after` begins at sits inside a
/// `${…}` expansion: `Some(true)` when the expansion only reads it,
/// `Some(false)` when it assigns it (`${NAME=…}`, `${NAME:=…}`,
/// `${NAME::=…}`), and `None` when it is not in one. `$NAME` reads it too.
fn expansion(before: &[char], after: &[char]) -> Option<bool> {
    if before.last() == Some(&'$') {
        return Some(true);
    }
    // Flags a `${…}` may carry before its name: `${#…}`, `${(j: :)…}`.
    let mut open = before.len();
    while open > 0 && "#!^=~+".contains(before[open - 1]) {
        open -= 1;
    }
    if open > 0 && before[open - 1] == ')' {
        open = before[..open].iter().rposition(|c| *c == '(')?;
    }
    if !before[..open].ends_with(&['$', '{']) {
        return None;
    }
    let mut k = 0;
    if after.first() == Some(&'[') {
        k = after
            .iter()
            .position(|c| *c == ']')
            .map_or(after.len(), |p| p + 1);
    }
    let rest = &after[k..];
    let assigns = rest.starts_with(&['='])
        || rest.starts_with(&[':', '='])
        || rest.starts_with(&[':', ':', '=']);
    Some(!assigns)
}

/// Whether the name between `before` and `rest` is assigned in arithmetic:
/// followed, after blanks, by `=` that is not `==`, by a compound assignment
/// or by `++`/`--`, or preceded by `++`/`--`.
fn arithmetic(before: &[char], rest: &[char]) -> bool {
    let next: String = rest
        .iter()
        .skip_while(|c| **c == ' ' || **c == '\t')
        .take(3)
        .collect();
    let assigns = (next.starts_with('=') && !next.starts_with("==") && !next.starts_with("=~"))
        || [
            "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "**=", "++", "--",
        ]
        .iter()
        .any(|op| next.starts_with(op));
    let previous: String = before
        .iter()
        .rev()
        .skip_while(|c| **c == ' ' || **c == '\t')
        .take(2)
        .collect();
    assigns || previous == "++" || previous == "--"
}

/// The text of the command `before` ends in: back to the nearest of `edges`
/// no backslash escapes, so a backslash-continued newline joins the lines it
/// splits and an escaped backtick is only text.
fn command_before(before: &[char], edges: &[char]) -> String {
    let mut k = before.len();
    while k > 0 {
        let c = before[k - 1];
        let escaped = k >= 2 && before[k - 2] == '\\';
        if edges.contains(&c) && !escaped {
            break;
        }
        k -= 1;
    }
    before[k..].iter().collect()
}

/// The shell word `text` begins with, as written — quotes and escapes kept —
/// or `None` when a quote in it does not close.
fn word(text: &[char]) -> Option<String> {
    let mut k = 0;
    while let Some(&c) = text.get(k) {
        match c {
            ' ' | '\t' | '\n' | ';' | '&' | '|' | ')' | '<' | '>' => break,
            '\'' => k += 2 + text[k + 1..].iter().position(|c| *c == '\'')?,
            '"' => {
                let mut j = k + 1;
                loop {
                    match text.get(j)? {
                        '\\' => j += 2,
                        '"' => break,
                        _ => j += 1,
                    }
                }
                k = j + 1;
            }
            '\\' => k += 2,
            _ => k += 1,
        }
    }
    Some(text[..k.min(text.len())].iter().collect())
}

/// The whole line the character at `at` is on.
fn line_of(chars: &[char], at: usize) -> String {
    let start = chars[..at]
        .iter()
        .rposition(|c| *c == '\n')
        .map_or(0, |p| p + 1);
    let end = chars[at..]
        .iter()
        .position(|c| *c == '\n')
        .map_or(chars.len(), |p| at + p);
    chars[start..end].iter().collect()
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
        let plan = plan(decls, cache, &RootSet::strict(), host);
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
             phase = \"completions\"\nenabled = false\n\
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
                    enabled: true,
                    origin: Origin {
                        file: PathBuf::from("/repo/bx.toml"),
                        line: 6,
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
                "name = \"a\"\ncommand = [\"a\"]\nenabled = \"no\"\n",
                "a boolean",
            ),
            // The never-cacheable form is gone, and saying so is refused.
            (
                "name = \"a\"\ncommand = [\"a\"]\ncache = false\n",
                "unknown key `cache`",
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
    fn every_assignment_to_a_relocating_variable_is_judged_by_the_guard() {
        use Reason::{NoRootsDeclared, NotEmittable, Unreadable};
        /// One refusal: its line, the variable it names, and why.
        type Refusal = (usize, &'static str, Reason);
        let strict = RootSet::strict();
        // (output, every refusal it holds).
        let cases: &[(&str, &[Refusal])] = &[
            // A tool's own variables, functions and constructs pass untouched,
            // however they assign: none of them relocates anything.
            (
                "export STARSHIP_SHELL=zsh\nexport MISE_SHELL=zsh\nlocal ret=1\n",
                &[],
            ),
            ("x=$(Y=1 cmd)\nX+=1\nX=(a b)\nread X\n", &[]),
            ("eval \"$(mise hook-env -s zsh)\"\n", &[]),
            (
                "(( X = 1 ))\nfor (( i = 0; i < 2; i++ )); do :; done\n",
                &[],
            ),
            ("cat <<EOF\nX=1\nEOF\necho 'unclosed\n", &[]),
            // Review item D6: `&&` inside `[[ … ]]` with a comparison after it.
            (
                "if [[ \"$a\" == \"b\" && \"$c\" != \"d\" ]]; then :; fi\n",
                &[],
            ),
            // A relocating name that is read, or is only text, passes.
            ("export PATH=\"$XDG_DATA_HOME/bin:$PATH\"\n", &[]),
            (
                "echo ${XDG_CACHE_HOME:-~/.cache} ${#CARGO_HOME} ${(j: :)CARGO_HOME}\n",
                &[],
            ),
            ("echo ${CARGO_HOME[1]} ${CARGO_HOME:+x}\n", &[]),
            ("[[ $x == CARGO_HOME || $CARGO_HOME == /x ]]\n", &[]),
            ("  # export CARGO_HOME=/x\n", &[]),
            ("unset XDG_CONFIG_HOME\n", &[]),
            ("'--cache-dir=[Path]:CACHE_DIR:_files -/' \\\n", &[]),
            ("MY_CARGO_HOME=/x\nCARGO_HOMES=/x\n1CARGO_HOME=/x\n", &[]),
            // A readable value is judged for what the name holds.
            (
                "export CARGO_HOME=/tmp/cargo\n",
                &[(1, "CARGO_HOME", NoRootsDeclared)],
            ),
            (
                "f() {\n  local XDG_CONFIG_HOME=/x\n}\n",
                &[(2, "XDG_CONFIG_HOME", NotEmittable)],
            ),
            (
                "CARGO_HOME=/tmp/c cargo build\n",
                &[(1, "CARGO_HOME", NoRootsDeclared)],
            ),
            (
                "true && XDG_CONFIG_HOME='/x'; _ZO_DATA_DIR=/y\n",
                &[
                    (1, "XDG_CONFIG_HOME", NotEmittable),
                    (1, "_ZO_DATA_DIR", NotEmittable),
                ],
            ),
            // Every other form that assigns, or may, is refused.
            ("CARGO_HOME+=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("CARGO_HOME[1]=x\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("CARGO_HOME[1\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("CARGO_HOME=(a b)\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("CARGO_HOME=\"unclosed\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("CARGO_HOME='unclosed\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("eval CARGO_HOME\\=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("export CARGO_HOME\n", &[(1, "CARGO_HOME", Unreadable)]),
            (
                "export \\\n  CARGO_HOME\n",
                &[(2, "CARGO_HOME", Unreadable)],
            ),
            (
                "\\typeset -gx CARGO_HOME\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "read -r XDG_CONFIG_HOME\n",
                &[(1, "XDG_CONFIG_HOME", Unreadable)],
            ),
            ("print -v CARGO_HOME x\n", &[(1, "CARGO_HOME", Unreadable)]),
            (
                "x=1 builtin export CARGO_HOME\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "if export CARGO_HOME; then :; fi\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "local x=$(y) CARGO_HOME\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "case $a in b) export CARGO_HOME ;; esac\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            ("$(export CARGO_HOME)\n", &[(1, "CARGO_HOME", Unreadable)]),
            (
                "x=\"a b\" y='c \"d' export CARGO_HOME\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            ("x=\"a b\" echo CARGO_HOME\n", &[]),
            // An escaped edge is text, so the command word is before it.
            ("_arguments 'a \\`for\\` b:CACHE_DIR:'\n", &[]),
            ("echo `for` CACHE_DIR\n", &[]),
            (
                "echo a; for CACHE_DIR in x; do :; done\n",
                &[(1, "CACHE_DIR", Unreadable)],
            ),
            (
                "for CARGO_HOME in a; do :; done\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            ("eval 'CARGO_HOME=/x'\n", &[(1, "CARGO_HOME", Unreadable)]),
            (
                "alias c='CARGO_HOME=/x cargo'\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "typeset -n r=CARGO_HOME\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            ("v='CARGO_HOME'\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("v=(a CARGO_HOME)\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("echo ${CARGO_HOME:=/x}\n", &[(1, "CARGO_HOME", Unreadable)]),
            (
                "echo ${(L)CARGO_HOME=/x}\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "echo ${CARGO_HOME::=/x}\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            ("(( CARGO_HOME = 1 ))\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("(( CARGO_HOME <<= 1 ))\n", &[(1, "CARGO_HOME", Unreadable)]),
            (
                "echo $(( CARGO_HOME++ ))\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            ("(( ++CARGO_HOME ))\n", &[(1, "CARGO_HOME", Unreadable)]),
            // Review item D7: a relocating name assembled from quoted or
            // escaped pieces is the name once quotes are removed, so it is
            // refused wherever it stands.
            ("export 'CARGO'_HOME=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
            ("export CARGO\\_HOME=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
            (
                "typeset -gx CARGO\"\"_HOME=/x\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "export $'CARGO'_HOME=/x\n",
                &[(1, "CARGO_HOME", Unreadable)],
            ),
            (
                "x=1\nC\"ARGO_HO\"ME=/x; echo 'XDG'\"_CONFIG_HOME\"\n",
                &[
                    (2, "CARGO_HOME", Unreadable),
                    (2, "XDG_CONFIG_HOME", Unreadable),
                ],
            ),
            // Quotes that only surround the name, an expansion joined to
            // text, a comment, and pieces that spell no relocating name pass.
            ("echo \"CARGO_HOME\" 'CARGO_HOME'\n", &[]),
            ("echo \"$CARGO\"_HOME ${CARGO}'_HOME'\n", &[]),
            ("# export 'CARGO'_HOME=/x\n", &[]),
            ("echo 'MY'_CARGO_HOME CARGO\\_HOMES '1'CARGO_HOME\n", &[]),
        ];
        for (output, expected) in cases {
            let found: Vec<(usize, String, Reason)> = relocations(output, &strict)
                .into_iter()
                .map(|v| (v.line, v.name, v.reason))
                .collect();
            let expected: Vec<(usize, String, Reason)> = expected
                .iter()
                .map(|(line, name, reason)| (*line, (*name).to_string(), *reason))
                .collect();
            assert_eq!(found, expected, "{output:?}");
        }

        // An unreadable refusal quotes its line.
        let quoted = relocations("true\n  export CARGO_HOME\n", &strict);
        assert_eq!(quoted[0].value, "export CARGO_HOME");
        // What a declared root allows, the guard allows here too.
        let rooted = RootSet::new(Path::new("/home/u"), &[PathBuf::from("/scratch")]);
        assert!(relocations("export CARGO_HOME=/scratch/cargo\n", &rooted).is_empty());
    }

    /// Every captured activation output under `tests/fixtures/activation/`,
    /// by the command that printed it. Each was captured from the real tool,
    /// with the absolute paths of the capturing machine replaced by neutral
    /// ones.
    const REAL_OUTPUTS: [(&str, &str); 5] = [
        (
            "mise activate zsh",
            include_str!("../../tests/fixtures/activation/mise-activate-zsh.zsh"),
        ),
        (
            "starship init zsh --print-full-init",
            include_str!("../../tests/fixtures/activation/starship-init-zsh.zsh"),
        ),
        (
            "zoxide init zsh",
            include_str!("../../tests/fixtures/activation/zoxide-init-zsh.zsh"),
        ),
        (
            "fzf --zsh",
            include_str!("../../tests/fixtures/activation/fzf-zsh.zsh"),
        ),
        (
            "uv generate-shell-completion zsh",
            include_str!("../../tests/fixtures/activation/uv-completion-zsh.zsh"),
        ),
    ];

    #[test]
    fn the_real_outputs_of_common_tools_render() {
        // Review items D1 to D5: the strict-grammar reader refused every one
        // of these, for assignments none of which relocates anything. Under
        // the strict root set too — nothing in them moves a tool.
        for (command, output) in REAL_OUTPUTS {
            assert_eq!(relocations(output, &RootSet::strict()), vec![], "{command}");
            let program = command.split(' ').next().unwrap();
            let host = Fake::default().tool(program, program.as_bytes(), &[output]);
            let mut activation = decl(program, &command.split(' ').collect::<Vec<_>>());
            activation.phase = Phase::Completions;
            let mut cache = Fingerprints::default();
            let (plan, file) = apply(&[activation], &mut cache, &host);
            assert_eq!(plan.steps()[0].action(), Action::Create, "{command}");
            assert!(file.contains(&literal(output)), "{command}");
        }
        // And one relocating assignment in any of them is still found.
        let (_, mise) = REAL_OUTPUTS[0];
        let moved = mise.replace(
            "export MISE_SHELL=zsh\n",
            "export MISE_SHELL=zsh\nexport MISE_DATA_DIR=/elsewhere\n",
        );
        let found = relocations(&moved, &RootSet::strict());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "MISE_DATA_DIR");
        assert_eq!(found[0].reason, Reason::NoRootsDeclared);
    }

    #[test]
    fn an_output_the_guard_refuses_is_blocked_named_and_never_written() {
        let host = Fake::default()
            .tool(
                "starship",
                b"starship",
                &["export STARSHIP_SHELL=zsh\nexport STARSHIP_CONFIG=/etc/x\n\
                   export CARGO_HOME=/c\nexport XDG_CACHE_HOME=/d\n"],
            )
            .tool("vi", b"vi", &["export EDITOR=vi\n"]);
        let decls = [decl("starship", &["starship"]), decl("vi", &["vi"])];
        let mut cache = Fingerprints::default();
        let (blocked, file) = apply(&decls, &mut cache, &host);
        let step = &blocked.steps()[0];
        assert_eq!(step.action(), Action::Blocked);
        assert_eq!(
            step.line(),
            "? activation `starship`: omitted: the environment guard refuses its output: \
             `STARSHIP_CONFIG` at line 2 assigns a variable no bx generator declares, so bx \
             cannot judge the value — a defect in bx, not in your configuration; 2 more \
             assignments are refused"
        );
        assert!(!file.contains("STARSHIP"), "{file}");
        assert!(
            file.contains("# bx activation: vi\neval 'export EDITOR=vi\n'\n"),
            "{file}"
        );
        let keys: Vec<&String> = cache.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["activation:vi"], "a refused output is never cached");

        // One more refusal, and an unreadable one, read as sentences.
        let one = Omission::Refused {
            first: relocations("export CARGO_HOME\n", &RootSet::strict()).remove(0),
            more: 1,
        };
        assert_eq!(
            one.to_string(),
            "the environment guard refuses its output: `CARGO_HOME` at line 1 is shell the \
             guard cannot read, so it is not approved; 1 more assignment is refused"
        );

        // A cached output is judged again at every plan: one the roots allowed
        // when it was captured is blocked, and forgotten, once they do not.
        let host = Fake::default().tool("cargo", b"cargo", &["export CARGO_HOME=/scratch/c\n"]);
        let decls = [decl("cargo", &["cargo"])];
        let rooted = RootSet::new(Path::new("/home/u"), &[PathBuf::from("/scratch")]);
        let mut cache = Fingerprints::default();
        plan(&decls, &cache, &rooted, &host).record(&mut cache);
        assert!(
            matches!(
                plan(&decls, &cache, &rooted, &host).steps()[0].outcome,
                Outcome::Reused { .. }
            ),
            "reused while the roots allow it"
        );
        let strict = plan(&decls, &cache, &RootSet::strict(), &host);
        assert!(matches!(
            &strict.steps()[0].outcome,
            Outcome::Omitted(Omission::Refused { first, more: 0 })
                if first.name == "CARGO_HOME" && first.reason == Reason::NoRootsDeclared
        ));
        assert_eq!(host.runs(), 2, "judging a cached output runs nothing");
        strict.record(&mut cache);
        assert!(cache.is_empty());
    }

    #[test]
    fn a_second_apply_on_an_unchanged_machine_runs_nothing_and_renders_the_same_bytes() {
        let host = Fake::default()
            .tool("starship", b"starship 1.0", &["export EDITOR=nvim\n"])
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
        assert!(file.contains("eval 'export EDITOR=nvim\n'\n"), "{file}");
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
        let decls = [decl(
            "tool",
            &["tool", "-c", "printf 'export EDITOR=vi\\n'"],
        )];
        let mut cache = Fingerprints::default();
        let roots = RootSet::strict();
        let plan_one = plan(&decls, &cache, &roots, &system);
        assert_eq!(
            plan_one.steps()[0].body().expect("captured"),
            "# bx activation: tool\neval 'export EDITOR=vi\n'\n"
        );
        plan_one.record(&mut cache);
        let plan_two = plan(&decls, &cache, &roots, &system);
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
