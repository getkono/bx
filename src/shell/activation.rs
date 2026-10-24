//! Declared tool activations, run once at `plan` time and cached, so a shell
//! that used to fork a process per tool at every start sources cached text
//! instead.
//!
//! # The `[[activation]]` schema
//!
//! ```toml
//! [[activation]]
//! name    = "starship"                        # required; the natural key
//! command = ["starship", "init", "{shell}"]   # argv, run without a shell
//! bash    = ["starship", "init", "bash"]      # optional; bash's own command
//! zsh     = ["starship", "init", "zsh"]       # optional; zsh's own command
//! shells  = ["zsh", "bash"]                   # optional; default every shell
//! phase   = "completions"                     # activations | completions; default activations
//! enabled = true                              # default true
//! ```
//!
//! `command[0]` is the tool: a bare program name looked up on `PATH`, or an
//! absolute path. Either way it holds only characters a bare shell word holds.
//!
//! # One command per shell
//!
//! A tool's integration is shell code, so each shell runs its own command
//! and caches its own output. The command a shell runs is, first, the one
//! its own key (`zsh` or `bash`) declares; else `command` with every
//! `{shell}` spelled as the shell's name — `starship init {shell}` is
//! `starship init zsh` for zsh and `starship init bash` for bash; else, for
//! zsh alone, `command` as written, since a `command` naming no shell is the
//! zsh integration it always was. A shell left with no command — bash, for a
//! `command` naming no `{shell}` and no `bash` key — is never given another
//! shell's output: the activation is not rendered there, and that shell's
//! generated file's plan row says so. `shells` keeps the activation to the
//! shells it lists, and a per-shell key for a shell it leaves out fails the
//! load. At least one of `command`, `zsh` and `bash` is required.
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
//! `activation:<name>` for zsh's command and `activation-bash:<name>` for
//! bash's — pairs a digest of that content, the resolved path and the whole
//! command with the output they produced. While the digest matches,
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
//! Commands run in bx's own process environment, with no input, and with
//! `PATH` set to exactly the search path the tool was looked up along. bx
//! does not build the environment the interactive shell will have before
//! running one.
//!
//! # The `PATH` a tool ran with
//!
//! A tool that puts itself on `PATH` prints the value it inherited:
//! `mise activate zsh` begins `export PATH='<its dirs>:<bx's PATH>'`. Cached
//! as printed, that would freeze whichever `PATH` the last capture ran under
//! into every shell, overwrite what `[path]` declares, and differ between
//! machines. So before an output is cached or judged, every occurrence of the
//! exact `PATH` value the tool ran with — standing as a whole value or list
//! entry, not as part of a longer path — is replaced by a reference to the
//! shell's own `$PATH`, quoted for the context it stands in: `"$PATH"` bare,
//! `${PATH}` inside double quotes, `'"$PATH"'` inside single quotes and
//! `'"$PATH"$'` inside `$'…'`. mise's line then prepends its directories to
//! the live `PATH` of the shell that runs it. The context is found by a
//! reading of quotes, escapes, comments, `$(…)` and backticks, not of here-
//! documents, whose bodies are read as ordinary lines.
//!
//! # Plan and apply
//!
//! [`plan`] is the one function: it decides every activation, runs whatever
//! has to run, and returns [`Step`]s that say which were reused, captured or
//! omitted. `apply` does not decide again. It hands the same
//! [`Plan`] to [`Plan::rendered`], whose text each interactive file carries
//! and renders through [`contribute`], and to
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

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{Assembly, Shell, quote};
use crate::config::target::Activated;
use crate::config::when::Machine;
use crate::detect::{self, Presence};
use crate::env_guard::{self, Reason, RootSet, Verdict, Violation};
use crate::report::Action;
use crate::state::{ContentHash, Fingerprint, Fingerprints};

/// The prefix of every cache key this module owns for zsh's commands.
pub const KEY_PREFIX: &str = "activation:";

/// The prefix of every cache key this module owns for bash's commands. Not an
/// extension of [`KEY_PREFIX`], so no activation name can spell one shell's
/// key as another's.
pub const BASH_KEY_PREFIX: &str = "activation-bash:";

/// What a `command` word spells the shell with.
pub const SHELL_PLACEHOLDER: &str = "{shell}";

/// How long one run of an activation's command may take.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The most output one run may print, in bytes.
pub const LIMIT: usize = 1 << 20;

/// How much of a failing command's standard error a note quotes.
const STDERR_KEPT: usize = 512;

/// A declared tool activation, as [`crate::config::activation`] parses it,
/// named here too, where everything that runs and renders one already looks
/// for it.
pub use crate::config::activation::ActivationDecl;

impl ActivationDecl {
    /// The [`Fingerprints`] key zsh's cache entry lives under.
    #[cfg(test)]
    #[must_use]
    pub fn key(&self) -> String {
        self.key_for(Shell::Zsh)
    }

    /// The [`Fingerprints`] key `shell`'s cache entry lives under.
    #[must_use]
    pub fn key_for(&self, shell: Shell) -> String {
        match shell {
            Shell::Zsh => format!("{KEY_PREFIX}{}", self.name),
            Shell::Bash => format!("{BASH_KEY_PREFIX}{}", self.name),
        }
    }

    /// The command `shell` runs, or `None` when the activation is kept out
    /// of `shell` or declares no command for it. See the module's
    /// *One command per shell*.
    #[must_use]
    pub fn command_for(&self, shell: Shell) -> Option<Vec<String>> {
        if !self.shells.includes(shell) {
            return None;
        }
        let own = match shell {
            Shell::Zsh => self.zsh.as_ref(),
            Shell::Bash => self.bash.as_ref(),
        };
        if let Some(own) = own {
            return Some(spelled(own, shell));
        }
        if self.command.is_empty() {
            return None;
        }
        let names_shell = self.command.iter().any(|w| w.contains(SHELL_PLACEHOLDER));
        (names_shell || shell == Shell::Zsh).then(|| spelled(&self.command, shell))
    }
}

/// `command` with every `{shell}` spelled as `shell`'s name.
fn spelled(command: &[String], shell: Shell) -> Vec<String> {
    command
        .iter()
        .map(|word| word.replace(SHELL_PLACEHOLDER, shell.name()))
        .collect()
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

    /// The `PATH` every [`Host::run`] gives the tool, which its output's
    /// copies of are replaced with a reference to the shell's own `$PATH`.
    fn path(&self) -> &OsStr;
}

/// The machine bx is running on, searched along one `PATH`, with the facts
/// a `when` condition on it is decided against.
#[derive(Debug, Clone)]
pub struct System {
    /// The search path `command[0]` is looked up along.
    path: OsString,
    /// How long one run may take.
    timeout: Duration,
    /// The facts `os:`, `arch:`, `host:`, `user:` and `distro:` are decided
    /// against: none known until [`System::with_machine`] supplies them.
    machine: Machine,
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
            machine: Machine::default(),
        }
    }

    /// The same machine, its facts being `machine`: what
    /// `plan::Inputs::load` reads once, and a test supplies its own.
    #[must_use]
    pub fn with_machine(mut self, machine: Machine) -> Self {
        self.machine = machine;
        self
    }

    /// The facts a `when` condition on this machine is decided against.
    #[must_use]
    pub const fn machine(&self) -> &Machine {
        &self.machine
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
            .env("PATH", &self.path)
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

    fn path(&self) -> &OsStr {
        &self.path
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

/// One activation's command for one shell, decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The declaration.
    pub decl: ActivationDecl,
    /// The shell whose command this is.
    pub shell: Shell,
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
        // zsh's steps read as they did before bash had any.
        let shell = match self.shell {
            Shell::Zsh => String::new(),
            Shell::Bash => " for bash".to_string(),
        };
        format!(
            "{} activation `{}`{shell}: {what}",
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
                Some(format!("{comment}eval {}\n", quote(output)))
            }
            Outcome::Omitted(_) => None,
        }
    }
}

/// Every enabled activation, decided in declaration order, one step per shell
/// it has a command for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// One step per enabled activation and shell it has a command for.
    steps: Vec<Step>,
}

impl Plan {
    /// The steps, in declaration order, each activation's zsh step before its
    /// bash one.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// `shell`'s text for every step that renders anything, in declaration
    /// order: what that shell's interactive file carries.
    #[must_use]
    pub fn rendered(&self, shell: Shell) -> Vec<Activated> {
        self.steps
            .iter()
            .filter(|step| step.shell == shell)
            .filter_map(|step| {
                step.body().map(|body| Activated {
                    phase: step.decl.phase,
                    name: step.decl.name.clone(),
                    body,
                })
            })
            .collect()
    }

    /// Bring `cache` up to date with the plan: record every capture, and
    /// forget every activation entry nothing reused or captured — an omitted
    /// one, a refused one, and one no enabled declaration names any more — so an omission is retried from nothing. Entries this module
    /// does not own are left alone.
    pub fn record(&self, cache: &mut Fingerprints) {
        let mut kept = Vec::new();
        for step in &self.steps {
            let key = step.decl.key_for(step.shell);
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
            .filter(|key| {
                (key.starts_with(KEY_PREFIX) || key.starts_with(BASH_KEY_PREFIX))
                    && !kept.contains(key)
            })
            .cloned()
            .collect();
        for key in stale {
            cache.remove(&key);
        }
    }
}

/// Add each of `activated` to its phase, in order.
///
/// # Errors
///
/// Whatever [`Assembly::contribute`] refuses. An activation lands only in
/// `activations` or `completions`, neither of which refuses anything.
pub fn contribute(assembly: &mut Assembly, activated: &[Activated]) -> Result<(), super::Error> {
    for activation in activated {
        assembly.contribute(
            activation.phase,
            activation.name.clone(),
            activation.body.clone(),
        )?;
    }
    Ok(())
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
    // v2: an entry's output holds `$PATH` where the tool printed the `PATH` it
    // ran with; a v1 entry held that value frozen, and is never reused.
    let mut bytes = b"bx.activation.v2\0".to_vec();
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
        .flat_map(|decl| {
            Shell::ALL.into_iter().filter_map(move |shell| {
                let command = decl.command_for(shell)?;
                let outcome = decide(&decl.key_for(shell), &command, cache, host);
                let refused = match &outcome {
                    Outcome::Reused { output } | Outcome::Captured { output, .. } => {
                        judged(output, roots)
                    }
                    Outcome::Omitted(_) => None,
                };
                Some(Step {
                    decl: decl.clone(),
                    shell,
                    outcome: refused.map_or(outcome, Outcome::Omitted),
                })
            })
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

/// Decide one shell's `command` of an activation, cached under `key`, before
/// the guard judges its output.
fn decide(key: &str, command: &[String], cache: &Fingerprints, host: &impl Host) -> Outcome {
    let program = &command[0];
    let binary = match host.locate(program) {
        Presence::Present { path } => path,
        Presence::NotExecutable { path } => {
            return Outcome::Omitted(Omission::NotExecutable { path });
        }
        Presence::Missing => {
            return Outcome::Omitted(Omission::Absent {
                program: program.clone(),
            });
        }
    };
    let content = match host.hash(&binary) {
        Ok(content) => content,
        Err(reason) => return Outcome::Omitted(Omission::Unreadable { reason }),
    };
    let inputs = inputs(&content, &binary, command);

    let previous = cache.get(key);
    if let Some(entry) = previous.and_then(Entry::decode)
        && entry.inputs == inputs
    {
        return Outcome::Reused {
            output: entry.output,
        };
    }

    let args = &command[1..];
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
    // Before it is cached, and so before the guard judges it, reused or not.
    let output = live_path(&output, host.path());
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

/// How the text being copied is quoted, innermost last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quoting {
    /// Top level: unquoted.
    Plain,
    /// Unquoted inside `$(…)`, holding this many unclosed `(`.
    Substitution(usize),
    /// Unquoted inside `` `…` ``.
    Backtick,
    /// Inside `"…"`.
    Double,
    /// Inside `'…'`.
    Single,
    /// Inside `$'…'`.
    AnsiC,
}

/// Whether `c` may stand beside a `PATH` value that is a whole value or list
/// entry: nothing, a blank, a list separator, a quote or an operator. Any
/// other character makes it part of a longer path.
fn is_edge(c: Option<char>) -> bool {
    c.is_none_or(|c| c.is_whitespace() || ":'\"=;&|(){}`<>".contains(c))
}

/// `output` with every occurrence of the value `path`, standing as a whole
/// value or list entry, replaced by a reference to the shell's own `$PATH`
/// quoted for the context it stands in. An empty or non-UTF-8 `path` is
/// never found. See the module documentation.
fn live_path(output: &str, path: &OsStr) -> String {
    let Some(path) = path.to_str().filter(|path| !path.is_empty()) else {
        return output.to_string();
    };
    let mut out = String::with_capacity(output.len());
    let mut stack = vec![Quoting::Plain];
    let mut comment = false;
    // Where the single-quoted span being copied began in `out`, and whether
    // it is closed around a reference and not yet reopened.
    let mut opened = 0;
    let mut closed = false;
    let mut chars = output.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        let top = stack.last().copied().unwrap_or(Quoting::Plain);
        if output[at..].starts_with(path)
            && is_edge(output[..at].chars().next_back())
            && is_edge(output[at + path.len()..].chars().next())
        {
            match top {
                Quoting::Single => {
                    if !closed {
                        if out.len() == opened {
                            // Nothing quoted yet: drop the opening quote.
                            out.pop();
                        } else {
                            out.push('\'');
                        }
                    }
                    out.push_str("\"$PATH\"");
                    closed = true;
                }
                Quoting::AnsiC => out.push_str("'\"$PATH\"$'"),
                Quoting::Double => out.push_str("${PATH}"),
                _ => out.push_str("\"$PATH\""),
            }
            while chars.next_if(|&(next, _)| next < at + path.len()).is_some() {}
            continue;
        }
        if comment {
            comment = c != '\n';
            out.push(c);
            continue;
        }
        let next = chars.peek().map(|&(_, next)| next);
        match (top, c) {
            (Quoting::Single, '\'') => {
                stack.pop();
                if !closed {
                    out.push('\'');
                }
                closed = false;
            }
            (Quoting::Single, _) => {
                if closed {
                    out.push('\'');
                    closed = false;
                }
                out.push(c);
            }
            (_, '\\') if top != Quoting::Single => {
                out.push(c);
                if let Some((_, escaped)) = chars.next() {
                    out.push(escaped);
                }
            }
            (Quoting::AnsiC, '\'') | (Quoting::Double, '"') | (Quoting::Backtick, '`') => {
                stack.pop();
                out.push(c);
            }
            (Quoting::AnsiC, _) => out.push(c),
            (_, '$') if next == Some('(') => {
                stack.push(Quoting::Substitution(0));
                out.push(c);
                out.extend(chars.next().map(|(_, open)| open));
            }
            (_, '`') => {
                stack.push(Quoting::Backtick);
                out.push(c);
            }
            (Quoting::Double, _) => out.push(c),
            (_, '$') if next == Some('\'') => {
                stack.push(Quoting::AnsiC);
                out.push(c);
                out.extend(chars.next().map(|(_, open)| open));
            }
            (_, '\'') => {
                stack.push(Quoting::Single);
                out.push(c);
                opened = out.len();
            }
            (_, '"') => {
                stack.push(Quoting::Double);
                out.push(c);
            }
            // A comment begins only where a word would.
            (_, '#')
                if output[..at]
                    .chars()
                    .next_back()
                    .is_none_or(|before| before.is_whitespace() || ";&|()`".contains(before)) =>
            {
                comment = true;
                out.push(c);
            }
            (Quoting::Substitution(depth), '(') => {
                stack.pop();
                stack.push(Quoting::Substitution(depth + 1));
                out.push(c);
            }
            (Quoting::Substitution(depth), ')') => {
                stack.pop();
                if depth > 0 {
                    stack.push(Quoting::Substitution(depth - 1));
                }
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
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
mod tests;
