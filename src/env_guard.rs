//! The one rule that keeps bx from breaking the tools it manages.
//!
//! bx *may* write an environment variable when that is a tool's own documented
//! configuration interface and the tool has no config file — `SCCACHE_CACHE_SIZE`
//! and `RUSTC_WRAPPER` are the motivating cases, since sccache is configured
//! entirely by environment.
//!
//! bx *may never* write a variable that moves a tool's config, data, or cache
//! **outside a root the configuration declares**. Doing so makes the tool
//! depend on bx having run: open a shell that bx did not initialise — a login
//! shell, a `systemd-run` unit, an SSH command, a container — and the tool
//! silently reads a different directory. Inside a declared root the user has
//! said where those directories live and has accepted that consequence, which
//! is why a machine that puts its toolchain caches on a scratch mount is a
//! configuration bx serves rather than one it refuses.
//!
//! bx *may never* point a tool at a directory **bx itself owns**, and that one
//! is unconditional: it holds inside a declared root too, because bx's state
//! directory holds the record that makes an uninstall exact, and a tool writing
//! among those files would make `bx rm` destructive. [`RootSet::owns`] is that
//! exclusion, and it is checked before containment.
//!
//! The rule is therefore about the **value** a variable is given, never about
//! the variable's name. [`is_relocating`] only decides whether a value has to be
//! looked at; [`check`] is the verdict, and [`RootSet`] is what it is judged
//! against. Declare no root — [`RootSet::strict`], which is what [`scan`] uses —
//! and nothing may be relocated anywhere.
//!
//! The guard **fails closed by shape**. It judges fragments bx generates, not
//! arbitrary shell, so it does not model shell syntax and approve whatever it
//! does not recognise: it reads a fragment against a small grammar — blank
//! lines, comments, and `NAME=VALUE` or `export NAME=VALUE` with a restricted
//! value — and refuses **every** line that is not one of those, whatever the
//! line mentions and whether or not it relocates anything. A multi-line
//! construct is refused at its first line, because no line the grammar accepts
//! can leave a quote, a continuation or a heredoc open. [`scan_with`] states the
//! grammar.
//!
//! This module is that rule as code. Anything bx generates for a shell is run
//! through [`scan_with`] before it is written, and the check is covered by tests
//! rather than left to review.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use crate::config::layers;
use crate::config::values::ResolvedValues;
use crate::paths;

/// Exact variable names whose assigned value must be checked against the
/// declared roots.
const DENIED_EXACT: &[&str] = &[
    // The home itself: `~` and every XDG default are resolved against it.
    "HOME",
    // XDG roots — relocating any of these moves every tool at once.
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    // Per-tool roots.
    "CARGO_HOME",
    "RUSTUP_HOME",
    "GNUPGHOME",
    "GOPATH",
    "GOMODCACHE",
    "GRADLE_USER_HOME",
    "PYENV_ROOT",
    "NVM_DIR",
    "BUN_INSTALL",
    "PNPM_HOME",
    "DENO_DIR",
    "DOTNET_CLI_HOME",
    "NUGET_PACKAGES",
    "GEM_HOME",
    "COMPOSER_HOME",
    "SSH_CONFIG",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GH_CONFIG_DIR",
    "DOCKER_CONFIG",
    "KUBECONFIG",
    // zsh reads every startup file after `.zshenv` from here.
    "ZDOTDIR",
    // Caches and configs the prefix and suffix rules below do not reach. Each
    // of these was observed relocating a real tool's directory while matching
    // no rule: the guard was letting them through silently.
    "GOCACHE",
    "NUGET_HTTP_CACHE_PATH",
    "HOMEBREW_CACHE",
    "HOMEBREW_LOGS",
    "HOMEBREW_TEMP",
    "YARN_CACHE_FOLDER",
    "STARSHIP_CONFIG",
    "PYTHONUSERBASE",
    "TMPDIR",
    // `_CACHE_DIR` requires the underscore, so neither `CCACHE_DIR` nor
    // `SCCACHE_DIR` (which ends in `CCACHE_DIR`) matched anything.
    "CCACHE_DIR",
    "SCCACHE_DIR",
];

/// Prefixes whose variables are, as a family, about where a tool's directories
/// live. Matched against the whole name, so `MISE_DATA_DIR` is value-checked
/// while `MISE_VERBOSE` is not.
///
/// A family holds far more behaviour variables than location variables, so a
/// name matched **only** by a prefix is not, by itself, evidence that it holds a
/// location. See [`names_a_location`].
const DENIED_PREFIXES: &[&str] = &["UV_", "MISE_", "ASDF_", "PIP_"];

/// Prefix families the tool itself reads without regard to case.
///
/// npm takes any environment variable matching `npm_config_*` in whatever case,
/// and its own documentation writes them lower-case: `npm_config_cache=/x`
/// moves npm's cache exactly as `NPM_CONFIG_CACHE=/x` does.
const CASELESS_PREFIXES: &[&str] = &["NPM_CONFIG_"];

/// Suffixes that mark a variable as naming a location.
const DENIED_SUFFIXES: &[&str] = &[
    "_HOME",
    "_CONFIG_DIR",
    "_DATA_DIR",
    "_CACHE_DIR",
    "_STATE_DIR",
    "_CONFIG_FILE",
    "_STORE_DIR",
];

/// The last word of a prefix-family name that says the variable holds a
/// location: `UV_TOOL_DIR`, `PIP_TARGET`, `NPM_CONFIG_CACHE`,
/// `UV_PROJECT_ENVIRONMENT`, `NPM_CONFIG_USERCONFIG`, `MISE_SHARED_INSTALL_DIRS`.
///
/// Each is taken from a location variable one of the families documents.
/// It is what keeps a bare relative value — `NPM_CONFIG_CACHE=.npm`,
/// `PIP_TARGET=build`, which move a tool's data to wherever the shell happens
/// to be — from passing as a behaviour setting.
const LOCATION_WORDS: &[&str] = &[
    "DIR",
    "DIRS",
    "PATH",
    "PATHS",
    "FILE",
    "FILENAME",
    "HOME",
    "ROOT",
    "PREFIX",
    "TARGET",
    "CACHE",
    "TMP",
    "SRC",
    "LOG",
    "PROJECT",
    "ENVIRONMENT",
    "USERCONFIG",
    "GLOBALCONFIG",
];

/// Names that match a rule above but carry no path at all: they configure
/// behaviour, so their value must not be checked against a root.
///
/// Only a name a *suffix* or a location word would otherwise mark is worth
/// listing. A prefix-family behaviour variable — `UV_NO_CACHE=1`,
/// `MISE_JOBS=8` — is recognised by its value and needs no entry here.
const ALLOWED_EXCEPTIONS: &[&str] = &[
    "UV_SYSTEM_PYTHON",
    "MISE_VERBOSE",
    "PIP_REQUIRE_VIRTUALENV",
    // pip's `--no-cache-dir` switch, which the `_CACHE_DIR` suffix catches.
    "PIP_NO_CACHE_DIR",
];

/// Names a shell defines and manages itself. A fragment may neither assign one
/// nor refer to one.
///
/// A value assigned to one of these does not read back as it was written:
/// `RANDOM`, `SECONDS` and `LINENO` are computed, `HISTSIZE` is an integer the
/// shell evaluates arithmetically, `UID` and `USERNAME` change who the process
/// is, and zsh's lower-case `path`, `fpath` and `manpath` are tied to the
/// upper-case lists, so assigning one rewrites another. A guard that learned
/// `RANDOM=<root>` and resolved `$RANDOM/cargo` inside the root would approve a
/// relative path.
///
/// The list is every parameter a pristine `bash --norc --noprofile` (5.3) and
/// `zsh -f` (5.9, with every bundled module loaded) define, plus the three
/// documented names — `FUNCNAME`, `ERRNO`, `ZLE_RPROMPT_INDENT` — whose assigned
/// value did not read back in one of them although neither defines it at
/// startup. A test re-derives the first part from whichever shells the machine
/// running it has.
///
/// `PATH` is deliberately absent. It reads back exactly as assigned in both
/// shells — zsh's tied `path` is what is reserved — and it is the one
/// shell-defined name a generated fragment plausibly extends. `HOME` is
/// present: `~` expands against it, so a fragment that assigned it would change
/// what every later `~` means.
const SHELL_NAMES: &[&str] = &[
    "ARGC",
    "BASH",
    "BASHOPTS",
    "BASHPID",
    "BASH_ALIASES",
    "BASH_ARGC",
    "BASH_ARGV",
    "BASH_ARGV0",
    "BASH_CMDS",
    "BASH_COMMAND",
    "BASH_EXECUTION_STRING",
    "BASH_LINENO",
    "BASH_LOADABLES_PATH",
    "BASH_MONOSECONDS",
    "BASH_SOURCE",
    "BASH_SUBSHELL",
    "BASH_VERSINFO",
    "BASH_VERSION",
    "CDPATH",
    "COLUMNS",
    "COMP_WORDBREAKS",
    "CPUTYPE",
    "DIRSTACK",
    "EGID",
    "EPOCHREALTIME",
    "EPOCHSECONDS",
    "ERRNO",
    "EUID",
    "FIGNORE",
    "FPATH",
    "FUNCNAME",
    "FUNCNEST",
    "GID",
    "GROUPS",
    "HISTCHARS",
    "HISTCMD",
    "HISTSIZE",
    "HOME",
    "HOST",
    "HOSTNAME",
    "HOSTTYPE",
    "IFS",
    "KEYBOARD_HACK",
    "KEYTIMEOUT",
    "LINENO",
    "LINES",
    "LISTMAX",
    "LOGCHECK",
    "LOGNAME",
    "MACHTYPE",
    "MAILCHECK",
    "MAILPATH",
    "MANPATH",
    "MODULE_PATH",
    "NULLCMD",
    "OLDPWD",
    "OPTARG",
    "OPTERR",
    "OPTIND",
    "OSTYPE",
    "PPID",
    "PROMPT",
    "PROMPT2",
    "PROMPT3",
    "PROMPT4",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "PSVAR",
    "PWD",
    "RANDOM",
    "READNULLCMD",
    "SAVEHIST",
    "SECONDS",
    "SHELL",
    "SHELLOPTS",
    "SHLVL",
    "SPROMPT",
    "SRANDOM",
    "TERM",
    "TIMEFMT",
    "TMPPREFIX",
    "TRY_BLOCK_ERROR",
    "TRY_BLOCK_INTERRUPT",
    "TTY",
    "TTYIDLE",
    "UID",
    "USERNAME",
    "VENDOR",
    "WATCH",
    "WATCHFMT",
    "WORDCHARS",
    "ZCURSES_COLORS",
    "ZCURSES_COLOR_PAIRS",
    "ZFTP_PREFS",
    "ZFTP_SESSION",
    "ZFTP_TMOUT",
    "ZFTP_VERBOSE",
    "ZLE_RPROMPT_INDENT",
    "ZSH_ARGZERO",
    "ZSH_EVAL_CONTEXT",
    "ZSH_EXECUTION_STRING",
    "ZSH_NAME",
    "ZSH_PATCHLEVEL",
    "ZSH_SUBSHELL",
    "ZSH_VERSION",
    "_",
    "aliases",
    "argv",
    "builtins",
    "cdpath",
    "commands",
    "dirstack",
    "dis_aliases",
    "dis_builtins",
    "dis_functions",
    "dis_functions_source",
    "dis_galiases",
    "dis_patchars",
    "dis_reswords",
    "dis_saliases",
    "epochtime",
    "errnos",
    "exarr",
    "exint",
    "exstr",
    "fignore",
    "fpath",
    "funcfiletrace",
    "funcsourcetrace",
    "funcstack",
    "functions",
    "functions_source",
    "functrace",
    "galiases",
    "histchars",
    "history",
    "historywords",
    "jobdirs",
    "jobstates",
    "jobtexts",
    "keymaps",
    "langinfo",
    "mailpath",
    "manpath",
    "mapfile",
    "module_path",
    "modules",
    "nameddirs",
    "options",
    "parameters",
    "patchars",
    "path",
    "pipestatus",
    "prompt",
    "psvar",
    "reswords",
    "saliases",
    "signals",
    "status",
    "sysparams",
    "termcap",
    "terminfo",
    "userdirs",
    "usergroups",
    "watch",
    "widgets",
    "zcurses_attrs",
    "zcurses_colors",
    "zcurses_keycodes",
    "zcurses_windows",
    "zle_bracketed_paste",
    "zsh_eval_context",
    "zsh_scheduled_events",
];

/// Whether assigning `name` requires its **value** to be checked against the
/// declared roots.
///
/// This used to be the verdict itself: a matching name was a denial. It is now
/// only the question. A matching name is one that names a location, so *where*
/// that location is decides whether bx may write it, and [`check`] is what
/// decides. The lists above are therefore no longer a deny-list.
///
/// Because a wider list now means more checking rather than more denial, the
/// list can afford to be wide — but it is still widened only by evidence. A
/// generic `_DIR` or `_PATH` suffix is deliberately absent: `_PATH` would
/// capture `LD_LIBRARY_PATH`, `MANPATH` and every other list of directories
/// that tools *search* rather than write to.
///
/// The check is case-sensitive, because environment variable names are and a
/// tool that reads `CARGO_HOME` does not read `cargo_home` — except for a family
/// its tool reads without regard to case, `npm_config_*`.
#[must_use]
pub fn is_relocating(name: &str) -> bool {
    if ALLOWED_EXCEPTIONS.contains(&name) {
        return false;
    }
    DENIED_EXACT.contains(&name) || has_location_suffix(name) || family_tail(name).is_some()
}

/// Whether `name` ends in one of [`DENIED_SUFFIXES`], with something before it.
fn has_location_suffix(name: &str) -> bool {
    DENIED_SUFFIXES
        .iter()
        .any(|s| name.ends_with(s) && name.len() > s.len())
}

/// What follows the family prefix `name` begins with, if it begins with one.
fn family_tail(name: &str) -> Option<&str> {
    let exact = DENIED_PREFIXES.iter().find_map(|p| name.strip_prefix(p));
    let caseless = || {
        CASELESS_PREFIXES.iter().find_map(|p| {
            name.get(..p.len())
                .filter(|head| head.eq_ignore_ascii_case(p))
                .map(|head| &name[head.len()..])
        })
    };
    exact.or_else(caseless).filter(|tail| !tail.is_empty())
}

/// Whether the variable's **name** says that it holds a location.
///
/// True of an exact name and of a suffix match, where the name is the evidence.
/// For a name matched only by a family prefix it is true when the name's last
/// word is a [`LOCATION_WORDS`] entry — unless the name is a `NO_` switch, which
/// turns a location off rather than naming one (`UV_NO_CACHE`).
///
/// A relocating variable whose name does *not* say so, given a value that is no
/// kind of path, is a behaviour setting: `MISE_JOBS=8`, `UV_PYTHON=3.12`.
fn names_a_location(name: &str) -> bool {
    if DENIED_EXACT.contains(&name) || has_location_suffix(name) {
        return true;
    }
    family_tail(name).is_some_and(|tail| {
        let tail = tail.to_ascii_uppercase();
        !tail.starts_with("NO_")
            && tail
                .rsplit('_')
                .next()
                .is_some_and(|last| LOCATION_WORDS.contains(&last))
    })
}

/// The roots a configuration declares as its own.
///
/// A relocation is judged against this set: a tool may be pointed at a
/// different directory exactly when that directory lies inside a root the user
/// declared. The set is a `Vec` in declaration order, not a `HashSet`, because
/// invariant 3 forbids any iteration order reaching generated output.
///
/// `home` is kept so that `~` and `$HOME` expand, and **not** as a permissive
/// root: relocating a tool inside `$HOME` is as invisible to a shell bx did not
/// initialise as relocating it anywhere else. A user who wants their home to be
/// a root declares a root whose value is `~`.
///
/// It also carries the directories **bx itself owns**, which are an exclusion
/// rather than a root: invariant 2's first sentence — never point a tool at a
/// bx-owned directory — is unconditional, so it holds even inside a declared
/// root and even when the declared root is the home. See [`RootSet::owns`].
///
/// Containment is decided **lexically**, never by touching the filesystem.
/// `canonicalize` would make the verdict depend on what exists and on what is
/// mounted, so the same `plan` would differ between two machines and between
/// two runs on one — which invariant 3 forbids. The price is that lexical `..`
/// normalisation is unsound across a symlink: `<root>/link/../x`, where `link`
/// points outside the root, is judged inside it, and so is a declared root that
/// is itself a symlink to `/`. That is accepted rather than fixed, because the
/// only fix is the one invariant 3 rules out.
///
/// Containment is also **one-directional**: a value inside a root is admitted,
/// and a value that *contains* a root — `~/.local/state`, the parent of bx's
/// own directory — is judged by where it points, not by what lies beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSet {
    home: Option<PathBuf>,
    roots: Vec<PathBuf>,
    inadmissible: Vec<PathBuf>,
    owned: Vec<PathBuf>,
}

impl RootSet {
    /// The set that declares nothing, and therefore permits no relocation.
    ///
    /// This is what [`scan`] uses, and it is why `scan` needs no home: with no
    /// root declared every relocating variable is a violation before its value
    /// is ever looked at, so there is nothing to expand `~` against.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            home: None,
            roots: Vec::new(),
            inadmissible: Vec::new(),
            owned: Vec::new(),
        }
    }

    /// A set of declared roots, resolved against `home`.
    ///
    /// Each root is `~`-expanded with [`paths::render`] and lexically
    /// normalised with [`paths::normalize`], so that a root and a value being
    /// compared have been through the same rules.
    ///
    /// A root that does not clear [`admissible_root`] is **not honoured**. It is
    /// kept, as declared, in [`RootSet::inadmissible`], logged at error level,
    /// and it changes the verdict: a set left with no admissible root refuses
    /// every relocation as [`Reason::InadmissibleRoot`], never as
    /// [`Reason::NoRootsDeclared`] — a user whose configuration visibly declares
    /// a root must not be told that none is declared.
    #[must_use]
    pub fn new(home: &Path, roots: &[PathBuf]) -> Self {
        let home = paths::normalize(home);
        let mut admitted = Vec::new();
        let mut inadmissible = Vec::new();
        for declared in roots {
            let root = paths::normalize(&paths::render(&declared.to_string_lossy(), &home));
            if admissible_root(declared, &root) {
                admitted.push(root);
            } else {
                inadmissible.push(declared.clone());
            }
        }
        let owned = vec![paths::normalize(&layers::state_dir(&home, None))];
        Self {
            home: Some(home),
            roots: admitted,
            inadmissible,
            owned,
        }
    }

    /// The roots a resolved configuration declares.
    ///
    /// Every value declared `is_root = true` and actually answered, in
    /// declaration order, resolved against the same home the values themselves
    /// were resolved against. A declaration nobody filled in contributes no
    /// root, and `is_root` is validated at load to imply `kind = "path"`, so
    /// there is nothing to filter here.
    ///
    /// The home travels inside the values rather than being read from the
    /// environment, which is what keeps the guard's verdict a pure function of
    /// the configuration (invariant 3).
    #[must_use]
    pub fn from_values(values: &ResolvedValues) -> Self {
        Self::new(values.home(), &values.roots())
    }

    /// The same set, additionally owning `dirs`.
    ///
    /// [`RootSet::new`] derives bx's state directory from the home, which is
    /// where it is unless `XDG_STATE_HOME` is set — and nothing on a pure
    /// resolution path may read the environment (invariant 3), so a caller that
    /// *has* read it passes the directory it found here. Adding, never
    /// replacing: the home-derived directory stays owned, because a fragment
    /// pointing at it is wrong on any machine where that override is absent.
    #[must_use]
    pub fn owning(mut self, dirs: &[PathBuf]) -> Self {
        self.owned
            .extend(dirs.iter().map(|dir| paths::normalize(dir)));
        self
    }

    /// Whether `path` is a directory bx owns, or lies inside one.
    ///
    /// bx's state directory holds the ledger, the fingerprints and the journal:
    /// the record that makes invariant 4 true. A tool pointed into it writes
    /// among those files, and `bx rm` would then restore a home by deleting a
    /// directory another tool believes is its own. So this is checked **before**
    /// containment and outranks it — a user may declare their home a root, and
    /// `XDG_STATE_HOME=~/.local/state/bx` is still refused.
    #[must_use]
    pub fn owns(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.owned.iter().any(|dir| normalised.starts_with(dir))
    }

    /// Whether `path` lies inside some declared root.
    ///
    /// The comparison is component-wise, so `/scratch/examplefoo` is **not**
    /// inside `/scratch/example`, and it is lexical, so `<root>/../etc` is not
    /// inside `<root>` either. A relative path keeps its leading `..` through
    /// normalisation and can therefore never be inside an absolute root.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.roots.iter().any(|root| normalised.starts_with(root))
    }

    /// Whether no admissible root is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The declared roots that were refused, exactly as they were declared.
    ///
    /// A caller reporting a configuration prints these: they are the mistake a
    /// [`Reason::InadmissibleRoot`] verdict is about.
    #[must_use]
    pub fn inadmissible(&self) -> &[PathBuf] {
        &self.inadmissible
    }

    /// The home `~` and `$HOME` expand against, if this set has one.
    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// Why this set permits no relocation, if it permits none.
    fn refuses_everything(&self) -> Option<Reason> {
        match (self.roots.is_empty(), self.inadmissible.is_empty()) {
            (false, _) => None,
            (true, true) => Some(Reason::NoRootsDeclared),
            (true, false) => Some(Reason::InadmissibleRoot),
        }
    }
}

/// Whether a declared root may widen the guard at all.
///
/// The floor under every root, whatever declared it. A root must be an absolute
/// path that names at least one directory, and must not climb.
///
/// The case this exists for is a root that normalises to `/`. Written as `/`,
/// as `/..`, or as `~/../../..`, it makes `starts_with` true for every absolute
/// path, so every tool may be relocated anywhere and every fragment scans clean
/// — the guard turns itself off and says nothing. A guard may fail loudly; it
/// may not fail open in silence.
///
/// The configuration layer does **not** refuse such a value: a `path` value of
/// `/` is accepted there. This floor is therefore the only one, which is why a
/// refused root is logged at error level — the level `bx` reports with `BX_LOG`
/// unset — and changes the verdict rather than only narrowing the set.
///
/// `..` is rejected *before* normalisation as well, on the shape rather than
/// the result: a declared root that climbs is anomalous by construction, and
/// admitting one would mean admitting a root whose meaning changes across a
/// symlink.
fn admissible_root(declared: &Path, normalised: &Path) -> bool {
    let why = if declared
        .components()
        .any(|component| component == Component::ParentDir)
    {
        "it climbs out of itself"
    } else if !normalised.is_absolute() {
        "it is not an absolute path"
    } else if !normalised
        .components()
        .any(|component| matches!(component, Component::Normal(_)))
    {
        "it is the filesystem root itself"
    } else {
        return true;
    };
    tracing::error!(
        root = %declared.display(),
        "refusing a declared root, so nothing may be relocated into it: {why}"
    );
    false
}

/// Why a relocating assignment was rejected.
///
/// Each names a different user action — declare a root, fix the declared root,
/// split the line, write the line in the grammar the guard reads, use a name
/// the shell does not manage, move the value out of bx's own directory, move it
/// inside a declared root, give a location variable a path, write an absolute
/// path, define the referenced variable earlier, fix the line that assigned it,
/// shorten it — so a caller that only knew *which* variable was rejected could
/// not say what to do about it. The messages name no data: the caller already
/// holds the value and the root set, and prints them itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    /// Nothing was declared, so nothing may be relocated.
    #[error("no root is declared, so nothing may be relocated")]
    NoRootsDeclared,
    /// Roots were declared, and every one of them was refused.
    #[error(
        "every declared root was refused — the filesystem root, a relative path, \
         or one that climbs — so nothing may be relocated"
    )]
    InadmissibleRoot,
    /// The line assigns more than one variable.
    #[error("puts more than one assignment on one line")]
    MultipleAssignments,
    /// A line, or a value, that is not in the grammar [`scan_with`] reads —
    /// any keyword but `export`, any quoting or escaping but one plain quoted
    /// string, a substitution other than `$NAME` and `${NAME}`, a special
    /// parameter, an operator, an unclosed quote, a control character.
    #[error("is shell the guard cannot read, so it is not approved")]
    Unreadable,
    /// It assigns, or refers to, a name the shell manages itself — `HOME`,
    /// `RANDOM`, zsh's tied `path` — whose value would not read back as
    /// written.
    #[error("assigns or refers to a name the shell manages itself")]
    ReservedName,
    /// It points at a directory bx owns, whatever the roots say.
    #[error("points inside a directory bx owns")]
    BxOwnedDirectory,
    /// It resolves to a path, but not one inside any declared root.
    #[error("resolves outside every declared root")]
    OutsideDeclaredRoots,
    /// Not a path at all, for a variable whose name says it holds one.
    #[error("is not a path, though the variable's name says it holds a location")]
    NotAPath,
    /// Empty, or relative — it is shaped like a path, but not one that can be
    /// shown to be inside a root. For a list, one of its entries is.
    #[error("is not an absolute path")]
    NotAbsolute,
    /// It names a variable this fragment has not assigned by this line.
    #[error("refers to a variable this fragment has not assigned")]
    UnresolvedReference,
    /// It names a variable whose assignment the guard could not read, or comes
    /// after a line the guard refused, after which nothing assigned is known.
    #[error("refers to a variable whose assignment the guard could not read")]
    UnreadableReference,
    /// Its expansion grows past [`MAX_EXPANDED_LEN`].
    #[error("expands past the guard's length bound")]
    ExpansionTooLong,
}

/// What [`check`] decided about one assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// bx may write this assignment.
    Allowed,
    /// bx may not, for this reason.
    Violation(Violation),
}

/// A forbidden assignment found in generated shell content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// 1-based line number within the scanned content.
    ///
    /// A violation returned by [`check`], which judges one assignment outside
    /// any content, carries `0`: there is no line to point at.
    pub line: usize,
    /// The variable being assigned.
    ///
    /// Empty for a line refused as [`Reason::Unreadable`] before any one
    /// variable could be picked out of it.
    pub name: String,
    /// Everything written after `NAME=`, trailing comment included, so a
    /// diagnostic can quote it back exactly as the user will see it.
    ///
    /// For a line refused before any one variable could be picked out of it,
    /// the line itself, without its indentation.
    pub value: String,
    /// Why the assignment was rejected.
    pub reason: Reason,
}

/// Whether bx may assign `value` to `name`, given the roots `roots` declares.
///
/// `value` is everything written after `NAME=`, and is read by the same value
/// grammar [`scan_with`] reads a line with — so a value that is not exactly one
/// value in that grammar, optionally followed by a comment, is refused for
/// every variable, and a `name` that is not a variable name is refused too.
/// Past that, a variable that does not relocate anything is allowed without
/// its value being judged against a root, so `EDITOR=nvim` and
/// `SCCACHE_CACHE_SIZE=100G` can never trip a path rule. A relocating variable
/// is allowed exactly when every `:`-separated entry of its value resolves to a
/// path inside a declared root.
///
/// This is the same function [`scan_with`] calls for every assignment it reads,
/// so the two cannot disagree about one. No reference resolves here except
/// `$HOME` and `~`: `check` judges one assignment in isolation and has no
/// fragment to learn from.
#[must_use]
pub fn check(name: &str, value: &str, roots: &RootSet) -> Verdict {
    match evaluate(name, value, &Scope::default(), roots).reason {
        None => Verdict::Allowed,
        Some(reason) => Verdict::Violation(Violation {
            line: 0,
            name: name.to_string(),
            value: value.to_string(),
            reason,
        }),
    }
}

/// Find every forbidden assignment in a block of shell bx is about to write,
/// judged against the roots `roots` declares. A fragment is approved exactly
/// when this returns nothing.
///
/// **The grammar.** The content is split at `\n`, and every line must be one
/// of:
///
/// * **blank** — spaces and tabs only;
/// * **a comment** — optional blanks, `#`, then anything without a control
///   character;
/// * **an assignment** — optional blanks, optionally `export` and blanks, then
///   `NAME=VALUE`, optionally followed by blanks and a `#` comment. `NAME` is
///   `[A-Za-z_][A-Za-z0-9_]*`. `VALUE` is exactly one of:
///   * nothing;
///   * `'…'`, one single-quoted string of printable ASCII, taken literally;
///   * `"…"`, one double-quoted string of printable ASCII other than `\`,
///     `` ` `` and `!`, in which `$` may only begin a reference;
///   * a bare word of `A-Z a-z 0-9 _ . / , : @ % + -` and references, which
///     may begin with `~` alone or `~/`.
///
///   A reference is `${NAME}`, or `$NAME` followed by `/` or by the end of the
///   value's text. zsh reads on past an unbraced name — `$NAME:h` is a
///   modifier and `$NAME[1]` a subscript — so nothing else may follow one.
///
/// **Everything else is refused**, as [`Reason::Unreadable`] or
/// [`Reason::MultipleAssignments`], whatever it mentions and whether or not it
/// relocates anything. That includes every keyword but `export` (`declare`,
/// `typeset`, `local`, `readonly`, `unset`, `set`, `alias`, `eval`, `source`,
/// `.`, `for`, `read`, `printf`), `export` itself quoted or escaped, `export`
/// with no value, a backslash, a quote that does not close on its line, mixed
/// quoting, command, arithmetic and brace substitution, a `${NAME…}` operator,
/// a special parameter (`$@ $* $# $? $! $$ $- $0`…), a glob, `;`, `&&`, `|`, a
/// redirection or heredoc, `+=`, an array or subscript, a `=` or `~` anywhere
/// but where listed (so zsh's `=cmd` and a `~` after `:` never occur), and any
/// control character. Because no accepted line can leave a quote, a
/// continuation or a heredoc open, every accepted line begins where a shell
/// begins a statement, and a multi-line construct is refused at its first line.
///
/// A name the shell manages itself — `HOME`, `RANDOM`, `LINENO`, zsh's `path`
/// and the rest of `SHELL_NAMES` — may be neither assigned nor referred to, and
/// is refused as [`Reason::ReservedName`]. `PATH` may.
///
/// **What is learned.** One forward pass. Every accepted assignment — exported
/// or not — is recorded, **expanded**, so a later line may refer to it: the
/// generated `.zshenv` is written in terms of a declared root variable, and a
/// guard that could not resolve `$SCRATCH_HOME` would either reject every
/// fragment bx generates or check nothing at all. A reference to a variable
/// assigned *later* is unresolved, because a shell would not have it either.
/// `~` and `$HOME` resolve against the root set's home, which a fragment cannot
/// change because it cannot assign `HOME`. After a refused line nothing is
/// known — such a line could have assigned or unset anything — so every later
/// reference is [`Reason::UnreadableReference`].
///
/// **Lists.** A relocating value is split at `:`, and every entry must be an
/// absolute path inside a root and outside bx's own directories: a
/// `KUBECONFIG` or a `GOPATH` is a list, and a single path with a `:` in it is
/// judged no less strictly for being split.
///
/// **Purity.** Nothing is read from the process environment and nothing is
/// read from disk. `$HOME` comes from `roots`, never from [`std::env`], and the
/// roots are held in declaration order, so this is a pure function of
/// `(content, roots)`. That is what lets `plan` call it without becoming
/// machine-dependent (invariant 3).
///
/// **What is out of scope.** The shell the fragment is sourced into: an alias,
/// a function or an option the user's own startup files set before bx's
/// fragment runs is the user's configuration, not bx's output. The grammar is
/// checked against bash and zsh.
#[must_use]
pub fn scan_with(content: &str, roots: &RootSet) -> Vec<Violation> {
    pass(content, roots).0
}

/// Find every forbidden assignment in a block of shell bx is about to write.
///
/// Equivalent to [`scan_with`] against [`RootSet::strict`]: with no root
/// declared, every relocating variable is a violation. This is the check for a
/// caller that has no configuration to consult, and it is why it needs no home.
#[must_use]
pub fn scan(content: &str) -> Vec<Violation> {
    scan_with(content, &RootSet::strict())
}

/// [`scan_with`]'s one pass: the violations, and what the fragment was learned
/// to assign.
fn pass(content: &str, roots: &RootSet) -> (Vec<Violation>, Scope) {
    let mut found = Vec::new();
    let mut scope = Scope::default();
    for (idx, line) in content.split('\n').enumerate() {
        let violation = |name: &str, value: &str, reason| Violation {
            line: idx + 1,
            name: name.to_string(),
            value: value.to_string(),
            reason,
        };
        match statement(line) {
            Statement::Nothing => {}
            Statement::Refused => {
                found.push(violation("", line.trim_matches(BLANKS), Reason::Unreadable));
                scope.forget_everything();
            }
            Statement::Assign { name, value } => {
                let judged = evaluate(name, value, &scope, roots);
                if let Some(reason) = judged.reason {
                    found.push(violation(name, value, reason));
                }
                scope.learn(name, judged);
            }
        }
    }
    (found, scope)
}

/// What [`evaluate`] found: the verdict, and what the value expands to.
struct Judged {
    /// Why the assignment may not be written, or `None` if it may.
    reason: Option<Reason>,
    /// The value a shell would give the name, or why it cannot be known. This
    /// is what a later reference to the name resolves to.
    resolved: Result<String, Reason>,
}

/// The verdict on `name = value`, for [`check`] and [`scan_with`] alike.
fn evaluate(name: &str, value: &str, scope: &Scope, roots: &RootSet) -> Judged {
    let refused = |reason| Judged {
        reason: Some(reason),
        resolved: Err(reason),
    };
    // The shape is read for every variable, relocating or not: a line the
    // grammar does not read may do anything, whatever its first name is.
    if !is_variable_name(name) {
        return refused(Reason::Unreadable);
    }
    let word = match read_value(value) {
        Ok(word) => word,
        Err(reason) => return refused(reason),
    };
    if SHELL_NAMES.contains(&name) {
        return refused(Reason::ReservedName);
    }
    let resolved = word.resolve(scope, roots.home());
    let judged = |reason| Judged {
        reason,
        resolved: resolved.clone(),
    };

    if !is_relocating(name) {
        return judged(None);
    }
    // An empty value is a degenerate path, not a non-path: `CARGO_HOME=` does
    // relocate the tool, to nowhere.
    let not_a_path = !word.text.is_empty() && !path_shaped(word.text);
    // A value that is no kind of path, for a variable whose name does not say
    // it holds a location, is a behaviour setting: it relocates nothing, so it
    // needs no root — `MISE_JOBS=8` is allowed with none declared.
    if not_a_path && !names_a_location(name) {
        return judged(None);
    }
    // A set with no admissible root permits no relocation, and is the only set
    // without a home — so past this point there is always a home.
    if let Some(reason) = roots.refuses_everything() {
        return judged(Some(reason));
    }
    if not_a_path {
        return judged(Some(Reason::NotAPath));
    }
    let reason = match &resolved {
        Ok(resolved) => resolved
            .split(':')
            .find_map(|entry| refuses_entry(Path::new(entry), roots)),
        Err(reason) => Some(*reason),
    };
    judged(reason)
}

/// Why one resolved path — a value, or one entry of a list — may not be a
/// relocation target, or `None` if it may.
fn refuses_entry(path: &Path, roots: &RootSet) -> Option<Reason> {
    if !path.is_absolute() {
        return Some(Reason::NotAbsolute);
    }
    // Before the root test, and therefore ahead of any declaration: a root the
    // user declared widens where tools may live, never who owns bx's own state.
    if roots.owns(path) {
        return Some(Reason::BxOwnedDirectory);
    }
    if roots.contains(path) {
        None
    } else {
        Some(Reason::OutsideDeclaredRoots)
    }
}

/// What one pass over a fragment has learned it assigns.
#[derive(Debug, Default)]
struct Scope {
    /// What each accepted assignment expanded to, or why the guard cannot know.
    learned: HashMap<String, Result<String, Reason>>,
    /// Whether a refused line has passed. After one nothing is known, because
    /// the guard did not read what it assigned or unset.
    lost: bool,
}

impl Scope {
    /// What a reference to `name` expands to.
    ///
    /// A name the fragment assigned wins, as it would in a shell. `HOME` comes
    /// from the root set, and is the only value not learned from the fragment —
    /// which is why a fragment may not assign it.
    fn lookup(&self, name: &str, home: Option<&Path>) -> Result<String, Reason> {
        if let Some(known) = self.learned.get(name) {
            return known.clone();
        }
        if self.lost {
            return Err(Reason::UnreadableReference);
        }
        if name == "HOME" {
            return home
                .map(|home| home.to_string_lossy().into_owned())
                .ok_or(Reason::UnresolvedReference);
        }
        Err(if SHELL_NAMES.contains(&name) {
            Reason::ReservedName
        } else {
            Reason::UnresolvedReference
        })
    }

    /// Learn what an assignment the pass has just judged gave its name.
    ///
    /// Only *after* judging it, as a shell does: the right-hand side sees the
    /// previous value of the name, not this one. A value the grammar refused
    /// is not a value any shell gives the name, and a line that assigns a
    /// name the shell manages may change another name with it, so either
    /// forgets everything.
    fn learn(&mut self, name: &str, judged: Judged) {
        match judged.reason {
            Some(Reason::Unreadable | Reason::MultipleAssignments | Reason::ReservedName) => {
                self.forget_everything();
            }
            _ => {
                self.learned
                    .insert(name.to_string(), judged.resolved.map_err(as_reference));
            }
        }
    }

    /// After a line the guard did not read, know nothing.
    fn forget_everything(&mut self) {
        self.learned.clear();
        self.lost = true;
    }
}

/// The reason a *reference* to a name reports, given why the name's own value
/// could not be known.
fn as_reference(reason: Reason) -> Reason {
    match reason {
        Reason::UnresolvedReference | Reason::ExpansionTooLong => reason,
        _ => Reason::UnreadableReference,
    }
}

/// How long an expansion may grow before it is refused.
///
/// The expander's bound on work. Values are learned expanded, so a line that
/// doubles a variable — `X=$X$X` — doubles what is stored, and a fragment of a
/// few dozen such lines would otherwise hold gigabytes.
const MAX_EXPANDED_LEN: usize = 4096;

/// Whether `value` is shaped like a path at all.
///
/// Shaped like a path means: absolute, `~`-relative, containing a `$` that may
/// name one, or containing a `/` without a `://` — a URL has slashes and is
/// still not a path. Everything else is a number, a flag or a word, which for a
/// variable whose name does not say it holds a location is a behaviour setting.
fn path_shaped(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('~')
        || value.contains('$')
        || (value.contains('/') && !value.contains("://"))
}

/// The blanks that may indent a line and separate a value from its comment.
const BLANKS: [char; 2] = [' ', '\t'];

/// What one line of a fragment is, to the grammar.
#[derive(Debug, PartialEq, Eq)]
enum Statement<'a> {
    /// A blank line or a comment.
    Nothing,
    /// `NAME=VALUE` or `export NAME=VALUE`: `value` is everything after the
    /// `=`, still to be read by the value grammar.
    Assign { name: &'a str, value: &'a str },
    /// Not a statement the grammar reads.
    Refused,
}

/// Read one line of a fragment against the statement grammar.
fn statement(line: &str) -> Statement<'_> {
    let text = line.trim_matches(BLANKS);
    if text.is_empty() {
        return Statement::Nothing;
    }
    if text.starts_with('#') {
        return if text.chars().any(is_unprintable) {
            Statement::Refused
        } else {
            Statement::Nothing
        };
    }
    let assignment = match text.strip_prefix("export") {
        Some(operand) if operand.starts_with(BLANKS) => operand.trim_start_matches(BLANKS),
        _ => text,
    };
    match assignment.split_once('=') {
        Some((name, value)) if is_variable_name(name) => Statement::Assign { name, value },
        _ => Statement::Refused,
    }
}

/// A character no line of a fragment may hold: a control character other
/// than a tab.
fn is_unprintable(c: char) -> bool {
    c.is_control() && c != '\t'
}

/// A character of printable ASCII, space included.
fn is_printable(c: char) -> bool {
    (' '..='~').contains(&c)
}

/// One piece of a value: text as written, or a reference to expand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part<'a> {
    Text(&'a str),
    Reference(&'a str),
}

/// A value, read by the value grammar.
#[derive(Debug, PartialEq, Eq)]
struct Word<'a> {
    /// The value without its quotes, references not expanded: what
    /// [`path_shaped`] looks at.
    text: &'a str,
    /// Whether the value begins with the unquoted `~` a shell expands.
    tilde: bool,
    /// The text, split into literal text and references, in order.
    parts: Vec<Part<'a>>,
}

impl Word<'_> {
    /// What a shell gives the name this value is assigned to.
    fn resolve(&self, scope: &Scope, home: Option<&Path>) -> Result<String, Reason> {
        let mut out = if self.tilde {
            scope.lookup("HOME", home)?
        } else {
            String::new()
        };
        for part in &self.parts {
            match part {
                Part::Text(text) => out.push_str(text),
                Part::Reference(name) => out.push_str(&scope.lookup(name, home)?),
            }
            if out.len() > MAX_EXPANDED_LEN {
                return Err(Reason::ExpansionTooLong);
            }
        }
        Ok(out)
    }
}

/// Read everything written after `NAME=` as one value, optionally followed by
/// blanks and a comment.
fn read_value(value: &str) -> Result<Word<'_>, Reason> {
    if value.chars().any(is_unprintable) {
        return Err(Reason::Unreadable);
    }
    let (word, rest) = if let Some(inner) = value.strip_prefix('\'') {
        single_quoted(inner)?
    } else if let Some(inner) = value.strip_prefix('"') {
        double_quoted(inner)?
    } else {
        bare(value)?
    };
    after_value(rest)?;
    Ok(word)
}

/// A single-quoted value whose content starts `inner`, and what follows it.
fn single_quoted(inner: &str) -> Result<(Word<'_>, &str), Reason> {
    let end = inner.find('\'').ok_or(Reason::Unreadable)?;
    let text = &inner[..end];
    if !text.chars().all(is_printable) {
        return Err(Reason::Unreadable);
    }
    let word = Word {
        text,
        tilde: false,
        parts: vec![Part::Text(text)],
    };
    Ok((word, &inner[end + 1..]))
}

/// A double-quoted value whose content starts `inner`, and what follows it.
fn double_quoted(inner: &str) -> Result<(Word<'_>, &str), Reason> {
    let end = inner.find('"').ok_or(Reason::Unreadable)?;
    let text = &inner[..end];
    let parts = parts(text, |c| is_printable(c) && !"\\`!".contains(c))?;
    let word = Word {
        text,
        tilde: false,
        parts,
    };
    Ok((word, &inner[end + 1..]))
}

/// An unquoted value, and what follows it.
fn bare(value: &str) -> Result<(Word<'_>, &str), Reason> {
    let (text, rest) = value.split_at(value.find(BLANKS).unwrap_or(value.len()));
    // A shell expands `~` at the start of a value, and zsh and bash expand it
    // after a `:` as well, so `~` is read only here and only as the home.
    let (tilde, body) = match text.strip_prefix('~') {
        None => (false, text),
        Some(body) if body.is_empty() || body.starts_with('/') => (true, body),
        Some(_) => return Err(Reason::Unreadable),
    };
    let parts = parts(body, |c| {
        c.is_ascii_alphanumeric() || "_./,:@%+-".contains(c)
    })?;
    let word = Word { text, tilde, parts };
    Ok((word, rest))
}

/// Split a value's text into literal text and references, refusing a
/// character `allowed` does not admit.
///
/// Every `$` begins a reference, so the text is split at each one: what
/// precedes the first is literal, and every later piece starts with a name.
fn parts(text: &str, allowed: impl Fn(char) -> bool) -> Result<Vec<Part<'_>>, Reason> {
    let mut pieces = text.split('$');
    let mut parts = vec![literal(pieces.next().unwrap_or_default(), &allowed)?];
    for piece in pieces {
        let (name, tail) = reference(piece)?;
        parts.push(Part::Reference(name));
        parts.push(literal(tail, &allowed)?);
    }
    Ok(parts)
}

/// Literal text of a value, if every character of it is `allowed`.
fn literal<'a>(text: &'a str, allowed: &impl Fn(char) -> bool) -> Result<Part<'a>, Reason> {
    if text.chars().all(allowed) {
        Ok(Part::Text(text))
    } else {
        Err(Reason::Unreadable)
    }
}

/// The name a reference whose text follows its `$` refers to, and the text
/// after it.
fn reference(piece: &str) -> Result<(&str, &str), Reason> {
    let (name, tail) = match piece.strip_prefix('{') {
        Some(braced) => braced.split_once('}').ok_or(Reason::Unreadable)?,
        None => {
            let end = piece
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(piece.len());
            let (name, tail) = piece.split_at(end);
            // zsh reads on past an unbraced name: `$X:h` takes a modifier and
            // `$X[1]` a subscript. Only a `/`, or the end, is a safe place to
            // stop.
            if !(tail.is_empty() || tail.starts_with('/')) {
                return Err(Reason::Unreadable);
            }
            (name, tail)
        }
    };
    if is_variable_name(name) {
        Ok((name, tail))
    } else {
        Err(Reason::Unreadable)
    }
}

/// What may follow a value on its line: nothing, or blanks and a comment.
fn after_value(rest: &str) -> Result<(), Reason> {
    if rest.is_empty() {
        return Ok(());
    }
    let after = rest.trim_start_matches(BLANKS);
    // Text straight after the value, with no blank between, is more of the
    // same shell word in a form the grammar does not read.
    if after.len() == rest.len() {
        return Err(Reason::Unreadable);
    }
    if after.is_empty() || after.starts_with('#') {
        return Ok(());
    }
    Err(match after.split_once('=') {
        Some((head, _)) if is_variable_name(head) => Reason::MultipleAssignments,
        _ => Reason::Unreadable,
    })
}

/// Whether `name` is a shell-legal variable name.
fn is_variable_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::guarded_home;

    // A deliberately neutral home and scratch root: nothing in this file may
    // name a real account or a real machine's layout (invariant 5).
    const HOME: &str = "/var/home/example";
    const ROOT: &str = "/var/mnt/scratch/example";

    fn rooted() -> RootSet {
        RootSet::new(Path::new(HOME), &[PathBuf::from(ROOT)])
    }

    #[test]
    fn a_declared_root_contains_itself() {
        assert!(rooted().contains(Path::new(ROOT)));
    }

    #[test]
    fn a_path_under_a_declared_root_is_inside() {
        assert!(rooted().contains(Path::new("/var/mnt/scratch/example/cache/cargo")));
    }

    #[test]
    fn a_sibling_whose_name_extends_the_root_is_outside() {
        // Containment is component-wise, not textual: `examplefoo` is a
        // different directory that merely shares a prefix of its name.
        assert!(!rooted().contains(Path::new("/var/mnt/scratch/examplefoo")));
        assert!(!rooted().contains(Path::new("/var/mnt/scratch/examplefoo/cargo")));
    }

    #[test]
    fn a_traversal_out_of_a_root_is_outside() {
        assert!(!rooted().contains(Path::new("/var/mnt/scratch/example/../etc")));
    }

    #[test]
    fn a_traversal_that_returns_inside_is_inside() {
        assert!(rooted().contains(Path::new("/var/mnt/scratch/example/a/../b")));
    }

    #[test]
    fn a_single_dot_component_is_ignored() {
        assert!(rooted().contains(Path::new("/var/mnt/scratch/example/./cache")));
    }

    #[test]
    fn traversal_cannot_escape_above_the_filesystem_root() {
        // `/..` is `/`, and `/` is not inside any declared root here.
        assert!(!rooted().contains(Path::new("/..")));
        assert!(!rooted().contains(Path::new("/../../..")));
    }

    #[test]
    fn a_root_that_normalises_to_the_filesystem_root_is_dropped() {
        // The one failure a guard may not have. `/` makes `starts_with` true
        // for every absolute path, so every tool could be relocated anywhere
        // and every fragment would still scan clean. The three spellings all
        // normalise to `/`; all three are refused, and the set admits nothing.
        for declared in ["/", "/..", "~/../../..", "/var/home/example/../../.."] {
            let roots = RootSet::new(Path::new(HOME), &[PathBuf::from(declared)]);
            assert!(roots.is_empty(), "{declared}");
            assert!(!roots.contains(Path::new("/etc")), "{declared}");
            assert_eq!(
                roots.inadmissible(),
                &[PathBuf::from(declared)],
                "{declared}"
            );
            assert_eq!(
                reason_of(&check("XDG_CONFIG_HOME", "/etc", &roots)),
                Some(Reason::InadmissibleRoot),
                "{declared}"
            );
        }
    }

    #[test]
    fn a_declared_root_that_climbs_is_dropped_even_where_it_lands_somewhere_real() {
        // This one normalises to `/var/mnt/scratch`, a perfectly real
        // directory, and is still refused: a declared root that climbs is
        // anomalous by construction, and lexical `..` folding is the thing the
        // module accepts as unsound across a symlink.
        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from("/var/mnt/scratch/example/..")],
        );
        assert!(roots.is_empty());
        assert!(!roots.contains(Path::new("/var/mnt/scratch/other")));
    }

    #[test]
    fn a_relative_root_is_dropped() {
        // `RootSet::new` is public and no configuration layer stands in front
        // of it. A relative root can contain no absolute value, so keeping one
        // would only make `is_empty` say a root was declared when nothing
        // usable was.
        let roots = RootSet::new(Path::new(HOME), &[PathBuf::from("cache/cargo")]);
        assert!(roots.is_empty());
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/cargo",
                &roots
            )),
            Some(Reason::InadmissibleRoot)
        );
    }

    #[test]
    fn an_inadmissible_root_does_not_take_the_roots_declared_beside_it_with_it() {
        // Dropping is per root: the admissible one still admits what it covers.
        let roots = RootSet::new(
            Path::new(HOME),
            &[
                PathBuf::from("/"),
                PathBuf::from(ROOT),
                PathBuf::from("~/.."),
            ],
        );
        assert!(!roots.is_empty());
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cache")));
        assert!(!roots.contains(Path::new("/etc")));
        assert!(!roots.contains(Path::new("/var/home")));
    }

    #[test]
    fn a_relative_path_is_never_inside_a_root() {
        assert!(!rooted().contains(Path::new("cache/cargo")));
        assert!(!rooted().contains(Path::new("../example/cache")));
    }

    #[test]
    fn a_second_root_covers_what_the_first_does_not() {
        // The root set is a set precisely so an sccache directory can live
        // outside the scratch root without the scratch root being widened.
        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(ROOT), PathBuf::from("/var/cache/sccache")],
        );
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cargo")));
        assert!(roots.contains(Path::new("/var/cache/sccache/x")));
        assert!(!roots.contains(Path::new("/var/cache/other")));
    }

    #[test]
    fn a_root_inside_another_root_admits_what_each_of_them_admits() {
        // Overlapping declarations are ordinary — a scratch mount and a
        // directory inside it — and `contains` is an `any`, so the narrower one
        // neither shadows nor narrows the wider.
        let inner = format!("{ROOT}/cache");
        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(ROOT), PathBuf::from(&inner)],
        );
        assert!(roots.contains(Path::new(&inner)));
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cache/cargo")));
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/other")));
        assert!(!roots.contains(Path::new("/var/mnt/scratch/elsewhere")));
        // Declared the other way round, the same set.
        let reversed = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(&inner), PathBuf::from(ROOT)],
        );
        assert!(reversed.contains(Path::new("/var/mnt/scratch/example/other")));
        assert!(!reversed.contains(Path::new("/var/mnt/scratch/elsewhere")));
    }

    #[test]
    fn a_root_written_with_a_tilde_expands_against_home() {
        let roots = RootSet::new(Path::new(HOME), &[PathBuf::from("~/scratch")]);
        assert!(roots.contains(Path::new("/var/home/example/scratch/cargo")));
        assert!(!roots.contains(Path::new("/var/home/example/other")));
    }

    #[test]
    fn a_root_set_is_built_from_the_values_the_configuration_declares() {
        use crate::config::Origin;
        use crate::config::values::{
            AssignedValue, ResolvedValues, ValueAssignment, ValueDecl, ValueKind,
        };

        let origin = Origin::unknown(Path::new("bx.toml"));
        let declare = |name: &str, is_root: bool| ValueDecl {
            name: name.into(),
            description: None,
            kind: ValueKind::Path,
            required: false,
            is_root,
            default: None,
            enabled: true,
            origin: origin.clone(),
        };
        let answer = |name: &str, text: &str| ValueAssignment {
            name: name.into(),
            value: AssignedValue::String(text.into()),
            origin: origin.clone(),
        };

        let values = ResolvedValues::resolve(
            vec![
                declare("scratch_root", true),
                declare("brew_prefix", false),
                declare("sccache_dir", true),
            ],
            &[
                answer("scratch_root", ROOT),
                answer("brew_prefix", "/home/linuxbrew/.linuxbrew"),
                answer("sccache_dir", "/var/cache/sccache"),
            ],
            Path::new(HOME),
        )
        .expect("the values resolve");

        let roots = RootSet::from_values(&values);
        assert_eq!(roots, RootSet::new(Path::new(HOME), &values.roots()));
        assert_eq!(roots.home(), Some(Path::new(HOME)));
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cache/cargo")));
        assert!(roots.contains(Path::new("/var/cache/sccache/objects")));
        // A `path` value that was not declared a root does not become one.
        assert!(!roots.contains(Path::new("/home/linuxbrew/.linuxbrew/lib")));
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cache/cargo", &roots),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/home/linuxbrew/.linuxbrew/x", &roots)),
            Some(Reason::OutsideDeclaredRoots)
        );
    }

    #[test]
    fn an_unanswered_root_declaration_widens_nothing() {
        use crate::config::Origin;
        use crate::config::values::{ResolvedValues, ValueDecl, ValueKind};

        // A declaration nobody filled in must not widen the guard on the
        // strength of an intention — so a configuration whose only root is
        // unanswered is the strict guard.
        let values = ResolvedValues::resolve(
            vec![ValueDecl {
                name: "scratch_root".into(),
                description: None,
                kind: ValueKind::Path,
                required: false,
                is_root: true,
                default: None,
                enabled: true,
                origin: Origin::unknown(Path::new("bx.toml")),
            }],
            &[],
            Path::new(HOME),
        )
        .expect("the values resolve");

        let roots = RootSet::from_values(&values);
        assert!(roots.is_empty());
        assert_eq!(
            reason_of(&check("CARGO_HOME", ROOT, &roots)),
            Some(Reason::NoRootsDeclared)
        );
    }

    #[test]
    fn a_root_set_that_declares_nothing_is_empty_and_has_no_home() {
        let strict = RootSet::strict();
        assert!(strict.is_empty());
        assert_eq!(strict.home(), None);
        assert!(!strict.contains(Path::new(ROOT)));

        let rooted = rooted();
        assert!(!rooted.is_empty());
        assert_eq!(rooted.home(), Some(Path::new(HOME)));
    }

    #[test]
    fn containment_never_touches_the_filesystem() {
        // Both the root and the path are under a directory that has just been
        // removed, so `canonicalize` would return `Err` for either of them.
        // A verdict that depended on the filesystem would be wrong here, and a
        // `plan` built on it would differ between machines — invariant 3.
        let gone = tempfile::tempdir().expect("tempdir");
        let base = gone.path().to_path_buf();
        drop(gone);
        assert!(!base.exists());

        let roots = RootSet::new(Path::new(HOME), std::slice::from_ref(&base));
        assert!(roots.contains(&base.join("cache/cargo")));
        assert!(!roots.contains(Path::new("/var/cache/elsewhere")));
    }

    // `check` — a relocating variable is judged by where its value points.

    fn reason_of(verdict: &Verdict) -> Option<Reason> {
        match verdict {
            Verdict::Allowed => None,
            Verdict::Violation(violation) => Some(violation.reason),
        }
    }

    #[test]
    fn a_variable_that_does_not_relocate_is_allowed_without_reading_its_value() {
        // None of these values is a path at all. A name-based guard never had
        // to care; a value-based one must not start.
        for (name, value) in [
            ("EDITOR", "nvim"),
            ("SCCACHE_CACHE_SIZE", "100G"),
            ("MISE_VERBOSE", "1"),
            ("RUSTC_WRAPPER", "/usr/bin/sccache"),
        ] {
            assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
            // And it is allowed even with nothing declared at all.
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
    }

    #[test]
    fn a_relocating_variable_inside_a_declared_root_is_allowed() {
        let verdict = check(
            "CARGO_HOME",
            "/var/mnt/scratch/example/cache/cargo",
            &rooted(),
        );
        assert_eq!(verdict, Verdict::Allowed);
        assert_eq!(reason_of(&verdict), None);
    }

    #[test]
    fn a_relocating_variable_outside_every_root_is_a_violation() {
        // The violation carries everything a diagnostic needs to say what to
        // do about it. `check` judges one assignment outside any content, so
        // there is no line to report.
        assert_eq!(
            check("CARGO_HOME", "/var/cache/elsewhere", &rooted()),
            Verdict::Violation(Violation {
                line: 0,
                name: "CARGO_HOME".into(),
                value: "/var/cache/elsewhere".into(),
                reason: Reason::OutsideDeclaredRoots,
            })
        );
    }

    #[test]
    fn the_declared_root_variable_itself_is_allowed() {
        // `SCRATCH_HOME` is caught by the `_HOME` suffix and was, under the
        // name-based guard, denied outright — a false positive on the one
        // variable the whole configuration is written in terms of.
        assert!(is_relocating("SCRATCH_HOME"));
        assert_eq!(check("SCRATCH_HOME", ROOT, &rooted()), Verdict::Allowed);
    }

    #[test]
    fn with_no_root_declared_every_relocating_variable_is_a_violation() {
        for (name, value) in [
            ("CARGO_HOME", "/var/mnt/scratch/example/cache/cargo"),
            ("XDG_CONFIG_HOME", "/anywhere"),
            ("MISE_DATA_DIR", "~/mise"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &RootSet::strict())),
                Some(Reason::NoRootsDeclared),
                "{name}"
            );
        }
    }

    #[test]
    fn a_root_set_with_a_home_but_no_roots_declares_nothing() {
        // Holding a home is not declaring a root: the strictness comes from the
        // root list being empty, not from the home being absent.
        let empty = RootSet::new(Path::new(HOME), &[]);
        assert_eq!(empty.home(), Some(Path::new(HOME)));
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x", &empty)),
            Some(Reason::NoRootsDeclared)
        );
    }

    #[test]
    fn an_empty_value_is_not_absolute() {
        // `export CARGO_HOME` with no value at all.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "", &rooted())),
            Some(Reason::NotAbsolute)
        );
    }

    #[test]
    fn a_value_that_is_no_kind_of_path_says_so_rather_than_asking_for_an_absolute_one() {
        // Every one of these has a name that says it holds a location and a
        // value that is no kind of path. Told that the value "is not an
        // absolute path", a user would reach for a directory without asking
        // whether the variable was meant to hold one.
        for (name, value) in [
            ("CARGO_HOME", "1"),
            ("SOMETOOL_CONFIG_DIR", "yes"),
            ("NPM_CONFIG_CACHE", "npm"),
            ("PIP_TARGET", "build"),
            ("UV_PROJECT_ENVIRONMENT", "venv"),
        ] {
            assert!(is_relocating(name), "{name}");
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(Reason::NotAPath),
                "{name}"
            );
        }
        // A prefix-family name that does not say so is a behaviour setting,
        // and so is pip's `--no-cache-dir` switch, which a suffix catches.
        for (name, value) in [
            ("PIP_TIMEOUT", "60"),
            ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
            ("UV_NO_CACHE", "1"),
            ("MISE_QUIET", "1"),
            ("PIP_NO_CACHE_DIR", "1"),
        ] {
            assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
        }
        // And the reason a user can act on is kept for values that really are
        // paths, where making it absolute is the right thing to do.
        for value in ["cache/cargo", "~other/cargo", "$HOME/../x"] {
            assert_ne!(
                reason_of(&check("PIP_CACHE_DIR", value, &rooted())),
                Some(Reason::NotAPath),
                "{value}"
            );
        }
    }

    #[test]
    fn a_relative_value_is_not_absolute() {
        for value in ["cache/cargo", "./cargo", "../example/cargo"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::NotAbsolute),
                "{value}"
            );
        }
    }

    #[test]
    fn another_users_home_is_refused() {
        // A shell expands `~other` to that account's home, which bx does not
        // resolve, so it cannot be shown to be inside any root. `~` is read
        // only alone or before `/`.
        for value in ["~other/cargo", "~+/cargo", "~-"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
    }

    #[test]
    fn a_home_relative_value_is_a_violation_when_home_is_not_a_declared_root() {
        // Holding the home for `~` expansion is not the same as declaring it a
        // root. A relocation into `$HOME` is as invisible to a shell bx did not
        // initialise as one anywhere else.
        for value in ["~/x", "$HOME/x", "${HOME}/x"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{value}"
            );
        }
        // Declaring home as a root is how a user opts in, and it then works.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(check("CARGO_HOME", "~/x", &home_rooted), Verdict::Allowed);
    }

    #[test]
    fn bxs_own_state_directory_is_refused_even_inside_a_declared_root() {
        // The configuration that makes this reachable is the supported one:
        // the user declared their home a root, so containment alone would
        // allow it. `~/.local/state/bx` is where the ledger, the fingerprints
        // and the journal live; a tool pointed there writes among the files
        // that make `bx rm` exact.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for value in [
            "/var/home/example/.local/state/bx",
            "/var/home/example/.local/state/bx/ledger",
            "~/.local/state/bx",
            "$HOME/.local/state/bx/journal",
        ] {
            assert_eq!(
                reason_of(&check("XDG_STATE_HOME", value, &home_rooted)),
                Some(Reason::BxOwnedDirectory),
                "{value}"
            );
        }
        // The parent, and a sibling whose name merely extends it, are not bx's.
        assert_eq!(
            check("XDG_STATE_HOME", "~/.local/state", &home_rooted),
            Verdict::Allowed
        );
        assert_eq!(
            check("XDG_STATE_HOME", "~/.local/state/bxtra", &home_rooted),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_state_directory_moved_by_the_environment_is_owned_when_it_is_declared() {
        // `RootSet::new` derives the state directory from the home, because a
        // resolution path may not read `XDG_STATE_HOME` itself. A caller that
        // did read it says so, and the derived one stays owned as well.
        let moved = PathBuf::from("/var/mnt/scratch/example/state/bx");
        let roots = rooted().owning(std::slice::from_ref(&moved));
        assert_eq!(
            reason_of(&check(
                "XDG_STATE_HOME",
                "/var/mnt/scratch/example/state/bx",
                &roots
            )),
            Some(Reason::BxOwnedDirectory)
        );
        // Inside the declared root, and still refused - the exclusion outranks
        // the root test rather than being overridden by it.
        assert!(roots.contains(&moved));
        // And the home-derived directory is owned too, though this set's own
        // root does not contain it.
        assert!(roots.owns(Path::new("/var/home/example/.local/state/bx")));
    }

    #[test]
    fn a_variable_that_does_not_relocate_may_still_name_bxs_directory() {
        // The exclusion is part of the relocation verdict, not a second rule
        // over every value: a tool told where bx's own state is has not been
        // moved there.
        assert_eq!(
            check(
                "EDITOR",
                "/var/home/example/.local/state/bx/editor",
                &rooted()
            ),
            Verdict::Allowed
        );
    }

    #[test]
    fn the_reasons_render_as_sentences() {
        // The messages name no data: a caller prints the value and the roots.
        assert_eq!(
            Reason::NoRootsDeclared.to_string(),
            "no root is declared, so nothing may be relocated"
        );
        assert_eq!(
            Reason::OutsideDeclaredRoots.to_string(),
            "resolves outside every declared root"
        );
        assert_eq!(
            Reason::BxOwnedDirectory.to_string(),
            "points inside a directory bx owns"
        );
        assert_eq!(
            Reason::NotAPath.to_string(),
            "is not a path, though the variable's name says it holds a location"
        );
        assert_eq!(Reason::NotAbsolute.to_string(), "is not an absolute path");
        assert_eq!(
            Reason::UnresolvedReference.to_string(),
            "refers to a variable this fragment has not assigned"
        );
        assert_eq!(
            Reason::InadmissibleRoot.to_string(),
            "every declared root was refused — the filesystem root, a relative \
             path, or one that climbs — so nothing may be relocated"
        );
        assert_eq!(
            Reason::MultipleAssignments.to_string(),
            "puts more than one assignment on one line"
        );
        assert_eq!(
            Reason::Unreadable.to_string(),
            "is shell the guard cannot read, so it is not approved"
        );
        assert_eq!(
            Reason::UnreadableReference.to_string(),
            "refers to a variable whose assignment the guard could not read"
        );
        assert_eq!(
            Reason::ExpansionTooLong.to_string(),
            "expands past the guard's length bound"
        );
    }

    // `scan_with` — the same rule over a whole fragment, with a learned
    // environment.

    #[test]
    fn scan_denies_every_relocation_and_nothing_else() {
        // What the strict guard actually returns, written out. Comparing
        // `scan` against `scan_with(_, &RootSet::strict())` is `scan`'s own
        // definition and cannot fail, so it shows nothing.
        //
        // This is not the name-based guard's output either: six widened names
        // are denied here that it allowed. What survives from it is the
        // direction — with no root declared, every relocating assignment is
        // refused and nothing else is touched.
        for (content, expected) in [
            ("export EDITOR=nvim\n", vec![]),
            ("export SCCACHE_CACHE_SIZE=100G\n", vec![]),
            ("# export CARGO_HOME=/x\n", vec![]),
            ("# source ~/.cargo/env\n", vec![]),
            ("export CARGO_HOME=$HOME/x\n", vec![(1, "CARGO_HOME")]),
            (
                "export GOPATH=/x\n# source ~/.cargo/env\n",
                vec![(1, "GOPATH")],
            ),
            // Widened: the name-based guard let this one through unchecked.
            ("export GOCACHE=/x\n", vec![(1, "GOCACHE")]),
            (
                "export XDG_CONFIG_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n",
                vec![(1, "XDG_CONFIG_HOME"), (3, "RUSTUP_HOME")],
            ),
        ] {
            let found = scan(content);
            assert_eq!(
                found
                    .iter()
                    .map(|violation| (violation.line, violation.name.as_str()))
                    .collect::<Vec<_>>(),
                expected,
                "{content}"
            );
            assert!(
                found
                    .iter()
                    .all(|violation| violation.reason == Reason::NoRootsDeclared),
                "{content}"
            );
        }
    }

    #[test]
    fn a_second_assignment_on_one_line_is_refused_rather_than_half_judged() {
        // A real shell exports both names. Judging the head alone allowed the
        // tail unread: this line is clean to a guard that stops at the first
        // value, and `GOPATH` lands outside every root. The name-based guard
        // this replaced denied the line, so allowing it would invert the
        // guard's error direction between two commits.
        let content = "export CARGO_HOME=/var/mnt/scratch/example/cargo GOPATH=/etc/evil\n";
        assert_eq!(
            scan_with(content, &rooted()),
            vec![Violation {
                line: 1,
                name: "CARGO_HOME".into(),
                value: "/var/mnt/scratch/example/cargo GOPATH=/etc/evil".into(),
                reason: Reason::MultipleAssignments,
            }]
        );
        // The head need not relocate anything for the tail to matter.
        let content = "export EDITOR=nvim GOPATH=/etc/evil\n";
        assert_eq!(
            scan_with(content, &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::MultipleAssignments]
        );
    }

    #[test]
    fn a_valueless_export_is_refused_and_teaches_the_scan_nothing() {
        // `export X` marks an inherited value for export; it does not set `X`.
        // Round 2 judged it and learned nothing. Round 3 does not read it at
        // all — bx has no reason to export a value it did not write — so it is
        // refused, and a later reference is as unknown as after any refused
        // line.
        let content = concat!(
            "export X\n",
            "export CARGO_HOME=$X/var/mnt/scratch/example/cargo\n",
        );
        assert_eq!(
            reasons(content, &rooted()),
            vec![(1, Reason::Unreadable), (2, Reason::UnreadableReference)]
        );
        assert_eq!(
            reasons("export CARGO_HOME\n", &rooted()),
            vec![(1, Reason::Unreadable)]
        );
        // `setenv` is csh, and neither bash nor zsh has it.
        let content = concat!(
            "setenv SCRATCH_HOME /var/mnt/scratch/example\n",
            "export CARGO_HOME=$SCRATCH_HOME/cargo\n",
        );
        assert_eq!(
            reasons(content, &rooted()),
            vec![(1, Reason::Unreadable), (2, Reason::UnreadableReference)]
        );
    }

    #[test]
    fn a_refused_line_teaches_the_scan_nothing() {
        // The head's "value" is not the value any shell would give the name,
        // so learning it would resolve a later reference to a fiction.
        let content = concat!(
            "A=/var/mnt/scratch/example B=/etc\n",
            "export CARGO_HOME=$A/cargo\n",
        );
        let found = scan_with(content, &rooted());
        assert_eq!(
            found
                .iter()
                .map(|violation| (violation.line, violation.reason))
                .collect::<Vec<_>>(),
            vec![
                (1, Reason::MultipleAssignments),
                (2, Reason::UnreadableReference),
            ]
        );
        // Nor may it leave an *earlier* value standing: a shell has replaced
        // it, so a guard that kept it would judge a path no shell produces.
        for refused in [
            "A=/etc B=1",
            "true && A=/etc",
            "export B A=/etc",
            "declare -n A=OTHER",
        ] {
            let content = format!("A={ROOT}\n{refused}\nexport CARGO_HOME=$A/cargo\n");
            assert_eq!(
                scan_with(&content, &rooted())
                    .iter()
                    .map(|violation| (violation.line, violation.reason))
                    .next_back(),
                Some((3, Reason::UnreadableReference)),
                "{refused}"
            );
        }
    }

    #[test]
    fn whitespace_in_a_value_is_not_a_second_assignment() {
        // The refusal is for another `NAME=`, not for a space: a quoted path
        // with a space in it, and a trailing comment, both still resolve.
        for content in [
            "export CARGO_HOME=\"/var/mnt/scratch/example/my cache\"\n",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # written by bx\n",
        ] {
            assert_eq!(scan_with(content, &rooted()), vec![], "{content}");
        }
    }

    #[test]
    fn a_reference_assigned_earlier_in_the_file_is_expanded() {
        let content =
            "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME=$SCRATCH_HOME/cargo\n";
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn a_reference_assigned_later_in_the_file_is_unresolved() {
        // A shell reading top to bottom would not have it either, so neither
        // does the guard. Order-dependence here is correctness.
        let content =
            "export CARGO_HOME=$SCRATCH_HOME/cargo\nSCRATCH_HOME=/var/mnt/scratch/example\n";
        let found = scan_with(content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[0].reason, Reason::UnresolvedReference);
    }

    #[test]
    fn a_chained_reference_resolves_through_two_hops() {
        let content = concat!(
            "SCRATCH_HOME=/var/mnt/scratch/example\n",
            "CACHE_DIR=$SCRATCH_HOME/cache\n",
            "export GOPATH=$CACHE_DIR/go\n",
            "export GOMODCACHE=$GOPATH/pkg/mod\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn several_references_in_one_value_are_all_substituted() {
        // One pass substitutes every reference in the value, so this resolves
        // in one hop however many there are. It is also what pins the pass's
        // own bound: a bound too small to visit them all leaves a `$` behind,
        // and the value stops resolving.
        let content = concat!(
            "A=/var/mnt/scratch/example\n",
            "B=cache\n",
            "C=cargo\n",
            "export CARGO_HOME=$A/$B/$C/$B/$C/$B\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn a_chain_of_references_resolves_however_deep_it_is() {
        // `X0` is the literal root and each link refers to the one below it. A
        // shell expands each link when it is assigned, so the depth of the
        // chain is never the depth of any one expansion — and neither is it
        // here, because values are learned expanded. A nine-deep chain was
        // once refused as "refers to a variable this fragment has not
        // assigned", every link of which it had assigned.
        fn chain(links: usize) -> String {
            let mut content = format!("X0={ROOT}\n");
            for link in 1..=links {
                content.push_str(&format!("X{link}=$X{}\n", link - 1));
            }
            content.push_str(&format!("export CARGO_HOME=$X{links}/cargo\n"));
            content
        }
        for links in [1, 7, 8, 9, 64] {
            assert_eq!(scan_with(&chain(links), &rooted()), vec![], "{links}");
        }
    }

    #[test]
    fn substituted_text_is_not_expanded_again() {
        // `Y='$X'` holds the two characters `$X`, and a shell that later
        // expands `$Y` yields them and stops. Expanding them again would judge
        // a path no shell produces.
        let content = format!("X=/etc\nY='$X'\nexport CARGO_HOME={ROOT}/$Y\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);
        let content = format!("X={ROOT}\nY='$X'\nexport CARGO_HOME=$Y/cargo\n");
        assert_eq!(
            scan_with(&content, &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::NotAbsolute]
        );
    }

    #[test]
    fn a_value_that_extends_itself_resolves_as_a_shell_would() {
        // `X=$X/b` sees the previous `X`, so it is one more path component
        // under the root, not a value that grows without end.
        let content = concat!(
            "X=/var/mnt/scratch/example\n",
            "X=$X/b\n",
            "export CARGO_HOME=$X/cargo\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
        // Before any `X` is assigned, the same line refers to nothing.
        let found = scan_with("X=$X/b\nexport CARGO_HOME=$X/cargo\n", &rooted());
        assert_eq!(
            found
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::UnresolvedReference]
        );
    }

    #[test]
    fn two_values_that_refer_to_each_other_do_not_resolve() {
        // A true two-node cycle. `A=$B` refers to a `B` not yet assigned, so
        // `A` is unresolvable, and `B=$A` inherits that. Neither `A` nor `B`
        // relocates anything, so the cycle reaches the guard through the value
        // that does.
        let content = concat!("A=$B\n", "B=$A\n", "export CARGO_HOME=$A/cargo\n");
        let found = scan_with(content, &rooted());
        assert_eq!(
            found
                .iter()
                .map(|violation| (violation.line, violation.reason))
                .collect::<Vec<_>>(),
            vec![(3, Reason::UnresolvedReference)]
        );
    }

    #[test]
    fn an_inline_comment_after_a_value_is_a_comment() {
        // An unquoted `#` beginning a word starts a comment in bash and zsh,
        // sourced or interactive, so the value ends before it. A `#` inside a
        // word, or quoted, is text.
        assert_eq!(
            scan_with(
                "export CARGO_HOME=/var/mnt/scratch/example/cargo # written by bx\n",
                &rooted()
            ),
            vec![]
        );
        // The value still has to be inside a root: the comment buys nothing.
        assert_eq!(
            scan_with("export CARGO_HOME=/var/cache/elsewhere # bx\n", &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::OutsideDeclaredRoots]
        );
        // A comment carrying an assignment assigns nothing: no shell reads it.
        for content in [
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # GOPATH=/etc\n",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # keep=this\n",
        ] {
            assert_eq!(scan_with(content, &rooted()), vec![], "{content}");
        }
        // A `#` that does not follow a blank is not a comment to a shell, and
        // not a character the bare-word grammar admits: refused. Quoted, it is
        // text.
        for value in ["/var/mnt/scratch/example/a#b", "#/etc", "\"/x\"#c"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        assert_eq!(
            check("CARGO_HOME", "\"/var/mnt/scratch/example/a#b\"", &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn the_statement_grammar_reads_only_its_own_statements() {
        for line in [
            "",
            "   ",
            "\t",
            "#",
            "# export CARGO_HOME=/x",
            "  \t# note — with prose",
        ] {
            assert_eq!(statement(line), Statement::Nothing, "{line:?}");
        }
        for (line, name, value) in [
            ("CARGO_HOME=/x", "CARGO_HOME", "/x"),
            ("export CARGO_HOME=/x", "CARGO_HOME", "/x"),
            ("  export\t CARGO_HOME=/x # c ", "CARGO_HOME", "/x # c"),
            ("export=/x", "export", "/x"),
            ("exportX=", "exportX", ""),
            ("X=a=b", "X", "a=b"),
        ] {
            assert_eq!(
                statement(line),
                Statement::Assign { name, value },
                "{line:?}"
            );
        }
        for line in [
            "export",
            "export CARGO_HOME",
            "export  ",
            "export\u{b}CARGO_HOME=/x",
            "\\export CARGO_HOME=/x",
            "\"export\" CARGO_HOME=/x",
            "e''xport CARGO_HOME=/x",
            "declare -x CARGO_HOME=/x",
            "export -- CARGO_HOME=/x",
            "CARGO_HOME+=/x",
            "CARGO_HOME[1]=/x",
            "2bad=x",
            "=x",
            "# comment\r",
            "# bell \u{7}",
            "\u{c}",
        ] {
            assert_eq!(statement(line), Statement::Refused, "{line:?}");
        }
    }

    #[test]
    fn an_expansion_that_grows_past_the_length_bound_is_refused_for_its_length() {
        // Values are learned expanded, so a line that doubles a value doubles
        // what is stored; the length bound is what keeps that from growing
        // without end. The reason says so, rather than that a variable the
        // fragment plainly assigned was never assigned.
        let long = format!("{ROOT}/{}", "a".repeat(MAX_EXPANDED_LEN / 2));
        let content = format!("X={long}\nY=$X$X\nexport CARGO_HOME=$Y/cargo\n");
        let found = scan_with(&content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::ExpansionTooLong);
        // And the same bound applies to the value being judged itself.
        let content = format!("X={long}\nexport CARGO_HOME=$X$X\n");
        assert_eq!(
            scan_with(&content, &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::ExpansionTooLong]
        );

        // The identical shape, under the bound, resolves — so the assertion
        // above pins the bound and not the shape.
        let short = format!("{ROOT}/{}", "a".repeat(16));
        let content = format!("X={short}\nY=$X$X\nexport CARGO_HOME=$Y/cargo\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);
    }

    #[test]
    fn an_unknown_reference_is_a_violation() {
        // Silently expanding an unset name to the empty string is exactly the
        // failure this guard exists to catch, so it is an error instead.
        for value in ["$NOWHERE/cargo", "${NOWHERE}/cargo", "/a/$NOWHERE"] {
            let found = scan_with(&format!("export CARGO_HOME={value}\n"), &rooted());
            assert_eq!(found.len(), 1, "{value}");
            assert_eq!(found[0].reason, Reason::UnresolvedReference, "{value}");
        }
    }

    #[test]
    fn a_braced_reference_consumes_its_closing_brace() {
        // `${X}` must expand to X's value and nothing else. Leaving the `}`
        // behind would produce a path with a `}` in a component name, which is
        // a different directory — and one that is no longer inside the root.
        let content = format!("X={ROOT}\nexport CARGO_HOME=${{X}}/cargo\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);

        // The brace ends the name and nothing more: text after it is appended
        // verbatim, with no separator invented. `${X}suffix` therefore names a
        // *sibling* of the root, which is outside it.
        let content = format!("X={ROOT}\nexport CARGO_HOME=${{X}}suffix/cargo\n");
        let found = scan_with(&content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::OutsideDeclaredRoots);
    }

    #[test]
    fn an_unbalanced_quote_is_not_stripped() {
        // A quote that never closes is a shell syntax error wherever it sits —
        // the file stops parsing there — so it is neither stripped nor taken
        // as part of a directory's name. Stripping one would have eaten a
        // character from each end and changed which path the value names.
        for value in [
            "\"/var/mnt/scratch/example/cargo",
            "'/var/mnt/scratch/example/cargo",
            "\"",
            "'",
            "/var/mnt/scratch/example/cargo\"",
            "/var/mnt/scratch/example/cargo'",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        // Quotes around part of a value are mixed quoting, which the grammar
        // does not read, even where a shell would make one path of it. A value
        // is one quoted string or one bare word.
        for value in [
            "/var/mnt/scratch/example/\"..\"/'..'/etc",
            "/var/mnt/scratch/example/\"..\"/\"..\"/etc",
            "\"/var/mnt/scratch/example\"/cargo",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
    }

    #[test]
    fn an_expansion_of_exactly_the_length_bound_still_resolves() {
        // The bound is a limit, not a ceiling one short of it: a value of
        // exactly MAX_EXPANDED_LEN bytes is within it.
        let exact = format!("{ROOT}/{}", "a".repeat(MAX_EXPANDED_LEN - ROOT.len() - 1));
        assert_eq!(exact.len(), MAX_EXPANDED_LEN);
        let content = format!("X={exact}\nexport CARGO_HOME=$X\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);
    }

    #[test]
    fn a_dollar_that_begins_no_reference_is_refused() {
        // The expansion grammar is closed: `$NAME` and `${NAME}`, nothing else.
        // A `$` that begins neither is a special parameter or an operator that
        // a shell expands — `$@` and `$1` to nothing, which let
        // `<root>/$@/$@/../..` climb out of the root while round 2 read the
        // `$@` as literal components — so it is refused wherever it sits.
        for value in [
            "$",
            "$1/x",
            "/var/mnt/scratch/example/a$1b",
            "/var/mnt/scratch/example/$@/$@/../../etc",
            "/var/mnt/scratch/example/$*",
            "/var/mnt/scratch/example/$#",
            "/var/mnt/scratch/example/$?",
            "/var/mnt/scratch/example/$!",
            "/var/mnt/scratch/example/$$",
            "/var/mnt/scratch/example/$-",
            "/var/mnt/scratch/example/$0",
            "${/x",
            "/var/mnt/scratch/example/${FOO",
            "${FOO",
            "${}/x",
            "/var/mnt/scratch/example/${}",
            "/var/mnt/scratch/example/${1}",
            "/var/mnt/scratch/example/${HOME:+..}",
            "/var/mnt/scratch/example/${HOME#/}",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        // `$b` on the other hand *is* a reference, and an undefined one.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/a$b",
                &rooted()
            )),
            Some(Reason::UnresolvedReference)
        );
    }

    #[test]
    fn home_is_taken_from_the_root_set_not_the_process_environment() {
        // A future refactor that reached for `std::env::var("HOME")` would make
        // the guard's verdict machine-dependent, which invariant 3 forbids.
        // Under a real process `$HOME` this fragment would be outside the root;
        // under the root set's home it is inside it.
        let _home = guarded_home();
        let declared = Path::new("/var/home/declared");
        let roots = RootSet::new(declared, &[PathBuf::from("~/scratch")]);
        assert_ne!(
            std::env::var_os("HOME").map(PathBuf::from),
            Some(declared.to_path_buf())
        );
        let content = "export CARGO_HOME=$HOME/scratch/cargo\n";
        assert_eq!(scan_with(content, &roots), vec![]);
    }

    #[test]
    fn a_single_quoted_value_does_not_expand() {
        // `'…'` suppresses expansion in a shell, so the value is the literal
        // text `$SCRATCH_HOME/cargo`, which is not an absolute path.
        let content =
            "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME='$SCRATCH_HOME/cargo'\n";
        let found = scan_with(content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::NotAbsolute);
    }

    #[test]
    fn surrounding_double_quotes_are_stripped() {
        let content = "SCRATCH_HOME=\"/var/mnt/scratch/example\"\nexport CARGO_HOME=\"$SCRATCH_HOME/cargo\"\n";
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn violations_are_reported_in_line_order() {
        let content = concat!(
            "export CARGO_HOME=/elsewhere/a\n",
            "export EDITOR=nvim\n",
            "export RUSTUP_HOME=/var/mnt/scratch/example/rustup\n",
            "export GOPATH=/elsewhere/b\n",
        );
        let found = scan_with(content, &rooted());
        assert_eq!(found.iter().map(|v| v.line).collect::<Vec<_>>(), vec![1, 4]);
        assert_eq!(
            found.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            vec!["CARGO_HOME", "GOPATH"]
        );
    }

    #[test]
    fn scanning_the_same_content_twice_returns_the_same_violations() {
        // Invariant 3. The guard is a pure function of `(content, roots)`: it
        // reads no process environment, touches no disk, and holds its roots in
        // declaration order, so no iteration order can reach the output.
        let content = OPERATOR_FRAGMENT;
        assert_eq!(scan_with(content, &rooted()), scan_with(content, &rooted()));
        assert_eq!(scan(content), scan(content));
    }

    /// The operator's own relocating exports, with the scratch mount replaced
    /// by a neutral root so nothing user-specific enters the repository
    /// (invariant 5). Every one of these was denied or leaked by the
    /// name-based guard; all 23 are value-checked now.
    const OPERATOR_FRAGMENT: &str = concat!(
        "export SCRATCH_HOME=\"/var/mnt/scratch/example\"\n",
        "CACHE_DIR=\"$SCRATCH_HOME/cache\"\n",
        "DATA_DIR=\"$SCRATCH_HOME/.local/share\"\n",
        "export NPM_CONFIG_CACHE=\"$SCRATCH_HOME/.npm\"\n",
        "export PNPM_CONFIG_STORE_DIR=\"$CACHE_DIR/pnpm\"\n",
        "export BUN_INSTALL=\"$SCRATCH_HOME/.bun\"\n",
        "export BUN_INSTALL_CACHE_DIR=\"$CACHE_DIR/bun\"\n",
        "export CARGO_HOME=\"$CACHE_DIR/cargo\"\n",
        "export RUSTUP_HOME=\"$CACHE_DIR/rustup\"\n",
        "export GOPATH=\"$CACHE_DIR/go\"\n",
        "export GOMODCACHE=\"$GOPATH/pkg/mod\"\n",
        "export GOCACHE=\"$CACHE_DIR/go-build\"\n",
        "export UV_CACHE_DIR=\"$CACHE_DIR/uv\"\n",
        "export PIP_CACHE_DIR=\"$CACHE_DIR/pip\"\n",
        "export ZIG_GLOBAL_CACHE_DIR=\"$CACHE_DIR/zig\"\n",
        "export ANDROID_HOME=\"$SCRATCH_HOME/Android/Sdk\"\n",
        "export ANDROID_USER_HOME=\"$SCRATCH_HOME/.android\"\n",
        "export NUGET_PACKAGES=\"$CACHE_DIR/nuget\"\n",
        "export NUGET_HTTP_CACHE_PATH=\"$CACHE_DIR/nuget-http\"\n",
        "export DOTNET_CLI_HOME=\"$CACHE_DIR/dotnet\"\n",
        "export HOMEBREW_CACHE=\"$CACHE_DIR/Homebrew/cache\"\n",
        "export HOMEBREW_LOGS=\"$CACHE_DIR/Homebrew/logs\"\n",
        "export HOMEBREW_TEMP=\"$CACHE_DIR/Homebrew/temp\"\n",
        "export MISE_DATA_DIR=\"$DATA_DIR/mise\"\n",
        "export MISE_CACHE_DIR=\"$CACHE_DIR/mise\"\n",
    );

    #[test]
    fn the_six_names_that_used_to_leak_are_now_checked() {
        // Each of these relocates a real toolchain cache and matched no rule in
        // the name list, so the guard let it through unexamined. This is the
        // regression test for that defect: they are checked now, and checking
        // means allowed inside a declared root and rejected outside every one.
        for name in [
            "PNPM_CONFIG_STORE_DIR",
            "GOCACHE",
            "NUGET_HTTP_CACHE_PATH",
            "HOMEBREW_CACHE",
            "HOMEBREW_LOGS",
            "HOMEBREW_TEMP",
        ] {
            assert!(is_relocating(name), "{name} should be value-checked");
            assert_eq!(
                check(name, "/var/mnt/scratch/example/x", &rooted()),
                Verdict::Allowed,
                "{name}"
            );
            assert_eq!(
                reason_of(&check(name, "/var/cache/elsewhere", &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{name}"
            );
        }
    }

    #[test]
    fn an_sccache_directory_is_value_checked() {
        // The motivating case for the root set being a *set*: an sccache
        // directory may legitimately live outside the scratch root, and must
        // then be covered by a root of its own rather than waved through.
        assert!(is_relocating("SCCACHE_DIR"));
        // The behaviour variables that share its prefix still are not.
        assert!(!is_relocating("SCCACHE_CACHE_SIZE"));
        assert!(!is_relocating("SCCACHE_SERVER_UDS"));

        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(ROOT), PathBuf::from("/var/cache/sccache")],
        );
        assert_eq!(
            check("SCCACHE_DIR", "/var/cache/sccache/objects", &roots),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check(
                "SCCACHE_DIR",
                "/var/cache/sccache/objects",
                &rooted()
            )),
            Some(Reason::OutsideDeclaredRoots)
        );
    }

    #[test]
    fn widening_the_list_did_not_capture_a_colon_separated_list() {
        // A generic `_PATH` or `_DIR` suffix would have. Those lists are not
        // single paths and would be rejected for not being absolute, which is
        // why the list is widened by observed evidence and nothing else.
        for name in ["LD_LIBRARY_PATH", "PATH", "MANPATH", "PKG_CONFIG_PATH"] {
            assert!(!is_relocating(name), "{name} should not be value-checked");
        }
    }

    #[test]
    fn the_same_fragment_is_all_violations_with_no_root_declared() {
        // A user who declares no root gets the strict guard, and the strict
        // guard denies every relocation. `CACHE_DIR` and `DATA_DIR` are not
        // relocating names, so 25 assignments yield 23 violations — and 23 is
        // the whole relocating set, six of which reach this count only because
        // the name list was widened.
        let found = scan(OPERATOR_FRAGMENT);
        assert_eq!(found.len(), 23);
        assert!(found.iter().all(|v| v.reason == Reason::NoRootsDeclared));
        assert!(found.windows(2).all(|w| w[0].line < w[1].line));
        assert!(!found.iter().any(|v| v.name == "CACHE_DIR"));
        assert!(!found.iter().any(|v| v.name == "DATA_DIR"));
    }

    #[test]
    fn the_operator_fragment_scans_clean_under_its_declared_root() {
        assert_eq!(scan_with(OPERATOR_FRAGMENT, &rooted()), vec![]);
    }

    #[test]
    fn xdg_roots_are_value_checked() {
        for name in [
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "XDG_STATE_HOME",
        ] {
            assert!(is_relocating(name), "{name} should be value-checked");
        }
    }

    #[test]
    fn per_tool_roots_are_value_checked() {
        for name in [
            "CARGO_HOME",
            "RUSTUP_HOME",
            "GNUPGHOME",
            "GH_CONFIG_DIR",
            "KUBECONFIG",
        ] {
            assert!(is_relocating(name), "{name} should be value-checked");
        }
    }

    #[test]
    fn tool_families_are_value_checked_by_prefix() {
        for name in [
            "MISE_DATA_DIR",
            "UV_CACHE_DIR",
            "NPM_CONFIG_PREFIX",
            "ASDF_DIR",
            "PIP_TARGET",
        ] {
            assert!(is_relocating(name), "{name} should be value-checked");
        }
    }

    #[test]
    fn location_suffixes_are_value_checked_generically() {
        // The point of the suffix rule is catching tools bx has never heard of.
        for name in ["SOMETOOL_CONFIG_DIR", "OTHERTOOL_HOME", "THIRD_CACHE_DIR"] {
            assert!(is_relocating(name), "{name} should be value-checked");
        }
    }

    #[test]
    fn a_bare_prefix_or_suffix_is_not_a_variable() {
        // `_HOME` is the suffix itself, not a tool's variable; likewise `UV_`.
        assert!(!is_relocating("_HOME"));
        assert!(!is_relocating("UV_"));
    }

    #[test]
    fn behaviour_variables_are_allowed() {
        for name in [
            "SCCACHE_CACHE_SIZE",
            "RUSTC_WRAPPER",
            "EDITOR",
            "VISUAL",
            "PAGER",
            "SCCACHE_SERVER_UDS",
        ] {
            assert!(!is_relocating(name), "{name} should be allowed");
        }
    }

    #[test]
    fn documented_exceptions_survive_the_prefix_rule() {
        assert!(!is_relocating("UV_SYSTEM_PYTHON"));
        assert!(!is_relocating("MISE_VERBOSE"));
        assert!(!is_relocating("PIP_REQUIRE_VIRTUALENV"));
    }

    #[test]
    fn the_check_is_case_sensitive() {
        assert!(!is_relocating("cargo_home"));
    }

    #[test]
    fn scan_reports_the_offending_line_and_name() {
        let content = "export EDITOR=nvim\nexport CARGO_HOME=$HOME/x\n";
        assert_eq!(
            scan(content),
            vec![Violation {
                line: 2,
                name: "CARGO_HOME".into(),
                value: "$HOME/x".into(),
                reason: Reason::NoRootsDeclared,
            }]
        );
    }

    #[test]
    fn scan_accepts_clean_content() {
        let content = "# bx generated\nexport SCCACHE_CACHE_SIZE=100G\nexport RUSTC_WRAPPER=/usr/bin/sccache\n";
        assert!(scan(content).is_empty());
    }

    #[test]
    fn scan_judges_its_two_assignment_forms_and_refuses_every_other() {
        for line in [
            "export CARGO_HOME=/x",
            "CARGO_HOME=/x",
            "  export CARGO_HOME=/x",
            "\texport\tCARGO_HOME=/x # note",
        ] {
            assert_eq!(
                scan(line)
                    .iter()
                    .map(|violation| (violation.name.as_str(), violation.reason))
                    .collect::<Vec<_>>(),
                vec![("CARGO_HOME", Reason::NoRootsDeclared)],
                "should have judged: {line}"
            );
        }
        for line in [
            "typeset -x CARGO_HOME=/x",
            "declare -x CARGO_HOME=/x",
            "setenv CARGO_HOME /x",
            "declare -gx CARGO_HOME=/x",
            "typeset -gx CARGO_HOME=/x",
            "export -- CARGO_HOME=/x",
            "readonly CARGO_HOME=/x",
            "local CARGO_HOME=/x",
            "export CARGO_HOME+=/x",
        ] {
            assert_eq!(
                scan(line),
                vec![Violation {
                    line: 1,
                    name: String::new(),
                    value: line.into(),
                    reason: Reason::Unreadable,
                }],
                "should have refused: {line}"
            );
        }
    }

    #[test]
    fn scan_ignores_comments() {
        assert!(scan("# export CARGO_HOME=/x\n   # CARGO_HOME=/x").is_empty());
    }

    #[test]
    fn scan_refuses_a_line_that_is_not_a_statement_it_reads() {
        // Round 2 let a command through as assigning nothing. Round 3 does not
        // decide what a command assigns: a line that is not blank, a comment or
        // an assignment in the grammar is refused.
        assert_eq!(
            reasons(
                "source ~/.cargo/env\n\n[[ -r $f ]] && source $f\n2bad=x\n=x",
                &RootSet::strict()
            ),
            vec![
                (1, Reason::Unreadable),
                (3, Reason::Unreadable),
                (4, Reason::Unreadable),
                (5, Reason::Unreadable),
            ]
        );
    }

    // Review round 2: the guard fails closed on shell it cannot read, reads
    // a value quote-aware, and gives one verdict whichever entry point asks.

    /// The reasons `scan_with` gives, in line order, with their line numbers.
    fn reasons(content: &str, roots: &RootSet) -> Vec<(usize, Reason)> {
        scan_with(content, roots)
            .iter()
            .map(|violation| (violation.line, violation.reason))
            .collect()
    }

    #[test]
    fn a_keyword_other_than_export_is_refused_whatever_it_assigns() {
        // Each of these sets `CARGO_HOME=/etc/evil` in bash or zsh. Round 2
        // read the keyword and judged the operand; round 3 reads no keyword but
        // `export`, so each is refused before its operand is looked at — and
        // so would be the next spelling of a keyword round 2 did not know.
        for line in [
            "declare -gx CARGO_HOME=/etc/evil",
            "typeset -gx CARGO_HOME=/etc/evil",
            "export -- CARGO_HOME=/etc/evil",
            "readonly CARGO_HOME=/etc/evil",
            "local CARGO_HOME=/etc/evil",
            "export -x CARGO_HOME=/etc/evil",
        ] {
            assert_eq!(
                scan(line),
                vec![Violation {
                    line: 1,
                    name: String::new(),
                    value: line.into(),
                    reason: Reason::Unreadable,
                }],
                "{line}"
            );
            assert_eq!(
                reasons(line, &rooted()),
                vec![(1, Reason::Unreadable)],
                "{line}"
            );
        }
    }

    #[test]
    fn a_line_the_guard_cannot_read_is_never_approved() {
        // A second assignment after a value: refused as one, and not learned.
        for line in [
            "export FOO=1 CARGO_HOME=/etc/evil",
            "FOO=1 CARGO_HOME=/etc/evil",
        ] {
            assert_eq!(
                reasons(line, &RootSet::strict()),
                vec![(1, Reason::MultipleAssignments)],
                "{line}"
            );
        }
        // Anything else that mentions a keyword, or assigns where a command
        // starts, and is not a form the guard reads.
        for line in [
            "export FOO CARGO_HOME=/etc/evil",
            "export A B CARGO_HOME=/etc/evil",
            "export PATH CARGO_HOME=/var/mnt/scratch/example/cargo",
            "true && export CARGO_HOME=/etc/evil",
            "[ -d /x ] && CARGO_HOME=/etc/evil",
            "builtin export CARGO_HOME=/etc/evil",
            "export CARGO_HOME=/etc/evil; echo done",
            "declare -n CARGO_HOME=OTHER",
            "typeset -u CARGO_HOME=/var/mnt/scratch/example",
            "export +x CARGO_HOME",
            "export CARGO_HOME=\"/var/mnt/scratch/example",
            "export EDITOR=nvim --wait",
            "export \\",
            "CARGO_HOME=/var/mnt/scratch/example cargo build",
        ] {
            assert_eq!(
                reasons(line, &rooted()),
                vec![(1, Reason::Unreadable)],
                "{line}"
            );
        }
        // A line refused before a variable can be picked out of it quotes
        // itself back whole, without its indentation.
        assert_eq!(
            scan("  true && export CARGO_HOME=/etc/evil # note"),
            vec![Violation {
                line: 1,
                name: String::new(),
                value: "true && export CARGO_HOME=/etc/evil # note".into(),
                reason: Reason::Unreadable,
            }]
        );
    }

    #[test]
    fn a_prefix_does_not_carry_a_value_past_bxs_own_directory() {
        // The exclusion the module calls unconditional, bypassed by one word.
        let wide = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let state = "/var/home/example/.local/state/bx";
        assert_eq!(
            reasons(&format!("export XDG_STATE_HOME={state}"), &wide),
            vec![(1, Reason::BxOwnedDirectory)]
        );
        for line in [
            format!("declare -gx XDG_STATE_HOME={state}"),
            format!("export FOO XDG_STATE_HOME={state}"),
        ] {
            assert_eq!(
                reasons(&line, &wide),
                vec![(1, Reason::Unreadable)],
                "{line}"
            );
        }
        assert_eq!(
            reasons(&format!("export FOO=1 XDG_STATE_HOME={state}"), &wide),
            vec![(1, Reason::MultipleAssignments)]
        );
    }

    #[test]
    fn a_value_or_a_line_the_guard_does_not_read_is_refused_whatever_the_name() {
        // A command substitution, an escape, a brace expansion, an array and
        // mixed quoting are shell the guard does not run. Round 2 refused them
        // for a relocating variable only; round 3 refuses them for every one,
        // because a line the grammar does not read may do anything whatever
        // its first name is.
        for name in ["CARGO_HOME", "EDITOR"] {
            for value in [
                "$(pwd)/cargo",
                "\"$(pwd)/cargo\"",
                "`pwd`/cargo",
                "/var/mnt/scratch/example/\\../cargo",
                "/var/mnt/scratch/example/{..,x}",
                "(/var/mnt/scratch/example)",
                "'/var/mnt/scratch/example'/$X",
            ] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    Some(Reason::Unreadable),
                    "{name}={value}"
                );
            }
        }
        // Ordinary rc content that round 2 let through as assigning nothing.
        for line in [
            "export GPG_TTY=$(tty)",
            "export GIT_TOP=\"$(git rev-parse --show-toplevel)\"",
            "path=(/var/mnt/scratch/example/bin $path)",
            "export PATH+=:/var/mnt/scratch/example/bin",
            "alias ll='ls -l'",
            "eval \"$(mise activate zsh)\"",
            "make V=1",
        ] {
            assert_eq!(
                reasons(line, &rooted()),
                vec![(1, Reason::Unreadable)],
                "{line}"
            );
        }
        // And what it could not read, it does not learn.
        let content = "X=$(pwd)\nexport CARGO_HOME=$X/cargo\n";
        assert_eq!(
            reasons(content, &rooted()),
            vec![(1, Reason::Unreadable), (2, Reason::UnreadableReference)]
        );
    }

    #[test]
    fn a_quoted_tilde_is_a_literal_tilde() {
        // A shell expands `~` only unquoted at the start of a value. Quoted, or
        // arriving through a reference, it is a relative path.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(
            check("CARGO_HOME", "~/cargo", &home_rooted),
            Verdict::Allowed
        );
        for value in ["\"~/cargo\"", "'~/cargo'"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &home_rooted)),
                Some(Reason::NotAbsolute),
                "{value}"
            );
        }
        assert_eq!(
            reasons("X='~'\nexport CARGO_HOME=$X/cargo\n", &home_rooted),
            vec![(2, Reason::NotAbsolute)]
        );
    }

    #[test]
    fn a_single_assignment_with_an_equals_sign_in_its_value_is_not_two() {
        // Each assigns one variable. The `=` is inside the value, so the old
        // remedy — split the line — was impossible to follow.
        for line in [
            "export MAKEFLAGS=\"-j8 V=1\"",
            "export MAKEFLAGS='-j8 V=1'",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # keep=this",
            "export GRADLE_USER_HOME=\"/var/mnt/scratch/example/a b=c/gradle\"",
        ] {
            assert_eq!(scan_with(line, &rooted()), vec![], "{line}");
        }
        // Unquoted, the same text is two assignments to a shell, and says so.
        assert_eq!(
            reasons("export MAKEFLAGS=-j8 V=1", &rooted()),
            vec![(1, Reason::MultipleAssignments)]
        );
    }

    #[test]
    fn check_and_scan_give_one_verdict() {
        // `check` and `scan_with` both call `evaluate`, so a value that is not
        // one shell word is refused whichever entry point is asked.
        for (name, value, reason) in [
            (
                "CARGO_HOME",
                "/var/mnt/scratch/example/cargo FOO=/etc/evil",
                Some(Reason::MultipleAssignments),
            ),
            (
                "EDITOR",
                "nvim GOPATH=/etc/evil",
                Some(Reason::MultipleAssignments),
            ),
            ("EDITOR", "nvim --wait", Some(Reason::Unreadable)),
            (
                "CARGO_HOME",
                " /var/mnt/scratch/example",
                Some(Reason::Unreadable),
            ),
            ("MAKEFLAGS", "\"-j8 V=1\"", None),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b\"", None),
            ("CARGO_HOME", "$(pwd)", Some(Reason::Unreadable)),
            ("CARGO_HOME", "/etc", Some(Reason::OutsideDeclaredRoots)),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                reason,
                "check {name}={value}"
            );
            assert_eq!(
                scan_with(&format!("export {name}={value}"), &rooted())
                    .first()
                    .map(|violation| violation.reason),
                reason,
                "scan {name}={value}"
            );
        }
    }

    #[test]
    fn an_inadmissible_root_is_not_mistaken_for_no_root() {
        // `scratch_root = "/"` visibly declares a root. Telling that user no
        // root is declared sends them looking for a declaration that exists.
        let dropped = RootSet::new(Path::new(HOME), &[PathBuf::from("/")]);
        let nothing = RootSet::new(Path::new(HOME), &[]);
        assert_ne!(dropped, nothing);
        assert_eq!(dropped.home(), nothing.home());
        assert_eq!(dropped.inadmissible(), &[PathBuf::from("/")]);
        assert!(nothing.inadmissible().is_empty());
        assert!(RootSet::strict().inadmissible().is_empty());
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x", &dropped)),
            Some(Reason::InadmissibleRoot)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x", &nothing)),
            Some(Reason::NoRootsDeclared)
        );
        assert_eq!(
            reasons("export CARGO_HOME=/x\n", &dropped),
            vec![(1, Reason::InadmissibleRoot)]
        );
        // Beside an admissible root, the refused one is still reported.
        let mixed = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from("/.."), PathBuf::from(ROOT)],
        );
        assert_eq!(mixed.inadmissible(), &[PathBuf::from("/..")]);
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cargo", &mixed),
            Verdict::Allowed
        );
    }

    #[test]
    fn behaviour_variables_in_a_location_family_are_allowed() {
        // All ten were refused as `NotAPath`, whose remedy was an edit to a
        // private list in bx's source. None relocates anything.
        for (name, value) in [
            ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
            ("NPM_CONFIG_FUND", "false"),
            ("NPM_CONFIG_LOGLEVEL", "warn"),
            ("PIP_INDEX_URL", "https://pypi.example.invalid/simple"),
            ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
            ("UV_NO_CACHE", "1"),
            ("UV_PYTHON", "3.12"),
            ("MISE_ENV", "production"),
            ("MISE_JOBS", "8"),
            ("ASDF_CONCURRENCY", "8"),
        ] {
            assert!(is_relocating(name), "{name}");
            assert!(!names_a_location(name), "{name}");
            assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
            // It relocates nothing, so it needs no root declared either.
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
    }

    #[test]
    fn a_family_variable_that_holds_a_location_is_still_judged() {
        // Invariant 2 is not relaxed for the same families: a location given a
        // path is judged by where it points, and one whose name says it holds a
        // location is refused a bare word, which is a path relative to
        // wherever the shell happens to be.
        for name in [
            "UV_TOOL_DIR",
            "PIP_TARGET",
            "NPM_CONFIG_CACHE",
            "NPM_CONFIG_PREFIX",
            "NPM_CONFIG_USERCONFIG",
            "MISE_INSTALL_PATH",
            "UV_PROJECT_ENVIRONMENT",
        ] {
            assert!(names_a_location(name), "{name}");
            assert_eq!(
                reason_of(&check(name, "cache", &rooted())),
                Some(Reason::NotAPath),
                "{name}"
            );
            assert_eq!(
                reason_of(&check(name, "/etc/evil", &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{name}"
            );
            assert_eq!(
                reason_of(&check(name, ".cache/x", &rooted())),
                Some(Reason::NotAbsolute),
                "{name}"
            );
        }
        // A name matched by nothing is not a family name at all.
        assert!(!names_a_location("EDITOR"));
        assert!(!names_a_location("UV_"));
    }

    #[test]
    fn scan_reports_every_violation() {
        let content = "export XDG_CONFIG_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n";
        let found = scan(content);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[1].line, 3);
    }

    // Round-3 reproductions, written against the round-2 API only.

    /// Every case the guard approves; a reproduction fails listing all of them.
    fn r3_approved_cases(cases: &[(&str, RootSet)]) -> Vec<String> {
        cases
            .iter()
            .filter(|(content, roots)| scan_with(content, roots).is_empty())
            .map(|(content, _)| content.to_string())
            .collect()
    }

    #[test]
    fn r3_1_quoted_escaped_and_aliased_keywords() {
        let mut cases = Vec::new();
        for content in [
            "\\export CARGO_HOME=/etc/evil",
            "\"export\" CARGO_HOME=/etc/evil",
            "e''xport CARGO_HOME=/etc/evil",
            "alias ex=export\nex CARGO_HOME=/etc/evil",
        ] {
            cases.push((content, rooted()));
            cases.push((content, RootSet::strict()));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r3_2_multi_line_constructs() {
        let cases = [
            ": '\n'; export CARGO_HOME=/etc/evil #'",
            "ex\\\nport CARGO_HOME=/etc/evil",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo\nCARGO_\\\nHOME=/etc/evil",
        ]
        .map(|content| (content, rooted()));
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r3_3_assigning_commands_and_stale_values() {
        let cases = [
            "for CARGO_HOME in /etc/evil; do :; done",
            "read -r CARGO_HOME <<< /etc/evil",
            "printf -v CARGO_HOME /etc/evil",
            "CARGO_HOME[1,-1]=/etc/evil",
            ": ${CARGO_HOME::=/etc/evil}",
            "set -a\n: ${CARGO_HOME:=/etc/evil}",
            "R=/var/mnt/scratch/example\nunset R\nexport CARGO_HOME=$R/etc/evil",
        ]
        .map(|content| (content, rooted()));
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r3_4_special_parameters_and_a_fragment_assigned_home() {
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let cases = [
            (
                "CARGO_HOME=/var/mnt/scratch/example/$@/$@/$@/$@/../../../../etc/evil",
                rooted(),
            ),
            ("XDG_STATE_HOME=~/.local/state/b$@x", home_rooted.clone()),
            ("HOME=/etc/evil\nCARGO_HOME=~/cargo", home_rooted),
        ];
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r3_5_eval_and_source_with_a_literal_payload() {
        let cases = [
            "eval \"export CARGO_HOME=/etc/evil\"",
            "source /dev/stdin <<< 'export CARGO_HOME=/etc/evil'",
        ]
        .map(|content| (content, rooted()));
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r3_6_missing_relocating_names() {
        let approved: Vec<&str> = [
            "HOME",
            "npm_config_cache",
            "ZDOTDIR",
            "YARN_CACHE_FOLDER",
            "CCACHE_DIR",
            "STARSHIP_CONFIG",
            "PYTHONUSERBASE",
            "TMPDIR",
        ]
        .into_iter()
        .filter(|name| check(name, "/etc/evil", &rooted()) == Verdict::Allowed)
        .collect();
        assert_eq!(approved, Vec::<&str>::new());
    }

    #[test]
    fn r3_7_colon_lists() {
        let cases = [
            "KUBECONFIG=/var/mnt/scratch/example/k:/etc/evil/config",
            "GOPATH=/var/mnt/scratch/example/go:/etc/evil",
        ]
        .map(|content| (content, rooted()));
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r3_8_location_words_and_zsh_equals_expansion() {
        let cases = [
            "MISE_SHARED_INSTALL_DIRS=evil",
            "MISE_TRUSTED_CONFIG_PATHS=evil",
            "UV_PROJECT=evil",
            "MISE_DEFAULT_CONFIG_FILENAME=evil.toml",
            "UV_PROJECT==ls",
        ]
        .map(|content| (content, rooted()));
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    // Review round 3: the guard fails closed by shape.

    #[test]
    fn the_value_grammar_reads_its_three_forms_and_nothing_else() {
        // Judged for a variable that relocates nothing, so the verdict is the
        // grammar's alone — and `check` and `scan_with` must give the same one.
        let accepted = [
            "",
            "''",
            "\"\"",
            "nvim",
            "/a_b.c,d:e@f%g+h-i",
            "'$X `x` \\ \"q\" ! ~ = # {a,b} *'",
            "\"a b=c{d}[e]*f?g#h~i'j %^&;|<>()\"",
            "\"-j8 V=1\"",
            "~",
            "~/x",
            "$HOME",
            "${HOME}",
            "$HOME/x",
            "${HOME}x",
            "${HOME}:h",
            "$HOME$HOME",
            "\"$HOME\"",
            "\"${HOME}[1]\"",
            "\"$HOME/a:$HOME\"",
            "/x # a comment",
            "/x\t# a comment",
            "\"/x\" # a comment",
        ];
        for value in accepted {
            assert_eq!(
                check("EDITOR", value, &rooted()),
                Verdict::Allowed,
                "{value:?}"
            );
            assert_eq!(
                scan_with(&format!("export EDITOR={value}"), &rooted()),
                vec![],
                "{value:?}"
            );
        }
        let unreadable = [
            // zsh modifiers and subscripts after an unbraced name.
            "$HOME:h",
            "\"$HOME:h\"",
            "$HOME[1]",
            "\"$HOME[1]\"",
            "$HOME.y",
            "$HOME-y",
            // zsh `=cmd`, and `~` or `=` after a `:`.
            "=ls",
            "a:=ls",
            "/a:~/b",
            "~other",
            "a~",
            // Escapes, and quoting that is not one plain string.
            "\\/x",
            "\"a\\\"b\"",
            "'a'b",
            "'a''b'",
            "\"a\"'b'",
            "a\"b\"",
            "'a",
            "\"a",
            "a'",
            "$'x'",
            "$\"x\"",
            // Substitutions and expansions.
            "`x`",
            "\"`x`\"",
            "$(x)",
            "\"$(x)\"",
            "$((1))",
            "${X:-y}",
            "${#X}",
            "${X",
            "{a,b}",
            // Globs, operators, history.
            "*",
            "?",
            "[a]",
            "a;b",
            "a&b",
            "a|b",
            "a>b",
            "a<b",
            "(a)",
            "!x",
            "\"!x\"",
            "^x",
            "#x",
            "x#y",
            // A second word that is not an assignment.
            "/x cmd",
            "/x \\",
            // Characters outside printable ASCII, and control characters.
            "é",
            "\"é\"",
            "'é'",
            "\"a\tb\"",
            "'a\tb'",
            "/x\u{7}",
            "/x # \u{7}",
            "/x\r",
        ];
        for value in unreadable {
            assert_eq!(
                reason_of(&check("EDITOR", value, &rooted())),
                Some(Reason::Unreadable),
                "{value:?}"
            );
            assert_eq!(
                reasons(&format!("export EDITOR={value}"), &rooted()),
                vec![(1, Reason::Unreadable)],
                "{value:?}"
            );
        }
        // A second word with an `=` in it is a second assignment only when
        // what precedes the `=` is a name; otherwise it is a command's
        // argument, which the grammar does not read either.
        for value in ["nvim --wait=1", "/x a-b=c", "/x 2a=b", "/x =b"] {
            assert_eq!(
                reason_of(&check("EDITOR", value, &rooted())),
                Some(Reason::Unreadable),
                "{value:?}"
            );
        }
        // A value that begins like a path is judged as one even for a name
        // that does not say it holds a location: `~` alone is the home, and
        // `/a://b` starts at the filesystem root however URL-like its middle.
        for value in ["~", "/a://b"] {
            assert_eq!(
                reason_of(&check("UV_PYTHON", value, &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{value:?}"
            );
        }
        for value in ["/x A=1", "/x\tA=1", "'/x' A=1"] {
            assert_eq!(
                reason_of(&check("EDITOR", value, &rooted())),
                Some(Reason::MultipleAssignments),
                "{value:?}"
            );
        }
        // A name `check` is handed that no shell could assign.
        for name in ["", "2bad", "A-B", "A B", "É"] {
            assert_eq!(
                reason_of(&check(name, "/x", &rooted())),
                Some(Reason::Unreadable),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_name_the_shell_manages_may_be_neither_assigned_nor_referred_to() {
        for name in [
            "HOME", "RANDOM", "SECONDS", "LINENO", "path", "fpath", "USERNAME", "UID", "_",
            "FUNCNAME", "ERRNO",
        ] {
            assert_eq!(
                reason_of(&check(name, ROOT, &rooted())),
                Some(Reason::ReservedName),
                "{name}"
            );
            assert_eq!(
                reasons(&format!("export {name}={ROOT}\n"), &RootSet::strict()),
                vec![(1, Reason::ReservedName)],
                "{name}"
            );
        }
        // `RANDOM` reads back as a number, whatever it was given.
        assert_eq!(
            reasons(
                &format!("RANDOM={ROOT}\nexport CARGO_HOME=$RANDOM/cargo\n"),
                &rooted()
            ),
            vec![(1, Reason::ReservedName), (2, Reason::UnreadableReference)]
        );
        assert_eq!(
            reasons(
                "export CARGO_HOME=/var/mnt/scratch/example/$LINENO\n",
                &rooted()
            ),
            vec![(1, Reason::ReservedName)]
        );
        // The review's case: a fragment that moves `HOME` no longer moves `~`.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(
            reasons("HOME=/etc/evil\nCARGO_HOME=~/cargo\n", &home_rooted),
            vec![(1, Reason::ReservedName), (2, Reason::UnreadableReference)]
        );
        // `PATH` reads back as written, so it may be assigned and extended.
        assert!(!SHELL_NAMES.contains(&"PATH"));
        assert_eq!(
            scan_with("export PATH=\"$HOME/.local/bin:$PATH\"\n", &rooted()),
            vec![]
        );
        // Without a home, `$HOME` is unresolved rather than reserved.
        assert_eq!(
            reason_of(&check("GPG_TTY", "$HOME", &RootSet::strict())),
            None
        );
        let mut scope = Scope::default();
        assert_eq!(scope.lookup("HOME", None), Err(Reason::UnresolvedReference));
        assert_eq!(scope.lookup("RANDOM", None), Err(Reason::ReservedName));
        assert_eq!(
            scope.lookup("SCRATCH", None),
            Err(Reason::UnresolvedReference)
        );
        scope.forget_everything();
        assert_eq!(
            scope.lookup("HOME", Some(Path::new(HOME))),
            Err(Reason::UnreadableReference)
        );
    }

    #[test]
    fn every_entry_of_a_list_is_judged() {
        use Reason::{BxOwnedDirectory, NotAbsolute, OutsideDeclaredRoots};
        for (value, reason) in [
            (
                "/var/mnt/scratch/example/k:/var/mnt/scratch/example/l",
                None,
            ),
            (
                "/var/mnt/scratch/example/k:/etc/evil/config",
                Some(OutsideDeclaredRoots),
            ),
            (
                "/etc/evil:/var/mnt/scratch/example/k",
                Some(OutsideDeclaredRoots),
            ),
            ("/var/mnt/scratch/example/k:", Some(NotAbsolute)),
            (":/var/mnt/scratch/example/k", Some(NotAbsolute)),
            ("/var/mnt/scratch/example/k:relative", Some(NotAbsolute)),
            (
                "/var/mnt/scratch/example/k:/var/home/example/.local/state/bx",
                Some(BxOwnedDirectory),
            ),
        ] {
            for name in ["KUBECONFIG", "GOPATH", "CARGO_HOME"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    reason,
                    "{name}={value}"
                );
            }
        }
        // Entries arriving through references are split the same way. The
        // references are braced: zsh reads `$A:$B` as `$A` with a modifier.
        let content = concat!(
            "A=/var/mnt/scratch/example/go\n",
            "B=/etc/evil\n",
            "export GOPATH=\"${A}:${B}\"\n",
            "export GOPATH=\"$A:$B\"\n",
        );
        assert_eq!(
            reasons(content, &rooted()),
            vec![(3, OutsideDeclaredRoots), (4, Reason::Unreadable)]
        );
    }

    #[test]
    fn npm_config_is_judged_whatever_its_case() {
        for name in [
            "npm_config_cache",
            "Npm_Config_Prefix",
            "npm_CONFIG_userconfig",
        ] {
            assert!(is_relocating(name), "{name}");
            assert!(names_a_location(name), "{name}");
            assert_eq!(
                reason_of(&check(name, "/etc/evil", &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{name}"
            );
            assert_eq!(
                reason_of(&check(name, ".npm", &rooted())),
                Some(Reason::NotAPath),
                "{name}"
            );
            assert_eq!(
                check(name, "/var/mnt/scratch/example/npm", &rooted()),
                Verdict::Allowed,
                "{name}"
            );
        }
        // A behaviour setting stays one in lower case.
        assert!(!names_a_location("npm_config_registry"));
        assert_eq!(
            check(
                "npm_config_registry",
                "https://registry.example.invalid",
                &RootSet::strict()
            ),
            Verdict::Allowed
        );
        assert!(!is_relocating("npm_config_"));
        assert!(!is_relocating("npm_confi"));
        // Only npm reads its family that way.
        assert!(!is_relocating("uv_cache_dir"));
        assert!(!is_relocating("mise_data_dir"));
    }

    #[test]
    fn the_names_and_location_words_the_review_found_missing_are_judged() {
        for name in [
            "ZDOTDIR",
            "YARN_CACHE_FOLDER",
            "CCACHE_DIR",
            "STARSHIP_CONFIG",
            "PYTHONUSERBASE",
            "TMPDIR",
        ] {
            assert!(is_relocating(name), "{name}");
            assert_eq!(
                reason_of(&check(name, "/etc/evil", &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{name}"
            );
            assert_eq!(
                check(name, "/var/mnt/scratch/example/x", &rooted()),
                Verdict::Allowed,
                "{name}"
            );
        }
        assert!(is_relocating("HOME"));
        for (name, value) in [
            ("MISE_SHARED_INSTALL_DIRS", "evil"),
            ("MISE_TRUSTED_CONFIG_PATHS", "evil"),
            ("UV_PROJECT", "evil"),
            ("MISE_DEFAULT_CONFIG_FILENAME", "evil.toml"),
        ] {
            assert!(names_a_location(name), "{name}");
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(Reason::NotAPath),
                "{name}"
            );
        }
        assert_eq!(
            reason_of(&check("UV_PROJECT", "=ls", &rooted())),
            Some(Reason::Unreadable)
        );
    }

    /// Shell that sets a variable in bash or zsh — `{N}` the name, `{V}` the
    /// value. The review's forms, and the neighbours of each.
    const ASSIGNING_FORMS: &[&str] = &[
        // A keyword quoted, escaped or aliased.
        "\\export {N}={V}",
        "\"export\" {N}={V}",
        "'export' {N}={V}",
        "e''xport {N}={V}",
        "ex\"\"port {N}={V}",
        "alias ex=export\nex {N}={V}",
        // Constructs that span lines.
        ": '\n'; export {N}={V} #'",
        "ex\\\nport {N}={V}",
        "{N}=\\\n{V}",
        "export {N}=/var/mnt/scratch/example/cargo\n{N}_\\\n={V}",
        ": <<'EOF'\nEOF\nexport {N}={V}",
        "X=\"\nexport {N}={V}\n\"",
        // Commands that assign.
        "for {N} in {V}; do :; done",
        "select {N} in {V}; do break; done",
        "read -r {N} <<< {V}",
        "printf -v {N} {V}",
        "getopts : {N}",
        "{N}[1,-1]={V}",
        "{N}[1]={V}",
        ": ${{N}::={V}}",
        ": ${{N}:={V}}",
        ": ${{N}={V}}",
        "set -a\n: ${{N}:={V}}",
        "unset {N}\nexport {N}={V}",
        "export {N}\n{N}={V}",
        // Declaration builtins.
        "declare -x {N}={V}",
        "declare -gx {N}={V}",
        "typeset -x {N}={V}",
        "readonly {N}={V}",
        "local {N}={V}",
        "integer {N}={V}",
        "export -- {N}={V}",
        "export -x {N}={V}",
        "{N}+={V}",
        "export {N}+={V}",
        "{N}=({V})",
        // Evaluation with a literal payload.
        "eval \"export {N}={V}\"",
        "eval export {N}={V}",
        "source /dev/stdin <<< 'export {N}={V}'",
        ". /dev/stdin <<< 'export {N}={V}'",
        // Operators and prefixes.
        "true && export {N}={V}",
        "export {N}={V}; :",
        "builtin export {N}={V}",
        "command export {N}={V}",
        "export A=1 {N}={V}",
        "{N}={V} true",
        // Values a shell expands.
        "export {N}=$(printf %s {V})",
        "export {N}=`printf %s {V}`",
        "export {N}=\"$(printf %s {V})\"",
        "export {N}=${{N}:-{V}}",
        "export {N}=\"${{N}:={V}}\"",
        "export {N}={V}/$@/$@/../..",
        "export {N}=$'{V}'",
        "export {N}=\"{V}",
    ];

    #[test]
    fn no_form_known_to_assign_is_approved_whatever_its_name_or_value() {
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for form in ASSIGNING_FORMS {
            for name in ["CARGO_HOME", "EDITOR", "npm_config_cache", "X"] {
                for value in ["/var/mnt/scratch/example/cargo", "/etc/evil", "nvim"] {
                    let content = form.replace("{N}", name).replace("{V}", value);
                    for roots in [rooted(), home_rooted.clone(), RootSet::strict()] {
                        assert_ne!(scan_with(&content, &roots), vec![], "{content:?}");
                    }
                }
            }
        }
    }

    /// A shell the guard is held to, and how to make it report every variable
    /// it holds when it exits. The report runs from an exit trap, so it still
    /// reports after a fragment that stops the shell with an error. zsh also
    /// reports arrays, joined with `:`, because `NAME[1,-1]=value` on an unset
    /// name makes one — and so every element is judged as a list entry.
    struct Shell {
        program: &'static str,
        flags: &'static [&'static str],
        report: &'static str,
    }

    const SHELLS: &[Shell] = &[
        Shell {
            program: "bash",
            flags: &["--norc", "--noprofile"],
            report: "__bx_report() { local __bx_n; for __bx_n in $(compgen -v); do \
                     printf '%s=%s\\0' \"$__bx_n\" \"${!__bx_n}\"; done; }; trap __bx_report EXIT",
        },
        Shell {
            program: "zsh",
            flags: &["-f"],
            report: "__bx_report() { local __bx_n; for __bx_n in ${(k)parameters}; do \
                     [[ ${parameters[$__bx_n]} == (scalar|array)* ]] && \
                     printf '%s=%s\\0' \"$__bx_n\" \"${(j.:.)${(P)__bx_n}}\"; done; }; \
                     trap __bx_report EXIT",
        },
    ];

    /// The installed shell `program` resolves to, or `None` with a message.
    fn installed(program: &str) -> Option<PathBuf> {
        match crate::detect::locate_in_env(program) {
            crate::detect::Presence::Present { path } => Some(path),
            _ => {
                eprintln!("skipping the {program} check: {program} is not installed");
                None
            }
        }
    }

    /// Run `script` in `shell` with an empty environment and the test home,
    /// and return what it printed. Nothing in this process's environment is
    /// touched: the child's is built per command.
    ///
    /// Some of the fragments these tests run are deliberately broken shell,
    /// and a stray `>` in one is a redirection. So the child runs in a fresh
    /// temporary directory, where a relative redirection lands, and with a
    /// `PATH` that finds no program, so a word that becomes a command runs
    /// nothing.
    fn run_script(shell: &Path, flags: &[&str], script: &str) -> Vec<u8> {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        std::process::Command::new(shell)
            .args(flags)
            .arg("-c")
            .arg(script)
            .current_dir(scratch.path())
            .env_clear()
            .env("HOME", HOME)
            .env("PATH", "/nonexistent")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .expect("an installed shell runs")
            .stdout
    }

    /// Every scalar variable `shell` holds after running `content`.
    fn variables_after(shell: &Shell, path: &Path, content: &str) -> HashMap<String, String> {
        let script = format!("{}\n{content}", shell.report);
        run_script(path, shell.flags, &script)
            .split(|&byte| byte == 0)
            .filter_map(|entry| {
                let entry = String::from_utf8_lossy(entry);
                let (name, value) = entry.split_once('=')?;
                (!name.starts_with("__bx_")).then(|| (name.to_string(), value.to_string()))
            })
            .collect()
    }

    /// Each installed shell, with the variables it holds running nothing.
    ///
    /// None at all if the neutral root exists on this machine: a broken
    /// fragment could then redirect into it, and a test may not write outside
    /// a temporary directory.
    fn installed_shells() -> Vec<(&'static Shell, PathBuf, HashMap<String, String>)> {
        if Path::new(ROOT).exists() {
            eprintln!("skipping the shell checks: {ROOT} exists on this machine");
            return Vec::new();
        }
        SHELLS
            .iter()
            .filter_map(|shell| {
                let path = installed(shell.program)?;
                let baseline = variables_after(shell, &path, "");
                Some((shell, path, baseline))
            })
            .collect()
    }

    /// Run `content` in every installed shell and hold the guard to what each
    /// shell did. The guard must never approve a fragment after which a
    /// relocating variable holds a value with an entry outside `roots` or
    /// inside bx's own directory; and where the guard read every line, what it
    /// learned must be exactly what the shell set. Returns, per shell, whether
    /// the shell relocated anything outside the roots.
    fn assert_the_shells_agree(
        shells: &[(&'static Shell, PathBuf, HashMap<String, String>)],
        content: &str,
        roots: &RootSet,
    ) -> Vec<bool> {
        let (found, scope) = pass(content, roots);
        let mut escaped_in = Vec::new();
        for (shell, path, baseline) in shells {
            let after = variables_after(shell, path, content);
            let changed: Vec<(&String, &String)> = after
                .iter()
                .filter(|(name, value)| baseline.get(*name) != Some(*value))
                .collect();
            let escaped: Vec<_> = changed
                .iter()
                .filter(|(name, value)| {
                    is_relocating(name)
                        && value
                            .split(':')
                            .any(|entry| refuses_entry(Path::new(entry), roots).is_some())
                })
                .collect();
            assert!(
                escaped.is_empty() || !found.is_empty(),
                "{}: the guard approved {content:?}, after which {escaped:?}",
                shell.program
            );
            escaped_in.push(!escaped.is_empty());
            if scope.lost {
                continue;
            }
            for (name, value) in &changed {
                if SHELL_NAMES.contains(&name.as_str()) {
                    continue;
                }
                match scope.learned.get(*name) {
                    Some(Ok(learned)) => assert_eq!(
                        learned, *value,
                        "{}: {content:?} gives {name} a different value",
                        shell.program
                    ),
                    Some(Err(_)) => {}
                    None => panic!(
                        "{}: {content:?} sets {name}={value:?}, which the guard did not learn",
                        shell.program
                    ),
                }
            }
            for (name, learned) in &scope.learned {
                if let Ok(learned) = learned {
                    assert_eq!(
                        after.get(name),
                        Some(learned),
                        "{}: {content:?} does not give {name} what the guard learned",
                        shell.program
                    );
                }
            }
        }
        escaped_in
    }

    /// Fragments the grammar reads line for line, some approved and some
    /// judged a violation, whose learned values the shells must reproduce.
    const READABLE_FRAGMENTS: &[&str] = &[
        OPERATOR_FRAGMENT,
        "X=/var/mnt/scratch/example\nexport CARGO_HOME=${X}:h\nexport RUSTUP_HOME=\"${X}[1]\"\n",
        "export MAKEFLAGS=\"-j8 V=1\"\nexport GRADLE_USER_HOME=\"/var/mnt/scratch/example/a b=c/gradle\"\n",
        "X=/etc\nY='$X'\nexport CARGO_HOME=/var/mnt/scratch/example/$Y\n",
        "export CARGO_HOME=~/x\nexport RUSTUP_HOME=~\nexport GOPATH=\"~/x\"\nexport GOCACHE='~'\n",
        "export KUBECONFIG=/var/mnt/scratch/example/k:/etc/evil/config\n",
        "export EDITOR=nvim # a comment\n  \texport  PAGER=less\t# another\n\n# only a comment\n",
        "X=a,b@c%d+e-f.g:h\nY=\nZ=''\nW=\"\"\nexport V=$X$X\n",
        "X=/var/mnt/scratch/example\nX=$X/b\nexport CARGO_HOME=$X/cargo\n",
        "export PATH=\"$HOME/.local/bin:/usr/bin\"\n",
        "export XDG_STATE_HOME=~/.local/state/bx\n",
        "export npm_config_cache=/etc/evil\nexport TMPDIR=/tmp\n",
        "X=\"it's\"\nY='say \"hi\"'\nZ='a\\b'\nW='$(echo pwned)'\nV=\"{a,b} *\"\n",
        "X=${HOME}x\nY=\"$HOME\"\nZ=$HOME$HOME\nexport export=1\nexportX=2\n",
    ];

    #[test]
    fn the_shells_read_every_readable_fragment_as_the_guard_does() {
        let shells = installed_shells();
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for content in READABLE_FRAGMENTS {
            for roots in [rooted(), home_rooted.clone()] {
                assert!(!pass(content, &roots).1.lost, "{content:?}");
                assert_the_shells_agree(&shells, content, &roots);
            }
        }
    }

    #[test]
    fn every_review_falsifier_relocates_in_a_real_shell_and_is_refused() {
        let shells = installed_shells();
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for form in ASSIGNING_FORMS {
            let content = form
                .replace("{N}", "CARGO_HOME")
                .replace("{V}", "/etc/evil");
            assert_ne!(scan_with(&content, &rooted()), vec![], "{content:?}");
            assert_the_shells_agree(&shells, &content, &rooted());
        }
        // The review's own list, each run for real: every one but the alias
        // (neither shell expands an alias defined in the same `-c` string)
        // relocates outside the roots in at least one installed shell.
        let falsifiers = [
            ("\\export CARGO_HOME=/etc/evil", rooted()),
            ("\"export\" CARGO_HOME=/etc/evil", rooted()),
            ("e''xport CARGO_HOME=/etc/evil", rooted()),
            (": '\n'; export CARGO_HOME=/etc/evil #'", rooted()),
            ("ex\\\nport CARGO_HOME=/etc/evil", rooted()),
            (
                "export CARGO_HOME=/var/mnt/scratch/example/cargo\nCARGO_\\\nHOME=/etc/evil",
                rooted(),
            ),
            ("for CARGO_HOME in /etc/evil; do :; done", rooted()),
            ("read -r CARGO_HOME <<< /etc/evil", rooted()),
            ("printf -v CARGO_HOME /etc/evil", rooted()),
            ("CARGO_HOME[1,-1]=/etc/evil", rooted()),
            (": ${CARGO_HOME::=/etc/evil}", rooted()),
            ("set -a\n: ${CARGO_HOME:=/etc/evil}", rooted()),
            (
                "R=/var/mnt/scratch/example\nunset R\nexport CARGO_HOME=$R/etc/evil",
                rooted(),
            ),
            (
                "CARGO_HOME=/var/mnt/scratch/example/$@/$@/$@/$@/../../../../etc/evil",
                rooted(),
            ),
            ("HOME=/etc/evil\nCARGO_HOME=~/cargo", home_rooted.clone()),
            ("eval \"export CARGO_HOME=/etc/evil\"", rooted()),
            (
                "source /dev/stdin <<< 'export CARGO_HOME=/etc/evil'",
                rooted(),
            ),
            ("UV_PROJECT==ls", rooted()),
            (
                "KUBECONFIG=/var/mnt/scratch/example/k:/etc/evil/config",
                rooted(),
            ),
            ("GOPATH=/var/mnt/scratch/example/go:/etc/evil", rooted()),
            ("npm_config_cache=/etc/evil", rooted()),
            ("ZDOTDIR=/etc/evil", rooted()),
        ];
        for (content, roots) in &falsifiers {
            assert_ne!(scan_with(content, roots), vec![], "{content:?}");
            let escaped = assert_the_shells_agree(&shells, content, roots);
            if shells.len() == SHELLS.len() {
                assert!(
                    escaped.contains(&true),
                    "{content:?} relocated nothing in any shell"
                );
            }
        }
    }

    /// Every variant of `base` with one of the characters or sequences a shell
    /// treats specially inserted at each of a few positions on its last line.
    fn variants(base: &str) -> Vec<String> {
        const INSERTS: &[&str] = &[
            "\\",
            "'",
            "\"",
            "`",
            "$",
            "$@",
            "$1",
            "${",
            "}",
            "(",
            ")",
            "{",
            "[1]",
            ":h",
            "<",
            ">",
            "|",
            "&",
            ";",
            "*",
            "?",
            "!",
            "#",
            " #",
            "~",
            ":~/",
            "=",
            "==",
            ":=",
            "^",
            " ",
            "\t",
            "\n",
            "\\\n",
            "\r",
            "..",
            "/../../../..",
            "$(printf /etc)",
        ];
        let last = base.rfind('\n').map_or(0, |at| at + 1);
        let equals = last + base[last..].find('=').expect("an assignment");
        let mut positions = vec![
            last,
            equals,
            equals + 1,
            equals + 2,
            base.len() - 3,
            base.len(),
        ];
        if base[last..].starts_with("export ") {
            positions.extend([last + 6, last + 7]);
        }
        let mut out = Vec::new();
        for at in positions {
            for insert in INSERTS {
                out.push(format!("{}{insert}{}", &base[..at], &base[at..]));
            }
        }
        out
    }

    #[test]
    fn no_single_special_character_makes_the_guard_approve_what_a_shell_reads_otherwise() {
        let shells = installed_shells();
        for base in [
            "export CARGO_HOME=/var/mnt/scratch/example/cargo",
            "R=/var/mnt/scratch/example\nexport CARGO_HOME=\"$R/cargo\"",
            "X=/var/mnt/scratch/example\nGOPATH=${X}/go:$X/b",
        ] {
            assert_eq!(scan_with(base, &rooted()), vec![], "{base:?}");
            for content in variants(base) {
                assert_the_shells_agree(&shells, &content, &rooted());
            }
        }
    }

    #[test]
    fn the_shells_define_no_name_a_fragment_may_assign_except_path() {
        for (program, flags, list) in [
            ("bash", &["--norc", "--noprofile"][..], "compgen -v"),
            (
                "zsh",
                &["-f"][..],
                "for __bx_m in $module_path[1]/zsh/**/*.so(N); do \
                 __bx_n=${__bx_m#$module_path[1]/}; zmodload ${__bx_n%.so} >/dev/null 2>&1; \
                 done; print -l ${(k)parameters}",
            ),
        ] {
            let Some(path) = installed(program) else {
                continue;
            };
            let listed = run_script(&path, flags, list);
            let unreserved: Vec<String> = String::from_utf8_lossy(&listed)
                .lines()
                .filter(|name| is_variable_name(name) && !name.starts_with("__bx_"))
                .filter(|name| *name != "PATH" && !SHELL_NAMES.contains(name))
                .map(str::to_string)
                .collect();
            assert_eq!(unreserved, Vec::<String>::new(), "{program}");
        }
    }
}
