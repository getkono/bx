//! The one rule that keeps bx from breaking the tools it manages.
//!
//! bx *may* write an environment variable that is a tool's own documented
//! configuration interface, but only a variable in bx's emit table, which grows
//! with the generators that need it — `SCCACHE_CACHE_SIZE` and `RUSTC_WRAPPER`
//! are the motivating cases, since sccache is configured entirely by environment.
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
//! **A fragment may set only a variable bx knows how to judge.** [`EMITTABLE`]
//! is the table of every name bx may generate, and it says what each one holds
//! — a [`Kind`]: a location, a list of locations, an anchor, a program, a
//! search list, a socket, or a setting.
//! The value is judged for what the name holds. Every name the table does not
//! list is refused as [`Reason::NotEmittable`], whatever its value.
//!
//! The name space is closed on purpose. A value alone cannot say what it is:
//! `EDITOR=nvim` names a program found through `PATH`, and `GIT_DIR=evil` names
//! a directory relative to wherever the shell happens to be. And the set of
//! variables some tool reads as a location is open-ended: every earlier guard
//! that judged by a list of location names, or by whether a value looked like
//! a path, approved a tool it had not heard of. The guard judges only what bx
//! generates, so the table grows with the generators and with nothing else.
//! [`check`] is the verdict. Declare no root — [`RootSet::strict`], which is
//! what [`scan`] uses — and no location may be set at all.
//!
//! The guard **fails closed by shape** as well. It does not model shell syntax
//! and approve whatever it does not recognise: it reads a fragment against a
//! small grammar — blank lines, comments, and `NAME=VALUE` or
//! `export NAME=VALUE` with a restricted value — and refuses **every** line that
//! is not one of those, whatever the line mentions and whether or not it
//! relocates anything. A multi-line construct is refused at its first line,
//! because no line the grammar accepts can leave a quote, a continuation or a
//! heredoc open. [`scan_with`] states the grammar.
//!
//! This module is that rule as code. Every environment fragment bx generates is
//! run through [`scan_with`] before it is written, and the check is covered by
//! tests rather than left to review. The shell-init snippet is not one: it is
//! fixed text from bx's source that sets only `BX_`-prefixed names, and sets
//! every other variable by sourcing a guarded environment fragment.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::config::layers;
use crate::config::values::ResolvedValues;
use crate::paths;

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
/// That probe finds names a shell *defines*. It cannot find a name the shell
/// *acts on* when it is assigned and that reads back exactly as written —
/// `HISTFILESIZE=0` is one — so those are curated by hand in
/// [`ACTS_ON_ASSIGNMENT`], and refused the same way.
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

/// Names whose **assignment** a shell acts on, beyond holding the value, or
/// whose value a shell it starts runs.
///
/// None of these is defined by a pristine shell and each reads back exactly as
/// written, so the probe behind [`SHELL_NAMES`] cannot find them. The list is
/// curated from bash(1) and zshparam(1), and is only as complete as that
/// reading — which is why a fragment is refused rather than judged when it
/// assigns one:
///
/// * `HISTFILESIZE` — bash truncates the history file to that many lines the
///   moment it is assigned, non-interactive shells included, so
///   `HISTFILESIZE=0` deletes the user's history (invariant 1).
/// * `POSIXLY_CORRECT`, `BASH_COMPAT` — bash changes how every later line
///   parses.
/// * `GLOBIGNORE` — bash turns `dotglob` on when it is set.
/// * `EXECIGNORE` — bash stops running any program whose path matches it.
/// * `BASH_XTRACEFD` — bash closes the descriptor it held when it changes.
/// * `PROMPT_COMMAND`, `PS0` — bash runs, or expands with command
///   substitution, the value at every prompt.
/// * `RPROMPT`, `RPS1`, `RPROMPT2`, `RPS2` — zsh's right-hand prompts, which it
///   expands at every prompt, command substitution included under
///   `PROMPT_SUBST`, as it does `PS1`.
/// * `BASH_ENV`, `ENV` — a non-interactive bash, and an interactive `sh`,
///   source the file named there when they start.
/// * `precmd_functions`, `preexec_functions`, `chpwd_functions`,
///   `periodic_functions`, `zshaddhistory_functions`, `zshexit_functions` — zsh
///   calls every function named in the value at its hook.
///
/// `HISTSIZE` and `SAVEHIST` are reserved already, as [`SHELL_NAMES`].
///
/// `LANG` and `LC_*` change the shell's locale on assignment and are not here:
/// the grammar admits printable ASCII only, whose meaning no locale changes,
/// and a fragment setting a locale is ordinary.
const ACTS_ON_ASSIGNMENT: &[&str] = &[
    "BASH_COMPAT",
    "BASH_ENV",
    "BASH_XTRACEFD",
    "ENV",
    "EXECIGNORE",
    "GLOBIGNORE",
    "HISTFILESIZE",
    "POSIXLY_CORRECT",
    "PROMPT_COMMAND",
    "PS0",
    "RPROMPT",
    "RPROMPT2",
    "RPS1",
    "RPS2",
    "chpwd_functions",
    "periodic_functions",
    "precmd_functions",
    "preexec_functions",
    "zshaddhistory_functions",
    "zshexit_functions",
];

/// Whether a fragment may neither assign nor refer to `name`.
fn is_reserved(name: &str) -> bool {
    SHELL_NAMES.contains(&name) || ACTS_ON_ASSIGNMENT.contains(&name)
}

/// What a variable in [`EMITTABLE`] holds, and therefore how its value is
/// judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Where a tool keeps its config, data or cache: one path. The tool reads the whole
    /// value, `:` and all, so the whole value must be an absolute path — `~`
    /// and `$HOME` expand to one — strictly beneath a declared root, never a
    /// root itself, and outside bx's own directories. A tool may derive a
    /// directory beside its own, as uv puts executables in
    /// `$XDG_DATA_HOME/../bin`, so at a root that directory is outside every
    /// root. A bare word, a relative path and a URL are all relative to
    /// wherever the shell happens to be, and are refused. Every `:`-separated
    /// entry is held to the same checks first, which costs only a path with a
    /// `:` in it. Every character is an ASCII letter or digit, `.`, `_`, `-`,
    /// `+` or `/`, with `:` only between entries.
    Location,
    /// A list of locations its tool splits at `:` and reads entry by entry —
    /// `GOPATH`. Every entry is judged as a [`Kind::Location`] is, and the
    /// whole string, which no tool reads as one path, is not.
    LocationList,
    /// A directory other assignments are written in terms of, and that no tool
    /// reads — the operator fragment's `SCRATCH_HOME`, `CACHE_DIR` and
    /// `DATA_DIR`. It is one path held to every check a [`Kind::Location`]'s
    /// path is, but one: it may contain bx's own directories. No tool clears
    /// an anchor, and every tool-read location written in terms of one is
    /// judged at its own line, containment included. So a home that is the
    /// scratch root, or lies under it, is still an anchor's to name.
    Anchor,
    /// A program a tool runs, found by name or by path: exactly one word,
    /// either an absolute path outside bx's own directories or a bare command
    /// name — a letter or digit, then letters, digits, `.`, `_`, `+` and `-`.
    /// No blank, so no argument: tools run the value through a shell, and an
    /// argument is a second path, or a second assignment, that no check reads.
    /// No `:`, `=`, `~` or URL either. Needs no root.
    Program,
    /// A list a shell or a tool searches. Every entry absolute, non-empty and
    /// outside bx's own directories, whatever its shape, because an empty
    /// entry or `.` *is* the current directory. A reference to the list's own
    /// name that the fragment has not assigned — the `$PATH` in
    /// `PATH="$HOME/.local/bin:$PATH"` — stands for the list the shell
    /// inherited, which is the user's and is not judged, but only as a whole
    /// entry: `$PATH/bin` is relative to nothing bx can know. Each entry holds
    /// only the characters a location's entries do. Needs no root.
    SearchList,
    /// The socket of an agent that is already running: an absolute path
    /// outside bx's own directories, of the characters a location's entries
    /// hold and no `:`. It says where to reach a process, not where a tool
    /// keeps anything, so it needs no root.
    Socket,
    /// A behaviour setting, which names no file at all.
    Setting(Setting),
}

/// The values a [`Kind::Setting`] accepts, each the shape its tool reads. None
/// of them can hold a `/`, a `~`, a `:`, a blank, a URL, or `.` or `..`, so no
/// setting names a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setting {
    /// `0`, `1`, `true` or `false`, and no other word.
    Switch,
    /// A count of things: a decimal from 1 to 1024, with no leading zero.
    Count,
    /// A size: one to six digits with no leading zero, then exactly one of
    /// `K`, `M`, `G` or `T`.
    Size,
    /// Exactly one of the listed words, as its tool spells them.
    OneOf(&'static [&'static str]),
    /// A locale name: one bare word — a letter or digit, then letters, digits,
    /// `.`, `_`, `+` and `-`.
    Locale,
}

impl Setting {
    /// Whether this setting accepts `value`.
    fn admits(self, value: &str) -> bool {
        match self {
            Self::Switch => matches!(value, "0" | "1" | "true" | "false"),
            Self::Count => {
                is_decimal(value, 4) && value.parse::<u16>().is_ok_and(|count| count <= 1024)
            }
            Self::Size => value
                .strip_suffix(['K', 'M', 'G', 'T'])
                .is_some_and(|digits| is_decimal(digits, 6)),
            Self::OneOf(words) => words.contains(&value),
            Self::Locale => is_bare_word(value),
        }
    }
}

/// Whether `text` is a decimal of one to `digits` digits with no leading zero.
fn is_decimal(text: &str, digits: usize) -> bool {
    (1..=digits).contains(&text.len())
        && !text.starts_with('0')
        && text.chars().all(|c| c.is_ascii_digit())
}

/// Every variable name bx may generate, in byte order, with what it holds.
///
/// **This table is the guard's whole name space**: a name it does not list is
/// [`Reason::NotEmittable`], whatever it is given. It must grow with the
/// generators, one name at a time, each with the kind its tool documents —
/// and a name whose tool reads it as a command line (`MAKEFLAGS`, `RUSTFLAGS`,
/// `LESS`) or as either a word or a path (`CARGO_BUILD_TARGET` takes a
/// `.json` target file) needs a kind that can judge that before it is added.
///
/// * `XDG_CACHE_HOME` and `XDG_DATA_HOME`, and the 23 relocating exports of
///   the operator fragment the module's tests hold the guard to:
///   `SCRATCH_HOME`, the anchor the fragment is written in terms of, and 22
///   toolchain caches and homes, of which `GOPATH` is a list of locations.
///   `CACHE_DIR` and `DATA_DIR` are that fragment's two unexported helpers,
///   also anchors, and `SCCACHE_DIR` is sccache's cache, the module's
///   motivating case.
/// * `EDITOR`, `VISUAL`, `PAGER`, `BROWSER`, `TERMINAL` — the program a tool
///   runs to edit, page, browse or open a terminal — and `RUSTC_WRAPPER`, the
///   program cargo runs `rustc` through.
/// * `PATH` and `INFOPATH`, searched for programs and documents.
/// * `SSH_AUTH_SOCK`, the running ssh agent.
/// * `SCCACHE_CACHE_SIZE` (a size), `MISE_JOBS` (a count), `UV_NO_CACHE` and
///   `MISE_VERBOSE` (switches), `CARGO_TERM_COLOR` (`auto`, `always` or
///   `never`) and `LANG` (a locale).
///
/// `SHELL`, `MANPATH` and `HOME` would belong here and do not: each is a
/// [`SHELL_NAMES`] entry, which may not be assigned at all.
///
/// `XDG_STATE_HOME` and `XDG_CONFIG_HOME` do not belong here either. bx reads
/// them to find its own state directory and config repo, so a fragment that
/// set either would move them on bx's next run and leave the ledger, the
/// journal and `local.toml` behind (invariants 3 and 4).
const EMITTABLE: &[(&str, Kind)] = &[
    ("ANDROID_HOME", Kind::Location),
    ("ANDROID_USER_HOME", Kind::Location),
    ("BROWSER", Kind::Program),
    ("BUN_INSTALL", Kind::Location),
    ("BUN_INSTALL_CACHE_DIR", Kind::Location),
    ("CACHE_DIR", Kind::Anchor),
    ("CARGO_HOME", Kind::Location),
    (
        "CARGO_TERM_COLOR",
        Kind::Setting(Setting::OneOf(&["auto", "always", "never"])),
    ),
    ("DATA_DIR", Kind::Anchor),
    ("DOTNET_CLI_HOME", Kind::Location),
    ("EDITOR", Kind::Program),
    ("GOCACHE", Kind::Location),
    ("GOMODCACHE", Kind::Location),
    ("GOPATH", Kind::LocationList),
    ("HOMEBREW_CACHE", Kind::Location),
    ("HOMEBREW_LOGS", Kind::Location),
    ("HOMEBREW_TEMP", Kind::Location),
    ("INFOPATH", Kind::SearchList),
    ("LANG", Kind::Setting(Setting::Locale)),
    ("MISE_CACHE_DIR", Kind::Location),
    ("MISE_DATA_DIR", Kind::Location),
    ("MISE_JOBS", Kind::Setting(Setting::Count)),
    ("MISE_VERBOSE", Kind::Setting(Setting::Switch)),
    ("NPM_CONFIG_CACHE", Kind::Location),
    ("NUGET_HTTP_CACHE_PATH", Kind::Location),
    ("NUGET_PACKAGES", Kind::Location),
    ("PAGER", Kind::Program),
    ("PATH", Kind::SearchList),
    ("PIP_CACHE_DIR", Kind::Location),
    ("PNPM_CONFIG_STORE_DIR", Kind::Location),
    ("RUSTC_WRAPPER", Kind::Program),
    ("RUSTUP_HOME", Kind::Location),
    ("SCCACHE_CACHE_SIZE", Kind::Setting(Setting::Size)),
    ("SCCACHE_DIR", Kind::Location),
    ("SCRATCH_HOME", Kind::Anchor),
    ("SSH_AUTH_SOCK", Kind::Socket),
    ("TERMINAL", Kind::Program),
    ("UV_CACHE_DIR", Kind::Location),
    ("UV_NO_CACHE", Kind::Setting(Setting::Switch)),
    ("VISUAL", Kind::Program),
    ("XDG_CACHE_HOME", Kind::Location),
    ("XDG_DATA_HOME", Kind::Location),
    ("ZIG_GLOBAL_CACHE_DIR", Kind::Location),
];

/// What `name` holds, if bx may generate it at all.
///
/// The match is exact and case-sensitive, because environment variable names
/// are: a tool that reads `CARGO_HOME` does not read `cargo_home`, and a name
/// the table does not spell is not in it.
fn emittable(name: &str) -> Option<Kind> {
    EMITTABLE
        .iter()
        .find(|(listed, _)| *listed == name)
        .map(|(_, kind)| *kind)
}

/// What an unassigned reference to a search list's own name expands to while
/// the list is judged. No accepted value holds a control character, so no
/// entry a fragment writes can equal it.
const INHERITED: &str = "\0";

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
/// And it carries bx's config repo, which bx does not own — it is the user's
/// committed tree — but which no tool may be pointed into either, for the same
/// unconditional reason. See [`RootSet::with_config_repos`].
///
/// Containment is decided **lexically**, never by touching the filesystem.
/// `canonicalize` would make the verdict depend on what exists and on what is
/// mounted, so the same `plan` would differ between two machines and between
/// two runs on one — which invariant 3 forbids. The price is that lexical `..`
/// normalisation is unsound across a symlink: `<root>/link/../x`, where `link`
/// points outside the root, is judged inside it, and so is a declared root that
/// is itself a symlink to `/`. That is accepted rather than fixed, because the
/// only fix is the one invariant 3 rules out — and a value bx may write never
/// has a `..` component at all ([`Reason::ParentComponent`]), so the unsound
/// case is left to the declared roots themselves.
///
/// Containment in a root is **one-directional**: a value inside a root is
/// admitted, whatever lies beneath it. A root contains itself, but a location
/// may not be a root itself ([`Reason::DeclaredRootItself`]), because its tool
/// may write beside it. bx's own directories are the exception,
/// and are judged **both ways**: a location may neither lie inside one nor
/// contain one ([`Reason::ContainsBxDirectory`]), because a tool clears its
/// own directory — `uv cache clean` on `UV_CACHE_DIR=~/.local/state` deletes
/// bx's ledger with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSet {
    home: Option<PathBuf>,
    roots: Vec<PathBuf>,
    inadmissible: Vec<PathBuf>,
    owned: Vec<PathBuf>,
    repos: Vec<PathBuf>,
}

impl RootSet {
    /// The set that declares nothing, and therefore permits no relocation.
    ///
    /// This is what [`scan`] uses, and it needs no home: with no root declared
    /// every location is a violation before it is compared with anything. A
    /// program, a search list or a socket needs no root, and without a home
    /// the set cannot say where bx's state directory is — so it owns every
    /// directory that could be it. See [`RootSet::owns`].
    #[must_use]
    pub fn strict() -> Self {
        Self {
            home: None,
            roots: Vec::new(),
            inadmissible: Vec::new(),
            owned: Vec::new(),
            repos: Vec::new(),
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
        let repos = vec![paths::normalize(&paths::config_root_in(&home, None))];
        Self {
            home: Some(home),
            roots: admitted,
            inadmissible,
            owned,
            repos,
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

    /// The same set, additionally treating each of `dirs` as bx's config repo.
    ///
    /// The twin of [`RootSet::owning`]: [`RootSet::new`] puts the repo where
    /// the home puts it, `~/.config/bx`, and a caller that has read an
    /// environment's `XDG_CONFIG_HOME` passes the repo it found here. Adding,
    /// never replacing.
    #[must_use]
    pub fn with_config_repos(mut self, dirs: &[PathBuf]) -> Self {
        self.repos
            .extend(dirs.iter().map(|dir| paths::normalize(dir)));
        self
    }

    /// Whether `path` is bx's config repo, or lies inside it.
    ///
    /// The repo is committed, and safe to make public: a tool that writes
    /// there may commit what it writes, credentials included (invariant 5),
    /// and a program or a search-list entry there runs whatever was committed.
    /// A set without a home treats every `.config/bx` as a repo, as
    /// [`RootSet::owns`] does every default state directory.
    fn in_config_repo(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.repos.iter().any(|dir| normalised.starts_with(dir))
            || (self.home.is_none() && passes_through(&normalised, &[".config", "bx"]))
    }

    /// Whether `path` contains, or is, a directory bx owns or a config repo.
    fn holds_bx_directory(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.owned
            .iter()
            .chain(&self.repos)
            .any(|dir| dir.starts_with(&normalised))
    }

    /// Whether `path` is a directory bx owns, or lies inside one.
    ///
    /// bx's state directory holds the ledger, the fingerprints and the journal:
    /// the record that makes invariant 4 true. A tool pointed into it writes
    /// among those files, and `bx rm` would then restore a home by deleting a
    /// directory another tool believes is its own. So this is checked **before**
    /// containment and outranks it — a user may declare their home a root, and
    /// `CARGO_HOME=~/.local/state/bx` is still refused.
    ///
    /// A set without a home — [`RootSet::strict`] — cannot show that a path is
    /// *not* bx's state directory, whose default place is under the home. So it
    /// owns every path that passes through `.local/state/bx`, whoever's home
    /// that is. A set with a home knows where its state directory is, and owns
    /// only that and what [`RootSet::owning`] adds.
    #[must_use]
    pub fn owns(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.owned.iter().any(|dir| normalised.starts_with(dir))
            || (self.home.is_none() && passes_through(&normalised, &[".local", "state", "bx"]))
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

/// Whether a normalised `path` has `parts` as consecutive components — so
/// `.local`, `state`, `bx` is the default state directory under some home.
fn passes_through(path: &Path, parts: &[&str]) -> bool {
    let wanted: Vec<Component<'_>> = parts
        .iter()
        .map(|part| Component::Normal(OsStr::new(part)))
        .collect();
    path.components()
        .collect::<Vec<_>>()
        .windows(wanted.len())
        .any(|window| window == wanted.as_slice())
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

/// Why an assignment was rejected.
///
/// Each names a different user action — declare a root, fix the declared root,
/// split the line, write the line in the grammar the guard reads, use a name
/// the shell does not manage, use a name bx may generate, move the value out of
/// bx's own directory, move it out of bx's config repo, point it beside bx's
/// directories rather than around them, write a path of plain characters with
/// no `..`, move it inside a declared root, point it beneath a declared root
/// rather than at one, write an absolute path,
/// give a program no arguments, give a setting a value it accepts, define the
/// referenced variable earlier, give the guard a home, fix the line
/// that assigned it, shorten it — so a caller that only knew *which* variable
/// was rejected could not say what to do about it. The messages name no data:
/// the caller already holds the value and the root set, and prints them itself.
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
    /// `RANDOM`, zsh's tied `path` — or acts on when it is assigned.
    #[error("assigns or refers to a name the shell manages itself")]
    ReservedName,
    /// It assigns a variable no bx generator declares, whatever the value: the
    /// guard cannot tell what a name it does not know holds. bx generates every
    /// fragment the guard judges, so this is a defect in bx — a generator that
    /// did not add its name to the emit table — and not in the user's
    /// configuration.
    #[error(
        "assigns a variable no bx generator declares, so bx cannot judge the \
         value — a defect in bx, not in your configuration"
    )]
    NotEmittable,
    /// It points at a directory bx owns, whatever the roots say.
    #[error("points inside a directory bx owns")]
    BxOwnedDirectory,
    /// It points inside bx's config repo — a committed tree, safe to make
    /// public — whatever the roots say.
    #[error("points inside bx's config repo, which is committed and may be public")]
    InsideConfigRepo,
    /// A location that contains bx's state directory or its config repo. The
    /// tool it is given to clears it — a cache clean, a prune — and deletes
    /// bx's record, or the user's repo, along with its own files.
    #[error("contains bx's state directory or its config repo, which the tool may clear")]
    ContainsBxDirectory,
    /// It resolves to a path, but not one inside any declared root.
    #[error("resolves outside every declared root")]
    OutsideDeclaredRoots,
    /// A location, or an entry of a list of locations, that is a declared root
    /// itself rather than a path beneath one. A tool may derive a directory
    /// beside its own: uv puts executables in `$XDG_DATA_HOME/../bin`, and so
    /// does every tool built on dirs-next, which lands outside every root when
    /// the value is one. A tool given a whole root also clears everything else
    /// the root holds. Point the value beneath the root.
    #[error("is a declared root itself, and its tool may write beside it, outside every root")]
    DeclaredRootItself,
    /// Empty, a bare word, a URL, or a relative path, where a path that can be
    /// shown to be somewhere is needed. For a list, one of its entries is.
    #[error("is not an absolute path")]
    NotAbsolute,
    /// A path with a `..` component, in any kind that holds one. It can climb
    /// out of where it appears to point — across a symlink, or past text a
    /// tool expands before it resolves the path — and nothing bx generates
    /// needs one.
    #[error("has a `..` component, so where it points cannot be shown")]
    ParentComponent,
    /// A path — a location, an entry of a list, a socket — holding a character
    /// other than those every path bx writes is made of: ASCII letters and
    /// digits, `.`, `_`, `-`, `+` and `/`, and `:` only between the entries of
    /// a list. Tools read other characters their own way — npm and pnpm expand
    /// `${NAME}`, NuGet `%NAME%`, and bun takes `\` for a separator — into a
    /// path nothing judged, and nothing bx generates needs one. It names the
    /// first such character.
    #[error("holds {0:?}, a character no path bx writes may hold")]
    UnlistedCharacter(char),
    /// A program given something other than exactly one absolute path or one
    /// bare command name: an argument, a `:` list, a URL, nothing at all.
    #[error("is not one program — an absolute path or a bare command name, with no arguments")]
    NotAProgram,
    /// A setting given a value it does not accept.
    #[error("is not a value this setting accepts")]
    NotASetting,
    /// It names a variable this fragment has not assigned by this line.
    #[error("refers to a variable this fragment has not assigned")]
    UnresolvedReference,
    /// It refers to the home — `~`, `$HOME` — and the guard was given no home
    /// to expand it against, as [`scan`] is not.
    #[error("refers to the home directory, and the guard was given none")]
    NoHome,
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
/// Past that, `name` must be one bx generates, and the value is judged for what
/// that name holds, as [`scan_with`] states.
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
/// and the rest of `SHELL_NAMES` — or acts on when it is assigned —
/// `HISTFILESIZE` and the rest of [`ACTS_ON_ASSIGNMENT`] — may be neither
/// assigned nor referred to, and is refused as [`Reason::ReservedName`].
///
/// **What is judged.** Every accepted assignment, exported or not, since
/// assigning a name the environment already exports changes what every child
/// sees. A name [`EMITTABLE`] does not list is [`Reason::NotEmittable`]. For
/// one it lists, the value as a shell gives it is judged for the [`Kind`] the
/// table records:
///
/// * a **location** needs a declared root, and every `:`-entry, and then the
///   whole value read as one path, must be absolute, outside bx's own
///   directories and strictly beneath a root, never a root itself
///   ([`Reason::DeclaredRootItself`]);
/// * a **list of locations** is judged the same way entry by entry, and not
///   as a whole;
/// * an **anchor** is judged as a location's one path, except that it may
///   contain bx's own directories and may be a root;
/// * a **program** is one absolute path outside bx's own directories, or one
///   bare command name;
/// * a **search list** has every entry absolute and outside bx's own
///   directories, its inherited self standing in for itself;
/// * a **socket** is an absolute path outside bx's own directories;
/// * a **setting** holds a value of its [`Setting`] shape.
///
/// No path of any kind may have a `..` component ([`Reason::ParentComponent`]),
/// hold a character other than an ASCII letter or digit, `.`, `_`, `-`, `+`
/// and `/` — with `:` only between a list's entries —
/// ([`Reason::UnlistedCharacter`]), or lie inside bx's state directory
/// ([`Reason::BxOwnedDirectory`]) or its config repo
/// ([`Reason::InsideConfigRepo`]), checked in that order and before any root.
/// No location or list of locations may contain either of bx's directories
/// ([`Reason::ContainsBxDirectory`]), or be a root itself
/// ([`Reason::DeclaredRootItself`]); an anchor may. The characters are an allowlist because
/// the guard cannot know which tool reads which other character its own way.
/// A value that does not resolve cannot be shown to be any of those, and is
/// refused for why it does not.
///
/// **What is learned.** Every accepted assignment — exported or not, emittable
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
/// **Where bx's directories are.** Where the root set says, and nowhere a
/// fragment could move them: `XDG_STATE_HOME` and `XDG_CONFIG_HOME`, which bx
/// reads to find them, are not in the emit table, so a fragment that sets
/// either is refused.
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
/// declared, every location is a violation, and a program, a search list or a
/// socket may not pass through a default state directory under any home. This
/// is the check for a caller that has no configuration to consult, and it is
/// why it needs no home.
#[must_use]
pub fn scan(content: &str) -> Vec<Violation> {
    scan_with(content, &RootSet::strict())
}

/// [`scan_with`]'s verdict, and what the fragment was learned to assign: one
/// walk over `content`, judging each line against `roots` and what the lines
/// before it assigned, and learning from it.
fn pass(content: &str, roots: &RootSet) -> (Vec<Violation>, Scope) {
    let mut scope = Scope::default();
    let mut found = Vec::new();
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
    /// For a search list, the value with each unassigned reference to its own
    /// name standing for the inherited list. This is what the list's next
    /// reference to itself extends, and `None` for every other kind.
    extended: Option<String>,
}

/// The verdict on `name = value`, for [`check`] and [`scan_with`] alike.
fn evaluate(name: &str, value: &str, scope: &Scope, roots: &RootSet) -> Judged {
    let refused = |reason| Judged {
        reason: Some(reason),
        resolved: Err(reason),
        extended: None,
    };
    // The shape is read for every variable: a line the grammar does not read
    // may do anything, whatever its first name is.
    if !is_variable_name(name) {
        return refused(Reason::Unreadable);
    }
    let word = match read_value(value) {
        Ok(word) => word,
        Err(reason) => return refused(reason),
    };
    if is_reserved(name) {
        return refused(Reason::ReservedName);
    }
    let resolved = word.resolve(scope, roots.home());
    let kind = emittable(name);
    // A search list is judged with its own inherited self standing in for
    // itself, which no other name's reference to it may do.
    let extended =
        (kind == Some(Kind::SearchList)).then(|| word.expand(scope, roots.home(), Some(name)));
    let reason = match kind {
        None => Some(Reason::NotEmittable),
        Some(kind) => judge(kind, extended.as_ref().unwrap_or(&resolved), roots),
    };
    Judged {
        reason,
        resolved,
        extended: extended.and_then(Result::ok),
    }
}

/// Why `resolved` may not be given to a variable of `kind`, or `None` if it
/// may. For a search list, `resolved` holds [`INHERITED`] wherever the list
/// refers to what the shell inherited.
fn judge(kind: Kind, resolved: &Result<String, Reason>, roots: &RootSet) -> Option<Reason> {
    let anchored = |entry: &str| refuses_unanchored(entry, None, roots);
    match kind {
        Kind::SearchList => within(resolved, |list| {
            list.split(':')
                .filter(|entry| *entry != INHERITED)
                .find_map(anchored)
        }),
        // A set with no admissible root permits no location, whatever it is.
        Kind::Location | Kind::LocationList => roots.refuses_everything().or_else(|| {
            within(resolved, |value| {
                let entries = value
                    .split(':')
                    .find_map(|entry| refuses_entry(entry, None, roots));
                // A location's tool reads the whole value as one path, whose
                // `:` its entries were judged apart at. Every entry has passed
                // by now, so this cannot newly refuse: the whole value begins
                // with its first absolute entry, holds only allowed characters
                // and `:`, and merging entries at a `:` makes a component
                // holding `:`, which no directory bx owns or roots names, so it
                // cannot complete a match with one that no entry already made.
                // And the first entry lies strictly beneath a root, so the
                // whole value's parent begins with that entry's parent, which
                // is inside the root. It is judged anyway, as the one path the
                // tool reads, so that stays true if an entry's rule changes.
                entries.or_else(|| {
                    (kind == Kind::Location)
                        .then(|| refuses_entry(value, Some(':'), roots))
                        .flatten()
                })
            })
        }),
        // An anchor is one directory that no tool reads, so none clears it.
        Kind::Anchor => roots
            .refuses_everything()
            .or_else(|| within(resolved, |value| refuses_anchor(value, roots))),
        Kind::Program => within(resolved, |value| refuses_program(value, roots)),
        Kind::Socket => within(resolved, anchored),
        Kind::Setting(setting) => within(resolved, |value| {
            (!setting.admits(value)).then_some(Reason::NotASetting)
        }),
    }
}

/// `judge` applied to a value that resolved, or why it did not.
fn within(
    resolved: &Result<String, Reason>,
    judge: impl FnOnce(&str) -> Option<Reason>,
) -> Option<Reason> {
    match resolved {
        Ok(value) => judge(value),
        Err(reason) => Some(*reason),
    }
}

/// Why `value` is not one program bx may name, or `None` if it is.
///
/// A value with a `/` in it and nothing but word characters beside is a path,
/// which must be absolute and outside bx's own directories. Anything else must
/// be a bare command name.
fn refuses_program(value: &str, roots: &RootSet) -> Option<Reason> {
    if value.contains('/') && value.chars().all(|c| c == '/' || is_word_char(c)) {
        refuses_unanchored(value, None, roots)
    } else if is_bare_word(value) {
        None
    } else {
        Some(Reason::NotAProgram)
    }
}

/// A character of a bare word: an ASCII letter or digit, `.`, `_`, `+` or `-`.
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._+-".contains(c)
}

/// Whether `value` is one bare word: a letter or digit, then word characters.
/// So never empty, never `.` or `..`, never an option, never a path.
fn is_bare_word(value: &str) -> bool {
    value.starts_with(|c: char| c.is_ascii_alphanumeric()) && value.chars().all(is_word_char)
}

/// Why one resolved path — a value, or one entry of a list — may not be a
/// relocation target, or `None` if it may. `separator` is the list separator
/// it may still hold, as [`refuses_unanchored`] reads it.
///
/// The order is part of the verdict. [`refuses_unanchored`] runs first, so a
/// path that is relative, climbs, or holds a character outside the allowlist
/// is refused for that before any reasoning about where it is: bx cannot read
/// such a value as a path at all. Inside bx's own directories comes next, then
/// containing them, then the roots: inside one, then beneath one.
fn refuses_entry(path: &str, separator: Option<char>, roots: &RootSet) -> Option<Reason> {
    refuses_unanchored(path, separator, roots)
        // bx's directories outrank the roots in this direction too.
        .or_else(|| {
            roots
                .holds_bx_directory(Path::new(path))
                .then_some(Reason::ContainsBxDirectory)
        })
        .or_else(|| (!roots.contains(Path::new(path))).then_some(Reason::OutsideDeclaredRoots))
        // Inside a root, but with a parent in none: the path is a root itself.
        .or_else(|| {
            (!paths::normalize(Path::new(path))
                .parent()
                .is_some_and(|parent| roots.contains(parent)))
            .then_some(Reason::DeclaredRootItself)
        })
}

/// Why a resolved [`Kind::Anchor`] may not be written, or `None` if it may:
/// every check [`refuses_entry`] makes of one path, but containing bx's own
/// directories. A tool-read location written in terms of the anchor is judged
/// for that at its own line.
fn refuses_anchor(path: &str, roots: &RootSet) -> Option<Reason> {
    refuses_unanchored(path, None, roots)
        .or_else(|| (!roots.contains(Path::new(path))).then_some(Reason::OutsideDeclaredRoots))
}

/// Why one resolved path may not be named at all — relative, climbing, made of
/// a character no path bx writes holds, inside a directory bx owns, or inside
/// bx's config repo — whether or not it must also lie inside a root.
///
/// `separator` is the one further character the text may hold: `Some(':')`
/// only for a whole location value, whose entries were judged apart at it.
fn refuses_unanchored(text: &str, separator: Option<char>, roots: &RootSet) -> Option<Reason> {
    let path = Path::new(text);
    if !path.is_absolute() {
        return Some(Reason::NotAbsolute);
    }
    // Read before normalisation, which would fold the `..` away.
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Some(Reason::ParentComponent);
    }
    // An allowlist, not a list of known-bad characters: the shell has resolved
    // the value, and a tool may read any other character its own way.
    if let Some(unlisted) = text
        .chars()
        .find(|&c| !(c == '/' || is_word_char(c) || Some(c) == separator))
    {
        return Some(Reason::UnlistedCharacter(unlisted));
    }
    // Before the root test, and therefore ahead of any declaration: a root the
    // user declared widens where tools may live, never who owns bx's own state.
    if roots.owns(path) {
        return Some(Reason::BxOwnedDirectory);
    }
    if roots.in_config_repo(path) {
        return Some(Reason::InsideConfigRepo);
    }
    None
}

/// What one walk over a fragment has learned it assigns.
#[derive(Debug, Default)]
struct Scope {
    /// What each accepted assignment expanded to, or why the guard cannot know.
    learned: HashMap<String, Result<String, Reason>>,
    /// Whether a refused line has passed. After one nothing is known, because
    /// the guard did not read what it assigned or unset.
    lost: bool,
    /// What each search list the fragment assigned extends, [`INHERITED`]
    /// standing for the list the shell inherited. Every assignment sets or
    /// removes its name's entry, and a refused line clears them all.
    extended: HashMap<String, String>,
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
                .ok_or(Reason::NoHome);
        }
        Err(if is_reserved(name) {
            Reason::ReservedName
        } else {
            Reason::UnresolvedReference
        })
    }

    /// Whether a reference to `name` is to the value the shell inherited:
    /// nothing in the fragment has assigned it, and no refused line could have.
    fn inherits(&self, name: &str) -> bool {
        !self.lost && !self.learned.contains_key(name)
    }

    /// What a search list's reference to its own `name` expands to while the
    /// list is judged: the inherited list, or the list the fragment's earlier
    /// extensions of it made, or else whatever [`Scope::lookup`] says.
    fn own_list(&self, name: &str, home: Option<&Path>) -> Result<String, Reason> {
        if self.inherits(name) {
            return Ok(INHERITED.to_string());
        }
        match self.extended.get(name) {
            Some(list) => Ok(list.clone()),
            None => self.lookup(name, home),
        }
    }

    /// Learn what an assignment the walk has just judged gave its name.
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
                match judged.extended {
                    Some(list) => {
                        self.extended.insert(name.to_string(), list);
                    }
                    None => {
                        self.extended.remove(name);
                    }
                }
                self.learned
                    .insert(name.to_string(), judged.resolved.map_err(as_reference));
            }
        }
    }

    /// After a line the guard did not read, know nothing.
    fn forget_everything(&mut self) {
        self.learned.clear();
        self.extended.clear();
        self.lost = true;
    }
}

/// The reason a *reference* to a name reports, given why the name's own value
/// could not be known.
fn as_reference(reason: Reason) -> Reason {
    match reason {
        Reason::UnresolvedReference | Reason::NoHome | Reason::ExpansionTooLong => reason,
        _ => Reason::UnreadableReference,
    }
}

/// How long an expansion may grow before it is refused.
///
/// The expander's bound on work. Values are learned expanded, so a line that
/// doubles a variable — `X=$X$X` — doubles what is stored, and a fragment of a
/// few dozen such lines would otherwise hold gigabytes.
const MAX_EXPANDED_LEN: usize = 4096;

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
    /// The value without its quotes, references not expanded, as written.
    text: &'a str,
    /// Whether the value begins with the unquoted `~` a shell expands.
    tilde: bool,
    /// The text, split into literal text and references, in order.
    parts: Vec<Part<'a>>,
}

impl Word<'_> {
    /// What a shell gives the name this value is assigned to.
    fn resolve(&self, scope: &Scope, home: Option<&Path>) -> Result<String, Reason> {
        self.expand(scope, home, None)
    }

    /// [`Word::resolve`], except that a reference to `inherited` expands as
    /// [`Scope::own_list`] says: to [`INHERITED`] if the fragment has not
    /// assigned it, and to its earlier extension if one was made.
    fn expand(
        &self,
        scope: &Scope,
        home: Option<&Path>,
        inherited: Option<&str>,
    ) -> Result<String, Reason> {
        let mut out = if self.tilde {
            scope.lookup("HOME", home)?
        } else {
            String::new()
        };
        for part in &self.parts {
            match part {
                Part::Text(text) => out.push_str(text),
                Part::Reference(name) if inherited == Some(*name) => {
                    out.push_str(&scope.own_list(name, home)?);
                }
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
                reason_of(&check("CARGO_HOME", "/etc", &roots)),
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
        // `SCRATCH_HOME` was caught by the `_HOME` suffix and, under the
        // name-based guard, denied outright — a false positive on the one
        // variable the whole configuration is written in terms of. The emit
        // table lists it as the location it is.
        assert_eq!(emittable("SCRATCH_HOME"), Some(Kind::Anchor));
        assert_eq!(check("SCRATCH_HOME", ROOT, &rooted()), Verdict::Allowed);
    }

    #[test]
    fn with_no_root_declared_every_relocating_variable_is_a_violation() {
        for (name, value) in [
            ("CARGO_HOME", "/var/mnt/scratch/example/cache/cargo"),
            ("XDG_CACHE_HOME", "/anywhere"),
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
    fn a_location_given_a_word_is_not_absolute_and_an_unlisted_name_is_not_emittable() {
        // Round 5 retires `NotAPath`. It existed because a name list was the
        // only evidence that a variable held a location; the emit table now
        // says so, and a bare word, a number or a URL given to a location is a
        // path relative to wherever the shell is. The remedy is an absolute
        // path, which is what the reason says.
        for (name, value) in [
            ("CARGO_HOME", "1"),
            ("NPM_CONFIG_CACHE", "npm"),
            ("PIP_CACHE_DIR", "cache"),
            ("CARGO_HOME", "https://example.invalid/cargo"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(Reason::NotAbsolute),
                "{name}={value}"
            );
        }
        // Round 4 judged these by their names' families; the table lists none
        // of them, so each is refused whatever it is given.
        for (name, value) in [
            ("SOMETOOL_CONFIG_DIR", "yes"),
            ("PIP_TARGET", "build"),
            ("UV_PROJECT_ENVIRONMENT", "venv"),
            ("PIP_TIMEOUT", "60"),
            ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
            ("MISE_QUIET", "1"),
            ("PIP_NO_CACHE_DIR", "1"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(Reason::NotEmittable),
                "{name}={value}"
            );
        }
        assert_eq!(check("UV_NO_CACHE", "1", &rooted()), Verdict::Allowed);
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
                reason_of(&check("CARGO_HOME", value, &home_rooted)),
                Some(Reason::BxOwnedDirectory),
                "{value}"
            );
        }
        // The parent is not bx's either, but it contains bx's state directory,
        // and a tool that clears it clears bx's record (r3 round 2). A sibling
        // whose name merely extends it is fine.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~/.local/state", &home_rooted)),
            Some(Reason::ContainsBxDirectory)
        );
        assert_eq!(
            check("CARGO_HOME", "~/.local/state/bxtra", &home_rooted),
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
                "CARGO_HOME",
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
    fn a_program_needs_no_root_but_may_not_live_in_bxs_directory() {
        // The exclusion holds for a program too. A program inside bx's state
        // directory is one `bx rm` deletes, so even a kind that needs no root
        // may not point there — and it may point at an ordinary program with
        // no root declared at all.
        assert_eq!(
            reason_of(&check(
                "EDITOR",
                "/var/home/example/.local/state/bx/editor",
                &rooted()
            )),
            Some(Reason::BxOwnedDirectory)
        );
        for roots in [
            rooted(),
            RootSet::new(Path::new(HOME), &[]),
            RootSet::strict(),
        ] {
            assert_eq!(check("EDITOR", "/usr/bin/nvim", &roots), Verdict::Allowed);
        }
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
            Reason::DeclaredRootItself.to_string(),
            "is a declared root itself, and its tool may write beside it, outside every root"
        );
        assert_eq!(
            Reason::BxOwnedDirectory.to_string(),
            "points inside a directory bx owns"
        );
        assert_eq!(
            Reason::NotEmittable.to_string(),
            "assigns a variable no bx generator declares, so bx cannot judge the \
             value — a defect in bx, not in your configuration"
        );
        assert_eq!(
            Reason::NotAProgram.to_string(),
            "is not one program — an absolute path or a bare command name, with no arguments"
        );
        assert_eq!(
            Reason::NotASetting.to_string(),
            "is not a value this setting accepts"
        );
        assert_eq!(
            Reason::ReservedName.to_string(),
            "assigns or refers to a name the shell manages itself"
        );
        assert_eq!(Reason::NotAbsolute.to_string(), "is not an absolute path");
        assert_eq!(
            Reason::ParentComponent.to_string(),
            "has a `..` component, so where it points cannot be shown"
        );
        assert_eq!(
            Reason::ContainsBxDirectory.to_string(),
            "contains bx's state directory or its config repo, which the tool may clear"
        );
        assert_eq!(
            Reason::UnlistedCharacter('\\').to_string(),
            "holds '\\\\', a character no path bx writes may hold"
        );
        assert_eq!(
            Reason::UnresolvedReference.to_string(),
            "refers to a variable this fragment has not assigned"
        );
        assert_eq!(
            Reason::NoHome.to_string(),
            "refers to the home directory, and the guard was given none"
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
                "export XDG_CACHE_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n",
                vec![(1, "XDG_CACHE_HOME"), (3, "RUSTUP_HOME")],
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
        // Since r3 round 3 the space is itself refused, by name, as a
        // character no path bx writes holds, and never as a second assignment.
        assert_eq!(
            reasons(
                "export CARGO_HOME=\"/var/mnt/scratch/example/my cache\"\n",
                &rooted()
            ),
            vec![(1, Reason::UnlistedCharacter(' '))]
        );
        assert_eq!(
            scan_with(
                "export CARGO_HOME=/var/mnt/scratch/example/cargo # written by bx\n",
                &rooted()
            ),
            vec![]
        );
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
        // The helpers are not in the emit table (round 5); the line that uses
        // them resolves inside the root and is not refused.
        assert_eq!(
            reasons(content, &rooted()),
            vec![
                (1, Reason::NotEmittable),
                (2, Reason::NotEmittable),
                (3, Reason::NotEmittable)
            ]
        );
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
        // The links are helpers the emit table does not list, so each one is
        // `NotEmittable` (round 5). What is pinned is that the line using the
        // chain resolves inside the root and is not refused.
        for links in [1, 7, 8, 9, 64] {
            let helpers: Vec<(usize, Reason)> = (1..=links + 1)
                .map(|line| (line, Reason::NotEmittable))
                .collect();
            assert_eq!(reasons(&chain(links), &rooted()), helpers, "{links}");
        }
    }

    #[test]
    fn substituted_text_is_not_expanded_again() {
        // `DATA_DIR='$CACHE_DIR'` holds the characters `$CACHE_DIR`, and a
        // shell that later expands `$DATA_DIR` yields them and stops. Expanding
        // them again would judge a path no shell produces. Both helpers are
        // locations, so each is judged as one. The line that uses the literal
        // inside the root holds a `$` a tool could expand itself, so since r3
        // round 2 it is refused for that, and not for where a second
        // expansion would point.
        let content =
            format!("CACHE_DIR=/etc\nDATA_DIR='$CACHE_DIR'\nexport CARGO_HOME={ROOT}/$DATA_DIR\n");
        assert_eq!(
            reasons(&content, &rooted()),
            vec![
                (1, Reason::OutsideDeclaredRoots),
                (2, Reason::NotAbsolute),
                (3, Reason::UnlistedCharacter('$'))
            ]
        );
        // Expanded once, `$DATA_DIR/cargo` is `$CACHE_DIR/cargo`: relative.
        // Expanded twice it would be inside the root and approved.
        let content =
            format!("CACHE_DIR={ROOT}\nDATA_DIR='$CACHE_DIR'\nexport CARGO_HOME=$DATA_DIR/cargo\n");
        assert_eq!(
            reasons(&content, &rooted()),
            vec![(2, Reason::NotAbsolute), (3, Reason::NotAbsolute)]
        );
    }

    #[test]
    fn a_value_that_extends_itself_resolves_as_a_shell_would() {
        // `X=$X/b` sees the previous `X`, so it is one more path component
        // under the root, not a value that grows without end.
        let content = concat!(
            "SCRATCH_HOME=/var/mnt/scratch/example\n",
            "SCRATCH_HOME=$SCRATCH_HOME/b\n",
            "export CARGO_HOME=$SCRATCH_HOME/cargo\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
        // Before it is assigned, the same line refers to nothing — and a value
        // that does not resolve is refused for that, so both lines say so.
        assert_eq!(
            reasons(
                "SCRATCH_HOME=$SCRATCH_HOME/b\nexport CARGO_HOME=$SCRATCH_HOME/cargo\n",
                &rooted()
            ),
            vec![
                (1, Reason::UnresolvedReference),
                (2, Reason::UnresolvedReference)
            ]
        );
    }

    #[test]
    fn two_values_that_refer_to_each_other_do_not_resolve() {
        // A true two-node cycle. `A=$B` refers to a `B` not yet assigned, so
        // `A` is unresolvable, and `B=$A` inherits that. A value that does not
        // resolve cannot be shown not to be a path, so every line is refused.
        let content = concat!(
            "CACHE_DIR=$DATA_DIR\n",
            "DATA_DIR=$CACHE_DIR\n",
            "export CARGO_HOME=$CACHE_DIR/cargo\n"
        );
        assert_eq!(
            reasons(content, &rooted()),
            vec![
                (1, Reason::UnresolvedReference),
                (2, Reason::UnresolvedReference),
                (3, Reason::UnresolvedReference)
            ]
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
        // Quoted, it is text, and since r3 round 3 a character no path bx
        // writes holds.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "\"/var/mnt/scratch/example/a#b\"",
                &rooted()
            )),
            Some(Reason::UnlistedCharacter('#'))
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
        // `Y` is judged too, as every value is (round 4).
        let content = format!(
            "SCRATCH_HOME={long}\nCACHE_DIR=$SCRATCH_HOME$SCRATCH_HOME\nexport CARGO_HOME=$CACHE_DIR/cargo\n"
        );
        assert_eq!(
            reasons(&content, &rooted()),
            vec![(2, Reason::ExpansionTooLong), (3, Reason::ExpansionTooLong)]
        );
        // And the same bound applies to the value being judged itself.
        let content =
            format!("SCRATCH_HOME={long}\nexport CARGO_HOME=$SCRATCH_HOME$SCRATCH_HOME\n");
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
        let content = format!(
            "SCRATCH_HOME={short}\nCACHE_DIR=$SCRATCH_HOME$SCRATCH_HOME\nexport CARGO_HOME=$CACHE_DIR/cargo\n"
        );
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
        let content = format!("SCRATCH_HOME={ROOT}\nexport CARGO_HOME=${{SCRATCH_HOME}}/cargo\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);

        // The brace ends the name and nothing more: text after it is appended
        // verbatim, with no separator invented. `${X}suffix` therefore names a
        // *sibling* of the root, which is outside it.
        let content =
            format!("SCRATCH_HOME={ROOT}\nexport CARGO_HOME=${{SCRATCH_HOME}}suffix/cargo\n");
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
        let content = format!("SCRATCH_HOME={exact}\nexport CARGO_HOME=$SCRATCH_HOME\n");
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
    /// name-based guard. All 23 exports and both helpers are locations in the
    /// emit table.
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
            assert_eq!(emittable(name), Some(Kind::Location), "{name}");
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
        assert_eq!(emittable("SCCACHE_DIR"), Some(Kind::Location));
        // The setting that shares its prefix is a size, and a name that
        // shares it and is not in the table is not emittable at all.
        assert_eq!(
            emittable("SCCACHE_CACHE_SIZE"),
            Some(Kind::Setting(Setting::Size))
        );
        assert_eq!(emittable("SCCACHE_SERVER_UDS"), None);

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
    fn only_the_search_lists_the_table_names_are_search_lists() {
        // `PATH` and `INFOPATH` are search lists. A list that changes what a
        // program loads or builds against is not in the table, so it is not
        // emittable even inside a root; `MANPATH` is the shell's own.
        assert_eq!(emittable("PATH"), Some(Kind::SearchList));
        assert_eq!(emittable("INFOPATH"), Some(Kind::SearchList));
        for name in ["LD_LIBRARY_PATH", "PKG_CONFIG_PATH", "XDG_DATA_DIRS"] {
            assert_eq!(
                reason_of(&check(name, "/var/mnt/scratch/example/lib", &rooted())),
                Some(Reason::NotEmittable),
                "{name}"
            );
        }
        assert_eq!(
            reason_of(&check("MANPATH", "/usr/share/man", &rooted())),
            Some(Reason::ReservedName)
        );
    }

    #[test]
    fn the_same_fragment_is_all_violations_with_no_root_declared() {
        // A user who declares no root gets the strict guard, and the strict
        // guard refuses every location. Round 5 keeps the count at 25: the 23
        // exports and the two helpers `CACHE_DIR` and `DATA_DIR` are all
        // locations in the emit table, so every one is `NoRootsDeclared` and
        // none is `NotEmittable`.
        let found = scan(OPERATOR_FRAGMENT);
        assert_eq!(found.len(), 25);
        assert!(found.iter().all(|v| v.reason == Reason::NoRootsDeclared));
        assert!(found.windows(2).all(|w| w[0].line < w[1].line));
        assert!(found.iter().any(|v| v.name == "CACHE_DIR"));
        assert!(found.iter().any(|v| v.name == "DATA_DIR"));
    }

    #[test]
    fn the_operator_fragment_scans_clean_under_its_declared_root() {
        assert_eq!(scan_with(OPERATOR_FRAGMENT, &rooted()), vec![]);
    }

    #[test]
    fn the_xdg_base_directories_and_the_operator_caches_are_locations() {
        // Not `XDG_CONFIG_HOME` or `XDG_STATE_HOME`: bx finds its own
        // directories through them (round 6).
        for name in [
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "MISE_DATA_DIR",
            "UV_CACHE_DIR",
        ] {
            assert_eq!(emittable(name), Some(Kind::Location), "{name}");
        }
    }

    #[test]
    fn a_name_the_table_does_not_list_is_not_emittable_whatever_its_family() {
        // Every rule round 4 matched a name by — an exact list, a family
        // prefix, a location suffix, an exception — is gone. None of these is
        // in the table, so each is refused, even given a path inside the root.
        for name in [
            "GNUPGHOME",
            "GH_CONFIG_DIR",
            "KUBECONFIG",
            "NPM_CONFIG_PREFIX",
            "ASDF_DIR",
            "PIP_TARGET",
            "SOMETOOL_CONFIG_DIR",
            "OTHERTOOL_HOME",
            "THIRD_CACHE_DIR",
            "_HOME",
            "UV_",
            "SCCACHE_SERVER_UDS",
            "UV_SYSTEM_PYTHON",
            "PIP_REQUIRE_VIRTUALENV",
        ] {
            assert_eq!(emittable(name), None, "{name}");
            assert_eq!(
                reason_of(&check(name, "/var/mnt/scratch/example/x", &rooted())),
                Some(Reason::NotEmittable),
                "{name}"
            );
        }
    }

    #[test]
    fn programs_and_settings_have_their_kinds() {
        for name in ["RUSTC_WRAPPER", "EDITOR", "VISUAL", "PAGER"] {
            assert_eq!(emittable(name), Some(Kind::Program), "{name}");
        }
        assert_eq!(
            emittable("SCCACHE_CACHE_SIZE"),
            Some(Kind::Setting(Setting::Size))
        );
        assert_eq!(emittable("MISE_JOBS"), Some(Kind::Setting(Setting::Count)));
        assert_eq!(emittable("LANG"), Some(Kind::Setting(Setting::Locale)));
        assert_eq!(
            emittable("MISE_VERBOSE"),
            Some(Kind::Setting(Setting::Switch))
        );
    }

    #[test]
    fn the_check_is_case_sensitive() {
        assert_eq!(emittable("cargo_home"), None);
        assert_eq!(
            reason_of(&check("cargo_home", ROOT, &rooted())),
            Some(Reason::NotEmittable)
        );
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
            reasons(&format!("export CARGO_HOME={state}"), &wide),
            vec![(1, Reason::BxOwnedDirectory)]
        );
        for line in [
            format!("declare -gx CARGO_HOME={state}"),
            format!("export FOO CARGO_HOME={state}"),
        ] {
            assert_eq!(
                reasons(&line, &wide),
                vec![(1, Reason::Unreadable)],
                "{line}"
            );
        }
        assert_eq!(
            reasons(&format!("export FOO=1 CARGO_HOME={state}"), &wide),
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
        // A literal `~` given to a location is a relative path.
        assert_eq!(
            reasons(
                "SCRATCH_HOME='~'\nexport CARGO_HOME=$SCRATCH_HOME/cargo\n",
                &home_rooted
            ),
            vec![(1, Reason::NotAbsolute), (2, Reason::NotAbsolute)]
        );
    }

    #[test]
    fn a_single_assignment_with_an_equals_sign_in_its_value_is_not_two() {
        // Each assigns one variable. The `=` is inside the value, so the old
        // remedy — split the line — was impossible to follow.
        // Since r3 round 3 a space in a location is refused by name; what is
        // pinned is that none of these is read as two assignments.
        for (line, expected) in [
            (
                "export CARGO_HOME=\"/var/mnt/scratch/example/-j8 V=1\"",
                vec![(1, Reason::UnlistedCharacter(' '))],
            ),
            (
                "export CARGO_HOME='/var/mnt/scratch/example/-j8 V=1'",
                vec![(1, Reason::UnlistedCharacter(' '))],
            ),
            (
                "export CARGO_HOME=/var/mnt/scratch/example/cargo # keep=this",
                vec![],
            ),
            (
                "export CARGO_HOME=\"/var/mnt/scratch/example/a b=c/cargo\"",
                vec![(1, Reason::UnlistedCharacter(' '))],
            ),
        ] {
            assert_eq!(reasons(line, &rooted()), expected, "{line}");
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
            ("MAKEFLAGS", "\"-j8 V=1\"", Some(Reason::NotEmittable)),
            (
                "CARGO_HOME",
                "\"/var/mnt/scratch/example/a b\"",
                Some(Reason::UnlistedCharacter(' ')),
            ),
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
        // A setting the table lists relocates nothing, so it needs no root.
        for (name, value) in [("UV_NO_CACHE", "1"), ("MISE_JOBS", "8")] {
            assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
        // Round 4 allowed the rest of the family as settings. The table does
        // not list them, so round 5 refuses them, with or without a root.
        for (name, value) in [
            ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
            ("NPM_CONFIG_FUND", "false"),
            ("NPM_CONFIG_LOGLEVEL", "warn"),
            ("PIP_INDEX_URL", "https://pypi.example.invalid/simple"),
            ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
            ("UV_PYTHON", "3.12"),
            ("MISE_ENV", "production"),
            ("ASDF_CONCURRENCY", "8"),
        ] {
            for roots in [rooted(), RootSet::strict()] {
                assert_eq!(
                    reason_of(&check(name, value, &roots)),
                    Some(Reason::NotEmittable),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_family_variable_that_holds_a_location_is_still_judged() {
        // Invariant 2 is not relaxed for the same families: a location given a
        // path is judged by where it points, and one whose name says it holds a
        // location is refused a bare word, which is a path relative to
        // wherever the shell happens to be.
        for name in [
            "UV_CACHE_DIR",
            "PIP_CACHE_DIR",
            "NPM_CONFIG_CACHE",
            "MISE_DATA_DIR",
            "MISE_CACHE_DIR",
        ] {
            assert_eq!(
                reason_of(&check(name, "cache", &rooted())),
                Some(Reason::NotAbsolute),
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
        // The family's other locations are not in the table at all.
        for name in [
            "UV_TOOL_DIR",
            "PIP_TARGET",
            "NPM_CONFIG_PREFIX",
            "NPM_CONFIG_USERCONFIG",
            "MISE_INSTALL_PATH",
            "UV_PROJECT_ENVIRONMENT",
        ] {
            assert_eq!(
                reason_of(&check(name, "/var/mnt/scratch/example/x", &rooted())),
                Some(Reason::NotEmittable),
                "{name}"
            );
        }
    }

    #[test]
    fn scan_reports_every_violation() {
        let content = "export XDG_CACHE_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n";
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

    // Round-4 reproductions, written against the round-3 API only.

    #[test]
    fn r4_1_a_state_directory_the_fragment_moves_is_owned_by_later_lines() {
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let cases = [
            (
                "export XDG_STATE_HOME=/var/mnt/scratch/example/state\n\
                 export CARGO_HOME=/var/mnt/scratch/example/state/bx",
                rooted(),
            ),
            (
                "export XDG_STATE_HOME=~/state\nexport CARGO_HOME=~/state/bx/cargo",
                home_rooted,
            ),
        ];
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r4_2_a_name_whose_assignment_the_shell_acts_on() {
        let mut cases = Vec::new();
        for content in [
            "export HISTFILESIZE=0",
            "export HISTFILE=/etc/evil",
            "export HISTFILE=history",
            "POSIXLY_CORRECT=1",
            "BASH_COMPAT=50",
            "GLOBIGNORE=x",
            "BASH_XTRACEFD=1",
            "PROMPT_COMMAND=x",
            "PS0=x",
            "precmd_functions=x",
        ] {
            cases.push((content, rooted()));
            cases.push((content, RootSet::strict()));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    /// Names the round-3 lists did not hold, each of which moves a tool's
    /// config, data or cache — `rg` and `git` were shown to obey two of them.
    const R4_UNLISTED_RELOCATIONS: &[&str] = &[
        "CARGO_TARGET_DIR",
        "CARGO_INSTALL_ROOT",
        "LESSHISTFILE",
        "NODE_REPL_HISTORY",
        "PYTHONPYCACHEPREFIX",
        "GOENV",
        "GOBIN",
        "GOTMPDIR",
        "RIPGREP_CONFIG_PATH",
        "BAT_CONFIG_PATH",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "INPUTRC",
        "TERMINFO",
        "CCACHE_CONFIGPATH",
        "XDG_CONFIG_DIRS",
        "XDG_DATA_DIRS",
        "YARN_GLOBAL_FOLDER",
        "BUNDLE_USER_CONFIG",
        "BUNDLE_PATH",
        "POETRY_VIRTUALENVS_PATH",
        "CONDA_PKGS_DIRS",
        "PIPX_HOME",
        "PIPX_BIN_DIR",
        "pnpm_config_store_dir",
        "RBENV_ROOT",
        "NODENV_ROOT",
        "FNM_DIR",
        "SDKMAN_DIR",
        "STARSHIP_CACHE",
        "NUGET_PLUGINS_CACHE_PATH",
        "PLAYWRIGHT_BROWSERS_PATH",
        "CYPRESS_CACHE_FOLDER",
        "ELECTRON_CACHE",
        "LD_LIBRARY_PATH",
    ];

    #[test]
    fn r4_3_a_path_given_to_a_name_no_list_holds() {
        let mut cases = Vec::new();
        let unlisted: Vec<String> = R4_UNLISTED_RELOCATIONS
            .iter()
            .map(|name| format!("export {name}=/etc/evil"))
            .collect();
        for content in &unlisted {
            cases.push((content.as_str(), rooted()));
            cases.push((content.as_str(), RootSet::strict()));
        }
        for content in [
            "export SOMETHING=.",
            "export SOMETHING=..",
            "export SOMETHING=build/cache",
            "export SOMETHING=~/elsewhere",
            "export SOMETHING=a:/etc/evil",
            "X=/etc/evil",
        ] {
            cases.push((content, rooted()));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r4_4_location_words_the_review_found_missing() {
        let cases = [
            "MISE_CONFIG_DIRECTORY=evil",
            "MISE_OVERRIDE_CONFIG_FILENAMES=evil",
            "UV_TOOL_FOLDER=evil",
            "ASDF_PLUGIN_MODULE=evil",
            "PIP_INSTALL_DEST=evil",
        ]
        .map(|content| (content, rooted()));
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r4_5_a_search_list_or_a_program_that_is_not_an_absolute_path() {
        let mut cases = Vec::new();
        for content in [
            "export PATH=.:/usr/bin",
            "export PATH=/usr/bin:",
            "export PATH=bin",
            "export PATH=",
            "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
            "export EDITOR=./nvim",
            "export EDITOR=/var/home/example/.local/state/bx/nvim",
        ] {
            cases.push((content, rooted()));
            cases.push((content, RootSet::new(Path::new(HOME), &[])));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    // Round-5 reproductions, written against the round-4 API only.

    /// Names the round-5 review ran a real tool against, and saw the tool
    /// read a bare word as a path relative to the current directory: `git`
    /// followed `GIT_DIR=evil` to `./evil`, `rg` read `./rc`, `cargo` built
    /// into `./target2`, a child `bash` sourced `./rc`.
    const R5_READ_AS_LOCATIONS: &[(&str, &str)] = &[
        ("GIT_DIR", "evil"),
        ("GIT_WORK_TREE", "work"),
        ("GIT_CONFIG_SYSTEM", "rc"),
        ("RIPGREP_CONFIG_PATH", "rc"),
        ("CARGO_TARGET_DIR", "target2"),
        ("CARGO_INSTALL_ROOT", "root"),
        ("PYTHONPYCACHEPREFIX", "pyc"),
        ("BASH_ENV", "rc"),
        ("ENV", "rc"),
        ("INPUTRC", "rc"),
        ("LESSHISTFILE", "hist"),
        ("GOENV", "env"),
        ("TERMINFO", "ti"),
        ("BAT_CONFIG_PATH", "rc"),
        ("NODE_REPL_HISTORY", "hist"),
    ];

    #[test]
    fn r5_1_a_bare_word_for_a_name_a_tool_reads_as_a_location() {
        let lines: Vec<String> = R5_READ_AS_LOCATIONS
            .iter()
            .map(|(name, value)| format!("export {name}={value}"))
            .collect();
        let mut cases = Vec::new();
        for line in &lines {
            cases.push((line.as_str(), rooted()));
            cases.push((line.as_str(), RootSet::strict()));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r5_2_a_program_given_arguments() {
        let mut cases = Vec::new();
        for content in [
            "export EDITOR=\"/usr/bin/touch /var/home/example/.local/state/bx/written-by-editor\"",
            "export EDITOR=\"/usr/bin/env XDG_CONFIG_HOME=/etc/evil nvim\"",
            "export PAGER=\"/usr/bin/less --lesskey-file=/etc/evil/lesskey\"",
        ] {
            cases.push((content, rooted()));
            cases.push((content, RootSet::strict()));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r5_3_a_state_directory_moved_by_a_later_line() {
        // Since round 6 the move itself is refused: bx's state directory is
        // not a fragment's to move.
        assert_eq!(
            reasons(
                "export CARGO_HOME=/var/mnt/scratch/example/state/bx\n\
                 export XDG_STATE_HOME=/var/mnt/scratch/example/state",
                &rooted()
            ),
            vec![(2, Reason::NotEmittable)]
        );
    }

    #[test]
    fn r5_4_a_url_shaped_value_is_a_relative_path() {
        let mut cases = Vec::new();
        for content in [
            "export EDITOR=x://ed",
            "export RIPGREP_CONFIG_PATH=cfg://rc",
            "export GIT_CONFIG_SYSTEM=https://x:/etc/evil",
        ] {
            cases.push((content, rooted()));
            cases.push((content, RootSet::strict()));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r5_5_the_strict_set_owns_the_default_state_directory() {
        let cases = [
            "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
            "export VISUAL=/var/home/example/.local/state/bx/nvim",
            "export SSH_AUTH_SOCK=/var/home/example/.local/state/bx/agent.sock",
        ]
        .map(|content| (content, RootSet::strict()));
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r5_6_prompts_and_execignore_act_on_assignment() {
        let mut cases = Vec::new();
        for content in [
            "RPROMPT='$(touch evil)'",
            "RPS1=x",
            "RPROMPT2=x",
            "RPS2=x",
            "EXECIGNORE=x",
        ] {
            cases.push((content, rooted()));
            cases.push((content, RootSet::strict()));
        }
        assert_eq!(r3_approved_cases(&cases), Vec::<String>::new());
    }

    #[test]
    fn r5_7_a_config_home_whose_repo_is_the_state_directory() {
        // Since round 6 no `XDG_CONFIG_HOME` is emittable at all.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(
            reasons("export XDG_CONFIG_HOME=~/.local/state", &home_rooted),
            vec![(1, Reason::NotEmittable)]
        );
    }

    // Review round 5: a fragment may set only a variable bx knows how to judge.

    #[test]
    fn every_round_5_falsifier_is_refused_for_the_reason_that_names_its_defect() {
        use Reason::{BxOwnedDirectory, NotAProgram, NotAbsolute, NotEmittable, ReservedName};
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        // 1: a bare word a tool reads as a path. `BASH_ENV` and `ENV` are also
        // names a starting shell acts on, so they are reserved first.
        for (name, value) in R5_READ_AS_LOCATIONS {
            let expected = if ["BASH_ENV", "ENV"].contains(name) {
                ReservedName
            } else {
                NotEmittable
            };
            for roots in [rooted(), RootSet::strict()] {
                assert_eq!(
                    reason_of(&check(name, value, &roots)),
                    Some(expected),
                    "{name}={value}"
                );
            }
        }
        // 2: a program given arguments.
        for value in [
            "\"/usr/bin/touch /var/home/example/.local/state/bx/written-by-editor\"",
            "\"/usr/bin/env XDG_CONFIG_HOME=/etc/evil nvim\"",
        ] {
            for roots in [rooted(), RootSet::strict()] {
                assert_eq!(
                    reason_of(&check("EDITOR", value, &roots)),
                    Some(NotAProgram),
                    "{value}"
                );
            }
        }
        assert_eq!(
            reason_of(&check(
                "PAGER",
                "\"/usr/bin/less --lesskey-file=/etc/evil/lesskey\"",
                &rooted()
            )),
            Some(NotAProgram)
        );
        // 3: a state directory a later line moves. Since round 6 the move is
        // what is refused.
        assert_eq!(
            reasons(
                "export CARGO_HOME=/var/mnt/scratch/example/state/bx\n\
                 export XDG_STATE_HOME=/var/mnt/scratch/example/state\n",
                &rooted()
            ),
            vec![(2, NotEmittable)]
        );
        // 4: no URL is exempt, for any kind that holds a path.
        for (name, value, reason) in [
            ("EDITOR", "x://ed", NotAProgram),
            ("RIPGREP_CONFIG_PATH", "cfg://rc", NotEmittable),
            ("GIT_CONFIG_SYSTEM", "https://x:/etc/evil", NotEmittable),
            ("CARGO_HOME", "cfg://rc", NotAbsolute),
            (
                "CARGO_HOME",
                "https://x:/var/mnt/scratch/example",
                NotAbsolute,
            ),
            ("PATH", "https://x:/usr/bin", NotAbsolute),
            ("SSH_AUTH_SOCK", "unix://agent", NotAbsolute),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(reason),
                "{name}={value}"
            );
        }
        // 5: the strict set owns the default state directory under any home.
        for content in [
            "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
            "export VISUAL=/var/home/example/.local/state/bx/nvim",
            "export SSH_AUTH_SOCK=/var/home/example/.local/state/bx/agent.sock",
        ] {
            assert_eq!(
                reasons(content, &RootSet::strict()),
                vec![(1, BxOwnedDirectory)],
                "{content}"
            );
        }
        // 6: names a shell acts on when assigned.
        for name in ["RPROMPT", "RPS1", "RPROMPT2", "RPS2", "EXECIGNORE"] {
            assert_eq!(
                reason_of(&check(name, "x", &RootSet::strict())),
                Some(ReservedName),
                "{name}"
            );
        }
        assert_eq!(
            reasons("RPROMPT='$(touch evil)'", &rooted()),
            vec![(1, ReservedName)]
        );
        // 7: a config repo landing on the state directory. Since round 6 no
        // fragment may move the config repo at all.
        assert_eq!(
            reasons("export XDG_CONFIG_HOME=~/.local/state", &home_rooted),
            vec![(1, NotEmittable)]
        );
    }

    #[test]
    fn every_name_in_the_emit_table_is_a_variable_name_with_one_kind() {
        let names: Vec<&str> = EMITTABLE.iter().map(|(name, _)| *name).collect();
        let mut ordered = names.clone();
        ordered.sort_unstable();
        ordered.dedup();
        assert_eq!(names, ordered, "in byte order, each name once");
        for (name, kind) in EMITTABLE {
            assert!(is_variable_name(name), "{name}");
            assert!(!is_reserved(name), "{name} is reserved, so never emitted");
            assert_eq!(emittable(name), Some(*kind), "{name}");
        }
        for kind in [
            Kind::Location,
            Kind::LocationList,
            Kind::Anchor,
            Kind::Program,
            Kind::SearchList,
            Kind::Socket,
            Kind::Setting(Setting::Switch),
            Kind::Setting(Setting::Count),
            Kind::Setting(Setting::Size),
            Kind::Setting(Setting::OneOf(&["auto", "always", "never"])),
            Kind::Setting(Setting::Locale),
        ] {
            assert!(
                EMITTABLE.iter().any(|(_, listed)| *listed == kind),
                "{kind:?} is used"
            );
        }
        // Every name the operator fragment assigns is a location in it.
        for line in OPERATOR_FRAGMENT.lines() {
            let assignment = line.strip_prefix("export ").unwrap_or(line);
            let (name, _) = assignment.split_once('=').expect("an assignment");
            assert!(
                matches!(
                    emittable(name),
                    Some(Kind::Location | Kind::LocationList | Kind::Anchor)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn an_unknown_name_is_refused_even_with_an_inert_value() {
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for (name, value) in [
            ("SOMETHING", "1"),
            ("SOMETHING", ""),
            ("SOMETHING", "''"),
            ("X", "true"),
            ("GIT_EDITOR", "vim"),
            ("MANPAGER", "less"),
            ("CC", "gcc"),
            ("JAVA_HOME", "/usr/lib/jvm/java-21"),
            ("SSL_CERT_FILE", "/etc/ssl/certs/ca-bundle.crt"),
            ("CARGO_BUILD_RUSTC_WRAPPER", "sccache"),
            ("MAKEFLAGS", "\"-j8\""),
        ] {
            for roots in [rooted(), home_rooted.clone(), RootSet::strict()] {
                assert_eq!(
                    reason_of(&check(name, value, &roots)),
                    Some(Reason::NotEmittable),
                    "{name}={value}"
                );
                assert_eq!(
                    reasons(&format!("export {name}={value}\n"), &roots),
                    vec![(1, Reason::NotEmittable)],
                    "{name}={value}"
                );
            }
        }
        // It is still learned, so a later line resolves it as a shell would.
        assert_eq!(
            reasons(
                &format!("X={ROOT}\nexport CARGO_HOME=$X/cargo\n"),
                &rooted()
            ),
            vec![(1, Reason::NotEmittable)]
        );
    }

    #[test]
    fn a_program_is_one_absolute_path_or_one_bare_command_name() {
        use Reason::{BxOwnedDirectory, NotAProgram, NotAbsolute, UnresolvedReference};
        for value in [
            "nvim",
            "code-insiders",
            "nvim.appimage",
            "g++",
            "7z",
            "ed_2",
            "/usr/bin/nvim",
            "/opt/x_y/bin/ed-2.1+b",
            "$HOME/bin/nvim",
            "/home/other/.local/state/bx/nvim",
        ] {
            assert_eq!(
                check("EDITOR", value, &rooted()),
                Verdict::Allowed,
                "{value}"
            );
        }
        for (value, reason) in [
            ("", NotAProgram),
            (".", NotAProgram),
            ("..", NotAProgram),
            ("-x", NotAProgram),
            (".hidden", NotAProgram),
            ("_x", NotAProgram),
            ("x://ed", NotAProgram),
            ("\"nvim --wait\"", NotAProgram),
            ("\"/usr/bin/nvim -u /etc/evil\"", NotAProgram),
            ("/usr/bin/a:b", NotAProgram),
            ("a:b", NotAProgram),
            ("\"a=b\"", NotAProgram),
            ("user@host", NotAProgram),
            ("a,b", NotAProgram),
            ("'~/bin/nvim'", NotAProgram),
            ("./nvim", NotAbsolute),
            ("bin/nvim", NotAbsolute),
            ("/var/home/example/.local/state/bx/nvim", BxOwnedDirectory),
            ("$NOWHERE", UnresolvedReference),
        ] {
            assert_eq!(
                reason_of(&check("EDITOR", value, &rooted())),
                Some(reason),
                "{value:?}"
            );
        }
        // With no home, a `~` or `$HOME` program cannot be shown to be outside
        // bx's state directory, and does not resolve.
        for value in ["~/bin/nvim", "$HOME/bin/nvim"] {
            assert_eq!(
                reason_of(&check("VISUAL", value, &RootSet::strict())),
                Some(Reason::NoHome),
                "{value}"
            );
        }
    }

    #[test]
    fn a_setting_accepts_only_its_own_shape() {
        for (name, value) in [
            ("UV_NO_CACHE", "0"),
            ("UV_NO_CACHE", "1"),
            ("MISE_VERBOSE", "true"),
            ("MISE_VERBOSE", "false"),
            ("MISE_JOBS", "8"),
            ("MISE_JOBS", "16"),
            ("SCCACHE_CACHE_SIZE", "100G"),
            ("SCCACHE_CACHE_SIZE", "512M"),
            ("SCCACHE_CACHE_SIZE", "2T"),
            ("SCCACHE_CACHE_SIZE", "10K"),
            ("CARGO_TERM_COLOR", "always"),
            ("LANG", "C.UTF-8"),
            ("LANG", "en_US.UTF-8"),
            ("LANG", "9"),
            ("CARGO_TERM_COLOR", "auto"),
            ("CARGO_TERM_COLOR", "never"),
            ("MISE_JOBS", "1"),
            ("MISE_JOBS", "1024"),
            ("SCCACHE_CACHE_SIZE", "1K"),
            ("SCCACHE_CACHE_SIZE", "999999T"),
        ] {
            for roots in [rooted(), RootSet::strict()] {
                assert_eq!(
                    check(name, value, &roots),
                    Verdict::Allowed,
                    "{name}={value}"
                );
            }
        }
        for (name, value) in [
            ("UV_NO_CACHE", "yes"),
            ("UV_NO_CACHE", ""),
            ("UV_NO_CACHE", "2"),
            ("MISE_VERBOSE", "/x"),
            ("MISE_JOBS", ""),
            ("MISE_JOBS", "G"),
            ("MISE_JOBS", "8X"),
            ("MISE_JOBS", "8GG"),
            ("MISE_JOBS", "-1"),
            ("MISE_JOBS", "1.5"),
            ("SCCACHE_CACHE_SIZE", "G100"),
            ("CARGO_TERM_COLOR", ""),
            ("CARGO_TERM_COLOR", "."),
            ("CARGO_TERM_COLOR", ".."),
            ("CARGO_TERM_COLOR", "-always"),
            ("CARGO_TERM_COLOR", "a/b"),
            ("CARGO_TERM_COLOR", "~"),
            ("CARGO_TERM_COLOR", "~/x"),
            ("CARGO_TERM_COLOR", "a:b"),
            ("CARGO_TERM_COLOR", "https://example.invalid"),
            ("LANG", "\"C UTF-8\""),
            ("LANG", "sr_RS@latin"),
            // Each setting holds only what its tool accepts (round 6): cargo
            // knows three colour modes, mise a job count, sccache a size with
            // a unit.
            ("CARGO_TERM_COLOR", "bogus"),
            ("CARGO_TERM_COLOR", "Always"),
            ("CARGO_TERM_COLOR", "1"),
            ("MISE_JOBS", "4K"),
            ("MISE_JOBS", "0"),
            ("MISE_JOBS", "1025"),
            ("MISE_JOBS", "99999999999999999999"),
            ("MISE_JOBS", "08"),
            ("SCCACHE_CACHE_SIZE", "100"),
            ("SCCACHE_CACHE_SIZE", "0G"),
            ("SCCACHE_CACHE_SIZE", "1000000G"),
            ("SCCACHE_CACHE_SIZE", "010G"),
            ("SCCACHE_CACHE_SIZE", "10g"),
            ("SCCACHE_CACHE_SIZE", "K"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(Reason::NotASetting),
                "{name}={value:?}"
            );
        }
    }

    #[test]
    fn a_socket_is_an_absolute_path_outside_bxs_directories() {
        use Reason::{BxOwnedDirectory, NoHome, NotAbsolute};
        for roots in [
            rooted(),
            RootSet::new(Path::new(HOME), &[]),
            RootSet::strict(),
        ] {
            for value in [
                "/run/user/1000/gnupg/S.gpg-agent.ssh",
                "\"/run/agent/socket\"",
            ] {
                assert_eq!(
                    check("SSH_AUTH_SOCK", value, &roots),
                    Verdict::Allowed,
                    "{value}"
                );
            }
            for (value, reason) in [
                ("agent.sock", NotAbsolute),
                ("", NotAbsolute),
                ("/var/home/example/.local/state/bx/agent", BxOwnedDirectory),
            ] {
                assert_eq!(
                    reason_of(&check("SSH_AUTH_SOCK", value, &roots)),
                    Some(reason),
                    "{value}"
                );
            }
        }
        assert_eq!(
            reason_of(&check("SSH_AUTH_SOCK", "~/agent", &RootSet::strict())),
            Some(NoHome)
        );
    }

    #[test]
    fn without_a_home_every_default_state_directory_is_owned() {
        let strict = RootSet::strict();
        for path in [
            "/var/home/example/.local/state/bx",
            "/home/other/.local/state/bx/x",
            "/root/.local/state/./bx",
            "/srv/.local/state/x/../bx/y",
        ] {
            assert!(strict.owns(Path::new(path)), "{path}");
        }
        for path in [
            "/var/home/example/.local/state/bxtra",
            "/var/home/example/.local/state",
            "/var/home/example/.local/bx",
            "/x/state/bx",
            "/x/.local/state",
        ] {
            assert!(!strict.owns(Path::new(path)), "{path}");
        }
        // A set with a home knows where its state directory is.
        assert!(!rooted().owns(Path::new("/home/other/.local/state/bx/x")));
        assert_eq!(
            check("PATH", "/home/other/.local/state/bx/bin", &rooted()),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("PATH", "/home/other/.local/state/bx/bin", &strict)),
            Some(Reason::BxOwnedDirectory)
        );
    }

    // Review round 6 (r3 round 1).

    #[test]
    fn a_fragment_never_moves_bxs_own_directories() {
        // bx reads `XDG_STATE_HOME` to find its state directory and
        // `XDG_CONFIG_HOME` to find its config repo. A fragment that set
        // either would move them on bx's next run, leaving the ledger, the
        // journal and `local.toml` behind (invariants 3 and 4), so neither is
        // in the emit table, whatever the roots admit.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for name in ["XDG_STATE_HOME", "XDG_CONFIG_HOME"] {
            assert_eq!(emittable(name), None, "{name}");
            for value in [
                "/var/mnt/scratch/example/s",
                "/var/mnt/scratch/example/c",
                "~/state",
                "~/.config",
            ] {
                for roots in [rooted(), home_rooted.clone(), RootSet::strict()] {
                    assert_eq!(
                        reason_of(&check(name, value, &roots)),
                        Some(Reason::NotEmittable),
                        "{name}={value}"
                    );
                    assert_eq!(
                        reasons(&format!("export {name}={value}\n"), &roots),
                        vec![(1, Reason::NotEmittable)],
                        "{name}={value}"
                    );
                }
            }
        }
        // The line before the move is judged against the directories bx
        // knows, and the move itself is what is refused.
        assert_eq!(
            reasons(
                "export CARGO_HOME=/var/mnt/scratch/example/s/bx\n\
                 export XDG_STATE_HOME=/var/mnt/scratch/example/s\n",
                &rooted()
            ),
            vec![(2, Reason::NotEmittable)]
        );
    }

    #[test]
    fn nothing_may_point_into_bxs_config_repo() {
        // The repo is committed, and README calls it safe to make public: a
        // tool writing there could commit its credentials (invariant 5), and a
        // program or a search list there runs whatever was committed.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for (name, value) in [
            ("CARGO_HOME", "~/.config/bx/cargo"),
            ("CARGO_HOME", "~/.config/bx"),
            ("EDITOR", "~/.config/bx/ed"),
            ("PATH", "~/.config/bx/bin:$PATH"),
            ("SSH_AUTH_SOCK", "~/.config/bx/a.sock"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &home_rooted)),
                Some(Reason::InsideConfigRepo),
                "{name}={value}"
            );
        }
        // A sibling whose name merely extends it is not the repo.
        assert_eq!(
            check("CARGO_HOME", "~/.config/bxtra", &home_rooted),
            Verdict::Allowed
        );
        // With no home, every default repo is refused, whoever's home.
        assert_eq!(
            reason_of(&check("PATH", "/home/o/.config/bx/bin", &RootSet::strict())),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(
            check("PATH", "/home/o/.config/bxtra/bin", &RootSet::strict()),
            Verdict::Allowed
        );
        // A repo the environment moved is refused once the caller says so,
        // inside a declared root, and the home's default stays refused.
        let moved = rooted().with_config_repos(&[PathBuf::from("/var/mnt/scratch/example/cfg/bx")]);
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/cfg/bx/c",
                &moved
            )),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/cfg/./bx/c",
                &moved
            )),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cfg/c", &moved),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("EDITOR", "/var/home/example/.config/bx/ed", &moved)),
            Some(Reason::InsideConfigRepo)
        );
        // A home of `/x` whose whole tree is a root: the repo under it is
        // still refused.
        let x = RootSet::new(Path::new("/x"), &[PathBuf::from("~")]);
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x/.config/bx/cargo", &x)),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(check("CARGO_HOME", "/x/cargo", &x), Verdict::Allowed);
        // bx's state directory is checked first: it is the stronger claim.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/home/example/.local/state/bx",
                &home_rooted
                    .clone()
                    .with_config_repos(&[PathBuf::from("/var/home/example/.local/state/bx")])
            )),
            Some(Reason::BxOwnedDirectory)
        );
    }

    #[test]
    fn a_location_is_the_one_path_its_tool_reads() {
        // cargo reads `CARGO_HOME` as one path, `:` and all. Each entry of this
        // value is inside the root, and the whole string is not: `example:` is
        // one component, a sibling of the root. Since #45 its first entry is
        // the root itself, which is refused first, for either kind. With every
        // entry strictly beneath a root, the whole string begins with its first
        // entry's parent, so it lies inside that root too.
        let joined = "/var/mnt/scratch/example:/var/mnt/scratch/example/y";
        for name in ["CARGO_HOME", "GOPATH"] {
            assert_eq!(
                reason_of(&check(name, joined, &rooted())),
                Some(Reason::DeclaredRootItself),
                "{name}"
            );
        }
        let beneath = "/var/mnt/scratch/example/x:/var/mnt/scratch/example/y";
        for name in ["CARGO_HOME", "GOPATH"] {
            assert_eq!(check(name, beneath, &rooted()), Verdict::Allowed, "{name}");
        }
        // `GOPATH` is a list go splits at `:`, so each entry is the path.
        assert_eq!(
            reason_of(&check(
                "GOPATH",
                "/var/mnt/scratch/example/go:/etc/evil",
                &rooted()
            )),
            Some(Reason::OutsideDeclaredRoots)
        );
        // The review's climbing case: its entries normalise inside the root
        // and the whole string outside it. Since r3 round 2 its `..` is refused
        // before either, whichever kind holds it.
        let climbing = "/var/mnt/scratch/example/x:/../../../var/mnt/scratch/example/y";
        for name in ["CARGO_HOME", "GOPATH"] {
            assert_eq!(
                reason_of(&check(name, climbing, &rooted())),
                Some(Reason::ParentComponent),
                "{name}"
            );
        }
        // An entry that is refused keeps its own reason, and a value with no
        // `:` is one path either way.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/k:",
                &rooted()
            )),
            Some(Reason::NotAbsolute)
        );
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cargo", &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_search_list_extended_twice_still_extends_the_inherited_list() {
        use Reason::{NotAbsolute, Unreadable, UnreadableReference, UnresolvedReference};
        for roots in [rooted(), RootSet::strict()] {
            for (content, expected) in [
                // The second `$PATH` is the first extension of the inherited
                // list, which is the user's and is not judged.
                ("export PATH=/a:$PATH\nexport PATH=/b:$PATH\n", vec![]),
                (
                    "PATH=/a:$PATH\nPATH=/b:$PATH\nexport PATH=/c:$PATH\n",
                    vec![],
                ),
                (
                    "export INFOPATH=/a:$INFOPATH\nexport INFOPATH=/b:$INFOPATH\n",
                    vec![],
                ),
                // What the first extension added is still judged.
                (
                    "export PATH=/a:$PATH\nexport PATH=./x:$PATH\n",
                    vec![(2, NotAbsolute)],
                ),
                (
                    "export PATH=./x:$PATH\nexport PATH=/b:$PATH\n",
                    vec![(1, NotAbsolute), (2, NotAbsolute)],
                ),
                // Another name still cannot use it: its value is not known.
                (
                    "export PATH=/a:$PATH\nexport EDITOR=$PATH\n",
                    vec![(2, UnresolvedReference)],
                ),
                // A list assigned outright replaces the extension.
                (
                    "export PATH=/a:$PATH\nexport PATH=/usr/bin\nexport PATH=./x:$PATH\n",
                    vec![(3, NotAbsolute)],
                ),
                // An extension that does not resolve replaces the one before
                // it: a later extension may not reach past it to line 1's.
                (
                    "export PATH=/a:$PATH\nexport PATH=${UNDEFINED}:$PATH\nexport PATH=/z:$PATH\n",
                    vec![(2, UnresolvedReference), (3, UnresolvedReference)],
                ),
                // After a line the guard could not read, nothing is inherited.
                (
                    "export PATH=/a:$PATH\ntrue\nexport PATH=/b:$PATH\n",
                    vec![(2, Unreadable), (3, UnreadableReference)],
                ),
            ] {
                assert_eq!(reasons(content, &roots), expected, "{content:?}");
            }
        }
    }

    #[test]
    fn a_reference_to_the_home_with_no_home_says_so() {
        // `scan` has no home to expand `~` or `$HOME` against. Saying that the
        // fragment has not assigned `HOME` would send a reader looking for an
        // assignment no fragment may make.
        let strict = RootSet::strict();
        for (name, value) in [
            ("EDITOR", "$HOME/bin/nvim"),
            ("EDITOR", "${HOME}/bin/nvim"),
            ("VISUAL", "~/bin/nvim"),
            ("PATH", "$HOME/bin:$PATH"),
            ("SSH_AUTH_SOCK", "~/agent"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &strict)),
                Some(Reason::NoHome),
                "{name}={value}"
            );
        }
        // A name that took its value from the home says the same.
        assert_eq!(
            reasons("export X=$HOME\nexport EDITOR=$X\n", &strict),
            vec![(1, Reason::NotEmittable), (2, Reason::NoHome)]
        );
        // A set with a home expands it, and a location with no root is
        // refused for that before its value is looked at.
        assert_eq!(
            check("EDITOR", "$HOME/bin/nvim", &rooted()),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~/cargo", &strict)),
            Some(Reason::NoRootsDeclared)
        );
    }

    #[test]
    fn the_init_snippet_is_not_an_environment_fragment() {
        // Invariant 2 sends bx's generated environment fragments through the
        // guard. The shell-init snippet is fixed text from bx's source — a
        // staleness test, a completion function, a `compdef` — that sets only
        // `BX_` names and gets every other variable by sourcing a guarded
        // fragment. The guard reads none of those statements, which is why the
        // invariant does not send the snippet to it.
        let snippet = include_str!("../bench/fixtures/bx/bx-init.zsh");
        assert_eq!(
            reasons(snippet, &RootSet::strict()),
            [8, 12, 13, 14, 15, 16, 17].map(|line| (line, Reason::Unreadable))
        );
    }

    #[test]
    fn a_path_a_tool_may_expand_or_that_climbs_is_refused() {
        use Reason::{NoRootsDeclared, ParentComponent, UnlistedCharacter};
        // The review's npm fragment, judged at the guard. A real shell holds
        // the cache value as the literal below, so the real-shell tests cannot
        // see what happens next: npm expands `${EDITOR}` inside the value
        // itself, resolves `<root>//../../../../../../var/home/example/.local/state/bx`,
        // and writes its logs into bx's state directory. So the guard refuses
        // the shape rather than modelling each tool: no location holds `$`,
        // `{` or `%` once the shell has resolved it, and no path of any kind
        // has a `..` component.
        let roots = RootSet::new(Path::new(HOME), &[PathBuf::from("/var/home/example/r")]);
        let fragment = "export EDITOR=/../../../../../..\n\
             export NPM_CONFIG_CACHE='/var/home/example/r/${EDITOR}/var/home/example/.local/state/bx'\n";
        assert_eq!(
            reasons(fragment, &roots),
            vec![(1, ParentComponent), (2, UnlistedCharacter('$'))]
        );
        // Each expansion character, in a location and in any entry of a list
        // of locations, quoted so that the shell leaves it alone.
        for value in [
            "'/var/mnt/scratch/example/${X}'",
            "'/var/mnt/scratch/example/$X'",
            "\"/var/mnt/scratch/example/{a}\"",
            "/var/mnt/scratch/example/%APPDATA%",
            "'/var/mnt/scratch/example/go:/var/mnt/scratch/example/$X'",
        ] {
            for name in ["CARGO_HOME", "GOPATH", "NUGET_PACKAGES"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    Some(UnlistedCharacter(
                        value
                            .chars()
                            .find(|c| "${%".contains(*c))
                            .expect("an expansion character")
                    )),
                    "{name}={value}"
                );
            }
        }
        // A `..` in every path-valued kind, even where it lands inside a root.
        for (name, value) in [
            ("CARGO_HOME", "/var/mnt/scratch/example/a/../cargo"),
            (
                "GOPATH",
                "/var/mnt/scratch/example/go:/var/mnt/scratch/example/a/../b",
            ),
            ("EDITOR", "/usr/bin/../bin/nvim"),
            ("PATH", "/usr/local/../bin:$PATH"),
            ("SSH_AUTH_SOCK", "/run/user/../agent"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(ParentComponent),
                "{name}={value}"
            );
        }
        // A kind that needs no root is refused for it with no root too; a
        // location is refused for having no root first.
        for (name, value) in [
            ("EDITOR", "/usr/bin/../bin/nvim"),
            ("PATH", "/usr/local/../bin:$PATH"),
            ("SSH_AUTH_SOCK", "/run/user/../agent"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &RootSet::strict())),
                Some(ParentComponent),
                "{name}={value}"
            );
        }
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/a/../cargo",
                &RootSet::strict()
            )),
            Some(NoRootsDeclared)
        );
        // A `.` component, and dots inside a name, are neither.
        assert_eq!(
            check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/./a..b/cargo",
                &rooted()
            ),
            Verdict::Allowed
        );
        assert_eq!(
            check("EDITOR", "/opt/a..b/nvim", &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_location_may_not_contain_bxs_own_directories() {
        use Reason::{BxOwnedDirectory, ContainsBxDirectory, InsideConfigRepo};
        // A tool clears its own cache: `uv cache clean` on an approved
        // `UV_CACHE_DIR=~/.local/state` deleted bx's ledger with it
        // (invariant 4). So a location may neither be inside bx's directories
        // nor contain them.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(
            reasons("export UV_CACHE_DIR=~/.local/state\n", &home_rooted),
            vec![(1, ContainsBxDirectory)]
        );
        for (name, value) in [
            ("UV_CACHE_DIR", "~/.config"),
            ("SCCACHE_DIR", "~/.local/state"),
            ("GOMODCACHE", "~/.local"),
            ("XDG_CACHE_HOME", "~/.local/state"),
            ("CARGO_HOME", "~"),
            ("GOPATH", "/var/home/example/go:/var/home/example/.local"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &home_rooted)),
                Some(ContainsBxDirectory),
                "{name}={value}"
            );
        }
        // bx's directories themselves keep their own reasons, and a sibling
        // or a directory beside them is fine.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~/.local/state/bx", &home_rooted)),
            Some(BxOwnedDirectory)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~/.config/bx", &home_rooted)),
            Some(InsideConfigRepo)
        );
        for value in [
            "~/.local/share",
            "~/.local/state/bxtra",
            "~/.config/other",
            "~/.cache",
        ] {
            assert_eq!(
                check("CARGO_HOME", value, &home_rooted),
                Verdict::Allowed,
                "{value}"
            );
        }
        // Directories the caller adds count the same way.
        let moved = rooted()
            .owning(&[PathBuf::from("/var/mnt/scratch/example/state/bx")])
            .with_config_repos(&[PathBuf::from("/var/mnt/scratch/example/cfg/bx")]);
        // Without them, the root itself is still refused for being one (#45),
        // which containing bx's directories outranks above.
        for (value, unmoved) in [
            ("/var/mnt/scratch/example/state", None),
            ("/var/mnt/scratch/example/cfg", None),
            ("/var/mnt/scratch/example", Some(Reason::DeclaredRootItself)),
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &moved)),
                Some(ContainsBxDirectory),
                "{value}"
            );
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                unmoved,
                "{value}"
            );
        }
        // A program, a search list or a socket is not cleared by its tool.
        for (name, value) in [
            ("EDITOR", "/var/home/example/.local"),
            ("PATH", "/var/home/example/.local:$PATH"),
            ("SSH_AUTH_SOCK", "/var/home/example/.config"),
        ] {
            assert_eq!(check(name, value, &home_rooted), Verdict::Allowed, "{name}");
        }
        // The operator fragment contains none of them.
        assert_eq!(scan_with(OPERATOR_FRAGMENT, &rooted()), vec![]);
        assert_eq!(scan(OPERATOR_FRAGMENT).len(), 25);
    }

    #[test]
    fn a_path_holds_only_the_characters_every_path_bx_writes_is_made_of() {
        use Reason::{NotAProgram, UnlistedCharacter};
        // The review's bun value. bun takes `\` for a path separator on
        // Linux, so to bun this one component climbs out of the root into bx's
        // state directory, and `bun pm cache rm` deleted the ledger. To the
        // guard it was a single component inside the root, with no `..` and
        // none of `$`, `{` or `%`: a list of known-bad characters missed it.
        let climb = r"'/var/mnt/scratch/example/a\..\..\..\..\..\var\home\example\.local\state\bx'";
        for name in ["BUN_INSTALL_CACHE_DIR", "BUN_INSTALL"] {
            assert_eq!(
                reason_of(&check(name, climb, &rooted())),
                Some(UnlistedCharacter('\\')),
                "{name}"
            );
        }
        // Every other character is refused by name, in a location and in an
        // entry of a list of locations.
        for (value, unlisted) in [
            ("'/var/mnt/scratch/example/${X}'", '$'),
            ("\"/var/mnt/scratch/example/{a}\"", '{'),
            ("/var/mnt/scratch/example/%APPDATA%", '%'),
            ("\"/var/mnt/scratch/example/my cache\"", ' '),
            ("\"/var/mnt/scratch/example/a~b\"", '~'),
            ("/var/mnt/scratch/example/a@b", '@'),
            ("/var/mnt/scratch/example/a,b", ','),
            ("\"/var/mnt/scratch/example/a#b\"", '#'),
            ("'/var/mnt/scratch/example/a=b'", '='),
        ] {
            for name in ["CARGO_HOME", "GOPATH"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    Some(UnlistedCharacter(unlisted)),
                    "{name}={value}"
                );
            }
        }
        // A search-list entry and a socket hold the same characters, and need
        // no root. A socket is one path, so a `:` in it is refused too.
        for roots in [rooted(), RootSet::strict()] {
            for (name, value, unlisted) in [
                ("PATH", r"'/usr/a\b:/usr/bin'", '\\'),
                ("PATH", "\"/usr/my bin:$PATH\"", ' '),
                ("INFOPATH", "/usr/share/a@b:$INFOPATH", '@'),
                ("SSH_AUTH_SOCK", "\"/run/an agent/socket\"", ' '),
                ("SSH_AUTH_SOCK", "/run/a:b", ':'),
                ("SSH_AUTH_SOCK", r"'/run/a\b'", '\\'),
            ] {
                assert_eq!(
                    reason_of(&check(name, value, &roots)),
                    Some(UnlistedCharacter(unlisted)),
                    "{name}={value}"
                );
            }
        }
        // `:` between a location's entries is the separator, not a character
        // of any path, and every allowed character passes.
        for (name, value) in [
            (
                "CARGO_HOME",
                "/var/mnt/scratch/example/k:/var/mnt/scratch/example/l",
            ),
            (
                "GOPATH",
                "/var/mnt/scratch/example/go:/var/mnt/scratch/example/b",
            ),
            ("CARGO_HOME", "/var/mnt/scratch/example/a.b_c-d+e/F9"),
        ] {
            assert_eq!(
                check(name, value, &rooted()),
                Verdict::Allowed,
                "{name}={value}"
            );
        }
        for (name, value) in [
            ("PATH", "/opt/x_y-1.2+b/bin:$PATH"),
            ("SSH_AUTH_SOCK", "/run/user/1000/gnupg/S.gpg-agent.ssh"),
        ] {
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
        // A program keeps its own, stricter rule.
        assert_eq!(
            reason_of(&check("EDITOR", "\"/usr/bin/a b\"", &rooted())),
            Some(NotAProgram)
        );
    }

    #[test]
    fn bun_reads_a_backslash_as_a_separator_and_the_guard_refuses_it() {
        // The mechanism behind the character allowlist, held to a real bun when
        // one is installed. Everything is in a temporary directory, the home
        // included, and `bun pm cache` only prints where the cache would be.
        let Some(bun) = installed("bun") else {
            return;
        };
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let root = scratch.path().join("r");
        let home = scratch.path().join("h");
        let state = home.join(".local/state/bx");
        std::fs::create_dir_all(root.join("a")).expect("the root");
        std::fs::create_dir_all(&state).expect("a stand-in state directory");
        std::fs::write(
            scratch.path().join("package.json"),
            "{\"name\":\"p\",\"version\":\"0.0.0\"}\n",
        )
        .expect("a package to run bun in");
        let value = format!(r"{}/a\..\..\h\.local\state\bx", root.display());
        let output = std::process::Command::new(bun)
            .args(["pm", "cache"])
            .current_dir(scratch.path())
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/nonexistent")
            .env("BUN_INSTALL_CACHE_DIR", &value)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("an installed bun runs");
        let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(
            paths::normalize(Path::new(&printed)),
            paths::normalize(&state),
            "bun read {value:?} as {printed:?} ({}; stderr {:?})",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let roots = RootSet::new(&home, std::slice::from_ref(&root));
        assert_eq!(
            reason_of(&check(
                "BUN_INSTALL_CACHE_DIR",
                &format!("'{value}'"),
                &roots
            )),
            Some(Reason::UnlistedCharacter('\\'))
        );
    }

    #[test]
    fn an_anchor_may_contain_bxs_directories_and_a_tool_read_location_may_not() {
        use Reason::{
            BxOwnedDirectory, ContainsBxDirectory, InsideConfigRepo, NoRootsDeclared,
            OutsideDeclaredRoots, ParentComponent, UnlistedCharacter,
        };
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for name in ["SCRATCH_HOME", "CACHE_DIR", "DATA_DIR"] {
            assert_eq!(emittable(name), Some(Kind::Anchor), "{name}");
        }
        // The operator's fragment written in terms of the home, under a `~`
        // root: the anchor names the home, which holds bx's directories, and
        // no tool reads or clears it.
        let at_home = OPERATOR_FRAGMENT.replacen(
            "export SCRATCH_HOME=\"/var/mnt/scratch/example\"",
            "export SCRATCH_HOME=\"$HOME\"",
            1,
        );
        assert_ne!(at_home, OPERATOR_FRAGMENT);
        assert_eq!(scan_with(&at_home, &home_rooted), vec![]);
        // The operator fragment under the three layouts: the home beside the
        // scratch root, the home equal to it, and the home under it.
        for roots in [
            rooted(),
            RootSet::new(Path::new(ROOT), &[PathBuf::from(ROOT)]),
            RootSet::new(
                Path::new("/var/mnt/scratch/example/home"),
                &[PathBuf::from(ROOT)],
            ),
        ] {
            assert_eq!(scan_with(OPERATOR_FRAGMENT, &roots), vec![], "{roots:?}");
        }
        assert_eq!(scan(OPERATOR_FRAGMENT).len(), 25);
        // A tool-read location is still refused for containing them, whether
        // it names the directory itself or is written in terms of an anchor
        // that does.
        assert_eq!(
            reason_of(&check("UV_CACHE_DIR", "~/.local/state", &home_rooted)),
            Some(ContainsBxDirectory)
        );
        assert_eq!(
            reasons(
                "export SCRATCH_HOME=~/.local/state\nexport UV_CACHE_DIR=$SCRATCH_HOME\n",
                &home_rooted
            ),
            vec![(2, ContainsBxDirectory)]
        );
        // Every other check a location's one path has, an anchor keeps.
        for (value, reason) in [
            ("~/.local/state/bx", BxOwnedDirectory),
            ("~/.config/bx/x", InsideConfigRepo),
            ("~/a/../b", ParentComponent),
            ("\"/var/home/example/a b\"", UnlistedCharacter(' ')),
            (
                "/var/home/example/a:/var/home/example/b",
                UnlistedCharacter(':'),
            ),
            ("scratch", Reason::NotAbsolute),
        ] {
            assert_eq!(
                reason_of(&check("SCRATCH_HOME", value, &home_rooted)),
                Some(reason),
                "{value}"
            );
        }
        assert_eq!(
            reason_of(&check("CACHE_DIR", "/etc", &rooted())),
            Some(OutsideDeclaredRoots)
        );
        assert_eq!(
            reason_of(&check("DATA_DIR", ROOT, &RootSet::strict())),
            Some(NoRootsDeclared)
        );
    }

    #[test]
    fn a_location_at_a_declared_root_is_refused_because_its_tool_may_write_beside_it() {
        use Reason::DeclaredRootItself;
        // uv puts executables in `$XDG_DATA_HOME/../bin`. With the value at the
        // root, that directory is beside the root and outside every one.
        for value in [ROOT.to_string(), format!("{ROOT}/")] {
            assert_eq!(
                reason_of(&check("XDG_DATA_HOME", &value, &rooted())),
                Some(DeclaredRootItself),
                "{value}"
            );
        }
        assert_eq!(
            reasons(
                &format!("export SCRATCH_HOME={ROOT}\nexport XDG_DATA_HOME=$SCRATCH_HOME\n"),
                &rooted()
            ),
            vec![(2, DeclaredRootItself)]
        );
        for value in [format!("{ROOT}/.local/share"), format!("{ROOT}/data")] {
            assert_eq!(
                check("XDG_DATA_HOME", &value, &rooted()),
                Verdict::Allowed,
                "{value}"
            );
        }
        // The rule is by shape, not by name: no tool-read location may be a
        // root, and no entry of a list of them may be either.
        for (name, kind) in EMITTABLE {
            if matches!(kind, Kind::Location | Kind::LocationList) {
                assert_eq!(
                    reason_of(&check(name, ROOT, &rooted())),
                    Some(DeclaredRootItself),
                    "{name}"
                );
            }
        }
        assert_eq!(
            reason_of(&check("GOPATH", &format!("{ROOT}/go:{ROOT}"), &rooted())),
            Some(DeclaredRootItself)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", &format!("{ROOT}:{ROOT}/x"), &rooted())),
            Some(DeclaredRootItself)
        );
        // One level: a root nested in another lies beneath the outer one, and
        // the outer one is still a root itself.
        let nested = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from("/var/mnt/scratch"), PathBuf::from(ROOT)],
        );
        assert_eq!(check("XDG_DATA_HOME", ROOT, &nested), Verdict::Allowed);
        assert_eq!(
            reason_of(&check("XDG_DATA_HOME", "/var/mnt/scratch", &nested)),
            Some(DeclaredRootItself)
        );
        // An anchor may be a root: no tool is known to read one.
        for name in ["SCRATCH_HOME", "DATA_DIR"] {
            assert_eq!(check(name, ROOT, &rooted()), Verdict::Allowed, "{name}");
        }
        // A search list and a socket need no root, so being one is no matter.
        assert_eq!(
            check("PATH", &format!("\"{ROOT}:$PATH\""), &rooted()),
            Verdict::Allowed
        );
        assert_eq!(check("SSH_AUTH_SOCK", ROOT, &rooted()), Verdict::Allowed);
    }

    #[test]
    fn uv_puts_executables_beside_its_data_home_and_the_guard_refuses_a_root() {
        // The mechanism behind `DeclaredRootItself`, held to a real uv when one
        // is installed. `dir --bin` only prints where executables would go, and
        // the home, the root and anything uv writes are in a temporary
        // directory.
        let Some(uv) = installed("uv") else {
            return;
        };
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let root = scratch.path().join("r");
        let home = scratch.path().join("h");
        std::fs::create_dir_all(&root).expect("the root");
        std::fs::create_dir_all(&home).expect("the home");
        let roots = RootSet::new(&home, std::slice::from_ref(&root));
        let bin_dir = |data_home: &Path, args: &[&str]| {
            let output = std::process::Command::new(&uv)
                .args(args)
                .current_dir(scratch.path())
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/nonexistent")
                .env("UV_NO_CONFIG", "1")
                .env("XDG_DATA_HOME", data_home)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("an installed uv runs");
            let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
            assert!(
                output.status.success() && !printed.is_empty(),
                "uv {args:?} printed {printed:?} ({}; stderr {:?})",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            paths::normalize(Path::new(&printed))
        };
        for args in [["tool", "dir", "--bin"], ["python", "dir", "--bin"]] {
            let beside = bin_dir(&root, &args);
            assert_eq!(
                beside,
                paths::normalize(&scratch.path().join("bin")),
                "{args:?}"
            );
            assert!(!roots.contains(&beside), "{args:?}");
            let beneath = bin_dir(&root.join("share"), &args);
            assert_eq!(beneath, paths::normalize(&root.join("bin")), "{args:?}");
            assert!(roots.contains(&beneath), "{args:?}");
        }
        assert_eq!(
            reason_of(&check("XDG_DATA_HOME", &root.display().to_string(), &roots)),
            Some(Reason::DeclaredRootItself)
        );
        assert_eq!(
            check(
                "XDG_DATA_HOME",
                &root.join("share").display().to_string(),
                &roots
            ),
            Verdict::Allowed
        );
    }

    #[test]
    fn the_operator_fragment_and_a_data_home_beneath_its_root_scan_clean_in_all_three_layouts() {
        use Reason::{ContainsBxDirectory, DeclaredRootItself};
        // The home beside the scratch root, equal to it, and under it. A data
        // home at the root is refused in each: beside, because uv would write
        // beside the root; equal and under, because the root holds bx's
        // directories, which outranks it.
        for (roots, at_root) in [
            (rooted(), DeclaredRootItself),
            (
                RootSet::new(Path::new(ROOT), &[PathBuf::from(ROOT)]),
                ContainsBxDirectory,
            ),
            (
                RootSet::new(
                    Path::new("/var/mnt/scratch/example/home"),
                    &[PathBuf::from(ROOT)],
                ),
                ContainsBxDirectory,
            ),
        ] {
            assert_eq!(scan_with(OPERATOR_FRAGMENT, &roots), vec![], "{roots:?}");
            let beneath = format!("{OPERATOR_FRAGMENT}export XDG_DATA_HOME=\"$DATA_DIR\"\n");
            assert_eq!(scan_with(&beneath, &roots), vec![], "{roots:?}");
            let at = format!("{OPERATOR_FRAGMENT}export XDG_DATA_HOME=\"$SCRATCH_HOME\"\n");
            assert_eq!(reasons(&at, &roots), vec![(26, at_root)], "{roots:?}");
        }
        // Written in terms of the home, under a `~` root.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let at_home = OPERATOR_FRAGMENT.replacen(
            "export SCRATCH_HOME=\"/var/mnt/scratch/example\"",
            "export SCRATCH_HOME=\"$HOME\"",
            1,
        );
        assert_ne!(at_home, OPERATOR_FRAGMENT);
        assert_eq!(scan_with(&at_home, &home_rooted), vec![]);
        assert_eq!(
            reasons(
                &format!("{at_home}export XDG_DATA_HOME=\"$SCRATCH_HOME\"\n"),
                &home_rooted
            ),
            vec![(26, ContainsBxDirectory)]
        );
        let found = scan(OPERATOR_FRAGMENT);
        assert_eq!(found.len(), 25);
        assert!(found.iter().all(|v| v.reason == Reason::NoRootsDeclared));
    }

    #[test]
    fn ordinary_settings_programs_and_lists_stay_allowed_beside_a_root() {
        for roots in [rooted(), RootSet::strict()] {
            for (name, value) in [
                ("SCCACHE_CACHE_SIZE", "10G"),
                ("MISE_JOBS", "8"),
                ("UV_NO_CACHE", "1"),
                ("MISE_VERBOSE", "0"),
                ("CARGO_TERM_COLOR", "always"),
                ("LANG", "C.UTF-8"),
                ("EDITOR", "nvim"),
                ("EDITOR", "/usr/bin/nvim"),
                ("SSH_AUTH_SOCK", "/run/user/1000/ssh-agent"),
            ] {
                assert_eq!(
                    check(name, value, &roots),
                    Verdict::Allowed,
                    "{name}={value} {roots:?}"
                );
            }
        }
        // A home is needed to expand `$HOME`, and the strict set has none.
        assert_eq!(
            check("PATH", "\"$HOME/.local/bin:$PATH\"", &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_path_refused_for_its_characters_is_refused_for_that_before_where_it_is() {
        use Reason::{BxOwnedDirectory, ContainsBxDirectory, UnlistedCharacter};
        // The order the checks run in is part of the verdict. The allowlist
        // comes first: a value bx cannot read as a path is refused for that
        // before any reasoning about where it is. Each of these values also
        // contains, is, or lies inside a directory the caller added.
        let odd = rooted()
            .owning(&[PathBuf::from("/var/mnt/scratch/example/a b/state/bx")])
            .with_config_repos(&[PathBuf::from("/var/mnt/scratch/example/c d/bx")]);
        for (name, value) in [
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b/state\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/c d\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b/state/bx\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/c d/bx/x\""),
            ("GOPATH", "\"/var/mnt/scratch/example/a b\""),
            ("SCRATCH_HOME", "\"/var/mnt/scratch/example/a b\""),
            ("SCRATCH_HOME", "\"/var/mnt/scratch/example/a b/state/bx\""),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &odd)),
                Some(UnlistedCharacter(' ')),
                "{name}={value}"
            );
        }
        // Without the character the containment reasons stand, and an anchor
        // may contain what a tool-read location may not.
        let plain = rooted().owning(&[PathBuf::from("/var/mnt/scratch/example/ab/state/bx")]);
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/var/mnt/scratch/example/ab", &plain)),
            Some(ContainsBxDirectory)
        );
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/ab/state/bx",
                &plain
            )),
            Some(BxOwnedDirectory)
        );
        assert_eq!(
            check("SCRATCH_HOME", "/var/mnt/scratch/example/ab", &plain),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check(
                "SCRATCH_HOME",
                "/var/mnt/scratch/example/ab/state/bx",
                &plain
            )),
            Some(BxOwnedDirectory)
        );
    }

    #[test]
    fn no_character_outside_the_allowlist_passes_any_path_valued_kind() {
        // The r3 round 3 self-sweep. Every round from 3 to 6 reopened this
        // class — a character a tool reads its own way — so every path-valued
        // kind is tried against every character class a value can carry. The
        // grammar refuses some before any kind is judged (`Unreadable`); every
        // other one is refused by name. None is approved.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let kinds = [
            ("CARGO_HOME", "/var/mnt/scratch/example/a{C}b", rooted()),
            (
                "GOPATH",
                "/var/mnt/scratch/example/go:/var/mnt/scratch/example/a{C}b",
                rooted(),
            ),
            ("SCRATCH_HOME", "/var/home/example/a{C}b", home_rooted),
            ("PATH", "/usr/a{C}b:/usr/bin", RootSet::strict()),
            ("INFOPATH", "/usr/share/a{C}b", RootSet::strict()),
            ("SSH_AUTH_SOCK", "/run/a{C}b", RootSet::strict()),
        ];
        let characters = [
            '\\', '$', '{', '}', '%', '~', '@', '!', '*', '?', '[', ']', ' ', '\t', '"', '\'', '`',
            '#', '=', ',', ';', '&', '|', '<', '>', '(', ')', '^', 'é', '\u{0}', '\u{7}', '\u{1b}',
            '\r', '\u{7f}', ':',
        ];
        for (name, template, roots) in &kinds {
            for character in characters {
                let value = template.replace("{C}", &character.to_string());
                // Single-quoted, the grammar holds every printable character
                // but the quote itself literally.
                for written in [format!("'{value}'"), format!("\"{value}\""), value.clone()] {
                    let reason = reason_of(&check(name, &written, roots));
                    let splits = matches!(*name, "CARGO_HOME" | "GOPATH" | "PATH" | "INFOPATH");
                    match reason {
                        Some(Reason::UnlistedCharacter(found)) => {
                            assert_eq!(found, character, "{name}={written:?}");
                        }
                        // The grammar's own refusal, before any kind.
                        Some(Reason::Unreadable) => {}
                        // A `:` splits a list, leaving the relative entry `b`.
                        Some(Reason::NotAbsolute) if character == ':' && splits => {}
                        // A bare `$b` is a reference, and `~b` is not the home.
                        Some(Reason::UnresolvedReference) if character == '$' => {}
                        other => panic!("{name}={written:?} gave {other:?}"),
                    }
                }
            }
        }
        // Components: `..` is refused in every path-valued kind, `.` and `//`
        // fold away, and a trailing `/` names the same directory.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for (name, value, roots, expected) in [
            (
                "CARGO_HOME",
                "~/a/../b",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "GOPATH",
                "/var/home/example/go:/var/home/example/..",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "SCRATCH_HOME",
                "~/..",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "EDITOR",
                "/usr/bin/../nvim",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "PATH",
                "/usr/..:$PATH",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "SSH_AUTH_SOCK",
                "/run/../agent",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            ("CARGO_HOME", ".", &home_rooted, Some(Reason::NotAbsolute)),
            ("SCRATCH_HOME", ".", &home_rooted, Some(Reason::NotAbsolute)),
            ("PATH", ".:$PATH", &home_rooted, Some(Reason::NotAbsolute)),
            (
                "SSH_AUTH_SOCK",
                ".",
                &home_rooted,
                Some(Reason::NotAbsolute),
            ),
            ("CARGO_HOME", "~/./cargo", &home_rooted, None),
            ("CARGO_HOME", "~//cargo", &home_rooted, None),
            ("CARGO_HOME", "~/cargo/", &home_rooted, None),
            ("SCRATCH_HOME", "~//s/./t/", &home_rooted, None),
            (
                "CARGO_HOME",
                "~/.local/state/bx/",
                &home_rooted,
                Some(Reason::BxOwnedDirectory),
            ),
            (
                "CARGO_HOME",
                "~/.local//state/./",
                &home_rooted,
                Some(Reason::ContainsBxDirectory),
            ),
            ("SCRATCH_HOME", "~/.local//state/./", &home_rooted, None),
            (
                "SCRATCH_HOME",
                "~/.config/bx/",
                &home_rooted,
                Some(Reason::InsideConfigRepo),
            ),
            (
                "PATH",
                "/var/home/example/.local/state/bx//bin:$PATH",
                &home_rooted,
                Some(Reason::BxOwnedDirectory),
            ),
        ] {
            assert_eq!(
                reason_of(&check(name, value, roots)),
                expected,
                "{name}={value}"
            );
        }
        // An anchor does not carry a tool-read location past the containment
        // check: the location is judged at its own line, whatever it refers to.
        for (content, expected) in [
            (
                "export DATA_DIR=~\nexport XDG_DATA_HOME=$DATA_DIR\n",
                vec![(2, Reason::ContainsBxDirectory)],
            ),
            (
                "export CACHE_DIR=~/.local\nexport GOPATH=~/go:$CACHE_DIR\n",
                vec![(2, Reason::ContainsBxDirectory)],
            ),
            (
                "export CACHE_DIR=~/.local\nexport GOPATH=\"${CACHE_DIR}\"\n",
                vec![(2, Reason::ContainsBxDirectory)],
            ),
            (
                "export SCRATCH_HOME=~/.local/state\nexport SCCACHE_DIR=$SCRATCH_HOME/x\n",
                vec![],
            ),
        ] {
            assert_eq!(reasons(content, &home_rooted), expected, "{content:?}");
        }
    }

    #[test]
    fn bash_truncates_the_history_file_when_a_fragment_assigns_histfilesize() {
        // The mechanism behind reserving `HISTFILESIZE`: bash truncates the
        // history file the moment the name is assigned, in a non-interactive
        // shell too, so a fragment that set it would destroy bytes the user
        // wrote (invariant 1). Run against a history file in a temporary
        // directory, never a real one.
        let Some(bash) = installed("bash") else {
            return;
        };
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let history = scratch.path().join("history");
        std::fs::write(&history, "echo one\necho two\n").expect("a history file");
        std::process::Command::new(bash)
            .args(["--norc", "--noprofile", "-c", "HISTFILESIZE=0"])
            .current_dir(scratch.path())
            .env_clear()
            .env("HOME", HOME)
            .env("PATH", "/nonexistent")
            .env("HISTFILE", &history)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("an installed shell runs");
        assert_eq!(std::fs::read(&history).expect("the history file"), b"");
        assert_eq!(
            reasons("export HISTFILESIZE=0\n", &rooted()),
            vec![(1, Reason::ReservedName)]
        );
    }

    // Review round 4: a value is judged whatever it is assigned to.

    #[test]
    fn a_name_no_table_holds_is_refused_and_a_location_is_judged_whatever_its_shape() {
        use Reason::{NotAbsolute, NotEmittable};
        // Round 4 judged these by value: allowed inside a root. Round 5 does
        // not know what they hold, so it refuses each whatever it is given.
        for name in R4_UNLISTED_RELOCATIONS {
            for value in ["/etc/evil", "/var/mnt/scratch/example/x", "1"] {
                for roots in [rooted(), RootSet::strict()] {
                    assert_eq!(
                        reason_of(&check(name, value, &roots)),
                        Some(NotEmittable),
                        "{name}={value}"
                    );
                }
            }
        }
        // A location is refused anything that is not an absolute path inside
        // a root — a bare word, a number, and every URL included (round 5).
        for (value, reason) in [
            (".", NotAbsolute),
            ("..", NotAbsolute),
            ("build/cache", NotAbsolute),
            ("a:.", NotAbsolute),
            // The home contains bx's directories (r3 round 2).
            ("~", Reason::ContainsBxDirectory),
            ("\"~x\"", NotAbsolute),
            // Its first entry is the root itself, refused before `a` (#45).
            ("/var/mnt/scratch/example:a", Reason::DeclaredRootItself),
            ("/var/mnt/scratch/example/x:a", NotAbsolute),
            ("file:///var/mnt/scratch/example", NotAbsolute),
            ("1+x://y", NotAbsolute),
            ("", NotAbsolute),
            ("1", NotAbsolute),
            ("a:b", NotAbsolute),
            ("...", NotAbsolute),
            (".x", NotAbsolute),
            ("\"-j8 V=1\"", NotAbsolute),
            ("https://example.invalid/a:b", NotAbsolute),
            ("git+ssh://example.invalid/x", NotAbsolute),
            ("s3.a-b://bucket/key", NotAbsolute),
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(reason),
                "{value:?}"
            );
        }
        // Of the round-4 brief's settings, the ones the table lists still pass
        // with no root declared; the others are not emittable.
        for (name, value) in [("UV_NO_CACHE", "1"), ("MISE_JOBS", "8"), ("EDITOR", "nvim")] {
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
        for (name, value) in [
            ("MAKEFLAGS", "\"-j8 V=1\""),
            ("CARGO_BUILD_TARGET", "x86_64-unknown-linux-gnu"),
            ("HISTFILE", "history"),
            ("PIP_NO_CACHE_DIR", "1"),
            ("JAVA_HOME", "/usr/lib/jvm/java-21"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &RootSet::strict())),
                Some(NotEmittable),
                "{name}"
            );
        }
    }

    #[test]
    fn a_name_whose_assignment_the_shell_acts_on_is_reserved() {
        for name in ACTS_ON_ASSIGNMENT {
            assert_eq!(
                reason_of(&check(name, "0", &rooted())),
                Some(Reason::ReservedName),
                "{name}"
            );
        }
        // Refused as assignments, and as references, and it forgets.
        assert_eq!(
            reasons(
                "HISTFILESIZE=0\nexport CARGO_HOME=/var/mnt/scratch/example/$HISTFILESIZE\n",
                &rooted()
            ),
            vec![(1, Reason::ReservedName), (2, Reason::UnreadableReference)]
        );
        assert_eq!(
            Scope::default().lookup("PROMPT_COMMAND", None),
            Err(Reason::ReservedName)
        );
        // `HISTFILE` is not reserved — assigning it writes nothing — and no
        // generator writes one, so it is not in the emit table either.
        for value in ["/var/mnt/scratch/example/history", "/etc/evil"] {
            assert_eq!(
                reason_of(&check("HISTFILE", value, &rooted())),
                Some(Reason::NotEmittable),
                "{value}"
            );
        }
    }

    #[test]
    fn a_search_list_or_a_program_needs_no_root_but_every_entry_is_anchored() {
        use Reason::{BxOwnedDirectory, NotAbsolute, UnreadableReference, UnresolvedReference};
        let no_root = RootSet::new(Path::new(HOME), &[]);
        for (content, expected) in [
            ("export PATH=\"$HOME/.local/bin:$PATH\"\n", vec![]),
            ("export PATH=$PATH\n", vec![]),
            ("export PATH=/usr/bin:/opt/x/bin\n", vec![]),
            ("export INFOPATH=/usr/share/info:$INFOPATH\n", vec![]),
            ("export PATH=.:/usr/bin\n", vec![(1, NotAbsolute)]),
            ("export PATH=/usr/bin:\n", vec![(1, NotAbsolute)]),
            ("export PATH=bin\n", vec![(1, NotAbsolute)]),
            ("export PATH=\n", vec![(1, NotAbsolute)]),
            ("export PATH=$PATH/bin\n", vec![(1, NotAbsolute)]),
            ("export PATH=${PATH}x\n", vec![(1, NotAbsolute)]),
            ("export INFOPATH=info\n", vec![(1, NotAbsolute)]),
            (
                "export PATH=/var/home/example/.local/state/bx/bin:$PATH\n",
                vec![(1, BxOwnedDirectory)],
            ),
            // Only its own name stands for what was inherited.
            (
                "export PATH=/usr/bin:$INFOPATH\n",
                vec![(1, UnresolvedReference)],
            ),
            // Once the fragment assigns it, `$PATH` is what it assigned.
            (
                "PATH=bin\nexport PATH=/usr/bin:$PATH\n",
                vec![(1, NotAbsolute), (2, NotAbsolute)],
            ),
            // After a refused line nothing is inherited either.
            (
                "true\nexport PATH=/usr/bin:$PATH\n",
                vec![(1, Reason::Unreadable), (2, UnreadableReference)],
            ),
            ("export EDITOR=/usr/bin/nvim\n", vec![]),
            ("export EDITOR=nvim\n", vec![]),
            ("export EDITOR=\n", vec![(1, Reason::NotAProgram)]),
            ("export RUSTC_WRAPPER=/usr/bin/sccache\n", vec![]),
            (
                "export SSH_AUTH_SOCK=/run/user/1000/ssh-agent.socket\n",
                vec![],
            ),
            ("export EDITOR=./nvim\n", vec![(1, NotAbsolute)]),
            (
                "export BROWSER=/usr/bin/firefox:chromium\n",
                vec![(1, Reason::NotAProgram)],
            ),
            ("export EDITOR=$NOWHERE\n", vec![(1, UnresolvedReference)]),
            (
                "export PAGER=/var/home/example/.local/state/bx/less\n",
                vec![(1, BxOwnedDirectory)],
            ),
        ] {
            assert_eq!(reasons(content, &no_root), expected, "{content:?}");
            assert_eq!(reasons(content, &rooted()), expected, "{content:?}");
        }
        // A list or a program is not a relocation, so it does not inherit
        // `$PATH` for another name.
        assert_eq!(
            reasons(
                "export GOPATH=/var/mnt/scratch/example:$GOPATH\n",
                &rooted()
            ),
            vec![(1, UnresolvedReference)]
        );
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
        // Since round 4 every value is judged, so a form the grammar reads may
        // still be refused for where it points. What is pinned here is that no
        // accepted form is refused *as a form*, and that `check` and
        // `scan_with` agree on it.
        for value in accepted {
            let verdict = reason_of(&check("EDITOR", value, &rooted()));
            assert!(
                !matches!(
                    verdict,
                    Some(Reason::Unreadable | Reason::MultipleAssignments)
                ),
                "{value:?}: {verdict:?}"
            );
            assert_eq!(
                reasons(&format!("export EDITOR={value}"), &rooted()),
                verdict
                    .map(|reason| (1, reason))
                    .into_iter()
                    .collect::<Vec<_>>(),
                "{value:?}"
            );
        }
        for value in ["nvim", "\"nvim\"", "$HOME/x", "/x # a comment"] {
            assert_eq!(
                check("EDITOR", value, &rooted()),
                Verdict::Allowed,
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
        // Given to a location, `~` alone is the home, which contains bx's
        // directories (r3 round 2), and `/a://b` starts at the filesystem root
        // however URL-like its middle.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~", &rooted())),
            Some(Reason::ContainsBxDirectory)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/a://b", &rooted())),
            Some(Reason::OutsideDeclaredRoots)
        );
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
        // Without a home, `$HOME` is refused for having none, not reserved.
        assert_eq!(
            reason_of(&check("EDITOR", "$HOME", &RootSet::strict())),
            Some(Reason::NoHome)
        );
        let mut scope = Scope::default();
        assert_eq!(scope.lookup("HOME", None), Err(Reason::NoHome));
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
            for name in ["GOPATH", "GOMODCACHE", "CARGO_HOME"] {
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
            "CACHE_DIR=/var/mnt/scratch/example/go\n",
            "DATA_DIR=/etc/evil\n",
            "export GOPATH=\"${CACHE_DIR}:${DATA_DIR}\"\n",
            "export GOPATH=\"$CACHE_DIR:$DATA_DIR\"\n",
        );
        // `DATA_DIR=/etc/evil` is itself a location outside the root.
        assert_eq!(
            reasons(content, &rooted()),
            vec![
                (2, OutsideDeclaredRoots),
                (3, OutsideDeclaredRoots),
                (4, Reason::Unreadable)
            ]
        );
    }

    #[test]
    fn npm_config_in_any_other_case_is_not_emittable() {
        // npm reads `npm_config_*` in any case, and round 3 judged every case
        // for that. The table spells `NPM_CONFIG_CACHE` alone, so every other
        // spelling is refused whatever it is given — which is stricter than
        // judging it, and needs no knowledge of which tools ignore case.
        for name in [
            "npm_config_cache",
            "Npm_Config_Prefix",
            "npm_CONFIG_userconfig",
            "npm_config_registry",
            "uv_cache_dir",
        ] {
            for value in ["/etc/evil", ".npm", "/var/mnt/scratch/example/npm"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    Some(Reason::NotEmittable),
                    "{name}={value}"
                );
            }
        }
        assert_eq!(
            check(
                "NPM_CONFIG_CACHE",
                "/var/mnt/scratch/example/npm",
                &rooted()
            ),
            Verdict::Allowed
        );
    }

    #[test]
    fn the_names_and_location_words_the_review_found_missing_are_refused() {
        for name in [
            "ZDOTDIR",
            "YARN_CACHE_FOLDER",
            "CCACHE_DIR",
            "STARSHIP_CONFIG",
            "PYTHONUSERBASE",
            "TMPDIR",
            "MISE_SHARED_INSTALL_DIRS",
            "MISE_TRUSTED_CONFIG_PATHS",
            "UV_PROJECT",
            "MISE_DEFAULT_CONFIG_FILENAME",
        ] {
            for value in ["/etc/evil", "/var/mnt/scratch/example/x", "evil"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    Some(Reason::NotEmittable),
                    "{name}={value}"
                );
            }
        }
        assert_eq!(
            reason_of(&check("HOME", ROOT, &rooted())),
            Some(Reason::ReservedName)
        );
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

    /// Whether a shell that ended holding `name=value` — and the variables
    /// `after` — has been pointed somewhere the roots do not admit.
    ///
    /// Decided independently of the guard's emit table and ownership rules, so
    /// it cannot share a blind spot with them. Every entry shaped like a path —
    /// containing `/`, beginning `~` or `=`, or `.` or `..` — makes the whole
    /// value one the roots must admit, for any name; so does any value of a
    /// name the round-5 review saw a tool read as a location. bx's state
    /// directory is worked out here from the test home and the shell's own
    /// `XDG_STATE_HOME`, and an `XDG_CONFIG_HOME` whose `/bx` lands in it
    /// escapes. The names the shell manages are its own business. The
    /// commands, search lists and socket written out below need no root: a
    /// command escapes with a second word or a relative or owned path, and a
    /// list or socket with any relative or owned entry.
    fn escapes(name: &str, value: &str, roots: &RootSet, after: &HashMap<String, String>) -> bool {
        if SHELL_NAMES.contains(&name) {
            return false;
        }
        // bx's state directory, worked out here rather than asked of the
        // guard: under the test home, or wherever the shell's own absolute
        // `XDG_STATE_HOME` moved it.
        // bx's config repo counts as well: a tool pointed into it writes into a
        // committed tree, or runs what was committed there.
        let mut owned = vec![
            Path::new(HOME).join(".local/state/bx"),
            Path::new(HOME).join(".config/bx"),
        ];
        if let Some(state) = after
            .get("XDG_STATE_HOME")
            .filter(|state| Path::new(state).is_absolute())
        {
            owned.push(Path::new(state).join("bx"));
        }
        // A leading `=` is zsh's `=cmd`, which expands to a program's path.
        let pathish = |entry: &str| {
            entry.contains('/') || entry.starts_with(['~', '=']) || entry == "." || entry == ".."
        };
        let unanchored = |entry: &str| {
            let path = paths::normalize(Path::new(entry));
            !path.is_absolute() || owned.iter().any(|dir| path.starts_with(dir))
        };
        // A location whose tool clears it clears whatever it contains.
        let holds_bx = |entry: &str| {
            let path = paths::normalize(Path::new(entry));
            path.is_absolute() && owned.iter().any(|dir| dir.starts_with(&path))
        };
        let entries: Vec<&str> = value.split(':').collect();
        if TEST_SEARCHED_OR_REACHED.contains(&name) {
            entries.iter().any(|entry| unanchored(entry))
        } else if TEST_RUN_AS_COMMANDS.contains(&name) {
            // A tool runs the value through a shell, so a second word is an
            // argument no check looked at.
            value.split([' ', '\t']).count() > 1
                || (pathish(value) && unanchored(value))
                || entries
                    .iter()
                    .any(|entry| pathish(entry) && unanchored(entry))
        } else {
            let read_as_location = R5_READ_AS_LOCATIONS.iter().any(|(known, _)| *known == name);
            let repo_lands_in_state =
                name == "XDG_CONFIG_HOME" && unanchored(&format!("{value}/bx"));
            // A tool that reads one path reads the whole value, `:` and all.
            let whole_escapes = !TEST_COLON_LISTS.contains(&name)
                && (read_as_location || pathish(value))
                && (unanchored(value) || holds_bx(value) || !roots.contains(Path::new(value)));
            repo_lands_in_state
                || whole_escapes
                || ((read_as_location || entries.iter().any(|entry| pathish(entry)))
                    && entries.iter().any(|entry| {
                        unanchored(entry) || holds_bx(entry) || !roots.contains(Path::new(entry))
                    }))
        }
    }

    /// Names a tool runs as a command, written out here independently of the
    /// guard's table: a value escapes when it has a second word, or when a
    /// path in it is relative or inside bx's state directory.
    const TEST_RUN_AS_COMMANDS: &[&str] = &[
        "BROWSER",
        "EDITOR",
        "PAGER",
        "RUSTC_WRAPPER",
        "TERMINAL",
        "VISUAL",
    ];

    /// Lists a shell or a tool searches, and a socket it connects to, written
    /// out independently of the guard's table: every entry must be absolute
    /// and outside bx's state directory, and no root is needed.
    const TEST_SEARCHED_OR_REACHED: &[&str] = &["INFOPATH", "PATH", "SSH_AUTH_SOCK"];

    /// Lists of locations their tool splits at `:`, written out independently
    /// of the guard's table. Every other value is also read as one whole path.
    const TEST_COLON_LISTS: &[&str] = &["GOPATH"];

    /// Run `content` in every installed shell and hold the guard to what each
    /// shell did. The guard must never approve a fragment after which any
    /// variable [`escapes`] — holds a path outside `roots` or inside bx's own
    /// directory, for any name; and where the guard read every line, what it
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
                .filter(|(name, value)| escapes(name, value, roots, &after))
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
                if is_reserved(name) {
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
        "export PATH=/a:$PATH\nexport PATH=/b:$PATH\n",
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
            // Round 4: names no list held, a state directory the fragment
            // moved, a history file, and a search list with a relative entry.
            ("export RIPGREP_CONFIG_PATH=/etc/evil", rooted()),
            ("export GIT_CONFIG_SYSTEM=/etc/evil", rooted()),
            ("export CARGO_TARGET_DIR=/etc/evil", rooted()),
            ("export XDG_CONFIG_DIRS=/etc/evil", rooted()),
            ("SOMETHING=build/cache", rooted()),
            (
                "export XDG_STATE_HOME=/var/mnt/scratch/example/state\n\
                 export CARGO_HOME=/var/mnt/scratch/example/state/bx",
                rooted(),
            ),
            ("export HISTFILE=/etc/evil", rooted()),
            ("export PATH=.:/usr/bin", rooted()),
            ("export EDITOR=./nvim", rooted()),
            // Round 5: a bare word a tool reads as a path, a program given
            // arguments, a state directory a later line moves, a URL-shaped
            // relative path, bx's default state directory with no home, and a
            // config repo landing on the state directory.
            (
                "export EDITOR=\"/usr/bin/touch /var/home/example/.local/state/bx/written-by-editor\"",
                rooted(),
            ),
            (
                "export EDITOR=\"/usr/bin/env XDG_CONFIG_HOME=/etc/evil nvim\"",
                RootSet::strict(),
            ),
            (
                "export PAGER=\"/usr/bin/less --lesskey-file=/etc/evil/lesskey\"",
                rooted(),
            ),
            (
                "export CARGO_HOME=/var/mnt/scratch/example/state/bx\n\
                 export XDG_STATE_HOME=/var/mnt/scratch/example/state",
                rooted(),
            ),
            ("export EDITOR=x://ed", rooted()),
            ("export RIPGREP_CONFIG_PATH=cfg://rc", rooted()),
            ("export GIT_CONFIG_SYSTEM=https://x:/etc/evil", rooted()),
            (
                "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
                RootSet::strict(),
            ),
            (
                "export VISUAL=/var/home/example/.local/state/bx/nvim",
                RootSet::strict(),
            ),
            (
                "export SSH_AUTH_SOCK=/var/home/example/.local/state/bx/agent.sock",
                RootSet::strict(),
            ),
            ("export XDG_CONFIG_HOME=~/.local/state", home_rooted.clone()),
            // r3 round 2: a location that contains bx's state directory.
            ("export UV_CACHE_DIR=~/.local/state", home_rooted.clone()),
            // Round 6: a tool pointed into bx's config repo.
            ("export CARGO_HOME=~/.config/bx/cargo", home_rooted.clone()),
            // Round 6: a location whose entries are inside the root and whose
            // whole value, which cargo reads, is not.
            (
                "export CARGO_HOME=/var/mnt/scratch/example/x:/../../../var/mnt/scratch/example/y",
                rooted(),
            ),
        ];
        let bare_words: Vec<String> = R5_READ_AS_LOCATIONS
            .iter()
            .map(|(name, value)| format!("export {name}={value}"))
            .collect();
        let falsifiers: Vec<(&str, RootSet)> = falsifiers
            .iter()
            .map(|(content, roots)| (*content, roots.clone()))
            .chain(
                bare_words
                    .iter()
                    .map(|content| (content.as_str(), rooted())),
            )
            .collect();
        for (content, roots) in &falsifiers {
            let escaped = assert_the_shells_agree(&shells, content, roots);
            assert_ne!(scan_with(content, roots), vec![], "{content:?}");
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
            "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME=\"$SCRATCH_HOME/cargo\"",
            "SCRATCH_HOME=/var/mnt/scratch/example\nGOPATH=${SCRATCH_HOME}/go:$SCRATCH_HOME/b",
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
