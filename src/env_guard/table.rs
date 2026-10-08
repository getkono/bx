//! The guard's name space: which names a fragment may set, what each one
//! holds, and which names the shell reserves or a tool relocates through.

/// Names a shell defines and manages itself. A fragment may not assign one,
/// and may not refer to one either — except `HOME`, which
/// [`Scope::lookup`](super::scope::Scope::lookup) answers from the root set, and which is how
/// `$HOME` and `~` resolve at all.
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
/// Which modules are *bundled* is a property of the build, not of zsh, and that
/// is how a name came to be missing here. `zgdbm_tied` is defined by
/// `zsh/db/gdbm`; Ubuntu's zsh ships that module and this repository's
/// development host does not, so the probe run by hand never loaded it and
/// never saw the name. CI, on a runner that has the module, is what found it —
/// the same test, the same sweep, a larger `$module_path`.
///
/// The rest of the list was re-checked against `zshmodules(1)` rather than
/// against what is installed. `zsh/db/gdbm` is the only module that page
/// documents which this host lacks, and `zgdbm_tied` is the only parameter it
/// documents for it — `zgdbmpath` is a builtin, and it writes `REPLY` when it
/// is called. Every other name that page attaches to a module is either already
/// here or is created by an event rather than by the module loading: the
/// connection-scoped `ZFTP_*` names appear on `open` and are unset on `close`,
/// the completion specials exist only while a completion widget runs, and
/// `MATCH`, `match` and `reply` are written by `pcre_match`, `zregexparse` and
/// `zselect` when those builtins run. No build defines any of them at startup,
/// so no build can widen this list through them. What could still widen it is a
/// module no upstream manual page describes — a distribution-local one — and
/// nothing establishes that none exists; the test is what would catch it.
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
pub(super) const SHELL_NAMES: &[&str] = &[
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
    "zgdbm_tied",
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
pub(super) fn is_reserved(name: &str) -> bool {
    SHELL_NAMES.contains(&name) || ACTS_ON_ASSIGNMENT.contains(&name)
}

/// What a variable in [`EMITTABLE`] holds, and therefore how its value is
/// judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// Where a tool keeps its config, data or cache: one path. The tool reads the whole
    /// value, `:` and all, so the whole value must be an absolute path — `~`
    /// and `$HOME` expand to one — strictly beneath a declared root, never a
    /// root itself, and outside bx's own directories. A tool may derive a
    /// directory beside its own, as uv puts executables in
    /// `$XDG_DATA_HOME/../bin`, so at a root that directory is outside every
    /// root. *Strictly beneath* buys exactly one level: an approved value's
    /// parent is inside a declared root, and its grandparent need not be, so a
    /// tool deriving a path two or more levels above its value is not modelled
    /// — bx knows of none. [`Reason::DeclaredRootItself`](super::Reason::DeclaredRootItself)
    /// states the bound in full. A bare word, a relative path and a URL are all relative to
    /// wherever the shell happens to be, and are refused. Every `:`-separated
    /// entry is held to the same checks first, which costs only a path with a
    /// `:` in it. Every character is an ASCII letter or digit, `.`, `_`, `-`,
    /// `+` or `/`, with `:` only between entries.
    Location,
    /// A list of locations its tool splits at `:` and reads entry by entry —
    /// `GOPATH`. Every entry is judged as a [`Kind::Location`] is, and the
    /// whole string, which no tool reads as one path, is not.
    LocationList,
    /// A directory other assignments are written in terms of, and that bx has
    /// found no tool to read: the operator fragment's `SCRATCH_HOME` and
    /// `DATA_DIR`. A name found to be read by a tool is not an anchor.
    /// `CACHE_DIR` is read by npm's find-cache-dir (babel-loader, nyc, ava),
    /// which writes, and may clear, `$CACHE_DIR/<name>` for a name its
    /// consumer picks, so it is a [`Kind::Location`] and may not contain bx's
    /// directories. An anchor is one path held to every check a
    /// [`Kind::Location`]'s path is, but two: it may contain bx's own
    /// directories, and it may be a root. An approved anchor still lies inside
    /// a root and outside bx's directories, and every tool-read location
    /// written in terms of one is judged at its own line: containing bx's
    /// directories, lying strictly beneath a root, and the roots. So a home
    /// that is the scratch root, or lies under it, is still an anchor's to
    /// name.
    Anchor,
    /// A program a tool runs, found by name or by path: exactly one word,
    /// either an absolute path outside bx's own directories or a bare command
    /// name — a letter or digit, then letters, digits, `.`, `_`, `+` and `-`.
    /// No blank, so no argument: tools run the value through a shell, and an
    /// argument is a second path, or a second assignment, that no check reads.
    /// No `:`, `=`, `~` or URL either. Needs no root.
    Program,
    /// A command line a tool hands to a shell to run: `EDITOR`, `PAGER`,
    /// `MANPAGER`. Its first word, up to the first blank, is judged exactly as
    /// a [`Kind::Program`] is. Everything after it is judged as
    /// [`Kind::Arguments`] are, so `sh -c 'col -bx | bat -l man -p'` is one.
    /// Needs no root.
    CommandLine,
    /// Words a tool reads as its own command-line options — `LESS`. Nothing
    /// in them is held to a grammar of its own, because no grammar covers
    /// every tool's options. What is judged is what a shell running them
    /// could make of them (`refuses_arguments`): no `$`, backquote or
    /// backslash, whose meaning a later shell decides, no path that points
    /// inside a directory bx owns or its config repo, and no relocating name,
    /// which a shell could assign with or without an `=`. Needs no root.
    Arguments,
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
///
/// **The numeric bounds are chosen here, not read from each tool's parser.**
/// [`Setting::Count`]'s 1024 and [`Setting::Size`]'s six digits are what bx is
/// willing to generate; mise and sccache may well accept more. That is safe in
/// one direction only: a bound too tight refuses a value bx might have wanted
/// to write, and is widened by the change that first wants it, which refuses
/// nothing approved before. A bound too loose would approve a value its tool
/// mis-parses, and nothing downstream would catch it. No generator emits
/// `MISE_JOBS` or `SCCACHE_CACHE_SIZE` today, so no bound here has yet had to
/// be right about a real tool — only about what bx will write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Setting {
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
    /// An input-method module a toolkit loads by name — `ibus`, `fcitx`,
    /// `fcitx5`, `uim` — for `GTK_IM_MODULE` and its kin: one bare word, the
    /// same shape a locale is, and not a locale.
    InputMethod,
    /// X's input-method modifier, `XMODIFIERS`: exactly `@im=` and then an
    /// [`Setting::InputMethod`] name, as in `@im=ibus`.
    ImModifier,
}

impl Setting {
    /// Whether this setting accepts `value`.
    pub(super) fn admits(self, value: &str) -> bool {
        match self {
            Self::Switch => matches!(value, "0" | "1" | "true" | "false"),
            Self::Count => {
                is_decimal(value, 4) && value.parse::<u16>().is_ok_and(|count| count <= 1024)
            }
            Self::Size => value
                .strip_suffix(['K', 'M', 'G', 'T'])
                .is_some_and(|digits| is_decimal(digits, 6)),
            Self::OneOf(words) => words.contains(&value),
            Self::Locale | Self::InputMethod => is_bare_word(value),
            Self::ImModifier => value.strip_prefix("@im=").is_some_and(is_bare_word),
        }
    }
}

/// Whether `text` is a decimal of one to `digits` digits with no leading zero.
fn is_decimal(text: &str, digits: usize) -> bool {
    (1..=digits).contains(&text.len())
        && !text.starts_with('0')
        && text.chars().all(|c| c.is_ascii_digit())
}

/// A character of a bare word: an ASCII letter or digit, `.`, `_`, `+` or `-`.
pub(super) fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._+-".contains(c)
}

/// Whether `value` is one bare word: a letter or digit, then word characters.
/// So never empty, never `.` or `..`, never an option, never a path.
pub(super) fn is_bare_word(value: &str) -> bool {
    value.starts_with(|c: char| c.is_ascii_alphanumeric()) && value.chars().all(is_word_char)
}

/// Every variable name bx may generate, in byte order, with what it holds.
///
/// **This table is the guard's whole name space**: a name it does not list is
/// [`Reason::NotEmittable`](super::Reason::NotEmittable), whatever it is given. It must grow
/// with the generators, one name at a time, each with the kind its tool documents —
/// and a name whose tool reads it as something no kind judges (`MAKEFLAGS`
/// and `RUSTFLAGS` hold assignments and paths their tool reads its own way,
/// and `CARGO_BUILD_TARGET` takes either a word or a `.json` target file)
/// needs a kind that can judge that before it is added.
///
/// * `XDG_CACHE_HOME` and `XDG_DATA_HOME`, and the 23 relocating exports of
///   the operator fragment the module's tests hold the guard to:
///   `SCRATCH_HOME`, the anchor the fragment is written in terms of, and 22
///   toolchain caches and homes, of which `GOPATH` is a list of locations.
///   `CACHE_DIR` and `DATA_DIR` are that fragment's two unexported helpers.
///   `DATA_DIR` is an anchor too. `CACHE_DIR` is a location, because npm's
///   find-cache-dir reads it and writes beneath it. `SCCACHE_DIR` is
///   sccache's cache, the module's motivating case.
/// * `BROWSER` and `TERMINAL` — the program a tool runs to browse or open a
///   terminal — and `RUSTC_WRAPPER`, the program cargo runs `rustc` through.
/// * `EDITOR`, `VISUAL`, `PAGER` and `MANPAGER`, the command line a tool runs
///   through a shell to edit or page, and `LESS`, the options `less` reads.
/// * `PATH` and `INFOPATH`, searched for programs and documents.
/// * `SSH_AUTH_SOCK`, the running ssh agent.
/// * `SCCACHE_CACHE_SIZE` (a size), `MISE_JOBS` (a count), `UV_NO_CACHE` and
///   `MISE_VERBOSE` (switches), `CARGO_TERM_COLOR` (`auto`, `always` or
///   `never`), `LANG`, `LC_ALL` and the twelve `LC_*` categories (locales),
///   `GTK_IM_MODULE`, `QT_IM_MODULE`, `SDL_IM_MODULE` and `GLFW_IM_MODULE`
///   (input-method modules) and `XMODIFIERS` (`@im=` and a module).
///
/// `SHELL`, `MANPATH` and `HOME` would belong here and do not: each is a
/// [`SHELL_NAMES`] entry, which may not be assigned at all.
///
/// `XDG_STATE_HOME` and `XDG_CONFIG_HOME` do not belong here either. bx reads
/// them to find its own state directory and config repo, so a fragment that
/// set either would move them on bx's next run and leave the ledger, the
/// journal and `local.toml` behind (invariants 3 and 4).
pub(super) const EMITTABLE: &[(&str, Kind)] = &[
    ("ANDROID_HOME", Kind::Location),
    ("ANDROID_USER_HOME", Kind::Location),
    ("BROWSER", Kind::Program),
    ("BUN_INSTALL", Kind::Location),
    ("BUN_INSTALL_CACHE_DIR", Kind::Location),
    ("CACHE_DIR", Kind::Location),
    ("CARGO_HOME", Kind::Location),
    (
        "CARGO_TERM_COLOR",
        Kind::Setting(Setting::OneOf(&["auto", "always", "never"])),
    ),
    ("DATA_DIR", Kind::Anchor),
    ("DOTNET_CLI_HOME", Kind::Location),
    ("EDITOR", Kind::CommandLine),
    ("GLFW_IM_MODULE", Kind::Setting(Setting::InputMethod)),
    ("GOCACHE", Kind::Location),
    ("GOMODCACHE", Kind::Location),
    ("GOPATH", Kind::LocationList),
    ("GTK_IM_MODULE", Kind::Setting(Setting::InputMethod)),
    ("HOMEBREW_CACHE", Kind::Location),
    ("HOMEBREW_LOGS", Kind::Location),
    ("HOMEBREW_TEMP", Kind::Location),
    ("INFOPATH", Kind::SearchList),
    ("LANG", Kind::Setting(Setting::Locale)),
    ("LC_ADDRESS", Kind::Setting(Setting::Locale)),
    ("LC_ALL", Kind::Setting(Setting::Locale)),
    ("LC_COLLATE", Kind::Setting(Setting::Locale)),
    ("LC_CTYPE", Kind::Setting(Setting::Locale)),
    ("LC_IDENTIFICATION", Kind::Setting(Setting::Locale)),
    ("LC_MEASUREMENT", Kind::Setting(Setting::Locale)),
    ("LC_MESSAGES", Kind::Setting(Setting::Locale)),
    ("LC_MONETARY", Kind::Setting(Setting::Locale)),
    ("LC_NAME", Kind::Setting(Setting::Locale)),
    ("LC_NUMERIC", Kind::Setting(Setting::Locale)),
    ("LC_PAPER", Kind::Setting(Setting::Locale)),
    ("LC_TELEPHONE", Kind::Setting(Setting::Locale)),
    ("LC_TIME", Kind::Setting(Setting::Locale)),
    ("LESS", Kind::Arguments),
    ("MANPAGER", Kind::CommandLine),
    ("MISE_CACHE_DIR", Kind::Location),
    ("MISE_DATA_DIR", Kind::Location),
    ("MISE_JOBS", Kind::Setting(Setting::Count)),
    ("MISE_VERBOSE", Kind::Setting(Setting::Switch)),
    ("NPM_CONFIG_CACHE", Kind::Location),
    ("NUGET_HTTP_CACHE_PATH", Kind::Location),
    ("NUGET_PACKAGES", Kind::Location),
    ("PAGER", Kind::CommandLine),
    ("PATH", Kind::SearchList),
    ("PIP_CACHE_DIR", Kind::Location),
    ("PNPM_CONFIG_STORE_DIR", Kind::Location),
    ("QT_IM_MODULE", Kind::Setting(Setting::InputMethod)),
    ("RUSTC_WRAPPER", Kind::Program),
    ("RUSTUP_HOME", Kind::Location),
    ("SCCACHE_CACHE_SIZE", Kind::Setting(Setting::Size)),
    ("SCCACHE_DIR", Kind::Location),
    ("SCRATCH_HOME", Kind::Anchor),
    ("SDL_IM_MODULE", Kind::Setting(Setting::InputMethod)),
    ("SSH_AUTH_SOCK", Kind::Socket),
    ("TERMINAL", Kind::Program),
    ("UV_CACHE_DIR", Kind::Location),
    ("UV_NO_CACHE", Kind::Setting(Setting::Switch)),
    ("VISUAL", Kind::CommandLine),
    ("XDG_CACHE_HOME", Kind::Location),
    ("XDG_DATA_HOME", Kind::Location),
    ("XMODIFIERS", Kind::Setting(Setting::ImModifier)),
    ("ZIG_GLOBAL_CACHE_DIR", Kind::Location),
];

/// What `name` holds, if bx may generate it at all.
///
/// The match is exact and case-sensitive, because environment variable names
/// are: a tool that reads `CARGO_HOME` does not read `cargo_home`, and a name
/// the table does not spell is not in it.
pub(super) fn emittable(name: &str) -> Option<Kind> {
    EMITTABLE
        .iter()
        .find(|(listed, _)| *listed == name)
        .map(|(_, kind)| *kind)
}

/// Names that move a tool's config, data or cache, or the directory every
/// such default is found from, and that the emit table does not list, so
/// [`check`](super::check) refuses every value given to one. The table's own locations,
/// lists of locations and anchors, and the `XDG_*_HOME` family, are
/// relocating too; [`is_relocating`] is the whole set.
///
/// These are the names this module's review rounds found some tool reading
/// as a location — `rg` and `git` were shown to obey two of them — plus the
/// homes of the tools whose activation output bx caches (mise, starship,
/// zoxide). The list is knowledge, not a closed name space: a name missing
/// from it is one a tool's cached activation output could assign unjudged,
/// so it grows whenever a relocating name is found missing.
const UNLISTED_RELOCATIONS: &[&str] = &[
    "BAT_CONFIG_PATH",
    "BUNDLE_PATH",
    "BUNDLE_USER_CONFIG",
    "CARGO_INSTALL_ROOT",
    "CARGO_TARGET_DIR",
    "CCACHE_CONFIGPATH",
    "CCACHE_DIR",
    "CONDA_PKGS_DIRS",
    "CYPRESS_CACHE_FOLDER",
    "ELECTRON_CACHE",
    "FNM_DIR",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "GOBIN",
    "GOENV",
    "GOTMPDIR",
    "HOME",
    "INPUTRC",
    "LD_LIBRARY_PATH",
    "LESSHISTFILE",
    "MISE_CONFIG_DIR",
    "MISE_GLOBAL_CONFIG_FILE",
    "MISE_STATE_DIR",
    "NODENV_ROOT",
    "NODE_REPL_HISTORY",
    "NUGET_PLUGINS_CACHE_PATH",
    "PIPX_BIN_DIR",
    "PIPX_HOME",
    "PLAYWRIGHT_BROWSERS_PATH",
    "POETRY_VIRTUALENVS_PATH",
    "PYTHONPYCACHEPREFIX",
    "PYTHONUSERBASE",
    "RBENV_ROOT",
    "RIPGREP_CONFIG_PATH",
    "SDKMAN_DIR",
    "STARSHIP_CACHE",
    "STARSHIP_CONFIG",
    "TERMINFO",
    "TMPDIR",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_DIRS",
    "XDG_RUNTIME_DIR",
    "YARN_CACHE_FOLDER",
    "YARN_GLOBAL_FOLDER",
    "ZDOTDIR",
    "_ZO_DATA_DIR",
    "npm_config_cache",
    "pnpm_config_store_dir",
];

/// Whether assigning `name` can move a tool's config, data or cache: a
/// location, a list of locations or an anchor in the emit table, a name of
/// the `XDG_*_HOME` family, or one of the tool homes and relocating names
/// the table does not list (`UNLISTED_RELOCATIONS`).
///
/// This is the set a tool's cached activation output is searched for
/// ([`crate::shell::activation::relocations`]). A fragment bx writes needs no
/// such set: every assignment in it is judged, whatever its name.
#[must_use]
pub fn is_relocating(name: &str) -> bool {
    let xdg_home = name
        .strip_prefix("XDG_")
        .and_then(|rest| rest.strip_suffix("_HOME"))
        .is_some_and(|middle| !middle.is_empty() && middle.bytes().all(|b| b.is_ascii_uppercase()));
    xdg_home
        || matches!(
            emittable(name),
            Some(Kind::Location | Kind::LocationList | Kind::Anchor)
        )
        || UNLISTED_RELOCATIONS.contains(&name)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::env_guard::fixtures::*;
    use crate::env_guard::*;

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
    fn the_relocating_names_are_the_locations_the_xdg_homes_and_the_known_tool_homes() {
        // Every location, list of locations and anchor the table lists.
        for (name, kind) in EMITTABLE {
            let locates = matches!(kind, Kind::Location | Kind::LocationList | Kind::Anchor);
            assert_eq!(is_relocating(name), locates, "{name}");
        }
        // The whole `XDG_*_HOME` family, listed or not, and every name a
        // review round found a tool reading as a location.
        for name in [
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "XDG_BIN_HOME",
            "XDG_RUNTIME_DIR",
            "HOME",
            "ZDOTDIR",
            "TMPDIR",
            "STARSHIP_CONFIG",
            "MISE_CONFIG_DIR",
            "_ZO_DATA_DIR",
        ]
        .into_iter()
        .chain(R4_UNLISTED_RELOCATIONS.iter().copied())
        {
            assert!(is_relocating(name), "{name}");
        }
        // Nothing else: a tool's own variables, and near misses of the family.
        for name in [
            "MISE_SHELL",
            "STARSHIP_SHELL",
            "BUFFER",
            "FZF_DEFAULT_OPTS",
            "XDG__HOME",
            "XDG_config_HOME",
            "XDG_HOME",
            "MY_CARGO_HOME",
            "cargo_home",
        ] {
            assert!(!is_relocating(name), "{name}");
        }
        // The list is sorted, so a duplicate or a missing name shows.
        assert!(UNLISTED_RELOCATIONS.windows(2).all(|w| w[0] < w[1]));
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
        for name in ["RUSTC_WRAPPER", "BROWSER", "TERMINAL"] {
            assert_eq!(emittable(name), Some(Kind::Program), "{name}");
        }
        for name in ["EDITOR", "VISUAL", "PAGER", "MANPAGER"] {
            assert_eq!(emittable(name), Some(Kind::CommandLine), "{name}");
        }
        assert_eq!(emittable("LESS"), Some(Kind::Arguments));
        for name in [
            "LC_ALL",
            "LC_ADDRESS",
            "LC_COLLATE",
            "LC_CTYPE",
            "LC_IDENTIFICATION",
            "LC_MEASUREMENT",
            "LC_MESSAGES",
            "LC_MONETARY",
            "LC_NAME",
            "LC_NUMERIC",
            "LC_PAPER",
            "LC_TELEPHONE",
            "LC_TIME",
        ] {
            assert_eq!(
                emittable(name),
                Some(Kind::Setting(Setting::Locale)),
                "{name}"
            );
        }
        for name in [
            "GTK_IM_MODULE",
            "QT_IM_MODULE",
            "SDL_IM_MODULE",
            "GLFW_IM_MODULE",
        ] {
            assert_eq!(
                emittable(name),
                Some(Kind::Setting(Setting::InputMethod)),
                "{name}"
            );
        }
        assert_eq!(
            emittable("XMODIFIERS"),
            Some(Kind::Setting(Setting::ImModifier))
        );
        // Command-line-shaped names no kind judges stay unlisted.
        for name in ["MAKEFLAGS", "RUSTFLAGS", "LESSOPEN", "LANGUAGE", "LC_FOO"] {
            assert_eq!(emittable(name), None, "{name}");
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
            ("GIT_PAGER", "less"),
            ("LESSOPEN", "\"|lesspipe.sh %s\""),
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
    fn a_name_the_shell_manages_may_not_be_assigned_and_only_home_may_be_referred_to() {
        // `HOME` is the one reserved name a value may refer to: `Scope::lookup`
        // answers it from the root set before it reaches the reserved branch,
        // which is what makes `$HOME` and `~` resolvable at all. Assigning it
        // is still refused, and so is a reference to every other reserved name.
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
        // A reserved reference reaching a *later* line through an ordinary
        // name, which is the one input that separates `as_reference`'s default
        // arm from `_ => reason`. Both lines above assign a reserved name, so
        // both answer through `Scope::lost`; here line 1 assigns `X`, which is
        // reserved by nothing and emittable by nothing, so its value is
        // learned as `Err(ReservedName)` and only `as_reference` decides what
        // line 2 is told. Under `_ => reason` line 2 would say "use a name the
        // shell does not manage" — an action about a name line 2 does not
        // contain — instead of naming the line whose assignment could not be
        // read.
        // Line 1 is reported for its *name* — `X` is in no generator's emit
        // table — while the value the scope learns for it is still
        // `Err(ReservedName)`, which is what line 2 then refers to.
        assert_eq!(
            reasons("X=$RANDOM\nexport CARGO_HOME=$X/cargo\n", &rooted()),
            vec![(1, Reason::NotEmittable), (2, Reason::UnreadableReference)]
        );
        // The review's case: a fragment that moves `HOME` no longer moves `~`.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(
            reasons("HOME=/etc/evil\nCARGO_HOME=~/cargo\n", &home_rooted),
            vec![(1, Reason::ReservedName), (2, Reason::UnreadableReference)]
        );
        // The exception the grammar names, and the whole reason it exists: a
        // *reference* to `HOME` resolves against the root set, and so does the
        // `~` that stands for it, while a reference to any other reserved name
        // is refused. Without it no value could be written against the home.
        assert_eq!(
            check("CARGO_HOME", "$HOME/.cargo", &home_rooted),
            Verdict::Allowed
        );
        assert_eq!(
            check("CARGO_HOME", "${HOME}/.cargo", &home_rooted),
            Verdict::Allowed
        );
        assert_eq!(
            check("CARGO_HOME", "~/.cargo", &home_rooted),
            Verdict::Allowed
        );
        for name in ["RANDOM", "SECONDS", "UID", "FUNCNAME"] {
            assert_eq!(
                reason_of(&check(
                    "CARGO_HOME",
                    &format!("${name}/.cargo"),
                    &home_rooted
                )),
                Some(Reason::ReservedName),
                "{name}"
            );
        }
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
}
