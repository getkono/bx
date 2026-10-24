//! A target: one path in the user's environment that bx has something to say about.
//!
//! # The `[[target]]` schema
//!
//! ```toml
//! [[target]]
//! path       = "~/.config/starship.toml"        # required; the natural key
//! file       = "files/starship.toml"            # body, repo-relative     )
//! content    = "…"                              # body, verbatim literal  ) exactly
//! generated  = "shell-init"                     # body, named generator   ) one of
//! secret     = "secrets/npmrc.age"              # body, age ciphertext    )
//! symlink    = "~/src/tool/bin/tool"            # the target is a symlink   )
//! dir        = true                             # the target is a directory )
//! tree       = "files/nvim"                     # a repo directory, file by file )
//! exclude    = ["*.md"]                         # only beside `tree`; see below
//! mode       = "0600"                           # optional octal *string*;
//!                                               #   required, and private, for a secret;
//!                                               #   refused for a symlink
//! attach     = "own"                            # own | region | include; default own
//! comment    = "#"                              # required iff attach = "region"
//! include    = "Include ~/.ssh/config.d/*.conf" # required iff attach = "include"
//!                                               #   one line, not blank; no body key
//!                                               #   beside it, the line *is* the body
//! direction  = "apply"                          # apply | track; default apply
//!                                               #   track needs a `file` body
//! format     = "opaque"                         # opaque | jsonc | env.d; default opaque
//!                                               #   jsonc and env.d need attach = "own"
//! owns       = ["agent.default_model"]          # required and non-empty iff format = "jsonc"
//! requires   = ["starship"]                     # default []; reported, never a gate
//! references = ["~/.gitconfig.local"]           # default []
//! enabled    = true                             # default true
//! when       = "os:macos"                       # optional; a condition bx decides
//! ```
//!
//! # `when` keeps a target to some machines
//!
//! `when` is one condition bx decides, or an array that is all of several:
//! `has:TOOL`, `os:OS`, `arch:ARCH`, `host:NAME`, `user:NAME` or `distro:ID`
//! (see [`super::when`]). A target is kept or left out as `plan` loads the
//! configuration, so a test only the shell could run — `interactive`,
//! `login`, `ssh`, `env:…` — has nothing to guard and is refused when the
//! config loads. Where the condition does not hold the target is not declared
//! on this machine: it replaces no earlier layer's target for the same file,
//! and a later toggle naming it flips nothing. A file it wrote on this machine
//! before is reported as no longer declared, exactly as with
//! `enabled = false`, and `bx rm` puts the prior bytes back. A tree's `when`
//! gates every file it expands to. See [`super::layers::gate`].
//!
//! A target under a directory only one OS reads — `~/.config/systemd/user`
//! and `~/.config/environment.d` on Linux, `~/Library` on macOS — must be
//! kept to that OS by its own `when` or its module's, or the layer is refused
//! as it loads, on every OS. See [`refuse_ungated_platform`]. A path that
//! reaches such a directory only once a `{{name}}` in it is answered is judged
//! again after substitution, by the same gates: a committed `default` leading
//! there fails the load, and an account's answer blocks the target.
//!
//! # Why the discriminant keys are flat
//!
//! `attach = "region"` with a sibling `comment = "#"`, not
//! `attach = { kind = "region", comment = "#" }`. Hand-editing a config file and
//! running a `bx` command have to be the same operation, and flat scalar keys are
//! what `toml_edit` edits surgically without reflowing a nested table — and what
//! a human types. A companion key without its discriminant is an error, so the
//! flat form cannot silently ignore a key.
//!
//! # `requires` never gates
//!
//! `requires` names the tools a target configures, by a bare name looked up on
//! `PATH` or by an absolute path. A target is written whether or not they are
//! installed: its file is decided on its own content and mode alone, so a
//! tool's configuration is already in place when the tool arrives, and nothing
//! has to be run again. `bx doctor` names every required tool that is not an
//! executable, in the same finding as a `[[tool]]` entry of the same name; see
//! [`crate::doctor::tools`].
//!
//! # A tree
//!
//! `tree = "files/nvim"` beside `path = "~/.config/nvim"` is not a target of
//! its own: when its layer is loaded from a config repo it becomes one target
//! per file beneath the directory — a `file` body for a regular file, a
//! `symlink` body holding the link's text for a symlink — at `path` joined
//! with the file's path relative to the tree. See [`super::tree`], which walks
//! it. Its `mode`, `direction`, `requires` and `enabled` are every expanded
//! file's; with no `mode`, each regular file is `0755` when its repo file is
//! executable by its owner and `0644` otherwise. `exclude` lists patterns
//! for files and directories the tree leaves out; see [`super::tree::Glob`].

use std::fmt;
use std::path::{Path, PathBuf};

use toml_edit::Table;

use super::alias::AliasDecl;
use super::env::Var;
use super::function::Function;
use super::history::History;
use super::keybindings::Keybindings;
use super::path::PathEntry;
use super::plugin::PluginDecl;
use super::resolution::Resolution;
use super::shell_options::ShellOptions;
use super::shells::Phase;
use super::source::Source;
use super::{Ctx, Error, Origin};
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[target]]";

/// Every key a `[[target]]` entry may carry.
const KEYS: [&str; 20] = [
    "path",
    "file",
    "content",
    "generated",
    "secret",
    "symlink",
    "dir",
    "tree",
    "exclude",
    "mode",
    "attach",
    "comment",
    "include",
    "direction",
    "format",
    "owns",
    "requires",
    "references",
    "enabled",
    "when",
];

/// The keys that declare a body. Exactly one, except for an `include` target.
const BODY_KEYS: [&str; 7] = [
    "file",
    "content",
    "generated",
    "secret",
    "symlink",
    "dir",
    "tree",
];

/// One path in the user's environment that bx has something to say about.
///
/// Its natural key is [`Target::path`]: a later layer whose target has a path
/// already present replaces that target in place, which is entry A3's merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Where it lands, home-relative.
    pub path: Portable,
    /// What goes there.
    pub body: Body,
    /// Explicit octal mode. `None` means [`Mode::DEFAULT_FILE`] for a file and
    /// [`Mode::DEFAULT_DIR`] for a directory — applying that default is entry
    /// A5's, so the model records the absence rather than guessing.
    pub mode: Option<Mode>,
    /// How bx attaches to the file.
    pub attach: Attach,
    /// Whether bx writes the file or only watches it.
    pub direction: Direction,
    /// How much of the file bx claims.
    pub format: Format,
    /// The tools this target configures. Never a gate: `bx doctor` reports
    /// the absent ones, and the target is written either way.
    pub requires: Vec<String>,
    /// Paths named inside the content, so drift in them can be reported.
    pub references: Vec<Portable>,
    /// `false` in any layer removes the target from the resolved configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
    /// The conditions that keep it to this machine: its own `when` and its
    /// module's, which [`refuse_ungated_platform`] reads again once a
    /// `{{name}}` in its path is answered.
    ///
    /// Empty as parsed, where both stay on the layer for [`super::layers::gate`]
    /// to decide; [`super::merge::merge`] carries them here, after every gate is
    /// decided, so a target that reaches resolution holds only conditions that
    /// held. Empty on a target bx makes itself.
    pub gates: Vec<super::when::When>,
}

/// What a target's content is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// A file in the config repo, named repo-relative.
    File(PathBuf),
    /// A literal written in the config file itself. The empty string is a
    /// body like any other: a zero-byte file bx delivers and keeps.
    Inline(String),
    /// Produced by a named generator.
    Generated(Gen),
    /// An age-encrypted file in the config repo, named repo-relative, whose
    /// plaintext is the content. Decrypted in-process by [`crate::secret`].
    Secret(PathBuf),
    /// The target is a symbolic link holding this text, as written.
    ///
    /// The text is what the link says, never a path bx resolves: a relative
    /// one stays relative to the link's own directory, and bx neither follows
    /// it nor asks whether anything is there, so a dangling link is created
    /// like any other. The one rendering it gets is a leading `~`, which
    /// becomes the home — see [`link_text`] — and a `{{name}}` in it is
    /// substituted like any other string field.
    ///
    /// A link has no mode, no format and no attachment but its own: the
    /// parser refuses a `mode`, a `format` other than `opaque` and an
    /// `attach` other than `own` beside it.
    Symlink(String),
    /// The target is a directory: it has a mode and no content.
    Dir,
}

/// A `[[target]]` whose body is `tree = "…"`, before it is expanded.
///
/// Not a [`Target`]: a tree names a repo directory, and what it declares is
/// the files beneath that directory, which only a read of the config repo can
/// list. The parser stays a pure function of the layer's text, so it records
/// the tree as written and [`super::tree::expand`] turns it into targets when
/// the layer is loaded from a repo. Nothing after loading ever sees one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// Where the directory lands, home-relative. Each file's target is this
    /// joined with the file's path relative to [`Tree::root`].
    pub path: Portable,
    /// The directory in the config repo, repo-relative and normalised.
    pub root: PathBuf,
    /// Files and directories left out, by their path relative to the root.
    pub exclude: Vec<super::tree::Glob>,
    /// Every regular file's mode. `None` gives each file the executable bit of
    /// its repo file: `0755` or `0644`.
    pub mode: Option<Mode>,
    /// Every expanded file's direction.
    pub direction: Direction,
    /// Every expanded file's requirements.
    pub requires: Vec<String>,
    /// Every expanded file's `enabled`, which a later layer can toggle one
    /// file at a time.
    pub enabled: bool,
    /// Where the entry was written, and so where each expanded file was.
    pub origin: Origin,
    /// How many of its layer's targets were written before it, so its files
    /// take its place in document order.
    pub at: usize,
}

/// One parsed `[[target]]` table: a target, or a tree that expands into some.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// An ordinary target.
    Target(Target),
    /// A `tree = "…"` entry, not yet expanded.
    Tree(Tree),
}

/// What a table's body key declares.
enum Declared {
    /// A target's body.
    Body(Body),
    /// A tree, by its repo-relative root.
    Tree(PathBuf),
}

/// Why the text of a `symlink` body cannot be a link's, if it cannot.
///
/// Empty text is no link at all, and a NUL cannot be in one: `symlink(2)`
/// takes a C string. A `~` is rendered as the home only as the whole text or
/// as `~/…`; a `~name` would name another account's home, which bx renders
/// no path against, so it is refused rather than written as a relative link
/// named `~name`.
///
/// Two callers, like [`confine_to_repo`]: the parser, on the text as written,
/// and [`super::resolve`], on the text a substitution produced.
pub(crate) fn check_link_text(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("`symlink` is the text of the link bx makes, so it may not be empty".into());
    }
    if text.contains('\0') {
        return Err(format!(
            "`symlink` may not hold a NUL character, which no link can; got {text:?}"
        ));
    }
    if text.starts_with('~') && text != "~" && !text.starts_with("~/") {
        return Err(format!(
            "`symlink` renders a leading `~` as the home only as `~` or `~/…`; \
             write another account's home out in full. Got {text:?}"
        ));
    }
    Ok(())
}

/// The text a link declared as `text` holds on this machine: `text` with a
/// leading `~` or `~/` rendered against `home`, and anything else verbatim.
///
/// Nothing else is normalised, so a relative text stays relative, `a//b`
/// stays `a//b`, and the link says exactly what the config wrote.
#[must_use]
pub fn link_text(text: &str, home: &Path) -> PathBuf {
    match text.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with('/') => {
            let mut rendered = home.as_os_str().to_os_string();
            rendered.push(rest);
            PathBuf::from(rendered)
        }
        _ => PathBuf::from(text),
    }
}

/// The generators a target's body can be produced by.
///
/// Each variant carries everything its bytes are made of, so producing them is
/// a pure function of the resolved target and whether each tool a
/// `when = "has:TOOL"` names is present: the plan decides on exactly the bytes
/// `apply` writes. [`Gen::render`], which [`crate::shell`] implements, is
/// that function.
///
/// Every variant so far is produced by the `[[env]]` placement graph
/// ([`super::env`]), which also carries the `[[plugin]]` entries, the
/// declared aliases, the declared functions and the declared optional sources
/// into the interactive file, or by bash's placement
/// ([`crate::shell::bash::place`]), and
/// none is named by a config author: a fragment carries the variables
/// resolution placed in it, which no `generated = "…"` string could spell. A
/// generator a config author may name adds its variant here and its arm in
/// [`parse_generated`] together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gen {
    /// An environment fragment: the variables one place holds. The plan judges
    /// it against the declared roots before it is written.
    Env(super::env::Fragment),
    /// The LaunchAgent `environment.d` is on macOS, holding the variables
    /// that place holds ([`super::env::LaunchAgent`]). The plan judges its
    /// fragment as it judges `environment.d`'s, and refuses a value launchd
    /// would be handed unexpanded.
    LaunchAgent(super::env::LaunchAgent),
    /// The one line of a fixed region, sourcing a fragment when it is readable.
    /// Sets nothing, so it is not an environment fragment and is not judged as
    /// one; `env_guard`'s tests hold its bytes to carrying no assignment.
    Source(Portable),
    /// The one line of `~/.bash_profile`'s fixed region on macOS, sourcing
    /// bash's generated file when it is readable and `~/.bashrc` has not
    /// already sourced it ([`crate::shell::bash::profile_line`]). Sets
    /// nothing either, and is not judged as a fragment; `env_guard`'s tests
    /// hold its bytes to carrying no assignment.
    Profile(Portable),
    /// The interactive shell file, assembled phase by phase. Only its `env`
    /// phase is an environment fragment, and only that phase is judged as
    /// one; see [`Interactive`]. Boxed, because it carries every interactive
    /// declaration and would otherwise size every target's body to it.
    Interactive(Box<Interactive>),
    /// bash's generated interactive file; see [`crate::shell::bash`]. Judged
    /// as [`Gen::Interactive`] is: by its `env` phase, its one environment
    /// fragment, and the history file it names. Boxed for the reason
    /// [`Gen::Interactive`] is.
    Bash(Box<Bash>),
    /// `~/.inputrc`, the declared keybindings in readline's syntax; see
    /// [`crate::shell::bash::render_inputrc`]. Readline's syntax has no
    /// environment variable to judge.
    Inputrc(Keybindings),
}

/// One tool activation's text in an interactive file, as the plan decided it:
/// what [`crate::shell::activation::plan`] reused or captured for one shell,
/// already written as the text its phase holds.
///
/// The interactive files carry this rather than the plan itself, because
/// running a tool and caching what it printed are the plan's and
/// [`crate::shell`]'s business, and what a file needs is the decided text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activated {
    /// The phase the text lands in.
    pub phase: Phase,
    /// The activation's name, which owns the text in its phase.
    pub name: String,
    /// The text: a comment naming the activation, then one `eval` of a
    /// single-quoted literal holding the output.
    pub body: String,
}

/// The interactive shell file, `~/.local/share/bx/zshrc.zsh`, rendered through
/// [`crate::shell::Assembly`] in its fixed phase order by
/// [`crate::shell::zsh`].
///
/// The interactive `[[env]]` fragment lands in the `env` phase, whole, and is
/// the one part of the file [`crate::env_guard`] judges; every enabled
/// `[[plugin]]` lands in the `plugins` phase, or in the `terminal` slot when it
/// claims it, as the one guarded line [`PluginDecl::line`] renders; the
/// declared `[history]` lands in the `options` phase in zsh's names, as
/// [`History::render_zsh`] renders it; every enabled alias lands in the
/// `aliases` phase, as the line [`crate::shell::alias::AliasDecl::render`]
/// renders for it; every enabled `[[function]]` whose body resolved lands in
/// the `functions` phase, as [`Function::render`] renders it; the declared
/// `[keybindings]` land in the `keybindings` phase, as
/// [`Keybindings::render_zsh`] renders them; and every enabled `[[source]]`
/// whose path resolved lands in the phase it names, after that phase's own
/// declarations, as the one guarded line [`Source::render_in`] renders; and
/// every declared tool activation the plan reused or captured lands in the phase it
/// names, as the one `eval` of a literal [`Activated::body`] holds,
/// before any source in that phase. No phase
/// but `env` holds an environment assignment (Invariant 2): the `options`
/// phase assigns only zsh's own unexported history parameters, which
/// [`super::history`]'s tests hold it to, and the `functions` phase assigns
/// only zsh's hook arrays, the update prompt's unexported `BX_` names and, in
/// bash's file, an append to an unexported `PROMPT_COMMAND`, none of which
/// a process inherits, as [`crate::env_guard`]'s non-fragment files say.
///
/// The fields are private so that every value holds at most one terminal
/// claimant: [`Interactive::with_plugins`] refuses a second, which is what
/// lets [`Interactive::render`] never fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interactive {
    /// The interactive variables, in the fragment `[[env]]` places.
    env: super::env::Fragment,
    /// The enabled plugins, in declaration order.
    plugins: Vec<PluginDecl>,
    /// The declared history, rendered in zsh's names into the `options`
    /// phase.
    history: History,
    /// The enabled aliases, in the merged configuration's order.
    aliases: Vec<AliasDecl>,
    /// The enabled functions, each resolved or held back in its own
    /// position, in the merged configuration's order.
    functions: Vec<Resolution<Function>>,
    /// The declared keybindings, rendered into the `keybindings` phase.
    keybindings: Keybindings,
    /// The enabled declared optional sources, each resolved or held back in
    /// its own position, in the merged configuration's order.
    sources: Vec<Resolution<Source>>,
    /// zsh's tool activations, as `plan` decided them, in declaration order.
    /// Empty until the plan attaches them ([`Interactive::with_activations`]):
    /// resolution runs no tool, so it cannot know their output.
    activations: Vec<Activated>,
    /// What the file's plan row says of the declarations that do not reach
    /// zsh ([`crate::shell::omitted`]), if any.
    omitted: Option<String>,
    /// Whether an external follows a branch, so the file asks about its
    /// updates ([`crate::shell::update_prompt`]).
    update_prompt: bool,
}

impl Interactive {
    /// The file holding `env`, and no plugin, history, alias, function,
    /// keybinding or source.
    #[must_use]
    pub fn new(env: super::env::Fragment) -> Self {
        Self {
            env,
            plugins: Vec::new(),
            history: History::default(),
            aliases: Vec::new(),
            functions: Vec::new(),
            keybindings: Keybindings::default(),
            sources: Vec::new(),
            activations: Vec::new(),
            omitted: None,
            update_prompt: false,
        }
    }

    /// The file asking, at a prompt, about followed externals' updates when
    /// `follows`.
    #[must_use]
    pub const fn with_update_prompt(mut self, follows: bool) -> Self {
        self.update_prompt = follows;
        self
    }

    /// Whether the file asks about followed externals' updates.
    #[must_use]
    pub const fn update_prompt(&self) -> bool {
        self.update_prompt
    }

    /// The file with `omitted` as what its plan row says of the declarations
    /// that do not reach zsh.
    #[must_use]
    pub fn with_omitted(mut self, omitted: Option<String>) -> Self {
        self.omitted = omitted;
        self
    }

    /// What the file's plan row says of the declarations that do not reach
    /// zsh, if anything.
    #[must_use]
    pub fn omitted(&self) -> Option<&str> {
        self.omitted.as_deref()
    }

    /// The file with `activations` in its `activations` and `completions`
    /// phases: zsh's text for every step that reused or captured an output,
    /// in declaration order. An omitted step has no text to add.
    #[must_use]
    pub fn with_activations(mut self, activations: Vec<Activated>) -> Self {
        self.activations = activations;
        self
    }

    /// zsh's tool activations the plan attached, in declaration order.
    #[must_use]
    pub fn activations(&self) -> &[Activated] {
        &self.activations
    }

    /// The file with `keybindings` in its `keybindings` phase.
    #[must_use]
    pub fn with_keybindings(mut self, keybindings: Keybindings) -> Self {
        self.keybindings = keybindings;
        self
    }

    /// The declared keybindings.
    #[must_use]
    pub const fn keybindings(&self) -> &Keybindings {
        &self.keybindings
    }

    /// The file with `history` in its `options` phase.
    #[must_use]
    pub fn with_history(mut self, history: History) -> Self {
        self.history = history;
        self
    }

    /// The declared history, whose zsh file the plan judges.
    #[must_use]
    pub const fn history(&self) -> &History {
        &self.history
    }

    /// The file with `sources` added: the enabled declared optional sources
    /// as [`crate::shell::source::resolve`] resolved them, each ready one
    /// written and each held-back one named by [`Interactive::note`].
    #[must_use]
    pub fn with_sources(mut self, sources: Vec<Resolution<Source>>) -> Self {
        self.sources = sources;
        self
    }

    /// The enabled declared optional sources, each resolved or held back:
    /// what [`crate::shell::source::missing`] is asked about.
    #[must_use]
    pub fn sources(&self) -> &[Resolution<Source>] {
        &self.sources
    }

    /// The file with `functions` added: the enabled functions as
    /// [`crate::shell::function::resolve`] resolved them, each ready one
    /// written and each held-back one named by [`Interactive::note`].
    #[must_use]
    pub fn with_functions(mut self, functions: Vec<Resolution<Function>>) -> Self {
        self.functions = functions;
        self
    }

    /// The enabled functions, each resolved or held back.
    #[must_use]
    pub fn functions(&self) -> &[Resolution<Function>] {
        &self.functions
    }

    /// The file with `aliases` added, the disabled ones dropped.
    ///
    /// Whether a `has:TOOL` alias is written is not decided here: it is
    /// decided by [`Interactive::render`]'s `present`, so the file carries
    /// every enabled alias and the bytes follow the machine.
    #[must_use]
    pub fn with_aliases(mut self, aliases: &[AliasDecl]) -> Self {
        self.aliases = aliases.iter().filter(|a| a.enabled).cloned().collect();
        self
    }

    /// The enabled aliases, in the merged configuration's order.
    #[must_use]
    pub fn aliases(&self) -> &[AliasDecl] {
        &self.aliases
    }

    /// The file with `plugins` added, the disabled ones dropped.
    ///
    /// # Errors
    ///
    /// Whatever [`super::plugin::check_terminal`] returns: a second
    /// enabled plugin claiming the terminal slot, named with the first.
    pub fn with_plugins(mut self, plugins: &[PluginDecl]) -> Result<Self, super::Error> {
        super::plugin::check_terminal(plugins)?;
        self.plugins = plugins.iter().filter(|p| p.enabled).cloned().collect();
        Ok(self)
    }

    /// The `env` phase's fragment, which the plan judges on its own.
    #[must_use]
    pub const fn env(&self) -> &super::env::Fragment {
        &self.env
    }

    /// The enabled plugins, in declaration order.
    #[must_use]
    pub fn plugins(&self) -> &[PluginDecl] {
        &self.plugins
    }
}

/// One variable bash's `env` phase holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashVar {
    /// The variable, its value substituted.
    pub var: Var,
    /// Whether only a login shell sets it: a `kind = "login"` variable, which
    /// zsh reads from `~/.zprofile`.
    pub login: bool,
}

/// What bash's generated interactive file holds, rendered by
/// [`crate::shell::bash`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bash {
    /// The variables, `environment` then `login` then `interactive`, each
    /// kind in the merged configuration's order.
    env: Vec<BashVar>,
    /// The `[path]` entries that reach bash, in the merged configuration's
    /// order.
    path: Vec<PathEntry>,
    /// The enabled aliases, in the merged configuration's order.
    aliases: Vec<AliasDecl>,
    /// The declared history, rendered in bash's names.
    history: History,
    /// The declared shell options.
    options: ShellOptions,
    /// The enabled functions bash defines, each resolved or held back.
    functions: Vec<Resolution<Function>>,
    /// The enabled sources bash reads, each resolved or held back.
    sources: Vec<Resolution<Source>>,
    /// bash's tool activations, as `plan` decided them, in declaration order.
    /// Empty until the plan attaches them.
    activations: Vec<Activated>,
    /// What the file's plan row says of the declarations that do not reach
    /// bash ([`crate::shell::omitted`]).
    omitted: Option<String>,
    /// Whether an external follows a branch, so the file asks about its
    /// updates ([`crate::shell::update_prompt`]).
    update_prompt: bool,
    /// Whether `~/.bash_profile` sources the file too, so the file defines
    /// the function that region asks about ([`crate::shell::bash::LOADED`]).
    profile: bool,
}

impl Bash {
    /// The file holding `aliases` — the disabled ones dropped — `history` and
    /// `options`, and nothing else yet.
    #[must_use]
    pub fn new(aliases: &[AliasDecl], history: History, options: ShellOptions) -> Self {
        Self {
            aliases: aliases.iter().filter(|a| a.enabled).cloned().collect(),
            history,
            options,
            ..Self::default()
        }
    }

    /// The file with `env` in its `env` phase.
    #[must_use]
    pub fn with_env(mut self, env: Vec<BashVar>) -> Self {
        self.env = env;
        self
    }

    /// The file with `entries` in its `path` phase.
    #[must_use]
    pub fn with_path(mut self, entries: Vec<PathEntry>) -> Self {
        self.path = entries;
        self
    }

    /// The file with `functions` in its `functions` phase, as
    /// [`crate::shell::function::resolve_bash`] resolved them.
    #[must_use]
    pub fn with_functions(mut self, functions: Vec<Resolution<Function>>) -> Self {
        self.functions = functions;
        self
    }

    /// The file with `sources`, each in the phase it names.
    #[must_use]
    pub fn with_sources(mut self, sources: Vec<Resolution<Source>>) -> Self {
        self.sources = sources;
        self
    }

    /// The file with `activations`, bash's text for every step that reused
    /// or captured an output, in their phases.
    #[must_use]
    pub fn with_activations(mut self, activations: Vec<Activated>) -> Self {
        self.activations = activations;
        self
    }

    /// The file with `omitted` as what its plan row says of the declarations
    /// that do not reach bash.
    #[must_use]
    pub fn with_omitted(mut self, omitted: Option<String>) -> Self {
        self.omitted = omitted;
        self
    }

    /// The file asking, at a prompt, about followed externals' updates when
    /// `follows`.
    #[must_use]
    pub const fn with_update_prompt(mut self, follows: bool) -> Self {
        self.update_prompt = follows;
        self
    }

    /// Whether the file asks about followed externals' updates.
    #[must_use]
    pub const fn update_prompt(&self) -> bool {
        self.update_prompt
    }

    /// The file, sourced from `~/.bash_profile` too when `profile`.
    #[must_use]
    pub const fn with_profile(mut self, profile: bool) -> Self {
        self.profile = profile;
        self
    }

    /// Whether `~/.bash_profile` sources the file too.
    #[must_use]
    pub const fn profile(&self) -> bool {
        self.profile
    }

    /// The variables, in the order the `env` phase holds them.
    #[must_use]
    pub fn env_vars(&self) -> &[BashVar] {
        &self.env
    }

    /// The `[path]` entries that reach bash.
    #[must_use]
    pub fn path(&self) -> &[PathEntry] {
        &self.path
    }

    /// The enabled aliases, in the merged configuration's order.
    #[must_use]
    pub fn aliases(&self) -> &[AliasDecl] {
        &self.aliases
    }

    /// The declared history, whose bash file the plan judges.
    #[must_use]
    pub const fn history(&self) -> &History {
        &self.history
    }

    /// The declared shell options.
    #[must_use]
    pub const fn options(&self) -> &ShellOptions {
        &self.options
    }

    /// The enabled functions bash defines, each resolved or held back.
    #[must_use]
    pub fn functions(&self) -> &[Resolution<Function>] {
        &self.functions
    }

    /// The enabled sources bash reads, each resolved or held back.
    #[must_use]
    pub fn sources(&self) -> &[Resolution<Source>] {
        &self.sources
    }

    /// bash's tool activations the plan attached, in declaration order.
    #[must_use]
    pub fn activations(&self) -> &[Activated] {
        &self.activations
    }

    /// What the file's plan row says of the declarations that do not reach
    /// bash, if anything.
    #[must_use]
    pub fn omitted(&self) -> Option<&str> {
        self.omitted.as_deref()
    }
}

/// Resolve the name a config author wrote as `generated = "…"`.
///
/// Returns `None` for every name: each generator there is so far is placed by
/// the `[[env]]` placement graph, carrying data no name could spell. See
/// [`Gen`].
#[must_use]
pub fn parse_generated(_name: &str) -> Option<Gen> {
    // A generator a config author may name adds its `match` arm here.
    None
}

/// A file mode, as an octal bit pattern.
///
/// **This is the file mode, not the plan/apply mode.** Entry A7 declares its own
/// `Mode { Plan, Apply }` in its own module; the two are never re-exported into
/// one scope.
///
/// Declared once, in [`crate::fs::mode`], and named here because that is where
/// the config schema needs it: a target's `mode` key, the mode the writer sets,
/// and the mode the ledger records are one type, so a mode a config author wrote
/// means the same thing as a mode `stat` reported. `parse_octal`, `ModeError`
/// and the four-digit `Display` are unchanged by the move.
///
/// One type does not mean one encoding. Deserialising a `[[target]]` accepts
/// only the **quoted** octal form, `mode = "0600"`; a bare `mode = 600` is
/// refused with the decimal it would have meant. The bare-integer encoding the
/// ledger writes is reachable only from a non-human-readable format, and never
/// from a config file.
pub use crate::fs::mode::Mode;

/// How bx attaches to a file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Attach {
    /// The whole file is bx's.
    #[default]
    Own,
    /// A delimited region inside a file the user also writes.
    Region {
        /// The comment character of the file's syntax.
        comment: char,
    },
    /// A single line inserted into the user's own file.
    Include {
        /// The line, verbatim.
        line: String,
    },
}

/// Which copy of a file leads: the config repo's, or this machine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// The repo's copy leads: bx writes it onto the machine.
    #[default]
    Apply,
    /// This machine's copy leads, because a tool rewrites it — a plugin
    /// manager's lock file. `bx sync` carries a change made here into the
    /// repo's copy and commits it; `apply` writes the repo's copy here only
    /// where this machine's did not change since the two last agreed; and a
    /// change on both sides is a conflict for a human. It needs a `file` body,
    /// whole and opaque; see `plan::decide`.
    Track,
}

/// How much of a file bx claims.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Format {
    /// The file is bytes; bx claims all of what it attaches to.
    #[default]
    Opaque,
    /// JSON with comments; bx owns only the listed keys.
    Jsonc {
        /// The key paths bx owns. Everything else in the file is the user's.
        owns: Vec<KeyPath>,
    },
    /// One fragment file in a `conf.d`-style directory of environment settings.
    ///
    /// A `Format` describes the file a target's `path` names, so this is the
    /// fragment, not the directory holding it: bx owns the whole fragment and
    /// says nothing about its neighbours. What the fragment's syntax is, and
    /// how the directory is assembled, belong to the entry that generates one.
    EnvD,
}

/// A dotted path to a key inside a structured file.
///
/// Split on `.`, with no escape syntax: a key containing a literal dot is not
/// expressible yet, and entry C3 extends [`KeyPath::parse`] when it needs one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyPath(Vec<String>);

impl KeyPath {
    /// Split a dotted key path.
    ///
    /// # Errors
    ///
    /// [`KeyPathError::EmptySegment`] if any segment is empty, including the
    /// empty string itself. `a..b` is a typo, not a key.
    pub fn parse(raw: &str) -> Result<Self, KeyPathError> {
        if raw.split('.').any(str::is_empty) {
            return Err(KeyPathError::EmptySegment(raw.to_string()));
        }
        Ok(Self(raw.split('.').map(str::to_string).collect()))
    }

    /// The segments, outermost first.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

/// A key path that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyPathError {
    /// A segment between two dots, or at either end, was empty.
    #[error("a key path may not have an empty segment, got {0:?}")]
    EmptySegment(String),
}

/// Parse one `[[target]]` entry, which may be a tree.
///
/// `text` is the whole layer file, because spans index into it. `home` is the
/// account's home directory: a target path is parsed against it so that a file
/// under the home has exactly one spelling, `~/…`, and cannot acquire a second
/// key by being written absolutely somewhere else in the layer set. See
/// [`Portable::parse_in`]. It also decides which paths are the home or above
/// it, where only a `dir = true` target may point.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_entry(table: &Table, file: &Path, text: &str, home: &Path) -> Result<Entry, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let raw_path = ctx.required_str(table, "path")?;
    let path =
        Portable::parse_in(raw_path, home).map_err(|e| ctx.bad(table, "path", e.to_string()))?;

    let attach = parse_attach(&ctx, table)?;
    let body = match parse_body(&ctx, table, &attach)? {
        Declared::Body(body) => body,
        Declared::Tree(root) => {
            return parse_tree(&ctx, table, path, root, &attach).map(Entry::Tree);
        }
    };
    if table.contains_key("exclude") {
        return Err(ctx.bad(
            table,
            "exclude",
            "`exclude` names files a `tree` leaves out, so it only means something beside `tree`",
        ));
    }
    let mode = parse_mode(&ctx, table)?;
    let direction = parse_direction(&ctx, table)?;
    let format = parse_format(&ctx, table)?;

    // The home and every directory above it, the filesystem root included, are
    // directories. A file body at any of them is an `own` claim on a directory
    // as if it were a file, which no writer can honour. Resolution re-applies
    // this to the path a placeholder substitution produced.
    refuse_file_at_home_or_above(raw_path, &path, &body, home)
        .map_err(|message| ctx.bad(table, "path", message))?;

    if body == Body::Dir {
        // The same rule the flat discriminant keys already follow elsewhere: a
        // companion key that cannot mean anything is an error, not a key that is
        // quietly ignored. `parse_attach` rejects `comment` without a region and
        // `parse_format` rejects `owns` without jsonc; this is the third pair.
        if attach != Attach::Own {
            return Err(ctx.bad(
                table,
                "attach",
                "a directory target is always attached as `own`: there is no content \
                 to delimit a region in and no file to insert a line into",
            ));
        }
        if format != Format::Opaque {
            return Err(ctx.bad(
                table,
                "format",
                "a directory target has no content, so `format` has nothing to describe",
            ));
        }
    }

    if matches!(body, Body::Secret(_)) {
        check_secret(&ctx, table, mode, &attach, &format, direction)?;
    }

    if matches!(body, Body::Symlink(_)) {
        check_symlink(&ctx, table, &attach, &format)?;
    }

    if matches!(&format, Format::Jsonc { owns } if owns.is_empty()) {
        // `Jsonc { owns: [] }` says bx manages part of a file and names no part:
        // every run a silent no-op. Checked here rather than in `parse_format`
        // so a directory target's more specific message above still wins.
        return Err(ctx.bad(
            table,
            "format",
            "format = \"jsonc\" claims only the keys `owns` lists, so it needs at least \
             one key in `owns`; with none the target claims nothing",
        ));
    }

    if format != Format::Opaque && attach != Attach::Own {
        // `Format` says how much of the file a target's `path` names bx claims:
        // `jsonc` the listed keys of a whole JSON document, `env.d` a whole
        // fragment. A region is a delimited span inside a file the user also
        // writes and an include is one line in it; neither is a JSON document or
        // a fragment, so the pair would claim two contradictory things about one
        // file and entry A5 would have to drop one of them silently. The raw
        // spellings are re-read because both keys have already been validated.
        let kind = ctx.str_at(table, "format")?.unwrap_or("opaque");
        let how = ctx.str_at(table, "attach")?.unwrap_or("own");
        return Err(ctx.bad(
            table,
            "format",
            format!(
                "format = {kind:?} describes a whole file bx owns, so it needs attach = \"own\"; \
                 this target is attached as {how:?}, which is part of a file the user also \
                 writes. Use format = \"opaque\", or attach = \"own\""
            ),
        ));
    }

    let requires = ctx.str_array_at(table, "requires")?;
    let references = ctx
        .str_array_at(table, "references")?
        .iter()
        .map(|raw| Portable::parse_in(raw, home))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ctx.bad(table, "references", e.to_string()))?;

    Ok(Entry::Target(Target {
        path,
        body,
        mode,
        attach,
        direction,
        format,
        requires,
        references,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
        gates: Vec::new(),
    }))
}

/// The rest of a tree entry, once its body key said it is one.
///
/// A tree is a set of whole files bx owns, so the keys that describe a part of
/// one file, or its content, are refused by name rather than copied onto every
/// file: `attach` other than `own`, `format` other than `opaque`, and
/// `references`, which names paths inside one file's content.
fn parse_tree(
    ctx: &Ctx,
    table: &Table,
    path: Portable,
    root: PathBuf,
    attach: &Attach,
) -> Result<Tree, Error> {
    if *attach != Attach::Own {
        return Err(ctx.bad(
            table,
            "attach",
            "a tree target is always attached as `own`: each file it expands to is a whole \
             file bx owns",
        ));
    }
    if parse_format(ctx, table)? != Format::Opaque {
        return Err(ctx.bad(
            table,
            "format",
            "a tree names many files, so `format`, which describes one file's content, has \
             nothing to describe; declare the one file as its own target instead",
        ));
    }
    if table.contains_key("references") {
        return Err(ctx.bad(
            table,
            "references",
            "`references` names paths inside one file's content, and a tree names many files; \
             declare the one file as its own target instead",
        ));
    }
    let exclude = ctx
        .str_array_at(table, "exclude")?
        .iter()
        .map(|raw| super::tree::Glob::parse(raw))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|message| ctx.bad(table, "exclude", message))?;
    Ok(Tree {
        path,
        root,
        exclude,
        mode: parse_mode(ctx, table)?,
        direction: parse_direction(ctx, table)?,
        requires: ctx.str_array_at(table, "requires")?,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
        at: 0,
    })
}

/// The rules a secret target is held to at load time.
///
/// **A private mode, written out.** A secret with no `mode` would be written at
/// [`Mode::DEFAULT_FILE`], `0644`, which every account on the machine can read,
/// and a default that silently publishes a secret is the one default this key
/// may not have. So the mode is required, and it must deny group and other
/// everything — and let its owner read, or the next `plan` could not compare
/// what `apply` wrote.
///
/// **The whole file.** A region or an include line is part of a file the user
/// also writes, at whatever mode the user gave it, and a structured format owns
/// keys inside one; none of them can keep plaintext private. An include target
/// already cannot carry a second body, so only a region and a format arrive
/// here.
///
/// **Applied, never tracked.** A tracked target is one the tool writes and bx
/// carries back, and the only place a secret may be carried back to is its
/// ciphertext; carrying the plaintext would put a cleartext secret in the repo.
fn check_secret(
    ctx: &Ctx,
    table: &Table,
    mode: Option<Mode>,
    attach: &Attach,
    format: &Format,
    direction: Direction,
) -> Result<(), Error> {
    if direction != Direction::Apply {
        return Err(ctx.bad(
            table,
            "direction",
            "a secret target is always applied: tracking it would carry the plaintext \
             the tool writes back toward the config repo",
        ));
    }
    let Some(mode) = mode else {
        return Err(ctx.bad(
            table,
            "secret",
            "a secret target needs an explicit private `mode`, such as mode = \"0600\"; \
             without one it would be written readable by every account on the machine",
        ));
    };
    if mode.is_shared() || mode.bits() & 0o400 == 0 {
        return Err(ctx.bad(
            table,
            "mode",
            format!(
                "a secret target's mode must let its owner read it and deny group and other \
                 everything, such as \"0600\" or \"0400\"; got \"{mode}\""
            ),
        ));
    }
    if *attach != Attach::Own {
        return Err(ctx.bad(
            table,
            "attach",
            "a secret target is always attached as `own`: a region is part of a file the \
             user also writes, at a mode bx does not choose",
        ));
    }
    if *format != Format::Opaque {
        return Err(ctx.bad(
            table,
            "format",
            "a secret target's plaintext is the whole file, so `format` has nothing to describe",
        ));
    }
    Ok(())
}

/// The companion keys a symlink target refuses, each by name.
///
/// A link is its text and nothing else. Its mode is not bx's to set — Linux
/// gives every link `0777` and ignores it — so a declared one would be a
/// promise the writer cannot keep, and the format and attachment describe
/// bytes in a file, which a link has none of. The same rule the other flat
/// companion keys follow: a key that cannot mean anything is an error, not a
/// key quietly ignored.
fn check_symlink(ctx: &Ctx, table: &Table, attach: &Attach, format: &Format) -> Result<(), Error> {
    if table.contains_key("mode") {
        return Err(ctx.bad(
            table,
            "mode",
            "a symlink target takes no `mode`: a link's permission bits are not used, \
             and the file it points at keeps its own",
        ));
    }
    if *format != Format::Opaque {
        return Err(ctx.bad(
            table,
            "format",
            "a symlink target holds no content, so `format` has nothing to describe",
        ));
    }
    if *attach != Attach::Own {
        return Err(ctx.bad(
            table,
            "attach",
            "a symlink target's `attach` is always \"own\": a link has no content to \
             delimit a region in",
        ));
    }
    Ok(())
}

/// `attach`, and the companion key its value requires.
fn parse_attach(ctx: &Ctx, table: &Table) -> Result<Attach, Error> {
    let kind = ctx.str_at(table, "attach")?.unwrap_or("own");
    let comment = ctx.str_at(table, "comment")?;
    let include = ctx.str_at(table, "include")?;

    let attach = match kind {
        "own" => Attach::Own,
        "region" => {
            let raw = comment.ok_or_else(|| {
                ctx.bad(
                    table,
                    "attach",
                    "attach = \"region\" needs a `comment` character, so bx knows how to \
                     delimit the region in this file's syntax",
                )
            })?;
            let mut chars = raw.chars();
            let comment = match (chars.next(), chars.next()) {
                (Some(c), None) => c,
                _ => {
                    return Err(ctx.bad(
                        table,
                        "comment",
                        format!("`comment` must be a single character, got {raw:?}"),
                    ));
                }
            };
            // Type-checked is not value-checked. `comment = "\n"` is a single
            // character and produced region delimiters that cannot be found
            // again, so the region stops delimiting anything: bx appends a
            // fresh region on every run, which is Invariant 3, or writes
            // outside the one it meant to, which is Invariant 1. A whitespace
            // comment character is the same defect with a subtler spelling, and
            // so is an invisible one: U+200B ZERO WIDTH SPACE is neither
            // whitespace nor a control character, and a delimiter nobody can see
            // in an editor is one a human deletes. Every comment character a
            // real config syntax uses is visible ASCII, so that is the rule.
            if !comment.is_ascii_graphic() {
                return Err(ctx.bad(
                    table,
                    "comment",
                    format!(
                        "`comment` starts the delimiter lines bx has to find again, so it \
                         must be a visible ASCII character: not whitespace or a control \
                         character, and nothing outside ASCII; got {raw:?}"
                    ),
                ));
            }
            Attach::Region { comment }
        }
        "include" => {
            let line = include.ok_or_else(|| {
                ctx.bad(
                    table,
                    "attach",
                    "attach = \"include\" needs an `include` line to insert",
                )
            })?;
            // The key is called `include` and holds one *line*: entry A5 finds
            // it again by looking for it in the file. An empty line matches
            // every blank line in `~/.ssh/config`, or is appended on every run
            // — Invariant 3 either way. A value bearing a line terminator is
            // not one line, so no line-wise search finds it whole; a multi-line
            // insertion is `attach = "region"`, which has delimiters for
            // exactly that reason.
            // A line of only spaces or tabs is the empty line with a subtler
            // spelling: it matches every blank line too.
            if line.trim().is_empty() || line.contains(['\n', '\r']) {
                return Err(ctx.bad(
                    table,
                    "include",
                    format!(
                        "`include` is the single line bx inserts and finds again, so it may \
                         not be empty or span lines; for a multi-line insertion use \
                         attach = \"region\". Got {line:?}"
                    ),
                ));
            }
            Attach::Include {
                line: line.to_string(),
            }
        }
        other => {
            return Err(ctx.bad(
                table,
                "attach",
                format!("`attach` must be \"own\", \"region\" or \"include\", got {other:?}"),
            ));
        }
    };

    if comment.is_some() && !matches!(attach, Attach::Region { .. }) {
        return Err(ctx.bad(
            table,
            "comment",
            "`comment` only means something with attach = \"region\"",
        ));
    }
    if include.is_some() && !matches!(attach, Attach::Include { .. }) {
        return Err(ctx.bad(
            table,
            "include",
            "`include` only means something with attach = \"include\"",
        ));
    }

    Ok(attach)
}

/// Exactly one body key — and for an `include` target, none, because its body
/// *is* its line.
fn parse_body(ctx: &Ctx, table: &Table, attach: &Attach) -> Result<Declared, Error> {
    let declared: Vec<&str> = BODY_KEYS
        .iter()
        .copied()
        .filter(|key| table.contains_key(key))
        .collect();

    // The same rule the other companion keys follow: a key that cannot mean
    // anything is an error, not a key that is quietly ignored. An include
    // target's body *is* its `include` line, so a `content`, `file` or
    // `generated` beside it is a second body nothing reads. Taken silently, an
    // author who edits an include target into an own-file target and forgets to
    // change `attach` gets a target whose forty lines of content entry A5 must
    // either drop or insert into a file bx does not own.
    //
    // `dir` is excluded because it already has a stricter rule, applied in
    // `parse_target`: a directory target's only admissible attachment is `own`,
    // whatever else it declares, and that message says so.
    let unreachable = declared.iter().find(|key| **key != "dir");
    if let (Attach::Include { .. }, Some(first)) = (attach, unreachable) {
        return Err(ctx.bad(
            table,
            first,
            format!(
                "attach = \"include\" already declares the only line bx writes, so `{first}` \
                 would never be read; drop it, or set `attach` to \"own\" or \"region\""
            ),
        ));
    }

    match declared.as_slice() {
        [] => match attach {
            // An include target already declares the only line it writes;
            // making it repeat that line as `content` would be ceremony.
            Attach::Include { line } => Ok(Declared::Body(Body::Inline(line.clone()))),
            _ => Err(Error::MissingKey {
                origin: ctx.origin().clone(),
                section: SECTION,
                key: "file`, `content`, `generated`, `secret`, `symlink`, `dir` or `tree",
            }),
        },
        ["tree"] => tree_root(ctx, table).map(Declared::Tree),
        [one] => body_from(ctx, table, one).map(Declared::Body),
        many => Err(ctx.bad(
            table,
            many[1],
            format!(
                "a target has exactly one body, but this one declares {}",
                many.iter()
                    .map(|k| format!("`{k}`"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        )),
    }
}

/// A body file is named relative to the config repo root, and stays inside it.
///
/// `path` and `references` are portable paths and are validated as such; `file`
/// is the third path a target carries and needs its own rule. An absolute value
/// would silently discard the repo root the moment it reached `repo.join`, and a
/// climbing one would read a file the repo does not contain — a config repo is
/// meant to be publishable and self-contained, and neither value can be.
///
/// The stored form is normalised, so `files/./a` and `files/a` are one body.
fn repo_relative(ctx: &Ctx, table: &Table, key: &str, raw: &str) -> Result<PathBuf, Error> {
    confine_to_repo(key, raw).map_err(|message| ctx.bad(table, key, message))
}

/// The rule itself, without the provenance to report it against.
///
/// Separate from [`repo_relative`] because it has **two** callers and may not
/// have two implementations. A `file` may carry a `{{name}}`, so what the parser
/// validates is the path as written and what reaches `repo.join` is the path as
/// *substituted*: `cfg/{{account}}/gitconfig` with an answer of `../../../etc`
/// is a repo escape that the parse-time check never sees. [`super::resolve`]
/// re-applies this to the substituted value.
///
/// The message is returned rather than an [`Error`], because the two callers
/// have different provenance to attach: a table and a key, or a target and its
/// origin.
pub(crate) fn confine_to_repo(key: &str, raw: &str) -> Result<PathBuf, String> {
    if names_a_machine_location(raw) {
        return Err(format!(
            "`{key}` names a file inside the config repo, so it is relative to the \
             repo root; got {raw:?}"
        ));
    }

    let mut parts: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!(
                        "`{key}` may not climb out of the config repo; got {raw:?}"
                    ));
                }
            }
            named => parts.push(named),
        }
    }

    if parts.is_empty() {
        return Err(format!(
            "`{key}` must name a file in the config repo; got {raw:?}"
        ));
    }

    Ok(PathBuf::from(parts.join("/")))
}

/// Whether `text` is rooted at the filesystem or the home rather than at the
/// config repo: it opens with `/` or `~`.
///
/// One predicate with two uses. [`confine_to_repo`] asks it of a whole `file`;
/// [`super::resolve`] asks it of each value's text as substituted into one,
/// because `cfg/{{dir}}/x` with `dir` answered `/home/example/…` normalises to
/// a relative path that still carries the account's machine location into the
/// repo.
pub(crate) fn names_a_machine_location(text: &str) -> bool {
    text.starts_with('/') || text.starts_with('~')
}

/// Refuse a file body at the home or at any directory above it.
///
/// The home, its ancestors and `/` are directories, so a file body at one is an
/// `own` claim on a directory as if it were a file, which no writer can honour.
/// Which paths those are is decided lexically from `path` and `home`, never from
/// the disk: `path` is `~`, or the normalised home starts with it component by
/// component, so `/var/home` is above `/var/home/example` and `/var/homes` is
/// not. A `dir = true` target may name any of them.
///
/// No "is `path` under the home?" test is needed beside that comparison, and an
/// earlier shape of this function carried one that could not decide anything. A
/// `Portable` under the home is `~`-rooted; `~` itself is the first operand; and
/// a `~/…` path is never a component prefix of the home, because the home
/// reaching here is always absolute.
///
/// That last clause is a precondition on the **callers**, not a property of any
/// argument's type: a `Path` is free to be relative, and nothing in this
/// signature forbids one. Both callers hold it the same way — each builds a
/// `Portable` against the *same* home before calling, and
/// [`Portable::parse_in`] refuses a home that does not normalise absolute. The
/// `debug_assert!` below states it where it is relied on, so any future caller
/// that does not hold it trips on the first test that reaches here rather than
/// silently reinstating the deleted operand's case.
///
/// Like [`confine_to_repo`] it has two callers: the parser, on the path as
/// written, and [`super::resolve`], on the path a substitution produced, because
/// `~/{{leaf}}` with `leaf` answered `.` is `~`. `shown` is the spelling to
/// quote, and the message is returned for each caller to attach its own
/// provenance.
pub(crate) fn refuse_file_at_home_or_above(
    shown: &str,
    path: &Portable,
    body: &Body,
    home: &Path,
) -> Result<(), String> {
    let home = crate::paths::normalize(home);
    debug_assert!(
        home.is_absolute(),
        "a caller reached refuse_file_at_home_or_above with the non-absolute home {home:?}; \
         against such a home a `~/…` path can be a component prefix, which is the case the \
         deleted `!path.under_home()` operand was thought to cover"
    );
    let at_or_above = path.as_str() == "~" || home.starts_with(path.as_str());
    if *body != Body::Dir && at_or_above {
        return Err(format!(
            "path = {shown:?} is the home directory or a directory above it, so only a \
             `dir = true` target may name it; a file target names a file beneath it"
        ));
    }
    Ok(())
}

/// A directory only one OS reads.
#[derive(Debug)]
struct PlatformAnchor {
    /// The directory, as a [`Portable`] spells it.
    dir: &'static str,
    /// The OS that reads it, as `os:` spells it.
    os: &'static str,
    /// Whether that OS's own volumes look names up without regard to case,
    /// so a path spelling the directory in another case lands in it there.
    folds_case: bool,
}

/// The directories only one OS reads.
///
/// The systemd user manager reads unit files and `environment.d` on Linux
/// alone, and `~/Library` is macOS's: a file there on the other OS is
/// written for nothing to read. macOS's default volume folds case, so
/// `~/library` is `~/Library` there; Linux's filesystems do not, and no other
/// OS reads the systemd directories, so only `~/Library` folds.
const PLATFORM_ANCHORS: [PlatformAnchor; 3] = [
    PlatformAnchor {
        dir: "~/.config/systemd/user",
        os: "linux",
        folds_case: false,
    },
    PlatformAnchor {
        dir: "~/.config/environment.d",
        os: "linux",
        folds_case: false,
    },
    PlatformAnchor {
        dir: "~/Library",
        os: "macos",
        folds_case: true,
    },
];

/// Where `path` lies under one of [`PLATFORM_ANCHORS`]: the anchor, and
/// whether `path` spells it exactly (`true`) or only in another case, on an
/// anchor that folds it (`false`).
fn platform_anchor(path: &Portable) -> Option<(&'static PlatformAnchor, bool)> {
    PLATFORM_ANCHORS.iter().find_map(|anchor| {
        if crate::lexical::is_within(path.as_str(), anchor.dir) {
            Some((anchor, true))
        } else if anchor.folds_case
            && crate::lexical::is_within_folding_case(path.as_str(), anchor.dir)
        {
            Some((anchor, false))
        } else {
            None
        }
    })
}

/// The OS a target at `path`, written on a machine running `here`, must be
/// kept to so [`refuse_ungated_platform`] accepts it: the anchor's OS for a
/// path that spells its anchor exactly, and `here` for one that spells it in
/// another case — on the anchor's own OS that is the anchor, and on any other
/// it is a different directory, read there. `None` when `path` lies under no
/// anchor and needs no gate.
pub(crate) fn platform_gate(path: &Portable, here: &'static str) -> Option<&'static str> {
    platform_anchor(path).map(|(anchor, exact)| if exact { anchor.os } else { here })
}

/// Refuse a target at `path` that lies under one of [`PLATFORM_ANCHORS`]
/// unless one of `gates` — its own `when`, its module's — names that
/// anchor's OS.
///
/// Judged as the layer loads, before any gate is decided, so a target meant
/// for one OS is refused on every OS: its author learns on the machine they
/// wrote it on, not on the other one. Containment is lexical
/// ([`crate::lexical::is_within`]), like the environment guard's, so a path
/// reaching an anchor through a symlink is not seen. A path that spells an
/// anchor which folds case in another case (`~/library/…`) is that anchor on
/// its OS and a different directory elsewhere, so any `os:` gate keeps it:
/// what is refused is a gate that decides nothing, under which it would land
/// in the anchor ungated. The message is returned for the caller to attach the
/// entry's origin.
pub(crate) fn refuse_ungated_platform(
    path: &Portable,
    gates: &[&super::when::When],
) -> Result<(), String> {
    let Some((anchor, exact)) = platform_anchor(path) else {
        return Ok(());
    };
    let PlatformAnchor { dir, os, .. } = anchor;
    if exact {
        if gates.iter().any(|when| when.names_os(os)) {
            return Ok(());
        }
        return Err(format!(
            "`{path}` lies under `{dir}`, which only {os} reads, so it must be kept to {os}: \
             add `when = \"os:{os}\"` to the target, or move it to a module whose own `when` \
             says so"
        ));
    }
    if gates.iter().any(|when| when.names_an_os()) {
        return Ok(());
    }
    Err(format!(
        "`{path}` is `{dir}` on {os}, whose volumes do not tell names apart by case, and only \
         {os} reads that, so it must be kept to an OS: add `when = \"os:{os}\"` to the target, \
         or the `os:` it is meant for, or move it to a module whose own `when` says so"
    ))
}

/// A tree's root: a directory in the config repo, confined to it as a `file`
/// is.
///
/// Unlike a `file`, it may not carry a `{{name}}`. A tree is expanded when its
/// layer is loaded, before any value has an answer, so a placeholder in its
/// root could only be read literally, and a directory that exists under a
/// name with braces in it would be a different directory from the one meant.
fn tree_root(ctx: &Ctx, table: &Table) -> Result<PathBuf, Error> {
    let raw = ctx.required_str(table, "tree")?;
    if raw.contains("{{") {
        return Err(ctx.bad(
            table,
            "tree",
            format!(
                "`tree` is expanded when its layer is loaded, before any value is answered, \
                 so it may not hold a `{{{{name}}}}`; got {raw:?}"
            ),
        ));
    }
    repo_relative(ctx, table, "tree", raw)
}

/// The body one declared key names.
fn body_from(ctx: &Ctx, table: &Table, key: &str) -> Result<Body, Error> {
    match key {
        "file" => {
            let raw = ctx.required_str(table, "file")?;
            Ok(Body::File(repo_relative(ctx, table, "file", raw)?))
        }
        "content" => Ok(Body::Inline(
            ctx.required_str(table, "content")?.to_string(),
        )),
        "secret" => {
            let raw = ctx.required_str(table, "secret")?;
            Ok(Body::Secret(repo_relative(ctx, table, "secret", raw)?))
        }
        "symlink" => {
            let text = ctx.required_str(table, "symlink")?;
            check_link_text(text).map_err(|message| ctx.bad(table, "symlink", message))?;
            Ok(Body::Symlink(text.to_string()))
        }
        "generated" => {
            let name = ctx.required_str(table, "generated")?;
            parse_generated(name).map(Body::Generated).ok_or_else(|| {
                ctx.bad(
                    table,
                    "generated",
                    format!("no generator named {name:?} exists in this version of bx"),
                )
            })
        }
        _ => match ctx.bool_at(table, "dir")? {
            Some(true) => Ok(Body::Dir),
            _ => Err(ctx.bad(
                table,
                "dir",
                "`dir` declares a directory target and is only ever `true`; \
                 remove the key for a file target",
            )),
        },
    }
}

/// `mode`, which is a quoted octal string or nothing.
fn parse_mode(ctx: &Ctx, table: &Table) -> Result<Option<Mode>, Error> {
    let Some(item) = table.get("mode") else {
        return Ok(None);
    };
    if item.is_integer() {
        return Err(ctx.bad(
            table,
            "mode",
            "`mode` is a quoted octal string: mode = 600 is decimal 600, and \
             TOML's own octal literal is spelled 0o600, which is not how a mode \
             is written anywhere else. Write mode = \"0600\".",
        ));
    }

    let raw = ctx.required_str(table, "mode")?;
    Mode::parse_octal(raw)
        .map(Some)
        .map_err(|e| ctx.bad(table, "mode", e.to_string()))
}

/// `direction`, defaulting to `apply`.
fn parse_direction(ctx: &Ctx, table: &Table) -> Result<Direction, Error> {
    match ctx.str_at(table, "direction")?.unwrap_or("apply") {
        "apply" => Ok(Direction::Apply),
        "track" => Ok(Direction::Track),
        other => Err(ctx.bad(
            table,
            "direction",
            format!("`direction` must be \"apply\" or \"track\", got {other:?}"),
        )),
    }
}

/// `format`, and the `owns` list that `jsonc` must carry and nothing else may.
fn parse_format(ctx: &Ctx, table: &Table) -> Result<Format, Error> {
    let kind = ctx.str_at(table, "format")?.unwrap_or("opaque");
    let owns_declared = table.contains_key("owns");

    if kind != "jsonc" && owns_declared {
        return Err(ctx.bad(
            table,
            "owns",
            "`owns` names the keys bx claims inside a structured file, so it \
             only means something with format = \"jsonc\"",
        ));
    }

    match kind {
        "opaque" => Ok(Format::Opaque),
        "env.d" => Ok(Format::EnvD),
        "jsonc" => {
            let owns = ctx
                .str_array_at(table, "owns")?
                .iter()
                .map(|raw| KeyPath::parse(raw))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ctx.bad(table, "owns", e.to_string()))?;
            Ok(Format::Jsonc { owns })
        }
        other => Err(ctx.bad(
            table,
            "format",
            format!("`format` must be \"opaque\", \"jsonc\" or \"env.d\", got {other:?}"),
        )),
    }
}

/// Parse one `[[target]]` entry that is not a tree.
///
/// Only tests parse a lone entry outside a layer, so this sits last, beside
/// them.
///
/// # Errors
///
/// Whatever [`parse_entry`] returns. A `tree` body is refused, since only a
/// layer loaded from a repo can expand one.
#[cfg(test)]
pub fn parse_target(table: &Table, file: &Path, text: &str, home: &Path) -> Result<Target, Error> {
    match parse_entry(table, file, text, home)? {
        Entry::Target(target) => Ok(target),
        Entry::Tree(_) => Err(Ctx::new(table, file, text, SECTION).bad(
            table,
            "tree",
            "a `tree` expands into one target per file in the config repo, so it is \
             read only as part of a layer loaded from one",
        )),
    }
}

#[cfg(test)]
mod tests;
