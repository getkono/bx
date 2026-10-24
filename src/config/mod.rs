//! The configuration model: what a `bx` config repo says, and where it said it.
//!
//! A config repo is a set of **layers**. `bx.toml` is the first, `modules/*.toml`
//! follow in lexicographic filename order, and the account's `local.toml` in the
//! state directory is last. This module discovers and parses them. It does not
//! merge them, resolve a value, or substitute anything: that is [`merge`]'s
//! and [`resolve`]'s, and keeping the two apart is what lets a merge be a pure
//! function of the layer files.
//!
//! Documents are read through `toml_edit`'s DOM and never through `serde`.
//! `serde` deserialisation discards the spans [`Origin`] is built from, and the
//! DOM is also what lets `bx add` ([`crate::adopt`]) edit a hand-written file
//! without reflowing a byte the user wrote.
//!
//! # Unknown keys are errors
//!
//! An unrecognised top-level section, or an unrecognised key inside a recognised
//! entry, is an [`Error`] carrying its origin. A config written for a newer `bx`
//! therefore fails on an older one, loudly. That is deliberate: `bx` ships one
//! binary through one install channel, so a repo and a binary are versioned
//! together, and a silent no-op is the failure mode this tool exists to end.

pub mod activation;
pub mod alias;
pub mod doctor;
pub mod env;
pub mod external;
pub mod function;
pub mod history;
pub mod keybindings;
pub mod layers;
pub mod lock;
pub mod merge;
pub mod origin;
pub mod path;
pub mod plugin;
pub mod resolution;
pub mod resolve;
pub mod secrets;
pub mod shell_options;
pub mod shells;
pub mod source;
pub mod target;
pub mod toggle;
pub mod tool;
pub mod tree;
pub mod update;
pub mod values;
pub mod when;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use env::EnvDecl;
pub use origin::Origin;
use shells::Shells;
use target::Target;
use toml_edit::{Document, Item, Table};
use values::{ValueAssignment, ValueDecl};

/// The name of the global layer inside a config repo.
const GLOBAL_LAYER: &str = "bx.toml";

/// The directory holding the further global layers.
const MODULES_DIR: &str = "modules";

/// One config repo's worth of configuration, unmerged.
///
/// **One field per section, each a `Vec<T>` keyed by its natural key, in layer
/// order.** That convention is what lets a later block add a field rather than
/// fifteen: the shell block adds one `shell` field, the inventory adds one, the
/// secrets block adds one, each with its own parse arm.
///
/// `Config` is a plain value — `Clone`, `PartialEq`, `Default` — and deliberately
/// does not retain the `toml_edit` documents it was parsed from. Entry A3's merge
/// has to be a pure function of the layer files, and a merge that also had to
/// merge documents would not be.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// `[[target]]`, keyed by `path`.
    pub targets: Vec<Target>,
    /// `[[target]]` entries whose body is `tree = "…"`, not yet expanded.
    ///
    /// Filled by [`parse_str`], which reads no disk, and emptied by
    /// [`tree::expand`], which [`load_layer`] runs against the config repo:
    /// each tree becomes one target per file, in [`Config::targets`] where the
    /// tree was written. A layer loaded from a repo never holds one.
    pub trees: Vec<target::Tree>,
    /// `[[external]]`, keyed by `path`. See [`external`].
    pub externals: Vec<external::External>,
    /// `[[value]]`, keyed by `name`.
    pub values: Vec<ValueDecl>,
    /// `[values]`, in document order. Parsed, never resolved.
    pub value_assignments: Vec<ValueAssignment>,
    /// `[[env]]`, keyed by `name`.
    pub envs: Vec<EnvDecl>,
    /// `[path]`'s entries, every list's in one `Vec`, keyed by the directory
    /// as zsh is given it. See [`path`].
    pub path: Vec<path::PathEntry>,
    /// `[aliases]` and `[[alias]]` together, keyed by `name`: table by table,
    /// in the order each table first appears in the file, and each table's
    /// entries in the order written. See [`alias`], and
    /// [`crate::shell::alias`] for how each is rendered.
    pub aliases: Vec<alias::AliasDecl>,
    /// `[[function]]`'s entries, keyed by `name`, in the order written. See
    /// [`function`], and [`crate::shell::function`] for how each is rendered.
    pub functions: Vec<function::FunctionDecl>,
    /// `[[plugin]]`'s entries, keyed by `name`, in the order written. See
    /// [`plugin`], and [`crate::shell::plugin`] for how each is rendered.
    pub plugins: Vec<plugin::PluginDecl>,
    /// `[[source]]`'s entries, keyed by `name`, in the order written: the
    /// declared optional sources. See [`source`], and
    /// [`crate::shell::source`] for how each is rendered.
    pub sources: Vec<source::SourceDecl>,
    /// `[[activation]]`'s entries, keyed by `name`, in the order written: the
    /// declared tool activations, run at `plan` time and cached. See
    /// [`activation`], and [`crate::shell::activation`] for how each is run.
    pub activations: Vec<activation::ActivationDecl>,
    /// `[[tool]]`'s entries, keyed by `name`, in the order written: the
    /// declared tool inventory `bx doctor` reports on and never installs. See
    /// [`tool`].
    pub tools: Vec<tool::ToolDecl>,
    /// `[secrets]`: a table, not a keyed list, so it merges key by key, the
    /// last layer that sets a key winning. See [`secrets`] for which layer may
    /// set which key.
    pub secrets: secrets::Secrets,
    /// `[history]`: a table, merged key by key like `[secrets]`. See
    /// [`history`].
    pub history: history::History,
    /// `[shell-options]`: a table, merged key by key. See [`shell_options`].
    pub shell_options: shell_options::ShellOptions,
    /// `[keybindings]`: a table, merged key by key. See [`keybindings`], and
    /// [`crate::shell::keybindings`] for how it is rendered.
    pub keybindings: keybindings::Keybindings,
    /// `[update]`: a table, merged key by key. See [`update`].
    pub update: update::Update,
    /// `[doctor]`: a table, merged key by key. See [`doctor`].
    pub doctor: doctor::Doctor,
    /// List entries that restate only their natural key and `enabled`.
    ///
    /// A **toggle**: it flips the flag on an entry an earlier layer introduced
    /// and leaves every other field alone, so opting out of a target costs three
    /// lines in `local.toml` rather than a copy of the whole target — body
    /// included — that the account wants gone. One list serves every keyed
    /// section, each toggle carrying the section it came from.
    ///
    /// Always empty after [`merge::merge`], which consumes them.
    pub toggles: Vec<toggle::Toggle>,
    /// Files one layer names more than once only because of this account's
    /// answers.
    ///
    /// Empty from the parser. [`merge::merge`] fills it instead of failing the
    /// load, and [`resolve::resolve`] blocks every target for such a file.
    pub(crate) conflicts: Vec<merge::Conflict>,
    /// The layer's own top-level `when`: the condition every declaration in
    /// it is gated on. Only a module may carry one; see [`layers::gate`].
    pub when: Option<when::Condition>,
    /// The `when` of each `[[target]]`, `[[plugin]]`, `[[activation]]`,
    /// `[[external]]` and `[[tool]]` that carries one, found again by the
    /// entry's origin, which is its own header's line. See [`layers::gate`].
    pub gates: Vec<when::Condition>,
    /// The `when` of each `[path]` entry that carries one, beside the entry's
    /// natural key, [`path::PathEntry::shell`]: entries share a line, so no
    /// origin tells them apart.
    pub path_gates: Vec<(String, when::When)>,
    /// The natural key of every entry [`layers::gate`] left out of this
    /// layer because its condition does not hold here, so a later toggle
    /// naming it flips nothing rather than naming nothing.
    pub gated: Vec<(toggle::Section, String)>,
}

/// One layer file and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// The file it was read from.
    pub file: PathBuf,
    /// Whether the file is committed material or this account's own.
    pub kind: LayerKind,
    /// What that file says, on its own.
    pub config: Config,
}

/// Which of the two roots a layer came from.
///
/// The distinction is not decoration: only [`LayerKind::Local`] may carry a
/// `[values]` table. A committed layer that answered a value would be putting
/// account content into a git working tree meant to be published, and Invariant
/// 5 has no exception clause. The mechanism for a global answer already exists
/// and is `default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum LayerKind {
    /// From the config repo: committed, publishable, account-independent.
    #[default]
    Global,
    /// This account's `local.toml`, from the state directory.
    Local,
}

/// The global layer files in a config repo, in merge order.
///
/// `bx.toml` first when it exists, then the entries of `modules/` that end in
/// `.toml`, are regular files, and do not begin with `.`, **sorted by the raw
/// bytes of their filenames**. Not case-insensitively, not naturally-numerically,
/// and never in directory order: Invariant 3 says two `plan` runs a week apart on
/// an unchanged tree are byte-identical, and the order layers merge in is what
/// decides the result.
///
/// A missing `bx.toml` and a missing `modules/` are both empty results, not
/// errors — a repo may hold either, both, or neither. A repo root that does not
/// exist, lies beneath a non-directory, or is not a directory is
/// [`Error::RepoMissing`].
///
/// # Only a clean answer skips a file
///
/// A candidate is skipped only when it is **cleanly** not a layer: its name is
/// dot-prefixed or does not end in `.toml` (decided from the name, before
/// anything is stat'ed), it does not exist, or it exists and is not a regular
/// file. Every other outcome of looking is an [`Error::Io`] naming the path:
/// a dangling symlink, `EACCES` from a `modules/` that can be listed but not
/// searched, `ELOOP`. `Path::is_file` answers `false` for all of those, and a
/// skipped module is a silent no-op — the module that says `enabled = false`
/// quietly never applies.
///
/// # Errors
///
/// [`Error::RepoMissing`] if `repo` does not exist, lies beneath a
/// non-directory, or is not a directory, and [`Error::Io`] naming the path for
/// any candidate that cannot be examined.
pub fn layer_files(repo: &Path) -> Result<Vec<PathBuf>, Error> {
    if !examine_root(repo)?.is_some_and(|meta| meta.is_dir()) {
        return Err(Error::RepoMissing(repo.to_path_buf()));
    }

    let mut files = Vec::new();
    let global = repo.join(GLOBAL_LAYER);
    if examine(&global)?.is_some_and(|meta| meta.is_file()) {
        files.push(global);
    }

    let modules = repo.join(MODULES_DIR);
    if examine(&modules)?.is_some_and(|meta| meta.is_dir()) {
        let mut found = Vec::new();
        let entries = std::fs::read_dir(&modules).map_err(|source| Error::Io {
            path: modules.clone(),
            source,
        })?;
        for entry in entries {
            let path = entry
                .map_err(|source| Error::Io {
                    path: modules.clone(),
                    source,
                })?
                .path();
            if is_module_name(&path) && examine(&path)?.is_some_and(|meta| meta.is_file()) {
                found.push(path);
            }
        }
        found.sort_by(|a, b| filename_bytes(a).cmp(filename_bytes(b)));
        files.extend(found);
    }

    Ok(files)
}

/// Whether a `modules/` entry's *name* makes it a candidate layer.
///
/// Decided from the name alone, so a dangling `README.md` or an editor's
/// `.#x.toml` lock symlink is never stat'ed and never becomes an error.
fn is_module_name(path: &Path) -> bool {
    let bytes = filename_bytes(path);
    bytes.first() != Some(&b'.') && bytes.ends_with(b".toml")
}

/// What is at `path`, following symlinks: `None` when nothing is there.
///
/// `lstat` first, so each outcome has exactly one meaning. `None` only when
/// `lstat` says `ENOENT`: nothing, not even a link, is at the path. A symlink is
/// then followed with `stat`, and `ENOENT` there is a **dangling** link, which
/// is an error rather than an absence, because a layer someone linked in and
/// broke is not a layer nobody wrote. Every other failure of either call —
/// `EACCES`, `ELOOP` — is an error carrying the call's own `errno`. The repo
/// root alone is examined with [`examine_root`], which also reads `ENOTDIR`
/// from `lstat` as nothing there.
///
/// # Errors
///
/// [`Error::Io`] naming `path` for anything but a clean answer.
fn examine(path: &Path) -> Result<Option<std::fs::Metadata>, Error> {
    examine_as(path, &[std::io::ErrorKind::NotFound])
}

/// [`examine`] for a repo root: `None` also when `lstat` says `ENOTDIR`.
///
/// A root beneath a regular file (`~/.config` is a file) is as missing as one
/// that does not exist, and as one that is itself a file. Only the root reads
/// it so: a state directory that is a file is where the account's layer has to
/// be, so there `ENOTDIR` stays an error. Following a root symlink is unchanged,
/// so a root linked to such a place is still an error: the follow with `stat`
/// fails with `ENOTDIR` too, never `ENOENT`, so it is an io error naming the
/// link and not the dangling one.
///
/// # Errors
///
/// [`Error::Io`] naming `path` for anything but a clean answer.
fn examine_root(path: &Path) -> Result<Option<std::fs::Metadata>, Error> {
    examine_as(
        path,
        &[
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::NotADirectory,
        ],
    )
}

/// [`examine`], with `absent` the `lstat` error kinds that mean nothing is there.
///
/// The list applies to `lstat` alone; following a symlink is the same for
/// every caller.
///
/// # Errors
///
/// [`Error::Io`] naming `path` for anything but a clean answer.
fn examine_as(
    path: &Path,
    absent: &[std::io::ErrorKind],
) -> Result<Option<std::fs::Metadata>, Error> {
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    let link = match std::fs::symlink_metadata(path) {
        Ok(link) => link,
        Err(source) if absent.contains(&source.kind()) => return Ok(None),
        Err(source) => return Err(io(source)),
    };
    if !link.file_type().is_symlink() {
        return Ok(Some(link));
    }
    match std::fs::metadata(path) {
        Ok(target) => Ok(Some(target)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            Err(io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "a dangling symlink: what it points at does not exist",
            )))
        }
        Err(source) => Err(io(source)),
    }
}

/// A path's filename as raw bytes.
///
/// Architecture spec §2 asks for `str::cmp` on the raw bytes. A filename that is
/// not valid UTF-8 has no `str`, and `OsStr::as_encoded_bytes` is byte-identical
/// to `str::as_bytes` for every name that does, so ordering on it is the same
/// order with no undefined case.
fn filename_bytes(path: &Path) -> &[u8] {
    path.file_name()
        .map_or(&[], std::ffi::OsStr::as_encoded_bytes)
}

/// Read and parse one layer file, expanding its trees against `repo`.
///
/// Any file in the layer schema, including the state directory's `local.toml`,
/// whose `tree` entries name directories in the same config repo the global
/// layers do.
///
/// # Errors
///
/// [`Error::Io`] if the file cannot be read, whatever [`parse_str`] returns,
/// and whatever [`tree::expand`] returns.
pub fn load_layer(path: &Path, repo: &Path, home: &Path) -> Result<Layer, Error> {
    tracing::debug!(file = %path.display(), "reading configuration layer");
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut config = parse_str(&text, path, home)?;
    tree::expand(&mut config, repo, home)?;
    // Again over the files the trees expanded to: a tree rooted above an
    // anchor, at `~/.config` say, reaches into it only through its files.
    refuse_ungated_platform_targets(&config)?;

    Ok(Layer {
        file: path.to_path_buf(),
        // The repo loader only ever reads committed material. `layers::load_layer_set`
        // is what marks the one layer that came from the state directory.
        kind: LayerKind::Global,
        config,
    })
}

/// Parse one layer's worth of TOML.
///
/// `file` is used for provenance only; nothing is read from disk. Entry order
/// inside each section is document order, which `toml_edit` preserves.
///
/// `home` is the account's home directory. A layer is parsed *against* a home
/// because a target path under it has exactly one spelling — `~/…` — and
/// recognising the absolute spelling as the same file is what stops `bx.toml`
/// and a module holding two keys for one file. See [`crate::paths::Portable`].
///
/// # Errors
///
/// [`Error::Syntax`] for invalid TOML, [`Error::UnknownSection`] for a section
/// this version of `bx` does not know, [`Error::Duplicate`] for two entries in
/// one layer sharing a natural key, and whatever the per-entry parsers return.
pub fn parse_str(text: &str, file: &Path, home: &Path) -> Result<Config, Error> {
    let doc = Document::parse(text).map_err(|source| Error::Syntax {
        file: file.to_path_buf(),
        source: Box::new(source),
    })?;
    let root = doc.as_table();
    let mut config = Config::default();

    for (name, item) in root.iter() {
        match name {
            "target" => {
                for table in entries(root, name, item, file, text)? {
                    // A table whose only keys are `path` and `enabled` is a
                    // toggle, not a target with no body: it flips a flag on an
                    // entry an earlier layer introduced.
                    match toggle::toggle_of(table, toggle::Section::Target, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => {
                            match target::parse_entry(table, file, text, home)? {
                                target::Entry::Target(target) => config.targets.push(target),
                                target::Entry::Tree(mut tree) => {
                                    tree.at = config.targets.len();
                                    config.trees.push(tree);
                                }
                            }
                            gate_of(table, target::SECTION, file, text, &mut config)?;
                        }
                    }
                }
            }
            "external" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::External, file, text)? {
                        // Keyed by its one normalised spelling, as the full
                        // entry is, so `~/a/./b` reaches the entry at `~/a/b`.
                        Some(mut toggle) => {
                            toggle.key = external::parse_path(&toggle.key, home)
                                .map_err(|message| Error::BadValue {
                                    origin: toggle.origin.clone(),
                                    message,
                                })?
                                .as_str()
                                .to_string();
                            config.toggles.push(toggle);
                        }
                        None => {
                            config
                                .externals
                                .push(external::parse_external(table, file, text, home)?);
                            gate_of(table, external::SECTION, file, text, &mut config)?;
                        }
                    }
                }
            }
            "value" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Value, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .values
                            .push(values::parse_value_decl(table, file, text)?),
                    }
                }
            }
            "env" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Env, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config.envs.push(env::parse_env(table, file, text)?),
                    }
                }
            }
            "values" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[values]`",
                    found: item.type_name(),
                })?;
                config.value_assignments = values::parse_assignments(table, file, text)?;
            }
            "secrets" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[secrets]`",
                    found: item.type_name(),
                })?;
                config.secrets = secrets::parse_secrets(table, file, text, home)?;
            }
            "path" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[path]`",
                    found: item.type_name(),
                })?;
                config.path = path::parse_path(table, file, text, &mut config.path_gates)?;
            }
            "history" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[history]`",
                    found: item.type_name(),
                })?;
                config.history = history::parse_history(table, file, text, home)?;
            }
            "shell-options" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[shell-options]`",
                    found: item.type_name(),
                })?;
                config.shell_options = shell_options::parse_shell_options(table, file, text)?;
            }
            "update" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[update]`",
                    found: item.type_name(),
                })?;
                config.update = update::parse_update(table, file, text)?;
            }
            "doctor" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[doctor]`",
                    found: item.type_name(),
                })?;
                config.doctor = doctor::parse_doctor(table, file, text)?;
            }
            "keybindings" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[keybindings]`",
                    found: item.type_name(),
                })?;
                config.keybindings = keybindings::parse_keybindings(table, file, text)?;
            }
            "aliases" => {
                let table = item.as_table().ok_or_else(|| Error::WrongType {
                    origin: section_origin(root, name, file, text),
                    key: name.to_string(),
                    expected: "a table `[aliases]`",
                    found: item.type_name(),
                })?;
                config
                    .aliases
                    .extend(alias::parse_aliases(table, file, text)?);
            }
            "alias" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Alias, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config.aliases.push(alias::parse_alias(table, file, text)?),
                    }
                }
            }
            "function" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Function, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .functions
                            .push(function::parse_function(table, file, text)?),
                    }
                }
            }
            "plugin" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Plugin, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => {
                            config
                                .plugins
                                .push(plugin::parse_plugin(table, file, text)?);
                            gate_of(table, plugin::SECTION, file, text, &mut config)?;
                        }
                    }
                }
            }
            "source" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Source, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .sources
                            .push(source::parse_source(table, file, text)?),
                    }
                }
            }
            "activation" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Activation, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => {
                            config
                                .activations
                                .push(activation::parse_activation(table, file, text)?);
                            gate_of(table, activation::SECTION, file, text, &mut config)?;
                        }
                    }
                }
            }
            "tool" => {
                for table in entries(root, name, item, file, text)? {
                    match toggle::toggle_of(table, toggle::Section::Tool, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => {
                            config.tools.push(tool::parse_tool(table, file, text)?);
                            gate_of(table, tool::SECTION, file, text, &mut config)?;
                        }
                    }
                }
            }
            when::KEY => {
                let origin = section_origin(root, name, file, text);
                let when = when::decided(item.as_value(), item.type_name())
                    .map_err(|refusal| refusal.at(origin.clone()))?;
                config.when = Some(when::Condition { origin, when });
            }
            unknown => {
                return Err(Error::UnknownSection {
                    origin: section_origin(root, unknown, file, text),
                    section: unknown.to_string(),
                });
            }
        }
    }

    // Toggles are checked alongside the entries they flip, so one layer cannot
    // both restate an entry and toggle it — which would leave the outcome
    // depending on the order the two were applied in.
    check_unique(
        "target",
        config
            .targets
            .iter()
            .map(|t| (t.path.as_str(), &t.origin))
            .chain(toggles_in(&config, toggle::Section::Target))
            .collect(),
    )?;
    check_unique(
        "external",
        config
            .externals
            .iter()
            .map(|e| (e.path.as_str(), &e.origin))
            .chain(toggles_in(&config, toggle::Section::External))
            .collect(),
    )?;
    check_unique(
        "value",
        config
            .values
            .iter()
            .map(|v| (v.name.as_str(), &v.origin))
            .chain(toggles_in(&config, toggle::Section::Value))
            .collect(),
    )?;
    check_unique(
        "env",
        config
            .envs
            .iter()
            .map(|e| (e.name.as_str(), &e.origin))
            .chain(toggles_in(&config, toggle::Section::Env))
            .collect(),
    )?;
    check_unique(
        "path entry",
        config
            .path
            .iter()
            .map(|entry| (entry.shell.as_str(), &entry.origin))
            .collect(),
    )?;
    // Both alias tables at once, so one name in each is a duplicate too.
    check_unique(
        "alias",
        config
            .aliases
            .iter()
            .map(|a| (a.name.as_str(), &a.origin))
            .chain(toggles_in(&config, toggle::Section::Alias))
            .collect(),
    )?;
    check_unique(
        "function",
        config
            .functions
            .iter()
            .map(|f| (f.name.as_str(), &f.origin))
            .chain(toggles_in(&config, toggle::Section::Function))
            .collect(),
    )?;
    check_unique(
        "plugin",
        config
            .plugins
            .iter()
            .map(|p| (p.name.as_str(), &p.origin))
            .chain(toggles_in(&config, toggle::Section::Plugin))
            .collect(),
    )?;
    check_unique(
        "source",
        config
            .sources
            .iter()
            .map(|s| (s.name.as_str(), &s.origin))
            .chain(toggles_in(&config, toggle::Section::Source))
            .collect(),
    )?;
    check_unique(
        "activation",
        config
            .activations
            .iter()
            .map(|a| (a.name.as_str(), &a.origin))
            .chain(toggles_in(&config, toggle::Section::Activation))
            .collect(),
    )?;
    check_unique(
        "tool",
        config
            .tools
            .iter()
            .map(|t| (t.name.as_str(), &t.origin))
            .chain(toggles_in(&config, toggle::Section::Tool))
            .collect(),
    )?;
    refuse_gated_values(&config)?;
    refuse_ungated_platform_targets(&config)?;

    Ok(config)
}

/// Record the bx-decided `when` of the entry `table` heads, if it has one,
/// in `config.gates`, found again by the entry's origin.
///
/// # Errors
///
/// Whatever [`when::decided_at`] refuses.
fn gate_of(
    table: &Table,
    section: &'static str,
    file: &Path,
    text: &str,
    config: &mut Config,
) -> Result<(), Error> {
    let ctx = Ctx::new(table, file, text, section);
    if let Some(when) = when::decided_at(&ctx, table)? {
        config.gates.push(when::Condition {
            origin: ctx.origin().clone(),
            when,
        });
    }
    Ok(())
}

/// Refuse a `[[value]]` in a layer its own `when` gates.
///
/// A value is referred to by name from every layer, so one that existed on
/// some machines only would turn every `{{name}}` elsewhere into a reference
/// to nothing there.
///
/// # Errors
///
/// [`Error::BadValue`] at the first declaration or toggle of a value.
fn refuse_gated_values(config: &Config) -> Result<(), Error> {
    if config.when.is_none() {
        return Ok(());
    }
    let first = config
        .values
        .iter()
        .map(|value| &value.origin)
        .chain(toggles_in(config, toggle::Section::Value).map(|(_, origin)| origin))
        .next();
    match first {
        None => Ok(()),
        Some(origin) => Err(Error::BadValue {
            origin: origin.clone(),
            message: "a module gated by its own `when` may not declare a `[[value]]`: a value \
                      is referred to by name from every layer, so declare it in `bx.toml` or \
                      in a module with no `when`"
                .to_string(),
        }),
    }
}

/// Refuse every target and tree in `config` that lies under a directory only
/// one OS reads without being kept to that OS, by its own `when` or its
/// layer's. See [`target::refuse_ungated_platform`].
///
/// # Errors
///
/// [`Error::BadValue`] at the first such entry.
fn refuse_ungated_platform_targets(config: &Config) -> Result<(), Error> {
    let entries = config
        .targets
        .iter()
        .map(|target| (&target.path, &target.origin))
        .chain(config.trees.iter().map(|tree| (&tree.path, &tree.origin)));
    for (path, origin) in entries {
        let gates: Vec<&when::When> = config
            .when
            .iter()
            .chain(config.gates.iter().filter(|gate| gate.origin == *origin))
            .map(|gate| &gate.when)
            .collect();
        target::refuse_ungated_platform(path, &gates).map_err(|message| Error::BadValue {
            origin: origin.clone(),
            message,
        })?;
    }
    Ok(())
}

/// The toggles in `config` that belong to one section, as `check_unique` wants
/// them.
fn toggles_in(config: &Config, section: toggle::Section) -> impl Iterator<Item = (&str, &Origin)> {
    config
        .toggles
        .iter()
        .filter(move |toggle| toggle.section == section)
        .map(|toggle| (toggle.key.as_str(), &toggle.origin))
}

/// The elements of an array-of-tables section.
fn entries<'a>(
    root: &Table,
    name: &str,
    item: &'a Item,
    file: &Path,
    text: &str,
) -> Result<impl Iterator<Item = &'a Table>, Error> {
    item.as_array_of_tables()
        .map(toml_edit::ArrayOfTables::iter)
        .ok_or_else(|| Error::WrongType {
            origin: section_origin(root, name, file, text),
            key: name.to_string(),
            expected: "a repeated section `[[…]]`",
            found: item.type_name(),
        })
}

/// Where a top-level section's header key is.
fn section_origin(root: &Table, name: &str, file: &Path, text: &str) -> Origin {
    root.key(name)
        .and_then(toml_edit::Key::span)
        .map_or_else(|| Origin::unknown(file), |s| Origin::at(file, text, &s))
}

/// Reject a natural key that appears twice in one layer.
///
/// Replacing an entry in place across layers is [`merge`]'s rule. Twice in
/// one file is a typo, and silently keeping one of them is how a config stops
/// meaning what it says.
///
/// Keys are compared as stored strings. For a target that string is a
/// [`crate::paths::Portable`], which is normalised and refuses an absolute
/// spelling textually under the home, so `~/.ssh/./config` and
/// `<home>/.ssh/config` both collide with `~/.ssh/config`. A spelling that
/// reaches the same file only **through a symlink**, such as `/home/u/.gitconfig`
/// where `/home` links to `var/home` and the home is `/var/home/u`, is a
/// different string and is not caught. See the lexical-matching section of
/// [`crate::paths::Portable::parse_in`] for why that is the recorded limit.
fn check_unique(kind: &'static str, entries: Vec<(&str, &Origin)>) -> Result<(), Error> {
    let mut seen: BTreeMap<&str, &Origin> = BTreeMap::new();
    for (key, origin) in entries {
        if let Some(first) = seen.get(key) {
            return Err(Error::Duplicate {
                origin: origin.clone(),
                kind,
                key: key.to_string(),
                first: (*first).clone(),
            });
        }
        seen.insert(key, origin);
    }
    Ok(())
}

/// Everything that can go wrong reading a configuration.
///
/// Every variant carries an [`Origin`] or a path, so a message always says where
/// to look.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The config repo directory does not exist.
    #[error("no bx config repo at {}", .0.display())]
    RepoMissing(PathBuf),

    /// A layer file could not be read.
    #[error("{}: {source}", .path.display())]
    Io {
        /// The file being read.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A layer file is not valid TOML.
    #[error("{}: {source}", .file.display())]
    Syntax {
        /// The file being parsed.
        file: PathBuf,
        /// `toml_edit`'s own diagnostic, which names the line and column.
        #[source]
        source: Box<toml_edit::TomlError>,
    },

    /// A top-level section this version of `bx` does not know.
    #[error("{origin}: unknown section `{section}`")]
    UnknownSection {
        /// Where the section was declared.
        origin: Origin,
        /// Its name.
        section: String,
    },

    /// A key this version of `bx` does not know, inside a section it does.
    #[error("{origin}: unknown key `{key}` in {section}")]
    UnknownKey {
        /// Where the key was written.
        origin: Origin,
        /// The enclosing section, spelled as it is in the file.
        section: &'static str,
        /// The key.
        key: String,
    },

    /// A required key is absent.
    #[error("{origin}: {section} is missing the required key `{key}`")]
    MissingKey {
        /// Where the entry starts.
        origin: Origin,
        /// The enclosing section.
        section: &'static str,
        /// The key that should have been there.
        key: &'static str,
    },

    /// A key holds the wrong TOML type.
    #[error("{origin}: `{key}` must be {expected}, found {found}")]
    WrongType {
        /// Where the key was written.
        origin: Origin,
        /// The key.
        key: String,
        /// What was wanted.
        expected: &'static str,
        /// What was there.
        found: &'static str,
    },

    /// A key holds the right type and an unusable value.
    #[error("{origin}: {message}")]
    BadValue {
        /// Where the value was written.
        origin: Origin,
        /// What is wrong with it, and what would be right.
        message: String,
    },

    /// Two entries in one layer share a natural key.
    #[error("{origin}: duplicate {kind} `{key}`, first declared at {first}")]
    Duplicate {
        /// Where the repeat is.
        origin: Origin,
        /// What kind of entry repeated — "target", "value".
        kind: &'static str,
        /// The natural key that repeated.
        key: String,
        /// Where it was first declared.
        first: Origin,
    },

    /// This account's layer would be read from inside the config repo.
    ///
    /// The state directory lies inside the repo — `XDG_STATE_HOME` set to
    /// `XDG_CONFIG_HOME`, for one — so `local.toml` would be account content
    /// in a publishable git tree. Refused rather than skipped, because an
    /// account whose layer is silently dropped gets every other account's
    /// configuration with nothing saying why.
    #[error(
        "{}: this account's local layer is inside the config repo {}, a git working \
         tree meant to be published; set XDG_STATE_HOME to a directory outside it",
        .local.display(),
        .repo.display()
    )]
    LocalInRepo {
        /// Where the local layer would be read from.
        local: PathBuf,
        /// The config repo it lies inside.
        repo: PathBuf,
    },
}

/// The file, the bytes, and the entry being parsed out of them.
///
/// Carried through parsing so every error can name a line without each function
/// threading three arguments.
pub(crate) struct Ctx<'a> {
    /// The layer file.
    file: &'a Path,
    /// Its whole text, which spans index into.
    text: &'a str,
    /// The section header as it is spelled in the file, for messages.
    section: &'static str,
    /// The origin of the entry's own header.
    origin: Origin,
}

impl<'a> Ctx<'a> {
    /// A context for the entry `table` heads.
    pub(crate) fn new(table: &Table, file: &'a Path, text: &'a str, section: &'static str) -> Self {
        let origin = table
            .span()
            .map_or_else(|| Origin::unknown(file), |s| Origin::at(file, text, &s));
        Self {
            file,
            text,
            section,
            origin,
        }
    }

    /// The origin of the entry's header.
    pub(crate) fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The origin of one key inside the entry, falling back to the header.
    pub(crate) fn key_origin(&self, table: &Table, key: &str) -> Origin {
        table.key(key).and_then(toml_edit::Key::span).map_or_else(
            || self.origin.clone(),
            |s| Origin::at(self.file, self.text, &s),
        )
    }

    /// Reject any key the caller did not list.
    pub(crate) fn reject_unknown_keys(&self, table: &Table, known: &[&str]) -> Result<(), Error> {
        for (key, _) in table.iter() {
            if !known.contains(&key) {
                return Err(Error::UnknownKey {
                    origin: self.key_origin(table, key),
                    section: self.section,
                    key: key.to_string(),
                });
            }
        }
        Ok(())
    }

    /// An `Error::BadValue` positioned at `key`.
    pub(crate) fn bad(&self, table: &Table, key: &str, message: impl Into<String>) -> Error {
        Error::BadValue {
            origin: self.key_origin(table, key),
            message: message.into(),
        }
    }

    /// An `Error::WrongType` positioned at `key`.
    fn wrong_type(&self, table: &Table, key: &str, expected: &'static str, item: &Item) -> Error {
        Error::WrongType {
            origin: self.key_origin(table, key),
            key: key.to_string(),
            expected,
            found: item.type_name(),
        }
    }

    /// An optional string-valued key.
    pub(crate) fn str_at<'t>(&self, table: &'t Table, key: &str) -> Result<Option<&'t str>, Error> {
        match table.get(key) {
            None => Ok(None),
            Some(item) => item
                .as_str()
                .map(Some)
                .ok_or_else(|| self.wrong_type(table, key, "a string", item)),
        }
    }

    /// A required string-valued key.
    pub(crate) fn required_str<'t>(
        &self,
        table: &'t Table,
        key: &'static str,
    ) -> Result<&'t str, Error> {
        self.str_at(table, key)?.ok_or(Error::MissingKey {
            origin: self.origin.clone(),
            section: self.section,
            key,
        })
    }

    /// An optional boolean-valued key.
    pub(crate) fn bool_at(&self, table: &Table, key: &str) -> Result<Option<bool>, Error> {
        match table.get(key) {
            None => Ok(None),
            Some(item) => item
                .as_bool()
                .map(Some)
                .ok_or_else(|| self.wrong_type(table, key, "a boolean", item)),
        }
    }

    /// An optional array-of-strings key, absent meaning empty.
    pub(crate) fn str_array_at(&self, table: &Table, key: &str) -> Result<Vec<String>, Error> {
        let Some(item) = table.get(key) else {
            return Ok(Vec::new());
        };
        let array = item
            .as_array()
            .ok_or_else(|| self.wrong_type(table, key, "an array of strings", item))?;

        array
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Error::WrongType {
                        origin: self.key_origin(table, key),
                        key: key.to_string(),
                        expected: "an array of strings",
                        found: value.type_name(),
                    })
            })
            .collect()
    }

    /// Read `shells` from `table`, or [`Shells::EVERY`] when it is absent.
    /// `owner` names the entry, as the message for a bad list opens with.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] for a value that is not an array of strings, and
    /// [`Error::BadValue`] for an empty list or a name that is not a shell bx
    /// generates for.
    pub(crate) fn shells_at(&self, table: &Table, owner: &str) -> Result<Shells, Error> {
        if table.get(Shells::KEY).is_none() {
            return Ok(Shells::EVERY);
        }
        let names = self.str_array_at(table, Shells::KEY)?;
        Shells::from_names(&names)
            .map_err(|problem| self.bad(table, Shells::KEY, format!("{owner}: {problem}")))
    }
}

/// Read and parse every global layer in a config repo, **unmerged**.
///
/// Only tests call it, so it sits last, beside them.
///
/// # Errors
///
/// Whatever [`layer_files`] and [`load_layer`] return.
#[cfg(test)]
pub fn load_layers(repo: &Path, home: &Path) -> Result<Vec<Layer>, Error> {
    layer_files(repo)?
        .iter()
        .map(|path| load_layer(path, repo, home))
        .collect()
}

#[cfg(test)]
mod tests;
