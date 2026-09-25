//! The configuration model: what a `bx` config repo says, and where it said it.
//!
//! A config repo is a set of **layers**. `bx.toml` is the first, `modules/*.toml`
//! follow in lexicographic filename order, and the account's `local.toml` in the
//! state directory is last. This module discovers and parses them. It does not
//! merge them, resolve a value, or substitute anything: that is entry A3's, and
//! keeping the two apart is what lets a merge be a pure function of the layer
//! files.
//!
//! Documents are read through `toml_edit`'s DOM and never through `serde`.
//! `serde` deserialisation discards the spans [`Origin`] is built from, and the
//! DOM is also what will let a future `bx add` edit a hand-written file without
//! reflowing a byte the user wrote.
//!
//! # Unknown keys are errors
//!
//! An unrecognised top-level section, or an unrecognised key inside a recognised
//! entry, is an [`Error`] carrying its origin. A config written for a newer `bx`
//! therefore fails on an older one, loudly. That is deliberate: `bx` ships one
//! binary through one install channel, so a repo and a binary are versioned
//! together, and a silent no-op is the failure mode this tool exists to end.

pub mod env;
pub mod external;
pub mod history;
pub mod layers;
pub mod merge;
pub mod origin;
pub mod path;
pub mod resolve;
pub mod secrets;
pub mod shell_options;
pub mod target;
pub mod values;
pub mod when;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::shell::{alias, function, plugin, source};
use env::EnvDecl;
pub use origin::Origin;
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
    /// entries in the order written. See [`crate::shell::alias`].
    pub aliases: Vec<crate::shell::alias::AliasDecl>,
    /// `[[function]]`'s entries, keyed by `name`, in the order written. See
    /// [`crate::shell::function`].
    pub functions: Vec<crate::shell::function::FunctionDecl>,
    /// `[[plugin]]`'s entries, keyed by `name`, in the order written. See
    /// [`crate::shell::plugin`].
    pub plugins: Vec<crate::shell::plugin::PluginDecl>,
    /// `[[source]]`'s entries, keyed by `name`, in the order written: the
    /// declared optional sources. See [`crate::shell::source`].
    pub sources: Vec<crate::shell::source::SourceDecl>,
    /// `[secrets]`: a table, not a keyed list, so it merges key by key, the
    /// last layer that sets a key winning. See [`secrets`] for which layer may
    /// set which key.
    pub secrets: secrets::Secrets,
    /// `[history]`: a table, merged key by key like `[secrets]`. See
    /// [`history`].
    pub history: history::History,
    /// `[shell-options]`: a table, merged key by key. See [`shell_options`].
    pub shell_options: shell_options::ShellOptions,
    /// List entries that restate only their natural key and `enabled`.
    ///
    /// A **toggle**: it flips the flag on an entry an earlier layer introduced
    /// and leaves every other field alone, so opting out of a target costs three
    /// lines in `local.toml` rather than a copy of the whole target — body
    /// included — that the account wants gone. One list serves every keyed
    /// section, each toggle carrying the section it came from.
    ///
    /// Always empty after [`merge::merge`], which consumes them.
    pub toggles: Vec<merge::Toggle>,
    /// Files one layer names more than once only because of this account's
    /// answers.
    ///
    /// Empty from the parser. [`merge::merge`] fills it instead of failing the
    /// load, and [`resolve::resolve`] blocks every target for such a file.
    pub(crate) conflicts: Vec<merge::Conflict>,
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

/// Read and parse every global layer in a config repo, **unmerged**.
///
/// Merging is entry A3's, and keeping the two apart is what lets `bx plan` name
/// the layer that set a given entry.
///
/// # Errors
///
/// Whatever [`layer_files`] and [`load_layer`] return.
pub fn load_layers(repo: &Path, home: &Path) -> Result<Vec<Layer>, Error> {
    layer_files(repo)?
        .iter()
        .map(|path| load_layer(path, home))
        .collect()
}

/// Read and parse one layer file.
///
/// Any file in the layer schema, including the state directory's `local.toml`.
///
/// # Errors
///
/// [`Error::Io`] if the file cannot be read, and whatever [`parse_str`] returns.
pub fn load_layer(path: &Path, home: &Path) -> Result<Layer, Error> {
    tracing::debug!(file = %path.display(), "reading configuration layer");
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(Layer {
        file: path.to_path_buf(),
        // The repo loader only ever reads committed material. `layers::load_layer_set`
        // is what marks the one layer that came from the state directory.
        kind: LayerKind::Global,
        config: parse_str(&text, path, home)?,
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
                    match merge::toggle_of(table, merge::Section::Target, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .targets
                            .push(target::parse_target(table, file, text, home)?),
                    }
                }
            }
            "external" => {
                for table in entries(root, name, item, file, text)? {
                    match merge::toggle_of(table, merge::Section::External, file, text)? {
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
                        None => config
                            .externals
                            .push(external::parse_external(table, file, text, home)?),
                    }
                }
            }
            "value" => {
                for table in entries(root, name, item, file, text)? {
                    match merge::toggle_of(table, merge::Section::Value, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .values
                            .push(values::parse_value_decl(table, file, text)?),
                    }
                }
            }
            "env" => {
                for table in entries(root, name, item, file, text)? {
                    match merge::toggle_of(table, merge::Section::Env, file, text)? {
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
                config.path = path::parse_path(table, file, text)?;
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
                    match merge::toggle_of(table, merge::Section::Alias, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config.aliases.push(alias::parse_alias(table, file, text)?),
                    }
                }
            }
            "function" => {
                for table in entries(root, name, item, file, text)? {
                    match merge::toggle_of(table, merge::Section::Function, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .functions
                            .push(function::parse_function(table, file, text)?),
                    }
                }
            }
            "plugin" => {
                for table in entries(root, name, item, file, text)? {
                    match merge::toggle_of(table, merge::Section::Plugin, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .plugins
                            .push(plugin::parse_plugin(table, file, text)?),
                    }
                }
            }
            "source" => {
                for table in entries(root, name, item, file, text)? {
                    match merge::toggle_of(table, merge::Section::Source, file, text)? {
                        Some(toggle) => config.toggles.push(toggle),
                        None => config
                            .sources
                            .push(source::parse_source(table, file, text)?),
                    }
                }
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
            .chain(toggles_in(&config, merge::Section::Target))
            .collect(),
    )?;
    check_unique(
        "external",
        config
            .externals
            .iter()
            .map(|e| (e.path.as_str(), &e.origin))
            .chain(toggles_in(&config, merge::Section::External))
            .collect(),
    )?;
    check_unique(
        "value",
        config
            .values
            .iter()
            .map(|v| (v.name.as_str(), &v.origin))
            .chain(toggles_in(&config, merge::Section::Value))
            .collect(),
    )?;
    check_unique(
        "env",
        config
            .envs
            .iter()
            .map(|e| (e.name.as_str(), &e.origin))
            .chain(toggles_in(&config, merge::Section::Env))
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
            .chain(toggles_in(&config, merge::Section::Alias))
            .collect(),
    )?;
    check_unique(
        "function",
        config
            .functions
            .iter()
            .map(|f| (f.name.as_str(), &f.origin))
            .chain(toggles_in(&config, merge::Section::Function))
            .collect(),
    )?;
    check_unique(
        "plugin",
        config
            .plugins
            .iter()
            .map(|p| (p.name.as_str(), &p.origin))
            .chain(toggles_in(&config, merge::Section::Plugin))
            .collect(),
    )?;
    check_unique(
        "source",
        config
            .sources
            .iter()
            .map(|s| (s.name.as_str(), &s.origin))
            .chain(toggles_in(&config, merge::Section::Source))
            .collect(),
    )?;

    Ok(config)
}

/// The toggles in `config` that belong to one section, as `check_unique` wants
/// them.
fn toggles_in(config: &Config, section: merge::Section) -> impl Iterator<Item = (&str, &Origin)> {
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
/// Replacing an entry in place across layers is entry A3's merge rule. Twice in
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A config repo with the given files, each `(relative path, contents)`.
    fn repo(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().expect("a tempdir");
        for (rel, contents) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(&path, contents).expect("write");
        }
        dir
    }

    /// Just the filenames of the discovered layers, in order.
    fn names(repo: &Path) -> Vec<String> {
        layer_files(repo)
            .expect("discovery")
            .iter()
            .map(|p| {
                p.file_name()
                    .expect("a name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// The account's home every test in this module parses against.
    fn home() -> &'static Path {
        Path::new("/var/home/example")
    }

    fn parse(text: &str) -> Result<Config, Error> {
        parse_str(text, Path::new("bx.toml"), home())
    }

    /// A `[[target]]` entry built in memory, with no spans anywhere.
    ///
    /// Entry A3 parses a single entry out of a layer it is merging without
    /// going through a whole document, which is the case these tests cover.
    fn in_memory_target(extra: &[(&str, toml_edit::Item)]) -> Table {
        let mut table = Table::new();
        table.insert("path", toml_edit::value("~/.gitconfig"));
        table.insert("file", toml_edit::value("files/gitconfig"));
        for (key, item) in extra {
            table.insert(key, item.clone());
        }
        table
    }

    #[test]
    fn an_entry_with_no_span_degrades_to_an_unknown_origin() {
        // `Ctx::new` asks `toml_edit` for the entry header's span, and a table
        // nothing parsed has none. Line 0 says "this file, position unknown"
        // rather than pretending it is line 1 -- and rather than panicking on
        // an `expect`, which is what a caller like entry A3 would hit.
        let file = Path::new("bx.toml");
        let target = target::parse_target(&in_memory_target(&[]), file, "", home()).unwrap();

        assert_eq!(target.origin, Origin::unknown(file));
        assert_eq!(target.origin.to_string(), "bx.toml:0");
    }

    #[test]
    fn a_key_with_no_span_falls_back_to_its_entry() {
        // `Ctx::key_origin` positions an error at the offending key. With no
        // span it falls back to the entry's own origin, which for an in-memory
        // table is itself unknown.
        let file = Path::new("bx.toml");
        let table = in_memory_target(&[("nope", toml_edit::value(1))]);
        let error = target::parse_target(&table, file, "", home()).expect_err("unknown key");

        assert!(error.to_string().starts_with("bx.toml:0:"), "{error}");
        assert!(error.to_string().contains("`nope`"), "{error}");
    }

    #[test]
    fn a_section_key_with_no_span_degrades_to_an_unknown_origin() {
        // The third fallback. Unreachable from `parse_str`, because every key
        // in a parsed document has a span -- including the implicit one in
        // `[nope.deep]` -- so it is exercised where it lives.
        let mut root = Table::new();
        root.insert("target", toml_edit::value(1));

        assert_eq!(
            section_origin(&root, "target", Path::new("bx.toml"), ""),
            Origin::unknown(Path::new("bx.toml"))
        );
    }

    #[test]
    fn an_unreadable_modules_directory_names_the_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = repo(&[("bx.toml", ""), ("modules/a.toml", "")]);
        let modules = dir.path().join(MODULES_DIR);
        std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 000");

        // A process that can read a 0000 directory -- root, or one holding
        // CAP_DAC_READ_SEARCH -- cannot construct this case at all. Every job in
        // `.github/workflows/ci.yml` is a plain `runs-on: ubuntu-latest` with no
        // `container:` and no `user:`, and `mise run test` runs as the invoking
        // user, so no gate takes the branch below. Rather than a silent skip
        // nothing exercises, such a run fails unless the skip is asked for by
        // name, and the opted-in skip is announced through the stderr handle.
        let constructible = std::fs::read_dir(&modules).is_err();
        let result = layer_files(dir.path());
        std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o755))
            .expect("restore, so the tempdir can be removed");

        if !constructible {
            crate::testing::skip_unconstructible(
                "this process can read a 0000 directory, so the io error cannot be \
                 constructed here",
            );
            return;
        }
        match result {
            Err(Error::Io { path, .. }) => assert_eq!(path, modules),
            other => panic!(
                "expected an io error naming {}, got {other:?}",
                modules.display()
            ),
        }
    }

    fn message(text: &str) -> String {
        parse(text)
            .expect_err("should have been rejected")
            .to_string()
    }

    // --- discovery and ordering ------------------------------------------

    #[test]
    fn the_global_layer_comes_before_every_module() {
        let dir = repo(&[
            ("modules/aaa.toml", ""),
            ("bx.toml", ""),
            ("modules/bbb.toml", ""),
        ]);

        assert_eq!(names(dir.path()), ["bx.toml", "aaa.toml", "bbb.toml"]);
    }

    #[test]
    fn modules_are_ordered_by_raw_filename_bytes() {
        // Byte order, and nothing else: this expectation fails under
        // case-insensitive ordering, under natural-numeric ordering, and under
        // directory-iteration order alike.
        let dir = repo(&[
            ("modules/a.toml", ""),
            ("modules/_.toml", ""),
            ("modules/Z.toml", ""),
            ("modules/2-b.toml", ""),
            ("modules/10-a.toml", ""),
        ]);

        assert_eq!(
            names(dir.path()),
            ["10-a.toml", "2-b.toml", "Z.toml", "_.toml", "a.toml"]
        );
    }

    #[test]
    fn module_order_does_not_depend_on_creation_order() {
        let forward: Vec<(String, String)> = (0..20)
            .map(|i| (format!("modules/{i:02}.toml"), String::new()))
            .collect();
        let reversed: Vec<(&str, &str)> = forward
            .iter()
            .rev()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();

        let dir = repo(&reversed);
        let expected: Vec<String> = (0..20).map(|i| format!("{i:02}.toml")).collect();

        assert_eq!(names(dir.path()), expected);
    }

    #[test]
    fn a_missing_modules_directory_is_not_an_error() {
        let dir = repo(&[("bx.toml", "")]);
        assert_eq!(names(dir.path()), ["bx.toml"]);
    }

    #[test]
    fn a_missing_bx_toml_is_not_an_error() {
        let dir = repo(&[("modules/one.toml", "")]);
        assert_eq!(names(dir.path()), ["one.toml"]);
    }

    #[test]
    fn an_empty_repo_has_no_layers() {
        let dir = repo(&[]);
        assert!(layer_files(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_missing_repo_is_an_error() {
        let dir = repo(&[]);
        let missing = dir.path().join("nowhere");

        let error = layer_files(&missing).expect_err("should be an error");
        assert!(matches!(error, Error::RepoMissing(ref p) if *p == missing));
        assert!(error.to_string().contains("no bx config repo at"));
    }

    /// A repo root beneath a regular file is missing, exactly as one at a file is.
    ///
    /// `lstat` on `dotconfig/bx` with `dotconfig` a regular file says `ENOTDIR`,
    /// not `ENOENT`, and that came back as an io error while a regular file at
    /// the root itself was `RepoMissing`: one fault, two answers.
    ///
    /// Guards the other side of R4-6: a root that is a symlink to such a place
    /// is still an error. The follow with `stat` fails with `ENOTDIR` as well,
    /// never `ENOENT`, so what comes back is a plain io error naming the link,
    /// and not the dangling one. The kind is asserted so this doc cannot drift
    /// from it.
    #[test]
    fn a_repo_beneath_a_regular_file_is_missing() {
        let dir = repo(&[("dotconfig", "")]);
        let beneath = dir.path().join("dotconfig/bx");

        let error = layer_files(&beneath).expect_err("should be an error");
        assert!(
            matches!(error, Error::RepoMissing(ref p) if *p == beneath),
            "{error:?}"
        );

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("dotconfig/x"), &link).expect("symlink");
        match layer_files(&link) {
            Err(Error::Io { path, source }) => {
                assert_eq!(path, link);
                assert_eq!(
                    source.kind(),
                    std::io::ErrorKind::NotADirectory,
                    "the follow fails at `dotconfig`, not at a missing target: {source}"
                );
                assert!(!source.to_string().contains("dangling"), "{source}");
            }
            other => panic!("expected an io error naming the link, got {other:?}"),
        }
    }

    #[test]
    fn non_toml_files_in_modules_are_ignored() {
        let dir = repo(&[
            ("modules/keep.toml", ""),
            ("modules/README.md", ""),
            ("modules/notes.toml.bak", ""),
            ("modules/toml", ""),
        ]);

        assert_eq!(names(dir.path()), ["keep.toml"]);
    }

    #[test]
    fn a_dotfile_in_modules_is_ignored() {
        let dir = repo(&[("modules/keep.toml", ""), ("modules/.hidden.toml", "")]);
        assert_eq!(names(dir.path()), ["keep.toml"]);
    }

    #[test]
    fn a_directory_named_like_a_module_is_ignored() {
        let dir = repo(&[("modules/keep.toml", "")]);
        std::fs::create_dir(dir.path().join("modules/looks-like.toml")).expect("mkdir");

        assert_eq!(names(dir.path()), ["keep.toml"]);
    }

    #[test]
    fn a_nested_directory_is_not_searched() {
        let dir = repo(&[("modules/keep.toml", ""), ("modules/sub/deep.toml", "")]);
        assert_eq!(names(dir.path()), ["keep.toml"]);
    }

    /// The io error `layer_files` returned for `repo`, which must name `expected`.
    fn io_error_naming(repo: &Path, expected: &Path) -> std::io::Error {
        match layer_files(repo) {
            Err(Error::Io { path, source }) => {
                assert_eq!(path, expected);
                source
            }
            other => panic!(
                "expected an io error naming {}, got {other:?}",
                expected.display()
            ),
        }
    }

    /// A module that is a dangling symlink is an error, not an absent layer.
    ///
    /// `is_file()` answers `false` for every failed `stat`, so a dangling
    /// `modules/20-off.toml` -- the module that says `enabled = false` -- was
    /// dropped and `Ok([bx.toml, 10-a.toml])` came back. The target it disables
    /// then applies, and nothing says why.
    #[test]
    fn a_dangling_module_symlink_is_an_error_naming_it() {
        let dir = repo(&[("bx.toml", ""), ("modules/10-a.toml", "")]);
        let dangling = dir.path().join("modules/20-off.toml");
        std::os::unix::fs::symlink(dir.path().join("nowhere.toml"), &dangling).expect("symlink");

        io_error_naming(dir.path(), &dangling);
        let message = layer_files(dir.path()).expect_err("dangling").to_string();
        assert!(message.contains("20-off.toml"), "{message}");
        assert!(message.contains("dangling symlink"), "{message}");
    }

    /// A symlink loop is reported as the loop, not as a dangling link.
    ///
    /// `ELOOP` comes from following the link, after `lstat` found it. Reading
    /// every failure there as "dangling" would name the wrong fault, and nothing
    /// else distinguishes the two branches.
    #[test]
    fn a_module_symlink_loop_is_an_error_naming_the_loop() {
        let dir = repo(&[("bx.toml", "")]);
        std::fs::create_dir(dir.path().join(MODULES_DIR)).expect("mkdir");
        let looped = dir.path().join("modules/loop.toml");
        std::os::unix::fs::symlink(&looped, &looped).expect("a symlink to itself");

        let source = io_error_naming(dir.path(), &looped);
        assert_ne!(source.kind(), std::io::ErrorKind::NotFound, "{source}");
        assert!(!source.to_string().contains("dangling"), "{source}");
    }

    /// A dangling `bx.toml` is an error, not a repo without a global layer.
    ///
    /// Under `is_file()` this returned `Ok([10-a.toml])`: every module, and
    /// silently not the layer they are all meant to sit on top of.
    #[test]
    fn a_dangling_bx_toml_is_an_error_naming_it() {
        let dir = repo(&[("modules/10-a.toml", "")]);
        let global = dir.path().join(GLOBAL_LAYER);
        std::os::unix::fs::symlink(dir.path().join("nowhere.toml"), &global).expect("symlink");

        io_error_naming(dir.path(), &global);
    }

    /// A dangling `modules` is an error, not a repo without modules.
    #[test]
    fn a_dangling_modules_directory_is_an_error_naming_it() {
        let dir = repo(&[("bx.toml", "")]);
        let modules = dir.path().join(MODULES_DIR);
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &modules).expect("symlink");

        io_error_naming(dir.path(), &modules);
    }

    /// A `modules/` that can be listed but not searched is an error.
    ///
    /// At mode 0644 `read_dir` succeeds, because listing needs only `r`, and
    /// every `stat` inside fails with `EACCES`, because that needs `x`. Under
    /// `is_file()` every module was dropped and `Ok([bx.toml])` came back.
    #[test]
    fn a_modules_directory_that_cannot_be_searched_names_the_entry() {
        use std::os::unix::fs::PermissionsExt;

        let dir = repo(&[("bx.toml", ""), ("modules/10-a.toml", "")]);
        let modules = dir.path().join(MODULES_DIR);
        let module = modules.join("10-a.toml");
        std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 644");

        // A process that can stat inside an unsearchable directory -- root, or
        // one holding CAP_DAC_READ_SEARCH -- cannot construct this case. No CI
        // job runs that way, so a silent skip would be a branch nothing
        // exercises: such a run fails unless the skip is asked for by name.
        let constructible = std::fs::metadata(&module).is_err();
        let result = layer_files(dir.path());
        std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o755))
            .expect("restore, so the tempdir can be removed");

        if !constructible {
            crate::testing::skip_unconstructible(
                "this process can stat inside a 0644 directory, so EACCES cannot be \
                 constructed here",
            );
            return;
        }
        match result {
            Err(Error::Io { path, source }) => {
                assert_eq!(path, module);
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!(
                "expected an io error naming {}, got {other:?}",
                module.display()
            ),
        }
    }

    /// A name that is not a layer is filtered out before it is ever stat'ed.
    ///
    /// Otherwise a dangling `README.md`, or the `.#keep.toml` lock Emacs leaves
    /// as a dangling symlink, would become an error about a file bx never meant
    /// to read.
    #[test]
    fn a_dangling_name_that_is_not_a_layer_is_never_examined() {
        let dir = repo(&[("modules/keep.toml", "")]);
        let modules = dir.path().join(MODULES_DIR);
        for name in [".#keep.toml", "README.md", "notes.toml.bak"] {
            std::os::unix::fs::symlink(dir.path().join("nowhere"), modules.join(name))
                .expect("symlink");
        }

        assert_eq!(names(dir.path()), ["keep.toml"]);
    }

    /// A symlink to a regular file is a layer, as it was under `is_file()`.
    #[test]
    fn a_module_symlinked_to_a_regular_file_is_a_layer() {
        let dir = repo(&[("elsewhere/real.toml", ""), ("bx.toml", "")]);
        std::fs::create_dir(dir.path().join(MODULES_DIR)).expect("mkdir");
        std::os::unix::fs::symlink(
            dir.path().join("elsewhere/real.toml"),
            dir.path().join("modules/linked.toml"),
        )
        .expect("symlink");

        assert_eq!(names(dir.path()), ["bx.toml", "linked.toml"]);
    }

    /// A `bx.toml` or `modules` that exists as the wrong kind of file is a
    /// clean "not a layer", not an error.
    #[test]
    fn a_global_layer_or_modules_of_the_wrong_kind_is_skipped() {
        let dir = repo(&[("modules", "a regular file, not a directory")]);
        std::fs::create_dir(dir.path().join(GLOBAL_LAYER)).expect("mkdir");

        assert!(layer_files(dir.path()).unwrap().is_empty());
    }

    /// A repo that is a regular file is missing; a dangling one is an error.
    #[test]
    fn a_repo_that_is_a_file_is_missing_and_a_dangling_one_is_an_error() {
        let dir = repo(&[("file", "")]);
        let file = dir.path().join("file");
        assert!(matches!(layer_files(&file), Err(Error::RepoMissing(ref p)) if *p == file));

        let dangling = dir.path().join("repo");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).expect("symlink");
        io_error_naming(&dangling, &dangling);
    }

    // --- loading ----------------------------------------------------------

    #[test]
    fn layers_are_returned_unmerged() {
        // The same target path in two layers stays two layers. Replacing one
        // with the other is A3's merge, and it needs both to do it.
        let dir = repo(&[
            (
                "bx.toml",
                "[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/gitconfig\"\n",
            ),
            (
                "modules/git.toml",
                "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"overridden\"\n",
            ),
        ]);
        let layers = load_layers(dir.path(), home()).expect("loading");

        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].file, dir.path().join("bx.toml"));
        assert_eq!(layers[1].file, dir.path().join("modules/git.toml"));
        assert_eq!(layers[0].config.targets.len(), 1);
        assert_eq!(layers[1].config.targets.len(), 1);
        assert_ne!(layers[0].config.targets[0], layers[1].config.targets[0]);
    }

    #[test]
    fn every_entry_names_the_file_it_came_from() {
        let dir = repo(&[(
            "modules/git.toml",
            "# a module\n\n[[target]]\npath = \"~/.gitconfig\"\nfile = \"f\"\n",
        )]);
        let layers = load_layers(dir.path(), home()).expect("loading");
        let origin = &layers[0].config.targets[0].origin;

        assert_eq!(origin.file, dir.path().join("modules/git.toml"));
        assert_eq!(origin.line, 3);
    }

    #[test]
    fn a_layer_that_cannot_be_read_names_the_file() {
        let dir = repo(&[]);
        let missing = dir.path().join("bx.toml");

        let error = load_layer(&missing, home()).expect_err("should be an error");
        assert!(matches!(error, Error::Io { .. }));
        assert!(error.to_string().contains("bx.toml"));
    }

    // --- parsing ----------------------------------------------------------

    #[test]
    fn an_empty_layer_is_the_default_config() {
        assert_eq!(parse("").unwrap(), Config::default());
        assert_eq!(parse("# only a comment\n").unwrap(), Config::default());
    }

    #[test]
    fn entries_keep_document_order() {
        let text = "[[target]]\npath = \"~/z\"\nfile = \"z\"\n\n\
                    [[target]]\npath = \"~/a\"\nfile = \"a\"\n\n\
                    [[target]]\npath = \"~/m\"\nfile = \"m\"\n";
        let config = parse(text).unwrap();
        let paths: Vec<&str> = config.targets.iter().map(|t| t.path.as_str()).collect();

        assert_eq!(paths, ["~/z", "~/a", "~/m"]);
    }

    #[test]
    fn every_section_lands_in_its_own_field() {
        let text = "[[target]]\npath = \"~/.gitconfig\"\nfile = \"f\"\n\n\
                    [[value]]\nname = \"git_email\"\nkind = \"email\"\nrequired = true\n\n\
                    [values]\ngit_email = \"someone@example.invalid\"\n\n\
                    [[env]]\nname = \"LANG\"\nvalue = \"C.UTF-8\"\nkind = \"environment\"\n";
        let config = parse(text).unwrap();

        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.values.len(), 1);
        assert_eq!(config.value_assignments.len(), 1);
        assert_eq!(config.value_assignments[0].name, "git_email");
        assert_eq!(config.envs.len(), 1);
        assert_eq!(config.envs[0].name, "LANG");
    }

    #[test]
    fn a_duplicate_env_name_in_one_layer_is_rejected() {
        let entry = "[[env]]\nname = \"LANG\"\nvalue = \"C\"\nkind = \"gui\"\n";
        let twice = message(&format!("{entry}{entry}"));
        assert!(twice.contains("duplicate env `LANG`"), "{twice}");
        // And a toggle beside the entry it flips is the same ambiguity.
        let toggled = message(&format!(
            "{entry}[[env]]\nname = \"LANG\"\nenabled = false\n"
        ));
        assert!(toggled.contains("duplicate env `LANG`"), "{toggled}");
    }

    #[test]
    fn a_plugin_section_parses_and_a_duplicate_name_is_rejected() {
        let entry = "[[plugin]]\nname = \"autosuggest\"\nsource = \"~/a.zsh\"\n";
        let config = parse_str(
            &format!("{entry}[[plugin]]\nname = \"other\"\nenabled = false\n"),
            Path::new("/repo/bx.toml"),
            home(),
        )
        .expect("parses");
        assert_eq!(config.plugins.len(), 1);
        assert_eq!(config.plugins[0].name, "autosuggest");
        assert_eq!(config.toggles.len(), 1);
        assert_eq!(config.toggles[0].section, merge::Section::Plugin);

        let twice = message(&format!("{entry}{entry}"));
        assert!(twice.contains("duplicate plugin `autosuggest`"), "{twice}");
        let toggled = message(&format!(
            "{entry}[[plugin]]\nname = \"autosuggest\"\nenabled = false\n"
        ));
        assert!(
            toggled.contains("duplicate plugin `autosuggest`"),
            "{toggled}"
        );
        // The entry's own parser runs: a malformed source is refused here.
        let bad = message("[[plugin]]\nname = \"a\"\nsource = \"a.zsh\"\n");
        assert!(bad.contains("must open with"), "{bad}");
    }

    #[test]
    fn an_unknown_section_is_rejected_with_its_line() {
        let text = "[[target]]\npath = \"~/a\"\nfile = \"f\"\n\n[[abbr]]\nname = \"ll\"\n";
        let message = message(text);

        assert!(message.contains("unknown section `abbr`"), "{message}");
        assert!(message.contains("bx.toml:5"), "{message}");
    }

    #[test]
    fn a_section_of_the_wrong_shape_is_rejected() {
        assert!(message("[target]\npath = \"~/a\"\n").contains("a repeated section"));
        assert!(message("[[values]]\nx = \"1\"\n").contains("a table `[values]`"));
    }

    #[test]
    fn a_syntax_error_names_the_file_and_position() {
        let error = parse_str("[[target]\n", Path::new("/repo/bx.toml"), home())
            .expect_err("should be a syntax error");

        assert!(matches!(error, Error::Syntax { .. }));
        let message = error.to_string();
        assert!(message.contains("/repo/bx.toml"), "{message}");
        assert!(message.contains("line 1"), "{message}");
    }

    #[test]
    fn a_duplicate_target_path_in_one_layer_is_rejected() {
        let text = "[[target]]\npath = \"~/.gitconfig\"\nfile = \"a\"\n\n\
                    [[target]]\npath = \"~/.gitconfig\"\nfile = \"b\"\n";
        let message = message(text);

        assert!(
            message.contains("duplicate target `~/.gitconfig`"),
            "{message}"
        );
        assert!(message.contains("first declared at bx.toml:1"), "{message}");
        assert!(message.contains("bx.toml:5"), "{message}");
    }

    #[test]
    fn a_duplicate_target_path_spelled_differently_is_rejected() {
        // The natural key is the normalised Portable, not the bytes a human
        // typed. Without that, one file quietly acquires two ledger rows.
        for second in ["~/.ssh/./config", "~/.ssh//config", "~/.ssh/keys/../config"] {
            let text = format!(
                "[[target]]\npath = \"~/.ssh/config\"\nfile = \"a\"\n\n\
                 [[target]]\npath = \"{second}\"\nfile = \"b\"\n"
            );
            assert!(
                message(&text).contains("duplicate target `~/.ssh/config`"),
                "{second} should collide with ~/.ssh/config"
            );
        }
    }

    #[test]
    fn the_absolute_spelling_of_a_home_file_never_becomes_a_second_key() {
        // check_unique compares the stored strings, so it cannot see that
        // `/var/home/example/.ssh/config` and `~/.ssh/config` are one file. The
        // parser refuses the absolute spelling instead, which is what keeps one
        // file from acquiring two `attach = "own"` targets in one layer set.
        let text = "[[target]]\npath = \"~/.ssh/config\"\nfile = \"a\"\n\n\
                    [[target]]\npath = \"/var/home/example/.ssh/config\"\nfile = \"b\"\n";
        let message = message(text);

        assert!(message.contains("~/.ssh/config"), "{message}");
        assert!(
            message.contains("bx.toml:6"),
            "the caret must land on the offending `path` key: {message}"
        );
    }

    /// `load_layers` parses against the home it is *given*.
    ///
    /// Nothing pinned that. Mutating `load_layers` to forward a hard-coded
    /// `/nonexistent/mutated/home` left every test in this module passing,
    /// because they all spell target paths `~/…`, which `parse_in` accepts
    /// identically under any home; the tests that do depend on the home call
    /// `parse_str` or `parse_target` directly and never reach the loader. So the
    /// home threads through five call sites and the first two — `load_layers`
    /// into `load_layer`, `load_layer` into `parse_str` — were unpinned, and
    /// `load_layers` is the function entry A3's merge and every later entry read
    /// a config repo through.
    ///
    /// An **absolutely** spelled target path is the discriminating input: it is
    /// admissible under one home and refused under another, so the error can
    /// only arrive if this exact home reached `Portable::parse_in`.
    #[test]
    fn load_layers_parses_against_the_home_it_is_given() {
        let dir = repo(&[(
            "modules/ssh.toml",
            "[[target]]\npath = \"/var/home/example/.ssh/config\"\nfile = \"files/ssh\"\n",
        )]);

        let error = load_layers(dir.path(), home()).expect_err("absolute, and under this home");
        let message = error.to_string();
        assert!(
            message.contains("write ~/.ssh/config"),
            "the message must name the `~/…` spelling for *this* home: {message}"
        );

        // The same repo under a home the path is not inside parses, and keeps
        // the absolute spelling: the rule is about this home, not about the
        // string.
        let layers = load_layers(dir.path(), Path::new("/var/home/other")).expect("outside");
        assert_eq!(
            layers[0].config.targets[0].path.as_str(),
            "/var/home/example/.ssh/config"
        );
    }

    #[test]
    fn a_target_path_that_climbs_out_of_home_is_rejected() {
        let text = "[[target]]\npath = \"~/../../etc/passwd\"\nfile = \"a\"\n";
        assert!(message(text).contains("climb out of the home"));
    }

    #[test]
    fn a_duplicate_value_name_in_one_layer_is_rejected() {
        let text = "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n\n\
                    [[value]]\nname = \"scratch_root\"\nkind = \"string\"\n";
        assert!(message(text).contains("duplicate value `scratch_root`"));
    }

    #[test]
    fn one_layer_may_not_both_restate_an_entry_and_toggle_it() {
        // The silent no-op the toggle mechanism exists to prevent, at its
        // sharpest: which of the two wins would depend on the order the merge
        // happens to apply them in, and nothing in the file says what that order
        // is. The uniqueness check sees toggles alongside the entries they flip
        // for exactly this.
        let text = "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"x\"\n\n\
                    [[target]]\npath = \"~/.gitconfig\"\nenabled = false\n";
        let message = message(text);

        assert!(
            message.contains("duplicate target `~/.gitconfig`"),
            "{message}"
        );
        assert!(message.contains("first declared at bx.toml:1"), "{message}");
        assert!(message.contains("bx.toml:5"), "{message}");
    }

    #[test]
    fn a_toggle_before_the_entry_it_flips_is_the_same_ambiguity() {
        // Order within the file makes no difference: it is the pair that is
        // ambiguous, not the direction.
        let text = "[[target]]\npath = \"~/.gitconfig\"\nenabled = false\n\n\
                    [[target]]\npath = \"~/.gitconfig\"\ncontent = \"x\"\n";
        assert!(message(text).contains("duplicate target `~/.gitconfig`"));

        let text = "[[value]]\nname = \"agent_slice\"\nkind = \"string\"\n\n\
                    [[value]]\nname = \"agent_slice\"\nenabled = false\n";
        assert!(message(text).contains("duplicate value `agent_slice`"));
    }

    #[test]
    fn the_same_path_in_two_layers_is_not_a_duplicate() {
        // It is a replacement, and A3 performs it.
        let a = parse("[[target]]\npath = \"~/a\"\nfile = \"a\"\n").unwrap();
        let b = parse("[[target]]\npath = \"~/a\"\nfile = \"b\"\n").unwrap();

        assert_eq!(a.targets[0].path, b.targets[0].path);
    }

    // --- the invariants ---------------------------------------------------

    #[test]
    fn parsing_is_a_pure_function_of_the_bytes() {
        // Invariant 3. Two plan runs a week apart on an unchanged tree have to
        // read the same configuration in the same order.
        let text = "[[target]]\npath = \"~/z\"\nfile = \"z\"\n\n\
                    [[target]]\npath = \"~/a\"\ncontent = \"x\"\n\n\
                    [[value]]\nname = \"v\"\nkind = \"string\"\n\n\
                    [values]\nv = \"1\"\n";

        let first = parse(text).unwrap();
        for _ in 0..8 {
            assert_eq!(parse(text).unwrap(), first);
        }
    }

    #[test]
    fn comments_and_formatting_survive_a_round_trip() {
        // Invariant 1, for configuration. Reading through toml_edit's DOM is
        // what will let `bx add` edit a hand-written file without rewriting a
        // byte the user wrote. `into_mut` is called only to render here; the
        // parser never calls it, because it discards every span.
        let text = "# the global layer\n\
                    \n\
                    [[target]]   # the gitconfig\n\
                    path    = \"~/.gitconfig\"     # where it lands\n\
                    file    = 'files/gitconfig'\n\
                    \n\
                    \n\
                    [values]\n\
                    v = \"1\"  # trailing\n\
                    # a trailing comment with no newline after it";

        parse(text).expect("the fixture parses");
        let rendered = Document::parse(text)
            .expect("valid TOML")
            .into_mut()
            .to_string();

        assert_eq!(rendered, text);
    }

    #[test]
    fn every_error_renders_with_its_origin() {
        let origin = Origin {
            file: PathBuf::from("bx.toml"),
            line: 7,
        };
        let first = Origin {
            file: PathBuf::from("bx.toml"),
            line: 2,
        };

        let rendered = [
            Error::RepoMissing(PathBuf::from("/repo")).to_string(),
            Error::Io {
                path: PathBuf::from("/repo/bx.toml"),
                source: std::io::Error::other("broken"),
            }
            .to_string(),
            Error::UnknownSection {
                origin: origin.clone(),
                section: "alias".to_string(),
            }
            .to_string(),
            Error::UnknownKey {
                origin: origin.clone(),
                section: "[[target]]",
                key: "symlink".to_string(),
            }
            .to_string(),
            Error::MissingKey {
                origin: origin.clone(),
                section: "[[target]]",
                key: "path",
            }
            .to_string(),
            Error::WrongType {
                origin: origin.clone(),
                key: "enabled".to_string(),
                expected: "a boolean",
                found: "string",
            }
            .to_string(),
            Error::BadValue {
                origin: origin.clone(),
                message: "unusable".to_string(),
            }
            .to_string(),
            Error::Duplicate {
                origin,
                kind: "target",
                key: "~/.gitconfig".to_string(),
                first,
            }
            .to_string(),
        ];

        assert_eq!(rendered[0], "no bx config repo at /repo");
        assert_eq!(rendered[1], "/repo/bx.toml: broken");
        assert_eq!(
            Error::LocalInRepo {
                local: PathBuf::from("/repo/local.toml"),
                repo: PathBuf::from("/repo"),
            }
            .to_string(),
            "/repo/local.toml: this account's local layer is inside the config repo /repo, a \
             git working tree meant to be published; set XDG_STATE_HOME to a directory outside it"
        );
        for message in &rendered[2..] {
            assert!(
                message.starts_with("bx.toml:7: "),
                "every error says where: {message}"
            );
        }
        assert!(
            rendered
                .last()
                .unwrap()
                .contains("first declared at bx.toml:2")
        );
    }
}
