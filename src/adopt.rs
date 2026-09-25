//! `bx add` and `bx rm`: taking existing config into the repo, and handing it
//! back.
//!
//! # `add` is lossless
//!
//! A file is adopted **byte for byte**. Its bytes are copied into the config
//! repo at `files/<its path under the home>` without being read as text, so
//! line endings, a missing trailing newline and non-UTF-8 content all survive,
//! and a `[[target]]` naming that copy is appended to `bx.toml`. The file's
//! mode is kept twice: on the copy, so a private file is not readable by other
//! accounts while it sits in the repo, and as the target's `mode`, because git
//! records only the executable bit and a fresh machine must get `0600` back.
//! The file in the home is never written: adoption changes what bx manages,
//! not what is on disk.
//!
//! Adoption is also a claim of ownership. The ledger records the file with the
//! bytes it holds now as both what bx left and what `rm` restores, so a later
//! edit to the repo's copy is a `Modify` that `apply` makes rather than a
//! conflict with a file bx does not own, and `rm` hands back exactly the
//! file that was adopted. The record is made without a journalled session
//! because nothing at the destination is written: there is nothing for an
//! interruption to leave half done, and every step here is safe to repeat. A
//! run that stops after the copy finds it on the next run and reuses it; one
//! that stops after the declaration finds the target declared, unchanged and
//! unowned, and records the ownership it lacked.
//!
//! Refused rather than adopted: a symbolic link (its resolved bytes are not
//! what is at that path), anything but a regular file, anything inside bx's
//! config repo or state directory, and a path on a conservative list of files
//! that hold credentials — Invariant 5 forbids a cleartext secret in the repo.
//! A directory is adopted file by file, in byte order of the names, skipping
//! those same things and every `.git` directory, whose objects are another
//! repository's and would make the config repo a nested one.
//!
//! A file whose environment assignments would move a tool's config, data or
//! cache outside a declared root is adopted with a warning naming each line:
//! it is the user's file, and bx neither rewrites it nor refuses it, but it
//! must not be adopted silently.
//!
//! # `rm` restores exactly
//!
//! `rm` spends the ledger through [`crate::restore`]: the prior bytes and mode
//! when bx replaced a file, removal when bx created one, and nothing written
//! when the file was edited since bx last wrote it. Each target it releases is
//! then removed from every layer that declares it; a conflict keeps its
//! declaration, so nothing about it changes. The body file in the repo is left
//! where it is: it may be a file the user wrote, and deleting it is theirs.
//!
//! A tracked target (`direction = "track"`) is handed back through what bx
//! claimed of its two copies: the repo copy gets back the bytes it held before
//! `sync` first carried this machine's copy into it, and a machine copy
//! `apply` created where this machine had none is removed, with the
//! directories made for it. A machine copy the tool had before bx wrote to it
//! is never claimed, and is left as it is. Where either copy would conflict,
//! neither is restored and the target stays declared.
//!
//! A `tree = "…"` entry is one declaration of many files, so `rm` hands a tree
//! back whole or not at all: on the tree's path it releases every file and the
//! table together, unless one file would be a conflict, which leaves the whole
//! tree managed; on a file inside it, it releases nothing and names `exclude`.
//! `add` likewise refuses to copy a file into a tree's root, where the tree
//! would declare it beside the `[[target]]` `add` writes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use toml_edit::{ArrayOfTables, Document, DocumentMut, Item, Table, value};

use crate::config::resolve::{Resolution, Resolved};
use crate::config::target::{Attach, Body, Direction, Format};
use crate::config::values::ResolvedValues;
use crate::config::{self, Layer, Origin, layers, merge, resolve};
use crate::env_guard::{self, Reason, RootSet};
use crate::fs::{self, Kind, Mode};
use crate::journal;
use crate::paths::{self, Portable};
use crate::plan::Env;
use crate::recover;
use crate::restore::{self, Restored};
use crate::state::{
    ContentHash, ExclusiveLock, Ledger, LedgerView, Mechanism, NewEntry, PriorBytes, StateDir,
};

/// The layer `add` declares new targets in.
const GLOBAL_LAYER: &str = "bx.toml";

/// The repo directory adopted bodies are copied into.
const FILES_DIR: &str = "files";

/// Everything that stops `add` or `rm`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No path was named.
    #[error(
        "name the file or directory to {0}, e.g. `bx {0} ~/.gitconfig`; `bx init` is what \
         offers the config already on this machine"
    )]
    NoPath(&'static str),
    /// The path could not be made portable.
    #[error(transparent)]
    Path(#[from] paths::Error),
    /// The path is not strictly inside the home.
    #[error(
        "{0} is not inside your home; bx manages files beneath it, so the repo means the same \
         files on every account"
    )]
    OutsideHome(String),
    /// There is nothing at the path.
    #[error("there is nothing at {0} to add")]
    Missing(String),
    /// There is no config repo.
    #[error("no bx config repo at {}; run `bx init` to create one", .0.display())]
    RepoMissing(PathBuf),
    /// The configuration could not be loaded, merged or resolved.
    #[error(transparent)]
    Config(config::Error),
    /// A layer file could not be edited.
    #[error("{}: {why}", .path.display())]
    Layer {
        /// The layer.
        path: PathBuf,
        /// Why.
        why: String,
    },
    /// A file or directory could not be read.
    #[error("reading {}: {source}", .path.display())]
    Read {
        /// What could not be read.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A directory in the config repo, to hold an adopted body, could not be
    /// made.
    #[error("creating {}: {source}", .path.display())]
    RepoDir {
        /// The directory.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A write failed.
    #[error(transparent)]
    Fs(#[from] fs::Error),
    /// The state directory failed, including another bx holding it.
    #[error(transparent)]
    State(#[from] crate::state::Error),
    /// A session is still standing after recovery ran.
    #[error(transparent)]
    Journal(#[from] journal::Error),
    /// An earlier interruption could not be resolved.
    #[error(transparent)]
    Recover(#[from] recover::Error),
    /// Restoring failed.
    #[error(transparent)]
    Restore(#[from] restore::Error),
    /// The output could not be written.
    #[error("writing the output: {0}")]
    Output(#[source] std::io::Error),
}

impl From<config::Error> for Error {
    fn from(error: config::Error) -> Self {
        match error {
            config::Error::RepoMissing(repo) => Self::RepoMissing(repo),
            other => Self::Config(other),
        }
    }
}

/// What `add` and `rm` work against, loaded once.
#[derive(Debug, Clone)]
pub struct Context {
    home: PathBuf,
    repo: PathBuf,
    state: StateDir,
    layers: Vec<Layer>,
    resolved: Resolved,
    roots: RootSet,
    /// The `git` `rm` asks whether a checkout bx cloned holds anything of
    /// the user's.
    git: crate::sync::Git,
    trees: Vec<TreeDecl>,
}

/// A `tree = "…"` entry some layer declares, as `add` and `rm` need it.
///
/// Loading expands a tree into ordinary targets and keeps nothing of the tree
/// itself, so this is read back from each layer's own parse. The files are
/// the expanded targets carrying the tree's origin: exactly those the tree
/// declares, and not an explicit target that happens to lie beneath its path.
#[derive(Debug, Clone)]
struct TreeDecl {
    /// Where the tree lands, as the resolved configuration names it.
    path: Portable,
    /// Its directory in the config repo, repo-relative.
    root: PathBuf,
    /// Where it was written.
    origin: Origin,
    /// Every file it declares, by resolved path.
    files: BTreeSet<Portable>,
}

/// Every tree `layers` declare, in layer order.
fn trees_of(layers: &[Layer], values: &ResolvedValues) -> Result<Vec<TreeDecl>, Error> {
    let mut found = Vec::new();
    for layer in layers {
        let (text, _) = open_layer(&layer.file)?;
        for tree in config::parse_str(&text, &layer.file, values.home())?.trees {
            let Some(path) = resolved_path(tree.path.as_str(), values) else {
                continue;
            };
            let files = layer
                .config
                .targets
                .iter()
                .filter(|target| target.origin == tree.origin)
                .filter_map(|target| resolved_path(target.path.as_str(), values))
                .collect();
            found.push(TreeDecl {
                path,
                root: tree.root,
                origin: tree.origin,
                files,
            });
        }
    }
    Ok(found)
}

impl Context {
    /// Locate the config repo and the state directory and load the layer set,
    /// exactly as `plan` does.
    ///
    /// # Errors
    ///
    /// [`Error::RepoMissing`] when there is no config repo, and
    /// [`Error::Config`] for anything the configuration refuses.
    pub fn load(env: &Env) -> Result<Self, Error> {
        let home = env.home.clone();
        let repo = paths::config_root_in(&home, env.xdg_config_home.as_deref());
        let state = StateDir::resolve_in(&home, env.xdg_state_home.as_deref());
        let layers = layers::load_layer_set(&repo, state.root(), &home)?;
        let merged = merge::merge(&layers, &home)?;
        let resolved = resolve::resolve(&merged, &home)?;
        let roots = RootSet::from_values(&resolved.values)
            .owning(&[state.root().to_path_buf()])
            .with_config_repos(std::slice::from_ref(&repo));
        let trees = trees_of(&layers, &resolved.values)?;
        Ok(Self {
            home,
            repo,
            state,
            layers,
            resolved,
            roots,
            git: crate::sync::Git::new(env),
            trees,
        })
    }

    /// The account's home.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Why bx will not adopt anything at `dest`, when it is bx's own.
    fn bx_own(&self, dest: &Path) -> Option<&'static str> {
        let dest = paths::normalize(dest);
        if dest.starts_with(paths::normalize(&self.repo)) {
            Some("is inside bx's config repo")
        } else if dest.starts_with(paths::normalize(self.state.root())) {
            Some("is inside bx's state directory")
        } else {
            None
        }
    }

    /// What the configuration already says about `target`.
    ///
    /// A layer's declarations and toggles, and a blocked target's key, are
    /// compared by the path they resolve to ([`resolved_path`]), as `rm`
    /// compares them: `~/.config/{{profile}}/s` switched off is still the
    /// declaration of `~/.config/work/s`, so adopting that file is refused
    /// rather than declared a second time.
    fn declared(&self, target: &Portable) -> Declared<'_> {
        let values = &self.resolved.values;
        let names = |raw: &str| resolved_path(raw, values).is_some_and(|path| path == *target);
        for resolution in &self.resolved.targets {
            match resolution {
                Resolution::Ready(ready) if ready.path == *target => {
                    return Declared::Ready(ready);
                }
                Resolution::Blocked(entry) if names(&entry.key) => {
                    return Declared::Blocked(&entry.origin, &entry.hint);
                }
                _ => {}
            }
        }
        for layer in &self.layers {
            if let Some(found) = layer.config.targets.iter().find(|t| names(t.path.as_str())) {
                return Declared::Disabled(&found.origin);
            }
            if let Some(toggle) = layer
                .config
                .toggles
                .iter()
                .find(|toggle| names(&toggle.key))
            {
                return Declared::Disabled(&toggle.origin);
            }
        }
        Declared::No
    }

    /// The repo copy of `target`, by the path the ledger records it under,
    /// when the configuration declares `target` tracked with a `file` body.
    fn tracked_copy(&self, target: &Portable) -> Option<Portable> {
        let Declared::Ready(declared) = self.declared(target) else {
            return None;
        };
        match (&declared.body, declared.direction) {
            (Body::File(rel), Direction::Track) => {
                Portable::from_path(&self.repo.join(rel), &self.home).ok()
            }
            _ => None,
        }
    }

    /// Every path the configuration declares, whether ready, held back, or
    /// switched off, each read as [`Context::declared`] reads it.
    fn declared_paths(&self) -> Vec<Portable> {
        let values = &self.resolved.values;
        let mut paths = Vec::new();
        for resolution in &self.resolved.targets {
            match resolution {
                Resolution::Ready(ready) => paths.push(ready.path.clone()),
                Resolution::Blocked(entry) => paths.extend(resolved_path(&entry.key, values)),
            }
        }
        for layer in &self.layers {
            let targets = layer.config.targets.iter().map(|t| t.path.as_str());
            let toggles = layer
                .config
                .toggles
                .iter()
                .filter(|t| t.section == merge::Section::Target)
                .map(|t| t.key.as_str());
            paths.extend(
                targets
                    .chain(toggles)
                    .filter_map(|raw| resolved_path(raw, values)),
            );
        }
        paths
    }
}

/// What the configuration says about one path.
enum Declared<'a> {
    /// Nothing.
    No,
    /// A resolved target.
    Ready(&'a crate::config::target::Target),
    /// A target held back, with its hint.
    Blocked(&'a Origin, &'a str),
    /// A declaration the merge switched off.
    Disabled(&'a Origin),
}

/// Resolve what a user typed into the home-relative target it names.
///
/// `~` and `~/…` are the home; anything else is taken relative to `cwd`, as a
/// shell would. The result is lexically normalised and must lie strictly
/// inside the home: the home itself is not one file, and a path outside it
/// would be an account-specific literal in the repo.
///
/// # Errors
///
/// [`Error::Path`] for a path bx cannot store, and [`Error::OutsideHome`] for
/// one outside the home or the home itself.
pub fn locate(arg: &str, cwd: &Path, home: &Path) -> Result<Portable, Error> {
    let absolute = if arg == "~" || arg.starts_with("~/") {
        paths::render(arg, home)
    } else {
        cwd.join(arg)
    };
    let target = Portable::from_path(&absolute, home)?;
    if !target.as_str().starts_with("~/") {
        return Err(Error::OutsideHome(target.as_str().to_string()));
    }
    Ok(target)
}

/// What `add` does, or would do, about one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adoption {
    /// The file is copied into the repo, declared, and owned.
    Adopt {
        /// The target.
        target: Portable,
        /// Its body, repo-relative.
        body: PathBuf,
        /// The file's bytes, verbatim.
        bytes: Vec<u8>,
        /// The file's mode.
        mode: Mode,
        /// Whether the repo already holds these exact bytes at `body`, so
        /// nothing is copied.
        reuse: bool,
        /// Each line that would relocate a tool outside a declared root.
        warnings: Vec<String>,
    },
    /// Already declared with these exact bytes and mode; bx records that it
    /// owns the file, which it did not.
    Own {
        /// The target.
        target: Portable,
        /// The file's bytes.
        bytes: Vec<u8>,
        /// The file's mode.
        mode: Mode,
    },
    /// Already declared, identical, and owned. Nothing to do.
    Unchanged {
        /// The target.
        target: Portable,
    },
    /// Passed over inside a directory, with the reason. Not an error: a
    /// directory holds things bx does not adopt.
    Skipped {
        /// The target.
        target: Portable,
        /// Why.
        note: String,
    },
    /// Refused, with the reason. Nothing is written for it.
    Refused {
        /// The target.
        target: Portable,
        /// Why.
        note: String,
    },
}

impl Adoption {
    /// The target this is about.
    #[must_use]
    pub const fn target(&self) -> &Portable {
        match self {
            Self::Adopt { target, .. }
            | Self::Own { target, .. }
            | Self::Unchanged { target }
            | Self::Skipped { target, .. }
            | Self::Refused { target, .. } => target,
        }
    }

    /// Whether a human has to look: `add` did not do what was asked.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }
}

/// Decide what `add` does about `target`, reading and writing nothing but
/// what it inspects.
///
/// # Errors
///
/// [`Error::Missing`] when nothing is at `target`, and [`Error::Read`] or
/// [`Error::Fs`] when something there cannot be read.
pub fn plan_add(
    ctx: &Context,
    ledger: &LedgerView,
    target: &Portable,
) -> Result<Vec<Adoption>, Error> {
    let dest = target.render(&ctx.home);
    let meta = match std::fs::symlink_metadata(&dest) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Missing(target.as_str().to_string()));
        }
        Err(source) => return Err(Error::Read { path: dest, source }),
    };
    let mut rows = Vec::new();
    visit(ctx, ledger, target, &dest, &meta, true, &mut rows)?;
    Ok(rows)
}

/// Decide one path, and every path beneath it when it is a directory.
fn visit(
    ctx: &Context,
    ledger: &LedgerView,
    target: &Portable,
    dest: &Path,
    meta: &std::fs::Metadata,
    named: bool,
    rows: &mut Vec<Adoption>,
) -> Result<(), Error> {
    // Named, bx refuses and says so; met inside a directory, it passes over.
    let pass = |note: String| {
        if named {
            Adoption::Refused {
                target: target.clone(),
                note,
            }
        } else {
            Adoption::Skipped {
                target: target.clone(),
                note,
            }
        }
    };
    if let Some(why) = ctx.bx_own(dest) {
        rows.push(pass(why.to_string()));
        return Ok(());
    }
    match Kind::from(meta.file_type()) {
        Kind::Symlink => rows.push(pass(
            "is a symbolic link; bx adopts files, not what a link points at".to_string(),
        )),
        Kind::Dir if dest.file_name().is_some_and(|name| name == ".git") => {
            rows.push(pass(
                "is a git repository's own directory, which the config repo cannot hold"
                    .to_string(),
            ));
        }
        Kind::Dir => {
            let read = |source| Error::Read {
                path: dest.to_path_buf(),
                source,
            };
            let mut entries = std::fs::read_dir(dest)
                .map_err(read)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(read)?;
            // Byte order of the names, never directory order (Invariant 3).
            entries.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
            for name in entries {
                let child = dest.join(&name);
                let child_target = match Portable::from_path(&child, &ctx.home) {
                    Ok(child_target) => child_target,
                    Err(e) => {
                        rows.push(Adoption::Skipped {
                            target: target.clone(),
                            note: e.to_string(),
                        });
                        continue;
                    }
                };
                let child_meta =
                    std::fs::symlink_metadata(&child).map_err(|source| Error::Read {
                        path: child.clone(),
                        source,
                    })?;
                visit(ctx, ledger, &child_target, &child, &child_meta, false, rows)?;
            }
        }
        Kind::File => rows.push(match secret(target) {
            Some(why) => pass(why),
            None => decide_file(ctx, ledger, target, dest, &pass)?,
        }),
        Kind::Absent | Kind::Other => {
            rows.push(pass("is not a regular file".to_string()));
        }
    }
    Ok(())
}

/// The existing tool config `bx init` offers to adopt, in byte order of the
/// paths.
///
/// Two places are looked in, one level deep each: the home's dotfiles that are
/// regular files, and every regular file or directory directly inside
/// `config_home` (`$XDG_CONFIG_HOME`, or `~/.config`). A dot-directory in the
/// home is not offered: `~/.cache`, `~/.local` and `~/.cargo` hold data and
/// caches rather than config, and a file inside one is still `bx add`'s to
/// take by name.
///
/// Not offered: a symbolic link or anything else that is not a regular file or
/// directory; a path that conventionally holds a credential, or a directory
/// whose whole content does; a shell history or another file a program writes
/// about its own use, which is state rather than config and often holds a
/// secret typed at a prompt; bx's own config repo and state directory; and
/// anything already declared, at the path or beneath it — so a second
/// `bx init` does not offer what the first one adopted. A `config_home`
/// outside the home is not looked in: bx manages files beneath the home.
///
/// Reads directory listings and `lstat`s only; no file's content is read.
///
/// # Errors
///
/// [`Error::Read`] when the home or `config_home` cannot be listed, or an
/// entry in either cannot be examined. Either being absent is nothing to
/// offer.
pub fn discover(ctx: &Context, config_home: &Path) -> Result<Vec<Portable>, Error> {
    let declared = ctx.declared_paths();
    let mut found = Vec::new();
    let mut offer = |dest: &Path, meta: &std::fs::Metadata| {
        let Ok(target) = Portable::from_path(dest, &ctx.home) else {
            return;
        };
        let offered = target.as_str().starts_with("~/")
            && ctx.bx_own(dest).is_none()
            && secret(&target).is_none()
            && !credential_dir(&target)
            && !declared
                .iter()
                .any(|path| beneath(path, &target) || beneath(&target, path));
        if offered && matches!(Kind::from(meta.file_type()), Kind::File | Kind::Dir) {
            found.push(target);
        }
    };
    for (name, dest, meta) in listing(&ctx.home)? {
        let name = name.to_string_lossy();
        if name.starts_with('.') && meta.is_file() && !machine_written(&name) {
            offer(&dest, &meta);
        }
    }
    if paths::normalize(config_home).starts_with(paths::normalize(&ctx.home)) {
        for (_, dest, meta) in listing(config_home)? {
            offer(&dest, &meta);
        }
    }
    found.sort_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
    found.dedup();
    Ok(found)
}

/// Every entry of `dir`, with its `lstat`; nothing when `dir` is absent.
fn listing(dir: &Path) -> Result<Vec<(std::ffi::OsString, PathBuf, std::fs::Metadata)>, Error> {
    let read = |source| Error::Read {
        path: dir.to_path_buf(),
        source,
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(read(source)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let name = entry.map_err(read)?.file_name();
        let dest = dir.join(&name);
        let meta = std::fs::symlink_metadata(&dest).map_err(|source| Error::Read {
            path: dest.clone(),
            source,
        })?;
        out.push((name, dest, meta));
    }
    Ok(out)
}

/// Whether a home dotfile named `name` is one a program writes about its own
/// use — a history, a cache of hosts it has seen, an X authority cookie —
/// rather than config a person wrote.
fn machine_written(name: &str) -> bool {
    name.contains("history")
        || name.starts_with(".zcompdump")
        || [
            ".lesshst",
            ".viminfo",
            ".wget-hsts",
            ".Xauthority",
            ".ICEauthority",
            ".xsession-errors",
            ".sudo_as_admin_successful",
        ]
        .contains(&name)
}

/// Whether `target` is a directory [`secret`] refuses every file beneath.
fn credential_dir(target: &Portable) -> bool {
    target
        .as_str()
        .strip_prefix("~/")
        .is_some_and(|rel| secret_rel(&format!("{rel}/x")).is_some())
}

/// Why a path must not be copied into the repo in cleartext, when it is one of
/// the files that conventionally hold a credential.
///
/// Conservative, and deliberately a list rather than a scan of the content:
/// which files hold secrets in general is the commit guard's to decide.
fn secret(target: &Portable) -> Option<String> {
    secret_rel(target.as_str().strip_prefix("~/")?)
}

/// [`secret`], for a path relative to the home.
fn secret_rel(rel: &str) -> Option<String> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let listed = [
        ".netrc",
        ".git-credentials",
        ".pgpass",
        ".pypirc",
        ".vault-token",
        ".aws/credentials",
        ".cargo/credentials",
        ".cargo/credentials.toml",
        ".config/gh/hosts.yml",
        ".docker/config.json",
        ".kube/config",
        ".config/sops/age/keys.txt",
    ]
    .contains(&rel);
    let under = [
        ".gnupg/",
        ".password-store/",
        ".local/share/keyrings/",
        ".config/age/",
    ]
    .iter()
    .any(|dir| rel.starts_with(dir));
    let ssh_key = rel.starts_with(".ssh/")
        && name.starts_with("id_")
        && !std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext == "pub");
    (listed || under || ssh_key).then(|| {
        "may hold a credential, and a secret never enters the repo in cleartext; \
         bx will not copy it"
            .to_string()
    })
}

/// Decide one regular file.
fn decide_file(
    ctx: &Context,
    ledger: &LedgerView,
    target: &Portable,
    dest: &Path,
    pass: &dyn Fn(String) -> Adoption,
) -> Result<Adoption, Error> {
    let observed = fs::observe(dest)?;
    let (Some(bytes), Some(mode)) = (observed.bytes, observed.mode) else {
        return Ok(pass("changed while bx was reading it".to_string()));
    };
    let refused = |note: String| Adoption::Refused {
        target: target.clone(),
        note,
    };

    match ctx.declared(target) {
        Declared::Ready(declared) => {
            let origin = &declared.origin;
            if declared.direction == Direction::Track {
                return Ok(refused(format!(
                    "is already declared at {origin} as tracked; bx sync carries it into the repo"
                )));
            }
            if declared.attach != Attach::Own || declared.format != Format::Opaque {
                return Ok(refused(format!(
                    "is already declared at {origin} as part of a file; bx add adopts whole files"
                )));
            }
            let wanted = match &declared.body {
                Body::Inline(content) => content.clone().into_bytes(),
                Body::File(rel) => {
                    let path = ctx.repo.join(rel);
                    std::fs::read(&path).map_err(|source| Error::Read { path, source })?
                }
                // A secret's declared bytes are ciphertext; adopting would
                // mean decrypting here, so it is refused like the others.
                Body::Generated(_) | Body::Dir | Body::Secret(_) | Body::Symlink(_) => {
                    return Ok(refused(format!(
                        "is already declared at {origin} with a body bx add does not adopt into"
                    )));
                }
            };
            if wanted != bytes || Mode::resolve(declared.mode, Kind::File) != mode {
                return Ok(refused(format!(
                    "is already declared at {origin}, and differs from what it declares; \
                     `bx plan` shows how"
                )));
            }
            let digest = ContentHash::of(&bytes);
            let owned = ledger.get(target).is_some_and(|entry| {
                entry.mechanism == Mechanism::Own && entry.written == digest && entry.mode == mode
            });
            Ok(if owned {
                Adoption::Unchanged {
                    target: target.clone(),
                }
            } else {
                Adoption::Own {
                    target: target.clone(),
                    bytes,
                    mode,
                }
            })
        }
        Declared::Blocked(origin, hint) => Ok(refused(format!(
            "is already declared at {origin}, and held back: {hint}"
        ))),
        Declared::Disabled(origin) => Ok(refused(format!(
            "is already declared at {origin} and switched off; enable it there rather than \
             adding it again"
        ))),
        Declared::No => {
            let rel = target
                .as_str()
                .strip_prefix("~/")
                .unwrap_or(target.as_str());
            if rel.contains("{{") || rel.contains("}}") {
                return Ok(refused(
                    "has `{{` or `}}` in its path, which a body path would read as a value \
                     placeholder"
                        .to_string(),
                ));
            }
            let body = Path::new(FILES_DIR).join(rel);
            // A copy inside a tree's root is a file that tree declares from
            // the next load on, so the `[[target]]` appended beside it would
            // declare one path twice in one layer — or deliver the copy to
            // a second place — and no command would load the repo after.
            if let Some(tree) = ctx.trees.iter().find(|tree| body.starts_with(&tree.root)) {
                return Ok(refused(format!(
                    "cannot be copied to {}: that is inside `tree = \"{}\"` at {}, which would \
                     declare it as well; to have the tree deliver it, copy it into {} yourself",
                    body.display(),
                    tree.root.display(),
                    tree.origin,
                    tree.root.display(),
                )));
            }
            let in_repo = ctx.repo.join(&body);
            let reuse = match fs::observe(&in_repo)? {
                present if present.kind == Kind::Absent => false,
                present if present.bytes.as_deref() == Some(bytes.as_slice()) => true,
                _ => {
                    return Ok(refused(format!(
                        "cannot be copied: the repo already holds {} with other content; \
                         move it aside or declare it yourself",
                        body.display()
                    )));
                }
            };
            let warnings = relocations(&bytes, &ctx.roots);
            Ok(Adoption::Adopt {
                target: target.clone(),
                body,
                bytes,
                mode,
                reuse,
                warnings,
            })
        }
    }
}

/// Each line of `bytes` that assigns a tool's location outside every declared
/// root, as `line N: NAME reason`.
///
/// The environment guard reads only assignments, so everything else in the
/// file — and every variable bx does not know how to judge — passes without
/// comment. Only a verdict about *where* a location points is reported: that
/// is what Invariant 2 is about, and the rest of the guard's grammar is for
/// shell bx generates, not shell the user wrote.
fn relocations(bytes: &[u8], roots: &RootSet) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    env_guard::scan_with(text, roots)
        .into_iter()
        .filter(|violation| {
            matches!(
                violation.reason,
                Reason::NoRootsDeclared
                    | Reason::InadmissibleRoot
                    | Reason::OutsideDeclaredRoots
                    | Reason::BxOwnedDirectory
                    | Reason::InsideConfigRepo
                    | Reason::ContainsBxDirectory
            )
        })
        .map(|violation| {
            format!(
                "line {}: {} {}",
                violation.line, violation.name, violation.reason
            )
        })
        .collect()
}

/// Take the state directory for a writing command: resolve any interrupted
/// session, then hold the lock, refusing if a session still stands.
fn lock(state: &StateDir) -> Result<ExclusiveLock, Error> {
    let lock = recover::lock_for_writing(state)?;
    let path = state.journal();
    if journal::load_exclusive(&path, &lock)?.is_interrupted() {
        return Err(journal::Error::InProgress { path }.into());
    }
    Ok(lock)
}

/// `bx add`: adopt `target`, and every regular file beneath it.
///
/// Decides with [`plan_add`] under the state directory's lock, then does
/// exactly what it decided: copy each new body into the repo, declare each
/// new target in `bx.toml`, and record ownership in the ledger — in that
/// order, so a run that stops partway is finished by running it again.
///
/// # Errors
///
/// As [`plan_add`], plus whatever the lock, the writes, and the ledger return.
pub fn add(ctx: &Context, target: &Portable) -> Result<Vec<Adoption>, Error> {
    let lock = lock(&ctx.state)?;
    let mut ledger = Ledger::open(&ctx.state, &lock, &ctx.home)?.value;
    let rows = plan_add(ctx, &ledger, target)?;

    for row in &rows {
        if let Adoption::Adopt {
            body,
            bytes,
            mode,
            reuse: false,
            ..
        } = row
        {
            // `write_atomically` makes no directories. These are in the user's
            // config repo, not the home: nothing reverses them (rm leaves the
            // body, decision 5), so they are made as `git` makes a checkout's
            // directories, at the umask's mode.
            let path = ctx.repo.join(body);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|source| Error::RepoDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            fs::write_atomically(&path, bytes, *mode)?;
        }
    }
    declare(ctx, &rows)?;

    let mut recorded = false;
    for row in &rows {
        if let Adoption::Adopt {
            target,
            bytes,
            mode,
            ..
        }
        | Adoption::Own {
            target,
            bytes,
            mode,
        } = row
        {
            ledger.record(
                // The prior is the file as the user left it, for `Own` as for
                // `Adopt`: bx wrote nothing here, so `rm` must put these bytes
                // back rather than read `Absent` and unlink a file the user
                // wrote.
                NewEntry::new(
                    target.clone(),
                    ContentHash::of(bytes),
                    *mode,
                    Mechanism::Own,
                    PriorBytes::Bytes {
                        bytes: bytes.clone(),
                        mode: *mode,
                    },
                ),
            )?;
            recorded = true;
        }
    }
    if recorded {
        ledger.save()?;
    }
    Ok(rows)
}

/// Read a layer file's text, with the mode it has now. An absent file is
/// empty.
fn open_layer(path: &Path) -> Result<(String, Mode), Error> {
    let observed = fs::observe(path)?;
    let text = match (observed.kind, observed.bytes) {
        (Kind::Absent, _) => String::new(),
        (Kind::File, Some(bytes)) => String::from_utf8(bytes).map_err(|_| Error::Layer {
            path: path.to_path_buf(),
            why: "is not UTF-8".to_string(),
        })?,
        (kind, _) => {
            return Err(Error::Layer {
                path: path.to_path_buf(),
                why: format!("is {kind}, not a file bx can edit"),
            });
        }
    };
    Ok((text, observed.mode.unwrap_or(Mode::DEFAULT_FILE)))
}

/// Parse a layer's text, keeping the spans an edit is made at.
fn parse_layer(path: &Path, text: &str) -> Result<Document<String>, Error> {
    Document::parse(text.to_string()).map_err(|e| Error::Layer {
        path: path.to_path_buf(),
        why: e.to_string(),
    })
}

/// Write an edited layer, refusing an edit the configuration would not load.
///
/// The check is the loader's own parse of the one file, so an edit that would
/// leave the repo unloadable is refused with the file as it was.
fn write_layer(path: &Path, text: &str, mode: Mode, home: &Path) -> Result<(), Error> {
    config::parse_str(text, path, home).map_err(|e| Error::Layer {
        path: path.to_path_buf(),
        why: format!("bx's edit would not load, so it was not made: {e}"),
    })?;
    fs::write_atomically(path, text.as_bytes(), mode)?;
    Ok(())
}

/// Append a `[[target]]` for each adopted file to `bx.toml`.
///
/// Appended as text after the last byte already there, which is never
/// touched: a re-serialised document would move a comment that stands alone
/// in the file to after the new tables. Each new table follows one blank line,
/// which is exactly what [`undeclare`] takes away with it.
fn declare(ctx: &Context, rows: &[Adoption]) -> Result<(), Error> {
    let mut tables = ArrayOfTables::new();
    for row in rows {
        let Adoption::Adopt {
            target, body, mode, ..
        } = row
        else {
            continue;
        };
        let mut table = Table::new();
        table.insert("path", value(target.as_str()));
        table.insert("file", value(body.to_string_lossy().as_ref()));
        if *mode != Mode::DEFAULT_FILE {
            table.insert("mode", value(mode.to_string()));
        }
        table.decor_mut().set_prefix("\n");
        tables.push(table);
    }
    if tables.is_empty() {
        return Ok(());
    }
    let mut added = DocumentMut::new();
    added.insert("target", Item::ArrayOfTables(tables));
    let added = added.to_string();

    let path = ctx.repo.join(GLOBAL_LAYER);
    let (mut text, mode) = open_layer(&path)?;
    if text.is_empty() {
        text.push_str(added.strip_prefix('\n').unwrap_or(&added));
    } else {
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&added);
    }
    write_layer(&path, &text, mode, &ctx.home)
}

/// What `rm` did to one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// What restoring it did.
    pub restored: Restored,
    /// The layer files it is no longer declared in.
    pub undeclared: Vec<PathBuf>,
    /// The repo-relative bodies it named, left in the repo.
    pub bodies: Vec<PathBuf>,
}

/// One `[[target]]` table a layer holds for a path `rm` was asked about.
struct Declaration {
    layer: PathBuf,
    target: Portable,
    body: Option<PathBuf>,
}

/// Whether `path` is `under`, or beneath it.
fn beneath(path: &Portable, under: &Portable) -> bool {
    path == under
        || path
            .as_str()
            .strip_prefix(under.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Every `[[target]]` table, in every layer, whose path is `under` or beneath
/// it, toggles included.
fn declarations(ctx: &Context, under: &Portable) -> Result<Vec<Declaration>, Error> {
    let mut found = Vec::new();
    for layer in &ctx.layers {
        let (text, _) = open_layer(&layer.file)?;
        let doc = parse_layer(&layer.file, &text)?;
        let Some(tables) = doc.get("target").and_then(Item::as_array_of_tables) else {
            continue;
        };
        for table in tables {
            let Some(target) = declared_path(table, &ctx.resolved.values) else {
                continue;
            };
            if beneath(&target, under) {
                found.push(Declaration {
                    layer: layer.file.clone(),
                    target,
                    // Both body keys that name a file in the repo: a secret's
                    // ciphertext stays there as much as a `file` body does.
                    body: ["file", "secret"]
                        .into_iter()
                        .find_map(|key| table.get(key).and_then(Item::as_str))
                        .map(PathBuf::from),
                });
            }
        }
    }
    Ok(found)
}

/// The file a `[[target]]` table declares, when it is one bx can read.
///
/// The path as the resolved configuration names it — every `{{name}}`
/// substituted — because that is the path the ledger records and `rm` is
/// given: `~/.config/{{profile}}/s` is `~/.config/work/s` once `profile` is
/// answered `work`. A path whose values are not all answered names no file
/// yet, so it is read as written.
fn declared_path(table: &Table, values: &ResolvedValues) -> Option<Portable> {
    resolved_path(table.get("path").and_then(Item::as_str)?, values)
}

/// The file a declared path names once its `{{name}}`s are substituted, or
/// as written when they are not all answered.
fn resolved_path(raw: &str, values: &ResolvedValues) -> Option<Portable> {
    let rendered = values.substitute(raw).unwrap_or_else(|_| raw.to_string());
    Portable::parse_in(&rendered, values.home()).ok()
}

/// Remove every `[[target]]` table naming one of `released` from `layer`.
///
/// Removed as text, a table at a time: from the start of its header line to
/// the end of the line its last value ends on. Everything outside that range
/// stays byte for byte — the comments above the header included, since they
/// may introduce more than this one target — except one blank line directly
/// above the header, which is the separator [`declare`] wrote, so `add` then
/// `rm` leaves `bx.toml` exactly as it was.
fn undeclare(
    layer: &Path,
    released: &BTreeSet<&Portable>,
    values: &ResolvedValues,
) -> Result<(), Error> {
    let home = values.home();
    let (text, mode) = open_layer(layer)?;
    let doc = parse_layer(layer, &text)?;
    let Some(tables) = doc.get("target").and_then(Item::as_array_of_tables) else {
        return Ok(());
    };
    let mut ranges = Vec::new();
    for table in tables {
        if !declared_path(table, values).is_some_and(|t| released.contains(&t)) {
            continue;
        }
        let Some(header) = table.span() else {
            continue;
        };
        let last = table
            .iter()
            .filter_map(|(_, item)| item.span())
            .map(|span| span.end)
            .max()
            .unwrap_or(header.end);
        let mut start = text[..header.start].rfind('\n').map_or(0, |at| at + 1);
        let end = text[last..]
            .find('\n')
            .map_or(text.len(), |at| last + at + 1);
        if text[..start].ends_with("\n\n") || text[..start] == *"\n" {
            start -= 1;
        }
        ranges.push(start..end);
    }
    if ranges.is_empty() {
        return Ok(());
    }
    let mut edited = text.clone();
    for range in ranges.into_iter().rev() {
        edited.replace_range(range, "");
    }
    write_layer(layer, &edited, mode, home)
}

/// `bx rm`: stop managing `target` and everything beneath it, restoring what
/// bx displaced.
///
/// The targets are every declaration of a path at or beneath `target`, in any
/// layer, and every ledger entry there — so a target whose declaration was
/// deleted by hand is still handed back. [`restore::restore`] decides and
/// restores each; each one it released is then removed from every layer
/// declaring it. A conflict is left declared and untouched, and a tree is
/// handed back whole or not at all ([`hold_trees`]). Nothing to do is an
/// empty result, which is what makes a second `rm` a no-op.
///
/// # Errors
///
/// Whatever reading the ledger, restoring, or editing a layer returns.
pub fn rm(ctx: &Context, target: &Portable) -> Result<Vec<Removal>, Error> {
    let ledger = LedgerView::read(&ctx.state, &ctx.home)?.value;
    let found = declarations(ctx, target)?;
    let mut targets: BTreeSet<Portable> = found
        .iter()
        .map(|declaration| declaration.target.clone())
        .chain(
            ledger
                .iter()
                .map(|(path, _)| path.clone())
                .filter(|path| beneath(path, target)),
        )
        // A tracked file a tree declares has no table naming it, and a ledger
        // entry of its own only where `apply` created it: its repo copy is
        // what `rm` hands back, with that entry where there is one.
        .chain(
            ctx.resolved
                .targets
                .iter()
                .filter_map(|resolution| match resolution {
                    Resolution::Ready(ready) if ready.direction == Direction::Track => {
                        Some(ready.path.clone())
                    }
                    _ => None,
                })
                .filter(|path| beneath(path, target)),
        )
        .collect();
    let held = hold_trees(ctx, &ledger, target, &mut targets)?;
    if targets.is_empty() && held.is_empty() {
        return Ok(Vec::new());
    }
    let targets: Vec<Portable> = targets.into_iter().collect();
    let restored = restore_tracking(ctx, &ledger, &targets)?;

    let conflicts: BTreeSet<&Portable> = restored
        .iter()
        .filter(|done| done.is_conflict())
        .map(Restored::target)
        .collect();
    // A tree's declaration is every one of its files' declaration, so it goes
    // only when none of them is a conflict: a conflict is left declared.
    let kept: BTreeSet<&Portable> = ctx
        .trees
        .iter()
        .filter(|tree| tree.files.iter().any(|file| conflicts.contains(file)))
        .map(|tree| &tree.path)
        .collect();
    let released: BTreeSet<Portable> = restored
        .iter()
        .filter(|done| !done.is_conflict())
        .map(Restored::target)
        .filter(|path| !kept.contains(path))
        .cloned()
        .collect();
    let layers: BTreeSet<&Path> = found
        .iter()
        .filter(|declaration| released.contains(&declaration.target))
        .map(|declaration| declaration.layer.as_path())
        .collect();
    if !layers.is_empty() {
        let _lock = lock(&ctx.state)?;
        let named: BTreeSet<&Portable> = released.iter().collect();
        for layer in layers {
            undeclare(layer, &named, &ctx.resolved.values)?;
        }
    }

    let mut removals: Vec<Removal> = restored
        .into_iter()
        .chain(held)
        .map(|done| {
            let mine: Vec<&Declaration> = if released.contains(done.target()) {
                found
                    .iter()
                    .filter(|declaration| declaration.target == *done.target())
                    .collect()
            } else {
                Vec::new()
            };
            Removal {
                undeclared: mine.iter().map(|d| d.layer.clone()).collect(),
                bodies: mine.iter().filter_map(|d| d.body.clone()).collect(),
                restored: done,
            }
        })
        .collect();
    removals.sort_by(|a, b| a.restored.target().cmp(b.restored.target()));
    Ok(removals)
}

/// Restore `targets` as [`restore::restore_with`] does, one result per
/// target in order, with each tracked target handed back through its repo
/// copy, and a row after them for each repo copy restored.
///
/// # Decision: `rm` restores a tracked target's two copies by what bx claimed of each
///
/// What bx wrote of a tracked target is the repo copy, each time `sync`
/// carried this machine's copy into it, and the machine copy `apply` created
/// where this machine had none. The ledger holds what each held before bx
/// first wrote it, and `rm` puts that back — removing a machine copy bx
/// created, and the directories it made for it — exactly as it restores any
/// file bx wrote. It refuses to when a copy changed since bx last wrote it: as
/// it does after another machine's sync brought a newer repo copy, or after
/// the tool rewrote the machine copy bx created. Such a conflict keeps the
/// tracked target declared, like any conflict.
///
/// A machine copy bx never claimed — the tool had it before bx wrote to it —
/// has nothing for `rm` to put back, and is left as it is.
///
/// # Decision: a tracked target is handed back whole or not at all
///
/// Where either copy would conflict, `rm` restores neither, as it holds a tree
/// ([`hold_trees`]): restoring the one that does not would leave the target
/// declared with one side handed back, and the next `sync` or `apply` would
/// write it straight back.
fn restore_tracking(
    ctx: &Context,
    ledger: &LedgerView,
    targets: &[Portable],
) -> Result<Vec<Restored>, Error> {
    let copies: Vec<Option<Portable>> = targets.iter().map(|t| ctx.tracked_copy(t)).collect();
    let mut held: Vec<Option<String>> = Vec::with_capacity(targets.len());
    for (target, copy) in targets.iter().zip(&copies) {
        held.push(match copy {
            Some(copy) => conflict_before_restore(ctx, ledger, target, Some(copy))?,
            None => None,
        });
    }
    let mut restoring: Vec<Portable> = targets
        .iter()
        .zip(&copies)
        .zip(&held)
        .filter(|((target, copy), held)| {
            held.is_none() && (copy.is_none() || ledger.get(target).is_some())
        })
        .map(|((target, _), _)| target.clone())
        .collect();
    for (copy, held) in copies.iter().zip(&held) {
        if let (Some(copy), None) = (copy, held)
            && ledger.get(copy).is_some()
            && !restoring.contains(copy)
        {
            restoring.push(copy.clone());
        }
    }
    if restoring.is_empty() && copies.iter().all(Option::is_none) {
        return Ok(Vec::new());
    }
    let done = if restoring.is_empty() {
        Vec::new()
    } else {
        restore::restore_with(&ctx.state, &ctx.home, &restoring, &ctx.git)?
    };
    let result = |path: &Portable| {
        restoring
            .iter()
            .position(|restored| restored == path)
            .and_then(|at| done.get(at))
    };
    let mut out = Vec::with_capacity(targets.len());
    for ((target, copy), held) in targets.iter().zip(&copies).zip(held) {
        let own = result(target).cloned();
        let Some(copy) = copy else {
            out.extend(own);
            continue;
        };
        let dest = target.render(&ctx.home);
        if let Some(note) = held {
            out.push(Restored::Conflict {
                target: target.clone(),
                dest,
                note,
            });
            continue;
        }
        out.push(match (own, result(copy)) {
            (_, Some(Restored::Conflict { note, .. })) => Restored::Conflict {
                target: target.clone(),
                dest,
                note: format!("its repo copy {copy} {note}"),
            },
            (Some(own), _) => own,
            (None, _) => Restored::Unmanaged {
                target: target.clone(),
            },
        });
    }
    // The repo copies restored alongside, each as a row of its own; one that
    // conflicts is already said by its tracked target's row.
    for (copy, done) in restoring.iter().zip(&done) {
        if !targets.contains(copy) && !done.is_conflict() {
            out.push(done.clone());
        }
    }
    Ok(out)
}

/// Why restoring `file`, and its repo copy `copy` where it is tracked, would
/// be a conflict, as [`restore::plan_restore_with`] reads each ledger entry
/// now: the first one's note, a copy's naming the copy. `None` when neither
/// would, or when the ledger holds no entry for either.
fn conflict_before_restore(
    ctx: &Context,
    ledger: &LedgerView,
    file: &Portable,
    copy: Option<&Portable>,
) -> Result<Option<String>, Error> {
    let entries = [Some(file), copy]
        .into_iter()
        .flatten()
        .filter_map(|path| Some((path, ledger.get(path)?)));
    for (path, entry) in entries {
        if let restore::Restoration::Conflict { note, .. } =
            restore::plan_restore_with(entry, &ctx.home, &ctx.git)?
        {
            return Ok(Some(if path == file {
                note
            } else {
                format!("its repo copy {path} {note}")
            }));
        }
    }
    Ok(None)
}

/// Take out of `targets` every file of a tree that `rm` must leave managed,
/// returning each as a conflict that says why.
///
/// A tree declares its files together, and its declaration is one table, so
/// `rm` hands a tree back whole or not at all:
///
/// - Asked about a path strictly inside a tree, `rm` releases none of the
///   files the tree declares there. Undeclaring them would mean editing the
///   tree, and restoring them while the tree still declares them would have
///   the next `apply` write them straight back; the note names `exclude` and
///   the tree's own path instead.
/// - Asked about the tree's path or above it, `rm` releases the tree only when
///   restoring none of its files would be a conflict, as
///   [`restore::plan_restore_with`] reads them now. When one would, every file of
///   the tree stays as it is, and so does its declaration.
///
/// A file the tree no longer declares — removed from the repo since bx wrote
/// it — is not held: nothing declares it, and `rm` hands it back as it would
/// any file with no declaration.
fn hold_trees(
    ctx: &Context,
    ledger: &LedgerView,
    target: &Portable,
    targets: &mut BTreeSet<Portable>,
) -> Result<Vec<Restored>, Error> {
    let mut held = Vec::new();
    for tree in &ctx.trees {
        let mine: Vec<Portable> = targets
            .iter()
            .filter(|path| tree.files.contains(*path))
            .cloned()
            .collect();
        if mine.is_empty() {
            continue;
        }
        let whole = beneath(&tree.path, target);
        let mut own: Vec<(Portable, String)> = Vec::new();
        if whole {
            for file in &mine {
                // A tracked file is handed back through its repo copy too, so
                // a copy that would conflict holds the tree as the file would.
                let copy = ctx.tracked_copy(file);
                if let Some(note) = conflict_before_restore(ctx, ledger, file, copy.as_ref())? {
                    own.push((file.clone(), note));
                }
            }
            if own.is_empty() {
                continue;
            }
            targets.remove(&tree.path);
        }
        let note = if whole {
            format!(
                "is left as it is: the tree at {} is released whole, and {} conflicts",
                tree.origin, own[0].0
            )
        } else {
            format!(
                "is declared by the tree at {}; add an `exclude` pattern there to stop managing \
                 it, or `bx rm {}` to release the whole tree",
                tree.origin, tree.path
            )
        };
        for file in mine {
            targets.remove(&file);
            let note = own
                .iter()
                .find(|(path, _)| *path == file)
                .map_or_else(|| note.clone(), |(_, own)| own.clone());
            held.push(Restored::Conflict {
                dest: file.render(&ctx.home),
                target: file,
                note,
            });
        }
    }
    Ok(held)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;
    use crate::plan::tests::{env, inline, seed};
    use crate::report::Exit;
    use crate::state::Prior;
    use crate::testing::{GuardedHome, guarded_home};

    /// What the user's own `bx.toml` holds before any test edits it.
    const MINE: &str = "# my own notes\n";

    /// A home with a config repo whose `bx.toml` is `layer`.
    fn repo(layer: &str) -> GuardedHome {
        let home = guarded_home();
        seed(home.path(), layer);
        home
    }

    /// Write `bytes` at `~/rel` with `mode`, making its parents.
    fn plant(home: &GuardedHome, rel: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = home.child(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("parents");
        std::fs::write(&path, bytes).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    fn target(home: &GuardedHome, rel: &str) -> Portable {
        Portable::parse_in(&format!("~/{rel}"), home.path()).expect("a target")
    }

    fn context(home: &GuardedHome) -> Context {
        Context::load(&env(home.path())).expect("the context loads")
    }

    fn add_rel(home: &GuardedHome, rel: &str) -> Vec<Adoption> {
        add(&context(home), &target(home, rel)).expect("add")
    }

    fn rm_rel(home: &GuardedHome, rel: &str) -> Vec<Removal> {
        rm(&context(home), &target(home, rel)).expect("rm")
    }

    fn layer(home: &GuardedHome) -> String {
        std::fs::read_to_string(home.child(".config/bx/bx.toml")).expect("bx.toml")
    }

    fn body(home: &GuardedHome, rel: &str) -> PathBuf {
        home.child(".config/bx/files").join(rel)
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
    }

    fn ledger(home: &GuardedHome) -> LedgerView {
        LedgerView::read(&StateDir::resolve(home.path()), home.path())
            .expect("the ledger")
            .value
    }

    fn plan_exit(home: &GuardedHome) -> (Exit, String) {
        let mut out = Vec::new();
        let exit = crate::command::plan(&env(home.path()), &mut out).expect("plan");
        (exit, String::from_utf8(out).expect("UTF-8"))
    }

    fn apply_yes(home: &GuardedHome) {
        let mut out = Vec::new();
        crate::command::apply(&env(home.path()), true, &mut out).expect("apply");
    }

    fn adopted(rows: &[Adoption]) -> Vec<&str> {
        rows.iter()
            .filter(|row| matches!(row, Adoption::Adopt { .. }))
            .map(|row| row.target().as_str())
            .collect()
    }

    #[test]
    fn add_copies_the_bytes_and_the_mode_verbatim_and_leaves_the_file_alone() {
        let home = repo(MINE);
        // CRLF, no trailing newline, and bytes that are not UTF-8.
        let bytes = b"a = 1\r\nb\x00\xff";
        let file = plant(&home, ".tool.conf", bytes, 0o600);
        let before = std::fs::metadata(&file).expect("stat");

        let rows = add_rel(&home, ".tool.conf");
        assert_eq!(adopted(&rows), ["~/.tool.conf"], "{rows:?}");

        let copy = body(&home, ".tool.conf");
        assert_eq!(std::fs::read(&copy).expect("the copy"), bytes);
        assert_eq!(mode_of(&copy), 0o600, "a private file stays private");
        assert_eq!(
            layer(&home),
            format!(
                "{MINE}\n[[target]]\npath = \"~/.tool.conf\"\nfile = \"files/.tool.conf\"\n\
                 mode = \"0600\"\n"
            ),
            "appended after every byte the user wrote",
        );
        let after = std::fs::metadata(&file).expect("stat");
        assert_eq!(std::fs::read(&file).expect("read"), bytes);
        assert_eq!(
            (after.ino(), after.mode(), after.mtime()),
            (before.ino(), before.mode(), before.mtime()),
            "adoption writes nothing in the home",
        );

        let entry = ledger(&home)
            .get(&target(&home, ".tool.conf"))
            .cloned()
            .expect("bx owns it");
        assert_eq!(entry.written, ContentHash::of(bytes));
        assert_eq!(entry.mode, Mode::PRIVATE_FILE);
        assert!(
            matches!(&entry.prior, Prior::Existed(prior) if prior.digest == ContentHash::of(bytes)),
            "rm restores the file as it was adopted: {:?}",
            entry.prior,
        );
        assert_eq!(plan_exit(&home).0, Exit::Converged);
    }

    #[test]
    fn a_default_mode_is_not_written_and_a_second_add_changes_nothing() {
        let home = repo("");
        plant(&home, ".plain", b"x\n", 0o644);
        add_rel(&home, ".plain");
        let layer_once = layer(&home);
        assert_eq!(
            layer_once,
            "[[target]]\npath = \"~/.plain\"\nfile = \"files/.plain\"\n"
        );
        let ledger_once = std::fs::read(StateDir::resolve(home.path()).ledger()).expect("ledger");

        let rows = add_rel(&home, ".plain");
        assert_eq!(
            rows,
            [Adoption::Unchanged {
                target: target(&home, ".plain")
            }]
        );
        assert_eq!(layer(&home), layer_once, "byte-identical");
        assert_eq!(
            std::fs::read(StateDir::resolve(home.path()).ledger()).expect("ledger"),
            ledger_once,
        );
    }

    #[test]
    fn a_symlink_is_refused_rather_than_adopted_as_what_it_points_at() {
        let home = repo(MINE);
        plant(&home, "real", b"real\n", 0o644);
        std::os::unix::fs::symlink(home.child("real"), home.child(".link")).expect("symlink");

        let rows = add_rel(&home, ".link");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("symbolic link")),
            "{rows:?}"
        );
        assert_eq!(layer(&home), MINE, "nothing declared");
        assert!(!home.child(".config/bx/files").exists(), "nothing copied");
        assert!(ledger(&home).is_empty(), "nothing owned");

        let mut out = Vec::new();
        let exit = crate::command::add(&env(home.path()), home.path(), Some(".link"), &mut out)
            .expect("add");
        assert_eq!(exit, Exit::Pending, "a refusal needs a human");
        assert!(
            String::from_utf8(out)
                .expect("UTF-8")
                .contains("  ! ~/.link  is a symbolic link")
        );
    }

    #[test]
    fn a_directory_adopts_every_regular_file_in_byte_order_and_skips_the_rest() {
        let home = repo(MINE);
        plant(&home, ".config/app/b", b"b\n", 0o644);
        plant(&home, ".config/app/a", b"a\n", 0o755);
        plant(&home, ".config/app/sub/c", b"c\n", 0o644);
        plant(&home, ".config/app/.git/HEAD", b"ref\n", 0o644);
        std::os::unix::fs::symlink(home.child(".config/app/a"), home.child(".config/app/link"))
            .expect("symlink");

        let rows = add_rel(&home, ".config/app");
        let shape: Vec<(&str, bool)> = rows
            .iter()
            .map(|row| (row.target().as_str(), matches!(row, Adoption::Adopt { .. })))
            .collect();
        assert_eq!(
            shape,
            [
                ("~/.config/app/.git", false),
                ("~/.config/app/a", true),
                ("~/.config/app/b", true),
                ("~/.config/app/link", false),
                ("~/.config/app/sub/c", true),
            ],
        );
        assert!(
            rows.iter()
                .all(|row| !row.needs_attention() && !matches!(row, Adoption::Refused { .. })),
            "what a directory holds and bx passes over is not a refusal: {rows:?}",
        );
        assert_eq!(mode_of(&body(&home, ".config/app/a")), 0o755);
        assert!(layer(&home).contains(
            "path = \"~/.config/app/a\"\nfile = \"files/.config/app/a\"\nmode = \"0755\"\n"
        ));
        assert!(!body(&home, ".config/app/.git").exists());
        let rows = add_rel(&home, ".config/app/.git");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("git repository")),
            "named, it is refused rather than walked: {rows:?}"
        );
        assert_eq!(plan_exit(&home).0, Exit::Converged);
    }

    #[test]
    fn credentials_are_refused_by_name_and_skipped_inside_a_directory() {
        let home = repo(MINE);
        plant(&home, ".ssh/id_ed25519", b"PRIVATE\n", 0o600);
        plant(&home, ".ssh/id_ed25519.pub", b"ssh-ed25519 AAAA\n", 0o644);
        plant(&home, ".ssh/config", b"Host *\n", 0o600);
        plant(&home, ".netrc", b"machine x\n", 0o600);

        for rel in [".ssh/id_ed25519", ".netrc"] {
            let rows = add_rel(&home, rel);
            assert!(
                matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("credential")),
                "{rel}: {rows:?}",
            );
        }
        let rows = add_rel(&home, ".ssh");
        assert_eq!(adopted(&rows), ["~/.ssh/config", "~/.ssh/id_ed25519.pub"]);
        assert!(
            rows.iter().any(|row| matches!(row, Adoption::Skipped { target: t, .. } if t.as_str() == "~/.ssh/id_ed25519")),
            "{rows:?}"
        );
        assert!(!body(&home, ".ssh/id_ed25519").exists());
        assert!(!layer(&home).contains("id_ed25519\""));
    }

    #[test]
    fn every_file_under_a_credential_directory_is_refused() {
        let home = repo(MINE);
        for rel in [
            ".gnupg/private-keys-v1.d/key.key",
            ".password-store/site.gpg",
            ".local/share/keyrings/login.keyring",
            ".config/age/keys.txt",
        ] {
            plant(&home, rel, b"SECRET\n", 0o600);
            let rows = add_rel(&home, rel);
            assert!(
                matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("credential")),
                "{rel}: {rows:?}",
            );
            assert!(!body(&home, rel).exists(), "{rel}");
        }
        assert_eq!(layer(&home), MINE);
    }

    #[test]
    fn a_path_holding_a_placeholder_delimiter_is_refused() {
        let home = repo(MINE);
        for rel in [".cfg/{{name}}", ".cfg/a{{b", ".cfg/a}}b"] {
            plant(&home, rel, b"x\n", 0o644);
            let rows = add_rel(&home, rel);
            assert!(
                matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("placeholder")),
                "{rel}: {rows:?}",
            );
            assert!(!body(&home, rel).exists(), "{rel}");
        }
        assert_eq!(layer(&home), MINE);
    }

    #[test]
    fn a_line_that_relocates_a_tool_is_a_warning_naming_it_and_the_file_is_still_adopted() {
        let home = repo(MINE);
        plant(
            &home,
            ".profile.d/env.sh",
            b"export EDITOR=vi\nexport CARGO_HOME=/elsewhere/cargo\nnot shell at all\n",
            0o644,
        );
        let rows = add_rel(&home, ".profile.d/env.sh");
        let [Adoption::Adopt { warnings, .. }] = rows.as_slice() else {
            panic!("adopted: {rows:?}");
        };
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("line 2: CARGO_HOME "),
            "{warnings:?}"
        );

        let mut out = Vec::new();
        plant(&home, ".other.sh", b"export CARGO_HOME=/x\n", 0o644);
        let exit = crate::command::add(
            &env(home.path()),
            home.path(),
            Some("~/.other.sh"),
            &mut out,
        )
        .expect("add");
        let text = String::from_utf8(out).expect("UTF-8");
        assert_eq!(exit, Exit::Converged, "a warning is not a refusal");
        assert!(text.contains("    warning: line 1: CARGO_HOME "), "{text}");
        assert!(text.contains("Adopted 1 file(s)"), "{text}");
    }

    #[test]
    fn bxs_own_directories_are_never_adopted() {
        let home = repo(MINE);
        let rows = add_rel(&home, ".config/bx/bx.toml");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("config repo")),
            "{rows:?}"
        );
        plant(&home, ".local/state/bx/local.toml", b"", 0o600);
        let rows = add_rel(&home, ".local/state/bx/local.toml");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("state directory")),
            "{rows:?}"
        );
        // Met inside a directory being adopted, the repo is passed over.
        plant(&home, ".config/tool.conf", b"t\n", 0o644);
        let rows = add_rel(&home, ".config");
        assert_eq!(adopted(&rows), ["~/.config/tool.conf"]);
        assert!(rows.iter().any(
            |row| matches!(row, Adoption::Skipped { target: t, .. } if t.as_str() == "~/.config/bx")
        ));
    }

    #[test]
    fn a_declared_identical_file_bx_does_not_own_becomes_owned() {
        let home = repo(&inline("~/.declared", "same\\n"));
        let file = plant(&home, ".declared", b"same\n", 0o644);
        let layer_before = layer(&home);

        let rows = add_rel(&home, ".declared");
        assert!(
            matches!(rows.as_slice(), [Adoption::Own { .. }]),
            "{rows:?}"
        );
        assert_eq!(layer(&home), layer_before, "nothing declared twice");
        let entry = ledger(&home)
            .get(&target(&home, ".declared"))
            .cloned()
            .expect("owned");
        assert!(
            matches!(entry.prior, Prior::Existed(_)),
            "the file the user wrote is the prior, never Absent: {entry:?}"
        );

        let rows = add_rel(&home, ".declared");
        assert!(
            matches!(rows.as_slice(), [Adoption::Unchanged { .. }]),
            "{rows:?}"
        );

        // `rm` hands the file back rather than unlinking it: bx wrote none of it.
        rm_rel(&home, ".declared");
        assert_eq!(std::fs::read(&file).expect("still there"), b"same\n");
        assert_eq!(mode_of(&file), 0o644);
    }

    #[test]
    fn a_declared_file_that_differs_or_is_switched_off_is_refused() {
        let home = repo(&inline("~/.declared", "repo\\n"));
        plant(&home, ".declared", b"disk\n", 0o644);
        let rows = add_rel(&home, ".declared");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("differs")),
            "{rows:?}"
        );

        let off = format!("{}enabled = false\n", inline("~/.off", "x\\n"));
        let home = repo(&off);
        plant(&home, ".off", b"x\n", 0o644);
        let rows = add_rel(&home, ".off");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("switched off")),
            "{rows:?}"
        );
        assert_eq!(layer(&home), off);
    }

    #[test]
    fn a_file_declared_as_a_secret_is_refused_and_nothing_is_copied() {
        let declared =
            "[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n";
        let home = repo(declared);
        plant(&home, ".token", b"hunter2\n", 0o600);
        let rows = add_rel(&home, ".token");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("does not adopt into")),
            "{rows:?}"
        );
        assert_eq!(layer(&home), declared);
        assert!(!home.child(".config/bx/files/.token").exists());
    }

    #[test]
    fn a_switched_off_placeholder_pathed_declaration_is_found_by_the_path_it_resolves_to() {
        let values = "[[value]]\nname = \"profile\"\nkind = \"string\"\ndefault = \"work\"\n";
        let templated = inline("~/.config/{{profile}}/s", "s\\n");

        // Switched off where it is declared.
        let off = format!("{values}\n{templated}enabled = false\n");
        let home = repo(&off);
        plant(&home, ".config/work/s", b"s\n", 0o644);
        let rows = add_rel(&home, ".config/work/s");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("switched off")),
            "{rows:?}"
        );
        assert_eq!(layer(&home), off, "not declared a second time");
        assert!(ledger(&home).is_empty());

        // Switched off by a toggle in local.toml.
        let on = format!("{values}\n{templated}");
        let home = repo(&on);
        let local = StateDir::resolve(home.path()).local_toml();
        let toggle = "[[target]]\npath = \"~/.config/{{profile}}/s\"\nenabled = false\n";
        std::fs::create_dir_all(local.parent().expect("parent")).expect("state dir");
        std::fs::write(&local, toggle).expect("local.toml");
        plant(&home, ".config/work/s", b"s\n", 0o644);
        let rows = add_rel(&home, ".config/work/s");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("switched off")),
            "{rows:?}"
        );
        assert_eq!(layer(&home), on, "not declared a second time");
        assert_eq!(std::fs::read_to_string(&local).expect("local.toml"), toggle);
    }

    #[test]
    fn discovery_leaves_out_what_a_blocked_target_or_a_switched_off_toggle_declares() {
        let values = "[[value]]\nname = \"who\"\nkind = \"string\"\n";
        let home = repo(&format!(
            "{values}\n{}\n{}",
            inline("~/.blocked", "{{who}}\\n"),
            inline("~/.toggled", "t\\n"),
        ));
        let local = StateDir::resolve(home.path()).local_toml();
        std::fs::create_dir_all(local.parent().expect("parent")).expect("state dir");
        std::fs::write(
            &local,
            "[[target]]\npath = \"~/.toggled\"\nenabled = false\n",
        )
        .expect("local.toml");
        for rel in [".blocked", ".toggled", ".free"] {
            plant(&home, rel, b"x\n", 0o644);
        }

        let ctx = context(&home);
        assert!(
            ctx.resolved
                .targets
                .iter()
                .any(|r| matches!(r, Resolution::Blocked(entry) if entry.key == "~/.blocked")),
            "the fixture holds a blocked target"
        );
        assert!(
            ctx.layers
                .iter()
                .any(|layer| { layer.config.toggles.iter().any(|t| t.key == "~/.toggled") }),
            "and a switched-off toggle"
        );
        assert_eq!(
            discover(&ctx, &home.child(".config")).expect("discover"),
            [target(&home, ".free")]
        );
    }

    #[test]
    fn discovery_leaves_out_what_programs_write_about_their_own_use() {
        let home = repo("");
        let written = [
            ".zcompdump",
            ".zcompdump-host-5.9",
            ".lesshst",
            ".viminfo",
            ".wget-hsts",
            ".Xauthority",
            ".ICEauthority",
            ".xsession-errors",
            ".sudo_as_admin_successful",
            ".python_history",
        ];
        for name in written {
            assert!(machine_written(name), "{name}");
            plant(&home, name, b"x\n", 0o600);
        }
        for name in [".zshrc", ".vimrc", ".lessrc"] {
            assert!(!machine_written(name), "{name}");
        }
        plant(&home, ".vimrc", b"x\n", 0o644);

        assert_eq!(
            discover(&context(&home), &home.child(".config")).expect("discover"),
            [target(&home, ".vimrc")]
        );
    }

    #[test]
    fn a_body_already_in_the_repo_is_reused_when_identical_and_refused_otherwise() {
        let home = repo(MINE);
        plant(&home, ".same", b"s\n", 0o644);
        plant(&home, ".config/bx/files/.same", b"s\n", 0o644);
        let rows = add_rel(&home, ".same");
        assert!(
            matches!(rows.as_slice(), [Adoption::Adopt { reuse: true, .. }]),
            "{rows:?}"
        );
        assert!(layer(&home).contains("path = \"~/.same\""));

        plant(&home, ".other", b"mine\n", 0o644);
        plant(&home, ".config/bx/files/.other", b"theirs\n", 0o644);
        let rows = add_rel(&home, ".other");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("other content")),
            "{rows:?}"
        );
        assert_eq!(
            std::fs::read(body(&home, ".other")).expect("body"),
            b"theirs\n",
            "the repo's file is not replaced",
        );
    }

    #[test]
    fn an_adopted_file_edited_in_the_repo_applies_and_rm_restores_the_adopted_bytes() {
        let home = repo(MINE);
        let file = plant(&home, ".rc", b"original\r\n", 0o600);
        add_rel(&home, ".rc");
        std::fs::write(body(&home, ".rc"), b"from the repo\n").expect("edit the body");

        let (exit, shown) = plan_exit(&home);
        assert_eq!(exit, Exit::Pending);
        assert!(
            shown.contains("  ~ ~/.rc"),
            "a modify, not a conflict: {shown}"
        );
        apply_yes(&home);
        assert_eq!(std::fs::read(&file).expect("read"), b"from the repo\n");

        let removals = rm_rel(&home, ".rc");
        assert!(
            matches!(
                removals.as_slice(),
                [Removal { restored: Restored::Reverted { .. }, undeclared, bodies }]
                    if undeclared.len() == 1 && bodies == &[PathBuf::from("files/.rc")]
            ),
            "{removals:?}"
        );
        assert_eq!(std::fs::read(&file).expect("read"), b"original\r\n");
        assert_eq!(mode_of(&file), 0o600);
        assert_eq!(layer(&home), MINE, "add then rm leaves bx.toml as it was");
        assert!(ledger(&home).is_empty());
        assert!(
            body(&home, ".rc").exists(),
            "the body is the user's to delete"
        );
        assert_eq!(plan_exit(&home).0, Exit::Converged);
    }

    #[test]
    fn rm_removes_a_file_bx_created_and_keeps_the_comments_around_its_declaration() {
        let layer_text = format!(
            "# above everything\n\n# the tool\n{}\n# after\n{}",
            inline("~/.made/new.conf", "new\\n"),
            inline("~/.kept", "kept\\n"),
        );
        let home = repo(&layer_text);
        apply_yes(&home);
        assert!(home.child(".made/new.conf").exists());

        let removals = rm_rel(&home, ".made");
        assert!(
            matches!(
                removals.as_slice(),
                [Removal {
                    restored: Restored::Removed { .. },
                    ..
                }]
            ),
            "{removals:?}"
        );
        assert!(
            !home.child(".made/new.conf").exists(),
            "removed, not emptied"
        );
        assert!(!home.child(".made").exists(), "and the directory bx made");
        assert_eq!(
            layer(&home),
            format!(
                "# above everything\n\n# the tool\n\n# after\n{}",
                inline("~/.kept", "kept\\n")
            ),
        );
        assert!(home.child(".kept").exists());
    }

    #[test]
    fn rm_puts_back_the_bytes_and_mode_of_a_file_bx_replaced() {
        let home = repo("");
        let file = plant(&home, ".replaced", b"the user's\n", 0o600);
        crate::plan::tests::own(home.path(), ".replaced", b"bx's\n", Mechanism::Own);
        seed(home.path(), &inline("~/.replaced", "bx's\\n"));
        assert_eq!(plan_exit(&home).0, Exit::Converged);

        let mut out = Vec::new();
        let exit = crate::command::rm(&env(home.path()), home.path(), Some(".replaced"), &mut out)
            .expect("rm");
        assert_eq!(exit, Exit::Converged);
        let text = String::from_utf8(out).expect("UTF-8");
        assert!(
            text.contains("  - ~/.replaced  put back the file bx replaced; no longer declared in ~/.config/bx/bx.toml"),
            "{text}"
        );
        assert_eq!(std::fs::read(&file).expect("read"), b"the user's\n");
        assert_eq!(mode_of(&file), 0o600);
        assert_eq!(layer(&home), "");
    }

    #[test]
    fn rm_over_an_edit_is_a_conflict_that_changes_nothing() {
        let layer_text = inline("~/.edited", "bx\\n");
        let home = repo(&layer_text);
        apply_yes(&home);
        std::fs::write(home.child(".edited"), b"hand edit\n").expect("edit");

        let mut out = Vec::new();
        let exit = crate::command::rm(&env(home.path()), home.path(), Some("~/.edited"), &mut out)
            .expect("rm");
        assert_eq!(exit, Exit::Pending);
        let text = String::from_utf8(out).expect("UTF-8");
        assert!(text.starts_with("  ! ~/.edited  "), "{text}");
        assert!(text.ends_with("; still managed\n"), "{text}");
        assert_eq!(
            std::fs::read(home.child(".edited")).expect("read"),
            b"hand edit\n"
        );
        assert_eq!(layer(&home), layer_text, "still declared");
        assert!(ledger(&home).get(&target(&home, ".edited")).is_some());
    }

    #[test]
    fn rm_of_something_bx_does_not_manage_is_a_no_op() {
        let home = repo(MINE);
        plant(&home, ".untouched", b"u\n", 0o644);
        let mut out = Vec::new();
        let exit = crate::command::rm(&env(home.path()), home.path(), Some(".untouched"), &mut out)
            .expect("rm");
        assert_eq!(exit, Exit::Converged);
        assert_eq!(
            String::from_utf8(out).expect("UTF-8"),
            "~/.untouched is not managed by bx; nothing to do.\n"
        );
        assert_eq!(
            std::fs::read(home.child(".untouched")).expect("read"),
            b"u\n"
        );
    }

    #[test]
    fn rm_of_a_declared_target_bx_never_wrote_only_undeclares_it_in_every_layer() {
        let home = repo(&inline("~/.never", "n\\n"));
        let local = StateDir::resolve(home.path()).local_toml();
        std::fs::create_dir_all(local.parent().expect("parent")).expect("state dir");
        std::fs::write(&local, "[[target]]\npath = \"~/.never\"\nenabled = true\n")
            .expect("local.toml");

        let removals = rm_rel(&home, ".never");
        assert!(
            matches!(
                removals.as_slice(),
                [Removal { restored: Restored::Unmanaged { .. }, undeclared, .. }] if undeclared.len() == 2
            ),
            "{removals:?}"
        );
        assert_eq!(layer(&home), "");
        assert_eq!(std::fs::read_to_string(&local).expect("local.toml"), "");
        assert!(rm_rel(&home, ".never").is_empty(), "a second rm is a no-op");
    }

    #[test]
    fn rm_of_a_secret_target_reports_its_ciphertext_as_left_in_the_repo() {
        let home = repo(
            "[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n",
        );

        let removals = rm_rel(&home, ".token");
        assert!(
            matches!(
                removals.as_slice(),
                [Removal { restored: Restored::Unmanaged { .. }, undeclared, bodies }]
                    if undeclared.len() == 1 && bodies == &[PathBuf::from("secrets/token.age")]
            ),
            "{removals:?}"
        );
        assert_eq!(layer(&home), "");
    }

    #[test]
    fn rm_of_a_placeholder_pathed_target_undeclares_it_by_the_path_it_resolves_to() {
        let values = "[[value]]\nname = \"profile\"\nkind = \"string\"\ndefault = \"work\"\n";
        let home = repo(&format!(
            "{values}\n{}",
            inline("~/.config/{{profile}}/s", "s\\n")
        ));
        apply_yes(&home);
        assert!(home.child(".config/work/s").exists());

        let removals = rm_rel(&home, ".config/work/s");
        assert!(
            matches!(
                removals.as_slice(),
                [Removal { restored: Restored::Removed { .. }, undeclared, .. }] if undeclared.len() == 1
            ),
            "{removals:?}"
        );
        assert!(!home.child(".config/work/s").exists());
        assert_eq!(layer(&home), values, "the templated declaration is gone");
        assert_eq!(
            plan_exit(&home).0,
            Exit::Converged,
            "and apply would not recreate it"
        );
        assert!(
            rm_rel(&home, ".config/work/s").is_empty(),
            "a second rm is a no-op"
        );
    }

    #[test]
    fn locate_takes_a_shell_spelling_and_refuses_what_is_not_inside_the_home() {
        let home = guarded_home();
        let cwd = home.child("work");
        let at = |arg: &str| locate(arg, &cwd, home.path()).map(|t| t.as_str().to_string());
        assert_eq!(at("~/.a").expect("tilde"), "~/.a");
        assert_eq!(at("x/../.b").expect("relative"), "~/work/.b");
        assert_eq!(
            at(&home.child(".c").to_string_lossy()).expect("absolute"),
            "~/.c"
        );
        assert!(matches!(at("~"), Err(Error::OutsideHome(_))));
        assert!(matches!(at("/etc/hosts"), Err(Error::OutsideHome(_))));
        assert!(matches!(
            at("~/../x"),
            Err(Error::OutsideHome(_) | Error::Path(_))
        ));
    }

    #[test]
    fn a_missing_path_no_path_and_no_repo_are_errors() {
        let home = repo(MINE);
        let mut out = Vec::new();
        let e = env(home.path());
        assert!(matches!(
            crate::command::add(&e, home.path(), None, &mut out),
            Err(Error::NoPath("add"))
        ));
        assert!(matches!(
            crate::command::rm(&e, home.path(), None, &mut out),
            Err(Error::NoPath("rm"))
        ));
        assert!(matches!(
            crate::command::add(&e, home.path(), Some(".nothing"), &mut out),
            Err(Error::Missing(missing)) if missing == "~/.nothing"
        ));

        let bare = guarded_home();
        plant(&bare, ".x", b"x\n", 0o644);
        let err = crate::command::add(&env(bare.path()), bare.path(), Some(".x"), &mut out)
            .expect_err("no repo");
        assert!(matches!(err, Error::RepoMissing(_)), "{err}");
        assert!(err.to_string().contains("bx init"), "{err}");
        assert!(out.is_empty());
    }

    /// A layer declaring the tree `files/.config/x` at `~/.config/x` — laid
    /// out as `add` lays out its copies — holding `a` and `sub/b`.
    const TREE: &str = "[[target]]\npath = \"~/.config/x\"\ntree = \"files/.config/x\"\n";

    fn tree_repo() -> GuardedHome {
        let home = repo(TREE);
        plant(&home, ".config/bx/files/.config/x/a", b"a\n", 0o644);
        plant(&home, ".config/bx/files/.config/x/sub/b", b"b\n", 0o644);
        home
    }

    fn rm_text(home: &GuardedHome, arg: &str) -> (Exit, String) {
        let mut out = Vec::new();
        let exit =
            crate::command::rm(&env(home.path()), home.path(), Some(arg), &mut out).expect("rm");
        (exit, String::from_utf8(out).expect("UTF-8"))
    }

    #[test]
    fn add_refuses_to_copy_a_file_into_a_tree_s_root() {
        let home = tree_repo();
        apply_yes(&home);
        plant(&home, ".config/x/new", b"new\n", 0o644);

        let rows = add_rel(&home, ".config/x/new");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                if note.contains("inside `tree = \"files/.config/x\"`")
                    && note.contains("copy it into files/.config/x yourself")),
            "{rows:?}"
        );
        assert_eq!(layer(&home), TREE, "nothing declared");
        assert!(!body(&home, ".config/x/new").exists(), "nothing copied");
        assert!(ledger(&home).get(&target(&home, ".config/x/new")).is_none());
        assert_eq!(plan_exit(&home).0, Exit::Converged, "the repo still loads");

        // A file the tree already delivers is declared, and adds as it did.
        let rows = add_rel(&home, ".config/x/a");
        assert!(
            matches!(rows.as_slice(), [Adoption::Unchanged { .. }]),
            "{rows:?}"
        );
    }

    #[test]
    fn add_refuses_a_copy_into_a_tree_root_that_lands_elsewhere() {
        // The tree mirrors `files/.config/x` to `~/.y`: a copy of `~/.config/x/new`
        // would be delivered to `~/.y/new` as well.
        let home = repo("[[target]]\npath = \"~/.y\"\ntree = \"files/.config/x\"\n");
        plant(&home, ".config/bx/files/.config/x/a", b"a\n", 0o644);
        plant(&home, ".config/x/new", b"new\n", 0o644);

        let rows = add_rel(&home, ".config/x/new");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { .. }]),
            "{rows:?}"
        );
        assert!(!body(&home, ".config/x/new").exists());
    }

    #[test]
    fn rm_on_a_tree_s_path_retires_the_whole_tree() {
        let home = tree_repo();
        apply_yes(&home);
        assert!(home.child(".config/x/sub/b").exists());

        let removals = rm_rel(&home, ".config/x");
        let rows: Vec<(&str, bool, usize)> = removals
            .iter()
            .map(|r| {
                (
                    r.restored.target().as_str(),
                    matches!(r.restored, Restored::Removed { .. }),
                    r.undeclared.len(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("~/.config/x", false, 1),
                ("~/.config/x/a", true, 0),
                ("~/.config/x/sub/b", true, 0),
            ],
            "{removals:?}"
        );
        assert!(!home.child(".config/x/a").exists());
        assert!(!home.child(".config/x/sub/b").exists());
        assert_eq!(layer(&home), "", "the tree's table is gone");
        assert!(
            body(&home, ".config/x/a").exists(),
            "the repo's files stay where they are"
        );
        assert_eq!(ledger(&home).iter().count(), 0);
        assert_eq!(plan_exit(&home).0, Exit::Converged);
        assert!(
            rm_rel(&home, ".config/x").is_empty(),
            "a second rm is a no-op"
        );
    }

    #[test]
    fn rm_on_a_tree_s_path_with_a_conflicting_file_leaves_the_whole_tree() {
        let home = tree_repo();
        apply_yes(&home);
        std::fs::write(home.child(".config/x/a"), b"hand edit\n").expect("edit");

        let (exit, text) = rm_text(&home, "~/.config/x");
        assert_eq!(exit, Exit::Pending);
        assert!(text.starts_with("  ! ~/.config/x/a  "), "{text}");
        assert!(
            text.contains("  ! ~/.config/x/sub/b  is left as it is: the tree at "),
            "{text}"
        );
        assert!(
            text.contains("and ~/.config/x/a conflicts; still managed"),
            "{text}"
        );
        assert!(!text.contains("no longer declared"), "{text}");
        assert_eq!(layer(&home), TREE, "the tree stays declared");
        assert_eq!(
            std::fs::read(home.child(".config/x/a")).expect("read"),
            b"hand edit\n"
        );
        assert_eq!(
            std::fs::read(home.child(".config/x/sub/b")).expect("read"),
            b"b\n",
            "the rest of the tree is not handed back either"
        );
        let owned = ledger(&home);
        assert!(owned.get(&target(&home, ".config/x/a")).is_some());
        assert!(owned.get(&target(&home, ".config/x/sub/b")).is_some());
    }

    #[test]
    fn rm_on_a_file_a_tree_declares_releases_nothing_and_names_exclude() {
        let home = tree_repo();
        apply_yes(&home);

        let (exit, text) = rm_text(&home, "~/.config/x/sub");
        assert_eq!(exit, Exit::Pending);
        assert!(
            text.starts_with("  ! ~/.config/x/sub/b  is declared by the tree at "),
            "{text}"
        );
        assert!(
            text.contains("add an `exclude` pattern there to stop managing it, or `bx rm ~/.config/x` to release the whole tree; still managed"),
            "{text}"
        );
        assert_eq!(text.lines().count(), 1, "{text}");
        assert_eq!(layer(&home), TREE);
        assert!(home.child(".config/x/sub/b").exists());
        assert!(
            ledger(&home)
                .get(&target(&home, ".config/x/sub/b"))
                .is_some()
        );
        assert_eq!(plan_exit(&home).0, Exit::Converged);
    }

    #[test]
    fn rm_inside_a_tree_hands_back_a_file_the_tree_no_longer_declares() {
        let home = tree_repo();
        apply_yes(&home);
        std::fs::remove_file(body(&home, ".config/x/sub/b")).expect("drop from the repo");

        let (exit, text) = rm_text(&home, "~/.config/x/sub/b");
        assert_eq!(exit, Exit::Converged, "{text}");
        assert!(
            text.starts_with("  - ~/.config/x/sub/b  removed the file bx created"),
            "{text}"
        );
        assert!(!home.child(".config/x/sub/b").exists());
        assert_eq!(layer(&home), TREE);
    }

    /// `~/.lock`, tracked, with its repo copy at `files/lock`.
    const TRACKED: &str =
        "[[target]]\npath = \"~/.lock\"\nfile = \"files/lock\"\ndirection = \"track\"\n";

    /// A sync's apply: carries every tracked target this machine changed.
    fn sync_apply(home: &GuardedHome) {
        let inputs = crate::plan::Inputs::load(&env(home.path())).expect("inputs");
        crate::plan::run(&inputs, crate::plan::Mode::Sync, &mut |_| Ok(true)).expect("sync");
    }

    /// A home tracking `~/.lock`, whose repo copy held `before` until this
    /// machine's `after` was carried into it.
    fn tracked_and_synced(before: &[u8], after: &[u8]) -> GuardedHome {
        let home = repo(TRACKED);
        plant(&home, ".config/bx/files/lock", before, 0o644);
        plant(&home, ".lock", before, 0o644);
        sync_apply(&home);
        plant(&home, ".lock", after, 0o644);
        sync_apply(&home);
        assert_eq!(
            std::fs::read(body(&home, "lock")).expect("the copy"),
            after,
            "carried"
        );
        home
    }

    #[test]
    fn rm_of_a_tracked_target_restores_the_repo_copy_and_leaves_the_machine_copy() {
        let home = tracked_and_synced(b"before\n", b"after\n");

        let (exit, text) = rm_text(&home, "~/.lock");
        assert_eq!(exit, Exit::Converged, "{text}");
        assert_eq!(
            text,
            "  - ~/.config/bx/files/lock  put back the file bx replaced\n\
             \x20 - ~/.lock  left as it is; bx never wrote it; no longer declared in \
             ~/.config/bx/bx.toml; files/lock stays in the repo\n"
        );
        assert_eq!(
            std::fs::read(body(&home, "lock")).expect("the copy"),
            b"before\n"
        );
        assert_eq!(
            std::fs::read(home.child(".lock")).expect("kept"),
            b"after\n"
        );
        assert_eq!(layer(&home), "");
        assert_eq!(ledger(&home).iter().count(), 0);
        assert!(rm_rel(&home, ".lock").is_empty(), "a second rm is a no-op");
    }

    #[test]
    fn rm_of_a_tracked_target_whose_repo_copy_moved_since_is_a_conflict_that_changes_nothing() {
        let home = tracked_and_synced(b"before\n", b"after\n");
        // Another machine's sync, pulled into this repo.
        std::fs::write(body(&home, "lock"), b"theirs\n").expect("theirs");

        let (exit, text) = rm_text(&home, "~/.lock");
        assert_eq!(exit, Exit::Pending, "{text}");
        assert!(
            text.starts_with("  ! ~/.lock  its repo copy ~/.config/bx/files/lock "),
            "{text}"
        );
        assert_eq!(text.lines().count(), 1, "{text}");
        assert_eq!(
            std::fs::read(body(&home, "lock")).expect("the copy"),
            b"theirs\n"
        );
        assert_eq!(
            std::fs::read(home.child(".lock")).expect("kept"),
            b"after\n"
        );
        assert_eq!(layer(&home), TRACKED, "still declared");
    }

    #[test]
    fn rm_of_a_tracked_target_never_synced_only_undeclares_it() {
        let home = repo(TRACKED);
        plant(&home, ".config/bx/files/lock", b"repo\n", 0o644);
        plant(&home, ".lock", b"machine\n", 0o644);

        let removals = rm_rel(&home, ".lock");
        assert!(
            matches!(
                removals.as_slice(),
                [Removal { restored: Restored::Unmanaged { .. }, undeclared, .. }]
                    if undeclared.len() == 1
            ),
            "{removals:?}"
        );
        assert_eq!(std::fs::read(body(&home, "lock")).expect("copy"), b"repo\n");
        assert_eq!(
            std::fs::read(home.child(".lock")).expect("kept"),
            b"machine\n"
        );
    }

    /// `~/.config/tool/lock`, tracked, with its repo copy at `files/lock`:
    /// nested, so the write onto a fresh machine makes a directory.
    const TRACKED_NESTED: &str = "[[target]]\npath = \"~/.config/tool/lock\"\n\
                                  file = \"files/lock\"\ndirection = \"track\"\n";

    /// A fresh machine tracking `~/.config/tool/lock`: only the repo has it,
    /// until `apply` writes it here.
    fn tracked_onto_a_fresh_machine() -> GuardedHome {
        let home = repo(TRACKED_NESTED);
        plant(&home, ".config/bx/files/lock", b"repo\n", 0o644);
        apply_yes(&home);
        assert_eq!(
            std::fs::read(home.child(".config/tool/lock")).expect("written"),
            b"repo\n"
        );
        home
    }

    #[test]
    fn rm_of_a_tracked_target_apply_created_removes_it_and_its_directories() {
        let home = tracked_onto_a_fresh_machine();
        assert_eq!(
            plan_exit(&home).0,
            Exit::Converged,
            "a second plan is empty"
        );

        let (exit, text) = rm_text(&home, "~/.config/tool");
        assert_eq!(exit, Exit::Converged, "{text}");
        assert!(
            text.starts_with("  - ~/.config/tool/lock  removed the file bx created"),
            "{text}"
        );
        assert!(
            !home.child(".config/tool").exists(),
            "the home is as it was"
        );
        assert_eq!(
            std::fs::read(body(&home, "lock")).expect("the copy"),
            b"repo\n",
            "bx never wrote the repo copy"
        );
        assert_eq!(layer(&home), "");
        assert_eq!(ledger(&home).iter().count(), 0);
        assert!(
            rm_rel(&home, ".config/tool").is_empty(),
            "a second rm is a no-op"
        );
    }

    #[test]
    fn rm_of_a_tracked_tree_apply_created_removes_every_file_and_its_directories() {
        let layer_text = "[[target]]\npath = \"~/.config/x\"\ntree = \"files/.config/x\"\n\
                          direction = \"track\"\n";
        let home = repo(layer_text);
        plant(&home, ".config/bx/files/.config/x/a", b"a\n", 0o644);
        plant(&home, ".config/bx/files/.config/x/sub/b", b"b\n", 0o644);
        apply_yes(&home);
        assert_eq!(
            std::fs::read(home.child(".config/x/sub/b")).expect("written"),
            b"b\n"
        );
        assert_eq!(
            plan_exit(&home).0,
            Exit::Converged,
            "a second plan is empty"
        );

        let (exit, text) = rm_text(&home, "~/.config/x");
        assert_eq!(exit, Exit::Converged, "{text}");
        assert!(
            text.contains("  - ~/.config/x/a  removed the file bx created")
                && text.contains("  - ~/.config/x/sub/b  removed the file bx created"),
            "{text}"
        );
        assert!(!home.child(".config/x").exists(), "the home is as it was");
        assert_eq!(
            std::fs::read(body(&home, ".config/x/a")).expect("a"),
            b"a\n",
            "bx never wrote the repo copies"
        );
        assert_eq!(
            std::fs::read(body(&home, ".config/x/sub/b")).expect("b"),
            b"b\n"
        );
        assert_eq!(layer(&home), "");
        assert_eq!(ledger(&home).iter().count(), 0);
        assert!(
            rm_rel(&home, ".config/x").is_empty(),
            "a second rm is a no-op"
        );
    }

    #[test]
    fn a_repo_change_written_over_a_copy_bx_created_keeps_it_claimed() {
        let home = tracked_onto_a_fresh_machine();
        std::fs::write(body(&home, "lock"), b"newer\n").expect("a pulled change");
        apply_yes(&home);
        assert_eq!(
            std::fs::read(home.child(".config/tool/lock")).expect("written"),
            b"newer\n"
        );

        let (exit, text) = rm_text(&home, "~/.config/tool/lock");
        assert_eq!(exit, Exit::Converged, "{text}");
        assert!(
            !home.child(".config/tool").exists(),
            "the home is as it was"
        );
    }

    #[test]
    fn rm_of_a_tracked_copy_the_tool_rewrote_is_a_conflict_that_changes_nothing() {
        let home = tracked_onto_a_fresh_machine();
        plant(&home, ".config/tool/lock", b"tool\n", 0o644);
        sync_apply(&home);
        assert_eq!(
            std::fs::read(body(&home, "lock")).expect("carried"),
            b"tool\n"
        );

        let (exit, text) = rm_text(&home, "~/.config/tool/lock");
        assert_eq!(exit, Exit::Pending, "{text}");
        assert!(
            text.starts_with("  ! ~/.config/tool/lock  has been edited since bx wrote it"),
            "{text}"
        );
        assert_eq!(text.lines().count(), 1, "{text}");
        assert_eq!(
            std::fs::read(home.child(".config/tool/lock")).expect("kept"),
            b"tool\n"
        );
        assert_eq!(
            std::fs::read(body(&home, "lock")).expect("the copy"),
            b"tool\n",
            "the repo copy is not handed back without the machine copy"
        );
        assert_eq!(layer(&home), TRACKED_NESTED, "still declared");
    }

    #[test]
    fn rm_of_a_tracked_tree_restores_every_copy_and_holds_on_one_that_conflicts() {
        let layer_text = "[[target]]\npath = \"~/.config/x\"\ntree = \"files/.config/x\"\n\
                          direction = \"track\"\n";
        let home = repo(layer_text);
        for (rel, bytes) in [("a", b"a\n"), ("b", b"b\n")] {
            plant(
                &home,
                &format!(".config/bx/files/.config/x/{rel}"),
                bytes,
                0o644,
            );
            plant(&home, &format!(".config/x/{rel}"), bytes, 0o644);
        }
        sync_apply(&home);
        plant(&home, ".config/x/a", b"a2\n", 0o644);
        plant(&home, ".config/x/b", b"b2\n", 0o644);
        sync_apply(&home);
        std::fs::write(body(&home, ".config/x/b"), b"theirs\n").expect("theirs");

        let (exit, text) = rm_text(&home, "~/.config/x");
        assert_eq!(exit, Exit::Pending, "{text}");
        assert_eq!(layer(&home), layer_text, "the tree stays whole");
        assert_eq!(
            std::fs::read(body(&home, ".config/x/a")).expect("a"),
            b"a2\n",
            "nothing restored"
        );

        std::fs::write(body(&home, ".config/x/b"), b"b2\n").expect("put back");
        let (exit, text) = rm_text(&home, "~/.config/x");
        assert_eq!(exit, Exit::Converged, "{text}");
        assert_eq!(layer(&home), "");
        assert_eq!(
            std::fs::read(body(&home, ".config/x/a")).expect("a"),
            b"a\n"
        );
        assert_eq!(
            std::fs::read(body(&home, ".config/x/b")).expect("b"),
            b"b\n"
        );
        assert_eq!(
            std::fs::read(home.child(".config/x/a")).expect("a"),
            b"a2\n"
        );
    }

    #[test]
    fn add_of_a_tracked_target_is_refused_naming_sync() {
        let home = repo(TRACKED);
        plant(&home, ".config/bx/files/lock", b"x\n", 0o644);
        plant(&home, ".lock", b"x\n", 0o644);
        let rows = add_rel(&home, ".lock");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                if note.ends_with("as tracked; bx sync carries it into the repo")),
            "{rows:?}"
        );
    }
}
