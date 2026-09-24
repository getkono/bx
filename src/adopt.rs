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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use toml_edit::{ArrayOfTables, Document, DocumentMut, Item, Table, value};

use crate::config::resolve::{Resolution, Resolved};
use crate::config::target::{Attach, Body, Direction, Format};
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
        Ok(Self {
            home,
            repo,
            state,
            layers,
            resolved,
            roots,
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
    fn declared(&self, target: &Portable) -> Declared<'_> {
        for resolution in &self.resolved.targets {
            match resolution {
                Resolution::Ready(ready) if ready.path == *target => {
                    return Declared::Ready(ready);
                }
                Resolution::Blocked(entry) if entry.key == target.as_str() => {
                    return Declared::Blocked(&entry.origin, &entry.hint);
                }
                _ => {}
            }
        }
        for layer in &self.layers {
            if let Some(found) = layer.config.targets.iter().find(|t| t.path == *target) {
                return Declared::Disabled(&found.origin);
            }
            if let Some(toggle) = layer.config.toggles.iter().find(|toggle| {
                Portable::parse_in(&toggle.key, &self.home).is_ok_and(|key| key == *target)
            }) {
                return Declared::Disabled(&toggle.origin);
            }
        }
        Declared::No
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
        Kind::Dir if !named && dest.file_name().is_some_and(|name| name == ".git") => {
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

/// Why a path must not be copied into the repo in cleartext, when it is one of
/// the files that conventionally hold a credential.
///
/// Conservative, and deliberately a list rather than a scan of the content:
/// which files hold secrets in general is the commit guard's to decide.
fn secret(target: &Portable) -> Option<String> {
    let rel = target.as_str().strip_prefix("~/")?;
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
            if declared.attach != Attach::Own
                || declared.direction != Direction::Apply
                || declared.format != Format::Opaque
            {
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
                Body::Generated(_) | Body::Dir => {
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
    recover::before_writing(state)?;
    state.ensure()?;
    let lock = ExclusiveLock::acquire(state)?;
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
            fs::write_atomically(&ctx.repo.join(body), bytes, *mode)?;
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
                NewEntry::new(
                    target.clone(),
                    ContentHash::of(bytes),
                    *mode,
                    Mechanism::Own,
                )
                .with_prior(PriorBytes::Bytes {
                    bytes: bytes.clone(),
                    mode: *mode,
                }),
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
            let Some(target) = declared_path(table, &ctx.home) else {
                continue;
            };
            if beneath(&target, under) {
                found.push(Declaration {
                    layer: layer.file.clone(),
                    target,
                    body: table.get("file").and_then(Item::as_str).map(PathBuf::from),
                });
            }
        }
    }
    Ok(found)
}

/// The path a `[[target]]` table declares, when it is one bx can read.
fn declared_path(table: &Table, home: &Path) -> Option<Portable> {
    let raw = table.get("path").and_then(Item::as_str)?;
    Portable::parse_in(raw, home).ok()
}

/// Remove every `[[target]]` table naming one of `released` from `layer`.
///
/// Removed as text, a table at a time: from the start of its header line to
/// the end of the line its last value ends on. Everything outside that range
/// stays byte for byte — the comments above the header included, since they
/// may introduce more than this one target — except one blank line directly
/// above the header, which is the separator [`declare`] wrote, so `add` then
/// `rm` leaves `bx.toml` exactly as it was.
fn undeclare(layer: &Path, released: &BTreeSet<&Portable>, home: &Path) -> Result<(), Error> {
    let (text, mode) = open_layer(layer)?;
    let doc = parse_layer(layer, &text)?;
    let Some(tables) = doc.get("target").and_then(Item::as_array_of_tables) else {
        return Ok(());
    };
    let mut ranges = Vec::new();
    for table in tables {
        if !declared_path(table, home).is_some_and(|t| released.contains(&t)) {
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
/// declaring it. A conflict is left declared and untouched. Nothing to do is
/// an empty result, which is what makes a second `rm` a no-op.
///
/// # Errors
///
/// Whatever reading the ledger, restoring, or editing a layer returns.
pub fn rm(ctx: &Context, target: &Portable) -> Result<Vec<Removal>, Error> {
    let ledger = LedgerView::read(&ctx.state, &ctx.home)?.value;
    let found = declarations(ctx, target)?;
    let targets: BTreeSet<Portable> = found
        .iter()
        .map(|declaration| declaration.target.clone())
        .chain(
            ledger
                .iter()
                .map(|(path, _)| path.clone())
                .filter(|path| beneath(path, target)),
        )
        .collect();
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let targets: Vec<Portable> = targets.into_iter().collect();
    let restored = restore::restore(&ctx.state, &ctx.home, &targets)?;

    let released: BTreeSet<&Portable> = restored
        .iter()
        .filter(|done| !done.is_conflict())
        .map(Restored::target)
        .collect();
    let layers: BTreeSet<&Path> = found
        .iter()
        .filter(|declaration| released.contains(&declaration.target))
        .map(|declaration| declaration.layer.as_path())
        .collect();
    if !layers.is_empty() {
        let _lock = lock(&ctx.state)?;
        for layer in layers {
            undeclare(layer, &released, &ctx.home)?;
        }
    }

    Ok(restored
        .into_iter()
        .map(|done| {
            let mine: Vec<&Declaration> = if done.is_conflict() {
                Vec::new()
            } else {
                found
                    .iter()
                    .filter(|declaration| declaration.target == *done.target())
                    .collect()
            };
            Removal {
                undeclared: mine.iter().map(|d| d.layer.clone()).collect(),
                bodies: mine.iter().filter_map(|d| d.body.clone()).collect(),
                restored: done,
            }
        })
        .collect())
}
