//! The ordered layer set: the config repo's global layers, then this account's.
//!
//! ```text
//! ~/.config/bx/bx.toml         global, committed, publishable
//! ~/.config/bx/modules/*.toml  global, committed, sorted by raw filename bytes
//! ~/.local/state/bx/local.toml this account's — never committed, never in the repo
//! ```
//!
//! The split between the two roots is load-bearing for Invariant 5. The config
//! repo is a git working tree that is meant to be published, and a file inside
//! one can be committed by accident; the state directory is not a working tree
//! and never becomes one. So `local.toml` lives in the state directory, and a
//! `local.toml` found inside the config repo is **never loaded** — it is
//! reported by [`stray_local`] so `bx doctor` can name the move. A state
//! directory that is itself inside the repo is refused outright, rather than
//! loading its `local.toml` or silently dropping it.
//!
//! # Why the local layer is a full layer
//!
//! It is not a value file. An account that could only fill in placeholders
//! somebody else had already declared could not add a target, replace one
//! target's body wholesale, or opt out of a target another account wants. Two of
//! the thirteen kinds of divergence in the source material — an age-encrypted
//! `~/.ssh/config`, and a per-GPU `nvtop/interface.ini` that the tool itself
//! generates — are expressible **only** through in-place entry replacement and
//! `enabled = false`. Making the last layer a full layer is what covers them,
//! and it is why this file exists rather than a `values.toml` reader.
//!
//! # Inside the repo is decided lexically, not on disk
//!
//! Whether a path is inside the config repo is decided by comparing spellings
//! after [`paths::normalize`], which reads no filesystem. That is the same rule
//! every other path comparison in the crate uses, and it is what lets the whole
//! of layer resolution stay a pure function of its arguments: Invariant 3 asks
//! for two `plan` runs a week apart to be byte-identical, which a check that
//! resolved symlinks could not promise, and Invariant 6 keeps I/O off paths
//! that do not need it.
//!
//! **Its limit, stated rather than discovered.** A symlinked alias of the repo
//! is a different spelling, so a state directory reached through one is *not*
//! refused, and `bx` will write a `local.toml` that is inside the repo on disk
//! — the hole the check exists to close.
//! `a_state_directory_reached_through_a_symlinked_alias_of_the_repo_is_not_refused`
//! pins that, so changing it is a deliberate edit to a named test rather than a
//! quiet change of behaviour. Closing it needs a decision this module does not
//! take on its own: layer resolution would have to read the filesystem, by
//! `canonicalize` or by comparing device and inode, and every caller would
//! inherit the I/O and the failure modes of a path that may not exist yet. The
//! `local.toml` writer entry A8 adds inherits the same limit, and must not take
//! this check as proof that the file it writes is outside the repo.
//!
//! # Nothing here reads the environment
//!
//! [`state_dir`] takes both the home and the `XDG_STATE_HOME` override as
//! arguments. A resolution path that read the environment would make the merge
//! impure and Invariant 3 unprovable, and the state directory has to be the same
//! one entry A4's ledger picks — two resolvers that disagreed would put the
//! ledger and the local layer in different directories.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::{Error, Layer, LayerKind, load_layer};
use crate::paths;

/// The account's own layer, in the state directory.
pub const LOCAL_FILE: &str = "local.toml";

/// The state directory's default, relative to the home.
const STATE_FALLBACK: &str = ".local/state";

/// The state directory — `$XDG_STATE_HOME/bx`, default `~/.local/state/bx`.
///
/// Both inputs are explicit so the library reads no environment. The binary
/// passes `std::env::var_os("XDG_STATE_HOME").as_deref()`; a test passes what it
/// wants to test.
#[must_use]
pub fn state_dir(home: &Path, xdg_state_home: Option<&OsStr>) -> PathBuf {
    paths::xdg_base(xdg_state_home, home, STATE_FALLBACK).join("bx")
}

/// This account's layer file inside `state_dir`.
#[must_use]
pub fn local_layer_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LOCAL_FILE)
}

/// Every layer file, in merge order: the repo's globals, then the local layer.
///
/// A missing `local.toml` is ordinary and yields a shorter list, not an error:
/// an account that has answered nothing is a real state, and every declared
/// value is simply unanswered.
///
/// Any `local.toml` **inside the repo** is filtered out here, wherever it sits.
/// Loading one would merge account content out of a publishable git tree, which
/// is the hole Invariant 5 exists to close; [`stray_local`] is how it gets
/// reported instead of silently ignored.
///
/// That includes the local layer itself. A state directory inside the repo —
/// `XDG_STATE_HOME` equal to `XDG_CONFIG_HOME` makes it the repo — is
/// [`Error::LocalInRepo`], whether or not a `local.toml` is there yet: loading
/// it would be the hole above, and skipping it would silently drop the
/// account's layer. Compared lexically after [`paths::normalize`], like every
/// other path rule in the crate, so a symlinked alias of the repo is not caught;
/// see *Inside the repo is decided lexically, not on disk* in the [module
/// documentation](self) for that rule, its limit, and what closing the limit
/// would cost.
///
/// # Only a clean answer skips the local layer
///
/// `local.toml` is examined the way [`super::layer_files`] examines a global
/// layer: `lstat` first. It is left out only when nothing is at the path, or
/// when what is there is not a regular file. A dangling symlink, `EACCES`,
/// `ELOOP`, or a state directory that is not a directory is an [`Error::Io`]
/// naming `local.toml`. `Path::is_file` answers `false` for all of those, and
/// an account whose layer is silently dropped gets every other account's
/// configuration with nothing saying why.
///
/// # Errors
///
/// Whatever [`super::layer_files`] returns, [`Error::LocalInRepo`] when the
/// state directory lies inside the repo, and [`Error::Io`] naming `local.toml`
/// when it cannot be examined.
pub fn layer_paths(repo: &Path, state_dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut paths: Vec<PathBuf> = super::layer_files(repo)?
        .into_iter()
        .filter(|path| path.file_name() != Some(OsStr::new(LOCAL_FILE)))
        .collect();

    let local = local_layer_path(state_dir);
    if paths::normalize(&local).starts_with(paths::normalize(repo)) {
        return Err(Error::LocalInRepo {
            local,
            repo: repo.to_path_buf(),
        });
    }
    if super::examine(&local)?.is_some_and(|meta| meta.is_file()) {
        paths.push(local);
    }

    Ok(paths)
}

/// Read and parse the whole layer set, **unmerged**, in merge order.
///
/// Each layer knows whether it is [`LayerKind::Global`] — committed, and so
/// forbidden from carrying a `[values]` table — or [`LayerKind::Local`].
///
/// `home` is threaded in, never read here: it is what a target path is parsed
/// against, so that `~/.gitconfig` in one layer and the absolute spelling in
/// another are one key rather than two. It is the same `home` [`state_dir`]
/// takes, so a caller that found the state directory already holds it.
///
/// # Errors
///
/// Whatever [`layer_paths`] and [`super::load_layer`] return.
pub fn load_layer_set(repo: &Path, state_dir: &Path, home: &Path) -> Result<Vec<Layer>, Error> {
    let local = local_layer_path(state_dir);

    layer_paths(repo, state_dir)?
        .iter()
        .map(|path| {
            let mut layer = load_layer(path, home)?;
            if *path == local {
                layer.kind = LayerKind::Local;
            }
            Ok(layer)
        })
        .collect()
}

/// A `local.toml` sitting inside the config repo, if there is one.
///
/// The config repo is a git working tree meant to be published, and this file
/// holds the one kind of content that must never be committed. It is never
/// loaded; `bx doctor` reports it and names the move to the state directory.
///
/// Both the repo root and `modules/` are checked, because either would be
/// picked up by a `git add .`.
///
/// Each place is examined the way [`super::layer_files`] examines it, so the two
/// agree about what is there: a repo root that is absent, lies beneath a
/// non-directory, or is not a directory holds no stray, and neither does a
/// `modules/` that is absent or not a directory; a `local.toml` that is absent
/// or not a regular file is not one. Anything that cannot be examined, such as a dangling
/// symlink, `EACCES` or `ELOOP`, is an error rather than `None`, because `None`
/// tells `bx doctor` the repo is clean.
///
/// # Errors
///
/// [`Error::Io`] naming the path that could not be examined.
pub fn stray_local(repo: &Path) -> Result<Option<PathBuf>, Error> {
    if !super::examine_root(repo)?.is_some_and(|meta| meta.is_dir()) {
        return Ok(None);
    }
    let root = repo.join(LOCAL_FILE);
    if super::examine(&root)?.is_some_and(|meta| meta.is_file()) {
        return Ok(Some(root));
    }
    let modules = repo.join(super::MODULES_DIR);
    if !super::examine(&modules)?.is_some_and(|meta| meta.is_dir()) {
        return Ok(None);
    }
    let nested = modules.join(LOCAL_FILE);
    Ok(super::examine(&nested)?
        .is_some_and(|meta| meta.is_file())
        .then_some(nested))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::guarded_home;

    /// A repo root and a state directory under a guarded home.
    fn repo_and_state(home: &crate::testing::GuardedHome) -> (PathBuf, PathBuf) {
        (home.child(".config/bx"), home.child(".local/state/bx"))
    }

    #[test]
    fn state_dir_defaults_to_local_state_bx() {
        assert_eq!(
            state_dir(Path::new("/var/home/example"), None),
            Path::new("/var/home/example/.local/state/bx")
        );
    }

    #[test]
    fn state_dir_honours_xdg_state_home() {
        assert_eq!(
            state_dir(
                Path::new("/var/home/example"),
                Some(OsStr::new("/var/mnt/scratch/one/state"))
            ),
            Path::new("/var/mnt/scratch/one/state/bx")
        );
    }

    #[test]
    fn a_relative_or_empty_xdg_state_home_falls_back() {
        // The base-directory specification honours the variable only when it is
        // non-empty and absolute; anything else is invalid and the default wins.
        let home = Path::new("/var/home/example");
        let default = home.join(".local/state/bx");

        assert_eq!(state_dir(home, Some(OsStr::new(""))), default);
        assert_eq!(state_dir(home, Some(OsStr::new("relative/state"))), default);
    }

    #[test]
    fn the_layer_order_is_bx_then_modules_then_local() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        home.write(".config/bx/modules/20-git.toml", "");
        home.write(".config/bx/modules/10-shell.toml", "");
        home.write(".local/state/bx/local.toml", "");

        let names: Vec<String> = layer_paths(&repo, &state)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            names,
            ["bx.toml", "10-shell.toml", "20-git.toml", "local.toml"],
            "the account always has the last word, which is the point"
        );
    }

    #[test]
    fn a_missing_local_layer_is_not_an_error() {
        // An account that has answered nothing is a real state.
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");

        let paths = layer_paths(&repo, &state).unwrap();

        assert_eq!(paths.len(), 1);
        assert!(!state.join(LOCAL_FILE).exists());
    }

    #[test]
    fn local_toml_in_the_repo_is_never_loaded() {
        // Merging account content out of a publishable git tree is the hole
        // Invariant 5 exists to close.
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        home.write(".config/bx/local.toml", "[values]\nscratch_root = \"/x\"\n");
        home.write(
            ".config/bx/modules/local.toml",
            "[values]\nscratch_root = \"/y\"\n",
        );

        let paths = layer_paths(&repo, &state).unwrap();

        assert_eq!(
            paths,
            [repo.join("bx.toml")],
            "neither the root nor the modules copy is a layer"
        );
    }

    /// A state directory inside the repo is refused, naming both, never loaded.
    ///
    /// With `XDG_STATE_HOME` equal to `XDG_CONFIG_HOME` the state directory *is*
    /// the repo. `layer_paths` used to push `repo/local.toml` back in as the
    /// local layer after filtering it out of the globals, so account answers
    /// were merged out of the publishable tree while `stray_local` reported the
    /// same file as a stray.
    #[test]
    fn a_state_directory_inside_the_repo_is_refused_naming_both() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        let config_home = home.child(".config");
        let state = state_dir(home.path(), Some(config_home.as_os_str()));
        assert_eq!(state, repo, "the configuration this case is about");
        home.write(".config/bx/bx.toml", "");
        let local = home.write(".config/bx/local.toml", "[values]\nscratch_root = \"/x\"\n");

        let message = layer_paths(&repo, &state)
            .expect_err("a local layer inside the repo is not loaded")
            .to_string();
        assert!(message.contains(&local.display().to_string()), "{message}");
        assert!(
            message.contains(&format!("inside the config repo {}", repo.display())),
            "{message}"
        );
        load_layer_set(&repo, &state, home.path()).expect_err("nor through the loader");
        assert_eq!(
            stray_local(&repo).unwrap(),
            Some(local),
            "and doctor still names it"
        );

        // Refused before anything is written there: the first `bx init` would
        // otherwise put this account's answers into the publishable tree.
        std::fs::remove_file(repo.join(LOCAL_FILE)).expect("rm");
        layer_paths(&repo, &state).expect_err("refused with no local.toml yet");
        layer_paths(&repo, &repo.join("modules")).expect_err("anywhere under the repo");
        layer_paths(&repo, &home.child(".config/elsewhere/../bx"))
            .expect_err("however the state directory is spelled");
    }

    /// Guards against over-reach: a sibling that shares the repo's name prefix
    /// is not inside it.
    #[test]
    fn a_state_directory_beside_the_repo_is_not_inside_it() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        let local = home.write(".config/bx-state/local.toml", "");

        assert_eq!(
            layer_paths(&repo, &home.child(".config/bx-state")).unwrap(),
            [repo.join("bx.toml"), local]
        );
    }

    /// The limit of the lexical check, pinned. `alias` is the repo under
    /// another spelling, so `alias/state` is inside it on disk but not as
    /// written, and it is accepted. Resolving symlinks here is a deliberate
    /// change to this test, not a quiet change of behaviour; the module
    /// documentation states the rule and this limit under *Inside the repo is
    /// decided lexically, not on disk*.
    #[test]
    fn a_state_directory_reached_through_a_symlinked_alias_of_the_repo_is_not_refused() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        let alias = home.child("alias");
        std::os::unix::fs::symlink(&repo, &alias).expect("symlink");
        assert_eq!(
            alias.canonicalize().expect("the alias resolves"),
            repo.canonicalize().expect("the repo resolves"),
            "the fixture must really be one directory under two spellings"
        );
        home.write(".config/bx/state/local.toml", "");

        let paths = layer_paths(&repo, &alias.join("state"))
            .expect("not refused: the check compares spellings");

        assert_eq!(paths.last(), Some(&alias.join("state").join(LOCAL_FILE)));
    }

    #[test]
    fn stray_local_reports_a_local_toml_in_the_repo() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        let stray = home.write(".config/bx/local.toml", "");

        assert_eq!(stray_local(&repo).unwrap(), Some(stray));
    }

    #[test]
    fn stray_local_also_looks_inside_modules() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        let stray = home.write(".config/bx/modules/local.toml", "");

        assert_eq!(stray_local(&repo).unwrap(), Some(stray));
    }

    #[test]
    fn stray_local_is_silent_when_there_is_none() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        home.write(".local/state/bx/local.toml", "");

        assert_eq!(
            stray_local(&repo).unwrap(),
            None,
            "the state directory is its home"
        );
    }

    #[test]
    fn the_local_layer_is_the_only_one_marked_local() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        home.write(".config/bx/modules/10-shell.toml", "");
        home.write(".local/state/bx/local.toml", "");

        let kinds: Vec<LayerKind> = load_layer_set(&repo, &state, home.path())
            .unwrap()
            .iter()
            .map(|layer| layer.kind)
            .collect();

        assert_eq!(
            kinds,
            [LayerKind::Global, LayerKind::Global, LayerKind::Local],
            "a committed layer has to be distinguishable, because only it is \
             forbidden from carrying a [values] table"
        );
    }

    #[test]
    fn a_layer_set_carries_each_layer_s_own_contents() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(
            ".config/bx/bx.toml",
            "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n",
        );
        home.write(
            ".local/state/bx/local.toml",
            "[values]\nscratch_root = \"/var/mnt/scratch/one\"\n",
        );

        let layers = load_layer_set(&repo, &state, home.path()).unwrap();

        assert_eq!(layers[0].config.values[0].name, "scratch_root");
        assert!(layers[0].config.value_assignments.is_empty());
        assert_eq!(layers[1].config.value_assignments[0].name, "scratch_root");
    }

    #[test]
    fn the_byte_sorted_later_module_wins_a_conflicting_key() {
        // End to end, off the disk, because the ordering property is only worth
        // anything if it survives the composition: `read_dir` order is the
        // filesystem's, and Invariant 3 admits none of it. `10-a.toml` sorts
        // *before* `9-a.toml` by raw filename bytes and after it numerically, so
        // this fails under either a numeric sort or a naive `read_dir` order.
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        home.write(
            ".config/bx/modules/9-a.toml",
            "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"from nine\"\n",
        );
        home.write(
            ".config/bx/modules/10-a.toml",
            "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"from ten\"\n",
        );

        let layers = load_layer_set(&repo, &state, home.path()).unwrap();
        let merged = crate::config::merge::merge(&layers, home.path()).unwrap();

        assert_eq!(merged.targets.len(), 1, "one key, one entry");
        assert_eq!(
            merged.targets[0].body,
            crate::config::target::Body::Inline("from nine".to_string()),
            "`9-a.toml` sorts after `10-a.toml` by raw filename bytes"
        );
        assert_eq!(
            merged.targets[0].origin.file.file_name().unwrap(),
            OsStr::new("9-a.toml"),
            "and the surviving entry says which layer set it"
        );
    }

    #[test]
    fn a_layer_set_is_parsed_against_the_home_it_is_given() {
        // The home threaded in is what every target path is parsed against, and
        // the reason it is threaded: a file under it has one spelling, so the
        // absolute spelling in a module is refused at load, naming the `~` one.
        // Parsed against any other home, the same line would load as a second
        // key for the file `bx.toml` already owns.
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(
            ".config/bx/bx.toml",
            "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"global\"\n",
        );
        let absolute = home.child(".gitconfig");
        home.write(
            ".config/bx/modules/10-git.toml",
            &format!(
                "[[target]]\npath = \"{}\"\ncontent = \"module\"\n",
                absolute.display()
            ),
        );

        let message = load_layer_set(&repo, &state, home.path())
            .expect_err("the absolute spelling of a file under the home is refused")
            .to_string();

        assert!(message.contains("10-git.toml"), "{message}");
        assert!(message.contains("~/.gitconfig"), "{message}");
    }

    #[test]
    fn a_missing_repo_is_an_error() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);

        let error = layer_paths(&repo, &state).expect_err("no repo at all");

        assert!(matches!(error, Error::RepoMissing(_)), "{error}");
    }

    // --- a local layer that cannot be examined ------------------------------

    /// The `Error::Io` `result` must be, naming `expected`; its source.
    fn io_error_naming<T: std::fmt::Debug>(
        result: Result<T, Error>,
        expected: &Path,
    ) -> std::io::Error {
        match result {
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

    /// A dangling `local.toml` is an error, not an account that answered nothing.
    ///
    /// Under `is_file()` this returned `Ok([bx.toml])`: the account's layer,
    /// with its values, its added targets and its `enabled = false` opt-outs,
    /// silently did not apply.
    #[test]
    fn a_dangling_local_layer_is_an_error_naming_it() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        std::fs::create_dir_all(&state).expect("mkdir");
        let local = local_layer_path(&state);
        std::os::unix::fs::symlink(state.join("nowhere.toml"), &local).expect("symlink");

        let source = io_error_naming(layer_paths(&repo, &state), &local);
        assert!(source.to_string().contains("dangling"), "{source}");
        io_error_naming(load_layer_set(&repo, &state, home.path()), &local);
    }

    /// A `local.toml` that links to itself is an error carrying `ELOOP`.
    #[test]
    fn a_local_layer_symlink_loop_is_an_error_naming_it() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        std::fs::create_dir_all(&state).expect("mkdir");
        let local = local_layer_path(&state);
        std::os::unix::fs::symlink(&local, &local).expect("a symlink to itself");

        let source = io_error_naming(layer_paths(&repo, &state), &local);
        assert_ne!(source.kind(), std::io::ErrorKind::NotFound, "{source}");
        assert!(!source.to_string().contains("dangling"), "{source}");
    }

    /// A state directory that can be listed but not searched is an error.
    ///
    /// At mode 0644 every `stat` inside fails with `EACCES`, which `is_file()`
    /// read as "no local layer".
    #[test]
    fn a_state_directory_that_cannot_be_searched_is_an_error_naming_the_local_layer() {
        use std::os::unix::fs::PermissionsExt;

        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        let local = home.write(".local/state/bx/local.toml", "");
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 644");

        // A process that can stat inside an unsearchable directory -- root, or
        // one holding CAP_DAC_READ_SEARCH -- cannot construct this case.
        let constructible = std::fs::metadata(&local).is_err();
        let result = layer_paths(&repo, &state);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755))
            .expect("restore, so the tempdir can be removed");

        if !constructible {
            eprintln!(
                "skipped: this process can stat inside a 0644 directory, so EACCES cannot be \
                 constructed here"
            );
            return;
        }
        let source = io_error_naming(result, &local);
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// A state directory that is a regular file is an error naming `local.toml`.
    ///
    /// The state directory is not a layer candidate that may be of the wrong
    /// kind; it is where the account's layer has to be, so `ENOTDIR` is not a
    /// clean absence.
    #[test]
    fn a_state_directory_that_is_a_file_is_an_error_naming_the_local_layer() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        home.write(".local/state/bx", "not a directory");

        io_error_naming(layer_paths(&repo, &state), &local_layer_path(&state));
    }

    /// Guards against over-reach: a clean answer still skips or loads.
    ///
    /// A directory named `local.toml` is not a layer, exactly as a directory
    /// named `x.toml` in `modules/` is not; a `local.toml` symlinked to a
    /// regular file is the account's layer.
    #[test]
    fn a_local_layer_of_the_wrong_kind_is_skipped_and_a_linked_one_is_loaded() {
        let home = guarded_home();
        let (repo, state) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        let local = local_layer_path(&state);
        std::fs::create_dir_all(&local).expect("a directory named local.toml");

        assert_eq!(layer_paths(&repo, &state).unwrap(), [repo.join("bx.toml")]);

        std::fs::remove_dir(&local).expect("rmdir");
        let real = home.write("elsewhere/local.toml", "[values]\n");
        std::os::unix::fs::symlink(&real, &local).expect("symlink");

        assert_eq!(
            layer_paths(&repo, &state).unwrap(),
            [repo.join("bx.toml"), local]
        );
    }

    /// `stray_local` does not answer "clean" about a path it could not examine.
    ///
    /// Under `is_file()` a dangling `local.toml` symlink in the repo, at the
    /// root or under `modules/`, was `None`: `bx doctor` would report a clean
    /// repo while a commit of the whole tree picked up the link.
    #[test]
    fn stray_local_on_a_dangling_symlink_is_an_error_naming_it() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config/bx/modules/10-a.toml", "");

        let nested = repo.join("modules").join(LOCAL_FILE);
        std::os::unix::fs::symlink(repo.join("nowhere.toml"), &nested).expect("symlink");
        let source = io_error_naming(stray_local(&repo), &nested);
        assert!(source.to_string().contains("dangling"), "{source}");

        let root = repo.join(LOCAL_FILE);
        std::os::unix::fs::symlink(&root, &root).expect("a symlink to itself");
        let source = io_error_naming(stray_local(&repo), &root);
        assert_ne!(source.kind(), std::io::ErrorKind::NotFound, "{source}");
    }

    /// Guards against over-reach: `stray_local` skips what `layer_files` skips.
    ///
    /// No repo, a repo that is a file, a `modules` that is a file, and a
    /// directory named `local.toml` are each a clean `None`, not an `ENOTDIR`.
    #[test]
    fn stray_local_skips_what_is_cleanly_not_a_stray() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);

        assert_eq!(stray_local(&repo).unwrap(), None, "no repo");

        home.write(".config/bx", "a file, not a repo");
        assert_eq!(stray_local(&repo).unwrap(), None, "a repo that is a file");

        std::fs::remove_file(&repo).expect("rm");
        home.write(".config/bx/modules", "a file, not a directory");
        std::fs::create_dir(repo.join(LOCAL_FILE)).expect("a directory named local.toml");
        assert_eq!(stray_local(&repo).unwrap(), None, "wrong kinds throughout");
    }

    /// A repo root beneath a regular file holds no stray, as `layer_files` agrees.
    ///
    /// `lstat` there says `ENOTDIR`, which was an io error while `layer_files`
    /// is to call the same root missing.
    #[test]
    fn stray_local_beneath_a_regular_file_is_none() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config", "a file, not a directory");

        assert_eq!(stray_local(&repo).unwrap(), None);
        assert!(matches!(
            super::super::layer_files(&repo),
            Err(Error::RepoMissing(ref p)) if *p == repo
        ));
    }
}
