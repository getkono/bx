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
//! reported by [`stray_local`] so `bx doctor` can name the move.
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
/// # Errors
///
/// Whatever [`super::layer_files`] returns.
pub fn layer_paths(repo: &Path, state_dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut paths: Vec<PathBuf> = super::layer_files(repo)?
        .into_iter()
        .filter(|path| path.file_name() != Some(OsStr::new(LOCAL_FILE)))
        .collect();

    let local = local_layer_path(state_dir);
    if local.is_file() {
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
#[must_use]
pub fn stray_local(repo: &Path) -> Option<PathBuf> {
    [repo.join(LOCAL_FILE), repo.join("modules").join(LOCAL_FILE)]
        .into_iter()
        .find(|candidate| candidate.is_file())
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

    #[test]
    fn stray_local_reports_a_local_toml_in_the_repo() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        let stray = home.write(".config/bx/local.toml", "");

        assert_eq!(stray_local(&repo), Some(stray));
    }

    #[test]
    fn stray_local_also_looks_inside_modules() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        let stray = home.write(".config/bx/modules/local.toml", "");

        assert_eq!(stray_local(&repo), Some(stray));
    }

    #[test]
    fn stray_local_is_silent_when_there_is_none() {
        let home = guarded_home();
        let (repo, _) = repo_and_state(&home);
        home.write(".config/bx/bx.toml", "");
        home.write(".local/state/bx/local.toml", "");

        assert_eq!(stray_local(&repo), None, "the state directory is its home");
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
        let merged = crate::config::merge::merge(&layers).unwrap();

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
}
