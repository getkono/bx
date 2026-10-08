//! What a run decides against: the configuration, the places it was loaded
//! from, and the machine it runs on, loaded once by [`Inputs::load`].

use std::path::{Path, PathBuf};

use super::Error;
use crate::config::layers;
use crate::config::merge;
use crate::config::resolve::{self, Resolution, Resolved};
use crate::config::target::Target;
use crate::env::Env;
use crate::env_guard::RootSet;
use crate::git::Git;
use crate::paths;
use crate::shell::activation;
use crate::state::StateDir;

/// What a run decides against, loaded once.
///
/// Its fields are the `plan` module's to read, and no other module's.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub(super) home: PathBuf,
    pub(super) repo: PathBuf,
    pub(super) state: StateDir,
    /// Every enabled target as the merged layers wrote it, before substitution:
    /// one per entry of `resolved.targets`, in the same order, so a blocked
    /// target's body is still known.
    pub(super) declared: Vec<Target>,
    pub(super) resolved: Resolved,
    pub(super) roots: RootSet,
    pub(super) progress: bool,
    /// The `git` a declared external is looked at and moved with: the user's
    /// own, seeing the home and config home this run resolved, and unable to
    /// ask anything.
    pub(super) git: Git,
    /// Every enabled `[[activation]]`, in the merged configuration's order.
    pub(super) activations: Vec<activation::ActivationDecl>,
    /// The machine an activation's tool is looked up and run on.
    pub(super) host: activation::System,
}

impl Inputs {
    /// Locate the config repo and the state directory, and load, merge and
    /// resolve the layer set.
    ///
    /// Reads configuration files only; nothing is created.
    ///
    /// # Errors
    ///
    /// [`Error::RepoMissing`] when there is no config repo, and
    /// [`Error::Config`] for anything else the configuration refuses.
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
            declared: merged.targets,
            resolved,
            roots,
            progress: env.stderr_tty,
            git: Git::new(env).unattended(),
            activations: merged.activations,
            host: activation::System::from_env(),
        })
    }

    /// The same inputs, looking at externals through `git`.
    #[cfg(test)]
    pub(crate) fn with_git(mut self, git: Git) -> Self {
        self.git = git;
        self
    }

    /// The same inputs, running activations on `host`.
    #[cfg(test)]
    pub(crate) fn with_host(mut self, host: activation::System) -> Self {
        self.host = host;
        self
    }

    /// The resolved configuration.
    #[must_use]
    pub const fn resolved(&self) -> &Resolved {
        &self.resolved
    }

    /// Every enabled target as written, paired with its resolution, in
    /// configuration order.
    pub fn declared_targets(&self) -> impl Iterator<Item = (&Target, &Resolution<Target>)> {
        self.declared.iter().zip(&self.resolved.targets)
    }

    /// The account's home.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The config repo.
    #[must_use]
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// The state directory.
    #[must_use]
    pub const fn state(&self) -> &StateDir {
        &self.state
    }

    /// Every enabled target, ready or held back, in configuration order — the
    /// list `plan` decides, for a read-only command that looks at the same
    /// targets without deciding them.
    #[must_use]
    pub fn targets(&self) -> &[Resolution<Target>] {
        &self.resolved.targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::decide;
    use crate::plan::tests::{env, inputs, seed};
    use crate::testing::guarded_home;

    #[test]
    fn a_missing_config_repo_says_to_run_bx_init() {
        let home = guarded_home();

        let error = Inputs::load(&env(home.path())).expect_err("no repo");

        assert!(matches!(error, Error::RepoMissing(_)), "{error:?}");
        assert!(error.to_string().contains("run `bx init`"), "{error}");
    }

    #[test]
    fn a_malformed_layer_is_a_config_error_not_a_missing_repo() {
        // P42R1-COV3. Only a missing repo becomes `RepoMissing`; everything
        // else the configuration refuses stays the configuration's error.
        let home = guarded_home();
        seed(home.path(), "[[target]\npath = \n");

        let error = Inputs::load(&env(home.path())).expect_err("a malformed layer");

        assert!(matches!(error, Error::Config(_)), "{error:?}");
        assert!(!error.to_string().contains("run `bx init`"), "{error}");
    }

    #[test]
    fn the_inputs_name_the_places_they_were_loaded_from() {
        let home = guarded_home();
        let inputs = inputs(&home, "");

        assert_eq!(inputs.home(), home.path());
        assert_eq!(inputs.repo(), home.child(".config/bx"));
        assert_eq!(inputs.state(), &StateDir::resolve(home.path()));
        assert!(!inputs.progress);
    }

    #[test]
    fn a_repo_the_environment_moved_is_the_repo_a_generated_fragment_may_not_name() {
        // The env guard's r3 round gave `RootSet` the config repo, derived
        // from the home unless a caller that read `XDG_CONFIG_HOME` names it.
        // The whole home is a declared root, so only the repo refuses it.
        let home = guarded_home();
        let xdg = home.child("cfg");
        let repo = xdg.join("bx");
        std::fs::create_dir_all(&repo).expect("the moved repo");
        std::fs::write(
            repo.join("bx.toml"),
            "[[value]]\nname = \"all\"\nkind = \"path\"\nis_root = true\ndefault = \"~\"\n",
        )
        .expect("bx.toml");
        let inputs = Inputs::load(&Env {
            xdg_config_home: Some(xdg.into_os_string()),
            ..env(home.path())
        })
        .expect("the inputs load");
        assert_eq!(inputs.repo(), repo);

        let fragment = format!("CARGO_HOME={}\n", repo.join("cargo").display());
        let note = decide::guard_fragment(&fragment, &inputs.roots).expect("refused");
        let inside = crate::env_guard::Reason::InsideConfigRepo.to_string();
        assert!(note.contains(&inside), "{note}");
    }
}
