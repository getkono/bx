//! What a run decides against: the configuration, the places it was loaded
//! from, and the machine it runs on, loaded once by [`Inputs::load`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::Error;
use crate::config::external::{External, Pin};
use crate::config::layers;
use crate::config::lock::Lock;
use crate::config::merge;
use crate::config::resolve::{self, Resolution, Resolved};
use crate::config::target::Target;
use crate::config::when::{Facts, Machine};
use crate::config::{Layer, LayerKind};
use crate::env::Env;
use crate::env_guard::RootSet;
use crate::git::Git;
use crate::paths::{self, Portable};
use crate::shell::activation::{self, Host as _};
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
    /// The machine an activation's tool and a `has:TOOL` condition's tool
    /// are looked up on, and whose facts every other condition bx decides is
    /// decided against.
    pub(super) host: activation::System,
    /// `bx.lock`: the commit each followed external is kept at.
    pub(super) lock: Lock,
    /// Every external the committed layers declare without this account's
    /// `local.toml`, on any machine: those enabled where they merge on this
    /// one, then every one a `when` keeps to other machines, as declared
    /// ([`layers::gated_externals`]). `None` when the committed layers
    /// cannot be merged alone on this machine.
    pub(super) committed_externals: Option<Vec<External>>,
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
        // The machine's facts are read here, once, so every condition on
        // them in this run is decided against the same answers.
        let host = activation::System::from_env().with_machine(Machine::read(env.user.clone()));
        Self::load_on(env, host)
    }

    /// [`Inputs::load`], on `host`: the machine every condition bx decides —
    /// a declaration's or a module's `when` as the layers load, and a
    /// generated line's as `plan` renders it — is decided against, and an
    /// activation's tool runs on.
    ///
    /// # Errors
    ///
    /// As [`Inputs::load`].
    pub fn load_on(env: &Env, host: activation::System) -> Result<Self, Error> {
        let home = env.home.clone();
        let repo = paths::config_root_in(&home, env.xdg_config_home.as_deref());
        let state = StateDir::resolve_in(&home, env.xdg_state_home.as_deref());
        let present = |tool: &str| host.locate(tool).is_usable();
        let facts = Facts {
            machine: host.machine(),
            present: &present,
        };
        // What a `when` keeps off this machine is left out before anything
        // merges, so it neither replaces nor collides with what stays.
        let layers::Gated { layers, elsewhere } =
            layers::load_gated(&repo, state.root(), &home, &facts)?;
        // What every machine sharing the config repo declares: the layers
        // `bx.lock` is committed beside, without this account's own. What a
        // `when` keeps to other machines (`elsewhere`) is never merged: two
        // such declarations may only clash where both hold, which no machine
        // reaches, so it is taken as declared beside what this machine
        // merges, and a follow gated to another machine keeps its commit.
        let committed: Vec<Layer> = layers
            .iter()
            .filter(|layer| layer.kind == LayerKind::Global)
            .cloned()
            .collect();
        let merged = merge::merge(&layers, &home)?;
        let committed_externals = merge::merge(&committed, &home).ok().map(|config| {
            let mut externals = config.externals;
            externals.extend(elsewhere);
            externals
        });
        let resolved = resolve::resolve(&merged, &home, crate::shell::placement::place)?;
        let lock = Lock::read(&repo, &home)?;
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
            host,
            lock,
            committed_externals,
        })
    }

    /// `bx.lock`, as this run read it.
    #[must_use]
    pub const fn lock(&self) -> &Lock {
        &self.lock
    }

    /// Every external the committed layers declare on their own, without
    /// this account's `local.toml`, on this machine or another: what the
    /// shared `bx.lock` is kept for. `None` when those layers cannot be
    /// merged without it.
    #[must_use]
    pub fn committed_externals(&self) -> Option<&[External]> {
        self.committed_externals.as_deref()
    }

    /// The same inputs, keeping followed externals at the commits `lock`
    /// holds rather than the file's: what `bx update` plans against before
    /// it writes the lock it proposes.
    #[must_use]
    pub fn with_lock(mut self, lock: Lock) -> Self {
        self.lock = lock;
        self
    }

    /// The same inputs, keeping each pinned external `pins` names at the
    /// commit it gives rather than the `rev` its layer holds: what
    /// `bx upgrade` plans against before it rewrites those layers.
    #[must_use]
    pub fn with_pins(mut self, pins: &BTreeMap<Portable, String>) -> Self {
        for external in &mut self.resolved.externals {
            if let (Pin::Rev(rev), Some(pin)) = (&mut external.pin, pins.get(&external.path)) {
                rev.clone_from(pin);
            }
        }
        self
    }

    /// The same inputs, looking at externals through `git`.
    #[cfg(test)]
    pub(crate) fn with_git(mut self, git: Git) -> Self {
        self.git = git;
        self
    }

    /// The same inputs, running activations on `host` and deciding every
    /// condition against its tools and facts.
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

    #[test]
    fn a_gated_target_and_module_come_and_go_with_the_machine_the_inputs_carry() {
        use crate::config::when::Distro;
        use crate::paths::Portable;
        use crate::plan::tests::{apply, inline, plan};
        use crate::report::Action;

        let home = guarded_home();
        home.write(".gitconfig.local", "mine\n");
        seed(
            home.path(),
            &format!(
                "{}when = [\"host:box\", \"distro:rhel\"]\n",
                inline("~/.boxed", "b\\n")
            ),
        );
        home.write(
            ".config/bx/modules/macos.toml",
            &format!("when = \"os:macos\"\n{}", inline("~/.mac", "m\\n")),
        );
        let on = |os: &str, host: &str| {
            let machine = Machine {
                os: os.to_string(),
                arch: "aarch64".to_string(),
                host: Some(host.to_string()),
                user: None,
                distro: Some(Distro {
                    id: "fedora".to_string(),
                    id_like: vec!["rhel".to_string()],
                }),
            };
            Inputs::load_on(
                &env(home.path()),
                activation::System::new("", activation::TIMEOUT).with_machine(machine),
            )
            .expect("the inputs load")
        };
        let declared = |inputs: &Inputs| -> Vec<String> {
            inputs
                .declared_targets()
                .map(|(target, _)| target.path.as_str().to_string())
                .collect()
        };
        let rows = |inputs: &Inputs| -> Vec<(String, Action)> {
            let mut rows: Vec<_> = plan(inputs)
                .changes
                .iter()
                .filter(|change| ["~/.boxed", "~/.mac"].contains(&change.target.as_str()))
                .map(|change| (change.target.to_string(), change.action))
                .collect();
            rows.sort();
            rows
        };

        // Neither condition holds: nothing is declared, and nothing planned.
        let neither = on("linux", "other");
        assert!(declared(&neither).is_empty());
        assert!(rows(&neither).is_empty());

        // Both hold: both arrive, and a second plan is empty.
        let both = on("macos", "BOX");
        assert_eq!(declared(&both), ["~/.boxed", "~/.mac"]);
        apply(&both);
        assert_eq!(
            std::fs::read_to_string(home.child(".mac")).expect("written"),
            "m\n"
        );
        assert!(
            plan(&both)
                .actions()
                .iter()
                .all(|action| *action == Action::Unchanged),
            "{:?}",
            plan(&both).actions()
        );
        let written = std::fs::read(home.child(".boxed")).expect("written");
        apply(&both);
        assert_eq!(std::fs::read(home.child(".boxed")).expect("kept"), written);

        // Off macOS the module's target is no longer declared, exactly as an
        // `enabled = false` one is, and nothing is written for it.
        let linux = on("linux", "box");
        assert_eq!(declared(&linux), ["~/.boxed"]);
        assert_eq!(
            rows(&linux),
            [
                ("~/.boxed".to_string(), Action::Unchanged),
                ("~/.mac".to_string(), Action::Undeclared),
            ]
        );
        assert!(!apply(&linux).executed);
        assert!(home.child(".mac").exists());

        // `bx rm` then puts back what was there before: nothing.
        let state = StateDir::resolve(home.path());
        let mac = Portable::parse_in("~/.mac", home.path()).expect("a portable path");
        crate::restore::restore(&state, home.path(), &[mac]).expect("rm");
        assert!(!home.child(".mac").exists());
        assert_eq!(rows(&linux), [("~/.boxed".to_string(), Action::Unchanged)]);
        assert_eq!(
            std::fs::read_to_string(home.child(".gitconfig.local")).expect("untouched"),
            "mine\n"
        );
    }

    #[test]
    fn the_shared_lock_keeps_what_any_machine_follows_and_nothing_only_this_account_does() {
        use crate::config::lock::{Unshared, why_unshared_at};
        use crate::paths::Portable;
        use crate::update::kept;

        let home = guarded_home();
        let follow = |path: &str, url: &str| {
            format!(
                "[[external]]\npath = \"{path}\"\nurl = \"https://h/o/{url}\"\nbranch = \"main\"\n"
            )
        };
        let terminal = |name: &str| {
            format!("[[plugin]]\nname = \"{name}\"\nsource = \"~/{name}.zsh\"\nterminal = true\n")
        };
        // A follow outside any module whose own `when` holds on macOS only.
        seed(
            home.path(),
            &format!(
                "{}{}when = \"os:macos\"\n",
                follow("~/shared", "shared"),
                follow("~/mac-entry", "mac-entry")
            ),
        );
        // One terminal plugin per OS module, which clash only where both
        // hold, and a macOS override of `bx.toml`'s follow.
        home.write(
            ".config/bx/modules/macos.toml",
            &format!(
                "when = \"os:macos\"\n{}{}{}",
                terminal("mac"),
                follow("~/shared", "mac-shared"),
                follow("~/mac-only", "mac-only")
            ),
        );
        home.write(
            ".config/bx/modules/linux.toml",
            &format!("when = \"os:linux\"\n{}", terminal("tux")),
        );
        home.write(".local/state/bx/local.toml", &follow("~/mine", "mine"));
        let on = |os: &str| {
            let machine = Machine {
                os: os.to_string(),
                arch: "aarch64".to_string(),
                host: None,
                user: None,
                distro: None,
            };
            Inputs::load_on(
                &env(home.path()),
                activation::System::new("", activation::TIMEOUT).with_machine(machine),
            )
            .expect("the inputs load")
        };
        let at = |raw: &str| Portable::parse_in(raw, home.path()).expect("a portable path");
        let why = |inputs: &Inputs, path: &str, url: &str| {
            let committed = inputs
                .committed_externals()
                .expect("the committed layers merge on every machine");
            why_unshared_at(
                &at(path),
                &format!("https://h/o/{url}"),
                "main",
                Some(committed),
            )
        };

        let linux = on("linux");
        let committed = linux.committed_externals().expect("known");
        // A follow gated to macOS keeps its commit when `bx update` runs on
        // Linux, and `bx.toml`'s follow, which the macOS module overrides
        // only where it holds, is locked here.
        assert!(kept(&at("~/mac-only"), &[], Some(committed)));
        assert_eq!(why(&linux, "~/mac-only", "mac-only"), None);
        assert_eq!(why(&linux, "~/shared", "shared"), None);
        // So does a follow whose own `when` excludes it outside a module.
        assert!(kept(&at("~/mac-entry"), &[], Some(committed)));
        assert_eq!(why(&linux, "~/mac-entry", "mac-entry"), None);
        // What only this account's `local.toml` follows stays out of the
        // shared lock, and a path nothing commits is pruned from it.
        assert_eq!(why(&linux, "~/mine", "mine"), Some(Unshared::NotCommitted));
        assert!(!kept(&at("~/mine"), &[], Some(committed)));

        let macos = on("macos");
        assert_eq!(why(&macos, "~/shared", "mac-shared"), None);
        assert_eq!(why(&macos, "~/mac-only", "mac-only"), None);
        assert_eq!(why(&macos, "~/mac-entry", "mac-entry"), None);
        assert_eq!(why(&macos, "~/mine", "mine"), Some(Unshared::NotCommitted));
    }
}
