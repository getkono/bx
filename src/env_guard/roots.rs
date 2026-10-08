//! The roots a configuration declares, the directories bx owns, and the
//! lexical containment every verdict on a location is decided by.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use super::reason::Reason;
use crate::config::env;
use crate::config::values::ResolvedValues;
use crate::paths;

/// The roots a configuration declares as its own.
///
/// A relocation is judged against this set: a tool may be pointed at a
/// different directory exactly when that directory lies inside a root the user
/// declared. The set is a `Vec` in declaration order, not a `HashSet`, because
/// invariant 3 forbids any iteration order reaching generated output.
///
/// `home` is kept so that `~` and `$HOME` expand, and **not** as a permissive
/// root: relocating a tool inside `$HOME` is as invisible to a shell bx did not
/// initialise as relocating it anywhere else. A user who wants their home to be
/// a root declares a root whose value is `~`.
///
/// It also carries the directories **bx itself owns**, which are an exclusion
/// rather than a root: invariant 2's first sentence — never point a tool at a
/// bx-owned directory — is unconditional, so it holds even inside a declared
/// root and even when the declared root is the home. See [`RootSet::owns`].
/// And it carries bx's config repo, which bx does not own — it is the user's
/// committed tree — but which no tool may be pointed into either, for the same
/// unconditional reason. See [`RootSet::with_config_repos`].
///
/// Containment is decided **lexically**, never by touching the filesystem.
/// `canonicalize` would make the verdict depend on what exists and on what is
/// mounted, so the same `plan` would differ between two machines and between
/// two runs on one — which invariant 3 forbids. The price is that lexical `..`
/// normalisation is unsound across a symlink: `<root>/link/../x`, where `link`
/// points outside the root, is judged inside it, and so is a declared root that
/// is itself a symlink to `/`. That is accepted rather than fixed, because the
/// only fix is the one invariant 3 rules out — and a value bx may write never
/// has a `..` component at all ([`Reason::ParentComponent`]), so the unsound
/// case is left to the declared roots themselves.
///
/// Containment in a root is **one-directional**: a value inside a root is
/// admitted, whatever lies beneath it. A root contains itself, but a location
/// may not be a root itself ([`Reason::DeclaredRootItself`]), because its tool
/// may write beside it. bx's own directories are the exception,
/// and are judged **both ways**: a location may neither lie inside one nor
/// contain one ([`Reason::ContainsBxDirectory`]), because a tool clears its
/// own directory — `uv cache clean` on `UV_CACHE_DIR=~/.local/state` deletes
/// bx's ledger with it.
///
/// bx's fragment directory, [`env::FRAGMENT_DIR`], is judged **one way**: no
/// location may lie inside it ([`Reason::BxOwnedDirectory`]), but one may
/// contain it. `XDG_DATA_HOME=~/.local/share` is that directory's native
/// default, and refusing it would refuse the native location invariant 2
/// protects. What a tool clearing it would delete is only generated output,
/// which the next `apply` writes again from the configuration; the ledger,
/// which nothing can regenerate, stays judged both ways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSet {
    home: Option<PathBuf>,
    roots: Vec<PathBuf>,
    inadmissible: Vec<PathBuf>,
    owned: Vec<PathBuf>,
    fragment_dirs: Vec<PathBuf>,
    repos: Vec<PathBuf>,
}

impl RootSet {
    /// The set that declares nothing, and therefore permits no relocation.
    ///
    /// This is what [`scan`](super::scan) uses, and it needs no home: with no root declared
    /// every location is a violation before it is compared with anything. A
    /// program, a search list or a socket needs no root, and without a home
    /// the set cannot say where bx's state directory is — so it owns every
    /// directory that could be it. See [`RootSet::owns`].
    #[must_use]
    pub fn strict() -> Self {
        Self {
            home: None,
            roots: Vec::new(),
            inadmissible: Vec::new(),
            owned: Vec::new(),
            fragment_dirs: Vec::new(),
            repos: Vec::new(),
        }
    }

    /// A set of declared roots, resolved against `home`.
    ///
    /// Each root is `~`-expanded with [`paths::render`] and lexically
    /// normalised with [`paths::normalize`], so that a root and a value being
    /// compared have been through the same rules.
    ///
    /// A root that does not clear [`admissible_root`] is **not honoured**. It is
    /// kept, as declared, in [`RootSet::inadmissible`], logged at error level,
    /// and it changes the verdict: a set left with no admissible root refuses
    /// every relocation as [`Reason::InadmissibleRoot`], never as
    /// [`Reason::NoRootsDeclared`] — a user whose configuration visibly declares
    /// a root must not be told that none is declared.
    #[must_use]
    pub fn new(home: &Path, roots: &[PathBuf]) -> Self {
        let home = paths::normalize(home);
        let mut admitted = Vec::new();
        let mut inadmissible = Vec::new();
        for declared in roots {
            let root = paths::normalize(&paths::render(&declared.to_string_lossy(), &home));
            if admissible_root(declared, &root) {
                admitted.push(root);
            } else {
                inadmissible.push(declared.clone());
            }
        }
        let owned = vec![paths::normalize(&paths::state_dir(&home, None))];
        let fragment_dirs = vec![paths::normalize(&paths::render(env::FRAGMENT_DIR, &home))];
        let repos = vec![paths::normalize(&paths::config_root_in(&home, None))];
        Self {
            home: Some(home),
            roots: admitted,
            inadmissible,
            owned,
            fragment_dirs,
            repos,
        }
    }

    /// The roots a resolved configuration declares.
    ///
    /// Every value declared `is_root = true` and actually answered, in
    /// declaration order, resolved against the same home the values themselves
    /// were resolved against. A declaration nobody filled in contributes no
    /// root, and `is_root` is validated at load to imply `kind = "path"`, so
    /// there is nothing to filter here.
    ///
    /// The home travels inside the values rather than being read from the
    /// environment, which is what keeps the guard's verdict a pure function of
    /// the configuration (invariant 3).
    #[must_use]
    pub fn from_values(values: &ResolvedValues) -> Self {
        Self::new(values.home(), &values.roots())
    }

    /// The same set, additionally owning `dirs`.
    ///
    /// [`RootSet::new`] derives bx's state directory from the home, which is
    /// where it is unless `XDG_STATE_HOME` is set — and nothing on a pure
    /// resolution path may read the environment (invariant 3), so a caller that
    /// *has* read it passes the directory it found here. Adding, never
    /// replacing: the home-derived directory stays owned, because a fragment
    /// pointing at it is wrong on any machine where that override is absent.
    #[must_use]
    pub fn owning(mut self, dirs: &[PathBuf]) -> Self {
        self.owned
            .extend(dirs.iter().map(|dir| paths::normalize(dir)));
        self
    }

    /// The same set, additionally treating each of `dirs` as bx's config repo.
    ///
    /// The twin of [`RootSet::owning`]: [`RootSet::new`] puts the repo where
    /// the home puts it, `~/.config/bx`, and a caller that has read an
    /// environment's `XDG_CONFIG_HOME` passes the repo it found here. Adding,
    /// never replacing.
    #[must_use]
    pub fn with_config_repos(mut self, dirs: &[PathBuf]) -> Self {
        self.repos
            .extend(dirs.iter().map(|dir| paths::normalize(dir)));
        self
    }

    /// Whether `path` is bx's config repo, or lies inside it.
    ///
    /// The repo is committed, and safe to make public: a tool that writes
    /// there may commit what it writes, credentials included (invariant 5),
    /// and a program or a search-list entry there runs whatever was committed.
    /// A set without a home treats every `.config/bx` as a repo, as
    /// [`RootSet::owns`] does every default state directory.
    pub(super) fn in_config_repo(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.repos.iter().any(|dir| normalised.starts_with(dir))
            || (self.home.is_none() && passes_through(&normalised, &[".config", "bx"]))
    }

    /// Whether `path` contains, or is, a directory bx owns or a config repo.
    ///
    /// [`RootSet::owns`] and [`RootSet::in_config_repo`] both fall back to a
    /// pattern for a set with no home, and this one deliberately does not.
    /// The asymmetry is in the question, not in the care taken: those two ask
    /// whether bx's directory is *in* the path, and `.local/state/bx` spells
    /// itself out there whoever's home it is; this asks whether one lies
    /// *under* the path, and under a path belonging to an unknown home one
    /// always might. A fallback would therefore have to answer `true` for
    /// every path a homeless set is shown, refusing all of them.
    ///
    /// Answering `false` instead is sound only because this is consulted from
    /// two places, and [`judge`](super::refuse::judge) reaches each only after
    /// [`RootSet::refuses_everything`] has refused a set with no admissible
    /// root: `refuses_entry_bx`, for a location or a list of them — once
    /// per `:`-entry through `refuses_entry_placement` and once for a
    /// location's whole value — and `refuses_anchor`, for an exported
    /// anchor. The only set without a home is [`RootSet::strict`], which
    /// declares none. A later kind given a containing check must not simply
    /// call this: unless it is judged behind the same refusal, under `scan` it
    /// would get no protection at all, and it needs its own answer to the
    /// question above.
    /// `a_set_with_no_home_is_never_asked_what_holds_bxs_directories` pins
    /// both halves.
    pub(super) fn holds_bx_directory(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.owned
            .iter()
            .chain(&self.repos)
            .any(|dir| dir.starts_with(&normalised))
    }

    /// Whether `path` is a directory bx owns, or lies inside one.
    ///
    /// bx's state directory holds the ledger, the fingerprints and the journal:
    /// the record that makes invariant 4 true. A tool pointed into it writes
    /// among those files, and `bx rm` would then restore a home by deleting a
    /// directory another tool believes is its own. So this is checked **before**
    /// containment and outranks it — a user may declare their home a root, and
    /// `CARGO_HOME=~/.local/state/bx` is still refused.
    ///
    /// A set without a home — [`RootSet::strict`] — cannot show that a path is
    /// *not* bx's state directory, whose default place is under the home. So it
    /// owns every path that passes through `.local/state/bx`, whoever's home
    /// that is. A set with a home knows where its state directory is, and owns
    /// only that and what [`RootSet::owning`] adds.
    ///
    /// bx's fragment directory, [`env::FRAGMENT_DIR`], is owned the same way —
    /// its own path under a home, `.local/share/bx` under any home for a set
    /// without one — since a tool pointed into it writes beside the fragments
    /// every shell sources. Unlike the state directory it is not consulted by
    /// [`RootSet::holds_bx_directory`]; see [`RootSet`].
    #[must_use]
    pub fn owns(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.owned
            .iter()
            .chain(&self.fragment_dirs)
            .any(|dir| normalised.starts_with(dir))
            || (self.home.is_none()
                && (passes_through(&normalised, &[".local", "state", "bx"])
                    || passes_through(&normalised, &[".local", "share", "bx"])))
    }

    /// Whether `path` lies inside some declared root.
    ///
    /// The comparison is component-wise, so `/scratch/examplefoo` is **not**
    /// inside `/scratch/example`, and it is lexical, so `<root>/../etc` is not
    /// inside `<root>` either. A relative path keeps its leading `..` through
    /// normalisation and can therefore never be inside an absolute root.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.roots.iter().any(|root| normalised.starts_with(root))
    }

    /// Whether no admissible root is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The declared roots that were refused, exactly as they were declared.
    ///
    /// A caller reporting a configuration prints these: they are the mistake a
    /// [`Reason::InadmissibleRoot`] verdict is about.
    #[must_use]
    pub fn inadmissible(&self) -> &[PathBuf] {
        &self.inadmissible
    }

    /// The home `~` and `$HOME` expand against, if this set has one.
    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// Why this set permits no relocation, if it permits none.
    pub(super) fn refuses_everything(&self) -> Option<Reason> {
        match (self.roots.is_empty(), self.inadmissible.is_empty()) {
            (false, _) => None,
            (true, true) => Some(Reason::NoRootsDeclared),
            (true, false) => Some(Reason::InadmissibleRoot),
        }
    }
}

/// Whether a normalised `path` has `parts` as consecutive components — so
/// `.local`, `state`, `bx` is the default state directory under some home.
fn passes_through(path: &Path, parts: &[&str]) -> bool {
    let wanted: Vec<Component<'_>> = parts
        .iter()
        .map(|part| Component::Normal(OsStr::new(part)))
        .collect();
    path.components()
        .collect::<Vec<_>>()
        .windows(wanted.len())
        .any(|window| window == wanted.as_slice())
}

/// Whether a declared root may widen the guard at all.
///
/// The floor under every root, whatever declared it. A root must be an absolute
/// path that names at least one directory, and must not climb.
///
/// The case this exists for is a root that normalises to `/`. Written as `/`,
/// as `/..`, or as `~/../../..`, it makes `starts_with` true for every absolute
/// path, so every tool may be relocated anywhere and every fragment scans clean
/// — the guard turns itself off and says nothing. A guard may fail loudly; it
/// may not fail open in silence.
///
/// This is the second floor, not the only one. The configuration layer refuses
/// an `is_root` answer that resolves to `/` — spelled `/`, `//`, `/./` or `/..`
/// — as `config::values::ValueError::RootIsFilesystem`, and refuses a
/// `~`-rooted climb such as `~/../../..` before it can resolve anywhere, so a
/// root read from `local.toml` reaches [`RootSet::new`] already normalised and
/// never trips this check. [`RootSet::new`] is public and takes any path,
/// though, so the guard does not rely on its caller: a root that reaches here
/// and fails the floor means something bypassed the configuration layer. That
/// is why a refused root is logged at error level — the level `bx` reports
/// with `BX_LOG` unset — and changes the verdict rather than only narrowing the
/// set.
///
/// `..` is rejected *before* normalisation as well, on the shape rather than
/// the result: a declared root that climbs is anomalous by construction, and
/// admitting one would mean admitting a root whose meaning changes across a
/// symlink.
fn admissible_root(declared: &Path, normalised: &Path) -> bool {
    let why = if declared
        .components()
        .any(|component| component == Component::ParentDir)
    {
        "it climbs out of itself"
    } else if !normalised.is_absolute() {
        "it is not an absolute path"
    } else if !normalised
        .components()
        .any(|component| matches!(component, Component::Normal(_)))
    {
        "it is the filesystem root itself"
    } else {
        return true;
    };
    tracing::error!(
        root = %declared.display(),
        "refusing a declared root, so nothing may be relocated into it: {why}"
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_guard::fixtures::*;
    use crate::env_guard::*;

    #[test]
    fn a_declared_root_contains_itself_and_a_location_may_still_not_be_one() {
        // The reflexivity issue #45 turns on, and the choice made about it.
        // `contains` stays reflexive: it answers "is this path inside a root",
        // and a root is. What changed is that the `Kind::Location` arm no
        // longer reads reflexive containment as approval — `refuses_entry_at_root`
        // asks separately whether the path's *parent* is inside a root, and a
        // root's parent is not. The alternative, making `contains` irreflexive,
        // would also move `refuses_anchor`, `refuses_program`, the search list
        // and the socket, none of which issue #45 is about.
        //
        // Both halves are asserted here, so this cannot be read as sanctioning
        // a location at a root.
        assert!(rooted().contains(Path::new(ROOT)));
        assert_eq!(
            reason_of(&check("CARGO_HOME", ROOT, &rooted())),
            Some(Reason::DeclaredRootItself)
        );
    }

    #[test]
    fn a_path_under_a_declared_root_is_inside() {
        assert!(rooted().contains(Path::new("/var/mnt/scratch/example/cache/cargo")));
    }

    #[test]
    fn a_sibling_whose_name_extends_the_root_is_outside() {
        // Containment is component-wise, not textual: `examplefoo` is a
        // different directory that merely shares a prefix of its name.
        assert!(!rooted().contains(Path::new("/var/mnt/scratch/examplefoo")));
        assert!(!rooted().contains(Path::new("/var/mnt/scratch/examplefoo/cargo")));
    }

    #[test]
    fn a_traversal_out_of_a_root_is_outside() {
        assert!(!rooted().contains(Path::new("/var/mnt/scratch/example/../etc")));
    }

    #[test]
    fn a_traversal_that_returns_inside_is_inside() {
        assert!(rooted().contains(Path::new("/var/mnt/scratch/example/a/../b")));
    }

    #[test]
    fn a_single_dot_component_is_ignored() {
        assert!(rooted().contains(Path::new("/var/mnt/scratch/example/./cache")));
    }

    #[test]
    fn traversal_cannot_escape_above_the_filesystem_root() {
        // `/..` is `/`, and `/` is not inside any declared root here.
        assert!(!rooted().contains(Path::new("/..")));
        assert!(!rooted().contains(Path::new("/../../..")));
    }

    #[test]
    fn a_root_that_normalises_to_the_filesystem_root_is_dropped() {
        // The one failure a guard may not have. `/` makes `starts_with` true
        // for every absolute path, so every tool could be relocated anywhere
        // and every fragment would still scan clean. The three spellings all
        // normalise to `/`; all three are refused, and the set admits nothing.
        for declared in ["/", "/..", "~/../../..", "/var/home/example/../../.."] {
            let roots = RootSet::new(Path::new(HOME), &[PathBuf::from(declared)]);
            assert!(roots.is_empty(), "{declared}");
            assert!(!roots.contains(Path::new("/etc")), "{declared}");
            assert_eq!(
                roots.inadmissible(),
                &[PathBuf::from(declared)],
                "{declared}"
            );
            assert_eq!(
                reason_of(&check("CARGO_HOME", "/etc", &roots)),
                Some(Reason::InadmissibleRoot),
                "{declared}"
            );
        }
    }

    #[test]
    fn a_declared_root_that_climbs_is_dropped_even_where_it_lands_somewhere_real() {
        // This one normalises to `/var/mnt/scratch`, a perfectly real
        // directory, and is still refused: a declared root that climbs is
        // anomalous by construction, and lexical `..` folding is the thing the
        // module accepts as unsound across a symlink.
        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from("/var/mnt/scratch/example/..")],
        );
        assert!(roots.is_empty());
        assert!(!roots.contains(Path::new("/var/mnt/scratch/other")));
    }

    #[test]
    fn a_relative_root_is_dropped() {
        // `RootSet::new` is public and no configuration layer stands in front
        // of it. A relative root can contain no absolute value, so keeping one
        // would only make `is_empty` say a root was declared when nothing
        // usable was.
        let roots = RootSet::new(Path::new(HOME), &[PathBuf::from("cache/cargo")]);
        assert!(roots.is_empty());
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/cargo",
                &roots
            )),
            Some(Reason::InadmissibleRoot)
        );
    }

    #[test]
    fn an_inadmissible_root_does_not_take_the_roots_declared_beside_it_with_it() {
        // Dropping is per root: the admissible one still admits what it covers.
        let roots = RootSet::new(
            Path::new(HOME),
            &[
                PathBuf::from("/"),
                PathBuf::from(ROOT),
                PathBuf::from("~/.."),
            ],
        );
        assert!(!roots.is_empty());
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cache")));
        assert!(!roots.contains(Path::new("/etc")));
        assert!(!roots.contains(Path::new("/var/home")));
    }

    #[test]
    fn a_relative_path_is_never_inside_a_root() {
        assert!(!rooted().contains(Path::new("cache/cargo")));
        assert!(!rooted().contains(Path::new("../example/cache")));
    }

    #[test]
    fn a_second_root_covers_what_the_first_does_not() {
        // The root set is a set precisely so an sccache directory can live
        // outside the scratch root without the scratch root being widened.
        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(ROOT), PathBuf::from("/var/cache/sccache")],
        );
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cargo")));
        assert!(roots.contains(Path::new("/var/cache/sccache/x")));
        assert!(!roots.contains(Path::new("/var/cache/other")));
    }

    #[test]
    fn a_root_inside_another_root_admits_what_each_of_them_admits() {
        // Overlapping declarations are ordinary — a scratch mount and a
        // directory inside it — and `contains` is an `any`, so the narrower one
        // neither shadows nor narrows the wider.
        let inner = format!("{ROOT}/cache");
        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(ROOT), PathBuf::from(&inner)],
        );
        assert!(roots.contains(Path::new(&inner)));
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cache/cargo")));
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/other")));
        assert!(!roots.contains(Path::new("/var/mnt/scratch/elsewhere")));
        // Declared the other way round, the same set.
        let reversed = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(&inner), PathBuf::from(ROOT)],
        );
        assert!(reversed.contains(Path::new("/var/mnt/scratch/example/other")));
        assert!(!reversed.contains(Path::new("/var/mnt/scratch/elsewhere")));
    }

    #[test]
    fn a_root_written_with_a_tilde_expands_against_home() {
        let roots = RootSet::new(Path::new(HOME), &[PathBuf::from("~/scratch")]);
        assert!(roots.contains(Path::new("/var/home/example/scratch/cargo")));
        assert!(!roots.contains(Path::new("/var/home/example/other")));
    }

    #[test]
    fn a_root_set_is_built_from_the_values_the_configuration_declares() {
        use crate::config::Origin;
        use crate::config::values::{
            AssignedValue, ResolvedValues, ValueAssignment, ValueDecl, ValueKind,
        };

        let origin = Origin::unknown(Path::new("bx.toml"));
        let declare = |name: &str, is_root: bool| ValueDecl {
            name: name.into(),
            description: None,
            kind: ValueKind::Path,
            required: false,
            is_root,
            default: None,
            enabled: true,
            origin: origin.clone(),
        };
        let answer = |name: &str, text: &str| ValueAssignment {
            name: name.into(),
            value: AssignedValue::String(text.into()),
            origin: origin.clone(),
        };

        let values = ResolvedValues::resolve(
            vec![
                declare("scratch_root", true),
                declare("brew_prefix", false),
                declare("sccache_dir", true),
            ],
            &[
                answer("scratch_root", ROOT),
                answer("brew_prefix", "/home/linuxbrew/.linuxbrew"),
                answer("sccache_dir", "/var/cache/sccache"),
            ],
            Path::new(HOME),
        )
        .expect("the values resolve");

        let roots = RootSet::from_values(&values);
        assert_eq!(roots, RootSet::new(Path::new(HOME), &values.roots()));
        assert_eq!(roots.home(), Some(Path::new(HOME)));
        assert!(roots.contains(Path::new("/var/mnt/scratch/example/cache/cargo")));
        assert!(roots.contains(Path::new("/var/cache/sccache/objects")));
        // A `path` value that was not declared a root does not become one.
        assert!(!roots.contains(Path::new("/home/linuxbrew/.linuxbrew/lib")));
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cache/cargo", &roots),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/home/linuxbrew/.linuxbrew/x", &roots)),
            Some(Reason::OutsideDeclaredRoots)
        );
    }

    #[test]
    fn an_unanswered_root_declaration_widens_nothing() {
        use crate::config::Origin;
        use crate::config::values::{ResolvedValues, ValueDecl, ValueKind};

        // A declaration nobody filled in must not widen the guard on the
        // strength of an intention — so a configuration whose only root is
        // unanswered is the strict guard.
        let values = ResolvedValues::resolve(
            vec![ValueDecl {
                name: "scratch_root".into(),
                description: None,
                kind: ValueKind::Path,
                required: false,
                is_root: true,
                default: None,
                enabled: true,
                origin: Origin::unknown(Path::new("bx.toml")),
            }],
            &[],
            Path::new(HOME),
        )
        .expect("the values resolve");

        let roots = RootSet::from_values(&values);
        assert!(roots.is_empty());
        assert_eq!(
            reason_of(&check("CARGO_HOME", ROOT, &roots)),
            Some(Reason::NoRootsDeclared)
        );
    }

    #[test]
    fn a_root_set_that_declares_nothing_is_empty_and_has_no_home() {
        let strict = RootSet::strict();
        assert!(strict.is_empty());
        assert_eq!(strict.home(), None);
        assert!(!strict.contains(Path::new(ROOT)));

        let rooted = rooted();
        assert!(!rooted.is_empty());
        assert_eq!(rooted.home(), Some(Path::new(HOME)));
    }

    #[test]
    fn containment_never_touches_the_filesystem() {
        // Both the root and the path are under a directory that has just been
        // removed, so `canonicalize` would return `Err` for either of them.
        // A verdict that depended on the filesystem would be wrong here, and a
        // `plan` built on it would differ between machines — invariant 3.
        let gone = tempfile::tempdir().expect("tempdir");
        let base = gone.path().to_path_buf();
        drop(gone);
        assert!(!base.exists());

        let roots = RootSet::new(Path::new(HOME), std::slice::from_ref(&base));
        assert!(roots.contains(&base.join("cache/cargo")));
        assert!(!roots.contains(Path::new("/var/cache/elsewhere")));
    }

    #[test]
    fn without_a_home_every_default_state_directory_is_owned() {
        let strict = RootSet::strict();
        for path in [
            "/var/home/example/.local/state/bx",
            "/home/other/.local/state/bx/x",
            "/root/.local/state/./bx",
            "/srv/.local/state/x/../bx/y",
        ] {
            assert!(strict.owns(Path::new(path)), "{path}");
        }
        for path in [
            "/var/home/example/.local/state/bxtra",
            "/var/home/example/.local/state",
            "/var/home/example/.local/bx",
            "/x/state/bx",
            "/x/.local/state",
        ] {
            assert!(!strict.owns(Path::new(path)), "{path}");
        }
        // A set with a home knows where its state directory is.
        assert!(!rooted().owns(Path::new("/home/other/.local/state/bx/x")));
        assert_eq!(
            check("PATH", "/home/other/.local/state/bx/bin", &rooted()),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("PATH", "/home/other/.local/state/bx/bin", &strict)),
            Some(Reason::BxOwnedDirectory)
        );
    }

    #[test]
    fn the_fragment_directory_is_owned_but_its_parent_is_not_refused() {
        // PR #75 note D2: `~/.local/share/bx` holds the fragments every shell
        // sources, so no tool may be pointed into it, even under a `~` root.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for value in [
            "/var/home/example/.local/share/bx",
            "/var/home/example/.local/share/bx/cargo",
            "/var/home/example/.local/share/./bx",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &home_rooted)),
                Some(Reason::BxOwnedDirectory),
                "{value}"
            );
        }
        // Its parent is `XDG_DATA_HOME`'s native default, and a location that
        // merely contains it is not refused.
        for name in ["CARGO_HOME", "XDG_DATA_HOME"] {
            assert_eq!(
                check(name, "/var/home/example/.local/share", &home_rooted),
                Verdict::Allowed,
                "{name}"
            );
        }
        assert_eq!(
            check(
                "CARGO_HOME",
                "/var/home/example/.local/share/bxtra",
                &home_rooted
            ),
            Verdict::Allowed
        );
        // A set without a home owns it under any home, as it does the state
        // directory; a set with one owns only its own.
        assert!(RootSet::strict().owns(Path::new("/home/other/.local/share/bx/x")));
        assert!(!RootSet::strict().owns(Path::new("/home/other/.local/share")));
        assert!(!home_rooted.owns(Path::new("/home/other/.local/share/bx/x")));
    }
}
