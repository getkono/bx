//! The one rule that keeps bx from breaking the tools it manages.
//!
//! bx *may* write an environment variable when that is a tool's own documented
//! configuration interface and the tool has no config file — `SCCACHE_CACHE_SIZE`
//! and `RUSTC_WRAPPER` are the motivating cases, since sccache is configured
//! entirely by environment.
//!
//! bx *may never* write a variable that relocates a tool's config, data, or
//! cache. Doing so makes the tool depend on bx having run: open a shell that
//! bx did not initialise — a login shell, a `systemd-run` unit, an SSH command,
//! a container — and the tool silently reads a different directory.
//!
//! This module is that rule as code. Anything bx generates for a shell is run
//! through [`scan`] before it is written, and the check is covered by tests
//! rather than left to review.

use std::path::{Path, PathBuf};

use crate::paths;

/// Exact variable names bx must never assign.
const DENIED_EXACT: &[&str] = &[
    // XDG roots — relocating any of these moves every tool at once.
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    // Per-tool roots.
    "CARGO_HOME",
    "RUSTUP_HOME",
    "GNUPGHOME",
    "GOPATH",
    "GOMODCACHE",
    "GRADLE_USER_HOME",
    "PYENV_ROOT",
    "NVM_DIR",
    "BUN_INSTALL",
    "PNPM_HOME",
    "DENO_DIR",
    "DOTNET_CLI_HOME",
    "NUGET_PACKAGES",
    "GEM_HOME",
    "COMPOSER_HOME",
    "SSH_CONFIG",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GH_CONFIG_DIR",
    "DOCKER_CONFIG",
    "KUBECONFIG",
];

/// Prefixes whose variables are, as a family, about relocating a tool's
/// directories. Matched against the whole name, so `MISE_DATA_DIR` is denied
/// while `MISE_VERBOSE` is not.
const DENIED_PREFIXES: &[&str] = &["NPM_CONFIG_", "UV_", "MISE_", "ASDF_", "PIP_"];

/// Suffixes that mark a variable as naming a location.
const DENIED_SUFFIXES: &[&str] = &[
    "_HOME",
    "_CONFIG_DIR",
    "_DATA_DIR",
    "_CACHE_DIR",
    "_STATE_DIR",
    "_CONFIG_FILE",
];

/// Names that match a denied prefix or suffix but are legitimate: they
/// configure behaviour bx is allowed to set, not a location.
const ALLOWED_EXCEPTIONS: &[&str] = &["UV_SYSTEM_PYTHON", "MISE_VERBOSE", "PIP_REQUIRE_VIRTUALENV"];

/// Whether bx is forbidden from assigning `name`.
///
/// The check is case-sensitive: environment variable names are, and a tool that
/// reads `CARGO_HOME` does not read `cargo_home`.
#[must_use]
pub fn is_relocating(name: &str) -> bool {
    if ALLOWED_EXCEPTIONS.contains(&name) {
        return false;
    }
    if DENIED_EXACT.contains(&name) {
        return true;
    }
    DENIED_PREFIXES
        .iter()
        .any(|p| name.starts_with(p) && name.len() > p.len())
        || DENIED_SUFFIXES
            .iter()
            .any(|s| name.ends_with(s) && name.len() > s.len())
}

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
/// Containment is decided **lexically**, never by touching the filesystem.
/// `canonicalize` would make the verdict depend on what exists and on what is
/// mounted, so the same `plan` would differ between two machines and between
/// two runs on one — which invariant 3 forbids. The price is that lexical `..`
/// normalisation is unsound across a symlink: `<root>/link/../x`, where `link`
/// points outside the root, is judged inside it. That is accepted rather than
/// fixed, because the only fix is the one invariant 3 rules out, and the values
/// bx checks are generated from declared roots, so a `..` component in one is
/// anomalous by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSet {
    home: Option<PathBuf>,
    roots: Vec<PathBuf>,
}

impl RootSet {
    /// The set that declares nothing, and therefore permits no relocation.
    ///
    /// This is what [`scan`] uses, and it is why `scan` needs no home: with no
    /// root declared every relocating variable is a violation before its value
    /// is ever looked at, so there is nothing to expand `~` against.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            home: None,
            roots: Vec::new(),
        }
    }

    /// A set of declared roots, resolved against `home`.
    ///
    /// Each root is `~`-expanded with [`paths::render`] and lexically
    /// normalised with [`paths::normalize`], so that a root and a value being
    /// compared have been through the same rules.
    #[must_use]
    pub fn new(home: &Path, roots: &[PathBuf]) -> Self {
        let home = paths::normalize(home);
        let roots = roots
            .iter()
            .map(|root| paths::normalize(&paths::render(&root.to_string_lossy(), &home)))
            .collect();
        Self {
            home: Some(home),
            roots,
        }
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

    /// Whether no root is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The home `~` and `$HOME` expand against, if this set has one.
    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }
}

/// A forbidden assignment found in generated shell content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// 1-based line number within the scanned content.
    pub line: usize,
    /// The variable being assigned.
    pub name: String,
}

/// Find every forbidden assignment in a block of shell bx is about to write.
///
/// Recognises `export NAME=`, `NAME=`, `typeset -x NAME=`, and `setenv NAME`,
/// which covers what bx itself generates. This is a guard against bx's own
/// output, not a shell parser — content bx merely *copies* from another tool
/// (a cached `mise activate` block, say) is that tool's business and is not
/// scanned.
#[must_use]
pub fn scan(content: &str) -> Vec<Violation> {
    let mut found = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(name) = assigned_name(line)
            && is_relocating(name)
        {
            found.push(Violation {
                line: idx + 1,
                name: name.to_string(),
            });
        }
    }
    found
}

/// The variable name a shell line assigns, if it assigns one.
fn assigned_name(line: &str) -> Option<&str> {
    let rest = ["export ", "typeset -x ", "declare -x ", "setenv "]
        .iter()
        .find_map(|kw| line.strip_prefix(*kw))
        .unwrap_or(line)
        .trim_start();

    // `setenv NAME value` separates with a space; everything else uses `=`.
    let name = match rest.split_once('=') {
        Some((name, _)) => name,
        None => rest.split_whitespace().next()?,
    }
    .trim();

    let valid = !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deliberately neutral home and scratch root: nothing in this file may
    // name a real account or a real machine's layout (invariant 5).
    const HOME: &str = "/var/home/example";
    const ROOT: &str = "/var/mnt/scratch/example";

    fn rooted() -> RootSet {
        RootSet::new(Path::new(HOME), &[PathBuf::from(ROOT)])
    }

    #[test]
    fn a_declared_root_contains_itself() {
        assert!(rooted().contains(Path::new(ROOT)));
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
    fn a_root_written_with_a_tilde_expands_against_home() {
        let roots = RootSet::new(Path::new(HOME), &[PathBuf::from("~/scratch")]);
        assert!(roots.contains(Path::new("/var/home/example/scratch/cargo")));
        assert!(!roots.contains(Path::new("/var/home/example/other")));
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
    fn xdg_roots_are_denied() {
        for name in [
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "XDG_STATE_HOME",
        ] {
            assert!(is_relocating(name), "{name} should be denied");
        }
    }

    #[test]
    fn per_tool_roots_are_denied() {
        for name in [
            "CARGO_HOME",
            "RUSTUP_HOME",
            "GNUPGHOME",
            "GH_CONFIG_DIR",
            "KUBECONFIG",
        ] {
            assert!(is_relocating(name), "{name} should be denied");
        }
    }

    #[test]
    fn tool_families_are_denied_by_prefix() {
        for name in [
            "MISE_DATA_DIR",
            "UV_CACHE_DIR",
            "NPM_CONFIG_PREFIX",
            "ASDF_DIR",
            "PIP_TARGET",
        ] {
            assert!(is_relocating(name), "{name} should be denied");
        }
    }

    #[test]
    fn location_suffixes_are_denied_generically() {
        // The point of the suffix rule is catching tools bx has never heard of.
        for name in ["SOMETOOL_CONFIG_DIR", "OTHERTOOL_HOME", "THIRD_CACHE_DIR"] {
            assert!(is_relocating(name), "{name} should be denied");
        }
    }

    #[test]
    fn a_bare_prefix_or_suffix_is_not_a_variable() {
        // `_HOME` is the suffix itself, not a tool's variable; likewise `UV_`.
        assert!(!is_relocating("_HOME"));
        assert!(!is_relocating("UV_"));
    }

    #[test]
    fn behaviour_variables_are_allowed() {
        for name in [
            "SCCACHE_CACHE_SIZE",
            "RUSTC_WRAPPER",
            "EDITOR",
            "VISUAL",
            "PAGER",
            "SCCACHE_SERVER_UDS",
        ] {
            assert!(!is_relocating(name), "{name} should be allowed");
        }
    }

    #[test]
    fn documented_exceptions_survive_the_prefix_rule() {
        assert!(!is_relocating("UV_SYSTEM_PYTHON"));
        assert!(!is_relocating("MISE_VERBOSE"));
        assert!(!is_relocating("PIP_REQUIRE_VIRTUALENV"));
    }

    #[test]
    fn the_check_is_case_sensitive() {
        assert!(!is_relocating("cargo_home"));
    }

    #[test]
    fn scan_reports_the_offending_line_and_name() {
        let content = "export EDITOR=nvim\nexport CARGO_HOME=$HOME/x\n";
        assert_eq!(
            scan(content),
            vec![Violation {
                line: 2,
                name: "CARGO_HOME".into()
            }]
        );
    }

    #[test]
    fn scan_accepts_clean_content() {
        let content = "# bx generated\nexport SCCACHE_CACHE_SIZE=100G\nexport RUSTC_WRAPPER=/usr/bin/sccache\n";
        assert!(scan(content).is_empty());
    }

    #[test]
    fn scan_recognises_every_assignment_form() {
        for line in [
            "export CARGO_HOME=/x",
            "CARGO_HOME=/x",
            "typeset -x CARGO_HOME=/x",
            "declare -x CARGO_HOME=/x",
            "setenv CARGO_HOME /x",
        ] {
            assert_eq!(scan(line).len(), 1, "should have flagged: {line}");
        }
    }

    #[test]
    fn scan_ignores_comments() {
        assert!(scan("# export CARGO_HOME=/x\n   # CARGO_HOME=/x").is_empty());
    }

    #[test]
    fn scan_ignores_lines_that_assign_nothing() {
        assert!(scan("source ~/.cargo/env\n\n[[ -r $f ]] && source $f\n2bad=x\n=x").is_empty());
    }

    #[test]
    fn scan_reports_every_violation() {
        let content = "export XDG_CONFIG_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n";
        let found = scan(content);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[1].line, 3);
    }
}
