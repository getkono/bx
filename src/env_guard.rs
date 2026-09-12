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
    // Caches the prefix and suffix rules below do not reach. Each of these was
    // observed relocating a real toolchain cache while matching no rule: the
    // guard was letting them through silently.
    "GOCACHE",
    "NUGET_HTTP_CACHE_PATH",
    "HOMEBREW_CACHE",
    "HOMEBREW_LOGS",
    "HOMEBREW_TEMP",
    // `_CACHE_DIR` requires the underscore, and `SCCACHE_DIR` ends in
    // `CCACHE_DIR`, so it matched nothing either.
    "SCCACHE_DIR",
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
    "_STORE_DIR",
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

/// Why a relocating assignment was rejected.
///
/// The four are four different user actions — declare a root, move the value,
/// write an absolute path, define the referenced variable earlier — so a caller
/// that only knew *which* variable was rejected could not say what to do about
/// it. The messages name no data: the caller already holds the value and the
/// root set, and prints them itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    /// Nothing was declared, so nothing may be relocated.
    #[error("no root is declared, so nothing may be relocated")]
    NoRootsDeclared,
    /// It resolves to a path, but not one inside any declared root.
    #[error("resolves outside every declared root")]
    OutsideDeclaredRoots,
    /// Empty, relative, or `~user` — it cannot be shown to be inside a root.
    #[error("is not an absolute path")]
    NotAbsolute,
    /// It names a variable this fragment has not assigned by this line.
    #[error("refers to a variable this fragment has not assigned")]
    UnresolvedReference,
}

/// What [`check`] decided about one assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// bx may write this assignment.
    Allowed,
    /// bx may not, for this reason.
    Violation(Violation),
}

/// A forbidden assignment found in generated shell content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// 1-based line number within the scanned content.
    ///
    /// A violation returned by [`check`], which judges one assignment outside
    /// any content, carries `0`: there is no line to point at.
    pub line: usize,
    /// The variable being assigned.
    pub name: String,
    /// The value as written, before quote stripping and expansion, so a
    /// diagnostic can quote the line back exactly as the user will see it.
    pub value: String,
    /// Why the assignment was rejected.
    pub reason: Reason,
}

/// Whether bx may assign `value` to `name`, given the roots `roots` declares.
///
/// A variable that does not relocate anything is allowed without its value
/// being looked at, so `EDITOR=nvim` and `SCCACHE_CACHE_SIZE=100G` can never
/// trip a path rule. A relocating variable is allowed exactly when its value
/// resolves to a path inside a declared root.
///
/// No `$VAR` reference resolves here except `$HOME`: `check` judges one
/// assignment in isolation and has no fragment to learn from. [`scan_with`] is
/// the entry point that does.
#[must_use]
pub fn check(name: &str, value: &str, roots: &RootSet) -> Verdict {
    match evaluate(name, value, &Assignments::new(), roots) {
        None => Verdict::Allowed,
        Some(reason) => Verdict::Violation(Violation {
            line: 0,
            name: name.to_string(),
            value: value.to_string(),
            reason,
        }),
    }
}

/// Find every forbidden assignment in a block of shell bx is about to write,
/// judged against the roots `roots` declares.
///
/// One forward pass. Every assignment the pass sees — exported or not — is
/// recorded, so a later line may refer to it: the generated `.zshenv` is
/// written in terms of a declared root variable, and a guard that could not
/// resolve `$SCRATCH_HOME` would either reject every fragment bx generates or
/// check nothing at all. A reference to a variable assigned *later* in the file
/// is unresolved, because a shell would not have it either; order-dependence
/// here is correctness.
///
/// Nothing is read from the process environment and nothing is read from disk.
/// `$HOME` comes from `roots`, never from [`std::env`], and the roots are held
/// in declaration order, so this is a pure function of `(content, roots)` and
/// two calls on the same arguments return the same violations. That is what
/// lets `plan` call it without becoming machine-dependent (invariant 3).
///
/// Recognises `export NAME=`, `NAME=`, `typeset -x NAME=`, `declare -x NAME=`
/// and `setenv NAME`, which covers what bx itself generates. This is a guard
/// over bx's own output, **not a shell parser** — content bx merely *copies*
/// from another tool (a cached `mise activate` block, say) is that tool's
/// business and is not scanned. Specifically not understood, and deliberately
/// so: `local X=`, `env X=y cmd`, several assignments on one line, an inline
/// `# comment` after a value, and `'single quotes'` suppressing expansion for
/// any use of the name other than the one on that line.
#[must_use]
pub fn scan_with(content: &str, roots: &RootSet) -> Vec<Violation> {
    let mut found = Vec::new();
    let mut seen = Assignments::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = assignment(line) else {
            continue;
        };
        if let Some(reason) = evaluate(name, value, &seen, roots) {
            found.push(Violation {
                line: idx + 1,
                name: name.to_string(),
                value: value.to_string(),
                reason,
            });
        }
        // Learn the assignment only *after* judging it, as a shell does: the
        // right-hand side sees the previous value of the name, not this one.
        seen.insert(name.to_string(), unquote(value).0.to_string());
    }
    found
}

/// Find every forbidden assignment in a block of shell bx is about to write.
///
/// Equivalent to [`scan_with`] against [`RootSet::strict`]: with no root
/// declared, every relocating variable is a violation. This is the check for a
/// caller that has no configuration to consult, and it is why it needs no home.
#[must_use]
pub fn scan(content: &str) -> Vec<Violation> {
    scan_with(content, &RootSet::strict())
}

/// The reason `name = value` must not be written, or `None` if it may be.
fn evaluate(name: &str, value: &str, seen: &Assignments, roots: &RootSet) -> Option<Reason> {
    if !is_relocating(name) {
        return None;
    }
    // A set with no root permits no relocation, and is the only set without a
    // home — so past this point there is always a home to expand against.
    let home = match roots.home() {
        Some(home) if !roots.is_empty() => home,
        _ => return Some(Reason::NoRootsDeclared),
    };

    let (inner, expands) = unquote(value);
    let resolved = if expands {
        match expand(inner, seen, home) {
            Ok(resolved) => resolved,
            Err(reason) => return Some(reason),
        }
    } else {
        inner.to_string()
    };

    // `render` handles a leading `~` and `~/`, and deliberately leaves `~user`
    // alone, which then fails the absoluteness check below — as it should,
    // since bx does not resolve another user's home.
    let path = paths::render(&resolved, home);
    if !path.is_absolute() {
        return Some(Reason::NotAbsolute);
    }
    if roots.contains(&path) {
        None
    } else {
        Some(Reason::OutsideDeclaredRoots)
    }
}

/// Variable values learned during one pass over a fragment.
type Assignments = std::collections::HashMap<String, String>;

/// How many substitution passes an expansion may take before the value is
/// treated as unresolvable.
///
/// This is one of the two bounds that keep the expander from growing into a
/// shell. More than one pass is genuinely needed — `GOMODCACHE=$GOPATH/pkg/mod`
/// where `GOPATH` was itself written as `$CACHE_DIR/go` takes two — but the
/// depth of a generated fragment is a small constant, and an unbounded loop is
/// reachable from a value that refers to itself.
const MAX_EXPANSION_HOPS: usize = 8;

/// How long an expansion may grow before it is treated as unresolvable.
///
/// The second bound. A self-referential chain grows the value on every pass
/// rather than looping on one string, so the hop limit alone bounds the number
/// of passes but not the work each one does.
const MAX_EXPANDED_LEN: usize = 4096;

/// Expand `$NAME` and `${NAME}` in `raw` from `seen`, plus `$HOME` from `home`.
///
/// The grammar is closed and is the whole of it: `$NAME` and `${NAME}` where
/// `NAME` is a shell-legal variable name, and nothing else. A `$` that begins
/// neither is literal text. There is no `${NAME:-default}`, no `$(cmd)`, no
/// backslash escape and no word splitting, and none is to be added — the two
/// bounds above and this paragraph are what stop this function becoming a shell
/// parser, and a reviewer should check those rather than its length.
fn expand(raw: &str, seen: &Assignments, home: &Path) -> Result<String, Reason> {
    let home = home.to_string_lossy();
    let mut current = raw.to_string();
    for _ in 0..MAX_EXPANSION_HOPS {
        let (next, substituted) = substitute_once(&current, seen, &home)?;
        if !substituted {
            return Ok(next);
        }
        if next.len() > MAX_EXPANDED_LEN {
            return Err(Reason::UnresolvedReference);
        }
        current = next;
    }
    Err(Reason::UnresolvedReference)
}

/// One substitution pass. Returns the result and whether anything was
/// substituted; an unknown name is an error rather than an empty string,
/// because a shell's silent empty expansion is exactly the failure this guard
/// exists to catch.
fn substitute_once(value: &str, seen: &Assignments, home: &str) -> Result<(String, bool), Reason> {
    let mut out = String::with_capacity(value.len());
    let mut substituted = false;
    let mut rest = value;

    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];

        let (name, tail) = match after.strip_prefix('{') {
            Some(braced) => match braced.find('}') {
                Some(end) => (&braced[..end], &braced[end + 1..]),
                // An unclosed `${` is not a reference; it is literal text.
                None => ("", after),
            },
            None => {
                let end = after
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(after.len());
                (&after[..end], &after[end..])
            }
        };

        if !is_variable_name(name) {
            out.push('$');
            rest = after;
            continue;
        }

        // A name the fragment assigned wins over `$HOME`, as it would in a
        // shell; `home` is the fallback, and is the only value not learned from
        // the fragment itself.
        let resolved = match seen.get(name) {
            Some(learned) => learned.as_str(),
            None if name == "HOME" => home,
            None => return Err(Reason::UnresolvedReference),
        };
        out.push_str(resolved);
        substituted = true;
        rest = tail;
    }
    out.push_str(rest);
    Ok((out, substituted))
}

/// Strip one matched pair of surrounding quotes.
///
/// Returns the inner text and whether `$` expansion applies to it: single
/// quotes suppress expansion, double quotes do not.
fn unquote(value: &str) -> (&str, bool) {
    for (quote, expands) in [('\'', false), ('"', true)] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return (&value[1..value.len() - 1], expands);
        }
    }
    (value, true)
}

/// The name and value a shell line assigns, if it assigns one.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let rest = ["export ", "typeset -x ", "declare -x ", "setenv "]
        .iter()
        .find_map(|kw| line.strip_prefix(*kw))
        .unwrap_or(line)
        .trim_start();

    // `setenv NAME value` separates with a space; everything else uses `=`.
    let (name, value) = match rest.split_once('=') {
        Some((name, value)) => (name, value),
        None => {
            let mut words = rest.split_whitespace();
            // `export NAME` with no value yields an empty value, which is not
            // an absolute path, so it stays flagged.
            (words.next()?, words.next().unwrap_or(""))
        }
    };
    let name = name.trim();
    is_variable_name(name).then_some((name, value.trim()))
}

/// Whether `name` is a shell-legal variable name.
fn is_variable_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::guarded_home;

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

    // `check` — a relocating variable is judged by where its value points.

    fn reason_of(verdict: &Verdict) -> Option<Reason> {
        match verdict {
            Verdict::Allowed => None,
            Verdict::Violation(violation) => Some(violation.reason),
        }
    }

    #[test]
    fn a_variable_that_does_not_relocate_is_allowed_without_reading_its_value() {
        // None of these values is a path at all. A name-based guard never had
        // to care; a value-based one must not start.
        for (name, value) in [
            ("EDITOR", "nvim"),
            ("SCCACHE_CACHE_SIZE", "100G"),
            ("MISE_VERBOSE", "1"),
            ("RUSTC_WRAPPER", "/usr/bin/sccache"),
        ] {
            assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
            // And it is allowed even with nothing declared at all.
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
    }

    #[test]
    fn a_relocating_variable_inside_a_declared_root_is_allowed() {
        assert_eq!(
            check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/cache/cargo",
                &rooted()
            ),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_relocating_variable_outside_every_root_is_a_violation() {
        let verdict = check("CARGO_HOME", "/var/cache/elsewhere", &rooted());
        assert_eq!(reason_of(&verdict), Some(Reason::OutsideDeclaredRoots));
        // The violation carries what a diagnostic needs to say what to do.
        let Verdict::Violation(violation) = verdict else {
            panic!("expected a violation");
        };
        assert_eq!(violation.name, "CARGO_HOME");
        assert_eq!(violation.value, "/var/cache/elsewhere");
        // `check` judges one assignment outside any content, so there is no
        // line to report.
        assert_eq!(violation.line, 0);
    }

    #[test]
    fn the_declared_root_variable_itself_is_allowed() {
        // `SCRATCH_HOME` is caught by the `_HOME` suffix and was, under the
        // name-based guard, denied outright — a false positive on the one
        // variable the whole configuration is written in terms of.
        assert!(is_relocating("SCRATCH_HOME"));
        assert_eq!(check("SCRATCH_HOME", ROOT, &rooted()), Verdict::Allowed);
    }

    #[test]
    fn with_no_root_declared_every_relocating_variable_is_a_violation() {
        for (name, value) in [
            ("CARGO_HOME", "/var/mnt/scratch/example/cache/cargo"),
            ("XDG_CONFIG_HOME", "/anywhere"),
            ("MISE_DATA_DIR", "~/mise"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &RootSet::strict())),
                Some(Reason::NoRootsDeclared),
                "{name}"
            );
        }
    }

    #[test]
    fn a_root_set_with_a_home_but_no_roots_declares_nothing() {
        // Holding a home is not declaring a root: the strictness comes from the
        // root list being empty, not from the home being absent.
        let empty = RootSet::new(Path::new(HOME), &[]);
        assert_eq!(empty.home(), Some(Path::new(HOME)));
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x", &empty)),
            Some(Reason::NoRootsDeclared)
        );
    }

    #[test]
    fn an_empty_value_is_not_absolute() {
        // `export CARGO_HOME` with no value at all.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "", &rooted())),
            Some(Reason::NotAbsolute)
        );
    }

    #[test]
    fn a_relative_value_is_not_absolute() {
        for value in ["cache/cargo", "./cargo", "../example/cargo"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::NotAbsolute),
                "{value}"
            );
        }
    }

    #[test]
    fn another_users_home_is_not_expanded_and_is_not_absolute() {
        // `~other` is deliberately left alone by `paths::render` — bx does not
        // resolve another account's home — so it cannot be shown to be inside
        // any root, and is rejected rather than silently accepted.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~other/cargo", &rooted())),
            Some(Reason::NotAbsolute)
        );
    }

    #[test]
    fn a_home_relative_value_is_a_violation_when_home_is_not_a_declared_root() {
        // Holding the home for `~` expansion is not the same as declaring it a
        // root. A relocation into `$HOME` is as invisible to a shell bx did not
        // initialise as one anywhere else.
        for value in ["~/x", "$HOME/x", "${HOME}/x"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{value}"
            );
        }
        // Declaring home as a root is how a user opts in, and it then works.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(check("CARGO_HOME", "~/x", &home_rooted), Verdict::Allowed);
    }

    #[test]
    fn the_reasons_render_as_sentences() {
        // The messages name no data: a caller prints the value and the roots.
        assert_eq!(
            Reason::NoRootsDeclared.to_string(),
            "no root is declared, so nothing may be relocated"
        );
        assert_eq!(
            Reason::OutsideDeclaredRoots.to_string(),
            "resolves outside every declared root"
        );
        assert_eq!(Reason::NotAbsolute.to_string(), "is not an absolute path");
        assert_eq!(
            Reason::UnresolvedReference.to_string(),
            "refers to a variable this fragment has not assigned"
        );
    }

    // `scan_with` — the same rule over a whole fragment, with a learned
    // environment.

    #[test]
    fn scan_is_scan_with_no_roots_declared() {
        // Backward compatibility as a property, not by inspection.
        for content in [
            "export EDITOR=nvim\n",
            "export CARGO_HOME=$HOME/x\n",
            "# export CARGO_HOME=/x\n",
            "export XDG_CONFIG_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n",
            "setenv GOPATH /x\nsource ~/.cargo/env\n",
            OPERATOR_FRAGMENT,
        ] {
            assert_eq!(
                scan(content),
                scan_with(content, &RootSet::strict()),
                "{content}"
            );
        }
    }

    #[test]
    fn a_reference_assigned_earlier_in_the_file_is_expanded() {
        let content =
            "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME=$SCRATCH_HOME/cargo\n";
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn a_reference_assigned_later_in_the_file_is_unresolved() {
        // A shell reading top to bottom would not have it either, so neither
        // does the guard. Order-dependence here is correctness.
        let content =
            "export CARGO_HOME=$SCRATCH_HOME/cargo\nSCRATCH_HOME=/var/mnt/scratch/example\n";
        let found = scan_with(content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[0].reason, Reason::UnresolvedReference);
    }

    #[test]
    fn a_chained_reference_resolves_through_two_hops() {
        let content = concat!(
            "SCRATCH_HOME=/var/mnt/scratch/example\n",
            "CACHE_DIR=$SCRATCH_HOME/cache\n",
            "export GOPATH=$CACHE_DIR/go\n",
            "export GOMODCACHE=$GOPATH/pkg/mod\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn a_self_referential_expansion_terminates() {
        // `X=$X/b` makes every later use of `$X` grow without ever resolving.
        // The hop limit is what stops it, and the value is then unresolvable.
        let content = concat!(
            "X=/var/mnt/scratch/example\n",
            "X=$X/b\n",
            "export CARGO_HOME=$X/cargo\n",
        );
        let found = scan_with(content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::UnresolvedReference);
    }

    #[test]
    fn an_unknown_reference_is_a_violation() {
        // Silently expanding an unset name to the empty string is exactly the
        // failure this guard exists to catch, so it is an error instead.
        for value in ["$NOWHERE/cargo", "${NOWHERE}/cargo", "/a/$NOWHERE"] {
            let found = scan_with(&format!("export CARGO_HOME={value}\n"), &rooted());
            assert_eq!(found.len(), 1, "{value}");
            assert_eq!(found[0].reason, Reason::UnresolvedReference, "{value}");
        }
    }

    #[test]
    fn a_dollar_that_begins_no_reference_is_literal_text() {
        // The expansion grammar is closed: `$NAME` and `${NAME}`, nothing else.
        // Anything else is text, and text that is not an absolute path is
        // rejected for being one, not for being unresolvable.
        for value in ["$", "$1/x", "${/x", "${}/x"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::NotAbsolute),
                "{value}"
            );
        }
        // And a literal `$` inside an otherwise-contained path is kept. `$1b`
        // is not a reference — a name may not begin with a digit — so it stays
        // as written rather than resolving or failing to.
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/a$1b", &rooted()),
            Verdict::Allowed
        );
        // `$b` on the other hand *is* a reference, and an undefined one.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/a$b",
                &rooted()
            )),
            Some(Reason::UnresolvedReference)
        );
    }

    #[test]
    fn home_is_taken_from_the_root_set_not_the_process_environment() {
        // A future refactor that reached for `std::env::var("HOME")` would make
        // the guard's verdict machine-dependent, which invariant 3 forbids.
        // Under a real process `$HOME` this fragment would be outside the root;
        // under the root set's home it is inside it.
        let _home = guarded_home();
        let declared = Path::new("/var/home/declared");
        let roots = RootSet::new(declared, &[PathBuf::from("~/scratch")]);
        assert_ne!(
            std::env::var_os("HOME").map(PathBuf::from),
            Some(declared.to_path_buf())
        );
        let content = "export CARGO_HOME=$HOME/scratch/cargo\n";
        assert_eq!(scan_with(content, &roots), vec![]);
    }

    #[test]
    fn a_single_quoted_value_does_not_expand() {
        // `'…'` suppresses expansion in a shell, so the value is the literal
        // text `$SCRATCH_HOME/cargo`, which is not an absolute path.
        let content =
            "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME='$SCRATCH_HOME/cargo'\n";
        let found = scan_with(content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::NotAbsolute);
    }

    #[test]
    fn surrounding_double_quotes_are_stripped() {
        let content = "SCRATCH_HOME=\"/var/mnt/scratch/example\"\nexport CARGO_HOME=\"$SCRATCH_HOME/cargo\"\n";
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn violations_are_reported_in_line_order() {
        let content = concat!(
            "export CARGO_HOME=/elsewhere/a\n",
            "export EDITOR=nvim\n",
            "export RUSTUP_HOME=/var/mnt/scratch/example/rustup\n",
            "export GOPATH=/elsewhere/b\n",
        );
        let found = scan_with(content, &rooted());
        assert_eq!(found.iter().map(|v| v.line).collect::<Vec<_>>(), vec![1, 4]);
        assert_eq!(
            found.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            vec!["CARGO_HOME", "GOPATH"]
        );
    }

    #[test]
    fn scanning_the_same_content_twice_returns_the_same_violations() {
        // Invariant 3. The guard is a pure function of `(content, roots)`: it
        // reads no process environment, touches no disk, and holds its roots in
        // declaration order, so no iteration order can reach the output.
        let content = OPERATOR_FRAGMENT;
        assert_eq!(scan_with(content, &rooted()), scan_with(content, &rooted()));
        assert_eq!(scan(content), scan(content));
    }

    /// The operator's own relocating exports, with the scratch mount replaced
    /// by a neutral root so nothing user-specific enters the repository
    /// (invariant 5). Every one of these was denied or leaked by the
    /// name-based guard; all 23 are value-checked now.
    const OPERATOR_FRAGMENT: &str = concat!(
        "export SCRATCH_HOME=\"/var/mnt/scratch/example\"\n",
        "CACHE_DIR=\"$SCRATCH_HOME/cache\"\n",
        "DATA_DIR=\"$SCRATCH_HOME/.local/share\"\n",
        "export NPM_CONFIG_CACHE=\"$SCRATCH_HOME/.npm\"\n",
        "export PNPM_CONFIG_STORE_DIR=\"$CACHE_DIR/pnpm\"\n",
        "export BUN_INSTALL=\"$SCRATCH_HOME/.bun\"\n",
        "export BUN_INSTALL_CACHE_DIR=\"$CACHE_DIR/bun\"\n",
        "export CARGO_HOME=\"$CACHE_DIR/cargo\"\n",
        "export RUSTUP_HOME=\"$CACHE_DIR/rustup\"\n",
        "export GOPATH=\"$CACHE_DIR/go\"\n",
        "export GOMODCACHE=\"$GOPATH/pkg/mod\"\n",
        "export GOCACHE=\"$CACHE_DIR/go-build\"\n",
        "export UV_CACHE_DIR=\"$CACHE_DIR/uv\"\n",
        "export PIP_CACHE_DIR=\"$CACHE_DIR/pip\"\n",
        "export ZIG_GLOBAL_CACHE_DIR=\"$CACHE_DIR/zig\"\n",
        "export ANDROID_HOME=\"$SCRATCH_HOME/Android/Sdk\"\n",
        "export ANDROID_USER_HOME=\"$SCRATCH_HOME/.android\"\n",
        "export NUGET_PACKAGES=\"$CACHE_DIR/nuget\"\n",
        "export NUGET_HTTP_CACHE_PATH=\"$CACHE_DIR/nuget-http\"\n",
        "export DOTNET_CLI_HOME=\"$CACHE_DIR/dotnet\"\n",
        "export HOMEBREW_CACHE=\"$CACHE_DIR/Homebrew/cache\"\n",
        "export HOMEBREW_LOGS=\"$CACHE_DIR/Homebrew/logs\"\n",
        "export HOMEBREW_TEMP=\"$CACHE_DIR/Homebrew/temp\"\n",
        "export MISE_DATA_DIR=\"$DATA_DIR/mise\"\n",
        "export MISE_CACHE_DIR=\"$CACHE_DIR/mise\"\n",
    );

    #[test]
    fn the_six_names_that_used_to_leak_are_now_checked() {
        // Each of these relocates a real toolchain cache and matched no rule in
        // the name list, so the guard let it through unexamined. This is the
        // regression test for that defect: they are checked now, and checking
        // means allowed inside a declared root and rejected outside every one.
        for name in [
            "PNPM_CONFIG_STORE_DIR",
            "GOCACHE",
            "NUGET_HTTP_CACHE_PATH",
            "HOMEBREW_CACHE",
            "HOMEBREW_LOGS",
            "HOMEBREW_TEMP",
        ] {
            assert!(is_relocating(name), "{name} should be value-checked");
            assert_eq!(
                check(name, "/var/mnt/scratch/example/x", &rooted()),
                Verdict::Allowed,
                "{name}"
            );
            assert_eq!(
                reason_of(&check(name, "/var/cache/elsewhere", &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{name}"
            );
        }
    }

    #[test]
    fn an_sccache_directory_is_value_checked() {
        // The motivating case for the root set being a *set*: an sccache
        // directory may legitimately live outside the scratch root, and must
        // then be covered by a root of its own rather than waved through.
        assert!(is_relocating("SCCACHE_DIR"));
        // The behaviour variables that share its prefix still are not.
        assert!(!is_relocating("SCCACHE_CACHE_SIZE"));
        assert!(!is_relocating("SCCACHE_SERVER_UDS"));

        let roots = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from(ROOT), PathBuf::from("/var/cache/sccache")],
        );
        assert_eq!(
            check("SCCACHE_DIR", "/var/cache/sccache/objects", &roots),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check(
                "SCCACHE_DIR",
                "/var/cache/sccache/objects",
                &rooted()
            )),
            Some(Reason::OutsideDeclaredRoots)
        );
    }

    #[test]
    fn widening_the_list_did_not_capture_a_colon_separated_list() {
        // A generic `_PATH` or `_DIR` suffix would have. Those lists are not
        // single paths and would be rejected for not being absolute, which is
        // why the list is widened by observed evidence and nothing else.
        for name in ["LD_LIBRARY_PATH", "PATH", "MANPATH", "PKG_CONFIG_PATH"] {
            assert!(!is_relocating(name), "{name} should not be value-checked");
        }
    }

    #[test]
    fn the_same_fragment_is_all_violations_with_no_root_declared() {
        // A user who declares no root gets the strict guard, and the strict
        // guard denies every relocation. `CACHE_DIR` and `DATA_DIR` are not
        // relocating names, so 25 assignments yield 23 violations — and 23 is
        // the whole relocating set, six of which reach this count only because
        // the name list was widened.
        let found = scan(OPERATOR_FRAGMENT);
        assert_eq!(found.len(), 23);
        assert!(found.iter().all(|v| v.reason == Reason::NoRootsDeclared));
        assert!(found.windows(2).all(|w| w[0].line < w[1].line));
        assert!(!found.iter().any(|v| v.name == "CACHE_DIR"));
        assert!(!found.iter().any(|v| v.name == "DATA_DIR"));
    }

    #[test]
    fn the_operator_fragment_scans_clean_under_its_declared_root() {
        assert_eq!(scan_with(OPERATOR_FRAGMENT, &rooted()), vec![]);
    }

    #[test]
    fn xdg_roots_are_value_checked() {
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
    fn per_tool_roots_are_value_checked() {
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
    fn tool_families_are_value_checked_by_prefix() {
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
    fn location_suffixes_are_value_checked_generically() {
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
                name: "CARGO_HOME".into(),
                value: "$HOME/x".into(),
                reason: Reason::NoRootsDeclared,
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
