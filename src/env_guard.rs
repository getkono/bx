//! The one rule that keeps bx from breaking the tools it manages.
//!
//! bx *may* write an environment variable when that is a tool's own documented
//! configuration interface and the tool has no config file — `SCCACHE_CACHE_SIZE`
//! and `RUSTC_WRAPPER` are the motivating cases, since sccache is configured
//! entirely by environment.
//!
//! bx *may never* write a variable that moves a tool's config, data, or cache
//! **outside a root the configuration declares**. Doing so makes the tool
//! depend on bx having run: open a shell that bx did not initialise — a login
//! shell, a `systemd-run` unit, an SSH command, a container — and the tool
//! silently reads a different directory. Inside a declared root the user has
//! said where those directories live and has accepted that consequence, which
//! is why a machine that puts its toolchain caches on a scratch mount is a
//! configuration bx serves rather than one it refuses.
//!
//! bx *may never* point a tool at a directory **bx itself owns**, and that one
//! is unconditional: it holds inside a declared root too, because bx's state
//! directory holds the record that makes an uninstall exact, and a tool writing
//! among those files would make `bx rm` destructive. [`RootSet::owns`] is that
//! exclusion, and it is checked before containment.
//!
//! The rule is therefore about the **value** a variable is given, never about
//! the variable's name. [`is_relocating`] only decides whether a value has to be
//! looked at; [`check`] is the verdict, and [`RootSet`] is what it is judged
//! against. Declare no root — [`RootSet::strict`], which is what [`scan`] uses —
//! and nothing may be relocated anywhere.
//!
//! The guard **fails closed**. Shell it cannot read is never approved: a line
//! that could assign a variable and is not one of the few forms [`scan_with`]
//! reads is refused as [`Reason::Unreadable`], whatever the variable.
//!
//! This module is that rule as code. Anything bx generates for a shell is run
//! through [`scan_with`] before it is written, and the check is covered by tests
//! rather than left to review.

use std::path::{Component, Path, PathBuf};

use crate::config::layers;
use crate::config::values::ResolvedValues;
use crate::paths;

/// Exact variable names whose assigned value must be checked against the
/// declared roots.
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

/// Prefixes whose variables are, as a family, about where a tool's directories
/// live. Matched against the whole name, so `MISE_DATA_DIR` is value-checked
/// while `MISE_VERBOSE` is not.
///
/// A family holds far more behaviour variables than location variables, so a
/// name matched **only** by a prefix is not, by itself, evidence that it holds a
/// location. See [`names_a_location`].
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

/// The last word of a prefix-family name that says the variable holds a
/// location: `UV_TOOL_DIR`, `PIP_TARGET`, `NPM_CONFIG_CACHE`,
/// `UV_PROJECT_ENVIRONMENT`, `NPM_CONFIG_USERCONFIG`.
///
/// Each is taken from a location variable one of the five families documents.
/// It is what keeps a bare relative value — `NPM_CONFIG_CACHE=.npm`,
/// `PIP_TARGET=build`, which move a tool's data to wherever the shell happens
/// to be — from passing as a behaviour setting.
const LOCATION_WORDS: &[&str] = &[
    "DIR",
    "PATH",
    "FILE",
    "HOME",
    "ROOT",
    "PREFIX",
    "TARGET",
    "CACHE",
    "TMP",
    "SRC",
    "LOG",
    "ENVIRONMENT",
    "USERCONFIG",
    "GLOBALCONFIG",
];

/// Names that match a rule above but carry no path at all: they configure
/// behaviour, so their value must not be checked against a root.
///
/// Only a name a *suffix* or a location word would otherwise mark is worth
/// listing. A prefix-family behaviour variable — `UV_NO_CACHE=1`,
/// `MISE_JOBS=8` — is recognised by its value and needs no entry here.
const ALLOWED_EXCEPTIONS: &[&str] = &[
    "UV_SYSTEM_PYTHON",
    "MISE_VERBOSE",
    "PIP_REQUIRE_VIRTUALENV",
    // pip's `--no-cache-dir` switch, which the `_CACHE_DIR` suffix catches.
    "PIP_NO_CACHE_DIR",
];

/// Whether assigning `name` requires its **value** to be checked against the
/// declared roots.
///
/// This used to be the verdict itself: a matching name was a denial. It is now
/// only the question. A matching name is one that names a location, so *where*
/// that location is decides whether bx may write it, and [`check`] is what
/// decides. The three lists above are therefore no longer a deny-list.
///
/// Because a wider list now means more checking rather than more denial, the
/// list can afford to be wide — but it is still widened only by evidence. A
/// generic `_DIR` or `_PATH` suffix is deliberately absent: `_PATH` would
/// capture colon-separated lists such as `LD_LIBRARY_PATH`, which are not
/// single paths and would be rejected for not being absolute.
///
/// The check is case-sensitive: environment variable names are, and a tool that
/// reads `CARGO_HOME` does not read `cargo_home`.
#[must_use]
pub fn is_relocating(name: &str) -> bool {
    if ALLOWED_EXCEPTIONS.contains(&name) {
        return false;
    }
    DENIED_EXACT.contains(&name) || has_location_suffix(name) || family_tail(name).is_some()
}

/// Whether `name` ends in one of [`DENIED_SUFFIXES`], with something before it.
fn has_location_suffix(name: &str) -> bool {
    DENIED_SUFFIXES
        .iter()
        .any(|s| name.ends_with(s) && name.len() > s.len())
}

/// What follows the family prefix `name` begins with, if it begins with one.
fn family_tail(name: &str) -> Option<&str> {
    DENIED_PREFIXES
        .iter()
        .find_map(|p| name.strip_prefix(p))
        .filter(|tail| !tail.is_empty())
}

/// Whether the variable's **name** says that it holds a location.
///
/// True of an exact name and of a suffix match, where the name is the evidence.
/// For a name matched only by a family prefix it is true when the name's last
/// word is a [`LOCATION_WORDS`] entry — unless the name is a `NO_` switch, which
/// turns a location off rather than naming one (`UV_NO_CACHE`).
///
/// A relocating variable whose name does *not* say so, given a value that is no
/// kind of path, is a behaviour setting: `MISE_JOBS=8`, `UV_PYTHON=3.12`.
fn names_a_location(name: &str) -> bool {
    if DENIED_EXACT.contains(&name) || has_location_suffix(name) {
        return true;
    }
    family_tail(name).is_some_and(|tail| {
        !tail.starts_with("NO_")
            && tail
                .rsplit('_')
                .next()
                .is_some_and(|last| LOCATION_WORDS.contains(&last))
    })
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
/// It also carries the directories **bx itself owns**, which are an exclusion
/// rather than a root: invariant 2's first sentence — never point a tool at a
/// bx-owned directory — is unconditional, so it holds even inside a declared
/// root and even when the declared root is the home. See [`RootSet::owns`].
///
/// Containment is decided **lexically**, never by touching the filesystem.
/// `canonicalize` would make the verdict depend on what exists and on what is
/// mounted, so the same `plan` would differ between two machines and between
/// two runs on one — which invariant 3 forbids. The price is that lexical `..`
/// normalisation is unsound across a symlink: `<root>/link/../x`, where `link`
/// points outside the root, is judged inside it, and so is a declared root that
/// is itself a symlink to `/`. That is accepted rather than fixed, because the
/// only fix is the one invariant 3 rules out.
///
/// Containment is also **one-directional**: a value inside a root is admitted,
/// and a value that *contains* a root — `~/.local/state`, the parent of bx's
/// own directory — is judged by where it points, not by what lies beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSet {
    home: Option<PathBuf>,
    roots: Vec<PathBuf>,
    inadmissible: Vec<PathBuf>,
    owned: Vec<PathBuf>,
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
            inadmissible: Vec::new(),
            owned: Vec::new(),
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
        let owned = vec![paths::normalize(&layers::state_dir(&home, None))];
        Self {
            home: Some(home),
            roots: admitted,
            inadmissible,
            owned,
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

    /// Whether `path` is a directory bx owns, or lies inside one.
    ///
    /// bx's state directory holds the ledger, the fingerprints and the journal:
    /// the record that makes invariant 4 true. A tool pointed into it writes
    /// among those files, and `bx rm` would then restore a home by deleting a
    /// directory another tool believes is its own. So this is checked **before**
    /// containment and outranks it — a user may declare their home a root, and
    /// `XDG_STATE_HOME=~/.local/state/bx` is still refused.
    #[must_use]
    pub fn owns(&self, path: &Path) -> bool {
        let normalised = paths::normalize(path);
        self.owned.iter().any(|dir| normalised.starts_with(dir))
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
    fn refuses_everything(&self) -> Option<Reason> {
        match (self.roots.is_empty(), self.inadmissible.is_empty()) {
            (false, _) => None,
            (true, true) => Some(Reason::NoRootsDeclared),
            (true, false) => Some(Reason::InadmissibleRoot),
        }
    }
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
/// The configuration layer does **not** refuse such a value: a `path` value of
/// `/` is accepted there. This floor is therefore the only one, which is why a
/// refused root is logged at error level — the level `bx` reports with `BX_LOG`
/// unset — and changes the verdict rather than only narrowing the set.
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

/// Why a relocating assignment was rejected.
///
/// Each names a different user action — declare a root, fix the declared root,
/// split the line, write the line in a form the guard reads, move the value out
/// of bx's own directory, move it inside a declared root, give a location
/// variable a path, write an absolute path, define the referenced variable
/// earlier, fix the line that assigned it, shorten it — so a caller that only
/// knew *which* variable was rejected could not say what to do about it. The
/// messages name no data: the caller already holds the value and the root set,
/// and prints them itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    /// Nothing was declared, so nothing may be relocated.
    #[error("no root is declared, so nothing may be relocated")]
    NoRootsDeclared,
    /// Roots were declared, and every one of them was refused.
    #[error(
        "every declared root was refused — the filesystem root, a relative path, \
         or one that climbs — so nothing may be relocated"
    )]
    InadmissibleRoot,
    /// The line assigns more than one variable.
    #[error("puts more than one assignment on one line")]
    MultipleAssignments,
    /// Shell the guard does not read, so it cannot approve it: a command
    /// substitution, an escape, an operator, a parameter expansion other than
    /// `$NAME` and `${NAME}`, a keyword option it does not know, or a statement
    /// that is not one of the forms [`scan_with`] reads.
    #[error("is shell the guard cannot read, so it is not approved")]
    Unreadable,
    /// It points at a directory bx owns, whatever the roots say.
    #[error("points inside a directory bx owns")]
    BxOwnedDirectory,
    /// It resolves to a path, but not one inside any declared root.
    #[error("resolves outside every declared root")]
    OutsideDeclaredRoots,
    /// Not a path at all, for a variable whose name says it holds one.
    #[error("is not a path, though the variable's name says it holds a location")]
    NotAPath,
    /// Empty, relative, or `~user` — it is shaped like a path, but not one
    /// that can be shown to be inside a root.
    #[error("is not an absolute path")]
    NotAbsolute,
    /// It names a variable this fragment has not assigned by this line.
    #[error("refers to a variable this fragment has not assigned")]
    UnresolvedReference,
    /// It names a variable whose assignment the guard could not read.
    #[error("refers to a variable whose assignment the guard could not read")]
    UnreadableReference,
    /// Its expansion grows past [`MAX_EXPANDED_LEN`].
    #[error("expands past the guard's length bound")]
    ExpansionTooLong,
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
    ///
    /// Empty for a line refused as [`Reason::Unreadable`] before any one
    /// variable could be picked out of it.
    pub name: String,
    /// The value as written, before quote stripping and expansion, so a
    /// diagnostic can quote the line back exactly as the user will see it.
    ///
    /// For a line refused before any one variable could be picked out of it,
    /// the line itself.
    pub value: String,
    /// Why the assignment was rejected.
    pub reason: Reason,
}

/// Whether bx may assign `value` to `name`, given the roots `roots` declares.
///
/// `value` is the value **as a shell would read it** after `name=`: quotes are
/// its quotes, and a blank outside them ends it. So the value is first read as
/// one shell word, for every variable — a second word after it is a second
/// assignment or a command, and is refused however harmless the first. Past
/// that, a variable that does not relocate anything is allowed without its
/// value being looked at, so `EDITOR=nvim` and `SCCACHE_CACHE_SIZE=100G` can
/// never trip a path rule. A relocating variable is allowed exactly when its
/// value resolves to a path inside a declared root.
///
/// This is the same function [`scan_with`] calls for every assignment it reads,
/// so the two cannot disagree about one. No `$VAR` reference resolves here
/// except `$HOME`: `check` judges one assignment in isolation and has no
/// fragment to learn from.
#[must_use]
pub fn check(name: &str, value: &str, roots: &RootSet) -> Verdict {
    match evaluate(name, value, &Assignments::new(), roots).reason {
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
/// One forward pass. Every assignment the pass reads — exported or not — is
/// recorded, **expanded**, so a later line may refer to it: the generated
/// `.zshenv` is written in terms of a declared root variable, and a guard that
/// could not resolve `$SCRATCH_HOME` would either reject every fragment bx
/// generates or check nothing at all. A reference to a variable assigned
/// *later* in the file is unresolved, because a shell would not have it either;
/// order-dependence here is correctness.
///
/// Nothing is read from the process environment and nothing is read from disk.
/// `$HOME` comes from `roots`, never from [`std::env`], and the roots are held
/// in declaration order, so this is a pure function of `(content, roots)` and
/// two calls on the same arguments return the same violations. That is what
/// lets `plan` call it without becoming machine-dependent (invariant 3).
///
/// **What is read.** Each line is split into shell words — quotes, `$(…)`,
/// `${…}` and a `NAME=(…)` array are kept whole, and an unquoted `#` beginning
/// a word starts a comment. A line is then one of:
///
/// * `NAME=value` or `NAME+=value`;
/// * a keyword — `export`, `declare`, `typeset`, `readonly`, `local`,
///   `integer`, `float` — with options drawn from `-x`, `-g`, `-r` and `--`,
///   followed by one `NAME` or `NAME=value`;
/// * `setenv NAME value`.
///
/// **What is refused.** A line that mentions one of those keywords anywhere, or
/// has an assignment where a command would start, and is *not* one of the
/// forms above — several operands, another option, an operator such as `&&`
/// or `;`, a keyword after a command such as `builtin export`, a quote that
/// does not close — is [`Reason::Unreadable`] or
/// [`Reason::MultipleAssignments`], whatever its names. The guard does not
/// parse such a line, and it does not approve it either. A refused line teaches
/// the pass nothing: every name it mentions becomes one a later reference
/// cannot resolve.
///
/// **What is out of scope.** A line with no keyword and no assignment in
/// command position is a command, and assigns nothing the guard judges:
/// `source`, `eval`, `alias`, `read`, `for`. Content bx merely *copies* from
/// another tool (a cached `mise activate` block, say) is that tool's business
/// and is not scanned. A statement continued onto the next line is judged line
/// by line, which refuses rather than misreads it.
#[must_use]
pub fn scan_with(content: &str, roots: &RootSet) -> Vec<Violation> {
    let mut found = Vec::new();
    let mut seen = Assignments::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        let violation = |name: &str, value: &str, reason| Violation {
            line: idx + 1,
            name: name.to_string(),
            value: value.to_string(),
            reason,
        };
        match statement(line) {
            Statement::Nothing => {}
            Statement::Refused {
                name,
                value,
                reason,
            } => {
                found.push(violation(name, value, reason));
                forget_names_in(line, &mut seen);
            }
            Statement::Assign {
                name,
                value,
                append,
            } => {
                // `NAME+=value` is `NAME=${NAME}value`: its result starts with
                // whatever the name held before, which is exactly what a
                // reference resolves.
                let written = match value {
                    Some(value) if append => Some(format!("${{{name}}}{value}")),
                    Some(value) => Some(value.to_string()),
                    // A valueless `export NAME` still has to be judged — an
                    // inherited value is no more a declared root than an empty
                    // one — and `""` is what it is judged as.
                    None => None,
                };
                let judged = evaluate(name, written.as_deref().unwrap_or(""), &seen, roots);
                if let Some(reason) = judged.reason {
                    found.push(violation(name, value.unwrap_or(""), reason));
                }
                // Learn the assignment only *after* judging it, as a shell does:
                // the right-hand side sees the previous value of the name, not
                // this one. A line that assigned no value teaches nothing:
                // `export X` marks an inherited value for export and does not
                // set one. `$HOME` is the one name that may come from outside
                // the fragment.
                if written.is_some() {
                    match judged.resolved {
                        Ok(resolved) => {
                            seen.insert(name.to_string(), Ok(resolved));
                        }
                        Err(reason) => {
                            if matches!(reason, Reason::MultipleAssignments | Reason::Unreadable) {
                                forget_names_in(line, &mut seen);
                            }
                            seen.insert(name.to_string(), Err(as_reference(reason)));
                        }
                    }
                }
            }
        }
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

/// What [`evaluate`] found: the verdict, and what the value expands to.
struct Judged {
    /// Why the assignment may not be written, or `None` if it may.
    reason: Option<Reason>,
    /// The value a shell would give the name, or why it cannot be known. This
    /// is what a later reference to the name resolves to.
    resolved: Result<String, Reason>,
}

/// The verdict on `name = value`, for [`check`] and [`scan_with`] alike.
fn evaluate(name: &str, value: &str, seen: &Assignments, roots: &RootSet) -> Judged {
    // The shape of the value is read for every variable: a second word is a
    // second assignment or a command, and a head the name lists do not know
    // must not carry it past the guard.
    let word = match value_word(value) {
        Ok(word) => word,
        Err(reason) => {
            return Judged {
                reason: Some(reason),
                resolved: Err(reason),
            };
        }
    };
    let resolved = resolve(&word, seen, roots.home());
    let judged = |reason| Judged {
        reason,
        resolved: resolved.clone(),
    };

    if !is_relocating(name) {
        return judged(None);
    }
    // An empty value is a degenerate path, not a non-path: `export CARGO_HOME`
    // with nothing after it does relocate the tool, to nowhere.
    let not_a_path = !word.text.is_empty() && !path_shaped(&word.text);
    // A value that is no kind of path, for a variable whose name does not say
    // it holds a location, is a behaviour setting: it relocates nothing, so it
    // needs no root — `MISE_JOBS=8` is allowed with none declared.
    if not_a_path && !names_a_location(name) {
        return judged(None);
    }
    // A set with no admissible root permits no relocation, and is the only set
    // without a home — so past this point there is always a home.
    if let Some(reason) = roots.refuses_everything() {
        return judged(Some(reason));
    }
    if word.opaque {
        return judged(Some(Reason::Unreadable));
    }
    if not_a_path {
        return judged(Some(Reason::NotAPath));
    }
    let path = match &resolved {
        Ok(resolved) => PathBuf::from(resolved),
        Err(reason) => return judged(Some(*reason)),
    };
    if !path.is_absolute() {
        return judged(Some(Reason::NotAbsolute));
    }
    // Before the root test, and therefore ahead of any declaration: a root the
    // user declared widens where tools may live, never who owns bx's own state.
    if roots.owns(&path) {
        return judged(Some(Reason::BxOwnedDirectory));
    }
    if roots.contains(&path) {
        judged(None)
    } else {
        judged(Some(Reason::OutsideDeclaredRoots))
    }
}

/// Variable values learned during one pass over a fragment: what each name
/// expands to, or why the guard cannot know.
type Assignments = std::collections::HashMap<String, Result<String, Reason>>;

/// The reason a *reference* to a name reports, given why the name's own value
/// could not be known.
fn as_reference(reason: Reason) -> Reason {
    match reason {
        Reason::UnresolvedReference | Reason::ExpansionTooLong => reason,
        _ => Reason::UnreadableReference,
    }
}

/// Mark every name `line` might assign as one a later reference cannot resolve.
///
/// For a line the guard refused to read. It does not know what such a line
/// assigns, so it forgets rather than guesses: any word that is a variable name,
/// or begins with one followed by `=` or `+=`, is forgotten.
fn forget_names_in(line: &str, seen: &mut Assignments) {
    let separators = |c: char| c.is_whitespace() || ";&|(){}!`\"'".contains(c);
    for chunk in line.split(separators) {
        let ident = chunk
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map_or(chunk, |end| &chunk[..end]);
        let rest = &chunk[ident.len()..];
        if is_variable_name(ident)
            && (rest.is_empty() || rest.starts_with('=') || rest.starts_with("+="))
        {
            seen.insert(ident.to_string(), Err(Reason::UnreadableReference));
        }
    }
}

/// How long an expansion may grow before it is refused.
///
/// The expander's bound on work. Values are learned expanded, so a line that
/// doubles a variable — `X=$X$X` — doubles what is stored, and a fragment of a
/// few dozen such lines would otherwise hold gigabytes.
const MAX_EXPANDED_LEN: usize = 4096;

/// How deeply `$(`, `${` and quotes may nest inside one word before the line is
/// refused. The word reader's bound on recursion.
const MAX_NESTING: usize = 32;

/// Expand `$NAME` and `${NAME}` in `raw` from `seen`, plus `$HOME` from `home`.
///
/// The grammar is closed and is the whole of it: `$NAME` and `${NAME}` where
/// `NAME` is a shell-legal variable name. A `$` followed by anything that
/// cannot begin a name is literal text. A `${` that does not close on a name —
/// `${}`, `${X:-y}`, `${X` — is not text to any shell, and is refused as
/// [`Reason::Unreadable`]. There is no backslash escape, no word splitting and
/// no second pass: values are learned already expanded, so substituted text is
/// never expanded again, as a shell never expands it again.
fn expand(raw: &str, seen: &Assignments, home: Option<&Path>) -> Result<String, Reason> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;

    // This pass's own bound, and the reason it is a `for` rather than a
    // `while`: every iteration consumes at least the `$` it found, so `rest`
    // strictly shrinks and there can be no more iterations than the value has
    // bytes. Without it, a refactor that stopped consuming the `$` would spin
    // here forever and hang `bx plan`, rather than return a wrong answer a test
    // can see.
    for _ in 0..raw.len() {
        let Some(at) = rest.find('$') else { break };
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];

        let (name, tail) = match after.strip_prefix('{') {
            Some(braced) => match braced.find('}') {
                Some(end) if is_variable_name(&braced[..end]) => {
                    (&braced[..end], &braced[end + 1..])
                }
                _ => return Err(Reason::Unreadable),
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
        match seen.get(name) {
            Some(Ok(learned)) => out.push_str(learned),
            Some(Err(reason)) => return Err(*reason),
            None => match home {
                Some(home) if name == "HOME" => out.push_str(&home.to_string_lossy()),
                _ => return Err(Reason::UnresolvedReference),
            },
        }
        if out.len() > MAX_EXPANDED_LEN {
            return Err(Reason::ExpansionTooLong);
        }
        rest = tail;
    }
    out.push_str(rest);
    Ok(out)
}

/// What a value expands to, as a shell would give it to the name.
fn resolve(word: &Word, seen: &Assignments, home: Option<&Path>) -> Result<String, Reason> {
    if word.opaque {
        return Err(Reason::Unreadable);
    }
    let expanded = if word.expands {
        expand(&word.text, seen, home)?
    } else {
        word.text.clone()
    };
    // A shell expands `~` only where it is written, unquoted, at the start of
    // the value. `"~/x"`, and a `~` that arrived through a reference, are the
    // literal character — and a relative path.
    match home {
        Some(home) if word.tilde => Ok(paths::render(&expanded, home)
            .to_string_lossy()
            .into_owned()),
        None if word.tilde => Err(Reason::UnresolvedReference),
        _ => Ok(expanded),
    }
}

/// Whether `value` is shaped like a path at all.
///
/// Shaped like a path means: absolute, `~`-relative, containing a `$` that may
/// name one, or containing a `/` without a `://` — a URL has slashes and is
/// still not a path. Everything else is a number, a flag or a word, which for a
/// variable whose name does not say it holds a location is a behaviour setting.
fn path_shaped(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('~')
        || value.contains('$')
        || (value.contains('/') && !value.contains("://"))
}

/// One shell word's value, with its quoting removed.
#[derive(Debug, Clone, Default)]
struct Word {
    /// The text with quotes removed; references not yet expanded.
    text: String,
    /// Whether `$` references in `text` expand: false for single quotes.
    expands: bool,
    /// Whether the word begins with an unquoted `~`, which a shell expands.
    tilde: bool,
    /// Whether it holds something this guard does not evaluate: a command
    /// substitution, a backslash escape, a brace expansion, an array, or
    /// single quotes mixed with other text.
    opaque: bool,
}

/// Read the value written after `NAME=` as exactly one shell word.
///
/// An empty value is the empty word. A value that starts with a blank is an
/// empty assignment followed by a command, and a value of more than one word is
/// a second assignment or a command: neither is a value.
fn value_word(value: &str) -> Result<Word, Reason> {
    let bytes = value.as_bytes();
    // The value's own word begins at its first byte, so a `#` there is text,
    // not a comment, and a `(` there opens an array. A blank there ends it at
    // once: the value is empty and whatever follows is not part of it.
    let end = match bytes.first() {
        None => return Ok(Word::default()),
        Some(b'(') => closing(bytes, 1, b')', 0),
        Some(_) => word_end(bytes, 0),
    }
    .ok_or(Reason::Unreadable)?;
    let rest = tokens(&value[end..]).ok_or(Reason::Unreadable)?;
    if rest.compound {
        return Err(Reason::Unreadable);
    }
    if !rest.words.is_empty() {
        return Err(
            if rest.words.iter().any(|w| assigned_name(w.raw).is_some()) {
                Reason::MultipleAssignments
            } else {
                Reason::Unreadable
            },
        );
    }
    Ok(dequote(&value[..end]))
}

/// Remove a word's quoting.
///
/// Called only on a word [`tokens`] has already read, so every quote closes.
fn dequote(raw: &str) -> Word {
    let opaque = Word {
        opaque: true,
        ..Word::default()
    };
    let mut text = String::with_capacity(raw.len());
    let (mut single, mut other) = (false, false);
    let mut rest = raw;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('\'') {
            let end = after.find('\'').unwrap_or(after.len());
            text.push_str(&after[..end]);
            single = true;
            rest = after.get(end + 1..).unwrap_or("");
        } else if let Some(after) = rest.strip_prefix('"') {
            let end = after.find('"').unwrap_or(after.len());
            let inner = &after[..end];
            if inner.contains(['\\', '`']) || inner.contains("$(") {
                return opaque;
            }
            text.push_str(inner);
            other = true;
            rest = after.get(end + 1..).unwrap_or("");
        } else {
            let end = rest.find(['\'', '"']).unwrap_or(rest.len());
            let bare = &rest[..end];
            // `(` covers `$(…)`, `$((…))` and an array; a `{` that does not
            // open `${` is brace expansion, which bash applies to an `export`
            // argument and turns one word into several.
            let brace_expansion = bare
                .match_indices('{')
                .any(|(at, _)| !bare[..at].ends_with('$'));
            if bare.contains(['\\', '`', '(']) || brace_expansion {
                return opaque;
            }
            text.push_str(bare);
            other = true;
            rest = &rest[end..];
        }
    }
    if single && other {
        // `'$A'/x` expands one part and not the other; a single flag cannot say
        // which, so the word is not evaluated.
        return opaque;
    }
    Word {
        text,
        expands: !single,
        tilde: raw.starts_with('~'),
        opaque: false,
    }
}

/// Keywords that assign a variable. A line mentioning one anywhere is judged
/// or refused, never ignored.
const KEYWORDS: &[&str] = &[
    "export", "declare", "typeset", "readonly", "local", "integer", "float", "setenv",
];

/// Reserved words after which the next word still begins a command.
const RESERVED: &[&str] = &[
    "!", "{", "if", "then", "elif", "else", "do", "while", "until", "time",
];

/// What one line of a fragment is, to the guard.
#[derive(Debug, PartialEq, Eq)]
enum Statement<'a> {
    /// A command, a comment, or nothing: it assigns nothing the guard judges.
    Nothing,
    /// One assignment: `value` as written, or `None` for `export NAME`.
    Assign {
        name: &'a str,
        value: Option<&'a str>,
        append: bool,
    },
    /// A line refused as a whole.
    Refused {
        name: &'a str,
        value: &'a str,
        reason: Reason,
    },
}

/// Read one trimmed line as a [`Statement`].
fn statement(line: &str) -> Statement<'_> {
    let Some(tokens) = tokens(line) else {
        // A quote that never closes, or nesting past the bound. Refused if it
        // could be an assignment at all.
        let mentions = line
            .split(|c: char| c.is_whitespace() || ";&|(){}!".contains(c))
            .any(|chunk| KEYWORDS.contains(&chunk) || assigned_name(chunk).is_some());
        return if mentions {
            Statement::Refused {
                name: "",
                value: line,
                reason: Reason::Unreadable,
            }
        } else {
            Statement::Nothing
        };
    };
    let triggered = tokens.words.iter().any(|word| {
        KEYWORDS.contains(&word.raw) || (word.command && assigned_name(word.raw).is_some())
    });
    if !triggered {
        return Statement::Nothing;
    }
    let content = line[..tokens.end].trim_end();
    let unreadable = Statement::Refused {
        name: "",
        value: content,
        reason: Reason::Unreadable,
    };
    if tokens.compound {
        return unreadable;
    }
    let words = &tokens.words;
    // `triggered` guarantees a word.
    let first = words[0].raw;
    let after = |word: &RawWord| content[word.start + word.raw.len()..].trim();

    if first == "setenv" {
        return match words.get(1) {
            None => Statement::Nothing,
            Some(name) if is_variable_name(name.raw) => {
                let value = after(name);
                Statement::Assign {
                    name: name.raw,
                    value: Some(value),
                    append: false,
                }
            }
            Some(_) => unreadable,
        };
    }

    let mut at = 0;
    if KEYWORDS.contains(&first) {
        at = 1;
        while let Some(word) = words.get(at) {
            if word.raw == "--" {
                at += 1;
                break;
            }
            if !word.raw.starts_with(['-', '+']) {
                break;
            }
            // `-x`, `-g` and `-r` change where a value is visible, never what it
            // is. Every other option — `-n` nameref, `-u` upper-casing, `-a`
            // array, `+x` — changes what the name means or holds.
            match word.raw.strip_prefix('-') {
                Some(flags) if !flags.is_empty() && flags.chars().all(|c| "xgr".contains(c)) => {
                    at += 1;
                }
                _ => return unreadable,
            }
        }
        if at == words.len() {
            // `export` or `declare -x` alone lists; it assigns nothing.
            return Statement::Nothing;
        }
    }

    let operand = &words[at];
    if let Some((name, append)) = assigned_name(operand.raw) {
        let skip = name.len() + if append { 2 } else { 1 };
        return Statement::Assign {
            name,
            value: Some(&content[operand.start + skip..]),
            append,
        };
    }
    if at > 0 && is_variable_name(operand.raw) {
        let extra = &words[at + 1..];
        return match extra.first() {
            None => Statement::Assign {
                name: operand.raw,
                value: None,
                append: false,
            },
            Some(next) => Statement::Refused {
                name: operand.raw,
                value: &content[next.start..],
                reason: if extra
                    .iter()
                    .any(|w| is_variable_name(w.raw) || assigned_name(w.raw).is_some())
                {
                    Reason::MultipleAssignments
                } else {
                    Reason::Unreadable
                },
            },
        };
    }
    unreadable
}

/// The name a word assigns, and whether it appends: `NAME=…` or `NAME+=…`.
fn assigned_name(word: &str) -> Option<(&str, bool)> {
    let (head, _) = word.split_once('=')?;
    match head.strip_suffix('+') {
        Some(name) if is_variable_name(name) => Some((name, true)),
        _ if is_variable_name(head) => Some((head, false)),
        _ => None,
    }
}

/// One word of a line, as written.
#[derive(Debug)]
struct RawWord<'a> {
    raw: &'a str,
    /// Byte offset of the word in the text it was read from.
    start: usize,
    /// Whether the word is where a command begins.
    command: bool,
}

/// A line read into words.
#[derive(Debug)]
struct Tokens<'a> {
    words: Vec<RawWord<'a>>,
    /// Whether an unquoted operator — `;`, `&`, `|`, `<`, `>`, `(`, `)` — made
    /// the line more than one simple statement.
    compound: bool,
    /// Where the line's content ends: its length, or where a comment starts.
    end: usize,
}

/// Split `text` into shell words, or `None` if a quote or a nested
/// construct does not close.
///
/// This finds where words begin and end and nothing more. The special
/// characters are all ASCII, so byte offsets are always character boundaries.
fn tokens(text: &str) -> Option<Tokens<'_>> {
    let bytes = text.as_bytes();
    let mut words = Vec::new();
    let mut compound = false;
    let mut command = true;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => i += 1,
            b'#' => {
                return Some(Tokens {
                    words,
                    compound,
                    end: i,
                });
            }
            b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')' => {
                compound = true;
                command = true;
                i += 1;
            }
            _ => {
                let start = i;
                i = word_end(bytes, i)?;
                let raw = &text[start..i];
                words.push(RawWord {
                    raw,
                    start,
                    command,
                });
                command = command && RESERVED.contains(&raw);
            }
        }
    }
    Some(Tokens {
        words,
        compound,
        end: bytes.len(),
    })
}

/// Where the word starting at `i` ends.
fn word_end(bytes: &[u8], mut i: usize) -> Option<usize> {
    let start = i;
    while let Some(&byte) = bytes.get(i) {
        i = match byte {
            b' ' | b'\t' | b';' | b'&' | b'|' | b'<' | b'>' | b')' => break,
            // `NAME=(…)` keeps its parentheses; anywhere else `(` is an
            // operator and ends the word.
            b'(' if std::str::from_utf8(&bytes[start..i])
                .ok()
                .and_then(|head| head.strip_suffix('='))
                .is_some_and(is_variable_name) =>
            {
                closing(bytes, i + 1, b')', 0)?
            }
            b'(' => break,
            _ => past_quoting(bytes, i, 0)?,
        };
    }
    Some(i)
}

/// Step past the byte at `i`, or past the whole quoted or nested construct it
/// opens.
fn past_quoting(bytes: &[u8], i: usize, depth: usize) -> Option<usize> {
    if depth > MAX_NESTING {
        return None;
    }
    match (bytes[i], bytes.get(i + 1)) {
        (b'\'', _) => Some(i + 1 + bytes[i + 1..].iter().position(|&b| b == b'\'')? + 1),
        (b'"', _) => double_quoted(bytes, i + 1, depth + 1),
        (b'`', _) => {
            let mut j = i + 1;
            loop {
                match bytes.get(j)? {
                    b'`' => return Some(j + 1),
                    b'\\' => j += 2,
                    _ => j += 1,
                }
            }
        }
        (b'\\', Some(_)) => Some(i + 2),
        (b'\\', None) => None,
        (b'$', Some(b'(')) => closing(bytes, i + 2, b')', depth + 1),
        (b'$', Some(b'{')) => closing(bytes, i + 2, b'}', depth + 1),
        _ => Some(i + 1),
    }
}

/// Where a double-quoted string whose content starts at `i` ends.
fn double_quoted(bytes: &[u8], mut i: usize, depth: usize) -> Option<usize> {
    loop {
        i = match bytes.get(i)? {
            b'"' => return Some(i + 1),
            b'\\' => i + 2,
            b'`' | b'$' => past_quoting(bytes, i, depth)?,
            _ => i + 1,
        };
    }
}

/// Where a `(…)` or `{…}` whose content starts at `i` ends, counting nested
/// pairs and stepping over quotes.
fn closing(bytes: &[u8], mut i: usize, close: u8, depth: usize) -> Option<usize> {
    let open = if close == b')' { b'(' } else { b'{' };
    let mut pairs = 1usize;
    loop {
        let byte = *bytes.get(i)?;
        if byte == close {
            pairs -= 1;
            if pairs == 0 {
                return Some(i + 1);
            }
            i += 1;
        } else if byte == open {
            pairs += 1;
            i += 1;
        } else {
            i = past_quoting(bytes, i, depth)?;
        }
    }
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
                reason_of(&check("XDG_CONFIG_HOME", "/etc", &roots)),
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
        let verdict = check(
            "CARGO_HOME",
            "/var/mnt/scratch/example/cache/cargo",
            &rooted(),
        );
        assert_eq!(verdict, Verdict::Allowed);
        assert_eq!(reason_of(&verdict), None);
    }

    #[test]
    fn a_relocating_variable_outside_every_root_is_a_violation() {
        // The violation carries everything a diagnostic needs to say what to
        // do about it. `check` judges one assignment outside any content, so
        // there is no line to report.
        assert_eq!(
            check("CARGO_HOME", "/var/cache/elsewhere", &rooted()),
            Verdict::Violation(Violation {
                line: 0,
                name: "CARGO_HOME".into(),
                value: "/var/cache/elsewhere".into(),
                reason: Reason::OutsideDeclaredRoots,
            })
        );
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
    fn a_value_that_is_no_kind_of_path_says_so_rather_than_asking_for_an_absolute_one() {
        // Every one of these has a name that says it holds a location and a
        // value that is no kind of path. Told that the value "is not an
        // absolute path", a user would reach for a directory without asking
        // whether the variable was meant to hold one.
        for (name, value) in [
            ("CARGO_HOME", "1"),
            ("SOMETOOL_CONFIG_DIR", "yes"),
            ("NPM_CONFIG_CACHE", "npm"),
            ("PIP_TARGET", "build"),
            ("UV_PROJECT_ENVIRONMENT", "venv"),
        ] {
            assert!(is_relocating(name), "{name}");
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(Reason::NotAPath),
                "{name}"
            );
        }
        // A prefix-family name that does not say so is a behaviour setting,
        // and so is pip's `--no-cache-dir` switch, which a suffix catches.
        for (name, value) in [
            ("PIP_TIMEOUT", "60"),
            ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
            ("UV_NO_CACHE", "1"),
            ("MISE_QUIET", "1"),
            ("PIP_NO_CACHE_DIR", "1"),
        ] {
            assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
        }
        // And the reason a user can act on is kept for values that really are
        // paths, where making it absolute is the right thing to do.
        for value in ["cache/cargo", "~other/cargo", "$HOME/../x"] {
            assert_ne!(
                reason_of(&check("PIP_CACHE_DIR", value, &rooted())),
                Some(Reason::NotAPath),
                "{value}"
            );
        }
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
    fn bxs_own_state_directory_is_refused_even_inside_a_declared_root() {
        // The configuration that makes this reachable is the supported one:
        // the user declared their home a root, so containment alone would
        // allow it. `~/.local/state/bx` is where the ledger, the fingerprints
        // and the journal live; a tool pointed there writes among the files
        // that make `bx rm` exact.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for value in [
            "/var/home/example/.local/state/bx",
            "/var/home/example/.local/state/bx/ledger",
            "~/.local/state/bx",
            "$HOME/.local/state/bx/journal",
        ] {
            assert_eq!(
                reason_of(&check("XDG_STATE_HOME", value, &home_rooted)),
                Some(Reason::BxOwnedDirectory),
                "{value}"
            );
        }
        // The parent, and a sibling whose name merely extends it, are not bx's.
        assert_eq!(
            check("XDG_STATE_HOME", "~/.local/state", &home_rooted),
            Verdict::Allowed
        );
        assert_eq!(
            check("XDG_STATE_HOME", "~/.local/state/bxtra", &home_rooted),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_state_directory_moved_by_the_environment_is_owned_when_it_is_declared() {
        // `RootSet::new` derives the state directory from the home, because a
        // resolution path may not read `XDG_STATE_HOME` itself. A caller that
        // did read it says so, and the derived one stays owned as well.
        let moved = PathBuf::from("/var/mnt/scratch/example/state/bx");
        let roots = rooted().owning(std::slice::from_ref(&moved));
        assert_eq!(
            reason_of(&check(
                "XDG_STATE_HOME",
                "/var/mnt/scratch/example/state/bx",
                &roots
            )),
            Some(Reason::BxOwnedDirectory)
        );
        // Inside the declared root, and still refused - the exclusion outranks
        // the root test rather than being overridden by it.
        assert!(roots.contains(&moved));
        // And the home-derived directory is owned too, though this set's own
        // root does not contain it.
        assert!(roots.owns(Path::new("/var/home/example/.local/state/bx")));
    }

    #[test]
    fn a_variable_that_does_not_relocate_may_still_name_bxs_directory() {
        // The exclusion is part of the relocation verdict, not a second rule
        // over every value: a tool told where bx's own state is has not been
        // moved there.
        assert_eq!(
            check(
                "EDITOR",
                "/var/home/example/.local/state/bx/editor",
                &rooted()
            ),
            Verdict::Allowed
        );
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
        assert_eq!(
            Reason::BxOwnedDirectory.to_string(),
            "points inside a directory bx owns"
        );
        assert_eq!(
            Reason::NotAPath.to_string(),
            "is not a path, though the variable's name says it holds a location"
        );
        assert_eq!(Reason::NotAbsolute.to_string(), "is not an absolute path");
        assert_eq!(
            Reason::UnresolvedReference.to_string(),
            "refers to a variable this fragment has not assigned"
        );
        assert_eq!(
            Reason::InadmissibleRoot.to_string(),
            "every declared root was refused — the filesystem root, a relative \
             path, or one that climbs — so nothing may be relocated"
        );
        assert_eq!(
            Reason::MultipleAssignments.to_string(),
            "puts more than one assignment on one line"
        );
        assert_eq!(
            Reason::Unreadable.to_string(),
            "is shell the guard cannot read, so it is not approved"
        );
        assert_eq!(
            Reason::UnreadableReference.to_string(),
            "refers to a variable whose assignment the guard could not read"
        );
        assert_eq!(
            Reason::ExpansionTooLong.to_string(),
            "expands past the guard's length bound"
        );
    }

    // `scan_with` — the same rule over a whole fragment, with a learned
    // environment.

    #[test]
    fn scan_denies_every_relocation_and_nothing_else() {
        // What the strict guard actually returns, written out. Comparing
        // `scan` against `scan_with(_, &RootSet::strict())` is `scan`'s own
        // definition and cannot fail, so it shows nothing.
        //
        // This is not the name-based guard's output either: six widened names
        // are denied here that it allowed. What survives from it is the
        // direction — with no root declared, every relocating assignment is
        // refused and nothing else is touched.
        for (content, expected) in [
            ("export EDITOR=nvim\n", vec![]),
            ("export SCCACHE_CACHE_SIZE=100G\n", vec![]),
            ("# export CARGO_HOME=/x\n", vec![]),
            ("source ~/.cargo/env\n", vec![]),
            ("export CARGO_HOME=$HOME/x\n", vec![(1, "CARGO_HOME")]),
            (
                "setenv GOPATH /x\nsource ~/.cargo/env\n",
                vec![(1, "GOPATH")],
            ),
            // Widened: the name-based guard let this one through unchecked.
            ("export GOCACHE=/x\n", vec![(1, "GOCACHE")]),
            (
                "export XDG_CONFIG_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n",
                vec![(1, "XDG_CONFIG_HOME"), (3, "RUSTUP_HOME")],
            ),
        ] {
            let found = scan(content);
            assert_eq!(
                found
                    .iter()
                    .map(|violation| (violation.line, violation.name.as_str()))
                    .collect::<Vec<_>>(),
                expected,
                "{content}"
            );
            assert!(
                found
                    .iter()
                    .all(|violation| violation.reason == Reason::NoRootsDeclared),
                "{content}"
            );
        }
    }

    #[test]
    fn a_second_assignment_on_one_line_is_refused_rather_than_half_judged() {
        // A real shell exports both names. Judging the head alone allowed the
        // tail unread: this line is clean to a guard that stops at the first
        // value, and `GOPATH` lands outside every root. The name-based guard
        // this replaced denied the line, so allowing it would invert the
        // guard's error direction between two commits.
        let content = "export CARGO_HOME=/var/mnt/scratch/example/cargo GOPATH=/etc/evil\n";
        assert_eq!(
            scan_with(content, &rooted()),
            vec![Violation {
                line: 1,
                name: "CARGO_HOME".into(),
                value: "/var/mnt/scratch/example/cargo GOPATH=/etc/evil".into(),
                reason: Reason::MultipleAssignments,
            }]
        );
        // The head need not relocate anything for the tail to matter.
        let content = "export EDITOR=nvim GOPATH=/etc/evil\n";
        assert_eq!(
            scan_with(content, &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::MultipleAssignments]
        );
    }

    #[test]
    fn a_valueless_export_teaches_the_scan_nothing() {
        // `export X` marks an inherited value for export; it does not set `X`
        // to the empty string. Learned as empty, `$X/...` resolved to a path
        // inside the root and the fragment scanned clean — while on a machine
        // where `X` is `/tmp` the shell writes a `CARGO_HOME` outside every
        // root. An absent name is unresolved, which is the safe direction.
        let content = concat!(
            "export X\n",
            "export CARGO_HOME=$X/var/mnt/scratch/example/cargo\n",
        );
        let found = scan_with(content, &rooted());
        assert_eq!(
            found
                .iter()
                .map(|violation| (violation.line, violation.reason))
                .collect::<Vec<_>>(),
            vec![(2, Reason::UnresolvedReference)]
        );

        // The valueless form is still judged when the name itself relocates.
        assert_eq!(
            scan_with("export CARGO_HOME\n", &rooted())
                .iter()
                .map(|violation| (violation.line, violation.reason))
                .collect::<Vec<_>>(),
            vec![(1, Reason::NotAbsolute)]
        );

        // `setenv NAME value` does assign, and is still learned.
        let content = concat!(
            "setenv SCRATCH_HOME /var/mnt/scratch/example\n",
            "export CARGO_HOME=$SCRATCH_HOME/cargo\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn a_refused_line_teaches_the_scan_nothing() {
        // The head's "value" is not the value any shell would give the name,
        // so learning it would resolve a later reference to a fiction.
        let content = concat!(
            "A=/var/mnt/scratch/example B=/etc\n",
            "export CARGO_HOME=$A/cargo\n",
        );
        let found = scan_with(content, &rooted());
        assert_eq!(
            found
                .iter()
                .map(|violation| (violation.line, violation.reason))
                .collect::<Vec<_>>(),
            vec![
                (1, Reason::MultipleAssignments),
                (2, Reason::UnreadableReference),
            ]
        );
        // Nor may it leave an *earlier* value standing: a shell has replaced
        // it, so a guard that kept it would judge a path no shell produces.
        for refused in [
            "A=/etc B=1",
            "true && A=/etc",
            "export B A=/etc",
            "declare -n A=OTHER",
        ] {
            let content = format!("A={ROOT}\n{refused}\nexport CARGO_HOME=$A/cargo\n");
            assert_eq!(
                scan_with(&content, &rooted())
                    .iter()
                    .map(|violation| (violation.line, violation.reason))
                    .next_back(),
                Some((3, Reason::UnreadableReference)),
                "{refused}"
            );
        }
    }

    #[test]
    fn whitespace_in_a_value_is_not_a_second_assignment() {
        // The refusal is for another `NAME=`, not for a space: a quoted path
        // with a space in it, and a trailing comment, both still resolve.
        for content in [
            "export CARGO_HOME=\"/var/mnt/scratch/example/my cache\"\n",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # written by bx\n",
        ] {
            assert_eq!(scan_with(content, &rooted()), vec![], "{content}");
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
    fn several_references_in_one_value_are_all_substituted() {
        // One pass substitutes every reference in the value, so this resolves
        // in one hop however many there are. It is also what pins the pass's
        // own bound: a bound too small to visit them all leaves a `$` behind,
        // and the value stops resolving.
        let content = concat!(
            "A=/var/mnt/scratch/example\n",
            "B=cache\n",
            "C=cargo\n",
            "export CARGO_HOME=$A/$B/$C/$B/$C/$B\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn a_chain_of_references_resolves_however_deep_it_is() {
        // `X0` is the literal root and each link refers to the one below it. A
        // shell expands each link when it is assigned, so the depth of the
        // chain is never the depth of any one expansion — and neither is it
        // here, because values are learned expanded. A nine-deep chain was
        // once refused as "refers to a variable this fragment has not
        // assigned", every link of which it had assigned.
        fn chain(links: usize) -> String {
            let mut content = format!("X0={ROOT}\n");
            for link in 1..=links {
                content.push_str(&format!("X{link}=$X{}\n", link - 1));
            }
            content.push_str(&format!("export CARGO_HOME=$X{links}/cargo\n"));
            content
        }
        for links in [1, 7, 8, 9, 64] {
            assert_eq!(scan_with(&chain(links), &rooted()), vec![], "{links}");
        }
    }

    #[test]
    fn substituted_text_is_not_expanded_again() {
        // `Y='$X'` holds the two characters `$X`, and a shell that later
        // expands `$Y` yields them and stops. Expanding them again would judge
        // a path no shell produces.
        let content = format!("X=/etc\nY='$X'\nexport CARGO_HOME={ROOT}/$Y\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);
        let content = format!("X={ROOT}\nY='$X'\nexport CARGO_HOME=$Y/cargo\n");
        assert_eq!(
            scan_with(&content, &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::NotAbsolute]
        );
    }

    #[test]
    fn a_value_that_extends_itself_resolves_as_a_shell_would() {
        // `X=$X/b` sees the previous `X`, so it is one more path component
        // under the root, not a value that grows without end.
        let content = concat!(
            "X=/var/mnt/scratch/example\n",
            "X=$X/b\n",
            "export CARGO_HOME=$X/cargo\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
        // Before any `X` is assigned, the same line refers to nothing.
        let found = scan_with("X=$X/b\nexport CARGO_HOME=$X/cargo\n", &rooted());
        assert_eq!(
            found
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::UnresolvedReference]
        );
    }

    #[test]
    fn two_values_that_refer_to_each_other_do_not_resolve() {
        // A true two-node cycle. `A=$B` refers to a `B` not yet assigned, so
        // `A` is unresolvable, and `B=$A` inherits that. Neither `A` nor `B`
        // relocates anything, so the cycle reaches the guard through the value
        // that does.
        let content = concat!("A=$B\n", "B=$A\n", "export CARGO_HOME=$A/cargo\n");
        let found = scan_with(content, &rooted());
        assert_eq!(
            found
                .iter()
                .map(|violation| (violation.line, violation.reason))
                .collect::<Vec<_>>(),
            vec![(3, Reason::UnresolvedReference)]
        );
    }

    #[test]
    fn an_inline_comment_after_a_value_is_a_comment() {
        // An unquoted `#` beginning a word starts a comment in bash and zsh,
        // sourced or interactive, so the value ends before it. A `#` inside a
        // word, or quoted, is text.
        assert_eq!(
            scan_with(
                "export CARGO_HOME=/var/mnt/scratch/example/cargo # written by bx\n",
                &rooted()
            ),
            vec![]
        );
        // The value still has to be inside a root: the comment buys nothing.
        assert_eq!(
            scan_with("export CARGO_HOME=/var/cache/elsewhere # bx\n", &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::OutsideDeclaredRoots]
        );
        // A comment carrying an assignment assigns nothing: no shell reads it.
        for content in [
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # GOPATH=/etc\n",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # keep=this\n",
        ] {
            assert_eq!(scan_with(content, &rooted()), vec![], "{content}");
        }
        // Text, not a comment: inside a word, and at the start of a value.
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/a#b", &rooted()),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "#/etc", &rooted())),
            Some(Reason::NotAbsolute)
        );
    }

    #[test]
    fn the_line_reader_holds_its_bounds() {
        // Lines that assign nothing stay nothing, including ones the reader
        // cannot split, as long as they mention no assignment.
        for line in [
            "export",
            "declare -x",
            "setenv",
            "echo \"it's",
            "echo `date`",
            "echo \"$(date \"+%F\")\" ${HOME}",
        ] {
            assert_eq!(statement(line), Statement::Nothing, "{line}");
        }
        // `setenv` assigns what follows its name, and nothing to a non-name.
        assert_eq!(
            statement("setenv GOPATH /x"),
            Statement::Assign {
                name: "GOPATH",
                value: Some("/x"),
                append: false,
            }
        );
        assert_eq!(
            statement("setenv 2bad /x"),
            Statement::Refused {
                name: "",
                value: "setenv 2bad /x",
                reason: Reason::Unreadable,
            }
        );
        // Every construct that must close, and does not, is unreadable.
        for value in ["`pwd", "\"`pwd\\`\"", "/x\\", "$(pwd", "\"$(pwd)", "(a b"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        // Nesting is bounded: past it, a line is refused rather than recursed
        // into without end.
        let deep = format!(
            "export GPG_TTY={}{}",
            "$(".repeat(MAX_NESTING + 2),
            ")".repeat(MAX_NESTING + 2)
        );
        assert_eq!(reasons(&deep, &rooted()), vec![(1, Reason::Unreadable)]);
        let shallow = format!("export GPG_TTY={}{}", "$(".repeat(4), ")".repeat(4));
        assert_eq!(scan_with(&shallow, &rooted()), vec![]);
    }

    #[test]
    fn an_expansion_that_grows_past_the_length_bound_is_refused_for_its_length() {
        // Values are learned expanded, so a line that doubles a value doubles
        // what is stored; the length bound is what keeps that from growing
        // without end. The reason says so, rather than that a variable the
        // fragment plainly assigned was never assigned.
        let long = format!("{ROOT}/{}", "a".repeat(MAX_EXPANDED_LEN / 2));
        let content = format!("X={long}\nY=$X$X\nexport CARGO_HOME=$Y/cargo\n");
        let found = scan_with(&content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::ExpansionTooLong);
        // And the same bound applies to the value being judged itself.
        let content = format!("X={long}\nexport CARGO_HOME=$X$X\n");
        assert_eq!(
            scan_with(&content, &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::ExpansionTooLong]
        );

        // The identical shape, under the bound, resolves — so the assertion
        // above pins the bound and not the shape.
        let short = format!("{ROOT}/{}", "a".repeat(16));
        let content = format!("X={short}\nY=$X$X\nexport CARGO_HOME=$Y/cargo\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);
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
    fn a_braced_reference_consumes_its_closing_brace() {
        // `${X}` must expand to X's value and nothing else. Leaving the `}`
        // behind would produce a path with a `}` in a component name, which is
        // a different directory — and one that is no longer inside the root.
        let content = format!("X={ROOT}\nexport CARGO_HOME=${{X}}/cargo\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);

        // The brace ends the name and nothing more: text after it is appended
        // verbatim, with no separator invented. `${X}suffix` therefore names a
        // *sibling* of the root, which is outside it.
        let content = format!("X={ROOT}\nexport CARGO_HOME=${{X}}suffix/cargo\n");
        let found = scan_with(&content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::OutsideDeclaredRoots);
    }

    #[test]
    fn an_unbalanced_quote_is_not_stripped() {
        // A quote that never closes is a shell syntax error wherever it sits —
        // the file stops parsing there — so it is neither stripped nor taken
        // as part of a directory's name. Stripping one would have eaten a
        // character from each end and changed which path the value names.
        for value in [
            "\"/var/mnt/scratch/example/cargo",
            "'/var/mnt/scratch/example/cargo",
            "\"",
            "'",
            "/var/mnt/scratch/example/cargo\"",
            "/var/mnt/scratch/example/cargo'",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        // Matched quotes around part of a value are removed, as a shell
        // removes them, so a quoted `..` still climbs.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/\"..\"/'..'/etc",
                &rooted()
            )),
            Some(Reason::Unreadable),
        );
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/\"..\"/\"..\"/etc",
                &rooted()
            )),
            Some(Reason::OutsideDeclaredRoots),
        );
        assert_eq!(
            check(
                "CARGO_HOME",
                "\"/var/mnt/scratch/example\"/cargo",
                &rooted()
            ),
            Verdict::Allowed
        );
    }

    #[test]
    fn an_expansion_of_exactly_the_length_bound_still_resolves() {
        // The bound is a limit, not a ceiling one short of it: a value of
        // exactly MAX_EXPANDED_LEN bytes is within it.
        let exact = format!("{ROOT}/{}", "a".repeat(MAX_EXPANDED_LEN - ROOT.len() - 1));
        assert_eq!(exact.len(), MAX_EXPANDED_LEN);
        let content = format!("X={exact}\nexport CARGO_HOME=$X\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);
    }

    #[test]
    fn a_dollar_that_begins_no_reference_is_literal_text() {
        // The expansion grammar is closed: `$NAME` and `${NAME}`, nothing else.
        // A `$` that cannot begin a name is text, and text that is not an
        // absolute path is rejected for being one, not for being unresolvable.
        for value in ["$", "$1/x"] {
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
        // A `${` that does not close on a name is not text to any shell: an
        // unclosed one is a syntax error, `${}` a bad substitution, and
        // `${A:+..}` an operator the guard does not evaluate — with `A` set it
        // is `..`, which climbs out of the root. None of them may be approved
        // even when the path around it is squarely inside a root.
        for value in [
            "${/x",
            "/var/mnt/scratch/example/${FOO",
            "${FOO",
            "${}/x",
            "/var/mnt/scratch/example/${}",
            "/var/mnt/scratch/example/${HOME:+..}",
            "/var/mnt/scratch/example/${HOME#/}",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
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
            assert!(is_relocating(name), "{name} should be value-checked");
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
            assert!(is_relocating(name), "{name} should be value-checked");
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
            assert!(is_relocating(name), "{name} should be value-checked");
        }
    }

    #[test]
    fn location_suffixes_are_value_checked_generically() {
        // The point of the suffix rule is catching tools bx has never heard of.
        for name in ["SOMETOOL_CONFIG_DIR", "OTHERTOOL_HOME", "THIRD_CACHE_DIR"] {
            assert!(is_relocating(name), "{name} should be value-checked");
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
            "declare -gx CARGO_HOME=/x",
            "typeset -gx CARGO_HOME=/x",
            "export -- CARGO_HOME=/x",
            "readonly CARGO_HOME=/x",
            "local CARGO_HOME=/x",
            "export CARGO_HOME+=/x",
        ] {
            assert_eq!(
                scan(line)
                    .iter()
                    .map(|violation| (violation.name.as_str(), violation.reason))
                    .collect::<Vec<_>>(),
                vec![("CARGO_HOME", Reason::NoRootsDeclared)],
                "should have judged: {line}"
            );
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

    // Review round 2: the guard fails closed on shell it cannot read, reads
    // a value quote-aware, and gives one verdict whichever entry point asks.

    /// The reasons `scan_with` gives, in line order, with their line numbers.
    fn reasons(content: &str, roots: &RootSet) -> Vec<(usize, Reason)> {
        scan_with(content, roots)
            .iter()
            .map(|violation| (violation.line, violation.reason))
            .collect()
    }

    #[test]
    fn a_keyword_line_is_judged_whatever_options_precede_the_assignment() {
        // Each of these sets `CARGO_HOME=/etc/evil` in bash and zsh, and each
        // was approved: the text before the first `=` was not one bare name,
        // so the line was read as assigning nothing.
        for line in [
            "declare -gx CARGO_HOME=/etc/evil",
            "typeset -gx CARGO_HOME=/etc/evil",
            "export -- CARGO_HOME=/etc/evil",
            "readonly CARGO_HOME=/etc/evil",
            "local CARGO_HOME=/etc/evil",
            "export -x CARGO_HOME=/etc/evil",
        ] {
            assert_eq!(
                scan(line),
                vec![Violation {
                    line: 1,
                    name: "CARGO_HOME".into(),
                    value: "/etc/evil".into(),
                    reason: Reason::NoRootsDeclared,
                }],
                "{line}"
            );
            assert_eq!(
                reasons(line, &rooted()),
                vec![(1, Reason::OutsideDeclaredRoots)],
                "{line}"
            );
        }
    }

    #[test]
    fn a_line_the_guard_cannot_read_is_never_approved() {
        // Several operands: refused as a second assignment, and not learned.
        for line in [
            "export FOO CARGO_HOME=/etc/evil",
            "export A B CARGO_HOME=/etc/evil",
            "export FOO=1 CARGO_HOME=/etc/evil",
            "export PATH CARGO_HOME=/var/mnt/scratch/example/cargo",
        ] {
            assert_eq!(
                reasons(line, &RootSet::strict()),
                vec![(1, Reason::MultipleAssignments)],
                "{line}"
            );
        }
        // Anything else that mentions a keyword, or assigns where a command
        // starts, and is not a form the guard reads.
        for line in [
            "true && export CARGO_HOME=/etc/evil",
            "[ -d /x ] && CARGO_HOME=/etc/evil",
            "builtin export CARGO_HOME=/etc/evil",
            "export CARGO_HOME=/etc/evil; echo done",
            "declare -n CARGO_HOME=OTHER",
            "typeset -u CARGO_HOME=/var/mnt/scratch/example",
            "export +x CARGO_HOME",
            "export CARGO_HOME=\"/var/mnt/scratch/example",
            "export EDITOR=nvim --wait",
            "export \\",
            "CARGO_HOME=/var/mnt/scratch/example cargo build",
        ] {
            assert_eq!(
                reasons(line, &rooted()),
                vec![(1, Reason::Unreadable)],
                "{line}"
            );
        }
        // A line refused before a variable can be picked out of it quotes
        // itself back, comment excluded.
        assert_eq!(
            scan("true && export CARGO_HOME=/etc/evil # note"),
            vec![Violation {
                line: 1,
                name: String::new(),
                value: "true && export CARGO_HOME=/etc/evil".into(),
                reason: Reason::Unreadable,
            }]
        );
    }

    #[test]
    fn a_prefix_does_not_carry_a_value_past_bxs_own_directory() {
        // The exclusion the module calls unconditional, bypassed by one word.
        let wide = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let state = "/var/home/example/.local/state/bx";
        assert_eq!(
            reasons(&format!("export XDG_STATE_HOME={state}"), &wide),
            vec![(1, Reason::BxOwnedDirectory)]
        );
        assert_eq!(
            reasons(&format!("declare -gx XDG_STATE_HOME={state}"), &wide),
            vec![(1, Reason::BxOwnedDirectory)]
        );
        assert_eq!(
            reasons(&format!("export FOO XDG_STATE_HOME={state}"), &wide),
            vec![(1, Reason::MultipleAssignments)]
        );
    }

    #[test]
    fn a_value_the_guard_does_not_evaluate_is_refused_for_a_relocating_name_only() {
        // A command substitution, an escape, a brace expansion, an array and
        // mixed quoting are shell the guard does not run. For a variable that
        // relocates nothing that costs nothing; for one that does, it is a
        // value that cannot be shown to be inside a root.
        for value in [
            "$(pwd)/cargo",
            "\"$(pwd)/cargo\"",
            "`pwd`/cargo",
            "/var/mnt/scratch/example/\\../cargo",
            "/var/mnt/scratch/example/{..,x}",
            "(/var/mnt/scratch/example)",
            "'/var/mnt/scratch/example'/$X",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        for line in [
            "export GPG_TTY=$(tty)",
            "export GIT_TOP=\"$(git rev-parse --show-toplevel)\"",
            "path=(/var/mnt/scratch/example/bin $path)",
            "export PATH+=:/var/mnt/scratch/example/bin",
            "alias ll='ls -l'",
            "eval \"$(mise activate zsh)\"",
            "make V=1",
        ] {
            assert_eq!(scan_with(line, &rooted()), vec![], "{line}");
        }
        // And what it could not evaluate, it does not learn.
        let content = "X=$(pwd)\nexport CARGO_HOME=$X/cargo\n";
        assert_eq!(
            reasons(content, &rooted()),
            vec![(2, Reason::UnreadableReference)]
        );
    }

    #[test]
    fn a_quoted_tilde_is_a_literal_tilde() {
        // A shell expands `~` only unquoted at the start of a value. Quoted, or
        // arriving through a reference, it is a relative path.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(
            check("CARGO_HOME", "~/cargo", &home_rooted),
            Verdict::Allowed
        );
        for value in ["\"~/cargo\"", "'~/cargo'"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &home_rooted)),
                Some(Reason::NotAbsolute),
                "{value}"
            );
        }
        assert_eq!(
            reasons("X='~'\nexport CARGO_HOME=$X/cargo\n", &home_rooted),
            vec![(2, Reason::NotAbsolute)]
        );
    }

    #[test]
    fn a_single_assignment_with_an_equals_sign_in_its_value_is_not_two() {
        // Each assigns one variable. The `=` is inside the value, so the old
        // remedy — split the line — was impossible to follow.
        for line in [
            "export MAKEFLAGS=\"-j8 V=1\"",
            "export MAKEFLAGS='-j8 V=1'",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # keep=this",
            "export GRADLE_USER_HOME=\"/var/mnt/scratch/example/a b=c/gradle\"",
        ] {
            assert_eq!(scan_with(line, &rooted()), vec![], "{line}");
        }
        // Unquoted, the same text is two assignments to a shell, and says so.
        assert_eq!(
            reasons("export MAKEFLAGS=-j8 V=1", &rooted()),
            vec![(1, Reason::MultipleAssignments)]
        );
    }

    #[test]
    fn check_and_scan_give_one_verdict() {
        // `check` and `scan_with` both call `evaluate`, so a value that is not
        // one shell word is refused whichever entry point is asked.
        for (name, value, reason) in [
            (
                "CARGO_HOME",
                "/var/mnt/scratch/example/cargo FOO=/etc/evil",
                Some(Reason::MultipleAssignments),
            ),
            (
                "EDITOR",
                "nvim GOPATH=/etc/evil",
                Some(Reason::MultipleAssignments),
            ),
            ("EDITOR", "nvim --wait", Some(Reason::Unreadable)),
            (
                "CARGO_HOME",
                " /var/mnt/scratch/example",
                Some(Reason::Unreadable),
            ),
            ("MAKEFLAGS", "\"-j8 V=1\"", None),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b\"", None),
            ("CARGO_HOME", "$(pwd)", Some(Reason::Unreadable)),
            ("CARGO_HOME", "/etc", Some(Reason::OutsideDeclaredRoots)),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                reason,
                "check {name}={value}"
            );
            assert_eq!(
                scan_with(&format!("export {name}={value}"), &rooted())
                    .first()
                    .map(|violation| violation.reason),
                reason,
                "scan {name}={value}"
            );
        }
    }

    #[test]
    fn an_inadmissible_root_is_not_mistaken_for_no_root() {
        // `scratch_root = "/"` visibly declares a root. Telling that user no
        // root is declared sends them looking for a declaration that exists.
        let dropped = RootSet::new(Path::new(HOME), &[PathBuf::from("/")]);
        let nothing = RootSet::new(Path::new(HOME), &[]);
        assert_ne!(dropped, nothing);
        assert_eq!(dropped.home(), nothing.home());
        assert_eq!(dropped.inadmissible(), &[PathBuf::from("/")]);
        assert!(nothing.inadmissible().is_empty());
        assert!(RootSet::strict().inadmissible().is_empty());
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x", &dropped)),
            Some(Reason::InadmissibleRoot)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x", &nothing)),
            Some(Reason::NoRootsDeclared)
        );
        assert_eq!(
            reasons("export CARGO_HOME=/x\n", &dropped),
            vec![(1, Reason::InadmissibleRoot)]
        );
        // Beside an admissible root, the refused one is still reported.
        let mixed = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from("/.."), PathBuf::from(ROOT)],
        );
        assert_eq!(mixed.inadmissible(), &[PathBuf::from("/..")]);
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cargo", &mixed),
            Verdict::Allowed
        );
    }

    #[test]
    fn behaviour_variables_in_a_location_family_are_allowed() {
        // All ten were refused as `NotAPath`, whose remedy was an edit to a
        // private list in bx's source. None relocates anything.
        for (name, value) in [
            ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
            ("NPM_CONFIG_FUND", "false"),
            ("NPM_CONFIG_LOGLEVEL", "warn"),
            ("PIP_INDEX_URL", "https://pypi.example.invalid/simple"),
            ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
            ("UV_NO_CACHE", "1"),
            ("UV_PYTHON", "3.12"),
            ("MISE_ENV", "production"),
            ("MISE_JOBS", "8"),
            ("ASDF_CONCURRENCY", "8"),
        ] {
            assert!(is_relocating(name), "{name}");
            assert!(!names_a_location(name), "{name}");
            assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
            // It relocates nothing, so it needs no root declared either.
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
    }

    #[test]
    fn a_family_variable_that_holds_a_location_is_still_judged() {
        // Invariant 2 is not relaxed for the same families: a location given a
        // path is judged by where it points, and one whose name says it holds a
        // location is refused a bare word, which is a path relative to
        // wherever the shell happens to be.
        for name in [
            "UV_TOOL_DIR",
            "PIP_TARGET",
            "NPM_CONFIG_CACHE",
            "NPM_CONFIG_PREFIX",
            "NPM_CONFIG_USERCONFIG",
            "MISE_INSTALL_PATH",
            "UV_PROJECT_ENVIRONMENT",
        ] {
            assert!(names_a_location(name), "{name}");
            assert_eq!(
                reason_of(&check(name, "cache", &rooted())),
                Some(Reason::NotAPath),
                "{name}"
            );
            assert_eq!(
                reason_of(&check(name, "/etc/evil", &rooted())),
                Some(Reason::OutsideDeclaredRoots),
                "{name}"
            );
            assert_eq!(
                reason_of(&check(name, ".cache/x", &rooted())),
                Some(Reason::NotAbsolute),
                "{name}"
            );
        }
        // A name matched by nothing is not a family name at all.
        assert!(!names_a_location("EDITOR"));
        assert!(!names_a_location("UV_"));
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
