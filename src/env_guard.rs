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
