//! What the guard's tests share across its submodules: the neutral home and
//! root they judge against, the helpers that read a verdict back, and the
//! fragments and name lists more than one submodule's tests are held to.

use std::path::{Path, PathBuf};

use super::*;

// A deliberately neutral home and scratch root: nothing in this file may
// name a real account or a real machine's layout (invariant 5).
pub(super) const HOME: &str = "/var/home/example";
pub(super) const ROOT: &str = "/var/mnt/scratch/example";

pub(super) fn rooted() -> RootSet {
    RootSet::new(Path::new(HOME), &[PathBuf::from(ROOT)])
}

pub(super) fn reason_of(verdict: &Verdict) -> Option<Reason> {
    match verdict {
        Verdict::Allowed => None,
        Verdict::Violation(violation) => Some(violation.reason),
    }
}

/// The operator's own relocating exports, with the scratch mount replaced
/// by a neutral root so nothing user-specific enters the repository
/// (invariant 5). Every one of these was denied or leaked by the
/// name-based guard. All 23 exports and both helpers are in the
/// emit table.
pub(super) const OPERATOR_FRAGMENT: &str = concat!(
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

/// The reasons `scan_with` gives, in line order, with their line numbers.
pub(super) fn reasons(content: &str, roots: &RootSet) -> Vec<(usize, Reason)> {
    scan_with(content, roots)
        .iter()
        .map(|violation| (violation.line, violation.reason))
        .collect()
}

/// The reason `NAME=VALUE` is refused on a line of its own that does not
/// say `export`, or `None` when it is allowed there. [`check`] judges as
/// exported, and this is the other reading.
pub(super) fn unexported(name: &str, value: &str, roots: &RootSet) -> Option<Reason> {
    scan_with(&format!("{name}={value}\n"), roots)
        .first()
        .map(|violation| violation.reason)
}

/// Names the round-3 lists did not hold, each of which moves a tool's
/// config, data or cache — `rg` and `git` were shown to obey two of them.
pub(super) const R4_UNLISTED_RELOCATIONS: &[&str] = &[
    "CARGO_TARGET_DIR",
    "CARGO_INSTALL_ROOT",
    "LESSHISTFILE",
    "NODE_REPL_HISTORY",
    "PYTHONPYCACHEPREFIX",
    "GOENV",
    "GOBIN",
    "GOTMPDIR",
    "RIPGREP_CONFIG_PATH",
    "BAT_CONFIG_PATH",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "INPUTRC",
    "TERMINFO",
    "CCACHE_CONFIGPATH",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_DIRS",
    "YARN_GLOBAL_FOLDER",
    "BUNDLE_USER_CONFIG",
    "BUNDLE_PATH",
    "POETRY_VIRTUALENVS_PATH",
    "CONDA_PKGS_DIRS",
    "PIPX_HOME",
    "PIPX_BIN_DIR",
    "pnpm_config_store_dir",
    "RBENV_ROOT",
    "NODENV_ROOT",
    "FNM_DIR",
    "SDKMAN_DIR",
    "STARSHIP_CACHE",
    "NUGET_PLUGINS_CACHE_PATH",
    "PLAYWRIGHT_BROWSERS_PATH",
    "CYPRESS_CACHE_FOLDER",
    "ELECTRON_CACHE",
    "LD_LIBRARY_PATH",
];

/// Names the round-5 review ran a real tool against, and saw the tool
/// read a bare word as a path relative to the current directory: `git`
/// followed `GIT_DIR=evil` to `./evil`, `rg` read `./rc`, `cargo` built
/// into `./target2`, a child `bash` sourced `./rc`.
pub(super) const R5_READ_AS_LOCATIONS: &[(&str, &str)] = &[
    ("GIT_DIR", "evil"),
    ("GIT_WORK_TREE", "work"),
    ("GIT_CONFIG_SYSTEM", "rc"),
    ("RIPGREP_CONFIG_PATH", "rc"),
    ("CARGO_TARGET_DIR", "target2"),
    ("CARGO_INSTALL_ROOT", "root"),
    ("PYTHONPYCACHEPREFIX", "pyc"),
    ("BASH_ENV", "rc"),
    ("ENV", "rc"),
    ("INPUTRC", "rc"),
    ("LESSHISTFILE", "hist"),
    ("GOENV", "env"),
    ("TERMINFO", "ti"),
    ("BAT_CONFIG_PATH", "rc"),
    ("NODE_REPL_HISTORY", "hist"),
];

/// Shell that sets a variable in bash or zsh — `{N}` the name, `{V}` the
/// value. The review's forms, and the neighbours of each.
///
/// **This is the reviewed set, not an exhaustive account of every way a
/// shell can assign**, and it cannot be one: the set is bounded by bash's
/// and zsh's grammars, not by anything bx controls, and a table claiming
/// exhaustiveness would be wrong the next time either shell grew a
/// builtin. Nothing here carries the guard's safety. The guard **fails
/// closed by shape** — it refuses every line outside its own small
/// grammar, whatever that line mentions — so a form nobody has thought of
/// is refused by not being `NAME=VALUE`, not by appearing below. This
/// table is a regression net over the forms review has actually produced,
/// and the thing it is worth being complete about is that every form in it
/// stays refused. `mapfile`, `readarray` and `coproc` were added in round
/// 3, which is what this paragraph exists to stop being read as a gap in a
/// proof.
pub(super) const ASSIGNING_FORMS: &[&str] = &[
    // A keyword quoted, escaped or aliased.
    "\\export {N}={V}",
    "\"export\" {N}={V}",
    "'export' {N}={V}",
    "e''xport {N}={V}",
    "ex\"\"port {N}={V}",
    "alias ex=export\nex {N}={V}",
    // Constructs that span lines.
    ": '\n'; export {N}={V} #'",
    "ex\\\nport {N}={V}",
    "{N}=\\\n{V}",
    "export {N}=/var/mnt/scratch/example/cargo\n{N}_\\\n={V}",
    ": <<'EOF'\nEOF\nexport {N}={V}",
    "X=\"\nexport {N}={V}\n\"",
    // Commands that assign.
    "for {N} in {V}; do :; done",
    "select {N} in {V}; do break; done",
    "read -r {N} <<< {V}",
    "read -p \"Enter: \" {N}",
    "read -rn 1 {N}",
    "read -r A {N}",
    "mapfile -t {N} < /x",
    "readarray -t {N} < /x",
    "coproc {N} {{ :; }}",
    "printf -v {N} {V}",
    "getopts : {N}",
    "{N}[1,-1]={V}",
    "{N}[1]={V}",
    ": ${{N}::={V}}",
    ": ${{N}:={V}}",
    ": ${{N}={V}}",
    "set -a\n: ${{N}:={V}}",
    "unset {N}\nexport {N}={V}",
    "export {N}\n{N}={V}",
    // Declaration builtins.
    "declare -x {N}={V}",
    "declare -gx {N}={V}",
    "typeset -x {N}={V}",
    "readonly {N}={V}",
    "local {N}={V}",
    "integer {N}={V}",
    "export -- {N}={V}",
    "export -x {N}={V}",
    "{N}+={V}",
    "export {N}+={V}",
    "{N}=({V})",
    // Evaluation with a literal payload.
    "eval \"export {N}={V}\"",
    "eval export {N}={V}",
    "source /dev/stdin <<< 'export {N}={V}'",
    ". /dev/stdin <<< 'export {N}={V}'",
    // Operators and prefixes.
    "true && export {N}={V}",
    "export {N}={V}; :",
    "builtin export {N}={V}",
    "command export {N}={V}",
    "export A=1 {N}={V}",
    "{N}={V} true",
    // Values a shell expands.
    "export {N}=$(printf %s {V})",
    "export {N}=`printf %s {V}`",
    "export {N}=\"$(printf %s {V})\"",
    "export {N}=${{N}:-{V}}",
    "export {N}=\"${{N}:={V}}\"",
    "export {N}={V}/$@/$@/../..",
    "export {N}=$'{V}'",
    "export {N}=\"{V}",
];
