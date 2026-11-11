//! Invariant 2's judgement of a generated body, made before a byte of it is
//! decided: every environment fragment bx generates passes through here.

use std::path::PathBuf;

use super::join;
use crate::config::env::Syntax;
use crate::config::target::Gen;
use crate::config::when::Decide;
use crate::env_guard::{self, RootSet};
use crate::paths::Portable;

/// Judge a generated body against Invariant 2, as what it is.
///
/// An environment fragment goes through the guard in its own syntax, and the
/// LaunchAgent on macOS through its `environment.d` fragment
/// ([`guard_launch_agent`]). The line
/// a region sources a fragment with sets nothing, so it is not a fragment:
/// the guard's grammar would refuse it as unreadable, and `env_guard`'s tests
/// hold its bytes to carrying no assignment instead.
///
/// The interactive file is judged by its `env` phase alone, rendered with the
/// same `decide` as the file, since that phase is its one environment
/// fragment; every other phase holds plugin and alias lines that set nothing,
/// and function definitions whose registrations assign only zsh's hook
/// arrays, the update prompt's unexported `BX_` names and, in bash's file, an
/// append to an unexported `PROMPT_COMMAND`, which the guard's grammar
/// would refuse as unreadable. The tests of
/// [`crate::config::target::Interactive`] hold the plugin and alias lines to
/// carrying no assignment, those of [`crate::shell::function`] and this
/// module hold the `functions` phase to changing no parameter but a hook
/// array, and [`crate::env_guard`]'s hold the update prompts to theirs.
/// A line number in the note is still the file's own: the phase is found in
/// the file's bytes, and each line is counted from the top of the file.
///
/// bash's interactive file is judged the same way: by its `env` and `path`
/// phases, its one environment fragment, and the history file it names. Its alias lines
/// set nothing, its functions and sources are held to what zsh's are, its
/// activations to the relocation rule, and its `options` phase assigns only
/// bash's own history variables, unexported, which [`crate::shell::bash`]'s
/// tests hold it to.
/// `~/.inputrc` is readline's syntax and names no variable.
pub(super) fn guard_generated(
    generator: &Gen,
    content: &str,
    roots: &RootSet,
    decide: &dyn Decide,
) -> Option<String> {
    match generator {
        Gen::Env(fragment) => match fragment.syntax {
            Syntax::Zsh => {
                guard_fragment_inheriting(&fragment.inherited_render(decide), content, roots)
            }
            Syntax::EnvironmentD => guard_environment_d(content, roots),
        },
        // The property list is not the fragment's syntax: its fragment is
        // rendered as `environment.d` would hold it, and judged as that.
        Gen::LaunchAgent(agent) => guard_launch_agent(&agent.env.render(decide), roots),
        Gen::Interactive(file) => {
            let env = file.env().render(decide);
            let before = content
                .find(&env)
                .map_or(0, |at| content[..at].matches('\n').count());
            join([
                guard_fragment_after(&env, roots, before),
                guard_history_file("zsh", file.history().zsh_file.as_ref(), roots),
            ])
        }
        // The fragment is the file's first bytes, so its lines are numbered
        // as the file's own.
        Gen::Bash(file) => {
            let env = file.env(decide);
            join([
                guard_fragment(&env, roots),
                guard_history_file("bash", file.history().bash_file.as_ref(), roots),
            ])
        }
        Gen::Source(_) | Gen::Profile(_) | Gen::Inputrc(_) => None,
    }
}

/// Judge a declared history file against Invariant 2: the one path an
/// interactive file's `options` phase names, for `shell`.
///
/// zsh keeps no history file unless one is named, and bash's default is its
/// own, so naming one moves nothing and needs no root; but the shell writes
/// every command line typed into it, so it may not lie inside a directory bx
/// owns, nor inside the config repo, where it would be committed. Rendered
/// against the set's home, the same home `${HOME}` is at shell start.
fn guard_history_file(shell: &str, file: Option<&Portable>, roots: &RootSet) -> Option<String> {
    let file = file?;
    let path = roots
        .home()
        .map_or_else(|| PathBuf::from(file.as_str()), |home| file.render(home));
    env_guard::refuses_bx_location(&path, roots)
        .map(|reason| format!("[history] {shell} file {file} {reason}"))
}

/// Judge a generated environment fragment against Invariant 2.
///
/// `None` when every assignment is one bx may write; otherwise one note naming
/// each violation as `line N: NAME <reason>`. Applied to generated bodies only:
/// the guard's grammar admits nothing but assignments, and a file the user
/// wrote is not bx's output to judge.
pub(in crate::plan) fn guard_fragment(content: &str, roots: &RootSet) -> Option<String> {
    guard_fragment_after(content, roots, 0)
}

/// [`guard_fragment`] for a fragment a shell reads after `inherited`, the
/// fragment its references may expand from: the two are judged as one, so a
/// reference resolves to what the earlier file gave it, and only what this
/// fragment's own lines do is reported, each under its own line number. A
/// violation in `inherited` is that fragment's to report, when it is judged.
fn guard_fragment_inheriting(inherited: &str, content: &str, roots: &RootSet) -> Option<String> {
    let skipped = inherited.lines().count();
    let mut found = env_guard::scan_with(&format!("{inherited}{content}"), roots);
    found.retain(|v| v.line > skipped);
    for v in &mut found {
        v.line -= skipped;
    }
    violations(&found, 0)
}

/// [`guard_fragment`] for a fragment that is one part of a file, preceded in
/// it by `before` lines, so each line the note names is the file's own.
fn guard_fragment_after(content: &str, roots: &RootSet, before: usize) -> Option<String> {
    violations(&env_guard::scan_with(content, roots), before)
}

/// [`guard_fragment`] for an `environment.d` fragment, where every line is
/// exported although none says `export`.
pub(in crate::plan) fn guard_environment_d(content: &str, roots: &RootSet) -> Option<String> {
    violations(&env_guard::scan_exported(content, roots), 0)
}

/// [`guard_environment_d`] for the `environment.d` fragment a LaunchAgent
/// holds on macOS, `env`, and one more refusal: a value that does not expand
/// to a literal. `environment.d` expands a reference itself, and launchd
/// expands none, so a value the guard cannot expand would reach every
/// program as the reference's own text.
///
/// The note names each variable, not a line: the lines are the fragment's,
/// and the property list written has others.
pub(in crate::plan) fn guard_launch_agent(env: &str, roots: &RootSet) -> Option<String> {
    let found = env_guard::scan_exported(env, roots);
    let refused = found.iter().map(|v| {
        let name = if v.name.is_empty() { &v.value } else { &v.name };
        Some(format!("{name} {}", v.reason))
    });
    let unexpanded = env_guard::expand_exported(env, roots)
        .into_iter()
        .filter(|expanded| !found.iter().any(|v| v.name == expanded.name))
        .map(|expanded| {
            expanded.value.err().map(|reason| {
                format!(
                    "{} {reason}, and launchd expands nothing, so it would be set to the \
                     reference's text",
                    expanded.name
                )
            })
        });
    join(refused.chain(unexpanded))
}

/// One note naming each violation as `line N: NAME <reason>`, each line moved
/// down by the `before` lines the scanned content is preceded by in its file.
fn violations(found: &[env_guard::Violation], before: usize) -> Option<String> {
    join(
        found
            .iter()
            .map(|v| Some(format!("line {}: {} {}", v.line + before, v.name, v.reason))),
    )
}

#[cfg(test)]
mod tests;
