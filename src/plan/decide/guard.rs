//! Invariant 2's judgement of a generated body, made before a byte of it is
//! decided: every environment fragment bx generates passes through here.

use std::path::PathBuf;

use super::join;
use crate::config::env::Syntax;
use crate::config::target::Gen;
use crate::env_guard::{self, RootSet};
use crate::paths::Portable;

/// Judge a generated body against Invariant 2, as what it is.
///
/// An environment fragment goes through the guard in its own syntax. The line
/// a region sources a fragment with sets nothing, so it is not a fragment:
/// the guard's grammar would refuse it as unreadable, and `env_guard`'s tests
/// hold its bytes to carrying no assignment instead.
///
/// The interactive file is judged by its `env` phase alone, rendered with the
/// same `present` as the file, since that phase is its one environment
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
    present: &dyn Fn(&str) -> bool,
) -> Option<String> {
    match generator {
        Gen::Env(fragment) => match fragment.syntax {
            Syntax::Zsh => guard_fragment(content, roots),
            Syntax::EnvironmentD => guard_environment_d(content, roots),
        },
        Gen::Interactive(file) => {
            let env = file.env().render(present);
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
            let env = file.env(present);
            join([
                guard_fragment(&env, roots),
                guard_history_file("bash", file.history().bash_file.as_ref(), roots),
            ])
        }
        Gen::Source(_) | Gen::Inputrc(_) => None,
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

/// [`guard_fragment`] for a fragment that is one part of a file, preceded in
/// it by `before` lines, so each line the note names is the file's own.
fn guard_fragment_after(content: &str, roots: &RootSet, before: usize) -> Option<String> {
    violations(&env_guard::scan_with(content, roots), before)
}

/// [`guard_fragment`] for an `environment.d` fragment, where every line is
/// exported although none says `export`.
fn guard_environment_d(content: &str, roots: &RootSet) -> Option<String> {
    violations(&env_guard::scan_exported(content, roots), 0)
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
mod tests {
    use super::*;
    use crate::plan::decide::*;
    use crate::testing::guarded_home;

    #[test]
    fn t8_the_fragment_guard_names_the_line_and_admits_what_it_allows() {
        let note = guard_fragment("CARGO_HOME=/elsewhere\n", &RootSet::strict())
            .expect("a relocation with no root is a violation");
        assert!(note.starts_with("line 1: CARGO_HOME "), "{note}");

        let two = guard_fragment(
            "export EDITOR=nvim\nCARGO_HOME=/a\nRUSTUP_HOME=/b\n",
            &RootSet::strict(),
        )
        .expect("two violations");
        assert!(two.contains("line 2: CARGO_HOME "), "{two}");
        assert!(two.contains("; line 3: RUSTUP_HOME "), "{two}");

        assert_eq!(
            guard_fragment("export EDITOR=nvim\n", &RootSet::strict()),
            None
        );
    }

    mod env_placement {
        //! The `[[env]]` placement graph, decided and applied end to end.

        use std::os::unix::fs::PermissionsExt as _;

        use super::*;
        use crate::plan::tests::{inputs, own};
        use crate::plan::{Mode as RunMode, Report, run};
        use crate::testing::GuardedHome;

        /// One `[[env]]` entry, as TOML.
        fn env(name: &str, value: &str, kind: &str) -> String {
            format!("[[env]]\nname = \"{name}\"\nvalue = \"{value}\"\nkind = \"{kind}\"\n")
        }

        /// One variable of each kind, none of which needs a root.
        fn every_kind() -> String {
            [
                env("LANG", "C.UTF-8", "environment"),
                env("BROWSER", "firefox", "gui"),
                env("PAGER", "less", "login"),
                env("EDITOR", "nvim", "interactive"),
            ]
            .concat()
        }

        const ZSHRC_REGION: &str = "# >>> bx >>>\n\
             [[ -r ~/.local/share/bx/zshrc.zsh ]] && source ~/.local/share/bx/zshrc.zsh\n\
             # <<< bx <<<\n";

        /// The interactive file's bytes with `env` in its `env` phase: the
        /// phase assembly's header, then the phase, when `env` holds anything.
        fn interactive(env: &str) -> String {
            let header = "# Generated by bx. Edit the config repo, not this file.\n";
            if env.is_empty() {
                header.to_string()
            } else {
                format!("{header}\n# bx phase: env\n{env}")
            }
        }

        fn plan(home: &GuardedHome, layer: &str) -> Report {
            run(&inputs(home, layer), RunMode::Plan, &mut |_| {
                panic!("plan never asks")
            })
            .expect("plan runs")
        }

        fn apply(home: &GuardedHome, layer: &str) -> Report {
            run(&inputs(home, layer), RunMode::Apply, &mut |_| Ok(true)).expect("apply runs")
        }

        /// Each row as `(target, action)`.
        fn rows(report: &Report) -> Vec<(&str, Action)> {
            report
                .changes
                .iter()
                .map(|change| (change.target.as_str(), change.action))
                .collect()
        }

        /// The row for `target`.
        fn row<'a>(report: &'a Report, target: &str) -> &'a Change {
            report
                .changes
                .iter()
                .find(|change| change.target == target)
                .unwrap_or_else(|| panic!("no row for {target}: {:?}", rows(report)))
        }

        fn read(home: &GuardedHome, rel: &str) -> String {
            std::fs::read_to_string(home.child(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
        }

        #[test]
        fn a_variable_switched_off_or_moved_leaves_its_old_fragment_empty() {
            // PR #75 note D1: a place no variable lands in any more emits no
            // target, so the fragment bx wrote for it stayed sourced with no
            // plan row. While the ledger records it, it is planned empty.
            let home = guarded_home();
            let before = [
                env("PAGER", "less", "login"),
                env("EDITOR", "nvim", "interactive"),
            ]
            .concat();
            apply(&home, &before);

            // PAGER moves to `interactive`, and EDITOR is switched off.
            let after = format!(
                "{}[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n\
                 enabled = false\n",
                env("PAGER", "less", "interactive")
            );
            let moved = plan(&home, &after);
            assert_eq!(
                row(&moved, "~/.local/share/bx/zprofile.zsh").action,
                Action::Modify
            );
            assert_eq!(
                row(&moved, "~/.local/share/bx/zshrc.zsh").action,
                Action::Modify
            );
            apply(&home, &after);
            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            assert_eq!(read(&home, ".local/share/bx/zprofile.zsh"), header);
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                interactive(&format!("{header}export PAGER=less\n"))
            );
            let second = plan(&home, &after);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );

            // Every variable gone: both fragments are left empty, and the
            // regions stay, sourcing them.
            let none = "";
            apply(&home, none);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), interactive(""));
            assert_eq!(read(&home, ".local/share/bx/zprofile.zsh"), header);
            assert_eq!(read(&home, ".zshrc"), ZSHRC_REGION);
            let settled = plan(&home, none);
            assert_eq!(
                rows(&settled),
                vec![
                    ("~/.local/share/bx/zprofile.zsh", Action::Unchanged),
                    ("~/.local/share/bx/zshrc.zsh", Action::Unchanged),
                    ("~/.local/share/bx/bashrc.bash", Action::Unchanged),
                ]
            );
        }

        #[test]
        fn a_fragment_bx_never_wrote_is_not_planned_empty() {
            let home = guarded_home();
            let report = plan(&home, &env("EDITOR", "nvim", "interactive"));
            assert_eq!(
                rows(&report),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Create),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
        }

        /// The lines an interactive file holding a plugin closes with.
        const SETTLED: &str = "\n# bx: done, whichever plugins were found\ntrue\n";

        /// One `[[plugin]]` entry, as TOML.
        fn plugin(name: &str, source: &str, terminal: bool) -> String {
            format!("[[plugin]]\nname = \"{name}\"\nsource = \"{source}\"\nterminal = {terminal}\n")
        }

        #[test]
        fn declared_plugins_reach_the_interactive_file_in_phase_order_and_rm_restores_it() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            // One plugin that is installed, by absolute path, and two that are
            // not: each still gets its guarded line.
            let installed = home.child("opt/installed.zsh");
            std::fs::create_dir_all(installed.parent().expect("a parent")).expect("mkdir");
            std::fs::write(&installed, "print -r -- installed-loaded\n").expect("write");
            let installed = installed.to_str().expect("a UTF-8 path");
            let layer = [
                // Declared out of load order: the terminal claimant first.
                plugin("highlight", "~/.zsh/highlight/highlight.zsh", true),
                env("EDITOR", "nvim", "interactive"),
                plugin("installed", installed, false),
                plugin("absent", "~/.zsh/absent/absent.zsh", false),
            ]
            .concat();

            let first = apply(&home, &layer);
            // The variable reaches bash too; the plugins are zsh's alone.
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: plugins\n\
                     [[ -r {installed} ]] && source {installed}\n\
                     [[ -r ~/.zsh/absent/absent.zsh ]] && source ~/.zsh/absent/absent.zsh\n\
                     \n# bx phase: terminal\n\
                     [[ -r ~/.zsh/highlight/highlight.zsh ]] && \
                     source ~/.zsh/highlight/highlight.zsh\n{SETTLED}",
                    interactive(
                        "# Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                         export EDITOR=nvim\n"
                    )
                )
            );

            // The shell starts with the absent plugins, even under ERR_EXIT,
            // having sourced the installed one: the file is sourced the way
            // the `~/.zshrc` region sources it, and returns 0.
            if let Some(zsh) = crate::shell::testing::installed("zsh") {
                let file = home.child(".local/share/bx/zshrc.zsh");
                let file = file.to_str().expect("a UTF-8 path");
                let out = crate::shell::testing::run(
                    &zsh,
                    &["-f", "-e"],
                    &format!("[[ -r {file} ]] && source {file}\nprint -r -- started\n"),
                );
                assert_eq!(
                    String::from_utf8(out).expect("utf-8"),
                    "installed-loaded\nstarted\n"
                );
            }

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, &layer).executed);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), written);

            // A plugin alone still places the file, with no `env` phase.
            let alone = plugin("absent", "~/.zsh/absent/absent.zsh", false);
            apply(&home, &alone);
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                format!(
                    "{}\n# bx phase: plugins\n\
                     [[ -r ~/.zsh/absent/absent.zsh ]] && source ~/.zsh/absent/absent.zsh\n\
                     {SETTLED}",
                    interactive("")
                )
            );

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
        }

        /// The source configuration's history and shell options.
        const HISTORY: &str = "[history]\nsize = 10000\nduplicates = \"all\"\nshare = true\n\
             [history.file]\nzsh = \"~/.zsh_history\"\n\
             [shell-options]\nhistappend = true\ncheckwinsize = true\n";

        #[test]
        fn declared_history_reaches_the_interactive_file_twice_alike_and_rm_restores_it() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let first = apply(&home, HISTORY);
            // bash's file carries the same declaration in bash's names.
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: options\n\
                     HISTFILE=\"${{HOME}}/.zsh_history\"\n\
                     HISTSIZE=10000\nSAVEHIST=10000\n\
                     typeset -g +x HISTFILE HISTSIZE SAVEHIST\n\
                     setopt HIST_IGNORE_ALL_DUPS SHARE_HISTORY\n",
                    interactive("")
                )
            );
            // The interactive file, which every interactive zsh sources —
            // not the login-only one, which bx does not write here at all.
            assert!(!home.child(".local/share/bx/zprofile.zsh").exists());
            assert!(!home.child(".zprofile").exists());
            // bash's option is bash's alone, and reaches no zsh file.
            assert!(!written.contains("histappend"), "{written}");

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, HISTORY);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, HISTORY).executed);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), written);

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = [
                "~/.local/share/bx/zshrc.zsh",
                "~/.zshrc",
                "~/.local/share/bx/bashrc.bash",
                "~/.bashrc",
            ]
            .iter()
            .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
            .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            assert!(!home.child(".local/share/bx/bashrc.bash").exists());
            assert!(!home.child(".bashrc").exists());
        }

        #[test]
        fn declared_keybindings_reach_the_interactive_file_twice_alike_and_rm_restores_it() {
            const KEYBINDINGS: &str = "[keybindings]\nalt-b = \"backward-word\"\n\
                                       home = \"beginning-of-line\"\n";
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let first = apply(&home, KEYBINDINGS);
            // readline gets the same bindings in `~/.inputrc`.
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.inputrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: keybindings\n\
                     if [[ -n ${{terminfo[khome]-}} ]]; then \
                     bindkey -- \"${{terminfo[khome]}}\" beginning-of-line; fi\n\
                     bindkey -- '^[[H' beginning-of-line\n\
                     bindkey -- '^[b' backward-word\n",
                    interactive("")
                )
            );

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, KEYBINDINGS);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, KEYBINDINGS).executed);
            assert_eq!(read(&home, ".local/share/bx/zshrc.zsh"), written);

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc", "~/.inputrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            assert!(!home.child(".inputrc").exists());
        }

        #[test]
        fn binding_no_key_places_nothing_and_an_unknown_one_fails_the_load() {
            let home = guarded_home();
            assert_eq!(rows(&plan(&home, "[keybindings]\n")), vec![]);
            for (layer, needle) in [
                (
                    "[keybindings]\nctrl-a = \"beginning-of-line\"\n",
                    "unknown key `ctrl-a` in [keybindings]",
                ),
                (
                    "[keybindings]\nhome = \"kill-line\"\n",
                    "found \"kill-line\"",
                ),
            ] {
                crate::plan::tests::seed(home.path(), layer);
                let err = crate::plan::Inputs::load(&crate::plan::tests::env(home.path()))
                    .expect_err(layer)
                    .to_string();
                assert!(err.contains(needle), "{layer}: {err}");
            }
        }

        #[test]
        fn declaring_no_history_zsh_reads_places_nothing() {
            let home = guarded_home();
            assert_eq!(rows(&plan(&home, "[history]\n[shell-options]\n")), vec![]);
            // What only bash reads places bash's file alone.
            let layer =
                "[history.file]\nbash = \"~/.bash_history\"\n[shell-options]\nhistappend = true\n";
            assert_eq!(
                rows(&plan(&home, layer)),
                vec![
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
        }

        #[test]
        fn a_zsh_history_file_bx_owns_or_would_commit_blocks_the_file() {
            let home = guarded_home();
            for (file, reason) in [
                (
                    "~/.local/state/bx/history",
                    "points inside a directory bx owns",
                ),
                (
                    "~/.local/share/bx/history",
                    "points inside a directory bx owns",
                ),
                ("~/.config/bx/history", "points inside bx's config repo"),
            ] {
                let layer = format!("[history.file]\nzsh = \"{file}\"\n");
                let report = plan(&home, &layer);
                let row = row(&report, "~/.local/share/bx/zshrc.zsh");
                assert_eq!(row.action, Action::Blocked, "{file}");
                let note = row.note.as_deref().expect("a note");
                assert!(
                    note.contains(&format!("[history] zsh file {file} {reason}")),
                    "{note}"
                );
            }
            // Anywhere else in the home, or outside it, is the user's choice.
            for file in [
                "~/.zsh_history",
                "~/.local/state/zsh/history",
                "/srv/history",
            ] {
                let layer = format!("[history.file]\nzsh = \"{file}\"\n");
                let report = plan(&home, &layer);
                assert_eq!(
                    row(&report, "~/.local/share/bx/zshrc.zsh").action,
                    Action::Create,
                    "{file}"
                );
            }
        }

        #[test]
        fn a_second_terminal_claimant_fails_the_load_naming_both() {
            let home = guarded_home();
            let layer = [
                plugin("zsh-syntax-highlighting", "~/a.zsh", true),
                plugin("fast-syntax-highlighting", "~/b.zsh", true),
            ]
            .concat();
            crate::plan::tests::seed(home.path(), &layer);
            let err = crate::plan::Inputs::load(&crate::plan::tests::env(home.path()))
                .expect_err("two terminal claimants fail the load")
                .to_string();
            assert!(err.contains("`fast-syntax-highlighting`"), "{err}");
            assert!(
                err.contains("plugin `zsh-syntax-highlighting` already claims at "),
                "{err}"
            );
            assert!(err.contains("bx.toml:1"), "{err}");
        }

        /// The `aliases` phase of an interactive file's bytes: from its
        /// heading up to the next phase's, headings excluded.
        fn aliases_phase(written: &str) -> &str {
            let heading = "# bx phase: aliases\n";
            let start = written.find(heading).expect("an aliases phase") + heading.len();
            let rest = &written[start..];
            rest.find("\n# bx phase: ")
                .map_or(rest, |end| &rest[..=end])
        }

        #[test]
        fn declared_aliases_arrive_as_their_tool_does_and_set_no_variable() {
            use std::os::unix::fs::PermissionsExt as _;
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            // A tool bx does not find yet, by absolute path so no `PATH` is
            // consulted.
            let tool = home.child("opt/bat");
            std::fs::create_dir_all(tool.parent().expect("a parent")).expect("mkdir");
            let tool = tool.to_str().expect("a UTF-8 path").to_string();
            let layer = format!(
                "[aliases]\nll = \"ls -la\"\nsudo = \"sudo \"\n\
                 [[alias]]\nname = \"cat\"\ncommand = \"bat --paging=never\"\n\
                 when = \"has:{tool}\"\n\
                 [[alias]]\nname = \"x\"\ncommand = \"export X=1\"\nwhen = \"env:TMUX\"\n\
                 [[alias]]\nname = \"off\"\ncommand = \"y\"\nenabled = false\n"
            );

            // Aliases alone place the file, and the region that sources it,
            // and bash's.
            let first = apply(&home, &layer);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            let runtime = "if [[ -n ${TMUX+x} ]]; then\n  alias x='export X=1'\nfi\n";
            assert_eq!(
                written,
                format!(
                    "{}\n# bx phase: aliases\nalias ll='ls -la'\nalias sudo='sudo '\n{runtime}",
                    interactive("")
                )
            );

            // Idempotent while the tool is missing.
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );

            // Installing the tool is a change the next plan shows, and the
            // alias arrives, written plainly, with no `command -v`.
            std::fs::write(&tool, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let installed = plan(&home, &layer);
            assert_eq!(
                row(&installed, "~/.local/share/bx/zshrc.zsh").action,
                Action::Modify
            );
            assert_eq!(row(&installed, "~/.zshrc").action, Action::Unchanged);
            assert_eq!(
                row(&installed, "~/.local/share/bx/bashrc.bash").action,
                Action::Modify
            );
            assert_eq!(row(&installed, "~/.bashrc").action, Action::Unchanged);
            apply(&home, &layer);
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            let phase = aliases_phase(&written);
            assert_eq!(
                phase,
                format!(
                    "alias ll='ls -la'\nalias sudo='sudo '\n\
                     alias cat='bat --paging=never'\n{runtime}"
                )
            );
            assert!(!written.contains("command -v"), "{written}");
            assert!(!written.contains("off"), "{written}");
            let settled = plan(&home, &layer);
            assert!(
                settled
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&settled)
            );

            // Invariant 2: the written `aliases` phase is not an environment
            // fragment, so sourcing its bytes, with its runtime condition
            // true, changes no parameter and exports nothing.
            if let Some(zsh) = crate::shell::testing::installed("zsh") {
                let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                            [[ ${parameters[$n]} == *special* ]] || \
                            print -r -- \"$n=${(P)n}\"; \
                            done; print -r -- ---; export; print -r -- ---; }\n";
                let dumps = |body: &str| {
                    let script =
                        format!("TMUX=1\n{dump}__bx_dump >/dev/null\n__bx_dump\n{body}__bx_dump\n");
                    let got = String::from_utf8(crate::shell::testing::run(&zsh, &["-f"], &script))
                        .expect("utf-8");
                    got.split("---\n").map(str::to_string).collect::<Vec<_>>()
                };
                let parts = dumps(phase);
                assert_eq!(parts[1], parts[3], "nothing is exported");
                assert_eq!(parts[0], parts[2], "no parameter changes");
                // The aliases were defined, so the phase ran at all.
                let defined = crate::shell::testing::run(
                    &zsh,
                    &["-f"],
                    &format!("TMUX=1\n{phase}print -r -- \"${{aliases[x]}}\"\n"),
                );
                assert_eq!(defined, b"export X=1\n");
                // The dump does see an assignment, so the equalities mean
                // something.
                let parts = dumps("Z=1\n");
                assert_ne!(parts[2], parts[0]);
            }

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
        }

        #[test]
        fn bash_gets_its_file_a_fixed_region_and_an_inputrc_twice_alike_and_rm_restores_them() {
            const SHARED: &str = "[aliases]\nll = \"ls -la\"\n\
                                  [history]\nsize = 500\nignore_space = true\n\
                                  [shell-options]\nhistappend = true\n\
                                  [keybindings]\nalt-f = \"forward-word\"\n";
            let bashrc = "# a distribution's own ~/.bashrc\n\
                          [ -z \"$PS1\" ] && return\nPS1='\\u@\\h \\w\\$ '\n";
            let home = guarded_home();
            home.write(".bashrc", bashrc);
            let first = apply(&home, SHARED);
            assert_eq!(
                rows(&first)
                    .into_iter()
                    .filter(|(path, _)| !path.contains("zsh"))
                    .collect::<Vec<_>>(),
                vec![
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Modify),
                    ("~/.inputrc", Action::Create),
                ]
            );
            // The region is appended, and every byte around it is the user's.
            let region = "# >>> bx >>>\n\
                          [[ -r ~/.local/share/bx/bashrc.bash ]] && \
                          source ~/.local/share/bx/bashrc.bash\n\
                          # <<< bx <<<\n";
            assert_eq!(read(&home, ".bashrc"), format!("{bashrc}{region}"));
            let file = read(&home, ".local/share/bx/bashrc.bash");
            assert_eq!(
                file,
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: aliases\nalias ll='ls -la'\n\
                 \n# bx phase: options\nHISTSIZE=500\nHISTFILESIZE=500\n\
                 HISTCONTROL=ignorespace\nexport -n HISTSIZE HISTFILESIZE HISTCONTROL\n\
                 shopt -s histappend\n"
            );
            let inputrc = read(&home, ".inputrc");
            assert!(
                inputrc.ends_with("$include /etc/inputrc\n\"\\ef\": forward-word\n"),
                "{inputrc}"
            );

            // bash reads the region, and through it the file.
            if let Some(bash) = crate::shell::testing::installed("bash") {
                // The region names the file under `~`, so run under this home.
                let script = format!(
                    "HOME={}\nPS1=x\nsource ~/.bashrc\n\
                     printf '%s|' \"${{BASH_ALIASES[ll]}}\" \"$HISTSIZE\"\n",
                    home.path().display()
                );
                let out = crate::shell::testing::run(&bash, &["--norc", "--noprofile"], &script);
                assert_eq!(String::from_utf8(out).expect("utf-8"), "ls -la|500|");
            }

            // Idempotent: an empty second plan, and nothing rewritten.
            let second = plan(&home, SHARED);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, SHARED).executed);
            assert_eq!(read(&home, ".local/share/bx/bashrc.bash"), file);
            assert_eq!(read(&home, ".bashrc"), format!("{bashrc}{region}"));
            assert_eq!(read(&home, ".inputrc"), inputrc);

            // Declaring nothing any more leaves bash's files planned empty,
            // and the region as it is.
            let vacated = plan(&home, "");
            for path in ["~/.local/share/bx/bashrc.bash", "~/.inputrc"] {
                assert_eq!(row(&vacated, path).action, Action::Modify, "{path}");
            }
            assert!(
                vacated
                    .changes
                    .iter()
                    .all(|change| change.target != "~/.bashrc"),
                "{:?}",
                rows(&vacated)
            );

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = [
                "~/.local/share/bx/zshrc.zsh",
                "~/.zshrc",
                "~/.local/share/bx/bashrc.bash",
                "~/.bashrc",
                "~/.inputrc",
            ]
            .iter()
            .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
            .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert_eq!(read(&home, ".bashrc"), bashrc);
            assert!(!home.child(".local/share/bx/bashrc.bash").exists());
            assert!(!home.child(".inputrc").exists());
        }

        #[test]
        fn an_inputrc_a_dropped_target_wrote_is_left_alone() {
            // PR #102 note D1: the ledger records a `[[target]]`'s file as
            // owned whole, as it does the inputrc bx generates, so dropping
            // the target planned `~/.inputrc` rewritten with no bindings. It
            // is reported as undeclared instead (#100), and never written.
            let bindings = "set editing-mode vi\n";
            let target =
                "[[target]]\npath = \"~/.inputrc\"\ncontent = \"set editing-mode vi\\n\"\n";
            let home = guarded_home();
            assert_eq!(
                row(&apply(&home, target), "~/.inputrc").action,
                Action::Create
            );
            assert_eq!(read(&home, ".inputrc"), bindings);

            let dropped = plan(&home, "");
            assert_eq!(rows(&dropped), [("~/.inputrc", Action::Undeclared)]);
            assert!(!apply(&home, "").executed);
            assert_eq!(read(&home, ".inputrc"), bindings);
        }

        #[test]
        fn an_inputrc_bx_did_not_write_is_a_conflict_left_as_it_is() {
            let home = guarded_home();
            home.write(".inputrc", "set bell-style none\n");
            let report = apply(&home, "[keybindings]\nhome = \"beginning-of-line\"\n");
            assert_eq!(row(&report, "~/.inputrc").action, Action::Conflict);
            assert_eq!(read(&home, ".inputrc"), "set bell-style none\n");
        }

        #[test]
        fn a_bash_history_file_bx_owns_blocks_bash_s_file() {
            let home = guarded_home();
            let layer = "[history.file]\nbash = \"~/.local/state/bx/history\"\n";
            let report = plan(&home, layer);
            let file = row(&report, "~/.local/share/bx/bashrc.bash");
            assert_eq!(file.action, Action::Blocked);
            let note = file.note.as_deref().expect("a note");
            assert!(
                note.contains(
                    "[history] bash file ~/.local/state/bx/history \
                     points inside a directory bx owns"
                ),
                "{note}"
            );
            let layer = "[history.file]\nbash = \"~/.bash_history\"\n";
            assert_eq!(
                row(&plan(&home, layer), "~/.local/share/bx/bashrc.bash").action,
                Action::Create
            );
        }

        /// The `functions` phase of an interactive file's bytes: from its
        /// heading up to the next phase's, headings excluded.
        fn functions_phase(written: &str) -> &str {
            let heading = "# bx phase: functions\n";
            let start = written.find(heading).expect("a functions phase") + heading.len();
            let rest = &written[start..];
            rest.find("\n# bx phase: ")
                .map_or(rest, |end| &rest[..=end])
        }

        #[test]
        fn a_declared_function_arrives_once_its_value_is_answered_and_sets_only_hook_arrays() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let layer = "[[value]]\nname = \"proj\"\nkind = \"string\"\n\n\
                         [[function]]\nname = \"mkcd\"\n\
                         body = '''\nmkdir -p -- \"$1\" && cd -- \"$1\"\n'''\n\
                         [[function]]\nname = \"goproj\"\nbody = \"cd -- {{proj}}\"\n\
                         [[function]]\nname = \"track\"\nbody = \"return 0\"\nhook = \"chpwd\"\n\
                         shells = [\"zsh\"]\n\
                         [[function]]\nname = \"off\"\nbody = \"x\"\nenabled = false\n";
            let registration = "(( ${+chpwd_functions} )) && \
                                (( ${chpwd_functions[(Ie)__bx_hook_track]} )) || \
                                chpwd_functions+=(__bx_hook_track)\n";
            let ready = format!(
                "function mkcd {{\nmkdir -p -- \"$1\" && cd -- \"$1\"\n}}\n\
                 function __bx_hook_track {{\nreturn 0\n}}\n{registration}"
            );

            // Functions alone place the file and its region. The one waiting
            // on `proj` is held back, named in the file's row, and every
            // other function is written.
            let first = apply(&home, layer);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            // bash defines what reaches it, and its row names the function
            // held back and the one kept to zsh.
            let bash_note = row(&first, "~/.local/share/bx/bashrc.bash")
                .note
                .as_deref()
                .expect("a note");
            assert!(
                bash_note.contains("function `goproj` held back: "),
                "{bash_note}"
            );
            assert!(
                bash_note.ends_with("; not in bash: function `track`"),
                "{bash_note}"
            );
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: functions\n\
                 function mkcd {\nmkdir -p -- \"$1\" && cd -- \"$1\"\n}\n"
            );
            let note = row(&first, "~/.local/share/bx/zshrc.zsh")
                .note
                .as_deref()
                .expect("a note naming the held-back function");
            assert!(note.contains("function `goproj` held back: "), "{note}");
            assert!(note.contains("proj"), "{note}");
            assert!(note.contains("bx init"), "{note}");
            assert_eq!(row(&first, "~/.zshrc").note, None);
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            assert_eq!(
                written,
                format!("{}\n# bx phase: functions\n{ready}", interactive(""))
            );
            assert!(!written.contains("goproj"), "{written}");
            assert!(!written.contains("off"), "{written}");

            // Idempotent while the value is unanswered: nothing to write, and
            // the row still says why the function is missing.
            let second = plan(&home, layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            let held = row(&second, "~/.local/share/bx/zshrc.zsh")
                .note
                .as_deref()
                .expect("the held-back function is still named");
            assert!(held.starts_with("function `goproj` held back: "), "{held}");
            assert!(note.ends_with(held), "{note}");

            // Answering the value is a change the next plan shows, and the
            // function arrives with it substituted, in declaration order.
            home.write(
                ".local/state/bx/local.toml",
                "[values]\nproj = \"src/bx\"\n",
            );
            let answered = plan(&home, layer);
            let file = row(&answered, "~/.local/share/bx/zshrc.zsh");
            assert_eq!(file.action, Action::Modify);
            assert_eq!(file.note, None, "nothing is held back");
            assert_eq!(row(&answered, "~/.zshrc").action, Action::Unchanged);
            apply(&home, layer);
            let written = read(&home, ".local/share/bx/zshrc.zsh");
            let phase = functions_phase(&written);
            assert_eq!(
                phase,
                format!(
                    "function mkcd {{\nmkdir -p -- \"$1\" && cd -- \"$1\"\n}}\n\
                     function goproj {{\ncd -- src/bx\n}}\n\
                     function __bx_hook_track {{\nreturn 0\n}}\n{registration}"
                )
            );
            let settled = plan(&home, layer);
            assert!(
                settled
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&settled)
            );

            // Invariant 2: sourcing the written `functions` phase exports
            // nothing and changes no parameter but zsh's hook arrays.
            if let Some(zsh) = crate::shell::testing::installed("zsh") {
                let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                            [[ ${parameters[$n]} == *special* ]] || \
                            print -r -- \"$n=${(P)n}\"; \
                            done; print -r -- ---; export; print -r -- ---; }\n";
                let dumps = |body: &str| {
                    let script =
                        format!("{dump}__bx_dump >/dev/null\n__bx_dump\n{body}__bx_dump\n");
                    let got = String::from_utf8(crate::shell::testing::run(&zsh, &["-f"], &script))
                        .expect("utf-8");
                    got.split("---\n").map(str::to_string).collect::<Vec<_>>()
                };
                let parts = dumps(phase);
                assert_eq!(parts[1], parts[3], "nothing is exported");
                let hooks: Vec<String> = crate::shell::function::Hook::ALL
                    .iter()
                    .map(|hook| hook.array())
                    .collect();
                let kept = |dump: &str| {
                    dump.lines()
                        .filter(|line| {
                            let name = line.split('=').next().unwrap_or_default();
                            !hooks.iter().any(|hook| hook == name)
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                assert_eq!(kept(&parts[2]), kept(&parts[0]), "only hook arrays change");
                assert!(
                    parts[2]
                        .lines()
                        .any(|line| line == "chpwd_functions=__bx_hook_track"),
                    "{}",
                    parts[2]
                );
                // The functions were defined, so the phase ran at all.
                let defined = crate::shell::testing::run(
                    &zsh,
                    &["-f"],
                    &format!("{phase}print -r -- ${{+functions[goproj]}} ${{+functions[mkcd]}}\n"),
                );
                assert_eq!(defined, b"1 1\n");
                // The dump does see an assignment, so the equalities mean
                // something.
                let parts = dumps("Z=1\n");
                assert_ne!(kept(&parts[2]), kept(&parts[0]));
            }

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
        }

        #[test]
        fn a_declared_source_arrives_guarded_in_its_phase_whether_or_not_its_file_exists() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let layer = "[[value]]\nname = \"host\"\nkind = \"string\"\n\n\
                         [[source]]\nname = \"keychain\"\npath = \"~/.keychain/{{host}}-sh\"\n\
                         phase = \"activations\"\n\
                         [[source]]\nname = \"fzf\"\npath = \"~/.fzf.zsh\"\n\
                         [[source]]\nname = \"off\"\npath = \"~/off\"\nenabled = false\n";
            let settle = "\n# bx: done, whichever plugins were found\ntrue\n";

            // Sources alone place the file and its region. The one waiting on
            // `host` is held back and named in the file's row; the other is
            // written as its guarded line, and the file settles to 0.
            let first = apply(&home, layer);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            // bash sources the same line, and settles the same way.
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                format!(
                    "# Generated by bx. Edit the config repo, not this file.\n\
                     \n# bx phase: plugins\n[[ -r ~/.fzf.zsh ]] && source ~/.fzf.zsh\n{settle}"
                )
            );
            let note = row(&first, "~/.local/share/bx/zshrc.zsh")
                .note
                .as_deref()
                .expect("a note naming the held-back source");
            assert!(note.contains("source `keychain` held back: "), "{note}");
            assert!(note.contains("bx init"), "{note}");
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                format!(
                    "{}\n# bx phase: plugins\n[[ -r ~/.fzf.zsh ]] && source ~/.fzf.zsh\n{settle}",
                    interactive("")
                )
            );

            // The file's presence is never an input: creating it changes no
            // plan, and nothing bx wrote reads it.
            home.write(".fzf.zsh", "print -r -- fzf\n");
            let present = plan(&home, layer);
            assert!(
                present
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&present)
            );

            // Answering the value is a change the next plan shows, and the
            // source arrives substituted, in the phase it names.
            home.write(".local/state/bx/local.toml", "[values]\nhost = \"box-1\"\n");
            let answered = plan(&home, layer);
            let file = row(&answered, "~/.local/share/bx/zshrc.zsh");
            assert_eq!(file.action, Action::Modify);
            assert_eq!(file.note, None, "nothing is held back");
            apply(&home, layer);
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                format!(
                    "{}\n# bx phase: activations\n\
                     [[ -r ~/.keychain/box-1-sh ]] && source ~/.keychain/box-1-sh\n\
                     \n# bx phase: plugins\n[[ -r ~/.fzf.zsh ]] && source ~/.fzf.zsh\n{settle}",
                    interactive("")
                )
            );
            let settled = plan(&home, layer);
            assert!(
                settled
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&settled)
            );

            // Reversible: `rm` puts back the bytes each file held before bx.
            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = ["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
                .iter()
                .map(|raw| Portable::parse_in(raw, home.path()).expect("portable"))
                .collect();
            crate::restore::restore(&state, home.path(), &targets).expect("rm");
            assert!(!home.child(".local/share/bx/zshrc.zsh").exists());
            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            assert_eq!(
                read(&home, ".fzf.zsh"),
                "print -r -- fzf\n",
                "never touched"
            );
        }

        #[test]
        fn each_kind_lands_only_in_its_native_files_and_a_second_plan_is_empty() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let layer = every_kind();

            let first = apply(&home, &layer);
            assert!(first.executed);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Create),
                    ("~/.config/environment.d/50-bx.conf", Action::Create),
                    ("~/.local/share/bx/zprofile.zsh", Action::Create),
                    ("~/.zprofile", Action::Create),
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            // bash reads every variable a zsh would, in zsh's load order,
            // a login one only in a login shell; the GUI one is not a shell's.
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: env\n\
                 export LANG=C.UTF-8\n\
                 if shopt -q login_shell; then\n  export PAGER=less\nfi\n\
                 export EDITOR=nvim\n"
            );

            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                format!("{header}export LANG=C.UTF-8\n")
            );
            assert_eq!(
                read(&home, ".config/environment.d/50-bx.conf"),
                format!("{header}LANG=C.UTF-8\nBROWSER=firefox\n")
            );
            assert_eq!(
                read(&home, ".local/share/bx/zprofile.zsh"),
                format!("{header}export PAGER=less\n")
            );
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                interactive(&format!("{header}export EDITOR=nvim\n"))
            );
            // The user's own lines come first, byte for byte, then the region.
            assert_eq!(
                read(&home, ".zshrc"),
                format!("alias ll='ls -l'\n{ZSHRC_REGION}")
            );
            for (file, fragment) in [(".zshenv", "zshenv"), (".zprofile", "zprofile")] {
                assert_eq!(
                    read(&home, file),
                    format!(
                        "# >>> bx >>>\n[[ -r ~/.local/share/bx/{fragment}.zsh ]] && source \
                         ~/.local/share/bx/{fragment}.zsh\n# <<< bx <<<\n"
                    )
                );
            }

            let written: Vec<String> = [
                ".local/share/bx/zshenv.zsh",
                ".config/environment.d/50-bx.conf",
                ".local/share/bx/zprofile.zsh",
                ".local/share/bx/zshrc.zsh",
                ".zshenv",
                ".zprofile",
                ".zshrc",
            ]
            .iter()
            .map(|rel| read(&home, rel))
            .collect();
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            let again = apply(&home, &layer);
            assert!(!again.executed);
            let rewritten: Vec<String> = [
                ".local/share/bx/zshenv.zsh",
                ".config/environment.d/50-bx.conf",
                ".local/share/bx/zprofile.zsh",
                ".local/share/bx/zshrc.zsh",
                ".zshenv",
                ".zprofile",
                ".zshrc",
            ]
            .iter()
            .map(|rel| read(&home, rel))
            .collect();
            assert_eq!(rewritten, written);
        }

        #[test]
        fn an_edit_outside_the_region_is_never_a_conflict() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            apply(&home, &every_kind());

            // Above the region, below it, and the file's own mode.
            home.write(
                ".zshrc",
                &format!("export FOO=1\nalias ll='ls -l'\n{ZSHRC_REGION}bindkey -v\n"),
            );
            let edited = plan(&home, &every_kind());
            assert_eq!(row(&edited, "~/.zshrc").action, Action::Unchanged);

            // A change of declaration rewrites bx's fragment, and the region's
            // bytes, which never vary, stay as they are.
            let more = format!("{}{}", every_kind(), env("VISUAL", "nvim", "interactive"));
            let changed = apply(&home, &more);
            assert_eq!(
                row(&changed, "~/.local/share/bx/zshrc.zsh").action,
                Action::Modify
            );
            assert_eq!(row(&changed, "~/.zshrc").action, Action::Unchanged);
            assert!(read(&home, ".local/share/bx/zshrc.zsh").ends_with("export VISUAL=nvim\n"));
            assert_eq!(
                read(&home, ".zshrc"),
                format!("export FOO=1\nalias ll='ls -l'\n{ZSHRC_REGION}bindkey -v\n")
            );
        }

        #[test]
        fn an_unset_value_holds_back_only_the_fragment_it_would_join() {
            let home = guarded_home();
            let layer = format!(
                "[[value]]\nname = \"editor\"\nkind = \"string\"\n\n{}{}{}",
                env("LANG", "C.UTF-8", "environment"),
                env("EDITOR", "{{editor}}", "interactive"),
                crate::plan::tests::inline("~/.other", "x\\n"),
            );
            let report = plan(&home, &layer);
            assert_eq!(
                rows(&report),
                vec![
                    ("~/.other", Action::Create),
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Create),
                    ("~/.config/environment.d/50-bx.conf", Action::Create),
                    ("~/.local/share/bx/zshrc.zsh", Action::Blocked),
                    ("~/.zshrc", Action::Create),
                    // bash's file holds EDITOR too, so it waits with zsh's.
                    ("~/.local/share/bx/bashrc.bash", Action::Blocked),
                    ("~/.bashrc", Action::Create),
                ]
            );
            for file in [
                "~/.local/share/bx/zshrc.zsh",
                "~/.local/share/bx/bashrc.bash",
            ] {
                let note = row(&report, file).note.as_deref().expect("a hint");
                assert!(note.contains("editor"), "{note}");
                assert!(note.contains("bx init"), "{note}");
            }
        }

        /// One `[[env]]` entry gated on `when`.
        fn gated(name: &str, value: &str, kind: &str, when: &str) -> String {
            format!("{}when = \"{when}\"\n", env(name, value, kind))
        }

        #[test]
        fn a_gated_variable_is_written_as_decided_and_a_second_plan_is_empty() {
            use std::os::unix::fs::PermissionsExt as _;
            let home = guarded_home();
            // A tool bx finds, by absolute path so no `PATH` is consulted, and
            // one it does not.
            let tool = home.child("opt/tool");
            std::fs::create_dir_all(tool.parent().expect("a parent")).expect("mkdir");
            std::fs::write(&tool, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let tool = tool.to_str().expect("a UTF-8 path");
            let missing = home.child("opt/missing");
            let missing = missing.to_str().expect("a UTF-8 path");
            let layer = [
                gated("PAGER", "less", "login", "ssh"),
                gated("LANG", "C.UTF-8", "environment", &format!("has:{tool}")),
                gated("BROWSER", "firefox", "gui", &format!("has:{missing}")),
                gated("EDITOR", "nvim", "interactive", "env:TMUX"),
            ]
            .concat();

            apply(&home, &layer);
            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            assert_eq!(
                read(&home, ".local/share/bx/zprofile.zsh"),
                format!(
                    "{header}if [[ -n ${{SSH_CONNECTION-}} ]]; then\n  export PAGER=less\nfi\n"
                )
            );
            assert_eq!(
                read(&home, ".local/share/bx/zshrc.zsh"),
                interactive(&format!(
                    "{header}if [[ -n ${{TMUX+x}} ]]; then\n  export EDITOR=nvim\nfi\n"
                ))
            );
            // Decided while planning: present is written plainly, missing is
            // left out, and neither asks the shell.
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                format!("{header}export LANG=C.UTF-8\n")
            );
            assert_eq!(
                read(&home, ".config/environment.d/50-bx.conf"),
                format!("{header}LANG=C.UTF-8\n")
            );

            // Unchanged machine, unchanged bytes.
            let again = plan(&home, &layer);
            assert!(
                again
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&again)
            );

            // Installing the missing tool is a change the next plan shows.
            std::fs::write(missing, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(missing, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            let installed = plan(&home, &layer);
            let change = row(&installed, "~/.config/environment.d/50-bx.conf");
            assert_eq!(change.action, Action::Modify);
        }

        #[test]
        fn a_relocating_export_behind_a_condition_is_still_held_back() {
            let home = guarded_home();
            let layer = [
                env("EDITOR", "nvim", "interactive"),
                gated("CARGO_HOME", "/elsewhere/cargo", "interactive", "ssh"),
            ]
            .concat();
            let report = plan(&home, &layer);
            let change = row(&report, "~/.local/share/bx/zshrc.zsh");
            assert_eq!(change.action, Action::Blocked);
            let note = change.note.as_deref().expect("a note");
            // The file's own line: the assembly's header, a blank and the
            // `env` phase's heading come before the fragment's four lines.
            assert!(note.starts_with("line 7: CARGO_HOME "), "{note}");
            let written = interactive(
                "# Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                 export EDITOR=nvim\nif [[ -n ${SSH_CONNECTION-} ]]; then\n  \
                 export CARGO_HOME=/elsewhere/cargo\nfi\n",
            );
            assert!(
                written
                    .lines()
                    .nth(6)
                    .is_some_and(|line| line.contains("CARGO_HOME")),
                "{written}"
            );
        }

        #[test]
        fn a_fragment_the_guard_refuses_is_held_back_naming_the_line() {
            let home = guarded_home();
            let layer = [
                env("LANG", "C.UTF-8", "environment"),
                env("CARGO_HOME", "/elsewhere/cargo", "environment"),
                env("EDITOR", "nvim", "interactive"),
            ]
            .concat();
            let report = plan(&home, &layer);
            for fragment in [
                "~/.local/share/bx/zshenv.zsh",
                "~/.config/environment.d/50-bx.conf",
            ] {
                let change = row(&report, fragment);
                assert_eq!(change.action, Action::Blocked, "{fragment}");
                let note = change.note.as_deref().expect("a note");
                assert!(note.starts_with("line 3: CARGO_HOME "), "{note}");
            }
            // bash's file holds the same line, judged the same way, named by
            // its own line in that file.
            let bash = row(&report, "~/.local/share/bx/bashrc.bash");
            assert_eq!(bash.action, Action::Blocked);
            let note = bash.note.as_deref().expect("a note");
            assert!(note.starts_with("line 5: CARGO_HOME "), "{note}");
            // Nothing else is held back by it.
            assert_eq!(
                row(&report, "~/.local/share/bx/zshrc.zsh").action,
                Action::Create
            );
            assert_eq!(row(&report, "~/.zshenv").action, Action::Create);
        }

        #[test]
        fn an_environment_d_line_is_judged_as_exported() {
            // environment.d says no `export`, and every line of it reaches the
            // environment: an anchor there is held to what an exported one is.
            // Judged as a line of shell that does not say `export`, it would
            // pass.
            let home = guarded_home();
            let layer = format!(
                "[[value]]\nname = \"home_root\"\nkind = \"path\"\nis_root = true\n\
                 default = \"~\"\n\n{}",
                env("SCRATCH_HOME", "{{home_root}}", "gui")
            );
            let report = plan(&home, &layer);
            let change = row(&report, "~/.config/environment.d/50-bx.conf");
            assert_eq!(change.action, Action::Blocked, "{change:?}");
            let note = change.note.as_deref().expect("a note");
            assert!(note.starts_with("line 2: SCRATCH_HOME "), "{note}");
            // The same line, read as shell that keeps it out of the
            // environment, is allowed: the syntax is what refused it.
            let roots = RootSet::new(home.path(), &[PathBuf::from("~")]);
            let line = format!("SCRATCH_HOME={}\n", home.path().display());
            assert_eq!(guard_fragment(&line, &roots), None);
            let refused = guard_environment_d(&line, &roots).expect("refused as exported");
            assert!(refused.starts_with("line 1: SCRATCH_HOME "), "{refused}");
        }

        #[test]
        fn a_region_write_is_recorded_as_a_region_and_not_the_whole_file() {
            // Invariant 1: the bytes around a region are the user's. The
            // ledger is what says so, and what a later write and `bx rm` read.
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            apply(&home, &env("EDITOR", "nvim", "interactive"));
            assert_eq!(
                read(&home, ".zshrc"),
                format!("alias ll='ls -l'\n{ZSHRC_REGION}")
            );
            let key = Portable::parse_in("~/.zshrc", home.path()).expect("a path");
            let ledger =
                LedgerView::read(&crate::state::StateDir::resolve(home.path()), home.path())
                    .expect("the ledger")
                    .value;
            assert_eq!(
                ledger.get(&key).map(|entry| entry.mechanism.clone()),
                Some(Mechanism::Region { comment: '#' })
            );
        }

        /// The `~/.zshrc` row an interactive declaration gets over `bytes`,
        /// with bx having left `recorded` there as a region when it is given.
        fn zshrc_row(bytes: Option<&str>, recorded: Option<&[u8]>) -> Change {
            let home = guarded_home();
            if let Some(recorded) = recorded {
                own(
                    home.path(),
                    ".zshrc",
                    recorded,
                    Mechanism::Region { comment: '#' },
                );
            }
            if let Some(bytes) = bytes {
                home.write(".zshrc", bytes);
            }
            let report = plan(&home, &env("EDITOR", "nvim", "interactive"));
            row(&report, "~/.zshrc").clone()
        }

        #[test]
        fn a_region_is_rewritten_only_while_the_file_is_as_bx_left_it() {
            let old = "top\n# >>> bx >>>\nsource ~/.old\n# <<< bx <<<\n";
            // bx's own older region, in a file nobody has touched since.
            let change = zshrc_row(None, Some(old.as_bytes()));
            assert_eq!(change.action, Action::Modify, "{change:?}");
            // The same, after the user edited the file.
            let change = zshrc_row(Some(&format!("{old}more\n")), Some(old.as_bytes()));
            assert_eq!(change.action, Action::Conflict, "{change:?}");
            assert!(
                change
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("edited since")),
                "{change:?}"
            );
        }

        #[test]
        fn a_region_the_user_removed_or_bx_never_recorded_is_left_alone() {
            let recorded = format!("top\n{ZSHRC_REGION}");
            let removed = zshrc_row(Some("top\n"), Some(recorded.as_bytes()));
            assert_eq!(removed.action, Action::Conflict);
            assert!(
                removed
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("was removed")),
                "{removed:?}"
            );

            let foreign = zshrc_row(
                Some("# >>> bx >>>\nsource ~/.elsewhere\n# <<< bx <<<\n"),
                None,
            );
            assert_eq!(foreign.action, Action::Conflict);
            assert!(
                foreign
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("no record")),
                "{foreign:?}"
            );

            // A region already holding what bx wants is unchanged either way.
            assert_eq!(
                zshrc_row(Some(&format!("mine\n{ZSHRC_REGION}")), None).action,
                Action::Unchanged
            );
        }

        #[test]
        fn a_region_in_a_file_bx_owns_another_way_or_with_damaged_delimiters_is_a_conflict() {
            let home = guarded_home();
            own(home.path(), ".zshrc", b"whole\n", Mechanism::Own);
            let report = plan(&home, &env("EDITOR", "nvim", "interactive"));
            let change = row(&report, "~/.zshrc");
            assert_eq!(change.action, Action::Conflict);
            assert!(
                change
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("the whole file")),
                "{change:?}"
            );

            let damaged = zshrc_row(Some("# >>> bx >>>\nno end\n"), None);
            assert_eq!(damaged.action, Action::Conflict);
            assert_eq!(damaged.diff, None);
            let note = damaged.note.expect("a note");
            assert!(note.contains("damaged"), "{note}");
            assert!(note.contains("no closing one"), "{note}");
        }

        #[test]
        fn a_region_keeps_the_mode_of_the_file_it_joins() {
            let home = guarded_home();
            let rc = home.write(".zshrc", "mine\n");
            std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            let applied = apply(&home, &env("EDITOR", "nvim", "interactive"));
            assert_eq!(row(&applied, "~/.zshrc").action, Action::Modify);
            let mode = std::fs::metadata(&rc).expect("stat").permissions().mode() & 0o7777;
            assert_eq!(mode, 0o600);
            // A file bx creates for a region gets the default.
            let zshenv = apply(&home, &env("LANG", "C", "environment"));
            assert_eq!(row(&zshenv, "~/.zshenv").action, Action::Create);
            let mode = std::fs::metadata(home.child(".zshenv"))
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, Mode::DEFAULT_FILE.bits());
        }

        #[test]
        fn rm_puts_every_file_the_placement_graph_wrote_back_exactly() {
            let home = guarded_home();
            home.write(".zshrc", "alias ll='ls -l'\n");
            let applied = apply(&home, &every_kind());
            assert!(applied.executed);

            let state = crate::state::StateDir::resolve(home.path());
            let targets: Vec<Portable> = LedgerView::read(&state, home.path())
                .expect("the ledger")
                .value
                .iter()
                .map(|(target, _)| target.clone())
                .collect();
            assert_eq!(targets.len(), 9);
            crate::restore::restore(&state, home.path(), &targets).expect("restore");

            assert_eq!(read(&home, ".zshrc"), "alias ll='ls -l'\n");
            for rel in [
                ".zshenv",
                ".zprofile",
                ".bashrc",
                ".config/environment.d",
                ".local/share/bx",
            ] {
                assert!(!home.child(rel).exists(), "{rel} is left behind");
            }
        }

        /// A `[path]` section: a prepend, a gated prepend, one reading an
        /// `[[env]]` variable, an append, and a removal.
        const PATH_SECTION: &str = "[path]\n\
             prepend = [\"~/bin\", { dir = \"~/.local/bin\", if_exists = true }, \
             \"$CARGO_HOME/bin\"]\n\
             append = [\"/opt/tool/bin\"]\n\
             remove = [\"~/.cargo/bin\"]\n";

        /// The lines [`PATH_SECTION`] puts in the `zshenv` fragment.
        const PATH_LINES: &str = "# [path]\n\
             path=(${path:#${CARGO_HOME}/bin})\n\
             export PATH=${CARGO_HOME}/bin:${PATH}\n\
             path=(${path:#${HOME}/.local/bin})\n\
             [[ -d ${HOME}/.local/bin ]] && export PATH=${HOME}/.local/bin:${PATH}\n\
             path=(${path:#${HOME}/bin})\n\
             export PATH=${HOME}/bin:${PATH}\n\
             path=(${path:#/opt/tool/bin})\n\
             export PATH=${PATH}:/opt/tool/bin\n\
             path=(${path:#${HOME}/.cargo/bin})\n";

        /// The lines [`PATH_SECTION`] puts in bash's file's `path` phase:
        /// zsh's, each removal in bash's words.
        const BASH_PATH_LINES: &str = "# [path]\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${CARGO_HOME}/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             export PATH=${CARGO_HOME}/bin:${PATH}\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/.local/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             [[ -d ${HOME}/.local/bin ]] && export PATH=${HOME}/.local/bin:${PATH}\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             export PATH=${HOME}/bin:${PATH}\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":/opt/tool/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n\
             export PATH=${PATH}:/opt/tool/bin\n\
             PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/.cargo/bin:\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}\n";

        /// [`PATH_SECTION`] with the variable it reads, under a declared
        /// root.
        fn with_path() -> String {
            format!(
                "[[value]]\nname = \"scratch\"\nkind = \"path\"\nis_root = true\n\
                 default = \"/var/mnt/scratch/example\"\n\n{}{}{}{PATH_SECTION}",
                env("LANG", "C.UTF-8", "environment"),
                env("CARGO_HOME", "{{scratch}}/cargo", "environment"),
                env("EDITOR", "nvim", "interactive"),
            )
        }

        #[test]
        fn path_entries_land_once_in_the_zshenv_fragment_and_bash_s_file_after_their_variables() {
            let home = guarded_home();
            home.write(".zshenv", "# my own\nexport FOO=1\n");
            let layer = with_path();

            let first = apply(&home, &layer);
            assert!(first.executed);
            assert_eq!(
                rows(&first),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Modify),
                    ("~/.config/environment.d/50-bx.conf", Action::Create),
                    ("~/.local/share/bx/zshrc.zsh", Action::Create),
                    ("~/.zshrc", Action::Create),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            let header = "# Generated by bx from [[env]]. Edit the config repo, not this file.\n";
            // The file every zsh reads, login or not: the variables it
            // exports, then the PATH lines that read them.
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                format!(
                    "{header}export LANG=C.UTF-8\n\
                     export CARGO_HOME=/var/mnt/scratch/example/cargo\n{PATH_LINES}"
                )
            );
            // bash's file: its variables, then the same PATH lines in its
            // own words.
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                format!(
                    "# Generated by bx. Edit the config repo, not this file.\n\
                     \n# bx phase: env\nexport LANG=C.UTF-8\n\
                     export CARGO_HOME=/var/mnt/scratch/example/cargo\n\
                     export EDITOR=nvim\n\
                     \n# bx phase: path\n{BASH_PATH_LINES}"
                )
            );
            // And nowhere else.
            for rel in [
                ".config/environment.d/50-bx.conf",
                ".local/share/bx/zshrc.zsh",
            ] {
                assert!(!read(&home, rel).contains("PATH"), "{rel}");
            }
            // The user's own lines survive, byte for byte, ahead of the region.
            assert_eq!(
                read(&home, ".zshenv"),
                "# my own\nexport FOO=1\n# >>> bx >>>\n[[ -r ~/.local/share/bx/zshenv.zsh ]] \
                 && source ~/.local/share/bx/zshenv.zsh\n# <<< bx <<<\n"
            );

            // Applying twice: an empty second plan, and the same bytes.
            let written = read(&home, ".local/share/bx/zshenv.zsh");
            let bash_written = read(&home, ".local/share/bx/bashrc.bash");
            let second = plan(&home, &layer);
            assert!(
                second
                    .changes
                    .iter()
                    .all(|change| change.action == Action::Unchanged),
                "{:?}",
                rows(&second)
            );
            assert!(!apply(&home, &layer).executed);
            assert_eq!(read(&home, ".local/share/bx/zshenv.zsh"), written);
            assert_eq!(read(&home, ".local/share/bx/bashrc.bash"), bash_written);

            // A line the user adds beside the region is theirs, and a change
            // of entries rewrites only bx's fragment.
            home.write(
                ".zshenv",
                &format!("{}bindkey -e\n", read(&home, ".zshenv")),
            );
            let fewer = layer.replace(", \"$CARGO_HOME/bin\"", "");
            let changed = apply(&home, &fewer);
            assert_eq!(
                row(&changed, "~/.local/share/bx/zshenv.zsh").action,
                Action::Modify
            );
            assert_eq!(row(&changed, "~/.zshenv").action, Action::Unchanged);
            assert!(read(&home, ".zshenv").starts_with("# my own\nexport FOO=1\n"));
            assert!(read(&home, ".zshenv").ends_with("# <<< bx <<<\nbindkey -e\n"));
            assert!(!read(&home, ".local/share/bx/zshenv.zsh").contains("CARGO_HOME}/bin"));
        }

        #[test]
        fn a_path_section_alone_places_the_zshenv_fragment_bash_s_file_and_their_regions() {
            let home = guarded_home();
            let layer = "[path]\nprepend = [\"~/bin\"]\n";
            let report = plan(&home, layer);
            assert_eq!(
                rows(&report),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Create),
                    ("~/.zshenv", Action::Create),
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
            apply(&home, layer);
            assert_eq!(
                read(&home, ".local/share/bx/zshenv.zsh"),
                "# Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                 # [path]\npath=(${path:#${HOME}/bin})\nexport PATH=${HOME}/bin:${PATH}\n"
            );
            assert_eq!(
                read(&home, ".local/share/bx/bashrc.bash"),
                "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: path\n# [path]\n\
                 PATH=:${PATH//:/::}:; PATH=${PATH//\":${HOME}/bin:\"/}; PATH=${PATH//::/:}; \
                 PATH=${PATH#:}; PATH=${PATH%:}\nexport PATH=${HOME}/bin:${PATH}\n"
            );
            // Taking the section out leaves both files setting nothing.
            let emptied = apply(&home, "");
            assert_eq!(
                rows(&emptied),
                vec![
                    ("~/.local/share/bx/zshenv.zsh", Action::Modify),
                    ("~/.local/share/bx/bashrc.bash", Action::Modify),
                ]
            );
            assert!(!read(&home, ".local/share/bx/zshenv.zsh").contains("PATH"));
            assert!(!read(&home, ".local/share/bx/bashrc.bash").contains("PATH"));
        }

        #[test]
        fn an_entry_kept_to_one_shell_reaches_only_its_file_and_the_other_row_names_it() {
            let home = guarded_home();
            let layer = "[path]\nprepend = [\"~/both\", { dir = \"~/z\", shells = [\"zsh\"] }, \
                         { dir = \"~/b\", shells = [\"bash\"] }]\n";
            let report = apply(&home, layer);
            let zshenv = read(&home, ".local/share/bx/zshenv.zsh");
            let bashrc = read(&home, ".local/share/bx/bashrc.bash");
            assert!(zshenv.contains("${HOME}/both") && bashrc.contains("${HOME}/both"));
            assert!(zshenv.contains("${HOME}/z:") && !bashrc.contains("${HOME}/z"));
            assert!(bashrc.contains("${HOME}/b:") && !zshenv.contains("${HOME}/b:"));
            let note = row(&report, "~/.local/share/bx/bashrc.bash")
                .note
                .clone()
                .expect("a note");
            assert!(note.ends_with("; not in bash: path `~/z`"), "{note}");
            // An entry kept to bash alone places bash's file and not zsh's.
            let home = guarded_home();
            let only_bash = "[path]\nappend = [{ dir = \"/opt/b\", shells = [\"bash\"] }]\n";
            assert_eq!(
                rows(&plan(&home, only_bash)),
                vec![
                    ("~/.local/share/bx/bashrc.bash", Action::Create),
                    ("~/.bashrc", Action::Create),
                ]
            );
        }

        #[test]
        fn a_reference_bash_s_file_cannot_read_holds_it_back_naming_its_own_line() {
            let home = guarded_home();
            let layer = format!(
                "{}[path]\nprepend = [\"${{NOWHERE}}/bin\"]\n",
                env("LANG", "C.UTF-8", "environment"),
            );
            let report = plan(&home, &layer);
            let change = row(&report, "~/.local/share/bx/bashrc.bash");
            assert_eq!(change.action, Action::Blocked);
            let note = change.note.as_deref().expect("a note");
            // The header, the env phase's heading and variable, the path
            // phase's heading and comment, then the removal on line 8.
            assert!(note.starts_with("line 8: PATH "), "{note}");
        }

        #[test]
        fn a_reference_to_a_variable_the_file_has_not_exported_holds_the_fragment_back() {
            // EDITOR is exported, but only to interactive shells, from another
            // file; NOWHERE is declared nowhere. Neither is set where the
            // PATH line would read it, so the fragment is held back naming
            // the line, and no other target is.
            for dir in ["$EDITOR/bin", "${NOWHERE}/bin"] {
                let home = guarded_home();
                let layer = format!(
                    "{}{}[path]\nprepend = [\"{dir}\"]\n",
                    env("LANG", "C.UTF-8", "environment"),
                    env("EDITOR", "nvim", "interactive"),
                );
                let report = plan(&home, &layer);
                let change = row(&report, "~/.local/share/bx/zshenv.zsh");
                assert_eq!(change.action, Action::Blocked, "{dir}");
                let note = change.note.as_deref().expect("a note");
                assert!(note.starts_with("line 4: PATH "), "{dir}: {note}");
                assert_eq!(row(&report, "~/.zshenv").action, Action::Create);
                assert_eq!(
                    row(&report, "~/.local/share/bx/zshrc.zsh").action,
                    Action::Create
                );
            }
        }
    }
}
