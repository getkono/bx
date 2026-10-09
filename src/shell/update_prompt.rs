//! The question about followed externals' updates, asked at a zsh or bash
//! prompt.
//!
//! When the configuration has an `[[external]]` that follows a branch, the
//! generated interactive zsh file defines one hook on `precmd` ([`ZSH`]), and
//! bash's generated interactive file defines the same hook in bash's words and
//! appends it to `PROMPT_COMMAND` ([`BASH`]). At each prompt
//! of an interactive shell a person is at, it reads the stamps `bx update`
//! keeps ([`crate::update`]) and does at most one of three things:
//!
//! 1. **Something was found.** `update/available` lists what a check found:
//!    the hook prints it and asks `bx: update now? [y/N]`. `y` runs
//!    `bx update`, which shows the plan and asks once more before it locks,
//!    commits or applies anything; any other answer runs
//!    `bx update --snooze`, which offers nothing more until the next interval.
//! 2. **A background check is due.** `update/check-due` has passed — an
//!    external is `check = "auto"`: the hook starts
//!    `bx update --background`, detached and silent, and asks nothing. What it
//!    finds is offered at a later prompt.
//! 3. **A question is due.** `update/ask-due` has passed: the hook asks
//!    whether to check now. `y` runs `bx update`; any other answer snoozes.
//!
//! It asks at most once per shell, and starts at most one background check
//! per shell. A shell that started one does not also ask whether to check:
//! it offers what that check finds instead.
//!
//! # Only a person at a terminal is asked
//!
//! The hook does nothing at all unless the shell is interactive, standard
//! input and output are both terminals, `TERM` is not `dumb`, and none of
//! `CI`, `CLAUDECODE`, `CODEX_SANDBOX`, `GEMINI_CLI`, `CURSOR_AGENT` and
//! `BX_NO_UPDATE_PROMPT` is set — the variables continuous integration and
//! the coding agents that drive a shell set, and the one a person sets to be
//! left alone. A script, a service, an agent, `zsh -c` and `bash -c`
//! therefore never see a question or start a check, and nothing reaches the
//! network without a keypress unless an external is `check = "auto"`.
//!
//! # bash's hook
//!
//! bash's only per-prompt hook is `PROMPT_COMMAND`, an ordinary variable a
//! parent may export, so registering there is held to more than zsh's
//! `precmd_functions` is:
//!
//! - **Appended, never replaced.** A scalar `PROMPT_COMMAND` keeps every
//!   byte it held and gains one line, `${BX_UPDATE_HOOK-}`; an array one
//!   (bash 5.1) gains one element. One already holding that entry — a
//!   `~/.bashrc` sourced twice — is left as it is.
//! - **Not in the environment, and harmless if put there.** An exported or
//!   read-only `PROMPT_COMMAND` is left alone and that shell is not asked;
//!   one that was unset becomes a shell variable, which no process inherits.
//!   bx cannot stop a line that runs after its own — a later
//!   `export PROMPT_COMMAND` in `~/.bashrc` — from exporting the appended
//!   entry, so the entry names no function: it expands the unexported
//!   `BX_UPDATE_HOOK`, which holds `__bx_update`. A child shell that
//!   inherits the entry has no `BX_UPDATE_HOOK`, so the entry expands to
//!   nothing there and prints no `command not found`.
//! - **The status kept.** `__bx_update` returns the status it was called
//!   with, so a prompt that shows the last command's status shows the same
//!   one it would without bx.
//! - **bash 4.4 or later.** Reading `PROMPT_COMMAND`'s attributes needs
//!   `${PROMPT_COMMAND@a}`; an older bash is not asked.
//!
//! # Invariant 6
//!
//! Sourcing either file defines two functions and registers one; nothing
//! runs until the first prompt, which a startup benchmark (`zsh -i -c exit`,
//! `bash -i -c exit`) never reaches. The hook itself reads the stamps with
//! the `read` builtin and takes the time from a prompt expansion in zsh and
//! `printf '%(%s)T'` in bash, so a prompt with nothing due starts no
//! process. The only processes it ever starts are the detached background
//! check, at most once per shell and only once `check-due` has passed, and
//! `bx update` itself once someone answers.
//!
//! # Invariant 2
//!
//! Generated shell content that is not an environment fragment may assign
//! nothing but bx's own `BX_` names, a function's locals, zsh's hook arrays
//! and an append to an unexported `PROMPT_COMMAND`. The hook assigns its
//! locals, `BX_UPDATE_ASKED`, `BX_UPDATE_CHECKING` and, in bash,
//! `BX_UPDATE_HOOK` (never exported), and
//! registers itself as above; `env_guard`'s
//! `the_update_prompt_is_not_an_environment_fragment` and
//! `the_bash_update_prompt_is_not_an_environment_fragment` hold the bytes to
//! that, and the tests here run them.

use super::{Assembly, Phase, Shell};

/// The owner the hook is contributed under.
pub const SECTION: &str = "bx update";

/// The hook, as the `functions` phase holds it.
pub const ZSH: &str = r#"# Asks about followed externals' updates at a prompt a person is at, at most
# once per shell. Reads bx's update stamps; starts nothing until one is due.
__bx_update() {
  [[ -o interactive && -t 0 && -t 1 && $TERM != dumb ]] || return 0
  __bx_update_due
}
__bx_update_due() {
  [[ -z $BX_UPDATE_ASKED ]] || return 0
  [[ -z ${CI-}${CLAUDECODE-}${CODEX_SANDBOX-}${GEMINI_CLI-}${CURSOR_AGENT-}${BX_NO_UPDATE_PROMPT-} ]] || return 0
  (( ${+commands[bx]} )) || return 0
  local dir=${XDG_STATE_HOME:-$HOME/.local/state}/bx/update
  local now=${(%):-%D{%s}} due line answer
  local -a found
  if [[ -s $dir/available ]]; then
    while read -r line
    do
      found+=("$line")
    done < $dir/available
    typeset -g BX_UPDATE_ASKED=1
    print -r -- "bx: what this configuration follows has new commits:"
    print -rl -- "  "${^found}
    print -n -- "bx: update now? [y/N] "
    read -k 1 -u 0 answer
    print
    if [[ $answer == [yY] ]]; then
      command bx update
    else
      command bx update --snooze </dev/null >/dev/null 2>&1 &!
    fi
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/check-due ]] && read -r due < $dir/check-due \
    && [[ $due == <-> ]] && (( due <= now )); then
    typeset -g BX_UPDATE_CHECKING=1
    command bx update --background </dev/null >/dev/null 2>&1 &!
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/ask-due ]] && read -r due < $dir/ask-due \
    && [[ $due == <-> ]] && (( due <= now )); then
    typeset -g BX_UPDATE_ASKED=1
    print -n -- "bx: check now whether what this configuration follows has new commits? [y/N] "
    read -k 1 -u 0 answer
    print
    if [[ $answer == [yY] ]]; then
      command bx update
    else
      command bx update --snooze </dev/null >/dev/null 2>&1 &!
    fi
  fi
  return 0
}
precmd_functions+=(__bx_update)
"#;

/// The hook in bash's words, as the `functions` phase of bash's file holds
/// it: what [`ZSH`] does, registered on `PROMPT_COMMAND` as the module's
/// *bash's hook* says.
pub const BASH: &str = r#"# Asks about followed externals' updates at a prompt a person is at, at most
# once per shell. Reads bx's update stamps; starts nothing until one is due.
# Returns the status it was called with, so the prompt shows the same one.
__bx_update() {
  local last=$?
  if [[ $- == *i* && -t 0 && -t 1 && $TERM != dumb ]]; then
    __bx_update_due
  fi
  return $last
}
__bx_update_due() {
  [[ -z $BX_UPDATE_ASKED ]] || return 0
  [[ -z ${CI-}${CLAUDECODE-}${CODEX_SANDBOX-}${GEMINI_CLI-}${CURSOR_AGENT-}${BX_NO_UPDATE_PROMPT-} ]] || return 0
  type -P bx >/dev/null || return 0
  local dir=${XDG_STATE_HOME:-$HOME/.local/state}/bx/update
  local now due line answer
  local -a found
  printf -v now '%(%s)T' -1
  if [[ -s $dir/available ]]; then
    while read -r line
    do
      found+=("$line")
    done < "$dir/available"
    BX_UPDATE_ASKED=1
    printf '%s\n' "bx: what this configuration follows has new commits:"
    printf '  %s\n' "${found[@]}"
    printf '%s' "bx: update now? [y/N] "
    read -r -n 1 answer
    printf '\n'
    if [[ $answer == [yY] ]]; then
      command bx update
    else
      (command bx update --snooze </dev/null >/dev/null 2>&1 &)
    fi
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/check-due ]] && read -r due < "$dir/check-due" \
    && [[ -n $due && $due != *[!0-9]* ]] && (( 10#$due <= now )); then
    BX_UPDATE_CHECKING=1
    (command bx update --background </dev/null >/dev/null 2>&1 &)
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/ask-due ]] && read -r due < "$dir/ask-due" \
    && [[ -n $due && $due != *[!0-9]* ]] && (( 10#$due <= now )); then
    BX_UPDATE_ASKED=1
    printf '%s' "bx: check now whether what this configuration follows has new commits? [y/N] "
    read -r -n 1 answer
    printf '\n'
    if [[ $answer == [yY] ]]; then
      command bx update
    else
      (command bx update --snooze </dev/null >/dev/null 2>&1 &)
    fi
  fi
  return 0
}
# Appended to PROMPT_COMMAND, never replacing it, and only where it is not
# exported or read-only. The entry names the hook through BX_UPDATE_HOOK, an
# unexported variable, so where a later line exports PROMPT_COMMAND a child
# shell that inherits the entry expands it to nothing rather than failing to
# find a function it never defined.
if (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 404 )); then
  case ${PROMPT_COMMAND@a} in
    *[xr]*) ;;
    *a*)
      BX_UPDATE_HOOK=__bx_update
      [[ " ${PROMPT_COMMAND[*]} " == *' ${BX_UPDATE_HOOK-} '* ]] \
        || PROMPT_COMMAND+=('${BX_UPDATE_HOOK-}')
      ;;
    *)
      BX_UPDATE_HOOK=__bx_update
      [[ $'\n'${PROMPT_COMMAND-}$'\n' == *$'\n''${BX_UPDATE_HOOK-}'$'\n'* ]] \
        || PROMPT_COMMAND=${PROMPT_COMMAND:+$PROMPT_COMMAND$'\n'}'${BX_UPDATE_HOOK-}'
      ;;
  esac
fi
"#;

/// Add `shell`'s hook to `assembly`'s `functions` phase when `follows` — the
/// configuration has an external that follows a branch — and nothing
/// otherwise, so a configuration without one renders exactly as before.
pub fn contribute(assembly: &mut Assembly, follows: bool, shell: Shell) {
    if follows {
        let hook = match shell {
            Shell::Zsh => ZSH,
            Shell::Bash => BASH,
        };
        assembly
            .contribute(Phase::Functions, SECTION, hook)
            .expect("the functions phase refuses nothing");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// A home with a recording `bx` on `PATH`, and the update stamps under
    /// its default state directory.
    struct Rig {
        home: tempfile::TempDir,
        shell: Shell,
    }

    impl Rig {
        fn new(shell: Shell) -> Self {
            let home = tempfile::tempdir().expect("a home");
            let bin = home.path().join("bin");
            std::fs::create_dir_all(&bin).expect("bin");
            let bx = bin.join("bx");
            std::fs::write(
                &bx,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\n",
                    home.path().join("calls").display()
                ),
            )
            .expect("a recording bx");
            crate::fs::set_mode(&bx, crate::fs::Mode::from_bits(0o755)).expect("executable");
            std::fs::create_dir_all(Self::dir_in(home.path())).expect("update/");
            Self { home, shell }
        }

        fn dir_in(home: &Path) -> PathBuf {
            home.join(".local/state/bx/update")
        }

        fn stamp(&self, name: &str, text: &str) {
            std::fs::write(Self::dir_in(self.home.path()).join(name), text).expect("a stamp");
        }

        /// Source the hook, call `function`, wait for any detached child, and
        /// return what was printed and every `bx` call made.
        fn run(&self, function: &str, input: &str, env: &[(&str, &str)]) -> (String, String) {
            self.run_after("", function, input, env)
        }

        /// [`Rig::run`], with `before` run ahead of the hook's bytes.
        fn run_after(
            &self,
            before: &str,
            function: &str,
            input: &str,
            env: &[(&str, &str)],
        ) -> (String, String) {
            let (program, flags, hook): (&str, &[&str], &str) = match self.shell {
                Shell::Zsh => ("zsh", &["-f"], ZSH),
                Shell::Bash => ("bash", &["--norc", "--noprofile"], BASH),
            };
            let Some(program) = crate::shell::testing::installed(program) else {
                return (String::new(), String::new());
            };
            let script = self.home.path().join("script");
            std::fs::write(
                &script,
                format!("{before}\n{hook}\n{function}\nwait\nsleep 0.2\n"),
            )
            .expect("the script");
            let mut command = Command::new(program);
            command
                .args(flags)
                .arg(&script)
                .env_clear()
                .env("HOME", self.home.path())
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", self.home.path().join("bin").display()),
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            for (name, value) in env {
                command.env(name, value);
            }
            let mut child = command.spawn().expect("the shell runs");
            std::io::Write::write_all(child.stdin.as_mut().expect("stdin"), input.as_bytes())
                .expect("input");
            let output = child.wait_with_output().expect("the shell finishes");
            assert!(output.status.success(), "{output:?}");
            let calls = std::fs::read_to_string(self.home.path().join("calls")).unwrap_or_default();
            // zsh puts a `read` prompt on standard error, after what the
            // hook printed: both are what a person sees.
            let shown = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            (shown, calls)
        }
    }

    const SHELLS: [Shell; 2] = [Shell::Zsh, Shell::Bash];

    #[test]
    fn nothing_due_is_silent_and_starts_nothing() {
        for shell in SHELLS {
            let rig = Rig::new(shell);
            assert_eq!(
                rig.run("__bx_update_due", "", &[]),
                (String::new(), String::new()),
                "{shell:?}"
            );
            rig.stamp("ask-due", "99999999999\n");
            rig.stamp("check-due", "99999999999\n");
            assert_eq!(
                rig.run("__bx_update_due", "", &[]),
                (String::new(), String::new()),
                "{shell:?}"
            );
            rig.stamp("ask-due", "soon\n");
            assert_eq!(
                rig.run("__bx_update_due", "", &[]),
                (String::new(), String::new()),
                "{shell:?}"
            );
        }
    }

    #[test]
    fn what_a_check_found_is_offered_and_yes_runs_bx_update() {
        for shell in SHELLS {
            let rig = Rig::new(shell);
            rig.stamp(
                "available",
                "~/a: 3 new commit(s) on main\n~/b: locks main\n",
            );
            let (printed, calls) = rig.run("__bx_update_due", "y", &[]);
            assert!(
                printed.contains("  ~/a: 3 new commit(s) on main\n  ~/b: locks main\n"),
                "{shell:?}: {printed}"
            );
            assert!(
                printed.contains("bx: update now? [y/N] "),
                "{shell:?}: {printed}"
            );
            assert_eq!(calls, "update\n", "{shell:?}");

            let (_, calls) = rig.run("__bx_update_due", "n", &[]);
            assert_eq!(
                calls, "update\nupdate --snooze\n",
                "{shell:?}: anything but y snoozes"
            );
        }
    }

    #[test]
    fn a_due_check_starts_one_quiet_background_check_and_asks_nothing() {
        for shell in SHELLS {
            let rig = Rig::new(shell);
            rig.stamp("check-due", "1\n");
            rig.stamp("ask-due", "1\n");
            let (printed, calls) = rig.run("__bx_update_due\n__bx_update_due", "", &[]);
            assert_eq!(
                printed, "",
                "{shell:?}: no question: it waits for what the check finds"
            );
            assert_eq!(calls, "update --background\n", "{shell:?}: once per shell");

            // Another shell, once the check found something, offers it.
            rig.stamp("available", "~/a: 1 new commit(s) on main\n");
            let (printed, calls) = rig.run("__bx_update_due", "n", &[]);
            assert!(
                printed.contains("~/a: 1 new commit(s) on main"),
                "{shell:?}: {printed}"
            );
            assert!(calls.ends_with("update --snooze\n"), "{shell:?}: {calls}");
        }
    }

    #[test]
    fn a_due_question_asks_whether_to_check_and_only_once() {
        for shell in SHELLS {
            let rig = Rig::new(shell);
            rig.stamp("ask-due", "1\n");
            let (printed, calls) = rig.run("__bx_update_due\n__bx_update_due", "y", &[]);
            assert_eq!(
                printed.matches("check now whether").count(),
                1,
                "{shell:?}: {printed}"
            );
            assert_eq!(calls, "update\n", "{shell:?}");
        }
    }

    #[test]
    fn an_agent_ci_or_an_opt_out_is_never_asked() {
        for shell in SHELLS {
            let rig = Rig::new(shell);
            rig.stamp("available", "~/a: x\n");
            rig.stamp("check-due", "1\n");
            for name in [
                "CI",
                "CLAUDECODE",
                "CODEX_SANDBOX",
                "GEMINI_CLI",
                "CURSOR_AGENT",
                "BX_NO_UPDATE_PROMPT",
            ] {
                assert_eq!(
                    rig.run("__bx_update_due", "y", &[(name, "1")]),
                    (String::new(), String::new()),
                    "{shell:?}: {name}"
                );
            }
        }
    }

    #[test]
    fn a_shell_without_a_terminal_is_never_asked() {
        for shell in SHELLS {
            let rig = Rig::new(shell);
            rig.stamp("available", "~/a: x\n");
            assert_eq!(
                rig.run("__bx_update", "y", &[]),
                (String::new(), String::new()),
                "{shell:?}"
            );
        }
    }

    /// What bash prints of `PROMPT_COMMAND` after sourcing the hook behind
    /// `before`: its attributes, then each element on its own line.
    fn prompt_command(before: &str) -> String {
        let rig = Rig::new(Shell::Bash);
        rig.run_after(
            before,
            "printf '[%s]\\n' \"${PROMPT_COMMAND@a}\" \"${PROMPT_COMMAND[@]}\"",
            "",
            &[],
        )
        .0
    }

    #[test]
    fn bash_appends_to_an_unexported_prompt_command_once() {
        if crate::shell::testing::installed("bash").is_none() {
            return;
        }
        assert_eq!(prompt_command(""), "[]\n[${BX_UPDATE_HOOK-}]\n", "unset");
        assert_eq!(
            prompt_command("PROMPT_COMMAND='history -a; echo hi'"),
            "[]\n[history -a; echo hi\n${BX_UPDATE_HOOK-}]\n",
            "every byte it held is kept"
        );
        assert_eq!(
            prompt_command(&format!("PROMPT_COMMAND=x\n{BASH}")),
            "[]\n[x\n${BX_UPDATE_HOOK-}]\n",
            "a ~/.bashrc sourced twice appends once"
        );
        assert_eq!(
            prompt_command("PROMPT_COMMAND=(a 'b c')"),
            "[a]\n[a]\n[b c]\n[${BX_UPDATE_HOOK-}]\n",
            "an array gains one element"
        );
        assert_eq!(
            prompt_command(&format!("PROMPT_COMMAND=(a)\n{BASH}")),
            "[a]\n[a]\n[${BX_UPDATE_HOOK-}]\n",
            "an array once"
        );
    }

    #[test]
    fn bash_leaves_an_exported_or_read_only_prompt_command_alone() {
        if crate::shell::testing::installed("bash").is_none() {
            return;
        }
        assert_eq!(
            prompt_command("export PROMPT_COMMAND=x"),
            "[x]\n[x]\n",
            "nothing bx appends reaches a process the shell starts"
        );
        assert_eq!(prompt_command("export PROMPT_COMMAND"), "[x]\n");
        assert_eq!(
            prompt_command("readonly PROMPT_COMMAND=x"),
            "[r]\n[x]\n",
            "and no error at startup"
        );
    }

    #[test]
    fn bash_keeps_the_status_the_prompt_would_have_shown() {
        if crate::shell::testing::installed("bash").is_none() {
            return;
        }
        let rig = Rig::new(Shell::Bash);
        let (printed, _) = rig.run("(exit 7); __bx_update; echo \"[$?]\"", "", &[]);
        assert_eq!(printed, "[7]\n");
    }

    #[test]
    fn a_later_export_carries_an_entry_a_child_bash_runs_without_error() {
        if crate::shell::testing::installed("bash").is_none() {
            return;
        }
        // A line of ~/.bashrc after bx's region exports PROMPT_COMMAND. In
        // this shell the entry still runs the hook and keeps the status; in a
        // child bash without bx's file it expands to nothing, so the child
        // prints no `command not found` at its prompt.
        let rig = Rig::new(Shell::Bash);
        let (printed, _) = rig.run(
            "export PROMPT_COMMAND\n\
             (exit 7); eval \"$PROMPT_COMMAND\"; echo \"[$?]\"\n\
             bash --norc --noprofile -c 'eval \"$PROMPT_COMMAND\"; echo \"[$?]\"'",
            "",
            &[],
        );
        assert_eq!(printed, "[7]\n[0]\n");
    }

    #[test]
    fn the_hook_is_contributed_only_when_something_follows_a_branch() {
        for (shell, registration) in [
            (Shell::Zsh, "precmd_functions+=(__bx_update)"),
            (Shell::Bash, "PROMPT_COMMAND+=('${BX_UPDATE_HOOK-}')"),
        ] {
            let mut none = Assembly::new();
            contribute(&mut none, false, shell);
            assert_eq!(none.render(), Assembly::new().render());
            let mut some = Assembly::new();
            contribute(&mut some, true, shell);
            assert!(some.render().contains(registration), "{shell:?}");
        }
        for hook in [ZSH, BASH] {
            assert!(
                !hook.contains("$(") && !hook.contains('`'),
                "the bench refuses a command substitution"
            );
        }
    }
}
