//! The question about followed externals' updates, asked at a zsh prompt.
//!
//! When the configuration has an `[[external]]` that follows a branch, the
//! generated interactive zsh file defines one hook on `precmd`. At each prompt
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
//! left alone. A script, a service, an agent and `zsh -c` therefore never see
//! a question or start a check, and nothing reaches the network without a
//! keypress unless an external is `check = "auto"`.
//!
//! # Invariant 6
//!
//! Sourcing the file defines two functions and appends one to
//! `precmd_functions`; nothing runs until the first prompt, which a startup
//! benchmark (`zsh -i -c exit`) never reaches. The hook itself reads the
//! stamps with the `read` builtin and takes the time from a prompt
//! expansion, so a prompt with nothing due starts no process. The only
//! processes it ever starts are the detached background check, at most once
//! per shell and only once `check-due` has passed, and `bx update` itself
//! once someone answers.
//!
//! # Invariant 2
//!
//! Generated shell content that is not an environment fragment may assign
//! nothing but bx's own `BX_` names, a function's locals and zsh's hook
//! arrays. The hook assigns its locals, `BX_UPDATE_ASKED` and
//! `BX_UPDATE_CHECKING` (both `typeset -g`, never exported), and appends to
//! `precmd_functions`; `env_guard`'s
//! `the_update_prompt_is_not_an_environment_fragment` holds the bytes to that,
//! and the tests here run them.

use super::{Assembly, Phase};

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

/// Add the hook to `assembly`'s `functions` phase when `follows` — the
/// configuration has an external that follows a branch — and nothing
/// otherwise, so a configuration without one renders exactly as before.
pub fn contribute(assembly: &mut Assembly, follows: bool) {
    if follows {
        assembly
            .contribute(Phase::Functions, SECTION, ZSH)
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
    }

    impl Rig {
        fn new() -> Self {
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
            Self { home }
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
            let Some(zsh) = crate::shell::testing::installed("zsh") else {
                return (String::new(), String::new());
            };
            let script = self.home.path().join("script.zsh");
            std::fs::write(&script, format!("{ZSH}\n{function}\nwait\nsleep 0.2\n"))
                .expect("the script");
            let mut command = Command::new(zsh);
            command
                .arg("-f")
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
            let mut child = command.spawn().expect("zsh runs");
            std::io::Write::write_all(child.stdin.as_mut().expect("stdin"), input.as_bytes())
                .expect("input");
            let output = child.wait_with_output().expect("zsh finishes");
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

    #[test]
    fn nothing_due_is_silent_and_starts_nothing() {
        let rig = Rig::new();
        assert_eq!(
            rig.run("__bx_update_due", "", &[]),
            (String::new(), String::new())
        );
        rig.stamp("ask-due", "99999999999\n");
        rig.stamp("check-due", "99999999999\n");
        assert_eq!(
            rig.run("__bx_update_due", "", &[]),
            (String::new(), String::new())
        );
        rig.stamp("ask-due", "soon\n");
        assert_eq!(
            rig.run("__bx_update_due", "", &[]),
            (String::new(), String::new())
        );
    }

    #[test]
    fn what_a_check_found_is_offered_and_yes_runs_bx_update() {
        let rig = Rig::new();
        rig.stamp(
            "available",
            "~/a: 3 new commit(s) on main\n~/b: locks main\n",
        );
        let (printed, calls) = rig.run("__bx_update_due", "y", &[]);
        assert!(
            printed.contains("  ~/a: 3 new commit(s) on main\n  ~/b: locks main\n"),
            "{printed}"
        );
        assert!(printed.contains("bx: update now? [y/N] "), "{printed}");
        assert_eq!(calls, "update\n");

        let (_, calls) = rig.run("__bx_update_due", "n", &[]);
        assert_eq!(calls, "update\nupdate --snooze\n", "anything but y snoozes");
    }

    #[test]
    fn a_due_check_starts_one_quiet_background_check_and_asks_nothing() {
        let rig = Rig::new();
        rig.stamp("check-due", "1\n");
        rig.stamp("ask-due", "1\n");
        let (printed, calls) = rig.run("__bx_update_due\n__bx_update_due", "", &[]);
        assert_eq!(
            printed, "",
            "no question: it waits for what the check finds"
        );
        assert_eq!(calls, "update --background\n", "once per shell");

        // Another shell, once the check found something, offers it.
        rig.stamp("available", "~/a: 1 new commit(s) on main\n");
        let (printed, calls) = rig.run("__bx_update_due", "n", &[]);
        assert!(
            printed.contains("~/a: 1 new commit(s) on main"),
            "{printed}"
        );
        assert!(calls.ends_with("update --snooze\n"), "{calls}");
    }

    #[test]
    fn a_due_question_asks_whether_to_check_and_only_once() {
        let rig = Rig::new();
        rig.stamp("ask-due", "1\n");
        let (printed, calls) = rig.run("__bx_update_due\n__bx_update_due", "y", &[]);
        assert_eq!(printed.matches("check now whether").count(), 1, "{printed}");
        assert_eq!(calls, "update\n");
    }

    #[test]
    fn an_agent_ci_or_an_opt_out_is_never_asked() {
        let rig = Rig::new();
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
                "{name}"
            );
        }
    }

    #[test]
    fn a_shell_without_a_terminal_is_never_asked() {
        let rig = Rig::new();
        rig.stamp("available", "~/a: x\n");
        assert_eq!(
            rig.run("__bx_update", "y", &[]),
            (String::new(), String::new())
        );
    }

    #[test]
    fn the_hook_is_contributed_only_when_something_follows_a_branch() {
        let mut none = Assembly::new();
        contribute(&mut none, false);
        assert_eq!(none.render(), Assembly::new().render());
        let mut some = Assembly::new();
        contribute(&mut some, true);
        assert!(some.render().contains("precmd_functions+=(__bx_update)"));
        assert!(
            !ZSH.contains("$("),
            "the bench refuses a command substitution"
        );
    }
}
