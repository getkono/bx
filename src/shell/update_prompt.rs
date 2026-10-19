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
//! It asks about an offer, or a question, at most once per shell: a shell that
//! asked one nobody answered remembers it in `BX_UPDATE_ASKED`, and asks again
//! only once a check finds something else. It starts at most one background
//! check per shell. A shell that started one does not also ask whether to
//! check: it offers what that check finds instead.
//!
//! # Many shells at once
//!
//! Every shell at a prompt sees the same offer, and the first answer, in any
//! of them, settles it for all ([`crate::update`]'s *Shells asking at once*):
//!
//! - **One generation per offer.** `available` begins `gen G`, a hash of what
//!   it offers. The hook offers it only while `answered` holds something else,
//!   so a shell opened after an answer is not asked, even while the
//!   `bx update` or `bx update --snooze` the answer started still runs. The
//!   question whether to check is named `ask` and its `ask-due` the same way.
//!   An offer's answer names the `ask-due` it was given under on a second
//!   line, so the question due with it is settled too.
//! - **Answered before anything starts.** The shell answered writes
//!   `answered` with one redirect, then sends `SIGURG` with the `kill` builtin
//!   to every other shell waiting under `waiting/`, then starts `bx update`
//!   or the snooze.
//! - **Waiting without polling.** A shell asking writes `waiting/$$`, traps
//!   `SIGURG`, checks once more that nothing settled what it asks, and only
//!   then reads, so no wake-up is lost between the check and the read. The
//!   signal ends the read at once: zsh's `read` returns for any trapped
//!   signal, and bash's does in POSIX mode, which the hook holds only for the
//!   read. Woken, it reads the stamps again: answered, or withdrawn by a
//!   `bx update` run by hand, it says `bx: answered in another shell`;
//!   replaced by a check that found something else, it says so and asks
//!   about that at the next prompt; otherwise it reads on. Afterwards it
//!   empties `waiting/$$` and puts back the `URG` trap it found. `SIGURG` is
//!   ignored by a process that does not trap it, so a waiting file left by a
//!   shell that is gone harms nothing that later takes its pid, and bx removes
//!   such files whenever it wakes the shells ([`crate::update::Stamps::wake`]).
//! - **Bounded.** A read waits at most `BX_UPDATE_PROMPT_TIMEOUT` seconds, 60
//!   unless that is a positive whole number. One that times out, or meets the
//!   end of its input, says `bx: no answer; asking again at a later shell`
//!   and writes nothing, so another shell asks.
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
//! - **bash 4.4 or later** ([`BASH_SINCE`]). Reading `PROMPT_COMMAND`'s
//!   attributes needs `${PROMPT_COMMAND@a}`; an older bash — macOS's
//!   `/bin/bash` is 3.2 — parses the file, registers nothing and is not
//!   asked, and `bx doctor` names the hook it left out.
//!
//! # Invariant 6
//!
//! Sourcing either file defines four functions and registers one; nothing
//! runs until the first prompt, which a startup benchmark (`zsh -i -c exit`,
//! `bash -i -c exit`) never reaches. The hook itself reads the stamps with
//! the `read` builtin and takes the time from a prompt expansion in zsh and
//! `printf '%(%s)T'` in bash, so a prompt with nothing due starts no
//! process. Asking starts none either: registering, waiting, waking and
//! answering are redirects, `trap`, `read`, a glob and the `kill` builtin.
//! The only processes it ever starts are the detached background check, at
//! most once per shell and only once `check-due` has passed, and `bx update`
//! itself once someone answers.
//!
//! # Invariant 2
//!
//! Generated shell content that is not an environment fragment may assign
//! nothing but bx's own `BX_` names, a function's locals, zsh's hook arrays
//! and an append to an unexported `PROMPT_COMMAND`. The hook assigns its
//! locals, `BX_UPDATE_ASKED`, `BX_UPDATE_CHECKING` and, in bash,
//! `BX_UPDATE_HOOK` (never exported); it reads `BX_UPDATE_PROMPT_TIMEOUT` and
//! assigns it nothing. Its `SIGURG` trap assigns a local, and bash's puts back
//! the trap it found by evaluating what `trap -p URG` printed, which is that
//! trap and nothing else. It registers itself as above; `env_guard`'s
//! `the_update_prompt_is_not_an_environment_fragment` and
//! `the_bash_update_prompt_is_not_an_environment_fragment` hold the bytes to
//! that, and the tests here run them.

use super::{Assembly, Phase, Shell};

/// The owner the hook is contributed under.
pub const SECTION: &str = "bx update";

/// The oldest bash, as `(major, minor)`, that [`BASH`] registers on: reading
/// `PROMPT_COMMAND`'s attributes needs `${PROMPT_COMMAND@a}`. An older bash —
/// macOS's `/bin/bash` is 3.2 — sources the file without the hook, and
/// `bx doctor` says so ([`crate::doctor::bash`]).
pub const BASH_SINCE: (u32, u32) = (4, 4);

/// The hook, as the `functions` phase holds it.
pub const ZSH: &str = r#"# Asks about followed externals' updates at a prompt a person is at, once per
# offer. Reads bx's update stamps; starts nothing until one is due.
__bx_update() {
  [[ -o interactive && -t 0 && -t 1 && $TERM != dumb ]] || return 0
  __bx_update_due
}
__bx_update_due() {
  [[ -z ${CI-}${CLAUDECODE-}${CODEX_SANDBOX-}${GEMINI_CLI-}${CURSOR_AGENT-}${BX_NO_UPDATE_PROMPT-} ]] || return 0
  (( ${+commands[bx]} )) || return 0
  local dir=$HOME/.local/state/bx/update
  [[ ${XDG_STATE_HOME-} == /* ]] && dir=$XDG_STATE_HOME/bx/update
  local now=${(%):-%D{%s}} due line gen= answered= also=
  local -a found
  if [[ -r $dir/answered ]]; then
    {
      read -r answered
      read -r also
    } < $dir/answered
  fi
  if [[ -s $dir/available ]]; then
    while read -r line
    do
      found+=("$line")
    done < $dir/available
    if [[ ${found[1]-} == 'gen '* ]]; then
      gen=${found[1]#gen }
      shift found
    fi
  fi
  if (( ${#found} )) && [[ -z $gen || $gen != "$answered" ]]; then
    [[ -n $gen && $gen == "${BX_UPDATE_ASKED-}" ]] && return 0
    print -r -- "bx: what this configuration follows has new commits:"
    print -rl -- "  "${^found}
    __bx_update_ask $dir offer "$gen" "bx: update now? [y/N] "
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/check-due ]] && read -r due < $dir/check-due \
    && [[ $due == <-> ]] && (( due <= now )); then
    typeset -g BX_UPDATE_CHECKING=1
    command bx update --background </dev/null >/dev/null 2>&1 &!
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/ask-due ]] && read -r due < $dir/ask-due \
    && [[ $due == <-> ]] && (( due <= now )) \
    && [[ "ask $due" != "$answered" && "ask $due" != "$also" ]] \
    && [[ "ask $due" != "${BX_UPDATE_ASKED-}" ]]; then
    __bx_update_ask $dir ask "ask $due" \
      "bx: check now whether what this configuration follows has new commits? [y/N] "
  fi
  return 0
}
# Whether what __bx_update_ask asks about ($2, offer or ask; $3, its
# generation) stands in the update stamps under $1: 1 while it does, 0 once it
# was answered, and 2 once a check replaced it with another offer.
__bx_update_settled() {
  local line= also=
  if [[ -r $1/answered ]]; then
    {
      read -r line
      read -r also
    } < $1/answered
  fi
  [[ -n $3 && $line == "$3" ]] && return 0
  [[ $2 == ask && $also == "$3" ]] && return 0
  line=
  if [[ $2 == offer ]]; then
    [[ -s $1/available ]] || return 0
    read -r line < $1/available
    [[ -z $3 || $line == "gen $3" ]] && return 1
    return 2
  fi
  [[ -r $1/ask-due ]] && read -r line < $1/ask-due
  [[ "ask $line" == "$3" ]] && return 1
  return 0
}
# Asks $4 about $2 ($3, its generation) under the update stamps in $1, for at
# most BX_UPDATE_PROMPT_TIMEOUT seconds. Waits under waiting/, where whoever
# answers it wakes this shell with SIGURG, so it gives way at once. An offer
# answered settles the question due with it too, until the answer moves on.
__bx_update_ask() {
  setopt localoptions localtraps nullglob
  local dir=$1 kind=$2 gen=$3 answer= woken= outcome= due= f p
  local -i wait=60 start=${(%):-%D{%s}} now left
  [[ ${BX_UPDATE_PROMPT_TIMEOUT-} == [1-9]* && $BX_UPDATE_PROMPT_TIMEOUT != *[^0-9]* ]] \
    && wait=$BX_UPDATE_PROMPT_TIMEOUT
  typeset -g BX_UPDATE_ASKED=$gen
  print -r -- "$gen" 2>/dev/null >| $dir/waiting/$$
  trap 'woken=1' URG
  print -n -- "$4"
  while [[ -z $outcome ]]
  do
    __bx_update_settled $dir $kind "$gen"
    case $? in
      0) outcome=answered ;;
      2) outcome=changed ;;
      *)
        now=${(%):-%D{%s}}
        left=wait-now+start
        if (( left <= 0 )); then
          outcome=none
        else
          woken=
          read -k 1 -u 0 -t $left answer && outcome=read
          [[ -n $outcome$woken ]] || outcome=none
        fi
        ;;
    esac
  done
  : 2>/dev/null >| $dir/waiting/$$
  trap - URG
  print
  case $outcome in
    answered) print -r -- "bx: answered in another shell"; return 0 ;;
    changed) print -r -- "bx: a check found something else; asking about it at the next prompt"; return 0 ;;
    none) print -r -- "bx: no answer; asking again at a later shell"; return 0 ;;
  esac
  [[ $kind == offer && -r $dir/ask-due ]] && read -r due < $dir/ask-due
  if [[ $kind == offer ]]; then
    printf '%s\nask %s\n' "$gen" "$due" 2>/dev/null >| $dir/answered
  else
    printf '%s\n' "$gen" 2>/dev/null >| $dir/answered
  fi
  for f in $dir/waiting/*
  do
    p=${f:t}
    [[ $p == [1-9]* && $p != *[^0-9]* && $p != $$ && -s $f ]] && kill -URG $p 2>/dev/null
  done
  if [[ $answer == [yY] ]]; then
    command bx update
  else
    command bx update --snooze </dev/null >/dev/null 2>&1 &!
  fi
  return 0
}
precmd_functions+=(__bx_update)
"#;

/// The hook in bash's words, as the `functions` phase of bash's file holds
/// it: what [`ZSH`] does, registered on `PROMPT_COMMAND` as the module's
/// *bash's hook* says.
pub const BASH: &str = r#"# Asks about followed externals' updates at a prompt a person is at, once per
# offer. Reads bx's update stamps; starts nothing until one is due.
# Returns the status it was called with, so the prompt shows the same one.
__bx_update() {
  local last=$?
  if [[ $- == *i* && -t 0 && -t 1 && $TERM != dumb ]]; then
    __bx_update_due
  fi
  return $last
}
__bx_update_due() {
  [[ -z ${CI-}${CLAUDECODE-}${CODEX_SANDBOX-}${GEMINI_CLI-}${CURSOR_AGENT-}${BX_NO_UPDATE_PROMPT-} ]] || return 0
  type -P bx >/dev/null || return 0
  local dir=$HOME/.local/state/bx/update
  [[ ${XDG_STATE_HOME-} == /* ]] && dir=$XDG_STATE_HOME/bx/update
  local now due line gen= answered= also=
  local -a found
  printf -v now '%(%s)T' -1
  if [[ -r $dir/answered ]]; then
    {
      read -r answered
      read -r also
    } < "$dir/answered"
  fi
  if [[ -s $dir/available ]]; then
    while read -r line
    do
      found+=("$line")
    done < "$dir/available"
    if [[ ${found[0]-} == 'gen '* ]]; then
      gen=${found[0]#gen }
      found=("${found[@]:1}")
    fi
  fi
  if (( ${#found[@]} )) && [[ -z $gen || $gen != "$answered" ]]; then
    [[ -n $gen && $gen == "${BX_UPDATE_ASKED-}" ]] && return 0
    printf '%s\n' "bx: what this configuration follows has new commits:"
    printf '  %s\n' "${found[@]}"
    __bx_update_ask "$dir" offer "$gen" "bx: update now? [y/N] "
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/check-due ]] && read -r due < "$dir/check-due" \
    && [[ -n $due && $due != *[!0-9]* ]] && (( 10#$due <= now )); then
    BX_UPDATE_CHECKING=1
    (command bx update --background </dev/null >/dev/null 2>&1 &)
    return 0
  fi
  if [[ -z $BX_UPDATE_CHECKING && -r $dir/ask-due ]] && read -r due < "$dir/ask-due" \
    && [[ -n $due && $due != *[!0-9]* ]] && (( 10#$due <= now )) \
    && [[ "ask $due" != "$answered" && "ask $due" != "$also" ]] \
    && [[ "ask $due" != "${BX_UPDATE_ASKED-}" ]]; then
    __bx_update_ask "$dir" ask "ask $due" \
      "bx: check now whether what this configuration follows has new commits? [y/N] "
  fi
  return 0
}
# Whether what __bx_update_ask asks about ($2, offer or ask; $3, its
# generation) stands in the update stamps under $1: 1 while it does, 0 once it
# was answered, and 2 once a check replaced it with another offer.
__bx_update_settled() {
  local line= also=
  if [[ -r $1/answered ]]; then
    {
      read -r line
      read -r also
    } < "$1/answered"
  fi
  [[ -n $3 && $line == "$3" ]] && return 0
  [[ $2 == ask && $also == "$3" ]] && return 0
  line=
  if [[ $2 == offer ]]; then
    [[ -s $1/available ]] || return 0
    read -r line < "$1/available"
    [[ -z $3 || $line == "gen $3" ]] && return 1
    return 2
  fi
  [[ -r $1/ask-due ]] && read -r line < "$1/ask-due"
  [[ "ask $line" == "$3" ]] && return 1
  return 0
}
# Asks $4 about $2 ($3, its generation) under the update stamps in $1, for at
# most BX_UPDATE_PROMPT_TIMEOUT seconds. Waits under waiting/, where whoever
# answers it wakes this shell with SIGURG, so it gives way at once: bash ends
# a read for a trapped signal only in POSIX mode, so the read runs in it. An
# offer answered settles the question due with it too, until the answer moves on.
__bx_update_ask() {
  local -
  local dir=$1 kind=$2 gen=$3 answer= woken= outcome= saved= posix= due= f p start now
  local -i wait=60 left
  [[ ${BX_UPDATE_PROMPT_TIMEOUT-} == [1-9]* && $BX_UPDATE_PROMPT_TIMEOUT != *[!0-9]* ]] \
    && wait=$BX_UPDATE_PROMPT_TIMEOUT
  [[ -o posix ]] && posix=1
  BX_UPDATE_ASKED=$gen
  printf -v start '%(%s)T' -1
  { printf '%s\n' "$gen"; trap -p URG; } 2>/dev/null >| "$dir/waiting/$$"
  {
    read -r saved
    read -r -d '' saved
  } 2>/dev/null < "$dir/waiting/$$"
  trap 'woken=1' URG
  printf '%s' "$4"
  while [[ -z $outcome ]]
  do
    __bx_update_settled "$dir" "$kind" "$gen"
    case $? in
      0) outcome=answered ;;
      2) outcome=changed ;;
      *)
        printf -v now '%(%s)T' -1
        left=wait-now+start
        if (( left <= 0 )); then
          outcome=none
        else
          woken=
          set -o posix
          read -r -n 1 -t $left answer && outcome=read
          [[ -n $posix ]] || set +o posix
          [[ -n $outcome$woken ]] || outcome=none
        fi
        ;;
    esac
  done
  : 2>/dev/null >| "$dir/waiting/$$"
  trap - URG
  [[ -n $saved ]] && eval "$saved"
  printf '\n'
  case $outcome in
    answered) printf '%s\n' "bx: answered in another shell"; return 0 ;;
    changed) printf '%s\n' "bx: a check found something else; asking about it at the next prompt"; return 0 ;;
    none) printf '%s\n' "bx: no answer; asking again at a later shell"; return 0 ;;
  esac
  [[ $kind == offer && -r $dir/ask-due ]] && read -r due < "$dir/ask-due"
  if [[ $kind == offer ]]; then
    printf '%s\nask %s\n' "$gen" "$due" 2>/dev/null >| "$dir/answered"
  else
    printf '%s\n' "$gen" 2>/dev/null >| "$dir/answered"
  fi
  for f in "$dir"/waiting/*
  do
    p=${f##*/}
    [[ $p == [1-9]* && $p != *[!0-9]* && $p != "$$" && -s $f ]] && kill -URG "$p" 2>/dev/null
  done
  if [[ $answer == [yY] ]]; then
    command bx update
  else
    (command bx update --snooze </dev/null >/dev/null 2>&1 &)
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
            // Run once here and its record dropped: macOS checks a newly
            // written executable before its first run, for long enough that a
            // detached first call could outlast the script's own pause. Not on
            // Linux, which has no such check, and where executing a file just
            // written can meet `ETXTBSY` from another test thread's fork.
            if cfg!(target_os = "macos") {
                let warmed = Command::new(&bx).status().expect("the recording bx runs");
                assert!(warmed.success(), "the recording bx: {warmed}");
                std::fs::remove_file(home.path().join("calls")).expect("the warm-up's record");
            }
            // As `Stamps::set` leaves it.
            std::fs::create_dir_all(Self::dir_in(home.path()).join("waiting")).expect("update/");
            Self { home, shell }
        }

        fn dir_in(home: &Path) -> PathBuf {
            home.join(".local/state/bx/update")
        }

        fn dir(&self) -> PathBuf {
            Self::dir_in(self.home.path())
        }

        fn stamp(&self, name: &str, text: &str) {
            std::fs::write(self.dir().join(name), text).expect("a stamp");
        }

        /// The stamp `name`, or `None` where it is absent.
        fn read(&self, name: &str) -> Option<String> {
            std::fs::read_to_string(self.dir().join(name)).ok()
        }

        /// `name` under the home once something writes it, as a detached
        /// call does after the shell that started it is gone; `None` when
        /// nothing does within ten seconds.
        fn eventually(&self, name: &str) -> Option<String> {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if let Ok(text) = std::fs::read_to_string(self.home.path().join(name)) {
                    return Some(text);
                }
                if std::time::Instant::now() >= until {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }

        /// The shell, sourcing the hook behind `before` and then running
        /// `function` from a script of its own called `name`, with its
        /// standard streams piped; `None` where the shell is not installed.
        fn spawn(
            &self,
            name: &str,
            before: &str,
            function: &str,
            env: &[(&str, &str)],
        ) -> Option<std::process::Child> {
            let (program, flags, hook): (&str, &[&str], &str) = match self.shell {
                Shell::Zsh => ("zsh", &["-f"], ZSH),
                Shell::Bash => ("bash", &["--norc", "--noprofile"], BASH),
            };
            let program = crate::shell::testing::installed(program)?;
            let script = self.home.path().join(name);
            std::fs::write(&script, format!("{before}\n{hook}\n{function}\n")).expect("the script");
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
            Some(command.spawn().expect("the shell runs"))
        }

        /// Wait until `child`, a shell [`Rig::spawn`] started, waits on a
        /// prompt: its file under `waiting/` is there and not empty.
        fn until_waiting(&self, child: &std::process::Child) {
            let file = self.dir().join("waiting").join(child.id().to_string());
            let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while !std::fs::metadata(&file).is_ok_and(|meta| meta.len() > 0) {
                assert!(
                    std::time::Instant::now() < until,
                    "the shell never waited on its prompt"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
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
            let Some(mut child) = self.spawn(
                "script",
                before,
                &format!("{function}\nwait\nsleep 0.2"),
                env,
            ) else {
                return (String::new(), String::new());
            };
            // A hook that asks nothing never reads its input, so the shell can
            // exit before it is written: a closed pipe is then not a failure.
            match std::io::Write::write_all(child.stdin.as_mut().expect("stdin"), input.as_bytes())
            {
                Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => {
                    panic!("input: {error:?}")
                }
                _ => {}
            }
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

    /// The shells every hook test runs in: zsh, and bash where it is one the
    /// hook registers on. An older bash never runs the hook, so what it does
    /// when called is nothing a person meets — `printf '%(%s)T'`, which takes
    /// the time without a process, is bash 4.2's.
    fn shells() -> Vec<Shell> {
        let mut shells = vec![Shell::Zsh];
        if bash_registers() {
            shells.push(Shell::Bash);
        }
        shells
    }

    #[test]
    fn nothing_due_is_silent_and_starts_nothing() {
        for shell in shells() {
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
        for shell in shells() {
            let rig = Rig::new(shell);
            rig.stamp(
                "available",
                "gen g1\n~/a: 3 new commit(s) on main\n~/b: locks main\n",
            );
            let (printed, calls) = rig.run("__bx_update_due", "y", &[]);
            assert!(
                printed.contains("  ~/a: 3 new commit(s) on main\n  ~/b: locks main\n"),
                "{shell:?}: {printed}"
            );
            assert!(!printed.contains("gen g1"), "{shell:?}: {printed}");
            assert!(
                printed.contains("bx: update now? [y/N] "),
                "{shell:?}: {printed}"
            );
            assert_eq!(calls, "update\n", "{shell:?}");
            assert_eq!(
                rig.read("answered").as_deref(),
                Some("g1\nask \n"),
                "{shell:?}: written before bx update ran"
            );

            std::fs::remove_file(rig.dir().join("answered")).expect("answered");
            let (_, calls) = rig.run("__bx_update_due", "n", &[]);
            assert_eq!(
                calls, "update\nupdate --snooze\n",
                "{shell:?}: anything but y snoozes"
            );
            assert_eq!(
                rig.read("answered").as_deref(),
                Some("g1\nask \n"),
                "{shell:?}"
            );
            let waiting: Vec<_> = std::fs::read_dir(rig.dir().join("waiting"))
                .expect("waiting/")
                .map(|entry| std::fs::read(entry.expect("an entry").path()).expect("a file"))
                .collect();
            assert!(
                waiting.iter().all(Vec::is_empty),
                "{shell:?}: no longer waiting: {waiting:?}"
            );
        }
    }

    #[test]
    fn a_due_check_starts_one_quiet_background_check_and_asks_nothing() {
        for shell in shells() {
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
        for shell in shells() {
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
    fn a_due_question_answered_no_snoozes() {
        for shell in shells() {
            let rig = Rig::new(shell);
            rig.stamp("ask-due", "1\n");
            let (printed, calls) = rig.run("__bx_update_due", "n", &[]);
            assert!(
                printed.contains(
                    "bx: check now whether what this configuration follows has new commits? \
                     [y/N] "
                ),
                "{shell:?}: {printed}"
            );
            assert_eq!(calls, "update --snooze\n", "{shell:?}");
        }
    }

    /// What a shell [`Rig::spawn`] started printed, once it exits; its
    /// standard input is held open until then, so it never reads an end of
    /// input.
    fn finished(mut child: std::process::Child) -> String {
        let input = child.stdin.take();
        let status = child.wait().expect("the shell finishes");
        drop(input);
        let mut shown = String::new();
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read>),
        ]
        .into_iter()
        .flatten()
        {
            let mut stream = stream;
            std::io::Read::read_to_string(&mut stream, &mut shown).expect("output");
        }
        assert!(status.success(), "{status}: {shown}");
        shown
    }

    /// A pid no process has: a child's, once it was reaped.
    fn gone_pid() -> u32 {
        let mut child = Command::new("true").spawn().expect("true runs");
        child.wait().expect("reaped");
        child.id()
    }

    #[test]
    fn shells_asking_at_once_give_way_to_the_first_answer() {
        let env = [("BX_UPDATE_PROMPT_TIMEOUT", "30")];
        for shell in shells() {
            for (stamp, text, answered) in [
                (
                    "available",
                    "gen g1\n~/a: 1 new commit(s) on main\n",
                    "g1\nask \n",
                ),
                ("ask-due", "1\n", "ask 1\n"),
            ] {
                let rig = Rig::new(shell);
                rig.stamp(stamp, text);
                let Some(waiter) = rig.spawn("waiter", "", "__bx_update_due", &env) else {
                    return;
                };
                rig.until_waiting(&waiter);
                let mut answerer = rig
                    .spawn("answerer", "", "__bx_update_due\nwait\nsleep 0.2", &env)
                    .expect("the same shell");
                std::io::Write::write_all(answerer.stdin.as_mut().expect("stdin"), b"n")
                    .expect("the answer");
                let answering = finished(answerer);
                let answered_at = std::time::Instant::now();
                let waited = finished(waiter);
                assert!(
                    answered_at.elapsed() < std::time::Duration::from_secs(1),
                    "{shell:?}, {stamp}: gave way {:?} after the answer",
                    answered_at.elapsed()
                );
                assert!(
                    waited.ends_with("\nbx: answered in another shell\n"),
                    "{shell:?}, {stamp}: {waited}"
                );
                assert!(
                    !answering.contains("another shell"),
                    "{shell:?}, {stamp}: {answering}"
                );
                assert_eq!(rig.read("answered").as_deref(), Some(answered));
                assert_eq!(
                    rig.eventually("calls").as_deref(),
                    Some("update --snooze\n"),
                    "{shell:?}, {stamp}: one answer, one snooze"
                );
            }
        }
    }

    #[test]
    fn a_shell_opened_after_an_answer_is_not_asked() {
        for shell in shells() {
            let rig = Rig::new(shell);
            // As a shell that answered leaves them while its snooze still
            // waits for the lock.
            rig.stamp("available", "gen g1\n~/a: 1 new commit(s) on main\n");
            rig.stamp("ask-due", "1\n");
            rig.stamp("answered", "g1\nask 1\n");
            assert_eq!(
                rig.run("__bx_update_due", "y", &[]),
                (String::new(), String::new()),
                "{shell:?}: neither the offer nor the question due with it"
            );

            // The question alone, answered in some shell.
            rig.stamp("answered", "ask 1\n");
            std::fs::remove_file(rig.dir().join("available")).expect("no offer");
            assert_eq!(
                rig.run("__bx_update_due", "y", &[]),
                (String::new(), String::new()),
                "{shell:?}"
            );

            // An offer answered, and a question due after it was.
            rig.stamp("available", "gen g1\n~/a: 1 new commit(s) on main\n");
            rig.stamp("answered", "g1\nask 0\n");
            let (printed, calls) = rig.run("__bx_update_due", "y", &[]);
            assert!(!printed.contains("new commits:"), "{shell:?}: {printed}");
            assert!(
                printed.contains("check now whether"),
                "{shell:?}: {printed}"
            );
            assert_eq!(calls, "update\n", "{shell:?}");
            assert_eq!(rig.read("answered").as_deref(), Some("ask 1\n"));
        }
    }

    #[test]
    fn an_unanswered_prompt_times_out_writes_nothing_and_asks_again_only_when_new() {
        for shell in shells() {
            let rig = Rig::new(shell);
            rig.stamp("available", "gen g1\n~/a: 1 new commit(s) on main\n");
            let (urg, list) = match shell {
                Shell::Zsh => ("trap 'print mine' URG", "trap"),
                Shell::Bash => ("trap 'echo mine' URG", "trap -p URG"),
            };
            let started = std::time::Instant::now();
            let Some(child) = rig.spawn(
                "script",
                urg,
                &format!(
                    "__bx_update_due\nprintf '@\\n'\n__bx_update_due\nprintf '@\\n'\n\
                     printf 'gen g2\\n~/a: 2 new commit(s) on main\\n' >| {}\n\
                     __bx_update_due\nprintf '@\\n'\n{list}",
                    rig.dir().join("available").display()
                ),
                &[("BX_UPDATE_PROMPT_TIMEOUT", "1")],
            ) else {
                return;
            };
            let shown = finished(child);
            let took = started.elapsed();
            let runs: Vec<&str> = shown.split("@\n").collect();
            assert_eq!(runs.len(), 4, "{shell:?}: {shown}");
            for asked in [runs[0], runs[2]] {
                assert!(
                    asked.ends_with(
                        "bx: update now? [y/N] \nbx: no answer; asking again at a later shell\n"
                    ),
                    "{shell:?}: {asked}"
                );
            }
            assert_eq!(runs[1], "", "{shell:?}: the same offer is not asked twice");
            assert!(runs[2].contains("2 new commit(s)"), "{shell:?}: {shown}");
            assert!(
                runs[3].contains("mine"),
                "{shell:?}: the trap is put back: {shown}"
            );
            assert!(
                took >= std::time::Duration::from_secs(2),
                "{shell:?}: each waited its second: {took:?}"
            );
            assert_eq!(rig.read("answered"), None, "{shell:?}: no answer written");
            assert_eq!(
                std::fs::read_to_string(rig.home.path().join("calls")).ok(),
                None,
                "{shell:?}: nothing started"
            );
        }
    }

    #[test]
    fn a_stale_waiter_is_harmless_to_the_shell_that_answers() {
        for shell in shells() {
            let rig = Rig::new(shell);
            rig.stamp("available", "gen g1\n~/a: 1 new commit(s) on main\n");
            let stale = rig.dir().join("waiting").join(gone_pid().to_string());
            std::fs::write(&stale, "g1\n").expect("a stale waiter");
            std::fs::write(rig.dir().join("waiting/notapid"), "g1\n").expect("a stray file");
            let (printed, calls) = rig.run("__bx_update_due", "n", &[]);
            assert!(
                printed.ends_with("bx: update now? [y/N] \n"),
                "{shell:?}: nothing said about the stale pid: {printed}"
            );
            assert_eq!(calls, "update --snooze\n", "{shell:?}");
        }
    }

    #[test]
    fn bx_withdraws_a_prompt_whose_offer_it_settles_or_replaces() {
        let env = [("BX_UPDATE_PROMPT_TIMEOUT", "30")];
        let state = |rig: &Rig| crate::state::StateDir::resolve(rig.home.path());
        for shell in shells() {
            for (lines, said) in [
                (
                    vec!["~/a: 2 new commit(s) on main".to_string()],
                    "bx: a check found something else; asking about it at the next prompt\n",
                ),
                (Vec::new(), "bx: answered in another shell\n"),
            ] {
                let rig = Rig::new(shell);
                let stamps = crate::update::Stamps::of(&state(&rig));
                let first = ["~/a: 1 new commit(s) on main".to_string()];
                stamps.set(0, None, None, Some(&first)).expect("an offer");
                let Some(waiter) = rig.spawn("waiter", "", "__bx_update_due", &env) else {
                    return;
                };
                rig.until_waiting(&waiter);
                let at = std::time::Instant::now();
                // A check finding more, or a `bx update` run by hand.
                stamps.set(0, None, None, Some(&lines)).expect("settled");
                let waited = finished(waiter);
                assert!(
                    at.elapsed() < std::time::Duration::from_secs(1),
                    "{shell:?}: {:?}",
                    at.elapsed()
                );
                assert!(waited.ends_with(said), "{shell:?}: {waited}");
                assert_eq!(
                    std::fs::read_to_string(rig.home.path().join("calls")).ok(),
                    None,
                    "{shell:?}"
                );
                // A shell that is gone is pruned by the next waking.
                let stale = stamps.waiting().join(gone_pid().to_string());
                std::fs::write(&stale, "g\n").expect("a stale waiter");
                stamps.wake();
                assert!(!stale.exists(), "{shell:?}");
            }
        }
    }

    #[test]
    fn a_hook_with_no_bx_on_path_is_silent() {
        for shell in shells() {
            let rig = Rig::new(shell);
            std::fs::remove_file(rig.home.path().join("bin/bx")).expect("no bx");
            rig.stamp("available", "~/a: x\n");
            rig.stamp("check-due", "1\n");
            rig.stamp("ask-due", "1\n");
            // Only the home's own `bin` on `PATH`, so no bx installed on this
            // machine is found; the script's `sleep` is a function.
            let path = rig.home.path().join("bin");
            let path = path.to_str().expect("a UTF-8 tempdir");
            let (printed, calls) =
                rig.run_after("sleep() { :; }", "__bx_update_due", "y", &[("PATH", path)]);
            assert_eq!(
                (printed, calls),
                (String::new(), String::new()),
                "{shell:?}"
            );
        }
    }

    #[test]
    fn the_rig_survives_a_shell_that_exits_without_reading_its_input() {
        // More input than a pipe holds: a hook that asks nothing never reads
        // it, so the write always meets a closed pipe once the shell exits.
        let input = "y\n".repeat(1 << 20);
        for shell in shells() {
            let rig = Rig::new(shell);
            assert_eq!(
                rig.run("__bx_update_due", &input, &[]),
                (String::new(), String::new()),
                "{shell:?}"
            );
        }
    }

    /// The bx calls the hook makes at a prompt of an interactive `shell` whose
    /// standard input and output are a terminal and whose `TERM` is `term`,
    /// with a background check due; `None` where zsh's `zpty`, which supplies
    /// the terminal, is not available.
    fn calls_at_a_terminal(shell: Shell, term: &str) -> Option<String> {
        let zsh = crate::shell::testing::installed("zsh")?;
        let rig = Rig::new(shell);
        rig.stamp("check-due", "1\n");
        let (program, flags, hook) = match shell {
            Shell::Zsh => (zsh.clone(), "-f -i", ZSH),
            Shell::Bash => (
                crate::shell::testing::installed("bash")?,
                "--norc --noprofile -i",
                BASH,
            ),
        };
        let script = rig.home.path().join("script");
        std::fs::write(&script, format!("{hook}\n__bx_update\nwait\nsleep 0.2\n"))
            .expect("the script");
        let driver = rig.home.path().join("driver");
        std::fs::write(
            &driver,
            format!(
                "zmodload zsh/zpty || exit 3\n\
                 zpty t 'TERM={term} exec {} {flags} {}'\n\
                 for i in {{1..100}}; do zpty -t t || break; sleep 0.1; done\n\
                 zpty -d t\n",
                program.display(),
                script.display()
            ),
        )
        .expect("the driver");
        let output = Command::new(&zsh)
            .arg("-f")
            .arg(&driver)
            .env_clear()
            .env("HOME", rig.home.path())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", rig.home.path().join("bin").display()),
            )
            .stdin(Stdio::null())
            .output()
            .expect("the driver runs");
        if output.status.code() == Some(3) {
            return None;
        }
        assert!(output.status.success(), "{output:?}");
        Some(std::fs::read_to_string(rig.home.path().join("calls")).unwrap_or_default())
    }

    #[test]
    fn a_dumb_terminal_is_never_asked() {
        for shell in shells() {
            let Some(at_a_terminal) = calls_at_a_terminal(shell, "xterm") else {
                return;
            };
            assert_eq!(
                at_a_terminal, "update --background\n",
                "{shell:?}: the terminal is one the hook acts at"
            );
            assert_eq!(
                calls_at_a_terminal(shell, "dumb").as_deref(),
                Some(""),
                "{shell:?}"
            );
        }
    }

    #[test]
    fn an_agent_ci_or_an_opt_out_is_never_asked() {
        for shell in shells() {
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
        for shell in shells() {
            let rig = Rig::new(shell);
            rig.stamp("available", "~/a: x\n");
            assert_eq!(
                rig.run("__bx_update", "y", &[]),
                (String::new(), String::new()),
                "{shell:?}"
            );
        }
    }

    #[test]
    fn the_hook_reads_the_stamps_where_bx_writes_them_for_every_xdg_state_home() {
        for shell in shells() {
            let rig = Rig::new(shell);
            let elsewhere = rig.home.path().join("elsewhere");
            let absolute = elsewhere.to_str().expect("a UTF-8 tempdir");
            // Unset, empty, absolute, relative: bx honours only the absolute
            // one, and the hook must look where bx resolves, not where the
            // shell's own `${XDG_STATE_HOME:-...}` would.
            for value in [None, Some(""), Some(absolute), Some("relative")] {
                let update = crate::state::StateDir::resolve_in(
                    rig.home.path(),
                    value.map(std::ffi::OsStr::new),
                )
                .update();
                std::fs::create_dir_all(&update).expect("update/");
                std::fs::write(update.join("available"), "~/a: 1 new commit(s) on main\n")
                    .expect("a stamp");
                let env: Vec<(&str, &str)> =
                    value.map(|v| ("XDG_STATE_HOME", v)).into_iter().collect();
                let (printed, calls) = rig.run("__bx_update_due", "y", &env);
                assert!(
                    printed.contains("~/a: 1 new commit(s) on main"),
                    "{shell:?}, XDG_STATE_HOME={value:?}: {printed}"
                );
                assert_eq!(calls, "update\n", "{shell:?}, XDG_STATE_HOME={value:?}");
                std::fs::remove_file(update.join("available")).expect("the stamp goes");
                std::fs::remove_file(rig.home.path().join("calls")).expect("the calls go");
            }
        }
    }

    /// Which of `stamps`, each the whole of an `ask-due` in a state directory
    /// of its own, `shell`'s hook asks from, in one run of `shell`; `None`
    /// when `shell` is not installed.
    fn asks_from(shell: Shell, stamps: &[String]) -> Option<Vec<bool>> {
        crate::shell::testing::installed(match shell {
            Shell::Zsh => "zsh",
            Shell::Bash => "bash",
        })?;
        let rig = Rig::new(shell);
        let mut script = String::new();
        for (i, text) in stamps.iter().enumerate() {
            let root = rig.home.path().join(format!("s{i}"));
            let state = crate::state::StateDir::resolve_in(rig.home.path(), Some(root.as_os_str()));
            std::fs::create_dir_all(state.update()).expect("update/");
            std::fs::write(crate::update::Stamps::of(&state).ask_due(), text).expect("a stamp");
            script.push_str(&format!(
                "XDG_STATE_HOME='{}'\nBX_UPDATE_ASKED=\nprintf '@\\n'\n__bx_update_due </dev/null\n",
                root.display()
            ));
        }
        let (printed, _) = rig.run(&script, "", &[]);
        let asked: Vec<bool> = printed
            .split("@\n")
            .skip(1)
            .map(|run| run.contains("check now whether"))
            .collect();
        assert_eq!(asked.len(), stamps.len(), "{shell:?}: {printed}");
        Some(asked)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(12))]

        /// `bx doctor` says a stamp holds no time exactly when the hook would
        /// not ask from it. Every time drawn is long past, so a stamp holding
        /// one is due, and the hook asks from it.
        #[test]
        fn the_hook_and_doctor_agree_on_which_stamps_hold_a_time(
            stamps in proptest::collection::vec(
                "\n?[ \t]{0,2}[+-]?[0-9]{0,9}[ \t\rx.]{0,2}(\n|\n[0-9x]{0,3}\n)?",
                1..24,
            ),
        ) {
            let dir = tempfile::tempdir().expect("a directory");
            let doctor: Vec<bool> = stamps
                .iter()
                .map(|text| {
                    let path = dir.path().join("ask-due");
                    std::fs::write(&path, text).expect("a stamp");
                    crate::update::Stamps::read(&path).is_some()
                })
                .collect();
            for shell in shells() {
                if let Some(hook) = asks_from(shell, &stamps) {
                    proptest::prop_assert_eq!(&hook, &doctor, "{:?}: {:?}", shell, stamps);
                }
            }
        }

        /// bx says an offer stands exactly when the hook offers it: the same
        /// lines, the same generation line, and the same reading of
        /// `answered`.
        #[test]
        fn the_hook_and_bx_agree_on_whether_an_offer_stands(
            stamps in proptest::collection::vec(
                (
                    proptest::option::of(
                        "([ \t]?gen[ \t]{1,2}[ab ]{0,2}[ \t]?\n)?([ \t]?[ab~:]{0,3}[ \t]?\n){0,2}[ab]{0,2}",
                    ),
                    proptest::option::of("[ \t]?[ab ]{0,2}[ \t]?(\n[ab\n]{0,2})?"),
                ),
                1..12,
            ),
        ) {
            let bx: Vec<bool> = stamps
                .iter()
                .map(|(available, answered)| {
                    crate::update::Stamps::offers(
                        available.as_deref().map(str::as_bytes),
                        answered.as_deref().map(str::as_bytes),
                    )
                })
                .collect();
            for shell in shells() {
                if let Some(hook) = offers_from(shell, &stamps) {
                    proptest::prop_assert_eq!(&hook, &bx, "{:?}: {:?}", shell, stamps);
                }
            }
        }
    }

    /// Which of `stamps`, each an `available` and an `answered` in a state
    /// directory of its own, `shell`'s hook offers, in one run of `shell`;
    /// `None` when `shell` is not installed.
    fn offers_from(shell: Shell, stamps: &[(Option<String>, Option<String>)]) -> Option<Vec<bool>> {
        crate::shell::testing::installed(match shell {
            Shell::Zsh => "zsh",
            Shell::Bash => "bash",
        })?;
        let rig = Rig::new(shell);
        let mut script = String::new();
        for (i, (available, answered)) in stamps.iter().enumerate() {
            let root = rig.home.path().join(format!("s{i}"));
            let state = crate::state::StateDir::resolve_in(rig.home.path(), Some(root.as_os_str()));
            let update = crate::update::Stamps::of(&state);
            std::fs::create_dir_all(state.update()).expect("update/");
            for (path, text) in [
                (update.available(), available),
                (update.answered(), answered),
            ] {
                if let Some(text) = text {
                    std::fs::write(path, text).expect("a stamp");
                }
            }
            script.push_str(&format!(
                "XDG_STATE_HOME='{}'\nBX_UPDATE_ASKED=\nprintf '@\\n'\n__bx_update_due </dev/null\n",
                root.display()
            ));
        }
        let (printed, _) = rig.run(&script, "", &[]);
        let offered: Vec<bool> = printed
            .split("@\n")
            .skip(1)
            .map(|run| run.contains("has new commits:"))
            .collect();
        assert_eq!(offered.len(), stamps.len(), "{shell:?}: {printed}");
        Some(offered)
    }

    /// Whether the installed bash is one [`BASH`] registers on: 4.4 or later.
    /// An older one — macOS's `/bin/bash` is 3.2 — registers nothing, which
    /// `a_bash_older_than_4_4_registers_nothing_and_says_nothing` holds it
    /// to, so the tests of what a registration does have nothing to read
    /// there.
    fn bash_registers() -> bool {
        static REGISTERS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *REGISTERS.get_or_init(|| {
            let Some(bash) = crate::shell::testing::installed("bash") else {
                return false;
            };
            let output = Command::new(bash)
                .args(["--norc", "--noprofile", "-c"])
                .arg("printf '%s %s' \"${BASH_VERSINFO[0]}\" \"${BASH_VERSINFO[1]}\"")
                .output()
                .expect("bash runs");
            let printed = String::from_utf8_lossy(&output.stdout);
            let version: Vec<u32> = printed
                .split(' ')
                .map(|part| part.parse().unwrap_or_else(|_| panic!("{printed:?}")))
                .collect();
            (version[0], version[1]) >= BASH_SINCE
        })
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
        if !bash_registers() {
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
        if !bash_registers() {
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
        if !bash_registers() {
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
    fn a_bash_older_than_4_4_registers_nothing_and_says_nothing() {
        if crate::shell::testing::installed("bash").is_none() {
            return;
        }
        // Whichever bash this is: 4.4 or later registers the entry, and an
        // older one — macOS's 3.2 — parses the whole hook, registers nothing
        // and prints nothing, so a shell sourcing bx's file there starts
        // cleanly without the question.
        let rig = Rig::new(Shell::Bash);
        let (printed, calls) = rig.run(
            "printf '%s|%s\\n' \"$(( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] ))\" \
             \"${PROMPT_COMMAND-}\"",
            "",
            &[],
        );
        let (version, registered) = printed
            .trim_end()
            .split_once('|')
            .unwrap_or_else(|| panic!("{printed:?}"));
        let version: u32 = version.parse().expect("bash's version");
        let since = BASH_SINCE.0 * 100 + BASH_SINCE.1;
        let expected = if version >= since {
            "${BX_UPDATE_HOOK-}"
        } else {
            ""
        };
        assert_eq!(registered, expected, "bash {version}: {printed:?}");
        assert_eq!(calls, "");
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
