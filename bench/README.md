# Startup benchmark

`bx` is on every shell start, so "fast enough to forget" is a product
requirement — and an unmeasured requirement is one that regresses. `mise run
bench` is the external profile that keeps it honest, and CI fails on a
regression on both platforms bx supports: the `Shell startup budget` job runs
it on Linux, where spawns are counted through `/proc`, and
`Shell startup budget (macOS)` runs it on macOS, holding bash to the system's
`/bin/bash` 3.2, where they are counted through kqueue. `run.sh`
prints which way it counted, and the macOS job fails unless that line names
kqueue, so neither job can pass with the trace skipped. Each uploads its
result as its own artifact, `startup-benchmark` and `startup-benchmark-macos`.

```
mise run bench
```

It measures bytes bx itself generated. The task builds the release binary, and
`run.sh` has that binary apply the example configuration in `fixtures/bx` to a
scratch home; the shells measured are the zsh and the bash that home starts. A
bench that could run without a binary would pass by measuring nothing, so
`run.sh` refuses to start without one (`BX_BIN` names another).

## What it measures

Everything below is measured for zsh and for bash alike.

**`overhead`** — `baseline` vs the same rc file after `bx apply`: bx's region
in `~/.zshrc` or `~/.bashrc`, the interactive file that region sources, and
for zsh the `~/.zshenv` fragment, with the example's four activations cached
into the interactive file and the hook that asks about a followed external's
updates defined and registered in it. What bx's generated files cost.
**Gated** at `BX_BUDGET_MS` (default 5), for each shell. The bench refuses to
measure when either interactive file lacks the hook, so the number always
includes it.

**`spawns`** — invariant 6 says the startup path spawns no process, and the
bench holds it twice. Read: the lines of those files, comments aside, that hold
a command substitution, which covers branches this home never takes; it counts
the hand-written rc files' four as well, so a pattern that finds nothing is
known to work. Traced: the shell runs bx's lines alone — the regions, cut out
of the rc files, in the bx home — and the processes it started are counted,
each way 0 exactly when bx's files started nothing, whatever else the machine
is doing. On Linux, once they are done and it has waited, the shell reads its
own `/proc/$$/stat` with builtins: a shell carries the page faults of every
child it waited for in that file's `cminflt`, and no process runs without
faulting. On macOS, which has no `/proc` and whose shells' builtins expose no
child page faults, a small Python tracer starts the shell and counts its forks
through a kqueue `NOTE_FORK` filter it registers before the shell's first
line runs; every command and subshell a shell starts begins as a fork. The
hand-written rc files' activation lines, traced the same way, must read
above 0. **Gated**: any is a failure.

**`reads`** — invariant 6 says the startup path parses no configuration file.
Every file under the bx home's `~/.config` and `~/.local/state` — bx's config
repo, its `local.toml` and state, and the tool configs it delivered — has its
access time set into the past, and each shell's traced start must leave all
of them unread. Linux's `relatime` and macOS's default APFS mounts both record
such a read, and BSD `find -newerat` and `touch -a -t` behave as GNU's do. A
read the harness makes first proves the filesystem records reads; on a
`noatime` mount the bench refuses to run (set `TMPDIR` elsewhere). **Gated**:
any read is a failure.

**`net`** — a hand-written rc file that activates the same four tools with
`eval "$(tool init zsh)"` or `bash`, against bx's. **Reported, never gated**:
which tools you integrate is your choice, so any threshold here would be
arbitrary.

## Why the result is trustworthy

- **Hermetic.** A scratch home per fixture, and `env -i` for every shell and
  every `bx` run; the developer's real config is never sourced. Each shell
  skips the machine's system-wide startup files too (`zsh -d`, and
  `bash --rcfile`, which also skips `/etc/bash.bashrc` where bash reads one).
  The number is about bx, not about the machine.
- **Converged.** `bx apply` must exit 0 and the `bx plan` after it must too, so
  what is measured is exactly what bx leaves in place.
- **Stub tools.** `stubs/` stands in for starship, zoxide, mise and fzf,
  emitting init blocks of representative size. The measurement does not depend
  on which tools happen to be installed, and the fork-and-exec cost that
  `eval "$(…)"` pays is real.
- **The stub output is real shell**, not comments, so the shell genuinely
  parses it; and it is shell zsh and bash both run cleanly, since the example
  activates each tool for both.
- **Primed.** Each fixture runs once before timing so `compinit`'s dump exists,
  and the `net` measurement warms up further before recording.
- **Medians.** The gate reads a median of differences, so a start the
  scheduler happened to delay does not move the number it reads.
- **Interleaved.** A shared CI runner moves the same start by more than the
  budget from one start to the next, and a macOS runner holds a slow spell for
  a fraction of a second, so a difference of two blocks of runs would carry
  that drift. The `overhead` is measured in `BX_BENCH_ROUNDS` rounds (default
  half of `BX_BENCH_RUNS`, rounded up) of four single starts, mirrored:
  `baseline bx bx baseline`, then `bx baseline baseline bx`. A round's
  difference is the mean of its two `bx` starts less the mean of its two
  `baseline` starts, so a drift steady across the round cancels, and the gate
  reads the median of the rounds' differences, so a round a spell broke into
  is outvoted.

The example's pinned external and its secret are switched off in the bench's
`local.toml`: one would clone over the network and the other needs a key, and
neither is on the startup path. `tests/acceptance.rs` applies both.

The example's followed external stays on, because following a branch is what
generates the update-prompt hook, and the hook is on the startup path. It
never reaches the network: `run.sh` makes a one-commit upstream in the scratch
directory, the bx home's `~/.gitconfig` redirects the declared url to it with
`url.<base>.insteadOf`, and the copy's `bx.lock` holds that upstream's commit
in place of the published one.

## The example configuration

`fixtures/bx` is a complete config repo, shaped like a real dotfiles
repository ported to bx, with nothing in it that names an account, a machine,
a mount or a key: `bx.toml` and `modules/*.toml` declare it, `bx.lock` holds
the commit its followed external is locked to, and `home/` holds the file
bodies. `tests/acceptance.rs` applies it with the real binary and
holds it to the invariants end to end, and walks it for anything
account-specific.

`fixtures/bx/bx-init.zsh` is not part of it. It is the shell-init snippet
`env_guard`'s `the_init_snippet_is_not_an_environment_fragment` holds to the
no-assignment rule, kept here until a generator emits it; bx reads nothing in
a config repo but its layers and the bodies they name.

## Layout

```
run.sh                    the harness
fixtures/baseline/        the account's own zshrc and bashrc, no integrations
fixtures/bx/              the example configuration, applied into a copy of baseline
fixtures/legacy/          baseline + eval "$(tool init)" per tool
stubs/                    stand-ins for starship, zoxide, mise, fzf
results/                  hyperfine JSON per measurement, round and shell (gitignored)
```

`BX_BENCH_RUNS` (default 50) sets the minimum runs per fixture of the `net`
measurement, and the runs per fixture of the `overhead` measurement, two in
each of its rounds.
