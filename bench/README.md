# Startup benchmark

`bx` is on every shell start, so "fast enough to forget" is a product
requirement — and an unmeasured requirement is one that regresses. `mise run
bench` is the external profile that keeps it honest, and CI fails on a
regression.

```
mise run bench
```

It measures bytes bx itself generated. The task builds the release binary, and
`run.sh` has that binary apply the example configuration in `fixtures/bx` to a
scratch home; the shell measured is the one that home starts. A bench that
could run without a binary would pass by measuring nothing, so `run.sh` refuses
to start without one (`BX_BIN` names another).

## What it measures

**`overhead`** — `baseline` vs the same `~/.zshrc` after `bx apply`: bx's
region in it, the interactive file that region sources, and the `~/.zshenv`
fragment, with the example's four activations cached into the interactive
file. What bx's generated files cost. **Gated** at `BX_BUDGET_MS` (default 5).

**`spawns`** — the lines of those files, comments aside, that hold a command
substitution. The startup path spawns no process (invariant 6), so the bench
fails on any; it counts the hand-written zshrc's four as well, so a pattern
that finds nothing is known to work.

**`net`** — a hand-written zshrc that activates the same four tools with
`eval "$(tool init zsh)"`, against bx's. **Reported, never gated**: which tools
you integrate is your choice, so any threshold here would be arbitrary.

## Why the result is trustworthy

- **Hermetic.** A scratch home per fixture, and `env -i` for every shell and
  every `bx` run; the developer's real config is never sourced. The number is
  about bx, not about the machine.
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
  and hyperfine warms up further before recording.

The example's external and secret are switched off in the bench's
`local.toml`: one would clone over the network and the other needs a key, and
neither is on the startup path. `tests/acceptance.rs` applies both.

## The example configuration

`fixtures/bx` is a complete config repo, shaped like a real dotfiles
repository ported to bx, with nothing in it that names an account, a machine,
a mount or a key: `bx.toml` and `modules/*.toml` declare it, and `home/` holds
the file bodies. `tests/acceptance.rs` applies it with the real binary and
holds it to the invariants end to end, and walks it for anything
account-specific.

`fixtures/bx/bx-init.zsh` is not part of it. It is the shell-init snippet
`env_guard`'s `the_init_snippet_is_not_an_environment_fragment` holds to the
no-assignment rule, kept here until a generator emits it; bx reads nothing in
a config repo but its layers and the bodies they name.

## Layout

```
run.sh                    the harness
fixtures/baseline/        the account's own zshrc: interactive zsh, no integrations
fixtures/bx/              the example configuration, applied into a copy of baseline
fixtures/legacy/          baseline + eval "$(tool init)" per tool
stubs/                    stand-ins for starship, zoxide, mise, fzf
results/                  hyperfine JSON (gitignored)
```

`BX_BENCH_RUNS` (default 50) sets the minimum runs per fixture.
