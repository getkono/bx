# Startup benchmark

`bx` runs at every shell start, so "fast enough to forget" is a product
requirement — and an unmeasured requirement is one that regresses. `mise run
bench` is the external profile that keeps it honest, and CI fails on a
regression.

```
mise run bench
```

## What it measures

Two numbers, answering two different questions.

**`overhead`** — `baseline` vs `baseline + bx`. What bx itself costs: one
`[[ -r ]]` test, one `source` of a zcompiled snippet, one `-nt` staleness test,
and a `compdef` registration. **Gated** at `BX_BUDGET_MS` (default 5).

**`net`** — a hand-written zshrc that activates four tools with
`eval "$(tool init zsh)"`, against the snippet bx generates for the same four.
**Reported, never gated**: which tools you integrate is your choice, so any
threshold here would be arbitrary.

The `net` pair also differs in `compinit -i` versus `compinit -C` against a
pre-generated dump, because that is part of what bx does and excluding it would
understate the thing being measured. That is why `generated` can come in below
`baseline`.

## Why the result is trustworthy

- **Hermetic.** A scratch `HOME` and a per-fixture `ZDOTDIR`; the developer's
  real config is never sourced. The number is about bx, not about the machine.
- **Stub tools.** `bench/stubs/` stands in for starship, zoxide, mise and fzf,
  emitting init blocks of representative size. The measurement does not depend
  on which tools happen to be installed, and the fork-and-exec cost that
  `eval "$(…)"` pays is real.
- **The stub output is real zsh**, not comments, so the shell genuinely parses
  it — otherwise `zcompile` would be measuring nothing.
- **Primed.** Each fixture runs once before timing so `compinit`'s dump exists,
  and hyperfine warms up further before recording.

## Layout

```
run.sh                    the harness
fixtures/baseline/        interactive zsh, no integrations
fixtures/bx/              baseline + bx's own block  (overhead numerator)
fixtures/legacy/          eval "$(tool init)" per tool
fixtures/generated/       bx's snippet, activations inlined and zcompiled
stubs/                    stand-ins for starship, zoxide, mise, fzf
results/                  hyperfine JSON (gitignored)
```

`BX_BENCH_RUNS` (default 50) sets the minimum runs per fixture.
