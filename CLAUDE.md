# bx

An idempotent, additive developer-environment manager for Linux and macOS. A
command-line application written in Rust (edition 2024). **Linux and macOS 13+,
on x86_64 and aarch64.** On macOS bx keeps the same XDG directories for its own
files (`~/.config/bx`, `~/.local/state/bx`, `~/.local/share/bx`), never a
`~/Library` layout. **No Windows** — do not add Windows code paths, targets, or
documentation.

## Layout

- `src/lib.rs` — the `bx` library crate. **All real logic lives here** so it is
  unit-testable and counted by coverage.
- `src/main.rs` — thin binary entry point. Wires up `color_eyre` and
  `tracing_subscriber`, then delegates to the library. **Excluded from coverage**
  (the `coverage` task passes `--ignore-filename-regex 'src/main\.rs'`).
- `build.rs` — embeds the build's commit, profile, compiler and time for
  `bx --version`, which `src/version.rs` lays out. Best-effort; never fail the
  build when git is unavailable.
- `bench/` — the hermetic shell-startup benchmark. See `bench/README.md`.
- `install.sh` — the only distribution channel. POSIX sh, shellcheck-clean.

Put logic in the library with tests; keep `main.rs` minimal. Logic moved into
`main.rs` is not covered and does not count toward the 80% threshold.

There are no feature gates. The whole binary is one product with one install
path; gating it would only create configurations CI never builds.

## Invariants

These are product requirements, not preferences. A change that breaks one is
wrong even if it passes CI.

1. **Additive only.** Never delete or rewrite a byte the user wrote. Writes land
   in delimited managed regions, or in files bx owns because the user said so.
2. **Native locations unless the configuration declares otherwise.** Never point
   a tool at a bx-owned directory. Never move a tool's config, data, or cache
   outside a root the configuration declares. Declare no root and nothing
   moves. `env_guard` enforces this: every generated environment fragment
   passes through it, generated shell content that is not a fragment carries
   no environment assignment beyond the exceptions it lists, and a change that
   generates a new such file carries the proof of its own bytes with it. The
   full statement — the kinds of value and how each is judged, the admitted
   non-fragment files and their exceptions, and why containment is lexical —
   is the module documentation of `src/env_guard.rs`, and is kept only there.
3. **Idempotent.** `apply` twice must produce an empty second `plan`, and
   generated files must be byte-identical between runs: no timestamps, no
   nondeterministic iteration order.
4. **Reversible.** Every write is recorded with the prior bytes, so `rm`
   restores exactly. An interrupted `apply` must be detectable and recoverable.
5. **Nothing user-specific and no cleartext secret in the repo.** Ever.
6. **Shell startup is budgeted at 5 ms**, enforced by `mise run bench`. The
   shell-start path spawns no process and parses no config file. After the
   first prompt, an interactive shell with a terminal and no CI or coding-agent
   variable set may start one detached, time-bounded
   `bx update --background`, and only once a followed `[[external]]` set to
   `check = "auto"` is due; it starts nothing else unless someone answers a
   question.
7. **`plan` and `apply` share one function.** `apply` must never do work `plan`
   did not announce.

## Packages

- **clap** — CLI surface. Completions are planned: `clap_complete` comes back
  with the body of the hidden `bx __complete`, which is a stub today, and
  dynamic values will come from it. Never put completion generation on the
  shell-startup path.
- **inquire** — interactive prompts for `init` and confirmations. There is no
  TUI beyond these.
- **similar** — diffs for `plan`. **anstyle** — styling that respects
  `NO_COLOR`. **indicatif** — progress during `apply` only.
- **age** — secrets, in-process, so the static binary needs no external
  `age`/`sops`. Default identity is the user's existing ssh ed25519 key.
- **rmp-serde** — MessagePack for machine-owned state (ledger, fingerprints,
  journal). Not JSON: length-prefixed, and it has a native binary type. Every
  such file must be reconstructible, so a corrupt one degrades to recomputation.
- **toml_edit** — hand-authored config, and comment-preserving edits to other
  tools' TOML. Commands and hand-editing must be the same operation.
- **tempfile + rustix** — atomic writes (temp in destination dir, fsync,
  rename), file modes, the advisory state-dir lock, and discarding what was
  typed ahead of a confirmation.
- **eyre + color-eyre** — application error reporting; `main` installs
  color-eyre at startup with its location and backtrace-hint sections off, so
  an error reads as its message chain alone.
- **tracing + tracing-subscriber** — diagnostics. Use `tracing` macros, not
  `println!`, in library code. Verbosity via `BX_LOG` (e.g. `BX_LOG=bx=debug`).
- **thiserror** — typed error enums for the library's public APIs.

## Testing

Anything that touches a home directory must run against a tempdir `HOME`, behind
a guard that aborts if `HOME` is not a tempdir. Alongside ordinary unit tests,
the properties in *Invariants* are the tests that matter: idempotence,
reversibility, additivity, and crash-safety.

## Quality

Validate changes with `mise run`:

- `format` / `format-check` — `cargo fmt`
- `lint` / `lint-fix` — clippy, warnings as errors
- `test` — the suite
- `coverage` — ≥ 80% lines, `main.rs` excluded
- `bench` — the 5 ms shell-startup budget
- `mutants` — mutation testing, to find logic the tests do not pin down
- `shellcheck` — every shell script: the installer, the bench harness and its
  stubs, and `scripts/`
- `actionlint` — the GitHub workflows
- `line-check` — no file newly grows past the line limit, the baseline of
  files already over it only shrinks, and the limit only goes down

`hk` runs `format`, `lint-fix`, `shellcheck`, `actionlint` and `line-check` on
pre-commit, and `format-check`, `lint`, `test` and `coverage` on pre-push.
Commit messages are Conventional Commits, enforced by `convco`.
