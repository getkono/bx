# bx

An idempotent, additive Linux developer-environment manager. A command-line
application written in Rust (edition 2024). **Linux only** — do not add macOS or
Windows code paths, targets, or documentation.

## Layout

- `src/lib.rs` — the `bx` library crate. **All real logic lives here** so it is
  unit-testable and counted by coverage.
- `src/main.rs` — thin binary entry point. Wires up `color_eyre` and
  `tracing_subscriber`, then delegates to the library. **Excluded from coverage**
  (the `coverage` task passes `--ignore-filename-regex 'src/main\.rs'`).
- `build.rs` — embeds the build commit for `bx --version`. Best-effort; never
  fail the build when git is unavailable.
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
2. **Native locations only.** Never point a tool at a bx-owned directory. Never
   emit an env var that relocates a tool's config, data, or cache — `env_guard`
   enforces this and every generated shell fragment must pass through it.
3. **Idempotent.** `apply` twice must produce an empty second `plan`, and
   generated files must be byte-identical between runs: no timestamps, no
   nondeterministic iteration order.
4. **Reversible.** Every write is recorded with the prior bytes, so `rm`
   restores exactly. An interrupted `apply` must be detectable and recoverable.
5. **Nothing user-specific and no cleartext secret in the repo.** Ever.
6. **Shell startup is budgeted at 5 ms**, enforced by `mise run bench`. The
   shell-start path spawns no process and parses no config file.
7. **`plan` and `apply` share one function.** `apply` must never do work `plan`
   did not announce.

## Packages

- **clap + clap_complete** — CLI surface and completions. Dynamic values come
  from the hidden `bx __complete`; never put completion generation on the
  shell-startup path.
- **inquire** — interactive prompts for `init` and confirmations. There is no
  TUI beyond these.
- **similar** — diffs for `plan`. **anstyle / owo-colors** — styling that
  respects `NO_COLOR`. **indicatif** — progress during `apply` only.
- **age** — secrets, in-process, so the static binary needs no external
  `age`/`sops`. Default identity is the user's existing ssh ed25519 key.
- **rmp-serde** — MessagePack for machine-owned state (ledger, fingerprints,
  journal). Not JSON: length-prefixed, and it has a native binary type. Every
  such file must be reconstructible, so a corrupt one degrades to recomputation.
- **toml_edit** — hand-authored config, and comment-preserving edits to other
  tools' TOML. Commands and hand-editing must be the same operation.
- **tempfile + rustix** — atomic writes (temp in destination dir, fsync,
  rename), file modes, and the advisory state-dir lock.
- **eyre + color-eyre** — application error reporting; `color_eyre::install()`
  runs at startup in `main`.
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

`hk` runs format + lint on pre-commit and the full gate on pre-push. Commit
messages are Conventional Commits, enforced by `convco`.
