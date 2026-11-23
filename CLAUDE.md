# bx

An idempotent developer-environment manager for Linux and macOS that never
touches a byte the user wrote. A command-line application written in Rust
(edition 2024). **Linux and macOS 13+, on x86_64 and aarch64.** On macOS bx
keeps the same XDG directories for its own files (`~/.config/bx`,
`~/.local/state/bx`, `~/.local/share/bx`), never a `~/Library` layout. **No
Windows** — do not add Windows code paths, targets, or documentation.

## Invariants

These are product requirements, not preferences. A change that breaks one is
wrong even if it passes CI.

1. **Never a byte the user wrote.** Never delete or rewrite a byte the user
   wrote. Writes land in delimited managed regions, or in files bx owns because
   the user said so. What bx wrote it takes back once nothing declares it, and
   only while the ledger proves the bytes are still exactly the ones it left; a
   file edited since is kept as it is and stops being managed. A configuration
   that declares nothing at all takes back nothing. bx rewrites a byte the user
   wrote only on that user's explicit answer for that file, and keeps the bytes
   it replaced restorable.
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
   lines bx generates for the shell-start path spawn no process and parse no
   config file. The one exception is a tool's cached activation output, which
   bx sources exactly as the tool printed it: caching saves running the tool's
   init, never changes what that init does, so whatever the output itself runs
   (starship's `PROMPT2="$(starship prompt --continuation)"`) runs at every
   start, as it would under `eval "$(tool init)"`. The bench always runs it:
   the budget counts it on Linux, and on macOS the bench reports its cost
   apart and gates bx's own share. bx never
   rewrites the cached text to avoid it. After the first prompt, an
   interactive shell with a terminal and no CI or coding-agent variable set
   may start one detached, time-bounded
   `bx update --background`, and only once a followed `[[external]]` set to
   `check = "auto"` is due; it starts nothing else unless someone answers a
   question.
7. **`plan` and `apply` share one function.** `apply` must never do work `plan`
   did not announce.

## Rules

- All logic lives in the library (`src/lib.rs` and below) with tests.
  `src/main.rs` stays a thin entry point: it is excluded from coverage, so
  logic moved there counts toward nothing.
- No feature gates. The binary is one product with one install path; a gate
  only creates configurations CI never builds.
- Library code reports through `tracing` macros, never `println!`.
- Machine-owned state (ledger, fingerprints, journal) is MessagePack, not
  JSON, for its native binary type. Every such file must be reconstructible:
  a corrupt one degrades to recomputation.
- Hand-authored TOML is read and edited through `toml_edit`, preserving
  comments and formatting, so running a command and hand-editing are the same
  operation.
- Never put completion generation on the shell-startup path.
- A new dependency says why it is there in a comment in `Cargo.toml`.

## Testing

Anything that touches a home directory must run against a tempdir `HOME`, behind
a guard that aborts if `HOME` is not a tempdir. Alongside ordinary unit tests,
the properties in *Invariants* are the tests that matter: idempotence,
reversibility, additivity, and crash-safety.

Validate with `mise run` (`mise tasks` lists them); the pre-commit and pre-push
hooks are in `hk.pkl`. Coverage must stay at or above 80% of lines. Commit
messages are Conventional Commits.
