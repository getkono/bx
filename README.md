# bx

> Project Status: Alpha. Linux support is ready but documentation is missing.

`bx` is a single-binary developer-environment manager. One `bx init` and
one `bx apply` replace setting up mise, sccache, uv, git, ssh, gh, starship and
the rest one tool at a time. Your configuration lives in a git repo you own;
your machine converges to it.

It is **additive**: it never deletes or rewrites config you wrote, and it never
moves another tool's config, data or cache anywhere you did not declare. Remove
`bx` and every tool you manage with it still works exactly as before.

Linux ready. macOS coming soon. No Windows unless refuted.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/getkono/bx/master/install.sh | sh
```

A single static binary, no runtime dependencies — it installs onto a barebones
box with no toolchain, which is the point: `bx` is what you run *before* you
have anything else.

It also installs as **`userbox`**. Two-letter names are a scarce namespace with
no registry, so the long name is the one that is guaranteed to keep working:
if `bx` ever collides with something on your machine, drop the short name and
nothing else changes. (`fd` ships `fdfind` on Debian for the same reason.)

To upgrade, run `bx self-upgrade`: it runs this same installer over the
installed binary. `bx self-upgrade --check` only reports whether a newer
release exists, exiting `2` when one does, and `bx self-upgrade --force`
reinstalls the latest release even when yours is not older. Each release pins the installer's checksum, so if the installer
has changed since your release, `bx self-upgrade` refuses and sends you here.
Reinstall with the line above.

## Getting started

```bash
bx init         # guided setup — first machine or fifth, same command
```

`init` finds the tools and config already on the machine, asks which of them to
manage, asks for the handful of values that are yours alone, shows you the diff,
and applies it on confirmation.

It is idempotent and resumable. Run it again at any time: it says whether it
created the config repo or found yours, asks only for values that still have no
answer, offers whatever config is still unmanaged, and ends by saying where the
machine stands. On a machine that is already set up it writes nothing unless
you pick something it offers: the only question it puts is the offer of config
you have not chosen to manage, and picking nothing is a fine answer. To change an answer you already gave,
`bx init --set NAME=VALUE`.

Esc or Ctrl-C at any question stops it there. What it had already written stays
and has already been reported, and the next `bx init` picks up from that point.
Answers you typed in a run that stopped at a later value question are not kept.

## Commands

There are twelve. You should not need a manual.

| | |
|---|---|
| `bx` | status: every managed target, and what is pending, in conflict or blocked |
| `bx init` | guided setup |
| `bx add PATH` | begin managing a config file, or a directory of them |
| `bx rm PATH` | stop managing it, and restore the original |
| `bx plan` | the diff `apply` would make |
| `bx apply` | converge this machine to the repo |
| `bx sync` | pull, apply, push — no git knowledge required |
| `bx update` | move [dependencies](#dependencies) that follow a branch to its new commits: pull, look, lock and commit, apply |
| `bx secret list` | list declared secrets, and whether each decrypts here |
| `bx doctor` | missing tools, unanswered values, damaged state, and what else needs a look; changes nothing |
| `bx shell-init` | the one line for your shell rc — not built yet |
| `bx self-upgrade` | install the latest release over this one; `--check` only looks, `--force` reinstalls even when this one is not older |

`init`, `apply`, `sync` and `update` take `--yes`, and `init` takes
`--set NAME=VALUE` for each value it would ask for, so all four run without a
terminal. `bx update --check` only looks, exiting `2` when something is new,
and `bx update --snooze` puts the next question off.

`add` and `rm` need the file or directory to act on; without one they refuse
and point you at `bx init`, which offers the config already on the machine.

`bx secret list` reads; nothing under `bx secret` writes. Who secrets are
encrypted to is the `recipients` list under `[secrets]` in `bx.toml` or a
module, edited by hand, and a secret is encrypted or re-encrypted to them with
`age -e`.

### Reading a plan

Six symbols, and none of them is "destroy". A tool that only adds never has
one, so those slots go to the cases that actually matter for a tool that must
not be invasive: something it does not own is in the way, the tool it is
configuring for is not on this machine, and a file it wrote is no longer
declared.

```
  +  create     it does not exist yet
  ~  modify     bx owns it and the content differs
  !  conflict   it exists, differs, and bx does not own it — or you edited
                bx's output. Reported and skipped, never overwritten.
  ?  blocked    the tool this configures is not installed, or is installed
                where you cannot run it. Reported and skipped until you
                install it — writing the config anyway would break your
                shell or your builds, not just that one tool.
  *  undeclared bx wrote it, and the configuration no longer declares it.
                Left exactly as it is; `bx rm` releases it.
  =  unchanged  already converged (hidden unless you ask)
```

`plan` and `apply` compute this with the same code, so `apply` can never do work
`plan` did not show you.

### Exit codes

`plan` follows the `diff` convention, so it is usable from CI, a prompt segment,
or a login banner without anyone parsing its output:

| | |
|---|---|
| `0` | converged — nothing to do |
| `1` | error |
| `2` | changes pending, or a conflict or blocked target needs a decision |
| `130` | you left a question with Esc or Ctrl-C; what was on offer was not done |

The other commands use the same codes. `bx add` exits `2` when it refused a
path, `bx rm` when a conflict left something as it was, and
`bx self-upgrade --check` when a newer release exists.

## Requirements

### Additive, always

- `bx` never deletes or rewrites a byte you wrote. Its writes land in delimited
  managed regions, or in files it owns because you said so.
- Every integration attaches at the target tool's **own** documented extension
  point — an `[include]` in `.gitconfig`, an `Include` in `.ssh/config`, mise's
  own config directory, one `source` line in `.zshrc`.
- `bx` never points a tool at a `bx`-owned directory, and never sets an
  environment variable that moves a tool's config, data, or cache outside a root
  you declared. It sets only variables it knows how to judge, and judges each
  value for what it is — a location, a list of locations, an anchor, a program,
  a command line, a tool's options, a search list, a socket or a setting: declare your scratch mount as a root
  and your toolchain caches may live there; declare nothing and no location,
  list of locations or anchor is allowed at all. The other kinds say what a
  tool runs, where it looks and what it connects to rather than where its files
  live, so they move nothing and need no root — and none of them, root or no
  root, may point inside a directory `bx` owns. It will write only a variable
  in bx's emit table, which grows with the generators that need it.
- Uninstalling is a supported operation, not an afterthought.

### Idempotent and reversible

- Running `apply` twice changes nothing the second time.
- `plan` shows a real diff before anything is written. Nothing is written
  without it being shown first.
- Every write is journalled and recorded, including the original bytes of
  whatever it replaced, so `bx rm` restores exactly those bytes and that file
  mode. It does not restore a replaced file's extended attributes, POSIX ACL,
  SELinux label, owner and group, or timestamps: replacing a file creates a new
  one, and none of these are recorded.
- An interrupted `apply` is detected on the next run and rolled back: a
  read-only command reports it, and the next writing command undoes it before
  it does anything else. No torn files, ever, and no half-applied plan left
  standing.
- Two `bx` processes cannot corrupt each other.

### Opinionated, to avoid surprises

- One way to do each thing. Configuration is data, not a program: there is no
  template language, no conditionals, no loops, no scripting hooks that can
  diverge between machines.
- Content that must differ per machine is a declared option or a declared
  value — never a branch hidden inside a config file.
- Paths are stored portably and rendered per machine, so a config repo moves to
  a machine with a different `$HOME` without edits.
- `bx` owns the **order** in which shell integrations load, declaratively.
  Ordering bugs between a version manager, a PATH edit, and a completion system
  are a solved problem, not yours.

### Your repo, your data

- All configuration lives in an ordinary git repo you can read, edit, review,
  and host wherever you like. `bx` is not required to understand it.
- Editing the repo by hand and running an `bx` command are the same operation:
  commands edit the same files, preserving your comments and formatting.
- **Nothing user-specific is ever committed.** Identity, hostnames, absolute
  paths, and per-machine choices are asked for at setup and stay on the machine.
- **No cleartext secret is ever committed.** Secrets are encrypted at rest with
  a key that never enters the repo, `bx` decrypts one only into its target,
  and `bx add` refuses the files at a fixed list of paths known to hold
  credentials. Nothing reads a file's content for one, and nothing scans what
  you commit by hand.
- A secret is delivered into a private-mode file.
- Adopting existing config is lossless: your current files are taken verbatim,
  so a fresh machine reproduces the one you have, not a skeleton of it.

### Drift is surfaced, never resolved behind your back

- A managed file edited by hand is a conflict: `plan` and `apply` report it,
  and `apply` skips it, leaving your edit exactly as it is.
- `bx` asks nothing about a conflict: there is no prompt to keep the edit,
  discard it, or skip the module. You settle it by hand, in the file or in
  your configuration, and the next `plan` reads what you decided.
- `doctor` reports a declared tool that is not on `PATH`, a required value with
  no answer, a damaged state file, an interrupted or running session, a
  directory wider than a private file in it, a declared optional source that is
  not readable, a unit file systemd has not reloaded, enabled or loaded, or that
  has failed, a declared reference that is not on disk, a temporary file an
  interrupted write left behind, and a dependency that follows a branch
  `bx.lock` holds no commit for. It has no notion of a cache's size limit or of
  an integration gone stale, and reports neither.

### Fast enough to forget

- `bx` runs at every shell start and must be unmeasurable. Its budget is **5 ms**
  and the budget is enforced by a benchmark in CI, not by good intentions.
- The shell startup path spawns no process and parses no configuration file.
  The one process a shell ever starts on its own is a dependency's background
  check, after the first prompt, and only for a dependency you set to
  `check = "auto"` once its interval has passed.
- Where `bx` can make *your other tools* start faster without changing their
  behaviour, it does.

## Configuration

Your config repo lives wherever you want it; `bx init` proposes
`~/.config/bx`. It contains a manifest of what you manage, the config content
`bx` owns, and your encrypted secrets. It is safe to make public.

Everything specific to you or to one machine — answers, the write record, caches,
and the key that decrypts your secrets — stays outside the repo, on the machine.

## Dependencies

A git repository you want on every machine — a zsh plugin, a theme, a
collection of agent skills — is an `[[external]]`: `bx` clones it where you
say, keeps it at one commit, and never moves it without showing you first.
It is the job git submodules do, without a superproject.

```toml
[[external]]
path   = "~/.local/share/skills"            # where the checkout lives
url    = "git@github.com:you/skills.git"     # https or ssh; credentials stay in git
branch = "master"                            # follow a branch…
# rev  = "0e810e5afa27acbd074398eefbe28d13005dbc15"   # …or pin a commit

[[external.link]]                            # put its children where a tool looks
from    = "skills/*"
to      = "~/.claude/skills/*"
require = "SKILL.md"
```

**Pinned or followed.** An external says exactly one of `rev` and `branch`.
A pinned one moves only when you edit `rev`: the form for code you review
before it runs. A followed one is kept at the commit `bx.lock` holds — a file
beside `bx.toml`, committed with it, so every machine checks out the same
commit — and `bx update` is the only thing that moves it.

**`bx update`** brings the config repo level with its upstream, asks each
followed branch where it is now, lists the new commits, and shows the plan the
new lock would make. Once you approve, it writes and commits `bx.lock` *before*
it moves any checkout, then applies; `bx sync` pushes the commit. If another
machine pushed first, `bx update` replays this machine's own unpushed lock
commits on top of theirs; when both changed `bx.lock`, or any other commit is
local, it changes nothing and says how to reconcile. A new commit
is locked only once it is shown to descend from the one locked before, so a
branch whose history was rewritten is reported and never locked. `plan` and
`apply` never ask a remote where a branch is: they read the lock, and `apply`
fetches only the commit it names.

**Links.** Each `[[external.link]]` turns every child directory of `from` in
the locked commit into a symlink of the same name in `to`, so a new skill
upstream becomes a new link on the next update and a removed one is reported
as undeclared, for `bx rm` to release. A link never replaces a file or link
you made; it is reported as a conflict instead. A `to` at, inside or above any
external's checkout is refused when the configuration loads.

**When bx asks.** An interactive zsh asks, at a prompt, at most once per shell:

| the dependency says | what happens |
|---|---|
| `check = "ask"` (the default) | once `[update] interval` (default `7d`) has passed, the prompt asks whether to check now; nothing reaches the network until you answer `y` |
| `check = "auto"`, with its own `interval` | once that interval has passed, the shell starts one quiet, time-bounded check after its first prompt, and a later prompt offers whatever it found; nothing is applied until you answer `y` |

Answering anything but `y` puts the question off for one interval. Nothing
asks, and nothing is checked, unless the shell is interactive with a terminal
on both ends: a script, `zsh -c`, a service, continuous integration
(`CI`), and coding agents (`CLAUDECODE`, `CODEX_SANDBOX`, `GEMINI_CLI`,
`CURSOR_AGENT`) never see a question. Set `BX_NO_UPDATE_PROMPT=1` to never be
asked. bx cannot tell a metered or mobile connection from any other, which is
why the default is to ask first. bash is not asked yet.

## License

MIT
