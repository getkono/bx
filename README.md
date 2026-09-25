# bx

`bx` is a single-binary Linux developer-environment manager. One `bx init` and
one `bx apply` replace setting up mise, sccache, uv, git, ssh, gh, starship and
the rest one tool at a time. Your configuration lives in a git repo you own;
your machine converges to it.

It is **additive**: it never deletes or rewrites config you wrote, and it never
moves another tool's config, data or cache anywhere you did not declare. Remove
`bx` and every tool you manage with it still works exactly as before.

Linux only. No macOS, no Windows.

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

## Getting started

```bash
bx init         # guided setup — first machine or fifth, same command
```

`init` finds the tools and config already on the machine, asks which of them to
manage, asks for the handful of values that are yours alone, shows you the diff,
and applies it on confirmation. It is idempotent and resumable — re-running it
is the supported way to change your mind.

## Commands

There are ten. You should not need a manual.

| | |
|---|---|
| `bx` | status: what is managed, what drifted, what is pending, what your shell costs |
| `bx init` | guided setup |
| `bx add` | begin managing a tool, a config file, or a secret |
| `bx rm` | stop managing it, and restore the original |
| `bx plan` | the diff `apply` would make |
| `bx apply` | converge this machine to the repo |
| `bx sync` | pull, apply, push — no git knowledge required |
| `bx secret` | set, list, rotate secrets and recipients |
| `bx doctor` | drift, missing tools, broken seams, stale caches, shell cost |
| `bx shell-init` | the one line for your shell rc |

Every prompt has a flag equivalent, plus `--yes`, so the whole surface is
scriptable. Tab completion is dynamic — it suggests your actual modules, files
and secrets, not just the flag list.

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
  a key that never enters the repo, and a guard blocks any commit that would
  leak one.
- Secrets are delivered into each tool's *own* credential store or agent where
  one exists; only failing that, into a private-mode file.
- Adopting existing config is lossless: your current files are taken verbatim,
  so a fresh machine reproduces the one you have, not a skeleton of it.

### Drift is surfaced, never resolved behind your back

- A managed file edited by hand stops `apply`, shows the diff, and asks whether
  to keep the edit, discard it, or skip the module.
- `doctor` reports config that points at things that do not exist, tools
  installed but not reachable, caches at their limit, and integrations that have
  gone stale.

### Fast enough to forget

- `bx` runs at every shell start and must be unmeasurable. Its budget is **5 ms**
  and the budget is enforced by a benchmark in CI, not by good intentions.
- The shell startup path spawns no process and parses no configuration file.
- Where `bx` can make *your other tools* start faster without changing their
  behaviour, it does — and tells you what it saved.

## Configuration

Your config repo lives wherever you want it; `bx init` proposes
`~/.config/bx`. It contains a manifest of what you manage, the config content
`bx` owns, and your encrypted secrets. It is safe to make public.

Everything specific to you or to one machine — answers, the write record, caches,
and the key that decrypts your secrets — stays outside the repo, on the machine.

## License

MIT
