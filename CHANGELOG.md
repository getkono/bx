# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This file is maintained by [release-plz](https://release-plz.dev) from
Conventional Commit messages.

## [Unreleased]

## [0.1.2](https://github.com/getkono/bx/compare/v0.1.1...v0.1.2) - 2026-10-10

### Added

- *(doctor)* report a local.toml inside the config repo ([#202](https://github.com/getkono/bx/pull/202))
- *(shell)* ask about followed externals' updates at a bash prompt ([#200](https://github.com/getkono/bx/pull/200))
- follow a branch through bx.lock, link checkout children, and add bx update ([#163](https://github.com/getkono/bx/pull/163))
- add bx self-upgrade
- *(install)* print the latest release with --latest

### Fixed

- *(update)* name the path once, and the operation that failed, in state-file errors ([#224](https://github.com/getkono/bx/pull/224))
- *(shell)* resolve XDG_STATE_HOME in the update-prompt hook as bx does ([#218](https://github.com/getkono/bx/pull/218))
- *(sync)* name the recovered commit when refusing a diverged branch ([#201](https://github.com/getkono/bx/pull/201))
- *(plan)* name the committed-layer or rev remedy for a follow bx update never locks ([#199](https://github.com/getkono/bx/pull/199))
- *(sync)* split git -z output before trimming, so a leading-whitespace path keeps it ([#198](https://github.com/getkono/bx/pull/198))
- restore green CI on clippy 1.99.0 and pin the Rust toolchain ([#149](https://github.com/getkono/bx/pull/149))
- *(init)* claim no more about a deferred adoption than a journal shows
- *(init)* keep every closing and cancel line true in the states review found
- *(init)* refuse a config repo path that is not a directory
- *(init)* say what it found, each write as it happens, and what is next
- *(cli)* describe bx secret and bx add as they are in --help
- *(cli)* refuse shell-init and __complete instead of panicking
- *(command)* end a canceled prompt with one line and exit 130
- *(cli)* report build details from -V and --version
- *(cli)* drop color-eyre's location and backtrace sections from errors

### Other

- give each followed-external rule and message one implementation ([#222](https://github.com/getkono/bx/pull/222))
- *(deps)* drop clap_complete until bx __complete is built ([#221](https://github.com/getkono/bx/pull/221))
- pin bx update, its prompt hook, sync and self-upgrade promises ([#219](https://github.com/getkono/bx/pull/219))
- align the README, CLAUDE.md and module docs with the shipped behaviour ([#217](https://github.com/getkono/bx/pull/217))
- *(state)* stage the over-PATH_MAX local.toml with few enough links to survive a retried walk ([#197](https://github.com/getkono/bx/pull/197))
- deal diff mutants across twelve shards instead of four ([#195](https://github.com/getkono/bx/pull/195))
- *(bench)* time bash startup and trace spawns and config reads ([#190](https://github.com/getkono/bx/pull/190))
- run bx self-upgrade end to end, replacing a copied binary and refusing a bad checksum ([#189](https://github.com/getkono/bx/pull/189))
- *(readme)* state that bx has no drift prompt and no cache or staleness checks ([#188](https://github.com/getkono/bx/pull/188))
- narrow the remaining test-only items to cfg(test) ([#185](https://github.com/getkono/bx/pull/185))
- make the config to shell dependency one-directional ([#184](https://github.com/getkono/bx/pull/184))
- make doc comments match the functions beneath them ([#183](https://github.com/getkono/bx/pull/183))
- *(plan)* state the additivity and plan/apply laws as property tests ([#181](https://github.com/getkono/bx/pull/181))
- move ContentHash to a crate-level hash module so fs imports nothing from state ([#180](https://github.com/getkono/bx/pull/180))
- *(plan)* split decide.rs and mod.rs along their cohesion lines ([#179](https://github.com/getkono/bx/pull/179))
- split recover.rs and state/ledger.rs along their cohesion lines ([#178](https://github.com/getkono/bx/pull/178))
- split config/resolve.rs and config/merge.rs along their cohesion lines ([#177](https://github.com/getkono/bx/pull/177))
- split fs/atomic.rs and journal.rs along their cohesion lines ([#168](https://github.com/getkono/bx/pull/168))
- *(env_guard)* split the guard along its cohesion lines ([#176](https://github.com/getkono/bx/pull/176))
- break the config, shell and env_guard cycles by rehoming misplaced items ([#161](https://github.com/getkono/bx/pull/161))
- rehome plan, sync and process-context helpers and narrow test-only items ([#169](https://github.com/getkono/bx/pull/169))
- hold pull-request mutation testing to the lines a diff writes, not those it moves ([#175](https://github.com/getkono/bx/pull/175))
- *(journal)* reword comments that name the removed new_entry ([#173](https://github.com/getkono/bx/pull/173))
- rehome fs, journal and ledger primitives into the modules that own them ([#158](https://github.com/getkono/bx/pull/158))
- copy .git into cargo-mutants' scratch tree so the baseline passes ([#166](https://github.com/getkono/bx/pull/166))
- pin the behaviours mutation testing and coverage left unconstrained ([#150](https://github.com/getkono/bx/pull/150))
- *(deps)* remove dependencies nothing references ([#157](https://github.com/getkono/bx/pull/157))
- run cargo-mutants on each pull request diff ([#156](https://github.com/getkono/bx/pull/156))
- derive the no-user-specific-data needles from the running machine ([#155](https://github.com/getkono/bx/pull/155))
- read source-scanning tests' files by module directory walk ([#154](https://github.com/getkono/bx/pull/154))
- correct top-level documentation to the shipped behaviour ([#153](https://github.com/getkono/bx/pull/153))
- bring CI, mise and hk gates into parity and keep coverage profiles out of the tree ([#152](https://github.com/getkono/bx/pull/152))
- gate file length at 3743 lines against a shrinking baseline ([#151](https://github.com/getkono/bx/pull/151))
- *(readme)* document bx self-upgrade
- *(init)* say a deferral may be a running apply's, and when a re-run writes
- Revise project status and platform compatibility
- *(init)* pin that a run which only adopted is set up, not already set up
- say what a re-run of bx init asks and keeps, and how errors are installed
- *(readme)* describe the commands this release ships
- *(release)* forward the commit date into the cross build

## [0.1.1](https://github.com/getkono/bx/compare/v0.1.0...v0.1.1) - 2026-09-28

### Added

- *(env_guard)* judge command lines, options, locales and input methods
- *(doctor)* report a written target's declared references missing from disk
- *(adopt)* hand a tracked target back through its repo copy
- *(sync)* carry tracked targets into the repo and commit them in one commit
- *(plan)* decide tracked targets against what both sides last agreed on
- *(config)* expand a tree target into one target per repo file
- *(shell)* render declared keybindings into the interactive file's keybindings phase
- *(shell)* render one declared history into the interactive zsh file
- *(shell)* render the interactive shell file through the phase assembly
- *(config)* parse and merge [[plugin]], refusing a second terminal claimant at load
- *(shell)* model functions and hooks as data, substituting declared values
- *(shell)* model aliases as data, single-quoted so every body survives exactly
- *(config)* declare PATH entries in a [path] section and place them in the zshenv fragment
- *(env-guard)* read a directory-gated search-list assignment and a zsh PATH removal
- *(shell)* place declared [[env]] variables in native startup files by kind

### Fixed

- *(journal)* remove only directories a write can show it made
- *(journal)* journal a write's temp file and parents before staging them
- *(rm)* claim the machine copy apply creates for a tracked target
- *(env_guard)* judge whole argument words and every relocating name in a command line
- *(plan)* bound tracked agreements in the fingerprint cache and forget untracked ones
- *(sync)* push nothing and exit pending when a declined sync leaves a carry undone
- *(adopt)* hand a tree back whole and never copy into a tree's root
- *(shell)* unexport the history parameters a parent exported
- *(shell)* refuse a leading + in an alias name, which zsh reads as an option
- *(path)* end a [path] block that closes on a gated line with a line that succeeds
- *(shell)* plan a fragment no variable lands in any more as empty
- *(env-guard)* refuse a location inside bx's fragment directory
- *(plan)* refuse writes beneath a declared ancestor that denies its owner search
- *(journal)* pass a directory's prior to NewEntry::new and drop forgotten entries deliberately
- *(config)* walk up from the state directory by handle so a deep one does not exceed PATH_MAX
- *(fs)* offer only remedies the parser accepts for an unquoted mode
- *(state)* withdraw a refused re-record to the entry it replaced
- *(ledger)* bound the restore read by its recorded length, and deduplicate stored created dirs
- *(state)* read a state file only if it is a regular file, and only up to a bound
- *(config)* resolve a .. after a symlink physically when judging the state directory ([#74](https://github.com/getkono/bx/pull/74))
- *(config)* name the toggle to remove when no answer can clear a same-layer clash ([#52](https://github.com/getkono/bx/pull/52))
- *(config)* refuse a rooted value text in a file body whatever its kind ([#69](https://github.com/getkono/bx/pull/69))
- *(config)* refuse a state directory inside the repo by identity, not only spelling ([#70](https://github.com/getkono/bx/pull/70))

### Other

- Update README with project status
- *(journal)* say which directories a rollback and a refused write remove
- *(recover)* pin that a rollback leaves directories bx cannot show it made
- *(journal)* say an intent names its temp file and parents before they exist
- *(fs)* pin the chosen temp name, the pre-stage refusals and the claim check
- merge master into the tracked backfill claim
- *(rm)* say which tracked machine copies bx claims and why the agreement stays out of the ledger
- *(rm)* remove a tracked tree apply created on a fresh machine
- *(acceptance)* drop the lock-file seed now that rm removes it
- merge master into the command-line and options kinds
- *(invariants)* name the command-line and options kinds among the root-free kinds
- *(readme)* list the command-line and options kinds the guard judges
- Merge pull request #110 from getkono/chore/36-add-bx-doctor-s-tenth-check
- Merge pull request #104 from getkono/chore/32-add-track-mode-behavior-bare-apply
- merge master's activation wiring into track mode
- *(plan)* pin tracked conflicts on unusable directories and unshowable diffs
- *(config)* say what direction = "track" does now
- merge master's git externals into the tree target
- *(config)* pin a local.toml tree expanding against the config repo
- *(config)* pin tree parsing, expansion, overrides and apply convergence
- Merge pull request #94 from getkono/chore/26-add-a-closed-six-key-four
- merge master's declared optional sources into the declared keybindings
- *(config)* drop the Interactive::keybindings getter nothing calls
- merge master's symlink bodies into the declared keybindings
- *(plan)* show declared keybindings reaching the interactive file, settling, and restoring
- merge master's declared functions into the unified history and shell options
- merge master into the unified history and shell options
- *(config)* pin the key-by-key merge of history and shell options across layers
- Merge pull request #88 from getkono/feat/80-wire-plugin-phase-assembly
- *(shell)* describe the interactive file's env-phase judgement and why plugins take no when
- *(shell)* say a function body is a template bx substitutes declared values into
- *(shell)* scope invariant 2 to bx-derived content, not transported function bodies
- *(shell)* hold declared functions to their acceptance in real zsh
- *(config)* state the order aliases are listed in, table by first appearance
- merge master (when-gated env) into the [path] branch
- *(env-guard)* pin that a removal forgets PATH's value as one string
- *(shell)* pin [path] placement, idempotence, additivity and reference order end to end
- *(env-guard)* run the [path] lines bx writes in zsh and hold them to the declared order
- *(env-guard)* know the [path] parser's import of the name predicate
- *(config)* check an [[env]] name with the guard's own predicate
- merge master (age secrets) into the env placement branch
- *(shell)* pin env placement, region ownership and reversal end to end
- Merge pull request #66 from getkono/chore/43-unblock-body-dir-in-plan-decide
- Merge branch 'master' into chore/43-unblock-body-dir-in-plan-decide
- *(env_guard)* hold the anchor exemption's premise to no generated fragment, not no caller
- Merge branch 'master' into feat/11-a7-plan-and-apply
- let the runner build the foreign-uid user-namespace test scenarios
- merge #8 @a3d7321 into A6 journal and recovery
- merge feat/a4-state-directory into the atomic-write branch
- *(state)* reach tighten's failure to examine what a linked directory names
- *(fs)* name the lock file's body as the one write that is not atomic
- *(config)* fail an unconstructible EACCES case unless its skip is asked for by name ([#72](https://github.com/getkono/bx/pull/72))
- *(release)* assign BX_BUILD_SHA before exporting it ([#71](https://github.com/getkono/bx/pull/71))
- merge the path-answer-in-file fix
- *(config)* mark the invalid-field examples as illustrative, not exhaustive
- merge the base's configuration-model review notes into the layered config
