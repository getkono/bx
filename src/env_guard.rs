//! The one rule that keeps bx from breaking the tools it manages.
//!
//! bx *may* write an environment variable that is a tool's own documented
//! configuration interface, but only a variable in bx's emit table, which grows
//! with the generators that need it — `SCCACHE_CACHE_SIZE` and `RUSTC_WRAPPER`
//! are the motivating cases, since sccache is configured entirely by environment.
//!
//! bx *may never* write a variable that moves a tool's config, data, or cache
//! **outside a root the configuration declares**. Doing so makes the tool
//! depend on bx having run: open a shell that bx did not initialise — a login
//! shell, a `systemd-run` unit, an SSH command, a container — and the tool
//! silently reads a different directory. Inside a declared root the user has
//! said where those directories live and has accepted that consequence, which
//! is why a machine that puts its toolchain caches on a scratch mount is a
//! configuration bx serves rather than one it refuses.
//!
//! A tool-read location must lie **strictly beneath** a declared root, never at
//! one, because a tool may derive a directory beside its own — uv puts
//! executables in `$XDG_DATA_HOME/../bin`. That bound is **one level**, and the
//! guard claims no more: an approved value's parent is inside a declared root,
//! its grandparent need not be, and a tool deriving a path two or more levels
//! above its value is not modelled. bx knows of none.
//! [`Reason::DeclaredRootItself`] is where the bound and its consequences are
//! written out.
//!
//! bx *may never* point a tool at a directory **bx itself owns**, and that one
//! is unconditional: it holds inside a declared root too, because bx's state
//! directory holds the record that makes an uninstall exact, and a tool writing
//! among those files would make `bx rm` destructive. [`RootSet::owns`] is that
//! exclusion, and it is checked before containment.
//!
//! **A fragment may set only a variable bx knows how to judge.** [`EMITTABLE`](table::EMITTABLE)
//! is the table of every name bx may generate, and it says what each one holds
//! — a [`Kind`]: a location, a list of locations, an anchor, a program, a
//! search list, a socket, or a setting.
//! The value is judged for what the name holds. Every name the table does not
//! list is refused as [`Reason::NotEmittable`], whatever its value.
//!
//! The name space is closed on purpose. A value alone cannot say what it is:
//! `EDITOR=nvim` names a program found through `PATH`, and `GIT_DIR=evil` names
//! a directory relative to wherever the shell happens to be. And the set of
//! variables some tool reads as a location is open-ended: every earlier guard
//! that judged by a list of location names, or by whether a value looked like
//! a path, approved a tool it had not heard of. The guard judges only what bx
//! generates, so the table grows with the generators and with nothing else.
//! [`check`] is the verdict. Declare no root — `RootSet::strict`, which is
//! what the test-only `scan` uses — and no location, no list of locations and no anchor
//! may be set at all. A program, a search list and a socket say what a tool
//! runs, where it looks and what it connects to rather than where its files
//! live, so they move nothing and need no root — but no more than any other
//! kind may they **point inside** a directory bx owns
//! ([`Reason::BxOwnedDirectory`], [`Reason::InsideConfigRepo`]), which
//! `refuses_unanchored` asks of every path-shaped value whatever its kind. A
//! setting names no path at all, and is held to no path check.
//!
//! The **containing** check is the one that does not generalise, and
//! deliberately. The criterion is **whether the tool clears what it is given**:
//! a tool empties its own cache or data directory, and everything beneath it
//! goes too, so a kind naming a directory the tool *owns* can take bx's state
//! down with it. A kind the tool only reads from cannot. That is the test to
//! apply to a new kind — not whether its value happens to name a directory,
//! which a search list's entries do: `PATH=/usr/bin:/opt/x/bin` is a list of
//! directories and is approved, because nothing empties a `PATH` entry.
//!
//! So the check is asked of a location and of a list of locations, and of
//! nothing else — not of a program, a search list or a socket, none of which
//! its tool clears, and not of an anchor, which [`Kind::Anchor`] exempts
//! because bx has found no tool that reads one at all.
//! `a_location_may_not_contain_bxs_own_directories` asserts both halves,
//! allowing an `EDITOR`, a `PATH` and an `SSH_AUTH_SOCK` that contain bx's
//! directories on the same lines as it refuses a `CARGO_HOME` that does.
//!
//! The guard **fails closed by shape** as well. It does not model shell syntax
//! and approve whatever it does not recognise: it reads a fragment against a
//! small grammar — blank lines, comments, `NAME=VALUE` or
//! `export NAME=VALUE` with a restricted value, the `if TEST; then` / `fi`
//! pair a runtime `when` condition renders, and two one-line zsh forms
//! `[path]` needs, a search-list assignment gated on `[[ -d WORD ]] && ` and
//! `path=(${path:#WORD})` — and refuses **every** line that
//! is not one of those, whatever the line mentions and whether or not it
//! relocates anything. Every multi-line construct but that block is refused at
//! its first line, because no line the grammar accepts can leave a quote, a
//! continuation or a heredoc open; the block's assignments are judged as if
//! the condition were not there. [`scan_with`] states the grammar.
//!
//! This module is that rule as code. Every environment fragment bx generates is
//! run through [`scan_with`] before it is written, and the check is covered by
//! tests rather than left to review. Generated shell content that is **not** an
//! environment fragment, and is not a tool's cached activation output, carries
//! no environment assignment at all, which is what leaves nothing outside the
//! guard's reach.
//!
//! **A tool's cached activation output** is the one exception, and the rule it
//! is held to is the relocation rule itself rather than the fragment grammar.
//! It is the tool's own shell code — `mise activate zsh`, `starship init zsh`,
//! `fzf --zsh` — full of functions, hooks and variables of its own
//! (`MISE_SHELL`, a function's locals, ZLE's `BUFFER`), none of which moves a
//! file. So it is searched, not parsed: every occurrence of a name
//! [`is_relocating`] knows, anywhere in the output, that stands in an
//! assigning position — `NAME=`, `NAME+=`, an operand of `export`, `typeset`,
//! `declare`, `local`, `readonly`, `read` and the other builtins that assign
//! their operands, an arithmetic assignment, `${NAME=…}`, and every quoted or
//! indirect form that could assign it — is judged by [`check`] when its value
//! is a readable literal, and refused as [`Reason::Unreadable`] when it is
//! not. An output with any refusal is not written. Every other line passes
//! untouched, and what the output's code runs later — `eval "$(mise
//! hook-env)"` — is the tool's own behaviour at runtime, outside what bx
//! emits. [`crate::shell::activation::relocations`] is that search.
//!
//! Two files are under the no-assignment rule above. The first is the
//! shell-init snippet: fixed text that sets no environment variable outside
//! bx's own `BX_` namespace, and gets every other variable by sourcing a
//! guarded environment fragment.
//! `tests::the_init_snippet_is_not_an_environment_fragment` holds the
//! snippet's bytes to the rule rather than assuming it, and holds the bytes
//! the repository actually keeps — `bench/fixtures/bx/bx-init.zsh`, the
//! snippet's only copy, since no bx generator emits it. The zsh update
//! prompt is the second: it assigns only its
//! locals, `BX_` names and zsh's `precmd_functions` hook array, and
//! `tests::the_update_prompt_is_not_an_environment_fragment` holds
//! [`crate::shell::update_prompt::ZSH`] to that. Nothing holds a *third*
//! non-fragment file to the rule, so the generator that adds one carries the
//! proof of its own bytes with it.
//!
//! **Reasons, and the one assertion.** Everything this module can be given —
//! any name, any value, any fragment, well formed or not — comes back as a
//! [`Verdict`], and every rejection as a [`Reason`]. The guard never panics on
//! input, because its whole job is to have an answer for input it does not
//! like. There is exactly one `debug_assert!`, in `judge`, and it is not an
//! input check: it states a **theorem about this module's own code** — that
//! once every `:`-entry of a location has been judged, the whole value the tool
//! reads lies strictly beneath a declared root as well. No value can falsify
//! it. Only an edit to the code it rests on can: the entry rules in `judge`,
//! [`RootSet::contains`], or [`crate::paths::normalize`], which decides what a
//! path's components are. It is written as an assertion rather than as a
//! [`Reason`] precisely because a [`Reason`] there could never be returned,
//! which is a branch no test can reach and no mutant can kill — the defect it
//! replaced (#47 round 3). Being a `debug_assert!` it does nothing in a release
//! build — the compiler keeps the code and then eliminates it, so a release
//! binary pays nothing for it; what it buys is that every test in the suite,
//! not only the one that targets the property, checks it on every location it
//! judges.
//!
//! **Before adding a second one**, ask which of the two it is. A statement
//! about a *value* is a [`Reason`], always, even when it seems impossible —
//! values come from a user's configuration and the guard's own reading of a
//! shell fragment, and neither is a place to be certain. That half of the rule
//! is load-bearing, not a matter of taste: a statement about a value written as
//! a `debug_assert!` would **fail open in the shipped binary** on exactly the
//! input it was meant to catch, approving a relocation instead of refusing it,
//! and the tests would not show it because they run with assertions on. A
//! statement about *this module's internal consistency*, which no input can
//! reach and whose falsification would be a bug in bx, may be a
//! `debug_assert!` — and should be, rather than an unreachable [`Reason`] that
//! reads like a verdict. Pair it with a test that pins the same property
//! through the public API, as
//! `every_entry_beneath_a_root_leaves_the_whole_value_beneath_one` does, so the
//! property is still pinned where assertions do nothing.

use crate::lexical::is_variable_name;

#[cfg(test)]
mod fixtures;
mod lex;
mod reason;
mod refuse;
mod roots;
mod scope;
mod table;
#[cfg(test)]
mod tests;

use lex::{BLANKS, SEARCH_PATH, Statement, read_value, readable, statement};
use refuse::judge;
use scope::Scope;
use table::{Kind, emittable, is_reserved};

pub use reason::{Reason, Verdict, Violation};
pub use refuse::refuses_bx_location;
pub use roots::RootSet;
pub use table::is_relocating;

/// Whether bx may assign `value` to `name`, given the roots `roots` declares.
///
/// `value` is everything written after `NAME=`, and is read by the same value
/// grammar [`scan_with`] reads a line with — so a value that is not exactly one
/// value in that grammar, optionally followed by a comment, is refused for
/// every variable, and a `name` that is not a variable name is refused too.
/// Past that, `name` must be one bx generates, and the value is judged for what
/// that name holds, as [`scan_with`] states.
///
/// This is the same function [`scan_with`] calls for every assignment it reads,
/// so the two cannot disagree about one. No reference resolves here except
/// `$HOME` and `~`: `check` judges one assignment in isolation and has no
/// fragment to learn from.
///
/// The assignment is judged as **exported**. There is no line to read an
/// `export` from, and the exported reading is the stricter one: it is the one
/// in which [`Kind::Anchor`]'s exemption does not apply, so a verdict of
/// [`Verdict::Allowed`] here holds wherever the assignment is written.
#[must_use]
pub fn check(name: &str, value: &str, roots: &RootSet) -> Verdict {
    match evaluate(name, value, true, &Scope::default(), roots).reason {
        None => Verdict::Allowed,
        Some(reason) => Verdict::Violation(Violation {
            line: 0,
            name: name.to_string(),
            value: value.to_string(),
            reason,
        }),
    }
}

/// Find every forbidden assignment in a block of shell bx is about to write,
/// judged against the roots `roots` declares. A fragment is approved exactly
/// when this returns nothing.
///
/// **The grammar.** The content is split at `\n`, and every line must be one
/// of:
///
/// * **blank** — spaces and tabs only;
/// * **a comment** — optional blanks, `#`, then anything without a control
///   character;
/// * **an assignment** — optional blanks, optionally `export` and blanks, then
///   `NAME=VALUE`, optionally followed by blanks and a `#` comment. `NAME` is
///   `[A-Za-z_][A-Za-z0-9_]*`. `VALUE` is exactly one of:
///   * nothing;
///   * `'…'`, one single-quoted string of printable ASCII, taken literally;
///   * `"…"`, one double-quoted string of printable ASCII other than `\`,
///     `` ` `` and `!`, in which `$` may only begin a reference;
///   * a bare word of `A-Z a-z 0-9 _ . / , : @ % + -` and references, which
///     may begin with `~` alone or `~/`.
///
///   A reference is `${NAME}`, or `$NAME` followed by `/` or by the end of the
///   value's text. zsh reads on past an unbraced name — `$NAME:h` is a
///   modifier and `$NAME[1]` a subscript — so nothing else may follow one;
/// * **a guarded block's opener** — optional blanks, then `if TEST; then`
///   where `TEST` is byte for byte one a runtime `when` condition renders
///   ([`crate::config::when::is_opener`]): a fixed option or `SSH_CONNECTION`
///   test, or a set-or-equals test on one variable name against a
///   double-quoted literal with no `$`, `` ` ``, `\`, `"` or `!`, in zsh's
///   words or bash's, bash's login test optionally joined by `&&` to one
///   more of them. It reads a variable and assigns none. Not in an `environment.d` fragment, which
///   runs no test, and not inside another block;
/// * **a guarded block's close** — optional blanks, then `fi`, closing the one
///   open block. A `fi` with no block open is refused, and so is a block left
///   open at the end, at the line that opened it;
/// * **a gated assignment** — optional blanks, `[[ -d WORD ]] && `, then an
///   assignment as above to a name the emit table records as a **search
///   list**. `WORD` is one bare word with no `~`. The shell makes the
///   assignment only when `WORD` is a directory, and the guard judges it
///   either way: every entry either outcome leaves in the list is one it
///   judged, which is what a search list is judged by. Its value as one
///   string is known in neither case, so a later reference to it by another
///   name is [`Reason::UnreadableReference`]; its own next extension still
///   reads it.
/// * **a removal** — optional blanks, then exactly zsh's
///   `path=(${path:#WORD})` or exactly bash's
///   `PATH=:${PATH//:/::}:; PATH=${PATH//":WORD:"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}`,
///   `WORD` as in a gated assignment, and in bash's shape not ending in an
///   unbraced reference, which zsh would read the `:` after as a modifier on.
///   Either shell takes every entry of `PATH` that is `WORD` out, and nothing
///   else changes, so nothing it can do is a relocation; `WORD` must still
///   resolve, because a reference to nothing would leave a word that names
///   some other entry.
///
/// The last two are read only by [`scan_with`]: bx writes them only into a
/// fragment a shell sources, and an `environment.d` fragment, read by
/// [`scan_exported`], refuses both as [`Reason::Unreadable`].
///
/// An assignment inside a block is judged exactly as one outside it, so a
/// condition hides nothing from the guard. After the block closes, every name
/// it assigned may hold its old value or its new one, so a later reference to
/// one is [`Reason::UnreadableReference`].
///
/// **Everything else is refused**, as [`Reason::Unreadable`] or
/// [`Reason::MultipleAssignments`], whatever it mentions and whether or not it
/// relocates anything. That includes every keyword but `export` and the
/// block's own `if … then` and `fi` (`declare`,
/// `typeset`, `local`, `readonly`, `unset`, `set`, `alias`, `eval`, `source`,
/// `.`, `for`, `read`, `printf`), `export` itself quoted or escaped, `export`
/// with no value, a backslash, a quote that does not close on its line, mixed
/// quoting, command, arithmetic and brace substitution, a `${NAME…}` operator,
/// a special parameter (`$@ $* $# $? $! $$ $- $0`…), a glob, `;`, `|`, an `&&`
/// or a `[[ … ]]` outside a gated assignment's one shape, a redirection or
/// heredoc, `+=`, an array or subscript outside a removal's one shape, and in
/// neither shape any word but a bare one: a `=` or `~` anywhere
/// but where listed (so zsh's `=cmd` and a `~` after `:` never occur), and any
/// control character. Because no accepted line can leave a quote, a
/// continuation or a heredoc open, every accepted line begins where a shell
/// begins a statement, and every multi-line construct but a guarded block is
/// refused at its first line.
///
/// A name the shell manages itself — `HOME`, `RANDOM`, `LINENO`, zsh's `path`
/// and the rest of `SHELL_NAMES` — or acts on when it is assigned —
/// `HISTFILESIZE` and the rest of `ACTS_ON_ASSIGNMENT` — may not be
/// assigned, and is refused as [`Reason::ReservedName`]. Nor may it be
/// referred to, with one exception: `$HOME`, and the `~` that stands for it,
/// resolve against the root set's home ([`Scope::lookup`]). That exception is
/// the mechanism every value written against the home is judged through, and
/// it is exactly why `HOME` may not be *assigned*: a fragment that moved it
/// would move `~` with it, and the guard would judge against a home no shell
/// will have.
///
/// **What is judged.** Every accepted assignment, exported or not, since
/// assigning a name the environment already exports changes what every child
/// sees. A name [`EMITTABLE`](table::EMITTABLE) does not list is [`Reason::NotEmittable`]. For
/// one it lists, the value as a shell gives it is judged for the [`Kind`] the
/// table records:
///
/// * a **location** needs a declared root, and every `:`-entry must be
///   absolute, outside bx's own directories and strictly beneath a root, never
///   a root itself ([`Reason::DeclaredRootItself`]). The whole value, read as
///   one path, is judged for bx's own directories too; being strictly beneath
///   a root then follows from the entries and is not asked again
///   ([`Reason::DeclaredRootItself`] says why). Strictly beneath covers the one
///   level a tool may derive above its value, and no more;
/// * a **list of locations** is judged the same way entry by entry, and not
///   as a whole;
/// * an **anchor** is judged as a location's one path, except that it may
///   contain bx's own directories and may be a root;
/// * a **program** is one absolute path outside bx's own directories, or one
///   bare command name;
/// * a **command line** begins with one program, and the rest is judged as
///   **options** are: nothing a later shell expands, no path inside bx's own
///   directories, and no assignment to a relocating name;
/// * a **search list** has every entry absolute and outside bx's own
///   directories, its inherited self standing in for itself;
/// * a **socket** is an absolute path outside bx's own directories;
/// * a **setting** holds a value of its [`Setting`](table::Setting) shape.
///
/// No path of any kind may have a `..` component ([`Reason::ParentComponent`]),
/// hold a character other than an ASCII letter or digit, `.`, `_`, `-`, `+`
/// and `/` — with `:` only between a list's entries —
/// ([`Reason::UnlistedCharacter`]), or lie inside bx's state directory
/// ([`Reason::BxOwnedDirectory`]) or its config repo
/// ([`Reason::InsideConfigRepo`]), checked in that order and before any root.
/// No location or list of locations may contain either of bx's directories
/// ([`Reason::ContainsBxDirectory`]), or be a root itself
/// ([`Reason::DeclaredRootItself`]); an anchor may. The characters are an allowlist because
/// the guard cannot know which tool reads which other character its own way.
/// A value that does not resolve cannot be shown to be any of those, and is
/// refused for why it does not.
///
/// **What is learned.** Every accepted assignment — exported or not, emittable
/// or not — is recorded, **expanded**, so a later line may refer to it: the
/// generated `.zshenv` is written in terms of a declared root variable, and a
/// guard that could not resolve `$SCRATCH_HOME` would either reject every
/// fragment bx generates or check nothing at all. A reference to a variable
/// assigned *later* is unresolved, because a shell would not have it either.
/// `~` and `$HOME` resolve against the root set's home, which a fragment cannot
/// change because it cannot assign `HOME`. After a refused line nothing is
/// known — such a line could have assigned or unset anything — so every later
/// reference is [`Reason::UnreadableReference`].
///
/// **Where bx's directories are.** Where the root set says, and nowhere a
/// fragment could move them: `XDG_STATE_HOME` and `XDG_CONFIG_HOME`, which bx
/// reads to find them, are not in the emit table, so a fragment that sets
/// either is refused.
///
/// **Purity.** Nothing is read from the process environment and nothing is
/// read from disk. `$HOME` comes from `roots`, never from [`std::env`], and the
/// roots are held in declaration order, so this is a pure function of
/// `(content, roots)`. That is what lets `plan` call it without becoming
/// machine-dependent (invariant 3).
///
/// **What is out of scope.** The shell the fragment is sourced into: an alias,
/// a function or an option the user's own startup files set before bx's
/// fragment runs is the user's configuration, not bx's output. The grammar is
/// checked against bash and zsh.
#[must_use]
pub fn scan_with(content: &str, roots: &RootSet) -> Vec<Violation> {
    pass(content, roots, false).0
}

/// [`scan_with`] for a fragment whose every assignment is exported although
/// no line says `export`: an `environment.d` fragment, which the systemd user
/// manager reads into the environment of everything it starts.
///
/// The grammar and the judgement are [`scan_with`]'s. Only whether a line is
/// exported differs, and that is what [`Kind::Anchor`]'s one exemption turns
/// on.
#[must_use]
pub fn scan_exported(content: &str, roots: &RootSet) -> Vec<Violation> {
    pass(content, roots, true).0
}

/// Find every forbidden assignment in a block of shell bx is about to write.
///
/// Equivalent to [`scan_with`] against `RootSet::strict`: with no root
/// declared, every location is a violation, and a program, a search list or a
/// socket may not pass through a default state directory under any home. This
/// is the check for a caller that has no configuration to consult, and it is
/// why it needs no home. Every shipped caller has one, so only tests call it.
#[cfg(test)]
#[must_use]
pub fn scan(content: &str) -> Vec<Violation> {
    scan_with(content, &RootSet::strict())
}

/// [`scan_with`]'s verdict, and what the fragment was learned to assign: one
/// walk over `content`, judging each line against `roots` and what the lines
/// before it assigned, and learning from it.
///
/// `every_exported` judges every assignment as exported, whether or not its
/// line says so — the reading of an `environment.d` fragment.
fn pass(content: &str, roots: &RootSet, every_exported: bool) -> (Vec<Violation>, Scope) {
    let mut scope = Scope::default();
    let mut found = Vec::new();
    // The open guarded block: the line that opened it, and every name
    // assigned inside it.
    let mut block: Option<(usize, Vec<String>)> = None;
    for (idx, line) in content.split('\n').enumerate() {
        let violation = |name: &str, value: &str, reason| Violation {
            line: idx + 1,
            name: name.to_string(),
            value: value.to_string(),
            reason,
        };
        let mut refuse = |scope: &mut Scope| {
            found.push(violation("", line.trim_matches(BLANKS), Reason::Unreadable));
            scope.forget_everything();
        };
        match readable(statement(line), every_exported) {
            Statement::Nothing => {}
            // `environment.d` runs no test, and a block does not nest.
            Statement::Open if every_exported || block.is_some() => refuse(&mut scope),
            Statement::Open => block = Some((idx, Vec::new())),
            Statement::Close => match block.take() {
                // After the block a name it assigned holds either value, so a
                // later reference to it cannot be judged.
                Some((_, assigned)) => scope.forget_conditional(&assigned),
                None => refuse(&mut scope),
            },
            Statement::Refused => refuse(&mut scope),
            Statement::Assign {
                name,
                value,
                exported,
            } => {
                let judged = evaluate(name, value, exported || every_exported, &scope, roots);
                if let Some(reason) = judged.reason {
                    found.push(violation(name, value, reason));
                }
                scope.learn(name, judged);
                if let Some((_, assigned)) = block.as_mut() {
                    assigned.push(name.to_string());
                }
            }
            Statement::Gated {
                name,
                value,
                exported,
                ..
            } => {
                let judged = evaluate(name, value, exported, &scope, roots);
                if let Some(reason) = judged.reason {
                    found.push(violation(name, value, reason));
                }
                scope.learn(name, judged);
                scope.perhaps(name);
                if let Some((_, assigned)) = block.as_mut() {
                    assigned.push(name.to_string());
                }
            }
            Statement::Removal { word } => {
                // Only an entry the guard can name is taken out: a reference
                // to nothing would leave a pattern that strips some other
                // entry instead.
                if let Err(reason) = word.resolve(&scope, roots.home()) {
                    found.push(violation(SEARCH_PATH, word.text, reason));
                }
                scope.narrowed(SEARCH_PATH);
                if let Some((_, assigned)) = block.as_mut() {
                    assigned.push(SEARCH_PATH.to_string());
                }
            }
        }
    }
    // A block left open swallows the rest of the file into its condition,
    // and is refused at the line that opened it.
    if let Some((opened, _)) = block {
        let line = content.split('\n').nth(opened).unwrap_or_default();
        found.push(Violation {
            line: opened + 1,
            name: String::new(),
            value: line.trim_matches(BLANKS).to_string(),
            reason: Reason::Unreadable,
        });
        scope.forget_everything();
    }
    (found, scope)
}

/// What [`evaluate`] found: the verdict, and what the value expands to.
struct Judged {
    /// Why the assignment may not be written, or `None` if it may.
    reason: Option<Reason>,
    /// The value a shell would give the name, or why it cannot be known. This
    /// is what a later reference to the name resolves to.
    resolved: Result<String, Reason>,
    /// For a search list, the value with each unassigned reference to its own
    /// name standing for the inherited list. This is what the list's next
    /// reference to itself extends, and `None` for every other kind.
    extended: Option<String>,
}

/// The verdict on `name = value`, for [`check`] and [`scan_with`] alike.
///
/// `exported` is whether the assignment reaches the environment of what the
/// shell starts, which only [`Kind::Anchor`]'s judgement turns on.
fn evaluate(name: &str, value: &str, exported: bool, scope: &Scope, roots: &RootSet) -> Judged {
    let refused = |reason| Judged {
        reason: Some(reason),
        resolved: Err(reason),
        extended: None,
    };
    // The shape is read for every variable: a line the grammar does not read
    // may do anything, whatever its first name is.
    if !is_variable_name(name) {
        return refused(Reason::Unreadable);
    }
    let word = match read_value(value) {
        Ok(word) => word,
        Err(reason) => return refused(reason),
    };
    if is_reserved(name) {
        return refused(Reason::ReservedName);
    }
    let resolved = word.resolve(scope, roots.home());
    let kind = emittable(name);
    // A search list is judged with its own inherited self standing in for
    // itself, which no other name's reference to it may do.
    let extended =
        (kind == Some(Kind::SearchList)).then(|| word.expand(scope, roots.home(), Some(name)));
    let reason = match kind {
        None => Some(Reason::NotEmittable),
        Some(kind) => judge(
            kind,
            exported,
            extended.as_ref().unwrap_or(&resolved),
            roots,
        ),
    };
    Judged {
        reason,
        resolved,
        extended: extended.and_then(Result::ok),
    }
}
