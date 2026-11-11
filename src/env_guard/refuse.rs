//! The judgement of a resolved value for what its name holds: each kind's
//! refusals, and the path checks every path-shaped value is put through.

use std::path::{Component, Path};

use super::lex::BLANKS;
use super::reason::Reason;
use super::roots::RootSet;
use super::scope::INHERITED;
use super::table::{Kind, is_bare_word, is_relocating, is_word_char};
use crate::paths;

/// Why `resolved` may not be given to a variable of `kind`, or `None` if it
/// may. For a search list, `resolved` holds [`INHERITED`] wherever the list
/// refers to what the shell inherited.
pub(super) fn judge(
    kind: Kind,
    exported: bool,
    resolved: &Result<String, Reason>,
    roots: &RootSet,
) -> Option<Reason> {
    let anchored = |entry: &str| refuses_unanchored(entry, None, roots);
    match kind {
        Kind::SearchList => within(resolved, |list| {
            list.split(':')
                .filter(|entry| *entry != INHERITED)
                .find_map(anchored)
        }),
        // A set with no admissible root permits no location, whatever it is.
        Kind::Location | Kind::LocationList => roots.refuses_everything().or_else(|| {
            within(resolved, |value| {
                // A location's tool reads the whole value as one path, whose
                // `:` its entries are judged apart at. A list's tool reads
                // only the entries.
                let whole = (kind == Kind::Location).then_some(value);
                // Every entry is judged for every other reason before any is
                // judged for being a root itself, so a root earlier in the
                // list does not hide a later entry's reason.
                let reason = value
                    .split(':')
                    .find_map(|entry| refuses_entry_placement(entry, None, roots))
                    // Once every entry has passed, the whole value begins with
                    // its first absolute entry and holds only allowed
                    // characters and `:`. Merging entries at a `:` makes a
                    // component holding `:`, which completes a match no entry
                    // made only with a directory whose own path holds a `:`.
                    // The home, and so bx's directories under it, may: with
                    // `HOME=<root>/x:<root>/y`, each entry of
                    // `CARGO_HOME=<root>/x:<root>/y/.local/state` passes, and
                    // the whole value, the path cargo reads, contains bx's
                    // state directory. That reason outranks an entry that is a
                    // root itself, as it does on one path.
                    .or_else(|| whole.and_then(|value| refuses_entry_bx(value, Some(':'), roots)))
                    .or_else(|| {
                        value
                            .split(':')
                            .find_map(|entry| refuses_entry_at_root(entry, roots))
                    });
                // There is no whole-value placement check after this, because
                // one could not refuse anything. Every entry now
                // lies strictly beneath a root, so the first entry's parent is
                // inside one; the whole value extends that parent's components,
                // so the whole value and its own parent are inside that root
                // too, and neither `refuses_entry_outside` nor
                // `refuses_entry_at_root` can fire on it. A check that can
                // never refuse is an equivalent mutant no test can catch, so
                // the property is asserted where a future change to the entry
                // rules would trip it, and pinned by
                // `every_entry_beneath_a_root_leaves_the_whole_value_beneath_one`.
                //
                // This is the module's only assertion, and the only place it
                // may be one: it says nothing about the value, which is a
                // `Reason`'s job, and everything about this module's own
                // consistency, which no input can reach. The module docs state
                // the policy, and what to do before adding a second.
                debug_assert!(
                    reason.is_some()
                        || whole.is_none_or(|value| {
                            refuses_entry_outside(value, roots).is_none()
                                && refuses_entry_at_root(value, roots).is_none()
                        }),
                    "a location whose entries all lie strictly beneath a declared root \
                     has a whole value that lies strictly beneath one too"
                );
                reason
            })
        }),
        // An anchor is one directory bx has found no tool to read, so none is
        // known to clear it or to write beside it — while it stays out of the
        // environment. Exported, every tool can read it.
        Kind::Anchor => roots
            .refuses_everything()
            .or_else(|| within(resolved, |value| refuses_anchor(value, exported, roots))),
        Kind::Program => within(resolved, |value| refuses_program(value, roots)),
        Kind::CommandLine => within(resolved, |value| refuses_command_line(value, roots)),
        Kind::Arguments => within(resolved, |value| refuses_arguments(value, roots)),
        Kind::Socket => within(resolved, anchored),
        Kind::Setting(setting) => within(resolved, |value| {
            (!setting.admits(value)).then_some(Reason::NotASetting)
        }),
    }
}

/// `judge` applied to a value that resolved, or why it did not.
fn within(
    resolved: &Result<String, Reason>,
    judge: impl FnOnce(&str) -> Option<Reason>,
) -> Option<Reason> {
    match resolved {
        Ok(value) => judge(value),
        Err(reason) => Some(*reason),
    }
}

/// Why `value` is not one program bx may name, or `None` if it is.
///
/// A value with a `/` in it and nothing but word characters beside is a path,
/// which must be absolute and outside bx's own directories. Anything else must
/// be a bare command name.
fn refuses_program(value: &str, roots: &RootSet) -> Option<Reason> {
    if value.contains('/') && value.chars().all(|c| c == '/' || is_word_char(c)) {
        refuses_unanchored(value, None, roots)
    } else if is_bare_word(value) {
        None
    } else {
        Some(Reason::NotAProgram)
    }
}

/// Why `value` is not a command line bx may name, or `None` if it is.
///
/// Its first word, up to the first blank, is one program ([`refuses_program`]),
/// and what follows is judged as [`refuses_arguments`] judges options. A first
/// word that is not one program is [`Reason::NotACommandLine`], whose sentence
/// does not tell the user to drop the arguments a command line may have.
fn refuses_command_line(value: &str, roots: &RootSet) -> Option<Reason> {
    let (program, rest) = value.split_once(BLANKS).unwrap_or((value, ""));
    match refuses_program(program, roots) {
        Some(Reason::NotAProgram) => Some(Reason::NotACommandLine),
        Some(reason) => Some(reason),
        None => refuses_arguments(rest, roots),
    }
}

/// The characters that end a word of a command line as a shell splits it, or
/// that begin an assignment's value or a list's next entry, where a `~`
/// expands again.
const WORD_BREAKS: &str = " \t;|&<>()=:";

/// The characters that end a word of a command line as a shell splits it:
/// [`WORD_BREAKS`] but `=` and `:`, which a path's own directories may hold.
const COMMAND_BREAKS: &str = " \t;|&<>()";

/// The characters a shell expands in a path into names nothing judged.
const GLOBS: &str = "*?[]{}";

/// Why the words `text` holds may not be handed to a shell as a command line's
/// arguments, or `None` if they may.
///
/// No grammar is imposed on the words: every tool reads its own options its
/// own way. What is judged is only what could make one point inside a
/// directory bx owns, or relocate a tool's files, lexically and without
/// knowing the tool:
///
/// * a `$`, a backquote or a backslash is [`Reason::LaterExpansion`]: a later
///   shell substitutes, or unescapes, words nothing judged;
/// * quotes are dropped before anything is read, because a shell joins what
///   they hold to the word around them and never splits a word at one — so
///   `sh -c 'col -bx | bat'` is read as `sh -c col -bx | bat`, and
///   `/x/.local/state/b"x"` as the path it spells;
/// * each word, split at blanks, shell operators, `=` and `:`, that opens with
///   `~` or `~/` stands for a path under the home, and one that opens with
///   any other `~` for another user's home, which cannot be shown
///   ([`Reason::LaterExpansion`]); a word holding a `/` names the path from
///   that `/` on, so `-o/x/log` is read as `/x/log`. A path holding a glob or
///   a brace is [`Reason::LaterExpansion`], and any other path is judged by
///   [`refuses_bx_location`] alone. A relative path is relative to wherever
///   the tool runs, which no lexical check can know, and so is every bare
///   word; neither is refused;
/// * each whole word, split at blanks and shell operators alone, is judged
///   the same way from its first `/` or leading `~/`, because a path's own
///   directories may hold `=` or `:`: with the home `/tmp/a:b`, the pieces of
///   `/tmp/a:b/.local/state/bx/ledger` are `/tmp/a` and `b/…`, and only the
///   whole word shows it inside bx's state directory;
/// * any name a shell could assign — each run of ASCII letters, digits and
///   `_` — that [`is_relocating`] is [`Reason::RelocatingAssignment`],
///   wherever it stands and whatever follows it. A shell assigns a name
///   without an `=` too — `for HOME in …`, `read HOME`, `printf -v HOME` —
///   so `env XDG_CONFIG_HOME=/elsewhere nvim` and
///   `sh -c 'read HOME </x; export HOME; nvim'` cannot move what the guard
///   refuses to move in a fragment. A word that merely mentions such a name
///   is refused with them: no lexical check tells the two apart.
fn refuses_arguments(text: &str, roots: &RootSet) -> Option<Reason> {
    if text.contains(['$', '`', '\\']) {
        return Some(Reason::LaterExpansion);
    }
    let text: String = text.chars().filter(|c| !matches!(c, '\'' | '"')).collect();
    let pieces = text
        .split(|c| WORD_BREAKS.contains(c))
        .map(|piece| (piece, true));
    let words = text
        .split(|c| COMMAND_BREAKS.contains(c))
        .map(|word| (word, false));
    for (word, piece) in pieces.chain(words) {
        if let Some(reason) = refuses_argument_path(word, piece, roots) {
            return Some(reason);
        }
    }
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(is_relocating)
        .then_some(Reason::RelocatingAssignment)
}

/// Why the path one word of a command line names may not be handed to a
/// shell, or `None` if it may, as [`refuses_arguments`] reads it. `piece` says
/// whether the word was split at `=` and `:` too, where a `~` expands again,
/// so that any other `~` opening it is another user's home; a whole word
/// opening with such a `~` is read from its first `/`, as its pieces are.
fn refuses_argument_path(word: &str, piece: bool, roots: &RootSet) -> Option<Reason> {
    let path = match word.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => match roots.home() {
            Some(home) => format!("{}{rest}", home.display()),
            None => return Some(Reason::NoHome),
        },
        Some(_) if piece => return Some(Reason::LaterExpansion),
        _ => word[word.find('/')?..].to_string(),
    };
    if path.contains(|c| GLOBS.contains(c)) {
        return Some(Reason::LaterExpansion);
    }
    refuses_bx_location(Path::new(&path), roots)
}

/// Why one resolved entry of a location value may not be a relocation target,
/// for any reason but being a root itself ([`refuses_entry_at_root`]), or
/// `None` if it may. `separator` is the list separator it may still hold, as
/// [`refuses_unanchored`] reads it.
///
/// The order is part of the verdict. [`refuses_unanchored`] runs first, so a
/// path that is relative, climbs, or holds a character outside the allowlist
/// is refused for that before any reasoning about where it is: bx cannot read
/// such a value as a path at all. Inside bx's own directories comes next, then
/// containing them, then inside a root. Beneath one comes last, and `judge`
/// asks it of an entry only once every entry, and a location's whole value,
/// has been judged for bx's directories, so a root earlier in a list does not
/// hide a harder reason later in it or in the whole value.
fn refuses_entry_placement(path: &str, separator: Option<char>, roots: &RootSet) -> Option<Reason> {
    refuses_entry_bx(path, separator, roots).or_else(|| refuses_entry_outside(path, roots))
}

/// Every reason [`refuses_entry_placement`] gives before it reasons about the
/// roots: [`refuses_unanchored`], then containing bx's own directories.
fn refuses_entry_bx(path: &str, separator: Option<char>, roots: &RootSet) -> Option<Reason> {
    refuses_unanchored(path, separator, roots)
        // bx's directories outrank the roots in this direction too.
        .or_else(|| {
            roots
                .holds_bx_directory(Path::new(path))
                .then_some(Reason::ContainsBxDirectory)
        })
}

/// [`Reason::OutsideDeclaredRoots`] if `path` lies inside no declared root.
fn refuses_entry_outside(path: &str, roots: &RootSet) -> Option<Reason> {
    (!roots.contains(Path::new(path))).then_some(Reason::OutsideDeclaredRoots)
}

/// [`Reason::DeclaredRootItself`] if `path`, already inside a root, has a
/// parent in none: the path is a root itself.
fn refuses_entry_at_root(path: &str, roots: &RootSet) -> Option<Reason> {
    (!paths::normalize(Path::new(path))
        .parent()
        .is_some_and(|parent| roots.contains(parent)))
    .then_some(Reason::DeclaredRootItself)
}

/// Why a resolved [`Kind::Anchor`] may not be written, or `None` if it may:
/// every check [`refuses_entry_placement`] makes of one path, but containing
/// bx's own directories. A tool-read location written in terms of the anchor
/// is judged for that at its own line.
///
/// # The exemption holds only while the anchor is not exported
///
/// **What it was.** With home `/var/home/example` and a single `~` root,
/// `DATA_DIR=/var/home/example/.local/state` and `SCRATCH_HOME` with the same
/// value were both `Allowed`, while `UV_CACHE_DIR` with the *identical* value
/// is [`Reason::ContainsBxDirectory`]. Both approved values contain bx's
/// ledger, journal and fingerprints — the record invariant 4 rests on.
///
/// The exemption's premise is that **no tool reads an anchor**, and that is a
/// property of the *name*, which the guard enforces nothing about. Issue #45
/// already falsified it once: npm's `find-cache-dir` reads an exported
/// `CACHE_DIR`, which is why `CACHE_DIR` is a [`Kind::Location`] here and no
/// longer an anchor. `DATA_DIR` and `SCRATCH_HOME` are generic names carrying
/// the same unenforced premise.
///
/// **How it is closed.** The exemption is conditioned on the assignment **not
/// being exported**, which is what actually makes "no tool reads it" hold: an
/// unexported anchor stays in the shell that sourced the fragment, where only
/// the fragment's own later lines read it. An `exported` one reaches every
/// program the shell starts, so it is held to the containing check a location
/// is — [`Reason::ContainsBxDirectory`] — and keeps only the other half of
/// the exemption, being a root itself, since no tool is known to write beside
/// it. A line says `export` in a zsh fragment; every line of an
/// `environment.d` fragment is exported ([`scan_exported`](super::scan_exported)); and
/// [`check`](super::check), which has no line to read, judges as exported, the stricter reading.
///
/// It was closed by the change that gave `config::target::Gen` its first
/// variant, because that is when a generated fragment first reached the
/// guard. `an_anchor_may_contain_bxs_directories_only_while_it_is_not_exported`
/// pins both halves.
fn refuses_anchor(path: &str, exported: bool, roots: &RootSet) -> Option<Reason> {
    refuses_unanchored(path, None, roots)
        .or_else(|| {
            (exported && roots.holds_bx_directory(Path::new(path)))
                .then_some(Reason::ContainsBxDirectory)
        })
        .or_else(|| (!roots.contains(Path::new(path))).then_some(Reason::OutsideDeclaredRoots))
}

/// Why one resolved path may not be named at all — relative, climbing, made of
/// a character no path bx writes holds, inside a directory bx owns, or inside
/// bx's config repo — whether or not it must also lie inside a root.
///
/// `separator` is the one further character the text may hold: `Some(':')`
/// only for a whole location value, whose entries were judged apart at it.
fn refuses_unanchored(text: &str, separator: Option<char>, roots: &RootSet) -> Option<Reason> {
    let path = Path::new(text);
    if !path.is_absolute() {
        return Some(Reason::NotAbsolute);
    }
    // Read before normalisation, which would fold the `..` away.
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Some(Reason::ParentComponent);
    }
    // An allowlist, not a list of known-bad characters: the shell has resolved
    // the value, and a tool may read any other character its own way.
    if let Some(unlisted) = text
        .chars()
        .find(|&c| !(c == '/' || is_word_char(c) || Some(c) == separator))
    {
        return Some(Reason::UnlistedCharacter(unlisted));
    }
    // Before the root test, and therefore ahead of any declaration: a root the
    // user declared widens where tools may live, never who owns bx's own state.
    refuses_bx_location(path, roots)
}

/// Why `path` may never be where a tool keeps a file, whatever roots are
/// declared: it lies inside a directory bx owns, or inside bx's config repo.
///
/// The part of the location rule that holds for a path bx writes outside an
/// environment fragment too — a declared shell history file, which the shell
/// keeps and no root need permit, is judged by this alone. Lexical, like every
/// containment test here.
#[must_use]
pub fn refuses_bx_location(path: &Path, roots: &RootSet) -> Option<Reason> {
    if roots.owns(path) {
        return Some(Reason::BxOwnedDirectory);
    }
    if roots.in_config_repo(path) {
        return Some(Reason::InsideConfigRepo);
    }
    None
}

#[cfg(test)]
mod tests;
