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
                // list does not hide a later entry's reason (#47 round 1).
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
                    // root itself, as it does on one path (#47 round 2).
                    .or_else(|| whole.and_then(|value| refuses_entry_bx(value, Some(':'), roots)))
                    .or_else(|| {
                        value
                            .split(':')
                            .find_map(|entry| refuses_entry_at_root(entry, roots))
                    });
                // There is no whole-value placement check after this, because
                // one could not refuse anything (#47 round 3). Every entry now
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
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::env_guard::fixtures::*;
    use crate::env_guard::table::EMITTABLE;
    use crate::env_guard::*;

    #[test]
    fn a_program_is_one_absolute_path_or_one_bare_command_name() {
        use Reason::{BxOwnedDirectory, NotAProgram, NotAbsolute, UnresolvedReference};
        for value in [
            "nvim",
            "code-insiders",
            "nvim.appimage",
            "g++",
            "7z",
            "ed_2",
            "/usr/bin/nvim",
            "/opt/x_y/bin/ed-2.1+b",
            "$HOME/bin/nvim",
            "/home/other/.local/state/bx/nvim",
        ] {
            assert_eq!(
                check("BROWSER", value, &rooted()),
                Verdict::Allowed,
                "{value}"
            );
        }
        for (value, reason) in [
            ("", NotAProgram),
            (".", NotAProgram),
            ("..", NotAProgram),
            ("-x", NotAProgram),
            (".hidden", NotAProgram),
            ("_x", NotAProgram),
            ("x://ed", NotAProgram),
            ("\"nvim --wait\"", NotAProgram),
            ("\"/usr/bin/nvim -u /etc/evil\"", NotAProgram),
            ("/usr/bin/a:b", NotAProgram),
            ("a:b", NotAProgram),
            ("\"a=b\"", NotAProgram),
            ("user@host", NotAProgram),
            ("a,b", NotAProgram),
            ("'~/bin/nvim'", NotAProgram),
            ("./nvim", NotAbsolute),
            ("bin/nvim", NotAbsolute),
            ("/var/home/example/.local/state/bx/nvim", BxOwnedDirectory),
            ("$NOWHERE", UnresolvedReference),
        ] {
            assert_eq!(
                reason_of(&check("BROWSER", value, &rooted())),
                Some(reason),
                "{value:?}"
            );
            // A command line's first word is judged as a program is, and only
            // the sentence of the grammar refusal differs.
            let as_command_line = match reason {
                NotAProgram => Reason::NotACommandLine,
                other => other,
            };
            let first_word_only = !value.contains(' ');
            if first_word_only {
                assert_eq!(
                    reason_of(&check("EDITOR", value, &rooted())),
                    Some(as_command_line),
                    "{value:?}"
                );
            }
        }
        // With no home, a `~` or `$HOME` program cannot be shown to be outside
        // bx's state directory, and does not resolve.
        for value in ["~/bin/nvim", "$HOME/bin/nvim"] {
            for name in ["TERMINAL", "VISUAL"] {
                assert_eq!(
                    reason_of(&check(name, value, &RootSet::strict())),
                    Some(Reason::NoHome),
                    "{name}={value}"
                );
            }
        }
    }

    #[test]
    fn a_command_line_is_one_program_and_arguments_that_point_nowhere_bx_owns() {
        use Reason::{
            BxOwnedDirectory, InsideConfigRepo, LaterExpansion, NoHome, NotACommandLine,
            NotAbsolute, RelocatingAssignment,
        };
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        // What the reference dotfiles set, and the shapes beside it.
        for (name, value) in [
            ("MANPAGER", "\"sh -c 'col -bx | bat -l man -p'\""),
            ("MANPAGER", "'sh -c \"col -bx | bat -l man -p\"'"),
            ("MANPAGER", "less"),
            ("EDITOR", "nvim"),
            ("EDITOR", "\"code --wait\""),
            ("VISUAL", "\"nvim -u /etc/xdg/nvim/init.lua\""),
            ("PAGER", "\"less -R\""),
            ("PAGER", "\"/usr/bin/less -R  -F\""),
            ("EDITOR", "\"nvim ~/notes/todo.md\""),
            ("EDITOR", "\"emacsclient -c -a ''\""),
            ("EDITOR", "\"nvim relative/.local/state/bx\""),
            ("PAGER", "\"env LESSCHARSET=utf-8 less\""),
            ("MANPAGER", "'nvim +Man!'"),
        ] {
            for roots in [rooted(), home_rooted.clone()] {
                assert_eq!(
                    check(name, value, &roots),
                    Verdict::Allowed,
                    "{name}={value}"
                );
            }
        }
        // With no home, a `~` argument cannot be shown to be outside bx's
        // state directory; every other argument above is judged the same.
        assert_eq!(
            reason_of(&check(
                "EDITOR",
                "\"nvim ~/notes/todo.md\"",
                &RootSet::strict()
            )),
            Some(NoHome)
        );
        assert_eq!(
            check(
                "MANPAGER",
                "\"sh -c 'col -bx | bat -l man -p'\"",
                &RootSet::strict()
            ),
            Verdict::Allowed
        );
        for (value, reason) in [
            // The first word is a program, or nothing is.
            ("\" nvim\"", NotACommandLine),
            ("\"-R less\"", NotACommandLine),
            ("\"./nvim --wait\"", NotAbsolute),
            ("\"x://ed --wait\"", NotACommandLine),
            (
                "\"/var/home/example/.local/state/bx/nvim -R\"",
                BxOwnedDirectory,
            ),
            // An argument inside bx's directories, however it is spelled.
            (
                "\"nvim /var/home/example/.local/state/bx/ledger\"",
                BxOwnedDirectory,
            ),
            ("\"nvim ~/.local/state/bx/ledger\"", BxOwnedDirectory),
            ("\"nvim ~/.local/share/bx/env.zsh\"", BxOwnedDirectory),
            ("\"nvim ~/.config/bx/bx.toml\"", InsideConfigRepo),
            (
                "\"less -o/var/home/example/.local/state/bx/log\"",
                BxOwnedDirectory,
            ),
            (
                "\"less --log-file=/var/home/example/.local/state/bx/log\"",
                BxOwnedDirectory,
            ),
            (
                "'sh -c \"tee /var/home/example/.local/state/b\"x\"/j\"'",
                BxOwnedDirectory,
            ),
            (
                "\"sh -c 'cat>/var/home/example/.local/state/bx/j'\"",
                BxOwnedDirectory,
            ),
            (
                "\"nvim /var/home/example/.local/../.local/state/bx\"",
                BxOwnedDirectory,
            ),
            // Anything a later shell expands.
            ("'nvim $HOME/.local/state/bx'", LaterExpansion),
            ("'nvim `pwd`'", LaterExpansion),
            ("'nvim a\\ b'", LaterExpansion),
            ("\"nvim ~other/x\"", LaterExpansion),
            ("\"nvim /var/home/example/.local/state/b*\"", LaterExpansion),
            ("\"nvim /var/home/example/.local/state/b?\"", LaterExpansion),
            (
                "\"nvim /var/home/example/.local/state/{bx,x}\"",
                LaterExpansion,
            ),
            // A relocating assignment, wherever it stands.
            (
                "\"env XDG_CONFIG_HOME=/etc/evil nvim\"",
                RelocatingAssignment,
            ),
            ("\"env CARGO_HOME=/tmp/c nvim\"", RelocatingAssignment),
            ("\"sh -c 'HOME=/tmp nvim'\"", RelocatingAssignment),
            ("\"sh -c 'x;TMPDIR=/tmp nvim'\"", RelocatingAssignment),
            // A shell assigns a name without an `=` too.
            (
                "\"sh -c 'for XDG_CONFIG_HOME in /etc/evil; do export XDG_CONFIG_HOME; nvim; done'\"",
                RelocatingAssignment,
            ),
            (
                "\"sh -c 'read HOME </etc/h; export HOME; nvim'\"",
                RelocatingAssignment,
            ),
            (
                "\"sh -c 'printf -v CARGO_HOME /etc/evil; nvim'\"",
                RelocatingAssignment,
            ),
            (
                "\"sh -c 'CARGO_HOME[1]=/etc/evil nvim'\"",
                RelocatingAssignment,
            ),
            ("\"sh -c 'CARGO_HOME+=/evil nvim'\"", RelocatingAssignment),
        ] {
            for roots in [rooted(), home_rooted.clone()] {
                assert_eq!(
                    reason_of(&check("EDITOR", value, &roots)),
                    Some(reason),
                    "{value}"
                );
            }
        }
    }

    #[test]
    fn a_whole_word_opening_with_a_tilde_before_a_break_is_read_from_its_first_slash() {
        // Split at `:` or `=`, `~:notes/todo.md` is the pieces `~` and
        // `notes/todo.md`, each judged on its own. Read whole, it opens with a
        // `~` that is not the home's, and is judged from its first `/`, as its
        // pieces are, rather than refused as another account's home.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for value in ["\"nvim ~:notes/todo.md\"", "\"nvim ~=notes/todo.md\""] {
            for roots in [rooted(), home_rooted.clone()] {
                assert_eq!(check("EDITOR", value, &roots), Verdict::Allowed, "{value}");
            }
        }
    }

    #[test]
    fn an_argument_is_judged_whole_when_its_homes_directories_hold_a_break() {
        use Reason::{BxOwnedDirectory, InsideConfigRepo};
        for home in ["/tmp/a:b", "/tmp/a=b", "/tmp/a:b=c"] {
            let roots = RootSet::new(Path::new(home), &[PathBuf::from("~")]);
            for (value, reason) in [
                (
                    format!("\"nvim {home}/.local/state/bx/ledger\""),
                    BxOwnedDirectory,
                ),
                (
                    format!("\"less --log-file={home}/.local/state/bx/log\""),
                    BxOwnedDirectory,
                ),
                (
                    format!("\"less -o{home}/.local/share/bx/env.zsh\""),
                    BxOwnedDirectory,
                ),
                (
                    format!("\"sh -c 'cat>{home}/.config/bx/bx.toml'\""),
                    InsideConfigRepo,
                ),
                (
                    "\"nvim ~/.local/state/bx/ledger\"".to_string(),
                    BxOwnedDirectory,
                ),
            ] {
                assert_eq!(
                    reason_of(&check("EDITOR", &value, &roots)),
                    Some(reason),
                    "{home}: {value}"
                );
                let options = value.replacen("nvim ", "", 1).replacen("less ", "", 1);
                assert_eq!(
                    reason_of(&check("LESS", &options, &roots)),
                    Some(reason),
                    "{home}: {options}"
                );
            }
            for value in [
                format!("\"nvim {home}/notes/todo.md\""),
                format!("\"less --log-file={home}/log\""),
                "\"nvim ~/notes:x/todo.md\"".to_string(),
            ] {
                assert_eq!(check("EDITOR", &value, &roots), Verdict::Allowed, "{value}");
            }
        }
    }

    #[test]
    fn options_are_judged_as_a_command_lines_arguments_are() {
        use Reason::{BxOwnedDirectory, LaterExpansion, RelocatingAssignment};
        for value in [
            "-R",
            "\"-R -F -X\"",
            "\"--RAW-CONTROL-CHARS --quit-if-one-screen\"",
            "\"-R --use-color -Dd+r\"",
            "''",
            "",
        ] {
            assert_eq!(check("LESS", value, &rooted()), Verdict::Allowed, "{value}");
        }
        for (value, reason) in [
            (
                "\"-R -o/var/home/example/.local/state/bx/log\"",
                BxOwnedDirectory,
            ),
            ("'-R $HOME'", LaterExpansion),
            ("\"-R XDG_STATE_HOME=/tmp\"", RelocatingAssignment),
            ("\"-R XDG_STATE_HOME\"", RelocatingAssignment),
        ] {
            assert_eq!(
                reason_of(&check("LESS", value, &rooted())),
                Some(reason),
                "{value}"
            );
        }
    }

    #[test]
    fn a_setting_accepts_only_its_own_shape() {
        for (name, value) in [
            ("UV_NO_CACHE", "0"),
            ("UV_NO_CACHE", "1"),
            ("MISE_VERBOSE", "true"),
            ("MISE_VERBOSE", "false"),
            ("MISE_JOBS", "8"),
            ("MISE_JOBS", "16"),
            ("SCCACHE_CACHE_SIZE", "100G"),
            ("SCCACHE_CACHE_SIZE", "512M"),
            ("SCCACHE_CACHE_SIZE", "2T"),
            ("SCCACHE_CACHE_SIZE", "10K"),
            ("CARGO_TERM_COLOR", "always"),
            ("LANG", "C.UTF-8"),
            ("LANG", "en_US.UTF-8"),
            ("LANG", "9"),
            ("CARGO_TERM_COLOR", "auto"),
            ("CARGO_TERM_COLOR", "never"),
            ("MISE_JOBS", "1"),
            ("MISE_JOBS", "1024"),
            ("SCCACHE_CACHE_SIZE", "1K"),
            ("SCCACHE_CACHE_SIZE", "999999T"),
        ] {
            for roots in [rooted(), RootSet::strict()] {
                assert_eq!(
                    check(name, value, &roots),
                    Verdict::Allowed,
                    "{name}={value}"
                );
            }
        }
        for (name, value) in [
            ("UV_NO_CACHE", "yes"),
            ("UV_NO_CACHE", ""),
            ("UV_NO_CACHE", "2"),
            ("MISE_VERBOSE", "/x"),
            ("MISE_JOBS", ""),
            ("MISE_JOBS", "G"),
            ("MISE_JOBS", "8X"),
            ("MISE_JOBS", "8GG"),
            ("MISE_JOBS", "-1"),
            ("MISE_JOBS", "1.5"),
            ("SCCACHE_CACHE_SIZE", "G100"),
            ("CARGO_TERM_COLOR", ""),
            ("CARGO_TERM_COLOR", "."),
            ("CARGO_TERM_COLOR", ".."),
            ("CARGO_TERM_COLOR", "-always"),
            ("CARGO_TERM_COLOR", "a/b"),
            ("CARGO_TERM_COLOR", "~"),
            ("CARGO_TERM_COLOR", "~/x"),
            ("CARGO_TERM_COLOR", "a:b"),
            ("CARGO_TERM_COLOR", "https://example.invalid"),
            ("LANG", "\"C UTF-8\""),
            ("LANG", "sr_RS@latin"),
            // Each setting holds only what its tool accepts (round 6): cargo
            // knows three colour modes, mise a job count, sccache a size with
            // a unit.
            ("CARGO_TERM_COLOR", "bogus"),
            ("CARGO_TERM_COLOR", "Always"),
            ("CARGO_TERM_COLOR", "1"),
            ("MISE_JOBS", "4K"),
            ("MISE_JOBS", "0"),
            ("MISE_JOBS", "1025"),
            ("MISE_JOBS", "99999999999999999999"),
            ("MISE_JOBS", "08"),
            ("SCCACHE_CACHE_SIZE", "100"),
            ("SCCACHE_CACHE_SIZE", "0G"),
            ("SCCACHE_CACHE_SIZE", "1000000G"),
            ("SCCACHE_CACHE_SIZE", "010G"),
            ("SCCACHE_CACHE_SIZE", "10g"),
            ("SCCACHE_CACHE_SIZE", "K"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(Reason::NotASetting),
                "{name}={value:?}"
            );
        }
    }

    #[test]
    fn locales_and_input_methods_admit_their_words_and_refuse_every_path() {
        let locales = [
            "LC_ALL",
            "LC_ADDRESS",
            "LC_COLLATE",
            "LC_CTYPE",
            "LC_IDENTIFICATION",
            "LC_MEASUREMENT",
            "LC_MESSAGES",
            "LC_MONETARY",
            "LC_NAME",
            "LC_NUMERIC",
            "LC_PAPER",
            "LC_TELEPHONE",
            "LC_TIME",
        ];
        let modules = [
            "GTK_IM_MODULE",
            "QT_IM_MODULE",
            "SDL_IM_MODULE",
            "GLFW_IM_MODULE",
        ];
        // A setting needs no root, so every set admits the same values.
        for roots in [rooted(), RootSet::strict()] {
            for name in locales {
                for value in ["en_US.UTF-8", "C.UTF-8", "C", "POSIX", "de_DE.utf8"] {
                    assert_eq!(
                        check(name, value, &roots),
                        Verdict::Allowed,
                        "{name}={value}"
                    );
                }
            }
            for name in modules {
                for value in ["ibus", "fcitx", "fcitx5", "uim", "xim"] {
                    assert_eq!(
                        check(name, value, &roots),
                        Verdict::Allowed,
                        "{name}={value}"
                    );
                }
            }
            // Written bare, the `=` is outside the value grammar, so bx's
            // `[[env]]` renderer quotes it.
            for value in ["\"@im=ibus\"", "'@im=fcitx'", "\"@im=fcitx5\""] {
                assert_eq!(
                    check("XMODIFIERS", value, &roots),
                    Verdict::Allowed,
                    "{value}"
                );
            }
            // Anything shaped like a path, a list or an option is refused.
            let refused = [
                "/usr/lib/locale/x",
                "\"a/b\"",
                "en_US:C",
                "\"en US\"",
                "..",
                "-x",
                "",
            ];
            for name in locales.iter().chain(&modules) {
                for value in refused {
                    assert_eq!(
                        reason_of(&check(name, value, &roots)),
                        Some(Reason::NotASetting),
                        "{name}={value}"
                    );
                }
            }
            for value in refused.iter().chain(&[
                "ibus",
                "\"@im=\"",
                "\"@im=/usr/lib/ibus\"",
                "\"@im=a:b\"",
                "\"@IM=ibus\"",
                "\"@im=ibus x\"",
                "\"x@im=ibus\"",
            ]) {
                assert_eq!(
                    reason_of(&check("XMODIFIERS", value, &roots)),
                    Some(Reason::NotASetting),
                    "{value}"
                );
            }
        }
        // None of them moves anything, so none is searched for in a tool's
        // activation output.
        for name in locales
            .iter()
            .chain(&modules)
            .chain(&["XMODIFIERS", "LESS", "MANPAGER"])
        {
            assert!(!is_relocating(name), "{name}");
        }
    }

    #[test]
    fn a_socket_is_an_absolute_path_outside_bxs_directories() {
        use Reason::{BxOwnedDirectory, NoHome, NotAbsolute};
        for roots in [
            rooted(),
            RootSet::new(Path::new(HOME), &[]),
            RootSet::strict(),
        ] {
            for value in [
                "/run/user/1000/gnupg/S.gpg-agent.ssh",
                "\"/run/agent/socket\"",
            ] {
                assert_eq!(
                    check("SSH_AUTH_SOCK", value, &roots),
                    Verdict::Allowed,
                    "{value}"
                );
            }
            for (value, reason) in [
                ("agent.sock", NotAbsolute),
                ("", NotAbsolute),
                ("/var/home/example/.local/state/bx/agent", BxOwnedDirectory),
            ] {
                assert_eq!(
                    reason_of(&check("SSH_AUTH_SOCK", value, &roots)),
                    Some(reason),
                    "{value}"
                );
            }
        }
        assert_eq!(
            reason_of(&check("SSH_AUTH_SOCK", "~/agent", &RootSet::strict())),
            Some(NoHome)
        );
    }

    // Review round 6 (r3 round 1).

    #[test]
    fn a_fragment_never_moves_bxs_own_directories() {
        // bx reads `XDG_STATE_HOME` to find its state directory and
        // `XDG_CONFIG_HOME` to find its config repo. A fragment that set
        // either would move them on bx's next run, leaving the ledger, the
        // journal and `local.toml` behind (invariants 3 and 4), so neither is
        // in the emit table, whatever the roots admit.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for name in ["XDG_STATE_HOME", "XDG_CONFIG_HOME"] {
            assert_eq!(emittable(name), None, "{name}");
            for value in [
                "/var/mnt/scratch/example/s",
                "/var/mnt/scratch/example/c",
                "~/state",
                "~/.config",
            ] {
                for roots in [rooted(), home_rooted.clone(), RootSet::strict()] {
                    assert_eq!(
                        reason_of(&check(name, value, &roots)),
                        Some(Reason::NotEmittable),
                        "{name}={value}"
                    );
                    assert_eq!(
                        reasons(&format!("export {name}={value}\n"), &roots),
                        vec![(1, Reason::NotEmittable)],
                        "{name}={value}"
                    );
                }
            }
        }
        // The line before the move is judged against the directories bx
        // knows, and the move itself is what is refused.
        assert_eq!(
            reasons(
                "export CARGO_HOME=/var/mnt/scratch/example/s/bx\n\
                 export XDG_STATE_HOME=/var/mnt/scratch/example/s\n",
                &rooted()
            ),
            vec![(2, Reason::NotEmittable)]
        );
    }

    #[test]
    fn nothing_may_point_into_bxs_config_repo() {
        // The repo is committed, and README calls it safe to make public: a
        // tool writing there could commit its credentials (invariant 5), and a
        // program or a search list there runs whatever was committed.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for (name, value) in [
            ("CARGO_HOME", "~/.config/bx/cargo"),
            ("CARGO_HOME", "~/.config/bx"),
            ("EDITOR", "~/.config/bx/ed"),
            ("PATH", "~/.config/bx/bin:$PATH"),
            ("SSH_AUTH_SOCK", "~/.config/bx/a.sock"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &home_rooted)),
                Some(Reason::InsideConfigRepo),
                "{name}={value}"
            );
        }
        // A sibling whose name merely extends it is not the repo.
        assert_eq!(
            check("CARGO_HOME", "~/.config/bxtra", &home_rooted),
            Verdict::Allowed
        );
        // With no home, every default repo is refused, whoever's home.
        assert_eq!(
            reason_of(&check("PATH", "/home/o/.config/bx/bin", &RootSet::strict())),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(
            check("PATH", "/home/o/.config/bxtra/bin", &RootSet::strict()),
            Verdict::Allowed
        );
        // A repo the environment moved is refused once the caller says so,
        // inside a declared root, and the home's default stays refused.
        let moved = rooted().with_config_repos(&[PathBuf::from("/var/mnt/scratch/example/cfg/bx")]);
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/cfg/bx/c",
                &moved
            )),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/cfg/./bx/c",
                &moved
            )),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cfg/c", &moved),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("EDITOR", "/var/home/example/.config/bx/ed", &moved)),
            Some(Reason::InsideConfigRepo)
        );
        // A home of `/x` whose whole tree is a root: the repo under it is
        // still refused.
        let x = RootSet::new(Path::new("/x"), &[PathBuf::from("~")]);
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/x/.config/bx/cargo", &x)),
            Some(Reason::InsideConfigRepo)
        );
        assert_eq!(check("CARGO_HOME", "/x/cargo", &x), Verdict::Allowed);
        // bx's state directory is checked first: it is the stronger claim.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/home/example/.local/state/bx",
                &home_rooted
                    .clone()
                    .with_config_repos(&[PathBuf::from("/var/home/example/.local/state/bx")])
            )),
            Some(Reason::BxOwnedDirectory)
        );
    }

    #[test]
    fn a_location_is_the_one_path_its_tool_reads() {
        // cargo reads `CARGO_HOME` as one path, `:` and all. Each entry of this
        // value is inside the root, and the whole string is not: `example:` is
        // one component, a sibling of the root. Since #45 its first entry is
        // the root itself, which is refused first, for either kind. With every
        // entry strictly beneath a root, the whole string begins with its first
        // entry's parent, so it lies inside that root too.
        let joined = "/var/mnt/scratch/example:/var/mnt/scratch/example/y";
        for name in ["CARGO_HOME", "GOPATH"] {
            assert_eq!(
                reason_of(&check(name, joined, &rooted())),
                Some(Reason::DeclaredRootItself),
                "{name}"
            );
        }
        let beneath = "/var/mnt/scratch/example/x:/var/mnt/scratch/example/y";
        for name in ["CARGO_HOME", "GOPATH"] {
            assert_eq!(check(name, beneath, &rooted()), Verdict::Allowed, "{name}");
        }
        // `GOPATH` is a list go splits at `:`, so each entry is the path.
        assert_eq!(
            reason_of(&check(
                "GOPATH",
                "/var/mnt/scratch/example/go:/etc/evil",
                &rooted()
            )),
            Some(Reason::OutsideDeclaredRoots)
        );
        // The review's climbing case: its entries normalise inside the root
        // and the whole string outside it. Since r3 round 2 its `..` is refused
        // before either, whichever kind holds it.
        let climbing = "/var/mnt/scratch/example/x:/../../../var/mnt/scratch/example/y";
        for name in ["CARGO_HOME", "GOPATH"] {
            assert_eq!(
                reason_of(&check(name, climbing, &rooted())),
                Some(Reason::ParentComponent),
                "{name}"
            );
        }
        // An entry that is refused keeps its own reason, and a value with no
        // `:` is one path either way.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/k:",
                &rooted()
            )),
            Some(Reason::NotAbsolute)
        );
        assert_eq!(
            check("CARGO_HOME", "/var/mnt/scratch/example/cargo", &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_path_a_tool_may_expand_or_that_climbs_is_refused() {
        use Reason::{NoRootsDeclared, ParentComponent, UnlistedCharacter};
        // The review's npm fragment, judged at the guard. A real shell holds
        // the cache value as the literal below, so the real-shell tests cannot
        // see what happens next: npm expands `${EDITOR}` inside the value
        // itself, resolves `<root>//../../../../../../var/home/example/.local/state/bx`,
        // and writes its logs into bx's state directory. So the guard refuses
        // the shape rather than modelling each tool: no location holds `$`,
        // `{` or `%` once the shell has resolved it, and no path of any kind
        // has a `..` component.
        let roots = RootSet::new(Path::new(HOME), &[PathBuf::from("/var/home/example/r")]);
        let fragment = "export EDITOR=/../../../../../..\n\
             export NPM_CONFIG_CACHE='/var/home/example/r/${EDITOR}/var/home/example/.local/state/bx'\n";
        assert_eq!(
            reasons(fragment, &roots),
            vec![(1, ParentComponent), (2, UnlistedCharacter('$'))]
        );
        // Each expansion character, in a location and in any entry of a list
        // of locations, quoted so that the shell leaves it alone.
        for value in [
            "'/var/mnt/scratch/example/${X}'",
            "'/var/mnt/scratch/example/$X'",
            "\"/var/mnt/scratch/example/{a}\"",
            "/var/mnt/scratch/example/%APPDATA%",
            "'/var/mnt/scratch/example/go:/var/mnt/scratch/example/$X'",
        ] {
            for name in ["CARGO_HOME", "GOPATH", "NUGET_PACKAGES"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    Some(UnlistedCharacter(
                        value
                            .chars()
                            .find(|c| "${%".contains(*c))
                            .expect("an expansion character")
                    )),
                    "{name}={value}"
                );
            }
        }
        // A `..` in every path-valued kind, even where it lands inside a root.
        for (name, value) in [
            ("CARGO_HOME", "/var/mnt/scratch/example/a/../cargo"),
            (
                "GOPATH",
                "/var/mnt/scratch/example/go:/var/mnt/scratch/example/a/../b",
            ),
            ("EDITOR", "/usr/bin/../bin/nvim"),
            ("PATH", "/usr/local/../bin:$PATH"),
            ("SSH_AUTH_SOCK", "/run/user/../agent"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &rooted())),
                Some(ParentComponent),
                "{name}={value}"
            );
        }
        // A kind that needs no root is refused for it with no root too; a
        // location is refused for having no root first.
        for (name, value) in [
            ("EDITOR", "/usr/bin/../bin/nvim"),
            ("PATH", "/usr/local/../bin:$PATH"),
            ("SSH_AUTH_SOCK", "/run/user/../agent"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &RootSet::strict())),
                Some(ParentComponent),
                "{name}={value}"
            );
        }
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/a/../cargo",
                &RootSet::strict()
            )),
            Some(NoRootsDeclared)
        );
        // A `.` component, and dots inside a name, are neither.
        assert_eq!(
            check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/./a..b/cargo",
                &rooted()
            ),
            Verdict::Allowed
        );
        assert_eq!(
            check("EDITOR", "/opt/a..b/nvim", &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_location_may_not_contain_bxs_own_directories() {
        use Reason::{BxOwnedDirectory, ContainsBxDirectory, InsideConfigRepo};
        // A tool clears its own cache: `uv cache clean` on an approved
        // `UV_CACHE_DIR=~/.local/state` deleted bx's ledger with it
        // (invariant 4). So a location may neither be inside bx's directories
        // nor contain them.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        assert_eq!(
            reasons("export UV_CACHE_DIR=~/.local/state\n", &home_rooted),
            vec![(1, ContainsBxDirectory)]
        );
        for (name, value) in [
            ("UV_CACHE_DIR", "~/.config"),
            ("SCCACHE_DIR", "~/.local/state"),
            ("GOMODCACHE", "~/.local"),
            ("XDG_CACHE_HOME", "~/.local/state"),
            ("CARGO_HOME", "~"),
            ("GOPATH", "/var/home/example/go:/var/home/example/.local"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &home_rooted)),
                Some(ContainsBxDirectory),
                "{name}={value}"
            );
        }
        // bx's directories themselves keep their own reasons, and a sibling
        // or a directory beside them is fine.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~/.local/state/bx", &home_rooted)),
            Some(BxOwnedDirectory)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~/.config/bx", &home_rooted)),
            Some(InsideConfigRepo)
        );
        for value in [
            "~/.local/share",
            "~/.local/state/bxtra",
            "~/.config/other",
            "~/.cache",
        ] {
            assert_eq!(
                check("CARGO_HOME", value, &home_rooted),
                Verdict::Allowed,
                "{value}"
            );
        }
        // Directories the caller adds count the same way.
        let moved = rooted()
            .owning(&[PathBuf::from("/var/mnt/scratch/example/state/bx")])
            .with_config_repos(&[PathBuf::from("/var/mnt/scratch/example/cfg/bx")]);
        // Without them, the root itself is still refused for being one (#45),
        // which containing bx's directories outranks above.
        for (value, unmoved) in [
            ("/var/mnt/scratch/example/state", None),
            ("/var/mnt/scratch/example/cfg", None),
            ("/var/mnt/scratch/example", Some(Reason::DeclaredRootItself)),
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &moved)),
                Some(ContainsBxDirectory),
                "{value}"
            );
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                unmoved,
                "{value}"
            );
        }
        // A program, a search list or a socket is not cleared by its tool.
        for (name, value) in [
            ("EDITOR", "/var/home/example/.local"),
            ("PATH", "/var/home/example/.local:$PATH"),
            ("SSH_AUTH_SOCK", "/var/home/example/.config"),
        ] {
            assert_eq!(check(name, value, &home_rooted), Verdict::Allowed, "{name}");
        }
        // The operator fragment contains none of them.
        assert_eq!(scan_with(OPERATOR_FRAGMENT, &rooted()), vec![]);
        assert_eq!(scan(OPERATOR_FRAGMENT).len(), 25);
    }

    #[test]
    fn a_path_holds_only_the_characters_every_path_bx_writes_is_made_of() {
        use Reason::{NotAProgram, UnlistedCharacter};
        // The review's bun value. bun takes `\` for a path separator on
        // Linux, so to bun this one component climbs out of the root into bx's
        // state directory, and `bun pm cache rm` deleted the ledger. To the
        // guard it was a single component inside the root, with no `..` and
        // none of `$`, `{` or `%`: a list of known-bad characters missed it.
        let climb = r"'/var/mnt/scratch/example/a\..\..\..\..\..\var\home\example\.local\state\bx'";
        for name in ["BUN_INSTALL_CACHE_DIR", "BUN_INSTALL"] {
            assert_eq!(
                reason_of(&check(name, climb, &rooted())),
                Some(UnlistedCharacter('\\')),
                "{name}"
            );
        }
        // Every other character is refused by name, in a location and in an
        // entry of a list of locations.
        for (value, unlisted) in [
            ("'/var/mnt/scratch/example/${X}'", '$'),
            ("\"/var/mnt/scratch/example/{a}\"", '{'),
            ("/var/mnt/scratch/example/%APPDATA%", '%'),
            ("\"/var/mnt/scratch/example/my cache\"", ' '),
            ("\"/var/mnt/scratch/example/a~b\"", '~'),
            ("/var/mnt/scratch/example/a@b", '@'),
            ("/var/mnt/scratch/example/a,b", ','),
            ("\"/var/mnt/scratch/example/a#b\"", '#'),
            ("'/var/mnt/scratch/example/a=b'", '='),
        ] {
            for name in ["CARGO_HOME", "GOPATH"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    Some(UnlistedCharacter(unlisted)),
                    "{name}={value}"
                );
            }
        }
        // A search-list entry and a socket hold the same characters, and need
        // no root. A socket is one path, so a `:` in it is refused too.
        for roots in [rooted(), RootSet::strict()] {
            for (name, value, unlisted) in [
                ("PATH", r"'/usr/a\b:/usr/bin'", '\\'),
                ("PATH", "\"/usr/my bin:$PATH\"", ' '),
                ("INFOPATH", "/usr/share/a@b:$INFOPATH", '@'),
                ("SSH_AUTH_SOCK", "\"/run/an agent/socket\"", ' '),
                ("SSH_AUTH_SOCK", "/run/a:b", ':'),
                ("SSH_AUTH_SOCK", r"'/run/a\b'", '\\'),
            ] {
                assert_eq!(
                    reason_of(&check(name, value, &roots)),
                    Some(UnlistedCharacter(unlisted)),
                    "{name}={value}"
                );
            }
        }
        // `:` between a location's entries is the separator, not a character
        // of any path, and every allowed character passes.
        for (name, value) in [
            (
                "CARGO_HOME",
                "/var/mnt/scratch/example/k:/var/mnt/scratch/example/l",
            ),
            (
                "GOPATH",
                "/var/mnt/scratch/example/go:/var/mnt/scratch/example/b",
            ),
            ("CARGO_HOME", "/var/mnt/scratch/example/a.b_c-d+e/F9"),
        ] {
            assert_eq!(
                check(name, value, &rooted()),
                Verdict::Allowed,
                "{name}={value}"
            );
        }
        for (name, value) in [
            ("PATH", "/opt/x_y-1.2+b/bin:$PATH"),
            ("SSH_AUTH_SOCK", "/run/user/1000/gnupg/S.gpg-agent.ssh"),
        ] {
            assert_eq!(
                check(name, value, &RootSet::strict()),
                Verdict::Allowed,
                "{name}"
            );
        }
        // A program keeps its own, stricter rule.
        assert_eq!(
            reason_of(&check("RUSTC_WRAPPER", "\"/usr/bin/a b\"", &rooted())),
            Some(NotAProgram)
        );
    }

    #[test]
    fn an_anchor_may_contain_bxs_directories_only_while_it_is_not_exported() {
        use Reason::{
            BxOwnedDirectory, ContainsBxDirectory, InsideConfigRepo, NoRootsDeclared,
            OutsideDeclaredRoots, ParentComponent, UnlistedCharacter,
        };
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for name in ["SCRATCH_HOME", "DATA_DIR"] {
            assert_eq!(emittable(name), Some(Kind::Anchor), "{name}");
        }
        // The operator's fragment written in terms of the home, under a `~`
        // root: the anchor names the home, which holds bx's directories. Kept
        // out of the environment, no tool reads or clears it; exported, every
        // tool the shell starts can.
        let exported = "export SCRATCH_HOME=\"/var/mnt/scratch/example\"";
        let unexported = "SCRATCH_HOME=\"/var/mnt/scratch/example\"";
        let at_home = OPERATOR_FRAGMENT.replacen(exported, "SCRATCH_HOME=\"$HOME\"", 1);
        assert_ne!(at_home, OPERATOR_FRAGMENT);
        assert_eq!(scan_with(&at_home, &home_rooted), vec![]);
        let exported_home =
            OPERATOR_FRAGMENT.replacen(exported, "export SCRATCH_HOME=\"$HOME\"", 1);
        assert_eq!(
            reasons(&exported_home, &home_rooted),
            vec![(1, ContainsBxDirectory)]
        );
        // So is every line of an `environment.d` fragment, which says no
        // `export` and is read into the environment whole.
        assert_eq!(
            scan_exported("SCRATCH_HOME=$HOME\n", &home_rooted)
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![ContainsBxDirectory]
        );
        // The operator fragment under the three layouts: the home beside the
        // scratch root, the home equal to it, and the home under it. Its
        // exported anchor contains bx's directories in the last two, and is
        // refused there; unexported, it scans clean in all three.
        let kept_in = OPERATOR_FRAGMENT.replacen(exported, unexported, 1);
        for (roots, refused) in [
            (rooted(), false),
            (RootSet::new(Path::new(ROOT), &[PathBuf::from(ROOT)]), true),
            (
                RootSet::new(
                    Path::new("/var/mnt/scratch/example/home"),
                    &[PathBuf::from(ROOT)],
                ),
                true,
            ),
        ] {
            let expected = if refused {
                vec![(1, ContainsBxDirectory)]
            } else {
                vec![]
            };
            assert_eq!(reasons(OPERATOR_FRAGMENT, &roots), expected, "{roots:?}");
            assert_eq!(scan_with(&kept_in, &roots), vec![], "{roots:?}");
        }
        assert_eq!(scan(OPERATOR_FRAGMENT).len(), 25);
        // A tool-read location is still refused for containing them, whether
        // it names the directory itself or is written in terms of an anchor
        // that does.
        assert_eq!(
            reason_of(&check("UV_CACHE_DIR", "~/.local/state", &home_rooted)),
            Some(ContainsBxDirectory)
        );
        assert_eq!(
            reasons(
                "SCRATCH_HOME=~/.local/state\nexport UV_CACHE_DIR=$SCRATCH_HOME\n",
                &home_rooted
            ),
            vec![(2, ContainsBxDirectory)]
        );
        // Every other check a location's one path has, an anchor keeps.
        for (value, reason) in [
            ("~/.local/state/bx", BxOwnedDirectory),
            ("~/.config/bx/x", InsideConfigRepo),
            ("~/a/../b", ParentComponent),
            ("\"/var/home/example/a b\"", UnlistedCharacter(' ')),
            (
                "/var/home/example/a:/var/home/example/b",
                UnlistedCharacter(':'),
            ),
            ("scratch", Reason::NotAbsolute),
        ] {
            assert_eq!(
                reason_of(&check("SCRATCH_HOME", value, &home_rooted)),
                Some(reason),
                "{value}"
            );
        }
        assert_eq!(
            reason_of(&check("CACHE_DIR", "/etc", &rooted())),
            Some(OutsideDeclaredRoots)
        );
        assert_eq!(
            reason_of(&check("DATA_DIR", ROOT, &RootSet::strict())),
            Some(NoRootsDeclared)
        );
    }

    #[test]
    fn the_anchor_exemption_is_closed_to_an_exported_anchor() {
        // The measurement `refuses_anchor`'s doc records as what the exemption
        // was, asserted in its own test so an earlier assertion cannot hide it
        // (round-5 note COV3): exported, an anchor is refused for containing
        // bx's state directory exactly as a tool-read location with the
        // identical value is, and only unexported does the exemption stand.
        use Reason::ContainsBxDirectory;
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let state = "/var/home/example/.local/state";
        for name in ["DATA_DIR", "SCRATCH_HOME", "UV_CACHE_DIR"] {
            assert_eq!(
                reason_of(&check(name, state, &home_rooted)),
                Some(ContainsBxDirectory),
                "{name}"
            );
            assert_eq!(
                reasons(&format!("export {name}={state}\n"), &home_rooted),
                vec![(1, ContainsBxDirectory)],
                "{name}"
            );
        }
        for name in ["DATA_DIR", "SCRATCH_HOME"] {
            assert_eq!(unexported(name, state, &home_rooted), None, "{name}");
        }
        assert_eq!(
            unexported("UV_CACHE_DIR", state, &home_rooted),
            Some(ContainsBxDirectory)
        );
    }

    #[test]
    fn a_location_at_a_declared_root_is_refused_because_its_tool_may_write_beside_it() {
        use Reason::DeclaredRootItself;
        // uv puts executables in `$XDG_DATA_HOME/../bin`. With the value at the
        // root, that directory is beside the root and outside every one.
        for value in [ROOT.to_string(), format!("{ROOT}/")] {
            assert_eq!(
                reason_of(&check("XDG_DATA_HOME", &value, &rooted())),
                Some(DeclaredRootItself),
                "{value}"
            );
        }
        assert_eq!(
            reasons(
                &format!("export SCRATCH_HOME={ROOT}\nexport XDG_DATA_HOME=$SCRATCH_HOME\n"),
                &rooted()
            ),
            vec![(2, DeclaredRootItself)]
        );
        for value in [format!("{ROOT}/.local/share"), format!("{ROOT}/data")] {
            assert_eq!(
                check("XDG_DATA_HOME", &value, &rooted()),
                Verdict::Allowed,
                "{value}"
            );
        }
        // The rule is by shape, not by name: no tool-read location may be a
        // root, and no entry of a list of them may be either.
        for (name, kind) in EMITTABLE {
            if matches!(kind, Kind::Location | Kind::LocationList) {
                assert_eq!(
                    reason_of(&check(name, ROOT, &rooted())),
                    Some(DeclaredRootItself),
                    "{name}"
                );
            }
        }
        assert_eq!(
            reason_of(&check("GOPATH", &format!("{ROOT}/go:{ROOT}"), &rooted())),
            Some(DeclaredRootItself)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", &format!("{ROOT}:{ROOT}/x"), &rooted())),
            Some(DeclaredRootItself)
        );
        // One level: a root nested in another lies beneath the outer one, and
        // the outer one is still a root itself.
        let nested = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from("/var/mnt/scratch"), PathBuf::from(ROOT)],
        );
        assert_eq!(check("XDG_DATA_HOME", ROOT, &nested), Verdict::Allowed);
        assert_eq!(
            reason_of(&check("XDG_DATA_HOME", "/var/mnt/scratch", &nested)),
            Some(DeclaredRootItself)
        );
        // An anchor may be a root: no tool is known to read one.
        for name in ["SCRATCH_HOME", "DATA_DIR"] {
            assert_eq!(check(name, ROOT, &rooted()), Verdict::Allowed, "{name}");
        }
        // A search list and a socket need no root, so being one is no matter.
        assert_eq!(
            check("PATH", &format!("\"{ROOT}:$PATH\""), &rooted()),
            Verdict::Allowed
        );
        assert_eq!(check("SSH_AUTH_SOCK", ROOT, &rooted()), Verdict::Allowed);
    }

    #[test]
    fn an_existing_reason_on_any_entry_outranks_a_root_itself_on_an_earlier_one() {
        use Reason::{BxOwnedDirectory, InsideConfigRepo, OutsideDeclaredRoots};
        // With the home beside the root, each value's first entry is the root
        // itself and a later entry has a reason that predates #45. Every entry
        // is judged for those first, so the later entry's reason names the fix,
        // as it did before the root-itself rule existed.
        let mut judged = Vec::new();
        let mut expected = Vec::new();
        for name in ["GOPATH", "CARGO_HOME"] {
            for (later, reason) in [
                ("/var/home/example/.local/state/bx", BxOwnedDirectory),
                ("/var/home/example/.config/bx", InsideConfigRepo),
                ("/etc", OutsideDeclaredRoots),
            ] {
                let value = format!("{ROOT}:{later}");
                judged.push((name, reason_of(&check(name, &value, &rooted()))));
                expected.push((name, Some(reason)));
            }
        }
        assert_eq!(judged, expected);
    }

    #[test]
    fn a_location_whose_entries_pass_is_refused_when_its_whole_path_holds_a_home_with_a_colon() {
        // A home may hold `:`, and so may bx's directories under it. Neither
        // entry of this value contains bx's state directory, and the one path
        // cargo reads does: the whole-value check is its only refusal. `GOPATH`
        // is read entry by entry, so its whole string is not judged.
        let home = format!("{ROOT}/x:{ROOT}/y");
        let roots = RootSet::new(Path::new(&home), &[PathBuf::from(ROOT)]);
        let value = format!("{ROOT}/x:{ROOT}/y/.local/state");
        for entry in value.split(':') {
            assert_eq!(
                check("CARGO_HOME", entry, &roots),
                Verdict::Allowed,
                "{entry}"
            );
        }
        assert_eq!(check("GOPATH", &value, &roots), Verdict::Allowed);
        assert_eq!(
            reason_of(&check("CARGO_HOME", &value, &roots)),
            Some(Reason::ContainsBxDirectory)
        );
    }

    #[test]
    fn a_whole_value_holding_a_bx_directory_outranks_an_entry_that_is_a_root_itself() {
        use Reason::{BxOwnedDirectory, ContainsBxDirectory, InsideConfigRepo};
        let roots = [
            PathBuf::from("/r1"),
            PathBuf::from("/r2"),
            PathBuf::from("/r3"),
        ];
        // A home that holds `:`. The middle entry of this value is the root
        // `/r2`, and no entry lies in bx's state directory, but the one path
        // cargo reads is that directory.
        let colon_home = RootSet::new(Path::new("/r1/a:/r2:/r3/h"), &roots);
        // A state directory and a config repo that hold `:`, as a caller that
        // read the environment may pass them.
        let owning_the_value =
            RootSet::new(Path::new(HOME), &roots).owning(&[PathBuf::from("/r1/s:/r2")]);
        let owning_beneath_it =
            RootSet::new(Path::new(HOME), &roots).owning(&[PathBuf::from("/r1/s:/r2/st")]);
        let repo =
            RootSet::new(Path::new(HOME), &roots).with_config_repos(&[PathBuf::from("/r1/c:/r2")]);
        let judged: Vec<_> = [
            (&colon_home, "~/.local/state/bx"),
            (&owning_the_value, "/r1/s:/r2"),
            (&owning_beneath_it, "/r1/s:/r2"),
            (&repo, "/r1/c:/r2"),
        ]
        .into_iter()
        .map(|(set, value)| (value, reason_of(&check("CARGO_HOME", value, set))))
        .collect();
        assert_eq!(
            judged,
            vec![
                ("~/.local/state/bx", Some(BxOwnedDirectory)),
                ("/r1/s:/r2", Some(BxOwnedDirectory)),
                ("/r1/s:/r2", Some(ContainsBxDirectory)),
                ("/r1/c:/r2", Some(InsideConfigRepo)),
            ]
        );
        // `GOPATH` is read entry by entry, so its whole string is not judged
        // and the root entry still names the fix.
        assert_eq!(
            reason_of(&check("GOPATH", "/r1/c:/r2", &repo)),
            Some(Reason::DeclaredRootItself)
        );
    }

    #[test]
    fn every_entry_beneath_a_root_leaves_the_whole_value_beneath_one() {
        // The property that lets `judge` stop after the at-root pass over
        // entries, and so the one a whole-value placement check would have been
        // the net for. Once every `:`-entry lies strictly beneath a declared
        // root, the whole value extends the first entry's parent, which is
        // inside a root, so the whole value and its own parent are inside that
        // root too. A whole-value `OutsideDeclaredRoots` or `DeclaredRootItself`
        // check would therefore be an equivalent mutant no test could catch
        // (#47 round 3), and this pins what it would have caught instead: break
        // an entry rule and this fails, where a dead branch would not have.
        let layouts = [
            (vec!["/r"], "/h"),
            (vec!["/r"], "/r"),
            (vec!["/r"], "/r/x"),
            (vec!["/r"], "/r/a:/r/b"),
            (vec!["/r", "/r/a"], "/h"),
            (vec!["/r/a", "/s"], "/h:/r"),
            (vec!["~"], HOME),
        ];
        let tails = ["", "/a", "/a/b", "/b", "/a:x", "/x", "/"];
        let heads = ["/r", "/r/a", "/r/a/b", "/s", "/h", "/", HOME];
        let seconds = ["", ":/r/q", ":/r/a/q", ":/s/q", ":/r", ":/"];
        let mut allowed = 0_usize;
        let mut loose = Vec::new();
        for (declared, home) in layouts {
            let declared: Vec<PathBuf> = declared.iter().map(PathBuf::from).collect();
            let roots = RootSet::new(Path::new(home), &declared);
            for head in heads {
                for tail in tails {
                    for second in seconds {
                        let value = format!("{head}{tail}{second}");
                        // The whole public verdict, not a replay of `judge`'s
                        // internals, so a later reordering inside `judge`
                        // cannot move the test in lockstep with the code.
                        if check("CARGO_HOME", &value, &roots) != Verdict::Allowed {
                            continue;
                        }
                        allowed += 1;
                        let whole = refuses_entry_outside(&value, &roots)
                            .or_else(|| refuses_entry_at_root(&value, &roots));
                        if let Some(reason) = whole {
                            loose.push((value, home, reason));
                        }
                    }
                }
            }
        }
        // Not vacuous: the values above really are allowed as locations.
        assert!(allowed > 200, "{allowed} of the values were allowed");
        assert_eq!(loose, Vec::new());
    }

    #[test]
    fn the_rule_covers_one_level_above_a_location_and_no_more() {
        // `DeclaredRootItself` buys exactly one level: an approved value's
        // parent is inside a declared root, so the directory uv derives at
        // `$XDG_DATA_HOME/../bin` is too. It buys no second level, and the
        // module's docs say so. A value one level beneath the root is allowed
        // although its grandparent — the root's own parent — is outside every
        // root, so a tool deriving two levels up would leave them.
        let one_level = format!("{ROOT}/share");
        assert_eq!(
            check("XDG_DATA_HOME", &one_level, &rooted()),
            Verdict::Allowed
        );
        let parent = Path::new(&one_level).parent().expect("a parent");
        assert!(rooted().contains(parent), "one level up is inside a root");
        let grandparent = parent.parent().expect("a grandparent");
        assert_eq!(grandparent, Path::new("/var/mnt/scratch"));
        assert!(
            !rooted().contains(grandparent),
            "two levels up is outside every root, and the guard does not model it"
        );
        // Two levels are covered only when a root happens to lie two levels
        // above the value, which no rule requires.
        let nested = RootSet::new(
            Path::new(HOME),
            &[PathBuf::from("/var/mnt/scratch"), PathBuf::from(ROOT)],
        );
        assert_eq!(
            check("XDG_DATA_HOME", &one_level, &nested),
            Verdict::Allowed
        );
        assert!(nested.contains(grandparent));
    }

    #[test]
    fn cache_dir_is_read_by_find_cache_dir_and_judged_as_a_location() {
        // npm's find-cache-dir writes, and may clear, `$CACHE_DIR/<name>` for a
        // name its consumer picks. A consumer named `bx` under
        // `CACHE_DIR=~/.local/state` or `~/.config`, or one named `state` under
        // `CACHE_DIR=~/.local`, reaches bx's directories. So `CACHE_DIR` may not
        // contain them, while the two anchors no tool is known to read still may
        // — unexported, where no tool can read them.
        assert_eq!(emittable("CACHE_DIR"), Some(Kind::Location));
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for value in ["~/.local/state", "~/.config", "~/.local"] {
            assert_eq!(
                reason_of(&check("CACHE_DIR", value, &home_rooted)),
                Some(Reason::ContainsBxDirectory),
                "{value}"
            );
            for anchor in ["DATA_DIR", "SCRATCH_HOME"] {
                assert_eq!(
                    unexported(anchor, value, &home_rooted),
                    None,
                    "{anchor}={value}"
                );
            }
        }
        assert_eq!(
            scan_with(
                "SCRATCH_HOME=~\nCACHE_DIR=$SCRATCH_HOME/cache\n",
                &home_rooted
            ),
            vec![]
        );
        // The one refusal this change turns into an approval. As an anchor,
        // `CACHE_DIR` was one path with no `:` at all, so any `:` value was
        // `UnlistedCharacter(':')`. As a location it is judged per `:`-entry
        // and then as the whole path find-cache-dir joins its consumer's name
        // onto, exactly as a tool reads `CARGO_HOME` — so a value whose
        // entries and whole path all lie strictly beneath a root is allowed,
        // and its verdict is `CARGO_HOME`'s. Revert the table line to
        // `Kind::Anchor` and this fails.
        // `Verdict` carries the name, so the two are compared by reason.
        let colon_home = RootSet::new(
            Path::new(&format!("{ROOT}/x:{ROOT}/y")),
            &[PathBuf::from(ROOT)],
        );
        for (value, roots, reason) in [
            (format!("{ROOT}/x:{ROOT}/y"), &rooted(), None),
            (
                format!("{ROOT}/x:{ROOT}/y/.local/state"),
                &colon_home,
                Some(Reason::ContainsBxDirectory),
            ),
            (
                format!("{ROOT}/x:/etc"),
                &rooted(),
                Some(Reason::OutsideDeclaredRoots),
            ),
            (
                format!("{ROOT}/x:{ROOT}"),
                &rooted(),
                Some(Reason::DeclaredRootItself),
            ),
        ] {
            assert_eq!(
                reason_of(&check("CACHE_DIR", &value, roots)),
                reason,
                "{value}"
            );
            assert_eq!(
                reason_of(&check("CACHE_DIR", &value, roots)),
                reason_of(&check("CARGO_HOME", &value, roots)),
                "{value}"
            );
        }
        assert_eq!(
            check("CACHE_DIR", &format!("{ROOT}/x:{ROOT}/y"), &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn ordinary_settings_programs_and_lists_stay_allowed_beside_a_root() {
        for roots in [rooted(), RootSet::strict()] {
            for (name, value) in [
                ("SCCACHE_CACHE_SIZE", "10G"),
                ("MISE_JOBS", "8"),
                ("UV_NO_CACHE", "1"),
                ("MISE_VERBOSE", "0"),
                ("CARGO_TERM_COLOR", "always"),
                ("LANG", "C.UTF-8"),
                ("EDITOR", "nvim"),
                ("EDITOR", "/usr/bin/nvim"),
                ("SSH_AUTH_SOCK", "/run/user/1000/ssh-agent"),
            ] {
                assert_eq!(
                    check(name, value, &roots),
                    Verdict::Allowed,
                    "{name}={value} {roots:?}"
                );
            }
        }
        // A home is needed to expand `$HOME`, and the strict set has none.
        assert_eq!(
            check("PATH", "\"$HOME/.local/bin:$PATH\"", &rooted()),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_path_refused_for_its_characters_is_refused_for_that_before_where_it_is() {
        use Reason::{BxOwnedDirectory, ContainsBxDirectory, UnlistedCharacter};
        // The order the checks run in is part of the verdict. The allowlist
        // comes first: a value bx cannot read as a path is refused for that
        // before any reasoning about where it is. Each of these values also
        // contains, is, or lies inside a directory the caller added.
        let odd = rooted()
            .owning(&[PathBuf::from("/var/mnt/scratch/example/a b/state/bx")])
            .with_config_repos(&[PathBuf::from("/var/mnt/scratch/example/c d/bx")]);
        for (name, value) in [
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b/state\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/c d\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/a b/state/bx\""),
            ("CARGO_HOME", "\"/var/mnt/scratch/example/c d/bx/x\""),
            ("GOPATH", "\"/var/mnt/scratch/example/a b\""),
            ("SCRATCH_HOME", "\"/var/mnt/scratch/example/a b\""),
            ("SCRATCH_HOME", "\"/var/mnt/scratch/example/a b/state/bx\""),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &odd)),
                Some(UnlistedCharacter(' ')),
                "{name}={value}"
            );
        }
        // Without the character the containment reasons stand, and an anchor
        // may contain what a tool-read location may not while it is not
        // exported. `check` judges as exported, so there it may not either.
        let plain = rooted().owning(&[PathBuf::from("/var/mnt/scratch/example/ab/state/bx")]);
        assert_eq!(
            unexported("SCRATCH_HOME", "/var/mnt/scratch/example/ab", &plain),
            None
        );
        assert_eq!(
            reason_of(&check(
                "SCRATCH_HOME",
                "/var/mnt/scratch/example/ab",
                &plain
            )),
            Some(ContainsBxDirectory)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/var/mnt/scratch/example/ab", &plain)),
            Some(ContainsBxDirectory)
        );
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/ab/state/bx",
                &plain
            )),
            Some(BxOwnedDirectory)
        );
        assert_eq!(
            reason_of(&check(
                "SCRATCH_HOME",
                "/var/mnt/scratch/example/ab/state/bx",
                &plain
            )),
            Some(BxOwnedDirectory)
        );
        // The other half of `refuses_entry_placement`'s order: containing bx's
        // directories outranks the declared roots. Every value above that
        // yields `ContainsBxDirectory` also lies inside a declared root, so
        // swapping the two arms would change none of them. This one lies
        // inside no declared root *and* contains bx's state directory, and it
        // is the only input that tells the two orders apart: under the swap it
        // would report `OutsideDeclaredRoots`, sending the user to declare a
        // root that would still not make the value legal.
        assert_eq!(
            reason_of(&check(
                "UV_CACHE_DIR",
                "/var/home/example/.local",
                &rooted()
            )),
            Some(ContainsBxDirectory)
        );
        // Not vacuous: a sibling that contains nothing of bx's, outside every
        // root in the same way, is refused for the roots.
        assert_eq!(
            reason_of(&check(
                "UV_CACHE_DIR",
                "/var/home/example/.cache",
                &rooted()
            )),
            Some(Reason::OutsideDeclaredRoots)
        );
    }

    #[test]
    fn no_character_outside_the_allowlist_passes_any_path_valued_kind() {
        // The r3 round 3 self-sweep. Every round from 3 to 6 reopened this
        // class — a character a tool reads its own way — so every path-valued
        // kind is tried against every character class a value can carry. The
        // grammar refuses some before any kind is judged (`Unreadable`); every
        // other one is refused by name. None is approved.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        let kinds = [
            ("CARGO_HOME", "/var/mnt/scratch/example/a{C}b", rooted()),
            (
                "GOPATH",
                "/var/mnt/scratch/example/go:/var/mnt/scratch/example/a{C}b",
                rooted(),
            ),
            ("SCRATCH_HOME", "/var/home/example/a{C}b", home_rooted),
            ("PATH", "/usr/a{C}b:/usr/bin", RootSet::strict()),
            ("INFOPATH", "/usr/share/a{C}b", RootSet::strict()),
            ("SSH_AUTH_SOCK", "/run/a{C}b", RootSet::strict()),
        ];
        let characters = [
            '\\', '$', '{', '}', '%', '~', '@', '!', '*', '?', '[', ']', ' ', '\t', '"', '\'', '`',
            '#', '=', ',', ';', '&', '|', '<', '>', '(', ')', '^', 'é', '\u{0}', '\u{7}', '\u{1b}',
            '\r', '\u{7f}', ':',
        ];
        for (name, template, roots) in &kinds {
            for character in characters {
                let value = template.replace("{C}", &character.to_string());
                // Single-quoted, the grammar holds every printable character
                // but the quote itself literally.
                for written in [format!("'{value}'"), format!("\"{value}\""), value.clone()] {
                    let reason = reason_of(&check(name, &written, roots));
                    let splits = matches!(*name, "CARGO_HOME" | "GOPATH" | "PATH" | "INFOPATH");
                    match reason {
                        Some(Reason::UnlistedCharacter(found)) => {
                            assert_eq!(found, character, "{name}={written:?}");
                        }
                        // The grammar's own refusal, before any kind.
                        Some(Reason::Unreadable) => {}
                        // A `:` splits a list, leaving the relative entry `b`.
                        Some(Reason::NotAbsolute) if character == ':' && splits => {}
                        // A bare `$b` is a reference, and `~b` is not the home.
                        Some(Reason::UnresolvedReference) if character == '$' => {}
                        other => panic!("{name}={written:?} gave {other:?}"),
                    }
                }
            }
        }
        // Components: `..` is refused in every path-valued kind, `.` and `//`
        // fold away, and a trailing `/` names the same directory.
        let home_rooted = RootSet::new(Path::new(HOME), &[PathBuf::from("~")]);
        for (name, value, roots, expected) in [
            (
                "CARGO_HOME",
                "~/a/../b",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "GOPATH",
                "/var/home/example/go:/var/home/example/..",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "SCRATCH_HOME",
                "~/..",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "EDITOR",
                "/usr/bin/../nvim",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "PATH",
                "/usr/..:$PATH",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            (
                "SSH_AUTH_SOCK",
                "/run/../agent",
                &home_rooted,
                Some(Reason::ParentComponent),
            ),
            ("CARGO_HOME", ".", &home_rooted, Some(Reason::NotAbsolute)),
            ("SCRATCH_HOME", ".", &home_rooted, Some(Reason::NotAbsolute)),
            ("PATH", ".:$PATH", &home_rooted, Some(Reason::NotAbsolute)),
            (
                "SSH_AUTH_SOCK",
                ".",
                &home_rooted,
                Some(Reason::NotAbsolute),
            ),
            ("CARGO_HOME", "~/./cargo", &home_rooted, None),
            ("CARGO_HOME", "~//cargo", &home_rooted, None),
            ("CARGO_HOME", "~/cargo/", &home_rooted, None),
            ("SCRATCH_HOME", "~//s/./t/", &home_rooted, None),
            (
                "CARGO_HOME",
                "~/.local/state/bx/",
                &home_rooted,
                Some(Reason::BxOwnedDirectory),
            ),
            (
                "CARGO_HOME",
                "~/.local//state/./",
                &home_rooted,
                Some(Reason::ContainsBxDirectory),
            ),
            // `check` judges an anchor as exported, which may not contain bx's
            // directories either.
            (
                "SCRATCH_HOME",
                "~/.local//state/./",
                &home_rooted,
                Some(Reason::ContainsBxDirectory),
            ),
            (
                "SCRATCH_HOME",
                "~/.config/bx/",
                &home_rooted,
                Some(Reason::InsideConfigRepo),
            ),
            (
                "PATH",
                "/var/home/example/.local/state/bx//bin:$PATH",
                &home_rooted,
                Some(Reason::BxOwnedDirectory),
            ),
        ] {
            assert_eq!(
                reason_of(&check(name, value, roots)),
                expected,
                "{name}={value}"
            );
        }
        // An anchor does not carry a tool-read location past the containment
        // check: the location is judged at its own line, whatever it refers to.
        // The anchors are unexported, where they may contain bx's directories.
        for (content, expected) in [
            (
                "DATA_DIR=~\nexport XDG_DATA_HOME=$DATA_DIR\n",
                vec![(2, Reason::ContainsBxDirectory)],
            ),
            (
                "DATA_DIR=~/.local\nexport GOPATH=~/go:$DATA_DIR\n",
                vec![(2, Reason::ContainsBxDirectory)],
            ),
            (
                "DATA_DIR=~/.local\nexport GOPATH=\"${DATA_DIR}\"\n",
                vec![(2, Reason::ContainsBxDirectory)],
            ),
            (
                "SCRATCH_HOME=~/.local/state\nexport SCCACHE_DIR=$SCRATCH_HOME/x\n",
                vec![],
            ),
        ] {
            assert_eq!(reasons(content, &home_rooted), expected, "{content:?}");
        }
    }

    #[test]
    fn a_search_list_or_a_program_needs_no_root_but_every_entry_is_anchored() {
        use Reason::{BxOwnedDirectory, NotAbsolute, UnreadableReference, UnresolvedReference};
        let no_root = RootSet::new(Path::new(HOME), &[]);
        for (content, expected) in [
            ("export PATH=\"$HOME/.local/bin:$PATH\"\n", vec![]),
            ("export PATH=$PATH\n", vec![]),
            ("export PATH=/usr/bin:/opt/x/bin\n", vec![]),
            ("export INFOPATH=/usr/share/info:$INFOPATH\n", vec![]),
            ("export PATH=.:/usr/bin\n", vec![(1, NotAbsolute)]),
            ("export PATH=/usr/bin:\n", vec![(1, NotAbsolute)]),
            ("export PATH=bin\n", vec![(1, NotAbsolute)]),
            ("export PATH=\n", vec![(1, NotAbsolute)]),
            ("export PATH=$PATH/bin\n", vec![(1, NotAbsolute)]),
            ("export PATH=${PATH}x\n", vec![(1, NotAbsolute)]),
            ("export INFOPATH=info\n", vec![(1, NotAbsolute)]),
            (
                "export PATH=/var/home/example/.local/state/bx/bin:$PATH\n",
                vec![(1, BxOwnedDirectory)],
            ),
            // Only its own name stands for what was inherited.
            (
                "export PATH=/usr/bin:$INFOPATH\n",
                vec![(1, UnresolvedReference)],
            ),
            // Once the fragment assigns it, `$PATH` is what it assigned.
            (
                "PATH=bin\nexport PATH=/usr/bin:$PATH\n",
                vec![(1, NotAbsolute), (2, NotAbsolute)],
            ),
            // After a refused line nothing is inherited either.
            (
                "true\nexport PATH=/usr/bin:$PATH\n",
                vec![(1, Reason::Unreadable), (2, UnreadableReference)],
            ),
            ("export EDITOR=/usr/bin/nvim\n", vec![]),
            ("export EDITOR=nvim\n", vec![]),
            ("export EDITOR=\n", vec![(1, Reason::NotACommandLine)]),
            ("export TERMINAL=\n", vec![(1, Reason::NotAProgram)]),
            ("export RUSTC_WRAPPER=/usr/bin/sccache\n", vec![]),
            (
                "export SSH_AUTH_SOCK=/run/user/1000/ssh-agent.socket\n",
                vec![],
            ),
            ("export EDITOR=./nvim\n", vec![(1, NotAbsolute)]),
            (
                "export BROWSER=/usr/bin/firefox:chromium\n",
                vec![(1, Reason::NotAProgram)],
            ),
            ("export EDITOR=$NOWHERE\n", vec![(1, UnresolvedReference)]),
            (
                "export PAGER=/var/home/example/.local/state/bx/less\n",
                vec![(1, BxOwnedDirectory)],
            ),
        ] {
            assert_eq!(reasons(content, &no_root), expected, "{content:?}");
            assert_eq!(reasons(content, &rooted()), expected, "{content:?}");
        }
        // A list or a program is not a relocation, so it does not inherit
        // `$PATH` for another name.
        assert_eq!(
            reasons(
                "export GOPATH=/var/mnt/scratch/example:$GOPATH\n",
                &rooted()
            ),
            vec![(1, UnresolvedReference)]
        );
    }

    #[test]
    fn every_entry_of_a_list_is_judged() {
        use Reason::{BxOwnedDirectory, NotAbsolute, OutsideDeclaredRoots};
        for (value, reason) in [
            (
                "/var/mnt/scratch/example/k:/var/mnt/scratch/example/l",
                None,
            ),
            (
                "/var/mnt/scratch/example/k:/etc/evil/config",
                Some(OutsideDeclaredRoots),
            ),
            (
                "/etc/evil:/var/mnt/scratch/example/k",
                Some(OutsideDeclaredRoots),
            ),
            ("/var/mnt/scratch/example/k:", Some(NotAbsolute)),
            (":/var/mnt/scratch/example/k", Some(NotAbsolute)),
            ("/var/mnt/scratch/example/k:relative", Some(NotAbsolute)),
            (
                "/var/mnt/scratch/example/k:/var/home/example/.local/state/bx",
                Some(BxOwnedDirectory),
            ),
        ] {
            for name in ["GOPATH", "GOMODCACHE", "CARGO_HOME"] {
                assert_eq!(
                    reason_of(&check(name, value, &rooted())),
                    reason,
                    "{name}={value}"
                );
            }
        }
        // Entries arriving through references are split the same way. The
        // references are braced: zsh reads `$A:$B` as `$A` with a modifier.
        let content = concat!(
            "CACHE_DIR=/var/mnt/scratch/example/go\n",
            "DATA_DIR=/etc/evil\n",
            "export GOPATH=\"${CACHE_DIR}:${DATA_DIR}\"\n",
            "export GOPATH=\"$CACHE_DIR:$DATA_DIR\"\n",
        );
        // `DATA_DIR=/etc/evil` is itself a location outside the root.
        assert_eq!(
            reasons(content, &rooted()),
            vec![
                (2, OutsideDeclaredRoots),
                (3, OutsideDeclaredRoots),
                (4, Reason::Unreadable)
            ]
        );
    }
}
