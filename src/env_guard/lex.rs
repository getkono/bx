//! The grammar a fragment is read in: the statements a line may be, and the
//! value forms an assignment may hold, down to each reference they expand.

use std::path::Path;

use super::reason::Reason;
use super::scope::Scope;
use super::table::{Kind, emittable};
use crate::config::path::{BASH_REMOVAL, GATE, ZSH_REMOVAL};
use crate::lexical::is_variable_name;

/// How long an expansion may grow before it is refused.
///
/// The expander's bound on work. Values are learned expanded, so a line that
/// doubles a variable — `X=$X$X` — doubles what is stored, and a fragment of a
/// few dozen such lines would otherwise hold gigabytes.
pub(super) const MAX_EXPANDED_LEN: usize = 4096;

/// The blanks that may indent a line and separate a value from its comment.
pub(super) const BLANKS: [char; 2] = [' ', '\t'];

/// What one line of a fragment is, to the grammar.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Statement<'a> {
    /// A blank line or a comment.
    Nothing,
    /// `NAME=VALUE` or `export NAME=VALUE`: `value` is everything after the
    /// `=`, still to be read by the value grammar, and `exported` whether the
    /// line said `export`.
    Assign {
        name: &'a str,
        value: &'a str,
        exported: bool,
    },
    /// `[[ -d TEST ]] && ` before an assignment to a search list, which the
    /// shell makes only when `TEST` is a directory. `test` is the bare word
    /// tested, already read; the rest is [`Statement::Assign`]'s.
    Gated {
        test: Word<'a>,
        name: &'a str,
        value: &'a str,
        exported: bool,
    },
    /// zsh's `path=(${path:#WORD})`, or bash's line of [`BASH_REMOVAL`]'s
    /// one shape around `WORD`: every entry of `PATH` that is exactly `WORD`
    /// taken out, and nothing else changed. `word` is the bare word removed,
    /// already read.
    Removal { word: Word<'a> },
    /// `if TEST; then`, where `TEST` is exactly one a runtime `when` condition
    /// renders ([`crate::config::when::is_opener`]).
    Open,
    /// `fi`, closing the block an [`Statement::Open`] opened.
    Close,
    /// Not a statement the grammar reads.
    Refused,
}

/// The one search list [`Statement::Removal`] takes an entry out of, as the
/// environment spells it.
pub(super) const SEARCH_PATH: &str = "PATH";

/// Read one line of a fragment against the statement grammar.
pub(super) fn statement(line: &str) -> Statement<'_> {
    let text = line.trim_matches(BLANKS);
    if text.is_empty() {
        return Statement::Nothing;
    }
    if text.starts_with('#') {
        return if text.chars().any(is_unprintable) {
            Statement::Refused
        } else {
            Statement::Nothing
        };
    }
    if text == crate::config::when::CLOSER {
        return Statement::Close;
    }
    if crate::config::when::is_opener(text) {
        return Statement::Open;
    }
    if let Some(gated) = text.strip_prefix(GATE.0) {
        return gated
            .split_once(GATE.1)
            .and_then(|(test, assignment)| {
                let test = exact_word(test)?;
                let (name, value, exported) = assignment_in(assignment)?;
                // Only a search list may be assigned conditionally: every entry
                // either outcome could hold is judged, which is not true of a
                // value a later line reads as one whole path.
                (emittable(name) == Some(Kind::SearchList)).then_some(Statement::Gated {
                    test,
                    name,
                    value,
                    exported,
                })
            })
            .unwrap_or(Statement::Refused);
    }
    for (open, close) in [ZSH_REMOVAL, BASH_REMOVAL] {
        if let Some(word) = text
            .strip_prefix(open)
            .and_then(|rest| rest.strip_suffix(close))
        {
            // In bash's shape a `:` follows the word, which zsh would read
            // as the start of a modifier on an unbraced reference ending it.
            let modified = close == BASH_REMOVAL.1
                && word.rfind('$').is_some_and(|at| {
                    !word[at + 1..].starts_with('{') && !word[at..].contains('/')
                });
            return exact_word(word)
                .filter(|_| !modified)
                .map_or(Statement::Refused, |word| Statement::Removal { word });
        }
    }
    match assignment_in(text) {
        Some((name, value, exported)) => Statement::Assign {
            name,
            value,
            exported,
        },
        None => Statement::Refused,
    }
}

/// `NAME=VALUE` or `export NAME=VALUE`, as `(name, value, exported)`: the
/// value still to be read by the value grammar.
fn assignment_in(text: &str) -> Option<(&str, &str, bool)> {
    let (assignment, exported) = match text.strip_prefix("export") {
        Some(operand) if operand.starts_with(BLANKS) => (operand.trim_start_matches(BLANKS), true),
        _ => (text, false),
    };
    let (name, value) = assignment.split_once('=')?;
    is_variable_name(name).then_some((name, value, exported))
}

/// `text` read as one bare word with nothing before or after it, and no `~`:
/// the word a [`Statement::Gated`] tests and a [`Statement::Removal`] removes.
///
/// A `~` is refused because whether zsh expands one inside a pattern depends
/// on options the fragment does not set; `$HOME` says the same thing in every
/// one of them.
fn exact_word(text: &str) -> Option<Word<'_>> {
    if text.chars().any(is_unprintable) {
        return None;
    }
    match bare(text) {
        Ok((word, "")) if !word.tilde => Some(word),
        _ => None,
    }
}

/// `statement` as a fragment of this syntax reads it: a gated assignment and a
/// removal are a shell's, and an `environment.d` fragment, where
/// `every_exported`, reads neither.
pub(super) fn readable(statement: Statement<'_>, every_exported: bool) -> Statement<'_> {
    match statement {
        Statement::Gated { .. } | Statement::Removal { .. } if every_exported => Statement::Refused,
        statement => statement,
    }
}

/// A character no line of a fragment may hold: a control character other
/// than a tab.
fn is_unprintable(c: char) -> bool {
    c.is_control() && c != '\t'
}

/// A character of printable ASCII, space included.
fn is_printable(c: char) -> bool {
    (' '..='~').contains(&c)
}

/// One piece of a value: text as written, or a reference to expand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part<'a> {
    Text(&'a str),
    Reference(&'a str),
}

/// A value, read by the value grammar.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Word<'a> {
    /// The value without its quotes, references not expanded, as written.
    pub(super) text: &'a str,
    /// Whether the value begins with the unquoted `~` a shell expands.
    tilde: bool,
    /// The text, split into literal text and references, in order.
    parts: Vec<Part<'a>>,
}

impl Word<'_> {
    /// What a shell gives the name this value is assigned to.
    pub(super) fn resolve(&self, scope: &Scope, home: Option<&Path>) -> Result<String, Reason> {
        self.expand(scope, home, None)
    }

    /// [`Word::resolve`], except that a reference to `inherited` expands as
    /// [`Scope::own_list`] says: to [`INHERITED`](super::scope::INHERITED) if the fragment has not
    /// assigned it, and to its earlier extension if one was made.
    pub(super) fn expand(
        &self,
        scope: &Scope,
        home: Option<&Path>,
        inherited: Option<&str>,
    ) -> Result<String, Reason> {
        let mut out = if self.tilde {
            scope.lookup("HOME", home)?
        } else {
            String::new()
        };
        for part in &self.parts {
            match part {
                Part::Text(text) => out.push_str(text),
                Part::Reference(name) if inherited == Some(*name) => {
                    out.push_str(&scope.own_list(name, home)?);
                }
                Part::Reference(name) => out.push_str(&scope.lookup(name, home)?),
            }
            if out.len() > MAX_EXPANDED_LEN {
                return Err(Reason::ExpansionTooLong);
            }
        }
        Ok(out)
    }
}

/// Read everything written after `NAME=` as one value, optionally followed by
/// blanks and a comment.
pub(super) fn read_value(value: &str) -> Result<Word<'_>, Reason> {
    if value.chars().any(is_unprintable) {
        return Err(Reason::Unreadable);
    }
    let (word, rest) = if let Some(inner) = value.strip_prefix('\'') {
        single_quoted(inner)?
    } else if let Some(inner) = value.strip_prefix('"') {
        double_quoted(inner)?
    } else {
        bare(value)?
    };
    after_value(rest)?;
    Ok(word)
}

/// A single-quoted value whose content starts `inner`, and what follows it.
fn single_quoted(inner: &str) -> Result<(Word<'_>, &str), Reason> {
    let end = inner.find('\'').ok_or(Reason::Unreadable)?;
    let text = &inner[..end];
    if !text.chars().all(is_printable) {
        return Err(Reason::Unreadable);
    }
    let word = Word {
        text,
        tilde: false,
        parts: vec![Part::Text(text)],
    };
    Ok((word, &inner[end + 1..]))
}

/// A double-quoted value whose content starts `inner`, and what follows it.
fn double_quoted(inner: &str) -> Result<(Word<'_>, &str), Reason> {
    let end = inner.find('"').ok_or(Reason::Unreadable)?;
    let text = &inner[..end];
    let parts = parts(text, |c| is_printable(c) && !"\\`!".contains(c))?;
    let word = Word {
        text,
        tilde: false,
        parts,
    };
    Ok((word, &inner[end + 1..]))
}

/// An unquoted value, and what follows it.
fn bare(value: &str) -> Result<(Word<'_>, &str), Reason> {
    let (text, rest) = value.split_at(value.find(BLANKS).unwrap_or(value.len()));
    // A shell expands `~` at the start of a value, and zsh and bash expand it
    // after a `:` as well, so `~` is read only here and only as the home.
    let (tilde, body) = match text.strip_prefix('~') {
        None => (false, text),
        Some(body) if body.is_empty() || body.starts_with('/') => (true, body),
        Some(_) => return Err(Reason::Unreadable),
    };
    let parts = parts(body, |c| {
        c.is_ascii_alphanumeric() || "_./,:@%+-".contains(c)
    })?;
    let word = Word { text, tilde, parts };
    Ok((word, rest))
}

/// Split a value's text into literal text and references, refusing a
/// character `allowed` does not admit.
///
/// Every `$` begins a reference, so the text is split at each one: what
/// precedes the first is literal, and every later piece starts with a name.
fn parts(text: &str, allowed: impl Fn(char) -> bool) -> Result<Vec<Part<'_>>, Reason> {
    let mut pieces = text.split('$');
    let mut parts = vec![literal(pieces.next().unwrap_or_default(), &allowed)?];
    for piece in pieces {
        let (name, tail) = reference(piece)?;
        parts.push(Part::Reference(name));
        parts.push(literal(tail, &allowed)?);
    }
    Ok(parts)
}

/// Literal text of a value, if every character of it is `allowed`.
fn literal<'a>(text: &'a str, allowed: &impl Fn(char) -> bool) -> Result<Part<'a>, Reason> {
    if text.chars().all(allowed) {
        Ok(Part::Text(text))
    } else {
        Err(Reason::Unreadable)
    }
}

/// The name a reference whose text follows its `$` refers to, and the text
/// after it.
fn reference(piece: &str) -> Result<(&str, &str), Reason> {
    let (name, tail) = match piece.strip_prefix('{') {
        Some(braced) => braced.split_once('}').ok_or(Reason::Unreadable)?,
        None => {
            let end = piece
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(piece.len());
            let (name, tail) = piece.split_at(end);
            // zsh reads on past an unbraced name: `$X:h` takes a modifier and
            // `$X[1]` a subscript. Only a `/`, or the end, is a safe place to
            // stop.
            if !(tail.is_empty() || tail.starts_with('/')) {
                return Err(Reason::Unreadable);
            }
            (name, tail)
        }
    };
    if is_variable_name(name) {
        Ok((name, tail))
    } else {
        Err(Reason::Unreadable)
    }
}

/// What may follow a value on its line: nothing, or blanks and a comment.
fn after_value(rest: &str) -> Result<(), Reason> {
    if rest.is_empty() {
        return Ok(());
    }
    let after = rest.trim_start_matches(BLANKS);
    // Text straight after the value, with no blank between, is more of the
    // same shell word in a form the grammar does not read.
    if after.len() == rest.len() {
        return Err(Reason::Unreadable);
    }
    if after.is_empty() || after.starts_with('#') {
        return Ok(());
    }
    Err(match after.split_once('=') {
        Some((head, _)) if is_variable_name(head) => Reason::MultipleAssignments,
        _ => Reason::Unreadable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_guard::fixtures::*;
    use crate::env_guard::*;

    #[test]
    fn an_inline_comment_after_a_value_is_a_comment() {
        // An unquoted `#` beginning a word starts a comment in bash and zsh,
        // sourced or interactive, so the value ends before it. A `#` inside a
        // word, or quoted, is text.
        assert_eq!(
            scan_with(
                "export CARGO_HOME=/var/mnt/scratch/example/cargo # written by bx\n",
                &rooted()
            ),
            vec![]
        );
        // The value still has to be inside a root: the comment buys nothing.
        assert_eq!(
            scan_with("export CARGO_HOME=/var/cache/elsewhere # bx\n", &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::OutsideDeclaredRoots]
        );
        // A comment carrying an assignment assigns nothing: no shell reads it.
        for content in [
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # GOPATH=/etc\n",
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # keep=this\n",
        ] {
            assert_eq!(scan_with(content, &rooted()), vec![], "{content}");
        }
        // A `#` that does not follow a blank is not a comment to a shell, and
        // not a character the bare-word grammar admits: refused. Quoted, it is
        // text.
        for value in ["/var/mnt/scratch/example/a#b", "#/etc", "\"/x\"#c"] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        // Quoted, it is text, and since r3 round 3 a character no path bx
        // writes holds.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "\"/var/mnt/scratch/example/a#b\"",
                &rooted()
            )),
            Some(Reason::UnlistedCharacter('#'))
        );
    }

    #[test]
    fn the_statement_grammar_reads_only_its_own_statements() {
        for line in [
            "",
            "   ",
            "\t",
            "#",
            "# export CARGO_HOME=/x",
            "  \t# note — with prose",
        ] {
            assert_eq!(statement(line), Statement::Nothing, "{line:?}");
        }
        for (line, name, value, exported) in [
            ("CARGO_HOME=/x", "CARGO_HOME", "/x", false),
            ("export CARGO_HOME=/x", "CARGO_HOME", "/x", true),
            (
                "  export\t CARGO_HOME=/x # c ",
                "CARGO_HOME",
                "/x # c",
                true,
            ),
            ("export=/x", "export", "/x", false),
            ("exportX=", "exportX", "", false),
            ("X=a=b", "X", "a=b", false),
        ] {
            assert_eq!(
                statement(line),
                Statement::Assign {
                    name,
                    value,
                    exported
                },
                "{line:?}"
            );
        }
        for line in [
            "export",
            "export CARGO_HOME",
            "export  ",
            "export\u{b}CARGO_HOME=/x",
            "\\export CARGO_HOME=/x",
            "\"export\" CARGO_HOME=/x",
            "e''xport CARGO_HOME=/x",
            "declare -x CARGO_HOME=/x",
            "export -- CARGO_HOME=/x",
            "CARGO_HOME+=/x",
            "CARGO_HOME[1]=/x",
            "2bad=x",
            "=x",
            "# comment\r",
            "# bell \u{7}",
            "\u{c}",
        ] {
            assert_eq!(statement(line), Statement::Refused, "{line:?}");
        }
    }

    #[test]
    fn bashs_removal_of_a_word_ending_in_a_braced_reference_is_read() {
        // bash's shape follows the word with a `:`, which zsh would read as a
        // modifier on an unbraced reference ending it; a braced one ends at
        // its `}`, so nothing follows it to misread.
        let bash = |word: &str| format!("{}{word}{}", BASH_REMOVAL.0, BASH_REMOVAL.1);
        for removed in ["${CARGO_HOME}", "/opt/${TOOL}"] {
            let line = bash(removed);
            let Statement::Removal { word } = statement(&line) else {
                panic!("bash's removal of a braced reference is read: {line:?}");
            };
            assert_eq!(word.text, removed);
        }
        // The same words unbraced are the ones refused.
        for refused in ["$CARGO_HOME", "/opt/$TOOL"] {
            let line = bash(refused);
            assert!(matches!(statement(&line), Statement::Refused), "{line:?}");
        }
    }

    #[test]
    fn a_gate_and_a_removal_are_read_only_in_the_one_shape_each_is_written() {
        let Statement::Gated {
            test,
            name,
            value,
            exported,
        } = statement("  [[ -d $HOME/bin ]] && export PATH=$HOME/bin:$PATH")
        else {
            panic!("a gated assignment to PATH is read");
        };
        assert_eq!(
            (test.text, name, value, exported),
            ("$HOME/bin", "PATH", "$HOME/bin:$PATH", true)
        );
        let Statement::Removal { word } = statement("path=(${path:#${CARGO_HOME}/bin})") else {
            panic!("a removal is read");
        };
        assert_eq!(word.text, "${CARGO_HOME}/bin");
        let bash = |word: &str| format!("{}{word}{}", BASH_REMOVAL.0, BASH_REMOVAL.1);
        for (line, removed) in [
            (bash("${CARGO_HOME}/bin"), "${CARGO_HOME}/bin"),
            (format!("  {}", bash("$HOME/bin")), "$HOME/bin"),
            (bash("/usr/local/bin"), "/usr/local/bin"),
        ] {
            let Statement::Removal { word } = statement(&line) else {
                panic!("bash's removal is read: {line:?}");
            };
            assert_eq!(word.text, removed);
        }
        // bash's shape, near missed: the word, each assignment, or what
        // follows the line.
        let bash_near_misses = [
            bash("~/x"),
            bash("$HOME"),
            bash("${HOME}/x/$Y"),
            bash("/x*"),
            bash("/x /y"),
            bash("$(pwd)"),
            bash("/x\"/evil\""),
            bash("/x:\"/}; export CARGO_HOME=/etc/evil; : \"${PATH//\":/x"),
            format!("{}; export CARGO_HOME=/etc/evil", bash("/x")),
            format!("{} # note", bash("/x")),
            bash("/x").replace("PATH=${PATH#:}; ", ""),
            bash("/x").replace("${PATH%:}", "${PATH%%:*}"),
            bash("/x").replace(":; PATH=${PATH//\":", ":; FPATH=${PATH//\":"),
            bash("/x").replace("\":/x:\"", ":/x:"),
        ];
        for line in &bash_near_misses {
            let (found, scope) = pass(line, &rooted(), false);
            assert_ne!(found, vec![], "{line:?}");
            assert!(scope.lost, "{line:?}");
        }

        // Every near miss is a line the guard does not read, so nothing after
        // it is known either.
        for line in [
            "[[ -d /x ]] && export CARGO_HOME=/x",
            "[[ -d /x ]] && EDITOR=nvim",
            "[[ -f /x ]] && export PATH=/x:$PATH",
            "[[ -d /x ]] || export PATH=/x:$PATH",
            "[[ -d /x ]]  && export PATH=/x:$PATH",
            "[[ -d /x y ]] && export PATH=/x:$PATH",
            "[[ -d ~/x ]] && export PATH=/x:$PATH",
            "[[ -d \"/x\" ]] && export PATH=/x:$PATH",
            "[[ -d $(pwd) ]] && export PATH=/x:$PATH",
            "[[ -d /x ]] && source /x",
            "[[ -d /x ]] && export PATH",
            "[[ -d /x ]] && [[ -d /y ]] && export PATH=/x:$PATH",
            "[[ -d /x ]] && export PATH=/x:$PATH; export CARGO_HOME=/etc/evil",
            "path=(${path:#~/x})",
            "path=(${path:#/x} /evil)",
            "path=(/evil ${path:#/x})",
            "path=(${path:#/x*})",
            "path=(${path:#/x /y})",
            "path=(${path:#$(pwd)})",
            "path=(${path:#\"/x\"})",
            "path=(${path:#$X[1]})",
            "path=(${path:#/x}) # note",
            "path=(${path:#/x}); export CARGO_HOME=/etc/evil",
            "fpath=(${fpath:#/x})",
            "path=(${path%/x})",
        ] {
            let (found, scope) = pass(line, &rooted(), false);
            assert_ne!(found, vec![], "{line:?}");
            assert!(scope.lost, "{line:?}");
        }
    }

    #[test]
    fn a_gated_entry_is_judged_as_any_other_and_a_removal_must_name_what_it_removes() {
        let roots = rooted();
        // The shape the `[path]` renderer writes, approved.
        let content = "export CARGO_HOME=/var/mnt/scratch/example/cargo\n\
                       path=(${path:#$HOME/bin})\n\
                       [[ -d $HOME/bin ]] && export PATH=$HOME/bin:$PATH\n\
                       path=(${path:#$CARGO_HOME/bin})\n\
                       export PATH=$CARGO_HOME/bin:$PATH\n\
                       export PATH=${PATH}:/opt/x/bin\n\
                       path=(${path:#${HOME}/.cargo/bin})\n";
        assert_eq!(reasons(content, &roots), vec![]);

        // A gate decides whether the entry is added, never whether it is
        // judged.
        for (line, reason) in [
            (
                "[[ -d $HOME/.local/state/bx/bin ]] && export PATH=$HOME/.local/state/bx/bin:$PATH",
                Reason::BxOwnedDirectory,
            ),
            ("[[ -d bin ]] && export PATH=bin:$PATH", Reason::NotAbsolute),
            (
                "[[ -d /x ]] && export PATH=$NOWHERE/bin:$PATH",
                Reason::UnresolvedReference,
            ),
        ] {
            assert_eq!(reasons(line, &roots), vec![(1, reason)], "{line:?}");
        }
        // Whether the gated line ran is not known, so the list's value as one
        // string is not either; the list itself still extends.
        assert_eq!(
            reasons(
                "[[ -d /a ]] && export PATH=/a:$PATH\nexport PATH=/b:$PATH\nexport INFOPATH=$PATH\n",
                &roots
            ),
            vec![(3, Reason::UnreadableReference)]
        );
        // A removal changes what the list holds, so its value as one string,
        // known before, is not after.
        assert_eq!(
            reasons(
                "export PATH=/usr/bin:/opt/x/bin\npath=(${path:#/opt/x/bin})\n\
                 export INFOPATH=$PATH\n",
                &roots
            ),
            vec![(3, Reason::UnreadableReference)]
        );
        // Inside a `when` block, either form assigns PATH as an assignment
        // there does, and the list extends nothing the guard can name after
        // the block closes.
        for line in ["[[ -d /a ]] && export PATH=/a:$PATH", "path=(${path:#/a})"] {
            assert_eq!(
                reasons(
                    &format!("if [[ -o login ]]; then\n  {line}\nfi\nexport PATH=/b:$PATH\n"),
                    &roots
                ),
                vec![(4, Reason::UnreadableReference)],
                "{line:?}"
            );
        }
        // An entry a later line would add is judged after a removal too.
        assert_eq!(
            reasons(
                "path=(${path:#/a})\nexport PATH=$HOME/.local/state/bx:$PATH\n",
                &roots
            ),
            vec![(2, Reason::BxOwnedDirectory)]
        );
        // A removal names only an entry the guard can resolve, since a
        // reference to nothing would remove some other entry instead.
        assert_eq!(
            reasons("path=(${path:#$NOWHERE/bin})\n", &roots),
            vec![(1, Reason::UnresolvedReference)]
        );
        assert_eq!(
            reasons(
                "export CARGO_HOME=/var/mnt/scratch/example/cargo\npath=(${path:#$CARGO_HOME/bin})\n",
                &roots
            ),
            vec![]
        );
        // bash's removal is judged exactly as zsh's: its value as one string
        // is unknown after it, its word must resolve, and a later entry is
        // judged.
        let bash = |word: &str| format!("{}{word}{}", BASH_REMOVAL.0, BASH_REMOVAL.1);
        for (content, expected) in [
            (
                format!(
                    "export PATH=/usr/bin:/opt/x/bin\n{}\nexport INFOPATH=$PATH\n",
                    bash("/opt/x/bin")
                ),
                vec![(3, Reason::UnreadableReference)],
            ),
            (
                format!("{}\nexport PATH=$HOME/.local/state/bx:$PATH\n", bash("/a")),
                vec![(2, Reason::BxOwnedDirectory)],
            ),
            (
                format!("{}\n", bash("${NOWHERE}/bin")),
                vec![(1, Reason::UnresolvedReference)],
            ),
            (
                format!(
                    "export CARGO_HOME=/var/mnt/scratch/example/cargo\n{}\n",
                    bash("${CARGO_HOME}/bin")
                ),
                vec![],
            ),
        ] {
            assert_eq!(reasons(&content, &roots), expected, "{content:?}");
        }
        // Each is a shell's, and an `environment.d` fragment reads neither.
        for line in [
            "[[ -d /a ]] && PATH=/a:$PATH",
            "path=(${path:#/a})",
            &bash("/a"),
        ] {
            let found = scan_exported(line, &roots);
            assert_eq!(
                found.iter().map(|v| v.reason).collect::<Vec<_>>(),
                vec![Reason::Unreadable],
                "{line:?}"
            );
            assert_eq!(scan_with(line, &roots), vec![], "{line:?}");
        }
    }

    #[test]
    fn a_braced_reference_consumes_its_closing_brace() {
        // `${X}` must expand to X's value and nothing else. Leaving the `}`
        // behind would produce a path with a `}` in a component name, which is
        // a different directory — and one that is no longer inside the root.
        let content = format!("SCRATCH_HOME={ROOT}\nexport CARGO_HOME=${{SCRATCH_HOME}}/cargo\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);

        // The brace ends the name and nothing more: text after it is appended
        // verbatim, with no separator invented. `${X}suffix` therefore names a
        // *sibling* of the root, which is outside it.
        let content =
            format!("SCRATCH_HOME={ROOT}\nexport CARGO_HOME=${{SCRATCH_HOME}}suffix/cargo\n");
        let found = scan_with(&content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::OutsideDeclaredRoots);
    }

    #[test]
    fn an_unbalanced_quote_is_not_stripped() {
        // A quote that never closes is a shell syntax error wherever it sits —
        // the file stops parsing there — so it is neither stripped nor taken
        // as part of a directory's name. Stripping one would have eaten a
        // character from each end and changed which path the value names.
        for value in [
            "\"/var/mnt/scratch/example/cargo",
            "'/var/mnt/scratch/example/cargo",
            "\"",
            "'",
            "/var/mnt/scratch/example/cargo\"",
            "/var/mnt/scratch/example/cargo'",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        // Quotes around part of a value are mixed quoting, which the grammar
        // does not read, even where a shell would make one path of it. A value
        // is one quoted string or one bare word.
        for value in [
            "/var/mnt/scratch/example/\"..\"/'..'/etc",
            "/var/mnt/scratch/example/\"..\"/\"..\"/etc",
            "\"/var/mnt/scratch/example\"/cargo",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
    }

    #[test]
    fn a_dollar_that_begins_no_reference_is_refused() {
        // The expansion grammar is closed: `$NAME` and `${NAME}`, nothing else.
        // A `$` that begins neither is a special parameter or an operator that
        // a shell expands — `$@` and `$1` to nothing, which let
        // `<root>/$@/$@/../..` climb out of the root while round 2 read the
        // `$@` as literal components — so it is refused wherever it sits.
        for value in [
            "$",
            "$1/x",
            "/var/mnt/scratch/example/a$1b",
            "/var/mnt/scratch/example/$@/$@/../../etc",
            "/var/mnt/scratch/example/$*",
            "/var/mnt/scratch/example/$#",
            "/var/mnt/scratch/example/$?",
            "/var/mnt/scratch/example/$!",
            "/var/mnt/scratch/example/$$",
            "/var/mnt/scratch/example/$-",
            "/var/mnt/scratch/example/$0",
            "${/x",
            "/var/mnt/scratch/example/${FOO",
            "${FOO",
            "${}/x",
            "/var/mnt/scratch/example/${}",
            "/var/mnt/scratch/example/${1}",
            "/var/mnt/scratch/example/${HOME:+..}",
            "/var/mnt/scratch/example/${HOME#/}",
        ] {
            assert_eq!(
                reason_of(&check("CARGO_HOME", value, &rooted())),
                Some(Reason::Unreadable),
                "{value}"
            );
        }
        // `$b` on the other hand *is* a reference, and an undefined one.
        assert_eq!(
            reason_of(&check(
                "CARGO_HOME",
                "/var/mnt/scratch/example/a$b",
                &rooted()
            )),
            Some(Reason::UnresolvedReference)
        );
    }

    #[test]
    fn a_single_quoted_value_does_not_expand() {
        // `'…'` suppresses expansion in a shell, so the value is the literal
        // text `$SCRATCH_HOME/cargo`, which is not an absolute path.
        let content =
            "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME='$SCRATCH_HOME/cargo'\n";
        let found = scan_with(content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, Reason::NotAbsolute);
    }

    #[test]
    fn surrounding_double_quotes_are_stripped() {
        let content = "SCRATCH_HOME=\"/var/mnt/scratch/example\"\nexport CARGO_HOME=\"$SCRATCH_HOME/cargo\"\n";
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    // Review round 3: the guard fails closed by shape.

    #[test]
    fn the_value_grammar_reads_its_three_forms_and_nothing_else() {
        // Judged for a variable that relocates nothing, so the verdict is the
        // grammar's alone — and `check` and `scan_with` must give the same one.
        let accepted = [
            "",
            "''",
            "\"\"",
            "nvim",
            "/a_b.c,d:e@f%g+h-i",
            "'$X `x` \\ \"q\" ! ~ = # {a,b} *'",
            "\"a b=c{d}[e]*f?g#h~i'j %^&;|<>()\"",
            "\"-j8 V=1\"",
            "~",
            "~/x",
            "$HOME",
            "${HOME}",
            "$HOME/x",
            "${HOME}x",
            "${HOME}:h",
            "$HOME$HOME",
            "\"$HOME\"",
            "\"${HOME}[1]\"",
            "\"$HOME/a:$HOME\"",
            "/x # a comment",
            "/x\t# a comment",
            "\"/x\" # a comment",
        ];
        // Since round 4 every value is judged, so a form the grammar reads may
        // still be refused for where it points. What is pinned here is that no
        // accepted form is refused *as a form*, and that `check` and
        // `scan_with` agree on it.
        for value in accepted {
            let verdict = reason_of(&check("EDITOR", value, &rooted()));
            assert!(
                !matches!(
                    verdict,
                    Some(Reason::Unreadable | Reason::MultipleAssignments)
                ),
                "{value:?}: {verdict:?}"
            );
            assert_eq!(
                reasons(&format!("export EDITOR={value}"), &rooted()),
                verdict
                    .map(|reason| (1, reason))
                    .into_iter()
                    .collect::<Vec<_>>(),
                "{value:?}"
            );
        }
        for value in ["nvim", "\"nvim\"", "$HOME/x", "/x # a comment"] {
            assert_eq!(
                check("EDITOR", value, &rooted()),
                Verdict::Allowed,
                "{value:?}"
            );
        }
        let unreadable = [
            // zsh modifiers and subscripts after an unbraced name.
            "$HOME:h",
            "\"$HOME:h\"",
            "$HOME[1]",
            "\"$HOME[1]\"",
            "$HOME.y",
            "$HOME-y",
            // zsh `=cmd`, and `~` or `=` after a `:`.
            "=ls",
            "a:=ls",
            "/a:~/b",
            "~other",
            "a~",
            // Escapes, and quoting that is not one plain string.
            "\\/x",
            "\"a\\\"b\"",
            "'a'b",
            "'a''b'",
            "\"a\"'b'",
            "a\"b\"",
            "'a",
            "\"a",
            "a'",
            "$'x'",
            "$\"x\"",
            // Substitutions and expansions.
            "`x`",
            "\"`x`\"",
            "$(x)",
            "\"$(x)\"",
            "$((1))",
            "${X:-y}",
            "${#X}",
            "${X",
            "{a,b}",
            // Globs, operators, history.
            "*",
            "?",
            "[a]",
            "a;b",
            "a&b",
            "a|b",
            "a>b",
            "a<b",
            "(a)",
            "!x",
            "\"!x\"",
            "^x",
            "#x",
            "x#y",
            // A second word that is not an assignment.
            "/x cmd",
            "/x \\",
            // Characters outside printable ASCII, and control characters.
            "é",
            "\"é\"",
            "'é'",
            "\"a\tb\"",
            "'a\tb'",
            "/x\u{7}",
            "/x # \u{7}",
            "/x\r",
        ];
        for value in unreadable {
            assert_eq!(
                reason_of(&check("EDITOR", value, &rooted())),
                Some(Reason::Unreadable),
                "{value:?}"
            );
            assert_eq!(
                reasons(&format!("export EDITOR={value}"), &rooted()),
                vec![(1, Reason::Unreadable)],
                "{value:?}"
            );
        }
        // A second word with an `=` in it is a second assignment only when
        // what precedes the `=` is a name; otherwise it is a command's
        // argument, which the grammar does not read either.
        for value in ["nvim --wait=1", "/x a-b=c", "/x 2a=b", "/x =b"] {
            assert_eq!(
                reason_of(&check("EDITOR", value, &rooted())),
                Some(Reason::Unreadable),
                "{value:?}"
            );
        }
        // Given to a location, `~` alone is the home, which contains bx's
        // directories (r3 round 2), and `/a://b` starts at the filesystem root
        // however URL-like its middle.
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~", &rooted())),
            Some(Reason::ContainsBxDirectory)
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "/a://b", &rooted())),
            Some(Reason::OutsideDeclaredRoots)
        );
        for value in ["/x A=1", "/x\tA=1", "'/x' A=1"] {
            assert_eq!(
                reason_of(&check("EDITOR", value, &rooted())),
                Some(Reason::MultipleAssignments),
                "{value:?}"
            );
        }
        // A name `check` is handed that no shell could assign.
        for name in ["", "2bad", "A-B", "A B", "É"] {
            assert_eq!(
                reason_of(&check(name, "/x", &rooted())),
                Some(Reason::Unreadable),
                "{name:?}"
            );
        }
    }
}
