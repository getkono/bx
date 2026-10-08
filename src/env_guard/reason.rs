//! What the guard answers: a verdict, and for every refusal the reason that
//! names what the user can do about it.

/// Why an assignment was rejected.
///
/// Each names a different user action — declare a root, fix the declared root,
/// split the line, write the line in the grammar the guard reads, use a name
/// the shell does not manage, use a name bx may generate, move the value out of
/// bx's own directory, move it out of bx's config repo, point it beside bx's
/// directories rather than around them, write a path of plain characters with
/// no `..`, move it inside a declared root, point it beneath a declared root
/// rather than at one, write an absolute path,
/// give a program no arguments, begin a command line with a program, write a
/// command line with nothing a later shell expands, set no relocating variable
/// inside a command line, give a setting a value it accepts, define the
/// referenced variable earlier, give the guard a home, fix the line
/// that assigned it, shorten it — so a caller that only knew *which* variable
/// was rejected could not say what to do about it. The messages name no data:
/// the caller already holds the value and the root set, and prints them itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    /// Nothing was declared, so nothing may be relocated.
    #[error("no root is declared, so nothing may be relocated")]
    NoRootsDeclared,
    /// Roots were declared, and every one of them was refused.
    #[error(
        "every declared root was refused — the filesystem root, a relative path, \
         or one that climbs — so nothing may be relocated"
    )]
    InadmissibleRoot,
    /// The line assigns more than one variable.
    #[error("puts more than one assignment on one line")]
    MultipleAssignments,
    /// A line, or a value, that is not in the grammar [`scan_with`](super::scan_with) reads —
    /// any keyword but `export`, any quoting or escaping but one plain quoted
    /// string, a substitution other than `$NAME` and `${NAME}`, a special
    /// parameter, an operator, an unclosed quote, a control character.
    #[error("is shell the guard cannot read, so it is not approved")]
    Unreadable,
    /// It assigns a name the shell manages itself — `HOME`, `RANDOM`, zsh's
    /// tied `path` — or acts on when it is assigned; or it *refers* to one of
    /// them other than `HOME`, which resolves against the root set's home
    /// instead ([`Scope::lookup`](super::scope::Scope::lookup)).
    #[error("assigns or refers to a name the shell manages itself")]
    ReservedName,
    /// It assigns a variable no bx generator declares, whatever the value: the
    /// guard cannot tell what a name it does not know holds. bx generates every
    /// fragment the guard judges, so this is a defect in bx — a generator that
    /// did not add its name to the emit table — and not in the user's
    /// configuration.
    #[error(
        "assigns a variable no bx generator declares, so bx cannot judge the \
         value — a defect in bx, not in your configuration"
    )]
    NotEmittable,
    /// It points at a directory bx owns, whatever the roots say.
    #[error("points inside a directory bx owns")]
    BxOwnedDirectory,
    /// It points inside bx's config repo — a committed tree, safe to make
    /// public — whatever the roots say.
    #[error("points inside bx's config repo, which is committed and may be public")]
    InsideConfigRepo,
    /// A location that contains bx's state directory or its config repo. The
    /// tool it is given to clears it — a cache clean, a prune — and deletes
    /// bx's record, or the user's repo, along with its own files.
    #[error("contains bx's state directory or its config repo, which the tool may clear")]
    ContainsBxDirectory,
    /// It resolves to a path, but not one inside any declared root.
    #[error("resolves outside every declared root")]
    OutsideDeclaredRoots,
    /// A location, or an entry of a list of locations, that is a declared root
    /// itself rather than a path beneath one. A tool may derive a directory
    /// beside its own: uv puts executables in `$XDG_DATA_HOME/../bin`, and so
    /// does every tool built on dirs-next, which lands outside every root when
    /// the value is one. A tool given a whole root also clears everything else
    /// the root holds. Point the value beneath the root.
    ///
    /// **The rule covers one level above the value, and no more.** Refusing a
    /// value that is a root leaves every approved value with a parent inside a
    /// declared root, so the directory a tool derives one level up is inside
    /// one too. It says nothing about the grandparent: a value one level
    /// beneath a root is approved, and `<value>/../..` is the root's own
    /// parent, outside every root. A tool that derives a path **two or more
    /// levels above its value is not modelled**, and bx knows of none.
    /// [`Kind::Location`](super::table::Kind::Location) states the same bound, and
    /// `the_rule_covers_one_level_above_a_location_and_no_more` pins it.
    ///
    /// Every other reason outranks it, at any entry and in a location's whole
    /// value: every entry, and then the whole value, is judged for bx's
    /// directories, and every entry for lying inside a root, before any entry
    /// is judged for being a root. Nothing is asked of a location's whole value
    /// after that, because nothing asked there could refuse: once no entry is a
    /// root itself, the whole value and its parent lie inside the root the
    /// first entry lies beneath (#47 round 3).
    #[error("is a declared root itself, and its tool may write beside it, outside every root")]
    DeclaredRootItself,
    /// Empty, a bare word, a URL, or a relative path, where a path that can be
    /// shown to be somewhere is needed. For a list, one of its entries is.
    #[error("is not an absolute path")]
    NotAbsolute,
    /// A path with a `..` component, in any kind that holds one. It can climb
    /// out of where it appears to point — across a symlink, or past text a
    /// tool expands before it resolves the path — and nothing bx generates
    /// needs one.
    #[error("has a `..` component, so where it points cannot be shown")]
    ParentComponent,
    /// A path — a location, an entry of a list, a socket — holding a character
    /// other than those every path bx writes is made of: ASCII letters and
    /// digits, `.`, `_`, `-`, `+` and `/`, and `:` only between the entries of
    /// a list. Tools read other characters their own way — npm and pnpm expand
    /// `${NAME}`, NuGet `%NAME%`, and bun takes `\` for a separator — into a
    /// path nothing judged, and nothing bx generates needs one. It names the
    /// first such character.
    #[error("holds {0:?}, a character no path bx writes may hold")]
    UnlistedCharacter(char),
    /// A program given something other than exactly one absolute path or one
    /// bare command name: an argument, a `:` list, a URL, nothing at all.
    #[error("is not one program — an absolute path or a bare command name, with no arguments")]
    NotAProgram,
    /// A command line whose first word is not one program: nothing, a
    /// relative path, an option, a URL.
    #[error("does not begin with one program — an absolute path or a bare command name")]
    NotACommandLine,
    /// A command line or options holding `$`, a backquote, a backslash, a
    /// `~NAME`, or a glob or brace in a path: the shell that runs it expands
    /// them later, into words nothing judged.
    #[error(
        "holds an expansion the shell running it performs later, so what it names cannot be shown"
    )]
    LaterExpansion,
    /// A command line or options naming a variable that moves a tool's
    /// config, data or cache ([`is_relocating`](super::is_relocating)) — `env XDG_CONFIG_HOME=…
    /// nvim`, `for HOME in …`, `read HOME` — which a shell running it could
    /// assign where the guard would never judge it.
    #[error("names a variable that relocates a tool's files, which its command line could assign")]
    RelocatingAssignment,
    /// A setting given a value it does not accept.
    #[error("is not a value this setting accepts")]
    NotASetting,
    /// It names a variable this fragment has not assigned by this line.
    #[error("refers to a variable this fragment has not assigned")]
    UnresolvedReference,
    /// It refers to the home — `~`, `$HOME` — and the guard was given no home
    /// to expand it against, as [`scan`](super::scan) is not.
    #[error("refers to the home directory, and the guard was given none")]
    NoHome,
    /// It names a variable whose assignment the guard could not read, or comes
    /// after a line the guard refused, after which nothing assigned is known.
    #[error("refers to a variable whose assignment the guard could not read")]
    UnreadableReference,
    /// Its expansion grows past [`MAX_EXPANDED_LEN`](super::lex::MAX_EXPANDED_LEN).
    #[error("expands past the guard's length bound")]
    ExpansionTooLong,
}

/// What [`check`](super::check) decided about one assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// bx may write this assignment.
    Allowed,
    /// bx may not, for this reason.
    Violation(Violation),
}

/// A forbidden assignment found in generated shell content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// 1-based line number within the scanned content.
    ///
    /// A violation returned by [`check`](super::check), which judges one assignment outside
    /// any content, carries `0`: there is no line to point at.
    pub line: usize,
    /// The variable being assigned.
    ///
    /// Empty for a line refused as [`Reason::Unreadable`] before any one
    /// variable could be picked out of it.
    pub name: String,
    /// Everything written after `NAME=`, trailing comment included, so a
    /// diagnostic can quote it back exactly as the user will see it.
    ///
    /// For a line refused before any one variable could be picked out of it,
    /// the line itself, without its indentation.
    pub value: String,
    /// Why the assignment was rejected.
    pub reason: Reason,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// The sentence a [`Reason`] renders as, and the variant that follows it
    /// in declaration order.
    ///
    /// One exhaustive `match`, so a [`Reason`] added and not given a sentence
    /// here does not compile. The `next` half chains every variant into a
    /// single walk, so a variant cannot be given a sentence and then left
    /// unvisited by the test.
    ///
    /// That is why `the_reasons_render_as_sentences` walks a chain instead of
    /// asserting a list of variants: a list can be short by one and still
    /// compile, and that is exactly how `InsideConfigRepo` came to be the one
    /// message no test asserted (round-2 note COV2) under an earlier repair
    /// that had claimed every message was pinned. A list of *n* things that
    /// was a list of *n - 1* last time is evidence the list is the wrong
    /// shape.
    fn sentence_and_next(reason: Reason) -> (String, Option<Reason>) {
        use Reason::*;
        let (sentence, next) = match reason {
            NoRootsDeclared => (
                "no root is declared, so nothing may be relocated".to_string(),
                Some(InadmissibleRoot),
            ),
            InadmissibleRoot => (
                "every declared root was refused — the filesystem root, a relative \
                 path, or one that climbs — so nothing may be relocated"
                    .to_string(),
                Some(MultipleAssignments),
            ),
            MultipleAssignments => (
                "puts more than one assignment on one line".to_string(),
                Some(Unreadable),
            ),
            Unreadable => (
                "is shell the guard cannot read, so it is not approved".to_string(),
                Some(ReservedName),
            ),
            ReservedName => (
                "assigns or refers to a name the shell manages itself".to_string(),
                Some(NotEmittable),
            ),
            NotEmittable => (
                "assigns a variable no bx generator declares, so bx cannot judge \
                 the value — a defect in bx, not in your configuration"
                    .to_string(),
                Some(BxOwnedDirectory),
            ),
            BxOwnedDirectory => (
                "points inside a directory bx owns".to_string(),
                Some(InsideConfigRepo),
            ),
            InsideConfigRepo => (
                "points inside bx's config repo, which is committed and may be public".to_string(),
                Some(ContainsBxDirectory),
            ),
            ContainsBxDirectory => (
                "contains bx's state directory or its config repo, which the tool may clear"
                    .to_string(),
                Some(OutsideDeclaredRoots),
            ),
            OutsideDeclaredRoots => (
                "resolves outside every declared root".to_string(),
                Some(DeclaredRootItself),
            ),
            DeclaredRootItself => (
                "is a declared root itself, and its tool may write beside it, outside every root"
                    .to_string(),
                Some(NotAbsolute),
            ),
            NotAbsolute => ("is not an absolute path".to_string(), Some(ParentComponent)),
            ParentComponent => (
                "has a `..` component, so where it points cannot be shown".to_string(),
                Some(UnlistedCharacter('\\')),
            ),
            // The one variant carrying data, so its sentence is formatted
            // rather than fixed. The wording either side of the character is
            // still written out here, so an edit to the `#[error]` text fails.
            UnlistedCharacter(held) => (
                format!("holds {held:?}, a character no path bx writes may hold"),
                Some(NotAProgram),
            ),
            NotAProgram => (
                "is not one program — an absolute path or a bare command name, with no arguments"
                    .to_string(),
                Some(NotACommandLine),
            ),
            NotACommandLine => (
                "does not begin with one program — an absolute path or a bare command name"
                    .to_string(),
                Some(LaterExpansion),
            ),
            LaterExpansion => (
                "holds an expansion the shell running it performs later, so what it names \
                 cannot be shown"
                    .to_string(),
                Some(RelocatingAssignment),
            ),
            RelocatingAssignment => (
                "names a variable that relocates a tool's files, which its command line \
                 could assign"
                    .to_string(),
                Some(NotASetting),
            ),
            NotASetting => (
                "is not a value this setting accepts".to_string(),
                Some(UnresolvedReference),
            ),
            UnresolvedReference => (
                "refers to a variable this fragment has not assigned".to_string(),
                Some(NoHome),
            ),
            NoHome => (
                "refers to the home directory, and the guard was given none".to_string(),
                Some(UnreadableReference),
            ),
            UnreadableReference => (
                "refers to a variable whose assignment the guard could not read".to_string(),
                Some(ExpansionTooLong),
            ),
            ExpansionTooLong => ("expands past the guard's length bound".to_string(), None),
        };
        (sentence, next)
    }

    /// The name of every variant [`Reason`] declares, read out of this
    /// module's own source.
    ///
    /// The exhaustive `match` in [`sentence_and_next`] forces a new [`Reason`]
    /// to be given a *sentence*. It does not force the variant to be any arm's
    /// `next`, and round 3 proved exactly that: a variant added with an
    /// `#[error]` and a terminating arm, chained from nothing, left the suite
    /// green because the count it was checked against was the hand-written
    /// `20`. **A mechanism built to replace a list must not contain a list**,
    /// and a hand-maintained number is a list of one.
    ///
    /// So the census is re-derived from the enum at every run instead. Rust
    /// cannot enumerate an enum's variants without a derive macro, and adding
    /// a crate for it is not this module's decision — but the declaration is
    /// in this module's source, and the census reads it from there at run
    /// time. `testing::tests::no_user_specific_literal_survives_in_a_tracked_file`
    /// already establishes source-reading as how this repository holds a
    /// property no type can carry.
    ///
    /// The module is read whole — `env_guard.rs` and every file beneath
    /// `env_guard/` — and the declaration is found by its content, a line that
    /// is exactly `pub enum Reason {`, so splitting the module does not move
    /// the enum out of the census's sight. Exactly one such line must exist.
    ///
    /// Returns names rather than a count, so the walk can say *which* variant
    /// it never reached.
    fn declared_reasons() -> Vec<&'static str> {
        static DECLARATION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let declaration = DECLARATION.get_or_init(|| {
            let mut found = Vec::new();
            for (path, source) in crate::testing::module_sources("env_guard") {
                let mut offset = 0;
                for line in source.split_inclusive('\n') {
                    if line.trim() == "pub enum Reason {" {
                        found.push((path.clone(), source[offset..].to_string()));
                    }
                    offset += line.len();
                }
            }
            let sites: Vec<_> = found.iter().map(|(path, _)| path).collect();
            assert_eq!(
                found.len(),
                1,
                "the Reason enum is declared once in this module, found at {sites:?}"
            );
            found.remove(0).1
        });
        reasons_declared_in(declaration)
    }

    /// The same census, over any source text.
    ///
    /// Split out from [`declared_reasons`] for one reason: **the census had no
    /// defender**. Round 5 measured that deleting both the comment strip and
    /// the whole cross-check below left the suite at 567 passed, 0 failed —
    /// and that is the structural reason this one defect has now recurred
    /// three times. Every generation was a better mechanism than the last, and
    /// not one of them was observable from inside the suite; each was caught
    /// by a reviewer's out-of-tree probe. A mechanism the suite cannot watch
    /// fail is a mechanism that regresses silently.
    ///
    /// Taking `source` as an argument is what lets the probes live in the
    /// repository. `the_census_*` below feed it synthetic declarations holding
    /// the shapes the real enum does not contain, so the strip and the
    /// cross-check each have a test that fails when it is removed.
    fn reasons_declared_in(source: &str) -> Vec<&str> {
        let body = source
            .split_once("pub enum Reason {")
            .expect("the Reason enum is declared in this file")
            .1
            .split_once("\n}\n")
            .expect("the Reason enum is closed")
            .0;
        let names: Vec<&str> = body
            .lines()
            .map(|line| line.trim())
            // A trailing `// note` is legal, `cargo fmt` keeps it, and reading
            // the line without dropping it hid `ProbeVariant, // note` from
            // round 4's probe entirely.
            .map(|line| line.split("//").next().unwrap_or(line).trim())
            .filter_map(|line| line.strip_suffix(','))
            // A variant is `Name,` or `Name(Type),`. Doc comments, `#[error]`
            // attributes and their wrapped strings are none of those shapes.
            // The payload is dropped, so the name matches what `Debug` prints.
            .filter_map(|line| {
                let head = line.split('(').next().unwrap_or(line);
                let shaped = !head.is_empty()
                    && head.starts_with(|c: char| c.is_ascii_uppercase())
                    && head.chars().all(|c| c.is_ascii_alphanumeric())
                    && (head.len() == line.len() || line.ends_with(')'));
                shaped.then_some(head)
            })
            .collect();
        // **The census is checked against a second count read out of the same
        // block**, and that is what makes it a property rather than another
        // pattern that holds until it does not.
        //
        // `thiserror` requires an `#[error(...)]` on every variant of this
        // enum — the crate will not derive `Display` without one — so the
        // number of message attributes in the block *is* the number of
        // variants, arrived at by a different route than reading the variant
        // lines. Two counts from one source: a variant that hides from the
        // name scrape has to hide from the message count as well.
        //
        // **What that does and does not buy, stated exactly.** Round 5 found
        // generation five: `#[error ("probe")]` — a space before the paren —
        // with `ProbeVariant /* note */,` moved *both* counts together, and
        // the claim written here, that nothing hiding a message attribute
        // still compiles, was false. It compiles. The whitespace is tolerated
        // below, which closes that shape; but this is a text reader, and no
        // text reader is complete against every spelling Rust accepts.
        //
        // What closes the rest is **`cargo fmt --check`**, an enforced gate —
        // a CI row and an `hk` pre-commit hook — which normalises attribute
        // spelling before any of this is read. So the invariant is not "no
        // hidden variant compiles"; it is **"no hidden variant survives a
        // formatted tree"**, and the formatter is the co-gate that makes the
        // two counts trustworthy. `the_census_refuses_a_declaration_it_cannot_account_for`
        // pins the cross-check; `the_formatter_normalises_what_the_census_reads`
        // pins the part `cargo fmt` is relied on for.
        let messages = body
            .lines()
            .map(|line| line.trim_start())
            .filter(|line| {
                line.strip_prefix("#[error")
                    .is_some_and(|rest| rest.trim_start().starts_with('('))
            })
            .count();
        assert_eq!(
            names.len(),
            messages,
            "the Reason census read {names:?} out of the source, but the enum declares \
             {messages} messages — a variant the scrape cannot see, or one it invented"
        );
        assert!(
            messages > 0,
            "no message attribute in the Reason enum, so the scrape is lost"
        );
        names
    }

    /// A synthetic `Reason` declaration holding `variant`, so the census can be
    /// held to shapes the real enum does not contain.
    fn probe_declaration(variant: &str) -> String {
        format!(
            "pub enum Reason {{\n    \
             /// The first.\n    #[error(\"first\")]\n    First,\n{variant}\n}}\n"
        )
    }

    #[test]
    fn the_census_reads_past_a_trailing_comment() {
        // Round 4's probe, now inside the suite. Deleting the `//` strip in
        // `reasons_declared_in` makes this fail: the variant stops being
        // counted as a name while its message is still counted, so the
        // cross-check fires.
        let source = probe_declaration("    #[error(\"probe\")]\n    ProbeVariant, // note");
        assert_eq!(reasons_declared_in(&source), vec!["First", "ProbeVariant"]);
    }

    #[test]
    #[should_panic(expected = "a variant the scrape cannot see")]
    fn the_census_refuses_a_declaration_it_cannot_account_for() {
        // Round 4's probe C: a block comment, which the `//` strip does not
        // touch, so the name scrape cannot see the variant at all. Only the
        // cross-count catches it — deleting the cross-check makes this fail,
        // which is what the census lacked for three generations.
        let source = probe_declaration("    #[error(\"probe\")]\n    ProbeVariant /* note */,");
        let _ = reasons_declared_in(&source);
    }

    #[test]
    #[should_panic(expected = "a variant the scrape cannot see")]
    fn the_census_sees_a_message_attribute_however_it_is_spaced() {
        // Round 5's generation five: `#[error (` moved both counts together,
        // so the cross-check agreed with itself and the variant hid. The
        // message count tolerates the space now, so the counts disagree and
        // the hidden variant is named.
        let source = probe_declaration("    #[error (\"probe\")]\n    ProbeVariant /* note */,");
        let _ = reasons_declared_in(&source);
    }

    #[test]
    fn the_formatter_normalises_what_the_census_reads() {
        // The census is a text reader, so it is only as good as the text. This
        // names the co-gate the paragraph in `reasons_declared_in` relies on:
        // `cargo fmt` is not optional here, it is a CI row and a pre-commit
        // hook, and it rewrites the attribute spellings a reader cannot chase.
        // If this repository ever stops enforcing formatting, the census's
        // guarantee weakens to exactly this test's absence.
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("hk.pkl")
                .exists(),
            "hk.pkl is what runs `cargo fmt` before a commit; without it the census \
             below is reading text nothing normalises"
        );
        let ci = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml"),
        )
        .expect("the CI workflow");
        assert!(
            ci.contains("format-check"),
            "no formatting gate in CI, so `reasons_declared_in` may be reading unformatted \
             source and its two counts can be made to agree by spacing alone"
        );
    }

    #[test]
    fn the_reason_census_is_read_from_the_declaration() {
        // The scrape is itself a mechanism, so it gets a test that fails if it
        // silently stops seeing variants. `UnlistedCharacter(char)` is the one
        // variant carrying data, and the one whose shape the filter could
        // plausibly drop.
        let names = declared_reasons();
        assert!(names.contains(&"UnlistedCharacter"), "{names:?}");
        assert!(names.contains(&"InsideConfigRepo"), "{names:?}");
        // No doc prose or `#[error]` text leaked in: every name is one
        // identifier.
        for name in &names {
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric()),
                "{name:?} is not a variant name"
            );
        }
        // And it is a set, not a list with repeats.
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "{names:?}");
    }

    #[test]
    fn the_reasons_render_as_sentences() {
        // The messages name no data: a caller prints the value and the roots.
        let mut reason = Some(Reason::NoRootsDeclared);
        //
        // The walk is held to the census read out of the declaration, so a
        // `Reason` given a sentence but never chained in is named here by the
        // variant it is, rather than passing because a hand-written count
        // nobody updated still agreed with itself.
        let declared = declared_reasons();
        let mut walked: Vec<String> = Vec::new();
        while let Some(current) = reason {
            let (sentence, next) = sentence_and_next(current);
            assert_eq!(current.to_string(), sentence, "{current:?}");
            let debug = format!("{current:?}");
            let name = debug.split('(').next().unwrap_or(&debug).to_string();
            assert!(
                !walked.contains(&name),
                "the chain revisits {name} after {walked:?}"
            );
            walked.push(name);
            assert!(
                walked.len() <= declared.len(),
                "the chain outruns the declaration: {walked:?}"
            );
            reason = next;
        }
        let missed: Vec<&&str> = declared
            .iter()
            .filter(|name| !walked.iter().any(|seen| seen == *name))
            .collect();
        assert!(
            missed.is_empty(),
            "declared, but never reached by the chain, so their messages are \
             asserted by nothing: {missed:?}"
        );
    }
}
