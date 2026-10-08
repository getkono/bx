//! What one walk over a fragment has learned its earlier lines assign, and
//! what a reference to a name resolves to from there.

use std::collections::HashMap;
use std::path::Path;

use super::Judged;
use super::reason::Reason;
use super::table::is_reserved;

/// What an unassigned reference to a search list's own name expands to while
/// the list is judged. No accepted value holds a control character, so no
/// entry a fragment writes can equal it.
pub(super) const INHERITED: &str = "\0";

/// What one walk over a fragment has learned it assigns.
#[derive(Debug, Default)]
pub(super) struct Scope {
    /// What each accepted assignment expanded to, or why the guard cannot know.
    pub(super) learned: HashMap<String, Result<String, Reason>>,
    /// Whether a refused line has passed. After one nothing is known, because
    /// the guard did not read what it assigned or unset.
    pub(super) lost: bool,
    /// What each search list the fragment assigned extends, [`INHERITED`]
    /// standing for the list the shell inherited. Every assignment sets or
    /// removes its name's entry, and a refused line clears them all.
    extended: HashMap<String, String>,
}

impl Scope {
    /// What a reference to `name` expands to.
    ///
    /// A name the fragment assigned wins, as it would in a shell. `HOME` comes
    /// from the root set, and is the only value not learned from the fragment —
    /// which is why a fragment may not assign it.
    pub(super) fn lookup(&self, name: &str, home: Option<&Path>) -> Result<String, Reason> {
        if let Some(known) = self.learned.get(name) {
            return known.clone();
        }
        if self.lost {
            return Err(Reason::UnreadableReference);
        }
        if name == "HOME" {
            return home
                .map(|home| home.to_string_lossy().into_owned())
                .ok_or(Reason::NoHome);
        }
        Err(if is_reserved(name) {
            Reason::ReservedName
        } else {
            Reason::UnresolvedReference
        })
    }

    /// Whether a reference to `name` is to the value the shell inherited:
    /// nothing in the fragment has assigned it, and no refused line could have.
    fn inherits(&self, name: &str) -> bool {
        !self.lost && !self.learned.contains_key(name)
    }

    /// What a search list's reference to its own `name` expands to while the
    /// list is judged: the inherited list, or the list the fragment's earlier
    /// extensions of it made, or else whatever [`Scope::lookup`] says.
    pub(super) fn own_list(&self, name: &str, home: Option<&Path>) -> Result<String, Reason> {
        if self.inherits(name) {
            return Ok(INHERITED.to_string());
        }
        match self.extended.get(name) {
            Some(list) => Ok(list.clone()),
            None => self.lookup(name, home),
        }
    }

    /// Learn what an assignment the walk has just judged gave its name.
    ///
    /// Only *after* judging it, as a shell does: the right-hand side sees the
    /// previous value of the name, not this one. A value the grammar refused
    /// is not a value any shell gives the name, and a line that assigns a
    /// name the shell manages may change another name with it, so either
    /// forgets everything.
    pub(super) fn learn(&mut self, name: &str, judged: Judged) {
        match judged.reason {
            Some(Reason::Unreadable | Reason::MultipleAssignments | Reason::ReservedName) => {
                self.forget_everything();
            }
            _ => {
                match judged.extended {
                    Some(list) => {
                        self.extended.insert(name.to_string(), list);
                    }
                    None => {
                        self.extended.remove(name);
                    }
                }
                self.learned
                    .insert(name.to_string(), judged.resolved.map_err(as_reference));
            }
        }
    }

    /// After a [`Statement::Gated`](super::lex::Statement::Gated) assignment to the search
    /// list `name`, which the shell may or may not have made.
    ///
    /// The list's extension stays as the assignment left it: its entries are
    /// every entry either outcome holds, and a search list is judged entry by
    /// entry, so judging them all covers both. Its value as one string is
    /// known in neither case, so a reference to it is unreadable.
    pub(super) fn perhaps(&mut self, name: &str) {
        if !self.lost {
            self.learned
                .insert(name.to_string(), Err(Reason::UnreadableReference));
        }
    }

    /// After a [`Statement::Removal`](super::lex::Statement::Removal) took entries out of
    /// the search list `name`.
    ///
    /// What is left is some of what was there, so the extension already
    /// known — the inherited list itself, when nothing has assigned it yet —
    /// still holds every entry the list can hold. Its value as one string is
    /// no longer known.
    pub(super) fn narrowed(&mut self, name: &str) {
        if self.lost {
            return;
        }
        if self.inherits(name) {
            self.extended
                .insert(name.to_string(), INHERITED.to_string());
        }
        self.learned
            .insert(name.to_string(), Err(Reason::UnreadableReference));
    }

    /// After a guarded block closes, know nothing about what it assigned: the
    /// shell may or may not have run it, so each name holds either its value
    /// from before the block or the one inside it. A later reference to one is
    /// [`Reason::UnreadableReference`], and a search list extends nothing the
    /// guard can name.
    pub(super) fn forget_conditional(&mut self, assigned: &[String]) {
        for name in assigned {
            self.learned
                .insert(name.clone(), Err(Reason::UnreadableReference));
            self.extended.remove(name);
        }
    }

    /// After a line the guard did not read, know nothing.
    pub(super) fn forget_everything(&mut self) {
        self.learned.clear();
        self.extended.clear();
        self.lost = true;
    }
}

/// The reason a *reference* to a name reports, given why the name's own value
/// could not be known.
fn as_reference(reason: Reason) -> Reason {
    match reason {
        Reason::UnresolvedReference | Reason::NoHome | Reason::ExpansionTooLong => reason,
        _ => Reason::UnreadableReference,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::env_guard::fixtures::*;
    use crate::env_guard::lex::MAX_EXPANDED_LEN;
    use crate::env_guard::*;
    use crate::testing::guarded_home;

    #[test]
    fn a_reference_assigned_earlier_in_the_file_is_expanded() {
        let content =
            "SCRATCH_HOME=/var/mnt/scratch/example\nexport CARGO_HOME=$SCRATCH_HOME/cargo\n";
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn a_reference_assigned_later_in_the_file_is_unresolved() {
        // A shell reading top to bottom would not have it either, so neither
        // does the guard. Order-dependence here is correctness.
        let content =
            "export CARGO_HOME=$SCRATCH_HOME/cargo\nSCRATCH_HOME=/var/mnt/scratch/example\n";
        let found = scan_with(content, &rooted());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[0].reason, Reason::UnresolvedReference);
    }

    #[test]
    fn a_chained_reference_resolves_through_two_hops() {
        let content = concat!(
            "SCRATCH_HOME=/var/mnt/scratch/example\n",
            "CACHE_DIR=$SCRATCH_HOME/cache\n",
            "export GOPATH=$CACHE_DIR/go\n",
            "export GOMODCACHE=$GOPATH/pkg/mod\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
    }

    #[test]
    fn several_references_in_one_value_are_all_substituted() {
        // One pass substitutes every reference in the value, so this resolves
        // in one hop however many there are. It is also what pins the pass's
        // own bound: a bound too small to visit them all leaves a `$` behind,
        // and the value stops resolving.
        let content = concat!(
            "A=/var/mnt/scratch/example\n",
            "B=cache\n",
            "C=cargo\n",
            "export CARGO_HOME=$A/$B/$C/$B/$C/$B\n",
        );
        // The helpers are not in the emit table (round 5); the line that uses
        // them resolves inside the root and is not refused.
        assert_eq!(
            reasons(content, &rooted()),
            vec![
                (1, Reason::NotEmittable),
                (2, Reason::NotEmittable),
                (3, Reason::NotEmittable)
            ]
        );
    }

    #[test]
    fn a_chain_of_references_resolves_however_deep_it_is() {
        // `X0` is the literal root and each link refers to the one below it. A
        // shell expands each link when it is assigned, so the depth of the
        // chain is never the depth of any one expansion — and neither is it
        // here, because values are learned expanded. A nine-deep chain was
        // once refused as "refers to a variable this fragment has not
        // assigned", every link of which it had assigned.
        fn chain(links: usize) -> String {
            let mut content = format!("X0={ROOT}\n");
            for link in 1..=links {
                content.push_str(&format!("X{link}=$X{}\n", link - 1));
            }
            content.push_str(&format!("export CARGO_HOME=$X{links}/cargo\n"));
            content
        }
        // The links are helpers the emit table does not list, so each one is
        // `NotEmittable` (round 5). What is pinned is that the line using the
        // chain resolves inside the root and is not refused.
        for links in [1, 7, 8, 9, 64] {
            let helpers: Vec<(usize, Reason)> = (1..=links + 1)
                .map(|line| (line, Reason::NotEmittable))
                .collect();
            assert_eq!(reasons(&chain(links), &rooted()), helpers, "{links}");
        }
    }

    #[test]
    fn substituted_text_is_not_expanded_again() {
        // `DATA_DIR='$CACHE_DIR'` holds the characters `$CACHE_DIR`, and a
        // shell that later expands `$DATA_DIR` yields them and stops. Expanding
        // them again would judge a path no shell produces. `CACHE_DIR` is a
        // location and `DATA_DIR` an anchor, and each is judged as one, where
        // a single-quoted `$` is relative either way. The line that uses the literal
        // inside the root holds a `$` a tool could expand itself, so since r3
        // round 2 it is refused for that, and not for where a second
        // expansion would point.
        let content =
            format!("CACHE_DIR=/etc\nDATA_DIR='$CACHE_DIR'\nexport CARGO_HOME={ROOT}/$DATA_DIR\n");
        assert_eq!(
            reasons(&content, &rooted()),
            vec![
                (1, Reason::OutsideDeclaredRoots),
                (2, Reason::NotAbsolute),
                (3, Reason::UnlistedCharacter('$'))
            ]
        );
        // Expanded once, `$DATA_DIR/cargo` is `$CACHE_DIR/cargo`: relative.
        // Expanded twice it would be inside the root and approved. Since #45,
        // `CACHE_DIR` is a location, and at the root itself it is refused too.
        let content =
            format!("CACHE_DIR={ROOT}\nDATA_DIR='$CACHE_DIR'\nexport CARGO_HOME=$DATA_DIR/cargo\n");
        assert_eq!(
            reasons(&content, &rooted()),
            vec![
                (1, Reason::DeclaredRootItself),
                (2, Reason::NotAbsolute),
                (3, Reason::NotAbsolute)
            ]
        );
    }

    #[test]
    fn a_value_that_extends_itself_resolves_as_a_shell_would() {
        // `X=$X/b` sees the previous `X`, so it is one more path component
        // under the root, not a value that grows without end.
        let content = concat!(
            "SCRATCH_HOME=/var/mnt/scratch/example\n",
            "SCRATCH_HOME=$SCRATCH_HOME/b\n",
            "export CARGO_HOME=$SCRATCH_HOME/cargo\n",
        );
        assert_eq!(scan_with(content, &rooted()), vec![]);
        // Before it is assigned, the same line refers to nothing — and a value
        // that does not resolve is refused for that, so both lines say so.
        assert_eq!(
            reasons(
                "SCRATCH_HOME=$SCRATCH_HOME/b\nexport CARGO_HOME=$SCRATCH_HOME/cargo\n",
                &rooted()
            ),
            vec![
                (1, Reason::UnresolvedReference),
                (2, Reason::UnresolvedReference)
            ]
        );
    }

    #[test]
    fn two_values_that_refer_to_each_other_do_not_resolve() {
        // A true two-node cycle. `A=$B` refers to a `B` not yet assigned, so
        // `A` is unresolvable, and `B=$A` inherits that. A value that does not
        // resolve cannot be shown not to be a path, so every line is refused.
        let content = concat!(
            "CACHE_DIR=$DATA_DIR\n",
            "DATA_DIR=$CACHE_DIR\n",
            "export CARGO_HOME=$CACHE_DIR/cargo\n"
        );
        assert_eq!(
            reasons(content, &rooted()),
            vec![
                (1, Reason::UnresolvedReference),
                (2, Reason::UnresolvedReference),
                (3, Reason::UnresolvedReference)
            ]
        );
    }

    #[test]
    fn an_expansion_that_grows_past_the_length_bound_is_refused_for_its_length() {
        // Values are learned expanded, so a line that doubles a value doubles
        // what is stored; the length bound is what keeps that from growing
        // without end. The reason says so, rather than that a variable the
        // fragment plainly assigned was never assigned.
        let long = format!("{ROOT}/{}", "a".repeat(MAX_EXPANDED_LEN / 2));
        // `Y` is judged too, as every value is (round 4).
        let content = format!(
            "SCRATCH_HOME={long}\nCACHE_DIR=$SCRATCH_HOME$SCRATCH_HOME\nexport CARGO_HOME=$CACHE_DIR/cargo\n"
        );
        assert_eq!(
            reasons(&content, &rooted()),
            vec![(2, Reason::ExpansionTooLong), (3, Reason::ExpansionTooLong)]
        );
        // And the same bound applies to the value being judged itself.
        let content =
            format!("SCRATCH_HOME={long}\nexport CARGO_HOME=$SCRATCH_HOME$SCRATCH_HOME\n");
        assert_eq!(
            scan_with(&content, &rooted())
                .iter()
                .map(|violation| violation.reason)
                .collect::<Vec<_>>(),
            vec![Reason::ExpansionTooLong]
        );

        // The identical shape, under the bound, resolves — so the assertion
        // above pins the bound and not the shape.
        let short = format!("{ROOT}/{}", "a".repeat(16));
        let content = format!(
            "SCRATCH_HOME={short}\nCACHE_DIR=$SCRATCH_HOME$SCRATCH_HOME\nexport CARGO_HOME=$CACHE_DIR/cargo\n"
        );
        assert_eq!(scan_with(&content, &rooted()), vec![]);
    }

    #[test]
    fn an_unknown_reference_is_a_violation() {
        // Silently expanding an unset name to the empty string is exactly the
        // failure this guard exists to catch, so it is an error instead.
        for value in ["$NOWHERE/cargo", "${NOWHERE}/cargo", "/a/$NOWHERE"] {
            let found = scan_with(&format!("export CARGO_HOME={value}\n"), &rooted());
            assert_eq!(found.len(), 1, "{value}");
            assert_eq!(found[0].reason, Reason::UnresolvedReference, "{value}");
        }
    }

    #[test]
    fn an_expansion_of_exactly_the_length_bound_still_resolves() {
        // The bound is a limit, not a ceiling one short of it: a value of
        // exactly MAX_EXPANDED_LEN bytes is within it.
        let exact = format!("{ROOT}/{}", "a".repeat(MAX_EXPANDED_LEN - ROOT.len() - 1));
        assert_eq!(exact.len(), MAX_EXPANDED_LEN);
        let content = format!("SCRATCH_HOME={exact}\nexport CARGO_HOME=$SCRATCH_HOME\n");
        assert_eq!(scan_with(&content, &rooted()), vec![]);
    }

    #[test]
    fn home_is_taken_from_the_root_set_not_the_process_environment() {
        // A future refactor that reached for `std::env::var("HOME")` would make
        // the guard's verdict machine-dependent, which invariant 3 forbids.
        // Under a real process `$HOME` this fragment would be outside the root;
        // under the root set's home it is inside it.
        let _home = guarded_home();
        let declared = Path::new("/var/home/declared");
        let roots = RootSet::new(declared, &[PathBuf::from("~/scratch")]);
        assert_ne!(
            std::env::var_os("HOME").map(PathBuf::from),
            Some(declared.to_path_buf())
        );
        let content = "export CARGO_HOME=$HOME/scratch/cargo\n";
        assert_eq!(scan_with(content, &roots), vec![]);
    }

    #[test]
    fn a_search_list_extended_twice_still_extends_the_inherited_list() {
        use Reason::{NotAbsolute, Unreadable, UnreadableReference, UnresolvedReference};
        for roots in [rooted(), RootSet::strict()] {
            for (content, expected) in [
                // The second `$PATH` is the first extension of the inherited
                // list, which is the user's and is not judged.
                ("export PATH=/a:$PATH\nexport PATH=/b:$PATH\n", vec![]),
                (
                    "PATH=/a:$PATH\nPATH=/b:$PATH\nexport PATH=/c:$PATH\n",
                    vec![],
                ),
                (
                    "export INFOPATH=/a:$INFOPATH\nexport INFOPATH=/b:$INFOPATH\n",
                    vec![],
                ),
                // What the first extension added is still judged.
                (
                    "export PATH=/a:$PATH\nexport PATH=./x:$PATH\n",
                    vec![(2, NotAbsolute)],
                ),
                (
                    "export PATH=./x:$PATH\nexport PATH=/b:$PATH\n",
                    vec![(1, NotAbsolute), (2, NotAbsolute)],
                ),
                // Another name still cannot use it: its value is not known.
                (
                    "export PATH=/a:$PATH\nexport EDITOR=$PATH\n",
                    vec![(2, UnresolvedReference)],
                ),
                // A list assigned outright replaces the extension.
                (
                    "export PATH=/a:$PATH\nexport PATH=/usr/bin\nexport PATH=./x:$PATH\n",
                    vec![(3, NotAbsolute)],
                ),
                // An extension that does not resolve replaces the one before
                // it: a later extension may not reach past it to line 1's.
                (
                    "export PATH=/a:$PATH\nexport PATH=${UNDEFINED}:$PATH\nexport PATH=/z:$PATH\n",
                    vec![(2, UnresolvedReference), (3, UnresolvedReference)],
                ),
                // After a line the guard could not read, nothing is inherited.
                (
                    "export PATH=/a:$PATH\ntrue\nexport PATH=/b:$PATH\n",
                    vec![(2, Unreadable), (3, UnreadableReference)],
                ),
            ] {
                assert_eq!(reasons(content, &roots), expected, "{content:?}");
            }
        }
    }

    #[test]
    fn a_reference_to_the_home_with_no_home_says_so() {
        // `scan` has no home to expand `~` or `$HOME` against. Saying that the
        // fragment has not assigned `HOME` would send a reader looking for an
        // assignment no fragment may make.
        let strict = RootSet::strict();
        for (name, value) in [
            ("EDITOR", "$HOME/bin/nvim"),
            ("EDITOR", "${HOME}/bin/nvim"),
            ("VISUAL", "~/bin/nvim"),
            ("PATH", "$HOME/bin:$PATH"),
            ("SSH_AUTH_SOCK", "~/agent"),
        ] {
            assert_eq!(
                reason_of(&check(name, value, &strict)),
                Some(Reason::NoHome),
                "{name}={value}"
            );
        }
        // A name that took its value from the home says the same.
        assert_eq!(
            reasons("export X=$HOME\nexport EDITOR=$X\n", &strict),
            vec![(1, Reason::NotEmittable), (2, Reason::NoHome)]
        );
        // A set with a home expands it, and a location with no root is
        // refused for that before its value is looked at.
        assert_eq!(
            check("EDITOR", "$HOME/bin/nvim", &rooted()),
            Verdict::Allowed
        );
        assert_eq!(
            reason_of(&check("CARGO_HOME", "~/cargo", &strict)),
            Some(Reason::NoRootsDeclared)
        );
    }
}
