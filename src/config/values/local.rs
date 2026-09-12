//! Comment-preserving edits to `local.toml`'s `[values]` table.
//!
//! `bx init` writes an account's answers, and the account also hand-edits the
//! same file. Commands and hand-editing have to be the same operation, so an
//! answer is set by editing the `toml_edit` document rather than by serialising
//! a struct over it: comments survive, key order survives, and the formatting a
//! person chose survives.
//!
//! # Nothing here performs I/O
//!
//! Every function takes a document and returns a document. That is deliberate,
//! and it is what makes this entry's additivity claim true rather than
//! aspirational: this entry opens no file for writing anywhere. Persisting the
//! rendered document belongs to `bx init` (entry A8) through the atomic writer
//! (entry A5), which is the only writer in the product that records the prior
//! bytes and can therefore satisfy Invariants 1 and 4.
//!
//! # Why `DocumentMut` here and `Document` there
//!
//! `config::parse_str` parses with `toml_edit::Document::parse` because
//! `Origin.line` is read off the spans, and `DocumentMut`'s `FromStr` despans
//! the document. Here spans are irrelevant: the result is rendered to text and
//! re-parsed on the next load, so the mutable document is the right one.

use toml_edit::{DocumentMut, Item, Table, Value, value};

/// The table an account's answers live in.
const VALUES: &str = "values";

/// An empty `local.toml`, for an account that has never answered anything.
///
/// Carries the header a reader needs in order to know what the file is and why
/// it is not in the config repo. `bx init` renders this when the file is absent
/// rather than writing a bare `[values]` table into the state directory.
#[must_use]
pub fn empty() -> DocumentMut {
    let mut doc = DocumentMut::new();
    doc.decor_mut().set_prefix(
        "# This account's answers to the values bx.toml declares.\n\
         #\n\
         # Never committed, and never inside the config repo: this file is the\n\
         # one place account-specific content is allowed to live.\n\
         #\n\
         # `bx init` writes it, and hand-editing it is the same operation.\n\n",
    );
    doc
}

/// Set `name` to `answer`, creating the `[values]` table when it is absent.
///
/// Only the *text* of an existing value is replaced; its position, the spacing
/// around its `=` and anything after it on the line — a trailing comment above
/// all — stay exactly as they were. A new key is appended to the table.
///
/// Assigning a fresh item over the old one would drop all of that. A comment
/// *above* a key is that key's own prefix decoration and survived either way,
/// but a comment *after* the value is the value's, and an account annotating its
/// own answers is the archetypal many-accounts note. This module exists because
/// commands and hand-editing have to be the same operation, which is false the
/// moment a command silently deletes what a person wrote next to the thing it
/// changed.
pub fn set(doc: &mut DocumentMut, name: &str, answer: &str) {
    let table = values_table(doc);
    match table.get_mut(name).and_then(Item::as_value_mut) {
        Some(existing) => {
            let mut replacement = Value::from(answer);
            *replacement.decor_mut() = existing.decor().clone();
            *existing = replacement;
        }
        // Absent, or present as something that is not a value at all — a
        // `[values.name]` sub-table, say. Neither has decoration worth carrying
        // onto a bare answer.
        None => table[name] = value(answer),
    }
}

/// Remove `name`, reporting whether it was there.
///
/// The `[values]` table itself is left behind even when it empties: an empty
/// table is a valid, readable statement that this account has answered nothing,
/// and removing it would discard whatever comments sat above it.
pub fn unset(doc: &mut DocumentMut, name: &str) -> bool {
    doc.get_mut(VALUES)
        .and_then(Item::as_table_mut)
        .is_some_and(|table| table.remove(name).is_some())
}

/// The `[values]` table, created as a real (not dotted, not inline) table if
/// this document has none.
fn values_table(doc: &mut DocumentMut) -> &mut Table {
    if doc.get(VALUES).is_some_and(|item| !item.is_table()) {
        // A `values` key that is not a table is not something to edit around:
        // replacing it is the only way to produce a document bx can read back.
        // It is *removed* rather than overwritten, because overwriting keeps the
        // old key's decoration and would render `[values ]`.
        doc.remove(VALUES);
    }
    doc.entry(VALUES)
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .expect("the entry is a table, or was just made one")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use std::path::Path;

    fn doc(text: &str) -> DocumentMut {
        text.parse::<DocumentMut>().expect("valid TOML")
    }

    #[test]
    fn setting_a_value_preserves_comments_and_key_order() {
        let mut document = doc("# this account's answers\n\
             [values]\n\
             # where scratch lives on this box\n\
             scratch_root = \"/var/mnt/scratch/one\"\n\
             git_email = \"someone@example.invalid\"\n");

        set(&mut document, "git_name", "Someone");

        assert_eq!(
            document.to_string(),
            "# this account's answers\n\
             [values]\n\
             # where scratch lives on this box\n\
             scratch_root = \"/var/mnt/scratch/one\"\n\
             git_email = \"someone@example.invalid\"\n\
             git_name = \"Someone\"\n",
        );
    }

    #[test]
    fn setting_an_existing_key_replaces_only_its_value() {
        let mut document = doc("[values]\n\
             # keep me\n\
             scratch_root = \"/var/mnt/scratch/one\"\n\
             git_name = \"Someone\"\n");

        set(&mut document, "scratch_root", "/var/mnt/scratch/two");

        assert_eq!(
            document.to_string(),
            "[values]\n\
             # keep me\n\
             scratch_root = \"/var/mnt/scratch/two\"\n\
             git_name = \"Someone\"\n",
            "the comment, the position and the sibling key all survive"
        );
    }

    #[test]
    fn setting_a_value_keeps_the_note_the_account_wrote_beside_it() {
        // An account annotating its own answers is the archetypal many-accounts
        // note, and a trailing comment belongs to the value, not to the key.
        let mut document = doc("[values]\n\
             # the fast disk\n\
             scratch_root   = \"/var/mnt/scratch/one\"  # nvme, not the array\n\
             git_name = \"Someone\"\n");

        set(&mut document, "scratch_root", "/var/mnt/scratch/two");

        assert_eq!(
            document.to_string(),
            "[values]\n\
             # the fast disk\n\
             scratch_root   = \"/var/mnt/scratch/two\"  # nvme, not the array\n\
             git_name = \"Someone\"\n",
            "the note, the alignment and the sibling key all survive"
        );
    }

    #[test]
    fn setting_over_a_key_that_is_not_a_value_replaces_it() {
        // A `[values.scratch_root]` sub-table is not something to edit around,
        // and it has no decoration worth carrying onto a bare answer.
        let mut document = doc("[values]\n[values.scratch_root]\nx = 1\n");

        set(&mut document, "scratch_root", "/var/mnt/scratch/one");

        assert_eq!(
            parse_str(&document.to_string(), Path::new("local.toml"))
                .expect("it loads")
                .value_assignments
                .len(),
            1
        );
    }

    #[test]
    fn unsetting_a_key_takes_the_comments_that_are_its_own() {
        // The other half of the same rule: what belongs to the key goes with the
        // key, and what belongs to a sibling stays.
        let mut document = doc("[values]\n\
             # the fast disk\n\
             scratch_root = \"/var/mnt/scratch/one\"  # nvme\n\
             # who this account is\n\
             git_name = \"Someone\"\n");

        assert!(unset(&mut document, "scratch_root"));

        assert_eq!(
            document.to_string(),
            "[values]\n\
             # who this account is\n\
             git_name = \"Someone\"\n",
            "the removed answer takes its own two comments and leaves the rest"
        );
    }

    #[test]
    fn setting_a_value_creates_the_values_table_when_it_is_absent() {
        let mut document = doc("");

        set(&mut document, "scratch_root", "/var/mnt/scratch/one");

        assert_eq!(
            document.to_string(),
            "[values]\nscratch_root = \"/var/mnt/scratch/one\"\n"
        );
    }

    #[test]
    fn setting_a_value_replaces_a_values_key_that_is_not_a_table() {
        // Nothing sensible can be edited around it, and leaving it would make
        // the file unreadable by the loader.
        let mut document = doc("values = 3\n");

        set(&mut document, "scratch_root", "/var/mnt/scratch/one");

        assert_eq!(
            document.to_string(),
            "[values]\nscratch_root = \"/var/mnt/scratch/one\"\n"
        );
    }

    #[test]
    fn unsetting_a_key_reports_whether_it_was_there() {
        let mut document = doc("[values]\nscratch_root = \"/var/mnt/scratch/one\"\n");

        assert!(unset(&mut document, "scratch_root"));
        assert!(
            !unset(&mut document, "scratch_root"),
            "gone the second time"
        );
        assert!(!unset(&mut document, "never_declared"));
        assert_eq!(
            document.to_string(),
            "[values]\n",
            "the table stays: it is a readable statement that nothing is answered"
        );
    }

    #[test]
    fn unsetting_in_a_document_with_no_values_table_is_false() {
        let mut document = doc("[[target]]\npath = \"~/.gitconfig\"\n");

        assert!(!unset(&mut document, "scratch_root"));
    }

    #[test]
    fn an_empty_document_explains_what_the_file_is() {
        let rendered = empty().to_string();

        assert!(rendered.starts_with("# This account's answers"));
        assert!(
            rendered.contains("Never committed"),
            "the header has to say why the file is not in the config repo"
        );
    }

    #[test]
    fn an_empty_document_takes_a_value_and_stays_parseable() {
        let mut document = empty();
        set(&mut document, "scratch_root", "/var/mnt/scratch/one");

        let config = parse_str(&document.to_string(), Path::new("local.toml"))
            .expect("the rendered document loads");

        assert_eq!(config.value_assignments.len(), 1);
        assert_eq!(config.value_assignments[0].name, "scratch_root");
    }

    #[test]
    fn a_document_round_trips_through_set_and_load() {
        // The property that matters: what the setter writes is what the loader
        // reads, so `bx init` and a hand-edit cannot disagree.
        let mut document = doc("# mine\n[values]\ngit_name = \"Someone\"\n");
        set(&mut document, "scratch_root", "/var/mnt/scratch/one");
        set(&mut document, "git_email", "someone@example.invalid");

        let rendered = document.to_string();
        let config = parse_str(&rendered, Path::new("local.toml")).expect("it loads");

        let answered: Vec<(&str, String)> = config
            .value_assignments
            .iter()
            .map(|a| (a.name.as_str(), a.value.to_string()))
            .collect();

        assert_eq!(
            answered,
            vec![
                ("git_name", "Someone".to_string()),
                ("scratch_root", "/var/mnt/scratch/one".to_string()),
                ("git_email", "someone@example.invalid".to_string()),
            ],
            "document order, with the pre-existing key still first"
        );
        assert!(rendered.starts_with("# mine\n"), "the comment survived");
    }

    #[test]
    fn the_setter_performs_no_io() {
        // Held structurally: every function in this module takes and returns a
        // document and never a path, so there is nothing for it to open. The
        // assertion is on the source, so it fails the moment that stops being
        // true.
        let source = include_str!("local.rs");
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("the non-test half");

        for forbidden in [
            "std::fs",
            "std::io",
            "File::",
            "OpenOptions",
            "write(",
            "tempfile",
            "rustix",
        ] {
            assert!(
                !body.contains(forbidden),
                "`{forbidden}` appeared: persisting a document belongs to the atomic writer"
            );
        }
    }
}
