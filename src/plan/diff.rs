//! What a change looks like: the diff `plan` prints for one target.
//!
//! A [`Diff`] is plain data. It is computed once, while deciding, from the
//! bytes the decision was made on, so what is shown is exactly what `apply`
//! writes. Colour is not part of it.

use similar::TextDiff;

use crate::fs::Mode;

/// The largest body, in bytes, that is shown line by line.
///
/// Past this a diff stops being something a human reads, and computing one is
/// quadratic in the worst case; the change is summarised instead.
pub const TEXT_LIMIT: usize = 256 * 1024;

/// Lines of unchanged context around each hunk.
const CONTEXT: usize = 3;

/// The difference between what is on disk and what bx would leave there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// What kind of difference it is, with what a renderer needs to show it.
    pub kind: DiffKind,
}

/// The shape of a [`Diff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffKind {
    /// A unified diff, headed by the target's portable path.
    Text(String),
    /// Only the mode differs; the bytes are identical.
    Mode {
        /// The mode on disk.
        from: Mode,
        /// The mode bx would set.
        to: Mode,
    },
    /// The content differs and is not shown line by line.
    Summary {
        /// How many bytes are on disk, or `None` when there is no file.
        before: Option<usize>,
        /// How many bytes bx would write.
        after: usize,
        /// Why it is summarised.
        why: Why,
    },
}

/// Why a change is summarised rather than shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// One side is not UTF-8.
    Binary,
    /// One side is larger than [`TEXT_LIMIT`].
    TooLarge,
}

impl Diff {
    /// The diff from `before` — the regular file on disk, or `None` when there
    /// is none — to `after`, for the target spelled `target`.
    ///
    /// `mode` is the mode drift the comparison found. Identical bytes with no
    /// mode drift have no diff.
    #[must_use]
    pub(super) fn between(
        target: &str,
        before: Option<&[u8]>,
        after: &[u8],
        mode: Option<(Mode, Mode)>,
    ) -> Option<Self> {
        if before == Some(after) {
            return mode.map(|(from, to)| Self {
                kind: DiffKind::Mode { from, to },
            });
        }
        let old = before.unwrap_or_default();
        let summary = |why| DiffKind::Summary {
            before: before.map(<[u8]>::len),
            after: after.len(),
            why,
        };
        let kind = if old.len() > TEXT_LIMIT || after.len() > TEXT_LIMIT {
            summary(Why::TooLarge)
        } else {
            match (std::str::from_utf8(old), std::str::from_utf8(after)) {
                (Ok(old), Ok(new)) => DiffKind::Text(unified(target, old, new)),
                _ => summary(Why::Binary),
            }
        };
        Some(Self { kind })
    }
}

/// A unified diff with [`CONTEXT`] lines of context, headed by `target`.
fn unified(target: &str, old: &str, new: &str) -> String {
    let diff = TextDiff::from_lines(old, new);
    diff.unified_diff()
        .context_radius(CONTEXT)
        .missing_newline_hint(true)
        .header(&format!("{target} (on disk)"), &format!("{target} (bx)"))
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_create_is_every_line_added() {
        let diff = Diff::between("~/.a", None, b"one\ntwo\n", None).expect("a diff");
        assert_eq!(
            diff.kind,
            DiffKind::Text(
                "--- ~/.a (on disk)\n+++ ~/.a (bx)\n@@ -0,0 +1,2 @@\n+one\n+two\n".to_string()
            )
        );
    }

    #[test]
    fn identical_bytes_have_no_diff_unless_the_mode_moved() {
        assert_eq!(Diff::between("~/.a", Some(b"x"), b"x", None), None);
        assert_eq!(
            Diff::between(
                "~/.a",
                Some(b"x"),
                b"x",
                Some((Mode::DEFAULT_FILE, Mode::PRIVATE_FILE))
            ),
            Some(Diff {
                kind: DiffKind::Mode {
                    from: Mode::DEFAULT_FILE,
                    to: Mode::PRIVATE_FILE
                }
            })
        );
    }

    #[test]
    fn a_body_at_the_limit_is_shown_and_one_past_it_is_summarised() {
        let at = "a\n".repeat(TEXT_LIMIT / 2);
        assert!(matches!(
            Diff::between("~/.a", None, at.as_bytes(), None).map(|d| d.kind),
            Some(DiffKind::Text(_))
        ));

        let past = format!("{at}b");
        assert_eq!(
            Diff::between("~/.a", Some(b"old\n"), past.as_bytes(), None).map(|d| d.kind),
            Some(DiffKind::Summary {
                before: Some(4),
                after: TEXT_LIMIT + 1,
                why: Why::TooLarge
            })
        );
        // Either side past the limit summarises.
        assert_eq!(
            Diff::between("~/.a", Some(past.as_bytes()), b"new\n", None).map(|d| d.kind),
            Some(DiffKind::Summary {
                before: Some(TEXT_LIMIT + 1),
                after: 4,
                why: Why::TooLarge
            })
        );
    }

    #[test]
    fn a_non_utf8_side_is_summarised_as_binary() {
        assert_eq!(
            Diff::between("~/.a", None, &[0xff, 0xfe], None).map(|d| d.kind),
            Some(DiffKind::Summary {
                before: None,
                after: 2,
                why: Why::Binary
            })
        );
        assert_eq!(
            Diff::between("~/.a", Some(&[0xff]), b"text\n", None).map(|d| d.kind),
            Some(DiffKind::Summary {
                before: Some(1),
                after: 5,
                why: Why::Binary
            })
        );
    }
}
