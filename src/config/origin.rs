//! Where a configuration entry came from.
//!
//! Every entry in a resolved configuration carries the file and line that last
//! set it. That is what makes an account divergence readable rather than
//! inferred: `bx plan` prints the origin of the contribution it is reporting, so
//! "why is this machine different" is answered by the plan itself.
//!
//! Lines are taken from `toml_edit` spans, never re-derived by searching the
//! text. An array-of-tables element's `Table::span()` is the `[[target]]` header
//! token range and a `Key::span()` is the key token, so the line a span starts on
//! is the line a human would point at.

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// The file and line a configuration entry was written on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    /// The layer file. Absolute when it came from disk.
    pub file: PathBuf,
    /// 1-based line number, or `0` when the entry has no span.
    pub line: usize,
}

impl Origin {
    /// The origin of the entry a `toml_edit` span points at.
    #[must_use]
    pub fn at(file: &Path, text: &str, span: &Range<usize>) -> Self {
        Self {
            file: file.to_path_buf(),
            line: line_of(text, span.start),
        }
    }

    /// The origin of an entry with no span.
    ///
    /// `toml_edit` returns `None` for the span of anything it did not parse —
    /// a document built in memory, or an item despanned by a mutation. Line `0`
    /// says "this file, position unknown" rather than pretending it is line 1.
    #[must_use]
    pub fn unknown(file: &Path) -> Self {
        Self {
            file: file.to_path_buf(),
            line: 0,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file.display(), self.line)
    }
}

/// The 1-based line `offset` falls on.
///
/// Counts `\n` only, so a CRLF document counts each line once: the `\r` belongs
/// to the line it terminates. An offset past the end of `text` is clamped, which
/// keeps a stale span from panicking a plan.
pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    let offset = offset.min(text.len());
    1 + text.as_bytes()[..offset]
        .iter()
        .filter(|&&byte| byte == b'\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_renders_as_file_and_line() {
        let origin = Origin {
            file: PathBuf::from("/var/home/example/.config/bx/bx.toml"),
            line: 12,
        };

        assert_eq!(
            origin.to_string(),
            "/var/home/example/.config/bx/bx.toml:12"
        );
    }

    #[test]
    fn the_first_line_is_line_one() {
        assert_eq!(line_of("[[target]]\n", 0), 1);
        assert_eq!(line_of("", 0), 1);
    }

    #[test]
    fn a_line_is_counted_from_a_byte_offset() {
        let text = "one\ntwo\nthree\n";

        assert_eq!(line_of(text, 0), 1);
        assert_eq!(line_of(text, 3), 1, "the newline still belongs to line one");
        assert_eq!(line_of(text, 4), 2);
        assert_eq!(line_of(text, 8), 3);
        assert_eq!(line_of(text, text.len()), 4, "the position after the last");
    }

    #[test]
    fn a_crlf_document_counts_each_line_once() {
        let text = "one\r\ntwo\r\nthree\r\n";

        assert_eq!(line_of(text, 0), 1);
        assert_eq!(line_of(text, 5), 2);
        assert_eq!(line_of(text, 10), 3);
    }

    #[test]
    fn an_offset_past_the_end_is_clamped_to_the_last_line() {
        assert_eq!(line_of("one\ntwo", 9_999), 2);
    }

    #[test]
    fn an_origin_is_built_from_a_span() {
        let text = "# lead\n[[target]]\npath = \"~/a\"\n";
        let file = Path::new("bx.toml");

        assert_eq!(Origin::at(file, text, &(7..17)).line, 2);
        assert_eq!(Origin::at(file, text, &(18..22)).line, 3);
        assert_eq!(Origin::at(file, text, &(7..17)).file, file);
    }

    #[test]
    fn an_origin_without_a_span_is_line_zero() {
        let origin = Origin::unknown(Path::new("bx.toml"));

        assert_eq!(origin.line, 0);
        assert_eq!(origin.to_string(), "bx.toml:0");
    }
}
