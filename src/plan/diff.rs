//! What a change looks like: the diff `plan` prints for one target, and the
//! rendering of a whole report.
//!
//! A [`Diff`] is plain data. It is computed once, while deciding, from the
//! bytes the decision was made on, so what is shown is exactly what `apply`
//! writes. Colour is not part of it: [`render`] alone applies a [`Palette`],
//! which is decided once from the environment and passed in.

use std::fmt::Write as _;
use std::path::Path;

use anstyle::{AnsiColor, Style};
use similar::TextDiff;

use super::{Change, Report};
use crate::fs::Mode;
use crate::paths;
use crate::report::{self, Action};

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
    /// The diff of a directory whose mode alone changes: it has no bytes, so
    /// a mode line is all there is to show.
    #[must_use]
    pub(super) const fn mode(from: Mode, to: Mode) -> Self {
        Self {
            kind: DiffKind::Mode { from, to },
        }
    }

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
///
/// A line ends at `\n` and nowhere else, so a `\r` stays inside its line: a
/// change of line ending is a changed line, and a lone `\r` does not start a
/// new one. Every line of the result ends with exactly one `\n`, a last line
/// that had none is followed by `\ No newline at end of file`, and the target
/// in the file headers is escaped as a row names it, so the text splits back
/// into its lines on `\n` alone.
///
/// The file headers are written even when there is no hunk. `unified` is only
/// asked about sides that differ, and two sides with no line between them
/// differ only in whether a file is there — an empty body created where there
/// was none, or rolled back to where there was none. `similar` has no hunk for
/// that, and without the headers the diff was the empty string, which a row
/// rendered as one blank indented line under nothing.
fn unified(target: &str, old: &str, new: &str) -> String {
    let old: Vec<&str> = old.split_inclusive('\n').collect();
    let new: Vec<&str> = new.split_inclusive('\n').collect();
    let diff = TextDiff::configure()
        .newline_terminated(true)
        .diff_slices(&old, &new);
    let target = escape(target);
    let mut unified = diff.unified_diff();
    unified.context_radius(CONTEXT);
    let mut out = String::new();
    let _ = writeln!(out, "--- {target} (on disk)\n+++ {target} (bx)");
    for hunk in unified.iter_hunks() {
        let _ = writeln!(out, "{}", hunk.header());
        for change in hunk.iter_changes() {
            let value = change.value();
            let line = value.strip_suffix('\n');
            let _ = writeln!(out, "{}{}", change.tag(), line.unwrap_or(value));
            if line.is_none() {
                out.push_str("\\ No newline at end of file\n");
            }
        }
    }
    out
}

/// `text` with every control character but a tab spelled out — `\r`, `\n`,
/// `\x1b` — so nothing a file or a path holds can move the cursor, colour the
/// terminal, or start a line the rendering did not.
pub(crate) fn escape(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(|c| c != '\t' && c.is_control()) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\t' => out.push(c),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Which rows a rendering shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// `bx plan` and `bx apply`: only what is not already converged.
    Plan,
    /// Bare `bx`: every row, unchanged ones included.
    Status,
}

/// Whether a rendering is coloured.
///
/// Decided once, from the environment, and carried explicitly: nothing that
/// renders reads `NO_COLOR` or asks whether it is writing to a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    color: bool,
}

impl Palette {
    /// No escape sequences at all.
    pub const PLAIN: Self = Self { color: false };

    /// Colour only on a terminal, and only when `NO_COLOR` is unset or empty —
    /// `no_color` is whether it is set to anything else.
    #[must_use]
    pub const fn resolve(no_color: bool, tty: bool) -> Self {
        Self {
            color: tty && !no_color,
        }
    }

    /// Whether this palette emits colour.
    #[must_use]
    pub const fn is_colored(self) -> bool {
        self.color
    }

    /// `text` in `style`, or `text` alone when plain.
    fn paint(self, style: Style, text: &str) -> String {
        if self.color {
            format!("{}{text}{}", style.render(), style.render_reset())
        } else {
            text.to_string()
        }
    }
}

/// A foreground colour.
const fn fg(color: AnsiColor) -> Style {
    Style::new().fg_color(Some(anstyle::Color::Ansi(color)))
}

/// An added line.
const ADDED: Style = fg(AnsiColor::Green);
/// A removed line.
const REMOVED: Style = fg(AnsiColor::Red);
/// A hunk header, and the symbol of a row nothing happens to.
const QUIET: Style = Style::new().dimmed();
/// A diff's file headers.
const HEADER: Style = Style::new().bold();
/// A banner, and the symbol of a row that needs a human.
const ATTENTION: Style = fg(AnsiColor::Yellow).bold();
/// The symbol of a row `apply` will write.
const PENDING: Style = fg(AnsiColor::Green).bold();

/// The indentation of a row.
const ROW_INDENT: &str = "  ";
/// The indentation of the diff beneath a row.
const DIFF_INDENT: &str = "    ";

/// Render a report: any banner, one row per shown change with its diff, and
/// the summary as the last line.
///
/// Every path is portable: a target already is, a diff is headed by its
/// target, and an origin is spelled against `home`.
#[must_use]
pub fn render(report: &Report, view: View, palette: Palette, home: &Path) -> String {
    let mut out = String::new();
    if let Some(banner) = banner(report) {
        out.push_str(&palette.paint(ATTENTION, &banner));
        out.push('\n');
    }
    for change in &report.changes {
        if view == View::Plan && change.action == Action::Unchanged && !interrupted(report) {
            continue;
        }
        row(&mut out, change, palette, home);
    }
    out.push_str(&report::summary(&report.actions()));
    out.push('\n');
    out
}

/// Whether every row in this report is about an interrupted session rather
/// than about a configured target.
///
/// # Decision 35: an interrupted session's rows are never hidden
///
/// [`View::Plan`] hides an [`Action::Unchanged`] row, because a target already
/// in its declared state is noise in a list of work. Over an interrupted
/// session that rule hid the work itself: `run` decides no configured target
/// while a journal stands, so every row is about the session, and a session
/// that wrote everything but did not record it makes every one of them
/// `Unchanged` — recording a write touches no file. `View::Plan` therefore
/// printed a banner, a summary line, and not one target.
///
/// `command::apply_with` renders its approval prompt with [`View::Plan`] too,
/// so the user was asked to confirm a recovery that named none of the files it
/// was about to record. A confirmation prompt that cannot show what it is
/// confirming is not one a user can answer, and the rows already exist — only
/// the filter stood between them and the screen.
fn interrupted(report: &Report) -> bool {
    report.interrupted.is_some()
}

/// The line above the rows, when the state directory has something to say.
fn banner(report: &Report) -> Option<String> {
    if report.apply_running {
        return Some(
            "A bx apply is running; what it has not finished yet is shown as still to do."
                .to_string(),
        );
    }
    let interrupted = report.interrupted.as_ref()?;
    let kind = interrupted.kind;
    let blocked = interrupted.blocked().count();
    Some(if interrupted.unreadable {
        "An interrupted bx session left a journal bx cannot read. `bx apply` sets it aside and \
         writes nothing else; run `bx plan` again after `bx apply` sets it aside."
            .to_string()
    } else if blocked > 0 {
        format!(
            "An interrupted bx {kind} left {blocked} file(s) bx cannot account for; `bx apply` \
             refuses, and rolls nothing back, until they are resolved."
        )
    } else if interrupted.complete {
        format!(
            "An interrupted bx {kind} wrote everything but did not record it. `bx apply` \
             records it and writes nothing else; run `bx plan` again after `bx apply` records it."
        )
    } else {
        format!(
            "An interrupted bx {kind} was found. `bx apply` rolls back what is shown below and \
             writes nothing else; run `bx plan` again after `bx apply` rolls these back."
        )
    })
}

/// One change — `  {symbol} {target}  ({origin}) {note}` — then its diff.
fn row(out: &mut String, change: &Change, palette: Palette, home: &Path) {
    let style = if change.action.needs_attention() {
        ATTENTION
    } else if change.action.is_pending() {
        PENDING
    } else {
        QUIET
    };
    let _ = write!(
        out,
        "{ROW_INDENT}{} {}  ({}:{})",
        palette.paint(style, &change.action.symbol().to_string()),
        escape(&change.target),
        escape(&paths::to_portable(&change.origin.file, home)),
        change.origin.line,
    );
    if let Some(note) = &change.note {
        let _ = write!(out, " {}", escape(note));
    }
    out.push('\n');

    let Some(diff) = &change.diff else {
        return;
    };
    match &diff.kind {
        DiffKind::Text(text) => {
            // Split on `\n` alone, as `unified` wrote it: a `\r` is part of its
            // line, and is shown escaped with every other control character.
            let lines = text.strip_suffix('\n').unwrap_or(text).split('\n');
            for (index, line) in lines.enumerate() {
                let style = match line.as_bytes().first() {
                    // The first two lines are the `---` and `+++` file headers.
                    _ if index < 2 => Some(HEADER),
                    Some(b'+') => Some(ADDED),
                    Some(b'-') => Some(REMOVED),
                    Some(b'@') => Some(QUIET),
                    _ => None,
                };
                let line = escape(line);
                out.push_str(DIFF_INDENT);
                match style {
                    Some(style) => out.push_str(&palette.paint(style, &line)),
                    None => out.push_str(&line),
                }
                out.push('\n');
            }
        }
        DiffKind::Mode { from, to } => {
            let _ = writeln!(out, "{DIFF_INDENT}mode {from} -> {to}");
        }
        DiffKind::Summary { before, after, why } => {
            let before = before.map_or_else(|| "no file".to_string(), |len| format!("{len} bytes"));
            let why = match why {
                Why::Binary => "binary content",
                Why::TooLarge => "too large to show",
            };
            let _ = writeln!(out, "{DIFF_INDENT}{why}: {before} -> {after} bytes");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::Origin;
    use crate::journal::SessionKind;
    use crate::paths::Portable;
    use crate::recover::{Interrupted, Standing, Unfinished};

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
    fn an_empty_body_where_there_was_no_file_is_the_headers_alone() {
        // `similar` has no hunk between two sides with no line, so this used
        // to be `Text("")`, rendered as one blank indented line and no header.
        let diff = Diff::between("~/.a", None, b"", None).expect("a diff");
        assert_eq!(
            diff.kind,
            DiffKind::Text("--- ~/.a (on disk)\n+++ ~/.a (bx)\n".to_string())
        );

        let mut create = change("~/.a", 1, Action::Create);
        create.diff = Some(diff);
        let shown = render(
            &Report {
                changes: vec![create],
                ..Report::default()
            },
            View::Plan,
            Palette::PLAIN,
            Path::new(HOME),
        );
        let lines: Vec<&str> = shown.lines().collect();
        assert_eq!(
            lines[1..3],
            ["    --- ~/.a (on disk)", "    +++ ~/.a (bx)"],
            "{shown}"
        );
        assert!(!lines.iter().any(|line| line.trim().is_empty()), "{shown}");
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
    fn t17_a_body_at_the_limit_is_shown_and_one_past_it_is_summarised() {
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
    fn t17_an_on_disk_side_at_the_limit_is_still_shown() {
        // The limit is inclusive on both sides, not only on the side bx writes.
        let at = "a\n".repeat(TEXT_LIMIT / 2);
        assert_eq!(at.len(), TEXT_LIMIT);
        assert!(matches!(
            Diff::between("~/.a", Some(at.as_bytes()), b"new\n", None).map(|d| d.kind),
            Some(DiffKind::Text(_))
        ));
    }

    #[test]
    fn t17_a_non_utf8_side_is_summarised_as_binary() {
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

    /// A home no test touches: rendering is pure.
    const HOME: &str = "/var/home/example";

    fn change(target: &str, line: usize, action: Action) -> Change {
        Change {
            target: target.to_string(),
            origin: Origin {
                file: PathBuf::from(HOME).join(".config/bx/bx.toml"),
                line,
            },
            action,
            diff: None,
            note: None,
        }
    }

    /// A modify with a change in the middle of nine lines, an unchanged row
    /// and a blocked row.
    fn a_report() -> Report {
        let mut modify = change("~/.gitconfig", 4, Action::Modify);
        modify.diff = Diff::between(
            "~/.gitconfig",
            Some(b"1\n2\n3\n4\n5\n6\n7\n8\n9\n"),
            b"1\n2\n3\n4\nfive\n6\n7\n8\n9\n",
            None,
        );
        let mut blocked = change("~/.env", 12, Action::Blocked);
        blocked.note = Some("run `bx init` to set scratch_root".to_string());
        Report {
            changes: vec![modify, change("~/.b", 8, Action::Unchanged), blocked],
            ..Report::default()
        }
    }

    #[test]
    fn t16_a_plan_renders_exactly_with_three_lines_of_context_and_portable_paths() {
        let rendered = render(&a_report(), View::Plan, Palette::PLAIN, Path::new(HOME));

        assert_eq!(
            rendered,
            "  ~ ~/.gitconfig  (~/.config/bx/bx.toml:4)\n\
             \x20   --- ~/.gitconfig (on disk)\n\
             \x20   +++ ~/.gitconfig (bx)\n\
             \x20   @@ -2,7 +2,7 @@\n\
             \x20    2\n\
             \x20    3\n\
             \x20    4\n\
             \x20   -5\n\
             \x20   +five\n\
             \x20    6\n\
             \x20    7\n\
             \x20    8\n\
             \x20 ? ~/.env  (~/.config/bx/bx.toml:12) run `bx init` to set scratch_root\n\
             Plan: 0 to create, 1 to modify, 0 conflict, 1 blocked, 1 unchanged.\n"
        );
        assert!(!rendered.contains(HOME), "{rendered}");
    }

    #[test]
    fn t17_a_mode_change_and_a_summary_render_as_one_line_each() {
        let mut mode = change("~/.a", 1, Action::Modify);
        mode.diff = Some(Diff {
            kind: DiffKind::Mode {
                from: Mode::DEFAULT_FILE,
                to: Mode::PRIVATE_FILE,
            },
        });
        let mut binary = change("~/.b", 2, Action::Create);
        binary.diff = Diff::between("~/.b", None, &[0xff, 0xfe], None);
        let mut large = change("~/.c", 3, Action::Conflict);
        large.diff = Some(Diff {
            kind: DiffKind::Summary {
                before: Some(4),
                after: TEXT_LIMIT + 1,
                why: Why::TooLarge,
            },
        });
        let report = Report {
            changes: vec![mode, binary, large],
            ..Report::default()
        };

        let rendered = render(&report, View::Plan, Palette::PLAIN, Path::new(HOME));

        assert!(rendered.contains("  ~ ~/.a  (~/.config/bx/bx.toml:1)\n    mode 0644 -> 0600\n"));
        assert!(rendered.contains("    binary content: no file -> 2 bytes\n"));
        assert!(rendered.contains("    too large to show: 4 bytes -> 262145 bytes\n"));
    }

    #[test]
    fn t18_colour_only_on_a_terminal_without_no_color() {
        assert_eq!(Palette::resolve(true, true), Palette::PLAIN);
        assert_eq!(Palette::resolve(false, false), Palette::PLAIN);
        assert_eq!(Palette::resolve(true, false), Palette::PLAIN);
        assert!(Palette::resolve(false, true).is_colored());
        assert!(!Palette::PLAIN.is_colored());

        let plain = render(
            &a_report(),
            View::Status,
            Palette::resolve(true, true),
            Path::new(HOME),
        );
        assert!(!plain.contains('\x1b'), "{plain:?}");

        let coloured = render(
            &a_report(),
            View::Status,
            Palette::resolve(false, true),
            Path::new(HOME),
        );
        assert!(coloured.contains("\x1b[32m+five\x1b[0m"), "{coloured:?}");
        assert!(coloured.contains("\x1b[31m-5\x1b[0m"), "{coloured:?}");
        assert!(
            coloured.contains("\x1b[2m@@ -2,7 +2,7 @@\x1b[0m"),
            "{coloured:?}"
        );
        assert!(coloured.contains("\x1b[1m--- ~/.gitconfig (on disk)\x1b[0m"));
        // Symbols by what they ask of a human.
        assert!(
            coloured.contains("\x1b[1m\x1b[33m?\x1b[0m") || coloured.contains("\x1b[33m\x1b[1m?")
        );
        assert!(coloured.contains("\x1b[2m=\x1b[0m"), "{coloured:?}");
        // The summary and a context line stay plain.
        assert!(coloured.ends_with("1 unchanged.\n"));
        assert!(coloured.contains("\n     2\n"), "{coloured:?}");
    }

    #[test]
    fn t19_unchanged_rows_are_hidden_in_plan_and_shown_in_status() {
        let plan = render(&a_report(), View::Plan, Palette::PLAIN, Path::new(HOME));
        let status = render(&a_report(), View::Status, Palette::PLAIN, Path::new(HOME));

        assert!(!plan.contains("~/.b"), "{plan}");
        assert!(
            status.contains("  = ~/.b  (~/.config/bx/bx.toml:8)\n"),
            "{status}"
        );
        for rendered in [&plan, &status] {
            assert_eq!(
                rendered.lines().last(),
                Some("Plan: 0 to create, 1 to modify, 0 conflict, 1 blocked, 1 unchanged.")
            );
        }
        let empty = render(
            &Report::default(),
            View::Status,
            Palette::PLAIN,
            Path::new(HOME),
        );
        assert_eq!(
            empty,
            "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
        );
    }

    /// `report` rendered for plan, plain, against the test home.
    fn plain(report: &Report) -> String {
        render(report, View::Plan, Palette::PLAIN, Path::new(HOME))
    }

    #[test]
    fn decision_19_a_line_ending_change_on_an_owned_file_is_shown() {
        // P42R1-D3. Lines were split with `str::lines`, which drops a `\r`
        // before the `\n`, so a CRLF-only change showed identical lines.
        let home = crate::testing::guarded_home();
        crate::plan::tests::own(
            home.path(),
            ".w",
            b"a\r\nb\r\n",
            crate::state::Mechanism::Own,
        );
        let inputs =
            crate::plan::tests::inputs(&home, &crate::plan::tests::inline("~/.w", "a\\nb\\n"));

        let report =
            crate::plan::run(&inputs, crate::plan::Mode::Plan, &mut |_| Ok(false)).expect("plan");

        assert_eq!(report.actions(), vec![Action::Modify]);
        let rendered = render(&report, View::Plan, Palette::PLAIN, home.path());
        assert!(
            rendered.contains("    -a\\r\n    -b\\r\n    +a\n    +b\n"),
            "{rendered:?}"
        );
        assert!(!rendered.contains('\r'), "{rendered:?}");
    }

    #[test]
    fn text_with_no_control_character_but_a_tab_is_shown_as_it_is() {
        // The mutation run found this unpinned: `escape` could copy every
        // string and still render the same text.
        for text in ["plain", "a\ttab", ""] {
            assert!(
                matches!(escape(text), std::borrow::Cow::Borrowed(kept) if kept == text),
                "{text:?}"
            );
        }
        assert!(matches!(escape("a\rb"), std::borrow::Cow::Owned(_)));
    }

    #[test]
    fn decision_19_a_lone_carriage_return_is_shown_inside_its_line() {
        let mut modify = change("~/.cr", 1, Action::Modify);
        modify.diff = Diff::between("~/.cr", Some(b"one\ntwo\n"), b"one\rtwo\n", None);

        let rendered = plain(&Report {
            changes: vec![modify],
            ..Report::default()
        });

        assert!(
            rendered.contains("    -one\n    -two\n    +one\\rtwo\n"),
            "{rendered:?}"
        );
        assert!(!rendered.contains('\r'), "{rendered:?}");
    }

    #[test]
    fn decision_19_control_bytes_are_shown_escaped_and_a_tab_is_kept() {
        let mut create = change("~/.e", 1, Action::Create);
        create.diff = Diff::between("~/.e", None, b"\x1b[31mred\tx\x7f\n", None);

        let rendered = plain(&Report {
            changes: vec![create],
            ..Report::default()
        });

        assert!(
            rendered.contains("    +\\x1b[31mred\tx\\x7f\n"),
            "{rendered:?}"
        );
        assert!(
            !rendered.contains('\x1b') && !rendered.contains('\x7f'),
            "{rendered:?}"
        );
    }

    #[test]
    fn decision_19_a_newline_in_a_path_stays_on_its_row() {
        let mut create = change("~/.a\nb", 1, Action::Create);
        create.diff = Diff::between("~/.a\nb", None, b"x\n", None);

        let rendered = plain(&Report {
            changes: vec![create],
            ..Report::default()
        });

        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(
            lines[0], "  + ~/.a\\nb  (~/.config/bx/bx.toml:1)",
            "{rendered:?}"
        );
        assert_eq!(lines[1], "    --- ~/.a\\nb (on disk)", "{rendered:?}");
        assert_eq!(lines[2], "    +++ ~/.a\\nb (bx)", "{rendered:?}");
        assert_eq!(lines[4], "    +x", "{rendered:?}");
        assert_eq!(lines.len(), 6, "{rendered:?}");
    }

    fn interrupted(unfinished: Vec<Unfinished>) -> Interrupted {
        Interrupted {
            kind: SessionKind::Apply,
            journal: PathBuf::from(HOME).join(".local/state/bx/journal"),
            complete: false,
            unreadable: false,
            unfinished,
        }
    }

    fn unfinished(resolvable: bool) -> Unfinished {
        Unfinished {
            target: Portable::parse_in("~/.a", Path::new(HOME)).expect("portable"),
            dest: PathBuf::from(HOME).join(".a"),
            standing: if resolvable {
                Standing::Written
            } else {
                Standing::Diverged
            },
            resolvable,
            note: "note".to_string(),
        }
    }

    #[test]
    fn a_banner_names_what_the_next_apply_does() {
        let first_line = |report: &Report| {
            render(report, View::Plan, Palette::PLAIN, Path::new(HOME))
                .lines()
                .next()
                .expect("a line")
                .to_string()
        };

        assert!(first_line(&Report::default()).starts_with("Plan: "));

        let running = Report {
            apply_running: true,
            interrupted: Some(interrupted(vec![])),
            ..Report::default()
        };
        assert!(first_line(&running).starts_with("A bx apply is running"));

        let rolled = Report {
            interrupted: Some(interrupted(vec![unfinished(true)])),
            ..Report::default()
        };
        // Decision 18: apply rolls back only what is shown and writes nothing
        // else, so the banner says to plan again afterwards.
        assert_eq!(
            first_line(&rolled),
            "An interrupted bx apply was found. `bx apply` rolls back what is shown below and \
             writes nothing else; run `bx plan` again after `bx apply` rolls these back."
        );

        let mut complete = interrupted(vec![unfinished(true)]);
        complete.complete = true;
        let complete = Report {
            interrupted: Some(complete),
            ..Report::default()
        };
        assert!(first_line(&complete).contains("records it and writes nothing else"));

        let blocked = Report {
            interrupted: Some(interrupted(vec![unfinished(true), unfinished(false)])),
            ..Report::default()
        };
        assert!(
            first_line(&blocked).contains("left 1 file(s) bx cannot account for"),
            "{}",
            first_line(&blocked)
        );

        let mut unreadable = interrupted(vec![]);
        unreadable.unreadable = true;
        let unreadable = Report {
            interrupted: Some(unreadable),
            ..Report::default()
        };
        assert!(first_line(&unreadable).contains("cannot read"));
        for report in [&running, &rolled, &complete, &blocked, &unreadable] {
            assert!(
                !render(report, View::Plan, Palette::PLAIN, Path::new(HOME)).contains(HOME),
                "a banner named an absolute path"
            );
        }
    }
}
