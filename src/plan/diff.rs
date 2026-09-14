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
        if view == View::Plan && change.action == Action::Unchanged {
            continue;
        }
        row(&mut out, change, palette, home);
    }
    out.push_str(&report::summary(&report.actions()));
    out.push('\n');
    out
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
        "An interrupted bx session left a journal bx cannot read; the next `bx apply` sets it \
         aside before it writes anything."
            .to_string()
    } else if blocked > 0 {
        format!(
            "An interrupted bx {kind} left {blocked} file(s) bx cannot account for; `bx apply` \
             refuses until they are resolved."
        )
    } else if interrupted.complete {
        format!(
            "An interrupted bx {kind} wrote everything but did not record it; the next \
             `bx apply` records it before it writes anything."
        )
    } else {
        format!(
            "An interrupted bx {kind} was found; the next `bx apply` rolls it back before it \
             writes anything."
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
        change.target,
        paths::to_portable(&change.origin.file, home),
        change.origin.line,
    );
    if let Some(note) = &change.note {
        let _ = write!(out, " {note}");
    }
    out.push('\n');

    let Some(diff) = &change.diff else {
        return;
    };
    match &diff.kind {
        DiffKind::Text(text) => {
            for (index, line) in text.lines().enumerate() {
                let style = match line.as_bytes().first() {
                    // The first two lines are the `---` and `+++` file headers.
                    _ if index < 2 => Some(HEADER),
                    Some(b'+') => Some(ADDED),
                    Some(b'-') => Some(REMOVED),
                    Some(b'@') => Some(QUIET),
                    _ => None,
                };
                out.push_str(DIFF_INDENT);
                match style {
                    Some(style) => out.push_str(&palette.paint(style, line)),
                    None => out.push_str(line),
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
        assert_eq!(
            first_line(&rolled),
            "An interrupted bx apply was found; the next `bx apply` rolls it back before it \
             writes anything."
        );

        let mut complete = interrupted(vec![unfinished(true)]);
        complete.complete = true;
        let complete = Report {
            interrupted: Some(complete),
            ..Report::default()
        };
        assert!(first_line(&complete).contains("records it before"));

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
