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
use similar::{ChangeTag, TextDiff};

use super::{Change, Report};
use crate::fs::Mode;
use crate::paths;
use crate::report::{self, Action, escape};
use crate::shell::activation;

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
    /// Several unified diffs of one target, each headed as [`DiffKind::Text`]
    /// is: a tracked target both sides changed, shown as what this machine
    /// and what the repo each did since the last sync.
    Texts(Vec<String>),
    /// Only the mode differs; the bytes are identical.
    Mode {
        /// The mode on disk.
        from: Mode,
        /// The mode bx would set.
        to: Mode,
    },
    /// A symlink's text: the link on disk and the one bx would leave, either
    /// `None` where there is no link. A link has no content to diff, so its
    /// text is the whole of what changes.
    Link {
        /// The text of the link on disk.
        from: Option<String>,
        /// The text of the link bx would leave.
        to: Option<String>,
    },
    /// A declared git external's checkout: the commit on disk, `None` where
    /// there is no checkout yet, and the commit bx would leave checked out
    /// from `url`. A checkout's files are git's to show, so the commit is the
    /// whole of what changes.
    Checkout {
        /// The commit checked out now.
        from: Option<String>,
        /// The commit bx would check out.
        to: String,
        /// Where it comes from.
        url: String,
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
    /// The target is a secret, whose content is never printed.
    Secret,
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

    /// The diff of a symlink target: the text of the link on disk, and the
    /// text of the one bx would leave, `None` on either side where there is
    /// no link.
    #[must_use]
    pub(super) fn link(from: Option<&Path>, to: Option<&Path>) -> Self {
        let text = |path: &Path| path.to_string_lossy().into_owned();
        Self {
            kind: DiffKind::Link {
                from: from.map(text),
                to: to.map(text),
            },
        }
    }

    /// The diff of a git external's checkout: the commit on disk, `None` where
    /// there is none, and the commit bx would check out from `url`.
    #[must_use]
    pub(super) fn checkout(from: Option<&str>, to: &str, url: &str) -> Self {
        Self {
            kind: DiffKind::Checkout {
                from: from.map(str::to_string),
                to: to.to_string(),
                url: url.to_string(),
            },
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
        Self::labelled(target, ("on disk", "bx"), before, after, mode)
    }

    /// [`Diff::between`], with the two sides named `labels` in the file
    /// headers rather than `on disk` and `bx`: a tracked target's sides are
    /// the repo's copy and this machine's, and neither is what bx wants.
    #[must_use]
    pub(super) fn labelled(
        target: &str,
        labels: (&str, &str),
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
                (Ok(old), Ok(new)) => DiffKind::Text(unified(target, labels, old, new)),
                _ => summary(Why::Binary),
            }
        };
        Some(Self { kind })
    }

    /// A tracked target both sides changed since `base`, the bytes they last
    /// agreed on: what this machine did to it and what the repo did to it, as
    /// two diffs. Where either cannot be shown line by line, the one line
    /// that says how the repo's copy and this machine's differ.
    #[must_use]
    pub(super) fn diverged(target: &str, base: &[u8], machine: &[u8], repo: &[u8]) -> Self {
        let side =
            |label, after| Self::labelled(target, ("last sync", label), Some(base), after, None);
        match (side("this machine", machine), side("repo", repo)) {
            (
                Some(Self {
                    kind: DiffKind::Text(mine),
                }),
                Some(Self {
                    kind: DiffKind::Text(theirs),
                }),
            ) => Self {
                kind: DiffKind::Texts(vec![mine, theirs]),
            },
            _ => Self {
                kind: DiffKind::Summary {
                    before: Some(repo.len()),
                    after: machine.len(),
                    why: if repo.len().max(machine.len()).max(base.len()) > TEXT_LIMIT {
                        Why::TooLarge
                    } else {
                        Why::Binary
                    },
                },
            },
        }
    }

    /// [`Diff::between`] for content that must not be printed: a secret's
    /// plaintext, and whatever sits where it goes. A mode change is still
    /// shown; changed content is only counted.
    #[must_use]
    pub(super) fn concealed(
        _target: &str,
        before: Option<&[u8]>,
        after: &[u8],
        mode: Option<(Mode, Mode)>,
    ) -> Option<Self> {
        if before == Some(after) {
            return mode.map(|(from, to)| Self {
                kind: DiffKind::Mode { from, to },
            });
        }
        Some(Self {
            kind: DiffKind::Summary {
                before: before.map(<[u8]>::len),
                after: after.len(),
                why: Why::Secret,
            },
        })
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
pub(crate) fn unified(target: &str, (from, to): (&str, &str), old: &str, new: &str) -> String {
    let old: Vec<&str> = old.split_inclusive('\n').collect();
    let new: Vec<&str> = new.split_inclusive('\n').collect();
    let diff = TextDiff::configure()
        .newline_terminated(true)
        .diff_slices(&old, &new);
    let target = escape(target);
    let mut unified = diff.unified_diff();
    unified.context_radius(CONTEXT);
    let mut out = String::new();
    let _ = writeln!(out, "--- {target} ({from})\n+++ {target} ({to})");
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

/// Which rows a rendering shows.
///
/// There is one view since bare `bx` stopped listing every row, unchanged
/// ones included: `bx status` lays the same report out as `git status`
/// would, in [`crate::status`], and draws no diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// `bx plan` and `bx apply`: only what is not already converged.
    Plan,
}

/// Whether a rendering is coloured, and how wide it is drawn.
///
/// Decided once, from the environment, and carried explicitly: nothing that
/// renders reads `NO_COLOR`, asks whether it is writing to a terminal, or asks
/// how wide that terminal is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    color: bool,
    /// The columns a diff's file header is ruled to.
    width: usize,
}

/// The width a rendering is drawn to where the terminal's is unknown: output
/// that is not a terminal, or a terminal that does not say.
pub const DEFAULT_WIDTH: usize = 80;

impl Palette {
    /// No escape sequences at all, [`DEFAULT_WIDTH`] wide.
    #[cfg(test)]
    pub const PLAIN: Self = Self {
        color: false,
        width: DEFAULT_WIDTH,
    };

    /// Colour only on a terminal, and only when `NO_COLOR` is unset or empty —
    /// `no_color` is whether it is set to anything else. 80 columns wide
    /// until [`Palette::within`] says otherwise.
    #[must_use]
    pub const fn resolve(no_color: bool, tty: bool) -> Self {
        Self {
            color: tty && !no_color,
            width: DEFAULT_WIDTH,
        }
    }

    /// This palette drawn `columns` wide, or 80 columns where the width is
    /// unknown.
    #[must_use]
    pub fn within(self, columns: Option<u16>) -> Self {
        Self {
            width: columns.map_or(DEFAULT_WIDTH, usize::from),
            ..self
        }
    }

    /// Whether this palette emits colour.
    #[cfg(test)]
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
/// The words that changed inside an added line.
const ADDED_EMPHASIS: Style = ADDED.invert();
/// The words that changed inside a removed line.
const REMOVED_EMPHASIS: Style = REMOVED.invert();
/// A hunk header, a line-number gutter, and the symbol of a row nothing
/// happens to.
const QUIET: Style = Style::new().dimmed();
/// A diff's file header.
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
    for (at, change) in report.changes.iter().enumerate() {
        // A deletion that stands is unchanged, and still said, as `git
        // status` says one: it is a question a writing run asks.
        // So is a row whose question stands answered *keep*.
        let asked =
            report.questions.iter().any(|question| question.row == at) || report.kept.contains(&at);
        if view == View::Plan
            && change.action == Action::Unchanged
            && !interrupted(report)
            && !asked
        {
            continue;
        }
        row(&mut out, change, palette, home);
    }
    for step in report.activations.steps() {
        let action = step.action();
        if view == View::Plan && action == Action::Unchanged {
            continue;
        }
        activation_row(&mut out, step, palette);
    }
    out.push_str(&report::summary(&report.actions()));
    out.push('\n');
    out
}

/// Render one row and `diff` beneath it in place of its own: the view a
/// question about an edited file shows when asked to, drawn as [`render`]
/// draws every row.
#[must_use]
pub fn render_row(change: &Change, diff: Option<&Diff>, palette: Palette, home: &Path) -> String {
    let mut out = String::new();
    let shown = Change {
        diff: diff.cloned().or_else(|| change.diff.clone()),
        ..change.clone()
    };
    row(&mut out, &shown, palette, home);
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

/// One line of a unified diff's body as [`unified`] wrote it, read back with
/// the line numbers its hunk header gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line<'a> {
    /// `@@ -a,b +c,d @@`.
    Hunk(&'a str),
    /// A line both sides have, at `old` and at `new`.
    Context {
        old: usize,
        new: usize,
        text: &'a str,
    },
    /// A line only the old side has, at `old`.
    Removed { old: usize, text: &'a str },
    /// A line only the new side has, at `new`.
    Added { new: usize, text: &'a str },
    /// `\ No newline at end of file`, or anything else [`unified`] does not
    /// write: shown as it is, with no line number.
    Note(&'a str),
}

/// The first line number of each side a hunk header names: `-a,b +c,d` gives
/// `a` and `c`, a count left out where it is one.
fn hunk_starts(header: &str) -> Option<(usize, usize)> {
    let mut ranges = header.strip_prefix("@@ -")?.split(' ');
    let start = |range: &str| range.split(',').next()?.parse().ok();
    let old = start(ranges.next()?)?;
    let new = start(ranges.next()?.strip_prefix('+')?)?;
    Some((old, new))
}

/// The body of a unified diff, each line numbered.
fn numbered<'a>(body: &[&'a str]) -> Vec<Line<'a>> {
    let (mut old, mut new) = (0, 0);
    body.iter()
        .map(|&line| {
            if let Some(starts) = hunk_starts(line) {
                (old, new) = starts;
                return Line::Hunk(line);
            }
            let text = line.get(1..).unwrap_or_default();
            match line.as_bytes().first() {
                Some(b' ') => {
                    let line = Line::Context { old, new, text };
                    (old, new) = (old + 1, new + 1);
                    line
                }
                Some(b'-') => {
                    old += 1;
                    Line::Removed { old: old - 1, text }
                }
                Some(b'+') => {
                    new += 1;
                    Line::Added { new: new - 1, text }
                }
                _ => Line::Note(line),
            }
        })
        .collect()
}

/// The words each changed line changed, by the index of the line in `lines`:
/// `Some` only for a line in a run of removed lines followed by added ones
/// that `similar` pairs as an edit, rather than as unrelated text, with each
/// piece of the line marked by whether it is one the edit changed.
fn emphasis(lines: &[Line<'_>]) -> Vec<Option<Vec<(bool, String)>>> {
    let mut emphasis = vec![None; lines.len()];
    // The removed lines of the run being read, and the added lines after
    // them. A removed line after an added one starts the next run; a note — a
    // missing newline — sits inside a run without ending it; anything else
    // ends it. Added lines with no removed line before them pair with
    // nothing: `similar` emphasises words only where it pairs an edit.
    let (mut removed, mut added) = (Vec::new(), Vec::new());
    for (index, line) in lines.iter().enumerate() {
        match line {
            Line::Removed { .. } if added.is_empty() => removed.push(index),
            Line::Removed { .. } => {
                pair(lines, &removed, &added, &mut emphasis);
                (removed, added) = (vec![index], Vec::new());
            }
            Line::Added { .. } => added.push(index),
            Line::Note(_) => {}
            Line::Hunk(_) | Line::Context { .. } => {
                pair(lines, &removed, &added, &mut emphasis);
                (removed, added) = (Vec::new(), Vec::new());
            }
        }
    }
    pair(lines, &removed, &added, &mut emphasis);
    emphasis
}

/// Mark in `emphasis` the words of each line in `removed` that `similar`
/// pairs with one in `added` as an edit, each a line's index in `lines`.
/// Either side empty pairs nothing: a whole-line insert or delete carries no
/// emphasised piece.
fn pair(
    lines: &[Line<'_>],
    removed: &[usize],
    added: &[usize],
    emphasis: &mut [Option<Vec<(bool, String)>>],
) {
    let text = |index: &usize| match lines[*index] {
        Line::Removed { text, .. } | Line::Added { text, .. } => text,
        _ => "",
    };
    let old: Vec<&str> = removed.iter().map(text).collect();
    let new: Vec<&str> = added.iter().map(text).collect();
    let diff = TextDiff::configure().diff_slices(&old, &new);
    for op in diff.ops() {
        for change in diff.iter_inline_changes(op) {
            let line = match change.tag() {
                ChangeTag::Delete => change.old_index().map(|index| removed[index]),
                ChangeTag::Insert => change.new_index().map(|index| added[index]),
                ChangeTag::Equal => None,
            };
            let values = change.values();
            if let Some(line) = line
                && values.iter().any(|(emphasised, _)| *emphasised)
            {
                // `similar` gives a single line's pieces with adjacent ones
                // already joined where they are alike.
                emphasis[line] = Some(
                    values
                        .iter()
                        .map(|&(emphasised, value)| (emphasised, value.to_string()))
                        .collect(),
                );
            }
        }
    }
}

/// The file header of a unified diff as [`unified`] wrote it — `--- T (a)`
/// and `+++ T (b)` — as the one title `T (a → b)`.
fn title(from: &str, to: &str) -> Option<String> {
    fn side<'a>(line: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
        line.strip_prefix(prefix)?
            .strip_suffix(')')?
            .rsplit_once(" (")
    }
    let (target, before) = side(from, "--- ")?;
    let (also, after) = side(to, "+++ ")?;
    (target == also).then(|| format!("{target} ({before} → {after})"))
}

/// The lines of one unified diff as [`unified`] wrote it, drawn the way a
/// reader scans a change: one file header ruled to the palette's width, each
/// line behind a gutter of its old and new line numbers, and, in colour, the
/// words an edited line changed in reverse video on its red or green.
///
/// The sign of each line stays in front of its text, so the plain rendering
/// reads without colour exactly as the coloured one does.
fn unified_rows(out: &mut String, text: &str, palette: Palette) {
    // Split on `\n` alone, as `unified` wrote it: a `\r` is part of its
    // line, and is shown escaped with every other control character.
    let lines: Vec<&str> = text
        .strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .collect();
    let (header, body) = match lines.as_slice() {
        [from, to, body @ ..] => match title(from, to) {
            Some(title) => (vec![ruled(&title, palette.width)], body),
            None => (vec![(*from).to_string(), (*to).to_string()], body),
        },
        _ => (Vec::new(), lines.as_slice()),
    };
    for line in header {
        let _ = writeln!(
            out,
            "{DIFF_INDENT}{}",
            palette.paint(HEADER, &escape(&line))
        );
    }

    let lines = numbered(body);
    let emphasis = emphasis(&lines);
    let widest = lines
        .iter()
        .map(|line| match *line {
            Line::Context { old, new, .. } => old.max(new),
            Line::Removed { old, .. } => old,
            Line::Added { new, .. } => new,
            Line::Hunk(_) | Line::Note(_) => 0,
        })
        .max()
        .unwrap_or_default();
    let digits = widest.to_string().len();
    let gutter = |old: Option<usize>, new: Option<usize>| {
        let number = |n: Option<usize>| n.map_or_else(String::new, |n| n.to_string());
        let gutter = format!("{:>digits$} {:>digits$} │", number(old), number(new));
        palette.paint(QUIET, &gutter)
    };
    for (line, emphasis) in lines.iter().zip(&emphasis) {
        out.push_str(DIFF_INDENT);
        match *line {
            Line::Hunk(header) => out.push_str(&palette.paint(QUIET, &escape(header))),
            Line::Context { old, new, text } => {
                let _ = write!(out, "{}  {}", gutter(Some(old), Some(new)), escape(text));
            }
            Line::Removed { old, text } => {
                let _ = write!(out, "{} ", gutter(Some(old), None));
                changed(
                    out,
                    '-',
                    text,
                    emphasis.as_deref(),
                    palette,
                    REMOVED,
                    REMOVED_EMPHASIS,
                );
            }
            Line::Added { new, text } => {
                let _ = write!(out, "{} ", gutter(None, Some(new)));
                changed(
                    out,
                    '+',
                    text,
                    emphasis.as_deref(),
                    palette,
                    ADDED,
                    ADDED_EMPHASIS,
                );
            }
            Line::Note(note) => {
                let _ = write!(
                    out,
                    "{} {}",
                    gutter(None, None),
                    palette.paint(QUIET, &escape(note))
                );
            }
        }
        out.push('\n');
    }
}

/// `title` as a file header ruled out to `width` columns —
/// `── ~/.gitconfig (on disk → bx) ─────…` — counting the diff's indentation,
/// and with a short rule still after a title too long to fit.
fn ruled(title: &str, width: usize) -> String {
    const MIN_RULE: usize = 3;
    // The indentation, `── ` before the title and ` ` after it.
    let taken = DIFF_INDENT.len() + 3 + escape(title).chars().count() + 1;
    let rule = width.saturating_sub(taken).max(MIN_RULE);
    format!("── {title} {}", "─".repeat(rule))
}

/// A removed or added line, `sign` and its text in `style`, and the pieces
/// `emphasis` marks in `strong`.
fn changed(
    out: &mut String,
    sign: char,
    text: &str,
    emphasis: Option<&[(bool, String)]>,
    palette: Palette,
    style: Style,
    strong: Style,
) {
    match emphasis {
        // Without colour the pieces join to `text`, escaped alike.
        Some(pieces) => {
            out.push_str(&palette.paint(style, &sign.to_string()));
            for (emphasised, piece) in pieces {
                let style = if *emphasised { strong } else { style };
                out.push_str(&palette.paint(style, &escape(piece)));
            }
        }
        _ => out.push_str(&palette.paint(style, &format!("{sign}{}", escape(text)))),
    }
}

/// One activation, as [`activation::Step::line`] says it, its symbol styled
/// as a change's is. Escaped whole: an omission can quote what a tool printed
/// on standard error.
fn activation_row(out: &mut String, step: &activation::Step, palette: Palette) {
    let action = step.action();
    let style = if action.needs_attention() {
        ATTENTION
    } else if action.is_pending() {
        PENDING
    } else {
        QUIET
    };
    let line = step.line();
    let symbol = action.symbol();
    let rest = line.strip_prefix(symbol).unwrap_or(&line);
    let _ = writeln!(
        out,
        "{ROW_INDENT}{}{}",
        palette.paint(style, &symbol.to_string()),
        escape(rest),
    );
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
        DiffKind::Text(text) => unified_rows(out, text, palette),
        DiffKind::Texts(texts) => {
            for text in texts {
                unified_rows(out, text, palette);
            }
        }
        DiffKind::Mode { from, to } => {
            let _ = writeln!(out, "{DIFF_INDENT}mode {from} -> {to}");
        }
        // One line per side, each escaped like any other text a row shows, so
        // a link's text cannot move the cursor or start a line of its own.
        DiffKind::Link { from, to } => {
            for (sign, style, text) in [('-', REMOVED, from), ('+', ADDED, to)] {
                if let Some(text) = text {
                    let line = format!("{sign} symlink {}", escape(text));
                    let _ = writeln!(out, "{DIFF_INDENT}{}", palette.paint(style, &line));
                }
            }
        }
        // One line per side, escaped: the url is configuration text and the
        // commit on disk is what git printed.
        DiffKind::Checkout { from, to, url } => {
            if let Some(from) = from {
                let line = format!("- commit {}", escape(from));
                let _ = writeln!(out, "{DIFF_INDENT}{}", palette.paint(REMOVED, &line));
            }
            let line = format!("+ commit {} from {}", escape(to), escape(url));
            let _ = writeln!(out, "{DIFF_INDENT}{}", palette.paint(ADDED, &line));
        }
        DiffKind::Summary { before, after, why } => {
            let before = before.map_or_else(|| "no file".to_string(), |len| format!("{len} bytes"));
            let why = match why {
                Why::Binary => "binary content",
                Why::TooLarge => "too large to show",
                Why::Secret => "secret, not shown",
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
    fn a_concealed_diff_counts_bytes_and_shows_only_a_mode() {
        assert_eq!(
            Diff::concealed("~/.s", None, b"token\n", None),
            Some(Diff {
                kind: DiffKind::Summary {
                    before: None,
                    after: 6,
                    why: Why::Secret
                }
            })
        );
        assert_eq!(
            Diff::concealed("~/.s", Some(b"old"), b"token\n", None).map(|diff| diff.kind),
            Some(DiffKind::Summary {
                before: Some(3),
                after: 6,
                why: Why::Secret
            })
        );
        let drift = Some((Mode::DEFAULT_FILE, Mode::PRIVATE_FILE));
        assert_eq!(
            Diff::concealed("~/.s", Some(b"same"), b"same", drift).map(|diff| diff.kind),
            Some(DiffKind::Mode {
                from: Mode::DEFAULT_FILE,
                to: Mode::PRIVATE_FILE
            })
        );
        assert_eq!(Diff::concealed("~/.s", Some(b"same"), b"same", None), None);
    }

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
    fn an_empty_body_where_there_was_no_file_is_the_header_alone() {
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
        assert!(
            lines[1].starts_with("    ── ~/.a (on disk → bx) ───"),
            "{shown}"
        );
        assert!(lines[2].starts_with("Plan: "), "{shown}");
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

    #[test]
    fn a_diverged_side_that_cannot_be_shown_summarises_repo_against_machine() {
        let binary = Diff::diverged("~/.a", b"base\n", &[0xff], b"repo\n");
        assert_eq!(
            binary.kind,
            DiffKind::Summary {
                before: Some(5),
                after: 1,
                why: Why::Binary
            }
        );
        let big = vec![b'x'; TEXT_LIMIT + 1];
        let large = Diff::diverged("~/.a", b"base\n", b"mine\n", &big);
        assert_eq!(
            large.kind,
            DiffKind::Summary {
                before: Some(TEXT_LIMIT + 1),
                after: 5,
                why: Why::TooLarge
            }
        );
        // #343. A side exactly at the limit is not too large to diff, so the
        // summary is `Binary`, for the machine's bytes, not `TooLarge`.
        let at = vec![b'x'; TEXT_LIMIT];
        let binary_at_the_limit = Diff::diverged("~/.a", &at, &[0xff], b"repo\n");
        assert_eq!(
            binary_at_the_limit.kind,
            DiffKind::Summary {
                before: Some(5),
                after: 1,
                why: Why::Binary
            }
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
            format!(
                "  ~ ~/.gitconfig  (~/.config/bx/bx.toml:4)\n\
                 \x20   ── ~/.gitconfig (on disk → bx) {}\n\
                 \x20   @@ -2,7 +2,7 @@\n\
                 \x20   2 2 │  2\n\
                 \x20   3 3 │  3\n\
                 \x20   4 4 │  4\n\
                 \x20   5   │ -5\n\
                 \x20     5 │ +five\n\
                 \x20   6 6 │  6\n\
                 \x20   7 7 │  7\n\
                 \x20   8 8 │  8\n\
                 \x20 ? ~/.env  (~/.config/bx/bx.toml:12) run `bx init` to set scratch_root\n\
                 Plan: 0 to create, 1 to modify, 0 conflict, 1 blocked, 1 unchanged.\n",
                "─".repeat(45)
            )
        );
        assert!(!rendered.contains(HOME), "{rendered}");
        // The header is ruled to exactly the default width.
        let header = rendered.lines().nth(1).expect("a header");
        assert_eq!(header.chars().count(), DEFAULT_WIDTH, "{header}");
    }

    #[test]
    fn a_header_is_ruled_to_the_width_and_keeps_a_short_rule_past_it() {
        let header = |palette: Palette| {
            render(&a_report(), View::Plan, palette, Path::new(HOME))
                .lines()
                .nth(1)
                .expect("a header")
                .to_string()
        };
        assert_eq!(Palette::PLAIN.within(None), Palette::PLAIN);
        assert_eq!(
            header(Palette::PLAIN.within(Some(120))).chars().count(),
            120
        );
        // The narrowest width a full rule fits: the title and three of it.
        assert_eq!(header(Palette::PLAIN.within(Some(38))).chars().count(), 38);
        // Narrower than the title: three rule characters still follow it.
        assert_eq!(
            header(Palette::PLAIN.within(Some(10))),
            "    ── ~/.gitconfig (on disk → bx) ───"
        );
        // A width of zero is a terminal that cannot say, drawn as narrow.
        assert_eq!(
            header(Palette::PLAIN.within(Some(0))),
            "    ── ~/.gitconfig (on disk → bx) ───"
        );
    }

    #[test]
    fn a_gutter_is_as_wide_as_the_largest_line_number() {
        let before: String = (1..=12).map(|n| format!("{n}\n")).collect();
        let after = before.replace("10\n", "ten\n");
        let mut modify = change("~/.n", 1, Action::Modify);
        modify.diff = Diff::between("~/.n", Some(before.as_bytes()), after.as_bytes(), None);

        let rendered = plain(&Report {
            changes: vec![modify],
            ..Report::default()
        });

        assert!(
            rendered.contains(
                "    @@ -7,6 +7,6 @@\n     7  7 │  7\n     8  8 │  8\n     9  9 │  9\n    \
                 10    │ -10\n       10 │ +ten\n    11 11 │  11\n    12 12 │  12\n"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn an_edited_line_emphasises_the_words_it_changed_in_colour_only() {
        let mut modify = change("~/.w", 1, Action::Modify);
        modify.diff = Diff::between(
            "~/.w",
            Some(b"name = alice\nkeep\n"),
            b"name = bob\nkeep\n",
            None,
        );
        let report = Report {
            changes: vec![modify],
            ..Report::default()
        };

        let plain = plain(&report);
        assert!(
            plain.contains("    1   │ -name = alice\n      1 │ +name = bob\n    2 2 │  keep\n"),
            "{plain}"
        );
        assert!(!plain.contains('\x1b'), "{plain:?}");

        let coloured = render(
            &report,
            View::Plan,
            Palette::resolve(false, true),
            Path::new(HOME),
        );
        let paint =
            |style: Style, text: &str| format!("{}{text}{}", style.render(), style.render_reset());
        let removed = [
            paint(REMOVED, "-"),
            paint(REMOVED, "name = "),
            paint(REMOVED_EMPHASIS, "alice"),
        ]
        .concat();
        let added = [
            paint(ADDED, "+"),
            paint(ADDED, "name = "),
            paint(ADDED_EMPHASIS, "bob"),
        ]
        .concat();
        assert!(coloured.contains(&removed), "{coloured:?}");
        assert!(coloured.contains(&added), "{coloured:?}");
        // The gutter is dimmed; the unchanged line is not emphasised.
        assert!(coloured.contains(&paint(QUIET, "2 2 │")), "{coloured:?}");
        assert!(coloured.contains("  keep\n"), "{coloured:?}");
    }

    #[test]
    fn emphasis_pairs_each_run_of_removed_lines_with_the_added_ones_after_it() {
        let removed = |old, text| Line::Removed { old, text };
        let added = |new, text| Line::Added { new, text };
        let context = Line::Context {
            old: 9,
            new: 9,
            text: "same",
        };
        let pieces = |words: &[&str]| {
            let mut pieces = vec![(false, "a ".to_string())];
            for (at, word) in words.iter().enumerate() {
                if at > 0 {
                    pieces.push((false, " ".to_string()));
                }
                pieces.push((true, (*word).to_string()));
            }
            Some(pieces)
        };
        let edit = |before: &[&str], after: &[&str]| vec![pieces(before), pieces(after)];
        // Two removed lines then two added: both pair, the first with the
        // first, across the note between them. The words alike before an
        // edit, `a` and the space after it, are one piece.
        let lines = [
            removed(1, "a one two"),
            removed(2, "a b"),
            Line::Note("\\ No newline at end of file"),
            added(1, "a three four"),
            added(2, "a c"),
        ];
        let got = emphasis(&lines);
        assert_eq!(got[0], edit(&["one", "two"], &["three", "four"])[0]);
        assert_eq!(got[1], edit(&["b"], &["c"])[0]);
        assert_eq!(got[2], None);
        assert_eq!(got[3], edit(&["one", "two"], &["three", "four"])[1]);
        assert_eq!(got[4], edit(&["b"], &["c"])[1]);

        // A removed line after an added one starts a run of its own, and a
        // context line ends one: neither pairs across it.
        let lines = [
            removed(1, "a b"),
            added(1, "a c"),
            removed(2, "x y z"),
            context,
            added(3, "x y q"),
            added(4, "lone"),
        ];
        let got = emphasis(&lines);
        assert_eq!(got[..2], edit(&["b"], &["c"]));
        assert_eq!(got[2..], [None, None, None, None]);

        // A word replaced and the words deleted after it are one emphasised
        // piece.
        let got = emphasis(&[removed(1, "a b c"), added(1, "a x")]);
        assert_eq!(
            got[0],
            Some(vec![(false, "a ".to_string()), (true, "b c".to_string())])
        );
    }

    #[test]
    fn a_missing_newline_does_not_break_a_run_or_take_a_line_number() {
        let mut modify = change("~/.m", 1, Action::Modify);
        modify.diff = Diff::between("~/.m", Some(b"key = one"), b"key = two", None);
        let report = Report {
            changes: vec![modify],
            ..Report::default()
        };

        let plain = plain(&report);
        assert!(
            plain.contains(
                "    1   │ -key = one\n        │ \\ No newline at end of file\n      \
                 1 │ +key = two\n        │ \\ No newline at end of file\n"
            ),
            "{plain}"
        );
        let coloured = render(
            &report,
            View::Plan,
            Palette::resolve(false, true),
            Path::new(HOME),
        );
        let strong = format!(
            "{}two{}",
            ADDED_EMPHASIS.render(),
            ADDED_EMPHASIS.render_reset()
        );
        assert!(coloured.contains(&strong), "{coloured:?}");
    }

    #[test]
    fn a_header_bx_did_not_write_is_shown_as_it_stands() {
        let mut out = String::new();
        unified_rows(
            &mut out,
            "--- a (x)\n+++ b (y)\n@@ -1 +1 @@\n-p\n+q\n",
            Palette::PLAIN,
        );
        assert_eq!(
            out,
            "    --- a (x)\n    +++ b (y)\n    @@ -1 +1 @@\n    1   │ -p\n      1 │ +q\n"
        );
        assert_eq!(hunk_starts("@@ -3,0 +4,2 @@"), Some((3, 4)));
        assert_eq!(hunk_starts("@@ -x +1 @@"), None);
        assert_eq!(hunk_starts("not a hunk"), None);
        assert_eq!(
            title("--- a (x)", "+++ a (y)"),
            Some("a (x → y)".to_string())
        );
        assert_eq!(title("--- a", "+++ a (y)"), None);
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
    fn a_checkout_renders_the_commit_on_each_side_and_its_url_escaped() {
        let mut advance = change("~/.zsh/a", 1, Action::Modify);
        advance.diff = Some(Diff::checkout(Some("aaa"), "bbb", "https://h/o/a"));
        let mut clone = change("~/.zsh/b", 2, Action::Create);
        clone.diff = Some(Diff::checkout(None, "ccc", "https://h/o/\x1b[2Jb"));
        let report = Report {
            changes: vec![advance, clone],
            ..Report::default()
        };

        let rendered = render(&report, View::Plan, Palette::PLAIN, Path::new(HOME));

        assert!(
            rendered.contains("    - commit aaa\n    + commit bbb from https://h/o/a\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("  + ~/.zsh/b  (~/.config/bx/bx.toml:2)\n    + commit ccc from "),
            "{rendered}"
        );
        assert!(!rendered.contains('\x1b'), "{rendered:?}");
    }

    #[test]
    fn a_link_renders_its_text_on_each_side_escaped_and_coloured() {
        let mut retarget = change("~/.tool", 1, Action::Modify);
        retarget.diff = Some(Diff::link(
            Some(Path::new("/opt/one")),
            Some(Path::new("/opt/two\x1b[2J")),
        ));
        let mut create = change("~/.new", 2, Action::Create);
        create.diff = Some(Diff::link(None, Some(Path::new("../x"))));
        let report = Report {
            changes: vec![retarget, create],
            ..Report::default()
        };

        let plain = render(&report, View::Plan, Palette::PLAIN, Path::new(HOME));
        assert!(
            plain.contains(
                "  ~ ~/.tool  (~/.config/bx/bx.toml:1)\n    - symlink /opt/one\n    \
                 + symlink /opt/two\\x1b[2J\n"
            ),
            "{plain}"
        );
        assert!(
            plain.contains("  + ~/.new  (~/.config/bx/bx.toml:2)\n    + symlink ../x\n"),
            "{plain}"
        );

        let coloured = render(
            &report,
            View::Plan,
            Palette::resolve(false, true),
            Path::new(HOME),
        );
        let red = format!(
            "{}- symlink /opt/one{}",
            REMOVED.render(),
            REMOVED.render_reset()
        );
        let green = format!("{}+ symlink ../x{}", ADDED.render(), ADDED.render_reset());
        assert!(coloured.contains(&red), "{coloured:?}");
        assert!(coloured.contains(&green), "{coloured:?}");
    }

    #[test]
    fn t18_colour_only_on_a_terminal_without_no_color() {
        assert_eq!(Palette::resolve(true, true), Palette::PLAIN);
        assert_eq!(Palette::resolve(false, false), Palette::PLAIN);
        assert_eq!(Palette::resolve(true, false), Palette::PLAIN);
        assert!(Palette::resolve(false, true).is_colored());
        assert!(!Palette::PLAIN.is_colored());

        // `~/.b` stands answered *keep*, so its unchanged row is shown.
        let report = Report {
            kept: vec![1],
            ..a_report()
        };
        let plain = render(
            &report,
            View::Plan,
            Palette::resolve(true, true),
            Path::new(HOME),
        );
        assert!(!plain.contains('\x1b'), "{plain:?}");

        let coloured = render(
            &report,
            View::Plan,
            Palette::resolve(false, true),
            Path::new(HOME),
        );
        assert!(coloured.contains("\x1b[32m+five\x1b[0m"), "{coloured:?}");
        assert!(coloured.contains("\x1b[31m-5\x1b[0m"), "{coloured:?}");
        assert!(
            coloured.contains("\x1b[2m@@ -2,7 +2,7 @@\x1b[0m"),
            "{coloured:?}"
        );
        assert!(coloured.contains("\x1b[1m── ~/.gitconfig (on disk → bx) ─"));
        // The gutter is dimmed, and a context line's text is not styled.
        assert!(
            coloured.contains("\x1b[2m2 2 │\x1b[0m  2\n"),
            "{coloured:?}"
        );
        assert!(coloured.contains("\x1b[2m5   │\x1b[0m \x1b[31m-5\x1b[0m\n"));
        // Symbols by what they ask of a human.
        assert!(
            coloured.contains("\x1b[1m\x1b[33m?\x1b[0m") || coloured.contains("\x1b[33m\x1b[1m?")
        );
        assert!(coloured.contains("\x1b[2m=\x1b[0m"), "{coloured:?}");
        // The summary and a context line stay plain.
        assert!(coloured.ends_with("1 unchanged.\n"));
    }

    #[test]
    fn no_escape_is_written_under_no_color_or_off_a_terminal_whatever_the_width() {
        let mut edit = change("~/.w", 1, Action::Modify);
        edit.diff = Diff::between("~/.w", Some(b"a = one\n"), b"a = two\n", None);
        let report = Report {
            changes: vec![edit],
            ..Report::default()
        };
        for palette in [
            Palette::resolve(true, true),
            Palette::resolve(false, false),
            Palette::resolve(true, true).within(Some(200)),
        ] {
            let shown = render(&report, View::Plan, palette, Path::new(HOME));
            assert!(!shown.contains('\x1b'), "{shown:?}");
            // The row symbol and the summary line are as a machine reads them.
            assert!(
                shown.starts_with("  ~ ~/.w  (~/.config/bx/bx.toml:1)\n"),
                "{shown}"
            );
            assert!(shown.ends_with(
                "\nPlan: 0 to create, 1 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
            ));
        }
    }

    #[test]
    fn t19_unchanged_rows_are_hidden_in_plan_and_counted() {
        let plan = render(&a_report(), View::Plan, Palette::PLAIN, Path::new(HOME));

        assert!(!plan.contains("~/.b"), "{plan}");
        assert_eq!(
            plan.lines().last(),
            Some("Plan: 0 to create, 1 to modify, 0 conflict, 1 blocked, 1 unchanged.")
        );
        let empty = render(
            &Report::default(),
            View::Plan,
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
        // Splitting lines with `str::lines` would drop a `\r` before the
        // `\n`, so a CRLF-only change would show identical lines.
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
            rendered.contains("    1   │ -a\\r\n    2   │ -b\\r\n      1 │ +a\n      2 │ +b\n"),
            "{rendered:?}"
        );
        assert!(!rendered.contains('\r'), "{rendered:?}");
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
            rendered.contains("    1   │ -one\n    2   │ -two\n      1 │ +one\\rtwo\n"),
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
            rendered.contains("      1 │ +\\x1b[31mred\tx\\x7f\n"),
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
        assert!(
            lines[1].starts_with("    ── ~/.a\\nb (on disk → bx) ───"),
            "{rendered:?}"
        );
        assert_eq!(lines[2], "    @@ -0,0 +1 @@", "{rendered:?}");
        assert_eq!(lines[3], "      1 │ +x", "{rendered:?}");
        assert_eq!(lines.len(), 5, "{rendered:?}");
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
