//! The writing half: every write a decision produced, through one session.
//!
//! [`execute`] is handed the writes and the session and nothing else — no
//! target, no configuration, no inputs — and it reads nothing. It cannot
//! decide anything, so it cannot do work `plan` did not announce.

use indicatif::{ProgressBar, ProgressDrawTarget};

use super::Error;
use super::decide::Op;
use crate::journal::Session;

/// Make every write through `session`, in order, then finish it.
///
/// The first failure is returned as it is. The session is then poisoned and
/// its journal stays, so the next writing run rolls back whatever this one
/// published.
///
/// # Errors
///
/// [`Error::Journal`] for whatever the session refuses or fails, including a
/// destination that changed since it was observed.
pub(super) fn execute(
    ops: Vec<Op>,
    mut session: Session,
    progress: &ProgressBar,
) -> Result<usize, Error> {
    for op in ops {
        progress.set_message(op.target().to_string());
        session.apply(op.into_request())?;
        progress.inc(1);
    }
    let written = session.finish()?;
    progress.finish_and_clear();
    Ok(written)
}

/// A progress bar over `len` writes, drawn on standard error only when it is a
/// terminal.
pub(super) fn progress(len: usize, visible: bool) -> ProgressBar {
    progress_to(len, visible, ProgressDrawTarget::stderr)
}

/// [`progress`], drawn on what `terminal` makes when `visible` and hidden
/// otherwise.
///
/// `terminal` is standard error in every caller but a test: indicatif reports a
/// bar on a standard error that is not a terminal as hidden, and a test's
/// standard error is a pipe.
fn progress_to(
    len: usize,
    visible: bool,
    terminal: impl FnOnce() -> ProgressDrawTarget,
) -> ProgressBar {
    let target = if visible {
        terminal()
    } else {
        ProgressDrawTarget::hidden()
    };
    ProgressBar::with_draw_target(Some(u64::try_from(len).unwrap_or(u64::MAX)), target)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A terminal that takes every draw and shows nothing.
    #[derive(Debug)]
    struct Terminal;

    impl indicatif::TermLike for Terminal {
        fn width(&self) -> u16 {
            80
        }

        fn move_cursor_up(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn move_cursor_down(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn move_cursor_right(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn move_cursor_left(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn write_line(&self, _: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn write_str(&self, _: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn clear_line(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn flush(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_progress_bar_is_hidden_unless_asked_for() {
        assert!(progress(3, false).is_hidden());
        assert_eq!(progress(3, false).length(), Some(3));
    }

    #[test]
    fn a_progress_bar_asked_for_draws_on_the_terminal() {
        // P42R1-COV1. `progress(3, true)` draws on standard error, which is a
        // pipe under the test runner, so indicatif reports it hidden whatever
        // the branch chose; the branch is pinned through a terminal that is one.
        let terminal = || ProgressDrawTarget::term_like(Box::new(Terminal));

        let shown = progress_to(3, true, terminal);
        assert!(!shown.is_hidden());
        assert_eq!(shown.length(), Some(3));

        assert!(progress_to(3, false, terminal).is_hidden());
    }
}
