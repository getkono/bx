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
    let target = if visible {
        ProgressDrawTarget::stderr()
    } else {
        ProgressDrawTarget::hidden()
    };
    ProgressBar::with_draw_target(Some(u64::try_from(len).unwrap_or(u64::MAX)), target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_progress_bar_is_hidden_unless_asked_for() {
        assert!(progress(3, false).is_hidden());
        assert_eq!(progress(3, false).length(), Some(3));
    }
}
