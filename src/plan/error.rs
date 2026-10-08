//! Everything that can stop a run, and how the errors of the modules a run
//! calls are folded into it.

use std::path::PathBuf;

use crate::config::{self, Origin};
use crate::{journal, recover, state};

/// Everything that can stop a run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There is no config repo.
    #[error("no bx config repo at {}; run `bx init` to create one", .0.display())]
    RepoMissing(PathBuf),
    /// The configuration could not be loaded, merged or resolved.
    #[error(transparent)]
    Config(config::Error),
    /// A target's `file` body could not be read from the config repo.
    #[error("{origin}: reading the body {}: {source}", .path.display())]
    Body {
        /// Where the target was declared.
        origin: Origin,
        /// The file that could not be read.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The state directory failed, including another bx holding it.
    #[error(transparent)]
    State(state::Error),
    /// A state file bx reads is something other than a regular file — a FIFO,
    /// a device, a link — which a read could wait on forever or never finish.
    #[error(
        "{} is not a regular file, so bx will not read it; move it out of the way and run bx \
         again",
        .path.display()
    )]
    NotARegularFile {
        /// The state file.
        path: PathBuf,
    },
    /// An interrupted session could not be inspected or resolved, including a
    /// recovery that is blocked on files it cannot account for.
    #[error(transparent)]
    Recover(recover::Error),
    /// The session refused or failed a write.
    #[error(transparent)]
    Journal(journal::Error),
    /// A destination could not be observed.
    #[error(transparent)]
    Fs(#[from] crate::fs::Error),
    /// There is something to apply, no `--yes`, and no terminal to ask on.
    /// The plan has been shown and none of it was applied. Names no command:
    /// `init` and `sync` reach it too, and `init` has by then written the
    /// answers it was given.
    #[error(
        "bx applies only what was confirmed, and there is no terminal to ask on; nothing \
         in the plan above was applied. Review it and rerun with --yes"
    )]
    NeedsConfirmation,
    /// The confirmation prompt failed.
    #[error("asking for confirmation: {0}")]
    Prompt(#[source] inquire::InquireError),
    /// The confirmation prompt was abandoned with Esc or Ctrl-C. Not a
    /// failure: the command says so in a line and exits [`crate::report::Exit::Canceled`],
    /// so this never reaches the error report.
    #[error("canceled at the confirmation prompt")]
    Canceled,
    /// The rendering could not be written to its output.
    #[error("writing the plan: {0}")]
    Output(#[source] std::io::Error),
}

impl From<config::Error> for Error {
    fn from(error: config::Error) -> Self {
        match error {
            config::Error::RepoMissing(repo) => Self::RepoMissing(repo),
            other => Self::Config(other),
        }
    }
}

impl From<state::Error> for Error {
    fn from(error: state::Error) -> Self {
        Self::State(error)
    }
}

impl From<journal::Error> for Error {
    fn from(error: journal::Error) -> Self {
        match error {
            journal::Error::State(error) => Self::State(error),
            other => Self::Journal(other),
        }
    }
}

impl From<recover::Error> for Error {
    fn from(error: recover::Error) -> Self {
        match error {
            recover::Error::State(error) => Self::State(error),
            recover::Error::Journal(error) => error.into(),
            other => Self::Recover(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_errors_are_one_variant_wherever_they_come_from() {
        let failure = || state::Error::NotADirectory {
            path: PathBuf::from("/x"),
        };
        assert!(matches!(Error::from(failure()), Error::State(_)));
        assert!(matches!(
            Error::from(recover::Error::State(failure())),
            Error::State(_)
        ));
        assert!(matches!(
            Error::from(journal::Error::State(failure())),
            Error::State(_)
        ));
        assert!(matches!(
            Error::from(recover::Error::Journal(journal::Error::State(failure()))),
            Error::State(_)
        ));
        assert!(matches!(
            Error::from(recover::Error::Journal(journal::Error::InProgress {
                path: PathBuf::from("/j")
            })),
            Error::Journal(_)
        ));
        assert!(matches!(
            Error::from(recover::Error::Blocked { conflicts: vec![] }),
            Error::Recover(_)
        ));
    }
}
