//! The state directory — `$XDG_STATE_HOME/bx`, default `~/.local/state/bx`.
//!
//! bx's layout has two halves. The *config repo* is a git working tree the user
//! owns, commits and publishes. The **state directory** is the other half: it is
//! never a git working tree, never published, and holds only what the machine
//! needs to know about this account — what bx wrote, what it replaced, and what
//! it can skip recomputing.
//!
//! # Resolution takes an explicit home
//!
//! [`StateDir::resolve`] takes the home directory as an argument and reads no
//! environment variable. Two tests with two tempdir `$HOME`s therefore get two
//! independent state directories. The XDG rule itself lives in exactly one place
//! — [`crate::paths::xdg_base`] — and a caller that has an `$XDG_STATE_HOME`
//! value to honour passes it to [`StateDir::resolve_in`].

mod dir;
mod hash;

use std::path::PathBuf;

pub use dir::StateDir;
pub use hash::ContentHash;

/// Everything that can go wrong in the state directory.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file occupies a path the state directory needs to be a directory.
    #[error("{} exists and is not a directory; move or remove it", .path.display())]
    NotADirectory {
        /// The offending path.
        path: PathBuf,
    },
    /// A directory could not be created.
    #[error("creating {}: {source}", .path.display())]
    CreateDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A read failed.
    #[error("reading {}: {source}", .path.display())]
    Read {
        /// The path being read.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}
