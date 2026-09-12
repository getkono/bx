//! `bx` — an idempotent, additive Linux developer-environment manager.
//!
//! The crate is organised around two invariants that the rest of the tool is
//! built on top of, and that are enforced here rather than by convention:
//!
//! * [`env_guard`] — bx may never emit an environment variable that moves
//!   another tool's config, data, or cache outside a root the configuration
//!   declares. The rule is about the value assigned, not the variable's name.
//! * [`paths`] — anything stored in the config repo is home-relative, so a repo
//!   moves between machines with different `$HOME` values without edits.
//!
//! [`detect`] answers whether a tool bx is configuring for is actually usable
//! on this machine, and [`report`] holds the vocabulary `plan` and `apply`
//! share, including the fact that an additive-only tool has no destroy action.
//!
//! [`config`] is what a config repo says — the layers, the targets, the declared
//! values, and the file and line each of them came from.
//!
//! [`state`] is the other half of the layout: `$XDG_STATE_HOME/bx`, which is
//! never a git working tree and never published. It holds the ledger of what bx
//! wrote and the bytes it displaced — the record `bx rm` restores from and the
//! one `bx plan` decides against — the fingerprint cache, and the advisory lock
//! that keeps two mutating `bx` processes from interleaving.
//!
//! [`fs`] is the single place a byte reaches the filesystem, for every one of
//! those files and every target: the one atomic write in the crate — temporary
//! file in the destination directory, the mode set before any content, `fsync`,
//! `rename`, `fsync` the directory — the one comparison `plan` and `apply`
//! share, and the one type that carries a file mode.
//!
//! [`journal`] is the durability layer between the two: the write-ahead log and
//! the session every byte bx writes passes through, which records each write
//! before it is made and unlinks the log only once the session has ended, so a
//! run that stops halfway leaves a record of everything it may have touched.
//! [`recover`] is what a later run does with a log that is still there:
//! detection and a report in a read-only command, an automatic roll back in a
//! writing one. Between them they are the second half of Invariant 4.
//!
//! [`testing`] is the tempdir-`$HOME` guard every home-touching test in this
//! crate runs behind. It is compiled unconditionally, and hidden from the docs,
//! so an integration test can reach it too.

pub mod config;
pub mod detect;
pub mod env_guard;
pub mod fs;
pub mod journal;
pub mod paths;
pub mod recover;
pub mod report;
pub mod state;
#[doc(hidden)]
pub mod testing;

/// The version reported by `bx --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
