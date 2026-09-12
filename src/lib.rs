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
//! [`testing`] is the tempdir-`$HOME` guard every home-touching test in this
//! crate runs behind. It is compiled unconditionally, and hidden from the docs,
//! so an integration test can reach it too.

pub mod detect;
pub mod env_guard;
pub mod paths;
pub mod report;
#[doc(hidden)]
pub mod testing;

/// The version reported by `bx --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
