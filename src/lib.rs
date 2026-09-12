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
//! # How one repo serves many accounts
//!
//! A developer with several Linux accounts has several *differences*, not
//! several configurations: a different scratch root, a different sccache
//! location, a different signing key, a different systemd slice. bx models that
//! with a **layer set**, and the shape of it is the reason the crate is arranged
//! this way:
//!
//! * [`config::layers`] orders the layers. The config repo's `bx.toml` and
//!   `modules/*.toml` are committed and publishable; the account's `local.toml`
//!   lives in the state directory, is never committed, and is **last**, so the
//!   account always has the final word.
//! * [`config::merge`] folds them by natural key. A later layer replaces an
//!   entry in place, adds one, or — with `enabled = false` — removes one. The
//!   local layer is a **full layer**, not a value file: an account that could
//!   only fill in placeholders could not add a target or opt out of one.
//! * [`config::values`] declares the divergence's *shape* in the repo and takes
//!   its *content* from the account, so nothing user-specific is ever committed.
//! * [`config::resolve`] substitutes `{{name}}` everywhere and holds back the
//!   targets whose values nobody answered, so an unanswered question costs the
//!   targets that need it rather than the whole apply.
//!
//! [`testing`] is the tempdir-`$HOME` guard every home-touching test in this
//! crate runs behind. It is compiled unconditionally, and hidden from the docs,
//! so an integration test can reach it too.

pub mod config;
pub mod detect;
pub mod env_guard;
pub mod paths;
pub mod report;
#[doc(hidden)]
pub mod testing;

/// The version reported by `bx --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
