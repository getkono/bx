//! `bx` — an idempotent, additive Linux developer-environment manager.
//!
//! The crate is organised around two invariants that the rest of the tool is
//! built on top of, and that are enforced here rather than by convention:
//!
//! * [`env_guard`] — bx may never emit an environment variable that moves
//!   another tool's config, data, or cache outside a root the configuration
//!   declares. It admits only variables bx knows how to judge, and judges each
//!   value for what the variable holds.
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
//! those files but the lock and for every target: the one atomic write in the
//! crate — temporary file in the destination directory, the mode set before any
//! content, `fsync`, `rename`, `fsync` the directory — the one comparison
//! `plan` and `apply` share, and the one type that carries a file mode. The
//! lock file's body — a best-effort line naming the holder — is truncated and
//! written in place through the locked descriptor, because an atomic write
//! renames a new inode over the name, and the lock is held on the old one.
//!
//! [`journal`] is the durability layer between the two: the write-ahead log and
//! the session every byte bx writes passes through, which records each write
//! before it is made and unlinks the log only once the session has ended, so a
//! run that stops halfway leaves a record of everything it may have touched.
//! [`recover`] is what a later run does with a log that is still there:
//! detection and a report in a read-only command, an automatic roll back in a
//! writing one. Between them they are the second half of Invariant 4, and
//! [`restore`] is the first: `bx rm`, spending the ledger's record of the
//! bytes bx displaced to put a file back exactly as it was — or to remove one
//! bx created, which is not the same as emptying it.
//!
//! [`plan`] is where those pieces meet and Invariant 7 is kept: one traversal
//! that decides every resolved target against the ledger and the one
//! comparison, and a diff of each decision, shared by `bx plan`, `bx apply`
//! and the status view. [`adopt`] is `bx add` and `bx rm`: existing config
//! taken into the repo byte for byte, and handed back exactly. [`command`]
//! holds the commands' bodies, `bx doctor`'s among them, so the binary only
//! parses its arguments and dispatches.
//!
//! [`doctor`] reads the same resolved targets without deciding them, and asks
//! read-only questions about what is on disk — whether systemd has reloaded,
//! enabled, or failed a unit file bx wrote — changing nothing itself.
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

pub mod adopt;
pub mod command;
pub mod config;
pub mod detect;
pub mod doctor;
pub mod env_guard;
pub mod fs;
pub mod journal;
pub mod paths;
pub mod plan;
pub mod recover;
pub mod report;
pub mod restore;
pub mod secret;
pub mod state;
#[doc(hidden)]
pub mod testing;

/// The version reported by `bx --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
