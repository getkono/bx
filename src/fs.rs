//! Filesystem primitives: file modes, and the one atomic write in the crate.
//!
//! This module is the single place in bx where a byte reaches the filesystem.
//! Everything downstream — generated shell fragments, managed regions and
//! include lines, surgical edits to another tool's config, and decrypted
//! secrets — writes through [`atomic`], so the durability sequence, the
//! reversibility record and the mode policy exist once rather than once per
//! caller.
//!
//! A write that is interrupted — by a crash, a full disk, or a `SIGKILL` —
//! must leave the previous file exactly as it was, because an additive tool
//! that half-rewrites a file the user wrote has destroyed something. The
//! sequence, and why each step is there, is documented on [`atomic`].
//!
//! [`Mode`] is the crate's single permission type and [`Kind`] is what a
//! destination turned out to be. Both are defined in [`mode`] and re-exported
//! here, so `bx::fs::Mode` names the one file mode in the crate wherever it is
//! used — including from `config::target`, which re-exports it again under the
//! name the architecture fixed for a target's declared mode.

pub mod atomic;
pub mod mode;

pub use atomic::{
    Desired, Error, Filled, Observed, Outcome, Parent, Staged, TEMP_PREFIX, compare, ensure_dir,
    observe, set_mode, stage, write_atomically,
};
pub use mode::{Kind, Mode, ModeError};
