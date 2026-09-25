//! Filesystem primitives: file modes, and the one atomic write in the crate.
//!
//! This module is the single place in bx where a byte reaches the filesystem,
//! but one. A symlink target's link is made here too, by [`link`], through the
//! same preamble and the same rename-then-sync as a file. Everything downstream — generated shell fragments, managed regions
//! and include lines, surgical edits to another tool's config, and decrypted
//! secrets — writes through [`atomic`], so the durability sequence, the
//! reversibility record and the mode policy exist once rather than once per
//! caller.
//!
//! The one exception is the advisory lock file's body, a best-effort line
//! naming the holder, which `state::lock` truncates and writes in place through
//! the descriptor the lock is held on. Renaming a new file over it would move
//! the name to an inode nobody holds the lock on, and the body is only ever a
//! diagnostic, so a torn one costs a vaguer "already running" message and
//! nothing else.
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
pub(crate) mod durable;
pub mod link;
pub mod mode;

pub use atomic::{
    CreatedDirs, Desired, EnsuredDir, Error, Filled, Observed, Outcome, Parent, ParentState,
    Staged, Stamp, TEMP_PREFIX, Unpublished, compare, compare_dir, ensure_dir, observe,
    refuse_stage, set_mode, stage, stage_as, temp_beside, write_atomically,
};
pub use link::{StagedLink, refuse_stage_link, stage_link, stage_link_as};
pub use mode::{Kind, Mode, ModeError};
