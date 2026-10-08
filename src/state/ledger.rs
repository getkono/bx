//! What bx wrote, and what it displaced.
//!
//! The ledger is the record Invariant 4 rests on. For every target bx has
//! written it holds the digest of the bytes bx left there, the mode it set, how
//! it attached to the file, and — content-addressed in `restore/` — the exact
//! bytes that were there before, or the explicit fact that nothing was.
//!
//! Two types, deliberately:
//!
//! * [`LedgerView`] is read-only and takes no lock. `plan` uses it. A state file
//!   is always replaced by `rename`, so a reader sees a whole file or the
//!   previous whole file, never a torn one.
//! * [`Ledger`] is writable and can only be obtained by presenting an
//!   [`ExclusiveLock`], so `&mut Ledger` is itself the proof that the state
//!   directory is locked and no second `bx` is writing to it.
//!
//! [`entry`] holds what one record is and the rules every record keeps,
//! [`view`] the read-only ledger and how a stored one is judged on load, and
//! [`write`](mod@write) the ledger under the lock.
//!
//! [`ExclusiveLock`]: super::ExclusiveLock

mod entry;
#[cfg(test)]
mod fixtures;
mod view;
mod write;

pub use entry::{
    DIR_BYTES, LedgerEntry, Mechanism, NewEntry, Prior, PriorBytes, RestoreRef, clone_written,
    dir_digest, dir_prior,
};
pub use view::LedgerView;
pub use write::Ledger;

/// The envelope tag for `ledger.mpk`.
const KIND: &str = "bx.ledger";

/// The newest ledger format this build writes and understands.
const VERSION: u16 = 1;
