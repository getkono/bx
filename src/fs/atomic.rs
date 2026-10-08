//! The one place a byte reaches the filesystem.
//!
//! Every write bx performs goes through here, and the sequence is fixed:
//!
//! 1. [`observe`](fn@observe) the destination with `symlink_metadata`, capturing what is
//!    there, its mode, its bytes and a [`Stamp`]. `plan` compares that
//!    observation, and [`stage`](fn@stage) is handed the same one: it refuses unless the
//!    destination still carries that stamp, so the verdict is decided once,
//!    by `plan`, and `apply` either acts on it or refuses — never on a verdict
//!    of its own.
//! 2. a temporary file **in the destination directory**, so the later `rename`
//!    is same-filesystem and therefore atomic. A `/tmp` on another mount would
//!    turn it into a copy-then-delete with a visible half-written window.
//! 3. the mode set with `fchmod` **before any content is written** — all of it
//!    but a declared setuid or setgid bit, which a write would clear.
//! 4. the content written, the set-id bits added if declared and read back to
//!    confirm the kernel kept them, then `fsync`ed.
//! 5. the prior state recorded — [`crate::state::NewEntry::for_write`] assembles it and
//!    [`crate::state::Ledger::record`] makes it durable — **before** the
//!    rename, so a crash after the rename still has a recoverable prior state.
//!    Steps 6 and 7 can still refuse or fail, so this record can outlive a
//!    write that never lands; [`Unpublished`] names the write so its record
//!    can be withdrawn, and [`crate::state::NewEntry::for_write`] says when and how.
//! 6. the destination `lstat`ed again and compared with what step 1 saw, and
//!    the write refused if it changed.
//! 7. `rename`.
//! 8. an `fsync` of the **destination directory**, so the rename itself
//!    survives a power loss. This is the step implementations omit, and without
//!    it the directory entry can be lost even though the file's data was
//!    synced.
//!
//! # Why the mode is set before the content
//!
//! Not tidiness: a decrypted secret is written through [`Staged::commit`], and
//! its plaintext must never exist at a wider mode than its final one, not even
//! for the microseconds between `write` and `fchmod`.
//!
//! `fchmod` is also the only call that makes a declared mode *authoritative*.
//! `tempfile`'s `Builder::permissions` routes the mode through
//! `OpenOptions::mode()`, which the kernel masks with the process `umask`, so a
//! target declared `0644` under `umask 077` would be created `0600` and stay
//! there. `fchmod(2)` is not masked. `tempfile` creates at `0600` and a `umask`
//! can only narrow that, so the temporary file is never *wider* than its final
//! mode at any instant either.
//!
//! The one exception is a declared setuid or setgid bit. The kernel clears
//! both on a write by a process without `CAP_FSETID`, so a set-id bit set
//! before the content would be gone after it: the second `plan` would read
//! `Modify`, and the ledger would record a mode that is not on disk. [`stage`](fn@stage)
//! sets every other bit, and [`Staged::fill`] adds the set-id bits after the
//! content and before the `fsync`. The empty file is therefore *narrower* than
//! its declared mode, never wider, and the content is at exactly that mode
//! before it is durable or visible at the destination.
//!
//! # Why the write is staged rather than one call
//!
//! [`stage`](fn@stage) → [`Staged::fill`] → [`Filled::publish`] exposes the boundary
//! between the `fsync` of the temporary file and the `rename`. A write-ahead
//! journal records its intent exactly there — before that point a crash leaves
//! the destination untouched, after it the destination is already replaced — and
//! it identifies a leftover temporary file by the path [`Staged::temp_path`]
//! reports. An opaque `write(dest, bytes, mode)` cannot express that boundary,
//! and it cannot let a test observe the mode of the temporary file while it is
//! still empty. [`Staged::commit`] is the shorthand for callers with nothing to
//! interpose.
//!
//! # What is checked before the rename, and what is not
//!
//! Staging widens the gap between looking at the destination and replacing
//! it: the content is written and synced, the ledger records the prior, and a
//! journal appends its intent, all in between. An editor that saves in that gap
//! would lose the save to the rename, and the prior bx recorded would predate
//! it, so `rm` could not bring it back either. [`observe`](fn@observe) therefore records a
//! [`Stamp`] — device, inode, size, and modification and status-change times to
//! the nanosecond — and [`Filled::publish`] `lstat`s the destination again as
//! the last step before the rename, refusing with [`Error::Changed`] unless it
//! is the same file, unchanged, or still absent. [`stage`](fn@stage) makes the same check
//! against `plan`'s observation, which closes the earlier gap between `plan`
//! printing a diff and `apply` starting to act on it.
//!
//! That narrows the gap to the distance between one `lstat` and one
//! `rename(2)`; it does not close it. A change landing in those microseconds is
//! still replaced. Closing it needs `renameat2(RENAME_EXCHANGE)`, a check of
//! what came out, and an exchange back on a mismatch — which would publish bx's
//! content for an instant even when refusing, and is not done. A timestamp
//! that does not move is also not seen: on a filesystem with coarse timestamps,
//! an in-place edit of the same length within one clock tick of the
//! observation leaves the stamp identical. Kernels with multigrain timestamps
//! give a fine-grained time to a change made just after the file's times were
//! queried, which is exactly what `observe` did.
//!
//! # What "restores exactly" covers
//!
//! The prior state is the displaced file's **bytes and its twelve mode bits**,
//! and that is what `rm` restores. Replacing a file creates a new inode, and
//! nothing else of the old one is carried over or recorded: not its extended
//! attributes (`user.*`), not its POSIX ACL (`system.posix_acl_access`), and
//! not its SELinux label, owner and group, or timestamps. A file bx replaced,
//! and a file `rm` restored, has none of them.
//!
//! Deliberately. Copying an ACL onto the replacement would grant access the
//! declared mode does not — a named-user entry survives a `0640` — and a
//! declared mode is authoritative. Recording any of it needs a field in the
//! ledger's prior, which belongs to the state directory rather than to the
//! writer. `a_replaced_file_keeps_neither_its_xattrs_nor_its_acl` pins the
//! behaviour, so changing it is a decision rather than an accident.
//!
//! # What the tests here do and do not establish
//!
//! The *observable* half is pinned throughout: the temporary file is in the
//! destination directory and at its final mode while still empty, an abandoned
//! or failed write leaves the previous file and no temporary behind, a
//! published one leaves only the destination, and the prior state a reversal
//! needs is in the ledger before the rename.
//!
//! The **durability half** has no observable result — an `fsync`'s only
//! witness is a reader that survives a power loss — so it is pinned through
//! the calls instead. Every `fsync` and the `rename` go through
//! `fs::durable`, which notes each call to a per-thread recorder in the
//! test build only. The tests assert that [`Staged::fill`] syncs the temporary
//! file before it returns, and that [`Filled::publish`] opens the directory,
//! renames, and only then syncs the directory, in that order. Deleting either
//! sync, or moving it across the rename, fails a test.
//!
//! What remains held by review is the one-line body of each function in
//! `durable` — that `sync_file` really calls `sync_all` — because nothing in
//! a unit test observes the kernel. That is a far smaller claim than "every
//! call site remembered to sync", and it is not one a change to this file can
//! break.
//!
//! # What the suite does not construct, and why that is a decision
//!
//! ## Syscall-failure arms that follow a successful syscall on the same object
//!
//! Several `Err` arms here are unreachable from a test, and they are one class
//! rather than a list: an arm that handles a syscall failing **after an earlier
//! syscall on the same path or descriptor succeeded**. Reaching one needs the
//! object to be removed, to lose a permission, or to run the filesystem out of
//! space or descriptors, in the microseconds between the two calls. A test
//! cannot schedule that, and no count of the arms is worth keeping current,
//! because the class is closed under the arms a later change adds.
//!
//! What would reach them is a `cfg(test)` seam that fails a chosen syscall.
//! There is deliberately none. `fs::durable` has one for the durability calls,
//! because an `fsync` has no result a test can read back and so no other
//! witness exists; `process_keeps_setgid` has one because the answer that
//! matters needs a user namespace to arrange. Both seams answer a question the
//! filesystem will not answer. These arms are not that: each does one thing —
//! wrap the failure in the typed error that names the path — and the object of
//! a seam here would be to watch bx run code a reader can see is right, in
//! exchange for a second control flow present in every test build.
//!
//! ## Mutants that survive because they are the same program
//!
//! `cargo mutants` reports survivors here that no test can kill, because the
//! mutation produces a program that cannot behave differently — a guard around
//! an operation that is a no-op when the guard is false, a bitwise `|` between
//! flags that share no bit, a body that drops a value the function would drop
//! anyway. Each such site carries the reason next to it rather than in a list
//! somewhere else, so the reason moves with the code it is about and a later
//! mutants run is read against the code rather than against a count taken at a
//! head that has moved.
//!
//! # Where each part lives
//!
//! - `error` — [`Error`], every way a write can fail, and the words its
//!   messages share.
//! - `observe` — what is at a destination and above it, and how a path is
//!   spelled before anything looks at it.
//! - `compare` — the verdict `plan` prints: [`Drift`] and its notes, for a
//!   file target and a directory target.
//! - `stage` — the write itself, from the refusals made before anything is
//!   created to the rename and the directory sync.
//! - `dir` — directory targets, and the parents a write creates.
//! - `setid` — keeping a declared setuid or setgid bit, and refusing a write
//!   where the kernel would drop one.
//!
//! Each part's tests sit beside it; `test_support` holds the fixtures more
//! than one of them uses.

mod compare;
mod dir;
mod error;
mod observe;
mod setid;
mod stage;
#[cfg(test)]
mod test_support;

pub use compare::{Desired, Drift, Outcome, compare, compare_dir};
pub use dir::{CreatedDirs, EnsuredDir, ensure_dir};
pub use error::Error;
pub use observe::{Observed, Parent, ParentState, Stamp, observe};
pub use stage::{
    Filled, Staged, TEMP_PREFIX, Unpublished, refuse_stage, set_mode, stage, stage_as, temp_beside,
    write_atomically,
};

pub(super) use observe::parent_of;
pub(crate) use stage::refuse_moved;
pub(super) use stage::{prepare, refuse_to_prepare, temp_name, verify_unchanged};
