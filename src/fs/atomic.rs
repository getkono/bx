//! The one place a byte reaches the filesystem.
//!
//! Every write bx performs goes through here, and the sequence is fixed:
//!
//! 1. [`observe`] the destination with `symlink_metadata`, capturing what is
//!    there, its mode, its bytes and a [`Stamp`]. `plan` compares that
//!    observation, and [`stage`] is handed the same one: it refuses unless the
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
//! 5. the prior state recorded — [`Filled::new_entry`] assembles it and
//!    [`crate::state::Ledger::record`] makes it durable — **before** the
//!    rename, so a crash after the rename still has a recoverable prior state.
//!    Steps 6 and 7 can still refuse or fail, so this record can outlive a
//!    write that never lands; [`Unpublished`] names the write so its record
//!    can be withdrawn, and [`Filled::new_entry`] says when and how.
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
//! `Modify`, and the ledger would record a mode that is not on disk. [`stage`]
//! sets every other bit, and [`Staged::fill`] adds the set-id bits after the
//! content and before the `fsync`. The empty file is therefore *narrower* than
//! its declared mode, never wider, and the content is at exactly that mode
//! before it is durable or visible at the destination.
//!
//! # Why the write is staged rather than one call
//!
//! [`stage`] → [`Staged::fill`] → [`Filled::publish`] exposes the boundary
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
//! it, so `rm` could not bring it back either. [`observe`] therefore records a
//! [`Stamp`] — device, inode, size, and modification and status-change times to
//! the nanosecond — and [`Filled::publish`] `lstat`s the destination again as
//! the last step before the rename, refusing with [`Error::Changed`] unless it
//! is the same file, unchanged, or still absent. [`stage`] makes the same check
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

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rustix::io::Errno;
use tempfile::NamedTempFile;

use super::durable;
use super::mode::{Kind, Mode};
use crate::paths::Portable;
use crate::report::Action;
use crate::state::{ContentHash, Mechanism, NewEntry, PriorBytes};

/// The prefix every temporary file bx creates in a destination directory
/// carries.
///
/// Reserved: an orphan left by a crash is attributable to bx rather than
/// anonymous, which is what lets recovery and `doctor` find one. Nothing else
/// in bx may use this prefix for a different purpose.
pub const TEMP_PREFIX: &str = ".bx-";

/// Everything that can go wrong writing a file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The destination has no parent directory, so there is nowhere to put the
    /// temporary file the atomic write needs.
    #[error("{} has no parent directory to write into", .0.display())]
    NoParent(PathBuf),
    /// The destination exists and is not a regular file, so writing bytes to it
    /// would mean replacing something that is not a file.
    #[error("{path} is {kind}, not a file bx can write", path = .path.display())]
    NotAFile {
        /// The destination.
        path: PathBuf,
        /// What is actually there.
        kind: Kind,
    },
    /// The destination is a symlink, and bx replaces no symlink.
    ///
    /// `rename(2)` onto a link's path replaces **the link itself**, so writing
    /// "through" one would silently convert a link into a regular file. bx
    /// refuses instead.
    ///
    /// # Including at a path bx owns
    ///
    /// The refusal is the same for a link found at a blob name inside the
    /// state directory as for one at a file the user declared, and that is a
    /// decision, not an oversight. bx did not make the link — it writes none —
    /// so it is something that arrived from a restored backup, an `rsync
    /// --links`, or a hand. Unlinking it would be bx deleting a name a person
    /// or a tool put there, which is Invariant 1 whatever directory it is in,
    /// and the content-addressed name gives bx no way to tell a stray link from
    /// a deliberate one.
    ///
    /// What the refusal owes such a caller is a remedy that makes sense for a
    /// file nobody declared, so the message leads with the one action that is
    /// always right — remove the link it names — and offers the target-shaped
    /// advice only as the alternative it is. A blob at
    /// `<state>/restore/<digest>` is reconstructed on the next `record` once the
    /// link is gone; nothing else has to be repaired.
    #[error(
        "{} is a symlink, and bx replaces no symlink: a rename onto it would replace the link \
         itself. Remove the link. If you declared this path as a target, you can instead point \
         the target at the file the link resolves to",
        .0.display()
    )]
    Symlink(PathBuf),
    /// A link would replace something that is not a link: a regular file, a
    /// directory, a socket or a device node. A symlink target replaces only a
    /// link, and only one `plan` showed it — see [`crate::fs::link`].
    #[error("{path} is {kind}, not a symlink bx can replace", path = .path.display())]
    NotALink {
        /// The destination.
        path: PathBuf,
        /// What is actually there.
        kind: Kind,
    },
    /// The destination's parent is on the filesystem but does not resolve to a
    /// directory: a dangling symlink, a symlink loop, or a non-directory.
    ///
    /// Distinct from a parent that is simply missing, which bx creates.
    /// `mkdir` cannot create a directory through a dangling link, so this is
    /// announced as a [`Action::Conflict`] by `compare` rather than left for
    /// `apply` to discover as an `ENOENT` naming a temporary file.
    #[error("{reason}")]
    UnusableParent {
        /// The parent directory, as it was named.
        path: PathBuf,
        /// What is wrong with it, in the same words `plan` prints.
        reason: String,
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
    /// A write, `chmod`, `fsync` or `rename` failed.
    #[error("writing {}: {source}", .path.display())]
    Write {
        /// The path being written, or the directory the temporary file was to
        /// be created in when the failure happened before the file existed.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// What is at the path is no longer what bx observed there, so acting on
    /// the observation would replace or change something bx never looked at.
    ///
    /// Raised by [`stage`] when the destination is no longer what `plan`
    /// observed, by [`Filled::publish`] when it changed between [`stage`] and
    /// the rename — an editor saving, a symlink swapped in, a file appearing
    /// where there was none — and by [`ensure_dir`] when a directory target is
    /// no longer what `plan` saw. Nothing is replaced: the path keeps what is
    /// there now, and the temporary file is dropped — see [`Staged`] for what
    /// that is worth.
    ///
    /// From [`Filled::publish`] it arrives inside an [`Unpublished`], because
    /// "nothing was replaced" is not the whole obligation: a caller that
    /// recorded a ledger entry before publishing, as [`Filled::new_entry`]
    /// requires, is holding an entry for a write that did not happen, and must
    /// withdraw it before it saves.
    #[error(
        "{} changed after bx looked at it ({detail}); nothing was replaced. Run plan again",
        .path.display()
    )]
    Changed {
        /// The path that changed.
        path: PathBuf,
        /// What bx saw, and what is there now.
        detail: String,
    },
    /// A path the ledger would record cannot be made portable against the
    /// home: it is not valid UTF-8, or the home is not absolute.
    ///
    /// [`crate::paths::Portable::from_path`] refuses rather than renaming such
    /// a path, so the entry is refused rather than recorded under a key that
    /// names a different file.
    #[error("{} cannot be recorded: {source}", .path.display())]
    NotPortable {
        /// The path that could not be made portable.
        path: PathBuf,
        /// Why.
        #[source]
        source: crate::paths::Error,
    },
    /// A declared setuid, setgid or sticky bit did not survive its `fchmod`.
    ///
    /// `fchmod(2)` reports success when the kernel silently clears `S_ISGID`
    /// from a file whose group the caller is not in, which is the group a
    /// setgid parent directory owned by another group gives every new file. A
    /// filesystem that stores no set-id or sticky bits — vfat or exfat mounted
    /// with `quiet`, and some FUSE and network filesystems — can drop any of
    /// the three the same way. Publishing it would put a mode on disk that is
    /// not the declared one and make every later `plan` announce a `Modify` no
    /// `apply` can close. The destination is untouched and the temporary file is
    /// dropped — see [`Staged`] for what that is worth.
    ///
    /// The message names the bits that were lost, and blames group membership
    /// only when the setgid bit is among them.
    #[error("{}", special_bits_not_kept(.path, *.declared, *.landed))]
    SetIdNotKept {
        /// The destination.
        path: PathBuf,
        /// The mode the target declares.
        declared: Mode,
        /// The mode the temporary file actually has.
        landed: Mode,
    },
    /// A setuid, setgid or sticky bit declared for a directory did not survive
    /// its `chmod` — the directory form of [`Error::SetIdNotKept`].
    ///
    /// `chmod(2)` reports success when the kernel clears `S_ISGID` from a
    /// directory whose group the caller is not in, which is the group a setgid
    /// parent gives every directory made inside it, and a filesystem that
    /// stores no special bits drops them the same way. Reporting the mode as
    /// applied would make every later `plan` announce a `Modify` no `apply` can
    /// close. So the mode is read back after the `chmod`, by [`ensure_dir`]
    /// and by [`stage`] for a directory it creates, and a missing bit is
    /// refused. Nothing is recorded. A directory whose mode a `Modify` changed
    /// is set back to the mode `plan` saw and read back again; a directory bx
    /// created is left in place at the mode that landed — as for an abandoned
    /// write's parent — so the next `plan` announces the `Modify` that is still
    /// owed.
    ///
    /// The kernel's own cause is refused before any `chmod`: [`ensure_dir`]
    /// does not `chmod` an existing directory that has `S_ISGID`, or is
    /// declared with it, unless a `chmod` by this process is **confirmed** to
    /// keep the bit — by `CAP_FSETID` in the effective set, or by the
    /// directory's group being one the kernel resolved and this process is in
    /// (see [`keeps_setgid`]). Anything it cannot confirm is refused. That
    /// `chmod` would strip the bit, and a set-back by the same process would
    /// strip it again, so a bit the user had would be lost for good. Then
    /// `chmod_left` is `None` and nothing was changed.
    ///
    /// The message is worded from `landed`, the mode on the directory when bx
    /// returned, and says whether a set-back restored the mode `plan` saw.
    #[error("{}", directory_set_id_not_kept(.path, *.declared, *.landed, *.chmod_left, *.set_back))]
    DirectorySetIdNotKept {
        /// The directory.
        path: PathBuf,
        /// The mode its target declares, or a directory target in this apply
        /// declares for it.
        declared: Mode,
        /// The mode the directory has now: after bx's last `chmod` of it and
        /// any set-back, or untouched when bx made none.
        landed: Mode,
        /// The mode bx's `chmod` left on the directory, before any set-back;
        /// `None` when bx refused before making any `chmod`.
        chmod_left: Option<Mode>,
        /// The mode a refused `Modify` set the directory back to, which is the
        /// mode `plan` saw; `None` when bx set nothing back.
        set_back: Option<Mode>,
    },
    /// The destination's parent directory does not exist, and the entry point
    /// asked creates none.
    ///
    /// Only [`write_atomically`] raises it. [`stage`] and [`ensure_dir`] create
    /// directories; this is the shorthand that has no [`CreatedDirs`] to record
    /// one in, no plan to announce it in, and no caller to say what mode it
    /// should get.
    #[error(
        "{} does not exist, and bx creates no directory for this write: nothing here decides \
         what mode it would get. Create it, or declare it as a directory target",
        .0.display()
    )]
    MissingParent(PathBuf),
    /// The path has a `..` component.
    ///
    /// The kernel resolves `..` *after* following the component before it, so
    /// `lnk/../f` with `lnk -> elsewhere/sub` names `elsewhere/f`, while the
    /// path read lexically — the reading a ledger key is made from — names `f`.
    /// Writing through it would record one file and change another, and `rm`
    /// would then restore the wrong one. bx neither resolves `..` (decision 2
    /// writes through links, so resolving is not lexical) nor drops it (which
    /// could name a different file), so it refuses the path.
    #[error(
        "{} has a `..` component, which the kernel resolves through any symlink before it; \
         bx will not write to a path it cannot name exactly. Spell the path without `..`",
        .0.display()
    )]
    ParentComponent(PathBuf),
    /// A file would be published beneath a directory this apply declares,
    /// while that directory still exists wider than its declared mode.
    ///
    /// The directory target's `Modify` has not been applied yet. Publishing
    /// first would leave the file reachable through a directory the
    /// configuration declares narrower — for as long as the apply takes to
    /// reach the directory target, and for good if it stops before then. A
    /// declared directory this apply *creates* is created at its declared mode,
    /// so this arises only for one that already exists. Nothing is created or
    /// written.
    #[error(
        "{} is beneath {}, which is {found}, wider than the {declared} its directory target \
         declares; apply that directory target first. Nothing was written",
        .path.display(),
        .dir.display()
    )]
    DirectoryTargetPending {
        /// The destination.
        path: PathBuf,
        /// The declared directory that is still wider than declared.
        dir: PathBuf,
        /// Its mode now.
        found: Mode,
        /// The mode its directory target declares.
        declared: Mode,
    },
    /// A directory target's directory was created earlier in this apply at a
    /// mode other than the one the target declares.
    ///
    /// A write beneath it ran before the directory was declared with
    /// [`CreatedDirs::declare`], so it was made at [`Mode::DEFAULT_DIR`] and a
    /// file may already have been published in it at that mode. Adopting it
    /// would hide that, and would leave the write's ledger entry and the
    /// directory target's both claiming the directory. Nothing is chmod'd; the
    /// next `plan` announces the `Modify` that narrows it.
    #[error(
        "{} was created at {created} earlier in this apply, not at the {declared} its directory \
         target declares: declare every directory target before applying any target. \
         Nothing was changed",
        .path.display()
    )]
    UndeclaredDirectory {
        /// The directory.
        path: PathBuf,
        /// The mode this apply created it at.
        created: Mode,
        /// The mode its directory target declares.
        declared: Mode,
    },
    /// A file target's declared mode denies the owner read, which bx needs to
    /// read the file's bytes back and compare them.
    ///
    /// Applying such a mode would succeed once and leave every later `plan`
    /// failing with a permission error, against Invariant 3. [`compare`]
    /// announces it as an [`Action::Conflict`] whose note is this error's
    /// words, less the path, so `apply` never reaches a target `plan` printed
    /// that way. No writer in `fs` raises it: [`stage`] writes the mode it is
    /// given, because a reversal restores a recorded prior mode through it. It
    /// is the typed form of that verdict for a caller that refuses the
    /// declaration itself.
    ///
    /// A directory target's mode is not held to it. Whether a directory mode
    /// shuts bx out depends on the targets beneath the directory, which only
    /// the plan layer knows.
    #[error("{} {}. Nothing was changed", .path.display(), owner_locked_out(*.declared, *.needs))]
    OwnerLockedOut {
        /// The file target.
        path: PathBuf,
        /// The mode declared for it.
        declared: Mode,
        /// The owner bits bx needs: `0400`.
        needs: Mode,
    },
}

/// What bx needs the owner of a file target to be granted: read, to observe
/// its bytes.
const FILE_OWNER_NEEDS: Mode = Mode::from_bits(0o400);

/// The words [`Error::OwnerLockedOut`] and `plan`'s conflict note share: the
/// owner bits of `needs` that `declared` lacks, and why bx needs them.
/// `names` as English: `""`, `"read"`, `"read and write"`, `"read, write and
/// search"`.
///
/// One function rather than one per message, because the two messages that need
/// it — [`owner_locked_out`] and [`bits_that_did_not_stick`] — each pass a list
/// whose length is bounded by what their caller happens to ask for today. Both
/// had their own version, and both versions had a branch that no caller reached:
/// a guard whose justification was the set of callers rather than the
/// conjunction it was written to produce. Tested directly, at every length.
fn and_list(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_string(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

fn owner_locked_out(declared: Mode, needs: Mode) -> String {
    let missing = needs.bits() & !declared.bits();
    let names: Vec<&str> = [(0o400, "read"), (0o200, "write"), (0o100, "search")]
        .into_iter()
        .filter(|(bit, _)| missing & bit != 0)
        .map(|(_, name)| name)
        .collect();
    let named = and_list(&names);
    format!(
        "declares {declared}, which denies its owner {named} ({missing:04o}): bx reads a file \
         target's bytes to compare them with what it wants there, so its mode must grant the \
         owner read ({needs})"
    )
}

/// The message of [`Error::SetIdNotKept`].
fn special_bits_not_kept(path: &Path, declared: Mode, landed: Mode) -> String {
    format!(
        "{} declares {declared}, and only {landed} is on the file: {}. Nothing was replaced",
        path.display(),
        bits_that_did_not_stick(declared, landed, "file")
    )
}

/// The message of [`Error::DirectorySetIdNotKept`]: why bx made no `chmod`,
/// or which special bits its `chmod` lost and what is on the directory now.
fn directory_set_id_not_kept(
    path: &Path,
    declared: Mode,
    landed: Mode,
    chmod_left: Option<Mode>,
    set_back: Option<Mode>,
) -> String {
    let Some(left) = chmod_left else {
        let lost = if landed.bits() & SETGID == 0 {
            "not keep the setgid bit it declares"
        } else {
            "lose the setgid bit it has"
        };
        return format!(
            "{} declares {declared} and is {landed}: the kernel drops a directory's setgid bit \
             on a chmod unless the process holds CAP_FSETID or is in the directory's group, and \
             bx could confirm neither for this process, so the directory would {lost}. bx did \
             not chmod it, and nothing was changed",
            path.display()
        );
    };
    let outcome = match set_back {
        None => format!(
            "Nothing was recorded, and the directory, which bx created in this apply, is left in \
             place at {landed}"
        ),
        Some(prior) if prior == landed => {
            format!("bx set it back to {prior}, the mode plan saw, and nothing was recorded")
        }
        Some(prior) => format!(
            "bx set it back to {prior}, the mode plan saw, but {landed} is on it now, so the \
             set-back did not restore it. Nothing was recorded"
        ),
    };
    format!(
        "{} declares {declared}, and only {left} was on the directory after its chmod: {}. \
         {outcome}",
        path.display(),
        bits_that_did_not_stick(declared, left, "directory")
    )
}

/// Which special bits `declared` has and `landed` lacks, and the causes that
/// can lose them, for a `what` ("file" or "directory").
fn bits_that_did_not_stick(declared: Mode, landed: Mode, what: &str) -> String {
    let lost = declared.bits() & SPECIAL & !landed.bits();
    let names: Vec<&str> = [(0o4000, "setuid"), (0o2000, "setgid"), (0o1000, "sticky")]
        .into_iter()
        .filter(|(bit, _)| lost & bit != 0)
        .map(|(_, name)| name)
        .collect();
    let noun = if names.len() == 1 { "bit" } else { "bits" };
    // `names` is never empty here: `bits_that_did_not_stick` is only called to
    // word `Error::SetIdNotKept`, and `Error::DirectorySetIdNotKept` when a
    // `chmod` was made, with the mode that `chmod` left; `verify_set_id_kept`
    // and `set_dir_mode` only construct either error when `lost` — `declared`'s
    // special bits minus that mode's — is non-empty. `and_list` is total for
    // the empty case anyway, so this opens no panic path.
    let named = if names.is_empty() {
        "special".to_string()
    } else {
        and_list(&names)
    };
    let group = if lost & SETGID != 0 {
        format!(
            "The kernel drops a setgid bit from a {what} whose group you are not in, such as the \
             group a setgid parent directory gives it, and a"
        )
    } else {
        "A".to_string()
    };
    format!(
        "the {named} {noun} did not stick. {group} filesystem that stores no set-id or sticky \
         bits, such as vfat or exfat mounted with `quiet`, drops them"
    )
}

impl Error {
    /// The path the failure is about.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::NoParent(path)
            | Self::MissingParent(path)
            | Self::Symlink(path)
            | Self::NotAFile { path, .. }
            | Self::NotALink { path, .. }
            | Self::UnusableParent { path, .. }
            | Self::Read { path, .. }
            | Self::Write { path, .. }
            | Self::Changed { path, .. }
            | Self::NotPortable { path, .. }
            | Self::SetIdNotKept { path, .. }
            | Self::DirectorySetIdNotKept { path, .. }
            | Self::ParentComponent(path)
            | Self::DirectoryTargetPending { path, .. }
            | Self::UndeclaredDirectory { path, .. }
            | Self::OwnerLockedOut { path, .. } => path,
        }
    }
}

/// What is at a destination right now.
///
/// Captured once, by [`observe`], and reused: `plan` compares against it and a
/// reversal restores from it. `bytes` is `None` for anything that is not a
/// regular file, because there is nothing to compare or restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The destination, as it was named less any trailing separator or `.`
    /// component — see [`observe`]. Not canonicalised.
    pub path: PathBuf,
    /// What is there.
    pub kind: Kind,
    /// Its mode, or `None` when nothing is there.
    pub mode: Option<Mode>,
    /// Its bytes, for a regular file only.
    pub bytes: Option<Vec<u8>>,
    /// What the link says, for a symlink only: its text, read with
    /// `readlink(2)` and never resolved.
    pub link: Option<PathBuf>,
    /// The destination's immediate parent directory.
    pub parent: Option<Parent>,
    /// Which file this was and when it last changed, or `None` when nothing is
    /// there.
    ///
    /// What [`Filled::publish`] checks the destination against immediately
    /// before the rename, so a file that changed after it was observed is not
    /// replaced, and a prior state recorded from this observation is never
    /// older than the file it displaces.
    pub stamp: Option<Stamp>,
}

impl Observed {
    /// The prior state, in the shape [`crate::state::Ledger::record`] takes.
    ///
    /// The conversion lives here rather than in the ledger because this is the
    /// only place that knows how the prior state was captured — one
    /// `symlink_metadata` and one read, before anything was touched.
    ///
    /// Anything that is not a regular file becomes [`PriorBytes::Absent`]. That
    /// is not a loss: a write only ever proceeds over a regular file or nothing
    /// at all, so the other kinds never reach a `record` call.
    #[must_use]
    pub fn prior_bytes(&self) -> PriorBytes {
        match (&self.bytes, self.mode) {
            (Some(bytes), Some(mode)) => PriorBytes::Bytes {
                bytes: bytes.clone(),
                mode,
            },
            _ => PriorBytes::Absent,
        }
    }

    /// The digest of the bytes that are there now, for a regular file.
    ///
    /// For a mode-only `Modify` this is the `written` its ledger entry records:
    /// that change is applied through [`stage`] with the bytes already there,
    /// so [`Filled::written`] is the digest of the same bytes.
    #[must_use]
    pub fn digest(&self) -> Option<ContentHash> {
        self.bytes.as_deref().map(ContentHash::of)
    }

    /// The digest of the link's text, for a symlink: the one a symlink
    /// target's ledger entry and journal intents record it under. See
    /// [`crate::fs::link`].
    #[must_use]
    pub fn link_digest(&self) -> Option<ContentHash> {
        self.link.as_deref().map(crate::fs::link::digest)
    }
}

/// Which file a path named, and when that file last changed, as one `lstat`
/// reported it.
///
/// Device and inode say *which* file: an editor that saves by writing a new
/// file and renaming it over the old one, or a symlink swapped in, changes
/// them. Size, and the modification and status-change times to the
/// nanosecond, say whether that file changed *in place*: a write moves `mtime`,
/// and a `chmod`, a `chown`, a new hard link or an extended attribute moves
/// `ctime`. Compared whole and never interpreted, so there is no field a
/// caller could compare on its own and get a different answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    /// The stamp of the file `meta` describes.
    fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

/// A destination's immediate parent directory.
///
/// Carried because a `0600` file inside a `0755` directory is a defect worth
/// reporting, and the mode of a directory bx is about to invent is knowable
/// before it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    /// The directory, as it was named. Not canonicalised.
    pub path: PathBuf,
    /// What resolving it found.
    pub state: ParentState,
    /// Where the directory really is, when `path` itself is a symlink to it.
    ///
    /// Only for reporting. bx writes *through* a symlinked parent but will not
    /// chmod a directory through one — [`ensure_dir`] refuses a link — so the
    /// only remedy for a wide one is to change the directory at the far end,
    /// and a report that does not name it gives the user nothing to act on.
    /// `None` for a parent that is not a link, and for one that does not
    /// resolve.
    pub resolved: Option<PathBuf>,
}

/// What a destination's parent turned out to be.
///
/// "Absent" and "there but unresolvable" are separated deliberately. They look
/// identical to a single `metadata` call — both report `ENOENT` — and treating
/// them alike made `plan` announce a `Create` that `apply` could not perform,
/// because `mkdir` cannot create a directory through a dangling symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentState {
    /// A directory, at this mode. A symlinked parent reports the mode of the
    /// directory it resolves to — see [`observe_parent`].
    Present(Mode),
    /// Nothing is on the path at all. bx would create it at this mode.
    Absent(Mode),
    /// Something is on the path and it does not resolve to a directory: a
    /// dangling symlink, a symlink loop, or a non-directory. The string is the
    /// cause, in the words `plan` prints and the error message `apply` returns.
    ///
    /// # It names an absolute path, and that is left for the renderer
    ///
    /// [`compare`]'s parent note is written against `home`, so `plan` prints
    /// `~/.config`; this reason is not, so a conflict line for a target under a
    /// dangling `~/.config` prints the user's home directory. Every
    /// [`Error`]'s `Display` is absolute the same way.
    ///
    /// Closing it means carrying the unusable component and its cause as
    /// fields and rendering them where the home is known, which is this variant
    /// — public, and matched on by the caller that will render it — and the
    /// [`Error::UnusableParent`] that repeats the same words, whose message
    /// `plan` and `apply` currently share verbatim
    /// (`a_dangling_symlink_parent_is_a_conflict_rather_than_a_create` asserts
    /// that `err.to_string()` *is* the note). Two renderings out of one is the
    /// decision, and it belongs to the entry that renders both rather than to
    /// the one that produces the string.
    Unusable(String),
}

impl Parent {
    /// The mode that governs a file in this directory, once there is one.
    ///
    /// `None` when the parent does not resolve, because there is then no
    /// directory whose mode could govern anything.
    #[must_use]
    pub const fn mode(&self) -> Option<Mode> {
        match self.state {
            ParentState::Present(mode) | ParentState::Absent(mode) => Some(mode),
            ParentState::Unusable(_) => None,
        }
    }

    /// Whether the directory is already there.
    #[must_use]
    pub const fn exists(&self) -> bool {
        matches!(self.state, ParentState::Present(_))
    }

    /// Why the parent cannot be written into, when it cannot.
    #[must_use]
    pub fn unusable(&self) -> Option<&str> {
        match &self.state {
            ParentState::Unusable(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Read what is at `dest`, following no symlink.
///
/// `symlink_metadata`, never `canonicalize`: a symlink is reported as a
/// [`Kind::Symlink`] rather than as whatever it points at, and `plan` therefore
/// never depends on resolving a path beyond the one the target declared.
///
/// A trailing separator or `.` is dropped from `dest` first, so `link/` is the
/// link rather than the directory the kernel would resolve it to, and the
/// observation's `path` is spelled without it. [`stage`], [`ensure_dir`] and
/// [`set_mode`] spell their paths the same way.
///
/// # Errors
///
/// [`Error::ParentComponent`] when `dest` has a `..` component,
/// [`Error::NoParent`] when `dest` has no parent component, and [`Error::Read`]
/// when the destination or its parent exists but cannot be read.
pub fn observe(dest: &Path) -> Result<Observed, Error> {
    let dest = lexical(dest)?;
    let dest = dest.as_path();
    let dir = parent_of(dest)?;
    let observed_parent = observe_parent(dir)?;

    // A parent that does not resolve leaves nothing to learn from the
    // destination: stat'ing it would fail with the parent's error rather than
    // the file's, and the verdict is the parent's either way.
    if observed_parent.unusable().is_some() {
        return Ok(Observed {
            path: dest.to_path_buf(),
            kind: Kind::Absent,
            mode: None,
            bytes: None,
            link: None,
            parent: Some(observed_parent),
            stamp: None,
        });
    }
    let parent = Some(observed_parent);

    let Some(meta) = optional_metadata(dest)? else {
        return Ok(Observed {
            path: dest.to_path_buf(),
            kind: Kind::Absent,
            mode: None,
            bytes: None,
            link: None,
            parent,
            stamp: None,
        });
    };

    let kind = Kind::from(meta.file_type());
    let read = |source| Error::Read {
        path: dest.to_path_buf(),
        source,
    };
    let bytes = if kind == Kind::File {
        Some(std::fs::read(dest).map_err(read)?)
    } else {
        None
    };
    // The link's own text, never what it resolves to: `readlink` reads the
    // link and follows nothing.
    let link = if kind == Kind::Symlink {
        Some(std::fs::read_link(dest).map_err(read)?)
    } else {
        None
    };

    Ok(Observed {
        path: dest.to_path_buf(),
        kind,
        mode: Some(mode_of(&meta)),
        bytes,
        link,
        parent,
        // From the `lstat` taken before the read, so a change that lands
        // between the two makes the stamp older than the bytes, and the check
        // before the rename refuses rather than trusting either.
        stamp: Some(Stamp::of(&meta)),
    })
}

/// What bx wants at a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desired<'a> {
    /// The content.
    pub bytes: &'a [u8],
    /// The mode, already resolved — see [`Mode::resolve`].
    pub mode: Mode,
}

/// The difference between what is at a destination and what bx wants there.
///
/// One function produces this for both `plan` and `apply`, which is how `apply`
/// is prevented from doing work `plan` did not announce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// What bx will do.
    pub action: Action,
    /// Whether the bytes on disk differ from the bytes bx wants there.
    ///
    /// `true` for an absent destination, including when the desired content is
    /// empty: "there is no file" and "there is an empty file" are different
    /// states and the ledger records them differently, so they are not equal
    /// here either. `false` for a conflict, where there are no comparable bytes.
    pub content_drift: bool,
    /// The mode found and the mode wanted, when they differ.
    pub mode_drift: Option<(Mode, Mode)>,
    /// The one-line explanation `plan` prints after the path.
    ///
    /// For a mode drift this is exactly `mode 0644 -> 0600`, so a renderer
    /// needs no mode-specific knowledge of its own.
    pub note: Option<String>,
    /// A parent directory that grants more than the declared mode does.
    ///
    /// Reported, never corrected: an existing directory is the user's, and bx
    /// surfaces drift rather than resolving it behind their back. The remedy is
    /// to declare the directory as a target with the mode it should have —
    /// except when the parent is a symlink, which a directory target refuses.
    /// Then the note names the directory the link resolves to and says to
    /// `chmod` that directory itself.
    ///
    /// A directory under the home is named `~/…`, never by its absolute path;
    /// see [`compare`].
    pub parent_note: Option<String>,
}

/// Compare what is at a destination with what bx wants there.
///
/// Reads nothing the verdict depends on: it works entirely from an [`Observed`]
/// captured earlier, so `plan` and `apply` reach the same verdict from the same
/// bytes. The one read, the realpath of `home`, only names a directory in the
/// parent note.
///
/// * [`Action::Unchanged`] — kind, bytes and mode all match.
/// * [`Action::Create`] — nothing is there.
/// * [`Action::Modify`] — a regular file whose bytes **or** mode differ. A mode
///   difference alone is still a `Modify`, with `content_drift == false`, and
///   `apply` closes it like any other `Modify`: [`stage`] with this
///   observation as `planned` and the desired mode, committed with the desired
///   bytes — the same bytes, for a mode-only drift. `stage` refuses with
///   [`Error::Changed`] unless the file still has the kind and [`Stamp`] this
///   observation recorded, so a `chmod`, an edit or a directory landing after
///   `plan` is refused rather than overwritten. [`set_mode`] is not the apply
///   for it: it compares nothing with `plan`.
/// * [`Action::Conflict`] — a directory, a symlink, or anything else that is
///   not a regular file; and, whatever is there, a declared mode that does not
///   grant the owner read (`0400`), because bx could not read the file back to
///   compare it. The note is [`Error::OwnerLockedOut`]'s words, less the path.
///   [`stage`] does not refuse such a mode: a reversal restores a recorded
///   prior mode through it as recorded.
///
/// # The parent note is about the immediate parent, and only about it
///
/// A directory anywhere above the immediate parent can be group- or
/// world-writable and no note says so — `~/.config` at `0777` holding
/// `~/.config/foo` at `0700` holding a `0600` file produces nothing. That is
/// the scope this function has, deliberately, and the reason is what the note
/// is *for* rather than what the danger is.
///
/// The immediate parent is the one directory this write interacts with: bx puts
/// its temporary file there, renames within it, and may create it — at a mode
/// this target's own declaration fixes ([`stage`]). Its mode is therefore
/// comparable with the mode this target declares, which is exactly what the
/// note compares, and the remedy is this target's author's: declare the
/// directory, or narrow it.
///
/// A writable ancestor is a different fact with a different remedy. It is one
/// fact about the home, not one per target: repeating it on every plan line
/// beneath it would say the same thing as many times as there are targets, and
/// the one action that fixes it is not this target's. It is also not the same
/// danger — an ancestor's *write* bit lets somebody rename a subtree, which no
/// mode on this file or its parent prevents — so reporting it through a
/// predicate built to compare a directory against a file inside it
/// ([`Mode::is_wider_than`], which excludes execute for that reason) would
/// answer the wrong question. A whole-home audit is where it belongs.
///
/// What this scope does **not** leave open: a wide ancestor bx made itself.
/// [`stage`] creates a missing ancestor at [`Mode::DEFAULT_DIR`] or at the mode
/// a directory target declares, never wider, and refuses to write beneath a
/// declared directory that is still wider than declared
/// ([`Error::DirectoryTargetPending`]). Every unreported ancestor was already
/// there and is the user's.
///
/// `home` only names things: a directory the parent note mentions is written
/// `~/…` when it is under `home`, through [`crate::paths::to_portable`],
/// because `plan` prints the note and plan output names no absolute home. The
/// directory a symlinked parent resolves to is a realpath, so it is named
/// against the realpath of `home` — the one read `compare` makes, and only for
/// that note — falling back to `home` as given when it does not resolve. A
/// directory outside it stays absolute. Nothing in the verdict depends on it.
#[must_use]
pub fn compare(observed: &Observed, desired: &Desired<'_>, home: &Path) -> Outcome {
    // So does a declared mode bx could not read back: `stage` refuses it
    // whatever is on disk.
    if !desired.mode.includes(FILE_OWNER_NEEDS) {
        return Outcome {
            action: Action::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(owner_locked_out(desired.mode, FILE_OWNER_NEEDS)),
            parent_note: None,
        };
    }
    // A parent that does not resolve settles the verdict on its own: there is
    // no directory to write into and none bx can create, so announcing
    // anything but a conflict would announce work `apply` cannot do.
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return Outcome {
            action: Action::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(reason.to_string()),
            parent_note: None,
        };
    }

    let parent_note = observed.parent.as_ref().and_then(|parent| {
        let mode = parent.mode()?;
        if !mode.is_wider_than(desired.mode) {
            return None;
        }
        let shown = crate::paths::to_portable(&parent.path, home);
        if let Some(resolved) = &parent.resolved {
            // Declaring the link as a directory target would be refused, so
            // the report names the directory that can actually be narrowed.
            // It is a realpath, so it is named against the home's realpath: a
            // home reached through a link (`/home -> var/home`) is never its
            // lexical prefix. A home that does not resolve is used as given.
            let real_home = std::fs::canonicalize(home);
            let resolved =
                crate::paths::to_portable(resolved, real_home.as_deref().unwrap_or(home));
            return Some(format!(
                "{shown} is a symlink to {resolved}, which is {mode}, wider than the {} this \
                 file declares; bx will not chmod a directory through a link, so chmod \
                 {resolved} itself",
                desired.mode,
            ));
        }
        let verb = if parent.exists() {
            "is"
        } else {
            "will be created at"
        };
        Some(format!(
            "{shown} {verb} {mode}, wider than the {} this file declares",
            desired.mode,
        ))
    });

    let (action, content_drift, mode_drift, note) = match observed.kind {
        Kind::Absent => (Action::Create, true, None, None),
        Kind::File => {
            let content_drift = observed.bytes.as_deref() != Some(desired.bytes);
            let mode_drift = observed
                .mode
                .filter(|found| *found != desired.mode)
                .map(|found| (found, desired.mode));
            let action = if content_drift || mode_drift.is_some() {
                Action::Modify
            } else {
                Action::Unchanged
            };
            let note = mode_drift.map(|(found, wanted)| format!("mode {found} -> {wanted}"));
            (action, content_drift, mode_drift, note)
        }
        Kind::Dir => (
            Action::Conflict,
            false,
            None,
            Some("a directory, where the target declares a file".to_string()),
        ),
        Kind::Symlink => (
            Action::Conflict,
            false,
            None,
            Some("a symlink; bx will not replace a link you created".to_string()),
        ),
        Kind::Other => (
            Action::Conflict,
            false,
            None,
            Some("not a regular file".to_string()),
        ),
    };

    Outcome {
        action,
        content_drift,
        mode_drift,
        note,
        parent_note,
    }
}

/// A write that has a temporary file at its final mode and no content yet.
///
/// Created by [`stage`]. Dropping it leaves the destination exactly as it was.
///
/// # What "the temporary file is removed" is worth
///
/// This is the one place that statement is qualified, and every other mention
/// of it in this module and in [`crate::fs::durable`] points here rather than
/// repeating it, so there is one sentence to be right rather than six.
///
/// Dropping a `Staged` or a [`Filled`] asks the kernel to unlink the `.bx-`
/// file, and **that unlink can fail**: it needs write permission on the
/// destination directory, which the directory can lose after [`stage`] made
/// the file. A directory narrowed to `0500` between `stage` and
/// [`Filled::publish`] fails the rename and keeps the temporary file. `tempfile`
/// reports nothing from `Drop`, so bx does not learn of it either.
///
/// Nothing in the writer can close that: removal is exactly what the directory
/// now refuses. It is why the prefix is reserved
/// ([`TEMP_PREFIX`]) — a leftover is identifiable as bx's by name, and recovery
/// and `doctor` find it there. Pinned by `a_failed_rename_syncs_no_directory`.
#[derive(Debug)]
pub struct Staged(Pending);

/// A write whose content is on disk and `fsync`ed, and which has not yet
/// replaced the destination.
///
/// Before [`Filled::publish`] the destination is untouched, after it the
/// destination is already the new content. A write-ahead journal records its
/// intent earlier still, before [`stage_as`] makes anything, so the temporary
/// file and the directories made for it are named before they exist. Dropping this removes the temporary file and
/// leaves the destination exactly as it was.
#[derive(Debug)]
pub struct Filled {
    pending: Pending,
    /// The digest of the bytes now in the temporary file. Not optional: a
    /// `Filled` cannot exist without them, so no accessor on it can fail.
    written: ContentHash,
}

/// The state both phases carry. Deliberately not public: the phase is the API.
#[derive(Debug)]
struct Pending {
    temp: NamedTempFile,
    dest: PathBuf,
    mode: Mode,
    prior: Observed,
    /// Parent directories this write invented and claims — all but one a
    /// directory target in this apply declares — deepest first, so a reversal
    /// can remove them in order and leave nothing behind.
    created_dirs: Vec<PathBuf>,
}

impl Pending {
    fn temp_path(&self) -> &Path {
        self.temp.path()
    }
}

/// Begin a write: a temporary file in the destination directory, at `mode`,
/// with no content.
///
/// A declared setuid or setgid bit is the exception: it is left off until
/// [`Staged::fill`] has written the content, because the write would clear it.
///
/// Missing parent directories are created at the mode a directory target in
/// this apply declares for them ([`CreatedDirs::declare`]), and at
/// [`Mode::DEFAULT_DIR`] when none does — a target deep under `~/.config` must
/// not need a directory declaration for every component. A declared directory
/// is therefore never created wider than declared with a file inside it,
/// whichever target is applied first. An *existing* directory is never
/// chmod'd: it is the user's, or its directory target's to change. When that
/// leaves a parent wider than the declared mode, [`compare`] reports it, and
/// the remedy is to declare the directory as a target of its own — or, for a
/// parent that is a symlink, to `chmod` the directory it resolves to, which the
/// report names. Beneath a directory that *is* declared and still exists wider
/// than declared, `stage` refuses with [`Error::DirectoryTargetPending`]
/// until that directory target's `Modify` has been applied.
///
/// A directory created here and then abandoned — because the temporary file
/// could not be made, or because the write was never committed — is left in
/// place. It is empty and at the mode a `mkdir` would have given it, the next
/// attempt reuses it, and removing it would race any other write that had
/// already begun using it.
///
/// Every directory created here is added to `created`, this apply's
/// [`CreatedDirs`]. [`ensure_dir`] reads it, so a declared directory that this
/// write created first is still the create `plan` announced for it. The write
/// claims, in [`Filled::created_dirs`], every directory it created except a
/// declared one: that one is its directory target's alone, so each directory
/// has exactly one claimant whichever target is applied first.
///
/// # What `planned` is for
///
/// `planned` is the observation `plan` compared for this destination — the
/// [`Observed`] it handed to [`compare`]. `stage` refuses the verdict `plan`
/// printed from `planned` itself, then observes the destination again and
/// refuses with [`Error::Changed`] unless it is the same file with the same
/// [`Stamp`], or still nothing at all. A file edited, replaced, removed or
/// created after `plan` is therefore never replaced with content `plan`
/// computed against something else, which is the diff `apply` would otherwise
/// make without having shown it. The prior a reversal restores comes from the
/// second observation, which the check has just shown to be the file `plan`
/// saw, and [`Filled::publish`] checks that stamp once more before the rename.
///
/// # Errors
///
/// `mode` is written as given, one without owner read included: it may be a
/// prior mode a reversal restores, and whether a declared mode may lack owner
/// read is [`compare`]'s verdict.
/// [`Error::Changed`] when the destination is no longer what `planned`
/// observed, or `planned` observed a different path. [`Error::UnusableParent`],
/// [`Error::Symlink`] or [`Error::NotAFile`] when `planned` or the second
/// observation found a parent that does not resolve, a symlink, or a directory
/// or device node. [`Error::DirectoryTargetPending`] when a directory `dest` is
/// beneath is declared and still wider than declared.
/// [`Error::DirectorySetIdNotKept`] when a missing parent it creates at a
/// declared mode does not keep that mode's setuid, setgid or sticky bit.
/// [`Error::ParentComponent`] when `dest` has a `..`
/// component, [`Error::NoParent`] when it has no parent component, and
/// [`Error::Write`] when the parent cannot be created or the temporary file
/// cannot be made.
pub fn stage(
    dest: &Path,
    mode: Mode,
    planned: &Observed,
    created: &mut CreatedDirs,
) -> Result<Staged, Error> {
    stage_in(dest, None, mode, planned, created)
}

/// [`stage`], with the temporary file at `temp`, a name [`temp_beside`]
/// chose for `dest` before anything was made.
///
/// For a write-ahead journal: it names the temporary file, and the
/// directories this call will invent, in a durable record **before** the
/// call makes either, so a crash at any point after it leaves nothing the
/// journal does not name. `temp` is created exclusively and never replaced:
/// a name something else took since is refused rather than reused.
///
/// # Errors
///
/// What [`stage`] returns, and [`Error::Write`] when `temp` is not a
/// [`TEMP_PREFIX`] name beside `dest` or cannot be created as a new file.
pub fn stage_as(
    dest: &Path,
    temp: &Path,
    mode: Mode,
    planned: &Observed,
    created: &mut CreatedDirs,
) -> Result<Staged, Error> {
    stage_in(dest, Some(temp), mode, planned, created)
}

/// A fresh temporary name for a write to `dest`: a [`TEMP_PREFIX`] file in
/// the directory [`stage`] would make its own in, which nothing is at yet.
///
/// Chosen before anything is made so a journal can record it first; see
/// [`stage_as`]. Random, from the standard library's per-process hash keys,
/// so two writes to one directory never choose the same name in practice,
/// and one that does is refused by the exclusive create rather than shared.
///
/// # Errors
///
/// [`Error::ParentComponent`] when `dest` has a `..` component and
/// [`Error::NoParent`] when it has no parent component.
pub fn temp_beside(dest: &Path) -> Result<PathBuf, Error> {
    use std::hash::{BuildHasher as _, Hasher as _};

    let dest = lexical(dest)?;
    let dir = parent_of(&dest)?;
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write(dest.as_os_str().as_encoded_bytes());
    Ok(dir.join(format!("{TEMP_PREFIX}{:016x}", hasher.finish())))
}

/// The file name `temp` has, when it is a [`TEMP_PREFIX`] name in `dir`: the
/// only temporary file [`stage_as`] and [`crate::fs::link::stage_link_as`]
/// will make.
///
/// # Errors
///
/// [`Error::Write`] naming `temp`, when it is anything else.
pub(super) fn temp_name<'a>(dir: &Path, temp: &'a Path) -> Result<&'a std::ffi::OsStr, Error> {
    match (temp.parent(), temp.file_name()) {
        (Some(parent), Some(name))
            if parent == dir && name.as_encoded_bytes().starts_with(TEMP_PREFIX.as_bytes()) =>
        {
            Ok(name)
        }
        _ => Err(Error::Write {
            path: temp.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "not a {TEMP_PREFIX} name in {}, the destination's directory",
                    dir.display()
                ),
            ),
        }),
    }
}

/// [`stage`] and [`stage_as`]: a temporary name of bx's choosing when `temp`
/// is `None`, and `temp` itself otherwise.
fn stage_in(
    dest: &Path,
    temp: Option<&Path>,
    mode: Mode,
    planned: &Observed,
    created: &mut CreatedDirs,
) -> Result<Staged, Error> {
    // Spelled as `observe` spells it, so `link/` is the link.
    let (dest, prior, created_dirs) = prepare(dest, planned, created, refuse_unwritable)?;
    let dest = dest.as_path();
    let dir = parent_of(dest)?;

    let mut builder = tempfile::Builder::new();
    match temp {
        // Exactly this name, created exclusively: no random suffix to add.
        Some(temp) => builder.prefix(temp_name(dir, temp)?).rand_bytes(0),
        None => builder.prefix(TEMP_PREFIX),
    };
    let temp = builder.tempfile_in(dir).map_err(|source| Error::Write {
        path: dir.to_path_buf(),
        source,
    })?;

    // Before any content. `tempfile` creates at 0600 and `fchmod` is not masked
    // by the umask, so the file is at its final permission bits while it is
    // still empty and was never wider than them at any instant. The set-id bits
    // wait for `fill`: the write clears them — see `SET_ID`.
    fchmod(temp.as_file(), without_set_id(mode), temp.path())?;

    Ok(Staged(Pending {
        temp,
        dest: dest.to_path_buf(),
        mode,
        prior,
        created_dirs,
    }))
}

impl Staged {
    /// The destination this write will replace.
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.0.dest
    }

    /// The temporary file, in the destination directory, at its final mode.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.0.temp_path()
    }

    /// The mode this write declares.
    ///
    /// The temporary file already has it, except for a setuid or setgid bit,
    /// which [`Staged::fill`] adds after the content.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.0.mode
    }

    /// What was at the destination before this write — the prior state a
    /// reversal restores from.
    #[must_use]
    pub const fn prior(&self) -> &Observed {
        &self.0.prior
    }

    /// The parent directories this write invented and claims, deepest first:
    /// the set [`Filled::created_dirs`] names once the content is written.
    #[must_use]
    pub fn created_dirs(&self) -> &[PathBuf] {
        &self.0.created_dirs
    }

    /// Write the content and `fsync` it, without touching the destination.
    ///
    /// # Errors
    ///
    /// [`Error::Write`] wrapping the first failing syscall, and
    /// [`Error::SetIdNotKept`] when a declared setuid, setgid or sticky bit is
    /// not on the file once the content is written. The temporary file is
    /// removed either way.
    pub fn fill(mut self, bytes: &[u8]) -> Result<Filled, Error> {
        let temp_path = self.0.temp.path().to_path_buf();
        let fail = |source| Error::Write {
            path: temp_path.clone(),
            source,
        };
        self.0.temp.write_all(bytes).map_err(&fail)?;
        // After the content and before the sync, so the sync covers it. A
        // set-id bit set earlier would already be gone: the kernel clears
        // S_ISUID, and S_ISGID alongside group execute, on a write by a process
        // without CAP_FSETID.
        //
        // Forcing either guard below *true* is a surviving mutant, and
        // equivalent: each guards an operation that does nothing when the
        // guard is false. With no set-id bit declared the `fchmod` asks for the
        // mode `stage` already set, and `verify_set_id_kept` looks for no bits
        // and finds them. Only the number of syscalls differs, and nothing
        // observes that — the `durable` recorder records durability calls, not
        // mode calls, deliberately: see the module documentation. Forcing
        // either *false* is killed, by the tests that declare a set-id bit.
        if self.0.mode.bits() & SET_ID != 0 {
            fchmod(self.0.temp.as_file(), self.0.mode, &temp_path)?;
        }
        // An fchmod succeeds even when the kernel drops S_ISGID, or the
        // filesystem stores no special bits at all, so what stuck is read back
        // rather than assumed — the sticky bit `stage` set included.
        if self.0.mode.bits() & SPECIAL != 0 {
            verify_set_id_kept(self.0.temp.as_file(), self.0.mode, &self.0.dest)?;
        }
        durable::sync_file(self.0.temp.as_file(), &temp_path).map_err(&fail)?;
        let written = ContentHash::of(bytes);
        Ok(Filled {
            pending: self.0,
            written,
        })
    }

    /// Fill and publish in one step, for a caller with nothing to interpose.
    ///
    /// # Errors
    ///
    /// Whatever [`Staged::fill`] or [`Filled::publish`] returns.
    pub fn commit(self, bytes: &[u8]) -> Result<(), Error> {
        // No ledger entry can exist for this write: `commit` never hands the
        // caller a `Filled`, so `new_entry` was never reachable for it.
        self.fill(bytes)?.publish().map_err(Unpublished::into_error)
    }

    /// Discard the write. The destination is untouched and the temporary file
    /// is dropped — see [`Staged`] for what that is worth. Identical to
    /// dropping it; named so a caller can say so.
    pub fn abandon(self) {
        // A surviving mutant, and equivalent: `self` is dropped at the end of
        // this function whether or not the body says so, so emptying the body
        // gives the same program. The call is here to be read, not to act.
        drop(self);
    }
}

impl Filled {
    /// The destination this write will replace.
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.pending.dest
    }

    /// The temporary file, holding the final content at the final mode.
    ///
    /// The path a journal records, so a leftover temporary file found after a
    /// crash is identifiable as this write's rather than some other one's.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.pending.temp_path()
    }

    /// The mode the content is already at.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.pending.mode
    }

    /// What was at the destination before this write.
    #[must_use]
    pub const fn prior(&self) -> &Observed {
        &self.pending.prior
    }

    /// The digest of the bytes now in the temporary file.
    ///
    /// Computed while filling rather than re-read afterwards, so the ledger
    /// records the digest of what was actually written rather than the digest of
    /// whatever is at the path by the time somebody looks.
    #[must_use]
    pub const fn written(&self) -> ContentHash {
        self.written
    }

    /// The parent directories this write invented and claims, deepest first.
    ///
    /// Empty when every component already existed. A directory that a
    /// directory target in this apply declares is left out even when this
    /// write made it: that target's [`EnsuredDir::created_dirs`] claims it, so
    /// reversing this write can never remove a directory that is still
    /// declared. A reversal removes these in order, so a target that created
    /// `~/.config/a/b` leaves nothing behind.
    #[must_use]
    pub fn created_dirs(&self) -> &[PathBuf] {
        &self.pending.created_dirs
    }

    /// The ledger entry for this write, assembled from what the writer knows.
    ///
    /// The writer supplies the prior bytes and their mode, the digest of what it
    /// wrote, the mode it set, and the directories it invented. The caller
    /// supplies the two facts only it has: the home directory to make the paths
    /// portable against, and how bx attached to the file.
    ///
    /// Call it **before** [`Filled::publish`] and hand the result to
    /// [`crate::state::Ledger::record`], which fsyncs the prior bytes into
    /// `restore/` before it returns. A crash after the rename is then
    /// recoverable, because the bytes that were displaced are already durable.
    ///
    /// # The entry is owed a withdrawal if the publish is refused
    ///
    /// That ordering is not a preference: the displaced bytes must be durable
    /// before anything can displace them, so the record has to precede a rename
    /// that may still fail. An entry recorded here therefore describes a write
    /// that has not happened yet, and [`Filled::publish`] can refuse — a
    /// destination changed after `stage` looked, a directory that cannot be
    /// opened, a `rename` out of space.
    ///
    /// So a caller that records an entry **must withdraw it when the publish is
    /// refused**, before it saves the ledger: take
    /// [`crate::state::LedgerView::withdrawal`] for the entry's path before the
    /// `record`, and hand it to [`crate::state::Ledger::withdraw`] on refusal.
    /// That puts back the entry as it was before the record — on a re-record,
    /// with the prior the user had before bx — rather than dropping the key,
    /// which [`crate::state::Ledger::forget`] would do and which loses that
    /// prior. [`Unpublished`] names the destination the entry is keyed on,
    /// because `publish` consumes the `Filled`. A durable entry for a write
    /// that never landed makes `bx rm` restore the recorded prior over content
    /// bx never replaced, which is Invariant 4 inverted.
    ///
    /// Pinned by
    /// `a_ledger_entry_for_a_refused_publish_is_withdrawn_through_what_the_refusal_names`
    /// for a first record, and by
    /// `a_refused_re_record_is_withdrawn_to_the_entry_it_replaced` for a
    /// re-record.
    ///
    /// # Errors
    ///
    /// [`Error::NotPortable`] if the destination or a created directory is not
    /// valid UTF-8, or `home` is not absolute: such a path has no key the
    /// ledger could record it under without naming a different file.
    pub fn new_entry(&self, home: &Path, mechanism: Mechanism) -> Result<NewEntry, Error> {
        let portable = |path: &Path| {
            Portable::from_path(path, home).map_err(|source| Error::NotPortable {
                path: path.to_path_buf(),
                source,
            })
        };
        Ok(NewEntry::new(
            portable(&self.pending.dest)?,
            self.written(),
            self.pending.mode,
            mechanism,
            self.pending.prior.prior_bytes(),
        )
        .with_created_dirs(
            self.pending
                .created_dirs
                .iter()
                .map(|dir| portable(dir))
                .collect::<Result<_, _>>()?,
        ))
    }

    /// `rename` the temporary file onto the destination, then `fsync` the
    /// destination directory so the rename itself is durable.
    ///
    /// A hard link to the destination is **not** followed: the destination is
    /// replaced by name, so any other link to the old inode keeps the old
    /// content and the old mode. That is inherent to an atomic rename, and it
    /// holds for a mode-only `Modify` too, which is applied through [`stage`]
    /// like any other so that it is refused when the file changed after `plan`
    /// — see [`compare`].
    ///
    /// The destination directory is opened **before** the rename and `fsync`ed
    /// after it. Opening a directory needs read permission on it and renaming
    /// into it does not, so in a `0300` directory an open placed after the
    /// rename would fail with the new content already in place. Opened first,
    /// that failure happens while the destination is still untouched, which is
    /// what [`write_atomically`]'s contract promises for every `Err` but a
    /// failing `fsync` of the directory.
    ///
    /// Immediately before the rename the destination is `lstat`ed again and
    /// compared with the [`Stamp`] [`stage`] observed. Anything else there — an
    /// edit saved in place or by rename, a symlink swapped in, a file where
    /// there was none, a file removed — is refused rather than replaced, so a
    /// write never destroys bytes bx did not observe and the recorded prior is
    /// never older than what it displaces. The window between that `lstat` and
    /// the `rename(2)` remains; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`Unpublished`], which names the destination as well as the cause, so a
    /// caller that recorded a ledger entry for this write before calling — as
    /// [`Filled::new_entry`] requires — can withdraw it. `publish` consumes the
    /// `Filled`, so the refusal is the only thing left that knows which write
    /// it was.
    ///
    /// The cause is [`Error::Changed`] when the destination is no longer what
    /// [`stage`] observed; nothing is replaced. [`Error::Write`] wrapping the
    /// failing `open` of the directory, `rename`, or `fsync`. The temporary file
    /// is dropped either way — see [`Staged`] for what that is worth. Only a
    /// failing `fsync` of the directory is returned after the destination was
    /// replaced.
    pub fn publish(self) -> Result<(), Unpublished> {
        let Self {
            pending:
                Pending {
                    temp,
                    dest,
                    mode,
                    prior,
                    ..
                },
            ..
        } = self;

        // Every refusal below names `dest`, because that is the key of the
        // ledger entry a caller was obliged to record before calling. There is
        // no early return that forgets to: the closure is the only way out.
        let refused = |error: Error| Unpublished {
            error,
            dest: dest.clone(),
        };
        let publish = || -> Result<(), Error> {
            let dir = parent_of(&dest)?;
            let dir_fail = |source| Error::Write {
                path: dir.to_path_buf(),
                source,
            };
            let handle = durable::Dir::open(dir).map_err(dir_fail)?;
            // The last thing before the rename, so the window it leaves open is
            // as narrow as it can be. Refusing drops `temp`, which removes it.
            verify_unchanged(&prior)?;
            durable::rename(temp, &dest).map_err(|e| Error::Write {
                path: dest.clone(),
                source: e.error,
            })?;
            handle.sync().map_err(dir_fail)
        };
        publish().map_err(refused)?;

        tracing::debug!(dest = %dest.display(), %mode, "wrote a file atomically");
        Ok(())
    }

    /// Discard the write. The destination is untouched and the temporary file
    /// is dropped — see [`Staged`] for what that is worth. Identical to
    /// dropping it; named so a caller can say so.
    pub fn abandon(self) {
        // A surviving mutant, and equivalent: `self` is dropped at the end of
        // this function whether or not the body says so, so emptying the body
        // gives the same program. The call is here to be read, not to act.
        drop(self);
    }
}

/// A write [`Filled::publish`] refused: why, and which write it was.
///
/// The second half is the point. [`Filled::new_entry`] must be called before
/// `publish`, because the bytes a rename displaces have to be durable before
/// anything displaces them — so by the time a publish is refused, a caller with
/// a ledger has already recorded an entry for a write that did not happen. That
/// record has to be withdrawn with [`crate::state::Ledger::withdraw`] before
/// the ledger is saved, or `bx rm` will restore the recorded prior over content
/// bx never replaced; see [`Filled::new_entry`].
///
/// `publish` consumes the [`Filled`], so nothing the caller still holds names
/// the write afterwards. This does: [`Unpublished::dest`] is the path
/// [`Filled::new_entry`] keyed the entry on.
///
/// # It is deliberately not an error type
///
/// No [`Display`](std::fmt::Display) and no
/// [`std::error::Error`], so `?` converts it into nothing: not into
/// [`Error`], and not into an aggregating type like `eyre::Report`, whose
/// blanket `From` needs exactly those impls. The ledger-holding caller lives in
/// that second layer, so an error impl here would have made the guard look
/// present and not be.
///
/// ```compile_fail
/// fn publish(filled: bx::fs::Filled) -> Result<(), bx::fs::Error> {
///     filled.publish()?; // no `From<Unpublished> for fs::Error`
///     Ok(())
/// }
/// ```
///
/// ```compile_fail
/// fn publish(filled: bx::fs::Filled) -> eyre::Result<()> {
///     filled.publish()?; // and none for `eyre::Report` either
///     Ok(())
/// }
/// ```
///
/// ```
/// fn publish(filled: bx::fs::Filled) -> Result<(), bx::fs::Error> {
///     // Written out, because it says "this write had no ledger entry".
///     filled.publish().map_err(bx::fs::Unpublished::into_error)
/// }
/// ```
#[derive(Debug)]
pub struct Unpublished {
    /// Why the write was refused.
    pub error: Error,
    /// The destination it would have replaced, and the path the entry to
    /// withdraw is keyed on.
    pub dest: PathBuf,
}

impl Unpublished {
    /// The cause alone, for a caller that recorded nothing to withdraw.
    ///
    /// Deliberately a named call rather than a `From` impl: `?` would then
    /// convert a refused publish into a plain [`Error`] silently, and a caller
    /// that *had* recorded an entry would lose the only thing that still names
    /// it. Writing this out says "there is no entry", which is true of
    /// [`Staged::commit`] and [`write_atomically`] and of nothing else here.
    ///
    /// The [`Error`] it returns does not name [`Unpublished::dest`], because by
    /// then the caller has said there is nothing keyed on it.
    #[must_use]
    pub fn into_error(self) -> Error {
        self.error
    }
}

/// Replace `path` with `bytes`, atomically, at `mode`.
///
/// After an `Ok`, `path` holds all of `bytes`, and the rename is durable: a
/// power loss after the call cannot resurrect the previous content. After an
/// `Err`, `path` holds exactly what it held before, or, for
/// [`Error::Changed`], whatever changed it after bx looked — with one
/// exception. A failing `fsync` of the destination directory is reported after
/// the rename, so that [`Error::Write`] comes back with `path` already holding
/// all of `bytes`, in a rename a power loss may still undo. The temporary file
/// is dropped in any case — see [`Staged`] for what that is worth.
///
/// The shorthand for [`observe`] + [`stage`] + [`Staged::commit`], for a caller
/// whose `plan` and `apply` are this one call. A caller that printed a plan
/// hands that plan's observation to [`stage`], and a caller that must record
/// something between the `fsync` and the `rename` uses the phases directly.
///
/// # The parent directory must already exist
///
/// This function creates no directories, and that is the whole of the claim.
/// Two entry points in this module do: [`stage`], for the parents a write
/// needs, and [`ensure_dir`], which is a directory target's own apply. Both
/// take a [`CreatedDirs`] to record what they made so a reversal can remove it,
/// both are announced by a [`compare`] or [`compare_dir`] first, and both get
/// their mode from a declaration. (Outside `fs` entirely,
/// `state::dir::ensure_dir` creates the state directory; it is bx's own and
/// does not pass through here.)
///
/// This shorthand has none of the three: no set to record in, no plan to
/// announce in, and no caller to say what mode a new directory should get.
/// Inventing a `0755` directory here to hold a `0600` decrypted secret would
/// answer that last question by default, silently, in the one function billed
/// as the single place a secret is written.
///
/// So a missing parent is [`Error::MissingParent`]: the caller creates the
/// directory it means, at the mode it means, and both state-directory callers
/// already do.
///
/// # Errors
///
/// [`Error::MissingParent`] when the destination's parent does not exist, and
/// whatever [`observe`], [`stage`] or [`Staged::commit`] returns.
pub fn write_atomically(path: &Path, bytes: &[u8], mode: Mode) -> Result<(), Error> {
    let planned = observe(path)?;
    // A parent that is there but does not resolve, or is a link, is left to the
    // verdicts `stage` already has for it; only "nothing is there" is this one.
    if let Some(parent) = &planned.parent
        && matches!(parent.state, ParentState::Absent(_))
    {
        return Err(Error::MissingParent(parent.path.clone()));
    }
    stage(path, mode, &planned, &mut CreatedDirs::new())?.commit(bytes)
}

/// Set the mode of an existing file or directory, in place, unconditionally.
///
/// It compares nothing with `plan`: it takes no planned observation, and it
/// looks at the path only to refuse a symlink. Whatever is there when it runs
/// — a file the user chmod'd after `plan`, or a directory that replaced the
/// file `plan` saw — is chmod'd. So it is **not** how a file target's
/// mode-only `Modify` is applied; that goes through [`stage`], which refuses a
/// destination that changed after `plan` (see [`compare`]).
///
/// Within this module it is called only where the verdict is already settled:
/// by [`ensure_dir`] for a directory target's `Modify`, after its own check
/// that the directory is still what `plan` saw, and on a directory
/// `create_dir_at` has just made, to make its declared mode authoritative over
/// the `umask`. Both go through `set_dir_mode`, which reads the directory back
/// and refuses a declared special bit that did not stick
/// ([`Error::DirectorySetIdNotKept`]). This function reads nothing back.
///
/// # Errors
///
/// [`Error::Symlink`] when `path` is a symlink — bx does not change the mode of
/// a link's target through the link — [`Error::ParentComponent`] when it has a
/// `..` component, and [`Error::Write`] when the `chmod` fails.
pub fn set_mode(path: &Path, mode: Mode) -> Result<(), Error> {
    // Without a trailing separator, or `lstat` below would follow the link too.
    let path = lexical(path)?;
    let path = path.as_path();
    // chmod(2) follows symlinks and Linux has no AT_SYMLINK_NOFOLLOW for it, so
    // the link is excluded by looking first. The remaining window is a race with
    // the invoking user against their own home directory, which is not a
    // boundary bx defends: they can chmod their own files directly.
    if let Some(meta) = optional_metadata(path)?
        && Kind::from(meta.file_type()) == Kind::Symlink
    {
        return Err(Error::Symlink(path.to_path_buf()));
    }

    rustix::fs::chmod(path, mode.into()).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    tracing::debug!(path = %path.display(), %mode, "set a file mode");
    Ok(())
}

/// Compare what is at a **declared directory** target with the mode bx wants
/// it at — the `plan` half of a directory target.
///
/// Reads nothing, exactly like [`compare`]: `plan` for a directory target is
/// [`observe`] then this, and nothing on disk changes. The parent is classified
/// by the same [`ParentState`] a file's is, so a dangling symlink, a loop or a
/// non-directory anywhere above the path is a conflict here, not an `ENOENT`
/// for `apply` to discover.
///
/// * [`Action::Unchanged`] — a directory at `mode`.
/// * [`Action::Create`] — nothing is there; `path` will be created at `mode`
///   and any missing ancestor at [`Mode::DEFAULT_DIR`].
/// * [`Action::Modify`] — a directory at another mode, closed by [`ensure_dir`]
///   with a `chmod` and a read-back of the special bits that stuck. The note
///   reads exactly `mode 0755 -> 0700`, as for a file.
/// * [`Action::Conflict`] — anything that is not a directory, including a
///   symlink to one: bx does not chmod a directory through a link.
///
/// # A declared mode that denies the owner access is applied like any other
///
/// `fs` applies any declared directory mode. `~/.gnupg` declared `0400` is
/// created at `0400`, and a declared `~/.gnupg/gpg.conf` beneath it then fails
/// in [`stage`] with an `EACCES` [`Error::Write`], because bx cannot make its
/// temporary file there. The directory is left in place and a later `plan` of
/// the file cannot observe it.
///
/// That is the decision, not an omission, and the reason is that the rule that
/// would refuse it cannot be stated here. "A directory target with a declared
/// file beneath it must grant its owner write and search" needs to know which
/// targets lie beneath this one. `fs` is handed one path at a time and never
/// sees the set; the plan layer is where the set exists, and that is where the
/// rule belongs. A rule `fs` could state instead — refuse any directory
/// without owner `rwx` — was tried and removed, because a childless read-only
/// directory target is legitimate and needs neither listing nor a temporary
/// file.
///
/// What `fs` still refuses is the case it *can* decide from one path: a
/// **file** target whose declared mode denies the owner read, because bx reads
/// a file back to compare it — [`Error::OwnerLockedOut`], raised by [`compare`].
#[must_use]
pub fn compare_dir(observed: &Observed, mode: Mode) -> Outcome {
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return Outcome {
            action: Action::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(reason.to_string()),
            parent_note: None,
        };
    }

    let conflict = |note: &str| (Action::Conflict, None, Some(note.to_string()));
    let (action, mode_drift, note) = match observed.kind {
        Kind::Absent => (Action::Create, None, None),
        Kind::Dir => match observed.mode.filter(|found| *found != mode) {
            None => (Action::Unchanged, None, None),
            Some(found) => (
                Action::Modify,
                Some((found, mode)),
                Some(format!("mode {found} -> {mode}")),
            ),
        },
        Kind::File => conflict("a file, where the target declares a directory"),
        Kind::Symlink => conflict("a symlink; bx will not change a directory through a link"),
        Kind::Other => conflict("not a directory"),
    };

    Outcome {
        action,
        // A directory has no content to drift.
        content_drift: false,
        mode_drift,
        note,
        parent_note: None,
    }
}

/// Make `path` the directory at `mode` that [`compare_dir`] announced — the
/// `apply` half of a declared directory target.
///
/// `planned` is the observation `plan` compared — the [`Observed`] it handed to
/// [`compare_dir`]. `ensure_dir` observes the path again and refuses with
/// [`Error::Changed`] unless [`compare_dir`] reaches the same verdict from both:
/// the same action, the same mode found for a `Modify`, the same cause for a
/// `Conflict`. A directory chmod'd after `plan` printed `Unchanged`, a directory
/// that appeared after `plan` printed `Create`, and a file that took the path
/// are refused rather than acted on, so `apply` never does work `plan` did not
/// announce. The refusal also covers a path taken between that second
/// observation and the `mkdir`: a `Create` succeeds only when this call is the
/// one that created the directory.
///
/// On agreement it performs **exactly** that action: nothing for `Unchanged`;
/// `mkdir` for `Create`, with `path` at `mode` and missing ancestors at the
/// mode declared for them or [`Mode::DEFAULT_DIR`]; [`set_mode`] for `Modify`,
/// with the directory read back so a declared special bit the kernel dropped is
/// refused rather than reported as applied;
/// and nothing at all for
/// `Conflict`, which is reported rather than raised because it is a verdict
/// `plan` already printed. `plan` must use [`observe`] + [`compare_dir`], not
/// this.
///
/// It returns what a ledger needs to reverse it: the action, the observation
/// it acted on — so the mode a `Modify` overwrote is `prior.mode` — and the
/// directories it created, deepest first.
///
/// `created` is this apply's [`CreatedDirs`]; [`stage`] and this function both
/// add to it, and this function declares `path` at `mode` in it. A path `plan`
/// saw absent that is now a directory an earlier call in this apply made —
/// the same device and inode — is still the `Create` `plan` announced, so it is
/// set to `mode` rather than refused, and the returned `created_dirs` names it.
/// That call made it at `mode` when the directory was declared before it ran.
/// One made at any other mode was made before its declaration, possibly with a
/// file already published in it at [`Mode::DEFAULT_DIR`], and is refused with
/// [`Error::UndeclaredDirectory`]. With every directory target declared before
/// any target is applied, the order in which a caller applies a directory
/// target and the targets beneath it does not matter. A directory outside the
/// set, or a different directory now at a path in it, that appeared after
/// `plan` is still refused.
///
/// Two windows remain. A `chmod` landing between the second observation and
/// the [`set_mode`] is overwritten, as for any directory mode change (decision
/// 6). And
/// when a `Create` is refused because the path was taken after the second
/// observation, an ancestor this call had already created is left in place,
/// empty, exactly as [`stage`] leaves one for an abandoned write.
///
/// # Errors
///
/// [`Error::Changed`] when the path is no longer what `plan` saw;
/// [`Error::UndeclaredDirectory`] when an earlier call in this apply made the
/// directory at another mode; [`Error::DirectorySetIdNotKept`] when a declared
/// setuid, setgid or sticky bit is not on the directory after its `chmod` — a
/// refused `Modify` sets the directory back to the mode `plan` saw first, and
/// reads it back — and, before any `chmod`, when the directory has `S_ISGID`
/// or `mode` adds it and nothing confirms that a `chmod` by this process keeps
/// the bit, so the kernel may strip it;
/// [`Error::ParentComponent`] when it has a `..`
/// component; [`Error::Read`]
/// when the path or its parent cannot be stat'd; and [`Error::Write`] when a
/// directory cannot be created or chmod'd.
pub fn ensure_dir(
    path: &Path,
    mode: Mode,
    planned: &Observed,
    created: &mut CreatedDirs,
) -> Result<EnsuredDir, Error> {
    // Spelled as `observe` spells it, so `link/` is the link and never the
    // directory a chmod through it would change.
    let path = lexical(path)?;
    let path = path.as_path();
    let fresh = observe(path)?;
    act_on_dir(path, mode, planned, fresh, created)
}

/// What [`ensure_dir`] did, and what a ledger needs to reverse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsuredDir {
    /// The action performed — the one `plan` announced.
    pub action: Action,
    /// What was at the path immediately before, which is what `plan` saw. For
    /// a `Modify` its `mode` is the mode that was overwritten. For a directory
    /// an earlier write in this apply created, it is `plan`'s observation:
    /// nothing was there before this apply.
    pub prior: Observed,
    /// The directories this target claims, deepest first — the path itself
    /// and any ancestor this call had to invent, less an ancestor another
    /// directory target in this apply declares, which that target claims —
    /// in the order a reversal removes them. For a directory an earlier call in
    /// this apply made, just the path. Empty unless `action` is `Create`.
    pub created_dirs: Vec<PathBuf>,
}

/// The directories one `apply` has created so far, and the modes its
/// directory targets declare.
///
/// Start one per apply, [`declare`](Self::declare) every directory target in
/// it before applying any target, and pass the same one to every [`stage`] and
/// [`ensure_dir`] in the apply. That is what makes the order of targets not
/// matter:
///
/// * [`stage`] creates a missing declared directory at its declared mode, not
///   [`Mode::DEFAULT_DIR`], so no file is published into a directory wider
///   than its target declares. Beneath a declared directory that already
///   exists wider than declared it refuses with
///   [`Error::DirectoryTargetPending`].
/// * Every directory has exactly one claimant. A declared directory is claimed
///   by its own directory target's [`EnsuredDir::created_dirs`] alone:
///   [`Filled::created_dirs`] and a deeper target's `created_dirs` leave it
///   out, whichever call made it. Any other directory is claimed by the call
///   that made it.
/// * [`ensure_dir`] adopts a declared directory an earlier call in this apply
///   made as the `Create` `plan` announced — only when it is the same
///   directory, by device and inode, and was made at the declared mode. One
///   made before its declaration is refused with
///   [`Error::UndeclaredDirectory`].
///
/// A fresh set per call brings back the refusal of a directory an earlier
/// write in the same apply made.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreatedDirs {
    /// Every directory this apply created, and how.
    made: BTreeMap<DirKey, Made>,
    /// The mode each directory target in this apply declares.
    declared: BTreeMap<DirKey, Mode>,
}

/// A directory path as [`CreatedDirs`] keys it.
///
/// Both maps are keyed on this and nothing else, and the only way to make one is
/// [`DirKey::of`]. So no method of `CreatedDirs` can read or write either map
/// with a path that did not pass through here: a lookup that forgot to would
/// not compile. That matters because `declare` and `declared` are public, and a
/// caller outside this module — the apply engine that will hold one set for the
/// whole apply — has every reason to expect `~/.ssh` and `~/.ssh/` to name one
/// directory, and no way to check that they do.
///
/// [`DirKey::of`] is what makes the spellings agree: it collects `components()`,
/// which drops a trailing separator and every `.` after the first component.
/// `Path`'s own `Ord` would agree on those two spellings without it — a key
/// holding raw `OsStr` bytes *and* normalising passes the test below, measured
/// — so the normalisation is the guarantee and `Ord` is not.
///
/// The newtype is what makes it un-skippable, and that is worth its weight for
/// two reasons that are not about `Ord`:
///
/// * **`declare` and `declared` are public**, and the caller that drives them is
///   outside this module — the apply engine that will hold one set for a whole
///   apply. An un-normalised lookup from there is a compile error rather than a
///   silent `None`.
/// * **The stored spelling is dereferenced, not just compared.** [`DirKey::path`]
///   goes into `symlink_metadata` and into [`Error::DirectoryTargetPending`]'s
///   `dir`, which a user reads. A trailing separator there makes the kernel
///   resolve the last component, so `link/` would be stat'd as the directory the
///   link points at — exactly what [`lexical`] exists to prevent everywhere else.
///
/// Pinned by `a_created_dirs_set_answers_for_a_directory_however_it_is_spelled`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DirKey(PathBuf);

impl DirKey {
    /// The key for `path`: its components, which drops a trailing separator and
    /// every `.`, exactly as [`lexical`] spells a path before using it.
    fn of(path: &Path) -> Self {
        Self(path.components().collect())
    }

    /// The normalised path this key is.
    fn path(&self) -> &Path {
        &self.0
    }
}

/// One directory an apply created: the mode it was created at, and which
/// directory it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Made {
    mode: Mode,
    dev: u64,
    ino: u64,
}

impl CreatedDirs {
    /// No directories created or declared yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            made: BTreeMap::new(),
            declared: BTreeMap::new(),
        }
    }

    /// Whether this apply created `path`.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        self.made.contains_key(&DirKey::of(path))
    }

    /// Declare that a directory target in this apply wants `path` at `mode`.
    ///
    /// Call it for every directory target before applying any target in the
    /// apply. [`ensure_dir`] declares its own path too, so a caller that always
    /// applies a directory target before anything beneath it needs no separate
    /// call — but one that does not, and skips this, gets
    /// [`Error::UndeclaredDirectory`] from the directory target.
    pub fn declare(&mut self, path: &Path, mode: Mode) {
        self.declared.insert(DirKey::of(path), mode);
    }

    /// The mode a directory target in this apply declares for `path`, if any.
    ///
    /// Answers for the same directory however it is spelled — see [`DirKey`].
    #[must_use]
    pub fn declared(&self, path: &Path) -> Option<Mode> {
        self.declared.get(&DirKey::of(path)).copied()
    }

    /// How this apply made `path`, if it did.
    fn made(&self, path: &Path) -> Option<Made> {
        self.made.get(&DirKey::of(path)).copied()
    }

    /// Note the directories a call just created, deepest first, and return the
    /// ones that call claims: all of them but a declared directory, unless it
    /// is `own`, the path of the directory target making the call.
    fn record(&mut self, made: Vec<(PathBuf, Made)>, own: Option<&Path>) -> Vec<PathBuf> {
        let own = own.map(DirKey::of);
        let mut claimed = Vec::with_capacity(made.len());
        for (path, how) in made {
            let key = DirKey::of(&path);
            if own.as_ref() == Some(&key) || !self.declared.contains_key(&key) {
                claimed.push(path);
            }
            self.made.insert(key, how);
        }
        claimed
    }
}

/// The half of [`ensure_dir`] after its own observation, separate so a test can
/// change the disk between the two.
fn act_on_dir(
    path: &Path,
    mode: Mode,
    planned: &Observed,
    fresh: Observed,
    created: &mut CreatedDirs,
) -> Result<EnsuredDir, Error> {
    created.declare(path, mode);
    let announced = compare_dir(planned, mode);
    // A directory an earlier call in this apply created is still the create
    // plan announced: plan saw nothing, and bx made it since. Only that very
    // directory counts — another one somebody put at the same path is not
    // bx's — and only one made at the declared mode: a write that ran before
    // the declaration made it at 0755 and may already have published into it.
    if announced.action == Action::Create
        && fresh.kind == Kind::Dir
        && let (Some(made), Some(stamp)) = (created.made(path), fresh.stamp)
        && (made.dev, made.ino) == (stamp.dev, stamp.ino)
    {
        if made.mode != mode {
            return Err(Error::UndeclaredDirectory {
                path: path.to_path_buf(),
                created: made.mode,
                declared: mode,
            });
        }
        // Normally a no-op; it also narrows the directory again if it was
        // chmod'd after bx made it, as a create at `mode` would have left it.
        // A directory always has a mode.
        refuse_setgid_a_chmod_strips(path, fresh.mode.unwrap_or(mode), mode)?;
        set_dir_mode(path, mode)?;
        tracing::debug!(
            path = %path.display(),
            %mode,
            "set a directory this apply created to its declared mode"
        );
        return Ok(EnsuredDir {
            action: Action::Create,
            prior: planned.clone(),
            created_dirs: vec![path.to_path_buf()],
        });
    }
    let outcome = compare_dir(&fresh, mode);
    // Equal outcomes are equal verdicts: the action, the mode found for a
    // `Modify`, and the cause of a `Conflict` are all part of one.
    if outcome != announced {
        return Err(Error::Changed {
            path: path.to_path_buf(),
            detail: format!("plan saw {}, and it is now {}", seen(planned), seen(&fresh)),
        });
    }

    let mut created_dirs = Vec::new();
    match outcome.action {
        Action::Create => {
            let made = create_missing_dirs(path, created)?;
            // The path itself is the deepest entry when this call made it. When
            // it is not there, something took the path between the observation
            // and the `mkdir` — somebody else's directory, or not a directory at
            // all — and neither is the create `plan` announced.
            if made.first().map(|(dir, _)| dir.as_path()) != Some(path) {
                let now = optional_metadata(path)?
                    .map_or(Kind::Absent, |meta| Kind::from(meta.file_type()));
                return Err(Error::Changed {
                    path: path.to_path_buf(),
                    detail: format!(
                        "plan saw nothing, and {now} took the path before bx could create it"
                    ),
                });
            }
            created_dirs = created.record(made, Some(path));
            tracing::debug!(path = %path.display(), %mode, "created a directory");
        }
        Action::Modify => {
            // A `Modify` is only announced for a directory, which always has
            // a mode.
            let prior = fresh.mode.unwrap_or(mode);
            // Before any chmod: one the kernel strips the setgid bit on would
            // lose a bit no set-back by this process can restore.
            refuse_setgid_a_chmod_strips(path, prior, mode)?;
            if let Err(refused) = set_dir_mode(path, mode) {
                return Err(set_back(path, prior, refused));
            }
        }
        _ => {}
    }
    Ok(EnsuredDir {
        action: outcome.action,
        prior: fresh,
        created_dirs,
    })
}

/// What an observation of a directory target found, in the words a refusal
/// uses.
fn seen(observed: &Observed) -> String {
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return format!("a parent that does not resolve ({reason})");
    }
    match (observed.kind, observed.mode) {
        (Kind::Dir, Some(mode)) => format!("a directory at {mode}"),
        (kind, _) => kind.to_string(),
    }
}

/// Everything a write does before it makes its temporary entry: spell `dest`
/// as [`observe`] does, refuse what `plan` refused, look again and refuse a
/// destination that changed since `planned`, then make the missing parents.
///
/// Shared by [`stage`], which writes a file, and
/// [`crate::fs::link::stage_link`], which writes a link: the two differ only
/// in what they may replace, which `refuse` says.
///
/// Returns the destination as spelled, the fresh observation — the prior a
/// reversal restores, which the check has just shown to be what `plan` saw —
/// and the directories made on the way that this write claims.
///
/// # Errors
///
/// [`Error::Changed`] when the destination is no longer what `planned`
/// observed, or `planned` observed a different path; whatever `refuse`
/// returns for `planned` or the fresh look; and what [`stage`] documents for
/// the parents.
pub(super) fn prepare(
    dest: &Path,
    planned: &Observed,
    created: &mut CreatedDirs,
    refuse: fn(&Observed) -> Result<(), Error>,
) -> Result<(PathBuf, Observed, Vec<PathBuf>), Error> {
    let (dest, prior) = refuse_to_prepare(dest, planned, created, refuse)?;
    let dir = parent_of(&dest)?;
    let made = create_missing_dirs(dir, created)?;
    let created_dirs = created.record(made, None);
    Ok((dest, prior, created_dirs))
}

/// Every refusal [`stage`] makes before it creates anything, made without
/// creating anything, and the fresh observation it made them against.
///
/// For a write-ahead journal that records a write before [`stage_as`]
/// makes it: a write `stage` would refuse outright — a destination `plan`
/// refused or that changed since, a parent that does not resolve, a declared
/// directory still wider than declared — is refused here with nothing
/// recorded, so the journal never announces a write that could not begin.
/// `stage_as` makes every one of these checks again; what can differ is only
/// what changed on disk in between.
///
/// The observation is the prior the write displaces, as [`Staged::prior`]
/// would report it: the check has just shown it to be the file `plan` saw.
///
/// # Errors
///
/// What [`stage`] documents, but for creating the parents and the temporary
/// file.
pub fn refuse_stage(
    dest: &Path,
    planned: &Observed,
    created: &CreatedDirs,
) -> Result<Observed, Error> {
    refuse_to_prepare(dest, planned, created, refuse_unwritable).map(|(_, prior)| prior)
}

/// [`prepare`] up to the first thing it makes: every refusal, and the fresh
/// observation. Shared by [`refuse_stage`] and
/// [`crate::fs::link::refuse_stage_link`], which make no directory.
pub(super) fn refuse_to_prepare(
    dest: &Path,
    planned: &Observed,
    created: &CreatedDirs,
    refuse: fn(&Observed) -> Result<(), Error>,
) -> Result<(PathBuf, Observed), Error> {
    let dest = lexical(dest)?;
    if planned.path != dest {
        return Err(Error::Changed {
            path: dest,
            detail: format!("plan observed {}, not this path", planned.path.display()),
        });
    }
    // Plan's verdict first: a conflict plan printed stays refused whatever is
    // there now, so `apply` never writes where `plan` said it would not.
    refuse(planned)?;
    let prior = observe(&dest)?;
    // Then plan's look against this one. Equal stamps are the same file,
    // unchanged, so this observation's bytes are the ones plan's diff was about.
    refuse_changed(planned, prior.stamp.map(|stamp| (prior.kind, stamp)))?;
    // The destination is unchanged; a parent above it may not be.
    refuse(&prior)?;

    let dir = parent_of(&dest)?;
    // Before creating anything, so a refusal leaves nothing behind.
    refuse_wider_than_declared(&dest, dir, created)?;
    Ok((dest, prior))
}

/// Refuse unless `prior.path` is still what [`observe`] found there: the same
/// file with the same [`Stamp`], or still nothing at all.
///
/// # Errors
///
/// [`Error::Changed`] naming what moved, and [`Error::Read`] when the path can
/// no longer be stat'd.
pub(super) fn verify_unchanged(prior: &Observed) -> Result<(), Error> {
    let now = optional_metadata(&prior.path)?
        .map(|meta| (Kind::from(meta.file_type()), Stamp::of(&meta)));
    refuse_changed(prior, now)
}

/// Refuse unless `now` — a kind and [`Stamp`], or `None` for nothing there —
/// is what `then` observed.
///
/// # Errors
///
/// [`Error::Changed`] naming what moved.
fn refuse_changed(then: &Observed, now: Option<(Kind, Stamp)>) -> Result<(), Error> {
    let was = then.stamp.map(|stamp| (then.kind, stamp));
    if now == was {
        return Ok(());
    }
    let detail = match (was, now) {
        (_, None) => "it has been removed",
        (None, Some(_)) => "nothing was there, and something is now",
        (Some(_), Some(_)) => "it has been modified or replaced",
    };
    Err(Error::Changed {
        path: then.path.clone(),
        detail: detail.to_string(),
    })
}

/// Refuse a write over what `observed` found, when that is not a regular file
/// or nothing, or when its parent does not resolve — the conflicts [`compare`]
/// announces.
///
/// # Errors
///
/// [`Error::UnusableParent`], [`Error::Symlink`] or [`Error::NotAFile`].
fn refuse_unwritable(observed: &Observed) -> Result<(), Error> {
    // The parent first: it settles the verdict `compare` announced on its own.
    if let Some(parent) = observed.parent.as_ref()
        && let Some(reason) = parent.unusable()
    {
        return Err(Error::UnusableParent {
            path: parent.path.clone(),
            reason: reason.to_string(),
        });
    }
    if observed.kind.is_writable_destination() {
        return Ok(());
    }
    Err(match observed.kind {
        Kind::Symlink => Error::Symlink(observed.path.clone()),
        kind => Error::NotAFile {
            path: observed.path.clone(),
            kind,
        },
    })
}

/// Refuse to put `dest` beneath a directory this apply declares while that
/// directory exists wider than its declared mode — see
/// [`Error::DirectoryTargetPending`].
///
/// "Wider" is [`Mode::grants_more_than`]: any group or other bit the
/// declaration does not grant, execute included, so a `0711` directory
/// declared `0700` is refused as surely as a `0755` one.
///
/// Only a declared directory that exists is checked: a missing one is about
/// to be created at its declared mode. Something there that is not a directory
/// is left to the verdicts `plan` already printed for it.
///
/// # Errors
///
/// [`Error::DirectoryTargetPending`], and [`Error::Read`] when a declared
/// directory above `dest` cannot be stat'd.
fn refuse_wider_than_declared(dest: &Path, dir: &Path, created: &CreatedDirs) -> Result<(), Error> {
    for (key, &declared) in &created.declared {
        let declared_dir = key.path();
        if !dir.starts_with(declared_dir) {
            continue;
        }
        let Some(meta) = optional_metadata(declared_dir)? else {
            continue;
        };
        let found = mode_of(&meta);
        // Every group and other bit, execute included: both modes are this
        // directory's, and a traversable directory exposes a file inside it by
        // name whatever the directory's read bits say.
        if meta.is_dir() && found.grants_more_than(declared) {
            return Err(Error::DirectoryTargetPending {
                path: dest.to_path_buf(),
                dir: declared_dir.to_path_buf(),
                found,
                declared,
            });
        }
    }
    Ok(())
}

/// `path` rebuilt from its components, which drops every trailing separator
/// and every `.` after the first component, or a refusal when it has a `..`.
///
/// A trailing `/` or `/.` makes the kernel resolve the last component:
/// `lstat("link/")` stats the directory a symlink points at, and
/// `chmod("link/")` changes it. bx decides about the component a target names,
/// however the path is spelled, so every entry point that looks at or changes a
/// path spells it this way first. Lexical only — nothing is resolved.
///
/// A `..` anywhere is refused rather than kept or removed: kept, the kernel
/// resolves it through any symlink before it, and removed, it can name a
/// different file. Either way the path bx records would not be the file it
/// changed — see [`Error::ParentComponent`].
///
/// # Errors
///
/// [`Error::ParentComponent`] when `path` has a `..` component.
fn lexical(path: &Path) -> Result<PathBuf, Error> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(Error::ParentComponent(path.to_path_buf()));
    }
    Ok(path.components().collect())
}

/// The directory `path` will be written into.
pub(super) fn parent_of(path: &Path) -> Result<&Path, Error> {
    match path.parent() {
        // A bare file name has an empty parent, which names the working
        // directory; `NamedTempFile::new_in("")` would fail on it.
        Some(dir) if dir.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(dir) => Ok(dir),
        None => Err(Error::NoParent(path.to_path_buf())),
    }
}

/// `symlink_metadata`, with "nothing is there" as a value rather than an error.
///
/// Follows no symlink: for a destination, a link is a thing in its own right.
fn optional_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Whether a failed lookup means "this path does not lead anywhere" — nothing
/// there, a non-directory in the way, or a symlink loop — rather than "bx was
/// not allowed to look".
fn unresolvable_path(e: &std::io::Error) -> bool {
    // By errno rather than `ErrorKind`: `ErrorKind::FilesystemLoop` is not
    // stable, and one comparison for all three keeps them visibly alike.
    [Errno::NOENT, Errno::NOTDIR, Errno::LOOP]
        .iter()
        .any(|errno| e.raw_os_error() == Some(errno.raw_os_error()))
}

/// The mode bits out of a `stat` result.
fn mode_of(meta: &std::fs::Metadata) -> Mode {
    use std::os::unix::fs::PermissionsExt as _;

    Mode::from_bits(meta.permissions().mode())
}

/// The destination's parent, and the mode it has or would be created at.
///
/// Stat'd with `metadata`, which **follows symlinks** — deliberately the
/// opposite of the `symlink_metadata` [`observe`] uses for the destination
/// itself. The asymmetry is the policy rather than an oversight, and each half
/// follows from what bx does at that component:
///
/// * a symlink at the **final** component is refused, so the link itself is
///   what bx is deciding about and its own bits are the ones to report;
/// * a symlink at a **parent** component is written *through* — decision 2 —
///   so the directory that actually governs the write is the one the link
///   resolves to.
///
/// A symlink's own mode is always `0777` on Linux, so stat'ing the parent
/// without following would report a correctly hardened `~/.ssh` reached through
/// a dotfiles symlink as world-writable, and report it identically to a
/// genuinely world-writable one.
fn observe_parent(dir: &Path) -> Result<Parent, Error> {
    let state = parent_state(dir)?;
    // Resolved only for a parent that is itself a link to a directory. The
    // verdict never depends on it — `state` is already settled — so a
    // `realpath` that races and fails costs the report its far-end name and
    // nothing else.
    let resolved = match state {
        ParentState::Present(_)
            if std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink()) =>
        {
            std::fs::canonicalize(dir).ok()
        }
        _ => None,
    };
    Ok(Parent {
        path: dir.to_path_buf(),
        state,
        resolved,
    })
}

/// Resolve `dir`, separating "nothing is there" from "something is there that
/// does not resolve to a directory".
///
/// The separation is the point. `metadata` reports `ENOENT` for both a path
/// with nothing on it and a path that ends at a dangling symlink, and a
/// directory bx can create from one it cannot are not the same announcement.
fn parent_state(dir: &Path) -> Result<ParentState, Error> {
    // Both guards below are pinned in both directions at the granularity
    // `cargo mutants` works at: forcing the `NotFound` comparison either way
    // fails a test, and replacing `unresolvable_path`'s body with `true` or
    // with `false` fails a test too — re-measured at r4 round 2, correcting an
    // r4 round 1 note that called the second one equivalent.
    //
    // What is not distinguished is the *first* `unresolvable_path` call site
    // alone, forced true. `cargo mutants` does not generate a per-call-site
    // mutation, so it is not a survivor it reports; it is recorded here because
    // it is real. It would matter only for a `symlink_metadata` failure that is
    // neither "nothing is there" nor a resolution refusal — a permission lost
    // between the `metadata` above and it, microseconds apart. That is the
    // class the module documentation explains is not constructed.
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => return Ok(ParentState::Present(mode_of(&meta))),
        Ok(_) => {
            return Ok(ParentState::Unusable(format!(
                "{} is not a directory, so bx cannot write a file inside it",
                dir.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            // The kernel refused to resolve the path — a symlink loop, most
            // often. If the component is readable as a link then the defect is
            // bx's to report. If it is not, the refusal may come from a
            // component further up, which the walk below finds; anything else
            // is a genuine read error.
            match std::fs::symlink_metadata(dir) {
                Ok(_) => {
                    return Ok(ParentState::Unusable(format!(
                        "{} does not resolve to a directory ({source}), so bx cannot write a file inside it",
                        dir.display()
                    )));
                }
                Err(e) if unresolvable_path(&e) => {}
                Err(_) => {
                    return Err(Error::Read {
                        path: dir.to_path_buf(),
                        source,
                    });
                }
            }
        }
    }

    // Nothing resolves at `dir`. That is ordinarily a directory bx will create,
    // but it is also what a dangling symlink, a symlink loop or a non-directory
    // anywhere along the path reports, and `mkdir` cannot create a directory
    // through any of them. The deepest component that is present at all
    // settles which it is. `ENOTDIR` and `ELOOP` on a component mean the
    // obstruction is further up, so the walk continues past them exactly as it
    // does past `ENOENT`.
    for ancestor in dir.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Err(e) if unresolvable_path(&e) => {}
            // Reachable only through a race, so no test constructs it — the
            // class the module documentation explains. Every
            // ancestor is a prefix that resolving `dir` above already walked,
            // and `lstat` does not follow its last component: a refusal here —
            // a permission denied, most often — means the permissions changed
            // between that resolution and this call. It stays a read error
            // rather than joining the arm above, which would report a directory
            // bx cannot see as absent and announce a `Create` it cannot make.
            Err(source) => {
                return Err(Error::Read {
                    path: ancestor.to_path_buf(),
                    source,
                });
            }
            Ok(_) => {
                let resolves_to_a_directory =
                    std::fs::metadata(ancestor).is_ok_and(|meta| meta.is_dir());
                return if resolves_to_a_directory {
                    Ok(ParentState::Absent(Mode::DEFAULT_DIR))
                } else {
                    Ok(ParentState::Unusable(format!(
                        "{} does not resolve to a directory, so bx cannot create {} inside it",
                        ancestor.display(),
                        dir.display(),
                    )))
                };
            }
        }
    }
    Ok(ParentState::Absent(Mode::DEFAULT_DIR))
}

/// Create every missing component of `dir`, each at the mode a directory target
/// in this apply declares for it, or at [`Mode::DEFAULT_DIR`] when none does.
///
/// There is no separate mode for the leaf. [`act_on_dir`] declares its own path
/// at the mode it is applying before it calls this, so `created.declared(dir)`
/// already *is* the leaf mode; a second way to say it would be a second thing
/// to keep in agreement.
///
/// Returns what it created and how, **deepest first**, which is the order a
/// reversal removes them in.
fn create_missing_dirs(dir: &Path, created: &CreatedDirs) -> Result<Vec<(PathBuf, Made)>, Error> {
    // `ancestors` yields deepest first, so the collected prefix is already in
    // removal order; reversing it gives shallowest-first creation order.
    let missing: Vec<PathBuf> = dir
        .ancestors()
        // `ancestors` on a *relative* path ends with `""`, which names the
        // working directory. `symlink_metadata("")` reports `ENOENT` for it, so
        // without this it enters `missing` and `mkdir("")` fails naming the
        // empty path — an error message with no path in it, from a call that
        // had nothing to create. The working directory is always there and is
        // never bx's to invent.
        .filter(|path| !path.as_os_str().is_empty())
        .take_while(|path| matches!(optional_metadata(path), Ok(None)))
        .map(Path::to_path_buf)
        .collect();

    // Only what bx actually created goes in the list. A directory that appeared
    // between the stat and the `mkdir` is somebody else's, and a reversal that
    // removed it would be deleting a directory another tool made — Invariant 1,
    // with no way to notice afterwards, because the wrong list is durable on
    // disk by the time `bx rm` reads it.
    let modes: Vec<(&PathBuf, Mode)> = missing
        .iter()
        .rev()
        .map(|path| (path, created.declared(path).unwrap_or(Mode::DEFAULT_DIR)))
        .collect();
    let mut made_here = Vec::with_capacity(missing.len());
    for (path, mode) in modes {
        if let Some(made) = create_dir_at(path, mode)? {
            made_here.push((path.clone(), made));
        }
    }
    // The walk above is shallowest first; a reversal wants deepest first.
    made_here.reverse();
    Ok(made_here)
}

/// `mkdir` one directory at exactly `mode`.
///
/// The mode is passed to `mkdir(2)` itself and then `chmod`'d, and both steps
/// are load-bearing in opposite directions. `mkdir`'s argument is masked by the
/// `umask`, so it can only ever produce something *narrower* than `mode` —
/// which is what keeps the directory from existing, even for an instant, at
/// bits wider than the ones declared for it. The `chmod` afterwards is not
/// masked, so it is what makes the declared mode authoritative.
///
/// `std::fs::create_dir` cannot do the first half: it issues
/// `mkdir(path, 0o777)` unconditionally, so under a default `umask` the
/// directory exists at `0755` until the `chmod` lands. The exposure is not the
/// contents — the directory is empty — it is the **descriptor**: a process that
/// opens it inside that window holds a handle whose access checks have already
/// passed, and the later `chmod` does not revoke it.
///
/// Returns the mode and the device and inode of the directory it made, or
/// `None` when something was already at `path`.
///
/// The `mkdir` arm itself is pinned. The `set_mode` and `symlink_metadata`
/// arms after a successful `mkdir` are not, and are of the class the module
/// documentation explains is not constructed: reaching either needs the
/// directory bx has just made to be removed or made inaccessible in the
/// microseconds before the next syscall on it.
fn create_dir_at(path: &Path, mode: Mode) -> Result<Option<Made>, Error> {
    use std::os::unix::fs::MetadataExt as _;

    match rustix::fs::mkdir(path, mode.into()) {
        Ok(()) => {}
        // Somebody else created it between the stat and the mkdir. It is not
        // bx's directory then, so its mode is not bx's to set — and it is not
        // bx's to record as one it invented, because a reversal removes those.
        Err(Errno::EXIST) => return Ok(None),
        Err(source) => {
            return Err(Error::Write {
                path: path.to_path_buf(),
                source: source.into(),
            });
        }
    }
    // `mkdir`'s mode argument is masked by the umask; `chmod` is not. The
    // read-back also says which directory this is, so a later call can tell it
    // from another one put at the same path after it.
    let meta = set_dir_mode(path, mode)?;
    Ok(Some(Made {
        mode,
        dev: meta.dev(),
        ino: meta.ino(),
    }))
}

/// [`set_mode`] on a directory, then the directory read back, refusing when a
/// declared setuid, setgid or sticky bit is not on it.
///
/// `chmod(2)` succeeds when the kernel silently clears `S_ISGID` — see
/// [`Error::DirectorySetIdNotKept`] — so what stuck is read rather than
/// assumed, exactly as [`Staged::fill`] reads a file's back. Returns the
/// metadata it read.
///
/// # Errors
///
/// Whatever [`set_mode`] returns, [`Error::Read`] when the directory cannot be
/// stat'd, and [`Error::DirectorySetIdNotKept`] when a declared special bit is
/// missing.
fn set_dir_mode(path: &Path, mode: Mode) -> Result<std::fs::Metadata, Error> {
    set_mode(path, mode)?;
    let meta = std::fs::symlink_metadata(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    refuse_dir_set_id_dropped(path, mode, &meta)?;
    Ok(meta)
}

/// Refuse when a declared setuid, setgid or sticky bit is missing from the
/// directory `meta` describes, after a `chmod` to `mode` that reported success.
///
/// Apart from [`set_dir_mode`] so that the refusal is constructible from a
/// metadata alone. Making the kernel actually drop a bit needs a directory in a
/// group the process is not in, which only a user namespace arranges; what
/// every caller depends on is this answer, and it does not need the kernel to
/// produce it.
///
/// # Errors
///
/// [`Error::DirectorySetIdNotKept`], naming what the `chmod` left.
fn refuse_dir_set_id_dropped(
    path: &Path,
    mode: Mode,
    meta: &std::fs::Metadata,
) -> Result<(), Error> {
    let landed = mode_of(meta);
    let declared = mode.bits() & SPECIAL;
    if landed.bits() & declared == declared {
        return Ok(());
    }
    Err(Error::DirectorySetIdNotKept {
        path: path.to_path_buf(),
        declared: mode,
        landed,
        chmod_left: Some(landed),
        set_back: None,
    })
}

/// Refuse to `chmod` the existing directory at `path`, which `plan` found at
/// `found`, to `declared` unless the setgid bit is confirmed to survive it: the
/// directory has `S_ISGID` or `declared` adds it, and nothing confirms that a
/// `chmod` by this process keeps it — see [`keeps_setgid`].
///
/// A `chmod` by a process the kernel does not exempt clears `S_ISGID` whatever
/// mode it asks for, so a bit declared would not stick, and a bit the directory
/// had would be lost for good: setting it back is another `chmod` by the same
/// process. Refused before any `chmod`, nothing changes.
///
/// # Errors
///
/// [`Error::DirectorySetIdNotKept`] with no `chmod_left`, naming the mode
/// the directory has, and [`Error::Read`] when it cannot be stat'd.
fn refuse_setgid_a_chmod_strips(path: &Path, found: Mode, declared: Mode) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt as _;

    if (found.bits() | declared.bits()) & SETGID == 0 {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let keeps = process_keeps_setgid(meta.uid(), meta.gid());
    refuse_unless_setgid_survives(path, declared, &meta, keeps)
}

/// The refusal itself: pass when `keeps` names a confirmation, refuse when it
/// is `None`.
///
/// The confirmation is an argument rather than something this function reads,
/// so that both answers are constructible on any host. The `None` answer is the
/// one that matters and the one a real filesystem cannot produce here: it needs
/// a directory in a group the process is not in, which only a user namespace
/// arranges.
///
/// # Errors
///
/// [`Error::DirectorySetIdNotKept`] with no `chmod_left`: nothing was changed.
fn refuse_unless_setgid_survives(
    path: &Path,
    declared: Mode,
    meta: &std::fs::Metadata,
    keeps: Option<KeepsSetgid>,
) -> Result<(), Error> {
    if keeps.is_some() {
        return Ok(());
    }
    Err(Error::DirectorySetIdNotKept {
        path: path.to_path_buf(),
        declared,
        landed: mode_of(meta),
        chmod_left: None,
        set_back: None,
    })
}

/// Why a `chmod` by this process is known to keep a directory's setgid bit.
///
/// There is no variant for "probably" and none for a uid. The preflight passes
/// only on a confirmation named here, so a setup nobody anticipated is refused
/// rather than waved through: refusing costs a plan line, and guessing wrong
/// costs a setgid bit that no second `chmod` by the same process can put back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepsSetgid {
    /// This process holds `CAP_FSETID` in its effective set.
    Capability,
    /// The directory's group is this process's effective group or one of its
    /// supplementary groups, and it is a group the kernel resolved into this
    /// process's user namespace.
    Group,
}

/// Whether a `chmod` by this process keeps the setgid bit of a directory that
/// `stat`s as owner `uid` and group `gid` — [`keeps_setgid`] against this
/// process's own capabilities, effective gid, supplementary groups and this
/// namespace's overflow ids.
fn process_keeps_setgid(uid: u32, gid: u32) -> Option<KeepsSetgid> {
    // The test build can force either answer on this thread, because the
    // `None` one needs a user namespace most hosts do not offer.
    #[cfg(test)]
    if let Some(forced) = forced::confirmation() {
        return forced;
    }
    // A process whose groups cannot be read is taken to be in none of them:
    // the refusal that follows changes nothing, where a wrong guess the
    // other way would strip a bit.
    let groups: Vec<u32> = rustix::process::getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .collect();
    keeps_setgid(
        uid,
        gid,
        has_cap_fsetid(),
        rustix::process::getegid().as_raw(),
        &groups,
        overflow_ids(),
    )
}

/// Whether the kernel keeps a directory's setgid bit through a `chmod` by a
/// process holding `cap_fsetid`, with effective gid `egid` and supplementary
/// groups `groups`, when the directory `stat`s as owner `uid` and group `gid`
/// and this user namespace's overflow ids are `overflow`.
///
/// # The rule the kernel applies
///
/// `chmod_common` keeps `S_ISGID` when either holds:
///
/// ```text
/// in_group_p(i_gid) || capable_wrt_inode_uidgid(inode, CAP_FSETID)
/// ```
///
/// and `capable_wrt_inode_uidgid` is `ns_capable(CAP_FSETID)` **and**
/// `kuid_has_mapping(ns, i_uid)` **and** `kgid_has_mapping(ns, i_gid)`. So the
/// capability does **not** outrank an unmapped id: it is the *weaker* of the
/// two paths, because it carries two mapping requirements the group path does
/// not. An id the namespace does not map is what makes `stat` report the
/// overflow uid or gid, which is how this function sees it.
///
/// # Why the order is not a choice here
///
/// An earlier version tested the capability first and returned on it, so a
/// process holding `CAP_FSETID` was confirmed for a directory whose group was
/// unmapped — and the kernel stripped the bit anyway. That was a claim about a
/// shape ("fail closed") whose *sequence* was load-bearing and only written
/// down in prose.
///
/// It is now carried by the types instead. [`MappedGid`] has one constructor,
/// which refuses the overflow gid, and **every** confirmation below takes one:
/// [`in_group`] because `in_group_p` compares against that gid, and
/// [`inode_capability`] because `kgid_has_mapping` must hold for it. An arm
/// added later that skipped the mapping test would have nothing to take and
/// would not compile.
///
/// `None` means refuse. There is no variant for "probably" and none for a uid.
fn keeps_setgid(
    uid: u32,
    gid: u32,
    cap_fsetid: bool,
    egid: u32,
    groups: &[u32],
    overflow: Overflow,
) -> Option<KeepsSetgid> {
    // Nothing below this line can be reached without it, and that is the point:
    // both paths the kernel offers are judged against this gid.
    let gid = MappedGid::of(gid, overflow)?;
    if inode_capability(uid, gid, cap_fsetid, overflow).is_some() {
        return Some(KeepsSetgid::Capability);
    }
    in_group(gid, egid, groups).then_some(KeepsSetgid::Group)
}

/// The overflow ids of a user namespace: what `stat` reports for an owner or a
/// group it does not map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Overflow {
    uid: u32,
    gid: u32,
}

/// A directory's group, as a gid this user namespace actually maps.
///
/// The one constructor refuses the overflow gid, and every arm of
/// [`keeps_setgid`] takes one, so no arm can compare a gid the kernel would not
/// compare. `stat` reports the overflow gid precisely when the mapping the
/// kernel needs is absent, so this is that mapping, as far as a `stat` can see
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappedGid(u32);

impl MappedGid {
    /// The group, or `None` when this namespace does not map it.
    const fn of(gid: u32, overflow: Overflow) -> Option<Self> {
        if gid == overflow.gid {
            return None;
        }
        Some(Self(gid))
    }
}

/// Whether this process is in the group `gid` — the kernel's `in_group_p`.
///
/// Takes a [`MappedGid`]: an unmapped group reads as the overflow gid, and
/// matching *that* against this process's own gids answers a different question
/// from the one `chmod(2)` asks. Two distinct unmapped groups read alike.
const fn in_group(gid: MappedGid, egid: u32, groups: &[u32]) -> bool {
    if egid == gid.0 {
        return true;
    }
    let mut i = 0;
    while i < groups.len() {
        if groups[i] == gid.0 {
            return true;
        }
        i += 1;
    }
    false
}

/// Evidence that `CAP_FSETID` applies to *this* inode — the kernel's
/// `capable_wrt_inode_uidgid`.
///
/// Needs the capability in the effective set **and** both of the inode's ids
/// mapped. The gid is already a [`MappedGid`], so only the owner is checked
/// here; an unmapped owner reads as the overflow uid.
const fn inode_capability(
    uid: u32,
    _gid: MappedGid,
    cap_fsetid: bool,
    overflow: Overflow,
) -> Option<InodeCapability> {
    if cap_fsetid && uid != overflow.uid {
        return Some(InodeCapability);
    }
    None
}

/// `CAP_FSETID`, established against one inode. Constructible only by
/// [`inode_capability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InodeCapability;

/// `CAP_FSETID`, capability 4 in `linux/capability.h`.
const CAP_FSETID: u32 = 4;

/// Whether this process holds `CAP_FSETID` in its effective capability set.
///
/// Read from `/proc/self/status`, which is the whole interface: bx forbids
/// `unsafe`, so `capget(2)` is not reachable without a dependency that adds
/// one, and bx is Linux-only, so `/proc` is the native answer rather than a
/// portability compromise.
///
/// A set that cannot be read or parsed confirms nothing and is `false`. The
/// caller then refuses, which changes nothing; the other guess strips a bit.
/// The whole judgement is [`cap_fsetid_in`], which takes the text, so the only
/// part no test reaches is the `read_to_string` itself.
fn has_cap_fsetid() -> bool {
    cap_fsetid_in(std::fs::read_to_string("/proc/self/status").ok().as_deref())
}

/// Whether `CAP_FSETID` is set in the `CapEff` mask of `status`, the text of
/// `/proc/self/status`.
///
/// `None` — the file could not be read — and text with no usable `CapEff` line
/// both confirm nothing, and so are `false`.
fn cap_fsetid_in(status: Option<&str>) -> bool {
    status
        .and_then(cap_eff)
        .is_some_and(|effective| effective & (1 << CAP_FSETID) != 0)
}

/// The effective capability mask on a `/proc/<pid>/status` `CapEff:` line.
///
/// `None` when the line is absent or is not the hex mask the kernel writes.
fn cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// The ids `stat` reports for an owner or a group with no mapping in this
/// process's user namespace, from `/proc/sys/kernel/overflowuid` and
/// `overflowgid`.
///
/// The kernel's own compiled-in defaults when they cannot be read: assuming
/// anything else is what would let an unmapped id through the comparisons
/// [`keeps_setgid`] makes. The reads are one line each; the judgement is
/// [`overflow_in`], which takes the text.
fn overflow_ids() -> Overflow {
    let read = |name: &str| std::fs::read_to_string(name).ok();
    Overflow {
        uid: overflow_in(read("/proc/sys/kernel/overflowuid").as_deref()),
        gid: overflow_in(read("/proc/sys/kernel/overflowgid").as_deref()),
    }
}

/// The overflow id in `text`, or the kernel's `DEFAULT_OVERFLOWUID` /
/// `DEFAULT_OVERFLOWGID` — both `65534` — when there is none to read.
fn overflow_in(text: Option<&str>) -> u32 {
    /// The kernel's `DEFAULT_OVERFLOWUID` and `DEFAULT_OVERFLOWGID`.
    const DEFAULT: u32 = 65534;

    text.and_then(|t| t.trim().parse().ok()).unwrap_or(DEFAULT)
}

/// A forced answer for [`process_keeps_setgid`], per thread, in the test build
/// only.
///
/// The refusal a foreign group causes is the whole point of the preflight, and
/// a foreign group needs unprivileged user namespaces and subordinate ids to
/// arrange. Forcing the answer constructs the refusal on every path that asks
/// for it, on any host. `cfg(test)`, not a feature gate: no configuration of
/// the binary differs from another, and the product build has no branch here.
#[cfg(test)]
mod forced {
    use std::cell::Cell;

    use super::KeepsSetgid;

    thread_local! {
        static ANSWER: Cell<Option<Option<KeepsSetgid>>> = const { Cell::new(None) };
    }

    /// The answer forced on this thread, if any.
    pub(super) fn confirmation() -> Option<Option<KeepsSetgid>> {
        ANSWER.get()
    }

    /// Run `f` with every [`super::process_keeps_setgid`] call on this thread
    /// answering `answer`. Cleared on unwind too.
    pub(super) fn answering<R>(answer: Option<KeepsSetgid>, f: impl FnOnce() -> R) -> R {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                ANSWER.set(None);
            }
        }
        ANSWER.set(Some(answer));
        let _clear = Clear;
        f()
    }
}

/// Set a directory whose `Modify` was `refused` back to `prior`, the mode
/// `plan` saw, so a refused `Modify` leaves no change that nothing records —
/// and read it back, so a [`Error::DirectorySetIdNotKept`] names the mode on
/// the directory now and whether the set-back restored `prior`. Any other
/// refusal is returned as it is.
///
/// A failing set-back is logged at warn; the read-back still names what is
/// there. When the directory cannot be stat'd, what is there is unknown, and
/// the refusal becomes [`Error::Read`].
fn set_back(path: &Path, prior: Mode, refused: Error) -> Error {
    if let Err(undo) = set_mode(path, prior) {
        tracing::warn!(
            path = %path.display(),
            %prior,
            error = %undo,
            "could not set a refused directory back to its prior mode"
        );
    }
    let Error::DirectorySetIdNotKept {
        path: named,
        declared,
        chmod_left,
        ..
    } = refused
    else {
        return refused;
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Error::DirectorySetIdNotKept {
            path: named,
            declared,
            landed: mode_of(&meta),
            chmod_left,
            set_back: Some(prior),
        },
        Err(source) => Error::Read {
            path: path.to_path_buf(),
            source,
        },
    }
}

/// The setuid and setgid bits.
///
/// The only mode bits a write can take away. The kernel clears S_ISUID, and
/// S_ISGID when group execute is set, on the first write to a file by a process
/// without `CAP_FSETID`, so a set-id mode applied before the content is gone
/// once the content lands. [`stage`] leaves them off the empty file and
/// [`Staged::fill`] adds them after the content and before the `fsync`, which
/// keeps both promises: never wider than the declared mode while empty, and
/// exactly the declared mode by the time anything can see the content.
const SET_ID: u32 = 0o6000;

/// The setgid bit: the one special bit the kernel strips from a directory on a
/// `chmod` by a process outside its group — see [`keeps_setgid`].
const SETGID: u32 = 0o2000;

/// The setuid, setgid and sticky bits: the ones a filesystem may not store.
///
/// [`Staged::fill`] reads them back after the content whenever a mode declares
/// any of them — see [`Error::SetIdNotKept`].
const SPECIAL: u32 = 0o7000;

/// `mode` without its setuid and setgid bits — see [`SET_ID`].
const fn without_set_id(mode: Mode) -> Mode {
    Mode::from_bits(mode.bits() & !SET_ID)
}

/// `fchmod`, so the mode is the declared one and not the declared one masked by
/// the process `umask`.
fn fchmod(file: &std::fs::File, mode: Mode, path: &Path) -> Result<(), Error> {
    rustix::fs::fchmod(file, mode.into()).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source: source.into(),
    })
}

/// Refuse unless every setuid, setgid or sticky bit `mode` declares is on
/// `file`.
///
/// Called after the content, because the `fchmod` that adds a set-id bit does
/// not fail when it does not stick — see [`Error::SetIdNotKept`]. `dest` is the
/// destination the refusal names; the temporary file is what is inspected.
///
/// # Errors
///
/// [`Error::SetIdNotKept`] when a declared special bit is missing, and
/// [`Error::Read`] when `file` cannot be stat'd.
fn verify_set_id_kept(file: &std::fs::File, mode: Mode, dest: &Path) -> Result<(), Error> {
    let meta = file.metadata().map_err(|source| Error::Read {
        path: dest.to_path_buf(),
        source,
    })?;
    let landed = mode_of(&meta);
    let declared = mode.bits() & SPECIAL;
    if landed.bits() & declared == declared {
        return Ok(());
    }
    Err(Error::SetIdNotKept {
        path: dest.to_path_buf(),
        declared: mode,
        landed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::Mutex;

    use crate::state::{ExclusiveLock, Ledger, LedgerView, Prior, StateDir};
    use crate::testing::{GuardedHome, guarded_home};

    /// Serialises the one test that mutates the process `umask`.
    ///
    /// Held in addition to whatever lock the home guard takes, so the
    /// serialisation does not depend on the guard continuing to take one.
    /// Nothing else in the suite depends on the `umask` anyway — every write
    /// `fchmod`s and every directory bx creates is `chmod`'d — so a leak could
    /// not flip another assertion even without this.
    static UMASK: Mutex<()> = Mutex::new(());

    /// Serialises the one test that mutates the process working directory.
    ///
    /// Every other test in the suite addresses its files absolutely, so a leak
    /// could not flip another assertion; the lock is here so the two relative
    /// writes cannot race each other or a future third.
    static CWD: Mutex<()> = Mutex::new(());

    /// The mode on disk, following no symlink.
    fn mode_of_path(path: &Path) -> Mode {
        mode_of(&std::fs::symlink_metadata(path).expect("stat"))
    }

    /// Every name in a directory, sorted, so an orphan is visible.
    fn names_in(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        names.sort();
        names
    }

    /// A file seeded at an exact mode, the umask notwithstanding.
    fn seed(path: &Path, bytes: &[u8], mode: Mode) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("seed parent");
        }
        std::fs::write(path, bytes).expect("seed");
        set_mode(path, mode).expect("seed mode");
    }

    /// What bx wants, for the comparison tests.
    fn desired(bytes: &[u8], mode: Mode) -> Desired<'_> {
        Desired { bytes, mode }
    }

    /// `plan`'s observation, then `stage` on it, with nothing changing in
    /// between.
    #[test]
    fn a_list_of_names_reads_as_english_at_every_length() {
        // Directly, at every length, because both messages that use it pass a
        // list whose length is bounded by what their caller asks for today —
        // one name, as it happens — and the branch that joins two or more was
        // therefore reachable from neither of them.
        assert_eq!(and_list(&[]), "");
        assert_eq!(and_list(&["read"]), "read");
        assert_eq!(and_list(&["read", "write"]), "read and write");
        assert_eq!(
            and_list(&["read", "write", "search"]),
            "read, write and search",
        );

        // Through the two messages, so the wording each wraps it in is pinned
        // with it.
        assert!(
            owner_locked_out(Mode::from_bits(0o000), Mode::from_bits(0o600))
                .contains("denies its owner read and write (0600)"),
            "{}",
            owner_locked_out(Mode::from_bits(0o000), Mode::from_bits(0o600)),
        );
        assert!(
            owner_locked_out(Mode::from_bits(0o200), Mode::from_bits(0o400))
                .contains("denies its owner read (0400)"),
        );
        let three = bits_that_did_not_stick(
            Mode::from_bits(0o7755),
            Mode::from_bits(0o0755),
            "directory",
        );
        assert!(
            three.contains("the setuid, setgid and sticky bits did not stick"),
            "{three}",
        );
        let one = bits_that_did_not_stick(
            Mode::from_bits(0o1755),
            Mode::from_bits(0o0755),
            "directory",
        );
        assert!(one.contains("the sticky bit did not stick"), "{one}");
    }

    fn stage_now(dest: &Path, mode: Mode) -> Result<Staged, Error> {
        let planned = observe(dest)?;
        stage(dest, mode, &planned, &mut CreatedDirs::new())
    }

    /// The outcome for a destination under a guarded home.
    fn outcome_for(home: &GuardedHome, rel: &str, bytes: &[u8], mode: Mode) -> Outcome {
        let path = home.child(rel);
        let observed = observe(&path).expect("observe");
        compare(&observed, &desired(bytes, mode), home.path())
    }

    #[test]
    fn an_absent_destination_is_a_create() {
        let home = guarded_home();
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Create);
        assert!(outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
    }

    #[test]
    fn identical_content_and_mode_is_unchanged() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Unchanged);
        assert!(!outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
        assert!(!outcome.action.is_pending(), "a second plan must be empty");
    }

    #[test]
    fn identical_content_with_the_wrong_mode_is_a_modify() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"x", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Modify);
        assert!(
            !outcome.content_drift,
            "the bytes match; only the mode drifted",
        );
        assert_eq!(
            outcome.mode_drift,
            Some((Mode::DEFAULT_FILE, Mode::PRIVATE_FILE)),
        );
    }

    #[test]
    fn the_ssh_config_mode_drift_renders_the_operator_s_line() {
        let home = guarded_home();
        // The worked example: a config faithfully reproduced at 0644 that ssh
        // will not accept, declared 0600.
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Modify);
        assert_eq!(outcome.note.as_deref(), Some("mode 0644 -> 0600"));
        assert_eq!(outcome.action.symbol(), '~');
    }

    #[test]
    fn changed_content_with_a_matching_mode_is_a_modify() {
        let home = guarded_home();
        seed(&home.child("f"), b"old", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"new", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Modify);
        assert!(outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
    }

    #[test]
    fn a_directory_where_a_file_is_declared_is_a_conflict() {
        let home = guarded_home();
        std::fs::create_dir(home.child("f")).expect("occupy");
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert!(outcome.action.needs_attention());
        assert!(
            outcome
                .note
                .as_deref()
                .is_some_and(|n| n.contains("directory")),
            "{:?}",
            outcome.note,
        );
    }

    #[test]
    fn a_device_node_where_a_file_is_declared_is_a_conflict() {
        let home = guarded_home();
        let path = home.child("f");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            Mode::PRIVATE_FILE.into(),
            0,
        )
        .expect("mkfifo");
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert_eq!(outcome.note.as_deref(), Some("not a regular file"));
    }

    #[test]
    fn stage_refuses_a_directory_or_fifo_destination_as_not_a_file() {
        // The apply half of the two conflicts above: `stage` refuses plan's
        // verdict with the kind that is there, and touches nothing.
        let home = guarded_home();
        let dir = home.child("d");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join("inside"), b"theirs").expect("an entry of their own");
        let fifo = home.child("p");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            Mode::PRIVATE_FILE.into(),
            0,
        )
        .expect("mkfifo");

        for (dest, kind) in [(&dir, Kind::Dir), (&fifo, Kind::Other)] {
            let err = stage_now(dest, Mode::DEFAULT_FILE).expect_err("not a file bx can write");
            let Error::NotAFile { path, kind: found } = &err else {
                panic!("{kind:?}: expected NotAFile, got {err:?}");
            };
            assert_eq!(path, dest, "{kind:?}");
            assert_eq!(*found, kind);
            assert_eq!(err.path(), dest.as_path(), "{kind:?}");
        }

        assert_eq!(
            names_in(home.path()),
            vec![OsString::from("d"), OsString::from("p")],
            "nothing written and no temporary file left",
        );
        assert_eq!(names_in(&dir), vec![OsString::from("inside")]);
        assert_eq!(std::fs::read(dir.join("inside")).expect("read"), b"theirs");
    }

    #[test]
    fn a_parent_that_does_not_resolve_governs_no_mode() {
        // `compare` returns before asking an unusable parent for a mode, but
        // `Parent` is public with public fields, so any caller can ask.
        let parent = |state: ParentState| Parent {
            path: PathBuf::from("/nowhere/d"),
            state,
            resolved: None,
        };
        assert_eq!(
            parent(ParentState::Unusable("a dangling symlink".into())).mode(),
            None,
            "no directory, so no mode to govern anything",
        );
        assert_eq!(
            parent(ParentState::Present(Mode::PRIVATE_DIR)).mode(),
            Some(Mode::PRIVATE_DIR),
        );
        assert_eq!(
            parent(ParentState::Absent(Mode::DEFAULT_DIR)).mode(),
            Some(Mode::DEFAULT_DIR),
            "the mode bx would create it at",
        );
    }

    #[test]
    fn a_parent_wider_than_the_declared_mode_is_reported() {
        let home = guarded_home();
        // ~/.ssh at 0755 holding a 0600 config: exactly what the source
        // material produces, and exactly what ssh refuses to work with.
        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::DEFAULT_DIR).expect("chmod");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Unchanged, "the file itself is fine");
        // Exactly, so a plain directory is never reported with the symlink
        // wording, whose remedy ("chmod ... itself") names a different action
        // and shares every substring checked above it.
        assert_eq!(
            outcome.parent_note,
            Some("~/.ssh is 0755, wider than the 0600 this file declares".to_string()),
        );
    }

    #[test]
    fn a_destination_that_cannot_be_stat_ed_is_an_error_not_an_absent_file() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let dir = home.child("unsearchable");
        std::fs::create_dir(&dir).expect("mkdir");
        let dest = dir.join("f");
        seed(&dest, b"theirs\n", Mode::DEFAULT_FILE);
        // Readable but not searchable: the directory itself stats fine, and
        // `lstat` on the file inside it fails with EACCES rather than ENOENT.
        set_mode(&dir, Mode::from_bits(0o600)).expect("chmod");

        let result = observe(&dest);
        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");

        // Reported as absent, plan would announce a Create over a file bx
        // cannot read.
        let err = result.expect_err("a file bx cannot look at is not an absent one");
        let Error::Read { path, source } = &err else {
            panic!("expected a read error, got {err:?}");
        };
        assert_eq!(path, &dest);
        assert_eq!(
            err.path(),
            dest,
            "Error::path() names the file this read error is about"
        );
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&dest).expect("read"), b"theirs\n");
    }

    #[test]
    fn an_ordinary_parent_of_an_ordinary_file_is_not_reported() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".config")).expect("mkdir");
        set_mode(&home.child(".config"), Mode::DEFAULT_DIR).expect("chmod");
        seed(&home.child(".config/f"), b"x", Mode::DEFAULT_FILE);

        let outcome = outcome_for(&home, ".config/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.parent_note, None, "0755 over 0644 is not a finding");
    }

    #[test]
    fn a_parent_bx_has_yet_to_create_is_reported_before_it_exists() {
        let home = guarded_home();
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.action, Action::Create);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(note.contains("will be created at 0755"), "{note}");
    }

    #[test]
    fn a_symlinked_parent_reports_the_directory_it_resolves_to() {
        let home = guarded_home();
        // The mainstream dotfiles layout: ~/.ssh is a link into a repository,
        // and the directory at the far end is already hardened.
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::PRIVATE_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let observed = observe(&home.child(".ssh/config")).expect("observe");
        let parent = observed.parent.as_ref().expect("a parent");
        assert_eq!(
            parent.state,
            ParentState::Present(Mode::PRIVATE_DIR),
            "the resolved directory's 0700, not the link's own 0777",
        );

        let outcome = compare(
            &observed,
            &desired(b"Host *\n", Mode::PRIVATE_FILE),
            home.path(),
        );
        assert_eq!(outcome.parent_note, None, "a hardened parent is no finding");

        // The asymmetry, stated as an assertion: the *destination* is still
        // stat'd without following, so a link there is a link.
        assert_eq!(mode_of_path(&home.child(".ssh")).bits(), 0o777);
    }

    #[test]
    fn a_symlinked_parent_that_is_genuinely_wide_is_still_reported() {
        let home = guarded_home();
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(note.contains("is 0755"), "{note}");
        assert!(note.contains("wider than the 0600"), "{note}");
    }

    #[test]
    fn a_dangling_symlink_parent_is_a_conflict_rather_than_a_create() {
        let home = guarded_home();
        // ~/.config is a link into a dotfiles repository that is not checked
        // out yet. `metadata` reports ENOENT for it exactly as it would for a
        // directory that is simply missing.
        std::os::unix::fs::symlink("nowhere", home.child(".config")).expect("symlink");

        let outcome = outcome_for(&home, ".config/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(
            outcome.action,
            Action::Conflict,
            "a create bx cannot perform is not a create",
        );
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains(".config"), "{note}");
        assert!(note.contains("does not resolve to a directory"), "{note}");
        // `metadata` says ENOENT, so the ancestor walk settles it, and its
        // words name the directory bx would have had to create through the link.
        assert!(
            note.ends_with(&format!(
                "so bx cannot create {} inside it",
                home.child(".config").display()
            )),
            "{note}",
        );
        assert_eq!(outcome.parent_note, None);

        // And `apply` refuses the same way, naming the parent rather than a
        // temporary path the user cannot interpret.
        let err = write_atomically(&home.child(".config/f"), b"x", Mode::DEFAULT_FILE)
            .expect_err("must refuse");
        let Error::UnusableParent { path, .. } = &err else {
            panic!("expected UnusableParent, got {err:?}");
        };
        assert_eq!(path, &home.child(".config"));
        assert_eq!(
            err.path(),
            home.child(".config"),
            "Error::path() names the parent, too"
        );
        assert_eq!(err.to_string(), note);
        assert!(
            std::fs::symlink_metadata(home.child("nowhere")).is_err(),
            "nothing was created at the far end",
        );
    }

    #[test]
    fn a_dangling_symlink_above_the_parent_is_a_conflict_too() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child(".config")).expect("symlink");

        // The link is two components up, so the immediate parent is absent for
        // a second reason and `mkdir` cannot reach it either.
        let outcome = outcome_for(&home, ".config/bx/init.sh", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains(".config"), "{note}");

        let err = write_atomically(&home.child(".config/bx/init.sh"), b"x", Mode::DEFAULT_FILE)
            .expect_err("must refuse");
        assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
    }

    #[test]
    fn a_symlink_loop_at_a_parent_is_a_conflict() {
        let home = guarded_home();
        std::os::unix::fs::symlink("loop", home.child("loop")).expect("symlink");

        let outcome = outcome_for(&home, "loop/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains("loop"), "{note}");
        assert!(note.contains("does not resolve to a directory"), "{note}");
        // `metadata` says ELOOP rather than ENOENT, and the link itself is
        // readable, so the refusal is settled before any walk, in its own words.
        assert!(
            note.ends_with("so bx cannot write a file inside it"),
            "{note}",
        );

        let err =
            write_atomically(&home.child("loop/f"), b"x", Mode::DEFAULT_FILE).expect_err("refuse");
        assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
    }

    #[test]
    fn a_parent_that_is_a_regular_file_is_a_conflict() {
        let home = guarded_home();
        seed(&home.child("notadir"), b"a file", Mode::DEFAULT_FILE);

        let outcome = outcome_for(&home, "notadir/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert!(
            outcome
                .note
                .as_deref()
                .is_some_and(|note| note.contains("is not a directory")),
            "{:?}",
            outcome.note,
        );

        let err = write_atomically(&home.child("notadir/f"), b"x", Mode::DEFAULT_FILE)
            .expect_err("must refuse");
        assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
        assert_eq!(
            std::fs::read(home.child("notadir")).expect("read"),
            b"a file",
            "the file that was in the way is untouched",
        );
    }

    #[test]
    fn a_private_parent_is_not_reported() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::PRIVATE_DIR).expect("chmod");
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.parent_note, None);
    }

    #[test]
    fn observe_does_not_follow_a_symlink() {
        let home = guarded_home();
        seed(&home.child("real"), b"real", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        let observed = observe(&home.child("link")).expect("observe");
        assert_eq!(observed.kind, Kind::Symlink);
        assert_eq!(observed.bytes, None, "a link has no content of its own");
    }

    #[test]
    fn the_temporary_file_is_created_in_the_destination_directory() {
        let home = guarded_home();
        let dest = home.child("f");
        let staged = stage_now(&dest, Mode::DEFAULT_FILE).expect("stage");

        assert_eq!(staged.temp_path().parent(), dest.parent());
        assert_eq!(staged.dest(), dest);
        let name = staged
            .temp_path()
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .to_string();
        assert!(name.starts_with(TEMP_PREFIX), "{name}");
        assert!(
            names_in(home.path()).contains(&OsString::from(&name)),
            "the temporary file is in the destination directory, not $TMPDIR",
        );
    }

    #[test]
    fn the_mode_is_final_before_any_content_exists() {
        let home = guarded_home();
        let staged = stage_now(&home.child("secret"), Mode::PRIVATE_FILE).expect("stage");

        // Observable on the temporary file, while it is still empty: this is
        // the property a decrypted secret depends on.
        let meta = std::fs::symlink_metadata(staged.temp_path()).expect("stat");
        assert_eq!(mode_of(&meta), Mode::PRIVATE_FILE);
        assert_eq!(meta.len(), 0, "the mode is set before any content");
        assert_eq!(staged.mode(), Mode::PRIVATE_FILE);
    }

    #[test]
    fn the_temporary_file_is_never_wider_than_its_final_mode() {
        let home = guarded_home();
        // tempfile creates at 0600 and the declared mode only narrows it, so
        // there is no instant at which the file is wider than 0600.
        let staged = stage_now(&home.child("secret"), Mode::from_bits(0o400)).expect("stage");
        assert_eq!(mode_of_path(staged.temp_path()), Mode::from_bits(0o400));
        let filled = staged.fill(b"plaintext").expect("fill");
        assert_eq!(mode_of_path(filled.temp_path()), Mode::from_bits(0o400));
        filled.publish().expect("publish");
        assert_eq!(mode_of_path(&home.child("secret")), Mode::from_bits(0o400));
    }

    #[test]
    fn a_declared_setuid_or_setgid_bit_survives_the_write_that_fills_the_file() {
        // The kernel clears S_ISUID, and S_ISGID alongside group execute, on the
        // first write to a file by a process without CAP_FSETID. A mode set
        // before the content therefore loses those bits the moment the content
        // lands: the second plan reads `Modify`, and the ledger records a mode
        // that is not on disk. Under root the bits survive either way, so this
        // cannot fail there — which is not a reason to skip it.
        for bits in [0o4755, 0o2755, 0o6755, 0o1755] {
            let home = guarded_home();
            let dest = home.child("tool");
            let mode = Mode::from_bits(bits);

            let staged = stage_now(&dest, mode).expect("stage");
            assert_eq!(
                mode_of_path(staged.temp_path()).bits() & !mode.bits(),
                0,
                "{mode}: the empty temporary file is never wider than the declared mode",
            );
            let filled = staged.fill(b"#!/bin/sh\nexit 0\n").expect("fill");
            assert_eq!(mode_of_path(filled.temp_path()), mode, "{mode}: after fill");
            assert_eq!(filled.mode(), mode);
            filled.publish().expect("publish");

            assert_eq!(mode_of_path(&dest), mode, "{mode}: on disk");
            let observed = observe(&dest).expect("observe");
            assert_eq!(
                compare(
                    &observed,
                    &desired(b"#!/bin/sh\nexit 0\n", mode),
                    home.path()
                )
                .action,
                Action::Unchanged,
                "{mode}: the second plan is empty",
            );
        }
    }

    #[test]
    fn a_set_id_bit_missing_after_its_fchmod_is_a_typed_error() {
        let home = guarded_home();
        let path = home.child("tool");
        seed(&path, b"x", Mode::from_bits(0o755));
        let file = std::fs::File::open(&path).expect("open");

        // A lost setuid bit names setuid, and does not blame group membership,
        // which only ever costs a file its setgid bit.
        let lost_setuid = verify_set_id_kept(&file, Mode::from_bits(0o4755), &path)
            .expect_err("0755 on disk is not a declared 4755")
            .to_string();
        assert!(
            lost_setuid.contains("the setuid bit did not stick"),
            "{lost_setuid}"
        );
        assert!(!lost_setuid.contains("setgid"), "{lost_setuid}");
        assert!(!lost_setuid.contains("group"), "{lost_setuid}");
        assert!(
            lost_setuid.contains("filesystem that stores no set-id or sticky bits"),
            "{lost_setuid}"
        );
        // Every bit that did not stick is named, and only those.
        let lost_both = verify_set_id_kept(&file, Mode::from_bits(0o7755), &path)
            .expect_err("0755 on disk is not a declared 7755")
            .to_string();
        assert!(
            lost_both.contains("the setuid, setgid and sticky bits did not stick"),
            "{lost_both}"
        );
        set_mode(&path, Mode::from_bits(0o1755)).expect("sticky sticks here");
        let lost_sticky = verify_set_id_kept(&file, Mode::from_bits(0o5755), &path)
            .expect_err("1755 on disk is not a declared 5755")
            .to_string();
        assert!(
            lost_sticky.contains("the setuid bit did not stick"),
            "{lost_sticky}"
        );
        assert!(
            verify_set_id_kept(&file, Mode::from_bits(0o1755), &path).is_ok(),
            "a sticky bit that stuck is no refusal",
        );
        seed(&path, b"x", Mode::from_bits(0o755));
        let lost_sticky = verify_set_id_kept(&file, Mode::from_bits(0o1755), &path)
            .expect_err("0755 on disk is not a declared 1755")
            .to_string();
        assert!(
            lost_sticky.contains("the sticky bit did not stick"),
            "{lost_sticky}"
        );

        let err = verify_set_id_kept(&file, Mode::from_bits(0o2755), &path)
            .expect_err("0755 on disk is not a declared 2755");
        let Error::SetIdNotKept {
            path: named,
            declared,
            landed,
        } = &err
        else {
            panic!("expected SetIdNotKept, got {err:?}");
        };
        assert_eq!(named, &path);
        assert_eq!(*declared, Mode::from_bits(0o2755));
        assert_eq!(*landed, Mode::from_bits(0o755));
        assert_eq!(err.path(), path);
        let message = err.to_string();
        assert!(
            message.contains("the setgid bit did not stick"),
            "{message}"
        );
        assert!(message.contains("whose group you are not in"), "{message}");
        assert!(
            message.contains("filesystem that stores no set-id or sticky bits"),
            "{message}"
        );
        assert!(message.contains("Nothing was replaced"), "{message}");

        // A bit that did stick is no refusal, and neither is a mode that
        // declares none.
        set_mode(&path, Mode::from_bits(0o2755)).expect("our own group keeps it");
        verify_set_id_kept(&file, Mode::from_bits(0o2755), &path).expect("kept");
        seed(&path, b"x", Mode::from_bits(0o755));
        verify_set_id_kept(&file, Mode::from_bits(0o755), &path).expect("none declared");
    }

    /// Set only in the unprivileged child
    /// `a_setgid_bit_the_kernel_drops_is_refused_rather_than_published` runs
    /// itself as, naming the setgid directory the child writes into.
    const SET_ID_CHILD_DIR: &str = "BX_TEST_SET_ID_CHILD_DIR";

    /// Printed by that child before anything else, so the parent can tell a
    /// child that ran and failed from one that could not be started.
    const SET_ID_CHILD_RAN: &str = "bx-set-id-child-ran";

    #[test]
    fn a_setgid_bit_the_kernel_drops_is_refused_rather_than_published() {
        const NAME: &str =
            "fs::atomic::tests::a_setgid_bit_the_kernel_drops_is_refused_rather_than_published";

        if let Some(dir) = std::env::var_os(SET_ID_CHILD_DIR) {
            // The child: uid 1, no supplementary groups, no capabilities, in a
            // setgid directory owned by a group it is not in. The file it
            // creates inherits that group, and the fchmod adding S_ISGID
            // succeeds while the kernel clears the bit.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            let dest = dir.join("tool");
            let mode = Mode::from_bits(0o2755);
            let err = stage_now(&dest, mode)
                .expect("stage")
                .fill(b"#!/bin/sh\nexit 0\n")
                .expect_err("a setgid bit the kernel dropped is not a mode bx may publish");
            let Error::SetIdNotKept {
                path,
                declared,
                landed,
            } = &err
            else {
                panic!("expected SetIdNotKept, got {err:?}");
            };
            assert_eq!(path, &dest);
            assert_eq!(*declared, mode);
            assert_eq!(landed.bits() & 0o2000, 0, "the bit really was dropped");
            assert!(!dest.exists(), "nothing was published");
            assert_eq!(
                names_in(&dir),
                Vec::<OsString>::new(),
                "no temporary file is left"
            );
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, SET_ID_CHILD_DIR, |_| {});
    }

    /// Set only in the unprivileged child
    /// `a_setgid_bit_the_kernel_drops_from_a_directory_is_refused` runs itself
    /// as, naming the setgid directory the child creates directories in.
    const SET_ID_DIR_CHILD_DIR: &str = "BX_TEST_SET_ID_DIR_CHILD_DIR";

    #[test]
    fn a_setgid_bit_the_kernel_drops_from_a_directory_is_refused() {
        const NAME: &str =
            "fs::atomic::tests::a_setgid_bit_the_kernel_drops_from_a_directory_is_refused";

        if let Some(dir) = std::env::var_os(SET_ID_DIR_CHILD_DIR) {
            // The child, as in the file test: uid 1, in a setgid directory
            // owned by a group it is not in. A directory it creates there
            // inherits that group, so the chmod adding S_ISGID succeeds while
            // the kernel clears the bit.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            let mode = Mode::from_bits(0o2775);

            // A directory target plan announces as a create.
            let team = dir.join("team");
            let planned = observe(&team).expect("observe");
            assert_eq!(compare_dir(&planned, mode).action, Action::Create);
            let err = ensure_dir(&team, mode, &planned, &mut CreatedDirs::new())
                .expect_err("create: a setgid bit the kernel dropped is not an applied mode");
            let landed = assert_directory_set_id_not_kept(&err, &team, mode);
            assert_eq!(
                mode_of_path(&team),
                landed,
                "the refusal names what is on disk"
            );
            let second = compare_dir(&observe(&team).expect("observe"), mode);
            assert_eq!(
                (second.action, second.mode_drift),
                (Action::Modify, Some((landed, mode))),
                "the second plan shows the bit that is still missing",
            );

            // A directory target plan announces as a modify: refused before
            // any chmod, because the kernel would drop the bit it adds.
            let team2 = dir.join("team2");
            std::fs::create_dir(&team2).expect("mkdir");
            set_mode(&team2, Mode::PRIVATE_DIR).expect("chmod");
            let planned = observe(&team2).expect("observe");
            assert_eq!(compare_dir(&planned, mode).action, Action::Modify);
            let err = ensure_dir(&team2, mode, &planned, &mut CreatedDirs::new())
                .expect_err("modify: a setgid bit the kernel would drop is not applied");
            let message = err.to_string();
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept {
                        path,
                        declared,
                        landed,
                        chmod_left: None,
                        set_back: None,
                    } if *path == team2 && *declared == mode && *landed == Mode::PRIVATE_DIR
                ),
                "{err:?}",
            );
            assert!(
                message.ends_with(
                    "so the directory would not keep the setgid bit it declares. bx did not \
                     chmod it, and nothing was changed"
                ),
                "{message}"
            );
            let after = observe(&team2).expect("observe");
            assert_eq!(
                (after.mode, after.stamp),
                (Some(Mode::PRIVATE_DIR), planned.stamp),
                "a refused modify leaves the directory plan saw, untouched",
            );
            let second = compare_dir(&observe(&team2).expect("observe"), mode);
            assert_eq!(
                (second.action, second.mode_drift),
                (Action::Modify, Some((Mode::PRIVATE_DIR, mode))),
                "the second plan is the first plan again",
            );

            // A declared directory a write beneath it creates.
            let crew = dir.join("crew");
            let dest = crew.join("tool");
            let mut created = CreatedDirs::new();
            created.declare(&crew, mode);
            let planned = observe(&dest).expect("observe");
            let err = stage(&dest, Mode::DEFAULT_FILE, &planned, &mut created)
                .expect_err("stage: a declared setgid bit the kernel dropped is refused");
            assert_directory_set_id_not_kept(&err, &crew, mode);
            assert_eq!(
                names_in(&crew),
                Vec::<OsString>::new(),
                "nothing is written into it"
            );
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, SET_ID_DIR_CHILD_DIR, |_| {});
    }

    /// The variable the preflight test's child finds its setgid directory in.
    const SET_ID_PREFLIGHT_CHILD_DIR: &str = "BX_TEST_SET_ID_PREFLIGHT_CHILD_DIR";

    #[test]
    fn a_setgid_bit_a_chmod_would_strip_is_refused_before_any_chmod() {
        const NAME: &str =
            "fs::atomic::tests::a_setgid_bit_a_chmod_would_strip_is_refused_before_any_chmod";

        if let Some(dir) = std::env::var_os(SET_ID_PREFLIGHT_CHILD_DIR) {
            // The child: uid 1, in a setgid directory owned by group 5, which
            // it is not in. A directory it makes there inherits group 5 and
            // S_ISGID, and any chmod it makes of that directory loses S_ISGID.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            // This child runs one test, so its umask is its own to set.
            rustix::process::umask(Mode::from_bits(0o022).into());
            let team = dir.join("team3");
            rustix::fs::mkdir(&team, Mode::DEFAULT_DIR.into()).expect("mkdir");
            let inherited = Mode::from_bits(0o2755);
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "the setgid bit is inherited"
            );

            for declared in [Mode::from_bits(0o2775), Mode::from_bits(0o775)] {
                let planned = observe(&team).expect("observe");
                let first = compare_dir(&planned, declared);
                assert_eq!(
                    (first.action, first.mode_drift),
                    (Action::Modify, Some((inherited, declared))),
                );
                let err = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
                    .expect_err("a chmod that would strip the setgid bit is refused");
                let message = err.to_string();
                assert!(
                    matches!(
                        &err,
                        Error::DirectorySetIdNotKept { path, declared: said, landed, .. }
                            if *path == team && *said == declared && *landed == inherited
                    ),
                    "{err:?}",
                );
                assert_eq!(
                    message,
                    format!(
                        "{} declares {declared} and is {inherited}: the kernel drops a \
                         directory's setgid bit on a chmod unless the process holds CAP_FSETID \
                         or is in the directory's group, and bx could confirm neither for this \
                         process, so the directory would lose the setgid bit it has. bx did not \
                         chmod it, and nothing was changed",
                        team.display()
                    ),
                );
                let after = observe(&team).expect("observe");
                assert_eq!(
                    (after.mode, after.stamp),
                    (planned.mode, planned.stamp),
                    "{declared}: nothing changed, not even a chmod and back a ctime would show",
                );
                assert_eq!(
                    compare_dir(&after, declared),
                    first,
                    "the second plan is the first"
                );
            }

            // The set-back itself, where the kernel strips the prior's bit: a
            // chmod that left 0775 is set back to the 2755 plan saw, and the
            // read-back names the 0755 that is on the directory instead.
            let left = Mode::from_bits(0o775);
            set_mode(&team, left).expect("chmod");
            let err = set_back(
                &team,
                inherited,
                not_kept(&team, Mode::from_bits(0o2775), left),
            );
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept { landed, chmod_left, set_back, .. }
                        if *landed == Mode::DEFAULT_DIR
                            && *chmod_left == Some(left)
                            && *set_back == Some(inherited)
                ),
                "{err:?}",
            );
            assert!(
                err.to_string().ends_with(
                    "bx set it back to 2755, the mode plan saw, but 0755 is on it now, so the \
                     set-back did not restore it. Nothing was recorded"
                ),
                "{err}"
            );
            assert_eq!(mode_of_path(&team), Mode::DEFAULT_DIR);
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, SET_ID_PREFLIGHT_CHILD_DIR, |_| {});
    }

    /// The variable the uid-0 child finds its setgid directory in.
    const SET_ID_ROOT_CHILD_DIR: &str = "BX_TEST_SET_ID_ROOT_CHILD_DIR";

    #[test]
    fn uid_zero_without_cap_fsetid_is_refused_like_any_other_process() {
        const NAME: &str =
            "fs::atomic::tests::uid_zero_without_cap_fsetid_is_refused_like_any_other_process";

        if let Some(dir) = std::env::var_os(SET_ID_ROOT_CHILD_DIR) {
            // The child: uid 0 in a user namespace, with an empty capability
            // bounding set, so `execve` left it no `CAP_FSETID`. The kernel
            // strips `S_ISGID` from a chmod it makes of a directory in a group
            // it is not in, exactly as it would for any other uid — and the
            // predicate that once read `euid == 0` said otherwise, passed the
            // preflight, and lost the bit for good.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            assert!(rustix::process::geteuid().is_root(), "the child is uid 0");
            let status = std::fs::read_to_string("/proc/self/status").expect("status");
            assert!(
                !has_cap_fsetid(),
                "uid 0 with no capabilities: CapEff {:?}",
                cap_eff(&status),
            );
            // This child runs one test, so its umask is its own to set.
            rustix::process::umask(Mode::from_bits(0o022).into());
            let team = dir.join("team-root");
            rustix::fs::mkdir(&team, Mode::DEFAULT_DIR.into()).expect("mkdir");
            let inherited = Mode::from_bits(0o2755);
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "a setgid parent gives it the bit and its group",
            );

            let declared = Mode::from_bits(0o2775);
            let planned = observe(&team).expect("observe");
            let err = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
                .expect_err("uid 0 is not CAP_FSETID");
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept { path, chmod_left: None, .. } if *path == team
                ),
                "{err:?}",
            );
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "the setgid bit the directory had is still on it",
            );
            return;
        }

        run_in_a_foreign_setgid_directory(
            NAME,
            SET_ID_ROOT_CHILD_DIR,
            &[
                "--reuid=0",
                "--regid=0",
                "--clear-groups",
                "--bounding-set=-all",
            ],
            |_| {},
        );
    }

    /// The variable the capability child finds its setgid directory in.
    const SET_ID_CAP_CHILD_DIR: &str = "BX_TEST_SET_ID_CAP_CHILD_DIR";

    #[test]
    fn a_capability_does_not_survive_a_group_this_namespace_does_not_map() {
        const NAME: &str = "fs::atomic::tests::\
                            a_capability_does_not_survive_a_group_this_namespace_does_not_map";

        if let Some(dir) = std::env::var_os(SET_ID_CAP_CHILD_DIR) {
            // The child: uid 0 in a user namespace that maps only the invoking
            // ids, holding a full capability set — so `CAP_FSETID` really is
            // held — in a setgid directory whose group 5 that namespace does
            // **not** map. `capable_wrt_inode_uidgid` needs the inode's uid and
            // gid mapped as well as the capability, so the kernel strips the
            // bit from a chmod this child makes, and the capability does not
            // save it.
            //
            // This is the arm nothing else exercises against a real kernel: the
            // other two harness callers drop the capability, one with
            // `--bounding-set=-all` and one with `--reuid=1`.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            assert!(rustix::process::geteuid().is_root(), "the child is uid 0");
            assert!(
                has_cap_fsetid(),
                "the child holds CAP_FSETID: CapEff {:?}",
                cap_eff(&std::fs::read_to_string("/proc/self/status").expect("status")),
            );
            let overflow = overflow_ids();
            let shared = std::fs::metadata(&dir).expect("stat");
            assert_eq!(
                shared.gid(),
                overflow.gid,
                "the shared directory's group is unmapped here, so it reads as the overflow gid",
            );

            rustix::process::umask(Mode::from_bits(0o022).into());
            let team = dir.join("team-cap");
            rustix::fs::mkdir(&team, Mode::DEFAULT_DIR.into()).expect("mkdir");
            let inherited = Mode::from_bits(0o2755);
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "a setgid parent gives it the bit and its unmapped group",
            );

            let declared = Mode::from_bits(0o2775);
            let planned = observe(&team).expect("observe");
            let err = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
                .expect_err("CAP_FSETID does not outrank an unmapped gid");
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept { path, chmod_left: None, .. } if *path == team
                ),
                "{err:?}",
            );
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "the setgid bit the directory had is still on it",
            );
            return;
        }

        run_in_a_foreign_setgid_directory_under(
            NAME,
            SET_ID_CAP_CHILD_DIR,
            // The child's namespace maps only the invoking ids, so group 5 is
            // unmapped in it. No `setpriv`: the child keeps uid 0 and the full
            // capability set the namespace gives its creator.
            &["--map-root-user"],
            &[],
            |_| {},
        );
    }

    /// The refusal `set_dir_mode` returns for `dir`, declared `declared`, when
    /// its chmod left `left`.
    fn not_kept(dir: &Path, declared: Mode, left: Mode) -> Error {
        Error::DirectorySetIdNotKept {
            path: dir.to_path_buf(),
            declared,
            landed: left,
            chmod_left: Some(left),
            set_back: None,
        }
    }

    /// The overflow ids of a namespace that maps everything below 65534.
    const OVER: Overflow = Overflow {
        uid: 65534,
        gid: 65534,
    };

    #[test]
    fn the_setgid_predicate_confirms_a_capability_or_a_mapped_group_and_nothing_else() {
        const UID: u32 = 1000;
        const GID: u32 = 5;

        // The capability is one of the two things chmod(2) tests, and it is the
        // only one that passes a process outside the directory's group.
        assert_eq!(
            keeps_setgid(UID, GID, true, 1, &[], OVER),
            Some(KeepsSetgid::Capability),
            "CAP_FSETID, held by a process in none of the groups",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, GID, &[], OVER),
            Some(KeepsSetgid::Group),
            "the effective group",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, 1, &[3, GID], OVER),
            Some(KeepsSetgid::Group),
            "a supplementary group",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, 1, &[3, 4], OVER),
            None,
            "other groups only",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, 1, &[], OVER),
            None,
            "no groups"
        );

        // uid 0 is not a parameter at all, and that is r4 round 1's repair: a
        // process that is root in a user namespace without CAP_FSETID has its
        // chmod stripped like any other, and there is no arm left for it.
        //
        // These are r4 round 2's. `capable_wrt_inode_uidgid` requires both of
        // the inode's ids to be mapped, so the capability does NOT outrank an
        // unmapped id — it is the weaker path, not the stronger one. The
        // assertion below used to read `Some(Capability)`, and the kernel
        // disagreed: see
        // `a_capability_does_not_survive_a_group_this_namespace_does_not_map`.
        assert_eq!(
            keeps_setgid(UID, OVER.gid, true, 1, &[], OVER),
            None,
            "an unmapped group defeats the capability too",
        );
        assert_eq!(
            keeps_setgid(OVER.uid, GID, true, 1, &[], OVER),
            None,
            "so does an unmapped owner",
        );
        // ...but only for the capability. The group path has no uid
        // requirement, so an unmapped owner in a group this process is in still
        // keeps the bit, and refusing there would refuse a chmod that works.
        assert_eq!(
            keeps_setgid(OVER.uid, GID, false, GID, &[], OVER),
            Some(KeepsSetgid::Group),
            "an unmapped owner does not defeat membership",
        );
        // An unmapped group reads as the overflow gid, which names no group.
        // Matching it confirms nothing, even against gids that read the same
        // way, which is how two distinct unmapped groups would otherwise look
        // like one membership.
        assert_eq!(
            keeps_setgid(UID, OVER.gid, false, OVER.gid, &[OVER.gid], OVER),
            None,
            "the overflow gid never confirms a membership",
        );
        // The overflow ids are only whatever this namespace reports: on a host
        // where they are something else, 65534 is an ordinary group again.
        assert_eq!(
            keeps_setgid(
                UID,
                65534,
                false,
                65534,
                &[],
                Overflow {
                    uid: 65533,
                    gid: 65533
                },
            ),
            Some(KeepsSetgid::Group),
        );

        // The same answers for this process, read through rustix and /proc.
        let (uid, egid) = (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        );
        let overflow = overflow_ids();
        let groups: Vec<u32> = rustix::process::getgroups()
            .expect("getgroups")
            .into_iter()
            .map(rustix::process::Gid::as_raw)
            .collect();
        if egid != overflow.gid && uid != overflow.uid {
            assert_eq!(
                process_keeps_setgid(uid, egid),
                Some(KeepsSetgid::Group),
                "this process's own group",
            );
        }
        for member in groups.iter().filter(|gid| **gid != overflow.gid) {
            assert_eq!(
                process_keeps_setgid(uid, *member),
                Some(KeepsSetgid::Group),
                "supplementary group {member}",
            );
        }
        let foreign = (1..)
            .find(|gid| *gid != egid && *gid != overflow.gid && !groups.contains(gid))
            .expect("a group this process is not in");
        assert_eq!(
            process_keeps_setgid(uid, foreign).is_some(),
            has_cap_fsetid() && uid != overflow.uid,
            "group {foreign}, which this process is not in: only the capability confirms it",
        );
        assert_eq!(
            process_keeps_setgid(uid, overflow.gid),
            None,
            "a group this namespace does not map is refused whatever this process holds",
        );
    }

    #[test]
    fn no_confirmation_can_skip_the_mapping_test() {
        // The ordering bug this repair is about was reachable because the
        // capability arm ran before the mapping test. It cannot now: both arms
        // take a `MappedGid`, and the only constructor refuses the overflow
        // gid, so there is nothing for an arm that skipped the test to be
        // handed.
        assert_eq!(MappedGid::of(OVER.gid, OVER), None);
        assert_eq!(MappedGid::of(5, OVER), Some(MappedGid(5)));
        assert_eq!(
            MappedGid::of(OVER.gid, Overflow { uid: 0, gid: 0 }),
            Some(MappedGid(OVER.gid)),
            "the overflow gid is whatever the namespace says it is",
        );

        let gid = MappedGid::of(5, OVER).expect("a mapped gid");
        assert!(in_group(gid, 5, &[]), "the effective group");
        assert!(in_group(gid, 1, &[9, 5]), "a supplementary group");
        assert!(!in_group(gid, 1, &[9]), "neither");
        assert!(!in_group(gid, 1, &[]), "no groups at all");

        // `capable_wrt_inode_uidgid`: the capability, and the owner mapped.
        assert_eq!(
            inode_capability(1000, gid, true, OVER),
            Some(InodeCapability)
        );
        assert_eq!(
            inode_capability(1000, gid, false, OVER),
            None,
            "no capability"
        );
        assert_eq!(
            inode_capability(OVER.uid, gid, true, OVER),
            None,
            "an unmapped owner",
        );
    }

    #[test]
    fn the_effective_capability_set_is_read_from_the_line_that_names_it() {
        assert_eq!(
            cap_eff("Name:\tbx\nCapInh:\t0000000000000000\nCapEff:\t0000000000000010\n"),
            Some(0x10),
        );
        assert_eq!(cap_eff("CapEff: 1ffffffffff\n"), Some(0x1ff_ffff_ffff));
        assert_eq!(cap_eff("CapEff:\t0\n"), Some(0));
        assert_eq!(
            cap_eff("CapInh:\t0000000000000010\n"),
            None,
            "a different capability set is not the effective one",
        );
        assert_eq!(cap_eff("CapEff:\tnot a mask\n"), None);
        assert_eq!(cap_eff(""), None);

        // CAP_FSETID is capability 4, so the mask above is that bit alone.
        assert_eq!(1u64 << CAP_FSETID, 0x10);
        assert!(cap_fsetid_in(Some("CapEff:\t0000000000000018\n")));
        assert!(
            !cap_fsetid_in(Some("CapEff:\t0000000000000008\n")),
            "another bit"
        );
        assert!(!cap_fsetid_in(Some("CapEff:\tnot a mask\n")), "unparsable");
        assert!(!cap_fsetid_in(Some("")), "no CapEff line");
        assert!(
            !cap_fsetid_in(None),
            "a /proc that could not be read confirms nothing, so it is not held",
        );

        // The overflow ids: the kernel's value when there is one, and the
        // kernel's own default when there is not. Both arms, without needing a
        // host that lacks /proc.
        assert_eq!(overflow_in(Some("65534\n")), 65534);
        assert_eq!(overflow_in(Some(" 60000 ")), 60000, "trimmed");
        assert_eq!(
            overflow_in(Some("nonsense")),
            65534,
            "unparsable falls back"
        );
        assert_eq!(overflow_in(Some("")), 65534, "empty falls back");
        assert_eq!(overflow_in(Some("-1")), 65534, "not a u32 falls back");
        assert_eq!(overflow_in(None), 65534, "unreadable falls back");

        // And what this host actually reports, read rather than assumed.
        let overflow = overflow_ids();
        for (name, got) in [
            ("/proc/sys/kernel/overflowuid", overflow.uid),
            ("/proc/sys/kernel/overflowgid", overflow.gid),
        ] {
            match std::fs::read_to_string(name) {
                Ok(text) => assert_eq!(got.to_string(), text.trim(), "{name}"),
                Err(_) => assert_eq!(got, 65534, "{name}"),
            }
        }
    }

    #[test]
    fn the_setgid_preflight_refuses_a_directory_whose_group_it_cannot_confirm() {
        let home = guarded_home();
        let dir = home.child("team");
        std::fs::create_dir(&dir).expect("mkdir");
        let found = Mode::from_bits(0o2755);
        set_mode(&dir, found).expect("chmod");
        let declared = Mode::from_bits(0o2775);

        // Forced rather than arranged: an unconfirmable group needs a user
        // namespace, and the preflight's answer is the same either way.
        let err = forced::answering(None, || refuse_setgid_a_chmod_strips(&dir, found, declared))
            .expect_err("an unconfirmed process may not chmod a setgid directory");
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept {
                    path,
                    declared: said,
                    landed,
                    chmod_left: None,
                    set_back: None,
                } if *path == dir && *said == declared && *landed == found
            ),
            "{err:?}",
        );
        assert_eq!(
            mode_of_path(&dir),
            found,
            "the refusal comes before any chmod",
        );
        let message = err.to_string();
        assert!(message.contains("CAP_FSETID"), "{message}");
        assert!(
            message.contains("bx did not chmod it, and nothing was changed"),
            "{message}",
        );

        // Either confirmation passes it.
        for keeps in [KeepsSetgid::Capability, KeepsSetgid::Group] {
            assert!(
                forced::answering(Some(keeps), || refuse_setgid_a_chmod_strips(
                    &dir, found, declared
                ))
                .is_ok(),
                "{keeps:?}",
            );
        }
    }

    #[test]
    fn a_directory_this_apply_created_is_refused_when_its_group_stops_being_confirmable() {
        // The adopt path: a directory this apply made at a declared setgid
        // mode, met again by its own directory target. It runs the same
        // preflight before its chmod, and nothing else constructs that call's
        // refusal.
        let home = guarded_home();
        let dir = home.child("shared");
        let declared = Mode::from_bits(0o2755);
        let planned = observe(&dir).expect("plan sees nothing");
        let mut created = CreatedDirs::new();
        let made = ensure_dir(&dir, declared, &planned, &mut created).expect("create");
        assert_eq!(made.action, Action::Create);
        assert_eq!(
            mode_of_path(&dir),
            declared,
            "the bit stuck for its creator"
        );

        let err = forced::answering(None, || ensure_dir(&dir, declared, &planned, &mut created))
            .expect_err("the adopt path refuses a chmod it cannot confirm");
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept { path, chmod_left: None, .. } if *path == dir
            ),
            "{err:?}",
        );
        assert_eq!(mode_of_path(&dir), declared, "nothing was changed");
    }

    #[test]
    fn a_declared_directory_bit_missing_after_its_chmod_is_a_typed_error() {
        // The read-back `set_dir_mode` makes, apart from the chmod: the kernel
        // drops the bit only for a process outside the directory's group, and
        // the answer every caller depends on is this one.
        let home = guarded_home();
        let dir = home.child("plain");
        std::fs::create_dir(&dir).expect("mkdir");
        let landed = Mode::DEFAULT_DIR;
        set_mode(&dir, landed).expect("chmod");
        let meta = std::fs::symlink_metadata(&dir).expect("stat");

        assert!(
            refuse_dir_set_id_dropped(&dir, landed, &meta).is_ok(),
            "no special bit declared, nothing to lose",
        );
        let declared = Mode::from_bits(0o2755);
        let err = refuse_dir_set_id_dropped(&dir, declared, &meta)
            .expect_err("a declared setgid bit that is not on the directory");
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept {
                    path,
                    declared: said,
                    landed: found,
                    chmod_left: Some(left),
                    set_back: None,
                } if *path == dir && *said == declared && *found == landed && *left == landed
            ),
            "{err:?}",
        );
        assert!(
            err.to_string().contains("the setgid bit did not stick"),
            "{err}"
        );
    }

    #[test]
    fn the_setgid_preflight_stats_only_a_setgid_directory_and_passes_its_own_group() {
        let home = guarded_home();
        let missing = home.child("missing");
        assert!(
            refuse_setgid_a_chmod_strips(&missing, Mode::DEFAULT_DIR, Mode::PRIVATE_DIR).is_ok(),
            "no setgid bit on either side: nothing to look at",
        );
        for (found, declared) in [(0o2755, 0o755), (0o755, 0o2755)] {
            let err = refuse_setgid_a_chmod_strips(
                &missing,
                Mode::from_bits(found),
                Mode::from_bits(declared),
            )
            .expect_err("a setgid bit on either side is looked at");
            assert!(
                matches!(&err, Error::Read { path, .. } if *path == missing),
                "{found:04o} -> {declared:04o}: {err:?}",
            );
        }

        // A setgid directory in this process's own group keeps the bit, so
        // its Modify is applied, and the second plan is empty.
        let team = home.child("team");
        std::fs::create_dir(&team).expect("mkdir");
        set_mode(&team, Mode::from_bits(0o2755)).expect("chmod");
        assert_eq!(mode_of_path(&team), Mode::from_bits(0o2755), "own group");
        let declared = Mode::from_bits(0o2775);
        let planned = observe(&team).expect("observe");
        let applied = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
            .expect("a member's chmod keeps the bit");
        assert_eq!(applied.action, Action::Modify);
        assert_eq!(mode_of_path(&team), declared);
        let second = observe(&team).expect("observe");
        assert_eq!(compare_dir(&second, declared).action, Action::Unchanged);
    }

    #[test]
    fn a_refused_directory_modify_is_set_back_and_worded_from_what_is_there_after() {
        let home = guarded_home();
        let dir = home.child("d");
        std::fs::create_dir(&dir).expect("mkdir");
        // As a chmod that dropped a declared sticky bit would leave it.
        set_mode(&dir, Mode::DEFAULT_DIR).expect("chmod");
        let declared = Mode::from_bits(0o1755);
        let err = set_back(
            &dir,
            Mode::PRIVATE_DIR,
            not_kept(&dir, declared, Mode::DEFAULT_DIR),
        );
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept { path, declared: said, landed, chmod_left, set_back }
                    if *path == dir
                        && *said == declared
                        && *landed == Mode::PRIVATE_DIR
                        && *chmod_left == Some(Mode::DEFAULT_DIR)
                        && *set_back == Some(Mode::PRIVATE_DIR)
            ),
            "{err:?}",
        );
        assert_eq!(
            err.to_string(),
            format!(
                "{} declares 1755, and only 0755 was on the directory after its chmod: the \
                 sticky bit did not stick. A filesystem that stores no set-id or sticky bits, \
                 such as vfat or exfat mounted with `quiet`, drops them. bx set it back to 0700, \
                 the mode plan saw, and nothing was recorded",
                dir.display()
            ),
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR, "set back");

        // Any other refusal is returned as it was, after the same set-back.
        set_mode(&dir, Mode::DEFAULT_DIR).expect("chmod");
        let other = Error::Write {
            path: dir.clone(),
            source: std::io::Error::from_raw_os_error(libc_eperm()),
        };
        let err = set_back(&dir, Mode::PRIVATE_DIR, other);
        assert!(
            matches!(&err, Error::Write { path, source } if *path == dir && source.raw_os_error() == Some(libc_eperm())),
            "{err:?}",
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR, "set back");

        // A directory that is gone cannot be read back: what is there is
        // unknown, so the refusal says that instead.
        let gone = home.child("gone");
        let err = set_back(
            &gone,
            Mode::PRIVATE_DIR,
            not_kept(&gone, declared, Mode::DEFAULT_DIR),
        );
        assert!(
            matches!(&err, Error::Read { path, .. } if *path == gone),
            "{err:?}"
        );
    }

    /// The variable the foreign-file test's child finds its directory in.
    const FOREIGN_FILE_CHILD_DIR: &str = "BX_TEST_FOREIGN_FILE_CHILD_DIR";

    #[test]
    fn a_foreign_file_s_prior_mode_without_owner_read_is_restored_as_recorded() {
        const NAME: &str = "fs::atomic::tests::\
             a_foreign_file_s_prior_mode_without_owner_read_is_restored_as_recorded";
        let theirs = b"theirs\n";
        let recorded = Mode::from_bits(0o004);

        if let Some(dir) = std::env::var_os(FOREIGN_FILE_CHILD_DIR) {
            // The child, uid 1: the file is somebody else's, at 0004, so it
            // reads the bytes through the other bits alone.
            println!("{SET_ID_CHILD_RAN}");
            let foreign = PathBuf::from(dir).join("foreign");
            let planned = observe(&foreign).expect("observe");
            assert_eq!(
                (planned.kind, planned.mode, planned.bytes.as_deref()),
                (Kind::File, Some(recorded), Some(&theirs[..])),
            );

            // apply records the prior, then replaces the file.
            let staged = stage(
                &foreign,
                Mode::DEFAULT_FILE,
                &planned,
                &mut CreatedDirs::new(),
            )
            .expect("stage");
            let prior = staged.prior().clone();
            staged.commit(b"managed\n").expect("commit");
            assert_eq!(prior.mode, Some(recorded), "the prior mode is recorded");

            // rm restores the recorded bytes at the recorded mode.
            let now = observe(&foreign).expect("observe");
            stage(&foreign, recorded, &now, &mut CreatedDirs::new())
                .expect("a recorded prior mode is staged as recorded")
                .commit(prior.bytes.as_deref().expect("prior bytes"))
                .expect("commit");
            assert_eq!(mode_of_path(&foreign), recorded, "restored exactly");
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, FOREIGN_FILE_CHILD_DIR, |dir| {
            seed(&dir.join("foreign"), theirs, recorded);
        });
    }

    #[test]
    fn a_restore_of_a_recorded_mode_without_owner_read_is_written_as_recorded() {
        let home = guarded_home();
        let dest = home.child("restored");
        seed(&dest, b"managed\n", Mode::DEFAULT_FILE);
        let recorded = Mode::from_bits(0o004);
        let now = observe(&dest).expect("observe");

        // Declared, the mode is still plan's conflict: bx could not read the
        // file back to compare it.
        assert_eq!(
            compare(&now, &desired(b"prior\n", recorded), home.path()).action,
            Action::Conflict,
        );
        // Restored, it is what was there, and stage writes it as recorded.
        stage(&dest, recorded, &now, &mut CreatedDirs::new())
            .expect("a recorded prior mode is staged as recorded")
            .commit(b"prior\n")
            .expect("commit");
        assert_eq!(mode_of_path(&dest), recorded);
        set_mode(&dest, Mode::DEFAULT_FILE).expect("unlock for the assertion");
        assert_eq!(std::fs::read(&dest).expect("read"), b"prior\n");
    }

    /// `EPERM`, the errno a refused `chmod` reports.
    fn libc_eperm() -> i32 {
        Errno::PERM.raw_os_error()
    }

    /// The refusal a directory whose declared special bit did not stick gets,
    /// naming `dir`; returns the mode it reports on disk.
    fn assert_directory_set_id_not_kept(err: &Error, dir: &Path, declared: Mode) -> Mode {
        let message = err.to_string();
        let Error::DirectorySetIdNotKept {
            path,
            declared: said,
            landed,
            chmod_left,
            set_back,
        } = err
        else {
            panic!("expected DirectorySetIdNotKept, got {err:?}");
        };
        assert_eq!(path, dir, "{message}");
        assert_eq!(*said, declared);
        assert_eq!(landed.bits() & 0o2000, 0, "the bit really was dropped");
        assert_eq!(
            (*chmod_left, *set_back),
            (Some(*landed), None),
            "a directory bx created is left as its chmod left it",
        );
        assert_eq!(err.path(), dir, "{message}");
        assert!(
            message.contains(&format!(
                "only {landed} was on the directory after its chmod"
            )),
            "{message}"
        );
        assert!(
            message.contains("a directory whose group you are not in"),
            "{message}"
        );
        assert!(
            message.ends_with(&format!(
                "Nothing was recorded, and the directory, which bx created in this apply, is \
                 left in place at {landed}"
            )),
            "{message}"
        );
        assert!(
            message.contains(&format!("declares {declared}, and only")),
            "{message}"
        );
        assert!(
            message.contains("the setgid bit did not stick"),
            "{message}"
        );
        *landed
    }

    /// Run the test `name` again as uid 1 with no supplementary groups, inside
    /// a user namespace, with `child_env` naming a world-writable setgid
    /// directory owned by a group that uid is not in.
    ///
    /// Skips, with a message on stderr, wherever the scenario cannot be
    /// constructed; fails only when the child ran and failed.
    fn run_unprivileged_in_a_foreign_setgid_directory(
        name: &str,
        child_env: &str,
        seed: impl FnOnce(&Path),
    ) {
        run_in_a_foreign_setgid_directory(
            name,
            child_env,
            &["--reuid=1", "--regid=1", "--clear-groups"],
            seed,
        );
    }

    /// Run the test `name` again under `setpriv`'s `credentials`, inside a user
    /// namespace, with `child_env` naming a world-writable setgid directory
    /// owned by a group those credentials are not in.
    ///
    /// Skips, with a message on stderr, wherever the scenario cannot be
    /// constructed; fails only when the child ran and failed.
    fn run_in_a_foreign_setgid_directory(
        name: &str,
        child_env: &str,
        credentials: &[&str],
        seed: impl FnOnce(&Path),
    ) {
        run_in_a_foreign_setgid_directory_under(
            name,
            child_env,
            &["--map-auto", "--map-root-user"],
            credentials,
            seed,
        );
    }

    /// As above, but with the namespace the **child** runs in given
    /// separately from the one the setup steps run in.
    ///
    /// They differ for one case and it is the case D1 was about. The setup
    /// needs `--map-auto` to `chown` the directory to group 5. A child run
    /// under `--map-root-user` alone is in a namespace that maps *only* the
    /// invoking ids, so group 5 has no mapping there and `stat` reports the
    /// overflow gid — while the child is uid 0 with a full capability set.
    /// That is the one combination `capable_wrt_inode_uidgid` refuses and
    /// nothing else here constructs.
    fn run_in_a_foreign_setgid_directory_under(
        name: &str,
        child_env: &str,
        child_namespace: &[&str],
        credentials: &[&str],
        seed: impl FnOnce(&Path),
    ) {
        // Written to the process's own stderr, not through `eprintln!`:
        // libtest captures the macro's output and discards it for a test that
        // passes, so a skip announced that way is invisible and the suite still
        // reports green. This goes to file descriptor 2, which libtest does not
        // intercept.
        let skip = |why: &str| {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "skipped {name}: {why}");
        };
        let home = guarded_home();
        // Another uid has to reach the directory and run this test binary,
        // whose own directory it may not be able to read.
        set_mode(home.path(), Mode::DEFAULT_DIR).expect("open the home to traversal");
        let exe = home.child("bx-test");
        // A copy rather than a hard link: the build's own file need not be
        // executable by anyone else either. A full disk cannot hold the copy,
        // and that is the scenario not being constructible, not a failure.
        if let Err(e) = std::fs::copy(std::env::current_exe().expect("the test binary"), &exe) {
            return skip(&format!("the test binary could not be copied: {e}"));
        }
        set_mode(&exe, Mode::from_bits(0o755)).expect("chmod the copy");
        let dir = home.child("shared");
        std::fs::create_dir(&dir).expect("mkdir");
        // Anything the child should find there owned by this user, which is
        // somebody else to uid 1.
        seed(&dir);

        // Each step in a user namespace mapping this user to root and its
        // subordinate ids above that: give the directory group 5, make it
        // setgid and world-writable, and run the child as uid 1.
        let unshared = |ns: &[&str], args: &[&std::ffi::OsStr]| {
            std::process::Command::new("unshare")
                .args(ns)
                .arg("--")
                .args(args)
                .env(child_env, &dir)
                .output()
        };
        let in_namespace =
            |args: &[&std::ffi::OsStr]| unshared(&["--map-auto", "--map-root-user"], args);
        for step in [
            [
                std::ffi::OsStr::new("chown"),
                "0:5".as_ref(),
                dir.as_os_str(),
            ],
            ["chmod".as_ref(), "2777".as_ref(), dir.as_os_str()],
        ] {
            match in_namespace(&step) {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    return skip(&format!(
                        "{step:?} in a user namespace failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    ));
                }
                Err(e) => return skip(&format!("unshare could not run: {e}")),
            }
        }
        let meta = std::fs::metadata(&dir).expect("stat");
        if meta.mode() & 0o2000 == 0 || meta.gid() == rustix::process::getegid().as_raw() {
            return skip("the directory is not setgid to a foreign group");
        }

        // No credentials asked for means no `setpriv` at all: the child keeps
        // the ids and the capability set its namespace gave it. `setpriv`
        // cannot be used for that anyway — a namespace created without
        // `--map-auto` has `setgroups` denied, so even `--clear-groups` fails.
        let mut argv: Vec<&std::ffi::OsStr> = Vec::new();
        if !credentials.is_empty() {
            argv.push("setpriv".as_ref());
            argv.extend(credentials.iter().map(|arg| std::ffi::OsStr::new(*arg)));
            argv.push("--".as_ref());
        }
        argv.extend([
            exe.as_os_str(),
            "--exact".as_ref(),
            name.as_ref(),
            "--nocapture".as_ref(),
        ]);
        let child = unshared(child_namespace, &argv);
        let out = match child {
            Ok(out) => out,
            Err(e) => return skip(&format!("unshare could not run: {e}")),
        };
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        if !stdout.contains(SET_ID_CHILD_RAN) {
            return skip(&format!("the unprivileged child did not start: {stderr}"));
        }
        assert!(
            out.status.success(),
            "the unprivileged child failed:\n{stdout}\n{stderr}"
        );
    }

    #[test]
    fn a_declared_mode_beats_the_process_umask() {
        let _serialised = UMASK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = guarded_home();
        let previous = rustix::process::umask(Mode::from_bits(0o077).into());

        let dest = home.child("wide/f");
        // Through the phases, not `write_atomically`: the parent is missing,
        // and creating one is `stage`'s to do.
        let result = stage_now(&dest, Mode::DEFAULT_FILE).and_then(|s| s.commit(b"x"));

        rustix::process::umask(previous);
        result.expect("write");

        assert_eq!(
            mode_of_path(&dest),
            Mode::DEFAULT_FILE,
            "OpenOptions::mode is masked by the umask; fchmod is not",
        );
        assert_eq!(
            mode_of_path(&home.child("wide")),
            Mode::DEFAULT_DIR,
            "mkdir's mode is masked by the umask too; the directory is chmod'd",
        );
    }

    #[test]
    fn a_directory_bx_creates_is_never_wider_than_its_declared_mode() {
        let _serialised = UMASK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = guarded_home();
        // umask 0 so the assertion means the same thing whatever the developer
        // or the runner happens to have set. Without it, a umask of 077 would
        // narrow `mkdir(0o777)` for free and the test would pass against the
        // defect it exists to catch.
        let previous = rustix::process::umask(Mode::from_bits(0).into());

        let path = home.child("restore");
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));

        let watcher = {
            let (path, done, seen) = (path.clone(), done.clone(), seen.clone());
            std::thread::spawn(move || {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok(meta) = std::fs::symlink_metadata(&path) {
                        let mode = mode_of(&meta);
                        let mut seen = seen
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if seen.last() != Some(&mode) {
                            seen.push(mode);
                        }
                    }
                }
            })
        };

        let result = create_dir_at(&path, Mode::PRIVATE_DIR);
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        watcher.join().expect("the watcher thread");
        rustix::process::umask(previous);
        result.expect("mkdir");

        // The exposure a `mkdir(0o777)` followed by a `chmod` opens is the
        // descriptor, not the contents: a process that opens the directory
        // inside the window keeps a handle whose access checks already passed,
        // and the later `chmod` does not revoke it. So the assertion is about
        // every instant, not about the end state.
        let seen = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for mode in seen.iter() {
            assert!(
                mode.bits() & !Mode::PRIVATE_DIR.bits() == 0,
                "the directory was {mode} at some instant, wider than the 0700 declared for it; \
                 every mode observed was {seen:?}",
            );
        }
        assert_eq!(mode_of_path(&path), Mode::PRIVATE_DIR);
    }

    #[test]
    fn an_abandoned_stage_leaves_the_original_intact() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        let staged = stage_now(&dest, Mode::PRIVATE_FILE).expect("stage");
        let temp = staged.temp_path().to_path_buf();
        staged.abandon();

        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        assert!(!temp.exists(), "no .bx- orphan survives an abandoned write");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
    }

    #[test]
    fn an_abandoned_filled_write_leaves_the_original_intact() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        // The crash phase that matters: the content is on disk and fsynced, and
        // the rename has not happened.
        let filled = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"v2")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();
        assert_eq!(std::fs::read(&temp).expect("read temp"), b"v2");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        filled.abandon();

        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        assert!(!temp.exists());
    }

    #[test]
    fn the_filled_phase_is_the_seam_a_journal_interposes_at() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        let filled = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"v2")
            .expect("fill");

        // Everything a journal needs to record its intent, before the rename.
        assert_eq!(filled.dest(), dest);
        assert_eq!(filled.temp_path().parent(), dest.parent());
        assert_eq!(filled.mode(), Mode::PRIVATE_FILE);
        assert_eq!(filled.prior().kind, Kind::File);
        assert_eq!(filled.prior().bytes.as_deref(), Some(&b"v1"[..]));
        assert_eq!(filled.prior().mode, Some(Mode::DEFAULT_FILE));

        filled.publish().expect("publish");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v2");
    }

    #[test]
    fn a_staged_write_carries_the_prior_state_a_reversal_needs() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::from_bits(0o640));

        let staged = stage_now(&dest, Mode::PRIVATE_FILE).expect("stage");
        let prior = staged.prior().clone();
        staged.commit(b"v2").expect("commit");

        // Restoring from the prior state alone must reproduce v1 exactly,
        // including its mode.
        assert_eq!(prior.path, dest);
        write_atomically(
            &prior.path,
            prior.bytes.as_deref().expect("prior bytes"),
            prior.mode.expect("prior mode"),
        )
        .expect("restore");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
        assert_eq!(mode_of_path(&dest), Mode::from_bits(0o640));
    }

    #[test]
    fn a_commit_replaces_content_and_mode_together() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);
        write_atomically(&dest, b"v2", Mode::PRIVATE_FILE).expect("write");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v2");
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
    }

    #[test]
    fn a_write_creates_the_file_at_the_requested_mode() {
        let home = guarded_home();
        let dest = home.child("f");
        write_atomically(&dest, b"hello", Mode::PRIVATE_FILE).expect("write");
        assert_eq!(std::fs::read(&dest).expect("read"), b"hello");
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
    }

    #[test]
    fn a_second_commit_of_identical_bytes_is_byte_identical() {
        let home = guarded_home();
        let dest = home.child("f");
        write_atomically(&dest, b"same\n", Mode::DEFAULT_FILE).expect("first");
        let first = std::fs::read(&dest).expect("read");
        write_atomically(&dest, b"same\n", Mode::DEFAULT_FILE).expect("second");

        assert_eq!(std::fs::read(&dest).expect("read"), first);
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        let observed = observe(&dest).expect("observe");
        assert_eq!(
            compare(
                &observed,
                &desired(b"same\n", Mode::DEFAULT_FILE),
                home.path()
            )
            .action,
            Action::Unchanged,
            "the second plan is empty",
        );
    }

    #[test]
    fn a_write_does_not_disturb_its_siblings() {
        let home = guarded_home();
        let sibling = home.child("sibling");
        seed(&sibling, b"untouched", Mode::from_bits(0o640));
        let sibling_ino = std::fs::metadata(&sibling).expect("stat").ino();

        write_atomically(&home.child("f"), b"x", Mode::DEFAULT_FILE).expect("write");

        assert_eq!(std::fs::read(&sibling).expect("read"), b"untouched");
        assert_eq!(mode_of_path(&sibling), Mode::from_bits(0o640));
        assert_eq!(
            std::fs::metadata(&sibling).expect("stat").ino(),
            sibling_ino
        );
        assert_eq!(
            names_in(home.path()),
            vec![OsString::from("f"), OsString::from("sibling")],
        );
    }

    #[test]
    fn a_write_leaves_no_temporary_file_behind() {
        let home = guarded_home();
        write_atomically(&home.child("f"), b"x", Mode::DEFAULT_FILE).expect("write");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
    }

    #[test]
    fn a_failed_publish_leaves_no_temporary_file_behind() {
        let home = guarded_home();
        let dest = home.child("f");
        let staged = stage_now(&dest, Mode::DEFAULT_FILE).expect("stage");
        // Something occupies the destination after it was observed, so the
        // publish fails after the temporary file has been written in full —
        // refused by the check before the rename, which is the one a rename
        // over a directory would also have failed.
        std::fs::create_dir(&dest).expect("occupy");

        let err = staged.commit(b"x").expect_err("must fail");
        assert_eq!(err.path(), dest);
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
    }

    #[test]
    fn a_destination_edited_between_fill_and_publish_is_refused_and_keeps_the_edit() {
        // The window a journal widens: between the observation `stage` takes
        // and the rename, an editor saves. Replacing the file then destroys the
        // save, and the prior bx recorded predates it, so `rm` cannot bring it
        // back either — Invariant 1 and Invariant 4 at once.
        let in_place: fn(&Path) = |dest| {
            std::fs::write(dest, b"the user's edit\n").expect("the user saves in place");
        };
        let by_rename: fn(&Path) = |dest| {
            // Same length as what was there, so only which file it is changed.
            let saved = dest.with_file_name("editor-swap");
            std::fs::write(&saved, b"v2\n").expect("the editor writes its copy");
            std::fs::rename(&saved, dest).expect("and renames it over the original");
        };

        for (how, save) in [("in place", in_place), ("by rename", by_rename)] {
            let home = guarded_home();
            let dest = home.child(".conf");
            seed(&dest, b"v1\n", Mode::DEFAULT_FILE);

            let filled = stage_now(&dest, Mode::DEFAULT_FILE)
                .expect("stage")
                .fill(b"bx\n")
                .expect("fill");
            let temp = filled.temp_path().to_path_buf();
            save(&dest);
            let saved = std::fs::read(&dest).expect("read the save");

            let refused = filled
                .publish()
                .expect_err("a destination that changed after it was observed is not replaced");
            assert_eq!(refused.dest, dest, "{how}: the refusal names the write");
            let err = refused.into_error();
            assert!(matches!(err, Error::Changed { .. }), "{how}: {err:?}");
            assert_eq!(err.path(), dest, "{how}");
            assert_eq!(
                std::fs::read(&dest).expect("read"),
                saved,
                "{how}: the user's save survives",
            );
            assert!(!temp.exists(), "{how}: the temporary file is removed");
            assert_eq!(
                names_in(home.path()),
                vec![OsString::from(".conf")],
                "{how}"
            );
        }
    }

    #[test]
    fn a_symlink_swapped_in_between_fill_and_publish_is_refused_and_survives() {
        let home = guarded_home();
        let dest = home.child(".conf");
        let other = home.child("elsewhere");
        seed(&dest, b"v1\n", Mode::DEFAULT_FILE);
        seed(&other, b"the link's target\n", Mode::DEFAULT_FILE);

        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"bx\n")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();
        // Decision 2 refuses a link at the final component; observing a file
        // there first must not turn into replacing a link that arrived later.
        std::fs::remove_file(&dest).expect("rm");
        std::os::unix::fs::symlink("elsewhere", &dest).expect("symlink");

        let refused = filled
            .publish()
            .expect_err("the link is not bx's to replace");
        assert_eq!(refused.dest, dest, "the refusal names the write");
        let err = refused.into_error();
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert!(
            std::fs::symlink_metadata(&dest)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the link is intact",
        );
        assert_eq!(
            std::fs::read_link(&dest).expect("readlink"),
            Path::new("elsewhere")
        );
        assert_eq!(std::fs::read(&other).expect("read"), b"the link's target\n");
        assert!(!temp.exists());
    }

    #[test]
    fn a_file_that_appears_where_there_was_none_is_not_replaced() {
        let home = guarded_home();
        let dest = home.child(".conf");

        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"bx\n")
            .expect("fill");
        assert_eq!(filled.prior().stamp, None, "nothing was there to stamp");
        std::fs::write(&dest, b"another tool's\n").expect("another tool creates it");

        let refused = filled
            .publish()
            .expect_err("bx announced a create, and there is now a file to replace");
        assert_eq!(refused.dest, dest, "the refusal names the write");
        let err = refused.into_error();
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(std::fs::read(&dest).expect("read"), b"another tool's\n");
        assert_eq!(names_in(home.path()), vec![OsString::from(".conf")]);
    }

    #[test]
    fn a_destination_changed_after_plan_is_refused_by_stage_and_keeps_the_change() {
        // Invariant 7: plan printed a diff against what it observed. A file
        // edited, replaced or removed after that is not the file plan's diff
        // was about, so apply may not replace it with that diff's content.
        let edited: fn(&Path) = |dest| {
            std::fs::write(dest, b"the user's edit after plan\n").expect("the user saves");
        };
        let replaced: fn(&Path) = |dest| {
            // Same length as what was there, so only which file it is changed.
            let saved = dest.with_file_name("editor-swap");
            std::fs::write(&saved, b"v2\n").expect("the editor writes its copy");
            std::fs::rename(&saved, dest).expect("and renames it over the original");
        };
        let removed: fn(&Path) = |dest| std::fs::remove_file(dest).expect("the user removes it");

        for (how, change) in [
            ("edited in place", edited),
            ("replaced by rename", replaced),
            ("removed", removed),
        ] {
            let home = guarded_home();
            let dest = home.child(".conf");
            seed(&dest, b"v1\n", Mode::DEFAULT_FILE);
            let planned = observe(&dest).expect("plan observes");
            assert_eq!(
                compare(&planned, &desired(b"bx\n", Mode::DEFAULT_FILE), home.path()).action,
                Action::Modify,
                "{how}",
            );

            change(&dest);
            let now = std::fs::read(&dest).ok();

            let err = stage(&dest, Mode::DEFAULT_FILE, &planned, &mut CreatedDirs::new())
                .expect_err("a destination that changed after plan is not staged over");
            assert!(matches!(err, Error::Changed { .. }), "{how}: {err:?}");
            assert_eq!(err.path(), dest, "{how}");
            assert_eq!(
                std::fs::read(&dest).ok(),
                now,
                "{how}: what is there now survives"
            );
            let expected: Vec<OsString> = now.iter().map(|_| OsString::from(".conf")).collect();
            assert_eq!(
                names_in(home.path()),
                expected,
                "{how}: no temporary file is left"
            );
        }

        // A file that appeared where plan saw nothing is not the create plan
        // announced either.
        let home = guarded_home();
        let dest = home.child(".conf");
        let planned = observe(&dest).expect("plan observes");
        std::fs::write(&dest, b"another tool's\n").expect("another tool creates it");
        let err = stage(&dest, Mode::DEFAULT_FILE, &planned, &mut CreatedDirs::new())
            .expect_err("plan announced a create");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(std::fs::read(&dest).expect("read"), b"another tool's\n");
        assert_eq!(names_in(home.path()), vec![OsString::from(".conf")]);

        // And plan's observation of one path does not license a write to
        // another.
        let err = stage(
            &home.child("other"),
            Mode::DEFAULT_FILE,
            &planned,
            &mut CreatedDirs::new(),
        )
        .expect_err("plan observed a different path");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(names_in(home.path()), vec![OsString::from(".conf")]);
    }

    /// A POSIX ACL in the kernel's `system.posix_acl_access` encoding: version
    /// 2, then `(tag, perm, id)` per entry, little-endian, sorted by tag.
    fn posix_acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut encoded = 2_u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            encoded.extend(tag.to_le_bytes());
            encoded.extend(perm.to_le_bytes());
            encoded.extend(id.to_le_bytes());
        }
        encoded
    }

    #[test]
    fn a_replaced_file_keeps_neither_its_xattrs_nor_its_acl() {
        // A documented exclusion from "restores exactly", pinned so that
        // changing it is a decision: see the module documentation.
        use rustix::fs::{XattrFlags, getxattr, setxattr};

        const USER_ATTR: &str = "user.bx-test";
        const ACL_ACCESS: &str = "system.posix_acl_access";
        const UNDEFINED_ID: u32 = u32::MAX;

        let home = guarded_home();
        let dest = home.child(".conf");
        seed(&dest, b"v1\n", Mode::DEFAULT_FILE);

        // What this filesystem can hold decides what there is to pin. An ACL
        // naming uid 65534 is refused with EINVAL where that uid is unmapped.
        let has_user_attr =
            match setxattr(dest.as_path(), USER_ATTR, b"theirs", XattrFlags::empty()) {
                Ok(()) => true,
                Err(e) if e == Errno::OPNOTSUPP => false,
                Err(e) => panic!("setxattr {USER_ATTR}: {e}"),
            };
        let acl = posix_acl(&[
            (0x01, 6, UNDEFINED_ID), // user::rw-
            (0x02, 4, 65534),        // user:nobody:r--
            (0x04, 4, UNDEFINED_ID), // group::r--
            (0x10, 4, UNDEFINED_ID), // mask::r--
            (0x20, 4, UNDEFINED_ID), // other::r--
        ]);
        let has_acl = match setxattr(dest.as_path(), ACL_ACCESS, &acl, XattrFlags::empty()) {
            Ok(()) => true,
            Err(e) if e == Errno::OPNOTSUPP || e == Errno::INVAL => false,
            Err(e) => panic!("setxattr {ACL_ACCESS}: {e}"),
        };
        let attrs: Vec<&str> = [(USER_ATTR, has_user_attr), (ACL_ACCESS, has_acl)]
            .into_iter()
            .filter_map(|(name, set)| set.then_some(name))
            .collect();
        if attrs.is_empty() {
            // Neither can exist here, so neither can be lost.
            return;
        }

        let attr = |name: &str| -> Option<Vec<u8>> {
            let mut buf = [0_u8; 256];
            match getxattr(dest.as_path(), name, &mut buf) {
                Ok(len) => Some(buf[..len].to_vec()),
                Err(e) if e == Errno::NODATA => None,
                Err(e) => panic!("getxattr {name}: {e}"),
            }
        };
        for name in &attrs {
            assert!(attr(name).is_some(), "{name} is on the user's file");
        }

        let staged = stage_now(&dest, Mode::DEFAULT_FILE).expect("stage");
        let prior = staged.prior().clone();
        staged.commit(b"bx\n").expect("commit");
        for name in &attrs {
            assert_eq!(
                attr(name),
                None,
                "{name} is not carried onto the replacement"
            );
        }

        // The prior is bytes and mode, so restoring from it brings the bytes
        // and the mode back, and nothing else.
        write_atomically(
            &dest,
            prior.bytes.as_deref().expect("prior bytes"),
            prior.mode.expect("prior mode"),
        )
        .expect("restore");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v1\n");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        for name in &attrs {
            assert_eq!(attr(name), None, "{name} is not restored either");
        }
    }

    #[test]
    fn a_symlink_destination_is_refused_and_writes_nothing() {
        let home = guarded_home();
        let other = home.child("other");
        seed(&other, b"the link's target", Mode::DEFAULT_FILE);
        let dest = home.child("link");
        std::os::unix::fs::symlink("other", &dest).expect("symlink");

        let err = write_atomically(&dest, b"replacement", Mode::DEFAULT_FILE)
            .expect_err("a link the user made is not bx's to replace");
        assert!(matches!(err, Error::Symlink(_)), "{err:?}");
        assert_eq!(err.path(), dest);

        // The link survives, still pointing where it pointed, and its target is
        // untouched.
        assert!(
            std::fs::symlink_metadata(&dest)
                .expect("stat")
                .file_type()
                .is_symlink(),
        );
        assert_eq!(
            std::fs::read_link(&dest).expect("readlink"),
            Path::new("other"),
        );
        assert_eq!(std::fs::read(&other).expect("read"), b"the link's target");

        // And `plan` says the same thing rather than something else.
        let outcome = outcome_for(&home, "link", b"replacement", Mode::DEFAULT_FILE);
        assert_eq!(outcome.action, Action::Conflict);
        assert_eq!(
            outcome.note.as_deref(),
            Some("a symlink; bx will not replace a link you created"),
        );
    }

    #[test]
    fn a_symlink_in_a_parent_component_is_written_through() {
        let home = guarded_home();
        // The kernel resolves a parent symlink, the temporary file lands in the
        // real directory, and the rename stays inside that one directory. Only
        // the final component is bx's business.
        std::fs::create_dir(home.child("real")).expect("mkdir");
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        write_atomically(&home.child("link/f"), b"x", Mode::DEFAULT_FILE).expect("write");

        assert_eq!(std::fs::read(home.child("real/f")).expect("read"), b"x");
        assert!(
            std::fs::symlink_metadata(home.child("link"))
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the link survives",
        );
    }

    #[test]
    fn a_missing_parent_directory_is_created_at_the_default_dir_mode() {
        let home = guarded_home();
        let dest = home.child("a/b/c/f");
        // `stage`, which is the only entry point that creates a directory.
        stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .commit(b"x")
            .expect("commit");

        assert_eq!(std::fs::read(&dest).expect("read"), b"x");
        for rel in ["a", "a/b", "a/b/c"] {
            assert_eq!(
                mode_of_path(&home.child(rel)),
                Mode::DEFAULT_DIR,
                "{rel} is an implicit parent, created at 0755",
            );
        }
    }

    #[test]
    fn the_one_call_shorthand_creates_no_directory_and_says_so() {
        // The base's contract, kept for the entry point that has no
        // `CreatedDirs` to record a directory in, no plan to announce it in,
        // and no caller to say what mode it should get — which is how a 0600
        // secret would otherwise land in a 0755 directory nobody decided on.
        // `stage` and `ensure_dir` still create directories; this one does not.
        let home = guarded_home();
        let dest = home.child("a/b/secret.age");

        let err = write_atomically(&dest, b"x", Mode::PRIVATE_FILE)
            .expect_err("the shorthand invents no directory");
        assert!(
            matches!(&err, Error::MissingParent(dir) if *dir == home.child("a/b")),
            "{err:?}",
        );
        assert_eq!(err.path(), home.child("a/b"));
        assert!(
            err.to_string()
                .contains("bx creates no directory for this write"),
            "{err}",
        );
        assert!(!home.child("a").exists(), "nothing was created");
        assert_eq!(names_in(home.path()), Vec::<OsString>::new());

        // With the directory there it writes, and the mode of the directory is
        // the caller's own decision rather than a default.
        std::fs::create_dir_all(home.child("a/b")).expect("the caller creates it");
        set_mode(&home.child("a/b"), Mode::PRIVATE_DIR).expect("chmod");
        write_atomically(&dest, b"x", Mode::PRIVATE_FILE).expect("write");
        assert_eq!(std::fs::read(&dest).expect("read"), b"x");
        assert_eq!(mode_of_path(&home.child("a/b")), Mode::PRIVATE_DIR);

        // A parent that is there but does not resolve is still the conflict it
        // was, not this.
        let dangling = home.child("dangling");
        std::os::unix::fs::symlink("nowhere", &dangling).expect("symlink");
        let err = write_atomically(&dangling.join("f"), b"x", Mode::DEFAULT_FILE)
            .expect_err("a dangling parent is unusable, not missing");
        assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
    }

    #[test]
    fn a_parent_created_for_an_abandoned_write_is_left_in_place() {
        let home = guarded_home();
        let dest = home.child(".ssh/config");
        let staged = stage_now(&dest, Mode::PRIVATE_FILE).expect("stage");
        let temp = staged.temp_path().to_path_buf();
        staged.abandon();

        // Documented behaviour, not an oversight: the directory is empty and at
        // the mode a mkdir would have given it, the next attempt reuses it, and
        // removing it would race any other write already using it.
        assert!(home.child(".ssh").is_dir());
        assert_eq!(mode_of_path(&home.child(".ssh")), Mode::DEFAULT_DIR);
        assert_eq!(names_in(&home.child(".ssh")), Vec::<OsString>::new());
        assert!(!temp.exists());
        assert!(!dest.exists());
    }

    #[test]
    fn an_existing_parent_directory_is_never_chmod_d() {
        let home = guarded_home();
        std::fs::create_dir(home.child("shared")).expect("mkdir");
        set_mode(&home.child("shared"), Mode::from_bits(0o770)).expect("chmod");

        write_atomically(&home.child("shared/f"), b"x", Mode::PRIVATE_FILE).expect("write");

        assert_eq!(
            mode_of_path(&home.child("shared")),
            Mode::from_bits(0o770),
            "a directory bx did not create is the user's",
        );
    }

    #[test]
    fn an_unwritable_parent_directory_surfaces_a_typed_error() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let dir = home.child("locked");
        std::fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

        let dest = dir.join("f");
        let err = write_atomically(&dest, b"x", Mode::DEFAULT_FILE).expect_err("must fail");
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(err.path(), dir, "the error names the directory");
        assert!(!dest.exists());

        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");
    }

    #[test]
    fn a_missing_directory_under_a_read_only_parent_is_a_write_error_naming_it() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so the mkdir is not refused.
            return;
        }
        let home = guarded_home();
        let dir = home.child("d");
        std::fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

        let result = stage_now(&dir.join("sub/f"), Mode::DEFAULT_FILE).and_then(|s| s.commit(b"x"));
        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for the assertions");

        let err = result.expect_err("a read-only directory refuses the mkdir");
        let Error::Write { path, source } = &err else {
            panic!("expected a write error, got {err:?}");
        };
        assert_eq!(
            path,
            &dir.join("sub"),
            "the error names the directory bx could not make",
        );
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            names_in(&dir),
            Vec::<OsString>::new(),
            "nothing was made or written",
        );
    }

    #[test]
    fn a_parent_that_cannot_be_stat_ed_is_an_error_not_an_absent_directory() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let locked = home.child("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        // No execute bit, so nothing below it can be stat'd at all.
        set_mode(&locked, Mode::from_bits(0o000)).expect("chmod");

        // The third `ENOENT`-adjacent case, and the one that must *not* become
        // a directory bx invents: the parent may well be there, and bx cannot
        // see. A read error is the only honest answer.
        let err = observe(&locked.join("sub/f")).expect_err("must fail");
        let Error::Read { path, .. } = &err else {
            panic!("expected a read error, got {err:?}");
        };
        assert_eq!(path, &locked.join("sub"));

        set_mode(&locked, Mode::PRIVATE_DIR).expect("unlock for cleanup");
    }

    #[test]
    fn a_path_with_no_parent_is_refused() {
        let err =
            write_atomically(Path::new("/"), b"x", Mode::DEFAULT_FILE).expect_err("must fail");
        assert!(matches!(err, Error::NoParent(_)), "{err:?}");
        assert_eq!(err.path(), Path::new("/"));
    }

    #[test]
    fn a_bare_file_name_writes_into_the_working_directory() {
        assert_eq!(parent_of(Path::new("f")).expect("parent"), Path::new("."));
    }

    #[test]
    fn a_relative_destination_writes_under_the_working_directory() {
        let _serialised = CWD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = guarded_home();
        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(home.path()).expect("chdir");

        // A bare name, which `parent_of` resolves to `.` — the contract it goes
        // out of its way to support, and which nothing had ever exercised
        // through an actual write.
        let bare = write_atomically(Path::new("bare"), b"x", Mode::DEFAULT_FILE);
        // And a relative path more than one component deep, where `ancestors`
        // ends with `""`. Its directories are missing, so it goes through the
        // phases: only `stage` creates one.
        let deep =
            stage_now(Path::new("a/b/c.txt"), Mode::PRIVATE_FILE).and_then(|s| s.commit(b"y"));

        std::env::set_current_dir(&previous).expect("restore the working directory");
        bare.expect("a bare relative name");
        deep.expect("a relative path two directories deep");

        assert_eq!(std::fs::read(home.child("bare")).expect("read"), b"x");
        assert_eq!(std::fs::read(home.child("a/b/c.txt")).expect("read"), b"y");
        for rel in ["a", "a/b"] {
            assert_eq!(mode_of_path(&home.child(rel)), Mode::DEFAULT_DIR, "{rel}");
        }
    }

    /// `apply` for a file target's `Modify`, acting on the observation `plan`
    /// compared: staged against it and committed with the desired bytes,
    /// whether the drift is in the content, the mode, or both.
    fn apply_file_modify(
        planned: &Observed,
        dest: &Path,
        desired: &Desired<'_>,
    ) -> Result<(), Error> {
        stage(dest, desired.mode, planned, &mut CreatedDirs::new())?.commit(desired.bytes)
    }

    #[test]
    fn a_mode_only_modify_changed_after_plan_is_refused_and_keeps_the_change() {
        // Invariants 4 and 7 for the smallest Modify there is: plan announced
        // `mode 0644 -> 0600` against one file, and apply may act only on that
        // file, unchanged.
        let home = guarded_home();
        let want = desired(b"Host *\n", Mode::PRIVATE_FILE);

        // (a) The user chmods the file after plan printed its line.
        let chmodded = home.child("chmodded");
        seed(&chmodded, b"Host *\n", Mode::DEFAULT_FILE);
        let planned_a = observe(&chmodded).expect("plan observes");
        let outcome = compare(&planned_a, &want, home.path());
        assert_eq!(outcome.action, Action::Modify);
        assert!(!outcome.content_drift, "only the mode drifted");
        set_mode(&chmodded, Mode::from_bits(0o640)).expect("the user's chmod after plan");
        let result_a = apply_file_modify(&planned_a, &chmodded, &want);
        let mode_a = mode_of_path(&chmodded);

        // (b) The file is replaced by a directory after plan printed its line.
        let replaced = home.child("replaced");
        seed(&replaced, b"Host *\n", Mode::DEFAULT_FILE);
        let planned_b = observe(&replaced).expect("plan observes");
        assert_eq!(
            compare(&planned_b, &want, home.path()).action,
            Action::Modify
        );
        std::fs::remove_file(&replaced).expect("rm");
        std::fs::create_dir(&replaced).expect("a directory takes the path");
        set_mode(&replaced, Mode::DEFAULT_DIR).expect("at its own mode");
        std::fs::write(replaced.join("inside"), b"theirs").expect("with an entry");
        let result_b = apply_file_modify(&planned_b, &replaced, &want);
        let mode_b = mode_of_path(&replaced);

        assert!(
            matches!(
                (&result_a, &result_b),
                (Err(Error::Changed { .. }), Err(Error::Changed { .. }))
            ),
            "(a) chmod 0640 after plan: {result_a:?}, file now {mode_a}; \
             (b) directory after plan: {result_b:?}, directory now {mode_b}",
        );
        assert_eq!(
            mode_a,
            Mode::from_bits(0o640),
            "(a) the user's chmod stands"
        );
        assert_eq!(std::fs::read(&chmodded).expect("read"), b"Host *\n");
        assert_eq!(
            mode_b,
            Mode::DEFAULT_DIR,
            "(b) the directory keeps its mode"
        );
        assert_eq!(
            std::fs::read(replaced.join("inside")).expect("the entry is still readable"),
            b"theirs",
        );
        assert_eq!(
            names_in(home.path()),
            vec![OsString::from("chmodded"), OsString::from("replaced")],
            "no temporary file is left",
        );
    }

    #[test]
    fn set_mode_changes_the_mode_in_place_without_replacing_the_inode() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);
        let link = home.child("hardlink");
        std::fs::hard_link(&dest, &link).expect("hard link");
        let before = std::fs::metadata(&dest).expect("stat").ino();

        set_mode(&dest, Mode::PRIVATE_FILE).expect("chmod");

        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"v1",
            "content is untouched"
        );
        assert_eq!(
            std::fs::metadata(&dest).expect("stat").ino(),
            before,
            "a chmod keeps the inode; a rewrite would not",
        );
        assert_eq!(
            mode_of_path(&link),
            Mode::PRIVATE_FILE,
            "the user's hard link still points at the same file",
        );
    }

    #[test]
    fn set_mode_refuses_a_symlink() {
        let home = guarded_home();
        seed(&home.child("real"), b"x", Mode::DEFAULT_FILE);
        let link = home.child("link");
        std::os::unix::fs::symlink("real", &link).expect("symlink");

        let err = set_mode(&link, Mode::PRIVATE_FILE).expect_err("must fail");
        assert!(matches!(err, Error::Symlink(_)), "{err:?}");
        assert_eq!(
            mode_of_path(&home.child("real")),
            Mode::DEFAULT_FILE,
            "the link's target keeps its mode",
        );
    }

    #[test]
    fn set_mode_names_a_path_that_is_not_there() {
        let home = guarded_home();
        let err = set_mode(&home.child("nope"), Mode::PRIVATE_FILE).expect_err("must fail");
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(err.path(), home.child("nope"));
    }

    /// The `plan` verdict for a declared directory target.
    fn dir_outcome_for(home: &GuardedHome, rel: &str, mode: Mode) -> Outcome {
        compare_dir(&observe(&home.child(rel)).expect("observe"), mode)
    }

    /// `plan` for a directory target, then `apply` on what that plan saw, with
    /// nothing changing in between.
    fn apply_dir(path: &Path, mode: Mode) -> Result<EnsuredDir, Error> {
        let planned = observe(path).expect("plan observes");
        ensure_dir(path, mode, &planned, &mut CreatedDirs::new())
    }

    #[test]
    fn ensure_dir_refuses_a_mode_changed_after_plan_saw_nothing_to_do() {
        let home = guarded_home();
        let dir = home.child(".ssh");
        std::fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, Mode::PRIVATE_DIR).expect("chmod");
        let planned = observe(&dir).expect("plan observes");
        assert_eq!(
            compare_dir(&planned, Mode::PRIVATE_DIR).action,
            Action::Unchanged,
        );

        set_mode(&dir, Mode::DEFAULT_DIR).expect("somebody widens it after plan");

        let err = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned, &mut CreatedDirs::new())
            .expect_err("plan announced nothing, so apply may do nothing");
        let Error::Changed { detail, .. } = &err else {
            panic!("expected Changed, got {err:?}");
        };
        assert_eq!(
            detail, "plan saw a directory at 0700, and it is now a directory at 0755",
            "the refusal says what each observation found",
        );
        assert_eq!(err.path(), dir);
        assert_eq!(
            mode_of_path(&dir),
            Mode::DEFAULT_DIR,
            "apply did not chmod a directory plan never said it would touch",
        );
    }

    #[test]
    fn ensure_dir_refuses_a_directory_that_appeared_after_plan_announced_a_create() {
        let home = guarded_home();
        let dir = home.child("shared");
        let planned = observe(&dir).expect("plan observes");
        assert_eq!(
            compare_dir(&planned, Mode::PRIVATE_DIR).action,
            Action::Create
        );

        std::fs::create_dir(&dir).expect("another tool makes it");
        set_mode(&dir, Mode::from_bits(0o777)).expect("at its own mode");

        let err = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned, &mut CreatedDirs::new())
            .expect_err("plan announced a create, not a chmod of somebody else's directory");
        let Error::Changed { detail, .. } = &err else {
            panic!("expected Changed, got {err:?}");
        };
        assert_eq!(
            detail,
            "plan saw nothing, and it is now a directory at 0777"
        );
        assert_eq!(mode_of_path(&dir), Mode::from_bits(0o777));
    }

    #[test]
    fn ensure_dir_refuses_a_parent_that_stopped_resolving_after_plan_observed() {
        let home = guarded_home();
        let parent = home.child("dotfiles");
        std::fs::create_dir(&parent).expect("mkdir parent");
        set_mode(&parent, Mode::DEFAULT_DIR).expect("chmod parent");
        let dir = parent.join("sub");
        std::fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, Mode::PRIVATE_DIR).expect("chmod");
        let planned = observe(&dir).expect("plan observes");
        assert_eq!(
            compare_dir(&planned, Mode::PRIVATE_DIR).action,
            Action::Unchanged,
        );

        // Somebody replaces the parent with a dangling symlink between `plan`
        // and `apply`: the same race `seen()` names for a file target's
        // parent, here on a directory target's own second observation.
        std::fs::remove_dir_all(&parent).expect("remove parent");
        std::os::unix::fs::symlink("nowhere", &parent).expect("symlink");

        let err = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned, &mut CreatedDirs::new())
            .expect_err("plan announced unchanged through a parent that no longer resolves");
        let Error::Changed { detail, .. } = &err else {
            panic!("expected Changed, got {err:?}");
        };
        assert!(
            detail.contains("a parent that does not resolve"),
            "{detail}",
        );
        assert!(
            detail.contains(&parent.display().to_string()),
            "the detail must name the parent that does not resolve: {detail}",
        );
    }

    /// The refusal a declared file mode that locks its owner out gets, naming
    /// `path` and the note `plan` printed for it.
    fn assert_owner_locked_out(err: &Error, path: &Path, note: &str) {
        let message = err.to_string();
        assert!(
            matches!(err, Error::OwnerLockedOut { path: named, .. } if named == path),
            "expected OwnerLockedOut naming {}, got {err:?}",
            path.display(),
        );
        assert_eq!(err.path(), path, "{message}");
        assert_eq!(
            message,
            format!("{} {note}. Nothing was changed", path.display()),
        );
    }

    #[test]
    fn a_file_target_that_denies_its_owner_read_is_a_conflict_at_plan_time() {
        let home = guarded_home();
        let dir = home.child("d");
        let declared = Mode::from_bits(0o200);
        let note = "declares 0200, which denies its owner read (0400): bx reads a file target's \
                    bytes to compare them with what it wants there, so its mode must grant the \
                    owner read (0400)";
        let conflict = Outcome {
            action: Action::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(note.to_string()),
            parent_note: None,
        };

        // An existing file declared 0200: its bytes could never be compared.
        let existing = dir.join("existing");
        seed(&existing, b"before", Mode::DEFAULT_FILE);
        let planned = observe(&existing).expect("plan observes");
        assert_eq!(
            compare(&planned, &desired(b"after", declared), home.path()),
            conflict,
            "plan announces the conflict",
        );

        // An absent file declared 0200: the same conflict.
        let fresh = dir.join("fresh");
        let planned = observe(&fresh).expect("plan observes");
        assert_eq!(
            compare(&planned, &desired(b"x", declared), home.path()),
            conflict
        );

        // The error a caller raises for it says the same words, with the path.
        let err = Error::OwnerLockedOut {
            path: existing.clone(),
            declared,
            needs: FILE_OWNER_NEEDS,
        };
        assert_owner_locked_out(&err, &existing, note);
    }

    #[test]
    fn a_directory_target_that_denies_its_owner_access_is_applied_as_declared() {
        let home = guarded_home();
        // Nothing beneath either is declared, so bx never lists, writes into
        // or searches them: whether a mode is too narrow for what lies beneath
        // is the plan layer's to judge.
        for (name, before, declared, action) in [
            ("ro", Some(Mode::DEFAULT_DIR), 0o555, Action::Modify),
            (".aws", None, 0o500, Action::Create),
        ] {
            let path = home.child(name);
            if let Some(mode) = before {
                std::fs::create_dir(&path).expect("mkdir");
                set_mode(&path, mode).expect("chmod");
            }
            let declared = Mode::from_bits(declared);
            let planned = observe(&path).expect("plan observes");
            let first = compare_dir(&planned, declared);
            assert_eq!(
                (first.action, first.mode_drift),
                (action, before.map(|mode| (mode, declared))),
                "{name}: the first plan",
            );
            let applied = ensure_dir(&path, declared, &planned, &mut CreatedDirs::new())
                .expect("a childless directory target applies");
            assert_eq!(applied.action, action, "{name}");
            assert_eq!(mode_of_path(&path), declared, "{name}");
            let second = compare_dir(&observe(&path).expect("plan observes"), declared);
            assert_eq!(second.action, Action::Unchanged, "{name}: the second plan");
            set_mode(&path, Mode::DEFAULT_DIR).expect("unlock for cleanup");
        }
    }

    #[test]
    fn ensure_dir_refuses_a_file_that_took_the_path_before_its_mkdir() {
        let home = guarded_home();
        let dir = home.child("d");
        let planned = observe(&dir).expect("plan observes");
        // Apply's own observation agrees with plan's...
        let fresh = observe(&dir).expect("apply observes");
        assert_eq!(
            compare_dir(&fresh, Mode::PRIVATE_DIR),
            compare_dir(&planned, Mode::PRIVATE_DIR),
        );
        // ...and then a file lands before the mkdir does.
        seed(&dir, b"a file\n", Mode::DEFAULT_FILE);

        let err = act_on_dir(
            &dir,
            Mode::PRIVATE_DIR,
            &planned,
            fresh,
            &mut CreatedDirs::new(),
        )
        .expect_err("a file where a directory was to be created is not a create");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(std::fs::read(&dir).expect("read"), b"a file\n");
        assert_eq!(mode_of_path(&dir), Mode::DEFAULT_FILE);
    }

    #[test]
    fn ensure_dir_returns_what_it_overwrote_and_what_it_created() {
        let home = guarded_home();
        let dir = home.child("a/b/c");

        let created = apply_dir(&dir, Mode::PRIVATE_DIR).expect("create");
        assert_eq!(created.action, Action::Create);
        assert_eq!(created.prior.kind, Kind::Absent);
        assert_eq!(
            created.created_dirs,
            [home.child("a/b/c"), home.child("a/b"), home.child("a")],
            "deepest first, the path itself included, for a reversal to remove",
        );

        set_mode(&dir, Mode::DEFAULT_DIR).expect("widen");
        let closed = apply_dir(&dir, Mode::PRIVATE_DIR).expect("modify");
        assert_eq!(closed.action, Action::Modify);
        assert_eq!(
            closed.prior.mode,
            Some(Mode::DEFAULT_DIR),
            "the mode it overwrote, for the ledger to restore",
        );
        assert!(closed.created_dirs.is_empty());

        let unchanged = apply_dir(&dir, Mode::PRIVATE_DIR).expect("unchanged");
        assert_eq!(unchanged.action, Action::Unchanged);
        assert_eq!(unchanged.prior.mode, Some(Mode::PRIVATE_DIR));
        assert!(unchanged.created_dirs.is_empty());
    }

    #[test]
    fn ensure_dir_creates_at_the_declared_mode_and_closes_the_drift_plan_announced() {
        let home = guarded_home();
        let dir = home.child(".ssh");

        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("create").action,
            Action::Create,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Idempotence: the second call changes nothing and reports nothing.
        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("again").action,
            Action::Unchanged,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Drift is announced by plan, which changes nothing...
        set_mode(&dir, Mode::DEFAULT_DIR).expect("widen");
        let planned = dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR);
        assert_eq!(planned.action, Action::Modify);
        assert_eq!(planned.note.as_deref(), Some("mode 0755 -> 0700"));
        assert_eq!(
            planned.mode_drift,
            Some((Mode::DEFAULT_DIR, Mode::PRIVATE_DIR))
        );
        assert!(!planned.content_drift);
        assert_eq!(
            mode_of_path(&dir),
            Mode::DEFAULT_DIR,
            "plan changed nothing"
        );

        // ...and closed by apply, which does exactly that and nothing else.
        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("drift").action,
            planned.action,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);
        assert_eq!(
            dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR).action,
            Action::Unchanged,
            "the second plan is empty",
        );
    }

    #[test]
    fn planning_a_directory_target_creates_nothing() {
        let home = guarded_home();

        let outcome = dir_outcome_for(&home, "declared/dir", Mode::PRIVATE_DIR);
        assert_eq!(outcome.action, Action::Create);
        assert_eq!(outcome.note, None);
        assert_eq!(outcome.parent_note, None);
        assert!(!outcome.content_drift);
        assert_eq!(
            names_in(home.path()),
            Vec::<OsString>::new(),
            "neither the directory nor its missing ancestor exists after plan",
        );

        // And apply performs the create plan announced.
        assert_eq!(
            apply_dir(&home.child("declared/dir"), Mode::PRIVATE_DIR)
                .expect("apply")
                .action,
            outcome.action,
        );
        assert_eq!(mode_of_path(&home.child("declared/dir")), Mode::PRIVATE_DIR);
        assert_eq!(mode_of_path(&home.child("declared")), Mode::DEFAULT_DIR);
    }

    #[test]
    fn a_dangling_link_above_a_directory_target_is_a_conflict_at_plan_time() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child("d")).expect("symlink");

        let outcome = dir_outcome_for(&home, "d/a", Mode::PRIVATE_DIR);
        assert_eq!(outcome.action, Action::Conflict);
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains("does not resolve to a directory"), "{note}");

        // A dangling link *at* the path is a link, and a conflict too.
        assert_eq!(
            dir_outcome_for(&home, "d", Mode::PRIVATE_DIR).action,
            Action::Conflict,
        );
        assert_eq!(
            apply_dir(&home.child("d"), Mode::PRIVATE_DIR)
                .expect("a verdict")
                .action,
            Action::Conflict,
        );
        assert!(std::fs::symlink_metadata(home.child("nowhere")).is_err());
    }

    #[test]
    fn a_directory_target_occupied_by_something_else_names_what_is_there() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        std::fs::create_dir(home.child("real")).expect("mkdir");
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            home.child("fifo"),
            rustix::fs::FileType::Fifo,
            Mode::PRIVATE_FILE.into(),
            0,
        )
        .expect("mkfifo");

        for (rel, expected) in [
            ("f", "a file, where the target declares a directory"),
            (
                "link",
                "a symlink; bx will not change a directory through a link",
            ),
            ("fifo", "not a directory"),
        ] {
            let outcome = dir_outcome_for(&home, rel, Mode::PRIVATE_DIR);
            assert_eq!(outcome.action, Action::Conflict, "{rel}");
            assert_eq!(outcome.note.as_deref(), Some(expected), "{rel}");
        }
    }

    #[test]
    fn a_directory_target_applied_after_a_file_beneath_it_is_the_create_plan_announced() {
        // ~/.ssh at 0700 and ~/.ssh/config at 0600, both absent and both
        // declared, applied file first. The file's write makes ~/.ssh at its
        // declared 0700, and the directory target that follows must adopt it
        // as its create rather than stop the apply with the file written.
        let home = guarded_home();
        let dir = home.child(".ssh");
        let file = home.child(".ssh/config");
        let planned_dir = observe(&dir).expect("plan observes the directory");
        let planned_file = observe(&file).expect("plan observes the file");
        assert_eq!(
            compare_dir(&planned_dir, Mode::PRIVATE_DIR).action,
            Action::Create
        );
        assert_eq!(
            compare(
                &planned_file,
                &desired(b"Host *\n", Mode::PRIVATE_FILE),
                home.path(),
            )
            .action,
            Action::Create,
        );

        let mut created = CreatedDirs::new();
        created.declare(&dir, Mode::PRIVATE_DIR);
        let filled = stage(&file, Mode::PRIVATE_FILE, &planned_file, &mut created)
            .expect("stage")
            .fill(b"Host *\n")
            .expect("fill");
        assert!(
            filled.created_dirs().is_empty(),
            "the file's write made the declared directory, and leaves it to its target",
        );
        assert_eq!(
            mode_of_path(&dir),
            Mode::PRIVATE_DIR,
            "made at its declared mode"
        );
        filled.publish().expect("publish");
        assert!(created.contains(&dir));

        // Outside this apply's set, the same directory is one plan never saw.
        let err = ensure_dir(
            &dir,
            Mode::PRIVATE_DIR,
            &planned_dir,
            &mut CreatedDirs::new(),
        )
        .expect_err("a directory from nowhere is still refused");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        let ensured = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned_dir, &mut created)
            .expect("the create plan announced");
        assert_eq!(ensured.action, Action::Create);
        assert_eq!(
            ensured.prior.kind,
            Kind::Absent,
            "nothing was there before this apply"
        );
        assert_eq!(
            ensured.created_dirs,
            std::slice::from_ref(&dir),
            "the declared directory's entry names it as bx's",
        );

        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);
        assert_eq!(mode_of_path(&file), Mode::PRIVATE_FILE);
        assert_eq!(std::fs::read(&file).expect("read"), b"Host *\n");
        assert_eq!(
            dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR).action,
            Action::Unchanged,
            "the second plan is empty for the directory",
        );
        assert_eq!(
            outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE).action,
            Action::Unchanged,
            "and for the file",
        );
    }

    #[test]
    fn nested_directory_targets_end_at_their_declared_modes_in_either_order() {
        let mode_a = Mode::from_bits(0o750);
        for deeper_first in [false, true] {
            let order = if deeper_first { "a/b first" } else { "a first" };
            let home = guarded_home();
            let (a, b) = (home.child("a"), home.child("a/b"));
            let planned_a = observe(&a).expect("plan observes a");
            let planned_b = observe(&b).expect("plan observes a/b");

            let mut created = CreatedDirs::new();
            created.declare(&a, mode_a);
            created.declare(&b, Mode::PRIVATE_DIR);
            let (ensured_a, ensured_b) = if deeper_first {
                let b_done = ensure_dir(&b, Mode::PRIVATE_DIR, &planned_b, &mut created);
                let a_done = ensure_dir(&a, mode_a, &planned_a, &mut created);
                (a_done, b_done)
            } else {
                let a_done = ensure_dir(&a, mode_a, &planned_a, &mut created);
                let b_done = ensure_dir(&b, Mode::PRIVATE_DIR, &planned_b, &mut created);
                (a_done, b_done)
            };
            let ensured_a = ensured_a.unwrap_or_else(|e| panic!("{order}: a: {e:?}"));
            let ensured_b = ensured_b.unwrap_or_else(|e| panic!("{order}: a/b: {e:?}"));

            assert_eq!(ensured_a.action, Action::Create, "{order}");
            assert_eq!(ensured_b.action, Action::Create, "{order}");
            assert_eq!(mode_of_path(&a), mode_a, "{order}");
            assert_eq!(mode_of_path(&b), Mode::PRIVATE_DIR, "{order}");
            assert_eq!(ensured_a.created_dirs, std::slice::from_ref(&a), "{order}");
            // `a` is declared, so its own target owns it in either order: a
            // deeper target that had to create it does not claim it too.
            assert_eq!(
                ensured_b.created_dirs,
                std::slice::from_ref(&b),
                "{order}: a/b claims only itself",
            );
            assert_eq!(
                dir_outcome_for(&home, "a", mode_a).action,
                Action::Unchanged,
                "{order}: the second plan is empty",
            );
            assert_eq!(
                dir_outcome_for(&home, "a/b", Mode::PRIVATE_DIR).action,
                Action::Unchanged,
                "{order}: the second plan is empty",
            );
        }
    }

    /// Run `during`, watching `dir` from another thread, and return every mode
    /// `dir` had at an instant anything was inside it.
    fn modes_while_occupied<T>(dir: &Path, during: impl FnOnce() -> T) -> (T, Vec<Mode>) {
        /// Stops the watcher when dropped, so an assertion failing inside
        /// `during` unwinds to a report instead of leaving the scope waiting
        /// on a thread that never stops.
        struct Stop<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let done = std::sync::atomic::AtomicBool::new(false);
        let seen = Mutex::new(Vec::new());
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    let occupied =
                        std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some());
                    if occupied && let Ok(meta) = std::fs::symlink_metadata(dir) {
                        let mode = mode_of(&meta);
                        let mut seen = seen
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if !seen.contains(&mode) {
                            seen.push(mode);
                        }
                    }
                }
            });
            let _stop = Stop(&done);
            during()
        });
        let seen = seen
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (result, seen)
    }

    #[test]
    fn a_file_never_sits_in_a_directory_wider_than_its_directory_target_declares_in_either_order() {
        // ~/.ssh declared 0700 and ~/.ssh/notes declared 0644, both absent.
        // Applied file first, the write used to create ~/.ssh at 0755 and
        // publish a file any local user could read, until the directory target
        // narrowed it — and for good if the apply stopped in between.
        for file_first in [true, false] {
            let order = if file_first {
                "file first"
            } else {
                "directory first"
            };
            let home = guarded_home();
            let (dir, file) = (home.child(".ssh"), home.child(".ssh/notes"));
            let planned_dir = observe(&dir).expect("plan observes the directory");
            let planned_file = observe(&file).expect("plan observes the file");
            let mut created = CreatedDirs::new();
            created.declare(&dir, Mode::PRIVATE_DIR);

            let write_file = |created: &mut CreatedDirs| {
                let staged = stage(&file, Mode::DEFAULT_FILE, &planned_file, created)
                    .unwrap_or_else(|e| panic!("{order}: stage: {e:?}"));
                assert_eq!(
                    mode_of_path(&dir),
                    Mode::PRIVATE_DIR,
                    "{order}: the directory the temporary file sits in",
                );
                staged
                    .commit(b"notes\n")
                    .unwrap_or_else(|e| panic!("{order}: commit: {e:?}"));
                assert_eq!(
                    mode_of_path(&dir),
                    Mode::PRIVATE_DIR,
                    "{order}: the directory the file was published into",
                );
            };
            let apply_dir_target = |created: &mut CreatedDirs| {
                ensure_dir(&dir, Mode::PRIVATE_DIR, &planned_dir, created)
                    .unwrap_or_else(|e| panic!("{order}: ensure_dir: {e:?}"))
            };
            let (ensured, modes) = modes_while_occupied(&dir, || {
                if file_first {
                    write_file(&mut created);
                    apply_dir_target(&mut created)
                } else {
                    let ensured = apply_dir_target(&mut created);
                    write_file(&mut created);
                    ensured
                }
            });

            for mode in &modes {
                assert_eq!(
                    mode.bits() & !Mode::PRIVATE_DIR.bits(),
                    0,
                    "{order}: ~/.ssh was {mode} while something was in it; every mode seen: \
                     {modes:?}",
                );
            }
            assert_eq!(ensured.action, Action::Create, "{order}");
            assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR, "{order}");
            assert_eq!(mode_of_path(&file), Mode::DEFAULT_FILE, "{order}");
            assert_eq!(std::fs::read(&file).expect("read"), b"notes\n", "{order}");
            assert_eq!(
                dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR).action,
                Action::Unchanged,
                "{order}: the second plan is empty for the directory",
            );
            assert_eq!(
                outcome_for(&home, ".ssh/notes", b"notes\n", Mode::DEFAULT_FILE).action,
                Action::Unchanged,
                "{order}: and for the file",
            );
        }
    }

    #[test]
    fn a_file_beneath_a_declared_directory_still_wider_than_declared_is_refused() {
        let home = guarded_home();
        let (dir, file) = (home.child(".ssh"), home.child(".ssh/notes"));
        std::fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, Mode::DEFAULT_DIR).expect("the user's own wide ~/.ssh");
        let planned_dir = observe(&dir).expect("plan observes the directory");
        assert_eq!(
            compare_dir(&planned_dir, Mode::PRIVATE_DIR).action,
            Action::Modify
        );
        let planned_file = observe(&file).expect("plan observes the file");
        let deeper = home.child(".ssh/sub/notes");
        let planned_deeper = observe(&deeper).expect("plan observes the deeper file");
        let mut created = CreatedDirs::new();
        created.declare(&dir, Mode::PRIVATE_DIR);

        let err = stage(&file, Mode::DEFAULT_FILE, &planned_file, &mut created)
            .expect_err("a file is not published into a declared directory still at 0755");
        let Error::DirectoryTargetPending {
            path,
            dir: named,
            found,
            declared,
        } = &err
        else {
            panic!("expected DirectoryTargetPending, got {err:?}");
        };
        assert_eq!(path, &file);
        assert_eq!(named, &dir);
        assert_eq!(*found, Mode::DEFAULT_DIR);
        assert_eq!(*declared, Mode::PRIVATE_DIR);
        assert_eq!(err.path(), file);
        assert!(
            err.to_string()
                .contains("apply that directory target first"),
            "{err}"
        );
        // A declared directory further up governs a file deeper down as well,
        // and nothing beneath it is created either.
        let err = stage(&deeper, Mode::DEFAULT_FILE, &planned_deeper, &mut created)
            .expect_err("nor into a directory beneath it");
        assert!(
            matches!(&err, Error::DirectoryTargetPending { dir: named, .. } if *named == dir),
            "{err:?}"
        );
        assert_eq!(
            names_in(&dir),
            Vec::<OsString>::new(),
            "nothing was written"
        );

        // Narrowed first, the same writes go through.
        ensure_dir(&dir, Mode::PRIVATE_DIR, &planned_dir, &mut created).expect("the modify");
        stage(&file, Mode::DEFAULT_FILE, &planned_file, &mut created)
            .expect("stage")
            .commit(b"notes\n")
            .expect("commit");
        stage(&deeper, Mode::DEFAULT_FILE, &planned_deeper, &mut created)
            .expect("stage the deeper file")
            .commit(b"notes\n")
            .expect("commit");
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // A declared directory that is already no wider than declared refuses
        // nothing.
        let open = home.child("open");
        std::fs::create_dir(&open).expect("mkdir");
        set_mode(&open, Mode::PRIVATE_DIR).expect("chmod");
        let mut created = CreatedDirs::new();
        created.declare(&open, Mode::DEFAULT_DIR);
        let inside = home.child("open/f");
        let planned_inside = observe(&inside).expect("plan observes");
        stage(&inside, Mode::DEFAULT_FILE, &planned_inside, &mut created)
            .expect("a narrower directory than declared is no exposure")
            .commit(b"x")
            .expect("commit");
    }

    #[test]
    fn a_declared_directory_wider_only_in_its_execute_bits_is_refused() {
        let home = guarded_home();
        // A group or other execute bit on a directory is traversal: a 0711
        // directory lets anyone reach a 0644 file inside it by name, which is
        // exactly the exposure its 0700 declaration exists to close.
        for bits in [0o711, 0o701, 0o710] {
            let dir = home.child(format!("d{bits:o}"));
            std::fs::create_dir(&dir).expect("mkdir");
            set_mode(&dir, Mode::from_bits(bits)).expect("the user's own traversable directory");
            let file = dir.join("notes");
            let planned = observe(&file).expect("plan observes the file");
            let mut created = CreatedDirs::new();
            created.declare(&dir, Mode::PRIVATE_DIR);

            let err = stage(&file, Mode::DEFAULT_FILE, &planned, &mut created)
                .expect_err("a file is not published into a declared directory still traversable");
            let Error::DirectoryTargetPending {
                path,
                dir: named,
                found,
                declared,
            } = &err
            else {
                panic!("{bits:04o}: expected DirectoryTargetPending, got {err:?}");
            };
            assert_eq!(path, &file, "{bits:04o}");
            assert_eq!(named, &dir, "{bits:04o}");
            assert_eq!(*found, Mode::from_bits(bits), "{bits:04o}");
            assert_eq!(*declared, Mode::PRIVATE_DIR, "{bits:04o}");
            assert_eq!(
                names_in(&dir),
                Vec::<OsString>::new(),
                "{bits:04o}: nothing was written"
            );
        }

        // A directory that grants nothing its declaration does not is no
        // exposure, even when the declaration is the wider of the two.
        let open = home.child("open");
        std::fs::create_dir(&open).expect("mkdir");
        set_mode(&open, Mode::from_bits(0o750)).expect("chmod");
        let mut created = CreatedDirs::new();
        created.declare(&open, Mode::DEFAULT_DIR);
        let inside = open.join("f");
        let planned_inside = observe(&inside).expect("plan observes");
        stage(&inside, Mode::DEFAULT_FILE, &planned_inside, &mut created)
            .expect("0750 grants nothing a 0755 declaration does not")
            .commit(b"x")
            .expect("commit");
    }

    #[test]
    fn a_directory_a_write_created_before_its_declaration_is_refused_rather_than_adopted() {
        // A caller that never declared ~/.ssh: the write beneath it made it at
        // 0755 and published into it. Adopting it would hide that, and both
        // the write's entry and the directory target's would claim it.
        let home = guarded_home();
        let (dir, file) = (home.child(".ssh"), home.child(".ssh/config"));
        let planned_dir = observe(&dir).expect("plan observes the directory");
        let planned_file = observe(&file).expect("plan observes the file");
        let mut created = CreatedDirs::new();

        let filled = stage(&file, Mode::PRIVATE_FILE, &planned_file, &mut created)
            .expect("stage")
            .fill(b"Host *\n")
            .expect("fill");
        assert_eq!(
            filled.created_dirs(),
            std::slice::from_ref(&dir),
            "undeclared, the directory is the write's to claim",
        );
        filled.publish().expect("publish");
        assert_eq!(mode_of_path(&dir), Mode::DEFAULT_DIR);

        let err = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned_dir, &mut created)
            .expect_err("a directory made before its declaration is not adopted");
        let Error::UndeclaredDirectory {
            path,
            created: at,
            declared,
        } = &err
        else {
            panic!("expected UndeclaredDirectory, got {err:?}");
        };
        assert_eq!(path, &dir);
        assert_eq!(*at, Mode::DEFAULT_DIR);
        assert_eq!(*declared, Mode::PRIVATE_DIR);
        assert_eq!(err.path(), dir);
        assert!(
            err.to_string()
                .contains("declare every directory target before applying any target"),
            "{err}"
        );
        assert_eq!(mode_of_path(&dir), Mode::DEFAULT_DIR, "nothing was chmod'd");
        assert_eq!(
            dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR)
                .note
                .as_deref(),
            Some("mode 0755 -> 0700"),
            "the next plan announces the modify that narrows it",
        );
    }

    #[test]
    fn a_declared_directory_is_owned_by_its_directory_target_alone_in_either_order() {
        // With #9's `prune_dirs`, removing a file whose entry also claimed a
        // still-declared ~/.ssh removed the directory — and only when the file
        // had been applied first. Every directory has exactly one claimant: a
        // declared one its directory target, any other the call that made it.
        for file_first in [true, false] {
            let order = if file_first {
                "file first"
            } else {
                "directory first"
            };
            let home = guarded_home();
            let (deep, dir, file) = (
                home.child("deep"),
                home.child("deep/.ssh"),
                home.child("deep/.ssh/config"),
            );
            let planned_dir = observe(&dir).expect("plan observes the directory");
            let planned_file = observe(&file).expect("plan observes the file");
            let mut created = CreatedDirs::new();
            created.declare(&dir, Mode::PRIVATE_DIR);

            let write_file = |created: &mut CreatedDirs| {
                let filled = stage(&file, Mode::PRIVATE_FILE, &planned_file, created)
                    .unwrap_or_else(|e| panic!("{order}: stage: {e:?}"))
                    .fill(b"Host *\n")
                    .unwrap_or_else(|e| panic!("{order}: fill: {e:?}"));
                let claim = filled.created_dirs().to_vec();
                let entry = filled
                    .new_entry(home.path(), Mechanism::Own)
                    .expect("a portable entry");
                assert_eq!(
                    entry.created_dirs.len(),
                    claim.len(),
                    "{order}: the ledger entry claims what the write reports",
                );
                filled
                    .publish()
                    .unwrap_or_else(|e| panic!("{order}: publish: {e:?}"));
                claim
            };
            let apply_dir_target = |created: &mut CreatedDirs| {
                ensure_dir(&dir, Mode::PRIVATE_DIR, &planned_dir, created)
                    .unwrap_or_else(|e| panic!("{order}: ensure_dir: {e:?}"))
                    .created_dirs
            };
            let (file_claim, dir_claim) = if file_first {
                let file_claim = write_file(&mut created);
                (file_claim, apply_dir_target(&mut created))
            } else {
                let dir_claim = apply_dir_target(&mut created);
                (write_file(&mut created), dir_claim)
            };

            for directory in [&dir, &deep] {
                let claimants = [&file_claim, &dir_claim]
                    .iter()
                    .filter(|claim| claim.contains(directory))
                    .count();
                assert_eq!(
                    claimants,
                    1,
                    "{order}: {} is claimed by the file {file_claim:?} and the directory \
                     target {dir_claim:?}",
                    directory.display(),
                );
            }
            assert_eq!(
                dir_claim.first(),
                Some(&dir),
                "{order}: the declared directory is its target's",
            );
            let (expected_file, expected_dir) = if file_first {
                (vec![deep.clone()], vec![dir.clone()])
            } else {
                (Vec::new(), vec![dir.clone(), deep.clone()])
            };
            assert_eq!(file_claim, expected_file, "{order}: the file's claim");
            assert_eq!(dir_claim, expected_dir, "{order}: the directory's claim");

            // `rm` of the file, pruned the way a reversal prunes: unlink, then
            // remove its claimed directories deepest first while they are empty.
            std::fs::remove_file(&file).expect("unlink");
            for claimed in &file_claim {
                if std::fs::remove_dir(claimed).is_err() {
                    break;
                }
            }
            assert!(
                dir.is_dir(),
                "{order}: removing the file leaves the directory that is still declared",
            );
            assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR, "{order}");
        }
    }

    #[test]
    fn a_directory_recreated_at_a_path_this_apply_created_is_not_adopted() {
        let home = guarded_home();
        let (dir, file) = (home.child(".ssh"), home.child(".ssh/config"));
        let planned_dir = observe(&dir).expect("plan observes the directory");
        let planned_file = observe(&file).expect("plan observes the file");
        let mut created = CreatedDirs::new();
        created.declare(&dir, Mode::PRIVATE_DIR);
        stage(&file, Mode::PRIVATE_FILE, &planned_file, &mut created)
            .expect("stage")
            .commit(b"Host *\n")
            .expect("commit");
        assert!(created.contains(&dir));

        // Another tool moves bx's directory aside and makes its own at the same
        // path. The moved one stays allocated under its new name, so the new
        // directory cannot reuse its inode number.
        std::fs::rename(&dir, home.child(".ssh.moved")).expect("move aside");
        std::fs::create_dir(&dir).expect("their own directory");
        set_mode(&dir, Mode::from_bits(0o770)).expect("at their own mode");

        let err = ensure_dir(&dir, Mode::PRIVATE_DIR, &planned_dir, &mut created)
            .expect_err("a directory from somebody else at the same path is not bx's create");
        assert!(matches!(err, Error::Changed { .. }), "{err:?}");
        assert_eq!(
            mode_of_path(&dir),
            Mode::from_bits(0o770),
            "their directory keeps its mode",
        );
        assert_eq!(names_in(&dir), Vec::<OsString>::new());
    }

    #[test]
    fn fill_syncs_the_temporary_file_before_it_returns() {
        let home = guarded_home();
        let staged = stage_now(&home.child("f"), Mode::DEFAULT_FILE).expect("stage");
        let temp = staged.temp_path().to_path_buf();

        let (filled, events) = durable::recording(|| staged.fill(b"x"));
        let filled = filled.expect("fill");

        assert_eq!(
            events,
            [durable::Event::SyncFile(temp)],
            "the content is fsynced inside fill, so a journal recording its intent \
             after fill returns is recording durable bytes",
        );
        filled.abandon();
    }

    #[test]
    fn publish_syncs_the_directory_only_after_the_rename() {
        let home = guarded_home();
        let dest = home.child(".config/f");
        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();

        let (published, events) = durable::recording(|| filled.publish());
        published.expect("publish");

        let dir = home.child(".config");
        assert_eq!(
            events,
            [
                durable::Event::OpenDir(dir.clone()),
                durable::Event::Rename {
                    from: temp,
                    to: dest.clone(),
                },
                durable::Event::SyncDir(dir),
            ],
            "the directory is opened before the rename and fsynced after it",
        );
    }

    #[test]
    fn write_atomically_makes_every_durability_call_in_order() {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        let (result, events) =
            durable::recording(|| write_atomically(&dest, b"v2", Mode::DEFAULT_FILE));
        result.expect("write");

        let [
            durable::Event::SyncFile(synced),
            durable::Event::OpenDir(opened),
            durable::Event::Rename { from, to },
            durable::Event::SyncDir(dir_synced),
        ] = events.as_slice()
        else {
            panic!("expected sync, open, rename, sync; got {events:?}");
        };
        assert_eq!(synced, from, "the file synced is the file renamed");
        assert_eq!(to, &dest);
        assert_eq!(opened, home.path());
        assert_eq!(dir_synced, home.path());
    }

    #[test]
    fn a_failed_rename_syncs_no_directory() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so the rename is not refused.
            return;
        }
        let home = guarded_home();
        let dir = home.child("d");
        let dest = dir.join("f");
        seed(&dest, b"theirs", Mode::DEFAULT_FILE);
        set_mode(&dir, Mode::PRIVATE_DIR).expect("chmod");
        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();
        // Read and search but no write: the directory still opens and the
        // destination is still what stage observed, so the rename itself is
        // the call that fails.
        set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

        let (published, events) = durable::recording(|| filled.publish());
        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for the assertions");

        let refused = published.expect_err("an unwritable directory refuses the rename");
        assert_eq!(refused.dest, dest, "the refusal names the write");
        let err = refused.into_error();
        let Error::Write { path, source } = &err else {
            panic!("expected a write error, got {err:?}");
        };
        assert_eq!(path, &dest, "the rename's error names the destination");
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            events,
            [durable::Event::OpenDir(dir.clone())],
            "no rename landed and no directory was synced",
        );
        assert_eq!(std::fs::read(&dest).expect("read"), b"theirs");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        // The directory that refused the rename refused the unlink too.
        assert!(temp.exists(), "the temporary file is left for recovery");
        std::fs::remove_file(&temp).expect("clean up the leftover");
        assert_eq!(names_in(&dir), vec![OsString::from("f")]);
    }

    #[test]
    fn ensure_dir_creates_implicit_ancestors_at_the_default_dir_mode() {
        let home = guarded_home();
        assert_eq!(
            apply_dir(&home.child("a/b/c"), Mode::PRIVATE_DIR)
                .expect("create")
                .action,
            Action::Create,
        );
        assert_eq!(mode_of_path(&home.child("a")), Mode::DEFAULT_DIR);
        assert_eq!(mode_of_path(&home.child("a/b")), Mode::DEFAULT_DIR);
        assert_eq!(mode_of_path(&home.child("a/b/c")), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_dir_refuses_a_path_a_file_occupies() {
        let home = guarded_home();
        let path = home.child("f");
        seed(&path, b"x", Mode::DEFAULT_FILE);
        assert_eq!(
            apply_dir(&path, Mode::PRIVATE_DIR).expect("report").action,
            Action::Conflict,
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"x");
        assert_eq!(mode_of_path(&path), Mode::DEFAULT_FILE);
    }

    #[test]
    fn a_trailing_slash_does_not_turn_a_symlink_into_what_it_points_at() {
        // `lstat("link/")` resolves the link, because a trailing slash demands
        // a directory, and `chmod("link/")` changes the directory at the far
        // end. bx decides about the component the target names, however the
        // path is spelled.
        let home = guarded_home();
        std::fs::create_dir(home.child("real")).expect("mkdir");
        set_mode(&home.child("real"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        for spelled in ["link/", "link//", "link/."] {
            let path = home.child(spelled);
            let observed = observe(&path).expect("observe");
            assert_eq!(observed.kind, Kind::Symlink, "{spelled}");
            assert_eq!(observed.path, home.child("link"), "{spelled}");
            assert_eq!(
                compare_dir(&observed, Mode::PRIVATE_DIR).action,
                Action::Conflict,
                "{spelled}",
            );
            assert_eq!(
                ensure_dir(&path, Mode::PRIVATE_DIR, &observed, &mut CreatedDirs::new())
                    .expect("a verdict")
                    .action,
                Action::Conflict,
                "{spelled}",
            );
            let err = set_mode(&path, Mode::PRIVATE_DIR).expect_err("a link is not chmod'd");
            assert!(matches!(err, Error::Symlink(_)), "{spelled}: {err:?}");
            let err = write_atomically(&path, b"x", Mode::DEFAULT_FILE)
                .expect_err("a link is not written over");
            assert!(matches!(err, Error::Symlink(_)), "{spelled}: {err:?}");

            assert_eq!(
                mode_of_path(&home.child("real")),
                Mode::DEFAULT_DIR,
                "{spelled}: the link's target keeps its mode",
            );
            assert_eq!(
                names_in(&home.child("real")),
                Vec::<OsString>::new(),
                "{spelled}: nothing was written through the link",
            );
        }

        // A link to a file, with a slash the kernel would refuse as ENOTDIR,
        // is still the link bx refuses to replace rather than a read error.
        seed(&home.child("file"), b"theirs\n", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink("file", home.child("flink")).expect("symlink");
        let err = write_atomically(&home.child("flink/"), b"x", Mode::DEFAULT_FILE)
            .expect_err("a link is not written over");
        assert!(matches!(err, Error::Symlink(_)), "{err:?}");
        assert_eq!(err.path(), home.child("flink"));
        assert_eq!(
            std::fs::read(home.child("file")).expect("read"),
            b"theirs\n"
        );
    }

    #[test]
    fn ensure_dir_refuses_a_symlink_where_a_directory_is_declared() {
        let home = guarded_home();
        std::fs::create_dir(home.child("real")).expect("mkdir");
        set_mode(&home.child("real"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        assert_eq!(
            apply_dir(&home.child("link"), Mode::PRIVATE_DIR)
                .expect("report")
                .action,
            Action::Conflict,
        );
        assert_eq!(
            mode_of_path(&home.child("real")),
            Mode::DEFAULT_DIR,
            "the link's target keeps its mode",
        );
        assert!(
            std::fs::symlink_metadata(home.child("link"))
                .expect("stat")
                .file_type()
                .is_symlink(),
        );
    }

    /// Assert that `result` is the refusal of a `..` component in `path`.
    fn assert_parent_component_refused<T: std::fmt::Debug>(
        what: &str,
        result: Result<T, Error>,
        path: &Path,
    ) {
        match result {
            Err(Error::ParentComponent(named)) => assert_eq!(named, path, "{what}"),
            other => panic!("{what}: expected ParentComponent, got {other:?}"),
        }
    }

    #[test]
    fn a_parent_component_is_refused_rather_than_resolved_through_a_link() {
        // `lnk/../f` with `lnk -> elsewhere/sub`: the kernel resolves `..`
        // after following the link, so it names `elsewhere/f`, while any
        // lexical reading of the path — the one a ledger key is made from —
        // names `f`. A write through it would record one file and change
        // another, and `rm` would restore the wrong one.
        let home = guarded_home();
        std::fs::create_dir_all(home.child("elsewhere/sub")).expect("mkdir");
        std::os::unix::fs::symlink("elsewhere/sub", home.child("lnk")).expect("symlink");
        seed(&home.child("elsewhere/f"), b"theirs\n", Mode::DEFAULT_FILE);

        let dotted = home.child("lnk/../f");
        assert_parent_component_refused("observe", observe(&dotted), &dotted);
        assert_parent_component_refused(
            "write_atomically",
            write_atomically(&dotted, b"ours\n", Mode::PRIVATE_FILE),
            &dotted,
        );
        let planned = observe(&home.child("f")).expect("plan observes the lexical name");
        assert_parent_component_refused(
            "stage",
            stage(
                &dotted,
                Mode::PRIVATE_FILE,
                &planned,
                &mut CreatedDirs::new(),
            ),
            &dotted,
        );
        assert_parent_component_refused("set_mode", set_mode(&dotted, Mode::PRIVATE_FILE), &dotted);
        let dotted_dir = home.child("lnk/../d");
        let planned_dir = observe(&home.child("d")).expect("plan observes the lexical name");
        assert_parent_component_refused(
            "ensure_dir",
            ensure_dir(
                &dotted_dir,
                Mode::PRIVATE_DIR,
                &planned_dir,
                &mut CreatedDirs::new(),
            ),
            &dotted_dir,
        );
        // A final `..`, and a relative path that starts with one, likewise.
        let trailing = home.child("lnk/..");
        assert_parent_component_refused("a final ..", observe(&trailing), &trailing);
        assert_parent_component_refused(
            "a relative ..",
            observe(Path::new("../f")),
            Path::new("../f"),
        );

        // Nothing was written or changed at either name.
        assert_eq!(
            std::fs::read(home.child("elsewhere/f")).expect("read"),
            b"theirs\n"
        );
        assert_eq!(mode_of_path(&home.child("elsewhere/f")), Mode::DEFAULT_FILE);
        assert!(std::fs::symlink_metadata(home.child("f")).is_err());
        assert!(std::fs::symlink_metadata(home.child("d")).is_err());
        assert!(std::fs::symlink_metadata(home.child("elsewhere/d")).is_err());
        assert_eq!(
            names_in(&home.child("elsewhere")),
            [OsString::from("f"), OsString::from("sub")],
            "no temporary file is left",
        );
        assert_eq!(
            Error::ParentComponent(dotted.clone()).path(),
            dotted,
            "the refusal names the path as given",
        );
    }

    #[test]
    fn observe_refuses_a_path_with_no_parent() {
        let err = observe(Path::new("/")).expect_err("must fail");
        assert!(matches!(err, Error::NoParent(_)), "{err:?}");
    }

    #[test]
    fn an_entry_that_cannot_be_made_portable_is_refused_not_recorded() {
        // `Portable::from_path` refuses rather than renaming a path it cannot
        // represent, so the entry is an error rather than a ledger key that
        // names a different file.
        let home = guarded_home();
        let dest = home.child(".config/tool/x.conf");
        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");

        let err = filled
            .new_entry(Path::new("relative/home"), Mechanism::Own)
            .expect_err("a relative home makes nothing portable");
        assert!(
            matches!(
                &err,
                Error::NotPortable {
                    source: crate::paths::Error::HomeNotAbsolute(_),
                    ..
                }
            ),
            "{err:?}",
        );
        assert_eq!(err.path(), dest);
        assert!(err.to_string().contains("cannot be recorded"), "{err}");

        // Under the real home the same write yields its entry.
        let entry = filled
            .new_entry(home.path(), Mechanism::Own)
            .expect("portable under the real home");
        assert_eq!(entry.path.as_str(), "~/.config/tool/x.conf");
    }

    /// A locked, writable ledger for a guarded home.
    fn ledger_for(home: &GuardedHome) -> (StateDir, ExclusiveLock, Ledger) {
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure the state directory");
        let lock = ExclusiveLock::acquire(&dir).expect("acquire the lock");
        let ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        (dir, lock, ledger)
    }

    #[test]
    fn the_prior_bytes_are_recordable_before_the_rename_and_restore_exactly() {
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host old\n", Mode::from_bits(0o640));

        let filled = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"Host new\n")
            .expect("fill");

        // The recording point: the new content is durable, the destination is
        // still the old content, and the entry describes both.
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host old\n");
        let recorded = ledger
            .record(
                filled
                    .new_entry(home.path(), Mechanism::Own)
                    .expect("a portable entry"),
            )
            .expect("record")
            .clone();
        filled.publish().expect("publish");

        assert_eq!(recorded.path.as_str(), "~/.ssh/config");
        assert_eq!(recorded.written, ContentHash::of(b"Host new\n"));
        assert_eq!(recorded.mode, Mode::PRIVATE_FILE);
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host new\n");
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);

        // Reversibility: the ledger alone reproduces the displaced file, byte
        // for byte and mode for mode.
        let Prior::Existed(reference) = &recorded.prior else {
            panic!("the prior state must be Existed, got {:?}", recorded.prior);
        };
        assert_eq!(reference.mode, Mode::from_bits(0o640));
        assert_eq!(reference.len, 9);
        let bytes = ledger
            .restore_bytes(&dir, reference)
            .expect("the blob is durable by the time record returns");
        write_atomically(&dest, &bytes, reference.mode).expect("restore");
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host old\n");
        assert_eq!(mode_of_path(&dest), Mode::from_bits(0o640));
    }

    #[test]
    fn a_link_at_a_blob_name_is_refused_with_a_remedy_that_fits_a_path_bx_owns() {
        // `write_atomically` refuses a symlink, and `Ledger::record` snapshots
        // the prior through it, so a link at `restore/<digest>` — from a
        // restored backup, an `rsync --links`, a hand — fails every record that
        // needs that content. bx will not unlink it: it made no link, so the
        // link is somebody's, and removing it inside bx's own directory is
        // still removing it. What it owes is a remedy that makes sense for a
        // file nobody declared.
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host old\n", Mode::from_bits(0o640));
        let blob = dir.restore().join(ContentHash::of(b"Host old\n").to_hex());
        std::fs::create_dir_all(dir.restore()).expect("restore/");
        let elsewhere = home.child("elsewhere");
        std::fs::write(&elsewhere, b"not a blob\n").expect("seed");
        std::os::unix::fs::symlink(&elsewhere, &blob).expect("symlink");

        let filled = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"Host new\n")
            .expect("fill");
        let entry = filled
            .new_entry(home.path(), Mechanism::Own)
            .expect("a portable entry");
        let err = ledger
            .record(entry.clone())
            .expect_err("a link at the blob name is not bx's to replace");
        let message = err.to_string();
        assert!(
            message.contains(&blob.display().to_string()),
            "the refusal names the file to remove: {message}",
        );
        assert!(message.contains("Remove the link"), "{message}");
        assert_eq!(
            std::fs::read_link(&blob).expect("readlink"),
            elsewhere,
            "the link and what it names are left alone",
        );
        assert_eq!(std::fs::read(&elsewhere).expect("read"), b"not a blob\n");

        // The remedy the message gives is the whole repair: the blob is
        // content-addressed, so the next record reconstructs it.
        std::fs::remove_file(&blob).expect("the remedy");
        ledger.record(entry).expect("record repairs itself");
        assert_eq!(std::fs::read(&blob).expect("read"), b"Host old\n");
        filled.publish().expect("publish");
    }

    #[test]
    fn a_ledger_entry_for_a_refused_publish_is_withdrawn_through_what_the_refusal_names() {
        // The one state the seam makes reachable and no other test reached:
        // `record` has succeeded, so the prior bytes are durable in `restore/`
        // and the in-memory ledger claims the target — and then `publish`
        // refuses, so the destination still holds what the user has.
        //
        // Saving the ledger from here would make `bx rm` write the recorded
        // prior over content bx never replaced. What stops it is that the
        // refusal names the write, so the entry can be withdrawn.
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host old\n", Mode::from_bits(0o640));

        let filled = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"Host new\n")
            .expect("fill");
        let key = Portable::from_path(&dest, home.path()).expect("portable");
        let withdrawal = ledger.withdrawal(&key);
        let recorded = ledger
            .record(
                filled
                    .new_entry(home.path(), Mechanism::Own)
                    .expect("a portable entry"),
            )
            .expect("record")
            .clone();
        let Prior::Existed(reference) = &recorded.prior else {
            panic!("the prior state must be Existed, got {:?}", recorded.prior);
        };

        // The user saves over the destination between the record and the
        // rename, which is exactly what `publish` refuses.
        std::fs::write(&dest, b"Host theirs\n").expect("the user saves");
        let refused = filled.publish().expect_err("the destination changed");
        assert_eq!(refused.dest, dest, "the refusal names the write");
        assert!(
            matches!(refused.error, Error::Changed { .. }),
            "{:?}",
            refused.error,
        );
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"Host theirs\n",
            "bx wrote nothing",
        );

        // What the ledger is left holding: the entry, and the blob its prior
        // names. Both are real, and both describe a write that did not happen.
        assert_eq!(ledger.len(), 1, "the entry is still in the ledger");
        assert_eq!(
            ledger
                .restore_bytes(&dir, reference)
                .expect("the blob record fsynced"),
            b"Host old\n",
            "the snapshot is durable, and it is not what is on disk now",
        );

        // The withdrawal: the refusal names the entry's key, and the entry
        // before the record was none, so none is put back.
        assert_eq!(
            Portable::from_path(&refused.dest, home.path()).expect("portable"),
            key,
            "the refusal names the key the withdrawal was taken for",
        );
        let withdrawn = ledger
            .withdraw(withdrawal)
            .expect("the entry is there to withdraw");
        assert_eq!(withdrawn.written, ContentHash::of(b"Host new\n"));
        assert!(ledger.is_empty(), "nothing claims the target now");
        ledger.save().expect("save");

        // Read back from disk: no entry, so `bx rm` has nothing to restore
        // over the user's file. The blob is left in `restore/`, which is
        // content-addressed and reused rather than owned by one entry.
        let reread = LedgerView::read(&dir, home.path()).expect("read").value;
        assert!(reread.is_empty(), "the durable ledger claims nothing");
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host theirs\n");
    }

    #[test]
    fn a_refused_re_record_is_withdrawn_to_the_entry_it_replaced() {
        // Every apply after the first re-records a target bx already has an
        // entry for, and that entry holds the prior the user had before bx.
        // Withdrawing a refused re-record by dropping the key — `forget` —
        // loses that prior for good. The withdrawal puts back the whole entry
        // as it was before the record: prior, history and all.
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host old\n", Mode::from_bits(0o640));
        let key = Portable::from_path(&dest, home.path()).expect("portable");

        // The first apply lands, and the ledger is saved.
        let first = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"Host v1\n")
            .expect("fill");
        ledger
            .record(
                first
                    .new_entry(home.path(), Mechanism::Own)
                    .expect("a portable entry"),
            )
            .expect("record");
        first.publish().expect("publish");
        ledger.save().expect("save");
        let before = ledger.get(&key).expect("recorded").clone();
        let Prior::Existed(original) = &before.prior else {
            panic!("the prior state must be Existed, got {:?}", before.prior);
        };

        // The user edits the result, so the second apply's record adopts the
        // edit as the prior and moves the original to the history — the
        // re-record that changes the most.
        std::fs::write(&dest, b"Host edited\n").expect("the user edits");
        let withdrawal = ledger.withdrawal(&key);
        let second = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(b"Host v2\n")
            .expect("fill");
        let recorded = ledger
            .record(
                second
                    .new_entry(home.path(), Mechanism::Own)
                    .expect("a portable entry"),
            )
            .expect("record")
            .clone();
        assert_ne!(recorded, before, "the re-record changed the entry");
        assert_eq!(recorded.superseded, vec![original.clone()]);

        // The user saves again between the record and the rename.
        std::fs::write(&dest, b"Host theirs\n").expect("the user saves");
        let refused = second.publish().expect_err("the destination changed");
        assert!(
            matches!(refused.error, Error::Changed { .. }),
            "{:?}",
            refused.error,
        );
        assert_eq!(
            Portable::from_path(&refused.dest, home.path()).expect("portable"),
            key,
        );

        let withdrawn = ledger.withdraw(withdrawal).expect("the refused record");
        assert_eq!(withdrawn, recorded, "the refused record is handed back");
        assert_eq!(
            ledger.get(&key),
            Some(&before),
            "the entry is exactly what it was before the record",
        );
        ledger.save().expect("save");

        // Durably: `bx rm` still restores the file the user had before bx.
        let reread = LedgerView::read(&dir, home.path()).expect("read").value;
        let entry = reread.get(&key).expect("the entry survives the withdrawal");
        assert_eq!(entry, &before);
        assert_eq!(
            reread
                .restore_bytes(&dir, original)
                .expect("the original prior"),
            b"Host old\n",
        );
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host theirs\n");
    }

    #[test]
    fn re_applying_after_an_edit_keeps_every_byte_the_user_wrote() {
        // The ordinary case, not an edge one: a user applies, edits the result,
        // and applies again. The second apply displaces the user's edit, so the
        // edit is what the user last had and becomes the prior `bx rm` restores
        // (#7, decision 13); the original file it replaces as the prior is not
        // dropped but kept in `superseded`. Losing either set of bytes, or
        // letting a later `PriorBytes::Absent` — which is what a writer over an
        // *absent* destination supplies — turn the prior into "unlink it",
        // turns Invariant 4 into its opposite, and the writer is the side that
        // supplies the prior, so the writer's tests are a place this has to be
        // pinned.
        //
        // This test used to be `..._still_restores_the_user_s_original_file`
        // and assert decision 7's first-prior-wins rule, under which rm wrote
        // `Host theirs` over the user's `Host edited` and the edit existed
        // nowhere.
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host theirs\n", Mode::from_bits(0o640));

        for content in [b"Host v1\n", b"Host v2\n"] {
            let filled = stage_now(&dest, Mode::PRIVATE_FILE)
                .expect("stage")
                .fill(content)
                .expect("fill");
            ledger
                .record(
                    filled
                        .new_entry(home.path(), Mechanism::Own)
                        .expect("a portable entry"),
                )
                .expect("record");
            filled.publish().expect("publish");
            // The user edits what bx wrote, so the second apply's `observe`
            // finds neither the user's original nor bx's output.
            std::fs::write(&dest, b"Host edited\n").expect("the user edits it");
        }

        let recorded = ledger
            .record(NewEntry::new(
                Portable::from_path(&dest, home.path()).expect("portable"),
                ContentHash::of(b"Host v2\n"),
                Mode::PRIVATE_FILE,
                Mechanism::Own,
                PriorBytes::Absent,
            ))
            .expect("record")
            .clone();

        let Prior::Existed(reference) = &recorded.prior else {
            panic!(
                "an absent incoming prior may not turn a snapshot into an unlink, got {:?}",
                recorded.prior
            );
        };
        // The edit was written over bx's 0600 output, so it carries that mode.
        assert_eq!(reference.mode, Mode::PRIVATE_FILE);
        assert_eq!(
            ledger
                .restore_bytes(&dir, reference)
                .expect("restore bytes"),
            b"Host edited\n",
            "the prior is what the user last had: the edit the second apply displaced",
        );

        assert_eq!(
            recorded.superseded.len(),
            1,
            "the original is kept, once: {:?}",
            recorded.superseded,
        );
        let original = &recorded.superseded[0];
        assert_eq!(original.mode, Mode::from_bits(0o640));
        assert_eq!(
            ledger
                .restore_bytes(&dir, original)
                .expect("restore the original"),
            b"Host theirs\n",
            "the file the user had before bx ever touched it is still restorable",
        );
    }

    #[test]
    fn a_prior_mode_is_recordable_for_a_mode_only_change() {
        let home = guarded_home();
        let (dir, _lock, mut ledger) = ledger_for(&home);
        let dest = home.child(".ssh/config");
        seed(&dest, b"Host *\n", Mode::DEFAULT_FILE);

        // The one read, shared by the comparison and the apply.
        let want = desired(b"Host *\n", Mode::PRIVATE_FILE);
        let planned = observe(&dest).expect("observe");
        let outcome = compare(&planned, &want, home.path());
        assert_eq!(outcome.action, Action::Modify);
        assert!(!outcome.content_drift);

        // Applied like any other Modify: staged against plan's observation,
        // with the same bytes at the new mode.
        let filled = stage(&dest, want.mode, &planned, &mut CreatedDirs::new())
            .expect("stage")
            .fill(want.bytes)
            .expect("fill");
        let recorded = ledger
            .record(
                filled
                    .new_entry(home.path(), Mechanism::Own)
                    .expect("a portable entry"),
            )
            .expect("record")
            .clone();
        filled.publish().expect("publish");

        let Prior::Existed(reference) = &recorded.prior else {
            panic!("the prior state must be Existed, got {:?}", recorded.prior);
        };
        assert_eq!(reference.mode, Mode::DEFAULT_FILE);
        assert_eq!(
            Some(recorded.written),
            planned.digest(),
            "a mode-only change writes back the content it found",
        );
        assert_eq!(recorded.written, ContentHash::of(b"Host *\n"));
        assert_eq!(recorded.mode, Mode::PRIVATE_FILE);
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host *\n");
        // Idempotent: the second plan is empty.
        assert_eq!(
            compare(&observe(&dest).expect("observe again"), &want, home.path()).action,
            Action::Unchanged,
        );

        // Reversing it restores the prior bytes at the prior mode.
        let bytes = ledger
            .restore_bytes(&dir, reference)
            .expect("the prior bytes are durable");
        write_atomically(&dest, &bytes, reference.mode).expect("reverse");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host *\n");
    }

    #[test]
    fn a_created_dirs_set_answers_for_a_directory_however_it_is_spelled() {
        // `declare` normalised its key and `declared` did not, so an external
        // caller — the apply engine that will hold one set for the whole apply
        // — could declare `~/.ssh` and be told `~/.ssh/` is undeclared. Every
        // spelling below names one directory to the kernel, and now to this set.
        //
        // What this pins is `DirKey::of`'s normalisation. It is not a test of
        // `Path`'s component-wise `Ord`: measured at r4 round 2, a key holding
        // raw `OsStr` bytes passes this as long as it normalises, and fails
        // only when it does neither.
        let home = guarded_home();
        let dir = home.child(".ssh");
        let spellings = [
            dir.clone(),
            dir.join(""),                                         // a trailing separator
            dir.parent().expect("a home").join(".").join(".ssh"), // a `.` component
            dir.components().collect::<PathBuf>(),                // rebuilt component by component
        ];

        for declared_as in &spellings {
            let mut created = CreatedDirs::new();
            created.declare(declared_as, Mode::PRIVATE_DIR);
            for asked_as in &spellings {
                assert_eq!(
                    created.declared(asked_as),
                    Some(Mode::PRIVATE_DIR),
                    "declared as {}, asked as {}",
                    declared_as.display(),
                    asked_as.display(),
                );
            }
            assert_eq!(created.declared(&home.child(".config")), None);
        }

        // `contains` and the claim rule key on the same thing: a write that
        // creates the directory under one spelling leaves it unclaimed for a
        // target that declared it under another.
        let mut created = CreatedDirs::new();
        created.declare(&dir.join(""), Mode::PRIVATE_DIR);
        let dest = dir.join("config");
        let planned = observe(&dest).expect("observe");
        let filled = stage(&dest, Mode::PRIVATE_FILE, &planned, &mut created)
            .expect("stage")
            .fill(b"Host *\n")
            .expect("fill");
        assert_eq!(
            filled.created_dirs(),
            Vec::<PathBuf>::new(),
            "the declared directory is its own target's to claim, however it was spelled",
        );
        assert_eq!(
            mode_of_path(&dir),
            Mode::PRIVATE_DIR,
            "at its declared mode"
        );
        for asked_as in &spellings {
            assert!(
                created.contains(asked_as),
                "contains {}",
                asked_as.display()
            );
        }
        filled.publish().expect("publish");
    }

    #[test]
    fn the_directories_a_write_invented_are_recorded_deepest_first() {
        let home = guarded_home();
        let dest = home.child(".config/a/b/f");
        let mut created = CreatedDirs::new();
        assert!(
            !created.contains(&home.child(".config")),
            "a fresh set contains nothing",
        );
        // Declared by a directory target, but never made by anything.
        let declared_only = home.child("declared-only");
        created.declare(&declared_only, Mode::PRIVATE_DIR);
        let planned = observe(&dest).expect("plan observes");
        let filled = stage(&dest, Mode::DEFAULT_FILE, &planned, &mut created)
            .expect("stage")
            .fill(b"x")
            .expect("fill");

        assert_eq!(
            filled.created_dirs(),
            [
                home.child(".config/a/b"),
                home.child(".config/a"),
                home.child(".config"),
            ],
            "deepest first, which is the order a reversal removes them in",
        );
        let entry = filled
            .new_entry(home.path(), Mechanism::Own)
            .expect("a portable entry");
        assert_eq!(
            entry
                .created_dirs
                .iter()
                .map(Portable::as_str)
                .collect::<Vec<_>>(),
            ["~/.config/a/b", "~/.config/a", "~/.config"],
        );
        assert_eq!(
            entry.prior,
            PriorBytes::Absent,
            "nothing was displaced, and that is not the same as empty bytes",
        );
        filled.publish().expect("publish");

        for made in [".config/a/b", ".config/a", ".config"] {
            assert!(created.contains(&home.child(made)), "{made} was made here");
        }
        assert!(
            !created.contains(&home.child(".config/a/sibling")),
            "a sibling of a directory this apply made is not one it made",
        );
        assert!(
            !created.contains(home.path()),
            "an existing parent the write did not create is not contained",
        );
        assert!(
            !created.contains(&declared_only),
            "a declared directory nothing made is not contained",
        );
    }

    #[test]
    fn a_directory_that_was_already_there_is_not_recorded_as_one_bx_invented() {
        let home = guarded_home();
        let path = home.child("theirs");
        std::fs::create_dir(&path).expect("mkdir");
        set_mode(&path, Mode::DEFAULT_DIR).expect("chmod");

        // The race `create_missing_dirs` cannot design away: the stat said
        // nothing was there, and by the time the `mkdir` ran another tool had
        // made it. It is that tool's directory, and `bx rm` removing it would
        // be deleting something bx did not create.
        assert!(
            create_dir_at(&path, Mode::PRIVATE_DIR)
                .expect("create_dir_at")
                .is_none(),
            "an existing directory was not created by this call",
        );
        assert_eq!(
            mode_of_path(&path),
            Mode::DEFAULT_DIR,
            "and its mode is not bx's to take either",
        );

        assert!(
            create_dir_at(&home.child("ours"), Mode::PRIVATE_DIR)
                .expect("create_dir_at")
                .is_some(),
            "a directory bx made is reported as bx's",
        );
        assert_eq!(mode_of_path(&home.child("ours")), Mode::PRIVATE_DIR);
    }

    #[test]
    fn a_write_over_nothing_records_that_nothing_was_there() {
        let home = guarded_home();
        let dest = home.child("f");
        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");
        assert_eq!(filled.prior().prior_bytes(), PriorBytes::Absent);
        assert_eq!(filled.prior().digest(), None);
        assert!(filled.created_dirs().is_empty());
        assert_eq!(filled.written(), ContentHash::of(b"x"));
    }

    #[test]
    fn a_non_file_destination_has_no_prior_bytes_to_record() {
        let home = guarded_home();
        std::fs::create_dir(home.child("d")).expect("mkdir");
        std::os::unix::fs::symlink("d", home.child("l")).expect("symlink");

        for rel in ["d", "l"] {
            let observed = observe(&home.child(rel)).expect("observe");
            assert_eq!(observed.prior_bytes(), PriorBytes::Absent, "{rel}");
            assert_eq!(observed.digest(), None, "{rel}");
        }
    }

    #[test]
    fn ensure_dir_under_a_dangling_link_is_a_conflict_not_a_write_error() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child("d")).expect("symlink");

        assert_eq!(
            apply_dir(&home.child("d/a"), Mode::PRIVATE_DIR)
                .expect("a verdict, not an error")
                .action,
            Action::Conflict,
        );
        assert!(
            std::fs::symlink_metadata(home.child("nowhere")).is_err(),
            "nothing was created at the far end",
        );
    }

    #[test]
    fn a_non_directory_further_up_is_a_conflict_not_a_read_error() {
        let home = guarded_home();
        seed(&home.child("f"), b"a file", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink("loop", home.child("loop")).expect("symlink");
        std::os::unix::fs::symlink("f", home.child("l")).expect("symlink");

        for (rel, culprit) in [("f/sub/x", "f"), ("loop/a/x", "loop"), ("l/a/x", "l")] {
            let outcome = outcome_for(&home, rel, b"x", Mode::DEFAULT_FILE);
            assert_eq!(outcome.action, Action::Conflict, "{rel}");
            let note = outcome.note.expect("the cause must be named");
            assert!(
                note.contains(&home.child(culprit).display().to_string()),
                "{rel}: {note}",
            );

            let err = write_atomically(&home.child(rel), b"x", Mode::DEFAULT_FILE)
                .expect_err("must refuse");
            assert!(
                matches!(err, Error::UnusableParent { .. }),
                "{rel}: {err:?}"
            );
        }
        assert_eq!(std::fs::read(home.child("f")).expect("read"), b"a file");
    }

    #[test]
    fn a_directory_that_cannot_be_opened_for_its_fsync_fails_before_the_rename() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            return;
        }
        let home = guarded_home();
        let dir = home.child("dropbox");
        let dest = dir.join("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);
        // Write and search, no read: a temporary file can be created and renamed
        // here, and the directory cannot be opened to fsync the rename.
        set_mode(&dir, Mode::from_bits(0o300)).expect("chmod");

        let result = write_atomically(&dest, b"v2", Mode::DEFAULT_FILE);
        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");

        let err = result.expect_err("the rename cannot be made durable");
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(err.path(), dir);
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"v1",
            "an Err from before the rename means the destination holds exactly what it held before",
        );
        assert_eq!(names_in(&dir), vec![OsString::from("f")]);
    }

    #[test]
    fn a_directory_that_opens_but_refuses_the_temporary_file_fails_the_write_naming_it() {
        // Integration of #7 @b70d40e (r3), porting ec3a544. In this writer
        // `stage` creates the temporary file, and only `Filled::publish`, later,
        // opens the directory to sync the rename. So the temporary file's own
        // creation failing is the first thing a directory without write
        // permission refuses: this write stops in `stage`, and the directory is
        // never opened at all.
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so the condition cannot be staged.
            return;
        }
        let home = guarded_home();
        let dir = home.child("d");
        let dest = dir.join("f");
        seed(&dest, b"before", Mode::DEFAULT_FILE);
        // Read and search, no write: the destination can be observed, and no
        // temporary file can be created beside it.
        set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

        let result = write_atomically(&dest, b"after", Mode::DEFAULT_FILE);
        let names = names_in(&dir);
        set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");

        let err = result.expect_err("a directory refusing the temporary file fails the write");
        assert!(matches!(&err, Error::Write { .. }), "{err:?}");
        assert_eq!(err.path(), dir, "the error names the directory");
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"before",
            "a failed write leaves the previous file exactly as it was",
        );
        assert_eq!(names, vec![OsString::from("f")], "no temporary file");
    }

    #[test]
    fn a_parent_note_names_directories_under_home_portably() {
        let home = guarded_home();
        // `resolved` is a realpath, so it is under the home only if the home
        // path is itself one. Fail loudly rather than pass on no evidence.
        assert_eq!(
            std::fs::canonicalize(home.path()).expect("realpath of the home"),
            home.path(),
            "the guarded home must be a canonical path for this test to mean anything",
        );
        let absolute_home = home.path().display().to_string();

        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::fs::create_dir_all(home.child("dotfiles/dot_gnupg")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_gnupg"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_gnupg", home.child(".gnupg")).expect("symlink");

        for (rel, expected) in [
            (
                ".ssh/config",
                "~/.ssh is 0755, wider than the 0600 this file declares",
            ),
            (
                ".aws/credentials",
                "~/.aws will be created at 0755, wider than the 0600 this file declares",
            ),
            (
                ".gnupg/gpg.conf",
                "~/.gnupg is a symlink to ~/dotfiles/dot_gnupg, which is 0755, wider than the \
                 0600 this file declares; bx will not chmod a directory through a link, so \
                 chmod ~/dotfiles/dot_gnupg itself",
            ),
        ] {
            let outcome = outcome_for(&home, rel, b"x", Mode::PRIVATE_FILE);
            let note = outcome.parent_note.expect("the parent must be reported");
            assert!(
                !note.contains(&absolute_home),
                "{rel}: `bx plan` prints this note, so it names no absolute home: {note}",
            );
            assert_eq!(note, expected, "{rel}");
        }
    }

    #[test]
    fn a_wide_symlinked_parent_names_the_directory_to_chmod() {
        let home = guarded_home();
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(
            note.contains("so chmod ~/dotfiles/dot_ssh itself"),
            "the note names the directory the link resolves to, portably: {note}",
        );
        assert!(note.contains("chmod"), "{note}");
    }

    #[test]
    fn a_symlinked_parent_is_named_portably_under_a_home_reached_through_a_symlink() {
        let guard = guarded_home();
        // The home as `/home/u` is on a system where `/home -> var/home`: a
        // link, so the realpath of anything under it is not under it lexically.
        std::fs::create_dir(guard.child("real")).expect("mkdir");
        std::os::unix::fs::symlink("real", guard.child("home")).expect("symlink");
        let home = guard.child("home");
        std::fs::create_dir_all(home.join("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.join("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.join(".ssh")).expect("symlink");

        let observed = observe(&home.join(".ssh/config")).expect("observe");
        let outcome = compare(&observed, &desired(b"Host *\n", Mode::PRIVATE_FILE), &home);
        assert_eq!(
            outcome.parent_note.as_deref(),
            Some(
                "~/.ssh is a symlink to ~/dotfiles/dot_ssh, which is 0755, wider than the 0600 \
                 this file declares; bx will not chmod a directory through a link, so chmod \
                 ~/dotfiles/dot_ssh itself"
            ),
            "`bx plan` prints this note, so it names no absolute home",
        );
    }

    #[test]
    fn a_temp_name_chosen_first_is_a_fresh_bx_name_beside_the_destination() {
        let home = guarded_home();
        let dest = home.child(".config/app/x.conf");
        let one = temp_beside(&dest).expect("a name");
        let two = temp_beside(&dest).expect("another");
        assert_eq!(one.parent(), dest.parent());
        let name = one
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with(TEMP_PREFIX), "{name}");
        assert_eq!(name.len(), TEMP_PREFIX.len() + 16, "{name}");
        assert_ne!(one, two, "each write gets its own");
        // Chosen, not made: nothing exists on the way to it yet.
        assert!(!home.child(".config").exists());
        assert!(matches!(
            temp_beside(&home.child("a/../b")),
            Err(Error::ParentComponent(_))
        ));
    }

    #[test]
    fn stage_as_makes_exactly_the_named_temp_and_the_parents_it_invents() {
        let home = guarded_home();
        let dest = home.child(".config/app/x.conf");
        let temp = temp_beside(&dest).expect("a name");
        let planned = observe(&dest).expect("observe");
        let staged = stage_as(
            &dest,
            &temp,
            Mode::DEFAULT_FILE,
            &planned,
            &mut CreatedDirs::new(),
        )
        .expect("stage");
        assert_eq!(staged.temp_path(), temp);
        assert!(temp.is_file());
        assert_eq!(
            staged.created_dirs(),
            [home.child(".config/app"), home.child(".config")],
            "deepest first, as the filled write names them",
        );
        let filled = staged.fill(b"x\n").expect("fill");
        assert_eq!(
            filled.created_dirs(),
            [home.child(".config/app"), home.child(".config")]
        );
        filled.publish().expect("publish");
        assert_eq!(std::fs::read(&dest).expect("read"), b"x\n");
        assert!(!temp.exists(), "renamed over the destination");
    }

    #[test]
    fn stage_as_refuses_a_name_that_is_taken_or_not_a_bx_name_beside_the_destination() {
        let home = guarded_home();
        let dest = home.child("x.conf");
        let planned = observe(&dest).expect("observe");
        let taken = temp_beside(&dest).expect("a name");
        std::fs::write(&taken, b"theirs").expect("take it");
        let elsewhere = home.child("sub").join(format!("{TEMP_PREFIX}x"));
        for temp in [taken.clone(), home.child("x.conf.tmp"), elsewhere] {
            let err = stage_as(
                &dest,
                &temp,
                Mode::DEFAULT_FILE,
                &planned,
                &mut CreatedDirs::new(),
            )
            .expect_err("refused");
            assert!(
                matches!(err, Error::Write { .. }),
                "{}: {err:?}",
                temp.display()
            );
        }
        assert_eq!(
            std::fs::read(&taken).expect("kept"),
            b"theirs",
            "never replaced"
        );
        assert!(!dest.exists());
    }

    #[test]
    fn refuse_stage_refuses_what_stage_would_and_makes_nothing() {
        let home = guarded_home();
        let dest = home.child(".config/app/x.conf");
        let planned = observe(&dest).expect("observe");
        let prior = refuse_stage(&dest, &planned, &CreatedDirs::new()).expect("admitted");
        assert_eq!(prior.kind, Kind::Absent);
        assert!(!home.child(".config").exists(), "nothing made");

        // A destination that changed since plan is refused as `stage` refuses it.
        let file = home.child("f");
        let planned = observe(&file).expect("observe");
        std::fs::write(&file, b"since\n").expect("write");
        assert!(matches!(
            refuse_stage(&file, &planned, &CreatedDirs::new()),
            Err(Error::Changed { .. })
        ));
        // And plan's own verdict: a directory is not a file bx can write.
        let dir = home.child("d");
        std::fs::create_dir(&dir).expect("mkdir");
        let planned = observe(&dir).expect("observe");
        assert!(matches!(
            refuse_stage(&dir, &planned, &CreatedDirs::new()),
            Err(Error::NotAFile { .. })
        ));
    }
}
