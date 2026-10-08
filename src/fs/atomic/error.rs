//! Every way a write can fail, and the words its messages share with `plan`'s
//! notes.

use std::path::{Path, PathBuf};

use super::setid::{SETGID, SPECIAL};
use crate::fs::mode::{Kind, Mode};

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
    /// announced as a [`Drift::Conflict`](super::Drift::Conflict) by `compare` rather than left for
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
    /// Raised by [`stage`](super::stage()) when the destination is no longer what `plan`
    /// observed, by [`Filled::publish`](super::Filled::publish) when it changed between [`stage`](super::stage()) and
    /// the rename — an editor saving, a symlink swapped in, a file appearing
    /// where there was none — and by [`ensure_dir`](super::ensure_dir) when a directory target is
    /// no longer what `plan` saw. Nothing is replaced: the path keeps what is
    /// there now, and the temporary file is dropped — see [`Staged`](super::Staged) for what
    /// that is worth.
    ///
    /// From [`Filled::publish`](super::Filled::publish) it arrives inside an [`Unpublished`](super::Unpublished), because
    /// "nothing was replaced" is not the whole obligation: a caller that
    /// recorded a ledger entry before publishing, as [`crate::state::NewEntry::for_write`]
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
    /// dropped — see [`Staged`](super::Staged) for what that is worth.
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
    /// close. So the mode is read back after the `chmod`, by [`ensure_dir`](super::ensure_dir)
    /// and by [`stage`](super::stage()) for a directory it creates, and a missing bit is
    /// refused. Nothing is recorded. A directory whose mode a `Modify` changed
    /// is set back to the mode `plan` saw and read back again; a directory bx
    /// created is left in place at the mode that landed — as for an abandoned
    /// write's parent — so the next `plan` announces the `Modify` that is still
    /// owed.
    ///
    /// The kernel's own cause is refused before any `chmod`: [`ensure_dir`](super::ensure_dir)
    /// does not `chmod` an existing directory that has `S_ISGID`, or is
    /// declared with it, unless a `chmod` by this process is **confirmed** to
    /// keep the bit — by `CAP_FSETID` in the effective set, or by the
    /// directory's group being one the kernel resolved and this process is in
    /// (see `setid::keeps_setgid`). Anything it cannot confirm is refused. That
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
    /// Only [`write_atomically`](super::write_atomically) raises it. [`stage`](super::stage()) and [`ensure_dir`](super::ensure_dir) create
    /// directories; this is the shorthand that has no [`CreatedDirs`](super::CreatedDirs) to record
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
    /// [`CreatedDirs::declare`](super::CreatedDirs::declare), so it was made at [`Mode::DEFAULT_DIR`] and a
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
    /// failing with a permission error, against Invariant 3. [`compare`](super::compare())
    /// announces it as an [`Drift::Conflict`](super::Drift::Conflict) whose note is this error's
    /// words, less the path, so `apply` never reaches a target `plan` printed
    /// that way. No writer in `fs` raises it: [`stage`](super::stage()) writes the mode it is
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
pub(super) const FILE_OWNER_NEEDS: Mode = Mode::from_bits(0o400);

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

pub(super) fn owner_locked_out(declared: Mode, needs: Mode) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
