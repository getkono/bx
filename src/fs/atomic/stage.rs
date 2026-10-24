//! The write itself: every refusal made before anything is created, the
//! temporary file beside the destination, its content and mode, the last look
//! before the rename, the rename, and the directory sync after it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use super::dir::create_missing_dirs;
use super::observe::{lexical, mode_of, observe, optional_metadata, parent_of};
use super::setid::{SET_ID, SPECIAL, verify_set_id_kept, without_set_id};
use super::{CreatedDirs, Error, Observed, ParentState, Stamp};
use crate::fs::durable;
use crate::fs::mode::{Kind, Mode};
#[cfg(test)]
use crate::hash::ContentHash;

/// The prefix every temporary file bx creates in a destination directory
/// carries.
///
/// Reserved: an orphan left by a crash is attributable to bx rather than
/// anonymous, which is what lets recovery and `doctor` find one. Nothing else
/// in bx may use this prefix for a different purpose.
pub const TEMP_PREFIX: &str = ".bx-";

/// A write that has a temporary file at its final mode and no content yet.
///
/// Created by [`stage`]. Dropping it leaves the destination exactly as it was.
///
/// # What "the temporary file is removed" is worth
///
/// This is the one place that statement is qualified, and every other mention
/// of it in `fs::atomic` and in [`crate::fs::durable`] points here rather than
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
    /// Only tests read it.
    #[cfg(test)]
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

#[cfg(test)]
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
/// leaves a parent wider than the declared mode, [`compare`](super::compare()) reports it, and
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
/// [`CreatedDirs`]. [`ensure_dir`](super::ensure_dir) reads it, so a declared directory that this
/// write created first is still the create `plan` announced for it. The write
/// claims, in `Filled::created_dirs`, every directory it created except a
/// declared one: that one is its directory target's alone, so each directory
/// has exactly one claimant whichever target is applied first.
///
/// # What `planned` is for
///
/// `planned` is the observation `plan` compared for this destination — the
/// [`Observed`] it handed to [`compare`](super::compare()). `stage` refuses the verdict `plan`
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
/// read is [`compare`](super::compare())'s verdict.
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
pub(in crate::fs) fn temp_name<'a>(
    dir: &Path,
    temp: &'a Path,
) -> Result<&'a std::ffi::OsStr, Error> {
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
    #[cfg(test)]
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.0.dest
    }

    /// The temporary file, in the destination directory, at its final mode.
    #[cfg(test)]
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.0.temp_path()
    }

    /// The mode this write declares.
    ///
    /// The temporary file already has it, except for a setuid or setgid bit,
    /// which [`Staged::fill`] adds after the content.
    #[cfg(test)]
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.0.mode
    }

    /// What was at the destination before this write — the prior state a
    /// reversal restores from.
    #[cfg(test)]
    #[must_use]
    pub const fn prior(&self) -> &Observed {
        &self.0.prior
    }

    /// The parent directories this write invented and claims, deepest first:
    /// the set `Filled::created_dirs` names once the content is written.
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
        self.0.temp.write_all(bytes).map_err(fail)?;
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
        durable::sync_file(self.0.temp.as_file(), &temp_path).map_err(fail)?;
        Ok(Filled {
            pending: self.0,
            #[cfg(test)]
            written: ContentHash::of(bytes),
        })
    }

    /// Fill and publish in one step, for a caller with nothing to interpose.
    ///
    /// # Errors
    ///
    /// Whatever [`Staged::fill`] or [`Filled::publish`] returns.
    pub fn commit(self, bytes: &[u8]) -> Result<(), Error> {
        // No ledger entry can exist for this write: `commit` never hands the
        // caller a `Filled`, so `NewEntry::for_write` was never reachable for it.
        self.fill(bytes)?.publish().map_err(Unpublished::into_error)
    }

    /// Discard the write. The destination is untouched and the temporary file
    /// is dropped — see [`Staged`] for what that is worth. Identical to
    /// dropping it; named so a caller can say so.
    #[cfg(test)]
    pub fn abandon(self) {
        // A surviving mutant, and equivalent: `self` is dropped at the end of
        // this function whether or not the body says so, so emptying the body
        // gives the same program. The call is here to be read, not to act.
        drop(self);
    }
}

impl Filled {
    /// The destination this write will replace.
    #[cfg(test)]
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.pending.dest
    }

    /// The temporary file, holding the final content at the final mode.
    #[cfg(test)]
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.pending.temp_path()
    }

    /// The mode the content is already at.
    #[cfg(test)]
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.pending.mode
    }

    /// What was at the destination before this write.
    #[cfg(test)]
    #[must_use]
    pub const fn prior(&self) -> &Observed {
        &self.pending.prior
    }

    /// The digest of the bytes now in the temporary file.
    ///
    /// Computed while filling rather than re-read afterwards, so it is the
    /// digest of what was actually written rather than the digest of whatever
    /// is at the path by the time somebody looks.
    #[cfg(test)]
    #[must_use]
    pub const fn written(&self) -> ContentHash {
        self.written
    }

    /// The parent directories this write invented and claims, deepest first.
    ///
    /// Empty when every component already existed. A directory that a
    /// directory target in this apply declares is left out even when this
    /// write made it: that target's [`EnsuredDir::created_dirs`](super::EnsuredDir::created_dirs) claims it, so
    /// reversing this write can never remove a directory that is still
    /// declared. A reversal removes these in order, so a target that created
    /// `~/.config/a/b` leaves nothing behind.
    #[cfg(test)]
    #[must_use]
    pub fn created_dirs(&self) -> &[PathBuf] {
        &self.pending.created_dirs
    }

    /// `rename` the temporary file onto the destination, then `fsync` the
    /// destination directory so the rename itself is durable.
    ///
    /// A hard link to the destination is **not** followed: the destination is
    /// replaced by name, so any other link to the old inode keeps the old
    /// content and the old mode. That is inherent to an atomic rename, and it
    /// holds for a mode-only `Modify` too, which is applied through [`stage`]
    /// like any other so that it is refused when the file changed after `plan`
    /// — see [`compare`](super::compare()).
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
    /// [`Unpublished`], which in a test build names the destination as well as
    /// the cause, so a caller that recorded a ledger entry for this write
    /// before calling — as the test-only `crate::state::NewEntry::for_write`
    /// requires — can withdraw it. `publish` consumes the `Filled`, so the
    /// refusal is the only thing left that knows which write it was.
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
            #[cfg(test)]
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
    #[cfg(test)]
    pub fn abandon(self) {
        // A surviving mutant, and equivalent: `self` is dropped at the end of
        // this function whether or not the body says so, so emptying the body
        // gives the same program. The call is here to be read, not to act.
        drop(self);
    }
}

/// A write [`Filled::publish`] refused: why, and which write it was.
///
/// The second half is for a caller that records a ledger entry before
/// `publish`, as the test-only `crate::state::NewEntry::for_write` requires,
/// because the bytes a rename displaces have to be durable before anything
/// displaces them — so by the time a publish is refused, such a caller has
/// already recorded an entry for a write that did not happen. That record has
/// to be withdrawn with [`crate::state::Ledger::withdraw`] before the ledger is
/// saved, or `bx rm` will restore the recorded prior over content bx never
/// replaced. The shipped `apply` records its entry only once the publish has
/// landed, so it has nothing to withdraw, and `dest` is compiled for tests
/// alone.
///
/// `publish` consumes the [`Filled`], so nothing the caller still holds names
/// the write afterwards. This does: `Unpublished::dest` is the path
/// `NewEntry::for_write` keyed the entry on.
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
    /// withdraw is keyed on. Only tests read it: no shipped caller records a
    /// ledger entry before publishing.
    #[cfg(test)]
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
    /// The [`Error`] it returns does not name `Unpublished::dest`, because by
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
/// Two entry points in `fs::atomic` do: [`stage`], for the parents a write
/// needs, and [`ensure_dir`](super::ensure_dir), which is a directory target's own apply. Both
/// take a [`CreatedDirs`] to record what they made so a reversal can remove it,
/// both are announced by a [`compare`](super::compare()) or [`compare_dir`](super::compare_dir) first, and both get
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
/// destination that changed after `plan` (see [`compare`](super::compare())).
///
/// Within `fs::atomic` it is called only where the verdict is already settled:
/// by [`ensure_dir`](super::ensure_dir) for a directory target's `Modify`, after its own check
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
pub(in crate::fs) fn prepare(
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
/// The observation is the prior the write displaces, as `Staged::prior`
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
pub(in crate::fs) fn refuse_to_prepare(
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
pub(in crate::fs) fn verify_unchanged(prior: &Observed) -> Result<(), Error> {
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
    Err(Error::Changed {
        path: then.path.clone(),
        detail: what_moved(was.is_some(), now.is_some()).to_string(),
    })
}

/// Refuse unless `now` is still what `planned` observed: the same path, the
/// same kind and the same stamp, or still nothing at all.
///
/// [`refuse_changed`] for two observations rather than an observation and a
/// fresh `lstat`: the journal's write paths and [`crate::recover`]'s rollback
/// of a create check the destination they judged this way before acting on it.
///
/// # Errors
///
/// [`Error::Changed`] naming what moved.
pub(crate) fn refuse_moved(planned: &Observed, now: &Observed) -> Result<(), Error> {
    if planned.path != now.path {
        return Err(Error::Changed {
            path: now.path.clone(),
            detail: format!("plan observed {}, not this path", planned.path.display()),
        });
    }
    if (planned.kind, planned.stamp) == (now.kind, now.stamp) {
        return Ok(());
    }
    Err(Error::Changed {
        path: now.path.clone(),
        detail: what_moved(planned.stamp.is_some(), now.stamp.is_some()).to_string(),
    })
}

/// What [`Error::Changed`] says moved, from whether something was there when
/// it was observed and whether something is there now.
const fn what_moved(was: bool, is: bool) -> &'static str {
    match (was, is) {
        (_, false) => "it has been removed",
        (false, true) => "nothing was there, and something is now",
        (true, true) => "it has been modified or replaced",
    }
}

/// Refuse a write over what `observed` found, when that is not a regular file
/// or nothing, or when its parent does not resolve — the conflicts [`compare`](super::compare())
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

/// `fchmod`, so the mode is the declared one and not the declared one masked by
/// the process `umask`.
fn fchmod(file: &std::fs::File, mode: Mode, path: &Path) -> Result<(), Error> {
    rustix::fs::fchmod(file, mode.into()).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source: source.into(),
    })
}

#[cfg(test)]
mod tests;
