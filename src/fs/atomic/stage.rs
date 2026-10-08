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
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::os::unix::fs::MetadataExt as _;

    use rustix::io::Errno;

    use crate::fs::atomic::test_support::{
        CWD, UMASK, desired, mode_of_path, names_in, outcome_for, seed, stage_now,
    };
    use crate::fs::atomic::{Desired, Drift, compare, stage};
    use crate::paths::Portable;
    use crate::state::{
        ExclusiveLock, Ledger, LedgerView, Mechanism, NewEntry, Prior, PriorBytes, StateDir,
        restore,
    };
    use crate::testing::{GuardedHome, guarded_home};

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
            .drift,
            Drift::Unchanged,
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
                compare(&planned, &desired(b"bx\n", Mode::DEFAULT_FILE), home.path()).drift,
                Drift::Modify,
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
        assert_eq!(outcome.drift, Drift::Conflict);
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
        assert_eq!(outcome.drift, Drift::Modify);
        assert!(!outcome.content_drift, "only the mode drifted");
        set_mode(&chmodded, Mode::from_bits(0o640)).expect("the user's chmod after plan");
        let result_a = apply_file_modify(&planned_a, &chmodded, &want);
        let mode_a = mode_of_path(&chmodded);

        // (b) The file is replaced by a directory after plan printed its line.
        let replaced = home.child("replaced");
        seed(&replaced, b"Host *\n", Mode::DEFAULT_FILE);
        let planned_b = observe(&replaced).expect("plan observes");
        assert_eq!(compare(&planned_b, &want, home.path()).drift, Drift::Modify);
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

        let err = NewEntry::for_write(&filled, Path::new("relative/home"), Mechanism::Own)
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
        let entry = NewEntry::for_write(&filled, home.path(), Mechanism::Own)
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
                NewEntry::for_write(&filled, home.path(), Mechanism::Own)
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
        let bytes =
            restore::read(&dir, reference).expect("the blob is durable by the time record returns");
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
        let entry =
            NewEntry::for_write(&filled, home.path(), Mechanism::Own).expect("a portable entry");
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
                NewEntry::for_write(&filled, home.path(), Mechanism::Own)
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
            restore::read(&dir, reference).expect("the blob record fsynced"),
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
                NewEntry::for_write(&first, home.path(), Mechanism::Own).expect("a portable entry"),
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
                NewEntry::for_write(&second, home.path(), Mechanism::Own)
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
            restore::read(&dir, original).expect("the original prior"),
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
                    NewEntry::for_write(&filled, home.path(), Mechanism::Own)
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
            restore::read(&dir, reference).expect("restore bytes"),
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
            restore::read(&dir, original).expect("restore the original"),
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
        assert_eq!(outcome.drift, Drift::Modify);
        assert!(!outcome.content_drift);

        // Applied like any other Modify: staged against plan's observation,
        // with the same bytes at the new mode.
        let filled = stage(&dest, want.mode, &planned, &mut CreatedDirs::new())
            .expect("stage")
            .fill(want.bytes)
            .expect("fill");
        let recorded = ledger
            .record(
                NewEntry::for_write(&filled, home.path(), Mechanism::Own)
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
            compare(&observe(&dest).expect("observe again"), &want, home.path()).drift,
            Drift::Unchanged,
        );

        // Reversing it restores the prior bytes at the prior mode.
        let bytes = restore::read(&dir, reference).expect("the prior bytes are durable");
        write_atomically(&dest, &bytes, reference.mode).expect("reverse");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
        assert_eq!(std::fs::read(&dest).expect("read"), b"Host *\n");
    }

    #[test]
    fn a_write_over_nothing_records_that_nothing_was_there() {
        let home = guarded_home();
        let dest = home.child("f");
        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"x")
            .expect("fill");
        assert_eq!(PriorBytes::of(filled.prior()), PriorBytes::Absent);
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
            assert_eq!(PriorBytes::of(&observed), PriorBytes::Absent, "{rel}");
            assert_eq!(observed.digest(), None, "{rel}");
        }
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
