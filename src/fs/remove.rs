//! Durable removal: unlinking a file and pruning the directories bx made.
//!
//! The counterpart of [`super::atomic`]'s durable write. A removal is made
//! durable the way a rename is — the directory is opened before the change and
//! `fsync`ed after it — and a directory is removed only while it stands empty,
//! so nothing bx did not put there is ever deleted. Rollback, `rm` and a
//! followed repository's refused fetch all remove through here.

use std::path::{Path, PathBuf};

use super::durable;

/// A removal, or the `fsync` that makes one durable, that failed.
#[derive(Debug, thiserror::Error)]
#[error("{}: {source}", .path.display())]
pub struct Error {
    /// The path the failure is about.
    pub path: PathBuf,
    /// The underlying failure.
    #[source]
    pub source: std::io::Error,
}

/// Remove `path` if it is there, and `fsync` the directory it was in.
///
/// Absence is success: the whole recovery path is re-runnable, and a second run
/// finds what the first removed already gone. A missing directory is the same
/// absence, since nothing can be in it.
///
/// The directory is opened **before** the unlink and `fsync`ed after it, the
/// order [`super::write_atomically`] keeps for a rename. Removing an entry
/// needs write and search permission on its directory, and opening the
/// directory needs read, so in a `0300` directory an open placed after the
/// unlink fails with the file already gone: an `Err` from a removal that
/// happened. Opened first, that failure happens while the file is still in
/// place.
///
/// # Errors
///
/// [`Error`] wrapping the failing `open` of the directory, `unlink`, or
/// `fsync`. Only a failing `fsync` is returned after the file was removed.
pub(crate) fn unlink(path: &Path) -> Result<(), Error> {
    // `Path::parent` of a bare name is the empty path, which names the current
    // directory the unlink resolves against, not a directory that is absent.
    let dir = path.parent().map(|dir| {
        if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        }
    });
    let opened = match dir {
        None => None,
        Some(dir) => match durable::Dir::open(dir) {
            Ok(handle) => Some((dir, handle)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(Error {
                    path: dir.to_path_buf(),
                    source,
                });
            }
        },
    };
    match durable::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(Error {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    if let Some((dir, handle)) = &opened {
        sync_dir(handle, dir)?;
    }
    Ok(())
}

/// Remove directories bx created, deepest first, stopping at the first that is
/// not empty.
///
/// The stop is the point: a directory that has acquired anything else is no
/// longer only bx's, and removing it would delete something bx did not put
/// there. One that is no longer a directory at all stops the walk the same way.
///
/// # Errors
///
/// [`Error`] for a failure that is neither "already gone", "not empty" nor
/// "not a directory".
pub(crate) fn prune_dirs(dirs: &[PathBuf]) -> Result<(), Error> {
    for dir in dirs {
        if !remove_if_empty(dir)? {
            break;
        }
    }
    Ok(())
}

/// Roll back the directories an interrupted write announced it would make,
/// given that this rollback has just removed `below` — the write's own
/// temporary file, its published destination, or a directory target's own
/// directory — from the deepest of them.
///
/// An Intent names its directories **before** they are made, so a crash
/// between the Intent and the stage leaves it naming directories bx never
/// made. Standing empty proves nothing: one the user made after that crash is
/// empty too. What proves a directory bx's is that it held bx's own artefact
/// and nothing else, so each is removed only when the one entry this Intent
/// names inside it — `below`, then each directory removed before it — was
/// directly inside it and has just gone, and it now stands empty. The walk
/// stops at the first that is not: one never made (absent), one holding
/// anything else, or one the chain does not reach, such as the parent of a
/// declared directory this Intent does not name. A predicted directory that
/// is fully empty is therefore left, for `bx doctor` to report.
///
/// `dirs` is deepest first, as [`crate::journal::Intent::created_dirs`] is.
///
/// # Errors
///
/// [`Error`] for a failure that is neither "not empty" nor "not a
/// directory".
pub(crate) fn prune_beneath(below: &Path, dirs: &[PathBuf]) -> Result<(), Error> {
    let mut child = below;
    for dir in dirs {
        if child.parent() != Some(dir.as_path()) || !remove_made_dir(dir)? {
            break;
        }
        child = dir;
    }
    Ok(())
}

/// Remove `dir` if it is an empty directory, and say whether this call
/// removed it. Unlike [`remove_if_empty`], one already absent is **not**
/// removed: nothing shows it was ever made.
///
/// # Errors
///
/// What [`remove_if_empty`] returns.
pub(crate) fn remove_made_dir(dir: &Path) -> Result<bool, Error> {
    if !std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()) {
        return Ok(false);
    }
    remove_if_empty(dir)
}

/// Remove a directory bx created if it is empty, and say whether it is gone.
///
/// A path that is no longer a directory — a symlink the user put in its
/// place, or a file where it or one of its parents was — still stands, and is
/// no longer bx's: it is left, as the hand-off of a removed target's claims
/// leaves it. `rmdir` never follows its last component, so that is decided by
/// the one call that would otherwise remove it, with no window between a look
/// and the removal.
///
/// # Errors
///
/// [`Error`] for a failure that is neither "already gone", "not empty" nor
/// "not a directory".
pub(crate) fn remove_if_empty(dir: &Path) -> Result<bool, Error> {
    match std::fs::remove_dir(dir) {
        Ok(()) => {
            tracing::debug!(dir = %dir.display(), "removed a directory bx created");
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        // `ENOTEMPTY` and `EEXIST` are both permitted spellings of "it is
        // not empty", and `std::io::ErrorKind` maps neither stably.
        Err(e)
            if matches!(
                e.raw_os_error().map(rustix::io::Errno::from_raw_os_error),
                Some(rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST)
            ) =>
        {
            Ok(false)
        }
        Err(e)
            if e.raw_os_error().map(rustix::io::Errno::from_raw_os_error)
                == Some(rustix::io::Errno::NOTDIR) =>
        {
            tracing::debug!(
                dir = %dir.display(),
                "left a directory bx created that is no longer a directory",
            );
            Ok(false)
        }
        Err(source) => Err(Error {
            path: dir.to_path_buf(),
            source,
        }),
    }
}

/// Open a directory so that a rename or an unlink inside it can be made
/// durable.
///
/// Call it **before** that operation and [`sync_dir`] after, never the two
/// together afterwards: an open that fails after the operation reports an
/// error for a change that has already happened. See [`unlink`].
///
/// # Errors
///
/// [`Error`] naming `dir` for the failing `open`.
pub(crate) fn open_dir(dir: &Path) -> Result<durable::Dir, Error> {
    durable::Dir::open(dir).map_err(|source| Error {
        path: dir.to_path_buf(),
        source,
    })
}

/// `fsync` a directory [`open_dir`] opened, so a rename or an unlink made
/// inside it since survives a power loss.
///
/// # Errors
///
/// [`Error`] naming `dir` for the failing `fsync`.
pub(crate) fn sync_dir(handle: &durable::Dir, dir: &Path) -> Result<(), Error> {
    handle.sync().map_err(|source| Error {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fs::Mode;

    #[test]
    fn a_directory_that_is_not_empty_stops_the_pruning() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let deep = dir.path().join("a/b/c");
        std::fs::create_dir_all(&deep).expect("mkdir");
        std::fs::write(dir.path().join("a/b/kept"), "the user's").expect("write");

        prune_dirs(&[deep.clone(), dir.path().join("a/b"), dir.path().join("a")]).expect("prune");

        assert!(!deep.exists(), "the empty leaf went");
        assert!(dir.path().join("a/b").is_dir(), "the non-empty one stayed");
        assert!(dir.path().join("a").is_dir(), "and the walk stopped there");
    }

    #[test]
    fn pruning_beneath_follows_only_the_chain_above_what_was_removed() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let root = dir.path();
        let chain = [root.join("a/b"), root.join("a")];
        std::fs::create_dir_all(&chain[0]).expect("mkdir");

        // Removed from `a/b`: both go.
        prune_beneath(&chain[0].join(".bx-0"), &chain).expect("prune");
        assert!(!root.join("a").exists(), "the whole chain went");

        // An absent directory breaks the chain: `a` stands empty and is not
        // shown made by anything beneath it.
        std::fs::create_dir(root.join("a")).expect("the user's");
        prune_beneath(&chain[0].join(".bx-0"), &chain).expect("prune");
        assert!(root.join("a").is_dir(), "never made, so never pruned");

        // So does a directory that is not the parent of what was removed.
        std::fs::create_dir(&chain[0]).expect("mkdir");
        prune_beneath(&root.join("elsewhere/.bx-0"), &chain).expect("prune");
        assert!(chain[0].is_dir(), "not beneath it");

        // And one that is not empty.
        std::fs::write(chain[0].join("kept"), "the user's").expect("write");
        prune_beneath(&chain[0].join(".bx-0"), &chain).expect("prune");
        assert!(chain[0].is_dir() && root.join("a").is_dir());
    }

    #[test]
    fn a_made_directory_is_removed_only_when_it_is_there_and_empty() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let made = dir.path().join("made");
        assert!(
            !remove_made_dir(&made).expect("absent"),
            "nothing to remove"
        );
        std::fs::write(&made, "a file").expect("write");
        assert!(!remove_made_dir(&made).expect("a file"), "not a directory");
        std::fs::remove_file(&made).expect("rm");
        std::fs::create_dir(&made).expect("mkdir");
        assert!(remove_made_dir(&made).expect("empty"));
        assert!(!made.exists());
    }

    #[test]
    fn pruning_a_directory_that_is_already_gone_is_not_an_error() {
        let dir = tempfile::tempdir().expect("a tempdir");
        prune_dirs(&[dir.path().join("never-existed")]).expect("prune");
        unlink(&dir.path().join("never-there")).expect("unlink");
        // Opening the directory first must not turn a missing one into an error.
        unlink(&dir.path().join("gone/never-there")).expect("unlink in a missing directory");
    }

    #[test]
    fn a_removal_opens_its_directory_before_the_unlink_and_syncs_it_after() {
        // The order `fs::write_atomically` keeps for a rename, observed: the
        // directory handle exists before the file goes, and the sync follows.
        use crate::fs::durable::{Event, recording};

        let dir = tempfile::tempdir().expect("a tempdir");
        let file = dir.path().join("f");
        std::fs::write(&file, "x\n").expect("write");

        let (removed, events) = recording(|| unlink(&file));
        removed.expect("unlink");

        assert_eq!(
            events,
            [
                Event::OpenDir(dir.path().to_path_buf()),
                Event::Unlink(file.clone()),
                Event::SyncDir(dir.path().to_path_buf()),
            ],
        );
        assert!(!file.exists());
    }

    #[test]
    fn a_directory_that_cannot_be_opened_fails_a_removal_before_the_file_goes() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the permission bits, so there is nothing to assert.
            crate::testing::skip_unconstructible("root ignores the permission bits");
            return;
        }
        let dir = tempfile::tempdir().expect("a tempdir");
        let file = dir.path().join("f");
        std::fs::write(&file, "the user's\n").expect("write");
        // Write and search, no read: the file can be unlinked, and the directory
        // cannot be opened to fsync the unlink.
        crate::fs::set_mode(dir.path(), Mode::from_bits(0o300)).expect("chmod");

        let result = unlink(&file);
        crate::fs::set_mode(dir.path(), Mode::PRIVATE_DIR).expect("unlock for cleanup");

        let Error { path, source } = result.expect_err("the directory cannot be opened");
        assert_eq!(path, dir.path());
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(&file).expect("the file is still there"),
            b"the user's\n",
            "an Err means the removal did not happen",
        );
    }
}
