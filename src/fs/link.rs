//! The one symlink write in the crate: a link made beside its destination and
//! renamed over it.
//!
//! A symlink target's content is its text. bx never resolves it, never follows
//! it and never asks whether anything is at the far end, so a dangling link is
//! made like any other. Everything that records a link records it the way it
//! records a file, under the digest of its text ([`digest`]) and at
//! [`Mode::LINK`], so the ledger, the journal and the restore store need no
//! second vocabulary; the [`crate::state::Mechanism::Link`] or
//! `Intent::link` beside the record says which is meant.
//!
//! The sequence is [`crate::fs::stage`]'s with a link in place of a file:
//!
//! 1. [`stage_link`] refuses what `plan` refused, looks again and refuses a
//!    destination that changed since `plan`, makes the missing parents, and
//!    makes the link under a reserved [`crate::fs::TEMP_PREFIX`] name in the
//!    destination directory. The destination is untouched.
//! 2. [`StagedLink::publish`] opens the directory, checks the destination
//!    against the stamp `stage_link` observed one last time, renames the link
//!    over it and `fsync`s the directory.
//!
//! A link has no content of its own to `fsync`: its text is written with the
//! directory entry, so the directory `fsync` after the rename is what makes
//! the result durable. A crash before it leaves the temporary link, which the
//! journal names, and which recovery removes.
//!
//! Only nothing or a link may be replaced. `rename(2)` onto a link's path
//! replaces the link itself, which is exactly what a symlink target wants and
//! exactly why a file target refuses one; a regular file, a directory or a
//! device node is never replaced by a link.

use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use super::atomic::{self, CreatedDirs, Error, Observed, Parent, TEMP_PREFIX, Unpublished};
use super::{Kind, durable};
use crate::state::ContentHash;

/// The digest a link holding `text` is recorded under: that of its bytes.
#[must_use]
pub fn digest(text: &Path) -> ContentHash {
    ContentHash::of(text.as_os_str().as_bytes())
}

/// A link made beside its destination and not yet renamed over it.
///
/// Dropping it removes the temporary link — see [`crate::fs::Staged`] for
/// what that is worth — and leaves the destination exactly as it was.
#[derive(Debug)]
pub struct StagedLink {
    temp: NamedTempFile<()>,
    dest: PathBuf,
    text: PathBuf,
    prior: Observed,
    created_dirs: Vec<PathBuf>,
}

/// Begin replacing `dest` with a link holding `text`.
///
/// `planned` is the observation `plan` compared, as for [`crate::fs::stage`]:
/// its verdict is refused first, then the destination is looked at again and
/// refused unless it is the same link with the same stamp, or still nothing.
/// Missing parents are made as `stage` makes them, and claimed the same way.
///
/// # Errors
///
/// [`Error::Changed`] when the destination is no longer what `planned`
/// observed. [`Error::UnusableParent`] or [`Error::NotALink`] when `planned`
/// or the second look found a parent that does not resolve, or something that
/// is neither nothing nor a link. [`Error::Write`] when the link cannot be
/// made, and what [`crate::fs::stage`] documents for the parents.
pub fn stage_link(
    dest: &Path,
    text: &Path,
    planned: &Observed,
    created: &mut CreatedDirs,
) -> Result<StagedLink, Error> {
    stage_link_in(dest, None, text, planned, created)
}

/// [`stage_link`], with the temporary link at `temp`, a name
/// [`crate::fs::temp_beside`] chose for `dest` before anything was made — as
/// [`crate::fs::stage_as`] is to [`crate::fs::stage`].
///
/// # Errors
///
/// What [`stage_link`] returns, and [`Error::Write`] when `temp` is not a
/// [`TEMP_PREFIX`] name beside `dest` or something is already there.
pub fn stage_link_as(
    dest: &Path,
    temp: &Path,
    text: &Path,
    planned: &Observed,
    created: &mut CreatedDirs,
) -> Result<StagedLink, Error> {
    stage_link_in(dest, Some(temp), text, planned, created)
}

/// Every refusal [`stage_link`] makes before it creates anything, made
/// without creating anything, and the fresh observation it made them against
/// — as [`crate::fs::refuse_stage`] is to [`crate::fs::stage`].
///
/// # Errors
///
/// What [`stage_link`] documents, but for making the parents and the link.
pub fn refuse_stage_link(
    dest: &Path,
    planned: &Observed,
    created: &CreatedDirs,
) -> Result<Observed, Error> {
    atomic::refuse_to_prepare(dest, planned, created, refuse_unlinkable).map(|(_, prior)| prior)
}

/// [`stage_link`] and [`stage_link_as`].
fn stage_link_in(
    dest: &Path,
    temp: Option<&Path>,
    text: &Path,
    planned: &Observed,
    created: &mut CreatedDirs,
) -> Result<StagedLink, Error> {
    let (dest, prior, created_dirs) = atomic::prepare(dest, planned, created, refuse_unlinkable)?;
    let dir = atomic::parent_of(&dest)?;
    let mut builder = tempfile::Builder::new();
    match temp {
        // Exactly this name: `symlink` fails on one that is taken.
        Some(temp) => builder.prefix(atomic::temp_name(dir, temp)?).rand_bytes(0),
        None => builder.prefix(TEMP_PREFIX),
    };
    let temp = builder
        .make_in(dir, |path| std::os::unix::fs::symlink(text, path))
        .map_err(|source| Error::Write {
            path: dir.to_path_buf(),
            source,
        })?;
    Ok(StagedLink {
        temp,
        dest,
        text: text.to_path_buf(),
        prior,
        created_dirs,
    })
}

/// Refuse to replace what `observed` found with a link, unless it is nothing
/// or a link and its parent resolves.
///
/// # Errors
///
/// [`Error::UnusableParent`] or [`Error::NotALink`].
fn refuse_unlinkable(observed: &Observed) -> Result<(), Error> {
    if let Some(parent) = observed.parent.as_ref()
        && let Some(reason) = Parent::unusable(parent)
    {
        return Err(Error::UnusableParent {
            path: parent.path.clone(),
            reason: reason.to_string(),
        });
    }
    match observed.kind {
        Kind::Absent | Kind::Symlink => Ok(()),
        kind => Err(Error::NotALink {
            path: observed.path.clone(),
            kind,
        }),
    }
}

impl StagedLink {
    /// The destination this link will replace.
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// The temporary link, beside the destination, already holding its text.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.temp.path()
    }

    /// What was at the destination before: nothing, or a link.
    #[must_use]
    pub const fn prior(&self) -> &Observed {
        &self.prior
    }

    /// The digest of the text the link holds.
    #[must_use]
    pub fn written(&self) -> ContentHash {
        digest(&self.text)
    }

    /// The parent directories this write invented and claims, deepest first,
    /// as [`crate::fs::Filled::created_dirs`].
    #[must_use]
    pub fn created_dirs(&self) -> &[PathBuf] {
        &self.created_dirs
    }

    /// Rename the link over the destination, then `fsync` the directory.
    ///
    /// The directory is opened first and the destination checked against the
    /// stamp [`stage_link`] observed immediately before the rename, exactly as
    /// [`crate::fs::Filled::publish`] does, so a link retargeted or a file
    /// put there since is refused rather than replaced.
    ///
    /// # Errors
    ///
    /// [`Unpublished`], as [`crate::fs::Filled::publish`] returns it.
    pub fn publish(self) -> Result<(), Unpublished> {
        let Self {
            temp, dest, prior, ..
        } = self;
        let refused = |error: Error| Unpublished {
            error,
            dest: dest.clone(),
        };
        let publish = || -> Result<(), Error> {
            let dir = atomic::parent_of(&dest)?;
            let dir_fail = |source| Error::Write {
                path: dir.to_path_buf(),
                source,
            };
            let handle = durable::Dir::open(dir).map_err(dir_fail)?;
            atomic::verify_unchanged(&prior)?;
            durable::rename(temp, &dest).map_err(|e| Error::Write {
                path: dest.clone(),
                source: e.error,
            })?;
            handle.sync().map_err(dir_fail)
        };
        publish().map_err(refused)?;
        tracing::debug!(dest = %dest.display(), "made a symlink atomically");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fs::{Mode, observe};

    fn link_at(dest: &Path, text: &str, planned: &Observed) -> Result<Vec<PathBuf>, Error> {
        let staged = stage_link(dest, Path::new(text), planned, &mut CreatedDirs::new())?;
        let dirs = staged.created_dirs().to_vec();
        staged.publish().map_err(Unpublished::into_error)?;
        Ok(dirs)
    }

    #[test]
    fn a_link_is_made_with_its_text_verbatim_and_never_followed() {
        let root = tempfile::tempdir().expect("tempdir");
        let dest = root.path().join("a/b/tool");
        let planned = observe(&dest).expect("observe");

        let dirs = link_at(&dest, "../../nowhere/tool", &planned).expect("a dangling link");

        assert_eq!(
            std::fs::read_link(&dest).expect("a link"),
            Path::new("../../nowhere/tool")
        );
        assert_eq!(dirs, [root.path().join("a/b"), root.path().join("a")]);
        let seen = observe(&dest).expect("observe");
        assert_eq!(seen.kind, Kind::Symlink);
        assert_eq!(seen.mode, Some(Mode::LINK));
        assert_eq!(seen.bytes, None, "a link has no bytes of its own");
        assert_eq!(
            seen.link_digest(),
            Some(digest(Path::new("../../nowhere/tool")))
        );
        assert_eq!(
            names(&root.path().join("a/b")),
            ["tool"],
            "no temporary link is left"
        );
    }

    #[test]
    fn a_link_replaces_the_link_plan_saw_and_nothing_else() {
        let root = tempfile::tempdir().expect("tempdir");
        let dest = root.path().join("tool");
        std::os::unix::fs::symlink("old", &dest).expect("seed");
        let planned = observe(&dest).expect("observe");
        assert_eq!(planned.link.as_deref(), Some(Path::new("old")));

        link_at(&dest, "/new", &planned).expect("retarget");
        assert_eq!(
            std::fs::read_link(&dest).expect("a link"),
            Path::new("/new")
        );

        // A file, a directory: never replaced, before or after plan looked.
        let file: fn(&Path) = |p| std::fs::write(p, b"x").expect("file");
        let dir: fn(&Path) = |p| std::fs::create_dir(p).expect("dir");
        for (make, kind) in [(file, Kind::File), (dir, Kind::Dir)] {
            let dest = root.path().join(format!("{kind:?}"));
            make(&dest);
            let planned = observe(&dest).expect("observe");
            let err = link_at(&dest, "x", &planned).expect_err("not a link");
            assert!(
                matches!(err, Error::NotALink { kind: k, .. } if k == kind),
                "{err}"
            );
            assert!(
                err.to_string().contains("not a symlink bx can replace"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_link_whose_parent_does_not_resolve_is_refused_before_anything_is_made() {
        let root = tempfile::tempdir().expect("tempdir");
        let file = root.path().join("file");
        std::fs::write(&file, b"x").expect("a file where the parent would be");

        // Plan already saw the parent as a file.
        let dest = file.join("tool");
        let planned = observe(&dest).expect("observe");
        let err = link_at(&dest, "x", &planned).expect_err("unusable parent");
        assert!(
            matches!(&err, Error::UnusableParent { path, .. } if *path == file),
            "{err}"
        );

        // Plan saw a usable parent, which became a file before apply.
        let dir = root.path().join("dir");
        std::fs::create_dir(&dir).expect("a directory");
        let dest = dir.join("tool");
        let planned = observe(&dest).expect("observe");
        std::fs::remove_dir(&dir).expect("rmdir");
        std::fs::write(&dir, b"x").expect("a file in its place");
        let err = link_at(&dest, "x", &planned).expect_err("unusable parent");
        assert!(
            matches!(&err, Error::UnusableParent { path, .. } if *path == dir),
            "{err}"
        );
        assert_eq!(
            std::fs::read(&dir).expect("kept"),
            b"x",
            "nothing replaced it"
        );
        assert_eq!(names(root.path()), ["dir", "file"], "no temporary link");
    }

    #[test]
    fn a_link_that_changed_since_plan_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let dest = root.path().join("tool");
        let planned = observe(&dest).expect("observe");
        std::os::unix::fs::symlink("theirs", &dest).expect("a link lands after plan");

        let err = link_at(&dest, "ours", &planned).expect_err("changed");
        assert!(matches!(err, Error::Changed { .. }), "{err}");
        assert_eq!(
            std::fs::read_link(&dest).expect("a link"),
            Path::new("theirs")
        );

        // Between stage and publish: the last look before the rename.
        let planned = observe(&dest).expect("observe");
        let staged =
            stage_link(&dest, Path::new("ours"), &planned, &mut CreatedDirs::new()).expect("stage");
        let temp = staged.temp_path().to_path_buf();
        std::fs::remove_file(&dest).expect("unlink");
        std::os::unix::fs::symlink("again", &dest).expect("relink");
        let refused = staged.publish().expect_err("changed before the rename");
        assert_eq!(refused.dest, dest);
        assert!(matches!(refused.error, Error::Changed { .. }));
        assert_eq!(
            std::fs::read_link(&dest).expect("a link"),
            Path::new("again")
        );
        assert!(
            std::fs::symlink_metadata(&temp).is_err(),
            "the temporary link is gone"
        );
    }

    #[test]
    fn a_rename_is_made_durable_by_a_directory_sync() {
        let root = tempfile::tempdir().expect("tempdir");
        let dest = root.path().join("tool");
        let planned = observe(&dest).expect("observe");
        let staged =
            stage_link(&dest, Path::new("x"), &planned, &mut CreatedDirs::new()).expect("stage");
        let temp = staged.temp_path().to_path_buf();
        assert!(
            temp.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(TEMP_PREFIX)),
            "{temp:?}"
        );
        let (published, events) = durable::recording(|| staged.publish());
        published.map_err(Unpublished::into_error).expect("publish");
        assert_eq!(
            events,
            [
                durable::Event::OpenDir(root.path().to_path_buf()),
                durable::Event::Rename {
                    from: temp,
                    to: dest.clone(),
                },
                durable::Event::SyncDir(root.path().to_path_buf()),
            ]
        );
    }

    #[test]
    fn a_link_staged_as_a_chosen_name_is_there_and_a_taken_name_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let dest = root.path().join("a/tool");
        let planned = observe(&dest).expect("observe");
        let prior = refuse_stage_link(&dest, &planned, &CreatedDirs::new()).expect("admitted");
        assert_eq!(prior.kind, Kind::Absent);
        assert!(!root.path().join("a").exists(), "the check makes nothing");

        let temp = crate::fs::temp_beside(&dest).expect("a name");
        let staged = stage_link_as(
            &dest,
            &temp,
            Path::new("t"),
            &planned,
            &mut CreatedDirs::new(),
        )
        .expect("stage");
        assert_eq!(staged.temp_path(), temp);
        assert_eq!(staged.created_dirs(), [root.path().join("a")]);
        assert_eq!(std::fs::read_link(&temp).expect("a link"), Path::new("t"));

        // The same name again is taken, and the link there is not replaced.
        let err = stage_link_as(
            &dest,
            &temp,
            Path::new("other"),
            &planned,
            &mut CreatedDirs::new(),
        )
        .expect_err("taken");
        assert!(matches!(err, Error::Write { .. }), "{err:?}");
        assert_eq!(std::fs::read_link(&temp).expect("kept"), Path::new("t"));

        // A file where plan saw nothing is refused before anything is made.
        let file = root.path().join("file");
        let planned = observe(&file).expect("observe");
        std::fs::write(&file, b"x").expect("since");
        assert!(matches!(
            refuse_stage_link(&file, &planned, &CreatedDirs::new()),
            Err(Error::Changed { .. })
        ));
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }
}
