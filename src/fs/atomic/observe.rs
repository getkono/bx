//! What is at a destination and in the directory above it, as one `lstat`
//! each reported it, and the one spelling of a path every entry point looks
//! at.

use std::path::{Path, PathBuf};

use rustix::io::Errno;

use super::Error;
use crate::fs::mode::{Kind, Mode};
use crate::hash::ContentHash;

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
    /// What [`Filled::publish`](super::Filled::publish) checks the destination against immediately
    /// before the rename, so a file that changed after it was observed is not
    /// replaced, and a prior state recorded from this observation is never
    /// older than the file it displaces.
    pub stamp: Option<Stamp>,
}

impl Observed {
    /// The digest of the bytes that are there now, for a regular file.
    ///
    /// For a mode-only `Modify` this is the `written` its ledger entry records:
    /// that change is applied through [`stage`](super::stage()) with the bytes already there,
    /// so what that write fills is the same bytes, with the same digest.
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
    pub(super) dev: u64,
    pub(super) ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    /// The stamp of the file `meta` describes.
    pub(super) fn of(meta: &std::fs::Metadata) -> Self {
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
    /// chmod a directory through one — [`ensure_dir`](super::ensure_dir) refuses a link — so the
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
    /// [`compare`](super::compare())'s parent note is written against `home`, so `plan` prints
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
/// observation's `path` is spelled without it. [`stage`](super::stage()), [`ensure_dir`](super::ensure_dir) and
/// [`set_mode`](super::set_mode) spell their paths the same way.
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
pub(super) fn lexical(path: &Path) -> Result<PathBuf, Error> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(Error::ParentComponent(path.to_path_buf()));
    }
    Ok(path.components().collect())
}

/// The directory `path` will be written into.
pub(in crate::fs) fn parent_of(path: &Path) -> Result<&Path, Error> {
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
pub(super) fn optional_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, Error> {
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
pub(super) fn mode_of(meta: &std::fs::Metadata) -> Mode {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;

    use crate::fs::atomic::test_support::{mode_of_path, names_in, outcome_for, seed};
    use crate::fs::atomic::{
        CreatedDirs, Drift, compare_dir, ensure_dir, observe, set_mode, stage, write_atomically,
    };
    use crate::testing::guarded_home;

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
    fn a_dangling_symlink_parent_is_a_conflict_rather_than_a_create() {
        let home = guarded_home();
        // ~/.config is a link into a dotfiles repository that is not checked
        // out yet. `metadata` reports ENOENT for it exactly as it would for a
        // directory that is simply missing.
        std::os::unix::fs::symlink("nowhere", home.child(".config")).expect("symlink");

        let outcome = outcome_for(&home, ".config/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(
            outcome.drift,
            Drift::Conflict,
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
        assert_eq!(outcome.drift, Drift::Conflict);
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
        assert_eq!(outcome.drift, Drift::Conflict);
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
        assert_eq!(outcome.drift, Drift::Conflict);
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
    fn observe_does_not_follow_a_symlink() {
        let home = guarded_home();
        seed(&home.child("real"), b"real", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

        let observed = observe(&home.child("link")).expect("observe");
        assert_eq!(observed.kind, Kind::Symlink);
        assert_eq!(observed.bytes, None, "a link has no content of its own");
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
                compare_dir(&observed, Mode::PRIVATE_DIR).drift,
                Drift::Conflict,
                "{spelled}",
            );
            assert_eq!(
                ensure_dir(&path, Mode::PRIVATE_DIR, &observed, &mut CreatedDirs::new())
                    .expect("a verdict")
                    .drift,
                Drift::Conflict,
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
    fn a_non_directory_further_up_is_a_conflict_not_a_read_error() {
        let home = guarded_home();
        seed(&home.child("f"), b"a file", Mode::DEFAULT_FILE);
        std::os::unix::fs::symlink("loop", home.child("loop")).expect("symlink");
        std::os::unix::fs::symlink("f", home.child("l")).expect("symlink");

        for (rel, culprit) in [("f/sub/x", "f"), ("loop/a/x", "loop"), ("l/a/x", "l")] {
            let outcome = outcome_for(&home, rel, b"x", Mode::DEFAULT_FILE);
            assert_eq!(outcome.drift, Drift::Conflict, "{rel}");
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
}
