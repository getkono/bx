//! Directory targets, and the parents a write creates on its way to a file:
//! which of them this apply made, and at what mode.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustix::io::Errno;

use super::observe::{lexical, observe, optional_metadata};
use super::setid::{refuse_dir_set_id_dropped, refuse_setgid_a_chmod_strips, set_back};
use super::{Drift, Error, Observed, Parent, compare_dir, set_mode};
use crate::fs::mode::{Kind, Mode};

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
/// `created` is this apply's [`CreatedDirs`]; [`stage`](super::stage()) and this function both
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
/// empty, exactly as [`stage`](super::stage()) leaves one for an abandoned write.
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
    /// The change performed — the one `plan` announced.
    pub drift: Drift,
    /// What was at the path immediately before, which is what `plan` saw. For
    /// a `Modify` its `mode` is the mode that was overwritten. For a directory
    /// an earlier write in this apply created, it is `plan`'s observation:
    /// nothing was there before this apply.
    pub prior: Observed,
    /// The directories this target claims, deepest first — the path itself
    /// and any ancestor this call had to invent, less an ancestor another
    /// directory target in this apply declares, which that target claims —
    /// in the order a reversal removes them. For a directory an earlier call in
    /// this apply made, just the path. Empty unless `drift` is `Create`.
    pub created_dirs: Vec<PathBuf>,
}

/// The directories one `apply` has created so far, and the modes its
/// directory targets declare.
///
/// Start one per apply, [`declare`](Self::declare) every directory target in
/// it before applying any target, and pass the same one to every [`stage`](super::stage()) and
/// [`ensure_dir`] in the apply. That is what makes the order of targets not
/// matter:
///
/// * [`stage`](super::stage()) creates a missing declared directory at its declared mode, not
///   [`Mode::DEFAULT_DIR`], so no file is published into a directory wider
///   than its target declares. Beneath a declared directory that already
///   exists wider than declared it refuses with
///   [`Error::DirectoryTargetPending`].
/// * Every directory has exactly one claimant. A declared directory is claimed
///   by its own directory target's [`EnsuredDir::created_dirs`] alone:
///   `Filled::created_dirs` and a deeper target's `created_dirs` leave it
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
    pub(super) declared: BTreeMap<DirKey, Mode>,
}

/// A directory path as [`CreatedDirs`] keys it.
///
/// Both maps are keyed on this and nothing else, and the only way to make one is
/// [`DirKey::of`]. So no method of `CreatedDirs` can read or write either map
/// with a path that did not pass through here: a lookup that forgot to would
/// not compile. That matters because `declare` and `declared` are public, and a
/// caller outside `fs::atomic` — the apply engine that will hold one set for the
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
///   outside `fs::atomic` — the apply engine that will hold one set for a whole
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
pub(super) struct DirKey(PathBuf);

impl DirKey {
    /// The key for `path`: its components, which drops a trailing separator and
    /// every `.`, exactly as [`lexical`] spells a path before using it.
    fn of(path: &Path) -> Self {
        Self(path.components().collect())
    }

    /// The normalised path this key is.
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

/// One directory an apply created: the mode it was created at, and which
/// directory it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Made {
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
    pub(super) fn record(
        &mut self,
        made: Vec<(PathBuf, Made)>,
        own: Option<&Path>,
    ) -> Vec<PathBuf> {
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
    if announced.drift == Drift::Create
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
            drift: Drift::Create,
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
    match outcome.drift {
        Drift::Create => {
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
        Drift::Modify => {
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
        drift: outcome.drift,
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
pub(super) fn create_missing_dirs(
    dir: &Path,
    created: &CreatedDirs,
) -> Result<Vec<(PathBuf, Made)>, Error> {
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
/// assumed, exactly as [`Staged::fill`](super::Staged::fill) reads a file's back. Returns the
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::sync::Mutex;

    use crate::fs::atomic::observe::mode_of;
    use crate::fs::atomic::test_support::{
        UMASK, desired, mode_of_path, names_in, outcome_for, seed,
    };
    use crate::fs::atomic::{Outcome, compare, stage};
    use crate::paths::Portable;
    use crate::state::{Mechanism, NewEntry, PriorBytes};
    use crate::testing::{GuardedHome, guarded_home};

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
            compare_dir(&planned, Mode::PRIVATE_DIR).drift,
            Drift::Unchanged,
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
            compare_dir(&planned, Mode::PRIVATE_DIR).drift,
            Drift::Create
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
            compare_dir(&planned, Mode::PRIVATE_DIR).drift,
            Drift::Unchanged,
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

    #[test]
    fn a_directory_target_that_denies_its_owner_access_is_applied_as_declared() {
        let home = guarded_home();
        // Nothing beneath either is declared, so bx never lists, writes into
        // or searches them: whether a mode is too narrow for what lies beneath
        // is the plan layer's to judge.
        for (name, before, declared, action) in [
            ("ro", Some(Mode::DEFAULT_DIR), 0o555, Drift::Modify),
            (".aws", None, 0o500, Drift::Create),
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
                (first.drift, first.mode_drift),
                (action, before.map(|mode| (mode, declared))),
                "{name}: the first plan",
            );
            let applied = ensure_dir(&path, declared, &planned, &mut CreatedDirs::new())
                .expect("a childless directory target applies");
            assert_eq!(applied.drift, action, "{name}");
            assert_eq!(mode_of_path(&path), declared, "{name}");
            let second = compare_dir(&observe(&path).expect("plan observes"), declared);
            assert_eq!(second.drift, Drift::Unchanged, "{name}: the second plan");
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
        assert_eq!(created.drift, Drift::Create);
        assert_eq!(created.prior.kind, Kind::Absent);
        assert_eq!(
            created.created_dirs,
            [home.child("a/b/c"), home.child("a/b"), home.child("a")],
            "deepest first, the path itself included, for a reversal to remove",
        );

        set_mode(&dir, Mode::DEFAULT_DIR).expect("widen");
        let closed = apply_dir(&dir, Mode::PRIVATE_DIR).expect("modify");
        assert_eq!(closed.drift, Drift::Modify);
        assert_eq!(
            closed.prior.mode,
            Some(Mode::DEFAULT_DIR),
            "the mode it overwrote, for the ledger to restore",
        );
        assert!(closed.created_dirs.is_empty());

        let unchanged = apply_dir(&dir, Mode::PRIVATE_DIR).expect("unchanged");
        assert_eq!(unchanged.drift, Drift::Unchanged);
        assert_eq!(unchanged.prior.mode, Some(Mode::PRIVATE_DIR));
        assert!(unchanged.created_dirs.is_empty());
    }

    #[test]
    fn ensure_dir_creates_at_the_declared_mode_and_closes_the_drift_plan_announced() {
        let home = guarded_home();
        let dir = home.child(".ssh");

        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("create").drift,
            Drift::Create,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Idempotence: the second call changes nothing and reports nothing.
        assert_eq!(
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("again").drift,
            Drift::Unchanged,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);

        // Drift is announced by plan, which changes nothing...
        set_mode(&dir, Mode::DEFAULT_DIR).expect("widen");
        let planned = dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR);
        assert_eq!(planned.drift, Drift::Modify);
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
            apply_dir(&dir, Mode::PRIVATE_DIR).expect("drift").drift,
            planned.drift,
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR);
        assert_eq!(
            dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR).drift,
            Drift::Unchanged,
            "the second plan is empty",
        );
    }

    #[test]
    fn planning_a_directory_target_creates_nothing() {
        let home = guarded_home();

        let outcome = dir_outcome_for(&home, "declared/dir", Mode::PRIVATE_DIR);
        assert_eq!(outcome.drift, Drift::Create);
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
                .drift,
            outcome.drift,
        );
        assert_eq!(mode_of_path(&home.child("declared/dir")), Mode::PRIVATE_DIR);
        assert_eq!(mode_of_path(&home.child("declared")), Mode::DEFAULT_DIR);
    }

    #[test]
    fn a_dangling_link_above_a_directory_target_is_a_conflict_at_plan_time() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child("d")).expect("symlink");

        let outcome = dir_outcome_for(&home, "d/a", Mode::PRIVATE_DIR);
        assert_eq!(outcome.drift, Drift::Conflict);
        let note = outcome.note.expect("the cause must be named");
        assert!(note.contains("does not resolve to a directory"), "{note}");

        // A dangling link *at* the path is a link, and a conflict too.
        assert_eq!(
            dir_outcome_for(&home, "d", Mode::PRIVATE_DIR).drift,
            Drift::Conflict,
        );
        assert_eq!(
            apply_dir(&home.child("d"), Mode::PRIVATE_DIR)
                .expect("a verdict")
                .drift,
            Drift::Conflict,
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
            assert_eq!(outcome.drift, Drift::Conflict, "{rel}");
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
            compare_dir(&planned_dir, Mode::PRIVATE_DIR).drift,
            Drift::Create
        );
        assert_eq!(
            compare(
                &planned_file,
                &desired(b"Host *\n", Mode::PRIVATE_FILE),
                home.path(),
            )
            .drift,
            Drift::Create,
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
        assert_eq!(ensured.drift, Drift::Create);
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
            dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR).drift,
            Drift::Unchanged,
            "the second plan is empty for the directory",
        );
        assert_eq!(
            outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE).drift,
            Drift::Unchanged,
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

            assert_eq!(ensured_a.drift, Drift::Create, "{order}");
            assert_eq!(ensured_b.drift, Drift::Create, "{order}");
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
                dir_outcome_for(&home, "a", mode_a).drift,
                Drift::Unchanged,
                "{order}: the second plan is empty",
            );
            assert_eq!(
                dir_outcome_for(&home, "a/b", Mode::PRIVATE_DIR).drift,
                Drift::Unchanged,
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
            assert_eq!(ensured.drift, Drift::Create, "{order}");
            assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR, "{order}");
            assert_eq!(mode_of_path(&file), Mode::DEFAULT_FILE, "{order}");
            assert_eq!(std::fs::read(&file).expect("read"), b"notes\n", "{order}");
            assert_eq!(
                dir_outcome_for(&home, ".ssh", Mode::PRIVATE_DIR).drift,
                Drift::Unchanged,
                "{order}: the second plan is empty for the directory",
            );
            assert_eq!(
                outcome_for(&home, ".ssh/notes", b"notes\n", Mode::DEFAULT_FILE).drift,
                Drift::Unchanged,
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
            compare_dir(&planned_dir, Mode::PRIVATE_DIR).drift,
            Drift::Modify
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
                let entry = NewEntry::for_write(&filled, home.path(), Mechanism::Own)
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
    fn ensure_dir_creates_implicit_ancestors_at_the_default_dir_mode() {
        let home = guarded_home();
        assert_eq!(
            apply_dir(&home.child("a/b/c"), Mode::PRIVATE_DIR)
                .expect("create")
                .drift,
            Drift::Create,
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
            apply_dir(&path, Mode::PRIVATE_DIR).expect("report").drift,
            Drift::Conflict,
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"x");
        assert_eq!(mode_of_path(&path), Mode::DEFAULT_FILE);
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
                .drift,
            Drift::Conflict,
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
        let entry =
            NewEntry::for_write(&filled, home.path(), Mechanism::Own).expect("a portable entry");
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
    fn ensure_dir_under_a_dangling_link_is_a_conflict_not_a_write_error() {
        let home = guarded_home();
        std::os::unix::fs::symlink("nowhere", home.child("d")).expect("symlink");

        assert_eq!(
            apply_dir(&home.child("d/a"), Mode::PRIVATE_DIR)
                .expect("a verdict, not an error")
                .drift,
            Drift::Conflict,
        );
        assert!(
            std::fs::symlink_metadata(home.child("nowhere")).is_err(),
            "nothing was created at the far end",
        );
    }
}
