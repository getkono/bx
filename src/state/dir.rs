//! The state directory's location and layout.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, RenameFlags};
use rustix::io::Errno;

use super::Error;
use super::lock::ExclusiveLock;
use crate::fs::Mode;

/// `$XDG_STATE_HOME/bx` — bx's machine-owned half.
///
/// Every path name in the state directory appears in exactly one place in the
/// crate: here. Nothing else joins `ledger.mpk`, `restore/` or `lock` onto a
/// root, so a rename is one edit rather than a search.
///
/// Holding a `StateDir` says nothing about whether the directory exists; call
/// [`StateDir::ensure`] for that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// The state directory for `home`, with no `$XDG_STATE_HOME` override.
    ///
    /// This reads no environment variable, which is the point: two tests with
    /// two tempdir homes get two independent state directories, and neither can
    /// be redirected by whatever the process environment happens to hold.
    ///
    /// A caller that must honour the user's `$XDG_STATE_HOME` — the binary,
    /// once — passes it to [`StateDir::resolve_in`] instead.
    #[must_use]
    pub fn resolve(home: &Path) -> Self {
        Self::resolve_in(home, None)
    }

    /// The state directory for `home`, honouring an `$XDG_STATE_HOME` value.
    ///
    /// The resolution itself is [`crate::config::layers::state_dir`]'s, not this
    /// module's, and this delegates to it rather than repeating the XDG rule.
    /// The local layer and the ledger have to agree about which directory they
    /// are in; two resolvers that agree today are two resolvers that can
    /// disagree tomorrow.
    #[must_use]
    pub fn resolve_in(home: &Path, xdg_state_home: Option<&OsStr>) -> Self {
        Self::new(crate::config::layers::state_dir(home, xdg_state_home))
    }

    /// A state directory at an already-known path.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `local.toml` — this account's own layer, which is never committed.
    ///
    /// Delegates to [`crate::config::layers::local_layer_path`], so the layer
    /// loader and the state directory cannot name two different files.
    #[must_use]
    pub fn local_toml(&self) -> PathBuf {
        crate::config::layers::local_layer_path(&self.root)
    }

    /// `ledger.mpk` — what bx wrote, and what it displaced.
    #[must_use]
    pub fn ledger(&self) -> PathBuf {
        self.root.join("ledger.mpk")
    }

    /// `fingerprints.mpk` — the cache-invalidation store.
    #[must_use]
    pub fn fingerprints(&self) -> PathBuf {
        self.root.join("fingerprints.mpk")
    }

    /// `journal.mpk` — the write-ahead journal.
    ///
    /// Named here so the layout stays in one place. Its contents belong to the
    /// recovery entry; nothing in this module reads or writes it.
    #[must_use]
    pub fn journal(&self) -> PathBuf {
        self.root.join("journal.mpk")
    }

    /// `restore/` — content-addressed copies of the bytes bx displaced.
    #[must_use]
    pub fn restore(&self) -> PathBuf {
        self.root.join("restore")
    }

    /// `shell/` — generated shell fragments, sourced at startup.
    #[must_use]
    pub fn shell(&self) -> PathBuf {
        self.root.join("shell")
    }

    /// `lock` — the advisory lock file. Created once and never unlinked.
    #[must_use]
    pub fn lock(&self) -> PathBuf {
        self.root.join("lock")
    }

    /// The first quarantine path for a damaged state file: `<name>.corrupt`.
    ///
    /// A later quarantine of the same file never reuses it while it is
    /// occupied: [`move_aside`] takes the first free of `<name>.corrupt`,
    /// `<name>.corrupt.1`, `<name>.corrupt.2`, …. Numbered rather than
    /// timestamped, so the name a given sequence of damage produces is
    /// deterministic; and never over an earlier one, because the earlier one
    /// may be the only index there is to the user's restore blobs.
    #[must_use]
    pub(crate) fn quarantine(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(".corrupt");
        PathBuf::from(name)
    }

    /// The `n`th quarantine path: [`StateDir::quarantine`] for `0`, then
    /// `<name>.corrupt.<n>`.
    #[must_use]
    pub(crate) fn quarantine_nth(path: &Path, n: u64) -> PathBuf {
        let mut name = Self::quarantine(path).into_os_string();
        if n > 0 {
            name.push(format!(".{n}"));
        }
        PathBuf::from(name)
    }

    /// Create the state directory and its subdirectories, at `0700`.
    ///
    /// Idempotent: running it twice changes nothing and fails on nothing.
    ///
    /// Missing **ancestors** (`~/.local`, `~/.local/state`) are created with the
    /// process `umask`, because they are shared with every other XDG-aware tool
    /// and are not bx's to tighten. The directories bx invents — `bx/`,
    /// `bx/restore/`, `bx/shell/` — are created at `0700` and tightened back to
    /// `0700` if they are found wider, because they hold `local.toml`, the age
    /// identity, and prior copies of the user's private files. Changing the mode
    /// of a directory bx created is not rewriting a byte the user wrote.
    ///
    /// # Errors
    ///
    /// [`Error::NotADirectory`] when something that is not a directory occupies
    /// one of those paths, naming the path to clear, and [`Error::CreateDir`]
    /// for any other failure.
    pub fn ensure(&self) -> Result<(), Error> {
        ensure_dir(&self.root, Mode::PRIVATE_DIR)?;
        ensure_dir(&self.restore(), Mode::PRIVATE_DIR)?;
        ensure_dir(&self.shell(), Mode::PRIVATE_DIR)
    }
}

/// Create `path` at exactly `mode`, or verify and tighten an existing one.
///
/// Missing **ancestors** are created with the process `umask`: they are shared
/// with every other XDG-aware tool and are not bx's to tighten. Only `path`
/// itself gets `mode`.
///
/// The explicit `chmod` after `mkdir` is not redundant: `mkdir` applies the
/// process `umask`, so an unusual `umask` would otherwise leave a directory bx
/// promised at `0700` at something else.
pub(crate) fn ensure_dir(path: &Path, mode: Mode) -> Result<(), Error> {
    let create_failed = |source: Errno| Error::CreateDir {
        path: path.to_path_buf(),
        source: source.into(),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    match rustix::fs::mkdir(path, mode.into()) {
        Ok(()) => rustix::fs::chmod(path, mode.into()).map_err(create_failed),
        Err(Errno::EXIST) => tighten(path, mode),
        Err(source) => Err(create_failed(source)),
    }
}

/// Move a damaged state file to the first quarantine name nothing occupies.
///
/// Demands the exclusive lock, because a rename by path moves whatever is at
/// the path *now*: only while no writer can save is that still the file whose
/// bytes were judged damaged.
///
/// The rename is `RENAME_NOREPLACE`, so an existing quarantine is never
/// destroyed — not by an earlier bx's leftovers, and not by a race. A
/// filesystem that does not support the flag (`EINVAL`) falls back to checking
/// for the name first and renaming second, which the lock makes sound against
/// every other bx.
///
/// The lock must be the one of the directory holding `path` — see
/// [`check_lock`] — or nothing is renamed.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] for another directory's lock, and
/// otherwise the first failure that is not "that name is taken".
pub(crate) fn move_aside(path: &Path, lock: &ExclusiveLock) -> std::io::Result<PathBuf> {
    check_lock(path, lock).map_err(|refused| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, refused.to_string())
    })?;
    let mut n: u64 = 0;
    loop {
        let candidate = StateDir::quarantine_nth(path, n);
        match rustix::fs::renameat_with(CWD, path, CWD, &candidate, RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(candidate),
            Err(Errno::EXIST) => {}
            Err(Errno::INVAL) if std::fs::symlink_metadata(&candidate).is_err() => {
                std::fs::rename(path, &candidate)?;
                return Ok(candidate);
            }
            Err(Errno::INVAL) => {}
            Err(source) => return Err(source.into()),
        }
        n = n
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("no free quarantine name"))?;
    }
}

/// Refuse `lock` unless it is the lock of the state directory holding `path`.
///
/// Every operation that demands an [`ExclusiveLock`] demands it for one
/// directory. A quarantine or a save under another directory's lock is as
/// unguarded as one under none: another bx holding *this* directory's lock can
/// be saving the very file being moved.
///
/// # Errors
///
/// [`Error::WrongLock`], naming both lock files.
pub(crate) fn check_lock(path: &Path, lock: &ExclusiveLock) -> Result<(), Error> {
    let root = path.parent().unwrap_or_else(|| Path::new(""));
    if lock.guards(root) {
        return Ok(());
    }
    Err(Error::WrongLock {
        held: lock.path().to_path_buf(),
        needed: StateDir::new(root.to_path_buf()).lock(),
    })
}

/// Check that an existing `path` is a directory, and narrow it to `mode` if it
/// is reachable by anyone but its owner.
fn tighten(path: &Path, mode: Mode) -> Result<(), Error> {
    let read_failed = |source| Error::Read {
        path: path.to_path_buf(),
        source,
    };
    let linked = std::fs::symlink_metadata(path)
        .map_err(read_failed)?
        .file_type()
        .is_symlink();
    // `metadata` follows symlinks on purpose: a state directory the user has
    // symlinked onto other storage is theirs to arrange, and refusing it would
    // be bx dictating a layout.
    let meta = std::fs::metadata(path).map_err(read_failed)?;
    if !meta.is_dir() {
        return Err(Error::NotADirectory {
            path: path.to_path_buf(),
        });
    }
    let found = Mode::from_bits(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
    if found.is_shared() && linked {
        // Never `chmod` through a link: the directory it names is not one bx
        // created, and may be shared with other users. Leaving it wide would
        // put prior copies of private files where others can read them, so
        // the only answer left is to refuse and say why.
        return Err(Error::SharedLinkedDir {
            path: path.to_path_buf(),
        });
    }
    if found.is_shared() {
        tracing::warn!(
            path = %path.display(),
            found = %found,
            tightened_to = %mode,
            "the bx state directory was readable beyond its owner; tightening it",
        );
        rustix::fs::chmod(path, mode.into()).map_err(|source| Error::CreateDir {
            path: path.to_path_buf(),
            source: source.into(),
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    use crate::testing::guarded_home;

    fn mode_of(path: &Path) -> Mode {
        Mode::from_bits(std::fs::metadata(path).expect("stat").permissions().mode())
    }

    #[test]
    fn the_layout_matches_the_specification() {
        let dir = StateDir::new(PathBuf::from("/s/bx"));
        let cases: [(PathBuf, &str); 8] = [
            (dir.root().to_path_buf(), "/s/bx"),
            (dir.local_toml(), "/s/bx/local.toml"),
            (dir.ledger(), "/s/bx/ledger.mpk"),
            (dir.fingerprints(), "/s/bx/fingerprints.mpk"),
            (dir.journal(), "/s/bx/journal.mpk"),
            (dir.restore(), "/s/bx/restore"),
            (dir.shell(), "/s/bx/shell"),
            (dir.lock(), "/s/bx/lock"),
        ];
        for (got, want) in cases {
            assert_eq!(got, PathBuf::from(want));
        }
    }

    #[test]
    fn the_default_location_is_under_local_state() {
        let dir = StateDir::resolve(Path::new("/home/someone"));
        assert_eq!(dir.root(), Path::new("/home/someone/.local/state/bx"));
    }

    #[test]
    fn an_absolute_xdg_state_home_is_honoured() {
        let dir = StateDir::resolve_in(Path::new("/home/someone"), Some(OsStr::new("/srv/state")));
        assert_eq!(dir.root(), Path::new("/srv/state/bx"));
    }

    #[test]
    fn a_relative_or_empty_xdg_state_home_is_ignored() {
        for bogus in ["", "relative/state"] {
            let dir = StateDir::resolve_in(Path::new("/home/someone"), Some(OsStr::new(bogus)));
            assert_eq!(dir.root(), Path::new("/home/someone/.local/state/bx"));
        }
    }

    #[test]
    fn the_layer_loader_and_the_state_directory_agree() {
        // The local layer and the ledger must be in the same directory, and
        // `local.toml` must be one file with one name. Both are delegated
        // rather than repeated; this is the test that says so.
        let home = Path::new("/home/someone");
        for xdg in [None, Some(OsStr::new("/srv/state"))] {
            let dir = StateDir::resolve_in(home, xdg);
            let resolved = crate::config::layers::state_dir(home, xdg);
            assert_eq!(dir.root(), resolved);
            assert_eq!(
                dir.local_toml(),
                crate::config::layers::local_layer_path(&resolved),
            );
        }
    }

    #[test]
    fn two_homes_resolve_to_two_state_directories() {
        let a = StateDir::resolve(Path::new("/tmp/a"));
        let b = StateDir::resolve(Path::new("/tmp/b"));
        assert_ne!(a.root(), b.root());
        assert!(a.root().starts_with("/tmp/a"));
        assert!(b.root().starts_with("/tmp/b"));
    }

    #[test]
    fn resolution_ignores_the_process_environment() {
        let home = guarded_home();
        // Whatever `$XDG_STATE_HOME` holds in this process — and the suite
        // mutates no environment variable, so it holds whatever the developer's
        // shell set — `resolve` reads none of it and answers under the home it
        // was given. The only way the value reaches resolution is as an
        // argument, which is what lets two tempdir homes get two independent
        // state directories.
        assert_eq!(
            StateDir::resolve(home.path()).root(),
            home.child(".local/state/bx"),
        );
        assert_eq!(
            StateDir::resolve_in(home.path(), Some(OsStr::new("/somewhere/else"))).root(),
            Path::new("/somewhere/else/bx"),
        );
    }

    #[test]
    fn the_state_directory_is_never_inside_the_config_repo() {
        let home = Path::new("/home/someone");
        let state = StateDir::resolve(home);
        let config = crate::paths::config_root_in(home, None);
        assert!(!state.root().starts_with(&config));
        assert!(!config.starts_with(state.root()));
    }

    #[test]
    fn ensure_creates_the_state_directory_at_0700() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        assert!(dir.root().is_dir());
        assert_eq!(mode_of(dir.root()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_creates_restore_and_shell_at_0700() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        assert_eq!(mode_of(&dir.restore()), Mode::PRIVATE_DIR);
        assert_eq!(mode_of(&dir.shell()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_is_idempotent() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("first");
        let before: Vec<_> = std::fs::read_dir(dir.root())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        dir.ensure().expect("second");
        let after: Vec<_> = std::fs::read_dir(dir.root())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(before, after);
        assert_eq!(mode_of(dir.root()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_tightens_a_group_readable_state_directory() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("first");
        std::fs::set_permissions(dir.root(), std::fs::Permissions::from_mode(0o755))
            .expect("widen");
        std::fs::set_permissions(dir.restore(), std::fs::Permissions::from_mode(0o750))
            .expect("widen");
        dir.ensure().expect("second");
        assert_eq!(mode_of(dir.root()), Mode::PRIVATE_DIR);
        assert_eq!(mode_of(&dir.restore()), Mode::PRIVATE_DIR);
    }

    #[test]
    fn ensure_leaves_an_owner_only_directory_alone() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("first");
        // 0500 is not shared, so it is not bx's business to change it.
        std::fs::set_permissions(dir.shell(), std::fs::Permissions::from_mode(0o500))
            .expect("narrow");
        dir.ensure().expect("second");
        assert_eq!(mode_of(&dir.shell()), Mode::from_bits(0o500));
    }

    #[test]
    fn ensure_creates_missing_ancestors_without_tightening_them() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");

        // The umask is whatever the test runner's is, so the assertion is
        // relative: an ancestor gets the same mode an ordinary `mkdir` would.
        let control = home.child("control");
        std::fs::create_dir(&control).expect("control");
        assert_eq!(mode_of(&home.child(".local")), mode_of(&control));
        assert_eq!(mode_of(&home.child(".local/state")), mode_of(&control));
    }

    #[test]
    fn ensure_reports_a_file_occupying_the_state_directory_path() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        home.write(".local/state/bx", "not a directory");
        let err = dir.ensure().expect_err("must fail");
        assert!(
            matches!(&err, Error::NotADirectory { path } if path == dir.root()),
            "unexpected error: {err}",
        );
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn ensure_reports_a_file_occupying_a_subdirectory_path() {
        let home = guarded_home();
        let dir = StateDir::resolve(home.path());
        home.write(".local/state/bx/restore", "not a directory");
        let err = dir.ensure().expect_err("must fail");
        assert!(
            matches!(&err, Error::NotADirectory { path } if *path == dir.restore()),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn ensure_reports_an_uncreatable_directory() {
        let home = guarded_home();
        // A file, not a directory, in the ancestor chain: `create_dir_all`
        // cannot descend through it.
        home.write(".local", "not a directory");
        let dir = StateDir::resolve(home.path());
        let err = dir.ensure().expect_err("must fail");
        assert!(matches!(err, Error::CreateDir { .. }), "got {err}");
    }

    #[test]
    fn a_quarantine_name_appends_rather_than_replacing_the_extension() {
        assert_eq!(
            StateDir::quarantine(Path::new("/s/bx/ledger.mpk")),
            PathBuf::from("/s/bx/ledger.mpk.corrupt"),
        );
        assert_eq!(
            StateDir::quarantine_nth(Path::new("/s/bx/ledger.mpk"), 0),
            PathBuf::from("/s/bx/ledger.mpk.corrupt"),
        );
        assert_eq!(
            StateDir::quarantine_nth(Path::new("/s/bx/ledger.mpk"), 12),
            PathBuf::from("/s/bx/ledger.mpk.corrupt.12"),
        );
    }

    #[test]
    fn another_directorys_lock_moves_nothing_aside() {
        // Review round 4: `move_aside` ignored which directory its lock
        // guarded, so A's lock quarantined B's ledger while B's own bx could be
        // saving it.
        let a = guarded_home();
        let b = guarded_home();
        let lock_a = ExclusiveLock::acquire(&StateDir::resolve(a.path())).expect("A's lock");
        let dir_b = StateDir::resolve(b.path());
        dir_b.ensure().expect("ensure");
        std::fs::write(dir_b.ledger(), b"damaged").expect("seed");

        let err = move_aside(&dir_b.ledger(), &lock_a).expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("not the lock"), "{err}");
        assert_eq!(std::fs::read(dir_b.ledger()).expect("in place"), b"damaged");
        assert!(!StateDir::quarantine(&dir_b.ledger()).exists());

        let lock_b = ExclusiveLock::acquire(&dir_b).expect("B's lock");
        let aside = move_aside(&dir_b.ledger(), &lock_b).expect("B's own lock moves it");
        assert_eq!(aside, StateDir::quarantine(&dir_b.ledger()));
    }

    #[test]
    fn a_symlinked_state_directory_is_accepted() {
        let home = guarded_home();
        let real = home.child("elsewhere");
        std::fs::create_dir_all(&real).expect("real");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("private");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&real, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        assert!(real.join("restore").is_dir());
        assert_eq!(mode_of(&real.join("restore")), Mode::PRIVATE_DIR);
    }

    #[test]
    fn a_symlinked_state_directory_onto_a_shared_directory_is_refused_not_chmodded() {
        // Review round 3: `tighten` followed the link and narrowed the
        // directory it named — one bx did not create, and may share with others.
        let home = guarded_home();
        let shared = home.child("shared");
        std::fs::create_dir_all(&shared).expect("shared");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).expect("wide");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&shared, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());

        let err = dir.ensure().expect_err("must refuse");
        assert!(
            matches!(&err, Error::SharedLinkedDir { path } if path == dir.root()),
            "got {err}",
        );
        assert!(err.to_string().contains("0700"), "{err}");
        assert_eq!(mode_of(&shared), Mode::from_bits(0o755), "left as it was");
        assert!(!shared.join("restore").exists(), "nothing was put in it");
    }
}
