//! The state directory's location and layout.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use rustix::io::Errno;

use super::Error;
use crate::fs::Mode;
use crate::paths::xdg_base;

/// The directory name under the XDG state base.
const DIR_NAME: &str = "bx";

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
    /// The XDG rule — honour the variable only when it is non-empty and
    /// absolute, else fall back to `~/.local/state` — is
    /// [`crate::paths::xdg_base`]'s, not this module's. bx has one XDG resolver
    /// and this is a caller of it.
    #[must_use]
    pub fn resolve_in(home: &Path, xdg_state_home: Option<&OsStr>) -> Self {
        Self::new(xdg_base(xdg_state_home, home, ".local/state").join(DIR_NAME))
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

    /// `local.toml` — this account's overrides, which are never committed.
    #[must_use]
    pub fn local_toml(&self) -> PathBuf {
        self.root.join("local.toml")
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

/// Check that an existing `path` is a directory, and narrow it to `mode` if it
/// is reachable by anyone but its owner.
fn tighten(path: &Path, mode: Mode) -> Result<(), Error> {
    // `metadata` follows symlinks on purpose: a state directory the user has
    // symlinked onto other storage is theirs to arrange, and refusing it would
    // be bx dictating a layout.
    let meta = std::fs::metadata(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(Error::NotADirectory {
            path: path.to_path_buf(),
        });
    }
    let found = Mode::from_bits(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
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
        home.set("XDG_STATE_HOME", Some(OsStr::new("/somewhere/else")));
        assert_eq!(
            StateDir::resolve(home.path()).root(),
            home.child(".local/state/bx"),
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
    fn a_symlinked_state_directory_is_accepted() {
        let home = guarded_home();
        let real = home.child("elsewhere");
        std::fs::create_dir_all(&real).expect("real");
        std::fs::create_dir_all(home.child(".local/state")).expect("ancestors");
        std::os::unix::fs::symlink(&real, home.child(".local/state/bx")).expect("symlink");
        let dir = StateDir::resolve(home.path());
        dir.ensure().expect("ensure");
        assert!(real.join("restore").is_dir());
    }
}
