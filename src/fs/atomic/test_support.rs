//! Fixtures the tests of more than one part of [`super`] share.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Mutex;

use super::observe::mode_of;
use super::{CreatedDirs, Desired, Error, Outcome, Staged, compare, observe, set_mode, stage};
use crate::fs::Mode;
use crate::testing::GuardedHome;

/// Serialises the one test that mutates the process `umask`.
///
/// Held in addition to whatever lock the home guard takes, so the
/// serialisation does not depend on the guard continuing to take one.
/// Nothing else in the suite depends on the `umask` anyway — every write
/// `fchmod`s and every directory bx creates is `chmod`'d — so a leak could
/// not flip another assertion even without this.
pub(super) static UMASK: Mutex<()> = Mutex::new(());

/// Serialises the one test that mutates the process working directory.
///
/// Every other test in the suite addresses its files absolutely, so a leak
/// could not flip another assertion; the lock is here so the two relative
/// writes cannot race each other or a future third.
pub(super) static CWD: Mutex<()> = Mutex::new(());

/// The mode on disk, following no symlink.
pub(super) fn mode_of_path(path: &Path) -> Mode {
    mode_of(&std::fs::symlink_metadata(path).expect("stat"))
}

/// Every name in a directory, sorted, so an orphan is visible.
pub(super) fn names_in(dir: &Path) -> Vec<OsString> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    names.sort();
    names
}

/// A file seeded at an exact mode, the umask notwithstanding.
pub(super) fn seed(path: &Path, bytes: &[u8], mode: Mode) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("seed parent");
    }
    std::fs::write(path, bytes).expect("seed");
    set_mode(path, mode).expect("seed mode");
}

/// What bx wants, for the comparison tests.
pub(super) fn desired(bytes: &[u8], mode: Mode) -> Desired<'_> {
    Desired { bytes, mode }
}

/// `plan`'s observation, then `stage` on it, with nothing changing in
/// between.
pub(super) fn stage_now(dest: &Path, mode: Mode) -> Result<Staged, Error> {
    let planned = observe(dest)?;
    stage(dest, mode, &planned, &mut CreatedDirs::new())
}

/// The outcome for a destination under a guarded home.
pub(super) fn outcome_for(home: &GuardedHome, rel: &str, bytes: &[u8], mode: Mode) -> Outcome {
    let path = home.child(rel);
    let observed = observe(&path).expect("observe");
    compare(&observed, &desired(bytes, mode), home.path())
}
