//! Check 5: a directory whose mode is wider than a file bx declared inside it.
//!
//! The comparison is [`Mode::is_wider_than`], the one `plan` makes before it
//! writes: group or other may read or write the directory where the file
//! declares they may not — a `0755` directory holding a `0600` file, the
//! `~/.ssh` case. Execute is not compared, so an ordinary `0755` directory
//! holding an ordinary `0644` file is nothing.
//!
//! Only a file that is on disk is looked at, against the mode its target
//! declares, and its directory as it is now, following a link the way the file
//! is reached. A directory bx has not made yet has nothing wider about it
//! today, and `plan` names the mode it would make one at. The `chmod` a finding
//! prints is the narrowest change that clears it: the group and other read and
//! write bits the file does not grant, taken off the directory, and nothing
//! else. It is printed, never run.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::Finding;
use crate::config::resolve::Resolution;
use crate::config::target::{Body, Target};
use crate::fs::{Kind, Mode};
use crate::paths;

/// Group and other, read and write: what [`Mode::is_wider_than`] compares.
const GROUP_AND_OTHER_RW: u32 = 0o066;

/// A finding for every file target on disk whose directory is wider than the
/// mode it declares, in configuration order.
#[must_use]
pub fn check(targets: &[Resolution<Target>], home: &Path) -> Vec<Finding> {
    targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) => Some(target),
            Resolution::Blocked(_) => None,
        })
        .filter_map(|target| wider(target, home))
        .collect()
}

/// The finding for one target, if its directory is wider than it.
fn wider(target: &Target, home: &Path) -> Option<Finding> {
    if matches!(target.body, Body::Symlink(_) | Body::Dir) {
        return None;
    }
    let path = target.path.render(home);
    if !std::fs::symlink_metadata(&path).ok()?.file_type().is_file() {
        return None;
    }
    let dir = path.parent()?;
    let meta = std::fs::metadata(dir).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let dir_mode = Mode::from_bits(meta.permissions().mode() & 0o7777);
    let file_mode = Mode::resolve(target.mode, Kind::File);
    if !dir_mode.is_wider_than(file_mode) {
        return None;
    }
    let narrowed = Mode::from_bits(dir_mode.bits() & !(GROUP_AND_OTHER_RW & !file_mode.bits()));
    let shown = paths::to_portable(dir, home);
    Some(Finding {
        subject: target.path.as_str().to_string(),
        origin: Some(target.origin.clone()),
        note: format!(
            "{shown} is {dir_mode}, wider than the {file_mode} this file declares; \
             `chmod {narrowed} {shown}` narrows it"
        ),
    })
}
