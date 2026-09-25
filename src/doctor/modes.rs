//! Check 5: a directory whose mode is wider than a file bx declared inside it.
//!
//! The comparison is [`Mode::is_wider_than`], the one `plan` makes before it
//! writes: group or other may read or write the directory where the file
//! declares they may not — a `0755` directory holding a `0600` file, the
//! `~/.ssh` case. Execute is not compared, so an ordinary `0755` directory
//! holding an ordinary `0644` file is nothing.
//!
//! Only a file that is on disk is looked at, against the mode `plan` keeps it
//! at — the one its target declares, or, for a region target that declares
//! none, the file's own — and its directory as it is now, following a link the
//! way the file is reached. A directory bx has not made yet has nothing wider about it
//! today, and `plan` names the mode it would make one at. The `chmod` a finding
//! prints is the narrowest change that clears it: the group and other read and
//! write bits the file does not grant, taken off the directory, and nothing
//! else. It is printed, never run.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::Finding;
use crate::config::resolve::Resolution;
use crate::config::target::{Attach, Body, Target};
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
    let file = std::fs::symlink_metadata(&path).ok()?;
    if !file.file_type().is_file() {
        return None;
    }
    let dir = path.parent()?;
    let meta = std::fs::metadata(dir).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let dir_mode = bits(&meta);
    // As `plan` keeps it: a region target that declares no mode leaves the
    // file at its own.
    let (file_mode, whose) = match (target.mode, &target.attach) {
        (Some(declared), _) => (declared, "this file declares"),
        (None, Attach::Region { .. }) => (bits(&file), "this file has"),
        (None, _) => (Mode::resolve(None, Kind::File), "this file declares"),
    };
    if !dir_mode.is_wider_than(file_mode) {
        return None;
    }
    let narrowed = Mode::from_bits(dir_mode.bits() & !(GROUP_AND_OTHER_RW & !file_mode.bits()));
    let shown = paths::to_portable(dir, home);
    Some(Finding {
        subject: target.path.as_str().to_string(),
        origin: Some(target.origin.clone()),
        note: format!(
            "{shown} is {dir_mode}, wider than the {file_mode} {whose}; \
             `chmod {narrowed} {shown}` narrows it"
        ),
    })
}

/// The permission bits `meta` carries.
fn bits(meta: &std::fs::Metadata) -> Mode {
    Mode::from_bits(meta.permissions().mode() & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::inputs;
    use crate::testing::guarded_home;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_region_target_with_no_mode_is_held_to_the_files_own() {
        let home = guarded_home();
        let rc = home.write(".d/rc", "mine\n");
        chmod(&rc, 0o600);
        chmod(&home.child(".d"), 0o775);
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.d/rc\"\ncontent = \"x\"\nattach = \"region\"\ncomment = \"#\"\n",
        );

        let findings = check(inputs.targets(), home.path());

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].note,
            "~/.d is 0775, wider than the 0600 this file has; `chmod 0711 ~/.d` narrows it"
        );
    }

    #[test]
    fn the_chmod_keeps_what_the_file_itself_grants() {
        let home = guarded_home();
        home.write(".d/f", "x");
        chmod(&home.child(".d"), 0o777);
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.d/f\"\ncontent = \"x\"\nmode = \"0640\"\n",
        );

        let findings = check(inputs.targets(), home.path());

        assert_eq!(
            findings[0].note,
            "~/.d is 0777, wider than the 0640 this file declares; `chmod 0751 ~/.d` narrows it"
        );
    }
}
