//! Check 7: a declared optional source ([`crate::shell::source`]) whose file
//! is not there to source.
//!
//! The question is the one the generated line asks — `[[ -r FILE ]]` — put
//! with `access(2)`, which opens nothing: [`source::missing`] is handed it and
//! asks nothing of the filesystem itself. A missing source never breaks a
//! shell, since the line tests before it sources; the finding is there because
//! the user declared the file and it is not doing anything.

use std::path::Path;

use rustix::fs::Access;

use super::Finding;
use crate::config::resolve::Resolution;
use crate::config::target::{Body, Gen, Target};
use crate::shell::source;

/// Whether the shell's `[[ -r path ]]` would be true.
#[must_use]
pub fn readable(path: &Path) -> bool {
    rustix::fs::access(path, Access::READ_OK).is_ok()
}

/// A finding for every enabled, resolved source whose file is not readable,
/// in declaration order.
///
/// The sources are the interactive file's: a configuration whose interactive
/// file is held back has none to look at, and its plan row says why.
#[must_use]
pub fn check(
    targets: &[Resolution<Target>],
    home: &Path,
    readable: &dyn Fn(&Path) -> bool,
) -> Vec<Finding> {
    targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(Target {
                body: Body::Generated(Gen::Interactive(interactive)),
                ..
            }) => Some(interactive),
            _ => None,
        })
        .flat_map(|interactive| source::missing(interactive.sources(), home, readable))
        .map(|missing| Finding {
            subject: format!("source {}", missing.name),
            origin: Some(missing.origin.clone()),
            note: format!(
                "{} is not readable, so the shell skips the line that sources it",
                missing.path
            ),
        })
        .collect()
}
