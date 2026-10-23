//! What the integration suites share: how each starts a program with an
//! environment of its own choosing, and the fixtures more than one needs.
//!
//! Each suite declares `mod common;` and uses what it needs, so an item one
//! suite leaves unused is not dead code.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// `program` with an environment of nothing at all but where a coverage
/// build writes its profile.
///
/// `cargo llvm-cov` names that file in `LLVM_PROFILE_FILE`, and an
/// instrumented `bx` without it writes `default_*.profraw` into its working
/// directory: the repository, or a home some comparison then finds it in.
pub fn isolated(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    command
}

/// The `bx` under test, [`isolated`].
pub fn bx() -> assert_cmd::Command {
    assert_cmd::Command::from_std(isolated(env!("CARGO_BIN_EXE_bx")))
}

/// Set `path`'s permission bits.
pub fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}
