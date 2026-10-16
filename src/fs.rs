//! Filesystem primitives: file modes, and the one atomic write in the crate.
//!
//! This module is the single place in bx where a byte reaches the filesystem,
//! but one. A symlink target's link is made here too, by [`link`], through the
//! same preamble and the same rename-then-sync as a file. Everything downstream — generated shell fragments, managed regions
//! and include lines, surgical edits to another tool's config, and decrypted
//! secrets — writes through [`atomic`], so the durability sequence, the
//! reversibility record and the mode policy exist once rather than once per
//! caller.
//!
//! The one exception is the advisory lock file's body, a best-effort line
//! naming the holder, which `state::lock` truncates and writes in place through
//! the descriptor the lock is held on. Renaming a new file over it would move
//! the name to an inode nobody holds the lock on, and the body is only ever a
//! diagnostic, so a torn one costs a vaguer "already running" message and
//! nothing else.
//!
//! A write that is interrupted — by a crash, a full disk, or a `SIGKILL` —
//! must leave the previous file exactly as it was, because an additive tool
//! that half-rewrites a file the user wrote has destroyed something. The
//! sequence, and why each step is there, is documented on [`atomic`].
//!
//! [`Mode`] is the crate's single permission type and [`Kind`] is what a
//! destination turned out to be. Both are defined in [`mode`] and re-exported
//! here, so `bx::fs::Mode` names the one file mode in the crate wherever it is
//! used — including from `config::target`, which re-exports it again under the
//! name the architecture fixed for a target's declared mode.

pub mod atomic;
pub(crate) mod durable;
pub mod link;
pub mod mode;
pub(crate) mod remove;

pub(crate) use atomic::refuse_moved;

pub use atomic::{
    CreatedDirs, Desired, Drift, Error, Filled, Observed, ParentState, TEMP_PREFIX, Unpublished,
    compare, compare_dir, ensure_dir, observe, refuse_stage, set_mode, stage, stage_as,
    temp_beside, write_atomically,
};
pub use link::{refuse_stage_link, stage_link, stage_link_as};
pub use mode::{Kind, Mode};

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Whether names in `dir` are looked up without regard to case, as on a
/// default APFS volume or an ext4 directory with casefolding on.
///
/// Decided by observing the volume, never by the OS: from the nearest existing
/// ancestor of `dir`, and up through its ancestors on the same device, the
/// first entry whose name has a case to swap is looked up under the swapped
/// name. The same `(dev, ino)` answers `Some(true)`; no such entry, or a
/// different one, answers `Some(false)`. Nothing is written, so `plan` can ask.
///
/// `None` when no directory on the way holds an entry to judge by, or when
/// none can be read.
pub fn case_insensitive(dir: &Path) -> Option<bool> {
    let existing = dir
        .ancestors()
        .find(|at| std::fs::metadata(at).is_ok_and(|meta| meta.is_dir()))?;
    let device = std::fs::metadata(existing).ok()?.dev();
    existing
        .ancestors()
        .take_while(|at| std::fs::metadata(at).is_ok_and(|meta| meta.dev() == device))
        .find_map(judge_by_an_entry)
}

/// [`case_insensitive`], judged by the first entry of `dir` whose name has a
/// case to swap.
fn judge_by_an_entry(dir: &Path) -> Option<bool> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .find_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let swapped = swap_case(&name);
            if swapped == name {
                return None;
            }
            let found = std::fs::symlink_metadata(entry.path()).ok()?;
            match std::fs::symlink_metadata(dir.join(&swapped)) {
                Ok(other) => Some(other.dev() == found.dev() && other.ino() == found.ino()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
                Err(_) => None,
            }
        })
}

/// `name` with every letter's case swapped.
fn swap_case(name: &str) -> String {
    name.chars()
        .flat_map(|c| {
            let lower: Vec<char> = c.to_lowercase().collect();
            if lower == [c] {
                c.to_uppercase().collect::<Vec<_>>()
            } else {
                lower
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swapping_case_swaps_every_letter_and_leaves_the_rest() {
        assert_eq!(swap_case(".Config-1"), ".cONFIG-1");
        assert_eq!(swap_case("..._"), "..._");
    }

    #[test]
    fn a_volume_is_judged_by_looking_an_entry_up_under_its_swapped_name() {
        let home = crate::testing::guarded_home();
        home.write("dir/Entry", "x");
        let dir = home.child("dir");
        let swapped_is_the_entry = std::fs::symlink_metadata(dir.join("eNTRY")).is_ok();

        assert_eq!(case_insensitive(&dir), Some(swapped_is_the_entry));
        assert_eq!(
            case_insensitive(&dir.join("not/yet/made")),
            Some(swapped_is_the_entry),
            "a path not made yet is judged by its nearest existing ancestor"
        );
    }

    #[test]
    fn an_entry_whose_swapped_name_is_another_file_means_case_matters() {
        let home = crate::testing::guarded_home();
        home.write("dir/a", "lower");
        let dir = home.child("dir");
        let folds = std::fs::symlink_metadata(dir.join("A")).is_ok();
        // On a volume that folds case, this overwrites `a`, and the lookup
        // still finds the one file under both names.
        home.write("dir/A", "upper");

        assert_eq!(judge_by_an_entry(&dir), Some(folds));
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            if folds { 1 } else { 2 }
        );
    }

    #[test]
    fn a_directory_with_nothing_to_judge_by_defers_to_its_parent() {
        let home = crate::testing::guarded_home();
        home.write("only_.../1", "x");
        assert_eq!(judge_by_an_entry(&home.child("only_...")), None);
        assert!(case_insensitive(&home.child("only_...")).is_some());
    }
}
