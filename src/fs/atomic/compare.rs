//! The verdict `plan` prints for a target: what [`Observed`] found against
//! what bx wants there, for a file target and for a directory target.

use std::path::Path;

use super::error::{FILE_OWNER_NEEDS, owner_locked_out};
use super::{Observed, Parent};
use crate::fs::mode::{Kind, Mode};

/// What bx wants at a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desired<'a> {
    /// The content.
    pub bytes: &'a [u8],
    /// The mode, already resolved — see [`Mode::resolve`].
    pub mode: Mode,
}

/// How what is at a destination stands against what bx wants there.
///
/// The filesystem's own verdict, in its own words: `fs` knows whether a path
/// matches, is missing, differs or cannot be written, and nothing about the
/// ownership, tracking or prerequisites the plan weighs besides. The plan maps
/// it to the [`crate::report::Action`] it announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drift {
    /// Kind, bytes and mode all match.
    Unchanged,
    /// Nothing is there.
    Create,
    /// It is there and differs, in bytes or in mode.
    Modify,
    /// Something is there that bx will not write over.
    Conflict,
}

/// The difference between what is at a destination and what bx wants there.
///
/// One function produces this for both `plan` and `apply`, which is how `apply`
/// is prevented from doing work `plan` did not announce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// What bx will do.
    pub drift: Drift,
    /// Whether the bytes on disk differ from the bytes bx wants there.
    ///
    /// `true` for an absent destination, including when the desired content is
    /// empty: "there is no file" and "there is an empty file" are different
    /// states and the ledger records them differently, so they are not equal
    /// here either. `false` for a conflict, where there are no comparable bytes.
    pub content_drift: bool,
    /// The mode found and the mode wanted, when they differ.
    pub mode_drift: Option<(Mode, Mode)>,
    /// The one-line explanation `plan` prints after the path.
    ///
    /// For a mode drift this is exactly `mode 0644 -> 0600`, so a renderer
    /// needs no mode-specific knowledge of its own.
    pub note: Option<String>,
    /// A parent directory that grants more than the declared mode does.
    ///
    /// Reported, never corrected: an existing directory is the user's, and bx
    /// surfaces drift rather than resolving it behind their back. The remedy is
    /// to declare the directory as a target with the mode it should have —
    /// except when the parent is a symlink, which a directory target refuses.
    /// Then the note names the directory the link resolves to and says to
    /// `chmod` that directory itself.
    ///
    /// A directory under the home is named `~/…`, never by its absolute path;
    /// see [`compare`].
    pub parent_note: Option<String>,
}

/// Compare what is at a destination with what bx wants there.
///
/// Reads nothing the verdict depends on: it works entirely from an [`Observed`]
/// captured earlier, so `plan` and `apply` reach the same verdict from the same
/// bytes. The one read, the realpath of `home`, only names a directory in the
/// parent note.
///
/// * [`Drift::Unchanged`] — kind, bytes and mode all match.
/// * [`Drift::Create`] — nothing is there.
/// * [`Drift::Modify`] — a regular file whose bytes **or** mode differ. A mode
///   difference alone is still a `Modify`, with `content_drift == false`, and
///   `apply` closes it like any other `Modify`: [`stage`](super::stage()) with this
///   observation as `planned` and the desired mode, committed with the desired
///   bytes — the same bytes, for a mode-only drift. `stage` refuses with
///   [`Error::Changed`](super::Error::Changed) unless the file still has the kind and [`Stamp`](super::Stamp) this
///   observation recorded, so a `chmod`, an edit or a directory landing after
///   `plan` is refused rather than overwritten. [`set_mode`](super::set_mode) is not the apply
///   for it: it compares nothing with `plan`.
/// * [`Drift::Conflict`] — a directory, a symlink, or anything else that is
///   not a regular file; and, whatever is there, a declared mode that does not
///   grant the owner read (`0400`), because bx could not read the file back to
///   compare it. The note is `Error::OwnerLockedOut`'s words, less the path.
///   [`stage`](super::stage()) does not refuse such a mode: a reversal restores a recorded
///   prior mode through it as recorded.
///
/// # The parent note is about the immediate parent, and only about it
///
/// A directory anywhere above the immediate parent can be group- or
/// world-writable and no note says so — `~/.config` at `0777` holding
/// `~/.config/foo` at `0700` holding a `0600` file produces nothing. That is
/// the scope this function has, deliberately, and the reason is what the note
/// is *for* rather than what the danger is.
///
/// The immediate parent is the one directory this write interacts with: bx puts
/// its temporary file there, renames within it, and may create it — at a mode
/// this target's own declaration fixes ([`stage`](super::stage())). Its mode is therefore
/// comparable with the mode this target declares, which is exactly what the
/// note compares, and the remedy is this target's author's: declare the
/// directory, or narrow it.
///
/// A writable ancestor is a different fact with a different remedy. It is one
/// fact about the home, not one per target: repeating it on every plan line
/// beneath it would say the same thing as many times as there are targets, and
/// the one action that fixes it is not this target's. It is also not the same
/// danger — an ancestor's *write* bit lets somebody rename a subtree, which no
/// mode on this file or its parent prevents — so reporting it through a
/// predicate built to compare a directory against a file inside it
/// ([`Mode::is_wider_than`], which excludes execute for that reason) would
/// answer the wrong question. A whole-home audit is where it belongs.
///
/// What this scope does **not** leave open: a wide ancestor bx made itself.
/// [`stage`](super::stage()) creates a missing ancestor at [`Mode::DEFAULT_DIR`] or at the mode
/// a directory target declares, never wider, and refuses to write beneath a
/// declared directory that is still wider than declared
/// ([`Error::DirectoryTargetPending`](super::Error::DirectoryTargetPending)). Every unreported ancestor was already
/// there and is the user's.
///
/// `home` only names things: a directory the parent note mentions is written
/// `~/…` when it is under `home`, through [`crate::paths::to_portable`],
/// because `plan` prints the note and plan output names no absolute home. The
/// directory a symlinked parent resolves to is a realpath, so it is named
/// against the realpath of `home` — the one read `compare` makes, and only for
/// that note — falling back to `home` as given when it does not resolve. A
/// directory outside it stays absolute. Nothing in the verdict depends on it.
#[must_use]
pub fn compare(observed: &Observed, desired: &Desired<'_>, home: &Path) -> Outcome {
    // So does a declared mode bx could not read back: `stage` refuses it
    // whatever is on disk.
    if !desired.mode.includes(FILE_OWNER_NEEDS) {
        return Outcome {
            drift: Drift::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(owner_locked_out(desired.mode, FILE_OWNER_NEEDS)),
            parent_note: None,
        };
    }
    // A parent that does not resolve settles the verdict on its own: there is
    // no directory to write into and none bx can create, so announcing
    // anything but a conflict would announce work `apply` cannot do.
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return Outcome {
            drift: Drift::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(reason.to_string()),
            parent_note: None,
        };
    }

    let parent_note = observed.parent.as_ref().and_then(|parent| {
        let mode = parent.mode()?;
        if !mode.is_wider_than(desired.mode) {
            return None;
        }
        let shown = crate::paths::to_portable(&parent.path, home);
        if let Some(resolved) = &parent.resolved {
            // Declaring the link as a directory target would be refused, so
            // the report names the directory that can actually be narrowed.
            // It is a realpath, so it is named against the home's realpath: a
            // home reached through a link (`/home -> var/home`) is never its
            // lexical prefix. A home that does not resolve is used as given.
            let real_home = std::fs::canonicalize(home);
            let resolved =
                crate::paths::to_portable(resolved, real_home.as_deref().unwrap_or(home));
            return Some(format!(
                "{shown} is a symlink to {resolved}, which is {mode}, wider than the {} this \
                 file declares; bx will not chmod a directory through a link, so chmod \
                 {resolved} itself",
                desired.mode,
            ));
        }
        let verb = if parent.exists() {
            "is"
        } else {
            "will be created at"
        };
        Some(format!(
            "{shown} {verb} {mode}, wider than the {} this file declares",
            desired.mode,
        ))
    });

    let (drift, content_drift, mode_drift, note) = match observed.kind {
        Kind::Absent => (Drift::Create, true, None, None),
        Kind::File => {
            let content_drift = observed.bytes.as_deref() != Some(desired.bytes);
            let mode_drift = observed
                .mode
                .filter(|found| *found != desired.mode)
                .map(|found| (found, desired.mode));
            let drift = if content_drift || mode_drift.is_some() {
                Drift::Modify
            } else {
                Drift::Unchanged
            };
            let note = mode_drift.map(|(found, wanted)| format!("mode {found} -> {wanted}"));
            (drift, content_drift, mode_drift, note)
        }
        Kind::Dir => (
            Drift::Conflict,
            false,
            None,
            Some("a directory, where the target declares a file".to_string()),
        ),
        Kind::Symlink => (
            Drift::Conflict,
            false,
            None,
            Some("a symlink; bx will not replace a link you created".to_string()),
        ),
        Kind::Other => (
            Drift::Conflict,
            false,
            None,
            Some("not a regular file".to_string()),
        ),
    };

    Outcome {
        drift,
        content_drift,
        mode_drift,
        note,
        parent_note,
    }
}

/// Compare what is at a **declared directory** target with the mode bx wants
/// it at — the `plan` half of a directory target.
///
/// Reads nothing, exactly like [`compare`]: `plan` for a directory target is
/// [`observe`](super::observe()) then this, and nothing on disk changes. The parent is classified
/// by the same [`ParentState`](super::ParentState) a file's is, so a dangling symlink, a loop or a
/// non-directory anywhere above the path is a conflict here, not an `ENOENT`
/// for `apply` to discover.
///
/// * [`Drift::Unchanged`] — a directory at `mode`.
/// * [`Drift::Create`] — nothing is there; `path` will be created at `mode`
///   and any missing ancestor at the mode a directory target in the same
///   apply declares for it, or at [`Mode::DEFAULT_DIR`] when none does.
/// * [`Drift::Modify`] — a directory at another mode, closed by [`ensure_dir`](super::ensure_dir)
///   with a `chmod` and a read-back of the special bits that stuck. The note
///   reads exactly `mode 0755 -> 0700`, as for a file.
/// * [`Drift::Conflict`] — anything that is not a directory, including a
///   symlink to one: bx does not chmod a directory through a link.
///
/// # A declared mode that denies the owner access is applied like any other
///
/// `fs` applies any declared directory mode. `~/.gnupg` declared `0400` is
/// created at `0400`, and a declared `~/.gnupg/gpg.conf` beneath it then fails
/// in [`stage`](super::stage()) with an `EACCES` [`Error::Write`](super::Error::Write), because bx cannot make its
/// temporary file there. The directory is left in place and a later `plan` of
/// the file cannot observe it.
///
/// That is the decision, not an omission, and the reason is that the rule that
/// would refuse it cannot be stated here. "A directory target with a declared
/// file beneath it must grant its owner write and search" needs to know which
/// targets lie beneath this one. `fs` is handed one path at a time and never
/// sees the set; the plan layer is where the set exists, and that is where the
/// rule belongs. A rule `fs` could state instead — refuse any directory
/// without owner `rwx` — was tried and removed, because a childless read-only
/// directory target is legitimate and needs neither listing nor a temporary
/// file.
///
/// What `fs` still refuses is the case it *can* decide from one path: a
/// **file** target whose declared mode denies the owner read, because bx reads
/// a file back to compare it — the [`Drift::Conflict`] [`compare`] announces,
/// whose note is `Error::OwnerLockedOut`'s words.
#[must_use]
pub fn compare_dir(observed: &Observed, mode: Mode) -> Outcome {
    if let Some(reason) = observed.parent.as_ref().and_then(Parent::unusable) {
        return Outcome {
            drift: Drift::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(reason.to_string()),
            parent_note: None,
        };
    }

    let conflict = |note: &str| (Drift::Conflict, None, Some(note.to_string()));
    let (drift, mode_drift, note) = match observed.kind {
        Kind::Absent => (Drift::Create, None, None),
        Kind::Dir => match observed.mode.filter(|found| *found != mode) {
            None => (Drift::Unchanged, None, None),
            Some(found) => (
                Drift::Modify,
                Some((found, mode)),
                Some(format!("mode {found} -> {mode}")),
            ),
        },
        Kind::File => conflict("a file, where the target declares a directory"),
        Kind::Symlink => conflict("a symlink; bx will not change a directory through a link"),
        Kind::Other => conflict("not a directory"),
    };

    Outcome {
        drift,
        // A directory has no content to drift.
        content_drift: false,
        mode_drift,
        note,
        parent_note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use crate::fs::atomic::test_support::{desired, mode_of_path, outcome_for, seed};
    use crate::fs::atomic::{Error, ParentState, compare, observe, set_mode};
    use crate::report::Action;
    use crate::testing::guarded_home;

    #[test]
    fn an_absent_destination_is_a_create() {
        let home = guarded_home();
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.drift, Drift::Create);
        assert!(outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
    }

    #[test]
    fn identical_content_and_mode_is_unchanged() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.drift, Drift::Unchanged);
        assert!(!outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
        assert!(
            !Action::from(outcome.drift).is_pending(),
            "a second plan must be empty"
        );
    }

    #[test]
    fn identical_content_with_the_wrong_mode_is_a_modify() {
        let home = guarded_home();
        seed(&home.child("f"), b"x", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"x", Mode::PRIVATE_FILE);
        assert_eq!(outcome.drift, Drift::Modify);
        assert!(
            !outcome.content_drift,
            "the bytes match; only the mode drifted",
        );
        assert_eq!(
            outcome.mode_drift,
            Some((Mode::DEFAULT_FILE, Mode::PRIVATE_FILE)),
        );
    }

    #[test]
    fn the_ssh_config_mode_drift_renders_the_operator_s_line() {
        let home = guarded_home();
        // The worked example: a config faithfully reproduced at 0644 that ssh
        // will not accept, declared 0600.
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.drift, Drift::Modify);
        assert_eq!(outcome.note.as_deref(), Some("mode 0644 -> 0600"));
        assert_eq!(Action::from(outcome.drift).symbol(), '~');
    }

    #[test]
    fn changed_content_with_a_matching_mode_is_a_modify() {
        let home = guarded_home();
        seed(&home.child("f"), b"old", Mode::DEFAULT_FILE);
        let outcome = outcome_for(&home, "f", b"new", Mode::DEFAULT_FILE);
        assert_eq!(outcome.drift, Drift::Modify);
        assert!(outcome.content_drift);
        assert_eq!(outcome.mode_drift, None);
        assert_eq!(outcome.note, None);
    }

    #[test]
    fn a_directory_where_a_file_is_declared_is_a_conflict() {
        let home = guarded_home();
        std::fs::create_dir(home.child("f")).expect("occupy");
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.drift, Drift::Conflict);
        assert!(Action::from(outcome.drift).needs_attention());
        assert!(
            outcome
                .note
                .as_deref()
                .is_some_and(|n| n.contains("directory")),
            "{:?}",
            outcome.note,
        );
    }

    #[test]
    fn a_device_node_where_a_file_is_declared_is_a_conflict() {
        let home = guarded_home();
        let path = home.child("f");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            Mode::PRIVATE_FILE.into(),
            0,
        )
        .expect("mkfifo");
        let outcome = outcome_for(&home, "f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.drift, Drift::Conflict);
        assert_eq!(outcome.note.as_deref(), Some("not a regular file"));
    }

    #[test]
    fn a_parent_that_does_not_resolve_governs_no_mode() {
        // `compare` returns before asking an unusable parent for a mode, but
        // `Parent` is public with public fields, so any caller can ask.
        let parent = |state: ParentState| Parent {
            path: PathBuf::from("/nowhere/d"),
            state,
            resolved: None,
        };
        assert_eq!(
            parent(ParentState::Unusable("a dangling symlink".into())).mode(),
            None,
            "no directory, so no mode to govern anything",
        );
        assert_eq!(
            parent(ParentState::Present(Mode::PRIVATE_DIR)).mode(),
            Some(Mode::PRIVATE_DIR),
        );
        assert_eq!(
            parent(ParentState::Absent(Mode::DEFAULT_DIR)).mode(),
            Some(Mode::DEFAULT_DIR),
            "the mode bx would create it at",
        );
    }

    #[test]
    fn a_parent_wider_than_the_declared_mode_is_reported() {
        let home = guarded_home();
        // ~/.ssh at 0755 holding a 0600 config: exactly what the source
        // material produces, and exactly what ssh refuses to work with.
        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::DEFAULT_DIR).expect("chmod");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.drift, Drift::Unchanged, "the file itself is fine");
        // Exactly, so a plain directory is never reported with the symlink
        // wording, whose remedy ("chmod ... itself") names a different action
        // and shares every substring checked above it.
        assert_eq!(
            outcome.parent_note,
            Some("~/.ssh is 0755, wider than the 0600 this file declares".to_string()),
        );
    }

    #[test]
    fn an_ordinary_parent_of_an_ordinary_file_is_not_reported() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".config")).expect("mkdir");
        set_mode(&home.child(".config"), Mode::DEFAULT_DIR).expect("chmod");
        seed(&home.child(".config/f"), b"x", Mode::DEFAULT_FILE);

        let outcome = outcome_for(&home, ".config/f", b"x", Mode::DEFAULT_FILE);
        assert_eq!(outcome.parent_note, None, "0755 over 0644 is not a finding");
    }

    #[test]
    fn a_parent_bx_has_yet_to_create_is_reported_before_it_exists() {
        let home = guarded_home();
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.drift, Drift::Create);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(note.contains("will be created at 0755"), "{note}");
    }

    #[test]
    fn a_symlinked_parent_reports_the_directory_it_resolves_to() {
        let home = guarded_home();
        // The mainstream dotfiles layout: ~/.ssh is a link into a repository,
        // and the directory at the far end is already hardened.
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::PRIVATE_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let observed = observe(&home.child(".ssh/config")).expect("observe");
        let parent = observed.parent.as_ref().expect("a parent");
        assert_eq!(
            parent.state,
            ParentState::Present(Mode::PRIVATE_DIR),
            "the resolved directory's 0700, not the link's own 0777",
        );

        let outcome = compare(
            &observed,
            &desired(b"Host *\n", Mode::PRIVATE_FILE),
            home.path(),
        );
        assert_eq!(outcome.parent_note, None, "a hardened parent is no finding");

        // The asymmetry, stated as an assertion: the *destination* is still
        // stat'd without following, so a link there is a link.
        assert_eq!(mode_of_path(&home.child(".ssh")).bits(), 0o777);
    }

    #[test]
    fn a_symlinked_parent_that_is_genuinely_wide_is_still_reported() {
        let home = guarded_home();
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");
        seed(&home.child(".ssh/config"), b"Host *\n", Mode::PRIVATE_FILE);

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(note.contains("is 0755"), "{note}");
        assert!(note.contains("wider than the 0600"), "{note}");
    }

    #[test]
    fn a_private_parent_is_not_reported() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::PRIVATE_DIR).expect("chmod");
        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        assert_eq!(outcome.parent_note, None);
    }

    /// The refusal a declared file mode that locks its owner out gets, naming
    /// `path` and the note `plan` printed for it.
    fn assert_owner_locked_out(err: &Error, path: &Path, note: &str) {
        let message = err.to_string();
        assert!(
            matches!(err, Error::OwnerLockedOut { path: named, .. } if named == path),
            "expected OwnerLockedOut naming {}, got {err:?}",
            path.display(),
        );
        assert_eq!(err.path(), path, "{message}");
        assert_eq!(
            message,
            format!("{} {note}. Nothing was changed", path.display()),
        );
    }

    #[test]
    fn a_file_target_that_denies_its_owner_read_is_a_conflict_at_plan_time() {
        let home = guarded_home();
        let dir = home.child("d");
        let declared = Mode::from_bits(0o200);
        let note = "declares 0200, which denies its owner read (0400): bx reads a file target's \
                    bytes to compare them with what it wants there, so its mode must grant the \
                    owner read (0400)";
        let conflict = Outcome {
            drift: Drift::Conflict,
            content_drift: false,
            mode_drift: None,
            note: Some(note.to_string()),
            parent_note: None,
        };

        // An existing file declared 0200: its bytes could never be compared.
        let existing = dir.join("existing");
        seed(&existing, b"before", Mode::DEFAULT_FILE);
        let planned = observe(&existing).expect("plan observes");
        assert_eq!(
            compare(&planned, &desired(b"after", declared), home.path()),
            conflict,
            "plan announces the conflict",
        );

        // An absent file declared 0200: the same conflict.
        let fresh = dir.join("fresh");
        let planned = observe(&fresh).expect("plan observes");
        assert_eq!(
            compare(&planned, &desired(b"x", declared), home.path()),
            conflict
        );

        // The error a caller raises for it says the same words, with the path.
        let err = Error::OwnerLockedOut {
            path: existing.clone(),
            declared,
            needs: FILE_OWNER_NEEDS,
        };
        assert_owner_locked_out(&err, &existing, note);
    }

    #[test]
    fn a_parent_note_names_directories_under_home_portably() {
        let home = guarded_home();
        // `resolved` is a realpath, so it is under the home only if the home
        // path is itself one. Fail loudly rather than pass on no evidence.
        assert_eq!(
            std::fs::canonicalize(home.path()).expect("realpath of the home"),
            home.path(),
            "the guarded home must be a canonical path for this test to mean anything",
        );
        let absolute_home = home.path().display().to_string();

        std::fs::create_dir(home.child(".ssh")).expect("mkdir");
        set_mode(&home.child(".ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::fs::create_dir_all(home.child("dotfiles/dot_gnupg")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_gnupg"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_gnupg", home.child(".gnupg")).expect("symlink");

        for (rel, expected) in [
            (
                ".ssh/config",
                "~/.ssh is 0755, wider than the 0600 this file declares",
            ),
            (
                ".aws/credentials",
                "~/.aws will be created at 0755, wider than the 0600 this file declares",
            ),
            (
                ".gnupg/gpg.conf",
                "~/.gnupg is a symlink to ~/dotfiles/dot_gnupg, which is 0755, wider than the \
                 0600 this file declares; bx will not chmod a directory through a link, so \
                 chmod ~/dotfiles/dot_gnupg itself",
            ),
        ] {
            let outcome = outcome_for(&home, rel, b"x", Mode::PRIVATE_FILE);
            let note = outcome.parent_note.expect("the parent must be reported");
            assert!(
                !note.contains(&absolute_home),
                "{rel}: `bx plan` prints this note, so it names no absolute home: {note}",
            );
            assert_eq!(note, expected, "{rel}");
        }
    }

    #[test]
    fn a_wide_symlinked_parent_names_the_directory_to_chmod() {
        let home = guarded_home();
        std::fs::create_dir_all(home.child("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.child("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.child(".ssh")).expect("symlink");

        let outcome = outcome_for(&home, ".ssh/config", b"Host *\n", Mode::PRIVATE_FILE);
        let note = outcome.parent_note.expect("the parent must be reported");
        assert!(
            note.contains("so chmod ~/dotfiles/dot_ssh itself"),
            "the note names the directory the link resolves to, portably: {note}",
        );
        assert!(note.contains("chmod"), "{note}");
    }

    #[test]
    fn a_symlinked_parent_is_named_portably_under_a_home_reached_through_a_symlink() {
        let guard = guarded_home();
        // The home as `/home/u` is on a system where `/home -> var/home`: a
        // link, so the realpath of anything under it is not under it lexically.
        std::fs::create_dir(guard.child("real")).expect("mkdir");
        std::os::unix::fs::symlink("real", guard.child("home")).expect("symlink");
        let home = guard.child("home");
        std::fs::create_dir_all(home.join("dotfiles/dot_ssh")).expect("mkdir");
        set_mode(&home.join("dotfiles/dot_ssh"), Mode::DEFAULT_DIR).expect("chmod");
        std::os::unix::fs::symlink("dotfiles/dot_ssh", home.join(".ssh")).expect("symlink");

        let observed = observe(&home.join(".ssh/config")).expect("observe");
        let outcome = compare(&observed, &desired(b"Host *\n", Mode::PRIVATE_FILE), &home);
        assert_eq!(
            outcome.parent_note.as_deref(),
            Some(
                "~/.ssh is a symlink to ~/dotfiles/dot_ssh, which is 0755, wider than the 0600 \
                 this file declares; bx will not chmod a directory through a link, so chmod \
                 ~/dotfiles/dot_ssh itself"
            ),
            "`bx plan` prints this note, so it names no absolute home",
        );
    }
}
