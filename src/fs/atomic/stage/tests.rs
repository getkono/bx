use super::*;

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt as _;

#[cfg(target_os = "linux")]
use rustix::io::Errno;

use crate::fs::atomic::test_support::{
    CWD, UMASK, desired, mode_of_path, names_in, outcome_for, seed, stage_now,
};
use crate::fs::atomic::{Desired, Drift, compare, stage};
use crate::paths::Portable;
use crate::state::{
    ExclusiveLock, Ledger, LedgerView, Mechanism, NewEntry, Prior, PriorBytes, StateDir, restore,
};
use crate::testing::{GuardedHome, guarded_home};

#[test]
fn stage_refuses_a_directory_or_fifo_destination_as_not_a_file() {
    // The apply half of the two conflicts above: `stage` refuses plan's
    // verdict with the kind that is there, and touches nothing.
    let home = guarded_home();
    let dir = home.child("d");
    std::fs::create_dir(&dir).expect("mkdir");
    std::fs::write(dir.join("inside"), b"theirs").expect("an entry of their own");
    let fifo = home.child("p");
    crate::testing::mkfifo(&fifo);

    for (dest, kind) in [(&dir, Kind::Dir), (&fifo, Kind::Other)] {
        let err = stage_now(dest, Mode::DEFAULT_FILE).expect_err("not a file bx can write");
        let Error::NotAFile { path, kind: found } = &err else {
            panic!("{kind:?}: expected NotAFile, got {err:?}");
        };
        assert_eq!(path, dest, "{kind:?}");
        assert_eq!(*found, kind);
        assert_eq!(err.path(), dest.as_path(), "{kind:?}");
    }

    assert_eq!(
        names_in(home.path()),
        vec![OsString::from("d"), OsString::from("p")],
        "nothing written and no temporary file left",
    );
    assert_eq!(names_in(&dir), vec![OsString::from("inside")]);
    assert_eq!(std::fs::read(dir.join("inside")).expect("read"), b"theirs");
}

#[test]
fn the_temporary_file_is_created_in_the_destination_directory() {
    let home = guarded_home();
    let dest = home.child("f");
    let staged = stage_now(&dest, Mode::DEFAULT_FILE).expect("stage");

    assert_eq!(staged.temp_path().parent(), dest.parent());
    assert_eq!(staged.dest(), dest);
    let name = staged
        .temp_path()
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .to_string();
    assert!(name.starts_with(TEMP_PREFIX), "{name}");
    assert!(
        names_in(home.path()).contains(&OsString::from(&name)),
        "the temporary file is in the destination directory, not $TMPDIR",
    );
}

#[test]
fn the_mode_is_final_before_any_content_exists_and_never_wider() {
    // Observable on the temporary file, while it is still empty: this is
    // the property a decrypted secret depends on. tempfile creates at 0600
    // and the declared mode only narrows it, so there is no instant at
    // which the file is wider than 0600.
    for mode in [Mode::PRIVATE_FILE, Mode::from_bits(0o400)] {
        let home = guarded_home();
        let staged = stage_now(&home.child("secret"), mode).expect("stage");
        let meta = std::fs::symlink_metadata(staged.temp_path()).expect("stat");
        assert_eq!(mode_of(&meta), mode);
        assert_eq!(meta.len(), 0, "the mode is set before any content");
        assert_eq!(staged.mode(), mode);
        let filled = staged.fill(b"plaintext").expect("fill");
        assert_eq!(mode_of_path(filled.temp_path()), mode);
        filled.publish().expect("publish");
        assert_eq!(mode_of_path(&home.child("secret")), mode);
    }
}

#[test]
fn a_declared_mode_beats_the_process_umask() {
    let _serialised = UMASK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let home = guarded_home();
    let previous = rustix::process::umask(Mode::from_bits(0o077).into());

    let dest = home.child("wide/f");
    // Through the phases, not `write_atomically`: the parent is missing,
    // and creating one is `stage`'s to do.
    let result = stage_now(&dest, Mode::DEFAULT_FILE).and_then(|s| s.commit(b"x"));

    rustix::process::umask(previous);
    result.expect("write");

    assert_eq!(
        mode_of_path(&dest),
        Mode::DEFAULT_FILE,
        "OpenOptions::mode is masked by the umask; fchmod is not",
    );
    assert_eq!(
        mode_of_path(&home.child("wide")),
        Mode::DEFAULT_DIR,
        "mkdir's mode is masked by the umask too; the directory is chmod'd",
    );
}

#[test]
fn a_write_abandoned_at_either_phase_leaves_the_original_intact() {
    // Filled is the crash phase that matters: the content is on disk and
    // fsynced, and the rename has not happened.
    for fill in [false, true] {
        let home = guarded_home();
        let dest = home.child("f");
        seed(&dest, b"v1", Mode::DEFAULT_FILE);

        let staged = stage_now(&dest, Mode::PRIVATE_FILE).expect("stage");
        let temp = staged.temp_path().to_path_buf();
        if fill {
            let filled = staged.fill(b"v2").expect("fill");
            assert_eq!(std::fs::read(&temp).expect("read temp"), b"v2");
            assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
            filled.abandon();
        } else {
            staged.abandon();
        }

        assert_eq!(std::fs::read(&dest).expect("read"), b"v1", "{fill}");
        assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE, "{fill}");
        assert!(!temp.exists(), "no .bx- orphan survives an abandoned write");
        assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
    }
}

#[test]
fn the_filled_phase_is_the_seam_a_journal_interposes_at() {
    let home = guarded_home();
    let dest = home.child("f");
    seed(&dest, b"v1", Mode::DEFAULT_FILE);

    let filled = stage_now(&dest, Mode::PRIVATE_FILE)
        .expect("stage")
        .fill(b"v2")
        .expect("fill");

    // Everything a journal needs to record its intent, before the rename.
    assert_eq!(filled.dest(), dest);
    assert_eq!(filled.temp_path().parent(), dest.parent());
    assert_eq!(filled.mode(), Mode::PRIVATE_FILE);
    assert_eq!(filled.prior().kind, Kind::File);
    assert_eq!(filled.prior().bytes.as_deref(), Some(&b"v1"[..]));
    assert_eq!(filled.prior().mode, Some(Mode::DEFAULT_FILE));

    filled.publish().expect("publish");
    assert_eq!(std::fs::read(&dest).expect("read"), b"v2");
}

#[test]
fn a_staged_write_carries_the_prior_state_a_reversal_needs() {
    let home = guarded_home();
    let dest = home.child("f");
    seed(&dest, b"v1", Mode::from_bits(0o640));

    let staged = stage_now(&dest, Mode::PRIVATE_FILE).expect("stage");
    let prior = staged.prior().clone();
    staged.commit(b"v2").expect("commit");

    // Restoring from the prior state alone must reproduce v1 exactly,
    // including its mode.
    assert_eq!(prior.path, dest);
    write_atomically(
        &prior.path,
        prior.bytes.as_deref().expect("prior bytes"),
        prior.mode.expect("prior mode"),
    )
    .expect("restore");
    assert_eq!(std::fs::read(&dest).expect("read"), b"v1");
    assert_eq!(mode_of_path(&dest), Mode::from_bits(0o640));
}

#[test]
fn a_write_creates_or_replaces_content_and_mode_together() {
    for replaces in [false, true] {
        let home = guarded_home();
        let dest = home.child("f");
        if replaces {
            seed(&dest, b"v1", Mode::DEFAULT_FILE);
        }
        write_atomically(&dest, b"v2", Mode::PRIVATE_FILE).expect("write");
        assert_eq!(std::fs::read(&dest).expect("read"), b"v2", "{replaces}");
        assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE, "{replaces}");
    }
}

#[test]
fn a_second_commit_of_identical_bytes_is_byte_identical() {
    let home = guarded_home();
    let dest = home.child("f");
    write_atomically(&dest, b"same\n", Mode::DEFAULT_FILE).expect("first");
    let first = std::fs::read(&dest).expect("read");
    write_atomically(&dest, b"same\n", Mode::DEFAULT_FILE).expect("second");

    assert_eq!(std::fs::read(&dest).expect("read"), first);
    assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
    let observed = observe(&dest).expect("observe");
    assert_eq!(
        compare(
            &observed,
            &desired(b"same\n", Mode::DEFAULT_FILE),
            home.path()
        )
        .drift,
        Drift::Unchanged,
        "the second plan is empty",
    );
}

#[test]
fn a_write_does_not_disturb_its_siblings() {
    let home = guarded_home();
    let sibling = home.child("sibling");
    seed(&sibling, b"untouched", Mode::from_bits(0o640));
    let sibling_ino = std::fs::metadata(&sibling).expect("stat").ino();

    write_atomically(&home.child("f"), b"x", Mode::DEFAULT_FILE).expect("write");

    assert_eq!(std::fs::read(&sibling).expect("read"), b"untouched");
    assert_eq!(mode_of_path(&sibling), Mode::from_bits(0o640));
    assert_eq!(
        std::fs::metadata(&sibling).expect("stat").ino(),
        sibling_ino
    );
    assert_eq!(
        names_in(home.path()),
        vec![OsString::from("f"), OsString::from("sibling")],
    );
}

#[test]
fn a_failed_publish_leaves_no_temporary_file_behind() {
    let home = guarded_home();
    let dest = home.child("f");
    let staged = stage_now(&dest, Mode::DEFAULT_FILE).expect("stage");
    // Something occupies the destination after it was observed, so the
    // publish fails after the temporary file has been written in full —
    // refused by the check before the rename, which is the one a rename
    // over a directory would also have failed.
    std::fs::create_dir(&dest).expect("occupy");

    let err = staged.commit(b"x").expect_err("must fail");
    assert_eq!(err.path(), dest);
    assert!(matches!(err, Error::Changed { .. }), "{err:?}");
    assert_eq!(names_in(home.path()), vec![OsString::from("f")]);
}

#[test]
fn a_destination_edited_between_fill_and_publish_is_refused_and_keeps_the_edit() {
    // The window a journal widens: between the observation `stage` takes
    // and the rename, an editor saves. Replacing the file then destroys the
    // save, and the prior bx recorded predates it, so `rm` cannot bring it
    // back either — Invariant 1 and Invariant 4 at once.
    let in_place: fn(&Path) = |dest| {
        std::fs::write(dest, b"the user's edit\n").expect("the user saves in place");
    };
    let by_rename: fn(&Path) = |dest| {
        // Same length as what was there, so only which file it is changed.
        let saved = dest.with_file_name("editor-swap");
        std::fs::write(&saved, b"v2\n").expect("the editor writes its copy");
        std::fs::rename(&saved, dest).expect("and renames it over the original");
    };

    for (how, save) in [("in place", in_place), ("by rename", by_rename)] {
        let home = guarded_home();
        let dest = home.child(".conf");
        seed(&dest, b"v1\n", Mode::DEFAULT_FILE);

        let filled = stage_now(&dest, Mode::DEFAULT_FILE)
            .expect("stage")
            .fill(b"bx\n")
            .expect("fill");
        let temp = filled.temp_path().to_path_buf();
        save(&dest);
        let saved = std::fs::read(&dest).expect("read the save");

        let refused = filled
            .publish()
            .expect_err("a destination that changed after it was observed is not replaced");
        assert_eq!(refused.dest, dest, "{how}: the refusal names the write");
        let err = refused.into_error();
        assert!(matches!(err, Error::Changed { .. }), "{how}: {err:?}");
        assert_eq!(err.path(), dest, "{how}");
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            saved,
            "{how}: the user's save survives",
        );
        assert!(!temp.exists(), "{how}: the temporary file is removed");
        assert_eq!(
            names_in(home.path()),
            vec![OsString::from(".conf")],
            "{how}"
        );
    }
}

#[test]
fn a_symlink_swapped_in_between_fill_and_publish_is_refused_and_survives() {
    let home = guarded_home();
    let dest = home.child(".conf");
    let other = home.child("elsewhere");
    seed(&dest, b"v1\n", Mode::DEFAULT_FILE);
    seed(&other, b"the link's target\n", Mode::DEFAULT_FILE);

    let filled = stage_now(&dest, Mode::DEFAULT_FILE)
        .expect("stage")
        .fill(b"bx\n")
        .expect("fill");
    let temp = filled.temp_path().to_path_buf();
    // Decision 2 refuses a link at the final component; observing a file
    // there first must not turn into replacing a link that arrived later.
    std::fs::remove_file(&dest).expect("rm");
    std::os::unix::fs::symlink("elsewhere", &dest).expect("symlink");

    let refused = filled
        .publish()
        .expect_err("the link is not bx's to replace");
    assert_eq!(refused.dest, dest, "the refusal names the write");
    let err = refused.into_error();
    assert!(matches!(err, Error::Changed { .. }), "{err:?}");
    assert!(
        std::fs::symlink_metadata(&dest)
            .expect("stat")
            .file_type()
            .is_symlink(),
        "the link is intact",
    );
    assert_eq!(
        std::fs::read_link(&dest).expect("readlink"),
        Path::new("elsewhere")
    );
    assert_eq!(std::fs::read(&other).expect("read"), b"the link's target\n");
    assert!(!temp.exists());
}

#[test]
fn a_file_that_appears_where_there_was_none_is_not_replaced() {
    let home = guarded_home();
    let dest = home.child(".conf");

    let filled = stage_now(&dest, Mode::DEFAULT_FILE)
        .expect("stage")
        .fill(b"bx\n")
        .expect("fill");
    assert_eq!(filled.prior().stamp, None, "nothing was there to stamp");
    std::fs::write(&dest, b"another tool's\n").expect("another tool creates it");

    let refused = filled
        .publish()
        .expect_err("bx announced a create, and there is now a file to replace");
    assert_eq!(refused.dest, dest, "the refusal names the write");
    let err = refused.into_error();
    assert!(matches!(err, Error::Changed { .. }), "{err:?}");
    assert_eq!(std::fs::read(&dest).expect("read"), b"another tool's\n");
    assert_eq!(names_in(home.path()), vec![OsString::from(".conf")]);
}

#[test]
fn a_destination_changed_after_plan_is_refused_by_stage_and_keeps_the_change() {
    // Invariant 7: plan printed a diff against what it observed. A file
    // edited, replaced or removed after that is not the file plan's diff
    // was about, so apply may not replace it with that diff's content.
    let edited: fn(&Path) = |dest| {
        std::fs::write(dest, b"the user's edit after plan\n").expect("the user saves");
    };
    let replaced: fn(&Path) = |dest| {
        // Same length as what was there, so only which file it is changed.
        let saved = dest.with_file_name("editor-swap");
        std::fs::write(&saved, b"v2\n").expect("the editor writes its copy");
        std::fs::rename(&saved, dest).expect("and renames it over the original");
    };
    let removed: fn(&Path) = |dest| std::fs::remove_file(dest).expect("the user removes it");

    for (how, change) in [
        ("edited in place", edited),
        ("replaced by rename", replaced),
        ("removed", removed),
    ] {
        let home = guarded_home();
        let dest = home.child(".conf");
        seed(&dest, b"v1\n", Mode::DEFAULT_FILE);
        let planned = observe(&dest).expect("plan observes");
        assert_eq!(
            compare(&planned, &desired(b"bx\n", Mode::DEFAULT_FILE), home.path()).drift,
            Drift::Modify,
            "{how}",
        );

        change(&dest);
        let now = std::fs::read(&dest).ok();

        let err = stage(&dest, Mode::DEFAULT_FILE, &planned, &mut CreatedDirs::new())
            .expect_err("a destination that changed after plan is not staged over");
        assert!(matches!(err, Error::Changed { .. }), "{how}: {err:?}");
        assert_eq!(err.path(), dest, "{how}");
        assert_eq!(
            std::fs::read(&dest).ok(),
            now,
            "{how}: what is there now survives"
        );
        let expected: Vec<OsString> = now.iter().map(|_| OsString::from(".conf")).collect();
        assert_eq!(
            names_in(home.path()),
            expected,
            "{how}: no temporary file is left"
        );
    }

    // A file that appeared where plan saw nothing is not the create plan
    // announced either.
    let home = guarded_home();
    let dest = home.child(".conf");
    let planned = observe(&dest).expect("plan observes");
    std::fs::write(&dest, b"another tool's\n").expect("another tool creates it");
    let err = stage(&dest, Mode::DEFAULT_FILE, &planned, &mut CreatedDirs::new())
        .expect_err("plan announced a create");
    assert!(matches!(err, Error::Changed { .. }), "{err:?}");
    assert_eq!(std::fs::read(&dest).expect("read"), b"another tool's\n");
    assert_eq!(names_in(home.path()), vec![OsString::from(".conf")]);

    // And plan's observation of one path does not license a write to
    // another.
    let err = stage(
        &home.child("other"),
        Mode::DEFAULT_FILE,
        &planned,
        &mut CreatedDirs::new(),
    )
    .expect_err("plan observed a different path");
    assert!(matches!(err, Error::Changed { .. }), "{err:?}");
    assert_eq!(names_in(home.path()), vec![OsString::from(".conf")]);
}

/// A POSIX ACL in the kernel's `system.posix_acl_access` encoding: version
/// 2, then `(tag, perm, id)` per entry, little-endian, sorted by tag.
#[cfg(target_os = "linux")]
fn posix_acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut encoded = 2_u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        encoded.extend(tag.to_le_bytes());
        encoded.extend(perm.to_le_bytes());
        encoded.extend(id.to_le_bytes());
    }
    encoded
}

// `user.*` and `system.posix_acl_access` xattrs are Linux's.
#[cfg(target_os = "linux")]
#[test]
fn a_replaced_file_keeps_neither_its_xattrs_nor_its_acl() {
    // A documented exclusion from "restores exactly", pinned so that
    // changing it is a decision: see the module documentation.
    use rustix::fs::{XattrFlags, getxattr, setxattr};

    const USER_ATTR: &str = "user.bx-test";
    const ACL_ACCESS: &str = "system.posix_acl_access";
    const UNDEFINED_ID: u32 = u32::MAX;

    let home = guarded_home();
    let dest = home.child(".conf");
    seed(&dest, b"v1\n", Mode::DEFAULT_FILE);

    // What this filesystem can hold decides what there is to pin. An ACL
    // naming uid 65534 is refused with EINVAL where that uid is unmapped.
    let has_user_attr = match setxattr(dest.as_path(), USER_ATTR, b"theirs", XattrFlags::empty()) {
        Ok(()) => true,
        Err(e) if e == Errno::OPNOTSUPP => false,
        Err(e) => panic!("setxattr {USER_ATTR}: {e}"),
    };
    let acl = posix_acl(&[
        (0x01, 6, UNDEFINED_ID), // user::rw-
        (0x02, 4, 65534),        // user:nobody:r--
        (0x04, 4, UNDEFINED_ID), // group::r--
        (0x10, 4, UNDEFINED_ID), // mask::r--
        (0x20, 4, UNDEFINED_ID), // other::r--
    ]);
    let has_acl = match setxattr(dest.as_path(), ACL_ACCESS, &acl, XattrFlags::empty()) {
        Ok(()) => true,
        Err(e) if e == Errno::OPNOTSUPP || e == Errno::INVAL => false,
        Err(e) => panic!("setxattr {ACL_ACCESS}: {e}"),
    };
    let attrs: Vec<&str> = [(USER_ATTR, has_user_attr), (ACL_ACCESS, has_acl)]
        .into_iter()
        .filter_map(|(name, set)| set.then_some(name))
        .collect();
    if attrs.is_empty() {
        // Neither can exist here, so neither can be lost.
        return;
    }

    let attr = |name: &str| -> Option<Vec<u8>> {
        let mut buf = [0_u8; 256];
        match getxattr(dest.as_path(), name, &mut buf) {
            Ok(len) => Some(buf[..len].to_vec()),
            Err(e) if e == Errno::NODATA => None,
            Err(e) => panic!("getxattr {name}: {e}"),
        }
    };
    for name in &attrs {
        assert!(attr(name).is_some(), "{name} is on the user's file");
    }

    let staged = stage_now(&dest, Mode::DEFAULT_FILE).expect("stage");
    let prior = staged.prior().clone();
    staged.commit(b"bx\n").expect("commit");
    for name in &attrs {
        assert_eq!(
            attr(name),
            None,
            "{name} is not carried onto the replacement"
        );
    }

    // The prior is bytes and mode, so restoring from it brings the bytes
    // and the mode back, and nothing else.
    write_atomically(
        &dest,
        prior.bytes.as_deref().expect("prior bytes"),
        prior.mode.expect("prior mode"),
    )
    .expect("restore");
    assert_eq!(std::fs::read(&dest).expect("read"), b"v1\n");
    assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
    for name in &attrs {
        assert_eq!(attr(name), None, "{name} is not restored either");
    }
}

#[test]
fn a_symlink_destination_is_refused_and_writes_nothing() {
    let home = guarded_home();
    let other = home.child("other");
    seed(&other, b"the link's target", Mode::DEFAULT_FILE);
    let dest = home.child("link");
    std::os::unix::fs::symlink("other", &dest).expect("symlink");

    let err = write_atomically(&dest, b"replacement", Mode::DEFAULT_FILE)
        .expect_err("a link the user made is not bx's to replace");
    assert!(matches!(err, Error::Symlink(_)), "{err:?}");
    assert_eq!(err.path(), dest);

    // The link survives, still pointing where it pointed, and its target is
    // untouched.
    assert!(
        std::fs::symlink_metadata(&dest)
            .expect("stat")
            .file_type()
            .is_symlink(),
    );
    assert_eq!(
        std::fs::read_link(&dest).expect("readlink"),
        Path::new("other"),
    );
    assert_eq!(std::fs::read(&other).expect("read"), b"the link's target");

    // And `plan` says the same thing rather than something else.
    let outcome = outcome_for(&home, "link", b"replacement", Mode::DEFAULT_FILE);
    assert_eq!(outcome.drift, Drift::Conflict);
    assert_eq!(
        outcome.note.as_deref(),
        Some("a symlink; bx will not replace a link you created"),
    );
}

#[test]
fn a_symlink_in_a_parent_component_is_written_through() {
    let home = guarded_home();
    // The kernel resolves a parent symlink, the temporary file lands in the
    // real directory, and the rename stays inside that one directory. Only
    // the final component is bx's business.
    std::fs::create_dir(home.child("real")).expect("mkdir");
    std::os::unix::fs::symlink("real", home.child("link")).expect("symlink");

    write_atomically(&home.child("link/f"), b"x", Mode::DEFAULT_FILE).expect("write");

    assert_eq!(std::fs::read(home.child("real/f")).expect("read"), b"x");
    assert!(
        std::fs::symlink_metadata(home.child("link"))
            .expect("stat")
            .file_type()
            .is_symlink(),
        "the link survives",
    );
}

#[test]
fn a_missing_parent_directory_is_created_at_the_default_dir_mode() {
    let home = guarded_home();
    let dest = home.child("a/b/c/f");
    // `stage`, which is the only entry point that creates a directory.
    stage_now(&dest, Mode::PRIVATE_FILE)
        .expect("stage")
        .commit(b"x")
        .expect("commit");

    assert_eq!(std::fs::read(&dest).expect("read"), b"x");
    for rel in ["a", "a/b", "a/b/c"] {
        assert_eq!(
            mode_of_path(&home.child(rel)),
            Mode::DEFAULT_DIR,
            "{rel} is an implicit parent, created at 0755",
        );
    }
}

#[test]
fn the_one_call_shorthand_creates_no_directory_and_says_so() {
    // The base's contract, kept for the entry point that has no
    // `CreatedDirs` to record a directory in, no plan to announce it in,
    // and no caller to say what mode it should get — which is how a 0600
    // secret would otherwise land in a 0755 directory nobody decided on.
    // `stage` and `ensure_dir` still create directories; this one does not.
    let home = guarded_home();
    let dest = home.child("a/b/secret.age");

    let err = write_atomically(&dest, b"x", Mode::PRIVATE_FILE)
        .expect_err("the shorthand invents no directory");
    assert!(
        matches!(&err, Error::MissingParent(dir) if *dir == home.child("a/b")),
        "{err:?}",
    );
    assert_eq!(err.path(), home.child("a/b"));
    assert!(
        err.to_string()
            .contains("bx creates no directory for this write"),
        "{err}",
    );
    assert!(!home.child("a").exists(), "nothing was created");
    assert_eq!(names_in(home.path()), Vec::<OsString>::new());

    // With the directory there it writes, and the mode of the directory is
    // the caller's own decision rather than a default.
    std::fs::create_dir_all(home.child("a/b")).expect("the caller creates it");
    set_mode(&home.child("a/b"), Mode::PRIVATE_DIR).expect("chmod");
    write_atomically(&dest, b"x", Mode::PRIVATE_FILE).expect("write");
    assert_eq!(std::fs::read(&dest).expect("read"), b"x");
    assert_eq!(mode_of_path(&home.child("a/b")), Mode::PRIVATE_DIR);

    // A parent that is there but does not resolve is still the conflict it
    // was, not this.
    let dangling = home.child("dangling");
    std::os::unix::fs::symlink("nowhere", &dangling).expect("symlink");
    let err = write_atomically(&dangling.join("f"), b"x", Mode::DEFAULT_FILE)
        .expect_err("a dangling parent is unusable, not missing");
    assert!(matches!(err, Error::UnusableParent { .. }), "{err:?}");
}

#[test]
fn a_parent_created_for_an_abandoned_write_is_left_in_place() {
    let home = guarded_home();
    let dest = home.child(".ssh/config");
    let staged = stage_now(&dest, Mode::PRIVATE_FILE).expect("stage");
    let temp = staged.temp_path().to_path_buf();
    staged.abandon();

    // Documented behaviour, not an oversight: the directory is empty and at
    // the mode a mkdir would have given it, the next attempt reuses it, and
    // removing it would race any other write already using it.
    assert!(home.child(".ssh").is_dir());
    assert_eq!(mode_of_path(&home.child(".ssh")), Mode::DEFAULT_DIR);
    assert_eq!(names_in(&home.child(".ssh")), Vec::<OsString>::new());
    assert!(!temp.exists());
    assert!(!dest.exists());
}

#[test]
fn an_existing_parent_directory_is_never_chmod_d() {
    let home = guarded_home();
    std::fs::create_dir(home.child("shared")).expect("mkdir");
    set_mode(&home.child("shared"), Mode::from_bits(0o770)).expect("chmod");

    write_atomically(&home.child("shared/f"), b"x", Mode::PRIVATE_FILE).expect("write");

    assert_eq!(
        mode_of_path(&home.child("shared")),
        Mode::from_bits(0o770),
        "a directory bx did not create is the user's",
    );
}

#[test]
fn an_unwritable_parent_directory_surfaces_a_typed_error() {
    if rustix::process::geteuid().is_root() {
        // Root ignores the permission bits, so there is nothing to assert.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let home = guarded_home();
    let dir = home.child("locked");
    std::fs::create_dir(&dir).expect("mkdir");
    set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

    let dest = dir.join("f");
    let err = write_atomically(&dest, b"x", Mode::DEFAULT_FILE).expect_err("must fail");
    assert!(matches!(err, Error::Write { .. }), "{err:?}");
    assert_eq!(err.path(), dir, "the error names the directory");
    assert!(!dest.exists());

    set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");
}

#[test]
fn a_missing_directory_under_a_read_only_parent_is_a_write_error_naming_it() {
    if rustix::process::geteuid().is_root() {
        // Root ignores the permission bits, so the mkdir is not refused.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let home = guarded_home();
    let dir = home.child("d");
    std::fs::create_dir(&dir).expect("mkdir");
    set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

    let result = stage_now(&dir.join("sub/f"), Mode::DEFAULT_FILE).and_then(|s| s.commit(b"x"));
    set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for the assertions");

    let err = result.expect_err("a read-only directory refuses the mkdir");
    let Error::Write { path, source } = &err else {
        panic!("expected a write error, got {err:?}");
    };
    assert_eq!(
        path,
        &dir.join("sub"),
        "the error names the directory bx could not make",
    );
    assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        names_in(&dir),
        Vec::<OsString>::new(),
        "nothing was made or written",
    );
}

#[test]
fn a_parent_that_cannot_be_stat_ed_is_an_error_not_an_absent_directory() {
    if rustix::process::geteuid().is_root() {
        // Root ignores the permission bits, so there is nothing to assert.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let home = guarded_home();
    let locked = home.child("locked");
    std::fs::create_dir(&locked).expect("mkdir");
    // No execute bit, so nothing below it can be stat'd at all.
    set_mode(&locked, Mode::from_bits(0o000)).expect("chmod");

    // The third `ENOENT`-adjacent case, and the one that must *not* become
    // a directory bx invents: the parent may well be there, and bx cannot
    // see. A read error is the only honest answer.
    let err = observe(&locked.join("sub/f")).expect_err("must fail");
    let Error::Read { path, .. } = &err else {
        panic!("expected a read error, got {err:?}");
    };
    assert_eq!(path, &locked.join("sub"));

    set_mode(&locked, Mode::PRIVATE_DIR).expect("unlock for cleanup");
}

#[test]
fn a_path_with_no_parent_is_refused() {
    let err = write_atomically(Path::new("/"), b"x", Mode::DEFAULT_FILE).expect_err("must fail");
    assert!(matches!(err, Error::NoParent(_)), "{err:?}");
    assert_eq!(err.path(), Path::new("/"));
}

#[test]
fn a_bare_file_name_writes_into_the_working_directory() {
    assert_eq!(parent_of(Path::new("f")).expect("parent"), Path::new("."));
}

#[test]
fn a_relative_destination_writes_under_the_working_directory() {
    let _serialised = CWD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let home = guarded_home();
    let previous = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(home.path()).expect("chdir");

    // A bare name, which `parent_of` resolves to `.` — the contract it goes
    // out of its way to support, and which nothing had ever exercised
    // through an actual write.
    let bare = write_atomically(Path::new("bare"), b"x", Mode::DEFAULT_FILE);
    // And a relative path more than one component deep, where `ancestors`
    // ends with `""`. Its directories are missing, so it goes through the
    // phases: only `stage` creates one.
    let deep = stage_now(Path::new("a/b/c.txt"), Mode::PRIVATE_FILE).and_then(|s| s.commit(b"y"));

    std::env::set_current_dir(&previous).expect("restore the working directory");
    bare.expect("a bare relative name");
    deep.expect("a relative path two directories deep");

    assert_eq!(std::fs::read(home.child("bare")).expect("read"), b"x");
    assert_eq!(std::fs::read(home.child("a/b/c.txt")).expect("read"), b"y");
    for rel in ["a", "a/b"] {
        assert_eq!(mode_of_path(&home.child(rel)), Mode::DEFAULT_DIR, "{rel}");
    }
}

/// `apply` for a file target's `Modify`, acting on the observation `plan`
/// compared: staged against it and committed with the desired bytes,
/// whether the drift is in the content, the mode, or both.
fn apply_file_modify(planned: &Observed, dest: &Path, desired: &Desired<'_>) -> Result<(), Error> {
    stage(dest, desired.mode, planned, &mut CreatedDirs::new())?.commit(desired.bytes)
}

#[test]
fn a_mode_only_modify_changed_after_plan_is_refused_and_keeps_the_change() {
    // Invariants 4 and 7 for the smallest Modify there is: plan announced
    // `mode 0644 -> 0600` against one file, and apply may act only on that
    // file, unchanged.
    let home = guarded_home();
    let want = desired(b"Host *\n", Mode::PRIVATE_FILE);

    // (a) The user chmods the file after plan printed its line.
    let chmodded = home.child("chmodded");
    seed(&chmodded, b"Host *\n", Mode::DEFAULT_FILE);
    let planned_a = observe(&chmodded).expect("plan observes");
    let outcome = compare(&planned_a, &want, home.path());
    assert_eq!(outcome.drift, Drift::Modify);
    assert!(!outcome.content_drift, "only the mode drifted");
    set_mode(&chmodded, Mode::from_bits(0o640)).expect("the user's chmod after plan");
    let result_a = apply_file_modify(&planned_a, &chmodded, &want);
    let mode_a = mode_of_path(&chmodded);

    // (b) The file is replaced by a directory after plan printed its line.
    let replaced = home.child("replaced");
    seed(&replaced, b"Host *\n", Mode::DEFAULT_FILE);
    let planned_b = observe(&replaced).expect("plan observes");
    assert_eq!(compare(&planned_b, &want, home.path()).drift, Drift::Modify);
    std::fs::remove_file(&replaced).expect("rm");
    std::fs::create_dir(&replaced).expect("a directory takes the path");
    set_mode(&replaced, Mode::DEFAULT_DIR).expect("at its own mode");
    std::fs::write(replaced.join("inside"), b"theirs").expect("with an entry");
    let result_b = apply_file_modify(&planned_b, &replaced, &want);
    let mode_b = mode_of_path(&replaced);

    assert!(
        matches!(
            (&result_a, &result_b),
            (Err(Error::Changed { .. }), Err(Error::Changed { .. }))
        ),
        "(a) chmod 0640 after plan: {result_a:?}, file now {mode_a}; \
             (b) directory after plan: {result_b:?}, directory now {mode_b}",
    );
    assert_eq!(
        mode_a,
        Mode::from_bits(0o640),
        "(a) the user's chmod stands"
    );
    assert_eq!(std::fs::read(&chmodded).expect("read"), b"Host *\n");
    assert_eq!(
        mode_b,
        Mode::DEFAULT_DIR,
        "(b) the directory keeps its mode"
    );
    assert_eq!(
        std::fs::read(replaced.join("inside")).expect("the entry is still readable"),
        b"theirs",
    );
    assert_eq!(
        names_in(home.path()),
        vec![OsString::from("chmodded"), OsString::from("replaced")],
        "no temporary file is left",
    );
}

#[test]
fn set_mode_changes_the_mode_in_place_without_replacing_the_inode() {
    let home = guarded_home();
    let dest = home.child("f");
    seed(&dest, b"v1", Mode::DEFAULT_FILE);
    let link = home.child("hardlink");
    std::fs::hard_link(&dest, &link).expect("hard link");
    let before = std::fs::metadata(&dest).expect("stat").ino();

    set_mode(&dest, Mode::PRIVATE_FILE).expect("chmod");

    assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"v1",
        "content is untouched"
    );
    assert_eq!(
        std::fs::metadata(&dest).expect("stat").ino(),
        before,
        "a chmod keeps the inode; a rewrite would not",
    );
    assert_eq!(
        mode_of_path(&link),
        Mode::PRIVATE_FILE,
        "the user's hard link still points at the same file",
    );
}

#[test]
fn set_mode_refuses_a_symlink() {
    let home = guarded_home();
    seed(&home.child("real"), b"x", Mode::DEFAULT_FILE);
    let link = home.child("link");
    std::os::unix::fs::symlink("real", &link).expect("symlink");

    let err = set_mode(&link, Mode::PRIVATE_FILE).expect_err("must fail");
    assert!(matches!(err, Error::Symlink(_)), "{err:?}");
    assert_eq!(
        mode_of_path(&home.child("real")),
        Mode::DEFAULT_FILE,
        "the link's target keeps its mode",
    );
}

#[test]
fn set_mode_names_a_path_that_is_not_there() {
    let home = guarded_home();
    let err = set_mode(&home.child("nope"), Mode::PRIVATE_FILE).expect_err("must fail");
    assert!(matches!(err, Error::Write { .. }), "{err:?}");
    assert_eq!(err.path(), home.child("nope"));
}

#[test]
fn fill_syncs_the_temporary_file_before_it_returns() {
    let home = guarded_home();
    let staged = stage_now(&home.child("f"), Mode::DEFAULT_FILE).expect("stage");
    let temp = staged.temp_path().to_path_buf();

    let (filled, events) = durable::recording(|| staged.fill(b"x"));
    let filled = filled.expect("fill");

    assert_eq!(
        events,
        [durable::Event::SyncFile(temp)],
        "the content is fsynced inside fill, so a journal recording its intent \
             after fill returns is recording durable bytes",
    );
    filled.abandon();
}

#[test]
fn publish_syncs_the_directory_only_after_the_rename() {
    let home = guarded_home();
    let dest = home.child(".config/f");
    let filled = stage_now(&dest, Mode::DEFAULT_FILE)
        .expect("stage")
        .fill(b"x")
        .expect("fill");
    let temp = filled.temp_path().to_path_buf();

    let (published, events) = durable::recording(|| filled.publish());
    published.expect("publish");

    let dir = home.child(".config");
    assert_eq!(
        events,
        [
            durable::Event::OpenDir(dir.clone()),
            durable::Event::Rename {
                from: temp,
                to: dest.clone(),
            },
            durable::Event::SyncDir(dir),
        ],
        "the directory is opened before the rename and fsynced after it",
    );
}

#[test]
fn write_atomically_makes_every_durability_call_in_order() {
    let home = guarded_home();
    let dest = home.child("f");
    seed(&dest, b"v1", Mode::DEFAULT_FILE);

    let (result, events) =
        durable::recording(|| write_atomically(&dest, b"v2", Mode::DEFAULT_FILE));
    result.expect("write");

    let [
        durable::Event::SyncFile(synced),
        durable::Event::OpenDir(opened),
        durable::Event::Rename { from, to },
        durable::Event::SyncDir(dir_synced),
    ] = events.as_slice()
    else {
        panic!("expected sync, open, rename, sync; got {events:?}");
    };
    assert_eq!(synced, from, "the file synced is the file renamed");
    assert_eq!(to, &dest);
    assert_eq!(opened, home.path());
    assert_eq!(dir_synced, home.path());
}

#[test]
fn a_failed_rename_syncs_no_directory() {
    if rustix::process::geteuid().is_root() {
        // Root ignores the permission bits, so the rename is not refused.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let home = guarded_home();
    let dir = home.child("d");
    let dest = dir.join("f");
    seed(&dest, b"theirs", Mode::DEFAULT_FILE);
    set_mode(&dir, Mode::PRIVATE_DIR).expect("chmod");
    let filled = stage_now(&dest, Mode::DEFAULT_FILE)
        .expect("stage")
        .fill(b"x")
        .expect("fill");
    let temp = filled.temp_path().to_path_buf();
    // Read and search but no write: the directory still opens and the
    // destination is still what stage observed, so the rename itself is
    // the call that fails.
    set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

    let (published, events) = durable::recording(|| filled.publish());
    set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for the assertions");

    let refused = published.expect_err("an unwritable directory refuses the rename");
    assert_eq!(refused.dest, dest, "the refusal names the write");
    let err = refused.into_error();
    let Error::Write { path, source } = &err else {
        panic!("expected a write error, got {err:?}");
    };
    assert_eq!(path, &dest, "the rename's error names the destination");
    assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        events,
        [durable::Event::OpenDir(dir.clone())],
        "no rename landed and no directory was synced",
    );
    assert_eq!(std::fs::read(&dest).expect("read"), b"theirs");
    assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
    // The directory that refused the rename refused the unlink too.
    assert!(temp.exists(), "the temporary file is left for recovery");
    std::fs::remove_file(&temp).expect("clean up the leftover");
    assert_eq!(names_in(&dir), vec![OsString::from("f")]);
}

#[test]
fn an_entry_that_cannot_be_made_portable_is_refused_not_recorded() {
    // `Portable::from_path` refuses rather than renaming a path it cannot
    // represent, so the entry is an error rather than a ledger key that
    // names a different file.
    let home = guarded_home();
    let dest = home.child(".config/tool/x.conf");
    let filled = stage_now(&dest, Mode::DEFAULT_FILE)
        .expect("stage")
        .fill(b"x")
        .expect("fill");

    let err = NewEntry::for_write(&filled, Path::new("relative/home"), Mechanism::Own)
        .expect_err("a relative home makes nothing portable");
    assert!(
        matches!(
            &err,
            Error::NotPortable {
                source: crate::paths::Error::HomeNotAbsolute(_),
                ..
            }
        ),
        "{err:?}",
    );
    assert_eq!(err.path(), dest);
    assert!(err.to_string().contains("cannot be recorded"), "{err}");

    // Under the real home the same write yields its entry.
    let entry = NewEntry::for_write(&filled, home.path(), Mechanism::Own)
        .expect("portable under the real home");
    assert_eq!(entry.path.as_str(), "~/.config/tool/x.conf");
}

/// A locked, writable ledger for a guarded home.
fn ledger_for(home: &GuardedHome) -> (StateDir, ExclusiveLock, Ledger) {
    let dir = StateDir::resolve(home.path());
    dir.ensure().expect("ensure the state directory");
    let lock = ExclusiveLock::acquire(&dir).expect("acquire the lock");
    let ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    (dir, lock, ledger)
}

#[test]
fn the_prior_bytes_are_recordable_before_the_rename_and_restore_exactly() {
    let home = guarded_home();
    let (dir, _lock, mut ledger) = ledger_for(&home);
    let dest = home.child(".ssh/config");
    seed(&dest, b"Host old\n", Mode::from_bits(0o640));

    let filled = stage_now(&dest, Mode::PRIVATE_FILE)
        .expect("stage")
        .fill(b"Host new\n")
        .expect("fill");

    // The recording point: the new content is durable, the destination is
    // still the old content, and the entry describes both.
    assert_eq!(std::fs::read(&dest).expect("read"), b"Host old\n");
    let recorded = ledger
        .record(
            NewEntry::for_write(&filled, home.path(), Mechanism::Own).expect("a portable entry"),
        )
        .expect("record")
        .clone();
    filled.publish().expect("publish");

    assert_eq!(recorded.path.as_str(), "~/.ssh/config");
    assert_eq!(recorded.written, ContentHash::of(b"Host new\n"));
    assert_eq!(recorded.mode, Mode::PRIVATE_FILE);
    assert_eq!(std::fs::read(&dest).expect("read"), b"Host new\n");
    assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);

    // Reversibility: the ledger alone reproduces the displaced file, byte
    // for byte and mode for mode.
    let Prior::Existed(reference) = &recorded.prior else {
        panic!("the prior state must be Existed, got {:?}", recorded.prior);
    };
    assert_eq!(reference.mode, Mode::from_bits(0o640));
    assert_eq!(reference.len, 9);
    let bytes =
        restore::read(&dir, reference).expect("the blob is durable by the time record returns");
    write_atomically(&dest, &bytes, reference.mode).expect("restore");
    assert_eq!(std::fs::read(&dest).expect("read"), b"Host old\n");
    assert_eq!(mode_of_path(&dest), Mode::from_bits(0o640));
}

#[test]
fn a_link_at_a_blob_name_is_refused_with_a_remedy_that_fits_a_path_bx_owns() {
    // `write_atomically` refuses a symlink, and `Ledger::record` snapshots
    // the prior through it, so a link at `restore/<digest>` — from a
    // restored backup, an `rsync --links`, a hand — fails every record that
    // needs that content. bx will not unlink it: it made no link, so the
    // link is somebody's, and removing it inside bx's own directory is
    // still removing it. What it owes is a remedy that makes sense for a
    // file nobody declared.
    let home = guarded_home();
    let (dir, _lock, mut ledger) = ledger_for(&home);
    let dest = home.child(".ssh/config");
    seed(&dest, b"Host old\n", Mode::from_bits(0o640));
    let blob = dir.restore().join(ContentHash::of(b"Host old\n").to_hex());
    std::fs::create_dir_all(dir.restore()).expect("restore/");
    let elsewhere = home.child("elsewhere");
    std::fs::write(&elsewhere, b"not a blob\n").expect("seed");
    std::os::unix::fs::symlink(&elsewhere, &blob).expect("symlink");

    let filled = stage_now(&dest, Mode::PRIVATE_FILE)
        .expect("stage")
        .fill(b"Host new\n")
        .expect("fill");
    let entry =
        NewEntry::for_write(&filled, home.path(), Mechanism::Own).expect("a portable entry");
    let err = ledger
        .record(entry.clone())
        .expect_err("a link at the blob name is not bx's to replace");
    let message = err.to_string();
    assert!(
        message.contains(&blob.display().to_string()),
        "the refusal names the file to remove: {message}",
    );
    assert!(message.contains("Remove the link"), "{message}");
    assert_eq!(
        std::fs::read_link(&blob).expect("readlink"),
        elsewhere,
        "the link and what it names are left alone",
    );
    assert_eq!(std::fs::read(&elsewhere).expect("read"), b"not a blob\n");

    // The remedy the message gives is the whole repair: the blob is
    // content-addressed, so the next record reconstructs it.
    std::fs::remove_file(&blob).expect("the remedy");
    ledger.record(entry).expect("record repairs itself");
    assert_eq!(std::fs::read(&blob).expect("read"), b"Host old\n");
    filled.publish().expect("publish");
}

#[test]
fn a_ledger_entry_for_a_refused_publish_is_withdrawn_through_what_the_refusal_names() {
    // The one state the seam makes reachable and no other test reached:
    // `record` has succeeded, so the prior bytes are durable in `restore/`
    // and the in-memory ledger claims the target — and then `publish`
    // refuses, so the destination still holds what the user has.
    //
    // Saving the ledger from here would make `bx rm` write the recorded
    // prior over content bx never replaced. What stops it is that the
    // refusal names the write, so the entry can be withdrawn.
    let home = guarded_home();
    let (dir, _lock, mut ledger) = ledger_for(&home);
    let dest = home.child(".ssh/config");
    seed(&dest, b"Host old\n", Mode::from_bits(0o640));

    let filled = stage_now(&dest, Mode::PRIVATE_FILE)
        .expect("stage")
        .fill(b"Host new\n")
        .expect("fill");
    let key = Portable::from_path(&dest, home.path()).expect("portable");
    let withdrawal = ledger.withdrawal(&key);
    let recorded = ledger
        .record(
            NewEntry::for_write(&filled, home.path(), Mechanism::Own).expect("a portable entry"),
        )
        .expect("record")
        .clone();
    let Prior::Existed(reference) = &recorded.prior else {
        panic!("the prior state must be Existed, got {:?}", recorded.prior);
    };

    // The user saves over the destination between the record and the
    // rename, which is exactly what `publish` refuses.
    std::fs::write(&dest, b"Host theirs\n").expect("the user saves");
    let refused = filled.publish().expect_err("the destination changed");
    assert_eq!(refused.dest, dest, "the refusal names the write");
    assert!(
        matches!(refused.error, Error::Changed { .. }),
        "{:?}",
        refused.error,
    );
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"Host theirs\n",
        "bx wrote nothing",
    );

    // What the ledger is left holding: the entry, and the blob its prior
    // names. Both are real, and both describe a write that did not happen.
    assert_eq!(ledger.len(), 1, "the entry is still in the ledger");
    assert_eq!(
        restore::read(&dir, reference).expect("the blob record fsynced"),
        b"Host old\n",
        "the snapshot is durable, and it is not what is on disk now",
    );

    // The withdrawal: the refusal names the entry's key, and the entry
    // before the record was none, so none is put back.
    assert_eq!(
        Portable::from_path(&refused.dest, home.path()).expect("portable"),
        key,
        "the refusal names the key the withdrawal was taken for",
    );
    let withdrawn = ledger
        .withdraw(withdrawal)
        .expect("the entry is there to withdraw");
    assert_eq!(withdrawn.written, ContentHash::of(b"Host new\n"));
    assert!(ledger.is_empty(), "nothing claims the target now");
    ledger.save().expect("save");

    // Read back from disk: no entry, so `bx rm` has nothing to restore
    // over the user's file. The blob is left in `restore/`, which is
    // content-addressed and reused rather than owned by one entry.
    let reread = LedgerView::read(&dir, home.path()).expect("read").value;
    assert!(reread.is_empty(), "the durable ledger claims nothing");
    assert_eq!(std::fs::read(&dest).expect("read"), b"Host theirs\n");
}

#[test]
fn a_refused_re_record_is_withdrawn_to_the_entry_it_replaced() {
    // Every apply after the first re-records a target bx already has an
    // entry for, and that entry holds the prior the user had before bx.
    // Withdrawing a refused re-record by dropping the key — `forget` —
    // loses that prior for good. The withdrawal puts back the whole entry
    // as it was before the record: prior, history and all.
    let home = guarded_home();
    let (dir, _lock, mut ledger) = ledger_for(&home);
    let dest = home.child(".ssh/config");
    seed(&dest, b"Host old\n", Mode::from_bits(0o640));
    let key = Portable::from_path(&dest, home.path()).expect("portable");

    // The first apply lands, and the ledger is saved.
    let first = stage_now(&dest, Mode::PRIVATE_FILE)
        .expect("stage")
        .fill(b"Host v1\n")
        .expect("fill");
    ledger
        .record(NewEntry::for_write(&first, home.path(), Mechanism::Own).expect("a portable entry"))
        .expect("record");
    first.publish().expect("publish");
    ledger.save().expect("save");
    let before = ledger.get(&key).expect("recorded").clone();
    let Prior::Existed(original) = &before.prior else {
        panic!("the prior state must be Existed, got {:?}", before.prior);
    };

    // The user edits the result, so the second apply's record adopts the
    // edit as the prior and moves the original to the history — the
    // re-record that changes the most.
    std::fs::write(&dest, b"Host edited\n").expect("the user edits");
    let withdrawal = ledger.withdrawal(&key);
    let second = stage_now(&dest, Mode::PRIVATE_FILE)
        .expect("stage")
        .fill(b"Host v2\n")
        .expect("fill");
    let recorded = ledger
        .record(
            NewEntry::for_write(&second, home.path(), Mechanism::Own).expect("a portable entry"),
        )
        .expect("record")
        .clone();
    assert_ne!(recorded, before, "the re-record changed the entry");
    assert_eq!(recorded.superseded, vec![original.clone()]);

    // The user saves again between the record and the rename.
    std::fs::write(&dest, b"Host theirs\n").expect("the user saves");
    let refused = second.publish().expect_err("the destination changed");
    assert!(
        matches!(refused.error, Error::Changed { .. }),
        "{:?}",
        refused.error,
    );
    assert_eq!(
        Portable::from_path(&refused.dest, home.path()).expect("portable"),
        key,
    );

    let withdrawn = ledger.withdraw(withdrawal).expect("the refused record");
    assert_eq!(withdrawn, recorded, "the refused record is handed back");
    assert_eq!(
        ledger.get(&key),
        Some(&before),
        "the entry is exactly what it was before the record",
    );
    ledger.save().expect("save");

    // Durably: `bx rm` still restores the file the user had before bx.
    let reread = LedgerView::read(&dir, home.path()).expect("read").value;
    let entry = reread.get(&key).expect("the entry survives the withdrawal");
    assert_eq!(entry, &before);
    assert_eq!(
        restore::read(&dir, original).expect("the original prior"),
        b"Host old\n",
    );
    assert_eq!(std::fs::read(&dest).expect("read"), b"Host theirs\n");
}

#[test]
fn re_applying_after_an_edit_keeps_every_byte_the_user_wrote() {
    // The ordinary case, not an edge one: a user applies, edits the result,
    // and applies again. The second apply displaces the user's edit, so the
    // edit is what the user last had and becomes the prior `bx rm` restores
    // (#7, decision 13); the original file it replaces as the prior is not
    // dropped but kept in `superseded`. Losing either set of bytes, or
    // letting a later `PriorBytes::Absent` — which is what a writer over an
    // *absent* destination supplies — turn the prior into "unlink it",
    // turns Invariant 4 into its opposite, and the writer is the side that
    // supplies the prior, so the writer's tests are a place this has to be
    // pinned.
    //
    // This test used to be `..._still_restores_the_user_s_original_file`
    // and assert decision 7's first-prior-wins rule, under which rm wrote
    // `Host theirs` over the user's `Host edited` and the edit existed
    // nowhere.
    let home = guarded_home();
    let (dir, _lock, mut ledger) = ledger_for(&home);
    let dest = home.child(".ssh/config");
    seed(&dest, b"Host theirs\n", Mode::from_bits(0o640));

    for content in [b"Host v1\n", b"Host v2\n"] {
        let filled = stage_now(&dest, Mode::PRIVATE_FILE)
            .expect("stage")
            .fill(content)
            .expect("fill");
        ledger
            .record(
                NewEntry::for_write(&filled, home.path(), Mechanism::Own)
                    .expect("a portable entry"),
            )
            .expect("record");
        filled.publish().expect("publish");
        // The user edits what bx wrote, so the second apply's `observe`
        // finds neither the user's original nor bx's output.
        std::fs::write(&dest, b"Host edited\n").expect("the user edits it");
    }

    let recorded = ledger
        .record(NewEntry::new(
            Portable::from_path(&dest, home.path()).expect("portable"),
            ContentHash::of(b"Host v2\n"),
            Mode::PRIVATE_FILE,
            Mechanism::Own,
            PriorBytes::Absent,
        ))
        .expect("record")
        .clone();

    let Prior::Existed(reference) = &recorded.prior else {
        panic!(
            "an absent incoming prior may not turn a snapshot into an unlink, got {:?}",
            recorded.prior
        );
    };
    // The edit was written over bx's 0600 output, so it carries that mode.
    assert_eq!(reference.mode, Mode::PRIVATE_FILE);
    assert_eq!(
        restore::read(&dir, reference).expect("restore bytes"),
        b"Host edited\n",
        "the prior is what the user last had: the edit the second apply displaced",
    );

    assert_eq!(
        recorded.superseded.len(),
        1,
        "the original is kept, once: {:?}",
        recorded.superseded,
    );
    let original = &recorded.superseded[0];
    assert_eq!(original.mode, Mode::from_bits(0o640));
    assert_eq!(
        restore::read(&dir, original).expect("restore the original"),
        b"Host theirs\n",
        "the file the user had before bx ever touched it is still restorable",
    );
}

#[test]
fn a_prior_mode_is_recordable_for_a_mode_only_change() {
    let home = guarded_home();
    let (dir, _lock, mut ledger) = ledger_for(&home);
    let dest = home.child(".ssh/config");
    seed(&dest, b"Host *\n", Mode::DEFAULT_FILE);

    // The one read, shared by the comparison and the apply.
    let want = desired(b"Host *\n", Mode::PRIVATE_FILE);
    let planned = observe(&dest).expect("observe");
    let outcome = compare(&planned, &want, home.path());
    assert_eq!(outcome.drift, Drift::Modify);
    assert!(!outcome.content_drift);

    // Applied like any other Modify: staged against plan's observation,
    // with the same bytes at the new mode.
    let filled = stage(&dest, want.mode, &planned, &mut CreatedDirs::new())
        .expect("stage")
        .fill(want.bytes)
        .expect("fill");
    let recorded = ledger
        .record(
            NewEntry::for_write(&filled, home.path(), Mechanism::Own).expect("a portable entry"),
        )
        .expect("record")
        .clone();
    filled.publish().expect("publish");

    let Prior::Existed(reference) = &recorded.prior else {
        panic!("the prior state must be Existed, got {:?}", recorded.prior);
    };
    assert_eq!(reference.mode, Mode::DEFAULT_FILE);
    assert_eq!(
        Some(recorded.written),
        planned.digest(),
        "a mode-only change writes back the content it found",
    );
    assert_eq!(recorded.written, ContentHash::of(b"Host *\n"));
    assert_eq!(recorded.mode, Mode::PRIVATE_FILE);
    assert_eq!(mode_of_path(&dest), Mode::PRIVATE_FILE);
    assert_eq!(std::fs::read(&dest).expect("read"), b"Host *\n");
    // Idempotent: the second plan is empty.
    assert_eq!(
        compare(&observe(&dest).expect("observe again"), &want, home.path()).drift,
        Drift::Unchanged,
    );

    // Reversing it restores the prior bytes at the prior mode.
    let bytes = restore::read(&dir, reference).expect("the prior bytes are durable");
    write_atomically(&dest, &bytes, reference.mode).expect("reverse");
    assert_eq!(mode_of_path(&dest), Mode::DEFAULT_FILE);
    assert_eq!(std::fs::read(&dest).expect("read"), b"Host *\n");
}

#[test]
fn a_write_over_nothing_records_that_nothing_was_there() {
    let home = guarded_home();
    let dest = home.child("f");
    let filled = stage_now(&dest, Mode::DEFAULT_FILE)
        .expect("stage")
        .fill(b"x")
        .expect("fill");
    assert_eq!(PriorBytes::of(filled.prior()), PriorBytes::Absent);
    assert_eq!(filled.prior().digest(), None);
    assert!(filled.created_dirs().is_empty());
    assert_eq!(filled.written(), ContentHash::of(b"x"));
}

#[test]
fn a_non_file_destination_has_no_prior_bytes_to_record() {
    let home = guarded_home();
    std::fs::create_dir(home.child("d")).expect("mkdir");
    std::os::unix::fs::symlink("d", home.child("l")).expect("symlink");

    for rel in ["d", "l"] {
        let observed = observe(&home.child(rel)).expect("observe");
        assert_eq!(PriorBytes::of(&observed), PriorBytes::Absent, "{rel}");
        assert_eq!(observed.digest(), None, "{rel}");
    }
}

#[test]
fn a_directory_that_cannot_be_opened_for_its_fsync_fails_before_the_rename() {
    if rustix::process::geteuid().is_root() {
        // Root ignores the permission bits, so there is nothing to assert.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let home = guarded_home();
    let dir = home.child("dropbox");
    let dest = dir.join("f");
    seed(&dest, b"v1", Mode::DEFAULT_FILE);
    // Write and search, no read: a temporary file can be created and renamed
    // here, and the directory cannot be opened to fsync the rename.
    set_mode(&dir, Mode::from_bits(0o300)).expect("chmod");

    let result = write_atomically(&dest, b"v2", Mode::DEFAULT_FILE);
    set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");

    let err = result.expect_err("the rename cannot be made durable");
    assert!(matches!(err, Error::Write { .. }), "{err:?}");
    assert_eq!(err.path(), dir);
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"v1",
        "an Err from before the rename means the destination holds exactly what it held before",
    );
    assert_eq!(names_in(&dir), vec![OsString::from("f")]);
}

#[test]
fn a_directory_that_opens_but_refuses_the_temporary_file_fails_the_write_naming_it() {
    // Integration of #7 @b70d40e (r3), porting ec3a544. In this writer
    // `stage` creates the temporary file, and only `Filled::publish`, later,
    // opens the directory to sync the rename. So the temporary file's own
    // creation failing is the first thing a directory without write
    // permission refuses: this write stops in `stage`, and the directory is
    // never opened at all.
    if rustix::process::geteuid().is_root() {
        // Root ignores the permission bits, so the condition cannot be staged.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let home = guarded_home();
    let dir = home.child("d");
    let dest = dir.join("f");
    seed(&dest, b"before", Mode::DEFAULT_FILE);
    // Read and search, no write: the destination can be observed, and no
    // temporary file can be created beside it.
    set_mode(&dir, Mode::from_bits(0o500)).expect("chmod");

    let result = write_atomically(&dest, b"after", Mode::DEFAULT_FILE);
    let names = names_in(&dir);
    set_mode(&dir, Mode::PRIVATE_DIR).expect("unlock for cleanup");

    let err = result.expect_err("a directory refusing the temporary file fails the write");
    assert!(matches!(&err, Error::Write { .. }), "{err:?}");
    assert_eq!(err.path(), dir, "the error names the directory");
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"before",
        "a failed write leaves the previous file exactly as it was",
    );
    assert_eq!(names, vec![OsString::from("f")], "no temporary file");
}

#[test]
fn a_temp_name_chosen_first_is_a_fresh_bx_name_beside_the_destination() {
    let home = guarded_home();
    let dest = home.child(".config/app/x.conf");
    let one = temp_beside(&dest).expect("a name");
    let two = temp_beside(&dest).expect("another");
    assert_eq!(one.parent(), dest.parent());
    let name = one
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .into_owned();
    assert!(name.starts_with(TEMP_PREFIX), "{name}");
    assert_eq!(name.len(), TEMP_PREFIX.len() + 16, "{name}");
    assert_ne!(one, two, "each write gets its own");
    // Chosen, not made: nothing exists on the way to it yet.
    assert!(!home.child(".config").exists());
    assert!(matches!(
        temp_beside(&home.child("a/../b")),
        Err(Error::ParentComponent(_))
    ));
}

#[test]
fn stage_as_makes_exactly_the_named_temp_and_the_parents_it_invents() {
    let home = guarded_home();
    let dest = home.child(".config/app/x.conf");
    let temp = temp_beside(&dest).expect("a name");
    let planned = observe(&dest).expect("observe");
    let staged = stage_as(
        &dest,
        &temp,
        Mode::DEFAULT_FILE,
        &planned,
        &mut CreatedDirs::new(),
    )
    .expect("stage");
    assert_eq!(staged.temp_path(), temp);
    assert!(temp.is_file());
    assert_eq!(
        staged.created_dirs(),
        [home.child(".config/app"), home.child(".config")],
        "deepest first, as the filled write names them",
    );
    let filled = staged.fill(b"x\n").expect("fill");
    assert_eq!(
        filled.created_dirs(),
        [home.child(".config/app"), home.child(".config")]
    );
    filled.publish().expect("publish");
    assert_eq!(std::fs::read(&dest).expect("read"), b"x\n");
    assert!(!temp.exists(), "renamed over the destination");
}

#[test]
fn stage_as_refuses_a_name_that_is_taken_or_not_a_bx_name_beside_the_destination() {
    let home = guarded_home();
    let dest = home.child("x.conf");
    let planned = observe(&dest).expect("observe");
    let taken = temp_beside(&dest).expect("a name");
    std::fs::write(&taken, b"theirs").expect("take it");
    let elsewhere = home.child("sub").join(format!("{TEMP_PREFIX}x"));
    for temp in [taken.clone(), home.child("x.conf.tmp"), elsewhere] {
        let err = stage_as(
            &dest,
            &temp,
            Mode::DEFAULT_FILE,
            &planned,
            &mut CreatedDirs::new(),
        )
        .expect_err("refused");
        assert!(
            matches!(err, Error::Write { .. }),
            "{}: {err:?}",
            temp.display()
        );
    }
    assert_eq!(
        std::fs::read(&taken).expect("kept"),
        b"theirs",
        "never replaced"
    );
    assert!(!dest.exists());
}

#[test]
fn refuse_stage_refuses_what_stage_would_and_makes_nothing() {
    let home = guarded_home();
    let dest = home.child(".config/app/x.conf");
    let planned = observe(&dest).expect("observe");
    let prior = refuse_stage(&dest, &planned, &CreatedDirs::new()).expect("admitted");
    assert_eq!(prior.kind, Kind::Absent);
    assert!(!home.child(".config").exists(), "nothing made");

    // A destination that changed since plan is refused as `stage` refuses it.
    let file = home.child("f");
    let planned = observe(&file).expect("observe");
    std::fs::write(&file, b"since\n").expect("write");
    assert!(matches!(
        refuse_stage(&file, &planned, &CreatedDirs::new()),
        Err(Error::Changed { .. })
    ));
    // And plan's own verdict: a directory is not a file bx can write.
    let dir = home.child("d");
    std::fs::create_dir(&dir).expect("mkdir");
    let planned = observe(&dir).expect("observe");
    assert!(matches!(
        refuse_stage(&dir, &planned, &CreatedDirs::new()),
        Err(Error::NotAFile { .. })
    ));
}
