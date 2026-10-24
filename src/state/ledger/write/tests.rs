use super::*;

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use crate::state::ledger::fixtures::*;
use crate::state::{Fingerprint, Fingerprints, Health};
use crate::testing::guarded_home;

#[test]
fn recording_a_target_stores_the_digest_mode_mechanism_and_prior_snapshot() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let stored = ledger
        .record(
            entry("~/.config/tool.toml", b"new")
                .with_prior(PriorBytes::Bytes {
                    bytes: b"old".to_vec(),
                    mode: Mode::from_bits(0o640),
                })
                .with_created_dirs(vec![target("~/.config")]),
        )
        .expect("record")
        .clone();

    assert_eq!(stored.path, target("~/.config/tool.toml"));
    assert_eq!(stored.written, ContentHash::of(b"new"));
    assert_eq!(stored.mode, Mode::DEFAULT_FILE);
    assert_eq!(stored.mechanism, Mechanism::Own);
    assert_eq!(stored.created_dirs, vec![target("~/.config")]);
    let Prior::Existed(reference) = &stored.prior else {
        panic!("expected a prior snapshot, got {:?}", stored.prior)
    };
    assert_eq!(reference.digest, ContentHash::of(b"old"));
    assert_eq!(reference.mode, Mode::from_bits(0o640));
    assert_eq!(reference.len, 3);
    assert_eq!(reference.blob_name(), ContentHash::of(b"old").to_hex());
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.is_empty());
}

#[test]
fn the_prior_blob_is_durable_before_record_returns() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.bashrc", b"new").with_prior(PriorBytes::Bytes {
            bytes: b"prior bytes".to_vec(),
            mode: Mode::PRIVATE_FILE,
        }))
        .expect("record");

    // No `save` has happened. The blob must already be on disk.
    let blob = dir.restore().join(ContentHash::of(b"prior bytes").to_hex());
    assert_eq!(std::fs::read(&blob).expect("read"), b"prior bytes");
    assert_eq!(mode_of(&blob), Mode::PRIVATE_FILE);
    assert!(!dir.ledger().exists(), "the ledger itself is not yet saved");
}

#[test]
fn re_recording_a_target_replaces_in_place_and_keeps_the_first_prior() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    // Apply #1: the user's own file is displaced and snapshotted.
    ledger
        .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
            bytes: b"the user wrote this".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("first");
    // Apply #2: the natural call, with no prior — what is on disk now is
    // bx's own output from apply #1, so there is nothing to snapshot.
    ledger
        .record(entry("~/.bashrc", b"second"))
        .expect("second");

    assert_eq!(ledger.len(), 1);
    let stored = ledger.get(&target("~/.bashrc")).expect("entry");
    assert_eq!(stored.written, ContentHash::of(b"second"));
    let Prior::Existed(reference) = &stored.prior else {
        panic!(
            "the first prior must survive a re-record, got {:?}",
            stored.prior
        );
    };
    assert_eq!(reference.digest, ContentHash::of(b"the user wrote this"));
    assert_eq!(
        restore::read(&dir, reference).expect("restore"),
        b"the user wrote this",
    );
}

#[test]
fn a_re_record_over_bxs_own_output_neither_stores_nor_adopts_it() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
            bytes: b"the user wrote this".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("first");
    // What is on disk is exactly what the first record said bx wrote.
    ledger
        .record(entry("~/.bashrc", b"second").with_prior(PriorBytes::Bytes {
            bytes: b"first".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("second");

    let stored = ledger.get(&target("~/.bashrc")).expect("entry");
    let Prior::Existed(reference) = &stored.prior else {
        panic!("expected the first prior");
    };
    assert_eq!(reference.digest, ContentHash::of(b"the user wrote this"));
    assert!(stored.superseded.is_empty());
    // bx's own output is never written, so re-recording leaves no orphan.
    let blobs: Vec<_> = std::fs::read_dir(dir.restore())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(
        blobs,
        vec![std::ffi::OsString::from(
            ContentHash::of(b"the user wrote this").to_hex()
        )],
    );
}

#[test]
fn forget_then_record_re_adopts_a_target_with_a_new_prior() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
            bytes: b"the user wrote this".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("first");
    let dropped = ledger.forget(&target("~/.bashrc")).expect("forget");
    assert_eq!(dropped.written, ContentHash::of(b"first"));

    ledger
        .record(entry("~/.bashrc", b"second").with_prior(PriorBytes::Bytes {
            bytes: b"and then the user wrote that".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("re-adopt");
    let stored = ledger.get(&target("~/.bashrc")).expect("entry");
    let Prior::Existed(reference) = &stored.prior else {
        panic!("expected the re-adopted prior");
    };
    assert_eq!(
        reference.digest,
        ContentHash::of(b"and then the user wrote that"),
    );
}

#[test]
fn a_re_record_cannot_turn_a_snapshot_into_an_unlink() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.bashrc", b"first").with_prior(PriorBytes::Bytes {
            bytes: b"the user wrote this".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("first");
    for _ in 0..3 {
        ledger
            .record(entry("~/.bashrc", b"again"))
            .expect("re-record");
        assert_ne!(
            ledger.get(&target("~/.bashrc")).expect("entry").prior,
            Prior::Absent,
            "re-recording must never rewrite a restore into an unlink",
        );
    }
}

#[test]
fn a_file_the_user_creates_between_two_applies_is_restored_by_rm_not_unlinked() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let rel = ".config/tool.toml";
    let users: &[u8] = b"[user]\nname = \"mine\"\ntheme = \"dark\"\n";
    assert_eq!(users.len(), 36);

    // Apply #1: nothing is there, so bx creates the file and the prior is
    // "there was no file".
    apply(&dir, &lock, &home, rel, b"# bx v1\n");
    // Between applies the user replaces bx's file with 36 bytes of their own.
    std::fs::write(home.child(rel), users).expect("the user writes");
    // Apply #2 displaces those bytes.
    apply(&dir, &lock, &home, rel, b"# bx v2\n");

    assert!(
        has_blob(&dir, users),
        "the displaced bytes must be in restore/, found {:?}",
        blob_names(&dir),
    );
    simulate_rm(&dir, &home, "~/.config/tool.toml");
    assert_eq!(
        std::fs::read(home.child(rel)).expect("rm must leave the user's file"),
        users,
    );
}

#[test]
fn a_user_edit_between_two_applies_is_what_rm_restores() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let rel = ".ssh/config";
    home.write(rel, "Host theirs\n");
    std::fs::set_permissions(home.child(rel), std::fs::Permissions::from_mode(0o640))
        .expect("chmod");

    apply(&dir, &lock, &home, rel, b"Host v1\n");
    std::fs::write(home.child(rel), b"Host edited\n").expect("the user edits");
    apply(&dir, &lock, &home, rel, b"Host v2\n");

    simulate_rm(&dir, &home, "~/.ssh/config");
    assert_eq!(
        std::fs::read(home.child(rel)).expect("read"),
        b"Host edited\n",
        "rm restores what the user last had, not what bx displaced first",
    );
    assert!(has_blob(&dir, b"Host theirs\n"), "the original is kept too");
    let view = LedgerView::read(&dir, home.path()).expect("read").value;
    let stored = view.get(&target("~/.ssh/config")).expect("entry");
    assert_eq!(stored.superseded.len(), 1, "the original stays indexed");
    assert_eq!(
        restore::read(&dir, &stored.superseded[0]).expect("restore"),
        b"Host theirs\n",
    );
    assert_eq!(stored.superseded[0].mode, Mode::from_bits(0o640));
}

#[test]
fn repeated_user_edits_are_superseded_in_order_and_an_untouched_apply_adds_nothing() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let rel = ".gitconfig";
    home.write(rel, "original\n");

    apply(&dir, &lock, &home, rel, b"bx 1\n");
    std::fs::write(home.child(rel), b"edit 1\n").expect("edit");
    apply(&dir, &lock, &home, rel, b"bx 2\n");
    let after_edit = std::fs::read(dir.ledger()).expect("read");
    // Nobody touches the file and bx writes the same bytes again: the
    // ledger must come out byte-identical, with no new prior and no history.
    apply(&dir, &lock, &home, rel, b"bx 2\n");
    assert_eq!(std::fs::read(dir.ledger()).expect("read"), after_edit);
    std::fs::write(home.child(rel), b"edit 2\n").expect("edit");
    apply(&dir, &lock, &home, rel, b"bx 3\n");

    let view = LedgerView::read(&dir, home.path()).expect("read").value;
    let stored = view.get(&target("~/.gitconfig")).expect("entry");
    assert_eq!(
        stored.prior,
        Prior::Existed(reference(b"edit 2\n", 0o644)),
        "the prior is the last thing the user had",
    );
    let history: Vec<Vec<u8>> = stored
        .superseded
        .iter()
        .map(|r| restore::read(&dir, r).expect("restore"))
        .collect();
    assert_eq!(history, vec![b"original\n".to_vec(), b"edit 1\n".to_vec()]);

    // The user puts the first edit back; it is the prior again, not history.
    std::fs::write(home.child(rel), b"edit 1\n").expect("edit");
    apply(&dir, &lock, &home, rel, b"bx 4\n");
    let view = LedgerView::read(&dir, home.path()).expect("read").value;
    let stored = view.get(&target("~/.gitconfig")).expect("entry");
    assert_eq!(stored.prior, Prior::Existed(reference(b"edit 1\n", 0o644)));
    assert_eq!(
        stored.superseded,
        vec![
            reference(b"original\n", 0o644),
            reference(b"edit 2\n", 0o644),
        ],
    );
}

/// What a cell's stored prior is.
#[derive(Debug, Clone, Copy)]
enum Stored {
    Absent,
    Existed,
}

/// What a cell's second record is handed.
#[derive(Debug, Clone, Copy)]
enum Incoming {
    /// No file on disk, or a caller that supplied no prior.
    Absent,
    /// The bytes bx left there, untouched.
    BxsOwnOutput,
    /// Bytes nobody but the user could have written.
    UserChanged,
    /// The user put their original bytes back.
    OriginalPutBack,
}

const ORIGINAL: &[u8] = b"the user's original\n";

const BX_V1: &[u8] = b"bx v1\n";

const BX_V2: &[u8] = b"bx v2\n";

const EDIT: &[u8] = b"the user's later edit\n";

/// Record `stored`, then re-record with `incoming`, and return the entry and
/// the blobs on disk.
fn run_cell(stored: Stored, incoming: Incoming) -> (LedgerEntry, Vec<String>) {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let first = match stored {
        Stored::Absent => entry("~/t", BX_V1),
        Stored::Existed => entry("~/t", BX_V1).with_prior(prior(ORIGINAL, 0o640)),
    };
    ledger.record(first).expect("first");
    let second = entry("~/t", BX_V2);
    let second = match incoming {
        Incoming::Absent => second,
        Incoming::BxsOwnOutput => second.with_prior(prior(BX_V1, 0o644)),
        Incoming::UserChanged => second.with_prior(prior(EDIT, 0o600)),
        Incoming::OriginalPutBack => second.with_prior(prior(ORIGINAL, 0o640)),
    };
    let stored = ledger.record(second).expect("second").clone();
    ledger.save().expect("save");
    let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
    assert_eq!(reloaded.get(&target("~/t")), Some(&stored), "round trip");
    (stored, blob_names(&dir))
}

#[test]
fn a_re_record_keeps_or_adopts_the_prior_in_every_cell_of_the_matrix() {
    let cells = [
        (
            Stored::Absent,
            Incoming::Absent,
            Prior::Absent,
            vec![],
            vec![],
        ),
        (
            Stored::Absent,
            Incoming::BxsOwnOutput,
            Prior::Absent,
            vec![],
            vec![],
        ),
        (
            Stored::Absent,
            Incoming::UserChanged,
            Prior::Existed(reference(EDIT, 0o600)),
            vec![],
            vec![hex(EDIT)],
        ),
        (
            Stored::Existed,
            Incoming::Absent,
            Prior::Existed(reference(ORIGINAL, 0o640)),
            vec![],
            vec![hex(ORIGINAL)],
        ),
        (
            Stored::Existed,
            Incoming::BxsOwnOutput,
            Prior::Existed(reference(ORIGINAL, 0o640)),
            vec![],
            vec![hex(ORIGINAL)],
        ),
        (
            Stored::Existed,
            Incoming::UserChanged,
            Prior::Existed(reference(EDIT, 0o600)),
            vec![reference(ORIGINAL, 0o640)],
            sorted(vec![hex(ORIGINAL), hex(EDIT)]),
        ),
        (
            Stored::Existed,
            Incoming::OriginalPutBack,
            Prior::Existed(reference(ORIGINAL, 0o640)),
            vec![],
            vec![hex(ORIGINAL)],
        ),
    ];
    for (stored, incoming, want_prior, want_superseded, want_blobs) in cells {
        let (entry, blobs) = run_cell(stored, incoming);
        let cell = format!("{stored:?} x {incoming:?}");
        assert_eq!(entry.prior, want_prior, "{cell}: prior");
        assert_eq!(entry.superseded, want_superseded, "{cell}: superseded");
        assert_eq!(blobs, want_blobs, "{cell}: restore/");
        // Every blob on disk is reachable from the entry: nothing orphaned.
        let mut reachable: Vec<String> = entry
            .superseded
            .iter()
            .chain(match &entry.prior {
                Prior::Existed(reference) => Some(reference),
                Prior::Absent => None,
            })
            .map(RestoreRef::blob_name)
            .collect();
        reachable.sort();
        reachable.dedup();
        assert_eq!(reachable, blobs, "{cell}: every blob is indexed");
        assert_eq!(entry.written, ContentHash::of(BX_V2), "{cell}: written");
        // Review round 5: a replaced `Absent` is history, not nothing.
        assert_eq!(
            entry.superseded_absent,
            matches!((stored, incoming), (Stored::Absent, Incoming::UserChanged)),
            "{cell}: superseded_absent",
        );
    }
}

#[test]
fn two_targets_with_identical_prior_bytes_share_one_blob() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    for name in ["~/a", "~/b"] {
        ledger
            .record(entry(name, b"x").with_prior(PriorBytes::Bytes {
                bytes: b"same".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }))
            .expect("record");
    }
    let blobs: Vec<_> = std::fs::read_dir(dir.restore())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(blobs.len(), 1, "content addressing means one copy");
}

#[test]
fn recording_the_same_prior_bytes_twice_writes_the_blob_once() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let prior = PriorBytes::Bytes {
        bytes: b"unchanged".to_vec(),
        mode: Mode::DEFAULT_FILE,
    };
    ledger
        .record(entry("~/a", b"x").with_prior(prior.clone()))
        .expect("first");
    let blob = dir.restore().join(ContentHash::of(b"unchanged").to_hex());
    let first = std::fs::metadata(&blob).expect("stat");

    // A second, distinct target displacing identical bytes: the skip is
    // reached through `restore::store_bytes` rather than through
    // first-prior-wins.
    ledger
        .record(entry("~/b", b"y").with_prior(prior))
        .expect("second");
    let second = std::fs::metadata(&blob).expect("stat");
    assert_eq!(
        first.ino(),
        second.ino(),
        "a blob of the right name and length already holds these bytes",
    );
}

#[test]
fn a_prior_that_cannot_be_stored_leaves_every_entry_and_the_saved_ledger_unchanged() {
    // r3 round 1 (C7): a failing blob write inside `record` and
    // `adopt_current_as_prior` was never reached, so the promise that
    // the entry is left unchanged was untested.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.own", b"bx wrote this"))
        .expect("own");
    ledger
        .record(NewEntry::new(
            target("~/.region"),
            ContentHash::of(b"a file with bx's region"),
            Mode::DEFAULT_FILE,
            Mechanism::Region { comment: '#' },
            PriorBytes::Absent,
        ))
        .expect("region");
    ledger.save().expect("save");
    let saved = std::fs::read(dir.ledger()).expect("read");
    let own = ledger.get(&target("~/.own")).expect("own").clone();
    let region = ledger.get(&target("~/.region")).expect("region").clone();

    // A non-empty directory at the blob's name: no rename of a file
    // replaces it, so the write of these bytes fails.
    let user = b"the user changed this";
    let occupied = dir.restore().join(ContentHash::of(user).to_hex());
    std::fs::create_dir_all(occupied.join("keep")).expect("occupy");
    let prior = || PriorBytes::Bytes {
        bytes: user.to_vec(),
        mode: Mode::DEFAULT_FILE,
    };

    let err = ledger
        .record(entry("~/.own", b"bx wrote this").with_prior(prior()))
        .expect_err("a re-record whose prior cannot be stored");
    assert!(matches!(err, Error::Write(_)), "got {err}");
    let err = ledger
        .record(entry("~/.new", b"bx wrote this").with_prior(prior()))
        .expect_err("a first record whose prior cannot be stored");
    assert!(matches!(err, Error::Write(_)), "got {err}");
    let err = ledger
        .adopt_current_as_prior(&target("~/.region"), user, Mode::DEFAULT_FILE)
        .expect_err("an adoption whose bytes cannot be stored");
    assert!(matches!(err, Error::Write(_)), "got {err}");

    assert_eq!(ledger.get(&target("~/.own")), Some(&own));
    assert_eq!(ledger.get(&target("~/.region")), Some(&region));
    assert_eq!(ledger.get(&target("~/.new")), None);
    assert_eq!(ledger.len(), 2);
    ledger.save().expect("save");
    assert_eq!(std::fs::read(dir.ledger()).expect("read"), saved);
    assert!(occupied.join("keep").is_dir(), "what held the name is kept");
}

#[test]
fn a_blob_of_the_wrong_length_is_rewritten_rather_than_trusted() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    // An orphan left by an interrupted write: the right name, the wrong
    // bytes. Trusting the name here loses the user's file, because `record`
    // returns `Ok` and the target is overwritten straight afterwards.
    ensure_dir(&dir.restore(), Mode::PRIVATE_DIR).expect("restore dir");
    let blob = dir
        .restore()
        .join(ContentHash::of(b"the user wrote this").to_hex());
    std::fs::write(&blob, b"").expect("seed an empty orphan");

    let stored = ledger
        .record(
            entry("~/.bashrc", b"bx wrote this").with_prior(PriorBytes::Bytes {
                bytes: b"the user wrote this".to_vec(),
                mode: Mode::DEFAULT_FILE,
            }),
        )
        .expect("record");
    let Prior::Existed(reference) = stored.prior.clone() else {
        panic!("expected a snapshot");
    };

    assert_eq!(
        std::fs::read(&blob).expect("read"),
        b"the user wrote this",
        "the blob must be repaired before `record` returns Ok",
    );
    assert_eq!(
        restore::read(&dir, &reference).expect("restore"),
        b"the user wrote this",
    );
}

#[test]
fn a_truncated_blob_is_repaired_by_the_next_record_of_those_bytes() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let prior = PriorBytes::Bytes {
        bytes: b"the user wrote all of this".to_vec(),
        mode: Mode::DEFAULT_FILE,
    };
    ledger
        .record(entry("~/a", b"x").with_prior(prior.clone()))
        .expect("first");
    let blob = dir
        .restore()
        .join(ContentHash::of(b"the user wrote all of this").to_hex());
    std::fs::write(&blob, b"the user wrote").expect("truncate");

    ledger
        .record(entry("~/b", b"y").with_prior(prior))
        .expect("second");
    assert_eq!(
        std::fs::read(&blob).expect("read"),
        b"the user wrote all of this",
    );
}

#[test]
fn a_decoy_link_at_a_blob_name_is_refused_and_a_decoy_hard_link_replaced_never_trusted() {
    // Review round 3: `blob_len` followed a symlink, so a link at
    // `restore/<digest>` to any file of the same length made `record`
    // return Ok with none of the user's bytes on disk — found only at rm,
    // as RestoreCorrupt. A second hard link was trusted the same way.
    //
    // Stack integration with #8: the writer refuses to replace a symlink
    // anywhere (`fs::Error::Symlink`), state files included. So a symlink
    // decoy is refused, not replaced: `record` fails, stores nothing, and
    // neither the link nor what it names is touched. A hard link is a
    // regular file to the writer, and is still replaced.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    home.write("decoy", "ZZZZZ");
    home.write("other", "YYYYY");
    let link = dir.restore().join(hex(b"prior"));
    std::os::unix::fs::symlink(home.child("decoy"), &link).expect("symlink");
    std::fs::hard_link(home.child("other"), dir.restore().join(hex(b"third"))).expect("hard link");

    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;

    let err = ledger
        .record(entry("~/.a", b"bx").with_prior(prior(b"prior", 0o644)))
        .expect_err("a symlink at the blob name is never trusted");
    assert!(
        matches!(&err, Error::Write(crate::fs::Error::Symlink(path)) if *path == link),
        "{err:?}",
    );
    assert!(
        ledger.get(&target("~/.a")).is_none(),
        "nothing was recorded"
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("stat")
            .file_type()
            .is_symlink(),
        "the link is left where it is",
    );
    assert_eq!(
        std::fs::read_link(&link).expect("readlink"),
        home.child("decoy")
    );

    let stored = ledger
        .record(entry("~/.b", b"bx").with_prior(prior(b"third", 0o644)))
        .expect("record")
        .clone();
    let Prior::Existed(reference) = &stored.prior else {
        panic!("expected a snapshot");
    };
    assert_eq!(restore::read(&dir, reference).expect("restore"), b"third");
    let blob = dir.restore().join(hex(b"third"));
    let meta = std::fs::symlink_metadata(&blob).expect("stat");
    assert!(meta.file_type().is_file(), "the hard link was replaced");
    assert_eq!(meta.nlink(), 1);

    // Neither decoy was written through.
    assert_eq!(std::fs::read(home.child("decoy")).expect("read"), b"ZZZZZ");
    assert_eq!(std::fs::read(home.child("other")).expect("read"), b"YYYYY");
}

#[test]
fn a_restore_blob_that_is_not_bxs_own_file_is_refused_rather_than_read() {
    // r4 round 1 (D5): the read side used plain `std::fs::read`, which
    // follows links and accepts any file type — precisely the entries the
    // write side's `blob_len` refuses to trust. A FIFO there blocked
    // `bx rm` forever inside the read, with no timeout and no diagnostic;
    // a link to an unbounded source allocated until the process died.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/a", b"x").with_prior(prior(b"original", 0o644)))
        .expect("record");
    let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
        panic!("expected a snapshot")
    };
    let reference = reference.clone();
    let blob = dir.restore().join(reference.digest.to_hex());

    home.write("elsewhere", "original");
    for stage in ["symlink", "directory", "fifo"] {
        if blob.is_dir() {
            std::fs::remove_dir(&blob).expect("clear the name");
        } else {
            std::fs::remove_file(&blob).expect("clear the name");
        }
        match stage {
            "symlink" => {
                std::os::unix::fs::symlink(home.child("elsewhere"), &blob).expect("symlink");
            }
            "directory" => std::fs::create_dir(&blob).expect("directory"),
            _ => crate::testing::mkfifo(&blob),
        }

        // In a thread with a deadline: without the fix the FIFO case does
        // not fail, it never returns, and a test that hangs reports
        // nothing. The thread is abandoned if it does hang.
        let (tx, rx) = std::sync::mpsc::channel();
        let (dir_for, reference_for) = (dir.clone(), reference.clone());
        std::thread::spawn(move || {
            let _ = tx.send(format!("{:?}", restore::read(&dir_for, &reference_for)));
        });
        let said = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("restore::read blocked on a {stage}"));
        assert!(said.starts_with("Err(RestoreNotAFile"), "{stage}: {said}");
        // And what the entry named was never read through.
        assert_eq!(
            std::fs::read(home.child("elsewhere")).expect("read"),
            b"original",
        );
    }
}

#[test]
fn a_hard_linked_restore_blob_is_still_restored() {
    // r4 round 2 (CL6): the read side repeated the write side's
    // `st_nlink == 1` test, where it can only reject. A hard-linking
    // deduplicator or backup tool run over `$HOME` raises `nlink` on an
    // intact blob, and `bx rm` then refused to restore the user's own
    // prior bytes though they were present and verifiable. Integrity is
    // settled by the digest; `nlink` says nothing about it.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/a", b"x").with_prior(prior(b"original", 0o644)))
        .expect("record");
    let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
        panic!("expected a snapshot")
    };
    let reference = reference.clone();
    let blob = dir.restore().join(reference.digest.to_hex());

    std::fs::hard_link(&blob, home.child("deduplicated")).expect("hard link");
    assert_eq!(
        std::fs::metadata(&blob).expect("stat").nlink(),
        2,
        "the blob now has a second name",
    );
    assert_eq!(
        restore::read(&dir, &reference).expect("restore"),
        b"original",
    );
}

#[test]
fn a_restore_blob_of_the_wrong_length_is_refused_before_it_is_read() {
    // r4 round 2 (D3): the read was an unbounded `read_to_end` although
    // the reference already held the expected length and the descriptor
    // had been `fstat`ed. A regular, single-linked file of any size at
    // `restore/<digest>` was allocated whole before the digest could
    // reject it — the "allocate until the process is killed" failure the
    // function's own preamble claims to close.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/a", b"x").with_prior(prior(b"original", 0o644)))
        .expect("record");
    let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
        panic!("expected a snapshot")
    };
    let reference = reference.clone();
    assert_eq!(reference.len, 8, "`original`");

    let blob = dir.restore().join(reference.digest.to_hex());
    std::fs::write(&blob, vec![b'z'; 4 << 20]).expect("a big decoy at the name");
    let err = restore::read(&dir, &reference).expect_err("must refuse");
    assert!(
        matches!(&err, Error::RestoreCorrupt { path, .. } if *path == blob),
        "got {err}",
    );
}

#[test]
fn a_directory_at_a_blob_name_fails_the_write_rather_than_being_skipped() {
    // r4 round 2 (COV7): `restore::store_bytes` with something at the blob name that
    // `blob_len` will not measure — so the skip does not fire — and that
    // the rename cannot replace. `a_restore_directory_that_cannot_be_
    // created_is_reported` covers `ensure_dir` failing, which is a
    // different arm.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    std::fs::create_dir_all(dir.restore()).expect("restore/");
    let name = dir.restore().join(ContentHash::of(b"original").to_hex());
    std::fs::create_dir(&name).expect("a directory at the blob name");

    let err = ledger
        .record(entry("~/a", b"x").with_prior(prior(b"original", 0o644)))
        .expect_err("must fail");
    assert!(matches!(&err, Error::Write(_)), "got {err}");
    assert!(name.is_dir(), "left exactly as it was");
    assert!(ledger.get(&target("~/a")).is_none(), "nothing recorded");
}

#[test]
fn a_tampered_restore_blob_is_refused_rather_than_returned() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
            bytes: b"original".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("record");
    let blob = dir.restore().join(ContentHash::of(b"original").to_hex());
    std::fs::write(&blob, b"tampered").expect("tamper");

    let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
        panic!("expected a snapshot")
    };
    let err = restore::read(&dir, reference).expect_err("must refuse");
    assert!(matches!(err, Error::RestoreCorrupt { .. }), "got {err}");
}

#[test]
fn a_missing_restore_blob_is_reported_by_digest() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
            bytes: b"gone".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("record");
    let digest = ContentHash::of(b"gone");
    std::fs::remove_file(dir.restore().join(digest.to_hex())).expect("remove");

    let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
        panic!("expected a snapshot")
    };
    let err = restore::read(&dir, reference).expect_err("must report");
    assert!(matches!(err, Error::RestoreMissing { .. }), "got {err}");
    assert!(err.to_string().contains(&digest.to_hex()));
}

#[test]
fn an_unreadable_restore_blob_is_reported() {
    if rustix::process::geteuid().is_root() {
        // Mode bits deny nothing to root, so the condition cannot be staged.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
            bytes: b"body".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("record");
    let digest = ContentHash::of(b"body");
    let blob = dir.restore().join(digest.to_hex());
    // A regular file nobody may open: unreadable, as against a name
    // occupied by something that is not a snapshot at all, which is
    // `Error::RestoreNotAFile`.
    std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o000)).expect("seal");

    let Prior::Existed(reference) = &ledger.get(&target("~/a")).expect("entry").prior else {
        panic!("expected a snapshot")
    };
    let err = restore::read(&dir, reference).expect_err("must report");
    assert!(matches!(err, Error::Read { .. }), "got {err}");
}

#[test]
fn record_refuses_a_path_the_next_open_under_the_same_home_would_refuse() {
    // Review round 4's falsifier: `record` accepted `/<home>/.gitconfig`
    // built through `Portable::try_from`, `save` wrote it, and every later
    // `open` under that home refused the ledger, with no way back.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.bashrc", b"bx").with_prior(prior(b"mine", 0o644)))
        .expect("an ordinary record");
    ledger.save().expect("save");
    let saved = std::fs::read(dir.ledger()).expect("read");
    let blobs = blob_names(&dir);

    let foreign_key = absolute_under(&home, ".gitconfig");
    let foreign_dir = absolute_under(&home, ".config/tool");
    let cases = [
        (
            NewEntry::new(
                foreign_key.clone(),
                ContentHash::of(b"bx"),
                Mode::DEFAULT_FILE,
                Mechanism::Own,
                prior(b"the user's gitconfig", 0o644),
            ),
            foreign_key,
        ),
        (
            entry("~/.config/tool/x.conf", b"bx")
                .with_prior(prior(b"the user's tool config", 0o644))
                .with_created_dirs(vec![foreign_dir.clone()]),
            foreign_dir,
        ),
    ];
    for (new, refused) in cases {
        let checked = ledger.check_record(&new).expect_err("check refuses");
        let recorded = ledger.record(new).expect_err("record refuses");
        for err in [checked, recorded] {
            assert!(
                matches!(
                    &err,
                    Error::ForeignRecord { home: at, stored, .. }
                        if at == home.path() && *stored == refused.as_str()
                ),
                "got {err}",
            );
            assert!(err.to_string().contains("Nothing was recorded"), "{err}");
        }
    }

    // Nothing entered the ledger, nothing reached `restore/`, and the
    // ledger still opens under the home it was opened with.
    assert_eq!(ledger.len(), 1);
    assert_eq!(blob_names(&dir), blobs);
    ledger.save().expect("save");
    assert_eq!(std::fs::read(dir.ledger()).expect("read"), saved);
    let reopened = Ledger::open(&dir, &lock, home.path()).expect("still opens");
    assert_eq!(reopened.health, Health::Loaded);
}

#[test]
fn check_record_refuses_exactly_what_record_refuses_and_stores_nothing() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let region = Mechanism::Region { comment: '#' };
    let bx1: &[u8] = b"user\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
    let at = |written: &[u8], before: &[u8]| {
        NewEntry::new(
            target("~/.bashrc"),
            ContentHash::of(written),
            Mode::DEFAULT_FILE,
            region.clone(),
            prior(before, 0o644),
        )
    };
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .check_record(&at(bx1, b"user\n"))
        .expect("a new target");
    ledger.record(at(bx1, b"user\n")).expect("record");
    let blobs = blob_names(&dir);

    let edited = at(b"BX2", b"user\n# >>> bx >>>\nBX1\n# <<< bx <<<\nedit\n");
    let err = (*ledger)
        .check_record(&edited)
        .expect_err("the view refuses");
    assert!(matches!(err, Error::PriorConflict { .. }), "got {err}");
    let err = ledger
        .check_record(&edited)
        .expect_err("the ledger refuses");
    assert!(matches!(err, Error::PriorConflict { .. }), "got {err}");
    let err = ledger.record(edited).expect_err("record refuses");
    assert!(matches!(err, Error::PriorConflict { .. }), "got {err}");
    assert_eq!(blob_names(&dir), blobs, "nothing was stored");

    ledger
        .check_record(&at(b"BX2", bx1))
        .expect("bx's own output");
    ledger.record(at(b"BX2", bx1)).expect("record");
}

#[test]
fn accepting_a_changed_shared_file_converges_and_keeps_the_first_original() {
    // Review round 4: `PriorConflict` fires on any edit outside bx's
    // region, its message named no remedy, and re-recording converged
    // nowhere.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let region = Mechanism::Region { comment: '#' };
    let original: &[u8] = b"user line 1\n";
    let bx1: &[u8] = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
    let edited: &[u8] = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\nuser line 2\n";
    let bx2: &[u8] = b"user line 1\n# >>> bx >>>\nBX2\n# <<< bx <<<\nuser line 2\n";
    let apply = |written: &[u8], before: &[u8]| {
        NewEntry::new(
            target("~/.bashrc"),
            ContentHash::of(written),
            Mode::DEFAULT_FILE,
            region.clone(),
            prior(before, 0o644),
        )
    };
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger.record(apply(bx1, original)).expect("first apply");

    // The edit: a conflict, every time, whose message names both ways out.
    for _ in 0..2 {
        let message = ledger
            .record(apply(bx2, edited))
            .expect_err("a conflict")
            .to_string();
        assert!(message.contains("put the file back"), "{message}");
        assert!(
            message.contains("accept the file as it is now"),
            "{message}"
        );
    }

    // The user accepts the file as it is now.
    let accepted = ledger
        .adopt_current_as_prior(&target("~/.bashrc"), edited, Mode::from_bits(0o640))
        .expect("adopt")
        .expect("an entry")
        .clone();
    assert_eq!(accepted.written, ContentHash::of(edited));
    assert_eq!(accepted.prior, Prior::Existed(reference(edited, 0o640)));
    assert_eq!(
        accepted.superseded,
        vec![reference(original, 0o644)],
        "the first original is kept, not dropped",
    );
    assert_eq!(accepted.mechanism, region);
    assert!(has_blob(&dir, edited) && has_blob(&dir, original));

    // Accepting the same file again changes nothing.
    ledger
        .adopt_current_as_prior(&target("~/.bashrc"), edited, Mode::from_bits(0o640))
        .expect("adopt again");
    assert_eq!(ledger.get(&target("~/.bashrc")), Some(&accepted));

    // The next apply converges: no conflict, and the accepted prior stands.
    let stored = ledger
        .record(apply(bx2, edited))
        .expect("the next apply records")
        .clone();
    assert_eq!(stored.written, ContentHash::of(bx2));
    assert_eq!(stored.prior, accepted.prior);
    assert_eq!(stored.superseded, accepted.superseded);
    ledger.save().expect("save");
    let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
    assert_eq!(reloaded.get(&target("~/.bashrc")), Some(&stored));

    // A target bx does not record is not invented.
    assert!(
        ledger
            .adopt_current_as_prior(&target("~/.zshrc"), edited, Mode::DEFAULT_FILE)
            .expect("adopt")
            .is_none()
    );
    assert!(ledger.get(&target("~/.zshrc")).is_none());
}

#[test]
fn accepting_a_file_bx_created_keeps_that_there_was_no_file_before_bx() {
    // Review round 5: `supersede` kept only `RestoreRef`s, so accepting a
    // file whose stored prior was `Absent` dropped that fact. bx creates
    // `~/.zshrc` holding only its include line, the user adds an alias,
    // and after accepting the entry read exactly like a file the user had
    // all along — while the conflict message said the original was kept.
    let include = Mechanism::Include {
        line: "source ~/.local/state/bx/shell/init.zsh".to_string(),
    };
    let created: &[u8] = b"source ~/.local/state/bx/shell/init.zsh\n";
    let edited: &[u8] = b"source ~/.local/state/bx/shell/init.zsh\nalias ll='ls -l'\n";
    let zshrc = target("~/.zshrc");
    let record = |written: &[u8]| {
        NewEntry::new(
            zshrc.clone(),
            ContentHash::of(written),
            Mode::DEFAULT_FILE,
            include.clone(),
            PriorBytes::Absent,
        )
    };

    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger.record(record(created)).expect("bx creates the file");
    let err = ledger
        .record(record(created).with_prior(prior(edited, 0o644)))
        .expect_err("the alias is a conflict");
    assert!(matches!(err, Error::PriorConflict { .. }), "got {err}");
    let accepted = ledger
        .adopt_current_as_prior(&zshrc, edited, Mode::DEFAULT_FILE)
        .expect("adopt")
        .expect("an entry")
        .clone();

    // The same bytes on a file the user had before bx ever wrote it.
    let other = guarded_home();
    let (other_dir, other_lock) = locked(&other);
    let mut all_along = Ledger::open(&other_dir, &other_lock, other.path())
        .expect("open")
        .value;
    let had = all_along
        .record(record(edited).with_prior(prior(edited, 0o644)))
        .expect("record")
        .clone();
    assert_eq!(accepted.prior, had.prior, "both restore the accepted bytes");
    assert_ne!(
        accepted, had,
        "a file bx created must not read, once accepted, as one the user had all along",
    );
    assert!(accepted.superseded_absent, "that there was no file is kept");
    assert!(
        accepted.superseded.is_empty(),
        "and no snapshot is invented"
    );
    assert!(!had.superseded_absent);

    // The next apply converges and keeps it, and so does a save.
    let stored = ledger
        .record(record(edited).with_prior(prior(edited, 0o644)))
        .expect("the next apply records")
        .clone();
    assert!(stored.superseded_absent);
    assert_eq!(stored.prior, accepted.prior);
    ledger.save().expect("save");
    let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
    assert_eq!(reloaded.get(&zshrc), Some(&stored));
}

#[test]
fn a_prior_conflict_says_plainly_what_accepting_leaves_behind() {
    // Review round 5: accepting a region or include file makes `bx rm`
    // write bx's stale lines back, unmanaged, and the message did not say
    // so.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let region = Mechanism::Region { comment: '#' };
    let bx1: &[u8] = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
    let edited: &[u8] = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\nuser line 2\n";
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let apply = |before: &[u8]| {
        NewEntry::new(
            target("~/.bashrc"),
            ContentHash::of(bx1),
            Mode::DEFAULT_FILE,
            region.clone(),
            prior(before, 0o644),
        )
    };
    ledger.record(apply(b"user line 1\n")).expect("first apply");
    let message = ledger
        .record(apply(edited))
        .expect_err("a conflict")
        .to_string();
    for needle in [
        "put the file back",
        "accept the file as it is now",
        "write them back stale",
        "no longer manages them",
        "remove them by hand",
        "or that there was none",
    ] {
        assert!(message.contains(needle), "missing {needle:?}: {message}");
    }
}

#[test]
fn a_lock_file_replaced_while_held_stops_every_write_through_the_ledger() {
    // Review round 5: an outside `mv` of the lock file while it was held
    // let a second bx lock a new file, and `record` and `save` never looked
    // again. The refusal also named the same path twice.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger.record(entry("~/a", b"x")).expect("record");
    ledger.save().expect("save");
    let saved = std::fs::read(dir.ledger()).expect("read");

    std::fs::rename(dir.lock(), home.child("moved-lock")).expect("an outside mv");
    let _second = ExclusiveLock::acquire(&dir).expect("a second writer locks a new file");
    let replaced = |err: &Error| {
        let message = err.to_string();
        let lock_path = dir.lock().display().to_string();
        matches!(err, Error::WrongLock { held, needed } if *held == dir.lock() && *needed == dir.lock())
            && message.contains("was replaced or removed while")
            && message.matches(&lock_path).count() == 1
    };

    let err = ledger
        .record(entry("~/b", b"y").with_prior(prior(b"mine", 0o644)))
        .expect_err("record refuses");
    assert!(replaced(&err), "got {err}");
    assert!(ledger.get(&target("~/b")).is_none());
    assert!(!has_blob(&dir, b"mine"), "nothing was stored");
    let err = ledger
        .adopt_current_as_prior(&target("~/a"), b"changed", Mode::DEFAULT_FILE)
        .expect_err("accepting refuses");
    assert!(replaced(&err), "got {err}");
    let err = ledger.save().expect_err("save refuses");
    assert!(replaced(&err), "got {err}");
    assert_eq!(std::fs::read(dir.ledger()).expect("read"), saved);
    let err = Fingerprints::default()
        .save(&dir, &lock)
        .expect_err("the cache refuses too");
    assert!(replaced(&err), "got {err}");
}

#[test]
fn a_changed_shared_file_is_a_conflict_not_a_prior_holding_bxs_own_lines() {
    // Review round 3. Region BX1, the user adds a line outside it, and the
    // next apply hands `record` the whole file. Adopting it stored BX1's
    // region as the user's original, and `bx rm` then wrote bx's stale
    // region back into the user's file.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let original = b"user line 1\n";
    let bx1 = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
    let mut edited = bx1.to_vec();
    edited.extend_from_slice(b"user line 2\n");
    let region = Mechanism::Region { comment: '#' };
    let include = Mechanism::Include {
        line: "source ~/.local/state/bx/shell/init.sh".to_string(),
    };
    // Either side of the re-record being shared is enough: the bytes on disk
    // hold what the stored mechanism wrote, and the prior is read back
    // under the incoming one.
    let cases = [
        (region.clone(), region.clone()),
        (include.clone(), include),
        (Mechanism::Own, region.clone()),
        (region, Mechanism::Own),
    ];
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    for (index, (first, second)) in cases.into_iter().enumerate() {
        let name = format!("~/.rc{index}");
        ledger
            .record(NewEntry::new(
                target(&name),
                ContentHash::of(bx1),
                Mode::DEFAULT_FILE,
                first,
                prior(original, 0o644),
            ))
            .expect("first apply");
        ledger.save().expect("save");
        let saved = std::fs::read(dir.ledger()).expect("read");
        let blobs = blob_names(&dir);

        let err = ledger
            .record(NewEntry::new(
                target(&name),
                ContentHash::of(b"BX2"),
                Mode::DEFAULT_FILE,
                second,
                prior(&edited, 0o644),
            ))
            .expect_err("a changed shared file is a conflict");
        assert!(
            matches!(
                &err,
                Error::PriorConflict { target: at, displaced }
                    if *at == name && *displaced == ContentHash::of(&edited)
            ),
            "case {index}: got {err}",
        );
        assert!(err.to_string().contains(&name), "{err}");

        // Nothing was adopted or stored, and the prior holds no bx region.
        let stored = ledger.get(&target(&name)).expect("entry");
        assert_eq!(stored.written, ContentHash::of(bx1));
        assert!(stored.superseded.is_empty());
        let Prior::Existed(reference) = &stored.prior else {
            panic!("case {index}: the original prior must stand");
        };
        assert_eq!(restore::read(&dir, reference).expect("restore"), original,);
        assert!(!has_blob(&dir, &edited), "case {index}");
        assert_eq!(blob_names(&dir), blobs, "case {index}");
        ledger.save().expect("save");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), saved);
    }
}

#[test]
fn an_untouched_shared_file_still_re_records_and_keeps_its_prior() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let bx1 = b"user line 1\n# >>> bx >>>\nBX1\n# <<< bx <<<\n";
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let region = Mechanism::Region { comment: '#' };
    ledger
        .record(NewEntry::new(
            target("~/.bashrc"),
            ContentHash::of(bx1),
            Mode::DEFAULT_FILE,
            region.clone(),
            prior(b"user line 1\n", 0o644),
        ))
        .expect("first");
    let stored = ledger
        .record(NewEntry::new(
            target("~/.bashrc"),
            ContentHash::of(b"BX2"),
            Mode::DEFAULT_FILE,
            region,
            prior(bx1, 0o644),
        ))
        .expect("bx's own output is not a conflict")
        .clone();
    assert_eq!(stored.written, ContentHash::of(b"BX2"));
    assert_eq!(
        stored.prior,
        Prior::Existed(reference(b"user line 1\n", 0o644))
    );
}

#[test]
fn the_ledger_survives_a_save_and_reload() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger.record(entry("~/a", b"x")).expect("record");
    ledger.save().expect("save");

    let reopened = Ledger::open(&dir, &lock, home.path()).expect("open");
    assert_eq!(reopened.health, Health::Loaded);
    assert_eq!(reopened.value.len(), 1);
    assert_eq!(reopened.value.dir(), &dir);
}

#[test]
fn saving_the_ledger_twice_produces_identical_bytes() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger.record(entry("~/b", b"x")).expect("record");
    ledger.record(entry("~/a", b"y")).expect("record");
    ledger.save().expect("first");
    let first = std::fs::read(dir.ledger()).expect("read");
    ledger.save().expect("second");
    assert_eq!(std::fs::read(dir.ledger()).expect("read"), first);

    // And the obligation `store::save` states on every payload type, so a
    // later field that iterates in hash order fails here.
    //
    // The closure *builds* a view rather than cloning one. A clone carries
    // the original's hasher and its table layout, so two clones of one
    // `HashMap` iterate identically and a hash-ordered payload passed the
    // assertion this call exists to fail (r4 round 2, D1/COV2). Sixty-four
    // keys, not two, because two independently built hash maps of two keys
    // agree half the time.
    store::assert_saves_identically(KIND, VERSION, || {
        let mut built = LedgerView::default();
        for n in 0..64_u8 {
            let path = target(&format!("~/k{n}"));
            built.entries.insert(
                path.clone(),
                LedgerEntry {
                    path,
                    written: ContentHash::of(&[n]),
                    mode: Mode::DEFAULT_FILE,
                    mechanism: Mechanism::Own,
                    prior: Prior::Absent,
                    created_dirs: Vec::new(),
                    superseded: Vec::new(),
                    superseded_absent: false,
                },
            );
        }
        built
    });
}

#[test]
fn re_adopting_the_stored_prior_leaves_it_the_prior_and_not_history() {
    // r4 round 1 (COV7): the one path where `supersede`'s push-then-retain
    // has to cancel out — the bytes being adopted are the exact bytes
    // already stored as the prior — was reached by no test. Without the
    // `retain`, the blob would be both the prior and a superseded entry,
    // and `bx rm` would index one snapshot twice.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.bashrc", b"bx wrote this").with_prior(prior(b"the original", 0o644)))
        .expect("record");

    // The user puts the original back, and it is accepted as it is now.
    let stored = ledger
        .adopt_current_as_prior(&target("~/.bashrc"), b"the original", Mode::DEFAULT_FILE)
        .expect("adopt")
        .expect("an entry")
        .clone();

    let Prior::Existed(reference) = &stored.prior else {
        panic!("expected a snapshot, got {:?}", stored.prior)
    };
    assert_eq!(reference.digest, ContentHash::of(b"the original"));
    assert!(
        stored.superseded.is_empty(),
        "the prior is the prior, not also history: {:?}",
        stored.superseded,
    );
    assert!(!stored.superseded_absent);
    assert_eq!(stored.written, ContentHash::of(b"the original"));
}

#[test]
fn a_restore_directory_that_cannot_be_created_is_reported() {
    // r4 round 1 (COV7): `Ledger::store_restore`'s `Error::CreateDir` arm — the
    // `ensure_dir` of `restore/` failing — was reached by no test.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    std::fs::remove_dir(dir.restore()).expect("clear the name");
    std::fs::write(dir.restore(), b"not a directory").expect("occupy it");

    let err = ledger
        .record(entry("~/a", b"x").with_prior(prior(b"the user wrote this", 0o644)))
        .expect_err("must fail");
    assert!(
        matches!(&err, Error::NotADirectory { path } if *path == dir.restore()),
        "got {err}",
    );
    assert!(ledger.is_empty(), "nothing was recorded");
}

#[test]
fn forgetting_a_target_leaves_its_restore_blob_in_place() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/a", b"x").with_prior(PriorBytes::Bytes {
            bytes: b"kept".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("record");
    let forgotten = ledger.forget(&target("~/a")).expect("an entry to forget");
    assert_eq!(forgotten.path, target("~/a"));
    assert!(ledger.is_empty());
    assert!(ledger.forget(&target("~/a")).is_none());
    assert!(
        dir.restore()
            .join(ContentHash::of(b"kept").to_hex())
            .exists(),
    );
}

#[test]
fn directories_bx_created_are_recorded_deepest_first() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let dirs = vec![target("~/.config/tool/sub"), target("~/.config/tool")];
    ledger
        .record(entry("~/.config/tool/sub/f", b"x").with_created_dirs(dirs.clone()))
        .expect("record");
    ledger.save().expect("save");

    let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
    assert_eq!(
        reloaded
            .get(&target("~/.config/tool/sub/f"))
            .expect("entry")
            .created_dirs,
        dirs,
    );
}

#[test]
fn a_first_record_normalises_the_directories_it_is_handed() {
    // r4 round 1 (COV3, CL8): a FIRST record stored `created_dirs`
    // verbatim, trusting `with_created_dirs`'s documented "deepest first"
    // and validating it nowhere, while every re-record sorted and
    // deduplicated. A caller handing them over shallowest-first had the
    // fault silently corrected from the second apply on and not the first,
    // so `bx rm` left a directory behind for a target applied exactly
    // once. The test that was here handed in an already-sorted list and
    // asserted round-trip equality, so it passed identically either way.
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let stored = ledger
        .record(entry("~/.config/tool/sub/f", b"x").with_created_dirs(vec![
            target("~/.config"),
            target("~/.config/tool/sub"),
            target("~/.config"),
            target("~/.config/tool"),
        ]))
        .expect("record")
        .clone();
    assert_eq!(
        stored.created_dirs,
        vec![
            target("~/.config/tool/sub"),
            target("~/.config/tool"),
            target("~/.config"),
        ],
        "deepest first, deduplicated, on the first record too",
    );
}

#[test]
fn a_re_record_keeps_the_directories_an_earlier_apply_created() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let file = "~/.config/newdir/x.conf";
    let dirs = vec![target("~/.config/newdir"), target("~/.config")];

    // Apply #1 invents both parents.
    ledger
        .record(entry(file, b"v1").with_created_dirs(dirs.clone()))
        .expect("first");
    // Apply #2: the parents exist now, so the writer reports none created.
    ledger.record(entry(file, b"v2")).expect("second");
    assert_eq!(
        ledger.get(&target(file)).expect("entry").created_dirs,
        dirs,
        "`bx rm` must still know which directories bx invented",
    );

    // Apply #3 re-creates one it had already recorded: no duplicate.
    ledger
        .record(entry(file, b"v3").with_created_dirs(vec![target("~/.config/newdir")]))
        .expect("third");
    assert_eq!(ledger.get(&target(file)).expect("entry").created_dirs, dirs);

    ledger.save().expect("save");
    let reloaded = LedgerView::read(&dir, home.path()).expect("read").value;
    assert_eq!(
        reloaded.get(&target(file)).expect("entry").created_dirs,
        dirs
    );
}

#[test]
fn directories_merged_across_re_records_stay_deepest_first() {
    let home = guarded_home();
    let (dir, lock) = locked(&home);
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    let file = "~/.config/newdir/x.conf";

    // Apply #1 invents only `~/.config`; `newdir` was there already.
    ledger
        .record(entry(file, b"v1").with_created_dirs(vec![target("~/.config")]))
        .expect("first");
    // Later `newdir` is gone and apply #2 invents it: deeper than the one
    // already recorded, so appending it would break the removal order.
    ledger
        .record(entry(file, b"v2").with_created_dirs(vec![target("~/.config/newdir")]))
        .expect("second");
    assert_eq!(
        ledger.get(&target(file)).expect("entry").created_dirs,
        vec![target("~/.config/newdir"), target("~/.config")],
    );
}

#[test]
fn nothing_outside_the_state_directory_is_created() {
    let home = guarded_home();
    let before = walk(home.path());

    let dir = StateDir::resolve(home.path());
    dir.ensure().expect("ensure");
    let lock = ExclusiveLock::acquire(&dir).expect("acquire");
    let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
    ledger
        .record(entry("~/.bashrc", b"x").with_prior(PriorBytes::Bytes {
            bytes: b"prior".to_vec(),
            mode: Mode::DEFAULT_FILE,
        }))
        .expect("record");
    ledger.save().expect("save");
    let mut fingerprints = Fingerprints::read(&dir).expect("read").value;
    fingerprints.set("activation:rustup", Fingerprint::hashed(b"v1"));
    fingerprints.save(&dir, &lock).expect("save");

    // r4 round 1 (D3): this asserted `starts_with(home/".local")`, two
    // components shallower than the state directory, so it admitted the
    // whole of `~/.local` — `~/.local/share/bx-cache`, `~/.local/bin`, or
    // another tool's `~/.local/state/<tool>` — while its name and the
    // body's claim both say "the state directory". The two XDG ancestors
    // `ensure_dir` creates are the sole exception, and they are named
    // rather than admitted by prefix.
    let ancestors = [home.child(".local"), home.child(".local/state")];
    for path in walk(home.path()) {
        if before.contains(&path) || ancestors.contains(&path) {
            continue;
        }
        assert!(
            path.starts_with(dir.root()),
            "{} was created outside the state directory",
            path.display(),
        );
    }
}

/// Every path under `root`, recursively.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        }
        out.push(path);
    }
    out.sort();
    out
}
