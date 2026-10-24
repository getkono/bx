use super::*;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use super::capture::capturing;
use crate::state::StateDir;
use crate::testing::mkfifo;

/// A state file's path in a fresh tempdir, which holds nothing yet.
fn state_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.mpk");
    (dir, path)
}

const KIND: &str = "bx.test";
const OTHER: &str = "bx.other";
const VERSION: u16 = 3;

type Value = BTreeMap<String, u32>;

/// [`load`] under the exclusive lock of `path`'s directory, as a writer does.
fn locked_load<T: DeserializeOwned + Default>(path: &Path) -> Result<Loaded<T>, Error> {
    let dir = StateDir::new(path.parent().expect("a parent").to_path_buf());
    let lock = ExclusiveLock::acquire(&dir).expect("lock");
    load(path, KIND, VERSION, Loss::Recomputable, Some(&lock))
}

/// Every name in `dir` but the lock file, sorted.
fn names_but_the_lock(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name != "lock")
        .collect();
    names.sort();
    names
}

fn sample() -> Value {
    let mut map = Value::new();
    map.insert("alpha".into(), 1);
    map.insert("beta".into(), 2);
    map
}

fn encoded(kind: &str, version: u16, payload: &Value) -> Vec<u8> {
    rmp_serde::to_vec_named(&Envelope {
        kind: kind.to_string(),
        version,
        payload,
    })
    .expect("encode")
}

#[test]
fn what_a_file_holds_decides_its_health_and_damage_degrades_to_empty() {
    // Each damage's text is pinned whole by
    // `every_damage_says_what_is_wrong_with_the_file`.
    let whole = encoded(KIND, VERSION, &sample());
    let mut trailing = whole.clone();
    trailing.extend_from_slice(b"\x00\x00leftovers");
    let future = Damage::FutureVersion {
        found: VERSION + 5,
        supported: VERSION,
    };
    let wrong_kind = Damage::WrongKind {
        found: OTHER.to_string(),
    };
    for (what, seed, health) in [
        ("missing", None, Health::Fresh),
        (
            "older",
            Some(encoded(KIND, VERSION - 1, &sample())),
            Health::Loaded,
        ),
        (
            "truncated",
            Some(whole[..whole.len() / 2].to_vec()),
            Health::Reset(Damage::Malformed),
        ),
        (
            "garbage",
            Some(b"this is certainly not MessagePack".to_vec()),
            Health::Reset(Damage::Malformed),
        ),
        (
            "trailing",
            Some(trailing),
            Health::Reset(Damage::TrailingBytes),
        ),
        (
            "future",
            Some(encoded(KIND, VERSION + 5, &sample())),
            Health::Reset(future),
        ),
        (
            "wrong kind",
            Some(encoded(OTHER, VERSION, &sample())),
            Health::Reset(wrong_kind),
        ),
    ] {
        let (_dir, path) = state_file();
        if let Some(seed) = &seed {
            std::fs::write(&path, seed).expect("seed");
        }
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        let damage = match &health {
            Health::Reset(damage) => Some(damage.clone()),
            _ => None,
        };
        let value = if health == Health::Loaded {
            sample()
        } else {
            Value::new()
        };
        assert_eq!(loaded.health, health, "{what}");
        assert_eq!(loaded.value, value, "{what}");
        assert_eq!(loaded.health.is_reset(), damage.is_some(), "{what}");
        assert_eq!(loaded.health.damage(), damage.as_ref(), "{what}");
    }
}

#[test]
fn a_round_trip_returns_the_same_value() {
    let (_dir, path) = state_file();
    save(&path, KIND, VERSION, &sample()).expect("save");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(loaded.health, Health::Loaded);
    assert_eq!(loaded.value, sample());
}

#[test]
fn saving_the_same_value_twice_produces_identical_bytes() {
    assert_saves_identically(KIND, VERSION, sample);
}

// The determinism obligation is carried by two mechanisms, and each of the
// three tests below fails when *only its own* mechanism is removed. Until
// r4 round 4 one test stood for both: its 128-key `HashMap` payload tripped
// inside `save` before the helper's comparison ran, so neutering either
// mechanism alone left the suite green and only their disjunction was
// tested (r4 round 4, COV1).

#[test]
fn the_re_encode_count_is_what_makes_detection_certain() {
    // r4 round 5 (COV1): `REENCODES` was a constant nothing defended. The
    // suite was green at `REENCODES = 1`, where a two-key `HashMap` is
    // missed 56% of the time — so the intermittency the previous round
    // removed was one edit from coming back, and the 300/300 measurement
    // that justified 32 lived in a report rather than in the suite.
    //
    // This measures instead of restating. Each trial encodes a freshly
    // built two-key map — the worst case, and the only size where one
    // comparison is close to a coin toss — and asks the verdict function
    // whether it looks deterministic. For a `HashMap` the honest answer is
    // always "no", so every `true` is a miss.
    //
    // Why it is not flaky, and why it fails at 1. A round misses with
    // probability 0.56, and the rounds are independent because each decodes
    // the original bytes afresh. At `REENCODES = 32` a trial misses with
    // `0.56^32` ≈ 8.75e-9, so 64 trials fail this assertion with
    // probability about 5.6e-7 — once in two million runs. At
    // `REENCODES = 1` a trial misses with probability 0.56, so 64 trials
    // pass with probability `0.44^64` ≈ 1e-23: it fails every time.
    const TRIALS: usize = 64;
    let mut missed = 0;
    for _ in 0..TRIALS {
        let two: std::collections::HashMap<String, u32> =
            [("a".to_string(), 1), ("b".to_string(), 2)]
                .into_iter()
                .collect();
        let bytes = rmp_serde::to_vec_named(&Envelope {
            kind: KIND.to_string(),
            version: VERSION,
            payload: &two,
        })
        .expect("encode");
        if reencodes_identically::<std::collections::HashMap<String, u32>>(&bytes, KIND) {
            missed += 1;
        }
    }
    assert_eq!(
        missed, 0,
        "{missed} of {TRIALS} two-key hash-ordered payloads went undetected; REENCODES is \
             {REENCODES} and has to be large enough that they do not",
    );
}

#[test]
#[should_panic(expected = "decoding it and encoding it again gives different bytes")]
fn a_hash_ordered_payload_is_refused_by_saves_own_check() {
    // `save` alone, with no helper in the picture: one value, saved once.
    // The helper cannot make this pass or fail.
    let dir = tempfile::tempdir().expect("tempdir");
    let hashed: std::collections::HashMap<String, u32> =
        (0..128_u32).map(|n| (format!("k{n}"), n)).collect();
    let _ = save(&dir.path().join("v.mpk"), KIND, VERSION, &hashed);
}

#[test]
#[should_panic(expected = "two independently built values")]
fn the_two_construction_assertion_refuses_an_order_dependent_sequence() {
    // The helper alone: a payload `save`'s check *accepts* and two
    // independent builds differ on. A `Vec` drained from a `HashSet` is in
    // hash order, but it decodes in its stored order and re-encodes
    // identically, so no number of re-encodings inside `save` can see it —
    // while two builds of it are two different orders, which is the
    // Invariant 3 breach. This is the class that makes the second
    // mechanism necessary rather than redundant (r4 round 4, D1).
    #[derive(Serialize, Deserialize)]
    struct Ordered {
        order: Vec<String>,
    }
    assert_saves_identically(KIND, VERSION, || Ordered {
        order: (0..64_u32)
            .map(|n| format!("k{n}"))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect(),
    });
}

#[test]
#[should_panic(expected = "does not decode the bytes it just encoded")]
fn a_payload_whose_encoding_it_cannot_read_back_is_refused() {
    // r4 round 4 (COV3): the decode arm of `save`'s own check was reached
    // by nothing, so a mutant turning the panic into a silent `return`
    // survived. A type whose `Serialize` and `Deserialize` disagree is what
    // reaches it, and it is a real condition: `load` would refuse the file
    // the save is about to write.
    struct Mismatched;
    impl Serialize for Mismatched {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str("not a number")
        }
    }
    impl<'de> Deserialize<'de> for Mismatched {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            u32::deserialize(d).map(|_| Self)
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let _ = save(&dir.path().join("v.mpk"), KIND, VERSION, &Mismatched);
}

#[test]
fn insertion_order_does_not_change_the_bytes() {
    let mut forwards = Value::new();
    forwards.insert("alpha".into(), 1);
    forwards.insert("beta".into(), 2);
    let mut backwards = Value::new();
    backwards.insert("beta".into(), 2);
    backwards.insert("alpha".into(), 1);
    assert_eq!(
        encoded(KIND, VERSION, &forwards),
        encoded(KIND, VERSION, &backwards),
    );
}

/// An envelope of `version` whose payload is a shape [`Value`] is not, as
/// a newer format that changed the payload would write.
fn reshaped(version: u16) -> Vec<u8> {
    rmp_serde::to_vec_named(&Envelope {
        kind: KIND.to_string(),
        version,
        payload: vec!["a shape", "this build has never seen"],
    })
    .expect("encode")
}

#[test]
fn a_newer_version_is_judged_before_its_payload_is_decoded() {
    // Review round 4: the payload was decoded before the version was
    // looked at, so a newer format with a changed payload read as
    // `Malformed` — damage — whatever the file's loss.
    let (_dir, path) = state_file();
    std::fs::write(&path, reshaped(VERSION + 1)).expect("seed");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(
        loaded.health,
        Health::Reset(Damage::FutureVersion {
            found: VERSION + 1,
            supported: VERSION,
        }),
    );

    // The same shape at a version this build reads is damage.
    std::fs::write(&path, reshaped(VERSION)).expect("seed");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
}

#[test]
fn a_newer_version_of_a_permanent_file_is_refused_and_nothing_is_renamed() {
    // Review round 4: after a rollback to an older bx, an intact ledger
    // was moved aside as damage, even under the lock.
    let (dir, path) = state_file();
    let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
    // Review round 5: whether the rest of the file reads as this format is
    // reported, so the message can say the version itself may be damaged.
    for (seed, readable) in [
        (encoded(KIND, VERSION + 1, &sample()), true),
        (reshaped(VERSION + 1), false),
    ] {
        std::fs::write(&path, &seed).expect("seed");
        for held in [None, Some(&lock)] {
            let err = load::<Value>(&path, KIND, VERSION, Loss::Permanent, held)
                .expect_err("a newer permanent file is refused");
            assert!(
                matches!(
                    &err,
                    Error::FutureVersion { path: at, found, supported, payload_readable }
                        if *at == path && *found == VERSION + 1 && *supported == VERSION
                            && *payload_readable == readable
                ),
                "got {err}",
            );
            let message = err.to_string();
            assert_eq!(message.contains("may be damaged"), readable, "{message}");
            assert!(message.contains("newer bx"), "{message}");
            assert!(message.contains("version 4"), "{message}");
            assert!(message.contains("up to 3"), "{message}");
            assert_eq!(std::fs::read(&path).expect("in place"), seed);
            assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
        }
    }

    // Every other damage to a permanent file still degrades under the lock.
    std::fs::write(&path, b"garbage").expect("seed");
    let loaded: Loaded<Value> =
        load(&path, KIND, VERSION, Loss::Permanent, Some(&lock)).expect("load");
    assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
}

#[test]
fn every_damage_says_what_is_wrong_with_the_file() {
    // r3 round 1 (C4): two of the six texts were never asserted, and
    // the others only in part, so an empty rendering survived mutation.
    let cases = [
        (Damage::Malformed, "it is not valid MessagePack"),
        (
            Damage::TrailingBytes,
            "it has unexpected bytes after the end",
        ),
        (
            Damage::WrongKind {
                found: OTHER.to_string(),
            },
            "it is a bx.other file",
        ),
        (
            Damage::FutureVersion {
                found: 8,
                supported: 3,
            },
            "it is version 8, and this bx understands up to 3",
        ),
        (
            Damage::DanglingLink,
            "it is a symbolic link to something that does not exist, or that cannot be \
                 followed",
        ),
        (
            Damage::NotAFile,
            "it is not a regular file (a FIFO, a device or a socket), so it was not read",
        ),
        (
            Damage::TooLarge,
            "it is longer than 268435456 bytes, which no state file bx writes comes near",
        ),
        (
            Damage::KeyMismatch {
                rows: vec![("~/.aaaa".to_string(), "~/.bbbb".to_string())],
            },
            "its entry for ~/.aaaa names a different path, ~/.bbbb",
        ),
        (
            Damage::KeyMismatch {
                rows: vec![
                    ("~/.aaaa".to_string(), "~/.bbbb".to_string()),
                    ("~/.cccc".to_string(), "~/.dddd".to_string()),
                ],
            },
            "its entry for ~/.aaaa names a different path, ~/.bbbb; its entry for ~/.cccc \
                 names a different path, ~/.dddd",
        ),
    ];
    for (damage, text) in cases {
        assert_eq!(damage.to_string(), text, "{damage:?}");
    }
}

#[test]
fn a_recomputable_link_that_cannot_be_followed_degrades_and_only_the_link_moves() {
    // A link to nothing, one that loops (`ELOOP`), and one whose path runs
    // through a file (`ENOTDIR`) are each a `DanglingLink`: fatal for the
    // ledger, and for a file whose loss costs a recomputation, damage. A
    // lockless reader leaves the link where it is; the lock holder moves
    // the link itself aside, never creating its far end.
    for far in ["unmounted/v.mpk", "v.mpk", "a-file/v.mpk"] {
        let (dir, path) = state_file();
        std::fs::write(dir.path().join("a-file"), b"not a directory").expect("a file");
        let far = dir.path().join(far);
        std::os::unix::fs::symlink(&far, &path).expect("symlink");
        let shown = far.display();

        let read = load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None)
            .unwrap_or_else(|e| panic!("{shown}: {e}"));
        assert_eq!(
            read.health,
            Health::Damaged(Damage::DanglingLink),
            "{shown}"
        );
        assert!(read.value.is_empty(), "{shown}");
        assert_eq!(std::fs::read_link(&path).expect("left in place"), far);

        let opened: Loaded<Value> = locked_load(&path).unwrap_or_else(|e| panic!("{shown}: {e}"));
        assert_eq!(
            opened.health,
            Health::Reset(Damage::DanglingLink),
            "{shown}"
        );
        let aside = StateDir::quarantine(&path);
        assert_eq!(std::fs::read_link(&aside).expect("the link, moved"), far);
        assert!(std::fs::symlink_metadata(&path).is_err(), "{shown}");
        assert!(!dir.path().join("unmounted").exists(), "{shown}");
    }
}

#[test]
fn damaged_bytes_are_quarantined_not_deleted() {
    let (_dir, path) = state_file();
    std::fs::write(&path, b"garbage").expect("seed");
    let _: Loaded<Value> = locked_load(&path).expect("load");
    assert!(!path.exists(), "the damaged file must be moved aside");
    let quarantine = StateDir::quarantine(&path);
    assert_eq!(std::fs::read(&quarantine).expect("read"), b"garbage");
}

#[test]
fn quarantining_a_symlinked_state_file_moves_the_link_not_its_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A state file that is a symlink to somewhere else — a hand-made link,
    // or a restored backup. What it points at may be a file the user wrote,
    // so the degradation must not reach through it.
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, b"whatever is at the far end").expect("seed");
    let path = dir.path().join("v.mpk");
    std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");

    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(loaded.health, Health::Reset(Damage::Malformed));

    // `rename` acts on the link itself, never on what it names.
    assert_eq!(
        std::fs::read(&elsewhere).expect("read"),
        b"whatever is at the far end",
    );
    assert!(std::fs::symlink_metadata(&path).is_err(), "the link moved");
    let quarantine = StateDir::quarantine(&path);
    assert!(
        std::fs::symlink_metadata(&quarantine)
            .expect("stat")
            .file_type()
            .is_symlink(),
        "the quarantined entry is the link, not a copy of the target",
    );
    assert_eq!(
        std::fs::read_link(&quarantine).expect("readlink"),
        elsewhere
    );
}

#[test]
fn saving_over_a_symlinked_state_file_refuses_and_touches_neither_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, b"the user wrote this").expect("seed");
    let path = dir.path().join("v.mpk");
    std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");

    let err = save(&path, KIND, VERSION, &sample()).expect_err("must refuse");
    assert!(
        matches!(err, Error::Write(crate::fs::Error::Symlink(_))),
        "{err:?}",
    );

    // Invariant 1, at both ends of the link. Nothing is written *through*
    // it to a file bx does not own, and the link itself — which the user
    // made — is not replaced either. A `rename` onto the link's path would
    // have destroyed it silently; refusing says so instead.
    assert_eq!(
        std::fs::read(&elsewhere).expect("read"),
        b"the user wrote this",
    );
    assert!(
        std::fs::symlink_metadata(&path)
            .expect("stat")
            .file_type()
            .is_symlink(),
    );
    assert_eq!(std::fs::read_link(&path).expect("readlink"), elsewhere);
}

#[test]
fn successive_quarantines_keep_every_earlier_one() {
    // Review round 3: a fixed `<name>.corrupt` was renamed over, so a
    // second damaged ledger destroyed the first — which may be the only
    // index there is to the user's restore blobs.
    let (dir, path) = state_file();
    for body in [&b"first"[..], b"second", b"third"] {
        std::fs::write(&path, body).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
    }

    assert_eq!(
        names_but_the_lock(dir.path()),
        vec!["v.mpk.corrupt", "v.mpk.corrupt.1", "v.mpk.corrupt.2"],
    );
    for (n, body) in [(0, &b"first"[..]), (1, b"second"), (2, b"third")] {
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&path, n)).expect("kept"),
            body,
        );
    }
}

#[test]
fn a_new_quarantine_takes_the_number_after_the_highest_and_never_refills_a_gap() {
    // Review round 5: `move_aside` took the lowest free number, so once a
    // human deleted `.corrupt` the next quarantine refilled it, and
    // `Loaded::quarantined` listed the newest first.
    let (_dir, path) = state_file();
    for body in [&b"first"[..], b"second", b"third"] {
        std::fs::write(&path, body).expect("seed");
        let _: Loaded<Value> = locked_load(&path).expect("load");
    }
    std::fs::remove_file(StateDir::quarantine(&path)).expect("a human removes the first");

    std::fs::write(&path, b"fourth").expect("seed");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert!(loaded.health.is_reset());
    let newest = StateDir::quarantine_nth(&path, 3);
    assert_eq!(
        loaded.quarantined,
        vec![
            StateDir::quarantine_nth(&path, 1),
            StateDir::quarantine_nth(&path, 2),
            newest.clone(),
        ],
        "creation order, newest last",
    );
    assert_eq!(std::fs::read(&newest).expect("the newest"), b"fourth");
    assert!(
        !StateDir::quarantine(&path).exists(),
        "the gap is not refilled"
    );

    // Once every quarantine is gone, numbering starts again at the first.
    for n in 1..=3 {
        std::fs::remove_file(StateDir::quarantine_nth(&path, n)).expect("remove");
    }
    std::fs::write(&path, b"fifth").expect("seed");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(loaded.quarantined, vec![StateDir::quarantine(&path)]);
}

#[test]
fn a_quarantine_number_with_no_successor_does_not_block_the_next_quarantine() {
    // r3 round 1 (L1a): with `v.mpk.corrupt.18446744073709551615` present,
    // the number after the highest overflowed, nothing was moved aside,
    // and the load still said the file had been quarantined.
    let (_dir, path) = state_file();
    let crafted = StateDir::quarantine_nth(&path, u64::MAX);
    std::fs::write(&crafted, b"crafted").expect("seed");
    std::fs::write(&path, b"garbage").expect("seed");

    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
    let first = StateDir::quarantine(&path);
    assert_eq!(std::fs::read(&first).expect("moved aside"), b"garbage");
    assert_eq!(std::fs::read(&crafted).expect("left alone"), b"crafted");
    assert_eq!(loaded.quarantined, vec![first, crafted]);
    assert!(std::fs::symlink_metadata(&path).is_err(), "the file moved");
}

#[test]
fn once_the_top_quarantine_number_is_present_gaps_are_refilled_and_the_last_is_not_the_newest() {
    // r3 round 2 (P7R4-D1): the docs still said the quarantines listed are
    // in the order they were made, the last the newest, and that bx never
    // makes `<name>.corrupt.<u64::MAX>`. Both stop being true once the top
    // number is present; the docs now say so, and this pins what they say.
    let nth = StateDir::quarantine_nth;

    // A crafted top number, three quarantines, the first removed by a
    // human, then a fourth damaged load.
    let (_dir, path) = state_file();
    let top = nth(&path, u64::MAX);
    std::fs::write(&top, b"crafted").expect("seed");
    for body in [&b"first"[..], b"second", b"third"] {
        std::fs::write(&path, body).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert!(loaded.health.is_reset());
    }
    std::fs::remove_file(nth(&path, 0)).expect("a human removes the first");
    std::fs::write(&path, b"fourth").expect("seed");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert!(loaded.health.is_reset());
    assert_eq!(
        loaded.quarantined,
        vec![nth(&path, 0), nth(&path, 1), nth(&path, 2), top.clone()],
        "ascending by number, the refilled gap included",
    );
    assert_eq!(
        std::fs::read(&loaded.quarantined[0]).expect("the refilled gap"),
        b"fourth",
        "the newest is listed first",
    );
    assert_eq!(
        std::fs::read(loaded.quarantined.last().expect("a last")).expect("the top"),
        b"crafted",
        "the last is not the newest",
    );

    // A crafted `<u64::MAX - 1>`: bx itself makes the top number, and
    // then takes the lowest free numbers.
    let (_dir, path) = state_file();
    let below_top = nth(&path, u64::MAX - 1);
    std::fs::write(&below_top, b"crafted").expect("seed");
    let mut made = Vec::new();
    for body in [&b"first"[..], b"second", b"third"] {
        std::fs::write(&path, body).expect("seed");
        let loaded: Loaded<Value> = locked_load(&path).expect("load");
        assert!(loaded.health.is_reset());
        made.push(loaded.quarantined);
    }
    assert_eq!(
        made,
        vec![
            vec![below_top.clone(), nth(&path, u64::MAX)],
            vec![nth(&path, 0), below_top.clone(), nth(&path, u64::MAX)],
            vec![
                nth(&path, 0),
                nth(&path, 1),
                below_top.clone(),
                nth(&path, u64::MAX),
            ],
        ],
        "the top number, then `.corrupt`, then `.corrupt.1`",
    );
    for (n, body) in [(u64::MAX, &b"first"[..]), (0, b"second"), (1, b"third")] {
        assert_eq!(std::fs::read(nth(&path, n)).expect("kept"), body);
    }
}

#[test]
fn a_quarantine_left_by_an_earlier_run_is_reported_on_every_load() {
    // Review round 4: a quarantine followed by a crash before the save left
    // the next reader and writer looking at `Health::Fresh`, with the
    // `.corrupt` file orphaned and reported nowhere.
    let (dir, path) = state_file();
    let first = StateDir::quarantine(&path);

    let absent: Loaded<Value> = load(
        &dir.path().join("absent/v.mpk"),
        KIND,
        VERSION,
        Loss::Recomputable,
        None,
    )
    .expect("a missing directory lists nothing");
    assert!(absent.quarantined.is_empty());
    // r4 round 2 (COV4): "no directory, so none — *known*" is the whole
    // distinction `unlisted` exists to draw, and nothing pinned it here.
    // It holds because `numbered`'s `NotFound` arm returns an empty list
    // rather than a listing failure; without that this would be `Some`,
    // and an empty `quarantined` beside it would mean nothing is known.
    assert_eq!(absent.unlisted, None, "absent is known, not unknown");

    std::fs::write(&path, b"garbage").expect("seed");
    let reset: Loaded<Value> = locked_load(&path).expect("load");
    assert!(reset.health.is_reset());
    assert_eq!(
        reset.quarantined,
        vec![first.clone()],
        "the quarantining load"
    );

    // The crash: no save. The next reader and writer both see Fresh, and
    // both are told what was set aside.
    let lockless: Loaded<Value> =
        load(&path, KIND, VERSION, Loss::Recomputable, None).expect("load");
    assert_eq!(lockless.health, Health::Fresh);
    assert_eq!(lockless.quarantined, vec![first.clone()]);
    let writer: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(writer.health, Health::Fresh);
    assert_eq!(writer.quarantined, vec![first.clone()]);

    // A clean save does not hide it either. A gap hides nothing after it,
    // and names that are not this file's quarantines are not listed.
    save(&path, KIND, VERSION, &sample()).expect("save");
    let third = StateDir::quarantine_nth(&path, 2);
    std::fs::write(&third, b"after a gap").expect("seed");
    for decoy in [
        "v.mpk.corrupt.01",
        "v.mpk.corrupt.0",
        "v.mpk.corrupt.+3",
        "v.mpk.corrupt.x",
        "v.mpk.corrupt.",
        "v.mpk.corrupted",
        "w.mpk.corrupt",
    ] {
        std::fs::write(dir.path().join(decoy), b"not a quarantine").expect("decoy");
    }
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(loaded.health, Health::Loaded);
    assert_eq!(loaded.quarantined, vec![first, third]);
}

#[test]
fn a_state_directory_that_cannot_be_listed_leaves_the_quarantines_unknown() {
    // r4 round 1 (D8): the listing failure was returned as `Error::Read`,
    // whose documented meaning is "the file's bytes were never seen" — and
    // whose path was the directory, not the state file a caller matches
    // on. It also discarded a quarantine `judge` had already completed,
    // and a persistently unlistable directory (0300: searchable and
    // writable, not readable) failed every `LedgerView::read` and
    // `Fingerprints::read` with no remedy, though each file read perfectly.
    if rustix::process::geteuid().is_root() {
        // Mode bits deny nothing to root, so the condition cannot be staged.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("state");
    std::fs::create_dir(&root).expect("root");
    let path = root.join("v.mpk");
    save(&path, KIND, VERSION, &sample()).expect("seed");
    // Searchable, so the file itself reads; not readable, so it cannot be
    // listed. Reporting no quarantines there would be a guess, so the load
    // says it does not know rather than saying there are none.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300)).expect("chmod");
    let (loaded, said) =
        capturing(|| load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None));
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("restore");

    let loaded = loaded.expect("the file itself read perfectly");
    assert_eq!(loaded.value, sample(), "the load stands");
    assert_eq!(loaded.health, Health::Loaded);
    let unlisted = loaded
        .unlisted
        .clone()
        .expect("the directory it could not list");
    assert_eq!(unlisted.path, root);
    // r4 round 2 (CL5): the cause used to be logged and dropped, so a
    // caller could not tell a remediable `chmod` from a failing disk.
    assert_eq!(unlisted.kind, std::io::ErrorKind::PermissionDenied);
    assert!(unlisted.cause.contains("Permission denied"), "{unlisted:?}");
    assert!(
        loaded.quarantined.is_empty(),
        "empty because nothing is known",
    );
    assert!(said.contains("Permission denied"), "{said}");
    assert!(said.contains(&root.display().to_string()), "{said}");

    // A listing that succeeds says so, whatever it found.
    let (fine, _) = capturing(|| load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None));
    assert_eq!(fine.expect("load").unlisted, None);
}

#[test]
fn a_damaged_file_is_reported_through_tracing_whether_or_not_it_is_moved() {
    // r4 round 1 (COV2): neither `tracing::warn!` body in this module had
    // ever been executed, because no library test installed a subscriber.
    // Both texts are stated as part of the contract — by this module's
    // `load` doc and by `state/mod.rs` — and deleting either macro passed
    // the entire suite.
    let (_dir, path) = state_file();
    std::fs::write(&path, b"garbage").expect("seed");

    // The lockless reader: told what is wrong, and told who will move it.
    let (lockless, said) =
        capturing(|| load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None));
    assert_eq!(
        lockless.expect("load").health,
        Health::Damaged(Damage::Malformed),
    );
    assert!(said.contains(&path.display().to_string()), "{said}");
    assert!(said.contains("is damaged"), "{said}");
    assert!(
        said.contains("the next bx that holds the state directory lock moves it aside"),
        "{said}",
    );

    // The lock holder: told what was discarded, and *where the bytes went*
    // — the only place the numbered quarantine name reaches the log.
    let (writer, said) = capturing(|| locked_load::<Value>(&path));
    assert!(writer.expect("load").health.is_reset());
    let quarantine = StateDir::quarantine(&path);
    assert!(said.contains("discarding"), "{said}");
    assert!(
        said.contains(&format!("moved_to={}", quarantine.display())),
        "{said}",
    );
    assert!(said.contains("The bytes were kept, not deleted."), "{said}",);
}

#[test]
fn a_save_that_cannot_be_written_is_reported_naming_the_directory() {
    // r4 round 1 (COV7): `save`'s `Error::Write` propagation from
    // `write_atomically` was reached by no test at all — region count
    // zero — so the whole arm could be replaced by `Ok(())` undetected.
    if rustix::process::geteuid().is_root() {
        // Mode bits deny nothing to root, so the condition cannot be staged.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    // A *linked* state directory at `0500`. `ensure_dir` never `chmod`s
    // through a link — see `dir::tighten` — so this is the one shape it
    // leaves unwritable, and the atomic write's temporary file cannot be
    // created in it. An unlinked `0500` would be set back to `0700` and
    // the write would succeed (r4 round 2, CL3).
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("real");
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let root = dir.path().join("state");
    std::os::unix::fs::symlink(&real, &root).expect("link");
    let result = save(&root.join("v.mpk"), KIND, VERSION, &sample());
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("restore");

    let err = result.expect_err("must fail");
    assert!(
        matches!(&err, Error::Write(inner) if inner.path() == root),
        "got {err}",
    );
    assert_eq!(
        names_but_the_lock(&root),
        Vec::<String>::new(),
        "nothing left"
    );
}

#[test]
fn a_file_where_the_state_directory_should_be_is_named_as_such_on_a_lockless_read() {
    // r4 round 2 (D5): `LedgerView::read` and `Fingerprints::read` never
    // call `ensure`, so the only code that raised `Error::NotADirectory`
    // was out of reach on the read path. With a plain file at
    // `~/.local/state/bx`, the read failed `ENOTDIR` and reported
    // "reading ~/.local/state/bx/ledger.mpk: Not a directory" — a file
    // inside a file, with no remedy — while the right error existed and
    // said exactly the right thing.
    let dir = tempfile::tempdir().expect("tempdir");
    let blocking = dir.path().join("bx");
    std::fs::write(&blocking, b"not a directory").expect("seed");

    let err = load::<Value>(
        &blocking.join("v.mpk"),
        KIND,
        VERSION,
        Loss::Recomputable,
        None,
    )
    .expect_err("must fail");
    assert!(
        matches!(&err, Error::NotADirectory { path } if *path == blocking),
        "got {err}",
    );
    assert!(err.to_string().contains("move or remove it"), "{err}");

    // Deeper, too: the component in the way is named, not the leaf.
    let err = load::<Value>(
        &blocking.join("restore/v.mpk"),
        KIND,
        VERSION,
        Loss::Recomputable,
        None,
    )
    .expect_err("must fail");
    assert!(
        matches!(&err, Error::NotADirectory { path } if *path == blocking),
        "got {err}",
    );
}

#[test]
fn a_lockless_reader_reports_damage_and_moves_nothing() {
    let (dir, path) = state_file();
    std::fs::write(&path, b"garbage").expect("seed");

    let loaded: Loaded<Value> = load(&path, KIND, VERSION, Loss::Recomputable, None).expect("load");
    assert_eq!(loaded.health, Health::Damaged(Damage::Malformed));
    assert!(!loaded.health.is_reset(), "nothing was moved aside");
    assert_eq!(loaded.health.damage(), Some(&Damage::Malformed));
    assert!(loaded.value.is_empty());
    assert_eq!(std::fs::read(&path).expect("in place"), b"garbage");
    assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
}

#[test]
fn a_writer_saving_inside_a_lockless_readers_window_keeps_its_file() {
    // Review round 3's falsifier: the reader has read and judged the bytes,
    // a writer saves a fresh file, and the reader then acts on the path.
    // A rename by path there moved the writer's fresh file aside.
    let (dir, path) = state_file();
    save(&path, KIND, VERSION, &Value::new()).expect("seed");

    let loaded: Loaded<Value> =
        load_checked(&path, KIND, VERSION, Loss::Recomputable, None, |_| {
            save(&path, KIND, VERSION, &sample()).expect("the writer saves");
            Err(Rejected::PartialDamage(Damage::KeyMismatch {
                rows: vec![("k".to_string(), "other".to_string())],
            }))
        })
        .expect("load");
    assert!(loaded.health.damage().is_some_and(Damage::is_partial));

    let now: Loaded<Value> = load(&path, KIND, VERSION, Loss::Recomputable, None).expect("reload");
    assert_eq!(now.health, Health::Loaded);
    assert_eq!(
        now.value,
        sample(),
        "the writer's file is where it saved it"
    );
    assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "the guard is a debug_assert")]
#[should_panic(expected = "`Damage::is_partial` accepts")]
fn a_check_reporting_whole_file_damage_as_partial_is_refused() {
    // r4 round 3 (COV2): the guard that holds `Rejected::PartialDamage` to
    // row-shaped damage was reached by no test, so the body's claim that
    // the two "cannot drift" rested on an assertion nothing exercised.
    // `Damage::Malformed` is what `decode` produces for a whole file, and
    // a check answering with it would make `is_partial` say the rows named
    // are the whole loss when nothing was named.
    let (_dir, path) = state_file();
    save(&path, KIND, VERSION, &sample()).expect("seed");
    let _ = load_checked::<Value>(&path, KIND, VERSION, Loss::Recomputable, None, |value| {
        value.clear();
        Err(Rejected::PartialDamage(Damage::Malformed))
    });
}

#[test]
fn a_refused_value_is_the_error_and_nothing_is_renamed_even_under_the_lock() {
    let (dir, path) = state_file();
    save(&path, KIND, VERSION, &sample()).expect("seed");
    let intact = std::fs::read(&path).expect("read");
    let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");

    let err = load_checked::<Value>(
        &path,
        KIND,
        VERSION,
        Loss::Recomputable,
        Some(&lock),
        |_| {
            Err(Rejected::Refused(Error::NotADirectory {
                path: PathBuf::from("/refused"),
            }))
        },
    )
    .expect_err("a refusal is an error");
    assert!(
        matches!(&err, Error::NotADirectory { path } if path == Path::new("/refused")),
        "got {err}",
    );
    assert_eq!(std::fs::read(&path).expect("in place"), intact);
    assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
}

#[test]
fn a_degraded_store_writes_a_clean_file_on_the_next_save() {
    let (_dir, path) = state_file();
    std::fs::write(&path, b"garbage").expect("seed");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert!(loaded.health.is_reset());

    save(&path, KIND, VERSION, &sample()).expect("save");
    let again: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(again.health, Health::Loaded);
    assert_eq!(again.value, sample());
}

#[test]
fn a_file_that_cannot_be_read_is_an_error_not_damage() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A directory where a file should be: `read` fails with EISDIR, which
    // is neither NotFound nor a statement about any bytes.
    let path = dir.path().join("v.mpk");
    std::fs::create_dir(&path).expect("seed");
    let err = locked_load::<Value>(&path).expect_err("must fail");
    assert!(
        matches!(&err, Error::Read { path: at, .. } if *at == path),
        "got {err}",
    );
}

/// Put a FIFO at `path`.

#[test]
fn a_state_file_that_is_not_a_regular_file_is_never_read() {
    // r5 (D1): `judge` read state files with plain `std::fs::read`, so a
    // FIFO at the name blocked in `open` until a writer appeared, and a
    // link to `/dev/zero` allocated until the process was killed. Both
    // return at once now, whether the name is the thing or a link to it.
    let (dir, path) = state_file();
    let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
    let fifo = || mkfifo(&path);
    let to_zero = || std::os::unix::fs::symlink("/dev/zero", &path).expect("symlink");
    for (stage, seed) in [("fifo", &fifo as &dyn Fn()), ("/dev/zero", &to_zero)] {
        seed();
        // The ledger is refused, lock or no lock, and nothing is renamed.
        for held in [None, Some(&lock)] {
            let err = load::<Value>(&path, KIND, VERSION, Loss::Permanent, held)
                .expect_err("a permanent file that is not a file is refused");
            assert!(
                matches!(&err, Error::StateNotAFile { path: at } if *at == path),
                "{stage}: got {err}",
            );
            assert!(err.to_string().contains("not a regular file"), "{err}");
            assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"], "{stage}");
        }
        // A cache is reported without the lock, and moved aside with it.
        let read: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, None).expect("lockless");
        assert_eq!(read.health, Health::Damaged(Damage::NotAFile), "{stage}");
        let opened: Loaded<Value> =
            load(&path, KIND, VERSION, Loss::Recomputable, Some(&lock)).expect("locked");
        assert_eq!(opened.health, Health::Reset(Damage::NotAFile), "{stage}");
        assert!(opened.value.is_empty(), "{stage}");
        assert!(std::fs::symlink_metadata(&path).is_err(), "{stage}: moved");
        std::fs::remove_file(StateDir::quarantine(&path)).expect("clear");
    }
}

#[test]
fn a_state_file_longer_than_the_limit_is_never_read_whole() {
    // r5 (D1): the length was not bounded at all. A sparse file one byte
    // past the limit costs nothing to make and is refused before any of
    // it is allocated.
    let (dir, path) = state_file();
    let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
    let seed = || {
        std::fs::File::create(&path)
            .expect("create")
            .set_len(MAX_STATE_FILE + 1)
            .expect("set_len");
    };
    seed();
    for held in [None, Some(&lock)] {
        let err = load::<Value>(&path, KIND, VERSION, Loss::Permanent, held)
            .expect_err("an oversized permanent file is refused");
        assert!(
            matches!(&err, Error::StateTooLarge { path: at } if *at == path),
            "got {err}",
        );
        assert!(err.to_string().contains("268435456 bytes"), "{err}");
        assert_eq!(names_but_the_lock(dir.path()), vec!["v.mpk"]);
    }
    let read: Loaded<Value> =
        load(&path, KIND, VERSION, Loss::Recomputable, None).expect("lockless");
    assert_eq!(read.health, Health::Damaged(Damage::TooLarge));
    let opened: Loaded<Value> =
        load(&path, KIND, VERSION, Loss::Recomputable, Some(&lock)).expect("locked");
    assert_eq!(opened.health, Health::Reset(Damage::TooLarge));
    assert!(!path.exists(), "moved aside");

    // Exactly the limit is still read, and judged on its bytes.
    std::fs::File::create(&path)
        .expect("create")
        .set_len(MAX_STATE_FILE)
        .expect("set_len");
    let at_limit: Loaded<Value> =
        load(&path, KIND, VERSION, Loss::Recomputable, None).expect("lockless");
    assert!(
        !matches!(at_limit.health.damage(), Some(Damage::TooLarge)),
        "{:?}",
        at_limit.health,
    );
}

#[test]
fn an_intact_file_that_cannot_be_read_is_left_exactly_where_it_is() {
    if rustix::process::geteuid().is_root() {
        // `0000` denies nothing to root, so the condition cannot be staged.
        // The root-independent half of this property is pinned by
        // `a_file_that_cannot_be_read_is_an_error_not_damage`.
        crate::testing::skip_unconstructible("root ignores the permission bits");
        return;
    }
    let (_dir, path) = state_file();
    save(&path, KIND, VERSION, &sample()).expect("save");
    let intact = std::fs::read(&path).expect("read");
    // What a `sudo bx` leaves behind: a perfectly good state file this
    // account cannot open. Nothing is known about its bytes, so nothing may
    // be renamed and nothing may be reset.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let err = locked_load::<Value>(&path).expect_err("must fail");
    assert!(matches!(err, Error::Read { .. }), "got {err}");
    assert!(path.exists(), "the file must not be moved aside");
    assert!(
        !StateDir::quarantine(&path).exists(),
        "a file whose bytes were never read must never be quarantined",
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert_eq!(loaded.health, Health::Loaded);
    assert_eq!(loaded.value, sample());
    assert_eq!(std::fs::read(&path).expect("read"), intact);
}

#[test]
fn a_file_that_cannot_be_moved_aside_is_refused_and_left_in_place() {
    // r3 round 1 (L1b): a failed move aside was logged and reported as
    // `Health::Reset` — "has been quarantined" — with the damaged file
    // still at its name, so the next save overwrote the bytes that
    // `Reset` and the module both promise are kept.
    let dir = tempfile::tempdir().expect("tempdir");
    let lock = ExclusiveLock::acquire(&StateDir::new(dir.path().to_path_buf())).expect("lock");
    // A name at the 255-byte limit: every quarantine name is longer, so
    // each rename fails with ENAMETOOLONG rather than finding a free name.
    let path = dir.path().join("v".repeat(255));
    for loss in [Loss::Recomputable, Loss::Permanent] {
        std::fs::write(&path, b"garbage").expect("seed");
        let result = load::<Value>(&path, KIND, VERSION, loss, Some(&lock));
        assert_eq!(
            std::fs::read(&path).expect("in place"),
            b"garbage",
            "{loss:?}: the damaged bytes are where they were",
        );
        assert_eq!(names_but_the_lock(dir.path()), vec!["v".repeat(255)]);
        let err = result.expect_err("a file that cannot be moved aside is refused");
        assert!(
            matches!(
                &err,
                Error::CannotQuarantine { path: at, damage: Damage::Malformed, source }
                    if *at == path
                        && source.raw_os_error()
                            == Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
            ),
            "{loss:?}: got {err}",
        );
        let message = err.to_string();
        for needle in [
            path.to_string_lossy().as_ref(),
            "not valid MessagePack",
            "by hand",
        ] {
            assert!(
                message.contains(needle),
                "{loss:?}: missing {needle:?}: {message}"
            );
        }
    }

    // A cache link that leads nowhere is the other damage moved aside.
    std::fs::remove_file(&path).expect("remove");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &path).expect("symlink");
    let err = load::<Value>(&path, KIND, VERSION, Loss::Recomputable, Some(&lock))
        .expect_err("a link that cannot be moved aside is refused");
    assert!(
        matches!(
            &err,
            Error::CannotQuarantine { path: at, damage: Damage::DanglingLink, .. }
                if *at == path
        ),
        "got {err}",
    );
    assert!(err.to_string().contains("symbolic link"), "{err}");
    assert!(
        std::fs::symlink_metadata(&path).is_ok(),
        "the link is in place"
    );

    // A lockless reader still reports the damage and moves nothing.
    std::fs::remove_file(&path).expect("remove");
    std::fs::write(&path, b"garbage").expect("seed");
    let loaded = load::<Value>(&path, KIND, VERSION, Loss::Recomputable, None).expect("load");
    assert_eq!(loaded.health, Health::Damaged(Damage::Malformed));
}

#[test]
fn an_occupied_quarantine_name_is_skipped_not_replaced() {
    let (_dir, path) = state_file();
    std::fs::write(&path, b"garbage").expect("seed");
    // Whatever holds the first name — a directory here — is left alone.
    let first = StateDir::quarantine(&path);
    std::fs::create_dir(&first).expect("occupy");
    std::fs::write(first.join("keep"), b"x").expect("occupy");

    let loaded: Loaded<Value> = locked_load(&path).expect("load");
    assert!(loaded.health.is_reset());
    assert_eq!(std::fs::read(first.join("keep")).expect("kept"), b"x");
    assert_eq!(
        std::fs::read(StateDir::quarantine_nth(&path, 1)).expect("moved"),
        b"garbage",
    );
}

#[test]
fn state_files_are_written_at_0600() {
    let (_dir, path) = state_file();
    save(&path, KIND, VERSION, &sample()).expect("save");
    let mode = Mode::from_bits(std::fs::metadata(&path).expect("stat").permissions().mode());
    assert_eq!(mode, Mode::PRIVATE_FILE);
}

#[test]
fn saving_creates_the_state_directory_at_0700() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("bx");
    save(&root.join("v.mpk"), KIND, VERSION, &sample()).expect("save");
    let mode = Mode::from_bits(std::fs::metadata(&root).expect("stat").permissions().mode());
    assert_eq!(mode, Mode::PRIVATE_DIR);
}

#[test]
fn a_save_leaves_no_temporary_file_behind() {
    let dir = tempfile::tempdir().expect("tempdir");
    save(&dir.path().join("v.mpk"), KIND, VERSION, &sample()).expect("save");
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("v.mpk")]);
}

#[test]
fn a_save_into_an_impossible_directory_reports_rather_than_panics() {
    let dir = tempfile::tempdir().expect("tempdir");
    let occupied = dir.path().join("file");
    std::fs::write(&occupied, b"x").expect("seed");
    let err = save(&occupied.join("v.mpk"), KIND, VERSION, &sample()).expect_err("must fail");
    assert!(
        matches!(&err, Error::NotADirectory { path } if *path == occupied),
        "got {err}",
    );
}

#[test]
fn a_loaded_value_can_be_mapped_without_losing_its_health() {
    let loaded = Loaded {
        value: 1_u32,
        health: Health::Reset(Damage::Malformed),
        quarantined: vec![PathBuf::from("/s/v.mpk.corrupt")],
        unlisted: Some(Unlisted {
            path: PathBuf::from("/s"),
            kind: std::io::ErrorKind::PermissionDenied,
            cause: "Permission denied".to_string(),
        }),
    };
    let mapped = loaded.map(|v| v + 1);
    assert_eq!(mapped.value, 2);
    assert_eq!(mapped.health, Health::Reset(Damage::Malformed));
    assert_eq!(mapped.quarantined, vec![PathBuf::from("/s/v.mpk.corrupt")]);
    assert_eq!(mapped.unlisted.map(|u| u.path), Some(PathBuf::from("/s")),);
}
