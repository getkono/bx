//! Restoring a link target: removed with the directories bx made for it,
//! left when retargeted since or no longer a link, and the link bx replaced
//! put back.

use super::*;

/// Let bx make `rel` a link holding `text`, through a finished session.
fn linked(state: &StateDir, home: &Path, rel: &str, text: &str) -> Portable {
    let request = crate::journal::tests::link_to(home, rel, text);
    let portable = request.target.clone();
    let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
    session.apply(request).expect("make the link");
    session.finish().expect("finish");
    portable
}

#[test]
fn rm_removes_a_link_bx_made_with_the_directories_it_made_and_never_its_target() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    home.write("real/tool", "the tool\n");
    let portable = linked(&state, home.path(), ".opt/bin/tool", "../../real/tool");
    let linked_twice = linked(&state, home.path(), ".opt/bin/tool", "/elsewhere");
    assert_eq!(portable, linked_twice);

    assert!(matches!(
        plan_restore_with(
            &entry_for(&state, home.path(), &portable).expect("managed"),
            home.path(),
            &Git::at_home(home.path()),
        )
        .expect("plan"),
        Restoration::RemoveLink { .. }
    ));
    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(
        matches!(restored.as_slice(), [Restored::Removed { .. }]),
        "{restored:?}"
    );
    assert!(
        std::fs::symlink_metadata(home.child(".opt")).is_err(),
        "all gone"
    );
    assert_eq!(
        std::fs::read(home.child("real/tool")).expect("kept"),
        b"the tool\n",
        "what a link points at is never touched"
    );
    assert!(entry_for(&state, home.path(), &portable).is_none());

    let again = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(matches!(again.as_slice(), [Restored::Unmanaged { .. }]));
}

#[test]
fn rm_leaves_a_link_retargeted_since_and_anything_that_is_not_a_link() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let retargeted = linked(&state, home.path(), ".a", "/opt/a");
    std::fs::remove_file(home.child(".a")).expect("unlink");
    std::os::unix::fs::symlink("/opt/theirs", home.child(".a")).expect("retarget");
    let replaced = linked(&state, home.path(), ".b", "/opt/b");
    std::fs::remove_file(home.child(".b")).expect("unlink");
    home.write(".b", "a file now\n");
    let gone = linked(&state, home.path(), ".c", "/opt/c");
    std::fs::remove_file(home.child(".c")).expect("unlink");

    let restored = restore(
        &state,
        home.path(),
        &[retargeted.clone(), replaced.clone(), gone.clone()],
    )
    .expect("rm");
    let [
        Restored::Conflict { note: first, .. },
        Restored::Conflict { note: second, .. },
        Restored::AlreadyGone { .. },
    ] = restored.as_slice()
    else {
        panic!("{restored:?}");
    };
    assert!(first.contains("retargeted since bx made it"), "{first}");
    assert!(second.contains("not the symlink bx made"), "{second}");
    assert_eq!(
        std::fs::read_link(home.child(".a")).expect("kept"),
        Path::new("/opt/theirs")
    );
    assert_eq!(
        std::fs::read(home.child(".b")).expect("kept"),
        b"a file now\n"
    );
    assert!(entry_for(&state, home.path(), &retargeted).is_some());
    assert!(entry_for(&state, home.path(), &replaced).is_some());
    assert!(entry_for(&state, home.path(), &gone).is_none());
}

#[test]
fn rm_puts_back_the_link_bx_replaced() {
    // No `apply` records a link bx replaced — a link bx did not make is a
    // conflict — so the entry is recorded directly, as an adoption would.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let (portable, dest) = target(home.path(), ".tool");
    {
        let lock = crate::state::ExclusiveLock::acquire(&state).expect("lock");
        let mut ledger = crate::state::Ledger::open(&state, &lock, home.path())
            .expect("open the ledger")
            .value;
        ledger
            .record(crate::state::NewEntry::new(
                portable.clone(),
                fs::link::digest(Path::new("/opt/bx")),
                Mode::LINK,
                Mechanism::Link,
                crate::state::PriorBytes::Bytes {
                    bytes: b"/opt/theirs".to_vec(),
                    mode: Mode::LINK,
                },
            ))
            .expect("record");
        ledger.save().expect("save");
    }
    std::os::unix::fs::symlink("/opt/bx", &dest).expect("bx's link");

    let restored = restore(&state, home.path(), std::slice::from_ref(&portable)).expect("rm");
    assert!(
        matches!(restored.as_slice(), [Restored::Reverted { .. }]),
        "{restored:?}"
    );
    assert_eq!(
        std::fs::read_link(&dest).expect("a link"),
        Path::new("/opt/theirs")
    );
    assert!(entry_for(&state, home.path(), &portable).is_none());
}

#[test]
fn every_link_bx_makes_is_removed_by_rm_with_the_directories_it_made() {
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let links = [
        linked(&state, home.path(), ".local/bin/one", "../../one"),
        linked(&state, home.path(), ".config/deep/two", "/opt/two"),
    ];
    restore(&state, home.path(), &links).expect("rm");
    assert!(std::fs::symlink_metadata(home.child(".local/bin")).is_err());
    assert!(std::fs::symlink_metadata(home.child(".config")).is_err());
}
