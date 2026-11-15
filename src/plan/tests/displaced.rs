//! The other changes made since bx wrote a target that `apply` asks about as
//! it asks about an edited file: a region of bx's edited inside its markers, a
//! mode changed on bytes that are still bx's, and a symlink bx made that was
//! retargeted. An answer of *keep* changes nothing, an answer of *take* writes
//! the write the row was decided with, `bx rm` then gives back exactly what
//! the user had, and a second plan is empty.

use super::*;

/// An `apply` approved, answering *take* for each of `taken`.
fn answer(inputs: &Inputs, taken: &[usize]) -> Report {
    answered(inputs, Mode::Apply, &mut |_| {
        Ok(Approval {
            approved: true,
            taken: taken.iter().copied().collect(),
        })
    })
    .expect("apply runs")
}

/// `bx rm` of every target the ledger holds.
fn rm(home: &GuardedHome) {
    let state = StateDir::resolve(home.path());
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("rm");
}

/// A configuration whose generated `~/.zshrc` region differs from the one
/// [`OLD_REGION`] holds.
const LAYER: &str = "[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n";

/// `~/.zshrc` as bx last left it: the user's line, then bx's older region.
const OLD_REGION: &str = "mine\n# >>> bx >>>\nsource ~/.old\n# <<< bx <<<\n";

/// `~/.zshrc` with bx's region in it edited inside its markers since bx
/// wrote it, and the inputs that want a different region there.
fn region_edited_inside(home: &GuardedHome) -> (Inputs, String) {
    own(
        home.path(),
        ".zshrc",
        OLD_REGION.as_bytes(),
        Mechanism::Region { comment: '#' },
    );
    let edited = OLD_REGION.replace("source ~/.old\n", "source ~/.old\nedited\n");
    home.write(".zshrc", &edited);
    (inputs(home, LAYER), edited)
}

/// The row of `report` for `~/.zshrc`, by index.
fn zshrc(report: &Report) -> usize {
    report
        .changes
        .iter()
        .position(|change| change.target == "~/.zshrc")
        .expect("a row for ~/.zshrc")
}

#[test]
fn a_region_edited_inside_is_asked_about_and_keep_changes_nothing() {
    let home = guarded_home();
    let (inputs, edited) = region_edited_inside(&home);

    let planned = plan(&inputs);
    let at = zshrc(&planned);
    assert_eq!(planned.changes[at].action, Action::Conflict);
    assert_eq!(
        planned.questions.iter().map(|q| q.row).collect::<Vec<_>>(),
        vec![at]
    );
    assert!(
        planned.changes[at]
            .note
            .as_deref()
            .is_some_and(|note| note.starts_with("bx's region was edited since")
                && note.ends_with(decide::ASK)),
        "{:?}",
        planned.changes[at].note
    );
    assert!(
        planned.changes[at].diff.is_some(),
        "the row's diff shows it"
    );
    assert_eq!(planned.questions[0].three_way, None);

    let kept = answer(&inputs, &[]);
    assert_eq!(kept.changes[at].action, Action::Conflict);
    assert_eq!(
        std::fs::read_to_string(home.child(".zshrc")).expect("kept"),
        edited,
        "the edit is left as it is"
    );
}

#[test]
fn take_over_a_region_edited_inside_and_rm_restores_the_edit_exactly() {
    let home = guarded_home();
    let (inputs, edited) = region_edited_inside(&home);
    let at = zshrc(&plan(&inputs));

    let taken = answer(&inputs, &[at]);
    assert!(taken.executed);
    assert_eq!(taken.changes[at].action, Action::Modify);
    let now = std::fs::read_to_string(home.child(".zshrc")).expect("bx's region");
    assert!(now.starts_with("mine\n"), "the bytes around it stay: {now}");
    assert!(!now.contains("edited") && !now.contains("~/.old"), "{now}");
    let again = plan(&inputs);
    assert!(
        again
            .actions()
            .iter()
            .all(|action| *action == Action::Unchanged),
        "{:?}",
        again.actions()
    );
    assert!(again.questions.is_empty());

    rm(&home);
    assert_eq!(
        std::fs::read_to_string(home.child(".zshrc")).expect("the edit is back"),
        edited
    );
}

#[test]
fn a_region_entry_with_no_digest_of_its_own_is_not_asked_about() {
    let home = guarded_home();
    let (inputs, _) = region_edited_inside(&home);
    let state = StateDir::resolve(home.path());
    let key = Portable::parse_in("~/.zshrc", home.path()).expect("a path");
    {
        let lock = crate::state::ExclusiveLock::acquire(&state).expect("the lock");
        let mut ledger = crate::state::Ledger::open(&state, &lock, home.path())
            .expect("open")
            .value;
        let stored = ledger.forget(&key).expect("the entry");
        ledger
            .record(crate::state::NewEntry::new(
                key,
                stored.written,
                stored.mode,
                stored.mechanism,
                crate::state::PriorBytes::Absent,
            ))
            .expect("a record with no region digest");
        ledger.save().expect("save");
    }

    let planned = plan(&inputs);
    assert_eq!(planned.changes[zshrc(&planned)].action, Action::Conflict);
    assert!(planned.questions.is_empty(), "{:?}", planned.questions);
}

#[test]
fn take_over_a_mode_changed_on_bxs_bytes_and_rm_restores_the_users_mode() {
    let home = guarded_home();
    let written = inputs(&home, &inline("~/.a", "bx\\n"));
    assert!(apply(&written).executed);
    std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
        .expect("the user's chmod");
    let before = snapshot(home.path(), &[]);

    let planned = plan(&written);
    assert_eq!(planned.actions(), vec![Action::Conflict]);
    assert_eq!(planned.questions.len(), 1);
    assert!(!answer(&written, &[]).executed, "keep writes nothing");
    assert_eq!(snapshot(home.path(), &[]), before);

    let taken = answer(&written, &[0]);
    assert!(taken.executed);
    assert_eq!(mode_of(&home.child(".a")), 0o644, "bx's mode");
    assert_eq!(std::fs::read(home.child(".a")).expect("bx's"), b"bx\n");
    let again = plan(&written);
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert!(again.questions.is_empty());

    rm(&home);
    assert_eq!(std::fs::read(home.child(".a")).expect("kept"), b"bx\n");
    assert_eq!(mode_of(&home.child(".a")), 0o600, "the user's mode is back");
}

#[test]
fn take_over_a_retargeted_link_and_rm_restores_the_users_text() {
    let home = guarded_home();
    assert!(apply(&inputs(&home, &symlink("~/.tool", "/opt/one"))).executed);
    std::fs::remove_file(home.child(".tool")).expect("unlink");
    std::os::unix::fs::symlink("/opt/theirs", home.child(".tool")).expect("retarget");
    let inputs = inputs(&home, &symlink("~/.tool", "/opt/two"));

    assert!(!answer(&inputs, &[]).executed, "keep writes nothing");
    assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/theirs"));

    let taken = answer(&inputs, &[0]);
    assert!(taken.executed);
    assert_eq!(taken.actions(), vec![Action::Modify]);
    assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/two"));
    let again = plan(&inputs);
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert!(again.questions.is_empty());

    rm(&home);
    assert_eq!(text_of(&home.child(".tool")), Path::new("/opt/theirs"));
}
