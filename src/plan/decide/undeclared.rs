//! The row for a file bx wrote that nothing declares any more, and what
//! `apply` does about it: takes it back exactly as `bx rm` would while it is
//! still what bx left, releases it when it was edited since, and otherwise
//! reports it and writes nothing.

use std::path::{Path, PathBuf};

use super::{Made, Op, attached_as, join};
use crate::config::Origin;
use crate::fs::{self, Kind, Observed};
use crate::git::Git;
use crate::plan::{Change, Diff};
use crate::report::Action;
use crate::restore::{self, Restoration};
use crate::state::{self, LedgerEntry, Mechanism, StateDir};

/// What deciding an undeclared ledger entry may read.
#[derive(Debug, Clone, Copy)]
pub(in crate::plan) struct Look<'a> {
    /// The account's home, which the entry's path renders against.
    pub home: &'a Path,
    /// The state directory, whose `restore/` holds what bx replaced.
    pub state: &'a StateDir,
    /// The `git` a checkout bx cloned is asked about.
    pub git: &'a Git,
    /// The config repo, lexically normalised.
    pub repo: &'a Path,
    /// Whether the configuration declares anything at all. One that declares
    /// nothing undoes nothing: see [`decide_undeclared`].
    pub declares_any: bool,
}

/// What `apply` does about an undeclared entry, beside its row.
#[derive(Debug)]
pub(in crate::plan) enum Undo {
    /// Nothing: the row is reported, and the entry stays.
    Nothing,
    /// The entry goes, and not a byte is written or deleted.
    Forget,
    /// This write takes the file back, in the run's session. Boxed, as it
    /// holds the bytes put back and the other variants hold nothing.
    Write(Box<Op>),
    /// The checkout is removed outside the session, as `bx rm` removes one.
    Clone,
}

/// The row for a ledger entry no enabled target or external declares — a file
/// bx wrote whose declaration is gone — and what `apply` does about it.
///
/// While what is on disk is still exactly what bx left, the row is
/// [`Action::Undo`]: `apply` takes the file back exactly as `bx rm` would,
/// because [`restore::plan_restore_undeclared`] decides it. A file bx created
/// is removed with the directories it created for it, one it replaced gets
/// its earlier bytes and mode back, a directory loses the mode bx set or is
/// removed while empty, a link is unlinked or the one it replaced put back,
/// and a checkout is removed when it holds nothing its remote does not. The
/// row's diff shows what is taken back; a file's bytes are concealed, as an
/// interrupted write's are, since nothing says any more whether they were a
/// secret.
///
/// Where there is nothing to take back without writing over something, the
/// row is [`Action::Release`], and `apply` drops the ledger entry and writes
/// nothing: a file whose bytes were edited since bx last wrote them, whose
/// edits are the user's; one already gone; one already holding what bx would
/// put back, as a file bx claimed because it already matched does; and a
/// copy in the config repo, whose history is git's to keep and which `apply`
/// never changes.
///
/// Any other drift — retargeted, its mode changed, or something of another
/// kind in its place — is an [`Action::Conflict`] saying why, as drift is for
/// a declared target, and nothing is overwritten. So is a prior `bx rm` would
/// refuse to restore: one whose blob is missing, or a destination it cannot
/// read. A checkout holding work is [`Action::Undeclared`], kept as `bx rm`
/// keeps it.
///
/// A configuration that declares nothing at all undoes nothing: every row it
/// would undo is [`Action::Undeclared`] instead, naming `bx rm`. An emptied
/// `bx.toml` is far likelier a mistake than an intent to take back every file
/// at once, and `bx rm` is the way to do that on purpose. A destination that
/// cannot be observed is reported as undeclared with the reason, rather than
/// stopping a run over a file nothing declares.
pub(in crate::plan) fn decide_undeclared(
    entry: &LedgerEntry,
    origin: &Origin,
    look: &Look<'_>,
) -> (Change, Undo) {
    let path = entry.path.as_str();
    let rm = rm_argument(path);
    let leaves = format!("{UNDECLARED}, so bx leaves it as it is; `bx rm {rm}` releases it");
    let row = |action, why: Option<String>, diff, then: String| Change {
        target: path.to_string(),
        origin: origin.clone(),
        action,
        diff,
        note: join([why, Some(then)]),
    };
    let dest = entry.path.render(look.home);
    let observed = match fs::observe(&dest) {
        Ok(observed) => observed,
        Err(error) => {
            let why = Some(format!("bx cannot look at it now: {error}"));
            return (row(Action::Undeclared, why, None, leaves), Undo::Nothing);
        }
    };
    match drift(entry, &observed) {
        Some(Drift::Edited) => {
            let then = format!(
                "{UNDECLARED}, so the edits are yours: bx keeps the file as it is and stops \
                 managing it"
            );
            return (
                row(Action::Release, Some(EDITED.to_string()), None, then),
                Undo::Forget,
            );
        }
        Some(Drift::Mode(why)) => {
            return (
                row(Action::Conflict, Some(why), None, leaves),
                Undo::Nothing,
            );
        }
        Some(Drift::Refused(why)) => {
            let then = format!(
                "{UNDECLARED}, so bx leaves it as it is, and `bx rm {rm}` will not restore over \
                 the change"
            );
            return (row(Action::Conflict, Some(why), None, then), Undo::Nothing);
        }
        None => {}
    }
    if !look.declares_any {
        let why = Some(DECLARES_NOTHING.to_string());
        return (row(Action::Undeclared, why, None, leaves), Undo::Nothing);
    }
    // Lexical, like every containment verdict bx makes.
    if crate::paths::normalize(&dest).starts_with(look.repo) {
        let why = Some("it is in the config repo, whose history git keeps".to_string());
        return (
            row(Action::Release, why, None, KEPT.to_string()),
            Undo::Forget,
        );
    }
    let restoration = match restore::plan_restore_undeclared(entry, look.home, look.git) {
        Ok(restoration) => restoration,
        Err(error) => {
            let why = Some(format!("bx cannot look at it now: {error}"));
            return (row(Action::Undeclared, why, None, leaves), Undo::Nothing);
        }
    };
    let (action, why, diff, then, undo) = take_back(entry, &observed, restoration, look.state);
    (row(action, why, diff, then), undo)
}

/// What every row about an undeclared entry says first or last.
const UNDECLARED: &str = "the configuration no longer declares it";

/// Why a file bx wrote is released rather than reported.
const EDITED: &str = "edited since bx last wrote it";

/// Why a file bx could take back is left where it is.
const DECLARES_NOTHING: &str = "the configuration declares nothing at all, so bx takes back \
                                nothing it wrote";

/// What a row whose file is released, unwritten, says last.
const KEPT: &str = "the configuration no longer declares it, so bx leaves it as it is and stops \
                    managing it";

/// One undeclared row's action, why, diff and closing words, and what `apply`
/// does, for what `bx rm` would do to the entry.
type Taken = (Action, Option<String>, Option<Diff>, String, Undo);

/// The row and undo for `restoration`, which [`restore`] decided for `entry`
/// from what is at its destination now, `observed`.
///
/// The earlier bytes of a file or link bx replaced are read from `state` here,
/// and verified, so the write `apply` makes carries the bytes `plan` decided
/// on: one whose blob is missing or corrupt is a conflict, never a guess.
fn take_back(
    entry: &LedgerEntry,
    observed: &Observed,
    restoration: Restoration,
    state: &StateDir,
) -> Taken {
    let path = entry.path.as_str();
    let undo = |dest: PathBuf, made, planned: Box<Observed>, mode| {
        Undo::Write(Box::new(Op {
            target: entry.path.clone(),
            dest,
            made,
            planned: *planned,
            mode,
            claimed: false,
            carry: false,
        }))
    };
    let then = |what: &str| format!("{UNDECLARED}, so apply {what}");
    let forget = |why: &str| {
        (
            Action::Release,
            Some(why.to_string()),
            None,
            KEPT.to_string(),
            Undo::Forget,
        )
    };
    let refuse = |note: String| {
        (
            Action::Conflict,
            Some(note),
            None,
            format!("{UNDECLARED}, so bx leaves it as it is"),
            Undo::Nothing,
        )
    };
    match restoration {
        Restoration::Remove {
            dest,
            created_dirs,
            planned,
        } => (
            Action::Undo,
            Some("bx created it".to_string()),
            Diff::concealed(path, observed.bytes.as_deref(), b"", None),
            then("removes it"),
            undo(dest, Made::Absent(created_dirs), planned, entry.mode),
        ),
        Restoration::Revert {
            reference, planned, ..
        } if planned.digest() == Some(reference.digest) && planned.mode == Some(reference.mode) => {
            forget("it already holds what was here before bx wrote it")
        }
        Restoration::Revert {
            dest,
            reference,
            planned,
        } => match state::restore::read(state, &reference) {
            Ok(bytes) => {
                let drift = planned
                    .mode
                    .filter(|mode| *mode != reference.mode)
                    .map(|mode| (mode, reference.mode));
                (
                    Action::Undo,
                    Some("bx replaced the file that was here".to_string()),
                    Diff::concealed(path, planned.bytes.as_deref(), &bytes, drift),
                    then("puts that file back"),
                    undo(dest, Made::Bytes(bytes), planned, reference.mode),
                )
            }
            Err(error) => refuse(format!(
                "{error}; bx will not guess at the bytes it displaced"
            )),
        },
        Restoration::RemoveDir {
            dest,
            created_dirs,
            planned,
        } => (
            Action::Undo,
            Some("bx created it".to_string()),
            None,
            then("removes it once it is empty, and stops managing it either way"),
            undo(dest, Made::DirAbsent(created_dirs), planned, entry.mode),
        ),
        Restoration::RevertMode {
            dest,
            mode,
            planned,
        } => (
            Action::Undo,
            Some(format!("bx set its mode to {}", entry.mode)),
            Some(Diff::mode(entry.mode, mode)),
            then("puts back the mode it had"),
            undo(dest, Made::Dir, planned, mode),
        ),
        Restoration::Release { .. } => forget("it is back at the mode it had before bx set it"),
        Restoration::RemoveLink {
            dest,
            created_dirs,
            planned,
        } => (
            Action::Undo,
            Some("bx made it".to_string()),
            Some(Diff::link(planned.link.as_deref(), None)),
            then("removes the link"),
            undo(dest, Made::LinkAbsent(created_dirs), planned, entry.mode),
        ),
        Restoration::Relink {
            dest,
            reference,
            planned,
        } => match state::restore::read(state, &reference) {
            Ok(bytes) => {
                let text = PathBuf::from(
                    <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(bytes),
                );
                (
                    Action::Undo,
                    Some("bx replaced the link that was here".to_string()),
                    Some(Diff::link(planned.link.as_deref(), Some(&text))),
                    then("puts that link back"),
                    undo(dest, Made::Link(text), planned, reference.mode),
                )
            }
            Err(error) => refuse(format!(
                "{error}; bx will not guess at the link it replaced"
            )),
        },
        Restoration::RemoveClone { .. } => (
            Action::Undo,
            Some("bx cloned it, and it holds nothing its remote does not".to_string()),
            None,
            then("removes the checkout"),
            Undo::Clone,
        ),
        Restoration::AlreadyGone { .. } => forget("it is no longer on disk"),
        Restoration::Keep { .. } => forget(EDITED),
        // A checkout holding work is kept, as `bx rm` keeps it, and nothing
        // in the way of a file that is not there: neither is a conflict, since
        // nothing about either is wrong.
        Restoration::Conflict { note, .. }
            if entry.mechanism == Mechanism::Clone || observed.kind == Kind::Absent =>
        {
            (
                Action::Undeclared,
                Some(note),
                None,
                format!("{UNDECLARED}, so bx leaves it as it is"),
                Undo::Nothing,
            )
        }
        Restoration::Conflict { note, .. } => refuse(note),
    }
}

/// How a destination differs from what its ledger entry says bx left there.
#[derive(Debug, PartialEq, Eq)]
enum Drift {
    /// A file whose bytes are no longer the ones bx left: released.
    Edited,
    /// A file bx owns whole that still holds bx's bytes, and whose mode alone
    /// changed: a conflict `bx rm` still hands back.
    Mode(String),
    /// Anything else, said as a row says it: a conflict `bx rm` refuses.
    Refused(String),
}

/// How `observed` differs from what `entry` says bx left there, or `None`
/// when it is still bx's, or gone.
fn drift(entry: &LedgerEntry, observed: &Observed) -> Option<Drift> {
    let refused = |why: String| Some(Drift::Refused(why));
    let expected = match entry.mechanism {
        Mechanism::Dir | Mechanism::Clone => Kind::Dir,
        Mechanism::Link => Kind::Symlink,
        Mechanism::Own | Mechanism::Region { .. } | Mechanism::Include { .. } => Kind::File,
    };
    match observed.kind {
        Kind::Absent => return None,
        kind if kind != expected => {
            return refused(format!(
                "bx left {} here, and something else is there now",
                attached_as(&entry.mechanism)
            ));
        }
        _ => {}
    }
    match entry.mechanism {
        Mechanism::Own | Mechanism::Region { .. } | Mechanism::Include { .. }
            if observed.digest() != Some(entry.written) =>
        {
            Some(Drift::Edited)
        }
        Mechanism::Own if observed.mode != Some(entry.mode) => Some(Drift::Mode(
            "its mode changed since bx wrote it".to_string(),
        )),
        Mechanism::Dir if observed.mode != Some(entry.mode) => refused(format!(
            "its mode changed since bx set it to {}",
            entry.mode
        )),
        Mechanism::Link if observed.link_digest() != Some(entry.written) => {
            refused("retargeted since bx made it".to_string())
        }
        _ => None,
    }
}

/// `path` as one word a shell passes to `bx rm` unchanged: bare when it holds
/// nothing a shell would read, single-quoted otherwise. A leading `~/` stays
/// inside the quotes, which `bx rm` reads as the home itself.
fn rm_argument(path: &str) -> std::borrow::Cow<'_, str> {
    let plain = |c: char| c.is_ascii_alphanumeric() || "~/._-+,@%=:".contains(c);
    if !path.is_empty() && path.chars().all(plain) && !path[1..].contains('~') {
        std::borrow::Cow::Borrowed(path)
    } else {
        std::borrow::Cow::Owned(crate::shell::quote(path))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::fs::Mode;
    use crate::paths::Portable;
    use crate::state::{ContentHash, Prior};
    use crate::testing::{GuardedHome, guarded_home};

    /// An entry saying bx left `written` at `~/rel`, attached as
    /// `mechanism`, at `mode`.
    fn entry(
        home: &GuardedHome,
        rel: &str,
        written: &[u8],
        mode: u32,
        mechanism: Mechanism,
    ) -> LedgerEntry {
        LedgerEntry {
            path: Portable::parse_in(&format!("~/{rel}"), home.path()).expect("portable"),
            written: ContentHash::of(written),
            mode: Mode::from_bits(mode),
            mechanism,
            prior: Prior::Absent,
            created_dirs: Vec::new(),
            superseded: Vec::new(),
            superseded_absent: false,
        }
    }

    /// The row and undo for `entry`, in a configuration that declares
    /// something when `declares_any`.
    fn undone(home: &GuardedHome, entry: &LedgerEntry, declares_any: bool) -> (Change, Undo) {
        let state = StateDir::resolve(home.path());
        let git = Git::at_home(home.path());
        let repo = home.child(".config/bx");
        let look = Look {
            home: home.path(),
            state: &state,
            git: &git,
            repo: &repo,
            declares_any,
        };
        decide_undeclared(entry, &Origin::unknown(Path::new("/l")), &look)
    }

    fn decided(home: &GuardedHome, entry: &LedgerEntry) -> (Action, String) {
        let (change, _) = undone(home, entry, true);
        (change.action, change.note.expect("a note"))
    }

    fn why(home: &GuardedHome, entry: &LedgerEntry) -> (Action, String) {
        let (action, note) = decided(home, entry);
        let why = note
            .split_once("; the configuration")
            .map_or_else(String::new, |(why, _)| why.to_string());
        (action, why)
    }

    #[test]
    fn a_region_is_judged_by_the_whole_file_and_not_its_mode() {
        let home = guarded_home();
        home.write(".r", "mine\n");
        std::fs::set_permissions(home.child(".r"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        let region = Mechanism::Region { comment: '#' };
        let kept = entry(&home, ".r", b"mine\n", 0o644, region.clone());
        assert_eq!(
            why(&home, &kept),
            (Action::Undo, "bx created it".to_string())
        );

        let edited = entry(&home, ".r", b"other\n", 0o600, region);
        assert_eq!(
            why(&home, &edited),
            (Action::Release, "edited since bx last wrote it".to_string())
        );
    }

    #[test]
    fn an_edited_file_is_released_whatever_attached_it() {
        let home = guarded_home();
        home.write(".e", "yours\n");
        for mechanism in [
            Mechanism::Own,
            Mechanism::Region { comment: '#' },
            Mechanism::Include {
                line: "[include]".to_string(),
            },
        ] {
            let edited = entry(&home, ".e", b"bx's\n", 0o644, mechanism.clone());
            let (action, note) = decided(&home, &edited);
            assert_eq!(action, Action::Release, "{mechanism:?}");
            assert_eq!(
                note,
                "edited since bx last wrote it; the configuration no longer declares it, so \
                 the edits are yours: bx keeps the file as it is and stops managing it",
                "{mechanism:?}"
            );
        }
    }

    #[test]
    fn a_file_whose_mode_changed_is_a_conflict() {
        let home = guarded_home();
        home.write(".a", "a\n");
        std::fs::set_permissions(home.child(".a"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        let owned = entry(&home, ".a", b"a\n", 0o644, Mechanism::Own);
        assert_eq!(
            why(&home, &owned),
            (
                Action::Conflict,
                "its mode changed since bx wrote it".to_string()
            )
        );
        // `bx rm` hands back a file whose bytes are still bx's, whatever
        // its mode, so the note still says it does.
        let (_, note) = decided(&home, &owned);
        assert!(note.ends_with("`bx rm ~/.a` releases it"), "{note}");
    }

    #[test]
    fn a_directory_is_judged_by_its_mode() {
        let home = guarded_home();
        std::fs::create_dir(home.child("d")).expect("mkdir");
        std::fs::set_permissions(home.child("d"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let same = entry(&home, "d", b"", 0o700, Mechanism::Dir);
        assert_eq!(
            why(&home, &same),
            (Action::Undo, "bx created it".to_string())
        );
        assert!(matches!(
            undone(&home, &same, true).1,
            Undo::Write(op) if matches!(*op, Op {
                made: Made::DirAbsent(_),
                claimed: false,
                ..
            })
        ));

        let set = entry(&home, "d", b"", 0o755, Mechanism::Dir);
        assert_eq!(
            why(&home, &set),
            (
                Action::Conflict,
                "its mode changed since bx set it to 0755".to_string()
            )
        );
    }

    #[test]
    fn a_link_is_judged_by_its_text() {
        let home = guarded_home();
        std::os::unix::fs::symlink("there", home.child("l")).expect("a link");
        let same = entry(&home, "l", b"there", 0o777, Mechanism::Link);
        assert_eq!(why(&home, &same), (Action::Undo, "bx made it".to_string()));
        let (change, undo) = undone(&home, &same, true);
        assert_eq!(
            change.diff,
            Some(Diff::link(Some(Path::new("there")), None))
        );
        assert!(matches!(
            undo,
            Undo::Write(op) if matches!(*op, Op {
                made: Made::LinkAbsent(_),
                claimed: false,
                ..
            })
        ));

        let moved = entry(&home, "l", b"elsewhere", 0o777, Mechanism::Link);
        assert_eq!(
            why(&home, &moved),
            (Action::Conflict, "retargeted since bx made it".to_string())
        );
    }

    #[test]
    fn a_checkout_bx_cannot_read_is_kept_as_bx_rm_keeps_it() {
        let home = guarded_home();
        std::fs::create_dir(home.child("c")).expect("mkdir");
        let clone = entry(&home, "c", b"any commit", 0o755, Mechanism::Clone);
        let (change, undo) = undone(&home, &clone, true);
        assert_eq!(change.action, Action::Undeclared);
        let note = change.note.expect("a note");
        assert!(
            note.contains("bx is leaving the checkout and forgetting nothing"),
            "{note}"
        );
        assert!(matches!(undo, Undo::Nothing));
    }

    #[test]
    fn a_checkout_bx_never_finished_is_removed() {
        let home = guarded_home();
        std::fs::create_dir(home.child("c")).expect("mkdir");
        let mut clone = entry(&home, "c", b"", 0o755, Mechanism::Clone);
        clone.written = state::clone_written(None);
        let (change, undo) = undone(&home, &clone, true);
        assert_eq!(change.action, Action::Undo);
        assert_eq!(change.diff, None);
        assert!(matches!(undo, Undo::Clone));
    }

    #[test]
    fn a_file_bx_created_is_removed_and_its_bytes_are_not_shown() {
        let home = guarded_home();
        home.write(".a", "token\n");
        let created = entry(&home, ".a", b"token\n", 0o644, Mechanism::Own);
        let (change, undo) = undone(&home, &created, true);
        assert_eq!(change.action, Action::Undo);
        assert_eq!(
            change.note.as_deref(),
            Some("bx created it; the configuration no longer declares it, so apply removes it")
        );
        assert_eq!(
            change.diff,
            Diff::concealed("~/.a", Some(b"token\n"), b"", None)
        );
        let Undo::Write(op) = undo else {
            panic!("a write");
        };
        assert_eq!(op.made, Made::Absent(Vec::new()));
        assert!(!op.claimed && !op.carry);
        assert_eq!(op.target, created.path);
    }

    #[test]
    fn a_configuration_declaring_nothing_takes_back_nothing() {
        let home = guarded_home();
        home.write(".a", "a\n");
        let created = entry(&home, ".a", b"a\n", 0o644, Mechanism::Own);
        let (change, undo) = undone(&home, &created, false);
        assert_eq!(change.action, Action::Undeclared);
        assert_eq!(
            change.note.as_deref(),
            Some(
                "the configuration declares nothing at all, so bx takes back nothing it \
                 wrote; the configuration no longer declares it, so bx leaves it as it is; \
                 `bx rm ~/.a` releases it"
            )
        );
        assert!(matches!(undo, Undo::Nothing));

        // An edited file is still released: that writes nothing either way.
        let edited = entry(&home, ".a", b"bx's\n", 0o644, Mechanism::Own);
        assert_eq!(undone(&home, &edited, false).0.action, Action::Release);
    }

    #[test]
    fn a_copy_in_the_config_repo_is_released_never_undone() {
        let home = guarded_home();
        home.write(".config/bx/files/x", "x\n");
        let copy = entry(&home, ".config/bx/files/x", b"x\n", 0o644, Mechanism::Own);
        let (change, undo) = undone(&home, &copy, true);
        assert_eq!(change.action, Action::Release);
        assert_eq!(
            change.note.as_deref(),
            Some(
                "it is in the config repo, whose history git keeps; the configuration no \
                 longer declares it, so bx leaves it as it is and stops managing it"
            )
        );
        assert!(matches!(undo, Undo::Forget));
    }

    #[test]
    fn a_file_already_gone_is_only_forgotten() {
        let home = guarded_home();
        let gone = entry(&home, ".gone", b"x\n", 0o644, Mechanism::Own);
        let (change, undo) = undone(&home, &gone, true);
        assert_eq!(change.action, Action::Release);
        assert!(
            change
                .note
                .as_deref()
                .is_some_and(|note| note.starts_with("it is no longer on disk; ")),
            "{change:?}"
        );
        assert!(matches!(undo, Undo::Forget));
    }

    #[test]
    fn a_prior_whose_blob_is_missing_is_a_conflict() {
        let home = guarded_home();
        home.write(".p", "bx's\n");
        let mut replaced = entry(&home, ".p", b"bx's\n", 0o644, Mechanism::Own);
        replaced.prior = Prior::Existed(state::RestoreRef {
            digest: ContentHash::of(b"theirs\n"),
            mode: Mode::from_bits(0o644),
            len: 7,
        });
        let (change, undo) = undone(&home, &replaced, true);
        assert_eq!(change.action, Action::Conflict);
        let note = change.note.expect("a note");
        assert!(
            note.contains("bx will not guess at the bytes it displaced"),
            "{note}"
        );
        assert!(matches!(undo, Undo::Nothing));
    }

    #[test]
    fn something_of_another_kind_in_its_place_is_a_conflict() {
        let home = guarded_home();
        std::fs::create_dir(home.child(".a")).expect("mkdir");
        let owned = entry(&home, ".a", b"a\n", 0o644, Mechanism::Own);
        assert_eq!(
            why(&home, &owned),
            (
                Action::Conflict,
                "bx left the whole file here, and something else is there now".to_string()
            )
        );
    }

    #[test]
    fn a_destination_bx_cannot_look_at_is_reported_with_the_reason() {
        let home = guarded_home();
        home.write(".f", "a file\n");
        let beneath = entry(&home, ".f/x", b"x\n", 0o644, Mechanism::Own);
        let (action, note) = decided(&home, &beneath);
        // Observing beneath a regular file either fails, which is named,
        // or finds nothing there; neither stops the run or is a conflict,
        // and nothing is taken back.
        assert_eq!(action, Action::Undeclared, "{note}");
        assert!(
            note.ends_with("the configuration no longer declares it, so bx leaves it as it is"),
            "{note}"
        );
        assert!(matches!(undone(&home, &beneath, true).1, Undo::Nothing));
    }

    #[test]
    fn the_rm_argument_is_quoted_only_where_a_shell_would_read_it() {
        assert_eq!(rm_argument("~/.config/x-y_z.toml"), "~/.config/x-y_z.toml");
        assert_eq!(rm_argument("~/a b"), "'~/a b'");
        assert_eq!(rm_argument("~/it's"), r"'~/it'\''s'");
        assert_eq!(rm_argument("~/a~b"), "'~/a~b'");
        assert_eq!(rm_argument("~/$HOME"), "'~/$HOME'");
        assert_eq!(rm_argument(""), "''");
    }
}
