//! The row for a file bx wrote that nothing declares any more: reported, and
//! never acted on.

use std::path::Path;

use super::{attached_as, join};
use crate::config::Origin;
use crate::fs::{self, Kind, Observed};
use crate::plan::Change;
use crate::report::Action;
use crate::state::{LedgerEntry, Mechanism};

/// The row for a ledger entry no enabled target or external declares: a file
/// bx wrote whose declaration is gone, reported and never acted on.
///
/// The row is [`Action::Undeclared`] while what is on disk is still what bx
/// left, or nothing at all, and names `bx rm` as the way to release it. When
/// the destination has drifted since — edited, retargeted, its mode changed,
/// or something of another kind in its place — it is an [`Action::Conflict`]
/// saying why, as drift is for a declared target, and nothing is overwritten
/// either way. `bx rm` refuses to restore over the same drift, so such a note
/// says so rather than promising a release; a file whose mode alone changed
/// is still one `bx rm` hands back. A checkout's commit is git's to read, so a
/// clone is judged by whether its directory is there alone, and `bx rm` says
/// itself when a checkout holds work it will not remove.
///
/// No diff: bx no longer knows what it would write, and it writes nothing.
/// A destination that cannot be observed is reported as undeclared with the
/// reason, rather than stopping a run over a file nothing declares.
pub(in crate::plan) fn decide_undeclared(
    entry: &LedgerEntry,
    origin: &Origin,
    home: &Path,
) -> Change {
    let path = entry.path.as_str();
    let rm = rm_argument(path);
    let undeclared = "the configuration no longer declares it, so bx leaves it as it is";
    let release = format!("{undeclared}; `bx rm {rm}` releases it");
    let (action, why, release) = match fs::observe(&entry.path.render(home)) {
        Err(error) => (
            Action::Undeclared,
            Some(format!("bx cannot look at it now: {error}")),
            release,
        ),
        Ok(observed) => match drift(entry, &observed) {
            Some(Drift { why, released }) => (
                Action::Conflict,
                Some(why),
                if released {
                    release
                } else {
                    format!("{undeclared}, and `bx rm {rm}` will not restore over the change")
                },
            ),
            None if observed.kind == Kind::Absent => (
                Action::Undeclared,
                Some("it is no longer on disk".to_string()),
                release,
            ),
            None => (Action::Undeclared, None, release),
        },
    };
    Change {
        target: path.to_string(),
        origin: origin.clone(),
        action,
        diff: None,
        note: join([why, Some(release)]),
    }
}

/// How a destination differs from what its ledger entry says bx left there.
struct Drift {
    /// Why it is not what bx left, as a row says it.
    why: String,
    /// Whether `bx rm` still hands it back: only when a file bx owns whole
    /// still holds bx's bytes, and its mode alone changed.
    released: bool,
}

/// How `observed` differs from what `entry` says bx left there, or `None`
/// when it is still bx's, or gone.
fn drift(entry: &LedgerEntry, observed: &Observed) -> Option<Drift> {
    let refused = |why: String| {
        Some(Drift {
            why,
            released: false,
        })
    };
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
            refused("edited since bx last wrote it".to_string())
        }
        Mechanism::Own if observed.mode != Some(entry.mode) => Some(Drift {
            why: "its mode changed since bx wrote it".to_string(),
            released: true,
        }),
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

    fn decided(home: &GuardedHome, entry: &LedgerEntry) -> (Action, String) {
        let change = decide_undeclared(entry, &Origin::unknown(Path::new("/l")), home.path());
        assert_eq!(change.diff, None, "an undeclared row never has a diff");
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
        assert_eq!(why(&home, &kept), (Action::Undeclared, String::new()));

        let edited = entry(&home, ".r", b"other\n", 0o600, region);
        assert_eq!(
            why(&home, &edited),
            (
                Action::Conflict,
                "edited since bx last wrote it".to_string()
            )
        );
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
        assert_eq!(why(&home, &same), (Action::Undeclared, String::new()));

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
        assert_eq!(why(&home, &same), (Action::Undeclared, String::new()));

        let moved = entry(&home, "l", b"elsewhere", 0o777, Mechanism::Link);
        assert_eq!(
            why(&home, &moved),
            (Action::Conflict, "retargeted since bx made it".to_string())
        );
    }

    #[test]
    fn a_checkout_is_judged_by_whether_its_directory_is_there() {
        let home = guarded_home();
        std::fs::create_dir(home.child("c")).expect("mkdir");
        let clone = entry(&home, "c", b"any commit", 0o755, Mechanism::Clone);
        assert_eq!(why(&home, &clone), (Action::Undeclared, String::new()));
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
        // or finds nothing there; neither stops the run or is a conflict.
        assert_eq!(action, Action::Undeclared, "{note}");
        assert!(note.ends_with("`bx rm ~/.f/x` releases it"), "{note}");
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
