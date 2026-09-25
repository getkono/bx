//! Check 9: a `.bx-` temporary file an interrupted write left beside a
//! destination, which no journal names.
//!
//! A write stages its content in a temporary file beside the destination, and
//! only then appends the intent that names it. A crash between the two leaves
//! a file the journal never recorded. Recovery removes only the temporary
//! file an intent names — unlinking by pattern in a directory the user owns is
//! a deletion bx cannot prove it is entitled to make — so such an orphan
//! survives every later `apply`. Its name is what attributes it: the prefix
//! [`TEMP_PREFIX`] is reserved for exactly these files.
//!
//! Only the directories bx writes into are looked in: the directory of every
//! declared target that is ready to be written, and of every target the
//! ledger records, since `bx rm` writes there too. A directory target stages
//! nothing, so its own directory is not looked in on its account. Nothing is
//! walked below those directories, and nothing is followed: an entry is
//! looked at with `lstat`, and only a regular file or a symbolic link — the
//! two things a write stages — can be an orphan.
//!
//! A temporary file the pending journal names is not an orphan: it is the
//! interrupted session's, check 4 reports that session, and the next `apply`
//! removes the file as it rolls the session back. A journal that cannot be
//! read says nothing about which files are whose, so the check then reports
//! nothing, and check 3 or 4 names the journal.
//!
//! An `apply` in flight has temporary files of its own that are not orphans,
//! so while one holds the lock the check reports nothing, as check 4 already
//! says to run `bx doctor` again once it finishes. The lock is asked before
//! and after the directories are listed, and the journal is read only after
//! the second question. An `apply` that started after the first either still
//! holds the lock at the second; or has finished and taken its temporary files
//! with it, so a file is reported only when it is still there afterwards; or
//! was killed, and then the intent naming its temporary file is already in the
//! journal the check reads. Doctor never removes an orphan; the finding says
//! how to.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::Finding;
use crate::config::resolve::Resolution;
use crate::config::target::{Body, Target};
use crate::fs::TEMP_PREFIX;
use crate::journal;
use crate::paths;
use crate::state::{LedgerView, SharedLock, StateDir};

/// A finding for every orphaned temporary file in a directory bx writes into,
/// sorted by path.
#[must_use]
pub fn check(
    targets: &[Resolution<Target>],
    ledger: &LedgerView,
    state: &StateDir,
    home: &Path,
) -> Vec<Finding> {
    if !settled(state) {
        return Vec::new();
    }
    let candidates: Vec<PathBuf> = directories(targets, ledger, home)
        .iter()
        .flat_map(|dir| staged_in(dir))
        .collect();
    if !settled(state) {
        return Vec::new();
    }
    // Read only now: an `apply` that started after the first probe and was
    // killed before the second has left an intent naming its temporary file,
    // and a journal read before the listing would not have seen it.
    let Some(named) = named(state) else {
        return Vec::new();
    };
    candidates
        .into_iter()
        .filter(|path| !named.contains(path))
        .filter(|path| std::fs::symlink_metadata(path).is_ok())
        .map(|path| Finding {
            subject: paths::to_portable(&path, home),
            origin: None,
            note: "is a temporary file a bx write left when it was interrupted before its \
                   journal named it, so recovery never removes it and nothing reads it; look \
                   at it, then delete it"
                .to_string(),
        })
        .collect()
}

/// Whether no `apply` holds the lock, so every temporary file is settled.
///
/// A lock that cannot be asked is not known to be free; check 4 names it.
fn settled(state: &StateDir) -> bool {
    SharedLock::probe(state).is_ok_and(|probe| !probe.is_held())
}

/// Every temporary file the pending journal names, or `None` when the journal
/// cannot be read.
fn named(state: &StateDir) -> Option<BTreeSet<PathBuf>> {
    let loaded = journal::load(&state.journal()).ok()?;
    if matches!(loaded, journal::Loaded::Unreadable { .. }) {
        return None;
    }
    Some(
        loaded
            .intents()
            .filter_map(|intent| intent.temp.clone())
            .collect(),
    )
}

/// The directories bx writes into, each once and in order.
fn directories(
    targets: &[Resolution<Target>],
    ledger: &LedgerView,
    home: &Path,
) -> BTreeSet<PathBuf> {
    let declared = targets.iter().filter_map(|resolution| match resolution {
        Resolution::Ready(target) if target.body != Body::Dir => Some(target.path.render(home)),
        _ => None,
    });
    let recorded = ledger.iter().map(|(path, _)| path.render(home));
    declared
        .chain(recorded)
        .filter_map(|dest| dest.parent().map(Path::to_path_buf))
        .collect()
}

/// Every entry of `dir` named as a staged write is, and staged as one is: a
/// regular file or a symbolic link, never followed. A directory that cannot be
/// listed has nothing to report.
fn staged_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(TEMP_PREFIX))
        })
        .filter(|entry| {
            entry
                .file_type()
                .is_ok_and(|kind| kind.is_file() || kind.is_symlink())
        })
        .map(|entry| entry.path())
        .collect();
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::inputs;
    use crate::testing::guarded_home;

    const LAYER: &str = "\
[[target]]
path = \"~/.config/a/config\"
content = \"a\\n\"

[[target]]
path = \"~/.l\"
symlink = \"~/.config/a/config\"

[[target]]
path = \"~/.config/d\"
dir = true
";

    fn findings(home: &crate::testing::GuardedHome, layer: &str) -> Vec<(String, String)> {
        let inputs = inputs(home, layer);
        let state = StateDir::resolve(home.path());
        check(
            inputs.targets(),
            &LedgerView::default(),
            &state,
            home.path(),
        )
        .into_iter()
        .map(|finding| (finding.subject, finding.note))
        .collect()
    }

    fn subjects(home: &crate::testing::GuardedHome, layer: &str) -> Vec<String> {
        findings(home, layer)
            .into_iter()
            .map(|(subject, _)| subject)
            .collect()
    }

    #[test]
    fn an_orphan_beside_a_declared_target_is_named_and_left_where_it_is() {
        let home = guarded_home();
        let orphan = home.write(".config/a/.bx-Ab3dEf", "half a write");

        let found = findings(&home, LAYER);

        assert_eq!(
            found,
            [(
                "~/.config/a/.bx-Ab3dEf".to_string(),
                "is a temporary file a bx write left when it was interrupted before its journal \
                 named it, so recovery never removes it and nothing reads it; look at it, then \
                 delete it"
                    .to_string()
            )]
        );
        assert_eq!(std::fs::read(&orphan).unwrap(), b"half a write");
    }

    #[test]
    fn only_the_directories_bx_writes_into_are_looked_in_and_in_path_order() {
        let home = guarded_home();
        // Beside the link target and the file target, a staged link among
        // them: all reported.
        home.write(".bx-zz", "");
        home.write(".config/a/.bx-b", "");
        std::os::unix::fs::symlink("nowhere", home.child(".config/a/.bx-a")).unwrap();
        // Not a directory bx writes into: the directory target's own
        // directory, one below a target's, and one nothing declares.
        home.write(".config/.bx-beside-a-directory-target", "");
        home.write(".config/a/deeper/.bx-below", "");
        home.write(".elsewhere/.bx-undeclared", "");
        // In a declared directory, but not a staged write.
        home.write(".config/a/bx-no-dot", "");
        std::fs::create_dir(home.child(".config/a/.bx-a-directory")).unwrap();

        assert_eq!(
            subjects(&home, LAYER),
            ["~/.bx-zz", "~/.config/a/.bx-a", "~/.config/a/.bx-b"]
        );
    }

    #[test]
    fn a_directory_a_ledger_entry_names_is_looked_in_too() {
        let home = guarded_home();
        let layer = "[[target]]\npath = \"~/.released/f\"\ncontent = \"f\\n\"\n";
        crate::plan::run(&inputs(&home, layer), crate::plan::Mode::Apply, &mut |_| {
            Ok(true)
        })
        .expect("apply runs");
        home.write(".released/.bx-left", "");
        let state = StateDir::resolve(home.path());
        let ledger = LedgerView::read(&state, home.path()).unwrap().value;

        let found = check(&[], &ledger, &state, home.path());

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].subject, "~/.released/.bx-left");
        assert!(
            check(&[], &LedgerView::default(), &state, home.path()).is_empty(),
            "undeclared and unrecorded, the directory is not bx's to look in"
        );
    }

    #[test]
    fn a_temporary_file_the_pending_journal_names_is_the_sessions_not_an_orphan() {
        use crate::journal::{Content, Ownership, Request, Session, SessionKind};
        use crate::paths::Portable;
        use crate::state::Mechanism;

        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let target = Portable::parse_in("~/.config/a/config", home.path()).unwrap();
        let dest = home.child(".config/a/config");
        let planned = crate::fs::observe(&dest).unwrap();
        let mut session = Session::open(
            &state,
            SessionKind::Apply,
            home.path(),
            vec![target.clone()],
        )
        .unwrap();
        session
            .apply(Request {
                target,
                dest,
                content: Content::Bytes {
                    bytes: b"a\n".to_vec(),
                    planned,
                },
                mode: crate::fs::Mode::DEFAULT_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .unwrap();
        drop(session);
        let loaded = journal::load(&state.journal()).unwrap();
        let temp = loaded
            .intents()
            .find_map(|intent| intent.temp.clone())
            .expect("the intent names its temporary file");
        std::fs::write(&temp, b"staged").unwrap();
        home.write(".config/a/.bx-unnamed", "");

        assert_eq!(subjects(&home, LAYER), ["~/.config/a/.bx-unnamed"]);
    }

    #[test]
    fn a_journal_that_cannot_be_read_names_no_orphan() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        std::fs::write(state.journal(), b"garbage").unwrap();
        home.write(".config/a/.bx-Ab3dEf", "");

        assert!(subjects(&home, LAYER).is_empty());
    }

    #[test]
    fn nothing_is_named_while_an_apply_holds_the_lock() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        home.write(".config/a/.bx-in-flight", "");
        let held = crate::state::ExclusiveLock::acquire(&state).unwrap();

        assert!(subjects(&home, LAYER).is_empty());

        drop(held);
        assert_eq!(subjects(&home, LAYER), ["~/.config/a/.bx-in-flight"]);
    }
}
