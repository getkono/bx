//! Fixtures the journal's tests share with one another and with the
//! recovery, restore, plan and doctor suites, and the tests that pin the
//! fixtures themselves — chiefly the rule for a scenario this machine cannot
//! build.

use super::*;

use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::crash::{Crash, FINISH_PHASES, PHASES};
use super::format::{FORMAT, HEADER, MAGIC, NONCE, frame, fresh_nonce};
use crate::fs::Mode;
use crate::state::{ContentHash, ExclusiveLock, Ledger, Mechanism, Prior, StateDir};

/// A target under `home`, both halves of it.
pub(crate) fn target(home: &Path, rel: &str) -> (Portable, PathBuf) {
    let dest = home.join(rel);
    (Portable::from_path(&dest, home).expect("portable"), dest)
}

/// A write request for `rel` under `home`, carrying what is there now as
/// plan's observation.
pub(crate) fn write_to(home: &Path, rel: &str, bytes: &str, mode: Mode) -> Request {
    let (target, dest) = target(home, rel);
    // Observed when the request is built, as plan observes before anything
    // is applied.
    let planned = fs::observe(&dest).expect("plan's observation");
    Request {
        target,
        dest,
        content: Content::Bytes {
            bytes: bytes.as_bytes().to_vec(),
            planned,
        },
        mode,
        ownership: Ownership::Owned(Mechanism::Own),
    }
}

/// A request to make `rel` under `home` a symlink holding `text`, owned
/// by bx, carrying what is there now as plan's observation.
pub(crate) fn link_to(home: &Path, rel: &str, text: &str) -> Request {
    let (target, dest) = target(home, rel);
    let planned = fs::observe(&dest).expect("plan's observation");
    Request {
        target,
        dest,
        content: Content::Link {
            text: PathBuf::from(text),
            planned,
        },
        mode: Mode::LINK,
        ownership: Ownership::Owned(Mechanism::Link),
    }
}

/// Create a file at exactly `mode`, parents included.
pub(crate) fn plant_file(path: &Path, bytes: &str, mode: Mode) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("the fixture's parents");
    }
    std::fs::write(path, bytes).expect("the fixture");
    fs::set_mode(path, mode).expect("the fixture's mode");
}

/// The bytes and mode at `path`, or `None` when nothing is there.
pub(crate) fn peek(path: &Path) -> Option<(Vec<u8>, Mode)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let bytes = std::fs::read(path).expect("a readable fixture");
    Some((bytes, Mode::from_bits(meta.permissions().mode())))
}

/// Whether a directory without write permission refuses this process.
///
/// It does not refuse root, so a test that needs a refused rename or
/// unlink cannot produce one there. A caller that finds `false` restores
/// whatever it broke and then calls [`crate::testing::cannot_build`], which
/// fails unless the skip was opted into.
pub(crate) fn permissions_refuse(dir: &Path) -> bool {
    let probe = dir.join("permission-probe");
    if std::fs::write(&probe, b"").is_err() {
        return true;
    }
    std::fs::remove_file(&probe).expect("remove the probe");
    false
}

/// Why a test that needs a refused write cannot run as this user.
pub(crate) const WRITES_THROUGH_PERMISSIONS: &str = "this process writes through file or directory permissions, so the \
         failure cannot be produced";

/// `PATH_MAX`, which counts the terminating NUL: 4096 on Linux, 1024 on
/// macOS.
pub(crate) const PATH_MAX: usize = if cfg!(target_os = "linux") {
    4096
} else {
    1024
};

/// A state directory, not yet created, whose files' paths fit [`PATH_MAX`]
/// and whose set-aside names do not.
///
/// Every [`crate::state::move_aside`] of its journal or ledger then fails
/// with ENAMETOOLONG, whoever the process runs as — "a name too long for a
/// quarantine suffix", as `state` puts it — while each can still be read,
/// written and locked. `fingerprints.mpk` is the one state file out of
/// reach.
pub(crate) fn state_beyond_set_aside_names(home: &crate::testing::GuardedHome) -> StateDir {
    const ROOT: usize = PATH_MAX - 16;
    let mut root = home.path().as_os_str().to_os_string();
    assert!(root.len() < ROOT - 256, "a home short enough to extend");
    while ROOT - root.len() > 256 {
        root.push(format!("/{}", "d".repeat(200)));
    }
    root.push(format!("/{}", "b".repeat(ROOT - root.len() - 1)));
    let state = StateDir::new(PathBuf::from(root));
    assert_eq!(state.root().as_os_str().len(), ROOT);
    for file in [state.journal(), state.ledger()] {
        assert!(file.as_os_str().len() < PATH_MAX, "{} fits", file.display());
        assert!(
            StateDir::quarantine(&file).as_os_str().len() >= PATH_MAX,
            "its set-aside name does not"
        );
    }
    state
}

/// The names in `dir`, sorted.
pub(crate) fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// A session header for a journal that needs one and does not care what it
/// says.
pub(super) fn some_begin() -> Begin {
    Begin {
        kind: SessionKind::Apply,
        home: PathBuf::from("/home/someone"),
        scope: Vec::new(),
    }
}

/// Where each whole frame in a journal's bytes starts.
pub(crate) fn frame_starts(bytes: &[u8]) -> Vec<usize> {
    let nonce = nonce_of(bytes);
    let mut starts = Vec::new();
    let mut at = HEADER;
    while let Ok((_, next)) = frame(bytes, at, &nonce) {
        starts.push(at);
        at = next;
    }
    starts
}

/// The nonce in a journal's header.
pub(crate) fn nonce_of(bytes: &[u8]) -> [u8; NONCE] {
    bytes[MAGIC.len() + 1..HEADER]
        .try_into()
        .expect("a whole header")
}

/// Write a journal exactly as given: a header, then each record as a frame.
///
/// For journals no session writes - one with no `Begin`, or one whose `End`
/// follows an Intent that has no `Done` - so recovery can be tested against
/// what damage or an earlier bx could leave behind.
pub(crate) fn raw_journal(path: &Path, records: &[Record]) {
    let nonce = fresh_nonce();
    let mut header = MAGIC.to_vec();
    header.push(FORMAT);
    header.extend_from_slice(&nonce);
    std::fs::write(path, &header).expect("write the header");
    let mut journal = Journal {
        file: OpenOptions::new()
            .append(true)
            .open(path)
            .expect("reopen the journal"),
        path: path.to_path_buf(),
        nonce,
    };
    for record in records {
        journal.append(record).expect("append");
    }
}

/// Append an `End` frame to an existing journal.
///
/// What [`Session::finish`] does *before* it saves the ledger — the one
/// window in which a crash leaves a terminated journal and a ledger that is
/// behind it.
pub(crate) fn seal(path: &Path, written: usize) {
    let mut journal = Journal {
        file: OpenOptions::new()
            .append(true)
            .open(path)
            .expect("reopen the journal"),
        path: path.to_path_buf(),
        nonce: nonce_of(&std::fs::read(path).expect("read the journal")),
    };
    journal
        .append(&Record::End(End { written }))
        .expect("append the End frame");
}

/// Every boundary the child can stop at, as `BX_CRASH_AT` spells it.
///
/// Spellings rather than [`Phase`] values, so the harness that drives this
/// can live in the module whose behaviour it is testing without the crash
/// seam having to become part of this module's surface.
pub(crate) fn crash_phases() -> [&'static str; PHASES.len()] {
    PHASES.map(Crash::name)
}

/// Every boundary inside [`Session::finish`], as `BX_CRASH_AT` spells it.
pub(crate) fn finish_crash_phases() -> [&'static str; FINISH_PHASES.len()] {
    FINISH_PHASES.map(Crash::name)
}

/// The Intent a session journals for creating `dest` holding `bytes`, owned
/// by bx: the base every test that needs another Intent builds on with
/// `..intent(..)`.
pub(crate) fn intent(target: &Portable, dest: &Path, bytes: &[u8]) -> Intent {
    Intent {
        target: target.clone(),
        dest: dest.to_path_buf(),
        temp: None,
        before: Prior::Absent,
        after: Written::Present {
            digest: ContentHash::of(bytes),
            mode: Mode::DEFAULT_FILE,
        },
        created_dirs: Vec::new(),
        mechanism: Some(Mechanism::Own),
        ledger_written: None,
        dir: false,
        link: false,
    }
}

/// An Intent that says bx created `dest` holding `bytes`.
pub(super) fn created(target: &Portable, dest: &Path, bytes: &[u8]) -> Record {
    Record::Intent(intent(target, dest, bytes))
}

/// The ledger as it stands on disk under `state`.
pub(super) fn saved_ledger(state: &StateDir, home: &Path) -> Ledger {
    let lock = ExclusiveLock::acquire(state).expect("lock");
    Ledger::open(state, &lock, home)
        .expect("open the ledger")
        .value
}

/// A directory request for `rel` under `home` at `mode`, carrying what is
/// there now as plan's observation.
pub(crate) fn dir_to(home: &Path, rel: &str, mode: Mode) -> Request {
    let (target, dest) = target(home, rel);
    let planned = fs::observe(&dest).expect("plan's observation");
    Request {
        target,
        dest,
        content: Content::Dir { planned },
        mode,
        ownership: Ownership::Owned(Mechanism::Dir),
    }
}

/// The mode of whatever is at `path`, or `None` when nothing is.
pub(crate) fn mode_at(path: &Path) -> Option<Mode> {
    std::fs::symlink_metadata(path)
        .ok()
        .map(|meta| Mode::from_bits(meta.permissions().mode()))
}

/// An apply session over `state`, for the account whose home is `home`,
/// scoped to nothing.
pub(crate) fn apply_session(state: &StateDir, home: &Path) -> Session {
    Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open")
}

/// Apply `requests` in one session and finish it.
pub(crate) fn applied(state: &StateDir, home: &Path, requests: Vec<Request>) {
    let mut session = apply_session(state, home);
    for request in requests {
        session.apply(request).expect("apply");
    }
    session.finish().expect("finish");
}

/// Apply `requests` in one session and abandon it without finishing, which
/// is exactly the state a crash leaves: a journal that stands, and a ledger
/// that does not yet know about any of it.
pub(crate) fn interrupted(state: &StateDir, home: &Path, requests: Vec<Request>) {
    let mut session = apply_session(state, home);
    for request in requests {
        session.apply(request).expect("apply");
    }
    drop(session);
}

/// A request to remove `rel` under `home`, releasing it, with the
/// directories bx created for it, carrying what is there now as plan's
/// observation.
pub(crate) fn remove_to(home: &Path, rel: &str, created_dirs: Vec<PathBuf>) -> Request {
    let (target, dest) = target(home, rel);
    let planned = fs::observe(&dest).expect("plan's observation");
    Request {
        target,
        dest,
        content: Content::Absent {
            created_dirs,
            planned,
        },
        mode: Mode::DEFAULT_FILE,
        ownership: Ownership::Released,
    }
}

/// The text at `path` when a symlink is there, following nothing.
pub(crate) fn link_at(path: &Path) -> Option<PathBuf> {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|meta| meta.file_type().is_symlink())
        .map(|_| std::fs::read_link(path).expect("a readable link"))
}
