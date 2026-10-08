//! What the ledger tests share across its submodules: targets, entries and
//! priors to record, and a locked state directory to record them in.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::{Ledger, LedgerView, Mechanism, NewEntry, Prior, PriorBytes, RestoreRef};
use crate::fs::{Mode, write_atomically};
use crate::paths::Portable;
use crate::state::dir::StateDir;
use crate::state::hash::ContentHash;
use crate::state::lock::ExclusiveLock;
use crate::state::restore;
use crate::testing::GuardedHome;

pub(super) fn target(name: &str) -> Portable {
    Portable::try_from(name.to_string()).expect("a portable path")
}

pub(super) fn locked(home: &GuardedHome) -> (StateDir, ExclusiveLock) {
    let dir = StateDir::resolve(home.path());
    dir.ensure().expect("ensure");
    let lock = ExclusiveLock::acquire(&dir).expect("acquire");
    (dir, lock)
}

pub(super) fn entry(path: &str, body: &[u8]) -> NewEntry {
    NewEntry::new(
        target(path),
        ContentHash::of(body),
        Mode::DEFAULT_FILE,
        Mechanism::Own,
        PriorBytes::Absent,
    )
}

pub(super) fn mode_of(path: &Path) -> Mode {
    Mode::from_bits(std::fs::metadata(path).expect("stat").permissions().mode())
}

/// Bytes as a prior, at `mode`.
pub(super) fn prior(body: &[u8], mode: u32) -> PriorBytes {
    PriorBytes::Bytes {
        bytes: body.to_vec(),
        mode: Mode::from_bits(mode),
    }
}

/// Whether `restore/` holds a blob for `body`.
pub(super) fn has_blob(dir: &StateDir, body: &[u8]) -> bool {
    dir.restore().join(ContentHash::of(body).to_hex()).is_file()
}

/// Every blob name in `restore/`, sorted.
pub(super) fn blob_names(dir: &StateDir) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir.restore()) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// What `bx rm` does with an entry, reduced to the prior: unlink for
/// `Absent`, write the snapshot back for `Existed`.
pub(super) fn simulate_rm(dir: &StateDir, home: &GuardedHome, name: &str) {
    let view = LedgerView::read(dir, home.path()).expect("read").value;
    let stored = view.get(&target(name)).expect("entry");
    let dest = stored.path.render(home.path());
    match &stored.prior {
        Prior::Absent => std::fs::remove_file(&dest).expect("unlink"),
        Prior::Existed(reference) => {
            let bytes = restore::read(dir, reference).expect("restore bytes");
            write_atomically(&dest, &bytes, reference.mode).expect("restore");
        }
    }
}

/// One apply of `body` to `rel`, as the writer does it: observe what is
/// there, record it as the prior, then replace the file.
pub(super) fn apply(
    dir: &StateDir,
    lock: &ExclusiveLock,
    home: &GuardedHome,
    rel: &str,
    body: &[u8],
) {
    let dest = home.child(rel);
    let observed = match std::fs::read(&dest) {
        Ok(bytes) => PriorBytes::Bytes {
            bytes,
            mode: mode_of(&dest),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => PriorBytes::Absent,
        Err(e) => panic!("observing {}: {e}", dest.display()),
    };
    let mut ledger = Ledger::open(dir, lock, home.path()).expect("open").value;
    ledger
        .record(entry(&format!("~/{rel}"), body).with_prior(observed))
        .expect("record");
    std::fs::create_dir_all(dest.parent().expect("a parent")).expect("parents");
    write_atomically(&dest, body, Mode::DEFAULT_FILE).expect("write the target");
    ledger.save().expect("save");
}

pub(super) fn hex(body: &[u8]) -> String {
    ContentHash::of(body).to_hex()
}

pub(super) fn reference(body: &[u8], mode: u32) -> RestoreRef {
    RestoreRef {
        digest: ContentHash::of(body),
        mode: Mode::from_bits(mode),
        len: u64::try_from(body.len()).expect("len"),
    }
}

pub(super) fn sorted(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    names
}

/// `home/<rel>` as the absolute `Portable` a hand-edited or foreign ledger
/// would hold: well-formed, so it decodes, and under this home.
pub(super) fn absolute_under(home: &GuardedHome, rel: &str) -> Portable {
    Portable::from_path(&home.child(rel), Path::new("/nonexistent/other/home"))
        .expect("an absolute portable path")
}
