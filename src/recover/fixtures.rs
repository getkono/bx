//! What the recovery tests share across its submodules: sessions
//! interrupted on purpose and the intents they journal.

use std::path::{Path, PathBuf};

use crate::fs::Mode;
use crate::journal::tests::{plant_file, target, write_to};
use crate::journal::{Intent, Request, Session, SessionKind, Written};
use crate::state::{ContentHash, Mechanism, Prior, StateDir};

/// Run a session and abandon it without finishing, which is exactly the
/// state a crash leaves: a journal that stands, and a ledger that does not
/// yet know about any of it.
pub(super) fn interrupted(state: &StateDir, home: &Path, requests: Vec<Request>) {
    let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
    for request in requests {
        session.apply(request).expect("apply");
    }
    drop(session);
}

/// An intent to create `rel` under `home`, as a session would journal it.
pub(super) fn intent_for(home: &Path, rel: &str) -> Intent {
    let (target, dest) = target(home, rel);
    Intent {
        target,
        dest,
        temp: None,
        before: Prior::Absent,
        after: Written::Present {
            digest: ContentHash::of(b"bx\n"),
            mode: Mode::DEFAULT_FILE,
        },
        created_dirs: Vec::new(),
        mechanism: Some(Mechanism::Own),
        ledger_written: None,
        dir: false,
        link: false,
    }
}

/// A session that modified `~/.conf` and died, and its journal's bytes.
pub(super) fn interrupted_modify(state: &StateDir, home: &Path) -> (PathBuf, Vec<u8>) {
    let dest = home.join(".conf");
    plant_file(&dest, "the user's original\n", Mode::DEFAULT_FILE);
    interrupted(
        state,
        home,
        vec![write_to(home, ".conf", "bx new\n", Mode::DEFAULT_FILE)],
    );
    (dest, std::fs::read(state.journal()).expect("the journal"))
}
