//! What the recovery tests share across its submodules: sessions
//! interrupted on purpose and the intents they journal.

use std::path::{Path, PathBuf};

use crate::fs::Mode;
use crate::journal::Intent;
pub(super) use crate::journal::tests::interrupted;
use crate::journal::tests::{intent, plant_file, target, write_to};
use crate::state::StateDir;

/// An intent to create `rel` under `home`, as a session would journal it.
pub(super) fn intent_for(home: &Path, rel: &str) -> Intent {
    let (target, dest) = target(home, rel);
    intent(&target, &dest, b"bx\n")
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
