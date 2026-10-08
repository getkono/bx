//! Carrying out recovery: the steps [`super::inspect::decide`] chose, the
//! ledger they rebuild, and the journal last of all.

use std::path::PathBuf;

use super::inspect::{Spelling, Step, decide, rebuild_home};
use super::{Error, Outcome};
use crate::fs::{self, remove};
use crate::journal::{self, Loaded, Written};
use crate::state::{ExclusiveLock, Ledger, StateDir};

/// The body of [`recover`](super::recover), with the lock already held.
pub(super) fn resolve(state: &StateDir, lock: &ExclusiveLock) -> Result<Outcome, Error> {
    let path = state.journal();
    let loaded = journal::load_exclusive(&path, lock)?;
    let complete = match loaded {
        Loaded::Absent | Loaded::Unreadable { .. } => return Ok(Outcome::Nothing),
        Loaded::Terminated(_) => true,
        Loaded::Unterminated(_) | Loaded::Torn { .. } => false,
    };
    // A journal that lost bytes is set aside at the end rather than unlinked.
    // The set-aside name is always free — the number after the highest
    // present, past any name taken since, or, once the top number is
    // present, the lowest free one — so nothing needs checking before the
    // rollback.
    let torn = matches!(loaded, Loaded::Torn { .. });
    let home = rebuild_home(&loaded, complete, &path)?;

    // Only a terminated journal's bookkeeping touches the ledger, and it is the
    // one kind with a home to check the ledger's stored paths against. A roll
    // back leaves the saved ledger exactly as it was, so it opens nothing.
    let mut ledger = match home {
        Some(home) => Some(Ledger::open(state, lock, home)?.value),
        None => None,
    };
    let mut conflicts = Vec::new();
    let mut resolved = 0_usize;
    // Every directory a target the terminated session dropped from the ledger
    // claimed. The session prunes a removal's after its `End` frame, so a crash
    // between the two leaves them standing. Handing on what still stands is
    // bookkeeping its save may not have reached; recovery removes none of them,
    // because a terminated session is never rolled back or finished on its
    // behalf, and one no entry is beneath is left for `bx doctor`, as
    // decision 11 keeps an orphaned temporary file.
    //
    // Owned rather than borrowed from the intents, because a dropped entry's
    // own claims are rendered here and belong to nobody else.
    let mut released: Vec<PathBuf> = Vec::new();

    let mut intents = loaded.landed();
    if !complete {
        // Reverse order, so a later write is undone before an earlier one it may
        // share a created directory with.
        intents.reverse();
    }
    for (intent, landed) in intents {
        let (step, report) = decide(
            state,
            intent,
            home,
            ledger.as_deref(),
            landed,
            Spelling::Absolute,
        )?;
        // A temporary file the journal names is this write's, and goes once
        // recovery is acting on the write at all: a blocked write is not
        // recovery's to touch, its temporary file included. The loader has
        // already refused a journal whose temporary file is not a `.bx-` file
        // beside its destination, and one the journal does not name is never
        // touched.
        //
        // One that cannot be removed — its directory has since stopped
        // letting this process write — is left, with a warning, and the
        // rollback goes on. Recovery never needs it: it holds bytes no
        // destination was ever given, which makes it the same kind of orphan
        // decision 11 keeps for `bx doctor`, and stopping every writing
        // command over it would make a leftover bx does not need a reason to
        // write nothing. `pending` names it in the write's note.
        //
        // Whether it was there to remove is what shows the directories the
        // Intent names were made: see `fs::remove::prune_beneath`.
        let mut temp_removed = None;
        if !complete
            && !matches!(step, Step::Blocked)
            && let Some(temp) = &intent.temp
        {
            let present = std::fs::symlink_metadata(temp).is_ok();
            match remove::unlink(temp).map_err(journal::Error::from) {
                Ok(()) if present => temp_removed = Some(temp),
                Ok(()) => {}
                Err(error) => tracing::warn!(
                    temp = %temp.display(),
                    %error,
                    "an interrupted write's temporary file could not be removed; \
                     it is left for bx doctor, and the rollback goes on",
                ),
            }
        }
        match step {
            Step::Blocked => {
                conflicts.push(report);
                continue;
            }
            Step::Skip => continue,
            // The Intent names its directories before they are made, so a
            // crash before the stage leaves it naming directories bx never
            // made, and the user may have made one since. Only a directory
            // that held this write's own temporary file, or the next
            // directory in that chain, is bx's to prune; with no temporary
            // file removed there is nothing to show any of them was made,
            // and every one is left.
            Step::Keep => {
                if intent.creates()
                    && let Some(temp) = temp_removed
                {
                    remove::prune_beneath(temp, &intent.created_dirs)?;
                }
            }
            // Both act against the observation `decide` judged, never a fresh
            // one: a destination the user edited after that look holds
            // neither recorded state, and is refused with
            // [`fs::Error::Changed`] rather than removed or overwritten. The
            // journal is kept, so the next run judges the edit as `decide`
            // judges any other, and blocks on it. What stays open is the
            // window between the last look and the `unlink` or `rename`
            // itself, as for `Session::remove` and [`fs::Filled::publish`].
            // A directory the session created goes only while it is empty,
            // and its parents after it: bx never removes what is inside one,
            // so an edit inside it since `decide` looked is never lost. Its
            // parents go only in the chain above what this rollback removed,
            // as for `Step::Keep`.
            Step::Unlink { .. } if intent.dir => {
                if remove::remove_made_dir(&intent.dest)? {
                    remove::prune_beneath(&intent.dest, &intent.created_dirs)?;
                }
            }
            Step::Unlink { observed } => {
                #[cfg(test)]
                tests::before_act(&intent.dest);
                fs::refuse_moved(&observed, &fs::observe(&intent.dest)?)
                    .map_err(journal::Error::from)?;
                remove::unlink(&intent.dest)?;
                remove::prune_beneath(&intent.dest, &intent.created_dirs)?;
            }
            Step::Rewrite {
                bytes,
                mode,
                observed,
            } => {
                #[cfg(test)]
                tests::before_act(&intent.dest);
                fs::stage(&intent.dest, mode, &observed, &mut fs::CreatedDirs::new())?
                    .commit(&bytes)?;
            }
            Step::Relink { text, observed } => {
                #[cfg(test)]
                tests::before_act(&intent.dest);
                fs::stage_link(&intent.dest, &text, &observed, &mut fs::CreatedDirs::new())?
                    .publish()
                    .map_err(fs::Unpublished::into_error)?;
            }
            // A directory's rollback acts against the observation `decide`
            // judged too: one whose mode or presence changed since is refused
            // with [`fs::Error::Changed`] rather than chmod'd or made over it.
            Step::Chmod { mode, observed } => {
                fs::refuse_moved(&observed, &fs::observe(&intent.dest)?)
                    .map_err(journal::Error::from)?;
                fs::set_mode(&intent.dest, mode)?;
            }
            Step::MakeDir { mode, observed } => {
                fs::ensure_dir(&intent.dest, mode, &observed, &mut fs::CreatedDirs::new())?;
            }
            // Rebuilding the bookkeeping touches no destination, so it is not
            // work `plan` failed to announce: the ledger is machine state, not
            // the user's.
            Step::Record(entry) => {
                if let Some(ledger) = ledger.as_mut() {
                    ledger.record(entry)?;
                }
            }
            Step::Forget => {
                let dropped = ledger
                    .as_mut()
                    .and_then(|ledger| ledger.forget(&intent.target));
                if intent.after == Written::Absent {
                    released.extend(intent.created_dirs.iter().cloned());
                    // A directory target's removal released the directory
                    // itself too.
                    if intent.dir {
                        released.push(intent.dest.clone());
                    }
                }
                // The entry's *own* claims, which are not always the Intent's.
                // A removal's Intent carries them, because `plan_restore` takes
                // them from the entry; a released write's does not — it records
                // only the directories that write invented, which is none. The
                // replay path drops the same entry `Session::write` drops, so
                // it has to carry the same claim on, or a crash turns a
                // hand-off into a loss. See `r3 round 4` decision R3R4-1.
                if let (Some(dropped), Some(home)) = (dropped, home) {
                    released.extend(dropped.created_dirs.iter().map(|dir| dir.render(home)));
                }
            }
        }
        resolved += 1;
    }
    // Blocked first, and *before* the hand-off. r3 coverage COV4: the
    // hand-off used to stand ahead of this return behind a
    // `conflicts.is_empty()` guard, and deleting that guard changed no
    // assertion — a blocked run saves no ledger, so the mutation it protected
    // against was invisible and the arm's correctness rested on the drop.
    // Returning first is the same behaviour with the ordering as the
    // guarantee: past this point there are no conflicts, so nothing has to say
    // so a second time.
    if !conflicts.is_empty() {
        tracing::error!(
            blocked = conflicts.len(),
            journal = %path.display(),
            "recovery is blocked; the journal is kept and bx will not write until it is resolved",
        );
        return Ok(Outcome::Blocked { conflicts });
    }

    if let (Some(ledger), Some(home)) = (ledger.as_mut(), home) {
        ledger
            .hand_off_claims(home, &released)
            .map_err(journal::Error::from)?;
    }

    if let Some(ledger) = &mut ledger {
        ledger.save()?;
    }
    // Last of all, and only once every step has succeeded. This is the rule that
    // makes recovery re-runnable without a journal of its own. A journal bytes
    // were discarded from is kept: they may have been a frame that damage, not a
    // crash, cut short, and the file is the only record of what it hid.
    if torn {
        let aside = journal::set_aside(&path, lock)?;
        tracing::warn!(
            path = %path.display(),
            moved_to = %aside.display(),
            "the recovered journal ended in bytes that were not a whole frame; \
             it was kept rather than deleted",
        );
    } else {
        remove::unlink(&path)?;
    }

    Ok(if complete {
        tracing::info!(
            entries = resolved,
            "brought the ledger up to date after an interruption"
        );
        Outcome::Recorded { entries: resolved }
    } else {
        tracing::info!(undone = resolved, "rolled back an interrupted bx session");
        Outcome::RolledBack { undone: resolved }
    })
}

#[cfg(test)]
mod tests {

    use crate::recover::fixtures::*;
    use crate::recover::*;

    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use crate::fs::{self, Mode};
    use crate::journal::tests::{
        crash_phases, dir_to, finish_crash_phases, link_at, link_to, names_in, peek, plant_file,
        seal, target, write_to,
    };
    use crate::journal::{
        self, Content, Intent, Ownership, Record, Request, Session, SessionKind, Written,
    };
    use crate::paths::Portable;

    use crate::state::{ContentHash, LedgerView, Mechanism, Prior, StateDir};
    use crate::testing::guarded_home;

    thread_local! {
        /// What a test does to a destination between `decide`'s look and the
        /// rollback acting on it. Per thread, so tests running in parallel
        /// never see each other's.
        static BEFORE_ACT: std::cell::Cell<Option<fn(&Path)>> =
            const { std::cell::Cell::new(None) };
    }

    /// The seam [`resolve`] calls before an `Unlink` or a `Rewrite` acts.
    pub(super) fn before_act(dest: &Path) {
        if let Some(meddle) = BEFORE_ACT.with(std::cell::Cell::get) {
            meddle(dest);
        }
    }

    /// Recover with `meddle` run on each destination a rollback is about to
    /// unlink or rewrite, after `decide` has judged it.
    fn recover_meddled(state: &StateDir, meddle: fn(&Path)) -> Result<Outcome, Error> {
        BEFORE_ACT.with(|cell| cell.set(Some(meddle)));
        let outcome = recover(state);
        BEFORE_ACT.with(|cell| cell.set(None));
        outcome
    }

    /// An editor's save: a sibling renamed over the destination.
    fn editors_save(dest: &Path) {
        let sibling = dest.with_file_name(".bx-test-edit~");
        std::fs::write(&sibling, "the user's edit\n").expect("write the sibling");
        std::fs::rename(&sibling, dest).expect("rename it over");
    }

    #[test]
    fn an_edit_after_recovery_judged_a_create_is_not_unlinked() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".made");
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".made", "made\n", Mode::DEFAULT_FILE)],
        );

        let err = recover_meddled(&state, editors_save).expect_err("the edit is refused");
        assert!(
            matches!(
                err,
                Error::Journal(journal::Error::Write(fs::Error::Changed { .. }))
            ),
            "got {err}",
        );
        assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's edit\n");
        // The journal stands, and the next run blocks on the edit.
        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. }
        ));
        assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's edit\n");
    }

    #[test]
    fn an_edit_after_recovery_judged_a_modify_is_not_overwritten() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "before\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                ".conf",
                "after\n",
                Mode::DEFAULT_FILE,
            )],
        );

        let err = recover_meddled(&state, editors_save).expect_err("the edit is refused");
        assert!(
            matches!(err, Error::Write(fs::Error::Changed { .. })),
            "got {err}"
        );
        assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's edit\n");
        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. }
        ));
        assert_eq!(std::fs::read(&dest).expect("kept"), b"the user's edit\n");
    }

    // ---------------------------------------------------------------------
    // The crash harness.
    //
    // The child is this very test binary, re-invoked, aborting at a chosen
    // write boundary. `abort` terminates without unwinding, without running a
    // destructor and without flushing a buffer, which is what process death
    // does and what an `Err` return does not. An in-process seam that returned
    // `Err` would test error handling; the failure this entry exists to survive
    // is the process ceasing to exist between two syscalls.
    //
    // What it models, and what it does not: killing a process models process
    // death at an arbitrary boundary. It does **not** model media loss, because
    // page-cache contents survive process death. Media loss is covered
    // structurally instead, by the `fsync` discipline in `Session::apply` and by
    // `the_intent_is_durable_before_the_destination_is_touched`, which pins the
    // ordering that discipline exists to guarantee.
    // ---------------------------------------------------------------------

    /// The home the crash child builds its fixture under.
    ///
    /// Passed per-command with `Command::env`: no test in this crate sets a
    /// variable in its own process.
    const CRASH_HOME: &str = "BX_CRASH_HOME";

    /// The variable the crash seam reads, once, at `Session::open`.
    const CRASH_AT: &str = "BX_CRASH_AT";

    /// The four requests the crash child makes, in the order it makes them: a
    /// modify at a non-default mode, a create in a directory bx must invent, a
    /// plain modify, and a removal of a private file from a private directory
    /// the removal claims as one bx created.
    fn crash_requests(home: &Path) -> Vec<Request> {
        vec![
            write_to(home, ".bxrc", "after bx\n", Mode::PRIVATE_FILE),
            write_to(
                home,
                ".config/bx-crash/made.conf",
                "made\n",
                Mode::DEFAULT_FILE,
            ),
            write_to(
                home,
                ".gitconfig",
                "[user]\n\tname = after\n",
                Mode::DEFAULT_FILE,
            ),
            {
                let (target, dest) = target(home, ".vault/gone.conf");
                // Observed when the request is built, as `write_to` observes.
                let planned = fs::observe(&dest).expect("plan's observation");
                Request {
                    target,
                    dest,
                    content: Content::Absent {
                        created_dirs: vec![home.join(".vault")],
                        planned,
                    },
                    mode: Mode::PRIVATE_FILE,
                    ownership: Ownership::Released,
                }
            },
        ]
    }

    /// What exists before the crashing session runs.
    fn plant_crash_fixture(home: &Path) {
        std::fs::create_dir_all(home).expect("the crash home");
        plant_file(&home.join(".bxrc"), "before bx\n", Mode::PRIVATE_FILE);
        plant_file(
            &home.join(".gitconfig"),
            "[user]\n\tname = before\n",
            Mode::DEFAULT_FILE,
        );
        plant_file(
            &home.join(".vault/gone.conf"),
            "bx made this\n",
            Mode::PRIVATE_FILE,
        );
        // A directory the user made private after bx created it: a rollback
        // that re-created it would do so at the default mode.
        fs::set_mode(&home.join(".vault"), Mode::PRIVATE_DIR).expect("chmod ~/.vault");
        // `~/.config` deliberately does not exist: the middle write has to
        // invent two directories, and a rollback has to remove both.
    }

    /// The bytes and mode at one destination, or `None` where nothing is.
    type FileState = Option<(Vec<u8>, Mode)>;

    /// What the crash harness compares before and after: bytes and mode at
    /// each destination, and the mode of each directory between a
    /// destination and the home — the ones a write invents and the ones a
    /// removal claims — or `None` where there is none.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Snapshot {
        files: Vec<(PathBuf, FileState)>,
        dirs: Vec<(PathBuf, Option<Mode>)>,
    }

    /// The mode of the directory at `path`, following no link, or `None`
    /// when no directory is there.
    fn dir_mode(path: &Path) -> Option<Mode> {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::symlink_metadata(path)
            .ok()
            .filter(std::fs::Metadata::is_dir)
            .map(|meta| Mode::from_bits(meta.permissions().mode() & 0o7777))
    }

    /// The crash harness's snapshot of `home`.
    fn crash_snapshot(home: &Path) -> Snapshot {
        let requests = crash_requests(home);
        let mut dirs: Vec<PathBuf> = requests
            .iter()
            .flat_map(|request| {
                request
                    .dest
                    .ancestors()
                    .skip(1)
                    .take_while(|dir| *dir != home)
                    .map(Path::to_path_buf)
                    .collect::<Vec<_>>()
            })
            .collect();
        dirs.sort();
        dirs.dedup();
        Snapshot {
            files: requests
                .into_iter()
                .map(|request| (request.dest.clone(), peek(&request.dest)))
                .collect(),
            dirs: dirs
                .into_iter()
                .map(|dir| {
                    let mode = dir_mode(&dir);
                    (dir, mode)
                })
                .collect(),
        }
    }

    /// Every path under `root`, files and directories alike.
    fn walk(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path.clone());
                }
                found.push(path);
            }
        }
        found.sort();
        found
    }

    /// Every leftover bx temporary file under `root`.
    fn leftover_temps(root: &Path) -> Vec<PathBuf> {
        walk(root)
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(fs::TEMP_PREFIX))
            })
            .collect()
    }

    /// Re-invoke this test binary, crashing at `phase` of write `index`.
    fn spawn_crash_child(home: &Path, index: usize, phase: &str) -> Output {
        spawn_child("recover::rollback::tests::crash_child", home, index, phase)
    }

    /// Re-invoke this test binary to run the ignored test `child`, crashing
    /// at `phase` of write `index`.
    fn spawn_child(child: &str, home: &Path, index: usize, phase: &str) -> Output {
        let exe = std::env::current_exe().expect("the test binary");
        Command::new(exe)
            .args(["--exact", "--ignored", "--nocapture", child])
            .env(CRASH_AT, format!("{index}:{phase}"))
            .env(CRASH_HOME, home)
            // cargo-llvm-cov points this at a pattern the parent owns. The child
            // is going to abort, so it would write no profile anyway; removing
            // it makes that independent of how coverage is configured.
            .env_remove("LLVM_PROFILE_FILE")
            .output()
            .expect("spawn the crash child")
    }

    /// The crashing half of the harness.
    ///
    /// Ignored, so an ordinary `cargo test` never runs it and never aborts the
    /// suite, and a bare `cargo test -- --ignored` finds no `BX_CRASH_HOME` and
    /// returns without doing anything. It is given its home explicitly, per
    /// process, and sets no variable of its own.
    #[test]
    #[ignore = "spawned by the crash harness; it aborts on purpose"]
    fn crash_child() {
        let Some(home) = std::env::var_os(CRASH_HOME) else {
            return;
        };
        let home = PathBuf::from(home);
        let state = StateDir::resolve(&home);
        let mut session =
            Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
        for request in crash_requests(&home) {
            session.apply(request).expect("apply");
        }
        session.finish().expect("finish");
    }

    /// The three link requests the link crash child makes, in order: a
    /// retarget of a link bx made, a create in directories bx must invent, and
    /// the removal `rm` makes of a link bx made.
    fn link_requests(home: &Path) -> Vec<Request> {
        vec![
            link_to(home, ".local/bin/tool", "/opt/tool/bin/tool"),
            link_to(home, ".config/bx-links/made", "../../nowhere/made"),
            {
                let (target, dest) = target(home, ".gone");
                let planned = fs::observe(&dest).expect("plan's observation");
                Request {
                    target,
                    dest,
                    content: Content::LinkAbsent {
                        created_dirs: Vec::new(),
                        planned,
                    },
                    mode: Mode::LINK,
                    ownership: Ownership::Released,
                }
            },
        ]
    }

    /// What exists before the crashing link session runs: the two links bx
    /// made earlier, and no `~/.config`.
    fn plant_link_fixture(home: &Path) {
        std::fs::create_dir_all(home.join(".local/bin")).expect("the link fixture's parents");
        std::os::unix::fs::symlink("../src/tool", home.join(".local/bin/tool")).expect("a link");
        std::os::unix::fs::symlink("bx made this", home.join(".gone")).expect("a link");
    }

    /// What the link crash harness compares: the text at each destination, or
    /// `None` where no link is, and whether `~/.config` is there.
    fn link_snapshot(home: &Path) -> (Vec<Option<PathBuf>>, bool) {
        (
            link_requests(home)
                .iter()
                .map(|request| link_at(&request.dest))
                .collect(),
            home.join(".config").exists(),
        )
    }

    /// The crashing half of [`a_crash_at_every_link_boundary_is_recoverable`].
    #[test]
    #[ignore = "spawned by the link crash harness; it aborts on purpose"]
    fn link_crash_child() {
        let Some(home) = std::env::var_os(CRASH_HOME) else {
            return;
        };
        let home = PathBuf::from(home);
        let state = StateDir::resolve(&home);
        let mut session =
            Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
        for request in link_requests(&home) {
            session.apply(request).expect("apply");
        }
        session.finish().expect("finish");
    }

    #[test]
    fn a_crash_at_every_link_boundary_is_recoverable() {
        let guard = guarded_home();
        for index in 0..link_requests(guard.path()).len() {
            for phase in crash_phases() {
                let removal = matches!(
                    link_requests(guard.path())[index].content,
                    Content::LinkAbsent { .. }
                );
                if removal && matches!(phase, "after-stage" | "after-fill") {
                    continue;
                }
                let case = format!("{index}:{phase}");
                let home = guard.child(format!("link-crash-{index}-{phase}"));
                plant_link_fixture(&home);
                let before = link_snapshot(&home);

                let out = spawn_child(
                    "recover::rollback::tests::link_crash_child",
                    &home,
                    index,
                    phase,
                );
                assert!(
                    !out.status.success(),
                    "{case}: the child was supposed to die; it said {}",
                    String::from_utf8_lossy(&out.stdout),
                );

                // The old link or the new one, never anything else.
                for (request, (found, was)) in link_requests(&home)
                    .iter()
                    .zip(link_snapshot(&home).0.into_iter().zip(before.0.clone()))
                {
                    let new = match &request.content {
                        Content::Link { text, .. } => Some(text.clone()),
                        _ => None,
                    };
                    assert!(found == was || found == new, "{case}: {found:?}");
                }

                let state = StateDir::resolve(&home);
                let interrupted = pending(&state)
                    .expect("pending")
                    .expect("a crash leaves an interrupted session");
                assert!(interrupted.blocked().next().is_none(), "{case}");
                assert!(
                    matches!(
                        recover(&state).expect("recover"),
                        Outcome::RolledBack { .. }
                    ),
                    "{case}"
                );
                // As for a file: the Intent names the temporary link and the
                // directories made for it before either exists, so the
                // rollback leaves neither at any boundary (#119).
                let (links, config) = link_snapshot(&home);
                assert_eq!(links, before.0, "{case}: not rolled back");
                assert_eq!(config, before.1, "{case}: ~/.config stands");
                let temps = leftover_temps(&home);
                assert!(temps.is_empty(), "{case}: {temps:?}");
            }
        }
    }

    #[test]
    fn a_terminated_link_session_is_recorded_as_a_link() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let request = link_to(home.path(), ".tool", "/opt/tool");
        let portable = request.target.clone();
        interrupted(&state, home.path(), vec![request]);
        seal(&state.journal(), 1);

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 }
        );
        let entry = LedgerView::read(&state, home.path())
            .expect("ledger")
            .value
            .get(&portable)
            .cloned()
            .expect("recorded");
        assert_eq!(entry.mechanism, Mechanism::Link);
        assert_eq!(entry.written, fs::link::digest(Path::new("/opt/tool")));
        assert_eq!(entry.mode, Mode::LINK);
    }

    /// A directory's earlier state is its mode, never a snapshot to read:
    /// rolling forward a terminated chmod of one records that mode even with
    /// the empty blob gone from `restore/`, where a file's missing snapshot
    /// would block it.
    #[test]
    fn a_terminated_directory_session_records_its_earlier_mode_without_a_snapshot() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".vault");
        std::fs::create_dir(&dest).expect("the prior directory");
        fs::set_mode(&dest, Mode::DEFAULT_DIR).expect("its prior mode");
        let request = dir_to(home.path(), ".vault", Mode::PRIVATE_DIR);
        let portable = request.target.clone();
        interrupted(&state, home.path(), vec![request]);
        seal(&state.journal(), 1);
        let empty = state.restore().join(crate::state::dir_digest().to_hex());
        std::fs::remove_file(&empty).expect("delete the empty blob");

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 }
        );
        let entry = LedgerView::read(&state, home.path())
            .expect("ledger")
            .value
            .get(&portable)
            .cloned()
            .expect("recorded");
        assert_eq!(entry.mechanism, Mechanism::Dir);
        assert_eq!(entry.mode, Mode::PRIVATE_DIR);
        let Prior::Existed(reference) = entry.prior else {
            panic!("the directory was there before: {:?}", entry.prior);
        };
        assert_eq!(reference.mode, Mode::DEFAULT_DIR);
    }

    /// The crashing half of [`a_killed_rm_rolls_back_into_the_directory_it_found`]:
    /// `rm` of `~/.vault/key.conf`, which bx created with `~/.vault`.
    #[test]
    #[ignore = "spawned by a crash test; it aborts on purpose"]
    fn rm_crash_child() {
        let Some(home) = std::env::var_os(CRASH_HOME) else {
            return;
        };
        let home = PathBuf::from(home);
        let state = StateDir::resolve(&home);
        let key = Portable::from_path(&home.join(".vault/key.conf"), &home).expect("portable");
        // Its outcome is the parent's to judge, from what the crash left.
        let _ = crate::restore::restore(&state, &home, &[key]);
    }

    #[test]
    fn a_killed_rm_rolls_back_into_the_directory_it_found() {
        // r3 round 2, P9R4-D2. A removal pruned the directories it claimed
        // before its session's `End`, so a rollback re-created `~/.vault` at
        // the default mode after the user had made it `0700`. Pruning now
        // waits for `End`; a crash between the two leaves the directory,
        // empty, for `bx doctor`.
        let guard = guarded_home();
        for (index, phase) in [
            (0, "after-intent"),
            (0, "after-publish"),
            (0, "after-done"),
            (1, "after-end"),
            (1, "after-save"),
        ] {
            let case = format!("{index}:{phase}");
            let home = guard.child(format!("rm-{index}-{phase}"));
            let state = StateDir::resolve(&home);
            let vault = home.join(".vault");
            let mut session =
                Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
            let request = write_to(&home, ".vault/key.conf", "secret\n", Mode::PRIVATE_FILE);
            let key = request.target.clone();
            session
                .apply(request)
                .expect("bx creates ~/.vault/key.conf");
            session.finish().expect("finish");
            fs::set_mode(&vault, Mode::PRIVATE_DIR).expect("the user makes ~/.vault private");

            let out = spawn_child(
                "recover::rollback::tests::rm_crash_child",
                &home,
                index,
                phase,
            );
            assert!(
                !out.status.success(),
                "{case}: the child was supposed to die; it said {}",
                String::from_utf8_lossy(&out.stdout),
            );
            let after_kill = dir_mode(&vault);
            let report = pending(&state).expect("pending").expect("a journal stands");
            assert!(report.blocked().next().is_none(), "{case}");
            let note = report.unfinished[0].note.clone();
            let outcome = recover(&state).expect("the next writing run");
            assert!(!state.journal().exists(), "{case}");
            let entry = LedgerView::read(&state, &home)
                .expect("read the ledger")
                .value
                .get(&key)
                .cloned();

            if index == 0 {
                assert_eq!(outcome, Outcome::RolledBack { undone: 1 }, "{case}");
                assert_eq!(
                    peek(&home.join(".vault/key.conf")),
                    Some((b"secret\n".to_vec(), Mode::PRIVATE_FILE)),
                    "{case}"
                );
                assert_eq!(
                    dir_mode(&vault),
                    Some(Mode::PRIVATE_DIR),
                    "{case}: rolled back into the directory the rm found, at its mode"
                );
                assert_eq!(
                    after_kill,
                    Some(Mode::PRIVATE_DIR),
                    "{case}: nothing is pruned before End"
                );
                assert!(entry.is_some(), "{case}: bx still manages it");
                assert!(!note.contains("bx doctor"), "{case}: {note}");
            } else if phase == "after-end" {
                assert_eq!(outcome, Outcome::Recorded { entries: 1 }, "{case}");
                assert_eq!(after_kill, Some(Mode::PRIVATE_DIR), "{case}");
                assert!(
                    note.contains(
                        "before it removed ~/.vault, which stand empty and are left for bx doctor"
                    ),
                    "{case}: {note}"
                );
                assert_eq!(
                    dir_mode(&vault),
                    Some(Mode::PRIVATE_DIR),
                    "{case}: recovery removes no directory"
                );
                assert_eq!(names_in(&vault), Vec::<String>::new(), "{case}");
                assert!(entry.is_none(), "{case}: the removal is recorded");
                assert!(
                    LedgerView::read(&state, &home)
                        .expect("read the ledger")
                        .value
                        .iter()
                        .all(|(_, entry)| entry.created_dirs.is_empty()),
                    "{case}: no entry claims the orphan"
                );
            } else {
                assert_eq!(outcome, Outcome::Recorded { entries: 1 }, "{case}");
                assert_eq!(after_kill, None, "{case}: pruned before the save");
                assert!(!note.contains("bx doctor"), "{case}: {note}");
                assert!(entry.is_none(), "{case}");
            }
            assert_eq!(recover(&state).expect("again"), Outcome::Nothing);
        }
    }

    #[test]
    fn the_intent_is_durable_before_the_destination_is_touched() {
        let guard = guarded_home();

        // Stopping one boundary *before* the intent: nothing is recorded, and
        // the destination is untouched.
        let early = guard.child("early");
        plant_crash_fixture(&early);
        assert!(
            !spawn_crash_child(&early, 0, "before-stage")
                .status
                .success()
        );
        let loaded = crate::journal::load(&StateDir::resolve(&early).journal()).expect("load");
        assert_eq!(
            loaded.intents().count(),
            0,
            "no intent had been written yet"
        );
        assert_eq!(
            peek(&early.join(".bxrc")).expect("the destination").0,
            b"before bx\n",
            "and the destination had not been touched",
        );

        // Stopping one boundary *after* it: the frame is on disk and fsynced,
        // and the destination is *still* untouched. The whole recoverability
        // argument lives in that gap.
        let late = guard.child("late");
        plant_crash_fixture(&late);
        assert!(!spawn_crash_child(&late, 0, "after-intent").status.success());
        let loaded = crate::journal::load(&StateDir::resolve(&late).journal()).expect("load");
        let intents: Vec<&Intent> = loaded.intents().collect();
        assert_eq!(intents.len(), 1, "the intent is durable");
        assert_eq!(intents[0].dest, late.join(".bxrc"));
        // The intent precedes the stage (#119): it names a temporary file
        // nothing has made yet, so a crash anywhere from here on leaves
        // nothing the journal does not name.
        let temp = intents[0].temp.as_ref().expect("a named temp");
        assert_eq!(temp.parent(), Some(late.as_path()));
        assert!(!temp.exists(), "the intent is durable before the stage");
        assert_eq!(
            peek(&late.join(".bxrc")).expect("the destination").0,
            b"before bx\n",
            "and the destination is still what it was",
        );
        assert!(matches!(
            recover(&StateDir::resolve(&late)).expect("recover"),
            Outcome::RolledBack { .. }
        ));
        assert!(leftover_temps(&late).is_empty());
    }

    #[test]
    fn a_crash_while_filling_leaves_no_directory_the_write_made() {
        // #119. A write whose parents are missing, stopped once its temporary
        // file and those parents exist and before any content does: the
        // journal names both, so the rollback removes the one and prunes the
        // others, and the home is as it was.
        let guard = guarded_home();
        let home = guard.child("deep");
        plant_crash_fixture(&home);
        let before = crash_snapshot(&home);
        let index = crash_requests(&home)
            .iter()
            .position(|request| {
                matches!(request.content, Content::Bytes { .. })
                    && !request.dest.parent().expect("a parent").exists()
            })
            .expect("the fixture writes beneath a directory it has to make");
        assert!(
            !spawn_crash_child(&home, index, "after-stage")
                .status
                .success()
        );

        let state = StateDir::resolve(&home);
        let loaded = crate::journal::load(&state.journal()).expect("load");
        let intent = loaded.intents().last().expect("the write's intent");
        let temp = intent.temp.clone().expect("a staged temp");
        assert!(temp.is_file(), "the stage made it");
        assert!(!intent.created_dirs.is_empty(), "and named what it made");
        assert!(intent.created_dirs.iter().all(|dir| dir.is_dir()));

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { .. }
        ));
        assert!(leftover_temps(&home).is_empty(), "the temp file is gone");
        assert!(
            intent.created_dirs.iter().all(|dir| !dir.exists()),
            "and every directory the write made",
        );
        assert_eq!(crash_snapshot(&home), before);
    }

    #[test]
    fn a_directory_the_user_made_after_a_crash_before_the_stage_is_left() {
        // The Intent names its directories before the stage makes them, so a
        // crash between the two leaves it naming directories bx never made.
        // The user makes them afterwards, empty: nothing of bx's is in them,
        // so nothing shows bx made them, and the rollback leaves every one.
        let guard = guarded_home();
        let home = guard.child("deep");
        plant_crash_fixture(&home);
        let index = crash_requests(&home)
            .iter()
            .position(|request| {
                matches!(request.content, Content::Bytes { .. })
                    && !request.dest.parent().expect("a parent").exists()
            })
            .expect("the fixture writes beneath a directory it has to make");
        assert!(
            !spawn_crash_child(&home, index, "after-intent")
                .status
                .success()
        );

        let state = StateDir::resolve(&home);
        let loaded = crate::journal::load(&state.journal()).expect("load");
        let intent = loaded.intents().last().expect("the write's intent");
        assert!(!intent.created_dirs.is_empty(), "the Intent predicted them");
        assert!(
            intent.created_dirs.iter().all(|dir| !dir.exists()),
            "and the crash came before the stage made any",
        );
        for dir in intent.created_dirs.iter().rev() {
            std::fs::create_dir(dir).expect("the user makes it");
        }

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { .. }
        ));
        assert!(
            intent.created_dirs.iter().all(|dir| dir.is_dir()),
            "the user's directories are left",
        );
    }

    #[test]
    fn a_predicted_directory_without_the_named_temp_file_is_left_even_when_empty() {
        // Emptiness is not the evidence, the temporary file is. With it gone
        // before the rollback, the deepest predicted directory stands empty
        // and holds nothing of bx's, so it and every directory above it are
        // left for `bx doctor`, exactly as a directory the user made would be.
        let guard = guarded_home();
        let home = guard.child("deep");
        plant_crash_fixture(&home);
        let index = crash_requests(&home)
            .iter()
            .position(|request| {
                matches!(request.content, Content::Bytes { .. })
                    && !request.dest.parent().expect("a parent").exists()
            })
            .expect("the fixture writes beneath a directory it has to make");
        assert!(
            !spawn_crash_child(&home, index, "after-stage")
                .status
                .success()
        );
        let state = StateDir::resolve(&home);
        let loaded = crate::journal::load(&state.journal()).expect("load");
        let intent = loaded.intents().last().expect("the write's intent");
        let temp = intent.temp.clone().expect("a staged temp");
        assert_eq!(temp.parent(), Some(intent.created_dirs[0].as_path()));
        std::fs::remove_file(&temp).expect("the temp goes");

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { .. }
        ));
        assert!(intent.created_dirs.iter().all(|dir| dir.is_dir()));
    }

    #[test]
    fn a_target_left_at_the_new_bytes_rolls_back_to_the_prior_bytes() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        assert_eq!(peek(&dest).expect("written").0, b"new\n");

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished.len(), 1);
        assert_eq!(interruption.unfinished[0].standing, Standing::Written);
        assert_eq!(interruption.kind, SessionKind::Apply);

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(
            peek(&dest).expect("restored"),
            (b"old\n".to_vec(), Mode::DEFAULT_FILE),
        );
        assert!(!state.journal().exists(), "the journal is unlinked last");
    }

    #[test]
    fn a_second_write_to_the_same_target_rolls_back_to_what_it_actually_displaced() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "the user's\n", Mode::DEFAULT_FILE);

        let mut first =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        first
            .apply(write_to(home.path(), ".conf", "one\n", Mode::DEFAULT_FILE))
            .expect("apply");
        first.finish().expect("finish");

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "two\n", Mode::DEFAULT_FILE)],
        );

        // Not "the user's", which is what the ledger's first-prior rule keeps:
        // a rollback returns the destination to the state the last *finished*
        // run left it in, so the next plan is computed against what the user
        // last saw converge.
        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished[0].standing, Standing::Written);
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(peek(&dest).expect("rolled back").0, b"one\n");

        // And `bx rm` still hands back what the user had before bx existed.
        assert!(matches!(
            crate::restore::restore(&state, home.path(), &[target(home.path(), ".conf").0])
                .expect("restore")
                .as_slice(),
            [crate::restore::Restored::Reverted { .. }],
        ));
        assert_eq!(peek(&dest).expect("restored").0, b"the user's\n");
    }

    #[test]
    fn roll_back_restores_the_prior_mode() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".ssh-config");
        plant_file(&dest, "Host *\n", Mode::PRIVATE_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                ".ssh-config",
                "Host *\n",
                Mode::DEFAULT_FILE,
            )],
        );
        assert_eq!(peek(&dest).expect("written").1, Mode::DEFAULT_FILE);

        recover(&state).expect("recover");
        assert_eq!(
            peek(&dest).expect("restored"),
            (b"Host *\n".to_vec(), Mode::PRIVATE_FILE),
            "the same bytes at a different mode is still a change to undo",
        );
    }

    #[test]
    fn a_target_left_at_the_prior_bytes_rolls_back_to_a_no_op() {
        let guard = guarded_home();
        let home = guard.child("crashed");
        plant_crash_fixture(&home);
        let before = crash_snapshot(&home);

        // Dying one boundary after the intent is durable: the destination has
        // not been replaced yet, so the rollback has nothing to write.
        assert!(
            !spawn_crash_child(&home, 0, "after-intent").status.success(),
            "the child was supposed to die",
        );
        let state = StateDir::resolve(&home);
        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert_eq!(interruption.unfinished[0].standing, Standing::Prior);

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert_eq!(crash_snapshot(&home), before);
    }

    #[test]
    fn a_target_the_session_created_is_removed_not_emptied_by_roll_back() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".config/deep/made.conf");

        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                ".config/deep/made.conf",
                "made\n",
                Mode::DEFAULT_FILE,
            )],
        );
        assert!(dest.is_file());

        recover(&state).expect("recover");
        assert!(!dest.exists(), "removed, never left as an empty file");
        assert!(!home.child(".config/deep").exists());
        assert!(
            !home.child(".config").exists(),
            "and the parents it invented",
        );
    }

    #[test]
    fn directories_the_session_created_are_removed_only_while_empty() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());

        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                ".config/deep/made.conf",
                "made\n",
                Mode::DEFAULT_FILE,
            )],
        );
        // The user put something of their own in the directory bx invented.
        std::fs::write(home.child(".config/deep/theirs"), "mine").expect("write");

        recover(&state).expect("recover");
        assert!(!home.child(".config/deep/made.conf").exists());
        assert!(
            home.child(".config/deep/theirs").is_file(),
            "a byte the user wrote is never removed",
        );
        assert!(home.child(".config/deep").is_dir());
        assert!(home.child(".config").is_dir(), "and the walk stopped there");
    }

    #[test]
    fn roll_back_undoes_completed_writes_too() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".one"), "one\n", Mode::DEFAULT_FILE);
        plant_file(&home.child(".two"), "two\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![
                write_to(home.path(), ".one", "ONE\n", Mode::DEFAULT_FILE),
                write_to(home.path(), ".two", "TWO\n", Mode::DEFAULT_FILE),
            ],
        );
        // Both reached `Done`; the journal is a transaction, not a tail.
        let loaded = crate::journal::load(&state.journal()).expect("load");
        assert_eq!(
            loaded
                .records()
                .iter()
                .filter(|record| matches!(record, Record::Done(_)))
                .count(),
            2,
        );

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 2 },
        );
        assert_eq!(peek(&home.child(".one")).expect("one").0, b"one\n");
        assert_eq!(peek(&home.child(".two")).expect("two").0, b"two\n");
    }

    #[test]
    fn a_removal_rolls_back_to_the_file_it_removed() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".config/deep/made.conf");
        plant_file(&dest, "bx wrote this\n", Mode::PRIVATE_FILE);

        interrupted(
            &state,
            home.path(),
            vec![Request {
                target: portable,
                dest: dest.clone(),
                content: Content::Absent {
                    created_dirs: vec![home.child(".config/deep"), home.child(".config")],
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::PRIVATE_FILE,
                ownership: Ownership::Released,
            }],
        );
        assert!(!dest.exists(), "the removal completed");
        assert!(
            home.child(".config/deep").is_dir(),
            "nothing a removal claims is pruned before its session's End",
        );

        recover(&state).expect("recover");
        assert_eq!(
            peek(&dest).expect("restored"),
            (b"bx wrote this\n".to_vec(), Mode::PRIVATE_FILE),
            "an interrupted removal puts the file back, parents and all",
        );
    }

    #[test]
    fn a_leftover_temp_file_named_by_an_intent_is_removed() {
        let guard = guarded_home();
        let home = guard.child("crashed");
        plant_crash_fixture(&home);
        assert!(!spawn_crash_child(&home, 0, "after-stage").status.success());

        let state = StateDir::resolve(&home);
        let loaded = crate::journal::load(&state.journal()).expect("load");
        let temp = loaded
            .intents()
            .next()
            .expect("one intent")
            .temp
            .clone()
            .expect("a staged temp file");
        assert!(temp.is_file(), "the crash left it behind");
        let note = pending(&state)
            .expect("pending")
            .expect("interrupted")
            .unfinished[0]
            .note
            .clone();
        assert!(
            !note.contains("temporary file"),
            "it can be removed: {note}"
        );

        recover(&state).expect("recover");
        assert!(!temp.exists(), "and recovery removed exactly it");
        assert!(leftover_temps(&home).is_empty());
    }

    #[test]
    fn a_temp_file_no_intent_names_is_left_alone() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        // Named like bx's, but bx did not make it and cannot prove it did.
        let stray = home.child(".bx-not-mine.tmp");
        plant_file(&stray, "somebody else's", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );
        recover(&state).expect("recover");

        assert_eq!(
            peek(&stray).expect("still there").0,
            b"somebody else's",
            "recovery removes the one path the journal names, and nothing else",
        );
    }

    #[test]
    fn recovery_run_twice_changes_nothing_the_second_time() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dest = home.child(".conf");
        plant_file(&dest, "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE)],
        );

        assert_eq!(
            recover(&state).expect("first"),
            Outcome::RolledBack { undone: 1 },
        );
        let after_first = peek(&dest).expect("restored");
        assert_eq!(recover(&state).expect("second"), Outcome::Nothing);
        assert_eq!(peek(&dest).expect("still restored"), after_first);
        assert_eq!(recover(&state).expect("third"), Outcome::Nothing);
    }

    #[test]
    fn a_terminated_journal_brings_the_ledger_up_to_date_without_touching_a_file() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);
        interrupted(
            &state,
            home.path(),
            vec![
                write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE),
                write_to(
                    home.path(),
                    ".config/deep/made.conf",
                    "made\n",
                    Mode::PRIVATE_FILE,
                ),
            ],
        );
        // Every write landed; the process died between the End frame and the
        // ledger save, which is the one window `finish` leaves open.
        seal(&state.journal(), 2);
        assert!(!state.ledger().exists(), "the ledger never got saved");

        let interruption = pending(&state).expect("pending").expect("interrupted");
        assert!(interruption.complete);

        let before = (
            peek(&home.child(".conf")),
            peek(&home.child(".config/deep/made.conf")),
        );
        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 2 },
        );
        assert_eq!(
            (
                peek(&home.child(".conf")),
                peek(&home.child(".config/deep/made.conf")),
            ),
            before,
            "no destination is touched: only the machine's own bookkeeping",
        );

        let ledger = LedgerView::read(&state, home.path())
            .expect("read the ledger")
            .value;
        let modified = ledger
            .get(&target(home.path(), ".conf").0)
            .expect("the modify");
        assert_eq!(modified.written, ContentHash::of(b"new\n"));
        assert_eq!(modified.mode, Mode::DEFAULT_FILE);
        assert_eq!(modified.mechanism, Mechanism::Own);
        let Prior::Existed(reference) = &modified.prior else {
            panic!("the prior bytes are recorded")
        };
        assert_eq!(reference.digest, ContentHash::of(b"old\n"));

        let created = ledger
            .get(&target(home.path(), ".config/deep/made.conf").0)
            .expect("the create");
        assert_eq!(created.prior, Prior::Absent);
        assert_eq!(created.mode, Mode::PRIVATE_FILE);
        assert_eq!(
            created
                .created_dirs
                .iter()
                .map(|dir| dir.render(home.path()))
                .collect::<Vec<_>>(),
            vec![home.child(".config/deep"), home.child(".config")],
        );

        assert!(!state.journal().exists());
        assert_eq!(recover(&state).expect("again"), Outcome::Nothing);
    }

    #[test]
    fn a_terminated_release_leaves_the_target_out_of_the_ledger() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let (portable, dest) = target(home.path(), ".conf");
        plant_file(&dest, "mine\n", Mode::DEFAULT_FILE);

        interrupted(
            &state,
            home.path(),
            vec![Request {
                target: portable.clone(),
                content: Content::Bytes {
                    bytes: b"yours\n".to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                dest,
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            }],
        );
        seal(&state.journal(), 1);

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 },
        );
        assert!(
            LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(&portable)
                .is_none()
        );
    }

    #[test]
    fn replaying_a_released_write_hands_on_the_directories_its_entry_claimed() {
        // r3 round 4, D1 and COV2. `Session::write` was repaired in round 3 to
        // stop discarding the entry `ledger.forget` returns; `resolve`'s
        // `Step::Forget` still discarded it, so the same `rm`, crashed between
        // its `End` frame and its save, lost the claims the live path keeps.
        // `hand_off_claims` documents the replay as running "the same hand-off
        // … so a crash between the `End` frame and the save loses no claim",
        // and nothing reached `Step::Forget` for a released write at all.
        //
        // A released write's Intent cannot stand in for the entry: it records
        // the directories *that write* invented, which for a write over a file
        // that is already there is none.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let dir = home.child(".config/app");
        let claims = vec![home.child(".config"), home.child(".config/app")];

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        for rel in [".config/app/a.conf", ".config/app/heir.conf"] {
            session
                .apply(write_to(home.path(), rel, "bx\n", Mode::DEFAULT_FILE))
                .expect("apply");
        }
        session.finish().expect("finish");
        let (a, a_dest) = target(home.path(), ".config/app/a.conf");
        let (heir, _) = target(home.path(), ".config/app/heir.conf");
        let saved_claims = |what: &Portable| -> Vec<PathBuf> {
            let mut dirs = LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(what)
                .map(|entry| {
                    entry
                        .created_dirs
                        .iter()
                        .map(|d| d.render(home.path()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            dirs.sort();
            dirs
        };
        assert_eq!(saved_claims(&a), claims, "a.conf claims both directories");
        assert!(saved_claims(&heir).is_empty());

        // `rm a.conf` hands the file back and then dies between its `End`
        // frame and its ledger save: a terminated journal over a ledger that
        // still holds the entry.
        interrupted(
            &state,
            home.path(),
            vec![Request {
                target: a.clone(),
                dest: a_dest.clone(),
                content: Content::Bytes {
                    bytes: b"theirs\n".to_vec(),
                    planned: fs::observe(&a_dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Released,
            }],
        );
        seal(&state.journal(), 1);
        let intent = journal::load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .cloned()
            .expect("the released write's Intent");
        assert!(
            intent.created_dirs.is_empty(),
            "the Intent carries no claim of its own: {:?}",
            intent.created_dirs,
        );

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::Recorded { entries: 1 },
        );
        assert!(saved_claims(&a).is_empty(), "the entry was handed back");
        assert_eq!(
            saved_claims(&heir),
            claims,
            "and its claims reached the entry still beneath them, as the live \
             path's do",
        );
        assert_eq!(peek(&a_dest).expect("handed back").0, b"theirs\n");
        assert!(dir.is_dir(), "nothing was pruned: no removal was announced");
    }

    #[test]
    fn a_blocked_recovery_hands_no_claim_on_and_leaves_the_saved_ledger_alone() {
        // r3 coverage COV4. One terminated journal holding both a blocked
        // intent and a released removal: the removal's claims must not reach
        // the entry beneath them while the run returns `Blocked`, and the
        // saved ledger must be exactly what it was. Once the conflict is
        // cleared, the same journal hands them on, which is what says the
        // first half is "not yet" rather than "never".
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        let theirs = "theirs\n";
        plant_file(&home.child(".blocked"), theirs, Mode::DEFAULT_FILE);

        // bx makes ~/.config/app for gone.conf, which claims it and ~/.config;
        // heir.conf goes in beside it and claims nothing.
        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        for rel in [".config/app/gone.conf", ".config/app/heir.conf"] {
            session
                .apply(write_to(home.path(), rel, "bx\n", Mode::DEFAULT_FILE))
                .expect("apply");
        }
        session.finish().expect("finish");
        let (gone, gone_dest) = target(home.path(), ".config/app/gone.conf");
        let (heir, _) = target(home.path(), ".config/app/heir.conf");
        let claims = vec![home.child(".config"), home.child(".config/app")];
        let saved_claims = |what: &Portable| -> Vec<PathBuf> {
            let mut dirs = LedgerView::read(&state, home.path())
                .expect("read the ledger")
                .value
                .get(what)
                .map(|entry| {
                    entry
                        .created_dirs
                        .iter()
                        .map(|dir| dir.render(home.path()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            dirs.sort();
            dirs
        };
        assert_eq!(saved_claims(&gone), claims, "gone.conf claims both");
        assert!(saved_claims(&heir).is_empty(), "heir.conf claims neither");

        // The interrupted session removes gone.conf, releasing both claims,
        // and rewrites ~/.blocked, whose prior snapshot then goes missing.
        interrupted(
            &state,
            home.path(),
            vec![
                Request {
                    target: gone.clone(),
                    dest: gone_dest.clone(),
                    content: Content::Absent {
                        created_dirs: claims.iter().rev().cloned().collect(),
                        planned: fs::observe(&gone_dest).expect("plan's observation"),
                    },
                    mode: Mode::DEFAULT_FILE,
                    ownership: Ownership::Released,
                },
                write_to(home.path(), ".blocked", "bx\n", Mode::DEFAULT_FILE),
            ],
        );
        seal(&state.journal(), 2);
        let blob = state
            .restore()
            .join(ContentHash::of(theirs.as_bytes()).to_hex());
        std::fs::remove_file(&blob).expect("delete the snapshot");

        let outcome = recover(&state).expect("recover");
        assert!(
            matches!(&outcome, Outcome::Blocked { conflicts } if conflicts.len() == 1),
            "{outcome:?}"
        );
        assert!(state.journal().exists(), "the journal is kept");
        assert_eq!(
            saved_claims(&gone),
            claims,
            "a blocked run saves no ledger, so the removal's entry stands",
        );
        assert!(
            saved_claims(&heir).is_empty(),
            "and no claim was handed to the entry beneath them",
        );

        // Clear the conflict and run again: now the hand-off happens.
        std::fs::write(&blob, theirs).expect("put the snapshot back");
        let outcome = recover(&state).expect("recover again");
        assert!(
            matches!(outcome, Outcome::Recorded { entries: 2 }),
            "{outcome:?}"
        );
        assert!(saved_claims(&gone).is_empty(), "the removal is recorded");
        assert_eq!(
            saved_claims(&heir),
            claims,
            "and both claims reached the entry still beneath them",
        );
    }

    #[test]
    fn the_intent_is_durable_before_a_removal_touches_the_destination() {
        let guard = guarded_home();
        let removal = crash_requests(guard.path())
            .iter()
            .position(|request| matches!(request.content, Content::Absent { .. }))
            .expect("the harness removes something");

        // One boundary before the removal's intent: nothing names it, and the
        // file is still there.
        let early = guard.child("early");
        plant_crash_fixture(&early);
        assert!(
            !spawn_crash_child(&early, removal, "before-stage")
                .status
                .success()
        );
        let loaded = crate::journal::load(&StateDir::resolve(&early).journal()).expect("load");
        assert!(
            loaded
                .intents()
                .all(|intent| intent.after != Written::Absent),
            "no removal had been announced yet",
        );
        assert!(early.join(".vault/gone.conf").is_file());

        // One boundary after it: the intent is durable and the file is *still*
        // there. Unlinking first would leave a window in which a crash removes a
        // file no journal frame names.
        let late = guard.child("late");
        plant_crash_fixture(&late);
        assert!(
            !spawn_crash_child(&late, removal, "after-intent")
                .status
                .success()
        );
        let loaded = crate::journal::load(&StateDir::resolve(&late).journal()).expect("load");
        let intent = loaded.intents().last().expect("the removal's intent");
        assert_eq!(intent.after, Written::Absent);
        assert_eq!(intent.dest, late.join(".vault/gone.conf"));
        assert_eq!(intent.temp, None);
        assert_eq!(
            peek(&late.join(".vault/gone.conf")).expect("still there"),
            (b"bx made this\n".to_vec(), Mode::PRIVATE_FILE),
            "and the destination is still what it was",
        );
    }

    #[test]
    fn a_blocked_write_keeps_its_temporary_file() {
        // Review round 3, item 2: the temporary file was unlinked before the
        // decision, so a blocked write lost it on every re-run.
        let guard = guarded_home();
        let home = guard.child("crashed");
        plant_crash_fixture(&home);
        assert!(!spawn_crash_child(&home, 0, "after-stage").status.success());
        let state = StateDir::resolve(&home);
        let temp = crate::journal::load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .expect("one intent")
            .temp
            .clone()
            .expect("a staged temp file");
        plant_file(
            &home.join(".bxrc"),
            "edited after the crash\n",
            Mode::PRIVATE_FILE,
        );

        assert!(matches!(
            recover(&state).expect("recover"),
            Outcome::Blocked { .. }
        ));
        assert!(temp.is_file(), "a blocked write is not recovery's to touch");
    }

    #[test]
    fn a_crash_inside_finish_is_recorded_and_rm_still_restores_the_originals() {
        // Review round 3, item 1. Every write has landed when `finish` runs, so
        // a crash there is bookkeeping, never a rollback. With an earlier apply
        // behind it, a crash after the ledger save and before the unlink is the
        // one that used to hand `rm` bx's first output instead of the user's
        // file.
        let guard = guarded_home();
        for phase in finish_crash_phases() {
            for earlier_apply in [false, true] {
                let case = format!("{phase}, earlier apply: {earlier_apply}");
                let home = guard.child(format!("finish-{phase}-{earlier_apply}"));
                plant_crash_fixture(&home);
                let before = crash_snapshot(&home);
                let state = StateDir::resolve(&home);
                let owned: Vec<Portable> = crash_requests(&home)
                    .into_iter()
                    .filter(|request| matches!(request.ownership, Ownership::Owned(_)))
                    .map(|request| request.target)
                    .collect();

                if earlier_apply {
                    let mut session =
                        Session::open(&state, SessionKind::Apply, &home, Vec::new()).expect("open");
                    for request in crash_requests(&home) {
                        if matches!(request.ownership, Ownership::Owned(_)) {
                            let Content::Bytes { planned, .. } = request.content else {
                                unreachable!("an owned crash request writes bytes");
                            };
                            session
                                .apply(Request {
                                    content: Content::Bytes {
                                        bytes: b"bx one\n".to_vec(),
                                        planned,
                                    },
                                    ..request
                                })
                                .expect("the earlier apply");
                        }
                    }
                    session.finish().expect("finish the earlier apply");
                }

                let out = spawn_crash_child(&home, crash_requests(&home).len(), phase);
                assert!(
                    !out.status.success(),
                    "{case}: the child was supposed to die; it said {}",
                    String::from_utf8_lossy(&out.stdout),
                );

                // Every write landed.
                for request in crash_requests(&home) {
                    let found = peek(&request.dest);
                    match &request.content {
                        Content::Bytes { bytes: wanted, .. } => {
                            assert_eq!(found, Some((wanted.clone(), request.mode)), "{case}");
                        }
                        Content::Absent { .. } => assert_eq!(found, None, "{case}"),
                        Content::Dir { .. }
                        | Content::DirAbsent { .. }
                        | Content::Link { .. }
                        | Content::LinkAbsent { .. } => {
                            unreachable!("{case}: the crash fixture writes files only")
                        }
                    }
                }

                let interrupted = pending(&state).expect("pending").expect("a journal stands");
                assert!(interrupted.complete, "{case}");
                assert!(interrupted.blocked().next().is_none(), "{case}");
                let removal_note = interrupted
                    .unfinished
                    .iter()
                    .find(|write| write.dest.ends_with(".vault/gone.conf"))
                    .expect("the removal is reported")
                    .note
                    .clone();
                // The claimed directory is pruned after `End`: a crash between
                // the two leaves it, empty and at its mode, as decision 11's
                // kind of orphan, and recovery removes it no more than it
                // removes an orphaned temporary file.
                let vault = home.join(".vault");
                let orphaned = phase == "after-end";
                assert_eq!(
                    dir_mode(&vault),
                    orphaned.then_some(Mode::PRIVATE_DIR),
                    "{case}"
                );
                assert_eq!(
                    removal_note.contains("~/.vault, which stand empty and are left for bx doctor"),
                    orphaned,
                    "{case}: {removal_note}"
                );
                let outcome = recover(&state).expect("recover");
                assert!(
                    matches!(outcome, Outcome::Recorded { .. }),
                    "{case}: {outcome:?}"
                );
                assert!(!state.journal().exists(), "{case}");
                assert_eq!(recover(&state).expect("again"), Outcome::Nothing, "{case}");
                assert_eq!(
                    dir_mode(&vault),
                    orphaned.then_some(Mode::PRIVATE_DIR),
                    "{case}: recovery leaves the orphan"
                );
                assert!(
                    LedgerView::read(&state, &home)
                        .expect("read the ledger")
                        .value
                        .iter()
                        .all(|(_, entry)| !entry
                            .created_dirs
                            .iter()
                            .any(|dir| dir.as_str() == "~/.vault")),
                    "{case}: no entry claims ~/.vault"
                );

                let restored = crate::restore::restore(&state, &home, &owned).expect("rm");
                assert!(
                    restored.iter().all(|done| !done.is_conflict()),
                    "{case}: {restored:?}"
                );
                for ((dest, was), (_, is)) in before.files.iter().zip(crash_snapshot(&home).files) {
                    if dest.ends_with(".vault/gone.conf") {
                        assert_eq!(is, None, "{case}: the session released and removed it");
                    } else {
                        assert_eq!(&is, was, "{case}: rm did not restore {}", dest.display());
                    }
                }
                assert!(!home.join(".config").exists(), "{case}");
            }
        }
    }

    #[test]
    fn a_crash_at_every_write_boundary_is_recoverable() {
        let guard = guarded_home();
        for index in 0..crash_requests(guard.path()).len() {
            for phase in crash_phases() {
                // A removal stages nothing, so it never reaches the two staging
                // boundaries and a child asked to die there would not.
                if matches!(
                    crash_requests(guard.path())[index].content,
                    Content::Absent { .. }
                ) && matches!(phase, "after-stage" | "after-fill")
                {
                    continue;
                }
                let home = guard.child(format!("crash-{index}-{phase}"));
                plant_crash_fixture(&home);
                let before = crash_snapshot(&home);

                let out = spawn_crash_child(&home, index, phase);
                assert!(
                    !out.status.success(),
                    "the child was supposed to die at {index}:{phase}; it said {}",
                    String::from_utf8_lossy(&out.stdout),
                );

                // 1. Old or new, never torn. This is what A5's atomic write
                //    buys, and this assertion is what proves it.
                for (dest, found) in crash_snapshot(&home).files {
                    let request = crash_requests(&home)
                        .into_iter()
                        .find(|candidate| candidate.dest == dest)
                        .expect("a fixture destination");
                    let was = before
                        .files
                        .iter()
                        .find(|(path, _)| *path == dest)
                        .and_then(|(_, state)| state.clone());
                    let is_new = match &request.content {
                        Content::Bytes { bytes: wanted, .. } => found
                            .as_ref()
                            .is_some_and(|(bytes, mode)| bytes == wanted && *mode == request.mode),
                        Content::Absent { .. } => found.is_none(),
                        Content::Dir { .. }
                        | Content::DirAbsent { .. }
                        | Content::Link { .. }
                        | Content::LinkAbsent { .. } => {
                            unreachable!("the crash fixture writes files only")
                        }
                    };
                    assert!(
                        found == was || is_new,
                        "{} was torn by a crash at {index}:{phase}: {found:?}",
                        dest.display(),
                    );
                }

                // 2. The interruption is detected.
                let state = StateDir::resolve(&home);
                let interrupted = pending(&state)
                    .expect("pending")
                    .expect("a crash leaves an interrupted session");
                assert_eq!(interrupted.kind, SessionKind::Apply);
                assert!(!interrupted.complete);
                assert!(
                    interrupted.blocked().next().is_none(),
                    "nothing edited the destinations, so nothing is blocked",
                );

                // 3. Recovery rolls it back.
                let outcome = recover(&state).expect("recover");
                assert!(
                    matches!(outcome, Outcome::RolledBack { .. }),
                    "got {outcome:?} at {index}:{phase}",
                );

                // 4. Byte- and mode-identical to the pre-run snapshot, the
                //    directories included, at every boundary. The intent
                //    names a write's temporary file and the directories it
                //    will invent before the stage makes either, so no crash
                //    leaves one the journal does not name (#119).
                assert_eq!(
                    crash_snapshot(&home),
                    before,
                    "rollback at {index}:{phase} did not restore the fixture",
                );

                // 5. Nothing bx staged is left: recovery removes the one
                //    temporary file each intent names, and never unlinks by
                //    pattern in a directory the user owns.
                let temps = leftover_temps(&home);
                assert!(
                    temps.is_empty(),
                    "a crash at {index}:{phase} left {temps:?}"
                );
                assert!(
                    !home.join(".config").exists(),
                    "the directories the session invented are gone too",
                );

                // 6. The journal is gone.
                assert!(!state.journal().exists());
                assert!(pending(&state).expect("pending").is_none());

                // 7. Recovery is idempotent.
                assert_eq!(recover(&state).expect("recover twice"), Outcome::Nothing);
                assert_eq!(crash_snapshot(&home), before);
            }
        }
    }

    #[test]
    fn a_rollback_removes_nested_created_directories_last_write_first() {
        // Coverage review round 5, item 1. Deleting the `!` before `complete`
        // survived: no rollback had two writes whose created directories nest.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        interrupted(
            &state,
            home.path(),
            vec![
                write_to(
                    home.path(),
                    ".config/deep/a.conf",
                    "a\n",
                    Mode::DEFAULT_FILE,
                ),
                write_to(
                    home.path(),
                    ".config/deep/nested/b.conf",
                    "b\n",
                    Mode::DEFAULT_FILE,
                ),
            ],
        );
        assert!(home.child(".config/deep/nested/b.conf").is_file());

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 2 }
        );
        assert!(
            !home.child(".config").exists(),
            "every directory bx created is gone"
        );
    }

    #[test]
    fn a_rollback_under_a_created_directory_replaced_with_a_symlink_completes() {
        // r3 round 1, D1. Pruning the created directory failed with ENOTDIR
        // after the unlink, so every writing run failed and the journal stood.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        interrupted(
            &state,
            home.path(),
            vec![write_to(
                home.path(),
                "d/a.conf",
                "bx\n",
                Mode::DEFAULT_FILE,
            )],
        );
        std::fs::rename(home.child("d"), home.child("real")).expect("move the directory");
        std::os::unix::fs::symlink(home.child("real"), home.child("d")).expect("link it back");

        assert_eq!(
            recover(&state).expect("recover"),
            Outcome::RolledBack { undone: 1 },
        );
        assert!(!state.journal().exists());
        assert!(peek(&home.child("real/a.conf")).is_none());
        assert!(
            std::fs::symlink_metadata(home.child("d"))
                .expect("the link stays")
                .file_type()
                .is_symlink()
        );
        assert_eq!(recover(&state).expect("again"), Outcome::Nothing);
    }
}
