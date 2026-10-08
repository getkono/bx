//! [`Session`]: the lock, the ledger and the journal held together, and the
//! fixed ordering every kind of request goes through on its way to the user's
//! filesystem.

use std::path::{Path, PathBuf};

use super::crash::{Crash, Phase};
use super::load::{missing_parents, stray_created_dir};
use super::{
    Begin, Done, End, Error, Intent, Journal, Record, SessionKind, Written, load_exclusive,
};
use crate::fs::remove::{prune_dirs, unlink};
use crate::fs::{self, Mode, Observed, refuse_moved};
use crate::paths::Portable;
use crate::state::restore;
use crate::state::{
    ContentHash, DIR_BYTES, ExclusiveLock, Ledger, LedgerView, Mechanism, NewEntry, Prior,
    PriorBytes, StateDir, dir_digest, dir_prior,
};

/// A transaction over the state directory: the lock, the ledger, the journal.
///
/// Every byte bx writes to a user's filesystem passes through one of these. It
/// holds the state directory's exclusive lock for its whole life, so no second
/// `bx` can interleave, and it is the *only* caller of
/// [`crate::state::Ledger::save`] — which is what keeps the saved ledger
/// describing the state a rollback returns to.
///
/// Dropping a session without [`Session::finish`] deliberately leaves the
/// journal in place. An abandoned session *is* an interrupted session, and the
/// next invocation must see it.
#[derive(Debug)]
pub struct Session {
    journal: Journal,
    state: StateDir,
    ledger: Ledger,
    home: PathBuf,
    written: usize,
    /// Set by the first write that fails. See [`Session::apply`].
    poisoned: bool,
    /// Every target a request has been admitted for, so none is written twice.
    touched: std::collections::HashSet<Portable>,
    /// Every directory a write in this session created. One set for the whole
    /// session, because [`crate::fs::ensure_dir`] reads it to tell a directory
    /// an earlier write made from one somebody else made since plan.
    created: fs::CreatedDirs,
    /// Every directory a target this session removed claimed. Pruned, as one
    /// union, once the session's `End` is durable, and handed on.
    released: std::collections::BTreeSet<PathBuf>,
    /// Every directory claimed by a target this session dropped from the ledger
    /// without announcing a removal: one [`Session::forget`] dropped, and one a
    /// [`Ownership::Released`] write handed back. Handed on when the session
    /// finishes, and never pruned — no removal was announced, so there is
    /// nothing `plan` promised to remove.
    forgotten: std::collections::BTreeSet<PathBuf>,
    crash: Crash,
    /// Called with the destination just before a write is published, so a test
    /// can make the publish fail the way a concurrent change to the destination
    /// would.
    #[cfg(test)]
    before_publish: Option<fn(&Path)>,
    /// Called with the destination after a removal's Intent is durable and
    /// before its last look, so a test can save over it the way a racing editor
    /// would.
    #[cfg(test)]
    before_unlink: Option<fn(&Path)>,
    /// Called with the directory [`Session::write`] just made for the home,
    /// before [`crate::fs::stage`] looks, so a test can produce the one
    /// trigger the claim filter has left: that directory going away in
    /// between. See `r3 round 7` decision R3R7-2.
    #[cfg(test)]
    before_stage: Option<fn(&Path)>,
    /// Called with the destination after a write's Intent is durable and
    /// before [`crate::fs::stage_as`] makes anything, so a test can change
    /// the parents the Intent predicted the way a racing process would.
    #[cfg(test)]
    after_intent: Option<fn(&Path)>,
    /// Held, never read: dropping it releases the state directory.
    _lock: ExclusiveLock,
}

/// What a caller asks a session to make true at one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The target, home-relative. The ledger's key.
    pub target: Portable,
    /// Where it goes, rendered absolute.
    pub dest: PathBuf,
    /// What should be there afterwards.
    pub content: Content,
    /// The mode the content is written at, already resolved. Ignored for
    /// [`Content::Absent`].
    pub mode: Mode,
    /// Whether bx owns the result.
    pub ownership: Ownership,
}

/// What a request leaves at the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// These bytes, at [`Request::mode`].
    Bytes {
        /// The whole content.
        bytes: Vec<u8>,
        /// What plan observed at the destination when it compared these bytes
        /// with it, from [`crate::fs::observe`]. The write is staged against
        /// it: a destination whose kind or stamp is no longer this is refused
        /// with [`crate::fs::Error::Changed`], which poisons the session with
        /// nothing staged, announced or published.
        planned: fs::Observed,
    },
    /// No file at all.
    ///
    /// The destination is unlinked, and when the session finishes, after its
    /// `End` frame, `created_dirs` are removed, deepest first, while they are
    /// empty directories and no entry the ledger still holds names them; one
    /// that is no longer a directory is left. Absence is not emptiness: a file
    /// bx created is removed, never truncated. The target is always dropped
    /// from the ledger — there is nothing left for bx to own. A claimed
    /// directory that still stands then is handed to a surviving entry beneath
    /// it: see [`Session::finish`].
    Absent {
        /// Directories bx created for the target, deepest first.
        created_dirs: Vec<PathBuf>,
        /// What plan observed at the destination when it decided on the
        /// removal, from [`crate::fs::observe`]. A destination whose path, kind
        /// or stamp is no longer this is refused with
        /// [`crate::fs::Error::Changed`] — before anything is stored or
        /// announced, and again immediately before the unlink — which poisons
        /// the session with nothing unlinked.
        planned: fs::Observed,
    },
    /// A directory at [`Request::mode`]: created where plan saw nothing, or
    /// set to that mode where plan saw a directory at another.
    ///
    /// Made through [`crate::fs::ensure_dir`] with the session's one set of
    /// created directories, after the Intent naming it is durable. The
    /// directory is checked against `planned` before anything is announced —
    /// the check `ensure_dir` makes again before it acts — so a directory that
    /// changed since plan poisons the session with nothing announced. Only the
    /// directory itself is made or changed, never what it holds.
    Dir {
        /// What plan observed at the destination when it compared the
        /// directory with it, from [`crate::fs::observe`].
        planned: fs::Observed,
    },
    /// No directory any more: the one bx created for a directory target.
    ///
    /// The directory and `created_dirs` are removed where they are empty and
    /// no entry the ledger still holds names them, and the target is dropped
    /// from the ledger. A directory something else still holds is left where
    /// it is, tried again when the session finishes, and handed to a surviving
    /// entry beneath it if it still stands — the rule a removed file's claimed
    /// directories follow. bx never removes what is inside a directory.
    DirAbsent {
        /// Directories bx created on the way to the directory, deepest first.
        created_dirs: Vec<PathBuf>,
        /// What plan observed at the destination when it decided on the
        /// removal. A directory whose path, kind or stamp is no longer this is
        /// refused with [`crate::fs::Error::Changed`], before anything is
        /// announced and again immediately before the removal.
        planned: fs::Observed,
    },
    /// A symlink holding this text, made through [`crate::fs::stage_link`]
    /// where plan saw nothing or a link. [`Request::mode`] is ignored: a link
    /// is recorded at [`crate::fs::Mode::LINK`].
    Link {
        /// The link's text, exactly as it is to be written.
        text: PathBuf,
        /// What plan observed at the destination when it decided on the link.
        /// The link is staged against it, as [`Content::Bytes`] is.
        planned: fs::Observed,
    },
    /// No symlink any more: the one bx made for a symlink target.
    ///
    /// The link is unlinked, never what it points at, and `created_dirs` are
    /// released as [`Content::Absent`] releases a file's. A destination that
    /// is not a link is refused.
    LinkAbsent {
        /// Directories bx created for the target, deepest first.
        created_dirs: Vec<PathBuf>,
        /// What plan observed at the destination when it decided on the
        /// removal, checked as [`Content::Absent`] checks its own.
        planned: fs::Observed,
    },
}

/// Whether bx owns what the write leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// bx manages the target from now on, attached this way.
    Owned(Mechanism),
    /// bx is handing the target back — the restore half of `bx rm`. The prior
    /// bytes are still copied into `restore/`, because that is what an
    /// interrupted restore is rolled back from; only the ledger entry goes,
    /// and the directories that entry claimed are handed to a surviving entry
    /// beneath them when the session finishes rather than dropped.
    Released,
}

impl Session {
    /// Open a session: take the lock, refuse over an unresolved interruption,
    /// and write the header and the [`Begin`] frame.
    ///
    /// # Errors
    ///
    /// [`Error::InProgress`] when a journal already stands — recover first.
    /// [`Error::FutureVersion`] when the journal that stands was written by a
    /// newer bx: nothing is set aside. [`Error::NotAJournal`] when what stands
    /// at the journal's path is not a regular file: it is never opened.
    /// [`Error::CannotSetAside`] when the
    /// journal that stands cannot be believed and cannot be moved aside: it is
    /// left in place, never replaced. [`Error::State`] with
    /// [`crate::state::Error::ForeignRecord`] when a scope entry is one the
    /// loader would refuse. [`Error::State`] when the directory
    /// cannot be made or locked, and [`Error::Io`] when the journal cannot be
    /// written.
    pub fn open(
        state: &StateDir,
        kind: SessionKind,
        home: &Path,
        scope: Vec<Portable>,
    ) -> Result<Self, Error> {
        state.ensure()?;
        // The lock first, so the check inside cannot race a second bx.
        let lock = ExclusiveLock::acquire(state)?;
        Self::open_locked(state, kind, home, scope, lock)
    }

    /// Open a session under a lock the caller already holds.
    ///
    /// The one-lock form: a writing command takes the lock, resolves any
    /// interruption under it, and hands the same guard here, so no second bx
    /// can win the directory in between and be reported as an interruption.
    /// [`crate::recover::lock_for_writing`] hands out that guard.
    ///
    /// # Errors
    ///
    /// As [`Session::open`], minus the acquisition of the lock.
    pub fn open_locked(
        state: &StateDir,
        kind: SessionKind,
        home: &Path,
        scope: Vec<Portable>,
        lock: ExclusiveLock,
    ) -> Result<Self, Error> {
        state.ensure()?;
        // Before the journal exists, because the loader refuses the *whole*
        // journal over one unportable scope entry: a session that wrote one
        // could never be rolled back. The same rule `admit` applies to a
        // request's target; `Session::write` applies it to a write's created
        // directories and drops what fails. Those are the places a path enters
        // a journal, with `Intent.dest` following its target and `Intent.temp`
        // a `.bx-` name beside it by construction.
        //
        // `home` itself needs no check here: `Ledger::open` below applies the
        // loader's own rule to it — absolute, and UTF-8 — and it runs before
        // `Journal::create`, so no `Begin` naming a home the loader would
        // refuse is ever written.
        // `a_home_the_loader_would_refuse_never_reaches_a_begin_frame` pins
        // that ordering.
        for entry in &scope {
            entry
                .check_against(home)
                .map_err(|source| crate::state::Error::ForeignRecord {
                    home: home.to_path_buf(),
                    stored: entry.as_str().to_string(),
                    source: Box::new(source),
                })?;
        }
        let path = state.journal();
        if load_exclusive(&path, &lock)?.is_interrupted() {
            return Err(Error::InProgress { path });
        }

        let ledger = Ledger::open(state, &lock, home)?.value;
        let journal = Journal::create(
            &path,
            Begin {
                kind,
                home: home.to_path_buf(),
                scope,
            },
        )?;
        tracing::debug!(%kind, home = %home.display(), "opened a journalled session");

        Ok(Self {
            journal,
            state: state.clone(),
            ledger,
            home: home.to_path_buf(),
            written: 0,
            poisoned: false,
            touched: std::collections::HashSet::new(),
            created: fs::CreatedDirs::new(),
            released: std::collections::BTreeSet::new(),
            forgotten: std::collections::BTreeSet::new(),
            crash: Crash::from_env(),
            #[cfg(test)]
            before_publish: None,
            #[cfg(test)]
            before_unlink: None,
            #[cfg(test)]
            before_stage: None,
            #[cfg(test)]
            after_intent: None,
            _lock: lock,
        })
    }

    /// The ledger as this session has it so far.
    #[must_use]
    pub fn ledger(&self) -> &LedgerView {
        &self.ledger
    }

    /// The state directory the session is against.
    #[must_use]
    pub fn state(&self) -> &StateDir {
        &self.state
    }

    /// The home the session's paths are rendered against.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The journal this session is appending to.
    #[must_use]
    pub fn journal(&self) -> &Path {
        self.journal.path()
    }

    /// How many writes the session has published.
    #[must_use]
    pub const fn written(&self) -> usize {
        self.written
    }

    /// Drop a target from the ledger without touching the filesystem.
    ///
    /// For the one case `bx rm` has where there is nothing to write: bx created
    /// the file, and the file is already gone.
    ///
    /// Not journalled, because there is no write to undo. The cost is that a
    /// session interrupted between its [`End`] frame and its save leaves the
    /// entry standing, since recovery rebuilds the ledger from the journal's
    /// intents and this made none. That self-heals: the next `rm` finds the
    /// file still absent, reaches this same call, and finishes.
    ///
    /// The directories the entry claimed are handed to a surviving entry
    /// beneath them when the session finishes, and never removed here: plan
    /// announced no removal.
    pub fn forget(&mut self, target: &Portable) {
        if let Some(entry) = self.ledger.forget(target) {
            self.forgotten
                .extend(entry.created_dirs.iter().map(|dir| dir.render(&self.home)));
        }
    }

    /// Make `request` true at its destination, durably and recoverably.
    ///
    /// The one place the ordering discipline [`crate::journal`] documents is expressed,
    /// and therefore the only place it can be got wrong.
    ///
    /// # A failed write poisons the session
    ///
    /// Any error here leaves the session refusing every later `apply` and
    /// [`Session::finish`], so its journal stays for recovery to roll back —
    /// whatever failed, and however early. A caller that wants to skip a target
    /// and go on decides that before calling, the way [`crate::restore`] asks
    /// [`crate::restore::plan_restore`] first.
    ///
    /// # Errors
    ///
    /// [`Error::Misplaced`] when the request's destination is not where its
    /// target renders, [`Error::State`] with
    /// [`crate::state::Error::ForeignRecord`] when the target is spelled
    /// absolutely under the home, [`Error::StrayCreatedDir`] when a removal names a
    /// created directory that is not a parent of its destination below the home,
    /// [`Error::Repeated`] when this session already wrote the target, [`Error::Write`] when the destination cannot be written, is not
    /// a file bx may replace, or is no longer what the request's plan observed
    /// ([`crate::fs::Error::Changed`]), [`Error::State`] when the prior bytes
    /// cannot be stored or recorded, [`Error::Io`] when the journal cannot be
    /// appended to, and [`Error::Poisoned`] when an earlier write in this
    /// session failed.
    pub fn apply(&mut self, request: Request) -> Result<(), Error> {
        if self.poisoned {
            return Err(self.poisoned_error());
        }
        let index = self.written;
        let Request {
            target,
            dest,
            content,
            mode,
            ownership,
        } = request;
        // A removal names the directories it claims up front, so `admit`
        // checks them before anything is touched, and a removal that named one
        // the loader refuses is an error: `plan` announced a prune bx must not
        // make. A write does not have them yet — `fs::stage` invents them — so
        // `Session::write` applies the same rule the moment they exist and
        // *drops* what fails it, because there nothing was announced and the
        // directory had to be made to reach the destination at all.
        let claimed: &[PathBuf] = match &content {
            Content::Bytes { .. } | Content::Dir { .. } | Content::Link { .. } => &[],
            Content::Absent { created_dirs, .. }
            | Content::DirAbsent { created_dirs, .. }
            | Content::LinkAbsent { created_dirs, .. } => created_dirs,
        };
        if let Err(e) = self.admit(&target, &dest, claimed) {
            self.poisoned = true;
            return Err(e);
        }
        self.crash.reached(index, Phase::BeforeStage);
        let applied = match content {
            Content::Bytes { bytes, planned } => {
                self.write(target, dest, &bytes, &planned, mode, &ownership)
            }
            Content::Absent {
                created_dirs,
                planned,
            } => self.remove(index, target, dest, created_dirs, &planned, false),
            Content::Dir { planned } => self.write_dir(target, dest, &planned, mode, &ownership),
            Content::DirAbsent {
                created_dirs,
                planned,
            } => self.remove_dir(index, target, dest, created_dirs, &planned),
            Content::Link { text, planned } => {
                self.write_link(target, dest, &text, &planned, &ownership)
            }
            Content::LinkAbsent {
                created_dirs,
                planned,
            } => self.remove(index, target, dest, created_dirs, &planned, true),
        };
        if let Err(e) = applied {
            self.poisoned = true;
            return Err(e);
        }
        self.written += 1;
        Ok(())
    }

    /// Refuse a request no journal bx believes could describe.
    ///
    /// [`load`](super::load()) refuses a journal whose intent's destination is not where its
    /// target renders, or that writes one target twice, so a session never
    /// writes either. A refusal poisons the session like any other failed
    /// write — decision 7 of the pull request that introduced the rule — though
    /// nothing has been touched: the rule does not depend on where in the
    /// sequence an error came from.
    ///
    /// A target spelled absolutely under the home renders to itself, so it
    /// passes the destination check, but it is the path the ledger's home check
    /// refuses: [`load`](super::load()) would refuse the Intent naming it, the ledger would key
    /// it under its `~` spelling, and the same file under that spelling would
    /// pass [`Error::Repeated`]. It is refused as
    /// [`crate::state::Error::ForeignRecord`] before anything is touched.
    ///
    /// A removal's `created_dirs` are what it prunes and what its Intent
    /// records, so each must be a strict parent of the destination below the
    /// home — the loader's rule — or the removal is [`Error::StrayCreatedDir`],
    /// before anything is observed, stored or touched. A **write's** claims are
    /// not declared: [`crate::fs::stage_as`] invents them. They go through the
    /// same rule in [`Session::write`], when it reads them from disk before the
    /// Intent that records them, and one that fails it is
    /// dropped from the claim rather than refused — so neither entry point can
    /// write a `created_dirs` the loader refuses, and no account is refused a
    /// write for a directory bx had to make to reach the destination.
    fn admit(
        &mut self,
        target: &Portable,
        dest: &Path,
        created_dirs: &[PathBuf],
    ) -> Result<(), Error> {
        let rendered = target.render(&self.home);
        if dest != rendered {
            return Err(Error::Misplaced {
                target: target.clone(),
                dest: dest.to_path_buf(),
                rendered,
            });
        }
        target
            .check_against(&self.home)
            .map_err(|source| crate::state::Error::ForeignRecord {
                home: self.home.clone(),
                stored: target.as_str().to_string(),
                source: Box::new(source),
            })?;
        if let Some(dir) = stray_created_dir(dest, &self.home, created_dirs) {
            return Err(Error::StrayCreatedDir {
                target: target.clone(),
                dir: dir.clone(),
            });
        }
        if !self.touched.insert(target.clone()) {
            return Err(Error::Repeated {
                target: target.clone(),
            });
        }
        Ok(())
    }

    /// The refusal a poisoned session gives.
    fn poisoned_error(&self) -> Error {
        Error::Poisoned {
            path: self.journal.path().to_path_buf(),
        }
    }

    /// The write path: record, journal, stage, fill, publish, done.
    ///
    /// Staged against `planned`, the observation plan compared, and with the
    /// session's one set of created directories, so every later write in the
    /// session knows a directory an earlier one made.
    ///
    /// The Intent is durable **before** `fs::stage` makes anything: it names
    /// the temporary file by a name [`fs::temp_beside`] chose, and the
    /// parents `stage` will invent, read from disk the way a directory
    /// target's Intent reads them. Journalled after `stage`, a crash or a
    /// refusal anywhere in between — the fill, which writes the whole content
    /// and is where a file-size limit or a full disk lands, or the Intent's
    /// own append — left the temporary file and those directories recorded
    /// nowhere, and the rollback could neither remove the one nor prune the
    /// other (#119). Journalled first, the destination is still `before`
    /// until the publish, and the rollback removes the temporary file and
    /// prunes the directories above it that it leaves empty
    /// ([`fs::remove::prune_beneath`]). A directory the Intent names and the rollback
    /// finds without the temporary file in it is not shown to be bx's — a
    /// crash before the stage made nothing, and the user may have made it
    /// since — so it is left. A write refused after its stage cannot leave
    /// that evidence behind, because the refused write drops its temporary
    /// file, so it removes the directories its stage made itself before
    /// returning the refusal ([`unmake`]).
    ///
    /// A directory this write invents that the loader would refuse — the home,
    /// or above it — is made and left unclaimed, by the Intent and by the
    /// ledger entry alike. [`Session::admit`] *refuses* a removal's declared
    /// claim instead, because that one `plan` announced.
    fn write(
        &mut self,
        target: Portable,
        dest: PathBuf,
        bytes: &[u8],
        planned: &fs::Observed,
        mode: Mode,
        ownership: &Ownership,
    ) -> Result<(), Error> {
        // `written` moves only once a write has succeeded, so it is this
        // write's index.
        let index = self.written;
        // Plan's verdict **before** anything is made. `fs::stage` takes the
        // same verdict and says why it takes it where it does — "before
        // creating anything, so a refusal leaves nothing behind" — and the
        // `create_dir_all` below has to run before `stage` does, which would
        // put a directory ahead of that guarantee: a write refused because the
        // destination changed since plan would leave the home created.
        // `Session::remove` already opens with this pair for the same reason,
        // so the two write paths now share one preamble rather than one of
        // them having none.
        //
        // `stage` remains the authority and takes the verdict again. What is
        // *not* taken here is its `refuse_unwritable` — which depends on the
        // kind `refuse_moved` has just pinned to plan's, and which plan itself
        // must already have passed to announce a write — and its
        // `refuse_wider_than_declared`, which no target in this tree can
        // trigger because nothing declares a directory. If either ever refuses
        // where this does not, the cost is the directory this used to make
        // unconditionally: the behaviour before `r3 round 7`, not worse.
        // See decision R3R7-1.
        refuse_unplanned(&dest, planned)?;
        // The home, and anything above it, that this destination needs and
        // that is not there. `fs::stage` would invent them like any other
        // ancestor: `mkdir` at [`Mode::DEFAULT_DIR`] and then a `chmod`, which
        // is deliberately *not* masked, so the result is `0755` whatever the
        // account's `umask` says. That is the right rule for a directory bx
        // owns and will remove again. These are not that. bx neither claims
        // nor ever removes them — see the loop below — so they are the shared
        // ancestors `crate::state::dir::ensure_dir` describes: "created with
        // the process `umask` … not bx's to tighten". Leaving one wider than
        // the account's own `umask` would have made it is bx deciding
        // something that is not its to decide, and nothing later narrows it,
        // because nothing later touches it.
        //
        // `create_dir_all` is the same call, with the same rule, that the
        // state directory's own ancestors get: `mkdir(0o777)` masked by the
        // `umask`, and no `chmod`. Made before `stage`, so the directory never
        // exists at `0755` for an instant — a window a descriptor opened
        // inside would outlive. See `r3 round 6` decision R3R6-1.
        self.make_shared_ancestors(&dest)?;
        // Every refusal `stage` would make, made now, so a write that could
        // not begin is refused with nothing announced. The observation is the
        // prior the Intent stores: `stage_as` looks again and refuses unless
        // it is the same file with the same stamp.
        let observed = fs::refuse_stage(&dest, planned, &self.created)?;
        // Named before anything is made, so the Intent can name it: see the
        // method's documentation.
        let temp = fs::temp_beside(&dest)?;

        // What this write will *claim* of what it makes: the parents
        // `fs::stage` will invent, read before it invents them, as a
        // directory target's Intent reads them before `fs::ensure_dir` runs.
        // `stage` must then make exactly these, or the write is refused
        // below. `refusal` puts an Intent's `created_dirs` through
        // `stray_created_dir` exactly as it does a removal's, and one entry
        // that fails makes the whole journal unreadable — so a session that
        // announced one could never be rolled back. `admit` cannot make this
        // check: a write's claims are not declared up front.
        //
        // The one rule a made directory can break here is being the home or
        // above it, which happens when the home does not exist and the state
        // directory is somewhere else (`$XDG_STATE_HOME`), so nothing made the
        // home on the way past. Such a directory is **made and not claimed**,
        // never refused: refusing would fail every first write on such an
        // account with nothing the user could do about it, and claiming it
        // would both make the journal unreadable and put the home itself in
        // reach of a rollback's `prune_dirs` and a later `rm`'s
        // `prune_claims`. Unclaimed, it is left standing — the orphan
        // decision 11 already keeps. See `r3 round 5` decision R3R5-1.
        //
        // Since `r3 round 6` the `create_dir_all` above makes those same
        // directories before `stage` runs, so `stage` no longer finds them
        // missing and this loop drops nothing in the ordinary sequence. Its one
        // live trigger is the race that fix created: the directory going away
        // between the two calls, which `before_stage` produces on purpose and
        // `a_claim_that_appears_after_the_directory_is_lost_is_still_dropped`
        // pins.
        //
        // It is kept because that trigger is a branch that can be taken, not a
        // branch that cannot. `r3 round 6` claimed instead that this is "the
        // only place the property is checked rather than argued"; that was a
        // true statement about the code and a false one about the tests, which
        // constrained it nowhere until the seam above existed (`r3 round 7`,
        // CL1). `missing_parents` leaves the same directories out of what is
        // read beforehand, and `claimable` drops them from what `stage` made.
        let created_dirs = missing_parents(&dest, &self.home, &self.created);
        // Assembled now, while the writer still holds the prior, and handed to
        // the ledger only once the write has landed. `None` is the restore half
        // of `bx rm`: bx is handing the target back, so there is nothing left for
        // it to own.
        let (entry, mechanism) = match ownership {
            Ownership::Owned(mechanism) => (
                Some({
                    // The entry claims `created_dirs`, the set the Intent
                    // names. The two have to claim the same set, or a rollback
                    // and an `rm` would disagree about the home: `prune_claims`
                    // would reach a directory the Intent deliberately left out.
                    //
                    // `portable_dirs`' `Err` is unreachable here: see its
                    // documentation.
                    //
                    // Assembled from the observation rather than a staged
                    // write, because none exists yet: the same fields
                    // `NewEntry::for_write` fills in, from the same prior.
                    let entry = NewEntry::new(
                        target.clone(),
                        ContentHash::of(bytes),
                        mode,
                        mechanism.clone(),
                        PriorBytes::of(&observed),
                    );
                    entry.with_created_dirs(portable_dirs(&created_dirs, &self.home)?)
                }),
                Some(mechanism.clone()),
            ),
            Ownership::Released => (None, None),
        };
        // The ledger's refusal is asked before anything is stored, announced or
        // published. `record` after the rename would refuse a changed shared
        // file only once bx's new bytes were already over it; asked here, the
        // refusal poisons the session with the destination untouched and no
        // Intent for recovery to act on.
        if let Some(entry) = &entry {
            self.ledger.check_record(entry)?;
        }
        // Durable before the Intent frame that names it, and therefore before
        // anything can displace it.
        let before = store_prior(&self.state, &observed)?;

        let ledger_written = self.ledger.get(&target).map(|entry| entry.written);
        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: Some(temp.clone()),
            before,
            after: Written::Present {
                digest: ContentHash::of(bytes),
                mode,
            },
            created_dirs: created_dirs.clone(),
            mechanism,
            ledger_written,
            dir: false,
            link: false,
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        #[cfg(test)]
        if let Some(meddle) = self.after_intent {
            meddle(&dest);
        }
        // Only now, with the temporary file and the directories named in a
        // durable Intent: see the method's documentation.
        let staged = fs::stage_as(&dest, &temp, mode, planned, &mut self.created)?;
        self.crash.reached(index, Phase::AfterStage);
        let made = staged.created_dirs().to_vec();
        let published = (|| -> Result<(), Error> {
            self.refuse_unannounced(&dest, &created_dirs, staged.created_dirs())?;
            let filled = staged.fill(bytes)?;
            self.crash.reached(index, Phase::AfterFill);

            #[cfg(test)]
            if let Some(meddle) = self.before_publish {
                meddle(filled.dest());
            }
            // Nothing is recorded yet, so a refused publish leaves no ledger
            // entry to withdraw: the refusal's cause is all there is to hand on.
            filled
                .publish()
                .map_err(crate::fs::Unpublished::into_error)?;
            Ok(())
        })();
        // The temporary file went with the refused write; see `unmake`.
        published.or_else(|error| unmake(&made, error))?;
        // Only now is there something to own, or to stop owning. Told any
        // earlier, the ledger would describe a write whose publish then failed.
        self.settle_entry(&target, entry)?;
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// Make the home, and anything above it, that `dest` needs and that is
    /// not there, at the process `umask`. See [`Session::write`] for why.
    fn make_shared_ancestors(&self, dest: &Path) -> Result<(), Error> {
        if let Some(shared) = shared_ancestor(dest, &self.home) {
            std::fs::create_dir_all(&shared).map_err(|source| fs::Error::Write {
                path: shared.clone(),
                source,
            })?;
            tracing::debug!(
                dir = %shared.display(),
                "made a directory bx shares with every other tool, at the process umask",
            );
            #[cfg(test)]
            if let Some(meddle) = self.before_stage {
                meddle(&shared);
            }
        }
        Ok(())
    }

    /// The directories a write made on the way to `dest` that it may claim:
    /// every one but the home or a directory above it, which is made and left
    /// unclaimed. See [`Session::write`] for why.
    fn claimable(&self, dest: &Path, made: &[PathBuf]) -> Vec<PathBuf> {
        let mut created_dirs = Vec::with_capacity(made.len());
        for dir in made {
            if stray_created_dir(dest, &self.home, std::slice::from_ref(dir)).is_some() {
                tracing::debug!(
                    dir = %dir.display(),
                    dest = %dest.display(),
                    "bx made a directory on the way to a destination and claims none of it",
                );
                continue;
            }
            created_dirs.push(dir.clone());
        }
        created_dirs
    }

    /// Refuse a staged write that claims other directories than its Intent
    /// announced.
    ///
    /// The Intent names the parents a write will invent before `fs::stage`
    /// invents them, read from disk; the two differ only when the disk
    /// changed in between. Refused, the session is poisoned with the Intent
    /// durable, and the caller removes every directory the stage made where
    /// it stands empty ([`unmake`]) — never a directory with anything in it —
    /// including one the Intent does not name, which no rollback or `rm`
    /// would ever reach. Carried on, the ledger entry
    /// would claim a set the journal does not, which is the disagreement
    /// between a rollback and an `rm` [`Session::write`] exists to prevent.
    ///
    /// # Errors
    ///
    /// [`Error::Write`] with [`crate::fs::Error::Changed`] naming `dest`.
    fn refuse_unannounced(
        &self,
        dest: &Path,
        announced: &[PathBuf],
        made: &[PathBuf],
    ) -> Result<(), Error> {
        let claimed = self.claimable(dest, made);
        if claimed == announced {
            return Ok(());
        }
        Err(fs::Error::Changed {
            path: dest.to_path_buf(),
            detail: format!(
                "bx meant to create {announced:?} on the way to it, and created {claimed:?}"
            ),
        }
        .into())
    }

    /// Tell the ledger about a write that has landed: record the entry, or,
    /// for a write that hands the target back, drop it.
    fn settle_entry(&mut self, target: &Portable, entry: Option<NewEntry>) -> Result<(), Error> {
        match entry {
            Some(entry) => {
                self.ledger.record(entry)?;
            }
            // The restore half of `bx rm`. The entry goes, but the directories
            // it claimed still stand and bx still made them, so its claims are
            // handed to a surviving entry beneath them when the session
            // finishes — exactly as `Session::forget` and `Session::remove`
            // hand theirs on. Dropped here instead, no entry would claim them
            // and no later `rm` could remove them: see `r3 round 3` decision 2.
            // `self.forgotten`, not `self.released`, because this write
            // announced no removal and so prunes nothing.
            None => {
                if let Some(dropped) = self.ledger.forget(target) {
                    self.forgotten.extend(
                        dropped
                            .created_dirs
                            .iter()
                            .map(|dir| dir.render(&self.home)),
                    );
                }
            }
        }
        Ok(())
    }

    /// The link path: record, journal, stage, publish, done — the file path
    /// with a link in place of a file, and nothing to fill.
    ///
    /// Staged against `planned` through [`crate::fs::stage_link_as`], which
    /// refuses anything but nothing or a link, and a destination that changed
    /// since plan. The prior is a link's text, stored in `restore/` before the
    /// Intent that names it, and the Intent is marked [`Intent::link`], so a
    /// rollback puts back a link rather than a file holding its text. As in
    /// `write`, the Intent names the temporary link and the directories made
    /// for it before either exists.
    fn write_link(
        &mut self,
        target: Portable,
        dest: PathBuf,
        text: &Path,
        planned: &Observed,
        ownership: &Ownership,
    ) -> Result<(), Error> {
        let index = self.written;
        // As in `write`: plan's verdict before any directory is made, and
        // every refusal `stage_link` would make before anything is announced.
        refuse_unplanned(&dest, planned)?;
        self.make_shared_ancestors(&dest)?;
        let observed = fs::refuse_stage_link(&dest, planned, &self.created)?;
        let temp = fs::temp_beside(&dest)?;
        let created_dirs = missing_parents(&dest, &self.home, &self.created);
        let written = fs::link::digest(text);
        let (entry, mechanism) = match ownership {
            Ownership::Owned(mechanism) => (
                Some(
                    NewEntry::new(
                        target.clone(),
                        written,
                        Mode::LINK,
                        mechanism.clone(),
                        link_prior_bytes(&observed),
                    )
                    .with_created_dirs(portable_dirs(&created_dirs, &self.home)?),
                ),
                Some(mechanism.clone()),
            ),
            Ownership::Released => (None, None),
        };
        // As in `write`: refused before anything is stored or announced.
        if let Some(entry) = &entry {
            self.ledger.check_record(entry)?;
        }
        let before = store_link_prior(&self.state, &observed)?;

        let ledger_written = self.ledger.get(&target).map(|entry| entry.written);
        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: Some(temp.clone()),
            before,
            after: Written::Present {
                digest: written,
                mode: Mode::LINK,
            },
            created_dirs: created_dirs.clone(),
            mechanism,
            ledger_written,
            dir: false,
            link: true,
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        #[cfg(test)]
        if let Some(meddle) = self.after_intent {
            meddle(&dest);
        }
        let staged = fs::stage_link_as(&dest, &temp, text, planned, &mut self.created)?;
        self.crash.reached(index, Phase::AfterStage);
        let made = staged.created_dirs().to_vec();
        let published = (|| -> Result<(), Error> {
            self.refuse_unannounced(&dest, &created_dirs, staged.created_dirs())?;
            // A link is complete when it is made: there is no content to fill.
            self.crash.reached(index, Phase::AfterFill);

            #[cfg(test)]
            if let Some(meddle) = self.before_publish {
                meddle(staged.dest());
            }
            staged
                .publish()
                .map_err(crate::fs::Unpublished::into_error)?;
            Ok(())
        })();
        // As in `write`.
        published.or_else(|error| unmake(&made, error))?;
        self.settle_entry(&target, entry)?;
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// The removal path: check, record, journal, check again, unlink, done. The
    /// directories the target claimed are pruned when the session finishes.
    ///
    /// Checked against `planned`, the observation plan decided on, twice. First
    /// before the prior is stored or the Intent announced, so a destination
    /// that changed since plan is refused with nothing written anywhere. Then
    /// immediately before the unlink, as [`crate::fs::Filled::publish`] checks
    /// before its rename, so an edit that lands while the snapshot and the
    /// Intent are made durable is refused rather than unlinked; recovery then
    /// finds a destination holding neither recorded state and leaves it alone.
    /// What stays open is the window between that last look and the `unlink`
    /// call itself.
    ///
    /// `link` says the target is a symlink: then only a link is removed, its
    /// text is the prior stored, and the Intent is marked [`Intent::link`].
    fn remove(
        &mut self,
        index: usize,
        target: Portable,
        dest: PathBuf,
        created_dirs: Vec<PathBuf>,
        planned: &Observed,
        link: bool,
    ) -> Result<(), Error> {
        let observed = refuse_unplanned(&dest, planned)?;
        if link && observed.kind != fs::Kind::Symlink {
            return Err(fs::Error::NotALink {
                path: dest,
                kind: observed.kind,
            }
            .into());
        }
        if !link && !observed.kind.is_writable_destination() {
            return Err(fs::Error::NotAFile {
                path: dest,
                kind: observed.kind,
            }
            .into());
        }

        // Same as in `write`: the bytes the removal is about to displace are
        // made durable before the Intent frame that names them.
        let before = if link {
            store_link_prior(&self.state, &observed)?
        } else {
            store_prior(&self.state, &observed)?
        };

        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: None,
            before,
            after: Written::Absent,
            created_dirs: created_dirs.clone(),
            mechanism: None,
            ledger_written: self.ledger.get(&target).map(|entry| entry.written),
            dir: false,
            link,
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        #[cfg(test)]
        if let Some(meddle) = self.before_unlink {
            meddle(&dest);
        }
        // The last look before the unlink: storing the snapshot and the Intent
        // took two `fsync`s, and an editor may have saved in between.
        refuse_moved(planned, &fs::observe(&dest)?)?;
        unlink(&dest)?;
        // Pruned only once the session's `End` is durable: see
        // `Session::finish`.
        self.released.extend(created_dirs);
        // As in `write`: the entry goes only once the file has. The entry is
        // dropped deliberately: its claims are the `created_dirs` the Intent
        // already carries into `self.released` above.
        let _ = self.ledger.forget(&target);
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// The directory path: check, record, journal, make, done.
    ///
    /// Checked against `planned` before anything is recorded or announced, by
    /// the verdict [`crate::fs::compare_dir`] reaches from it and from a fresh
    /// look — the comparison [`crate::fs::ensure_dir`] makes again before it
    /// acts. A directory an earlier write in this session made where plan saw
    /// nothing is still the create plan announced, as `ensure_dir` treats it.
    ///
    /// The Intent names the parents the create will invent, read from disk as
    /// `ensure_dir` reads them, less a directory another directory target
    /// declares. The ledger records the ones `ensure_dir` reports it made.
    fn write_dir(
        &mut self,
        target: Portable,
        dest: PathBuf,
        planned: &Observed,
        mode: Mode,
        ownership: &Ownership,
    ) -> Result<(), Error> {
        let index = self.written;
        let announced = fs::compare_dir(planned, mode);
        if !matches!(announced.drift, fs::Drift::Create | fs::Drift::Modify) {
            return Err(fs::Error::Changed {
                path: dest,
                detail: "plan announced nothing for bx to make here".to_string(),
            }
            .into());
        }
        let fresh = fs::observe(&dest)?;
        let made_here = planned.kind == fs::Kind::Absent
            && fresh.kind == fs::Kind::Dir
            && self.created.contains(&dest);
        if !made_here && fs::compare_dir(&fresh, mode) != announced {
            return Err(fs::Error::Changed {
                path: dest,
                detail: "it is no longer what plan compared".to_string(),
            }
            .into());
        }

        let found = planned.mode.filter(|_| planned.kind == fs::Kind::Dir);
        let before = found.map_or(Prior::Absent, dir_prior);
        let invented = if found.is_none() && !made_here {
            missing_parents(&dest, &self.home, &self.created)
        } else {
            Vec::new()
        };
        let (entry, mechanism) = match ownership {
            Ownership::Owned(mechanism) => {
                let prior = found.map_or(PriorBytes::Absent, |mode| PriorBytes::Bytes {
                    bytes: DIR_BYTES.to_vec(),
                    mode,
                });
                (
                    Some(NewEntry::new(
                        target.clone(),
                        dir_digest(),
                        mode,
                        mechanism.clone(),
                        prior,
                    )),
                    Some(mechanism.clone()),
                )
            }
            Ownership::Released => (None, None),
        };
        // As in `write`: the ledger's refusal is asked before anything is
        // announced or made.
        if let Some(entry) = &entry {
            self.ledger.check_record(entry)?;
        }

        let ledger_written = self.ledger.get(&target).map(|entry| entry.written);
        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: None,
            before,
            after: Written::Present {
                digest: dir_digest(),
                mode,
            },
            created_dirs: invented,
            mechanism,
            ledger_written,
            dir: true,
            link: false,
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        let ensured = fs::ensure_dir(&dest, mode, planned, &mut self.created)?;
        match entry {
            Some(entry) => {
                let claimed = ensured
                    .created_dirs
                    .iter()
                    .filter(|dir| **dir != dest)
                    .map(|dir| {
                        Portable::from_path(dir, &self.home).map_err(|source| {
                            fs::Error::NotPortable {
                                path: dir.clone(),
                                source,
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.ledger.record(entry.with_created_dirs(claimed))?;
            }
            None => {
                // Released: bx gives the directory up, so the entry is
                // dropped deliberately, as `remove` drops a file's.
                let _ = self.ledger.forget(&target);
            }
        }
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// The directory removal path: check, journal, check again, remove where
    /// empty, done.
    ///
    /// Checked against `planned` twice, as [`Session::remove`] checks a file.
    /// The directory and the parents it claims are released rather than
    /// forced: each goes where it is empty and no surviving entry names it,
    /// and [`Session::finish`] tries again and hands what still stands to an
    /// entry beneath it.
    fn remove_dir(
        &mut self,
        index: usize,
        target: Portable,
        dest: PathBuf,
        created_dirs: Vec<PathBuf>,
        planned: &Observed,
    ) -> Result<(), Error> {
        let observed = fs::observe(&dest)?;
        refuse_moved(planned, &observed)?;
        let Some(mode) = observed.mode.filter(|_| observed.kind == fs::Kind::Dir) else {
            return Err(fs::Error::Changed {
                path: dest,
                detail: "plan saw no directory here".to_string(),
            }
            .into());
        };

        self.journal.append(&Record::Intent(Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: None,
            before: dir_prior(mode),
            after: Written::Absent,
            created_dirs: created_dirs.clone(),
            mechanism: None,
            ledger_written: self.ledger.get(&target).map(|entry| entry.written),
            dir: true,
            link: false,
        }))?;
        self.crash.reached(index, Phase::AfterIntent);

        #[cfg(test)]
        if let Some(meddle) = self.before_unlink {
            meddle(&dest);
        }
        refuse_moved(planned, &fs::observe(&dest)?)?;
        // The entry goes first here: `prune_claims` never removes a directory
        // an entry still names, and this one names the directory itself. The
        // entry is dropped deliberately: its claims are `created_dirs`, which
        // are pruned and released below.
        let _ = self.ledger.forget(&target);
        let mut claims = Vec::with_capacity(created_dirs.len() + 1);
        claims.push(dest);
        claims.extend(created_dirs);
        self.ledger.prune_claims(&self.home, &claims)?;
        self.released.extend(claims);
        self.crash.reached(index, Phase::AfterPublish);

        self.journal.append(&Record::Done(Done { target }))?;
        self.crash.reached(index, Phase::AfterDone);
        Ok(())
    }

    /// Declare that a directory target in this session wants `path` at `mode`.
    ///
    /// Call it for every directory target the session will make, before the
    /// first [`Session::apply`]: see [`crate::fs::CreatedDirs::declare`]. A
    /// file staged beneath a declared directory that is still wider than
    /// declared is then refused rather than published into it.
    pub fn declare_dir(&mut self, path: &Path, mode: Mode) {
        self.created.declare(path, mode);
    }

    /// Prune the union of the directories released targets claimed, and hand
    /// what still stands to the entries beneath it.
    ///
    /// A removal prunes nothing itself: a directory removed before the
    /// session's `End` would have to be re-created by a rollback, which cannot
    /// know the mode it had. Deferring the prune costs no later target in the
    /// session anything, because a directory an entry the ledger still holds
    /// names is never pruned, so no later target can need a claimed directory
    /// gone. By the time the session finishes every removal has run, so each
    /// claimed directory is tried once, deepest first. Nothing is assumed
    /// about which entry claimed it: it is removed when it is empty and no
    /// entry the ledger still holds names it. A claim still standing — a
    /// released one, or one of a target this session dropped from the ledger
    /// without announcing a removal ([`Session::forget`], or a
    /// [`Ownership::Released`] write) — is
    /// given to a surviving entry beneath it, so the `rm` that removes that
    /// entry removes the directory too.
    fn settle_claims(&mut self) -> Result<(), Error> {
        let released = std::mem::take(&mut self.released);
        self.ledger.prune_claims(&self.home, &released)?;
        let forgotten = std::mem::take(&mut self.forgotten);
        Ok(self
            .ledger
            .hand_off_claims(&self.home, released.iter().chain(&forgotten))?)
    }

    /// End the session: [`End`], settle the claimed directories, save the
    /// ledger, and unlink the journal last.
    ///
    /// The directories released targets claimed are settled only after the
    /// `End` frame is durable: see [`Session::settle_claims`]. Until then no
    /// directory a removal claimed is removed, so a crash before `End` rolls
    /// the session back into the very directories it found, at the modes they
    /// had — never into one re-created at the default mode. A crash between
    /// `End` and the prune leaves those directories standing, empty, and
    /// claimed by no entry once recovery has recorded the session: the same
    /// kind of orphan decision 11 keeps, which recovery leaves where it is and
    /// [`crate::recover::pending`] names.
    ///
    /// The order is the ordering rule that makes recovery idempotent. The `End`
    /// frame goes down first, so a crash before the save is a *terminated*
    /// journal that recovery finishes as bookkeeping and no destination is
    /// touched. The journal is unlinked last, so a crash — or a failed unlink —
    /// after the save leaves a terminated journal over a ledger that already
    /// holds every write in it; recovery recognises those entries by
    /// [`Intent::ledger_written`] and leaves them exactly as they are.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], [`Error::State`] or [`Error::Write`]. The journal is left
    /// in place on any failure, so the session stays recoverable.
    /// [`Error::Poisoned`] when a write in the session failed: nothing is
    /// appended, nothing is saved, and the journal is left for recovery.
    pub fn finish(mut self) -> Result<usize, Error> {
        if self.poisoned {
            return Err(self.poisoned_error());
        }
        let written = self.written;
        self.journal.append(&Record::End(End { written }))?;
        self.crash.reached(written, Phase::AfterEnd);
        self.settle_claims()?;
        self.ledger.save()?;
        self.crash.reached(written, Phase::AfterSave);
        unlink(self.journal.path())?;
        tracing::debug!(written, "closed a journalled session");
        Ok(written)
    }
}

/// Copy the bytes a write is about to displace into `restore/`, durably, and
/// describe where they went.
///
/// Deliberately **not** [`crate::state::Ledger::record`], which answers a
/// different question. The ledger keeps the *first* prior it was ever given for
/// a target, and that is right: what `bx rm` owes the user is the file as it was
/// before bx ever touched it. A rollback owes them something else — whatever was
/// on disk a moment ago, which for a target bx already manages is bx's own
/// previous output. Asking `record` for that would hand back the original and
/// leave recovery comparing the destination against a state it has not been in
/// since the first `apply`, so every repeat write would look like a conflict
/// after a crash.
///
/// Nothing is duplicated on disk. Both copies are content-addressed under the
/// same `restore/<digest>` name, so identical bytes are one file, and a write
/// that displaces bytes the ledger already holds stores nothing at all.
///
/// # Errors
///
/// [`Error::Write`] when the snapshot cannot be stored. It is `fsync`ed, along
/// with the directory entry naming it, before this returns.
fn store_prior(state: &StateDir, observed: &Observed) -> Result<Prior, Error> {
    Ok(restore::store(state, PriorBytes::of(observed))?)
}

/// [`store_prior`] for a symlink target: the link's text is its bytes.
///
/// # Errors
///
/// As [`store_prior`].
fn store_link_prior(state: &StateDir, observed: &Observed) -> Result<Prior, Error> {
    Ok(restore::store(state, link_prior_bytes(observed))?)
}

/// What a symlink target displaces, in the shape a ledger entry records: the
/// link's text at [`Mode::LINK`], or nothing when no link was there.
fn link_prior_bytes(observed: &Observed) -> PriorBytes {
    use std::os::unix::ffi::OsStrExt as _;

    match &observed.link {
        Some(text) => PriorBytes::Bytes {
            bytes: text.as_os_str().as_bytes().to_vec(),
            mode: Mode::LINK,
        },
        None => PriorBytes::Absent,
    }
}

/// Look at `dest`, and refuse it unless it is still what `planned` observed.
///
/// The opening move of both write paths: [`Session::write`] before it makes
/// any directory, and [`Session::remove`] before it stores a prior or
/// announces an Intent. A destination that changed since `plan` is refused
/// with nothing made, stored, announced or touched.
///
/// # Errors
///
/// [`Error::Read`] when the destination cannot be looked at — a parent that
/// does not resolve, or one this process may not search — and [`Error::Write`]
/// with [`crate::fs::Error::Changed`] when it is no longer what plan saw.
fn refuse_unplanned(dest: &Path, planned: &Observed) -> Result<Observed, Error> {
    let observed = fs::observe(dest)?;
    refuse_moved(planned, &observed)?;
    Ok(observed)
}

/// The deepest ancestor of `dest` that is `home` or above it and is not
/// there, or `None` when every one of them already is.
///
/// Creating that one creates every ancestor of it too, so it is the whole
/// answer. It is exactly the set [`stray_created_dir`] refuses a claim for:
/// a directory bx must make to reach the destination and must never remove,
/// because the home lives under it.
fn shared_ancestor(dest: &Path, home: &Path) -> Option<PathBuf> {
    // "Cannot look" is not "not there". An `EACCES` on the way up is a
    // directory that exists and that this process may not examine, and
    // treating it as missing would try to create it and report the failure as
    // a write — where [`crate::fs::observe`], which has already looked at the
    // destination through the same chain, reports it as a read (`r3 round 7`,
    // D2).
    let missing = |dir: &Path| {
        std::fs::symlink_metadata(dir)
            .err()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    };
    dest.ancestors()
        .skip(1)
        .find(|dir| home.starts_with(dir) && missing(dir))
        .map(Path::to_path_buf)
}

/// Every directory in `dirs`, made portable against `home`.
///
/// # Errors
///
/// [`Error::Write`] with [`crate::fs::Error::NotPortable`] for one that cannot
/// be, which a ledger would refuse to store. Unreachable from both callers,
/// [`Session::write`] and [`Session::write_link`], which pass the
/// [`missing_parents`] of a destination [`Session::admit`] has already checked
/// is its target rendered against the session's home. [`Session::open`]
/// refuses a home that is not absolute or not UTF-8, so each such parent is an
/// absolute, normalised UTF-8 path, which
/// [`Portable::from_path`] always converts. Kept rather than unwrapped — a panic in a writer's durability
/// path is worse than a returned error nothing produces — and named here so it
/// reads as a gap on purpose (`r3 round 6`, COV3), like `plan_restore`'s own
/// unreachable `Err` arm.
fn portable_dirs(dirs: &[PathBuf], home: &Path) -> Result<Vec<Portable>, Error> {
    dirs.iter()
        .map(|dir| {
            Portable::from_path(dir, home).map_err(|source| {
                fs::Error::NotPortable {
                    path: dir.clone(),
                    source,
                }
                .into()
            })
        })
        .collect()
}

/// Hand on `error`, the refusal of a staged write, once the directories the
/// stage just made — `made`, deepest first — are removed where they stand
/// empty.
///
/// The stage made them in this process a moment ago, so they are bx's without
/// any record to show it; the refused write dropped its temporary file on the
/// way here. Left standing, one the Intent did not predict (a parent deleted
/// between the prediction and the stage) is in neither the journal nor the
/// ledger, and no rollback or `rm` would ever remove it; one it did predict no
/// longer holds the temporary file, so the rollback could not show it was made
/// (see [`fs::remove::prune_beneath`]). `rmdir` only, stopping at the first that is not
/// empty, as [`prune_dirs`] does. A failure to remove one is logged and the
/// refusal is still what is returned: it is the cause the user needs.
///
/// # Errors
///
/// `error`, always.
fn unmake(made: &[PathBuf], error: Error) -> Result<(), Error> {
    if let Err(prune) = prune_dirs(made) {
        tracing::warn!(
            %prune,
            "a directory a refused write made could not be removed; it is left for bx doctor",
        );
    }
    Err(error)
}

#[cfg(test)]
mod tests;
