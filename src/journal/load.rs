//! Reading a journal back: what is at its path, what its frames say once each
//! is judged against the home its header names, and setting aside a journal
//! that cannot be believed.

use std::path::{Path, PathBuf};

use super::format::{Damage, FORMAT, HEADER, MAGIC, NONCE, frame, whole_frame_after};
use super::{Begin, Error, Intent, Record};
use crate::fs;
use crate::fs::remove::{open_dir, sync_dir};
use crate::paths::Portable;
use crate::state::ExclusiveLock;

/// What was found at a journal's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// There is no journal: no session is in flight.
    Absent,
    /// The journal ends with [`End`](super::End), so every write in it was published and
    /// only the ledger may be behind.
    Terminated(Vec<Record>),
    /// The journal has no [`End`](super::End): the session was interrupted.
    Unterminated(Vec<Record>),
    /// The journal has no [`End`](super::End), and ends in bytes that are not a whole
    /// frame, with no whole frame after them: the session was interrupted while
    /// it appended one. The bytes either stop short of a frame, as a killed
    /// process leaves them, or fail their checksum, as a power loss that
    /// zero-fills an unsynced tail leaves them.
    ///
    /// The whole frames before them are what [`Loaded::Unterminated`] would
    /// hold, and recovery rolls them back the same way. The difference is what
    /// becomes of the file. A frame a crash tore announces a write that had not
    /// begun, but bytes that stop short are also what a damaged length looks
    /// like, and that would hide every frame after it. So once recovery is done
    /// with a journal it discarded anything from, it sets the file aside rather
    /// than unlinking it.
    Torn {
        /// The whole frames, in the order they were written.
        records: Vec<Record>,
        /// How many bytes after them were not a whole frame.
        discarded: usize,
    },
    /// The bytes are not a journal a bx session could have written: a wrong
    /// header or an older format, a first frame that is not whole, a later frame whose
    /// checksum or decoding fails with a whole frame after it, bytes after its
    /// [`End`](super::End), or a record that stores a path its session could not have
    /// written. See [`load`].
    ///
    /// It is not believed, so recovery rolls nothing back and a session opens
    /// over it as over [`Loaded::Absent`]; [`crate::recover::pending`] still
    /// reports it, so a read-only command does not hide it. [`load_exclusive`]
    /// moves the bytes aside — never deletes them, and never over a journal set
    /// aside earlier — and [`load`], which runs without the lock, leaves them
    /// where they are. What the write may have completed is then recomputed by
    /// `plan`, which reports a file bx wrote but never recorded as a conflict:
    /// skipped, never overwritten. A journal [`load_exclusive`] cannot move
    /// aside is never this value, but [`Error::CannotSetAside`].
    Unreadable {
        /// Where the bytes were kept, or `None` if they were not moved because
        /// the read held no lock.
        moved_to: Option<PathBuf>,
    },
}

impl Loaded {
    /// Every [`Intent`], in the order it was written.
    pub fn intents(&self) -> impl DoubleEndedIterator<Item = &Intent> {
        self.records().iter().filter_map(|record| match record {
            Record::Intent(intent) => Some(intent),
            _ => None,
        })
    }

    /// Every [`Intent`], in the order it was written, with whether it was
    /// published.
    ///
    /// A session appends an Intent's [`Done`](super::Done) as the very next frame, and a
    /// session whose write fails appends nothing more at all, so "the next frame
    /// is its `Done`" is exactly "it landed".
    #[must_use]
    pub fn landed(&self) -> Vec<(&Intent, bool)> {
        let records = self.records();
        records
            .iter()
            .enumerate()
            .filter_map(|(at, record)| match record {
                Record::Intent(intent) => Some((
                    intent,
                    matches!(
                        records.get(at + 1),
                        Some(Record::Done(done)) if done.target == intent.target
                    ),
                )),
                _ => None,
            })
            .collect()
    }

    /// The session header, if the journal has one.
    #[must_use]
    pub fn begin(&self) -> Option<&Begin> {
        self.records().iter().find_map(|record| match record {
            Record::Begin(begin) => Some(begin),
            _ => None,
        })
    }

    /// The frames, which is nothing at all for the two empty outcomes.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        match self {
            Self::Terminated(records)
            | Self::Unterminated(records)
            | Self::Torn { records, .. } => records,
            Self::Absent | Self::Unreadable { .. } => &[],
        }
    }

    /// Whether a session is unresolved: recorded, and not known to be cleared.
    #[must_use]
    pub const fn is_interrupted(&self) -> bool {
        matches!(
            self,
            Self::Terminated(_) | Self::Unterminated(_) | Self::Torn { .. }
        )
    }
}

/// Read a journal, classifying anything a crash can leave behind, and move
/// nothing.
///
/// A torn *tail* — bytes after the last whole frame, with no whole frame after
/// them — is discarded and reported as [`Loaded::Torn`]. That covers bytes that
/// stop short of a frame, which is what a process killed mid-append leaves, and
/// a frame that is all there but fails its checksum or its decoding, which is
/// what a power loss that zero-fills an unsynced tail leaves. Either way the
/// ordering discipline in [`Session::apply`](super::Session::apply) means a frame whose `fsync` had not
/// returned announces a write that had not begun, and every frame before it is
/// checksum-verified. A file that is only a prefix of a header, or a header
/// alone, is a session that wrote nothing: [`Loaded::Unterminated`] with no
/// records.
///
/// Everything else that is not whole frames is [`Loaded::Unreadable`]: a wrong
/// magic or an older format; a first frame that is torn or damaged, which no crash
/// leaves, because [`Journal::create`](super::Journal::create) renames the header and the first frame
/// into place together; a frame whose checksum or decoding fails **with a whole
/// frame after it**, which no crash leaves either, because only the last frame
/// can be unsynced; and bytes after an [`End`](super::End). That is damage bx cannot place,
/// and it is not believed.
///
/// One case stays a torn tail though it may be damage: a length damaged to
/// point past the end of the file hides the frames after it inside its own
/// claimed extent. Its whole frames before it are rolled back, which undoes
/// nothing the hidden frames announced, and the file is kept.
///
/// This is the read [`crate::recover::pending`] makes without the state lock,
/// so it never renames, unlinks or writes: the journal it is looking at may
/// belong to a session running right now. Setting an unreadable journal aside
/// is [`load_exclusive`]'s, and only the lock holder's.
///
/// # Errors
///
/// [`Error::Io`] when the file exists and cannot be read at all. Damage is a
/// value, not an error; only a failure to look is. [`Error::FutureVersion`]
/// for a journal a newer bx wrote, which is not damage and is never set aside.
/// [`Error::NotAJournal`] for a path that is not a regular file, which is
/// never opened.
pub fn load(path: &Path) -> Result<Loaded, Error> {
    Ok(match inspect(path)? {
        Ok(loaded) => loaded,
        Err(why) => {
            tracing::warn!(
                path = %path.display(),
                "the write-ahead journal {} is unreadable: {why}. It is left in \
                 place for the next writing bx run to set aside.",
                path.display(),
            );
            Loaded::Unreadable { moved_to: None }
        }
    })
}

/// [`load`], and move an unreadable journal aside, to the number after the
/// highest of `journal.mpk.corrupt`, `journal.mpk.corrupt.1`, … present — or,
/// once the top number, `journal.mpk.corrupt.<u64::MAX>`, is present, the
/// lowest free one.
///
/// The [`ExclusiveLock`] is the proof that no session can be creating or
/// appending to the journal while it is moved. A reader without it could rename
/// a live journal out from under the session writing it, which is why [`load`]
/// does not. A journal set aside earlier is never renamed over: see
/// [`crate::state::StateDir::quarantine`].
///
/// # Errors
///
/// As [`load`], and [`Error::CannotSetAside`] for an unreadable journal that
/// cannot be moved aside, which is left in place. It is not reported as
/// [`Loaded::Unreadable`]: every caller treats that as nothing standing, and
/// [`Session::open`](super::Session::open) would create its own journal over the bytes.
pub fn load_exclusive(path: &Path, lock: &ExclusiveLock) -> Result<Loaded, Error> {
    match inspect(path)? {
        Ok(loaded) => Ok(loaded),
        Err(why) => quarantine(path, why, lock),
    }
}

/// Classify the bytes at `path`: what a session, or a crash of one, left there,
/// or why it is neither.
fn inspect(path: &Path) -> Result<Result<Loaded, &'static str>, Error> {
    // Looked at before it is opened, following no link. See
    // `Error::NotAJournal`.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(Error::NotAJournal {
                path: path.to_path_buf(),
                kind: fs::Kind::from(meta.file_type()),
            });
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Ok(Loaded::Absent)),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    // A journal unlinked since that look — `pending` takes no lock, and a
    // session may just have finished — is as absent as one never there.
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Ok(Loaded::Absent)),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    if bytes.len() <= MAGIC.len() {
        // A prefix of the magic is a header a crash tore.
        return Ok(if MAGIC.starts_with(&bytes) {
            Ok(Loaded::Unterminated(Vec::new()))
        } else {
            Err("it does not start with a bx journal header")
        });
    }
    if &bytes[..MAGIC.len()] != MAGIC.as_slice() {
        return Ok(Err("it does not start with a bx journal header"));
    }
    let found = bytes[MAGIC.len()];
    // Before anything else is classified: a newer format is not damage, and
    // nothing this build could decide about its bytes is believable.
    if found > FORMAT {
        return Err(Error::FutureVersion {
            path: path.to_path_buf(),
            found,
            supported: FORMAT,
        });
    }
    if found != FORMAT {
        return Ok(Err("it is a journal format this bx cannot read"));
    }
    // A header cut inside its nonce is still a header a crash tore.
    let Some(nonce) = bytes
        .get(MAGIC.len() + 1..HEADER)
        .and_then(|nonce| <[u8; NONCE]>::try_from(nonce).ok())
    else {
        return Ok(Ok(Loaded::Unterminated(Vec::new())));
    };

    let mut records = Vec::new();
    let mut at = HEADER;
    let mut discarded = 0;
    while at < bytes.len() {
        match frame(&bytes, at, &nonce) {
            Ok((record, next)) => {
                records.push(record);
                at = next;
            }
            // The header and the first frame are renamed into place together,
            // so no crash leaves the one without the other whole.
            Err(_) if records.is_empty() => {
                return Ok(Err("its first frame is not a whole record"));
            }
            Err(_) if matches!(records.last(), Some(Record::End(_))) => {
                return Ok(Err("bytes follow the end of its session"));
            }
            // Every append is one `fsync`ed write of a whole frame at the end of
            // the file, so a crash only ever damages the last frame: a process
            // killed mid-write cuts it short, and a power loss can zero-fill or
            // leave stale blocks in its unsynced bytes. A frame that fails with a
            // whole frame bx wrote after it is none of those. It is damage in the
            // middle of the log, and the frames it hides are not believed either.
            Err(Damage::Invalid) if whole_frame_after(&bytes, at, &nonce) => {
                return Ok(Err(
                    "a frame after its first is damaged, and a whole frame follows it",
                ));
            }
            Err(_) => {
                discarded = bytes.len() - at;
                tracing::warn!(
                    path = %path.display(),
                    discarded,
                    "the write-ahead journal ends in bytes that are not a whole frame; \
                     the whole frames before them are rolled back, and the file is set \
                     aside rather than deleted once it is recovered",
                );
                break;
            }
        }
    }

    if let Some(why) = refusal(&records) {
        return Ok(Err(why));
    }

    Ok(Ok(if matches!(records.last(), Some(Record::End(_))) {
        Loaded::Terminated(records)
    } else if discarded > 0 {
        Loaded::Torn { records, discarded }
    } else {
        Loaded::Unterminated(records)
    }))
}

/// Why the journal could not have been written by a bx session, if it could
/// not.
///
/// A journal is believed only as far as a session could have written it,
/// because everything recovery does with one — unlink a temporary file, rewrite
/// or unlink a destination, remove directories — is done to the paths it
/// stores. A journal that fails any rule below is bytes bx never wrote, and the
/// caller treats it as unreadable: [`load`] leaves it in place and
/// [`load_exclusive`] sets it aside. It is never believed, so it can never
/// drive a rollback.
///
/// * **A header first, and only first.** Every other rule needs the home, and
///   the home is the [`Begin`]'s. A session writes exactly one, as the file's
///   first frame, and writes nothing after its [`End`](super::End).
/// * **Portable paths.** Decoding a [`Portable`] applies every rule that needs
///   no home. The one that does cannot run in a decoder: `/<home>/.gitconfig`
///   is well-formed, and on the account whose home that is, a second key for
///   `~/.gitconfig`. So the header's home, its scope, and each [`Intent`]'s and
///   [`Done`](super::Done)'s target go through [`Portable::check_against`].
/// * **An intent's paths are its target's.** The destination is exactly where
///   the target renders, which [`Session::apply`](super::Session::apply) also refuses to break; the
///   temporary file is a `.bx-` file beside the destination, the only place
///   [`crate::fs::stage`] puts one; and each created directory is a parent of
///   the destination that is neither the home nor above it.
/// * **One write per target.** See [`Error::Repeated`].
fn refusal(records: &[Record]) -> Option<&'static str> {
    let (first, rest) = records.split_first()?;
    let Record::Begin(begin) = first else {
        return Some("it records a session with no header before it");
    };
    if let Err(error) = Portable::parse_in("~", &begin.home) {
        tracing::warn!(%error, "the journal's session header names an unusable home");
        return Some("its session header names a home that is not an absolute UTF-8 path");
    }
    let home = begin.home.as_path();
    if let Some(refused) = records
        .iter()
        .flat_map(|record| match record {
            Record::Begin(begin) => begin.scope.iter().collect::<Vec<_>>(),
            Record::Intent(intent) => vec![&intent.target],
            Record::Done(done) => vec![&done.target],
            Record::End(_) => Vec::new(),
        })
        .find_map(|portable| portable.check_against(home).err())
    {
        tracing::warn!(error = %refused, "a journal record stores a path its session's home refuses");
        return Some("it records a path that is not portable against its session's home");
    }
    let mut targets = std::collections::HashSet::new();
    for (at, record) in rest.iter().enumerate() {
        match record {
            Record::Begin(_) => return Some("it has a second session header"),
            Record::End(_) if at + 1 < rest.len() => {
                return Some("a record follows the end of its session");
            }
            Record::Intent(intent) => {
                if let Some(why) = misplaced(intent, home) {
                    return Some(why);
                }
                if !targets.insert(&intent.target) {
                    return Some("it records two writes to one target");
                }
            }
            Record::Done(_) | Record::End(_) => {}
        }
    }
    None
}

/// Why an intent stores a path its own target could not have, if it does.
fn misplaced(intent: &Intent, home: &Path) -> Option<&'static str> {
    let dest = &intent.dest;
    if *dest != intent.target.render(home) {
        return Some("an intent's destination is not where its target renders");
    }
    if intent.dir && intent.link {
        return Some("an intent names its destination both a directory and a link");
    }
    if let Some(temp) = &intent.temp {
        if intent.dir {
            return Some("a directory intent names a temporary file");
        }
        let staged = temp != dest
            && temp.parent() == dest.parent()
            && temp
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(fs::TEMP_PREFIX));
        if !staged {
            return Some(
                "an intent's temporary file is not a bx temporary file beside its destination",
            );
        }
    }
    if stray_created_dir(dest, home, &intent.created_dirs).is_some() {
        return Some(
            "an intent's created directory is not a parent of its destination below the home",
        );
    }
    None
}

/// The first of `dirs` that is not a strict parent of `dest` below `home`, if
/// one is not.
///
/// The one rule for a directory bx may claim it created for a destination,
/// shared by the loader, which refuses a journal breaking it, and by
/// [`Session::apply`](super::Session::apply), which refuses a removal that would write such a journal.
pub(super) fn stray_created_dir<'a>(
    dest: &Path,
    home: &Path,
    dirs: &'a [PathBuf],
) -> Option<&'a PathBuf> {
    dirs.iter()
        .find(|dir| *dir == dest || !dest.starts_with(dir) || home.starts_with(dir))
}

/// The parents of `dest` that are not there, deepest first, strictly below
/// `home`, less any `created` declares for a directory target of its own.
///
/// What [`crate::fs::ensure_dir`] will invent on the way to `dest`, read the
/// way it reads it, and what a directory intent names before it is made. A
/// declared parent is its own target's to claim, exactly as
/// [`crate::fs::CreatedDirs`] leaves it out of every other claim.
pub(super) fn missing_parents(dest: &Path, home: &Path, created: &fs::CreatedDirs) -> Vec<PathBuf> {
    dest.ancestors()
        .skip(1)
        .filter(|dir| !dir.as_os_str().is_empty())
        .take_while(|dir| {
            matches!(
                std::fs::symlink_metadata(dir),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            )
        })
        .filter(|dir| !home.starts_with(dir) && created.declared(dir).is_none())
        .map(Path::to_path_buf)
        .collect()
}

/// Move a journal that carries no information aside, and say so.
///
/// The name is the number after the highest set-aside name present — or,
/// once the top number is present, the lowest free one — taken with
/// `RENAME_NOREPLACE` by [`crate::state::move_aside`], so an earlier
/// set-aside journal is never replaced.
///
/// # Errors
///
/// [`Error::CannotSetAside`] when the move fails. The journal is left where it
/// is, and it is an error rather than a value its caller could read as
/// "nothing stands": [`Session::open`](super::Session::open) would then create its own journal over
/// the bytes by rename.
fn quarantine(path: &Path, why: &str, lock: &ExclusiveLock) -> Result<Loaded, Error> {
    match crate::state::move_aside(path, lock) {
        Ok(aside) => {
            tracing::error!(
                path = %path.display(),
                moved_to = %aside.display(),
                "discarding the write-ahead journal {}: {why}. \
                 The bytes were kept, not deleted. Run `bx plan`: a file bx \
                 wrote but never recorded is reported as a conflict, never \
                 overwritten.",
                path.display(),
            );
            Ok(Loaded::Unreadable {
                moved_to: Some(aside),
            })
        }
        Err(source) => {
            tracing::error!(
                path = %path.display(),
                %source,
                "the write-ahead journal {} cannot be believed: {why}. \
                 It could not be moved aside, so it is left in place and \
                 nothing is written over it.",
                path.display(),
            );
            Err(Error::CannotSetAside {
                path: path.to_path_buf(),
                source,
            })
        }
    }
}

/// Move a journal aside, durably, and never over one set aside earlier.
///
/// The name is the number after the highest of `journal.mpk.corrupt`,
/// `journal.mpk.corrupt.1`, … present — or, once the top number is present,
/// the lowest free one — taken with `RENAME_NOREPLACE` by
/// [`crate::state::move_aside`] under the state directory's
/// [`ExclusiveLock`]. A second set-aside therefore succeeds, and every earlier
/// one survives intact.
///
/// # Errors
///
/// [`Error::Io`] for the failing `open` of the directory, `rename` or `fsync`.
/// Only a failing `fsync` is returned after the journal was moved.
pub(crate) fn set_aside(path: &Path, lock: &ExclusiveLock) -> Result<PathBuf, Error> {
    // Opened before the rename, as `unlink` opens before its unlink: in a
    // directory that can be written but not read, an open placed after the
    // rename fails with the journal already moved aside.
    let dir = path
        .parent()
        .map(|dir| open_dir(dir).map(|handle| (dir, handle)))
        .transpose()?;
    let aside = crate::state::move_aside(path, lock).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some((dir, handle)) = &dir {
        sync_dir(handle, dir)?;
    }
    Ok(aside)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    use crate::fs::Mode;
    use crate::journal::tests::{
        WRITES_THROUGH_PERMISSIONS, cannot_build, created, frame_starts, names_in, peek,
        permissions_refuse, plant_file, raw_journal, seal, some_begin,
        state_beyond_set_aside_names, target, write_to,
    };
    use crate::journal::{Done, End, Journal, Session, SessionKind, Written};
    use crate::state::{ContentHash, Mechanism, Prior, StateDir, dir_digest};
    use crate::testing::guarded_home;

    #[test]
    fn a_fresh_state_directory_has_no_session() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        assert_eq!(load(&state.journal()).expect("load"), Loaded::Absent);
    }

    #[test]
    fn a_journal_with_a_bad_header_is_moved_aside_by_the_lock_holder_and_read_as_absent() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        plant_file(&path, "GARBAGE!", Mode::PRIVATE_FILE);

        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None },
            "a read without the lock moves nothing",
        );
        assert!(path.is_file());

        let loaded = load_exclusive(&path, &lock).expect("load");
        let Loaded::Unreadable { moved_to } = &loaded else {
            panic!("expected Unreadable, got {loaded:?}")
        };
        let aside = moved_to.as_ref().expect("it should have been moved aside");
        assert_eq!(aside, &StateDir::quarantine(&path));
        assert!(!path.exists(), "the damaged journal is out of the way");
        assert_eq!(
            std::fs::read(aside).expect("the quarantined bytes"),
            b"GARBAGE!",
            "the bytes are kept, never deleted",
        );
        assert!(loaded.records().is_empty());
        assert!(!loaded.is_interrupted(), "it is read exactly as absent");
    }

    #[test]
    fn a_short_journal_that_is_not_the_start_of_a_header_is_unreadable() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        // Too short for a header, like a torn one, but not a prefix of one.
        plant_file(&path, "BY", Mode::PRIVATE_FILE);
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unreadable { .. }
        ));
    }

    #[test]
    fn a_journal_from_a_future_format_is_refused_and_never_moved_aside() {
        // Review round 5, item 2. It read as `Unreadable`, and the lock holder
        // set it aside with nothing rolled back.
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        drop(Journal::create(&path, some_begin()).expect("create"));
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[MAGIC.len()] = FORMAT + 1;
        std::fs::write(&path, &bytes).expect("write");

        for (how, loaded) in [
            ("load", load(&path)),
            ("load_exclusive", load_exclusive(&path, &lock)),
        ] {
            let err = loaded.expect_err(how);
            let Error::FutureVersion {
                path: named,
                found,
                supported,
            } = &err
            else {
                panic!("{how}: {err}")
            };
            assert_eq!((named, *found, *supported), (&path, FORMAT + 1, FORMAT));
            assert!(
                err.to_string().contains("run a bx at least as new"),
                "{err}"
            );
        }
        assert_eq!(std::fs::read(&path).expect("left in place"), bytes);
        assert!(!StateDir::quarantine(&path).exists());
    }

    #[test]
    fn a_journal_from_an_older_format_is_unreadable() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT - 1);
        bytes.extend_from_slice(&[0; NONCE]);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_run_of_nul_bytes_is_not_a_valid_frame() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT);
        bytes.extend(std::iter::repeat_n(0_u8, 4096));
        std::fs::write(&path, &bytes).expect("write");

        // Nothing decodes, so the journal carries no information at all.
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unreadable { .. }
        ));
    }

    #[test]
    fn nul_bytes_after_a_whole_frame_are_a_torn_tail() {
        // Review round 4, item 1. A filesystem that zero-fills an unsynced tail
        // after a power loss leaves them. Round 3 read that as damage and set
        // the journal aside with nothing rolled back; with no whole frame after
        // them they are the tail, and the whole frames before are kept.
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        drop(Journal::create(&path, some_begin()).expect("create"));

        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend(std::iter::repeat_n(0_u8, 512));
        std::fs::write(&path, &bytes).expect("write");

        let torn = Loaded::Torn {
            records: vec![Record::Begin(some_begin())],
            discarded: 512,
        };
        assert_eq!(load(&path).expect("load"), torn);
        assert_eq!(load_exclusive(&path, &lock).expect("load"), torn);
        assert_eq!(
            std::fs::read(&path).expect("left for recovery"),
            bytes,
            "the lock holder does not set a torn journal aside before recovery rolls it back",
        );
    }

    #[test]
    fn a_damaged_frame_is_a_torn_tail_only_when_no_whole_frame_follows_it() {
        // Review round 4, item 1. Only the last frame can be unsynced, so a
        // damaged last frame is what a power loss leaves, and a damaged frame
        // with a whole one after it is what no crash leaves.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let done = |rel: &str| {
            Record::Done(Done {
                target: Portable::try_from(format!("~/{rel}")).expect("portable"),
            })
        };
        let mut journal = Journal::create(&path, some_begin()).expect("create");
        journal.append(&done(".a")).expect("append");
        journal.append(&done(".b")).expect("append");
        drop(journal);
        let whole = std::fs::read(&path).expect("read");
        let starts = frame_starts(&whole);
        let last = starts[2];

        // The last frame's body, one byte flipped: its checksum fails.
        let mut flipped = whole.clone();
        flipped[whole.len() - 1] ^= 0x01;
        // The last frame zero-filled in place, length and checksum included.
        let mut zeroed = whole.clone();
        zeroed[last..].fill(0);
        for (case, bytes) in [("flipped", flipped), ("zeroed", zeroed)] {
            std::fs::write(&path, &bytes).expect("write");
            assert_eq!(
                load(&path).expect("load"),
                Loaded::Torn {
                    records: vec![Record::Begin(some_begin()), done(".a")],
                    discarded: whole.len() - last,
                },
                "{case}",
            );
        }

        // The middle frame's body, one byte flipped: `.b` is whole after it.
        let mut middle = whole.clone();
        middle[last - 1] ^= 0x01;
        std::fs::write(&path, &middle).expect("write");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_header_with_nothing_after_it_is_an_empty_interrupted_session() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut header = MAGIC.to_vec();
        header.push(FORMAT);
        std::fs::write(&path, &header).expect("write");
        assert_eq!(load(&path).expect("load"), Loaded::Unterminated(Vec::new()));
    }

    #[test]
    fn a_journal_without_an_end_record_is_an_interrupted_session() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        plant_file(&home.child(".conf"), "old\n", Mode::DEFAULT_FILE);

        let mut session =
            Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open");
        session
            .apply(write_to(home.path(), ".conf", "new\n", Mode::DEFAULT_FILE))
            .expect("apply");
        // Dropped, never finished: an abandoned session *is* an interrupted one.
        drop(session);

        let loaded = load(&state.journal()).expect("load");
        assert!(loaded.is_interrupted());
        assert!(matches!(loaded, Loaded::Unterminated(_)));
        assert_eq!(loaded.intents().count(), 1);
        assert_eq!(loaded.begin().expect("a header").kind, SessionKind::Apply);
    }

    #[test]
    fn a_journal_truncated_at_any_byte_offset_keeps_every_whole_frame() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let source = dir.path().join("source.mpk");
        let records = [
            Record::Begin(Begin {
                kind: SessionKind::Apply,
                home: PathBuf::from("/home/someone"),
                scope: vec![Portable::try_from("~/.a".to_string()).expect("portable")],
            }),
            Record::Done(Done {
                target: Portable::try_from("~/.a".to_string()).expect("portable"),
            }),
            Record::Done(Done {
                target: Portable::try_from("~/.b".to_string()).expect("portable"),
            }),
            Record::End(End { written: 2 }),
        ];

        // Record the file length after each frame, so "every whole frame" is an
        // exact expectation rather than an approximation.
        let Record::Begin(begin) = &records[0] else {
            unreachable!("the first record is the header")
        };
        let mut journal = Journal::create(&source, begin.clone()).expect("create");
        let mut boundaries: Vec<usize> = Vec::new();
        for (at, record) in records.iter().enumerate() {
            if at > 0 {
                journal.append(record).expect("append");
            }
            boundaries.push(
                std::fs::metadata(&source)
                    .expect("stat")
                    .len()
                    .try_into()
                    .expect("a small journal"),
            );
        }
        drop(journal);
        let whole: Vec<u8> = std::fs::read(&source).expect("read");

        for cut in 0..=whole.len() {
            let path = dir.path().join(format!("cut-{cut}.mpk"));
            std::fs::write(&path, &whole[..cut]).expect("write");
            let loaded = load(&path).expect("load");

            // A cut inside the header is a session that wrote nothing. A cut
            // inside the Begin is damage no crash leaves, because the journal is
            // created whole. A cut anywhere later keeps every whole frame, and
            // says how much it discarded.
            let kept: usize = boundaries.iter().filter(|end| **end <= cut).count();
            let expected = if cut <= HEADER {
                Loaded::Unterminated(Vec::new())
            } else if kept == 0 {
                Loaded::Unreadable { moved_to: None }
            } else if kept == records.len() {
                Loaded::Terminated(records.to_vec())
            } else if boundaries[kept - 1] == cut {
                Loaded::Unterminated(records[..kept].to_vec())
            } else {
                Loaded::Torn {
                    records: records[..kept].to_vec(),
                    discarded: cut - boundaries[kept - 1],
                }
            };
            assert_eq!(loaded, expected, "cut at {cut}");
        }
    }

    /// A journal header for a session under `home`.
    fn begin_under(home: &Path, scope: Vec<Portable>) -> Record {
        Record::Begin(Begin {
            kind: SessionKind::Apply,
            home: home.to_path_buf(),
            scope,
        })
    }

    /// `rel` under `home`, spelled absolutely: well-formed, so it decodes.
    fn absolute_under(home: &Path, rel: &str) -> Portable {
        Portable::from_path(&home.join(rel), Path::new("/nonexistent/other/home"))
            .expect("an absolute portable path")
    }

    #[test]
    fn a_journal_naming_an_absolute_path_under_its_home_never_drives_a_rollback() {
        // #4's decision R3-1, for the journal. Believed, this journal says bx
        // created `.gitconfig` and the file there is bx's: an unterminated
        // session, so recovery would unlink the user's file.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let dest = home.child(".gitconfig");
        plant_file(&dest, "[user]\n", Mode::DEFAULT_FILE);
        let path = state.journal();
        let foreign = absolute_under(home.path(), ".gitconfig");
        raw_journal(
            &path,
            &[
                begin_under(home.path(), Vec::new()),
                Record::Intent(Intent {
                    target: foreign,
                    dest: dest.clone(),
                    temp: None,
                    before: Prior::Absent,
                    after: Written::Present {
                        digest: ContentHash::of(b"[user]\n"),
                        mode: Mode::DEFAULT_FILE,
                    },
                    created_dirs: Vec::new(),
                    mechanism: Some(Mechanism::Own),
                    ledger_written: None,
                    dir: false,
                    link: false,
                }),
            ],
        );
        let bytes = std::fs::read(&path).expect("the journal");

        // Unlocked: unreadable, and left exactly where it is.
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
        assert_eq!(std::fs::read(&path).expect("still there"), bytes);
        assert!(
            crate::recover::pending(&state)
                .expect("pending")
                .expect("reported")
                .unreadable
        );

        // Under the lock: set aside with its bytes kept, and nothing rolled back.
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::Nothing,
        );
        assert_eq!(
            std::fs::read(StateDir::quarantine(&path)).expect("kept, not deleted"),
            bytes
        );
        assert!(!path.exists());
        assert_eq!(
            peek(&dest),
            Some((b"[user]\n".to_vec(), Mode::DEFAULT_FILE)),
            "the user's file is untouched",
        );
    }

    #[test]
    fn every_stored_path_in_a_journal_is_checked_against_its_home() {
        let home = guarded_home();
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let ours = target(home.path(), ".conf").0;
        let foreign = absolute_under(home.path(), ".conf");

        for (why, records) in [
            (
                "a scope entry",
                vec![begin_under(home.path(), vec![foreign.clone()])],
            ),
            (
                "a Done target",
                vec![
                    begin_under(home.path(), Vec::new()),
                    Record::Done(Done {
                        target: foreign.clone(),
                    }),
                ],
            ),
            (
                "the header's own home",
                vec![begin_under(Path::new("relative/home"), vec![ours.clone()])],
            ),
        ] {
            raw_journal(&path, &records);
            assert_eq!(
                load(&path).expect("load"),
                Loaded::Unreadable { moved_to: None },
                "{why}",
            );
        }

        // A path genuinely outside the home, and the ~/ spelling, still load.
        let outside = Portable::try_from("/etc/bx-example.conf".to_string()).expect("absolute");
        let records = vec![
            begin_under(home.path(), vec![ours.clone(), outside.clone()]),
            Record::Done(Done { target: outside }),
            Record::Done(Done { target: ours }),
        ];
        raw_journal(&path, &records);
        assert_eq!(load(&path).expect("load"), Loaded::Unterminated(records));
    }

    #[test]
    fn a_journal_that_writes_one_target_twice_is_unreadable() {
        let home = guarded_home();
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let (target, dest) = target(home.path(), ".conf");
        let intent = Intent {
            target: target.clone(),
            dest,
            temp: None,
            before: Prior::Absent,
            after: Written::Absent,
            created_dirs: Vec::new(),
            mechanism: None,
            ledger_written: None,
            dir: false,
            link: false,
        };
        let once = vec![
            Record::Begin(Begin {
                kind: SessionKind::Apply,
                home: home.path().to_path_buf(),
                scope: Vec::new(),
            }),
            Record::Intent(intent.clone()),
            Record::Done(Done {
                target: target.clone(),
            }),
        ];
        raw_journal(&path, &once);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unterminated(once.clone())
        );

        let mut twice = once;
        twice.push(Record::Intent(intent));
        raw_journal(&path, &twice);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_journal_with_a_second_session_header_is_unreadable() {
        // r3 coverage C5.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let begin = Record::Begin(some_begin());
        raw_journal(&path, &[begin.clone(), begin]);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn an_unreadable_journal_is_never_set_aside_over_an_earlier_one() {
        // Review round 3, item 5. The set-aside name was fixed, and opening a
        // session renamed the unreadable journal over the earlier one. Round 3
        // refused the session instead; since #7's numbered names integrated,
        // the journal takes the next free name and the session opens.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let aside = StateDir::quarantine(&state.journal());
        std::fs::write(&aside, b"the first").expect("a journal set aside earlier");
        std::fs::write(state.journal(), b"GARBAGE!").expect("an unreadable journal");

        let session = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect("the unreadable journal is set aside and the session opens");
        assert_eq!(std::fs::read(&aside).expect("kept"), b"the first");
        assert_eq!(
            std::fs::read(StateDir::quarantine_nth(&state.journal(), 1)).expect("set aside"),
            b"GARBAGE!",
        );
        drop(session);
    }

    #[test]
    fn a_journal_that_ends_with_an_end_record_is_terminated() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let begin = Record::Begin(some_begin());
        drop(Journal::create(&path, some_begin()).expect("create"));
        assert!(matches!(
            load(&path).expect("load"),
            Loaded::Unterminated(_)
        ));

        seal(&path, 0);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Terminated(vec![begin, Record::End(End { written: 0 })]),
        );
    }

    #[test]
    fn a_zero_byte_journal_is_an_empty_interrupted_session_and_stays_in_place() {
        // What a crash between creating the file and writing its header used to
        // leave. It records no write, so it is an empty interrupted session -
        // never corruption - even for the lock holder, the only reader that
        // could move it.
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().to_path_buf());
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let path = state.journal();
        std::fs::write(&path, b"").expect("write");

        assert_eq!(
            load_exclusive(&path, &lock).expect("load"),
            Loaded::Unterminated(Vec::new()),
        );
        assert!(path.is_file(), "left exactly where it was");
        assert!(
            !StateDir::quarantine(&path).exists(),
            "and nothing was set aside",
        );
    }

    #[test]
    fn a_torn_header_is_an_empty_session_and_a_torn_first_frame_is_set_aside() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let state = StateDir::new(dir.path().join("state"));
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        let whole = dir.path().join("whole.mpk");
        drop(Journal::create(&whole, some_begin()).expect("create"));
        let bytes = std::fs::read(&whole).expect("read");

        // Every cut short of the first whole frame. Inside the header it is a
        // session that wrote nothing. Past the header it is damage: the header
        // and the first frame are renamed into place together, so no crash
        // leaves the one without the other whole.
        for cut in 0..bytes.len() {
            let path = state.root().join(format!("torn-{cut}.mpk"));
            std::fs::write(&path, &bytes[..cut]).expect("write");
            let aside = StateDir::quarantine(&path);
            let loaded = load_exclusive(&path, &lock).expect("load");
            if cut <= HEADER {
                assert_eq!(loaded, Loaded::Unterminated(Vec::new()), "a cut at {cut}");
                assert!(path.is_file(), "a cut at {cut} stays in place");
                assert!(!aside.exists());
            } else {
                assert_eq!(
                    loaded,
                    Loaded::Unreadable {
                        moved_to: Some(aside.clone())
                    },
                    "a cut at {cut}",
                );
                assert!(!path.exists(), "a cut at {cut} is set aside");
                assert_eq!(std::fs::read(&aside).expect("kept"), &bytes[..cut]);
            }
        }
    }

    #[test]
    fn a_journal_that_cannot_be_moved_aside_is_an_error_and_stays_in_place() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let lock = ExclusiveLock::acquire(&state).expect("lock");
        std::fs::write(state.journal(), b"GARBAGE!").expect("write");

        // No root here, so a directory without write permission refuses the
        // rename. Narrower than 0700 rather than wider, so nothing tightens it.
        fs::set_mode(state.root(), Mode::from_bits(0o500)).expect("make it read-only");
        if !permissions_refuse(state.root()) {
            fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");
            return cannot_build(
                "a_journal_that_cannot_be_moved_aside_is_an_error_and_stays_in_place",
                WRITES_THROUGH_PERMISSIONS,
            );
        }
        let loaded = load_exclusive(&state.journal(), &lock);
        fs::set_mode(state.root(), Mode::PRIVATE_DIR).expect("make it writable again");

        let err = loaded.expect_err("a journal that cannot be moved aside is refused");
        assert!(
            matches!(&err, Error::CannotSetAside { path, .. } if *path == state.journal()),
            "got {err}"
        );
        assert_eq!(
            std::fs::read(state.journal()).expect("still in place"),
            b"GARBAGE!",
        );
        assert!(!StateDir::quarantine(&state.journal()).exists());
    }

    #[test]
    fn an_unreadable_journal_that_cannot_be_set_aside_is_refused_and_never_replaced() {
        // r3, routed from #7's repair planning. `load_exclusive` reported a
        // journal it could not move aside as `Unreadable { moved_to: None }`,
        // which is not an interruption, so `Session::open` created its own
        // journal over it by rename and the bytes were gone.
        let home = guarded_home();
        // Every set-aside name is longer than the kernel accepts, so the move
        // fails with no permission bit involved, and a session could write.
        // (A crafted `journal.mpk.corrupt.<u64::MAX>` no longer blocks it:
        // `move_aside` takes the lowest free name past that number.)
        let state = state_beyond_set_aside_names(&home);
        state.ensure().expect("ensure");
        std::fs::write(state.journal(), b"GARBAGE!").expect("an unreadable journal");

        let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new());
        assert_eq!(
            std::fs::read(state.journal()).expect("kept"),
            b"GARBAGE!",
            "the unreadable journal's bytes are still at its path"
        );
        assert!(
            matches!(
                &opened,
                Err(Error::CannotSetAside { source, .. })
                    if source.raw_os_error()
                        == Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
            ),
            "got {opened:?}"
        );

        let recovered = crate::recover::recover(&state);
        assert!(
            matches!(
                recovered,
                Err(crate::recover::Error::Journal(Error::CannotSetAside { .. }))
            ),
            "got {recovered:?}"
        );
        assert_eq!(std::fs::read(state.journal()).expect("kept"), b"GARBAGE!");
        assert!(
            crate::recover::pending(&state)
                .expect("pending")
                .expect("still reported")
                .unreadable
        );
        assert_eq!(
            names_in(state.root()),
            ["journal.mpk", "lock", "restore", "shell"],
            "nothing was set aside and no session wrote"
        );
    }

    #[test]
    fn a_whole_record_after_the_end_of_a_session_is_unreadable_and_nothing_rolls_back() {
        // Coverage review round 5, item 2. Believed, the trailing Intent made
        // this an unterminated session, and both files would be unlinked.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        state.ensure().expect("ensure");
        let (first, first_dest) = target(home.path(), ".first");
        let (second, second_dest) = target(home.path(), ".second");
        plant_file(&first_dest, "first\n", Mode::DEFAULT_FILE);
        plant_file(&second_dest, "second\n", Mode::DEFAULT_FILE);
        raw_journal(
            &state.journal(),
            &[
                begin_under(home.path(), Vec::new()),
                created(&first, &first_dest, b"first\n"),
                Record::Done(Done {
                    target: first.clone(),
                }),
                Record::End(End { written: 1 }),
                created(&second, &second_dest, b"second\n"),
            ],
        );

        assert_eq!(
            load(&state.journal()).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
        assert_eq!(
            crate::recover::recover(&state).expect("recover"),
            crate::recover::Outcome::Nothing
        );
        assert_eq!(peek(&first_dest).expect("kept").0, b"first\n");
        assert_eq!(peek(&second_dest).expect("kept").0, b"second\n");
        assert!(StateDir::quarantine(&state.journal()).is_file());
    }

    #[test]
    fn bytes_after_the_end_of_a_session_are_unreadable_not_terminated() {
        // Coverage review round 5, item 3.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut journal = Journal::create(&path, some_begin()).expect("create");
        journal
            .append(&Record::End(End { written: 0 }))
            .expect("append");
        drop(journal);
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Terminated(vec![
                Record::Begin(some_begin()),
                Record::End(End { written: 0 })
            ]),
        );

        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend_from_slice(&[0xab; 32]);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }

    #[test]
    fn a_journal_path_that_cannot_be_looked_at_is_an_error_not_an_absent_journal() {
        // r3 round 2, restricted mutants on P42R1-D5. The look before the read
        // treats only NotFound as "no journal": any other failure — here
        // ENOTDIR, a state directory that is a file, which no permission
        // setting can bypass — is an error, as the read's was before it.
        let dir = tempfile::tempdir().expect("a tempdir");
        let file = dir.path().join("not-a-directory");
        plant_file(
            &file,
            "a file where the state directory should be\n",
            Mode::DEFAULT_FILE,
        );
        let path = file.join("journal.mpk");

        let err = load(&path).expect_err("a path that cannot be looked at is not absent");
        assert!(
            matches!(&err, Error::Io { path: at, .. } if *at == path),
            "got {err}"
        );
    }

    #[test]
    fn a_journal_that_cannot_be_read_is_an_error_and_a_session_does_not_replace_it() {
        // Coverage review round 5, item 4. Read as absent, it would be replaced
        // by the next session's journal without ever being examined.
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
        let path = state.journal();
        let bytes = std::fs::read(&path).expect("read");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::fs::read(&path).is_ok() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod back");
            return cannot_build(
                "a_journal_that_cannot_be_read_is_an_error_and_a_session_does_not_replace_it",
                WRITES_THROUGH_PERMISSIONS,
            );
        }

        let loaded = load(&path).expect_err("an unreadable journal is not an absent one");
        assert!(matches!(loaded, Error::Io { .. }), "got {loaded}");
        let opened = Session::open(&state, SessionKind::Apply, home.path(), Vec::new())
            .expect_err("a session refuses");
        assert!(matches!(opened, Error::Io { .. }), "got {opened}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod back");
        assert_eq!(
            std::fs::read(&path).expect("read"),
            bytes,
            "and it was not replaced"
        );
    }

    /// The home a journal-read child finds its state directory under.
    const READ_CHILD_HOME: &str = "BX_JOURNAL_READ_HOME";

    /// Which read a journal-read child makes: `load`, `open` or `recover`.
    const READ_CHILD_CALL: &str = "BX_JOURNAL_READ_CALL";

    /// The reading half of
    /// [`a_journal_that_is_not_a_regular_file_is_refused_without_being_read`].
    ///
    /// Run in a child so a read that never returns can be killed, and with its
    /// address space capped, so a read of `/dev/zero` aborts on its first
    /// gigabyte instead of taking the host's memory with it.
    #[test]
    #[ignore = "spawned by a_journal_that_is_not_a_regular_file_is_refused_without_being_read"]
    fn journal_read_child() {
        let (Some(home), Ok(call)) = (
            std::env::var_os(READ_CHILD_HOME),
            std::env::var(READ_CHILD_CALL),
        ) else {
            return;
        };
        rustix::process::setrlimit(
            rustix::process::Resource::As,
            rustix::process::Rlimit {
                current: Some(1 << 30),
                maximum: None,
            },
        )
        .expect("cap the address space");
        let home = PathBuf::from(home);
        let state = StateDir::resolve(&home);
        let path = state.journal();
        let named = |e: &Error| matches!(e, Error::NotAJournal { path: at, .. } if *at == path);
        let refusal = match call.as_str() {
            "load" => load(&path)
                .map(|_| ())
                .map_err(|e| (named(&e), e.to_string())),
            "open" => Session::open(&state, SessionKind::Apply, &home, Vec::new())
                .map(|_| ())
                .map_err(|e| (named(&e), e.to_string())),
            "recover" => crate::recover::recover(&state).map(|_| ()).map_err(|e| {
                let refused = matches!(&e, crate::recover::Error::Journal(inner) if named(inner));
                (refused, e.to_string())
            }),
            other => panic!("no such read: {other}"),
        };
        println!("{call}: {refusal:?}");
        let (refused, message) =
            refusal.expect_err("a journal that is not a regular file is refused");
        assert!(refused, "refused as NotAJournal: {message}");
        assert!(
            message.contains(&path.display().to_string()),
            "the refusal names the journal: {message}"
        );
        assert!(message.contains("only from a regular file"), "{message}");
    }

    #[test]
    fn a_journal_that_is_not_a_regular_file_is_refused_without_being_read() {
        // P42R1-D5 (journal part). The journal was read whole with a blocking
        // read and no look at its type, so a FIFO at `journal.mpk` blocked
        // load, Session::open and recovery forever, and a link to /dev/zero
        // read without end.
        fn fifo(path: &Path) {
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                path,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .expect("mkfifo");
        }
        fn device_link(path: &Path) {
            std::os::unix::fs::symlink("/dev/zero", path).expect("link to /dev/zero");
        }
        fn dangling_link(path: &Path) {
            std::os::unix::fs::symlink(path.with_file_name("nowhere"), path)
                .expect("a link to nothing");
        }

        let guard = guarded_home();
        // Every case is run before any is judged, so one read that hangs
        // does not hide what the others do.
        let mut failures = Vec::new();
        for (name, plant, kind) in [
            ("fifo", fifo as fn(&Path), fs::Kind::Other),
            ("device-link", device_link as fn(&Path), fs::Kind::Symlink),
            (
                "dangling-link",
                dangling_link as fn(&Path),
                fs::Kind::Symlink,
            ),
        ] {
            for call in ["load", "open", "recover"] {
                let case = format!("{name} read by {call}");
                let home = guard.child(format!("{name}-{call}"));
                let state = StateDir::resolve(&home);
                state.ensure().expect("the state directory");
                plant(&state.journal());

                let mut child =
                    std::process::Command::new(std::env::current_exe().expect("the test binary"))
                        .args([
                            "--exact",
                            "--ignored",
                            "--nocapture",
                            "journal::load::tests::journal_read_child",
                        ])
                        .env(READ_CHILD_HOME, &home)
                        .env(READ_CHILD_CALL, call)
                        // Inherited, unlike the crash harness's: this child
                        // exits normally and writes a profile, which belongs
                        // where coverage put the parent's, not in the working
                        // directory under a default name.
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .expect("spawn the reading child");
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                let finished = loop {
                    if child.try_wait().expect("wait").is_some() {
                        break true;
                    }
                    if std::time::Instant::now() > deadline {
                        child.kill().expect("kill the reading child");
                        break false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                };
                let out = child.wait_with_output().expect("the child's output");
                let said = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if !finished {
                    failures.push(format!("{case}: still reading after 60 s: {said}"));
                    continue;
                }
                if !out.status.success() {
                    failures.push(format!("{case}: {} {said}", out.status));
                    continue;
                }

                let meta = std::fs::symlink_metadata(state.journal()).expect("left in place");
                assert_eq!(
                    fs::Kind::from(meta.file_type()),
                    kind,
                    "{case}: never replaced"
                );
                assert!(
                    std::fs::symlink_metadata(StateDir::quarantine(&state.journal())).is_err(),
                    "{case}: never set aside"
                );

                // The way out: `abandon` moves it aside without opening it,
                // and bx writes again.
                let aside = crate::recover::abandon(&state)
                    .expect("abandon")
                    .expect("something stood at the journal's path");
                assert_eq!(
                    fs::Kind::from(std::fs::symlink_metadata(&aside).expect("kept").file_type()),
                    kind,
                    "{case}: moved, not replaced"
                );
                assert_eq!(
                    crate::recover::recover(&state).expect("bx writes again"),
                    crate::recover::Outcome::Nothing,
                    "{case}"
                );
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_journal_whose_directory_intent_names_a_temporary_file_is_unreadable() {
        let home = guarded_home();
        let (target, dest) = target(home.path(), ".d");
        let intent = Intent {
            target: target.clone(),
            dest: dest.clone(),
            temp: Some(home.child(format!("{}x", fs::TEMP_PREFIX))),
            before: Prior::Absent,
            after: Written::Present {
                digest: dir_digest(),
                mode: Mode::PRIVATE_DIR,
            },
            created_dirs: Vec::new(),
            mechanism: Some(Mechanism::Dir),
            ledger_written: None,
            dir: true,
            link: false,
        };
        assert_eq!(
            misplaced(&intent, home.path()),
            Some("a directory intent names a temporary file")
        );
        assert_eq!(
            misplaced(
                &Intent {
                    temp: None,
                    ..intent.clone()
                },
                home.path()
            ),
            None
        );
        assert_eq!(
            misplaced(
                &Intent {
                    temp: None,
                    link: true,
                    ..intent
                },
                home.path()
            ),
            Some("an intent names its destination both a directory and a link")
        );
    }
}
