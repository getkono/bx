//! The journal file: created whole through an atomic write, then appended to
//! and synced in place, one `write` per frame.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::format::{FORMAT, HEADER, MAGIC, NONCE, encode, fresh_nonce};
use super::{Begin, Error, Record};
use crate::fs::{self, Mode};

/// The append-only log itself.
///
/// [`Session`](super::Session) is the supported way to write one; this is public so recovery can
/// be exercised against journals a crash could produce but a correct session
/// never writes.
#[derive(Debug)]
pub struct Journal {
    pub(super) file: File,
    pub(super) path: PathBuf,
    /// The nonce in this journal's header, which every frame's checksum covers.
    pub(super) nonce: [u8; NONCE],
}

impl Journal {
    /// Create the journal whole — header and [`Begin`] frame — through
    /// [`crate::fs::write_atomically`], then open it for appending.
    ///
    /// Whatever was at `path` is replaced by `rename`, never truncated in place,
    /// so an unlocked reader sees either the file that was there or the new
    /// journal with its `Begin`, and never an empty or half-written one. The
    /// temporary file is `fsync`ed before the rename and the directory after it,
    /// and the journal is at `0600` from its first instant.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`] or [`Error::FrameTooLarge`] for a `Begin` that cannot be
    /// framed, [`Error::Write`] when the file cannot be written, and
    /// [`Error::Io`] when it cannot be reopened for appending.
    pub fn create(path: &Path, begin: Begin) -> Result<Self, Error> {
        let nonce = fresh_nonce();
        let mut bytes = Vec::with_capacity(HEADER);
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&encode(&Record::Begin(begin), &nonce)?);
        fs::write_atomically(path, &bytes, Mode::PRIVATE_FILE)?;

        let file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|source| Error::Io {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            nonce,
        })
    }

    /// The journal's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and `fsync` it.
    ///
    /// Returns once the frame is durable, which is the guarantee the ordering in
    /// [`Session::apply`](super::Session::apply) rests on.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`] for a record that cannot be encoded,
    /// [`Error::FrameTooLarge`] for one that is absurdly big, and [`Error::Io`]
    /// wrapping the failing `write` or `fsync`.
    pub fn append(&mut self, record: &Record) -> Result<(), Error> {
        // One buffer and one `write_all`, so a frame torn by a crash can only
        // ever be the last bytes of the file.
        let frame = encode(record, &self.nonce)?;
        self.emit(&frame)
    }

    /// Write bytes at the end of the journal and `fsync` the file.
    ///
    /// The `fsync` goes through [`crate::fs::durable::sync_file`], so a test can
    /// see that it happens, and where it falls against the rename or unlink the
    /// frame announces.
    fn emit(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let fail = |source| Error::Io {
            path: self.path.clone(),
            source,
        };
        self.file.write_all(bytes).map_err(fail)?;
        crate::fs::durable::sync_file(&self.file, &self.path).map_err(fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::journal::tests::{peek, plant_file, some_begin};
    use crate::journal::{Done, Loaded, load};
    use crate::paths::Portable;

    #[test]
    fn the_journal_is_created_whole_at_0600_and_replaces_whatever_was_there() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        plant_file(&path, "not a journal at all", Mode::DEFAULT_FILE);

        let journal = Journal::create(&path, some_begin()).expect("create");
        assert_eq!(journal.path(), path);
        let (bytes, mode) = peek(&path).expect("the journal");
        assert_eq!(mode, Mode::PRIVATE_FILE);
        assert!(bytes.starts_with(MAGIC), "the previous bytes are gone");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unterminated(vec![Record::Begin(some_begin())]),
            "and it exists whole, header and Begin, from its first instant",
        );
    }

    #[test]
    fn creating_a_journal_replaces_its_name_and_never_truncates_a_file_in_place() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        plant_file(&path, "the previous file\n", Mode::PRIVATE_FILE);

        // A reader that opened the previous file before the create - `bx plan`
        // running unlocked beside an `apply` - goes on reading whole bytes. An
        // in-place truncate would hand it an emptied file instead.
        let mut earlier = File::open(&path).expect("open the previous file");
        let journal = Journal::create(&path, some_begin()).expect("create");
        let mut seen = String::new();
        std::io::Read::read_to_string(&mut earlier, &mut seen).expect("read");
        assert_eq!(seen, "the previous file\n");
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unterminated(vec![Record::Begin(some_begin())]),
            "and the name holds the whole new journal, Begin and all",
        );
        drop(journal);
    }

    #[test]
    fn a_frame_appended_after_a_torn_one_is_hidden_from_recovery() {
        // Why a failed append has to end the session: a frame torn mid-write
        // stops the loader, so anything appended after it is invisible to
        // recovery - including the Intent for a write that then lands.
        let dir = tempfile::tempdir().expect("a tempdir");
        let path = dir.path().join("journal.mpk");
        let mut journal = Journal::create(&path, some_begin()).expect("create");
        let after_begin = std::fs::read(&path).expect("read").len();
        journal
            .append(&Record::Done(Done {
                target: Portable::try_from("~/.torn".to_string()).expect("portable"),
            }))
            .expect("append");
        let after_torn = std::fs::read(&path).expect("read").len();
        journal
            .append(&Record::Done(Done {
                target: Portable::try_from("~/.hidden".to_string()).expect("portable"),
            }))
            .expect("append");
        drop(journal);

        let whole = std::fs::read(&path).expect("read");
        let mut torn = whole[..after_begin + (after_torn - after_begin) / 2].to_vec();
        torn.extend_from_slice(&whole[after_torn..]);
        std::fs::write(&path, &torn).expect("write");

        // With a checksum on every frame the loader also sees that what follows
        // the torn frame is not a frame: the later one stays invisible, and the
        // journal is unreadable rather than silently short.
        assert_eq!(
            load(&path).expect("load"),
            Loaded::Unreadable { moved_to: None }
        );
    }
}
