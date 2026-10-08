//! The restore-blob store: the bytes a write displaced, under `restore/`.
//!
//! Every snapshot bx keeps is a file named by the digest of its bytes, written
//! here and read back here, whether the ledger or the journal asked for it. A
//! decoy the ledger refuses to trust is therefore not trusted by the journal
//! either, and a blob one of them stored is the blob the other finds.

use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode as RawMode, OFlags};

use super::Error;
use super::dir::StateDir;
use super::hash::ContentHash;
use super::ledger::{Prior, PriorBytes, RestoreRef};
use crate::fs::{Mode, write_atomically};

/// Store `prior` under its digest in `restore/`, durably, and say what a
/// record names it by: [`Prior::Absent`] when there was no file, which stores
/// nothing.
///
/// `restore/` must already exist.
///
/// # Errors
///
/// What [`store_bytes`] returns.
pub(crate) fn store(dir: &StateDir, prior: PriorBytes) -> Result<Prior, crate::fs::Error> {
    let PriorBytes::Bytes { bytes, mode } = prior else {
        return Ok(Prior::Absent);
    };
    store_bytes(dir, ContentHash::of(&bytes), &bytes, mode).map(Prior::Existed)
}

/// Write `bytes`, already hashed to `digest`, to `restore/<digest>`, durably,
/// unless the bytes are already there, and return the reference.
///
/// `restore/` must already exist.
///
/// The skip is guarded by the blob's *length*, not merely by its existence.
/// A name proves content only while nothing has damaged the file, and this
/// design already accepts that a blob can stop matching its name — that is
/// what [`Error::RestoreCorrupt`] is for. Checking when the bytes are in
/// hand costs one `stat` and repairs the blob; checking only in [`read`]
/// discovers the loss when the target has already been overwritten and the
/// original bytes exist nowhere.
///
/// A `stat` rather than a re-hash: it keeps the common repeat path O(1),
/// and the two ways a blob is plausibly lost — a truncated write and an
/// empty file left by an interrupted one — both change the length.
///
/// The `stat` is of the name itself, never of what it links to: see
/// [`blob_len`]. A symlink or a second hard link of the right length is not
/// a blob bx wrote, so it is never trusted. A second hard link is rewritten.
/// A symlink is refused: [`write_atomically`] never replaces a link, so
/// this returns [`crate::fs::Error::Symlink`] and leaves the link and what it
/// names alone.
///
/// # Errors
///
/// What [`write_atomically`] returns. The blob and `restore/` itself are
/// `fsync`ed before this returns `Ok`.
pub(crate) fn store_bytes(
    dir: &StateDir,
    digest: ContentHash,
    bytes: &[u8],
    mode: Mode,
) -> Result<RestoreRef, crate::fs::Error> {
    // `usize` is never wider than 64 bits on any target Rust supports, so
    // the saturation is unreachable and the length is exact. Saturating
    // rather than panicking keeps a blob's length wrong instead of killing
    // `bx rm`, if that ever stops being true.
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let path = blob_path(dir, &digest);
    if blob_len(&path) != Some(len) {
        // `write_atomically` fsyncs the blob and then `restore/` itself, which
        // is what makes the snapshot durable before this function returns.
        write_atomically(&path, bytes, Mode::PRIVATE_FILE)?;
    }
    Ok(RestoreRef { digest, mode, len })
}

/// The bytes a restore snapshot holds.
///
/// The digest is recomputed and checked. Silently restoring corrupted
/// content over a file the user wrote would be worse than refusing, so this
/// refuses.
///
/// # The read side asks a different question from the write side
///
/// Availability, not ownership. Reading with plain `std::fs::read` accepted
/// entries that can never return: a FIFO blocks `bx rm` forever with no
/// diagnostic, and a symlink to an unbounded source such as `/dev/zero`
/// allocates until the process is killed. So the open is `O_NOFOLLOW |
/// O_NONBLOCK`, the descriptor must be a regular file, and the read is
/// bounded by `reference.len`.
///
/// The write side's `st_nlink == 1` test is **not** repeated here (r4
/// round 2, CL6). A second hard link changes nothing about availability,
/// and content integrity is settled by the digest recomputed below — bytes
/// that hash to `reference.digest` are the user's prior bytes whoever else
/// has a name for them. Refusing them would make an ordinary hard-linking
/// deduplicator or backup tool run over `$HOME` turn an intact, verifiable
/// snapshot into [`Error::RestoreMissing`], and the user's own prior bytes
/// would not be restored though they are sitting there. On the write side
/// the test still earns its place: there `nlink` decides whether bx may
/// *skip* a write, and a shared inode is not a file bx can be sure it wrote.
///
/// # Errors
///
/// [`Error::RestoreMissing`] if the blob is gone,
/// [`Error::RestoreNotAFile`] if what is at the name is not a regular file,
/// [`Error::RestoreCorrupt`] if it is not `reference.len` bytes long or its
/// bytes do not hash to `reference.digest`, and [`Error::Read`] for any
/// other read failure.
pub fn read(dir: &StateDir, reference: &RestoreRef) -> Result<Vec<u8>, Error> {
    let path = blob_path(dir, &reference.digest);
    let missing = || Error::RestoreMissing {
        digest: reference.digest,
        path: path.clone(),
    };
    let not_a_file = || Error::RestoreNotAFile {
        digest: reference.digest,
        path: path.clone(),
    };
    // `O_NONBLOCK` as well as `O_NOFOLLOW`: `O_NOFOLLOW` refuses a symlink,
    // but a FIFO is opened by name and `open` itself blocks on one until a
    // writer appears, before there is any descriptor to `fstat`. The flags
    // are joined with `union` rather than `|`: they share no bit, so a `^` in
    // place of a `|` is the same program, and a mutant no test can kill.
    let fd = match rustix::fs::open(
        &path,
        OFlags::RDONLY
            .union(OFlags::NOFOLLOW)
            .union(OFlags::NONBLOCK)
            .union(OFlags::CLOEXEC),
        RawMode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Err(missing()),
        // `ELOOP`: a symlink, refused by `O_NOFOLLOW`.
        Err(rustix::io::Errno::LOOP) => return Err(not_a_file()),
        Err(source) => {
            return Err(Error::Read {
                path,
                source: source.into(),
            });
        }
    };
    let stat = rustix::fs::fstat(&fd).map_err(|source| Error::Read {
        path: path.clone(),
        source: source.into(),
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(not_a_file());
    }
    // The recorded length bounds the read. `reference.len` is written by
    // `store_bytes` and, until now, read by nothing: a regular,
    // single-linked file of any size at `restore/<digest>` — left by an
    // interrupted write, or put there by anything with access to
    // `restore/` — was allocated whole before the digest below could
    // reject it, which is the "allocate until the process is killed"
    // failure this function's own preamble claims to close (r4 round 2,
    // D3 and COV7). Different length means different bytes, so this is the
    // refusal the digest would make, made before the allocation.
    if !u64::try_from(stat.st_size).is_ok_and(|size| size == reference.len) {
        return Err(Error::RestoreCorrupt {
            digest: reference.digest,
            path,
        });
    }
    // The `st_size` test above is a statement about the file when it was
    // `fstat`ed, not when it is read: a blob with a second hard link can
    // grow in between, and `read_to_end` would follow it (r5, D2). So the
    // read itself stops at `reference.len`. Whatever the first
    // `reference.len` bytes are, the digest below judges them.
    let mut bytes = Vec::new();
    if let Err(source) = std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::from(fd), reference.len),
        &mut bytes,
    ) {
        return Err(Error::Read { path, source });
    }
    if ContentHash::of(&bytes) == reference.digest {
        Ok(bytes)
    } else {
        Err(Error::RestoreCorrupt {
            digest: reference.digest,
            path,
        })
    }
}

/// The length of the blob at `path`, or `None` unless it is bx's own file.
///
/// `None` means *rewrite it*: a blob that cannot be stat'ed is not a blob whose
/// content has been established.
///
/// The name is opened `O_PATH | O_NOFOLLOW` and the descriptor is checked, so
/// what is measured is the entry in `restore/` and never what a symlink there
/// names: a decoy link to a same-length file elsewhere used to satisfy the
/// check with none of the user's bytes behind it. It must be a regular file
/// with exactly one link. `O_PATH` reads nothing and cannot block on a FIFO.
/// The rewrite goes through [`write_atomically`]: its rename replaces a second
/// hard link, and it refuses a symlink outright, so a link is never written
/// through.
fn blob_len(path: &Path) -> Option<u64> {
    // `union`, not `|`, for the reason `read` gives.
    let fd = rustix::fs::open(
        path,
        OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC),
        RawMode::empty(),
    )
    .ok()?;
    let stat = rustix::fs::fstat(&fd).ok()?;
    let own = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_nlink == 1;
    own.then(|| u64::try_from(stat.st_size).ok()).flatten()
}

/// Where a snapshot with this digest lives.
fn blob_path(dir: &StateDir, digest: &ContentHash) -> PathBuf {
    dir.restore().join(digest.to_hex())
}
