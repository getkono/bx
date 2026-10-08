//! Keeping a declared setuid or setgid bit: when the kernel would drop one,
//! how bx tells in advance, and refusing rather than publishing a mode that
//! did not stick.

use std::path::Path;

use super::observe::mode_of;
use super::{Error, set_mode};
use crate::fs::mode::Mode;

/// Refuse when a declared setuid, setgid or sticky bit is missing from the
/// directory `meta` describes, after a `chmod` to `mode` that reported success.
///
/// Apart from `dir::set_dir_mode` so that the refusal is constructible from a
/// metadata alone. Making the kernel actually drop a bit needs a directory in a
/// group the process is not in, which only a user namespace arranges; what
/// every caller depends on is this answer, and it does not need the kernel to
/// produce it.
///
/// # Errors
///
/// [`Error::DirectorySetIdNotKept`], naming what the `chmod` left.
pub(super) fn refuse_dir_set_id_dropped(
    path: &Path,
    mode: Mode,
    meta: &std::fs::Metadata,
) -> Result<(), Error> {
    let landed = mode_of(meta);
    let declared = mode.bits() & SPECIAL;
    if landed.bits() & declared == declared {
        return Ok(());
    }
    Err(Error::DirectorySetIdNotKept {
        path: path.to_path_buf(),
        declared: mode,
        landed,
        chmod_left: Some(landed),
        set_back: None,
    })
}

/// Refuse to `chmod` the existing directory at `path`, which `plan` found at
/// `found`, to `declared` unless the setgid bit is confirmed to survive it: the
/// directory has `S_ISGID` or `declared` adds it, and nothing confirms that a
/// `chmod` by this process keeps it — see [`keeps_setgid`].
///
/// A `chmod` by a process the kernel does not exempt clears `S_ISGID` whatever
/// mode it asks for, so a bit declared would not stick, and a bit the directory
/// had would be lost for good: setting it back is another `chmod` by the same
/// process. Refused before any `chmod`, nothing changes.
///
/// # Errors
///
/// [`Error::DirectorySetIdNotKept`] with no `chmod_left`, naming the mode
/// the directory has, and [`Error::Read`] when it cannot be stat'd.
pub(super) fn refuse_setgid_a_chmod_strips(
    path: &Path,
    found: Mode,
    declared: Mode,
) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt as _;

    if (found.bits() | declared.bits()) & SETGID == 0 {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let keeps = process_keeps_setgid(meta.uid(), meta.gid());
    refuse_unless_setgid_survives(path, declared, &meta, keeps)
}

/// The refusal itself: pass when `keeps` names a confirmation, refuse when it
/// is `None`.
///
/// The confirmation is an argument rather than something this function reads,
/// so that both answers are constructible on any host. The `None` answer is the
/// one that matters and the one a real filesystem cannot produce here: it needs
/// a directory in a group the process is not in, which only a user namespace
/// arranges.
///
/// # Errors
///
/// [`Error::DirectorySetIdNotKept`] with no `chmod_left`: nothing was changed.
fn refuse_unless_setgid_survives(
    path: &Path,
    declared: Mode,
    meta: &std::fs::Metadata,
    keeps: Option<KeepsSetgid>,
) -> Result<(), Error> {
    if keeps.is_some() {
        return Ok(());
    }
    Err(Error::DirectorySetIdNotKept {
        path: path.to_path_buf(),
        declared,
        landed: mode_of(meta),
        chmod_left: None,
        set_back: None,
    })
}

/// Why a `chmod` by this process is known to keep a directory's setgid bit.
///
/// There is no variant for "probably" and none for a uid. The preflight passes
/// only on a confirmation named here, so a setup nobody anticipated is refused
/// rather than waved through: refusing costs a plan line, and guessing wrong
/// costs a setgid bit that no second `chmod` by the same process can put back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepsSetgid {
    /// This process holds `CAP_FSETID` in its effective set.
    Capability,
    /// The directory's group is this process's effective group or one of its
    /// supplementary groups, and it is a group the kernel resolved into this
    /// process's user namespace.
    Group,
}

/// Whether a `chmod` by this process keeps the setgid bit of a directory that
/// `stat`s as owner `uid` and group `gid` — [`keeps_setgid`] against this
/// process's own capabilities, effective gid, supplementary groups and this
/// namespace's overflow ids.
fn process_keeps_setgid(uid: u32, gid: u32) -> Option<KeepsSetgid> {
    // The test build can force either answer on this thread, because the
    // `None` one needs a user namespace most hosts do not offer.
    #[cfg(test)]
    if let Some(forced) = forced::confirmation() {
        return forced;
    }
    // A process whose groups cannot be read is taken to be in none of them:
    // the refusal that follows changes nothing, where a wrong guess the
    // other way would strip a bit.
    let groups: Vec<u32> = rustix::process::getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .collect();
    keeps_setgid(
        uid,
        gid,
        has_cap_fsetid(),
        rustix::process::getegid().as_raw(),
        &groups,
        overflow_ids(),
    )
}

/// Whether the kernel keeps a directory's setgid bit through a `chmod` by a
/// process holding `cap_fsetid`, with effective gid `egid` and supplementary
/// groups `groups`, when the directory `stat`s as owner `uid` and group `gid`
/// and this user namespace's overflow ids are `overflow`.
///
/// # The rule the kernel applies
///
/// `chmod_common` keeps `S_ISGID` when either holds:
///
/// ```text
/// in_group_p(i_gid) || capable_wrt_inode_uidgid(inode, CAP_FSETID)
/// ```
///
/// and `capable_wrt_inode_uidgid` is `ns_capable(CAP_FSETID)` **and**
/// `kuid_has_mapping(ns, i_uid)` **and** `kgid_has_mapping(ns, i_gid)`. So the
/// capability does **not** outrank an unmapped id: it is the *weaker* of the
/// two paths, because it carries two mapping requirements the group path does
/// not. An id the namespace does not map is what makes `stat` report the
/// overflow uid or gid, which is how this function sees it.
///
/// # Why the order is not a choice here
///
/// An earlier version tested the capability first and returned on it, so a
/// process holding `CAP_FSETID` was confirmed for a directory whose group was
/// unmapped — and the kernel stripped the bit anyway. That was a claim about a
/// shape ("fail closed") whose *sequence* was load-bearing and only written
/// down in prose.
///
/// It is now carried by the types instead. [`MappedGid`] has one constructor,
/// which refuses the overflow gid, and **every** confirmation below takes one:
/// [`in_group`] because `in_group_p` compares against that gid, and
/// [`inode_capability`] because `kgid_has_mapping` must hold for it. An arm
/// added later that skipped the mapping test would have nothing to take and
/// would not compile.
///
/// `None` means refuse. There is no variant for "probably" and none for a uid.
fn keeps_setgid(
    uid: u32,
    gid: u32,
    cap_fsetid: bool,
    egid: u32,
    groups: &[u32],
    overflow: Overflow,
) -> Option<KeepsSetgid> {
    // Nothing below this line can be reached without it, and that is the point:
    // both paths the kernel offers are judged against this gid.
    let gid = MappedGid::of(gid, overflow)?;
    if inode_capability(uid, gid, cap_fsetid, overflow).is_some() {
        return Some(KeepsSetgid::Capability);
    }
    in_group(gid, egid, groups).then_some(KeepsSetgid::Group)
}

/// The overflow ids of a user namespace: what `stat` reports for an owner or a
/// group it does not map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Overflow {
    uid: u32,
    gid: u32,
}

/// A directory's group, as a gid this user namespace actually maps.
///
/// The one constructor refuses the overflow gid, and every arm of
/// [`keeps_setgid`] takes one, so no arm can compare a gid the kernel would not
/// compare. `stat` reports the overflow gid precisely when the mapping the
/// kernel needs is absent, so this is that mapping, as far as a `stat` can see
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappedGid(u32);

impl MappedGid {
    /// The group, or `None` when this namespace does not map it.
    const fn of(gid: u32, overflow: Overflow) -> Option<Self> {
        if gid == overflow.gid {
            return None;
        }
        Some(Self(gid))
    }
}

/// Whether this process is in the group `gid` — the kernel's `in_group_p`.
///
/// Takes a [`MappedGid`]: an unmapped group reads as the overflow gid, and
/// matching *that* against this process's own gids answers a different question
/// from the one `chmod(2)` asks. Two distinct unmapped groups read alike.
const fn in_group(gid: MappedGid, egid: u32, groups: &[u32]) -> bool {
    if egid == gid.0 {
        return true;
    }
    let mut i = 0;
    while i < groups.len() {
        if groups[i] == gid.0 {
            return true;
        }
        i += 1;
    }
    false
}

/// Evidence that `CAP_FSETID` applies to *this* inode — the kernel's
/// `capable_wrt_inode_uidgid`.
///
/// Needs the capability in the effective set **and** both of the inode's ids
/// mapped. The gid is already a [`MappedGid`], so only the owner is checked
/// here; an unmapped owner reads as the overflow uid.
const fn inode_capability(
    uid: u32,
    _gid: MappedGid,
    cap_fsetid: bool,
    overflow: Overflow,
) -> Option<InodeCapability> {
    if cap_fsetid && uid != overflow.uid {
        return Some(InodeCapability);
    }
    None
}

/// `CAP_FSETID`, established against one inode. Constructible only by
/// [`inode_capability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InodeCapability;

/// `CAP_FSETID`, capability 4 in `linux/capability.h`.
const CAP_FSETID: u32 = 4;

/// Whether this process holds `CAP_FSETID` in its effective capability set.
///
/// Read from `/proc/self/status`, which is the whole interface: bx forbids
/// `unsafe`, so `capget(2)` is not reachable without a dependency that adds
/// one, and bx is Linux-only, so `/proc` is the native answer rather than a
/// portability compromise.
///
/// A set that cannot be read or parsed confirms nothing and is `false`. The
/// caller then refuses, which changes nothing; the other guess strips a bit.
/// The whole judgement is [`cap_fsetid_in`], which takes the text, so the only
/// part no test reaches is the `read_to_string` itself.
fn has_cap_fsetid() -> bool {
    cap_fsetid_in(std::fs::read_to_string("/proc/self/status").ok().as_deref())
}

/// Whether `CAP_FSETID` is set in the `CapEff` mask of `status`, the text of
/// `/proc/self/status`.
///
/// `None` — the file could not be read — and text with no usable `CapEff` line
/// both confirm nothing, and so are `false`.
fn cap_fsetid_in(status: Option<&str>) -> bool {
    status
        .and_then(cap_eff)
        .is_some_and(|effective| effective & (1 << CAP_FSETID) != 0)
}

/// The effective capability mask on a `/proc/<pid>/status` `CapEff:` line.
///
/// `None` when the line is absent or is not the hex mask the kernel writes.
fn cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// The ids `stat` reports for an owner or a group with no mapping in this
/// process's user namespace, from `/proc/sys/kernel/overflowuid` and
/// `overflowgid`.
///
/// The kernel's own compiled-in defaults when they cannot be read: assuming
/// anything else is what would let an unmapped id through the comparisons
/// [`keeps_setgid`] makes. The reads are one line each; the judgement is
/// [`overflow_in`], which takes the text.
fn overflow_ids() -> Overflow {
    let read = |name: &str| std::fs::read_to_string(name).ok();
    Overflow {
        uid: overflow_in(read("/proc/sys/kernel/overflowuid").as_deref()),
        gid: overflow_in(read("/proc/sys/kernel/overflowgid").as_deref()),
    }
}

/// The overflow id in `text`, or the kernel's `DEFAULT_OVERFLOWUID` /
/// `DEFAULT_OVERFLOWGID` — both `65534` — when there is none to read.
fn overflow_in(text: Option<&str>) -> u32 {
    /// The kernel's `DEFAULT_OVERFLOWUID` and `DEFAULT_OVERFLOWGID`.
    const DEFAULT: u32 = 65534;

    text.and_then(|t| t.trim().parse().ok()).unwrap_or(DEFAULT)
}

/// A forced answer for [`process_keeps_setgid`], per thread, in the test build
/// only.
///
/// The refusal a foreign group causes is the whole point of the preflight, and
/// a foreign group needs unprivileged user namespaces and subordinate ids to
/// arrange. Forcing the answer constructs the refusal on every path that asks
/// for it, on any host. `cfg(test)`, not a feature gate: no configuration of
/// the binary differs from another, and the product build has no branch here.
#[cfg(test)]
mod forced {
    use std::cell::Cell;

    use super::KeepsSetgid;

    thread_local! {
        static ANSWER: Cell<Option<Option<KeepsSetgid>>> = const { Cell::new(None) };
    }

    /// The answer forced on this thread, if any.
    pub(super) fn confirmation() -> Option<Option<KeepsSetgid>> {
        ANSWER.get()
    }

    /// Run `f` with every [`super::process_keeps_setgid`] call on this thread
    /// answering `answer`. Cleared on unwind too.
    pub(super) fn answering<R>(answer: Option<KeepsSetgid>, f: impl FnOnce() -> R) -> R {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                ANSWER.set(None);
            }
        }
        ANSWER.set(Some(answer));
        let _clear = Clear;
        f()
    }
}

/// Set a directory whose `Modify` was `refused` back to `prior`, the mode
/// `plan` saw, so a refused `Modify` leaves no change that nothing records —
/// and read it back, so a [`Error::DirectorySetIdNotKept`] names the mode on
/// the directory now and whether the set-back restored `prior`. Any other
/// refusal is returned as it is.
///
/// A failing set-back is logged at warn; the read-back still names what is
/// there. When the directory cannot be stat'd, what is there is unknown, and
/// the refusal becomes [`Error::Read`].
pub(super) fn set_back(path: &Path, prior: Mode, refused: Error) -> Error {
    if let Err(undo) = set_mode(path, prior) {
        tracing::warn!(
            path = %path.display(),
            %prior,
            error = %undo,
            "could not set a refused directory back to its prior mode"
        );
    }
    let Error::DirectorySetIdNotKept {
        path: named,
        declared,
        chmod_left,
        ..
    } = refused
    else {
        return refused;
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Error::DirectorySetIdNotKept {
            path: named,
            declared,
            landed: mode_of(&meta),
            chmod_left,
            set_back: Some(prior),
        },
        Err(source) => Error::Read {
            path: path.to_path_buf(),
            source,
        },
    }
}

/// The setuid and setgid bits.
///
/// The only mode bits a write can take away. The kernel clears S_ISUID, and
/// S_ISGID when group execute is set, on the first write to a file by a process
/// without `CAP_FSETID`, so a set-id mode applied before the content is gone
/// once the content lands. [`stage`](super::stage()) leaves them off the empty file and
/// [`Staged::fill`](super::Staged::fill) adds them after the content and before the `fsync`, which
/// keeps both promises: never wider than the declared mode while empty, and
/// exactly the declared mode by the time anything can see the content.
pub(super) const SET_ID: u32 = 0o6000;

/// The setgid bit: the one special bit the kernel strips from a directory on a
/// `chmod` by a process outside its group — see [`keeps_setgid`].
pub(super) const SETGID: u32 = 0o2000;

/// The setuid, setgid and sticky bits: the ones a filesystem may not store.
///
/// [`Staged::fill`](super::Staged::fill) reads them back after the content whenever a mode declares
/// any of them — see [`Error::SetIdNotKept`].
pub(super) const SPECIAL: u32 = 0o7000;

/// `mode` without its setuid and setgid bits — see [`SET_ID`].
pub(super) const fn without_set_id(mode: Mode) -> Mode {
    Mode::from_bits(mode.bits() & !SET_ID)
}

/// Refuse unless every setuid, setgid or sticky bit `mode` declares is on
/// `file`.
///
/// Called after the content, because the `fchmod` that adds a set-id bit does
/// not fail when it does not stick — see [`Error::SetIdNotKept`]. `dest` is the
/// destination the refusal names; the temporary file is what is inspected.
///
/// # Errors
///
/// [`Error::SetIdNotKept`] when a declared special bit is missing, and
/// [`Error::Read`] when `file` cannot be stat'd.
pub(super) fn verify_set_id_kept(
    file: &std::fs::File,
    mode: Mode,
    dest: &Path,
) -> Result<(), Error> {
    let meta = file.metadata().map_err(|source| Error::Read {
        path: dest.to_path_buf(),
        source,
    })?;
    let landed = mode_of(&meta);
    let declared = mode.bits() & SPECIAL;
    if landed.bits() & declared == declared {
        return Ok(());
    }
    Err(Error::SetIdNotKept {
        path: dest.to_path_buf(),
        declared: mode,
        landed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    use rustix::io::Errno;

    use crate::fs::atomic::test_support::{desired, mode_of_path, names_in, seed, stage_now};
    use crate::fs::atomic::{CreatedDirs, Drift, compare, compare_dir, ensure_dir, observe, stage};
    use crate::fs::mode::Kind;
    use crate::testing::guarded_home;

    #[test]
    fn a_declared_setuid_or_setgid_bit_survives_the_write_that_fills_the_file() {
        // The kernel clears S_ISUID, and S_ISGID alongside group execute, on the
        // first write to a file by a process without CAP_FSETID. A mode set
        // before the content therefore loses those bits the moment the content
        // lands: the second plan reads `Modify`, and the ledger records a mode
        // that is not on disk. Under root the bits survive either way, so this
        // cannot fail there — which is not a reason to skip it.
        for bits in [0o4755, 0o2755, 0o6755, 0o1755] {
            let home = guarded_home();
            let dest = home.child("tool");
            let mode = Mode::from_bits(bits);

            let staged = stage_now(&dest, mode).expect("stage");
            assert_eq!(
                mode_of_path(staged.temp_path()).bits() & !mode.bits(),
                0,
                "{mode}: the empty temporary file is never wider than the declared mode",
            );
            let filled = staged.fill(b"#!/bin/sh\nexit 0\n").expect("fill");
            assert_eq!(mode_of_path(filled.temp_path()), mode, "{mode}: after fill");
            assert_eq!(filled.mode(), mode);
            filled.publish().expect("publish");

            assert_eq!(mode_of_path(&dest), mode, "{mode}: on disk");
            let observed = observe(&dest).expect("observe");
            assert_eq!(
                compare(
                    &observed,
                    &desired(b"#!/bin/sh\nexit 0\n", mode),
                    home.path()
                )
                .drift,
                Drift::Unchanged,
                "{mode}: the second plan is empty",
            );
        }
    }

    #[test]
    fn a_set_id_bit_missing_after_its_fchmod_is_a_typed_error() {
        let home = guarded_home();
        let path = home.child("tool");
        seed(&path, b"x", Mode::from_bits(0o755));
        let file = std::fs::File::open(&path).expect("open");

        // A lost setuid bit names setuid, and does not blame group membership,
        // which only ever costs a file its setgid bit.
        let lost_setuid = verify_set_id_kept(&file, Mode::from_bits(0o4755), &path)
            .expect_err("0755 on disk is not a declared 4755")
            .to_string();
        assert!(
            lost_setuid.contains("the setuid bit did not stick"),
            "{lost_setuid}"
        );
        assert!(!lost_setuid.contains("setgid"), "{lost_setuid}");
        assert!(!lost_setuid.contains("group"), "{lost_setuid}");
        assert!(
            lost_setuid.contains("filesystem that stores no set-id or sticky bits"),
            "{lost_setuid}"
        );
        // Every bit that did not stick is named, and only those.
        let lost_both = verify_set_id_kept(&file, Mode::from_bits(0o7755), &path)
            .expect_err("0755 on disk is not a declared 7755")
            .to_string();
        assert!(
            lost_both.contains("the setuid, setgid and sticky bits did not stick"),
            "{lost_both}"
        );
        set_mode(&path, Mode::from_bits(0o1755)).expect("sticky sticks here");
        let lost_sticky = verify_set_id_kept(&file, Mode::from_bits(0o5755), &path)
            .expect_err("1755 on disk is not a declared 5755")
            .to_string();
        assert!(
            lost_sticky.contains("the setuid bit did not stick"),
            "{lost_sticky}"
        );
        assert!(
            verify_set_id_kept(&file, Mode::from_bits(0o1755), &path).is_ok(),
            "a sticky bit that stuck is no refusal",
        );
        seed(&path, b"x", Mode::from_bits(0o755));
        let lost_sticky = verify_set_id_kept(&file, Mode::from_bits(0o1755), &path)
            .expect_err("0755 on disk is not a declared 1755")
            .to_string();
        assert!(
            lost_sticky.contains("the sticky bit did not stick"),
            "{lost_sticky}"
        );

        let err = verify_set_id_kept(&file, Mode::from_bits(0o2755), &path)
            .expect_err("0755 on disk is not a declared 2755");
        let Error::SetIdNotKept {
            path: named,
            declared,
            landed,
        } = &err
        else {
            panic!("expected SetIdNotKept, got {err:?}");
        };
        assert_eq!(named, &path);
        assert_eq!(*declared, Mode::from_bits(0o2755));
        assert_eq!(*landed, Mode::from_bits(0o755));
        assert_eq!(err.path(), path);
        let message = err.to_string();
        assert!(
            message.contains("the setgid bit did not stick"),
            "{message}"
        );
        assert!(message.contains("whose group you are not in"), "{message}");
        assert!(
            message.contains("filesystem that stores no set-id or sticky bits"),
            "{message}"
        );
        assert!(message.contains("Nothing was replaced"), "{message}");

        // A bit that did stick is no refusal, and neither is a mode that
        // declares none.
        set_mode(&path, Mode::from_bits(0o2755)).expect("our own group keeps it");
        verify_set_id_kept(&file, Mode::from_bits(0o2755), &path).expect("kept");
        seed(&path, b"x", Mode::from_bits(0o755));
        verify_set_id_kept(&file, Mode::from_bits(0o755), &path).expect("none declared");
    }

    /// Set only in the unprivileged child
    /// `a_setgid_bit_the_kernel_drops_is_refused_rather_than_published` runs
    /// itself as, naming the setgid directory the child writes into.
    const SET_ID_CHILD_DIR: &str = "BX_TEST_SET_ID_CHILD_DIR";

    /// Printed by that child before anything else, so the parent can tell a
    /// child that ran and failed from one that could not be started.
    const SET_ID_CHILD_RAN: &str = "bx-set-id-child-ran";

    #[test]
    fn a_setgid_bit_the_kernel_drops_is_refused_rather_than_published() {
        const NAME: &str = "fs::atomic::setid::tests::a_setgid_bit_the_kernel_drops_is_refused_rather_than_published";

        if let Some(dir) = std::env::var_os(SET_ID_CHILD_DIR) {
            // The child: uid 1, no supplementary groups, no capabilities, in a
            // setgid directory owned by a group it is not in. The file it
            // creates inherits that group, and the fchmod adding S_ISGID
            // succeeds while the kernel clears the bit.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            let dest = dir.join("tool");
            let mode = Mode::from_bits(0o2755);
            let err = stage_now(&dest, mode)
                .expect("stage")
                .fill(b"#!/bin/sh\nexit 0\n")
                .expect_err("a setgid bit the kernel dropped is not a mode bx may publish");
            let Error::SetIdNotKept {
                path,
                declared,
                landed,
            } = &err
            else {
                panic!("expected SetIdNotKept, got {err:?}");
            };
            assert_eq!(path, &dest);
            assert_eq!(*declared, mode);
            assert_eq!(landed.bits() & 0o2000, 0, "the bit really was dropped");
            assert!(!dest.exists(), "nothing was published");
            assert_eq!(
                names_in(&dir),
                Vec::<OsString>::new(),
                "no temporary file is left"
            );
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, SET_ID_CHILD_DIR, |_| {});
    }

    /// Set only in the unprivileged child
    /// `a_setgid_bit_the_kernel_drops_from_a_directory_is_refused` runs itself
    /// as, naming the setgid directory the child creates directories in.
    const SET_ID_DIR_CHILD_DIR: &str = "BX_TEST_SET_ID_DIR_CHILD_DIR";

    #[test]
    fn a_setgid_bit_the_kernel_drops_from_a_directory_is_refused() {
        const NAME: &str =
            "fs::atomic::setid::tests::a_setgid_bit_the_kernel_drops_from_a_directory_is_refused";

        if let Some(dir) = std::env::var_os(SET_ID_DIR_CHILD_DIR) {
            // The child, as in the file test: uid 1, in a setgid directory
            // owned by a group it is not in. A directory it creates there
            // inherits that group, so the chmod adding S_ISGID succeeds while
            // the kernel clears the bit.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            let mode = Mode::from_bits(0o2775);

            // A directory target plan announces as a create.
            let team = dir.join("team");
            let planned = observe(&team).expect("observe");
            assert_eq!(compare_dir(&planned, mode).drift, Drift::Create);
            let err = ensure_dir(&team, mode, &planned, &mut CreatedDirs::new())
                .expect_err("create: a setgid bit the kernel dropped is not an applied mode");
            let landed = assert_directory_set_id_not_kept(&err, &team, mode);
            assert_eq!(
                mode_of_path(&team),
                landed,
                "the refusal names what is on disk"
            );
            let second = compare_dir(&observe(&team).expect("observe"), mode);
            assert_eq!(
                (second.drift, second.mode_drift),
                (Drift::Modify, Some((landed, mode))),
                "the second plan shows the bit that is still missing",
            );

            // A directory target plan announces as a modify: refused before
            // any chmod, because the kernel would drop the bit it adds.
            let team2 = dir.join("team2");
            std::fs::create_dir(&team2).expect("mkdir");
            set_mode(&team2, Mode::PRIVATE_DIR).expect("chmod");
            let planned = observe(&team2).expect("observe");
            assert_eq!(compare_dir(&planned, mode).drift, Drift::Modify);
            let err = ensure_dir(&team2, mode, &planned, &mut CreatedDirs::new())
                .expect_err("modify: a setgid bit the kernel would drop is not applied");
            let message = err.to_string();
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept {
                        path,
                        declared,
                        landed,
                        chmod_left: None,
                        set_back: None,
                    } if *path == team2 && *declared == mode && *landed == Mode::PRIVATE_DIR
                ),
                "{err:?}",
            );
            assert!(
                message.ends_with(
                    "so the directory would not keep the setgid bit it declares. bx did not \
                     chmod it, and nothing was changed"
                ),
                "{message}"
            );
            let after = observe(&team2).expect("observe");
            assert_eq!(
                (after.mode, after.stamp),
                (Some(Mode::PRIVATE_DIR), planned.stamp),
                "a refused modify leaves the directory plan saw, untouched",
            );
            let second = compare_dir(&observe(&team2).expect("observe"), mode);
            assert_eq!(
                (second.drift, second.mode_drift),
                (Drift::Modify, Some((Mode::PRIVATE_DIR, mode))),
                "the second plan is the first plan again",
            );

            // A declared directory a write beneath it creates.
            let crew = dir.join("crew");
            let dest = crew.join("tool");
            let mut created = CreatedDirs::new();
            created.declare(&crew, mode);
            let planned = observe(&dest).expect("observe");
            let err = stage(&dest, Mode::DEFAULT_FILE, &planned, &mut created)
                .expect_err("stage: a declared setgid bit the kernel dropped is refused");
            assert_directory_set_id_not_kept(&err, &crew, mode);
            assert_eq!(
                names_in(&crew),
                Vec::<OsString>::new(),
                "nothing is written into it"
            );
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, SET_ID_DIR_CHILD_DIR, |_| {});
    }

    /// The variable the preflight test's child finds its setgid directory in.
    const SET_ID_PREFLIGHT_CHILD_DIR: &str = "BX_TEST_SET_ID_PREFLIGHT_CHILD_DIR";

    #[test]
    fn a_setgid_bit_a_chmod_would_strip_is_refused_before_any_chmod() {
        const NAME: &str = "fs::atomic::setid::tests::a_setgid_bit_a_chmod_would_strip_is_refused_before_any_chmod";

        if let Some(dir) = std::env::var_os(SET_ID_PREFLIGHT_CHILD_DIR) {
            // The child: uid 1, in a setgid directory owned by group 5, which
            // it is not in. A directory it makes there inherits group 5 and
            // S_ISGID, and any chmod it makes of that directory loses S_ISGID.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            // This child runs one test, so its umask is its own to set.
            rustix::process::umask(Mode::from_bits(0o022).into());
            let team = dir.join("team3");
            rustix::fs::mkdir(&team, Mode::DEFAULT_DIR.into()).expect("mkdir");
            let inherited = Mode::from_bits(0o2755);
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "the setgid bit is inherited"
            );

            for declared in [Mode::from_bits(0o2775), Mode::from_bits(0o775)] {
                let planned = observe(&team).expect("observe");
                let first = compare_dir(&planned, declared);
                assert_eq!(
                    (first.drift, first.mode_drift),
                    (Drift::Modify, Some((inherited, declared))),
                );
                let err = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
                    .expect_err("a chmod that would strip the setgid bit is refused");
                let message = err.to_string();
                assert!(
                    matches!(
                        &err,
                        Error::DirectorySetIdNotKept { path, declared: said, landed, .. }
                            if *path == team && *said == declared && *landed == inherited
                    ),
                    "{err:?}",
                );
                assert_eq!(
                    message,
                    format!(
                        "{} declares {declared} and is {inherited}: the kernel drops a \
                         directory's setgid bit on a chmod unless the process holds CAP_FSETID \
                         or is in the directory's group, and bx could confirm neither for this \
                         process, so the directory would lose the setgid bit it has. bx did not \
                         chmod it, and nothing was changed",
                        team.display()
                    ),
                );
                let after = observe(&team).expect("observe");
                assert_eq!(
                    (after.mode, after.stamp),
                    (planned.mode, planned.stamp),
                    "{declared}: nothing changed, not even a chmod and back a ctime would show",
                );
                assert_eq!(
                    compare_dir(&after, declared),
                    first,
                    "the second plan is the first"
                );
            }

            // The set-back itself, where the kernel strips the prior's bit: a
            // chmod that left 0775 is set back to the 2755 plan saw, and the
            // read-back names the 0755 that is on the directory instead.
            let left = Mode::from_bits(0o775);
            set_mode(&team, left).expect("chmod");
            let err = set_back(
                &team,
                inherited,
                not_kept(&team, Mode::from_bits(0o2775), left),
            );
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept { landed, chmod_left, set_back, .. }
                        if *landed == Mode::DEFAULT_DIR
                            && *chmod_left == Some(left)
                            && *set_back == Some(inherited)
                ),
                "{err:?}",
            );
            assert!(
                err.to_string().ends_with(
                    "bx set it back to 2755, the mode plan saw, but 0755 is on it now, so the \
                     set-back did not restore it. Nothing was recorded"
                ),
                "{err}"
            );
            assert_eq!(mode_of_path(&team), Mode::DEFAULT_DIR);
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, SET_ID_PREFLIGHT_CHILD_DIR, |_| {});
    }

    /// The variable the uid-0 child finds its setgid directory in.
    const SET_ID_ROOT_CHILD_DIR: &str = "BX_TEST_SET_ID_ROOT_CHILD_DIR";

    #[test]
    fn uid_zero_without_cap_fsetid_is_refused_like_any_other_process() {
        const NAME: &str = "fs::atomic::setid::tests::uid_zero_without_cap_fsetid_is_refused_like_any_other_process";

        if let Some(dir) = std::env::var_os(SET_ID_ROOT_CHILD_DIR) {
            // The child: uid 0 in a user namespace, with an empty capability
            // bounding set, so `execve` left it no `CAP_FSETID`. The kernel
            // strips `S_ISGID` from a chmod it makes of a directory in a group
            // it is not in, exactly as it would for any other uid — and the
            // predicate that once read `euid == 0` said otherwise, passed the
            // preflight, and lost the bit for good.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            assert!(rustix::process::geteuid().is_root(), "the child is uid 0");
            let status = std::fs::read_to_string("/proc/self/status").expect("status");
            assert!(
                !has_cap_fsetid(),
                "uid 0 with no capabilities: CapEff {:?}",
                cap_eff(&status),
            );
            // This child runs one test, so its umask is its own to set.
            rustix::process::umask(Mode::from_bits(0o022).into());
            let team = dir.join("team-root");
            rustix::fs::mkdir(&team, Mode::DEFAULT_DIR.into()).expect("mkdir");
            let inherited = Mode::from_bits(0o2755);
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "a setgid parent gives it the bit and its group",
            );

            let declared = Mode::from_bits(0o2775);
            let planned = observe(&team).expect("observe");
            let err = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
                .expect_err("uid 0 is not CAP_FSETID");
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept { path, chmod_left: None, .. } if *path == team
                ),
                "{err:?}",
            );
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "the setgid bit the directory had is still on it",
            );
            return;
        }

        run_in_a_foreign_setgid_directory(
            NAME,
            SET_ID_ROOT_CHILD_DIR,
            &[
                "--reuid=0",
                "--regid=0",
                "--clear-groups",
                "--bounding-set=-all",
            ],
            |_| {},
        );
    }

    /// The variable the capability child finds its setgid directory in.
    const SET_ID_CAP_CHILD_DIR: &str = "BX_TEST_SET_ID_CAP_CHILD_DIR";

    #[test]
    fn a_capability_does_not_survive_a_group_this_namespace_does_not_map() {
        const NAME: &str = "fs::atomic::setid::tests::\
                            a_capability_does_not_survive_a_group_this_namespace_does_not_map";

        if let Some(dir) = std::env::var_os(SET_ID_CAP_CHILD_DIR) {
            // The child: uid 0 in a user namespace that maps only the invoking
            // ids, holding a full capability set — so `CAP_FSETID` really is
            // held — in a setgid directory whose group 5 that namespace does
            // **not** map. `capable_wrt_inode_uidgid` needs the inode's uid and
            // gid mapped as well as the capability, so the kernel strips the
            // bit from a chmod this child makes, and the capability does not
            // save it.
            //
            // This is the arm nothing else exercises against a real kernel: the
            // other two harness callers drop the capability, one with
            // `--bounding-set=-all` and one with `--reuid=1`.
            println!("{SET_ID_CHILD_RAN}");
            let dir = PathBuf::from(dir);
            assert!(rustix::process::geteuid().is_root(), "the child is uid 0");
            assert!(
                has_cap_fsetid(),
                "the child holds CAP_FSETID: CapEff {:?}",
                cap_eff(&std::fs::read_to_string("/proc/self/status").expect("status")),
            );
            let overflow = overflow_ids();
            let shared = std::fs::metadata(&dir).expect("stat");
            assert_eq!(
                shared.gid(),
                overflow.gid,
                "the shared directory's group is unmapped here, so it reads as the overflow gid",
            );

            rustix::process::umask(Mode::from_bits(0o022).into());
            let team = dir.join("team-cap");
            rustix::fs::mkdir(&team, Mode::DEFAULT_DIR.into()).expect("mkdir");
            let inherited = Mode::from_bits(0o2755);
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "a setgid parent gives it the bit and its unmapped group",
            );

            let declared = Mode::from_bits(0o2775);
            let planned = observe(&team).expect("observe");
            let err = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
                .expect_err("CAP_FSETID does not outrank an unmapped gid");
            assert!(
                matches!(
                    &err,
                    Error::DirectorySetIdNotKept { path, chmod_left: None, .. } if *path == team
                ),
                "{err:?}",
            );
            assert_eq!(
                mode_of_path(&team),
                inherited,
                "the setgid bit the directory had is still on it",
            );
            return;
        }

        run_in_a_foreign_setgid_directory_under(
            NAME,
            SET_ID_CAP_CHILD_DIR,
            // The child's namespace maps only the invoking ids, so group 5 is
            // unmapped in it. No `setpriv`: the child keeps uid 0 and the full
            // capability set the namespace gives its creator.
            &["--map-root-user"],
            &[],
            |_| {},
        );
    }

    /// The refusal `set_dir_mode` returns for `dir`, declared `declared`, when
    /// its chmod left `left`.
    fn not_kept(dir: &Path, declared: Mode, left: Mode) -> Error {
        Error::DirectorySetIdNotKept {
            path: dir.to_path_buf(),
            declared,
            landed: left,
            chmod_left: Some(left),
            set_back: None,
        }
    }

    /// The overflow ids of a namespace that maps everything below 65534.
    const OVER: Overflow = Overflow {
        uid: 65534,
        gid: 65534,
    };

    #[test]
    fn the_setgid_predicate_confirms_a_capability_or_a_mapped_group_and_nothing_else() {
        const UID: u32 = 1000;
        const GID: u32 = 5;

        // The capability is one of the two things chmod(2) tests, and it is the
        // only one that passes a process outside the directory's group.
        assert_eq!(
            keeps_setgid(UID, GID, true, 1, &[], OVER),
            Some(KeepsSetgid::Capability),
            "CAP_FSETID, held by a process in none of the groups",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, GID, &[], OVER),
            Some(KeepsSetgid::Group),
            "the effective group",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, 1, &[3, GID], OVER),
            Some(KeepsSetgid::Group),
            "a supplementary group",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, 1, &[3, 4], OVER),
            None,
            "other groups only",
        );
        assert_eq!(
            keeps_setgid(UID, GID, false, 1, &[], OVER),
            None,
            "no groups"
        );

        // uid 0 is not a parameter at all, and that is r4 round 1's repair: a
        // process that is root in a user namespace without CAP_FSETID has its
        // chmod stripped like any other, and there is no arm left for it.
        //
        // These are r4 round 2's. `capable_wrt_inode_uidgid` requires both of
        // the inode's ids to be mapped, so the capability does NOT outrank an
        // unmapped id — it is the weaker path, not the stronger one. The
        // assertion below used to read `Some(Capability)`, and the kernel
        // disagreed: see
        // `a_capability_does_not_survive_a_group_this_namespace_does_not_map`.
        assert_eq!(
            keeps_setgid(UID, OVER.gid, true, 1, &[], OVER),
            None,
            "an unmapped group defeats the capability too",
        );
        assert_eq!(
            keeps_setgid(OVER.uid, GID, true, 1, &[], OVER),
            None,
            "so does an unmapped owner",
        );
        // ...but only for the capability. The group path has no uid
        // requirement, so an unmapped owner in a group this process is in still
        // keeps the bit, and refusing there would refuse a chmod that works.
        assert_eq!(
            keeps_setgid(OVER.uid, GID, false, GID, &[], OVER),
            Some(KeepsSetgid::Group),
            "an unmapped owner does not defeat membership",
        );
        // An unmapped group reads as the overflow gid, which names no group.
        // Matching it confirms nothing, even against gids that read the same
        // way, which is how two distinct unmapped groups would otherwise look
        // like one membership.
        assert_eq!(
            keeps_setgid(UID, OVER.gid, false, OVER.gid, &[OVER.gid], OVER),
            None,
            "the overflow gid never confirms a membership",
        );
        // The overflow ids are only whatever this namespace reports: on a host
        // where they are something else, 65534 is an ordinary group again.
        assert_eq!(
            keeps_setgid(
                UID,
                65534,
                false,
                65534,
                &[],
                Overflow {
                    uid: 65533,
                    gid: 65533
                },
            ),
            Some(KeepsSetgid::Group),
        );

        // The same answers for this process, read through rustix and /proc.
        let (uid, egid) = (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        );
        let overflow = overflow_ids();
        let groups: Vec<u32> = rustix::process::getgroups()
            .expect("getgroups")
            .into_iter()
            .map(rustix::process::Gid::as_raw)
            .collect();
        if egid != overflow.gid && uid != overflow.uid {
            assert_eq!(
                process_keeps_setgid(uid, egid),
                Some(KeepsSetgid::Group),
                "this process's own group",
            );
        }
        for member in groups.iter().filter(|gid| **gid != overflow.gid) {
            assert_eq!(
                process_keeps_setgid(uid, *member),
                Some(KeepsSetgid::Group),
                "supplementary group {member}",
            );
        }
        let foreign = (1..)
            .find(|gid| *gid != egid && *gid != overflow.gid && !groups.contains(gid))
            .expect("a group this process is not in");
        assert_eq!(
            process_keeps_setgid(uid, foreign).is_some(),
            has_cap_fsetid() && uid != overflow.uid,
            "group {foreign}, which this process is not in: only the capability confirms it",
        );
        assert_eq!(
            process_keeps_setgid(uid, overflow.gid),
            None,
            "a group this namespace does not map is refused whatever this process holds",
        );
    }

    #[test]
    fn no_confirmation_can_skip_the_mapping_test() {
        // The ordering bug this repair is about was reachable because the
        // capability arm ran before the mapping test. It cannot now: both arms
        // take a `MappedGid`, and the only constructor refuses the overflow
        // gid, so there is nothing for an arm that skipped the test to be
        // handed.
        assert_eq!(MappedGid::of(OVER.gid, OVER), None);
        assert_eq!(MappedGid::of(5, OVER), Some(MappedGid(5)));
        assert_eq!(
            MappedGid::of(OVER.gid, Overflow { uid: 0, gid: 0 }),
            Some(MappedGid(OVER.gid)),
            "the overflow gid is whatever the namespace says it is",
        );

        let gid = MappedGid::of(5, OVER).expect("a mapped gid");
        assert!(in_group(gid, 5, &[]), "the effective group");
        assert!(in_group(gid, 1, &[9, 5]), "a supplementary group");
        assert!(!in_group(gid, 1, &[9]), "neither");
        assert!(!in_group(gid, 1, &[]), "no groups at all");

        // `capable_wrt_inode_uidgid`: the capability, and the owner mapped.
        assert_eq!(
            inode_capability(1000, gid, true, OVER),
            Some(InodeCapability)
        );
        assert_eq!(
            inode_capability(1000, gid, false, OVER),
            None,
            "no capability"
        );
        assert_eq!(
            inode_capability(OVER.uid, gid, true, OVER),
            None,
            "an unmapped owner",
        );
    }

    #[test]
    fn the_effective_capability_set_is_read_from_the_line_that_names_it() {
        assert_eq!(
            cap_eff("Name:\tbx\nCapInh:\t0000000000000000\nCapEff:\t0000000000000010\n"),
            Some(0x10),
        );
        assert_eq!(cap_eff("CapEff: 1ffffffffff\n"), Some(0x1ff_ffff_ffff));
        assert_eq!(cap_eff("CapEff:\t0\n"), Some(0));
        assert_eq!(
            cap_eff("CapInh:\t0000000000000010\n"),
            None,
            "a different capability set is not the effective one",
        );
        assert_eq!(cap_eff("CapEff:\tnot a mask\n"), None);
        assert_eq!(cap_eff(""), None);

        // CAP_FSETID is capability 4, so the mask above is that bit alone.
        assert_eq!(1u64 << CAP_FSETID, 0x10);
        assert!(cap_fsetid_in(Some("CapEff:\t0000000000000018\n")));
        assert!(
            !cap_fsetid_in(Some("CapEff:\t0000000000000008\n")),
            "another bit"
        );
        assert!(!cap_fsetid_in(Some("CapEff:\tnot a mask\n")), "unparsable");
        assert!(!cap_fsetid_in(Some("")), "no CapEff line");
        assert!(
            !cap_fsetid_in(None),
            "a /proc that could not be read confirms nothing, so it is not held",
        );

        // The overflow ids: the kernel's value when there is one, and the
        // kernel's own default when there is not. Both arms, without needing a
        // host that lacks /proc.
        assert_eq!(overflow_in(Some("65534\n")), 65534);
        assert_eq!(overflow_in(Some(" 60000 ")), 60000, "trimmed");
        assert_eq!(
            overflow_in(Some("nonsense")),
            65534,
            "unparsable falls back"
        );
        assert_eq!(overflow_in(Some("")), 65534, "empty falls back");
        assert_eq!(overflow_in(Some("-1")), 65534, "not a u32 falls back");
        assert_eq!(overflow_in(None), 65534, "unreadable falls back");

        // And what this host actually reports, read rather than assumed.
        let overflow = overflow_ids();
        for (name, got) in [
            ("/proc/sys/kernel/overflowuid", overflow.uid),
            ("/proc/sys/kernel/overflowgid", overflow.gid),
        ] {
            match std::fs::read_to_string(name) {
                Ok(text) => assert_eq!(got.to_string(), text.trim(), "{name}"),
                Err(_) => assert_eq!(got, 65534, "{name}"),
            }
        }
    }

    #[test]
    fn the_setgid_preflight_refuses_a_directory_whose_group_it_cannot_confirm() {
        let home = guarded_home();
        let dir = home.child("team");
        std::fs::create_dir(&dir).expect("mkdir");
        let found = Mode::from_bits(0o2755);
        set_mode(&dir, found).expect("chmod");
        let declared = Mode::from_bits(0o2775);

        // Forced rather than arranged: an unconfirmable group needs a user
        // namespace, and the preflight's answer is the same either way.
        let err = forced::answering(None, || refuse_setgid_a_chmod_strips(&dir, found, declared))
            .expect_err("an unconfirmed process may not chmod a setgid directory");
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept {
                    path,
                    declared: said,
                    landed,
                    chmod_left: None,
                    set_back: None,
                } if *path == dir && *said == declared && *landed == found
            ),
            "{err:?}",
        );
        assert_eq!(
            mode_of_path(&dir),
            found,
            "the refusal comes before any chmod",
        );
        let message = err.to_string();
        assert!(message.contains("CAP_FSETID"), "{message}");
        assert!(
            message.contains("bx did not chmod it, and nothing was changed"),
            "{message}",
        );

        // Either confirmation passes it.
        for keeps in [KeepsSetgid::Capability, KeepsSetgid::Group] {
            assert!(
                forced::answering(Some(keeps), || refuse_setgid_a_chmod_strips(
                    &dir, found, declared
                ))
                .is_ok(),
                "{keeps:?}",
            );
        }
    }

    #[test]
    fn a_directory_this_apply_created_is_refused_when_its_group_stops_being_confirmable() {
        // The adopt path: a directory this apply made at a declared setgid
        // mode, met again by its own directory target. It runs the same
        // preflight before its chmod, and nothing else constructs that call's
        // refusal.
        let home = guarded_home();
        let dir = home.child("shared");
        let declared = Mode::from_bits(0o2755);
        let planned = observe(&dir).expect("plan sees nothing");
        let mut created = CreatedDirs::new();
        let made = ensure_dir(&dir, declared, &planned, &mut created).expect("create");
        assert_eq!(made.drift, Drift::Create);
        assert_eq!(
            mode_of_path(&dir),
            declared,
            "the bit stuck for its creator"
        );

        let err = forced::answering(None, || ensure_dir(&dir, declared, &planned, &mut created))
            .expect_err("the adopt path refuses a chmod it cannot confirm");
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept { path, chmod_left: None, .. } if *path == dir
            ),
            "{err:?}",
        );
        assert_eq!(mode_of_path(&dir), declared, "nothing was changed");
    }

    #[test]
    fn a_declared_directory_bit_missing_after_its_chmod_is_a_typed_error() {
        // The read-back `set_dir_mode` makes, apart from the chmod: the kernel
        // drops the bit only for a process outside the directory's group, and
        // the answer every caller depends on is this one.
        let home = guarded_home();
        let dir = home.child("plain");
        std::fs::create_dir(&dir).expect("mkdir");
        let landed = Mode::DEFAULT_DIR;
        set_mode(&dir, landed).expect("chmod");
        let meta = std::fs::symlink_metadata(&dir).expect("stat");

        assert!(
            refuse_dir_set_id_dropped(&dir, landed, &meta).is_ok(),
            "no special bit declared, nothing to lose",
        );
        let declared = Mode::from_bits(0o2755);
        let err = refuse_dir_set_id_dropped(&dir, declared, &meta)
            .expect_err("a declared setgid bit that is not on the directory");
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept {
                    path,
                    declared: said,
                    landed: found,
                    chmod_left: Some(left),
                    set_back: None,
                } if *path == dir && *said == declared && *found == landed && *left == landed
            ),
            "{err:?}",
        );
        assert!(
            err.to_string().contains("the setgid bit did not stick"),
            "{err}"
        );
    }

    #[test]
    fn the_setgid_preflight_stats_only_a_setgid_directory_and_passes_its_own_group() {
        let home = guarded_home();
        let missing = home.child("missing");
        assert!(
            refuse_setgid_a_chmod_strips(&missing, Mode::DEFAULT_DIR, Mode::PRIVATE_DIR).is_ok(),
            "no setgid bit on either side: nothing to look at",
        );
        for (found, declared) in [(0o2755, 0o755), (0o755, 0o2755)] {
            let err = refuse_setgid_a_chmod_strips(
                &missing,
                Mode::from_bits(found),
                Mode::from_bits(declared),
            )
            .expect_err("a setgid bit on either side is looked at");
            assert!(
                matches!(&err, Error::Read { path, .. } if *path == missing),
                "{found:04o} -> {declared:04o}: {err:?}",
            );
        }

        // A setgid directory in this process's own group keeps the bit, so
        // its Modify is applied, and the second plan is empty.
        let team = home.child("team");
        std::fs::create_dir(&team).expect("mkdir");
        set_mode(&team, Mode::from_bits(0o2755)).expect("chmod");
        assert_eq!(mode_of_path(&team), Mode::from_bits(0o2755), "own group");
        let declared = Mode::from_bits(0o2775);
        let planned = observe(&team).expect("observe");
        let applied = ensure_dir(&team, declared, &planned, &mut CreatedDirs::new())
            .expect("a member's chmod keeps the bit");
        assert_eq!(applied.drift, Drift::Modify);
        assert_eq!(mode_of_path(&team), declared);
        let second = observe(&team).expect("observe");
        assert_eq!(compare_dir(&second, declared).drift, Drift::Unchanged);
    }

    #[test]
    fn a_refused_directory_modify_is_set_back_and_worded_from_what_is_there_after() {
        let home = guarded_home();
        let dir = home.child("d");
        std::fs::create_dir(&dir).expect("mkdir");
        // As a chmod that dropped a declared sticky bit would leave it.
        set_mode(&dir, Mode::DEFAULT_DIR).expect("chmod");
        let declared = Mode::from_bits(0o1755);
        let err = set_back(
            &dir,
            Mode::PRIVATE_DIR,
            not_kept(&dir, declared, Mode::DEFAULT_DIR),
        );
        assert!(
            matches!(
                &err,
                Error::DirectorySetIdNotKept { path, declared: said, landed, chmod_left, set_back }
                    if *path == dir
                        && *said == declared
                        && *landed == Mode::PRIVATE_DIR
                        && *chmod_left == Some(Mode::DEFAULT_DIR)
                        && *set_back == Some(Mode::PRIVATE_DIR)
            ),
            "{err:?}",
        );
        assert_eq!(
            err.to_string(),
            format!(
                "{} declares 1755, and only 0755 was on the directory after its chmod: the \
                 sticky bit did not stick. A filesystem that stores no set-id or sticky bits, \
                 such as vfat or exfat mounted with `quiet`, drops them. bx set it back to 0700, \
                 the mode plan saw, and nothing was recorded",
                dir.display()
            ),
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR, "set back");

        // Any other refusal is returned as it was, after the same set-back.
        set_mode(&dir, Mode::DEFAULT_DIR).expect("chmod");
        let other = Error::Write {
            path: dir.clone(),
            source: std::io::Error::from_raw_os_error(libc_eperm()),
        };
        let err = set_back(&dir, Mode::PRIVATE_DIR, other);
        assert!(
            matches!(&err, Error::Write { path, source } if *path == dir && source.raw_os_error() == Some(libc_eperm())),
            "{err:?}",
        );
        assert_eq!(mode_of_path(&dir), Mode::PRIVATE_DIR, "set back");

        // A directory that is gone cannot be read back: what is there is
        // unknown, so the refusal says that instead.
        let gone = home.child("gone");
        let err = set_back(
            &gone,
            Mode::PRIVATE_DIR,
            not_kept(&gone, declared, Mode::DEFAULT_DIR),
        );
        assert!(
            matches!(&err, Error::Read { path, .. } if *path == gone),
            "{err:?}"
        );
    }

    /// The variable the foreign-file test's child finds its directory in.
    const FOREIGN_FILE_CHILD_DIR: &str = "BX_TEST_FOREIGN_FILE_CHILD_DIR";

    #[test]
    fn a_foreign_file_s_prior_mode_without_owner_read_is_restored_as_recorded() {
        const NAME: &str = "fs::atomic::setid::tests::\
             a_foreign_file_s_prior_mode_without_owner_read_is_restored_as_recorded";
        let theirs = b"theirs\n";
        let recorded = Mode::from_bits(0o004);

        if let Some(dir) = std::env::var_os(FOREIGN_FILE_CHILD_DIR) {
            // The child, uid 1: the file is somebody else's, at 0004, so it
            // reads the bytes through the other bits alone.
            println!("{SET_ID_CHILD_RAN}");
            let foreign = PathBuf::from(dir).join("foreign");
            let planned = observe(&foreign).expect("observe");
            assert_eq!(
                (planned.kind, planned.mode, planned.bytes.as_deref()),
                (Kind::File, Some(recorded), Some(&theirs[..])),
            );

            // apply records the prior, then replaces the file.
            let staged = stage(
                &foreign,
                Mode::DEFAULT_FILE,
                &planned,
                &mut CreatedDirs::new(),
            )
            .expect("stage");
            let prior = staged.prior().clone();
            staged.commit(b"managed\n").expect("commit");
            assert_eq!(prior.mode, Some(recorded), "the prior mode is recorded");

            // rm restores the recorded bytes at the recorded mode.
            let now = observe(&foreign).expect("observe");
            stage(&foreign, recorded, &now, &mut CreatedDirs::new())
                .expect("a recorded prior mode is staged as recorded")
                .commit(prior.bytes.as_deref().expect("prior bytes"))
                .expect("commit");
            assert_eq!(mode_of_path(&foreign), recorded, "restored exactly");
            return;
        }

        run_unprivileged_in_a_foreign_setgid_directory(NAME, FOREIGN_FILE_CHILD_DIR, |dir| {
            seed(&dir.join("foreign"), theirs, recorded);
        });
    }

    #[test]
    fn a_restore_of_a_recorded_mode_without_owner_read_is_written_as_recorded() {
        let home = guarded_home();
        let dest = home.child("restored");
        seed(&dest, b"managed\n", Mode::DEFAULT_FILE);
        let recorded = Mode::from_bits(0o004);
        let now = observe(&dest).expect("observe");

        // Declared, the mode is still plan's conflict: bx could not read the
        // file back to compare it.
        assert_eq!(
            compare(&now, &desired(b"prior\n", recorded), home.path()).drift,
            Drift::Conflict,
        );
        // Restored, it is what was there, and stage writes it as recorded.
        stage(&dest, recorded, &now, &mut CreatedDirs::new())
            .expect("a recorded prior mode is staged as recorded")
            .commit(b"prior\n")
            .expect("commit");
        assert_eq!(mode_of_path(&dest), recorded);
        set_mode(&dest, Mode::DEFAULT_FILE).expect("unlock for the assertion");
        assert_eq!(std::fs::read(&dest).expect("read"), b"prior\n");
    }

    /// `EPERM`, the errno a refused `chmod` reports.
    fn libc_eperm() -> i32 {
        Errno::PERM.raw_os_error()
    }

    /// The refusal a directory whose declared special bit did not stick gets,
    /// naming `dir`; returns the mode it reports on disk.
    fn assert_directory_set_id_not_kept(err: &Error, dir: &Path, declared: Mode) -> Mode {
        let message = err.to_string();
        let Error::DirectorySetIdNotKept {
            path,
            declared: said,
            landed,
            chmod_left,
            set_back,
        } = err
        else {
            panic!("expected DirectorySetIdNotKept, got {err:?}");
        };
        assert_eq!(path, dir, "{message}");
        assert_eq!(*said, declared);
        assert_eq!(landed.bits() & 0o2000, 0, "the bit really was dropped");
        assert_eq!(
            (*chmod_left, *set_back),
            (Some(*landed), None),
            "a directory bx created is left as its chmod left it",
        );
        assert_eq!(err.path(), dir, "{message}");
        assert!(
            message.contains(&format!(
                "only {landed} was on the directory after its chmod"
            )),
            "{message}"
        );
        assert!(
            message.contains("a directory whose group you are not in"),
            "{message}"
        );
        assert!(
            message.ends_with(&format!(
                "Nothing was recorded, and the directory, which bx created in this apply, is \
                 left in place at {landed}"
            )),
            "{message}"
        );
        assert!(
            message.contains(&format!("declares {declared}, and only")),
            "{message}"
        );
        assert!(
            message.contains("the setgid bit did not stick"),
            "{message}"
        );
        *landed
    }

    /// Run the test `name` again as uid 1 with no supplementary groups, inside
    /// a user namespace, with `child_env` naming a world-writable setgid
    /// directory owned by a group that uid is not in.
    ///
    /// Skips, with a message on stderr, wherever the scenario cannot be
    /// constructed; fails only when the child ran and failed.
    fn run_unprivileged_in_a_foreign_setgid_directory(
        name: &str,
        child_env: &str,
        seed: impl FnOnce(&Path),
    ) {
        run_in_a_foreign_setgid_directory(
            name,
            child_env,
            &["--reuid=1", "--regid=1", "--clear-groups"],
            seed,
        );
    }

    /// Run the test `name` again under `setpriv`'s `credentials`, inside a user
    /// namespace, with `child_env` naming a world-writable setgid directory
    /// owned by a group those credentials are not in.
    ///
    /// Skips, with a message on stderr, wherever the scenario cannot be
    /// constructed; fails only when the child ran and failed.
    fn run_in_a_foreign_setgid_directory(
        name: &str,
        child_env: &str,
        credentials: &[&str],
        seed: impl FnOnce(&Path),
    ) {
        run_in_a_foreign_setgid_directory_under(
            name,
            child_env,
            &["--map-auto", "--map-root-user"],
            credentials,
            seed,
        );
    }

    /// As above, but with the namespace the **child** runs in given
    /// separately from the one the setup steps run in.
    ///
    /// They differ for one case and it is the case D1 was about. The setup
    /// needs `--map-auto` to `chown` the directory to group 5. A child run
    /// under `--map-root-user` alone is in a namespace that maps *only* the
    /// invoking ids, so group 5 has no mapping there and `stat` reports the
    /// overflow gid — while the child is uid 0 with a full capability set.
    /// That is the one combination `capable_wrt_inode_uidgid` refuses and
    /// nothing else here constructs.
    fn run_in_a_foreign_setgid_directory_under(
        name: &str,
        child_env: &str,
        child_namespace: &[&str],
        credentials: &[&str],
        seed: impl FnOnce(&Path),
    ) {
        // Written to the process's own stderr, not through `eprintln!`:
        // libtest captures the macro's output and discards it for a test that
        // passes, so a skip announced that way is invisible and the suite still
        // reports green. This goes to file descriptor 2, which libtest does not
        // intercept.
        let skip = |why: &str| {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "skipped {name}: {why}");
        };
        let home = guarded_home();
        // Another uid has to reach the directory and run this test binary,
        // whose own directory it may not be able to read.
        set_mode(home.path(), Mode::DEFAULT_DIR).expect("open the home to traversal");
        let exe = home.child("bx-test");
        // A copy rather than a hard link: the build's own file need not be
        // executable by anyone else either. A full disk cannot hold the copy,
        // and that is the scenario not being constructible, not a failure.
        if let Err(e) = std::fs::copy(std::env::current_exe().expect("the test binary"), &exe) {
            return skip(&format!("the test binary could not be copied: {e}"));
        }
        set_mode(&exe, Mode::from_bits(0o755)).expect("chmod the copy");
        let dir = home.child("shared");
        std::fs::create_dir(&dir).expect("mkdir");
        // Anything the child should find there owned by this user, which is
        // somebody else to uid 1.
        seed(&dir);

        // Each step in a user namespace mapping this user to root and its
        // subordinate ids above that: give the directory group 5, make it
        // setgid and world-writable, and run the child as uid 1.
        let unshared = |ns: &[&str], args: &[&std::ffi::OsStr]| {
            std::process::Command::new("unshare")
                .args(ns)
                .arg("--")
                .args(args)
                .env(child_env, &dir)
                .output()
        };
        let in_namespace =
            |args: &[&std::ffi::OsStr]| unshared(&["--map-auto", "--map-root-user"], args);
        for step in [
            [
                std::ffi::OsStr::new("chown"),
                "0:5".as_ref(),
                dir.as_os_str(),
            ],
            ["chmod".as_ref(), "2777".as_ref(), dir.as_os_str()],
        ] {
            match in_namespace(&step) {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    return skip(&format!(
                        "{step:?} in a user namespace failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    ));
                }
                Err(e) => return skip(&format!("unshare could not run: {e}")),
            }
        }
        let meta = std::fs::metadata(&dir).expect("stat");
        if meta.mode() & 0o2000 == 0 || meta.gid() == rustix::process::getegid().as_raw() {
            return skip("the directory is not setgid to a foreign group");
        }

        // No credentials asked for means no `setpriv` at all: the child keeps
        // the ids and the capability set its namespace gave it. `setpriv`
        // cannot be used for that anyway — a namespace created without
        // `--map-auto` has `setgroups` denied, so even `--clear-groups` fails.
        let mut argv: Vec<&std::ffi::OsStr> = Vec::new();
        if !credentials.is_empty() {
            argv.push("setpriv".as_ref());
            argv.extend(credentials.iter().map(|arg| std::ffi::OsStr::new(*arg)));
            argv.push("--".as_ref());
        }
        argv.extend([
            exe.as_os_str(),
            "--exact".as_ref(),
            name.as_ref(),
            "--nocapture".as_ref(),
        ]);
        let child = unshared(child_namespace, &argv);
        let out = match child {
            Ok(out) => out,
            Err(e) => return skip(&format!("unshare could not run: {e}")),
        };
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        if !stdout.contains(SET_ID_CHILD_RAN) {
            return skip(&format!("the unprivileged child did not start: {stderr}"));
        }
        assert!(
            out.status.success(),
            "the unprivileged child failed:\n{stdout}\n{stderr}"
        );
    }
}
