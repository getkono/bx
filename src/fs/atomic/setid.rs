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
    /// This process holds `CAP_FSETID` in its effective set — on macOS, which
    /// has no capabilities, it runs as the superuser. See [`has_cap_fsetid`].
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
///
/// On macOS `getgroups` reports at most 16 supplementary groups, while the
/// kernel asks the membership resolver, which knows them all. A group beyond
/// the sixteenth is therefore not confirmed and the preflight refuses: the
/// refusal costs a plan line, the other guess a bit.
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
#[cfg(any(target_os = "linux", test))]
const CAP_FSETID: u32 = 4;

/// Whether this process holds `CAP_FSETID` in its effective capability set.
///
/// Read from `/proc/self/status`, which is the whole interface: bx forbids
/// `unsafe`, so `capget(2)` is not reachable without a dependency that adds
/// one, and `/proc` is Linux's native answer rather than a portability
/// compromise.
///
/// A set that cannot be read or parsed confirms nothing and is `false`. The
/// caller then refuses, which changes nothing; the other guess strips a bit.
/// The whole judgement is [`cap_fsetid_in`], which takes the text, so the only
/// part no test reaches is the `read_to_string` itself.
///
/// What stands in for `CAP_FSETID` on macOS is an effective uid of 0. XNU has
/// no capabilities and no `/proc`. Its `chmod` keeps `S_ISGID` for the
/// superuser and otherwise only for a member of the directory's group, so the
/// superuser is the whole of the privileged path, and the group path is
/// [`in_group`], as on Linux.
///
/// One function with an arm per platform, not one function per platform:
/// mutation testing runs on Linux, where a function compiled only for macOS
/// is never built, so every mutant of its body would survive.
fn has_cap_fsetid() -> bool {
    #[cfg(target_os = "linux")]
    {
        cap_fsetid_in(std::fs::read_to_string("/proc/self/status").ok().as_deref())
    }
    #[cfg(not(target_os = "linux"))]
    {
        rustix::process::geteuid().is_root()
    }
}

/// Whether `CAP_FSETID` is set in the `CapEff` mask of `status`, the text of
/// `/proc/self/status`.
///
/// `None` — the file could not be read — and text with no usable `CapEff` line
/// both confirm nothing, and so are `false`.
#[cfg(any(target_os = "linux", test))]
fn cap_fsetid_in(status: Option<&str>) -> bool {
    status
        .and_then(cap_eff)
        .is_some_and(|effective| effective & (1 << CAP_FSETID) != 0)
}

/// The effective capability mask on a `/proc/<pid>/status` `CapEff:` line.
///
/// `None` when the line is absent or is not the hex mask the kernel writes.
#[cfg(any(target_os = "linux", test))]
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
///
/// macOS has no user namespaces, so no id is unmapped and none reads as an
/// overflow id. `(uid_t)-1` and `(gid_t)-1` stand in for one: they are
/// `KAUTH_UID_NONE` and `KAUTH_GID_NONE`, and `chown` reads `-1` as "leave it
/// unchanged", so no file can be given either. The directory service does name
/// `nogroup` with gid `-1`; were a file ever to `stat` as it, the preflight
/// would refuse it, which is the safe direction.
///
/// One function with an arm per platform, for the reason [`has_cap_fsetid`]
/// gives.
fn overflow_ids() -> Overflow {
    #[cfg(target_os = "linux")]
    {
        let read = |name: &str| std::fs::read_to_string(name).ok();
        Overflow {
            uid: overflow_in(read("/proc/sys/kernel/overflowuid").as_deref()),
            gid: overflow_in(read("/proc/sys/kernel/overflowgid").as_deref()),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Overflow {
            uid: u32::MAX,
            gid: u32::MAX,
        }
    }
}

/// The overflow id in `text`, or the kernel's `DEFAULT_OVERFLOWUID` /
/// `DEFAULT_OVERFLOWGID` — both `65534` — when there is none to read.
#[cfg(any(target_os = "linux", test))]
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
mod tests;
