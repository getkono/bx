//! Track mode's agreements: what each `direction = "track"` target's copy on
//! this machine and copy in the config repo last agreed on.
//!
//! [`super::decide`] reads them to tell which side moved since the last sync,
//! and reports when its decision makes the two sides agree again. This module
//! keeps them: read from the fingerprint cache once per run by [`bases`], and
//! recorded there by [`agree`] once the run has made them true.

use std::collections::{BTreeMap, BTreeSet};

use super::{Error, Inputs, Mode};
use crate::config::resolve::Resolution;
use crate::config::target::Direction;
use crate::paths::Portable;
use crate::state::{ContentHash, ExclusiveLock, Fingerprint, Fingerprints};

/// What each tracked target's copy on this machine and copy in the repo last
/// agreed on, keyed by the target: what "changed since the last sync" is
/// measured from. Read from the fingerprint cache — see [`bases`].
pub(super) type Bases = BTreeMap<Portable, Base>;

/// What a tracked target's two sides last agreed on, as the fingerprint cache
/// keeps it: the bytes themselves while they are small, and otherwise only
/// their digest. See [`Base::fingerprint`] for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Base {
    /// The agreed bytes, kept whole so a conflict can show each side's diff
    /// from them.
    Bytes(Vec<u8>),
    /// The SHA-256 of agreed bytes larger than [`Base::KEPT_WHOLE`].
    Digest([u8; 32]),
}

impl Base {
    /// The largest agreement kept whole, in bytes.
    pub(super) const KEPT_WHOLE: usize = 64 * 1024;

    /// The tag of an agreement kept whole.
    const BYTES: u8 = b'=';

    /// The tag of an agreement kept as a digest.
    const DIGEST: u8 = b'#';

    /// The agreement on `bytes`, as it is kept.
    pub(super) fn of(bytes: &[u8]) -> Self {
        if bytes.len() <= Self::KEPT_WHOLE {
            Self::Bytes(bytes.to_vec())
        } else {
            Self::Digest(*ContentHash::of(bytes).as_bytes())
        }
    }

    /// Whether `bytes` are what was agreed on.
    pub(super) fn holds(&self, bytes: &[u8]) -> bool {
        match self {
            Self::Bytes(agreed) => agreed == bytes,
            Self::Digest(digest) => digest == ContentHash::of(bytes).as_bytes(),
        }
    }

    /// The fingerprint-cache entry this agreement is kept as: a tag byte, then
    /// the bytes or the digest.
    ///
    /// # Decision: small agreements are kept whole, large ones as a digest
    ///
    /// Deciding which side moved needs only a comparison, which a digest
    /// answers. Showing a conflict does not: issue #32 asks for *both sides'
    /// diffs*, each measured from the last agreement, and a diff needs the
    /// bytes it is measured from. Nothing else holds them — the repo's copy
    /// may have been rewritten by another machine since, and the machine's by
    /// the tool — so the cache keeps them.
    ///
    /// The fingerprint cache is for short inputs, so what it keeps is bounded:
    /// an agreement of at most [`Base::KEPT_WHOLE`] bytes is kept whole, and a
    /// larger one only as its digest, whose conflict shows the one diff
    /// between the two sides instead. A plugin manager's lock file, the
    /// target track mode exists for, is a few kilobytes.
    pub(super) fn fingerprint(&self) -> Fingerprint {
        let mut kept = Vec::new();
        match self {
            Self::Bytes(bytes) => {
                kept.push(Self::BYTES);
                kept.extend_from_slice(bytes);
            }
            Self::Digest(digest) => {
                kept.push(Self::DIGEST);
                kept.extend_from_slice(digest);
            }
        }
        Fingerprint::raw(kept)
    }

    /// The agreement a fingerprint-cache entry keeps, or `None` for one in no
    /// shape [`Base::fingerprint`] writes — which reads as no agreement, and
    /// so costs a question rather than an overwrite.
    pub(super) fn from_fingerprint(fingerprint: &Fingerprint) -> Option<Self> {
        match fingerprint.as_bytes().split_first()? {
            (&Self::BYTES, bytes) if bytes.len() <= Self::KEPT_WHOLE => {
                Some(Self::Bytes(bytes.to_vec()))
            }
            (&Self::DIGEST, digest) => Some(Self::Digest(digest.try_into().ok()?)),
            _ => None,
        }
    }
}

/// When the bytes a tracked target's two sides hold become the bytes they
/// last agreed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum When {
    /// Already: both sides hold them.
    Now,
    /// Once `apply` has written the repo's copy onto this machine.
    Applied,
    /// Once `sync` has carried this machine's copy into the repo.
    Synced,
}

/// What a tracked target's two sides will agree on, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Agreed {
    /// The tracked target.
    pub target: Portable,
    /// The bytes both sides hold once [`Agreed::when`] has happened.
    pub bytes: Vec<u8>,
    /// What has to happen first.
    pub when: When,
}

/// What every fingerprint-cache key a tracked target's agreement is kept
/// under begins with.
const TRACK_PREFIX: &str = "track:";

/// The fingerprint-cache key a tracked target's agreement is kept under.
fn base_key(target: &Portable) -> String {
    format!("{TRACK_PREFIX}{}", target.as_str())
}

/// Every target the configuration declares tracked.
fn tracked(inputs: &Inputs) -> Vec<&Portable> {
    inputs
        .resolved
        .targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) if target.direction == Direction::Track => Some(&target.path),
            _ => None,
        })
        .collect()
}

/// What each tracked target's two sides last agreed on, read from the
/// fingerprint cache without the lock.
///
/// # Decision: the agreement is kept in the fingerprint cache
///
/// It is machine-owned, per account, and never published, which is what the
/// state directory holds; and losing it is what the cache's contract allows,
/// because [`super::decide`]'s tracked decision reads a missing agreement as
/// "cannot tell which side moved" and asks a human rather than overwriting
/// either side. The ledger is the wrong home: an entry there claims a file and holds
/// the bytes `rm` puts back, and bx claims the machine's copy only where
/// `apply` created it, while every tracked target has an agreement. Keeping it
/// in the ledger would claim a copy the tool had before bx wrote to it, so
/// `rm` would replace the tool's later bytes with ones the tool no longer
/// holds.
///
/// What it keeps is bounded, and is the bytes themselves only while they are
/// small: see [`Base::fingerprint`].
pub(super) fn bases(inputs: &Inputs) -> Result<Bases, Error> {
    let tracked = tracked(inputs);
    if tracked.is_empty() {
        return Ok(Bases::new());
    }
    let cache = Fingerprints::read(&inputs.state)?.value;
    Ok(tracked
        .into_iter()
        .filter_map(|target| {
            let base = Base::from_fingerprint(cache.get(&base_key(target))?)?;
            Some((target.clone(), base))
        })
        .collect())
}

/// The agreements `cache` keeps for targets the configuration no longer
/// declares tracked, or none while any target is blocked.
///
/// # Decision: an agreement is forgotten once its target is not tracked
///
/// An agreement outlives nothing it could be used for: a target no longer
/// tracked is never decided against it, and one tracked again later that
/// finds none asks a human where the two copies differ, never overwriting
/// either. A blocked target's direction cannot be read, so while any is
/// blocked nothing is forgotten, and an agreement a target that is only
/// waiting for a value still needs is kept for it.
fn stale(inputs: &Inputs, cache: &Fingerprints) -> Vec<String> {
    let blocked = inputs
        .resolved
        .targets
        .iter()
        .any(|resolution| matches!(resolution, Resolution::Blocked(_)));
    if blocked {
        return Vec::new();
    }
    let kept: BTreeSet<String> = tracked(inputs).into_iter().map(base_key).collect();
    cache
        .iter()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with(TRACK_PREFIX) && !kept.contains(*key))
        .cloned()
        .collect()
}

/// Record what each tracked target's two sides now agree on: every agreement
/// that holds already, and — once this run `executed` — those its writes made,
/// a carry into the repo only in [`Mode::Sync`]; and forget every agreement
/// [`stale`] names.
///
/// Written under the lock, and only when something changed, so a run with
/// nothing new to record leaves the state directory as it found it.
pub(super) fn agree(
    inputs: &Inputs,
    bases: &Bases,
    agreed: &[Agreed],
    mode: Mode,
    executed: bool,
) -> Result<(), Error> {
    let settled = agreed
        .iter()
        .filter(|agreed| match agreed.when {
            When::Now => true,
            When::Applied => executed,
            When::Synced => executed && mode == Mode::Sync,
        })
        .map(|agreed| (&agreed.target, Base::of(&agreed.bytes)))
        .filter(|(target, base)| bases.get(*target) != Some(base))
        .map(|(target, base)| (base_key(target), base))
        .collect::<Vec<_>>();
    if settled.is_empty() && stale(inputs, &Fingerprints::read(&inputs.state)?.value).is_empty() {
        return Ok(());
    }
    inputs.state.ensure()?;
    let lock = ExclusiveLock::acquire(&inputs.state)?;
    let before = Fingerprints::open(&inputs.state, &lock)?.value;
    let mut cache = before.clone();
    for key in stale(inputs, &before) {
        cache.remove(&key);
    }
    for (key, base) in settled {
        cache.set(key, base.fingerprint());
    }
    if cache != before {
        cache.save(&inputs.state, &lock)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agreement_of_up_to_64_kib_is_kept_whole_and_a_larger_one_as_its_digest() {
        // Written out rather than read from `Base::KEPT_WHOLE`, so a change to
        // the bound is a change a test names.
        const SIXTY_FOUR_KIB: usize = 65_536;
        let whole = vec![b'a'; SIXTY_FOUR_KIB];
        let large = vec![b'a'; SIXTY_FOUR_KIB + 1];
        assert_eq!(Base::of(&whole), Base::Bytes(whole.clone()));
        assert_eq!(
            Base::of(&large),
            Base::Digest(*ContentHash::of(&large).as_bytes())
        );
        // Each reads back from the cache as it was kept; whole bytes past the
        // bound are no shape the cache writes.
        for base in [Base::of(&whole), Base::of(&large)] {
            assert_eq!(Base::from_fingerprint(&base.fingerprint()), Some(base));
        }
        let mut past = vec![Base::BYTES];
        past.extend_from_slice(&large);
        assert_eq!(Base::from_fingerprint(&Fingerprint::raw(past)), None);
    }
}
