//! The decision for a tracked target one copy of which was deleted since the
//! two copies last agreed: the deletion carried to the other side, or a
//! conflict.

use super::parent::{Write, locked_parent};
use super::{Ctx, Made, Op};
use crate::fs::{Mode, Observed};
use crate::paths::Portable;
use crate::plan::track::{Agreed, Base, When};
use crate::plan::{Change, Diff};
use crate::report::Action;

/// Which of a tracked target's two copies was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gone {
    /// This machine's, at the target's path.
    Machine,
    /// The repo's, at the target's `file` body.
    Repo,
}

/// The row, the write and the agreement of the tracked target `tracked`, one
/// copy of which was deleted since the two last agreed on `base`.
/// `kept` is the other copy as it stands, with its ledger key, holding
/// `present`.
///
/// # Decision: a deletion is a change, as git takes one
///
/// | the side deleted | the other side | row |
/// | --- | --- | --- |
/// | this machine's | as they agreed | sync: `sync` removes the repo's copy, and commits the removal |
/// | the repo's | as they agreed | modify: `apply` removes this machine's copy |
/// | either | changed since they agreed | conflict: deleted on one side, changed on the other |
///
/// Copying the present side over the deletion, as a first sync does, would
/// undo it; with an agreement recorded, bx can tell that one side deleted
/// the file and the other did not touch it, so the deletion is carried
/// across, as a merge carries a deletion against an unchanged base. With no
/// agreement recorded, nothing tells a deletion from a copy that was never
/// there, and [`super::decide_track`] copies the present side as before.
///
/// # Decision: the removal keeps its ledger entry
///
/// Either removal is bx's write, so `bx rm` must be able to take it back
/// (Invariant 4). It is claimed: the session keeps the copy's ledger entry,
/// recorded at [`crate::state::removed_written`] with the bytes it removed as
/// the prior, by the rules every re-record follows — so a copy that held what
/// bx itself last wrote there keeps the prior it had, and one bx never wrote
/// gets its bytes back from `bx rm`. The entry's claims stay with it, so the
/// removal names no directory to prune.
///
/// Once the deletion is carried, the two sides agree on nothing, and the
/// agreement is forgotten: see [`Agreed::bytes`].
pub(super) fn one_side_deleted(
    tracked: &Portable,
    gone: Gone,
    (key, kept): (Portable, &Observed),
    base: &Base,
    present: &[u8],
    ctx: &Ctx<'_>,
    row: impl Fn(Action, Option<Diff>, Option<String>) -> Change,
) -> (Change, Option<Op>, Option<Agreed>) {
    let shown = tracked.as_str();
    let (deleted, other, present_side) = match gone {
        Gone::Machine => ("this machine's copy", "the repo's", "repo"),
        Gone::Repo => ("the repo's copy", "this machine's", "this machine"),
    };
    if !base.holds(present) {
        let why = format!(
            "{deleted} was deleted since the last sync, and {other} changed since; bx merges \
             neither. Delete the other copy too, or put one back, by hand"
        );
        let diff = match base {
            Base::Bytes(base) => Diff::labelled(
                shown,
                ("last sync", present_side),
                Some(base),
                present,
                None,
            ),
            // Too large to have been kept whole: the side still there is all
            // there is to show.
            Base::Digest(_) => {
                Diff::labelled(shown, ("deleted", present_side), None, present, None)
            }
        };
        return (row(Action::Conflict, diff, Some(why)), None, None);
    }
    if let Some(why) = locked_parent(kept, ctx.home, ctx.declared, Write::File) {
        return (row(Action::Conflict, None, Some(why)), None, None);
    }
    let diff = Diff::labelled(shown, (present_side, "deleted"), Some(present), b"", None);
    let (action, note, when) = match gone {
        Gone::Machine => (
            Action::Sync,
            "deleted: this machine's copy was deleted since the last sync; bx sync removes the \
             repo's and commits the removal; bx rm puts it back unless bx itself created that \
             copy",
            When::Synced,
        ),
        Gone::Repo => (
            Action::Modify,
            "deleted: the repo's copy was deleted since the last sync; apply removes this \
             machine's; bx rm puts it back unless bx itself created that copy",
            When::Applied,
        ),
    };
    let op = Op {
        target: key,
        dest: kept.path.clone(),
        made: Made::Absent(Vec::new()),
        planned: kept.clone(),
        mode: kept.mode.unwrap_or(Mode::DEFAULT_FILE),
        claimed: true,
        carry: gone == Gone::Machine,
        base: false,
    };
    let agreement = Agreed {
        target: tracked.clone(),
        bytes: None,
        when,
    };
    (
        row(action, diff, Some(note.to_string())),
        Some(op),
        Some(agreement),
    )
}
