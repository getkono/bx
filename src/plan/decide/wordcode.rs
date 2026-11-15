//! A zsh activation's wordcode is written only with its file, and always after
//! it.
//!
//! zsh's `source` reads `NAME.zsh.zwc` in place of `NAME.zsh` whenever the
//! `.zwc` is at least as new as the file, so the two writes are one decision:
//!
//! - **The file is not written** — kept as the user edited it, held for an
//!   answer, or blocked — and the wordcode is not either. A `.zwc` compiled
//!   from bx's bytes, newer than an edit kept on disk, would have zsh run
//!   bx's bytes in place of the edit. A wordcode decided against a file that
//!   is already what bx wants is written as decided: it compiles those bytes.
//! - **The file is held for an answer**, and its wordcode's write is tied to
//!   it: made only for *take bx's*, right after the file's.
//! - **The file is written**, and so is its wordcode, after it, even where
//!   its bytes are already right: a file rewritten with the same output — a
//!   refreshed claim, a re-created file, a taken edit — is newer than the
//!   `.zwc` left beside it, and zsh would stop reading the compiled form
//!   while the plan reported nothing to do.

use super::{Base, Change, Error, Made, Op, join};
use crate::config::resolve::Resolution;
use crate::config::target::{Body, Gen, Target};
use crate::fs::{self, Kind, Mode};
use crate::report::Action;

/// A wordcode's write tied to its file's, which is held for an answer: made
/// only once the file's is, right after it.
#[derive(Debug)]
pub(in crate::plan) struct Tied {
    /// The row of the file, in [`super::Decided::held`].
    pub source: usize,
    /// The wordcode's own row.
    pub row: usize,
    /// The wordcode's write.
    pub op: Op,
    /// The note the wordcode's row carries once its write is made.
    pub note: Option<String>,
}

/// The note a wordcode's row carries when its file is not written.
pub(in crate::plan) const WAITS: &str = "written only with its file, which is not: zsh would \
                                         read it in place of what that file holds";

/// The note a wordcode's row carries when it is rewritten, bytes unchanged,
/// after its file.
pub(in crate::plan) const REWRITTEN: &str = "rewritten after its file, so zsh keeps reading the \
                                             compiled form; its bytes stay as they are";

/// Tie each wordcode target's write to its file's, as the module says,
/// adjusting `changes`, `ops` and `held`, all indexed as `resolutions` is.
///
/// # Errors
///
/// Where a wordcode rewritten after its file cannot be observed.
pub(super) fn tie(
    resolutions: &[Resolution<Target>],
    changes: &mut [Change],
    ops: &mut Vec<Op>,
    held: &mut Vec<(usize, Op)>,
    home: &std::path::Path,
) -> Result<Vec<Tied>, Error> {
    let mut tied = Vec::new();
    for (row, resolution) in resolutions.iter().enumerate() {
        let Resolution::Ready(target) = resolution else {
            continue;
        };
        let Body::Generated(Gen::Wordcode(bytes)) = &target.body else {
            continue;
        };
        let path = target.path.as_str();
        let Some(source) = path.strip_suffix(".zwc").and_then(|file| {
            resolutions.iter().position(|resolution| {
                matches!(resolution, Resolution::Ready(target) if target.path.as_str() == file)
            })
        }) else {
            continue;
        };
        let written = ops
            .iter()
            .position(|op| op.target().as_str() == changes[source].target);
        let asked = held.iter().any(|(at, _)| *at == source);
        // Its own write, wherever the decision put it.
        let own = |ops: &mut Vec<Op>, held: &mut Vec<(usize, Op)>| {
            ops.iter()
                .position(|op| op.target().as_str() == path)
                .map(|at| ops.remove(at))
                .or_else(|| {
                    held.iter()
                        .position(|(at, _)| *at == row)
                        .map(|at| held.remove(at).1)
                })
        };
        match written {
            Some(at) => {
                if changes[row].action == Action::Unchanged {
                    ops.insert(at + 1, rewrite(target, bytes, home)?);
                    changes[row].action = Action::Modify;
                    changes[row].note =
                        join([Some(REWRITTEN.to_string()), changes[row].note.take()]);
                }
            }
            None if asked => {
                let (op, note) = match own(ops, held) {
                    Some(op) => {
                        let note = changes[row].note.take();
                        changes[row].action = Action::Conflict;
                        changes[row].note = join([Some(WAITS.to_string()), note.clone()]);
                        (op, note)
                    }
                    None if changes[row].action == Action::Unchanged => (
                        rewrite(target, bytes, home)?,
                        join([Some(REWRITTEN.to_string()), changes[row].note.clone()]),
                    ),
                    None => continue,
                };
                tied.push(Tied {
                    source,
                    row,
                    op,
                    note,
                });
            }
            None if changes[source].action == Action::Unchanged => {}
            None => {
                if own(ops, held).is_some() {
                    changes[row].action = Action::Conflict;
                    changes[row].note = join([Some(WAITS.to_string()), changes[row].note.take()]);
                }
            }
        }
    }
    Ok(tied)
}

/// The write that leaves a wordcode already holding `bytes` as it is, made
/// again after its file so it is not the older of the two.
fn rewrite(target: &Target, bytes: &[u8], home: &std::path::Path) -> Result<Op, Error> {
    let dest = target.path.render(home);
    let planned = fs::observe(&dest)?;
    Ok(Op {
        target: target.path.clone(),
        dest,
        made: Made::Bytes(bytes.to_vec()),
        planned,
        mode: Mode::resolve(target.mode, Kind::File),
        claimed: true,
        carry: false,
        base: bytes.len() <= Base::KEPT_WHOLE,
    })
}
