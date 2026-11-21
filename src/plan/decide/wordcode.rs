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
//!   it: made only for *take bx's*, right after the file's. The plan says so
//!   on the wordcode's row, which is held with its file — even where its
//!   bytes are already right and it is only rewritten — and once taken the
//!   row is the create or modify its write is. A wordcode edited since bx
//!   wrote it is a question of its own, as any such file is, which an answer
//!   of *take bx's* writes only with its file: bx never writes over it on the
//!   answer for another file.
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

/// A wordcode tied to its file, which is held for an answer: written only
/// once the file's is, right after it.
#[derive(Debug)]
pub(in crate::plan) struct Tied {
    /// The row of the file, in [`super::Decided::held`].
    pub source: usize,
    /// The wordcode's own row.
    pub row: usize,
    /// How the wordcode's write waits on its file's answer.
    tie: Tie,
}

impl Tied {
    /// Whether the wordcode is a question of its own, whose *take bx's* is
    /// made only where its file's is too.
    pub(in crate::plan) const fn asked(&self) -> bool {
        matches!(self.tie, Tie::Asked)
    }

    /// The write made right after the file's once that is taken, with the
    /// action and note the wordcode's row then carries; `None` for a
    /// wordcode that is a question of its own, whose own answer writes it.
    pub(in crate::plan) fn into_write(self) -> Option<(Op, Action, Option<String>)> {
        match self.tie {
            Tie::Write { op, action, note } => Some((*op, action, note)),
            Tie::Asked => None,
        }
    }
}

impl Op {
    /// Refuse a taken write — a file answered *take bx's*, and the wordcode
    /// written right after it — unless its destination is still what plan
    /// observed, as the session refuses it at the write itself, so a file
    /// changed while its question was open is refused before the first write.
    ///
    /// # Errors
    ///
    /// [`fs::Error::Read`] where the destination cannot be looked at, and
    /// [`fs::Error::Changed`] where it moved since plan.
    pub(in crate::plan) fn refuse_moved(&self) -> Result<(), fs::Error> {
        fs::refuse_moved(&self.planned, &fs::observe(&self.dest)?)
    }
}

/// How a [`Tied`] wordcode's write waits on its file's answer.
#[derive(Debug)]
enum Tie {
    /// Made right after the file's, once *take bx's* is answered for it.
    Write {
        /// The wordcode's write.
        op: Box<Op>,
        /// What the wordcode's row is once its write is made: the create or
        /// modify it was decided as, or a modify where it is only rewritten.
        action: Action,
        /// The note the wordcode's row carries once its write is made.
        note: Option<String>,
    },
    /// The wordcode was edited since bx wrote it and is a question of its
    /// own, held in [`super::Decided::held`]: *take bx's* for it is made only
    /// with its file's.
    Asked,
}

/// The note a wordcode's row carries when its file is not written.
pub(in crate::plan) const WAITS: &str = "written only with its file, which is not: zsh would \
                                         read it in place of what that file holds";

/// The note a wordcode's row carries when its write waits on its file's
/// answer.
pub(in crate::plan) const TIED: &str = "written right after its file only if bx's is taken \
                                        there: zsh would read it in place of what that file \
                                        holds";

/// The note an edited wordcode's row carries when its file is asked about
/// too.
pub(in crate::plan) const TAKEN_WITH: &str = "taken only with its file: zsh would read it in \
                                              place of what that file holds";

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
            // An edited wordcode stays the question it is, answered only
            // with its file's.
            None if asked && held.iter().any(|(at, _)| *at == row) => {
                changes[row].note = join([Some(TAKEN_WITH.to_string()), changes[row].note.take()]);
                tied.push(Tied {
                    source,
                    row,
                    tie: Tie::Asked,
                });
            }
            None if asked => {
                let note = changes[row].note.take();
                let tie = match own(ops, held) {
                    Some(op) => Tie::Write {
                        op: Box::new(op),
                        action: changes[row].action,
                        note: note.clone(),
                    },
                    None if changes[row].action == Action::Unchanged => Tie::Write {
                        op: Box::new(rewrite(target, bytes, home)?),
                        action: Action::Modify,
                        note: join([Some(REWRITTEN.to_string()), note.clone()]),
                    },
                    None => {
                        changes[row].note = note;
                        continue;
                    }
                };
                // Announced as held with its file, whose answer decides it.
                changes[row].action = Action::Conflict;
                changes[row].note = join([Some(TIED.to_string()), note]);
                tied.push(Tied { source, row, tie });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::shell::activation::file;
    use crate::testing::guarded_home;

    /// The activation `stub`'s file and its wordcode, as resolved targets.
    fn resolved() -> Vec<Resolution<Target>> {
        let code = file::Wordcode {
            bytes: b"code".to_vec(),
            entry: None,
        };
        let origin = Origin {
            file: std::path::PathBuf::new(),
            line: 0,
        };
        file::targets("stub", "stub_hook() { :; }\n", Some(&code), &origin)
            .into_iter()
            .map(Resolution::Ready)
            .collect()
    }

    /// The target `resolution` resolved to.
    fn ready(resolution: &Resolution<Target>) -> &Target {
        let Resolution::Ready(target) = resolution else {
            unreachable!("every row is ready")
        };
        target
    }

    /// The file's row and the wordcode's, decided as `file` and `wordcode`.
    fn rows(resolutions: &[Resolution<Target>], file: Action, wordcode: Action) -> Vec<Change> {
        [file, wordcode]
            .into_iter()
            .zip(resolutions)
            .map(|(action, resolution)| Change {
                target: ready(resolution).path.as_str().to_string(),
                origin: ready(resolution).origin.clone(),
                action,
                diff: None,
                note: None,
            })
            .collect()
    }

    #[test]
    fn a_rewritten_wordcode_is_kept_as_a_base_only_while_it_is_small_enough() {
        let home = guarded_home();
        let resolutions = resolved();
        for (len, kept) in [
            (1, true),
            (Base::KEPT_WHOLE, true),
            (Base::KEPT_WHOLE + 1, false),
        ] {
            let op =
                rewrite(ready(&resolutions[1]), &vec![b'w'; len], home.path()).expect("observed");
            assert_eq!(op.base, kept, "{len} bytes");
        }
    }

    #[test]
    fn a_held_file_ties_no_wordcode_that_is_neither_written_nor_already_right() {
        let home = guarded_home();
        let resolutions = resolved();
        let file = rewrite(ready(&resolutions[0]), b"file", home.path()).expect("observed");
        // The wordcode is a conflict of its own that nothing writes: no write
        // waits on the file's answer, and its row stays as it was decided.
        let mut changes = rows(&resolutions, Action::Conflict, Action::Conflict);
        let (mut ops, mut held) = (Vec::new(), vec![(0, file)]);
        let tied = tie(&resolutions, &mut changes, &mut ops, &mut held, home.path()).expect("tied");
        assert!(tied.is_empty(), "{tied:?}");
        assert_eq!(
            (changes[1].action, changes[1].note.as_deref()),
            (Action::Conflict, None)
        );
        assert!(ops.is_empty() && held.len() == 1);
    }

    #[test]
    fn a_wordcode_waits_on_a_file_that_is_neither_written_nor_held_nor_right() {
        let home = guarded_home();
        let resolutions = resolved();
        let own = rewrite(ready(&resolutions[1]), b"code", home.path()).expect("observed");
        // The file is a conflict with no write of its own: the wordcode's
        // write is dropped, and its row says it waits on the file.
        let mut changes = rows(&resolutions, Action::Conflict, Action::Create);
        let (mut ops, mut held) = (vec![own], Vec::new());
        let tied = tie(&resolutions, &mut changes, &mut ops, &mut held, home.path()).expect("tied");
        assert!(tied.is_empty() && ops.is_empty(), "{ops:?}");
        assert_eq!(
            (changes[1].action, changes[1].note.as_deref()),
            (Action::Conflict, Some(WAITS))
        );
    }
}
