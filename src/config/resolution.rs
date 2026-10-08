//! The vocabulary every resolved entry is reported in: ready, or held back
//! with the reason and what would clear it.
//!
//! Shared by [`super::resolve`], which produces it for targets, the shell
//! placement that produces it for fragments, functions and sources, and
//! [`super::target`], whose interactive file carries the held-back entries it
//! names. It depends on nothing but [`Origin`], so none of them reaches
//! another to name a blocked entry.

use super::Origin;

/// A configuration entry that either resolved or could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<T> {
    /// Fully substituted, ready to be written.
    Ready(T),
    /// Held back, with the reason and what would clear it.
    Blocked(BlockedEntry),
}

/// Why an entry could not be resolved.
///
/// The shared reason enum: a later reason extends it rather than introducing a
/// parallel blocked type, which is why `report::Action::Blocked` is documented
/// as "a prerequisite is absent" rather than as one specific prerequisite.
///
/// An absent tool is deliberately not a reason. A target's `requires` never
/// blocks it — its file is written on its own content and mode alone, and
/// `bx doctor` names the tool — so no variant here says a tool is missing. A
/// target whose whole content is the output of running an absent tool would
/// need one; that case is reserved, and nothing produces it yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// One or more declared values this entry references have no answer.
    UnsetValue {
        /// The values that need answering, in declaration order.
        names: Vec<String>,
    },
    /// One or more declared values this entry references are switched off.
    ///
    /// Kept apart from [`BlockReason::UnsetValue`] because the two are cleared
    /// by different acts, and a note that told an account to answer a value it
    /// has itself refused would be advice it cannot follow.
    DisabledValue {
        /// The declarations to re-enable, in declaration order.
        names: Vec<String>,
    },
    /// One or more answers in this account's layer leave this entry unusable:
    /// an answer its kind refuses, one that made a committed `default` invalid,
    /// or one that, substituted into this entry, makes a field invalid — a path
    /// that climbs out of the home, a `file` that climbs out of the repo, an
    /// owned key with an empty segment or with more or fewer segments than
    /// written — or a `file` that reaches a `path` value through an answer.
    ///
    /// Kept apart from [`BlockReason::UnsetValue`] because nothing is
    /// unanswered: every answer the entry needs is written, and one of them is
    /// the account's to change. They share one variant because they share that
    /// cause, not because one act clears them all: which answer to change, and
    /// whether changing one is the whole act, is [`BlockedEntry::hint`]'s to
    /// say. A clash holding a toggle bx cannot show names a declared target is
    /// cleared by removing that toggle first, and by an answer only for the
    /// statements the removal leaves — so the hint may name one of these
    /// values, or none of them.
    InvalidValue {
        /// The answers this block was made of, in declaration order: the
        /// declarations whose text is invalid, the answers that went into the
        /// invalid field, or every answer that made a layer's clashing
        /// spellings meet. The cause, which a report may name as the entry's;
        /// the instruction is the hint.
        names: Vec<String>,
    },
}

/// An entry that was held back, and what it would take to release it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedEntry {
    /// The entry's natural key, so a report can name it.
    pub key: String,
    /// Where the entry was declared.
    pub origin: Origin,
    /// Why it is blocked.
    pub reason: BlockReason,
    /// What the user should do. Spelled in `values` — `init_hint`,
    /// `disabled_hint`, `path_answer_hint`, `ResolvedValues::invalid_hint`,
    /// `ResolvedValues::answers_hint` or `ResolvedValues::removal_hint` — never
    /// at a call site.
    pub hint: String,
}
