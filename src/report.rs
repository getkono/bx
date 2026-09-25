//! The vocabulary `plan` and `apply` share.
//!
//! `plan` and `apply` compute the same actions with the same function; `apply`
//! must never do work `plan` did not announce. That makes the set of things an
//! action can *be* a contract rather than a rendering detail, so it lives here
//! with its symbols and its exit codes.
//!
//! Note what is missing: there is no "destroy". bx is additive-only, so nothing
//! it plans can remove a user's file. The slot a declarative tool would spend on
//! destruction is spent instead on [`Action::Conflict`] — the case that actually
//! matters for a non-invasive tool, where something bx does not own is in the
//! way.

use std::fmt;

/// What `apply` would do to one target.
///
/// The declaration order is load-bearing: `Ord` is derived from it, and the
/// variants are declared in increasing order of how much a human has to do
/// about them. Reordering them silently reorders any sorted plan output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Already converged. Hidden unless the user asks for detail.
    Unchanged,
    /// bx wrote this file, the ledger still owns it, and no enabled target
    /// declares it any more: its `[[target]]` was deleted or switched off, or
    /// the repo file a `tree` mirrored was removed.
    ///
    /// Reported and left alone. Nothing is written and nothing is deleted —
    /// bx is additive-only — so the row names `bx rm` as the way to release
    /// the file, and it stays until the user runs it. Not pending work and not
    /// a decision bx is waiting on, so `apply` twice still converges. A file
    /// that has drifted from what bx wrote is reported as a
    /// [`Action::Conflict`] instead, as drift is for a declared target.
    Undeclared,
    /// The target does not exist and will be created.
    Create,
    /// bx owns the target and its content differs; it will be updated.
    Modify,
    /// The target exists, differs, and bx does not own it — or bx owns it but
    /// the user has since edited it. Reported and skipped, never overwritten.
    Conflict,
    /// A prerequisite this target needs is absent: a missing tool, or a declared
    /// value this account has not answered. Reported and skipped until the user
    /// supplies it, while every other target is applied.
    ///
    /// There are two producers, and they share one reason enum —
    /// [`config::resolve::BlockReason`](crate::config::resolve::BlockReason) —
    /// so a later entry extends it rather than introducing a parallel blocked
    /// state.
    ///
    /// An **unanswered value** blocks the targets that reference it and nothing
    /// else. That is deliberate and is the difference between bx and the
    /// source material it replaces, where a single missing account file makes
    /// the whole apply exit 1. The blocked entry names the values and the
    /// `bx init` invocation that sets them, so the report is actionable.
    ///
    /// An **absent tool** is produced from [`crate::detect::Presence::is_usable`].
    /// It matters most
    /// where a tool is configured entirely by environment and bx's output is a
    /// shell fragment naming a binary: writing `RUSTC_WRAPPER=/usr/bin/sccache`
    /// when sccache is absent does not degrade gracefully, it breaks every
    /// `cargo build` on the machine. [`env_guard`](crate::env_guard) cannot
    /// catch that — it checks where a value points, never whether what it
    /// points at exists, which is a question only the filesystem can answer.
    Blocked,
}

impl Action {
    /// The single character that prefixes this action in `plan` output.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Self::Unchanged => '=',
            Self::Undeclared => '*',
            Self::Create => '+',
            Self::Modify => '~',
            Self::Conflict => '!',
            Self::Blocked => '?',
        }
    }

    /// Whether this action means `apply` has work to do.
    ///
    /// Neither a conflict nor a blocked target is pending work: bx will skip
    /// both, and they stay reported until the user resolves the conflict or
    /// installs the tool. Counting them as pending would make `plan` signal
    /// "changes waiting" forever.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Create | Self::Modify)
    }

    /// Whether this action needs the user to do something before bx can
    /// converge: resolve a conflict, or install a missing tool.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::Conflict | Self::Blocked)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            Self::Unchanged => "unchanged",
            Self::Undeclared => "undeclared",
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Conflict => "conflict",
            Self::Blocked => "blocked",
        };
        write!(f, "{word}")
    }
}

/// Process exit status, following `diff` and `terraform plan -detailed-exitcode`.
///
/// The point is that `plan` is usable from CI, a prompt segment, or a motd
/// without anyone parsing its text output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Converged: nothing to do.
    Converged = 0,
    /// Something went wrong.
    Error = 1,
    /// Changes are pending, or a conflict or blocked target needs a decision.
    Pending = 2,
}

impl Exit {
    /// The process exit code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// The status a set of actions implies.
    ///
    /// Conflicts and blocked targets count as pending here even though they
    /// are not pending *work*: the machine is not converged and a human has to
    /// look at it, which is exactly what a non-zero exit is for.
    #[must_use]
    pub fn from_actions(actions: &[Action]) -> Self {
        let unresolved = actions
            .iter()
            .any(|a| a.is_pending() || a.needs_attention());
        if unresolved {
            Self::Pending
        } else {
            Self::Converged
        }
    }
}

/// A one-line tally, rendered as the last line of `plan`.
///
/// [`Action::Undeclared`] is counted only when there is one, so the line a
/// configuration with nothing undeclared prints is the one it always printed.
#[must_use]
pub fn summary(actions: &[Action]) -> String {
    let count = |want: Action| actions.iter().filter(|a| **a == want).count();
    let undeclared = match count(Action::Undeclared) {
        0 => String::new(),
        n => format!(" {n} undeclared,"),
    };
    format!(
        "Plan: {} to create, {} to modify, {} conflict, {} blocked,{undeclared} {} unchanged.",
        count(Action::Create),
        count(Action::Modify),
        count(Action::Conflict),
        count(Action::Blocked),
        count(Action::Unchanged),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_has_a_distinct_symbol() {
        let all = [
            Action::Unchanged,
            Action::Undeclared,
            Action::Create,
            Action::Modify,
            Action::Conflict,
            Action::Blocked,
        ];
        let mut symbols: Vec<char> = all.iter().map(|a| a.symbol()).collect();
        symbols.sort_unstable();
        symbols.dedup();
        assert_eq!(symbols.len(), all.len());
    }

    #[test]
    fn symbols_are_the_documented_ones() {
        assert_eq!(Action::Create.symbol(), '+');
        assert_eq!(Action::Modify.symbol(), '~');
        assert_eq!(Action::Conflict.symbol(), '!');
        assert_eq!(Action::Blocked.symbol(), '?');
        assert_eq!(Action::Unchanged.symbol(), '=');
        assert_eq!(Action::Undeclared.symbol(), '*');
    }

    #[test]
    fn only_create_and_modify_are_pending_work() {
        assert!(Action::Create.is_pending());
        assert!(Action::Modify.is_pending());
        assert!(!Action::Conflict.is_pending());
        assert!(!Action::Blocked.is_pending());
        assert!(!Action::Unchanged.is_pending());
        assert!(!Action::Undeclared.is_pending());
    }

    #[test]
    fn conflicts_and_blocked_targets_need_a_decision() {
        assert!(Action::Conflict.needs_attention());
        assert!(Action::Blocked.needs_attention());
        for a in [
            Action::Create,
            Action::Modify,
            Action::Unchanged,
            Action::Undeclared,
        ] {
            assert!(!a.needs_attention(), "{a} should not need attention");
        }
    }

    #[test]
    fn actions_order_by_how_much_a_human_must_do() {
        // `Ord` is derived from the declaration order, so this pins it: a
        // reordering that looks cosmetic would resort plan output.
        let mut actions = [
            Action::Blocked,
            Action::Create,
            Action::Unchanged,
            Action::Conflict,
            Action::Undeclared,
            Action::Modify,
        ];
        actions.sort_unstable();
        assert_eq!(
            actions,
            [
                Action::Unchanged,
                Action::Undeclared,
                Action::Create,
                Action::Modify,
                Action::Conflict,
                Action::Blocked,
            ]
        );
    }

    #[test]
    fn actions_render_as_words() {
        assert_eq!(Action::Conflict.to_string(), "conflict");
        assert_eq!(Action::Blocked.to_string(), "blocked");
        assert_eq!(Action::Unchanged.to_string(), "unchanged");
        assert_eq!(Action::Create.to_string(), "create");
        assert_eq!(Action::Modify.to_string(), "modify");
        assert_eq!(Action::Undeclared.to_string(), "undeclared");
    }

    #[test]
    fn exit_codes_follow_the_diff_convention() {
        assert_eq!(Exit::Converged.code(), 0);
        assert_eq!(Exit::Error.code(), 1);
        assert_eq!(Exit::Pending.code(), 2);
    }

    #[test]
    fn nothing_to_do_exits_zero() {
        assert_eq!(Exit::from_actions(&[]), Exit::Converged);
        assert_eq!(
            Exit::from_actions(&[Action::Unchanged, Action::Unchanged]),
            Exit::Converged
        );
    }

    #[test]
    fn an_undeclared_file_alone_exits_zero() {
        // bx will never act on it and nothing is wrong with it: `apply` twice
        // must still converge while the user decides whether to `bx rm` it.
        assert_eq!(
            Exit::from_actions(&[Action::Unchanged, Action::Undeclared]),
            Exit::Converged
        );
    }

    #[test]
    fn pending_work_exits_two() {
        assert_eq!(
            Exit::from_actions(&[Action::Unchanged, Action::Create]),
            Exit::Pending
        );
        assert_eq!(Exit::from_actions(&[Action::Modify]), Exit::Pending);
    }

    #[test]
    fn a_conflict_alone_exits_two() {
        // apply will skip it, but the machine is not converged and someone has
        // to look — which is what a non-zero exit is for.
        assert_eq!(Exit::from_actions(&[Action::Conflict]), Exit::Pending);
    }

    #[test]
    fn a_blocked_target_alone_exits_two() {
        // Same reasoning as a conflict: apply skips it, but the machine is not
        // converged until someone installs the tool.
        assert_eq!(Exit::from_actions(&[Action::Blocked]), Exit::Pending);
        assert_eq!(
            Exit::from_actions(&[Action::Unchanged, Action::Blocked]),
            Exit::Pending
        );
    }

    #[test]
    fn the_summary_counts_every_category() {
        let actions = [
            Action::Create,
            Action::Create,
            Action::Modify,
            Action::Conflict,
            Action::Blocked,
            Action::Unchanged,
            Action::Unchanged,
            Action::Unchanged,
        ];
        assert_eq!(
            summary(&actions),
            "Plan: 2 to create, 1 to modify, 1 conflict, 1 blocked, 3 unchanged."
        );
    }

    #[test]
    fn the_summary_counts_undeclared_files_only_when_there_are_some() {
        assert_eq!(
            summary(&[Action::Undeclared, Action::Undeclared, Action::Unchanged]),
            "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 2 undeclared, 1 unchanged."
        );
    }

    #[test]
    fn an_empty_plan_still_summarises() {
        assert_eq!(
            summary(&[]),
            "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged."
        );
    }
}
