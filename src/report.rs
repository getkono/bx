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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Already converged. Hidden unless the user asks for detail.
    Unchanged,
    /// The target does not exist and will be created.
    Create,
    /// bx owns the target and its content differs; it will be updated.
    Modify,
    /// The target exists, differs, and bx does not own it — or bx owns it but
    /// the user has since edited it. Reported and skipped, never overwritten.
    Conflict,
}

impl Action {
    /// The single character that prefixes this action in `plan` output.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Self::Unchanged => '=',
            Self::Create => '+',
            Self::Modify => '~',
            Self::Conflict => '!',
        }
    }

    /// Whether this action means `apply` has work to do.
    ///
    /// A conflict is *not* pending work: bx will skip it, and it stays reported
    /// until the user resolves it. Counting it as pending would make `plan`
    /// signal "changes waiting" forever.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Create | Self::Modify)
    }

    /// Whether this action needs the user to decide something.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::Conflict)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            Self::Unchanged => "unchanged",
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Conflict => "conflict",
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
    /// Changes are pending, or a conflict needs a decision.
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
    /// Conflicts count as pending here even though they are not pending *work*:
    /// the machine is not converged and a human has to look at it, which is
    /// exactly what a non-zero exit is for.
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
#[must_use]
pub fn summary(actions: &[Action]) -> String {
    let count = |want: Action| actions.iter().filter(|a| **a == want).count();
    format!(
        "Plan: {} to create, {} to modify, {} conflict, {} unchanged.",
        count(Action::Create),
        count(Action::Modify),
        count(Action::Conflict),
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
            Action::Create,
            Action::Modify,
            Action::Conflict,
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
        assert_eq!(Action::Unchanged.symbol(), '=');
    }

    #[test]
    fn only_create_and_modify_are_pending_work() {
        assert!(Action::Create.is_pending());
        assert!(Action::Modify.is_pending());
        assert!(!Action::Conflict.is_pending());
        assert!(!Action::Unchanged.is_pending());
    }

    #[test]
    fn only_a_conflict_needs_a_decision() {
        assert!(Action::Conflict.needs_attention());
        for a in [Action::Create, Action::Modify, Action::Unchanged] {
            assert!(!a.needs_attention(), "{a} should not need attention");
        }
    }

    #[test]
    fn actions_render_as_words() {
        assert_eq!(Action::Conflict.to_string(), "conflict");
        assert_eq!(Action::Unchanged.to_string(), "unchanged");
        assert_eq!(Action::Create.to_string(), "create");
        assert_eq!(Action::Modify.to_string(), "modify");
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
    fn the_summary_counts_every_category() {
        let actions = [
            Action::Create,
            Action::Create,
            Action::Modify,
            Action::Conflict,
            Action::Unchanged,
            Action::Unchanged,
            Action::Unchanged,
        ];
        assert_eq!(
            summary(&actions),
            "Plan: 2 to create, 1 to modify, 1 conflict, 3 unchanged."
        );
    }

    #[test]
    fn an_empty_plan_still_summarises() {
        assert_eq!(
            summary(&[]),
            "Plan: 0 to create, 0 to modify, 0 conflict, 0 unchanged."
        );
    }
}
