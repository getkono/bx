//! The crash seam: the boundaries a session crosses, and, in the test build
//! only, a process that stops existing at the one `BX_CRASH_AT` names.

/// The boundaries [`Session::apply`](super::Session::apply) and [`Session::finish`](super::Session::finish) cross, named so a
/// test can stop at one.
///
/// Six in `apply`, and each is a real durability boundary rather than a
/// convenient line: before anything exists; after the intent is durable and
/// before anything it names is made; after a temporary file exists at its
/// final mode but holds nothing; after its content is `fsync`ed but the
/// destination is untouched; after the destination is replaced; after the
/// completion is durable. Two in `finish`, where every
/// write has landed: after the `End` frame is durable and before the claimed
/// directories are pruned, and after the ledger is saved. A `finish` boundary
/// is reached with the number of writes as its index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    BeforeStage,
    AfterIntent,
    AfterStage,
    AfterFill,
    AfterPublish,
    AfterDone,
    AfterEnd,
    AfterSave,
}

/// Every phase of a write, in the order [`Session::apply`](super::Session::apply) passes them.
#[cfg(test)]
pub(super) const PHASES: [Phase; 6] = [
    Phase::BeforeStage,
    Phase::AfterIntent,
    Phase::AfterStage,
    Phase::AfterFill,
    Phase::AfterPublish,
    Phase::AfterDone,
];

/// Every phase of [`Session::finish`](super::Session::finish), in the order it passes them.
#[cfg(test)]
pub(super) const FINISH_PHASES: [Phase; 2] = [Phase::AfterEnd, Phase::AfterSave];

/// The environment variable a test child reads to choose where to stop.
#[cfg(test)]
const CRASH_AT: &str = "BX_CRASH_AT";

/// The crash seam: where, if anywhere, this process is to stop existing.
///
/// The field is `cfg(test)`-gated, so outside a test build this is a zero-sized
/// value whose [`Crash::reached`] compiles to nothing. No shipped binary can
/// read `BX_CRASH_AT` and no shipped binary can abort itself; the only process
/// that can honour the variable is a test binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Crash {
    #[cfg(test)]
    at: Option<(usize, Phase)>,
}

impl Crash {
    /// Read `BX_CRASH_AT` once, at [`Session::open`](super::Session::open).
    ///
    /// The format is `<intent-index>:<phase>`; anything else is ignored, so a
    /// stray value cannot silently turn into "crash somewhere else".
    pub(super) fn from_env() -> Self {
        Self {
            #[cfg(test)]
            at: std::env::var(CRASH_AT)
                .ok()
                .as_deref()
                .and_then(Self::parse),
        }
    }

    /// Stop existing, if this is the chosen boundary.
    ///
    /// `abort` rather than `panic` or `exit`: it terminates without unwinding,
    /// without running a destructor, and without flushing a buffer, which is
    /// what a crash does and what an `Err` return does not.
    pub(super) fn reached(self, index: usize, phase: Phase) {
        #[cfg(test)]
        if self.at == Some((index, phase)) {
            std::process::abort();
        }
        #[cfg(not(test))]
        let _ = (self, index, phase);
    }

    /// Parse `<intent-index>:<phase>`, where the phase is a [`Crash::name`].
    #[cfg(test)]
    fn parse(raw: &str) -> Option<(usize, Phase)> {
        let (index, phase) = raw.split_once(':')?;
        let index = index.parse().ok()?;
        let phase = PHASES
            .iter()
            .chain(&FINISH_PHASES)
            .copied()
            .find(|candidate| Self::name(*candidate) == phase)?;
        Some((index, phase))
    }

    /// The spelling of one phase.
    #[cfg(test)]
    pub(super) fn name(phase: Phase) -> &'static str {
        match phase {
            Phase::BeforeStage => "before-stage",
            Phase::AfterStage => "after-stage",
            Phase::AfterFill => "after-fill",
            Phase::AfterIntent => "after-intent",
            Phase::AfterPublish => "after-publish",
            Phase::AfterDone => "after-done",
            Phase::AfterEnd => "after-end",
            Phase::AfterSave => "after-save",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::journal::tests::{crash_phases, finish_crash_phases};

    #[test]
    fn a_crash_point_round_trips_through_its_spelling() {
        // The spellings are the seam's whole interface: the harness that drives
        // it passes `<index>:<phase>` to a child process, so a rename that broke
        // this would make the harness silently stop crashing anything.
        for (index, phase) in crash_phases().iter().enumerate() {
            assert_eq!(
                Crash::parse(&format!("{index}:{phase}")),
                Some((index, PHASES[index])),
            );
        }
        for (index, phase) in finish_crash_phases().iter().enumerate() {
            assert_eq!(
                Crash::parse(&format!("{index}:{phase}")),
                Some((index, FINISH_PHASES[index])),
            );
        }
        assert_eq!(Crash::parse("not a crash point"), None);
        assert_eq!(Crash::parse("0:no-such-phase"), None);
        assert_eq!(Crash::parse("x:after-fill"), None);
        // Nothing set this process's variable, so a session here never aborts.
        assert_eq!(Crash::from_env(), Crash { at: None });
    }
}
