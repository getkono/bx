//! `bx doctor`: what a human should look at, found without changing anything.
//!
//! Doctor reads the same resolved targets `plan` decides ([`Inputs::targets`])
//! and asks read-only questions about them. It writes nothing, takes no lock,
//! and never runs anything that could install, start or modify something: a
//! command that would clear a finding is printed in its note, never run.
//!
//! Every check reports in a fixed order, and each one in configuration order,
//! so two runs over an unchanged machine print the same bytes. Any finding at
//! all exits [`Exit::Pending`]; none exits [`Exit::Converged`]. A check that
//! cannot ask what it needs is a finding, not an error.
//!
//! The checks, in order:
//!
//! 1. [`systemd`] — a declared unit file systemd has not reloaded, that is not
//!    enabled, that it could not load, or that has failed.

pub mod systemd;

use std::fmt::Write as _;
use std::path::Path;

use crate::config::Origin;
use crate::paths;
use crate::plan::{Inputs, escape};
use crate::report::Exit;

/// One thing worth a human's attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// What it is about: a target, spelled portably, or a named subsystem.
    pub subject: String,
    /// Where the subject was declared, when it was.
    pub origin: Option<Origin>,
    /// What is wrong, and what would clear it.
    pub note: String,
}

/// Everything one run found, in the order it is printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Every finding, check by check.
    pub findings: Vec<Finding>,
}

/// What the checks ask the machine through.
pub struct Probes<'a> {
    /// The systemd user unit directory.
    pub unit_dir: &'a Path,
    /// The question put to the user's systemd.
    pub systemd: &'a dyn systemd::Query,
}

/// Run every check against `inputs`.
#[must_use]
pub fn run(inputs: &Inputs, probes: &Probes<'_>) -> Report {
    let units = systemd::units(inputs.targets(), inputs.home(), probes.unit_dir);
    Report {
        findings: systemd::check(&units, probes.systemd),
    }
}

/// The text `bx doctor` prints: one line per finding, then a tally.
///
/// A finding reads like a `plan` row — `  ! {subject}  ({origin}) {note}` — so
/// the two outputs point at a declaration the same way.
#[must_use]
pub fn render(report: &Report, home: &Path) -> String {
    let mut out = String::new();
    for finding in &report.findings {
        let _ = write!(out, "  ! {}", escape(&finding.subject));
        if let Some(origin) = &finding.origin {
            let _ = write!(
                out,
                "  ({}:{})",
                escape(&paths::to_portable(&origin.file, home)),
                origin.line
            );
        }
        let _ = writeln!(out, " {}", escape(&finding.note));
    }
    let _ = writeln!(out, "Doctor: {} finding(s).", report.findings.len());
    out
}

/// The process status a report implies: pending on any finding at all.
#[must_use]
pub fn exit(report: &Report) -> Exit {
    if report.findings.is_empty() {
        Exit::Converged
    } else {
        Exit::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;

    use super::systemd::{Query, State, Unreachable};
    use super::*;
    use crate::plan::tests::inputs;
    use crate::testing::guarded_home;

    /// A systemd that answers every unit with one state, and counts questions.
    struct Every {
        state: Option<State>,
        asked: Cell<usize>,
    }

    impl Every {
        fn unit(state: State) -> Self {
            Self {
                state: Some(state),
                asked: Cell::new(0),
            }
        }

        fn unreachable() -> Self {
            Self {
                state: None,
                asked: Cell::new(0),
            }
        }
    }

    impl Query for Every {
        fn show(&self, names: &[String]) -> Result<Vec<State>, Unreachable> {
            self.asked.set(self.asked.get() + 1);
            self.state.as_ref().map_or_else(
                || Err(Unreachable("Failed to connect to bus".to_string())),
                |state| Ok(vec![state.clone(); names.len()]),
            )
        }
    }

    fn disabled() -> State {
        State {
            load: "loaded".into(),
            active: "inactive".into(),
            file: "disabled".into(),
            need_reload: false,
        }
    }

    const TWO_UNITS: &str = "\
[[target]]
path = \"~/.config/systemd/user/a.service\"
content = \"[Service]\\n\"

[[target]]
path = \"~/.config/systemd/user/b.timer\"
content = \"[Timer]\\n\"

[[target]]
path = \"~/.a\"
content = \"a\\n\"
";

    fn doctor(home: &crate::testing::GuardedHome, systemd: &dyn Query) -> (String, Exit) {
        let inputs = inputs(home, TWO_UNITS);
        let unit_dir = paths::systemd_user_dir_in(home.path(), None);
        let report = run(
            &inputs,
            &Probes {
                unit_dir: &unit_dir,
                systemd,
            },
        );
        (render(&report, home.path()), exit(&report))
    }

    #[test]
    fn declared_units_not_yet_written_produce_nothing_and_ask_nothing() {
        let home = guarded_home();
        let systemd = Every::unreachable();

        let (out, code) = doctor(&home, &systemd);

        assert_eq!(out, "Doctor: 0 finding(s).\n");
        assert_eq!(code, Exit::Converged);
        assert_eq!(systemd.asked.get(), 0);
    }

    #[test]
    fn written_units_are_checked_in_configuration_order_and_deterministically() {
        let home = guarded_home();
        home.write(".config/systemd/user/b.timer", "[Timer]\n");
        home.write(".config/systemd/user/a.service", "[Service]\n");
        home.write(".a", "a\n");
        let systemd = Every::unit(disabled());

        let (first, code) = doctor(&home, &systemd);
        let (second, _) = doctor(&home, &systemd);

        assert_eq!(
            first,
            "  ! ~/.config/systemd/user/a.service  (~/.config/bx/bx.toml:1) is written but not \
             enabled; `systemctl --user enable a.service` enables it\n  ! \
             ~/.config/systemd/user/b.timer  (~/.config/bx/bx.toml:5) is written but not \
             enabled; `systemctl --user enable b.timer` enables it\nDoctor: 2 finding(s).\n"
        );
        assert_eq!(code, Exit::Pending);
        assert_eq!(first, second, "two runs print the same bytes");
        assert_eq!(systemd.asked.get(), 2, "one question per run");
    }

    #[test]
    fn an_unreachable_session_is_one_pending_finding() {
        let home = guarded_home();
        home.write(".config/systemd/user/b.timer", "[Timer]\n");
        home.write(".config/systemd/user/a.service", "[Service]\n");

        let (out, code) = doctor(&home, &Every::unreachable());

        assert_eq!(
            out,
            "  ! systemd --user is unreachable, so 2 unit file(s) went unchecked: Failed to \
             connect to bus\nDoctor: 1 finding(s).\n"
        );
        assert_eq!(code, Exit::Pending, "pending, not an error");
    }

    #[test]
    fn a_control_character_cannot_reach_the_terminal() {
        let report = Report {
            findings: vec![Finding {
                subject: "systemd\x1b[2J".to_string(),
                origin: Some(Origin {
                    file: PathBuf::from("/elsewhere/bx.toml"),
                    line: 7,
                }),
                note: "said\r\nno".to_string(),
            }],
        };

        assert_eq!(
            render(&report, Path::new("/var/home/example")),
            "  ! systemd\\x1b[2J  (/elsewhere/bx.toml:7) said\\r\\nno\nDoctor: 1 finding(s).\n"
        );
    }
}
