//! `bx doctor`: what a human should look at, found without changing anything.
//!
//! Doctor reads the same resolved targets `plan` decides ([`Inputs::targets`])
//! and asks read-only questions about them. It writes nothing, takes no lock,
//! and never runs anything that could install, start or modify something: a
//! command that would clear a finding is printed in its note, never run.
//!
//! Every check reports in a fixed order, and each one in configuration order,
//! so two runs over an unchanged machine print the same bytes. Any finding at
//! all exits [`Exit::Pending`]; none exits [`Exit::Converged`]. There is no
//! severity: a finding is something to look at, whichever check found it. A
//! check that cannot ask what it needs is a finding, not an error.
//!
//! Doctor takes no exclusive lock and writes nothing under the state directory
//! or the home, so it runs beside an `apply` that holds the lock. It starts no
//! process but the one read-only `systemctl --user show` [`systemd`] builds.
//!
//! The checks, in order:
//!
//! 1. [`tools`] — a declared tool that is not an executable on `PATH`, with
//!    its `install` command quoted, never run.
//! 2. [`values`] — a required declared value with no answer.
//! 3. [`state`] — a state file that is damaged, unreadable, not a regular
//!    file, or set aside as damaged and still standing.
//! 4. [`state`] — a session an `apply` or `rm` left interrupted, or an
//!    `apply` running now.
//! 5. [`modes`] — a directory whose mode is wider than a file declared in it.
//! 6. [`sources`] — a declared optional source whose file is not readable.
//! 7. [`systemd`] — a declared unit file systemd has not reloaded, that is not
//!    enabled, that it could not load, or that has failed.

pub mod modes;
pub mod sources;
pub mod state;
pub mod systemd;
pub mod tools;
pub mod values;

use std::ffi::OsStr;
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
    /// The `PATH` a declared tool is looked for along.
    pub path: &'a OsStr,
    /// The systemd user unit directory.
    pub unit_dir: &'a Path,
    /// The question put to the user's systemd.
    pub systemd: &'a dyn systemd::Query,
}

/// Run every check against `inputs`, in the order the module lists them.
#[must_use]
pub fn run(inputs: &Inputs, probes: &Probes<'_>) -> Report {
    let home = inputs.home();
    let resolved = inputs.resolved();
    let state = state::check(inputs.state(), home);
    let units = systemd::units(inputs.targets(), home, probes.unit_dir);

    let mut findings = tools::check(&resolved.tools, probes.path, home);
    findings.extend(values::check(&resolved.values));
    findings.extend(state.damage);
    findings.extend(state.session);
    findings.extend(modes::check(inputs.targets(), home));
    findings.extend(sources::check(inputs.targets(), home, &sources::readable));
    findings.extend(systemd::check(&units, probes.systemd));
    Report { findings }
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
                path: OsStr::new(""),
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

    /// A machine with one thing for every check to find, in the order the
    /// checks run — each declared out of that order, so the output's order is
    /// the checks' and not the file's.
    const EVERY_CHECK: &str = "\
[[target]]
path = \"~/.config/systemd/user/a.service\"
content = \"[Service]\\n\"

[[source]]
name = \"keychain\"
path = \"~/.keychain/host-sh\"

[[target]]
path = \"~/.ssh/config\"
content = \"Host *\\n\"
mode = \"0600\"

[[value]]
name = \"email\"
kind = \"email\"
required = true

[[tool]]
name = \"bx-no-such-tool\"
install = \"sudo dnf install bx-no-such-tool\"
";

    /// Run doctor over `layer` in `home`, looking for tools along `path`.
    fn doctor_of(
        home: &crate::testing::GuardedHome,
        layer: &str,
        path: &OsStr,
        systemd: &dyn Query,
    ) -> (String, Exit) {
        let inputs = inputs(home, layer);
        let unit_dir = paths::systemd_user_dir_in(home.path(), None);
        let report = run(
            &inputs,
            &Probes {
                path,
                unit_dir: &unit_dir,
                systemd,
            },
        );
        (render(&report, home.path()), exit(&report))
    }

    /// Leave `~/.ssh/config` written at `0600` in a `0755` `~/.ssh`, and the
    /// unit file written.
    fn plant_files(home: &crate::testing::GuardedHome) {
        use std::os::unix::fs::PermissionsExt as _;

        let config = home.write(".ssh/config", "Host *\n");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(home.child(".ssh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        home.write(".config/systemd/user/a.service", "[Service]\n");
    }

    /// Leave a session that wrote `~/.ssh/config` and died before finishing.
    fn interrupt(home: &Path) {
        use crate::journal::{Content, Ownership, Request, Session, SessionKind};
        use crate::paths::Portable;
        use crate::state::{Mechanism, StateDir};

        let state = StateDir::resolve(home);
        let target = Portable::parse_in("~/.ssh/config", home).unwrap();
        let dest = home.join(".ssh/config");
        let planned = crate::fs::observe(&dest).unwrap();
        let mut session =
            Session::open(&state, SessionKind::Apply, home, vec![target.clone()]).unwrap();
        session
            .apply(Request {
                target,
                dest,
                content: Content::Bytes {
                    bytes: b"Host *\n".to_vec(),
                    planned,
                },
                mode: crate::fs::Mode::PRIVATE_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .unwrap();
        drop(session);
    }

    #[test]
    fn every_check_reports_in_its_fixed_order_and_twice_the_same() {
        let home = guarded_home();
        plant_files(&home);
        let state = crate::state::StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        std::fs::write(state.fingerprints(), b"not MessagePack").unwrap();
        interrupt(home.path());
        let systemd = Every::unit(disabled());

        let (first, code) = doctor_of(&home, EVERY_CHECK, OsStr::new(""), &systemd);
        let (second, _) = doctor_of(&home, EVERY_CHECK, OsStr::new(""), &systemd);

        assert_eq!(
            first,
            "  ! tool bx-no-such-tool  (~/.config/bx/bx.toml:19) is not on PATH; `sudo dnf \
             install bx-no-such-tool` installs it\n\
             \x20 ! value email  (~/.config/bx/bx.toml:14) is required and has no answer; run \
             `bx init` to set email\n\
             \x20 ! ~/.local/state/bx/fingerprints.mpk is damaged: it is not valid MessagePack; \
             it is a cache, and the next `bx apply` sets it aside and rebuilds it\n\
             \x20 ! ~/.local/state/bx/journal.mpk records an interrupted apply session of 1 \
             write(s) that stopped before it finished; the next `bx apply` rolls it back; `bx \
             plan` shows what it would do\n\
             \x20 ! ~/.ssh/config  (~/.config/bx/bx.toml:9) ~/.ssh is 0755, wider than the 0600 \
             this file declares; `chmod 0711 ~/.ssh` narrows it\n\
             \x20 ! source keychain  (~/.config/bx/bx.toml:5) ~/.keychain/host-sh is not \
             readable, so the shell skips the line that sources it\n\
             \x20 ! ~/.config/systemd/user/a.service  (~/.config/bx/bx.toml:1) is written but \
             not enabled; `systemctl --user enable a.service` enables it\n\
             Doctor: 7 finding(s).\n"
        );
        assert_eq!(code, Exit::Pending);
        assert_eq!(first, second, "two runs print the same bytes");
    }

    #[test]
    fn an_interrupted_write_recovery_cannot_account_for_is_named_on_its_own() {
        let home = guarded_home();
        plant_files(&home);
        interrupt(home.path());
        // Somebody else's bytes, since the session died: recovery will not
        // roll back over them.
        home.write(".ssh/config", "the user's edit\n");

        let (out, _) = doctor_of(&home, "", OsStr::new(""), &Every::unreachable());

        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(
            lines[0].ends_with(
                "the next `bx apply` rolls it back, once 1 write(s) recovery cannot account for \
                 are resolved by hand; `bx plan` shows what it would do"
            ),
            "{out}"
        );
        assert!(lines[1].starts_with("  ! ~/.ssh/config "), "{out}");
    }

    #[test]
    fn a_converged_installed_answered_machine_has_no_findings() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = guarded_home();
        let bin = home.write("bin/bx-no-such-tool", "#!/bin/sh\n");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        plant_files(&home);
        std::fs::set_permissions(home.child(".ssh"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        home.write(".keychain/host-sh", "");
        seed_local(home.path(), "[values]\nemail = \"a@example.com\"\n");
        let enabled = State {
            file: "enabled".into(),
            active: "active".into(),
            ..disabled()
        };

        let (out, code) = doctor_of(
            &home,
            EVERY_CHECK,
            home.child("bin").as_os_str(),
            &Every::unit(enabled),
        );

        assert_eq!(out, "Doctor: 0 finding(s).\n");
        assert_eq!(code, Exit::Converged);
    }

    /// Write `text` as this account's `local.toml`.
    fn seed_local(home: &Path, text: &str) {
        let state = crate::state::StateDir::resolve(home);
        std::fs::create_dir_all(state.root()).unwrap();
        std::fs::write(state.local_toml(), text).unwrap();
    }

    #[test]
    fn doctor_writes_nothing_and_runs_beside_a_held_lock() {
        let home = guarded_home();
        plant_files(&home);
        let state = crate::state::StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        // Damage doctor must leave where it is: a writing run would set it
        // aside.
        std::fs::write(state.ledger(), b"not MessagePack").unwrap();
        let held = crate::state::ExclusiveLock::acquire(&state).unwrap();
        crate::plan::tests::seed(home.path(), EVERY_CHECK);
        let before = crate::plan::tests::snapshot(home.path(), &[]);

        let (out, code) = doctor_of(&home, EVERY_CHECK, OsStr::new(""), &Every::unreachable());

        assert_eq!(crate::plan::tests::snapshot(home.path(), &[]), before);
        assert!(
            out.contains(
                "  ! bx apply is running now, so doctor cannot tell its journal from an \
                 interrupted one; run `bx doctor` again once it finishes\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("  ! ~/.local/state/bx/ledger.mpk is damaged: it is not valid"),
            "{out}"
        );
        assert_eq!(code, Exit::Pending);
        drop(held);
    }

    #[test]
    fn a_set_aside_state_file_is_named_until_a_human_moves_it() {
        let home = guarded_home();
        let state = crate::state::StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        std::fs::write(state.root().join("ledger.mpk.corrupt"), b"old").unwrap();

        let (out, _) = doctor_of(&home, "", OsStr::new(""), &Every::unreachable());

        assert_eq!(
            out,
            "  ! ~/.local/state/bx/ledger.mpk.corrupt is a damaged state file bx set aside, and \
             bx never deletes one; look at it, then move it out of the state directory\n\
             Doctor: 1 finding(s).\n"
        );
    }

    #[test]
    fn a_set_aside_journal_is_named_as_well() {
        let home = guarded_home();
        let state = crate::state::StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        std::fs::write(state.root().join("journal.mpk.corrupt"), b"old").unwrap();
        std::fs::write(state.root().join("journal.mpk.corrupt.1"), b"older").unwrap();

        let (out, code) = doctor_of(&home, "", OsStr::new(""), &Every::unreachable());

        assert_eq!(
            out,
            "  ! ~/.local/state/bx/journal.mpk.corrupt is a damaged state file bx set aside, and \
             bx never deletes one; look at it, then move it out of the state directory\n  \
             ! ~/.local/state/bx/journal.mpk.corrupt.1 is a damaged state file bx set aside, \
             and bx never deletes one; look at it, then move it out of the state directory\n\
             Doctor: 2 finding(s).\n"
        );
        assert_eq!(code, Exit::Pending);
    }

    #[test]
    fn a_state_file_that_is_not_a_regular_file_stops_every_state_read() {
        let home = guarded_home();
        let state = crate::state::StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            state.journal(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        let (out, code) = doctor_of(&home, "", OsStr::new(""), &Every::unreachable());

        assert_eq!(
            out,
            "  ! ~/.local/state/bx/journal.mpk is not a regular file, so doctor read nothing in \
             the state directory; move it out of the way\nDoctor: 1 finding(s).\n"
        );
        assert_eq!(code, Exit::Pending);
    }

    #[test]
    fn a_journal_no_session_wrote_is_reported_and_left_in_place() {
        let home = guarded_home();
        let state = crate::state::StateDir::resolve(home.path());
        std::fs::create_dir_all(state.root()).unwrap();
        std::fs::write(state.journal(), b"garbage").unwrap();

        let (out, _) = doctor_of(&home, "", OsStr::new(""), &Every::unreachable());

        assert_eq!(
            out,
            "  ! ~/.local/state/bx/journal.mpk is a journal no bx session could have written; \
             the next `bx apply` sets it aside and rolls nothing back\nDoctor: 1 finding(s).\n"
        );
        assert_eq!(std::fs::read(state.journal()).unwrap(), b"garbage");
    }

    #[test]
    fn an_ordinary_file_in_an_ordinary_directory_is_no_finding() {
        let home = guarded_home();
        home.write(".gitconfig", "x");
        let layer = "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"x\"\n\
                     [[target]]\npath = \"~/.d\"\ndir = true\nmode = \"0755\"\n\
                     [[target]]\npath = \"~/.l\"\nsymlink = \"~/.gitconfig\"\n";

        let (out, _) = doctor_of(&home, layer, OsStr::new(""), &Every::unreachable());

        assert_eq!(out, "Doctor: 0 finding(s).\n");
    }
}
