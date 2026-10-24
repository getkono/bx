//! `bx doctor`: what a human should look at, found without changing anything.
//!
//! Doctor reads the same resolved targets `plan` decides ([`Inputs::targets`])
//! and asks read-only questions about them. It writes nothing, takes no lock,
//! and never runs anything that could install, start or modify something: a
//! command that would clear a finding is printed in its note, never run.
//!
//! Every check reports in a fixed order, and each one in configuration order,
//! so two runs over an unchanged machine print the same bytes. Any finding at
//! all exits [`Exit::Pending`]; none exits [`Exit::Converged`]. Findings have
//! no severity among themselves: a finding is something to look at, whichever
//! check found it. A check that cannot ask what it needs is a finding, not an
//! error. Beside the findings a report holds notes: what is worth reading and
//! needs nothing done, such as what the last update check found. A note is
//! printed after every finding, and never changes the exit.
//!
//! Doctor takes no exclusive lock and writes nothing under the state directory
//! or the home, so it runs beside an `apply` that holds the lock. It starts no
//! process but the one read-only `systemctl --user show` [`systemd`] builds,
//! the one read-only `launchctl print` [`launchd`] builds on macOS,
//! `bash --version` when bash's generated file asks about updates
//! ([`bash`]), and, when `[doctor] login-shell` asserts a shell, the one
//! read-only account lookup [`login_shell`] builds: `getent passwd` on Linux,
//! `dscacheutil` on macOS; and, when the config repo is a git repository, the
//! read-only `git` questions [`repo`] asks of it and of the followed
//! externals' checkouts bx cloned, none of which reaches a remote.
//!
//! The checks, in order:
//!
//! 1. [`tools`] — a declared tool, or a tool a target `requires`, that is not
//!    an executable on `PATH`, with its `install` command quoted, never run,
//!    and the targets that require it named. One finding per tool, whichever
//!    declarations name it.
//! 2. [`values`] — a required declared value with no answer.
//! 3. [`state`] — a state file that is damaged, unreadable, not a regular
//!    file, or set aside as damaged and still standing.
//! 4. [`state`] — a session an `apply` or `rm` left interrupted, or an
//!    `apply` running now.
//! 5. [`modes`] — a directory whose mode is wider than a file declared in it.
//! 6. [`sources`] — a declared optional source whose file is not readable.
//! 7. [`systemd`] — a declared unit file systemd has not reloaded, that is not
//!    enabled, that it could not load, or that has failed; and on macOS
//!    [`launchd`] — bx's LaunchAgent, written and not loaded by launchd.
//! 8. [`references`] — a path a written target declares in `references` that
//!    is not on disk.
//! 9. [`orphans`] — a `.bx-` temporary file an interrupted write left beside
//!    a destination, which no journal names and recovery never removes.
//! 10. [`externals`] — an external that follows a branch `bx.lock` holds no
//!     commit for, a lock entry nothing follows, an update stamp that holds
//!     no time, and a `last-check` saying `bx update` stopped; what else
//!     `last-check` says is a note.
//! 11. [`stray_local`] — a `local.toml` inside the config repo, which bx
//!     never loads, with the move to the state directory that makes it count.
//! 12. [`bash`] — bash's generated file asks about followed externals'
//!     updates, and the `bash` on `PATH` is older than 4.4, which leaves the
//!     question out.
//! 13. [`login_shell`] — the account's login shell is not the one
//!     `[doctor] login-shell` asserts, with the `chsh` that changes it quoted,
//!     never run; it could not be read; or it is, and this session's `$SHELL`
//!     is still another.
//! 14. [`repo`] — the config repo has uncommitted changes, commits its
//!     upstream lacks, is behind or has diverged from it as last fetched, has
//!     no upstream or a gone one, has a detached `HEAD`, or has a rebase or
//!     `git am` in progress; and a followed external's checkout holds local
//!     work.

pub mod bash;
pub mod externals;
pub mod launchd;
pub mod login_shell;
pub mod modes;
pub mod orphans;
pub mod references;
pub mod repo;
pub mod sources;
pub mod state;
pub mod stray_local;
pub mod systemd;
pub mod tools;
pub mod values;

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::Path;

use crate::config::Origin;
use crate::git::Git;
use crate::paths;
use crate::plan::Inputs;
use crate::report::{Exit, escape};

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
    /// Every note, check by check: printed after the findings, and never a
    /// reason to exit [`Exit::Pending`].
    pub notes: Vec<Finding>,
}

/// What the checks ask the machine through.
pub struct Probes<'a> {
    /// The `PATH` a declared or required tool is looked for along.
    pub path: &'a OsStr,
    /// The systemd user unit directory.
    pub unit_dir: &'a Path,
    /// The question put to the user's systemd.
    pub systemd: &'a dyn systemd::Query,
    /// The question put to launchd about bx's LaunchAgent.
    pub launchd: &'a dyn launchd::Query,
    /// The question put to the `bash` on `path`.
    pub bash: &'a dyn bash::Query,
    /// The question put to the account database about the login shell.
    pub login_shell: &'a dyn login_shell::Query,
    /// The `git` [`repo`] asks about the config repo and followed checkouts.
    pub git: &'a Git,
}

/// Run every check against `inputs`, in the order the module lists them.
#[must_use]
pub fn run(inputs: &Inputs, probes: &Probes<'_>) -> Report {
    let home = inputs.home();
    let resolved = inputs.resolved();
    let state = state::check(inputs.state(), home);
    let units = systemd::units(inputs.targets(), home, probes.unit_dir);

    let mut findings = tools::check(&resolved.tools, inputs.targets(), probes.path, home);
    findings.extend(values::check(&resolved.values));
    findings.extend(state.damage);
    findings.extend(state.session);
    findings.extend(modes::check(inputs.targets(), home));
    findings.extend(sources::check(inputs.targets(), home, &sources::readable));
    findings.extend(systemd::check(&units, probes.systemd));
    findings.extend(launchd::check(
        launchd::agent(inputs.targets(), home).as_ref(),
        probes.launchd,
    ));
    findings.extend(references::check(
        inputs.targets(),
        &state.ledger,
        home,
        &references::exists,
    ));
    findings.extend(orphans::check(
        inputs.targets(),
        &state.ledger,
        inputs.state(),
        home,
    ));
    findings.extend(externals::check(
        &resolved.externals,
        inputs.committed_externals(),
        inputs.lock(),
        inputs.repo(),
        inputs.state(),
    ));
    findings.extend(stray_local::check(inputs.repo(), inputs.state(), home));
    findings.extend(bash::check(inputs.targets(), probes.path, probes.bash));
    findings.extend(login_shell::check(
        resolved.doctor.login_shell.as_ref(),
        probes.login_shell,
    ));
    findings.extend(repo::check(
        inputs.repo(),
        &resolved.externals,
        &state.ledger,
        home,
        probes.git,
    ));
    let notes = externals::notes(&resolved.externals, inputs.state());
    Report { findings, notes }
}

/// The text `bx doctor` prints: one line per finding, then one per note,
/// then a tally, which counts the notes only when there are any.
///
/// A finding reads like a `plan` row — `  ! {subject}  ({origin}) {note}` — so
/// the two outputs point at a declaration the same way; a note reads the same
/// with `i` for `!`.
#[must_use]
pub fn render(report: &Report, home: &Path) -> String {
    let mut out = String::new();
    let marked = report
        .findings
        .iter()
        .map(|finding| ('!', finding))
        .chain(report.notes.iter().map(|note| ('i', note)));
    for (mark, finding) in marked {
        let _ = write!(out, "  {mark} {}", escape(&finding.subject));
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
    let _ = write!(out, "Doctor: {} finding(s)", report.findings.len());
    if !report.notes.is_empty() {
        let _ = write!(out, ", {} note(s)", report.notes.len());
    }
    out.push_str(".\n");
    out
}

/// The process status a report implies: pending on any finding at all,
/// whatever the notes say.
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
    // The units these tests declare are kept to Linux, as every unit must be.
    use crate::plan::tests::inputs_on_linux as inputs;
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
when = \"os:linux\"

[[target]]
path = \"~/.config/systemd/user/b.timer\"
content = \"[Timer]\\n\"
when = \"os:linux\"

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
                launchd: &Unasked,
                bash: &bash::Version,
                login_shell: &Unasked,
                git: &Git::at_home(home.path()),
            },
        );
        (render(&report, home.path()), exit(&report))
    }

    /// A launchd no test here may ask: what they declare is placed for
    /// Linux, which has no LaunchAgent. And an account database no test may
    /// ask that asserts no login shell.
    struct Unasked;

    impl launchd::Query for Unasked {
        fn loaded(&self, label: &str) -> Result<bool, launchd::Unreachable> {
            panic!("launchd was asked about {label}")
        }
    }

    impl login_shell::Query for Unasked {
        fn account(&self) -> Result<String, login_shell::Unreadable> {
            panic!("the login shell was asked with none asserted")
        }

        fn session(&self) -> Option<String> {
            panic!("$SHELL was asked with no login shell asserted")
        }
    }

    /// An account that logs in to `account`, in a session started with it.
    fn logs_in_to(account: &str) -> login_shell::Fixed {
        login_shell::Fixed {
            account: Ok(account.to_string()),
            session: Some(account.to_string()),
        }
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
             ~/.config/systemd/user/b.timer  (~/.config/bx/bx.toml:6) is written but not \
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
            ..Report::default()
        };

        assert_eq!(
            render(&report, Path::new("/var/home/example")),
            "  ! systemd\\x1b[2J  (/elsewhere/bx.toml:7) said\\r\\nno\nDoctor: 1 finding(s).\n"
        );
    }

    #[test]
    fn notes_print_after_the_findings_and_never_leave_doctor_pending() {
        let note = |subject: &str, note: &str| Finding {
            subject: subject.to_string(),
            origin: None,
            note: note.to_string(),
        };
        let mut report = Report {
            findings: Vec::new(),
            notes: vec![note("bx update", "found\x1b[2J"), note("b", "two")],
        };
        let home = Path::new("/var/home/example");
        assert_eq!(
            render(&report, home),
            "  i bx update found\\x1b[2J\n  i b two\nDoctor: 0 finding(s), 2 note(s).\n"
        );
        assert_eq!(exit(&report), Exit::Converged);

        report.findings.push(note("a", "one"));
        assert_eq!(
            render(&report, home),
            "  ! a one\n  i bx update found\\x1b[2J\n  i b two\nDoctor: 1 finding(s), 2 note(s).\n"
        );
        assert_eq!(exit(&report), Exit::Pending);
    }

    /// A machine with one thing for every check to find, in the order the
    /// checks run — each declared out of that order, so the output's order is
    /// the checks' and not the file's.
    const EVERY_CHECK: &str = "\
[[target]]
path = \"~/.config/systemd/user/a.service\"
content = \"[Service]\\n\"
when = \"os:linux\"

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

[doctor]
login-shell = \"zsh\"
";

    /// Run doctor over `layer` in `home`, looking for tools along `path`, on
    /// an account that logs in to bash.
    fn doctor_of(
        home: &crate::testing::GuardedHome,
        layer: &str,
        path: &OsStr,
        systemd: &dyn Query,
    ) -> (String, Exit) {
        doctor_as(home, layer, path, systemd, &logs_in_to("/bin/bash"))
    }

    /// [`doctor_of`], asking `login_shell` about the account's login shell.
    fn doctor_as(
        home: &crate::testing::GuardedHome,
        layer: &str,
        path: &OsStr,
        systemd: &dyn Query,
        login_shell: &dyn login_shell::Query,
    ) -> (String, Exit) {
        let inputs = inputs(home, layer);
        let unit_dir = paths::systemd_user_dir_in(home.path(), None);
        let report = run(
            &inputs,
            &Probes {
                path,
                unit_dir: &unit_dir,
                systemd,
                launchd: &Unasked,
                bash: &bash::Version,
                login_shell,
                git: &Git::at_home(home.path()),
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
        home.write(".config/systemd/user/.bx-Ab3dEf", "");
        home.write(".config/bx/local.toml", "[values]\n");
        let systemd = Every::unit(disabled());

        let (first, code) = doctor_of(&home, EVERY_CHECK, OsStr::new(""), &systemd);
        let (second, _) = doctor_of(&home, EVERY_CHECK, OsStr::new(""), &systemd);

        assert_eq!(
            first,
            "  ! tool bx-no-such-tool  (~/.config/bx/bx.toml:20) is not on PATH; `sudo dnf \
             install bx-no-such-tool` installs it\n\
             \x20 ! value email  (~/.config/bx/bx.toml:15) is required and has no answer; run \
             `bx init` to set email\n\
             \x20 ! ~/.local/state/bx/fingerprints.mpk is damaged: it is not valid MessagePack; \
             it is a cache, and the next `bx apply` sets it aside and rebuilds it\n\
             \x20 ! ~/.local/state/bx/journal.mpk records an interrupted apply session of 1 \
             write(s) that stopped before it finished; the next `bx apply` rolls it back; `bx \
             plan` shows what it would do\n\
             \x20 ! ~/.ssh/config  (~/.config/bx/bx.toml:10) ~/.ssh is 0755, wider than the 0600 \
             this file declares; `chmod 0711 ~/.ssh` narrows it\n\
             \x20 ! source keychain  (~/.config/bx/bx.toml:6) ~/.keychain/host-sh is not \
             readable, so the shell skips the line that sources it\n\
             \x20 ! ~/.config/systemd/user/a.service  (~/.config/bx/bx.toml:1) is written but \
             not enabled; `systemctl --user enable a.service` enables it\n\
             \x20 ! ~/.config/systemd/user/.bx-Ab3dEf is a temporary file a bx write left when \
             it was interrupted before its journal named it, so recovery never removes it and \
             nothing reads it; look at it, then delete it\n\
             \x20 ! ~/.config/bx/local.toml is inside the config repo, so bx never loads it \
             and could publish it; move what it holds into ~/.local/state/bx/local.toml, the \
             local layer bx loads\n\
             \x20 ! login shell  (~/.config/bx/bx.toml:25) is /bin/bash, not the asserted zsh; \
             `chsh -s \"$(command -v zsh)\"` changes it\n\
             Doctor: 10 finding(s).\n"
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
    fn what_the_last_update_check_found_is_a_note_and_a_stopped_update_a_finding() {
        let home = guarded_home();
        home.write(
            ".config/bx/bx.lock",
            "[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\nbranch = \"main\"\n\
             rev = \"0e810e5afa27acbd074398eefbe28d13005dbc15\"\n",
        );
        let layer = "[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\nbranch = \"main\"\n";
        let state = crate::state::StateDir::resolve(home.path());
        state.ensure_update().unwrap();
        let last = crate::update::Stamps::of(&state).last_check();
        let summary = "~/a: 1 new commit(s) on main, 0e810e5 -> 1f921f6";
        std::fs::write(&last, format!("{summary}\n")).unwrap();

        let (out, code) = doctor_of(&home, layer, OsStr::new(""), &Every::unreachable());
        assert_eq!(
            out,
            format!(
                "  i bx update {} says `{summary}`\nDoctor: 0 finding(s), 1 note(s).\n",
                last.display()
            )
        );
        assert_eq!(code, Exit::Converged);

        // `run` carries `externals::check`'s findings into the report too.
        let stopped = format!("{}the remote was unreachable", crate::update::STOPPED);
        std::fs::write(&last, format!("{stopped}\n")).unwrap();
        let (out, code) = doctor_of(&home, layer, OsStr::new(""), &Every::unreachable());
        assert!(out.starts_with("  ! bx update "), "{out}");
        assert_eq!(code, Exit::Pending);
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

        let (out, code) = doctor_as(
            &home,
            EVERY_CHECK,
            home.child("bin").as_os_str(),
            &Every::unit(enabled),
            &logs_in_to("/usr/bin/zsh"),
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
        crate::testing::mkfifo(&state.journal());

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
    fn a_missing_reference_of_an_applied_target_reports_last_and_twice_the_same() {
        let home = guarded_home();
        // Declared first, so the output's order is the checks' and not the
        // file's.
        let layer = "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"[include]\\n\"\n\
                     references = [\"~/.gitconfig.local\"]\n\
                     [[target]]\npath = \"~/.config/systemd/user/a.service\"\n\
                     content = \"[Service]\\n\"\nwhen = \"os:linux\"\n";
        let (before, code) = doctor_of(&home, layer, OsStr::new(""), &Every::unit(disabled()));
        assert_eq!(before, "Doctor: 0 finding(s).\n", "nothing applied yet");
        assert_eq!(code, Exit::Converged);

        crate::plan::run(&inputs(&home, layer), crate::plan::Mode::Apply, &mut |_| {
            Ok(true)
        })
        .expect("apply runs");
        let (first, code) = doctor_of(&home, layer, OsStr::new(""), &Every::unit(disabled()));
        let (second, _) = doctor_of(&home, layer, OsStr::new(""), &Every::unit(disabled()));

        assert_eq!(
            first,
            "  ! ~/.config/systemd/user/a.service  (~/.config/bx/bx.toml:5) is written but not \
             enabled; `systemctl --user enable a.service` enables it\n\
             \x20 ! ~/.gitconfig  (~/.config/bx/bx.toml:1) references ~/.gitconfig.local, which \
             does not exist; create it, or drop it from `references`\n\
             Doctor: 2 finding(s).\n"
        );
        assert_eq!(code, Exit::Pending);
        assert_eq!(first, second, "two runs print the same bytes");

        home.write(".gitconfig.local", "[user]\n");
        let (after, _) = doctor_of(&home, layer, OsStr::new(""), &Every::unit(disabled()));
        assert!(!after.contains("~/.gitconfig "), "{after}");
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

    #[test]
    fn a_required_tool_that_is_absent_never_blocks_its_target_and_doctor_names_it() {
        use crate::plan::Mode;
        use crate::report::Action;

        let home = guarded_home();
        let layer = "[[tool]]\nname = \"bx-no-such-tool\"\ninstall = \"make install\"\n\
                     [[target]]\npath = \"~/.config/absent/config\"\ncontent = \"x\\n\"\n\
                     requires = [\"bx-no-such-tool\", \"bx-nor-this-one\"]\n";
        let inputs = inputs(&home, layer);
        let action = |mode| {
            let report = crate::plan::run(&inputs, mode, &mut |_| Ok(true)).expect("it runs");
            report.changes.iter().map(|c| c.action).collect::<Vec<_>>()
        };

        assert_eq!(
            action(Mode::Plan),
            [Action::Create],
            "an absent tool blocks nothing"
        );
        assert_eq!(action(Mode::Apply), [Action::Create]);
        assert_eq!(
            std::fs::read(home.child(".config/absent/config")).unwrap(),
            b"x\n",
            "the target is written while its tools are absent"
        );
        assert_eq!(
            action(Mode::Plan),
            [Action::Unchanged],
            "and stays converged"
        );

        let (out, code) = doctor_of(&home, layer, OsStr::new(""), &Every::unreachable());

        assert_eq!(
            out,
            "  ! tool bx-no-such-tool  (~/.config/bx/bx.toml:1) is not on PATH; `make install` \
             installs it; ~/.config/absent/config requires it\n  ! tool bx-nor-this-one  \
             (~/.config/bx/bx.toml:4) is not on PATH, and no `[[tool]]` entry declares it; \
             ~/.config/absent/config requires it\nDoctor: 2 finding(s).\n"
        );
        assert_eq!(code, Exit::Pending);
    }
}
