//! Check 7 on macOS: bx's LaunchAgent, written by `apply` and checked against
//! what launchd has made of it.
//!
//! On macOS the `environment` and `gui` variables land in a LaunchAgent bx
//! owns whole ([`crate::config::env::LAUNCH_AGENT`]) in place of
//! `environment.d`, and launchd is to it what the systemd user manager is to a
//! unit file ([`super::systemd`]). Writing it is all `apply` does: bx never
//! bootstraps, kickstarts or loads anything, so the file takes effect at the
//! next login. What doctor adds is the part a user would otherwise find out
//! later — that it is written and launchd has not loaded it, so no program
//! the session starts has its variables yet.
//!
//! The only question put to launchd is one `launchctl print` of the agent in
//! the account's GUI domain ([`PRINT`]), and only when the agent is on disk.
//! No other command line is built anywhere in this module, so no code path can
//! ask for a load, a bootstrap or a start.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use super::Finding;
use crate::config::Origin;
use crate::config::env::{LAUNCH_AGENT, LAUNCH_AGENT_LABEL};
use crate::config::resolve::Resolution;
use crate::config::target::Target;

/// The program asked: by its absolute path, so the answer is the system's own
/// launchd and never a `launchctl` earlier on `PATH`.
pub const LAUNCHCTL: &str = "/bin/launchctl";

/// The one subcommand: a read-only description of one service.
pub const PRINT: &str = "print";

/// The status `launchctl print` exits with when the domain has no service of
/// that label: the agent is not loaded.
pub const NOT_FOUND: i32 = 113;

/// The subject of the finding a run reports when launchd cannot be asked.
pub const SESSION: &str = "launchd";

/// bx's LaunchAgent, declared and on disk to be checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// The target, spelled portably, as `plan` names it.
    pub target: String,
    /// Where the variable that placed it was declared.
    pub origin: Origin,
}

/// bx's LaunchAgent among `targets`, when one is ready and on disk.
///
/// Held back, it has no bytes to load; not yet written, it has nothing for
/// launchd to have missed. Whatever is at the path counts — a file bx wrote,
/// one it has yet to update, or one in conflict — because launchd reads what
/// is there, not what bx means to write.
#[must_use]
pub fn agent(targets: &[Resolution<Target>], home: &Path) -> Option<Agent> {
    targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) => Some(target),
            Resolution::Blocked(_) => None,
        })
        .find(|target| target.path.as_str() == LAUNCH_AGENT)
        .filter(|target| std::fs::symlink_metadata(target.path.render(home)).is_ok())
        .map(|target| Agent {
            target: target.path.as_str().to_string(),
            origin: target.origin.clone(),
        })
}

/// launchd could not be asked, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreachable(pub String);

/// The one question doctor puts to launchd.
pub trait Query {
    /// Whether the account's GUI domain has loaded the service `label`.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] when launchd cannot be asked, or answers anything but
    /// a service or its absence — over SSH, say, where the account has no GUI
    /// domain.
    fn loaded(&self, label: &str) -> Result<bool, Unreachable>;
}

/// [`Query`] through `launchctl print gui/UID/LABEL`.
#[derive(Debug, Clone)]
pub struct Launchctl {
    program: OsString,
    leading: Vec<OsString>,
    uid: u32,
}

impl Default for Launchctl {
    fn default() -> Self {
        Self {
            program: OsString::from(LAUNCHCTL),
            leading: Vec::new(),
            uid: rustix::process::getuid().as_raw(),
        }
    }
}

impl Launchctl {
    /// `program`, with `leading` before the arguments, in place of
    /// `launchctl`: a test's `sh -c SCRIPT sh`, so a canned answer needs no
    /// executable file.
    #[cfg(test)]
    fn stand_in(program: &str, leading: &[&str], uid: u32) -> Self {
        Self {
            program: OsString::from(program),
            leading: leading.iter().map(OsString::from).collect(),
            uid,
        }
    }

    /// The service `label` in this account's GUI domain, as launchd names it.
    fn service(&self, label: &str) -> String {
        format!("gui/{}/{label}", self.uid)
    }
}

impl Query for Launchctl {
    fn loaded(&self, label: &str) -> Result<bool, Unreachable> {
        tracing::debug!(label, "asking launchctl print");
        let output = Command::new(&self.program)
            .args(&self.leading)
            .arg(PRINT)
            .arg(self.service(label))
            .stdin(Stdio::null())
            .output()
            .map_err(|error| Unreachable(format!("running launchctl: {error}")))?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(NOT_FOUND) => Ok(false),
            _ => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // `launchctl` opens every refusal with "Bad request."; the
                // line after it says what was wrong.
                let why = stderr
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty() && *line != "Bad request.")
                    .map_or_else(
                        || format!("launchctl {}", output.status),
                        ToString::to_string,
                    );
                Err(Unreachable(why))
            }
        }
    }
}

/// Every finding about `agent`, asking `query` once, and not at all when
/// there is no agent to ask about.
pub fn check(agent: Option<&Agent>, query: &dyn Query) -> Vec<Finding> {
    let Some(agent) = agent else {
        return Vec::new();
    };
    match query.loaded(LAUNCH_AGENT_LABEL) {
        Ok(true) => Vec::new(),
        Ok(false) => vec![Finding {
            subject: agent.target.clone(),
            origin: Some(agent.origin.clone()),
            note: format!(
                "is written but launchd has not loaded it, so its variables reach programs only \
                 after the next login; `launchctl bootstrap gui/$(id -u) {LAUNCH_AGENT}` loads it \
                 now"
            ),
        }],
        Err(Unreachable(why)) => vec![Finding {
            subject: SESSION.to_string(),
            origin: None,
            note: format!("is unreachable, so {} went unchecked: {why}", agent.target),
        }],
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::config::parse_str;
    use crate::config::values::ResolvedValues;
    use crate::shell::placement::{Platform, place_on};
    use crate::testing::guarded_home;

    const GUI: &str = "[[env]]\nname = \"GTK_IM_MODULE\"\nvalue = \"ibus\"\nkind = \"gui\"\n";

    /// What `text` places on `platform`, under `home`.
    fn placed(text: &str, home: &Path, platform: Platform) -> Vec<Resolution<Target>> {
        let config = parse_str(text, &home.join(".config/bx/bx.toml"), home).expect("parses");
        let values =
            ResolvedValues::resolve(config.values.clone(), &config.value_assignments, home)
                .expect("values");
        place_on(&config, &values, platform).expect("places")
    }

    #[test]
    fn the_agent_is_checked_once_it_is_placed_and_on_disk() {
        let home = guarded_home();
        let macos = placed(GUI, home.path(), Platform::Macos);
        assert_eq!(agent(&macos, home.path()), None, "not on disk yet");
        home.write("Library/LaunchAgents/dev.bx.environment.plist", "");
        let found = agent(&macos, home.path()).expect("the agent");
        assert_eq!(found.target, LAUNCH_AGENT);
        assert_eq!(found.origin.line, 1);
        // Linux places `environment.d`, never the agent, so there is nothing
        // to ask launchd about even with the file there.
        assert_eq!(
            agent(&placed(GUI, home.path(), Platform::Linux), home.path()),
            None
        );
        // Held back, it is not checked either.
        let held = "[[value]]\nname = \"im\"\nkind = \"string\"\n\n\
                    [[env]]\nname = \"GTK_IM_MODULE\"\nvalue = \"{{im}}\"\nkind = \"gui\"\n";
        assert_eq!(
            agent(&placed(held, home.path(), Platform::Macos), home.path()),
            None
        );
    }

    /// A [`Query`] that gives one answer and records each label it is asked.
    struct Canned {
        answer: Result<bool, Unreachable>,
        asked: RefCell<Vec<String>>,
    }

    impl Canned {
        fn new(answer: Result<bool, Unreachable>) -> Self {
            Self {
                answer,
                asked: RefCell::new(Vec::new()),
            }
        }
    }

    impl Query for Canned {
        fn loaded(&self, label: &str) -> Result<bool, Unreachable> {
            self.asked.borrow_mut().push(label.to_string());
            self.answer.clone()
        }
    }

    fn the_agent() -> Agent {
        Agent {
            target: LAUNCH_AGENT.to_string(),
            origin: Origin {
                file: "/var/home/example/.config/bx/bx.toml".into(),
                line: 3,
            },
        }
    }

    #[test]
    fn a_loaded_agent_is_no_finding() {
        let query = Canned::new(Ok(true));
        assert_eq!(check(Some(&the_agent()), &query), Vec::new());
        assert_eq!(*query.asked.borrow(), [LAUNCH_AGENT_LABEL]);
    }

    #[test]
    fn an_agent_launchd_has_not_loaded_says_how_to_load_it() {
        let query = Canned::new(Ok(false));
        let found = check(Some(&the_agent()), &query);
        assert_eq!(
            found,
            vec![Finding {
                subject: LAUNCH_AGENT.to_string(),
                origin: Some(the_agent().origin),
                note: "is written but launchd has not loaded it, so its variables reach \
                       programs only after the next login; `launchctl bootstrap gui/$(id -u) \
                       ~/Library/LaunchAgents/dev.bx.environment.plist` loads it now"
                    .to_string(),
            }]
        );
    }

    #[test]
    fn an_unreachable_launchd_is_one_finding_about_the_session() {
        let query = Canned::new(Err(Unreachable(
            "Could not find domain for user gui: 501".to_string(),
        )));
        let found = check(Some(&the_agent()), &query);
        assert_eq!(
            found,
            vec![Finding {
                subject: SESSION.to_string(),
                origin: None,
                note: format!(
                    "is unreachable, so {LAUNCH_AGENT} went unchecked: Could not find domain \
                     for user gui: 501"
                ),
            }]
        );
    }

    #[test]
    fn no_agent_asks_nothing() {
        let query = Canned::new(Ok(false));
        assert_eq!(check(None, &query), Vec::new());
        assert!(query.asked.borrow().is_empty());
    }

    fn sh(script: &str) -> Launchctl {
        Launchctl::stand_in("/bin/sh", &["-c", script, "sh"], 501)
    }

    #[test]
    fn the_only_command_line_is_a_read_only_print_in_the_gui_domain() {
        // The stand-in fails, printing the arguments it was given, so the whole
        // command line comes back as the reason.
        let error = sh("echo 'Bad request.' >&2; printf '%s\\n' \"$*\" >&2; exit 1")
            .loaded(LAUNCH_AGENT_LABEL)
            .expect_err("the stand-in fails");
        assert_eq!(
            error,
            Unreachable("print gui/501/dev.bx.environment".to_string())
        );
    }

    #[test]
    fn launchctl_s_status_says_whether_the_service_is_loaded() {
        assert_eq!(sh("exit 0").loaded("a"), Ok(true));
        assert_eq!(sh("exit 113").loaded("a"), Ok(false));
        // Any other status is launchd failing to answer, quoted from stderr,
        // or named by the status when it says nothing.
        assert_eq!(
            sh(
                "echo 'Bad request.' >&2; echo 'Could not find domain for user gui: 501' >&2; \
                exit 112"
            )
            .loaded("a"),
            Err(Unreachable(
                "Could not find domain for user gui: 501".to_string()
            ))
        );
        let silent = sh("exit 5").loaded("a").expect_err("unreachable");
        assert!(silent.0.starts_with("launchctl "), "{silent:?}");
        assert!(silent.0.contains('5'), "{silent:?}");
    }

    #[test]
    fn a_missing_launchctl_is_unreachable() {
        let error = Launchctl::stand_in("/nonexistent/bx-test/launchctl", &[], 501)
            .loaded("a")
            .expect_err("nothing to run");
        assert!(error.0.starts_with("running launchctl: "), "{error:?}");
    }

    #[test]
    fn the_default_query_is_the_system_s_launchctl_for_this_account() {
        let query = Launchctl::default();
        assert_eq!(query.program, LAUNCHCTL);
        assert!(query.leading.is_empty());
        assert_eq!(query.uid, rustix::process::getuid().as_raw());
        assert_eq!(query.service("x"), format!("gui/{}/x", query.uid));
    }
}
