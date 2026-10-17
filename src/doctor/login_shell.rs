//! Check 13: the shell this account logs in to, against the one `[doctor]
//! login-shell` asserts ([`crate::config::doctor`]).
//!
//! bx generates files for zsh and bash alike, and which of them a terminal
//! starts is the account's login shell — a field of the account database bx
//! never writes. Doctor reads it and reports one that is not the asserted
//! shell, quoting the `chsh` that changes it, never running it. Without an
//! assertion the check asks nothing.
//!
//! The account's shell is asked of the account database by this process's
//! uid, so a network account is read as the system resolves it:
//!
//! - on Linux, one `getent passwd UID` ([`GETENT`]), which honours NSS, and
//!   when that cannot answer, the uid's line of `/etc/passwd` ([`PASSWD`]);
//! - on macOS, one `dscacheutil -q user -a uid UID` ([`DSCACHEUTIL`]), which
//!   asks Directory Services by uid, so no account name is needed first.
//!
//! No other command line is built in this module, so no code path can change
//! the shell. A login shell that matches while this session's `$SHELL` does
//! not is the account changed since the session began: logging out and back
//! in is what applies it.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::Finding;
use crate::config::doctor::LoginShell;

/// The program asked on Linux, found on `PATH` as every libc installs it.
pub const GETENT: &str = "getent";

/// The account database read when [`GETENT`] cannot answer.
pub const PASSWD: &str = "/etc/passwd";

/// The program asked on macOS: by its absolute path, so the answer is the
/// system's own Directory Services.
pub const DSCACHEUTIL: &str = "/usr/bin/dscacheutil";

/// The subject of every finding this check reports.
pub const SUBJECT: &str = "login shell";

/// The account's login shell could not be read, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable(pub String);

/// The questions doctor puts about the account's login shell.
pub trait Query {
    /// The login shell the account database names for this account, as the
    /// path it is written as.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] when no account database could be asked, or none names
    /// this account.
    fn account(&self) -> Result<String, Unreadable>;

    /// This session's `$SHELL`, when it is set.
    fn session(&self) -> Option<String>;
}

/// Which account database [`Account`] asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Database {
    /// `getent passwd UID`, then `/etc/passwd`.
    Passwd,
    /// `dscacheutil -q user -a uid UID`.
    DirectoryServices,
}

/// [`Query`] through the platform's account database and `$SHELL`.
#[derive(Debug, Clone)]
pub struct Account {
    database: Database,
    program: OsString,
    leading: Vec<OsString>,
    passwd: PathBuf,
    uid: u32,
    session: Option<OsString>,
}

impl Default for Account {
    fn default() -> Self {
        let (database, program) = if cfg!(target_os = "macos") {
            (Database::DirectoryServices, DSCACHEUTIL)
        } else {
            (Database::Passwd, GETENT)
        };
        Self {
            database,
            program: OsString::from(program),
            leading: Vec::new(),
            passwd: PathBuf::from(PASSWD),
            uid: rustix::process::getuid().as_raw(),
            session: std::env::var_os("SHELL"),
        }
    }
}

impl Account {
    /// `program`, with `leading` before the arguments, in place of the
    /// platform's: a test's `sh -c SCRIPT sh`, so a canned answer needs no
    /// executable file.
    #[cfg(test)]
    fn stand_in(database: Database, program: &str, leading: &[&str], passwd: &Path) -> Self {
        Self {
            database,
            program: OsString::from(program),
            leading: leading.iter().map(OsString::from).collect(),
            passwd: passwd.to_path_buf(),
            uid: 1000,
            session: None,
        }
    }

    /// Run the program with `args` after the leading ones, and return its
    /// standard output when it exits 0.
    fn ask(&self, args: &[&str]) -> Result<String, String> {
        let name = Path::new(&self.program)
            .file_name()
            .unwrap_or(self.program.as_os_str())
            .to_string_lossy()
            .into_owned();
        tracing::debug!(program = name, ?args, "asking for the login shell");
        let output = Command::new(&self.program)
            .args(&self.leading)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("running {name}: {error}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(stderr
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map_or_else(
                    || format!("{name} {}", output.status),
                    |line| format!("{name}: {line}"),
                ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// The shell `getent passwd UID` names, else the uid's `/etc/passwd`
    /// line's.
    fn passwd(&self) -> Result<String, Unreadable> {
        let uid = self.uid.to_string();
        let asked = self.ask(&["passwd", &uid]).and_then(|out| {
            passwd_shell(&out, self.uid).ok_or_else(|| format!("getent named no uid {uid}"))
        });
        let error = match asked {
            Ok(shell) => return Ok(shell),
            Err(error) => error,
        };
        let read = std::fs::read_to_string(&self.passwd)
            .map_err(|e| format!("reading {}: {e}", self.passwd.display()))
            .and_then(|text| {
                passwd_shell(&text, self.uid)
                    .ok_or_else(|| format!("{} has no uid {uid}", self.passwd.display()))
            });
        read.map_err(|fallback| Unreadable(format!("{error}; {fallback}")))
    }

    /// The shell `dscacheutil -q user -a uid UID` names.
    fn directory_services(&self) -> Result<String, Unreadable> {
        let uid = self.uid.to_string();
        let out = self
            .ask(&["-q", "user", "-a", "uid", &uid])
            .map_err(Unreadable)?;
        out.lines()
            .find_map(|line| line.strip_prefix("shell:"))
            .map(|shell| shell.trim().to_string())
            .ok_or_else(|| Unreadable(format!("Directory Services names no uid {uid}")))
    }
}

impl Query for Account {
    fn account(&self) -> Result<String, Unreadable> {
        match self.database {
            Database::Passwd => self.passwd(),
            Database::DirectoryServices => self.directory_services(),
        }
    }

    fn session(&self) -> Option<String> {
        self.session
            .as_deref()
            .map(|shell| shell.to_string_lossy().into_owned())
    }
}

/// The shell field of `uid`'s line in passwd-format `text`.
///
/// An empty field is `/bin/sh`, as `passwd(5)` says a login reads it.
fn passwd_shell(text: &str, uid: u32) -> Option<String> {
    let uid = uid.to_string();
    text.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.as_slice() {
            [_, _, id, _, _, _, shell] if *id == uid => Some(if shell.is_empty() {
                "/bin/sh".to_string()
            } else {
                (*shell).to_string()
            }),
            _ => None,
        }
    })
}

/// Whether the shell at `path` is `name`: by its last component, so
/// `/usr/bin/zsh` and `/opt/homebrew/bin/zsh` are both zsh.
fn is(path: &str, name: &str) -> bool {
    Path::new(path).file_name() == Some(OsStr::new(name))
}

/// Every finding about `asserted`, asking `query`, and not at all when nothing
/// is asserted.
pub fn check(asserted: Option<&LoginShell>, query: &dyn Query) -> Vec<Finding> {
    let Some(asserted) = asserted else {
        return Vec::new();
    };
    let name = asserted.shell.name();
    let note = match query.account() {
        Err(Unreadable(why)) => {
            format!("could not be read, so whether it is the asserted {name} went unchecked: {why}")
        }
        Ok(account) if !is(&account, name) => format!(
            "is {account}, not the asserted {name}; `chsh -s \"$(command -v {name})\"` changes it"
        ),
        Ok(account) => match query.session() {
            Some(session) if !is(&session, name) => format!(
                "is {account}, but this session's $SHELL is still {session}; log out and back in \
                 to start a session with it"
            ),
            _ => return Vec::new(),
        },
    };
    vec![Finding {
        subject: SUBJECT.to_string(),
        origin: Some(asserted.origin.clone()),
        note,
    }]
}

/// A [`Query`] that answers from fixed values, for tests anywhere in the crate.
#[cfg(test)]
pub(crate) struct Fixed {
    /// What [`Query::account`] answers.
    pub account: Result<String, Unreadable>,
    /// What [`Query::session`] answers.
    pub session: Option<String>,
}

#[cfg(test)]
impl Query for Fixed {
    fn account(&self) -> Result<String, Unreadable> {
        self.account.clone()
    }

    fn session(&self) -> Option<String> {
        self.session.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::config::shells::Shell;

    fn zsh() -> LoginShell {
        LoginShell {
            shell: Shell::Zsh,
            origin: Origin {
                file: PathBuf::from("/state/local.toml"),
                line: 2,
            },
        }
    }

    fn fixed(account: Result<&str, &str>, session: Option<&str>) -> Fixed {
        Fixed {
            account: account
                .map(str::to_string)
                .map_err(|why| Unreadable(why.to_string())),
            session: session.map(str::to_string),
        }
    }

    /// The one note `check` reports, or `None` for no finding.
    fn note(asserted: Option<&LoginShell>, query: &dyn Query) -> Option<String> {
        let mut findings = check(asserted, query);
        assert!(findings.len() <= 1, "{findings:?}");
        findings.pop().map(|finding| {
            assert_eq!(finding.subject, SUBJECT);
            assert_eq!(finding.origin, Some(zsh().origin));
            finding.note
        })
    }

    /// A query no test may ask: nothing is asserted.
    struct Unasked;

    impl Query for Unasked {
        fn account(&self) -> Result<String, Unreadable> {
            panic!("the account was asked with nothing asserted")
        }

        fn session(&self) -> Option<String> {
            panic!("the session was asked with nothing asserted")
        }
    }

    #[test]
    fn no_assertion_asks_nothing_and_finds_nothing() {
        assert!(check(None, &Unasked).is_empty());
    }

    #[test]
    fn a_matching_account_and_session_is_no_finding() {
        for (account, session) in [
            ("/bin/zsh", Some("/bin/zsh")),
            ("/usr/bin/zsh", Some("/opt/homebrew/bin/zsh")),
            ("/usr/bin/zsh", None),
        ] {
            assert_eq!(
                note(Some(&zsh()), &fixed(Ok(account), session)),
                None,
                "{account} {session:?}"
            );
        }
    }

    #[test]
    fn a_different_account_shell_quotes_the_chsh_that_changes_it() {
        assert_eq!(
            note(Some(&zsh()), &fixed(Ok("/bin/bash"), Some("/bin/zsh"))).as_deref(),
            Some("is /bin/bash, not the asserted zsh; `chsh -s \"$(command -v zsh)\"` changes it")
        );
        assert!(
            note(Some(&zsh()), &fixed(Ok("/bin/zsh-5.9"), None))
                .is_some_and(|note| note.starts_with("is /bin/zsh-5.9, not")),
            "a name is matched whole"
        );
    }

    #[test]
    fn an_unreadable_account_shell_is_a_finding_with_the_reason() {
        assert_eq!(
            note(Some(&zsh()), &fixed(Err("getent named no uid 1000"), None)).as_deref(),
            Some(
                "could not be read, so whether it is the asserted zsh went unchecked: getent \
                 named no uid 1000"
            )
        );
    }

    #[test]
    fn a_stale_session_shell_says_to_log_in_again() {
        assert_eq!(
            note(Some(&zsh()), &fixed(Ok("/bin/zsh"), Some("/bin/bash"))).as_deref(),
            Some(
                "is /bin/zsh, but this session's $SHELL is still /bin/bash; log out and back in \
                 to start a session with it"
            )
        );
    }

    const PASSWD_TEXT: &str = "root:x:0:0:root:/root:/bin/bash\n\
                               # a comment line\n\
                               me:x:1000:1000:Me:/home/me:/usr/bin/zsh\n\
                               nologin:x:1001:1001::/home/n:\n";

    #[test]
    fn a_passwd_line_is_found_by_uid_and_an_empty_shell_is_sh() {
        assert_eq!(
            passwd_shell(PASSWD_TEXT, 1000).as_deref(),
            Some("/usr/bin/zsh")
        );
        assert_eq!(passwd_shell(PASSWD_TEXT, 0).as_deref(), Some("/bin/bash"));
        assert_eq!(passwd_shell(PASSWD_TEXT, 1001).as_deref(), Some("/bin/sh"));
        assert_eq!(passwd_shell(PASSWD_TEXT, 100).as_deref(), None);
        assert_eq!(
            passwd_shell("me:x:1000", 1000),
            None,
            "a short line is none"
        );
    }

    fn sh(database: Database, script: &str, passwd: &Path) -> Account {
        Account::stand_in(database, "/bin/sh", &["-c", script, "sh"], passwd)
    }

    #[test]
    fn getent_is_asked_by_uid_for_the_passwd_database() {
        // The stand-in answers only the exact command line getent is given.
        let account = sh(
            Database::Passwd,
            "[ \"$*\" = 'passwd 1000' ] && echo 'me:x:1000:1000::/home/me:/bin/zsh'",
            Path::new("/nonexistent/bx-test/passwd"),
        );
        assert_eq!(account.account(), Ok("/bin/zsh".to_string()));
    }

    #[test]
    fn passwd_is_read_when_getent_cannot_answer() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(&passwd, PASSWD_TEXT).unwrap();

        let missing = Account::stand_in(
            Database::Passwd,
            "/nonexistent/bx-test/getent",
            &[],
            &passwd,
        );
        assert_eq!(missing.account(), Ok("/usr/bin/zsh".to_string()));

        let not_found = sh(Database::Passwd, "exit 2", &passwd);
        assert_eq!(not_found.account(), Ok("/usr/bin/zsh".to_string()));
    }

    #[test]
    fn both_failing_names_both_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(&passwd, "root:x:0:0:root:/root:/bin/bash\n").unwrap();

        let error = sh(
            Database::Passwd,
            "echo 'no such database' >&2; exit 1",
            &passwd,
        )
        .account()
        .unwrap_err();
        assert_eq!(
            error.0,
            format!("sh: no such database; {} has no uid 1000", passwd.display())
        );

        let error = sh(Database::Passwd, "true", &dir.path().join("absent"))
            .account()
            .unwrap_err();
        assert!(
            error.0.starts_with("getent named no uid 1000; reading "),
            "{error:?}"
        );

        let error = sh(Database::Passwd, "exit 3", &passwd)
            .account()
            .unwrap_err();
        assert!(error.0.starts_with("sh exit status: 3; "), "{error:?}");
    }

    #[test]
    fn directory_services_is_asked_by_uid() {
        let none = Path::new("/nonexistent/bx-test/passwd");
        let account = sh(
            Database::DirectoryServices,
            "[ \"$*\" = '-q user -a uid 1000' ] && printf 'name: me\\nuid: 1000\\nshell: /bin/zsh\\n'",
            none,
        );
        assert_eq!(account.account(), Ok("/bin/zsh".to_string()));

        let error = sh(Database::DirectoryServices, "true", none)
            .account()
            .unwrap_err();
        assert_eq!(error.0, "Directory Services names no uid 1000");

        let error = Account::stand_in(
            Database::DirectoryServices,
            "/nonexistent/bx-test/dscacheutil",
            &[],
            none,
        )
        .account()
        .unwrap_err();
        assert!(error.0.starts_with("running dscacheutil: "), "{error:?}");
    }

    #[test]
    fn the_session_is_the_shell_variable_as_given() {
        let account = Account {
            session: Some(OsString::from("/bin/zsh")),
            ..Account::default()
        };
        assert_eq!(account.session().as_deref(), Some("/bin/zsh"));
        let account = Account {
            session: None,
            ..account
        };
        assert_eq!(account.session(), None);
    }

    #[test]
    fn the_default_asks_the_platform_database_for_this_uid() {
        let account = Account::default();
        assert_eq!(account.uid, rustix::process::getuid().as_raw());
        if cfg!(target_os = "macos") {
            assert_eq!(account.database, Database::DirectoryServices);
            assert_eq!(account.program, DSCACHEUTIL);
        } else {
            assert_eq!(account.database, Database::Passwd);
            assert_eq!(account.program, GETENT);
            assert_eq!(account.passwd, Path::new(PASSWD));
        }
    }
}
