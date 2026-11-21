//! Everything bx takes from the process it runs in.
//!
//! [`Env::from_process`] reads the process environment and its terminals on
//! the path every command takes; the other reads on that path are the
//! `PATH` that `plan::Inputs::load` takes through
//! `activation::System::from_env`, for a declared activation's tool and a
//! `has:TOOL` condition, and the machine's facts it takes through
//! `config::when::Machine::read`, for the conditions on them. Every other
//! function is handed the [`Env`] it read,
//! so a test supplies its own instead of touching the process.

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal as _;
use std::path::PathBuf;

use crate::paths;

/// Why the process environment cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `$HOME` is not usable.
    #[error(transparent)]
    Home(#[from] paths::Error),
    /// `$HOME` climbs out of a directory and back in, so bx cannot name the
    /// home exactly.
    #[error(
        "HOME has a `..` component: {}; bx renders every path against HOME and will not guess \
         which directory it names. Set HOME without `..`",
        .0.display()
    )]
    HomeParentComponent(PathBuf),
}

/// Everything bx takes from the process it runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    /// `$HOME`.
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`, which places the config repo.
    pub xdg_config_home: Option<OsString>,
    /// `$XDG_STATE_HOME`, which places the state directory.
    pub xdg_state_home: Option<OsString>,
    /// Whether `$NO_COLOR` is set to something other than the empty string.
    pub no_color: bool,
    /// Whether standard output is a terminal.
    pub stdout_tty: bool,
    /// Whether standard input is a terminal, so a confirmation can be asked.
    pub stdin_tty: bool,
    /// Whether standard error is a terminal, so progress can be drawn.
    pub stderr_tty: bool,
    /// How many columns standard output's terminal has, when it is one and
    /// says: what a diff's file header is ruled to.
    pub columns: Option<u16>,
    /// How many rows standard output's terminal has, when it is one and says:
    /// a rendering this tall or taller is paged.
    pub rows: Option<u16>,
    /// The pager a tall rendering goes through, or `None` where nothing is
    /// paged: see [`Pager::resolve`].
    pub pager: Option<Pager>,
    /// The account's name: `$USER`, else `$LOGNAME`, whichever is set and
    /// not empty first, for a `when = "user:NAME"` condition.
    pub user: Option<String>,
}

impl Env {
    /// Read the environment of this process. The only place in the `plan`
    /// path that does.
    ///
    /// # Errors
    ///
    /// [`Error::Home`] when `$HOME` is unset, empty or relative, and
    /// [`Error::HomeParentComponent`] when it has a `..` component.
    pub fn from_process() -> Result<Self, Error> {
        let no_color = no_color(std::env::var_os("NO_COLOR").as_deref());
        let stdout_tty = std::io::stdout().is_terminal();
        let (columns, rows) = if stdout_tty {
            size(rustix::termios::tcgetwinsize(std::io::stdout()).ok())
        } else {
            (None, None)
        };
        Ok(Self {
            home: usable_home(paths::home()?)?,
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            no_color,
            stdout_tty,
            stdin_tty: std::io::stdin().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
            columns,
            rows,
            pager: Pager::resolve(
                no_color,
                stdout_tty,
                std::env::var_os("BX_PAGER").as_deref(),
                std::env::var_os("PAGER").as_deref(),
                std::env::var_os("LESS").as_deref(),
            ),
            user: account(std::env::var("USER").ok(), std::env::var("LOGNAME").ok()),
        })
    }

    /// The pager `text` goes through: [`Env::pager`], where `text` is at least
    /// as tall as the terminal. A rendering exactly as tall is paged too, since
    /// the line after it — a shell prompt, or `apply`'s question — would push
    /// its first line off the screen.
    #[must_use]
    pub fn pager_for(&self, text: &str) -> Option<&Pager> {
        let rows = usize::from(self.rows?);
        let lines = text.lines().count();
        self.pager.as_ref().filter(|_| rows > 0 && lines >= rows)
    }
}

/// The columns and rows of a terminal's window size, each `None` where the
/// terminal reports zero, which is how one says it does not know.
fn size(size: Option<rustix::termios::Winsize>) -> (Option<u16>, Option<u16>) {
    let known = |n: u16| (n > 0).then_some(n);
    size.map_or((None, None), |size| {
        (known(size.ws_col), known(size.ws_row))
    })
}

/// The program a rendering taller than the terminal is shown through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pager {
    /// The command, run by `sh -c`, so it may carry its own arguments as
    /// `$PAGER` conventionally does.
    pub command: String,
    /// What `LESS` is set to for it: [`LESS_OPTIONS`], after whatever `$LESS`
    /// already held. A `less` then shows colour, exits at once where
    /// everything fits, and leaves the plan on the screen when it exits, so
    /// the question put next follows it: see [`Pager::resolve`].
    pub less: OsString,
}

/// The options `less` is always given through `LESS`: `F` exits at once where
/// everything fits, `R` shows colour, and `X` keeps the terminal's alternate
/// screen out of it, so what was paged stays on the screen once it exits.
pub const LESS_OPTIONS: &str = "FRX";

/// What bx pages through when neither `$BX_PAGER` nor `$PAGER` names one.
pub const DEFAULT_PAGER: &str = "less -FRX";

/// The status `sh -c` exits with where it found the command but could not
/// run it.
const NOT_RUN: i32 = 126;

/// The status `sh -c` exits with where it found no such command.
const NOT_FOUND: i32 = 127;

impl Pager {
    /// The pager, or `None` where nothing is paged: standard output is not a
    /// terminal, `NO_COLOR` asks for plain output, or `$BX_PAGER` is set to
    /// the empty string, which is the one switch that turns paging off.
    ///
    /// Otherwise `$BX_PAGER`, else a `$PAGER` that is not empty, else
    /// [`DEFAULT_PAGER`].
    ///
    /// `less` is `$LESS`. [`LESS_OPTIONS`] are appended to it, rather than set
    /// only where it is unset: under a `LESS=-R`, as a shell framework
    /// exports, `less` would otherwise run on the alternate screen and wipe
    /// the plan before the question about it is put. Every option `$LESS`
    /// gave that these do not override is kept.
    #[must_use]
    pub fn resolve(
        no_color: bool,
        stdout_tty: bool,
        bx_pager: Option<&OsStr>,
        pager: Option<&OsStr>,
        less: Option<&OsStr>,
    ) -> Option<Self> {
        if no_color || !stdout_tty {
            return None;
        }
        let command = match bx_pager {
            Some(chosen) if chosen.is_empty() => return None,
            Some(chosen) => chosen.to_string_lossy().into_owned(),
            None => pager.filter(|pager| !pager.is_empty()).map_or_else(
                || DEFAULT_PAGER.to_string(),
                |p| p.to_string_lossy().into_owned(),
            ),
        };
        Some(Self {
            command,
            less: keep_on_screen(less),
        })
    }

    /// Show `text` through this pager, returning once it exits, so whatever
    /// is written next — `apply`'s question — follows it on the screen.
    ///
    /// `Ok(false)` where the pager could not be started, and nothing was
    /// shown: the caller writes `text` itself. That is the case too where
    /// `sh` started but exited 126 or 127, which is how it says the command
    /// was not found or could not be run — the default `less -FRX` where no
    /// `less` is installed. A pager quit before it read everything is not an
    /// error.
    ///
    /// # Errors
    ///
    /// The error writing `text` to it, or waiting for it.
    pub fn page(&self, text: &str) -> std::io::Result<bool> {
        use std::io::Write as _;

        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg(&self.command)
            .stdin(std::process::Stdio::piped());
        command.env("LESS", &self.less);
        let Ok(mut child) = command.spawn() else {
            return Ok(false);
        };
        let written = child
            .stdin
            .take()
            .map_or(Ok(()), |mut stdin| stdin.write_all(text.as_bytes()));
        let waited = child.wait();
        match written {
            Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => return Err(error),
            _ => {}
        }
        waited.map(|status| !matches!(status.code(), Some(NOT_RUN | NOT_FOUND)))
    }
}

/// `LESS` for the pager: [`LESS_OPTIONS`] after what `inherited` holds, as an
/// option of their own, or alone where it holds nothing but blanks.
fn keep_on_screen(inherited: Option<&OsStr>) -> OsString {
    match inherited.filter(|less| !less.as_encoded_bytes().iter().all(u8::is_ascii_whitespace)) {
        None => OsString::from(LESS_OPTIONS),
        Some(less) => {
            let mut kept = less.to_owned();
            kept.push(" -");
            kept.push(LESS_OPTIONS);
            kept
        }
    }
}

/// The account's name: `user`, else `logname`, whichever is not empty
/// first.
fn account(user: Option<String>, logname: Option<String>) -> Option<String> {
    user.filter(|name| !name.is_empty())
        .or_else(|| logname.filter(|name| !name.is_empty()))
}

/// `home`, refused when it has a `..` component.
///
/// Not normalised: `/a/..` is not `/` when `/a` is a symlink, and every path bx
/// writes is rendered against the home, so a home bx cannot name exactly is
/// refused here, naming `HOME`, rather than by the first target beneath it.
fn usable_home(home: PathBuf) -> Result<PathBuf, Error> {
    if home
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(Error::HomeParentComponent(home));
    }
    Ok(home)
}

/// Whether a `NO_COLOR` value asks for no colour: set, to anything but the
/// empty string.
fn no_color(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn decision_21_a_home_with_a_parent_component_is_refused_and_any_other_is_kept() {
        let climbing = "/var/home/../home/u";
        let refused = usable_home(PathBuf::from(climbing)).expect_err("a `..` home");
        assert!(
            matches!(&refused, Error::HomeParentComponent(path) if path == Path::new(climbing)),
            "{refused:?}"
        );
        assert!(
            refused
                .to_string()
                .starts_with("HOME has a `..` component: /var/home/../home/u;"),
            "{refused}"
        );

        // Kept exactly as spelled: bx does not normalise a home.
        for kept in ["/var/home/u", "/var/home/u/", "/var//home/./u"] {
            assert_eq!(
                usable_home(PathBuf::from(kept)).expect("kept"),
                PathBuf::from(kept)
            );
        }
    }

    #[test]
    fn no_color_is_asked_for_by_any_value_but_the_empty_string() {
        assert!(!no_color(None));
        assert!(!no_color(Some(OsStr::new(""))));
        assert!(no_color(Some(OsStr::new("1"))));
        assert!(no_color(Some(OsStr::new("0"))));
    }

    #[test]
    fn the_account_is_user_else_logname_and_never_empty() {
        let some = |name: &str| Some(name.to_string());
        assert_eq!(account(some("u"), some("l")), some("u"));
        assert_eq!(account(None, some("l")), some("l"));
        assert_eq!(account(some(""), some("l")), some("l"));
        assert_eq!(account(some(""), some("")), None);
        assert_eq!(account(None, None), None);
    }

    fn pager(command: &str, less: &str) -> Option<Pager> {
        Some(Pager {
            command: command.to_string(),
            less: OsString::from(less),
        })
    }

    #[test]
    fn a_pager_is_chosen_only_on_a_terminal_with_colour_and_paging_on() {
        let os = |value: &'static str| Some(OsStr::new(value));
        // Off a terminal, or under NO_COLOR, nothing is paged whatever is set.
        assert_eq!(
            Pager::resolve(false, false, os("more"), os("most"), None),
            None
        );
        assert_eq!(
            Pager::resolve(true, true, os("more"), os("most"), None),
            None
        );
        // `BX_PAGER=` empty is the switch that turns it off.
        assert_eq!(Pager::resolve(false, true, os(""), os("most"), None), None);
        // `BX_PAGER`, else a `PAGER` that is not empty, else `less -FRX`.
        assert_eq!(
            Pager::resolve(false, true, os("more"), os("most"), None),
            pager("more", "FRX")
        );
        assert_eq!(
            Pager::resolve(false, true, None, os("most"), None),
            pager("most", "FRX")
        );
        assert_eq!(
            Pager::resolve(false, true, None, os(""), None),
            pager(DEFAULT_PAGER, "FRX")
        );
        assert_eq!(
            Pager::resolve(false, true, None, None, None),
            pager(DEFAULT_PAGER, "FRX")
        );
    }

    #[test]
    fn an_inherited_less_still_keeps_the_plan_on_the_screen() {
        let less = |value: &'static str| {
            Pager::resolve(false, true, None, None, Some(OsStr::new(value)))
                .expect("a pager")
                .less
        };
        // oh-my-zsh's `LESS=-R` alone runs `less` on the alternate screen,
        // which wipes the plan before the question about it is put.
        assert_eq!(less("-R"), "-R -FRX");
        // Every option it gave is kept, ahead of the ones bx needs.
        assert_eq!(less("-i -x4"), "-i -x4 -FRX");
        assert_eq!(less("SR"), "SR -FRX");
        // Set to nothing but blanks, it gives no option of its own.
        assert_eq!(less(""), "FRX");
        assert_eq!(less(" \t"), "FRX");
    }

    #[test]
    fn a_rendering_is_paged_once_it_is_as_tall_as_the_terminal() {
        let env = |rows: Option<u16>, pager: Option<Pager>| Env {
            home: PathBuf::from("/var/home/example"),
            xdg_config_home: None,
            xdg_state_home: None,
            no_color: false,
            stdout_tty: true,
            stdin_tty: true,
            stderr_tty: true,
            columns: Some(80),
            rows,
            pager,
            user: None,
        };
        let less = pager(DEFAULT_PAGER, LESS_OPTIONS);
        let tall = "a\nb\nc\n";
        assert_eq!(env(Some(3), less.clone()).pager_for(tall), less.as_ref());
        assert_eq!(env(Some(2), less.clone()).pager_for(tall), less.as_ref());
        assert_eq!(env(Some(4), less.clone()).pager_for(tall), None);
        // No height known, a height of zero, or no pager: never paged.
        assert_eq!(env(None, less.clone()).pager_for(tall), None);
        assert_eq!(env(Some(0), less).pager_for(tall), None);
        assert_eq!(env(Some(1), None).pager_for(tall), None);
    }

    #[test]
    fn a_window_size_of_zero_is_unknown() {
        let winsize = |ws_col, ws_row| rustix::termios::Winsize {
            ws_col,
            ws_row,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(size(None), (None, None));
        assert_eq!(size(Some(winsize(120, 40))), (Some(120), Some(40)));
        assert_eq!(size(Some(winsize(0, 40))), (None, Some(40)));
        assert_eq!(size(Some(winsize(120, 0))), (Some(120), None));
    }

    #[test]
    fn a_pager_is_given_the_whole_text_and_waited_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seen = dir.path().join("seen");
        let less = dir.path().join("less");
        let command = format!(
            "cat > '{}'; printf %s \"$LESS\" > '{}'",
            seen.display(),
            less.display()
        );
        let shown = Pager::resolve(
            false,
            true,
            Some(command.as_ref()),
            None,
            Some("-R".as_ref()),
        )
        .expect("a pager")
        .page("one\ntwo\n")
        .expect("paged");
        assert!(shown);
        // Waited for: what it wrote is there once `page` returns.
        assert_eq!(std::fs::read_to_string(&seen).expect("seen"), "one\ntwo\n");
        assert_eq!(std::fs::read_to_string(&less).expect("LESS"), "-R -FRX");

        // A pager that quits without reading is no error.
        let quit = pager("exit 0", "FRX").expect("a pager");
        assert!(quit.page(&"x\n".repeat(1 << 20)).expect("quit early"));
    }

    #[test]
    fn a_pager_that_does_not_exist_or_cannot_run_has_shown_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-pager").display().to_string();
        let missing = pager(&missing, "FRX").expect("a pager");
        assert!(!missing.page("one\ntwo\n").expect("not shown"));

        let unrunnable = dir.path().join("unrunnable");
        std::fs::write(&unrunnable, "#!/bin/sh\n").expect("write");
        let unrunnable = pager(&unrunnable.display().to_string(), "FRX").expect("a pager");
        assert!(!unrunnable.page("one\n").expect("not shown"));

        // Any other status is a pager that ran, and its own business.
        let failed = pager("exit 1", "FRX").expect("a pager");
        assert!(failed.page("one\n").expect("ran"));
    }

    #[test]
    fn the_process_environment_is_read_as_it_is() {
        let env = Env::from_process();
        match std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            Some(home) if Path::new(&home).is_absolute() => {
                let env = env.expect("a usable HOME");
                assert_eq!(env.home, PathBuf::from(home));
                assert_eq!(env.xdg_state_home, std::env::var_os("XDG_STATE_HOME"));
                assert_eq!(env.xdg_config_home, std::env::var_os("XDG_CONFIG_HOME"));
                assert_eq!(
                    env.no_color,
                    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
                );
            }
            _ => assert!(matches!(env, Err(Error::Home(_)))),
        }
    }
}
