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
/// everything fits, `R` shows colour, `X` keeps the terminal's alternate
/// screen out of it, so what was paged stays on the screen once it exits, and
/// `K` exits at once on Ctrl-C, which [`Pager::page`] reports as
/// [`Paged::Interrupted`].
pub const LESS_OPTIONS: &str = "FRXK";

/// What became of a rendering handed to [`Pager::page`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paged {
    /// The pager ran and exited, so the rendering was shown.
    Shown,
    /// The pager could not be started, and nothing was shown: the caller
    /// writes the rendering itself.
    NotRun,
    /// Ctrl-C reached bx while the pager ran. A terminal sends it to the
    /// pager and bx alike; bx outlives it so that it can say what it did not
    /// do, and asks nothing that would have followed.
    Interrupted,
}

/// A signal caught only while a pager runs: elsewhere it does what it would
/// without the handler, which for `SIGINT` is to end bx.
pub(crate) struct Interrupt {
    /// How many pagers run, under the lock that keeps `outside` in step.
    running: std::sync::Mutex<usize>,
    /// Whether no pager runs, so the signal takes its default action.
    outside: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Whether the signal arrived since the first running pager started.
    seen: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Interrupt {
    /// Catch `signal` from now on, through no pager yet. The default action
    /// is registered first, so a signal arriving outside a pager takes it
    /// before anything records the signal as seen.
    fn catching(signal: i32) -> std::io::Result<Self> {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let outside = Arc::new(AtomicBool::new(true));
        let seen = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register_conditional_default(signal, Arc::clone(&outside))?;
        signal_hook::flag::register(signal, Arc::clone(&seen))?;
        Ok(Self {
            running: std::sync::Mutex::new(0),
            outside,
            seen,
        })
    }

    /// Run `pager`, with the signal caught and not acted on throughout, and
    /// whether it arrived meanwhile.
    fn during<T>(&self, pager: impl FnOnce() -> T) -> (T, bool) {
        use std::sync::atomic::Ordering::SeqCst;

        /// Leaves the pager on drop, so a panic does not leave the signal
        /// caught for good.
        struct Running<'a>(&'a Interrupt);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                let mut running = self.0.lock();
                *running = running.saturating_sub(1);
                if *running == 0 {
                    self.0.outside.store(true, SeqCst);
                }
            }
        }

        {
            let mut running = self.lock();
            if *running == 0 {
                self.seen.store(false, SeqCst);
            }
            *running += 1;
            self.outside.store(false, SeqCst);
        }
        let _running = Running(self);
        let ran = pager();
        (ran, self.seen.load(SeqCst))
    }

    /// The count of running pagers, which no panic leaves unusable.
    fn lock(&self) -> std::sync::MutexGuard<'_, usize> {
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// `SIGINT`, caught while a pager runs from the first paging on, or `None`
/// where its handler could not be installed and the pager runs as it did
/// without one.
pub(crate) fn interrupt() -> Option<&'static Interrupt> {
    static SIGINT: std::sync::OnceLock<Option<Interrupt>> = std::sync::OnceLock::new();
    SIGINT
        .get_or_init(|| {
            Interrupt::catching(signal_hook::consts::SIGINT)
                .inspect_err(|error| tracing::debug!(%error, "Ctrl-C is not caught while paging"))
                .ok()
        })
        .as_ref()
}

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
    /// [`Paged::NotRun`] where the pager could not be started, and nothing
    /// was shown: the caller writes `text` itself. That is the case too where
    /// `sh` started but exited 126 or 127, which is how it says the command
    /// was not found or could not be run — the default `less -FRX` where no
    /// `less` is installed. A pager quit before it read everything is not an
    /// error.
    ///
    /// Ctrl-C while it runs ends the pager and not bx: [`Paged::Interrupted`],
    /// so the caller cancels what would have followed.
    ///
    /// # Errors
    ///
    /// The error writing `text` to it, or waiting for it.
    pub fn page(&self, text: &str) -> std::io::Result<Paged> {
        self.page_catching(text, interrupt())
    }

    /// [`Pager::page`], with `interrupt` caught while the pager runs.
    fn page_catching(&self, text: &str, interrupt: Option<&Interrupt>) -> std::io::Result<Paged> {
        use std::io::Write as _;

        let run = || {
            let spawned = std::process::Command::new("sh")
                .arg("-c")
                .arg(&self.command)
                .env("LESS", &self.less)
                .stdin(std::process::Stdio::piped())
                .spawn();
            let Ok(mut child) = spawned else {
                return Ok(None);
            };
            let written = child
                .stdin
                .take()
                .map_or(Ok(()), |mut stdin| stdin.write_all(text.as_bytes()));
            let waited = child.wait();
            match written {
                Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => Err(error),
                _ => waited.map(Some),
            }
        };
        let (ran, interrupted) = match interrupt {
            Some(interrupt) => interrupt.during(run),
            None => (run(), false),
        };
        Ok(match ran? {
            None => Paged::NotRun,
            Some(status) if matches!(status.code(), Some(NOT_RUN | NOT_FOUND)) => Paged::NotRun,
            Some(_) if interrupted => Paged::Interrupted,
            Some(_) => Paged::Shown,
        })
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
            pager("more", "FRXK")
        );
        assert_eq!(
            Pager::resolve(false, true, None, os("most"), None),
            pager("most", "FRXK")
        );
        assert_eq!(
            Pager::resolve(false, true, None, os(""), None),
            pager(DEFAULT_PAGER, "FRXK")
        );
        assert_eq!(
            Pager::resolve(false, true, None, None, None),
            pager(DEFAULT_PAGER, "FRXK")
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
        assert_eq!(less("-R"), "-R -FRXK");
        // Every option it gave is kept, ahead of the ones bx needs.
        assert_eq!(less("-i -x4"), "-i -x4 -FRXK");
        assert_eq!(less("SR"), "SR -FRXK");
        // Set to nothing but blanks, it gives no option of its own.
        assert_eq!(less(""), "FRXK");
        assert_eq!(less(" \t"), "FRXK");
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
        // Uncaught: the Ctrl-C another test sends bx is not this pager's.
        .page_catching("one\ntwo\n", None)
        .expect("paged");
        assert_eq!(shown, Paged::Shown);
        // Waited for: what it wrote is there once `page` returns.
        assert_eq!(std::fs::read_to_string(&seen).expect("seen"), "one\ntwo\n");
        assert_eq!(std::fs::read_to_string(&less).expect("LESS"), "-R -FRXK");

        // A pager that quits without reading is no error.
        let quit = pager("exit 0", LESS_OPTIONS).expect("a pager");
        assert_eq!(
            quit.page_catching(&"x\n".repeat(1 << 20), None)
                .expect("quit early"),
            Paged::Shown
        );
    }

    #[test]
    fn a_pager_that_does_not_exist_or_cannot_run_has_shown_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-pager").display().to_string();
        let missing = pager(&missing, LESS_OPTIONS).expect("a pager");
        assert_eq!(
            missing.page("one\ntwo\n").expect("not shown"),
            Paged::NotRun
        );

        let unrunnable = dir.path().join("unrunnable");
        std::fs::write(&unrunnable, "#!/bin/sh\n").expect("write");
        let unrunnable = pager(&unrunnable.display().to_string(), LESS_OPTIONS).expect("a pager");
        assert_eq!(unrunnable.page("one\n").expect("not shown"), Paged::NotRun);

        // Any other status is a pager that ran, and its own business.
        let failed = pager("exit 1", LESS_OPTIONS).expect("a pager");
        assert_eq!(
            failed.page_catching("one\n", None).expect("ran"),
            Paged::Shown
        );
    }

    #[test]
    fn an_interrupt_while_the_pager_runs_ends_the_pager_and_not_bx() {
        use signal_hook::consts::SIGURG;

        // SIGURG stands in for SIGINT, which would end this test process
        // where it arrived outside a pager; its default action is to be
        // ignored, and nothing else here catches it.
        let interrupt = Interrupt::catching(SIGURG).expect("caught");
        let dir = tempfile::tempdir().expect("tempdir");
        let ack = dir.path().join("ack");
        // Written once bx's handler has run, after it marked the signal seen,
        // so the pager below exits only once bx has caught it.
        let acked = std::fs::File::create(&ack).expect("ack");
        signal_hook::low_level::pipe::register(SIGURG, acked).expect("acked");

        // A terminal's Ctrl-C reaches the pager and bx alike; `less -K`
        // exits 2 on it.
        let interrupted = pager(
            &format!(
                "kill -URG $PPID; until [ -s '{}' ]; do :; done; exit 2",
                ack.display()
            ),
            LESS_OPTIONS,
        )
        .expect("a pager");
        assert_eq!(
            interrupted
                .page_catching("one\n", Some(&interrupt))
                .expect("interrupted"),
            Paged::Interrupted
        );
        assert!(
            interrupt.outside.load(std::sync::atomic::Ordering::SeqCst),
            "once the pager is gone the signal takes its default action again"
        );

        // The next pager starts without it.
        let quiet = pager("cat > /dev/null", LESS_OPTIONS).expect("a pager");
        assert_eq!(
            quiet
                .page_catching("one\n", Some(&interrupt))
                .expect("shown"),
            Paged::Shown
        );
        // A pager that never started showed nothing, interrupted or not.
        let missing = dir.path().join("no-such-pager").display().to_string();
        let missing = pager(&missing, LESS_OPTIONS).expect("a pager");
        let (paged, seen) = interrupt.during(|| {
            signal_hook::low_level::raise(SIGURG).expect("raised");
            missing.page_catching("one\n", Some(&interrupt))
        });
        assert!(seen);
        assert_eq!(paged.expect("not shown"), Paged::NotRun);

        // Two pagers at once: the signal is caught until the last exits,
        // and seen by both.
        let ((seen_inner, outside_between), seen_outer) = interrupt.during(|| {
            let ((), seen_inner) = interrupt.during(|| {
                signal_hook::low_level::raise(SIGURG).expect("raised");
            });
            (
                seen_inner,
                interrupt.outside.load(std::sync::atomic::Ordering::SeqCst),
            )
        });
        assert!(seen_inner && seen_outer);
        assert!(!outside_between);
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
