//! Everything bx takes from the process it runs in.
//!
//! [`Env::from_process`] reads the process environment and its terminals on
//! the path every command takes; the one other read on that path is the
//! `PATH` that `plan::Inputs::load` takes through
//! `activation::System::from_env`, for a declared activation's tool and a
//! `has:TOOL` condition. Every other function is handed the [`Env`] it read,
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
        Ok(Self {
            home: usable_home(paths::home()?)?,
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            no_color: no_color(std::env::var_os("NO_COLOR").as_deref()),
            stdout_tty: std::io::stdout().is_terminal(),
            stdin_tty: std::io::stdin().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
        })
    }
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
