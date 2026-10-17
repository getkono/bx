//! What `bx doctor` is told to expect of the machine: one `[doctor]` table.
//!
//! # The `[doctor]` schema
//!
//! ```toml
//! [doctor]
//! login-shell = "zsh"   # the shell this account logs in to: "zsh" or "bash"
//! ```
//!
//! Every key is optional. Without `login-shell`, doctor asks nothing about the
//! account's login shell. With it, doctor reads the shell the account database
//! names for this account and reports one that is not the asserted shell, with
//! the `chsh` that changes it quoted, never run
//! ([`crate::doctor::login_shell`]).
//!
//! # Layers
//!
//! `[doctor]` is one table, not a keyed list, so it merges key by key, the
//! last layer that sets a key winning, as `[update]` does. Which shell an
//! account logs in to is usually the machine's, so it is usually written in
//! `local.toml`; a committed layer may set the shell every machine is expected
//! to have.

use std::path::Path;

use toml_edit::Table;

use super::shells::Shell;
use super::{Ctx, Error, Origin};

/// The section header, as messages spell it.
const SECTION: &str = "[doctor]";

/// The key that asserts the login shell.
const LOGIN_SHELL: &str = "login-shell";

/// Every key a `[doctor]` table may carry.
const KEYS: [&str; 1] = [LOGIN_SHELL];

/// The login shell the configuration asserts, and where it says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginShell {
    /// The shell the account is expected to log in to.
    pub shell: Shell,
    /// Where the `login-shell` key that set it was written.
    pub origin: Origin,
}

/// What one layer's `[doctor]` table says, or what the merged layers say.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Doctor {
    /// The asserted login shell, when a layer asserts one.
    pub login_shell: Option<LoginShell>,
}

impl Doctor {
    /// Fold a later layer's table over this one, key by key, the later layer
    /// winning.
    pub(crate) fn absorb(&mut self, later: &Self) {
        if let Some(login_shell) = &later.login_shell {
            self.login_shell = Some(login_shell.clone());
        }
    }
}

/// Parse a `[doctor]` table.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key beyond `login-shell`, [`Error::BadValue`]
/// for a `login-shell` that names no shell bx generates for, and
/// [`Error::WrongType`] for one that is not a string.
pub fn parse_doctor(table: &Table, file: &Path, text: &str) -> Result<Doctor, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;
    let login_shell = ctx
        .str_at(table, LOGIN_SHELL)?
        .map(|raw| {
            let shell = Shell::parse(raw).ok_or_else(|| {
                ctx.bad(
                    table,
                    LOGIN_SHELL,
                    format!("`{raw}` is not a shell bx generates for; write \"zsh\" or \"bash\""),
                )
            })?;
            Ok::<_, Error>(LoginShell {
                shell,
                origin: ctx.key_origin(table, LOGIN_SHELL),
            })
        })
        .transpose()?;
    Ok(Doctor { login_shell })
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml_edit::Document;

    fn parse(text: &str) -> Result<Doctor, String> {
        let doc = Document::parse(text).map_err(|e| e.to_string())?;
        let table = doc["doctor"].as_table().ok_or("no [doctor]")?;
        parse_doctor(table, Path::new("/repo/local.toml"), text).map_err(|e| e.to_string())
    }

    fn asserted(doctor: &Doctor) -> Option<(Shell, usize)> {
        doctor
            .login_shell
            .as_ref()
            .map(|login| (login.shell, login.origin.line))
    }

    #[test]
    fn each_shell_parses_at_its_key_line() {
        assert_eq!(
            asserted(&parse("[doctor]\nlogin-shell = \"zsh\"\n").unwrap()),
            Some((Shell::Zsh, 2))
        );
        assert_eq!(
            asserted(&parse("[doctor]\n\nlogin-shell = \"bash\"\n").unwrap()),
            Some((Shell::Bash, 3))
        );
        assert_eq!(asserted(&parse("[doctor]\n").unwrap()), None);
    }

    #[test]
    fn the_table_merges_key_by_key_the_later_layer_winning() {
        let mut merged = Doctor::default();
        assert_eq!(asserted(&merged), None);
        merged.absorb(&parse("[doctor]\nlogin-shell = \"bash\"\n").unwrap());
        assert_eq!(asserted(&merged), Some((Shell::Bash, 2)));
        merged.absorb(&parse("[doctor]\n").unwrap());
        assert_eq!(asserted(&merged), Some((Shell::Bash, 2)), "unset keeps");
        merged.absorb(&parse("[doctor]\n\n\nlogin-shell = \"zsh\"\n").unwrap());
        assert_eq!(asserted(&merged), Some((Shell::Zsh, 4)), "later wins");
    }

    #[test]
    fn an_unknown_key_or_a_shell_that_is_not_one_is_a_load_error_at_its_line() {
        let err = parse("[doctor]\nshell = \"zsh\"\n").unwrap_err();
        assert!(err.contains("unknown key `shell` in [doctor]"), "{err}");
        let err = parse("[doctor]\nlogin-shell = \"fish\"\n").unwrap_err();
        assert!(err.starts_with("/repo/local.toml:2:"), "{err}");
        assert!(err.contains("`fish` is not a shell"), "{err}");
        assert!(err.contains("\"zsh\" or \"bash\""), "{err}");
        let err = parse("[doctor]\nlogin-shell = 1\n").unwrap_err();
        assert!(err.contains("a string"), "{err}");
    }
}
