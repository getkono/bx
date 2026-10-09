//! Check 11: a `local.toml` inside the config repo, which bx never loads.
//!
//! The config repo is a git working tree meant to be published, so
//! [`crate::config::layers`] skips any `local.toml` in it and loads this
//! account's layer from the state directory alone. A user who put machine
//! values there would otherwise see them ignored with nothing saying why.
//! [`layers::stray_local`] finds the file; this check names it and the move
//! that makes it count. It reads the repo root and `modules/`, and nothing
//! else.

use std::path::Path;

use super::Finding;
use crate::config::{Error, layers};
use crate::paths;
use crate::state::StateDir;

/// A finding for a `local.toml` in `repo`, or for a repo doctor could not
/// examine for one.
#[must_use]
pub fn check(repo: &Path, state: &StateDir, home: &Path) -> Vec<Finding> {
    match layers::stray_local(repo) {
        Ok(None) => Vec::new(),
        Ok(Some(stray)) => vec![Finding {
            subject: paths::to_portable(&stray, home),
            origin: None,
            note: format!(
                "is inside the config repo, so bx never loads it and could publish it; move \
                 what it holds into {}, the local layer bx loads",
                paths::to_portable(&state.local_toml(), home)
            ),
        }],
        Err(Error::Io { path, source }) => vec![unexamined(
            paths::to_portable(&path, home),
            &source.to_string(),
        )],
        Err(error) => vec![unexamined(
            paths::to_portable(repo, home),
            &error.to_string(),
        )],
    }
}

/// The finding for a path doctor could not look at.
fn unexamined(subject: String, cause: &str) -> Finding {
    Finding {
        subject,
        origin: None,
        note: format!(
            "could not be examined ({cause}), so doctor cannot say whether a local.toml sits \
             in the config repo"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::guarded_home;

    fn found(home: &crate::testing::GuardedHome) -> Vec<Finding> {
        let state = StateDir::resolve(home.path());
        check(&home.child(".config/bx"), &state, home.path())
    }

    #[test]
    fn a_repo_without_a_local_toml_has_no_finding() {
        let home = guarded_home();
        home.write(".config/bx/bx.toml", "");
        home.write(".config/bx/modules/10-git.toml", "");
        home.write(".local/state/bx/local.toml", "");

        assert_eq!(found(&home), []);
    }

    #[test]
    fn a_local_toml_at_the_repo_root_is_named_with_the_move() {
        let home = guarded_home();
        home.write(".config/bx/local.toml", "[values]\n");

        assert_eq!(
            found(&home),
            [Finding {
                subject: "~/.config/bx/local.toml".to_string(),
                origin: None,
                note: "is inside the config repo, so bx never loads it and could publish it; \
                       move what it holds into ~/.local/state/bx/local.toml, the local layer \
                       bx loads"
                    .to_string(),
            }]
        );
    }

    #[test]
    fn a_local_toml_in_modules_is_named() {
        let home = guarded_home();
        home.write(".config/bx/modules/local.toml", "");

        let findings = found(&home);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].subject, "~/.config/bx/modules/local.toml");
    }

    #[test]
    fn a_local_toml_that_cannot_be_examined_is_a_finding_naming_it() {
        let home = guarded_home();
        std::fs::create_dir_all(home.child(".config/bx")).unwrap();
        std::os::unix::fs::symlink("nowhere", home.child(".config/bx/local.toml")).unwrap();

        let findings = found(&home);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].subject, "~/.config/bx/local.toml");
        assert!(
            findings[0].note.starts_with("could not be examined (")
                && findings[0].note.ends_with(
                    "), so doctor cannot say whether a local.toml sits in the config repo"
                ),
            "{}",
            findings[0].note
        );
    }
}
