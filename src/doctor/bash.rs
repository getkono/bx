//! Check 12: bash's generated file asks about followed externals' updates,
//! and the `bash` on `PATH` is too old to register the question.
//!
//! The hook ([`crate::shell::update_prompt::BASH`]) registers itself on bash
//! [`BASH_SINCE`] or later only. An older bash — macOS's `/bin/bash` is 3.2 —
//! sources the file cleanly and leaves the hook out, saying nothing, so a
//! person on it would never be asked about an update. This is where that is
//! said.
//!
//! The question is put only when the file holds the hook, and then to the
//! `bash` the shell would start: the first one on `PATH`, asked
//! `bash --version`, which reads and runs nothing of the account's. A `bash`
//! not on `PATH` at all is no finding here: nothing then reads the file.

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Stdio};

use super::Finding;
use crate::config::resolve::Resolution;
use crate::config::target::{Body, Gen, Target};
use crate::detect::{self, Presence};
use crate::shell::update_prompt::BASH_SINCE;

/// The question put to a `bash`: its `(major, minor)` version.
pub trait Query {
    /// The version of the `bash` at `program`.
    ///
    /// # Errors
    ///
    /// Why it could not be read.
    fn version(&self, program: &Path) -> Result<(u32, u32), String>;
}

/// [`Query`] through `bash --version`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Version;

impl Query for Version {
    fn version(&self, program: &Path) -> Result<(u32, u32), String> {
        tracing::debug!(program = %program.display(), "asking bash --version");
        let output = Command::new(program)
            .arg("--version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|error| format!("running {}: {error}", program.display()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse(&stdout).ok_or_else(|| {
            format!(
                "{} --version printed no version: {:?}",
                program.display(),
                stdout.lines().next().unwrap_or_default()
            )
        })
    }
}

/// The `(major, minor)` in `bash --version`'s first line,
/// `GNU bash, version 3.2.57(1)-release (arm64-apple-darwin25)`.
#[must_use]
pub fn parse(stdout: &str) -> Option<(u32, u32)> {
    let (_, rest) = stdout.lines().next()?.split_once("version ")?;
    let mut numbers = rest.split(['.', '(', ' ', '-']);
    let major = numbers.next()?.parse().ok()?;
    let minor = numbers.next()?.parse().ok()?;
    Some((major, minor))
}

/// A finding when a resolved bash file holds the update hook and the `bash`
/// first on `path` is older than [`BASH_SINCE`], or cannot say which it is.
#[must_use]
pub fn check(targets: &[Resolution<Target>], path: &OsStr, query: &dyn Query) -> Vec<Finding> {
    let Some(file) = targets.iter().find_map(|resolution| match resolution {
        Resolution::Ready(
            target @ Target {
                body: Body::Generated(Gen::Bash(bash)),
                ..
            },
        ) if bash.update_prompt() => Some(target),
        _ => None,
    }) else {
        return Vec::new();
    };
    let Presence::Present { path: program } = detect::locate("bash", path) else {
        return Vec::new();
    };
    let (major, minor) = BASH_SINCE;
    let note = match query.version(&program) {
        Ok(found) if found >= BASH_SINCE => return Vec::new(),
        Ok((has_major, has_minor)) => format!(
            "{} is bash {has_major}.{has_minor}, older than {major}.{minor}, so this file leaves \
             out its question about followed externals' updates and that bash is never asked; \
             put bash {major}.{minor} or later ahead of it on PATH, or run `bx update` yourself",
            program.display()
        ),
        Err(why) => format!(
            "could not tell whether {} is bash {major}.{minor} or later, which this file's \
             question about followed externals' updates needs: {why}",
            program.display()
        ),
    };
    vec![Finding {
        subject: file.path.to_string(),
        origin: Some(file.origin.clone()),
        note,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Origin;
    use crate::config::target::{Attach, Bash, Direction, Format};
    use crate::paths::Portable;

    /// A `bash` that answers every question with `answer`.
    struct Answers(Result<(u32, u32), String>);

    impl Query for Answers {
        fn version(&self, _: &Path) -> Result<(u32, u32), String> {
            self.0.clone()
        }
    }

    fn file(update_prompt: bool) -> Resolution<Target> {
        Resolution::Ready(Target {
            path: Portable::parse_in(crate::shell::bash::FILE, Path::new("/h")).expect("portable"),
            body: Body::Generated(Gen::Bash(Box::new(
                Bash::default().with_update_prompt(update_prompt),
            ))),
            mode: None,
            attach: Attach::Own,
            direction: Direction::Apply,
            format: Format::Opaque,
            requires: Vec::new(),
            references: Vec::new(),
            enabled: true,
            origin: Origin {
                file: "/repo/bx.toml".into(),
                line: 3,
            },
        })
    }

    /// A directory holding an executable `bash`, for `PATH`.
    fn with_bash() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a directory");
        let bash = dir.path().join("bash");
        std::fs::write(&bash, "#!/bin/sh\n").expect("a bash");
        crate::fs::set_mode(&bash, crate::fs::Mode::from_bits(0o755)).expect("executable");
        dir
    }

    #[test]
    fn bash_s_version_line_is_read_on_both_platforms() {
        assert_eq!(
            parse("GNU bash, version 3.2.57(1)-release (arm64-apple-darwin25)\nCopyright\n"),
            Some((3, 2))
        );
        assert_eq!(
            parse("GNU bash, version 5.2.37(1)-release (x86_64-redhat-linux-gnu)\n"),
            Some((5, 2))
        );
        assert_eq!(parse("GNU bash, version 4.4.20(1)-release\n"), Some((4, 4)));
        assert_eq!(parse(""), None);
        assert_eq!(parse("zsh 5.9\n"), None);
        assert_eq!(parse("GNU bash, version x.y\n"), None);
    }

    #[test]
    fn an_old_bash_is_a_finding_only_when_the_file_holds_the_hook() {
        let dir = with_bash();
        let path = dir.path().as_os_str();
        let old = Answers(Ok((3, 2)));

        let found = check(&[file(true)], path, &old);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].subject, crate::shell::bash::FILE);
        assert_eq!(found[0].origin.as_ref().map(|o| o.line), Some(3));
        assert!(
            found[0].note.contains("is bash 3.2, older than 4.4")
                && found[0]
                    .note
                    .contains(&dir.path().join("bash").display().to_string()),
            "{}",
            found[0].note
        );

        // No hook in the file, nothing to leave out.
        assert!(check(&[file(false)], path, &old).is_empty());
        assert!(check(&[], path, &old).is_empty());
        // 4.4 and later register it.
        for new in [(4, 4), (4, 10), (5, 0)] {
            assert!(
                check(&[file(true)], path, &Answers(Ok(new))).is_empty(),
                "{new:?}"
            );
        }
        assert!(!check(&[file(true)], path, &Answers(Ok((4, 3)))).is_empty());
        // No bash on PATH: nothing reads the file.
        assert!(check(&[file(true)], OsStr::new(""), &old).is_empty());
    }

    #[test]
    fn a_bash_that_cannot_say_its_version_is_a_finding() {
        let dir = with_bash();
        let found = check(
            &[file(true)],
            dir.path().as_os_str(),
            &Answers(Err("no answer".to_string())),
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].note.ends_with(": no answer"), "{}", found[0].note);
    }

    #[test]
    fn the_installed_bash_says_its_version() {
        let Some(bash) = crate::shell::testing::installed("bash") else {
            return;
        };
        let (major, _) = Version.version(&bash).expect("a version");
        assert!(major >= 3, "{major}");
        // A program that prints no version line of bash's is an error naming
        // it. Not a stand-in written here: on Linux, executing a file just
        // written can meet `ETXTBSY` from another test thread's fork.
        let why = Version
            .version(Path::new("/usr/bin/true"))
            .expect_err("no version");
        assert!(why.contains("printed no version"), "{why}");
        let dir = tempfile::tempdir().expect("a directory");
        let why = Version
            .version(&dir.path().join("absent"))
            .expect_err("no program");
        assert!(why.starts_with("running "), "{why}");
    }
}
