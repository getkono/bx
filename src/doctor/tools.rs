//! Check 1: every declared tool ([`crate::config::tool`]) is an executable on
//! `PATH`.
//!
//! A tool is looked up by its name alone, with [`detect::locate`] — `stat` and
//! `access`, never a process — so a tool installed under another file name is
//! reported missing: bx says what it can honestly check. A missing tool's
//! `install` command is quoted in the finding and never run; nothing in this
//! module builds a command line.

use std::ffi::OsStr;
use std::path::Path;

use super::Finding;
use crate::config::tool::ToolDecl;
use crate::detect::{self, Presence};
use crate::paths;

/// How a finding names a tool.
#[must_use]
pub fn subject(name: &str) -> String {
    format!("tool {name}")
}

/// A finding for every declared tool that is not an executable on `path_var`,
/// in configuration order.
#[must_use]
pub fn check(tools: &[ToolDecl], path_var: &OsStr, home: &Path) -> Vec<Finding> {
    tools
        .iter()
        .filter_map(|tool| {
            let note = match detect::locate(&tool.name, path_var) {
                Presence::Present { .. } => return None,
                Presence::NotExecutable { path } => format!(
                    "is on PATH at {}, but this account cannot execute it",
                    paths::to_portable(&path, home)
                ),
                Presence::Missing => match &tool.install {
                    Some(install) => format!("is not on PATH; `{install}` installs it"),
                    None => "is not on PATH, and declares no `install` command".to_string(),
                },
            };
            Some(Finding {
                subject: subject(&tool.name),
                origin: Some(tool.origin.clone()),
                note,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use super::*;
    use crate::config::Origin;

    fn tool(name: &str, install: Option<&str>, line: usize) -> ToolDecl {
        ToolDecl {
            name: name.to_string(),
            install: install.map(str::to_string),
            enabled: true,
            origin: Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line,
            },
        }
    }

    fn bin(dir: &Path, name: &str, mode: u32) {
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_present_tool_is_no_finding_and_the_rest_are_named_in_order() {
        let dir = tempfile::tempdir().unwrap();
        bin(dir.path(), "rg", 0o755);
        bin(dir.path(), "fd", 0o644);
        let path_var = OsString::from(dir.path());

        let findings = check(
            &[
                tool("jq", None, 7),
                tool("rg", Some("never shown"), 1),
                tool("fd", None, 4),
                tool("bat", Some("sudo dnf install bat"), 10),
            ],
            &path_var,
            Path::new("/home/u"),
        );

        let notes: Vec<(&str, &str, usize)> = findings
            .iter()
            .map(|f| {
                (
                    f.subject.as_str(),
                    f.note.as_str(),
                    f.origin.as_ref().unwrap().line,
                )
            })
            .collect();
        let fd = format!(
            "is on PATH at {}, but this account cannot execute it",
            dir.path().join("fd").display()
        );
        assert_eq!(
            notes,
            vec![
                (
                    "tool jq",
                    "is not on PATH, and declares no `install` command",
                    7
                ),
                ("tool fd", fd.as_str(), 4),
                (
                    "tool bat",
                    "is not on PATH; `sudo dnf install bat` installs it",
                    10
                ),
            ]
        );
    }

    #[test]
    fn a_tool_is_looked_up_by_its_name_and_nothing_else() {
        // The package is "installed" under another file name: `ripgrep`'s
        // binary is `rg`, and a tool declared as `ripgrep` is not on PATH.
        let dir = tempfile::tempdir().unwrap();
        bin(dir.path(), "rg", 0o755);

        let findings = check(
            &[tool("ripgrep", Some("sudo dnf install ripgrep"), 1)],
            &OsString::from(dir.path()),
            Path::new("/home/u"),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].subject, "tool ripgrep");
    }

    #[test]
    fn an_install_command_is_printed_and_never_run() {
        // Were the install command run, it would create this file.
        let dir = tempfile::tempdir().unwrap();
        let witness = dir.path().join("ran");
        let install = format!("touch {}", witness.display());

        let findings = check(
            &[tool("absent-tool", Some(&install), 1)],
            OsStr::new("/usr/bin:/bin"),
            Path::new("/home/u"),
        );

        assert_eq!(
            findings[0].note,
            format!("is not on PATH; `{install}` installs it")
        );
        assert!(!witness.exists(), "the install command was run");
    }

    #[test]
    fn a_path_under_home_is_named_portably() {
        let home = tempfile::tempdir().unwrap();
        let bin_dir = home.path().join(".local/bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        bin(&bin_dir, "rg", 0o600);

        let findings = check(&[tool("rg", None, 1)], bin_dir.as_os_str(), home.path());

        assert_eq!(
            findings[0].note,
            "is on PATH at ~/.local/bin/rg, but this account cannot execute it"
        );
    }
}
