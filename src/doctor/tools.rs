//! Check 1: every tool the configuration names is an executable on `PATH`.
//!
//! Two declarations name a tool: a `[[tool]]` entry ([`crate::config::tool`]),
//! and a target's `requires`. Both are asked the same question, and a name
//! both of them give is one finding, not two: the `[[tool]]` entry's, carrying
//! its `install` command and naming the targets that require it. A name only
//! `requires` gives is a finding of its own, declared where the first target
//! requiring it was.
//!
//! `requires` never gates a target: a target naming an absent tool is still
//! written, because a tool's configuration file is worth having in place
//! before the tool is installed. Reporting the tool here is the whole of what
//! `requires` does. A target held back ([`Resolution::Blocked`]) is not read:
//! its `requires` may still hold a value it has no answer for, and the block
//! is reported by `plan`.
//!
//! A tool is looked up by its name alone, with [`detect::locate`] — `stat` and
//! `access`, never a process — so a tool installed under another file name is
//! reported missing: bx says what it can honestly check. A `requires` entry
//! may name a program by an absolute path, which is looked at where it names.
//! A missing tool's `install` command is quoted in the finding and never run;
//! nothing in this module builds a command line.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::Path;

use super::Finding;
use crate::config::Origin;
use crate::config::resolve::Resolution;
use crate::config::target::Target;
use crate::config::tool::ToolDecl;
use crate::detect::{self, Presence};
use crate::paths;

/// How a finding names a tool: by its name, or by its path, spelled portably,
/// when a `requires` entry names it by one.
#[must_use]
pub fn subject(name: &str, home: &Path) -> String {
    if name.contains('/') {
        format!("tool {}", paths::to_portable(Path::new(name), home))
    } else {
        format!("tool {name}")
    }
}

/// One tool name, with every declaration that gives it.
struct Named<'a> {
    name: &'a str,
    declared: Option<&'a ToolDecl>,
    required_by: Vec<&'a Target>,
}

/// Every tool name the configuration gives, once each: the `[[tool]]`
/// entries in configuration order, then each name only a `requires` gives,
/// in the order it is first required.
fn named<'a>(tools: &'a [ToolDecl], targets: &'a [Resolution<Target>]) -> Vec<Named<'a>> {
    let mut named: Vec<Named<'a>> = tools
        .iter()
        .map(|tool| Named {
            name: &tool.name,
            declared: Some(tool),
            required_by: Vec::new(),
        })
        .collect();
    let ready = targets.iter().filter_map(|resolution| match resolution {
        Resolution::Ready(target) => Some(target),
        Resolution::Blocked(_) => None,
    });
    for target in ready {
        for tool in &target.requires {
            match named.iter_mut().find(|n| n.name == tool) {
                Some(entry) => {
                    // A target naming one tool twice requires it once.
                    if !entry.required_by.iter().any(|t| std::ptr::eq(*t, target)) {
                        entry.required_by.push(target);
                    }
                }
                None => named.push(Named {
                    name: tool,
                    declared: None,
                    required_by: vec![target],
                }),
            }
        }
    }
    named
}

/// A finding for every tool a `[[tool]]` entry or a ready target's `requires`
/// names that is not an executable on `path_var`: the declared tools in
/// configuration order, then the tools only `requires` names.
#[must_use]
pub fn check(
    tools: &[ToolDecl],
    targets: &[Resolution<Target>],
    path_var: &OsStr,
    home: &Path,
) -> Vec<Finding> {
    named(tools, targets)
        .into_iter()
        .filter_map(|tool| finding(&tool, path_var, home))
        .collect()
}

/// The finding for one tool, if it is not an executable.
fn finding(tool: &Named<'_>, path_var: &OsStr, home: &Path) -> Option<Finding> {
    let by_path = tool.name.contains('/');
    let mut note = match detect::locate(tool.name, path_var) {
        Presence::Present { .. } => return None,
        Presence::NotExecutable { path } if by_path => format!(
            "is at {}, but this account cannot execute it",
            paths::to_portable(&path, home)
        ),
        Presence::NotExecutable { path } => format!(
            "is on PATH at {}, but this account cannot execute it",
            paths::to_portable(&path, home)
        ),
        Presence::Missing => {
            let missing = if by_path {
                "is not an executable file"
            } else {
                "is not on PATH"
            };
            match tool.declared.map(|decl| decl.install.as_deref()) {
                Some(Some(install)) => format!("{missing}; `{install}` installs it"),
                Some(None) => format!("{missing}, and declares no `install` command"),
                None => format!("{missing}, and no `[[tool]]` entry declares it"),
            }
        }
    };
    if let Some((first, rest)) = tool.required_by.split_first() {
        let first = first.path.as_str();
        let _ = match rest.len() {
            0 => write!(note, "; {first} requires it"),
            more => write!(note, "; {first} and {more} other target(s) require it"),
        };
    }
    let origin: Origin = match (tool.declared, tool.required_by.first()) {
        (Some(decl), _) => decl.origin.clone(),
        (None, Some(target)) => target.origin.clone(),
        (None, None) => return None,
    };
    Some(Finding {
        subject: subject(tool.name, home),
        origin: Some(origin),
        note,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use super::*;
    use crate::config::target::{Attach, Body, Direction, Format};
    use crate::paths::Portable;

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
            &[],
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
            &[],
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
            &[],
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

        let findings = check(
            &[tool("rg", None, 1)],
            &[],
            bin_dir.as_os_str(),
            home.path(),
        );

        assert_eq!(
            findings[0].note,
            "is on PATH at ~/.local/bin/rg, but this account cannot execute it"
        );
    }

    fn target(path: &str, requires: &[&str], line: usize) -> Resolution<Target> {
        Resolution::Ready(Target {
            path: Portable::parse_in(path, Path::new("/home/u")).expect("a portable path"),
            body: Body::Inline("x\n".to_string()),
            mode: None,
            attach: Attach::Own,
            direction: Direction::Apply,
            format: Format::Opaque,
            requires: requires.iter().map(|r| (*r).to_string()).collect(),
            references: Vec::new(),
            enabled: true,
            origin: Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line,
            },
        })
    }

    fn blocked(line: usize) -> Resolution<Target> {
        Resolution::Blocked(crate::config::resolve::BlockedEntry {
            key: "~/.held".to_string(),
            reason: crate::config::resolve::BlockReason::UnsetValue {
                names: vec!["tool".to_string()],
            },
            hint: "answer it".to_string(),
            origin: Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line,
            },
        })
    }

    fn rows(findings: &[Finding]) -> Vec<(String, String, usize)> {
        findings
            .iter()
            .map(|f| {
                (
                    f.subject.clone(),
                    f.note.clone(),
                    f.origin.as_ref().expect("an origin").line,
                )
            })
            .collect()
    }

    #[test]
    fn a_required_tool_is_folded_into_its_declaration_and_an_undeclared_one_stands_alone() {
        let dir = tempfile::tempdir().unwrap();
        bin(dir.path(), "rg", 0o755);

        let findings = check(
            &[
                tool("nvim", Some("sudo dnf install neovim"), 1),
                tool("rg", None, 2),
            ],
            &[
                target("~/.config/nvim/init.lua", &["nvim"], 10),
                target("~/.config/starship.toml", &["starship", "starship"], 20),
                target("~/.config/nvim/lua/a.lua", &["nvim", "rg"], 30),
                blocked(40),
                target("~/.config/nvim/lua/b.lua", &["nvim"], 50),
                target("~/.config/fish/config.fish", &["starship"], 60),
            ],
            &OsString::from(dir.path()),
            Path::new("/home/u"),
        );

        assert_eq!(
            rows(&findings),
            vec![
                (
                    "tool nvim".to_string(),
                    "is not on PATH; `sudo dnf install neovim` installs it; \
                     ~/.config/nvim/init.lua and 2 other target(s) require it"
                        .to_string(),
                    1
                ),
                (
                    "tool starship".to_string(),
                    "is not on PATH, and no `[[tool]]` entry declares it; \
                     ~/.config/starship.toml and 1 other target(s) require it"
                        .to_string(),
                    20
                ),
            ],
            "one finding per tool, declared first, a duplicate named once, \
             a present tool and a blocked target nothing"
        );
    }

    #[test]
    fn a_tool_required_by_one_target_names_it_alone() {
        let findings = check(
            &[tool("jq", None, 3)],
            &[target("~/.jqrc", &["jq"], 9)],
            OsStr::new(""),
            Path::new("/home/u"),
        );

        assert_eq!(
            rows(&findings),
            vec![(
                "tool jq".to_string(),
                "is not on PATH, and declares no `install` command; ~/.jqrc requires it"
                    .to_string(),
                3
            )]
        );
    }

    #[test]
    fn a_tool_required_by_path_is_looked_at_where_it_names() {
        let home = tempfile::tempdir().unwrap();
        let bin_dir = home.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        bin(&bin_dir, "held", 0o600);
        bin(&bin_dir, "ok", 0o755);
        let at = |name: &str| bin_dir.join(name).to_str().unwrap().to_string();

        let findings = check(
            &[],
            &[target("~/.a", &[&at("held"), &at("gone"), &at("ok")], 4)],
            OsStr::new(""),
            home.path(),
        );

        assert_eq!(
            rows(&findings),
            vec![
                (
                    "tool ~/bin/held".to_string(),
                    "is at ~/bin/held, but this account cannot execute it; ~/.a requires it"
                        .to_string(),
                    4
                ),
                (
                    "tool ~/bin/gone".to_string(),
                    "is not an executable file, and no `[[tool]]` entry declares it; \
                     ~/.a requires it"
                        .to_string(),
                    4
                ),
            ]
        );
    }
}
