//! Systemd user units: written by bx like any other file, checked by `bx
//! doctor` against what the user's systemd has made of them.
//!
//! A unit is not a kind of target. It is an ordinary file target whose path is
//! a direct child of the user unit directory ([`crate::paths::systemd_user_dir_in`])
//! and whose name has a suffix systemd loads from a file there. Writing it is
//! all `apply` does: bx never reloads, enables or starts anything. What doctor
//! adds is the part a user would otherwise find out later — that the file is
//! written but systemd has not reloaded it, that it is written but not enabled,
//! or that it is enabled and has failed.
//!
//! The only question put to systemd is one `systemctl --user show` for every
//! unit at once, with a fixed argument list ([`ARGS`]) and the unit names after
//! `--`. No other command line is built anywhere in this module, so no code
//! path can ask for a reload, an enable or a start.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use super::Finding;
use crate::config::Origin;
use crate::config::resolve::Resolution;
use crate::config::target::Target;
use crate::paths;

/// The unit types systemd loads from a file in the user unit directory.
///
/// `device` and `scope` are missing on purpose: a device unit comes from udev
/// and a scope unit is only ever created at runtime, so a file with either
/// suffix is not something systemd reads.
pub const SUFFIXES: &[&str] = &[
    "automount",
    "mount",
    "path",
    "service",
    "slice",
    "socket",
    "swap",
    "target",
    "timer",
];

/// The properties asked for, in the order a [`State`] is read from.
const PROPERTIES: &str = "--property=LoadState,ActiveState,UnitFileState,NeedDaemonReload";

/// The whole command line but the unit names: a read-only status query of the
/// user's systemd, and nothing else.
pub const ARGS: &[&str] = &["--user", "--no-pager", "show", PROPERTIES, "--"];

/// The subject of the one finding a run reports when systemd cannot be asked.
pub const SESSION: &str = "systemd --user";

/// A unit file bx declared, and that is on disk to be checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    /// The unit's name, as systemd knows it: `name.suffix`.
    pub name: String,
    /// The target, spelled portably, as `plan` names it.
    pub target: String,
    /// Where the target was declared.
    pub origin: Origin,
}

/// The unit name `path` has when it is a unit file in `unit_dir`, or `None`.
///
/// `None` for anything that is not a direct child of `unit_dir` — a drop-in
/// under `name.service.d/`, a link under `name.target.wants/`, a file anywhere
/// else — for a suffix systemd does not load from a file, for a name systemd
/// would refuse, and for a template (`name@.service`), which is never a unit
/// itself, only the source of its instances. Lexical, like every path
/// comparison in bx: nothing is resolved on disk.
#[must_use]
pub fn unit_name(path: &Path, unit_dir: &Path) -> Option<String> {
    let path = paths::normalize(path);
    if path.parent()? != paths::normalize(unit_dir) {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let (stem, suffix) = name.rsplit_once('.')?;
    // systemd's own alphabet for a unit name; `\` is how `systemd-escape`
    // spells everything outside it, as in `mnt-scratch\x2ddisk.mount`.
    let valid =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-' | '@' | '\\');
    if stem.is_empty()
        || stem.ends_with('@')
        || !SUFFIXES.contains(&suffix)
        || !stem.chars().all(valid)
    {
        return None;
    }
    Some(name.to_string())
}

/// The unit files among `targets` that are on disk, in configuration order.
///
/// A target held back by resolution has no path to look at, and one that is
/// declared but not yet on disk has nothing for systemd to be stale about:
/// neither is a unit to check. Whatever is at the path counts — a file bx
/// wrote, one it has yet to update, or one in conflict — because systemd reads
/// what is there, not what bx means to write.
#[must_use]
pub fn units(targets: &[Resolution<Target>], home: &Path, unit_dir: &Path) -> Vec<Unit> {
    targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) => Some(target),
            Resolution::Blocked(_) => None,
        })
        .filter_map(|target| {
            let path = target.path.render(home);
            let name = unit_name(&path, unit_dir)?;
            std::fs::symlink_metadata(&path).ok()?;
            Some(Unit {
                name,
                target: target.path.as_str().to_string(),
                origin: target.origin.clone(),
            })
        })
        .collect()
}

/// What systemd says about one unit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// `LoadState`: `loaded`, `not-found`, `bad-setting`, `error`, `masked`.
    pub load: String,
    /// `ActiveState`: `active`, `inactive`, `failed`, and the transitions.
    pub active: String,
    /// `UnitFileState`: `enabled`, `disabled`, `static`, and the rest.
    pub file: String,
    /// `NeedDaemonReload`: the file on disk changed after systemd loaded it.
    pub need_reload: bool,
}

/// systemd could not be asked, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreachable(pub String);

/// The one question doctor puts to systemd.
pub trait Query {
    /// The state of each of `names`, in the same order.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] when systemd cannot be asked, or its answer cannot be
    /// read — the whole question fails, never one unit of it.
    fn show(&self, names: &[String]) -> Result<Vec<State>, Unreachable>;
}

/// [`Query`] through `systemctl --user show`.
#[derive(Debug, Clone)]
pub struct Systemctl {
    program: OsString,
    leading: Vec<OsString>,
}

impl Default for Systemctl {
    fn default() -> Self {
        Self {
            program: OsString::from("systemctl"),
            leading: Vec::new(),
        }
    }
}

impl Systemctl {
    /// `program`, with `leading` before [`ARGS`], in place of `systemctl`: a
    /// test's `sh -c SCRIPT sh`, so a canned answer needs no executable file.
    #[cfg(test)]
    fn stand_in(program: &str, leading: &[&str]) -> Self {
        Self {
            program: OsString::from(program),
            leading: leading.iter().map(OsString::from).collect(),
        }
    }
}

impl Query for Systemctl {
    fn show(&self, names: &[String]) -> Result<Vec<State>, Unreachable> {
        tracing::debug!(units = names.len(), "asking systemctl --user show");
        let output = Command::new(&self.program)
            .args(&self.leading)
            .args(ARGS)
            .args(names)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| Unreachable(format!("running systemctl: {error}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let why = stderr
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map_or_else(
                    || format!("systemctl {}", output.status),
                    ToString::to_string,
                );
            return Err(Unreachable(why));
        }
        parse(&String::from_utf8_lossy(&output.stdout), names.len())
    }
}

/// Read `systemctl show`'s answer: one block of `Key=value` lines per unit, in
/// the order the units were named, separated by a blank line.
///
/// # Errors
///
/// [`Unreachable`] when there are not `expected` blocks, so no block can be
/// matched to its unit.
pub fn parse(stdout: &str, expected: usize) -> Result<Vec<State>, Unreachable> {
    let text = stdout.trim_matches('\n');
    let blocks: Vec<&str> = if text.is_empty() {
        Vec::new()
    } else {
        text.split("\n\n").collect()
    };
    if blocks.len() != expected {
        return Err(Unreachable(format!(
            "systemctl answered for {} unit(s), not {expected}",
            blocks.len()
        )));
    }
    Ok(blocks
        .into_iter()
        .map(|block| {
            let mut state = State::default();
            for (key, value) in block.lines().filter_map(|line| line.split_once('=')) {
                match key {
                    "LoadState" => state.load = value.to_string(),
                    "ActiveState" => state.active = value.to_string(),
                    "UnitFileState" => state.file = value.to_string(),
                    "NeedDaemonReload" => state.need_reload = value == "yes",
                    _ => {}
                }
            }
            state
        })
        .collect())
}

/// Every finding about `units`, asking `query` once, and not at all when there
/// is no unit to ask about.
///
/// When systemd cannot be asked the run gets exactly one finding, naming how
/// many units went unchecked, rather than one per unit: the cause is the
/// session, not any unit, and it is cleared once.
pub fn check(units: &[Unit], query: &dyn Query) -> Vec<Finding> {
    if units.is_empty() {
        return Vec::new();
    }
    let names: Vec<String> = units.iter().map(|unit| unit.name.clone()).collect();
    match query.show(&names) {
        Err(Unreachable(why)) => vec![Finding {
            subject: SESSION.to_string(),
            origin: None,
            note: format!(
                "is unreachable, so {} unit file(s) went unchecked: {why}",
                units.len()
            ),
        }],
        Ok(states) => units
            .iter()
            .zip(&states)
            .flat_map(|(unit, state)| findings(unit, state))
            .collect(),
    }
}

/// What is worth a human's attention about one unit, in a fixed order: reload,
/// load, enable, failure.
fn findings(unit: &Unit, state: &State) -> Vec<Finding> {
    let name = &unit.name;
    let finding = |note: String| Finding {
        subject: unit.target.clone(),
        origin: Some(unit.origin.clone()),
        note,
    };
    // systemd has not read the file at all, so nothing else it says is about
    // this file.
    if state.load == "not-found" {
        return vec![finding(not_reloaded())];
    }
    let mut out = Vec::new();
    if state.need_reload {
        out.push(finding(not_reloaded()));
    }
    match state.load.as_str() {
        "bad-setting" | "error" => out.push(finding(format!(
            "systemd could not load it ({}); see `systemctl --user status {name}`",
            state.load
        ))),
        "masked" => out.push(finding(format!(
            "is masked; `systemctl --user unmask {name}` lifts it"
        ))),
        _ => {}
    }
    if state.file == "disabled" {
        out.push(finding(format!(
            "is written but not enabled; `systemctl --user enable {name}` enables it"
        )));
    }
    if state.active == "failed" {
        out.push(finding(format!(
            "has failed; see `systemctl --user status {name}`"
        )));
    }
    out
}

/// The note for a unit file systemd has not reloaded.
fn not_reloaded() -> String {
    "is written but not reloaded; `systemctl --user daemon-reload` reloads it".to_string()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;

    use super::*;
    use crate::plan::tests::inputs;
    use crate::testing::guarded_home;

    const DIR: &str = "/var/home/example/.config/systemd/user";

    fn name(path: &str) -> Option<String> {
        unit_name(Path::new(path), Path::new(DIR))
    }

    #[test]
    fn a_unit_file_is_a_direct_child_with_a_recognised_suffix() {
        for suffix in SUFFIXES {
            assert_eq!(
                name(&format!("{DIR}/app.{suffix}")),
                Some(format!("app.{suffix}"))
            );
        }
        assert_eq!(
            name(&format!("{DIR}/app-work.slice")),
            Some("app-work.slice".to_string())
        );
        assert_eq!(
            name(&format!("{DIR}/mnt-scratch\\x2ddisk.mount")),
            Some("mnt-scratch\\x2ddisk.mount".to_string()),
            "an escaped name is a name"
        );
        assert_eq!(
            name(&format!("{DIR}/sub/../app.timer")),
            Some("app.timer".to_string()),
            "decided lexically, after normalising"
        );
        assert_eq!(
            unit_name(
                Path::new(&format!("{DIR}/app.service")),
                Path::new(&format!("{DIR}/"))
            ),
            Some("app.service".to_string())
        );
    }

    #[test]
    fn a_template_is_not_a_unit_but_an_instance_is() {
        assert_eq!(name(&format!("{DIR}/app@.service")), None);
        assert_eq!(
            name(&format!("{DIR}/app@one.service")),
            Some("app@one.service".to_string())
        );
    }

    #[test]
    fn anything_else_is_not_a_unit() {
        for path in [
            "/var/home/example/.config/app.service".to_string(),
            "/var/home/example/.config/systemd/app.service".to_string(),
            format!("{DIR}/app.service.d/override.conf"),
            format!("{DIR}/default.target.wants/app.service"),
            format!("{DIR}/app.conf"),
            format!("{DIR}/app.device"),
            format!("{DIR}/app.scope"),
            format!("{DIR}/app"),
            format!("{DIR}/.service"),
            format!("{DIR}/my app.service"),
            format!("{DIR}/app!.service"),
            DIR.to_string(),
            "/".to_string(),
        ] {
            assert_eq!(name(&path), None, "{path}");
        }
    }

    #[test]
    fn only_ready_targets_on_disk_in_the_unit_directory_are_units() {
        let home = guarded_home();
        let layer = "\
[[target]]
path = \"~/.config/systemd/user/on-disk.service\"
content = \"[Service]\\n\"

[[target]]
path = \"~/.config/systemd/user/not-yet.timer\"
content = \"[Timer]\\n\"

[[target]]
path = \"~/.config/systemd/on-disk.service\"
content = \"[Service]\\n\"

[[target]]
path = \"~/.config/systemd/user/app@.service\"
content = \"[Service]\\n\"

[[value]]
name = \"slice\"
kind = \"string\"

[[target]]
path = \"~/.config/systemd/user/{{slice}}.slice\"
content = \"[Slice]\\n\"
";
        for rel in [
            ".config/systemd/user/on-disk.service",
            ".config/systemd/on-disk.service",
            ".config/systemd/user/app@.service",
        ] {
            home.write(rel, "[Service]\n");
        }
        let inputs = inputs(&home, layer);
        let dir = paths::systemd_user_dir_in(home.path(), None);

        let found = units(inputs.targets(), home.path(), &dir);

        assert_eq!(
            found
                .iter()
                .map(|unit| (unit.name.as_str(), unit.target.as_str(), unit.origin.line))
                .collect::<Vec<_>>(),
            [(
                "on-disk.service",
                "~/.config/systemd/user/on-disk.service",
                1
            )]
        );
    }

    #[test]
    fn a_dangling_link_is_still_on_disk() {
        let home = guarded_home();
        let dir = home.child(".config/systemd/user");
        std::fs::create_dir_all(&dir).expect("the unit directory");
        std::os::unix::fs::symlink(home.child("missing"), dir.join("link.service"))
            .expect("a link");
        let inputs = inputs(
            &home,
            "[[target]]\npath = \"~/.config/systemd/user/link.service\"\ncontent = \"x\"\n",
        );

        assert_eq!(units(inputs.targets(), home.path(), &dir).len(), 1);
    }

    #[test]
    fn show_output_is_one_block_per_unit_in_order() {
        let stdout = "LoadState=loaded\nActiveState=failed\nNeedDaemonReload=yes\n\
                      UnitFileState=enabled\n\nLoadState=not-found\nActiveState=inactive\n\
                      NeedDaemonReload=no\nUnitFileState=\nIgnored=1\nno equals sign\n";

        assert_eq!(
            parse(stdout, 2).expect("two blocks"),
            [
                State {
                    load: "loaded".into(),
                    active: "failed".into(),
                    file: "enabled".into(),
                    need_reload: true,
                },
                State {
                    load: "not-found".into(),
                    active: "inactive".into(),
                    file: String::new(),
                    need_reload: false,
                },
            ]
        );
    }

    #[test]
    fn a_show_output_that_does_not_match_the_units_is_refused() {
        assert_eq!(
            parse("LoadState=loaded\n", 2),
            Err(Unreachable(
                "systemctl answered for 1 unit(s), not 2".to_string()
            ))
        );
        assert_eq!(
            parse("\n", 1),
            Err(Unreachable(
                "systemctl answered for 0 unit(s), not 1".to_string()
            ))
        );
        assert_eq!(parse("", 0), Ok(Vec::new()));
    }

    fn sh(script: &str) -> Systemctl {
        Systemctl::stand_in("/bin/sh", &["-c", script, "sh"])
    }

    #[test]
    fn the_only_command_line_is_a_read_only_show() {
        // The stand-in fails, printing the arguments it was given, so the whole
        // command line comes back as the reason.
        let query = sh("printf '%s\\n' \"$*\" >&2; exit 1");

        let error = query
            .show(&["a.service".to_string(), "b.timer".to_string()])
            .expect_err("the stand-in fails");

        assert_eq!(
            error,
            Unreachable(
                "--user --no-pager show \
                 --property=LoadState,ActiveState,UnitFileState,NeedDaemonReload -- a.service \
                 b.timer"
                    .to_string()
            )
        );
        for word in ["daemon-reload", "enable", "start", "restart", "reload"] {
            assert!(!ARGS.contains(&word), "{word}");
        }
    }

    #[test]
    fn a_successful_show_is_parsed() {
        let query = sh("printf 'LoadState=loaded\\nUnitFileState=disabled\\n\\n\
                        LoadState=masked\\n'");

        let states = query
            .show(&["a.service".to_string(), "b.timer".to_string()])
            .expect("an answer");

        assert_eq!(states[0].file, "disabled");
        assert_eq!(states[1].load, "masked");
    }

    #[test]
    fn a_failure_with_nothing_on_stderr_names_the_status() {
        let error = sh("exit 3")
            .show(&["a.service".to_string()])
            .expect_err("the stand-in fails");

        assert_eq!(error, Unreachable("systemctl exit status: 3".to_string()));
    }

    #[test]
    fn a_missing_systemctl_is_unreachable() {
        let error = Systemctl::stand_in("/nonexistent/bx-test/systemctl", &[])
            .show(&["a.service".to_string()])
            .expect_err("nothing to run");

        assert!(error.0.starts_with("running systemctl: "), "{error:?}");
    }

    #[test]
    fn the_default_query_is_systemctl_itself() {
        let query = Systemctl::default();
        assert_eq!(query.program, "systemctl");
        assert!(query.leading.is_empty());
    }

    /// A [`Query`] that answers from a list and counts the questions.
    struct Canned {
        answer: Result<Vec<State>, Unreachable>,
        asked: Cell<usize>,
    }

    impl Canned {
        fn new(answer: Result<Vec<State>, Unreachable>) -> Self {
            Self {
                answer,
                asked: Cell::new(0),
            }
        }
    }

    impl Query for Canned {
        fn show(&self, names: &[String]) -> Result<Vec<State>, Unreachable> {
            self.asked.set(self.asked.get() + 1);
            if let Ok(states) = &self.answer {
                assert_eq!(states.len(), names.len(), "one state per unit");
            }
            self.answer.clone()
        }
    }

    fn unit(name: &str) -> Unit {
        Unit {
            name: name.to_string(),
            target: format!("~/.config/systemd/user/{name}"),
            origin: Origin {
                file: PathBuf::from("/var/home/example/.config/bx/bx.toml"),
                line: 3,
            },
        }
    }

    fn state(load: &str, active: &str, file: &str, need_reload: bool) -> State {
        State {
            load: load.into(),
            active: active.into(),
            file: file.into(),
            need_reload,
        }
    }

    fn notes(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.note.as_str()).collect()
    }

    #[test]
    fn no_unit_asks_nothing() {
        let query = Canned::new(Err(Unreachable("never".into())));

        assert!(check(&[], &query).is_empty());
        assert_eq!(query.asked.get(), 0);
    }

    #[test]
    fn an_unreachable_session_is_one_finding_for_the_whole_run() {
        let query = Canned::new(Err(Unreachable("Failed to connect to bus".into())));
        let units = [unit("a.service"), unit("b.timer"), unit("c.slice")];

        let found = check(&units, &query);

        assert_eq!(query.asked.get(), 1, "one question for every unit");
        assert_eq!(
            found,
            [Finding {
                subject: SESSION.to_string(),
                origin: None,
                note: "is unreachable, so 3 unit file(s) went unchecked: Failed to connect to bus"
                    .to_string(),
            }]
        );
    }

    #[test]
    fn a_healthy_unit_has_no_finding() {
        for healthy in [
            state("loaded", "active", "enabled", false),
            state("loaded", "inactive", "static", false),
            state("loaded", "inactive", "linked", false),
        ] {
            assert!(findings(&unit("a.service"), &healthy).is_empty());
        }
    }

    #[test]
    fn each_stale_state_is_named_with_the_command_that_clears_it() {
        let a = unit("a.service");
        assert_eq!(
            notes(&findings(
                &a,
                &state("not-found", "failed", "disabled", true)
            )),
            ["is written but not reloaded; `systemctl --user daemon-reload` reloads it"],
            "an unread file has nothing else to say"
        );
        assert_eq!(
            notes(&findings(&a, &state("loaded", "failed", "disabled", true))),
            [
                "is written but not reloaded; `systemctl --user daemon-reload` reloads it",
                "is written but not enabled; `systemctl --user enable a.service` enables it",
                "has failed; see `systemctl --user status a.service`",
            ]
        );
        assert_eq!(
            notes(&findings(&a, &state("bad-setting", "inactive", "", false))),
            ["systemd could not load it (bad-setting); see `systemctl --user status a.service`"]
        );
        assert_eq!(
            notes(&findings(&a, &state("error", "inactive", "", false))),
            ["systemd could not load it (error); see `systemctl --user status a.service`"]
        );
        assert_eq!(
            notes(&findings(&a, &state("masked", "inactive", "masked", false))),
            ["is masked; `systemctl --user unmask a.service` lifts it"]
        );
    }

    #[test]
    fn findings_follow_the_units_and_carry_their_origin() {
        let units = [unit("a.service"), unit("b.timer")];
        let query = Canned::new(Ok(vec![
            state("loaded", "active", "enabled", false),
            state("loaded", "failed", "enabled", false),
        ]));

        let found = check(&units, &query);

        assert_eq!(
            found,
            [Finding {
                subject: "~/.config/systemd/user/b.timer".to_string(),
                origin: Some(units[1].origin.clone()),
                note: "has failed; see `systemctl --user status b.timer`".to_string(),
            }]
        );
    }
}
