//! The product invariants stated as properties over generated
//! configurations, rather than pinned by one example each: plan and apply
//! agree and converge (invariants 3 and 7), `rm` puts back every byte apply
//! displaced (invariant 4), and no fragment bx writes assigns a variable the
//! guard cannot judge (invariant 2).
//!
//! A generated configuration is a [`Layer`]: inline targets over whatever the
//! user or an earlier bx left at their paths, `[[env]]` variables of every
//! kind kept to either shell or both, `[aliases]`, the user's own shell
//! startup files, and an `[[external]]` cloned from an upstream in the home.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use super::decide::{guard_environment_d, guard_fragment};
use super::tests::{inline, load, own, seed, snapshot};
use super::{Action, Inputs, LedgerView, Mechanism, Mode, Report, StateDir, region, run};
use crate::config::env::ENVIRONMENT_D;
use crate::paths::Portable;
use crate::shell::bash;
use crate::sync::tests::{commit_all, git, run as git_run};
use crate::testing::{GuardedHome, guarded_home};

/// What is on disk at a generated target before bx runs.
#[derive(Debug, Clone)]
enum Before {
    Absent,
    /// The user wrote these bytes; bx never touched the file.
    Users(String),
    /// bx wrote it, holding this body: the target's own when `same`.
    Owned {
        body: String,
        same: bool,
    },
    /// bx wrote it and the user has since rewritten it.
    Edited(String),
}

/// One generated `[[target]]` and what its file holds beforehand.
#[derive(Debug, Clone)]
struct Generated {
    nested: bool,
    region: bool,
    body: String,
    before: Before,
}

impl Generated {
    /// Its path under the home, distinct for each `index`.
    fn rel(&self, index: usize) -> String {
        if self.nested {
            format!(".d{index}/p")
        } else {
            format!(".p{index}")
        }
    }

    /// Its `[[target]]`, as TOML.
    fn toml(&self, index: usize) -> String {
        let mut toml = inline(
            &format!("~/{}", self.rel(index)),
            &self.body.replace('\n', "\\n"),
        );
        if self.region {
            toml.push_str("attach = \"region\"\ncomment = \"#\"\n");
        }
        toml
    }

    /// The file bx would have left for `body`.
    fn written(&self, body: &str) -> Vec<u8> {
        if self.region {
            region::block('#', body.as_bytes())
        } else {
            body.as_bytes().to_vec()
        }
    }

    /// Put its `before` on disk under `home`, if the user wrote it.
    fn lay_down_users(&self, home: &Path, index: usize) {
        if let Before::Users(text) = &self.before {
            let path = home.join(self.rel(index));
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a parent");
            std::fs::write(&path, text).expect("the user's file");
        }
    }

    /// Put its `before` on disk under `home`, if bx wrote it.
    fn lay_down_owned(&self, home: &Path, index: usize) {
        let rel = self.rel(index);
        let mechanism = if self.region {
            Mechanism::Region { comment: '#' }
        } else {
            Mechanism::Own
        };
        match &self.before {
            Before::Absent | Before::Users(_) => {}
            Before::Owned { body, same } => {
                let body = if *same { &self.body } else { body };
                own(home, &rel, &self.written(body), mechanism);
            }
            Before::Edited(text) => {
                own(home, &rel, &self.written(&self.body), mechanism);
                std::fs::write(home.join(&rel), text).expect("the user's edit");
            }
        }
    }
}

/// When a declared variable has to be visible, as `kind` spells it.
const KINDS: [&str; 4] = ["environment", "gui", "login", "interactive"];

/// Every variable a generated `[[env]]` may name, each with the values it
/// may take and whether the guard approves each one under [`ROOT`]: names it
/// judges as a program, a command line, a setting, a location and a socket,
/// a name outside its table, one the shell reserves, and one bx reads to find
/// its own state.
const VARIABLES: [(&str, &[(&str, bool)]); 10] = [
    ("EDITOR", &[("nvim", true), ("{{scratch}}/bin/ed -w", true)]),
    ("PAGER", &[("less -R", true)]),
    ("RUSTC_WRAPPER", &[("sccache", true)]),
    (
        "CARGO_TERM_COLOR",
        &[("always", true), ("sometimes", false)],
    ),
    ("SCCACHE_CACHE_SIZE", &[("10G", true)]),
    (
        "CARGO_HOME",
        &[("{{scratch}}/cargo", true), ("~/.cargo", false)],
    ),
    ("SSH_AUTH_SOCK", &[("{{scratch}}/agent.sock", true)]),
    ("NOT_A_KNOWN_ONE", &[("x", false)]),
    ("HOME", &[("{{scratch}}/home", false)]),
    ("XDG_STATE_HOME", &[("{{scratch}}/state", false)]),
];

/// The one declared root, a path value every `{{scratch}}` names.
const ROOT: &str = "[[value]]\nname = \"scratch\"\nkind = \"path\"\nis_root = true\n\
                    default = \"~/scratch\"\n";

/// One generated `[[env]]` entry.
#[derive(Debug, Clone)]
struct Variable {
    name: &'static str,
    value: &'static str,
    /// Whether the guard approves `value` for `name` under [`ROOT`].
    approved: bool,
    kind: &'static str,
    /// The one shell it is kept to, when its kind lands in no
    /// `environment.d`.
    only: Option<&'static str>,
}

impl Variable {
    fn toml(&self) -> String {
        let mut toml = format!(
            "[[env]]\nname = \"{}\"\nvalue = \"{}\"\nkind = \"{}\"\n",
            self.name, self.value, self.kind
        );
        if let Some(shell) = self.only {
            toml.push_str(&format!("shells = [\"{shell}\"]\n"));
        }
        toml
    }

    /// Every generated file it lands in, relative to the home.
    fn files(&self) -> Vec<&'static str> {
        let zsh = self.only != Some("bash");
        let bash = self.only != Some("zsh");
        let mut files = Vec::new();
        if matches!(self.kind, "environment" | "gui") {
            files.push(&ENVIRONMENT_D[2..]);
        }
        if zsh {
            match self.kind {
                "environment" => files.push(".local/share/bx/zshenv.zsh"),
                "login" => files.push(".local/share/bx/zprofile.zsh"),
                "interactive" => files.push(ZSHRC),
                _ => {}
            }
        }
        if bash && self.kind != "gui" {
            files.push(&bash::FILE[2..]);
        }
        files
    }
}

/// zsh's generated interactive file, relative to the home.
const ZSHRC: &str = ".local/share/bx/zshrc.zsh";

/// Every alias a generated `[aliases]` may declare.
const ALIASES: [(&str, &str); 3] = [("ll", "ls -l"), ("gs", "git status"), ("k", "kubectl")];

/// The user's own shell startup files, each of which a region may attach to.
const STARTUP: [&str; 4] = [".zshenv", ".zprofile", ".zshrc", ".bashrc"];

/// Where the generated `[[external]]` is checked out, relative to the home.
const EXTERNAL: &str = ".ext";

/// The url it declares, which `~/.gitconfig` rewrites to `~/upstream`.
const URL: &str = "https://example.invalid/upstream";

/// One generated configuration and the home it is applied over.
#[derive(Debug, Clone)]
struct Layer {
    targets: Vec<Generated>,
    variables: Vec<Variable>,
    aliases: Vec<(&'static str, &'static str)>,
    /// The user's text in each of [`STARTUP`], where it exists.
    startup: Vec<Option<String>>,
    external: bool,
}

impl Layer {
    /// Lay down what the user wrote — their targets' files, their startup
    /// files, and the upstream an external clones — then return the layer's
    /// TOML.
    fn lay_down_users(&self, home: &GuardedHome) -> String {
        for (index, target) in self.targets.iter().enumerate() {
            target.lay_down_users(home.path(), index);
        }
        for (file, text) in STARTUP.iter().zip(&self.startup) {
            if let Some(text) = text {
                home.write(file, text);
            }
        }
        let mut toml = String::from(ROOT);
        if self.external {
            let rev = upstream(home);
            toml.push_str(&format!(
                "[[external]]\npath = \"~/{EXTERNAL}\"\nurl = \"{URL}\"\nrev = \"{rev}\"\n"
            ));
        }
        for (index, target) in self.targets.iter().enumerate() {
            toml.push_str(&target.toml(index));
        }
        for variable in &self.variables {
            toml.push_str(&variable.toml());
        }
        if !self.aliases.is_empty() {
            toml.push_str("[aliases]\n");
            for (name, command) in &self.aliases {
                toml.push_str(&format!("{name} = \"{command}\"\n"));
            }
        }
        toml
    }

    /// Lay down what an earlier bx wrote, and the user's edits over it.
    fn lay_down_owned(&self, home: &GuardedHome) {
        for (index, target) in self.targets.iter().enumerate() {
            target.lay_down_owned(home.path(), index);
        }
    }

    /// Lay everything down, seed the layer, and load it.
    fn inputs(&self, home: &GuardedHome) -> Inputs {
        let toml = self.lay_down_users(home);
        self.lay_down_owned(home);
        seed(home.path(), &toml);
        load(home.path()).with_git(git(home.path()))
    }
}

/// An upstream at `~/upstream` holding one commit, reachable as [`URL`];
/// returns that commit.
fn upstream(home: &GuardedHome) -> String {
    let dir = home.child("upstream");
    std::fs::create_dir_all(&dir).expect("the upstream");
    home.write(
        ".gitconfig",
        &format!(
            "[url \"file://{}/\"]\n\tinsteadOf = https://example.invalid/\n",
            home.path().display()
        ),
    );
    git_run(home.path(), &dir, &["init", "--quiet", "-b", "master"]);
    std::fs::write(dir.join("a.zsh"), "one\n").expect("a file");
    commit_all(home.path(), &dir, "first");
    git_run(home.path(), &dir, &["rev-parse", "HEAD"])
}

fn targets() -> impl Strategy<Value = Vec<Generated>> {
    let text = || "([a-z =]{0,6}\n){0,3}";
    let before = prop_oneof![
        Just(Before::Absent),
        text().prop_map(Before::Users),
        (text(), any::<bool>()).prop_map(|(body, same)| Before::Owned { body, same }),
        text().prop_map(Before::Edited),
    ];
    let target = (any::<bool>(), any::<bool>(), "([a-z]{1,6}\n){1,3}", before).prop_map(
        |(nested, region, body, before)| Generated {
            nested,
            region,
            body,
            before,
        },
    );
    proptest::collection::vec(target, 0..=3)
}

/// `[[env]]` entries over distinct names from [`VARIABLES`], each with one
/// of its values, any kind, and kept to one shell where its kind allows.
fn variables() -> impl Strategy<Value = Vec<Variable>> {
    let variable = |(name, values): (&'static str, &'static [(&'static str, bool)])| {
        (
            proptest::sample::select(values),
            proptest::sample::select(&KINDS[..]),
            proptest::option::of(proptest::sample::select(&["zsh", "bash"][..])),
        )
            .prop_map(move |((value, approved), kind, only)| Variable {
                name,
                value,
                approved,
                kind,
                only: only.filter(|_| matches!(kind, "login" | "interactive")),
            })
    };
    proptest::sample::subsequence(&VARIABLES[..], 0..=4)
        .prop_flat_map(move |chosen| chosen.into_iter().map(variable).collect::<Vec<_>>())
}

/// Generated configurations. The external is rarer than the rest, since it
/// costs an upstream and a clone.
fn layers() -> impl Strategy<Value = Layer> {
    (
        targets(),
        variables(),
        proptest::sample::subsequence(&ALIASES[..], 0..=2),
        proptest::collection::vec(proptest::option::of("([a-z =]{0,6}\n){0,2}"), STARTUP.len()),
        proptest::bool::weighted(0.2),
    )
        .prop_map(|(targets, variables, aliases, startup, external)| Layer {
            targets,
            variables,
            aliases,
            startup,
            external,
        })
}

/// Every path under `home` outside bx's records and the repo, keyed to its
/// bytes and mode. `~/.local` itself is left out too: bx creates it as the
/// state directory's ancestor, and keeps it for as long as it keeps records.
fn tree(home: &Path) -> BTreeMap<PathBuf, (Option<Vec<u8>>, u32)> {
    snapshot(home, &[".local/state", ".config/bx"])
        .into_iter()
        .filter(|(path, _, _)| path != Path::new(".local"))
        .map(|(path, bytes, mode)| (path, (bytes, mode)))
        .collect()
}

/// Each row's target, action, diff and note.
fn rows(report: &Report) -> Vec<(String, Action, Option<super::Diff>, Option<String>)> {
    report
        .changes
        .iter()
        .map(|c| (c.target.clone(), c.action, c.diff.clone(), c.note.clone()))
        .collect()
}

/// What bx would hand back: every target its ledger holds.
fn ledger(home: &Path) -> Vec<Portable> {
    LedgerView::read(&StateDir::resolve(home), home)
        .expect("the ledger")
        .value
        .iter()
        .map(|(target, _)| target.clone())
        .collect()
}

/// Whether `text` assigns `name` on any line, as `NAME=` or `export NAME=`.
fn assigns(text: &str, name: &str) -> bool {
    let assignment = format!("{name}=");
    text.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix("export ")
            .unwrap_or(line)
            .starts_with(&assignment)
    })
}

/// The body of `phase` in a generated interactive file: every line after its
/// header up to the next phase's.
fn phase<'a>(file: &'a str, phase: &str) -> &'a str {
    let header = format!("# bx phase: {phase}\n");
    file.find(&header).map_or("", |at| {
        let body = &file[at + header.len()..];
        body.find("\n# bx phase: ").map_or(body, |end| &body[..end])
    })
}

proptest::proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Invariants 3 and 7 over generated configurations: apply changes
    /// exactly the files plan announced and announces what plan did, and
    /// the plan after it announces no work.
    #[test]
    fn apply_changes_what_plan_announced_and_a_second_plan_is_empty(layer in layers()) {
        let home = guarded_home();
        let inputs = layer.inputs(&home);

        let untouched = snapshot(home.path(), &[]);
        let planned = run(&inputs, Mode::Plan, &mut |_| panic!("plan never asks"))
            .expect("plan runs");
        prop_assert_eq!(snapshot(home.path(), &[]), untouched, "plan wrote");
        let announced = planned
            .changes
            .iter()
            .filter(|change| matches!(change.action, Action::Create | Action::Modify))
            .map(|change| PathBuf::from(change.target.strip_prefix("~/").expect("in home")))
            .collect::<BTreeSet<_>>();

        let before = tree(home.path());
        let applied = run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("apply runs");
        let after = tree(home.path());
        prop_assert_eq!(rows(&applied), rows(&planned));
        prop_assert_eq!(applied.executed, !announced.is_empty());

        let changed = before
            .keys()
            .chain(after.keys())
            .filter(|path| before.get(*path) != after.get(*path))
            .collect::<BTreeSet<_>>();
        let (dirs, files): (BTreeSet<&PathBuf>, BTreeSet<&PathBuf>) = changed
            .iter()
            .partition(|path| home.path().join(path).is_dir());
        // Every file that changed is an announced target, or lies within an
        // announced external's checkout; every announced target changed.
        for file in &files {
            prop_assert!(
                announced.iter().any(|target| file.starts_with(target)),
                "{} changed unannounced",
                file.display()
            );
        }
        for target in &announced {
            prop_assert!(
                changed.iter().any(|path| path.starts_with(target)),
                "{} was announced and did not change",
                target.display()
            );
        }
        // A directory changes only by being created: as a parent of an
        // announced target, or within an announced checkout.
        for dir in dirs {
            prop_assert!(
                !before.contains_key(dir)
                    && announced
                        .iter()
                        .any(|target| target.starts_with(dir) || dir.starts_with(target)),
                "{} changed",
                dir.display()
            );
        }

        let second = run(&inputs, Mode::Plan, &mut |_| panic!("plan never asks"))
            .expect("the second plan");
        prop_assert!(
            second
                .changes
                .iter()
                .all(|change| !matches!(change.action, Action::Create | Action::Modify)),
            "{:?}",
            second.actions()
        );
        let again = run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve"))
            .expect("the second apply");
        prop_assert!(!again.executed);
        prop_assert_eq!(tree(home.path()), after);
    }

    /// Invariant 4 over generated configurations: `rm` of everything bx
    /// manages after an apply leaves the home byte for byte, and mode for
    /// mode, as the user had it before bx first wrote — except a file the
    /// user rewrote after bx wrote it, which `rm` will not restore over and
    /// leaves exactly as the user left it.
    #[test]
    fn rm_after_apply_restores_every_generated_home_byte_for_byte(layer in layers()) {
        let home = guarded_home();
        let toml = layer.lay_down_users(&home);
        seed(home.path(), &toml);
        let mut want = tree(home.path());
        layer.lay_down_owned(&home);
        let laid = tree(home.path());
        for (index, target) in layer.targets.iter().enumerate() {
            if matches!(target.before, Before::Edited(_)) {
                let rel = PathBuf::from(target.rel(index));
                for path in rel.ancestors().filter(|path| !path.as_os_str().is_empty()) {
                    let entry = laid.get(path).expect("laid down").clone();
                    want.insert(path.to_path_buf(), entry);
                }
            }
        }
        let inputs = load(home.path()).with_git(git(home.path()));

        run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("apply runs");
        crate::restore::restore_with(
            &StateDir::resolve(home.path()),
            home.path(),
            &ledger(home.path()),
            &git(home.path()),
        )
        .expect("rm");

        prop_assert_eq!(tree(home.path()), want);
    }

    /// Invariant 2 over generated `[[env]]` declarations: every environment
    /// fragment bx writes passes the guard it was judged by, a variable the
    /// guard refuses is assigned in no file bx writes, and one it approves
    /// is written wherever no refused one holds its file back.
    #[test]
    fn no_generated_fragment_assigns_a_variable_the_guard_cannot_judge(
        variables in variables(),
        aliases in proptest::sample::subsequence(&ALIASES[..], 0..=2),
    ) {
        let home = guarded_home();
        let layer = Layer {
            targets: Vec::new(),
            variables,
            aliases,
            startup: vec![None; STARTUP.len()],
            external: false,
        };
        let inputs = layer.inputs(&home);
        run(&inputs, Mode::Apply, &mut |_| Ok(true)).expect("apply runs");

        // Each file is judged by the plan's own judgement of its syntax, the
        // one route to the guard `env_guard`'s
        // `every_site_that_reaches_the_guard_is_known` admits.
        let read = |rel: &str| std::fs::read_to_string(home.child(rel)).ok();
        let roots = &inputs.roots;
        for rel in [".local/share/bx/zshenv.zsh", ".local/share/bx/zprofile.zsh"] {
            if let Some(text) = read(rel) {
                prop_assert_eq!(guard_fragment(&text, roots), None, "{}", rel);
            }
        }
        if let Some(text) = read(&ENVIRONMENT_D[2..]) {
            prop_assert_eq!(guard_environment_d(&text, roots), None);
        }
        for rel in [ZSHRC, &bash::FILE[2..]] {
            if let Some(text) = read(rel) {
                prop_assert_eq!(guard_fragment(phase(&text, "env"), roots), None, "{}", rel);
            }
        }

        let written: BTreeMap<&str, String> = layer
            .variables
            .iter()
            .flat_map(Variable::files)
            .chain(STARTUP)
            .filter_map(|rel| read(rel).map(|text| (rel, text)))
            .collect();
        for variable in &layer.variables {
            if !variable.approved {
                for (rel, text) in &written {
                    prop_assert!(!assigns(text, variable.name), "{} in {}", variable.name, rel);
                }
                continue;
            }
            for rel in variable.files() {
                let held = layer
                    .variables
                    .iter()
                    .any(|other| !other.approved && other.files().contains(&rel));
                if !held {
                    let text = written.get(rel).map_or("", String::as_str);
                    prop_assert!(assigns(text, variable.name), "{} not in {}", variable.name, rel);
                }
            }
        }
    }
}

/// The guard's verdict on a pool entry is the one [`VARIABLES`] records, so
/// the property above asserts against the guard rather than a guess.
#[test]
fn every_pool_entry_is_judged_as_recorded() {
    let home = guarded_home();
    let inputs = Layer {
        targets: Vec::new(),
        variables: Vec::new(),
        aliases: Vec::new(),
        startup: vec![None; STARTUP.len()],
        external: false,
    }
    .inputs(&home);
    let scratch = home.child("scratch");
    for (name, values) in VARIABLES {
        for (value, approved) in values {
            let value = value
                .replace("{{scratch}}", scratch.to_str().expect("UTF-8"))
                .replace('~', home.path().to_str().expect("UTF-8"));
            // As a fragment writes it: exported, inside double quotes.
            let verdict = guard_fragment(&format!("export {name}=\"{value}\"\n"), &inputs.roots);
            assert_eq!(verdict.is_none(), *approved, "{name}={value}: {verdict:?}");
        }
    }
}
