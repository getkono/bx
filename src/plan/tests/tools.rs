//! What a declared tool contributes: its activation run once, cached,
//! rendered per shell and reversed, and the conditions decided by the tools
//! and machine facts the inputs were loaded with.

use super::*;

/// A stub tool at `~/bin/stub` that appends a line to `~/runs` each time
/// it runs and prints a one-line activation, and the machine that finds
/// it: `~/bin` is its whole `PATH`.
fn stub_tool(home: &GuardedHome) -> activation::System {
    let bin = home.child("bin");
    std::fs::create_dir_all(&bin).expect("~/bin");
    let stub = bin.join("stub");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\necho ran >> '{}'\nprintf 'stub_hook() {{ :; }}\\n'\n",
            home.child("runs").display()
        ),
    )
    .expect("the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("executable");
    // Another test thread that forks while the stub is open for writing
    // holds that descriptor until its child calls `exec`, and running the
    // stub inside that window fails with `ETXTBSY`. The window closes on
    // its own, so the stub is run once here, retrying only that error,
    // and the record of that run dropped, before any code under test runs
    // it.
    let mut warmed = false;
    for _ in 0..200 {
        match std::process::Command::new(&stub).output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => panic!("the stub would not run: {e}"),
            Ok(_) => {
                warmed = true;
                break;
            }
        }
    }
    assert!(warmed, "the stub stayed busy");
    std::fs::remove_file(home.child("runs")).expect("the warm-up's record");
    activation::System::new(bin.into_os_string(), activation::TIMEOUT)
}

/// How many times the stub tool has run.
fn stub_runs(home: &GuardedHome) -> usize {
    std::fs::read_to_string(home.child("runs")).map_or(0, |runs| runs.lines().count())
}

const STUB: &str = "[[activation]]\nname = \"stub\"\ncommand = [\"stub\", \"init\", \"zsh\"]\n\
                        phase = \"completions\"\n";

const INTERACTIVE: &str = ".local/share/bx/zshrc.zsh";

/// Where the stub activation's output is written, and its wordcode.
const OUTPUT: &str = ".local/share/bx/activation/stub.zsh";
const WORDCODE: &str = ".local/share/bx/activation/stub.zsh.zwc";

#[test]
fn a_declared_activation_is_run_once_cached_rendered_and_reversed() {
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    seed(home.path(), STUB);
    let inputs = load(home.path()).with_host(stub_tool(&home));
    let state = StateDir::resolve(home.path());

    // `plan` runs it twice, shows the capture, and writes nothing.
    let planned = plan(&inputs);
    assert_eq!(stub_runs(&home), 2);
    // The interactive file, its `~/.zshrc` region, the output's own file,
    // and the capture; no wordcode, since no zsh is on this `PATH`.
    assert_eq!(
        planned.actions(),
        vec![
            Action::Create,
            Action::Modify,
            Action::Create,
            Action::Create
        ]
    );
    assert_eq!(exit(&planned, Mode::Plan), Exit::Pending);
    let shown = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        shown.contains("  + activation `stub`: run twice, output agreed; cached\n"),
        "{shown}"
    );
    assert!(!state.fingerprints().exists());

    // `apply` renders the output into the interactive file and records it.
    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(stub_runs(&home), 4, "one plan inside the apply, not two");
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
    assert!(
        file.contains(
            "\n# bx phase: completions\n# bx activation: stub\n\
             [[ -r ~/.local/share/bx/activation/stub.zsh ]] && \
             source ~/.local/share/bx/activation/stub.zsh\n"
        ),
        "{file}"
    );
    assert_eq!(
        std::fs::read_to_string(home.child(OUTPUT)).expect("the output's file"),
        "stub_hook() { :; }\n"
    );
    assert!(!home.child(WORDCODE).exists());
    let cache = std::fs::read(state.fingerprints()).expect("the cache is saved");

    // On an unchanged machine nothing runs and nothing is written.
    let again = plan(&inputs);
    assert_eq!(stub_runs(&home), 4);
    assert_eq!(again.actions(), vec![Action::Unchanged; 4]);
    assert_eq!(exit(&again, Mode::Plan), Exit::Converged);
    let quiet = render(
        &again,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(!quiet.contains("activation"), "{quiet}");
    let status = render(
        &again,
        View::Status,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        status.contains("  = activation `stub`: cached output reused, nothing run\n"),
        "{status}"
    );
    let second =
        run(&inputs, Mode::Apply, &mut |_| panic!("nothing to approve")).expect("the second apply");
    assert!(!second.executed);
    assert_eq!(stub_runs(&home), 4);
    assert_eq!(
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
        file
    );
    assert_eq!(
        std::fs::read(state.fingerprints()).expect("the cache"),
        cache
    );

    // Losing the cache costs a re-run, and nothing else: the file is
    // already right, and the cache comes back byte for byte.
    std::fs::remove_file(state.fingerprints()).expect("lose the cache");
    let lost = apply(&inputs);
    assert!(lost.executed);
    assert_eq!(
        lost.actions(),
        vec![
            Action::Unchanged,
            Action::Unchanged,
            Action::Unchanged,
            Action::Create
        ]
    );
    assert_eq!(stub_runs(&home), 6);
    assert_eq!(
        std::fs::read(state.fingerprints()).expect("the cache"),
        cache
    );
    assert_eq!(
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
        file
    );

    // `rm` puts back exactly what was there before.
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("restore");
    assert_eq!(
        std::fs::read_to_string(home.child(".zshrc")).expect(".zshrc"),
        "user\n"
    );
    assert!(!home.child(INTERACTIVE).exists());
    assert!(!home.child(OUTPUT).exists());
}

#[test]
fn each_shell_s_command_is_cached_and_rendered_in_its_own_file_and_reversed() {
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    home.write(".bashrc", "mine\n");
    seed(
        home.path(),
        "[[activation]]\nname = \"stub\"\ncommand = [\"stub\", \"init\", \"{shell}\"]\n\
             phase = \"completions\"\n\
             [[activation]]\nname = \"zonly\"\ncommand = [\"stub\", \"zsh\"]\n",
    );
    let inputs = load(home.path()).with_host(stub_tool(&home));
    let state = StateDir::resolve(home.path());

    // Three commands — `stub` for each shell, `zonly` for zsh alone —
    // each run twice.
    let planned = plan(&inputs);
    assert_eq!(stub_runs(&home), 6);
    let shown = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        shown.contains("  + activation `stub`: run twice, output agreed; cached\n")
            && shown.contains("  + activation `stub` for bash: run twice, output agreed; cached\n")
            && shown.contains("  + activation `zonly`: run twice, output agreed; cached\n")
            && !shown.contains("`zonly` for bash"),
        "{shown}"
    );
    // bash's row says why `zonly` is not in its file.
    let bash_row = planned
        .changes
        .iter()
        .find(|change| change.target == crate::shell::bash::FILE)
        .expect("bash's file");
    let note = bash_row.note.as_deref().expect("a note");
    assert!(
        note.ends_with("activation `zonly` declares no bash command, so it is not run for bash"),
        "{note}"
    );

    let applied = apply(&inputs);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    assert_eq!(stub_runs(&home), 12, "one plan inside the apply");
    let bash =
        std::fs::read_to_string(home.child(".local/share/bx/bashrc.bash")).expect("bash's file");
    assert_eq!(
        bash,
        "# Generated by bx. Edit the config repo, not this file.\n\
             \n# bx phase: completions\n# bx activation: stub\neval 'stub_hook() { :; }\n'\n\
             \n# bx: done, whichever plugins were found\ntrue\n"
    );
    let zsh = std::fs::read_to_string(home.child(INTERACTIVE)).expect("zsh's file");
    assert!(zsh.contains("# bx activation: stub\n"), "{zsh}");
    assert!(zsh.contains("# bx activation: zonly\n"), "{zsh}");

    // Idempotent: nothing runs, nothing is written.
    let again = plan(&inputs);
    assert_eq!(stub_runs(&home), 12);
    assert!(
        again.actions().iter().all(|a| *a == Action::Unchanged),
        "{:?}",
        again.actions()
    );

    // `rm` restores the user's `~/.bashrc` exactly.
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("restore");
    assert_eq!(
        std::fs::read_to_string(home.child(".bashrc")).expect(".bashrc"),
        "mine\n"
    );
    assert!(!home.child(".local/share/bx/bashrc.bash").exists());
}

#[test]
fn a_capture_under_another_path_renders_the_same_file() {
    // D1: a tool that prints the PATH it ran with, as `mise activate`
    // does. Re-captured under a different PATH, the file does not change.
    let home = guarded_home();
    let bin = home.child("bin");
    std::fs::create_dir_all(&bin).expect("~/bin");
    let stub = bin.join("stub");
    std::fs::write(
        &stub,
        "#!/bin/sh\nprintf \"export PATH='/opt/stub/bin:%s'\\n\" \"$PATH\"\n",
    )
    .expect("the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("executable");
    seed(home.path(), STUB);
    let state = StateDir::resolve(home.path());
    let under = |path: String| {
        load(home.path()).with_host(activation::System::new(path, activation::TIMEOUT))
    };

    let applied = apply(&under(bin.display().to_string()));
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    let file = std::fs::read_to_string(home.child(OUTPUT)).expect("the output's file");
    assert_eq!(file, "export PATH='/opt/stub/bin:'\"$PATH\"\n");

    std::fs::remove_file(state.fingerprints()).expect("lose the cache");
    let elsewhere = under(format!("{}:/nonexistent", bin.display()));
    let planned = plan(&elsewhere);
    assert_eq!(
        planned.actions(),
        vec![
            Action::Unchanged,
            Action::Unchanged,
            Action::Unchanged,
            Action::Create
        ]
    );
    apply(&elsewhere);
    assert_eq!(
        std::fs::read_to_string(home.child(OUTPUT)).expect("the output's file"),
        file
    );
}

#[test]
fn a_has_condition_looks_its_tool_up_on_the_host_the_inputs_were_loaded_with() {
    // The lookup used to read the process's own `PATH`, which
    // `Inputs::load` never took and no test controls. A tool only the
    // host's `PATH` holds is found, and one it does not hold is not.
    let home = guarded_home();
    seed(
        home.path(),
        "[[alias]]\nname = \"s\"\ncommand = \"stub\"\nwhen = \"has:stub\"\n",
    );
    let written = |host| {
        apply(&load(home.path()).with_host(host));
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file")
    };

    let without = written(activation::System::new("", activation::TIMEOUT));
    assert!(!without.contains("alias s="), "{without}");
    let with = written(stub_tool(&home));
    assert!(with.contains("alias s='stub'\n"), "{with}");
}

#[test]
fn on_macos_a_planned_bash_file_declares_the_bash_profile_region_too() {
    use crate::shell::bash::{FILE, PROFILE, STARTUP_FILE};
    let declared = |platform| {
        // bash's file planned and nothing else: as it is once nothing
        // places it and only the vacated file is left.
        let mut declared = BTreeSet::from([FILE]);
        declare_sourcing(&mut declared, platform);
        declared
    };
    assert_eq!(
        declared(Platform::Macos),
        BTreeSet::from([FILE, STARTUP_FILE, PROFILE])
    );
    assert_eq!(
        declared(Platform::Linux),
        BTreeSet::from([FILE, STARTUP_FILE])
    );
    // Nothing planned declares no startup file on either platform.
    for platform in [Platform::Linux, Platform::Macos] {
        let mut none = BTreeSet::new();
        declare_sourcing(&mut none, platform);
        assert!(none.is_empty(), "{platform:?}");
    }
}

#[test]
fn a_condition_on_the_machine_is_decided_by_the_facts_the_inputs_carry() {
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    home.write(".bashrc", "mine\n");
    seed(
        home.path(),
        "[[env]]\nname = \"EDITOR\"\nvalue = \"nvim\"\nkind = \"interactive\"\n\
             when = \"host:box\"\n\
             [[alias]]\nname = \"mac\"\ncommand = \"m\"\nwhen = [\"os:macos\", \"arch:aarch64\"]\n\
             [[alias]]\nname = \"lin\"\ncommand = \"l\"\nwhen = [\"os:linux\", \"ssh\"]\n\
             [[source]]\nname = \"boxed\"\npath = \"~/.boxed.sh\"\nwhen = \"host:box\"\n\
             [[function]]\nname = \"hi\"\nbody = \"print hi\"\nhook = \"precmd\"\n\
             when = [\"user:me\", \"distro:rhel\"]\nshells = [\"zsh\"]\n",
    );
    // The machine's facts are whatever the host the inputs carry says,
    // never this process's own.
    let on = |host: &str| {
        let machine = Machine {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            host: Some(host.to_string()),
            user: Some("me".to_string()),
            distro: Some(Distro {
                id: "fedora".to_string(),
                id_like: vec!["rhel".to_string()],
            }),
        };
        load(home.path())
            .with_host(activation::System::new("", activation::TIMEOUT).with_machine(machine))
    };
    let files = || {
        [INTERACTIVE, ".local/share/bx/bashrc.bash"]
            .map(|rel| std::fs::read_to_string(home.child(rel)).expect("a generated file"))
    };

    let boxed = on("BOX");
    assert_eq!(exit(&apply(&boxed), Mode::Apply), Exit::Converged);
    let [zsh, bash] = files();
    for file in [&zsh, &bash] {
        assert!(file.contains("export EDITOR=nvim\n"), "{file}");
        assert!(!file.contains("alias mac="), "{file}");
        assert!(
            file.contains("if [[ -n ${SSH_CONNECTION-} ]]; then\n  alias lin='l'\nfi\n"),
            "{file}"
        );
        assert!(file.contains("~/.boxed.sh"), "{file}");
    }
    assert!(zsh.contains("precmd_functions+=(__bx_hook_hi)\n"), "{zsh}");

    // Idempotent: a second plan is empty and the bytes do not move.
    let again = plan(&boxed);
    assert!(
        again.actions().iter().all(|a| *a == Action::Unchanged),
        "{:?}",
        again.actions()
    );
    apply(&boxed);
    assert_eq!(files(), [zsh.clone(), bash.clone()]);

    // A renamed host takes its lines out of both files, and nothing else.
    let renamed = on("other");
    let moved = plan(&renamed);
    let mut changed: Vec<(&str, Action)> = moved
        .changes
        .iter()
        .filter(|change| change.action != Action::Unchanged)
        .map(|change| (change.target.as_str(), change.action))
        .collect();
    changed.sort_unstable();
    assert_eq!(
        changed,
        [
            (crate::shell::bash::FILE, Action::Modify),
            ("~/.local/share/bx/zshrc.zsh", Action::Modify),
        ],
        "{:?}",
        moved.actions()
    );
    apply(&renamed);
    let [zsh_after, bash_after] = files();
    for file in [&zsh_after, &bash_after] {
        assert!(!file.contains("EDITOR"), "{file}");
        assert!(!file.contains("~/.boxed.sh"), "{file}");
        assert!(file.contains("alias lin='l'\n"), "{file}");
    }
    assert!(
        zsh_after.contains("precmd_functions+=(__bx_hook_hi)\n"),
        "{zsh_after}"
    );
}

#[test]
fn an_absent_tool_is_blocked_and_everything_else_is_still_written() {
    let home = guarded_home();
    seed(
        home.path(),
        &format!("{STUB}[[activation]]\nname = \"gone\"\ncommand = [\"gone\"]\n"),
    );
    let inputs = load(home.path()).with_host(stub_tool(&home));

    let planned = plan(&inputs);
    assert_eq!(
        planned.actions(),
        vec![
            Action::Create,
            Action::Create,
            Action::Create,
            Action::Create,
            Action::Blocked
        ]
    );
    let shown = render(
        &planned,
        View::Plan,
        Palette::resolve(true, false),
        home.path(),
    );
    assert!(
        shown.contains("  ? activation `gone`: omitted: `gone` is not on PATH\n"),
        "{shown}"
    );

    let applied = apply(&inputs);
    assert!(applied.executed);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Pending);
    let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
    assert!(file.contains("# bx activation: stub\n"), "{file}");
    assert!(!file.contains("gone"), "{file}");
    assert!(home.child(OUTPUT).exists());
    assert!(!home.child(".local/share/bx/activation/gone.zsh").exists());
}

#[test]
fn a_zsh_activation_is_written_compiled_recompiled_and_taken_back_with_its_wordcode() {
    let Some(zsh) = crate::shell::testing::installed("zsh") else {
        return;
    };
    let home = guarded_home();
    home.write(".zshrc", "user\n");
    seed(home.path(), STUB);
    stub_tool(&home);
    // zsh's own directory after `~/bin`, so the plan finds a zsh to compile
    // with.
    let search = format!(
        "{}:{}",
        home.child("bin").display(),
        zsh.parent().expect("zsh's directory").display()
    );
    let inputs = load(home.path()).with_host(activation::System::new(search, activation::TIMEOUT));
    let state = StateDir::resolve(home.path());
    let modified = |path: &str| {
        std::fs::metadata(home.child(path))
            .and_then(|meta| meta.modified())
            .expect("written")
    };

    // The output's own file holds exactly the tool's bytes, and the wordcode
    // zsh compiled from it is written after it, both as files bx owns.
    let planned = plan(&inputs);
    let rows: Vec<(&str, Action)> = planned
        .changes
        .iter()
        .map(|change| (change.target.as_str(), change.action))
        .collect();
    assert_eq!(
        rows[2..],
        [
            ("~/.local/share/bx/activation/stub.zsh", Action::Create),
            ("~/.local/share/bx/activation/stub.zsh.zwc", Action::Create),
        ]
    );
    let applied = apply(&inputs);
    assert_eq!(exit(&applied, Mode::Apply), Exit::Converged);
    assert_eq!(
        std::fs::read(home.child(OUTPUT)).expect("the output's file"),
        b"stub_hook() { :; }\n"
    );
    let wordcode = std::fs::read(home.child(WORDCODE)).expect("the wordcode");
    assert!(modified(WORDCODE) >= modified(OUTPUT));
    let ledger = LedgerView::read(&state, home.path())
        .expect("the ledger")
        .value;
    for path in [OUTPUT, WORDCODE] {
        let entry = ledger
            .get(&Portable::try_from(format!("~/{path}")).expect("portable"))
            .expect("ledgered");
        assert_eq!(entry.mechanism, Mechanism::Own, "{path}");
    }
    // zsh loads it: the hook the output defines is defined.
    let out = std::process::Command::new(&zsh)
        .args([
            "-f",
            "-c",
            "source ~/.local/share/bx/zshrc.zsh; whence -w stub_hook",
        ])
        .env_clear()
        .env("HOME", home.path())
        .output()
        .expect("zsh runs");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "stub_hook: function\n"
    );

    // A second apply has nothing to do, and runs neither the tool nor zsh.
    let again = plan(&inputs);
    assert!(
        again.actions().iter().all(|a| *a == Action::Unchanged),
        "{:?}",
        again.actions()
    );
    assert_eq!(stub_runs(&home), 4);
    assert!(!apply(&inputs).executed);
    assert_eq!(
        std::fs::read(home.child(WORDCODE)).expect("unchanged"),
        wordcode
    );

    // A tool printing something else rewrites both, the wordcode after.
    std::fs::write(
        home.child("bin/stub"),
        "#!/bin/sh\nprintf 'stub_hook() { true; }\\n'\n",
    )
    .expect("an upgraded stub");
    let upgraded = apply(&inputs);
    assert_eq!(exit(&upgraded, Mode::Apply), Exit::Converged);
    assert_eq!(
        std::fs::read(home.child(OUTPUT)).expect("the output's file"),
        b"stub_hook() { true; }\n"
    );
    let recompiled = std::fs::read(home.child(WORDCODE)).expect("the wordcode");
    assert_ne!(recompiled, wordcode, "compiled again");
    assert!(modified(WORDCODE) >= modified(OUTPUT));
    assert!(
        plan(&inputs)
            .actions()
            .iter()
            .all(|a| *a == Action::Unchanged)
    );

    // Switched off, in a configuration that still declares something, both
    // are taken back; `rm` restores the rest.
    seed(
        home.path(),
        &format!("{STUB}enabled = false\n[[target]]\npath = \"~/.a\"\ncontent = \"a\\n\"\n"),
    );
    let off = load(home.path()).with_host(activation::System::new(
        home.child("bin").into_os_string(),
        activation::TIMEOUT,
    ));
    apply(&off);
    assert!(!home.child(OUTPUT).exists() && !home.child(WORDCODE).exists());
    seed(home.path(), STUB);
    apply(&inputs);
    assert!(home.child(OUTPUT).exists() && home.child(WORDCODE).exists());
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("restore");
    assert!(!home.child(OUTPUT).exists() && !home.child(WORDCODE).exists());
    assert!(!home.child(".local/share/bx/activation").exists());
    assert_eq!(
        std::fs::read_to_string(home.child(".zshrc")).expect(".zshrc"),
        "user\n"
    );
}

/// The stub activation applied with a zsh on the search path, so its output's
/// file and its wordcode are both written; `None` where no zsh is installed.
fn compiled(home: &GuardedHome) -> Option<(Inputs, PathBuf)> {
    let zsh = crate::shell::testing::installed("zsh")?;
    home.write(".zshrc", "user\n");
    seed(home.path(), STUB);
    stub_tool(home);
    let search = format!(
        "{}:{}",
        home.child("bin").display(),
        zsh.parent().expect("zsh's directory").display()
    );
    let inputs = load(home.path()).with_host(activation::System::new(search, activation::TIMEOUT));
    assert_eq!(exit(&apply(&inputs), Mode::Apply), Exit::Converged);
    assert!(home.child(WORDCODE).exists(), "zsh compiled the output");
    Some((inputs, zsh))
}

/// The row of `path`, home-relative, in `report`.
fn row_of(report: &Report, path: &str) -> usize {
    report
        .changes
        .iter()
        .position(|change| change.target == format!("~/{path}"))
        .expect("a row")
}

/// Whether the wordcode is at least as new as the output's file, which is
/// what has zsh's `source` read it.
fn fresh(home: &GuardedHome) -> bool {
    let modified = |path: &str| {
        std::fs::metadata(home.child(path))
            .and_then(|meta| meta.modified())
            .expect("written")
    };
    modified(WORDCODE) >= modified(OUTPUT)
}

/// Leave the wordcode an hour older than it is, so a file written after it
/// without it is newer than it.
fn backdate_wordcode(home: &GuardedHome) {
    let file = std::fs::File::options()
        .write(true)
        .open(home.child(WORDCODE))
        .expect("the wordcode");
    let then = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    file.set_modified(then).expect("backdated");
}

/// `apply`, approved, answering *take* for each of `taken`.
fn answer(inputs: &Inputs, taken: &[usize]) -> Report {
    answered(inputs, Mode::Apply, &mut |_| {
        Ok(Approval {
            approved: true,
            taken: taken.iter().copied().collect(),
        })
    })
    .expect("apply runs")
}

#[test]
fn a_kept_edit_of_an_activation_file_keeps_its_wordcode_from_overriding_it() {
    let home = guarded_home();
    let Some((inputs, zsh)) = compiled(&home) else {
        return;
    };
    let before = std::fs::read(home.child(WORDCODE)).expect("the wordcode");
    // zsh compares whole seconds: an edit made in the second bx wrote the
    // wordcode would lose to it whatever bx did next.
    backdate_wordcode(&home);
    std::fs::write(home.child(OUTPUT), "edited_hook() { :; }\n").expect("the edit");
    std::fs::write(
        home.child("bin/stub"),
        "#!/bin/sh\nprintf 'stub_hook() { true; }\\n'\n",
    )
    .expect("an upgraded stub");

    // The file is a question, and the wordcode compiled from bx's new output
    // waits on its answer rather than being written on its own.
    let planned = plan(&inputs);
    let (output, wordcode) = (row_of(&planned, OUTPUT), row_of(&planned, WORDCODE));
    assert_eq!(planned.changes[output].action, Action::Conflict);
    assert_eq!(planned.changes[wordcode].action, Action::Conflict);
    assert!(
        planned.changes[wordcode]
            .note
            .as_deref()
            .is_some_and(|note| note.contains(crate::plan::decide::WAITS)),
        "{:?}",
        planned.changes[wordcode].note
    );

    // Kept: neither is written, and zsh still runs the edit.
    let kept = answer(&inputs, &[]);
    assert_eq!(kept.changes[wordcode].action, Action::Conflict);
    assert_eq!(
        std::fs::read(home.child(WORDCODE)).expect("the wordcode"),
        before
    );
    let out = std::process::Command::new(&zsh)
        .args([
            "-f",
            "-c",
            "source ~/.local/share/bx/zshrc.zsh; whence -w edited_hook stub_hook",
        ])
        .env_clear()
        .env("HOME", home.path())
        .output()
        .expect("zsh runs");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "edited_hook: function\nstub_hook: none\n"
    );

    // Taken: both are written, the wordcode after, and the plan converges.
    let taken = answer(&inputs, &[output]);
    assert_eq!(taken.changes[output].action, Action::Modify);
    assert_eq!(taken.changes[wordcode].action, Action::Modify);
    assert_ne!(
        std::fs::read(home.child(WORDCODE)).expect("the wordcode"),
        before
    );
    assert!(fresh(&home));
    assert!(
        plan(&inputs)
            .actions()
            .iter()
            .all(|a| *a == Action::Unchanged)
    );
}

#[test]
fn a_wordcode_missing_beside_a_file_already_right_is_written_on_its_own() {
    let home = guarded_home();
    let Some((inputs, _)) = compiled(&home) else {
        return;
    };
    let wordcode = std::fs::read(home.child(WORDCODE)).expect("the wordcode");

    // The file is what bx wants, so it is not written; its wordcode is
    // decided on its own and compiles exactly those bytes.
    std::fs::remove_file(home.child(WORDCODE)).expect("deleted");
    let planned = plan(&inputs);
    let row = row_of(&planned, WORDCODE);
    assert_eq!(
        planned.changes[row_of(&planned, OUTPUT)].action,
        Action::Unchanged
    );
    assert_eq!(planned.changes[row].action, Action::Create);
    assert!(
        planned.changes[row]
            .note
            .as_deref()
            .is_none_or(|note| !note.contains(crate::plan::decide::WAITS)),
        "{:?}",
        planned.changes[row].note
    );
    assert_eq!(exit(&apply(&inputs), Mode::Apply), Exit::Converged);
    assert_eq!(
        std::fs::read(home.child(WORDCODE)).expect("the wordcode"),
        wordcode
    );
    assert!(fresh(&home));
    assert!(
        plan(&inputs)
            .actions()
            .iter()
            .all(|a| *a == Action::Unchanged)
    );
}

#[test]
fn an_activation_file_written_again_with_the_same_output_rewrites_its_wordcode_after_it() {
    let home = guarded_home();
    let Some((inputs, _)) = compiled(&home) else {
        return;
    };
    let wordcode = std::fs::read(home.child(WORDCODE)).expect("the wordcode");

    // Re-created after a deletion: the wordcode's bytes are right, and it is
    // rewritten after the file all the same.
    std::fs::remove_file(home.child(OUTPUT)).expect("deleted");
    backdate_wordcode(&home);
    let planned = plan(&inputs);
    let row = row_of(&planned, WORDCODE);
    assert_eq!(
        planned.changes[row_of(&planned, OUTPUT)].action,
        Action::Create
    );
    assert_eq!(planned.changes[row].action, Action::Modify);
    assert!(
        planned.changes[row]
            .note
            .as_deref()
            .is_some_and(|note| note.contains(crate::plan::decide::REWRITTEN)),
        "{:?}",
        planned.changes[row].note
    );
    assert_eq!(exit(&apply(&inputs), Mode::Apply), Exit::Converged);
    assert_eq!(
        std::fs::read(home.child(WORDCODE)).expect("the wordcode"),
        wordcode
    );
    assert!(fresh(&home));
    assert!(
        plan(&inputs)
            .actions()
            .iter()
            .all(|a| *a == Action::Unchanged)
    );

    // An edit answered *take bx's*, the output unchanged: the same.
    std::fs::write(home.child(OUTPUT), "edited_hook() { :; }\n").expect("the edit");
    backdate_wordcode(&home);
    let planned = plan(&inputs);
    let output = row_of(&planned, OUTPUT);
    assert_eq!(planned.changes[output].action, Action::Conflict);
    assert_eq!(planned.changes[row].action, Action::Unchanged);
    let kept = answer(&inputs, &[]);
    assert_eq!(kept.changes[row].action, Action::Unchanged);
    assert!(!fresh(&home), "kept: the wordcode is left as it was");
    let taken = answer(&inputs, &[output]);
    assert_eq!(taken.changes[row].action, Action::Modify);
    assert_eq!(
        std::fs::read(home.child(WORDCODE)).expect("the wordcode"),
        wordcode
    );
    assert!(fresh(&home));
    assert!(
        plan(&inputs)
            .actions()
            .iter()
            .all(|a| *a == Action::Unchanged)
    );
}
