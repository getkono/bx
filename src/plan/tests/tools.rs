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
    assert_eq!(
        planned.actions(),
        vec![Action::Create, Action::Modify, Action::Create]
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
            "\n# bx phase: completions\n# bx activation: stub\neval 'stub_hook() { :; }\n'\n"
        ),
        "{file}"
    );
    let cache = std::fs::read(state.fingerprints()).expect("the cache is saved");

    // On an unchanged machine nothing runs and nothing is written.
    let again = plan(&inputs);
    assert_eq!(stub_runs(&home), 4);
    assert_eq!(again.actions(), vec![Action::Unchanged; 3]);
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
        vec![Action::Unchanged, Action::Unchanged, Action::Create]
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
    let file = std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file");
    assert!(
        file.contains("eval 'export PATH='\\''/opt/stub/bin:'\\''\"$PATH\"\n'\n"),
        "{file}"
    );

    std::fs::remove_file(state.fingerprints()).expect("lose the cache");
    let elsewhere = under(format!("{}:/nonexistent", bin.display()));
    let planned = plan(&elsewhere);
    assert_eq!(
        planned.actions(),
        vec![Action::Unchanged, Action::Unchanged, Action::Create]
    );
    apply(&elsewhere);
    assert_eq!(
        std::fs::read_to_string(home.child(INTERACTIVE)).expect("the file"),
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
}
