//! What resolution places on the shell-start path: each environment fragment
//! and its region, the interactive file with its plugins and activations, and
//! the fragments it holds back with the reason it names.

use super::*;

#[test]
fn no_env_entry_places_nothing() {
    let resolved = resolved("", None).unwrap();
    assert!(resolved.targets.is_empty());
}

#[test]
fn the_placement_graph_emits_each_fragment_before_its_region_after_the_targets() {
    let global = format!(
        "{}{}{}",
        "[[target]]\npath = \"~/.a\"\ncontent = \"x\"\n",
        env("EDITOR", "{{a}}", "interactive"),
        env("LANG", "C", "gui"),
    );
    let resolved = resolved(&format!("{ABC}{global}"), None).unwrap();
    assert_eq!(
        keys(&resolved),
        vec![
            "~/.a",
            "~/.config/environment.d/50-bx.conf",
            "~/.local/share/bx/zshrc.zsh",
            "~/.zshrc",
            "~/.local/share/bx/bashrc.bash",
            "~/.bashrc",
        ]
    );
    let env_d = ready(&resolved, 1);
    assert_eq!(env_d.format, Format::EnvD);
    assert_eq!(env_d.attach, Attach::Own);
    let zshrc_fragment = ready(&resolved, 2);
    assert_eq!(
        zshrc_fragment.body,
        Body::Generated(Gen::Interactive(Box::new(Interactive::new(Fragment {
            syntax: Syntax::Zsh,
            vars: vec![Var::always("EDITOR", "x")],
            path: Vec::new(),
            inherited: Vec::new(),
        }))))
    );
    assert_eq!(zshrc_fragment.format, Format::Opaque);
    // Attributed to the variable that put it there.
    assert_eq!(
        zshrc_fragment.origin.line,
        ready(&resolved, 0).origin.line + 3
    );
    let region = ready(&resolved, 3);
    assert_eq!(region.attach, Attach::Region { comment: '#' });
    assert_eq!(
        region.body,
        Body::Generated(Gen::Source(zshrc_fragment.path.clone()))
    );
}

#[test]
fn zsh_s_interactive_row_names_every_declaration_kept_from_zsh() {
    let both = resolved(
        &format!(
            "{}{}shells = [\"bash\"]\n{}shells = [\"zsh\"]\n\
                 [[function]]\nname = \"fb\"\nbody = \"echo b\"\nshells = [\"bash\"]\n\
                 [[function]]\nname = \"off\"\nbody = \"x\"\nshells = [\"bash\"]\nenabled = false\n\
                 [[source]]\nname = \"sb\"\npath = \"~/.bash_extra\"\nshells = [\"bash\"]\n\
                 [[activation]]\nname = \"ab\"\ncommand = [\"a\", \"{{shell}}\"]\n\
                 shells = [\"bash\"]\n\
                 [[activation]]\nname = \"bonly\"\nbash = [\"b\", \"init\"]\n\
                 [[activation]]\nname = \"both\"\ncommand = [\"c\", \"{{shell}}\"]\n",
            env("EDITOR", "nvim", "interactive"),
            env("BONLY", "1", "login"),
            env("ZONLY", "1", "interactive"),
        ),
        None,
    )
    .unwrap();
    let zshrc = target_at(&both, "~/.local/share/bx/zshrc.zsh");
    let Body::Generated(generator) = &zshrc.body else {
        panic!("{:?}", zshrc.body);
    };
    // Every enabled entry `shells` keeps from zsh, in declaration-kind
    // order, then the activation that reaches zsh with no zsh command.
    // The disabled function, the zsh-only variable and the shared
    // activation are not named.
    assert_eq!(
        generator.note().as_deref(),
        Some(
            "not in zsh: env `BONLY`, function `fb`, source `sb`, activation `ab`; \
                 activation `bonly` declares no zsh command, so it is not run for zsh"
        )
    );
    // The bash-only variable reaches none of zsh's files.
    assert!(
        !keys(&both).iter().any(|key| key.ends_with("zprofile.zsh")),
        "{:?}",
        keys(&both)
    );
}

/// The ready target at `path`.
fn target_at<'r>(resolved: &'r Resolved, path: &str) -> &'r Target {
    let index = keys(resolved)
        .iter()
        .position(|key| key == path)
        .unwrap_or_else(|| panic!("{path}: {:?}", keys(resolved)));
    ready(resolved, index)
}

/// One `[[plugin]]` entry, as TOML.
fn plugin(name: &str, terminal: bool) -> String {
    format!(
        "[[plugin]]\nname = \"{name}\"\nsource = \"~/.zsh/{name}.zsh\"\nterminal = {terminal}\n"
    )
}

#[test]
fn declared_plugins_land_in_the_interactive_file_and_alone_still_place_it() {
    // Beside an interactive variable: one file, attributed to the variable.
    let both = resolved(
        &format!(
            "{}{}",
            plugin("p", false),
            env("EDITOR", "nvim", "interactive")
        ),
        None,
    )
    .unwrap();
    // The variable reaches bash's file too; the plugin, zsh's alone.
    assert_eq!(
        keys(&both),
        vec![
            "~/.local/share/bx/zshrc.zsh",
            "~/.zshrc",
            "~/.local/share/bx/bashrc.bash",
            "~/.bashrc",
        ]
    );
    let file = ready(&both, 0);
    assert_eq!(file.origin.line, 5, "the variable's line");
    let Body::Generated(Gen::Interactive(interactive)) = &file.body else {
        panic!("{:?}", file.body);
    };
    assert_eq!(interactive.env().vars, vec![Var::always("EDITOR", "nvim")]);
    let names: Vec<&str> = interactive
        .plugins()
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, ["p"]);

    // Alone: the file and its region, attributed to the first enabled plugin.
    let alone = resolved(
        &format!(
            "[[plugin]]\nname = \"off\"\nsource = \"~/off.zsh\"\nenabled = false\n{}",
            plugin("p", true)
        ),
        None,
    )
    .unwrap();
    assert_eq!(
        keys(&alone),
        vec!["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
    );
    assert_eq!(ready(&alone, 0).origin.line, 5);
    assert_eq!(ready(&alone, 1).origin.line, 5);

    // Only a switched-off plugin: nothing is placed.
    let off = resolved(
        "[[plugin]]\nname = \"off\"\nsource = \"~/off.zsh\"\nenabled = false\n",
        None,
    )
    .unwrap();
    assert!(off.targets.is_empty());
}

#[test]
fn a_declared_activation_alone_places_the_interactive_file() {
    // Alone: the file and its region, attributed to the first enabled
    // activation, and holding nothing until the plan attaches it.
    let alone = resolved(
        "[[activation]]\nname = \"off\"\ncommand = [\"off\"]\nenabled = false\n\
             [[activation]]\nname = \"mise\"\ncommand = [\"mise\", \"activate\", \"zsh\"]\n",
        None,
    )
    .unwrap();
    assert_eq!(
        keys(&alone),
        vec!["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
    );
    assert_eq!(ready(&alone, 0).origin.line, 5);
    assert_eq!(ready(&alone, 1).origin.line, 5);
    let Body::Generated(generator) = &ready(&alone, 0).body else {
        panic!("{:?}", ready(&alone, 0).body);
    };
    assert_eq!(
        generator.render(&crate::config::when::tools(&|_| true)),
        "# Generated by bx. Edit the config repo, not this file.\n"
    );

    // Beside a plugin, the plugin places it.
    let both = resolved(
        &format!(
            "{}[[activation]]\nname = \"mise\"\ncommand = [\"mise\"]\n",
            plugin("p", false)
        ),
        None,
    )
    .unwrap();
    assert_eq!(ready(&both, 0).origin.line, 1);

    // Only a switched-off activation: nothing is placed.
    let off = resolved(
        "[[activation]]\nname = \"off\"\ncommand = [\"off\"]\nenabled = false\n",
        None,
    )
    .unwrap();
    assert!(off.targets.is_empty());
}

#[test]
fn a_held_back_interactive_variable_holds_its_plugins_back_with_it() {
    let held = resolved(
        &format!(
            "{ABC}{}{}",
            plugin("p", false),
            env("EDITOR", "{{b}}", "interactive")
        ),
        None,
    )
    .unwrap();
    assert_eq!(blocked(&held, 0).key, "~/.local/share/bx/zshrc.zsh");
    // The region still sources it once it is there.
    assert_eq!(ready(&held, 1).path.to_string(), "~/.zshrc");
}

#[test]
fn resolving_a_configuration_with_two_terminal_claimants_fails() {
    // `merge` refuses them first; a `Config` built another way is refused
    // here too, so no rendered file ever holds two.
    let mut merged = merge(
        &[layer("bx.toml", LayerKind::Global, &plugin("one", true)).unwrap()],
        &home(),
    )
    .unwrap();
    let mut second = merged.plugins[0].clone();
    second.name = "two".to_string();
    merged.plugins.push(second);
    let err = resolve(&merged, &home(), place)
        .expect_err("refused")
        .to_string();
    assert!(
        err.contains("plugin `two` claims the terminal slot"),
        "{err}"
    );
    assert!(err.contains("plugin `one` already claims"), "{err}");
}

#[test]
fn a_recorded_interactive_file_nothing_places_is_planned_empty() {
    let ledger = Path::new("/var/home/example/.local/state/bx/ledger");
    let every = vacated_fragments(&[], |_| true, |_, _| true, &home(), ledger);
    let Some(Resolution::Ready(file)) = every.iter().find(|resolution| {
        matches!(resolution, Resolution::Ready(target)
                if target.path.as_str() == "~/.local/share/bx/zshrc.zsh")
    }) else {
        panic!("{every:?}");
    };
    assert_eq!(
        file.body,
        Body::Generated(Gen::Interactive(Box::new(Interactive::new(Fragment {
            syntax: Syntax::Zsh,
            vars: Vec::new(),
            path: Vec::new(),
            inherited: Vec::new(),
        }))))
    );
}

#[test]
fn a_recorded_fragment_no_place_names_is_planned_empty_and_no_other() {
    // environment.d is held back on `b`, zshrc.zsh is placed, and the
    // other two fragments are named by nothing.
    let placed = resolved(
        &format!(
            "{ABC}{}{}",
            env("X", "{{b}}", "gui"),
            env("EDITOR", "nvim", "interactive")
        ),
        None,
    )
    .unwrap();
    let ledger = Path::new("/var/home/example/.local/state/bx/ledger");
    // Only zsh's fragments are recorded: bash's files are
    // `shell::bash::vacated`'s to test.
    let zsh = |path: &Portable| path.as_str().ends_with(".zsh");
    let every = vacated_fragments(&placed.targets, zsh, |_, _| false, &home(), ledger);
    let paths: Vec<String> = every
        .iter()
        .map(|resolution| match resolution {
            Resolution::Ready(target) => {
                assert_eq!(
                    target.body,
                    Body::Generated(Gen::Env(Fragment {
                        syntax: Syntax::Zsh,
                        vars: Vec::new(),
                        path: Vec::new(),
                        inherited: Vec::new(),
                    }))
                );
                assert_eq!(target.origin.file, ledger);
                target.path.to_string()
            }
            Resolution::Blocked(entry) => panic!("{entry:?}"),
        })
        .collect();
    assert_eq!(
        paths,
        vec![
            "~/.local/share/bx/zshenv.zsh",
            "~/.local/share/bx/zprofile.zsh"
        ]
    );
    // Nothing bx has not written is planned.
    assert!(
        vacated_fragments(&placed.targets, |_| false, |_, _| false, &home(), ledger).is_empty()
    );
}

#[test]
fn a_fragment_held_back_names_its_most_specific_reason_across_its_variables() {
    // Unanswered alone: the values to answer, and `bx init`.
    let unset = resolved(&format!("{ABC}{}", env("X", "{{b}}", "gui")), None).unwrap();
    let entry = blocked(&unset, 0);
    assert_eq!(entry.key, "~/.config/environment.d/50-bx.conf");
    assert_eq!(
        entry.reason,
        BlockReason::UnsetValue {
            names: vec!["b".to_string()]
        }
    );
    assert!(entry.hint.contains("bx init"), "{}", entry.hint);

    // Switched off outranks unanswered, across two variables.
    let both = resolved(
        &format!(
            "{ABC}{}{}{}",
            env("X", "{{b}}", "gui"),
            env("Y", "{{c}}", "environment"),
            env("Z", "{{a}}", "gui"),
        ),
        None,
    )
    .unwrap();
    // zshenv and bash's file hold only Y; environment.d holds X, Y and
    // Z.
    assert_eq!(
        keys(&both),
        vec![
            "~/.local/share/bx/zshenv.zsh",
            "~/.zshenv",
            "~/.config/environment.d/50-bx.conf",
            "~/.local/share/bx/bashrc.bash",
            "~/.bashrc",
        ]
    );
    // bash's file is held back by Y as zshenv is, and its region is not.
    assert_eq!(
        blocked(&both, 3).reason,
        BlockReason::DisabledValue {
            names: vec!["c".to_string()]
        }
    );
    ready(&both, 4);
    assert_eq!(
        blocked(&both, 2).reason,
        BlockReason::DisabledValue {
            names: vec!["c".to_string()]
        }
    );
    // The region is never held back.
    ready(&both, 1);

    // An unusable answer outranks unanswered too, and names its line.
    let invalid = resolved(
        &format!(
            "{ABC}{}{}",
            env("X", "{{b}}", "gui"),
            env("Y", "{{a}}", "gui")
        ),
        Some("[values]\na = \"say \\\"hi\\\"\"\n"),
    )
    .unwrap();
    let entry = blocked(&invalid, 0);
    assert_eq!(
        entry.reason,
        BlockReason::InvalidValue {
            names: vec!["a".to_string()]
        }
    );
    assert!(entry.hint.contains("control character"), "{}", entry.hint);
    assert!(entry.hint.contains("local.toml"), "{}", entry.hint);
}

#[test]
fn a_value_invalid_for_its_kind_holds_back_its_fragment() {
    let resolved = resolved(
        &format!(
            "{SCRATCH}{}",
            env("SCCACHE_DIR", "{{scratch_root}}/sccache", "login")
        ),
        Some("[values]\nscratch_root = \"relative\"\n"),
    )
    .unwrap();
    let entry = blocked(&resolved, 0);
    assert_eq!(entry.key, "~/.local/share/bx/zprofile.zsh");
    assert_eq!(
        entry.reason,
        BlockReason::InvalidValue {
            names: vec!["scratch_root".to_string()]
        }
    );
}

#[test]
fn a_repo_defect_in_an_env_value_fails_the_load() {
    for (global, needle) in [
        (env("X", "{{nobody}}", "gui"), "nobody"),
        (env("X", "{{a", "gui"), "env `X`"),
        (
            format!(
                "[[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"a`b\"\n{}",
                env("X", "{{q}}", "gui")
            ),
            "control character",
        ),
    ] {
        let err = resolved(&global, None).expect_err(&global);
        assert!(err.contains(needle), "{global}: {err}");
    }
}

#[test]
fn a_declared_target_may_not_claim_a_file_the_placement_graph_writes() {
    let err = resolved(
        &format!(
            "[[target]]\npath = \"~/.zshrc\"\ncontent = \"mine\"\n{}",
            env("EDITOR", "vi", "interactive")
        ),
        None,
    )
    .expect_err("one file, two targets");
    assert!(err.contains("`~/.zshrc` is the same file"), "{err}");
}
