//! A fragment may set only a variable bx knows how to judge: the round 5
//! falsifiers, the sweep of every form a shell assigns through, and the
//! generated shell content that is not a fragment and so carries no
//! assignment beyond the exceptions the guard lists.

use super::*;

#[test]
fn every_round_5_falsifier_is_refused_for_the_reason_that_names_its_defect() {
    use Reason::{
        BxOwnedDirectory, NotACommandLine, NotAProgram, NotAbsolute, NotEmittable,
        RelocatingAssignment, ReservedName,
    };
    let home_rooted = home_rooted();
    // Each falsifier is refused as `check` judges it and as the scan reads
    // its `export` line, under both root sets.
    let both = |name: &str, value: &str, reason: Reason| {
        for roots in [rooted(), RootSet::strict()] {
            refused(name, value, &roots, reason);
            let line = format!("export {name}={value}");
            assert_eq!(reasons(&line, &roots), vec![(1, reason)], "{line}");
        }
    };
    // 1: a bare word a tool reads as a path. `BASH_ENV` and `ENV` are also
    // names a starting shell acts on, so they are reserved first.
    for (name, value) in R5_READ_AS_LOCATIONS {
        let expected = if ["BASH_ENV", "ENV"].contains(name) {
            ReservedName
        } else {
            NotEmittable
        };
        both(name, value, expected);
    }
    // 2: a program given arguments. `EDITOR` is a command line since
    // issue #112, whose arguments are judged for what they point at and
    // what they assign; a program is still one word.
    let lesskey = "\"/usr/bin/less --lesskey-file=/etc/evil/lesskey\"";
    for (value, reason) in [
        (
            "\"/usr/bin/touch /var/home/example/.local/state/bx/written-by-editor\"",
            BxOwnedDirectory,
        ),
        (
            "\"/usr/bin/env XDG_CONFIG_HOME=/etc/evil nvim\"",
            RelocatingAssignment,
        ),
    ] {
        both("EDITOR", value, reason);
        both("RUSTC_WRAPPER", value, NotAProgram);
    }
    both("RUSTC_WRAPPER", lesskey, NotAProgram);
    // A flag that points a tool at a file of its own outside bx's
    // directories is the user's command line to write: the maintainer's
    // ruling on #112 judges arguments only for bx's directories.
    assert_eq!(check("PAGER", lesskey, &rooted()), Verdict::Allowed);
    // 3: a state directory a later line moves. The move is what is
    // refused.
    assert_eq!(
        reasons(
            "export CARGO_HOME=/var/mnt/scratch/example/state/bx\n\
                 export XDG_STATE_HOME=/var/mnt/scratch/example/state\n",
            &rooted()
        ),
        vec![(2, NotEmittable)]
    );
    // 4: no URL is exempt, for any kind that holds a path. A relocation is
    // judged where a root is declared: under the strict set it has none.
    for (name, value, reason) in [
        ("EDITOR", "x://ed", NotACommandLine),
        ("BROWSER", "x://ed", NotAProgram),
        ("RIPGREP_CONFIG_PATH", "cfg://rc", NotEmittable),
        ("GIT_CONFIG_SYSTEM", "https://x:/etc/evil", NotEmittable),
    ] {
        both(name, value, reason);
    }
    for (name, value, reason) in [
        ("CARGO_HOME", "cfg://rc", NotAbsolute),
        (
            "CARGO_HOME",
            "https://x:/var/mnt/scratch/example",
            NotAbsolute,
        ),
        ("PATH", "https://x:/usr/bin", NotAbsolute),
        ("SSH_AUTH_SOCK", "unix://agent", NotAbsolute),
    ] {
        refused(name, value, &rooted(), reason);
    }
    // 5: the strict set owns the default state directory under any home.
    for content in [
        "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
        "export VISUAL=/var/home/example/.local/state/bx/nvim",
        "export SSH_AUTH_SOCK=/var/home/example/.local/state/bx/agent.sock",
    ] {
        assert_eq!(
            reasons(content, &RootSet::strict()),
            vec![(1, BxOwnedDirectory)],
            "{content}"
        );
    }
    // 6: names a shell acts on when assigned.
    for roots in [rooted(), RootSet::strict()] {
        for name in ["RPROMPT", "RPS1", "RPROMPT2", "RPS2", "EXECIGNORE"] {
            refused(name, "x", &roots, ReservedName);
            assert_eq!(unexported(name, "x", &roots), Some(ReservedName), "{name}");
        }
        assert_eq!(
            reasons("RPROMPT='$(touch evil)'", &roots),
            vec![(1, ReservedName)]
        );
    }
    // 7: a config repo landing on the state directory. No
    // fragment may move the config repo at all.
    assert_eq!(
        reasons("export XDG_CONFIG_HOME=~/.local/state", &home_rooted),
        vec![(1, NotEmittable)]
    );
}

/// Whether `word` is a shell variable name.
fn is_shell_name(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Every name `text` gives a value to, by any form this module knows a
/// shell assigns through.
///
/// Two sweeps, because the forms divide in two. Most of them put the name
/// in front of an `=` — `export N=V`, `N+=V`, `N[1]=V`, `: ${N:=V}` — and
/// are found by walking the `=`s. The rest hold no `=` at all and name
/// their target as a word after a keyword: the control variable of a `for`
/// or a `select`, an operand of `read` or `getopts`, the target of
/// `printf -v`. The `=` sweep alone is not enough —
/// it cannot see a single one of the second group, so a `read -r
/// CARGO_HOME` in the snippet went unnoticed.
///
/// The second sweep is deliberately generous: it takes every `-v` operand
/// and *every* name-shaped operand of a `read`, `mapfile` or `readarray`,
/// which over-reports rather than under-reports, and over-reporting can
/// only make the caller stricter. Taking only the first non-flag operand
/// under-reported instead, against this very sentence — `read -p "Enter: "
/// N`, `read -d '' N`, `read -rn 1 N` and `read -r A N` each hid `N`
/// behind a flag's own operand or a second target.
/// Comments are dropped first, so prose ending in the word `for` is not an
/// assignment.
///
/// This is not held to a list of forms of its own.
/// `the_assignment_sweep_sees_every_form_the_module_knows_assigns` holds
/// it to [`ASSIGNING_FORMS`], the table the module already maintains, so a
/// form added there that this cannot see fails rather than quietly
/// narrowing what the snippet is held to.
fn assignments_in(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for (at, _) in text.match_indices('=') {
        let (before, from) = text.split_at(at);
        // `==`, `!=`, `<=` and `>=` compare; they assign nothing.
        if before.ends_with(['=', '!', '<', '>']) || from[1..].starts_with('=') {
            continue;
        }
        // `:=`, `+=` and the rest of the assigning operators keep the name
        // in front of them.
        let before = before.trim_end_matches([':', '+', '-', '?']);
        // `N[1]=V`, and zsh's `N[1,-1]=V`, assign to `N`.
        let before = match before
            .strip_suffix(']')
            .and_then(|head| head.rfind('[').map(|open| &head[..open]))
        {
            Some(name) => name,
            None => before,
        };
        let head = before.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
        found.push(&before[head.len()..]);
    }
    for line in text.lines() {
        let words: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == ';')
            .filter(|word| !word.is_empty())
            .take_while(|word| !word.starts_with('#'))
            .collect();
        for (at, word) in words.iter().enumerate() {
            let named: Vec<&str> = match *word {
                // `for N in V` and `select N in V` name their control
                // variable immediately.
                "for" | "select" => words.get(at + 1).copied().into_iter().collect(),
                // `getopts OPTSTRING N` names it after the option string.
                "getopts" => words.get(at + 2).copied().into_iter().collect(),
                // `coproc N { ... }` names its array immediately.
                "coproc" => words.get(at + 1).copied().into_iter().collect(),
                // `read [-flags] N...`, `mapfile [-flags] N`, `readarray
                // [-flags] N`. Every *name-shaped* word after the command
                // is taken, not the first non-flag one: a flag's own
                // operand may sit between the flags and the target —
                // `read -p "Enter: " N`, `read -d '' N`, `read -rn 1 N` —
                // and `read` may name several targets at once. Taking them
                // all over-reports, which is the safe direction and is
                // what this function's contract promises.
                "read" | "mapfile" | "readarray" => words[at + 1..]
                    .iter()
                    .copied()
                    .filter(|operand| !operand.starts_with('-'))
                    .collect(),
                // `printf -v N V`, and any other `-v` target.
                "-v" => words.get(at + 1).copied().into_iter().collect(),
                _ => Vec::new(),
            };
            found.extend(named.into_iter().filter(|named| is_shell_name(named)));
        }
    }
    found
}

/// Assert that every name generated shell `text` gives a value to — found
/// by [`assignments_in`], and by the guard's own reading of each line — is
/// one of bx's own `BX_` names, which no tool reads, a name `text` declares
/// `local`, which never leaves its function, or one of `allowed`. Returns
/// the swept names and the locals, for the caller's non-vacuity checks.
#[track_caller]
fn assert_assigns_only<'a>(text: &'a str, allowed: &[&str]) -> (Vec<&'a str>, Vec<&'a str>) {
    let locals: Vec<&str> = text
        .lines()
        .filter_map(|line| line.trim_matches(BLANKS).strip_prefix("local "))
        .flat_map(str::split_whitespace)
        .filter(|word| !word.starts_with('-'))
        .map(|declared| declared.split('=').next().unwrap_or(declared))
        .collect();
    let admitted =
        |name: &str| name.starts_with("BX_") || locals.contains(&name) || allowed.contains(&name);
    let assigned = assignments_in(text);
    for name in &assigned {
        assert!(!name.is_empty(), "an assignment that names nothing");
        assert!(
            admitted(name),
            "{name} is given a value, and is neither one of bx's own names, \
             a local, nor one of {allowed:?}"
        );
    }
    for (idx, line) in text.split('\n').enumerate() {
        if let Statement::Assign { name, .. } = statement(line) {
            assert!(
                admitted(name),
                "line {} assigns {name}, which the guard would have to judge",
                idx + 1
            );
        }
    }
    (assigned, locals)
}

#[test]
fn the_assignment_sweep_sees_every_form_the_module_knows_assigns() {
    // What makes `assignments_in` a mechanism rather than another list.
    // Every form the module knows a shell assigns through is re-derived
    // here, at this head, from the table the module already keeps — so the
    // sweep cannot fall behind the forms without this failing, and a form
    // added to `ASSIGNING_FORMS` is held by the snippet check the same day
    // it is written.
    for form in ASSIGNING_FORMS {
        let content = form.replace("{N}", "CARGO_HOME").replace("{V}", "/x");
        assert!(
            assignments_in(&content).contains(&"CARGO_HOME"),
            "the sweep does not see {content:?} assign CARGO_HOME"
        );
    }
    // The exact shapes once measured returning nothing, where
    // a flag's own operand or a second target sat between the command and
    // the name. `read -d ''` is here and not in the table above because
    // the table's `{V}` substitution cannot express an empty delimiter.
    for form in [
        "read -p \"Enter: \" CARGO_HOME",
        "read -d '' CARGO_HOME",
        "read -rn 1 CARGO_HOME",
        "read -r A CARGO_HOME",
        "mapfile -t CARGO_HOME < /x",
        "readarray -t CARGO_HOME < /x",
        "coproc CARGO_HOME { :; }",
    ] {
        assert!(
            assignments_in(form).contains(&"CARGO_HOME"),
            "the sweep does not see {form:?} assign CARGO_HOME"
        );
    }
    // Not vacuous: shell that assigns nothing is reported as assigning
    // nothing, including prose that merely ends in a keyword.
    for quiet in [
        "compdef _bx bx 2>/dev/null",
        "# the user was already paying for",
        "[[ -n $X ]] && print -- $X",
    ] {
        assert_eq!(assignments_in(quiet), Vec::<&str>::new(), "{quiet:?}");
    }
}

#[test]
fn the_region_line_is_not_an_environment_fragment() {
    // The fixed region the `[[env]]` placement graph attaches to each zsh
    // startup file is generated shell content that is not an environment
    // fragment: two delimiter comments and one line that tests a fragment
    // and sources it. Invariant 2 requires of it that it carry no
    // environment assignment at all, and the plan does not send it through
    // the guard — whose grammar would refuse the line as unreadable, which
    // is no evidence that it sets nothing. So it is established here, of
    // the bytes the generator actually emits, for every place that has
    // one. The delimiters are `plan::region`'s, spelled out.
    use crate::config::env::{Place, source_line};
    use crate::paths::Portable;
    let mut regions = 0;
    for place in Place::ALL {
        if place.startup_file().is_none() {
            continue;
        }
        let fragment =
            Portable::parse_in(place.fragment(), Path::new(HOME)).expect("a portable path");
        let line = source_line(&fragment);
        let region = format!("# >>> bx >>>\n{line}# <<< bx <<<\n");
        assert_eq!(region.lines().count(), 3, "{region:?}");
        assert_eq!(assignments_in(&region), Vec::<&str>::new(), "{region:?}");
        for text in region.lines() {
            assert!(
                !matches!(statement(text), Statement::Assign { .. }),
                "{text:?}"
            );
        }
        // It names the fragment it sources and nothing else.
        assert_eq!(
            line,
            format!("[[ -r {0} ]] && source {0}\n", fragment.as_str())
        );
        regions += 1;
    }
    assert_eq!(regions, 3, "zshenv, zprofile and zshrc each have one");
}

#[test]
fn the_bash_profile_region_line_is_not_an_environment_fragment() {
    // The region bx attaches to `~/.bash_profile` on macOS is held to what
    // the zsh regions are, of the bytes its generator emits: it tests bash's
    // file and a function, and sources the file. It assigns nothing.
    use crate::paths::Portable;
    use crate::shell::bash::{FILE, LOADED, profile_line};
    let file = Portable::parse_in(FILE, Path::new(HOME)).expect("a portable path");
    let line = profile_line(&file);
    let region = format!("# >>> bx >>>\n{line}# <<< bx <<<\n");
    assert_eq!(region.lines().count(), 3, "{region:?}");
    assert_eq!(assignments_in(&region), Vec::<&str>::new(), "{region:?}");
    for text in region.lines() {
        assert!(
            !matches!(statement(text), Statement::Assign { .. }),
            "{text:?}"
        );
    }
    // It names the file it sources, and the function it asks about.
    assert_eq!(
        line,
        format!(
            "[[ -r {0} ]] && ! declare -F {LOADED} >/dev/null && source {0}\n",
            file.as_str()
        )
    );
}

#[test]
fn the_init_snippet_is_not_an_environment_fragment() {
    // Invariant 2 sends bx's generated environment fragments through the
    // guard, and requires of generated shell content that is *not* one of
    // them that it carry no environment assignment at all. The shell-init
    // snippet is one such file — a staleness test, a completion function,
    // a `compdef` — so that property has to be established of it rather
    // than assumed. The placement graph's region line is the other, and
    // `the_region_line_is_not_an_environment_fragment` establishes it.
    //
    // The bytes below are the benchmark's copy, and at this head they are
    // the *only* copy: no bx generator emits the snippet yet. So this
    // holds the snippet bx will emit, in the one place the repository
    // keeps it, and the generator that emits it must emit these bytes for
    // it to keep meaning that.
    //
    // It is established positively, and not out of the guard's inability
    // to parse the snippet: `Reason::Unreadable` says only that a line is
    // outside the grammar, which is no evidence at all that the line sets
    // nothing. Every name the snippet gives a value to is found instead —
    // through an `=` or through any of the assigning forms that hold no
    // `=`, which an `=` sweep alone misses — and each
    // must be one of bx's own `BX_` names, which no tool reads, or an
    // array the completion function declares `local`, which never leaves
    // that function.
    //
    // Written this way the test survives the snippet being reformatted,
    // and fails the moment a generator puts a real assignment in it.
    let snippet = include_str!("../../../bench/fixtures/bx/bx-init.zsh");
    let (assigned, locals) = assert_assigns_only(snippet, &[]);
    // Not vacuous: the staleness test is what the snippet is for, and it
    // is the two names found above.
    assert!(assigned.contains(&"BX_BIN") && assigned.contains(&"BX_STALE"));
    // So the guard reads no environment assignment out of it either. Every
    // line is a comment, a blank, or shell outside the grammar, but for the
    // one local array — whose value the grammar cannot read, so nothing is
    // learned from it and nothing is approved. Not even a `BX_` name.
    for (idx, line) in snippet.split('\n').enumerate() {
        if let Statement::Assign { name, .. } = statement(line) {
            assert!(
                locals.contains(&name),
                "line {} assigns {name}, which the guard would have to judge",
                idx + 1
            );
        }
    }
    assert!(
        pass(snippet, &RootSet::strict(), false)
            .1
            .learned
            .values()
            .all(Result::is_err)
    );
}

#[test]
fn the_update_prompt_is_not_an_environment_fragment() {
    // The second generated file under the no-assignment rule, after the
    // init snippet, and held to it the same way: every name the hook's
    // bytes give a value to is found, and each must be one of bx's own
    // `BX_` names, a local of the function that assigns it, or zsh's
    // `precmd_functions` — a hook array zsh cannot export, which says what
    // runs at a prompt and moves no tool's files, as the functions phase's
    // registrations do.
    let hook = crate::shell::update_prompt::ZSH;
    let (assigned, _) = assert_assigns_only(hook, &["precmd_functions"]);
    // Not vacuous: the once-per-shell markers, the registration, and the
    // locals the cross-shell wait assigns — the trap's included.
    for name in [
        "BX_UPDATE_ASKED",
        "BX_UPDATE_CHECKING",
        "precmd_functions",
        "answer",
        "woken",
        "outcome",
        "also",
        "left",
    ] {
        assert!(assigned.contains(&name), "{name}: {assigned:?}");
    }
    assert_eq!(
        hook.matches("trap ").count(),
        2,
        "one SIGURG trap set and taken down, under localtraps"
    );
    assert!(!hook.contains("eval"), "zsh puts the trap back itself");
    // Nothing is exported.
    assert!(!hook.contains("export"), "the hook exports nothing");
}

#[test]
fn the_bash_update_prompt_is_not_an_environment_fragment() {
    // The third generated file under the no-assignment rule, held to it as
    // the zsh hook is, with the one name bash has instead of a hook array:
    // `PROMPT_COMMAND`. A parent can export that, so it is admitted only in
    // the shapes that append to it, never replace it, and only behind the
    // test that leaves an exported or read-only one alone — so the append is
    // to a shell variable no process inherits, as a zsh hook array is. A line
    // after bx's region can still export it, so the appended entry names no
    // function: it expands the unexported BX_UPDATE_HOOK, and is nothing in a
    // child that inherits it.
    let hook = crate::shell::update_prompt::BASH;
    let (assigned, _) = assert_assigns_only(hook, &["PROMPT_COMMAND"]);
    for name in [
        "BX_UPDATE_ASKED",
        "BX_UPDATE_CHECKING",
        "BX_UPDATE_HOOK",
        "PROMPT_COMMAND",
        "answer",
        "now",
    ] {
        assert!(assigned.contains(&name), "{name}: {assigned:?}");
    }
    // Every assignment to PROMPT_COMMAND is one of the two appends, each
    // keeping the value it finds whole.
    let appends = [
        "PROMPT_COMMAND+=('${BX_UPDATE_HOOK-}')",
        "PROMPT_COMMAND=${PROMPT_COMMAND:+$PROMPT_COMMAND$'\\n'}'${BX_UPDATE_HOOK-}'",
    ];
    let mut registered = 0;
    for (at, _) in hook.match_indices("PROMPT_COMMAND") {
        let rest = &hook[at..];
        if rest.starts_with("PROMPT_COMMAND=") || rest.starts_with("PROMPT_COMMAND+=") {
            assert!(
                appends.iter().any(|append| rest.starts_with(append)),
                "PROMPT_COMMAND is assigned by something other than an append: {}",
                rest.lines().next().unwrap_or_default()
            );
            registered += 1;
        }
    }
    assert_eq!(registered, 2, "the scalar and the array append");
    assert_eq!(
        assigned
            .iter()
            .filter(|name| **name == "PROMPT_COMMAND")
            .count(),
        registered,
        "PROMPT_COMMAND is assigned in a form the appends above do not cover"
    );
    // Both appends sit behind the case that leaves an exported or read-only
    // PROMPT_COMMAND alone.
    let guard = hook
        .find("case ${PROMPT_COMMAND@a} in\n    *[xr]*) ;;")
        .expect("the attribute test");
    assert!(
        appends
            .iter()
            .all(|append| hook.find(append).is_some_and(|at| at > guard)),
        "an append outside the attribute test"
    );
    // Nothing is exported: the hook's comments say "exported"; no line runs
    // `export`.
    assert!(
        hook.lines()
            .all(|line| line.trim_start().starts_with('#') || !line.contains("export")),
        "the hook exports nothing"
    );
    assert!(!hook.contains("declare"), "nor declares a global");
    // The one `eval` puts back the SIGURG trap the shell had: its text is
    // what `trap -p URG` printed into the shell's waiting file, read back
    // past the generation line before the hook's own trap is set. Where that
    // file cannot be written, neither trap is touched.
    assert_eq!(
        hook.matches("eval").count(),
        1,
        "one eval, putting the trap back"
    );
    for piece in [
        "  if { printf '%s\\n' \"$gen\"; trap -p URG; } 2>/dev/null >| \"$dir/waiting/$$\"; then\n    \
         waits=1\n",
        "      read -r saved\n      read -r -d '' saved\n    } 2>/dev/null < \"$dir/waiting/$$\"\n    \
         trap 'woken=1' URG\n  fi\n",
        "  if [[ -n $waits ]]; then\n    : 2>/dev/null >| \"$dir/waiting/$$\"\n    trap - URG\n    \
         [[ -n $saved ]] && eval \"$saved\"\n  fi\n",
    ] {
        assert!(hook.contains(piece), "{piece}");
    }
    assert_eq!(
        assignments_in(hook)
            .iter()
            .filter(|name| **name == "saved")
            .count(),
        3,
        "saved is declared empty, then holds what trap -p printed and nothing else"
    );
}

#[test]
fn the_operator_fragment_and_a_data_home_beneath_its_root_scan_clean_in_all_three_layouts() {
    use Reason::{ContainsBxDirectory, DeclaredRootItself};
    // The home beside the scratch root, equal to it, and under it. A data
    // home at the root is refused in each: beside, because uv would write
    // beside the root; equal and under, because the root holds bx's
    // directories, which outranks it.
    //
    // The anchor is kept out of the environment here: exported, it
    // contains bx's directories in the last two layouts and is refused
    // there, which
    // `an_anchor_may_contain_bxs_directories_only_while_it_is_not_exported`
    // pins.
    let fragment = OPERATOR_FRAGMENT.replacen("export SCRATCH_HOME=", "SCRATCH_HOME=", 1);
    assert_ne!(fragment, OPERATOR_FRAGMENT);
    for (roots, at_root) in [
        (rooted(), DeclaredRootItself),
        (
            RootSet::new(Path::new(ROOT), &[PathBuf::from(ROOT)]),
            ContainsBxDirectory,
        ),
        (
            RootSet::new(
                Path::new("/var/mnt/scratch/example/home"),
                &[PathBuf::from(ROOT)],
            ),
            ContainsBxDirectory,
        ),
    ] {
        assert_eq!(scan_with(&fragment, &roots), vec![], "{roots:?}");
        let beneath = format!("{fragment}export XDG_DATA_HOME=\"$DATA_DIR\"\n");
        assert_eq!(scan_with(&beneath, &roots), vec![], "{roots:?}");
        let at = format!("{fragment}export XDG_DATA_HOME=\"$SCRATCH_HOME\"\n");
        assert_eq!(reasons(&at, &roots), vec![(26, at_root)], "{roots:?}");
    }
    // Written in terms of the home, under a `~` root.
    let home_rooted = home_rooted();
    let at_home = OPERATOR_FRAGMENT.replacen(
        "export SCRATCH_HOME=\"/var/mnt/scratch/example\"",
        "SCRATCH_HOME=\"$HOME\"",
        1,
    );
    assert_ne!(at_home, OPERATOR_FRAGMENT);
    assert_eq!(scan_with(&at_home, &home_rooted), vec![]);
    assert_eq!(
        reasons(
            &format!("{at_home}export XDG_DATA_HOME=\"$SCRATCH_HOME\"\n"),
            &home_rooted
        ),
        vec![(26, ContainsBxDirectory)]
    );
    let found = scan(OPERATOR_FRAGMENT);
    assert_eq!(found.len(), 25);
    assert!(found.iter().all(|v| v.reason == Reason::NoRootsDeclared));
}
