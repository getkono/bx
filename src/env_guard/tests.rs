//! The guard as a whole: `check` and the scans, the review rounds'
//! reproductions, and (in `census`) the sites outside this module that reach
//! it.

use std::path::{Path, PathBuf};

use super::fixtures::*;
use super::table::Setting;
use super::*;

mod census;
mod shells;

// `check` — a relocating variable is judged by where its value points.

#[test]
fn a_variable_that_does_not_relocate_is_allowed_without_reading_its_value() {
    // None of these values is a path at all. A name-based guard never had
    // to care; a value-based one must not start.
    for (name, value) in [
        ("EDITOR", "nvim"),
        ("SCCACHE_CACHE_SIZE", "100G"),
        ("MISE_VERBOSE", "1"),
        ("RUSTC_WRAPPER", "/usr/bin/sccache"),
    ] {
        assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
        // And it is allowed even with nothing declared at all.
        assert_eq!(
            check(name, value, &RootSet::strict()),
            Verdict::Allowed,
            "{name}"
        );
    }
}

#[test]
fn a_relocating_variable_inside_a_declared_root_is_allowed() {
    let verdict = check(
        "CARGO_HOME",
        "/var/mnt/scratch/example/cache/cargo",
        &rooted(),
    );
    assert_eq!(verdict, Verdict::Allowed);
    assert_eq!(reason_of(&verdict), None);
}

#[test]
fn a_relocating_variable_outside_every_root_is_a_violation() {
    // The violation carries everything a diagnostic needs to say what to
    // do about it. `check` judges one assignment outside any content, so
    // there is no line to report.
    assert_eq!(
        check("CARGO_HOME", "/var/cache/elsewhere", &rooted()),
        Verdict::Violation(Violation {
            line: 0,
            name: "CARGO_HOME".into(),
            value: "/var/cache/elsewhere".into(),
            reason: Reason::OutsideDeclaredRoots,
        })
    );
}

#[test]
fn the_declared_root_variable_itself_is_allowed() {
    // `SCRATCH_HOME` was caught by the `_HOME` suffix and, under the
    // name-based guard, denied outright — a false positive on the one
    // variable the whole configuration is written in terms of. The emit
    // table lists it as the location it is.
    assert_eq!(emittable("SCRATCH_HOME"), Some(Kind::Anchor));
    assert_eq!(check("SCRATCH_HOME", ROOT, &rooted()), Verdict::Allowed);
}

#[test]
fn with_no_root_declared_every_relocating_variable_is_a_violation() {
    for (name, value) in [
        ("CARGO_HOME", "/var/mnt/scratch/example/cache/cargo"),
        ("XDG_CACHE_HOME", "/anywhere"),
        ("MISE_DATA_DIR", "~/mise"),
    ] {
        refused(name, value, &RootSet::strict(), Reason::NoRootsDeclared);
    }
}

#[test]
fn a_root_set_with_a_home_but_no_roots_declares_nothing() {
    // Holding a home is not declaring a root: the strictness comes from the
    // root list being empty, not from the home being absent.
    let empty = RootSet::new(Path::new(HOME), &[]);
    assert_eq!(empty.home(), Some(Path::new(HOME)));
    refused("CARGO_HOME", "/x", &empty, Reason::NoRootsDeclared);
}

#[test]
fn an_empty_value_is_not_absolute() {
    // `export CARGO_HOME` with no value at all.
    refused("CARGO_HOME", "", &rooted(), Reason::NotAbsolute);
}

#[test]
fn a_location_given_a_word_is_not_absolute_and_an_unlisted_name_is_not_emittable() {
    // Round 5 retires `NotAPath`. It existed because a name list was the
    // only evidence that a variable held a location; the emit table now
    // says so, and a bare word, a number or a URL given to a location is a
    // path relative to wherever the shell is. The remedy is an absolute
    // path, which is what the reason says.
    for (name, value) in [
        ("CARGO_HOME", "1"),
        ("NPM_CONFIG_CACHE", "npm"),
        ("PIP_CACHE_DIR", "cache"),
        ("CARGO_HOME", "https://example.invalid/cargo"),
    ] {
        refused(name, value, &rooted(), Reason::NotAbsolute);
    }
    // Round 4 judged these by their names' families; the table lists none
    // of them, so each is refused whatever it is given.
    for (name, value) in [
        ("SOMETOOL_CONFIG_DIR", "yes"),
        ("PIP_TARGET", "build"),
        ("UV_PROJECT_ENVIRONMENT", "venv"),
        ("PIP_TIMEOUT", "60"),
        ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
        ("MISE_QUIET", "1"),
        ("PIP_NO_CACHE_DIR", "1"),
    ] {
        refused(name, value, &rooted(), Reason::NotEmittable);
    }
    assert_eq!(check("UV_NO_CACHE", "1", &rooted()), Verdict::Allowed);
}

#[test]
fn a_relative_value_is_not_absolute() {
    for value in ["cache/cargo", "./cargo", "../example/cargo"] {
        refused("CARGO_HOME", value, &rooted(), Reason::NotAbsolute);
    }
}

#[test]
fn another_users_home_is_refused() {
    // A shell expands `~other` to that account's home, which bx does not
    // resolve, so it cannot be shown to be inside any root. `~` is read
    // only alone or before `/`.
    for value in ["~other/cargo", "~+/cargo", "~-"] {
        refused("CARGO_HOME", value, &rooted(), Reason::Unreadable);
    }
}

#[test]
fn a_home_relative_value_is_a_violation_when_home_is_not_a_declared_root() {
    // Holding the home for `~` expansion is not the same as declaring it a
    // root. A relocation into `$HOME` is as invisible to a shell bx did not
    // initialise as one anywhere else.
    for value in ["~/x", "$HOME/x", "${HOME}/x"] {
        refused("CARGO_HOME", value, &rooted(), Reason::OutsideDeclaredRoots);
    }
    // Declaring home as a root is how a user opts in, and it then works.
    let home_rooted = home_rooted();
    assert_eq!(check("CARGO_HOME", "~/x", &home_rooted), Verdict::Allowed);
}

#[test]
fn bxs_own_state_directory_is_refused_even_inside_a_declared_root() {
    // The configuration that makes this reachable is the supported one:
    // the user declared their home a root, so containment alone would
    // allow it. `~/.local/state/bx` is where the ledger, the fingerprints
    // and the journal live; a tool pointed there writes among the files
    // that make `bx rm` exact.
    let home_rooted = home_rooted();
    for value in [
        "/var/home/example/.local/state/bx",
        "/var/home/example/.local/state/bx/ledger",
        "~/.local/state/bx",
        "$HOME/.local/state/bx/journal",
    ] {
        refused("CARGO_HOME", value, &home_rooted, Reason::BxOwnedDirectory);
    }
    // The parent is not bx's either, but it contains bx's state directory,
    // and a tool that clears it clears bx's record (r3 round 2). A sibling
    // whose name merely extends it is fine.
    refused(
        "CARGO_HOME",
        "~/.local/state",
        &home_rooted,
        Reason::ContainsBxDirectory,
    );
    assert_eq!(
        check("CARGO_HOME", "~/.local/state/bxtra", &home_rooted),
        Verdict::Allowed
    );
}

#[test]
fn a_state_directory_moved_by_the_environment_is_owned_when_it_is_declared() {
    // `RootSet::new` derives the state directory from the home, because a
    // resolution path may not read `XDG_STATE_HOME` itself. A caller that
    // did read it says so, and the derived one stays owned as well.
    let moved = PathBuf::from("/var/mnt/scratch/example/state/bx");
    let roots = rooted().owning(std::slice::from_ref(&moved));
    refused(
        "CARGO_HOME",
        "/var/mnt/scratch/example/state/bx",
        &roots,
        Reason::BxOwnedDirectory,
    );
    // Inside the declared root, and still refused - the exclusion outranks
    // the root test rather than being overridden by it.
    assert!(roots.contains(&moved));
    // And the home-derived directory is owned too, though this set's own
    // root does not contain it.
    assert!(roots.owns(Path::new("/var/home/example/.local/state/bx")));
}

#[test]
fn a_program_needs_no_root_but_may_not_live_in_bxs_directory() {
    // The exclusion holds for a program too. A program inside bx's state
    // directory is one `bx rm` deletes, so even a kind that needs no root
    // may not point there — and it may point at an ordinary program with
    // no root declared at all.
    refused(
        "EDITOR",
        "/var/home/example/.local/state/bx/editor",
        &rooted(),
        Reason::BxOwnedDirectory,
    );
    for roots in [
        rooted(),
        RootSet::new(Path::new(HOME), &[]),
        RootSet::strict(),
    ] {
        assert_eq!(check("EDITOR", "/usr/bin/nvim", &roots), Verdict::Allowed);
    }
}

// `scan_with` — the same rule over a whole fragment, with a learned
// environment.

#[test]
fn scan_denies_every_relocation_and_nothing_else() {
    // What the strict guard actually returns, written out. Comparing
    // `scan` against `scan_with(_, &RootSet::strict())` is `scan`'s own
    // definition and cannot fail, so it shows nothing.
    //
    // This is not the name-based guard's output either: six widened names
    // are denied here that it allowed. What survives from it is the
    // direction — with no root declared, every relocating assignment is
    // refused and nothing else is touched.
    for (content, expected) in [
        ("export EDITOR=nvim\n", vec![]),
        ("export SCCACHE_CACHE_SIZE=100G\n", vec![]),
        ("# export CARGO_HOME=/x\n", vec![]),
        ("# source ~/.cargo/env\n", vec![]),
        ("export CARGO_HOME=$HOME/x\n", vec![(1, "CARGO_HOME")]),
        (
            "export GOPATH=/x\n# source ~/.cargo/env\n",
            vec![(1, "GOPATH")],
        ),
        // Widened: the name-based guard let this one through unchecked.
        ("export GOCACHE=/x\n", vec![(1, "GOCACHE")]),
        (
            "export XDG_CACHE_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n",
            vec![(1, "XDG_CACHE_HOME"), (3, "RUSTUP_HOME")],
        ),
    ] {
        let found = scan(content);
        assert_eq!(
            found
                .iter()
                .map(|violation| (violation.line, violation.name.as_str()))
                .collect::<Vec<_>>(),
            expected,
            "{content}"
        );
        assert!(
            found
                .iter()
                .all(|violation| violation.reason == Reason::NoRootsDeclared),
            "{content}"
        );
    }
}

#[test]
fn the_kinds_that_move_nothing_need_no_root() {
    // "Declare no root and nothing moves" is true of the three kinds that
    // say where a tool keeps its files — a location, a list of them and an
    // anchor — and of nothing else. A program is one the tool runs, a
    // search list is where it looks, a socket is what it connects to, and
    // a setting is not a path at all: none of them moves a tool's config,
    // data or cache, which is what invariant 2 is about, so none needs a
    // root. The module documentation, and the summaries of it in
    // `CLAUDE.md` and `README.md`, are written to say exactly that, and this
    // is what holds them to it.
    for (name, value) in [
        ("PATH", "/etc/evil:/usr/bin"),
        ("INFOPATH", "/etc/evil"),
        ("SSH_AUTH_SOCK", "/tmp/agent/s"),
        ("EDITOR", "/usr/bin/vim"),
        ("RUSTC_WRAPPER", "sccache"),
        ("MISE_JOBS", "8"),
    ] {
        assert_eq!(
            scan(&format!("export {name}={value}\n")),
            vec![],
            "{name}={value}"
        );
    }
    // And false of the three that do move something: with nothing
    // declared each is refused for having no root, whatever its value.
    for (name, value) in [
        ("CARGO_HOME", "/etc/evil"),
        ("GOPATH", "/etc/evil:/usr/lib/go"),
        ("SCRATCH_HOME", "/etc/evil"),
    ] {
        refused(name, value, &RootSet::strict(), Reason::NoRootsDeclared);
    }
    // Needing no root is not a licence: bx's own directories are still
    // refused to every one of them.
    let owned = "/var/home/example/.local/state/bx/x";
    for name in ["PATH", "INFOPATH", "SSH_AUTH_SOCK", "EDITOR"] {
        assert_eq!(
            reason_of(&check(name, owned, &RootSet::new(Path::new(HOME), &[]))),
            Some(Reason::BxOwnedDirectory),
            "{name}"
        );
    }
}

#[test]
fn a_set_with_no_home_is_never_asked_what_holds_bxs_directories() {
    // `owns` and `in_config_repo` recognise bx's directories under any
    // home, so a set with none still refuses a path into them. The
    // containing check has no such fallback and cannot have one: a
    // `.local/state/bx` may lie under any path at all, so a fallback would
    // have to refuse every path a homeless set is shown. Answering `false`
    // is sound only while the check is reached from `refuses_entry_bx`
    // alone, behind `refuses_everything`. Both halves are pinned here, so
    // a later kind given a containing check cannot inherit the hole
    // unnoticed.
    let strict = RootSet::strict();
    assert!(strict.owns(Path::new("/x/.local/state/bx/ledger")));
    assert!(strict.in_config_repo(Path::new("/x/.config/bx/bx.toml")));
    assert!(!strict.holds_bx_directory(Path::new("/x")));
    // The only set without a home declares no root, so every kind that
    // consults the containing check is refused before it is reached.
    assert!(strict.refuses_everything().is_some());
    for name in ["CARGO_HOME", "SCRATCH_HOME"] {
        refused(name, "/x", &strict, Reason::NoRootsDeclared);
    }
    // A set that does have a home answers the containing question, which
    // is the only configuration that asks it.
    refused(
        "CARGO_HOME",
        "/var/home/example/.local",
        &home_rooted(),
        Reason::ContainsBxDirectory,
    );
}

#[test]
fn a_second_assignment_on_one_line_is_refused_rather_than_half_judged() {
    // A real shell exports both names. Judging the head alone allowed the
    // tail unread: this line is clean to a guard that stops at the first
    // value, and `GOPATH` lands outside every root. The name-based guard
    // this replaced denied the line, so allowing it would invert the
    // guard's error direction between two commits.
    let content = "export CARGO_HOME=/var/mnt/scratch/example/cargo GOPATH=/etc/evil\n";
    assert_eq!(
        scan_with(content, &rooted()),
        vec![Violation {
            line: 1,
            name: "CARGO_HOME".into(),
            value: "/var/mnt/scratch/example/cargo GOPATH=/etc/evil".into(),
            reason: Reason::MultipleAssignments,
        }]
    );
    // The head need not relocate anything for the tail to matter.
    let content = "export EDITOR=nvim GOPATH=/etc/evil\n";
    assert_eq!(
        scan_with(content, &rooted())
            .iter()
            .map(|violation| violation.reason)
            .collect::<Vec<_>>(),
        vec![Reason::MultipleAssignments]
    );
}

#[test]
fn a_valueless_export_is_refused_and_teaches_the_scan_nothing() {
    // `export X` marks an inherited value for export; it does not set `X`.
    // Round 2 judged it and learned nothing. Round 3 does not read it at
    // all — bx has no reason to export a value it did not write — so it is
    // refused, and a later reference is as unknown as after any refused
    // line.
    let content = concat!(
        "export X\n",
        "export CARGO_HOME=$X/var/mnt/scratch/example/cargo\n",
    );
    assert_eq!(
        reasons(content, &rooted()),
        vec![(1, Reason::Unreadable), (2, Reason::UnreadableReference)]
    );
    assert_eq!(
        reasons("export CARGO_HOME\n", &rooted()),
        vec![(1, Reason::Unreadable)]
    );
    // `setenv` is csh, and neither bash nor zsh has it.
    let content = concat!(
        "setenv SCRATCH_HOME /var/mnt/scratch/example\n",
        "export CARGO_HOME=$SCRATCH_HOME/cargo\n",
    );
    assert_eq!(
        reasons(content, &rooted()),
        vec![(1, Reason::Unreadable), (2, Reason::UnreadableReference)]
    );
}

#[test]
fn a_refused_line_teaches_the_scan_nothing() {
    // The head's "value" is not the value any shell would give the name,
    // so learning it would resolve a later reference to a fiction.
    let content = concat!(
        "A=/var/mnt/scratch/example B=/etc\n",
        "export CARGO_HOME=$A/cargo\n",
    );
    let found = scan_with(content, &rooted());
    assert_eq!(
        found
            .iter()
            .map(|violation| (violation.line, violation.reason))
            .collect::<Vec<_>>(),
        vec![
            (1, Reason::MultipleAssignments),
            (2, Reason::UnreadableReference),
        ]
    );
    // Nor may it leave an *earlier* value standing: a shell has replaced
    // it, so a guard that kept it would judge a path no shell produces.
    for refused in [
        "A=/etc B=1",
        "true && A=/etc",
        "export B A=/etc",
        "declare -n A=OTHER",
    ] {
        let content = format!("A={ROOT}\n{refused}\nexport CARGO_HOME=$A/cargo\n");
        assert_eq!(
            scan_with(&content, &rooted())
                .iter()
                .map(|violation| (violation.line, violation.reason))
                .next_back(),
            Some((3, Reason::UnreadableReference)),
            "{refused}"
        );
    }
}

#[test]
fn a_guarded_block_is_read_and_what_it_hides_is_still_judged() {
    // Every runtime `when` renders an opener the grammar reads, and the
    // assignment inside is judged like any other.
    for test in [
        "[[ -o interactive ]]",
        "[[ -o login ]]",
        "[[ -n ${SSH_CONNECTION-} ]]",
        "[[ -n ${TMUX+x} ]]",
        "[[ ${TERM_PROGRAM-} == \"WezTerm\" ]]",
    ] {
        let ok = format!("if {test}; then\n  export CARGO_HOME={ROOT}/cargo\nfi\n");
        assert_eq!(scan_with(&ok, &rooted()), vec![], "{ok}");
        // A relocating export behind a condition is refused at its line.
        let hidden = format!("if {test}; then\n  export CARGO_HOME=/var/cache/elsewhere\nfi\n");
        assert_eq!(
            reasons(&hidden, &rooted()),
            vec![(2, Reason::OutsideDeclaredRoots)],
            "{hidden}"
        );
    }
}

#[test]
fn a_block_that_is_not_one_a_when_renders_is_refused() {
    let body = format!("  export CARGO_HOME={ROOT}/cargo\n");
    for (content, line) in [
        // Inlined beside the assignment rather than guarding a block.
        (
            format!("[[ -o interactive ]] && export CARGO_HOME={ROOT}/cargo\n"),
            1,
        ),
        // A runtime tool lookup, which a `has:` never renders.
        (format!("if command -v sccache; then\n{body}fi\n"), 1),
        (format!("if [[ -o monitor ]]; then\n{body}fi\n"), 1),
        // A stray `fi`.
        (format!("{body}fi\n"), 2),
        // A nested opener.
        (
            format!("if [[ -o login ]]; then\nif [[ -o login ]]; then\n{body}fi\nfi\n"),
            2,
        ),
        // A block never closed, refused where it opened.
        (format!("if [[ -o login ]]; then\n{body}"), 1),
    ] {
        let found = reasons(&content, &rooted());
        assert!(
            found.contains(&(line, Reason::Unreadable)),
            "{content}: {found:?}"
        );
    }
}

#[test]
fn environment_d_reads_no_block() {
    let content = format!("if [[ -o login ]]; then\nCARGO_HOME={ROOT}/cargo\nfi\n");
    let found = scan_exported(&content, &rooted());
    assert_eq!(found[0].line, 1);
    assert_eq!(found[0].reason, Reason::Unreadable);
}

#[test]
fn a_name_a_block_assigned_is_unknown_after_it() {
    // The shell may or may not have run the block, so the name holds one
    // of two values and a later reference to it cannot be judged. Inside
    // the block it is known.
    let content = format!(
        "SCRATCH_HOME={ROOT}\n\
             if [[ -o login ]]; then\n  SCRATCH_HOME=/etc\n  export GOPATH=$SCRATCH_HOME/go\nfi\n\
             export CARGO_HOME=$SCRATCH_HOME/cargo\n"
    );
    assert_eq!(
        reasons(&content, &rooted()),
        vec![
            (3, Reason::OutsideDeclaredRoots),
            (4, Reason::OutsideDeclaredRoots),
            (6, Reason::UnreadableReference)
        ]
    );
    // A name the block did not assign is still known after it.
    let content = format!(
        "SCRATCH_HOME={ROOT}\nif [[ -o login ]]; then\nfi\n\
             export CARGO_HOME=$SCRATCH_HOME/cargo\n"
    );
    assert_eq!(scan_with(&content, &rooted()), vec![]);
}

#[test]
fn whitespace_in_a_value_is_not_a_second_assignment() {
    // The refusal is for another `NAME=`, not for a space: a quoted path
    // with a space in it, and a trailing comment, both still resolve.
    // Since r3 round 3 the space is itself refused, by name, as a
    // character no path bx writes holds, and never as a second assignment.
    assert_eq!(
        reasons(
            "export CARGO_HOME=\"/var/mnt/scratch/example/my cache\"\n",
            &rooted()
        ),
        vec![(1, Reason::UnlistedCharacter(' '))]
    );
    assert_eq!(
        scan_with(
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # written by bx\n",
            &rooted()
        ),
        vec![]
    );
}

#[test]
fn violations_are_reported_in_line_order() {
    let content = concat!(
        "export CARGO_HOME=/elsewhere/a\n",
        "export EDITOR=nvim\n",
        "export RUSTUP_HOME=/var/mnt/scratch/example/rustup\n",
        "export GOPATH=/elsewhere/b\n",
    );
    let found = scan_with(content, &rooted());
    assert_eq!(found.iter().map(|v| v.line).collect::<Vec<_>>(), vec![1, 4]);
    assert_eq!(
        found.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        vec!["CARGO_HOME", "GOPATH"]
    );
}

#[test]
fn scanning_the_same_content_twice_returns_the_same_violations() {
    // Invariant 3. The guard is a pure function of `(content, roots)`: it
    // reads no process environment, touches no disk, and holds its roots in
    // declaration order, so no iteration order can reach the output.
    let content = OPERATOR_FRAGMENT;
    assert_eq!(scan_with(content, &rooted()), scan_with(content, &rooted()));
    assert_eq!(scan(content), scan(content));
}

#[test]
fn the_six_names_that_used_to_leak_are_now_checked() {
    // Each of these relocates a real toolchain cache and matched no rule in
    // the name list, so the guard let it through unexamined. This is the
    // regression test for that defect: they are checked now, and checking
    // means allowed inside a declared root and rejected outside every one.
    for name in [
        "PNPM_CONFIG_STORE_DIR",
        "GOCACHE",
        "NUGET_HTTP_CACHE_PATH",
        "HOMEBREW_CACHE",
        "HOMEBREW_LOGS",
        "HOMEBREW_TEMP",
    ] {
        assert_eq!(emittable(name), Some(Kind::Location), "{name}");
        assert_eq!(
            check(name, "/var/mnt/scratch/example/x", &rooted()),
            Verdict::Allowed,
            "{name}"
        );
        refused(
            name,
            "/var/cache/elsewhere",
            &rooted(),
            Reason::OutsideDeclaredRoots,
        );
    }
}

#[test]
fn an_sccache_directory_is_value_checked() {
    // The motivating case for the root set being a *set*: an sccache
    // directory may legitimately live outside the scratch root, and must
    // then be covered by a root of its own rather than waved through.
    assert_eq!(emittable("SCCACHE_DIR"), Some(Kind::Location));
    // The setting that shares its prefix is a size, and a name that
    // shares it and is not in the table is not emittable at all.
    assert_eq!(
        emittable("SCCACHE_CACHE_SIZE"),
        Some(Kind::Setting(Setting::Size))
    );
    assert_eq!(emittable("SCCACHE_SERVER_UDS"), None);

    let roots = RootSet::new(
        Path::new(HOME),
        &[PathBuf::from(ROOT), PathBuf::from("/var/cache/sccache")],
    );
    assert_eq!(
        check("SCCACHE_DIR", "/var/cache/sccache/objects", &roots),
        Verdict::Allowed
    );
    refused(
        "SCCACHE_DIR",
        "/var/cache/sccache/objects",
        &rooted(),
        Reason::OutsideDeclaredRoots,
    );
}

#[test]
fn the_same_fragment_is_all_violations_with_no_root_declared() {
    // A user who declares no root gets the strict guard, and the strict
    // guard refuses every location. Round 5 keeps the count at 25: the 23
    // exports and the two helpers `CACHE_DIR` and `DATA_DIR` are all in
    // the emit table, as locations, a list of them, or anchors, each of
    // which needs a root. So every one is `NoRootsDeclared` and none is
    // `NotEmittable`.
    let found = scan(OPERATOR_FRAGMENT);
    assert_eq!(found.len(), 25);
    assert!(found.iter().all(|v| v.reason == Reason::NoRootsDeclared));
    assert!(found.windows(2).all(|w| w[0].line < w[1].line));
    assert!(found.iter().any(|v| v.name == "CACHE_DIR"));
    assert!(found.iter().any(|v| v.name == "DATA_DIR"));
}

#[test]
fn the_operator_fragment_scans_clean_under_its_declared_root() {
    assert_eq!(scan_with(OPERATOR_FRAGMENT, &rooted()), vec![]);
}

#[test]
fn scan_reports_the_offending_line_and_name() {
    let content = "export EDITOR=nvim\nexport CARGO_HOME=$HOME/x\n";
    assert_eq!(
        scan(content),
        vec![Violation {
            line: 2,
            name: "CARGO_HOME".into(),
            value: "$HOME/x".into(),
            reason: Reason::NoRootsDeclared,
        }]
    );
}

#[test]
fn scan_accepts_clean_content() {
    let content =
        "# bx generated\nexport SCCACHE_CACHE_SIZE=100G\nexport RUSTC_WRAPPER=/usr/bin/sccache\n";
    assert!(scan(content).is_empty());
}

#[test]
fn scan_judges_its_two_assignment_forms_and_refuses_every_other() {
    for line in [
        "export CARGO_HOME=/x",
        "CARGO_HOME=/x",
        "  export CARGO_HOME=/x",
        "\texport\tCARGO_HOME=/x # note",
    ] {
        assert_eq!(
            scan(line)
                .iter()
                .map(|violation| (violation.name.as_str(), violation.reason))
                .collect::<Vec<_>>(),
            vec![("CARGO_HOME", Reason::NoRootsDeclared)],
            "should have judged: {line}"
        );
    }
    for line in [
        "typeset -x CARGO_HOME=/x",
        "declare -x CARGO_HOME=/x",
        "setenv CARGO_HOME /x",
        "declare -gx CARGO_HOME=/x",
        "typeset -gx CARGO_HOME=/x",
        "export -- CARGO_HOME=/x",
        "readonly CARGO_HOME=/x",
        "local CARGO_HOME=/x",
        "export CARGO_HOME+=/x",
    ] {
        assert_eq!(
            scan(line),
            vec![Violation {
                line: 1,
                name: String::new(),
                value: line.into(),
                reason: Reason::Unreadable,
            }],
            "should have refused: {line}"
        );
    }
}

#[test]
fn scan_ignores_comments() {
    assert!(scan("# export CARGO_HOME=/x\n   # CARGO_HOME=/x").is_empty());
}

#[test]
fn scan_refuses_a_line_that_is_not_a_statement_it_reads() {
    // Round 2 let a command through as assigning nothing. Round 3 does not
    // decide what a command assigns: a line that is not blank, a comment or
    // an assignment in the grammar is refused.
    assert_eq!(
        reasons(
            "source ~/.cargo/env\n\n[[ -r $f ]] && source $f\n2bad=x\n=x",
            &RootSet::strict()
        ),
        vec![
            (1, Reason::Unreadable),
            (3, Reason::Unreadable),
            (4, Reason::Unreadable),
            (5, Reason::Unreadable),
        ]
    );
}

// Review round 2: the guard fails closed on shell it cannot read, reads
// a value quote-aware, and gives one verdict whichever entry point asks.

#[test]
fn a_keyword_other_than_export_is_refused_whatever_it_assigns() {
    // Each of these sets `CARGO_HOME=/etc/evil` in bash or zsh. Round 2
    // read the keyword and judged the operand; round 3 reads no keyword but
    // `export`, so each is refused before its operand is looked at — and
    // so would be the next spelling of a keyword round 2 did not know.
    for line in [
        "declare -gx CARGO_HOME=/etc/evil",
        "typeset -gx CARGO_HOME=/etc/evil",
        "export -- CARGO_HOME=/etc/evil",
        "readonly CARGO_HOME=/etc/evil",
        "local CARGO_HOME=/etc/evil",
        "export -x CARGO_HOME=/etc/evil",
    ] {
        assert_eq!(
            scan(line),
            vec![Violation {
                line: 1,
                name: String::new(),
                value: line.into(),
                reason: Reason::Unreadable,
            }],
            "{line}"
        );
        assert_eq!(
            reasons(line, &rooted()),
            vec![(1, Reason::Unreadable)],
            "{line}"
        );
    }
}

#[test]
fn a_line_the_guard_cannot_read_is_never_approved() {
    // A second assignment after a value: refused as one, and not learned.
    for line in [
        "export FOO=1 CARGO_HOME=/etc/evil",
        "FOO=1 CARGO_HOME=/etc/evil",
    ] {
        assert_eq!(
            reasons(line, &RootSet::strict()),
            vec![(1, Reason::MultipleAssignments)],
            "{line}"
        );
    }
    // Anything else that mentions a keyword, or assigns where a command
    // starts, and is not a form the guard reads.
    for line in [
        "export FOO CARGO_HOME=/etc/evil",
        "export A B CARGO_HOME=/etc/evil",
        "export PATH CARGO_HOME=/var/mnt/scratch/example/cargo",
        "true && export CARGO_HOME=/etc/evil",
        "[ -d /x ] && CARGO_HOME=/etc/evil",
        "builtin export CARGO_HOME=/etc/evil",
        "export CARGO_HOME=/etc/evil; echo done",
        "declare -n CARGO_HOME=OTHER",
        "typeset -u CARGO_HOME=/var/mnt/scratch/example",
        "export +x CARGO_HOME",
        "export CARGO_HOME=\"/var/mnt/scratch/example",
        "export EDITOR=nvim --wait",
        "export \\",
        "CARGO_HOME=/var/mnt/scratch/example cargo build",
    ] {
        assert_eq!(
            reasons(line, &rooted()),
            vec![(1, Reason::Unreadable)],
            "{line}"
        );
    }
    // A line refused before a variable can be picked out of it quotes
    // itself back whole, without its indentation.
    assert_eq!(
        scan("  true && export CARGO_HOME=/etc/evil # note"),
        vec![Violation {
            line: 1,
            name: String::new(),
            value: "true && export CARGO_HOME=/etc/evil # note".into(),
            reason: Reason::Unreadable,
        }]
    );
}

#[test]
fn a_prefix_does_not_carry_a_value_past_bxs_own_directory() {
    // The exclusion the module calls unconditional, bypassed by one word.
    let wide = home_rooted();
    let state = "/var/home/example/.local/state/bx";
    assert_eq!(
        reasons(&format!("export CARGO_HOME={state}"), &wide),
        vec![(1, Reason::BxOwnedDirectory)]
    );
    for line in [
        format!("declare -gx CARGO_HOME={state}"),
        format!("export FOO CARGO_HOME={state}"),
    ] {
        assert_eq!(
            reasons(&line, &wide),
            vec![(1, Reason::Unreadable)],
            "{line}"
        );
    }
    assert_eq!(
        reasons(&format!("export FOO=1 CARGO_HOME={state}"), &wide),
        vec![(1, Reason::MultipleAssignments)]
    );
}

#[test]
fn a_value_or_a_line_the_guard_does_not_read_is_refused_whatever_the_name() {
    // A command substitution, an escape, a brace expansion, an array and
    // mixed quoting are shell the guard does not run. Round 2 refused them
    // for a relocating variable only; round 3 refuses them for every one,
    // because a line the grammar does not read may do anything whatever
    // its first name is.
    for name in ["CARGO_HOME", "EDITOR"] {
        for value in [
            "$(pwd)/cargo",
            "\"$(pwd)/cargo\"",
            "`pwd`/cargo",
            "/var/mnt/scratch/example/\\../cargo",
            "/var/mnt/scratch/example/{..,x}",
            "(/var/mnt/scratch/example)",
            "'/var/mnt/scratch/example'/$X",
        ] {
            refused(name, value, &rooted(), Reason::Unreadable);
        }
    }
    // Ordinary rc content that round 2 let through as assigning nothing.
    for line in [
        "export GPG_TTY=$(tty)",
        "export GIT_TOP=\"$(git rev-parse --show-toplevel)\"",
        "path=(/var/mnt/scratch/example/bin $path)",
        "export PATH+=:/var/mnt/scratch/example/bin",
        "alias ll='ls -l'",
        "eval \"$(mise activate zsh)\"",
        "make V=1",
    ] {
        assert_eq!(
            reasons(line, &rooted()),
            vec![(1, Reason::Unreadable)],
            "{line}"
        );
    }
    // And what it could not read, it does not learn.
    let content = "X=$(pwd)\nexport CARGO_HOME=$X/cargo\n";
    assert_eq!(
        reasons(content, &rooted()),
        vec![(1, Reason::Unreadable), (2, Reason::UnreadableReference)]
    );
}

#[test]
fn a_quoted_tilde_is_a_literal_tilde() {
    // A shell expands `~` only unquoted at the start of a value. Quoted, or
    // arriving through a reference, it is a relative path.
    let home_rooted = home_rooted();
    assert_eq!(
        check("CARGO_HOME", "~/cargo", &home_rooted),
        Verdict::Allowed
    );
    for value in ["\"~/cargo\"", "'~/cargo'"] {
        refused("CARGO_HOME", value, &home_rooted, Reason::NotAbsolute);
    }
    // A literal `~` given to a location is a relative path.
    assert_eq!(
        reasons(
            "SCRATCH_HOME='~'\nexport CARGO_HOME=$SCRATCH_HOME/cargo\n",
            &home_rooted
        ),
        vec![(1, Reason::NotAbsolute), (2, Reason::NotAbsolute)]
    );
}

#[test]
fn a_single_assignment_with_an_equals_sign_in_its_value_is_not_two() {
    // Each assigns one variable. The `=` is inside the value, so the old
    // remedy — split the line — was impossible to follow.
    // Since r3 round 3 a space in a location is refused by name; what is
    // pinned is that none of these is read as two assignments.
    for (line, expected) in [
        (
            "export CARGO_HOME=\"/var/mnt/scratch/example/-j8 V=1\"",
            vec![(1, Reason::UnlistedCharacter(' '))],
        ),
        (
            "export CARGO_HOME='/var/mnt/scratch/example/-j8 V=1'",
            vec![(1, Reason::UnlistedCharacter(' '))],
        ),
        (
            "export CARGO_HOME=/var/mnt/scratch/example/cargo # keep=this",
            vec![],
        ),
        (
            "export CARGO_HOME=\"/var/mnt/scratch/example/a b=c/cargo\"",
            vec![(1, Reason::UnlistedCharacter(' '))],
        ),
    ] {
        assert_eq!(reasons(line, &rooted()), expected, "{line}");
    }
    // Unquoted, the same text is two assignments to a shell, and says so.
    assert_eq!(
        reasons("export MAKEFLAGS=-j8 V=1", &rooted()),
        vec![(1, Reason::MultipleAssignments)]
    );
}

#[test]
fn check_and_scan_give_one_verdict() {
    // `check` and `scan_with` both call `evaluate`, so a value that is not
    // one shell word is refused whichever entry point is asked.
    for (name, value, reason) in [
        (
            "CARGO_HOME",
            "/var/mnt/scratch/example/cargo FOO=/etc/evil",
            Some(Reason::MultipleAssignments),
        ),
        (
            "EDITOR",
            "nvim GOPATH=/etc/evil",
            Some(Reason::MultipleAssignments),
        ),
        ("EDITOR", "nvim --wait", Some(Reason::Unreadable)),
        (
            "CARGO_HOME",
            " /var/mnt/scratch/example",
            Some(Reason::Unreadable),
        ),
        ("MAKEFLAGS", "\"-j8 V=1\"", Some(Reason::NotEmittable)),
        (
            "CARGO_HOME",
            "\"/var/mnt/scratch/example/a b\"",
            Some(Reason::UnlistedCharacter(' ')),
        ),
        ("CARGO_HOME", "$(pwd)", Some(Reason::Unreadable)),
        ("CARGO_HOME", "/etc", Some(Reason::OutsideDeclaredRoots)),
    ] {
        assert_eq!(
            reason_of(&check(name, value, &rooted())),
            reason,
            "check {name}={value}"
        );
        assert_eq!(
            scan_with(&format!("export {name}={value}"), &rooted())
                .first()
                .map(|violation| violation.reason),
            reason,
            "scan {name}={value}"
        );
    }
}

#[test]
fn an_inadmissible_root_is_not_mistaken_for_no_root() {
    // `scratch_root = "/"` visibly declares a root. Telling that user no
    // root is declared sends them looking for a declaration that exists.
    let dropped = RootSet::new(Path::new(HOME), &[PathBuf::from("/")]);
    let nothing = RootSet::new(Path::new(HOME), &[]);
    assert_ne!(dropped, nothing);
    assert_eq!(dropped.home(), nothing.home());
    assert_eq!(dropped.inadmissible(), &[PathBuf::from("/")]);
    assert!(nothing.inadmissible().is_empty());
    assert!(RootSet::strict().inadmissible().is_empty());
    refused("CARGO_HOME", "/x", &dropped, Reason::InadmissibleRoot);
    refused("CARGO_HOME", "/x", &nothing, Reason::NoRootsDeclared);
    assert_eq!(
        reasons("export CARGO_HOME=/x\n", &dropped),
        vec![(1, Reason::InadmissibleRoot)]
    );
    // Beside an admissible root, the refused one is still reported.
    let mixed = RootSet::new(
        Path::new(HOME),
        &[PathBuf::from("/.."), PathBuf::from(ROOT)],
    );
    assert_eq!(mixed.inadmissible(), &[PathBuf::from("/..")]);
    assert_eq!(
        check("CARGO_HOME", "/var/mnt/scratch/example/cargo", &mixed),
        Verdict::Allowed
    );
}

#[test]
fn behaviour_variables_in_a_location_family_are_allowed() {
    // A setting the table lists relocates nothing, so it needs no root.
    for (name, value) in [("UV_NO_CACHE", "1"), ("MISE_JOBS", "8")] {
        assert_eq!(check(name, value, &rooted()), Verdict::Allowed, "{name}");
        assert_eq!(
            check(name, value, &RootSet::strict()),
            Verdict::Allowed,
            "{name}"
        );
    }
    // Round 4 allowed the rest of the family as settings. The table does
    // not list them, so round 5 refuses them, with or without a root.
    for (name, value) in [
        ("NPM_CONFIG_REGISTRY", "https://registry.example.invalid"),
        ("NPM_CONFIG_FUND", "false"),
        ("NPM_CONFIG_LOGLEVEL", "warn"),
        ("PIP_INDEX_URL", "https://pypi.example.invalid/simple"),
        ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
        ("UV_PYTHON", "3.12"),
        ("MISE_ENV", "production"),
        ("ASDF_CONCURRENCY", "8"),
    ] {
        for roots in [rooted(), RootSet::strict()] {
            refused(name, value, &roots, Reason::NotEmittable);
        }
    }
}

#[test]
fn a_family_variable_that_holds_a_location_is_still_judged() {
    // Invariant 2 is not relaxed for the same families: a location given a
    // path is judged by where it points, and one whose name says it holds a
    // location is refused a bare word, which is a path relative to
    // wherever the shell happens to be.
    for name in [
        "UV_CACHE_DIR",
        "PIP_CACHE_DIR",
        "NPM_CONFIG_CACHE",
        "MISE_DATA_DIR",
        "MISE_CACHE_DIR",
    ] {
        refused(name, "cache", &rooted(), Reason::NotAbsolute);
        refused(name, "/etc/evil", &rooted(), Reason::OutsideDeclaredRoots);
        refused(name, ".cache/x", &rooted(), Reason::NotAbsolute);
    }
    // The family's other locations are not in the table at all.
    for name in [
        "UV_TOOL_DIR",
        "PIP_TARGET",
        "NPM_CONFIG_PREFIX",
        "NPM_CONFIG_USERCONFIG",
        "MISE_INSTALL_PATH",
        "UV_PROJECT_ENVIRONMENT",
    ] {
        refused(
            name,
            "/var/mnt/scratch/example/x",
            &rooted(),
            Reason::NotEmittable,
        );
    }
}

#[test]
fn scan_reports_every_violation() {
    let content = "export XDG_CACHE_HOME=/a\nexport EDITOR=nvim\nexport RUSTUP_HOME=/b\n";
    let found = scan(content);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].line, 1);
    assert_eq!(found[1].line, 3);
}

// Review rounds 3 and 4: each reproduction, written against the API of the
// round before it and labelled with its round and item. The guard approves
// none of them, under any root set its row names.

/// The root sets a reproduction is scanned under, each built afresh.
type Sets = &'static [fn() -> RootSet];

const ROOTED: Sets = &[rooted];
const BOTH: Sets = &[rooted, RootSet::strict];

/// The home with no root declared.
fn home_only() -> RootSet {
    RootSet::new(Path::new(HOME), &[])
}

/// `(label, contents, root sets)`: every content is scanned under every set.
#[rustfmt::skip]
const ROUNDS_3_AND_4: &[(&str, &[&str], Sets)] = &[
    ("r3.1 quoted, escaped and aliased keywords", &[
        "\\export CARGO_HOME=/etc/evil",
        "\"export\" CARGO_HOME=/etc/evil",
        "e''xport CARGO_HOME=/etc/evil",
        "alias ex=export\nex CARGO_HOME=/etc/evil",
    ], BOTH),
    ("r3.2 multi-line constructs", &[
        ": '\n'; export CARGO_HOME=/etc/evil #'",
        "ex\\\nport CARGO_HOME=/etc/evil",
        "export CARGO_HOME=/var/mnt/scratch/example/cargo\nCARGO_\\\nHOME=/etc/evil",
    ], ROOTED),
    ("r3.3 assigning commands and stale values", &[
        "for CARGO_HOME in /etc/evil; do :; done",
        "read -r CARGO_HOME <<< /etc/evil",
        "printf -v CARGO_HOME /etc/evil",
        "CARGO_HOME[1,-1]=/etc/evil",
        ": ${CARGO_HOME::=/etc/evil}",
        "set -a\n: ${CARGO_HOME:=/etc/evil}",
        "R=/var/mnt/scratch/example\nunset R\nexport CARGO_HOME=$R/etc/evil",
    ], ROOTED),
    ("r3.4 special parameters", &[
        "CARGO_HOME=/var/mnt/scratch/example/$@/$@/$@/$@/../../../../etc/evil",
    ], ROOTED),
    ("r3.4 a fragment-assigned home", &[
        "XDG_STATE_HOME=~/.local/state/b$@x",
        "HOME=/etc/evil\nCARGO_HOME=~/cargo",
    ], &[home_rooted]),
    ("r3.5 eval and source with a literal payload", &[
        "eval \"export CARGO_HOME=/etc/evil\"",
        "source /dev/stdin <<< 'export CARGO_HOME=/etc/evil'",
    ], ROOTED),
    ("r3.7 colon lists", &[
        "KUBECONFIG=/var/mnt/scratch/example/k:/etc/evil/config",
        "GOPATH=/var/mnt/scratch/example/go:/etc/evil",
    ], ROOTED),
    ("r3.8 location words and zsh equals expansion", &[
        "MISE_SHARED_INSTALL_DIRS=evil",
        "MISE_TRUSTED_CONFIG_PATHS=evil",
        "UV_PROJECT=evil",
        "MISE_DEFAULT_CONFIG_FILENAME=evil.toml",
        "UV_PROJECT==ls",
    ], ROOTED),
    ("r4.1 a state directory the fragment moves is owned by later lines", &[
        "export XDG_STATE_HOME=/var/mnt/scratch/example/state\n\
         export CARGO_HOME=/var/mnt/scratch/example/state/bx",
    ], ROOTED),
    ("r4.1 a state directory the fragment moves, under the home", &[
        "export XDG_STATE_HOME=~/state\nexport CARGO_HOME=~/state/bx/cargo",
    ], &[home_rooted]),
    ("r4.2 a name whose assignment the shell acts on", &[
        "export HISTFILESIZE=0",
        "export HISTFILE=/etc/evil",
        "export HISTFILE=history",
        "POSIXLY_CORRECT=1",
        "BASH_COMPAT=50",
        "GLOBIGNORE=x",
        "BASH_XTRACEFD=1",
        "PROMPT_COMMAND=x",
        "PS0=x",
        "precmd_functions=x",
    ], BOTH),
    ("r4.3 a path given to a name no list holds", &[
        "export SOMETHING=.",
        "export SOMETHING=..",
        "export SOMETHING=build/cache",
        "export SOMETHING=~/elsewhere",
        "export SOMETHING=a:/etc/evil",
        "X=/etc/evil",
    ], ROOTED),
    ("r4.4 location words the review found missing", &[
        "MISE_CONFIG_DIRECTORY=evil",
        "MISE_OVERRIDE_CONFIG_FILENAMES=evil",
        "UV_TOOL_FOLDER=evil",
        "ASDF_PLUGIN_MODULE=evil",
        "PIP_INSTALL_DEST=evil",
    ], ROOTED),
    ("r4.5 a search list or a program that is not an absolute path", &[
        "export PATH=.:/usr/bin",
        "export PATH=/usr/bin:",
        "export PATH=bin",
        "export PATH=",
        "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
        "export EDITOR=./nvim",
        "export EDITOR=/var/home/example/.local/state/bx/nvim",
    ], &[rooted, home_only]),
];

#[test]
fn no_round_3_or_4_reproduction_is_approved() {
    let mut approved = Vec::new();
    let mut judge = |label: &str, content: &str, sets: Sets| {
        for roots in sets {
            if scan_with(content, &roots()).is_empty() {
                approved.push(format!("{label}: {content:?}"));
            }
        }
    };
    for (label, contents, sets) in ROUNDS_3_AND_4 {
        for content in *contents {
            judge(label, content, sets);
        }
    }
    for name in R4_UNLISTED_RELOCATIONS {
        let content = format!("export {name}=/etc/evil");
        judge("r4.3 a relocation no list held", &content, BOTH);
    }
    // r3.6: relocating names the round-3 lists missed, judged by `check`.
    for name in [
        "HOME",
        "npm_config_cache",
        "ZDOTDIR",
        "YARN_CACHE_FOLDER",
        "CCACHE_DIR",
        "STARSHIP_CONFIG",
        "PYTHONUSERBASE",
        "TMPDIR",
    ] {
        if check(name, "/etc/evil", &rooted()) == Verdict::Allowed {
            approved.push(format!("r3.6 missing relocating names: {name}"));
        }
    }
    assert_eq!(approved, Vec::<String>::new());
}

// Review round 5: a fragment may set only a variable bx knows how to judge.

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
    // 3: a state directory a later line moves. Since round 6 the move is
    // what is refused.
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
    // 7: a config repo landing on the state directory. Since round 6 no
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
/// `printf -v`. The `=` sweep alone is what round-2 note COV1 was about —
/// it cannot see a single one of the second group, so a `read -r
/// CARGO_HOME` in the snippet went unnoticed.
///
/// The second sweep is deliberately generous: it takes every `-v` operand
/// and *every* name-shaped operand of a `read`, `mapfile` or `readarray`,
/// which over-reports rather than under-reports, and over-reporting can
/// only make the caller stricter. Taking only the first non-flag operand
/// under-reported instead, against this very sentence — `read -p "Enter: "
/// N`, `read -d '' N`, `read -rn 1 N` and `read -r A N` each hid `N`
/// behind a flag's own operand or a second target (round-3 note D2).
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
    // The exact shapes round-3 note D2 measured returning nothing, where
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
    // `=`, which is what round-2 note COV1 found this missing — and each
    // must be one of bx's own `BX_` names, which no tool reads, or an
    // array the completion function declares `local`, which never leaves
    // that function.
    //
    // Written this way the test survives the snippet being reformatted,
    // and fails the moment a generator puts a real assignment in it.
    let snippet = include_str!("../../bench/fixtures/bx/bx-init.zsh");
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

// Review round 4: a value is judged whatever it is assigned to.

#[test]
fn a_name_no_table_holds_is_refused_and_a_location_is_judged_whatever_its_shape() {
    use Reason::{NotAbsolute, NotEmittable};
    // Round 4 judged these by value: allowed inside a root. Round 5 does
    // not know what they hold, so it refuses each whatever it is given.
    for name in R4_UNLISTED_RELOCATIONS {
        for value in ["/etc/evil", "/var/mnt/scratch/example/x", "1"] {
            for roots in [rooted(), RootSet::strict()] {
                refused(name, value, &roots, NotEmittable);
            }
        }
    }
    // A location is refused anything that is not an absolute path inside
    // a root — a bare word, a number, and every URL included (round 5).
    for (value, reason) in [
        (".", NotAbsolute),
        ("..", NotAbsolute),
        ("build/cache", NotAbsolute),
        ("a:.", NotAbsolute),
        // The home contains bx's directories (r3 round 2).
        ("~", Reason::ContainsBxDirectory),
        ("\"~x\"", NotAbsolute),
        // Its first entry is the root itself, refused before `a` (#45).
        // Since #47 round 1, `a` is judged for every other reason before
        // any entry is judged for being a root, so `a` names the fix.
        ("/var/mnt/scratch/example:a", NotAbsolute),
        ("/var/mnt/scratch/example/x:a", NotAbsolute),
        ("file:///var/mnt/scratch/example", NotAbsolute),
        ("1+x://y", NotAbsolute),
        ("", NotAbsolute),
        ("1", NotAbsolute),
        ("a:b", NotAbsolute),
        ("...", NotAbsolute),
        (".x", NotAbsolute),
        ("\"-j8 V=1\"", NotAbsolute),
        ("https://example.invalid/a:b", NotAbsolute),
        ("git+ssh://example.invalid/x", NotAbsolute),
        ("s3.a-b://bucket/key", NotAbsolute),
    ] {
        refused("CARGO_HOME", value, &rooted(), reason);
    }
    // Of the round-4 brief's settings, the ones the table lists still pass
    // with no root declared; the others are not emittable.
    for (name, value) in [("UV_NO_CACHE", "1"), ("MISE_JOBS", "8"), ("EDITOR", "nvim")] {
        assert_eq!(
            check(name, value, &RootSet::strict()),
            Verdict::Allowed,
            "{name}"
        );
    }
    for (name, value) in [
        ("MAKEFLAGS", "\"-j8 V=1\""),
        ("CARGO_BUILD_TARGET", "x86_64-unknown-linux-gnu"),
        ("HISTFILE", "history"),
        ("PIP_NO_CACHE_DIR", "1"),
        ("JAVA_HOME", "/usr/lib/jvm/java-21"),
    ] {
        refused(name, value, &RootSet::strict(), NotEmittable);
    }
}

#[test]
fn the_names_and_location_words_the_review_found_missing_are_refused() {
    for name in [
        "ZDOTDIR",
        "YARN_CACHE_FOLDER",
        "CCACHE_DIR",
        "STARSHIP_CONFIG",
        "PYTHONUSERBASE",
        "TMPDIR",
        "MISE_SHARED_INSTALL_DIRS",
        "MISE_TRUSTED_CONFIG_PATHS",
        "UV_PROJECT",
        "MISE_DEFAULT_CONFIG_FILENAME",
    ] {
        for value in ["/etc/evil", "/var/mnt/scratch/example/x", "evil"] {
            refused(name, value, &rooted(), Reason::NotEmittable);
        }
    }
    refused("HOME", ROOT, &rooted(), Reason::ReservedName);
    refused("UV_PROJECT", "=ls", &rooted(), Reason::Unreadable);
}

#[test]
fn no_form_known_to_assign_is_approved_whatever_its_name_or_value() {
    let home_rooted = home_rooted();
    for form in ASSIGNING_FORMS {
        for name in ["CARGO_HOME", "EDITOR", "npm_config_cache", "X"] {
            for value in ["/var/mnt/scratch/example/cargo", "/etc/evil", "nvim"] {
                let content = form.replace("{N}", name).replace("{V}", value);
                for roots in [rooted(), home_rooted.clone(), RootSet::strict()] {
                    assert_ne!(scan_with(&content, &roots), vec![], "{content:?}");
                }
            }
        }
    }
}
