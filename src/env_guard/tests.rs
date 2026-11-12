//! The guard as a whole: `check` and the scans, (in `bypasses`) the
//! reproductions of bypasses it once approved, (in `assignments`) the variables
//! a fragment may set and the generated content that is not a fragment, and
//! (in `census`) the sites outside this module that reach it.

use std::path::{Path, PathBuf};

use super::fixtures::*;
use super::table::Setting;
use super::*;

mod assignments;
mod bypasses;
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
    // There is no `NotAPath`. It would exist only if a name list were the
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
    // Their names' families say nothing; the table lists none of them, so
    // each is refused whatever it is given.
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
    // and a tool that clears it clears bx's record. A sibling
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
    // Judging it learns nothing, so the guard does not read it at
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
    // The space is itself refused, by name, as a
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
    // guard refuses every location. The count is 25: the 23
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
    // A command is not let through as assigning nothing. The guard does not
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

// The guard fails closed on shell it cannot read, reads
// a value quote-aware, and gives one verdict whichever entry point asks.

#[test]
fn a_keyword_other_than_export_is_refused_whatever_it_assigns() {
    // Each of these sets `CARGO_HOME=/etc/evil` in bash or zsh. Reading the
    // keyword and judging the operand misses any keyword it does not know;
    // the guard reads no keyword but `export`, so each is refused before its
    // operand is looked at — and so would be the next spelling of a keyword.
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
    // mixed quoting are shell the guard does not run. They are refused for
    // every variable, not only a relocating one, because a line the grammar
    // does not read may do anything whatever its first name is.
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
    // Ordinary rc content that reads as assigning nothing, refused anyway.
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
    // A space in a location is refused by name; what is
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
    // The rest of the family are not settings bx knows. The table does
    // not list them, so they are refused, with or without a root.
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

// A value is judged whatever it is assigned to.

#[test]
fn a_name_no_table_holds_is_refused_and_a_location_is_judged_whatever_its_shape() {
    use Reason::{NotAbsolute, NotEmittable};
    // Judged by value, these would be allowed inside a root. The guard does
    // not know what they hold, so it refuses each whatever it is given.
    for name in R4_UNLISTED_RELOCATIONS {
        for value in ["/etc/evil", "/var/mnt/scratch/example/x", "1"] {
            for roots in [rooted(), RootSet::strict()] {
                refused(name, value, &roots, NotEmittable);
            }
        }
    }
    // A location is refused anything that is not an absolute path inside
    // a root — a bare word, a number, and every URL included.
    for (value, reason) in [
        (".", NotAbsolute),
        ("..", NotAbsolute),
        ("build/cache", NotAbsolute),
        ("a:.", NotAbsolute),
        // The home contains bx's directories.
        ("~", Reason::ContainsBxDirectory),
        ("\"~x\"", NotAbsolute),
        // Its first entry is the root itself, refused before `a` (#45).
        // `a` is judged for every other reason before
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
    // Of these ordinary settings, the ones the table lists pass
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
