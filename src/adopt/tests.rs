use std::os::unix::fs::MetadataExt as _;

use super::*;
use crate::plan::tests::{env, inline, seed};
use crate::report::Exit;
use crate::state::Prior;
use crate::testing::{GuardedHome, chmod, guarded_home, mode_of};

/// What the user's own `bx.toml` holds before any test edits it.
const MINE: &str = "# my own notes\n";

/// A home with a config repo whose `bx.toml` is `layer`.
fn repo(layer: &str) -> GuardedHome {
    let home = guarded_home();
    seed(home.path(), layer);
    home
}

/// Write `bytes` at `~/rel` with `mode`, making its parents.
fn plant(home: &GuardedHome, rel: &str, bytes: &[u8], mode: u32) -> PathBuf {
    let path = home.child(rel);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("parents");
    std::fs::write(&path, bytes).expect("write");
    chmod(&path, mode);
    path
}

fn target(home: &GuardedHome, rel: &str) -> Portable {
    Portable::parse_in(&format!("~/{rel}"), home.path()).expect("a target")
}

fn context(home: &GuardedHome) -> Context {
    Context::load(&env(home.path())).expect("the context loads")
}

fn add_rel(home: &GuardedHome, rel: &str) -> Vec<Adoption> {
    add(&context(home), &target(home, rel)).expect("add")
}

fn rm_rel(home: &GuardedHome, rel: &str) -> Vec<Removal> {
    rm(&context(home), &target(home, rel)).expect("rm")
}

fn layer(home: &GuardedHome) -> String {
    std::fs::read_to_string(home.child(".config/bx/bx.toml")).expect("bx.toml")
}

fn body(home: &GuardedHome, rel: &str) -> PathBuf {
    home.child(".config/bx/files").join(rel)
}

fn ledger(home: &GuardedHome) -> LedgerView {
    LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("the ledger")
        .value
}

fn plan_exit(home: &GuardedHome) -> (Exit, String) {
    let mut out = Vec::new();
    let exit = crate::command::plan(&env(home.path()), &mut out).expect("plan");
    (exit, String::from_utf8(out).expect("UTF-8"))
}

fn apply_yes(home: &GuardedHome) {
    let mut out = Vec::new();
    crate::command::apply(&env(home.path()), true, &mut out).expect("apply");
}

fn adopted(rows: &[Adoption]) -> Vec<&str> {
    rows.iter()
        .filter(|row| matches!(row, Adoption::Adopt { .. }))
        .map(|row| row.target().as_str())
        .collect()
}

#[test]
fn add_copies_the_bytes_and_the_mode_verbatim_and_leaves_the_file_alone() {
    let home = repo(MINE);
    // CRLF, no trailing newline, and bytes that are not UTF-8.
    let bytes = b"a = 1\r\nb\x00\xff";
    let file = plant(&home, ".tool.conf", bytes, 0o600);
    let before = std::fs::metadata(&file).expect("stat");

    let rows = add_rel(&home, ".tool.conf");
    assert_eq!(adopted(&rows), ["~/.tool.conf"], "{rows:?}");

    let copy = body(&home, ".tool.conf");
    assert_eq!(std::fs::read(&copy).expect("the copy"), bytes);
    assert_eq!(mode_of(&copy), 0o600, "a private file stays private");
    assert_eq!(
        layer(&home),
        format!(
            "{MINE}\n[[target]]\npath = \"~/.tool.conf\"\nfile = \"files/.tool.conf\"\n\
                 mode = \"0600\"\n"
        ),
        "appended after every byte the user wrote",
    );
    let after = std::fs::metadata(&file).expect("stat");
    assert_eq!(std::fs::read(&file).expect("read"), bytes);
    assert_eq!(
        (after.ino(), after.mode(), after.mtime()),
        (before.ino(), before.mode(), before.mtime()),
        "adoption writes nothing in the home",
    );

    let entry = ledger(&home)
        .get(&target(&home, ".tool.conf"))
        .cloned()
        .expect("bx owns it");
    assert_eq!(entry.written, ContentHash::of(bytes));
    assert_eq!(entry.mode, Mode::PRIVATE_FILE);
    assert!(
        matches!(&entry.prior, Prior::Existed(prior) if prior.digest == ContentHash::of(bytes)),
        "rm restores the file as it was adopted: {:?}",
        entry.prior,
    );
    assert_eq!(plan_exit(&home).0, Exit::Converged);
}

#[test]
fn a_default_mode_is_not_written_and_a_second_add_changes_nothing() {
    let home = repo("");
    plant(&home, ".plain", b"x\n", 0o644);
    add_rel(&home, ".plain");
    let layer_once = layer(&home);
    assert_eq!(
        layer_once,
        "[[target]]\npath = \"~/.plain\"\nfile = \"files/.plain\"\n"
    );
    let ledger_once = std::fs::read(StateDir::resolve(home.path()).ledger()).expect("ledger");

    let rows = add_rel(&home, ".plain");
    assert_eq!(
        rows,
        [Adoption::Unchanged {
            target: target(&home, ".plain")
        }]
    );
    assert_eq!(layer(&home), layer_once, "byte-identical");
    assert_eq!(
        std::fs::read(StateDir::resolve(home.path()).ledger()).expect("ledger"),
        ledger_once,
    );
}

#[test]
fn a_file_under_a_directory_only_one_os_reads_is_declared_kept_to_that_os() {
    let here = std::env::consts::OS;
    for (rel, os) in [
        (".config/systemd/user/a.service", "linux"),
        (".config/environment.d/60-a.conf", "linux"),
        ("Library/Preferences/a.plist", "macos"),
        // `~/Library` on macOS's case-folding volume, a directory of its
        // own elsewhere: kept to the OS it was adopted on.
        ("library/b.plist", here),
    ] {
        let home = repo("");
        plant(&home, rel, b"x\n", 0o644);
        let rows = add_rel(&home, rel);
        assert_eq!(adopted(&rows), [format!("~/{rel}")], "{rows:?}");
        assert_eq!(
            layer(&home),
            format!("[[target]]\npath = \"~/{rel}\"\nfile = \"files/{rel}\"\nwhen = \"os:{os}\"\n"),
            "{rel}",
        );
        // The configuration it wrote loads, and a second add changes
        // nothing, on every OS.
        let once = layer(&home);
        assert_eq!(
            add_rel(&home, rel),
            [Adoption::Unchanged {
                target: target(&home, rel)
            }],
            "{rel}",
        );
        assert_eq!(layer(&home), once, "{rel}");
    }
}

#[test]
fn a_symlink_is_refused_rather_than_adopted_as_what_it_points_at() {
    let home = repo(MINE);
    plant(&home, "real", b"real\n", 0o644);
    std::os::unix::fs::symlink(home.child("real"), home.child(".link")).expect("symlink");

    let rows = add_rel(&home, ".link");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("symbolic link")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), MINE, "nothing declared");
    assert!(!home.child(".config/bx/files").exists(), "nothing copied");
    assert!(ledger(&home).is_empty(), "nothing owned");

    let mut out = Vec::new();
    let exit =
        crate::command::add(&env(home.path()), home.path(), Some(".link"), &mut out).expect("add");
    assert_eq!(exit, Exit::Pending, "a refusal needs a human");
    assert!(
        String::from_utf8(out)
            .expect("UTF-8")
            .contains("  ! ~/.link  is a symbolic link")
    );
}

#[test]
fn a_directory_adopts_every_regular_file_in_byte_order_and_skips_the_rest() {
    let home = repo(MINE);
    plant(&home, ".config/app/b", b"b\n", 0o644);
    plant(&home, ".config/app/a", b"a\n", 0o755);
    plant(&home, ".config/app/sub/c", b"c\n", 0o644);
    plant(&home, ".config/app/.git/HEAD", b"ref\n", 0o644);
    std::os::unix::fs::symlink(home.child(".config/app/a"), home.child(".config/app/link"))
        .expect("symlink");

    let rows = add_rel(&home, ".config/app");
    let shape: Vec<(&str, bool)> = rows
        .iter()
        .map(|row| (row.target().as_str(), matches!(row, Adoption::Adopt { .. })))
        .collect();
    assert_eq!(
        shape,
        [
            ("~/.config/app/.git", false),
            ("~/.config/app/a", true),
            ("~/.config/app/b", true),
            ("~/.config/app/link", false),
            ("~/.config/app/sub/c", true),
        ],
    );
    assert!(
        rows.iter()
            .all(|row| !row.needs_attention() && !matches!(row, Adoption::Refused { .. })),
        "what a directory holds and bx passes over is not a refusal: {rows:?}",
    );
    assert_eq!(mode_of(&body(&home, ".config/app/a")), 0o755);
    assert!(
        layer(&home).contains(
            "path = \"~/.config/app/a\"\nfile = \"files/.config/app/a\"\nmode = \"0755\"\n"
        )
    );
    assert!(!body(&home, ".config/app/.git").exists());
    let rows = add_rel(&home, ".config/app/.git");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("git repository")),
        "named, it is refused rather than walked: {rows:?}"
    );
    assert_eq!(plan_exit(&home).0, Exit::Converged);
}

#[test]
fn credentials_are_refused_by_name_and_skipped_inside_a_directory() {
    let home = repo(MINE);
    plant(&home, ".ssh/id_ed25519", b"PRIVATE\n", 0o600);
    plant(&home, ".ssh/id_ed25519.pub", b"ssh-ed25519 AAAA\n", 0o644);
    plant(&home, ".ssh/config", b"Host *\n", 0o600);
    plant(&home, ".netrc", b"machine x\n", 0o600);

    for rel in [".ssh/id_ed25519", ".netrc"] {
        let rows = add_rel(&home, rel);
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("credential")),
            "{rel}: {rows:?}",
        );
    }
    let rows = add_rel(&home, ".ssh");
    assert_eq!(adopted(&rows), ["~/.ssh/config", "~/.ssh/id_ed25519.pub"]);
    assert!(
            rows.iter().any(|row| matches!(row, Adoption::Skipped { target: t, .. } if t.as_str() == "~/.ssh/id_ed25519")),
            "{rows:?}"
        );
    assert!(!body(&home, ".ssh/id_ed25519").exists());
    assert!(!layer(&home).contains("id_ed25519\""));
}

#[test]
fn every_file_under_a_credential_directory_is_refused() {
    let home = repo(MINE);
    for rel in [
        ".gnupg/private-keys-v1.d/key.key",
        ".password-store/site.gpg",
        ".local/share/keyrings/login.keyring",
        ".config/age/keys.txt",
        "Library/Keychains/login.keychain-db",
    ] {
        plant(&home, rel, b"SECRET\n", 0o600);
        let rows = add_rel(&home, rel);
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("credential")),
            "{rel}: {rows:?}",
        );
        assert!(!body(&home, rel).exists(), "{rel}");
    }
    assert_eq!(layer(&home), MINE);
}

#[test]
fn the_credential_list_is_matched_without_regard_to_case() {
    for rel in [
        ".SSH/id_ed25519",
        ".ssh/ID_ED25519",
        ".NETRC",
        ".Config/GH/hosts.yml",
        ".GnuPG/pubring.kbx",
        "Library/Keychains/login.keychain-db",
        "library/keychains/login.keychain-db",
        "Library/Application Support/sops/age/keys.txt",
        "LIBRARY/APPLICATION SUPPORT/SOPS/AGE/KEYS.TXT",
    ] {
        assert!(secret_rel(rel).is_some(), "{rel}");
    }
    for rel in [
        ".SSH/id_ed25519.PUB",
        ".SSH/config",
        "Library/Application Support/sops/age/other.txt",
        "Library/Preferences/x.plist",
    ] {
        assert!(secret_rel(rel).is_none(), "{rel}");
    }
    assert!(credential_dir(
        &Portable::try_from("~/Library/Keychains".to_string()).unwrap()
    ));
}

#[test]
fn a_path_holding_a_placeholder_delimiter_is_refused() {
    let home = repo(MINE);
    for rel in [".cfg/{{name}}", ".cfg/a{{b", ".cfg/a}}b"] {
        plant(&home, rel, b"x\n", 0o644);
        let rows = add_rel(&home, rel);
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("placeholder")),
            "{rel}: {rows:?}",
        );
        assert!(!body(&home, rel).exists(), "{rel}");
    }
    assert_eq!(layer(&home), MINE);
}

#[test]
fn a_line_that_relocates_a_tool_is_a_warning_naming_it_and_the_file_is_still_adopted() {
    let home = repo(MINE);
    plant(
        &home,
        ".profile.d/env.sh",
        b"export EDITOR=vi\nexport CARGO_HOME=/elsewhere/cargo\nnot shell at all\n",
        0o644,
    );
    let rows = add_rel(&home, ".profile.d/env.sh");
    let [Adoption::Adopt { warnings, .. }] = rows.as_slice() else {
        panic!("adopted: {rows:?}");
    };
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with("line 2: CARGO_HOME "),
        "{warnings:?}"
    );

    let mut out = Vec::new();
    plant(&home, ".other.sh", b"export CARGO_HOME=/x\n", 0o644);
    let exit = crate::command::add(
        &env(home.path()),
        home.path(),
        Some("~/.other.sh"),
        &mut out,
    )
    .expect("add");
    let text = String::from_utf8(out).expect("UTF-8");
    assert_eq!(exit, Exit::Converged, "a warning is not a refusal");
    assert!(text.contains("    warning: line 1: CARGO_HOME "), "{text}");
    assert!(text.contains("Adopted 1 file(s)"), "{text}");
}

#[test]
fn bxs_own_directories_are_never_adopted() {
    let home = repo(MINE);
    let rows = add_rel(&home, ".config/bx/bx.toml");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("config repo")),
        "{rows:?}"
    );
    plant(&home, ".local/state/bx/local.toml", b"", 0o600);
    let rows = add_rel(&home, ".local/state/bx/local.toml");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("state directory")),
        "{rows:?}"
    );
    // Met inside a directory being adopted, the repo is passed over.
    plant(&home, ".config/tool.conf", b"t\n", 0o644);
    let rows = add_rel(&home, ".config");
    assert_eq!(adopted(&rows), ["~/.config/tool.conf"]);
    assert!(rows.iter().any(
        |row| matches!(row, Adoption::Skipped { target: t, .. } if t.as_str() == "~/.config/bx")
    ));
}

#[test]
fn a_declared_identical_file_bx_does_not_own_becomes_owned() {
    let home = repo(&inline("~/.declared", "same\\n"));
    let file = plant(&home, ".declared", b"same\n", 0o644);
    let layer_before = layer(&home);

    let rows = add_rel(&home, ".declared");
    assert!(
        matches!(rows.as_slice(), [Adoption::Own { .. }]),
        "{rows:?}"
    );
    assert_eq!(layer(&home), layer_before, "nothing declared twice");
    let entry = ledger(&home)
        .get(&target(&home, ".declared"))
        .cloned()
        .expect("owned");
    assert!(
        matches!(entry.prior, Prior::Existed(_)),
        "the file the user wrote is the prior, never Absent: {entry:?}"
    );

    let rows = add_rel(&home, ".declared");
    assert!(
        matches!(rows.as_slice(), [Adoption::Unchanged { .. }]),
        "{rows:?}"
    );

    // `rm` hands the file back rather than unlinking it: bx wrote none of it.
    rm_rel(&home, ".declared");
    assert_eq!(std::fs::read(&file).expect("still there"), b"same\n");
    assert_eq!(mode_of(&file), 0o644);
}

#[test]
fn a_declared_file_that_differs_or_is_switched_off_is_refused() {
    let home = repo(&inline("~/.declared", "repo\\n"));
    plant(&home, ".declared", b"disk\n", 0o644);
    let rows = add_rel(&home, ".declared");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("differs")),
        "{rows:?}"
    );

    let off = format!("{}enabled = false\n", inline("~/.off", "x\\n"));
    let home = repo(&off);
    plant(&home, ".off", b"x\n", 0o644);
    let rows = add_rel(&home, ".off");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("switched off")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), off);
}

#[test]
fn a_target_gated_off_this_machine_is_undeclared_to_add() {
    // No machine bx runs on is named this, so the condition never holds.
    // In a module, since `add` declares in `bx.toml` and one layer may not
    // declare a path twice, gated or not.
    let gated = format!(
        "{}when = \"host:no-such-bx-host\"\n",
        inline("~/.gated", "x\\n")
    );
    let home = repo("");
    home.write(".config/bx/modules/elsewhere.toml", &gated);
    plant(&home, ".gated", b"mine\n", 0o644);

    let rows = add_rel(&home, ".gated");
    assert!(
        matches!(rows.as_slice(), [Adoption::Adopt { .. }]),
        "adopted as undeclared, neither refused nor owned: {rows:?}"
    );
}

#[test]
fn a_target_bx_toml_keeps_off_this_machine_is_not_declared_there_twice() {
    let gated = "[[target]]\npath = \"~/.gated\"\nfile = \"files/.gated\"\n\
                     when = \"host:no-such-bx-host\"\n";
    let home = repo(gated);
    home.write(".config/bx/files/.gated", "held\n");

    plant(&home, ".gated", b"held\n", 0o644);
    assert_eq!(
        add_rel(&home, ".gated"),
        [Adoption::Unchanged {
            target: target(&home, ".gated")
        }],
    );
    assert_eq!(layer(&home), gated);

    // Matching bytes under another mode differ from the declaration too.
    for (bytes, mode) in [(b"mine\n", 0o644), (b"held\n", 0o600)] {
        plant(&home, ".gated", bytes, mode);
        let rows = add_rel(&home, ".gated");
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                    if note.contains("kept off this machine") && note.contains("differs")),
            "{rows:?}"
        );
        assert_eq!(layer(&home), gated);
    }

    // An inline body is compared as the declared path's is.
    let gated = format!(
        "{}when = \"host:no-such-bx-host\"\n",
        inline("~/.gated", "held\\n")
    );
    let home = repo(&gated);
    plant(&home, ".gated", b"held\n", 0o644);
    assert_eq!(
        add_rel(&home, ".gated"),
        [Adoption::Unchanged {
            target: target(&home, ".gated")
        }],
    );
    plant(&home, ".gated", b"mine\n", 0o644);
    let rows = add_rel(&home, ".gated");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                if note.contains("kept off this machine") && note.contains("differs")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), gated);

    // A body that holds no bytes to compare is refused as such.
    let gated = "[[target]]\npath = \"~/.gated\"\nsymlink = \"~/elsewhere\"\n\
                     when = \"host:no-such-bx-host\"\n";
    let home = repo(gated);
    plant(&home, ".gated", b"held\n", 0o644);
    let rows = add_rel(&home, ".gated");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                if note.contains("kept off this machine") && note.contains("does not adopt into")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), gated);
}

#[test]
fn modules_gating_a_terminal_plugin_each_to_their_own_os_load_for_add() {
    let home = repo("");
    for os in ["linux", "macos"] {
        home.write(
            format!(".config/bx/modules/{os}.toml"),
            &format!(
                "when = \"os:{os}\"\n[[plugin]]\nname = \"{os}\"\n\
                     source = \"~/{os}.zsh\"\nterminal = true\n"
            ),
        );
    }
    plant(&home, ".free", b"x\n", 0o644);

    let rows = add_rel(&home, ".free");
    assert!(
        matches!(rows.as_slice(), [Adoption::Adopt { .. }]),
        "{rows:?}"
    );
}

#[test]
fn a_path_declared_under_another_case_is_refused_where_the_volume_folds_case() {
    let declared = inline("~/.config/app/x", "x\\n");
    let home = repo(&declared);
    plant(&home, ".Config/app/x", b"x\n", 0o644);
    let plan_with = |folds: fn(&Path) -> Option<bool>| {
        let ctx = Context {
            folds,
            ..context(&home)
        };
        plan_add(&ctx, &ledger(&home), &target(&home, ".Config/app/x")).expect("plan_add")
    };

    for (folds, judged) in [
        (
            (|_| Some(true)) as fn(&Path) -> Option<bool>,
            "does not tell names apart",
        ),
        (|_| None, "could not determine"),
    ] {
        let rows = plan_with(folds);
        assert!(
            matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                    if note.contains("same file as `~/.config/app/x`") && note.contains(judged)),
            "{rows:?}"
        );
    }
    let rows = plan_with(|_| Some(false));
    assert_eq!(adopted(&rows), ["~/.Config/app/x"], "{rows:?}");

    // Only a case-only difference is refused: an unrelated path on a
    // folding volume is still adopted.
    plant(&home, ".other", b"o\n", 0o644);
    let ctx = Context {
        folds: |_| Some(true),
        ..context(&home)
    };
    let rows = plan_add(&ctx, &ledger(&home), &target(&home, ".other")).expect("plan_add");
    assert_eq!(adopted(&rows), ["~/.other"], "{rows:?}");

    // The volume itself is asked by default, and the refusal agrees with it.
    let rows = add_rel(&home, ".Config/app/x");
    let folds = crate::fs::case_insensitive(home.path()) != Some(false);
    assert_eq!(adopted(&rows).is_empty(), folds, "{rows:?}");
    if folds {
        assert_eq!(layer(&home), declared, "not declared a second time");
        assert!(ledger(&home).is_empty());
    }
}

#[test]
fn a_file_declared_as_a_secret_is_refused_and_nothing_is_copied() {
    let declared =
        "[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n";
    let home = repo(declared);
    plant(&home, ".token", b"hunter2\n", 0o600);
    let rows = add_rel(&home, ".token");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("does not adopt into")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), declared);
    assert!(!home.child(".config/bx/files/.token").exists());
}

#[test]
fn a_switched_off_placeholder_pathed_declaration_is_found_by_the_path_it_resolves_to() {
    let values = "[[value]]\nname = \"profile\"\nkind = \"string\"\ndefault = \"work\"\n";
    let templated = inline("~/.config/{{profile}}/s", "s\\n");

    // Switched off where it is declared.
    let off = format!("{values}\n{templated}enabled = false\n");
    let home = repo(&off);
    plant(&home, ".config/work/s", b"s\n", 0o644);
    let rows = add_rel(&home, ".config/work/s");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("switched off")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), off, "not declared a second time");
    assert!(ledger(&home).is_empty());

    // Switched off by a toggle in local.toml.
    let on = format!("{values}\n{templated}");
    let home = repo(&on);
    let local = StateDir::resolve(home.path()).local_toml();
    let toggle = "[[target]]\npath = \"~/.config/{{profile}}/s\"\nenabled = false\n";
    std::fs::create_dir_all(local.parent().expect("parent")).expect("state dir");
    std::fs::write(&local, toggle).expect("local.toml");
    plant(&home, ".config/work/s", b"s\n", 0o644);
    let rows = add_rel(&home, ".config/work/s");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("switched off")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), on, "not declared a second time");
    assert_eq!(std::fs::read_to_string(&local).expect("local.toml"), toggle);
}

#[test]
fn discovery_leaves_out_what_a_blocked_target_or_a_switched_off_toggle_declares() {
    let values = "[[value]]\nname = \"who\"\nkind = \"string\"\n";
    let home = repo(&format!(
        "{values}\n{}\n{}",
        inline("~/.blocked", "{{who}}\\n"),
        inline("~/.toggled", "t\\n"),
    ));
    let local = StateDir::resolve(home.path()).local_toml();
    std::fs::create_dir_all(local.parent().expect("parent")).expect("state dir");
    std::fs::write(
        &local,
        "[[target]]\npath = \"~/.toggled\"\nenabled = false\n",
    )
    .expect("local.toml");
    for rel in [".blocked", ".toggled", ".free"] {
        plant(&home, rel, b"x\n", 0o644);
    }

    let ctx = context(&home);
    assert!(
        ctx.resolved
            .targets
            .iter()
            .any(|r| matches!(r, Resolution::Blocked(entry) if entry.key == "~/.blocked")),
        "the fixture holds a blocked target"
    );
    assert!(
        ctx.layers
            .iter()
            .any(|layer| { layer.config.toggles.iter().any(|t| t.key == "~/.toggled") }),
        "and a switched-off toggle"
    );
    assert_eq!(
        discover(&ctx, &home.child(".config")).expect("discover"),
        [target(&home, ".free")]
    );
}

#[test]
fn discovery_leaves_out_what_programs_write_about_their_own_use() {
    let home = repo("");
    let written = [
        ".zcompdump",
        ".zcompdump-host-5.9",
        ".lesshst",
        ".viminfo",
        ".wget-hsts",
        ".Xauthority",
        ".ICEauthority",
        ".xsession-errors",
        ".sudo_as_admin_successful",
        ".python_history",
    ];
    for name in written {
        assert!(machine_written(name), "{name}");
        plant(&home, name, b"x\n", 0o600);
    }
    for name in [".zshrc", ".vimrc", ".lessrc"] {
        assert!(!machine_written(name), "{name}");
    }
    plant(&home, ".vimrc", b"x\n", 0o644);

    assert_eq!(
        discover(&context(&home), &home.child(".config")).expect("discover"),
        [target(&home, ".vimrc")]
    );
}

#[test]
fn a_body_already_in_the_repo_is_reused_when_identical_and_refused_otherwise() {
    let home = repo(MINE);
    plant(&home, ".same", b"s\n", 0o644);
    plant(&home, ".config/bx/files/.same", b"s\n", 0o644);
    let rows = add_rel(&home, ".same");
    assert!(
        matches!(rows.as_slice(), [Adoption::Adopt { reuse: true, .. }]),
        "{rows:?}"
    );
    assert!(layer(&home).contains("path = \"~/.same\""));

    plant(&home, ".other", b"mine\n", 0o644);
    plant(&home, ".config/bx/files/.other", b"theirs\n", 0o644);
    let rows = add_rel(&home, ".other");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }] if note.contains("other content")),
        "{rows:?}"
    );
    assert_eq!(
        std::fs::read(body(&home, ".other")).expect("body"),
        b"theirs\n",
        "the repo's file is not replaced",
    );
}

#[test]
fn an_adopted_file_edited_in_the_repo_applies_and_rm_restores_the_adopted_bytes() {
    let home = repo(MINE);
    let file = plant(&home, ".rc", b"original\r\n", 0o600);
    add_rel(&home, ".rc");
    std::fs::write(body(&home, ".rc"), b"from the repo\n").expect("edit the body");

    let (exit, shown) = plan_exit(&home);
    assert_eq!(exit, Exit::Pending);
    assert!(
        shown.contains("  ~ ~/.rc"),
        "a modify, not a conflict: {shown}"
    );
    apply_yes(&home);
    assert_eq!(std::fs::read(&file).expect("read"), b"from the repo\n");

    let removals = rm_rel(&home, ".rc");
    assert!(
        matches!(
            removals.as_slice(),
            [Removal { restored: Restored::Reverted { .. }, undeclared, bodies }]
                if undeclared.len() == 1 && bodies == &[PathBuf::from("files/.rc")]
        ),
        "{removals:?}"
    );
    assert_eq!(std::fs::read(&file).expect("read"), b"original\r\n");
    assert_eq!(mode_of(&file), 0o600);
    assert_eq!(layer(&home), MINE, "add then rm leaves bx.toml as it was");
    assert!(ledger(&home).is_empty());
    assert!(
        body(&home, ".rc").exists(),
        "the body is the user's to delete"
    );
    assert_eq!(plan_exit(&home).0, Exit::Converged);
}

#[test]
fn rm_removes_a_file_bx_created_and_keeps_the_comments_around_its_declaration() {
    let layer_text = format!(
        "# above everything\n\n# the tool\n{}\n# after\n{}",
        inline("~/.made/new.conf", "new\\n"),
        inline("~/.kept", "kept\\n"),
    );
    let home = repo(&layer_text);
    apply_yes(&home);
    assert!(home.child(".made/new.conf").exists());

    let removals = rm_rel(&home, ".made");
    assert!(
        matches!(
            removals.as_slice(),
            [Removal {
                restored: Restored::Removed { .. },
                ..
            }]
        ),
        "{removals:?}"
    );
    assert!(
        !home.child(".made/new.conf").exists(),
        "removed, not emptied"
    );
    assert!(!home.child(".made").exists(), "and the directory bx made");
    assert_eq!(
        layer(&home),
        format!(
            "# above everything\n\n# the tool\n\n# after\n{}",
            inline("~/.kept", "kept\\n")
        ),
    );
    assert!(home.child(".kept").exists());
}

#[test]
fn rm_puts_back_the_bytes_and_mode_of_a_file_bx_replaced() {
    let home = repo("");
    let file = plant(&home, ".replaced", b"the user's\n", 0o600);
    crate::plan::tests::own(home.path(), ".replaced", b"bx's\n", Mechanism::Own);
    seed(home.path(), &inline("~/.replaced", "bx's\\n"));
    assert_eq!(plan_exit(&home).0, Exit::Converged);

    let mut out = Vec::new();
    let exit = crate::command::rm(&env(home.path()), home.path(), Some(".replaced"), &mut out)
        .expect("rm");
    assert_eq!(exit, Exit::Converged);
    let text = String::from_utf8(out).expect("UTF-8");
    assert!(
            text.contains("  - ~/.replaced  put back the file bx replaced; no longer declared in ~/.config/bx/bx.toml"),
            "{text}"
        );
    assert_eq!(std::fs::read(&file).expect("read"), b"the user's\n");
    assert_eq!(mode_of(&file), 0o600);
    assert_eq!(layer(&home), "");
}

#[test]
fn rm_over_an_edit_is_a_conflict_that_changes_nothing() {
    let layer_text = inline("~/.edited", "bx\\n");
    let home = repo(&layer_text);
    apply_yes(&home);
    std::fs::write(home.child(".edited"), b"hand edit\n").expect("edit");

    let mut out = Vec::new();
    let exit = crate::command::rm(&env(home.path()), home.path(), Some("~/.edited"), &mut out)
        .expect("rm");
    assert_eq!(exit, Exit::Pending);
    let text = String::from_utf8(out).expect("UTF-8");
    assert!(text.starts_with("  ! ~/.edited  "), "{text}");
    assert!(text.ends_with("; still managed\n"), "{text}");
    assert_eq!(
        std::fs::read(home.child(".edited")).expect("read"),
        b"hand edit\n"
    );
    assert_eq!(layer(&home), layer_text, "still declared");
    assert!(ledger(&home).get(&target(&home, ".edited")).is_some());
}

#[test]
fn rm_of_something_bx_does_not_manage_is_a_no_op() {
    let home = repo(MINE);
    plant(&home, ".untouched", b"u\n", 0o644);
    let mut out = Vec::new();
    let exit = crate::command::rm(&env(home.path()), home.path(), Some(".untouched"), &mut out)
        .expect("rm");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(
        String::from_utf8(out).expect("UTF-8"),
        "~/.untouched is not managed by bx; nothing to do.\n"
    );
    assert_eq!(
        std::fs::read(home.child(".untouched")).expect("read"),
        b"u\n"
    );
}

#[test]
fn rm_of_a_declared_target_bx_never_wrote_only_undeclares_it_in_every_layer() {
    let home = repo(&inline("~/.never", "n\\n"));
    let local = StateDir::resolve(home.path()).local_toml();
    std::fs::create_dir_all(local.parent().expect("parent")).expect("state dir");
    std::fs::write(&local, "[[target]]\npath = \"~/.never\"\nenabled = true\n")
        .expect("local.toml");

    let removals = rm_rel(&home, ".never");
    assert!(
        matches!(
            removals.as_slice(),
            [Removal { restored: Restored::Unmanaged { .. }, undeclared, .. }] if undeclared.len() == 2
        ),
        "{removals:?}"
    );
    assert_eq!(layer(&home), "");
    assert_eq!(std::fs::read_to_string(&local).expect("local.toml"), "");
    assert!(rm_rel(&home, ".never").is_empty(), "a second rm is a no-op");
}

#[test]
fn rm_of_a_secret_target_reports_its_ciphertext_as_left_in_the_repo() {
    let home =
        repo("[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n");

    let removals = rm_rel(&home, ".token");
    assert!(
        matches!(
            removals.as_slice(),
            [Removal { restored: Restored::Unmanaged { .. }, undeclared, bodies }]
                if undeclared.len() == 1 && bodies == &[PathBuf::from("secrets/token.age")]
        ),
        "{removals:?}"
    );
    assert_eq!(layer(&home), "");
}

#[test]
fn rm_of_a_placeholder_pathed_target_undeclares_it_by_the_path_it_resolves_to() {
    let values = "[[value]]\nname = \"profile\"\nkind = \"string\"\ndefault = \"work\"\n";
    let home = repo(&format!(
        "{values}\n{}",
        inline("~/.config/{{profile}}/s", "s\\n")
    ));
    apply_yes(&home);
    assert!(home.child(".config/work/s").exists());

    let removals = rm_rel(&home, ".config/work/s");
    assert!(
        matches!(
            removals.as_slice(),
            [Removal { restored: Restored::Removed { .. }, undeclared, .. }] if undeclared.len() == 1
        ),
        "{removals:?}"
    );
    assert!(!home.child(".config/work/s").exists());
    assert_eq!(layer(&home), values, "the templated declaration is gone");
    assert_eq!(
        plan_exit(&home).0,
        Exit::Converged,
        "and apply would not recreate it"
    );
    assert!(
        rm_rel(&home, ".config/work/s").is_empty(),
        "a second rm is a no-op"
    );
}

#[test]
fn locate_takes_a_shell_spelling_and_refuses_what_is_not_inside_the_home() {
    let home = guarded_home();
    let cwd = home.child("work");
    let at = |arg: &str| locate(arg, &cwd, home.path()).map(|t| t.as_str().to_string());
    assert_eq!(at("~/.a").expect("tilde"), "~/.a");
    assert_eq!(at("x/../.b").expect("relative"), "~/work/.b");
    assert_eq!(
        at(&home.child(".c").to_string_lossy()).expect("absolute"),
        "~/.c"
    );
    assert!(matches!(at("~"), Err(Error::OutsideHome(_))));
    assert!(matches!(at("/etc/hosts"), Err(Error::OutsideHome(_))));
    assert!(matches!(
        at("~/../x"),
        Err(Error::OutsideHome(_) | Error::Path(_))
    ));
}

#[test]
fn a_missing_path_no_path_and_no_repo_are_errors() {
    let home = repo(MINE);
    let mut out = Vec::new();
    let e = env(home.path());
    assert!(matches!(
        crate::command::add(&e, home.path(), None, &mut out),
        Err(Error::NoPath("add"))
    ));
    assert!(matches!(
        crate::command::rm(&e, home.path(), None, &mut out),
        Err(Error::NoPath("rm"))
    ));
    assert!(matches!(
        crate::command::add(&e, home.path(), Some(".nothing"), &mut out),
        Err(Error::Missing(missing)) if missing == "~/.nothing"
    ));

    let bare = guarded_home();
    plant(&bare, ".x", b"x\n", 0o644);
    let err = crate::command::add(&env(bare.path()), bare.path(), Some(".x"), &mut out)
        .expect_err("no repo");
    assert!(matches!(err, Error::RepoMissing(_)), "{err}");
    assert!(err.to_string().contains("bx init"), "{err}");
    assert!(out.is_empty());
}

/// A layer declaring the tree `files/.config/x` at `~/.config/x` — laid
/// out as `add` lays out its copies — holding `a` and `sub/b`.
const TREE: &str = "[[target]]\npath = \"~/.config/x\"\ntree = \"files/.config/x\"\n";

fn tree_repo() -> GuardedHome {
    let home = repo(TREE);
    plant(&home, ".config/bx/files/.config/x/a", b"a\n", 0o644);
    plant(&home, ".config/bx/files/.config/x/sub/b", b"b\n", 0o644);
    home
}

fn rm_text(home: &GuardedHome, arg: &str) -> (Exit, String) {
    let mut out = Vec::new();
    let exit = crate::command::rm(&env(home.path()), home.path(), Some(arg), &mut out).expect("rm");
    (exit, String::from_utf8(out).expect("UTF-8"))
}

#[test]
fn add_refuses_to_copy_a_file_into_a_tree_s_root() {
    let home = tree_repo();
    apply_yes(&home);
    plant(&home, ".config/x/new", b"new\n", 0o644);

    let rows = add_rel(&home, ".config/x/new");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                if note.contains("inside `tree = \"files/.config/x\"`")
                    && note.contains("copy it into files/.config/x yourself")),
        "{rows:?}"
    );
    assert_eq!(layer(&home), TREE, "nothing declared");
    assert!(!body(&home, ".config/x/new").exists(), "nothing copied");
    assert!(ledger(&home).get(&target(&home, ".config/x/new")).is_none());
    assert_eq!(plan_exit(&home).0, Exit::Converged, "the repo still loads");

    // A file the tree already delivers is declared, and adds as it did.
    let rows = add_rel(&home, ".config/x/a");
    assert!(
        matches!(rows.as_slice(), [Adoption::Unchanged { .. }]),
        "{rows:?}"
    );
}

#[test]
fn add_refuses_a_copy_into_a_tree_root_that_lands_elsewhere() {
    // The tree mirrors `files/.config/x` to `~/.y`: a copy of `~/.config/x/new`
    // would be delivered to `~/.y/new` as well.
    let home = repo("[[target]]\npath = \"~/.y\"\ntree = \"files/.config/x\"\n");
    plant(&home, ".config/bx/files/.config/x/a", b"a\n", 0o644);
    plant(&home, ".config/x/new", b"new\n", 0o644);

    let rows = add_rel(&home, ".config/x/new");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { .. }]),
        "{rows:?}"
    );
    assert!(!body(&home, ".config/x/new").exists());
}

#[test]
fn rm_on_a_tree_s_path_retires_the_whole_tree() {
    let home = tree_repo();
    apply_yes(&home);
    assert!(home.child(".config/x/sub/b").exists());

    let removals = rm_rel(&home, ".config/x");
    let rows: Vec<(&str, bool, usize)> = removals
        .iter()
        .map(|r| {
            (
                r.restored.target().as_str(),
                matches!(r.restored, Restored::Removed { .. }),
                r.undeclared.len(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("~/.config/x", false, 1),
            ("~/.config/x/a", true, 0),
            ("~/.config/x/sub/b", true, 0),
        ],
        "{removals:?}"
    );
    assert!(!home.child(".config/x/a").exists());
    assert!(!home.child(".config/x/sub/b").exists());
    assert_eq!(layer(&home), "", "the tree's table is gone");
    assert!(
        body(&home, ".config/x/a").exists(),
        "the repo's files stay where they are"
    );
    assert_eq!(ledger(&home).iter().count(), 0);
    assert_eq!(plan_exit(&home).0, Exit::Converged);
    assert!(
        rm_rel(&home, ".config/x").is_empty(),
        "a second rm is a no-op"
    );
}

#[test]
fn rm_on_a_tree_s_path_with_a_conflicting_file_leaves_the_whole_tree() {
    let home = tree_repo();
    apply_yes(&home);
    std::fs::write(home.child(".config/x/a"), b"hand edit\n").expect("edit");

    let (exit, text) = rm_text(&home, "~/.config/x");
    assert_eq!(exit, Exit::Pending);
    assert!(text.starts_with("  ! ~/.config/x/a  "), "{text}");
    assert!(
        text.contains("  ! ~/.config/x/sub/b  is left as it is: the tree at "),
        "{text}"
    );
    assert!(
        text.contains("and ~/.config/x/a conflicts; still managed"),
        "{text}"
    );
    assert!(!text.contains("no longer declared"), "{text}");
    assert_eq!(layer(&home), TREE, "the tree stays declared");
    assert_eq!(
        std::fs::read(home.child(".config/x/a")).expect("read"),
        b"hand edit\n"
    );
    assert_eq!(
        std::fs::read(home.child(".config/x/sub/b")).expect("read"),
        b"b\n",
        "the rest of the tree is not handed back either"
    );
    let owned = ledger(&home);
    assert!(owned.get(&target(&home, ".config/x/a")).is_some());
    assert!(owned.get(&target(&home, ".config/x/sub/b")).is_some());
}

#[test]
fn rm_on_a_file_a_tree_declares_releases_nothing_and_names_exclude() {
    let home = tree_repo();
    apply_yes(&home);

    let (exit, text) = rm_text(&home, "~/.config/x/sub");
    assert_eq!(exit, Exit::Pending);
    assert!(
        text.starts_with("  ! ~/.config/x/sub/b  is declared by the tree at "),
        "{text}"
    );
    assert!(
            text.contains("add an `exclude` pattern there to stop managing it, or `bx rm ~/.config/x` to release the whole tree; still managed"),
            "{text}"
        );
    assert_eq!(text.lines().count(), 1, "{text}");
    assert_eq!(layer(&home), TREE);
    assert!(home.child(".config/x/sub/b").exists());
    assert!(
        ledger(&home)
            .get(&target(&home, ".config/x/sub/b"))
            .is_some()
    );
    assert_eq!(plan_exit(&home).0, Exit::Converged);
}

#[test]
fn rm_inside_a_tree_hands_back_a_file_the_tree_no_longer_declares() {
    let home = tree_repo();
    apply_yes(&home);
    std::fs::remove_file(body(&home, ".config/x/sub/b")).expect("drop from the repo");

    let (exit, text) = rm_text(&home, "~/.config/x/sub/b");
    assert_eq!(exit, Exit::Converged, "{text}");
    assert!(
        text.starts_with("  - ~/.config/x/sub/b  removed the file bx created"),
        "{text}"
    );
    assert!(!home.child(".config/x/sub/b").exists());
    assert_eq!(layer(&home), TREE);
}

/// `~/.lock`, tracked, with its repo copy at `files/lock`.
const TRACKED: &str =
    "[[target]]\npath = \"~/.lock\"\nfile = \"files/lock\"\ndirection = \"track\"\n";

/// A sync's apply: carries every tracked target this machine changed.
fn sync_apply(home: &GuardedHome) {
    let inputs = crate::plan::Inputs::load(&env(home.path())).expect("inputs");
    crate::plan::run(&inputs, crate::plan::Mode::Sync, &mut |_| Ok(true)).expect("sync");
}

/// A home tracking `~/.lock`, whose repo copy held `before` until this
/// machine's `after` was carried into it.
fn tracked_and_synced(before: &[u8], after: &[u8]) -> GuardedHome {
    let home = repo(TRACKED);
    plant(&home, ".config/bx/files/lock", before, 0o644);
    plant(&home, ".lock", before, 0o644);
    sync_apply(&home);
    plant(&home, ".lock", after, 0o644);
    sync_apply(&home);
    assert_eq!(
        std::fs::read(body(&home, "lock")).expect("the copy"),
        after,
        "carried"
    );
    home
}

#[test]
fn rm_of_a_tracked_target_restores_the_repo_copy_and_leaves_the_machine_copy() {
    let home = tracked_and_synced(b"before\n", b"after\n");

    let (exit, text) = rm_text(&home, "~/.lock");
    assert_eq!(exit, Exit::Converged, "{text}");
    assert_eq!(
        text,
        "  - ~/.config/bx/files/lock  put back the file bx replaced\n\
             \x20 - ~/.lock  left as it is; bx never wrote it; no longer declared in \
             ~/.config/bx/bx.toml; files/lock stays in the repo\n"
    );
    assert_eq!(
        std::fs::read(body(&home, "lock")).expect("the copy"),
        b"before\n"
    );
    assert_eq!(
        std::fs::read(home.child(".lock")).expect("kept"),
        b"after\n"
    );
    assert_eq!(layer(&home), "");
    assert_eq!(ledger(&home).iter().count(), 0);
    assert!(rm_rel(&home, ".lock").is_empty(), "a second rm is a no-op");
}

#[test]
fn rm_of_a_tracked_target_whose_repo_copy_moved_since_is_a_conflict_that_changes_nothing() {
    let home = tracked_and_synced(b"before\n", b"after\n");
    // Another machine's sync, pulled into this repo.
    std::fs::write(body(&home, "lock"), b"theirs\n").expect("theirs");

    let (exit, text) = rm_text(&home, "~/.lock");
    assert_eq!(exit, Exit::Pending, "{text}");
    assert!(
        text.starts_with("  ! ~/.lock  its repo copy ~/.config/bx/files/lock "),
        "{text}"
    );
    assert_eq!(text.lines().count(), 1, "{text}");
    assert_eq!(
        std::fs::read(body(&home, "lock")).expect("the copy"),
        b"theirs\n"
    );
    assert_eq!(
        std::fs::read(home.child(".lock")).expect("kept"),
        b"after\n"
    );
    assert_eq!(layer(&home), TRACKED, "still declared");
}

#[test]
fn rm_of_a_tracked_target_never_synced_only_undeclares_it() {
    let home = repo(TRACKED);
    plant(&home, ".config/bx/files/lock", b"repo\n", 0o644);
    plant(&home, ".lock", b"machine\n", 0o644);

    let removals = rm_rel(&home, ".lock");
    assert!(
        matches!(
            removals.as_slice(),
            [Removal { restored: Restored::Unmanaged { .. }, undeclared, .. }]
                if undeclared.len() == 1
        ),
        "{removals:?}"
    );
    assert_eq!(std::fs::read(body(&home, "lock")).expect("copy"), b"repo\n");
    assert_eq!(
        std::fs::read(home.child(".lock")).expect("kept"),
        b"machine\n"
    );
}

/// `~/.config/tool/lock`, tracked, with its repo copy at `files/lock`:
/// nested, so the write onto a fresh machine makes a directory.
const TRACKED_NESTED: &str = "[[target]]\npath = \"~/.config/tool/lock\"\n\
                                  file = \"files/lock\"\ndirection = \"track\"\n";

/// A fresh machine tracking `~/.config/tool/lock`: only the repo has it,
/// until `apply` writes it here.
fn tracked_onto_a_fresh_machine() -> GuardedHome {
    let home = repo(TRACKED_NESTED);
    plant(&home, ".config/bx/files/lock", b"repo\n", 0o644);
    apply_yes(&home);
    assert_eq!(
        std::fs::read(home.child(".config/tool/lock")).expect("written"),
        b"repo\n"
    );
    home
}

#[test]
fn rm_of_a_tracked_target_apply_created_removes_it_and_its_directories() {
    let home = tracked_onto_a_fresh_machine();
    assert_eq!(
        plan_exit(&home).0,
        Exit::Converged,
        "a second plan is empty"
    );

    let (exit, text) = rm_text(&home, "~/.config/tool");
    assert_eq!(exit, Exit::Converged, "{text}");
    assert!(
        text.starts_with("  - ~/.config/tool/lock  removed the file bx created"),
        "{text}"
    );
    assert!(
        !home.child(".config/tool").exists(),
        "the home is as it was"
    );
    assert_eq!(
        std::fs::read(body(&home, "lock")).expect("the copy"),
        b"repo\n",
        "bx never wrote the repo copy"
    );
    assert_eq!(layer(&home), "");
    assert_eq!(ledger(&home).iter().count(), 0);
    assert!(
        rm_rel(&home, ".config/tool").is_empty(),
        "a second rm is a no-op"
    );
}

#[test]
fn rm_of_a_tracked_tree_apply_created_removes_every_file_and_its_directories() {
    let layer_text = "[[target]]\npath = \"~/.config/x\"\ntree = \"files/.config/x\"\n\
                          direction = \"track\"\n";
    let home = repo(layer_text);
    plant(&home, ".config/bx/files/.config/x/a", b"a\n", 0o644);
    plant(&home, ".config/bx/files/.config/x/sub/b", b"b\n", 0o644);
    apply_yes(&home);
    assert_eq!(
        std::fs::read(home.child(".config/x/sub/b")).expect("written"),
        b"b\n"
    );
    assert_eq!(
        plan_exit(&home).0,
        Exit::Converged,
        "a second plan is empty"
    );

    let (exit, text) = rm_text(&home, "~/.config/x");
    assert_eq!(exit, Exit::Converged, "{text}");
    assert!(
        text.contains("  - ~/.config/x/a  removed the file bx created")
            && text.contains("  - ~/.config/x/sub/b  removed the file bx created"),
        "{text}"
    );
    assert!(!home.child(".config/x").exists(), "the home is as it was");
    assert_eq!(
        std::fs::read(body(&home, ".config/x/a")).expect("a"),
        b"a\n",
        "bx never wrote the repo copies"
    );
    assert_eq!(
        std::fs::read(body(&home, ".config/x/sub/b")).expect("b"),
        b"b\n"
    );
    assert_eq!(layer(&home), "");
    assert_eq!(ledger(&home).iter().count(), 0);
    assert!(
        rm_rel(&home, ".config/x").is_empty(),
        "a second rm is a no-op"
    );
}

#[test]
fn a_repo_change_written_over_a_copy_bx_created_keeps_it_claimed() {
    let home = tracked_onto_a_fresh_machine();
    std::fs::write(body(&home, "lock"), b"newer\n").expect("a pulled change");
    apply_yes(&home);
    assert_eq!(
        std::fs::read(home.child(".config/tool/lock")).expect("written"),
        b"newer\n"
    );

    let (exit, text) = rm_text(&home, "~/.config/tool/lock");
    assert_eq!(exit, Exit::Converged, "{text}");
    assert!(
        !home.child(".config/tool").exists(),
        "the home is as it was"
    );
}

#[test]
fn rm_of_a_tracked_copy_the_tool_rewrote_is_a_conflict_that_changes_nothing() {
    let home = tracked_onto_a_fresh_machine();
    plant(&home, ".config/tool/lock", b"tool\n", 0o644);
    sync_apply(&home);
    assert_eq!(
        std::fs::read(body(&home, "lock")).expect("carried"),
        b"tool\n"
    );

    let (exit, text) = rm_text(&home, "~/.config/tool/lock");
    assert_eq!(exit, Exit::Pending, "{text}");
    assert!(
        text.starts_with("  ! ~/.config/tool/lock  has been edited since bx wrote it"),
        "{text}"
    );
    assert_eq!(text.lines().count(), 1, "{text}");
    assert_eq!(
        std::fs::read(home.child(".config/tool/lock")).expect("kept"),
        b"tool\n"
    );
    assert_eq!(
        std::fs::read(body(&home, "lock")).expect("the copy"),
        b"tool\n",
        "the repo copy is not handed back without the machine copy"
    );
    assert_eq!(layer(&home), TRACKED_NESTED, "still declared");
}

#[test]
fn rm_of_a_tracked_tree_restores_every_copy_and_holds_on_one_that_conflicts() {
    let layer_text = "[[target]]\npath = \"~/.config/x\"\ntree = \"files/.config/x\"\n\
                          direction = \"track\"\n";
    let home = repo(layer_text);
    for (rel, bytes) in [("a", b"a\n"), ("b", b"b\n")] {
        plant(
            &home,
            &format!(".config/bx/files/.config/x/{rel}"),
            bytes,
            0o644,
        );
        plant(&home, &format!(".config/x/{rel}"), bytes, 0o644);
    }
    sync_apply(&home);
    plant(&home, ".config/x/a", b"a2\n", 0o644);
    plant(&home, ".config/x/b", b"b2\n", 0o644);
    sync_apply(&home);
    std::fs::write(body(&home, ".config/x/b"), b"theirs\n").expect("theirs");

    let (exit, text) = rm_text(&home, "~/.config/x");
    assert_eq!(exit, Exit::Pending, "{text}");
    assert_eq!(layer(&home), layer_text, "the tree stays whole");
    assert_eq!(
        std::fs::read(body(&home, ".config/x/a")).expect("a"),
        b"a2\n",
        "nothing restored"
    );

    std::fs::write(body(&home, ".config/x/b"), b"b2\n").expect("put back");
    let (exit, text) = rm_text(&home, "~/.config/x");
    assert_eq!(exit, Exit::Converged, "{text}");
    assert_eq!(layer(&home), "");
    assert_eq!(
        std::fs::read(body(&home, ".config/x/a")).expect("a"),
        b"a\n"
    );
    assert_eq!(
        std::fs::read(body(&home, ".config/x/b")).expect("b"),
        b"b\n"
    );
    assert_eq!(
        std::fs::read(home.child(".config/x/a")).expect("a"),
        b"a2\n"
    );
}

#[test]
fn add_of_a_tracked_target_is_refused_naming_sync() {
    let home = repo(TRACKED);
    plant(&home, ".config/bx/files/lock", b"x\n", 0o644);
    plant(&home, ".lock", b"x\n", 0o644);
    let rows = add_rel(&home, ".lock");
    assert!(
        matches!(rows.as_slice(), [Adoption::Refused { note, .. }]
                if note.ends_with("as tracked; bx sync carries it into the repo")),
        "{rows:?}"
    );
}
