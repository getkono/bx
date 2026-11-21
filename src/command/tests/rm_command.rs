//! `bx rm`: the rows it shows before it asks, the answers to its question,
//! what it reports when a layer cannot be edited part way, and the way out it
//! names when an edit stops it.

use super::*;
use crate::paths::Portable;

/// Two files bx created under `~/.d`, each declared inline in `bx.toml`.
const TWO: &str = "[[target]]\npath = \"~/.d/a\"\ncontent = \"a\\n\"\n\n\
                   [[target]]\npath = \"~/.d/b\"\ncontent = \"b\\n\"\n";

/// A home where bx applied [`TWO`].
fn applied() -> crate::testing::GuardedHome {
    let home = guarded_home();
    seed(home.path(), TWO);
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("bx writes them");
    home
}

fn tty(home: &Path) -> Env {
    Env {
        stdin_tty: true,
        ..env(home)
    }
}

fn never_rm() -> Result<bool, adopt::Error> {
    panic!("nothing should have been asked")
}

fn layer(home: &Path) -> String {
    std::fs::read_to_string(home.join(".config/bx/bx.toml")).expect("bx.toml")
}

/// The preview of `rm ~/.d` over [`applied`].
const PREVIEW: &str = "bx rm ~/.d will:\n\
    \x20 - ~/.d/a  removes the file bx created; undeclared from ~/.config/bx/bx.toml\n\
    \x20 - ~/.d/b  removes the file bx created; undeclared from ~/.config/bx/bx.toml\n";

/// What `rm ~/.d` over [`applied`] did.
const DONE: &str = "  - ~/.d/a  removed the file bx created; no longer declared in \
                    ~/.config/bx/bx.toml\n  \
                    - ~/.d/b  removed the file bx created; no longer declared in \
                    ~/.config/bx/bx.toml\n";

#[test]
fn rm_of_a_directory_without_a_terminal_shows_its_rows_and_changes_nothing() {
    let home = applied();
    let mut out = Vec::new();
    let error = rm_with(
        &env(home.path()),
        home.path(),
        "~/.d",
        false,
        &mut out,
        &mut never_rm,
    )
    .expect_err("nobody confirmed it");
    assert!(
        matches!(error, adopt::Error::NeedsConfirmation),
        "{error:?}"
    );
    assert!(error.to_string().contains("--yes"), "{error}");
    assert_eq!(text(&out), PREVIEW);
    assert!(home.child(".d/a").exists() && home.child(".d/b").exists());
    assert_eq!(layer(home.path()), TWO, "still declared");
}

#[test]
fn rm_declined_at_its_question_changes_nothing() {
    let home = applied();
    let mut out = Vec::new();
    let exit = rm_with(
        &tty(home.path()),
        home.path(),
        "~/.d",
        false,
        &mut out,
        &mut || Ok(false),
    )
    .expect("rm");
    assert_eq!(exit, Exit::Pending);
    assert_eq!(text(&out), format!("{PREVIEW}Nothing was changed.\n"));
    assert!(home.child(".d/a").exists() && home.child(".d/b").exists());
    assert_eq!(layer(home.path()), TWO);
}

#[test]
fn rm_abandoned_at_its_question_is_a_cancel_that_changes_nothing() {
    let home = applied();
    let mut out = Vec::new();
    let exit = rm_with(
        &tty(home.path()),
        home.path(),
        "~/.d",
        false,
        &mut out,
        &mut || Err(adopt::Error::Canceled),
    )
    .expect("a cancel is not an error");
    assert_eq!(exit, Exit::Canceled);
    assert_eq!(
        text(&out),
        format!("{PREVIEW}Canceled. Nothing was changed.\n")
    );
    assert!(home.child(".d/a").exists());
    assert_eq!(layer(home.path()), TWO);
}

#[test]
fn rm_approved_at_its_question_does_what_it_showed() {
    let home = applied();
    let mut out = Vec::new();
    let exit = rm_with(
        &tty(home.path()),
        home.path(),
        "~/.d",
        false,
        &mut out,
        &mut || Ok(true),
    )
    .expect("rm");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(text(&out), format!("{PREVIEW}{DONE}"));
    assert!(!home.child(".d").exists(), "the directory bx made goes too");
    assert_eq!(layer(home.path()), "");
}

#[test]
fn rm_yes_asks_nothing_and_says_what_it_did() {
    let home = applied();
    let mut out = Vec::new();
    let exit = rm_with(
        &tty(home.path()),
        home.path(),
        "~/.d",
        true,
        &mut out,
        &mut never_rm,
    )
    .expect("rm");
    assert_eq!(exit, Exit::Converged);
    assert_eq!(text(&out), DONE);
}

#[test]
fn rm_with_only_a_conflict_to_show_asks_nothing() {
    let home = guarded_home();
    seed(home.path(), &inline("~/.e", "bx\\n"));
    apply_with(&env(home.path()), true, &mut Vec::new(), &mut never).expect("apply");
    std::fs::write(home.child(".e"), "mine\n").expect("the edit");
    let mut out = Vec::new();
    let exit = rm_with(
        &tty(home.path()),
        home.path(),
        "~/.e",
        false,
        &mut out,
        &mut never_rm,
    )
    .expect("rm");
    assert_eq!(exit, Exit::Pending);
    assert!(text(&out).starts_with("  ! ~/.e  "), "{}", text(&out));
}

#[test]
fn rm_after_add_then_an_edit_names_the_way_out_by_path_and_no_digest() {
    let home = guarded_home();
    seed(home.path(), "");
    std::fs::write(home.child(".rc"), "original\n").expect("the file");
    let mut out = Vec::new();
    add(&env(home.path()), home.path(), "~/.rc", false, &mut out).expect("add");
    std::fs::write(home.child(".rc"), "edited\n").expect("the edit");

    let mut out = Vec::new();
    let exit = rm(&env(home.path()), home.path(), "~/.rc", false, &mut out).expect("rm");
    assert_eq!(exit, Exit::Pending);
    let shown = text(&out);
    assert_eq!(
        shown,
        "  ! ~/.rc  has been edited since bx wrote it, and restoring the file bx replaced would \
         destroy those edits, so bx is leaving it and forgetting nothing; to hand it back, save \
         your edit into the repo with `bx add ~/.rc` or take bx's bytes back with `bx apply`, \
         then run `bx rm ~/.rc` again; still managed\n"
    );
    assert_eq!(std::fs::read(home.child(".rc")).expect("kept"), b"edited\n");
}

#[test]
fn rm_carries_out_only_what_its_preview_announced() {
    // `~/.d/a` is edited when the preview is decided, so it is shown as a
    // conflict; the edit is undone before the answer, which would make it
    // a removal nobody was asked about.
    let home = applied();
    std::fs::write(home.child(".d/a"), "mine\n").expect("the edit");
    let ctx = adopt::Context::load(&env(home.path())).expect("the context");
    let target = Portable::parse_in("~/.d", home.path()).expect("portable");
    let mut shown = Vec::new();
    let rows = adopt::rm_asking(&ctx, &target, &mut |rows| {
        shown = rows.to_vec();
        std::fs::write(home.child(".d/a"), "a\n").expect("the edit undone");
        Ok(true)
    })
    .expect("rm")
    .expect("approved");
    assert!(
        matches!(
            shown.as_slice(),
            [
                adopt::Removal {
                    restored: Restored::Conflict { .. },
                    ..
                },
                adopt::Removal {
                    restored: Restored::Removed { .. },
                    ..
                }
            ]
        ),
        "{shown:?}"
    );
    match rows.as_slice() {
        [
            adopt::Removal {
                restored: Restored::Conflict { note, .. },
                undeclared,
                ..
            },
            adopt::Removal {
                restored: Restored::Removed { .. },
                ..
            },
        ] => {
            assert!(note.contains("showed what it would do"), "{note}");
            assert!(undeclared.is_empty());
        }
        other => panic!("{other:?}"),
    }
    assert!(home.child(".d/a").exists(), "nobody was asked about it");
    assert!(!home.child(".d/b").exists());
    assert_eq!(
        layer(home.path()),
        "[[target]]\npath = \"~/.d/a\"\ncontent = \"a\\n\"\n"
    );
}

#[test]
fn a_layer_rm_cannot_edit_after_handing_back_still_reports_what_was_done() {
    use std::os::unix::fs::PermissionsExt as _;
    if rustix::process::geteuid().is_root() {
        // A directory's mode does not stop root writing into it.
        return;
    }
    let home = applied();
    let repo = home.child(".config/bx");
    let mut out = Vec::new();
    let result = rm_with(
        &tty(home.path()),
        home.path(),
        "~/.d/a",
        false,
        &mut out,
        &mut || {
            // After the preview, so only the edit of `bx.toml` fails.
            std::fs::set_permissions(&repo, std::fs::Permissions::from_mode(0o555)).expect("chmod");
            Ok(true)
        },
    );
    std::fs::set_permissions(&repo, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let error = result.expect_err("bx.toml cannot be edited");
    assert!(
        matches!(&error, adopt::Error::Undeclare { layer, .. } if layer == "~/.config/bx/bx.toml"),
        "{error:?}"
    );
    assert!(error.to_string().contains("run `bx rm` again"), "{error}");
    assert_eq!(
        text(&out),
        "bx rm ~/.d/a will:\n  - ~/.d/a  removes the file bx created; undeclared from \
         ~/.config/bx/bx.toml\n  - ~/.d/a  removed the file bx created\n",
        "the row is said before the error, naming no layer it was not undeclared from"
    );
    assert!(!home.child(".d/a").exists());
    assert_eq!(layer(home.path()), TWO, "still declared");

    // A second `rm` finishes it.
    let mut out = Vec::new();
    let exit = rm(&env(home.path()), home.path(), "~/.d/a", true, &mut out).expect("rm");
    assert_eq!(exit, Exit::Converged, "{}", text(&out));
    assert_eq!(
        layer(home.path()),
        "\n[[target]]\npath = \"~/.d/b\"\ncontent = \"b\\n\"\n"
    );
}
