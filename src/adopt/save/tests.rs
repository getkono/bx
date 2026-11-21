use std::path::{Path, PathBuf};

use crate::adopt::{self, Adoption, Context, Error, MOVED, NOT_CONFIRMED};
use crate::paths::Portable;
use crate::plan::tests::{env, inline, seed};
use crate::report::Exit;
use crate::restore::Restored;
use crate::state::{ContentHash, LedgerView, StateDir};
use crate::testing::{GuardedHome, chmod, guarded_home, mode_of};

use super::How;

/// A `[[target]]` for `~/.rc` whose body is the repo file `files/rc`.
const FILE_BODY: &str = "# my own notes\n[[target]]\npath = \"~/.rc\"\nfile = \"files/rc\"\n";

/// A home whose repo declares `layer`, holding `files/rc` as `body`, applied
/// once so bx owns what it wrote.
fn applied(layer: &str, body: &[u8]) -> GuardedHome {
    let home = guarded_home();
    seed(home.path(), layer);
    let files = home.child(".config/bx/files");
    std::fs::create_dir_all(&files).expect("files");
    std::fs::write(files.join("rc"), body).expect("the body");
    let mut out = Vec::new();
    crate::command::apply(&env(home.path()), true, &mut out).expect("apply");
    home
}

fn rc(home: &GuardedHome) -> PathBuf {
    home.child(".rc")
}

fn repo_body(home: &GuardedHome) -> Vec<u8> {
    std::fs::read(home.child(".config/bx/files/rc")).expect("the repo body")
}

fn layer(home: &GuardedHome) -> String {
    std::fs::read_to_string(home.child(".config/bx/bx.toml")).expect("bx.toml")
}

fn target(home: &GuardedHome) -> Portable {
    Portable::parse_in("~/.rc", home.path()).expect("a target")
}

fn add(home: &GuardedHome) -> Vec<Adoption> {
    let ctx = Context::load(&env(home.path())).expect("the context");
    adopt::add(&ctx, &target(home)).expect("add")
}

fn plan(home: &GuardedHome) -> (Exit, String) {
    let mut out = Vec::new();
    let exit = crate::command::plan(&env(home.path()), &mut out).expect("plan");
    (exit, String::from_utf8(out).expect("UTF-8"))
}

fn written(home: &GuardedHome) -> ContentHash {
    LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("the ledger")
        .value
        .get(&target(home))
        .expect("bx owns it")
        .written
}

fn how(rows: &[Adoption]) -> Option<How> {
    match rows {
        [Adoption::Save { save, .. }] => Some(save.how),
        _ => None,
    }
}

fn refusal(rows: &[Adoption]) -> &str {
    match rows {
        [Adoption::Refused { note, .. }] => note,
        other => panic!("not one refusal: {other:?}"),
    }
}

#[test]
fn an_edit_of_a_file_body_is_saved_into_the_repo_and_the_next_plan_is_empty() {
    let home = applied(FILE_BODY, b"one\ntwo\n");
    std::fs::write(rc(&home), b"one\nmine\n").expect("edit");
    assert_eq!(plan(&home).0, Exit::Pending, "the edit is a conflict");

    let rows = add(&home);
    assert_eq!(how(&rows), Some(How::Save), "{rows:?}");
    assert_eq!(repo_body(&home), b"one\nmine\n");
    assert_eq!(std::fs::read(rc(&home)).expect("read"), b"one\nmine\n");
    assert_eq!(layer(&home), FILE_BODY, "nothing to declare");
    assert_eq!(written(&home), ContentHash::of(b"one\nmine\n"));
    let (exit, shown) = plan(&home);
    assert_eq!(exit, Exit::Converged, "{shown}");

    let again = add(&home);
    assert!(
        matches!(again.as_slice(), [Adoption::Unchanged { .. }]),
        "{again:?}"
    );

    // `rm` hands back the file the user left: the saved edit.
    let ctx = Context::load(&env(home.path())).expect("the context");
    let removals = adopt::rm(&ctx, &target(&home)).expect("rm");
    assert!(
        matches!(
            removals.as_slice(),
            [adopt::Removal {
                restored: Restored::Reverted { .. },
                ..
            }]
        ),
        "{removals:?}"
    );
    assert_eq!(std::fs::read(rc(&home)).expect("read"), b"one\nmine\n");
}

#[test]
fn an_edit_of_an_inline_body_is_saved_into_its_layer_and_nothing_else_there_moves() {
    let declared = format!("# keep me\n{}# and me\n", inline("~/.rc", "repo\\n"));
    let home = applied(&declared, b"");
    std::fs::write(rc(&home), b"mine\n  indented\n").expect("edit");

    let rows = add(&home);
    assert_eq!(how(&rows), Some(How::Save), "{rows:?}");
    let saved = layer(&home);
    assert_eq!(
        saved,
        declared.replace("\"repo\\n\"", "\"\"\"\nmine\n  indented\n\"\"\""),
        "only the content's value moved, written as toml_edit writes a string of lines"
    );
    assert_eq!(plan(&home).0, Exit::Converged, "{}", plan(&home).1);
}

#[test]
fn a_mode_changed_on_this_machine_is_saved_as_the_declared_mode() {
    let home = applied(FILE_BODY, b"same\n");
    chmod(&rc(&home), 0o600);

    let rows = add(&home);
    assert_eq!(how(&rows), Some(How::Save), "{rows:?}");
    assert_eq!(layer(&home), format!("{FILE_BODY}mode = \"0600\"\n"));
    assert_eq!(repo_body(&home), b"same\n", "the bytes were not edited");
    assert_eq!(plan(&home).0, Exit::Converged, "{}", plan(&home).1);

    // A declared mode is edited where it is.
    chmod(&rc(&home), 0o640);
    add(&home);
    assert_eq!(layer(&home), format!("{FILE_BODY}mode = \"0640\"\n"));
    assert_eq!(plan(&home).0, Exit::Converged);
}

#[test]
fn a_body_file_another_target_also_delivers_is_refused_naming_it() {
    let shared = format!("{FILE_BODY}[[target]]\npath = \"~/.other\"\nfile = \"files/rc\"\n");
    let home = applied(&shared, b"both\n");
    std::fs::write(rc(&home), b"mine\n").expect("edit");

    let rows = add(&home);
    let note = refusal(&rows);
    assert!(note.contains("~/.other"), "{note}");
    assert_eq!(repo_body(&home), b"both\n", "nothing was saved");
}

#[test]
fn an_inline_content_holding_a_placeholder_is_refused() {
    let values = "[[value]]\nname = \"who\"\nkind = \"string\"\ndefault = \"me\"\n";
    let home = applied(&format!("{values}{}", inline("~/.rc", "{{who}}\\n")), b"");
    assert_eq!(std::fs::read(rc(&home)).expect("read"), b"me\n");
    std::fs::write(rc(&home), b"me, edited\n").expect("edit");

    let before = layer(&home);
    let note = refusal(&add(&home)).to_string();
    assert!(note.contains("{{name}}"), "{note}");
    assert_eq!(layer(&home), before);
}

#[test]
fn a_layer_saved_by_an_editor_while_bx_asked_is_refused_and_keeps_the_save() {
    let home = applied(&inline("~/.rc", "repo\\n"), b"");
    std::fs::write(rc(&home), b"mine\n").expect("edit");
    let ctx = Context::load(&env(home.path())).expect("the context");
    let edited = format!("# saved meanwhile\n{}", inline("~/.rc", "repo\\n"));

    let rows = adopt::add_asking(&ctx, &target(&home), &mut |_| {
        std::fs::write(home.child(".config/bx/bx.toml"), &edited).expect("an editor saves");
        Ok(true)
    })
    .expect("add");
    assert_eq!(refusal(&rows), MOVED);
    assert_eq!(layer(&home), edited, "the editor's save stands");

    // And a layer changed between the decision and the write is refused by
    // the write itself.
    let ctx = Context::load(&env(home.path())).expect("the context");
    let ledger = LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("ledger")
        .value;
    let rows = adopt::plan_add(&ctx, &ledger, &target(&home)).expect("plan");
    let [Adoption::Save { save, .. }] = rows.as_slice() else {
        panic!("{rows:?}");
    };
    std::fs::write(home.child(".config/bx/bx.toml"), MINE_AGAIN).expect("saved again");
    let error = save.repo[0].write().expect_err("refused");
    assert!(
        matches!(&error, Error::Layer { why, .. } if why.contains("changed after bx read it")),
        "{error}"
    );
    assert_eq!(layer(&home), MINE_AGAIN);
}

/// A layer an editor saves over bx's read.
const MINE_AGAIN: &str = "[[target]]\npath = \"~/.rc\"\ncontent = \"repo\\n\"\n# again\n";

#[test]
fn a_save_nobody_confirmed_writes_nothing_and_says_how_to_confirm() {
    let home = applied(FILE_BODY, b"one\n");
    std::fs::write(rc(&home), b"mine\n").expect("edit");

    let mut out = Vec::new();
    let exit =
        crate::command::add(&env(home.path()), home.path(), ".rc", false, &mut out).expect("add");
    let text = String::from_utf8(out).expect("UTF-8");
    assert_eq!(exit, Exit::Pending, "{text}");
    assert!(text.contains("+mine"), "the diff is shown first: {text}");
    assert!(text.contains(NOT_CONFIRMED), "{text}");
    assert_eq!(repo_body(&home), b"one\n");

    let mut out = Vec::new();
    let exit =
        crate::command::add(&env(home.path()), home.path(), ".rc", true, &mut out).expect("add");
    let text = String::from_utf8(out).expect("UTF-8");
    assert_eq!(exit, Exit::Converged, "{text}");
    assert!(
        text.contains("  < ~/.rc  saved into ~/.config/bx/files/rc"),
        "{text}"
    );
    assert!(text.contains("bx sync commits and pushes"), "{text}");
    assert_eq!(repo_body(&home), b"mine\n");
}

#[test]
fn at_a_terminal_the_save_is_asked_about_and_a_no_writes_nothing() {
    let home = applied(FILE_BODY, b"one\n");
    std::fs::write(rc(&home), b"mine\n").expect("edit");
    let mut tty = env(home.path());
    tty.stdin_tty = true;

    for (answer, body) in [(false, &b"one\n"[..]), (true, b"mine\n")] {
        let mut out = Vec::new();
        let mut asked = 0;
        crate::command::add_with(&tty, home.path(), ".rc", false, &mut out, &mut || {
            asked += 1;
            Ok(answer)
        })
        .expect("add");
        assert_eq!(asked, 1);
        assert_eq!(repo_body(&home), body);
    }

    std::fs::write(rc(&home), b"again\n").expect("edit");
    let mut out = Vec::new();
    let exit = crate::command::add_with(&tty, home.path(), ".rc", false, &mut out, &mut || {
        Err(Error::Canceled)
    })
    .expect("add");
    assert_eq!(exit, Exit::Canceled);
    assert_eq!(repo_body(&home), b"mine\n");
}

/// Three lines, the base both sides edit.
const BASE: &[u8] = b"one\ntwo\nthree\n";

#[test]
fn both_sides_changed_merge_cleanly_into_both_and_rm_restores_the_pre_merge_bytes() {
    let home = applied(FILE_BODY, BASE);
    std::fs::write(rc(&home), b"ONE\ntwo\nthree\n").expect("edit here");
    std::fs::write(home.child(".config/bx/files/rc"), b"one\ntwo\nTHREE\n").expect("there");

    let rows = add(&home);
    assert_eq!(how(&rows), Some(How::Merged), "{rows:?}");
    let merged = b"ONE\ntwo\nTHREE\n";
    assert_eq!(repo_body(&home), merged);
    assert_eq!(std::fs::read(rc(&home)).expect("read"), merged);
    assert_eq!(mode_of(&rc(&home)), 0o644);
    let (exit, shown) = plan(&home);
    assert_eq!(exit, Exit::Converged, "{shown}");

    let ctx = Context::load(&env(home.path())).expect("the context");
    adopt::rm(&ctx, &target(&home)).expect("rm");
    assert_eq!(
        std::fs::read(rc(&home)).expect("read"),
        b"ONE\ntwo\nthree\n",
        "the bytes the merge replaced are back"
    );
}

#[test]
fn a_conflicted_merge_marks_the_machine_file_only_and_stays_an_edit() {
    let home = applied(FILE_BODY, BASE);
    std::fs::write(rc(&home), b"one\nmine\nthree\n").expect("edit here");
    std::fs::write(home.child(".config/bx/files/rc"), b"one\ntheirs\nthree\n").expect("there");

    let mut out = Vec::new();
    let exit =
        crate::command::add(&env(home.path()), home.path(), ".rc", true, &mut out).expect("add");
    let text = String::from_utf8(out).expect("UTF-8");
    assert_eq!(exit, Exit::Pending, "{text}");
    assert!(
        text.contains("resolve them, then run bx add ~/.rc"),
        "{text}"
    );
    assert_eq!(
        repo_body(&home),
        b"one\ntheirs\nthree\n",
        "the repo is not changed"
    );
    let marked = String::from_utf8(std::fs::read(rc(&home)).expect("read")).expect("UTF-8");
    assert!(
        marked.contains("<<<<<<< yours\nmine\n=======\ntheirs\n>>>>>>> the repo\n"),
        "{marked}"
    );
    assert_eq!(
        written(&home),
        ContentHash::of(BASE),
        "still bx's last write"
    );
    let (exit, shown) = plan(&home);
    assert_eq!(exit, Exit::Pending, "an edit plan asks about: {shown}");

    // Resolved, the next add merges cleanly.
    std::fs::write(rc(&home), b"one\nboth\nthree\n").expect("resolve");
    std::fs::write(home.child(".config/bx/files/rc"), b"one\ntheirs\nthree\n").expect("same");
    let rows = add(&home);
    assert!(how(&rows).is_some(), "{rows:?}");
}

#[test]
fn rm_after_a_conflicted_merge_leaves_the_marked_file_as_a_conflict() {
    let home = applied(FILE_BODY, BASE);
    std::fs::write(rc(&home), b"one\nmine\nthree\n").expect("edit here");
    std::fs::write(home.child(".config/bx/files/rc"), b"one\ntheirs\nthree\n").expect("there");
    let mut out = Vec::new();
    crate::command::add(&env(home.path()), home.path(), ".rc", true, &mut out).expect("add");
    let state = StateDir::resolve(home.path());
    assert!(
        !state.journal().exists(),
        "the merge's session finished whole"
    );
    assert_eq!(
        written(&home),
        ContentHash::of(BASE),
        "saved with the write"
    );

    let marked = std::fs::read(rc(&home)).expect("the marked file");
    let text = String::from_utf8(out).expect("UTF-8");
    assert!(
        text.contains("merged with conflict markers around both sides"),
        "{text}"
    );

    let ctx = Context::load(&env(home.path())).expect("the context");
    adopt::rm(&ctx, &target(&home)).expect("rm");

    // Not bx's last write, so an edit rm will not hand back over: left
    // byte for byte, every line of the user's inside it, still managed.
    assert_eq!(std::fs::read(rc(&home)).expect("read"), marked);
    assert!(String::from_utf8_lossy(&marked).contains("\nmine\n"));
    assert_eq!(written(&home), ContentHash::of(BASE), "still declared");
}

#[test]
fn both_sides_changed_with_no_base_kept_is_refused() {
    let home = applied(FILE_BODY, BASE);
    let state = StateDir::resolve(home.path());
    std::fs::remove_dir_all(state.restore()).expect("lose the bases");
    std::fs::create_dir_all(state.restore()).expect("an empty store");
    std::fs::write(rc(&home), b"ONE\ntwo\nthree\n").expect("edit here");
    std::fs::write(home.child(".config/bx/files/rc"), b"one\ntwo\nTHREE\n").expect("there");

    let note = refusal(&add(&home)).to_string();
    assert!(note.contains("kept no copy"), "{note}");
    assert_eq!(repo_body(&home), b"one\ntwo\nTHREE\n");
}

#[test]
fn a_binary_both_sides_changed_is_refused_as_unmergeable() {
    let home = applied(FILE_BODY, b"\0base\n");
    std::fs::write(rc(&home), b"\0mine\n").expect("edit here");
    std::fs::write(home.child(".config/bx/files/rc"), b"\0theirs\n").expect("there");

    let note = refusal(&add(&home)).to_string();
    assert!(note.contains("could not be merged"), "{note}");
}

#[test]
fn a_repo_change_alone_is_refused_naming_apply() {
    let home = applied(FILE_BODY, BASE);
    std::fs::write(home.child(".config/bx/files/rc"), b"moved\n").expect("there");
    let note = refusal(&add(&home)).to_string();
    assert!(note.contains("bx apply"), "{note}");
}

#[test]
fn an_edit_that_is_not_utf8_is_refused_for_an_inline_body() {
    let home = applied(&inline("~/.rc", "repo\\n"), b"");
    std::fs::write(rc(&home), b"\xff\n").expect("edit");
    let note = refusal(&add(&home)).to_string();
    assert!(note.contains("not UTF-8"), "{note}");
}

#[test]
fn shapes_bx_does_not_save_into_are_refused_by_the_decision_itself() {
    let home = applied(FILE_BODY, b"x\n");
    let ctx = Context::load(&env(home.path())).expect("the context");
    let sides = ctx.sides();
    let declared = match &ctx.resolved.targets[0] {
        crate::config::resolve::Resolution::Ready(target) => target.clone(),
        other => panic!("{other:?}"),
    };
    let ledger = LedgerView::read(&StateDir::resolve(home.path()), home.path())
        .expect("ledger")
        .value;
    let entry = ledger.get(&target(&home)).expect("owned").clone();
    let observed = crate::fs::observe(&rc(&home)).expect("observe");
    use crate::config::target::{Attach, Body, Direction};
    let mut tracked = declared.clone();
    tracked.direction = Direction::Track;
    let mut secret = declared.clone();
    secret.body = Body::Secret(Path::new("s.age").to_path_buf());
    let mut dir = declared.clone();
    dir.body = Body::Dir;
    let mut region = declared.clone();
    region.attach = Attach::Region { comment: '#' };
    let cases = [
        ("tracked", tracked),
        ("secret", secret),
        ("a directory", dir),
        ("a region", region),
    ];
    for (what, shaped) in cases {
        assert!(
            matches!(
                super::decide(&sides, &shaped, &entry, &observed, b"y\n"),
                super::Decision::Refused(_)
            ),
            "{what}"
        );
    }
}
