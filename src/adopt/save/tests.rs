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
fn a_mode_change_alone_is_saved_without_undoing_the_repo_s_newer_body() {
    let home = applied(FILE_BODY, b"one\n");
    std::fs::write(home.child(".config/bx/files/rc"), b"two\n").expect("the repo's edit");
    chmod(&rc(&home), 0o600);

    let rows = add(&home);
    assert_eq!(how(&rows), Some(How::Save), "a save, not a merge: {rows:?}");
    assert_eq!(layer(&home), format!("{FILE_BODY}mode = \"0600\"\n"));
    assert_eq!(repo_body(&home), b"two\n", "the repo's edit stands");
    assert_eq!(std::fs::read(rc(&home)).expect("read"), b"one\n");
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

/// The home the conflicted-merge crash child saves in.
const CONFLICT_CRASH_HOME: &str = "BX_ADD_CONFLICT_CRASH_HOME";

#[test]
#[ignore = "spawned by the conflicted-merge crash harness; it aborts on purpose"]
fn conflicted_merge_crash_child() {
    let Some(home) = std::env::var_os(CONFLICT_CRASH_HOME) else {
        return;
    };
    let home = Path::new(&home);
    let mut out = Vec::new();
    crate::command::add(&env(home), home, ".rc", true, &mut out).expect("add");
}

#[test]
fn a_conflicted_merge_killed_as_its_session_finishes_recovers_to_an_edit_plan_asks_about() {
    // The defect: the write's journal intent named the marked bytes as what
    // bx left, so a crash after the `End` frame — before the ledger save, or
    // after it and before the journal went — had recovery record the marked
    // file as bx's own, and the next apply wrote the repo's bytes over it
    // unasked.
    for phase in crate::journal::tests::finish_crash_phases() {
        let home = applied(FILE_BODY, BASE);
        std::fs::write(rc(&home), b"one\nmine\nthree\n").expect("edit here");
        std::fs::write(home.child(".config/bx/files/rc"), b"one\ntheirs\nthree\n").expect("there");

        let output =
            crate::testing::ignored_child("adopt::save::tests::conflicted_merge_crash_child")
                .env("BX_CRASH_AT", format!("1:{phase}"))
                .env(CONFLICT_CRASH_HOME, home.path())
                .env_remove("LLVM_PROFILE_FILE")
                .output()
                .expect("spawn the crash child");
        assert!(!output.status.success(), "{phase}: the child did not stop");
        let state = StateDir::resolve(home.path());
        assert!(state.journal().exists(), "{phase}: interrupted");
        let marked = std::fs::read(rc(&home)).expect("the marked file");
        assert!(
            String::from_utf8_lossy(&marked).contains("<<<<<<< yours\nmine\n"),
            "{phase}: the merge landed"
        );

        let mut out = Vec::new();
        crate::command::apply(&env(home.path()), true, &mut out).expect("the recovering apply");
        let text = String::from_utf8(out).expect("UTF-8");
        assert!(!state.journal().exists(), "{phase}: recovered: {text}");
        assert_eq!(
            std::fs::read(rc(&home)).expect("read"),
            marked,
            "{phase}: never written over unasked: {text}"
        );
        assert_eq!(
            written(&home),
            ContentHash::of(BASE),
            "{phase}: still bx's last write"
        );
        let (exit, shown) = plan(&home);
        assert_eq!(
            exit,
            Exit::Pending,
            "{phase}: an edit plan asks about: {shown}"
        );
        assert!(
            shown.contains("edited since bx last wrote it"),
            "{phase}: {shown}"
        );

        // And the apply after it, with nobody to ask, leaves the edit.
        let mut out = Vec::new();
        crate::command::apply(&env(home.path()), true, &mut out).expect("the next apply");
        assert_eq!(
            std::fs::read(rc(&home)).expect("read"),
            marked,
            "{phase}: {}",
            String::from_utf8_lossy(&out)
        );
    }
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

/// The shared settings every machine applies, laid out as a JSON printer
/// lays it out, and what this machine adds to it.
const SHARED_JSON: &str = "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(ls)\"\n    ]\n  },\n  \"hooks\": {}\n}\n";
const HOOK_JSON: &str =
    r#"{"hooks": {"SubagentStop": [{"type": "command", "command": "~/bin/stop"}]}}"#;

/// A home whose repo declares `~/.settings.json` from `files/settings.json`
/// with this machine's overlay from `files/hook.json`, applied once.
fn overlaid() -> GuardedHome {
    let home = guarded_home();
    seed(
        home.path(),
        "[[target]]\npath = \"~/.settings.json\"\nfile = \"files/settings.json\"\n\
         [[overlay]]\nname = \"hook\"\npath = \"~/.settings.json\"\nfile = \"files/hook.json\"\n",
    );
    home.write(".config/bx/files/settings.json", SHARED_JSON);
    home.write(".config/bx/files/hook.json", HOOK_JSON);
    let mut out = Vec::new();
    crate::command::apply(&env(home.path()), true, &mut out).expect("apply");
    home
}

fn json_at(home: &GuardedHome, rel: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(home.child(rel)).expect("read")).expect("JSON")
}

/// The file on this machine rewritten as a tool rewrites it: parsed, changed
/// by `edit`, and printed again.
fn rewrite(home: &GuardedHome, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut value = json_at(home, ".settings.json");
    edit(&mut value);
    let mut bytes = serde_json::to_vec_pretty(&value).expect("print");
    bytes.push(b'\n');
    std::fs::write(home.child(".settings.json"), bytes).expect("the tool's write");
}

fn add_settings(home: &GuardedHome) -> Vec<Adoption> {
    let ctx = Context::load(&env(home.path())).expect("the context");
    let target = Portable::parse_in("~/.settings.json", home.path()).expect("a target");
    adopt::add(&ctx, &target).expect("add")
}

fn shared_body(home: &GuardedHome) -> String {
    std::fs::read_to_string(home.child(".config/bx/files/settings.json")).expect("read")
}

#[test]
fn a_tool_s_rewrite_is_saved_without_this_machine_s_overlay() {
    let home = overlaid();
    assert!(
        json_at(&home, ".settings.json")["hooks"]["SubagentStop"].is_array(),
        "the overlay is applied"
    );
    // The tool adds a shared setting, and keeps everything else, the hook
    // included, where it was.
    rewrite(&home, |value| {
        value["model"] = serde_json::Value::from("opus");
    });

    let rows = add_settings(&home);
    assert_eq!(how(&rows), Some(How::Save), "{rows:?}");
    let saved = json_at(&home, ".config/bx/files/settings.json");
    assert_eq!(saved["model"], "opus", "the tool's edit reaches the repo");
    assert_eq!(
        saved["hooks"],
        serde_json::json!({}),
        "the overlay does not"
    );
    assert_eq!(
        std::fs::read_to_string(home.child(".config/bx/files/hook.json")).expect("read"),
        HOOK_JSON,
        "nothing shared moves into the overlay"
    );
    let (exit, shown) = plan(&home);
    assert_eq!(exit, Exit::Converged, "{shown}");
}

#[test]
fn a_rewrite_that_changes_nothing_shared_saves_nothing_into_the_repo() {
    let home = overlaid();
    // Only the layout changes: the same data, printed compactly.
    let value = json_at(&home, ".settings.json");
    std::fs::write(
        home.child(".settings.json"),
        serde_json::to_vec(&value).expect("print"),
    )
    .expect("the tool's write");

    add_settings(&home);
    assert_eq!(
        shared_body(&home),
        SHARED_JSON,
        "the shared body is as it was"
    );
    // The file is bx's at the tool's layout now, and bx writes its own: the
    // next plan lays it out again, as a change to bytes bx wrote, and the
    // one after is empty.
    let (exit, shown) = plan(&home);
    assert_eq!(exit, Exit::Pending, "{shown}");
    let mut out = Vec::new();
    crate::command::apply(&env(home.path()), true, &mut out).expect("apply");
    let (exit, shown) = plan(&home);
    assert_eq!(exit, Exit::Converged, "{shown}");
}

#[test]
fn a_mode_change_alone_to_an_overlaid_file_leaves_the_repo_s_newer_body() {
    let home = overlaid();
    let repo_edit = SHARED_JSON.replace("\"hooks\": {}", "\"hooks\": {},\n  \"model\": \"opus\"");
    home.write(".config/bx/files/settings.json", &repo_edit);
    chmod(&home.child(".settings.json"), 0o600);

    let rows = add_settings(&home);
    assert_eq!(how(&rows), Some(How::Save), "{rows:?}");
    assert_eq!(shared_body(&home), repo_edit, "the repo's edit stands");
}

#[test]
fn add_refuses_a_file_whose_overlays_cannot_be_merged() {
    let home = overlaid();
    home.write(".config/bx/files/hook.json", r#"{"hooks": 1}"#);
    let note = refusal(&add_settings(&home)).to_string();
    assert!(note.contains("`hooks`"), "{note}");
}

#[test]
fn a_toml_rewrite_is_saved_without_the_overlay_and_keeps_the_tool_s_layout() {
    let home = guarded_home();
    seed(
        home.path(),
        "[[target]]\npath = \"~/.tool.toml\"\nfile = \"files/tool.toml\"\n\
         [[overlay]]\nname = \"font\"\npath = \"~/.tool.toml\"\ncontent = \"[editor]\\nfont = \\\"mono\\\"\\n\"\n",
    );
    home.write(
        ".config/bx/files/tool.toml",
        "# shared\n[editor]\ntheme = \"dark\"\n",
    );
    let mut out = Vec::new();
    crate::command::apply(&env(home.path()), true, &mut out).expect("apply");
    let applied = std::fs::read_to_string(home.child(".tool.toml")).expect("read");
    assert!(applied.contains("font = \"mono\""), "{applied}");

    // The tool adds a shared key at the top and keeps the rest.
    std::fs::write(
        home.child(".tool.toml"),
        format!("model = \"opus\"\n{applied}"),
    )
    .expect("the tool's write");
    let ctx = Context::load(&env(home.path())).expect("the context");
    let target = Portable::parse_in("~/.tool.toml", home.path()).expect("a target");
    let rows = adopt::add(&ctx, &target).expect("add");
    assert_eq!(how(&rows), Some(How::Save), "{rows:?}");
    assert_eq!(
        std::fs::read_to_string(home.child(".config/bx/files/tool.toml")).expect("read"),
        "model = \"opus\"\n# shared\n[editor]\ntheme = \"dark\"\n"
    );
    let (exit, shown) = plan(&home);
    assert_eq!(exit, Exit::Converged, "{shown}");
}

#[test]
fn a_hand_laid_out_shared_body_still_merges_cleanly_with_a_tool_s_rewrite() {
    let home = overlaid();
    let compact = "{\"permissions\": {\"allow\": [\"Bash(ls)\", \"Bash(cat)\"]}, \"hooks\": {}}";
    rewrite(&home, |value| {
        value["model"] = serde_json::Value::from("opus");
    });
    home.write(".config/bx/files/settings.json", compact);

    let rows = add_settings(&home);
    assert_eq!(how(&rows), Some(How::Merged), "{rows:?}");
    let saved = json_at(&home, ".config/bx/files/settings.json");
    assert_eq!(saved["model"], "opus");
    assert_eq!(saved["permissions"]["allow"][1], "Bash(cat)");
    assert_eq!(saved["hooks"], serde_json::json!({}));
}

#[test]
fn a_tool_changing_what_the_overlay_added_is_refused_rather_than_saved() {
    let home = overlaid();
    rewrite(&home, |value| {
        value["hooks"]["SubagentStop"][0]["command"] = serde_json::Value::from("~/bin/other");
    });
    let rows = add_settings(&home);
    let note = refusal(&rows);
    assert!(note.contains("overlay"), "{note}");
    assert_eq!(shared_body(&home), SHARED_JSON, "nothing saved");
}

#[test]
fn both_sides_changed_merge_the_shared_parts_and_keep_the_overlay_out_of_the_repo() {
    let home = overlaid();
    rewrite(&home, |value| {
        value["model"] = serde_json::Value::from("opus");
    });
    let repo_edit = SHARED_JSON.replace("\"Bash(ls)\"", "\"Bash(ls)\",\n      \"Bash(cat)\"");
    home.write(".config/bx/files/settings.json", &repo_edit);

    let rows = add_settings(&home);
    assert_eq!(how(&rows), Some(How::Merged), "{rows:?}");
    let saved = json_at(&home, ".config/bx/files/settings.json");
    assert_eq!(saved["model"], "opus");
    assert_eq!(saved["permissions"]["allow"][1], "Bash(cat)");
    assert_eq!(
        saved["hooks"],
        serde_json::json!({}),
        "the overlay stays out"
    );
    let machine = json_at(&home, ".settings.json");
    assert_eq!(machine["model"], "opus");
    assert_eq!(machine["permissions"]["allow"][1], "Bash(cat)");
    assert!(
        machine["hooks"]["SubagentStop"].is_array(),
        "and stays here"
    );
}
