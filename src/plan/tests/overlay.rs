//! A shared structured target with a machine's overlays merged in: the
//! machine that declares one gets the merge, every other machine the shared
//! body's exact bytes, an edit to the shared body reaches both, a clash is a
//! blocked row, the plan shows what the machine adds as its own part, and
//! taking the overlay away gives the shared body back.

use super::*;

/// The shared `~/.claude/settings.json` every machine applies, as a JSON
/// printer lays it out.
const SHARED: &str = r#"{
  "permissions": {
    "allow": [
      "Bash(ls)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/bin/check"
          }
        ]
      }
    ]
  }
}
"#;

/// What the build host adds.
const HOOK: &str = r#"{"hooks": {"SubagentStop": [
  {"hooks": [{"type": "command", "command": "~/bin/on-subagent-stop"}]}
]}}"#;

const TARGET: &str =
    "[[target]]\npath = \"~/.claude/settings.json\"\nfile = \"files/settings.json\"\n";

const OVERLAY: &str = "[[overlay]]\nname = \"subagent-stop\"\npath = \"~/.claude/settings.json\"\n\
                       file = \"files/subagent-stop.json\"\n";

/// A repo declaring the shared target in `bx.toml` and the overlay in a module
/// gated to the host `build1`.
fn repo(home: &GuardedHome, shared: &str) {
    seed(home.path(), TARGET);
    home.write(".config/bx/files/settings.json", shared);
    home.write(".config/bx/files/subagent-stop.json", HOOK);
    home.write(
        ".config/bx/modules/build.toml",
        &format!("when = \"host:build1\"\n{OVERLAY}"),
    );
}

/// The inputs as the machine named `host` loads them.
fn on(home: &GuardedHome, host: &str) -> Inputs {
    let machine = Machine {
        host: Some(host.to_string()),
        ..Machine::read(None)
    };
    Inputs::load_on(
        &env(home.path()),
        activation::System::from_env().with_machine(machine),
    )
    .expect("the inputs load")
}

fn settings(home: &GuardedHome) -> Vec<u8> {
    std::fs::read(home.child(".claude/settings.json")).expect("the settings")
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("JSON")
}

/// `SHARED` with the hook merged in, as data.
fn hooked(shared: &str) -> serde_json::Value {
    let mut value = json(shared.as_bytes());
    value["hooks"]["SubagentStop"] =
        json(br#"[{"hooks": [{"type": "command", "command": "~/bin/on-subagent-stop"}]}]"#);
    value
}

#[test]
fn one_host_gets_the_hook_and_every_other_host_the_shared_bytes_unchanged() {
    let build = guarded_home();
    repo(&build, SHARED);
    let applied = apply(&on(&build, "build1"));
    assert_eq!(applied.actions(), vec![Action::Create]);
    assert_eq!(json(&settings(&build)), hooked(SHARED));
    assert_eq!(
        plan(&on(&build, "build1")).actions(),
        vec![Action::Unchanged]
    );

    let laptop = guarded_home();
    repo(&laptop, SHARED);
    apply(&on(&laptop, "laptop"));
    assert_eq!(settings(&laptop), SHARED.as_bytes(), "byte for byte");
}

#[test]
fn every_account_on_the_host_gets_it_and_one_opts_out_in_its_own_local_toml() {
    let one = guarded_home();
    let two = guarded_home();
    for home in [&one, &two] {
        repo(home, SHARED);
    }
    two.write(
        ".local/state/bx/local.toml",
        "[[overlay]]\nname = \"subagent-stop\"\nenabled = false\n",
    );
    apply(&on(&one, "build1"));
    apply(&on(&two, "build1"));
    assert_eq!(json(&settings(&one)), hooked(SHARED));
    assert_eq!(settings(&two), SHARED.as_bytes());
}

#[test]
fn an_edit_to_the_shared_body_reaches_the_host_that_carries_the_hook() {
    let home = guarded_home();
    repo(&home, SHARED);
    apply(&on(&home, "build1"));

    let edited = SHARED.replace("\"Bash(ls)\"", "\"Bash(ls)\",\n      \"Bash(cat)\"");
    home.write(".config/bx/files/settings.json", &edited);
    let report = plan(&on(&home, "build1"));
    assert_eq!(
        report.actions(),
        vec![Action::Modify],
        "no question: bx's own bytes"
    );
    apply(&on(&home, "build1"));
    assert_eq!(json(&settings(&home)), hooked(&edited));
    assert_eq!(
        plan(&on(&home, "build1")).actions(),
        vec![Action::Unchanged]
    );
}

#[test]
fn the_plan_shows_what_this_machine_adds_as_its_own_part_of_the_change() {
    let home = guarded_home();
    repo(&home, SHARED);
    let report = plan(&on(&home, "build1"));
    let change = &report.changes[0];
    let note = change.note.as_deref().unwrap_or_default();
    assert!(
        note.contains("overlay `subagent-stop` (") && note.contains("modules/build.toml:2)"),
        "{note}"
    );
    match change.diff.as_ref().map(|diff| &diff.kind) {
        Some(DiffKind::Texts(texts)) => {
            assert_eq!(texts.len(), 2);
            assert!(texts[1].contains("shared body"), "{}", texts[1]);
            assert!(
                texts[1].contains("with this machine's overlays"),
                "{}",
                texts[1]
            );
            assert!(
                texts[1].contains("+    \"SubagentStop\": ["),
                "{}",
                texts[1]
            );
            assert!(!texts[1].contains("+    \"PreToolUse\""), "{}", texts[1]);
        }
        other => panic!("two diffs, found {other:?}"),
    }
}

#[test]
fn a_missing_overlay_file_is_an_error_naming_the_overlay() {
    let home = guarded_home();
    repo(&home, SHARED);
    std::fs::remove_file(home.child(".config/bx/files/subagent-stop.json")).expect("remove");
    let error =
        run(&on(&home, "build1"), Mode::Plan, &mut |_| Ok(false)).expect_err("a missing fragment");
    assert!(matches!(error, Error::Body { .. }), "{error:?}");
    assert!(
        error.to_string().contains("modules/build.toml:2"),
        "{error}"
    );
}

#[test]
fn a_hand_laid_out_shared_body_s_part_shows_only_what_the_overlay_adds() {
    let home = guarded_home();
    let compact = "{\"permissions\": {\"allow\": [\"Bash(ls)\"]}, \"hooks\": {}}";
    repo(&home, compact);
    let report = plan(&on(&home, "build1"));
    match report.changes[0].diff.as_ref().map(|diff| &diff.kind) {
        Some(DiffKind::Texts(texts)) => {
            let removed: Vec<&str> = texts[1]
                .lines()
                .filter(|line| line.starts_with('-') && !line.starts_with("---"))
                .collect();
            // Only the object the hook goes into opens up; no shared line
            // is shown changing because of how it was laid out.
            assert_eq!(removed, vec!["-  \"hooks\": {}"], "{}", texts[1]);
            assert!(
                texts[1].contains("+    \"SubagentStop\": ["),
                "{}",
                texts[1]
            );
        }
        other => panic!("two diffs, found {other:?}"),
    }

    // Once applied, the row is unchanged and says nothing of how it was made.
    apply(&on(&home, "build1"));
    let again = plan(&on(&home, "build1"));
    assert_eq!(again.actions(), vec![Action::Unchanged]);
    assert_eq!(again.changes[0].note, None);
}

#[test]
fn taking_the_overlay_away_gives_the_shared_body_back_and_rm_restores_the_prior() {
    let home = guarded_home();
    home.write(".claude/settings.json", "{\"mine\": true}\n");
    let before = snapshot(home.path(), &[".config", ".local"]);
    repo(&home, SHARED);
    // The file was the user's. bx takes it over the way an answer of *take*
    // would, keeping the user's bytes as the prior `rm` restores.
    own(
        home.path(),
        ".claude/settings.json",
        b"{\"mine\": true}\n",
        Mechanism::Own,
    );
    apply(&on(&home, "build1"));
    assert_eq!(json(&settings(&home)), hooked(SHARED));

    std::fs::remove_file(home.child(".config/bx/modules/build.toml")).expect("undeclare");
    let report = plan(&on(&home, "build1"));
    assert_eq!(report.actions(), vec![Action::Modify]);
    apply(&on(&home, "build1"));
    assert_eq!(
        settings(&home),
        SHARED.as_bytes(),
        "the shared body, byte for byte"
    );
    assert_eq!(
        plan(&on(&home, "build1")).actions(),
        vec![Action::Unchanged]
    );

    let state = StateDir::resolve(home.path());
    let targets = ledger_targets(&state, home.path());
    crate::restore::restore(&state, home.path(), &targets).expect("restore");
    assert_eq!(snapshot(home.path(), &[".config", ".local"]), before);
}

#[test]
fn a_key_both_set_differently_blocks_the_target_naming_the_key() {
    let home = guarded_home();
    repo(&home, "{\"model\": \"opus\"}\n");
    home.write(
        ".config/bx/files/subagent-stop.json",
        "{\"model\": \"haiku\"}",
    );
    let report = plan(&on(&home, "build1"));
    assert_eq!(report.actions(), vec![Action::Blocked]);
    let note = report.changes[0].note.as_deref().unwrap_or_default();
    assert!(note.contains("`model`"), "{note}");
    assert!(note.contains("subagent-stop"), "{note}");
    apply(&on(&home, "build1"));
    assert!(
        !home.child(".claude/settings.json").exists(),
        "nothing written"
    );

    // Agreeing on a value is not a clash.
    home.write(
        ".config/bx/files/subagent-stop.json",
        "{\"model\": \"opus\"}",
    );
    assert_eq!(plan(&on(&home, "build1")).actions(), vec![Action::Create]);
}

#[test]
fn an_element_the_shared_array_already_holds_is_not_added_twice() {
    let home = guarded_home();
    repo(&home, SHARED);
    home.write(
        ".config/bx/files/subagent-stop.json",
        r#"{"permissions": {"allow": ["Bash(ls)", "Bash(git status)"]}}"#,
    );
    apply(&on(&home, "build1"));
    let allow = &json(&settings(&home))["permissions"]["allow"];
    assert_eq!(allow, &json(br#"["Bash(ls)", "Bash(git status)"]"#));
}

#[test]
fn a_toml_target_keeps_the_shared_body_s_comments_and_gains_the_overlay() {
    let shared = "# shared settings\n[editor]\ntheme = \"dark\" # everyone\n";
    let home = guarded_home();
    seed(
        home.path(),
        "[[target]]\npath = \"~/.config/tool/config.toml\"\nfile = \"files/tool.toml\"\n\
         [[overlay]]\nname = \"font\"\npath = \"~/.config/tool/config.toml\"\n\
         content = \"[editor]\\nfont = \\\"mono\\\"\\n[[plugins]]\\nname = \\\"x\\\"\\n\"\n",
    );
    home.write(".config/bx/files/tool.toml", shared);
    apply(&load(home.path()));
    let written = std::fs::read_to_string(home.child(".config/tool/config.toml")).expect("written");
    assert!(
        written.starts_with("# shared settings\n[editor]\ntheme = \"dark\" # everyone\n"),
        "{written}"
    );
    let doc: toml_edit::DocumentMut = written.parse().expect("TOML");
    assert_eq!(doc["editor"]["font"].as_str(), Some("mono"));
    assert_eq!(
        doc["plugins"]
            .as_array_of_tables()
            .map(toml_edit::ArrayOfTables::len),
        Some(1)
    );
    assert_eq!(plan(&load(home.path())).actions(), vec![Action::Unchanged]);
}
