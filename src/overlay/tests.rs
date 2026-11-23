//! The overlay module's tests: the shared surface and JSON here, TOML and the
//! properties in their own files.

mod props;
mod toml;

use std::path::Path;

use super::*;

/// One overlay named `name` holding `bytes`.
fn frag<'a>(name: &'a str, bytes: &'a str) -> Fragment<'a> {
    Fragment {
        name,
        bytes: bytes.as_bytes(),
    }
}

/// `merge` for JSON over strings, panicking on an error.
fn json_merge(shared: &str, overlays: &[Fragment<'_>]) -> String {
    String::from_utf8(merge(Syntax::Json, shared.as_bytes(), overlays).unwrap()).unwrap()
}

/// `strip` for JSON over strings.
fn json_strip(disk: &str, shared: &str, overlays: &[Fragment<'_>]) -> Result<String, Error> {
    strip(Syntax::Json, disk.as_bytes(), shared.as_bytes(), overlays)
        .map(|bytes| String::from_utf8(bytes).unwrap())
}

/// Whether two JSON texts hold the same data.
fn json_same(a: &str, b: &str) -> bool {
    same(Syntax::Json, a.as_bytes(), b.as_bytes()).unwrap()
}

/// The error `merge` returns for JSON.
fn json_merge_err(shared: &str, overlays: &[Fragment<'_>]) -> Error {
    merge(Syntax::Json, shared.as_bytes(), overlays).unwrap_err()
}

#[test]
fn syntax_comes_from_the_exact_lowercase_extension() {
    assert_eq!(Syntax::of(Path::new("a/settings.json")), Some(Syntax::Json));
    assert_eq!(Syntax::of(Path::new("config.toml")), Some(Syntax::Toml));
    assert_eq!(Syntax::of(Path::new("a.JSON")), None);
    assert_eq!(Syntax::of(Path::new("a.Toml")), None);
    assert_eq!(Syntax::of(Path::new("a.yaml")), None);
    assert_eq!(Syntax::of(Path::new("json")), None);
    assert_eq!(Syntax::of(Path::new(".json")), None);
    assert_eq!(Syntax::Json.name(), "JSON");
    assert_eq!(Syntax::Toml.name(), "TOML");
}

#[test]
fn check_accepts_an_object_and_refuses_anything_else() {
    assert_eq!(check(Syntax::Json, b"{\"a\": 1}"), Ok(()));
    assert_eq!(check(Syntax::Toml, b"a = 1\n[b]\nc = 2\n"), Ok(()));
    assert_eq!(
        check(Syntax::Json, b"[1, 2]"),
        Err(Error::NotATable {
            what: Part::Document,
            syntax: Syntax::Json,
        })
    );
    assert_eq!(
        check(Syntax::Json, b"[1]").unwrap_err().to_string(),
        "the top level of the document is not a JSON object, and overlays merge key by key"
    );
    let Err(Error::Parse {
        what,
        syntax,
        message,
    }) = check(Syntax::Json, b"{\"a\": }")
    else {
        panic!("a broken document parses");
    };
    assert_eq!((what, syntax), (Part::Document, Syntax::Json));
    assert!(message.contains("line 1"), "{message}");
    let Err(Error::Parse { syntax, .. }) = check(Syntax::Toml, b"a = = 1") else {
        panic!("a broken document parses");
    };
    assert_eq!(syntax, Syntax::Toml);
    assert!(matches!(
        check(Syntax::Toml, b"a = \"\xff\""),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn parse_errors_name_the_document() {
    let err = json_merge_err("{}", &[frag("work", "{")]);
    assert!(matches!(&err, Error::Parse { what: Part::Overlay(name), .. } if name == "work"));
    assert!(
        err.to_string()
            .starts_with("overlay `work` is not valid JSON: "),
        "{err}"
    );
    let err = json_merge_err("nope", &[frag("work", "{}")]);
    assert!(
        err.to_string()
            .starts_with("the shared body is not valid JSON: "),
        "{err}"
    );
    let err = json_strip("[]", "{}", &[frag("work", "{}")]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "the top level of the file on disk is not a JSON object, and overlays merge key by key"
    );
    let err = same(Syntax::Json, b"{}", b"1").unwrap_err();
    assert!(matches!(
        err,
        Error::NotATable {
            what: Part::Second,
            ..
        }
    ));
}

#[test]
fn no_overlays_returns_the_bytes_verbatim_without_parsing() {
    for syntax in [Syntax::Json, Syntax::Toml] {
        let junk = b"not { valid = at all\xff";
        assert_eq!(merge(syntax, junk, &[]).unwrap(), junk);
        assert_eq!(strip(syntax, junk, b"also junk", &[]).unwrap(), junk);
    }
}

#[test]
fn objects_merge_key_by_key_with_new_keys_after_existing_ones() {
    let out = json_merge(
        r#"{"b": 1, "a": {"x": 1}}"#,
        &[frag("o", r#"{"z": true, "a": {"y": 2}, "c": null}"#)],
    );
    assert_eq!(
        out,
        "{\n  \"b\": 1,\n  \"a\": {\n    \"x\": 1,\n    \"y\": 2\n  },\n  \"z\": true,\n  \"c\": null\n}\n"
    );
}

#[test]
fn numbers_keep_their_text() {
    let out = json_merge(
        r#"{"a": 1.50}"#,
        &[frag("o", r#"{"b": 12345678901234567890123}"#)],
    );
    assert_eq!(
        out,
        "{\n  \"a\": 1.50,\n  \"b\": 12345678901234567890123\n}\n"
    );
}

#[test]
fn arrays_append_and_skip_elements_already_present() {
    let out = json_merge(
        r#"{"a": [1, {"k": [2, 3]}]}"#,
        &[frag("o", r#"{"a": [{"k": [2,3]}, 4, 1, 5]}"#)],
    );
    assert!(
        json_same(&out, r#"{"a": [1, {"k": [2, 3]}, 4, 5]}"#),
        "{out}"
    );
}

#[test]
fn an_equal_scalar_merges_to_itself() {
    let out = json_merge(r#"{"a": {"b": "x"}}"#, &[frag("o", r#"{"a": {"b": "x"}}"#)]);
    assert!(json_same(&out, r#"{"a": {"b": "x"}}"#));
}

#[test]
fn a_different_scalar_is_a_clash_naming_the_path() {
    let err = json_merge_err(
        r#"{"hooks": {"foo": 1}}"#,
        &[frag("X", r#"{"hooks": {"foo": 2}}"#)],
    );
    assert_eq!(
        err,
        Error::Clash {
            overlay: "X".to_owned(),
            key: "hooks.foo".to_owned(),
            shared: "1".to_owned(),
            overlay_value: "2".to_owned(),
        }
    );
    assert_eq!(
        err.to_string(),
        "overlay `X` sets `hooks.foo` to 2, where the file already has 1"
    );
}

#[test]
fn a_type_mismatch_is_a_clash() {
    let err = json_merge_err(r#"{"a": {"b": 1}}"#, &[frag("o", r#"{"a": [1]}"#)]);
    assert_eq!(
        err.to_string(),
        "overlay `o` sets `a` to [1], where the file already has {\"b\":1}"
    );
    let err = json_merge_err(r#"{"a": "s"}"#, &[frag("o", r#"{"a": {"b": 1}}"#)]);
    assert!(matches!(err, Error::Clash { key, .. } if key == "a"));
    let err = json_merge_err(r#"{"a": [1]}"#, &[frag("o", r#"{"a": 1}"#)]);
    assert!(matches!(err, Error::Clash { key, .. } if key == "a"));
}

#[test]
fn a_clash_between_overlays_names_the_later_one() {
    let err = json_merge_err(
        "{}",
        &[
            frag("first", r#"{"a": {"b": 1}}"#),
            frag("second", r#"{"a": {"b": 2}}"#),
        ],
    );
    assert_eq!(
        err.to_string(),
        "overlay `second` sets `a.b` to 2, where the file already has 1"
    );
}

#[test]
fn clash_paths_quote_keys_that_are_not_bare_and_long_values_are_cut() {
    let long = "x".repeat(100);
    let err = json_merge_err(
        r#"{"a.b": {"c d": "short"}}"#,
        &[frag("o", &format!(r#"{{"a.b": {{"c d": "{long}"}}}}"#))],
    );
    let Error::Clash {
        key,
        shared,
        overlay_value,
        ..
    } = err
    else {
        panic!("no clash");
    };
    assert_eq!(key, r#""a.b"."c d""#);
    assert_eq!(shared, "\"short\"");
    assert_eq!(overlay_value.chars().count(), RENDER_LIMIT);
    assert!(overlay_value.ends_with('…'));
    assert_eq!(
        overlay_value,
        format!("\"{}…", "x".repeat(RENDER_LIMIT - 2))
    );
}

#[test]
fn key_paths_write_an_array_index_in_brackets() {
    let mut path = KeyPath::default();
    path.with_key("hooks", |path| {
        let indexed = path.index(2);
        let mut indexed = indexed.clone();
        indexed.with_key("matcher", |p| assert_eq!(p.to_string(), "hooks[2].matcher"));
        assert_eq!(indexed.to_string(), "hooks[2]");
    });
    assert_eq!(path.to_string(), "");
    path.with_key("", |p| assert_eq!(p.to_string(), "\"\""));
    path.with_key("a\"\\\n", |p| assert_eq!(p.to_string(), r#""a\"\\\u{a}""#));
}

#[test]
fn key_paths_write_underscores_and_hyphens_bare() {
    let mut path = KeyPath::default();
    for key in ["snake_case", "kebab-case", "_", "-"] {
        path.with_key(key, |p| assert_eq!(p.to_string(), key));
    }
}

/// A Claude Code settings file a team shares.
const CLAUDE_SHARED: &str = r#"{
  "permissions": {
    "allow": ["Bash(git status)", "Read(~/src/**)"],
    "deny": ["Read(./.env)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "~/bin/check-bash"}]
      }
    ]
  }
}
"#;

/// One machine's overlay: a hook only it runs.
const CLAUDE_OVERLAY: &str = r#"{"hooks": {"SubagentStop": [{"hooks": [{"type": "command", "command": "~/bin/on-subagent-stop"}]}]}}"#;

#[test]
fn a_claude_settings_overlay_adds_a_hook_event() {
    let out = json_merge(CLAUDE_SHARED, &[frag("laptop", CLAUDE_OVERLAY)]);
    let expected = r#"{
  "permissions": {
    "allow": [
      "Bash(git status)",
      "Read(~/src/**)"
    ],
    "deny": [
      "Read(./.env)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/bin/check-bash"
          }
        ]
      }
    ],
    "SubagentStop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "~/bin/on-subagent-stop"
          }
        ]
      }
    ]
  }
}
"#;
    assert_eq!(out, expected);
    let back = json_strip(&out, CLAUDE_SHARED, &[frag("laptop", CLAUDE_OVERLAY)]).unwrap();
    assert!(json_same(&back, CLAUDE_SHARED), "{back}");
}

#[test]
fn a_claude_settings_overlay_adds_hooks_to_a_body_without_any() {
    let shared = r#"{"permissions": {"allow": ["Bash(ls)"]}}"#;
    let out = json_merge(shared, &[frag("laptop", CLAUDE_OVERLAY)]);
    let expected = r#"{
        "permissions": {"allow": ["Bash(ls)"]},
        "hooks": {"SubagentStop": [{"hooks": [{"type": "command", "command": "~/bin/on-subagent-stop"}]}]}
    }"#;
    assert!(json_same(&out, expected), "{out}");
    let back = json_strip(&out, shared, &[frag("laptop", CLAUDE_OVERLAY)]).unwrap();
    assert_eq!(
        back,
        "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(ls)\"\n    ]\n  }\n}\n"
    );
}

#[test]
fn strip_keeps_a_shared_key_the_tool_added() {
    let overlays = [frag("laptop", CLAUDE_OVERLAY)];
    let mut disk: serde_json::Value =
        serde_json::from_str(&json_merge(CLAUDE_SHARED, &overlays)).unwrap();
    disk["model"] = serde_json::json!("opus");
    disk["permissions"]["allow"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("Bash(ls)"));
    let back = json_strip(&disk.to_string(), CLAUDE_SHARED, &overlays).unwrap();
    let mut expected: serde_json::Value = serde_json::from_str(CLAUDE_SHARED).unwrap();
    expected["model"] = serde_json::json!("opus");
    expected["permissions"]["allow"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("Bash(ls)"));
    assert!(json_same(&back, &expected.to_string()), "{back}");
}

#[test]
fn strip_keeps_what_the_tool_added_inside_an_object_the_overlay_introduced() {
    let shared = r#"{"a": 1}"#;
    let overlays = [frag("o", r#"{"env": {"FOO": "1"}}"#)];
    let disk = r#"{"a": 1, "env": {"FOO": "1", "BAR": "2"}}"#;
    let back = json_strip(disk, shared, &overlays).unwrap();
    assert!(
        json_same(&back, r#"{"a": 1, "env": {"BAR": "2"}}"#),
        "{back}"
    );
}

#[test]
fn strip_refuses_an_overlay_element_no_longer_there_but_not_a_removed_container() {
    let overlays = [frag("laptop", CLAUDE_OVERLAY)];
    // Changed and removed leave the same file: neither is guessed at.
    let disk = r#"{"permissions": {}, "hooks": {"SubagentStop": [], "PreToolUse": []}}"#;
    assert_eq!(
        json_strip(disk, CLAUDE_SHARED, &overlays).unwrap_err(),
        Error::Missing {
            overlay: "laptop".to_owned(),
            key: "hooks.SubagentStop".to_owned(),
        }
    );
    // A container the overlay introduced, gone whole, holds nothing to leak.
    let back = json_strip(r#"{"x": 1}"#, CLAUDE_SHARED, &overlays).unwrap();
    assert!(json_same(&back, r#"{"x": 1}"#), "{back}");
}

#[test]
fn strip_refuses_an_overlay_scalar_the_tool_changed() {
    let overlays = [frag("X", r#"{"hooks": {"foo": 1}}"#)];
    let err = json_strip(r#"{"hooks": {"foo": 2}}"#, r#"{"hooks": {}}"#, &overlays).unwrap_err();
    assert_eq!(
        err,
        Error::Changed {
            overlay: "X".to_owned(),
            key: "hooks.foo".to_owned(),
        }
    );
    assert_eq!(
        err.to_string(),
        "`hooks.foo` comes from overlay `X` and was changed in this file; \
         change it in the overlay instead"
    );
    let err = json_strip(r#"{"hooks": {"foo": {"a": 1}}}"#, "{}", &overlays).unwrap_err();
    assert!(matches!(err, Error::Changed { key, .. } if key == "hooks.foo"));
}

#[test]
fn strip_keeps_content_the_shared_body_also_has() {
    let shared = r#"{"a": 1, "list": [1, 2], "o": {"k": true}}"#;
    let overlays = [frag(
        "o",
        r#"{"a": 1, "list": [2, 3], "o": {"k": true}, "b": 2}"#,
    )];
    let merged = json_merge(shared, &overlays);
    assert!(json_same(
        &merged,
        r#"{"a": 1, "list": [1, 2, 3], "o": {"k": true}, "b": 2}"#
    ));
    let back = json_strip(&merged, shared, &overlays).unwrap();
    assert!(json_same(&back, shared), "{back}");
}

#[test]
fn strip_takes_the_last_equal_element() {
    let shared = r#"{"a": [{"x": 1}]}"#;
    let overlays = [frag("o", r#"{"a": [{"y": 1}]}"#)];
    let disk = r#"{"a": [{"y": 1}, {"x": 1}, {"y": 1}, {"z": 1}]}"#;
    let back = json_strip(disk, shared, &overlays).unwrap();
    assert_eq!(
        back,
        "{\n  \"a\": [\n    {\n      \"y\": 1\n    },\n    {\n      \"x\": 1\n    },\n    {\n      \"z\": 1\n    }\n  ]\n}\n"
    );
}

#[test]
fn strip_undoes_overlays_last_first() {
    let shared = r#"{"a": 1}"#;
    let overlays = [
        frag("one", r#"{"o": {"x": 1}, "l": [1]}"#),
        frag("two", r#"{"o": {"y": 2}, "l": [2]}"#),
    ];
    let merged = json_merge(shared, &overlays);
    assert!(json_same(
        &merged,
        r#"{"a": 1, "o": {"x": 1, "y": 2}, "l": [1, 2]}"#
    ));
    let back = json_strip(&merged, shared, &overlays).unwrap();
    assert_eq!(back, "{\n  \"a\": 1\n}\n");
    let err = json_strip(r#"{"o": {"x": 1, "y": 3}}"#, shared, &overlays).unwrap_err();
    assert!(matches!(err, Error::Changed { overlay, key } if overlay == "two" && key == "o.y"));
}

#[test]
fn strip_ignores_a_container_the_tool_replaced() {
    let shared = r#"{"o": {"a": 1}, "l": [1]}"#;
    let overlays = [frag("x", r#"{"o": {"b": 2}, "l": [2]}"#)];
    let back = json_strip(r#"{"o": 5, "l": "gone"}"#, shared, &overlays).unwrap();
    assert!(json_same(&back, r#"{"o": 5, "l": "gone"}"#), "{back}");
}

#[test]
fn same_ignores_formatting_and_key_order() {
    assert!(json_same(
        r#"{"a": 1, "b": [1, {"c": 2, "d": 3}]}"#,
        "{\"b\":[1,{\"d\":3,\"c\":2}],\"a\":1}"
    ));
    assert!(!json_same(r#"{"a": [1, 2]}"#, r#"{"a": [2, 1]}"#));
    assert!(!json_same(r#"{"a": 1}"#, r#"{"a": 1.0}"#));
}

#[test]
fn merge_is_deterministic() {
    let overlays = [
        frag("laptop", CLAUDE_OVERLAY),
        frag("x", r#"{"z": [1, 2]}"#),
    ];
    let first = merge(Syntax::Json, CLAUDE_SHARED.as_bytes(), &overlays).unwrap();
    let second = merge(Syntax::Json, CLAUDE_SHARED.as_bytes(), &overlays).unwrap();
    assert_eq!(first, second);
}
