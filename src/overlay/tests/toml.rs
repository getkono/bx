//! TOML merge and strip, and what each keeps of the formatting.

use super::frag;
use crate::overlay::{Error, Fragment, Syntax, merge, same, strip};

/// `merge` for TOML over strings, panicking on an error.
fn toml_merge(shared: &str, overlays: &[Fragment<'_>]) -> String {
    String::from_utf8(merge(Syntax::Toml, shared.as_bytes(), overlays).unwrap()).unwrap()
}

/// `strip` for TOML over strings.
fn toml_strip(disk: &str, shared: &str, overlays: &[Fragment<'_>]) -> Result<String, Error> {
    strip(Syntax::Toml, disk.as_bytes(), shared.as_bytes(), overlays)
        .map(|bytes| String::from_utf8(bytes).unwrap())
}

/// Whether two TOML texts hold the same data.
fn toml_same(a: &str, b: &str) -> bool {
    same(Syntax::Toml, a.as_bytes(), b.as_bytes()).unwrap()
}

/// The error `merge` returns for TOML.
fn toml_merge_err(shared: &str, overlays: &[Fragment<'_>]) -> Error {
    merge(Syntax::Toml, shared.as_bytes(), overlays).unwrap_err()
}

/// A shared body with comments and formatting of its own.
const SHARED: &str = "\
# The team's settings.
top   =   \"kept\"   # spacing and all

[editor]
# How wide.
width = 100
tabs = [ \"a\",\"b\" ]

[[servers]]
name = \"one\"   # first

[tail]
x = 1
";

#[test]
fn merge_keeps_every_byte_of_the_shared_body_outside_the_insertions() {
    let overlay = "\
extra = true

[editor]
theme = \"dark\"
tabs = [\"b\", \"c\"]

[[servers]]
name = \"two\"

[machine]
cores = 8
";
    let out = toml_merge(SHARED, &[frag("laptop", overlay)]);
    let expected = "\
# The team's settings.
top   =   \"kept\"   # spacing and all
extra = true

[editor]
# How wide.
width = 100
tabs = [ \"a\",\"b\",\"c\" ]
theme = \"dark\"

[[servers]]
name = \"one\"   # first

[[servers]]
name = \"two\"

[tail]
x = 1

[machine]
cores = 8
";
    assert_eq!(out, expected);
    let back = toml_strip(&out, SHARED, &[frag("laptop", overlay)]).unwrap();
    assert_eq!(back, SHARED);
}

#[test]
fn merge_is_deterministic_and_idempotent() {
    let overlays = [frag(
        "a",
        "[editor]\nfont = \"mono\"\n[[servers]]\nname = \"two\"\n",
    )];
    let once = toml_merge(SHARED, &overlays);
    assert_eq!(once, toml_merge(SHARED, &overlays));
    let twice = toml_merge(&once, &overlays);
    assert_eq!(twice, once);
}

#[test]
fn arrays_of_tables_append_and_skip_tables_already_present() {
    let shared = "[[x]]\na = 1\n\n[[x]]\na = 2\n";
    let overlay = "[[x]]\na = 2\n\n[[x]]\na = 3\nsub = { k = 1 }\n";
    let out = toml_merge(shared, &[frag("o", overlay)]);
    assert_eq!(
        out,
        "[[x]]\na = 1\n\n[[x]]\na = 2\n\n[[x]]\na = 3\nsub = { k = 1 }\n"
    );
    assert!(toml_same(
        &out,
        "x = [{a = 1}, {a = 2}, {a = 3, sub = {k = 1}}]"
    ));
    let back = toml_strip(&out, shared, &[frag("o", overlay)]).unwrap();
    assert_eq!(back, shared);
}

#[test]
fn an_array_of_tables_in_the_overlay_appends_to_an_array_as_inline_tables() {
    let shared = "x = [{ a = 1 }]\n";
    let out = toml_merge(shared, &[frag("o", "[[x]]\na = 1\n\n[[x]]\na = 2\n")]);
    assert_eq!(out, "x = [{ a = 1 }, { a = 2 }]\n");
}

#[test]
fn inline_tables_in_the_overlay_append_to_an_array_of_tables() {
    let shared = "[[x]]\na = 1\n";
    let out = toml_merge(shared, &[frag("o", "x = [{a = 1}, {a = 2}]\n")]);
    assert!(toml_same(&out, "x = [{a = 1}, {a = 2}]"), "{out}");
    assert!(out.starts_with("[[x]]\na = 1\n"), "{out}");
    assert_eq!(out.matches("[[x]]").count(), 2, "{out}");
}

#[test]
fn a_non_table_element_cannot_join_an_array_of_tables() {
    let err = toml_merge_err("[[x]]\na = 1\n", &[frag("o", "x = [{a = 1}, 5]\n")]);
    assert_eq!(
        err.to_string(),
        "overlay `o` sets `x[1]` to 5, where the file already has [{ a = 1 }]"
    );
}

#[test]
fn a_standard_table_merges_into_an_inline_table() {
    let shared = "server = { host = \"h\" }\n";
    let overlay = "[server]\nport = 22\n\n[server.tls]\non = true\n";
    let out = toml_merge(shared, &[frag("o", overlay)]);
    assert_eq!(
        out,
        "server = { host = \"h\", port = 22, tls = { on = true } }\n"
    );
    let back = toml_strip(&out, shared, &[frag("o", overlay)]).unwrap();
    assert_eq!(back, shared);
}

#[test]
fn an_inline_table_merges_into_a_standard_table() {
    let shared = "[server]\nhost = \"h\"\n";
    let out = toml_merge(
        shared,
        &[frag("o", "server = {port = 22,   user = \"me\"}\n")],
    );
    assert_eq!(out, "[server]\nhost = \"h\"\nport = 22\nuser = \"me\"\n");
}

#[test]
fn a_new_key_in_an_array_keeps_the_arrays_layout() {
    let shared = "list = [\n  \"a\",\n  \"b\",\n]\nempty = []\n";
    let out = toml_merge(shared, &[frag("o", "list = [\"c\"]\nempty = [   1,2 ]\n")]);
    assert_eq!(
        out,
        "list = [\n  \"a\",\n  \"b\",\n  \"c\",\n]\nempty = [1, 2]\n"
    );
    let back = toml_strip(
        &out,
        shared,
        &[frag("o", "list = [\"c\"]\nempty = [1, 2]\n")],
    )
    .unwrap();
    assert_eq!(back, shared);
}

#[test]
fn a_different_scalar_is_a_clash() {
    let err = toml_merge_err("[hooks]\nfoo = 1\n", &[frag("X", "hooks.foo = 2\n")]);
    assert_eq!(
        err,
        Error::Clash {
            overlay: "X".to_owned(),
            key: "hooks.foo".to_owned(),
            shared: "1".to_owned(),
            overlay_value: "2".to_owned(),
        }
    );
    let err = toml_merge_err("a = 'x'\n", &[frag("o", "a = \"y\"\n")]);
    assert_eq!(
        err.to_string(),
        "overlay `o` sets `a` to \"y\", where the file already has \"x\""
    );
    let err = toml_merge_err("a = 1\n", &[frag("o", "a = 1.0\n")]);
    assert!(matches!(err, Error::Clash { .. }));
}

#[test]
fn a_type_mismatch_is_a_clash() {
    let err = toml_merge_err("[a]\nb = 1\n", &[frag("o", "a = [1]\n")]);
    assert_eq!(
        err.to_string(),
        "overlay `o` sets `a` to [1], where the file already has { b = 1 }"
    );
    let err = toml_merge_err("a = 1\n", &[frag("o", "[[a]]\nb = 1\n")]);
    assert!(matches!(err, Error::Clash { key, .. } if key == "a"));
}

#[test]
fn a_clash_between_overlays_names_the_later_one() {
    let err = toml_merge_err(
        "",
        &[
            frag("one", "[a]\nb = true\n"),
            frag("two", "a = { b = false }\n"),
        ],
    );
    assert_eq!(
        err.to_string(),
        "overlay `two` sets `a.b` to false, where the file already has true"
    );
}

#[test]
fn strip_keeps_what_the_tool_added_and_its_formatting() {
    let shared = "# shared\n[a]\nx = 1\n";
    let overlays = [frag("o", "[a]\ny = 2\n\n[env]\nFOO = \"1\"\n")];
    let merged = toml_merge(shared, &overlays);
    assert_eq!(
        merged,
        "# shared\n[a]\nx = 1\ny = 2\n\n[env]\nFOO = \"1\"\n"
    );
    let disk = "# shared\n[a]\nx = 1\ny = 2\nz   =   3 # tool\n\n[env]\nFOO = \"1\"\nBAR = \"2\"\n";
    let back = toml_strip(disk, shared, &overlays).unwrap();
    assert_eq!(
        back,
        "# shared\n[a]\nx = 1\nz   =   3 # tool\n\n[env]\nBAR = \"2\"\n"
    );
}

#[test]
fn strip_refuses_a_missing_element_and_a_changed_value_but_not_a_removed_key() {
    let shared = "[a]\nx = 1\n";
    let overlays = [frag("X", "[a]\ny = 2\n\n[[hooks]]\nrun = \"go\"\n")];
    let back = toml_strip("[a]\nx = 1\n", shared, &overlays).unwrap();
    assert_eq!(back, shared);
    let err = toml_strip("hooks = []\n[a]\nx = 1\ny = 2\n", shared, &overlays).unwrap_err();
    assert!(
        matches!(err, Error::Missing { ref key, .. } if key == "hooks"),
        "{err}"
    );
    let err = toml_strip("[a]\nx = 1\ny = 3\n", shared, &overlays).unwrap_err();
    assert_eq!(
        err.to_string(),
        "`a.y` comes from overlay `X` and was changed in this file; \
         change it in the overlay instead"
    );
}

#[test]
fn strip_keeps_content_the_shared_body_also_has() {
    let shared = "a = 1\nl = [1, 2]\n\n[[t]]\nk = true\n";
    let overlays = [frag("o", "a = 1\nl = [2, 3]\nb = 2\n\n[[t]]\nk = true\n")];
    let merged = toml_merge(shared, &overlays);
    assert!(
        toml_same(&merged, "a = 1\nl = [1, 2, 3]\nb = 2\nt = [{k = true}]"),
        "{merged}"
    );
    assert_eq!(toml_strip(&merged, shared, &overlays).unwrap(), shared);
}

#[test]
fn strip_removing_the_first_element_keeps_the_array_tidy() {
    let shared = "l = [2]\n";
    let overlays = [frag("o", "l = [1]\n")];
    let back = toml_strip("l = [1, 2]\n", shared, &overlays).unwrap();
    assert_eq!(back, "l = [2]\n");
}

#[test]
fn same_ignores_the_form_a_table_or_array_is_written_in() {
    assert!(toml_same(
        "[a]\nb = 1\n[[c]]\nd = 2\n",
        "c = [ { d = 2 } ]\na.b = 1\n"
    ));
    assert!(!toml_same("a = 1\n", "a = 2\n"));
    assert!(!toml_same("a = [1, 2]\n", "a = [2, 1]\n"));
}

#[test]
fn a_table_from_an_overlay_prints_under_the_table_it_joins() {
    // In the overlay each joins `a` after `z`; in the result each follows
    // `a`, where it now belongs, and before `b`.
    let shared = "[a]\nx = 1\n\n[b]\ny = 2\n";
    let tables = "[z]\nk = 1\n\n[a.sub]\nm = 2\n\n[a.sub.deep]\nn = 3\n";
    assert_eq!(
        toml_merge(shared, &[frag("o", tables)]),
        "[a]\nx = 1\n\n[a.sub]\nm = 2\n\n[a.sub.deep]\nn = 3\n\n[b]\ny = 2\n[z]\nk = 1\n"
    );
    let array = "[z]\nk = 1\n\n[[a.list]]\nm = 2\n";
    assert_eq!(
        toml_merge(shared, &[frag("o", array)]),
        "[a]\nx = 1\n\n[[a.list]]\nm = 2\n\n[b]\ny = 2\n[z]\nk = 1\n"
    );
}

#[test]
fn a_new_key_keeps_the_form_the_overlay_wrote_it_in() {
    let out = toml_merge(
        "[a]\nx = 1\n",
        &[frag("o", "[a]\n\"quoted key\"   =   1\n'lit'=2\n")],
    );
    assert_eq!(out, "[a]\nx = 1\n\"quoted key\"   =   1\n'lit'=2\n");
}

#[test]
fn an_element_joining_a_lone_one_on_its_own_line_goes_on_its_own_line() {
    let out = toml_merge("list = [\n  \"a\",\n]\n", &[frag("o", "list = [\"b\"]\n")]);
    assert_eq!(out, "list = [\n  \"a\",\n  \"b\",\n]\n");
}

#[test]
fn an_appended_element_keeps_the_space_written_before_each_comma() {
    let out = toml_merge("list = [\"a\" , \"b\"]\n", &[frag("o", "list = [\"c\"]\n")]);
    assert_eq!(out, "list = [\"a\" , \"b\" , \"c\"]\n");
}
