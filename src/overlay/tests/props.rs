//! Properties of merge and strip over small generated documents, in both
//! syntaxes.

use std::collections::BTreeMap;

use proptest::prelude::*;
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use crate::overlay::{Fragment, Syntax, merge, same, strip};

/// A generated document node, written out as JSON or TOML.
#[derive(Debug, Clone)]
enum Node {
    /// An integer.
    Int(i64),
    /// A boolean.
    Bool(bool),
    /// A string.
    Str(String),
    /// An array; `true` writes an all-table array as an array of tables in
    /// TOML.
    Array(Vec<Node>, bool),
    /// An object; `true` writes it as an inline table in TOML.
    Object(BTreeMap<String, Node>, bool),
}

/// A small generated tree, three levels deep at most, over few keys and values
/// so that documents overlap and sometimes clash.
fn node() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![
        (0i64..3).prop_map(Node::Int),
        any::<bool>().prop_map(Node::Bool),
        prop::sample::select(vec!["x", "y"]).prop_map(|s| Node::Str(s.to_owned())),
    ];
    leaf.prop_recursive(3, 24, 3, |inner| {
        prop_oneof![
            (prop::collection::vec(inner.clone(), 0..3), any::<bool>())
                .prop_map(|(v, aot)| Node::Array(v, aot)),
            (object(inner), any::<bool>()).prop_map(|(o, inline)| Node::Object(o, inline)),
        ]
    })
}

/// An object over the keys `a`, `b` and `c`, with values from `inner`.
fn object(inner: impl Strategy<Value = Node>) -> impl Strategy<Value = BTreeMap<String, Node>> {
    prop::collection::btree_map(
        prop::sample::select(vec!["a", "b", "c"]).prop_map(str::to_owned),
        inner,
        0..3,
    )
}

/// A top-level document.
fn document() -> impl Strategy<Value = BTreeMap<String, Node>> {
    object(node())
}

/// `node` as a JSON value.
fn to_json(node: &Node) -> serde_json::Value {
    match node {
        Node::Int(i) => (*i).into(),
        Node::Bool(b) => (*b).into(),
        Node::Str(s) => s.clone().into(),
        Node::Array(items, _) => items.iter().map(to_json).collect(),
        Node::Object(map, _) => {
            serde_json::Value::Object(map.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
    }
}

/// `doc` written as JSON.
fn json_text(doc: &BTreeMap<String, Node>) -> String {
    to_json(&Node::Object(doc.clone(), false)).to_string()
}

/// `node` as a TOML value, for a place only a value can go.
fn to_toml_value(node: &Node) -> Value {
    match node {
        Node::Int(i) => (*i).into(),
        Node::Bool(b) => (*b).into(),
        Node::Str(s) => s.as_str().into(),
        Node::Array(items, _) => Value::Array(items.iter().map(to_toml_value).collect::<Array>()),
        Node::Object(map, _) => Value::InlineTable(
            map.iter()
                .map(|(k, v)| (k.clone(), to_toml_value(v)))
                .collect::<InlineTable>(),
        ),
    }
}

/// `node` as a TOML item in a standard table, in the form it asks for.
fn to_toml_item(node: &Node) -> Item {
    match node {
        Node::Object(map, false) => Item::Table(to_toml_table(map)),
        Node::Array(items, true)
            if !items.is_empty() && items.iter().all(|i| matches!(i, Node::Object(..))) =>
        {
            let mut tables = ArrayOfTables::new();
            for item in items {
                if let Node::Object(map, _) = item {
                    tables.push(to_toml_table(map));
                }
            }
            Item::ArrayOfTables(tables)
        }
        other => Item::Value(to_toml_value(other)),
    }
}

/// `map` as a standard TOML table.
fn to_toml_table(map: &BTreeMap<String, Node>) -> Table {
    let mut table = Table::new();
    for (k, v) in map {
        table.insert(k, to_toml_item(v));
    }
    table
}

/// `doc` written as TOML.
fn toml_text(doc: &BTreeMap<String, Node>) -> String {
    let mut out = DocumentMut::new();
    for (k, v) in doc {
        out.insert(k, to_toml_item(v));
    }
    out.to_string()
}

/// Check the three properties for one syntax over `shared` and `overlay`.
fn properties(syntax: Syntax, shared: &str, overlay: &str) -> Result<(), TestCaseError> {
    let shared = shared.as_bytes();
    let overlays = [Fragment {
        name: "o",
        bytes: overlay.as_bytes(),
    }];
    prop_assert_eq!(merge(syntax, shared, &[]).unwrap(), shared);
    let Ok(merged) = merge(syntax, shared, &overlays) else {
        return Ok(());
    };
    let again = merge(syntax, &merged, &overlays).unwrap();
    prop_assert!(
        same(syntax, &again, &merged).unwrap(),
        "merging twice differs:\n{}\n---\n{}",
        String::from_utf8_lossy(&merged),
        String::from_utf8_lossy(&again)
    );
    let back = strip(syntax, &merged, shared, &overlays).unwrap();
    prop_assert!(
        same(syntax, &back, shared).unwrap(),
        "strip did not undo merge:\nshared:\n{}\nmerged:\n{}\nstripped:\n{}",
        String::from_utf8_lossy(shared),
        String::from_utf8_lossy(&merged),
        String::from_utf8_lossy(&back)
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn json_merge_is_idempotent_and_strip_undoes_it(s in document(), o in document()) {
        properties(Syntax::Json, &json_text(&s), &json_text(&o))?;
    }

    #[test]
    fn toml_merge_is_idempotent_and_strip_undoes_it(s in document(), o in document()) {
        properties(Syntax::Toml, &toml_text(&s), &toml_text(&o))?;
    }
}
