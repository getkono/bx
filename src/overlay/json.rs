//! [`merge`](super::merge), [`strip`](super::strip) and [`same`](super::same)
//! for JSON, over `serde_json` values that keep each object's key order and
//! each number's text.

use serde_json::{Map, Value};

use super::{Error, Fragment, KeyPath, Part, Syntax, changed, clash, missing};

/// A JSON object: the top level of every document merged or stripped.
type Object = Map<String, Value>;

/// `bytes` parsed as a JSON object; `what` names the document in an error.
pub(super) fn parse(bytes: &[u8], what: impl Fn() -> Part) -> Result<Object, Error> {
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(Error::NotATable {
            what: what(),
            syntax: Syntax::Json,
        }),
        Err(e) => Err(Error::Parse {
            what: what(),
            syntax: Syntax::Json,
            message: e.to_string(),
        }),
    }
}

/// See [`merge`](super::merge).
pub(super) fn merge(shared: &[u8], overlays: &[Fragment<'_>]) -> Result<Vec<u8>, Error> {
    let mut chain = chain(shared, overlays)?;
    let merged = chain.pop().unwrap_or_default();
    Ok(print(merged))
}

/// See [`strip`](super::strip).
pub(super) fn strip(
    disk: &[u8],
    shared: &[u8],
    overlays: &[Fragment<'_>],
) -> Result<Vec<u8>, Error> {
    let chain = chain(shared, overlays)?;
    let mut disk = parse(disk, || Part::Disk)?;
    for (i, overlay) in overlays.iter().enumerate().rev() {
        strip_common(
            &chain[i + 1],
            &chain[i],
            &mut disk,
            &mut KeyPath::default(),
            overlay.name,
        )?;
    }
    Ok(print(disk))
}

/// See [`canonical`](super::canonical).
pub(super) fn canonical(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(print(parse(bytes, || Part::Shared)?))
}

/// See [`same`](super::same).
pub(super) fn same(a: &[u8], b: &[u8]) -> Result<bool, Error> {
    Ok(parse(a, || Part::First)? == parse(b, || Part::Second)?)
}

/// `shared` and the result of folding in each overlay in turn: `W0 = S`, then
/// `W1` through `Wn`.
fn chain(shared: &[u8], overlays: &[Fragment<'_>]) -> Result<Vec<Object>, Error> {
    let mut chain = vec![parse(shared, || Part::Shared)?];
    for overlay in overlays {
        let over = parse(overlay.bytes, || Part::Overlay(overlay.name.to_owned()))?;
        let mut next = chain.last().cloned().unwrap_or_default();
        merge_object(&mut next, &over, &mut KeyPath::default(), overlay.name)?;
        chain.push(next);
    }
    Ok(chain)
}

/// `object` pretty-printed with two-space indentation and a trailing newline.
fn print(object: Object) -> Vec<u8> {
    let mut out = serde_json::to_vec_pretty(&Value::Object(object)).unwrap_or_default();
    out.push(b'\n');
    out
}

/// `value` rendered compactly for a message.
fn render(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Merge `over` into `base` key by key.
fn merge_object(
    base: &mut Object,
    over: &Object,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    for (key, value) in over {
        match base.get_mut(key) {
            Some(existing) => {
                path.with_key(key, |path| merge_value(existing, value, path, overlay))?;
            }
            None => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

/// Merge `over` into `base`, which both sit at `path`.
fn merge_value(
    base: &mut Value,
    over: &Value,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    match (base, over) {
        (Value::Object(base), Value::Object(over)) => merge_object(base, over, path, overlay),
        (Value::Array(base), Value::Array(over)) => {
            for element in over {
                if !base.contains(element) {
                    base.push(element.clone());
                }
            }
            Ok(())
        }
        (base, over) if *base == *over => Ok(()),
        (base, over) => Err(clash(overlay, path, &render(base), &render(over))),
    }
}

/// Take out of `disk` what `merged` holds beyond `base` under keys both hold.
fn strip_common(
    merged: &Object,
    base: &Object,
    disk: &mut Object,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    for (key, value) in merged {
        path.with_key(key, |path| match base.get(key) {
            Some(before) => match disk.get_mut(key) {
                Some(on_disk) => strip_value(value, before, on_disk, path, overlay),
                None => Ok(()),
            },
            None => strip_added(value, disk, key, path, overlay),
        })?;
    }
    Ok(())
}

/// Take out of `disk` what `merged` holds beyond `base`, all three at `path`.
fn strip_value(
    merged: &Value,
    base: &Value,
    disk: &mut Value,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    match (merged, base, disk) {
        (Value::Object(merged), Value::Object(base), Value::Object(disk)) => {
            strip_common(merged, base, disk, path, overlay)
        }
        (Value::Array(merged), Value::Array(base), Value::Array(disk)) => {
            for element in merged.iter().skip(base.len()) {
                if !remove_last(disk, element) {
                    return Err(missing(overlay, path));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Take `merged`, the value an overlay introduced under `key`, out of
/// `parent` on disk.
fn strip_added(
    merged: &Value,
    parent: &mut Object,
    key: &str,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    let Some(on_disk) = parent.get_mut(key) else {
        return Ok(());
    };
    let emptied = match (merged, on_disk) {
        (Value::Object(merged), Value::Object(on_disk)) => {
            for (inner, value) in merged {
                path.with_key(inner, |path| {
                    strip_added(value, on_disk, inner, path, overlay)
                })?;
            }
            on_disk.is_empty()
        }
        (Value::Array(merged), Value::Array(on_disk)) => {
            for element in merged {
                if !remove_last(on_disk, element) {
                    return Err(missing(overlay, path));
                }
            }
            on_disk.is_empty()
        }
        (merged, on_disk) if *merged == *on_disk => true,
        _ => return Err(changed(overlay, path)),
    };
    if emptied {
        parent.shift_remove(key);
    }
    Ok(())
}

/// Remove the last element of `array` equal to `element`, if there is one,
/// saying whether there was.
fn remove_last(array: &mut Vec<Value>, element: &Value) -> bool {
    let found = array.iter().rposition(|e| e == element);
    if let Some(at) = found {
        array.remove(at);
    }
    found.is_some()
}
