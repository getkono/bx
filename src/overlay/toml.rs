//! [`merge`](super::merge), [`strip`](super::strip) and [`same`](super::same)
//! for TOML, editing a `toml_edit` document in place so every byte outside
//! what changes keeps its formatting.

use std::collections::BTreeMap;

use toml_edit::{Array, Datetime, DocumentMut, Item, Key, RawString, Table, TableLike, Value};

use super::{Error, Fragment, KeyPath, Part, Syntax, changed, clash, missing};

/// `bytes` parsed as a TOML document; `what` names it in an error.
pub(super) fn parse(bytes: &[u8], what: impl Fn() -> Part) -> Result<DocumentMut, Error> {
    let error = |message: String| Error::Parse {
        what: what(),
        syntax: Syntax::Toml,
        message,
    };
    let text = std::str::from_utf8(bytes).map_err(|e| error(e.to_string()))?;
    text.parse::<DocumentMut>()
        .map_err(|e| error(e.to_string().trim_end().to_owned()))
}

/// See [`merge`](super::merge).
pub(super) fn merge(shared: &[u8], overlays: &[Fragment<'_>]) -> Result<Vec<u8>, Error> {
    let mut doc = parse(shared, || Part::Shared)?;
    for overlay in overlays {
        merge_one(&mut doc, overlay)?;
    }
    Ok(doc.to_string().into_bytes())
}

/// See [`strip`](super::strip).
pub(super) fn strip(
    disk: &[u8],
    shared: &[u8],
    overlays: &[Fragment<'_>],
) -> Result<Vec<u8>, Error> {
    let mut chain = vec![parse(shared, || Part::Shared)?];
    for overlay in overlays {
        let mut next = chain[chain.len() - 1].clone();
        merge_one(&mut next, overlay)?;
        chain.push(next);
    }
    let mut disk = parse(disk, || Part::Disk)?;
    for (i, overlay) in overlays.iter().enumerate().rev() {
        strip_common(
            chain[i + 1].as_table(),
            chain[i].as_table(),
            disk.as_table_mut(),
            false,
            &mut KeyPath::default(),
            overlay.name,
        )?;
    }
    Ok(disk.to_string().into_bytes())
}

/// See [`same`](super::same).
pub(super) fn same(a: &[u8], b: &[u8]) -> Result<bool, Error> {
    let a = parse(a, || Part::First)?;
    let b = parse(b, || Part::Second)?;
    Ok(plain_table(a.as_table()) == plain_table(b.as_table()))
}

/// Merge `overlay` into `doc`.
fn merge_one(doc: &mut DocumentMut, overlay: &Fragment<'_>) -> Result<(), Error> {
    let over = parse(overlay.bytes, || Part::Overlay(overlay.name.to_owned()))?;
    merge_table(
        doc.as_table_mut(),
        false,
        over.as_table(),
        false,
        &mut KeyPath::default(),
        overlay.name,
    )
}

/// A TOML value with its formatting gone: what two values are compared by.
///
/// A standard and an inline table are both a [`Plain::Table`], whose keys are
/// unordered; an array and an array of tables are both a [`Plain::Array`].
#[derive(Debug, PartialEq)]
enum Plain {
    /// An absent item.
    Nothing,
    /// A string.
    String(String),
    /// An integer.
    Integer(i64),
    /// A float, by its bits, so a NaN equals itself.
    Float(u64),
    /// A boolean.
    Boolean(bool),
    /// An offset or local date-time, date or time.
    Datetime(Datetime),
    /// An array or array of tables.
    Array(Vec<Plain>),
    /// A standard or inline table.
    Table(BTreeMap<String, Plain>),
}

/// `item` with its formatting gone.
fn plain(item: &Item) -> Plain {
    match item {
        Item::None => Plain::Nothing,
        Item::Value(value) => plain_value(value),
        Item::Table(table) => plain_table(table),
        Item::ArrayOfTables(tables) => {
            Plain::Array(tables.iter().map(|t| plain_table(t)).collect())
        }
    }
}

/// `value` with its formatting gone.
fn plain_value(value: &Value) -> Plain {
    match value {
        Value::String(s) => Plain::String(s.value().clone()),
        Value::Integer(i) => Plain::Integer(*i.value()),
        Value::Float(f) => Plain::Float(f.value().to_bits()),
        Value::Boolean(b) => Plain::Boolean(*b.value()),
        Value::Datetime(d) => Plain::Datetime(*d.value()),
        Value::Array(array) => Plain::Array(array.iter().map(plain_value).collect()),
        Value::InlineTable(table) => plain_table(table),
    }
}

/// `table` with its formatting and key order gone.
fn plain_table(table: &dyn TableLike) -> Plain {
    Plain::Table(
        table
            .iter()
            .filter(|(_, item)| !item.is_none())
            .map(|(key, item)| (key.to_owned(), plain(item)))
            .collect(),
    )
}

/// What an item holds, for deciding how two items merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A standard or inline table.
    Table,
    /// An array or array of tables.
    Array,
    /// Anything else.
    Scalar,
}

/// What `item` holds.
fn kind(item: &Item) -> Kind {
    match item {
        Item::Table(_) | Item::Value(Value::InlineTable(_)) => Kind::Table,
        Item::ArrayOfTables(_) | Item::Value(Value::Array(_)) => Kind::Array,
        Item::None | Item::Value(_) => Kind::Scalar,
    }
}

/// One element of an array or an array of tables.
#[derive(Debug, Clone, Copy)]
enum Element<'a> {
    /// An element of an array.
    Value(&'a Value),
    /// A table of an array of tables.
    Table(&'a Table),
}

impl Element<'_> {
    /// The element with its formatting gone.
    fn plain(self) -> Plain {
        match self {
            Self::Value(value) => plain_value(value),
            Self::Table(table) => plain_table(table),
        }
    }
}

/// The elements of `item`, an array or array of tables; none for anything
/// else.
fn elements(item: &Item) -> Vec<Element<'_>> {
    match item {
        Item::Value(Value::Array(array)) => array.iter().map(Element::Value).collect(),
        Item::ArrayOfTables(tables) => tables.iter().map(Element::Table).collect(),
        _ => Vec::new(),
    }
}

/// `item` rendered compactly, as an inline TOML value, for a message.
fn render(item: &Item) -> String {
    match item.clone().into_value() {
        Ok(mut value) => {
            normalize(&mut value);
            value.to_string()
        }
        Err(_) => String::new(),
    }
}

/// `value` with every part of it given the default formatting.
fn normalize(value: &mut Value) {
    match value {
        Value::String(f) => f.fmt(),
        Value::Integer(f) => f.fmt(),
        Value::Float(f) => f.fmt(),
        Value::Boolean(f) => f.fmt(),
        Value::Datetime(f) => f.fmt(),
        Value::Array(array) => {
            array.iter_mut().for_each(normalize);
            array.fmt();
        }
        Value::InlineTable(table) => {
            table.iter_mut().for_each(|(_, value)| normalize(value));
            table.fmt();
        }
    }
    value.decor_mut().clear();
}

/// Clear the document position of every table in `item`, so one copied from
/// an overlay is printed after the table it is inserted under rather than at
/// the place it held in the overlay.
fn unposition(item: &mut Item) {
    match item {
        Item::Table(table) => unposition_table(table),
        Item::ArrayOfTables(tables) => tables.iter_mut().for_each(unposition_table),
        Item::None | Item::Value(_) => {}
    }
}

/// [`unposition`] for one table.
fn unposition_table(table: &mut Table) {
    table.set_position(None);
    for (_, item) in table.iter_mut() {
        unposition(item);
    }
}

/// Merge `over` into `base` key by key. `base_inline` and `over_inline` say
/// whether each is an inline table, which decides the form an inserted key
/// takes.
fn merge_table(
    base: &mut dyn TableLike,
    base_inline: bool,
    over: &dyn TableLike,
    over_inline: bool,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    for (key, item) in over.iter() {
        if item.is_none() {
            continue;
        }
        match base.get_mut(key) {
            Some(existing) if !existing.is_none() => {
                path.with_key(key, |path| merge_item(existing, item, path, overlay))?;
            }
            _ => {
                let mut item = item.clone();
                unposition(&mut item);
                base.remove(key);
                if base_inline {
                    if let Ok(value) = item.into_value() {
                        insert_inline(base, key, value);
                    }
                    continue;
                }
                let key = match over.key(key) {
                    Some(formatted) if !over_inline => formatted.clone(),
                    _ => Key::new(key),
                };
                if over_inline && let Item::Value(value) = &mut item {
                    value.decor_mut().clear();
                }
                if let toml_edit::Entry::Vacant(vacant) = base.entry_format(&key) {
                    vacant.insert(item);
                }
            }
        }
    }
    Ok(())
}

/// Insert `value` under `key` at the end of `table`, an inline table, in the
/// default formatting. The space before the closing brace, which the last
/// value holds, moves to the new last value.
fn insert_inline(table: &mut dyn TableLike, key: &str, mut value: Value) {
    value.decor_mut().clear();
    if let Some((_, last)) = table.iter_mut().last()
        && let Some(last) = last.as_value_mut()
        && let Some(suffix) = raw(last.decor().suffix())
    {
        let suffix = suffix.to_owned();
        last.decor_mut().set_suffix("");
        value.decor_mut().set_suffix(suffix);
    }
    table.insert(key, Item::Value(value));
}

/// Append `value` to `array` in the array's own layout: after the first
/// element, a new one takes the separator the last one was written with, and
/// the space before the closing bracket, which the last element holds, moves
/// to the new last element. An element joining a lone first element goes on
/// its own line if that one does, and after a space otherwise.
fn append_value(array: &mut Array, mut value: Value) {
    value.decor_mut().clear();
    let len = array.len();
    if len > 0 {
        let last_prefix = array.get(len - 1).and_then(|v| raw(v.decor().prefix()));
        let prefix = match (len, last_prefix) {
            (1, Some(prefix)) if prefix.contains('\n') => prefix.to_owned(),
            (1, _) | (_, None) => " ".to_owned(),
            (_, Some(prefix)) => prefix.to_owned(),
        };
        let before = match len {
            1 => String::new(),
            _ => array
                .get(len - 2)
                .and_then(|v| raw(v.decor().suffix()))
                .unwrap_or_default()
                .to_owned(),
        };
        if let Some(last) = array.get_mut(len - 1) {
            if let Some(suffix) = raw(last.decor().suffix()) {
                value.decor_mut().set_suffix(suffix.to_owned());
            }
            last.decor_mut().set_suffix(before);
        }
        value.decor_mut().set_prefix(prefix);
    }
    array.push_formatted(value);
}

/// The text of a decor's prefix or suffix, when one is set.
fn raw(part: Option<&RawString>) -> Option<&str> {
    part.and_then(RawString::as_str)
}

/// Merge `over` into `base`, which both sit at `path`.
fn merge_item(
    base: &mut Item,
    over: &Item,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    match (kind(base), kind(over)) {
        (Kind::Table, Kind::Table) => {
            let base_inline = base.is_inline_table();
            let over_inline = over.is_inline_table();
            match (base.as_table_like_mut(), over.as_table_like()) {
                (Some(base), Some(over)) => {
                    merge_table(base, base_inline, over, over_inline, path, overlay)
                }
                _ => Ok(()),
            }
        }
        (Kind::Array, Kind::Array) => merge_array(base, over, path, overlay),
        _ if plain(base) == plain(over) => Ok(()),
        _ => Err(clash(overlay, path, &render(base), &render(over))),
    }
}

/// Append each element of `over` that `base` does not already hold, in the
/// form `base` holds its elements in.
fn merge_array(base: &mut Item, over: &Item, path: &KeyPath, overlay: &str) -> Result<(), Error> {
    let mut present: Vec<Plain> = elements(base).into_iter().map(Element::plain).collect();
    for element in elements(over) {
        let plain = element.plain();
        if present.contains(&plain) {
            continue;
        }
        match base {
            Item::Value(Value::Array(array)) => {
                let value = match element {
                    Element::Value(value) => value.clone(),
                    Element::Table(table) => Value::InlineTable(table.clone().into_inline_table()),
                };
                append_value(array, value);
            }
            Item::ArrayOfTables(tables) => {
                let table = match element {
                    Element::Table(table) => {
                        let mut table = table.clone();
                        unposition_table(&mut table);
                        table
                    }
                    Element::Value(Value::InlineTable(table)) => table.clone().into_table(),
                    Element::Value(value) => {
                        let shared = render(&Item::ArrayOfTables(tables.clone()));
                        let value = render(&Item::Value(value.clone()));
                        return Err(clash(overlay, &path.index(tables.len()), &shared, &value));
                    }
                };
                tables.push(table);
            }
            _ => return Ok(()),
        }
        present.push(plain);
    }
    Ok(())
}

/// Take out of `disk` what `merged` holds beyond `base` under keys both hold.
fn strip_common(
    merged: &dyn TableLike,
    base: &dyn TableLike,
    disk: &mut dyn TableLike,
    disk_inline: bool,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    for (key, item) in merged.iter() {
        if item.is_none() {
            continue;
        }
        path.with_key(key, |path| match base.get(key).filter(|b| !b.is_none()) {
            Some(before) => match disk.get_mut(key) {
                Some(on_disk) => strip_item(item, before, on_disk, path, overlay),
                None => Ok(()),
            },
            None => strip_added(item, disk, disk_inline, key, path, overlay),
        })?;
    }
    Ok(())
}

/// Take out of `disk` what `merged` holds beyond `base`, all three at `path`.
fn strip_item(
    merged: &Item,
    base: &Item,
    disk: &mut Item,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    match (kind(merged), kind(base), kind(disk)) {
        (Kind::Table, Kind::Table, Kind::Table) => {
            let disk_inline = disk.is_inline_table();
            match (
                merged.as_table_like(),
                base.as_table_like(),
                disk.as_table_like_mut(),
            ) {
                (Some(merged), Some(base), Some(disk)) => {
                    strip_common(merged, base, disk, disk_inline, path, overlay)
                }
                _ => Ok(()),
            }
        }
        (Kind::Array, Kind::Array, Kind::Array) => {
            let skip = elements(base).len();
            for element in elements(merged).into_iter().skip(skip) {
                if !remove_last(disk, &element.plain()) {
                    return Err(missing(overlay, path));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Take `merged`, the item an overlay introduced under `key`, out of `parent`
/// on disk; `parent_inline` says whether `parent` is an inline table.
fn strip_added(
    merged: &Item,
    parent: &mut dyn TableLike,
    parent_inline: bool,
    key: &str,
    path: &mut KeyPath,
    overlay: &str,
) -> Result<(), Error> {
    let Some(on_disk) = parent.get_mut(key) else {
        return Ok(());
    };
    let emptied = match (kind(merged), kind(on_disk)) {
        (Kind::Table, Kind::Table) => {
            let inline = on_disk.is_inline_table();
            match (merged.as_table_like(), on_disk.as_table_like_mut()) {
                (Some(merged), Some(on_disk)) => {
                    for (inner, item) in merged.iter() {
                        if !item.is_none() {
                            path.with_key(inner, |path| {
                                strip_added(item, on_disk, inline, inner, path, overlay)
                            })?;
                        }
                    }
                    on_disk.is_empty()
                }
                _ => false,
            }
        }
        (Kind::Array, Kind::Array) => {
            for element in elements(merged) {
                if !remove_last(on_disk, &element.plain()) {
                    return Err(missing(overlay, path));
                }
            }
            elements(on_disk).is_empty()
        }
        _ if plain(merged) == plain(on_disk) => true,
        _ => return Err(changed(overlay, path)),
    };
    if emptied {
        remove_key(parent, parent_inline, key);
    }
    Ok(())
}

/// Remove `key` from `table`. In an inline table, the last value holds the
/// space before the closing brace, so removing it hands that to the value that
/// becomes last: what [`insert_inline`] did, undone.
fn remove_key(table: &mut dyn TableLike, inline: bool, key: &str) {
    let was_last = table.iter().last().is_some_and(|(last, _)| last == key);
    let removed = table.remove(key);
    if !(inline && was_last) {
        return;
    }
    if let Some(Item::Value(removed)) = removed
        && let Some(suffix) = raw(removed.decor().suffix())
        && let Some((_, last)) = table.iter_mut().last()
        && let Some(last) = last.as_value_mut()
    {
        last.decor_mut().set_suffix(suffix.to_owned());
    }
}

/// Remove the last element of `item`, an array or array of tables, equal to
/// `target`, if there is one, saying whether there was. What [`append_value`] moved, this moves back: a
/// removed first element hands its prefix to the element that becomes first,
/// so `[a, b]` loses `a` as `[b]`, and a removed last element hands its suffix
/// to the element that becomes last.
fn remove_last(item: &mut Item, target: &Plain) -> bool {
    let Some(at) = elements(item).iter().rposition(|e| e.plain() == *target) else {
        return false;
    };
    match item {
        Item::Value(Value::Array(array)) => {
            let removed = array.remove(at);
            let len = array.len();
            if len == 0 {
                return true;
            }
            if at == 0
                && let Some(first) = array.get_mut(0)
                && let Some(prefix) = raw(removed.decor().prefix())
            {
                first.decor_mut().set_prefix(prefix.to_owned());
            }
            if at == len
                && let Some(last) = array.get_mut(len - 1)
                && let Some(suffix) = raw(removed.decor().suffix())
            {
                last.decor_mut().set_suffix(suffix.to_owned());
            }
        }
        Item::ArrayOfTables(tables) => {
            tables.remove(at);
        }
        _ => {}
    }
    true
}
