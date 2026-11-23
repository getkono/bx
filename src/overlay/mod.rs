//! Merge machine overlays into a shared structured document, and strip them
//! back out.
//!
//! A config file several machines share — `~/.claude/settings.json`, say — is
//! rendered from one shared body `S`. A machine may also declare overlays
//! `O1..On`: fragments in the same syntax holding what only that machine
//! wants. [`merge`] folds them into `S` to get `W`, the bytes bx writes. When
//! the tool that owns the file later rewrites it on disk as `D`, [`strip`]
//! takes out of `D` exactly what the overlays contributed, so the body saved
//! back into the shared repo carries no machine-only content and loses none of
//! the shared content.
//!
//! # Merge
//!
//! Overlays fold in order: overlay `i` is merged into the result of overlays
//! `1..i`, so a clash between two overlays names the later one. Merging one
//! value into another goes by what each side holds:
//!
//! * **Object into object** (JSON object, TOML table): key by key. A key only
//!   the overlay has is inserted after the existing keys, in the overlay's
//!   order; a key both have is merged recursively.
//! * **Array into array**: each overlay element is appended, unless an element
//!   structurally equal to it is already there. Equality ignores formatting
//!   and key order; a JSON number compares by its text, so `1` and `1.0`
//!   differ.
//! * **Anything else**: equal values merge to themselves; any difference — a
//!   different scalar, or an object, array and scalar meeting each other — is
//!   an [`Error::Clash`] naming the key path, both values, and the overlay.
//!
//! Merge only ever adds: nothing in `S`, or in an earlier overlay, is changed
//! or removed. That is what lets [`strip`] reconstruct the contributions from
//! the inputs alone.
//!
//! ## TOML forms
//!
//! TOML spells one table two ways and one array two ways. For merging, a
//! standard table (`[a]`, or a dotted key) and an inline table (`a = {…}`)
//! are both a table, and an array (`a = […]`) and an array of tables
//! (`[[a]]`) are both an array. The shared document's form always wins:
//!
//! * a key inserted into an inline table is converted to a value (a table to
//!   an inline table, an array of tables to an array of inline tables);
//! * an element appended to an array is converted the same way;
//! * what is inserted into an inline table or appended to an array follows the
//!   layout already there rather than the overlay's: an element takes the
//!   separator the array's last element was written with, so a one-line array
//!   stays on one line and a one-per-line array one per line, and the space
//!   before a closing bracket or brace stays before it. [`strip`] moves that
//!   space back when it takes the element out again;
//! * a key copied from an inline table into a standard table is written in
//!   the default `key = value` form;
//! * an element appended to an array of tables must be a table (standard or
//!   inline); any other element cannot be written as `[[a]]`, and is an
//!   [`Error::Clash`] at the index it would have taken.
//!
//! Everything else keeps the overlay's own formatting. The shared document is
//! edited in place, so every byte of it outside what is inserted is unchanged.
//!
//! # Strip
//!
//! [`strip`] recomputes the chain `W0 = S, W1, …, Wn = W` and takes each
//! overlay's contribution — what `Wi` has that `Wi-1` has not — out of `D`,
//! last overlay first. A contribution is one of:
//!
//! * **A key `Wi-1` lacks.** If its value is an object or array, it was
//!   introduced by the overlay and is recursed into rather than compared
//!   whole, so whatever the tool added inside it stays; once emptied it is
//!   removed too. A scalar is removed from `D` when `D` holds the same value,
//!   left alone when `D` no longer has the key (the tool removed it), and is
//!   an [`Error::Changed`] when `D` holds a different value: the change
//!   belongs in the overlay, and saving it into the shared body would leak it.
//! * **An array element beyond `Wi-1`'s.** One structurally equal occurrence
//!   is removed from `D`'s array at that path, the last if there are several.
//!   None there is an [`Error::Missing`]: a tool that changed the element and
//!   one that removed it leave the same file, and a changed element left
//!   behind would leak into the shared body.
//!
//! Keys both `Wi` and `Wi-1` hold are recursed into, and nothing `Wi-1` holds
//! is ever removed — in particular nothing in `S`. Where `D` no longer holds a
//! container at a path, or holds a different kind of value there, the tool
//! replaced what the overlay contributed to, and there is nothing to take out.
//!
//! Stripping the file merge wrote gives back the shared body: `strip(merge(S,
//! O), S, O)` holds the same data as `S`.
//!
//! # Output
//!
//! With no overlay, [`merge`] and [`strip`] return their input verbatim
//! without parsing it. Otherwise JSON is written pretty-printed with two-space
//! indentation and a trailing newline, keys in document order; TOML is the
//! shared document (for [`merge`]) or the disk document (for [`strip`]) edited
//! in place. The output is a function of the inputs alone.

mod json;
mod toml;

use std::fmt;
use std::path::Path;

/// The syntax of a structured file, from its path's extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// JSON, from a `.json` extension.
    Json,
    /// TOML, from a `.toml` extension.
    Toml,
}

impl Syntax {
    /// The syntax a path's extension names: `.json` is [`Syntax::Json`] and
    /// `.toml` is [`Syntax::Toml`], exactly and in lowercase; anything else is
    /// `None`.
    #[must_use]
    pub fn of(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "json" => Some(Self::Json),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }

    /// The syntax's name as a message spells it: `JSON` or `TOML`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Toml => "TOML",
        }
    }

    /// What the syntax calls a keyed container: `object` or `table`.
    #[must_use]
    pub fn container(self) -> &'static str {
        match self {
            Self::Json => "object",
            Self::Toml => "table",
        }
    }
}

impl fmt::Display for Syntax {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One overlay: its name, for messages, and its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Fragment<'a> {
    /// The name a message calls the overlay by.
    pub name: &'a str,
    /// The overlay's bytes, in the file's syntax.
    pub bytes: &'a [u8],
}

/// Which document an [`Error`] is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// The shared body every machine renders the file from.
    Shared,
    /// The overlay with this name.
    Overlay(String),
    /// The file as it is on disk.
    Disk,
    /// The one document [`check`] is given.
    Document,
    /// The first of the two documents [`same`] compares.
    First,
    /// The second of the two documents [`same`] compares.
    Second,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shared => f.write_str("the shared body"),
            Self::Overlay(name) => write!(f, "overlay `{name}`"),
            Self::Disk => f.write_str("the file on disk"),
            Self::Document => f.write_str("the document"),
            Self::First => f.write_str("the first document compared"),
            Self::Second => f.write_str("the second document compared"),
        }
    }
}

/// Everything that can go wrong merging, stripping or comparing documents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A document is not valid in its syntax.
    #[error("{what} is not valid {syntax}: {message}")]
    Parse {
        /// The document that failed to parse.
        what: Part,
        /// The syntax it was parsed as.
        syntax: Syntax,
        /// The parser's own account of what is wrong.
        message: String,
    },
    /// A document's top level is not an object or table, so it has no keys
    /// to merge by.
    #[error(
        "the top level of {what} is not a {syntax} {}, and overlays merge key by key",
        syntax.container()
    )]
    NotATable {
        /// The document whose top level is wrong.
        what: Part,
        /// The syntax it was parsed as.
        syntax: Syntax,
    },
    /// An overlay sets a value the document it merges into already sets
    /// differently.
    #[error(
        "overlay `{overlay}` sets `{key}` to {overlay_value}, where the file already has {shared}"
    )]
    Clash {
        /// The overlay that clashes.
        overlay: String,
        /// The dotted key path, an array index written `[i]`.
        key: String,
        /// The value already there, rendered compactly.
        shared: String,
        /// The value the overlay sets, rendered compactly.
        overlay_value: String,
    },
    /// The file on disk holds a different value for something an overlay
    /// contributed, so it cannot be taken out, and saving it would leak it into
    /// the shared body.
    #[error(
        "`{key}` comes from overlay `{overlay}` and was changed in this file; \
         change it in the overlay instead"
    )]
    Changed {
        /// The overlay the value comes from.
        overlay: String,
        /// The dotted key path, an array index written `[i]`.
        key: String,
    },
    /// The file on disk no longer holds, as the overlay wrote it, an element
    /// an overlay appended to an array. A tool that changed it and one that
    /// removed it leave the same file, and a changed element left behind
    /// would leak into the shared body, so neither is guessed at.
    #[error(
        "`{key}` no longer holds the element overlay `{overlay}` adds to it, so bx cannot \
         tell whether it was changed or removed here; change the overlay instead, or put \
         the element back"
    )]
    Missing {
        /// The overlay the element comes from.
        overlay: String,
        /// The dotted key path of the array.
        key: String,
    },
}

/// Check that `bytes` parse in `syntax` and hold an object or table at the top
/// level.
///
/// # Errors
///
/// [`Error::Parse`] or [`Error::NotATable`], naming [`Part::Document`].
pub fn check(syntax: Syntax, bytes: &[u8]) -> Result<(), Error> {
    let what = || Part::Document;
    match syntax {
        Syntax::Json => json::parse(bytes, what).map(drop),
        Syntax::Toml => toml::parse(bytes, what).map(drop),
    }
}

/// `shared` with each overlay merged in, in order.
///
/// With `overlays` empty, `shared` is returned verbatim without being parsed.
///
/// # Errors
///
/// [`Error::Parse`] or [`Error::NotATable`] for a document that is not an
/// object or table, and [`Error::Clash`] for an overlay that sets a value
/// differently.
pub fn merge(syntax: Syntax, shared: &[u8], overlays: &[Fragment<'_>]) -> Result<Vec<u8>, Error> {
    if overlays.is_empty() {
        return Ok(shared.to_vec());
    }
    match syntax {
        Syntax::Json => json::merge(shared, overlays),
        Syntax::Toml => toml::merge(shared, overlays),
    }
}

/// `disk` with what `merge(syntax, shared, overlays)` added beyond `shared`
/// taken out.
///
/// With `overlays` empty, `disk` is returned verbatim without being parsed.
///
/// # Errors
///
/// What [`merge`] returns, an [`Error::Parse`] or [`Error::NotATable`] for
/// `disk`, [`Error::Changed`] for a value an overlay contributed that `disk`
/// holds differently, and [`Error::Missing`] for an element an overlay
/// appended that `disk` no longer holds as the overlay wrote it.
pub fn strip(
    syntax: Syntax,
    disk: &[u8],
    shared: &[u8],
    overlays: &[Fragment<'_>],
) -> Result<Vec<u8>, Error> {
    if overlays.is_empty() {
        return Ok(disk.to_vec());
    }
    match syntax {
        Syntax::Json => json::strip(disk, shared, overlays),
        Syntax::Toml => toml::strip(disk, shared, overlays),
    }
}

/// The shared body as [`merge`] lays out what it writes, so that it can be
/// compared line by line with a merge or a strip: JSON pretty-printed as
/// [`merge`] prints it, and TOML, which both edit in place, as it is.
///
/// # Errors
///
/// [`Error::Parse`] or [`Error::NotATable`], naming [`Part::Shared`].
pub fn canonical(syntax: Syntax, shared: &[u8]) -> Result<Vec<u8>, Error> {
    match syntax {
        Syntax::Json => json::canonical(shared),
        Syntax::Toml => toml::parse(shared, || Part::Shared).map(|_| shared.to_vec()),
    }
}

/// Whether two documents hold the same data, formatting and key order aside.
///
/// # Errors
///
/// [`Error::Parse`] or [`Error::NotATable`] for either document.
pub fn same(syntax: Syntax, a: &[u8], b: &[u8]) -> Result<bool, Error> {
    match syntax {
        Syntax::Json => json::same(a, b),
        Syntax::Toml => toml::same(a, b),
    }
}

/// One step of a key path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// A key of an object or table.
    Key(String),
    /// An index into an array.
    Index(usize),
}

/// The path from the top level to the value being merged or stripped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KeyPath(Vec<Step>);

impl KeyPath {
    /// Run `f` with `key` pushed onto the path, popping it afterwards.
    fn with_key<T>(&mut self, key: &str, f: impl FnOnce(&mut Self) -> T) -> T {
        self.0.push(Step::Key(key.to_owned()));
        let out = f(self);
        self.0.pop();
        out
    }

    /// The path with `index` appended, for an element that is not there yet.
    fn index(&self, index: usize) -> Self {
        let mut path = self.clone();
        path.0.push(Step::Index(index));
        path
    }
}

impl fmt::Display for KeyPath {
    /// Keys joined with `.`, each quoted unless it is a bare key (ASCII
    /// letters, digits, `_` and `-`), and each index written `[i]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, step) in self.0.iter().enumerate() {
            match step {
                Step::Key(key) => {
                    if i > 0 {
                        f.write_str(".")?;
                    }
                    let bare = !key.is_empty()
                        && key
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                    if bare {
                        f.write_str(key)?;
                    } else {
                        f.write_str("\"")?;
                        for c in key.chars() {
                            match c {
                                '"' => f.write_str("\\\"")?,
                                '\\' => f.write_str("\\\\")?,
                                c if c.is_control() => write!(f, "\\u{{{:x}}}", u32::from(c))?,
                                c => write!(f, "{c}")?,
                            }
                        }
                        f.write_str("\"")?;
                    }
                }
                Step::Index(index) => write!(f, "[{index}]")?,
            }
        }
        Ok(())
    }
}

/// The longest a value rendered in a message may be, in characters.
const RENDER_LIMIT: usize = 60;

/// `rendered`, cut to [`RENDER_LIMIT`] characters with a trailing `…` when it
/// is longer.
fn shorten(rendered: &str) -> String {
    if rendered.chars().count() <= RENDER_LIMIT {
        return rendered.to_owned();
    }
    let mut out: String = rendered.chars().take(RENDER_LIMIT - 1).collect();
    out.push('…');
    out
}

/// The [`Error::Clash`] for `overlay` setting `key` to `overlay_value` over
/// `shared`, both already rendered.
fn clash(overlay: &str, key: &KeyPath, shared: &str, overlay_value: &str) -> Error {
    Error::Clash {
        overlay: overlay.to_owned(),
        key: key.to_string(),
        shared: shorten(shared),
        overlay_value: shorten(overlay_value),
    }
}

/// The [`Error::Missing`] for the array at `key`, which `overlay` appended
/// to.
fn missing(overlay: &str, key: &KeyPath) -> Error {
    Error::Missing {
        overlay: overlay.to_owned(),
        key: key.to_string(),
    }
}

/// The [`Error::Changed`] for `key`, which `overlay` contributed.
fn changed(overlay: &str, key: &KeyPath) -> Error {
    Error::Changed {
        overlay: overlay.to_owned(),
        key: key.to_string(),
    }
}

#[cfg(test)]
mod tests;
