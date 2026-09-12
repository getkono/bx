//! The configuration model: what a `bx` config repo says, and where it said it.
//!
//! A config repo is a set of **layers**. `bx.toml` is the first, `modules/*.toml`
//! follow in lexicographic filename order, and the account's `local.toml` in the
//! state directory is last. This module discovers and parses them. It does not
//! merge them, resolve a value, or substitute anything: that is entry A3's, and
//! keeping the two apart is what lets a merge be a pure function of the layer
//! files.
//!
//! Documents are read through `toml_edit`'s DOM and never through `serde`.
//! `serde` deserialisation discards the spans [`Origin`] is built from, and the
//! DOM is also what will let a future `bx add` edit a hand-written file without
//! reflowing a byte the user wrote.
//!
//! # Unknown keys are errors
//!
//! An unrecognised top-level section, or an unrecognised key inside a recognised
//! entry, is an [`Error`] carrying its origin. A config written for a newer `bx`
//! therefore fails on an older one, loudly. That is deliberate: `bx` ships one
//! binary through one install channel, so a repo and a binary are versioned
//! together, and a silent no-op is the failure mode this tool exists to end.

pub mod origin;
pub mod target;

use std::path::{Path, PathBuf};

pub use origin::Origin;
use toml_edit::{Item, Table};

/// Everything that can go wrong reading a configuration.
///
/// Every variant carries an [`Origin`] or a path, so a message always says where
/// to look.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The config repo directory does not exist.
    #[error("no bx config repo at {}", .0.display())]
    RepoMissing(PathBuf),

    /// A layer file could not be read.
    #[error("{}: {source}", .path.display())]
    Io {
        /// The file being read.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A layer file is not valid TOML.
    #[error("{}: {source}", .file.display())]
    Syntax {
        /// The file being parsed.
        file: PathBuf,
        /// `toml_edit`'s own diagnostic, which names the line and column.
        #[source]
        source: Box<toml_edit::TomlError>,
    },

    /// A top-level section this version of `bx` does not know.
    #[error("{origin}: unknown section `{section}`")]
    UnknownSection {
        /// Where the section was declared.
        origin: Origin,
        /// Its name.
        section: String,
    },

    /// A key this version of `bx` does not know, inside a section it does.
    #[error("{origin}: unknown key `{key}` in {section}")]
    UnknownKey {
        /// Where the key was written.
        origin: Origin,
        /// The enclosing section, spelled as it is in the file.
        section: &'static str,
        /// The key.
        key: String,
    },

    /// A required key is absent.
    #[error("{origin}: {section} is missing the required key `{key}`")]
    MissingKey {
        /// Where the entry starts.
        origin: Origin,
        /// The enclosing section.
        section: &'static str,
        /// The key that should have been there.
        key: &'static str,
    },

    /// A key holds the wrong TOML type.
    #[error("{origin}: `{key}` must be {expected}, found {found}")]
    WrongType {
        /// Where the key was written.
        origin: Origin,
        /// The key.
        key: String,
        /// What was wanted.
        expected: &'static str,
        /// What was there.
        found: &'static str,
    },

    /// A key holds the right type and an unusable value.
    #[error("{origin}: {message}")]
    BadValue {
        /// Where the value was written.
        origin: Origin,
        /// What is wrong with it, and what would be right.
        message: String,
    },

    /// Two entries in one layer share a natural key.
    #[error("{origin}: duplicate {kind} `{key}`, first declared at {first}")]
    Duplicate {
        /// Where the repeat is.
        origin: Origin,
        /// What kind of entry repeated — "target", "value".
        kind: &'static str,
        /// The natural key that repeated.
        key: String,
        /// Where it was first declared.
        first: Origin,
    },
}

/// The file, the bytes, and the entry being parsed out of them.
///
/// Carried through parsing so every error can name a line without each function
/// threading three arguments.
pub(crate) struct Ctx<'a> {
    /// The layer file.
    file: &'a Path,
    /// Its whole text, which spans index into.
    text: &'a str,
    /// The section header as it is spelled in the file, for messages.
    section: &'static str,
    /// The origin of the entry's own header.
    origin: Origin,
}

impl<'a> Ctx<'a> {
    /// A context for the entry `table` heads.
    pub(crate) fn new(table: &Table, file: &'a Path, text: &'a str, section: &'static str) -> Self {
        let origin = table
            .span()
            .map_or_else(|| Origin::unknown(file), |s| Origin::at(file, text, &s));
        Self {
            file,
            text,
            section,
            origin,
        }
    }

    /// The origin of the entry's header.
    pub(crate) fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The origin of one key inside the entry, falling back to the header.
    pub(crate) fn key_origin(&self, table: &Table, key: &str) -> Origin {
        table.key(key).and_then(toml_edit::Key::span).map_or_else(
            || self.origin.clone(),
            |s| Origin::at(self.file, self.text, &s),
        )
    }

    /// Reject any key the caller did not list.
    pub(crate) fn reject_unknown_keys(&self, table: &Table, known: &[&str]) -> Result<(), Error> {
        for (key, _) in table.iter() {
            if !known.contains(&key) {
                return Err(Error::UnknownKey {
                    origin: self.key_origin(table, key),
                    section: self.section,
                    key: key.to_string(),
                });
            }
        }
        Ok(())
    }

    /// An `Error::BadValue` positioned at `key`.
    pub(crate) fn bad(&self, table: &Table, key: &str, message: impl Into<String>) -> Error {
        Error::BadValue {
            origin: self.key_origin(table, key),
            message: message.into(),
        }
    }

    /// An `Error::WrongType` positioned at `key`.
    fn wrong_type(&self, table: &Table, key: &str, expected: &'static str, item: &Item) -> Error {
        Error::WrongType {
            origin: self.key_origin(table, key),
            key: key.to_string(),
            expected,
            found: item.type_name(),
        }
    }

    /// An optional string-valued key.
    pub(crate) fn str_at<'t>(&self, table: &'t Table, key: &str) -> Result<Option<&'t str>, Error> {
        match table.get(key) {
            None => Ok(None),
            Some(item) => item
                .as_str()
                .map(Some)
                .ok_or_else(|| self.wrong_type(table, key, "a string", item)),
        }
    }

    /// A required string-valued key.
    pub(crate) fn required_str<'t>(
        &self,
        table: &'t Table,
        key: &'static str,
    ) -> Result<&'t str, Error> {
        self.str_at(table, key)?.ok_or(Error::MissingKey {
            origin: self.origin.clone(),
            section: self.section,
            key,
        })
    }

    /// An optional boolean-valued key.
    pub(crate) fn bool_at(&self, table: &Table, key: &str) -> Result<Option<bool>, Error> {
        match table.get(key) {
            None => Ok(None),
            Some(item) => item
                .as_bool()
                .map(Some)
                .ok_or_else(|| self.wrong_type(table, key, "a boolean", item)),
        }
    }

    /// An optional array-of-strings key, absent meaning empty.
    pub(crate) fn str_array_at(&self, table: &Table, key: &str) -> Result<Vec<String>, Error> {
        let Some(item) = table.get(key) else {
            return Ok(Vec::new());
        };
        let array = item
            .as_array()
            .ok_or_else(|| self.wrong_type(table, key, "an array of strings", item))?;

        array
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Error::WrongType {
                        origin: self.key_origin(table, key),
                        key: key.to_string(),
                        expected: "an array of strings",
                        found: value.type_name(),
                    })
            })
            .collect()
    }
}
