//! Declared values, and the assignments that supply them.
//!
//! This is how bx models "many accounts, each with some differences". A global
//! layer declares the *shape* of a divergence and never its content:
//!
//! ```toml
//! [[value]]
//! name        = "scratch_root"
//! description = "Root of this account's scratch storage"
//! kind        = "path"     # path | string | bool | email | ssh-key | age-recipient
//! required    = true       # default false
//! is_root     = true       # default false; joins the env_guard root set
//! default     = "…"        # optional; a string or a boolean
//! ```
//!
//! The account's own `local.toml`, which lives in the state directory and is
//! never committed, supplies the content:
//!
//! ```toml
//! [values]
//! scratch_root = "/var/scratch/this-account"
//! ```
//!
//! **Nothing here is resolved.** Kind validation against an assignment, default
//! application, `{{name}}` substitution and the merge across layers are all
//! entry A3's. This entry parses the two sections so that A3 can load
//! `local.toml` through the same function, and so that the commit guard has a
//! parsed handle on the one section that must never be committed.

use std::fmt;
use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};

/// The `[[value]]` section header, as messages spell it.
const DECL_SECTION: &str = "[[value]]";

/// The `[values]` section header, as messages spell it.
const ASSIGN_SECTION: &str = "[values]";

/// Every key a `[[value]]` entry may carry.
const DECL_KEYS: [&str; 6] = [
    "name",
    "description",
    "kind",
    "required",
    "is_root",
    "default",
];

/// A value a global layer declares and the local layer supplies.
///
/// Its natural key is [`ValueDecl::name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueDecl {
    /// The name an assignment and a `{{name}}` substitution use.
    pub name: String,
    /// What it is for, used as the `bx init` prompt.
    pub description: Option<String>,
    /// What shape the answer has to be.
    pub kind: ValueKind,
    /// Whether a target that references it is `Blocked` while it is unset.
    pub required: bool,
    /// Whether it joins the `env_guard` root set, making paths under it
    /// allowable destinations for a relocating variable.
    pub is_root: bool,
    /// The answer to use when the local layer is silent.
    pub default: Option<AssignedValue>,
    /// Where the declaration was written.
    pub origin: Origin,
}

/// What shape a declared value's answer has to be.
///
/// Validating an assignment against its kind is entry A3's; this is the
/// vocabulary that validation is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueKind {
    /// A filesystem path. `~`-expanded and made absolute when resolved.
    Path,
    /// Free text.
    String,
    /// A boolean.
    Bool,
    /// An email address.
    Email,
    /// An ssh public key.
    SshKey,
    /// An age recipient.
    AgeRecipient,
}

impl ValueKind {
    /// Every spelling a config file may use, in declaration order.
    const SPELLINGS: [(&'static str, Self); 6] = [
        ("path", Self::Path),
        ("string", Self::String),
        ("bool", Self::Bool),
        ("email", Self::Email),
        ("ssh-key", Self::SshKey),
        ("age-recipient", Self::AgeRecipient),
    ];

    /// Resolve the spelling a config file uses.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::SPELLINGS
            .iter()
            .find_map(|(spelling, kind)| (*spelling == raw).then_some(*kind))
    }

    /// The spelling a config file uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        Self::SPELLINGS
            .iter()
            .find_map(|(spelling, kind)| (*kind == self).then_some(*spelling))
            .unwrap_or("string")
    }
}

impl fmt::Display for ValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A value as a config file writes it.
///
/// Strings and booleans only: every declared [`ValueKind`] is one or the other,
/// and a number or a datetime in a `[values]` table is a mistake rather than a
/// kind bx has not implemented yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignedValue {
    /// A TOML string.
    String(String),
    /// A TOML boolean.
    Bool(bool),
}

impl fmt::Display for AssignedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => f.write_str(s),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

/// One `name = value` line from a `[values]` table.
///
/// Parsed, never resolved: nothing here is checked against its declaration, and
/// nothing is substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueAssignment {
    /// The declared value's name.
    pub name: String,
    /// What this layer assigns it.
    pub value: AssignedValue,
    /// Where the assignment was written.
    pub origin: Origin,
}

/// Parse one `[[value]]` entry.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_value_decl(table: &Table, file: &Path, text: &str) -> Result<ValueDecl, Error> {
    let ctx = Ctx::new(table, file, text, DECL_SECTION);
    ctx.reject_unknown_keys(table, &DECL_KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();

    let raw_kind = ctx.required_str(table, "kind")?;
    let kind = ValueKind::parse(raw_kind).ok_or_else(|| {
        ctx.bad(
            table,
            "kind",
            format!(
                "`kind` must be one of {}, got {raw_kind:?}",
                ValueKind::SPELLINGS
                    .iter()
                    .map(|(spelling, _)| format!("{spelling:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;

    let default = match table.get("default") {
        None => None,
        Some(item) => Some(assigned_value(item).ok_or_else(|| {
            ctx.bad(
                table,
                "default",
                format!(
                    "a `default` is a string or a boolean, found {}",
                    item.type_name()
                ),
            )
        })?),
    };

    Ok(ValueDecl {
        name,
        description: ctx.str_at(table, "description")?.map(str::to_string),
        kind,
        required: ctx.bool_at(table, "required")?.unwrap_or(false),
        is_root: ctx.bool_at(table, "is_root")?.unwrap_or(false),
        default,
        origin: ctx.origin().clone(),
    })
}

/// Parse a whole `[values]` table, in document order.
///
/// # Errors
///
/// [`Error::BadValue`] for an assignment that is neither a string nor a boolean.
pub fn parse_assignments(
    table: &Table,
    file: &Path,
    text: &str,
) -> Result<Vec<ValueAssignment>, Error> {
    let ctx = Ctx::new(table, file, text, ASSIGN_SECTION);

    table
        .iter()
        .map(|(name, item)| {
            let value = assigned_value(item).ok_or_else(|| {
                ctx.bad(
                    table,
                    name,
                    format!(
                        "a value assignment is a string or a boolean, found {} for `{name}`",
                        item.type_name()
                    ),
                )
            })?;
            Ok(ValueAssignment {
                name: name.to_string(),
                value,
                origin: ctx.key_origin(table, name),
            })
        })
        .collect()
}

/// Read a TOML item as an assignable value.
fn assigned_value(item: &toml_edit::Item) -> Option<AssignedValue> {
    item.as_str()
        .map(|s| AssignedValue::String(s.to_string()))
        .or_else(|| item.as_bool().map(AssignedValue::Bool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml_edit::Document;

    /// Parse the first `[[value]]` out of a document.
    fn decl(text: &str) -> Result<ValueDecl, Error> {
        let doc = Document::parse(text).expect("valid TOML");
        let table = doc
            .as_table()
            .get("value")
            .expect("a [[value]]")
            .as_array_of_tables()
            .expect("an array of tables")
            .get(0)
            .expect("one element");
        parse_value_decl(table, Path::new("bx.toml"), text)
    }

    /// Parse the `[values]` table out of a document.
    fn assignments(text: &str) -> Result<Vec<ValueAssignment>, Error> {
        let doc = Document::parse(text).expect("valid TOML");
        let table = doc
            .as_table()
            .get("values")
            .expect("a [values]")
            .as_table()
            .expect("a table");
        parse_assignments(table, Path::new("local.toml"), text)
    }

    fn with(extra: &str) -> String {
        format!("[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n{extra}")
    }

    fn message(result: Result<impl std::fmt::Debug, Error>) -> String {
        result.expect_err("should have been rejected").to_string()
    }

    #[test]
    fn a_value_declaration_parses_every_field() {
        let text = "[[value]]\n\
                    name = \"scratch_root\"\n\
                    description = \"Root of this account's scratch storage\"\n\
                    kind = \"path\"\n\
                    required = true\n\
                    is_root = true\n\
                    default = \"/var/scratch\"\n";
        let decl = decl(text).unwrap();

        assert_eq!(decl.name, "scratch_root");
        assert_eq!(
            decl.description.as_deref(),
            Some("Root of this account's scratch storage")
        );
        assert_eq!(decl.kind, ValueKind::Path);
        assert!(decl.required);
        assert!(decl.is_root);
        assert_eq!(
            decl.default,
            Some(AssignedValue::String("/var/scratch".to_string()))
        );
        assert_eq!(decl.origin.line, 1);
    }

    #[test]
    fn the_natural_key_is_the_name() {
        assert_eq!(decl(&with("")).unwrap().name, "scratch_root");
    }

    #[test]
    fn every_declared_kind_is_accepted() {
        for (spelling, expected) in ValueKind::SPELLINGS {
            let text = format!("[[value]]\nname = \"v\"\nkind = \"{spelling}\"\n");
            assert_eq!(decl(&text).unwrap().kind, expected, "{spelling}");
            assert_eq!(expected.to_string(), spelling);
        }
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        let text = "[[value]]\nname = \"v\"\nkind = \"gpg-key\"\n";
        let message = message(decl(text));

        assert!(message.contains("\"age-recipient\""), "{message}");
        assert!(message.contains("bx.toml:3"), "{message}");
    }

    #[test]
    fn required_defaults_to_false() {
        assert!(!decl(&with("")).unwrap().required);
        assert!(decl(&with("required = true\n")).unwrap().required);
    }

    #[test]
    fn is_root_defaults_to_false() {
        assert!(!decl(&with("")).unwrap().is_root);
        assert!(decl(&with("is_root = true\n")).unwrap().is_root);
    }

    #[test]
    fn a_default_may_be_a_string_or_a_boolean() {
        assert_eq!(
            decl(&with("default = \"/var/scratch\"\n")).unwrap().default,
            Some(AssignedValue::String("/var/scratch".to_string()))
        );
        assert_eq!(
            decl(&with("default = false\n")).unwrap().default,
            Some(AssignedValue::Bool(false))
        );
        assert_eq!(decl(&with("")).unwrap().default, None);
    }

    #[test]
    fn a_default_of_any_other_type_is_rejected() {
        assert!(
            message(decl(&with("default = 7\n"))).contains("string or a boolean, found integer")
        );
        assert!(
            message(decl(&with("default = [\"a\"]\n")))
                .contains("string or a boolean, found array")
        );
    }

    #[test]
    fn a_value_without_a_name_is_rejected() {
        let text = "[[value]]\nkind = \"path\"\n";
        assert!(message(decl(text)).contains("missing the required key `name`"));
    }

    #[test]
    fn a_value_without_a_kind_is_rejected() {
        // Without a kind nothing can be validated, and `path` versus `string` is
        // the difference between a `~` being expanded and being left alone.
        let text = "[[value]]\nname = \"v\"\n";
        assert!(message(decl(text)).contains("missing the required key `kind`"));
    }

    #[test]
    fn an_unknown_value_key_is_rejected_with_its_line() {
        let message = message(decl(&with("secret = true\n")));

        assert!(message.contains("unknown key `secret`"), "{message}");
        assert!(message.contains("[[value]]"), "{message}");
        assert!(message.contains("bx.toml:4"), "{message}");
    }

    #[test]
    fn a_value_key_of_the_wrong_type_names_both_types() {
        assert!(
            message(decl(&with("required = \"yes\"\n")))
                .contains("`required` must be a boolean, found string")
        );
    }

    #[test]
    fn an_assignment_is_parsed_without_being_resolved() {
        // No kind checking, no default application, no {{name}} substitution.
        let text = "[values]\n\
                    scratch_root = \"/var/scratch/this-account\"\n\
                    use_sccache = true\n\
                    greeting = \"hello {{git_email}}\"\n";
        let parsed = assignments(text).unwrap();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].name, "scratch_root");
        assert_eq!(
            parsed[0].value,
            AssignedValue::String("/var/scratch/this-account".to_string())
        );
        assert_eq!(parsed[1].value, AssignedValue::Bool(true));
        assert_eq!(
            parsed[1].value.to_string(),
            "true",
            "a boolean renders as a boolean; entry A3 reports an assignment by \
             its rendered value and must not print `Bool(true)`"
        );
        assert_eq!(
            parsed[2].value.to_string(),
            "hello {{git_email}}",
            "substitution is A3's, so the braces survive"
        );
    }

    #[test]
    fn assignments_keep_document_order() {
        let text = "[values]\nzeta = \"1\"\nalpha = \"2\"\nmiddle = \"3\"\n";
        let names: Vec<String> = assignments(text)
            .unwrap()
            .into_iter()
            .map(|a| a.name)
            .collect();

        assert_eq!(names, ["zeta", "alpha", "middle"]);
    }

    #[test]
    fn every_assignment_carries_its_key_origin() {
        let text = "# local to this account\n[values]\nscratch_root = \"/var/scratch\"\n";
        let parsed = assignments(text).unwrap();

        assert_eq!(parsed[0].origin.line, 3);
        assert_eq!(parsed[0].origin.file, Path::new("local.toml"));
    }

    #[test]
    fn an_assignment_of_an_unsupported_type_is_rejected() {
        let message = message(assignments("[values]\ncount = 3\n"));

        assert!(
            message.contains("string or a boolean, found integer"),
            "{message}"
        );
        assert!(message.contains("`count`"), "{message}");
    }

    #[test]
    fn an_empty_values_table_assigns_nothing() {
        assert!(assignments("[values]\n").unwrap().is_empty());
    }
}
