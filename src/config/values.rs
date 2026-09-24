//! Declared values, and the assignments that supply them.
//!
//! This is how bx models "many accounts, each with some differences". A global
//! layer declares the *shape* of a divergence and never its content:
//!
//! ```toml
//! [[value]]
//! name        = "scratch_root"  # [a-z][a-z0-9_]*, here and as a [values] key
//! description = "Root of this account's scratch storage"
//! kind        = "path"     # path | string | bool | email | ssh-key | age-recipient
//! required    = true       # default false
//! is_root     = true       # default false; joins the env_guard root set; path only
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

//! # Resolution
//!
//! [`ResolvedValues`] is the declarations and their answers, in declaration
//! order, resolved against one `home` that is threaded in rather than read from
//! the environment. Resolution is one pass: a `default` may reference an
//! **earlier** value, so twenty-four derived cache paths cost one answer instead
//! of twenty-four, and a forward or self reference is an error — which makes a
//! cycle unrepresentable rather than something to detect.
//!
//! Substitution is `{{name}}`: a **single-level name lookup**, with `{{{{` a
//! literal `{{` and nothing else. No expressions, no conditionals, no nesting,
//! and the result is never rescanned. A template language on this path would put
//! arbitrary logic between what a user reads in `bx.toml` and what lands on
//! disk, and `bx plan` would stop being readable.
//!
//! # Unset is not an error
//!
//! A defect in the **committed** repo — an unknown kind, a malformed
//! placeholder, a reference to a value no layer declares — fails the load, since
//! no account can fix it by answering a prompt. A **missing answer** is exactly
//! what an account is expected to supply, so it blocks only the targets that
//! reference it and lets the rest of the apply proceed. [`Unresolved`] is the
//! type that keeps the two apart.

pub mod local;

use std::fmt;
use std::path::{Path, PathBuf};
use std::slice;

use toml_edit::Table;

use super::{Ctx, Error, Origin};
use crate::paths;

/// The `[[value]]` section header, as messages spell it.
pub(crate) const DECL_SECTION: &str = "[[value]]";

/// The `[values]` section header, as messages spell it.
const ASSIGN_SECTION: &str = "[values]";

/// Every key a `[[value]]` entry may carry.
const DECL_KEYS: [&str; 7] = [
    "name",
    "description",
    "kind",
    "required",
    "is_root",
    "default",
    "enabled",
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
    ///
    /// Substituted once, at this declaration's own position, so it may reference
    /// a value declared **earlier** — which is what lets `bx.toml` write
    /// `default = "{{scratch_root}}/cache/sccache"` and an account that has not
    /// moved sccache answer nothing.
    pub default: Option<AssignedValue>,
    /// `false` in any layer removes the declaration from the configuration.
    ///
    /// The last layer to set it wins, and `local.toml` is the last layer, so an
    /// account can always have the final word — which is the point of the
    /// mechanism.
    pub enabled: bool,
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
    if !is_value_name(&name) {
        return Err(ctx.bad(table, "name", bad_name_message(&name)));
    }

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

    let is_root = ctx.bool_at(table, "is_root")?.unwrap_or(false);
    if is_root && kind != ValueKind::Path {
        // `is_root` names a directory the guard will admit a relocating variable
        // into, so it has to be a directory. Accepting it on any other kind
        // would widen the guard on the strength of something that is not a path.
        return Err(ctx.bad(
            table,
            "is_root",
            format!(
                "`is_root` declares a directory the env_guard root set admits, \
                 so it is only legal on `kind = \"path\"`; `{name}` is `{kind}`"
            ),
        ));
    }

    Ok(ValueDecl {
        name,
        description: ctx.str_at(table, "description")?.map(str::to_string),
        kind,
        required: ctx.bool_at(table, "required")?.unwrap_or(false),
        is_root,
        default,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// What to say about a name that is not `[a-z][a-z0-9_]*`.
fn bad_name_message(name: &str) -> String {
    format!(
        "`{name}` is not a value name: a name starts with a lowercase letter and \
         holds only lowercase letters, digits and underscores"
    )
}

/// Parse a whole `[values]` table, in document order.
///
/// # Errors
///
/// [`Error::BadValue`] for a key that is not a value name, and for an assignment
/// that is neither a string nor a boolean.
pub fn parse_assignments(
    table: &Table,
    file: &Path,
    text: &str,
) -> Result<Vec<ValueAssignment>, Error> {
    let ctx = Ctx::new(table, file, text, ASSIGN_SECTION);

    table
        .iter()
        .map(|(name, item)| {
            // Both sides of the vocabulary, checked by one predicate. A
            // declaration is already held to `[a-z][a-z0-9_]*` and so is a
            // `{{name}}` reference, so a key outside it — `""`, `"a.b"`,
            // `"a{{b}}"` — names something no layer can ever have declared. It
            // is not the case the ignore-an-unknown-answer rule protects: that
            // exists so an account's `local.toml` outlives the repo revision
            // that declared what it answers, and every name that revision could
            // have declared is inside this vocabulary.
            if !is_value_name(name) {
                return Err(ctx.bad(table, name, bad_name_message(name)));
            }
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

// ---------------------------------------------------------------------------
// Kind validation
// ---------------------------------------------------------------------------

/// An answer that is not of the kind it was declared as.
///
/// Carries no [`Origin`] on purpose: [`ResolvedValues::check_answer`] is called
/// both by the loader, which has an origin to attach, and by `bx init`, which
/// has a prompt instead. The caller supplies the provenance it has.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValueError {
    /// The answer does not parse as its declared kind.
    #[error("a `{kind}` value must {expected}; got {answer:?}")]
    Malformed {
        /// The kind it was declared as.
        kind: ValueKind,
        /// What was written.
        answer: String,
        /// What would have been accepted.
        expected: &'static str,
    },
    /// A `path` answer that expanded to something relative.
    ///
    /// Only reachable through a home that is itself relative. A `path` value is
    /// joined, substituted into content and compared against the `env_guard`
    /// root set, and every one of those reads it as absolute.
    #[error(
        "a `path` value must resolve to an absolute path; {answer:?} against home {home} does not"
    )]
    NotAbsolute {
        /// What was written.
        answer: String,
        /// The home it was expanded against.
        home: String,
    },
    /// An `is_root` answer that resolves to the filesystem root.
    ///
    /// A declared root is a place bx is permitted to point a tool at, so `/`
    /// admits every destination there is and Invariant 2's only enforcement
    /// mechanism is off — invisibly, because `plan` shows nothing unusual.
    #[error(
        "a root value may not be `/`: it would admit every destination on the \
         filesystem and turn the relocation guard off; got {answer:?}"
    )]
    RootIsFilesystem {
        /// What was written.
        answer: String,
    },
}

impl ValueKind {
    /// Validate one **already-substituted** answer and return the text bx stores.
    ///
    /// The second half of validating an answer, and deliberately not public:
    /// [`ResolvedValues::check_answer`] is the whole of it, and it is the whole
    /// of it that `bx init` has to call. An answer is resolved as *expand, then
    /// check*, so a check without the expansion disagrees with the loader in
    /// both directions — it accepts `Someone {{Nested}}` as a `string`, which no
    /// later load can read, and it rejects `{{scratch_root}}/sccache` as a
    /// `path`, which is the spelling the design documents as valid.
    ///
    /// It returns the *canonical* text — a `path` expanded against `home` and
    /// lexically normalised, a `bool` lowercased — so a prompt writes exactly
    /// what a load would have produced.
    ///
    /// Nothing here touches the network or the filesystem: an `ssh-key` and an
    /// `age-recipient` are syntax-checked only. A `plan` that reached out to a
    /// key server, or that depended on whether a directory happened to exist,
    /// would not be a plan.
    ///
    /// # Errors
    ///
    /// [`ValueError::Malformed`] when `answer` is not of this kind.
    pub(crate) fn check(self, answer: &str, home: &Path) -> Result<String, ValueError> {
        let malformed = |expected: &'static str| ValueError::Malformed {
            kind: self,
            answer: answer.to_string(),
            expected,
        };

        match self {
            Self::Path => {
                if !(answer == "~" || answer.starts_with("~/") || answer.starts_with('/')) {
                    // A relative path would resolve against whatever directory
                    // bx happened to be invoked from, which is not a property of
                    // the account at all. `~user` is refused because nothing
                    // expands it: `render` leaves it alone, so `~scratch/one` —
                    // a plausible typo for `~/scratch/one` — would become a
                    // *relative* value that the root set can never match.
                    return Err(malformed(
                        "be `~`, start with `~/`, or be absolute; bx never expands another \
                         account's `~user`",
                    ));
                }
                // Through the one normaliser, which refuses a `~`-rooted climb
                // rather than clamping it. Clamping would let `~/../../..`
                // resolve to `/`, and an `is_root` value answered that way
                // widens the guard to the whole filesystem with nothing on
                // screen to say so.
                let rooted = paths::normalize_rooted(answer)
                    .map_err(|_| malformed("not climb out of the home it is rooted in"))?;
                let rendered = paths::normalize(&paths::render(&rooted, home));
                if !rendered.is_absolute() {
                    return Err(ValueError::NotAbsolute {
                        answer: answer.to_string(),
                        home: home.display().to_string(),
                    });
                }
                Ok(rendered.to_string_lossy().into_owned())
            }
            Self::String => Ok(answer.to_string()),
            Self::Bool => match answer {
                a if a.eq_ignore_ascii_case("true") => Ok("true".to_string()),
                a if a.eq_ignore_ascii_case("false") => Ok("false".to_string()),
                _ => Err(malformed("be `true` or `false`")),
            },
            Self::Email => {
                if is_email(answer) {
                    Ok(answer.to_string())
                } else {
                    Err(malformed("hold exactly one `@`, with no whitespace"))
                }
            }
            Self::SshKey => {
                if is_ssh_public_key(answer) {
                    Ok(answer.to_string())
                } else {
                    Err(malformed(
                        "be an ssh public key: an algorithm, a space, and base64",
                    ))
                }
            }
            Self::AgeRecipient => {
                if is_recipient(answer) {
                    Ok(answer.to_string())
                } else {
                    Err(malformed("be an `age1…` recipient or an ssh public key"))
                }
            }
        }
    }
}

/// Whether `text` is an address: one `@`, non-empty either side, no whitespace.
///
/// Deliberately shallow. The full grammar admits things no git config will ever
/// hold, and a stricter rule would reject addresses that work.
fn is_email(text: &str) -> bool {
    let mut halves = text.split('@');
    matches!(
        (halves.next(), halves.next(), halves.next()),
        (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty()
    ) && !text.chars().any(char::is_whitespace)
}

/// The algorithm names an `ssh-key` value may open with.
///
/// Anything beginning `sk-` is a FIDO-backed key — `sk-ssh-ed25519@openssh.com`
/// and `sk-ecdsa-sha2-nistp256@openssh.com` today — and matching the prefix
/// keeps this list from needing an edit when a third one appears.
const SSH_ALGORITHMS: [&str; 5] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

/// Whether `text` is syntactically an OpenSSH public key.
///
/// `<algorithm> <base64>`, optionally followed by a comment, which is the form
/// `~/.ssh/*.pub` and a `gpg.ssh.allowedSignersFile` both use.
fn is_ssh_public_key(text: &str) -> bool {
    let mut fields = text.split(' ');
    let (Some(algorithm), Some(blob)) = (fields.next(), fields.next()) else {
        return false;
    };
    let known = SSH_ALGORITHMS.contains(&algorithm) || algorithm.starts_with("sk-");
    known
        && !blob.is_empty()
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Whether `text` is something age can encrypt to: an `age1…` recipient or an
/// ssh public key. The rule an `age-recipient` value is held to, and the one a
/// `[secrets]` recipient list is.
pub(crate) fn is_recipient(text: &str) -> bool {
    is_age_recipient(text) || is_ssh_public_key(text)
}

/// The bech32 data charset an `age1…` recipient is spelled in.
const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Whether `text` is syntactically an age recipient.
fn is_age_recipient(text: &str) -> bool {
    let Some(data) = text.strip_prefix("age1") else {
        return false;
    };
    !data.is_empty() && data.chars().all(|c| BECH32.contains(c))
}

// ---------------------------------------------------------------------------
// Names and the `{{name}}` grammar
// ---------------------------------------------------------------------------

/// Whether `name` is a usable value name: `[a-z][a-z0-9_]*`.
///
/// Deliberately narrow. One spelling has to work as a TOML bare key in
/// `[values]`, as a `{{name}}` reference, and as a `bx init` prompt label, and a
/// name that needed quoting in one of the three would be a trap.
#[must_use]
pub fn is_value_name(name: &str) -> bool {
    let mut chars = name.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_lowercase()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Add `count` to `name`'s entry in `totals`, appending it when it is new.
///
/// One place where two counts for one name become one, so a name is a single
/// entry with a total wherever a reach is accumulated.
fn add_reach(totals: &mut Vec<(String, usize)>, name: String, count: usize) {
    match totals.iter_mut().find(|(held, _)| *held == name) {
        Some((_, held)) => *held = held.saturating_add(count),
        None => totals.push((name, count)),
    }
}

/// One span of a scanned string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Piece<'a> {
    /// Text to copy through unchanged.
    Literal(&'a str),
    /// A `{{name}}` reference.
    Name(&'a str),
}

/// A string that is not a well-formed template at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlaceholderError {
    /// An opening brace pair with no closing pair after it.
    #[error("unterminated placeholder at byte {at}: an opening brace pair must be closed")]
    Unterminated {
        /// Byte offset of the opening brace pair.
        at: usize,
    },
    /// The text between the braces is not a value name.
    ///
    /// A nested placeholder lands here rather than expanding: the inner braces
    /// are not name characters, so a nested reference is an error and never a
    /// two-level lookup.
    #[error(
        "{name:?} at byte {at} is not a value name: a name starts with a \
         lowercase letter and holds only lowercase letters, digits and underscores"
    )]
    IllegalName {
        /// What was between the braces.
        name: String,
        /// Byte offset of the opening brace pair.
        at: usize,
    },
}

/// Split `text` into literals and `{{name}}` references.
///
/// Left to right, one pass. Four braces emit a literal opening pair and consume
/// all four. An unmatched closing pair is ordinary content — there is no escape
/// for it and none is needed, because a closing pair is only special once a
/// placeholder is open.
///
/// Every step names the byte the next one starts at, and that byte is asserted
/// to be past this one. A cursor that stopped advancing would loop forever — and
/// in the escape branch grow `pieces` without bound while it did — so a defect
/// in the arithmetic is a panic naming the byte, never a hang.
pub(crate) fn scan(text: &str) -> Result<Vec<Piece<'_>>, PlaceholderError> {
    let mut pieces = Vec::new();
    let mut literal_from = 0;
    let mut at = 0;

    while at < text.len() {
        let next = if !text[at..].starts_with("{{") {
            // Advance one *character*, so a multi-byte character can never be
            // split and indexed into the middle of.
            at + text[at..].chars().next().map_or(1, char::len_utf8)
        } else if text[at..].starts_with("{{{{") {
            // Flush the run *including* the first brace pair, which is exactly
            // the literal the escape stands for. Nothing is synthesised.
            pieces.push(Piece::Literal(&text[literal_from..at + 2]));
            literal_from = at + 4;
            literal_from
        } else {
            let open = at + 2;
            let Some(close) = text[open..].find("}}").map(|rel| open + rel) else {
                return Err(PlaceholderError::Unterminated { at });
            };
            let name = &text[open..close];
            if !is_value_name(name) {
                return Err(PlaceholderError::IllegalName {
                    name: name.to_string(),
                    at,
                });
            }

            if literal_from < at {
                pieces.push(Piece::Literal(&text[literal_from..at]));
            }
            pieces.push(Piece::Name(name));
            literal_from = close + 2;
            literal_from
        };
        assert!(
            next > at,
            "the placeholder scan did not advance past byte {at}"
        );
        at = next;
    }

    if literal_from < text.len() {
        pieces.push(Piece::Literal(&text[literal_from..]));
    }
    Ok(pieces)
}

/// The value names `text` references, in order of first appearance.
///
/// # Errors
///
/// [`PlaceholderError`] when `text` is not a well-formed template.
pub fn placeholders(text: &str) -> Result<Vec<&str>, PlaceholderError> {
    let mut names: Vec<&str> = Vec::new();
    for piece in scan(text)? {
        if let Piece::Name(name) = piece
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    Ok(names)
}

/// Why a string could not be substituted.
///
/// The split is this entry's core safety property. [`Unresolved::Unset`] is a
/// **missing answer**, which is what an account supplies, so it blocks the
/// targets that depend on it and nothing else. Every other variant is a defect
/// in the committed repo that no answer could fix, so it fails the load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unresolved {
    /// Declared, but no layer answered and no default applied.
    #[error("no answer for {}", .names.join(", "))]
    Unset {
        /// The values that need answering, in declaration order.
        names: Vec<String>,
    },
    /// The text is not a well-formed template.
    #[error(transparent)]
    Malformed(#[from] PlaceholderError),
    /// Declared, but a layer set `enabled = false` on the declaration.
    ///
    /// An account's own refusal, so it blocks what depends on it rather than
    /// failing the load — the same degradation an unanswered value gets. It is
    /// kept apart from [`Unresolved::Unset`] because the two are cleared by
    /// different acts: one is answered, and the other is switched back on.
    #[error("no enabled declaration of {}", .names.join(", "))]
    Disabled {
        /// The declarations that are switched off, in declaration order.
        names: Vec<String>,
    },
    /// Declared, but its text is not of its kind, and the cause is this account's.
    ///
    /// Either an answer the account wrote that its kind refuses —
    /// `scratch_root = "/"` for a root — or a committed `default` an account
    /// answer turned into such text: `{{prefix}}/cache` as a `path`, with
    /// `prefix` answered `scratch`. Both are the account's to fix, so this
    /// blocks what depends on the value rather than failing the load. A
    /// `default` that is invalid with no account answer involved is a defect in
    /// the committed repo, and still fails it.
    #[error("no usable value for {}", .names.join(", "))]
    Invalid {
        /// The declarations whose text is invalid, in declaration order.
        names: Vec<String>,
    },
    /// A reference to a value no layer declares — a repo typo.
    #[error("no layer declares the value `{0}`")]
    Undeclared(String),
    /// A `default` referencing a value declared later, or itself.
    ///
    /// Resolution is one pass in declaration order, which is what makes a cycle
    /// unrepresentable rather than something to detect at runtime.
    #[error("`{0}` is declared later; a default may only reference an earlier value")]
    Forward(String),
}

/// Why an answer is not usable.
///
/// The error of [`ResolvedValues::check_answer`], which is the one entry point
/// that validates an answer the way the loader does. The two halves are kept
/// apart because their callers act on them differently: a
/// [`AnswerError::Reference`] carrying [`Unresolved::Unset`] means *answer that
/// one first*, and everything else means *this answer is wrong*.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    /// The answer's own `{{name}}` references could not be resolved.
    #[error(transparent)]
    Reference(#[from] Unresolved),
    /// The answer resolved, but is not of its declared kind.
    #[error(transparent)]
    Kind(#[from] ValueError),
}

/// What a name resolved to while expanding.
enum Lookup<'a> {
    /// Answered, with this text.
    Answered(&'a str),
    /// Declared and unanswered; these are the names that need answering.
    Unset(&'a [String]),
    /// Declared, but switched off by a layer; these are the names to re-enable.
    Disabled(&'a [String]),
    /// Declared, but answered into text its kind refuses; these are the
    /// declarations whose text is invalid.
    Invalid(&'a [String]),
    /// Declared after the point being expanded, or by the same declaration.
    Forward,
    /// Not declared by any layer.
    Undeclared,
}

/// Expand every `{{name}}` in `text` through `lookup`.
///
/// The result is **never rescanned**: a value whose own text contains a brace
/// pair yields that text verbatim. One pass is what keeps this a name lookup
/// rather than a template language.
fn expand<'a>(text: &str, lookup: &impl Fn(&str) -> Lookup<'a>) -> Result<String, Unresolved> {
    let pieces = scan(text)?;
    let mut unset: Vec<String> = Vec::new();
    let mut disabled: Vec<String> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    let mut out = String::with_capacity(text.len());

    let record = |causes: &[String], into: &mut Vec<String>| {
        for cause in causes {
            if !into.contains(cause) {
                into.push(cause.clone());
            }
        }
    };

    for piece in pieces {
        match piece {
            Piece::Literal(literal) => out.push_str(literal),
            Piece::Name(name) => match lookup(name) {
                Lookup::Answered(answer) => out.push_str(answer),
                Lookup::Unset(causes) => record(causes, &mut unset),
                Lookup::Disabled(causes) => record(causes, &mut disabled),
                Lookup::Invalid(causes) => record(causes, &mut invalid),
                Lookup::Forward => return Err(Unresolved::Forward(name.to_string())),
                Lookup::Undeclared => return Err(Unresolved::Undeclared(name.to_string())),
            },
        }
    }

    // A switched-off declaration is reported ahead of an unanswered one: it is
    // the more specific statement, and telling an account to answer a value it
    // has itself refused would be advice it cannot follow.
    if !disabled.is_empty() {
        return Err(Unresolved::Disabled { names: disabled });
    }
    // An invalid value is reported ahead of an unanswered one: answering the
    // unanswered one would still leave this text unusable.
    if !invalid.is_empty() {
        return Err(Unresolved::Invalid { names: invalid });
    }
    if unset.is_empty() {
        Ok(out)
    } else {
        Err(Unresolved::Unset { names: unset })
    }
}

/// The one place in the codebase that spells the `bx init` invocation.
///
/// Every message that tells a user how to answer goes through here, so there is
/// one string to change rather than one per call site. Entry A8 sharpens this
/// single function when `bx init --set <name>=<value>` lands.
#[must_use]
pub fn init_hint(names: &[&str]) -> String {
    if names.is_empty() {
        "run `bx init` to answer this account's declared values".to_string()
    } else {
        format!("run `bx init` to set {}", names.join(", "))
    }
}

/// What to do about an entry blocked by a declaration a layer switched off.
///
/// Not a `bx init` invocation: `bx init` does not prompt for a declaration that
/// is switched off, so telling an account to run it would be advice that does
/// nothing. The two acts that clear this are both edits to a layer.
#[must_use]
pub fn disabled_hint(names: &[&str]) -> String {
    format!(
        "re-enable {} where a layer sets `enabled = false`, or disable this entry too",
        names.join(", ")
    )
}

/// The statements of one clash, named as every hint about it spells them.
///
/// Each spelling quoted with the line it was written on, joined with "and" in
/// the order read. One spelling of the phrase, so the problem a conflict states
/// and the hint that follows it cannot render one clash two ways; the reason
/// [`ResolvedValues::answers_hint`] and [`ResolvedValues::removal_hint`] share
/// `answers_named`.
///
/// Takes the triples a clash holds its statements in. The flag saying whether
/// bx can show a statement names a declared target decides which statements a
/// caller passes, never how one of them is spelled.
#[must_use]
pub(crate) fn statements_named<'a>(
    statements: impl IntoIterator<Item = &'a (String, Origin, bool)>,
) -> String {
    statements
        .into_iter()
        .map(|(spelling, origin, _)| format!("`{spelling}` at {origin}"))
        .collect::<Vec<_>>()
        .join(" and ")
}

/// Why an answer the account wrote has no usable text.
///
/// Names the line, which is in the file the account can edit. Blocking rather
/// than failing the load is the degradation an unanswered value gets: the
/// answer is the account's, so it costs the targets that reference it.
fn broken_answer_why(decl: &ValueDecl, assignment: &ValueAssignment, error: &ValueError) -> String {
    format!(
        "value `{name}` has no usable value: the answer at {origin} is refused, because \
         {error}; change that answer",
        name = decl.name,
        origin = assignment.origin,
    )
}

/// What to do about a target whose `file` reaches a `path` value through
/// this account's answers.
///
/// `problem` names the target and the way to the `path` value; each of
/// `answers` is named with its line, which is in the file the account can
/// edit. Unlike [`ResolvedValues::answers_hint`] it reads the answers as
/// written, so it can name one whose value is unset or invalid: with the
/// `path` value unanswered the answer referencing it resolves to nothing, and
/// it is still the answer to change.
///
/// `answers` is never empty: an empty one would read "…, because of ; change
/// that answer", naming nothing to change. The one caller holds a way to the
/// `path` value that runs through at least one answer, and enforces it rather
/// than assuming it, so this takes the slice as it finds it.
#[must_use]
pub(crate) fn path_answer_hint(problem: &str, answers: &[&ValueAssignment]) -> String {
    let answers = answers
        .iter()
        .map(|answer| format!("the answer to `{}` at {}", answer.name, answer.origin))
        .collect::<Vec<_>>()
        .join(" and ");
    format!("{problem}, because of {answers}; change that answer")
}

/// Why a committed `default` has no usable text for this account.
///
/// Names each answer that went into it with the line it was written on, which
/// is the file the account can edit, as well as the declaration, which it
/// cannot. `causes` come from the account's answers, so each has an assignment.
fn broken_default_why(
    decl: &ValueDecl,
    default: &str,
    error: &ValueError,
    causes: &[String],
    assignments: &[ValueAssignment],
) -> String {
    let answers = causes
        .iter()
        .filter_map(|name| assignments.iter().find(|a| &a.name == name))
        .map(|a| format!("the answer to `{}` at {}", a.name, a.origin))
        .collect::<Vec<_>>()
        .join(" and ");
    format!(
        "value `{name}` has no usable value: its default `{default}` at {origin} is \
         built from {answers}, and {error}; change that answer, or answer `{name}` \
         itself",
        name = decl.name,
        origin = decl.origin,
    )
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// One resolved answer: the canonical text, and the layer that supplied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The canonical text, as [`ResolvedValues::check_answer`] returned it.
    pub text: String,
    /// The layer that answered — the local layer, or the one whose `default`
    /// applied — so `bx plan` can name which file made this account differ.
    pub origin: Origin,
}

/// A resolved answer, or the reason there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// Answered, by the local layer or by a `default`.
    Given {
        /// The canonical text and the layer that supplied it.
        value: Value,
        /// The account answers this text was built from: the declaration's own
        /// name when the local layer answered it, and every name carried by the
        /// values its references reached. Empty for text built from committed
        /// defaults alone.
        from_account: Vec<String>,
        /// The values the text that answered it references, in written order:
        /// the account's answer when there is one, otherwise the `default`. An
        /// overridden default's references are not here, because its text
        /// never reached this value.
        built_from: Vec<String>,
    },
    /// Unanswered, and these are the names that actually need answering.
    ///
    /// Usually the declaration's own name. When a `default` could not resolve
    /// because an *earlier* value is unanswered, it is that earlier value —
    /// reporting the name the user can act on rather than the derived one.
    Unset(Vec<String>),
    /// Switched off by a layer, or derived from one that is.
    ///
    /// Not the same state as unanswered: no answer would help, and what clears
    /// it is switching the declaration back on.
    Disabled(Vec<String>),
    /// The text is not of its kind, and an account answer is the cause.
    ///
    /// Not a load failure: the answer is the account's to change, so it blocks
    /// what depends on this value and nothing else.
    Invalid {
        /// The declarations whose text is invalid: this one's own name, or the
        /// names carried from a reference.
        names: Vec<String>,
        /// Set on the declaration whose text broke, naming the answers and the
        /// lines responsible.
        why: Option<String>,
    },
}

impl Answer {
    /// The answer, when there is one.
    fn value(&self) -> Option<&Value> {
        match self {
            Self::Given { value, .. } => Some(value),
            Self::Unset(_) | Self::Disabled(_) | Self::Invalid { .. } => None,
        }
    }
}

/// Every declared value, in declaration order, with whatever answered it.
///
/// Parallel vectors rather than a map. The order `bx init` prompts in, the order
/// `bx doctor` lists in and the order [`ResolvedValues::roots`] returns are all
/// declaration order, and a hash map has no order at all — Invariant 3 admits
/// none of it. Lookup is a linear scan over a list that is a few dozen entries
/// long at most.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValues {
    /// The enabled declarations, in declaration order.
    decls: Vec<ValueDecl>,
    /// Parallel to `decls`.
    answers: Vec<Answer>,
    /// The home every `path` value was expanded against.
    home: PathBuf,
}

impl ResolvedValues {
    /// Resolve `decls` against `assignments`.
    ///
    /// One pass, in declaration order. A `default` or an answer may reference an
    /// **earlier** value; a forward or self reference is an error, which is what
    /// makes a cycle unrepresentable rather than something to detect.
    ///
    /// `home` is threaded in rather than read from the environment, so the whole
    /// resolution is a pure function of the layer bytes plus this argument —
    /// which is what makes Invariant 3 testable rather than asserted.
    ///
    /// # Errors
    ///
    /// [`Error::BadValue`] for a malformed template, a reference to an
    /// undeclared or later value, or a `default` that is not of its kind with
    /// no account answer involved.
    ///
    /// Text that is not of its kind **because of this account** is not an error:
    /// an answer the account wrote, or a `default` an answer went into. The
    /// value becomes [`Unresolved::Invalid`] and blocks only what references it,
    /// and [`ResolvedValues::invalid_hint`] names the `local.toml` lines
    /// responsible.
    pub fn resolve(
        decls: Vec<ValueDecl>,
        assignments: &[ValueAssignment],
        home: &Path,
    ) -> Result<Self, Error> {
        let declared: Vec<String> = decls.iter().map(|decl| decl.name.clone()).collect();
        let mut resolved = Self {
            decls: Vec::with_capacity(decls.len()),
            answers: Vec::with_capacity(decls.len()),
            home: home.to_path_buf(),
        };

        for decl in decls {
            let supplied = assignments.iter().find(|a| a.name == decl.name);
            let (raw, origin) = match supplied {
                Some(assignment) => (
                    Some(assignment.value.to_string()),
                    assignment.origin.clone(),
                ),
                None => (
                    decl.default.as_ref().map(AssignedValue::to_string),
                    decl.origin.clone(),
                ),
            };

            let answer = if !decl.enabled {
                // A layer switched the declaration off. It stays in the list so
                // a reference to it is distinguishable from a reference to a
                // name no layer ever declared, which is a repo typo and fatal.
                Answer::Disabled(vec![decl.name.clone()])
            } else {
                match raw {
                    // Nothing answered it and it has no default. The cause is
                    // itself: this is the name `bx init` will prompt for.
                    None => Answer::Unset(vec![decl.name.clone()]),
                    // The same function `bx init` calls, at this declaration's
                    // own position: expand against the values declared before
                    // it, then check the result against the kind.
                    Some(raw) => {
                        match resolved.validate(&decl, resolved.decls.len(), &raw, &declared) {
                            Ok(canonical) => {
                                let mut from_account = Vec::new();
                                if supplied.is_some() {
                                    from_account.push(decl.name.clone());
                                }
                                for input in resolved.account_inputs(&raw) {
                                    if !from_account.contains(&input) {
                                        from_account.push(input);
                                    }
                                }
                                let built_from = placeholders(&raw)
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(str::to_string)
                                    .collect();
                                Answer::Given {
                                    value: Value {
                                        text: canonical,
                                        origin,
                                    },
                                    from_account,
                                    built_from,
                                }
                            }
                            // An earlier value is unanswered, so this one is too
                            // — and it carries the earlier name, which is the
                            // one to act on.
                            Err(AnswerError::Reference(Unresolved::Unset { names })) => {
                                Answer::Unset(names)
                            }
                            // Derived from a declaration somebody switched off,
                            // and cleared by switching that one back on.
                            Err(AnswerError::Reference(Unresolved::Disabled { names })) => {
                                Answer::Disabled(names)
                            }
                            // Derived from a value this account's answers broke,
                            // and cleared by fixing that one.
                            Err(AnswerError::Reference(Unresolved::Invalid { names })) => {
                                Answer::Invalid { names, why: None }
                            }
                            // Text that expanded fine and failed its kind. An
                            // answer the account wrote, or a committed default an
                            // account answer went into, is the account's to fix:
                            // block what depends on it and name the lines. A
                            // default no answer went into is a repo defect that
                            // no answer could fix.
                            Err(AnswerError::Kind(error)) => {
                                let why = if let Some(assignment) = supplied {
                                    broken_answer_why(&decl, assignment, &error)
                                } else {
                                    let causes = resolved.account_inputs(&raw);
                                    if causes.is_empty() {
                                        return Err(Error::BadValue {
                                            origin,
                                            message: format!("value `{}`: {error}", decl.name),
                                        });
                                    }
                                    broken_default_why(&decl, &raw, &error, &causes, assignments)
                                };
                                Answer::Invalid {
                                    names: vec![decl.name.clone()],
                                    why: Some(why),
                                }
                            }
                            Err(other) => {
                                return Err(Error::BadValue {
                                    origin,
                                    message: format!("value `{}`: {other}", decl.name),
                                });
                            }
                        }
                    }
                }
            };

            resolved.decls.push(decl);
            resolved.answers.push(answer);
        }

        Ok(resolved)
    }

    /// Validate one answer for a declaration at `horizon`, as the loader does.
    ///
    /// **The whole of answer validation, in one function**, because `bx init`
    /// checking what a user typed and bx checking a line already in `local.toml`
    /// have to agree by construction rather than by two implementations that
    /// happen to match. An answer is *expanded* against the values declared
    /// before it and then *checked* against its kind; doing either half alone
    /// disagrees with the loader for any answer carrying a brace pair.
    fn validate(
        &self,
        decl: &ValueDecl,
        horizon: usize,
        answer: &str,
        declared: &[String],
    ) -> Result<String, AnswerError> {
        let text = self.expand_before(answer, horizon, declared)?;
        let canonical = decl.kind.check(&text, &self.home)?;
        if decl.is_root && canonical == "/" {
            return Err(ValueError::RootIsFilesystem {
                answer: answer.to_string(),
            }
            .into());
        }
        Ok(canonical)
    }

    /// Validate an answer for `name` exactly as loading it from `local.toml`
    /// would.
    ///
    /// The canonical text is what bx would have stored, so `bx init` writes the
    /// same bytes a hand-edit would have to. A `{{name}}` reference to an
    /// **earlier** declared value is expanded, which is what makes
    /// `sccache_dir = "{{scratch_root}}/sccache"` as legal at a prompt as it is
    /// in the file.
    ///
    /// # Errors
    ///
    /// [`AnswerError::Reference`] when the answer's own references cannot be
    /// resolved — including [`Unresolved::Undeclared`] when no layer declares
    /// `name`, and [`Unresolved::Disabled`] when one does but a layer switched
    /// it off — and [`AnswerError::Kind`] when the resolved text is not of the
    /// declared kind.
    ///
    /// A switched-off declaration is refused rather than validated: the loader
    /// never reads an answer for it, so accepting one would have `bx init` write
    /// a line that does nothing. It is its own arm rather than `Undeclared`
    /// because the act that clears it is re-enabling the declaration, not
    /// declaring it.
    pub fn check_answer(&self, name: &str, answer: &str) -> Result<String, AnswerError> {
        let Some(index) = self.index_of(name) else {
            return Err(Unresolved::Undeclared(name.to_string()).into());
        };
        if !self.decls[index].enabled {
            return Err(Unresolved::Disabled {
                names: vec![name.to_string()],
            }
            .into());
        }
        let declared: Vec<String> = self.decls.iter().map(|decl| decl.name.clone()).collect();
        self.validate(&self.decls[index], index, answer, &declared)
    }

    /// Expand `text` against the values declared before `horizon`.
    ///
    /// Everything at or after it is a forward reference, which is what keeps
    /// resolution one pass and a cycle unrepresentable.
    fn expand_before(
        &self,
        text: &str,
        horizon: usize,
        declared: &[String],
    ) -> Result<String, Unresolved> {
        expand(text, &|name: &str| match self.index_of(name) {
            Some(index) if index < horizon => self.lookup_at(index),
            // Declared, but not resolvable from here: later, or this very
            // declaration.
            Some(_) => Lookup::Forward,
            None if declared.iter().any(|d| d == name) => Lookup::Forward,
            None => Lookup::Undeclared,
        })
    }

    /// How the value at `index` answers a reference.
    fn lookup_at(&self, index: usize) -> Lookup<'_> {
        match &self.answers[index] {
            Answer::Given { value, .. } => Lookup::Answered(&value.text),
            Answer::Unset(causes) => Lookup::Unset(causes),
            Answer::Disabled(causes) => Lookup::Disabled(causes),
            Answer::Invalid { names, .. } => Lookup::Invalid(names),
        }
    }

    /// The values `name`'s answered text was built from, in written order.
    ///
    /// The references of whichever text answered it — the account's answer, or
    /// the `default` when there is none — and nothing else. Empty for a value
    /// with no answer, or one whose text references nothing.
    pub(crate) fn built_from(&self, name: &str) -> &[String] {
        match self.index_of(name).map(|index| &self.answers[index]) {
            Some(Answer::Given { built_from, .. }) => built_from,
            _ => &[],
        }
    }

    /// The account answers the `{{name}}` references in `text` were built from.
    ///
    /// Consults only the values resolved so far, which is every value a text
    /// that expanded can reference. Deduplicated, in the order reached.
    ///
    /// Every name returned was answered in the account's layer, so
    /// [`ResolvedValues::answers_hint`] can name the line it is on. Empty means
    /// no account answer went into `text`: whatever is wrong with the result is
    /// the committed repo's.
    pub(crate) fn account_inputs(&self, text: &str) -> Vec<String> {
        let mut inputs: Vec<String> = Vec::new();
        let reached = placeholders(text)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|name| self.index_of(name))
            .filter_map(|index| match self.answers.get(index) {
                Some(Answer::Given { from_account, .. }) => Some(from_account),
                _ => None,
            })
            .flatten();
        for input in reached {
            if !inputs.contains(input) {
                inputs.push(input.clone());
            }
        }
        inputs
    }

    /// What to do about an entry this account's answers made unusable.
    ///
    /// `problem` says what is wrong with the entry; each of `names`, an answer
    /// the account wrote as [`ResolvedValues::account_inputs`] reports it, is
    /// named with its line, which is in the file the account can edit. Not a
    /// `bx init` invocation, for the reason [`ResolvedValues::invalid_hint`]
    /// gives.
    ///
    /// `texts` are the entry's fields as written. A value they reference that
    /// is not answered itself but carries an answer in through its committed
    /// `default` — `q` defaulting to `{{p}}`, with `p` answered — is named too,
    /// with its declaration's line, because answering it directly is the other
    /// act that clears the entry. With no such value the hint names the
    /// answers alone.
    ///
    /// When `texts` are two or more spellings that name one file, a value each
    /// of them carries **the same number of times** is not named: the spellings
    /// hold it in equal measure, so answering it rewrites all of them alike and
    /// the likeliest outcome is that they stay one file. A value some carry and
    /// some do not, or that one spelling carries more often than another, *is*
    /// named, because answering it can part them: `~/{{q}}/x` carries `q` once
    /// and `~/{{q}}{{q}}/x` twice, so with `q` derived from an empty `p` the two
    /// are one file and `q = "a"` makes them two.
    ///
    /// The count itself is exact — [`ResolvedValues::derived_between`] says why
    /// it has to be, and what an inexact one did to this comparison. Counting
    /// is still not a *proof* of separation, in either direction, because it
    /// reads how often a spelling carries a value and never where: `~/{{q}}/x`
    /// and `~/x/{{q}}` carry `q` once each, meet when `q` is empty, and part
    /// when it is not, so a value in a separating position can be withheld.
    /// Equally, a difference in count is evidence that two spellings do not
    /// carry a value alike, not a demonstration that some answer parts them.
    /// Stated here so a reader is not told the exclusion is exact.
    ///
    /// That limit is **decided, not overlooked**, and the obvious repair is the
    /// reason. Expanding both spellings with the candidate value replaced by a
    /// marker and calling it separating when the two texts differ does decide
    /// the positional case above — and it wrongly *offers* a value for every
    /// pair whose spellings differ as text and normalise to one path, which is
    /// the direction this comparison was just corrected in, and it would land
    /// with nothing pinning it. Deciding it soundly means re-keying each
    /// spelling against a hypothetical answer, which is the merge's rule:
    /// `Portable::parse_in` and the written form. Putting that here would
    /// invert the module order — the merge reads this module, not the other way
    /// round — and duplicate the normalisation. So the rule stays a count, and
    /// the count stays exact so that what remains is the proxy itself rather
    /// than an error in it.
    /// `a_derived_value_one_spelling_carries_twice_is_offered_as_the_way_out`
    /// pins the counting case,
    /// `a_derived_value_every_colliding_spelling_carries_is_not_offered_as_the_way_out`
    /// pins the exclusion that remains, and
    /// `a_derived_value_two_spellings_reach_by_different_routes_is_not_offered`
    /// pins that the route to a value never changes its count.
    #[must_use]
    pub(crate) fn answers_hint(&self, problem: &str, texts: &[&str], names: &[String]) -> String {
        let (cause, direct) = self.answer_route(texts, names);
        if direct.is_empty() {
            return format!("{problem}, because of {cause}; change that answer");
        }
        format!("{problem}, because of {cause}; change that answer, or answer {direct} directly")
    }

    /// The cause an answer route names, and the values it offers to answer.
    ///
    /// The cause is [`ResolvedValues::answers_named`], and where a value some
    /// of `texts` reach through a committed `default` could part them, that
    /// phrase followed by ", carried in by the default of `x` at …". The
    /// second is those values, for the "or answer `x` directly" offer, and is
    /// empty where there are none.
    ///
    /// One computation, so the hint that gives this route on its own and the
    /// hint that adds it to another act cannot come to disagree about which
    /// values carry an answer in, or about which of them can part `texts`.
    fn answer_route(&self, texts: &[&str], names: &[String]) -> (String, String) {
        let answers = self.answers_named(names);

        let carried: Vec<Vec<(String, usize)>> = texts
            .iter()
            .map(|text| {
                let mut into = Vec::new();
                self.derived_between(text, &mut into);
                into
            })
            .collect();
        let mut between: Vec<String> = Vec::new();
        for (name, times) in carried.iter().flatten() {
            // One text: every derived value it carries is a way out. Two or
            // more: only one they do not all carry the same number of times.
            let separates = carried.len() == 1
                || carried
                    .iter()
                    .any(|set| !set.iter().any(|(held, also)| held == name && also == times));
            // The `contains` is belt and braces: `in_declaration_order` below
            // sorts and dedups, so a name reached from two of the texts is
            // named once either way. Kept so the list this loop builds is the
            // list the hint prints, rather than one the ordering step repairs.
            if separates && !between.contains(name) {
                between.push(name.clone());
            }
        }
        // Both halves of the sentence are read off **one** list of
        // declarations, so they cannot disagree about how many values there
        // are. Every name here reached `answers_hint` through a successful
        // `index_of` inside `derived_between`, so no lookup fails today; the
        // shape is what keeps a future one from naming N declarations and N + 1
        // values to answer, or from printing "carried in by ;" with nothing in
        // the clause. When nothing resolves, the short form is the hint.
        let ordered = self.in_declaration_order(between);
        let between: Vec<&ValueDecl> = ordered.iter().filter_map(|name| self.decl(name)).collect();
        if between.is_empty() {
            return (answers, String::new());
        }
        let defaults = between
            .iter()
            .map(|decl| format!("the default of `{}` at {}", decl.name, decl.origin))
            .collect::<Vec<_>>()
            .join(" and ");
        let direct = between
            .iter()
            .map(|decl| format!("`{}`", decl.name))
            .collect::<Vec<_>>()
            .join(" or ");
        (format!("{answers}, carried in by {defaults}"), direct)
    }

    /// What to do about a file one layer names more than once because of this
    /// account's answers, when a toggle among the statements cannot be shown to
    /// name a declared target whatever is answered.
    ///
    /// Changing the answer is not offered *for such a toggle*. Under another
    /// answer it may name a file no earlier layer declares, which fails the
    /// whole load, so the answer that made the clash can be the only one that
    /// loads. Removing it can always be followed: a toggle creates no entry, so
    /// removing one leaves nothing unknown, and every statement that stays
    /// already names the file. Nor, for that act, is a value carried in by a
    /// `default` named, as [`ResolvedValues::answers_hint`] names one:
    /// answering it directly is changing an answer too. The clause that closes
    /// the hint does name one — see `still_one_file`, which says why the same
    /// reason does not reach it.
    ///
    /// The removals alone clear the clash only while one statement stays. Two
    /// or more still name one file once the flagged toggles are gone, and none
    /// of those is a toggle an answer could strand — that is what being
    /// unflagged says — so the hint ends by naming the answers that went into
    /// them, the act that parts them. The whole hint is then what the layer
    /// needs, rather than a first step leaving a second block for the account
    /// to find by re-running. That closing answer change is followable exactly
    /// as far as `answers_hint`'s is, and no further.
    ///
    /// `problem` and `names` are as `answers_hint` takes them. `statements` are
    /// the spellings in the order read, each with its line, and flagged when it
    /// is such a toggle. Each flagged one is named; when every statement is
    /// flagged, none is the one to keep, so the hint says to keep any one, and
    /// nothing stays to answer for. Which one is kept is not indifferent — the
    /// toggles in a clash need not agree on `enabled`, and the one kept is the
    /// one that decides — so the keep-one wording says so rather than leaving
    /// an account to find the target off when it read "keep any".
    #[must_use]
    pub(crate) fn removal_hint(
        &self,
        problem: &str,
        names: &[String],
        statements: &[(String, Origin, bool)],
    ) -> String {
        let answers = self.answers_named(names);
        let unshown: Vec<&(String, Origin, bool)> = statements
            .iter()
            .filter(|(_, _, unshown)| *unshown)
            .collect();
        if unshown.len() == statements.len() {
            return format!(
                "{problem}, because of {answers}; keep one of these toggles and remove the \
                 rest: bx cannot show that any of them names a declared target for every \
                 answer, so another answer may leave one toggling a file no earlier layer \
                 declares; the one kept decides whether that file's target is enabled"
            );
        }
        let named = statements_named(unshown.iter().copied());
        let still = self.still_one_file(statements, unshown.len() == 1);
        if unshown.len() == 1 {
            return format!(
                "{problem}, because of {answers}; remove the toggle {named}: bx cannot show \
                 that it names a declared target for every answer, so another answer may \
                 leave it toggling a file no earlier layer declares{still}"
            );
        }
        format!(
            "{problem}, because of {answers}; remove the toggles {named}: bx cannot show that \
             they name declared targets for every answer, so another answer may leave them \
             toggling files no earlier layer declares{still}"
        )
    }

    /// What is left to do once the flagged toggles are gone, or nothing.
    ///
    /// Empty while fewer than two statements stay: one statement names the file
    /// once, which is what a layer is allowed. Two or more still name it twice,
    /// so the clause names them and the answers that went into them. `one_gone`
    /// is whether one toggle was named for removal rather than several.
    ///
    /// Only the answers those statements carry are named, not every answer the
    /// clash was made of: one that only a removed toggle carried parts nothing
    /// that is left. Any two statements have an answer between them — a pair
    /// with none in either spelling is refused as the repo's own defect — so
    /// the phrase is never empty.
    ///
    /// This clause takes the whole [`ResolvedValues::answer_route`], the offer
    /// to answer a value a committed `default` carries an answer in included,
    /// where the removal advice above it withholds that offer. The two are not
    /// the same act on the same statements: the removal is withheld an answer
    /// because a flagged toggle may name nothing under another one, and no
    /// statement here is flagged. Withholding it anyway would leave a clash
    /// that only answering the derived value parts — two spellings that differ
    /// only in reaching one value through another's `default` — with a closing
    /// act that does not clear it, which is the defect this clause exists to
    /// close, one level down.
    fn still_one_file(&self, statements: &[(String, Origin, bool)], one_gone: bool) -> String {
        let kept: Vec<&(String, Origin, bool)> = statements
            .iter()
            .filter(|(_, _, unshown)| !*unshown)
            .collect();
        if kept.len() < 2 {
            return String::new();
        }
        let texts: Vec<&str> = kept.iter().map(|statement| statement.0.as_str()).collect();
        let names = self.in_declaration_order(
            texts
                .iter()
                .flat_map(|text| self.account_inputs(text))
                .collect(),
        );
        let (cause, direct) = self.answer_route(&texts, &names);
        let directly = if direct.is_empty() {
            String::new()
        } else {
            format!(", or answer {direct} directly")
        };
        format!(
            "; {} still name one file once {} gone, because of {cause}; change that answer \
             too{directly}",
            statements_named(kept.iter().copied()),
            if one_gone { "it is" } else { "they are" }
        )
    }

    /// Each of `names` as the answer the account wrote and its line, joined
    /// with "and": the phrase every answer hint gives its cause in.
    fn answers_named(&self, names: &[String]) -> String {
        names
            .iter()
            .filter_map(|name| {
                self.get(name)
                    .map(|value| format!("the answer to `{name}` at {}", value.origin))
            })
            .collect::<Vec<_>>()
            .join(" and ")
    }

    /// Collect into `into` every value `text` reaches that carries an account
    /// answer in through its own `default` without being answered itself,
    /// following those defaults down, **with how many times `text` reaches it**.
    ///
    /// A name written `k` times inside a default the text reaches `m` times is
    /// counted `k * m`. The count is what [`ResolvedValues::answers_hint`]
    /// compares between two spellings; a name both reach equally often is
    /// carried in equal measure by both.
    ///
    /// The count is **exact**, and has to be. The comparison reads whether two
    /// spellings agree on it, so a rule that under-counts one route shape and
    /// not another makes them disagree about a value both carry identically,
    /// and the hint then offers an act that clears nothing. Exactness comes
    /// from the reach being multiplicative: what a text carries is the sum,
    /// over the names it writes, of what **one** occurrence of that name
    /// carries. [`ResolvedValues::carried_in_by`] is that per-name figure,
    /// computed once per declaration and scaled here — rather than a walk cut
    /// short wherever it meets a name it has seen before, which is what made
    /// the count depend on the route.
    fn derived_between(&self, text: &str, into: &mut Vec<(String, usize)>) {
        let mut known: Vec<Option<Vec<(String, usize)>>> = vec![None; self.decls.len()];
        for (index, seen) in self.derived_directly(text) {
            for (name, count) in self.carried_in_by(index, &mut known) {
                add_reach(into, name, seen.saturating_mul(count));
            }
        }
    }

    /// The declarations `text` names directly that carry an account answer in
    /// through their own `default` without being answered themselves, in
    /// written order, with how many times `text` names each.
    ///
    /// Over [`scan`] rather than [`placeholders`], which reports each name once
    /// and so could not count a repetition.
    fn derived_directly(&self, text: &str) -> Vec<(usize, usize)> {
        // Every text reaching here has already substituted, and substitution
        // scans the very same text, so `scan` cannot refuse one — the twin of
        // the invariant `refuse_committed_requirement` states in `resolve`.
        // The default is for a future caller that breaks it: such a text
        // carries nothing, degrading the hint to its short form rather than
        // panicking, which
        // `derived_between_takes_a_malformed_text_as_carrying_nothing` pins.
        let written = scan(text)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|piece| match piece {
                Piece::Name(name) => Some(name),
                Piece::Literal(_) => None,
            });
        let mut direct: Vec<(usize, usize)> = Vec::new();
        for name in written {
            // Never taken today: every text reaching here names only declared
            // values. A clash's spellings are all keyed as one file, so each
            // substituted, and a field is reported broken only after its
            // substitution succeeded. A default followed below was expanded
            // when its value resolved, and an undeclared name there fails the
            // load. Kept as `continue`, not a panic, for a future caller.
            let Some(index) = self.index_of(name) else {
                continue;
            };
            // Never taken today either. Substitution succeeds only when every
            // name is `Answer::Given`, which holds for both kinds of text above.
            // A default is followed only for a value `Given` from that default,
            // and a value's default expands only when every name in it is
            // `Given`; otherwise that value is `Unset`, `Disabled` or `Invalid`.
            let Answer::Given { from_account, .. } = &self.answers[index] else {
                continue;
            };
            // Empty: built from committed text alone. Its own name: answered.
            if from_account.is_empty() || from_account.iter().any(|input| input == name) {
                continue;
            }
            match direct.iter_mut().find(|(held, _)| *held == index) {
                Some((_, seen)) => *seen += 1,
                None => direct.push((index, 1)),
            }
        }
        direct
    }

    /// What **one** occurrence of the declaration at `index` carries in: itself,
    /// then every derived value its own `default` reaches, with how many times.
    ///
    /// A pure function of `index`, which is what makes
    /// [`ResolvedValues::derived_between`]'s counts a function of the text
    /// alone rather than of the order a walk happened to meet things in.
    /// `known` memoises it per declaration, so a name reached down many routes
    /// is expanded once and scaled many times.
    ///
    /// Finite by construction: a default is followed only into values declared
    /// **before** it, so each step descends in declaration order and no chain
    /// can return to where it started. That is not a restriction — every value
    /// a default may reference is declared before it, because
    /// [`Unresolved::Forward`] refuses the rest, and a declaration whose
    /// `default` did not expand is never `Given` from it and so never reaches
    /// here.
    fn carried_in_by(
        &self,
        index: usize,
        known: &mut [Option<Vec<(String, usize)>>],
    ) -> Vec<(String, usize)> {
        if let Some(done) = &known[index] {
            return done.clone();
        }
        let mut totals = vec![(self.decls[index].name.clone(), 1)];
        // A `default` always exists here: this declaration is `Given` from an
        // account answer that is not its own name, so nothing but its `default`
        // could have built its text. Kept as an `if let`, not an unwrap, so a
        // future caller that breaks the invariant gets the name alone.
        if let Some(default) = &self.decls[index].default {
            for (inner, seen) in self.derived_directly(&default.to_string()) {
                // Never taken. A default is expanded by `expand_before` with
                // this declaration's own index as the horizon, so a reference
                // at or after it is `Unresolved::Forward`, which fails the
                // load — a declaration whose default named a later value is
                // never `Given` from that default and so never reaches here.
                // Kept because it is what makes the recursion finite by
                // construction rather than by that argument holding: it can
                // only ever descend in declaration order.
                if inner >= index {
                    continue;
                }
                for (name, count) in self.carried_in_by(inner, known) {
                    add_reach(&mut totals, name, seen.saturating_mul(count));
                }
            }
        }
        known[index] = Some(totals.clone());
        totals
    }

    /// What to do about an entry blocked by [`Unresolved::Invalid`] on `names`.
    ///
    /// Each declaration whose default broke says which answers, on which lines,
    /// broke it — the file the account can edit, rather than the committed
    /// declaration it cannot. Not a `bx init` invocation: the answer that needs
    /// changing is already written, so `bx init` would not prompt for it.
    #[must_use]
    pub fn invalid_hint(&self, names: &[String]) -> String {
        names
            .iter()
            .filter_map(|name| match self.index_of(name).map(|i| &self.answers[i]) {
                Some(Answer::Invalid { why: Some(why), .. }) => Some(why.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// The declaration index of `name`, switched off or not.
    ///
    /// Unfiltered, unlike [`ResolvedValues::decls`]: a declaration's position is
    /// where it was written, and `enabled` does not move it. That is what lets
    /// `resolve`'s `in_declaration_order` order the names of a block that is
    /// *about* switched-off declarations.
    pub(crate) fn index_of(&self, name: &str) -> Option<usize> {
        self.decls.iter().position(|decl| decl.name == name)
    }

    /// Substitute every `{{name}}` in `text`.
    ///
    /// # Errors
    ///
    /// [`Unresolved::Unset`] when a referenced value has no answer — which makes
    /// a target blocked, not the load failed. [`Unresolved::Malformed`] and
    /// [`Unresolved::Undeclared`] are repo defects and do fail the load.
    pub fn substitute(&self, text: &str) -> Result<String, Unresolved> {
        let expanded = expand(text, &|name: &str| match self.index_of(name) {
            Some(index) => self.lookup_at(index),
            None => Lookup::Undeclared,
        });

        match expanded {
            Err(Unresolved::Unset { names }) => Err(Unresolved::Unset {
                names: self.in_declaration_order(names),
            }),
            Err(Unresolved::Disabled { names }) => Err(Unresolved::Disabled {
                names: self.in_declaration_order(names),
            }),
            Err(Unresolved::Invalid { names }) => Err(Unresolved::Invalid {
                names: self.in_declaration_order(names),
            }),
            other => other,
        }
    }

    /// Put `names` into declaration order, so two reports of one problem read
    /// the same way regardless of which field was substituted first.
    pub(crate) fn in_declaration_order(&self, mut names: Vec<String>) -> Vec<String> {
        names.sort_by_key(|name| self.index_of(name).unwrap_or(usize::MAX));
        names.dedup();
        names
    }

    /// The answer for `name`, if it has one.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.index_of(name)
            .and_then(|index| self.answers[index].value())
    }

    /// The declaration of `name`, if any layer declares it.
    #[must_use]
    pub fn decl(&self, name: &str) -> Option<&ValueDecl> {
        self.index_of(name).map(|index| &self.decls[index])
    }

    /// Every **enabled** declaration, in declaration order.
    ///
    /// The order `bx init` walks. A declaration a layer switched off is not one
    /// of this account's values, so it is absent here and is never prompted for;
    /// it is still findable by [`ResolvedValues::decl`], which is what keeps a
    /// reference to it distinguishable from a reference to a name no layer ever
    /// declared.
    #[must_use]
    pub fn decls(&self) -> Vec<&ValueDecl> {
        self.decls.iter().filter(|decl| decl.enabled).collect()
    }

    /// Every enabled declaration with no answer, in declaration order.
    ///
    /// What `bx doctor` lists.
    #[must_use]
    pub fn unset(&self) -> Vec<&ValueDecl> {
        self.decls
            .iter()
            .zip(&self.answers)
            .filter(|(decl, answer)| decl.enabled && answer.value().is_none())
            .map(|(decl, _)| decl)
            .collect()
    }

    /// Every **required** declaration that needs an answer of its own, in
    /// declaration order.
    ///
    /// What `bx init` prompts for, each carrying its `description` for the
    /// prompt and its `default` for the pre-fill.
    ///
    /// A declaration whose `default` merely failed to resolve is **not** here.
    /// With `root` unanswered and `cache` defaulting to `{{root}}/cache`, both
    /// are unanswered but only `root` can be acted on: prompting for `cache`
    /// would pre-fill the literal `{{root}}/cache` and then ask the twenty-four
    /// questions that deriving a default exists to avoid. The blocked entry
    /// already names only `root`, and this agrees with it.
    ///
    /// [`ResolvedValues::unset`] is unaffected — doctor lists everything that
    /// has no answer, whatever the reason.
    #[must_use]
    pub fn unset_required(&self) -> Vec<&ValueDecl> {
        self.decls
            .iter()
            .zip(&self.answers)
            .filter(|(decl, answer)| {
                decl.enabled
                    && decl.required
                    && matches!(answer, Answer::Unset(names) if names == slice::from_ref(&decl.name))
            })
            .map(|(decl, _)| decl)
            .collect()
    }

    /// The **names** of every required declaration with no answer.
    ///
    /// Names rather than a predicate, because a report has to say *which* value
    /// is missing or the user cannot act on it.
    #[must_use]
    pub fn unset_required_names(&self) -> Vec<&str> {
        self.unset_required()
            .into_iter()
            .map(|decl| decl.name.as_str())
            .collect()
    }

    /// Every answered `is_root` value, in declaration order.
    ///
    /// The roots `env_guard` admits a relocating variable into, already
    /// `~`-expanded and lexically normalised, so a root and a variable's value
    /// are directly comparable. An **unanswered** `is_root` value contributes
    /// nothing: a declaration nobody filled in must not widen the guard on the
    /// strength of an intention.
    #[must_use]
    pub fn roots(&self) -> Vec<PathBuf> {
        self.decls
            .iter()
            .zip(&self.answers)
            .filter(|(decl, _)| decl.is_root)
            .filter_map(|(_, answer)| answer.value())
            .map(|value| PathBuf::from(&value.text))
            .collect()
    }

    /// The home every `path` value was expanded against.
    ///
    /// Stored rather than re-derived. `env_guard`'s root set needs `$HOME` as
    /// well as the declared roots, and it has to be the *same* home the values
    /// were resolved against — so the home travels inside the values and no
    /// consumer on a resolution path ever reads the environment for it.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }
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

    // --- declaration-time validation this entry adds ------------------------

    #[test]
    fn an_assignment_key_must_be_a_value_name_too() {
        // One vocabulary, enforced wherever a name is written: a declaration, a
        // `{{name}}` reference, and the key of an answer.
        for bad in ["", "a.b", "a{{b}}", "Scratch", "scratch-root", "1st"] {
            let text = format!("[values]\n\"{bad}\" = \"x\"\n");
            let message = message(assignments(&text));
            assert!(message.contains("is not a value name"), "{bad}: {message}");
            assert!(message.contains("local.toml:2"), "{bad}: {message}");
        }
        for good in ["a", "scratch_root", "x2"] {
            let text = format!("[values]\n{good} = \"x\"\n");
            assert!(assignments(&text).is_ok(), "{good} should be accepted");
        }
    }

    #[test]
    fn a_value_name_must_be_lowercase_snake_case() {
        for bad in ["Scratch", "1st", "scratch-root", "scratch root", "", "_x"] {
            let text = format!("[[value]]\nname = \"{bad}\"\nkind = \"path\"\n");
            let message = message(decl(&text));
            assert!(message.contains("is not a value name"), "{bad}: {message}");
        }
        for good in ["a", "scratch_root", "x2", "bun_root_2"] {
            let text = format!("[[value]]\nname = \"{good}\"\nkind = \"string\"\n");
            assert!(decl(&text).is_ok(), "{good} should be accepted");
        }
    }

    #[test]
    fn is_root_requires_kind_path() {
        // A root is a directory the guard admits a relocating variable into, so
        // declaring one on a non-path kind would widen the guard on something
        // that is not a path at all.
        let message = message(decl(
            "[[value]]\nname = \"x\"\nkind = \"string\"\nis_root = true\n",
        ));
        assert!(
            message.contains("only legal on `kind = \"path\"`"),
            "{message}"
        );
        assert!(message.contains("`string`"), "{message}");

        assert!(
            decl("[[value]]\nname = \"x\"\nkind = \"path\"\nis_root = true\n").is_ok(),
            "a path root is fine"
        );
        assert!(
            decl("[[value]]\nname = \"x\"\nkind = \"string\"\nis_root = false\n").is_ok(),
            "`is_root = false` says nothing and constrains nothing"
        );
    }

    #[test]
    fn a_declaration_is_enabled_unless_a_layer_says_otherwise() {
        assert!(decl(&with("")).unwrap().enabled);
        assert!(!decl(&with("enabled = false\n")).unwrap().enabled);
        assert!(decl(&with("enabled = true\n")).unwrap().enabled);
    }

    // --- kind validation ----------------------------------------------------

    fn a_home() -> PathBuf {
        PathBuf::from("/var/home/example")
    }

    /// The canonical text a kind accepts `answer` as, or the rejection message.
    fn check(kind: ValueKind, answer: &str) -> Result<String, String> {
        kind.check(answer, &a_home()).map_err(|e| e.to_string())
    }

    #[test]
    fn a_path_value_is_tilde_expanded_and_normalised() {
        assert_eq!(
            check(ValueKind::Path, "~/.cache/../cache/sccache").unwrap(),
            "/var/home/example/cache/sccache"
        );
        assert_eq!(check(ValueKind::Path, "~").unwrap(), "/var/home/example");
        assert_eq!(
            check(ValueKind::Path, "~/").unwrap(),
            "/var/home/example",
            "a trailing separator is folded by the same rule"
        );
        assert_eq!(
            check(ValueKind::Path, "/var/mnt//scratch/one/").unwrap(),
            "/var/mnt/scratch/one"
        );
    }

    #[test]
    fn a_relative_path_value_is_an_error() {
        // It would resolve against whatever directory bx was invoked from,
        // which is not a property of the account.
        let message = check(ValueKind::Path, "scratch/one").unwrap_err();
        assert!(message.contains("be `~`, start with `~/`"), "{message}");
        assert!(check(ValueKind::Path, "").is_err());
    }

    #[test]
    fn another_accounts_home_is_not_a_path_value() {
        // Nothing expands `~user`, so `~scratch/one` — a plausible typo for
        // `~/scratch/one` — would be canonicalised to a *relative* string. The
        // env_guard compares absolute destinations against it, so every
        // relocating variable the account meant to permit would be refused with
        // nothing naming the cause.
        for other in ["~user/x", "~x", "~root/.ssh", "~scratch/one"] {
            let message = check(ValueKind::Path, other)
                .expect_err(&format!("{other} was accepted as a path value"));
            assert!(
                message.contains("never expands another account"),
                "{message}"
            );
        }
    }

    #[test]
    fn a_path_value_may_not_climb_out_of_the_home() {
        // Clamped, `~/../../..` is `/`, and an `is_root` value answered that way
        // makes every destination on the filesystem admissible with nothing on
        // screen to say so.
        for climbing in [
            "~/..",
            "~/../../..",
            "~/.ssh/../../etc",
            "~//..",
            "~//../etc",
            "~///../etc",
        ] {
            let message =
                check(ValueKind::Path, climbing).expect_err(&format!("{climbing} was accepted"));
            assert!(message.contains("not climb out of"), "{message}");
        }

        // Through the entry point `bx init` calls, which once answered
        // `~//../etc` with `/var/home/example/etc`.
        let values =
            ResolvedValues::resolve(vec![a_decl("scratch", ValueKind::Path)], &[], &a_home())
                .unwrap();
        let message = values
            .check_answer("scratch", "~//../etc")
            .expect_err("a doubled separator is still a climb out of the home");
        assert!(
            message.to_string().contains("not climb out of"),
            "{message}"
        );
        assert_eq!(
            check(ValueKind::Path, "~/.cache/../scratch").unwrap(),
            "/var/home/example/scratch",
            "a `..` that stays inside the home is ordinary"
        );
    }

    #[test]
    fn a_root_value_may_not_be_the_whole_filesystem() {
        // The guard's only enforcement mechanism, switched off invisibly.
        let mut root = a_decl("scratch_root", ValueKind::Path);
        root.is_root = true;

        let values = resolve(vec![root.clone()], &[answer("scratch_root", "/")]).unwrap();
        assert!(values.roots().is_empty(), "refused, and admits nothing");

        // The same answer through the prompt, because one entry point validates
        // both and a prompt that accepted it would write a line that holds back
        // every target referencing the root.
        let values = ResolvedValues::resolve(vec![root], &[], &a_home()).unwrap();
        let message = values.check_answer("scratch_root", "/a/../..").unwrap_err();
        assert!(message.to_string().contains("may not be `/`"), "{message}");

        // A value that is not a root is unaffected: it names a location, and
        // nothing is admitted on the strength of it.
        let plain = a_decl("brew_prefix", ValueKind::Path);
        assert!(resolve(vec![plain], &[answer("brew_prefix", "/")]).is_ok());
    }

    #[test]
    fn a_root_answered_as_the_filesystem_blocks_and_admits_nothing() {
        // `/` as a root puts every destination inside the declared roots. A
        // local.toml line that says so is refused at load however it is spelled,
        // and names that line. It holds back what references the root rather
        // than every target, and it never reaches `roots()`.
        let mut root = a_decl("scratch_root", ValueKind::Path);
        root.is_root = true;

        for spelling in ["/", "//", "/./", "/..", "/a/../.."] {
            let values = resolve(vec![root.clone()], &[answer("scratch_root", spelling)])
                .unwrap_or_else(|e| panic!("{spelling:?} failed the whole load: {e}"));

            assert!(values.get("scratch_root").is_none(), "{spelling:?}");
            assert!(
                values.roots().is_empty(),
                "{spelling:?} widened the root set"
            );
            assert_eq!(
                values.substitute("{{scratch_root}}"),
                Err(Unresolved::Invalid {
                    names: vec!["scratch_root".to_string()]
                }),
                "{spelling:?}"
            );
            let hint = values.invalid_hint(&["scratch_root".to_string()]);
            assert!(hint.contains("local.toml:2"), "{spelling:?}: {hint}");
            assert!(hint.contains("may not be `/`"), "{spelling:?}: {hint}");
        }

        let values = resolve(
            vec![root],
            &[answer("scratch_root", "/var/mnt/scratch/one")],
        )
        .unwrap();
        assert_eq!(
            values.roots(),
            [PathBuf::from("/var/mnt/scratch/one")],
            "an ordinary absolute root is still a root"
        );
    }

    #[test]
    fn a_path_value_expanded_against_a_relative_home_is_an_error() {
        // Held by the caller everywhere in the product — `paths::home_in`
        // refuses a relative home — but a `path` value is joined, substituted
        // into content and compared against the root set, and all three read it
        // as absolute, so it is asserted here rather than assumed.
        let message = ValueKind::Path
            .check("~/scratch", Path::new("relative/home"))
            .expect_err("a relative home cannot produce an absolute value");

        assert!(
            message.to_string().contains("must resolve to an absolute"),
            "{message}"
        );
    }

    #[test]
    fn a_bool_value_renders_as_true_or_false() {
        assert_eq!(check(ValueKind::Bool, "true").unwrap(), "true");
        assert_eq!(check(ValueKind::Bool, "TRUE").unwrap(), "true");
        assert_eq!(check(ValueKind::Bool, "False").unwrap(), "false");
        assert!(check(ValueKind::Bool, "yes").is_err());
        assert!(check(ValueKind::Bool, "1").is_err());
    }

    #[test]
    fn an_email_needs_one_at_and_no_whitespace() {
        assert_eq!(
            check(ValueKind::Email, "someone@example.invalid").unwrap(),
            "someone@example.invalid"
        );
        for bad in [
            "someone",
            "@example.invalid",
            "someone@",
            "one@two@three",
            "some one@example.invalid",
            "someone@example.invalid ",
        ] {
            assert!(check(ValueKind::Email, bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn an_ssh_key_must_carry_a_known_algorithm_prefix() {
        let ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial00000000000000";
        assert_eq!(check(ValueKind::SshKey, ed25519).unwrap(), ed25519);
        assert!(check(ValueKind::SshKey, &format!("{ed25519} a comment")).is_ok());
        assert!(check(ValueKind::SshKey, "ssh-rsa AAAAB3NzaC1yc2E=").is_ok());
        assert!(check(ValueKind::SshKey, "ecdsa-sha2-nistp256 AAAAE2Vj").is_ok());
        assert!(
            check(ValueKind::SshKey, "sk-ssh-ed25519@openssh.com AAAAGnNr").is_ok(),
            "a FIDO-backed key is matched by its `sk-` prefix"
        );

        for bad in [
            "AAAAC3NzaC1lZDI1NTE5",
            "ssh-ed25519",
            "ssh-ed25519 ",
            "rsa AAAAB3Nz",
            "ssh-ed25519 not-base64!",
        ] {
            assert!(check(ValueKind::SshKey, bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn an_age_recipient_accepts_age1_and_an_ssh_key() {
        let age = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        assert_eq!(check(ValueKind::AgeRecipient, age).unwrap(), age);
        assert!(
            check(
                ValueKind::AgeRecipient,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"
            )
            .is_ok(),
            "age accepts an ssh recipient, and so does bx"
        );

        for bad in ["age1", "age1BADCHARS", "age2ql3z7", "ql3z7hjy54pw3hy"] {
            assert!(
                check(ValueKind::AgeRecipient, bad).is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn a_key_blob_may_carry_every_base64_symbol() {
        // Base64 spells key material with `+` and `/` as well as letters and
        // digits, and a real key's blob holds both almost every time. Every
        // other fixture here is alphanumeric, so a check that refused either
        // symbol would pass them all and reject nearly every real key.
        //
        // Synthetic: the algorithm headers are the real encodings of the
        // algorithm names, and what follows them is made-up material, not
        // anyone's key.
        let ed25519 =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+synthetic/key+material/for+tests/only0";
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+synthetic/rsa+material/for+tests/only0== a comment";

        for key in [ed25519, rsa] {
            assert_eq!(
                check(ValueKind::SshKey, key).as_deref(),
                Ok(key),
                "an ssh-key value"
            );
            assert_eq!(
                check(ValueKind::AgeRecipient, key).as_deref(),
                Ok(key),
                "an ssh key is an age recipient too"
            );
        }

        // Each symbol on its own, so neither can hide behind the other.
        for blob in ["AAAA+AAAA", "AAAA/AAAA"] {
            let key = format!("ssh-ed25519 {blob}");
            assert!(check(ValueKind::SshKey, &key).is_ok(), "{key}");
            assert!(check(ValueKind::AgeRecipient, &key).is_ok(), "{key}");
        }
    }

    #[test]
    fn a_string_value_accepts_anything() {
        for text in ["", "192", "agents.slice", "a b\tc\n"] {
            assert_eq!(check(ValueKind::String, text).unwrap(), text);
        }
    }

    #[test]
    fn no_kind_check_touches_the_network_or_the_filesystem() {
        // Held structurally: `check` takes only a `&str` and a home, so there is
        // nothing it could open or dial. A `path` value that does not exist
        // still resolves, which `canonicalize` could not do.
        let absent = "/var/mnt/scratch/definitely/not/here";
        assert!(!Path::new(absent).exists());
        assert_eq!(check(ValueKind::Path, absent).unwrap(), absent);
    }

    // --- resolution ---------------------------------------------------------

    /// A declaration with everything at its default.
    fn a_decl(name: &str, kind: ValueKind) -> ValueDecl {
        ValueDecl {
            name: name.to_string(),
            description: Some(format!("the {name}")),
            kind,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        }
    }

    /// A string answer, as the local layer would write it.
    fn answer(name: &str, text: &str) -> ValueAssignment {
        ValueAssignment {
            name: name.to_string(),
            value: AssignedValue::String(text.to_string()),
            origin: Origin {
                file: PathBuf::from("local.toml"),
                line: 2,
            },
        }
    }

    /// Resolve, or return the load error's message.
    fn resolve(
        decls: Vec<ValueDecl>,
        answers: &[ValueAssignment],
    ) -> Result<ResolvedValues, String> {
        ResolvedValues::resolve(decls, answers, &a_home()).map_err(|e| e.to_string())
    }

    #[test]
    fn a_default_applies_when_the_local_layer_is_silent() {
        let mut decl = a_decl("agent_slice", ValueKind::String);
        decl.default = Some(AssignedValue::String("agents.slice".to_string()));

        let values = resolve(vec![decl], &[]).unwrap();

        assert_eq!(values.get("agent_slice").unwrap().text, "agents.slice");
        assert_eq!(
            values.get("agent_slice").unwrap().origin.file,
            Path::new("bx.toml"),
            "the default came from the declaring layer, and says so"
        );
    }

    #[test]
    fn a_local_answer_overrides_a_default() {
        let mut decl = a_decl("agent_slice", ValueKind::String);
        decl.default = Some(AssignedValue::String("agents.slice".to_string()));

        let values = resolve(vec![decl], &[answer("agent_slice", "work.slice")]).unwrap();

        assert_eq!(values.get("agent_slice").unwrap().text, "work.slice");
        assert_eq!(
            values.get("agent_slice").unwrap().origin.file,
            Path::new("local.toml"),
            "`bx plan` has to be able to name the file that made this account differ"
        );
    }

    #[test]
    fn a_default_may_reference_an_earlier_value() {
        // The decision that makes the operator's requirement cheap: twenty-four
        // relocating cache paths derive from one root, so an account that has
        // not moved them answers one question instead of twenty-four.
        let scratch = a_decl("scratch_root", ValueKind::Path);
        let mut sccache = a_decl("sccache_dir", ValueKind::Path);
        sccache.default = Some(AssignedValue::String(
            "{{scratch_root}}/cache/sccache".to_string(),
        ));

        let values = resolve(
            vec![scratch, sccache],
            &[answer("scratch_root", "/var/mnt/scratch/one")],
        )
        .unwrap();

        assert_eq!(
            values.get("sccache_dir").unwrap().text,
            "/var/mnt/scratch/one/cache/sccache"
        );
    }

    #[test]
    fn a_default_referencing_a_later_value_is_an_error() {
        let mut early = a_decl("sccache_dir", ValueKind::Path);
        early.default = Some(AssignedValue::String("{{scratch_root}}/x".to_string()));
        let late = a_decl("scratch_root", ValueKind::Path);

        let message = resolve(vec![early, late], &[]).unwrap_err();

        assert!(message.contains("is declared later"), "{message}");
        assert!(message.contains("scratch_root"), "{message}");
    }

    #[test]
    fn a_default_referencing_itself_is_an_error() {
        // One pass in declaration order makes a cycle unrepresentable rather
        // than something to detect, and a self reference is the shortest cycle.
        let mut decl = a_decl("scratch_root", ValueKind::Path);
        decl.default = Some(AssignedValue::String("{{scratch_root}}/x".to_string()));

        let message = resolve(vec![decl], &[]).unwrap_err();

        assert!(message.contains("is declared later"), "{message}");
    }

    #[test]
    fn a_default_referencing_an_undeclared_value_is_an_error() {
        let mut decl = a_decl("sccache_dir", ValueKind::Path);
        decl.default = Some(AssignedValue::String("{{nowhere}}/x".to_string()));

        let message = resolve(vec![decl], &[]).unwrap_err();

        assert!(
            message.contains("no layer declares the value `nowhere`"),
            "{message}"
        );
    }

    #[test]
    fn an_answer_that_is_not_of_its_kind_blocks_its_dependents_naming_its_line() {
        // The line is wrong on its own terms, and it is the account's: it costs
        // what references `git_email`, not the load, and the note names it.
        let decl = a_decl("git_email", ValueKind::Email);

        let values = resolve(vec![decl], &[answer("git_email", "not an address")])
            .expect("an account's own bad line does not fail the load");

        assert!(values.get("git_email").is_none());
        let hint = values.invalid_hint(&["git_email".to_string()]);
        assert!(hint.contains("local.toml:2"), "{hint}");
        assert!(hint.contains("git_email"), "{hint}");
        assert!(hint.contains("exactly one `@`"), "{hint}");
    }

    #[test]
    fn a_default_an_answer_makes_invalid_blocks_rather_than_failing() {
        // `prefix = "scratch"` is a legal `string`. The committed default of
        // `cache` it feeds becomes `scratch/cache`, which is not a `path` — but
        // the account's line is right for its own declaration, so this blocks
        // what references `cache` instead of failing every target.
        let prefix = a_decl("prefix", ValueKind::String);
        let mut cache = a_decl("cache", ValueKind::Path);
        cache.required = true;
        cache.default = Some(AssignedValue::String("{{prefix}}/cache".to_string()));
        let mut sub = a_decl("sub", ValueKind::Path);
        sub.default = Some(AssignedValue::String("{{cache}}/sub".to_string()));
        let note = a_decl("note", ValueKind::String);

        let values = resolve(
            vec![prefix, cache, sub, note],
            &[answer("prefix", "scratch")],
        )
        .expect("a legal answer does not fail the load");

        let invalid = Unresolved::Invalid {
            names: vec!["cache".to_string()],
        };
        assert!(values.get("cache").is_none());
        assert_eq!(values.substitute("{{cache}}"), Err(invalid.clone()));
        assert_eq!(
            values.substitute("{{sub}}"),
            Err(invalid.clone()),
            "the cause travels to what derives from it"
        );
        assert_eq!(
            values.check_answer("note", "{{cache}}"),
            Err(AnswerError::Reference(invalid))
        );
        assert!(
            values.unset_required_names().is_empty(),
            "no prompt would help: the answer that needs changing is written"
        );
        assert_eq!(
            values
                .unset()
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            ["cache", "sub", "note"],
            "doctor still lists everything with no usable answer"
        );

        let hint = values.invalid_hint(&["cache".to_string()]);
        assert!(hint.contains("value `cache`"), "{hint}");
        assert!(hint.contains("`prefix` at local.toml:2"), "{hint}");
        assert!(hint.contains("\"scratch/cache\""), "{hint}");
    }

    #[test]
    fn a_default_names_every_answer_it_was_built_from() {
        // An answer that is itself built from another answer carries both, so
        // the note names every line that could be changed to fix it.
        let prefix = a_decl("prefix", ValueKind::String);
        let mid = a_decl("mid", ValueKind::String);
        let mut cache = a_decl("cache", ValueKind::Path);
        cache.default = Some(AssignedValue::String("{{prefix}}{{mid}}/c".to_string()));

        let values = resolve(
            vec![prefix, mid, cache],
            &[answer("prefix", "a"), answer("mid", "{{prefix}}b")],
        )
        .unwrap();

        let hint = values.invalid_hint(&["cache".to_string()]);
        assert!(hint.contains("`prefix` at"), "{hint}");
        assert!(hint.contains("`mid` at"), "{hint}");
    }

    // --- the derived-value hint ---------------------------------------------

    /// `p` answered, `q` deriving its whole value from `p`'s answer, and `r`
    /// deriving from `q`. Nothing here is answered but `p`.
    fn derived_chain() -> ResolvedValues {
        let p = a_decl("p", ValueKind::String);
        let mut q = a_decl("q", ValueKind::String);
        q.default = Some(AssignedValue::String("{{p}}".to_string()));
        let mut r = a_decl("r", ValueKind::String);
        r.default = Some(AssignedValue::String("{{q}}".to_string()));
        resolve(vec![p, q, r], &[answer("p", "one")]).expect("the chain resolves")
    }

    #[test]
    fn derived_between_counts_every_occurrence_of_a_name() {
        // A name written twice is one entry counted twice, not two entries.
        // The count is what parts two spellings that both carry it.
        let values = derived_chain();

        let mut once = Vec::new();
        values.derived_between("~/{{q}}/x", &mut once);
        assert_eq!(once, [("q".to_string(), 1)]);

        let mut twice = Vec::new();
        values.derived_between("~/{{q}}{{q}}/x", &mut twice);
        assert_eq!(twice, [("q".to_string(), 2)]);
    }

    #[test]
    fn derived_between_multiplies_a_count_down_a_default() {
        // `r`'s own default reaches `q` once, and the text reaches `r` twice,
        // so `q` is reached twice as well.
        let values = derived_chain();

        let mut into = Vec::new();
        values.derived_between("~/{{r}}{{r}}/x", &mut into);

        assert_eq!(into, [("r".to_string(), 2), ("q".to_string(), 2)]);
    }

    #[test]
    fn derived_between_names_a_value_reached_down_two_defaults_once() {
        // `left` and `right` both default to `{{q}}`. `q` is reached twice, by
        // two routes, and gets one entry with the total.
        let p = a_decl("p", ValueKind::String);
        let mut q = a_decl("q", ValueKind::String);
        q.default = Some(AssignedValue::String("{{p}}".to_string()));
        let mut left = a_decl("left", ValueKind::String);
        left.default = Some(AssignedValue::String("{{q}}".to_string()));
        let mut right = a_decl("right", ValueKind::String);
        right.default = Some(AssignedValue::String("{{q}}".to_string()));
        let values =
            resolve(vec![p, q, left, right], &[answer("p", "one")]).expect("the pair resolves");

        let mut into = Vec::new();
        values.derived_between("{{left}}{{right}}", &mut into);

        assert_eq!(
            into,
            [
                ("left".to_string(), 1),
                ("q".to_string(), 2),
                ("right".to_string(), 1),
            ]
        );
    }

    /// `p` answered, and two spellings that reach `deep` by different routes.
    ///
    /// `{{left}}{{right}}` reaches it down two defaults; `{{m}}{{m}}` reaches
    /// `m` twice directly. Both are four copies of `deep` for every answer.
    fn route_diamond() -> ResolvedValues {
        let p = a_decl("p", ValueKind::String);
        let mut deep = a_decl("deep", ValueKind::String);
        deep.default = Some(AssignedValue::String("{{p}}".to_string()));
        let mut m = a_decl("m", ValueKind::String);
        m.default = Some(AssignedValue::String("{{deep}}{{deep}}".to_string()));
        let mut left = a_decl("left", ValueKind::String);
        left.default = Some(AssignedValue::String("{{m}}".to_string()));
        let mut right = a_decl("right", ValueKind::String);
        right.default = Some(AssignedValue::String("{{m}}".to_string()));
        resolve(vec![p, deep, m, left, right], &[answer("p", "")]).expect("the diamond resolves")
    }

    /// `name`'s count in a `derived_between` result, if it is in one at all.
    fn reached(into: &[(String, usize)], name: &str) -> Option<usize> {
        into.iter()
            .find(|(held, _)| held == name)
            .map(|(_, count)| *count)
    }

    #[test]
    fn derived_between_counts_a_name_by_how_often_a_text_reaches_it_not_by_its_route() {
        // Both spellings reach `deep` four times and `m` twice, by different
        // routes. A walk that stopped at a name it had already seen gave the
        // two-defaults spelling two `deep` and the twice-directly spelling
        // four, because only the second carried its multiplier into the
        // recursion — and `answers_hint` read that difference as evidence that
        // `deep` parts them.
        let values = route_diamond();

        let mut two_defaults = Vec::new();
        values.derived_between("{{left}}{{right}}", &mut two_defaults);
        let mut twice_directly = Vec::new();
        values.derived_between("{{m}}{{m}}", &mut twice_directly);

        assert_eq!(reached(&two_defaults, "deep"), Some(4), "{two_defaults:?}");
        assert_eq!(
            reached(&twice_directly, "deep"),
            Some(4),
            "{twice_directly:?}"
        );
        assert_eq!(reached(&two_defaults, "m"), Some(2), "{two_defaults:?}");
        assert_eq!(reached(&twice_directly, "m"), Some(2), "{twice_directly:?}");
        // The two names that really do part the spellings.
        assert_eq!(reached(&two_defaults, "left"), Some(1), "{two_defaults:?}");
        assert_eq!(reached(&twice_directly, "left"), None, "{twice_directly:?}");
    }

    #[test]
    fn a_derived_value_two_spellings_reach_by_different_routes_is_not_offered() {
        // The hint the counts feed. `deep` and `m` expand to the same text on
        // both sides for every answer, so answering either leaves the two
        // spellings equal and neither is an act that clears the block; only
        // `left` or `right` is.
        let values = route_diamond();

        let hint = values.answers_hint(
            "broken",
            &["{{left}}{{right}}", "{{m}}{{m}}"],
            &["p".to_string()],
        );

        assert!(
            hint.ends_with("change that answer, or answer `left` or `right` directly"),
            "{hint}"
        );
        assert!(!hint.contains("`deep`"), "{hint}");
        assert!(!hint.contains("`m`"), "{hint}");
    }

    #[test]
    fn derived_between_takes_a_malformed_text_as_carrying_nothing() {
        // Defensive: every text the hint walks has already substituted, and
        // substitution scans the same text, so `scan` cannot refuse one. This
        // pins what a future caller that breaks that invariant gets — the
        // short-form hint, whole, rather than a panic or a half-walked text.
        let values = derived_chain();

        let mut into = Vec::new();
        values.derived_between("{{q}}{{oops", &mut into);
        assert!(into.is_empty(), "{into:?}");

        let hint = values.answers_hint("broken", &["{{q}}{{oops"], &["p".to_string()]);
        assert!(hint.ends_with("; change that answer"), "{hint}");
    }

    #[test]
    fn derived_between_passes_over_a_name_no_layer_declares() {
        // Defensive: every text the hint walks names declared values only. The
        // walk stops at the name rather than panicking, and a future caller
        // that breaks the invariant gets no entry rather than a crash.
        let values = derived_chain();

        let mut into = Vec::new();
        values.derived_between("{{nowhere}}{{q}}", &mut into);

        assert_eq!(into, [("q".to_string(), 1)]);
    }

    #[test]
    fn derived_between_passes_over_a_value_with_no_answer() {
        // Defensive in the same way: the hint is only built for texts that
        // substituted, so every name in one is `Given`. An unanswered one is
        // passed over.
        let p = a_decl("p", ValueKind::String);
        let unanswered = a_decl("unanswered", ValueKind::String);
        let mut q = a_decl("q", ValueKind::String);
        q.default = Some(AssignedValue::String("{{p}}".to_string()));
        let values =
            resolve(vec![p, unanswered, q], &[answer("p", "one")]).expect("the rest resolves");
        assert!(values.get("unanswered").is_none());

        let mut into = Vec::new();
        values.derived_between("{{unanswered}}{{q}}", &mut into);

        assert_eq!(into, [("q".to_string(), 1)]);
    }

    #[test]
    fn derived_between_passes_over_a_value_answered_in_its_own_right() {
        // `q` is answered by the account, so it is named as an answer rather
        // than as a declaration to answer directly, and a value built from
        // committed text alone carries no answer to offer.
        let p = a_decl("p", ValueKind::String);
        let mut q = a_decl("q", ValueKind::String);
        q.default = Some(AssignedValue::String("{{p}}".to_string()));
        let mut fixed = a_decl("fixed", ValueKind::String);
        fixed.default = Some(AssignedValue::String("committed".to_string()));
        let values = resolve(vec![p, q, fixed], &[answer("p", "one"), answer("q", "two")])
            .expect("the values resolve");

        let mut into = Vec::new();
        values.derived_between("{{q}}{{fixed}}", &mut into);

        assert!(into.is_empty(), "{into:?}");
    }

    #[test]
    fn answers_hint_names_every_derived_value_a_single_text_carries() {
        // One text: there is nothing to separate it from, so every value that
        // carries the answer in is an act that changes it.
        let values = derived_chain();

        let hint = values.answers_hint("broken", &["~/{{r}}/x"], &["p".to_string()]);

        assert!(
            hint.ends_with("change that answer, or answer `q` or `r` directly"),
            "{hint}"
        );
    }

    #[test]
    fn answers_hint_withholds_a_derived_value_two_spellings_carry_equally() {
        // Both spellings hold `q` once, so answering it rewrites both alike and
        // naming it would be advice that clears nothing.
        let values = derived_chain();

        let hint = values.answers_hint(
            "broken",
            &["~/{{q}}/x", "~/a/{{q}}/x/.."],
            &["p".to_string()],
        );

        assert!(hint.ends_with("; change that answer"), "{hint}");
        assert!(!hint.contains("directly"), "{hint}");
    }

    #[test]
    fn answers_hint_names_a_derived_value_one_spelling_carries_more_often() {
        // The same value, carried once by one spelling and twice by the other.
        // Answering it does part them, so the hint has to offer it.
        let values = derived_chain();

        let hint = values.answers_hint(
            "broken",
            &["~/{{q}}/x", "~/{{q}}{{q}}/x"],
            &["p".to_string()],
        );

        assert!(
            hint.ends_with("change that answer, or answer `q` directly"),
            "{hint}"
        );
    }

    #[test]
    fn a_default_invalid_without_an_account_answer_is_still_a_load_error() {
        // No answer caused it and none can fix it, so it is a defect in the
        // committed repo, and the declaration is the right thing to name.
        let mut cache = a_decl("cache", ValueKind::Path);
        cache.default = Some(AssignedValue::String("relative/cache".to_string()));

        let message = resolve(vec![cache], &[]).unwrap_err();
        assert!(message.contains("bx.toml"), "{message}");
        assert!(message.contains("value `cache`"), "{message}");

        // Nor is it the account's doing when what it derives from is itself a
        // committed default.
        let mut prefix = a_decl("prefix", ValueKind::String);
        prefix.default = Some(AssignedValue::String("scratch".to_string()));
        let mut cache = a_decl("cache", ValueKind::Path);
        cache.default = Some(AssignedValue::String("{{prefix}}/cache".to_string()));

        let message = resolve(vec![prefix, cache], &[]).unwrap_err();
        assert!(message.contains("\"scratch/cache\""), "{message}");
    }

    #[test]
    fn a_derived_value_reports_the_answer_its_user_must_supply() {
        // `sccache_dir` is unanswerable until `scratch_root` is answered, so the
        // name reported is the one the user can act on, not the derived one.
        let scratch = a_decl("scratch_root", ValueKind::Path);
        let mut sccache = a_decl("sccache_dir", ValueKind::Path);
        sccache.default = Some(AssignedValue::String("{{scratch_root}}/x".to_string()));

        let values = resolve(vec![scratch, sccache], &[]).unwrap();

        assert!(values.get("sccache_dir").is_none());
        let blocked = values
            .substitute("cache is at {{sccache_dir}}")
            .unwrap_err();
        assert_eq!(
            blocked,
            Unresolved::Unset {
                names: vec!["scratch_root".to_string()]
            }
        );
    }

    #[test]
    fn declarations_enumerate_in_declaration_order() {
        let names = ["scratch_root", "bun_root", "agent_slice", "git_name"];
        let decls = names
            .iter()
            .map(|name| a_decl(name, ValueKind::String))
            .collect();

        let values = resolve(decls, &[]).unwrap();

        assert_eq!(
            values
                .decls()
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            names,
            "not sorted, not hashed: the order the layers declared them in"
        );
    }

    #[test]
    fn unset_required_values_are_listed_in_declaration_order() {
        let mut scratch = a_decl("scratch_root", ValueKind::Path);
        scratch.required = true;
        let optional = a_decl("agent_slice", ValueKind::String);
        let mut email = a_decl("git_email", ValueKind::Email);
        email.required = true;

        let values = resolve(
            vec![scratch, optional, email],
            &[answer("git_email", "someone@example.invalid")],
        )
        .unwrap();

        assert_eq!(
            values
                .unset_required()
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            ["scratch_root"],
            "answered required values and unset optional ones are both absent"
        );
        assert_eq!(
            values
                .unset()
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            ["scratch_root", "agent_slice"],
            "doctor lists every unanswered value, required or not"
        );
    }

    #[test]
    fn a_derived_value_is_not_prompted_for_in_its_own_right() {
        // `cache` cannot be answered usefully: `bx init` would pre-fill the
        // literal `{{root}}/cache`, which its own validator then rejects. The
        // blocked entry names only `root`, and the prompt list agrees with it.
        let mut root = a_decl("root", ValueKind::Path);
        root.required = true;
        let mut cache = a_decl("cache", ValueKind::Path);
        cache.required = true;
        cache.default = Some(AssignedValue::String("{{root}}/cache".to_string()));

        let values = resolve(vec![root, cache], &[]).unwrap();

        assert_eq!(
            values.unset_required_names(),
            ["root"],
            "one question, not two, and the one that can be answered"
        );
        assert_eq!(
            values
                .unset()
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            ["root", "cache"],
            "doctor still lists everything with no answer, whatever the reason"
        );
        assert_eq!(
            values.substitute("{{cache}}").unwrap_err(),
            Unresolved::Unset {
                names: vec!["root".to_string()]
            },
            "which is what the blocked entry already said"
        );
    }

    #[test]
    fn unset_required_names_returns_names_not_a_flag() {
        // A report has to say *which* value is missing or the user cannot act.
        let mut scratch = a_decl("scratch_root", ValueKind::Path);
        scratch.required = true;
        let mut email = a_decl("git_email", ValueKind::Email);
        email.required = true;

        let values = resolve(vec![scratch, email], &[]).unwrap();

        assert_eq!(
            values.unset_required_names(),
            ["scratch_root", "git_email"],
            "declaration order, and names rather than a boolean"
        );
    }

    #[test]
    fn roots_are_declaration_ordered_and_absolute() {
        let mut scratch = a_decl("scratch_root", ValueKind::Path);
        scratch.is_root = true;
        let not_a_root = a_decl("brew_prefix", ValueKind::Path);
        let mut sccache = a_decl("sccache_dir", ValueKind::Path);
        sccache.is_root = true;

        let values = resolve(
            vec![scratch, not_a_root, sccache],
            &[
                answer("scratch_root", "~/scratch/./one"),
                answer("brew_prefix", "/home/linuxbrew/.linuxbrew"),
                answer("sccache_dir", "/var/mnt/other/sccache"),
            ],
        )
        .unwrap();

        assert_eq!(
            values.roots(),
            [
                PathBuf::from("/var/home/example/scratch/one"),
                PathBuf::from("/var/mnt/other/sccache"),
            ],
            "expanded, normalised, declaration-ordered, and only the declared roots"
        );
    }

    #[test]
    fn an_unanswered_root_contributes_no_root() {
        // A declaration nobody filled in must not widen the guard on the
        // strength of an intention.
        let mut scratch = a_decl("scratch_root", ValueKind::Path);
        scratch.is_root = true;
        let mut sccache = a_decl("sccache_dir", ValueKind::Path);
        sccache.is_root = true;

        let values = resolve(
            vec![scratch, sccache],
            &[answer("sccache_dir", "/var/mnt/other/sccache")],
        )
        .unwrap();

        assert_eq!(values.roots(), [PathBuf::from("/var/mnt/other/sccache")]);
    }

    #[test]
    fn resolved_values_report_the_home_they_were_resolved_against() {
        // `env_guard` needs `$HOME` in its root set and it has to be the *same*
        // home the path values were expanded with, so the home travels inside
        // the values rather than being read from the environment again.
        let mut scratch = a_decl("scratch_root", ValueKind::Path);
        scratch.is_root = true;

        let values = resolve(vec![scratch], &[answer("scratch_root", "~/scratch")]).unwrap();

        assert_eq!(values.home(), a_home());
        assert_eq!(values.roots(), [a_home().join("scratch")]);
    }

    #[test]
    fn a_declaration_and_its_answer_are_both_reachable_by_name() {
        let decl = a_decl("agent_slice", ValueKind::String);

        let values = resolve(vec![decl], &[answer("agent_slice", "work.slice")]).unwrap();

        assert_eq!(values.decl("agent_slice").unwrap().kind, ValueKind::String);
        assert_eq!(values.get("agent_slice").unwrap().text, "work.slice");
        assert!(values.decl("never_declared").is_none());
        assert!(values.get("never_declared").is_none());
    }

    #[test]
    fn a_boolean_answer_resolves_through_the_same_path_as_a_string() {
        let decl = a_decl("is_desktop", ValueKind::Bool);
        let assignment = ValueAssignment {
            name: "is_desktop".to_string(),
            value: AssignedValue::Bool(true),
            origin: Origin::unknown(Path::new("local.toml")),
        };

        let values = resolve(vec![decl], &[assignment]).unwrap();

        assert_eq!(values.get("is_desktop").unwrap().text, "true");
    }

    #[test]
    fn an_answer_for_a_value_no_layer_declares_is_ignored() {
        // Deliberately not fatal. An account's `local.toml` outlives the repo
        // that declared what it answers, so a repo update that drops a
        // declaration must not stop that account applying anything at all. It is
        // detectable rather than silent — the value the account meant to answer
        // is still reported as unset — and listing the leftovers is doctor's.
        let mut decl = a_decl("scratch_root", ValueKind::Path);
        decl.required = true;

        let values = resolve(vec![decl], &[answer("scratch_roott", "/var/mnt/x")]).unwrap();

        assert_eq!(values.unset_required_names(), ["scratch_root"]);
        assert!(values.get("scratch_roott").is_none());
    }

    #[test]
    fn resolving_twice_is_byte_identical() {
        // Invariant 3: the resolution is a pure function of the declarations,
        // the answers and the home.
        let decls = || {
            let mut scratch = a_decl("scratch_root", ValueKind::Path);
            scratch.is_root = true;
            let mut sccache = a_decl("sccache_dir", ValueKind::Path);
            sccache.default = Some(AssignedValue::String("{{scratch_root}}/s".to_string()));
            vec![scratch, sccache, a_decl("git_name", ValueKind::String)]
        };
        let answers = [answer("scratch_root", "/var/mnt/scratch/one")];

        let first = resolve(decls(), &answers).unwrap();
        let second = resolve(decls(), &answers).unwrap();

        assert_eq!(format!("{first:#?}"), format!("{second:#?}"));
    }

    // --- substitution -------------------------------------------------------

    /// Values for the substitution tests: one answered, one not.
    fn substitution_values() -> ResolvedValues {
        let scratch = a_decl("scratch_root", ValueKind::Path);
        let unanswered = a_decl("git_name", ValueKind::String);
        let braced = a_decl("braced", ValueKind::String);
        resolve(
            vec![scratch, unanswered, braced],
            &[
                answer("scratch_root", "/var/mnt/scratch/one"),
                // Escaped, so the stored text is a literal brace pair: an answer
                // is itself substituted once, at its own declaration's position.
                answer("braced", "{{{{scratch_root}}"),
            ],
        )
        .unwrap()
    }

    #[test]
    fn a_single_placeholder_is_substituted() {
        let values = substitution_values();

        assert_eq!(
            values
                .substitute("export CARGO_HOME={{scratch_root}}/cargo")
                .unwrap(),
            "export CARGO_HOME=/var/mnt/scratch/one/cargo"
        );
    }

    #[test]
    fn two_placeholders_in_one_field_are_substituted() {
        let values = substitution_values();

        assert_eq!(
            values
                .substitute("{{scratch_root}}:{{scratch_root}}")
                .unwrap(),
            "/var/mnt/scratch/one:/var/mnt/scratch/one"
        );
    }

    #[test]
    fn text_with_no_placeholder_is_returned_unchanged() {
        let values = substitution_values();

        assert_eq!(values.substitute("").unwrap(), "");
        assert_eq!(values.substitute("plain text").unwrap(), "plain text");
    }

    #[test]
    fn four_braces_are_a_literal_two() {
        // The operator's own files contain literal brace pairs — a GitHub
        // workflow's expression syntax, a handlebars template — so there has to
        // be a way to write one.
        let values = substitution_values();

        assert_eq!(
            values.substitute("{{{{scratch_root}}").unwrap(),
            "{{scratch_root}}"
        );
        assert_eq!(values.substitute("{{{{}}").unwrap(), "{{}}");
        assert_eq!(
            values.substitute("a{{{{b{{scratch_root}}").unwrap(),
            "a{{b/var/mnt/scratch/one"
        );
    }

    #[test]
    fn an_unmatched_closing_brace_is_content() {
        // There is no escape for a closing pair and none is needed: a closing
        // pair is only special once a placeholder is open.
        let values = substitution_values();

        assert_eq!(values.substitute("a}}b").unwrap(), "a}}b");
        assert_eq!(values.substitute("}}").unwrap(), "}}");
        assert_eq!(
            values.substitute("{{scratch_root}}}}").unwrap(),
            "/var/mnt/scratch/one}}"
        );
    }

    #[test]
    fn an_unterminated_placeholder_is_an_error() {
        let values = substitution_values();

        assert!(matches!(
            values.substitute("{{scratch_root").unwrap_err(),
            Unresolved::Malformed(PlaceholderError::Unterminated { at: 0 })
        ));
        assert!(matches!(
            values.substitute("ok {{x").unwrap_err(),
            Unresolved::Malformed(PlaceholderError::Unterminated { at: 3 })
        ));
    }

    #[test]
    fn a_placeholder_with_illegal_name_characters_is_an_error() {
        let values = substitution_values();

        for bad in [
            "{{Scratch}}",
            "{{scratch-root}}",
            "{{ scratch_root }}",
            "{{}}",
        ] {
            assert!(
                matches!(
                    values.substitute(bad).unwrap_err(),
                    Unresolved::Malformed(PlaceholderError::IllegalName { .. })
                ),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn a_nested_placeholder_is_an_error_not_an_expansion() {
        let values = substitution_values();

        let error = values.substitute("{{a{{scratch_root}}}}").unwrap_err();

        assert!(
            matches!(
                &error,
                Unresolved::Malformed(PlaceholderError::IllegalName { name, .. })
                    if name == "a{{scratch_root"
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_substituted_value_is_not_rescanned() {
        // `braced` holds the literal text of a placeholder. Substituting it
        // yields that text verbatim rather than expanding it a second time: one
        // pass is what keeps this a name lookup rather than a template language.
        let values = substitution_values();

        assert_eq!(values.get("braced").unwrap().text, "{{scratch_root}}");
        assert_eq!(values.substitute("{{braced}}").unwrap(), "{{scratch_root}}");
    }

    #[test]
    fn an_answer_is_itself_substituted_once() {
        // Which is what lets `local.toml` say `sccache_dir =
        // "{{scratch_root}}/sccache"` as well as spelling it out.
        let scratch = a_decl("scratch_root", ValueKind::Path);
        let sccache = a_decl("sccache_dir", ValueKind::Path);

        let values = resolve(
            vec![scratch, sccache],
            &[
                answer("scratch_root", "/var/mnt/scratch/one"),
                answer("sccache_dir", "{{scratch_root}}/sccache"),
            ],
        )
        .unwrap();

        assert_eq!(
            values.get("sccache_dir").unwrap().text,
            "/var/mnt/scratch/one/sccache"
        );
    }

    #[test]
    fn a_placeholder_naming_an_undeclared_value_is_an_error() {
        // A repo typo, unfixable by any answer, so it fails the load rather
        // than blocking a target.
        let values = substitution_values();

        assert_eq!(
            values.substitute("{{nowhere}}").unwrap_err(),
            Unresolved::Undeclared("nowhere".to_string())
        );
    }

    #[test]
    fn an_unanswered_value_is_unset_rather_than_an_error() {
        let values = substitution_values();

        assert_eq!(
            values.substitute("name = {{git_name}}").unwrap_err(),
            Unresolved::Unset {
                names: vec!["git_name".to_string()]
            }
        );
    }

    #[test]
    fn unset_names_come_back_in_declaration_order() {
        let mut first = a_decl("git_name", ValueKind::String);
        first.required = true;
        let mut second = a_decl("git_email", ValueKind::Email);
        second.required = true;
        let values = resolve(vec![first, second], &[]).unwrap();

        // Referenced in the opposite order to the one they were declared in.
        let error = values.substitute("{{git_email}} {{git_name}}").unwrap_err();

        assert_eq!(
            error,
            Unresolved::Unset {
                names: vec!["git_name".to_string(), "git_email".to_string()]
            },
            "two reports of one problem have to read the same way"
        );
    }

    #[test]
    fn substitution_handles_multi_byte_content() {
        // The scanner indexes into the string, so it advances by characters and
        // never splits one.
        let values = substitution_values();

        assert_eq!(
            values.substitute("café → {{scratch_root}} ☕").unwrap(),
            "café → /var/mnt/scratch/one ☕"
        );
        assert_eq!(values.substitute("日本語").unwrap(), "日本語");
    }

    #[test]
    fn placeholders_lists_names_in_order_of_first_appearance() {
        assert_eq!(
            placeholders("{{b}} {{a}} {{b}}").unwrap(),
            ["b", "a"],
            "deduplicated, and in the order they appear"
        );
        assert_eq!(placeholders("none here").unwrap(), Vec::<&str>::new());
        assert_eq!(placeholders("{{{{a}}").unwrap(), Vec::<&str>::new());
        assert!(placeholders("{{A}}").is_err());
    }

    #[test]
    fn init_hint_names_the_values_and_spells_bx_init() {
        // One function spells the invocation, so there is one string to change
        // when `bx init --set` lands.
        assert_eq!(
            init_hint(&["scratch_root", "git_email"]),
            "run `bx init` to set scratch_root, git_email"
        );
        assert!(init_hint(&[]).contains("bx init"));
    }

    // --- the two validation paths are one behaviour -------------------------

    /// The scratch root every brace-bearing case below references.
    const SCRATCH: &str = "/var/mnt/scratch/one";

    /// A two-value configuration: an answered `scratch_root`, then `v`.
    ///
    /// `v` is deliberately left unanswered, so the same fixture serves both the
    /// prompt path — which validates an answer that is not in the file yet — and
    /// the load path, which supplies one.
    fn a_prompt(kind: ValueKind) -> ResolvedValues {
        ResolvedValues::resolve(
            vec![a_decl("scratch_root", ValueKind::Path), a_decl("v", kind)],
            &[answer("scratch_root", SCRATCH)],
            &a_home(),
        )
        .expect("the fixture resolves")
    }

    /// What `bx init` would accept `answer_text` as, for a `v` of `kind`.
    fn through_a_prompt(kind: ValueKind, answer_text: &str) -> Result<String, String> {
        a_prompt(kind)
            .check_answer("v", answer_text)
            .map_err(|e| e.to_string())
    }

    /// What a `local.toml` line answering `v` resolves to.
    fn through_the_loader(kind: ValueKind, answer_text: &str) -> Result<String, String> {
        let values = resolve(
            vec![a_decl("scratch_root", ValueKind::Path), a_decl("v", kind)],
            &[answer("scratch_root", SCRATCH), answer("v", answer_text)],
        )?;
        values
            .get("v")
            .map(|value| value.text.clone())
            .ok_or_else(|| values.invalid_hint(&["v".to_string()]))
    }

    /// Every kind, with an answer it accepts and one it does not.
    ///
    /// The brace-bearing rows are the ones that matter: an answer is resolved as
    /// *expand, then check*, and a validator that did only half of that accepted
    /// `Someone {{Nested}}` and rejected `{{scratch_root}}/sccache`.
    const KIND_CASES: [(ValueKind, &str, Option<&str>); 9] = [
        (ValueKind::Path, "~/scratch/./one", Some("relative/path")),
        (ValueKind::String, "anything at all", None),
        (ValueKind::Bool, "TRUE", Some("yes")),
        (ValueKind::Email, "someone@example.invalid", Some("someone")),
        (
            ValueKind::SshKey,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample",
            Some("not-a-key"),
        ),
        (
            ValueKind::AgeRecipient,
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
            Some("age1BAD"),
        ),
        // A brace pair a person typed into a prompt, escaped, and one that is
        // not a value name.
        (
            ValueKind::String,
            "Someone {{{{Nested}}",
            Some("Someone {{Nested}}"),
        ),
        // A reference to an earlier value, and one that never closes.
        (
            ValueKind::Path,
            "{{scratch_root}}/sccache",
            Some("{{scratch_root/sccache"),
        ),
        // A reference to a value no layer declares is a repo defect either way.
        (ValueKind::String, "{{{{scratch_root}}", Some("{{nowhere}}")),
    ];

    #[test]
    fn a_prompt_accepts_what_the_loader_accepts() {
        // `bx init` validating a typed answer and bx validating a `local.toml`
        // line are one behaviour, not two that happen to agree.
        for (kind, good, _) in KIND_CASES {
            let prompted = through_a_prompt(kind, good).unwrap_or_else(|e| panic!("{kind}: {e}"));
            let loaded = through_the_loader(kind, good).unwrap_or_else(|e| panic!("{kind}: {e}"));
            assert_eq!(
                prompted, loaded,
                "{kind} disagreed about the canonical text for {good:?}"
            );
        }
    }

    #[test]
    fn a_prompt_rejects_what_the_loader_rejects() {
        for (kind, _, bad) in KIND_CASES {
            let Some(bad) = bad else {
                continue; // every string is a string; there is nothing to reject
            };
            assert!(
                through_a_prompt(kind, bad).is_err(),
                "{kind} accepted {bad:?} at a prompt"
            );
            assert!(
                through_the_loader(kind, bad).is_err(),
                "{kind} accepted {bad:?} from a file"
            );
        }
    }

    #[test]
    fn a_prompt_expands_a_reference_to_an_earlier_value() {
        // The spelling the design documents as valid, and the one a check
        // without the expansion refused outright.
        assert_eq!(
            through_a_prompt(ValueKind::Path, "{{scratch_root}}/sccache").unwrap(),
            "/var/mnt/scratch/one/sccache"
        );
    }

    #[test]
    fn a_prompt_refuses_a_brace_pair_that_is_not_a_reference() {
        // `bx init` has no escaping step, so an answer it accepts is written to
        // `local.toml` verbatim. Accepting this would make every later `bx plan`
        // and `bx apply` fail at load, which is not the blocked-target
        // degradation an unanswered value gets.
        let message = through_a_prompt(ValueKind::String, "Someone {{Nested}}").unwrap_err();

        assert!(message.contains("is not a value name"), "{message}");
    }

    #[test]
    fn a_prompt_refuses_a_reference_to_a_later_value() {
        // Resolution is one pass in declaration order, so an answer may only
        // reach backwards — the same rule the loader applies to a `default`.
        let values = ResolvedValues::resolve(
            vec![
                a_decl("v", ValueKind::Path),
                a_decl("later", ValueKind::Path),
            ],
            &[],
            &a_home(),
        )
        .unwrap();

        let message = values
            .check_answer("v", "{{later}}/x")
            .unwrap_err()
            .to_string();

        assert!(message.contains("is declared later"), "{message}");
    }

    #[test]
    fn a_prompt_refuses_an_answer_that_references_its_own_value() {
        // A self reference is the shortest cycle, and the loader refuses it as
        // a forward reference because a value is not resolvable from its own
        // position. The prompt has to refuse it the same way, whether or not the
        // value already has an answer to read back.
        let unanswered = a_prompt(ValueKind::String);
        let answered = resolve(
            vec![
                a_decl("scratch_root", ValueKind::Path),
                a_decl("v", ValueKind::String),
            ],
            &[answer("scratch_root", SCRATCH), answer("v", "earlier")],
        )
        .unwrap();

        for values in [&unanswered, &answered] {
            assert_eq!(
                values.check_answer("v", "{{v}}"),
                Err(AnswerError::Reference(Unresolved::Forward("v".to_string())))
            );
            assert_eq!(
                values.check_answer("v", "again {{v}}/x"),
                Err(AnswerError::Reference(Unresolved::Forward("v".to_string())))
            );
        }

        let loaded = through_the_loader(ValueKind::String, "{{v}}")
            .expect_err("the loader refuses a self reference");
        assert!(loaded.contains("is declared later"), "{loaded}");
        assert!(loaded.contains("local.toml:2"), "{loaded}");
    }

    #[test]
    fn a_prompt_for_an_undeclared_value_says_so() {
        let message = through_a_prompt(ValueKind::String, "anything");
        assert!(message.is_ok(), "the fixture declares `v`");

        let message = a_prompt(ValueKind::String)
            .check_answer("nowhere", "anything")
            .unwrap_err()
            .to_string();

        assert!(
            message.contains("no layer declares the value `nowhere`"),
            "{message}"
        );
    }

    #[test]
    fn a_prompt_for_a_switched_off_value_says_so() {
        // A declaration a layer switched off is not one of this account's
        // values: the loader never reads an answer for it, so a prompt that
        // accepted one would write a line that does nothing.
        let mut scratch = a_decl("scratch", ValueKind::Path);
        scratch.enabled = false;
        let values = ResolvedValues::resolve(vec![scratch], &[], &a_home()).unwrap();

        assert_eq!(
            values.check_answer("scratch", "/var/mnt/other"),
            Err(AnswerError::Reference(Unresolved::Disabled {
                names: vec!["scratch".to_string()]
            })),
            "switched off, which is cleared by a different act than undeclared"
        );
    }

    #[test]
    fn a_prompt_reports_an_earlier_value_that_needs_answering_first() {
        // Not an invalid answer: the name the account has to supply before this
        // one can be validated at all.
        let values = ResolvedValues::resolve(
            vec![
                a_decl("scratch_root", ValueKind::Path),
                a_decl("v", ValueKind::Path),
            ],
            &[],
            &a_home(),
        )
        .unwrap();

        assert_eq!(
            values.check_answer("v", "{{scratch_root}}/sccache"),
            Err(AnswerError::Reference(Unresolved::Unset {
                names: vec!["scratch_root".to_string()]
            }))
        );
    }

    /// A value name is `[a-z][a-z0-9_]*`, in a declaration and in `[values]`.
    ///
    /// `""`, `"a b"` and `"{{x}}"` all parsed as declaration names. One name is
    /// written three ways, as a `[values]` bare key, inside a `{{name}}`
    /// reference and as a `bx init` prompt label, and a name that needs quoting
    /// in any of them, or carries the substitution braces itself, can never be
    /// referenced.
    #[test]
    fn a_value_name_must_be_an_identifier() {
        for bad in [
            "",
            "a b",
            "{{x}}",
            "A",
            "1st",
            "_x",
            "git-email",
            "a.b",
            "é",
            "a\\tb",
        ] {
            let text = format!("[[value]]\nname = \"{bad}\"\nkind = \"string\"\n");
            let declared = message(decl(&text));
            assert!(
                declared.contains("is not a value name"),
                "{bad:?}: {declared}"
            );
            assert!(declared.contains("bx.toml:2"), "{bad:?}: {declared}");

            let text = format!("[values]\n\"{bad}\" = \"x\"\n");
            let assigned = message(assignments(&text));
            assert!(
                assigned.contains("is not a value name"),
                "[values] {bad:?}: {assigned}"
            );
        }
        for good in ["a", "git_email", "scratch_root2", "a_1_b"] {
            let text = format!("[[value]]\nname = \"{good}\"\nkind = \"string\"\n");
            assert_eq!(decl(&text).unwrap().name, good);
            let text = format!("[values]\n{good} = true\n");
            assert_eq!(assignments(&text).unwrap()[0].name, good);
        }
    }

    /// `is_root` is only legal on a path.
    ///
    /// `is_root = true` on `kind = "bool"` parsed. The flag admits a directory
    /// into the env_guard root set, so on any other kind it would widen the
    /// guard on the strength of a value that is not a directory.
    #[test]
    fn is_root_is_only_legal_on_a_path() {
        for kind in ["string", "bool", "email", "ssh-key", "age-recipient"] {
            let text = format!("[[value]]\nname = \"v\"\nkind = \"{kind}\"\nis_root = true\n");
            let message = message(decl(&text));
            assert!(
                message.contains("only legal on `kind = \"path\"`"),
                "{kind}: {message}"
            );
            assert!(message.contains("bx.toml:4"), "{kind}: {message}");

            // `false` claims nothing, so it is allowed on every kind.
            let text = format!("[[value]]\nname = \"v\"\nkind = \"{kind}\"\nis_root = false\n");
            assert!(!decl(&text).unwrap().is_root, "{kind}");
        }
        let text = "[[value]]\nname = \"v\"\nkind = \"path\"\nis_root = true\n";
        assert!(decl(text).unwrap().is_root);
    }
}
