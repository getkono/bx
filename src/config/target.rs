//! A target: one path in the user's environment that bx has something to say about.
//!
//! # The `[[target]]` schema
//!
//! ```toml
//! [[target]]
//! path       = "~/.config/starship.toml"        # required; the natural key
//! file       = "files/starship.toml"            # body, repo-relative     )
//! content    = "…"                              # body, verbatim literal  ) exactly
//! generated  = "shell-init"                     # body, named generator   ) one of
//! secret     = "secrets/npmrc.age"              # body, age ciphertext    )
//! dir        = true                             # the target is a directory )
//! mode       = "0600"                           # optional octal *string*;
//!                                               #   required, and private, for a secret
//! attach     = "own"                            # own | region | include; default own
//! comment    = "#"                              # required iff attach = "region"
//! include    = "Include ~/.ssh/config.d/*.conf" # required iff attach = "include"
//!                                               #   one line, not blank; no body key
//!                                               #   beside it, the line *is* the body
//! direction  = "apply"                          # apply | track; default apply
//! format     = "opaque"                         # opaque | jsonc | env.d; default opaque
//!                                               #   jsonc and env.d need attach = "own"
//! owns       = ["agent.default_model"]          # required and non-empty iff format = "jsonc"
//! requires   = ["starship"]                     # default []
//! references = ["~/.gitconfig.local"]           # default []
//! enabled    = true                             # default true
//! ```
//!
//! # Why the discriminant keys are flat
//!
//! `attach = "region"` with a sibling `comment = "#"`, not
//! `attach = { kind = "region", comment = "#" }`. Hand-editing a config file and
//! running a `bx` command have to be the same operation, and flat scalar keys are
//! what `toml_edit` edits surgically without reflowing a nested table — and what
//! a human types. A companion key without its discriminant is an error, so the
//! flat form cannot silently ignore a key.

use std::fmt;
use std::path::{Path, PathBuf};

use toml_edit::Table;

use super::{Ctx, Error, Origin};
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[target]]";

/// Every key a `[[target]]` entry may carry.
const KEYS: [&str; 16] = [
    "path",
    "file",
    "content",
    "generated",
    "secret",
    "dir",
    "mode",
    "attach",
    "comment",
    "include",
    "direction",
    "format",
    "owns",
    "requires",
    "references",
    "enabled",
];

/// The keys that declare a body. Exactly one, except for an `include` target.
const BODY_KEYS: [&str; 5] = ["file", "content", "generated", "secret", "dir"];

/// One path in the user's environment that bx has something to say about.
///
/// Its natural key is [`Target::path`]: a later layer whose target has a path
/// already present replaces that target in place, which is entry A3's merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Where it lands, home-relative.
    pub path: Portable,
    /// What goes there.
    pub body: Body,
    /// Explicit octal mode. `None` means [`Mode::DEFAULT_FILE`] for a file and
    /// [`Mode::DEFAULT_DIR`] for a directory — applying that default is entry
    /// A5's, so the model records the absence rather than guessing.
    pub mode: Option<Mode>,
    /// How bx attaches to the file.
    pub attach: Attach,
    /// Whether bx writes the file or only watches it.
    pub direction: Direction,
    /// How much of the file bx claims.
    pub format: Format,
    /// Tool names this target is gated on.
    pub requires: Vec<String>,
    /// Paths named inside the content, so drift in them can be reported.
    pub references: Vec<Portable>,
    /// `false` in any layer removes the target from the resolved configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// What a target's content is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// A file in the config repo, named repo-relative.
    File(PathBuf),
    /// A literal written in the config file itself.
    Inline(String),
    /// Produced by a named generator.
    Generated(Gen),
    /// An age-encrypted file in the config repo, named repo-relative, whose
    /// plaintext is the content. Decrypted in-process by [`crate::secret`].
    Secret(PathBuf),
    /// The target is a directory: it has a mode and no content.
    Dir,
}

/// The generators a target's body can be produced by.
///
/// **Empty at this entry, and that is honest**: nothing generates anything yet,
/// so every `generated = "…"` is an unknown generator and a parse error naming
/// its origin. Each generating entry adds one variant here and one arm in
/// [`parse_generated`], keyed by the string a config author writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gen {}

/// Resolve the name a config author wrote as `generated = "…"`.
///
/// Returns `None` for every name, because [`Gen`] has no variants yet.
#[must_use]
pub fn parse_generated(_name: &str) -> Option<Gen> {
    // `Gen` has no variants, so there is nothing any name could resolve to.
    // Each generating entry adds its variant and a `match` arm here together.
    None
}

/// A file mode, as an octal bit pattern.
///
/// **This is the file mode, not the plan/apply mode.** Entry A7 declares its own
/// `Mode { Plan, Apply }` in its own module; the two are never re-exported into
/// one scope.
///
/// Declared once, in [`crate::fs::mode`], and named here because that is where
/// the config schema needs it: a target's `mode` key, the mode the writer sets,
/// and the mode the ledger records are one type, so a mode a config author wrote
/// means the same thing as a mode `stat` reported. `parse_octal`, `ModeError`
/// and the four-digit `Display` are unchanged by the move.
///
/// One type does not mean one encoding. Deserialising a `[[target]]` accepts
/// only the **quoted** octal form, `mode = "0600"`; a bare `mode = 600` is
/// refused with the decimal it would have meant. The bare-integer encoding the
/// ledger writes is reachable only from a non-human-readable format, and never
/// from a config file.
pub use crate::fs::mode::{Mode, ModeError};

/// How bx attaches to a file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Attach {
    /// The whole file is bx's.
    #[default]
    Own,
    /// A delimited region inside a file the user also writes.
    Region {
        /// The comment character of the file's syntax.
        comment: char,
    },
    /// A single line inserted into the user's own file.
    Include {
        /// The line, verbatim.
        line: String,
    },
}

/// Whether bx writes a file or only watches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// bx writes it.
    #[default]
    Apply,
    /// The tool writes it; bx reports drift and never touches it.
    Track,
}

/// How much of a file bx claims.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Format {
    /// The file is bytes; bx claims all of what it attaches to.
    #[default]
    Opaque,
    /// JSON with comments; bx owns only the listed keys.
    Jsonc {
        /// The key paths bx owns. Everything else in the file is the user's.
        owns: Vec<KeyPath>,
    },
    /// One fragment file in a `conf.d`-style directory of environment settings.
    ///
    /// A `Format` describes the file a target's `path` names, so this is the
    /// fragment, not the directory holding it: bx owns the whole fragment and
    /// says nothing about its neighbours. What the fragment's syntax is, and
    /// how the directory is assembled, belong to the entry that generates one.
    EnvD,
}

/// A dotted path to a key inside a structured file.
///
/// Split on `.`, with no escape syntax: a key containing a literal dot is not
/// expressible yet, and entry C3 extends [`KeyPath::parse`] when it needs one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyPath(Vec<String>);

impl KeyPath {
    /// Split a dotted key path.
    ///
    /// # Errors
    ///
    /// [`KeyPathError::EmptySegment`] if any segment is empty, including the
    /// empty string itself. `a..b` is a typo, not a key.
    pub fn parse(raw: &str) -> Result<Self, KeyPathError> {
        if raw.split('.').any(str::is_empty) {
            return Err(KeyPathError::EmptySegment(raw.to_string()));
        }
        Ok(Self(raw.split('.').map(str::to_string).collect()))
    }

    /// The segments, outermost first.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

/// A key path that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyPathError {
    /// A segment between two dots, or at either end, was empty.
    #[error("a key path may not have an empty segment, got {0:?}")]
    EmptySegment(String),
}

/// Parse one `[[target]]` entry.
///
/// Exposed for entry A3, which parses a single entry out of a layer it is
/// merging without going through a whole document.
///
/// `text` is the whole layer file, because spans index into it. `home` is the
/// account's home directory: a target path is parsed against it so that a file
/// under the home has exactly one spelling, `~/…`, and cannot acquire a second
/// key by being written absolutely somewhere else in the layer set. See
/// [`Portable::parse_in`]. It also decides which paths are the home or above
/// it, where only a `dir = true` target may point.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_target(table: &Table, file: &Path, text: &str, home: &Path) -> Result<Target, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let raw_path = ctx.required_str(table, "path")?;
    let path =
        Portable::parse_in(raw_path, home).map_err(|e| ctx.bad(table, "path", e.to_string()))?;

    let attach = parse_attach(&ctx, table)?;
    let body = parse_body(&ctx, table, &attach)?;
    let mode = parse_mode(&ctx, table)?;
    let direction = parse_direction(&ctx, table)?;
    let format = parse_format(&ctx, table)?;

    // The home and every directory above it, the filesystem root included, are
    // directories. A file body at any of them is an `own` claim on a directory
    // as if it were a file, which no writer can honour. Resolution re-applies
    // this to the path a placeholder substitution produced.
    refuse_file_at_home_or_above(raw_path, &path, &body, home)
        .map_err(|message| ctx.bad(table, "path", message))?;

    if body == Body::Dir {
        // The same rule the flat discriminant keys already follow elsewhere: a
        // companion key that cannot mean anything is an error, not a key that is
        // quietly ignored. `parse_attach` rejects `comment` without a region and
        // `parse_format` rejects `owns` without jsonc; this is the third pair.
        if attach != Attach::Own {
            return Err(ctx.bad(
                table,
                "attach",
                "a directory target is always attached as `own`: there is no content \
                 to delimit a region in and no file to insert a line into",
            ));
        }
        if format != Format::Opaque {
            return Err(ctx.bad(
                table,
                "format",
                "a directory target has no content, so `format` has nothing to describe",
            ));
        }
    }

    if matches!(body, Body::Secret(_)) {
        check_secret(&ctx, table, mode, &attach, &format)?;
    }

    if matches!(&format, Format::Jsonc { owns } if owns.is_empty()) {
        // `Jsonc { owns: [] }` says bx manages part of a file and names no part:
        // every run a silent no-op. Checked here rather than in `parse_format`
        // so a directory target's more specific message above still wins.
        return Err(ctx.bad(
            table,
            "format",
            "format = \"jsonc\" claims only the keys `owns` lists, so it needs at least \
             one key in `owns`; with none the target claims nothing",
        ));
    }

    if format != Format::Opaque && attach != Attach::Own {
        // `Format` says how much of the file a target's `path` names bx claims:
        // `jsonc` the listed keys of a whole JSON document, `env.d` a whole
        // fragment. A region is a delimited span inside a file the user also
        // writes and an include is one line in it; neither is a JSON document or
        // a fragment, so the pair would claim two contradictory things about one
        // file and entry A5 would have to drop one of them silently. The raw
        // spellings are re-read because both keys have already been validated.
        let kind = ctx.str_at(table, "format")?.unwrap_or("opaque");
        let how = ctx.str_at(table, "attach")?.unwrap_or("own");
        return Err(ctx.bad(
            table,
            "format",
            format!(
                "format = {kind:?} describes a whole file bx owns, so it needs attach = \"own\"; \
                 this target is attached as {how:?}, which is part of a file the user also \
                 writes. Use format = \"opaque\", or attach = \"own\""
            ),
        ));
    }

    let requires = ctx.str_array_at(table, "requires")?;
    let references = ctx
        .str_array_at(table, "references")?
        .iter()
        .map(|raw| Portable::parse_in(raw, home))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ctx.bad(table, "references", e.to_string()))?;

    Ok(Target {
        path,
        body,
        mode,
        attach,
        direction,
        format,
        requires,
        references,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// The rules a secret target is held to at load time.
///
/// **A private mode, written out.** A secret with no `mode` would be written at
/// [`Mode::DEFAULT_FILE`], `0644`, which every account on the machine can read,
/// and a default that silently publishes a secret is the one default this key
/// may not have. So the mode is required, and it must deny group and other
/// everything — and let its owner read, or the next `plan` could not compare
/// what `apply` wrote.
///
/// **The whole file.** A region or an include line is part of a file the user
/// also writes, at whatever mode the user gave it, and a structured format owns
/// keys inside one; none of them can keep plaintext private. An include target
/// already cannot carry a second body, so only a region and a format arrive
/// here.
fn check_secret(
    ctx: &Ctx,
    table: &Table,
    mode: Option<Mode>,
    attach: &Attach,
    format: &Format,
) -> Result<(), Error> {
    let Some(mode) = mode else {
        return Err(ctx.bad(
            table,
            "secret",
            "a secret target needs an explicit private `mode`, such as mode = \"0600\"; \
             without one it would be written readable by every account on the machine",
        ));
    };
    if mode.is_shared() || mode.bits() & 0o400 == 0 {
        return Err(ctx.bad(
            table,
            "mode",
            format!(
                "a secret target's mode must let its owner read it and deny group and other \
                 everything, such as \"0600\" or \"0400\"; got \"{mode}\""
            ),
        ));
    }
    if *attach != Attach::Own {
        return Err(ctx.bad(
            table,
            "attach",
            "a secret target is always attached as `own`: a region is part of a file the \
             user also writes, at a mode bx does not choose",
        ));
    }
    if *format != Format::Opaque {
        return Err(ctx.bad(
            table,
            "format",
            "a secret target's plaintext is the whole file, so `format` has nothing to describe",
        ));
    }
    Ok(())
}

/// `attach`, and the companion key its value requires.
fn parse_attach(ctx: &Ctx, table: &Table) -> Result<Attach, Error> {
    let kind = ctx.str_at(table, "attach")?.unwrap_or("own");
    let comment = ctx.str_at(table, "comment")?;
    let include = ctx.str_at(table, "include")?;

    let attach = match kind {
        "own" => Attach::Own,
        "region" => {
            let raw = comment.ok_or_else(|| {
                ctx.bad(
                    table,
                    "attach",
                    "attach = \"region\" needs a `comment` character, so bx knows how to \
                     delimit the region in this file's syntax",
                )
            })?;
            let mut chars = raw.chars();
            let comment = match (chars.next(), chars.next()) {
                (Some(c), None) => c,
                _ => {
                    return Err(ctx.bad(
                        table,
                        "comment",
                        format!("`comment` must be a single character, got {raw:?}"),
                    ));
                }
            };
            // Type-checked is not value-checked. `comment = "\n"` is a single
            // character and produced region delimiters that cannot be found
            // again, so the region stops delimiting anything: bx appends a
            // fresh region on every run, which is Invariant 3, or writes
            // outside the one it meant to, which is Invariant 1. A whitespace
            // comment character is the same defect with a subtler spelling, and
            // so is an invisible one: U+200B ZERO WIDTH SPACE is neither
            // whitespace nor a control character, and a delimiter nobody can see
            // in an editor is one a human deletes. Every comment character a
            // real config syntax uses is visible ASCII, so that is the rule.
            if !comment.is_ascii_graphic() {
                return Err(ctx.bad(
                    table,
                    "comment",
                    format!(
                        "`comment` starts the delimiter lines bx has to find again, so it \
                         must be a visible ASCII character: not whitespace or a control \
                         character, and nothing outside ASCII; got {raw:?}"
                    ),
                ));
            }
            Attach::Region { comment }
        }
        "include" => {
            let line = include.ok_or_else(|| {
                ctx.bad(
                    table,
                    "attach",
                    "attach = \"include\" needs an `include` line to insert",
                )
            })?;
            // The key is called `include` and holds one *line*: entry A5 finds
            // it again by looking for it in the file. An empty line matches
            // every blank line in `~/.ssh/config`, or is appended on every run
            // — Invariant 3 either way. A value bearing a line terminator is
            // not one line, so no line-wise search finds it whole; a multi-line
            // insertion is `attach = "region"`, which has delimiters for
            // exactly that reason.
            // A line of only spaces or tabs is the empty line with a subtler
            // spelling: it matches every blank line too.
            if line.trim().is_empty() || line.contains(['\n', '\r']) {
                return Err(ctx.bad(
                    table,
                    "include",
                    format!(
                        "`include` is the single line bx inserts and finds again, so it may \
                         not be empty or span lines; for a multi-line insertion use \
                         attach = \"region\". Got {line:?}"
                    ),
                ));
            }
            Attach::Include {
                line: line.to_string(),
            }
        }
        other => {
            return Err(ctx.bad(
                table,
                "attach",
                format!("`attach` must be \"own\", \"region\" or \"include\", got {other:?}"),
            ));
        }
    };

    if comment.is_some() && !matches!(attach, Attach::Region { .. }) {
        return Err(ctx.bad(
            table,
            "comment",
            "`comment` only means something with attach = \"region\"",
        ));
    }
    if include.is_some() && !matches!(attach, Attach::Include { .. }) {
        return Err(ctx.bad(
            table,
            "include",
            "`include` only means something with attach = \"include\"",
        ));
    }

    Ok(attach)
}

/// Exactly one body key — and for an `include` target, none, because its body
/// *is* its line.
fn parse_body(ctx: &Ctx, table: &Table, attach: &Attach) -> Result<Body, Error> {
    let declared: Vec<&str> = BODY_KEYS
        .iter()
        .copied()
        .filter(|key| table.contains_key(key))
        .collect();

    // The same rule the other companion keys follow: a key that cannot mean
    // anything is an error, not a key that is quietly ignored. An include
    // target's body *is* its `include` line, so a `content`, `file` or
    // `generated` beside it is a second body nothing reads. Taken silently, an
    // author who edits an include target into an own-file target and forgets to
    // change `attach` gets a target whose forty lines of content entry A5 must
    // either drop or insert into a file bx does not own.
    //
    // `dir` is excluded because it already has a stricter rule, applied in
    // `parse_target`: a directory target's only admissible attachment is `own`,
    // whatever else it declares, and that message says so.
    let unreachable = declared.iter().find(|key| **key != "dir");
    if let (Attach::Include { .. }, Some(first)) = (attach, unreachable) {
        return Err(ctx.bad(
            table,
            first,
            format!(
                "attach = \"include\" already declares the only line bx writes, so `{first}` \
                 would never be read; drop it, or set `attach` to \"own\" or \"region\""
            ),
        ));
    }

    match declared.as_slice() {
        [] => match attach {
            // An include target already declares the only line it writes;
            // making it repeat that line as `content` would be ceremony.
            Attach::Include { line } => Ok(Body::Inline(line.clone())),
            _ => Err(Error::MissingKey {
                origin: ctx.origin().clone(),
                section: SECTION,
                key: "file`, `content`, `generated`, `secret` or `dir",
            }),
        },
        [one] => body_from(ctx, table, one),
        many => Err(ctx.bad(
            table,
            many[1],
            format!(
                "a target has exactly one body, but this one declares {}",
                many.iter()
                    .map(|k| format!("`{k}`"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        )),
    }
}

/// A body file is named relative to the config repo root, and stays inside it.
///
/// `path` and `references` are portable paths and are validated as such; `file`
/// is the third path a target carries and needs its own rule. An absolute value
/// would silently discard the repo root the moment it reached `repo.join`, and a
/// climbing one would read a file the repo does not contain — a config repo is
/// meant to be publishable and self-contained, and neither value can be.
///
/// The stored form is normalised, so `files/./a` and `files/a` are one body.
fn repo_relative(ctx: &Ctx, table: &Table, key: &str, raw: &str) -> Result<PathBuf, Error> {
    confine_to_repo(key, raw).map_err(|message| ctx.bad(table, key, message))
}

/// The rule itself, without the provenance to report it against.
///
/// Separate from [`repo_relative`] because it has **two** callers and may not
/// have two implementations. A `file` may carry a `{{name}}`, so what the parser
/// validates is the path as written and what reaches `repo.join` is the path as
/// *substituted*: `cfg/{{account}}/gitconfig` with an answer of `../../../etc`
/// is a repo escape that the parse-time check never sees. [`super::resolve`]
/// re-applies this to the substituted value.
///
/// The message is returned rather than an [`Error`], because the two callers
/// have different provenance to attach: a table and a key, or a target and its
/// origin.
pub(crate) fn confine_to_repo(key: &str, raw: &str) -> Result<PathBuf, String> {
    if names_a_machine_location(raw) {
        return Err(format!(
            "`{key}` names a file inside the config repo, so it is relative to the \
             repo root; got {raw:?}"
        ));
    }

    let mut parts: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!(
                        "`{key}` may not climb out of the config repo; got {raw:?}"
                    ));
                }
            }
            named => parts.push(named),
        }
    }

    if parts.is_empty() {
        return Err(format!(
            "`{key}` must name a file in the config repo; got {raw:?}"
        ));
    }

    Ok(PathBuf::from(parts.join("/")))
}

/// Whether `text` is rooted at the filesystem or the home rather than at the
/// config repo: it opens with `/` or `~`.
///
/// One predicate with two uses. [`confine_to_repo`] asks it of a whole `file`;
/// [`super::resolve`] asks it of each value's text as substituted into one,
/// because `cfg/{{dir}}/x` with `dir` answered `/home/example/…` normalises to
/// a relative path that still carries the account's machine location into the
/// repo.
pub(crate) fn names_a_machine_location(text: &str) -> bool {
    text.starts_with('/') || text.starts_with('~')
}

/// Refuse a file body at the home or at any directory above it.
///
/// The home, its ancestors and `/` are directories, so a file body at one is an
/// `own` claim on a directory as if it were a file, which no writer can honour.
/// Which paths those are is decided lexically from `path` and `home`, never from
/// the disk: `path` is `~`, or the normalised home starts with it component by
/// component, so `/var/home` is above `/var/home/example` and `/var/homes` is
/// not. A `dir = true` target may name any of them.
///
/// No "is `path` under the home?" test is needed beside that comparison, and an
/// earlier shape of this function carried one that could not decide anything. A
/// `Portable` under the home is `~`-rooted; `~` itself is the first operand; and
/// a `~/…` path is never a component prefix of the home, because the home
/// reaching here is always absolute.
///
/// That last clause is a precondition on the **callers**, not a property of any
/// argument's type: a `Path` is free to be relative, and nothing in this
/// signature forbids one. Both callers hold it the same way — each builds a
/// `Portable` against the *same* home before calling, and
/// [`Portable::parse_in`] refuses a home that does not normalise absolute. The
/// `debug_assert!` below states it where it is relied on, so any future caller
/// that does not hold it trips on the first test that reaches here rather than
/// silently reinstating the deleted operand's case.
///
/// Like [`confine_to_repo`] it has two callers: the parser, on the path as
/// written, and [`super::resolve`], on the path a substitution produced, because
/// `~/{{leaf}}` with `leaf` answered `.` is `~`. `shown` is the spelling to
/// quote, and the message is returned for each caller to attach its own
/// provenance.
pub(crate) fn refuse_file_at_home_or_above(
    shown: &str,
    path: &Portable,
    body: &Body,
    home: &Path,
) -> Result<(), String> {
    let home = crate::paths::normalize(home);
    debug_assert!(
        home.is_absolute(),
        "a caller reached refuse_file_at_home_or_above with the non-absolute home {home:?}; \
         against such a home a `~/…` path can be a component prefix, which is the case the \
         deleted `!path.under_home()` operand was thought to cover"
    );
    let at_or_above = path.as_str() == "~" || home.starts_with(path.as_str());
    if *body != Body::Dir && at_or_above {
        return Err(format!(
            "path = {shown:?} is the home directory or a directory above it, so only a \
             `dir = true` target may name it; a file target names a file beneath it"
        ));
    }
    Ok(())
}

/// The body one declared key names.
fn body_from(ctx: &Ctx, table: &Table, key: &str) -> Result<Body, Error> {
    match key {
        "file" => {
            let raw = ctx.required_str(table, "file")?;
            Ok(Body::File(repo_relative(ctx, table, "file", raw)?))
        }
        "content" => Ok(Body::Inline(
            ctx.required_str(table, "content")?.to_string(),
        )),
        "secret" => {
            let raw = ctx.required_str(table, "secret")?;
            Ok(Body::Secret(repo_relative(ctx, table, "secret", raw)?))
        }
        "generated" => {
            let name = ctx.required_str(table, "generated")?;
            parse_generated(name).map(Body::Generated).ok_or_else(|| {
                ctx.bad(
                    table,
                    "generated",
                    format!("no generator named {name:?} exists in this version of bx"),
                )
            })
        }
        _ => match ctx.bool_at(table, "dir")? {
            Some(true) => Ok(Body::Dir),
            _ => Err(ctx.bad(
                table,
                "dir",
                "`dir` declares a directory target and is only ever `true`; \
                 remove the key for a file target",
            )),
        },
    }
}

/// `mode`, which is a quoted octal string or nothing.
fn parse_mode(ctx: &Ctx, table: &Table) -> Result<Option<Mode>, Error> {
    let Some(item) = table.get("mode") else {
        return Ok(None);
    };
    if item.is_integer() {
        return Err(ctx.bad(
            table,
            "mode",
            "`mode` is a quoted octal string: mode = 600 is decimal 600, and \
             TOML's own octal literal is spelled 0o600, which is not how a mode \
             is written anywhere else. Write mode = \"0600\".",
        ));
    }

    let raw = ctx.required_str(table, "mode")?;
    Mode::parse_octal(raw)
        .map(Some)
        .map_err(|e| ctx.bad(table, "mode", e.to_string()))
}

/// `direction`, defaulting to `apply`.
fn parse_direction(ctx: &Ctx, table: &Table) -> Result<Direction, Error> {
    match ctx.str_at(table, "direction")?.unwrap_or("apply") {
        "apply" => Ok(Direction::Apply),
        "track" => Ok(Direction::Track),
        other => Err(ctx.bad(
            table,
            "direction",
            format!("`direction` must be \"apply\" or \"track\", got {other:?}"),
        )),
    }
}

/// `format`, and the `owns` list that `jsonc` must carry and nothing else may.
fn parse_format(ctx: &Ctx, table: &Table) -> Result<Format, Error> {
    let kind = ctx.str_at(table, "format")?.unwrap_or("opaque");
    let owns_declared = table.contains_key("owns");

    if kind != "jsonc" && owns_declared {
        return Err(ctx.bad(
            table,
            "owns",
            "`owns` names the keys bx claims inside a structured file, so it \
             only means something with format = \"jsonc\"",
        ));
    }

    match kind {
        "opaque" => Ok(Format::Opaque),
        "env.d" => Ok(Format::EnvD),
        "jsonc" => {
            let owns = ctx
                .str_array_at(table, "owns")?
                .iter()
                .map(|raw| KeyPath::parse(raw))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ctx.bad(table, "owns", e.to_string()))?;
            Ok(Format::Jsonc { owns })
        }
        other => Err(ctx.bad(
            table,
            "format",
            format!("`format` must be \"opaque\", \"jsonc\" or \"env.d\", got {other:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml_edit::Document;

    /// The account's home every test in this module parses against.
    ///
    /// Deliberately not `/home/<user>`: nothing here may name a real account,
    /// and nothing here may assume where a home lives.
    fn home() -> &'static Path {
        Path::new("/var/home/example")
    }

    /// Parse the first `[[target]]` out of a document, against `home`.
    fn parse_in(text: &str, home: &Path) -> Result<Target, Error> {
        let doc = Document::parse(text).expect("valid TOML");
        let table = doc
            .as_table()
            .get("target")
            .expect("a [[target]]")
            .as_array_of_tables()
            .expect("an array of tables")
            .get(0)
            .expect("one element");
        parse_target(table, Path::new("bx.toml"), text, home)
    }

    /// Parse the first `[[target]]` out of a document.
    fn parse(text: &str) -> Result<Target, Error> {
        parse_in(text, home())
    }

    /// A minimal valid target, plus whatever else the test needs.
    fn with(extra: &str) -> String {
        format!("[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/gitconfig\"\n{extra}")
    }

    fn message(text: &str) -> String {
        parse(text)
            .expect_err("should have been rejected")
            .to_string()
    }

    #[test]
    fn a_minimal_target_parses() {
        let target = parse(&with("")).unwrap();

        assert_eq!(target.path.as_str(), "~/.gitconfig");
        assert_eq!(target.body, Body::File(PathBuf::from("files/gitconfig")));
        assert_eq!(target.mode, None);
        assert_eq!(target.attach, Attach::Own);
        assert_eq!(target.direction, Direction::Apply);
        assert_eq!(target.format, Format::Opaque);
        assert!(target.requires.is_empty());
        assert!(target.references.is_empty());
        assert!(target.enabled);
    }

    #[test]
    fn the_natural_key_is_the_path() {
        assert_eq!(
            parse(&with("")).unwrap().path,
            Portable::parse_in("~/.gitconfig", home()).unwrap()
        );
    }

    #[test]
    fn every_target_carries_its_origin() {
        let text = "# a leading comment\n\n[[target]]\npath = \"~/.gitconfig\"\nfile = \"f\"\n";
        let target = parse(text).unwrap();

        assert_eq!(target.origin.line, 3, "the [[target]] header's own line");
        assert_eq!(target.origin.file, Path::new("bx.toml"));
    }

    #[test]
    fn a_target_with_no_body_is_rejected() {
        let text = "[[target]]\npath = \"~/.gitconfig\"\n";
        assert!(message(text).contains("missing the required key"));
    }

    #[test]
    fn a_target_with_two_bodies_is_rejected() {
        let text = "[[target]]\npath = \"~/.gitconfig\"\nfile = \"f\"\ncontent = \"x\"\n";
        assert!(message(text).contains("exactly one body"));
    }

    #[test]
    fn an_inline_body_is_taken_verbatim() {
        let text =
            "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"\"\"\n[user]\n\tname = x\n\"\"\"\n";
        assert_eq!(
            parse(text).unwrap().body,
            Body::Inline("[user]\n\tname = x\n".to_string())
        );
    }

    #[test]
    fn an_unknown_generator_is_rejected() {
        let text = "[[target]]\npath = \"~/.zshrc\"\ngenerated = \"shell-init\"\n";
        let message = message(text);

        assert!(message.contains("no generator named"), "{message}");
        assert!(message.contains("bx.toml:3"), "{message}");
        assert!(parse_generated("shell-init").is_none());
    }

    #[test]
    fn a_directory_target_declares_itself_a_directory() {
        let text = "[[target]]\npath = \"~/.ssh\"\ndir = true\nmode = \"0700\"\n";
        let target = parse(text).unwrap();

        assert_eq!(target.body, Body::Dir);
        assert_eq!(target.mode, Some(Mode::parse_octal("0700").unwrap()));
    }

    #[test]
    fn a_body_file_must_be_relative_to_the_config_repo() {
        // `repo.join` on an absolute path discards the base, so an absolute
        // `file` would read anywhere on the machine.
        for escaping in ["/etc/shadow", "~/.ssh/id_ed25519", "~other/secrets"] {
            let text = format!("[[target]]\npath = \"~/a\"\nfile = \"{escaping}\"\n");
            assert!(
                message(&text).contains("relative to the repo root"),
                "{escaping} should be rejected"
            );
        }
    }

    #[test]
    fn a_body_file_may_not_climb_out_of_the_config_repo() {
        for escaping in ["../../../etc/shadow", "..", "files/../../outside"] {
            let text = format!("[[target]]\npath = \"~/a\"\nfile = \"{escaping}\"\n");
            assert!(
                message(&text).contains("climb out of the config repo"),
                "{escaping} should be rejected"
            );
        }
    }

    /// A secret target, plus whatever else the test needs.
    fn secret(extra: &str) -> String {
        format!("[[target]]\npath = \"~/.npmrc\"\nsecret = \"secrets/./npmrc.age\"\n{extra}")
    }

    #[test]
    fn a_secret_target_names_its_ciphertext_repo_relative() {
        let target = parse(&secret("mode = \"0600\"\n")).expect("parses");
        assert_eq!(
            target.body,
            Body::Secret(PathBuf::from("secrets/npmrc.age"))
        );
        assert_eq!(target.mode, Some(Mode::PRIVATE_FILE));

        let target = parse(&secret("mode = \"0400\"\n")).expect("read-only is private");
        assert_eq!(target.mode, Some(Mode::from_bits(0o400)));

        for escaping in ["/etc/age/x.age", "~/x.age", "../x.age"] {
            let text =
                format!("[[target]]\npath = \"~/a\"\nsecret = \"{escaping}\"\nmode = \"0600\"\n");
            let message = message(&text);
            assert!(message.contains("`secret`"), "{escaping}: {message}");
        }
    }

    #[test]
    fn a_secret_target_without_a_mode_is_a_load_error() {
        let message = message(&secret(""));
        assert!(
            message.starts_with("bx.toml:3:"),
            "at the secret key: {message}"
        );
        assert!(message.contains("explicit private `mode`"), "{message}");
    }

    #[test]
    fn a_secret_target_with_a_shared_mode_is_a_load_error() {
        for shared in [
            "0640", "0604", "0644", "0660", "0610", "0601", "0200", "0000",
        ] {
            let message = message(&secret(&format!("mode = \"{shared}\"\n")));
            assert!(
                message.starts_with("bx.toml:4:"),
                "at the mode key: {message}"
            );
            assert!(
                message.contains(&format!("got \"{shared}\"")),
                "{shared}: {message}"
            );
        }
    }

    #[test]
    fn a_secret_target_owns_its_whole_file() {
        let region = message(&secret(
            "mode = \"0600\"\nattach = \"region\"\ncomment = \"#\"\n",
        ));
        assert!(region.contains("always attached as `own`"), "{region}");

        let format = message(&secret("mode = \"0600\"\nformat = \"env.d\"\n"));
        assert!(
            format.contains("`format` has nothing to describe"),
            "{format}"
        );

        let include = message(
            "[[target]]\npath = \"~/a\"\nsecret = \"s.age\"\nmode = \"0600\"\n\
             attach = \"include\"\ninclude = \"x\"\n",
        );
        assert!(
            include.contains("`secret` would never be read"),
            "{include}"
        );
    }

    #[test]
    fn a_secret_is_one_body_among_the_others() {
        let message = message(&with("secret = \"s.age\"\nmode = \"0600\"\n"));
        assert!(message.contains("exactly one body"), "{message}");
        assert!(message.contains("`secret`"), "{message}");
    }

    #[test]
    fn a_body_file_must_name_something() {
        assert!(message("[[target]]\npath = \"~/a\"\nfile = \"\"\n").contains("must name a file"));
        assert!(
            message("[[target]]\npath = \"~/a\"\nfile = \"./\"\n").contains("must name a file")
        );
    }

    #[test]
    fn a_body_file_is_normalised() {
        let target =
            parse("[[target]]\npath = \"~/a\"\nfile = \"files/./sub//starship.toml\"\n").unwrap();

        assert_eq!(
            target.body,
            Body::File(PathBuf::from("files/sub/starship.toml"))
        );
    }

    #[test]
    fn a_directory_target_has_no_attachment_but_its_own() {
        let text = "[[target]]\npath = \"~/.ssh\"\ndir = true\n\
                    attach = \"region\"\ncomment = \"#\"\n";
        assert!(message(text).contains("always attached as `own`"));

        let text = "[[target]]\npath = \"~/.ssh\"\ndir = true\n\
                    attach = \"include\"\ninclude = \"x\"\n";
        assert!(message(text).contains("always attached as `own`"));
    }

    #[test]
    fn a_directory_target_has_no_format() {
        let text = "[[target]]\npath = \"~/.config/zed\"\ndir = true\nformat = \"jsonc\"\n";
        assert!(message(text).contains("no content, so `format` has nothing to describe"));

        let text = "[[target]]\npath = \"~/.config/environment.d\"\ndir = true\n\
                    format = \"env.d\"\n";
        assert!(message(text).contains("no content, so `format` has nothing to describe"));
    }

    #[test]
    fn a_directory_target_is_never_declared_false() {
        let text = "[[target]]\npath = \"~/.ssh\"\ndir = false\n";
        assert!(message(text).contains("only ever `true`"));
    }

    #[test]
    fn the_default_modes_document_what_none_means() {
        assert_eq!(Mode::DEFAULT_FILE.to_string(), "0644");
        assert_eq!(Mode::DEFAULT_DIR.to_string(), "0755");
        assert_eq!(Mode::DEFAULT_DIR.bits(), 0o755);
    }

    #[test]
    fn a_relative_target_path_is_rejected() {
        let text = "[[target]]\npath = \"files/gitconfig\"\nfile = \"f\"\n";
        assert!(message(text).contains("must start with `~` or `/`"));
    }

    #[test]
    fn an_absolute_target_path_under_home_is_rejected_with_its_line() {
        // A layer is parsed against a home so that a file under it has exactly
        // one spelling. Accepting both would let one file acquire two keys that
        // `check_unique` cannot see.
        let text = "[[target]]\npath = \"/var/home/example/.gitconfig\"\nfile = \"f\"\n";
        let message = message(text);

        assert!(message.contains("~/.gitconfig"), "{message}");
        assert!(message.contains("bx.toml:2"), "{message}");
    }

    #[test]
    fn an_absolute_reference_under_home_is_rejected_too() {
        // `references` is the other place a target carries a portable path, and
        // entry A7 reports drift keyed on it.
        let message = message(&with(
            "references = [\"/var/home/example/.gitconfig.local\"]\n",
        ));

        assert!(message.contains("~/.gitconfig.local"), "{message}");
    }

    /// A bare root is a directory, and only a directory target may name it.
    ///
    /// `path = "~"` and `path = "/"` with `content` parsed as whole-file
    /// targets: an `attach = "own"` claim on the home directory, or on `/`, as
    /// if it were a file. Every spelling that normalises to one of the two is the
    /// same claim, and every kind of file body is the same mistake. `/` is the
    /// outermost of the home's ancestors, which
    /// `a_directory_above_the_home_is_refused_as_a_file_target` covers.
    #[test]
    fn a_bare_root_is_refused_as_a_file_target() {
        for path in ["~", "~/", "~/.", "/", "//", "/.."] {
            for body in [
                "content = \"x\"\n",
                "file = \"files/x\"\n",
                "attach = \"region\"\ncomment = \"#\"\ncontent = \"x\"\n",
                "attach = \"include\"\ninclude = \"x\"\n",
            ] {
                let text = format!("[[target]]\npath = \"{path}\"\n{body}");
                let message = message(&text);
                assert!(
                    message.contains("is the home directory or a directory above it"),
                    "{path:?} with {body:?}: {message}"
                );
                assert!(message.contains("bx.toml:2"), "{path:?}: {message}");
            }
        }

        // The home's own mode is a real thing to manage, so a directory target
        // may still name it.
        let target = parse("[[target]]\npath = \"~\"\ndir = true\nmode = \"0700\"\n").unwrap();
        assert_eq!(target.body, Body::Dir);
        assert_eq!(target.path.as_str(), "~");
    }

    /// The parser never reaches the refusal with a home that is not absolute.
    ///
    /// A **call-site** property, which is the only place it can live: `home`
    /// arrives at `refuse_file_at_home_or_above` as a plain `&Path` and the type
    /// does not forbid a relative one. `parse_target` holds it by handing the
    /// same `home` to `Portable::parse_in` first, so a non-absolute home leaves
    /// through that error and the refusal never runs. This drives `parse_target`
    /// end to end rather than asserting `Portable::parse_in`'s own contract,
    /// which `paths.rs` already pins.
    ///
    /// It is what lets the comparison in `refuse_file_at_home_or_above` stand
    /// alone. The function once also asked `!path.under_home()`, which could not
    /// decide anything: a `~/…` path is a component prefix of the home only if
    /// the home is itself `~`-rooted. Should a home like that start reaching the
    /// refusal, the `debug_assert!` there trips this test and the operand is
    /// owed again.
    #[test]
    fn the_parser_never_reaches_the_refusal_with_a_non_absolute_home() {
        for home in ["~/nested", "~", "relative/home", "", "."] {
            let message = parse_in(&with(""), Path::new(home))
                .expect_err("a non-absolute home is refused before the refusal")
                .to_string();
            assert!(
                message.contains("HOME is not an absolute path"),
                "home {home:?} reached past the constructor: {message}"
            );
        }

        // The refusal is reached, and passes, for the absolute home the rest of
        // this module parses against -- so the loop above is a statement about
        // the home, not about `with("")` being unparseable.
        let target = parse(&with("")).expect("a path under the home parses");
        assert_eq!(target.path.as_str(), "~/.gitconfig");
    }

    /// The precondition is checked where it is relied on, not merely argued.
    ///
    /// `the_parser_never_reaches_the_refusal_with_a_non_absolute_home` shows one
    /// call site holds it today. This shows the guard that will catch the next
    /// caller that does not: `super::resolve` reaches the same function, and no
    /// test in this module can drive that call site. Without this, the
    /// `debug_assert!` could be deleted and every other test still pass.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "non-absolute home")]
    fn a_non_absolute_home_at_the_refusal_trips_its_precondition() {
        let path = Portable::parse_in("~/x", home()).expect("a path under the home");
        let _ = refuse_file_at_home_or_above(
            "~/x",
            &path,
            &Body::Inline(String::new()),
            Path::new("~/nested"),
        );
    }

    /// The home's ancestors are directories too, and so is the home by any spelling.
    ///
    /// Only `~` and `/` were refused: with the home at `/var/home/example`,
    /// `path = "/var/home/example/.."` with `content` parsed as a file target at
    /// `/var/home`, the same `own` claim on a directory as `~`. Which paths are
    /// the home's ancestors is known from the home string, without the disk.
    #[test]
    fn a_directory_above_the_home_is_refused_as_a_file_target() {
        for path in [
            "/var",
            "/var/home",
            "/var/home/",
            "/var/./home",
            "/var/home/example/..",
            "/var/home/example/../..",
        ] {
            for body in [
                "content = \"x\"\n",
                "file = \"files/x\"\n",
                "attach = \"region\"\ncomment = \"#\"\ncontent = \"x\"\n",
                "attach = \"include\"\ninclude = \"x\"\n",
            ] {
                let text = format!("[[target]]\npath = \"{path}\"\n{body}");
                let message = message(&text);
                assert!(
                    message.contains("or a directory above it"),
                    "{path:?} with {body:?}: {message}"
                );
                assert!(message.contains("bx.toml:2"), "{path:?}: {message}");
            }
        }

        let target = parse("[[target]]\npath = \"/var/home\"\ndir = true\n").unwrap();
        assert_eq!(target.body, Body::Dir);
        assert_eq!(target.path.as_str(), "/var/home");

        // Component-wise, not by string prefix: a sibling sharing the home's
        // leading bytes, or the home's parent's other children, is not above it.
        for path in [
            "/var/home/examp",
            "/var/homes",
            "/var/home/other/.x",
            "/etc/hosts",
        ] {
            let target = parse(&format!("[[target]]\npath = \"{path}\"\ncontent = \"x\"\n"))
                .unwrap_or_else(|e| panic!("{path:?}: {e}"));
            assert_eq!(target.path.as_str(), path);
        }
    }

    #[test]
    fn an_absolute_target_path_outside_home_is_kept() {
        let target = parse("[[target]]\npath = \"/etc/hosts\"\nfile = \"f\"\n").unwrap();

        assert_eq!(target.path.as_str(), "/etc/hosts");
        assert!(!target.path.under_home());
    }

    #[test]
    fn a_mode_is_an_octal_string() {
        let target = parse(&with("mode = \"0600\"\n")).unwrap();

        assert_eq!(target.mode.unwrap().bits(), 0o600);
        assert_eq!(target.mode.unwrap().to_string(), "0600");
        assert_eq!(Mode::parse_octal("755").unwrap().bits(), 0o755);
        assert_eq!(Mode::parse_octal("4755").unwrap().bits(), 0o4755);
    }

    #[test]
    fn a_mode_given_as_an_integer_names_the_string_form() {
        let message = message(&with("mode = 600\n"));

        assert!(message.contains("quoted octal string"), "{message}");
        assert!(message.contains("mode = \"0600\""), "{message}");
    }

    #[test]
    fn a_non_octal_mode_is_rejected() {
        assert!(message(&with("mode = \"0688\"\n")).contains("octal digits"));
        assert!(message(&with("mode = \"rw-\"\n")).contains("octal digits"));
        assert_eq!(
            Mode::parse_octal("0688"),
            Err(ModeError::Invalid("0688".to_string()))
        );
        assert!(
            Mode::parse_octal("").is_err(),
            "an empty mode is not a mode"
        );
        assert!(
            Mode::parse_octal("+644").is_err(),
            "a sign is not an octal digit"
        );
    }

    #[test]
    fn a_mode_wider_than_four_digits_is_rejected() {
        assert!(Mode::parse_octal("00644").is_err());
        assert!(message(&with("mode = \"00644\"\n")).contains("octal digits"));
    }

    #[test]
    fn an_absent_mode_is_none_not_a_guess() {
        assert_eq!(parse(&with("")).unwrap().mode, None);
    }

    #[test]
    fn attach_defaults_to_own() {
        assert_eq!(parse(&with("")).unwrap().attach, Attach::Own);
        assert_eq!(
            parse(&with("attach = \"own\"\n")).unwrap().attach,
            Attach::Own
        );
    }

    #[test]
    fn a_region_needs_a_comment_character() {
        let target = parse(&with("attach = \"region\"\ncomment = \"#\"\n")).unwrap();
        assert_eq!(target.attach, Attach::Region { comment: '#' });

        assert!(message(&with("attach = \"region\"\n")).contains("needs a `comment` character"));
    }

    #[test]
    fn a_comment_character_without_a_region_is_rejected() {
        assert!(message(&with("comment = \"#\"\n")).contains("attach = \"region\""));
    }

    #[test]
    fn a_multi_character_comment_is_rejected() {
        let text = with("attach = \"region\"\ncomment = \"//\"\n");
        assert!(message(&text).contains("single character"));
    }

    #[test]
    fn an_include_carries_its_line() {
        let text = "[[target]]\npath = \"~/.ssh/config\"\nattach = \"include\"\n\
                    include = \"Include ~/.ssh/config.d/*.conf\"\n";
        assert_eq!(
            parse(text).unwrap().attach,
            Attach::Include {
                line: "Include ~/.ssh/config.d/*.conf".to_string()
            }
        );
    }

    /// An include target's body is its line; a second body is unreachable.
    ///
    /// `parse_body` synthesised `Body::Inline(include_line)` only when *no* body
    /// key was declared, so with one alongside the body key was taken and
    /// nothing compared it against the include line -- the target parsed as an
    /// `Include` carrying a line *and* an `Inline` carrying something else
    /// entirely. An author editing an include target into an own-file target and
    /// forgetting to change `attach` got forty lines A5 must either drop
    /// silently or insert into a file bx does not own.
    #[test]
    fn an_include_target_may_not_also_declare_a_body() {
        for body in [
            "content = \"something else entirely\"",
            "file = \"files/config\"",
            "generated = \"shell-init\"",
        ] {
            let text = format!(
                "[[target]]\npath = \"~/.ssh/config\"\nattach = \"include\"\n\
                 include = \"Include ~/.ssh/config.d/*.conf\"\n{body}\n"
            );
            let message = message(&text);
            assert!(
                message.contains("would never be read"),
                "`{body}` beside an include line: {message}"
            );
        }
    }

    #[test]
    fn an_include_without_a_line_is_rejected() {
        assert!(message(&with("attach = \"include\"\n")).contains("needs an `include` line"));
    }

    #[test]
    fn an_include_line_without_an_include_attach_is_rejected() {
        assert!(message(&with("include = \"Include x\"\n")).contains("attach = \"include\""));
    }

    #[test]
    fn an_include_body_defaults_to_its_line() {
        let text = "[[target]]\npath = \"~/.ssh/config\"\nattach = \"include\"\n\
                    include = \"Include ~/.ssh/config.d/*.conf\"\n";
        let target = parse(text).unwrap();

        assert_eq!(
            target.body,
            Body::Inline("Include ~/.ssh/config.d/*.conf".to_string()),
        );
    }

    /// An `include` line is type-checked and now value-checked.
    ///
    /// Both values here parsed. An empty line makes A5's idempotence check
    /// match every blank line in the file, or append one on every run --
    /// Invariant 3 either way. A value bearing a terminator is not one line, so
    /// nothing line-wise finds it again; a multi-line insertion is
    /// `attach = "region"`, which carries delimiters for that purpose.
    #[test]
    fn an_include_line_that_is_not_one_line_is_rejected() {
        // `" "` and `"\t"` passed an `is_empty` check and are the same defect as
        // `""`: a blank line, which every blank line in the file matches.
        for raw in [
            "",
            " ",
            "\\t",
            " \\t  ",
            "[include]\\n\\tpath = ~/.gitconfig.bx",
            "Include a\\r\\nInclude b",
        ] {
            let text = format!(
                "[[target]]\npath = \"~/.gitconfig\"\nattach = \"include\"\ninclude = \"{raw}\"\n"
            );
            let message = message(&text);
            assert!(
                message.contains("not be empty or span lines"),
                "include = {raw:?}: {message}"
            );
        }
    }

    /// A `comment` character is type-checked and now value-checked.
    ///
    /// `comment = "\n"` is a single character and parsed. It produces region
    /// delimiters that cannot be found again, so the region stops delimiting
    /// anything: a fresh region on every run, which is Invariant 3, or a write
    /// outside the one bx meant, which is Invariant 1.
    #[test]
    fn a_comment_character_that_cannot_start_a_delimiter_is_rejected() {
        for raw in ["\\n", "\\t", " ", "\\u0000"] {
            let text = format!(
                "[[target]]\npath = \"~/.ssh/config\"\nattach = \"region\"\ncomment = \"{raw}\"\n"
            );
            let message = message(&text);
            assert!(
                message.contains("whitespace or a control character"),
                "comment = {raw:?}: {message}"
            );
        }
        // Invisible or non-ASCII characters passed the whitespace-and-control
        // check: U+200B ZERO WIDTH SPACE and U+00AD SOFT HYPHEN are neither, and
        // a delimiter nobody can see in an editor is one a human will delete.
        // The body is present so the comment rule is the only thing to refuse.
        for raw in ["\\u200b", "\\u00ad", "é", "\\u007f"] {
            let text = format!(
                "[[target]]\npath = \"~/.ssh/config\"\nattach = \"region\"\n\
                 comment = \"{raw}\"\ncontent = \"x\"\n"
            );
            let message = message(&text);
            assert!(
                message.contains("a visible ASCII character"),
                "comment = {raw:?}: {message}"
            );
        }
        // The characters real config syntaxes actually use still parse.
        for raw in ["#", ";", "%", "\\\"", "/"] {
            let text = format!(
                "[[target]]\npath = \"~/.ssh/config\"\nattach = \"region\"\n\
                 comment = \"{raw}\"\ncontent = \"x\"\n"
            );
            parse(&text).unwrap_or_else(|e| panic!("comment = {raw:?}: {e}"));
        }
    }

    #[test]
    fn an_unknown_attach_is_rejected() {
        assert!(message(&with("attach = \"symlink\"\n")).contains("\"own\", \"region\""));
    }

    #[test]
    fn direction_defaults_to_apply() {
        assert_eq!(parse(&with("")).unwrap().direction, Direction::Apply);
    }

    #[test]
    fn track_is_parsed() {
        assert_eq!(
            parse(&with("direction = \"track\"\n")).unwrap().direction,
            Direction::Track
        );
        assert!(message(&with("direction = \"watch\"\n")).contains("\"apply\" or \"track\""));
    }

    #[test]
    fn format_defaults_to_opaque() {
        assert_eq!(parse(&with("")).unwrap().format, Format::Opaque);
    }

    #[test]
    fn jsonc_owns_dotted_key_paths() {
        let text =
            with("format = \"jsonc\"\nowns = [\"agent.default_model.provider\", \"vim_mode\"]\n");
        let Format::Jsonc { owns } = parse(&text).unwrap().format else {
            panic!("expected a jsonc format");
        };

        assert_eq!(owns.len(), 2);
        assert_eq!(
            owns[0].segments(),
            ["agent", "default_model", "provider"].map(String::from)
        );
        assert_eq!(owns[0].to_string(), "agent.default_model.provider");
        assert_eq!(owns[1].segments(), ["vim_mode".to_string()]);
    }

    #[test]
    fn owned_keys_without_jsonc_are_rejected() {
        assert!(message(&with("owns = [\"a.b\"]\n")).contains("format = \"jsonc\""));
    }

    #[test]
    fn an_empty_key_path_segment_is_rejected() {
        let text = with("format = \"jsonc\"\nowns = [\"a..b\"]\n");
        assert!(message(&text).contains("empty segment"));
        assert_eq!(
            KeyPath::parse(""),
            Err(KeyPathError::EmptySegment(String::new()))
        );
        assert!(KeyPath::parse(".a").is_err());
    }

    #[test]
    fn env_d_is_spelled_with_a_dot() {
        assert_eq!(
            parse(&with("format = \"env.d\"\n")).unwrap().format,
            Format::EnvD
        );
        assert!(message(&with("format = \"envd\"\n")).contains("\"env.d\""));
    }

    /// A structured format describes a file bx owns whole, so it needs `own`.
    ///
    /// All four parsed. `Format` says how much of the file a target claims:
    /// `jsonc` claims the listed keys of a whole JSON document, and `env.d` claims
    /// a whole fragment. A region is a delimited span inside someone else's file,
    /// and an include is one line in it. Neither is a JSON document or a
    /// fragment, so each combination claims two contradictory things about one
    /// file, and entry A5 would have to pick one silently.
    #[test]
    fn a_structured_format_needs_attach_own() {
        let region = "attach = \"region\"\ncomment = \"#\"\ncontent = \"x\"\n";
        let include = "attach = \"include\"\ninclude = \"Include x\"\n";
        let jsonc = "format = \"jsonc\"\nowns = [\"a.b\"]\n";
        let env_d = "format = \"env.d\"\n";

        for (attach, format) in [
            (region, jsonc),
            (region, env_d),
            (include, jsonc),
            (include, env_d),
        ] {
            let text = format!("[[target]]\npath = \"~/.config/x\"\n{attach}{format}");
            let message = message(&text);
            assert!(
                message.contains("needs attach = \"own\""),
                "{attach}{format}: {message}"
            );
            assert!(message.contains("bx.toml:"), "{attach}{format}: {message}");
        }

        // Opaque is the one format every attachment can carry.
        for attach in [region, include] {
            let text = format!("[[target]]\npath = \"~/.config/x\"\n{attach}format = \"opaque\"\n");
            parse(&text).unwrap_or_else(|e| panic!("{attach}: {e}"));
        }
    }

    /// `format = "jsonc"` with no owned key claims nothing.
    ///
    /// It parsed as `Jsonc { owns: [] }`: a target that says bx manages part of
    /// a file and names no part, so every run is a silent no-op.
    #[test]
    fn jsonc_without_an_owned_key_is_rejected() {
        for owns in ["", "owns = []\n"] {
            let message = message(&with(&format!("format = \"jsonc\"\n{owns}")));
            assert!(
                message.contains("at least one key in `owns`"),
                "{owns:?}: {message}"
            );
        }
    }

    /// `dir` counts as a body key when two are declared.
    #[test]
    fn a_directory_target_that_also_declares_a_body_has_two_bodies() {
        for body in ["file = \"f\"", "content = \"x\""] {
            let text = format!("[[target]]\npath = \"~/.ssh\"\ndir = true\n{body}\n");
            let message = message(&text);
            assert!(message.contains("exactly one body"), "{body}: {message}");
            assert!(message.contains("`dir`"), "{body}: {message}");
        }
    }

    #[test]
    fn requires_defaults_to_empty() {
        assert!(parse(&with("")).unwrap().requires.is_empty());
        assert_eq!(
            parse(&with("requires = [\"starship\", \"git\"]\n"))
                .unwrap()
                .requires,
            ["starship".to_string(), "git".to_string()]
        );
    }

    #[test]
    fn references_are_portable_paths() {
        let target = parse(&with("references = [\"~/.gitconfig.local\"]\n")).unwrap();

        assert_eq!(
            target.references,
            [Portable::parse_in("~/.gitconfig.local", home()).unwrap()]
        );
        assert!(
            message(&with("references = [\"relative/path\"]\n"))
                .contains("must start with `~` or `/`")
        );
    }

    #[test]
    fn enabled_defaults_to_true() {
        assert!(parse(&with("")).unwrap().enabled);
    }

    #[test]
    fn enabled_false_is_parsed_not_dropped() {
        // Removing the entry is A3's merge rule; the model records the flag.
        assert!(!parse(&with("enabled = false\n")).unwrap().enabled);
    }

    #[test]
    fn an_unknown_target_key_is_rejected_with_its_line() {
        let message = message(&with("symlink = true\n"));

        assert!(message.contains("unknown key `symlink`"), "{message}");
        assert!(message.contains("[[target]]"), "{message}");
        assert!(message.contains("bx.toml:4"), "{message}");
    }

    #[test]
    fn a_key_of_the_wrong_type_names_both_types() {
        assert!(
            message(&with("enabled = \"yes\"\n"))
                .contains("`enabled` must be a boolean, found string")
        );
        assert!(
            message(&with("requires = \"starship\"\n"))
                .contains("an array of strings, found string")
        );
        assert!(message(&with("requires = [1]\n")).contains("an array of strings, found integer"));
        assert!(
            message("[[target]]\npath = 1\nfile = \"f\"\n")
                .contains("`path` must be a string, found integer")
        );
    }
}
