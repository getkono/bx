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
//! dir        = true                             # the target is a directory )
//! mode       = "0600"                           # optional octal *string*
//! attach     = "own"                            # own | region | include; default own
//! comment    = "#"                              # required iff attach = "region"
//! include    = "Include ~/.ssh/config.d/*.conf" # required iff attach = "include"
//! direction  = "apply"                          # apply | track; default apply
//! format     = "opaque"                         # opaque | jsonc | env.d; default opaque
//! owns       = ["agent.default_model"]          # permitted iff format = "jsonc"
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
const KEYS: [&str; 15] = [
    "path",
    "file",
    "content",
    "generated",
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
const BODY_KEYS: [&str; 4] = ["file", "content", "generated", "dir"];

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
/// one scope. This type depends on nothing else in `config`, so entry A5 can
/// relocate its body to `bx::fs::Mode` and leave a `pub use` behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mode(u32);

impl Mode {
    /// The mode a file gets when the target does not say.
    pub const DEFAULT_FILE: Self = Self(0o644);
    /// The mode a directory gets when the target does not say.
    pub const DEFAULT_DIR: Self = Self(0o755);

    /// Parse the quoted octal form a config file uses.
    ///
    /// **A bare TOML integer is not accepted.** TOML has no octal literal, so
    /// `mode = 600` is decimal 600 and means nothing at all; only `mode = "0600"`
    /// parses. One to four octal digits, so the setuid, setgid and sticky bits
    /// are expressible and a fifth digit is a typo.
    ///
    /// # Errors
    ///
    /// [`ModeError::Invalid`] for anything else.
    pub fn parse_octal(raw: &str) -> Result<Self, ModeError> {
        // `from_str_radix` alone is not enough: it accepts a leading `+`, and it
        // has no opinion about how many digits a mode may have.
        let usable = (1..=4).contains(&raw.len()) && raw.bytes().all(|b| matches!(b, b'0'..=b'7'));

        u32::from_str_radix(raw, 8)
            .ok()
            .filter(|_| usable)
            .map(Self)
            .ok_or_else(|| ModeError::Invalid(raw.to_string()))
    }

    /// The bit pattern.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

/// A mode that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModeError {
    /// Not one to four octal digits.
    #[error("a mode must be one to four octal digits in quotes, like \"0600\"; got {0:?}")]
    Invalid(String),
}

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
    /// A `conf.d`-style directory of environment fragments.
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
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_target(table: &Table, file: &Path, text: &str) -> Result<Target, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let raw_path = ctx.required_str(table, "path")?;
    let path = Portable::parse(raw_path).map_err(|e| ctx.bad(table, "path", e.to_string()))?;

    let attach = parse_attach(&ctx, table)?;
    let body = parse_body(&ctx, table, &attach)?;
    let mode = parse_mode(&ctx, table)?;
    let direction = parse_direction(&ctx, table)?;
    let format = parse_format(&ctx, table)?;

    let requires = ctx.str_array_at(table, "requires")?;
    let references = ctx
        .str_array_at(table, "references")?
        .iter()
        .map(|raw| Portable::parse(raw))
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
            match (chars.next(), chars.next()) {
                (Some(c), None) => Attach::Region { comment: c },
                _ => {
                    return Err(ctx.bad(
                        table,
                        "comment",
                        format!("`comment` must be a single character, got {raw:?}"),
                    ));
                }
            }
        }
        "include" => {
            let line = include.ok_or_else(|| {
                ctx.bad(
                    table,
                    "attach",
                    "attach = \"include\" needs an `include` line to insert",
                )
            })?;
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

/// Exactly one body key, or none for an `include` target.
fn parse_body(ctx: &Ctx, table: &Table, attach: &Attach) -> Result<Body, Error> {
    let declared: Vec<&str> = BODY_KEYS
        .iter()
        .copied()
        .filter(|key| table.contains_key(key))
        .collect();

    match declared.as_slice() {
        [] => match attach {
            // An include target already declares the only line it writes;
            // making it repeat that line as `content` would be ceremony.
            Attach::Include { line } => Ok(Body::Inline(line.clone())),
            _ => Err(Error::MissingKey {
                origin: ctx.origin().clone(),
                section: SECTION,
                key: "file`, `content`, `generated` or `dir",
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

/// The body one declared key names.
fn body_from(ctx: &Ctx, table: &Table, key: &str) -> Result<Body, Error> {
    match key {
        "file" => Ok(Body::File(PathBuf::from(ctx.required_str(table, "file")?))),
        "content" => Ok(Body::Inline(
            ctx.required_str(table, "content")?.to_string(),
        )),
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
            "`mode` is a quoted octal string: TOML has no octal literal, so \
             mode = 600 is decimal 600. Write mode = \"0600\".",
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

/// `format`, and the `owns` list only `jsonc` may carry.
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

    /// Parse the first `[[target]]` out of a document.
    fn parse(text: &str) -> Result<Target, Error> {
        let doc = Document::parse(text).expect("valid TOML");
        let table = doc
            .as_table()
            .get("target")
            .expect("a [[target]]")
            .as_array_of_tables()
            .expect("an array of tables")
            .get(0)
            .expect("one element");
        parse_target(table, Path::new("bx.toml"), text)
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
            Portable::parse("~/.gitconfig").unwrap()
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
                    include = \"Include ~/.ssh/config.d/*.conf\"\ncontent = \"x\"\n";
        assert_eq!(
            parse(text).unwrap().attach,
            Attach::Include {
                line: "Include ~/.ssh/config.d/*.conf".to_string()
            }
        );
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
        let text = "[[target]]\npath = \"~/.gitconfig\"\nattach = \"include\"\n\
                    include = \"[include]\\n\\tpath = ~/.gitconfig.bx\"\n";
        let target = parse(text).unwrap();

        assert_eq!(
            target.body,
            Body::Inline("[include]\n\tpath = ~/.gitconfig.bx".to_string()),
        );
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
            [Portable::parse("~/.gitconfig.local").unwrap()]
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
