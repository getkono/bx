//! Declared `PATH` entries: what goes on the search path, in what order, and
//! what comes off it.
//!
//! # The `[path]` schema
//!
//! ```toml
//! [path]
//! prepend = [
//!     "~/bin",
//!     { dir = "~/.local/bin", if_exists = true },
//!     "${CARGO_HOME}/bin",
//! ]
//! append  = ["/opt/tool/bin"]
//! remove  = ["~/.cargo/bin"]
//! ```
//!
//! Each list holds directories, one per string. An entry is a string, or an
//! inline table `{ dir = "…", if_exists = true, enabled = false }` when it
//! needs either flag:
//!
//! - `prepend` — put ahead of the inherited `PATH`, the first entry first.
//! - `append` — put after it, the first entry first.
//! - `remove` — take out of `PATH` after every other entry is in place, so a
//!   stale copy of a tool the package manager or an older install put on the
//!   search path stops shadowing, or being shadowed by, the one declared.
//! - `if_exists` — add the entry only while its directory exists, tested each
//!   time a shell starts. Not allowed on a `remove` entry, which removing
//!   covers whether or not the directory is there.
//! - `enabled = false` — drop an entry an earlier layer declared.
//!
//! # What an entry may say
//!
//! An absolute path, `~` or a path under it, or a path that opens with a
//! variable reference, `${NAME}` or `$NAME`. A reference is **not** resolved
//! by bx: it is written for zsh to expand, so the variable has to be one the
//! same file exports first — an `[[env]]` variable of kind `environment`,
//! whose `export` lines come before every `PATH` line — or `HOME`. The guard
//! judges the fragment before it is written, and a reference to anything else
//! holds the fragment back naming the line. A `{{placeholder}}` is not
//! substituted here; declare an `[[env]]` variable and refer to it.
//!
//! Otherwise an entry holds only the characters a path the guard judges may:
//! ASCII letters and digits, `.`, `_`, `-`, `+` and `/`. One string is one
//! directory, so a `:` is refused rather than read as two.
//!
//! # Layers
//!
//! An entry's natural key is the directory as zsh reads it — `~/bin`,
//! `$HOME/bin` and `${HOME}/bin` are one — across all three lists. A later
//! layer that names a directory again replaces the earlier entry wholesale,
//! **in its place**, whichever list either is in; one layer naming one
//! directory twice is an error.
//!
//! # Where it lands
//!
//! In the `zshenv` fragment, which every zsh reads whether it is a login shell
//! or not, interactive or not, after the fragment's `[[env]]` variables. Each
//! prepended or appended entry is first taken out of `PATH` wherever it
//! already is, so a nested shell that reads the file again moves the entry
//! rather than repeating it. bash, and the `environment.d` fragment, get no
//! `PATH` entry from here.

use std::path::Path;

use toml_edit::{InlineTable, Table, Value};

use super::{Ctx, Error, Origin};
use crate::env_guard::is_variable_name;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[path]";

/// Every key a `[path]` table may carry, each a list, in the order the
/// section documents them.
const LISTS: [(&str, Position); 3] = [
    ("prepend", Position::Prepend),
    ("append", Position::Append),
    ("remove", Position::Remove),
];

/// Every key an entry's inline table may carry.
const ENTRY_KEYS: [&str; 3] = ["dir", "if_exists", "enabled"];

/// Which list an entry is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Position {
    /// Ahead of the inherited `PATH`.
    Prepend,
    /// After it.
    Append,
    /// Taken out of it.
    Remove,
}

/// One `[path]` entry, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEntry {
    /// The directory as the config author wrote it.
    pub dir: String,
    /// The directory as zsh is given it: `~` spelled `${HOME}`, and every
    /// reference braced, so no character after one can extend it. The
    /// natural key.
    pub shell: String,
    /// Which list it is in.
    pub position: Position,
    /// Whether it is added only while its directory exists.
    pub if_exists: bool,
    /// `false` in a later layer drops an entry an earlier one declared.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// Parse a `[path]` table into its entries, list by list and in document order
/// within each.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key this version does not know, in the table or
/// in an entry, [`Error::WrongType`] for a list or an entry of the wrong type,
/// [`Error::MissingKey`] for an inline entry with no `dir`, and
/// [`Error::BadValue`] for a directory [`shell_spelling`] refuses or an
/// `if_exists` on a `remove` entry.
pub fn parse_path(table: &Table, file: &Path, text: &str) -> Result<Vec<PathEntry>, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &LISTS.map(|(key, _)| key))?;

    let mut entries = Vec::new();
    for (key, position) in LISTS {
        let Some(item) = table.get(key) else {
            continue;
        };
        let array = item
            .as_array()
            .ok_or_else(|| ctx.wrong_type(table, key, "an array of directories", item))?;
        for value in array {
            let origin = value.span().map_or_else(
                || ctx.key_origin(table, key),
                |s| Origin::at(file, text, &s),
            );
            entries.push(parse_entry(value, key, position, origin)?);
        }
    }
    Ok(entries)
}

/// One element of a `[path]` list.
fn parse_entry(
    value: &Value,
    list: &str,
    position: Position,
    origin: Origin,
) -> Result<PathEntry, Error> {
    let wrong = |key: &str, expected, found: &Value| Error::WrongType {
        origin: origin.clone(),
        key: key.to_string(),
        expected,
        found: found.type_name(),
    };
    let bad = |message: String| Error::BadValue {
        origin: origin.clone(),
        message,
    };
    let (dir, if_exists, enabled) = match value {
        Value::String(dir) => (dir.value().as_str(), false, true),
        Value::InlineTable(entry) => {
            reject_unknown_entry_keys(entry, list, &origin)?;
            let flag = |key: &str| match entry.get(key) {
                None => Ok(None),
                Some(flag) => flag
                    .as_bool()
                    .map(Some)
                    .ok_or_else(|| wrong(key, "a boolean", flag)),
            };
            let dir = match entry.get("dir") {
                Some(dir) => dir.as_str().ok_or_else(|| wrong("dir", "a string", dir))?,
                None => {
                    return Err(Error::MissingKey {
                        origin: origin.clone(),
                        section: SECTION,
                        key: "dir",
                    });
                }
            };
            (
                dir,
                flag("if_exists")?.unwrap_or(false),
                flag("enabled")?.unwrap_or(true),
            )
        }
        other => {
            return Err(wrong(
                list,
                "a directory, or an inline table `{ dir = \"…\" }`",
                other,
            ));
        }
    };
    if if_exists && position == Position::Remove {
        return Err(bad(format!(
            "`{dir}`: `if_exists` gates adding a directory, and `remove` takes one out \
             whether or not it exists; drop `if_exists`"
        )));
    }
    let shell = shell_spelling(dir).map_err(|problem| bad(format!("`{dir}`: {problem}")))?;
    Ok(PathEntry {
        dir: dir.to_string(),
        shell,
        position,
        if_exists,
        enabled,
        origin,
    })
}

/// Refuse a key an entry's inline table may not carry.
fn reject_unknown_entry_keys(
    entry: &InlineTable,
    list: &str,
    origin: &Origin,
) -> Result<(), Error> {
    match entry.iter().find(|(key, _)| !ENTRY_KEYS.contains(key)) {
        Some((key, _)) => Err(Error::UnknownKey {
            origin: origin.clone(),
            section: SECTION,
            key: format!("{list}.{key}"),
        }),
        None => Ok(()),
    }
}

/// `dir` as zsh is to be given it, or why it cannot be one `PATH` entry.
///
/// `~` and `~/…` open with `${HOME}` instead; every reference is braced; every
/// other character is kept. The result is what the fragment writes, and what
/// two layers' entries are compared by.
///
/// # Errors
///
/// A message saying what is wrong: an empty directory, a `{{placeholder}}`, a
/// `:`, a character a path the guard judges may not hold, a malformed or
/// self-referring reference, or an opening that is neither `/`, `~` nor a
/// reference.
pub fn shell_spelling(dir: &str) -> Result<String, String> {
    if dir.is_empty() {
        return Err("a directory is needed".to_string());
    }
    if dir.contains("{{") {
        return Err(
            "a `{{placeholder}}` is not substituted in [path]; declare an [[env]] variable \
             of kind \"environment\" and refer to it as `${NAME}`"
                .to_string(),
        );
    }
    let body = match dir.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            return Ok(format!("${{HOME}}{}", spelled(rest)?));
        }
        Some(_) => {
            return Err("only the home is spelled with `~`; write `~/…`".to_string());
        }
        None => dir,
    };
    if !body.starts_with(['/', '$']) {
        return Err(
            "an entry is an absolute path, `~/…`, or opens with a variable reference; \
             a relative entry would search wherever the shell happens to be"
                .to_string(),
        );
    }
    spelled(body)
}

/// `text` with every reference braced, refusing a character no entry holds.
fn spelled(text: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c == '$' {
            let after = &rest[1..];
            let (name, tail) = match after.strip_prefix('{') {
                Some(braced) => braced
                    .split_once('}')
                    .ok_or("a `${` reference is not closed with `}`")?,
                None => after.split_at(
                    after
                        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .unwrap_or(after.len()),
                ),
            };
            if !is_variable_name(name) {
                return Err(format!(
                    "`${name}` is not a reference: a variable name starts with a letter or `_` \
                     and holds only ASCII letters, digits and `_`"
                ));
            }
            if name == "PATH" {
                return Err("an entry may not refer to `PATH` itself".to_string());
            }
            out.push_str("${");
            out.push_str(name);
            out.push('}');
            rest = tail;
            continue;
        }
        if c == ':' {
            return Err("one string is one directory, and `:` separates two; \
                        list each as its own entry"
                .to_string());
        }
        if !(c.is_ascii_alphanumeric() || "._-+/".contains(c)) {
            return Err(format!(
                "{c:?} is not a character a PATH entry may hold: only ASCII letters and \
                 digits, `.`, `_`, `-`, `+` and `/`, and `${{NAME}}` references"
            ));
        }
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    Ok(out)
}

/// The lines the `zshenv` fragment carries for `entries`, after its
/// variables; empty when there are none.
///
/// Prepended entries are written last first, so the first one declared ends
/// up first, and each added entry is taken out of `PATH` just before it is
/// put back where it is declared. Removals come after every entry has been
/// added.
///
/// The block never ends on a gated line. A gated line whose directory is
/// missing returns 1, and a file sourced at startup returns the status of its
/// last command, so a `zshenv` fragment ending on one would stop a shell
/// running under `ERR_EXIT` (`zsh -e`) before its prompt. When the last line
/// written is gated, the block closes with [`SETTLE`], which assigns `PATH`
/// its own value and returns 0.
#[must_use]
pub fn render(entries: &[PathEntry]) -> String {
    if entries.is_empty() {
        return String::new();
    }
    let in_list = |position| entries.iter().filter(move |e| e.position == position);
    let mut out = String::from("# [path]\n");
    let removal = |out: &mut String, dir: &str| {
        out.push_str("path=(${path:#");
        out.push_str(dir);
        out.push_str("})\n");
    };
    let added = |out: &mut String, entry: &PathEntry, list: String| {
        removal(out, &entry.shell);
        if entry.if_exists {
            out.push_str("[[ -d ");
            out.push_str(&entry.shell);
            out.push_str(" ]] && ");
        }
        out.push_str("export PATH=");
        out.push_str(&list);
        out.push('\n');
    };
    for entry in in_list(Position::Prepend)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        added(&mut out, entry, format!("{}:${{PATH}}", entry.shell));
    }
    for entry in in_list(Position::Append) {
        added(&mut out, entry, format!("${{PATH}}:{}", entry.shell));
    }
    for entry in in_list(Position::Remove) {
        removal(&mut out, &entry.shell);
    }
    if out
        .lines()
        .next_back()
        .is_some_and(|line| line.starts_with("[[ -d "))
    {
        out.push_str(SETTLE);
    }
    out
}

/// The line that closes a `[path]` block whose last line is gated: `PATH`
/// assigned its own value, changing nothing and returning 0.
const SETTLE: &str = "export PATH=${PATH}\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use std::path::PathBuf;

    fn parse(text: &str) -> Result<Vec<PathEntry>, String> {
        parse_str(
            text,
            Path::new("/repo/bx.toml"),
            Path::new("/var/home/example"),
        )
        .map(|config| config.path)
        .map_err(|e| e.to_string())
    }

    fn entry(shell: &str, position: Position, if_exists: bool) -> PathEntry {
        PathEntry {
            dir: shell.to_string(),
            shell: shell.to_string(),
            position,
            if_exists,
            enabled: true,
            origin: Origin::unknown(Path::new("/repo/bx.toml")),
        }
    }

    #[test]
    fn every_list_parses_in_document_order_with_each_entrys_own_line() {
        let entries = parse(
            "[path]\nremove = [\"~/.cargo/bin\"]\nprepend = [\n  \"~/bin\",\n  \
             { dir = \"~/.local/bin\", if_exists = true },\n  \"$CARGO_HOME/bin\",\n]\n\
             append = [{ dir = \"/opt/x/bin\", enabled = false }]\n",
        )
        .expect("parses");
        let seen: Vec<_> = entries
            .iter()
            .map(|e| {
                (
                    e.dir.as_str(),
                    e.shell.as_str(),
                    e.position,
                    e.if_exists,
                    e.enabled,
                    e.origin.line,
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                ("~/bin", "${HOME}/bin", Position::Prepend, false, true, 4),
                (
                    "~/.local/bin",
                    "${HOME}/.local/bin",
                    Position::Prepend,
                    true,
                    true,
                    5
                ),
                (
                    "$CARGO_HOME/bin",
                    "${CARGO_HOME}/bin",
                    Position::Prepend,
                    false,
                    true,
                    6
                ),
                (
                    "/opt/x/bin",
                    "/opt/x/bin",
                    Position::Append,
                    false,
                    false,
                    8
                ),
                (
                    "~/.cargo/bin",
                    "${HOME}/.cargo/bin",
                    Position::Remove,
                    false,
                    true,
                    2
                ),
            ]
        );
        assert_eq!(entries[0].origin.file, PathBuf::from("/repo/bx.toml"));
        assert_eq!(parse("").expect("parses"), vec![]);
    }

    #[test]
    fn a_directory_is_spelled_once_for_zsh() {
        for (dir, shell) in [
            ("~", "${HOME}"),
            ("~/bin", "${HOME}/bin"),
            ("$HOME/bin", "${HOME}/bin"),
            ("${HOME}/bin", "${HOME}/bin"),
            ("$BUN_INSTALL", "${BUN_INSTALL}"),
            ("$A/x-1.2+b/$B_2", "${A}/x-1.2+b/${B_2}"),
            ("/usr/local/bin", "/usr/local/bin"),
        ] {
            assert_eq!(shell_spelling(dir).as_deref(), Ok(shell), "{dir}");
        }
        for (dir, needle) in [
            ("", "needed"),
            ("{{root}}/bin", "placeholder"),
            ("~other/bin", "`~/…`"),
            ("bin", "relative"),
            ("./bin", "relative"),
            ("/a:/b", "`:`"),
            ("/a b", "not a character"),
            ("/a*", "not a character"),
            ("/a\"b", "not a character"),
            ("/é", "not a character"),
            ("${X", "not closed"),
            ("${1X}/bin", "not a reference"),
            ("$/bin", "not a reference"),
            ("$PATH/bin", "`PATH` itself"),
            ("/x/${PATH}", "`PATH` itself"),
        ] {
            let err = shell_spelling(dir).expect_err(dir);
            assert!(err.contains(needle), "{dir}: {err}");
        }
    }

    #[test]
    fn a_malformed_section_or_entry_is_refused_naming_it() {
        for (text, needle) in [
            (
                "[path]\nfront = [\"/x\"]\n",
                "unknown key `front` in [path]",
            ),
            ("[path]\nprepend = \"/x\"\n", "an array of directories"),
            ("[path]\nprepend = [1]\n", "a directory, or an inline table"),
            (
                "[path]\nprepend = [{ dir = \"/x\", when = true }]\n",
                "unknown key `prepend.when`",
            ),
            ("[path]\nprepend = [{ if_exists = true }]\n", "`dir`"),
            (
                "[path]\nprepend = [{ dir = 1 }]\n",
                "`dir` must be a string",
            ),
            (
                "[path]\nprepend = [{ dir = \"/x\", if_exists = \"yes\" }]\n",
                "`if_exists` must be a boolean",
            ),
            (
                "[path]\nremove = [{ dir = \"/x\", if_exists = true }]\n",
                "drop `if_exists`",
            ),
            ("[path]\nappend = [\"relative/bin\"]\n", "relative"),
            ("path = 1\n", "a table `[path]`"),
        ] {
            let err = parse(text).expect_err(text);
            assert!(err.contains(needle), "{text}: {err}");
        }
    }

    #[test]
    fn one_layer_may_not_name_one_directory_twice_under_any_spelling() {
        let err = parse("[path]\nprepend = [\"~/bin\"]\nremove = [\"$HOME/bin\"]\n")
            .expect_err("a duplicate");
        assert!(err.contains("duplicate path entry `${HOME}/bin`"), "{err}");
        assert!(err.contains("first declared at /repo/bx.toml:2"), "{err}");
    }

    #[test]
    fn the_lines_put_each_list_where_it_goes_and_removals_last() {
        let entries = [
            entry("${HOME}/.cargo/bin", Position::Remove, false),
            entry("${HOME}/bin", Position::Prepend, false),
            entry("/opt/x/bin", Position::Append, true),
            entry("${HOME}/.local/bin", Position::Prepend, true),
            entry("/opt/y/bin", Position::Append, false),
        ];
        assert_eq!(
            render(&entries),
            "# [path]\n\
             path=(${path:#${HOME}/.local/bin})\n\
             [[ -d ${HOME}/.local/bin ]] && export PATH=${HOME}/.local/bin:${PATH}\n\
             path=(${path:#${HOME}/bin})\n\
             export PATH=${HOME}/bin:${PATH}\n\
             path=(${path:#/opt/x/bin})\n\
             [[ -d /opt/x/bin ]] && export PATH=${PATH}:/opt/x/bin\n\
             path=(${path:#/opt/y/bin})\n\
             export PATH=${PATH}:/opt/y/bin\n\
             path=(${path:#${HOME}/.cargo/bin})\n"
        );
        assert_eq!(render(&[]), "");
        assert_eq!(render(&entries), render(&entries));
    }

    #[test]
    fn a_block_whose_last_line_is_gated_ends_on_a_line_that_succeeds() {
        // The first-declared prepend is written last, so with nothing after
        // it the block would end on its gate.
        assert_eq!(
            render(&[
                entry("${HOME}/.local/bin", Position::Prepend, true),
                entry("${HOME}/bin", Position::Prepend, false),
            ]),
            "# [path]\n\
             path=(${path:#${HOME}/bin})\n\
             export PATH=${HOME}/bin:${PATH}\n\
             path=(${path:#${HOME}/.local/bin})\n\
             [[ -d ${HOME}/.local/bin ]] && export PATH=${HOME}/.local/bin:${PATH}\n\
             export PATH=${PATH}\n"
        );
        // The last append, with no removal after it, is the same case.
        assert_eq!(
            render(&[entry("/opt/x/bin", Position::Append, true)]),
            "# [path]\n\
             path=(${path:#/opt/x/bin})\n\
             [[ -d /opt/x/bin ]] && export PATH=${PATH}:/opt/x/bin\n\
             export PATH=${PATH}\n"
        );
        // A block that ends on anything else gets no extra line.
        assert!(
            !render(&[
                entry("/opt/x/bin", Position::Append, true),
                entry("/opt/y/bin", Position::Remove, false),
            ])
            .ends_with(SETTLE)
        );
    }
}
