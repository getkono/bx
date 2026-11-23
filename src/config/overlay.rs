//! `[[overlay]]`: what one machine adds to a structured file every machine
//! shares.
//!
//! ```toml
//! # modules/buildhost.toml
//! when = "host:build1"
//!
//! [[overlay]]
//! name = "subagent-stop-hook"                # natural key; required
//! path = "~/.claude/settings.json"           # the [[target]] it adds to; required
//! file = "files/claude/subagent-stop.json"   # the fragment, repo-relative )
//! content = "…"                              # the fragment, verbatim     ) exactly one
//! when = "host:build1"                       # optional; a condition bx decides
//! enabled = true                             # default true
//! ```
//!
//! # Why an overlay, and not a second copy of the file
//!
//! A target's body is the file every machine that applies the repo shares. A
//! later layer can replace a target wholesale or switch it off, never add to
//! it: a second, per-host copy of the whole file drifts from the shared one and
//! doubles every edit. An overlay is a **fragment** of the same syntax — JSON
//! for a `.json` target, TOML for a `.toml` one — that `plan` merges into the
//! shared body where it applies. A machine with no overlay gets the shared
//! body's exact bytes; one with an overlay gets the merge, and an edit to the
//! shared body reaches both.
//!
//! An overlay is scoped like every other declaration: by its own `when`, its
//! module's `when`, or by being declared, or toggled, in `local.toml`. Every
//! account on a host that applies the repo sees a committed module gated on
//! `host:`, so opting all of them in needs no per-account repo; one account
//! opts out with a three-line toggle naming the overlay in its own
//! `local.toml`.
//!
//! # Merging, exactly
//!
//! Objects and tables merge key by key. An array — `hooks.SubagentStop` — gets
//! the overlay's elements appended, skipping any already in it. A key both set
//! is accepted when they agree; when they disagree, or one holds a table and
//! the other a scalar, the target is blocked with a message naming the key,
//! never guessed. Several overlays on one file are merged in layer order. See
//! [`crate::overlay`] for the merge itself, and for its inverse.
//!
//! # The repo never learns what only this machine adds
//!
//! A tool that rewrites the file itself — Claude Code rewrites
//! `settings.json` — leaves bx a file holding both the shared body and this
//! machine's additions. Saving it to the repo (`bx add`, or *save* when
//! `apply` asks about an edited file) first takes out exactly what the
//! overlays added, so the shared body gains only the tool's edit, and nothing
//! the shared body also holds is moved into an overlay. bx never writes an
//! overlay's own file.
//!
//! # Which targets take one
//!
//! A whole file bx owns (`attach = "own"`) with a `file` or `content` body,
//! applied (`direction = "apply"`), `format = "opaque"`, at a path ending in
//! `.json` or `.toml`. Any other target an overlay names is refused when the
//! configuration loads. An overlay naming a file no layer declares a target
//! for is refused too: it is a typo, not a declaration. One whose target is
//! switched off or gated out on this machine adds nothing.
//!
//! `path` may hold a `{{name}}`, and names the target either as the target
//! writes it or as it is substituted on this machine.

use std::path::{Path, PathBuf};

use toml_edit::Table;

use super::target::{self, Attach, Body, Direction, Format, Target};
use super::values;
use super::{Ctx, Error, Origin};
use crate::overlay::Syntax;

#[cfg(test)]
mod tests;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[[overlay]]";

/// Every key an `[[overlay]]` entry may carry.
const KEYS: [&str; 6] = ["name", "path", "file", "content", "when", "enabled"];

/// An overlay's fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fragment {
    /// A file in the config repo, named repo-relative.
    File(PathBuf),
    /// A literal written in the config file itself.
    Inline(String),
}

/// One `[[overlay]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDecl {
    /// The overlay's name, its natural key.
    pub name: String,
    /// The target's path as the overlay writes it, `{{name}}` references and
    /// all.
    pub path: String,
    /// What it adds.
    pub fragment: Fragment,
    /// `false` in any layer removes the overlay from the resolved
    /// configuration.
    pub enabled: bool,
    /// Where the entry was written.
    pub origin: Origin,
}

/// Parse one `[[overlay]]` entry.
///
/// `text` is the whole layer file, because spans index into it. Its `when` is
/// read by the caller, as for every entry [`super::layers::gate`] decides.
///
/// # Errors
///
/// Any [`Error`] the entry's own keys can produce. Every one carries an origin.
pub fn parse_overlay(table: &Table, file: &Path, text: &str) -> Result<OverlayDecl, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let name = ctx.required_str(table, "name")?.to_string();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ctx.bad(
            table,
            "name",
            format!("{name:?} is not an overlay name: a name is non-empty and on one line"),
        ));
    }

    let path = ctx.required_str(table, "path")?.to_string();
    if let Err(problem) = values::placeholders(&path) {
        return Err(ctx.bad(table, "path", format!("overlay `{name}`: {problem}")));
    }
    if Syntax::of(Path::new(&path)).is_none() {
        return Err(ctx.bad(
            table,
            "path",
            format!(
                "overlay `{name}`: an overlay is merged into a JSON or TOML file, so its \
                 target's path ends in `.json` or `.toml`; got {path:?}"
            ),
        ));
    }

    let fragment = match (ctx.str_at(table, "file")?, ctx.str_at(table, "content")?) {
        (Some(raw), None) => {
            if raw.contains("{{") {
                return Err(ctx.bad(
                    table,
                    "file",
                    format!(
                        "overlay `{name}`: an overlay's `file` is one file every machine \
                         reads the same, so it holds no `{{{{name}}}}`"
                    ),
                ));
            }
            Fragment::File(
                target::confine_to_repo("file", raw)
                    .map_err(|message| ctx.bad(table, "file", message))?,
            )
        }
        (None, Some(content)) => Fragment::Inline(content.to_string()),
        (Some(_), Some(_)) => {
            return Err(ctx.bad(
                table,
                "content",
                "an overlay has exactly one fragment, but this one declares `file` and \
                 `content`",
            ));
        }
        (None, None) => {
            return Err(Error::MissingKey {
                origin: ctx.origin().clone(),
                section: SECTION,
                key: "file` or `content",
            });
        }
    };

    Ok(OverlayDecl {
        name,
        path,
        fragment,
        enabled: ctx.bool_at(table, "enabled")?.unwrap_or(true),
        origin: ctx.origin().clone(),
    })
}

/// Why `target` cannot take an overlay, if it cannot.
///
/// An overlay is merged into the bytes of a whole file bx owns and writes from
/// the repo. A region or an include line is not a document, a secret's
/// plaintext never reaches the repo to be merged back into, a generated body is
/// not the repo's to save into, a tracked file's machine copy leads, and a
/// link or a directory has no content.
#[must_use]
pub fn ineligible(target: &Target) -> Option<&'static str> {
    match (
        &target.body,
        &target.attach,
        target.direction,
        &target.format,
    ) {
        (Body::File(_) | Body::Inline(_), Attach::Own, Direction::Apply, Format::Opaque) => None,
        (Body::File(_) | Body::Inline(_), Attach::Own, Direction::Track, _) => Some(
            "it is tracked (`direction = \"track\"`): this machine's copy leads, so there \
             is no shared body to merge into",
        ),
        (Body::File(_) | Body::Inline(_), Attach::Own, _, _) => {
            Some("its `format` already claims part of the file")
        }
        (Body::File(_) | Body::Inline(_), _, _, _) => Some(
            "it is a region or an include line in a file bx does not own whole, not a \
             document an overlay can be merged into",
        ),
        (Body::Secret(_), _, _, _) => Some(
            "it is a secret, whose plaintext bx never saves back to the repo, so an \
             overlay could not be kept out of it",
        ),
        (Body::Generated(_), _, _, _) => Some("bx generates its body"),
        (Body::Symlink(_) | Body::Dir, _, _, _) => Some("it is a link or a directory"),
    }
}

/// One overlay resolved against this account: the target it adds to, and the
/// fragment to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    /// The name it was declared under.
    pub name: String,
    /// The target's path, as the target resolved it on this machine.
    pub path: crate::paths::Portable,
    /// What it adds.
    pub fragment: Fragment,
    /// Where the entry was written.
    pub origin: Origin,
}

impl Overlay {
    /// The fragment's bytes: its `content`, or its `file` in the config repo,
    /// read through a link and refused unless a regular file is at its end.
    ///
    /// # Errors
    ///
    /// The I/O error, for a `file` that cannot be read, with the path read.
    pub fn read(&self, repo: &Path) -> Result<Vec<u8>, (PathBuf, std::io::Error)> {
        match &self.fragment {
            Fragment::Inline(content) => Ok(content.clone().into_bytes()),
            Fragment::File(rel) => {
                let path = repo.join(rel);
                if std::fs::metadata(&path).is_ok_and(|meta| !meta.is_file()) {
                    return Err((path, std::io::Error::other("not a regular file")));
                }
                std::fs::read(&path).map_err(|error| (path, error))
            }
        }
    }
}

/// The overlays in `overlays` that add to the target at `path`, in
/// configuration order.
pub fn naming<'a>(
    overlays: &'a [Overlay],
    path: &'a crate::paths::Portable,
) -> impl Iterator<Item = &'a Overlay> + 'a {
    overlays.iter().filter(move |overlay| overlay.path == *path)
}
