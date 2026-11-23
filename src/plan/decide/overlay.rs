//! A shared target's bytes with this machine's overlays merged in.
//!
//! What an overlay is, and which targets take one, is
//! [`crate::config::overlay`]'s; the merge itself is [`crate::overlay`]'s.
//! This is the step between: finding the overlays that name a target, reading
//! their fragments, and turning a merge bx cannot make into a blocked row
//! rather than a guess.

use std::path::Path;

use super::super::Error;
use crate::config::overlay::{Overlay, naming};
use crate::config::target::Target;
use crate::overlay::{self, Syntax};

/// A target's bytes once its overlays are merged in, and what went into them.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Layered {
    /// The shared body every machine without an overlay gets, laid out as
    /// the merge lays out what it writes, so the diff between the two shows
    /// only what the overlays add.
    pub shared: Vec<u8>,
    /// Each overlay merged in, as a row names it: its name and its origin.
    pub applied: Vec<String>,
}

/// Read each overlay's fragment.
///
/// # Errors
///
/// [`Error::Body`] at the overlay, naming a `file` that cannot be read.
fn fragments(overlays: &[&Overlay], repo: &Path) -> Result<Vec<Vec<u8>>, Error> {
    overlays
        .iter()
        .map(|overlay| {
            overlay.read(repo).map_err(|(path, source)| Error::Body {
                origin: overlay.origin.clone(),
                path,
                source,
            })
        })
        .collect()
}

/// A target's bytes with its overlays merged in, and what went into them;
/// or, where they cannot be merged, the note its blocked row carries.
pub(super) type Merged = Result<(Vec<u8>, Option<Layered>), String>;

/// `shared` with every overlay naming `target` merged in.
///
/// `Ok(Ok((bytes, None)))` when no overlay names it: the shared bytes,
/// untouched. `Ok(Err(note))` when the merge cannot be made — a fragment or
/// the shared body that does not parse, or a key both set differently — which
/// blocks the target's row with the note.
///
/// # Errors
///
/// [`Error::Body`] for an overlay `file` that cannot be read.
pub(super) fn layered(
    target: &Target,
    shared: Vec<u8>,
    overlays: &[Overlay],
    repo: &Path,
) -> Result<Merged, Error> {
    let named: Vec<&Overlay> = naming(overlays, &target.path).collect();
    if named.is_empty() {
        return Ok(Ok((shared, None)));
    }
    let Some(syntax) = Syntax::of(Path::new(target.path.as_str())) else {
        // The parser refuses an overlay path with any other extension, and an
        // overlay names its target by that path.
        return Ok(Err(format!(
            "an overlay adds to `{}`, which is not a JSON or TOML file",
            target.path
        )));
    };
    let bytes = fragments(&named, repo)?;
    let parts: Vec<overlay::Fragment<'_>> = named
        .iter()
        .zip(&bytes)
        .map(|(overlay, bytes)| overlay::Fragment {
            name: &overlay.name,
            bytes,
        })
        .collect();
    let merged = overlay::merge(syntax, &shared, &parts)
        .and_then(|merged| Ok((merged, overlay::canonical(syntax, &shared)?)));
    Ok(match merged {
        Ok((merged, shared)) => Ok((
            merged,
            Some(Layered {
                shared,
                applied: named
                    .iter()
                    .map(|overlay| format!("`{}` ({})", overlay.name, overlay.origin))
                    .collect(),
            }),
        )),
        Err(why) => Err(format!(
            "this machine's overlays cannot be merged into the shared body: {why}"
        )),
    })
}
