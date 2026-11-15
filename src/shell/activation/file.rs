//! zsh's activation files: each activation's output in a file of its own, and
//! zsh's compiled wordcode of that file beside it.
//!
//! # Why a file
//!
//! An output held in the interactive file as `eval '<output>'` is read twice
//! at every start: zsh lexes the whole single-quoted word, then parses the
//! text again inside `eval`. No compiled form can save the second parse,
//! since a `.zwc` of the interactive file would hold only the string. So zsh's
//! interactive file holds, under each `# bx activation: NAME` line, the one
//! guarded line that sources [`source`] — the same `[[ -r … ]] && source …`
//! a plugin is — and that file holds the output **byte for byte**, as the
//! tool printed it once `PATH` was made live (see the parent module). bash
//! keeps its `eval`: bash has no compiled form to gain.
//!
//! # The wordcode
//!
//! While the plan decides, [`compile`] runs the `zsh` it finds on the search
//! path the inputs took — `zcompile -U` in a `zsh -f`, on a copy of the
//! output in a scratch directory under the system's temporary directory,
//! named as [`source`] is and relative to that directory — and reads back the
//! `.zwc` beside it. That file's
//! bytes become the [`wordcode`] target, written after the output's own file,
//! so its modification time is not older than the file it compiles. `-f` and
//! `-U` keep every alias out of the compiled code — none is defined in a zsh
//! that read no startup file, and `-U` would not expand one that were — so
//! the code is the same whatever aliases the account defines. A shell
//! loading compiled code parses nothing, so it expands none of its own
//! aliases into the tool's code either, which is what the tools write
//! `builtin` and `command` throughout to avoid. zsh's
//! `source` reads `NAME.zsh.zwc` in
//! place of `NAME.zsh` when the `.zwc` is at least as new as the file and
//! was written by the same zsh version; otherwise it reads the file, so a
//! zsh that differs from the one the plan found, or a `.zwc` an interrupted
//! write left older than its file, costs the compiled form and nothing else.
//!
//! The wordcode is deterministic: the same zsh, compiling the same bytes under
//! the same name, writes the same `.zwc`, which holds the name it was given
//! and zsh's version and no time — and no directory, since the name it is
//! given is relative. It is cached in the [`Fingerprints`] store
//! under [`KEY_PREFIX`] and the activation's name, against the content and
//! path of the `zsh` binary, the file's name and the output, so a second plan
//! on an unchanged machine starts no zsh. A machine with no `zsh` on that
//! path, or a `zsh` that does not compile the output, gets no `.zwc`, and the
//! interactive file sources the output's own file as it would anyway.
//!
//! # Invariants
//!
//! Both files are generated files bx owns whole: journalled, ledgered, and
//! taken back by `bx rm` and by the undeclared-cleanup once no activation
//! renders them, exactly as the interactive file is. Invariant 2 is held where
//! it always was: the output is judged by the relocation rule before any of
//! it becomes a target, and an output with a refusal writes neither file. The
//! line bx adds sets nothing and starts nothing (invariant 6); what the output
//! runs, it runs as it did inside the `eval`.

use std::path::Path;

use super::Host;
use crate::config::Origin;
use crate::config::target::{Attach, Body, Direction, Format, Gen, Target};
use crate::detect::Presence;
use crate::paths::Portable;
use crate::state::{ContentHash, Fingerprint, Fingerprints};

/// The directory every activation's files are written in.
pub const DIR: &str = "~/.local/share/bx/activation";

/// The prefix of every cache key holding an activation's compiled wordcode.
/// Neither [`super::KEY_PREFIX`] nor [`super::BASH_KEY_PREFIX`] extends to
/// it, so no activation name spells one store's key as another's.
pub const KEY_PREFIX: &str = "activation-zwc:";

/// What `zsh -c` runs to compile its second argument, named relative to its
/// first, into `<it>.zwc`.
const ZCOMPILE: &str = "cd -- \"$1\" && zcompile -U -- \"$2\"";

/// The name the files of the activation `name` share, before `.zsh`: the name
/// itself when it is made of ASCII letters, digits, `_` and `-`, and
/// otherwise `x.` and a digest of the name, which no such name spells.
///
/// An activation's name is any one line of text, which a file name and a
/// bare shell word cannot all hold.
#[must_use]
pub fn stem(name: &str) -> String {
    if !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        name.to_string()
    } else {
        format!("x.{}", &ContentHash::of(name.as_bytes()).to_hex()[..16])
    }
}

/// Where the activation `name`'s output is written, home-relative.
#[must_use]
pub fn source(name: &str) -> String {
    format!("{DIR}/{}.zsh", stem(name))
}

/// Where the activation `name`'s compiled wordcode is written: beside
/// [`source`], where zsh's `source` looks for it.
#[must_use]
pub fn wordcode(name: &str) -> String {
    format!("{}.zwc", source(name))
}

/// The line zsh's interactive file sources the activation `name`'s output
/// with: the guarded line a plugin is, which sets nothing and starts nothing.
#[must_use]
pub fn line(name: &str) -> String {
    crate::shell::plugin::guarded(&source(name))
}

/// One zsh activation's compiled wordcode, as the plan decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wordcode {
    /// The `.zwc`'s bytes.
    pub bytes: Vec<u8>,
    /// The cache entry recording them, when zsh compiled them during this
    /// plan; `None` when the cache already held them.
    pub entry: Option<Fingerprint>,
}

/// The digest of everything a `.zwc` is a function of: the compiling zsh's
/// content and path, the file's name, and the output.
fn inputs(zsh: &ContentHash, path: &Path, stem: &str, output: &str) -> ContentHash {
    let mut bytes = b"bx.activation.zwc.v1\0".to_vec();
    let mut field = |value: &[u8]| {
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value);
    };
    field(zsh.as_bytes());
    field(path.as_os_str().as_encoded_bytes());
    field(stem.as_bytes());
    field(output.as_bytes());
    ContentHash::of(&bytes)
}

/// The cache entry for `bytes` compiled from `inputs`: the digest, then the
/// wordcode.
fn encode(inputs: &ContentHash, bytes: &[u8]) -> Fingerprint {
    let mut raw = inputs.as_bytes().to_vec();
    raw.extend_from_slice(bytes);
    Fingerprint::raw(raw)
}

/// The wordcode `entry` holds, when it was compiled from `inputs`.
fn decode(entry: &Fingerprint, inputs: &ContentHash) -> Option<Vec<u8>> {
    let (digest, bytes) = entry.as_bytes().split_at_checked(inputs.as_bytes().len())?;
    (digest == inputs.as_bytes() && !bytes.is_empty()).then(|| bytes.to_vec())
}

/// zsh's wordcode of the activation `name`'s `output`: reused from `cache`
/// while the zsh `host` finds and the output are the ones it was compiled
/// from, and otherwise compiled now. `None` when there is no zsh, or it does
/// not compile the output, and the output's own file is sourced as it is.
pub fn compile(
    name: &str,
    output: &str,
    cache: &Fingerprints,
    host: &impl Host,
) -> Option<Wordcode> {
    let Presence::Present { path: zsh } = host.locate("zsh") else {
        return None;
    };
    let content = host.hash(&zsh).ok()?;
    let stem = stem(name);
    let inputs = inputs(&content, &zsh, &stem, output);
    let key = format!("{KEY_PREFIX}{name}");
    if let Some(bytes) = cache.get(&key).and_then(|entry| decode(entry, &inputs)) {
        return Some(Wordcode { bytes, entry: None });
    }
    match zcompile(host, &zsh, &stem, output) {
        Ok(bytes) if !bytes.is_empty() => Some(Wordcode {
            entry: Some(encode(&inputs, &bytes)),
            bytes,
        }),
        Ok(_) => None,
        Err(reason) => {
            tracing::debug!("zsh did not compile activation `{name}`: {reason}");
            None
        }
    }
}

/// Run `zsh`'s `zcompile` on `output`, written as `<stem>.zsh` in a scratch
/// directory, and return the `.zwc` it wrote beside it.
///
/// The file is named relative to the scratch directory, because the `.zwc`
/// records the name it was given: an absolute one would put the scratch
/// directory's random name in the bytes.
fn zcompile(host: &impl Host, zsh: &Path, stem: &str, output: &str) -> Result<Vec<u8>, String> {
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    let name = format!("{stem}.zsh");
    let file = scratch.path().join(&name);
    std::fs::write(&file, output).map_err(|e| e.to_string())?;
    let dir = scratch
        .path()
        .to_str()
        .ok_or("the scratch directory's path is not UTF-8")?;
    let args = ["-f", "-c", ZCOMPILE, "zsh", dir, &name].map(str::to_string);
    host.run(zsh, &args).map_err(|e| e.to_string())?;
    let mut compiled = file.into_os_string();
    compiled.push(".zwc");
    std::fs::read(&compiled).map_err(|e| e.to_string())
}

/// The targets the activation `name`'s `output` and its `wordcode` are
/// written as: the output's own file first, so the `.zwc` written after it is
/// never the older of the two.
#[must_use]
pub fn targets(
    name: &str,
    output: &str,
    wordcode: Option<&Wordcode>,
    origin: &Origin,
) -> Vec<Target> {
    let target = |path: String, generator: Gen| Target {
        path: Portable::try_from(path).expect("an activation file's path is portable"),
        body: Body::Generated(generator),
        mode: None,
        attach: Attach::Own,
        direction: Direction::Apply,
        format: Format::Opaque,
        requires: Vec::new(),
        references: Vec::new(),
        enabled: true,
        origin: origin.clone(),
        gates: Vec::new(),
    };
    std::iter::once(target(source(name), Gen::Activation(output.to_string())))
        .chain(wordcode.map(|code| target(self::wordcode(name), Gen::Wordcode(code.bytes.clone()))))
        .collect()
}
