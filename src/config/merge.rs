//! Folding the ordered layer set into one configuration.
//!
//! Every keyed list section — `[[target]]`, `[[value]]`, and every list type the
//! shell, inventory and secrets blocks will add — merges by the entry's **natural
//! key**. A later layer whose entry has a key already present **replaces that
//! entry in place**, keeping its position; a key not already present
//! **appends**. `[values]` merges as scalars, last layer wins.
//!
//! Replacement is **wholesale, not field-wise**. A later `[[target]]` with a
//! known `path` replaces the earlier one entirely. A field-wise merge would make
//! the resolved value of any one field depend on a three-layer interaction that
//! nobody can read off the files, and `bx plan` printing one origin per entry
//! would then be a lie.
//!
//! # A target's key is the file it names
//!
//! A target's `path` may carry a `{{name}}`, so the text as written is not the
//! file. Targets are compared **after substitution**, against the values this
//! account ends up with: `~/.config/{{acct}}/settings.json` in `bx.toml` and
//! `~/.config/one/settings.json` in `local.toml`, with `acct` answered `one`,
//! are one target, and the later one replaces or toggles the earlier. Compared
//! as written they were two targets owning one file — two ledger rows for it,
//! so `rm` restores the wrong prior, and two writers, so the second `plan` is
//! never empty.
//!
//! So the merge resolves the values first, and a target's key is its
//! substituted, normalised path. A path waiting on a value with no usable
//! answer names no file yet; it is keyed by its spelling, and a toggle reaches
//! it by that spelling. One layer naming one file twice, under any two
//! spellings, is an error, as it is under one — when no account answer went
//! into either spelling, or when the two spellings are one path before any
//! answer goes in, which is decided by reducing each spelling with its
//! placeholders unanswered. That is sound: a pair the reduction calls one path
//! is one file for every answer, or none. It is complete over the shapes the
//! fixed-seed property test generates, not over every spelling. The shapes it
//! is known not to decide are registered and executed under *Shapes the written
//! form does not decide* below. A `..` cancels a placeholder's segment only for a `bool`,
//! which is always one segment, as a `string` need not be.
//!
//! When one did, the collision is the account's. `bx.toml` declaring
//! `~/.config/{{profile}}/s` and `~/.config/default/s` names two files as
//! written, and `profile = "default"` makes them one. Failing the load would
//! name a committed file the account cannot edit and take every unrelated
//! target with it, so instead both entries are kept and recorded as a
//! [`Conflict`], and resolution blocks each one, naming both lines and the
//! answer's. A later layer that names the file settles it.
//!
//! # Shapes the written form does not decide
//!
//! This is what [`written_form`], [`one_path_as_written`] and [`Root`] point
//! at. It is here, in the tree, rather than in a review thread, so that a
//! maintainer changing the reduction reads the limitation beside the code it
//! limits, and so that it outlives whatever tracker entry carried it.
//!
//! **What holds.** The form is *sound*: two spellings with one form name one
//! file for every answer, or no file for any. It is *complete over the shapes
//! the fixed-seed property test generates* — there, two spellings with
//! different forms are parted by some answer in the set, so the collision is
//! one the account can clear.
//!
//! **What does not hold.** The form does not recognise every pair that names
//! one file for every answer. When it misses one, a layer that spells the same
//! file twice loads `Ok` and the file is blocked as a [`Conflict`], whose
//! "change that answer" hint no answer satisfies. **No general rule is claimed
//! for which pairs are missed.** Several rounds of review each proposed one and
//! each was found unsound or too narrow.
//!
//! **A miss is reached as a toggle, not as a full entry.** A `[[target]]`'s
//! `path` is a [`Portable`](crate::paths::Portable) parsed by
//! `Portable::parse_in`, which normalises the spelling with its placeholders
//! still in it; a spelling it rejects, and a pair whose normalised spellings
//! coincide, are both refused before `merge` runs. Which rule catches a given
//! registered spelling differs between them, and nothing here depends on
//! which. A toggle names a key by the spelling it reaches and is held to none
//! of those rules, so that is the route by which one of these pairs becomes a
//! [`Conflict`]. The two halves are executed at different widths, deliberately:
//! `no_registered_pair_reaches_the_comparison_as_full_entries` asserts the
//! full-entry refusal for **every** entry in `UNDECIDED`, since that half
//! generalises and a new entry must satisfy it too, while
//! `a_registered_pair_reaches_the_comparison_as_a_toggle_and_not_as_a_full_entry`
//! carries **one** worked pair all the way to a blocked file, since that half
//! needs an anchor target chosen for the pair.
//!
//! **The two registers are tests, not prose**, so that each entry is measured
//! at the head it is published against rather than carried forward:
//!
//! - `UNDECIDED`, asserted by
//!   `every_pair_the_written_form_is_known_to_miss_is_still_missed`, holds the
//!   pairs whose forms differ while, under some home, every answer keys them as
//!   one file. Each entry says what makes it undecided. A repair that decides
//!   one turns that test red, and the pair then moves into the fuzz's
//!   `segments` and `openers` arrays.
//! - `REFUTED`, asserted by `every_rule_the_written_form_refused_is_still_refuted`,
//!   holds each proposed rule with the two spellings and the answer that parts
//!   them, so none is re-adopted on the strength of a claim nobody re-ran.
//!
//! Both draw their answers from `answer_sets`, which the fuzz draws from too,
//! and which varies the home as well as the values — so neither register can
//! claim evidence the fuzz was not asserted over. Widening the fuzz's
//! generators to draw a registered shape turns its completeness assertion red,
//! which is the same fact as a register entry and not a second instruction:
//! decide the shape in `written_form` first, then move it.
//!
//! # Toggles: how an account opts out cheaply
//!
//! A list entry whose only keys are its natural key and `enabled` is a
//! **toggle**. It flips the flag on the existing entry and leaves every other
//! field alone, so opting out of a target costs three lines in `local.toml`
//! rather than a copy of the whole target — body included — that the account
//! wants gone. An entry with any further key is a full replacement and must
//! parse as a complete, valid entry.
//!
//! `enabled` is an ordinary scalar, so the last layer that sets it wins and a
//! later layer may re-enable. Since `local.toml` is the last layer, an account
//! can always have the final word, which is the point of the mechanism.
//!
//! A toggle naming a key **no earlier layer introduced** is an error. A
//! misspelled path in `local.toml` would otherwise be a silent no-op, and a
//! silent no-op in an opt-out mechanism is how an account ends up with a file it
//! explicitly refused.
//!
//! # Determinism
//!
//! The merge is a pure function of the layer files' bytes and the home threaded
//! in. It reads no
//! environment variable, calls no `canonicalize`, spawns nothing, and iterates
//! no hash map: entries live in a `Vec` in insertion order and lookup is a
//! linear scan. Invariant 3 says two `plan` runs a week apart on an unchanged
//! tree are byte-identical, and an entry order that came from a hash would make
//! that false in a way no reviewer could see.

use std::path::Path;

use toml_edit::Table;

use super::target::Target;
use super::values::{Piece, ResolvedValues, ValueAssignment, ValueDecl, ValueKind, scan};
use super::{Config, Ctx, Error, Layer, LayerKind, Origin};
use crate::paths::Portable;

/// A list entry that merges by a natural key.
///
/// Implemented by every keyed list type. The natural-key table in the
/// architecture specification is the whole contract, so a later entry that adds
/// a list type implements this and writes no merge logic of its own.
pub trait Keyed {
    /// The natural key: `path` for a target, `name` for a value.
    ///
    /// As written. A target is merged by the file this names once substituted,
    /// which is not a function of the entry alone; see [`merge`].
    fn key(&self) -> &str;
    /// The layer and line that last set this entry.
    fn origin(&self) -> &Origin;
    /// Whether the entry survives into the resolved configuration.
    fn enabled(&self) -> bool;
    /// Flip the flag, as a toggle does.
    fn set_enabled(&mut self, enabled: bool);
}

impl Keyed for Target {
    // Unreachable from `merge`, which keys targets by the file they name
    // (`TargetKey`); kept because `Keyed` requires it of a public list type.
    fn key(&self) -> &str {
        self.path.as_str()
    }
    fn origin(&self) -> &Origin {
        &self.origin
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for ValueDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn origin(&self) -> &Origin {
        &self.origin
    }
    // Unreachable from `merge`, which keeps disabled declarations with
    // `into_entries`; kept because `Keyed` requires it of a public list type.
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// Which keyed list an entry belongs to.
///
/// An enum rather than the section's name, because [`Toggle`], [`Config`],
/// [`Layer`] and [`merge`] are all public: a section string with no arm in the
/// merge would panic a library call, and a `&str` match has no exhaustiveness
/// checking to stop one being written. The later entries that add keyed sections
/// are exactly the callers that would have hit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// `[[target]]`, keyed by `path`.
    Target,
    /// `[[value]]`, keyed by `name`.
    Value,
}

impl Section {
    /// The TOML key the section is written under.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Value => "value",
        }
    }

    /// The section header, as messages spell it.
    #[must_use]
    pub fn header(self) -> &'static str {
        match self {
            Self::Target => super::target::SECTION,
            Self::Value => super::values::DECL_SECTION,
        }
    }

    /// The natural key an entry in this section merges by.
    #[must_use]
    pub fn natural_key(self) -> &'static str {
        match self {
            Self::Target => "path",
            Self::Value => "name",
        }
    }

    /// What a *full* entry in this section still needs.
    ///
    /// For the one message that has to cover both readings of a toggle-shaped
    /// table: a toggle naming an entry nothing introduced, or an entry somebody
    /// meant to write in full and left incomplete.
    fn a_full_entry_needs(self) -> &'static str {
        match self {
            Self::Target => "one of `file`, `content`, `generated` or `dir`",
            Self::Value => "a `kind`",
        }
    }
}

/// A list entry that restates only its key and its `enabled` flag.
///
/// Parsed rather than resolved: which list it belongs to is carried as a
/// [`Section`] so one representation serves every keyed section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toggle {
    /// The section it appeared in.
    pub section: Section,
    /// The natural key of the entry it flips.
    pub key: String,
    /// What to flip it to.
    pub enabled: bool,
    /// Where the toggle was written.
    pub origin: Origin,
}

/// Read `table` as a toggle, if that is its whole shape.
///
/// A table whose keys are exactly the natural key and `enabled` is a toggle;
/// anything else is a full entry and is handed to its own parser. The types are
/// checked here rather than deferred, so `enabled = "false"` is reported as the
/// wrong type for `enabled` rather than as a target with no body.
///
/// # Errors
///
/// [`Error::WrongType`] when the two keys are present but not as a string and a
/// boolean.
pub(crate) fn toggle_of(
    table: &Table,
    section: Section,
    file: &Path,
    text: &str,
) -> Result<Option<Toggle>, Error> {
    let natural_key = section.natural_key();
    let keys: Vec<&str> = table.iter().map(|(key, _)| key).collect();
    if keys.len() != 2 || !keys.contains(&natural_key) || !keys.contains(&"enabled") {
        return Ok(None);
    }

    let ctx = Ctx::new(table, file, text, section.header());
    let key = ctx.required_str(table, natural_key)?;
    let enabled = ctx
        .bool_at(table, "enabled")?
        .ok_or_else(|| Error::WrongType {
            origin: ctx.key_origin(table, "enabled"),
            key: "enabled".to_string(),
            expected: "a boolean",
            found: "nothing",
        })?;

    Ok(Some(Toggle {
        section,
        key: key.to_string(),
        enabled,
        origin: ctx.origin().clone(),
    }))
}

/// One keyed list, mid-merge.
///
/// Insertion-ordered. Lookup is a linear scan, which is right for a list a few
/// dozen entries long and is the only lookup with no iteration order to get
/// wrong.
///
/// Each entry is held beside the key it merges by. For a value that is its name
/// as written; for a target it is the file its path names once substituted,
/// which is not a function of the entry alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged<T, K = String> {
    entries: Vec<(K, T)>,
}

impl<T, K> Default for Merged<T, K> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T: Keyed> Merged<T> {
    /// Fold one later layer's entries in, keyed by their natural key as written.
    ///
    /// A known key is replaced **wholesale and in place**; a new key appends.
    pub fn absorb(&mut self, later: impl IntoIterator<Item = T>) {
        for entry in later {
            let key = entry.key().to_string();
            match self.position(&key) {
                Some(index) => self.entries[index] = (key, entry),
                None => self.entries.push((key, entry)),
            }
        }
    }

    /// Apply one toggle, matched by its natural key as written.
    ///
    /// # Errors
    ///
    /// [`Error::BadValue`] when no earlier layer introduced the key. A silent
    /// no-op here is how an account ends up with a file it explicitly refused.
    pub fn toggle(&mut self, toggle: &Toggle) -> Result<(), Error> {
        let index = self
            .position(&toggle.key)
            .ok_or_else(|| unknown_toggle(toggle, ""))?;
        self.entries[index].1.set_enabled(toggle.enabled);
        Ok(())
    }
}

impl<T: Keyed, K: PartialEq> Merged<T, K> {
    /// The entries that survive, in order.
    ///
    /// Disabled entries stay in the list until this point, so a disable in one
    /// layer followed by a re-enable in a later one keeps the original position.
    #[must_use]
    pub fn into_enabled(self) -> Vec<T> {
        self.entries
            .into_iter()
            .map(|(_, entry)| entry)
            .filter(Keyed::enabled)
            .collect()
    }

    /// Every entry, disabled ones included, in order.
    ///
    /// For a list whose entries are referred to **by name** from elsewhere in
    /// the configuration. Dropping a disabled one would make a reference to it
    /// indistinguishable from a reference to a name no layer ever declared,
    /// which is a different fault with a different outcome.
    #[must_use]
    pub fn into_entries(self) -> Vec<T> {
        self.entries.into_iter().map(|(_, entry)| entry).collect()
    }

    /// Where `key` sits, if it is present.
    fn position(&self, key: &K) -> Option<usize> {
        self.entries.iter().position(|(held, _)| held == key)
    }
}

/// The message for a toggle that matches nothing.
///
/// Both readings, because nothing here can tell them apart: a table holding
/// only the natural key and `enabled` is a toggle wherever it appears, so in the
/// first layer an entry somebody meant to write in full and left incomplete
/// arrives here too. `more` is appended, for a section with something further
/// to say about which spelling would have matched.
fn unknown_toggle(toggle: &Toggle, more: &str) -> Error {
    Error::BadValue {
        origin: toggle.origin.clone(),
        message: format!(
            "`{}` toggles `{}`, which no earlier layer declares; a toggle — an \
             entry with only `{}` and `enabled` — may only flip an entry that \
             already exists, and a new entry needs {}{more}",
            toggle.section.header(),
            toggle.key,
            toggle.section.natural_key(),
            toggle.section.a_full_entry_needs(),
        ),
    }
}

/// What a target merges by: the file it names, for this account.
///
/// Compared **after substitution**, so `~/.config/{{acct}}/settings.json` with
/// `acct` answered `one` and `~/.config/one/settings.json` are one key.
/// `Portable` is what the ledger and the journal are written against, and two
/// targets for one file would give `rm` two priors to restore.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetKey {
    /// The substituted, normalised path.
    File(String),
    /// The path as written: it waits on a value with no usable answer, or it
    /// substitutes to something that is not a portable path, which resolution
    /// reports. Two of these match only when they are spelled identically.
    AsWritten(String),
}

impl TargetKey {
    /// The key of a path spelled `raw`.
    fn of(raw: &str, values: &ResolvedValues) -> Self {
        values
            .substitute(raw)
            .ok()
            .and_then(|text| Portable::parse_in(&text, values.home()).ok())
            .map_or_else(
                || Self::AsWritten(raw.to_string()),
                |path| Self::File(path.as_str().to_string()),
            )
    }
}

/// A file one layer names more than once, only because of this account's answers.
///
/// Every pair of spellings is two files as written, and an answer made them
/// one. That is the account's to change, so it is not a load error:
/// [`super::resolve`] blocks every target for the file, naming each spelling's
/// line and each answer's. A pair no answer went into is the repo's own defect
/// and still fails the merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Conflict {
    /// The file, as the substituted, normalised path the targets resolve to.
    pub(crate) file: String,
    /// The answers that made the spellings meet, in declaration order.
    pub(crate) names: Vec<String>,
    /// What to do, spelled by [`ResolvedValues::answers_hint`].
    pub(crate) hint: String,
}

/// One statement a layer made about a target: a full entry, or a toggle.
struct Said {
    /// The file it names.
    key: TargetKey,
    /// Its path as written.
    spelling: String,
    /// Where it was written.
    origin: Origin,
}

/// A [`Conflict`] while the layers are still being folded.
struct Clash {
    /// The layer whose statements collided.
    layer: std::path::PathBuf,
    /// The file they collided on.
    key: TargetKey,
    /// Every statement in that layer naming the file, in the order read.
    statements: Vec<(String, Origin)>,
    /// The answers that went into them.
    names: Vec<String>,
}

impl Clash {
    /// The conflict resolution reads, with its hint spelled.
    fn into_conflict(self, values: &ResolvedValues) -> Conflict {
        let (TargetKey::File(file) | TargetKey::AsWritten(file)) = self.key;
        let spellings = self
            .statements
            .iter()
            .map(|(spelling, origin)| format!("`{spelling}` at {origin}"))
            .collect::<Vec<_>>()
            .join(" and ");
        let names = values.in_declaration_order(self.names);
        let problem = format!(
            "`[[target]]` {spellings} name one file, `{file}`, and one layer may name a \
             file once"
        );
        let texts: Vec<&str> = self
            .statements
            .iter()
            .map(|(spelling, _)| spelling.as_str())
            .collect();
        Conflict {
            hint: values.answers_hint(&problem, &texts, &names),
            file,
            names,
        }
    }
}

impl Merged<Target, TargetKey> {
    /// Fold one layer's targets and target toggles in, keyed by the file each
    /// one names.
    ///
    /// One layer naming one file twice would leave the outcome to an order
    /// nothing in the file states. When an account answer made the two
    /// spellings meet, the statements are recorded as a [`Clash`] rather than
    /// applied: both entries are kept, the later one directly after the entries
    /// already held for the file rather than at the end, and every entry for the
    /// file is held enabled, so resolution blocks each one where the file's rows
    /// are instead of hiding it. A file's rows stay contiguous and in the order
    /// written, and unrelated targets keep their order among themselves; which
    /// slot the file holds is decided by the answer, though, so a later row for
    /// it can sit ahead of an unrelated target for one answer and not another.
    /// A later layer that names the file settles it — a full entry replaces
    /// every entry for it, and a toggle flips every one.
    ///
    /// # Errors
    ///
    /// [`Error::BadValue`] when a toggle names a file no earlier layer declares,
    /// or when this one layer names one file twice under two spellings with no
    /// account answer in either — the parser's own duplicate check compares
    /// spellings, and cannot see that `~/{{acct}}/x` and `~/one/x` are one file
    /// — or under two spellings that reduce to one text with their placeholders
    /// left in, which no answer could pull apart.
    fn absorb_layer(
        &mut self,
        layer: &Layer,
        values: &ResolvedValues,
        clashes: &mut Vec<Clash>,
    ) -> Result<(), Error> {
        // What this layer has said so far, statement by statement.
        let mut said: Vec<Said> = Vec::new();

        for target in &layer.config.targets {
            let spelling = target.path.as_str();
            let key = TargetKey::of(spelling, values);
            match self.position(&key) {
                None => self.entries.push((key.clone(), target.clone())),
                Some(index) => {
                    let statement = (spelling, &target.origin);
                    if clash(&said, &key, statement, values, &layer.file, clashes)? {
                        // Beside the entries already held for the file, not at
                        // the end: the file's rows stay together and in written
                        // order. The slot is wherever the file's first row
                        // landed, which the answer decided, so this row can sit
                        // ahead of an unrelated target written before it.
                        let beside = self.positions(&key).into_iter().last().unwrap_or(index) + 1;
                        self.entries.insert(beside, (key.clone(), target.clone()));
                        self.set_enabled_for(&key, true);
                    } else {
                        // A full entry replaces every entry for the file: it
                        // takes the first one's place and the rest go.
                        self.entries[index] = (key.clone(), target.clone());
                        let mut first = true;
                        self.entries
                            .retain(|(held, _)| held != &key || std::mem::take(&mut first));
                        clashes.retain(|clash| clash.key != key);
                    }
                }
            }
            said.push(Said {
                key,
                spelling: spelling.to_string(),
                origin: target.origin.clone(),
            });
        }

        for toggle in &layer.config.toggles {
            // Exhaustive over `Section`, so a keyed list added later is a
            // compile error here rather than a panic in a library call.
            match toggle.section {
                Section::Target => {
                    let key = TargetKey::of(&toggle.key, values);
                    if self.position(&key).is_none() {
                        return Err(unknown_toggle(toggle, &self.as_written_note()));
                    }
                    let statement = (toggle.key.as_str(), &toggle.origin);
                    if clash(&said, &key, statement, values, &layer.file, clashes)? {
                        self.set_enabled_for(&key, true);
                    } else {
                        self.set_enabled_for(&key, toggle.enabled);
                    }
                    said.push(Said {
                        key,
                        spelling: toggle.key.clone(),
                        origin: toggle.origin.clone(),
                    });
                }
                Section::Value => {}
            }
        }

        Ok(())
    }

    /// Every position holding `key`, in order. More than one only while a
    /// [`Clash`] keeps two entries for one file.
    fn positions(&self, key: &TargetKey) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, (held, _))| held == key)
            .map(|(index, _)| index)
            .collect()
    }

    /// Set the flag on every entry for `key`.
    fn set_enabled_for(&mut self, key: &TargetKey, enabled: bool) {
        for (held, entry) in &mut self.entries {
            if held == key {
                entry.set_enabled(enabled);
            }
        }
    }

    /// Which spelling reaches a target whose file is not known yet, if any is.
    ///
    /// Without it, a toggle by the path `plan` would show once the value is
    /// answered reads as naming an entry that does not exist.
    fn as_written_note(&self) -> String {
        self.entries
            .iter()
            .find_map(|(key, target)| match key {
                TargetKey::AsWritten(_) => Some(format!(
                    "; a target whose `path` waits on a value with no usable answer is \
                     matched by the spelling it was declared with, such as `{}` at {}",
                    target.path, target.origin
                )),
                TargetKey::File(_) => None,
            })
            .unwrap_or_default()
    }
}

/// Whether a statement names a file its own layer has already named.
///
/// `Ok(false)` when nothing said earlier in this layer names the file, which
/// leaves the statement to replace or toggle as usual. When something does,
/// every such pair has to be the account's doing. A pair with no account answer
/// in either spelling, or whose two spellings are one path before any answer
/// goes in (`~/.config/{{p}}/s` and `~/.config/{{p}}/./s`; see
/// [`one_path_as_written`]), names one file for every account whatever is
/// answered, which is the repo's defect and fails the merge. Otherwise the
/// collision is the account's, it is
/// recorded against this layer, replacing what was recorded for the file so far
/// with every statement this layer has made about it, and the answer is
/// `Ok(true)`.
fn clash(
    said: &[Said],
    key: &TargetKey,
    (spelling, origin): (&str, &Origin),
    values: &ResolvedValues,
    layer: &Path,
    clashes: &mut Vec<Clash>,
) -> Result<bool, Error> {
    let earlier: Vec<&Said> = said
        .iter()
        .filter(|statement| statement.key == *key)
        .collect();
    if earlier.is_empty() {
        return Ok(false);
    }

    let mine = values.account_inputs(spelling);
    let mut names = mine.clone();
    for statement in &earlier {
        let theirs = values.account_inputs(&statement.spelling);
        // No answer in either spelling, or two spellings that are one path
        // before any answer goes in: either way the pair names one file for
        // every account, and no answer could clear it.
        if (mine.is_empty() && theirs.is_empty())
            || one_path_as_written(spelling, &statement.spelling, values)
        {
            return Err(refuse_twice(statement, spelling, origin));
        }
        for name in theirs {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    let mut statements: Vec<(String, Origin)> = earlier
        .iter()
        .map(|statement| (statement.spelling.clone(), statement.origin.clone()))
        .collect();
    statements.push((spelling.to_string(), origin.clone()));
    clashes.retain(|clash| !(clash.key == *key && clash.layer == layer));
    clashes.push(Clash {
        layer: layer.to_path_buf(),
        key: key.clone(),
        statements,
        names,
    });
    Ok(true)
}

/// Whether two spellings name one file whatever is answered.
///
/// When their [`written_form`]s are identical. The same answers put into one
/// form give one text, so identical forms name one file for every answer, or no
/// file for any: the comparison is sound. It is complete over the shapes the
/// fixed-seed property test generates: there, forms that differ are parted by
/// some answer, so the collision is one the account can clear. It is not
/// complete over every spelling. The shapes it is known not to decide are
/// registered and executed as `UNDECIDED`, under *Shapes the written form does
/// not decide* in the [module documentation](self).
///
/// Only spellings whose keys are one [`TargetKey::File`] are compared here, so
/// every placeholder in either is declared, enabled and answered: a
/// substitution that failed would have keyed the spelling as written.
fn one_path_as_written(first: &str, second: &str, values: &ResolvedValues) -> bool {
    written_form(first, values).is_some_and(|form| Some(form) == written_form(second, values))
}

/// A spelling reduced by the lexical rule, with its placeholders unanswered.
#[derive(Debug, PartialEq, Eq)]
struct WrittenForm<'a> {
    root: Root<'a>,
    segments: Vec<Segment<'a>>,
}

/// Where a [`WrittenForm`] is rooted.
///
/// Part of the form [`one_path_as_written`] compares, which is sound and
/// complete over the shapes the fixed-seed property test generates; the known
/// shapes it does not decide are listed under *Shapes the written form does not
/// decide* in the [module documentation](self).
#[derive(Debug, PartialEq, Eq)]
enum Root<'a> {
    /// `/`, or a `path` value opening the spelling, alone or with text glued
    /// after it. Every `path` answer is absolute, so a `path` value starts its
    /// own segment (see [`written_form`]).
    Absolute,
    /// `~`, whether a `/` or a `path` value follows it.
    Home,
    /// Whatever the answers make of the first segment, which the lexical rule
    /// cannot see into: an answer may root it at `~`, at `/`, or not at all.
    /// Whether anything follows it matters as well, since an empty answer makes
    /// the segment nothing, and the segment with a separator after it `/`,
    /// but only when every piece of the segment is a `string` placeholder: any
    /// other piece is never empty, and a text that is not empty is one path
    /// with a separator after it or without, so `followed` is then `false`.
    Opening {
        first: Vec<Piece<'a>>,
        followed: bool,
    },
}

/// One segment of a [`WrittenForm`].
#[derive(Debug, PartialEq, Eq)]
enum Segment<'a> {
    /// One ordinary segment whatever is answered: literal text, or text whose
    /// only placeholders are `bool`s, whose answers are never empty and never
    /// hold a `/`. A `..` cancels it.
    Fixed(Vec<Piece<'a>>),
    /// A segment holding a placeholder an answer may make empty, `.`, `..`, or
    /// several segments. Nothing cancels it.
    Opaque(Vec<Piece<'a>>),
    /// A `..` that nothing written before it can be shown to cancel.
    Up,
}

/// `spelling` reduced by the lexical rule, deciding nothing an answer decides.
///
/// The form is sound: identical forms name one file for every answer, or none.
/// It is complete over the shapes the fixed-seed property test generates; the
/// shapes it is known not to decide are registered and executed as `UNDECIDED`,
/// under *Shapes the written form does not decide* in the [module
/// documentation](self).
///
/// A `path` value starts its own segment wherever it sits, as though a `/` were
/// written before it. That changes no file. A `path` answer is absolute and
/// normalised, so its text begins with exactly one `/`, and substituting it
/// after text `x` gives `x/…`, where the spelling with the `/` written gives
/// `x//…`. The two texts differ only by one doubled separator, and keying a
/// path reads a doubled separator as one wherever it falls. At the start, `/…`
/// and `//…` both have the root `/` and a rest with its leading `/` stripped.
/// After a text that is exactly `~`, `~/…` and `~//…` both have the root `~`.
/// After a text that starts with `/` or `~/`, the doubled separator is inside
/// the path and folds. After any other text, neither is a portable path. So the
/// rule holds for
/// every `path` answer, including `/`, `~`, `~/…` and `//srv/`, which are
/// stored as `/`, the home, a path under the home and `/srv`.
///
/// A `.` and an empty segment fold, and a `..` cancels the [`Segment::Fixed`]
/// before it. A `..` after anything else stays in the form, except at `/`, where
/// there is nothing above to climb to; under `~` it is the climb out of the home
/// that no answer rescues.
///
/// A segment is compared by its pieces. A new literal piece starts only after a
/// `{{{{` escape, so a segment spelled `.` or `..` is always one literal piece.
///
/// `None` when `spelling` is not a well-formed template. That is defensive: a
/// spelling keyed as a file substituted, and substitution scans the same text.
fn written_form<'a>(spelling: &'a str, values: &ResolvedValues) -> Option<WrittenForm<'a>> {
    // A name no layer declares is taken as the widest kind. That too is
    // defensive, for the reason `None` is.
    let is = |piece: &Piece<'_>, kind: ValueKind| {
        matches!(piece, Piece::Name(name)
            if values.decl(name).is_some_and(|decl| decl.kind == kind))
    };
    // Only a `string` answer may be empty; a literal piece never is.
    let may_be_empty = |piece: &Piece<'_>| {
        matches!(piece, Piece::Name(name)
            if values.decl(name).is_none_or(|decl| decl.kind == ValueKind::String))
    };

    let mut split: Vec<Vec<Piece<'a>>> = Vec::new();
    let mut current: Vec<Piece<'a>> = Vec::new();
    for piece in scan(spelling).ok()? {
        match piece {
            Piece::Literal(text) => {
                for (index, chunk) in text.split('/').enumerate() {
                    if index > 0 {
                        split.push(std::mem::take(&mut current));
                    }
                    if !chunk.is_empty() {
                        current.push(Piece::Literal(chunk));
                    }
                }
            }
            name @ Piece::Name(_) => {
                // A `path` answer begins with `/`, so the value starts a
                // segment wherever it sits: `x{{r}}` is split as `x/{{r}}` is.
                // What was before it ends there, as an empty segment when
                // nothing was, which folds, or at the start roots the spelling
                // at `/`.
                if is(&name, ValueKind::Path) {
                    split.push(std::mem::take(&mut current));
                }
                current.push(name);
            }
        }
    }
    split.push(current);

    let mut split = split.into_iter();
    // Never the default: the scan loop above is always followed by a final
    // push, so `split` holds at least one segment, even for an empty spelling.
    let first = split.next().unwrap_or_default();
    let followed = !split.as_slice().is_empty();
    let root = if first.is_empty() && followed {
        Root::Absolute
    } else if first == [Piece::Literal("~")] {
        Root::Home
    } else {
        // An empty spelling lands here too, as an empty opening segment with
        // nothing after it. That is defensive: `Portable::parse_in("")` refuses
        // it, so it is never keyed as a file and never reaches `clash`'s
        // comparison.
        //
        // What follows the opening segment parts two spellings only when an
        // answer can make that segment nothing: a non-empty text is one path
        // with a separator after it or without.
        let followed = followed && first.iter().all(may_be_empty);
        Root::Opening { first, followed }
    };

    let mut segments = Vec::new();
    for segment in split {
        if segment.is_empty() || segment == [Piece::Literal(".")] {
            continue;
        }
        if segment == [Piece::Literal("..")] {
            match segments.last() {
                Some(Segment::Fixed(_)) => {
                    segments.pop();
                }
                None if root == Root::Absolute => {}
                _ => segments.push(Segment::Up),
            }
            continue;
        }
        let fixed = segment
            .iter()
            .all(|piece| matches!(piece, Piece::Literal(_)) || is(piece, ValueKind::Bool));
        segments.push(if fixed {
            Segment::Fixed(segment)
        } else {
            Segment::Opaque(segment)
        });
    }
    Some(WrittenForm { root, segments })
}

/// A second statement for one file from one layer, with no answer to blame.
fn refuse_twice(earlier: &Said, spelling: &str, origin: &Origin) -> Error {
    Error::BadValue {
        origin: origin.clone(),
        message: format!(
            "`[[target]]` `{spelling}` names the same file as `{}` at {} in this same \
             layer; one layer may name a file once, and a later layer replaces it",
            earlier.spelling, earlier.origin
        ),
    }
}

/// Fold the ordered layer set into one configuration.
///
/// The result is one of the base's own `Config` values, still **unresolved**:
/// every entry is returned as written, and substituting it is
/// [`super::resolve`]'s work. The values are resolved once here, against
/// `home`, only so that a target can be keyed by the file it names.
///
/// # Errors
///
/// [`Error::BadValue`] when a committed layer carries a `[values]` table, when a
/// toggle names a key no earlier layer introduced, when one layer names one
/// file twice with no account answer in either spelling, or for any defect
/// [`ResolvedValues::resolve`] reports. The same collision with an answer in it
/// is not an error; it is carried to [`super::resolve`] as a [`Conflict`].
pub fn merge(layers: &[Layer], home: &Path) -> Result<Config, Error> {
    let mut values: Merged<ValueDecl> = Merged::default();
    let mut assignments: Vec<ValueAssignment> = Vec::new();

    // Values first, across every layer. A value never depends on a target, and
    // a target's key depends on the values — the final ones, because the file a
    // target is written to is decided by the answers this account ends up with,
    // not by the answers known when its own layer was read.
    for layer in layers {
        refuse_committed_answers(layer)?;

        values.absorb(layer.config.values.iter().cloned());

        for toggle in &layer.config.toggles {
            // Exhaustive over `Section`, so a keyed list added later is a
            // compile error here rather than a panic in a library call.
            match toggle.section {
                Section::Value => values.toggle(toggle)?,
                Section::Target => {}
            }
        }

        for assignment in &layer.config.value_assignments {
            assign(&mut assignments, assignment.clone());
        }
    }

    // Values keep their disabled entries and targets do not, and the asymmetry
    // is the point: nothing refers to a target except by being one, so a
    // disabled target simply is not written. A value is referred to by name
    // from every string field in the configuration, so a declaration an account
    // switched off has to stay visible to resolution — otherwise
    // `{{git_email}}` reads as a repo typo, which is fatal, and the three-line
    // toggle an account is invited to write stops the whole load with a message
    // naming a committed file it cannot edit.
    let values = values.into_entries();
    let resolved = ResolvedValues::resolve(values.clone(), &assignments, home)?;

    let mut targets: Merged<Target, TargetKey> = Merged::default();
    let mut clashes: Vec<Clash> = Vec::new();
    for layer in layers {
        targets.absorb_layer(layer, &resolved, &mut clashes)?;
    }

    Ok(Config {
        targets: targets.into_enabled(),
        values,
        value_assignments: assignments,
        // Consumed above; a merged configuration has no toggles left to apply.
        toggles: Vec::new(),
        conflicts: clashes
            .into_iter()
            .map(|clash| clash.into_conflict(&resolved))
            .collect(),
    })
}

/// Refuse a `[values]` table in a committed layer.
///
/// The config repo is a git working tree meant to be published, so an answer
/// written there is account content in a publishable tree by construction, and
/// Invariant 5 has no exception clause. The global mechanism for a global answer
/// already exists and is `default`.
fn refuse_committed_answers(layer: &Layer) -> Result<(), Error> {
    if layer.kind != LayerKind::Global {
        return Ok(());
    }
    let Some(first) = layer.config.value_assignments.first() else {
        return Ok(());
    };

    Err(Error::BadValue {
        origin: first.origin.clone(),
        message: format!(
            "a committed layer may not answer a value: `{}` belongs in \
             local.toml in the state directory, or the declaration needs a \
             `default`. Nothing account-specific is ever committed",
            first.name
        ),
    })
}

/// Set one assignment, last layer winning.
///
/// The position of the first layer to answer is kept, so the order `bx plan`
/// reports answers in does not shuffle when a later layer overrides one. The
/// origin is the **later** layer's, because that is the file that made this
/// account differ.
fn assign(assignments: &mut Vec<ValueAssignment>, later: ValueAssignment) {
    match assignments.iter().position(|a| a.name == later.name) {
        Some(index) => assignments[index] = later,
        None => assignments.push(later),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use std::path::PathBuf;

    /// The home every fixture here is parsed against.
    ///
    /// A layer is parsed *against* a home, because a target path under it has
    /// one spelling. Nothing in this module reads one from the environment.
    fn home() -> PathBuf {
        PathBuf::from("/var/home/example")
    }

    /// The merge, against the fixtures' home.
    fn merge(layers: &[Layer]) -> Result<Config, Error> {
        super::merge(layers, &home())
    }

    /// A layer parsed from `text`, named `file`.
    fn layer(file: &str, kind: LayerKind, text: &str) -> Layer {
        Layer {
            file: PathBuf::from(file),
            kind,
            config: parse_str(text, Path::new(file), &home())
                .unwrap_or_else(|e| panic!("{file}: {e}")),
        }
    }

    /// A committed global layer.
    fn global(file: &str, text: &str) -> Layer {
        layer(file, LayerKind::Global, text)
    }

    /// The account's own layer.
    fn local(text: &str) -> Layer {
        layer("local.toml", LayerKind::Local, text)
    }

    /// A `[[target]]` with a one-line inline body.
    fn target_toml(path: &str, body: &str) -> String {
        format!("[[target]]\npath = \"{path}\"\ncontent = \"{body}\"\n")
    }

    /// The merged target paths, in order.
    fn paths(config: &Config) -> Vec<&str> {
        config.targets.iter().map(|t| t.path.as_str()).collect()
    }

    /// The merge's error message.
    fn failure(layers: &[Layer]) -> String {
        merge(layers)
            .expect_err("should have been refused")
            .to_string()
    }

    #[test]
    fn a_later_layer_replaces_an_entry_in_place() {
        let merged = merge(&[
            global("bx.toml", &target_toml("~/.gitconfig", "global")),
            local(&target_toml("~/.gitconfig", "mine")),
        ])
        .unwrap();

        assert_eq!(merged.targets.len(), 1);
        assert_eq!(
            merged.targets[0].origin.file,
            Path::new("local.toml"),
            "the surviving entry names the layer that last set it"
        );
    }

    #[test]
    fn replacement_preserves_the_original_position() {
        let merged = merge(&[
            global(
                "bx.toml",
                &format!(
                    "{}{}{}",
                    target_toml("~/.a", "a"),
                    target_toml("~/.b", "b"),
                    target_toml("~/.c", "c")
                ),
            ),
            local(&target_toml("~/.b", "mine")),
        ])
        .unwrap();

        assert_eq!(
            paths(&merged),
            ["~/.a", "~/.b", "~/.c"],
            "a replacement does not jump to the end of the plan"
        );
    }

    #[test]
    fn a_new_key_appends_in_layer_order() {
        let merged = merge(&[
            global("bx.toml", &target_toml("~/.a", "a")),
            global("modules/10-git.toml", &target_toml("~/.b", "b")),
            local(&target_toml("~/.c", "c")),
        ])
        .unwrap();

        assert_eq!(paths(&merged), ["~/.a", "~/.b", "~/.c"]);
    }

    #[test]
    fn a_toggle_disables_without_restating_the_entry() {
        // Three lines in `local.toml`, not a copy of the whole target — body
        // included — that this account wants gone.
        let merged = merge(&[
            global(
                "bx.toml",
                &target_toml("~/.config/nvtop/interface.ini", "x"),
            ),
            local("[[target]]\npath = \"~/.config/nvtop/interface.ini\"\nenabled = false\n"),
        ])
        .unwrap();

        assert!(merged.targets.is_empty());
    }

    #[test]
    fn a_toggle_does_not_erase_the_other_fields() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[target]]\npath = \"~/.a\"\ncontent = \"body\"\nmode = \"0600\"\n",
            ),
            global(
                "modules/10-off.toml",
                "[[target]]\npath = \"~/.a\"\nenabled = false\n",
            ),
            local("[[target]]\npath = \"~/.a\"\nenabled = true\n"),
        ])
        .unwrap();

        assert_eq!(merged.targets.len(), 1);
        assert_eq!(
            merged.targets[0].mode.map(|m| m.to_string()).as_deref(),
            Some("0600")
        );
        assert_eq!(
            merged.targets[0].origin.file,
            Path::new("bx.toml"),
            "a toggle flips a flag; it does not claim authorship of the entry"
        );
    }

    #[test]
    fn a_later_layer_may_re_enable_a_disabled_entry() {
        // `enabled` is an ordinary scalar, so the last layer that sets it wins,
        // and `local.toml` is the last layer.
        let merged = merge(&[
            global(
                "bx.toml",
                "[[target]]\npath = \"~/.a\"\ncontent = \"x\"\nenabled = false\n",
            ),
            local("[[target]]\npath = \"~/.a\"\nenabled = true\n"),
        ])
        .unwrap();

        assert_eq!(paths(&merged), ["~/.a"]);
    }

    #[test]
    fn a_disabled_entry_is_absent_from_the_resolved_configuration() {
        let merged = merge(&[global(
            "bx.toml",
            "[[target]]\npath = \"~/.a\"\ncontent = \"x\"\nenabled = false\n",
        )])
        .unwrap();

        assert!(merged.targets.is_empty());
    }

    #[test]
    fn a_disable_then_re_enable_keeps_the_original_position() {
        // Disabled entries stay in the list until the very end, which is what
        // makes this true rather than accidental.
        let merged = merge(&[
            global(
                "bx.toml",
                &format!(
                    "{}{}{}",
                    target_toml("~/.a", "a"),
                    target_toml("~/.b", "b"),
                    target_toml("~/.c", "c")
                ),
            ),
            global(
                "modules/10-off.toml",
                "[[target]]\npath = \"~/.b\"\nenabled = false\n",
            ),
            local("[[target]]\npath = \"~/.b\"\nenabled = true\n"),
        ])
        .unwrap();

        assert_eq!(paths(&merged), ["~/.a", "~/.b", "~/.c"]);
    }

    #[test]
    fn a_toggle_for_an_unknown_key_is_an_error() {
        // A misspelled path in `local.toml` would otherwise be a silent no-op,
        // and a silent no-op in an opt-out mechanism is how an account gets a
        // file it explicitly refused.
        let message = failure(&[
            global(
                "bx.toml",
                &target_toml("~/.config/nvtop/interface.ini", "x"),
            ),
            local("[[target]]\npath = \"~/.config/nvtop/interfase.ini\"\nenabled = false\n"),
        ]);

        assert!(
            message.contains("which no earlier layer declares"),
            "{message}"
        );
        assert!(message.contains("interfase.ini"), "{message}");
        assert!(message.contains("local.toml:1"), "{message}");
    }

    #[test]
    fn the_toggle_error_covers_both_readings_of_a_two_key_entry() {
        // A table holding only the natural key and `enabled` is a toggle
        // wherever it appears, so in the *first* layer an entry somebody meant
        // to write in full and left incomplete arrives at the same place. No
        // valid entry has exactly those two keys, so nothing real is swallowed
        // — but the message has to name both readings or the second one reads
        // as nonsense.
        let message = failure(&[global(
            "bx.toml",
            "[[target]]\npath = \"~/.gitconfig\"\nenabled = true\n",
        )]);

        assert!(message.contains("no earlier layer declares"), "{message}");
        assert!(
            message.contains("`file`, `content`, `generated` or `dir`"),
            "{message}"
        );

        let message = failure(&[global(
            "bx.toml",
            "[[value]]\nname = \"agent_slice\"\nenabled = true\n",
        )]);

        assert!(message.contains("needs a `kind`"), "{message}");
    }

    #[test]
    fn every_keyed_section_is_a_variant_with_its_own_names() {
        // `Toggle`, `Config`, `Layer` and `merge` are all public, so a section
        // with no arm in the merge would panic a library call. It is an enum,
        // and the match over it is exhaustive.
        for (section, key, header, natural) in [
            (Section::Target, "target", "[[target]]", "path"),
            (Section::Value, "value", "[[value]]", "name"),
        ] {
            assert_eq!(section.key(), key);
            assert_eq!(section.header(), header);
            assert_eq!(section.natural_key(), natural);
        }
    }

    #[test]
    fn a_toggle_with_a_non_boolean_enabled_names_the_key() {
        let layer = global("bx.toml", &format!("{}\n", target_toml("~/.a", "x")));
        let broken = parse_str(
            "[[target]]\npath = \"~/.a\"\nenabled = \"false\"\n",
            Path::new("local.toml"),
            &home(),
        )
        .expect_err("a string is not a boolean")
        .to_string();

        drop(layer);
        assert!(broken.contains("`enabled` must be a boolean"), "{broken}");
    }

    #[test]
    fn an_untouched_entry_keeps_its_original_origin() {
        let merged = merge(&[
            global("bx.toml", &target_toml("~/.a", "a")),
            local(&target_toml("~/.b", "b")),
        ])
        .unwrap();

        assert_eq!(merged.targets[0].origin.file, Path::new("bx.toml"));
        assert_eq!(merged.targets[1].origin.file, Path::new("local.toml"));
    }

    #[test]
    fn the_three_config_sections_merge_by_their_own_rule() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[target]]\npath = \"~/.a\"\ncontent = \"a\"\n\
                 [[value]]\nname = \"scratch_root\"\nkind = \"path\"\nrequired = true\n",
            ),
            local(
                "[[target]]\npath = \"~/.a\"\ncontent = \"mine\"\n\
                 [[value]]\nname = \"scratch_root\"\nkind = \"path\"\ndescription = \"mine\"\n\
                 [values]\nscratch_root = \"/var/mnt/scratch/one\"\n",
            ),
        ])
        .unwrap();

        assert_eq!(merged.targets.len(), 1, "targets by `path`");
        assert_eq!(merged.values.len(), 1, "values by `name`");
        assert_eq!(
            merged.values[0].description.as_deref(),
            Some("mine"),
            "a declaration is replaced wholesale, so `required` went with it"
        );
        assert!(!merged.values[0].required);
        assert_eq!(merged.value_assignments.len(), 1, "assignments are scalars");
    }

    #[test]
    fn an_assignment_reports_the_layer_that_answered() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n",
            ),
            local("[values]\nscratch_root = \"/var/mnt/scratch/one\"\n"),
        ])
        .unwrap();

        assert_eq!(
            merged.value_assignments[0].origin.file,
            Path::new("local.toml"),
            "`bx plan` has to be able to name the file that made this account differ"
        );
    }

    #[test]
    fn a_later_answer_wins_and_keeps_the_first_position() {
        // Two local-kind layers is not a shape the loader produces, but the
        // last-wins rule is the merge's, so it is tested at the merge.
        let merged = merge(&[
            local("[values]\na = \"first\"\nb = \"b\"\n"),
            layer(
                "second.toml",
                LayerKind::Local,
                "[values]\na = \"second\"\n",
            ),
        ])
        .unwrap();

        let answers: Vec<(&str, String)> = merged
            .value_assignments
            .iter()
            .map(|a| (a.name.as_str(), a.value.to_string()))
            .collect();

        assert_eq!(
            answers,
            [("a", "second".to_string()), ("b", "b".to_string())],
            "the later answer wins in the earlier answer's position"
        );
    }

    #[test]
    fn values_in_a_committed_layer_are_an_error() {
        // A publishable git tree is not where an account's answers live, and
        // Invariant 5 has no exception clause.
        let message = failure(&[global(
            "bx.toml",
            "[[value]]\nname = \"git_email\"\nkind = \"email\"\n\
             [values]\ngit_email = \"someone@example.invalid\"\n",
        )]);

        assert!(message.contains("may not answer a value"), "{message}");
        assert!(message.contains("git_email"), "{message}");
        assert!(message.contains("`default`"), "{message}");
    }

    #[test]
    fn values_in_the_local_layer_are_fine() {
        assert!(merge(&[local("[values]\ngit_email = \"someone@example.invalid\"\n")]).is_ok());
    }

    #[test]
    fn resolved_order_is_declaration_order_for_sixteen_keys() {
        // Sixteen distinct keys, with a hard-coded expected order. For sixteen
        // keys the chance that a hash map's iteration order coincides with
        // insertion order is negligible, so this is the test that fails the
        // moment the entry list stops being a `Vec`.
        let names: Vec<String> = (0..16).map(|i| format!("~/.config/t{i:02}")).collect();
        let body: String = names.iter().map(|p| target_toml(p, "x")).collect();

        let merged = merge(&[global("bx.toml", &body)]).unwrap();

        assert_eq!(
            paths(&merged),
            names.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn merging_the_same_layers_twice_is_byte_identical() {
        // Invariant 3, at the merge: a pure function of the layer files' bytes.
        let layers = || {
            vec![
                global(
                    "bx.toml",
                    &format!("{}{}", target_toml("~/.a", "a"), target_toml("~/.b", "b")),
                ),
                global(
                    "modules/10-off.toml",
                    "[[target]]\npath = \"~/.a\"\nenabled = false\n",
                ),
                local(&target_toml("~/.b", "mine")),
            ]
        };

        let first = merge(&layers()).unwrap();
        let second = merge(&layers()).unwrap();

        assert_eq!(format!("{first:#?}"), format!("{second:#?}"));
    }

    #[test]
    fn an_account_that_disables_a_target_still_gets_every_other_target() {
        let merged = merge(&[
            global(
                "bx.toml",
                &format!(
                    "{}{}{}",
                    target_toml("~/.gitconfig", "git"),
                    target_toml("~/.config/nvtop/interface.ini", "nvtop"),
                    target_toml("~/.zshrc", "zsh")
                ),
            ),
            local("[[target]]\npath = \"~/.config/nvtop/interface.ini\"\nenabled = false\n"),
        ])
        .unwrap();

        assert_eq!(paths(&merged), ["~/.gitconfig", "~/.zshrc"]);
    }

    #[test]
    fn an_account_replaces_a_target_body_in_place() {
        // The nvtop case: no value models a machine-generated INI section, so
        // the account restates the entry with its own body. This is expressible
        // only because the local layer is a full layer.
        let merged = merge(&[
            global(
                "bx.toml",
                &target_toml("~/.config/nvtop/interface.ini", "shared"),
            ),
            local(&target_toml("~/.config/nvtop/interface.ini", "this GPU")),
        ])
        .unwrap();

        assert_eq!(paths(&merged), ["~/.config/nvtop/interface.ini"]);
        assert_eq!(merged.targets[0].origin.file, Path::new("local.toml"));
    }

    #[test]
    fn a_value_declared_twice_is_replaced_by_the_later_layer() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\nis_root = true\n",
            ),
            local(
                "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n\
                 description = \"this account's scratch\"\nis_root = true\n",
            ),
        ])
        .unwrap();

        assert_eq!(merged.values.len(), 1);
        assert_eq!(
            merged.values[0].description.as_deref(),
            Some("this account's scratch")
        );
    }

    #[test]
    fn a_value_toggle_disables_a_declaration() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[value]]\nname = \"agent_slice\"\nkind = \"string\"\nrequired = true\n",
            ),
            local("[[value]]\nname = \"agent_slice\"\nenabled = false\n"),
        ])
        .unwrap();

        assert_eq!(merged.values.len(), 1, "by name, so it is one declaration");
        assert!(
            !merged.values[0].enabled,
            "the flag is flipped, not the declaration dropped: a target still \
             referring to it has to be distinguishable from one referring to a \
             name no layer ever declared"
        );
    }

    #[test]
    fn a_disabled_declaration_survives_the_merge_and_a_disabled_target_does_not() {
        // The asymmetry, stated once: nothing refers to a target except by being
        // one, and every string field in the configuration refers to a value by
        // name.
        let merged = merge(&[
            global(
                "bx.toml",
                "[[target]]\npath = \"~/.a\"\ncontent = \"a\"\n\
                 [[value]]\nname = \"agent_slice\"\nkind = \"string\"\n",
            ),
            local(
                "[[target]]\npath = \"~/.a\"\nenabled = false\n\
                 [[value]]\nname = \"agent_slice\"\nenabled = false\n",
            ),
        ])
        .unwrap();

        assert!(merged.targets.is_empty());
        assert_eq!(merged.values.len(), 1);
    }

    #[test]
    fn a_value_toggle_for_an_unknown_name_is_an_error() {
        let message = failure(&[
            global(
                "bx.toml",
                "[[value]]\nname = \"agent_slice\"\nkind = \"string\"\n",
            ),
            local("[[value]]\nname = \"agent_slize\"\nenabled = false\n"),
        ]);

        assert!(
            message.contains("which no earlier layer declares"),
            "{message}"
        );
    }

    /// A committed layer declaring `acct`, and a target whose path uses it.
    fn acct_layer(default: Option<&str>) -> Layer {
        let default = default.map_or_else(String::new, |d| format!("default = \"{d}\"\n"));
        global(
            "bx.toml",
            &format!(
                "[[value]]\nname = \"acct\"\nkind = \"string\"\n{default}{}",
                target_toml("~/.config/{{acct}}/settings.json", "GLOBAL")
            ),
        )
    }

    #[test]
    fn a_later_layer_replaces_a_target_by_the_file_its_path_names() {
        // `plan` shows `~/.config/one/settings.json`, so that is the spelling an
        // account overrides by. Compared as written, the two were two targets
        // owning one file.
        let merged = merge(&[
            acct_layer(Some("one")),
            local(&target_toml("~/.config/one/settings.json", "LOCAL")),
        ])
        .unwrap();

        assert_eq!(
            paths(&merged),
            ["~/.config/one/settings.json"],
            "one file, one target"
        );
        assert_eq!(merged.targets[0].origin.file, Path::new("local.toml"));
    }

    #[test]
    fn a_toggle_reaches_a_target_by_the_file_its_path_names() {
        // Keyed against the values this account ends up with: `acct` is answered
        // by the same last layer that toggles, not by the committed default.
        let merged = merge(&[
            acct_layer(Some("one")),
            local(
                "[values]\nacct = \"two\"\n\
                 [[target]]\npath = \"~/.config/two/settings.json\"\nenabled = false\n",
            ),
        ])
        .unwrap();
        assert!(merged.targets.is_empty(), "{:?}", paths(&merged));

        let merged = merge(&[
            acct_layer(Some("one")),
            local("[[target]]\npath = \"~/.config/{{acct}}/settings.json\"\nenabled = false\n"),
        ])
        .unwrap();
        assert!(
            merged.targets.is_empty(),
            "the declared spelling still reaches it"
        );
    }

    /// The homes the written-form properties are asserted over.
    ///
    /// The home is one of the axes, not a fixture detail: `Portable::parse_in`
    /// folds against it and can refuse an absolute path under it, so which file
    /// a spelling names is home-dependent. `/` is the degenerate one — `~` and
    /// `/` coincide there and a `..` under the home has no parent to climb to —
    /// and a pair that is one file under one home and two under another is a
    /// property of that account rather than of the rule.
    fn homes() -> [PathBuf; 2] {
        [home(), PathBuf::from("/")]
    }

    /// Every answer set drawn against `at`, each labelled with its answers.
    fn answer_sets_at(at: &Path) -> Vec<(String, ResolvedValues)> {
        use crate::config::values::AssignedValue;

        let decl = |name: &str, kind: ValueKind| ValueDecl {
            name: name.into(),
            description: None,
            kind,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let decls = || {
            vec![
                decl("p", ValueKind::String),
                decl("q", ValueKind::String),
                decl("f", ValueKind::Bool),
                decl("r", ValueKind::Path),
                decl("e", ValueKind::Email),
            ]
        };
        let assign = |name: &str, value: AssignedValue| ValueAssignment {
            name: name.into(),
            value,
            origin: Origin::unknown(Path::new("local.toml")),
        };
        // Deep answers first: they part most pairs, so most pairs stop early.
        let strings = [
            "a/b/c/d/e/f/g/h",
            "/a/b/c/d/e/f/g/h",
            "a",
            "a/b",
            "",
            ".",
            "..",
            "../..",
            "/a",
            "~",
            "~/a",
            "a/",
            "a/..",
        ];
        let others = ["b/c/d/e/f/g/h/i", "b", ""];
        let roots = ["/srv/d/e/f/g/h/i/j", "/srv", "/", "/var/home/example"];
        // An address may hold a `/`, so it too can root a spelling or climb.
        let emails = ["/a@b/c/d/e/f/g/h", "~/m@n"];
        let mut answers = Vec::new();
        for p in strings {
            for q in others {
                for r in roots {
                    for e in emails {
                        for f in [true, false] {
                            let given = [
                                assign("p", AssignedValue::String(p.into())),
                                assign("q", AssignedValue::String(q.into())),
                                assign("f", AssignedValue::Bool(f)),
                                assign("r", AssignedValue::String(r.into())),
                                assign("e", AssignedValue::String(e.into())),
                            ];
                            if let Ok(values) = ResolvedValues::resolve(decls(), &given, at) {
                                answers.push((
                                    format!(
                                        "home={} p={p:?} q={q:?} f={f} r={r:?} e={e:?}",
                                        at.display()
                                    ),
                                    values,
                                ));
                            }
                        }
                    }
                }
            }
        }
        answers
    }

    /// Every answer set, over every home.
    ///
    /// The fuzz asserts over all of them at once, which is the strict
    /// direction: more answers can only part more pairs, so soundness is
    /// checked harder and completeness is never weakened.
    fn answer_sets() -> Vec<(String, ResolvedValues)> {
        homes().iter().flat_map(|at| answer_sets_at(at)).collect()
    }

    /// How `first` and `second` key across `answers`: whether some answer gives
    /// them one file, and the first answer that gives them different keys.
    ///
    /// This decides nothing on its own: it reports over whatever `answers` it
    /// is handed. A pair is **undecided** when some answer met, none parted,
    /// and [`one_path_as_written`] says false — for `answers` **drawn against
    /// one home**, which is the only set over which that conjunction is the
    /// account's experience. `UNDECIDED`'s test is what applies it that way;
    /// handing this the union of every home asks a different and stricter
    /// question, and one registered pair does not survive it.
    fn keying(
        first: &str,
        second: &str,
        answers: &[(String, ResolvedValues)],
    ) -> (bool, Option<String>) {
        let mut met = false;
        for (label, values) in answers {
            let (key_a, key_b) = (TargetKey::of(first, values), TargetKey::of(second, values));
            match (&key_a, &key_b) {
                (TargetKey::File(x), TargetKey::File(y)) if x == y => met = true,
                (TargetKey::AsWritten(_), TargetKey::AsWritten(_)) => {}
                _ => return (met, Some(format!("{label}: {key_a:?} against {key_b:?}"))),
            }
        }
        (met, None)
    }

    #[test]
    fn one_path_as_written_agrees_with_every_answer_in_a_fuzzed_set() {
        // Soundness: a pair the rule calls one path has one key, or no key, under
        // every answer below. Completeness over that set: a pair it does not call
        // one path, which some answer gives one key, is parted by another answer,
        // so the block its hint describes is one an answer can clear. The pairs
        // come from a fixed seed, so every run tries the same ones.
        use std::collections::HashSet;

        let answers = answer_sets();

        let segments = [
            "x",
            "y",
            ".",
            "..",
            "..",
            "..",
            "",
            "~",
            "{{p}}",
            "{{q}}",
            "a{{p}}",
            "{{p}}b",
            "{{p}}{{q}}",
            "{{f}}",
            "x{{f}}",
            "{{r}}",
            "x{{r}}",
            "..{{r}}",
        ];
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut pick = move |n: usize| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(seed >> 33).expect("a 31-bit value fits") % n
        };

        let (mut proven, mut parted) = (0, 0);
        let mut unsound: Vec<String> = Vec::new();
        let mut incomplete: Vec<String> = Vec::new();
        let mut tried = HashSet::new();
        for _ in 0..3000 {
            let root = ["~/", "/", ""][pick(3)];
            let len = 1 + pick(5);
            let mut first: Vec<&str> = (0..len).map(|_| segments[pick(segments.len())]).collect();
            // A spelling with no root opens with a placeholder: alone, with text
            // glued on, after a `~`, of a kind no answer makes empty, or with a
            // second placeholder beside it.
            if root.is_empty() {
                let openers = [
                    "{{r}}",
                    "{{p}}",
                    "{{r}}.d",
                    "{{r}}x",
                    "~{{r}}",
                    "~{{p}}",
                    "{{e}}",
                    "{{r}}{{p}}",
                    "{{p}}{{r}}",
                ];
                first[0] = openers[pick(openers.len())];
            }
            let mut second: Vec<String> = first.iter().map(|s| (*s).to_string()).collect();
            for _ in 0..=pick(3) {
                let at = if second.len() > 1 {
                    (1 + pick(second.len())).min(second.len())
                } else {
                    second.len()
                };
                match pick(8) {
                    0 => second.insert(at, ".".into()),
                    1 => second.insert(at, "..".into()),
                    2 if second.len() > 1 && at < second.len() => {
                        second.remove(at);
                    }
                    3 if at < second.len() => second[at] = segments[pick(segments.len())].into(),
                    4 => {
                        second.insert(at, "..".into());
                        second.insert(at, "x".into());
                    }
                    // Glue: a `path` value that starts a segment is joined onto
                    // the text before it, taking the `/` between them away.
                    5 => {
                        let led: Vec<usize> = (1..second.len())
                            .filter(|&i| second[i].starts_with("{{r}}"))
                            .collect();
                        if !led.is_empty() {
                            let i = led[pick(led.len())];
                            let glued = second.remove(i);
                            second[i - 1].push_str(&glued);
                        }
                    }
                    // Unglue: a `path` value glued after other text is split off
                    // into its own segment, putting a `/` before it.
                    6 => {
                        let glued: Vec<usize> = (0..second.len())
                            .filter(|&i| second[i].find("{{r}}").is_some_and(|at| at > 0))
                            .collect();
                        if !glued.is_empty() {
                            let i = glued[pick(glued.len())];
                            let split = second[i].find("{{r}}").expect("found above");
                            let rest = second[i].split_off(split);
                            second.insert(i + 1, rest);
                        }
                    }
                    _ => second.insert(at, String::new()),
                }
            }
            let a = format!("{root}{}", first.join("/"));
            let mut b = format!("{root}{}", second.join("/"));
            // A leading `/` before a placeholder that opens the spelling.
            if root.is_empty() && pick(4) == 0 {
                b.insert(0, '/');
            }
            // A `/` before a `path` value taken away, a root's own included:
            // `/{{r}}` becomes `{{r}}` and `~/{{r}}` becomes `~{{r}}`.
            let slashed: Vec<usize> = b.match_indices("/{{r}}").map(|(at, _)| at).collect();
            if !slashed.is_empty() && pick(3) == 0 {
                b.remove(slashed[pick(slashed.len())]);
            }
            if a == b || !tried.insert((a.clone(), b.clone())) {
                continue;
            }

            let one_path = one_path_as_written(&a, &b, &answers[0].1);
            let (met, apart) = keying(&a, &b, &answers);
            match (one_path, apart) {
                (true, Some(why)) => unsound.push(format!("{a:?} and {b:?}, parted by {why}")),
                (true, None) => proven += 1,
                (false, Some(_)) => parted += 1,
                (false, None) if met => incomplete.push(format!("{a:?} and {b:?}")),
                (false, None) => {}
            }
        }

        assert!(
            unsound.is_empty(),
            "{} pairs called one path were parted by an answer:\n{}",
            unsound.len(),
            unsound[..unsound.len().min(10)].join("\n")
        );
        // Completeness is asserted **over the shapes generated above**, not
        // over every spelling. The `segments` and `openers` arrays are what
        // bounds it, and that exclusion is load-bearing: the pairs `UNDECIDED`
        // holds are known to be undecided and are deliberately not generated.
        // Widening either array will turn one of them red — the same fact
        // `every_pair_the_written_form_is_known_to_miss_is_still_missed`
        // records, not a second obligation. The repair is to decide the shape
        // in `written_form`, then move the pair out of `UNDECIDED` and into
        // these arrays — never to weaken this assertion.
        assert!(
            incomplete.is_empty(),
            "{} pairs no answer parts were not called one path:\n{}",
            incomplete.len(),
            incomplete[..incomplete.len().min(10)].join("\n")
        );
        assert!(
            proven >= 100 && parted >= 100,
            "the set must exercise both verdicts: {proven} one path, {parted} parted"
        );
    }

    /// The pairs the written form is known **not** to decide.
    ///
    /// For each, there is **some home** under which every answer
    /// [`answer_sets_at`] draws keys the two spellings as one file, and the two
    /// written forms differ anyway. Per home, and not over the union of them:
    /// one entry below is one file for every answer only under a home of `/`,
    /// and an account under that home has the unclearable block just the same.
    /// That is the criterion
    /// `every_pair_the_written_form_is_known_to_miss_is_still_missed`
    /// executes — stated here in the words it executes, because a header
    /// asserting the broader "under every answer" is the exact failure this
    /// register replaced prose to end.
    ///
    /// This is the register the module
    /// documentation points at, kept here rather than in prose so that it is
    /// re-derived on every run: a pair that stops being undecided fails
    /// `every_pair_the_written_form_is_known_to_miss_is_still_missed`, and a
    /// pair nobody can reproduce cannot be added.
    ///
    /// Every entry is an **open defect**, registered rather than repaired, and
    /// that is a decision: the pair loads `Ok` and the file it names is blocked
    /// as a [`Conflict`] whose hint no answer satisfies. Deciding one means
    /// widening the reduction, and every rule proposed for these shapes so far
    /// has been refuted — `REFUTED` holds each with the answers that killed it,
    /// which is why no general rule is claimed and why adding a pair here is a
    /// disposition rather than a delay. The repair for one is to decide it in
    /// [`written_form`], prove the decision against
    /// `one_path_as_written_agrees_with_every_answer_in_a_fuzzed_set`, and then
    /// move the pair out of here and into that test's generators — never to
    /// weaken either assertion.
    const UNDECIDED: [(&str, &str, &str); 9] = [
        (
            "{{p}}",
            "{{p}}/",
            "under a home of `/` alone: a trailing separator after an opening \
             placeholder, where the home is the root the empty answer names",
        ),
        (
            "~/{{p}}x/..",
            "~/{{p}}y/..",
            "literal text glued after a placeholder, ending the segment the \
             following `..` cancels",
        ),
        (
            "{{r}}./..",
            "{{r}}/..",
            "glue after a `path` value where nothing but the root `/` stands above it",
        ),
        ("{{r}}x/..", "{{r}}/..", "the same, with the glue not a dot"),
        (
            "/opt/{{r}}../../conf",
            "/opt/{{r}}/../conf",
            "a `..` glued after a `path` value that climbs through every fixed \
             segment above it to `/`",
        ),
        (
            "/opt/{{r}}x/../../conf",
            "/opt/{{r}}/../../conf",
            "the same climb, with the glue not a dot",
        ),
        (
            "/a/b/{{r}}../../..",
            "/a/b/{{r}}/../..",
            "the same climb, from two fixed segments",
        ),
        (
            "~/{{p}}{{f}}/..",
            "~/{{p}}x/..",
            "a glued tail holding a `bool`, whose answer is never empty, never \
             only dots and never holds a `/`, so the `..` cancels the segment \
             either way",
        ),
        (
            "~{{p}}/.{{p}}",
            "~{{p}}/{{p}}",
            "an opening occurrence limits which answers name a file at all, and \
             each occurrence is read on its own",
        ),
    ];

    #[test]
    fn every_pair_the_written_form_is_known_to_miss_is_still_missed() {
        // The register, executed. A pair belongs in it when, under **some**
        // home, every answer keys it as one file and the two written forms
        // differ anyway — which is exactly the account that gets a `Conflict`
        // no answer clears. Judged per home rather than over the union,
        // because a pair one home parts is still an unclearable block for an
        // account under the home that does not.
        //
        // The list is therefore a measurement at this head, not a claim carried
        // forward from an earlier one. A pair a repair to `written_form`
        // decides turns this red and must move into the fuzz's `segments` and
        // `openers` arrays, which is the one instruction this register gives.
        let by_home: Vec<(PathBuf, Vec<(String, ResolvedValues)>)> = homes()
            .into_iter()
            .map(|at| {
                let sets = answer_sets_at(&at);
                (at, sets)
            })
            .collect();
        let declarations = &by_home[0].1[0].1;

        let mut decided: Vec<String> = Vec::new();
        for (first, second, why) in UNDECIDED {
            if one_path_as_written(first, second, declarations) {
                decided.push(format!(
                    "{first:?} and {second:?} ({why}): now one path as written"
                ));
                continue;
            }
            let mut per_home = Vec::new();
            for (at, answers) in &by_home {
                match keying(first, second, answers) {
                    (true, None) => per_home.clear(),
                    (_, Some(apart)) => {
                        per_home.push(format!("{}: parted by {apart}", at.display()))
                    }
                    (false, None) => per_home.push(format!(
                        "{}: no answer keys it as a file at all",
                        at.display()
                    )),
                }
                if per_home.is_empty() {
                    break;
                }
            }
            if !per_home.is_empty() {
                decided.push(format!(
                    "{first:?} and {second:?} ({why}): undecided under no home — {}",
                    per_home.join("; ")
                ));
            }
        }
        assert!(
            decided.is_empty(),
            "{} registered pairs no longer describe a miss:\n{}",
            decided.len(),
            decided.join("\n")
        );
    }

    /// Rules for deciding a pair that were proposed and refuted, each with the
    /// two spellings, the answers to `p` and `r` that part them, and the rule
    /// the parting kills.
    ///
    /// Kept so that none is re-adopted, and kept executable so that a refutation
    /// cannot outlive the behaviour it rests on.
    const REFUTED: [(&str, &str, &str, &str, &str); 5] = [
        (
            "{{r}}{{p}}/..",
            "{{r}}/..",
            "~/a",
            "//srv/",
            "treat any glued placeholder tail like literal text",
        ),
        (
            "{{r}}x/conf",
            "{{r}}/conf",
            "",
            "/srv",
            "treat glue with no following `..` as one path",
        ),
        (
            "/opt/{{r}}./conf",
            "/opt/{{r}}/conf",
            "",
            "/srv",
            "treat a dot glued after a `path` value as one path",
        ),
        (
            "/a/b/{{r}}../..",
            "/a/b/{{r}}/..",
            "",
            "/",
            "treat a `..` glued after a `path` value as always undecided",
        ),
        (
            "/opt/{{r}}x/../conf",
            "/opt/{{r}}/../conf",
            "",
            "/",
            "the same, with one fixed segment above the value",
        ),
    ];

    /// The classifier's declarations, with `p` and `r` answered.
    fn answered(p: &str, r: &str) -> ResolvedValues {
        use crate::config::values::AssignedValue;

        let decl = |name: &str, kind: ValueKind| ValueDecl {
            name: name.into(),
            description: None,
            kind,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let assign = |name: &str, text: &str| ValueAssignment {
            name: name.into(),
            value: AssignedValue::String(text.into()),
            origin: Origin::unknown(Path::new("local.toml")),
        };
        ResolvedValues::resolve(
            classifier_kinds()
                .into_iter()
                .map(|(name, kind)| decl(name, kind))
                .collect(),
            &[assign("p", p), assign("r", r)],
            &home(),
        )
        .expect("the answers resolve")
    }

    #[test]
    fn every_rule_the_written_form_refused_is_still_refuted() {
        // A proposed rule is dead when one answer gives its two spellings
        // different keys, because a rule calling them one path would refuse a
        // whole load an account could have cleared. Executed rather than
        // recited, so a refutation is re-measured at the head it is published
        // against instead of being carried forward.
        for (first, second, p, r, rule) in REFUTED {
            let values = answered(p, r);
            assert!(
                !one_path_as_written(first, second, &values),
                "{rule}: {first:?} and {second:?} are called one path today"
            );
            assert_ne!(
                TargetKey::of(first, &values),
                TargetKey::of(second, &values),
                "{rule}: {first:?} and {second:?} with p={p:?} r={r:?}"
            );
        }
    }

    #[test]
    fn no_registered_pair_reaches_the_comparison_as_full_entries() {
        // The half of the reachability argument that generalises, executed over
        // **every** entry rather than one worked example. Written as a pair of
        // `[[target]]`s, each registered spelling is refused before `merge`
        // runs at all — by whichever rule catches it, which differs between
        // them: a spelling that opens with a placeholder, one that opens with a
        // `~` glued to one, one that reduces to a root, and two whose
        // normalised spellings coincide are four different refusals. The point
        // is not which one fires but that none of these pairs ever reaches the
        // comparison this way, so the register's consequence is a toggle's.
        const VALUES: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                              [[value]]\nname = \"f\"\nkind = \"bool\"\n\
                              [[value]]\nname = \"r\"\nkind = \"path\"\n";

        let mut loaded: Vec<String> = Vec::new();
        for (first, second, why) in UNDECIDED {
            let text = format!(
                "{VALUES}{}{}",
                target_toml(first, "ONE"),
                target_toml(second, "TWO")
            );
            if parse_str(&text, Path::new("bx.toml"), &home()).is_ok() {
                loaded.push(format!("{first:?} and {second:?} ({why})"));
            }
        }
        assert!(
            loaded.is_empty(),
            "{} registered pairs parse as full entries, so the register's \
             toggle-only reachability no longer holds for them:\n{}",
            loaded.len(),
            loaded.join("\n")
        );
    }

    #[test]
    fn a_registered_pair_reaches_the_comparison_as_a_toggle_and_not_as_a_full_entry() {
        // Why the register's consequence is a toggle's, and why a maintainer
        // cannot reproduce a registered pair by writing its two spellings as
        // `[[target]]` entries. A full `path` is a `Portable` parsed by
        // `Portable::parse_in`, which normalises the spelling with its
        // placeholders still in it: both spellings below store as `/conf`, and
        // `check_unique` refuses the layer before `merge` compares anything. A
        // toggle names a key by the spelling it reaches and is held to neither
        // that rule nor the one refusing a spelling that opens with a
        // placeholder, so it is the route by which a miss becomes a `Conflict`
        // whose "change that answer" hint no answer satisfies.
        const VALUES: &str = "[[value]]\nname = \"r\"\nkind = \"path\"\n";
        let (first, second) = ("/opt/{{r}}x/../../conf", "/opt/{{r}}/../../conf");

        let as_entries = parse_str(
            &format!(
                "{VALUES}{}{}",
                target_toml(first, "ONE"),
                target_toml(second, "TWO")
            ),
            Path::new("bx.toml"),
            &home(),
        )
        .expect_err("two full entries whose normalised spellings coincide are refused")
        .to_string();
        assert!(as_entries.contains("duplicate target"), "{as_entries}");
        assert!(as_entries.contains("`/conf`"), "{as_entries}");

        let as_toggles = merge(&[
            global(
                "bx.toml",
                &format!(
                    "{VALUES}{}[[target]]\npath = \"{first}\"\nenabled = false\n\
                     [[target]]\npath = \"{second}\"\nenabled = true\n",
                    target_toml("/conf", "C")
                ),
            ),
            local("[values]\nr = \"/srv\"\n"),
        ])
        .unwrap_or_else(|e| panic!("the toggle route loads rather than failing: {e}"));

        assert_eq!(as_toggles.conflicts.len(), 1, "{:?}", as_toggles.conflicts);
        assert_eq!(as_toggles.conflicts[0].file, "/conf");
    }

    #[test]
    fn an_opening_placeholder_an_answer_may_empty_is_parted_by_what_follows_it() {
        // `{{p}}` and `{{p}}/.` are one file, `/srv`, for `p = "/srv"`, but
        // `p = ""` makes the first nothing and the second `/`. Some answer parts
        // them, so meeting is the account's doing: a conflict, not a refusal.
        let config = merge(&[
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n{}\
                     [[target]]\npath = \"{{{{p}}}}\"\nenabled = false\n\
                     [[target]]\npath = \"{{{{p}}}}/.\"\nenabled = true\n",
                    target_toml("/srv", "S")
                ),
            ),
            local("[values]\np = \"/srv\"\n"),
        ])
        .unwrap_or_else(|e| panic!("an answer that names one file twice failed the merge: {e}"));
        assert_eq!(config.conflicts.len(), 1);
        assert_eq!(config.conflicts[0].file, "/srv");

        let decl = ValueDecl {
            name: "p".into(),
            description: None,
            kind: ValueKind::String,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let empty = ValueAssignment {
            name: "p".into(),
            value: crate::config::values::AssignedValue::String(String::new()),
            origin: Origin::unknown(Path::new("local.toml")),
        };
        let values = ResolvedValues::resolve(vec![decl], &[empty], &home()).unwrap();
        assert_ne!(
            TargetKey::of("{{p}}", &values),
            TargetKey::of("{{p}}/.", &values),
            "`p = \"\"` parts the pair"
        );
    }

    #[test]
    fn a_path_value_after_a_placeholder_is_not_rooted_at_home() {
        // Only a literal `~` before a `path` value roots a spelling at `~`.
        // `{{p}}{{r}}/s` and `~/{{r}}/s` are one file, `~/srv/s`, for `p = "~"`,
        // but `p = ""` makes the first `/srv/s`. Some answer parts them, so
        // meeting is the account's doing: a conflict, not a refusal.
        let config = merge(&[
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                     [[value]]\nname = \"r\"\nkind = \"path\"\n{}\
                     [[target]]\npath = \"{{{{p}}}}{{{{r}}}}/s\"\nenabled = false\n\
                     [[target]]\npath = \"~/{{{{r}}}}/s\"\nenabled = true\n",
                    target_toml("~/srv/s", "S")
                ),
            ),
            local("[values]\np = \"~\"\nr = \"/srv\"\n"),
        ])
        .unwrap_or_else(|e| panic!("an answer that names one file twice failed the merge: {e}"));
        assert_eq!(config.conflicts.len(), 1);
        assert_eq!(config.conflicts[0].file, "~/srv/s");
    }

    #[test]
    fn two_toggles_that_each_cancel_a_placeholder_meet_for_one_answer_only() {
        // `~/.config/{{p}}/../s` and `~/.config/{{q}}/../s` are `~/.config/s`
        // while `p` and `q` each hold one segment, and two files once either
        // holds a `/`. Meeting for these answers is the account's doing, so the
        // file is recorded as a conflict rather than failing the merge.
        let config = merge(&[
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                     [[value]]\nname = \"q\"\nkind = \"string\"\n{}\
                     [[target]]\npath = \"~/.config/{{{{p}}}}/../s\"\nenabled = false\n\
                     [[target]]\npath = \"~/.config/{{{{q}}}}/../s\"\nenabled = true\n",
                    target_toml("~/.config/s", "S")
                ),
            ),
            local("[values]\np = \"a\"\nq = \"b\"\n"),
        ])
        .unwrap_or_else(|e| panic!("an answer that names one file twice failed the merge: {e}"));
        assert_eq!(config.conflicts.len(), 1);
        assert_eq!(config.conflicts[0].file, "~/.config/s");
    }

    #[test]
    fn toggles_one_path_past_a_placeholder_are_the_layer_s_defect_whatever_climbs() {
        // `~/{{p}}/../../s` and `~/{{p}}/.././../s` differ only by a `.`, so
        // whatever `p` holds they name one file, or both climb out of the home
        // and name none. No answer can part them: it is the layer's defect, even
        // though a one-segment `p` makes neither a portable path. The second pair
        // spreads the climb over two placeholders.
        for (first, second) in [
            ("~/{{p}}/../../s", "~/{{p}}/.././../s"),
            ("~/{{p}}/{{q}}/../../../s", "~/{{p}}/{{q}}/../.././../s"),
        ] {
            let message = failure(&[
                global(
                    "bx.toml",
                    &format!(
                        "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                         [[value]]\nname = \"q\"\nkind = \"string\"\n{}\
                         [[target]]\npath = \"{first}\"\nenabled = false\n\
                         [[target]]\npath = \"{second}\"\nenabled = true\n",
                        target_toml("~/s", "S")
                    ),
                ),
                local("[values]\np = \"a/b\"\nq = \"c\"\n"),
            ]);
            assert!(
                message.contains(&format!("names the same file as `{first}`")),
                "{second}: {message}"
            );
            assert!(
                message.contains("in this same layer"),
                "{second}: {message}"
            );
        }
    }

    #[test]
    fn a_dotdot_past_the_root_is_the_layer_s_defect_whatever_is_answered() {
        // At `/` there is nothing above to climb to, so a `..` left with nothing
        // written before it to cancel is dropped. `/a/../../{{p}}` and
        // `/a/../../../{{p}}` both name `/{{p}}`, as `/../{{p}}` and
        // `/../../{{p}}` do, whatever `p` holds. A `path` value glued after the
        // climb starts its own segment and clamps the same way (`/..{{r}}`
        // against `/../../{{r}}`). No answer parts any pair, so each is the
        // layer's defect rather than a block an answer could clear.
        for (file, first, second) in [
            ("/s", "/a/../../{{p}}", "/a/../../../{{p}}"),
            ("/s", "/../{{p}}", "/../../{{p}}"),
            ("/srv", "/..{{r}}", "/../../{{r}}"),
        ] {
            let message = failure(&[
                global(
                    "bx.toml",
                    &format!(
                        "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                         [[value]]\nname = \"r\"\nkind = \"path\"\n{}\
                         [[target]]\npath = \"{first}\"\nenabled = false\n\
                         [[target]]\npath = \"{second}\"\nenabled = true\n",
                        target_toml(file, "S")
                    ),
                ),
                local("[values]\np = \"s\"\nr = \"/srv\"\n"),
            ]);
            assert!(
                message.contains(&format!("names the same file as `{first}`")),
                "{second}: {message}"
            );
            assert!(
                message.contains("in this same layer"),
                "{second}: {message}"
            );
        }
    }

    #[test]
    fn a_literal_tilde_is_rooted_at_home_not_absolute() {
        // `written_form`'s `Root::Home` arm — the one that reads a first
        // segment of exactly `[Piece::Literal("~")]` — is what parts a pair
        // that climbs above the home and what keeps `~` from meeting `/`.
        // Cited by name rather than by line, which is the convention the rest
        // of this file follows and the only citation a refactor cannot rot.
        // At `/` nothing is above the root, so a bare `..` clamps away (see
        // `a_dotdot_past_the_root_is_the_layer_s_defect_whatever_is_answered`
        // above); under `~` the home's own parent is unknown, so it does not.
        //
        // The root is pinned directly, and not only through a pair's verdict:
        // a mutant that folds `~` into `Root::Opening` gives it the same first
        // segment and the same `followed` (a literal piece is never
        // `may_be_empty`) as any other pure-`~` spelling, so no pair of
        // spellings moves `one_path_as_written`'s verdict at all — the
        // fixed-seed property test above would not catch it either.
        let decl = ValueDecl {
            name: "p".into(),
            description: None,
            kind: ValueKind::String,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let values = ResolvedValues::resolve(vec![decl], &[], &home()).unwrap();

        for spelling in ["~", "~/{{p}}", "~/../{{p}}"] {
            let form = written_form(spelling, &values).expect("well-formed");
            assert_eq!(form.root, Root::Home, "{spelling}: {form:?}");
        }

        // (a) A pair that climbs above `~` does not prove one path: the extra
        // `..` stays in the form instead of clamping the way it does at `/`,
        // so the pair is judged after substitution rather than refused as the
        // layer's defect.
        assert!(
            !one_path_as_written("~/../{{p}}", "~/../../{{p}}", &values),
            "a climb above the home is not proof of one path"
        );

        // (b) `~/{{p}}` and `/{{p}}` are not one path: `~` is not `/`.
        assert!(
            !one_path_as_written("~/{{p}}", "/{{p}}", &values),
            "`~` is not `/`"
        );

        // This test is the branch's only pin, and deliberately so: the two
        // `one_path_as_written` assertions above hold with the branch deleted.
        // A refactor that folds `Root::Home` away while keeping every verdict
        // fails exactly the `form.root` assertions, and must re-decide the
        // branch rather than delete the assertions.
    }

    /// Declarations of every kind the classifier reads, plus a name the set
    /// deliberately omits.
    fn classifier_values() -> ResolvedValues {
        let decl = |name: &str, kind: ValueKind| ValueDecl {
            name: name.into(),
            description: None,
            kind,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        ResolvedValues::resolve(
            classifier_kinds()
                .into_iter()
                .map(|(name, kind)| decl(name, kind))
                .collect(),
            &[],
            &home(),
        )
        .expect("the declarations resolve")
    }

    /// Every kind a value may be declared with, under the name the classifier
    /// tests declare it as.
    ///
    /// One list, so a kind cannot be declared for these fixtures without
    /// `every_kind_but_a_string_fills_an_opening_segment` deciding it, and that
    /// test's match is exhaustive, so a new [`ValueKind`] does not compile
    /// until someone has.
    fn classifier_kinds() -> [(&'static str, ValueKind); 6] {
        [
            ("p", ValueKind::String),
            ("f", ValueKind::Bool),
            ("r", ValueKind::Path),
            ("e", ValueKind::Email),
            ("k", ValueKind::SshKey),
            ("g", ValueKind::AgeRecipient),
        ]
    }

    #[test]
    fn every_kind_but_a_string_fills_an_opening_segment() {
        // `may_be_empty` is the one place `written_form` reads a kind, and it
        // names `String` alone. Every other kind therefore makes a separator
        // after an opening placeholder change no file, which is what
        // `followed = false` records. Asserted over the kinds themselves rather
        // than over the four a spelling happened to use, because the
        // discrimination is on the kind axis.
        let values = classifier_values();

        for (name, kind) in classifier_kinds() {
            let spelling = format!("{{{{{name}}}}}/a");
            let opening = |followed| Root::Opening {
                first: vec![Piece::Name(name)],
                followed,
            };
            let root = form_of(&spelling, &values).root;
            match kind {
                // A `path` answer is absolute, so it roots the spelling instead
                // of opening a segment and `may_be_empty` never reaches it.
                ValueKind::Path => assert_eq!(root, Root::Absolute, "{spelling}"),
                ValueKind::String => assert_eq!(root, opening(true), "{spelling}"),
                ValueKind::Bool
                | ValueKind::Email
                | ValueKind::SshKey
                | ValueKind::AgeRecipient => assert_eq!(root, opening(false), "{spelling}"),
            }
        }
    }

    /// `written_form`, for a spelling the caller knows is well-formed.
    fn form_of<'a>(spelling: &'a str, values: &ResolvedValues) -> WrittenForm<'a> {
        written_form(spelling, values).expect("well-formed")
    }

    #[test]
    fn written_form_classifies_each_root() {
        // The four roots, read off directly rather than through a pair's
        // verdict, so a change to the classification is a change to this test.
        let values = classifier_values();

        assert_eq!(
            form_of("/a/b", &values).root,
            Root::Absolute,
            "a written `/`"
        );
        assert_eq!(
            form_of("{{r}}/b", &values).root,
            Root::Absolute,
            "a `path` answer is absolute, so it roots the spelling at `/`"
        );
        assert_eq!(form_of("~/a", &values).root, Root::Home);
        assert_eq!(
            form_of("{{p}}/a", &values).root,
            Root::Opening {
                first: vec![Piece::Name("p")],
                followed: true,
            },
            "a `string` may be emptied, so what follows the opening segment parts it"
        );
        assert_eq!(
            form_of("{{e}}/a", &values).root,
            Root::Opening {
                first: vec![Piece::Name("e")],
                followed: false,
            },
            "an `email` answer is never empty, so a separator after it changes no file"
        );
        assert_eq!(
            form_of("{{p}}", &values).root,
            Root::Opening {
                first: vec![Piece::Name("p")],
                followed: false,
            },
            "nothing follows it"
        );
    }

    #[test]
    fn written_form_classifies_each_segment() {
        // `Fixed` is what a `..` cancels and `Opaque` is what it does not, so
        // the split between them is the whole of the reduction's strength.
        let values = classifier_values();

        assert_eq!(
            form_of("/a/x{{f}}", &values).segments,
            [
                Segment::Fixed(vec![Piece::Literal("a")]),
                Segment::Fixed(vec![Piece::Literal("x"), Piece::Name("f")]),
            ],
            "a `bool` answer is never empty, never a dot and never holds a `/`"
        );
        assert_eq!(
            form_of("/a/{{p}}", &values).segments,
            [
                Segment::Fixed(vec![Piece::Literal("a")]),
                Segment::Opaque(vec![Piece::Name("p")]),
            ],
            "a `string` answer may be anything, so nothing cancels it"
        );
        assert_eq!(
            form_of("/a/./b/..", &values).segments,
            [Segment::Fixed(vec![Piece::Literal("a")])],
            "a `.` folds and a `..` cancels the `Fixed` before it"
        );
        assert_eq!(
            form_of("/{{p}}/..", &values).segments,
            [Segment::Opaque(vec![Piece::Name("p")]), Segment::Up],
            "nothing cancels an `Opaque`"
        );
        assert_eq!(
            form_of("/..", &values).segments,
            [],
            "at `/` there is nothing above to climb to"
        );
        assert_eq!(
            form_of("~/..", &values).segments,
            [Segment::Up],
            "under `~` the climb out of the home is no answer's doing"
        );
    }

    #[test]
    fn written_form_takes_a_name_no_layer_declares_as_the_widest_kind() {
        // Defensive: a spelling keyed as a file substituted, so every name in
        // one is declared. Exercised directly so the fallback is constrained
        // rather than merely commented — `cargo mutants` generates no mutant
        // for either closure.
        let values = classifier_values();

        // Not a `path`, so it does not start its own segment or root at `/`.
        assert_eq!(
            form_of("/a/x{{nowhere}}", &values).segments,
            [
                Segment::Fixed(vec![Piece::Literal("a")]),
                Segment::Opaque(vec![Piece::Literal("x"), Piece::Name("nowhere")]),
            ],
            "the widest kind: not a `bool`, so the segment is opaque"
        );
        // Widest means it may be empty, so what follows an opening one parts it.
        assert_eq!(
            form_of("{{nowhere}}/a", &values).root,
            Root::Opening {
                first: vec![Piece::Name("nowhere")],
                followed: true,
            }
        );
    }

    #[test]
    fn written_form_refuses_a_spelling_that_is_not_a_template() {
        // Defensive in the same way: substitution scans the same text, so a
        // spelling keyed as a file is well-formed. `None` rather than a panic,
        // and `one_path_as_written` then answers `false` rather than claiming
        // a proof it does not have.
        let values = classifier_values();

        assert!(written_form("~/{{unclosed", &values).is_none());
        assert!(!one_path_as_written(
            "~/{{unclosed",
            "~/{{unclosed",
            &values
        ));
    }

    #[test]
    fn written_form_of_an_empty_spelling_is_an_empty_opening_segment() {
        // The `unwrap_or_default` on the first segment is unreachable — the
        // scan loop always pushes a final segment — and an empty spelling is
        // the closest a caller gets to it. `Portable::parse_in("")` refuses it,
        // so it is never keyed as a file and never reaches `clash`.
        let values = classifier_values();
        let form = written_form("", &values).expect("an empty template is well-formed");

        assert_eq!(
            form.root,
            Root::Opening {
                first: Vec::new(),
                followed: false,
            }
        );
        assert!(form.segments.is_empty());
    }

    #[test]
    fn one_layer_may_not_name_one_file_twice_under_two_spellings() {
        // The parser's duplicate check compares spellings, so it cannot see this.
        let message = failure(&[global(
            "bx.toml",
            &format!(
                "[[value]]\nname = \"acct\"\nkind = \"string\"\ndefault = \"one\"\n{}{}",
                target_toml("~/.config/{{acct}}/settings.json", "a"),
                target_toml("~/.config/one/settings.json", "b"),
            ),
        )]);
        assert!(
            message
                .contains("names the same file as `~/.config/{{acct}}/settings.json` at bx.toml:"),
            "{message}"
        );

        // A toggle and a full entry in one layer are the same conflict.
        let message = failure(&[
            acct_layer(Some("one")),
            local(&format!(
                "{}[[target]]\npath = \"~/.config/one/settings.json\"\nenabled = false\n",
                target_toml("~/.config/{{acct}}/settings.json", "LOCAL")
            )),
        ]);
        assert!(message.contains("in this same layer"), "{message}");
        assert!(message.starts_with("local.toml:"), "{message}");
    }

    #[test]
    fn one_layer_naming_one_file_twice_by_spelling_alone_is_refused_whatever_the_answer() {
        // `~/.config/{{p}}/./s` and `~/.config/{{p}}/s` are one file for every
        // answer to `p`, so no answer can clear the collision: it is the layer's
        // own defect, and blocking it with a hint to change the answer would be
        // advice nothing can follow. Both spellings carry an answer, which is
        // why "is an answer in either spelling" cannot tell this apart.
        for toggle in [
            "~/.config/{{p}}/./s",
            "~/.config/{{p}}//s",
            "~/.config/{{p}}/s/",
        ] {
            let message = failure(&[
                global(
                    "bx.toml",
                    &format!(
                        "[[value]]\nname = \"p\"\nkind = \"string\"\n{}\
                         [[target]]\npath = \"{toggle}\"\nenabled = false\n",
                        target_toml("~/.config/{{p}}/s", "x")
                    ),
                ),
                local("[values]\np = \"work\"\n"),
            ]);
            assert!(message.starts_with("bx.toml:7:"), "{toggle}: {message}");
            assert!(
                message.contains("names the same file as `~/.config/{{p}}/s` at bx.toml:4"),
                "{toggle}: {message}"
            );
            assert!(
                message.contains("in this same layer"),
                "{toggle}: {message}"
            );
        }
    }

    #[test]
    fn a_toggle_for_a_target_waiting_on_a_value_names_the_declared_spelling() {
        // With `acct` unanswered the file is not known, so the spelling `plan`
        // would show once it is answered cannot reach it. The message says which
        // spelling will, rather than that the entry does not exist.
        let message = failure(&[
            acct_layer(None),
            local("[[target]]\npath = \"~/.config/one/settings.json\"\nenabled = false\n"),
        ]);
        assert!(
            message.contains("which no earlier layer declares"),
            "{message}"
        );
        assert!(
            message.contains(
                "matched by the spelling it was declared with, such as \
                 `~/.config/{{acct}}/settings.json` at bx.toml:"
            ),
            "{message}"
        );

        let merged = merge(&[
            acct_layer(None),
            local("[[target]]\npath = \"~/.config/{{acct}}/settings.json\"\nenabled = false\n"),
        ])
        .unwrap();
        assert!(merged.targets.is_empty());
    }

    #[test]
    fn an_empty_layer_set_merges_to_an_empty_configuration() {
        assert_eq!(merge(&[]).unwrap(), Config::default());
    }

    #[test]
    fn a_merged_configuration_has_no_toggles_left() {
        let merged = merge(&[
            global("bx.toml", &target_toml("~/.a", "a")),
            local("[[target]]\npath = \"~/.a\"\nenabled = true\n"),
        ])
        .unwrap();

        assert!(
            merged.toggles.is_empty(),
            "toggles are consumed by the merge"
        );
    }

    #[test]
    fn no_config_module_reads_the_environment() {
        // A structural test, and the one that catches a reach for the
        // environment on a resolution path instead of threading `home` through.
        // It is structural because `std::env::set_var` is `unsafe` in edition
        // 2024 and process-global, so a test that mutated the environment would
        // race every other test in this binary.
        //
        // `layers.rs` is here because it is the module whose own doc asserts
        // "nothing here reads the environment" — it takes both the home and the
        // `XDG_STATE_HOME` override as arguments — which is the claim this test
        // is quoted as proving.
        //
        // `target.rs` parses every target a layer holds, against the home it is
        // handed. `paths.rs` holds `Portable::parse_in` and `normalize`, which
        // every module above calls, and also the crate's two deliberate reads
        // of the environment: `home()` and `config_root()`, the edges that hand
        // a resolution path its arguments. Each edge line is allowed exactly
        // once and by its whole text, so a third read anywhere in the module,
        // or a second copy of either, still fails here.
        const PATHS_EDGES: [&str; 2] = [
            "home_in(std::env::var_os(\"HOME\").as_deref())",
            "std::env::var_os(\"XDG_CONFIG_HOME\").as_deref(),",
        ];
        for (name, source) in [
            ("layers.rs", include_str!("layers.rs")),
            ("merge.rs", include_str!("merge.rs")),
            ("values.rs", include_str!("values.rs")),
            ("resolve.rs", include_str!("resolve.rs")),
            ("values/local.rs", include_str!("values/local.rs")),
            ("target.rs", include_str!("target.rs")),
            ("paths.rs", include_str!("../paths.rs")),
        ] {
            // The non-test half, minus its prose. This very test names the
            // strings it forbids, and `layers.rs` documents what the *binary*
            // passes in by naming the call the library itself may not make — a
            // textual scan cannot tell a description from a call, so whole-line
            // comments are dropped and code is what is scanned.
            let code = source
                .split("#[cfg(test)]")
                .next()
                .expect("the non-test half");
            let edges: &[&str] = if name == "paths.rs" {
                &PATHS_EDGES
            } else {
                &[]
            };
            for edge in edges {
                assert_eq!(
                    code.lines().filter(|line| line.trim() == *edge).count(),
                    1,
                    "{name}: the edge `{edge}` is expected exactly once; if it moved, \
                     re-verify this list rather than widening the scan's exceptions"
                );
            }
            let body: String = code
                .lines()
                .filter(|line| {
                    !line.trim_start().starts_with("//") && !edges.contains(&line.trim())
                })
                .collect::<Vec<_>>()
                .join("\n");
            // `paths::home(` is the likeliest real regression: a resolution
            // module calling the crate's own home resolver — which does read
            // `$HOME` — instead of threading the argument through, which would
            // read as innocuous at the call site and make the merge impure.
            for forbidden in [
                "env::var",
                "var_os",
                "env!(",
                "option_env!",
                "canonicalize(",
                "current_dir(",
                "paths::home(",
            ] {
                assert!(
                    !body.contains(forbidden),
                    "{name} contains `{forbidden}`: resolution is a pure function of \
                     the layer bytes plus the home that is threaded in"
                );
            }
        }
    }
}
