//! Keying a target by the file it names, and what one layer naming one file
//! twice comes to.
//!
//! A target's key is its substituted, normalised path, so two spellings an
//! answer makes one file are one target. One layer naming one file twice is
//! the repo's defect when no answer went into the pair, and otherwise a
//! [`Conflict`] resolution blocks, with a hint that names the answer to change
//! or the toggles to remove.

use super::Section;
use super::merged::{Keyed, Merged, unknown_toggle};
use super::written_form::one_path_as_written;
use crate::config::target::Target;
use crate::config::values::{ResolvedValues, statements_named};
use crate::config::{Error, Layer, Origin};
use crate::paths::Portable;
use std::path::Path;

/// What a target merges by: the file it names, for this account.
///
/// Compared **after substitution**, so `~/.config/{{acct}}/settings.json` with
/// `acct` answered `one` and `~/.config/one/settings.json` are one key.
/// `Portable` is what the ledger and the journal are written against, and two
/// targets for one file would give `rm` two priors to restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TargetKey {
    /// The substituted, normalised path.
    File(String),
    /// The path as written: it waits on a value with no usable answer, or it
    /// substitutes to something that is not a portable path, which resolution
    /// reports. Two of these match only when they are spelled identically.
    AsWritten(String),
}

impl TargetKey {
    /// The key of a path spelled `raw`.
    pub(super) fn of(raw: &str, values: &ResolvedValues) -> Self {
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
/// [`crate::config::resolve`] blocks every target for the file, naming each spelling's
/// line and each answer's. A pair no answer went into is the repo's own defect
/// and still fails the merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Conflict {
    /// The file, as the substituted, normalised path the targets resolve to.
    pub(crate) file: String,
    /// The answers that made the spellings meet, in declaration order.
    pub(crate) names: Vec<String>,
    /// What to do, spelled by [`ResolvedValues::answers_hint`], or by
    /// [`ResolvedValues::removal_hint`] when a toggle among the statements
    /// cannot be shown to name a declared target for every answer.
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
    /// Whether it is a toggle bx cannot show names a declared target for
    /// every answer (see [`anchored`]). Never a full entry, which creates the
    /// file it names.
    fragile: bool,
}

/// A [`Conflict`] while the layers are still being folded.
pub(super) struct Clash {
    /// The layer whose statements collided.
    layer: std::path::PathBuf,
    /// The file they collided on.
    key: TargetKey,
    /// Every statement in that layer naming the file, in the order read, each
    /// with [`Said::fragile`].
    statements: Vec<(String, Origin, bool)>,
    /// The answers that went into them.
    names: Vec<String>,
}

impl Clash {
    /// The conflict resolution reads, with its hint spelled.
    ///
    /// Changing an answer is advice only while every toggle in the clash names a
    /// declared target whatever is answered. Otherwise another answer may leave
    /// a toggle naming nothing, which fails the load, so the hint names the
    /// toggles to remove instead, and closes with the answer to change when
    /// two or more statements outlive them and still name one file.
    pub(super) fn into_conflict(self, values: &ResolvedValues) -> Conflict {
        let (TargetKey::File(file) | TargetKey::AsWritten(file)) = self.key;
        let spellings = statements_named(&self.statements);
        let names = values.in_declaration_order(self.names);
        let problem = format!(
            "`[[target]]` {spellings} name one file, `{file}`, and one layer may name a \
             file once"
        );
        let hint = if self.statements.iter().any(|(_, _, fragile)| *fragile) {
            values.removal_hint(&problem, &names, &self.statements)
        } else {
            let texts: Vec<&str> = self
                .statements
                .iter()
                .map(|(spelling, _, _)| spelling.as_str())
                .collect();
            values.answers_hint(&problem, &texts, &names)
        };
        Conflict { hint, file, names }
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
    /// Only a later layer's full entry for the file settles it: it replaces
    /// every entry for the file and drops the file's recorded clashes. A later
    /// toggle flips every entry for the file and settles nothing; the clashes
    /// stay recorded.
    ///
    /// # Errors
    ///
    /// [`Error::BadValue`] when a toggle names a file no earlier layer declares,
    /// or when this one layer names one file twice under two spellings with no
    /// account answer in either — the parser's own duplicate check compares
    /// spellings, and cannot see that `~/{{acct}}/x` and `~/one/x` are one file
    /// — or under two spellings that reduce to one text with their placeholders
    /// left in, which no answer could pull apart.
    ///
    /// `earlier` are the layers folded before this one: a toggle is compared
    /// against their full entries' spellings, and this layer's, to decide which
    /// hint a clash it is in gets. It is a slice of borrows rather than of
    /// layers so that the set the caller is iterating cannot be passed in its
    /// place: `&layers` does not type-check here, and the list the caller does
    /// pass is one a layer enters only once it has been folded. A barrier, not
    /// a proof — `layers.iter().collect()` would still pass every layer — and
    /// nothing stronger is available, since no test can tell the bound apart:
    /// a toggle judged against a later layer's entry gets no hint at all, for
    /// the reason [`anchored`] gives.
    pub(super) fn absorb_layer(
        &mut self,
        layer: &Layer,
        earlier: &[&Layer],
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
                    let statement = (spelling, &target.origin, false);
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
                fragile: false,
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
                    let fragile = !anchored(&toggle.key, earlier, layer, values);
                    let statement = (toggle.key.as_str(), &toggle.origin, fragile);
                    if clash(&said, &key, statement, values, &layer.file, clashes)? {
                        self.set_enabled_for(&key, true);
                    } else {
                        self.set_enabled_for(&key, toggle.enabled);
                    }
                    said.push(Said {
                        key,
                        spelling: toggle.key.clone(),
                        origin: toggle.origin.clone(),
                        fragile,
                    });
                }
                Section::Value
                | Section::Env
                | Section::Alias
                | Section::Function
                | Section::Plugin
                | Section::Source
                | Section::Activation
                | Section::Tool
                | Section::External => {}
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
/// `Ok(true)`. Each statement keeps its [`Said::fragile`] flag, which decides
/// whether the conflict's hint names an answer or toggles to remove.
fn clash(
    said: &[Said],
    key: &TargetKey,
    (spelling, origin, fragile): (&str, &Origin, bool),
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

    let mut statements: Vec<(String, Origin, bool)> = earlier
        .iter()
        .map(|statement| {
            (
                statement.spelling.clone(),
                statement.origin.clone(),
                statement.fragile,
            )
        })
        .collect();
    statements.push((spelling.to_string(), origin.clone(), fragile));
    clashes.retain(|clash| !(clash.key == *key && clash.layer == layer));
    clashes.push(Clash {
        layer: layer.to_path_buf(),
        key: key.clone(),
        statements,
        names,
    });
    Ok(true)
}

/// Whether a toggle spelled `toggle` can be shown to name a declared target for
/// every answer: its spelling is one path as written with a full entry's, in an
/// earlier layer or in `layer`, its own.
///
/// Such a toggle names that entry's file whenever the entry names one, and a
/// declared file is never taken out of the merge, since a later entry for it
/// replaces in place. So an answer that parts a clash leaves the toggle naming
/// a target. Layers after `layer` do not count: at this toggle their entries
/// are not there yet.
///
/// `false` says only that bx cannot show it. A toggle that meets a declared
/// spelling through this account's answer alone is not anchored, and neither
/// is one whose pair with a declared spelling the written form does not
/// decide.
///
/// Neither arm is the one that decides a hint. Take a toggle anchored by an
/// entry in `layer`, its own, and suppose it reaches a clash. The two have one
/// written form, so:
///
/// - if the strings the layer stores are the same — an entry's `path`
///   normalised when it was parsed, a toggle's key raw — the parser's own
///   duplicate check refused the layer before `merge` ran, and there is no
///   clash;
/// - if they differ and the toggle's spelling resolves, so does the entry's,
///   one form being one file, so the entry holds the toggle's
///   [`TargetKey::File`] in this very layer and [`clash`] refuses the pair as
///   that layer naming one file twice;
/// - if they differ and the toggle's spelling does not resolve, it is keyed as
///   written, by its own text, and no entry holds that key: an entry's stored
///   `path` is normalised, so it carries no `..`, and cancelling a fixed
///   segment is the only way a written form drops a placeholder, which is what
///   a spelling that does not resolve while its pair does must have done. So
///   either [`unknown_toggle`] refuses the toggle, or something else in the
///   merge holds its key — an entry in an *earlier* layer, spelled exactly as
///   the toggle is, which has the toggle's form too and anchors it through
///   `earlier` whatever its own layer declares.
///
/// The split is on two facts, whether the stored strings are equal and whether
/// the toggle's spelling resolves, so it leaves no case out. A pair need not
/// agree on the second — a `bool` left unanswered makes `/opt/{{b}}/../x` one
/// path as written with `/opt/x`, a `bool` being always one segment, while the
/// first is keyed as written and the second keys its file — and the third case
/// is where every such mixed pair lands, for the reason it gives. In each case
/// the own-layer arm changes no verdict that reaches a hint. The layers after
/// `layer` are the same story from the other end: a full entry drops every
/// clash held for its file, so a toggle judged against one gets no hint rather
/// than a reworded one.
///
/// Both arms are kept all the same: this answers what bx can show about one
/// toggle, and none of those rules is its to assume. Three refusals, the mixed
/// pair among them, are exhibited by
/// `an_own_layer_entry_and_toggle_for_one_file_meet_three_different_refusals`,
/// the case no refusal catches by
/// `an_own_layer_pair_no_refusal_catches_is_anchored_by_the_earlier_layer_anyway`,
/// and the middle refusal over every folding by
/// `one_layer_naming_one_file_twice_by_spelling_alone_is_refused_whatever_the_answer`.
fn anchored(toggle: &str, earlier: &[&Layer], layer: &Layer, values: &ResolvedValues) -> bool {
    earlier
        .iter()
        .copied()
        .chain([layer])
        .flat_map(|layer| &layer.config.targets)
        .any(|target| one_path_as_written(toggle, target.path.as_str(), values))
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

#[cfg(test)]
mod tests {
    use super::super::tests::{failure, global, home, local, merge, paths, target_toml};
    use super::*;
    use crate::config::parse_str;
    use crate::config::values::{ValueAssignment, ValueDecl};

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
        // placeholder, so it is the route by which a miss becomes a `Conflict`.
        // No answer clears that clash, and neither toggle is anchored to a
        // declared spelling, so its hint names both toggles for removal rather
        // than an answer to change: removing them leaves the entry naming
        // `/conf` once.
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
        let hint = &as_toggles.conflicts[0].hint;
        assert!(
            hint.ends_with(&format!(
                "remove the toggles `{first}` at bx.toml:7 and `{second}` at \
                 bx.toml:10{CANNOT_SHOW_SEVERAL}"
            )),
            "{hint}"
        );
        assert!(!hint.contains("change that answer"), "{hint}");
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
    fn an_own_layer_entry_and_toggle_for_one_file_meet_three_different_refusals() {
        // Three refusals an own-layer `[[target]]` entry and toggle for one
        // file can meet, by three different producers, and which one a pair
        // meets turns on the strings the layer stores — an entry's `path`
        // normalised when it was parsed, a toggle's key raw. Not every such
        // pair is refused: the one none of these catches is
        // `an_own_layer_pair_no_refusal_catches_is_anchored_by_the_earlier_layer_anyway`.
        // Why no toggle anchored by its own layer's entry reaches a hint is
        // argued at `anchored`, and rests on none of these being the whole
        // list.
        let text = |entry: &str, toggle: &str| {
            format!(
                "[[value]]\nname = \"p\"\nkind = \"string\"\n{}\
                 [[target]]\npath = \"{toggle}\"\nenabled = false\n",
                target_toml(entry, "x")
            )
        };

        // (i) The strings coincide: the parser's own duplicate check refuses
        // the layer, before any merge. The second row's entry folds to the
        // toggle's spelling when it is parsed.
        for (entry, toggle) in [
            ("~/.config/s", "~/.config/s"),
            ("~/.config/{{p}}/../s", "~/.config/s"),
        ] {
            let message = parse_str(&text(entry, toggle), Path::new("bx.toml"), &home())
                .expect_err("a layer that names one file twice is refused")
                .to_string();
            assert!(message.contains("duplicate target"), "{entry}: {message}");
            assert!(message.contains("first declared at"), "{entry}: {message}");
        }

        // (ii) The strings differ and the file is known: `clash` refuses it as
        // one layer naming one file twice. Covered in full, over every folding,
        // by `one_layer_naming_one_file_twice_by_spelling_alone_is_refused_whatever_the_answer`.
        let message = failure(&[
            global("bx.toml", &text("~/.config/{{p}}/s", "~/.config/{{p}}/./s")),
            local("[values]\np = \"work\"\n"),
        ]);
        assert!(message.contains("in this same layer"), "{message}");

        // (iii) The strings differ and the file is not known: each spelling is
        // keyed by its own text, so the toggle matches no entry at all and
        // `unknown_toggle` refuses it. `p` is declared and unanswered here.
        let message = failure(&[
            global("bx.toml", &text("~/.config/{{p}}/s", "~/.config/{{p}}/./s")),
            local(""),
        ]);
        assert!(
            message.contains("which no earlier layer declares"),
            "{message}"
        );
        assert!(
            message.contains(
                "matched by the spelling it was declared with, such as `~/.config/{{p}}/s` \
                 at bx.toml:4"
            ),
            "{message}"
        );

        // (iv) A pair need not agree on whether its spellings resolve. With a
        // `bool` unanswered, `/opt/{{b}}/../x` cancels to `/opt/x` as written —
        // a `bool` is always one segment — so the two are one path, while the
        // entry keys the file and the toggle is keyed as written. The refusal
        // is (iii)'s all the same: an entry's stored `path` is normalised, so
        // no entry holds a key with a `..` still in it.
        let mixed = format!(
            "[[value]]\nname = \"b\"\nkind = \"bool\"\n{}\
             [[target]]\npath = \"/opt/{{{{b}}}}/../x\"\nenabled = false\n",
            target_toml("/opt/x", "x")
        );
        let values = resolved(&[global("bx.toml", &mixed), local("")]);
        assert!(
            one_path_as_written("/opt/{{b}}/../x", "/opt/x", &values),
            "the pair is one path as written"
        );
        let message = failure(&[global("bx.toml", &mixed), local("")]);
        assert!(
            message.contains("which no earlier layer declares"),
            "{message}"
        );
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

    /// A target toggle switching `path` off.
    fn toggle_toml(path: &str) -> String {
        format!("[[target]]\npath = \"{path}\"\nenabled = false\n")
    }

    /// The `profile` declaration the toggle-clash fixtures share, lines 1-3.
    const PROFILE: &str = "[[value]]\nname = \"profile\"\nkind = \"string\"\n";

    /// What a toggle-clash hint says once no answer is recommended, after the
    /// toggle or toggles it names.
    const CANNOT_SHOW_ONE: &str = ": bx cannot show that it names a declared target for every \
                                   answer, so another answer may leave it toggling a file no \
                                   earlier layer declares";
    const CANNOT_SHOW_SEVERAL: &str = ": bx cannot show that they name declared targets for every \
                                       answer, so another answer may leave them toggling files no \
                                       earlier layer declares";
    const CANNOT_SHOW_ANY: &str = "; keep one of these toggles and remove the rest: bx cannot \
                                   show that any of them names a declared target for every \
                                   answer, so another answer may leave one toggling a file no \
                                   earlier layer declares; the one kept decides whether that \
                                   file's target is enabled";

    /// The layers merged and resolved with no conflict, no block and no error:
    /// a configuration that loads. The ready targets, as path and body.
    fn loads(layers: &[Layer]) -> Vec<(String, crate::config::target::Body)> {
        use crate::config::resolution::Resolution;
        use crate::config::resolve::resolve;

        let config = merge(layers).unwrap_or_else(|e| panic!("the merge failed: {e}"));
        assert!(config.conflicts.is_empty(), "{:#?}", config.conflicts);
        resolve(&config, &home())
            .unwrap_or_else(|e| panic!("the resolution failed: {e}"))
            .targets
            .into_iter()
            .map(|resolution| match resolution {
                Resolution::Ready(target) => (target.path.as_str().to_string(), target.body),
                Resolution::Blocked(entry) => panic!("blocked: {}", entry.hint),
            })
            .collect()
    }

    /// The account's layer: `profile` answered, then one toggle per spelling,
    /// the first at line 3 and each next three lines on.
    fn profile_toggles(answer: &str, toggles: &[&str]) -> Layer {
        local(&format!(
            "[values]\nprofile = \"{answer}\"\n{}",
            toggles
                .iter()
                .map(|path| toggle_toml(path))
                .collect::<String>()
        ))
    }

    #[test]
    fn a_toggle_clash_no_answer_can_clear_names_the_toggle_to_remove() {
        // Issue #46. `~/.config/{{profile}}/s` reaches the declared
        // `~/.config/default/s` only while `profile` is `default`, the answer
        // that makes it meet the literal toggle. "Change that answer" cannot be
        // followed: any other answer leaves that toggle naming a file nothing
        // declares, which fails the whole load. Removing it can.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "{PROFILE}{}{}",
                    target_toml("~/.config/default/s", "D"),
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let both = ["~/.config/default/s", "~/.config/{{profile}}/s"];
        let layers = [base(), profile_toggles("default", &both)];

        let config = merge(&layers).unwrap_or_else(|e| {
            panic!("an answer that names one file twice failed the merge: {e}")
        });
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        assert_eq!(
            config.conflicts[0].hint,
            format!(
                "`[[target]]` `~/.config/default/s` at local.toml:3 and \
                 `~/.config/{{{{profile}}}}/s` at local.toml:6 name one file, \
                 `~/.config/default/s`, and one layer may name a file once, because of the \
                 answer to `profile` at local.toml:2; remove the toggle \
                 `~/.config/{{{{profile}}}}/s` at local.toml:6{CANNOT_SHOW_ONE}"
            )
        );
        assert_eq!(
            merge(&layers).unwrap(),
            config,
            "the merge is deterministic"
        );

        // The hint's advice loads.
        assert_eq!(
            loads(&[base(), profile_toggles("default", &both[..1])]),
            [(
                "~/.zshrc".to_string(),
                crate::config::target::Body::Inline("setopt".to_string())
            )]
        );

        // The advice it replaced does not.
        let message = failure(&[base(), profile_toggles("other", &both)]);
        assert!(
            message.contains("toggles `~/.config/{{profile}}/s`, which no earlier layer declares"),
            "{message}"
        );
    }

    #[test]
    fn a_literal_toggle_meeting_a_placeholder_target_only_through_an_answer_is_the_one_to_remove() {
        // The mirror of the reproduction: the placeholder spelling is the
        // declared one, so the literal toggle is the one an answer strands.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "{PROFILE}{}{}",
                    target_toml("~/.config/{{profile}}/s", "P"),
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let both = ["~/.config/default/s", "~/.config/{{profile}}/s"];

        let config = merge(&[base(), profile_toggles("default", &both)]).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(&format!(
                "; remove the toggle `~/.config/default/s` at local.toml:3{CANNOT_SHOW_ONE}"
            )),
            "{hint}"
        );
        assert!(!hint.contains("change that answer"), "{hint}");

        assert_eq!(
            loads(&[base(), profile_toggles("default", &both[1..])]).len(),
            1,
            "only `~/.zshrc` is left"
        );
        let message = failure(&[base(), profile_toggles("other", &both)]);
        assert!(
            message.contains("toggles `~/.config/default/s`, which no earlier layer declares"),
            "{message}"
        );
    }

    #[test]
    fn a_full_entry_and_a_toggle_that_reaches_it_only_through_an_answer_name_the_toggle() {
        // The toggle meets a full entry its own layer wrote. Only the toggle can
        // be stranded by another answer: a full entry creates its file.
        let base = || {
            global(
                "bx.toml",
                &format!("{PROFILE}{}", target_toml("~/.zshrc", "setopt")),
            )
        };
        let entry = target_toml("~/.config/{{profile}}/s", "L");

        let config = merge(&[
            base(),
            local(&format!(
                "[values]\nprofile = \"default\"\n{entry}{}",
                toggle_toml("~/.config/default/s")
            )),
        ])
        .unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(&format!(
                "because of the answer to `profile` at local.toml:2; remove the toggle \
                 `~/.config/default/s` at local.toml:6{CANNOT_SHOW_ONE}"
            )),
            "{hint}"
        );

        assert_eq!(
            loads(&[
                base(),
                local(&format!("[values]\nprofile = \"default\"\n{entry}"))
            ]),
            [
                (
                    "~/.zshrc".to_string(),
                    crate::config::target::Body::Inline("setopt".to_string())
                ),
                (
                    "~/.config/default/s".to_string(),
                    crate::config::target::Body::Inline("L".to_string())
                ),
            ]
        );
    }

    #[test]
    fn several_toggles_that_reach_a_full_entry_only_through_an_answer_are_each_named() {
        // Two toggles, each two files as written with the full entry and with
        // each other, and each stranded by some other answer.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "{PROFILE}[[value]]\nname = \"q\"\nkind = \"string\"\n{}",
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let answers = "[values]\nprofile = \"default\"\nq = \"a\"\n";
        let entry = target_toml("~/.config/{{profile}}/s", "L");

        let config = merge(&[
            base(),
            local(&format!(
                "{answers}{entry}{}{}",
                toggle_toml("~/.config/default/s"),
                toggle_toml("~/.config/{{q}}/../default/s")
            )),
        ])
        .unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        assert_eq!(
            config.conflicts[0].hint,
            format!(
                "`[[target]]` `~/.config/{{{{profile}}}}/s` at local.toml:4 and \
                 `~/.config/default/s` at local.toml:7 and \
                 `~/.config/{{{{q}}}}/../default/s` at local.toml:10 name one file, \
                 `~/.config/default/s`, and one layer may name a file once, because of the \
                 answer to `profile` at local.toml:2 and the answer to `q` at local.toml:3; \
                 remove the toggles `~/.config/default/s` at local.toml:7 and \
                 `~/.config/{{{{q}}}}/../default/s` at local.toml:10{CANNOT_SHOW_SEVERAL}"
            )
        );

        assert_eq!(
            loads(&[base(), local(&format!("{answers}{entry}"))]).len(),
            2,
            "`~/.zshrc` and the full entry"
        );
    }

    /// The values one layer set resolves to, for a predicate taken on its own.
    fn resolved(layers: &[Layer]) -> ResolvedValues {
        let decls: Vec<ValueDecl> = layers
            .iter()
            .flat_map(|layer| layer.config.values.clone())
            .collect();
        let given: Vec<ValueAssignment> = layers
            .iter()
            .flat_map(|layer| layer.config.value_assignments.clone())
            .collect();
        ResolvedValues::resolve(decls, &given, &home()).expect("the fixture's values resolve")
    }

    #[test]
    fn a_toggle_is_anchored_by_a_full_entry_in_any_layer_folded_so_far() {
        // `anchored` taken on its own, because neither source it adds to the
        // first can be told apart through a hint: a same-layer entry one path
        // as written with the toggle either has the pair refused before a hint
        // is chosen or anchors the toggle from an earlier layer as well, for
        // the reason `anchored` gives, and an entry a later layer declares
        // settles the clash instead of rewording it (see resolve.rs's
        // `one_file_clashing_in_two_layers_is_recorded_for_each_and_settled_only_by_name`).
        // What the predicate answers is still what the hints rest on, so each
        // source it consults is pinned here.
        let declaring = || {
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n{}",
                    target_toml("~/.config/{{p}}/s", "P")
                ),
            )
        };
        let answering = || local("[values]\np = \"default\"\n");
        let values = resolved(&[declaring(), answering()]);
        let folded = declaring();

        assert!(
            anchored("~/.config/{{p}}/./s", &[&folded], &answering(), &values),
            "an earlier layer's entry anchors it"
        );
        assert!(
            anchored("~/.config/{{p}}/./s", &[], &declaring(), &values),
            "its own layer's entry anchors it"
        );
        assert!(
            !anchored("~/.config/default/s", &[&folded], &answering(), &values),
            "a spelling only this account's answer pairs with the entry does not"
        );
        assert!(
            !anchored("~/.config/{{p}}/./s", &[], &answering(), &values),
            "a layer set that declares nothing anchors nothing"
        );
    }

    #[test]
    fn a_toggle_the_hint_leaves_standing_is_one_no_answer_can_strand() {
        // The premise the closing clause rests on: what outlives the removals
        // is not a toggle an answer could strand. Here one survivor is a
        // toggle — `~/.config/{{p}}/./s`, anchored by `bx.toml`'s own spelling
        // of it, which `local.toml`'s entry replaced in the merge but not in
        // the layer — so following the whole hint has to leave it naming a
        // declared target. It does: the answer change moves it onto `bx.toml`'s
        // entry under the new answer, and the configuration loads.
        const DECLS: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\n\
                             [[value]]\nname = \"r\"\nkind = \"string\"\n";
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "{DECLS}{}{}",
                    target_toml("~/.config/{{p}}/s", "P"),
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let answered = |p: &str, toggles: &str| {
            [
                base(),
                local(&format!(
                    "[values]\np = \"{p}\"\nq = \"default\"\nr = \"default\"\n{}{}{toggles}",
                    target_toml("~/.config/{{q}}/s", "L"),
                    "[[target]]\npath = \"~/.config/{{p}}/./s\"\nenabled = false\n"
                )),
            ]
        };

        let config = merge(&answered("default", &toggle_toml("~/.config/{{r}}/s"))).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(
                "; remove the toggle `~/.config/{{r}}/s` at local.toml:11: bx cannot show \
                 that it names a declared target for every answer, so another answer may \
                 leave it toggling a file no earlier layer declares; `~/.config/{{q}}/s` at \
                 local.toml:5 and `~/.config/{{p}}/./s` at local.toml:8 still name one file \
                 once it is gone, because of the answer to `p` at local.toml:2 and the \
                 answer to `q` at local.toml:3; change that answer too"
            ),
            "{hint}"
        );

        // The whole hint followed: the flagged toggle gone, `p` changed. The
        // surviving toggle now names `bx.toml`'s entry under the new answer and
        // switches it off; nothing is stranded and nothing clashes.
        assert_eq!(
            loads(&answered("other", "")),
            [
                (
                    "~/.zshrc".to_string(),
                    crate::config::target::Body::Inline("setopt".to_string())
                ),
                (
                    "~/.config/default/s".to_string(),
                    crate::config::target::Body::Inline("L".to_string())
                ),
            ]
        );
    }

    #[test]
    fn an_own_layer_pair_no_refusal_catches_is_anchored_by_the_earlier_layer_anyway() {
        // The case that is refused by nothing: `two.toml` declares
        // `/opt{{r}}/conf` and toggles `/opt/{{r}}/conf`, which are one path as
        // written; the stored strings differ, so the parser's duplicate check
        // passes; `r` is unanswered, so both spellings are keyed as written, by
        // their own text, and no statement in `two.toml` shares the toggle's
        // key for `clash` to refuse; and `bx.toml` holds that key already, so
        // the unknown-toggle check does not fire either. The layer set merges.
        //
        // The toggle still reaches no hint through its own layer's entry: what
        // let it past the unknown-toggle check is an entry in an *earlier*
        // layer spelled exactly as the toggle is, and that entry anchors it
        // through the earlier-layer arm. Drop it and route (iii) returns.
        let declaring = || {
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"r\"\nkind = \"path\"\n{}",
                    target_toml("/opt/{{r}}/conf", "D")
                ),
            )
        };
        let pairing = || {
            global(
                "modules/20-two.toml",
                &format!(
                    "{}[[target]]\npath = \"/opt/{{{{r}}}}/conf\"\nenabled = false\n",
                    target_toml("/opt{{r}}/conf", "G")
                ),
            )
        };
        let values = resolved(&[declaring(), pairing(), local("")]);

        assert!(
            one_path_as_written("/opt/{{r}}/conf", "/opt{{r}}/conf", &values),
            "the own-layer pair is one path as written"
        );
        let config = merge(&[declaring(), pairing(), local("")])
            .unwrap_or_else(|e| panic!("no refusal catches this pair: {e}"));
        assert!(config.conflicts.is_empty(), "{:#?}", config.conflicts);

        // Both arms answer yes here, which is the point: the entry that let the
        // toggle past the unknown-toggle check is spelled exactly as the toggle
        // is, so it anchors it whether or not its own layer's entry is
        // consulted. The verdict does not rest on the own-layer arm.
        assert!(
            anchored("/opt/{{r}}/conf", &[&declaring()], &local(""), &values),
            "the earlier layer's entry anchors it with nothing declared beside it"
        );
        assert!(
            anchored("/opt/{{r}}/conf", &[], &pairing(), &values),
            "its own layer's entry would too"
        );

        // Without that entry the toggle reaches nothing and is refused.
        let message = failure(&[pairing(), local("")]);
        assert!(
            message.contains("which no earlier layer declares"),
            "{message}"
        );
    }

    #[test]
    fn a_removal_that_leaves_two_statements_naming_one_file_names_the_answer_too() {
        // Three statements, one flagged: two full entries and a toggle bx
        // cannot show names a declared target for every answer. Removing the
        // named toggle is necessary and not enough — the two entries still name
        // one file — so the hint closes with the answer that parts them, and
        // names only the answer those two carry, not the one only the toggle
        // brought in.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "{PROFILE}[[value]]\nname = \"q\"\nkind = \"string\"\n{}",
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let entries = format!(
            "{}{}",
            target_toml("~/.config/default/s", "A"),
            target_toml("~/.config/{{profile}}/s", "B")
        );
        let answered = |profile: &str, toggles: &str| {
            [
                base(),
                local(&format!(
                    "[values]\nprofile = \"{profile}\"\nq = \"default\"\n{entries}{toggles}"
                )),
            ]
        };

        let config = merge(&answered("default", &toggle_toml("~/.config/{{q}}/s"))).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        assert_eq!(
            config.conflicts[0].hint,
            format!(
                "`[[target]]` `~/.config/default/s` at local.toml:4 and \
                 `~/.config/{{{{profile}}}}/s` at local.toml:7 and \
                 `~/.config/{{{{q}}}}/s` at local.toml:10 name one file, \
                 `~/.config/default/s`, and one layer may name a file once, because of the \
                 answer to `profile` at local.toml:2 and the answer to `q` at local.toml:3; \
                 remove the toggle `~/.config/{{{{q}}}}/s` at local.toml:10{CANNOT_SHOW_ONE}; \
                 `~/.config/default/s` at local.toml:4 and `~/.config/{{{{profile}}}}/s` at \
                 local.toml:7 still name one file once it is gone, because of the answer to \
                 `profile` at local.toml:2; change that answer too"
            )
        );

        // The named removal is necessary: changing the answer alone leaves the
        // toggle on a file it is only shown to name through this account's
        // answer, so the layer still names one file twice.
        assert!(
            !merge(&answered("other", &toggle_toml("~/.config/{{q}}/s")))
                .unwrap()
                .conflicts
                .is_empty(),
            "the toggle still meets one of the entries"
        );
        // And not sufficient, which is why the hint does not stop there.
        assert!(
            !merge(&answered("default", ""))
                .unwrap()
                .conflicts
                .is_empty(),
            "the two entries still name one file"
        );
        // Two flagged toggles read the same way, in the plural.
        let both = format!(
            "{}{}",
            toggle_toml("~/.config/{{q}}/s"),
            toggle_toml("~/.config/{{r}}/s")
        );
        let config = merge(&[
            global(
                "bx.toml",
                &format!(
                    "{PROFILE}[[value]]\nname = \"q\"\nkind = \"string\"\n\
                     [[value]]\nname = \"r\"\nkind = \"string\"\n{}",
                    target_toml("~/.zshrc", "setopt")
                ),
            ),
            local(&format!(
                "[values]\nprofile = \"default\"\nq = \"default\"\nr = \"default\"\n\
                 {entries}{both}"
            )),
        ])
        .unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(&format!(
                "{CANNOT_SHOW_SEVERAL}; `~/.config/default/s` at local.toml:5 and \
                 `~/.config/{{{{profile}}}}/s` at local.toml:8 still name one file once they \
                 are gone, because of the answer to `profile` at local.toml:2; change that \
                 answer too"
            )),
            "{hint}"
        );

        // The whole hint followed — the toggle gone, the answer changed — loads.
        assert_eq!(
            loads(&answered("other", "")),
            [
                (
                    "~/.zshrc".to_string(),
                    crate::config::target::Body::Inline("setopt".to_string())
                ),
                (
                    "~/.config/default/s".to_string(),
                    crate::config::target::Body::Inline("A".to_string())
                ),
                (
                    "~/.config/other/s".to_string(),
                    crate::config::target::Body::Inline("B".to_string())
                ),
            ]
        );
    }

    #[test]
    fn what_a_removal_leaves_is_offered_the_answer_a_default_carries_it_into() {
        // The two entries differ only in that one reaches `p` through `q`'s
        // committed `default`, so no answer to `p` parts them and answering `q`
        // directly does. The removal advice withholds that offer (decision 6);
        // the clause that closes the hint makes it, because the statements it
        // is about are not the flagged toggle and the reason for withholding it
        // does not reach them. Withheld, the clause would be an act that does
        // not clear the clash.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                     [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{{{p}}}}\"\n\
                     [[value]]\nname = \"r\"\nkind = \"string\"\n{}",
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let entries = format!(
            "{}{}",
            target_toml("~/.config/{{p}}/s", "A"),
            target_toml("~/.config/{{q}}/s", "B")
        );
        let answered =
            |values: &str, toggles: &str| [base(), local(&format!("{values}{entries}{toggles}"))];
        let both = "[values]\np = \"a\"\nr = \"a\"\n";

        let config = merge(&answered(both, &toggle_toml("~/.config/{{r}}/s"))).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(
                "; `~/.config/{{p}}/s` at local.toml:4 and `~/.config/{{q}}/s` at \
                 local.toml:7 still name one file once it is gone, because of the answer to \
                 `p` at local.toml:2, carried in by the default of `q` at bx.toml:4; change \
                 that answer too, or answer `q` directly"
            ),
            "{hint}"
        );

        // The act the clause names first does not part them: `q` follows `p`.
        assert!(
            !merge(&answered("[values]\np = \"b\"\nr = \"a\"\n", ""))
                .unwrap()
                .conflicts
                .is_empty(),
            "changing the answer to `p` moves both spellings together"
        );
        // The offer it would have withheld does.
        assert_eq!(
            loads(&answered("[values]\np = \"a\"\nq = \"b\"\nr = \"a\"\n", "")).len(),
            3,
            "`~/.zshrc` and the two entries, now two files"
        );
    }

    #[test]
    fn a_removal_hint_does_not_offer_to_answer_a_value_a_default_carries_an_answer_into() {
        // `q` is not answered: its committed `default` carries the answer to
        // `p` in. `answers_hint` would name that default and offer to answer
        // `q` directly. The removal hint does not (decision 6), and the reason
        // is the same as for the answer it already withholds: answering `q`
        // directly is an answer change, and under one the toggle names a file
        // no earlier layer declares, which fails the whole load.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                     [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{{{p}}}}\"\n\
                     {}{}",
                    target_toml("~/.config/default/s", "D"),
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let answered = |values: &str, toggles: &[&str]| {
            [
                base(),
                local(&format!(
                    "{values}{}",
                    toggles
                        .iter()
                        .map(|path| toggle_toml(path))
                        .collect::<String>()
                )),
            ]
        };
        let both = ["~/.config/default/s", "~/.config/{{q}}/s"];

        let config = merge(&answered("[values]\np = \"default\"\n", &both)).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(&format!(
                "because of the answer to `p` at local.toml:2; remove the toggle \
                 `~/.config/{{{{q}}}}/s` at local.toml:6{CANNOT_SHOW_ONE}"
            )),
            "{hint}"
        );
        assert!(!hint.contains("carried in by"), "{hint}");
        assert!(!hint.contains("answer `q` directly"), "{hint}");

        // What it does say loads.
        assert_eq!(
            loads(&answered("[values]\np = \"default\"\n", &both[..1])).len(),
            1,
            "only `~/.zshrc` is left"
        );
        // What it withholds does not: `q` answered directly strands the toggle.
        let message = failure(&answered(
            "[values]\np = \"default\"\nq = \"other\"\n",
            &both,
        ));
        assert!(
            message.contains("toggles `~/.config/{{q}}/s`, which no earlier layer declares"),
            "{message}"
        );
    }

    #[test]
    fn toggles_that_each_reach_a_target_only_through_an_answer_keep_one() {
        // `two_toggles_that_each_cancel_a_placeholder_meet_for_one_answer_only`'s
        // toggles. Neither is the declared spelling, so neither is the one to
        // keep: either is. With the target declared in an earlier layer the
        // two toggles are the whole clash, so keeping one clears it — and the
        // two disagree on `enabled`, so which one is kept decides whether the
        // target ships, which is what the hint says it does.
        const DECLS: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\n";
        let first = "[[target]]\npath = \"~/.config/{{p}}/../s\"\nenabled = false\n";
        let second = "[[target]]\npath = \"~/.config/{{q}}/../s\"\nenabled = true\n";
        let answers = || local("[values]\np = \"a\"\nq = \"b\"\n");
        let earlier = |toggles: &str| {
            [
                global(
                    "bx.toml",
                    &format!("{DECLS}{}", target_toml("~/.config/s", "S")),
                ),
                global("modules/10-toggles.toml", toggles),
                answers(),
            ]
        };

        let config = merge(&earlier(&format!("{first}{second}"))).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(hint.ends_with(CANNOT_SHOW_ANY), "{hint}");
        assert!(
            hint.starts_with(
                "`[[target]]` `~/.config/{{p}}/../s` at modules/10-toggles.toml:1 and \
                 `~/.config/{{q}}/../s` at modules/10-toggles.toml:4 name one file"
            ),
            "{hint}"
        );
        assert!(
            loads(&earlier(first)).is_empty(),
            "the kept toggle switched the one target off"
        );
        assert_eq!(
            loads(&earlier(second)),
            [(
                "~/.config/s".to_string(),
                crate::config::target::Body::Inline("S".to_string())
            )],
            "the other kept toggle leaves it on"
        );

        // In that test's own layout the target is declared beside the toggles,
        // so the full entry is in the clash too: keeping one toggle would leave
        // it clashing with the entry, and the hint names both toggles instead.
        let beside = |toggles: &str| {
            [
                global(
                    "bx.toml",
                    &format!("{DECLS}{}{toggles}", target_toml("~/.config/s", "S")),
                ),
                answers(),
            ]
        };
        let config = merge(&beside(&format!("{first}{second}"))).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(&format!(
                "; remove the toggles `~/.config/{{{{p}}}}/../s` at bx.toml:10 and \
                 `~/.config/{{{{q}}}}/../s` at bx.toml:13{CANNOT_SHOW_SEVERAL}"
            )),
            "{hint}"
        );
        assert_eq!(loads(&beside("")).len(), 1, "the entry alone loads");
        assert!(
            !merge(&beside(first)).unwrap().conflicts.is_empty(),
            "keeping one toggle beside the entry still clashes"
        );
    }

    #[test]
    fn a_toggle_pair_the_written_form_misses_gets_the_removal_hint() {
        // `~/.c/{{p}}x/../s` and `~/.c/{{p}}y/../s` name one file for every
        // answer, but the written form does not decide it: the pair is among
        // the known examples in the final statement of the forms the written
        // form does not decide, in pull request #16's review notes. So the
        // clash is not refused, and no answer clears it. The removal hint does
        // not rest on the form: keeping either toggle loads.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n{}{}",
                    target_toml("~/.c/s", "S"),
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let toggles = ["~/.c/{{p}}x/../s", "~/.c/{{p}}y/../s"];
        let answered = |answer: &str, toggles: &[&str]| {
            local(&format!(
                "[values]\np = \"{answer}\"\n{}",
                toggles
                    .iter()
                    .map(|path| toggle_toml(path))
                    .collect::<String>()
            ))
        };

        let config = merge(&[base(), answered("a", &toggles)]).unwrap();
        assert_eq!(config.conflicts.len(), 1, "{:#?}", config.conflicts);
        let hint = &config.conflicts[0].hint;
        assert!(
            hint.ends_with(&format!(
                "because of the answer to `p` at local.toml:2{CANNOT_SHOW_ANY}"
            )),
            "{hint}"
        );

        for kept in toggles {
            assert_eq!(
                loads(&[base(), answered("a", &[kept])]),
                [(
                    "~/.zshrc".to_string(),
                    crate::config::target::Body::Inline("setopt".to_string())
                )],
                "{kept}"
            );
        }
        let message = failure(&[base(), answered("a/b", &toggles)]);
        assert!(
            message.contains("which no earlier layer declares"),
            "{message}"
        );
    }

    #[test]
    fn a_toggle_clash_a_different_answer_clears_keeps_the_answer_hint() {
        // Every toggle here is one path as written with a declared spelling, so
        // an answer that parts the pair leaves both toggles naming declared
        // files. The second row spells the toggle unfolded and the third glues
        // a `path` value: only a comparison of written forms, not of text, sees
        // either as the declared spelling.
        let profile_targets = format!(
            "{PROFILE}{}{}{}",
            target_toml("~/.config/default/s", "D"),
            target_toml("~/.config/{{profile}}/s", "P"),
            target_toml("~/.zshrc", "setopt")
        );
        let path_targets = format!(
            "[[value]]\nname = \"r\"\nkind = \"path\"\n{}{}{}",
            target_toml("/opt/default/conf", "D"),
            target_toml("/opt/{{r}}/conf", "R"),
            target_toml("~/.zshrc", "setopt")
        );
        for (declared, name, clashing, clearing, toggles) in [
            (
                &profile_targets,
                "profile",
                "default",
                "other",
                ["~/.config/default/s", "~/.config/{{profile}}/s"],
            ),
            (
                &profile_targets,
                "profile",
                "default",
                "other",
                ["~/.config/default/s", "~/.config/{{profile}}/./s"],
            ),
            (
                &path_targets,
                "r",
                "/default",
                "/other",
                ["/opt/default/conf", "/opt{{r}}/conf"],
            ),
        ] {
            let layers = |answer: &str| {
                [
                    global("bx.toml", declared),
                    local(&format!(
                        "[values]\n{name} = \"{answer}\"\n{}",
                        toggles
                            .iter()
                            .map(|path| toggle_toml(path))
                            .collect::<String>()
                    )),
                ]
            };

            let config = merge(&layers(clashing))
                .unwrap_or_else(|e| panic!("{}: the merge failed: {e}", toggles[1]));
            assert!(!config.conflicts.is_empty(), "{}", toggles[1]);
            for conflict in &config.conflicts {
                assert!(
                    conflict.hint.ends_with(&format!(
                        "because of the answer to `{name}` at local.toml:2; change that answer"
                    )),
                    "{}: {}",
                    toggles[1],
                    conflict.hint
                );
            }

            assert_eq!(loads(&layers(clearing)).len(), 1, "{}", toggles[1]);
        }
    }

    #[test]
    fn a_clash_recorded_against_an_earlier_layer_keeps_its_answer_hint() {
        // A later layer's toggle that reaches the file only through the answer
        // changes nothing about the hint `bx.toml`'s own clash carries, whether
        // that later layer clashes itself or not.
        let base = || {
            global(
                "bx.toml",
                &format!(
                    "{PROFILE}{}{}{}",
                    target_toml("~/.config/default/s", "D"),
                    target_toml("~/.config/{{profile}}/s", "P"),
                    target_toml("~/.zshrc", "setopt")
                ),
            )
        };
        let committed = "`[[target]]` `~/.config/default/s` at bx.toml:4 and \
                         `~/.config/{{profile}}/s` at bx.toml:7 name one file, \
                         `~/.config/default/s`, and one layer may name a file once, because of \
                         the answer to `profile` at local.toml:2; change that answer";

        for (toggles, conflicts) in [
            (&["~/.config/{{profile}}x/../default/s"][..], 1),
            (
                &["~/.config/{{profile}}x/../default/s", "~/.config/default/s"][..],
                2,
            ),
        ] {
            let config = merge(&[base(), profile_toggles("default", toggles)]).unwrap();
            assert_eq!(config.conflicts.len(), conflicts, "{:#?}", config.conflicts);
            assert_eq!(config.conflicts[0].hint, committed, "{toggles:?}");
        }
    }
}
