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
//! The merge is a pure function of the layer files' bytes. It reads no
//! environment variable, calls no `canonicalize`, spawns nothing, and iterates
//! no hash map: entries live in a `Vec` in insertion order and lookup is a
//! linear scan. Invariant 3 says two `plan` runs a week apart on an unchanged
//! tree are byte-identical, and an entry order that came from a hash would make
//! that false in a way no reviewer could see.

use std::path::Path;

use toml_edit::Table;

use super::target::Target;
use super::values::{ValueAssignment, ValueDecl};
use super::{Config, Ctx, Error, Layer, LayerKind, Origin};

/// A list entry that merges by a natural key.
///
/// Implemented by every keyed list type. The natural-key table in the
/// architecture specification is the whole contract, so a later entry that adds
/// a list type implements this and writes no merge logic of its own.
pub trait Keyed {
    /// The natural key: `path` for a target, `name` for a value.
    fn key(&self) -> &str;
    /// The layer and line that last set this entry.
    fn origin(&self) -> &Origin;
    /// Whether the entry survives into the resolved configuration.
    fn enabled(&self) -> bool;
    /// Flip the flag, as a toggle does.
    fn set_enabled(&mut self, enabled: bool);
}

impl Keyed for Target {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged<T> {
    entries: Vec<T>,
}

impl<T> Default for Merged<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T: Keyed> Merged<T> {
    /// Fold one later layer's entries in.
    ///
    /// A known key is replaced **wholesale and in place**; a new key appends.
    pub fn absorb(&mut self, later: impl IntoIterator<Item = T>) {
        for entry in later {
            match self.position(entry.key()) {
                Some(index) => self.entries[index] = entry,
                None => self.entries.push(entry),
            }
        }
    }

    /// Apply one toggle.
    ///
    /// # Errors
    ///
    /// [`Error::BadValue`] when no earlier layer introduced the key. A silent
    /// no-op here is how an account ends up with a file it explicitly refused.
    pub fn toggle(&mut self, toggle: &Toggle) -> Result<(), Error> {
        let Some(index) = self.position(&toggle.key) else {
            // Both readings, because nothing here can tell them apart: a table
            // holding only the natural key and `enabled` is a toggle wherever it
            // appears, so in the first layer an entry somebody meant to write in
            // full and left incomplete arrives here too.
            return Err(Error::BadValue {
                origin: toggle.origin.clone(),
                message: format!(
                    "`{}` toggles `{}`, which no earlier layer declares; a toggle — an \
                     entry with only `{}` and `enabled` — may only flip an entry that \
                     already exists, and a new entry needs {}",
                    toggle.section.header(),
                    toggle.key,
                    toggle.section.natural_key(),
                    toggle.section.a_full_entry_needs(),
                ),
            });
        };
        self.entries[index].set_enabled(toggle.enabled);
        Ok(())
    }

    /// The entries that survive, in order.
    ///
    /// Disabled entries stay in the list until this point, so a disable in one
    /// layer followed by a re-enable in a later one keeps the original position.
    #[must_use]
    pub fn into_enabled(self) -> Vec<T> {
        self.entries.into_iter().filter(Keyed::enabled).collect()
    }

    /// Every entry, disabled ones included, in order.
    ///
    /// For a list whose entries are referred to **by name** from elsewhere in
    /// the configuration. Dropping a disabled one would make a reference to it
    /// indistinguishable from a reference to a name no layer ever declared,
    /// which is a different fault with a different outcome.
    #[must_use]
    pub fn into_entries(self) -> Vec<T> {
        self.entries
    }

    /// Where `key` sits, if it is present.
    fn position(&self, key: &str) -> Option<usize> {
        self.entries.iter().position(|entry| entry.key() == key)
    }
}

/// Fold the ordered layer set into one configuration.
///
/// The result is one of the base's own `Config` values, still **unresolved**: no
/// value is checked against its kind and no `{{name}}` is substituted, which is
/// [`super::resolve`]'s work.
///
/// # Errors
///
/// [`Error::BadValue`] when a committed layer carries a `[values]` table, or
/// when a toggle names a key no earlier layer introduced.
pub fn merge(layers: &[Layer]) -> Result<Config, Error> {
    let mut targets: Merged<Target> = Merged::default();
    let mut values: Merged<ValueDecl> = Merged::default();
    let mut assignments: Vec<ValueAssignment> = Vec::new();

    for layer in layers {
        refuse_committed_answers(layer)?;

        targets.absorb(layer.config.targets.iter().cloned());
        values.absorb(layer.config.values.iter().cloned());

        for toggle in &layer.config.toggles {
            // Exhaustive over `Section`, so a keyed list added later is a
            // compile error here rather than a panic in a library call.
            match toggle.section {
                Section::Target => targets.toggle(toggle)?,
                Section::Value => values.toggle(toggle)?,
            }
        }

        for assignment in &layer.config.value_assignments {
            assign(&mut assignments, assignment.clone());
        }
    }

    Ok(Config {
        targets: targets.into_enabled(),
        // Values keep their disabled entries and targets do not, and the
        // asymmetry is the point: nothing refers to a target except by being
        // one, so a disabled target simply is not written. A value is referred
        // to by name from every string field in the configuration, so a
        // declaration an account switched off has to stay visible to resolution
        // — otherwise `{{git_email}}` reads as a repo typo, which is fatal, and
        // the three-line toggle an account is invited to write stops the whole
        // load with a message naming a committed file it cannot edit.
        values: values.into_entries(),
        value_assignments: assignments,
        // Consumed above; a merged configuration has no toggles left to apply.
        toggles: Vec::new(),
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
        for (name, source) in [
            ("layers.rs", include_str!("layers.rs")),
            ("merge.rs", include_str!("merge.rs")),
            ("values.rs", include_str!("values.rs")),
            ("resolve.rs", include_str!("resolve.rs")),
            ("values/local.rs", include_str!("values/local.rs")),
        ] {
            // The non-test half, minus its prose. This very test names the
            // strings it forbids, and `layers.rs` documents what the *binary*
            // passes in by naming the call the library itself may not make — a
            // textual scan cannot tell a description from a call, so whole-line
            // comments are dropped and code is what is scanned.
            let body: String = source
                .split("#[cfg(test)]")
                .next()
                .expect("the non-test half")
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
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
