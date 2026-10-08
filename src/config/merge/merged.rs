//! One keyed list, folded layer by layer.
//!
//! [`Keyed`] is what a list entry must say about itself to merge, and
//! [`Merged`] is the insertion-ordered fold every keyed list section shares: a
//! known key is replaced in place, a new key appends, and a toggle flips the
//! entry it names or fails naming the section.

use super::Toggle;
use crate::config::Error;
use crate::config::env::EnvDecl;
use crate::config::external::External;
use crate::config::path::PathEntry;
use crate::config::target::Target;
use crate::config::tool::ToolDecl;
use crate::config::values::ValueDecl;
use crate::shell::activation::ActivationDecl;
use crate::shell::alias::AliasDecl;
use crate::shell::function::FunctionDecl;
use crate::shell::plugin::PluginDecl;
use crate::shell::source::SourceDecl;

/// A list entry that merges by a natural key.
///
/// Implemented by every keyed list type. The natural-key table in the
/// architecture specification is the whole contract, so a later entry that adds
/// a list type implements this and writes no merge logic of its own.
pub trait Keyed {
    /// The natural key: `path` for a target, `name` for a value.
    ///
    /// As written. A target is merged by the file this names once substituted,
    /// which is not a function of the entry alone; see [`merge`](super::merge).
    fn key(&self) -> &str;
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
    // Unreachable from `merge`, which keeps disabled declarations with
    // `into_entries`; kept because `Keyed` requires it of a public list type.
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for EnvDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for AliasDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for FunctionDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for PluginDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for SourceDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for ActivationDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for ToolDecl {
    fn key(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for External {
    /// The checkout's directory, as its one normalised spelling. Nothing in
    /// an external is substituted, so the path written is the directory.
    fn key(&self) -> &str {
        self.path.as_str()
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Keyed for PathEntry {
    /// The directory as zsh is given it, so two spellings of one directory
    /// are one entry.
    fn key(&self) -> &str {
        &self.shell
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    // Unreachable from `merge`: a `[path]` entry is switched off by restating
    // it with `enabled = false`, never by a toggle; kept because `Keyed`
    // requires it of a public list type.
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
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
    pub(super) entries: Vec<(K, T)>,
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
    pub(super) fn position(&self, key: &K) -> Option<usize> {
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
pub(super) fn unknown_toggle(toggle: &Toggle, more: &str) -> Error {
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

#[cfg(test)]
mod tests {
    use super::super::tests::{failure, global, home, local, merge, paths, target_toml};
    use crate::config::parse_str;
    use crate::config::toggle::Section;
    use std::path::Path;

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
            (Section::Env, "env", "[[env]]", "name"),
            (Section::Alias, "alias", "[[alias]]", "name"),
            (Section::Function, "function", "[[function]]", "name"),
            (Section::Plugin, "plugin", "[[plugin]]", "name"),
            (Section::Source, "source", "[[source]]", "name"),
            (Section::Activation, "activation", "[[activation]]", "name"),
            (Section::Tool, "tool", "[[tool]]", "name"),
            (Section::External, "external", "[[external]]", "path"),
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
}
