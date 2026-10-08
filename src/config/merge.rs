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
//! answer's. A later layer's full entry for the file settles it; a later
//! toggle does not, and leaves the conflict recorded. When a toggle among
//! the statements cannot be shown to name a declared target for every answer —
//! its spelling is not one path as written with a full entry's in its own layer
//! or an earlier one — another answer may leave it naming a file nothing
//! declares, which fails the load, so the hint names that toggle to remove
//! rather than the answer to change — and then the answer to change anyway,
//! when removing it leaves two or more statements still naming the one file.
//!
//! # Shapes the written form does not decide
//!
//! This is what `written_form`, `one_path_as_written` and `Root`, in
//! [`written_form`], point at. It is here, in the tree, rather than in a review
//! thread, so that a maintainer changing the reduction reads the limitation
//! beside the code it limits, and so that it outlives whatever tracker entry
//! carried it.
//!
//! **What holds.** The form is *sound*: two spellings with one form name one
//! file for every answer, or no file for any. It is *complete over the shapes
//! the fixed-seed property test generates* — there, two spellings with
//! different forms are parted by some answer in the set, so the collision is
//! one the account can clear.
//!
//! **What does not hold.** The form does not recognise every pair that names
//! one file for every answer. When it misses one, a layer that spells the same
//! file twice loads `Ok` and the file is blocked as a [`Conflict`] that no
//! answer clears. Because the form cannot anchor such a toggle to a declared
//! spelling, the conflict's hint names the toggles to remove rather than an
//! answer to change. **No general rule is claimed
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

mod merged;
mod target_key;
mod written_form;

use std::path::Path;

use super::env::EnvDecl;
use super::external::External;
use super::history::History;
use super::path::PathEntry;
use super::secrets::Secrets;
use super::shell_options::ShellOptions;
use super::target::Target;
use super::tool::ToolDecl;
use super::values::{ResolvedValues, ValueAssignment, ValueDecl};
use super::{Config, Error, Layer, LayerKind};
use crate::shell::activation::ActivationDecl;
use crate::shell::alias::AliasDecl;
use crate::shell::function::FunctionDecl;
use crate::shell::keybindings::Keybindings;
use crate::shell::plugin::{self, PluginDecl};
use crate::shell::source::SourceDecl;

/// The toggle vocabulary, defined in [`super::toggle`] where a layer is
/// parsed, and named here too, where the merge applies it.
pub use super::toggle::{Section, Toggle};
/// The list-merge vocabulary, defined in [`merged`] and named here too, where
/// every keyed list section is folded.
pub use merged::{Keyed, Merged};
/// A file one layer names twice because of this account's answers, defined in
/// [`target_key`] and named here too, where resolution reads it off the merge.
pub(crate) use target_key::Conflict;
use target_key::{Clash, TargetKey};

/// Fold the ordered layer set into one configuration.
///
/// The result is one of the base's own `Config` values, still **unresolved**:
/// every entry is returned as written, and substituting it is
/// [`super::resolve`]'s work. The values are resolved once here, against
/// `home`, only so that a target can be keyed by the file it names.
///
/// # Errors
///
/// [`Error::BadValue`] when a committed layer carries a `[values]` table or a
/// `[secrets]` `identity`, when `local.toml` carries a `[secrets]`
/// `recipients` list, when a toggle names a key no earlier layer introduced,
/// when one layer names one file twice with no account answer in either
/// spelling or under two spellings that are one path before any answer goes
/// in, when two enabled
/// plugins claim the terminal slot ([`plugin::check_terminal`]), or for any
/// defect [`ResolvedValues::resolve`] reports. The same collision with an answer in it
/// is not an error; it is carried to [`super::resolve`] as a [`Conflict`].
pub fn merge(layers: &[Layer], home: &Path) -> Result<Config, Error> {
    let mut values: Merged<ValueDecl> = Merged::default();
    let mut assignments: Vec<ValueAssignment> = Vec::new();
    let mut envs: Merged<EnvDecl> = Merged::default();
    let mut path: Merged<PathEntry> = Merged::default();
    let mut aliases: Merged<AliasDecl> = Merged::default();
    let mut functions: Merged<FunctionDecl> = Merged::default();
    let mut plugins: Merged<PluginDecl> = Merged::default();
    let mut sources: Merged<SourceDecl> = Merged::default();
    let mut activations: Merged<ActivationDecl> = Merged::default();
    let mut tools: Merged<ToolDecl> = Merged::default();
    let mut externals: Merged<External> = Merged::default();
    let mut secrets = Secrets::default();
    let mut history = History::default();
    let mut shell_options = ShellOptions::default();
    let mut keybindings = Keybindings::default();

    // Values first, across every layer. A value never depends on a target, and
    // a target's key depends on the values — the final ones, because the file a
    // target is written to is decided by the answers this account ends up with,
    // not by the answers known when its own layer was read.
    //
    // An `[[env]]` entry is keyed by its name as written, which no answer can
    // change, so it folds here beside the values; so does a `[path]` entry,
    // keyed by its directory, which holds no placeholder; and so does an
    // alias, keyed by its name, whichever of its two tables it is written in;
    // and so does a function, keyed by its name, whose body's placeholders are
    // substituted only once the values are final; and so does a plugin, keyed
    // by its name, which holds no placeholder; and so does a declared optional
    // source, keyed by its name, whose path is substituted only once the
    // values are final; and so does a tool activation, keyed by its name,
    // which holds no placeholder; and so does an external, keyed by its path,
    // which holds no placeholder; and so does a declared tool, keyed by its
    // name, which holds no placeholder either.
    for layer in layers {
        refuse_committed_answers(layer)?;
        refuse_misplaced_secrets(layer)?;
        secrets.absorb(&layer.config.secrets);
        // These tables hold no placeholder, so they fold here too, key by key.
        history.absorb(&layer.config.history);
        shell_options.absorb(&layer.config.shell_options);
        keybindings.absorb(&layer.config.keybindings);

        values.absorb(layer.config.values.iter().cloned());
        envs.absorb(layer.config.envs.iter().cloned());
        path.absorb(layer.config.path.iter().cloned());
        aliases.absorb(layer.config.aliases.iter().cloned());
        functions.absorb(layer.config.functions.iter().cloned());
        plugins.absorb(layer.config.plugins.iter().cloned());
        sources.absorb(layer.config.sources.iter().cloned());
        activations.absorb(layer.config.activations.iter().cloned());
        tools.absorb(layer.config.tools.iter().cloned());
        externals.absorb(layer.config.externals.iter().cloned());

        for toggle in &layer.config.toggles {
            // Exhaustive over `Section`, so a keyed list added later is a
            // compile error here rather than a panic in a library call.
            match toggle.section {
                Section::Value => values.toggle(toggle)?,
                Section::Env => envs.toggle(toggle)?,
                Section::Alias => aliases.toggle(toggle)?,
                Section::Function => functions.toggle(toggle)?,
                Section::Plugin => plugins.toggle(toggle)?,
                Section::Source => sources.toggle(toggle)?,
                Section::Activation => activations.toggle(toggle)?,
                Section::Tool => tools.toggle(toggle)?,
                Section::External => externals.toggle(toggle)?,
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
    // Over the plugins the layers left enabled, so a claim a later layer
    // switched off does not count, and before anything else is resolved: two
    // terminal claimants are a defect in the configuration as a whole.
    let plugins = plugins.into_enabled();
    plugin::check_terminal(&plugins)?;

    let values = values.into_entries();
    let resolved = ResolvedValues::resolve(values.clone(), &assignments, home)?;

    let mut targets: Merged<Target, TargetKey> = Merged::default();
    let mut clashes: Vec<Clash> = Vec::new();
    // Built as the fold goes rather than sliced by index: what a toggle may be
    // judged against is the layers already folded, and a layer only enters this
    // list once it has been.
    let mut folded: Vec<&Layer> = Vec::with_capacity(layers.len());
    for layer in layers {
        targets.absorb_layer(layer, &folded, &resolved, &mut clashes)?;
        folded.push(layer);
    }

    Ok(Config {
        targets: targets.into_enabled(),
        // A tree is expanded as its layer is loaded, into the targets above;
        // what the merge folds has none left.
        trees: Vec::new(),
        // Nothing refers to an external by its path, so a disabled one is
        // simply not checked out, as a disabled target is not written.
        externals: externals.into_enabled(),
        values,
        value_assignments: assignments,
        // Nothing refers to a variable by name, so a disabled one is simply
        // not placed, as a disabled target is not written.
        envs: envs.into_enabled(),
        // Nothing refers to a `[path]` entry either.
        path: path.into_enabled(),
        // Nor to an alias.
        aliases: aliases.into_enabled(),
        // Nor to a function.
        functions: functions.into_enabled(),
        // Nor to a plugin.
        plugins,
        // Nor to a declared optional source.
        sources: sources.into_enabled(),
        // Nor to a tool activation.
        activations: activations.into_enabled(),
        // Nor to a declared tool.
        tools: tools.into_enabled(),
        secrets,
        history,
        shell_options,
        keybindings,
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

/// Refuse a `[secrets]` key in the layer that may not hold it: an `identity`
/// in a committed layer, or a `recipients` list in `local.toml`.
///
/// An identity names a private key on this machine, which is account content,
/// and Invariant 5 keeps that out of a publishable tree. A recipient list is
/// the repo's: an account that encrypted to a list only its own `local.toml`
/// held would produce secrets no other account can be sure it can open.
fn refuse_misplaced_secrets(layer: &Layer) -> Result<(), Error> {
    let secrets = &layer.config.secrets;
    match layer.kind {
        LayerKind::Global => secrets.identity.as_ref().map_or(Ok(()), |identity| {
            Err(Error::BadValue {
                origin: identity.origin.clone(),
                message: "a committed layer may not name an identity: it is a private key on \
                          one machine, so `identity` belongs under [secrets] in local.toml in \
                          the state directory. Nothing account-specific is ever committed"
                    .to_string(),
            })
        }),
        LayerKind::Local => secrets.recipients.as_ref().map_or(Ok(()), |recipients| {
            Err(Error::BadValue {
                origin: recipients.origin.clone(),
                message: "local.toml may not list recipients: every account's secrets are \
                          encrypted to the one list the config repo commits, so `recipients` \
                          belongs under [secrets] in bx.toml or a module"
                    .to_string(),
            })
        }),
    }
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
    pub(super) fn home() -> PathBuf {
        PathBuf::from("/var/home/example")
    }

    /// The merge, against the fixtures' home.
    pub(super) fn merge(layers: &[Layer]) -> Result<Config, Error> {
        super::merge(layers, &home())
    }

    /// A layer parsed from `text`, named `file`.
    pub(super) fn layer(file: &str, kind: LayerKind, text: &str) -> Layer {
        Layer {
            file: PathBuf::from(file),
            kind,
            config: parse_str(text, Path::new(file), &home())
                .unwrap_or_else(|e| panic!("{file}: {e}")),
        }
    }

    /// A committed global layer.
    pub(super) fn global(file: &str, text: &str) -> Layer {
        layer(file, LayerKind::Global, text)
    }

    /// The account's own layer.
    pub(super) fn local(text: &str) -> Layer {
        layer("local.toml", LayerKind::Local, text)
    }

    /// A `[[target]]` with a one-line inline body.
    pub(super) fn target_toml(path: &str, body: &str) -> String {
        format!("[[target]]\npath = \"{path}\"\ncontent = \"{body}\"\n")
    }

    /// The merged target paths, in order.
    pub(super) fn paths(config: &Config) -> Vec<&str> {
        config.targets.iter().map(|t| t.path.as_str()).collect()
    }

    /// The merge's error message.
    pub(super) fn failure(layers: &[Layer]) -> String {
        merge(layers)
            .expect_err("should have been refused")
            .to_string()
    }

    /// An `[[env]]` entry.
    fn env_toml(name: &str, value: &str, kind: &str) -> String {
        format!("[[env]]\nname = \"{name}\"\nvalue = \"{value}\"\nkind = \"{kind}\"\n")
    }

    #[test]
    fn env_entries_merge_by_name_and_a_toggle_removes_one() {
        let merged = merge(&[
            global(
                "bx.toml",
                &format!(
                    "{}{}{}",
                    env_toml("LANG", "C", "environment"),
                    env_toml("EDITOR", "vi", "interactive"),
                    env_toml("PAGER", "less", "login")
                ),
            ),
            global("modules/a.toml", &env_toml("LANG", "C.UTF-8", "gui")),
            local("[[env]]\nname = \"EDITOR\"\nenabled = false\n"),
        ])
        .unwrap();
        let envs: Vec<(&str, &str, &Path)> = merged
            .envs
            .iter()
            .map(|e| (e.name.as_str(), e.value.as_str(), e.origin.file.as_path()))
            .collect();
        assert_eq!(
            envs,
            vec![
                ("LANG", "C.UTF-8", Path::new("modules/a.toml")),
                ("PAGER", "less", Path::new("bx.toml")),
            ]
        );
        assert_eq!(merged.envs[0].kind, crate::config::env::EnvKind::Gui);
    }

    #[test]
    fn an_env_toggle_that_names_nothing_is_refused() {
        let message = failure(&[
            global("bx.toml", &env_toml("LANG", "C", "gui")),
            local("[[env]]\nname = \"PAGER\"\nenabled = false\n"),
        ]);
        assert!(message.contains("PAGER"), "{message}");
        assert!(message.contains("a `value` and a `kind`"), "{message}");
    }

    #[test]
    fn aliases_merge_by_name_across_both_tables_and_a_toggle_flips_one() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[aliases]\nll = \"ls -la\"\ngs = \"git status\"\n\
                 [[alias]]\nname = \"cat\"\ncommand = \"bat\"\nwhen = \"has:bat\"\nenabled = false\n",
            ),
            // A flat entry replaces a conditional one in place, and the reverse.
            global(
                "modules/a.toml",
                "[aliases]\ncat = \"batcat\"\n\
                 [[alias]]\nname = \"ll\"\ncommand = \"eza -l\"\nwhen = \"has:eza\"\n",
            ),
            local(
                "[[alias]]\nname = \"gs\"\nenabled = false\n\
                 [[alias]]\nname = \"cat\"\nenabled = true\n",
            ),
        ])
        .unwrap();
        let aliases: Vec<(&str, &str, bool, &Path)> = merged
            .aliases
            .iter()
            .map(|a| {
                (
                    a.name.as_str(),
                    a.command.as_str(),
                    a.when.is_some(),
                    a.origin.file.as_path(),
                )
            })
            .collect();
        assert_eq!(
            aliases,
            vec![
                ("ll", "eza -l", true, Path::new("modules/a.toml")),
                ("cat", "batcat", false, Path::new("modules/a.toml")),
            ]
        );

        let message = failure(&[
            global("bx.toml", "[aliases]\nll = \"ls -la\"\n"),
            local("[[alias]]\nname = \"la\"\nenabled = false\n"),
        ]);
        assert!(message.contains("`la`"), "{message}");
        assert!(message.contains("a `command`"), "{message}");
    }

    #[test]
    fn functions_merge_by_name_and_a_toggle_flips_one() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[function]]\nname = \"a\"\nbody = \"one\"\n\
                 [[function]]\nname = \"b\"\nbody = \"two\"\n\
                 [[function]]\nname = \"c\"\nbody = \"three\"\nhook = \"chpwd\"\nenabled = false\n\
                 shells = [\"zsh\"]\n",
            ),
            global(
                "modules/m.toml",
                "[[function]]\nname = \"a\"\nbody = \"replaced\"\nhook = \"precmd\"\n\
                 shells = [\"zsh\"]\n",
            ),
            local(
                "[[function]]\nname = \"b\"\nenabled = false\n\
                 [[function]]\nname = \"c\"\nenabled = true\n",
            ),
        ])
        .unwrap();
        let functions: Vec<(&str, &str, &Path)> = merged
            .functions
            .iter()
            .map(|f| (f.name.as_str(), f.body.as_str(), f.origin.file.as_path()))
            .collect();
        assert_eq!(
            functions,
            vec![
                ("a", "replaced", Path::new("modules/m.toml")),
                ("c", "three", Path::new("bx.toml")),
            ]
        );

        let message = failure(&[
            global("bx.toml", "[[function]]\nname = \"a\"\nbody = \"one\"\n"),
            local("[[function]]\nname = \"z\"\nenabled = true\n"),
        ]);
        assert!(message.contains("`z`"), "{message}");
        assert!(message.contains("a `body`"), "{message}");
    }

    #[test]
    fn plugins_merge_by_name_and_a_toggle_flips_one() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[plugin]]\nname = \"a\"\nsource = \"~/a.zsh\"\n\
                 [[plugin]]\nname = \"b\"\nsource = \"~/b.zsh\"\n\
                 [[plugin]]\nname = \"c\"\nsource = \"~/c.zsh\"\nenabled = false\n",
            ),
            global(
                "modules/m.toml",
                "[[plugin]]\nname = \"a\"\nsource = \"/usr/share/a.zsh\"\nterminal = true\n",
            ),
            local(
                "[[plugin]]\nname = \"b\"\nenabled = false\n\
                 [[plugin]]\nname = \"c\"\nenabled = true\n",
            ),
        ])
        .unwrap();
        let plugins: Vec<(&str, &str, bool, &Path)> = merged
            .plugins
            .iter()
            .map(|p| {
                (
                    p.name.as_str(),
                    p.source.as_str(),
                    p.terminal,
                    p.origin.file.as_path(),
                )
            })
            .collect();
        assert_eq!(
            plugins,
            vec![
                ("a", "/usr/share/a.zsh", true, Path::new("modules/m.toml")),
                ("c", "~/c.zsh", false, Path::new("bx.toml")),
            ]
        );

        let message = failure(&[
            global(
                "bx.toml",
                "[[plugin]]\nname = \"a\"\nsource = \"~/a.zsh\"\n",
            ),
            local("[[plugin]]\nname = \"z\"\nenabled = true\n"),
        ]);
        assert!(message.contains("`z`"), "{message}");
        assert!(message.contains("a `source`"), "{message}");
    }

    /// One `[[external]]` entry, as TOML.
    fn external(path: &str, url: &str, rev: char) -> String {
        format!(
            "[[external]]\npath = \"{path}\"\nurl = \"{url}\"\nrev = \"{}\"\n",
            rev.to_string().repeat(40)
        )
    }

    #[test]
    fn externals_merge_by_path_and_a_toggle_flips_one() {
        let merged = merge(&[
            global(
                "bx.toml",
                &format!(
                    "{}{}{}enabled = false\n",
                    external("~/a", "https://h/o/a", 'a'),
                    external("~/b", "https://h/o/b", 'b'),
                    external("~/c", "https://h/o/c", 'c'),
                ),
            ),
            // Replaced wholesale and in place, by another spelling of the path.
            global("modules/m.toml", &external("~/./a", "git@h:o/fork", 'f')),
            local(
                "[[external]]\npath = \"~/b/\"\nenabled = false\n\
                 [[external]]\npath = \"~/c\"\nenabled = true\n",
            ),
        ])
        .unwrap();
        let externals: Vec<(&str, &str, &str, &Path)> = merged
            .externals
            .iter()
            .map(|e| {
                (
                    e.path.as_str(),
                    e.url.as_str(),
                    &e.rev[..1],
                    e.origin.file.as_path(),
                )
            })
            .collect();
        assert_eq!(
            externals,
            vec![
                ("~/a", "git@h:o/fork", "f", Path::new("modules/m.toml")),
                ("~/c", "https://h/o/c", "c", Path::new("bx.toml")),
            ]
        );

        let message = failure(&[
            global("bx.toml", &external("~/a", "https://h/o/a", 'a')),
            local("[[external]]\npath = \"~/z\"\nenabled = true\n"),
        ]);
        assert!(message.contains("`~/z`"), "{message}");
        assert!(message.contains("a `url` and a `rev`"), "{message}");
    }

    #[test]
    fn one_layer_may_not_name_an_external_twice_even_as_a_toggle() {
        for text in [
            format!(
                "{}{}",
                external("~/a", "https://h/o/a", 'a'),
                external("~/a/.", "https://h/o/b", 'b')
            ),
            format!(
                "{}[[external]]\npath = \"~/a\"\nenabled = false\n",
                external("~/a", "https://h/o/a", 'a')
            ),
        ] {
            let err = parse_str(&text, Path::new("bx.toml"), &home())
                .expect_err("one directory, twice")
                .to_string();
            assert!(err.contains("duplicate external `~/a`"), "{err}");
        }

        let err = parse_str(
            "[[external]]\npath = \"/opt/a\"\nenabled = false\n",
            Path::new("local.toml"),
            &home(),
        )
        .expect_err("a toggle's path is held to the entry's rule")
        .to_string();
        assert!(err.starts_with("local.toml:1: "), "{err}");
        assert!(err.contains("beneath the home"), "{err}");
    }

    #[test]
    fn sources_merge_by_name_and_a_toggle_flips_one() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[source]]\nname = \"a\"\npath = \"~/a\"\n\
                 [[source]]\nname = \"b\"\npath = \"~/b\"\n\
                 [[source]]\nname = \"c\"\npath = \"~/c\"\nenabled = false\n",
            ),
            global(
                "modules/m.toml",
                "[[source]]\nname = \"a\"\npath = \"/opt/a\"\nphase = \"options\"\n",
            ),
            local(
                "[[source]]\nname = \"b\"\nenabled = false\n\
                 [[source]]\nname = \"c\"\nenabled = true\n",
            ),
        ])
        .unwrap();
        let sources: Vec<(&str, &str, &str, &Path)> = merged
            .sources
            .iter()
            .map(|s| {
                (
                    s.name.as_str(),
                    s.path.as_str(),
                    s.phase.name(),
                    s.origin.file.as_path(),
                )
            })
            .collect();
        assert_eq!(
            sources,
            vec![
                ("a", "/opt/a", "options", Path::new("modules/m.toml")),
                ("c", "~/c", "plugins", Path::new("bx.toml")),
            ]
        );

        let message = failure(&[
            global("bx.toml", "[[source]]\nname = \"a\"\npath = \"~/a\"\n"),
            local("[[source]]\nname = \"z\"\nenabled = true\n"),
        ]);
        assert!(message.contains("`z`"), "{message}");
        assert!(message.contains("a `path`"), "{message}");
    }

    #[test]
    fn activations_merge_by_name_and_a_toggle_flips_one() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[[activation]]\nname = \"mise\"\ncommand = [\"mise\", \"activate\", \"zsh\"]\n\
                 [[activation]]\nname = \"starship\"\ncommand = [\"starship\", \"init\", \"zsh\"]\n\
                 [[activation]]\nname = \"zoxide\"\ncommand = [\"zoxide\", \"init\", \"zsh\"]\n\
                 enabled = false\n",
            ),
            global(
                "modules/m.toml",
                "[[activation]]\nname = \"mise\"\ncommand = [\"/opt/mise\", \"activate\", \"zsh\"]\n\
                 phase = \"completions\"\n",
            ),
            local(
                "[[activation]]\nname = \"starship\"\nenabled = false\n\
                 [[activation]]\nname = \"zoxide\"\nenabled = true\n",
            ),
        ])
        .unwrap();
        let activations: Vec<(&str, &str, &str, &Path)> = merged
            .activations
            .iter()
            .map(|a| {
                (
                    a.name.as_str(),
                    a.command[0].as_str(),
                    a.phase.name(),
                    a.origin.file.as_path(),
                )
            })
            .collect();
        assert_eq!(
            activations,
            vec![
                (
                    "mise",
                    "/opt/mise",
                    "completions",
                    Path::new("modules/m.toml")
                ),
                ("zoxide", "zoxide", "activations", Path::new("bx.toml")),
            ]
        );

        let message = failure(&[
            global(
                "bx.toml",
                "[[activation]]\nname = \"a\"\ncommand = [\"a\"]\n",
            ),
            local("[[activation]]\nname = \"z\"\nenabled = true\n"),
        ]);
        assert!(message.contains("`z`"), "{message}");
        assert!(message.contains("a `command`"), "{message}");
    }

    #[test]
    fn a_second_terminal_claimant_fails_the_merge_unless_a_layer_switches_one_off() {
        let claimants = "[[plugin]]\nname = \"zsh-syntax-highlighting\"\n\
                         source = \"~/zsh/zsh-syntax-highlighting.zsh\"\nterminal = true\n";
        let second = "[[plugin]]\nname = \"fast-syntax-highlighting\"\n\
                      source = \"~/zsh/fast-syntax-highlighting.zsh\"\nterminal = true\n";

        // Across two layers, and named by both with the first one's origin.
        let message = failure(&[
            global("bx.toml", claimants),
            global("modules/m.toml", second),
        ]);
        assert!(message.starts_with("modules/m.toml:1: "), "{message}");
        assert!(
            message.contains("plugin `fast-syntax-highlighting` claims the terminal slot"),
            "{message}"
        );
        assert!(
            message.contains("plugin `zsh-syntax-highlighting` already claims at bx.toml:1"),
            "{message}"
        );

        // A later layer switching either claim off settles it.
        let merged = merge(&[
            global("bx.toml", claimants),
            global("modules/m.toml", second),
            local("[[plugin]]\nname = \"zsh-syntax-highlighting\"\nenabled = false\n"),
        ])
        .expect("one claimant is left");
        assert_eq!(merged.plugins.len(), 1);
        assert_eq!(merged.plugins[0].name, "fast-syntax-highlighting");
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
    fn values_in_the_local_layer_are_kept_as_answered() {
        let merged = merge(&[local("[values]\ngit_email = \"someone@example.invalid\"\n")])
            .expect("a local answer is accepted");
        let answers: Vec<(&str, String, &Path)> = merged
            .value_assignments
            .iter()
            .map(|a| {
                (
                    a.name.as_str(),
                    a.value.to_string(),
                    a.origin.file.as_path(),
                )
            })
            .collect();
        assert_eq!(
            answers,
            [(
                "git_email",
                "someone@example.invalid".to_string(),
                Path::new("local.toml")
            )],
            "the local layer's answer is the one kept, named by its file"
        );
    }

    const RECIPIENTS: &str = "[secrets]\nrecipients = [\"ssh-ed25519 AAAAC3Nz one\"]\n";

    #[test]
    fn an_identity_in_a_committed_layer_is_an_error() {
        let message = failure(&[global("bx.toml", "[secrets]\nidentity = \"~/.ssh/id\"\n")]);
        assert!(message.starts_with("bx.toml:2:"), "{message}");
        assert!(message.contains("may not name an identity"), "{message}");
        assert!(message.contains("local.toml"), "{message}");

        let message = failure(&[
            global("bx.toml", RECIPIENTS),
            global("modules/k.toml", "[secrets]\nidentity = \"~/.ssh/id\"\n"),
        ]);
        assert!(message.starts_with("modules/k.toml:2:"), "{message}");
    }

    #[test]
    fn recipients_in_the_local_layer_are_an_error() {
        let message = failure(&[local(RECIPIENTS)]);
        assert!(message.contains("may not list recipients"), "{message}");
        assert!(message.contains("bx.toml or a module"), "{message}");
    }

    #[test]
    fn each_secrets_key_merges_from_its_own_layer() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[secrets]\nrecipients = [\"ssh-ed25519 AAAAC3Nz old\"]\n",
            ),
            global("modules/k.toml", RECIPIENTS),
            local("[secrets]\nidentity = \"~/.config/age/key.txt\"\n"),
        ])
        .expect("merges");

        let recipients = merged.secrets.recipients.expect("recipients");
        assert_eq!(
            recipients.keys,
            ["ssh-ed25519 AAAAC3Nz one"],
            "the later layer wins"
        );
        assert_eq!(recipients.origin.file, Path::new("modules/k.toml"));
        assert_eq!(
            merged.secrets.identity.expect("an identity").path.as_str(),
            "~/.config/age/key.txt"
        );
    }

    #[test]
    fn history_and_shell_options_merge_key_by_key_the_last_layer_winning() {
        let merged = merge(&[
            global(
                "bx.toml",
                "[history]\nsize = 10000\nshare = true\n[history.file]\nzsh = \"~/.zsh_history\"\n\
                 [shell-options]\nhistappend = true\ncheckwinsize = true\n",
            ),
            global("modules/k.toml", "[history]\nsize = 500\n"),
            local(
                "[history.file]\nbash = \"~/.bash_history\"\n[shell-options]\nhistappend = false\n",
            ),
        ])
        .expect("merges");

        let history = merged.history;
        assert_eq!(history.size, Some(500), "the later layer wins");
        assert_eq!(
            history.share,
            Some(true),
            "a key no later layer sets is kept"
        );
        assert_eq!(
            history
                .zsh_file
                .as_ref()
                .map(crate::paths::Portable::as_str),
            Some("~/.zsh_history")
        );
        assert_eq!(
            history
                .bash_file
                .as_ref()
                .map(crate::paths::Portable::as_str),
            Some("~/.bash_history"),
            "each shell's file is its own key"
        );
        assert_eq!(merged.shell_options.checkwinsize, Some(true));
        assert_eq!(merged.shell_options.histappend, Some(false));
    }

    #[test]
    fn keybindings_merge_key_by_key_the_last_layer_winning() {
        use crate::shell::keybindings::{Action, Key};
        let merged = merge(&[
            global(
                "bx.toml",
                "[keybindings]\nhome = \"beginning-of-line\"\nalt-f = \"forward-word\"\n",
            ),
            global("modules/k.toml", "[keybindings]\nalt-f = \"end-of-line\"\n"),
            local("[keybindings]\nend = \"end-of-line\"\n"),
        ])
        .expect("merges");
        let keybindings = merged.keybindings;
        assert_eq!(keybindings.get(Key::Home), Some(Action::BeginningOfLine));
        assert_eq!(
            keybindings.get(Key::AltF),
            Some(Action::EndOfLine),
            "the later layer wins"
        );
        assert_eq!(keybindings.get(Key::End), Some(Action::EndOfLine));
        assert_eq!(keybindings.get(Key::AltB), None);
        assert!(
            keybindings
                .origin
                .as_ref()
                .is_some_and(|origin| origin.to_string().contains("local.toml")),
            "{:?}",
            keybindings.origin
        );
    }

    #[test]
    fn a_path_entry_merges_by_its_directory_in_place_across_lists() {
        use super::super::path::Position;
        let merged = merge(&[
            global(
                "bx.toml",
                "[path]\nprepend = [\"~/bin\", \"/opt/a/bin\", \"/opt/b/bin\"]\n\
                 append = [\"/opt/c/bin\"]\n",
            ),
            global(
                "modules/tool.toml",
                "[path]\nprepend = [\"/opt/d/bin\"]\nremove = [\"$HOME/bin\"]\n",
            ),
            local(
                "[path]\nprepend = [{ dir = \"/opt/a/bin\", enabled = false }]\n\
                 append = [{ dir = \"/opt/b/bin\", if_exists = true }]\n",
            ),
        ])
        .expect("merges");
        let seen: Vec<_> = merged
            .path
            .iter()
            .map(|e| {
                (
                    e.shell.as_str(),
                    e.position,
                    e.if_exists,
                    e.origin.file.clone(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                // Restated as `$HOME/bin`, one directory with `~/bin`: moved
                // to `remove`, where `~/bin` was.
                (
                    "${HOME}/bin",
                    Position::Remove,
                    false,
                    "modules/tool.toml".into()
                ),
                // `/opt/a/bin`, switched off by the account, is gone, and
                // `/opt/b/bin` is replaced in place and moved to `append`.
                ("/opt/b/bin", Position::Append, true, "local.toml".into()),
                ("/opt/c/bin", Position::Append, false, "bx.toml".into()),
                (
                    "/opt/d/bin",
                    Position::Prepend,
                    false,
                    "modules/tool.toml".into()
                ),
            ]
        );
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
        // Every file of the `config` module is scanned, read off the directory
        // at run time rather than from a list of names, so a file added to it
        // or split out of one is scanned without anyone remembering to list
        // it. `layers.rs` is the module whose own doc asserts "nothing here
        // reads the environment" — it takes both the home and the
        // `XDG_STATE_HOME` override as arguments — which is the claim this test
        // is quoted as proving.
        //
        // `target.rs` parses every target a layer holds, against the home it is
        // handed. The `paths` module holds `Portable::parse_in` and
        // `normalize`, which every module above calls, and also the crate's one
        // deliberate read of the environment there: `home()`, the edge that
        // hands a resolution path its argument. The edge line is allowed only
        // in `paths`, exactly once across the whole module and by its whole
        // text, so a second read anywhere in it, or a second copy of it, still
        // fails here.
        const PATHS_EDGES: [&str; 1] = ["home_in(std::env::var_os(\"HOME\").as_deref())"];
        let mut edges_seen = [0_usize; PATHS_EDGES.len()];
        for (module, edges) in [("config", &[][..]), ("paths", &PATHS_EDGES[..])] {
            for (path, source) in crate::testing::module_sources(module) {
                let name = path.display();
                // The non-test half, minus its prose. This very test names the
                // strings it forbids, and `layers.rs` documents what the *binary*
                // passes in by naming the call the library itself may not make — a
                // textual scan cannot tell a description from a call, so whole-line
                // comments are dropped and code is what is scanned.
                let code = source
                    .split("#[cfg(test)]")
                    .next()
                    .expect("the non-test half");
                for (edge, seen) in edges.iter().zip(&mut edges_seen) {
                    *seen += code.lines().filter(|line| line.trim() == *edge).count();
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
        for (edge, seen) in PATHS_EDGES.iter().zip(edges_seen) {
            assert_eq!(
                seen, 1,
                "paths: the edge `{edge}` is expected exactly once; if it moved, \
                 re-verify this list rather than widening the scan's exceptions"
            );
        }
    }
}
