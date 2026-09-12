//! Turning a merged configuration into one that can be written.
//!
//! Resolution takes the merged layers and this account's home and produces
//! [`Resolved`]: the answered values, and every enabled target with every
//! `{{name}}` in it already substituted.
//!
//! # A placeholder never reaches the writer
//!
//! Substitution is **eager** and happens here, so after [`resolve`] returns
//! there is no unsubstituted string left in the configuration for a later entry
//! to forget about. That is a property of the types rather than a discipline: a
//! lazy design would put the obligation on every future consumer, and forgetting
//! once writes a literal `{{scratch_root}}` into a user's file.
//!
//! # An unset value blocks one target, not the apply
//!
//! A target that references a value nobody answered becomes
//! [`Resolution::Blocked`] **in its own position**, carrying the value names and
//! the `bx init` invocation that sets them. Every other target resolves and is
//! applied. That is the difference between this and the source material, where a
//! missing `~/.gitconfig.local` makes the whole apply exit 1: the three git
//! identity values become declared values, and their absence blocks the one
//! target that needs them.
//!
//! The same holds for a value this account made unusable: an answer its kind
//! refuses, such as `scratch_root = "/"` for a root, or a legal answer that
//! makes a committed `default` invalid — `{{prefix}}/cache` as a `path` with
//! `prefix` answered `scratch`. It blocks the targets that reference it, and the
//! note names the `local.toml` line that caused it.
//!
//! A defect in the **committed** repo is not blocked but fatal — a malformed
//! placeholder, or a reference to a value no layer declares, cannot be fixed by
//! answering a prompt.

use std::path::Path;

use super::target::{Attach, Body, Format, KeyPath, Target};
use super::values::{ResolvedValues, Unresolved};
use super::{Config, Error, Origin};
use crate::paths::Portable;

/// A configuration entry that either resolved or could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<T> {
    /// Fully substituted, ready to be written.
    Ready(T),
    /// Held back, with the reason and what would clear it.
    Blocked(BlockedEntry),
}

/// Why an entry could not be resolved.
///
/// The shared reason enum. Entries C2 and E1 add `MissingTool { tool }` to it
/// rather than introducing a parallel blocked type, which is why
/// `report::Action::Blocked` is documented as "a prerequisite is absent" rather
/// than as one specific prerequisite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// One or more declared values this entry references have no answer.
    UnsetValue {
        /// The values that need answering, in declaration order.
        names: Vec<String>,
    },
    /// One or more declared values this entry references are switched off.
    ///
    /// Kept apart from [`BlockReason::UnsetValue`] because the two are cleared
    /// by different acts, and a note that told an account to answer a value it
    /// has itself refused would be advice it cannot follow.
    DisabledValue {
        /// The declarations to re-enable, in declaration order.
        names: Vec<String>,
    },
    /// One or more declared values this entry references have no usable text,
    /// because of an answer in this account's layer: one its kind refuses, or
    /// one that made a committed `default` invalid.
    ///
    /// Kept apart from [`BlockReason::UnsetValue`] because nothing is
    /// unanswered: the answer that needs changing is already written, and the
    /// hint names its line.
    InvalidValue {
        /// The declarations whose text is invalid, in declaration order.
        names: Vec<String>,
    },
}

/// An entry that was held back, and what it would take to release it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedEntry {
    /// The entry's natural key, so a report can name it.
    pub key: String,
    /// Where the entry was declared.
    pub origin: Origin,
    /// Why it is blocked.
    pub reason: BlockReason,
    /// What the user should do. Spelled in `values` — `init_hint`,
    /// `disabled_hint` or `ResolvedValues::invalid_hint` — never at a call site.
    pub hint: String,
}

/// A merged configuration, resolved against one account's home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Every declared value, with whatever answered it.
    pub values: ResolvedValues,
    /// Every enabled target, in the resolved configuration's order.
    ///
    /// Blocked targets keep their position, so the order `bx plan` reports in is
    /// the configuration's own order with nothing silently moved to the end.
    pub targets: Vec<Resolution<Target>>,
}

/// Resolve a merged configuration.
///
/// `home` is threaded in rather than read from the environment, so the whole
/// resolution is a pure function of the layer bytes plus this argument.
///
/// # Errors
///
/// [`Error::BadValue`] for a defect in the committed repo: a malformed
/// placeholder, a reference to a value no layer declares, a `default` that
/// references a later value, or a `default` that is not of its kind with no
/// account answer involved; and for two ready targets that name one file.
pub fn resolve(merged: &Config, home: &Path) -> Result<Resolved, Error> {
    let values = ResolvedValues::resolve(merged.values.clone(), &merged.value_assignments, home)?;

    let targets = merged
        .targets
        .iter()
        .map(|target| resolve_target(target, &values))
        .collect::<Result<Vec<_>, Error>>()?;

    refuse_shared_files(&targets)?;

    Ok(Resolved { values, targets })
}

/// Refuse two ready targets that write one file.
///
/// The merge keys targets by the file they name, so a configuration that came
/// through it cannot trip this. [`resolve`] takes any [`Config`], though, and
/// `Portable` is the key the ledger and the journal are written against: two
/// targets for one file would give `rm` two priors to restore and `apply` two
/// writers, so the second `plan` would never be empty.
fn refuse_shared_files(targets: &[Resolution<Target>]) -> Result<(), Error> {
    let ready: Vec<&Target> = targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) => Some(target),
            Resolution::Blocked(_) => None,
        })
        .collect();

    for (index, later) in ready.iter().enumerate() {
        if let Some(earlier) = ready[..index]
            .iter()
            .find(|earlier| earlier.path.as_str() == later.path.as_str())
        {
            return Err(Error::BadValue {
                origin: later.origin.clone(),
                message: format!(
                    "target `{}` is the same file as the target at {}; one file has one target",
                    later.path, earlier.origin
                ),
            });
        }
    }
    Ok(())
}

/// Substitute one target, or explain why it cannot be.
fn resolve_target(target: &Target, values: &ResolvedValues) -> Result<Resolution<Target>, Error> {
    let mut unset: Vec<String> = Vec::new();
    let mut disabled: Vec<String> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    let mut bad: Option<Unresolved> = None;

    // One pass to find out whether it can be resolved at all, so a blocked
    // target reports *every* value it is waiting on rather than the first.
    let mut probe = |text: &str| match values.substitute(text) {
        Ok(_) => {}
        Err(Unresolved::Unset { names }) => unset.extend(names),
        Err(Unresolved::Disabled { names }) => disabled.extend(names),
        Err(Unresolved::Invalid { names }) => invalid.extend(names),
        Err(other) => bad = bad.take().or(Some(other)),
    };
    for_each_string(target, &mut probe);

    if let Some(defect) = bad {
        return Err(Error::BadValue {
            origin: target.origin.clone(),
            message: format!("target `{}`: {defect}", target.path),
        });
    }

    let block = |reason, hint| {
        Ok(Resolution::Blocked(BlockedEntry {
            key: target.path.to_string(),
            origin: target.origin.clone(),
            reason,
            hint,
        }))
    };

    // A switched-off declaration is reported ahead of an unanswered one: it is
    // the more specific statement about what this target is waiting for.
    if !disabled.is_empty() {
        let names = in_declaration_order(values, disabled);
        let hint =
            super::values::disabled_hint(&names.iter().map(String::as_str).collect::<Vec<_>>());
        return block(BlockReason::DisabledValue { names }, hint);
    }

    // An invalid value ahead of an unanswered one: answering would not clear it.
    if !invalid.is_empty() {
        let names = in_declaration_order(values, invalid);
        let hint = values.invalid_hint(&names);
        return block(BlockReason::InvalidValue { names }, hint);
    }

    if !unset.is_empty() {
        let names = in_declaration_order(values, unset);
        let hint = super::values::init_hint(&names.iter().map(String::as_str).collect::<Vec<_>>());
        return block(BlockReason::UnsetValue { names }, hint);
    }

    substituted(target, values).map(Resolution::Ready)
}

/// Every string field of a target that substitution applies to.
///
/// **`Body::File` names a file; its contents are not visited.** A repo file is
/// byte-verbatim, because the operator's own repository holds files with literal
/// brace pairs — a workflow's expression syntax, a handlebars template — and
/// making every one of them a template would either break them or force bx to
/// edit the user's content to suit bx. Account-varying file content is expressed
/// as an inline body instead.
fn for_each_string(target: &Target, visit: &mut impl FnMut(&str)) {
    visit(target.path.as_str());

    match &target.body {
        Body::File(path) => visit(&path.to_string_lossy()),
        Body::Inline(text) => visit(text),
        Body::Generated(_) | Body::Dir => {}
    }

    if let Attach::Include { line } = &target.attach {
        visit(line);
    }

    if let Format::Jsonc { owns } = &target.format {
        for key in owns {
            visit(&key.to_string());
        }
    }

    for tool in &target.requires {
        visit(tool);
    }
    for reference in &target.references {
        visit(reference.as_str());
    }
}

/// Rebuild `target` with every string field substituted.
///
/// Only called once every reference is known to be answered, so a substitution
/// here cannot fail for want of an answer; it can still fail because a
/// substituted string is no longer a valid portable path or key path, which is
/// a configuration defect and is reported as one.
fn substituted(target: &Target, values: &ResolvedValues) -> Result<Target, Error> {
    let origin = &target.origin;
    let sub = |text: &str| -> Result<String, Error> {
        values.substitute(text).map_err(|defect| Error::BadValue {
            origin: origin.clone(),
            message: format!("target `{}`: {defect}", target.path),
        })
    };
    let portable = |text: &str| -> Result<Portable, Error> {
        // Against the home the values were resolved against, never a re-derived
        // one: `Portable::parse_in` rejects an absolute path under the home, and
        // a different home would make that judgement about a different file.
        Portable::parse_in(&sub(text)?, values.home()).map_err(|source| Error::BadValue {
            origin: origin.clone(),
            message: format!("target `{}`: {source}", target.path),
        })
    };

    let body = match &target.body {
        // Through the parser's own rule, not straight into the target. A `file`
        // is the one substituted field whose validator the parse-time check
        // cannot stand in for: `cfg/{{account}}/gitconfig` is a legal body file
        // as written, and an `account` answered `../../../../etc` makes it read
        // a file off the machine and write it into a target.
        Body::File(path) => Body::File(
            super::target::confine_to_repo("file", &sub(&path.to_string_lossy())?).map_err(
                |message| Error::BadValue {
                    origin: origin.clone(),
                    message: format!("target `{}`: {message}", target.path),
                },
            )?,
        ),
        Body::Inline(text) => Body::Inline(sub(text)?),
        other => other.clone(),
    };

    let attach = match &target.attach {
        Attach::Include { line } => Attach::Include { line: sub(line)? },
        other => other.clone(),
    };

    let format = match &target.format {
        Format::Jsonc { owns } => Format::Jsonc {
            owns: owns
                .iter()
                .map(|key| {
                    KeyPath::parse(&sub(&key.to_string())?).map_err(|source| Error::BadValue {
                        origin: origin.clone(),
                        message: format!("target `{}`: {source}", target.path),
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?,
        },
        other => other.clone(),
    };

    Ok(Target {
        path: portable(target.path.as_str())?,
        body,
        mode: target.mode,
        attach,
        direction: target.direction,
        format,
        requires: target
            .requires
            .iter()
            .map(|tool| sub(tool))
            .collect::<Result<Vec<_>, Error>>()?,
        references: target
            .references
            .iter()
            .map(|reference| portable(reference.as_str()))
            .collect::<Result<Vec<_>, Error>>()?,
        enabled: target.enabled,
        origin: target.origin.clone(),
    })
}

/// Order `names` the way the values were declared, deduplicated.
///
/// So two reports of one problem read the same way regardless of which field
/// happened to be probed first.
fn in_declaration_order(values: &ResolvedValues, mut names: Vec<String>) -> Vec<String> {
    let index = |name: &String| {
        values
            .decls()
            .iter()
            .position(|decl| &decl.name == name)
            .unwrap_or(usize::MAX)
    };
    names.sort_by_key(index);
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::merge::merge;
    use crate::config::{Layer, LayerKind, parse_str};
    use std::path::PathBuf;

    fn home() -> PathBuf {
        PathBuf::from("/var/home/example")
    }

    /// Build a layer of the given kind out of TOML.
    ///
    /// A parse failure is returned rather than panicked, because some of the
    /// rules under test — a target path that opens with a placeholder — are
    /// enforced by the parser rather than by resolution.
    fn layer(file: &str, kind: LayerKind, text: &str) -> Result<Layer, String> {
        Ok(Layer {
            file: PathBuf::from(file),
            kind,
            config: parse_str(text, Path::new(file), &home())
                .map_err(|e| format!("{file}: {e}"))?,
        })
    }

    /// Merge and resolve a global layer and an optional local one.
    fn resolved(global: &str, local: Option<&str>) -> Result<Resolved, String> {
        let mut layers = vec![layer("bx.toml", LayerKind::Global, global)?];
        if let Some(local) = local {
            layers.push(layer("local.toml", LayerKind::Local, local)?);
        }
        let merged = merge(&layers, &home()).map_err(|e| e.to_string())?;
        resolve(&merged, &home()).map_err(|e| e.to_string())
    }

    /// The resolved targets' keys, blocked ones included and in position.
    fn keys(resolved: &Resolved) -> Vec<String> {
        resolved
            .targets
            .iter()
            .map(|r| match r {
                Resolution::Ready(target) => target.path.to_string(),
                Resolution::Blocked(entry) => entry.key.clone(),
            })
            .collect()
    }

    /// The one target, expected to be `Ready`.
    fn ready(resolved: &Resolved, index: usize) -> &Target {
        match &resolved.targets[index] {
            Resolution::Ready(target) => target,
            Resolution::Blocked(entry) => panic!("blocked: {}", entry.hint),
        }
    }

    /// The one target, expected to be `Blocked`.
    fn blocked(resolved: &Resolved, index: usize) -> &BlockedEntry {
        match &resolved.targets[index] {
            Resolution::Blocked(entry) => entry,
            Resolution::Ready(target) => panic!("unexpectedly ready: {}", target.path),
        }
    }

    /// A declaration and a target that uses it.
    const SCRATCH: &str = "[[value]]\n\
                           name = \"scratch_root\"\n\
                           kind = \"path\"\n\
                           required = true\n\
                           is_root = true\n";

    #[test]
    fn a_placeholder_in_a_body_is_substituted() {
        let resolved = resolved(
            &format!(
                "{SCRATCH}[[target]]\n\
                 path = \"~/.config/env\"\n\
                 content = \"CARGO_HOME={{{{scratch_root}}}}/cargo\"\n"
            ),
            Some("[values]\nscratch_root = \"/var/mnt/scratch/one\"\n"),
        )
        .unwrap();

        assert_eq!(
            ready(&resolved, 0).body,
            Body::Inline("CARGO_HOME=/var/mnt/scratch/one/cargo".to_string())
        );
    }

    #[test]
    fn a_placeholder_in_a_target_path_is_substituted() {
        let resolved = resolved(
            "[[value]]\nname = \"flavour\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/bx/{{flavour}}.toml\"\ncontent = \"x\"\n",
            Some("[values]\nflavour = \"dark\"\n"),
        )
        .unwrap();

        assert_eq!(ready(&resolved, 0).path.as_str(), "~/.config/bx/dark.toml");
    }

    #[test]
    fn a_substituted_body_file_is_confined_to_the_config_repo() {
        // An account-varying `file` is the natural spelling for a per-account
        // body, and it is the one substituted field the parse-time check cannot
        // stand in for: what the parser saw was `cfg/{{account}}/gitconfig`, and
        // what reaches `repo.join` is whatever the answer made of it.
        const LAYER: &str = "[[value]]\n\
                             name = \"account\"\n\
                             kind = \"string\"\n\
                             [[target]]\n\
                             path = \"~/.gitconfig\"\n\
                             file = \"cfg/{{account}}/gitconfig\"\n";

        let message = resolved(LAYER, Some("[values]\naccount = \"../../../../etc\"\n"))
            .expect_err("a climbing answer is a repo escape");
        assert!(
            message.contains("may not climb out of the config repo"),
            "{message}"
        );
        assert!(message.contains("~/.gitconfig"), "{message}");

        // A `file` that *opens* with a value, answered absolutely, would discard
        // the repo root the moment it reached `repo.join`.
        const ROOTED: &str = "[[value]]\n\
                              name = \"account\"\n\
                              kind = \"string\"\n\
                              [[target]]\n\
                              path = \"~/.gitconfig\"\n\
                              file = \"{{account}}/gitconfig\"\n";

        let message = resolved(ROOTED, Some("[values]\naccount = \"/etc\"\n"))
            .expect_err("an absolute answer discards the repo root");
        assert!(message.contains("relative to the repo root"), "{message}");

        let ordinary = resolved(LAYER, Some("[values]\naccount = \"work\"\n")).unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::File(PathBuf::from("cfg/work/gitconfig")),
            "the case this spelling exists for still resolves"
        );
    }

    #[test]
    fn a_substitution_that_breaks_a_portable_path_is_a_load_error() {
        // Every substituted field is re-validated, because substitution can turn
        // a legal value into an illegal one. A path that climbs out of the home
        // is the case that matters: `under_home` is a claim about location, and
        // a `Portable` that escaped it would make a later entry's write gate on
        // nothing.
        let message = resolved(
            "[[value]]\nname = \"leaf\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/{{leaf}}\"\ncontent = \"x\"\n",
            Some("[values]\nleaf = \"../../etc/passwd\"\n"),
        )
        .expect_err("the substituted path climbs out of the home");
        assert!(message.contains("climb out of the home"), "{message}");

        let message = resolved(
            "[[value]]\nname = \"leaf\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.gitconfig\"\ncontent = \"x\"\n\
             references = [\"~/{{leaf}}\"]\n",
            Some("[values]\nleaf = \"../../etc/passwd\"\n"),
        )
        .expect_err("a reference is a portable path too");
        assert!(message.contains("climb out of the home"), "{message}");
    }

    #[test]
    fn a_substitution_that_breaks_a_key_path_is_a_load_error() {
        let message = resolved(
            "[[value]]\nname = \"setting\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/zed/settings.json\"\ncontent = \"{{{{}}\"\n\
             format = \"jsonc\"\nowns = [\"editor.{{setting}}\"]\n",
            Some("[values]\nsetting = \"\"\n"),
        )
        .expect_err("`editor.` has an empty segment");

        assert!(message.contains("empty segment"), "{message}");
    }

    #[test]
    fn a_directory_target_resolves_with_nothing_to_substitute() {
        // A directory has no body to visit, and a body-less target must still
        // have its path and its other string fields substituted.
        let resolved = resolved(
            "[[value]]\nname = \"flavour\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/{{flavour}}.d\"\ndir = true\n\
             requires = [\"{{flavour}}-tool\"]\n",
            Some("[values]\nflavour = \"dark\"\n"),
        )
        .unwrap();

        let target = ready(&resolved, 0);
        assert_eq!(target.path.as_str(), "~/.config/dark.d");
        assert_eq!(target.body, Body::Dir);
        assert_eq!(target.requires, ["dark-tool"]);
    }

    #[test]
    fn a_directory_target_is_blocked_on_an_unset_value_like_any_other() {
        let resolved = resolved(
            "[[value]]\nname = \"flavour\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/{{flavour}}.d\"\ndir = true\n",
            None,
        )
        .unwrap();

        assert_eq!(
            blocked(&resolved, 0).reason,
            BlockReason::UnsetValue {
                names: vec!["flavour".to_string()]
            }
        );
    }

    #[test]
    fn a_target_path_may_not_open_with_a_placeholder() {
        // `Portable` is the natural key of a target and the key the ledger and
        // the journal are written against, so it is `~`- or `/`-rooted by
        // construction and is checked at parse time, before any substitution has
        // happened. A path that *begins* with a value is therefore not
        // expressible; a value anywhere after the first character is. The
        // restriction is loud rather than silent, which is what matters.
        let message = resolved(
            "[[value]]\nname = \"cache_dir\"\nkind = \"path\"\n\
             [[target]]\npath = \"{{cache_dir}}/marker\"\ncontent = \"x\"\n",
            None,
        )
        .unwrap_err();

        assert!(message.contains("must start with `~` or `/`"), "{message}");
    }

    #[test]
    fn disabling_a_declaration_blocks_its_targets_and_nothing_else() {
        // The sanctioned three-line toggle. It used to fail the whole load with
        // "no layer declares the value git_email" -- a statement that is not
        // true, pointing at a committed file the account cannot edit.
        let resolved = resolved(
            "[[value]]\nname = \"git_email\"\nkind = \"email\"\nrequired = true\n\
             [[target]]\npath = \"~/.gitconfig.d/id\"\ncontent = \"email = {{git_email}}\"\n\
             [[target]]\npath = \"~/.config/starship.toml\"\ncontent = \"format = \\\"x\\\"\"\n",
            Some("[[value]]\nname = \"git_email\"\nenabled = false\n"),
        )
        .unwrap();

        let entry = blocked(&resolved, 0);
        assert_eq!(
            entry.reason,
            BlockReason::DisabledValue {
                names: vec!["git_email".to_string()]
            }
        );
        assert!(
            entry.hint.contains("re-enable git_email"),
            "a note telling the account to run `bx init` for a value it has \
             itself switched off is advice it cannot follow: {}",
            entry.hint
        );
        assert!(!entry.hint.contains("bx init"), "{}", entry.hint);

        assert_eq!(
            keys(&resolved),
            ["~/.gitconfig.d/id", "~/.config/starship.toml"],
            "one target is held back, in its own position, and the rest apply"
        );
        ready(&resolved, 1);
    }

    #[test]
    fn a_value_derived_from_a_disabled_one_blocks_by_the_same_reason() {
        // The cause travels: `sccache_dir` is unanswerable because the account
        // switched off what its default derives from, and switching that back on
        // is what clears both.
        let resolved = resolved(
            "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n\
             [[value]]\nname = \"sccache_dir\"\nkind = \"path\"\n\
             default = \"{{scratch_root}}/sccache\"\n\
             [[target]]\npath = \"~/.config/env\"\ncontent = \"SCCACHE_DIR={{sccache_dir}}\"\n",
            Some(
                "[[value]]\nname = \"scratch_root\"\nenabled = false\n\
                 [values]\nscratch_root = \"/var/mnt/scratch/one\"\n",
            ),
        )
        .unwrap();

        assert_eq!(
            blocked(&resolved, 0).reason,
            BlockReason::DisabledValue {
                names: vec!["scratch_root".to_string()]
            },
            "the name reported is the one to act on, not the derived one"
        );
    }

    #[test]
    fn a_disabled_declaration_is_not_prompted_for() {
        // The other half of the same decision: an account that switched a value
        // off is not asked about it, so the blocked note may not say `bx init`.
        let resolved = resolved(
            "[[value]]\nname = \"agent_slice\"\nkind = \"string\"\nrequired = true\n",
            Some("[[value]]\nname = \"agent_slice\"\nenabled = false\n"),
        )
        .unwrap();

        assert!(resolved.values.unset_required_names().is_empty());
        assert!(resolved.values.unset().is_empty());
        assert!(resolved.values.decls().is_empty());
        assert!(
            resolved.values.decl("agent_slice").is_some(),
            "still findable, which is what keeps a reference to it apart from a \
             reference to a name no layer declares"
        );
    }

    #[test]
    fn an_unanswered_value_blocks_every_target_that_references_it() {
        let resolved = resolved(
            &format!(
                "{SCRATCH}[[target]]\n\
                 path = \"~/.config/env\"\n\
                 content = \"CARGO_HOME={{{{scratch_root}}}}/cargo\"\n"
            ),
            None,
        )
        .unwrap();

        let entry = blocked(&resolved, 0);
        assert_eq!(
            entry.reason,
            BlockReason::UnsetValue {
                names: vec!["scratch_root".to_string()]
            }
        );
    }

    #[test]
    fn a_blocked_target_names_the_value_and_the_init_invocation() {
        // A report has to say which value is missing and what to run, or the
        // user cannot act on it.
        let resolved = resolved(
            &format!("{SCRATCH}[[target]]\npath = \"~/.a\"\ncontent = \"{{{{scratch_root}}}}\"\n"),
            None,
        )
        .unwrap();

        let entry = blocked(&resolved, 0);
        assert_eq!(entry.key, "~/.a");
        assert_eq!(entry.origin.file, Path::new("bx.toml"));
        assert_eq!(entry.hint, "run `bx init` to set scratch_root");
    }

    #[test]
    fn a_blocked_target_keeps_its_position_in_the_resolved_order() {
        let resolved = resolved(
            &format!(
                "{SCRATCH}\
                 [[target]]\npath = \"~/.a\"\ncontent = \"a\"\n\
                 [[target]]\npath = \"~/.b\"\ncontent = \"{{{{scratch_root}}}}\"\n\
                 [[target]]\npath = \"~/.c\"\ncontent = \"c\"\n"
            ),
            None,
        )
        .unwrap();

        assert_eq!(keys(&resolved), ["~/.a", "~/.b", "~/.c"]);
        assert!(matches!(resolved.targets[1], Resolution::Blocked(_)));
    }

    #[test]
    fn an_unrelated_target_resolves_while_another_is_blocked() {
        // The source material's `~/.gitconfig` declares `gpgSign = true` with no
        // `user.name`, `user.email` or `user.signingkey`, and its check script
        // exits 1 when the account file is missing. Here the three become
        // declared values, their absence blocks the one target that needs them,
        // and everything else still applies.
        let resolved = resolved(
            "[[value]]\nname = \"git_name\"\nkind = \"string\"\nrequired = true\n\
             [[value]]\nname = \"git_email\"\nkind = \"email\"\nrequired = true\n\
             [[value]]\nname = \"git_signingkey\"\nkind = \"ssh-key\"\nrequired = true\n\
             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n\
             [[target]]\npath = \"~/.gitconfig.d/identity\"\n\
             content = \"name = {{git_name}}\\nemail = {{git_email}}\"\n\
             [[target]]\npath = \"~/.config/starship.toml\"\ncontent = \"x\"\n",
            None,
        )
        .unwrap();

        assert!(matches!(resolved.targets[0], Resolution::Ready(_)));
        assert!(matches!(resolved.targets[2], Resolution::Ready(_)));

        let entry = blocked(&resolved, 1);
        assert_eq!(
            entry.reason,
            BlockReason::UnsetValue {
                names: vec!["git_name".to_string(), "git_email".to_string()]
            },
            "every value it waits on, in declaration order, not just the first"
        );
        assert_eq!(
            resolved.values.unset_required_names(),
            ["git_name", "git_email", "git_signingkey"],
            "the unreferenced third value is listed but blocks nothing"
        );
    }

    #[test]
    fn a_root_answered_as_the_filesystem_blocks_only_what_references_it() {
        // End to end through the merge: the account's own local.toml line is
        // refused and named, a target that references no value still applies,
        // and nothing is admitted to the root set.
        for spelling in ["/", "//", "/./", "/.."] {
            let resolved = resolved(
                &format!(
                    "{SCRATCH}[[target]]\npath = \"~/.config/env\"\n\
                     content = \"CACHE={{{{scratch_root}}}}/cache\"\n\
                     [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n"
                ),
                Some(format!("[values]\nscratch_root = \"{spelling}\"\n").as_str()),
            )
            .unwrap_or_else(|e| panic!("{spelling:?} failed the whole load: {e}"));

            let entry = blocked(&resolved, 0);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["scratch_root".to_string()]
                },
                "{spelling:?}"
            );
            assert!(
                entry.hint.contains("local.toml:2"),
                "{spelling:?}: {}",
                entry.hint
            );
            ready(&resolved, 1);
            assert!(resolved.values.roots().is_empty(), "{spelling:?}");
        }
    }

    #[test]
    fn a_legal_answer_that_breaks_a_derived_default_blocks_only_its_dependents() {
        // `prefix = "scratch"` is a perfectly good `string`. It makes `cache`'s
        // default expand to `scratch/cache`, which is not a `path` — but that is
        // this account's answer interacting with a committed default, not a repo
        // defect, so it may not take `~/.zshrc` down with it, and the note has
        // to name the local.toml line that caused it rather than the committed
        // declaration the account may not edit.
        let resolved = resolved(
            "[[value]]\nname = \"prefix\"\nkind = \"string\"\n\
             [[value]]\nname = \"cache\"\nkind = \"path\"\ndefault = \"{{prefix}}/cache\"\n\
             [[target]]\npath = \"~/.config/env\"\ncontent = \"CACHE={{cache}}\"\n\
             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n",
            Some("# this account's answers\n[values]\nprefix = \"scratch\"\n"),
        )
        .expect("an account's legal answer does not fail the load");

        ready(&resolved, 1);
        let entry = blocked(&resolved, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["cache".to_string()]
            }
        );
        assert!(entry.hint.contains("local.toml:3"), "{}", entry.hint);
        assert!(entry.hint.contains("prefix"), "{}", entry.hint);
        assert!(entry.hint.contains("\"scratch/cache\""), "{}", entry.hint);
    }

    #[test]
    fn an_account_overrides_a_placeholder_pathed_target_by_the_path_it_resolves_to() {
        // End to end: this used to produce two `Ready` targets with
        // byte-identical keys — one file with two owners.
        let resolved = resolved(
            "[[value]]\nname = \"acct\"\nkind = \"string\"\ndefault = \"one\"\n\
             [[target]]\npath = \"~/.config/{{acct}}/settings.json\"\ncontent = \"GLOBAL\"\n",
            Some("[[target]]\npath = \"~/.config/one/settings.json\"\ncontent = \"LOCAL\"\n"),
        )
        .unwrap();

        assert_eq!(keys(&resolved), ["~/.config/one/settings.json"]);
        assert_eq!(ready(&resolved, 0).body, Body::Inline("LOCAL".to_string()));
    }

    #[test]
    fn an_account_opts_out_of_a_placeholder_pathed_target_by_the_path_it_resolves_to() {
        // The three-line opt-out, by the path `plan` shows. It used to fail the
        // whole load saying no earlier layer declares an entry `plan` lists.
        let resolved = resolved(
            "[[value]]\nname = \"acct\"\nkind = \"string\"\ndefault = \"one\"\n\
             [[target]]\npath = \"~/.config/{{acct}}/settings.json\"\ncontent = \"GLOBAL\"\n\
             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n",
            Some("[[target]]\npath = \"~/.config/one/settings.json\"\nenabled = false\n"),
        )
        .expect("the opt-out reaches the target");

        assert_eq!(keys(&resolved), ["~/.zshrc"]);
    }

    #[test]
    fn two_ready_targets_for_one_file_are_refused_even_unmerged() {
        // `resolve` takes any `Config`, and one that did not come through the
        // merge can still carry two spellings of one file.
        let global = layer(
            "bx.toml",
            LayerKind::Global,
            "[[value]]\nname = \"acct\"\nkind = \"string\"\ndefault = \"one\"\n\
             [[target]]\npath = \"~/.config/{{acct}}/settings.json\"\ncontent = \"GLOBAL\"\n",
        )
        .unwrap();
        let local = layer(
            "local.toml",
            LayerKind::Local,
            "[[target]]\npath = \"~/.config/one/settings.json\"\ncontent = \"LOCAL\"\n",
        )
        .unwrap();
        let mut config = global.config;
        config.targets.extend(local.config.targets);

        let message = resolve(&config, &home()).unwrap_err().to_string();

        assert!(message.contains("local.toml:1"), "{message}");
        assert!(
            message.contains("same file as the target at bx.toml:"),
            "{message}"
        );
    }

    #[test]
    fn answering_the_values_releases_the_blocked_target() {
        let global = "[[value]]\nname = \"git_email\"\nkind = \"email\"\nrequired = true\n\
                      [[target]]\npath = \"~/.gitconfig.d/identity\"\n\
                      content = \"email = {{git_email}}\"\n";

        let resolved = resolved(
            global,
            Some("[values]\ngit_email = \"someone@example.invalid\"\n"),
        )
        .unwrap();

        assert_eq!(
            ready(&resolved, 0).body,
            Body::Inline("email = someone@example.invalid".to_string())
        );
    }

    #[test]
    fn no_resolved_target_contains_a_placeholder() {
        // The pin that every later entry adding a string-bearing field must
        // extend: after `resolve` returns, no unsubstituted string exists.
        let resolved = resolved(
            "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n\
             [[value]]\nname = \"tool\"\nkind = \"string\"\n\
             [[target]]\n\
             path = \"~/.config/{{tool}}/config.json\"\n\
             content = \"cache = {{scratch_root}}\"\n\
             format = \"jsonc\"\n\
             owns = [\"{{tool}}.model\"]\n\
             requires = [\"{{tool}}\"]\n\
             references = [\"~/{{tool}}/other\"]\n",
            Some("[values]\nscratch_root = \"/var/mnt/scratch/one\"\ntool = \"zed\"\n"),
        )
        .unwrap();

        let target = ready(&resolved, 0);
        let mut seen = Vec::new();
        for_each_string(target, &mut |text| seen.push(text.to_string()));

        assert!(!seen.is_empty());
        for field in &seen {
            assert!(!field.contains("{{"), "a placeholder survived in {field:?}");
        }
        assert_eq!(target.requires, ["zed"]);
        assert_eq!(target.references[0].as_str(), "~/zed/other");
    }

    #[test]
    fn an_include_line_is_substituted() {
        let resolved = resolved(
            "[[value]]\nname = \"ssh_dir\"\nkind = \"path\"\n\
             [[target]]\npath = \"~/.ssh/config\"\n\
             attach = \"include\"\ninclude = \"Include {{ssh_dir}}/config.d/*.conf\"\n",
            Some("[values]\nssh_dir = \"~/.ssh\"\n"),
        )
        .unwrap();

        assert_eq!(
            ready(&resolved, 0).attach,
            Attach::Include {
                line: "Include /var/home/example/.ssh/config.d/*.conf".to_string()
            }
        );
    }

    #[test]
    fn a_file_body_names_a_file_and_is_not_read() {
        // The path is a config string field and is substituted; the file's
        // *contents* are byte-verbatim and are never visited here.
        let resolved = resolved(
            "[[value]]\nname = \"flavour\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/starship.toml\"\nfile = \"files/{{flavour}}.toml\"\n",
            Some("[values]\nflavour = \"dark\"\n"),
        )
        .unwrap();

        assert_eq!(
            ready(&resolved, 0).body,
            Body::File(PathBuf::from("files/dark.toml"))
        );
    }

    #[test]
    fn a_placeholder_naming_an_undeclared_value_is_a_load_error() {
        // A repo typo, unfixable by any answer, so it is fatal rather than
        // blocking one target.
        let message = resolved(
            "[[target]]\npath = \"~/.a\"\ncontent = \"{{nowhere}}\"\n",
            None,
        )
        .unwrap_err();

        assert!(
            message.contains("no layer declares the value `nowhere`"),
            "{message}"
        );
        assert!(message.contains("bx.toml:1"), "{message}");
    }

    #[test]
    fn a_malformed_placeholder_is_a_load_error() {
        let message = resolved(
            "[[target]]\npath = \"~/.a\"\ncontent = \"{{unterminated\"\n",
            None,
        )
        .unwrap_err();

        assert!(message.contains("unterminated placeholder"), "{message}");
    }

    #[test]
    fn a_disabled_target_is_never_resolved() {
        let resolved = resolved(
            &format!(
                "{SCRATCH}\
                 [[target]]\npath = \"~/.a\"\ncontent = \"{{{{scratch_root}}}}\"\nenabled = false\n\
                 [[target]]\npath = \"~/.b\"\ncontent = \"b\"\n"
            ),
            None,
        )
        .unwrap();

        assert_eq!(
            keys(&resolved),
            ["~/.b"],
            "an entry an account opted out of cannot block anything"
        );
    }

    #[test]
    fn an_account_that_disables_a_target_still_gets_every_other_target() {
        let resolved = resolved(
            "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"git\"\n\
             [[target]]\npath = \"~/.config/nvtop/interface.ini\"\ncontent = \"nvtop\"\n\
             [[target]]\npath = \"~/.zshrc\"\ncontent = \"zsh\"\n",
            Some("[[target]]\npath = \"~/.config/nvtop/interface.ini\"\nenabled = false\n"),
        )
        .unwrap();

        assert_eq!(keys(&resolved), ["~/.gitconfig", "~/.zshrc"]);
    }

    #[test]
    fn the_resolved_values_travel_with_the_targets() {
        // Entry A1 builds its root set from these two accessors and never reads
        // the environment for a home.
        let resolved = resolved(
            SCRATCH,
            Some("[values]\nscratch_root = \"/var/mnt/scratch/one\"\n"),
        )
        .unwrap();

        assert_eq!(resolved.values.home(), home());
        assert_eq!(
            resolved.values.roots(),
            [PathBuf::from("/var/mnt/scratch/one")]
        );
    }

    #[test]
    fn resolving_twice_is_byte_identical() {
        // Invariant 3, end to end through merge and resolution.
        let global = format!(
            "{SCRATCH}\
             [[target]]\npath = \"~/.a\"\ncontent = \"{{{{scratch_root}}}}\"\n\
             [[target]]\npath = \"~/.b\"\ncontent = \"b\"\n"
        );
        let local = "[values]\nscratch_root = \"/var/mnt/scratch/one\"\n";

        let first = resolved(&global, Some(local)).unwrap();
        let second = resolved(&global, Some(local)).unwrap();

        assert_eq!(format!("{first:#?}"), format!("{second:#?}"));
    }

    #[test]
    fn an_empty_configuration_resolves_to_nothing() {
        let resolved = resolved("", None).unwrap();

        assert!(resolved.targets.is_empty());
        assert!(resolved.values.decls().is_empty());
    }

    #[test]
    fn two_accounts_read_one_repo_and_get_two_configurations() {
        // The whole point of the entry, in one test: the repo declares the shape
        // of the divergence, and each account's own layer supplies its content.
        let repo = "[[value]]\n\
                    name = \"scratch_root\"\nkind = \"path\"\nrequired = true\nis_root = true\n\
                    [[value]]\n\
                    name = \"sccache_dir\"\nkind = \"path\"\nis_root = true\n\
                    default = \"{{scratch_root}}/cache/sccache\"\n\
                    [[target]]\npath = \"~/.config/env\"\n\
                    content = \"SCCACHE_DIR={{sccache_dir}}\"\n\
                    [[target]]\npath = \"~/.config/nvtop/interface.ini\"\ncontent = \"shared\"\n";

        let one = resolved(
            repo,
            Some("[values]\nscratch_root = \"/var/mnt/scratch/one\"\n"),
        )
        .unwrap();
        let two = resolved(
            repo,
            Some(
                "[values]\nscratch_root = \"/var/mnt/scratch/two\"\n\
                 sccache_dir = \"/var/mnt/fast/sccache\"\n\
                 [[target]]\npath = \"~/.config/nvtop/interface.ini\"\nenabled = false\n",
            ),
        )
        .unwrap();

        assert_eq!(
            ready(&one, 0).body,
            Body::Inline("SCCACHE_DIR=/var/mnt/scratch/one/cache/sccache".to_string()),
            "the account that has not moved sccache answers one question"
        );
        assert_eq!(
            ready(&two, 0).body,
            Body::Inline("SCCACHE_DIR=/var/mnt/fast/sccache".to_string()),
            "the account that keeps it on another filesystem answers two"
        );
        assert_eq!(
            keys(&one),
            ["~/.config/env", "~/.config/nvtop/interface.ini"]
        );
        assert_eq!(
            keys(&two),
            ["~/.config/env"],
            "and opts out of a target the first account wants"
        );
        assert_eq!(
            one.values.roots(),
            [
                PathBuf::from("/var/mnt/scratch/one"),
                PathBuf::from("/var/mnt/scratch/one/cache/sccache"),
            ]
        );
        assert_eq!(
            two.values.roots(),
            [
                PathBuf::from("/var/mnt/scratch/two"),
                PathBuf::from("/var/mnt/fast/sccache"),
            ],
            "two roots, because sccache is outside this account's scratch root"
        );
    }
}
