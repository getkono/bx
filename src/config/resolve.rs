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
    /// What the user should run. Spelled by `values::init_hint`, in one place.
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
/// references a later value, or an answer that is not of its declared kind.
pub fn resolve(merged: &Config, home: &Path) -> Result<Resolved, Error> {
    let values = ResolvedValues::resolve(merged.values.clone(), &merged.value_assignments, home)?;

    let targets = merged
        .targets
        .iter()
        .map(|target| resolve_target(target, &values))
        .collect::<Result<Vec<_>, Error>>()?;

    Ok(Resolved { values, targets })
}

/// Substitute one target, or explain why it cannot be.
fn resolve_target(target: &Target, values: &ResolvedValues) -> Result<Resolution<Target>, Error> {
    let mut unset: Vec<String> = Vec::new();
    let mut bad: Option<Unresolved> = None;

    // One pass to find out whether it can be resolved at all, so a blocked
    // target reports *every* value it is waiting on rather than the first.
    let mut probe = |text: &str| match values.substitute(text) {
        Ok(_) => {}
        Err(Unresolved::Unset { names }) => unset.extend(names),
        Err(other) => bad = bad.take().or(Some(other)),
    };
    for_each_string(target, &mut probe);

    if let Some(defect) = bad {
        return Err(Error::BadValue {
            origin: target.origin.clone(),
            message: format!("target `{}`: {defect}", target.path),
        });
    }

    if !unset.is_empty() {
        let names = in_declaration_order(values, unset);
        let hint = super::values::init_hint(&names.iter().map(String::as_str).collect::<Vec<_>>());
        return Ok(Resolution::Blocked(BlockedEntry {
            key: target.path.to_string(),
            origin: target.origin.clone(),
            reason: BlockReason::UnsetValue { names },
            hint,
        }));
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
        Portable::parse(&sub(text)?).map_err(|source| Error::BadValue {
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
            config: parse_str(text, Path::new(file)).map_err(|e| format!("{file}: {e}"))?,
        })
    }

    /// Merge and resolve a global layer and an optional local one.
    fn resolved(global: &str, local: Option<&str>) -> Result<Resolved, String> {
        let mut layers = vec![layer("bx.toml", LayerKind::Global, global)?];
        if let Some(local) = local {
            layers.push(layer("local.toml", LayerKind::Local, local)?);
        }
        let merged = merge(&layers).map_err(|e| e.to_string())?;
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
             [[target]]\npath = \"~/.ssh/config\"\ncontent = \"Host x\"\n\
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
