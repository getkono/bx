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
//! So does a legal answer that makes a **target's own field** invalid once
//! substituted, among them: `acct = "../../.."` into
//! `~/.config/{{acct}}/settings.json` climbs out of the home, `seg = ""` into
//! `owns = ["a.{{seg}}"]` leaves an empty key segment, `seg = "b.c"` adds a
//! segment, naming a deeper key than the one written, and `leaf = "."` into a
//! file target's `~/{{leaf}}` makes it the home directory itself. The target is
//! blocked naming the answer's line, and nothing is written for it. The same
//! field broken with no account answer in it — a committed `default` alone — is
//! the repo's defect and fails the load.
//!
//! A defect in the **committed** repo is not blocked but fatal — a malformed
//! placeholder, or a reference to a value no layer declares, cannot be fixed by
//! answering a prompt.
//!
//! A `file` that reaches a `path` value is refused either way, since a `path`
//! value is absolute and `file` is relative to the repo root. When only
//! committed declarations lead there, it is the repo's defect and fails the
//! load. When the way there runs through this account's answer — `s =
//! "{{b}}"` into `file = "cfg/{{s}}/x"`, with `b` a `path` value — the target
//! is blocked, naming that answer's line, whether or not `b` is answered.
//!
//! A value of any other kind whose text is absolute, or opens with `~`, is
//! refused in `file` too, judged on the text substituted in rather than the
//! declared kind: `cfg/{{dir}}/x` with a `string` value `dir` answered
//! `/home/example/…` would otherwise carry the account's machine location into
//! the repo. An answer blocks the target, naming its line; a committed
//! `default` with no answer in it fails the load.

mod repo_file;
mod requirement;
mod substitute;

use std::path::Path;

use super::external::External;
use super::merge::Conflict;
use super::target::{Body, Target};
use super::values::{ResolvedValues, Unresolved, ValueAssignment};
use super::{Config, Error};
use crate::paths::Portable;
use repo_file::{refuse_path_answer_in_file, refuse_path_value_in_file, repo_file};
use requirement::refuse_committed_requirement;
use substitute::{Broken, for_each_string, substituted};

/// The vocabulary a resolution is reported in, defined in
/// [`super::resolution`] and named here too, where every caller that resolves
/// a configuration already looks.
pub use super::resolution::{BlockReason, BlockedEntry, Resolution};

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
    /// Every enabled `[[external]]`, in the resolved configuration's order.
    ///
    /// Nothing in one is substituted, so none is ever held back: an external
    /// the configuration can name is ready, and one it cannot failed the load.
    pub externals: Vec<External>,
    /// The merged `[secrets]` table: nothing in it is substituted.
    pub secrets: super::secrets::Secrets,
    /// Every enabled `[[tool]]`, in the resolved configuration's order.
    ///
    /// Nothing in one is substituted, so none is ever held back.
    pub tools: Vec<super::tool::ToolDecl>,
    /// The merged `[update]` table: nothing in it is substituted.
    pub update: super::update::Update,
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
/// references a later value, a `default` that is not of its kind with no
/// account answer involved, a target field that substitution makes invalid
/// with no account answer in it, a `file` that references a `path` value,
/// answered or not, or a `requires` entry no answer could make a tool bx can
/// look up; for an `[[env]]` value that is a repo defect, as
/// [`crate::shell::placement::place_envs`] lists, and a home that cannot hold
/// bash's files' paths; for a `[[function]]` body holding a malformed placeholder,
/// a reference to a value no layer declares, or a committed `default` it
/// cannot hold; for a `[[source]]` path referencing a value no layer declares,
/// or made unwritable by a committed `default`; for two enabled plugins that
/// claim the terminal slot; for two ready targets that name one file; and for
/// an external whose checkout overlaps another external's or a ready target's
/// path.
///
/// # Placement
///
/// `place` derives the targets the configuration's shell declarations land
/// in from the merged configuration and its resolved values; they follow
/// every declared target, and are held to the same refusals. The caller hands
/// it over — [`crate::shell::placement::place`] in every caller but a test —
/// because which files a shell reads, and what goes in them, is
/// [`crate::shell`]'s, and this module reads nothing of it.
pub fn resolve(
    merged: &Config,
    home: &Path,
    place: impl FnOnce(&Config, &ResolvedValues) -> Result<Vec<Resolution<Target>>, Error>,
) -> Result<Resolved, Error> {
    let values = ResolvedValues::resolve(merged.values.clone(), &merged.value_assignments, home)?;

    let mut targets = merged
        .targets
        .iter()
        .map(|target| {
            resolve_target(
                target,
                &values,
                &merged.value_assignments,
                &merged.conflicts,
            )
        })
        .collect::<Result<Vec<_>, Error>>()?;
    targets.extend(place(merged, &values)?);

    refuse_shared_files(&targets)?;
    refuse_overlapping_externals(&merged.externals, &targets)?;

    Ok(Resolved {
        values,
        targets,
        externals: merged.externals.clone(),
        secrets: merged.secrets.clone(),
        tools: merged.tools.clone(),
        update: merged.update.clone(),
    })
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

/// Refuse an external whose checkout overlaps another external's or a ready
/// target's path.
///
/// A checkout is a directory git owns whole. A target at or beneath it would
/// be a file bx writes into somebody else's working tree, leaving it with
/// uncommitted changes that stop every later move to a new `rev`. One external
/// beneath another is the same thing from git's side: the inner clone is an
/// untracked directory in the outer. And an external at or above a target's
/// path would clone over, or into the parent of, a file bx already writes.
///
/// The one overlap allowed is an external strictly beneath a `dir` target:
/// that target only makes sure the directory exists, and a clone inside it
/// changes nothing it claims.
///
/// Decided lexically on the normalised paths, as every other path comparison
/// in resolution is, and over ready targets only: a held-back target's file is
/// not known yet.
///
/// # Errors
///
/// [`Error::BadValue`] at the later entry's origin, naming the other one.
fn refuse_overlapping_externals(
    externals: &[External],
    targets: &[Resolution<Target>],
) -> Result<(), Error> {
    for (index, later) in externals.iter().enumerate() {
        if let Some(earlier) = externals[..index]
            .iter()
            .find(|earlier| overlap(&earlier.path, &later.path).is_some())
        {
            return Err(Error::BadValue {
                origin: later.origin.clone(),
                message: format!(
                    "external `{}` overlaps external `{}` at {}; one checkout inside \
                     another is an untracked directory in it",
                    later.path, earlier.path, earlier.origin
                ),
            });
        }
    }

    // A link's children land in its `to`: inside any checkout, they would be
    // untracked files in it, as a target there would be; above one, a child
    // could take the checkout's own name, or a directory on its way, and be
    // a link another external is then cloned through.
    for (linking, link) in externals
        .iter()
        .flat_map(|external| external.links.iter().map(move |link| (external, link)))
    {
        if let Some((external, at)) = externals
            .iter()
            .find_map(|external| overlap(&external.path, &link.to).map(|at| (external, at)))
        {
            let place = if at == Overlap::Above {
                "above"
            } else {
                "inside"
            };
            return Err(Error::BadValue {
                origin: link.origin.clone(),
                message: format!(
                    "a link of external `{}` puts its children in `{}`, {place} external \
                     `{}` at {}; a checkout is a directory git owns whole",
                    linking.path, link.to, external.path, external.origin
                ),
            });
        }
    }

    for target in targets.iter().filter_map(|resolution| match resolution {
        Resolution::Ready(target) => Some(target),
        Resolution::Blocked(_) => None,
    }) {
        for external in externals {
            let allowed = matches!(target.body, Body::Dir)
                && overlap(&target.path, &external.path) == Some(Overlap::Beneath);
            if overlap(&external.path, &target.path).is_some() && !allowed {
                return Err(Error::BadValue {
                    origin: external.origin.clone(),
                    message: format!(
                        "external `{}` overlaps the target `{}` at {}; a checkout is a \
                         directory git owns whole, so no target may be written at, inside \
                         or above it",
                        external.path, target.path, target.origin
                    ),
                });
            }
        }
    }
    Ok(())
}

/// How one normalised path lies relative to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overlap {
    /// The two are one path.
    Same,
    /// The second lies strictly beneath the first.
    Beneath,
    /// The first lies strictly beneath the second.
    Above,
}

/// Whether `a` and `b` are one path or one lies beneath the other, and which.
fn overlap(a: &Portable, b: &Portable) -> Option<Overlap> {
    let beneath = |outer: &str, inner: &str| {
        inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('/') || outer.ends_with('/'))
    };
    let (a, b) = (a.as_str(), b.as_str());
    if a == b {
        Some(Overlap::Same)
    } else if beneath(a, b) {
        Some(Overlap::Beneath)
    } else if beneath(b, a) {
        Some(Overlap::Above)
    } else {
        None
    }
}

/// Substitute one target, or explain why it cannot be.
///
/// `assignments` are this account's answers as written, which `values` no
/// longer holds once substituted. `conflicts` are the files a layer named twice
/// because of this account's answers; a target that resolves to one of them is
/// blocked rather than ready.
fn resolve_target(
    target: &Target,
    values: &ResolvedValues,
    assignments: &[ValueAssignment],
    conflicts: &[Conflict],
) -> Result<Resolution<Target>, Error> {
    if let Some((key, file)) = repo_file(&target.body) {
        refuse_path_value_in_file(target, key, &file, values)?;
    }
    for tool in &target.requires {
        refuse_committed_requirement(target, tool)?;
    }

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

    // Ahead of the blocks the probe found: each of them names an act —
    // answering a value, changing an answer — that would leave this target
    // blocked here. Behind the repo defects above, which no answer could
    // clear.
    //
    // What this ordering does for a switched-off declaration is left to the
    // tests, which hold three different answers to it — the paragraph that
    // tried to summarise them was wrong three times.
    // `a_path_answer_block_outranks_an_unrelated_disabled_or_invalid_value`,
    // `a_switched_off_declaration_is_walked_through_by_its_default` and
    // `a_disabled_value_s_answer_is_not_walked`.
    if let Some((key, file)) = repo_file(&target.body)
        && let Some((names, hint)) =
            refuse_path_answer_in_file(target, key, &file, values, assignments)
    {
        return block(BlockReason::InvalidValue { names }, hint);
    }

    // A switched-off declaration is reported ahead of an unanswered one: it is
    // the more specific statement about what this target is waiting for.
    if !disabled.is_empty() {
        let names = values.in_declaration_order(disabled);
        let hint =
            super::values::disabled_hint(&names.iter().map(String::as_str).collect::<Vec<_>>());
        return block(BlockReason::DisabledValue { names }, hint);
    }

    // An invalid value ahead of an unanswered one: answering would not clear it.
    if !invalid.is_empty() {
        let names = values.in_declaration_order(invalid);
        let hint = values.invalid_hint(&names);
        return block(BlockReason::InvalidValue { names }, hint);
    }

    if !unset.is_empty() {
        let names = values.in_declaration_order(unset);
        let hint = super::values::init_hint(&names.iter().map(String::as_str).collect::<Vec<_>>());
        return block(BlockReason::UnsetValue { names }, hint);
    }

    match substituted(target, values) {
        // One file a layer named twice because of this account's answers. Each
        // entry for it is held back in its own position, naming the lines.
        Ok(ready) => {
            let clashes: Vec<&Conflict> = conflicts
                .iter()
                .filter(|conflict| conflict.file == ready.path.as_str())
                .collect();
            if clashes.is_empty() {
                return Ok(Resolution::Ready(ready));
            }
            let names = values.in_declaration_order(
                clashes
                    .iter()
                    .flat_map(|conflict| conflict.names.iter().cloned())
                    .collect(),
            );
            let hint = clashes
                .iter()
                .map(|conflict| conflict.hint.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            block(BlockReason::InvalidValue { names }, hint)
        }
        Err(Broken::Defect(error)) => Err(error),
        // A field substitution made invalid. With an account answer in it, the
        // answer is the account's to change, so it costs this target and names
        // the line; nothing is written either way. With none, the committed
        // repo wrote it, and no answer could fix it.
        Err(Broken::Field { raw, problem }) => {
            let problem = format!("target `{}`: {problem}", target.path);
            let causes = values.account_inputs(&raw);
            if causes.is_empty() {
                return Err(Error::BadValue {
                    origin: target.origin.clone(),
                    message: problem,
                });
            }
            let names = values.in_declaration_order(causes);
            let hint = values.answers_hint(&problem, &[raw.as_str()], &names);
            block(BlockReason::InvalidValue { names }, hint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::env::{Fragment, Syntax, Var};
    use crate::config::merge::merge;
    use crate::config::target::{Attach, Format, Gen, Interactive};
    use crate::config::{Layer, LayerKind, parse_str};
    use crate::shell::placement::{place, vacated_fragments};
    use std::path::PathBuf;

    pub(super) fn home() -> PathBuf {
        PathBuf::from("/var/home/example")
    }

    /// Build a layer of the given kind out of TOML.
    ///
    /// A parse failure is returned rather than panicked, because some of the
    /// rules under test — a target path that opens with a placeholder — are
    /// enforced by the parser rather than by resolution.
    pub(super) fn layer(file: &str, kind: LayerKind, text: &str) -> Result<Layer, String> {
        Ok(Layer {
            file: PathBuf::from(file),
            kind,
            config: parse_str(text, Path::new(file), &home())
                .map_err(|e| format!("{file}: {e}"))?,
        })
    }

    /// Merge and resolve a global layer and an optional local one.
    pub(super) fn resolved(global: &str, local: Option<&str>) -> Result<Resolved, String> {
        let mut layers = vec![layer("bx.toml", LayerKind::Global, global)?];
        if let Some(local) = local {
            layers.push(layer("local.toml", LayerKind::Local, local)?);
        }
        let merged = merge(&layers, &home()).map_err(|e| e.to_string())?;
        resolve(&merged, &home(), place).map_err(|e| e.to_string())
    }

    /// The resolved targets' keys, blocked ones included and in position.
    pub(super) fn keys(resolved: &Resolved) -> Vec<String> {
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
    pub(super) fn ready(resolved: &Resolved, index: usize) -> &Target {
        match &resolved.targets[index] {
            Resolution::Ready(target) => target,
            Resolution::Blocked(entry) => panic!("blocked: {}", entry.hint),
        }
    }

    /// The one target, expected to be `Blocked`.
    pub(super) fn blocked(resolved: &Resolved, index: usize) -> &BlockedEntry {
        match &resolved.targets[index] {
            Resolution::Blocked(entry) => entry,
            Resolution::Ready(target) => panic!("unexpectedly ready: {}", target.path),
        }
    }

    /// One `[[external]]` entry, as TOML.
    fn external(path: &str) -> String {
        format!(
            "[[external]]\npath = \"{path}\"\nurl = \"https://h/o/a\"\nrev = \"{}\"\n",
            "a".repeat(40)
        )
    }

    #[test]
    fn enabled_externals_resolve_in_order_as_written() {
        let resolved = resolved(
            &format!(
                "{}{}{}enabled = false\n",
                external("~/b"),
                external("~/a"),
                external("~/off")
            ),
            None,
        )
        .unwrap();
        let paths: Vec<&str> = resolved.externals.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["~/b", "~/a"]);
        assert!(resolved.targets.is_empty(), "an external is not a target");
    }

    #[test]
    fn an_external_overlapping_another_is_refused_naming_both() {
        for (first, second) in [("~/a", "~/a/b"), ("~/a/b", "~/a")] {
            let err = resolved(&format!("{}{}", external(first), external(second)), None)
                .expect_err("one checkout inside another");
            assert!(err.starts_with("bx.toml:5: "), "{err}");
            assert!(
                err.contains(&format!(
                    "external `{second}` overlaps external `{first}` at bx.toml:1"
                )),
                "{err}"
            );
        }
        // A shared prefix that is not a parent is no overlap.
        assert!(resolved(&format!("{}{}", external("~/a"), external("~/ab")), None).is_ok());
    }

    #[test]
    fn a_followed_external_places_the_update_prompt_and_a_pinned_one_does_not() {
        let interactive = |text: &str| -> Option<String> {
            let resolved = resolved(text, None).unwrap();
            resolved
                .targets
                .iter()
                .find_map(|resolution| match resolution {
                    Resolution::Ready(Target {
                        body: Body::Generated(generated @ Gen::Interactive(_)),
                        ..
                    }) => Some(generated.render(&|_| true)),
                    _ => None,
                })
        };
        assert_eq!(
            interactive(&external("~/a")),
            None,
            "a pinned external alone"
        );

        let followed = "[[external]]\npath = \"~/a\"\nurl = \"https://h/o/a\"\nbranch = \"main\"\n";
        let file = interactive(followed).expect("placed for the prompt alone");
        assert!(file.contains("precmd_functions+=(__bx_update)"), "{file}");

        let alias = "[[alias]]\nname = \"ll\"\ncommand = \"ls -l\"\n";
        let without = interactive(&format!("{alias}{}", external("~/a"))).expect("an alias");
        assert!(!without.contains("__bx_update"), "{without}");
        let with = interactive(&format!("{alias}{followed}")).expect("an alias");
        assert!(
            with.contains("alias ll") && with.contains("__bx_update"),
            "{with}"
        );
    }

    #[test]
    fn a_link_into_another_external_is_refused_naming_both() {
        for to in ["~/b", "~/b/sub"] {
            let text = format!(
                "{}[[external.link]]\nfrom = \"*\"\nto = \"{to}/*\"\n{}",
                external("~/a"),
                external("~/b")
            );
            let err = resolved(&text, None).expect_err(to);
            assert!(err.starts_with("bx.toml:5: "), "at the link: {err}");
            assert!(
                err.contains(&format!(
                    "puts its children in `{to}`, inside external `~/b`"
                )),
                "{err}"
            );
        }
        let beside = format!(
            "{}[[external.link]]\nfrom = \"*\"\nto = \"~/bin/*\"\n{}",
            external("~/a"),
            external("~/b")
        );
        assert!(resolved(&beside, None).is_ok());
    }

    #[test]
    fn a_link_above_an_external_is_refused_since_a_child_could_take_its_way() {
        for (to, other) in [("~/src", "~/src/b"), ("~/src", "~/src/b/c"), ("~", "~/b")] {
            let text = format!(
                "{}[[external.link]]\nfrom = \"*\"\nto = \"{to}/*\"\n{}",
                external("~/a"),
                external(other)
            );
            let err = resolved(&text, None).expect_err(to);
            assert!(err.starts_with("bx.toml:5: "), "at the link: {err}");
            assert!(
                err.contains(&format!("in `{to}`, above external `")),
                "{err}"
            );
        }
    }

    #[test]
    fn an_external_overlapping_a_ready_target_is_refused() {
        for (target, body) in [
            ("~/a", "content = \"x\""),
            ("~/a/file", "content = \"x\""),
            ("~/a/sub", "dir = true"),
            ("~/a", "dir = true"),
        ] {
            let text = format!(
                "{}[[target]]\npath = \"{target}\"\n{body}\n",
                external("~/a")
            );
            let err = resolved(&text, None).expect_err(&format!("{target} with {body}"));
            assert!(err.starts_with("bx.toml:1: "), "{target}: {err}");
            assert!(
                err.contains(&format!("overlaps the target `{target}` at bx.toml:5")),
                "{target}: {err}"
            );
        }
        // A file target above the checkout would be cloned into.
        let above = format!(
            "{}[[target]]\npath = \"~/x\"\ncontent = \"x\"\n",
            external("~/x/b")
        );
        let err = resolved(&above, None).unwrap_err();
        assert!(err.contains("overlaps the target `~/x`"), "{err}");
        // A sibling is no overlap.
        let sibling = format!(
            "{}[[target]]\npath = \"~/x/a\"\ncontent = \"x\"\n",
            external("~/x/b")
        );
        assert!(resolved(&sibling, None).is_ok());
    }

    #[test]
    fn an_external_beneath_a_dir_target_or_beside_a_blocked_one_resolves() {
        let text = format!(
            "{ABC}{}[[target]]\npath = \"~/x\"\ndir = true\n\
             [[target]]\npath = \"~/x/b/{{{{b}}}}\"\ncontent = \"x\"\n",
            external("~/x/b")
        );
        let resolved = resolved(&text, None).unwrap();
        assert_eq!(resolved.externals.len(), 1);
        assert!(matches!(resolved.targets[1], Resolution::Blocked(_)));
    }

    /// One `[[env]]` entry, as TOML.
    fn env(name: &str, value: &str, kind: &str) -> String {
        format!("[[env]]\nname = \"{name}\"\nvalue = \"{value}\"\nkind = \"{kind}\"\n")
    }

    /// Three string values: `a` answered, `b` unanswered, `c` switched off.
    const ABC: &str = "[[value]]\nname = \"a\"\nkind = \"string\"\ndefault = \"x\"\n\
                       [[value]]\nname = \"b\"\nkind = \"string\"\n\
                       [[value]]\nname = \"c\"\nkind = \"string\"\ndefault = \"z\"\n\
                       enabled = false\n";

    #[test]
    fn no_env_entry_places_nothing() {
        let resolved = resolved("", None).unwrap();
        assert!(resolved.targets.is_empty());
    }

    #[test]
    fn the_placement_graph_emits_each_fragment_before_its_region_after_the_targets() {
        let global = format!(
            "{}{}{}",
            "[[target]]\npath = \"~/.a\"\ncontent = \"x\"\n",
            env("EDITOR", "{{a}}", "interactive"),
            env("LANG", "C", "gui"),
        );
        let resolved = resolved(&format!("{ABC}{global}"), None).unwrap();
        assert_eq!(
            keys(&resolved),
            vec![
                "~/.a",
                "~/.config/environment.d/50-bx.conf",
                "~/.local/share/bx/zshrc.zsh",
                "~/.zshrc",
                "~/.local/share/bx/bashrc.bash",
                "~/.bashrc",
            ]
        );
        let env_d = ready(&resolved, 1);
        assert_eq!(env_d.format, Format::EnvD);
        assert_eq!(env_d.attach, Attach::Own);
        let zshrc_fragment = ready(&resolved, 2);
        assert_eq!(
            zshrc_fragment.body,
            Body::Generated(Gen::Interactive(Box::new(Interactive::new(Fragment {
                syntax: Syntax::Zsh,
                vars: vec![Var::always("EDITOR", "x")],
                path: Vec::new(),
            }))))
        );
        assert_eq!(zshrc_fragment.format, Format::Opaque);
        // Attributed to the variable that put it there.
        assert_eq!(
            zshrc_fragment.origin.line,
            ready(&resolved, 0).origin.line + 3
        );
        let region = ready(&resolved, 3);
        assert_eq!(region.attach, Attach::Region { comment: '#' });
        assert_eq!(
            region.body,
            Body::Generated(Gen::Source(zshrc_fragment.path.clone()))
        );
    }

    #[test]
    fn zsh_s_interactive_row_names_every_declaration_kept_from_zsh() {
        let both = resolved(
            &format!(
                "{}{}shells = [\"bash\"]\n{}shells = [\"zsh\"]\n\
                 [[function]]\nname = \"fb\"\nbody = \"echo b\"\nshells = [\"bash\"]\n\
                 [[function]]\nname = \"off\"\nbody = \"x\"\nshells = [\"bash\"]\nenabled = false\n\
                 [[source]]\nname = \"sb\"\npath = \"~/.bash_extra\"\nshells = [\"bash\"]\n\
                 [[activation]]\nname = \"ab\"\ncommand = [\"a\", \"{{shell}}\"]\n\
                 shells = [\"bash\"]\n\
                 [[activation]]\nname = \"bonly\"\nbash = [\"b\", \"init\"]\n\
                 [[activation]]\nname = \"both\"\ncommand = [\"c\", \"{{shell}}\"]\n",
                env("EDITOR", "nvim", "interactive"),
                env("BONLY", "1", "login"),
                env("ZONLY", "1", "interactive"),
            ),
            None,
        )
        .unwrap();
        let zshrc = target_at(&both, "~/.local/share/bx/zshrc.zsh");
        let Body::Generated(generator) = &zshrc.body else {
            panic!("{:?}", zshrc.body);
        };
        // Every enabled entry `shells` keeps from zsh, in declaration-kind
        // order, then the activation that reaches zsh with no zsh command.
        // The disabled function, the zsh-only variable and the shared
        // activation are not named.
        assert_eq!(
            generator.note().as_deref(),
            Some(
                "not in zsh: env `BONLY`, function `fb`, source `sb`, activation `ab`; \
                 activation `bonly` declares no zsh command, so it is not run for zsh"
            )
        );
        // The bash-only variable reaches none of zsh's files.
        assert!(
            !keys(&both).iter().any(|key| key.ends_with("zprofile.zsh")),
            "{:?}",
            keys(&both)
        );
    }

    /// The ready target at `path`.
    fn target_at<'r>(resolved: &'r Resolved, path: &str) -> &'r Target {
        let index = keys(resolved)
            .iter()
            .position(|key| key == path)
            .unwrap_or_else(|| panic!("{path}: {:?}", keys(resolved)));
        ready(resolved, index)
    }

    /// One `[[plugin]]` entry, as TOML.
    fn plugin(name: &str, terminal: bool) -> String {
        format!(
            "[[plugin]]\nname = \"{name}\"\nsource = \"~/.zsh/{name}.zsh\"\nterminal = {terminal}\n"
        )
    }

    #[test]
    fn declared_plugins_land_in_the_interactive_file_and_alone_still_place_it() {
        // Beside an interactive variable: one file, attributed to the variable.
        let both = resolved(
            &format!(
                "{}{}",
                plugin("p", false),
                env("EDITOR", "nvim", "interactive")
            ),
            None,
        )
        .unwrap();
        // The variable reaches bash's file too; the plugin, zsh's alone.
        assert_eq!(
            keys(&both),
            vec![
                "~/.local/share/bx/zshrc.zsh",
                "~/.zshrc",
                "~/.local/share/bx/bashrc.bash",
                "~/.bashrc",
            ]
        );
        let file = ready(&both, 0);
        assert_eq!(file.origin.line, 5, "the variable's line");
        let Body::Generated(Gen::Interactive(interactive)) = &file.body else {
            panic!("{:?}", file.body);
        };
        assert_eq!(interactive.env().vars, vec![Var::always("EDITOR", "nvim")]);
        let names: Vec<&str> = interactive
            .plugins()
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, ["p"]);

        // Alone: the file and its region, attributed to the first enabled plugin.
        let alone = resolved(
            &format!(
                "[[plugin]]\nname = \"off\"\nsource = \"~/off.zsh\"\nenabled = false\n{}",
                plugin("p", true)
            ),
            None,
        )
        .unwrap();
        assert_eq!(
            keys(&alone),
            vec!["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
        );
        assert_eq!(ready(&alone, 0).origin.line, 5);
        assert_eq!(ready(&alone, 1).origin.line, 5);

        // Only a switched-off plugin: nothing is placed.
        let off = resolved(
            "[[plugin]]\nname = \"off\"\nsource = \"~/off.zsh\"\nenabled = false\n",
            None,
        )
        .unwrap();
        assert!(off.targets.is_empty());
    }

    #[test]
    fn a_declared_activation_alone_places_the_interactive_file() {
        // Alone: the file and its region, attributed to the first enabled
        // activation, and holding nothing until the plan attaches it.
        let alone = resolved(
            "[[activation]]\nname = \"off\"\ncommand = [\"off\"]\nenabled = false\n\
             [[activation]]\nname = \"mise\"\ncommand = [\"mise\", \"activate\", \"zsh\"]\n",
            None,
        )
        .unwrap();
        assert_eq!(
            keys(&alone),
            vec!["~/.local/share/bx/zshrc.zsh", "~/.zshrc"]
        );
        assert_eq!(ready(&alone, 0).origin.line, 5);
        assert_eq!(ready(&alone, 1).origin.line, 5);
        let Body::Generated(generator) = &ready(&alone, 0).body else {
            panic!("{:?}", ready(&alone, 0).body);
        };
        assert_eq!(
            generator.render(&|_| true),
            "# Generated by bx. Edit the config repo, not this file.\n"
        );

        // Beside a plugin, the plugin places it.
        let both = resolved(
            &format!(
                "{}[[activation]]\nname = \"mise\"\ncommand = [\"mise\"]\n",
                plugin("p", false)
            ),
            None,
        )
        .unwrap();
        assert_eq!(ready(&both, 0).origin.line, 1);

        // Only a switched-off activation: nothing is placed.
        let off = resolved(
            "[[activation]]\nname = \"off\"\ncommand = [\"off\"]\nenabled = false\n",
            None,
        )
        .unwrap();
        assert!(off.targets.is_empty());
    }

    #[test]
    fn a_held_back_interactive_variable_holds_its_plugins_back_with_it() {
        let held = resolved(
            &format!(
                "{ABC}{}{}",
                plugin("p", false),
                env("EDITOR", "{{b}}", "interactive")
            ),
            None,
        )
        .unwrap();
        assert_eq!(blocked(&held, 0).key, "~/.local/share/bx/zshrc.zsh");
        // The region still sources it once it is there.
        assert_eq!(ready(&held, 1).path.to_string(), "~/.zshrc");
    }

    #[test]
    fn resolving_a_configuration_with_two_terminal_claimants_fails() {
        // `merge` refuses them first; a `Config` built another way is refused
        // here too, so no rendered file ever holds two.
        let mut merged = merge(
            &[layer("bx.toml", LayerKind::Global, &plugin("one", true)).unwrap()],
            &home(),
        )
        .unwrap();
        let mut second = merged.plugins[0].clone();
        second.name = "two".to_string();
        merged.plugins.push(second);
        let err = resolve(&merged, &home(), place)
            .expect_err("refused")
            .to_string();
        assert!(
            err.contains("plugin `two` claims the terminal slot"),
            "{err}"
        );
        assert!(err.contains("plugin `one` already claims"), "{err}");
    }

    #[test]
    fn a_recorded_interactive_file_nothing_places_is_planned_empty() {
        let ledger = Path::new("/var/home/example/.local/state/bx/ledger");
        let every = vacated_fragments(&[], |_| true, |_, _| true, &home(), ledger);
        let Some(Resolution::Ready(file)) = every.iter().find(|resolution| {
            matches!(resolution, Resolution::Ready(target)
                if target.path.as_str() == "~/.local/share/bx/zshrc.zsh")
        }) else {
            panic!("{every:?}");
        };
        assert_eq!(
            file.body,
            Body::Generated(Gen::Interactive(Box::new(Interactive::new(Fragment {
                syntax: Syntax::Zsh,
                vars: Vec::new(),
                path: Vec::new(),
            }))))
        );
    }

    #[test]
    fn a_recorded_fragment_no_place_names_is_planned_empty_and_no_other() {
        // environment.d is held back on `b`, zshrc.zsh is placed, and the
        // other two fragments are named by nothing.
        let placed = resolved(
            &format!(
                "{ABC}{}{}",
                env("X", "{{b}}", "gui"),
                env("EDITOR", "nvim", "interactive")
            ),
            None,
        )
        .unwrap();
        let ledger = Path::new("/var/home/example/.local/state/bx/ledger");
        // Only zsh's fragments are recorded: bash's files are
        // `shell::bash::vacated`'s to test.
        let zsh = |path: &Portable| path.as_str().ends_with(".zsh");
        let every = vacated_fragments(&placed.targets, zsh, |_, _| false, &home(), ledger);
        let paths: Vec<String> = every
            .iter()
            .map(|resolution| match resolution {
                Resolution::Ready(target) => {
                    assert_eq!(
                        target.body,
                        Body::Generated(Gen::Env(Fragment {
                            syntax: Syntax::Zsh,
                            vars: Vec::new(),
                            path: Vec::new(),
                        }))
                    );
                    assert_eq!(target.origin.file, ledger);
                    target.path.to_string()
                }
                Resolution::Blocked(entry) => panic!("{entry:?}"),
            })
            .collect();
        assert_eq!(
            paths,
            vec![
                "~/.local/share/bx/zshenv.zsh",
                "~/.local/share/bx/zprofile.zsh"
            ]
        );
        // Nothing bx has not written is planned.
        assert!(
            vacated_fragments(&placed.targets, |_| false, |_, _| false, &home(), ledger).is_empty()
        );
    }

    #[test]
    fn a_fragment_held_back_names_its_most_specific_reason_across_its_variables() {
        // Unanswered alone: the values to answer, and `bx init`.
        let unset = resolved(&format!("{ABC}{}", env("X", "{{b}}", "gui")), None).unwrap();
        let entry = blocked(&unset, 0);
        assert_eq!(entry.key, "~/.config/environment.d/50-bx.conf");
        assert_eq!(
            entry.reason,
            BlockReason::UnsetValue {
                names: vec!["b".to_string()]
            }
        );
        assert!(entry.hint.contains("bx init"), "{}", entry.hint);

        // Switched off outranks unanswered, across two variables.
        let both = resolved(
            &format!(
                "{ABC}{}{}{}",
                env("X", "{{b}}", "gui"),
                env("Y", "{{c}}", "environment"),
                env("Z", "{{a}}", "gui"),
            ),
            None,
        )
        .unwrap();
        // zshenv and bash's file hold only Y; environment.d holds X, Y and
        // Z.
        assert_eq!(
            keys(&both),
            vec![
                "~/.local/share/bx/zshenv.zsh",
                "~/.zshenv",
                "~/.config/environment.d/50-bx.conf",
                "~/.local/share/bx/bashrc.bash",
                "~/.bashrc",
            ]
        );
        // bash's file is held back by Y as zshenv is, and its region is not.
        assert_eq!(
            blocked(&both, 3).reason,
            BlockReason::DisabledValue {
                names: vec!["c".to_string()]
            }
        );
        ready(&both, 4);
        assert_eq!(
            blocked(&both, 2).reason,
            BlockReason::DisabledValue {
                names: vec!["c".to_string()]
            }
        );
        // The region is never held back.
        ready(&both, 1);

        // An unusable answer outranks unanswered too, and names its line.
        let invalid = resolved(
            &format!(
                "{ABC}{}{}",
                env("X", "{{b}}", "gui"),
                env("Y", "{{a}}", "gui")
            ),
            Some("[values]\na = \"say \\\"hi\\\"\"\n"),
        )
        .unwrap();
        let entry = blocked(&invalid, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["a".to_string()]
            }
        );
        assert!(entry.hint.contains("control character"), "{}", entry.hint);
        assert!(entry.hint.contains("local.toml"), "{}", entry.hint);
    }

    #[test]
    fn a_value_invalid_for_its_kind_holds_back_its_fragment() {
        let resolved = resolved(
            &format!(
                "{SCRATCH}{}",
                env("SCCACHE_DIR", "{{scratch_root}}/sccache", "login")
            ),
            Some("[values]\nscratch_root = \"relative\"\n"),
        )
        .unwrap();
        let entry = blocked(&resolved, 0);
        assert_eq!(entry.key, "~/.local/share/bx/zprofile.zsh");
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["scratch_root".to_string()]
            }
        );
    }

    #[test]
    fn a_repo_defect_in_an_env_value_fails_the_load() {
        for (global, needle) in [
            (env("X", "{{nobody}}", "gui"), "nobody"),
            (env("X", "{{a", "gui"), "env `X`"),
            (
                format!(
                    "[[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"a`b\"\n{}",
                    env("X", "{{q}}", "gui")
                ),
                "control character",
            ),
        ] {
            let err = resolved(&global, None).expect_err(&global);
            assert!(err.contains(needle), "{global}: {err}");
        }
    }

    #[test]
    fn a_declared_target_may_not_claim_a_file_the_placement_graph_writes() {
        let err = resolved(
            &format!(
                "[[target]]\npath = \"~/.zshrc\"\ncontent = \"mine\"\n{}",
                env("EDITOR", "vi", "interactive")
            ),
            None,
        )
        .expect_err("one file, two targets");
        assert!(err.contains("`~/.zshrc` is the same file"), "{err}");
    }

    /// A declaration and a target that uses it.
    pub(super) const SCRATCH: &str = "[[value]]\n\
                           name = \"scratch_root\"\n\
                           kind = \"path\"\n\
                           required = true\n\
                           is_root = true\n";

    #[test]
    fn the_secrets_table_is_carried_through_resolution() {
        let resolved = resolved(
            "[secrets]\nrecipients = [\"ssh-ed25519 AAAAC3Nz one\"]\n",
            Some("[secrets]\nidentity = \"~/.config/age/key.txt\"\n"),
        )
        .unwrap();
        assert_eq!(
            resolved.secrets.identity_spelling(),
            "~/.config/age/key.txt"
        );
        assert!(resolved.secrets.recipients.is_some());
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

    /// Two committed targets whose paths are two files as written, and one file
    /// when `profile` is answered `default`.
    const PROFILE: &str = "[[value]]\nname = \"profile\"\nkind = \"string\"\n\
                           [[target]]\npath = \"~/.config/{{profile}}/s\"\ncontent = \"PROFILE\"\n\
                           [[target]]\npath = \"~/.config/default/s\"\ncontent = \"DEFAULT\"\n\
                           [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

    #[test]
    fn an_answer_that_makes_one_layer_name_one_file_twice_blocks_both_and_nothing_else() {
        // The panel's falsifier. `profile = "default"` made two committed
        // targets one file, and the whole load failed naming `bx.toml`, which
        // the account cannot edit, taking `~/.zshrc` with it.
        let unanswered = resolved(PROFILE, None).expect("unanswered");
        blocked(&unanswered, 0);
        ready(&unanswered, 1);
        assert_eq!(ready(&unanswered, 2).path.as_str(), "~/.zshrc");

        let work = resolved(PROFILE, Some("[values]\nprofile = \"work\"\n")).expect("work");
        assert_eq!(
            keys(&work),
            ["~/.config/work/s", "~/.config/default/s", "~/.zshrc"]
        );
        ready(&work, 0);
        ready(&work, 1);
        ready(&work, 2);

        let default = resolved(
            PROFILE,
            Some("# this account's answers\n[values]\nprofile = \"default\"\n"),
        )
        .expect("an account's answer does not fail the load");
        assert_eq!(
            keys(&default),
            ["~/.config/{{profile}}/s", "~/.config/default/s", "~/.zshrc"],
            "both targets for the file are held back, each in its own position"
        );
        for index in [0, 1] {
            let entry = blocked(&default, index);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["profile".to_string()]
                }
            );
            for part in [
                "`~/.config/{{profile}}/s` at bx.toml:4",
                "`~/.config/default/s` at bx.toml:7",
                "the answer to `profile` at local.toml:3",
            ] {
                assert!(entry.hint.contains(part), "{part}: {}", entry.hint);
            }
        }
        assert_eq!(ready(&default, 2).path.as_str(), "~/.zshrc");
    }

    #[test]
    fn a_clash_through_a_derived_value_names_the_declaration_between() {
        // `q` defaults to `{{p}}`, so `~/{{p}}/s` and `~/{{q}}/s` are one file for
        // every answer to `p`. Naming only `p` left out the act that clears it:
        // answering `q`. `r` is built from a committed default alone, so no
        // answer is carried through it and it is not named.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{p}}\"\n\
                             [[value]]\nname = \"r\"\nkind = \"string\"\ndefault = \"s\"\n\
                             [[target]]\npath = \"~/{{p}}/s\"\ncontent = \"P\"\n\
                             [[target]]\npath = \"~/{{q}}/{{r}}\"\ncontent = \"Q\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let derived = resolved(LAYER, Some("[values]\np = \"work\"\n"))
            .expect("an account's answer does not fail the load");
        for index in [0, 1] {
            let entry = blocked(&derived, index);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["p".to_string()]
                }
            );
            for part in [
                "`~/{{p}}/s` at bx.toml:12",
                "`~/{{q}}/{{r}}` at bx.toml:15",
                "because of the answer to `p` at local.toml:2, carried in by the default of \
                 `q` at bx.toml:4; change that answer, or answer `q` directly",
            ] {
                assert!(entry.hint.contains(part), "{index} {part}: {}", entry.hint);
            }
            assert!(!entry.hint.contains("`r`"), "{index}: {}", entry.hint);
        }
        ready(&derived, 2);

        // With `q` answered too, nothing is carried in: the hint names both
        // answers and says nothing more.
        let answered = resolved(LAYER, Some("[values]\np = \"work\"\nq = \"work\"\n"))
            .expect("an account's answers do not fail the load");
        let entry = blocked(&answered, 0);
        assert!(
            entry.hint.ends_with(
                "because of the answer to `p` at local.toml:2 and the answer to `q` at \
                 local.toml:3; change that answer"
            ),
            "{}",
            entry.hint
        );
    }

    #[test]
    fn a_clash_through_two_derived_values_names_both_declarations() {
        // `q` and `r` both default to `{{p}}`, so `~/{{q}}/s` and `~/{{r}}/s` are
        // one file for every answer to `p`. Either declaration answered directly
        // clears it, so the hint names both, each once, in declaration order.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{p}}\"\n\
                             [[value]]\nname = \"r\"\nkind = \"string\"\ndefault = \"{{p}}\"\n\
                             [[target]]\npath = \"~/{{q}}/s\"\ncontent = \"Q\"\n\
                             [[target]]\npath = \"~/{{r}}/s\"\ncontent = \"R\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let resolved = resolved(LAYER, Some("[values]\np = \"work\"\n"))
            .expect("an account's answer does not fail the load");
        for index in [0, 1] {
            let entry = blocked(&resolved, index);
            assert!(
                entry.hint.ends_with(
                    "because of the answer to `p` at local.toml:2, carried in by the default \
                     of `q` at bx.toml:4 and the default of `r` at bx.toml:8; change that \
                     answer, or answer `q` or `r` directly"
                ),
                "{index}: {}",
                entry.hint
            );
        }
        ready(&resolved, 2);
    }

    #[test]
    fn a_clash_through_a_chain_of_defaults_names_every_declaration_between() {
        // `t` defaults to `{{q}}`, which defaults to `{{p}}`, which is answered.
        // Answering `t` or `q` directly both separate `~/{{t}}/s` from
        // `~/work/s`, so the hint follows the chain down and names each.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{p}}\"\n\
                             [[value]]\nname = \"t\"\nkind = \"string\"\ndefault = \"{{q}}\"\n\
                             [[target]]\npath = \"~/{{t}}/s\"\ncontent = \"T\"\n\
                             [[target]]\npath = \"~/work/s\"\ncontent = \"W\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let resolved = resolved(LAYER, Some("[values]\np = \"work\"\n"))
            .expect("an account's answer does not fail the load");
        for index in [0, 1] {
            let entry = blocked(&resolved, index);
            assert!(
                entry.hint.ends_with(
                    "because of the answer to `p` at local.toml:2, carried in by the default \
                     of `q` at bx.toml:4 and the default of `t` at bx.toml:8; change that \
                     answer, or answer `q` or `t` directly"
                ),
                "{index}: {}",
                entry.hint
            );
        }
        ready(&resolved, 2);
    }

    #[test]
    fn a_derived_value_every_colliding_spelling_carries_is_not_offered_as_the_way_out() {
        // `q` carries the answer to `o` into both spellings, so answering `q`
        // directly moves both files together and they stay one file. Naming it
        // would be advice that clears nothing, so the hint does not.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"o\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{o}}\"\n\
                             [[target]]\npath = \"~/{{p}}/{{q}}\"\ncontent = \"P\"\n\
                             [[target]]\npath = \"~/work/{{q}}\"\ncontent = \"W\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        for local in [
            "[values]\np = \"work\"\no = \"x\"\n",
            "[values]\np = \"work\"\no = \"x\"\nq = \"y\"\n",
        ] {
            let resolved =
                resolved(LAYER, Some(local)).expect("an account's answers do not fail the load");
            for index in [0, 1] {
                let entry = blocked(&resolved, index);
                assert!(
                    entry.hint.ends_with("; change that answer"),
                    "{local:?} {index}: {}",
                    entry.hint
                );
                for part in ["the default of `q`", "directly"] {
                    assert!(
                        !entry.hint.contains(part),
                        "{local:?} {index} {part}: {}",
                        entry.hint
                    );
                }
            }
            ready(&resolved, 2);
        }
    }

    #[test]
    fn a_derived_value_one_spelling_carries_twice_is_offered_as_the_way_out() {
        // The exclusion above is by *count*, not by membership. `q` is carried
        // by both spellings, but once by the first and twice by the second, so
        // answering it does part them and the hint has to say so: with
        // `p = ""` both key `~/x`, and `q = "a"` makes them `~/a/x` and
        // `~/aa/x`. Before the count comparison, `q` was excluded and the hint
        // named only `p`, whose every answer keeps them one file or parts the
        // pair the same way.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{p}}\"\n\
                             [[target]]\npath = \"~/{{q}}/x\"\ncontent = \"ONE\"\n\
                             [[target]]\npath = \"~/{{q}}{{q}}/x\"\ncontent = \"TWO\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let blocking = resolved(LAYER, Some("[values]\np = \"\"\n"))
            .expect("an account's answer blocks the file, not the load");
        // A blocked entry is keyed by its spelling; both name `~/x` once `q` is
        // empty, which is why they collide at all.
        assert_eq!(keys(&blocking), ["~/{{q}}/x", "~/{{q}}{{q}}/x", "~/.zshrc"]);
        for index in [0, 1] {
            let entry = blocked(&blocking, index);
            assert!(
                entry.hint.ends_with(
                    "because of the answer to `p` at local.toml:2, carried in by the default of \
                     `q` at bx.toml:4; change that answer, or answer `q` directly"
                ),
                "{index}: {}",
                entry.hint
            );
        }

        // The act the hint names is one that clears the block.
        let cleared = resolved(LAYER, Some("[values]\np = \"\"\nq = \"a\"\n"))
            .expect("answering `q` directly parts the two spellings");
        assert_eq!(keys(&cleared), ["~/a/x", "~/aa/x", "~/.zshrc"]);
        for index in [0, 1, 2] {
            ready(&cleared, index);
        }
    }

    #[test]
    fn a_derived_value_two_of_three_colliding_spellings_carry_is_offered_as_the_way_out() {
        // Three spellings for one file. `q` is carried by two of them and not
        // by the third, so it is in a separating position and the hint names
        // it. The third spelling is what makes the deduplication guard matter:
        // `q` is reached once per spelling that carries it and named once.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{p}}\"\n\
                             [[target]]\npath = \"~/{{q}}/x\"\ncontent = \"ONE\"\n\
                             [[target]]\npath = \"~/{{q}}{{q}}/x\"\ncontent = \"TWO\"\n\
                             [[target]]\npath = \"~/{{p}}/x\"\ncontent = \"THREE\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let blocking = resolved(LAYER, Some("[values]\np = \"\"\n"))
            .expect("an account's answer blocks the file, not the load");
        assert_eq!(
            keys(&blocking),
            ["~/{{q}}/x", "~/{{q}}{{q}}/x", "~/{{p}}/x", "~/.zshrc"]
        );
        for index in [0, 1, 2] {
            let hint = &blocked(&blocking, index).hint;
            assert!(hint.ends_with("or answer `q` directly"), "{index}: {hint}");
            assert_eq!(
                hint.matches("`q`").count(),
                2,
                "named once in the defaults and once in the direct list: {hint}"
            );
        }
    }

    #[test]
    fn a_derived_value_reached_down_two_defaults_is_named_once() {
        // `left` and `right` both default to `{{shared}}`, so one text reaches
        // `shared` twice, by two different routes, and every value on the way
        // is an act that clears the entry. `shared` is offered once and in
        // declaration order. `add_reach` is what keeps it to one entry with one
        // total, which
        // `derived_between_names_a_value_reached_down_two_defaults_once` pins
        // directly; here the interest is that the whole chain reaches the
        // account.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[value]]\nname = \"shared\"\nkind = \"string\"\n\
                             default = \"{{p}}\"\n\
                             [[value]]\nname = \"left\"\nkind = \"string\"\n\
                             default = \"{{shared}}\"\n\
                             [[value]]\nname = \"right\"\nkind = \"string\"\n\
                             default = \"{{shared}}\"\n\
                             [[target]]\npath = \"~/.config/zed/settings.json\"\n\
                             content = \"{{{{}}\"\n\
                             format = \"jsonc\"\nowns = [\"a.{{left}}{{right}}\"]\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let answered = resolved(LAYER, Some("[values]\np = \"b.c\"\n"))
            .expect("an account's answer blocks its target, not the load");
        let hint = &blocked(&answered, 0).hint;
        assert_eq!(
            hint.matches("`shared`").count(),
            2,
            "one default entry and one direct entry, not two of each: {hint}"
        );
        assert!(
            hint.ends_with("change that answer, or answer `shared` or `left` or `right` directly"),
            "{hint}"
        );
        ready(&answered, 1);
    }

    #[test]
    fn a_dotdot_against_a_placeholder_is_not_one_path_as_written() {
        // Reduced with its placeholder left in, `~/.config/{{p}}/../s` folds to
        // `~/.config/s`, which read as proof that the toggle and the first entry
        // are one path for every answer. They are not: `p = "a/b"` makes the
        // toggle `~/.config/a/s`. With `p = "a"` the collision is the answer's,
        // so it blocks the file's row instead of failing the load.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/s\"\ncontent = \"S\"\n\
                             [[target]]\npath = \"~/.config/a/s\"\ncontent = \"AS\"\n\
                             [[target]]\npath = \"~/.config/{{p}}/../s\"\nenabled = false\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let folded = resolved(LAYER, Some("[values]\np = \"a\"\n"))
            .expect("an answer that names one file twice blocks it, not the load");
        assert_eq!(keys(&folded), ["~/.config/s", "~/.config/a/s", "~/.zshrc"]);
        let entry = blocked(&folded, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["p".to_string()]
            }
        );
        for part in [
            "`~/.config/s` at bx.toml:4",
            "`~/.config/{{p}}/../s` at bx.toml:10",
            "the answer to `p` at local.toml:2",
        ] {
            assert!(entry.hint.contains(part), "{part}: {}", entry.hint);
        }
        ready(&folded, 1);
        ready(&folded, 2);

        // The same toggle meeting the other entry, as before.
        let deeper = resolved(LAYER, Some("[values]\np = \"a/b\"\n"))
            .expect("an answer that names one file twice blocks it, not the load");
        assert_eq!(keys(&deeper), ["~/.config/s", "~/.config/a/s", "~/.zshrc"]);
        ready(&deeper, 0);
        blocked(&deeper, 1);
        ready(&deeper, 2);
    }

    #[test]
    fn a_dotdot_pair_that_is_one_path_for_every_answer_is_the_layer_s_defect() {
        // A `bool` holds no `/`, so `~/.config/{{flag}}/../s` is `~/.config/s`
        // for both answers. And `{{p}}/..` against `{{p}}/./..` stay one path
        // whether `p` holds a `/` or not. Neither pair is the answer's doing, so
        // each fails the load rather than blocking with advice no answer could
        // follow.
        const BOOL: &str = "[[value]]\nname = \"flag\"\nkind = \"bool\"\n\
                            [[target]]\npath = \"~/.config/s\"\ncontent = \"S\"\n\
                            [[target]]\npath = \"~/.config/{{flag}}/../s\"\nenabled = false\n\
                            [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";
        for flag in ["true", "false"] {
            let message = resolved(BOOL, Some(&format!("[values]\nflag = {flag}\n")))
                .expect_err("one path for every answer is the layer's defect");
            for part in [
                "bx.toml:7",
                "names the same file as `~/.config/s` at bx.toml:4",
                "in this same layer",
            ] {
                assert!(message.contains(part), "{flag} {part}: {message}");
            }
        }

        const TWICE: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/s\"\ncontent = \"S\"\n\
                             [[target]]\npath = \"~/.config/a/s\"\ncontent = \"AS\"\n\
                             [[target]]\npath = \"~/.config/{{p}}/../s\"\nenabled = false\n\
                             [[target]]\npath = \"~/.config/{{p}}/./../s\"\nenabled = true\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";
        for p in ["a", "a/b"] {
            let message = resolved(TWICE, Some(&format!("[values]\np = \"{p}\"\n")))
                .expect_err("one path for every answer is the layer's defect");
            for part in [
                "bx.toml:13",
                "names the same file as `~/.config/{{p}}/../s` at bx.toml:10",
                "in this same layer",
            ] {
                assert!(message.contains(part), "{p} {part}: {message}");
            }
        }
    }

    #[test]
    fn a_pair_some_answer_separates_blocks_whatever_shape_separates_it() {
        // Each pair is one file for these answers and two files for another, so
        // each blocks the file's row rather than failing the load. What
        // separates them differs: a placeholder only the earlier spelling
        // holds, a placeholder that must be one segment (`~/s` against
        // `~/.config/s`), and a placeholder that is not the first one named.
        const EARLIER_ONLY: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                                    [[value]]\nname = \"q\"\nkind = \"string\"\n\
                                    [[target]]\npath = \"~/.config/s\"\ncontent = \"S\"\n\
                                    [[target]]\npath = \"~/{{q}}/../.config/{{p}}/../s\"\n\
                                    enabled = false\n\
                                    [[target]]\npath = \"~/{{q}}/../.config/s\"\nenabled = true\n\
                                    [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";
        const ONE_SEGMENT: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                                   [[target]]\npath = \"~/.config/s\"\ncontent = \"S\"\n\
                                   [[target]]\npath = \"~/.config/{{p}}/../../s\"\n\
                                   enabled = false\n\
                                   [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";
        const SECOND_NAME: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                                   [[value]]\nname = \"q\"\nkind = \"string\"\n\
                                   [[target]]\npath = \"~/{{p}}/.config/s\"\ncontent = \"S\"\n\
                                   [[target]]\npath = \"~/{{p}}/.config/{{q}}/../s\"\n\
                                   enabled = false\n\
                                   [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        for (layer, answers) in [
            (EARLIER_ONLY, "p = \"b\"\nq = \"a\"\n"),
            (ONE_SEGMENT, "p = \"a/b\"\n"),
            (SECOND_NAME, "p = \"x\"\nq = \"a\"\n"),
        ] {
            let resolved = resolved(layer, Some(&format!("[values]\n{answers}")))
                .unwrap_or_else(|e| panic!("{answers:?} failed the whole load: {e}"));
            let entry = blocked(&resolved, 0);
            assert!(
                matches!(entry.reason, BlockReason::InvalidValue { .. }),
                "{answers:?}: {:?}",
                entry.reason
            );
            ready(&resolved, 1);
        }
    }

    #[test]
    fn a_path_value_pair_apart_only_by_a_dot_segment_fails_the_load() {
        // The toggles `{{root}}/s` and `{{root}}/./s` share an opening segment
        // and differ only by a `.`, which folds, so they are one file for every
        // answer. That holds however the opening segment is rooted; the root a
        // `path` value gives is pinned by
        // `a_path_value_opening_a_spelling_is_rooted_at_slash`. (A full entry
        // may not open with a placeholder; a toggle names a file by the spelling
        // it reaches.)
        const LAYER: &str = "[[value]]\nname = \"root\"\nkind = \"path\"\n\
                             [[target]]\npath = \"/srv/data/s\"\ncontent = \"S\"\n\
                             [[target]]\npath = \"{{root}}/s\"\nenabled = false\n\
                             [[target]]\npath = \"{{root}}/./s\"\nenabled = true\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let message = resolved(LAYER, Some("[values]\nroot = \"/srv/data\"\n"))
            .expect_err("one path for every answer is the layer's defect");
        for part in [
            "bx.toml:10",
            "names the same file as `{{root}}/s` at bx.toml:7",
            "in this same layer",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }

    #[test]
    fn a_path_value_opening_a_spelling_is_rooted_at_slash() {
        // `{{r}}/s` and `/{{r}}/s` differ in their opening segment, and are one
        // file for every answer only because every `path` answer is absolute:
        // the `/` written before it adds nothing. So the pair is the layer's
        // defect, not a block an answer could clear.
        const LAYER: &str = "[[value]]\nname = \"r\"\nkind = \"path\"\n\
                             [[target]]\npath = \"/srv/s\"\ncontent = \"S\"\n\
                             [[target]]\npath = \"{{r}}/s\"\nenabled = false\n\
                             [[target]]\npath = \"/{{r}}/s\"\nenabled = true\n";

        let message = resolved(LAYER, Some("[values]\nr = \"/srv\"\n"))
            .expect_err("one path for every answer is the layer's defect");
        for part in [
            "bx.toml:10",
            "names the same file as `{{r}}/s` at bx.toml:7",
            "in this same layer",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }

    #[test]
    fn a_pair_apart_only_around_its_opening_segment_fails_the_load() {
        // Each pair names one file whatever is answered, so no answer could clear
        // the collision and it is the layer's defect. A `path` answer is
        // absolute, so a `/` before it adds nothing even with text glued on
        // (`{{r}}.d/conf`), and neither does one after a `~` that precedes it
        // (`~{{r}}/s`). An opening segment no answer makes empty (`~{{p}}`, and a
        // lone `email`) is the same path with a separator after it or without.
        let cases = [
            (
                "r",
                "path",
                "/srv.d/conf",
                "{{r}}.d/conf",
                "/{{r}}.d/conf",
                "r = \"/srv\"",
            ),
            (
                "r",
                "path",
                "~/srv/s",
                "~{{r}}/s",
                "~/{{r}}/s",
                "r = \"/srv\"",
            ),
            (
                "p",
                "string",
                "~/work",
                "~{{p}}",
                "~{{p}}/",
                "p = \"/work\"",
            ),
            ("e", "email", "/a@b", "{{e}}", "{{e}}/", "e = \"/a@b\""),
        ];
        let mut loaded = Vec::new();
        for (name, kind, file, first, second, answer) in cases {
            let layer = format!(
                "[[value]]\nname = \"{name}\"\nkind = \"{kind}\"\n\
                 [[target]]\npath = \"{file}\"\ncontent = \"S\"\n\
                 [[target]]\npath = \"{first}\"\nenabled = false\n\
                 [[target]]\npath = \"{second}\"\nenabled = true\n"
            );
            let Err(message) = resolved(&layer, Some(&format!("[values]\n{answer}\n"))) else {
                loaded.push(format!("{first} and {second}"));
                continue;
            };
            for part in [
                "bx.toml:10".to_string(),
                format!("names the same file as `{first}` at bx.toml:7"),
                "in this same layer".to_string(),
            ] {
                assert!(
                    message.contains(&part),
                    "{first} {second}: {part}: {message}"
                );
            }
        }
        assert!(
            loaded.is_empty(),
            "one path for every answer is the layer's defect, yet these loaded: {loaded:?}"
        );
    }

    #[test]
    fn a_path_value_glued_after_text_starts_its_own_segment() {
        // A `path` answer always begins with `/`, so text glued before a `path`
        // value is joined to it by that `/`: `/opt{{r}}/conf` is `/opt/srv/conf`
        // for `r = "/srv"`, as `/opt/{{r}}/conf` is, and a `/` written before the
        // value only doubles a separator, which folds. Each pair is one file for
        // every answer, wherever the value sits and whatever is glued before it,
        // so it is the layer's defect rather than a block an answer could clear.
        let cases = [
            ("/opt/srv/conf", "/opt{{r}}/conf", "/opt/{{r}}/conf"),
            ("/srv/d/conf", "{{r}}{{s}}/conf", "{{r}}/{{s}}/conf"),
            ("~/srv/conf", "{{p}}{{r}}/conf", "{{p}}/{{r}}/conf"),
            ("~/srv/d", "~{{r}}{{s}}", "~/{{r}}/{{s}}"),
        ];
        let mut loaded = Vec::new();
        for (file, first, second) in cases {
            let layer = format!(
                "[[value]]\nname = \"r\"\nkind = \"path\"\n\
                 [[value]]\nname = \"s\"\nkind = \"path\"\n\
                 [[value]]\nname = \"p\"\nkind = \"string\"\n\
                 [[target]]\npath = \"{file}\"\ncontent = \"S\"\n\
                 [[target]]\npath = \"{first}\"\nenabled = false\n\
                 [[target]]\npath = \"{second}\"\nenabled = true\n"
            );
            let answers = "[values]\nr = \"/srv\"\ns = \"/d\"\np = \"~\"\n";
            let message = match resolved(&layer, Some(answers)) {
                Ok(resolved) => {
                    loaded.push(format!("{first} and {second}: {:?}", keys(&resolved)));
                    continue;
                }
                Err(message) => message,
            };
            for part in [
                "bx.toml:16".to_string(),
                format!("names the same file as `{first}` at bx.toml:13"),
                "in this same layer".to_string(),
            ] {
                assert!(
                    message.contains(&part),
                    "{first} {second}: {part}: {message}"
                );
            }
        }
        assert!(
            loaded.is_empty(),
            "one path for every answer is the layer's defect, yet these loaded: {loaded:#?}"
        );
    }

    #[test]
    fn a_dotdot_run_past_a_placeholder_is_judged_after_substitution() {
        // A run of `..` after a placeholder reaches as far as the answer is deep.
        // `/opt/{{p}}/../../../s` and `/opt/{{p}}/../../../../s` both name `/s`
        // for `p = "a"` or `"a/b"`, and `p = "a/b/c"` parts them; `{{r}}/../../s`
        // and `{{r}}/../../../s` meet for `r = "/srv/d"` and part for
        // `"/srv/d/e"`. Where they meet it is the answer's doing, so the file
        // blocks and the load goes on.
        let outcome = |base: &str, top: &str, local: &str| -> Result<Resolved, String> {
            let layers = vec![
                layer("base.toml", LayerKind::Global, base)?,
                layer("bx.toml", LayerKind::Global, top)?,
                layer("local.toml", LayerKind::Local, local)?,
            ];
            let merged = merge(&layers, &home()).map_err(|e| e.to_string())?;
            resolve(&merged, &home(), place).map_err(|e| e.to_string())
        };
        // A base layer, the layer holding the pair, and each answer with whether
        // the pair meets under it.
        type Case<'a> = (&'a str, &'a str, &'a [(&'a str, bool)]);
        let cases: [Case<'_>; 2] = [
            (
                "[[target]]\npath = \"/s\"\ncontent = \"S\"\n\
                 [[target]]\npath = \"/opt/s\"\ncontent = \"O\"\n",
                "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                 [[target]]\npath = \"/opt/{{p}}/../../../s\"\nenabled = false\n\
                 [[target]]\npath = \"/opt/{{p}}/../../../../s\"\nenabled = false\n",
                &[
                    ("p = \"a\"", true),
                    ("p = \"a/b\"", true),
                    ("p = \"a/b/c\"", false),
                ],
            ),
            (
                "[[target]]\npath = \"/s\"\ncontent = \"S\"\n\
                 [[target]]\npath = \"/srv/s\"\ncontent = \"O\"\n",
                "[[value]]\nname = \"r\"\nkind = \"path\"\n\
                 [[target]]\npath = \"{{r}}/../../s\"\nenabled = false\n\
                 [[target]]\npath = \"{{r}}/../../../s\"\nenabled = false\n",
                &[("r = \"/srv/d\"", true), ("r = \"/srv/d/e\"", false)],
            ),
        ];

        for (base, top, answers) in cases {
            for (answer, meet) in answers {
                let resolved = outcome(base, top, &format!("[values]\n{answer}\n"))
                    .unwrap_or_else(|e| panic!("{answer} failed the whole load: {e}"));
                let blocked: Vec<&str> = resolved
                    .targets
                    .iter()
                    .filter_map(|target| match target {
                        Resolution::Blocked(entry) => Some(entry.key.as_str()),
                        Resolution::Ready(_) => None,
                    })
                    .collect();
                let expected: &[&str] = if *meet { &["/s"] } else { &[] };
                assert_eq!(blocked, expected, "{answer}");
            }
        }
    }

    #[test]
    fn toggles_one_path_past_a_placeholder_fail_the_load_for_every_answer() {
        // `{{p}}/../../s` and `{{p}}/.././../s` differ only by a `.`: whenever
        // they name a file they name the same one, so no answer parts them and
        // the pair is the layer's defect. `{{p}}/s` and `{{p}}/./s` are the same
        // with the placeholder opening the spelling, which `p = "~"` roots.
        for prefix in ["~/", "~/x/y/"] {
            let layer = format!(
                "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                 [[target]]\npath = \"{prefix}s\"\ncontent = \"S\"\n\
                 [[target]]\npath = \"{prefix}{{{{p}}}}/../../s\"\nenabled = false\n\
                 [[target]]\npath = \"{prefix}{{{{p}}}}/.././../s\"\nenabled = true\n"
            );
            for answer in ["a/b", "b/c", "a", "a/b/c", "."] {
                let message = resolved(&layer, Some(&format!("[values]\np = \"{answer}\"\n")))
                    .expect_err("no answer loads this layer");
                if matches!(answer, "a/b" | "b/c") {
                    for part in [
                        format!("names the same file as `{prefix}{{{{p}}}}/../../s`"),
                        "in this same layer".to_string(),
                    ] {
                        assert!(
                            message.contains(&part),
                            "{prefix} {answer} {part}: {message}"
                        );
                    }
                }
            }
        }

        let lead = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                    [[target]]\npath = \"~/s\"\ncontent = \"S\"\n\
                    [[target]]\npath = \"{{p}}/s\"\nenabled = false\n\
                    [[target]]\npath = \"{{p}}/./s\"\nenabled = true\n";
        let message = resolved(lead, Some("[values]\np = \"~\"\n"))
            .expect_err("one path for every answer is the layer's defect");
        for part in [
            "names the same file as `{{p}}/s` at bx.toml:7",
            "in this same layer",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }

    #[test]
    fn a_pair_with_many_placeholders_is_decided_like_any_other() {
        // Nothing about the rule grows with the placeholders in a spelling: a
        // pair carrying thirteen that is one path as written fails the load like
        // a pair carrying one.
        let layer = |count: usize| {
            let decls: String = (1..=count)
                .map(|i| format!("[[value]]\nname = \"v{i}\"\nkind = \"string\"\n"))
                .collect();
            let segments: String = (1..=count).map(|i| format!("/{{{{v{i}}}}}")).collect();
            let answers: String = (1..=count).map(|i| format!("v{i} = \"a\"\n")).collect();
            (
                format!(
                    "{decls}[[target]]\npath = \"~{segments}/s\"\ncontent = \"S\"\n\
                     [[target]]\npath = \"~{segments}/./s\"\nenabled = false\n\
                     [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n"
                ),
                format!("[values]\n{answers}"),
            )
        };

        for count in [1, 13] {
            let (text, answers) = layer(count);
            let message = resolved(&text, Some(&answers))
                .expect_err("one path for every answer is the layer's defect");
            assert!(message.contains("in this same layer"), "{count}: {message}");
        }
    }

    #[test]
    fn a_later_layer_that_names_the_file_settles_what_an_answer_made_one_layer_name_twice() {
        // The account has the last word: a full entry for the file replaces
        // both, and a toggle switches both off.
        let replaced = resolved(
            PROFILE,
            Some(
                "[values]\nprofile = \"default\"\n\
                 [[target]]\npath = \"~/.config/default/s\"\ncontent = \"LOCAL\"\n",
            ),
        )
        .expect("a later full entry settles it");
        assert_eq!(keys(&replaced), ["~/.config/default/s", "~/.zshrc"]);
        assert_eq!(ready(&replaced, 0).body, Body::Inline("LOCAL".to_string()));

        let off = resolved(
            PROFILE,
            Some(
                "[values]\nprofile = \"default\"\n\
                 [[target]]\npath = \"~/.config/default/s\"\nenabled = false\n",
            ),
        )
        .expect("a later toggle switches every entry for the file off");
        assert_eq!(keys(&off), ["~/.zshrc"]);
    }

    #[test]
    fn an_answer_that_makes_a_layer_toggle_its_own_entry_blocks_that_file() {
        // A module that adds a per-profile file and switches the default one
        // off. With `profile = "default"` it both sets and switches off one file,
        // and which wins would be an order nothing in the file states. It is
        // reported, not hidden: the entry stays in the plan, blocked.
        let merged = merge(
            &[
                layer(
                    "bx.toml",
                    LayerKind::Global,
                    "[[value]]\nname = \"profile\"\nkind = \"string\"\n\
                     [[target]]\npath = \"~/.config/default/s\"\ncontent = \"DEFAULT\"\n\
                     [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n",
                )
                .unwrap(),
                layer(
                    "modules/10-profile.toml",
                    LayerKind::Global,
                    "[[target]]\npath = \"~/.config/{{profile}}/s\"\ncontent = \"PROFILE\"\n\
                     [[target]]\npath = \"~/.config/default/s\"\nenabled = false\n",
                )
                .unwrap(),
                layer(
                    "local.toml",
                    LayerKind::Local,
                    "[values]\nprofile = \"default\"\n",
                )
                .unwrap(),
            ],
            &home(),
        )
        .expect("an account's answer does not fail the merge");
        let resolved = resolve(&merged, &home(), place).unwrap();

        assert_eq!(keys(&resolved), ["~/.config/{{profile}}/s", "~/.zshrc"]);
        let entry = blocked(&resolved, 0);
        for part in [
            "modules/10-profile.toml:1",
            "modules/10-profile.toml:4",
            "the answer to `profile` at local.toml:2",
        ] {
            assert!(entry.hint.contains(part), "{part}: {}", entry.hint);
        }
        ready(&resolved, 1);
    }

    /// Merge and resolve an arbitrary layer set against the fixtures' home.
    fn merged_and_resolved(layers: &[(&str, LayerKind, &str)]) -> (Config, Resolved) {
        let layers: Vec<Layer> = layers
            .iter()
            .map(|(file, kind, text)| layer(file, *kind, text).unwrap())
            .collect();
        let merged = merge(&layers, &home()).expect("an account's answer does not fail the merge");
        let resolved = resolve(&merged, &home(), place).expect("nor the resolution");
        (merged, resolved)
    }

    /// Two independent pairs, `s` and `t`, each two files as written and one
    /// file when `profile` is answered `default`.
    const TWO_PAIRS: &str = "[[value]]\nname = \"profile\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/{{profile}}/s\"\ncontent = \"PS\"\n\
                             [[target]]\npath = \"~/.config/default/s\"\ncontent = \"DS\"\n\
                             [[target]]\npath = \"~/.config/{{profile}}/t\"\ncontent = \"PT\"\n\
                             [[target]]\npath = \"~/.config/default/t\"\ncontent = \"DT\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

    #[test]
    fn two_clashing_pairs_in_one_layer_each_keep_their_own_conflict() {
        // Recording the second pair's clash may only replace what was recorded
        // for that same file in that same layer. Dropping the first pair's clash
        // would leave two ready targets for `~/.config/default/s`.
        let (merged, resolved) = merged_and_resolved(&[
            ("bx.toml", LayerKind::Global, TWO_PAIRS),
            (
                "local.toml",
                LayerKind::Local,
                "[values]\nprofile = \"default\"\n",
            ),
        ]);

        assert_eq!(
            merged
                .conflicts
                .iter()
                .map(|conflict| conflict.file.as_str())
                .collect::<Vec<_>>(),
            ["~/.config/default/s", "~/.config/default/t"]
        );
        assert_eq!(
            keys(&resolved),
            [
                "~/.config/{{profile}}/s",
                "~/.config/default/s",
                "~/.config/{{profile}}/t",
                "~/.config/default/t",
                "~/.zshrc",
            ]
        );
        for (index, own, other) in [
            (0, ["bx.toml:4", "bx.toml:7"], ["bx.toml:10", "bx.toml:13"]),
            (1, ["bx.toml:4", "bx.toml:7"], ["bx.toml:10", "bx.toml:13"]),
            (2, ["bx.toml:10", "bx.toml:13"], ["bx.toml:4", "bx.toml:7"]),
            (3, ["bx.toml:10", "bx.toml:13"], ["bx.toml:4", "bx.toml:7"]),
        ] {
            let entry = blocked(&resolved, index);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["profile".to_string()]
                }
            );
            for line in own {
                assert!(entry.hint.contains(line), "{index} {line}: {}", entry.hint);
            }
            for line in other {
                assert!(!entry.hint.contains(line), "{index} {line}: {}", entry.hint);
            }
        }
        assert_eq!(ready(&resolved, 4).path.as_str(), "~/.zshrc");
    }

    #[test]
    fn one_file_clashing_in_two_layers_is_recorded_for_each_and_settled_only_by_name() {
        // `bx.toml` names `s` twice through `profile`, and a module toggles it
        // twice the same way. Recording the module's clash may not drop
        // `bx.toml`'s, which is a different layer's statement about the file.
        // A later full entry for `s` settles both, and leaves `t` alone.
        const MODULE: &str = "[[target]]\npath = \"~/.config/{{profile}}/s\"\nenabled = true\n\
                              [[target]]\npath = \"~/.config/default/s\"\nenabled = true\n";

        let (merged, resolved) = merged_and_resolved(&[
            ("bx.toml", LayerKind::Global, TWO_PAIRS),
            ("modules/10-profile.toml", LayerKind::Global, MODULE),
            (
                "local.toml",
                LayerKind::Local,
                "[values]\nprofile = \"default\"\n",
            ),
        ]);

        assert_eq!(
            merged
                .conflicts
                .iter()
                .map(|conflict| conflict.file.as_str())
                .collect::<Vec<_>>(),
            [
                "~/.config/default/s",
                "~/.config/default/t",
                "~/.config/default/s"
            ],
            "one conflict per layer that named the file twice"
        );
        for index in [0, 1] {
            let entry = blocked(&resolved, index);
            for line in [
                "`~/.config/{{profile}}/s` at bx.toml:4",
                "`~/.config/default/s` at bx.toml:7",
                "`~/.config/{{profile}}/s` at modules/10-profile.toml:1",
                "`~/.config/default/s` at modules/10-profile.toml:4",
            ] {
                assert!(entry.hint.contains(line), "{index} {line}: {}", entry.hint);
            }
        }

        let (merged, resolved) = merged_and_resolved(&[
            ("bx.toml", LayerKind::Global, TWO_PAIRS),
            ("modules/10-profile.toml", LayerKind::Global, MODULE),
            (
                "local.toml",
                LayerKind::Local,
                "[values]\nprofile = \"default\"\n\
                 [[target]]\npath = \"~/.config/default/s\"\ncontent = \"LOCAL\"\n",
            ),
        ]);

        assert_eq!(
            merged
                .conflicts
                .iter()
                .map(|conflict| conflict.file.as_str())
                .collect::<Vec<_>>(),
            ["~/.config/default/t"],
            "the full entry settles every layer's clash for `s`, and only `s`"
        );
        assert_eq!(
            keys(&resolved),
            [
                "~/.config/default/s",
                "~/.config/{{profile}}/t",
                "~/.config/default/t",
                "~/.zshrc",
            ]
        );
        assert_eq!(ready(&resolved, 0).body, Body::Inline("LOCAL".to_string()));
        blocked(&resolved, 1);
        blocked(&resolved, 2);
        ready(&resolved, 3);
    }

    #[test]
    fn a_clashing_pair_reasserted_a_third_time_is_one_conflict_naming_all_three() {
        // The third statement replaces the clash the first two recorded; it
        // does not add a second one beside it, which would repeat every line in
        // the hint.
        let (merged, resolved) = merged_and_resolved(&[
            (
                "bx.toml",
                LayerKind::Global,
                "[[value]]\nname = \"profile\"\nkind = \"string\"\n\
                 [[value]]\nname = \"other\"\nkind = \"string\"\n\
                 [[target]]\npath = \"~/.config/{{profile}}/s\"\ncontent = \"P\"\n\
                 [[target]]\npath = \"~/.config/default/s\"\ncontent = \"D\"\n\
                 [[target]]\npath = \"~/.config/{{other}}/s\"\ncontent = \"O\"\n\
                 [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n",
            ),
            (
                "local.toml",
                LayerKind::Local,
                "[values]\nprofile = \"default\"\nother = \"default\"\n",
            ),
        ]);

        assert_eq!(merged.conflicts.len(), 1, "{:#?}", merged.conflicts);
        assert_eq!(merged.conflicts[0].names, ["profile", "other"]);
        assert_eq!(
            keys(&resolved),
            [
                "~/.config/{{profile}}/s",
                "~/.config/default/s",
                "~/.config/{{other}}/s",
                "~/.zshrc",
            ]
        );
        for index in [0, 1, 2] {
            let entry = blocked(&resolved, index);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["profile".to_string(), "other".to_string()]
                }
            );
            for line in [
                "bx.toml:7",
                "bx.toml:10",
                "bx.toml:13",
                "`profile` at local.toml:2",
                "`other` at local.toml:3",
            ] {
                assert_eq!(
                    entry.hint.matches(line).count(),
                    1,
                    "{index} {line}: {}",
                    entry.hint
                );
            }
        }
        ready(&resolved, 3);
    }

    #[test]
    fn a_clashing_entry_is_held_beside_the_file_it_names_not_moved_to_the_end() {
        // `bx.toml` puts `~/.config/default/s` first. A module names that file
        // again, once through `profile`. With `work` the module's plain spelling
        // replaces it in place; with `default` both module spellings are the
        // file, and the second may not be appended after `~/.zshrc` — the
        // file's rows stay together, in the file's slot and in the order
        // written. That is all it promises: which slot is the file's depends on
        // the answer, so a row can sit ahead of an unrelated target for one
        // answer and behind it for another, as
        // `a_later_row_for_a_file_can_move_ahead_of_an_unrelated_target_by_answer`
        // shows.
        const BASE: &str = "[[value]]\nname = \"profile\"\nkind = \"string\"\n\
                            [[target]]\npath = \"~/.config/default/s\"\ncontent = \"BASE\"\n\
                            [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";
        const MODULE: &str = "[[target]]\npath = \"~/.config/{{profile}}/s\"\ncontent = \"PROFILE\"\n\
                              [[target]]\npath = \"~/.config/default/s\"\ncontent = \"DEFAULT\"\n\
                              [[target]]\npath = \"~/.config/other\"\ncontent = \"other\"\n";
        let layers = |answer: &str| {
            merged_and_resolved(&[
                ("bx.toml", LayerKind::Global, BASE),
                ("modules/10-profile.toml", LayerKind::Global, MODULE),
                (
                    "local.toml",
                    LayerKind::Local,
                    &format!("[values]\nprofile = \"{answer}\"\n"),
                ),
            ])
            .1
        };

        let work = layers("work");
        assert_eq!(
            keys(&work),
            [
                "~/.config/default/s",
                "~/.zshrc",
                "~/.config/work/s",
                "~/.config/other"
            ]
        );
        assert_eq!(ready(&work, 0).body, Body::Inline("DEFAULT".to_string()));

        let default = layers("default");
        assert_eq!(
            keys(&default),
            [
                "~/.config/{{profile}}/s",
                "~/.config/default/s",
                "~/.zshrc",
                "~/.config/other"
            ],
            "both rows for the file sit in the file's slot, in the order written"
        );
        blocked(&default, 0);
        blocked(&default, 1);
        ready(&default, 2);
        ready(&default, 3);
    }

    #[test]
    fn a_later_row_for_a_file_can_move_ahead_of_an_unrelated_target_by_answer() {
        // Decision 31 as narrowed: a file's rows are contiguous and in written
        // order, and unrelated targets keep their order among themselves. It is
        // not that nothing moves. With `default`, `~/.config/default/s` is the
        // file the first row already holds, so its row joins that slot, ahead
        // of `~/.zshrc`; with `work` it is a file of its own, and appends.
        const LAYER: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/{{p}}/s\"\ncontent = \"P\"\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n\
                             [[target]]\npath = \"~/.config/default/s\"\ncontent = \"D\"\n";

        let default = resolved(LAYER, Some("[values]\np = \"default\"\n"))
            .expect("an account's answer does not fail the load");
        assert_eq!(
            keys(&default),
            ["~/.config/{{p}}/s", "~/.config/default/s", "~/.zshrc"]
        );
        blocked(&default, 0);
        blocked(&default, 1);
        ready(&default, 2);

        let work = resolved(LAYER, Some("[values]\np = \"work\"\n")).expect("work");
        assert_eq!(
            keys(&work),
            ["~/.config/work/s", "~/.zshrc", "~/.config/default/s"]
        );
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

        let message = resolve(&config, &home(), place).unwrap_err().to_string();

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
