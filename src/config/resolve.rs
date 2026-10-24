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
    /// The merged `[doctor]` table: nothing in it is substituted.
    pub doctor: super::doctor::Doctor,
}

/// Resolve a merged configuration.
///
/// `home` is threaded in rather than read from the environment, so the whole
/// resolution is a pure function of the layer bytes plus this argument — but
/// for two ready targets whose keys differ only by case, where the volume is
/// asked whether it tells them apart (see [`crate::fs::case_insensitive`]).
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
/// claim the terminal slot; for two ready targets that name one file, by one
/// key or by two that differ only by case on a volume that does not tell them
/// apart; and for
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

    refuse_shared_files(&targets, home, crate::fs::case_insensitive)?;
    refuse_overlapping_externals(&merged.externals, &targets)?;

    Ok(Resolved {
        values,
        targets,
        externals: merged.externals.clone(),
        secrets: merged.secrets.clone(),
        tools: merged.tools.clone(),
        update: merged.update.clone(),
        doctor: merged.doctor.clone(),
    })
}

/// Refuse two ready targets that write one file.
///
/// The merge keys targets by the file they name, so a configuration that came
/// through it cannot trip this. [`resolve`] takes any [`Config`], though, and
/// `Portable` is the key the ledger and the journal are written against: two
/// targets for one file would give `rm` two priors to restore and `apply` two
/// writers, so the second `plan` would never be empty.
///
/// Two keys that differ only by case are one file too where the directory they
/// part in looks names up without regard to case, as a default APFS volume
/// does. That is asked of the volume through `folds` — never assumed from the
/// OS — and only for such a pair, so a configuration without one touches no
/// filesystem here. A volume `folds` cannot judge is taken to fold: refusing
/// costs an edit to the configuration, and two priors for one file cost `rm`.
fn refuse_shared_files(
    targets: &[Resolution<Target>],
    home: &Path,
    folds: impl Fn(&Path) -> Option<bool>,
) -> Result<(), Error> {
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

    for (index, later) in ready.iter().enumerate() {
        for earlier in &ready[..index] {
            if earlier.path.as_str().to_lowercase() != later.path.as_str().to_lowercase() {
                continue;
            }
            let parting = parting_dir(&earlier.path.render(home), &later.path.render(home));
            let judged = match folds(&parting) {
                Some(false) => continue,
                Some(true) => "on this volume, which does not tell names apart by case",
                None => {
                    "unless this volume tells names apart by case, which bx could not \
                     determine"
                }
            };
            return Err(Error::BadValue {
                origin: later.origin.clone(),
                message: format!(
                    "target `{}` is the same file as `{}`, the target at {}, {judged}; \
                     one file has one target",
                    later.path, earlier.path, earlier.origin
                ),
            });
        }
    }
    Ok(())
}

/// The directory in which two paths first name different entries: where a
/// lookup decides whether they are one file.
pub(crate) fn parting_dir(one: &Path, other: &Path) -> std::path::PathBuf {
    one.components()
        .zip(other.components())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect()
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
mod tests;
