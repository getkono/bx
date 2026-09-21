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
//! substituted: `acct = "../../.."` into `~/.config/{{acct}}/settings.json`
//! climbs out of the home, `seg = ""` into `owns = ["a.{{seg}}"]` leaves an
//! empty key segment, and `seg = "b.c"` adds a segment, naming a deeper key
//! than the one written. The target is blocked naming the answer's line, and
//! nothing is written for it. The same field broken with no account answer in
//! it — a committed `default` alone — is the repo's defect and fails the load.
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
//! What is refused is reaching a **`path` value**, not every absolute text: an
//! account answering a plain `string` value `/home/example/…` still resolves,
//! because nothing separates that from a string the account meant.

use std::path::Path;

use super::merge::Conflict;
use super::target::{Attach, Body, Format, KeyPath, Target};
use super::values::{ResolvedValues, Unresolved, ValueAssignment, ValueDecl};
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
    /// One or more answers in this account's layer leave this entry unusable:
    /// an answer its kind refuses, one that made a committed `default` invalid,
    /// or one that, substituted into this entry, makes a field invalid — a path
    /// that climbs out of the home, a `file` that climbs out of the repo, an
    /// owned key with an empty segment or with more or fewer segments than
    /// written — or a `file` that reaches a `path` value through an answer.
    ///
    /// Kept apart from [`BlockReason::UnsetValue`] because nothing is
    /// unanswered: the answer that needs changing is already written, and the
    /// hint names its line. Every case is cleared by the same act, changing
    /// that answer, which is why they share one variant.
    InvalidValue {
        /// The values to change, in declaration order: the declarations whose
        /// text is invalid, or the answers that went into the invalid field.
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
    /// `disabled_hint`, `path_answer_hint`, `ResolvedValues::invalid_hint` or
    /// `ResolvedValues::answers_hint` — never at a call site.
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
/// references a later value, a `default` that is not of its kind with no
/// account answer involved, a target field that substitution makes invalid
/// with no account answer in it, or a `file` that references a `path` value,
/// answered or not; and for two ready targets that name one file.
pub fn resolve(merged: &Config, home: &Path) -> Result<Resolved, Error> {
    let values = ResolvedValues::resolve(merged.values.clone(), &merged.value_assignments, home)?;

    let targets = merged
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
    if let Body::File(file) = &target.body {
        refuse_path_value_in_file(target, &file.to_string_lossy(), values)?;
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
    // Not ahead of a switched-off declaration, though the disabled block sits
    // below: while the switch is off, the answer under it is not this
    // account's value, so this walk does not see it and the switch is reported
    // first. Re-enabling then lands here. That is two true statements in the
    // order they become true, each one progress, and not the loop this
    // placement exists to avoid — which is a hint whose act returns the target
    // to the *same* block.
    if let Body::File(file) = &target.body
        && let Some((names, hint)) =
            refuse_path_answer_in_file(target, &file.to_string_lossy(), values, assignments)
    {
        return block(BlockReason::InvalidValue { names }, hint);
    }

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
            let names = in_declaration_order(
                values,
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
            let names = in_declaration_order(values, causes);
            let hint = values.answers_hint(&problem, &[raw.as_str()], &names);
            block(BlockReason::InvalidValue { names }, hint)
        }
    }
}

/// Refuse a `requires` entry written entirely in committed text.
///
/// An entry holding no placeholder is the same text for every account, so a
/// defect in it is the layer's whatever anyone answered — the rule this module
/// opens with. Checked **before** the probe, beside
/// [`refuse_path_value_in_file`], because [`substituted`] is reached only once
/// every value the target references has a usable answer: left there alone, the
/// very same committed line would fail the load for an account that has
/// answered and be invisible to one that has not.
///
/// [`check_requirement`] still runs inside [`substituted`], for text an answer
/// filled. That is the account's to change, and it costs that target alone.
///
/// A malformed placeholder is left to the probe, which reports it with the rest
/// of the target's defects, so text `scan` refuses is passed over here.
///
/// The `owns` arity check needs no twin: with no placeholder in the key, the
/// substituted text is the text as written, so its segment count cannot move.
fn refuse_committed_requirement(target: &Target, tool: &str) -> Result<(), Error> {
    let Ok(names) = super::values::placeholders(tool) else {
        return Ok(());
    };
    if !names.is_empty() {
        return Ok(());
    }
    check_requirement(tool).map_err(|problem| Error::BadValue {
        origin: target.origin.clone(),
        message: format!("target `{}`: {problem}", target.path),
    })
}

/// Refuse a `file` that references a `path` value.
///
/// A `path` value is absolute by construction, and `file` names a file relative
/// to the config repo root. Opening `file`, the substituted text can never be
/// repo-relative whatever the answer; further in, it names repo content by an
/// account's absolute location. No answer fixes either, so it is the layer's
/// defect and a load error naming the target, whether or not the value has an
/// answer yet — not a blocked target whose hint advises changing one.
///
/// The same holds for a value whose committed `default` is built from a `path`
/// value, however many defaults lie between: `s` defaulting to `{{b}}` carries
/// `b`'s absolute text into `file`. Each default is followed as written,
/// whether or not it applies for this account, so the refusal is the same for
/// every account; the message names each declaration on the way.
///
/// `file` may hold both kinds of reference. The one refused is whichever comes
/// **first in written order**, with the chain behind it, and there is no
/// preference for the more direct one. A value directly of kind `path` is a
/// one-step chain, so the two cases are one walk and one message shape; a rule
/// that reported the direct reference first would tell the reader about the
/// second `{{name}}` in the field and leave the first, whose chain is just as
/// fatal, unmentioned. Written order is also the deterministic choice, which is
/// the direction Invariant 3 points.
///
/// An account's answer is not read here. A way to a `path` value that runs
/// through one is judged by [`refuse_path_answer_in_file`], and blocks the
/// target rather than failing the load.
///
/// Written order rules **within this walk**. It does not rule between the two:
/// when `file` holds a committed way to a `path` value and an answered one,
/// this walk wins whichever is written first, because it runs first and returns
/// `Err`. That is not an accident of the call order. A committed way is the
/// same defect for every account and no answer clears it, so reporting it as
/// one account's blocked target would hide a repository defect behind a hint
/// advising that account to change something — and would report it to the
/// account that answered and not to the one that did not. The load error
/// outranks the block; only the field it names is decided by written order.
/// `a_file_reached_by_a_committed_route_and_an_answered_one_fails_the_load`
/// pins it in both written orders.
///
/// A malformed placeholder is left to the probe, which reports it with the
/// rest of the target's defects.
fn refuse_path_value_in_file(
    target: &Target,
    file: &str,
    values: &ResolvedValues,
) -> Result<(), Error> {
    let names = super::values::placeholders(file).unwrap_or_default();
    let mut seen: Vec<String> = Vec::new();
    let chain = names
        .iter()
        .find_map(|name| path_value_behind(values, name, &mut seen));
    let Some(chain) = chain else {
        return Ok(());
    };

    let steps: String = chain
        .windows(2)
        .map(|pair| {
            format!(
                ", whose default at {} is built from `{}`",
                pair[0].origin, pair[1].name
            )
        })
        .collect();
    let not_built = if chain.len() > 1 {
        " that is not built from one"
    } else {
        ""
    };
    Err(Error::BadValue {
        origin: target.origin.clone(),
        message: format!(
            "target `{}`: `file` references `{}`{steps}, a `path` value; a `path` value \
             is always absolute and `file` is relative to the config repo root, so no \
             answer could make it name a file in the repo; reference a `string` value\
             {not_built}",
            target.path, chain[0].name
        ),
    })
}

/// The declarations from `name` down its committed defaults to a `path` value.
///
/// Depth first, each default's references in the order written. `seen` stops
/// the walk at a name it has already walked, and it is reachable.
/// [`Unresolved::Forward`](super::values::Unresolved::Forward) keeps every
/// *expanded* default acyclic, since a default may reference only an earlier
/// declaration. But a default an answer overrides is never expanded, so
/// `default = "{{q}}"` on an answered `q` reaches this walk unrefused, and
/// without `seen` the walk would recurse until the stack ran out.
fn path_value_behind<'a>(
    values: &'a ResolvedValues,
    name: &str,
    seen: &mut Vec<String>,
) -> Option<Vec<&'a super::values::ValueDecl>> {
    if seen.iter().any(|walked| walked == name) {
        return None;
    }
    seen.push(name.to_string());
    let decl = values.decl(name)?;
    if decl.kind == super::values::ValueKind::Path {
        return Some(vec![decl]);
    }
    let default = decl.default.as_ref()?.to_string();
    super::values::placeholders(&default)
        .unwrap_or_default()
        .into_iter()
        .find_map(|next| path_value_behind(values, next, seen))
        .map(|mut chain| {
            chain.insert(0, decl);
            chain
        })
}

/// Block a target whose `file` reaches a `path` value through this account's
/// answer, returning the answers' names and the hint.
///
/// Called once [`refuse_path_value_in_file`] has found no way there through
/// committed defaults alone from the same names, so a way found here is
/// expected to run through at least one answer. That answer is the account's to
/// change, which is why this blocks rather than fails; the hint names each one
/// on the way, with its line.
///
/// That expectation is a claim about a **different** function — that
/// [`path_value_behind`] is a complete walk of the committed graph this one
/// also walks — so it is enforced here rather than left to prose. A chain of
/// [`Step::Default`] and [`Step::Terminal`] alone names no answer, and the hint
/// would read "…repo root, because of ; change that answer": no target is
/// blocked on that, and the load error the committed walk owes is left to it.
/// `a_committed_chain_alone_is_not_an_answer_block` calls this with exactly
/// that chain, so the coupling is pinned rather than asserted.
///
/// Only a declaration of kind `path` ends the walk, so this closes the route an
/// account's answer opens *into a `path` value*, not every way an absolute
/// literal reaches `file`. An account answering a plain `string` value
/// `/home/example/…` still resolves Ready: that text is what a `string` value
/// is for, and nothing separates a machine location from a string an account
/// meant.
fn refuse_path_answer_in_file(
    target: &Target,
    file: &str,
    values: &ResolvedValues,
    assignments: &[ValueAssignment],
) -> Option<(Vec<String>, String)> {
    let mut seen: Vec<String> = Vec::new();
    let chain = super::values::placeholders(file)
        .unwrap_or_default()
        .into_iter()
        .find_map(|name| path_value_through_answer(values, assignments, name, &mut seen))?;
    if !chain.iter().any(|step| matches!(step, Step::Answer(..))) {
        return None;
    }

    let steps: String = chain
        .iter()
        .map(|step| match step {
            Step::Default(decl) => format!(
                "`{}`, whose default at {} is built from ",
                decl.name, decl.origin
            ),
            Step::Answer(decl, answer) => format!(
                "`{}`, whose answer at {} is built from ",
                decl.name, answer.origin
            ),
            Step::Terminal(decl) => format!("`{}`", decl.name),
        })
        .collect();
    let problem = format!(
        "target `{}`: `file` references {steps}, a `path` value; a `path` value is always \
         absolute and `file` is relative to the config repo root",
        target.path
    );

    let names = in_declaration_order(
        values,
        chain
            .iter()
            .filter_map(|step| match step {
                Step::Answer(decl, _) => Some(decl.name.clone()),
                Step::Default(_) | Step::Terminal(_) => None,
            })
            .collect(),
    );
    let answers: Vec<&ValueAssignment> = names
        .iter()
        .filter_map(|name| assignments.iter().find(|answer| &answer.name == name))
        .collect();
    let hint = super::values::path_answer_hint(&problem, &answers);
    Some((names, hint))
}

/// One declaration on the way from a name in `file` to a `path` value.
enum Step<'a> {
    /// Left through its committed `default`.
    Default(&'a ValueDecl),
    /// Left through this account's answer to it.
    Answer(&'a ValueDecl, &'a ValueAssignment),
    /// The `path` value the way ends at.
    Terminal(&'a ValueDecl),
}

/// The way from `name` to a `path` value, through answers and defaults.
///
/// Depth first. At each declaration, this account's answer is followed before
/// the committed `default`, each one's references in the order written. The
/// default is followed whether or not the answer overrides it, as
/// [`path_value_behind`] follows it, so an answer `s = "{{t}}"` is refused
/// alike whether `t` is answered or left to a default built from a `path`
/// value. A switched-off declaration's answer is not this account's value and
/// is not followed; its kind and default are still read, as the committed walk
/// reads them.
///
/// So `enabled` gates the **answer edge alone**, and the walk ends at a `path`
/// declaration whether or not it is switched on. The two are not in tension:
/// they ask different questions. `enabled` says whether an answer is *this
/// account's value* — which is the answer edge's question, and the reason this
/// uses the same lookup [`ResolvedValues::resolve`] does. It does not say what
/// a declaration *is*: a switched-off `path` declaration is still declared
/// `path`, and the terminal asks only its kind. That is also why
/// [`refuse_path_value_in_file`], which reads kinds and defaults and nothing
/// else, never consults `enabled` at all. Gating the terminal would make the
/// two walks judge one `b` differently, and it would leave a `file` reaching a
/// switched-off `path` value refused for an account with no answer and allowed
/// for one with an answer that reaches it.
///
/// What does **not** settle this is which hint the account sees first.
/// Switching `s` off gives `DisabledValue{["s"]}` and "re-enable s", and
/// re-enabling lands in this block; dropping the answer edge's gate gives this
/// block first, and changing the answer lands in `DisabledValue`. Either way
/// two statements are true and are reported in the order they become true, so
/// that reading decides nothing.
/// `a_switched_off_path_declaration_still_ends_the_walk` and
/// `a_disabled_value_s_answer_is_not_walked` pin both halves.
///
/// `seen` stops the walk at a name it has already walked, and it is
/// load-bearing here for the reason [`path_value_behind`] gives: an overridden
/// default is never expanded, so
/// [`Unresolved::Forward`](super::values::Unresolved::Forward) never refuses a
/// cycle that one closes, and the walk reads it anyway. Following answers opens
/// a second shape of that cycle — `q` answered `{{r}}` with `r`'s overridden
/// default naming `q` back — because an answer may name only an earlier value,
/// but the default it overrides may name a later one.
/// `an_answer_re_entering_a_walked_name_still_resolves` pins that shape;
/// `a_file_body_through_an_answered_value_whose_default_names_itself_resolves`
/// pins the one-declaration one.
///
/// `seen` is also shared across the names in `file`, so a subtree walked for
/// one of them is not walked again for the next. The walk is a function of the
/// declarations and this account's answers alone, so the second visit would
/// have returned what the first did.
fn path_value_through_answer<'a>(
    values: &'a ResolvedValues,
    assignments: &'a [ValueAssignment],
    name: &str,
    seen: &mut Vec<String>,
) -> Option<Vec<Step<'a>>> {
    if seen.iter().any(|walked| walked == name) {
        return None;
    }
    seen.push(name.to_string());
    let decl = values.decl(name)?;
    if decl.kind == super::values::ValueKind::Path {
        return Some(vec![Step::Terminal(decl)]);
    }

    // The same lookup `ResolvedValues::resolve` answers a declaration with.
    let answer = assignments
        .iter()
        .find(|answer| answer.name == decl.name)
        .filter(|_| decl.enabled);
    if let Some(answer) = answer {
        let text = answer.value.to_string();
        let through = super::values::placeholders(&text)
            .unwrap_or_default()
            .into_iter()
            .find_map(|next| path_value_through_answer(values, assignments, next, seen));
        if let Some(mut chain) = through {
            chain.insert(0, Step::Answer(decl, answer));
            return Some(chain);
        }
    }

    let default = decl.default.as_ref()?.to_string();
    super::values::placeholders(&default)
        .unwrap_or_default()
        .into_iter()
        .find_map(|next| path_value_through_answer(values, assignments, next, seen))
        .map(|mut chain| {
            chain.insert(0, Step::Default(decl));
            chain
        })
}

/// Why [`substituted`] could not rebuild a target.
enum Broken {
    /// A defect no answer could fix, already worded as a load error.
    Defect(Error),
    /// A substituted field that is no longer valid.
    Field {
        /// The field as written, so the caller can ask which answers went in.
        raw: String,
        /// What is wrong with what it became.
        problem: String,
    },
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
/// substituted string is no longer a valid portable path, repo file or key
/// path. That is [`Broken::Field`], carrying the text as written, and
/// [`resolve_target`] decides whose it is from the answers that went in.
fn substituted(target: &Target, values: &ResolvedValues) -> Result<Target, Broken> {
    let origin = &target.origin;
    let sub = |text: &str| -> Result<String, Broken> {
        values.substitute(text).map_err(|defect| {
            Broken::Defect(Error::BadValue {
                origin: origin.clone(),
                message: format!("target `{}`: {defect}", target.path),
            })
        })
    };
    let field = |raw: &str, problem: String| Broken::Field {
        raw: raw.to_string(),
        problem,
    };
    let portable = |text: &str| -> Result<Portable, Broken> {
        // Against the home the values were resolved against, never a re-derived
        // one: `Portable::parse_in` rejects an absolute path under the home, and
        // a different home would make that judgement about a different file.
        Portable::parse_in(&sub(text)?, values.home())
            .map_err(|source| field(text, source.to_string()))
    };

    let body = match &target.body {
        // Through the parser's own rule, not straight into the target. A `file`
        // is the one substituted field whose validator the parse-time check
        // cannot stand in for: `cfg/{{account}}/gitconfig` is a legal body file
        // as written, and an `account` answered `../../../../etc` makes it read
        // a file off the machine and write it into a target.
        Body::File(path) => {
            let raw = path.to_string_lossy();
            Body::File(
                super::target::confine_to_repo("file", &sub(&raw)?)
                    .map_err(|message| field(&raw, message))?,
            )
        }
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
                    let raw = key.to_string();
                    let text = sub(&raw)?;
                    let parsed =
                        KeyPath::parse(&text).map_err(|source| field(&raw, source.to_string()))?;
                    // `KeyPath` splits on `.`, so an answer holding one would
                    // name a different, deeper key than the one written.
                    let (written, now) = (key.segments().len(), parsed.segments().len());
                    if now != written {
                        return Err(field(
                            &raw,
                            format!(
                                "`owns` key `{raw}` has {written} segments as written and {now} \
                                 once substituted, as `{text}`; an answer may fill a segment but \
                                 not add or remove one"
                            ),
                        ));
                    }
                    Ok(parsed)
                })
                .collect::<Result<Vec<_>, Broken>>()?,
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
            .map(|tool| {
                let text = sub(tool)?;
                check_requirement(&text).map_err(|problem| field(tool, problem))?;
                Ok(text)
            })
            .collect::<Result<Vec<_>, Broken>>()?,
        references: target
            .references
            .iter()
            .map(|reference| portable(reference.as_str()))
            .collect::<Result<Vec<_>, Broken>>()?,
        enabled: target.enabled,
        origin: target.origin.clone(),
    })
}

/// Refuse a `requires` entry detection could never find.
///
/// Detection looks a bare name up on `PATH` and opens an absolute path as it
/// is; a relative name holding a `/` is never found, and an empty one would be
/// joined onto every `PATH` directory. A name made only of `.` and `..`
/// segments (`/` among them) names a directory, which detection never counts
/// as a tool. Checked once substituted, because an answer is where any of these
/// most plausibly comes from.
fn check_requirement(text: &str) -> Result<(), String> {
    let only_dots = text
        .split('/')
        .all(|segment| matches!(segment, "" | "." | ".."));
    if only_dots || (text.contains('/') && !text.starts_with('/')) {
        return Err(format!(
            "`requires` names a tool by a bare name to look up on `PATH`, or by an \
             absolute path; got {text:?}"
        ));
    }
    Ok(())
}

/// Order `names` the way the values were declared, deduplicated.
///
/// So two reports of one problem read the same way regardless of which field
/// happened to be probed first.
///
/// Indexed against [`ResolvedValues::index_of`], which counts every
/// declaration, rather than [`ResolvedValues::decls`], which lists only the
/// enabled ones. The difference shows in exactly one caller:
/// [`BlockReason::DisabledValue`], whose names are switched off by definition.
/// Against the filtered list every one of them would come back `usize::MAX`,
/// leaving the sort to report them in whichever order the fields happened to be
/// probed — the one thing this function exists to prevent, in the one block
/// that cannot avoid it.
fn in_declaration_order(values: &ResolvedValues, mut names: Vec<String>) -> Vec<String> {
    let index = |name: &String| values.index_of(name).unwrap_or(usize::MAX);
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

        // An account's answer that climbs is refused and blocks this target
        // only; nothing is read and nothing is written.
        let climbing = resolved(LAYER, Some("[values]\naccount = \"../../../../etc\"\n"))
            .expect("an account's answer blocks its target, not the load");
        let entry = blocked(&climbing, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["account".to_string()]
            }
        );
        assert!(
            entry.hint.contains("may not climb out of the config repo"),
            "{}",
            entry.hint
        );
        assert!(entry.hint.contains("local.toml:2"), "{}", entry.hint);

        // A `file` that *opens* with a value, answered absolutely, would discard
        // the repo root the moment it reached `repo.join`.
        const ROOTED: &str = "[[value]]\n\
                              name = \"account\"\n\
                              kind = \"string\"\n\
                              [[target]]\n\
                              path = \"~/.gitconfig\"\n\
                              file = \"{{account}}/gitconfig\"\n";

        let rooted = resolved(ROOTED, Some("[values]\naccount = \"/etc\"\n"))
            .expect("an absolute answer blocks its target");
        let entry = blocked(&rooted, 0);
        assert!(
            entry.hint.contains("relative to the repo root"),
            "{}",
            entry.hint
        );

        // With no account answer in it, the same escape is the repo's own defect.
        let message = resolved(
            &LAYER.replace(
                "kind = \"string\"\n",
                "kind = \"string\"\ndefault = \"../../../../etc\"\n",
            ),
            None,
        )
        .expect_err("a committed default that climbs is a repo defect");
        assert!(
            message.contains("may not climb out of the config repo"),
            "{message}"
        );
        assert!(message.contains("~/.gitconfig"), "{message}");

        let ordinary = resolved(LAYER, Some("[values]\naccount = \"work\"\n")).unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::File(PathBuf::from("cfg/work/gitconfig")),
            "the case this spelling exists for still resolves"
        );
    }

    #[test]
    fn a_file_body_through_an_answered_value_whose_default_names_itself_resolves() {
        // An answer overrides its declaration's default, so that default is never
        // expanded and `Unresolved::Forward` never refuses it. The walk for a
        // `path` value behind `file` reads committed defaults, answered or not,
        // so it has to stop at a name it has already walked.
        const LAYER: &str = "[[value]]\nname = \"q\"\nkind = \"string\"\ndefault = \"{{q}}\"\n\
                             [[target]]\npath = \"~/.gitconfig\"\nfile = \"cfg/{{q}}/gitconfig\"\n";

        let answered = resolved(LAYER, Some("[values]\nq = \"work\"\n"))
            .expect("an answered value's unexpanded default does not fail the load");
        assert_eq!(
            ready(&answered, 0).body,
            Body::File(PathBuf::from("cfg/work/gitconfig"))
        );
    }

    #[test]
    fn a_file_body_may_not_reference_a_path_value() {
        // A `path` value is absolute by construction and `file` is relative to
        // the repo root. Opening `file`, it can never name a repo file whatever
        // the answer; inside it, it names repo content by an account's absolute
        // location. Either way no answer fixes it, so it is refused at load,
        // naming the target's line, before anything is answered.
        const LAYER: &str = "[[value]]\n\
                             name = \"cfg_dir\"\n\
                             kind = \"path\"\n\
                             [[target]]\n\
                             path = \"~/.gitconfig\"\n\
                             file = \"FILE\"\n\
                             [[target]]\n\
                             path = \"~/.zshrc\"\n\
                             content = \"setopt\"\n";

        for file in ["{{cfg_dir}}/gitconfig", "cfg/{{cfg_dir}}/gitconfig"] {
            for local in [None, Some("[values]\ncfg_dir = \"/var/mnt/cfg\"\n")] {
                let message = resolved(&LAYER.replace("FILE", file), local)
                    .expect_err("a `path` value in `file` is the layer's defect");
                for part in [
                    "bx.toml:4",
                    "`cfg_dir`",
                    "a `path` value",
                    "relative to the config repo",
                ] {
                    assert!(message.contains(part), "{file} {local:?} {part}: {message}");
                }
                // One step: nothing lies between, so the advice stops at the kind.
                assert!(
                    message.ends_with(
                        "`file` references `cfg_dir`, a `path` value; a `path` value is always \
                         absolute and `file` is relative to the config repo root, so no answer \
                         could make it name a file in the repo; reference a `string` value"
                    ),
                    "{file} {local:?}: {message}"
                );
            }
        }

        // The same spelling with a `string` value is the case `file` substitution
        // exists for.
        let string = LAYER
            .replace("kind = \"path\"", "kind = \"string\"")
            .replace("FILE", "cfg/{{cfg_dir}}/gitconfig");
        let ordinary = resolved(&string, Some("[values]\ncfg_dir = \"work\"\n")).unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::File(PathBuf::from("cfg/work/gitconfig"))
        );
    }

    #[test]
    fn a_file_body_may_not_reach_a_path_value_through_a_default() {
        // `s` is a `string`, but its committed default is `{{b}}`, a `path`
        // value. Checking only the kind of the name written in `file` let
        // `cfg/{{s}}/gitconfig` resolve to a repo file carrying the account's
        // absolute location, and blocked `{{s}}/gitconfig` with a hint naming
        // only `b`. The declaration is the layer's defect whatever is answered,
        // `s` included, so it is refused at load and the chain is named.
        const LAYER: &str = "[[value]]\n\
                             name = \"b\"\n\
                             kind = \"path\"\n\
                             [[value]]\n\
                             name = \"s\"\n\
                             kind = \"string\"\n\
                             default = \"{{b}}\"\n\
                             [[target]]\n\
                             path = \"~/.gitconfig\"\n\
                             file = \"FILE\"\n\
                             [[target]]\n\
                             path = \"~/.zshrc\"\n\
                             content = \"setopt\"\n";

        for file in ["{{s}}/gitconfig", "cfg/{{s}}/gitconfig"] {
            for local in [
                None,
                Some("[values]\nb = \"/var/mnt/cfg\"\n"),
                Some("[values]\ns = \"work\"\n"),
            ] {
                let message = resolved(&LAYER.replace("FILE", file), local)
                    .expect_err("a `path` value reached through a default is the layer's defect");
                for part in [
                    "bx.toml:8",
                    "`file` references `s`, whose default at bx.toml:4 is built from `b`, \
                     a `path` value",
                    "relative to the config repo",
                    "reference a `string` value that is not built from one",
                ] {
                    assert!(message.contains(part), "{file} {local:?} {part}: {message}");
                }
            }
        }

        // Three steps: `t` defaults to `{{s}}`, which defaults to `{{b}}`.
        let chained = LAYER
            .replace(
                "[[target]]\npath = \"~/.gitconfig\"",
                "[[value]]\nname = \"t\"\nkind = \"string\"\ndefault = \"{{s}}\"\n\
                 [[target]]\npath = \"~/.gitconfig\"",
            )
            .replace("FILE", "cfg/{{t}}/gitconfig");
        let message = resolved(&chained, Some("[values]\nb = \"/var/mnt/cfg\"\n"))
            .expect_err("however many defaults lie between");
        assert!(
            message.contains(
                "bx.toml:12: target `~/.gitconfig`: `file` references `t`, whose default at \
                 bx.toml:8 is built from `s`, whose default at bx.toml:4 is built from `b`, \
                 a `path` value"
            ),
            "{message}"
        );

        // A `string` default built from no `path` value is still the case
        // `file` substitution exists for.
        let plain = LAYER
            .replace("default = \"{{b}}\"", "default = \"work\"")
            .replace("FILE", "cfg/{{s}}/gitconfig");
        let ordinary = resolved(&plain, None).unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::File(PathBuf::from("cfg/work/gitconfig"))
        );
    }

    #[test]
    fn a_substitution_that_breaks_a_portable_path_blocks_or_fails_by_whose_input_it_is() {
        // Every substituted field is re-validated, because substitution can turn
        // a legal value into an illegal one. A path that climbs out of the home
        // is the case that matters: `under_home` is a claim about location, and
        // a `Portable` that escaped it would make a later entry's write gate on
        // nothing. An account's answer costs the account's target; a committed
        // default with no answer in it is a repo defect.
        const PATH: &str = "[[value]]\nname = \"leaf\"\nkind = \"string\"\n\
                            [[target]]\npath = \"~/.config/{{leaf}}\"\ncontent = \"x\"\n\
                            [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";
        const REFERENCE: &str = "[[value]]\nname = \"leaf\"\nkind = \"string\"\n\
                                 [[target]]\npath = \"~/.gitconfig\"\ncontent = \"x\"\n\
                                 references = [\"~/{{leaf}}\"]\n\
                                 [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        for (layer, what) in [(PATH, "a path"), (REFERENCE, "a reference")] {
            let answered = resolved(layer, Some("[values]\nleaf = \"../../etc/passwd\"\n"))
                .unwrap_or_else(|e| panic!("{what}: an answer failed the whole load: {e}"));
            let entry = blocked(&answered, 0);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["leaf".to_string()]
                },
                "{what}"
            );
            assert!(
                entry.hint.contains("climb out of the home"),
                "{what}: {}",
                entry.hint
            );
            assert!(
                entry.hint.contains("the answer to `leaf` at local.toml:2"),
                "{what}: {}",
                entry.hint
            );
            assert_eq!(ready(&answered, 1).path.as_str(), "~/.zshrc", "{what}");

            let message = resolved(
                &layer.replace(
                    "kind = \"string\"\n",
                    "kind = \"string\"\ndefault = \"../../etc/passwd\"\n",
                ),
                None,
            )
            .expect_err("a committed default with no answer in it is a repo defect");
            assert!(
                message.contains("climb out of the home"),
                "{what}: {message}"
            );
        }
    }

    #[test]
    fn a_legal_answer_that_makes_a_substituted_field_invalid_blocks_only_its_target() {
        // The panel's falsifier: a climbing answer in a target path, and an
        // empty answer in a `jsonc` owned key, each failed the whole load naming
        // the committed file, and took `~/.zshrc` with them.
        let resolved = resolved(
            "[[value]]\nname = \"acct\"\nkind = \"string\"\n\
             [[value]]\nname = \"seg\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/{{acct}}/settings.json\"\ncontent = \"x\"\n\
             [[target]]\npath = \"~/.config/zed/settings.json\"\ncontent = \"{{{{}}\"\n\
             format = \"jsonc\"\nowns = [\"a.{{seg}}\"]\n\
             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n",
            Some("# this account's answers\n[values]\nacct = \"../../..\"\nseg = \"\"\n"),
        )
        .expect("an account's legal answers do not fail the load");

        let acct = blocked(&resolved, 0);
        assert_eq!(
            acct.reason,
            BlockReason::InvalidValue {
                names: vec!["acct".to_string()]
            }
        );
        assert!(acct.hint.contains("local.toml:3"), "{}", acct.hint);
        assert!(acct.hint.contains("climb out of the home"), "{}", acct.hint);

        let seg = blocked(&resolved, 1);
        assert_eq!(
            seg.reason,
            BlockReason::InvalidValue {
                names: vec!["seg".to_string()]
            }
        );
        assert!(seg.hint.contains("local.toml:4"), "{}", seg.hint);
        assert!(seg.hint.contains("empty segment"), "{}", seg.hint);

        assert_eq!(ready(&resolved, 2).path.as_str(), "~/.zshrc");
    }

    #[test]
    fn a_committed_path_that_climbs_out_of_the_home_through_a_doubled_slash_is_refused() {
        // `~//../.bashrc` once folded to `~/.bashrc` and resolved ready: its
        // rest, `/../.bashrc`, was normalised as an absolute path and clamped.
        let message = resolved(
            "[[target]]\npath = \"~//../.bashrc\"\ncontent = \"x\"\n\
             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n",
            None,
        )
        .expect_err("a climb out of the home is refused however it is spelled");
        assert!(message.contains("climb out of the home"), "{message}");
    }

    #[test]
    fn a_substitution_that_breaks_a_key_path_blocks_or_fails_by_whose_input_it_is() {
        const LAYER: &str = "[[value]]\nname = \"setting\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/zed/settings.json\"\n\
                             content = \"{{{{}}\"\n\
                             format = \"jsonc\"\nowns = [\"editor.{{setting}}\"]\n";

        let answered = resolved(LAYER, Some("[values]\nsetting = \"\"\n"))
            .expect("an account's empty answer blocks its target");
        let entry = blocked(&answered, 0);
        assert!(entry.hint.contains("empty segment"), "{}", entry.hint);
        assert!(entry.hint.contains("local.toml:2"), "{}", entry.hint);

        let message = resolved(
            &LAYER.replace("kind = \"string\"\n", "kind = \"string\"\ndefault = \"\"\n"),
            None,
        )
        .expect_err("`editor.` from a committed default is a repo defect");
        assert!(message.contains("empty segment"), "{message}");
    }

    #[test]
    fn a_substitution_that_changes_a_key_path_s_segment_count_blocks_or_fails() {
        // `KeyPath` splits on `.`, so `setting = "b.c"` turned the one key
        // `editor.{{setting}}` into `editor.b.c`: a different key, one level
        // deeper, owned without anyone having written it. An answer may fill a
        // segment; it may not add or remove one.
        const LAYER: &str = "[[value]]\nname = \"setting\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/zed/settings.json\"\n\
                             content = \"{{{{}}\"\n\
                             format = \"jsonc\"\nowns = [\"editor.{{setting}}\"]\n";

        let answered = resolved(LAYER, Some("[values]\nsetting = \"b.c\"\n"))
            .expect("an account's answer blocks its target, not the load");
        let entry = blocked(&answered, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["setting".to_string()]
            }
        );
        for part in [
            "local.toml:2",
            "`owns` key `editor.{{setting}}` has 2 segments as written and 3 once \
             substituted, as `editor.b.c`",
        ] {
            assert!(entry.hint.contains(part), "{part}: {}", entry.hint);
        }

        let message = resolved(
            &LAYER.replace(
                "kind = \"string\"\n",
                "kind = \"string\"\ndefault = \"b.c\"\n",
            ),
            None,
        )
        .expect_err("a committed default that adds a segment is a repo defect");
        assert!(message.contains("segments"), "{message}");
        assert!(message.contains("~/.config/zed/settings.json"), "{message}");

        // Filling the segment is the case the placeholder is for.
        let filled = resolved(LAYER, Some("[values]\nsetting = \"tab_size\"\n")).unwrap();
        assert_eq!(
            ready(&filled, 0).format,
            Format::Jsonc {
                owns: vec![KeyPath::parse("editor.tab_size").unwrap()]
            }
        );
    }

    #[test]
    fn a_field_broken_through_a_derived_value_names_the_declaration_between() {
        // `derived` is not answered; its default carries the answer to `base`
        // in. The broken field is one text, so answering `derived` directly
        // changes it and clears the entry: the hint names that declaration.
        const LAYER: &str = "[[value]]\nname = \"base\"\nkind = \"string\"\n\
                             [[value]]\nname = \"derived\"\nkind = \"string\"\n\
                             default = \"{{base}}\"\n\
                             [[target]]\npath = \"~/.config/zed/settings.json\"\n\
                             content = \"{{{{}}\"\n\
                             format = \"jsonc\"\nowns = [\"a.{{derived}}\"]\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let answered = resolved(LAYER, Some("[values]\nbase = \"b.c\"\n"))
            .expect("an account's answer blocks its target, not the load");
        let entry = blocked(&answered, 0);
        assert!(
            entry.hint.ends_with(
                "because of the answer to `base` at local.toml:2, carried in by the default of \
                 `derived` at bx.toml:4; change that answer, or answer `derived` directly"
            ),
            "{}",
            entry.hint
        );
        ready(&answered, 1);
    }

    #[test]
    fn a_requires_that_detect_could_never_find_blocks_or_fails() {
        // Detection looks a tool up by a bare name on `PATH`, or opens an
        // absolute path. An empty name, a relative one holding a `/`, or one made
        // only of `.` and `..` (a directory, never a tool) is never found, so the
        // target would be reported as waiting on a tool no install could supply.
        // Substituted text is checked like any field.
        const LAYER: &str = "[[value]]\nname = \"tool\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/env\"\ncontent = \"x\"\n\
                             requires = [\"{{tool}}\"]\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        for answer in ["", "bin/sccache", ".", "..", "/"] {
            let answered = resolved(LAYER, Some(&format!("[values]\ntool = \"{answer}\"\n")))
                .unwrap_or_else(|e| panic!("{answer:?} failed the whole load: {e}"));
            let entry = blocked(&answered, 0);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["tool".to_string()]
                },
                "{answer:?}"
            );
            for part in [
                "`requires` names a tool by a bare name to look up on `PATH`, or by an \
                 absolute path",
                "local.toml:2",
            ] {
                assert!(
                    entry.hint.contains(part),
                    "{answer:?} {part}: {}",
                    entry.hint
                );
            }
            ready(&answered, 1);
        }

        let message = resolved(
            &LAYER.replace("kind = \"string\"\n", "kind = \"string\"\ndefault = \"\"\n"),
            None,
        )
        .expect_err("a committed default detection could never find is a repo defect");
        assert!(message.contains("`requires`"), "{message}");
        assert!(message.contains("~/.config/env"), "{message}");

        for answer in ["/usr/bin/sccache", "sccache"] {
            let found = resolved(LAYER, Some(&format!("[values]\ntool = \"{answer}\"\n")))
                .unwrap_or_else(|e| panic!("{answer:?}: {e}"));
            assert_eq!(ready(&found, 0).requires, [answer]);
        }
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
        // declaration order. `derived_between`'s own guard is what keeps it to
        // one entry with one count, which
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
    fn a_committed_requires_defect_fails_the_load_whether_or_not_the_target_is_blocked() {
        // The defect is written entirely in committed text, so it is the
        // layer's for every account. It is checked before the probe, so an
        // account that has not answered `acct` — whose target is blocked on
        // that alone and never reaches substitution — gets the same load error
        // as one that has. Checked only after substitution, the same committed
        // line was fatal for one account and invisible to the other.
        const LAYER: &str = "[[value]]\nname = \"acct\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/{{acct}}/env\"\n\
                             content = \"x\"\nrequires = [\"./bin/foo\"]\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        for local in [None, Some("[values]\nacct = \"one\"\n")] {
            let message = resolved(LAYER, local)
                .expect_err("a committed `requires` defect fails the load for every account");
            assert!(
                message.contains("`requires` names a tool by a bare name"),
                "{local:?}: {message}"
            );
            assert!(message.contains("./bin/foo"), "{local:?}: {message}");
        }
    }

    #[test]
    fn a_requires_defect_an_answer_filled_blocks_only_that_target() {
        // The other half of the same rule: text an answer filled is the
        // account's, so it costs that target and names the line. The check
        // inside `substituted` is what does this, and moving the committed case
        // out of it did not take this with it.
        const LAYER: &str = "[[value]]\nname = \"tool\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/env\"\n\
                             content = \"x\"\nrequires = [\"{{tool}}\"]\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let answered = resolved(LAYER, Some("[values]\ntool = \"./bin/foo\"\n"))
            .expect("an account's answer blocks its target, not the load");
        let entry = blocked(&answered, 0);
        assert!(
            entry
                .hint
                .contains("`requires` names a tool by a bare name"),
            "{}",
            entry.hint
        );
        assert!(entry.hint.contains("local.toml:2"), "{}", entry.hint);
        ready(&answered, 1);
    }

    #[test]
    fn an_answered_value_whose_committed_default_names_an_undeclared_value_resolves() {
        // A default an answer overrides is never expanded, so `Unresolved::
        // Forward` never sees the undeclared `nowhere` and the load succeeds.
        // The `file` walk reads that unexpanded default anyway, and stops at
        // the name with no declaration behind it rather than refusing or
        // panicking. Pinned so that making an undeclared name in an unexpanded
        // default an error becomes a deliberate change.
        const LAYER: &str = "[[value]]\nname = \"s\"\nkind = \"string\"\n\
                             default = \"{{nowhere}}\"\n\
                             [[target]]\npath = \"~/.config/env\"\nfile = \"cfg/{{s}}\"\n";

        let answered = resolved(LAYER, Some("[values]\ns = \"one\"\n"))
            .expect("an overridden default is never expanded, so it is never refused");
        assert_eq!(
            ready(&answered, 0).body,
            Body::File(PathBuf::from("cfg/one"))
        );
    }

    #[test]
    fn a_file_holding_both_a_chained_and_a_direct_path_value_names_the_first_written() {
        // `s` reaches a `path` value through its default and `b` is one
        // directly. The refusal names whichever comes first in written order,
        // with the chain behind it. Naming the direct reference first would
        // tell the reader about `b` alone, and fixing that leaves `s` carrying
        // the same absolute text in.
        const LAYER: &str = "[[value]]\nname = \"b\"\nkind = \"path\"\n\
                             [[value]]\nname = \"s\"\nkind = \"string\"\ndefault = \"{{b}}\"\n\
                             [[target]]\npath = \"~/.config/env\"\n\
                             file = \"cfg/{{s}}/{{b}}/x\"\n";

        let message = resolved(LAYER, None).expect_err("a `path` value in `file` is a defect");
        assert!(
            message.contains(
                "`file` references `s`, whose default at bx.toml:4 is built from `b`, a `path` \
                 value"
            ),
            "{message}"
        );

        // Written the other way round, `b` comes first and is a one-step chain.
        let message = resolved(
            &LAYER.replace("cfg/{{s}}/{{b}}/x", "cfg/{{b}}/{{s}}/x"),
            None,
        )
        .expect_err("a `path` value in `file` is a defect");
        assert!(
            message.contains("`file` references `b`, a `path` value"),
            "{message}"
        );
        assert!(!message.contains("whose default"), "{message}");
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
            resolve(&merged, &home()).map_err(|e| e.to_string())
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
        let resolved = resolve(&merged, &home()).unwrap();

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
        let resolved = resolve(&merged, &home()).expect("nor the resolution");
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

    /// `b`, a `path` value, then `s`, a `string`, then a target whose `file`
    /// is `FILE`, and a second target that references neither.
    const ANSWERED_PATH: &str = "[[value]]\n\
                                 name = \"b\"\n\
                                 kind = \"path\"\n\
                                 [[value]]\n\
                                 name = \"s\"\n\
                                 kind = \"string\"\n\
                                 [[target]]\n\
                                 path = \"~/.config/thing\"\n\
                                 file = \"FILE\"\n\
                                 [[target]]\n\
                                 path = \"~/.zshrc\"\n\
                                 content = \"setopt\"\n";

    #[test]
    fn a_file_body_may_not_reach_a_path_value_through_an_answer() {
        // `s` is a `string` with no default, so nothing committed reaches `b`.
        // The account's answer `s = "{{b}}"` does, and `cfg/{{s}}/x` resolved
        // to a repo file carrying the account's absolute location. No committed
        // layer is at fault, so it blocks this target and names the answer.
        for file in ["cfg/{{s}}/x", "{{s}}/x"] {
            let layer = ANSWERED_PATH.replace("FILE", file);
            for local in [
                "[values]\ns = \"{{b}}\"\nb = \"/home/example/secret-machine-name\"\n",
                // Unanswered, `b` would otherwise block the target with advice
                // to answer it, which leads straight into this block.
                "[values]\ns = \"{{b}}\"\n",
            ] {
                let resolved = resolved(&layer, Some(local))
                    .expect("an account's answer blocks its target, not the load");
                let entry = blocked(&resolved, 0);
                assert_eq!(
                    entry.reason,
                    BlockReason::InvalidValue {
                        names: vec!["s".to_string()]
                    },
                    "{file} {local}"
                );
                assert_eq!(
                    entry.hint,
                    "target `~/.config/thing`: `file` references `s`, whose answer at \
                     local.toml:2 is built from `b`, a `path` value; a `path` value is always \
                     absolute and `file` is relative to the config repo root, because of the \
                     answer to `s` at local.toml:2; change that answer",
                    "{file} {local}"
                );
                assert_eq!(entry.origin.to_string(), "bx.toml:7", "{file} {local}");
                assert_eq!(
                    ready(&resolved, 1).path.as_str(),
                    "~/.zshrc",
                    "{file} {local}"
                );
            }
        }

        // An answer built from no `path` value is the case `file` substitution
        // exists for.
        let ordinary = resolved(
            &ANSWERED_PATH.replace("FILE", "cfg/{{s}}/x"),
            Some("[values]\ns = \"work\"\n"),
        )
        .unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::File(PathBuf::from("cfg/work/x"))
        );
    }

    #[test]
    fn a_file_body_through_an_answer_and_a_default_names_every_step() {
        // `t`, declared between, defaults to `{{b}}`. The walk follows an
        // answer first, then the committed default whether or not it applies.
        let layer = ANSWERED_PATH
            .replace(
                "[[value]]\nname = \"s\"",
                "[[value]]\nname = \"t\"\nkind = \"string\"\ndefault = \"{{b}}\"\n\
                 [[value]]\nname = \"s\"",
            )
            .replace("FILE", "cfg/{{s}}/x");

        for local in [
            // `t` unanswered: its default applies and carries `b` in.
            "[values]\ns = \"{{t}}\"\nb = \"/var/mnt/cfg\"\n",
            // `t` answered: its default does not apply, and is followed anyway,
            // as the committed walk follows it.
            "[values]\ns = \"{{t}}\"\nt = \"work\"\n",
        ] {
            let resolved = resolved(&layer, Some(local)).expect("blocked, not a load error");
            let entry = blocked(&resolved, 0);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["s".to_string()]
                },
                "{local}"
            );
            assert!(
                entry.hint.starts_with(
                    "target `~/.config/thing`: `file` references `s`, whose answer at \
                     local.toml:2 is built from `t`, whose default at bx.toml:4 is built \
                     from `b`, a `path` value; "
                ),
                "{local}: {}",
                entry.hint
            );
            assert!(
                entry.hint.ends_with(
                    ", because of the answer to `s` at local.toml:2; change that answer"
                ),
                "{local}: {}",
                entry.hint
            );
        }

        // Two answers on the way: both are named, in declaration order — `t`
        // before `s`, though the walk met `s` first. `BlockReason::
        // InvalidValue`'s "in declaration order" and `in_declaration_order`
        // both predate this change, and every other block reason uses them;
        // walk order here would be the one exception. An answer may name only
        // an earlier value, so the two orders differ for every chain of two.
        let resolved = resolved(
            &layer,
            Some("[values]\ns = \"{{t}}\"\nt = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n"),
        )
        .expect("blocked, not a load error");
        let entry = blocked(&resolved, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["t".to_string(), "s".to_string()]
            }
        );
        assert!(
            entry.hint.contains(
                "`file` references `s`, whose answer at local.toml:2 is built from `t`, whose \
                 answer at local.toml:3 is built from `b`, a `path` value"
            ),
            "{}",
            entry.hint
        );
        assert!(
            entry.hint.ends_with(
                ", because of the answer to `t` at local.toml:3 and the answer to `s` at \
                 local.toml:2; change that answer"
            ),
            "{}",
            entry.hint
        );
    }

    #[test]
    fn a_path_answer_outside_file_still_resolves() {
        // Only `file` is relative to the repo root. Every other field this
        // walk could have been widened to is what a `path` value is for: two
        // more fields of the very target whose `file` is walked (`requires`,
        // an owned key), the target path, and inline content. `owns` matters
        // most of the four, being the other field that looks repo-shaped.
        let resolved = resolved(
            "[[value]]\nname = \"b\"\nkind = \"path\"\n\
             [[value]]\nname = \"s\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/thing\"\nfile = \"cfg/x\"\n\
             format = \"jsonc\"\nowns = [\"tool.{{s}}\"]\n\
             requires = [\"{{s}}/bin/tool\"]\n\
             [[target]]\npath = \"~/.config/env\"\ncontent = \"DIR={{s}}\"\n\
             [[target]]\npath = \"~/.config/{{s}}/x\"\ncontent = \"x\"\n",
            Some("[values]\ns = \"{{b}}\"\nb = \"/var/mnt/work\"\n"),
        )
        .unwrap();

        assert_eq!(ready(&resolved, 0).requires, ["/var/mnt/work/bin/tool"]);
        assert_eq!(ready(&resolved, 0).body, Body::File(PathBuf::from("cfg/x")));
        assert_eq!(
            ready(&resolved, 0).format,
            Format::Jsonc {
                owns: vec![KeyPath::parse("tool./var/mnt/work").unwrap()]
            }
        );
        assert_eq!(
            ready(&resolved, 1).body,
            Body::Inline("DIR=/var/mnt/work".to_string())
        );
        // A target path may not *open* with a placeholder — the parser refuses
        // that, which is why the plan's own spelling was unusable — but one
        // further along is legal, and the answer reaches it unrefused.
        assert_eq!(
            ready(&resolved, 2).path.as_str(),
            "~/.config/var/mnt/work/x"
        );
    }

    #[test]
    fn a_repo_defect_in_a_target_outranks_a_path_answer_block() {
        // The same target also names a value no layer declares. That is the
        // committed repo's defect and fails the load; blocking the target on
        // the account's answer instead would hide it.
        let message = resolved(
            &ANSWERED_PATH.replace(
                "file = \"FILE\"\n",
                "file = \"cfg/{{s}}/x\"\nrequires = [\"{{nowhere}}\"]\n",
            ),
            Some("[values]\ns = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n"),
        )
        .expect_err("a repo defect fails the load");

        assert!(
            message.contains("no layer declares the value `nowhere`"),
            "{message}"
        );
    }

    #[test]
    fn a_disabled_value_s_answer_is_not_walked() {
        // A switched-off declaration's answer is not this account's value, so
        // the walk does not see it and the target is blocked by the switch, as
        // it was before.
        let switched_off = resolved(
            &ANSWERED_PATH.replace("FILE", "cfg/{{s}}/x"),
            Some(
                "[[value]]\nname = \"s\"\nenabled = false\n\
                 [values]\ns = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n",
            ),
        )
        .unwrap();

        assert_eq!(
            blocked(&switched_off, 0).reason,
            BlockReason::DisabledValue {
                names: vec!["s".to_string()]
            }
        );
        assert!(
            blocked(&switched_off, 0).hint.starts_with("re-enable s"),
            "{}",
            blocked(&switched_off, 0).hint
        );

        // Where that act leads, pinned beside it so the sequence is legible
        // rather than left to a reader to assemble: the same layers with the
        // switch on block on the answer, which changing clears outright. Two
        // statements, each true when it is made, each one progress. The order
        // they are reported in is a consequence of what `enabled` means, not a
        // rule this module keeps for its own sake.
        let switched_on = resolved(
            &ANSWERED_PATH.replace("FILE", "cfg/{{s}}/x"),
            Some("[values]\ns = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n"),
        )
        .unwrap();

        assert_eq!(
            blocked(&switched_on, 0).reason,
            BlockReason::InvalidValue {
                names: vec!["s".to_string()]
            }
        );
    }

    #[test]
    fn switched_off_names_are_ordered_by_declaration_like_every_other_block() {
        // `a` is declared before `b`, and the target names `b` in its path and
        // `a` in its body, so the probe meets them the other way round —
        // `for_each_string` visits the path first. `BlockReason::DisabledValue`
        // documents its names as being in declaration order, like every other
        // block reason, and a switch does not move a declaration.
        let resolved = resolved(
            "[[value]]\nname = \"a\"\nkind = \"string\"\n\
             [[value]]\nname = \"b\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/{{b}}\"\ncontent = \"{{a}}\"\n",
            Some(
                "[[value]]\nname = \"a\"\nenabled = false\n\
                 [[value]]\nname = \"b\"\nenabled = false\n",
            ),
        )
        .unwrap();

        assert_eq!(
            blocked(&resolved, 0).reason,
            BlockReason::DisabledValue {
                names: vec!["a".to_string(), "b".to_string()]
            }
        );
        assert!(
            blocked(&resolved, 0).hint.starts_with("re-enable a, b"),
            "{}",
            blocked(&resolved, 0).hint
        );
    }

    #[test]
    fn a_file_reached_by_a_committed_route_and_an_answered_one_fails_the_load() {
        // `c`'s committed default reaches `b`; the account's answer to `s`
        // reaches it too. The committed way is the same defect for every
        // account and no answer clears it, so it outranks the block whichever
        // name is written first in `file` — written order decides which
        // reference a walk names, not which walk answers. Reporting the block
        // instead would hide a repository defect behind advice to this one
        // account, and would report it only to an account that had answered.
        const LAYER: &str = "[[value]]\nname = \"b\"\nkind = \"path\"\n\
                             [[value]]\nname = \"c\"\nkind = \"string\"\n\
                             default = \"{{b}}\"\n\
                             [[value]]\nname = \"s\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/thing\"\nfile = \"FILE\"\n";

        for file in ["cfg/{{c}}/{{s}}/x", "cfg/{{s}}/{{c}}/x"] {
            let message = resolved(
                &LAYER.replace("FILE", file),
                Some("[values]\ns = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n"),
            )
            .expect_err("the committed route is a load error, not one account's block");
            assert!(
                message.contains(
                    "`file` references `c`, whose default at bx.toml:4 is built from `b`, \
                     a `path` value"
                ),
                "{file}: {message}"
            );
        }
    }

    #[test]
    fn a_switched_off_path_declaration_still_ends_the_walk() {
        // The twin of the test above, for the *terminal* declaration rather
        // than one in the middle. `enabled` gates the answer edge alone: a
        // switched-off `b` is still a `path` declaration, and `s = "{{b}}"`
        // still carries its absolute text into `file`. Blocking on `b` with
        // "re-enable it" would name an act that lands straight back here, and
        // would judge that `b` differently from the committed walk, which
        // fails the load for a `file` whose default chain reaches a
        // switched-off `path` value.
        for local in [
            "[[value]]\nname = \"b\"\nenabled = false\n\
             [values]\ns = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n",
            // Switched off and unanswered: still this block, not `bx init`.
            "[[value]]\nname = \"b\"\nenabled = false\n\
             [values]\ns = \"{{b}}\"\n",
        ] {
            let resolved = resolved(&ANSWERED_PATH.replace("FILE", "cfg/{{s}}/x"), Some(local))
                .expect("blocked, not a load error");
            let entry = blocked(&resolved, 0);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["s".to_string()]
                },
                "{local}"
            );
            assert_eq!(
                entry.hint,
                "target `~/.config/thing`: `file` references `s`, whose answer at \
                 local.toml:5 is built from `b`, a `path` value; a `path` value is always \
                 absolute and `file` is relative to the config repo root, because of the \
                 answer to `s` at local.toml:5; change that answer",
                "{local}"
            );
        }
    }

    #[test]
    fn an_answer_re_entering_a_walked_name_still_resolves() {
        // The `seen` guard along the answer edge. `q`'s answer names `r`,
        // whose committed default names `q` back. That default is never
        // expanded, because `r` is answered, so value resolution never refuses
        // the forward reference and the walk is the one thing that meets the
        // cycle — at `q`, a second time. Without `seen` it recurses until the
        // stack runs out. Nothing on the way is a `path` value, so the target
        // resolves.
        let resolved = resolved(
            "[[value]]\nname = \"r\"\nkind = \"string\"\ndefault = \"{{q}}\"\n\
             [[value]]\nname = \"q\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/.config/thing\"\nfile = \"cfg/{{q}}/x\"\n",
            Some("[values]\nr = \"work\"\nq = \"{{r}}\"\n"),
        )
        .expect("an overridden default may name a later value");

        assert_eq!(
            ready(&resolved, 0).body,
            Body::File(PathBuf::from("cfg/work/x"))
        );
        // `q` has no committed default, so the committed walk returns at once
        // and never reaches its own guard: this cycle is the answer walk's.
        assert_eq!(
            path_value_behind(&resolved.values, "q", &mut Vec::new()).map(|chain| chain.len()),
            None
        );
    }

    #[test]
    fn a_committed_chain_alone_is_not_an_answer_block() {
        // `refuse_path_answer_in_file` may name only answers, and it may say
        // so only because `refuse_path_value_in_file` has already failed the
        // load for every committed way to a `path` value from the same names.
        // That is a claim about a different function, so the guard is called
        // with the chain the claim forbids: `s`'s committed default reaches
        // `b` and the account answered nothing. Were the two walks ever to
        // disagree, this must stay `None` rather than block a target on an
        // empty list of answers to change.
        let layers = vec![
            layer(
                "bx.toml",
                LayerKind::Global,
                "[[value]]\nname = \"b\"\nkind = \"path\"\n\
                 [[value]]\nname = \"s\"\nkind = \"string\"\ndefault = \"{{b}}\"\n\
                 [[target]]\npath = \"~/.config/thing\"\ncontent = \"x\"\n",
            )
            .unwrap(),
        ];
        let merged = merge(&layers, &home()).unwrap();
        let values =
            ResolvedValues::resolve(merged.values.clone(), &merged.value_assignments, &home())
                .unwrap();

        // The chain is there for the committed walk, which owes the load error.
        assert!(
            refuse_path_value_in_file(&merged.targets[0], "cfg/{{s}}/x", &values).is_err(),
            "the committed walk is the one that reaches this chain"
        );
        assert_eq!(
            refuse_path_answer_in_file(
                &merged.targets[0],
                "cfg/{{s}}/x",
                &values,
                &merged.value_assignments,
            ),
            None
        );
    }
}
