//! Keeping a target's repo file inside the repo and free of machine locations.
//!
//! A `file` or `secret` body names a file relative to the config repo root, so
//! no value substituted into it may carry an absolute or home-rooted text: a
//! `path` value reached through committed defaults fails the load, one reached
//! through this account's answer blocks the target, and a value of any other
//! kind is judged on the text substituted in.

use super::substitute::Broken;
use crate::config::Error;
use crate::config::target::{Body, Target};
use crate::config::values::{ResolvedValues, ValueAssignment, ValueDecl};

/// The body key that names a repo file, with the file as written.
///
/// `file`, or `secret`, whose ciphertext is a repo file by the same rule: every
/// refusal that keeps `file` inside the repo and free of machine locations
/// keeps `secret` there too, since an escape through it would decrypt whatever
/// age file it reached into the target.
pub(super) fn repo_file(body: &Body) -> Option<(&'static str, std::borrow::Cow<'_, str>)> {
    match body {
        Body::File(path) => Some(("file", path.to_string_lossy())),
        Body::Secret(path) => Some(("secret", path.to_string_lossy())),
        Body::Inline(_) | Body::Generated(_) | Body::Symlink(_) | Body::Dir => None,
    }
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
///
/// `key` is the body key that names the repo file, as [`repo_file`] gives it.
pub(super) fn refuse_path_value_in_file(
    target: &Target,
    key: &str,
    file: &str,
    values: &ResolvedValues,
) -> Result<(), Error> {
    let names = crate::config::values::placeholders(file).unwrap_or_default();
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
            "target `{}`: `{key}` references `{}`{steps}, a `path` value; a `path` value \
             is always absolute and `{key}` is relative to the config repo root, so no \
             answer could make it name a file in the repo; reference a `string` value\
             {not_built}, with relative text: an absolute text is refused in `{key}` \
             whatever its kind",
            target.path, chain[0].name
        ),
    })
}

/// The declarations from `name` down its committed defaults to a `path` value.
///
/// Depth first, each default's references in the order written. `seen` stops
/// the walk at a name it has already walked, and it is reachable.
/// [`Unresolved::Forward`](crate::config::values::Unresolved::Forward) keeps every
/// *expanded* default acyclic, since a default may reference only an earlier
/// declaration. But a default an answer overrides is never expanded, so
/// `default = "{{q}}"` on an answered `q` reaches this walk unrefused, and
/// without `seen` the walk would recurse until the stack ran out.
fn path_value_behind<'a>(
    values: &'a ResolvedValues,
    name: &str,
    seen: &mut Vec<String>,
) -> Option<Vec<&'a crate::config::values::ValueDecl>> {
    if seen.iter().any(|walked| walked == name) {
        return None;
    }
    seen.push(name.to_string());
    let decl = values.decl(name)?;
    if decl.kind == crate::config::values::ValueKind::Path {
        return Some(vec![decl]);
    }
    let default = decl.default.as_ref()?.to_string();
    crate::config::values::placeholders(&default)
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
/// account's answer opens *into a `path` value*. An absolute literal reaching
/// `file` through a value of another kind — a plain `string` answered
/// `/home/example/…` — is judged on its substituted text by
/// [`refuse_rooted_value_in_file`], once every value is answered.
pub(super) fn refuse_path_answer_in_file(
    target: &Target,
    key: &str,
    file: &str,
    values: &ResolvedValues,
    assignments: &[ValueAssignment],
) -> Option<(Vec<String>, String)> {
    let mut seen: Vec<String> = Vec::new();
    let chain = crate::config::values::placeholders(file)
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
        "target `{}`: `{key}` references {steps}, a `path` value; a `path` value is always \
         absolute and `{key}` is relative to the config repo root",
        target.path
    );

    let names = values.in_declaration_order(
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
    let hint = crate::config::values::path_answer_hint(&problem, &answers);
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
/// reads them — so such a declaration is not a wall, and the walk goes through
/// it by its default. `a_switched_off_declaration_is_walked_through_by_its_default`
/// pins both halves of that: the default followed, the answer over it not.
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
/// The rule is stated with its sites so a reader can check it rather than
/// take it. **Seven** places read a `ValueDecl`'s `enabled`. Six ask the
/// account-value question:
///
/// - [`ResolvedValues::resolve`], which gives a switched-off declaration no
///   answer of this account's — the site the other five and everything below
///   follow from;
/// - `check_answer`, which refuses an answer to one;
/// - [`ResolvedValues::unset_required`], and the test-only
///   `ResolvedValues::decls` and `ResolvedValues::unset`, each listing what
///   this account may answer;
/// - the answer edge here.
///
/// The seventh is `merge`'s `<ValueDecl as Keyed>::enabled`, and it asks
/// nothing, because it is never called. `Keyed::enabled` is read in one place,
/// `Merged::into_enabled`, which is instantiated once — for `Target`.
/// Declarations leave the merge through `into_entries`, which keeps the
/// switched-off ones so that a reference to one stays distinguishable from a
/// reference to a name no layer declares. The accessor exists because `Keyed`
/// requires it of a public list type, and says so at its definition. Its
/// sibling `set_enabled` **writes** the field and is live: it is how a later
/// layer's toggle switches a declaration off in the first place.
///
/// Nothing else reads it. `roots`, [`ResolvedValues::substitute`] and
/// [`ResolvedValues::get`] all behave correctly for a switched-off declaration
/// **without** consulting `enabled`, because they read the answer `resolve`
/// already derived; they are consequences of the first site, not further
/// sites. `Target::enabled` is a different field on a different type — a
/// target's own switch, and the one `into_enabled` acts on.
///
/// Everything that asks what a declaration *is* reads it through
/// [`ResolvedValues::decl`] or [`ResolvedValues::index_of`], both unfiltered,
/// and ignores `enabled`: this walk's terminal, [`path_value_behind`],
/// `merge`'s `written_form` kind lookups, and
/// [`ResolvedValues::in_declaration_order`]. A resolve-side copy of that last
/// one was the single exception — it indexed against the filtered `decls`, so
/// a switch moved a declaration's position — and every caller now uses the
/// one method.
///
/// This list was derived by grepping `enabled` across `src` and classifying
/// every hit, reads and writes alike. Two earlier versions were not: the first
/// named two sites that do not read `enabled` and missed one that does, and
/// the second disposed of its neighbours with "a different field on a
/// different type", a clause that silently excluded the one site which is the
/// same field on the same type. A site is named and dispositioned here, or it
/// is not covered.
///
/// `seen` stops the walk at a name it has already walked, and it is
/// load-bearing here for the reason [`path_value_behind`] gives: an overridden
/// default is never expanded, so
/// [`Unresolved::Forward`](crate::config::values::Unresolved::Forward) never refuses a
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
    if decl.kind == crate::config::values::ValueKind::Path {
        return Some(vec![Step::Terminal(decl)]);
    }

    // The same lookup `ResolvedValues::resolve` answers a declaration with.
    let answer = assignments
        .iter()
        .find(|answer| answer.name == decl.name)
        .filter(|_| decl.enabled);
    if let Some(answer) = answer {
        let text = answer.value.to_string();
        let through = crate::config::values::placeholders(&text)
            .unwrap_or_default()
            .into_iter()
            .find_map(|next| path_value_through_answer(values, assignments, next, seen));
        if let Some(mut chain) = through {
            chain.insert(0, Step::Answer(decl, answer));
            return Some(chain);
        }
    }

    let default = decl.default.as_ref()?.to_string();
    crate::config::values::placeholders(&default)
        .unwrap_or_default()
        .into_iter()
        .find_map(|next| path_value_through_answer(values, assignments, next, seen))
        .map(|mut chain| {
            chain.insert(0, Step::Default(decl));
            chain
        })
}

/// Refuse a `file` any of whose values is substituted in as rooted text.
///
/// [`crate::config::target::confine_to_repo`] judges the whole substituted `file`, and
/// that is not enough: `cfg/{{dir}}/gitconfig` with `dir` answered
/// `/home/example/…` normalises to `cfg/home/example/…/gitconfig`, which is
/// relative and inside the repo, and carries the account's machine location
/// into a repository meant to be account-independent. So each value's text is
/// judged as it is substituted in, in written order, whatever the value's
/// declared kind — the refusal is decided on the text, so choosing a different
/// kind does not walk around it.
///
/// A `path` value never reaches here: [`refuse_path_value_in_file`] and
/// [`refuse_path_answer_in_file`] have refused or blocked every `file` that
/// reaches one, with their own messages. This closes the remaining route, an
/// absolute literal in a value of any other kind.
///
/// The field carried out is the one `{{name}}`, not the whole `file`, so
/// [`resolve_target`](super::resolve_target) asks which answers went into
/// **that value**: an account's answer blocks this target naming its line, and
/// a committed `default` with no answer in it fails the load.
///
/// Judging only the text substituted **directly** is not enough either: `dir`
/// defaulting to `x/{{base}}` with `base` answered `/home/example/…` puts
/// `x//home/example/…` into `file`, which opens with neither `/` nor `~`. So
/// every value along the chain is judged — each one named in `file`, then the
/// values *its* text was built from, depth first in written order, following
/// only the text that actually answered it
/// ([`ResolvedValues::built_from`]), so an overridden default is never read.
/// The message names each value on the way to the rooted one; the field
/// carried out is still the `{{name}}` written in `file`, whose account inputs
/// include every answer along that chain.
pub(super) fn refuse_rooted_value_in_file(
    key: &str,
    raw: &str,
    values: &ResolvedValues,
    sub: &impl Fn(&str) -> Result<String, Broken>,
) -> Result<(), Broken> {
    let mut seen: Vec<String> = Vec::new();
    for name in crate::config::values::placeholders(raw).unwrap_or_default() {
        let Some((chain, text)) = rooted_value_behind(values, name, sub, &mut seen)? else {
            continue;
        };
        let through: String = chain
            .windows(2)
            .map(|pair| format!(", which is built from `{}`", pair[1]))
            .collect();
        let rooted = chain.last().map_or(name, String::as_str);
        let problem = if chain.len() > 1 {
            format!(
                "`{key}` takes `{name}`{through}, and `{rooted}` is {text:?}, which is rooted \
                 at the filesystem or the home; `{key}` is relative to the config repo root, \
                 so every value in it, and every value those are built from, must be \
                 relative text whatever its kind"
            )
        } else {
            format!(
                "`{key}` takes `{name}` as {text:?}, which is rooted at the filesystem or \
                 the home; `{key}` is relative to the config repo root, so a value in it \
                 must be relative text whatever its kind"
            )
        };
        return Err(Broken::Field {
            raw: format!("{{{{{name}}}}}"),
            problem,
        });
    }
    Ok(())
}

/// The names from `name` down to the first value whose own text is rooted,
/// with that text.
///
/// Depth first: `name`'s own text, then each value its answering text was built
/// from, in written order. `seen` skips a name already judged, so a value
/// shared by two references in `file` is judged once.
fn rooted_value_behind(
    values: &ResolvedValues,
    name: &str,
    sub: &impl Fn(&str) -> Result<String, Broken>,
    seen: &mut Vec<String>,
) -> Result<Option<(Vec<String>, String)>, Broken> {
    if seen.iter().any(|judged| judged == name) {
        return Ok(None);
    }
    seen.push(name.to_string());
    let text = sub(&format!("{{{{{name}}}}}"))?;
    if crate::config::target::names_a_machine_location(&text) {
        return Ok(Some((vec![name.to_string()], text)));
    }
    for next in values.built_from(name) {
        if let Some((mut chain, text)) = rooted_value_behind(values, next, sub, seen)? {
            chain.insert(0, name.to_string());
            return Ok(Some((chain, text)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{blocked, home, layer, ready, resolved};
    use super::*;
    use crate::config::LayerKind;
    use crate::config::merge::merge;
    use crate::config::resolution::BlockReason;
    use crate::config::target::{Format, KeyPath};
    use std::path::PathBuf;

    #[test]
    fn a_rooted_text_substituted_into_a_file_body_is_refused_whatever_its_kind() {
        // Inside `file`, an absolute answer normalises away its leading `/`:
        // `cfg/{{cfg_dir}}/gitconfig` with `/home/example/…` became the
        // relative `cfg/home/example/…/gitconfig` and resolved Ready, carrying
        // the account's machine location into the repo. The refusal reads the
        // text substituted in, so no declared kind walks around it.
        const LAYER: &str = "[[value]]\n\
                             name = \"cfg_dir\"\n\
                             kind = \"KIND\"\n\
                             [[target]]\n\
                             path = \"~/.gitconfig\"\n\
                             file = \"cfg/{{cfg_dir}}/gitconfig\"\n\
                             [[target]]\n\
                             path = \"~/.zshrc\"\n\
                             content = \"setopt\"\n";

        for (kind, answer) in [
            ("string", "/home/example/secret-machine-name"),
            ("string", "~/secret-machine-name"),
            ("email", "/home/example@host"),
        ] {
            let answered = resolved(
                &LAYER.replace("KIND", kind),
                Some(&format!("[values]\ncfg_dir = \"{answer}\"\n")),
            )
            .unwrap_or_else(|e| panic!("{kind} {answer}: an answer failed the load: {e}"));
            let entry = blocked(&answered, 0);
            assert_eq!(
                entry.reason,
                BlockReason::InvalidValue {
                    names: vec!["cfg_dir".to_string()]
                },
                "{kind} {answer}"
            );
            for part in [
                "target `~/.gitconfig`: `file` takes `cfg_dir`",
                "relative to the config repo root",
                "the answer to `cfg_dir` at local.toml:2",
            ] {
                assert!(
                    entry.hint.contains(part),
                    "{kind} {answer} {part}: {}",
                    entry.hint
                );
            }
            assert_eq!(ready(&answered, 1).path.as_str(), "~/.zshrc", "{kind}");
        }

        // A committed default with no answer in it is the repo's own defect.
        let message = resolved(
            &LAYER.replace(
                "kind = \"KIND\"\n",
                "kind = \"string\"\ndefault = \"/var/mnt/cfg\"\n",
            ),
            None,
        )
        .expect_err("a committed rooted default is a repo defect");
        assert!(
            message.contains("bx.toml:5: target `~/.gitconfig`: `file` takes `cfg_dir`"),
            "{message}"
        );

        // The case `file` substitution exists for still resolves.
        let ordinary = resolved(
            &LAYER.replace("KIND", "string"),
            Some("[values]\ncfg_dir = \"work\"\n"),
        )
        .unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::File(PathBuf::from("cfg/work/gitconfig"))
        );
    }

    #[test]
    fn a_rooted_text_behind_a_derived_value_in_a_file_body_is_refused() {
        // `dir` defaults to `x/{{base}}`, so `base` answered `/home/example/…`
        // put `x//home/example/…` into `file`: not rooted itself, and it
        // resolved Ready as `cfg/x/home/example/…/gitconfig`. Every value along
        // the chain is judged, not only the one written in `file`.
        const LAYER: &str = "[[value]]\n\
                             name = \"base\"\n\
                             kind = \"string\"\n\
                             BASE_DEFAULT\
                             [[value]]\n\
                             name = \"mid\"\n\
                             kind = \"string\"\n\
                             default = \"m/{{base}}\"\n\
                             [[value]]\n\
                             name = \"dir\"\n\
                             kind = \"string\"\n\
                             default = \"x/{{mid}}\"\n\
                             [[target]]\n\
                             path = \"~/.gitconfig\"\n\
                             file = \"cfg/{{dir}}/gitconfig\"\n\
                             [[target]]\n\
                             path = \"~/.zshrc\"\n\
                             content = \"setopt\"\n";
        let layer = |default: &str| LAYER.replace("BASE_DEFAULT", default);

        // An account's answer at the end of the chain blocks the target, naming
        // the chain and the answer's line.
        let answered = resolved(
            &layer(""),
            Some("[values]\nbase = \"/home/example/secret\"\n"),
        )
        .unwrap();
        let entry = blocked(&answered, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["base".to_string()]
            }
        );
        for part in [
            "`file` takes `dir`, which is built from `mid`, which is built from `base`, \
             and `base` is \"/home/example/secret\"",
            "the answer to `base` at local.toml:2",
        ] {
            assert!(entry.hint.contains(part), "{part}: {}", entry.hint);
        }
        assert_eq!(ready(&answered, 1).path.as_str(), "~/.zshrc");

        // A committed chain with no answer in it is the repo's defect.
        let message = resolved(&layer("default = \"/var/mnt/cfg\"\n"), None)
            .expect_err("a committed rooted default behind `file` is a repo defect");
        assert!(
            message.contains("`file` takes `dir`, which is built from `mid`"),
            "{message}"
        );

        // An answer that routes `file` through a committed rooted value is the
        // account's to change.
        let through = resolved(
            &layer("default = \"/var/mnt/cfg\"\n"),
            Some("[values]\ndir = \"y/{{base}}\"\n"),
        )
        .unwrap();
        let entry = blocked(&through, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["dir".to_string()]
            }
        );
        assert!(
            entry
                .hint
                .contains("`file` takes `dir`, which is built from `base`"),
            "{}",
            entry.hint
        );

        // An overridden default is not read: `dir` answered `work` never
        // carries `base`, whatever `base` is.
        let overridden = resolved(
            &layer(""),
            Some("[values]\nbase = \"/home/example/secret\"\ndir = \"work\"\n"),
        )
        .unwrap();
        assert_eq!(
            ready(&overridden, 0).body,
            Body::File(PathBuf::from("cfg/work/gitconfig"))
        );

        // A relative chain still resolves.
        let relative = resolved(&layer(""), Some("[values]\nbase = \"work\"\n")).unwrap();
        assert_eq!(
            ready(&relative, 0).body,
            Body::File(PathBuf::from("cfg/x/m/work/gitconfig"))
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
    fn a_secret_reaching_a_path_value_through_an_answer_is_blocked() {
        let layer = "[[value]]\n\
                     name = \"base\"\n\
                     kind = \"path\"\n\
                     default = \"~/x\"\n\
                     [[value]]\n\
                     name = \"account\"\n\
                     kind = \"string\"\n\
                     [[target]]\n\
                     path = \"~/.token\"\n\
                     secret = \"secrets/{{account}}/token.age\"\n\
                     mode = \"0600\"\n";
        let through = resolved(layer, Some("[values]\naccount = \"{{base}}\"\n"))
            .expect("an answer reaching a `path` value blocks its target, not the load");
        let entry = blocked(&through, 0);
        assert!(
            entry.hint.contains("`secret` references `account`"),
            "{}",
            entry.hint
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
                         could make it name a file in the repo; reference a `string` value, \
                         with relative text: an absolute text is refused in `file` whatever \
                         its kind"
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
    fn a_switched_off_declaration_is_walked_through_by_its_default() {
        // `enabled` gates the answer edge and nothing else, so a switched-off
        // declaration is not a wall. `d` is off, but its committed default
        // reaches `b`, and the walk follows that default straight through it:
        // the target blocks on the answer that led there, naming `d`'s
        // default as the step, rather than on `d`'s switch.
        const THROUGH: &str = "[[value]]\nname = \"b\"\nkind = \"path\"\n\
                               [[value]]\nname = \"d\"\nkind = \"string\"\n\
                               default = \"{{b}}\"\n\
                               [[value]]\nname = \"s\"\nkind = \"string\"\n\
                               [[target]]\npath = \"~/.config/thing\"\n\
                               file = \"cfg/{{s}}/x\"\n";

        let walked = resolved(
            THROUGH,
            Some(
                "[[value]]\nname = \"d\"\nenabled = false\n\
                 [values]\ns = \"{{d}}\"\n",
            ),
        )
        .expect("blocked, not a load error");
        assert_eq!(
            blocked(&walked, 0).reason,
            BlockReason::InvalidValue {
                names: vec!["s".to_string()]
            }
        );
        assert!(
            blocked(&walked, 0).hint.contains(
                "`file` references `s`, whose answer at local.toml:5 is built from `d`, \
                 whose default at bx.toml:4 is built from `b`, a `path` value"
            ),
            "{}",
            blocked(&walked, 0).hint
        );

        // The other half of "the answer edge alone": `d`'s default is now a
        // plain string and its ANSWER is what reaches `b`. While the switch is
        // off that answer is not this account's value, so the walk does not
        // follow it and finds nothing; the switch is what reports.
        const BY_ANSWER: &str = "[[value]]\nname = \"b\"\nkind = \"path\"\n\
                                 [[value]]\nname = \"d\"\nkind = \"string\"\n\
                                 default = \"work\"\n\
                                 [[value]]\nname = \"s\"\nkind = \"string\"\n\
                                 [[target]]\npath = \"~/.config/thing\"\n\
                                 file = \"cfg/{{s}}/x\"\n";
        const ANSWERS: &str = "[values]\ns = \"{{d}}\"\nd = \"{{b}}\"\n\
                               b = \"/var/mnt/cfg\"\n";

        let gated = resolved(
            BY_ANSWER,
            Some(&format!(
                "[[value]]\nname = \"d\"\nenabled = false\n{ANSWERS}"
            )),
        )
        .expect("blocked, not a load error");
        assert_eq!(
            blocked(&gated, 0).reason,
            BlockReason::DisabledValue {
                names: vec!["d".to_string()]
            }
        );

        // The same answers with the switch on: the answer really does reach
        // `b`, so the case above is the gate working and not an answer that
        // was never going to get there.
        let ungated = resolved(BY_ANSWER, Some(ANSWERS)).expect("blocked, not a load error");
        assert_eq!(
            blocked(&ungated, 0).reason,
            BlockReason::InvalidValue {
                names: vec!["d".to_string(), "s".to_string()]
            }
        );
    }

    #[test]
    fn a_path_answer_block_outranks_an_unrelated_disabled_or_invalid_value() {
        // The placement this block was given is "before the disabled, invalid
        // and unset blocks", and only the unset half was ever exercised. Each
        // of the other two is given a value of its own, in `requires`, with
        // nothing to do with the way `file` reaches `b`: clearing either one
        // would leave this target blocked here, so neither may be reported
        // first. The second half of each case drops the answer route and shows
        // the block that would otherwise have won, so the first half is a
        // statement about precedence rather than about the only block there is.
        const LAYER: &str = "[[value]]\nname = \"b\"\nkind = \"path\"\n\
                             [[value]]\nname = \"other\"\nkind = \"KIND\"\n\
                             [[value]]\nname = \"s\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/thing\"\nfile = \"FILE\"\n\
                             requires = [\"{{other}}\"]\n";
        let reaching = "cfg/{{s}}/x";

        for (kind, local, without) in [
            // Switched off: `other` is unrelated to the way to `b`.
            (
                "string",
                "[[value]]\nname = \"other\"\nenabled = false\n\
                 [values]\ns = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n",
                BlockReason::DisabledValue {
                    names: vec!["other".to_string()],
                },
            ),
            // Answered something its kind refuses, likewise unrelated.
            (
                "path",
                "[values]\ns = \"{{b}}\"\nb = \"/var/mnt/cfg\"\n\
                 other = \"relative/thing\"\n",
                BlockReason::InvalidValue {
                    names: vec!["other".to_string()],
                },
            ),
        ] {
            let layer = LAYER.replace("KIND", kind);

            let blocking = resolved(&layer.replace("FILE", reaching), Some(local)).unwrap();
            assert_eq!(
                blocked(&blocking, 0).reason,
                BlockReason::InvalidValue {
                    names: vec!["s".to_string()]
                },
                "{kind}: the path-answer block did not outrank {without:?}"
            );
            assert!(
                blocked(&blocking, 0).hint.contains("a `path` value"),
                "{kind}: {}",
                blocked(&blocking, 0).hint
            );

            // The same layers with `file` reaching nothing: the block that was
            // outranked is really there, and really would have reported.
            let alone = resolved(&layer.replace("FILE", "cfg/x"), Some(local)).unwrap();
            assert_eq!(blocked(&alone, 0).reason, without, "{kind}");
        }
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
            refuse_path_value_in_file(&merged.targets[0], "file", "cfg/{{s}}/x", &values).is_err(),
            "the committed walk is the one that reaches this chain"
        );
        assert_eq!(
            refuse_path_answer_in_file(
                &merged.targets[0],
                "file",
                "cfg/{{s}}/x",
                &values,
                &merged.value_assignments,
            ),
            None
        );
    }
}
