//! Whether a target's `requires` entry names a tool detection could find.
//!
//! Judged twice: against stand-in texts before any value is substituted, so a
//! committed skeleton no string could complete is the layer's defect, and on
//! the substituted text, so an answer that breaks it blocks only its target.

use crate::config::Error;
use crate::config::target::Target;

/// Refuse a `requires` entry **no text at all** could make findable.
///
/// The boundary is the **committed skeleton**: an entry that no string, put in
/// place of its placeholders, could make findable is broken by the bytes a
/// layer wrote, so it is that layer's defect whatever anyone answered. An entry
/// holding no placeholder is the degenerate case of that, not a separate rule —
/// its one producible text is the text as written. Holding a placeholder is
/// therefore no exemption: `requires = ["bin/{{tool}}"]` is a relative name
/// with a `/` in it whatever text fills `{{tool}}`, and is refused here.
///
/// The boundary is deliberately **not** "no answer could satisfy it", which is
/// the wider set: a declared kind narrows which strings are answers, so
/// `requires = ["bx{{sfx}}"]` with `sfx` of kind `path` is unsatisfiable by
/// every answer — a `path` is always absolute, so the result always holds a `/`
/// and never opens with one — and is still not refused here. That is by design,
/// and the reason is which file the verdict would then depend on. A `[[value]]`
/// declaration is **not** restricted to committed layers; only a `[values]`
/// table is. An account may redeclare `sfx` in `local.toml` and change its
/// kind, so a kind-aware refusal would let an account's own edit fail the whole
/// load — or repair a load its layers broke — which is exactly the
/// account-caused whole-load failure resolution exists to prevent. A kind
/// narrowing an entry into unusability therefore stays a **blocked target**: it
/// names the value and costs that one entry, which is what an account can act
/// on. `a_kind_that_narrows_a_requires_skeleton_blocks_the_target_not_the_load`
/// pins that, and pins that the load survives it.
///
/// Checked **before** the probe, beside
/// [`refuse_path_value_in_file`](super::repo_file::refuse_path_value_in_file),
/// because [`substituted`](super::substitute::substituted) is reached only once
/// every value the target references has a usable answer: left there alone,
/// the very same committed line would fail the load for an account that has
/// answered and be invisible to one that has not.
///
/// [`check_requirement`] still runs inside `substituted`, for an entry some
/// answer could have satisfied and this account's did not — `["{{tool}}"]` with
/// `tool = "./bin/foo"`. That is the account's to change, and it costs that
/// target alone.
///
/// A malformed placeholder is left to the probe, which reports it with the rest
/// of the target's defects, so text `scan` refuses is passed over here.
///
/// The `owns` arity check needs no twin: with no placeholder in the key, the
/// substituted text is the text as written, so its segment count cannot move.
pub(super) fn refuse_committed_requirement(target: &Target, tool: &str) -> Result<(), Error> {
    let Ok(pieces) = crate::config::values::scan(tool) else {
        return Ok(());
    };
    let satisfiable = REQUIREMENT_STAND_INS
        .iter()
        .any(|stand_in| check_requirement(&stood_in(&pieces, stand_in)).is_ok());
    if satisfiable {
        return Ok(());
    }
    Err(Error::BadValue {
        origin: target.origin.clone(),
        message: format!("target `{}`: {}", target.path, unfindable_requirement(tool)),
    })
}

/// The two texts [`refuse_committed_requirement`] asks its question with.
///
/// [`check_requirement`] reads a substituted text three ways: whether it opens
/// with `/`, whether it holds a `/` anywhere, and whether every `/`-separated
/// segment is empty, `.` or `..`. A filled placeholder moves all three only
/// through the text it contributes, so two stand-ins settle the whole question
/// rather than a list of shapes that would keep growing.
///
/// Suppose some assignment of strings passes. Then the text it makes opens with
/// `/`, or holds no `/`; take each in turn.
///
/// - **It opens with `/`.** Split on the **first piece**, not on where the `/`
///   came from. If that piece is a literal it is non-empty — `scan` emits no
///   empty literal — so the result begins with its first byte under every
///   assignment, this one included, and both stand-ins leave it alone. If that
///   piece is a name, `/q` begins with `/`, so the result does too whatever
///   follows. Either way `/q` opens with `/`. (Splitting instead on the origin
///   of the `/` misses `{{a}}/usr/bin` with `a` empty, where the `/` is
///   committed text that is not before the first placeholder.)
/// - **It holds no `/`.** Then no committed chunk holds one and no substituted
///   text does, so `q`, which holds none either, leaves the result `/`-free.
///
/// Neither stand-in is empty or a dot, and a text reaching this question holds
/// at least one placeholder — with none, both stand-ins reproduce the text
/// unchanged and the question is just [`check_requirement`] — so neither
/// stand-in can make an all-dots result that the committed text did not force.
///
/// One of the two therefore passes whenever any assignment does, so refusing
/// when both fail refuses only an entry no string rescues. They stand in for an
/// arbitrary string, which is the whole boundary and not an approximation of a
/// kind-aware one; [`refuse_committed_requirement`] says why the kind is
/// deliberately not consulted.
///
/// `a_requires_skeleton_only_one_stand_in_satisfies_is_not_a_committed_defect`
/// pins that both are needed, and
/// `a_requires_skeleton_no_text_could_complete_fails_the_load` pins the
/// refusal itself.
const REQUIREMENT_STAND_INS: [&str; 2] = ["/q", "q"];

/// `pieces` with every `{{name}}` replaced by `stand_in`.
fn stood_in(pieces: &[crate::config::values::Piece<'_>], stand_in: &str) -> String {
    pieces
        .iter()
        .map(|piece| match piece {
            crate::config::values::Piece::Literal(literal) => *literal,
            crate::config::values::Piece::Name(_) => stand_in,
        })
        .collect()
}

/// Refuse a `requires` entry detection could never find.
///
/// Detection looks a bare name up on `PATH` and opens an absolute path as it
/// is; a relative name holding a `/` is never found, and an empty one would be
/// joined onto every `PATH` directory. A name made only of `.` and `..`
/// segments (`/` among them) names a directory, which detection never counts
/// as a tool. Checked once substituted, because an answer is where any of these
/// most plausibly comes from — and, through [`refuse_committed_requirement`],
/// against stand-in texts before the probe, so a skeleton no string satisfies
/// is the layer's defect rather than one account's.
pub(super) fn check_requirement(text: &str) -> Result<(), String> {
    let only_dots = text
        .split('/')
        .all(|segment| matches!(segment, "" | "." | ".."));
    if only_dots || (text.contains('/') && !text.starts_with('/')) {
        return Err(unfindable_requirement(text));
    }
    Ok(())
}

/// How [`check_requirement`] says it refused `text`.
///
/// One spelling, so the pre-probe refusal reports a skeleton the way the
/// post-substitution one reports a filled text.
fn unfindable_requirement(text: &str) -> String {
    format!(
        "`requires` names a tool by a bare name to look up on `PATH`, or by an \
         absolute path; got {text:?}"
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::{blocked, ready, resolved};
    use crate::config::resolution::BlockReason;

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
    fn a_requires_skeleton_no_text_could_complete_fails_the_load() {
        // `bin/{{tool}}` is a relative name holding a `/` whatever text fills
        // `{{tool}}`, so the committed skeleton alone makes it unfindable and
        // holding a placeholder is no exemption. The three account states below are the
        // ones that used to disagree: unanswered the target was blocked on
        // `tool` with a hint no answer cleared, answered it was blocked naming
        // the answer's line, and with a committed `default` the load failed.
        // One committed line, one verdict.
        const DECL: &str = "[[value]]\nname = \"tool\"\nkind = \"string\"\n";
        const WITH_DEFAULT: &str =
            "[[value]]\nname = \"tool\"\nkind = \"string\"\ndefault = \"foo\"\n";
        const TARGETS: &str = "[[target]]\npath = \"~/.config/env\"\n\
                               content = \"x\"\nrequires = [\"bin/{{tool}}\"]\n\
                               [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        for (global, local) in [
            (DECL, None),
            (DECL, Some("[values]\ntool = \"foo\"\n")),
            (WITH_DEFAULT, None),
        ] {
            let message = resolved(&format!("{global}{TARGETS}"), local)
                .expect_err("a skeleton no string completes fails the load for every account");
            assert!(
                message.contains("`requires` names a tool by a bare name"),
                "{local:?}: {message}"
            );
            // The skeleton is reported as committed, which is the text a
            // maintainer has to edit — not one account's filled-in version.
            assert!(message.contains("bin/{{tool}}"), "{local:?}: {message}");
        }
    }

    #[test]
    fn a_requires_skeleton_only_one_stand_in_satisfies_is_not_a_committed_defect() {
        // Both halves of the pre-probe question, each satisfied by one stand-in
        // and not the other. `{{dir}}/foo` opens with the placeholder, so an
        // absolute answer makes it an absolute path — the `/q` stand-in — while
        // a bare one does not. `bx{{sfx}}` holds no `/` in its committed text,
        // so a `/`-free answer makes it a bare name — the `q` stand-in — while
        // an absolute one does not. Asking with either stand-in alone would
        // refuse one of these two at load, for an account that has answered
        // nothing.
        const LAYER: &str = "[[value]]\nname = \"dir\"\nkind = \"string\"\n\
                             [[value]]\nname = \"sfx\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/env\"\n\
                             content = \"x\"\nrequires = [\"{{dir}}/foo\"]\n\
                             [[target]]\npath = \"~/.config/other\"\n\
                             content = \"y\"\nrequires = [\"bx{{sfx}}\"]\n";

        // Unanswered: the load succeeds and each target waits on its value.
        let waiting =
            resolved(LAYER, None).expect("a skeleton some answer completes is not a load error");
        for index in [0, 1] {
            let entry = blocked(&waiting, index);
            assert!(
                matches!(entry.reason, BlockReason::UnsetValue { .. }),
                "{index}: {:?}",
                entry.reason
            );
        }

        // Answered the way the stand-ins stand in for: both resolve.
        let answered = resolved(
            LAYER,
            Some("[values]\ndir = \"/usr/bin\"\nsfx = \"-nightly\"\n"),
        )
        .expect("the answers complete both skeletons");
        assert_eq!(ready(&answered, 0).requires, ["/usr/bin/foo"]);
        assert_eq!(ready(&answered, 1).requires, ["bx-nightly"]);
    }

    #[test]
    fn a_requires_skeleton_an_empty_answer_completes_is_not_a_committed_defect() {
        // The shape the soundness argument splits on the first *piece* to
        // cover. `{{a}}/usr/bin` opens with a name, and the answer that makes
        // it findable contributes no text at all: `a = ""` gives `/usr/bin`,
        // whose leading `/` is committed text that is not before the first
        // placeholder. The `/q` stand-in still settles it, because a spelling
        // opening with a name opens with the stand-in, but an argument split on
        // where the `/` came from would have missed this entry and refused a
        // load that has a perfectly good answer.
        const LAYER: &str = "[[value]]\nname = \"a\"\nkind = \"string\"\n\
                             [[target]]\npath = \"~/.config/env\"\n\
                             content = \"x\"\nrequires = [\"{{a}}/usr/bin\"]\n";

        let resolved = resolved(LAYER, Some("[values]\na = \"\"\n"))
            .expect("an empty answer completes the skeleton, so it is no load error");
        assert_eq!(ready(&resolved, 0).requires, ["/usr/bin"]);
    }

    #[test]
    fn a_kind_that_narrows_a_requires_skeleton_blocks_the_target_not_the_load() {
        // The boundary the pre-probe refusal deliberately does **not** take.
        // `bx{{sfx}}` is satisfiable by some string — `sfx = "-nightly"` — so it
        // is not the committed skeleton's defect; but with `sfx` declared
        // `path`, every *answer* is absolute, so every answer leaves a relative
        // name holding a `/`, and none is findable. The load still succeeds and
        // the cost is the one target, because a `[[value]]` declaration is not
        // restricted to committed layers: an account may redeclare `sfx` in
        // `local.toml`, and a kind-aware refusal would make that edit fail or
        // repair the whole load.
        const LAYER: &str = "[[value]]\nname = \"sfx\"\nkind = \"path\"\n\
                             [[target]]\npath = \"~/.config/env\"\n\
                             content = \"x\"\nrequires = [\"bx{{sfx}}\"]\n\
                             [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        // Unanswered, and answered with the only shape the kind allows: the
        // load survives both, and every other target is unaffected.
        for local in [None, Some("[values]\nsfx = \"/opt/x\"\n")] {
            let resolved = resolved(LAYER, local)
                .expect("a kind that narrows a skeleton is not the layer's defect");
            blocked(&resolved, 0);
            ready(&resolved, 1);
        }

        // The account's redeclaration is what clears it, and it clears it
        // without the load having failed in the meantime.
        let widened = resolved(
            LAYER,
            Some("[[value]]\nname = \"sfx\"\nkind = \"string\"\n[values]\nsfx = \"-nightly\"\n"),
        )
        .expect("the redeclaration resolves");
        assert_eq!(ready(&widened, 0).requires, ["bx-nightly"]);
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
}
