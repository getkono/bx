//! Rebuilding a target with every `{{name}}` in it substituted.
//!
//! Every string field substitution applies to is visited here, and each one is
//! put back through the rule its field obeys as written, so an answer cannot
//! make a field the parser would have refused.

use super::repo_file::refuse_rooted_value_in_file;
use super::requirement::check_requirement;
use crate::config::Error;
use crate::config::target::{Attach, Body, Format, KeyPath, Target};
use crate::config::values::ResolvedValues;
use crate::paths::Portable;

/// Why [`substituted`] could not rebuild a target.
pub(super) enum Broken {
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
pub(super) fn for_each_string(target: &Target, visit: &mut impl FnMut(&str)) {
    visit(target.path.as_str());

    match &target.body {
        Body::File(path) | Body::Secret(path) => visit(&path.to_string_lossy()),
        Body::Inline(text) | Body::Symlink(text) => visit(text),
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
/// path, or because a file target's path became the home or a directory above
/// it. That is [`Broken::Field`], carrying the text as written, and
/// [`resolve_target`](super::resolve_target) decides whose it is from the
/// answers that went in.
pub(super) fn substituted(target: &Target, values: &ResolvedValues) -> Result<Target, Broken> {
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
            let confined = crate::config::target::confine_to_repo("file", &sub(&raw)?)
                .map_err(|message| field(&raw, message))?;
            refuse_rooted_value_in_file("file", &raw, values, &sub)?;
            Body::File(confined)
        }
        // The ciphertext is a repo file by the same rule, and an escape through
        // it would decrypt whatever age file it reached into the target.
        Body::Secret(path) => {
            let raw = path.to_string_lossy();
            let confined = crate::config::target::confine_to_repo("secret", &sub(&raw)?)
                .map_err(|message| field(&raw, message))?;
            refuse_rooted_value_in_file("secret", &raw, values, &sub)?;
            Body::Secret(confined)
        }
        Body::Inline(text) => Body::Inline(sub(text)?),
        // Through the parser's own rule, as a `file` is: an answer can empty
        // the text, or put a NUL or a `~name` at its start.
        Body::Symlink(text) => {
            let linked = sub(text)?;
            crate::config::target::check_link_text(&linked)
                .map_err(|message| field(text, message))?;
            Body::Symlink(linked)
        }
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

    // The parser's own refusal again, on the path as substituted: it saw
    // `~/{{leaf}}`, and a `string` answer of `.` makes that the home itself.
    let path = portable(target.path.as_str())?;
    crate::config::target::refuse_file_at_home_or_above(path.as_str(), &path, &body, values.home())
        .map_err(|message| field(target.path.as_str(), message))?;

    Ok(Target {
        path,
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

#[cfg(test)]
mod tests {
    use super::super::tests::{SCRATCH, blocked, ready, resolved};
    use super::*;
    use crate::config::resolution::BlockReason;
    use std::path::PathBuf;

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
    fn a_symlink_text_is_substituted_and_checked_again() {
        const LAYER: &str = "[[value]]\n\
                             name = \"tool\"\n\
                             kind = \"string\"\n\
                             [[target]]\n\
                             path = \"~/.local/bin/tool\"\n\
                             symlink = \"{{tool}}/bin/tool\"\n";

        // An absolute answer is a link to an absolute path: a link's text is
        // not confined to anything, and bx never follows it.
        let ordinary = resolved(LAYER, Some("[values]\ntool = \"/opt/tool\"\n")).unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::Symlink("/opt/tool/bin/tool".to_string())
        );
        let home = resolved(LAYER, Some("[values]\ntool = \"~/src/tool\"\n")).unwrap();
        assert_eq!(
            ready(&home, 0).body,
            Body::Symlink("~/src/tool/bin/tool".to_string()),
            "stored as written; the home is rendered where the link is made"
        );

        // An answer that makes the text one no link can hold blocks the
        // target, naming the answer.
        let other = resolved(LAYER, Some("[values]\ntool = \"~other\"\n"))
            .expect("an answer blocks its target, not the load");
        let entry = blocked(&other, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["tool".to_string()]
            }
        );
        assert!(
            entry.hint.contains("another account's home"),
            "{}",
            entry.hint
        );
    }

    #[test]
    fn a_substituted_secret_is_confined_to_the_config_repo_like_a_file() {
        const LAYER: &str = "[[value]]\n\
                             name = \"account\"\n\
                             kind = \"KIND\"\n\
                             [[target]]\n\
                             path = \"~/.token\"\n\
                             secret = \"secrets/{{account}}/token.age\"\n\
                             mode = \"0600\"\n";
        let string = LAYER.replace("KIND", "string");

        let climbing = resolved(&string, Some("[values]\naccount = \"../../../../etc\"\n"))
            .expect("an account's answer blocks its target, not the load");
        let entry = blocked(&climbing, 0);
        assert!(
            entry
                .hint
                .contains("`secret` may not climb out of the config repo"),
            "{}",
            entry.hint
        );

        let rooted = resolved(&string, Some("[values]\naccount = \"/home/example\"\n"))
            .expect("an account's rooted answer blocks its target, not the load");
        let entry = blocked(&rooted, 0);
        assert!(
            entry.hint.contains("`secret` takes `account`"),
            "{}",
            entry.hint
        );

        let ordinary = resolved(&string, Some("[values]\naccount = \"work\"\n")).unwrap();
        assert_eq!(
            ready(&ordinary, 0).body,
            Body::Secret(PathBuf::from("secrets/work/token.age"))
        );

        let message = resolved(&LAYER.replace("KIND", "path"), None)
            .expect_err("a `path` value in `secret` is the layer's defect");
        assert!(
            message.contains("`secret` references `account`"),
            "{message}"
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
    fn a_target_path_substituted_onto_the_home_or_above_is_refused() {
        // The parser refuses a file target at the home or above it, but it sees
        // `~/{{leaf}}`. A `string` answer is used verbatim, so `leaf = "."`
        // resolved a ready file target at `~` itself. An account's answer costs
        // the account's target; a committed default is a repo defect.
        const HOME: &str = "[[value]]\nname = \"leaf\"\nkind = \"string\"\n\
                            [[target]]\npath = \"~/{{leaf}}\"\ncontent = \"x\"\n\
                            [[target]]\npath = \"~/.zshrc\"\ncontent = \"setopt\"\n";

        let answered = resolved(HOME, Some("[values]\nleaf = \".\"\n"))
            .unwrap_or_else(|e| panic!("an answer failed the whole load: {e}"));
        let entry = blocked(&answered, 0);
        assert_eq!(
            entry.reason,
            BlockReason::InvalidValue {
                names: vec!["leaf".to_string()]
            }
        );
        assert!(
            entry
                .hint
                .contains("the home directory or a directory above it"),
            "{}",
            entry.hint
        );
        assert!(
            entry.hint.contains("the answer to `leaf` at local.toml:2"),
            "{}",
            entry.hint
        );
        assert_eq!(ready(&answered, 1).path.as_str(), "~/.zshrc");

        let message = resolved(
            &HOME.replace(
                "kind = \"string\"\n",
                "kind = \"string\"\ndefault = \".\"\n",
            ),
            None,
        )
        .expect_err("a committed default with no answer in it is a repo defect");
        assert!(
            message.contains("the home directory or a directory above it"),
            "{message}"
        );

        let above = resolved(
            "[[value]]\nname = \"seg\"\nkind = \"string\"\n\
             [[target]]\npath = \"/var/{{seg}}\"\ncontent = \"x\"\n",
            Some("[values]\nseg = \"home\"\n"),
        )
        .unwrap_or_else(|e| panic!("an answer failed the whole load: {e}"));
        let entry = blocked(&above, 0);
        assert!(
            entry
                .hint
                .contains("the home directory or a directory above it"),
            "{}",
            entry.hint
        );

        // A directory target may still land there.
        let dir = resolved(
            "[[value]]\nname = \"leaf\"\nkind = \"string\"\n\
             [[target]]\npath = \"~/{{leaf}}\"\ndir = true\n",
            Some("[values]\nleaf = \".\"\n"),
        )
        .unwrap();
        assert_eq!(ready(&dir, 0).path.as_str(), "~");
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
}
