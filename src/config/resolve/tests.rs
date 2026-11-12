use super::*;
use crate::config::env::{Fragment, Syntax, Var};
use crate::config::merge::merge;
use crate::config::target::{Attach, Format, Gen, Interactive};
use crate::config::{Layer, LayerKind, parse_str};
use crate::shell::placement::{place, vacated_fragments};
use crate::testing::assert_mentions;
use std::path::PathBuf;

mod clashes;
mod placement;

pub(super) fn home() -> PathBuf {
    crate::testing::example_home().to_path_buf()
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
        config: parse_str(text, Path::new(file), &home()).map_err(|e| format!("{file}: {e}"))?,
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
                }) => Some(generated.render(&crate::config::when::tools(&|_| true))),
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

/// A declaration and a target that uses it.
pub(super) const SCRATCH: &str = "[[value]]\n\
                           name = \"scratch_root\"\n\
                           kind = \"path\"\n\
                           required = true\n\
                           is_root = true\n";

#[test]
fn the_secrets_table_is_carried_through_resolution() {
    let resolved = resolved(
        // The public half of a throwaway key generated for this test.
        "[secrets]\nrecipients = [\"ssh-ed25519 \
         AAAAC3NzaC1lZDI1NTE5AAAAIDRgIMdfCcjBrb0DLH6nJeNNHH1XkH50spiqT5vkgbv/ one\"]\n",
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
