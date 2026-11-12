//! Targets that name one file: an answer that makes a layer name a file twice,
//! the declarations a clash runs through and the way out it offers, how later
//! layers settle it, and paths that differ only by case on the volume.

use super::*;

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
        assert_mentions(
            &entry.hint,
            &[
                "`~/.config/{{profile}}/s` at bx.toml:4",
                "`~/.config/default/s` at bx.toml:7",
                "the answer to `profile` at local.toml:3",
            ],
        );
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
        assert_mentions(
            &entry.hint,
            &[
                "`~/{{p}}/s` at bx.toml:12",
                "`~/{{q}}/{{r}}` at bx.toml:15",
                "because of the answer to `p` at local.toml:2, carried in by the default of \
                     `q` at bx.toml:4; change that answer, or answer `q` directly",
            ],
        );
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
fn a_derived_value_one_spelling_carries_twice_is_offered_as_the_way_out() {
    // The end-to-end proof that a hint reaches the blocked entry and that
    // the act it names clears it. Which derived values a hint offers is
    // `answers_hint`'s rule, pinned by its tests in `values.rs`: a value
    // every spelling carries equally is withheld, and the exclusion is by
    // *count*, not by membership. `q` is carried by both spellings, but
    // once by the first and twice by the second, so answering it does
    // part them and the hint has to say so: with
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
    assert_mentions(
        &entry.hint,
        &[
            "`~/.config/s` at bx.toml:4",
            "`~/.config/{{p}}/../s` at bx.toml:10",
            "the answer to `p` at local.toml:2",
        ],
    );
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
    assert_mentions(
        &entry.hint,
        &[
            "modules/10-profile.toml:1",
            "modules/10-profile.toml:4",
            "the answer to `profile` at local.toml:2",
        ],
    );
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

/// Two ready targets, at `bx.toml:2` and `local.toml:1`, whose keys
/// differ only by the case of `App`.
fn targets_differing_by_case() -> Vec<Resolution<Target>> {
    let global = layer(
        "bx.toml",
        LayerKind::Global,
        "\n[[target]]\npath = \"~/.config/App/settings.json\"\ncontent = \"GLOBAL\"\n",
    )
    .unwrap();
    let local = layer(
        "local.toml",
        LayerKind::Local,
        "[[target]]\npath = \"~/.config/app/settings.json\"\ncontent = \"LOCAL\"\n",
    )
    .unwrap();
    global
        .config
        .targets
        .into_iter()
        .chain(local.config.targets)
        .map(Resolution::Ready)
        .collect()
}

#[test]
fn targets_differing_only_by_case_are_refused_where_the_volume_folds_case() {
    let asked = std::cell::RefCell::new(Vec::new());
    let message = refuse_shared_files(&targets_differing_by_case(), &home(), |dir| {
        asked.borrow_mut().push(dir.to_path_buf());
        Some(true)
    })
    .unwrap_err()
    .to_string();

    assert!(message.contains("local.toml:1"), "{message}");
    assert!(message.contains("the target at bx.toml:2"), "{message}");
    assert!(
        message.contains("`~/.config/App/settings.json`"),
        "{message}"
    );
    assert!(
        message.contains("does not tell names apart by case"),
        "{message}"
    );
    assert_eq!(
        *asked.borrow(),
        [home().join(".config")],
        "the volume is asked about the directory the two names part in"
    );
}

#[test]
fn targets_differing_only_by_case_stand_where_the_volume_tells_them_apart() {
    refuse_shared_files(&targets_differing_by_case(), &home(), |_| Some(false))
        .expect("two files on a case-sensitive volume");
}

#[test]
fn targets_differing_only_by_case_are_refused_where_the_volume_cannot_be_judged() {
    let message = refuse_shared_files(&targets_differing_by_case(), &home(), |_| None)
        .unwrap_err()
        .to_string();
    assert!(message.contains("could not determine"), "{message}");
    assert!(message.contains("the target at bx.toml:2"), "{message}");
}

#[test]
fn targets_that_differ_by_more_than_case_never_ask_the_volume() {
    let mut targets = targets_differing_by_case();
    targets.truncate(1);
    targets.extend(resolved_targets(
        "[[target]]\npath = \"~/.config/app/other.json\"\ncontent = \"x\"\n",
    ));
    refuse_shared_files(&targets, &home(), |dir| {
        panic!("asked about {}", dir.display())
    })
    .expect("different files");
}

#[test]
fn the_real_volume_decides_whether_case_differing_targets_are_one_file() {
    let home = crate::testing::guarded_home();
    home.write(".config/App/settings.json", "{}");
    let folds = home.child(".config/app/settings.json").exists();

    let outcome = refuse_shared_files(
        &targets_differing_by_case(),
        home.path(),
        crate::fs::case_insensitive,
    );

    match outcome {
        Ok(()) => assert!(!folds, "two names for one file stood"),
        Err(error @ Error::BadValue { .. }) => {
            assert!(folds, "two files refused as one: {error}");
            let message = error.to_string();
            assert!(
                message.contains("on this volume, which does not tell names apart by case"),
                "the volume was judged, not guessed at: {message}"
            );
        }
        Err(other) => panic!("not the shared-file refusal: {other:?}"),
    }
}

/// The targets of one global layer, each ready.
fn resolved_targets(text: &str) -> Vec<Resolution<Target>> {
    layer("bx.toml", LayerKind::Global, text)
        .unwrap()
        .config
        .targets
        .into_iter()
        .map(Resolution::Ready)
        .collect()
}

#[test]
fn the_directory_two_paths_part_in_is_their_common_prefix() {
    assert_eq!(
        parting_dir(Path::new("/h/.config/App/x"), Path::new("/h/.config/app/x")),
        Path::new("/h/.config")
    );
    assert_eq!(
        parting_dir(Path::new("/h/A"), Path::new("/h/a")),
        Path::new("/h")
    );
}
