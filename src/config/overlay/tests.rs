use std::path::{Path, PathBuf};

use super::*;
use crate::config::layers::gate;
use crate::config::merge::merge;
use crate::config::when::{Facts, Machine};
use crate::config::{Layer, LayerKind, parse_str};

fn home() -> PathBuf {
    crate::testing::example_home().to_path_buf()
}

fn layer(file: &str, kind: LayerKind, text: &str) -> Layer {
    Layer {
        file: PathBuf::from(file),
        kind,
        config: parse_str(text, Path::new(file), &home()).unwrap_or_else(|e| panic!("{file}: {e}")),
    }
}

fn global(file: &str, text: &str) -> Layer {
    layer(file, LayerKind::Global, text)
}

fn local(text: &str) -> Layer {
    layer("local.toml", LayerKind::Local, text)
}

/// The parse's error message for `text` as `bx.toml`.
fn refused(text: &str) -> String {
    parse_str(text, Path::new("bx.toml"), &home())
        .expect_err("should have been refused")
        .to_string()
}

/// `layers` gated on a machine named `host`, then merged.
fn merged_on(
    host: &str,
    layers: Vec<Layer>,
) -> Result<crate::config::Config, crate::config::Error> {
    let machine = Machine {
        host: Some(host.to_string()),
        ..Machine::read(None)
    };
    let present = |_: &str| false;
    let facts = Facts {
        machine: &machine,
        present: &present,
    };
    merge(&gate(layers, &facts), &home())
}

const SETTINGS: &str =
    "[[target]]\npath = \"~/.claude/settings.json\"\nfile = \"files/settings.json\"\n";

const HOOK: &str = "[[overlay]]\nname = \"hook\"\npath = \"~/.claude/settings.json\"\n\
                    file = \"files/hook.json\"\n";

#[test]
fn an_overlay_parses_its_name_path_and_fragment() {
    let config = parse_str(
        &format!(
            "{HOOK}[[overlay]]\nname = \"inline\"\npath = \"~/a.toml\"\ncontent = \"x = 1\"\n"
        ),
        Path::new("bx.toml"),
        &home(),
    )
    .expect("parses");
    let parsed: Vec<(&str, &str, &Fragment, bool)> = config
        .overlays
        .iter()
        .map(|o| (o.name.as_str(), o.path.as_str(), &o.fragment, o.enabled))
        .collect();
    assert_eq!(
        parsed,
        vec![
            (
                "hook",
                "~/.claude/settings.json",
                &Fragment::File(PathBuf::from("files/hook.json")),
                true
            ),
            (
                "inline",
                "~/a.toml",
                &Fragment::Inline("x = 1".to_string()),
                true
            ),
        ]
    );
}

#[test]
fn an_overlay_needs_exactly_one_fragment_and_a_structured_path() {
    let both =
        refused("[[overlay]]\nname = \"a\"\npath = \"~/a.json\"\nfile = \"f\"\ncontent = \"{}\"\n");
    assert!(both.contains("exactly one fragment"), "{both}");

    let none = refused("[[overlay]]\nname = \"a\"\npath = \"~/a.json\"\n");
    assert!(none.contains("`file` or `content`"), "{none}");

    let opaque = refused("[[overlay]]\nname = \"a\"\npath = \"~/.bashrc\"\ncontent = \"x\"\n");
    assert!(opaque.contains("`.json` or `.toml`"), "{opaque}");

    let unknown = refused(
        "[[overlay]]\nname = \"a\"\npath = \"~/a.json\"\ncontent = \"{}\"\nmode = \"0600\"\n",
    );
    assert!(unknown.contains("mode"), "{unknown}");

    let placeholder =
        refused("[[overlay]]\nname = \"a\"\npath = \"~/a.json\"\nfile = \"f/{{who}}.json\"\n");
    assert!(placeholder.contains("holds no"), "{placeholder}");

    let climbing = refused("[[overlay]]\nname = \"a\"\npath = \"~/a.json\"\nfile = \"../x\"\n");
    assert!(climbing.contains("climb"), "{climbing}");

    let twice = refused(&format!("{HOOK}{HOOK}"));
    assert!(twice.contains("hook"), "{twice}");
}

#[test]
fn an_overlay_name_is_non_empty_and_on_one_line() {
    // Each refusal on its own: an empty name has no control character, and a
    // name with one is not empty.
    for name in [r#""""#, r#""two\nlines""#, r#""tab\there""#] {
        let note = refused(&format!(
            "[[overlay]]\nname = {name}\npath = \"~/a.json\"\ncontent = \"{{}}\"\n"
        ));
        assert!(note.contains("is not an overlay name"), "{name}: {note}");
    }
}

#[test]
fn a_host_gated_module_adds_its_overlay_on_that_host_only() {
    let layers = || {
        vec![
            global("bx.toml", SETTINGS),
            global(
                "modules/build.toml",
                &format!("when = \"host:build1\"\n{HOOK}"),
            ),
        ]
    };
    let on_build = merged_on("build1", layers()).expect("merges");
    assert_eq!(on_build.overlays.len(), 1);
    assert_eq!(on_build.overlays[0].name, "hook");

    let elsewhere = merged_on("laptop", layers()).expect("merges");
    assert!(elsewhere.overlays.is_empty());
}

#[test]
fn an_overlay_s_own_when_gates_it_alone() {
    let layers = || {
        vec![global(
            "bx.toml",
            &format!("{SETTINGS}{HOOK}when = \"host:build1\"\n"),
        )]
    };
    let on_build = merged_on("build1", layers()).expect("merges");
    assert_eq!(on_build.overlays.len(), 1);
    assert_eq!(on_build.targets.len(), 1);

    let elsewhere = merged_on("laptop", layers()).expect("merges");
    assert!(elsewhere.overlays.is_empty());
    assert_eq!(
        elsewhere.targets.len(),
        1,
        "the target is not gated with it"
    );
}

#[test]
fn an_account_opts_out_of_a_committed_overlay_with_a_toggle() {
    let merged = merged_on(
        "build1",
        vec![
            global("bx.toml", &format!("{SETTINGS}{HOOK}")),
            local("[[overlay]]\nname = \"hook\"\nenabled = false\n"),
        ],
    )
    .expect("merges");
    assert!(merged.overlays.is_empty());
}

#[test]
fn an_overlay_naming_no_declared_target_is_refused_as_a_typo() {
    let message = merged_on(
        "build1",
        vec![global(
            "bx.toml",
            &format!(
                "{SETTINGS}{}",
                HOOK.replace("settings.json", "setings.json")
            ),
        )],
    )
    .expect_err("a typo")
    .to_string();
    assert!(
        message.contains("no layer declares a [[target]]"),
        "{message}"
    );
    assert!(message.contains("bx.toml:4"), "{message}");
}

#[test]
fn an_overlay_whose_target_is_off_on_this_machine_adds_nothing() {
    let gated = merged_on(
        "laptop",
        vec![
            global(
                "modules/build.toml",
                &format!("when = \"host:build1\"\n{SETTINGS}"),
            ),
            global("modules/hook.toml", HOOK),
        ],
    )
    .expect("merges");
    assert!(gated.overlays.is_empty());

    let disabled = merged_on(
        "laptop",
        vec![
            global("bx.toml", &format!("{SETTINGS}{HOOK}")),
            local("[[target]]\npath = \"~/.claude/settings.json\"\nenabled = false\n"),
        ],
    )
    .expect("merges");
    assert!(disabled.overlays.is_empty());
}

#[test]
fn an_overlay_reaches_a_target_whose_path_holds_a_placeholder() {
    let merged = merged_on(
        "laptop",
        vec![
            global(
                "bx.toml",
                "[[value]]\nname = \"acct\"\nkind = \"string\"\n\
                 [[target]]\npath = \"~/.config/{{acct}}/settings.json\"\ncontent = \"{}\"\n",
            ),
            local(
                "[values]\nacct = \"one\"\n\
                 [[overlay]]\nname = \"mine\"\npath = \"~/.config/one/settings.json\"\n\
                 content = \"{}\"\n",
            ),
        ],
    )
    .expect("merges");
    assert_eq!(merged.overlays.len(), 1);
}

#[test]
fn a_target_an_overlay_cannot_be_merged_into_is_refused_naming_why() {
    let tracked = merged_on(
        "laptop",
        vec![global(
            "bx.toml",
            &format!("{}direction = \"track\"\n{HOOK}", SETTINGS),
        )],
    )
    .expect_err("tracked")
    .to_string();
    assert!(tracked.contains("cannot take an overlay"), "{tracked}");
    assert!(tracked.contains("tracked"), "{tracked}");

    let secret = merged_on(
        "laptop",
        vec![global(
            "bx.toml",
            &format!(
                "[[target]]\npath = \"~/.claude/settings.json\"\nsecret = \"s.age\"\n\
                 mode = \"0600\"\n{HOOK}"
            ),
        )],
    )
    .expect_err("a secret")
    .to_string();
    assert!(secret.contains("secret"), "{secret}");
}

#[test]
fn each_ineligible_shape_says_why() {
    let base = || {
        parse_str(SETTINGS, Path::new("bx.toml"), &home())
            .expect("parses")
            .targets
            .remove(0)
    };
    assert_eq!(ineligible(&base()), None);
    let mut region = base();
    region.attach = Attach::Region { comment: '#' };
    assert!(ineligible(&region).is_some_and(|why| why.contains("region")));
    let mut link = base();
    link.body = Body::Symlink("x".to_string());
    assert!(ineligible(&link).is_some_and(|why| why.contains("link")));
    let mut dir = base();
    dir.body = Body::Dir;
    assert!(ineligible(&dir).is_some_and(|why| why.contains("directory")));
    let mut env_d = base();
    env_d.format = Format::EnvD;
    assert!(ineligible(&env_d).is_some_and(|why| why.contains("format")));
}
