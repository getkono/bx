use super::*;
use crate::config::when::tools;
use crate::fs::mode::ModeError;
use toml_edit::Document;

use crate::testing::example_home as home;

/// Parse the first `[[target]]` out of a document, against `home`.
fn parse_in(text: &str, home: &Path) -> Result<Target, Error> {
    let doc = Document::parse(text).expect("valid TOML");
    let table = doc
        .as_table()
        .get("target")
        .expect("a [[target]]")
        .as_array_of_tables()
        .expect("an array of tables")
        .get(0)
        .expect("one element");
    parse_target(table, Path::new("bx.toml"), text, home)
}

/// Parse the first `[[target]]` out of a document.
fn parse(text: &str) -> Result<Target, Error> {
    parse_in(text, home())
}

/// A minimal valid target, plus whatever else the test needs.
fn with(extra: &str) -> String {
    format!("[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/gitconfig\"\n{extra}")
}

fn message(text: &str) -> String {
    parse(text)
        .expect_err("should have been rejected")
        .to_string()
}

/// Every default a target that names only a path and a body takes: an
/// absent mode is `None`, not a guess.
#[test]
fn a_minimal_target_parses() {
    let target = parse(&with("")).unwrap();

    assert_eq!(target.path.as_str(), "~/.gitconfig");
    assert_eq!(
        target.path,
        Portable::parse_in("~/.gitconfig", home()).unwrap(),
        "the natural key is the path"
    );
    assert_eq!(target.body, Body::File(PathBuf::from("files/gitconfig")));
    assert_eq!(target.mode, None);
    assert_eq!(target.attach, Attach::Own);
    assert_eq!(target.direction, Direction::Apply);
    assert_eq!(target.format, Format::Opaque);
    assert!(target.requires.is_empty());
    assert!(target.references.is_empty());
    assert!(target.enabled);
}

/// Each key a minimal target may add lands in its own field and moves no
/// other: the whole target is compared, not the one field.
#[test]
fn each_key_a_target_accepts_sets_its_field_and_no_other() {
    /// What a key changes in the minimal target.
    type Change = fn(&mut Target);
    let minimal = parse(&with("")).unwrap();
    let cases: [(&str, Change); 8] = [
        ("attach = \"own\"\n", |_| {}),
        ("attach = \"region\"\ncomment = \"#\"\n", |t| {
            t.attach = Attach::Region { comment: '#' };
        }),
        ("mode = \"0600\"\n", |t| {
            t.mode = Some(Mode::from_bits(0o600))
        }),
        ("direction = \"track\"\n", |t| {
            t.direction = Direction::Track
        }),
        ("format = \"env.d\"\n", |t| t.format = Format::EnvD),
        ("requires = [\"starship\", \"git\"]\n", |t| {
            t.requires = vec!["starship".to_string(), "git".to_string()];
        }),
        // Removing the entry is A3's merge rule; the model records the flag.
        ("enabled = false\n", |t| t.enabled = false),
        ("references = [\"~/.gitconfig.local\"]\n", |t| {
            t.references = vec![Portable::parse_in("~/.gitconfig.local", home()).unwrap()];
        }),
    ];
    for (extra, change) in cases {
        let mut expected = minimal.clone();
        change(&mut expected);
        assert_eq!(parse(&with(extra)).unwrap(), expected, "{extra}");
    }
}

/// Each body is read as written, or normalised where it is a repo path,
/// with the attachment and mode the body implies.
#[test]
fn each_body_parses_to_what_it_names() {
    let include = "Include ~/.ssh/config.d/*.conf";
    let cases = [
        (
            "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"\"\"\n[user]\n\tname = x\n\"\"\"\n",
            Body::Inline("[user]\n\tname = x\n".to_string()),
            Attach::Own,
            None,
        ),
        // An empty inline body is a zero-byte file, not a missing body.
        (
            "[[target]]\npath = \"~/.hushlogin\"\ncontent = \"\"\n",
            Body::Inline(String::new()),
            Attach::Own,
            None,
        ),
        (
            "[[target]]\npath = \"~/a\"\nfile = \"files/./sub//starship.toml\"\n",
            Body::File(PathBuf::from("files/sub/starship.toml")),
            Attach::Own,
            None,
        ),
        (
            "[[target]]\npath = \"~/.ssh\"\ndir = true\nmode = \"0700\"\n",
            Body::Dir,
            Attach::Own,
            Some(Mode::from_bits(0o700)),
        ),
        // An include target's body is its line.
        (
            "[[target]]\npath = \"~/.ssh/config\"\nattach = \"include\"\n\
                 include = \"Include ~/.ssh/config.d/*.conf\"\n",
            Body::Inline(include.to_string()),
            Attach::Include {
                line: include.to_string(),
            },
            None,
        ),
    ];
    for (text, body, attach, mode) in cases {
        let target = parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(
            (target.body, target.attach, target.mode),
            (body, attach, mode),
            "{text}"
        );
    }
}

/// The variant a parse error was raised as.
fn variant(error: &Error) -> &'static str {
    match error {
        Error::MissingKey { .. } => "MissingKey",
        Error::WrongType { .. } => "WrongType",
        Error::UnknownKey { .. } => "UnknownKey",
        Error::BadValue { .. } => "BadValue",
        _ => "another",
    }
}

/// Each target the parser refuses, by the variant it is raised as and the
/// parts of the message that tell the author what to change.
#[test]
fn each_malformed_target_is_refused_saying_why() {
    let dir = |extra: &str| format!("[[target]]\npath = \"~/.ssh\"\ndir = true\n{extra}");
    let bare = |rest: &str| format!("[[target]]\n{rest}");
    const NO_FORMAT: &str = "no content, so `format` has nothing to describe";
    let bad_values = [
        (with("content = \"x\"\n"), "exactly one body"),
        (
            with("secret = \"s.age\"\nmode = \"0600\"\n"),
            "exactly one body",
        ),
        (with("secret = \"s.age\"\nmode = \"0600\"\n"), "`secret`"),
        (bare("path = \"~/a\"\nfile = \"\"\n"), "must name a file"),
        (bare("path = \"~/a\"\nfile = \"./\"\n"), "must name a file"),
        (
            dir("attach = \"region\"\ncomment = \"#\"\n"),
            "always attached as `own`",
        ),
        (
            dir("attach = \"include\"\ninclude = \"x\"\n"),
            "always attached as `own`",
        ),
        (
            bare("path = \"~/.config/zed\"\ndir = true\nformat = \"jsonc\"\n"),
            NO_FORMAT,
        ),
        (
            bare("path = \"~/.config/env.d\"\ndir = true\nformat = \"env.d\"\n"),
            NO_FORMAT,
        ),
        (bare("path = \"~/.ssh\"\ndir = false\n"), "only ever `true`"),
        (
            bare("path = \"files/gitconfig\"\nfile = \"f\"\n"),
            "must start with `~` or `/`",
        ),
        (
            with("references = [\"relative/path\"]\n"),
            "must start with `~` or `/`",
        ),
        // A layer is parsed against a home so that a file under it has
        // exactly one spelling. Accepting both would let one file acquire
        // two keys that `check_unique` cannot see. `references` is the
        // other place a target carries a portable path, and entry A7
        // reports drift keyed on it.
        (
            bare("path = \"/var/home/example/.gitconfig\"\nfile = \"f\"\n"),
            "~/.gitconfig",
        ),
        (
            bare("path = \"/var/home/example/.gitconfig\"\nfile = \"f\"\n"),
            "bx.toml:2",
        ),
        (
            with("references = [\"/var/home/example/.gitconfig.local\"]\n"),
            "~/.gitconfig.local",
        ),
        (with("mode = 600\n"), "quoted octal string"),
        (with("mode = 600\n"), "mode = \"0600\""),
        (with("attach = \"region\"\n"), "needs a `comment` character"),
        (with("comment = \"#\"\n"), "attach = \"region\""),
        (
            with("attach = \"region\"\ncomment = \"//\"\n"),
            "single character",
        ),
        (with("attach = \"include\"\n"), "needs an `include` line"),
        (with("include = \"Include x\"\n"), "attach = \"include\""),
        (with("attach = \"symlink\"\n"), "\"own\", \"region\""),
        (with("direction = \"watch\"\n"), "\"apply\" or \"track\""),
        (with("owns = [\"a.b\"]\n"), "format = \"jsonc\""),
        (with("format = \"envd\"\n"), "\"env.d\""),
        (
            with("exclude = [\"*.md\"]\n"),
            "only means something beside `tree`",
        ),
        // `parse_target` cannot expand a tree; only the layer loader can.
        (tree(""), "loaded from"),
        (
            bare("path = \"~\"\nsymlink = \"/elsewhere\"\n"),
            "only a `dir = true` target",
        ),
        (
            bare("path = \"~/.zshrc\"\ngenerated = \"shell-init\"\n"),
            "no generator named",
        ),
        (
            bare("path = \"~/.zshrc\"\ngenerated = \"shell-init\"\n"),
            "bx.toml:3",
        ),
    ];
    let wrong_types = [
        (
            with("enabled = \"yes\"\n"),
            "`enabled` must be a boolean, found string",
        ),
        (
            with("requires = \"starship\"\n"),
            "an array of strings, found string",
        ),
        (
            with("requires = [1]\n"),
            "an array of strings, found integer",
        ),
        (
            bare("path = 1\nfile = \"f\"\n"),
            "`path` must be a string, found integer",
        ),
    ];
    // `tree` is offered among the body keys.
    let missing = [
        (
            bare("path = \"~/.gitconfig\"\n"),
            "missing the required key",
        ),
        (bare("path = \"~/.gitconfig\"\n"), "`dir` or `tree`"),
    ];
    let unknown = [
        (with("hardlink = true\n"), "unknown key `hardlink`"),
        (with("hardlink = true\n"), "[[target]]"),
        (with("hardlink = true\n"), "bx.toml:4"),
    ];
    for (expected, cases) in [
        ("BadValue", &bad_values[..]),
        ("WrongType", &wrong_types),
        ("MissingKey", &missing),
        ("UnknownKey", &unknown),
    ] {
        for (text, part) in cases {
            let error = parse(text).expect_err(text);
            assert_eq!(variant(&error), expected, "{text}: {error}");
            assert!(error.to_string().contains(part), "{part}: {error}");
        }
    }
    assert!(parse_generated("shell-init").is_none());
}

#[test]
fn every_target_carries_its_origin() {
    let text = "# a leading comment\n\n[[target]]\npath = \"~/.gitconfig\"\nfile = \"f\"\n";
    let target = parse(text).unwrap();

    assert_eq!(target.origin.line, 3, "the [[target]] header's own line");
    assert_eq!(target.origin.file, Path::new("bx.toml"));
}

#[test]
fn a_body_file_must_be_relative_to_the_config_repo() {
    // `repo.join` on an absolute path discards the base, so an absolute
    // `file` would read anywhere on the machine.
    for escaping in ["/etc/shadow", "~/.ssh/id_ed25519", "~other/secrets"] {
        let text = format!("[[target]]\npath = \"~/a\"\nfile = \"{escaping}\"\n");
        assert!(
            message(&text).contains("relative to the repo root"),
            "{escaping} should be rejected"
        );
    }
}

#[test]
fn a_body_file_may_not_climb_out_of_the_config_repo() {
    for escaping in ["../../../etc/shadow", "..", "files/../../outside"] {
        let text = format!("[[target]]\npath = \"~/a\"\nfile = \"{escaping}\"\n");
        assert!(
            message(&text).contains("climb out of the config repo"),
            "{escaping} should be rejected"
        );
    }
}

/// A secret target, plus whatever else the test needs.
fn secret(extra: &str) -> String {
    format!("[[target]]\npath = \"~/.npmrc\"\nsecret = \"secrets/./npmrc.age\"\n{extra}")
}

#[test]
fn a_secret_target_names_its_ciphertext_repo_relative() {
    let target = parse(&secret("mode = \"0600\"\n")).expect("parses");
    assert_eq!(
        target.body,
        Body::Secret(PathBuf::from("secrets/npmrc.age"))
    );
    assert_eq!(target.mode, Some(Mode::PRIVATE_FILE));

    let target = parse(&secret("mode = \"0400\"\n")).expect("read-only is private");
    assert_eq!(target.mode, Some(Mode::from_bits(0o400)));

    for escaping in ["/etc/age/x.age", "~/x.age", "../x.age"] {
        let text =
            format!("[[target]]\npath = \"~/a\"\nsecret = \"{escaping}\"\nmode = \"0600\"\n");
        let message = message(&text);
        assert!(message.contains("`secret`"), "{escaping}: {message}");
    }
}

#[test]
fn a_secret_target_without_a_mode_is_a_load_error() {
    let message = message(&secret(""));
    assert!(
        message.starts_with("bx.toml:3:"),
        "at the secret key: {message}"
    );
    assert!(message.contains("explicit private `mode`"), "{message}");
}

#[test]
fn a_secret_target_with_a_shared_mode_is_a_load_error() {
    for shared in [
        "0640", "0604", "0644", "0660", "0610", "0601", "0200", "0000",
    ] {
        let message = message(&secret(&format!("mode = \"{shared}\"\n")));
        assert!(
            message.starts_with("bx.toml:4:"),
            "at the mode key: {message}"
        );
        assert!(
            message.contains(&format!("got \"{shared}\"")),
            "{shared}: {message}"
        );
    }
}

#[test]
fn a_secret_target_owns_its_whole_file() {
    let region = message(&secret(
        "mode = \"0600\"\nattach = \"region\"\ncomment = \"#\"\n",
    ));
    assert!(region.contains("always attached as `own`"), "{region}");

    let format = message(&secret("mode = \"0600\"\nformat = \"env.d\"\n"));
    assert!(
        format.contains("`format` has nothing to describe"),
        "{format}"
    );

    let include = message(
        "[[target]]\npath = \"~/a\"\nsecret = \"s.age\"\nmode = \"0600\"\n\
             attach = \"include\"\ninclude = \"x\"\n",
    );
    assert!(
        include.contains("`secret` would never be read"),
        "{include}"
    );
}

#[test]
fn a_secret_target_is_never_tracked() {
    let track = message(&secret("mode = \"0600\"\ndirection = \"track\"\n"));
    assert!(track.contains("always applied"), "{track}");
    assert!(parse(&secret("mode = \"0600\"\ndirection = \"apply\"\n")).is_ok());
}

#[test]
fn the_default_modes_document_what_none_means() {
    assert_eq!(Mode::DEFAULT_FILE.to_string(), "0644");
    assert_eq!(Mode::DEFAULT_DIR.to_string(), "0755");
    assert_eq!(Mode::DEFAULT_DIR.bits(), 0o755);
}

/// A bare root is a directory, and only a directory target may name it.
///
/// `path = "~"` and `path = "/"` with `content` parsed as whole-file
/// targets: an `attach = "own"` claim on the home directory, or on `/`, as
/// if it were a file. Every spelling that normalises to one of the two is the
/// same claim, and every kind of file body is the same mistake. `/` is the
/// outermost of the home's ancestors, which
/// `a_directory_above_the_home_is_refused_as_a_file_target` covers.
#[test]
fn a_bare_root_is_refused_as_a_file_target() {
    for path in ["~", "~/", "~/.", "/", "//", "/.."] {
        for body in [
            "content = \"x\"\n",
            "file = \"files/x\"\n",
            "attach = \"region\"\ncomment = \"#\"\ncontent = \"x\"\n",
            "attach = \"include\"\ninclude = \"x\"\n",
        ] {
            let text = format!("[[target]]\npath = \"{path}\"\n{body}");
            let message = message(&text);
            assert!(
                message.contains("is the home directory or a directory above it"),
                "{path:?} with {body:?}: {message}"
            );
            assert!(message.contains("bx.toml:2"), "{path:?}: {message}");
        }
    }

    // The home's own mode is a real thing to manage, so a directory target
    // may still name it.
    let target = parse("[[target]]\npath = \"~\"\ndir = true\nmode = \"0700\"\n").unwrap();
    assert_eq!(target.body, Body::Dir);
    assert_eq!(target.path.as_str(), "~");
}

/// The parser never reaches the refusal with a home that is not absolute.
///
/// A **call-site** property, which is the only place it can live: `home`
/// arrives at `refuse_file_at_home_or_above` as a plain `&Path` and the type
/// does not forbid a relative one. `parse_target` holds it by handing the
/// same `home` to `Portable::parse_in` first, so a non-absolute home leaves
/// through that error and the refusal never runs. This drives `parse_target`
/// end to end rather than asserting `Portable::parse_in`'s own contract,
/// which `paths.rs` already pins.
///
/// It is what lets the comparison in `refuse_file_at_home_or_above` stand
/// alone. The function once also asked `!path.under_home()`, which could not
/// decide anything: a `~/…` path is a component prefix of the home only if
/// the home is itself `~`-rooted. Should a home like that start reaching the
/// refusal, the `debug_assert!` there trips this test and the operand is
/// owed again.
#[test]
fn the_parser_never_reaches_the_refusal_with_a_non_absolute_home() {
    for home in ["~/nested", "~", "relative/home", "", "."] {
        let message = parse_in(&with(""), Path::new(home))
            .expect_err("a non-absolute home is refused before the refusal")
            .to_string();
        assert!(
            message.contains("HOME is not an absolute path"),
            "home {home:?} reached past the constructor: {message}"
        );
    }

    // The refusal is reached, and passes, for the absolute home the rest of
    // this module parses against -- so the loop above is a statement about
    // the home, not about `with("")` being unparseable.
    let target = parse(&with("")).expect("a path under the home parses");
    assert_eq!(target.path.as_str(), "~/.gitconfig");
}

/// The precondition is checked where it is relied on, not merely argued.
///
/// `the_parser_never_reaches_the_refusal_with_a_non_absolute_home` shows one
/// call site holds it today. This shows the guard that will catch the next
/// caller that does not: `super::resolve` reaches the same function, and no
/// test in this module can drive that call site. Without this, the
/// `debug_assert!` could be deleted and every other test still pass.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "non-absolute home")]
fn a_non_absolute_home_at_the_refusal_trips_its_precondition() {
    let path = Portable::parse_in("~/x", home()).expect("a path under the home");
    let _ = refuse_file_at_home_or_above(
        "~/x",
        &path,
        &Body::Inline(String::new()),
        Path::new("~/nested"),
    );
}

/// The home's ancestors are directories too, and so is the home by any spelling.
///
/// Only `~` and `/` were refused: with the home at `/var/home/example`,
/// `path = "/var/home/example/.."` with `content` parsed as a file target at
/// `/var/home`, the same `own` claim on a directory as `~`. Which paths are
/// the home's ancestors is known from the home string, without the disk.
#[test]
fn a_directory_above_the_home_is_refused_as_a_file_target() {
    for path in [
        "/var",
        "/var/home",
        "/var/home/",
        "/var/./home",
        "/var/home/example/..",
        "/var/home/example/../..",
    ] {
        for body in [
            "content = \"x\"\n",
            "file = \"files/x\"\n",
            "attach = \"region\"\ncomment = \"#\"\ncontent = \"x\"\n",
            "attach = \"include\"\ninclude = \"x\"\n",
        ] {
            let text = format!("[[target]]\npath = \"{path}\"\n{body}");
            let message = message(&text);
            assert!(
                message.contains("or a directory above it"),
                "{path:?} with {body:?}: {message}"
            );
            assert!(message.contains("bx.toml:2"), "{path:?}: {message}");
        }
    }

    let target = parse("[[target]]\npath = \"/var/home\"\ndir = true\n").unwrap();
    assert_eq!(target.body, Body::Dir);
    assert_eq!(target.path.as_str(), "/var/home");

    // Component-wise, not by string prefix: a sibling sharing the home's
    // leading bytes, or the home's parent's other children, is not above it.
    for path in [
        "/var/home/examp",
        "/var/homes",
        "/var/home/other/.x",
        "/etc/hosts",
    ] {
        let target = parse(&format!("[[target]]\npath = \"{path}\"\ncontent = \"x\"\n"))
            .unwrap_or_else(|e| panic!("{path:?}: {e}"));
        assert_eq!(target.path.as_str(), path);
    }
}

#[test]
fn an_absolute_target_path_outside_home_is_kept() {
    let target = parse("[[target]]\npath = \"/etc/hosts\"\nfile = \"f\"\n").unwrap();

    assert_eq!(target.path.as_str(), "/etc/hosts");
    assert!(!target.path.under_home());
}

#[test]
fn a_mode_is_an_octal_string() {
    let target = parse(&with("mode = \"0600\"\n")).unwrap();

    assert_eq!(target.mode.unwrap().bits(), 0o600);
    assert_eq!(target.mode.unwrap().to_string(), "0600");
    assert_eq!(Mode::parse_octal("755").unwrap().bits(), 0o755);
    assert_eq!(Mode::parse_octal("4755").unwrap().bits(), 0o4755);
}

#[test]
fn a_non_octal_mode_is_rejected() {
    assert!(message(&with("mode = \"0688\"\n")).contains("octal digits"));
    assert!(message(&with("mode = \"rw-\"\n")).contains("octal digits"));
    assert_eq!(
        Mode::parse_octal("0688"),
        Err(ModeError::Invalid("0688".to_string()))
    );
    assert_eq!(
        Mode::parse_octal(""),
        Err(ModeError::Invalid(String::new())),
        "an empty mode is not a mode"
    );
    assert_eq!(
        Mode::parse_octal("+644"),
        Err(ModeError::Invalid("+644".to_string())),
        "a sign is not an octal digit"
    );
}

#[test]
fn a_mode_wider_than_four_digits_is_rejected() {
    assert_eq!(
        Mode::parse_octal("00644"),
        Err(ModeError::Invalid("00644".to_string()))
    );
    assert!(message(&with("mode = \"00644\"\n")).contains("octal digits"));
}

/// An include target's body is its line; a second body is unreachable.
///
/// `parse_body` synthesised `Body::Inline(include_line)` only when *no* body
/// key was declared, so with one alongside the body key was taken and
/// nothing compared it against the include line -- the target parsed as an
/// `Include` carrying a line *and* an `Inline` carrying something else
/// entirely. An author editing an include target into an own-file target and
/// forgetting to change `attach` got forty lines A5 must either drop
/// silently or insert into a file bx does not own.
#[test]
fn an_include_target_may_not_also_declare_a_body() {
    for body in [
        "content = \"something else entirely\"",
        "file = \"files/config\"",
        "generated = \"shell-init\"",
    ] {
        let text = format!(
            "[[target]]\npath = \"~/.ssh/config\"\nattach = \"include\"\n\
                 include = \"Include ~/.ssh/config.d/*.conf\"\n{body}\n"
        );
        let message = message(&text);
        assert!(
            message.contains("would never be read"),
            "`{body}` beside an include line: {message}"
        );
    }
}

/// An `include` line is type-checked and now value-checked.
///
/// Both values here parsed. An empty line makes A5's idempotence check
/// match every blank line in the file, or append one on every run --
/// Invariant 3 either way. A value bearing a terminator is not one line, so
/// nothing line-wise finds it again; a multi-line insertion is
/// `attach = "region"`, which carries delimiters for that purpose.
#[test]
fn an_include_line_that_is_not_one_line_is_rejected() {
    // `" "` and `"\t"` passed an `is_empty` check and are the same defect as
    // `""`: a blank line, which every blank line in the file matches.
    for raw in [
        "",
        " ",
        "\\t",
        " \\t  ",
        "[include]\\n\\tpath = ~/.gitconfig.bx",
        "Include a\\r\\nInclude b",
    ] {
        let text = format!(
            "[[target]]\npath = \"~/.gitconfig\"\nattach = \"include\"\ninclude = \"{raw}\"\n"
        );
        let message = message(&text);
        assert!(
            message.contains("not be empty or span lines"),
            "include = {raw:?}: {message}"
        );
    }
}

/// A `comment` character is type-checked and now value-checked.
///
/// `comment = "\n"` is a single character and parsed. It produces region
/// delimiters that cannot be found again, so the region stops delimiting
/// anything: a fresh region on every run, which is Invariant 3, or a write
/// outside the one bx meant, which is Invariant 1.
#[test]
fn a_comment_character_that_cannot_start_a_delimiter_is_rejected() {
    for raw in ["\\n", "\\t", " ", "\\u0000"] {
        let text = format!(
            "[[target]]\npath = \"~/.ssh/config\"\nattach = \"region\"\ncomment = \"{raw}\"\n"
        );
        let message = message(&text);
        assert!(
            message.contains("whitespace or a control character"),
            "comment = {raw:?}: {message}"
        );
    }
    // Invisible or non-ASCII characters passed the whitespace-and-control
    // check: U+200B ZERO WIDTH SPACE and U+00AD SOFT HYPHEN are neither, and
    // a delimiter nobody can see in an editor is one a human will delete.
    // The body is present so the comment rule is the only thing to refuse.
    for raw in ["\\u200b", "\\u00ad", "é", "\\u007f"] {
        let text = format!(
            "[[target]]\npath = \"~/.ssh/config\"\nattach = \"region\"\n\
                 comment = \"{raw}\"\ncontent = \"x\"\n"
        );
        let message = message(&text);
        assert!(
            message.contains("a visible ASCII character"),
            "comment = {raw:?}: {message}"
        );
    }
    // The characters real config syntaxes actually use still parse.
    for raw in ["#", ";", "%", "\\\"", "/"] {
        let text = format!(
            "[[target]]\npath = \"~/.ssh/config\"\nattach = \"region\"\n\
                 comment = \"{raw}\"\ncontent = \"x\"\n"
        );
        parse(&text).unwrap_or_else(|e| panic!("comment = {raw:?}: {e}"));
    }
}

#[test]
fn jsonc_owns_dotted_key_paths() {
    let text =
        with("format = \"jsonc\"\nowns = [\"agent.default_model.provider\", \"vim_mode\"]\n");
    let Format::Jsonc { owns } = parse(&text).unwrap().format else {
        panic!("expected a jsonc format");
    };

    assert_eq!(owns.len(), 2);
    assert_eq!(
        owns[0].segments(),
        ["agent", "default_model", "provider"].map(String::from)
    );
    assert_eq!(owns[0].to_string(), "agent.default_model.provider");
    assert_eq!(owns[1].segments(), ["vim_mode".to_string()]);
}

#[test]
fn an_empty_key_path_segment_is_rejected() {
    let text = with("format = \"jsonc\"\nowns = [\"a..b\"]\n");
    assert!(message(&text).contains("empty segment"));
    assert_eq!(
        KeyPath::parse(""),
        Err(KeyPathError::EmptySegment(String::new()))
    );
    assert_eq!(
        KeyPath::parse(".a"),
        Err(KeyPathError::EmptySegment(".a".to_string()))
    );
}

/// A structured format describes a file bx owns whole, so it needs `own`.
///
/// All four parsed. `Format` says how much of the file a target claims:
/// `jsonc` claims the listed keys of a whole JSON document, and `env.d` claims
/// a whole fragment. A region is a delimited span inside someone else's file,
/// and an include is one line in it. Neither is a JSON document or a
/// fragment, so each combination claims two contradictory things about one
/// file, and entry A5 would have to pick one silently.
#[test]
fn a_structured_format_needs_attach_own() {
    let region = "attach = \"region\"\ncomment = \"#\"\ncontent = \"x\"\n";
    let include = "attach = \"include\"\ninclude = \"Include x\"\n";
    let jsonc = "format = \"jsonc\"\nowns = [\"a.b\"]\n";
    let env_d = "format = \"env.d\"\n";

    for (attach, format) in [
        (region, jsonc),
        (region, env_d),
        (include, jsonc),
        (include, env_d),
    ] {
        let text = format!("[[target]]\npath = \"~/.config/x\"\n{attach}{format}");
        let message = message(&text);
        assert!(
            message.contains("needs attach = \"own\""),
            "{attach}{format}: {message}"
        );
        assert!(message.contains("bx.toml:"), "{attach}{format}: {message}");
    }

    // Opaque is the one format every attachment can carry.
    for attach in [region, include] {
        let text = format!("[[target]]\npath = \"~/.config/x\"\n{attach}format = \"opaque\"\n");
        parse(&text).unwrap_or_else(|e| panic!("{attach}: {e}"));
    }
}

/// `format = "jsonc"` with no owned key claims nothing.
///
/// It parsed as `Jsonc { owns: [] }`: a target that says bx manages part of
/// a file and names no part, so every run is a silent no-op.
#[test]
fn jsonc_without_an_owned_key_is_rejected() {
    for owns in ["", "owns = []\n"] {
        let message = message(&with(&format!("format = \"jsonc\"\n{owns}")));
        assert!(
            message.contains("at least one key in `owns`"),
            "{owns:?}: {message}"
        );
    }
}

/// `dir` counts as a body key when two are declared.
#[test]
fn a_directory_target_that_also_declares_a_body_has_two_bodies() {
    for body in ["file = \"f\"", "content = \"x\""] {
        let text = format!("[[target]]\npath = \"~/.ssh\"\ndir = true\n{body}\n");
        let message = message(&text);
        assert!(message.contains("exactly one body"), "{body}: {message}");
        assert!(message.contains("`dir`"), "{body}: {message}");
    }
}

/// A tree entry, plus whatever else the test needs.
fn tree(extra: &str) -> String {
    format!("[[target]]\npath = \"~/.config/nvim\"\ntree = \"files/nvim\"\n{extra}")
}

/// Parse the first `[[target]]` out of a document as an entry.
fn entry(text: &str) -> Result<Entry, Error> {
    let doc = Document::parse(text).expect("valid TOML");
    let table = doc["target"]
        .as_array_of_tables()
        .and_then(|tables| tables.get(0))
        .expect("one [[target]]");
    parse_entry(table, Path::new("bx.toml"), text, home())
}

fn tree_message(text: &str) -> String {
    entry(text)
        .expect_err("should have been rejected")
        .to_string()
}

#[test]
fn a_tree_parses_with_its_companion_keys() {
    let text = tree(
        "exclude = [\"*.md\", \"docs/**\"]\nmode = \"0600\"\ndirection = \"track\"\n\
             requires = [\"nvim\"]\nenabled = false\n",
    );
    let Entry::Tree(parsed) = entry(&text).expect("parses") else {
        panic!("a tree");
    };
    assert_eq!(parsed.path.as_str(), "~/.config/nvim");
    assert_eq!(parsed.root, PathBuf::from("files/nvim"));
    assert_eq!(
        parsed
            .exclude
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["*.md", "docs/**"]
    );
    assert_eq!(parsed.mode, Mode::parse_octal("0600").ok());
    assert_eq!(parsed.direction, Direction::Track);
    assert_eq!(parsed.requires, ["nvim"]);
    assert!(!parsed.enabled);
    assert_eq!(parsed.origin.line, 1);

    let Entry::Tree(bare) = entry(&tree("")).expect("parses") else {
        panic!("a tree");
    };
    assert_eq!(
        (bare.mode, bare.direction, bare.enabled),
        (None, Direction::Apply, true)
    );
    assert!(bare.exclude.is_empty());
    assert!(matches!(entry(&with("")), Ok(Entry::Target(_))));
}

#[test]
fn a_tree_root_is_normalised_and_confined_to_the_repo() {
    let Entry::Tree(parsed) = entry(&tree("").replace("files/nvim", "files/./nvim/")).unwrap()
    else {
        panic!("a tree");
    };
    assert_eq!(parsed.root, PathBuf::from("files/nvim"));

    for root in ["../out", "/etc", "~/x", ".", "files/{{acct}}"] {
        let message = tree_message(&tree("").replace("files/nvim", root));
        assert!(message.contains("`tree`"), "{root}: {message}");
    }
}

#[test]
fn a_tree_is_one_body_among_the_others() {
    for body in [
        "file = \"f\"",
        "content = \"x\"",
        "symlink = \"x\"",
        "dir = true",
    ] {
        let message = tree_message(&tree(&format!("{body}\n")));
        assert!(message.contains("exactly one body"), "{body}: {message}");
        assert!(message.contains("`tree`"), "{body}: {message}");
    }
    let message = tree_message(&tree("attach = \"include\"\ninclude = \"x\"\n"));
    assert!(message.contains("`tree` would never be read"), "{message}");
}

#[test]
fn a_tree_refuses_the_keys_that_describe_one_file() {
    for (extra, key) in [
        ("attach = \"region\"\ncomment = \"#\"\n", "attach"),
        ("format = \"env.d\"\n", "format"),
        ("format = \"jsonc\"\nowns = [\"a\"]\n", "format"),
        ("references = [\"~/.x\"]\n", "references"),
        ("exclude = [\"[a]\"]\n", "exclude"),
        ("exclude = \"*.md\"\n", "exclude"),
    ] {
        let message = tree_message(&tree(extra));
        assert!(message.contains(key), "{extra}: {message}");
    }
}

/// A symlink target, plus whatever else the test needs.
fn symlink(text: &str, extra: &str) -> String {
    format!("[[target]]\npath = \"~/.local/bin/tool\"\nsymlink = {text:?}\n{extra}")
}

#[test]
fn a_symlink_target_keeps_its_text_as_written() {
    for text in [
        "../share/tool/bin/tool",
        "/opt/tool/bin/tool",
        "~/src/tool",
        "~",
    ] {
        assert_eq!(
            parse(&symlink(text, "")).unwrap().body,
            Body::Symlink(text.to_string()),
            "{text}"
        );
    }
}

#[test]
fn a_symlink_is_one_body_among_the_others() {
    for body in [
        "file = \"f\"",
        "content = \"x\"",
        "secret = \"s.age\"",
        "dir = true",
    ] {
        let message = message(&symlink("x", &format!("{body}\n")));
        assert!(message.contains("exactly one body"), "{body}: {message}");
        assert!(message.contains("`symlink`"), "{body}: {message}");
    }
    let generated = message(&symlink("x", "generated = \"shell-init\"\n"));
    assert!(generated.contains("exactly one body"), "{generated}");
}

#[test]
fn a_symlink_target_refuses_every_key_that_describes_content() {
    // Each is named where it was written: the key's own line, or for an
    // include target the `symlink` it would never read.
    for (extra, key, line) in [
        ("mode = \"0644\"\n", "`mode`", "bx.toml:4"),
        ("format = \"env.d\"\n", "`format`", "bx.toml:4"),
        (
            "attach = \"region\"\ncomment = \"#\"\n",
            "`attach`",
            "bx.toml:4",
        ),
        (
            "attach = \"include\"\ninclude = \"x\"\n",
            "`symlink`",
            "bx.toml:3",
        ),
    ] {
        let message = message(&symlink("x", extra));
        assert!(message.contains(key), "{extra}: {message}");
        assert!(message.contains(line), "{extra}: {message}");
    }
    // Their defaults, and the keys that say nothing about content, are
    // not refused.
    let target = parse(&symlink(
        "x",
        "format = \"opaque\"\nattach = \"own\"\nrequires = [\"tool\"]\n",
    ))
    .unwrap();
    assert_eq!(target.body, Body::Symlink("x".to_string()));
}

#[test]
fn a_symlink_text_that_no_link_can_hold_is_refused() {
    // Spelled as TOML, since Rust's `{:?}` escapes a NUL in a way TOML
    // does not read.
    for (text, why) in [
        ("\"\"", "may not be empty"),
        ("\"a\\u0000b\"", "NUL"),
        ("\"~other/bin\"", "another account's home"),
    ] {
        let toml = format!("[[target]]\npath = \"~/.local/bin/tool\"\nsymlink = {text}\n");
        let message = message(&toml);
        assert!(message.contains(why), "{text}: {message}");
        assert!(message.contains("`symlink`"), "{text}: {message}");
    }
    assert!(message(&symlink("x", "").replace("\"x\"", "true")).contains("string"));
}

#[test]
fn link_text_renders_only_a_leading_home() {
    let home = home();
    for (text, rendered) in [
        ("~", "/var/home/example"),
        ("~/src/tool", "/var/home/example/src/tool"),
        ("../a/~/b", "../a/~/b"),
        ("a//b/./c", "a//b/./c"),
        ("/opt/x/", "/opt/x/"),
    ] {
        assert_eq!(link_text(text, home), PathBuf::from(rendered), "{text}");
    }
}

mod interactive {
    //! The interactive shell file, rendered through the phase assembly.

    use super::super::super::env::{Fragment, Syntax, Var};
    use super::*;
    use crate::config::resolution::BlockedEntry;
    use crate::shell::activation;
    use crate::shell::testing::{installed, run};

    /// The fragment the interactive place holds, with `vars`.
    fn fragment(vars: Vec<Var>) -> Fragment {
        Fragment {
            syntax: Syntax::Zsh,
            vars,
            path: Vec::new(),
            inherited: Vec::new(),
        }
    }

    fn plugin(name: &str, source: &str, terminal: bool, line: usize) -> PluginDecl {
        PluginDecl {
            name: name.to_string(),
            source: source.to_string(),
            terminal,
            enabled: true,
            origin: super::super::super::Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line,
            },
        }
    }

    fn alias(name: &str, command: &str, when: Option<&str>) -> AliasDecl {
        AliasDecl {
            name: name.to_string(),
            command: command.to_string(),
            when: when.map(|w| crate::config::when::When::parse(w).expect("a condition")),
            enabled: true,
            origin: super::super::super::Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line: 1,
            },
        }
    }

    fn render(file: &Interactive) -> String {
        file.render(&tools(&|_| true))
    }

    /// The non-blank lines of `rendered` from `heading` up to the next
    /// heading or the end.
    fn phase<'a>(rendered: &'a str, heading: &str) -> Vec<&'a str> {
        rendered
            .lines()
            .skip_while(|line| *line != heading)
            .skip(1)
            .take_while(|line| !line.starts_with("# bx phase: "))
            .filter(|line| !line.is_empty())
            .collect()
    }

    #[test]
    fn env_then_plugins_then_the_terminal_slot_whatever_the_declaration_order() {
        let mut off = plugin("off", "~/off.zsh", false, 4);
        off.enabled = false;
        let file = Interactive::new(fragment(vec![Var::always("EDITOR", "nvim")]))
            .with_plugins(&[
                plugin("highlight", "~/h.zsh", true, 1),
                plugin("b", "~/b.zsh", false, 2),
                off,
                plugin("a", "/usr/share/a.zsh", false, 3),
            ])
            .expect("one terminal claimant");
        assert_eq!(file.plugins().len(), 3, "the disabled one is dropped");
        assert_eq!(file.env().vars.len(), 1);
        let rendered = render(&file);
        assert_eq!(
            rendered,
            "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: env\n\
                 # Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                 export EDITOR=nvim\n\
                 \n# bx phase: plugins\n\
                 [[ -r ~/b.zsh ]] && source ~/b.zsh\n\
                 [[ -r /usr/share/a.zsh ]] && source /usr/share/a.zsh\n\
                 \n# bx phase: terminal\n\
                 [[ -r ~/h.zsh ]] && source ~/h.zsh\n\
                 \n# bx: done, whichever plugins were found\ntrue\n"
        );
        assert_eq!(render(&file), rendered, "byte-identical");
    }

    #[test]
    fn an_empty_part_emits_no_phase_and_no_plugin_emits_no_closing_line() {
        let bare = "# Generated by bx. Edit the config repo, not this file.\n";
        assert_eq!(render(&Interactive::new(fragment(Vec::new()))), bare);
        let env_only = render(&Interactive::new(fragment(vec![Var::always("A", "1")])));
        assert!(env_only.ends_with("export A=1\n"), "{env_only}");
        assert!(!env_only.contains("true"), "{env_only}");
        let plugins_only = render(
            &Interactive::new(fragment(Vec::new()))
                .with_plugins(&[plugin("p", "~/p.zsh", false, 1)])
                .expect("no claimant"),
        );
        assert!(!plugins_only.contains("# bx phase: env"), "{plugins_only}");
        assert!(!plugins_only.contains("[[env]]"), "{plugins_only}");
        assert!(plugins_only.starts_with(bare), "{plugins_only}");
        // Aliases alone: no `env` phase, and no closing line, since an
        // alias line returns 0.
        let aliases_only = render(
            &Interactive::new(fragment(Vec::new())).with_aliases(&[alias("ll", "ls", None)]),
        );
        assert_eq!(
            aliases_only,
            format!("{bare}\n# bx phase: aliases\nalias ll='ls'\n")
        );
        // Every alias gated on a missing tool: no `aliases` phase at all.
        let gated_off = Interactive::new(fragment(Vec::new()))
            .with_aliases(&[alias("cat", "bat", Some("has:bat"))])
            .render(&tools(&|_| false));
        assert_eq!(gated_off, bare);
    }

    #[test]
    fn aliases_land_between_plugins_and_the_terminal_slot_decided_by_present() {
        let mut off = alias("off", "nothing", None);
        off.enabled = false;
        let file = Interactive::new(fragment(vec![Var::always("EDITOR", "nvim")]))
            .with_plugins(&[
                plugin("highlight", "~/h.zsh", true, 1),
                plugin("p", "~/p.zsh", false, 2),
            ])
            .expect("one claimant")
            .with_aliases(&[
                alias("zz", "declared first", None),
                off,
                alias("cat", "bat --paging=never", Some("has:bat")),
                alias("ls", "eza", Some("has:eza")),
            ]);
        assert_eq!(file.aliases().len(), 3, "the disabled one is dropped");
        let with_bat = file.render(&tools(&|tool| tool == "bat"));
        assert_eq!(
            with_bat,
            "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: env\n\
                 # Generated by bx from [[env]]. Edit the config repo, not this file.\n\
                 export EDITOR=nvim\n\
                 \n# bx phase: plugins\n\
                 [[ -r ~/p.zsh ]] && source ~/p.zsh\n\
                 \n# bx phase: aliases\n\
                 alias zz='declared first'\n\
                 alias cat='bat --paging=never'\n\
                 \n# bx phase: terminal\n\
                 [[ -r ~/h.zsh ]] && source ~/h.zsh\n\
                 \n# bx: done, whichever plugins were found\ntrue\n"
        );
        assert_eq!(
            file.render(&tools(&|tool| tool == "bat")),
            with_bat,
            "byte-identical"
        );
        let with_eza = file.render(&tools(&|tool| tool == "eza"));
        assert!(with_eza.contains("alias ls='eza'\n"), "{with_eza}");
        assert!(!with_eza.contains("bat"), "{with_eza}");
        assert!(!with_eza.contains("command -v"), "{with_eza}");
    }

    fn ready(name: &str, body: &str, hook: Option<&str>) -> Resolution<Function> {
        Resolution::Ready(Function {
            name: name.to_string(),
            body: body.to_string(),
            hook: hook.map(|h| crate::config::function::Hook::parse(h).expect("a hook")),
            when: None,
        })
    }

    fn held<T>(name: &str, hint: &str) -> Resolution<T> {
        Resolution::Blocked(BlockedEntry {
            key: name.to_string(),
            origin: super::super::super::Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line: 9,
            },
            reason: super::super::super::resolution::BlockReason::UnsetValue {
                names: vec!["proj".to_string()],
            },
            hint: hint.to_string(),
        })
    }

    #[test]
    fn functions_land_after_aliases_and_the_held_back_ones_are_named_in_the_note() {
        let file = Interactive::new(fragment(Vec::new()))
            .with_aliases(&[alias("ll", "ls -la", None)])
            .with_functions(vec![
                ready("mkcd", "mkdir -p -- \"$1\" && cd -- \"$1\"\n", None),
                held("goproj", "run `bx init` to set proj"),
                ready("track", "return 0", Some("chpwd")),
            ]);
        assert_eq!(file.functions().len(), 3);
        let rendered = render(&file);
        assert_eq!(
            rendered,
            "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: aliases\n\
                 alias ll='ls -la'\n\
                 \n# bx phase: functions\n\
                 function mkcd {\nmkdir -p -- \"$1\" && cd -- \"$1\"\n}\n\
                 function __bx_hook_track {\nreturn 0\n}\n\
                 (( ${+chpwd_functions} )) && (( ${chpwd_functions[(Ie)__bx_hook_track]} )) \
                 || chpwd_functions+=(__bx_hook_track)\n"
        );
        assert_eq!(render(&file), rendered, "byte-identical");
        assert!(!rendered.contains("goproj"), "{rendered}");
        assert_eq!(
            file.note().as_deref(),
            Some("function `goproj` held back: run `bx init` to set proj")
        );
        assert_eq!(
            Gen::Interactive(Box::new(file.clone())).note(),
            file.note(),
            "the generator's note is the file's"
        );

        // Every function held back: no `functions` phase, and the note
        // names each in declaration order.
        let all_held = Interactive::new(fragment(Vec::new()))
            .with_functions(vec![held("a", "answer a"), held("b", "answer b")]);
        assert_eq!(
            render(&all_held),
            "# Generated by bx. Edit the config repo, not this file.\n"
        );
        assert_eq!(
            all_held.note().as_deref(),
            Some("function `a` held back: answer a; function `b` held back: answer b")
        );

        // Nothing held back, and no other generator, says anything.
        assert_eq!(Interactive::new(fragment(Vec::new())).note(), None);
        assert_eq!(Gen::Env(fragment(Vec::new())).note(), None);
        let source = Portable::parse_in("~/.x", Path::new("/home/u")).expect("portable");
        assert_eq!(Gen::Source(source).note(), None);
    }

    fn sourced(name: &str, path: &str, phase: Phase, when: Option<&str>) -> Resolution<Source> {
        Resolution::Ready(Source {
            name: name.to_string(),
            path: path.to_string(),
            phase,
            when: when.map(|w| crate::config::when::When::parse(w).expect("a condition")),
            origin: super::super::super::Origin {
                file: PathBuf::from("/repo/bx.toml"),
                line: 1,
            },
        })
    }

    #[test]
    fn sources_follow_their_phases_own_declarations_and_the_file_settles_to_zero() {
        let file = Interactive::new(fragment(Vec::new()))
            .with_plugins(&[plugin("p", "~/p.zsh", false, 1)])
            .expect("no claimant")
            .with_aliases(&[alias("ll", "ls -la", None)])
            .with_sources(vec![
                sourced("aliases", "~/.aliases", Phase::Aliases, None),
                sourced("fzf", "~/.fzf.zsh", Phase::Plugins, None),
                held("keychain", "run `bx init` to set host"),
            ]);
        assert_eq!(file.sources().len(), 3);
        let rendered = render(&file);
        assert_eq!(
            rendered,
            "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: plugins\n\
                 [[ -r ~/p.zsh ]] && source ~/p.zsh\n\
                 [[ -r ~/.fzf.zsh ]] && source ~/.fzf.zsh\n\
                 \n# bx phase: aliases\n\
                 alias ll='ls -la'\n\
                 [[ -r ~/.aliases ]] && source ~/.aliases\n\
                 \n# bx: done, whichever plugins were found\ntrue\n"
        );
        assert_eq!(render(&file), rendered, "byte-identical");
        assert_eq!(
            file.note().as_deref(),
            Some("source `keychain` held back: run `bx init` to set host")
        );

        // A source alone closes the file too, since its line returns 1
        // when the file is absent; a source gated off writes nothing and
        // needs no closing line.
        let alone = render(
            &Interactive::new(fragment(Vec::new())).with_sources(vec![sourced(
                "fzf",
                "~/.fzf.zsh",
                Phase::Options,
                None,
            )]),
        );
        assert!(alone.ends_with("~/.fzf.zsh\n\n# bx: done, whichever plugins were found\ntrue\n"));
        let gated = Interactive::new(fragment(Vec::new()))
            .with_sources(vec![sourced("b", "~/b", Phase::Plugins, Some("has:bat"))])
            .render(&tools(&|_| false));
        assert_eq!(
            gated,
            "# Generated by bx. Edit the config repo, not this file.\n"
        );

        // Functions and sources held back together: functions first.
        let both = Interactive::new(fragment(Vec::new()))
            .with_functions(vec![held("f", "answer a")])
            .with_sources(vec![held("s", "answer b")]);
        assert_eq!(
            both.note().as_deref(),
            Some("function `f` held back: answer a; source `s` held back: answer b")
        );
    }

    /// A machine on which every tool is `/usr/bin/<name>` and prints
    /// `<name>_init` — except `absent`, which is not on it.
    struct Echo;

    impl activation::Host for Echo {
        fn locate(&self, program: &str) -> crate::detect::Presence {
            if program == "absent" {
                return crate::detect::Presence::Missing;
            }
            crate::detect::Presence::Present {
                path: PathBuf::from(format!("/usr/bin/{program}")),
            }
        }
        fn hash(&self, path: &Path) -> Result<crate::state::ContentHash, String> {
            Ok(crate::state::ContentHash::of(
                path.as_os_str().as_encoded_bytes(),
            ))
        }
        fn run(&self, program: &Path, _: &[String]) -> Result<Vec<u8>, activation::RunError> {
            let name = program.file_name().expect("a name").to_string_lossy();
            Ok(format!("{name}_init\n").into_bytes())
        }
        fn path(&self) -> &std::ffi::OsStr {
            std::ffi::OsStr::new("")
        }
    }

    /// zsh's text for `decls`, as the plan decides it on [`Echo`].
    fn activations(decls: &[(&str, Phase)]) -> Vec<Activated> {
        let decls: Vec<activation::ActivationDecl> = decls
            .iter()
            .map(|(name, phase)| activation::ActivationDecl {
                name: (*name).to_string(),
                command: vec![(*name).to_string()],
                zsh: None,
                bash: None,
                shells: crate::config::shells::Shells::EVERY,
                phase: *phase,
                enabled: true,
                origin: super::super::super::Origin {
                    file: PathBuf::from("/repo/bx.toml"),
                    line: 1,
                },
            })
            .collect();
        activation::plan(
            &decls,
            &crate::state::Fingerprints::default(),
            &crate::env_guard::RootSet::strict(),
            &Echo,
        )
        .rendered(crate::config::shells::Shell::Zsh)
    }

    #[test]
    fn activations_land_in_their_phases_before_a_source_there_and_the_file_settles() {
        let file = Interactive::new(fragment(Vec::new()))
            .with_sources(vec![sourced(
                "late",
                "~/late.zsh",
                Phase::Activations,
                None,
            )])
            .with_activations(activations(&[
                ("starship", Phase::Completions),
                ("absent", Phase::Activations),
                ("mise", Phase::Activations),
            ]));
        assert_eq!(
            render(&file),
            "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: activations\n\
                 # bx activation: mise\n\
                 eval 'mise_init\n'\n\
                 [[ -r ~/late.zsh ]] && source ~/late.zsh\n\
                 \n# bx phase: completions\n\
                 # bx activation: starship\n\
                 eval 'starship_init\n'\n\
                 \n# bx: done, whichever plugins were found\ntrue\n"
        );

        // An activation alone closes the file too; one that was omitted
        // adds nothing, not even the closing line.
        let alone = render(
            &Interactive::new(fragment(Vec::new()))
                .with_activations(activations(&[("mise", Phase::Activations)])),
        );
        assert!(alone.ends_with("\n# bx: done, whichever plugins were found\ntrue\n"));
        let omitted = render(
            &Interactive::new(fragment(Vec::new()))
                .with_activations(activations(&[("absent", Phase::Activations)])),
        );
        assert_eq!(
            omitted,
            "# Generated by bx. Edit the config repo, not this file.\n"
        );
    }

    #[test]
    fn a_second_terminal_claimant_is_refused_naming_both() {
        let err = Interactive::new(fragment(Vec::new()))
            .with_plugins(&[
                plugin("zsh-syntax-highlighting", "~/a.zsh", true, 3),
                plugin("fast-syntax-highlighting", "~/b.zsh", true, 7),
            ])
            .expect_err("two claimants")
            .to_string();
        assert!(err.starts_with("/repo/bx.toml:7: "), "{err}");
        assert!(
            err.contains("plugin `zsh-syntax-highlighting` already claims at /repo/bx.toml:3"),
            "{err}"
        );
    }

    #[test]
    fn no_phase_but_env_sets_anything() {
        // Invariant 2: only the `env` phase is an environment fragment.
        // Every other line bx writes here is a comment, a blank, a plugin
        // line, an alias line or the guarded block around one, or the
        // closing `true`. None but an alias line holds an `=`, and an
        // alias line is exactly the one its declaration renders: the
        // `alias` builtin given one word, the body single-quoted.
        let aliases = [
            alias("ll", "ls -la", None),
            alias("g", "export X=1", Some("interactive")),
            alias("h", "Y=2 it's", Some("env:TMUX")),
            alias("gone", "Z=3", Some("has:missing")),
        ];
        let file = Interactive::new(fragment(vec![Var::always("EDITOR", "nvim")]))
            .with_plugins(&[
                plugin("t", "~/t.zsh", true, 1),
                plugin("p", "/opt/p/p.zsh", false, 2),
            ])
            .expect("one claimant")
            .with_aliases(&aliases);
        let present = |tool: &str| tool != "missing";
        let rendered = file.render(&tools(&present));
        let env = phase(&rendered, "# bx phase: env");
        assert_eq!(env.len(), 2, "{rendered}");
        assert_eq!(phase(&rendered, "# bx phase: aliases").len(), 7);
        let alias_lines: Vec<String> = aliases
            .iter()
            .map(|a| a.line().trim_end().to_string())
            .collect();
        let rest: Vec<&str> = rendered
            .lines()
            .filter(|line| !env.contains(line))
            .collect();
        for line in &rest {
            let bare = line.trim_start();
            if alias_lines.iter().any(|expected| expected == bare) {
                continue;
            }
            assert!(!line.contains('='), "{line:?}");
            assert!(
                line.is_empty()
                    || line.starts_with("# ")
                    || line.starts_with("[[ -r ")
                    || (line.starts_with("if [[ ") && line.ends_with(" ]]; then"))
                    || *line == "fi"
                    || *line == "true",
                "{line:?}"
            );
        }
        assert!(!rendered.contains("Z=3"), "{rendered}");

        // And in zsh: sourcing everything but the `env` phase changes no
        // parameter and exports nothing, whether or not a plugin's file
        // is there, and whichever runtime condition an alias holds.
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let without_env = Interactive::new(fragment(Vec::new()))
            .with_plugins(file.plugins())
            .expect("one claimant")
            .with_aliases(file.aliases())
            .render(&tools(&present));
        assert!(without_env.contains("alias ll='ls -la'\n"), "{without_env}");
        let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                        [[ ${parameters[$n]} == *special* ]] || print -r -- \"$n=${(P)n}\"; \
                        done; print -r -- ---; export; print -r -- ---; }\n";
        let script = format!("{dump}__bx_dump >/dev/null\n__bx_dump\n{without_env}__bx_dump\n");
        let got = String::from_utf8(run(&zsh, &["-f"], &script)).expect("utf-8");
        let parts: Vec<&str> = got.split("---\n").collect();
        assert_eq!(parts[1], parts[3], "nothing is exported");
        assert_eq!(parts[0], parts[2], "no parameter changes");
        // The dump does see an assignment, so the equality means something.
        let script = format!("{dump}__bx_dump >/dev/null\n__bx_dump\nZ=1\n__bx_dump\n");
        let got = String::from_utf8(run(&zsh, &["-f"], &script)).expect("utf-8");
        let parts: Vec<&str> = got.split("---\n").collect();
        assert_ne!(parts[2], parts[0]);
    }

    /// The source configuration's zsh history, parsed as a layer would.
    fn history() -> History {
        crate::config::parse_str(
            "[history]\nsize = 10000\nduplicates = \"all\"\nshare = true\n\
                 [history.file]\nzsh = \"~/.zsh_history\"\nbash = \"~/.bash_history\"\n",
            std::path::Path::new("/repo/bx.toml"),
            std::path::Path::new("/home/u"),
        )
        .expect("parses")
        .history
    }

    #[test]
    fn declared_history_lands_in_the_options_phase_in_zshs_names_only() {
        let file = Interactive::new(fragment(Vec::new()))
            .with_plugins(&[
                plugin("t", "~/t.zsh", true, 1),
                plugin("p", "~/p.zsh", false, 2),
            ])
            .expect("one claimant")
            .with_history(history());
        assert_eq!(file.history(), &history());
        let rendered = render(&file);
        assert_eq!(
            rendered,
            "# Generated by bx. Edit the config repo, not this file.\n\
                 \n# bx phase: plugins\n\
                 [[ -r ~/p.zsh ]] && source ~/p.zsh\n\
                 \n# bx phase: options\n\
                 HISTFILE=\"${HOME}/.zsh_history\"\n\
                 HISTSIZE=10000\n\
                 SAVEHIST=10000\n\
                 typeset -g +x HISTFILE HISTSIZE SAVEHIST\n\
                 setopt HIST_IGNORE_ALL_DUPS SHARE_HISTORY\n\
                 \n# bx phase: terminal\n\
                 [[ -r ~/t.zsh ]] && source ~/t.zsh\n\
                 \n# bx: done, whichever plugins were found\ntrue\n"
        );
        // bash's file and bash's names never reach zsh's file.
        assert!(!rendered.contains("bash_history"), "{rendered}");
        assert!(!rendered.contains("HISTFILESIZE"), "{rendered}");

        // A history alone is a file of its own, and one declaring nothing
        // zsh reads adds nothing.
        let alone = render(&Interactive::new(fragment(Vec::new())).with_history(history()));
        assert!(
            alone.ends_with("setopt HIST_IGNORE_ALL_DUPS SHARE_HISTORY\n"),
            "{alone}"
        );
        let bash_only = History {
            bash_file: history().bash_file,
            ..History::default()
        };
        assert_eq!(
            render(&Interactive::new(fragment(Vec::new())).with_history(bash_only)),
            "# Generated by bx. Edit the config repo, not this file.\n"
        );
    }

    #[test]
    fn an_interactive_zsh_reads_the_declared_history() {
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let rendered = render(&Interactive::new(fragment(Vec::new())).with_history(history()));
        let got = run(
            &zsh,
            &["-f", "-e"],
            &format!(
                "{rendered}print -r -- \"${{HISTFILE#$HOME}} $HISTSIZE $SAVEHIST\"\n\
                     [[ -o histignorealldups && -o sharehistory ]] && print -r -- options-on\n"
            ),
        );
        assert_eq!(
            String::from_utf8(got).expect("utf-8"),
            "/.zsh_history 10000 10000\noptions-on\n"
        );
    }
}
