use super::*;
use toml_edit::Document;

/// Parse the first `[[value]]` out of a document.
fn decl(text: &str) -> Result<ValueDecl, Error> {
    let doc = Document::parse(text).expect("valid TOML");
    let table = doc
        .as_table()
        .get("value")
        .expect("a [[value]]")
        .as_array_of_tables()
        .expect("an array of tables")
        .get(0)
        .expect("one element");
    parse_value_decl(table, Path::new("bx.toml"), text)
}

/// Parse the `[values]` table out of a document.
fn assignments(text: &str) -> Result<Vec<ValueAssignment>, Error> {
    let doc = Document::parse(text).expect("valid TOML");
    let table = doc
        .as_table()
        .get("values")
        .expect("a [values]")
        .as_table()
        .expect("a table");
    parse_assignments(table, Path::new("local.toml"), text)
}

fn with(extra: &str) -> String {
    format!("[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n{extra}")
}

fn message(result: Result<impl std::fmt::Debug, Error>) -> String {
    result.expect_err("should have been rejected").to_string()
}

#[test]
fn a_value_declaration_parses_every_field() {
    let text = "[[value]]\n\
                    name = \"scratch_root\"\n\
                    description = \"Root of this account's scratch storage\"\n\
                    kind = \"path\"\n\
                    required = true\n\
                    is_root = true\n\
                    default = \"/var/scratch\"\n";
    let decl = decl(text).unwrap();

    assert_eq!(decl.name, "scratch_root");
    assert_eq!(
        decl.description.as_deref(),
        Some("Root of this account's scratch storage")
    );
    assert_eq!(decl.kind, ValueKind::Path);
    assert!(decl.required);
    assert!(decl.is_root);
    assert_eq!(
        decl.default,
        Some(AssignedValue::String("/var/scratch".to_string()))
    );
    assert_eq!(decl.origin.line, 1);

    // Each flag set above is off unless a declaration says otherwise, and
    // the name is the natural key whatever else is declared.
    let bare = self::decl(&with("")).unwrap();
    assert_eq!(bare.name, "scratch_root");
    assert!(!bare.required);
    assert!(!bare.is_root);
}

#[test]
fn every_declared_kind_is_accepted() {
    for (spelling, expected) in ValueKind::SPELLINGS {
        let text = format!("[[value]]\nname = \"v\"\nkind = \"{spelling}\"\n");
        assert_eq!(decl(&text).unwrap().kind, expected, "{spelling}");
        assert_eq!(expected.to_string(), spelling);
    }
}

#[test]
fn an_unknown_kind_is_rejected() {
    let text = "[[value]]\nname = \"v\"\nkind = \"gpg-key\"\n";
    let message = message(decl(text));

    assert!(message.contains("\"age-recipient\""), "{message}");
    assert!(message.contains("bx.toml:3"), "{message}");
}

#[test]
fn a_default_may_be_a_string_or_a_boolean() {
    assert_eq!(
        decl(&with("default = \"/var/scratch\"\n")).unwrap().default,
        Some(AssignedValue::String("/var/scratch".to_string()))
    );
    assert_eq!(
        decl(&with("default = false\n")).unwrap().default,
        Some(AssignedValue::Bool(false))
    );
    assert_eq!(decl(&with("")).unwrap().default, None);
}

#[test]
fn a_default_of_any_other_type_is_rejected() {
    assert!(message(decl(&with("default = 7\n"))).contains("string or a boolean, found integer"));
    assert!(
        message(decl(&with("default = [\"a\"]\n"))).contains("string or a boolean, found array")
    );
}

#[test]
fn a_value_without_a_name_is_rejected() {
    let text = "[[value]]\nkind = \"path\"\n";
    assert!(message(decl(text)).contains("missing the required key `name`"));
}

#[test]
fn a_value_without_a_kind_is_rejected() {
    // Without a kind nothing can be validated, and `path` versus `string` is
    // the difference between a `~` being expanded and being left alone.
    let text = "[[value]]\nname = \"v\"\n";
    assert!(message(decl(text)).contains("missing the required key `kind`"));
}

#[test]
fn an_unknown_value_key_is_rejected_with_its_line() {
    let message = message(decl(&with("secret = true\n")));

    assert!(message.contains("unknown key `secret`"), "{message}");
    assert!(message.contains("[[value]]"), "{message}");
    assert!(message.contains("bx.toml:4"), "{message}");
}

#[test]
fn a_value_key_of_the_wrong_type_names_both_types() {
    assert!(
        message(decl(&with("required = \"yes\"\n")))
            .contains("`required` must be a boolean, found string")
    );
}

#[test]
fn an_assignment_is_parsed_without_being_resolved() {
    // No kind checking, no default application, no {{name}} substitution.
    let text = "[values]\n\
                    scratch_root = \"/var/scratch/this-account\"\n\
                    use_sccache = true\n\
                    greeting = \"hello {{git_email}}\"\n";
    let parsed = assignments(text).unwrap();

    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0].name, "scratch_root");
    assert_eq!(
        parsed[0].value,
        AssignedValue::String("/var/scratch/this-account".to_string())
    );
    assert_eq!(parsed[1].value, AssignedValue::Bool(true));
    assert_eq!(
        parsed[1].value.to_string(),
        "true",
        "a boolean renders as a boolean; entry A3 reports an assignment by \
             its rendered value and must not print `Bool(true)`"
    );
    assert_eq!(
        parsed[2].value.to_string(),
        "hello {{git_email}}",
        "substitution is A3's, so the braces survive"
    );
}

#[test]
fn assignments_keep_document_order() {
    let text = "[values]\nzeta = \"1\"\nalpha = \"2\"\nmiddle = \"3\"\n";
    let names: Vec<String> = assignments(text)
        .unwrap()
        .into_iter()
        .map(|a| a.name)
        .collect();

    assert_eq!(names, ["zeta", "alpha", "middle"]);
}

#[test]
fn every_assignment_carries_its_key_origin() {
    let text = "# local to this account\n[values]\nscratch_root = \"/var/scratch\"\n";
    let parsed = assignments(text).unwrap();

    assert_eq!(parsed[0].origin.line, 3);
    assert_eq!(parsed[0].origin.file, Path::new("local.toml"));
}

#[test]
fn an_assignment_of_an_unsupported_type_is_rejected() {
    let message = message(assignments("[values]\ncount = 3\n"));

    assert!(
        message.contains("string or a boolean, found integer"),
        "{message}"
    );
    assert!(message.contains("`count`"), "{message}");
}

#[test]
fn an_empty_values_table_assigns_nothing() {
    assert!(assignments("[values]\n").unwrap().is_empty());
}

// --- declaration-time validation this entry adds ------------------------

#[test]
fn an_assignment_key_must_be_a_value_name_too() {
    // One vocabulary, enforced wherever a name is written: a declaration, a
    // `{{name}}` reference, and the key of an answer.
    for bad in ["", "a.b", "a{{b}}", "Scratch", "scratch-root", "1st"] {
        let text = format!("[values]\n\"{bad}\" = \"x\"\n");
        let message = message(assignments(&text));
        assert!(message.contains("is not a value name"), "{bad}: {message}");
        assert!(message.contains("local.toml:2"), "{bad}: {message}");
    }
    for good in ["a", "scratch_root", "x2"] {
        let text = format!("[values]\n{good} = \"x\"\n");
        assert!(assignments(&text).is_ok(), "{good} should be accepted");
    }
}

#[test]
fn a_value_name_must_be_lowercase_snake_case() {
    for bad in ["Scratch", "1st", "scratch-root", "scratch root", "", "_x"] {
        let text = format!("[[value]]\nname = \"{bad}\"\nkind = \"path\"\n");
        let message = message(decl(&text));
        assert!(message.contains("is not a value name"), "{bad}: {message}");
    }
    for good in ["a", "scratch_root", "x2", "bun_root_2"] {
        let text = format!("[[value]]\nname = \"{good}\"\nkind = \"string\"\n");
        assert!(decl(&text).is_ok(), "{good} should be accepted");
    }
}

#[test]
fn is_root_requires_kind_path() {
    // A root is a directory the guard admits a relocating variable into, so
    // declaring one on a non-path kind would widen the guard on something
    // that is not a path at all.
    let message = message(decl(
        "[[value]]\nname = \"x\"\nkind = \"string\"\nis_root = true\n",
    ));
    assert!(
        message.contains("only legal on `kind = \"path\"`"),
        "{message}"
    );
    assert!(message.contains("`string`"), "{message}");

    assert!(
        decl("[[value]]\nname = \"x\"\nkind = \"path\"\nis_root = true\n").is_ok(),
        "a path root is fine"
    );
    assert!(
        decl("[[value]]\nname = \"x\"\nkind = \"string\"\nis_root = false\n").is_ok(),
        "`is_root = false` says nothing and constrains nothing"
    );
}

#[test]
fn a_declaration_is_enabled_unless_a_layer_says_otherwise() {
    assert!(decl(&with("")).unwrap().enabled);
    assert!(!decl(&with("enabled = false\n")).unwrap().enabled);
    assert!(decl(&with("enabled = true\n")).unwrap().enabled);
}

// --- kind validation ----------------------------------------------------

fn a_home() -> PathBuf {
    PathBuf::from("/var/home/example")
}

/// The canonical text a kind accepts `answer` as, or the rejection message.
fn check(kind: ValueKind, answer: &str) -> Result<String, String> {
    kind.check(answer, &a_home()).map_err(|e| e.to_string())
}

/// Whether `kind` refuses `answer` as malformed, not as some other error.
fn malformed(kind: ValueKind, answer: &str) -> bool {
    matches!(kind.check(answer, &a_home()), Err(ValueError::Malformed { kind: k, .. }) if k == kind)
}

#[test]
fn a_path_value_is_tilde_expanded_and_normalised() {
    assert_eq!(
        check(ValueKind::Path, "~/.cache/../cache/sccache").unwrap(),
        "/var/home/example/cache/sccache"
    );
    assert_eq!(check(ValueKind::Path, "~").unwrap(), "/var/home/example");
    assert_eq!(
        check(ValueKind::Path, "~/").unwrap(),
        "/var/home/example",
        "a trailing separator is folded by the same rule"
    );
    assert_eq!(
        check(ValueKind::Path, "/var/mnt//scratch/one/").unwrap(),
        "/var/mnt/scratch/one"
    );
}

#[test]
fn a_relative_path_value_is_an_error() {
    // It would resolve against whatever directory bx was invoked from,
    // which is not a property of the account.
    let message = check(ValueKind::Path, "scratch/one").unwrap_err();
    assert!(message.contains("be `~`, start with `~/`"), "{message}");
    assert!(check(ValueKind::Path, "").is_err());
}

#[test]
fn another_accounts_home_is_not_a_path_value() {
    // Nothing expands `~user`, so `~scratch/one` — a plausible typo for
    // `~/scratch/one` — would be canonicalised to a *relative* string. The
    // env_guard compares absolute destinations against it, so every
    // relocating variable the account meant to permit would be refused with
    // nothing naming the cause.
    for other in ["~user/x", "~x", "~root/.ssh", "~scratch/one"] {
        let message = check(ValueKind::Path, other)
            .expect_err(&format!("{other} was accepted as a path value"));
        assert!(
            message.contains("never expands another account"),
            "{message}"
        );
    }
}

#[test]
fn a_path_value_may_not_climb_out_of_the_home() {
    // Clamped, `~/../../..` is `/`, and an `is_root` value answered that way
    // makes every destination on the filesystem admissible with nothing on
    // screen to say so.
    for climbing in [
        "~/..",
        "~/../../..",
        "~/.ssh/../../etc",
        "~//..",
        "~//../etc",
        "~///../etc",
    ] {
        let message =
            check(ValueKind::Path, climbing).expect_err(&format!("{climbing} was accepted"));
        assert!(message.contains("not climb out of"), "{message}");
    }

    // Through the entry point `bx init` calls, which once answered
    // `~//../etc` with `/var/home/example/etc`.
    let values =
        ResolvedValues::resolve(vec![a_decl("scratch", ValueKind::Path)], &[], &a_home()).unwrap();
    let message = values
        .check_answer("scratch", "~//../etc")
        .expect_err("a doubled separator is still a climb out of the home");
    assert!(
        message.to_string().contains("not climb out of"),
        "{message}"
    );
    assert_eq!(
        check(ValueKind::Path, "~/.cache/../scratch").unwrap(),
        "/var/home/example/scratch",
        "a `..` that stays inside the home is ordinary"
    );
}

#[test]
fn a_root_value_may_not_be_the_whole_filesystem() {
    // The guard's only enforcement mechanism, switched off invisibly.
    let mut root = a_decl("scratch_root", ValueKind::Path);
    root.is_root = true;
    let values = resolve(vec![root.clone()], &[answer("scratch_root", "/")]).unwrap();
    assert!(values.roots().is_empty(), "refused, and admits nothing");

    // The same answer through the prompt, because one entry point validates
    // both and a prompt that accepted it would write a line that holds back
    // every target referencing the root.
    let values = ResolvedValues::resolve(vec![root], &[], &a_home()).unwrap();
    let message = values.check_answer("scratch_root", "/a/../..").unwrap_err();
    assert!(message.to_string().contains("may not be `/`"), "{message}");

    // A value that is not a root is unaffected: it is kept, and admits nothing.
    let plain = a_decl("brew_prefix", ValueKind::Path);
    let values = resolve(vec![plain], &[answer("brew_prefix", "/")]).unwrap();
    assert_eq!(values.get("brew_prefix").unwrap().text, "/");
    assert!(values.roots().is_empty(), "and it admits nothing");
}

#[test]
fn a_root_answered_as_the_filesystem_blocks_and_admits_nothing() {
    // `/` as a root puts every destination inside the declared roots. A
    // local.toml line that says so is refused at load however it is spelled,
    // and names that line. It holds back what references the root rather
    // than every target, and it never reaches `roots()`.
    let mut root = a_decl("scratch_root", ValueKind::Path);
    root.is_root = true;

    for spelling in ["/", "//", "/./", "/..", "/a/../.."] {
        let values = resolve(vec![root.clone()], &[answer("scratch_root", spelling)])
            .unwrap_or_else(|e| panic!("{spelling:?} failed the whole load: {e}"));

        assert!(values.get("scratch_root").is_none(), "{spelling:?}");
        assert!(
            values.roots().is_empty(),
            "{spelling:?} widened the root set"
        );
        assert_eq!(
            values.substitute("{{scratch_root}}"),
            Err(Unresolved::Invalid {
                names: vec!["scratch_root".to_string()]
            }),
            "{spelling:?}"
        );
        let hint = values.invalid_hint(&["scratch_root".to_string()]);
        assert!(hint.contains("local.toml:2"), "{spelling:?}: {hint}");
        assert!(hint.contains("may not be `/`"), "{spelling:?}: {hint}");
    }

    let values = resolve(
        vec![root],
        &[answer("scratch_root", "/var/mnt/scratch/one")],
    )
    .unwrap();
    assert_eq!(
        values.roots(),
        [PathBuf::from("/var/mnt/scratch/one")],
        "an ordinary absolute root is still a root"
    );
}

#[test]
fn a_path_value_expanded_against_a_relative_home_is_an_error() {
    // Held by the caller everywhere in the product — `paths::home_in`
    // refuses a relative home — but a `path` value is joined, substituted
    // into content and compared against the root set, and all three read it
    // as absolute, so it is asserted here rather than assumed.
    let message = ValueKind::Path
        .check("~/scratch", Path::new("relative/home"))
        .expect_err("a relative home cannot produce an absolute value");

    assert!(
        message.to_string().contains("must resolve to an absolute"),
        "{message}"
    );
}

#[test]
fn a_bool_value_renders_as_true_or_false() {
    assert_eq!(check(ValueKind::Bool, "true").unwrap(), "true");
    assert_eq!(check(ValueKind::Bool, "TRUE").unwrap(), "true");
    assert_eq!(check(ValueKind::Bool, "False").unwrap(), "false");
    assert!(malformed(ValueKind::Bool, "yes"));
    assert!(malformed(ValueKind::Bool, "1"));
}

#[test]
fn an_email_needs_one_at_and_no_whitespace() {
    assert_eq!(
        check(ValueKind::Email, "someone@example.invalid").unwrap(),
        "someone@example.invalid"
    );
    for bad in [
        "someone",
        "@example.invalid",
        "someone@",
        "one@two@three",
        "some one@example.invalid",
        "someone@example.invalid ",
    ] {
        assert!(malformed(ValueKind::Email, bad), "{bad} was accepted");
    }
}

#[test]
fn an_ssh_key_must_carry_a_known_algorithm_prefix() {
    let ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial00000000000000";
    assert_eq!(check(ValueKind::SshKey, ed25519).unwrap(), ed25519);
    assert!(check(ValueKind::SshKey, &format!("{ed25519} a comment")).is_ok());
    assert!(check(ValueKind::SshKey, "ssh-rsa AAAAB3NzaC1yc2E=").is_ok());
    assert!(check(ValueKind::SshKey, "ecdsa-sha2-nistp256 AAAAE2Vj").is_ok());
    assert!(
        check(ValueKind::SshKey, "sk-ssh-ed25519@openssh.com AAAAGnNr").is_ok(),
        "a FIDO-backed key is matched by its `sk-` prefix"
    );

    for bad in [
        "AAAAC3NzaC1lZDI1NTE5",
        "ssh-ed25519",
        "ssh-ed25519 ",
        "rsa AAAAB3Nz",
        "ssh-ed25519 not-base64!",
    ] {
        assert!(malformed(ValueKind::SshKey, bad), "{bad} was accepted");
    }
}

#[test]
fn an_age_recipient_accepts_age1_and_an_ssh_key() {
    let age = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    assert_eq!(check(ValueKind::AgeRecipient, age).unwrap(), age);
    // age accepts an ssh recipient, and so does bx.
    let ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample";
    assert_eq!(check(ValueKind::AgeRecipient, ssh).as_deref(), Ok(ssh));

    for bad in ["age1", "age1BADCHARS", "age2ql3z7", "ql3z7hjy54pw3hy"] {
        assert!(malformed(ValueKind::AgeRecipient, bad), "{bad}");
    }
}

#[test]
fn a_key_blob_may_carry_every_base64_symbol() {
    // Base64 spells key material with `+` and `/` as well as letters and
    // digits, and a real key's blob holds both almost every time. Every
    // other fixture here is alphanumeric, so a check that refused either
    // symbol would pass them all and reject nearly every real key.
    //
    // Synthetic: the algorithm headers are the real encodings of the
    // algorithm names, and what follows them is made-up material, not
    // anyone's key.
    let ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+synthetic/key+material/for+tests/only0";
    let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+synthetic/rsa+material/for+tests/only0== a comment";

    for key in [ed25519, rsa] {
        assert_eq!(
            check(ValueKind::SshKey, key).as_deref(),
            Ok(key),
            "an ssh-key value"
        );
        assert_eq!(
            check(ValueKind::AgeRecipient, key).as_deref(),
            Ok(key),
            "an ssh key is an age recipient too"
        );
    }

    // Each symbol on its own, so neither can hide behind the other.
    for blob in ["AAAA+AAAA", "AAAA/AAAA"] {
        let key = format!("ssh-ed25519 {blob}");
        assert!(check(ValueKind::SshKey, &key).is_ok(), "{key}");
        assert!(check(ValueKind::AgeRecipient, &key).is_ok(), "{key}");
    }
}

#[test]
fn a_string_value_accepts_anything() {
    for text in ["", "192", "agents.slice", "a b\tc\n"] {
        assert_eq!(check(ValueKind::String, text).unwrap(), text);
    }
}

#[test]
fn no_kind_check_touches_the_network_or_the_filesystem() {
    // Held structurally: `check` takes only a `&str` and a home, so there is
    // nothing it could open or dial. A `path` value that does not exist
    // still resolves, which `canonicalize` could not do.
    let absent = "/var/mnt/scratch/definitely/not/here";
    assert!(!Path::new(absent).exists());
    assert_eq!(check(ValueKind::Path, absent).unwrap(), absent);
}

// --- resolution ---------------------------------------------------------

/// A declaration with everything at its default.
fn a_decl(name: &str, kind: ValueKind) -> ValueDecl {
    ValueDecl {
        name: name.to_string(),
        description: Some(format!("the {name}")),
        kind,
        required: false,
        is_root: false,
        default: None,
        enabled: true,
        origin: Origin::unknown(Path::new("bx.toml")),
    }
}

/// A string answer, as the local layer would write it.
fn answer(name: &str, text: &str) -> ValueAssignment {
    ValueAssignment {
        name: name.to_string(),
        value: AssignedValue::String(text.to_string()),
        origin: Origin {
            file: PathBuf::from("local.toml"),
            line: 2,
        },
    }
}

/// Resolve, or return the load error's message.
fn resolve(decls: Vec<ValueDecl>, answers: &[ValueAssignment]) -> Result<ResolvedValues, String> {
    ResolvedValues::resolve(decls, answers, &a_home()).map_err(|e| e.to_string())
}

#[test]
fn a_default_applies_when_the_local_layer_is_silent() {
    let mut decl = a_decl("agent_slice", ValueKind::String);
    decl.default = Some(AssignedValue::String("agents.slice".to_string()));

    let values = resolve(vec![decl], &[]).unwrap();

    assert_eq!(values.get("agent_slice").unwrap().text, "agents.slice");
    assert_eq!(
        values.get("agent_slice").unwrap().origin.file,
        Path::new("bx.toml"),
        "the default came from the declaring layer, and says so"
    );
}

#[test]
fn a_local_answer_overrides_a_default() {
    let mut decl = a_decl("agent_slice", ValueKind::String);
    decl.default = Some(AssignedValue::String("agents.slice".to_string()));

    let values = resolve(vec![decl], &[answer("agent_slice", "work.slice")]).unwrap();

    assert_eq!(values.get("agent_slice").unwrap().text, "work.slice");
    assert_eq!(
        values.get("agent_slice").unwrap().origin.file,
        Path::new("local.toml"),
        "`bx plan` has to be able to name the file that made this account differ"
    );
}

#[test]
fn a_default_may_reference_an_earlier_value() {
    // The decision that makes the operator's requirement cheap: twenty-four
    // relocating cache paths derive from one root, so an account that has
    // not moved them answers one question instead of twenty-four.
    let scratch = a_decl("scratch_root", ValueKind::Path);
    let mut sccache = a_decl("sccache_dir", ValueKind::Path);
    sccache.default = Some(AssignedValue::String(
        "{{scratch_root}}/cache/sccache".to_string(),
    ));

    let values = resolve(
        vec![scratch, sccache],
        &[answer("scratch_root", "/var/mnt/scratch/one")],
    )
    .unwrap();

    assert_eq!(
        values.get("sccache_dir").unwrap().text,
        "/var/mnt/scratch/one/cache/sccache"
    );
}

#[test]
fn a_default_referencing_a_later_value_is_an_error() {
    let mut early = a_decl("sccache_dir", ValueKind::Path);
    early.default = Some(AssignedValue::String("{{scratch_root}}/x".to_string()));
    let late = a_decl("scratch_root", ValueKind::Path);

    let message = resolve(vec![early, late], &[]).unwrap_err();

    assert!(message.contains("is declared later"), "{message}");
    assert!(message.contains("scratch_root"), "{message}");
}

#[test]
fn a_default_referencing_itself_is_an_error() {
    // One pass in declaration order makes a cycle unrepresentable rather
    // than something to detect, and a self reference is the shortest cycle.
    let mut decl = a_decl("scratch_root", ValueKind::Path);
    decl.default = Some(AssignedValue::String("{{scratch_root}}/x".to_string()));

    let message = resolve(vec![decl], &[]).unwrap_err();

    assert!(message.contains("is declared later"), "{message}");
}

#[test]
fn a_default_referencing_an_undeclared_value_is_an_error() {
    let mut decl = a_decl("sccache_dir", ValueKind::Path);
    decl.default = Some(AssignedValue::String("{{nowhere}}/x".to_string()));

    let message = resolve(vec![decl], &[]).unwrap_err();

    assert!(
        message.contains("no layer declares the value `nowhere`"),
        "{message}"
    );
}

#[test]
fn an_answer_that_is_not_of_its_kind_blocks_its_dependents_naming_its_line() {
    // The line is wrong on its own terms, and it is the account's: it costs
    // what references `git_email`, not the load, and the note names it.
    let decl = a_decl("git_email", ValueKind::Email);

    let values = resolve(vec![decl], &[answer("git_email", "not an address")])
        .expect("an account's own bad line does not fail the load");

    assert!(values.get("git_email").is_none());
    let hint = values.invalid_hint(&["git_email".to_string()]);
    assert!(hint.contains("local.toml:2"), "{hint}");
    assert!(hint.contains("git_email"), "{hint}");
    assert!(hint.contains("exactly one `@`"), "{hint}");
}

#[test]
fn a_default_an_answer_makes_invalid_blocks_rather_than_failing() {
    // `prefix = "scratch"` is a legal `string`. The committed default of
    // `cache` it feeds becomes `scratch/cache`, which is not a `path` — but
    // the account's line is right for its own declaration, so this blocks
    // what references `cache` instead of failing every target.
    let prefix = a_decl("prefix", ValueKind::String);
    let mut cache = a_decl("cache", ValueKind::Path);
    cache.required = true;
    cache.default = Some(AssignedValue::String("{{prefix}}/cache".to_string()));
    let mut sub = a_decl("sub", ValueKind::Path);
    sub.default = Some(AssignedValue::String("{{cache}}/sub".to_string()));
    let note = a_decl("note", ValueKind::String);

    let values = resolve(
        vec![prefix, cache, sub, note],
        &[answer("prefix", "scratch")],
    )
    .expect("a legal answer does not fail the load");

    let invalid = Unresolved::Invalid {
        names: vec!["cache".to_string()],
    };
    assert!(values.get("cache").is_none());
    assert_eq!(values.substitute("{{cache}}"), Err(invalid.clone()));
    assert_eq!(
        values.substitute("{{sub}}"),
        Err(invalid.clone()),
        "the cause travels to what derives from it"
    );
    assert_eq!(
        values.check_answer("note", "{{cache}}"),
        Err(AnswerError::Reference(invalid))
    );
    assert!(
        values.unset_required_names().is_empty(),
        "no prompt would help: the answer that needs changing is written"
    );
    assert_eq!(
        values
            .unset()
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>(),
        ["cache", "sub", "note"],
        "doctor still lists everything with no usable answer"
    );

    let hint = values.invalid_hint(&["cache".to_string()]);
    assert!(hint.contains("value `cache`"), "{hint}");
    assert!(hint.contains("`prefix` at local.toml:2"), "{hint}");
    assert!(hint.contains("\"scratch/cache\""), "{hint}");
}

#[test]
fn a_default_names_every_answer_it_was_built_from() {
    // An answer that is itself built from another answer carries both, so
    // the note names every line that could be changed to fix it.
    let prefix = a_decl("prefix", ValueKind::String);
    let mid = a_decl("mid", ValueKind::String);
    let mut cache = a_decl("cache", ValueKind::Path);
    cache.default = Some(AssignedValue::String("{{prefix}}{{mid}}/c".to_string()));

    let values = resolve(
        vec![prefix, mid, cache],
        &[answer("prefix", "a"), answer("mid", "{{prefix}}b")],
    )
    .unwrap();

    let hint = values.invalid_hint(&["cache".to_string()]);
    assert!(hint.contains("`prefix` at"), "{hint}");
    assert!(hint.contains("`mid` at"), "{hint}");
}

// --- the derived-value hint ---------------------------------------------

/// `p` answered, `q` deriving its whole value from `p`'s answer, and `r`
/// deriving from `q`. Nothing here is answered but `p`.
fn derived_chain() -> ResolvedValues {
    let p = a_decl("p", ValueKind::String);
    let mut q = a_decl("q", ValueKind::String);
    q.default = Some(AssignedValue::String("{{p}}".to_string()));
    let mut r = a_decl("r", ValueKind::String);
    r.default = Some(AssignedValue::String("{{q}}".to_string()));
    resolve(vec![p, q, r], &[answer("p", "one")]).expect("the chain resolves")
}

#[test]
fn derived_between_counts_every_occurrence_of_a_name() {
    // A name written twice is one entry counted twice, not two entries.
    // The count is what parts two spellings that both carry it.
    let values = derived_chain();

    let mut once = Vec::new();
    values.derived_between("~/{{q}}/x", &mut once);
    assert_eq!(once, [("q".to_string(), 1)]);

    let mut twice = Vec::new();
    values.derived_between("~/{{q}}{{q}}/x", &mut twice);
    assert_eq!(twice, [("q".to_string(), 2)]);
}

#[test]
fn derived_between_multiplies_a_count_down_a_default() {
    // `r`'s own default reaches `q` once, and the text reaches `r` twice,
    // so `q` is reached twice as well.
    let values = derived_chain();

    let mut into = Vec::new();
    values.derived_between("~/{{r}}{{r}}/x", &mut into);

    assert_eq!(into, [("r".to_string(), 2), ("q".to_string(), 2)]);
}

#[test]
fn derived_between_names_a_value_reached_down_two_defaults_once() {
    // `left` and `right` both default to `{{q}}`. `q` is reached twice, by
    // two routes, and gets one entry with the total.
    let p = a_decl("p", ValueKind::String);
    let mut q = a_decl("q", ValueKind::String);
    q.default = Some(AssignedValue::String("{{p}}".to_string()));
    let mut left = a_decl("left", ValueKind::String);
    left.default = Some(AssignedValue::String("{{q}}".to_string()));
    let mut right = a_decl("right", ValueKind::String);
    right.default = Some(AssignedValue::String("{{q}}".to_string()));
    let values =
        resolve(vec![p, q, left, right], &[answer("p", "one")]).expect("the pair resolves");

    let mut into = Vec::new();
    values.derived_between("{{left}}{{right}}", &mut into);

    assert_eq!(
        into,
        [
            ("left".to_string(), 1),
            ("q".to_string(), 2),
            ("right".to_string(), 1),
        ]
    );
}

/// `p` answered, and two spellings that reach `deep` by different routes.
///
/// `{{left}}{{right}}` reaches it down two defaults; `{{m}}{{m}}` reaches
/// `m` twice directly. Both are four copies of `deep` for every answer.
fn route_diamond() -> ResolvedValues {
    let p = a_decl("p", ValueKind::String);
    let mut deep = a_decl("deep", ValueKind::String);
    deep.default = Some(AssignedValue::String("{{p}}".to_string()));
    let mut m = a_decl("m", ValueKind::String);
    m.default = Some(AssignedValue::String("{{deep}}{{deep}}".to_string()));
    let mut left = a_decl("left", ValueKind::String);
    left.default = Some(AssignedValue::String("{{m}}".to_string()));
    let mut right = a_decl("right", ValueKind::String);
    right.default = Some(AssignedValue::String("{{m}}".to_string()));
    resolve(vec![p, deep, m, left, right], &[answer("p", "")]).expect("the diamond resolves")
}

/// `name`'s count in a `derived_between` result, if it is in one at all.
fn reached(into: &[(String, usize)], name: &str) -> Option<usize> {
    into.iter()
        .find(|(held, _)| held == name)
        .map(|(_, count)| *count)
}

#[test]
fn derived_between_counts_a_name_by_how_often_a_text_reaches_it_not_by_its_route() {
    // Both spellings reach `deep` four times and `m` twice, by different
    // routes. A walk that stopped at a name it had already seen gave the
    // two-defaults spelling two `deep` and the twice-directly spelling
    // four, because only the second carried its multiplier into the
    // recursion — and `answers_hint` read that difference as evidence that
    // `deep` parts them.
    let values = route_diamond();

    let mut two_defaults = Vec::new();
    values.derived_between("{{left}}{{right}}", &mut two_defaults);
    let mut twice_directly = Vec::new();
    values.derived_between("{{m}}{{m}}", &mut twice_directly);

    assert_eq!(reached(&two_defaults, "deep"), Some(4), "{two_defaults:?}");
    assert_eq!(
        reached(&twice_directly, "deep"),
        Some(4),
        "{twice_directly:?}"
    );
    assert_eq!(reached(&two_defaults, "m"), Some(2), "{two_defaults:?}");
    assert_eq!(reached(&twice_directly, "m"), Some(2), "{twice_directly:?}");
    // The two names that really do part the spellings.
    assert_eq!(reached(&two_defaults, "left"), Some(1), "{two_defaults:?}");
    assert_eq!(reached(&twice_directly, "left"), None, "{twice_directly:?}");
}

#[test]
fn a_derived_value_two_spellings_reach_by_different_routes_is_not_offered() {
    // The hint the counts feed. `deep` and `m` expand to the same text on
    // both sides for every answer, so answering either leaves the two
    // spellings equal and neither is an act that clears the block; only
    // `left` or `right` is.
    let values = route_diamond();

    let hint = values.answers_hint(
        "broken",
        &["{{left}}{{right}}", "{{m}}{{m}}"],
        &["p".to_string()],
    );

    assert!(
        hint.ends_with("change that answer, or answer `left` or `right` directly"),
        "{hint}"
    );
    assert!(!hint.contains("`deep`"), "{hint}");
    assert!(!hint.contains("`m`"), "{hint}");
}

#[test]
fn derived_between_takes_a_malformed_text_as_carrying_nothing() {
    // Defensive: every text the hint walks has already substituted, and
    // substitution scans the same text, so `scan` cannot refuse one. This
    // pins what a future caller that breaks that invariant gets — the
    // short-form hint, whole, rather than a panic or a half-walked text.
    let values = derived_chain();

    let mut into = Vec::new();
    values.derived_between("{{q}}{{oops", &mut into);
    assert!(into.is_empty(), "{into:?}");

    let hint = values.answers_hint("broken", &["{{q}}{{oops"], &["p".to_string()]);
    assert!(hint.ends_with("; change that answer"), "{hint}");
}

#[test]
fn derived_between_passes_over_a_name_no_layer_declares() {
    // Defensive: every text the hint walks names declared values only. The
    // walk stops at the name rather than panicking, and a future caller
    // that breaks the invariant gets no entry rather than a crash.
    let values = derived_chain();

    let mut into = Vec::new();
    values.derived_between("{{nowhere}}{{q}}", &mut into);

    assert_eq!(into, [("q".to_string(), 1)]);
}

#[test]
fn derived_between_passes_over_a_value_with_no_answer() {
    // Defensive in the same way: the hint is only built for texts that
    // substituted, so every name in one is `Given`. An unanswered one is
    // passed over.
    let p = a_decl("p", ValueKind::String);
    let unanswered = a_decl("unanswered", ValueKind::String);
    let mut q = a_decl("q", ValueKind::String);
    q.default = Some(AssignedValue::String("{{p}}".to_string()));
    let values = resolve(vec![p, unanswered, q], &[answer("p", "one")]).expect("the rest resolves");
    assert!(values.get("unanswered").is_none());

    let mut into = Vec::new();
    values.derived_between("{{unanswered}}{{q}}", &mut into);

    assert_eq!(into, [("q".to_string(), 1)]);
}

#[test]
fn derived_between_passes_over_a_value_answered_in_its_own_right() {
    // `q` is answered by the account, so it is named as an answer rather
    // than as a declaration to answer directly, and a value built from
    // committed text alone carries no answer to offer.
    let p = a_decl("p", ValueKind::String);
    let mut q = a_decl("q", ValueKind::String);
    q.default = Some(AssignedValue::String("{{p}}".to_string()));
    let mut fixed = a_decl("fixed", ValueKind::String);
    fixed.default = Some(AssignedValue::String("committed".to_string()));
    let values = resolve(vec![p, q, fixed], &[answer("p", "one"), answer("q", "two")])
        .expect("the values resolve");

    let mut into = Vec::new();
    values.derived_between("{{q}}{{fixed}}", &mut into);

    assert!(into.is_empty(), "{into:?}");
}

#[test]
fn answers_hint_names_every_derived_value_a_single_text_carries() {
    // One text: there is nothing to separate it from, so every value that
    // carries the answer in is an act that changes it.
    let values = derived_chain();

    let hint = values.answers_hint("broken", &["~/{{r}}/x"], &["p".to_string()]);

    assert!(
        hint.ends_with("change that answer, or answer `q` or `r` directly"),
        "{hint}"
    );
}

#[test]
fn a_derived_value_every_colliding_spelling_carries_is_not_offered_as_the_way_out() {
    // Both spellings hold `q` once, so answering it rewrites both alike and
    // naming it would be advice that clears nothing.
    let values = derived_chain();

    let hint = values.answers_hint(
        "broken",
        &["~/{{q}}/x", "~/a/{{q}}/x/.."],
        &["p".to_string()],
    );

    assert!(hint.ends_with("; change that answer"), "{hint}");
    assert!(!hint.contains("directly"), "{hint}");
}

#[test]
fn answers_hint_names_a_derived_value_one_spelling_carries_more_often() {
    // The same value, carried once by one spelling and twice by the other.
    // Answering it does part them, so the hint has to offer it.
    let values = derived_chain();

    let hint = values.answers_hint(
        "broken",
        &["~/{{q}}/x", "~/{{q}}{{q}}/x"],
        &["p".to_string()],
    );

    assert!(
        hint.ends_with("change that answer, or answer `q` directly"),
        "{hint}"
    );
}

#[test]
fn a_default_invalid_without_an_account_answer_is_still_a_load_error() {
    // No answer caused it and none can fix it, so it is a defect in the
    // committed repo, and the declaration is the right thing to name.
    let mut cache = a_decl("cache", ValueKind::Path);
    cache.default = Some(AssignedValue::String("relative/cache".to_string()));

    let message = resolve(vec![cache], &[]).unwrap_err();
    assert!(message.contains("bx.toml"), "{message}");
    assert!(message.contains("value `cache`"), "{message}");

    // Nor is it the account's doing when what it derives from is itself a
    // committed default.
    let mut prefix = a_decl("prefix", ValueKind::String);
    prefix.default = Some(AssignedValue::String("scratch".to_string()));
    let mut cache = a_decl("cache", ValueKind::Path);
    cache.default = Some(AssignedValue::String("{{prefix}}/cache".to_string()));

    let message = resolve(vec![prefix, cache], &[]).unwrap_err();
    assert!(message.contains("\"scratch/cache\""), "{message}");
}

#[test]
fn a_derived_value_reports_the_answer_its_user_must_supply() {
    // `sccache_dir` is unanswerable until `scratch_root` is answered, so the
    // name reported is the one the user can act on, not the derived one.
    let scratch = a_decl("scratch_root", ValueKind::Path);
    let mut sccache = a_decl("sccache_dir", ValueKind::Path);
    sccache.default = Some(AssignedValue::String("{{scratch_root}}/x".to_string()));

    let values = resolve(vec![scratch, sccache], &[]).unwrap();

    assert!(values.get("sccache_dir").is_none());
    let blocked = values
        .substitute("cache is at {{sccache_dir}}")
        .unwrap_err();
    assert_eq!(
        blocked,
        Unresolved::Unset {
            names: vec!["scratch_root".to_string()]
        }
    );
}

#[test]
fn declarations_enumerate_in_declaration_order() {
    let names = ["scratch_root", "bun_root", "agent_slice", "git_name"];
    let decls = names
        .iter()
        .map(|name| a_decl(name, ValueKind::String))
        .collect();

    let values = resolve(decls, &[]).unwrap();

    assert_eq!(
        values
            .decls()
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>(),
        names,
        "not sorted, not hashed: the order the layers declared them in"
    );
}

#[test]
fn unset_required_values_are_listed_in_declaration_order() {
    let mut scratch = a_decl("scratch_root", ValueKind::Path);
    scratch.required = true;
    let optional = a_decl("agent_slice", ValueKind::String);
    let mut email = a_decl("git_email", ValueKind::Email);
    email.required = true;

    let values = resolve(
        vec![scratch, optional, email],
        &[answer("git_email", "someone@example.invalid")],
    )
    .unwrap();

    assert_eq!(
        values
            .unset_required()
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>(),
        ["scratch_root"],
        "answered required values and unset optional ones are both absent"
    );
    assert_eq!(
        values
            .unset()
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>(),
        ["scratch_root", "agent_slice"],
        "doctor lists every unanswered value, required or not"
    );
}

#[test]
fn a_derived_value_is_not_prompted_for_in_its_own_right() {
    // `cache` cannot be answered usefully: `bx init` would pre-fill the
    // literal `{{root}}/cache`, which its own validator then rejects. The
    // blocked entry names only `root`, and the prompt list agrees with it.
    let mut root = a_decl("root", ValueKind::Path);
    root.required = true;
    let mut cache = a_decl("cache", ValueKind::Path);
    cache.required = true;
    cache.default = Some(AssignedValue::String("{{root}}/cache".to_string()));

    let values = resolve(vec![root, cache], &[]).unwrap();

    assert_eq!(
        values.unset_required_names(),
        ["root"],
        "one question, not two, and the one that can be answered"
    );
    assert_eq!(
        values
            .unset()
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>(),
        ["root", "cache"],
        "doctor still lists everything with no answer, whatever the reason"
    );
    assert_eq!(
        values.substitute("{{cache}}").unwrap_err(),
        Unresolved::Unset {
            names: vec!["root".to_string()]
        },
        "which is what the blocked entry already said"
    );
}

#[test]
fn unset_required_names_returns_names_not_a_flag() {
    // A report has to say *which* value is missing or the user cannot act.
    let mut scratch = a_decl("scratch_root", ValueKind::Path);
    scratch.required = true;
    let mut email = a_decl("git_email", ValueKind::Email);
    email.required = true;

    let values = resolve(vec![scratch, email], &[]).unwrap();

    assert_eq!(
        values.unset_required_names(),
        ["scratch_root", "git_email"],
        "declaration order, and names rather than a boolean"
    );
}

#[test]
fn roots_are_declaration_ordered_and_absolute() {
    let mut scratch = a_decl("scratch_root", ValueKind::Path);
    scratch.is_root = true;
    let not_a_root = a_decl("brew_prefix", ValueKind::Path);
    let mut sccache = a_decl("sccache_dir", ValueKind::Path);
    sccache.is_root = true;

    let values = resolve(
        vec![scratch, not_a_root, sccache],
        &[
            answer("scratch_root", "~/scratch/./one"),
            answer("brew_prefix", "/home/linuxbrew/.linuxbrew"),
            answer("sccache_dir", "/var/mnt/other/sccache"),
        ],
    )
    .unwrap();

    assert_eq!(
        values.roots(),
        [
            PathBuf::from("/var/home/example/scratch/one"),
            PathBuf::from("/var/mnt/other/sccache"),
        ],
        "expanded, normalised, declaration-ordered, and only the declared roots"
    );
}

#[test]
fn an_unanswered_root_contributes_no_root() {
    // A declaration nobody filled in must not widen the guard on the
    // strength of an intention.
    let mut scratch = a_decl("scratch_root", ValueKind::Path);
    scratch.is_root = true;
    let mut sccache = a_decl("sccache_dir", ValueKind::Path);
    sccache.is_root = true;

    let values = resolve(
        vec![scratch, sccache],
        &[answer("sccache_dir", "/var/mnt/other/sccache")],
    )
    .unwrap();

    assert_eq!(values.roots(), [PathBuf::from("/var/mnt/other/sccache")]);
}

#[test]
fn resolved_values_report_the_home_they_were_resolved_against() {
    // `env_guard` needs `$HOME` in its root set and it has to be the *same*
    // home the path values were expanded with, so the home travels inside
    // the values rather than being read from the environment again.
    let mut scratch = a_decl("scratch_root", ValueKind::Path);
    scratch.is_root = true;

    let values = resolve(vec![scratch], &[answer("scratch_root", "~/scratch")]).unwrap();

    assert_eq!(values.home(), a_home());
    assert_eq!(values.roots(), [a_home().join("scratch")]);
}

#[test]
fn a_declaration_and_its_answer_are_both_reachable_by_name() {
    let decl = a_decl("agent_slice", ValueKind::String);

    let values = resolve(vec![decl], &[answer("agent_slice", "work.slice")]).unwrap();

    assert_eq!(values.decl("agent_slice").unwrap().kind, ValueKind::String);
    assert_eq!(values.get("agent_slice").unwrap().text, "work.slice");
    assert!(values.decl("never_declared").is_none());
    assert!(values.get("never_declared").is_none());
}

#[test]
fn a_boolean_answer_resolves_through_the_same_path_as_a_string() {
    let decl = a_decl("is_desktop", ValueKind::Bool);
    let assignment = ValueAssignment {
        name: "is_desktop".to_string(),
        value: AssignedValue::Bool(true),
        origin: Origin::unknown(Path::new("local.toml")),
    };

    let values = resolve(vec![decl], &[assignment]).unwrap();

    assert_eq!(values.get("is_desktop").unwrap().text, "true");
}

#[test]
fn an_answer_for_a_value_no_layer_declares_is_ignored() {
    // Deliberately not fatal. An account's `local.toml` outlives the repo
    // that declared what it answers, so a repo update that drops a
    // declaration must not stop that account applying anything at all. It is
    // detectable rather than silent — the value the account meant to answer
    // is still reported as unset — and listing the leftovers is doctor's.
    let mut decl = a_decl("scratch_root", ValueKind::Path);
    decl.required = true;

    let values = resolve(vec![decl], &[answer("scratch_roott", "/var/mnt/x")]).unwrap();

    assert_eq!(values.unset_required_names(), ["scratch_root"]);
    assert!(values.get("scratch_roott").is_none());
}

#[test]
fn resolving_twice_is_byte_identical() {
    // Invariant 3: the resolution is a pure function of the declarations,
    // the answers and the home.
    let decls = || {
        let mut scratch = a_decl("scratch_root", ValueKind::Path);
        scratch.is_root = true;
        let mut sccache = a_decl("sccache_dir", ValueKind::Path);
        sccache.default = Some(AssignedValue::String("{{scratch_root}}/s".to_string()));
        vec![scratch, sccache, a_decl("git_name", ValueKind::String)]
    };
    let answers = [answer("scratch_root", "/var/mnt/scratch/one")];

    let first = resolve(decls(), &answers).unwrap();
    let second = resolve(decls(), &answers).unwrap();

    assert_eq!(format!("{first:#?}"), format!("{second:#?}"));
}

// --- substitution -------------------------------------------------------

/// Values for the substitution tests: one answered, one not.
fn substitution_values() -> ResolvedValues {
    let scratch = a_decl("scratch_root", ValueKind::Path);
    let unanswered = a_decl("git_name", ValueKind::String);
    let braced = a_decl("braced", ValueKind::String);
    resolve(
        vec![scratch, unanswered, braced],
        &[
            answer("scratch_root", "/var/mnt/scratch/one"),
            // Escaped, so the stored text is a literal brace pair: an answer
            // is itself substituted once, at its own declaration's position.
            answer("braced", "{{{{scratch_root}}"),
        ],
    )
    .unwrap()
}

#[test]
fn substitute_replaces_each_placeholder_and_refuses_what_is_not_one() {
    use PlaceholderError::{IllegalName, Unterminated};
    let values = substitution_values();
    let scratch = "/var/mnt/scratch/one";
    let illegal = |name: &str| {
        Err(Unresolved::Malformed(IllegalName {
            name: name.to_string(),
            at: 0,
        }))
    };

    let cases: Vec<(&str, Result<String, Unresolved>)> = vec![
        (
            "export CARGO_HOME={{scratch_root}}/cargo",
            Ok(format!("export CARGO_HOME={scratch}/cargo")),
        ),
        (
            "{{scratch_root}}:{{scratch_root}}",
            Ok(format!("{scratch}:{scratch}")),
        ),
        ("", Ok(String::new())),
        ("plain text", Ok("plain text".to_string())),
        // The operator's own files contain literal brace pairs — a GitHub
        // workflow's expression syntax, a handlebars template — so four
        // braces are a literal two.
        ("{{{{scratch_root}}", Ok("{{scratch_root}}".to_string())),
        ("{{{{}}", Ok("{{}}".to_string())),
        ("a{{{{b{{scratch_root}}", Ok(format!("a{{{{b{scratch}"))),
        // There is no escape for a closing pair and none is needed: a
        // closing pair is only special once a placeholder is open.
        ("a}}b", Ok("a}}b".to_string())),
        ("}}", Ok("}}".to_string())),
        ("{{scratch_root}}}}", Ok(format!("{scratch}}}}}"))),
        // `braced` holds the literal text of a placeholder, and yields it
        // verbatim rather than expanding it a second time: one pass is what
        // keeps this a name lookup rather than a template language.
        ("{{braced}}", Ok("{{scratch_root}}".to_string())),
        // The scanner indexes into the string, so it advances by characters
        // and never splits one.
        (
            "café → {{scratch_root}} ☕",
            Ok(format!("café → {scratch} ☕")),
        ),
        ("日本語", Ok("日本語".to_string())),
        (
            "{{scratch_root",
            Err(Unresolved::Malformed(Unterminated { at: 0 })),
        ),
        ("ok {{x", Err(Unresolved::Malformed(Unterminated { at: 3 }))),
        ("{{Scratch}}", illegal("Scratch")),
        ("{{scratch-root}}", illegal("scratch-root")),
        ("{{ scratch_root }}", illegal(" scratch_root ")),
        ("{{}}", illegal("")),
        // A nested placeholder is an error, not an expansion.
        ("{{a{{scratch_root}}}}", illegal("a{{scratch_root")),
        // A repo typo, unfixable by any answer, so it fails the load rather
        // than blocking a target.
        (
            "{{nowhere}}",
            Err(Unresolved::Undeclared("nowhere".to_string())),
        ),
        // An unanswered value is unset rather than an error.
        (
            "name = {{git_name}}",
            Err(Unresolved::Unset {
                names: vec!["git_name".to_string()],
            }),
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(values.substitute(text), expected, "{text}");
    }
    assert_eq!(values.get("braced").unwrap().text, "{{scratch_root}}");
}

#[test]
fn an_answer_is_itself_substituted_once() {
    // Which is what lets `local.toml` say `sccache_dir =
    // "{{scratch_root}}/sccache"` as well as spelling it out.
    let scratch = a_decl("scratch_root", ValueKind::Path);
    let sccache = a_decl("sccache_dir", ValueKind::Path);

    let values = resolve(
        vec![scratch, sccache],
        &[
            answer("scratch_root", "/var/mnt/scratch/one"),
            answer("sccache_dir", "{{scratch_root}}/sccache"),
        ],
    )
    .unwrap();

    assert_eq!(
        values.get("sccache_dir").unwrap().text,
        "/var/mnt/scratch/one/sccache"
    );
}

#[test]
fn unset_names_come_back_in_declaration_order() {
    let mut first = a_decl("git_name", ValueKind::String);
    first.required = true;
    let mut second = a_decl("git_email", ValueKind::Email);
    second.required = true;
    let values = resolve(vec![first, second], &[]).unwrap();

    // Referenced in the opposite order to the one they were declared in.
    let error = values.substitute("{{git_email}} {{git_name}}").unwrap_err();

    assert_eq!(
        error,
        Unresolved::Unset {
            names: vec!["git_name".to_string(), "git_email".to_string()]
        },
        "two reports of one problem have to read the same way"
    );
}

#[test]
fn placeholders_lists_names_in_order_of_first_appearance() {
    assert_eq!(
        placeholders("{{b}} {{a}} {{b}}").unwrap(),
        ["b", "a"],
        "deduplicated, and in the order they appear"
    );
    assert_eq!(placeholders("none here").unwrap(), Vec::<&str>::new());
    assert_eq!(placeholders("{{{{a}}").unwrap(), Vec::<&str>::new());
    let refused = placeholders("{{A}}");
    assert!(matches!(refused, Err(PlaceholderError::IllegalName { .. })));
}

#[test]
fn init_hint_names_the_values_and_spells_bx_init() {
    // One function spells the invocation, so there is one string to change
    // when `bx init --set` lands.
    assert_eq!(
        init_hint(&["scratch_root", "git_email"]),
        "run `bx init` to set scratch_root, git_email"
    );
    assert!(init_hint(&[]).contains("bx init"));
    assert_eq!(set_flag("scratch_root"), "--set scratch_root=VALUE");
}

// --- the two validation paths are one behaviour -------------------------

/// The scratch root every brace-bearing case below references.
const SCRATCH: &str = "/var/mnt/scratch/one";

/// A two-value configuration: an answered `scratch_root`, then `v`.
///
/// `v` is deliberately left unanswered, so the same fixture serves both the
/// prompt path — which validates an answer that is not in the file yet — and
/// the load path, which supplies one.
fn a_prompt(kind: ValueKind) -> ResolvedValues {
    ResolvedValues::resolve(
        vec![a_decl("scratch_root", ValueKind::Path), a_decl("v", kind)],
        &[answer("scratch_root", SCRATCH)],
        &a_home(),
    )
    .expect("the fixture resolves")
}

/// What `bx init` would accept `answer_text` as, for a `v` of `kind`.
fn through_a_prompt(kind: ValueKind, answer_text: &str) -> Result<String, String> {
    a_prompt(kind)
        .check_answer("v", answer_text)
        .map_err(|e| e.to_string())
}

/// What a `local.toml` line answering `v` resolves to.
fn through_the_loader(kind: ValueKind, answer_text: &str) -> Result<String, String> {
    let values = resolve(
        vec![a_decl("scratch_root", ValueKind::Path), a_decl("v", kind)],
        &[answer("scratch_root", SCRATCH), answer("v", answer_text)],
    )?;
    values
        .get("v")
        .map(|value| value.text.clone())
        .ok_or_else(|| values.invalid_hint(&["v".to_string()]))
}

/// Every kind, with an answer it accepts and one it does not.
///
/// The brace-bearing rows are the ones that matter: an answer is resolved as
/// *expand, then check*, and a validator that did only half of that accepted
/// `Someone {{Nested}}` and rejected `{{scratch_root}}/sccache`.
const KIND_CASES: [(ValueKind, &str, Option<&str>); 9] = [
    (ValueKind::Path, "~/scratch/./one", Some("relative/path")),
    (ValueKind::String, "anything at all", None),
    (ValueKind::Bool, "TRUE", Some("yes")),
    (ValueKind::Email, "someone@example.invalid", Some("someone")),
    (
        ValueKind::SshKey,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample",
        Some("not-a-key"),
    ),
    (
        ValueKind::AgeRecipient,
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
        Some("age1BAD"),
    ),
    // A brace pair a person typed into a prompt, escaped, and one that is
    // not a value name.
    (
        ValueKind::String,
        "Someone {{{{Nested}}",
        Some("Someone {{Nested}}"),
    ),
    // A reference to an earlier value, and one that never closes.
    (
        ValueKind::Path,
        "{{scratch_root}}/sccache",
        Some("{{scratch_root/sccache"),
    ),
    // A reference to a value no layer declares is a repo defect either way.
    (ValueKind::String, "{{{{scratch_root}}", Some("{{nowhere}}")),
];

#[test]
fn a_prompt_accepts_what_the_loader_accepts() {
    // `bx init` validating a typed answer and bx validating a `local.toml`
    // line are one behaviour, not two that happen to agree.
    for (kind, good, _) in KIND_CASES {
        let prompted = through_a_prompt(kind, good).unwrap_or_else(|e| panic!("{kind}: {e}"));
        let loaded = through_the_loader(kind, good).unwrap_or_else(|e| panic!("{kind}: {e}"));
        assert_eq!(
            prompted, loaded,
            "{kind} disagreed about the canonical text for {good:?}"
        );
    }
}

#[test]
fn a_prompt_rejects_what_the_loader_rejects() {
    for (kind, _, bad) in KIND_CASES {
        let Some(bad) = bad else {
            continue; // every string is a string; there is nothing to reject
        };
        assert!(
            through_a_prompt(kind, bad).is_err(),
            "{kind} accepted {bad:?} at a prompt"
        );
        assert!(
            through_the_loader(kind, bad).is_err(),
            "{kind} accepted {bad:?} from a file"
        );
    }
}

#[test]
fn a_prompt_expands_a_reference_to_an_earlier_value() {
    // The spelling the design documents as valid, and the one a check
    // without the expansion refused outright.
    assert_eq!(
        through_a_prompt(ValueKind::Path, "{{scratch_root}}/sccache").unwrap(),
        "/var/mnt/scratch/one/sccache"
    );
}

#[test]
fn a_prompt_refuses_a_brace_pair_that_is_not_a_reference() {
    // `bx init` has no escaping step, so an answer it accepts is written to
    // `local.toml` verbatim. Accepting this would make every later `bx plan`
    // and `bx apply` fail at load, which is not the blocked-target
    // degradation an unanswered value gets.
    let message = through_a_prompt(ValueKind::String, "Someone {{Nested}}").unwrap_err();

    assert!(message.contains("is not a value name"), "{message}");
}

#[test]
fn a_prompt_refuses_a_reference_to_a_later_value() {
    // Resolution is one pass in declaration order, so an answer may only
    // reach backwards — the same rule the loader applies to a `default`.
    let values = ResolvedValues::resolve(
        vec![
            a_decl("v", ValueKind::Path),
            a_decl("later", ValueKind::Path),
        ],
        &[],
        &a_home(),
    )
    .unwrap();

    let message = values
        .check_answer("v", "{{later}}/x")
        .unwrap_err()
        .to_string();

    assert!(message.contains("is declared later"), "{message}");
}

#[test]
fn a_prompt_refuses_an_answer_that_references_its_own_value() {
    // A self reference is the shortest cycle, and the loader refuses it as
    // a forward reference because a value is not resolvable from its own
    // position. The prompt has to refuse it the same way, whether or not the
    // value already has an answer to read back.
    let unanswered = a_prompt(ValueKind::String);
    let answered = resolve(
        vec![
            a_decl("scratch_root", ValueKind::Path),
            a_decl("v", ValueKind::String),
        ],
        &[answer("scratch_root", SCRATCH), answer("v", "earlier")],
    )
    .unwrap();

    for values in [&unanswered, &answered] {
        assert_eq!(
            values.check_answer("v", "{{v}}"),
            Err(AnswerError::Reference(Unresolved::Forward("v".to_string())))
        );
        assert_eq!(
            values.check_answer("v", "again {{v}}/x"),
            Err(AnswerError::Reference(Unresolved::Forward("v".to_string())))
        );
    }

    let loaded = through_the_loader(ValueKind::String, "{{v}}")
        .expect_err("the loader refuses a self reference");
    assert!(loaded.contains("is declared later"), "{loaded}");
    assert!(loaded.contains("local.toml:2"), "{loaded}");
}

#[test]
fn a_prompt_for_an_undeclared_value_says_so() {
    let message = through_a_prompt(ValueKind::String, "anything");
    assert!(message.is_ok(), "the fixture declares `v`");

    let message = a_prompt(ValueKind::String)
        .check_answer("nowhere", "anything")
        .unwrap_err()
        .to_string();

    assert!(
        message.contains("no layer declares the value `nowhere`"),
        "{message}"
    );
}

#[test]
fn a_prompt_for_a_switched_off_value_says_so() {
    // A declaration a layer switched off is not one of this account's
    // values: the loader never reads an answer for it, so a prompt that
    // accepted one would write a line that does nothing.
    let mut scratch = a_decl("scratch", ValueKind::Path);
    scratch.enabled = false;
    let values = ResolvedValues::resolve(vec![scratch], &[], &a_home()).unwrap();

    assert_eq!(
        values.check_answer("scratch", "/var/mnt/other"),
        Err(AnswerError::Reference(Unresolved::Disabled {
            names: vec!["scratch".to_string()]
        })),
        "switched off, which is cleared by a different act than undeclared"
    );
}

#[test]
fn a_prompt_reports_an_earlier_value_that_needs_answering_first() {
    // Not an invalid answer: the name the account has to supply before this
    // one can be validated at all.
    let values = ResolvedValues::resolve(
        vec![
            a_decl("scratch_root", ValueKind::Path),
            a_decl("v", ValueKind::Path),
        ],
        &[],
        &a_home(),
    )
    .unwrap();

    assert_eq!(
        values.check_answer("v", "{{scratch_root}}/sccache"),
        Err(AnswerError::Reference(Unresolved::Unset {
            names: vec!["scratch_root".to_string()]
        }))
    );
}

/// A value name is `[a-z][a-z0-9_]*`, in a declaration and in `[values]`.
///
/// `""`, `"a b"` and `"{{x}}"` all parsed as declaration names. One name is
/// written three ways, as a `[values]` bare key, inside a `{{name}}`
/// reference and as a `bx init` prompt label, and a name that needs quoting
/// in any of them, or carries the substitution braces itself, can never be
/// referenced.
#[test]
fn a_value_name_must_be_an_identifier() {
    for bad in [
        "",
        "a b",
        "{{x}}",
        "A",
        "1st",
        "_x",
        "git-email",
        "a.b",
        "é",
        "a\\tb",
    ] {
        let text = format!("[[value]]\nname = \"{bad}\"\nkind = \"string\"\n");
        let declared = message(decl(&text));
        assert!(
            declared.contains("is not a value name"),
            "{bad:?}: {declared}"
        );
        assert!(declared.contains("bx.toml:2"), "{bad:?}: {declared}");

        let text = format!("[values]\n\"{bad}\" = \"x\"\n");
        let assigned = message(assignments(&text));
        assert!(
            assigned.contains("is not a value name"),
            "[values] {bad:?}: {assigned}"
        );
    }
    for good in ["a", "git_email", "scratch_root2", "a_1_b"] {
        let text = format!("[[value]]\nname = \"{good}\"\nkind = \"string\"\n");
        assert_eq!(decl(&text).unwrap().name, good);
        let text = format!("[values]\n{good} = true\n");
        assert_eq!(assignments(&text).unwrap()[0].name, good);
    }
}

/// `is_root` is only legal on a path.
///
/// `is_root = true` on `kind = "bool"` parsed. The flag admits a directory
/// into the env_guard root set, so on any other kind it would widen the
/// guard on the strength of a value that is not a directory.
#[test]
fn is_root_is_only_legal_on_a_path() {
    for kind in ["string", "bool", "email", "ssh-key", "age-recipient"] {
        let text = format!("[[value]]\nname = \"v\"\nkind = \"{kind}\"\nis_root = true\n");
        let message = message(decl(&text));
        assert!(
            message.contains("only legal on `kind = \"path\"`"),
            "{kind}: {message}"
        );
        assert!(message.contains("bx.toml:4"), "{kind}: {message}");

        // `false` claims nothing, so it is allowed on every kind.
        let text = format!("[[value]]\nname = \"v\"\nkind = \"{kind}\"\nis_root = false\n");
        assert!(!decl(&text).unwrap().is_root, "{kind}");
    }
    let text = "[[value]]\nname = \"v\"\nkind = \"path\"\nis_root = true\n";
    assert!(decl(text).unwrap().is_root);
}
