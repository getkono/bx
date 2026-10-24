//! The sites outside this module that reach the guard, read from the source:
//! a census that fails when one appears or disappears.

/// `text` with its comments removed, line by line, carrying block state.
///
/// Written because a `//`-prefix test is not comment handling: round 5
/// found that the tripwire below both **missed** a caller after a block
/// comment opened and **false-positived** on the module's name inside one.
/// That is the same blind spot the `Reason` census had, reappearing in the
/// round's other new mechanism — so it is fixed the same way, with a test
/// that fails when it is removed.
///
/// It skips string literals — escaped, raw, byte and spanning lines — and
/// char literals, keeping their text as code, so a `//` or `/*` inside one
/// is not a comment. Issue #235: an earlier version did not, and the `/*`
/// in a string spelling `config.d/*.conf` opened a block comment that never
/// closed, so the rest of `config/target.rs` went unscanned and a site
/// naming the guard there was never read. A `/*` carries over lines, so not
/// knowing strings was never a safe direction.
///
/// **What it does not do:** it does not nest block comments, as Rust does,
/// so `/* a /* b */ c */` leaves ` c */` as code. That direction is safe
/// here: it can only expose text, which reports a caller rather than hiding
/// one.
fn code_only(text: &str) -> Vec<(usize, String)> {
    /// What the scan is inside of, carried from one line to the next.
    #[derive(Clone, Copy)]
    enum Lex {
        Code,
        Block,
        Str,
        /// A raw string, closed by `"` and this many `#`.
        Raw(usize),
    }
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    let mut state = Lex::Code;
    for (idx, raw) in text.lines().enumerate() {
        let chars: Vec<char> = raw.chars().collect();
        let at = |i: usize| chars.get(i).copied();
        let mut code = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            match state {
                Lex::Block => {
                    if c == '*' && at(i + 1) == Some('/') {
                        state = Lex::Code;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                Lex::Str => {
                    code.push(c);
                    if c == '\\' {
                        code.extend(at(i + 1));
                        i += 2;
                        continue;
                    }
                    if c == '"' {
                        state = Lex::Code;
                    }
                    i += 1;
                }
                Lex::Raw(hashes) => {
                    code.push(c);
                    i += 1;
                    if c == '"' && (i..i + hashes).all(|j| at(j) == Some('#')) {
                        code.extend(&chars[i..i + hashes]);
                        i += hashes;
                        state = Lex::Code;
                    }
                }
                Lex::Code => {
                    let next = at(i + 1);
                    if c == '/' && next == Some('/') {
                        break;
                    }
                    if c == '/' && next == Some('*') {
                        state = Lex::Block;
                        i += 2;
                        continue;
                    }
                    code.push(c);
                    i += 1;
                    if c == '"' {
                        state = Lex::Str;
                    } else if c == 'r' && (i < 2 || !ident(chars[i - 2]) || chars[i - 2] == 'b') {
                        // `r"…"`, `r#"…"#` and `br…`: a raw string only
                        // where the `r` starts a token, not ends a name.
                        let hashes = chars[i..].iter().take_while(|&&h| h == '#').count();
                        let starts_token =
                            i < 2 || chars[i - 2] != 'b' || i < 3 || !ident(chars[i - 3]);
                        if starts_token && at(i + hashes) == Some('"') {
                            code.extend(&chars[i..=i + hashes]);
                            i += hashes + 1;
                            state = Lex::Raw(hashes);
                        }
                    } else if c == '\'' {
                        // `'\''`, `'\n'` and `'\u{…}'` run to the next
                        // quote past their escape; `'x'` is three
                        // characters; anything else is a lifetime or a
                        // label, which has no closing quote.
                        let end = if next == Some('\\') {
                            (i + 2..chars.len()).find(|&j| chars[j] == '\'')
                        } else if at(i + 1) == Some('\'') {
                            Some(i + 1)
                        } else {
                            None
                        };
                        if let Some(end) = end {
                            code.extend(&chars[i..=end]);
                            i = end + 1;
                        }
                    }
                }
            }
        }
        out.push((idx + 1, code));
    }
    out
}

#[test]
fn comments_are_stripped_however_they_are_written() {
    let stripped = |text: &str| {
        code_only(text)
            .into_iter()
            .map(|(_, code)| code.trim().to_string())
            .collect::<Vec<_>>()
    };
    // A line comment, a doc comment, a block comment on one line, and a
    // block comment spanning lines — including code that resumes after it
    // closes, which a `//`-prefix test loses entirely.
    assert_eq!(stripped("let a = 1; // note"), vec!["let a = 1;"]);
    assert_eq!(stripped("/// doc"), vec![""]);
    assert_eq!(stripped("let a = /* x */ 1;"), vec!["let a =  1;"]);
    assert_eq!(
        stripped("/* open\nstill\n*/ let a = 1;"),
        vec!["", "", "let a = 1;"]
    );
    // The name of this module inside a block comment is prose; a call
    // after that block closes is not.
    assert_eq!(stripped("/* env_guard */"), vec![""]);
    assert_eq!(
        stripped("/* env_guard\n*/ env_guard::scan(\"\");"),
        vec!["", "env_guard::scan(\"\");"]
    );
    // Issue #235: a `/*` or `//` inside a string or char literal opens no
    // comment, so the code after it — on its own line or the next — is
    // still read. Escaped quotes, raw and multi-line strings, and a quote
    // as a char do not end or open a string early; a lifetime is not a
    // char.
    assert_eq!(
        stripped("let a = \"a/*b\";\nenv_guard::scan(\"\");"),
        vec!["let a = \"a/*b\";", "env_guard::scan(\"\");"]
    );
    assert_eq!(
        stripped("f(\"//\", env_guard::x); // note"),
        vec!["f(\"//\", env_guard::x);"]
    );
    assert_eq!(
        stripped("let a = \"\\\"/*\"; b // c"),
        vec!["let a = \"\\\"/*\"; b"]
    );
    assert_eq!(
        stripped("let a = r#\"\"/*\"#; b // c"),
        vec!["let a = r#\"\"/*\"#; b"]
    );
    assert_eq!(
        stripped("let a = br\"/*\"; b // c"),
        vec!["let a = br\"/*\"; b"]
    );
    assert_eq!(
        stripped("let a = \"one\n/* two\n\"; b // c"),
        vec!["let a = \"one", "/* two", "\"; b"]
    );
    assert_eq!(
        stripped("let q = '\"'; let e = '\\''; b // c"),
        vec!["let q = '\"'; let e = '\\''; b"]
    );
    assert_eq!(
        stripped("fn f<'a>(x: &'a str) -> char { 'x' } // c"),
        vec!["fn f<'a>(x: &'a str) -> char { 'x' }"]
    );
    // A name ending in `r` before a string is not a raw string's prefix.
    assert_eq!(stripped("bar(\"/*\"); b // c"), vec!["bar(\"/*\"); b"]);
}

/// Whether `code` names this module in a position a Rust path can use.
///
/// `env_guard::…`, `use …env_guard;`, `use …env_guard as g;` and
/// `use …{env_guard, …}` — every way a path reaches in, the alias round-5
/// note D1 found included. A bare mention in prose is not one of them, and
/// matching bare names reported a diagnostic string in `config::values` as
/// a caller.
fn names_the_guard(code: &str) -> bool {
    let mut rest = code;
    while let Some(at) = rest.find("env_guard") {
        let after = &rest[at + "env_guard".len()..];
        if after.starts_with([':', ';', ',', '}']) || after.trim_start().starts_with("as ") {
            return true;
        }
        rest = after;
    }
    false
}

#[test]
fn the_guard_is_named_in_path_position_and_not_in_prose() {
    for path in [
        "crate::env_guard::scan(\"\")",
        "use crate::env_guard;",
        "use crate::env_guard as guard;",
        "use crate::{env_guard, paths};",
        "use crate::{paths, env_guard};",
    ] {
        assert!(names_the_guard(path), "{path:?}");
    }
    for prose in [
        "declares a directory the env_guard root set admits",
        "pub mod env_guard",
        "env_guard enforces invariant 2",
    ] {
        assert!(!names_the_guard(prose), "{prose:?}");
    }
}

#[test]
fn every_site_that_reaches_the_guard_is_known() {
    // Generated environment fragments reach the guard through the plan,
    // and through nothing else: **every site outside this module that
    // names the guard is one of `KNOWN`** — the plan's two fragment
    // judgements, one per syntax, the note they share, its type imports,
    // `bx add`'s advisory scan, and a test that reads a `Reason`'s text. A
    // new site fails here, and so does a known one that is gone, so the
    // list cannot rot, and a second route from a generated body to bytes
    // cannot open without being read. The interactive file's `env` phase
    // reaches the zsh judgement too, carrying the count of lines above it
    // so a note names the file's own line.
    //
    // Until `config::target::Gen` had a variant this test held a second
    // fact — that no generated fragment reached the guard at all — which
    // capped the open `Kind::Anchor` exemption at zero impact. The change
    // that gave `Gen` its variants closed the exemption for an exported
    // anchor first, so that fact no longer caps anything and is not held.
    //
    // Round-4 note COV3: that was prose, and prose is the same shape as
    // the premise the exemption itself is criticised for. Round-5 note D1:
    // the first version searched for `env_guard::` after a `//` test, so
    // `use crate::env_guard as guard;` followed by `guard::scan("")` — a
    // real caller — passed it. It searches for the module's *name* now, in
    // comment-free code, which catches the alias at its `use` line.
    //
    // **What it catches:** the module's name in *path position* in
    // comment-free code — `env_guard::`, `use …env_guard;`,
    // `use …env_guard as g;`, `use …{env_guard, …}`. Those are the forms
    // by which a Rust path can reach into this module, alias included.
    // **What it does not:** a caller that never names the module, which no
    // Rust path can manage. `pub mod env_guard;` is the declaration rather
    // than a way in, and is the one allowed form.
    //
    // Path position, not the bare name, because the bare name appears in
    // prose this test must not fire on — `src/config/values.rs` quotes
    // "the env_guard root set" inside a user-facing diagnostic, and a
    // bare-name search reports it as a caller.
    //
    // `adopt.rs` scans a file the *user* wrote, at `bx add`, and only to
    // print a warning: the file is adopted verbatim whatever the verdict,
    // and the scan's text is never generated. So no generated fragment
    // reaches the guard through it.
    //
    // `shell/activation.rs` judges a tool's cached activation output,
    // which is the tool's own shell code rather than an environment
    // fragment: it searches the output for every name `is_relocating`
    // knows, passes each readable assignment of one through `check`, the
    // function `scan_with` calls per assignment, refuses every other
    // assigning form, and never writes an output with any refusal.
    //
    // A site is matched by its code alone, not by the file it sits in, so
    // splitting a module moves a known site without failing here. `KNOWN`
    // is a multiset: each entry is claimed by one site, so a line repeated
    // into a further file is a new caller, as it was when sites were
    // matched by file. "This module" is the `env_guard` module wherever
    // its files are — `env_guard.rs` and everything beneath `env_guard/`.
    //
    // **A site is its whole line, arguments included, on purpose** (issue
    // #308). Matching the call's shape — the path it names — would let a
    // known site change what it hands the guard, `scan_with(content, …)`
    // becoming `scan_with("", …)`, and still be claimed. A rename or a
    // rustfmt reflow fails here instead; that failure is closed, names the
    // lines, and costs one edit to `KNOWN`.
    const KNOWN: [&str; 20] = [
        // `bx add`'s advisory scan.
        "use crate::env_guard::{self, Reason, RootSet};",
        "env_guard::scan_with(text, roots)",
        // The plan's fragment judgements. The `zprofile` fragment on macOS
        // is judged read after the variables it inherits, and only its own
        // lines' violations are kept.
        "use crate::env_guard::{self, RootSet};",
        "violations(&env_guard::scan_with(content, roots), before)",
        "let mut found = env_guard::scan_with(&format!(\"{inherited}{content}\"), roots);",
        "violations(&env_guard::scan_exported(content, roots), 0)",
        // The LaunchAgent on macOS: its `environment.d` fragment judged by
        // `scan_exported`, and every value it holds expanded, refused where
        // it does not expand; the property list renders the values the
        // same walk expanded, against a root set built for its home alone.
        "let found = env_guard::scan_exported(env, roots);",
        "let unexpanded = env_guard::expand_exported(env, roots)",
        "let roots = crate::env_guard::RootSet::new(&self.home, &[]);",
        "crate::env_guard::expand_exported(&self.env.render(decide), &roots)",
        "fn violations(found: &[env_guard::Violation], before: usize) -> Option<String> {",
        // The interactive file's history path, judged beside its `env`
        // phase, which still goes through `scan_with` above.
        "env_guard::refuses_bx_location(&path, roots)",
        // The root set's type, named where the plan's inputs hold it and
        // where a decision borrows it; neither judges anything.
        "use crate::env_guard::RootSet;",
        "use crate::env_guard::RootSet;",
        "let inside = crate::env_guard::Reason::InsideConfigRepo.to_string();",
        // Cached activation output: the name search, once over names as
        // written and once over names a quote or escape splits, and the
        // judgement of each assignment it finds.
        "use crate::env_guard::{self, Reason, RootSet, Verdict, Violation};",
        "if name.starts_with(|c: char| c.is_ascii_digit()) || !env_guard::is_relocating(&name) {",
        "if name.starts_with(|c: char| c.is_ascii_digit()) || !env_guard::is_relocating(&name) {",
        "Use::Assigns(value) => match env_guard::check(&name, &value, roots) {",
        // A `config::target` test hands the strict root set to
        // `activation::plan`, which judges through the `check` above; it
        // names the type and judges nothing itself. Unread until issue
        // #235, when a `/*` in a string above it hid it from this scan.
        "&crate::env_guard::RootSet::strict(),",
    ];
    let live = "A generated body reaches bytes through the plan's judgement of it, and a \
                    new route has to be read before it is trusted: check that it passes every \
                    environment fragment through `scan_with` or `scan_exported`, as its syntax \
                    exports, before adding it to `KNOWN`.";
    let src = crate::testing::src_root();
    let own = src.join("env_guard");
    let mut callers = Vec::new();
    let mut unclaimed: Vec<&str> = KNOWN.to_vec();
    for path in crate::testing::rust_sources(&src) {
        if path.with_extension("") == own || path.starts_with(&own) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a source file");
        for (line, code) in code_only(&text) {
            if code.trim() == "pub mod env_guard;" {
                continue;
            }
            if !names_the_guard(&code) {
                continue;
            }
            match unclaimed.iter().position(|known| *known == code.trim()) {
                Some(at) => {
                    unclaimed.remove(at);
                }
                None => callers.push(format!("{}:{line}", path.display())),
            }
        }
    }
    assert!(
        callers.is_empty(),
        "the guard has a new caller: {callers:?}. {live}"
    );
    let gone = unclaimed;
    assert!(
        gone.is_empty(),
        "a known site no longer names the guard: {gone:?}. Update `KNOWN`, and check the \
             route it took still passes a generated body through `guard_fragment`."
    );
}
