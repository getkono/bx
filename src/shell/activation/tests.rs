use super::*;
use crate::config::Origin;
use crate::config::activation::parse_activation;
use crate::config::shells::{Phase, Shells};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use toml_edit::Document;

/// Every `[[activation]]` entry in `text`, parsed.
fn parse(text: &str) -> Result<Vec<ActivationDecl>, String> {
    let doc = Document::parse(text).map_err(|e| format!("{e}"))?;
    let tables = doc
        .get("activation")
        .and_then(|item| item.as_array_of_tables())
        .ok_or("no [[activation]]")?;
    tables
        .iter()
        .map(|table| parse_activation(table, Path::new("/repo/bx.toml"), text))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())
}

fn decl(name: &str, command: &[&str]) -> ActivationDecl {
    ActivationDecl {
        name: name.to_string(),
        command: command.iter().map(ToString::to_string).collect(),
        zsh: None,
        bash: None,
        shells: Shells::EVERY,
        phase: Phase::Activations,
        enabled: true,
        origin: Origin {
            file: PathBuf::from("/repo/bx.toml"),
            line: 1,
        },
    }
}

/// What each run of each path prints, in order.
type Outputs = BTreeMap<PathBuf, VecDeque<Result<Vec<u8>, RunError>>>;

/// A machine whose tools, binaries and outputs a test decides, and which
/// counts every run.
#[derive(Default)]
struct Fake {
    /// Each tool's resolved path and binary content.
    tools: BTreeMap<String, (PathBuf, Vec<u8>)>,
    /// Tools found but not executable.
    inexecutable: Vec<String>,
    /// Tools whose binary cannot be read.
    unreadable: Vec<String>,
    /// What each run of a path prints, in order; the last one repeats.
    outputs: RefCell<Outputs>,
    /// Every run, in order.
    runs: RefCell<Vec<PathBuf>>,
    /// The `PATH` every run is given; empty unless a test sets it.
    path: OsString,
}

impl Fake {
    fn tool(mut self, name: &str, binary: &[u8], outputs: &[&str]) -> Self {
        let path = PathBuf::from(format!("/usr/bin/{name}"));
        self.tools
            .insert(name.to_string(), (path.clone(), binary.to_vec()));
        self.outputs.borrow_mut().insert(
            path,
            outputs.iter().map(|o| Ok(o.as_bytes().to_vec())).collect(),
        );
        self
    }

    fn failing(self, name: &str, error: RunError) -> Self {
        let fake = self.tool(name, b"bin", &[]);
        fake.outputs
            .borrow_mut()
            .get_mut(Path::new(&format!("/usr/bin/{name}")))
            .unwrap()
            .push_back(Err(error));
        fake
    }

    fn upgrade(&mut self, name: &str, binary: &[u8], outputs: &[&str]) {
        self.tools.get_mut(name).unwrap().1 = binary.to_vec();
        let path = self.tools[name].0.clone();
        self.outputs.borrow_mut().insert(
            path,
            outputs.iter().map(|o| Ok(o.as_bytes().to_vec())).collect(),
        );
    }

    fn runs(&self) -> usize {
        self.runs.borrow().len()
    }
}

impl Host for Fake {
    fn locate(&self, program: &str) -> Presence {
        if self.inexecutable.iter().any(|p| p == program) {
            return Presence::NotExecutable {
                path: PathBuf::from(format!("/usr/bin/{program}")),
            };
        }
        self.tools
            .get(program)
            .map_or(Presence::Missing, |(path, _)| Presence::Present {
                path: path.clone(),
            })
    }

    fn hash(&self, path: &Path) -> Result<ContentHash, String> {
        let (name, (_, content)) = self
            .tools
            .iter()
            .find(|(_, (p, _))| p == path)
            .expect("hashed a located path");
        if self.unreadable.contains(name) {
            return Err("permission denied".to_string());
        }
        Ok(ContentHash::of(content))
    }

    fn run(&self, program: &Path, _args: &[String]) -> Result<Vec<u8>, RunError> {
        self.runs.borrow_mut().push(program.to_path_buf());
        let mut outputs = self.outputs.borrow_mut();
        let queue = outputs.get_mut(program).expect("ran a known tool");
        if queue.len() > 1 {
            queue.pop_front().unwrap()
        } else {
            queue.front().cloned().expect("an output")
        }
    }

    fn path(&self) -> &OsStr {
        &self.path
    }
}

/// Plan, render and record, as `apply` does; the rendered file.
fn apply(decls: &[ActivationDecl], cache: &mut Fingerprints, host: &Fake) -> (Plan, String) {
    let plan = plan(decls, cache, &RootSet::strict(), host);
    let mut assembly = Assembly::new();
    contribute(&mut assembly, &plan.rendered(Shell::Zsh))
        .expect("activations never claim the terminal slot");
    plan.record(cache);
    (plan, assembly.render())
}

#[test]
fn an_activation_entry_parses_every_key() {
    let decls = parse(
        "[[activation]]\nname = \"starship\"\ncommand = [\"starship\", \"init\", \"zsh\"]\n\
             phase = \"completions\"\nenabled = false\n\
             [[activation]]\nname = \"brew\"\n\
             command = [\"/home/linuxbrew/.linuxbrew/bin/brew\", \"shellenv\"]\n",
    )
    .expect("parses");
    assert_eq!(
        decls,
        vec![
            ActivationDecl {
                name: "starship".to_string(),
                command: vec!["starship".into(), "init".into(), "zsh".into()],
                zsh: None,
                bash: None,
                shells: Shells::EVERY,
                phase: Phase::Completions,
                enabled: false,
                origin: Origin {
                    file: PathBuf::from("/repo/bx.toml"),
                    line: 1,
                },
            },
            ActivationDecl {
                name: "brew".to_string(),
                command: vec![
                    "/home/linuxbrew/.linuxbrew/bin/brew".into(),
                    "shellenv".into()
                ],
                zsh: None,
                bash: None,
                shells: Shells::EVERY,
                phase: Phase::Activations,
                enabled: true,
                origin: Origin {
                    file: PathBuf::from("/repo/bx.toml"),
                    line: 6,
                },
            },
        ]
    );
    assert_eq!(decls[0].key(), "activation:starship");
    assert_eq!(decls[0].key_for(Shell::Bash), "activation-bash:starship");
}

#[test]
fn each_shell_runs_its_own_command_and_none_runs_another_shell_s() {
    let decls = parse(
        "[[activation]]\nname = \"starship\"\ncommand = [\"starship\", \"init\", \"{shell}\"]\n\
             [[activation]]\nname = \"mise\"\ncommand = [\"mise\", \"activate\", \"zsh\"]\n\
             [[activation]]\nname = \"fzf\"\ncommand = [\"fzf\", \"--{shell}\"]\n\
             bash = [\"fzf\", \"--bash\", \"--no-extra\"]\n\
             [[activation]]\nname = \"zonly\"\ncommand = [\"z\", \"{shell}\"]\nshells = [\"zsh\"]\n\
             [[activation]]\nname = \"bonly\"\nbash = [\"b\", \"init\"]\n",
    )
    .expect("parses");
    let commands = |shell| -> Vec<Option<String>> {
        decls
            .iter()
            .map(|decl| decl.command_for(shell).map(|c| c.join(" ")))
            .collect()
    };
    assert_eq!(
        commands(Shell::Zsh),
        [
            Some("starship init zsh".to_string()),
            Some("mise activate zsh".to_string()),
            Some("fzf --zsh".to_string()),
            Some("z zsh".to_string()),
            None,
        ]
    );
    assert_eq!(
        commands(Shell::Bash),
        [
            Some("starship init bash".to_string()),
            None,
            Some("fzf --bash --no-extra".to_string()),
            None,
            Some("b init".to_string()),
        ]
    );

    // Each shell's step is decided, cached and rendered on its own.
    let host = Fake::default()
        .tool("starship", b"s", &["starship_hook\n"])
        .tool("mise", b"m", &["mise_hook\n"])
        .tool("fzf", b"f", &["fzf_hook\n"])
        .tool("z", b"z", &["z_hook\n"])
        .tool("b", b"b", &["b_hook\n"]);
    let mut cache = Fingerprints::default();
    let decided = plan(&decls, &cache, &RootSet::strict(), &host);
    let steps: Vec<(String, Shell)> = decided
        .steps()
        .iter()
        .map(|step| (step.decl.name.clone(), step.shell))
        .collect();
    assert_eq!(
        steps,
        [
            ("starship".to_string(), Shell::Zsh),
            ("starship".to_string(), Shell::Bash),
            ("mise".to_string(), Shell::Zsh),
            ("fzf".to_string(), Shell::Zsh),
            ("fzf".to_string(), Shell::Bash),
            ("zonly".to_string(), Shell::Zsh),
            ("bonly".to_string(), Shell::Bash),
        ]
    );
    assert_eq!(
        decided.steps()[1].line(),
        "+ activation `starship` for bash: run twice, output agreed; cached"
    );
    let mut bash = Assembly::new();
    contribute(&mut bash, &decided.rendered(Shell::Bash)).expect("contributes");
    let bash = bash.render();
    for name in ["starship", "fzf", "bonly"] {
        assert!(
            bash.contains(&format!("# bx activation: {name}\n")),
            "{bash}"
        );
    }
    for name in ["mise", "zonly"] {
        assert!(
            !bash.contains(&format!("# bx activation: {name}\n")),
            "{bash}"
        );
    }
    assert!(!decided.rendered(Shell::Bash).is_empty() && !decided.rendered(Shell::Zsh).is_empty());
    decided.record(&mut cache);
    let mut keys: Vec<&String> = cache.iter().map(|(key, _)| key).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "activation-bash:bonly",
            "activation-bash:fzf",
            "activation-bash:starship",
            "activation:fzf",
            "activation:mise",
            "activation:starship",
            "activation:zonly",
        ]
    );
    // A second plan reuses every entry, for both shells, and runs nothing.
    let runs = host.runs();
    let again = plan(&decls, &cache, &RootSet::strict(), &host);
    assert_eq!(host.runs(), runs);
    assert!(
        again
            .steps()
            .iter()
            .all(|step| step.action() == Action::Unchanged)
    );
    // Dropping bash forgets bash's entries alone.
    let zsh_only: Vec<ActivationDecl> = decls
        .iter()
        .cloned()
        .map(|decl| ActivationDecl {
            shells: Shells::only(Shell::Zsh),
            bash: None,
            ..decl
        })
        .collect();
    plan(&zsh_only, &cache, &RootSet::strict(), &host).record(&mut cache);
    assert!(
        cache.iter().all(|(key, _)| key.starts_with(KEY_PREFIX)),
        "{:?}",
        cache.iter().map(|(key, _)| key).collect::<Vec<_>>()
    );
}

#[test]
fn a_malformed_entry_is_refused_naming_its_key() {
    for (body, needle) in [
        ("command = [\"a\"]\n", "`name`"),
        ("name = \"a\"\n", "`command`"),
        ("name = \"\"\ncommand = [\"a\"]\n", "not an activation name"),
        (
            "name = \"a\\nb\"\ncommand = [\"a\"]\n",
            "not an activation name",
        ),
        ("name = \"a\"\ncommand = []\n", "is empty"),
        ("name = \"a\"\ncommand = \"a\"\n", "an array of strings"),
        ("name = \"a\"\ncommand = [1]\n", "an array of strings"),
        (
            "name = \"a\"\ncommand = [\"a b\"]\n",
            "must be a program name",
        ),
        ("name = \"a\"\ncommand = [\"\"]\n", "must be a program name"),
        (
            "name = \"a\"\ncommand = [\"-a\"]\n",
            "must be a program name",
        ),
        (
            "name = \"a\"\ncommand = [\"bin/a\"]\n",
            "must be a program name",
        ),
        (
            "name = \"a\"\ncommand = [\"a]\"]\n",
            "must be a program name",
        ),
        (
            "name = \"a\"\ncommand = [\"/\"]\n",
            "must be a program name",
        ),
        (
            "name = \"a\"\ncommand = [\"/a b\"]\n",
            "must be a program name",
        ),
        ("name = \"a\"\ncommand = [\"a\", \"x\\u0000\"]\n", "NUL"),
        (
            "name = \"a\"\ncommand = [\"{shell}\"]\n",
            "must be a program name",
        ),
        ("name = \"a\"\nbash = []\n", "is empty"),
        ("name = \"a\"\nzsh = [\"a b\"]\n", "must be a program name"),
        (
            "name = \"a\"\nbash = [\"a\"]\nshells = [\"zsh\"]\n",
            "keeps the activation out of bash",
        ),
        (
            "name = \"a\"\nzsh = [\"a\"]\nshells = [\"bash\"]\n",
            "keeps the activation out of zsh",
        ),
        (
            "name = \"a\"\ncommand = [\"a\"]\nshells = [\"fish\"]\n",
            "not a shell bx generates for",
        ),
        (
            "name = \"a\"\ncommand = [\"a\"]\nphase = \"terminal\"\n",
            "not a phase",
        ),
        ("name = \"a\"\ncommand = [\"a\"]\nphase = 1\n", "a string"),
        (
            "name = \"a\"\ncommand = [\"a\"]\nenabled = \"no\"\n",
            "a boolean",
        ),
        // The never-cacheable form is gone, and saying so is refused.
        (
            "name = \"a\"\ncommand = [\"a\"]\ncache = false\n",
            "unknown key `cache`",
        ),
    ] {
        let err = parse(&format!("[[activation]]\n{body}")).expect_err(body);
        assert!(err.contains(needle), "{body}: {err}");
    }
}

#[test]
fn every_assignment_to_a_relocating_variable_is_judged_by_the_guard() {
    use Reason::{NoRootsDeclared, NotEmittable, Unreadable};
    /// One refusal: its line, the variable it names, and why.
    type Refusal = (usize, &'static str, Reason);
    let strict = RootSet::strict();
    // (output, every refusal it holds).
    let cases: &[(&str, &[Refusal])] = &[
        // A tool's own variables, functions and constructs pass untouched,
        // however they assign: none of them relocates anything.
        (
            "export STARSHIP_SHELL=zsh\nexport MISE_SHELL=zsh\nlocal ret=1\n",
            &[],
        ),
        ("x=$(Y=1 cmd)\nX+=1\nX=(a b)\nread X\n", &[]),
        ("eval \"$(mise hook-env -s zsh)\"\n", &[]),
        (
            "(( X = 1 ))\nfor (( i = 0; i < 2; i++ )); do :; done\n",
            &[],
        ),
        ("cat <<EOF\nX=1\nEOF\necho 'unclosed\n", &[]),
        // Review item D6: `&&` inside `[[ … ]]` with a comparison after it.
        (
            "if [[ \"$a\" == \"b\" && \"$c\" != \"d\" ]]; then :; fi\n",
            &[],
        ),
        // A relocating name that is read, or is only text, passes.
        ("export PATH=\"$XDG_DATA_HOME/bin:$PATH\"\n", &[]),
        (
            "echo ${XDG_CACHE_HOME:-~/.cache} ${#CARGO_HOME} ${(j: :)CARGO_HOME}\n",
            &[],
        ),
        ("echo ${CARGO_HOME[1]} ${CARGO_HOME:+x}\n", &[]),
        ("[[ $x == CARGO_HOME || $CARGO_HOME == /x ]]\n", &[]),
        ("  # export CARGO_HOME=/x\n", &[]),
        ("unset XDG_CONFIG_HOME\n", &[]),
        ("'--cache-dir=[Path]:CACHE_DIR:_files -/' \\\n", &[]),
        ("MY_CARGO_HOME=/x\nCARGO_HOMES=/x\n1CARGO_HOME=/x\n", &[]),
        // A readable value is judged for what the name holds.
        (
            "export CARGO_HOME=/tmp/cargo\n",
            &[(1, "CARGO_HOME", NoRootsDeclared)],
        ),
        (
            "f() {\n  local XDG_CONFIG_HOME=/x\n}\n",
            &[(2, "XDG_CONFIG_HOME", NotEmittable)],
        ),
        (
            "CARGO_HOME=/tmp/c cargo build\n",
            &[(1, "CARGO_HOME", NoRootsDeclared)],
        ),
        (
            "true && XDG_CONFIG_HOME='/x'; _ZO_DATA_DIR=/y\n",
            &[
                (1, "XDG_CONFIG_HOME", NotEmittable),
                (1, "_ZO_DATA_DIR", NotEmittable),
            ],
        ),
        // Every other form that assigns, or may, is refused.
        ("CARGO_HOME+=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("CARGO_HOME[1]=x\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("CARGO_HOME[1\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("CARGO_HOME=(a b)\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("CARGO_HOME=\"unclosed\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("CARGO_HOME='unclosed\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("eval CARGO_HOME\\=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("export CARGO_HOME\n", &[(1, "CARGO_HOME", Unreadable)]),
        (
            "export \\\n  CARGO_HOME\n",
            &[(2, "CARGO_HOME", Unreadable)],
        ),
        (
            "\\typeset -gx CARGO_HOME\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "read -r XDG_CONFIG_HOME\n",
            &[(1, "XDG_CONFIG_HOME", Unreadable)],
        ),
        ("print -v CARGO_HOME x\n", &[(1, "CARGO_HOME", Unreadable)]),
        (
            "x=1 builtin export CARGO_HOME\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "if export CARGO_HOME; then :; fi\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "local x=$(y) CARGO_HOME\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "case $a in b) export CARGO_HOME ;; esac\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        ("$(export CARGO_HOME)\n", &[(1, "CARGO_HOME", Unreadable)]),
        (
            "x=\"a b\" y='c \"d' export CARGO_HOME\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        ("x=\"a b\" echo CARGO_HOME\n", &[]),
        // An escaped edge is text, so the command word is before it.
        ("_arguments 'a \\`for\\` b:CACHE_DIR:'\n", &[]),
        ("echo `for` CACHE_DIR\n", &[]),
        (
            "echo a; for CACHE_DIR in x; do :; done\n",
            &[(1, "CACHE_DIR", Unreadable)],
        ),
        (
            "for CARGO_HOME in a; do :; done\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        ("eval 'CARGO_HOME=/x'\n", &[(1, "CARGO_HOME", Unreadable)]),
        (
            "alias c='CARGO_HOME=/x cargo'\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "typeset -n r=CARGO_HOME\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        ("v='CARGO_HOME'\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("v=(a CARGO_HOME)\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("echo ${CARGO_HOME:=/x}\n", &[(1, "CARGO_HOME", Unreadable)]),
        (
            "echo ${(L)CARGO_HOME=/x}\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "echo ${CARGO_HOME::=/x}\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        ("(( CARGO_HOME = 1 ))\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("(( CARGO_HOME <<= 1 ))\n", &[(1, "CARGO_HOME", Unreadable)]),
        (
            "echo $(( CARGO_HOME++ ))\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        ("(( ++CARGO_HOME ))\n", &[(1, "CARGO_HOME", Unreadable)]),
        // Review item D7: a relocating name assembled from quoted or
        // escaped pieces is the name once quotes are removed, so it is
        // refused wherever it stands.
        ("export 'CARGO'_HOME=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
        ("export CARGO\\_HOME=/x\n", &[(1, "CARGO_HOME", Unreadable)]),
        (
            "typeset -gx CARGO\"\"_HOME=/x\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "export $'CARGO'_HOME=/x\n",
            &[(1, "CARGO_HOME", Unreadable)],
        ),
        (
            "x=1\nC\"ARGO_HO\"ME=/x; echo 'XDG'\"_CONFIG_HOME\"\n",
            &[
                (2, "CARGO_HOME", Unreadable),
                (2, "XDG_CONFIG_HOME", Unreadable),
            ],
        ),
        // Quotes that only surround the name, an expansion joined to
        // text, a comment, and pieces that spell no relocating name pass.
        ("echo \"CARGO_HOME\" 'CARGO_HOME'\n", &[]),
        ("echo \"$CARGO\"_HOME ${CARGO}'_HOME'\n", &[]),
        ("# export 'CARGO'_HOME=/x\n", &[]),
        ("echo 'MY'_CARGO_HOME CARGO\\_HOMES '1'CARGO_HOME\n", &[]),
    ];
    for (output, expected) in cases {
        let found: Vec<(usize, String, Reason)> = relocations(output, &strict)
            .into_iter()
            .map(|v| (v.line, v.name, v.reason))
            .collect();
        let expected: Vec<(usize, String, Reason)> = expected
            .iter()
            .map(|(line, name, reason)| (*line, (*name).to_string(), *reason))
            .collect();
        assert_eq!(found, expected, "{output:?}");
    }

    // An unreadable refusal quotes its line.
    let quoted = relocations("true\n  export CARGO_HOME\n", &strict);
    assert_eq!(quoted[0].value, "export CARGO_HOME");
    // A judged value is the whole word, a space inside its quotes included.
    let values: Vec<String> = relocations(
        "CARGO_HOME='/tmp/a b' c\nCARGO_HOME=\"/tmp/c d\" c\nCARGO_HOME=/tmp/e\\ f c\n",
        &strict,
    )
    .into_iter()
    .map(|v| v.value)
    .collect();
    assert_eq!(values, ["'/tmp/a b'", "\"/tmp/c d\"", "/tmp/e\\ f"]);
    // A flag group is skipped back to its own opening parenthesis.
    let chars = |s: &str| s.chars().collect::<Vec<_>>();
    assert_eq!(expansion(&chars("${(L)"), &chars("}")), Some(true));
    assert_eq!(expansion(&chars("${(j: :)"), &chars("=/x}")), Some(false));
    // A subscript is skipped to its own closing bracket.
    assert_eq!(expansion(&chars("${"), &chars("[1]=/x}")), Some(false));
    assert_eq!(expansion(&chars("${"), &chars("[1]}")), Some(true));
    // What a declared root allows, the guard allows here too.
    let rooted = RootSet::new(Path::new("/home/u"), &[PathBuf::from("/scratch")]);
    assert!(relocations("export CARGO_HOME=/scratch/cargo\n", &rooted).is_empty());
}

/// Every captured activation output under `tests/fixtures/activation/`,
/// by the command that printed it. Each was captured from the real tool,
/// with the absolute paths of the capturing machine replaced by neutral
/// ones.
const REAL_OUTPUTS: [(&str, &str); 5] = [
    (
        "mise activate zsh",
        include_str!("../../../tests/fixtures/activation/mise-activate-zsh.zsh"),
    ),
    (
        "starship init zsh --print-full-init",
        include_str!("../../../tests/fixtures/activation/starship-init-zsh.zsh"),
    ),
    (
        "zoxide init zsh",
        include_str!("../../../tests/fixtures/activation/zoxide-init-zsh.zsh"),
    ),
    (
        "fzf --zsh",
        include_str!("../../../tests/fixtures/activation/fzf-zsh.zsh"),
    ),
    (
        "uv generate-shell-completion zsh",
        include_str!("../../../tests/fixtures/activation/uv-completion-zsh.zsh"),
    ),
];

#[test]
fn the_real_outputs_of_common_tools_render() {
    // Review items D1 to D5: the strict-grammar reader refused every one
    // of these, for assignments none of which relocates anything. Under
    // the strict root set too — nothing in them moves a tool.
    for (command, output) in REAL_OUTPUTS {
        assert_eq!(relocations(output, &RootSet::strict()), vec![], "{command}");
        let program = command.split(' ').next().unwrap();
        let host = Fake::default().tool(program, program.as_bytes(), &[output]);
        let mut activation = decl(program, &command.split(' ').collect::<Vec<_>>());
        activation.phase = Phase::Completions;
        let mut cache = Fingerprints::default();
        let (plan, file) = apply(&[activation], &mut cache, &host);
        assert_eq!(plan.steps()[0].action(), Action::Create, "{command}");
        assert!(file.contains(&quote(output)), "{command}");
    }
    // And one relocating assignment in any of them is still found.
    let (_, mise) = REAL_OUTPUTS[0];
    let moved = mise.replace(
        "export MISE_SHELL=zsh\n",
        "export MISE_SHELL=zsh\nexport MISE_DATA_DIR=/elsewhere\n",
    );
    let found = relocations(&moved, &RootSet::strict());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "MISE_DATA_DIR");
    assert_eq!(found[0].reason, Reason::NoRootsDeclared);
}

#[test]
fn an_output_the_guard_refuses_is_blocked_named_and_never_written() {
    let host = Fake::default()
        .tool(
            "starship",
            b"starship",
            &["export STARSHIP_SHELL=zsh\nexport STARSHIP_CONFIG=/etc/x\n\
                   export CARGO_HOME=/c\nexport XDG_CACHE_HOME=/d\n"],
        )
        .tool("vi", b"vi", &["export EDITOR=vi\n"]);
    let decls = [decl("starship", &["starship"]), decl("vi", &["vi"])];
    let mut cache = Fingerprints::default();
    let (blocked, file) = apply(&decls, &mut cache, &host);
    let step = &blocked.steps()[0];
    assert_eq!(step.action(), Action::Blocked);
    assert_eq!(
        step.line(),
        "? activation `starship`: omitted: the environment guard refuses its output: \
             `STARSHIP_CONFIG` at line 2 assigns a variable no bx generator declares, so bx \
             cannot judge the value — a defect in bx, not in your configuration; 2 more \
             assignments are refused"
    );
    assert!(!file.contains("STARSHIP"), "{file}");
    assert!(
        file.contains("# bx activation: vi\neval 'export EDITOR=vi\n'\n"),
        "{file}"
    );
    let keys: Vec<&String> = cache.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["activation:vi"], "a refused output is never cached");

    // One more refusal, and an unreadable one, read as sentences.
    let one = Omission::Refused {
        first: relocations("export CARGO_HOME\n", &RootSet::strict()).remove(0),
        more: 1,
    };
    assert_eq!(
        one.to_string(),
        "the environment guard refuses its output: `CARGO_HOME` at line 1 is shell the \
             guard cannot read, so it is not approved; 1 more assignment is refused"
    );

    // A cached output is judged again at every plan: one the roots allowed
    // when it was captured is blocked, and forgotten, once they do not.
    let host = Fake::default().tool("cargo", b"cargo", &["export CARGO_HOME=/scratch/c\n"]);
    let decls = [decl("cargo", &["cargo"])];
    let rooted = RootSet::new(Path::new("/home/u"), &[PathBuf::from("/scratch")]);
    let mut cache = Fingerprints::default();
    plan(&decls, &cache, &rooted, &host).record(&mut cache);
    assert!(
        matches!(
            plan(&decls, &cache, &rooted, &host).steps()[0].outcome,
            Outcome::Reused { .. }
        ),
        "reused while the roots allow it"
    );
    let strict = plan(&decls, &cache, &RootSet::strict(), &host);
    assert!(matches!(
        &strict.steps()[0].outcome,
        Outcome::Omitted(Omission::Refused { first, more: 0 })
            if first.name == "CARGO_HOME" && first.reason == Reason::NoRootsDeclared
    ));
    assert_eq!(host.runs(), 2, "judging a cached output runs nothing");
    strict.record(&mut cache);
    assert!(cache.is_empty());
}

#[test]
fn a_second_apply_on_an_unchanged_machine_runs_nothing_and_renders_the_same_bytes() {
    let host = Fake::default()
        .tool("starship", b"starship 1.0", &["export EDITOR=nvim\n"])
        .tool("zoxide", b"zoxide 0.9", &["z() { :; }\n"]);
    let mut completions = decl("starship", &["starship", "init", "zsh"]);
    completions.phase = Phase::Completions;
    let decls = [completions, decl("zoxide", &["zoxide", "init", "zsh"])];
    let mut cache = Fingerprints::default();

    let (first, file) = apply(&decls, &mut cache, &host);
    assert_eq!(host.runs(), 4, "each new capture runs twice");
    for step in first.steps() {
        assert_eq!(step.action(), Action::Create, "{step:?}");
    }
    assert_eq!(cache.len(), 2);
    assert!(file.contains("eval 'export EDITOR=nvim\n'\n"), "{file}");
    assert!(
        file.find("# bx phase: activations").unwrap()
            < file.find("# bx phase: completions").unwrap()
    );

    let saved = cache.clone();
    let (second, again) = apply(&decls, &mut cache, &host);
    assert_eq!(host.runs(), 4, "the second apply starts no process");
    assert_eq!(again, file, "byte-identical");
    assert_eq!(cache, saved, "the cache is unchanged");
    for step in second.steps() {
        assert!(matches!(step.outcome, Outcome::Reused { .. }), "{step:?}");
        assert_eq!(step.action(), Action::Unchanged);
    }
}

#[test]
fn only_a_change_in_the_binarys_content_or_the_command_runs_it_again() {
    let mut host = Fake::default().tool("mise", b"mise 1", &["v1\n"]);
    let decls = [decl("mise", &["mise", "activate", "zsh"])];
    let mut cache = Fingerprints::default();
    apply(&decls, &mut cache, &host);
    assert_eq!(host.runs(), 2);

    // The same content at the same path is reused, whatever else changed.
    host.upgrade("mise", b"mise 1", &["ignored\n"]);
    let (plan, file) = apply(&decls, &mut cache, &host);
    assert_eq!(host.runs(), 2);
    assert!(file.contains("eval 'v1\n'"), "{file}");
    assert_eq!(plan.steps()[0].action(), Action::Unchanged);

    // New content runs it again and replaces the entry.
    host.upgrade("mise", b"mise 2", &["v2\n"]);
    let (plan, file) = apply(&decls, &mut cache, &host);
    assert_eq!(host.runs(), 4);
    assert!(file.contains("eval 'v2\n'"), "{file}");
    assert_eq!(plan.steps()[0].action(), Action::Modify);
    assert!(plan.steps()[0].line().contains("cache replaced"));

    // So does a changed command.
    let changed = [decl("mise", &["mise", "activate", "bash"])];
    apply(&changed, &mut cache, &host);
    assert_eq!(host.runs(), 6);
}

#[test]
fn the_cache_key_covers_the_binarys_content_its_path_and_the_command() {
    let content = ContentHash::of(b"a");
    let base = inputs(&content, Path::new("/bin/a"), &["a".into(), "x".into()]);
    assert_eq!(
        base,
        inputs(&content, Path::new("/bin/a"), &["a".into(), "x".into()])
    );
    for other in [
        inputs(
            &ContentHash::of(b"b"),
            Path::new("/bin/a"),
            &["a".into(), "x".into()],
        ),
        inputs(&content, Path::new("/opt/a"), &["a".into(), "x".into()]),
        inputs(&content, Path::new("/bin/a"), &["a".into(), "y".into()]),
        // Length-prefixed, so words cannot run together.
        inputs(&content, Path::new("/bin/a"), &["ax".into()]),
    ] {
        assert_ne!(base, other);
    }
}

#[test]
fn output_that_differs_between_two_runs_is_omitted_uncached_and_retried() {
    let host = Fake::default().tool("uv", b"uv", &["one\n", "two\n", "two\n"]);
    let decls = [decl("uv", &["uv", "generate-shell-completion", "zsh"])];
    let mut cache = Fingerprints::default();

    let (plan, file) = apply(&decls, &mut cache, &host);
    assert_eq!(
        plan.steps()[0].outcome,
        Outcome::Omitted(Omission::Unstable)
    );
    assert_eq!(plan.steps()[0].action(), Action::Blocked);
    assert!(
        plan.steps()[0]
            .line()
            .contains("omitted: two consecutive runs")
    );
    assert!(!file.contains("activation: uv"), "{file}");
    assert!(cache.is_empty(), "never cached");

    // Retried at the next plan, and trusted once two runs agree.
    let (plan, file) = apply(&decls, &mut cache, &host);
    assert!(matches!(plan.steps()[0].outcome, Outcome::Captured { .. }));
    assert!(file.contains("eval 'two\n'"), "{file}");
    assert_eq!(host.runs(), 4);
}

#[test]
fn an_absent_or_misbehaving_tool_is_omitted_and_everything_else_renders() {
    let mut host = Fake::default()
        .tool("ok", b"ok", &["ok\n"])
        .tool("binary", b"bin", &["\u{0}\n"])
        .failing(
            "fails",
            RunError::Exited {
                status: "exit status: 3".into(),
                stderr: "boom".into(),
            },
        )
        .failing("slow", RunError::TimedOut(TIMEOUT))
        .tool("locked", b"locked", &["x\n"])
        .tool("noexec", b"noexec", &["x\n"]);
    host.unreadable.push("locked".into());
    host.inexecutable.push("noexec".into());
    host.outputs.borrow_mut().insert(
        PathBuf::from("/usr/bin/latin1"),
        VecDeque::from([Ok(vec![0xff])]),
    );
    host.tools
        .insert("latin1".into(), ("/usr/bin/latin1".into(), b"l".to_vec()));

    let decls: Vec<_> = [
        "absent", "binary", "fails", "slow", "locked", "noexec", "latin1", "ok",
    ]
    .iter()
    .map(|name| decl(name, &[name]))
    .collect();
    let mut cache = Fingerprints::default();
    for decl in &decls {
        cache.set(decl.key(), Fingerprint::raw(vec![0]));
    }
    let (plan, file) = apply(&decls, &mut cache, &host);

    let notes: Vec<String> = plan.steps().iter().map(Step::line).collect();
    assert_eq!(
        notes,
        [
            "? activation `absent`: omitted: `absent` is not on PATH",
            "? activation `binary`: omitted: it printed something that is not text",
            "? activation `fails`: omitted: it exited with exit status: 3: boom",
            "? activation `slow`: omitted: it was still running after 10 s and was stopped",
            "? activation `locked`: omitted: its binary cannot be hashed: permission denied",
            "? activation `noexec`: omitted: /usr/bin/noexec is not executable by this account",
            "? activation `latin1`: omitted: it printed something that is not text",
            "~ activation `ok`: binary or command changed; run twice, output agreed; \
                 cache replaced",
        ]
    );
    assert!(
        file.contains("# bx activation: ok\neval 'ok\n'\n"),
        "{file}"
    );
    assert_eq!(file.matches("# bx activation:").count(), 1, "{file}");
    let keys: Vec<&String> = cache.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["activation:ok"], "an omission forgets its entry");
}

#[test]
fn recording_forgets_only_activation_entries_nothing_uses() {
    let host = Fake::default().tool("a", b"a", &["a\n"]);
    let mut off = decl("b", &["b"]);
    off.enabled = false;
    let decls = [decl("a", &["a"]), off];
    let mut cache = Fingerprints::default();
    cache.set("activation:b", Fingerprint::raw(vec![1]));
    cache.set("activation:gone", Fingerprint::raw(vec![1]));
    cache.set("other:thing", Fingerprint::raw(vec![1]));
    let (plan, _) = apply(&decls, &mut cache, &host);
    assert_eq!(
        plan.steps().len(),
        1,
        "a disabled activation is not planned"
    );
    let keys: Vec<&String> = cache.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["activation:a", "other:thing"]);
}

#[test]
fn an_entry_that_does_not_decode_is_a_miss() {
    let host = Fake::default().tool("a", b"a", &["a\n"]);
    let decls = [decl("a", &["a"])];
    let mut cache = Fingerprints::default();
    cache.set(
        "activation:a",
        Fingerprint::raw(b"not messagepack".to_vec()),
    );
    let (plan, _) = apply(&decls, &mut cache, &host);
    assert_eq!(plan.steps()[0].action(), Action::Modify);
    assert_eq!(host.runs(), 2);
    let entry = Entry::decode(cache.get("activation:a").unwrap()).expect("decodes");
    assert_eq!(entry.output, "a\n");
}

#[test]
fn a_rendered_activation_is_one_eval_of_a_literal_and_sets_nothing_itself() {
    // Invariant 2: the phase is not an environment fragment. The tool's
    // text, however hostile, is the single-quoted argument of one `eval`;
    // stripping that literal leaves bx's own bytes, which set nothing.
    let output = "export A='1'\nB=2; echo \"$(x)\" '\\''\n}\n'unterminated\n";
    let step = Step {
        decl: decl("t", &["t"]),
        shell: Shell::Zsh,
        outcome: Outcome::Reused {
            output: output.to_string(),
        },
    };
    let body = step.body().expect("renders");
    let rest = body
        .strip_prefix("# bx activation: t\neval '")
        .and_then(|b| b.strip_suffix("'\n"))
        .expect("one eval of one literal");
    // Inside the literal, a quote appears only as the `'\''` escape, so the
    // literal never ends early and the text round-trips.
    assert_eq!(rest.replace(r"'\''", "'"), output);
    assert!(!rest.replace(r"'\''", "").contains('\''), "{rest}");

    assert_eq!(
        Step {
            decl: decl("o", &["o"]),
            shell: Shell::Bash,
            outcome: Outcome::Omitted(Omission::NotText),
        }
        .body(),
        None
    );
}

#[test]
fn zsh_runs_a_cached_activation_as_the_tool_wrote_it_and_contains_a_broken_one() {
    let Some(zsh) = crate::shell::testing::installed("zsh") else {
        return;
    };
    let step = |name: &str, output: &str| Step {
        decl: decl(name, &[name]),
        shell: Shell::Zsh,
        outcome: Outcome::Reused {
            output: output.to_string(),
        },
    };
    let steps = vec![
        step(
            "quoted",
            "export X='a'\\''b $HOME' W=\"$HOME/w\"\nz() { print -r -- zed; }\n",
        ),
        step("broken", "echo 'never closed\n"),
        step("after", "export Y=ok\n"),
    ];
    let mut assembly = Assembly::new();
    contribute(&mut assembly, &Plan { steps }.rendered(Shell::Zsh)).expect("contributes");
    let dir = tempfile::TempDir::new().expect("tempdir");
    let file = dir.path().join("zshrc.zsh");
    std::fs::write(&file, assembly.render()).expect("write");
    let out = Command::new(zsh)
        .args([
            "-f",
            "-c",
            "source \"$1\"; print -r -- \"$X|$W|$Y|$(z)\"",
            "zsh",
        ])
        .arg(&file)
        .env_clear()
        .env("HOME", dir.path())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("zsh runs");
    let home = dir.path().display();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("a'b $HOME|{home}/w|ok|zed\n")
    );
}

/// A tool named `tool` first on a search path of its own: a link to `sh`,
/// so the test starts a real process without writing an executable. The
/// system directories follow it, so the scripts it runs find `head`.
fn linked_sh() -> (tempfile::TempDir, System) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::os::unix::fs::symlink("/bin/sh", dir.path().join("tool")).expect("link");
    let system = System::new(searched(&dir, "/usr/bin:/bin"), Duration::from_secs(5));
    (dir, system)
}

/// `dir`, then `rest`, as one search path.
fn searched(dir: &tempfile::TempDir, rest: &str) -> OsString {
    format!("{}:{rest}", dir.path().display()).into()
}

#[test]
fn a_tool_that_prints_the_path_it_ran_with_is_cached_referring_to_the_live_path() {
    // D1: a tool that echoes its PATH, run under two different ones. What
    // it prints differs; what is cached and rendered does not.
    let (dir, system) = linked_sh();
    let decls = [decl(
        "tool",
        &[
            "tool",
            "-c",
            "printf \"export PATH='/opt/t/bin:%s'\\nexport X=\\\"%s\\\"\\n\" \"$PATH\" \"$PATH\"",
        ],
    )];
    let other = System::new(searched(&dir, "/bin:/usr/bin"), Duration::from_secs(5));
    let raw = other
        .run(&dir.path().join("tool"), &decls[0].command[1..])
        .expect("ran");
    assert!(
        String::from_utf8(raw).unwrap().contains(":/bin:/usr/bin'"),
        "the tool really printed the PATH it ran with"
    );
    let expected = "# bx activation: tool\neval 'export PATH='\\''/opt/t/bin:'\\''\"$PATH\"\n\
                        export X=\"${PATH}\"\n'\n";
    let roots = RootSet::strict();
    let mut caches = Vec::new();
    for system in [&system, &other] {
        let planned = plan(&decls, &Fingerprints::default(), &roots, system);
        assert_eq!(planned.steps()[0].body().as_deref(), Some(expected));
        let mut cache = Fingerprints::default();
        planned.record(&mut cache);
        caches.push(cache);
    }
    assert_eq!(caches[0], caches[1], "the cache holds no PATH either");
}

#[test]
fn the_path_is_replaced_by_a_reference_quoted_for_where_it_stands() {
    let p = OsStr::new("/a:/b");
    let cases = [
        // mise's own line, and one that prepends a directory.
        ("export PATH='/a:/b'\n", "export PATH=\"$PATH\"\n"),
        (
            "export PATH='/m/bin:/a:/b'\n",
            "export PATH='/m/bin:'\"$PATH\"\n",
        ),
        ("x='/a:/b:/z'", "x=\"$PATH\"':/z'"),
        ("x='p /a:/b q /a:/b'", "x='p '\"$PATH\"' q '\"$PATH\""),
        ("x=\"/m:/a:/b\"", "x=\"/m:${PATH}\""),
        ("x=/m:/a:/b", "x=/m:\"$PATH\""),
        (
            "x=$'/a:/b' y=$'\\'/a:/b'",
            "x=$''\"$PATH\"$'' y=$'\\''\"$PATH\"$''",
        ),
        ("x=\"$(echo '/a:/b')\"", "x=\"$(echo \"$PATH\")\""),
        (
            "x=\"$(echo \"/a:/b\")\" '/a:/b'",
            "x=\"$(echo \"${PATH}\")\" \"$PATH\"",
        ),
        ("x=`echo /a:/b`", "x=`echo \"$PATH\"`"),
        // A single quote is text inside double quotes, but opens a span
        // again inside a substitution they hold.
        ("x=\"it's /a:/b\"", "x=\"it's ${PATH}\""),
        ("x=\"`echo '/a:/b'`\"", "x=\"`echo \"$PATH\"`\""),
        ("x=$(( (1) )) '/a:/b'", "x=$(( (1) )) \"$PATH\""),
        // A parenthesis a substitution holds closes inside it, not it.
        (
            "x=\"$( (true); echo /a:/b )\"",
            "x=\"$( (true); echo \"$PATH\" )\"",
        ),
        // A comment's quote opens nothing; the value in it is replaced too.
        ("# it's /a:/b\nx='/a:/b'", "# it's \"$PATH\"\nx=\"$PATH\""),
        ("echo ${#a} '/a:/b'", "echo ${#a} \"$PATH\""),
        // An escaped quote opens nothing.
        ("x=\\' '/a:/b'", "x=\\' \"$PATH\""),
        ("x=\"\\\" /a:/b\"", "x=\"\\\" ${PATH}\""),
        // Inside `$'…'` a double quote is text, so it opens nothing.
        ("x=$'a\"b' '/a:/b'", "x=$'a\"b' \"$PATH\""),
        // Part of a longer path is not the value.
        ("x='/a:/b/c' y=/z/a:/b", "x='/a:/b/c' y=/z/a:/b"),
    ];
    for (output, expected) in cases {
        assert_eq!(live_path(output, p), expected, "{output}");
    }
    // Nothing to find in an empty or unreadable PATH.
    assert_eq!(live_path("x=''", OsStr::new("")), "x=''");
    let unreadable = <OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"/a\xff");
    assert_eq!(live_path("x=/a", unreadable), "x=/a");
}

#[test]
fn the_captured_mise_activation_prepends_to_the_live_path() {
    // The fixture was captured with this PATH.
    let (_, mise) = REAL_OUTPUTS[0];
    assert!(mise.starts_with("export PATH='/usr/local/bin:/usr/bin:/bin'\n"));
    let mut host = Fake::default().tool("mise", b"mise", &[mise]);
    host.path = "/usr/local/bin:/usr/bin:/bin".into();
    let planned = plan(
        &[decl("mise", &["mise", "activate", "zsh"])],
        &Fingerprints::default(),
        &RootSet::strict(),
        &host,
    );
    let Outcome::Captured { output, .. } = &planned.steps()[0].outcome else {
        panic!("{:?}", planned.steps()[0].outcome);
    };
    let rest = mise.split_once('\n').unwrap().1;
    assert_eq!(output, &format!("export PATH=\"$PATH\"\n{rest}"));
}

#[test]
fn the_system_runs_the_resolved_binary_and_caches_what_it_printed() {
    let (dir, system) = linked_sh();
    let decls = [decl(
        "tool",
        &["tool", "-c", "printf 'export EDITOR=vi\\n'"],
    )];
    let mut cache = Fingerprints::default();
    let roots = RootSet::strict();
    let plan_one = plan(&decls, &cache, &roots, &system);
    assert_eq!(
        plan_one.steps()[0].body().expect("captured"),
        "# bx activation: tool\neval 'export EDITOR=vi\n'\n"
    );
    plan_one.record(&mut cache);
    let plan_two = plan(&decls, &cache, &roots, &system);
    assert!(matches!(
        plan_two.steps()[0].outcome,
        Outcome::Reused { .. }
    ));
    assert_eq!(
        system.locate("tool"),
        Presence::Present {
            path: dir.path().join("tool")
        }
    );
    assert_eq!(system.locate("absent-tool"), Presence::Missing);
    let absent = dir.path().join("absent");
    let missing = std::io::Error::from_raw_os_error(rustix::io::Errno::NOENT.raw_os_error());
    assert_eq!(
        system.hash(&absent),
        Err(format!("reading {}: {missing}", absent.display()))
    );
}

#[test]
fn the_system_reports_a_failing_slow_or_noisy_command() {
    let (dir, system) = linked_sh();
    let sh = dir.path().join("tool");
    let run =
        |system: &System, script: &str| system.run(&sh, &["-c".to_string(), script.to_string()]);
    assert_eq!(run(&system, "printf ok"), Ok(b"ok".to_vec()));
    // A tool that warns at length still succeeds.
    assert_eq!(
        run(&system, "head -c 1000000 /dev/zero >&2; printf ok"),
        Ok(b"ok".to_vec())
    );
    assert_eq!(
        run(&system, "echo first >&2; echo second >&2; exit 3"),
        Err(RunError::Exited {
            status: "exit status: 3".to_string(),
            stderr: "first".to_string(),
        })
    );
    assert_eq!(
        run(&system, "exit 4").unwrap_err().to_string(),
        "it exited with exit status: 4"
    );
    let quick = System::new(searched(&dir, "/usr/bin:/bin"), Duration::from_millis(200));
    assert_eq!(
        run(&quick, "sleep 5"),
        Err(RunError::TimedOut(Duration::from_millis(200)))
    );
    // A child left holding the pipe bounds the read by the same deadline.
    assert_eq!(
        run(&quick, "sleep 5 & exit 0"),
        Err(RunError::TimedOut(Duration::from_millis(200)))
    );
    assert_eq!(
        run(&system, &format!("head -c {} /dev/zero", LIMIT + 1)),
        Err(RunError::TooLarge(LIMIT))
    );
    assert_eq!(
        run(&system, &format!("head -c {LIMIT} /dev/zero")).map(|o| o.len()),
        Ok(LIMIT)
    );
    assert!(matches!(
        system.run(&dir.path().join("absent"), &[]),
        Err(RunError::Spawn(_))
    ));
    assert!(System::from_env().timeout == TIMEOUT);
}
