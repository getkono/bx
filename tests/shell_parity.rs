//! zsh and bash are configured alike from one set of declarations.
//!
//! One configuration declares every kind of shell declaration bash and zsh
//! share — variables of each kind a shell reads, `PATH` entries, functions,
//! optional sources, aliases and tool activations — and one of each kept to a
//! single shell.
//! `bx apply` writes it through the real binary, and the declarations each
//! shell's generated files carry are read back from their bytes: the two sets
//! are equal but for the entries kept to one shell, and a second `apply`
//! changes nothing.
//!
//! Every invocation gets its home from a guarded tempdir.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use bx::testing::guarded_home;

/// `bx` against `home`, with `~/bin` its whole `PATH`, so an activation's
/// tool is the stub there and nothing else is found.
fn bx(home: &Path, args: &[&str]) -> Output {
    Command::cargo_bin("bx")
        .expect("the bx binary")
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", home.join("bin"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run bx")
}

/// A tool that prints, for `stub init SHELL`, a function naming the shell.
fn stub(home: &Path) {
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).expect("~/bin");
    let stub = bin.join("stub");
    std::fs::write(&stub, "#!/bin/sh\nprintf 'stub_%s() { :; }\\n' \"$2\"\n").expect("the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("executable");
}

/// Every shared declaration once, then one of each kept to a single shell.
/// Variable names are ones the environment guard knows how to judge.
const CONFIG: &str = r#"
[[env]]
name = "LANG"
value = "C.UTF-8"
kind = "environment"

[[env]]
name = "PAGER"
value = "less"
kind = "login"

[[env]]
name = "EDITOR"
value = "nvim"
kind = "interactive"

[[env]]
name = "MISE_JOBS"
value = "4"
kind = "interactive"
when = "ssh"

[[env]]
name = "BROWSER"
value = "firefox"
kind = "gui"

[[env]]
name = "VISUAL"
value = "nvim"
kind = "interactive"
shells = ["zsh"]

[[env]]
name = "TERMINAL"
value = "foot"
kind = "login"
shells = ["bash"]

[path]
prepend = [
    "~/bin",
    { dir = "~/.local/bin", if_exists = true },
    { dir = "~/.zsh-only/bin", shells = ["zsh"] },
]
append = [{ dir = "/opt/bash-only/bin", shells = ["bash"] }, "/opt/tool/bin"]
remove = ["~/.cargo/bin"]

[aliases]
ll = "ls -la"

[[function]]
name = "mkcd"
body = 'mkdir -p -- "$1" && cd -- "$1"'

[[function]]
name = "venv"
body = "print -r -- venv"
hook = "chpwd"
bash = "echo venv"

[[function]]
name = "hook_zsh"
body = "print -r -- $PWD"
hook = "precmd"
shells = ["zsh"]

[[function]]
name = "fn_bash"
body = "echo bash"
shells = ["bash"]

[[source]]
name = "extra"
path = "~/.aliases"

[[source]]
name = "src_zsh"
path = "~/.zplug/init.zsh"
shells = ["zsh"]

[[activation]]
name = "stub"
command = ["stub", "init", "{shell}"]
phase = "completions"

[[activation]]
name = "act_zsh"
command = ["stub", "init", "zsh"]

[[activation]]
name = "act_bash"
bash = ["stub", "init", "bash"]
"#;

/// What bash's line taking a directory out of `PATH` opens and closes with.
const BASH_REMOVAL: (&str, &str) = (
    "PATH=:${PATH//:/::}:; PATH=${PATH//\":",
    ":\"/}; PATH=${PATH//::/:}; PATH=${PATH#:}; PATH=${PATH%:}",
);

/// The `PATH` edit `line` makes, in either shell's words, as `path-in DIR`
/// or `path-out DIR`; `None` for any other line, and for the line that only
/// settles a block's status.
fn path_edit(line: &str) -> Option<String> {
    let line = match line.strip_prefix("[[ -d ") {
        Some(gated) => gated.split_once(" ]] && ")?.1,
        None => line,
    };
    let removed = line
        .strip_prefix("path=(${path:#")
        .and_then(|rest| rest.strip_suffix("})"))
        .or_else(|| {
            line.strip_prefix(BASH_REMOVAL.0)
                .and_then(|rest| rest.strip_suffix(BASH_REMOVAL.1))
        });
    if let Some(dir) = removed {
        return Some(format!("path-out {dir}"));
    }
    let list = line.strip_prefix("export PATH=")?;
    let dir = list
        .strip_suffix(":${PATH}")
        .or_else(|| list.strip_prefix("${PATH}:"))?;
    Some(format!("path-in {dir}"))
}

/// Every `PATH` edit `text` makes, in order.
fn path_edits(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim_start)
        .filter_map(path_edit)
        .collect()
}

/// The declarations `text` carries, each as `kind name`: the variables it
/// exports, the `PATH` edits it makes, the functions it defines — a hooked
/// one under its declared name — the files it sources, the aliases and the
/// activations.
fn declarations(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim_start)
        .filter_map(|line| {
            if ["export PATH=", "[[ -d ", "PATH=:", "path=("]
                .iter()
                .any(|opening| line.starts_with(opening))
            {
                return path_edit(line);
            }
            if let Some(rest) = line.strip_prefix("export ") {
                let name = rest.split('=').next()?;
                return Some(format!("env {name}"));
            }
            if let Some(rest) = line.strip_prefix("function ") {
                let name = rest.strip_suffix(" {")?;
                let name = name.strip_prefix("__bx_hook_").unwrap_or(name);
                return Some(format!("function {name}"));
            }
            if let Some(rest) = line.strip_prefix("alias ") {
                return Some(format!("alias {}", rest.split('=').next()?));
            }
            if let Some(name) = line.strip_prefix("# bx activation: ") {
                return Some(format!("activation {name}"));
            }
            line.split_once(" ]] && source ")
                .map(|(_, path)| format!("source {path}"))
        })
        .collect()
}

/// The declarations every one of `files` under `home` carries.
fn read_all(home: &Path, files: &[&str]) -> (BTreeSet<String>, Vec<Vec<u8>>) {
    let mut found = BTreeSet::new();
    let mut bytes = Vec::new();
    for file in files {
        let raw = std::fs::read(home.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        found.extend(declarations(std::str::from_utf8(&raw).expect("UTF-8")));
        bytes.push(raw);
    }
    (found, bytes)
}

const ZSH: [&str; 3] = [
    ".local/share/bx/zshenv.zsh",
    ".local/share/bx/zprofile.zsh",
    ".local/share/bx/zshrc.zsh",
];
const BASH: [&str; 1] = [".local/share/bx/bashrc.bash"];

#[test]
fn zsh_and_bash_render_the_same_declarations_but_those_kept_to_one_shell() {
    let home = guarded_home();
    stub(home.path());
    let repo = home.child(".config/bx");
    std::fs::create_dir_all(&repo).expect("the config repo");
    std::fs::write(repo.join("bx.toml"), CONFIG).expect("bx.toml");

    let applied = bx(home.path(), &["apply", "--yes"]);
    assert_eq!(
        applied.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );

    let (zsh, zsh_bytes) = read_all(home.path(), &ZSH);
    let (bash, bash_bytes) = read_all(home.path(), &BASH);
    let set = |items: &[&str]| -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    };
    let zsh_only = set(&[
        "env VISUAL",
        "path-in ${HOME}/.zsh-only/bin",
        "path-out ${HOME}/.zsh-only/bin",
        "function hook_zsh",
        "source ~/.zplug/init.zsh",
        "activation act_zsh",
    ]);
    let bash_only = set(&[
        "env TERMINAL",
        "path-in /opt/bash-only/bin",
        "path-out /opt/bash-only/bin",
        "function fn_bash",
        "activation act_bash",
    ]);

    // The sets are equal but for the entries kept to one shell: each of
    // those reaches its own shell and not the other.
    assert_eq!(
        zsh.difference(&bash).cloned().collect::<BTreeSet<_>>(),
        zsh_only,
        "zsh: {zsh:?}\nbash: {bash:?}"
    );
    assert_eq!(
        bash.difference(&zsh).cloned().collect::<BTreeSet<_>>(),
        bash_only,
        "zsh: {zsh:?}\nbash: {bash:?}"
    );
    // What reaches both is every shared declaration: nothing is lost from
    // both at once. A GUI variable is no shell's.
    assert_eq!(
        zsh.intersection(&bash).cloned().collect::<BTreeSet<_>>(),
        set(&[
            "env LANG",
            "env PAGER",
            "env EDITOR",
            "env MISE_JOBS",
            "path-in ${HOME}/bin",
            "path-out ${HOME}/bin",
            "path-in ${HOME}/.local/bin",
            "path-out ${HOME}/.local/bin",
            "path-in /opt/tool/bin",
            "path-out /opt/tool/bin",
            "path-out ${HOME}/.cargo/bin",
            "alias ll",
            "function mkcd",
            "function venv",
            "source ~/.aliases",
            "activation stub",
        ])
    );

    // Each shell edits PATH in the same order, but for the entries kept to
    // the other.
    let zshenv = String::from_utf8_lossy(&zsh_bytes[0]);
    let bashrc = String::from_utf8_lossy(&bash_bytes[0]);
    let without = |edits: Vec<String>, kept: &str| -> Vec<String> {
        edits
            .into_iter()
            .filter(|edit| !edit.ends_with(kept))
            .collect()
    };
    assert_eq!(
        without(path_edits(&zshenv), " ${HOME}/.zsh-only/bin"),
        without(path_edits(&bashrc), " /opt/bash-only/bin"),
        "zsh:\n{zshenv}\nbash:\n{bashrc}"
    );

    // Each shell ran its own activation command.
    let zshrc = String::from_utf8_lossy(&zsh_bytes[2]);
    assert!(zshrc.contains("stub_zsh() { :; }") && !zshrc.contains("stub_bash"));
    assert!(bashrc.contains("stub_bash() { :; }") && !bashrc.contains("stub_zsh"));

    // Idempotent: the second plan is empty and a second apply rewrites
    // nothing.
    let planned = bx(home.path(), &["plan"]);
    assert_eq!(
        planned.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&planned.stdout)
    );
    let again = bx(home.path(), &["apply", "--yes"]);
    assert_eq!(again.status.code(), Some(0));
    assert_eq!(read_all(home.path(), &ZSH).1, zsh_bytes);
    assert_eq!(read_all(home.path(), &BASH).1, bash_bytes);
}
