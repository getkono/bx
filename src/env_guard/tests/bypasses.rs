//! Bypass reproductions: each row is a way of relocating a tool that an earlier
//! version of the guard approved, and its label names the construct. The guard
//! approves none of them, under any root set its row names.

use super::*;

/// The root sets a reproduction is scanned under, each built afresh.
type Sets = &'static [fn() -> RootSet];

const ROOTED: Sets = &[rooted];
const BOTH: Sets = &[rooted, RootSet::strict];

/// The home with no root declared.
fn home_only() -> RootSet {
    RootSet::new(Path::new(HOME), &[])
}

/// `(label, contents, root sets)`: every content is scanned under every set.
#[rustfmt::skip]
const ROUNDS_3_AND_4: &[(&str, &[&str], Sets)] = &[
    ("r3.1 quoted, escaped and aliased keywords", &[
        "\\export CARGO_HOME=/etc/evil",
        "\"export\" CARGO_HOME=/etc/evil",
        "e''xport CARGO_HOME=/etc/evil",
        "alias ex=export\nex CARGO_HOME=/etc/evil",
    ], BOTH),
    ("r3.2 multi-line constructs", &[
        ": '\n'; export CARGO_HOME=/etc/evil #'",
        "ex\\\nport CARGO_HOME=/etc/evil",
        "export CARGO_HOME=/var/mnt/scratch/example/cargo\nCARGO_\\\nHOME=/etc/evil",
    ], ROOTED),
    ("r3.3 assigning commands and stale values", &[
        "for CARGO_HOME in /etc/evil; do :; done",
        "read -r CARGO_HOME <<< /etc/evil",
        "printf -v CARGO_HOME /etc/evil",
        "CARGO_HOME[1,-1]=/etc/evil",
        ": ${CARGO_HOME::=/etc/evil}",
        "set -a\n: ${CARGO_HOME:=/etc/evil}",
        "R=/var/mnt/scratch/example\nunset R\nexport CARGO_HOME=$R/etc/evil",
    ], ROOTED),
    ("r3.4 special parameters", &[
        "CARGO_HOME=/var/mnt/scratch/example/$@/$@/$@/$@/../../../../etc/evil",
    ], ROOTED),
    ("r3.4 a fragment-assigned home", &[
        "XDG_STATE_HOME=~/.local/state/b$@x",
        "HOME=/etc/evil\nCARGO_HOME=~/cargo",
    ], &[home_rooted]),
    ("r3.5 eval and source with a literal payload", &[
        "eval \"export CARGO_HOME=/etc/evil\"",
        "source /dev/stdin <<< 'export CARGO_HOME=/etc/evil'",
    ], ROOTED),
    ("r3.7 colon lists", &[
        "KUBECONFIG=/var/mnt/scratch/example/k:/etc/evil/config",
        "GOPATH=/var/mnt/scratch/example/go:/etc/evil",
    ], ROOTED),
    ("r3.8 location words and zsh equals expansion", &[
        "MISE_SHARED_INSTALL_DIRS=evil",
        "MISE_TRUSTED_CONFIG_PATHS=evil",
        "UV_PROJECT=evil",
        "MISE_DEFAULT_CONFIG_FILENAME=evil.toml",
        "UV_PROJECT==ls",
    ], ROOTED),
    ("r4.1 a state directory the fragment moves is owned by later lines", &[
        "export XDG_STATE_HOME=/var/mnt/scratch/example/state\n\
         export CARGO_HOME=/var/mnt/scratch/example/state/bx",
    ], ROOTED),
    ("r4.1 a state directory the fragment moves, under the home", &[
        "export XDG_STATE_HOME=~/state\nexport CARGO_HOME=~/state/bx/cargo",
    ], &[home_rooted]),
    ("r4.2 a name whose assignment the shell acts on", &[
        "export HISTFILESIZE=0",
        "export HISTFILE=/etc/evil",
        "export HISTFILE=history",
        "POSIXLY_CORRECT=1",
        "BASH_COMPAT=50",
        "GLOBIGNORE=x",
        "BASH_XTRACEFD=1",
        "PROMPT_COMMAND=x",
        "PS0=x",
        "precmd_functions=x",
    ], BOTH),
    ("r4.3 a path given to a name no list holds", &[
        "export SOMETHING=.",
        "export SOMETHING=..",
        "export SOMETHING=build/cache",
        "export SOMETHING=~/elsewhere",
        "export SOMETHING=a:/etc/evil",
        "X=/etc/evil",
    ], ROOTED),
    ("r4.4 location words the review found missing", &[
        "MISE_CONFIG_DIRECTORY=evil",
        "MISE_OVERRIDE_CONFIG_FILENAMES=evil",
        "UV_TOOL_FOLDER=evil",
        "ASDF_PLUGIN_MODULE=evil",
        "PIP_INSTALL_DEST=evil",
    ], ROOTED),
    ("r4.5 a search list or a program that is not an absolute path", &[
        "export PATH=.:/usr/bin",
        "export PATH=/usr/bin:",
        "export PATH=bin",
        "export PATH=",
        "export PATH=/var/home/example/.local/state/bx/bin:/usr/bin",
        "export EDITOR=./nvim",
        "export EDITOR=/var/home/example/.local/state/bx/nvim",
    ], &[rooted, home_only]),
];

#[test]
fn no_round_3_or_4_reproduction_is_approved() {
    let mut approved = Vec::new();
    let mut judge = |label: &str, content: &str, sets: Sets| {
        for roots in sets {
            if scan_with(content, &roots()).is_empty() {
                approved.push(format!("{label}: {content:?}"));
            }
        }
    };
    for (label, contents, sets) in ROUNDS_3_AND_4 {
        for content in *contents {
            judge(label, content, sets);
        }
    }
    for name in R4_UNLISTED_RELOCATIONS {
        let content = format!("export {name}=/etc/evil");
        judge("r4.3 a relocation no list held", &content, BOTH);
    }
    // Relocating names an earlier name list missed, judged by `check`.
    for name in [
        "HOME",
        "npm_config_cache",
        "ZDOTDIR",
        "YARN_CACHE_FOLDER",
        "CCACHE_DIR",
        "STARSHIP_CONFIG",
        "PYTHONUSERBASE",
        "TMPDIR",
    ] {
        if check(name, "/etc/evil", &rooted()) == Verdict::Allowed {
            approved.push(format!("r3.6 missing relocating names: {name}"));
        }
    }
    assert_eq!(approved, Vec::<String>::new());
}
