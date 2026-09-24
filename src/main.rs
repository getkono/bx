//! The `bx` binary.
//!
//! Ten commands, no manual. Everything the user needs to discover is reachable
//! from `--help`, dynamic completion, and the prompts in `bx init`.

use std::io::Write as _;

use clap::{Parser, Subcommand};
use eyre::Result;

/// `bx --version`: the release, and the commit it was built from. A user
/// reporting a problem with a statically installed binary has no other way to
/// say which build they have.
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("BX_COMMIT_HASH"),
    " ",
    env!("BX_COMMIT_DATE"),
    ")"
);

#[derive(Parser)]
#[command(name = "bx", version, long_version = LONG_VERSION, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Guided setup — first machine or fifth, same command
    Init,
    /// Begin managing a tool, a config file, or a secret
    Add { target: Option<String> },
    /// Stop managing it, and restore the original
    Rm { target: Option<String> },
    /// The diff `apply` would make
    Plan,
    /// Converge this machine to the repo
    Apply {
        /// Write without asking for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Pull, apply, push
    Sync,
    /// Set, list, and rotate secrets
    Secret,
    /// Drift, missing tools, broken seams, stale caches, shell cost
    Doctor,
    /// Print the one line for your shell rc
    ShellInit { shell: String },
    /// Completion candidates for the current word (used by the shell)
    #[command(hide = true, name = "__complete")]
    Complete { args: Vec<String> },
}

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("BX_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let command = Cli::parse().command;
    let env = bx::plan::Env::from_process()?;
    let mut out = std::io::stdout().lock();
    let exit = match command {
        // No subcommand is the status view.
        None => bx::command::status(&env, &mut out)?,
        Some(Command::Plan) => bx::command::plan(&env, &mut out)?,
        Some(Command::Apply { yes }) => bx::command::apply(&env, yes, &mut out)?,
        Some(Command::Doctor) => bx::command::doctor(&env, &mut out)?,
        Some(Command::Add { target }) => {
            bx::command::add(&env, &std::env::current_dir()?, target.as_deref(), &mut out)?
        }
        Some(Command::Rm { target }) => {
            bx::command::rm(&env, &std::env::current_dir()?, target.as_deref(), &mut out)?
        }
        Some(_) => todo!("command dispatch"),
    };
    out.flush()?;
    std::process::exit(exit.code());
}
