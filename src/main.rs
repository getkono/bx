//! The `bx` binary.
//!
//! Twelve commands, no manual. Everything the user needs to discover is reachable
//! from `--help` and the prompts in `bx init`.

use std::io::Write as _;

use clap::{Parser, Subcommand};
use eyre::Result;

// One version text for `-V` and `--version` alike: a user reporting a problem
// with a statically installed binary has no other way to say which build they
// have, whichever flag they reach for.
#[derive(Parser)]
#[command(name = "bx", version = bx::version::long_version(), about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Guided setup — first machine or fifth, same command
    Init {
        /// Answer a declared value without its prompt; repeatable
        #[arg(long = "set", value_name = "NAME=VALUE")]
        set: Vec<String>,
        /// Ask nothing: fail on a value no --set answers, adopt nothing, and
        /// write the plan without asking for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Begin managing a config file, or a directory of them
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
    Sync {
        /// Write without asking for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Move externals that follow a branch to its new commits: pull, look,
    /// lock and commit, apply
    Update {
        /// Only these externals, by path; every followed one when none
        paths: Vec<String>,
        /// Lock, commit and apply without asking for confirmation
        #[arg(long, conflicts_with_all = ["check", "snooze"])]
        yes: bool,
        /// Only look and report: exit 0 when nothing is new, 2 when
        /// something is; locks, commits and applies nothing
        #[arg(long, conflicts_with = "snooze")]
        check: bool,
        /// Ask again only after the next interval; reaches no network
        #[arg(long, conflicts_with = "paths")]
        snooze: bool,
        /// The interactive shell's own quiet, bounded check
        #[arg(long, hide = true, conflicts_with_all = ["yes", "check", "snooze", "paths"])]
        background: bool,
    },
    /// List declared secrets, and whether each decrypts here
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Missing tools, unanswered values, damaged state, and what else needs a
    /// look; changes nothing
    Doctor,
    /// Print the one line for your shell rc (not built yet)
    ShellInit { shell: String },
    /// Install the latest release over this one, as a fresh install would
    SelfUpgrade {
        /// Only report whether a newer release exists: exit 0 when not, 2
        /// when there is
        #[arg(long, conflicts_with = "force")]
        check: bool,
        /// Reinstall the latest release even when this one is not older
        #[arg(long)]
        force: bool,
    },
    /// Completion candidates for the current word (used by the shell)
    #[command(hide = true, name = "__complete")]
    Complete { args: Vec<String> },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Every declared secret, its ciphertext, and whether it decrypts here
    List,
}

fn main() -> Result<()> {
    // An error is something to read, not to debug: where in bx it was
    // propagated from and how to ask for a backtrace say nothing to the person
    // whose config it refused.
    color_eyre::config::HookBuilder::default()
        .display_location_section(false)
        .display_env_section(false)
        .install()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("BX_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let command = Cli::parse().command;
    let mut out = std::io::stdout().lock();
    // Upgrading reads no configuration, so it does not need a usable home.
    if let Some(Command::SelfUpgrade { check, force }) = command {
        let exit = bx::command::self_upgrade(check, force, &mut out)?;
        out.flush()?;
        std::process::exit(exit.code());
    }
    let env = bx::env::Env::from_process()?;
    let exit = match command {
        // No subcommand is the status view.
        None => bx::command::status(&env, &mut out)?,
        Some(Command::Init { set, yes }) => bx::command::init(&env, &set, yes, &mut out)?,
        Some(Command::Plan) => bx::command::plan(&env, &mut out)?,
        Some(Command::Apply { yes }) => bx::command::apply(&env, yes, &mut out)?,
        Some(Command::Sync { yes }) => bx::command::sync(&env, yes, &mut out)?,
        Some(Command::Update {
            paths,
            yes,
            check,
            snooze,
            background,
        }) => {
            let mode = bx::command::UpdateMode::from_flags(yes, check, snooze, background);
            bx::command::update(&env, &paths, mode, &mut out)?
        }
        Some(Command::Doctor) => bx::command::doctor(&env, &mut out)?,
        Some(Command::Secret {
            action: SecretAction::List,
        }) => bx::command::secret_list(&env, &mut out)?,
        Some(Command::Add { target }) => {
            bx::command::add(&env, &std::env::current_dir()?, target.as_deref(), &mut out)?
        }
        Some(Command::Rm { target }) => {
            bx::command::rm(&env, &std::env::current_dir()?, target.as_deref(), &mut out)?
        }
        // Every command is named: one without a body is refused, not panicked
        // on, and a new one without an arm does not compile.
        Some(Command::ShellInit { .. }) => {
            bx::command::not_built("bx shell-init", &mut std::io::stderr())?
        }
        Some(Command::Complete { .. }) => {
            bx::command::not_built("bx __complete", &mut std::io::stderr())?
        }
        Some(Command::SelfUpgrade { .. }) => unreachable!("dispatched before the environment"),
    };
    out.flush()?;
    std::process::exit(exit.code());
}
