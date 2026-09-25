//! The bodies of `bx`, `bx init`, `bx plan`, `bx apply`, `bx sync`,
//! `bx doctor`, `bx add`, `bx rm` and `bx secret list`.
//!
//! Each loads the configuration, runs the one traversal in [`crate::plan`] —
//! or, for `doctor`, the read-only checks in [`crate::doctor`], for `add` and
//! `rm`, [`crate::adopt`], for `init`, [`crate::init`] before the
//! traversal, and for `sync`, [`crate::sync`] around it — writes the rendering
//! to the output it is
//! handed, and returns the exit status. `main` does nothing but call one of
//! them.

use std::io::Write;
use std::path::Path;

use crate::adopt::{self, Adoption, Removal};
use crate::config::resolve::Resolution;
use crate::config::target::Body;
use crate::doctor::{self, Probes, systemd};
use crate::init;
use crate::paths;
use crate::plan::{self, Env, Error, Inputs, Mode, Palette, Report, View};
use crate::report::Exit;
use crate::restore::Restored;
use crate::secret::{Passphrase, Unlock};
use crate::sync;

/// `bx doctor`: what a human should look at, changing nothing.
///
/// # Errors
///
/// Whatever loading the configuration returns, and [`Error::Output`] when
/// `out` cannot be written. A check that cannot ask what it needs — systemd's
/// user session unreachable — is a finding, not an error.
pub fn doctor(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    doctor_with(env, out, &systemd::Systemctl::default())
}

/// [`doctor`], asking systemd through `systemd`.
fn doctor_with(
    env: &Env,
    out: &mut dyn Write,
    systemd: &dyn systemd::Query,
) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let unit_dir = paths::systemd_user_dir_in(&env.home, env.xdg_config_home.as_deref());
    let report = doctor::run(
        &inputs,
        &Probes {
            unit_dir: &unit_dir,
            systemd,
        },
    );
    out.write_all(doctor::render(&report, &env.home).as_bytes())
        .map_err(Error::Output)?;
    Ok(doctor::exit(&report))
}

/// Bare `bx`: every target, unchanged ones included.
///
/// # Errors
///
/// Whatever loading or deciding returns, and [`Error::Output`] when `out`
/// cannot be written.
pub fn status(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    show(env, View::Status, out)
}

/// `bx plan`: what `apply` would do, writing nothing.
///
/// # Errors
///
/// As [`status`].
pub fn plan(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    show(env, View::Plan, out)
}

/// `bx apply`: recover, show the plan, obtain approval, and write.
///
/// Approval is `yes`, or the answer to a prompt when standard input is a
/// terminal. With neither, the plan is shown and nothing is written: a piped
/// `bx apply` must not write what nobody confirmed.
///
/// # Errors
///
/// [`Error::NeedsConfirmation`] when there is something to write, no `yes`,
/// and no terminal to ask on; [`Error::Prompt`] when the prompt fails; and
/// otherwise as [`status`], plus whatever recovery and the session return.
pub fn apply(env: &Env, yes: bool, out: &mut dyn Write) -> Result<Exit, Error> {
    apply_with(env, yes, out, &mut confirm)
}

/// Ask on the terminal whether to write.
///
/// The default is **no**: a prompt answered with a bare newline, or one whose
/// terminal goes away mid-question, must not be read as approval. Everything
/// around this — `yes`, no terminal, declined, accepted, a failing prompt — is
/// decided in [`apply_with`] and tested through its `ask` seam; this wrapper
/// exists only to put the question.
fn confirm() -> Result<bool, Error> {
    inquire::Confirm::new("Apply these changes?")
        .with_default(false)
        .prompt()
        .map_err(Error::Prompt)
}

/// [`apply`], with the question asked through `ask`.
fn apply_with(
    env: &Env,
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, Error> {
    let report = converge(env, yes, out, ask)?;
    Ok(plan::exit(&report, Mode::Apply))
}

/// `bx apply`'s body: load, show the plan, obtain approval, write, and say
/// what was done. Shared with [`sync`], so the change list `sync` asks about
/// is `apply`'s own.
fn converge(
    env: &Env,
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Report, Error> {
    let inputs = Inputs::load(env)?;
    let mut shown = false;
    let report = plan::run(&inputs, Mode::Apply, &mut |report| {
        emit(out, report, View::Plan, env)?;
        shown = true;
        if yes {
            Ok(true)
        } else if env.stdin_tty {
            ask()
        } else {
            Err(Error::NeedsConfirmation)
        }
    })?;

    if !shown {
        emit(out, &report, View::Plan, env)?;
    } else if let Some(outcome) = &report.recovered {
        writeln!(out, "{}", recovered(&report, outcome)).map_err(Error::Output)?;
    } else if report.executed {
        // Every row and every activation it cached: an activation's pending
        // step is a cache entry written, as a row's is a file.
        let written = report
            .actions()
            .into_iter()
            .filter(|action| action.is_pending())
            .count();
        writeln!(out, "Applied {written} change(s).").map_err(Error::Output)?;
        // A row apply stopped short of was announced as work and shown so; its
        // reason is known only now, so it is said now.
        for &at in &report.stopped {
            let change = &report.changes[at];
            writeln!(
                out,
                "  ! {}  stopped: {}",
                plan::escape(&change.target),
                plan::escape(change.note.as_deref().unwrap_or_default()),
            )
            .map_err(Error::Output)?;
        }
    } else {
        writeln!(out, "Nothing was written.").map_err(Error::Output)?;
    }
    Ok(report)
}

/// `bx sync`: fast-forward the config repo from its upstream, apply exactly as
/// `bx apply` does, and push what this machine committed.
///
/// [`sync::pull`] runs first and refuses a diverged branch, a missing
/// upstream, and a push that would carry a state file, all before anything is
/// changed. The apply is [`apply`]'s, with its one confirmation and its `yes`.
/// The push follows only when [`sync::may_push`] says the apply left nothing
/// undone: a declined apply, one that left a target in conflict or blocked,
/// or one that only recovered an interrupted session, pushes nothing, and the
/// next `sync` picks up where it stopped.
///
/// Exits as `bx apply` would over the same report, so a sync that applied
/// every pending change exits [`Exit::Converged`].
///
/// # Errors
///
/// Whatever [`sync::pull`] and [`sync::push`] return, and as [`apply`].
pub fn sync(env: &Env, yes: bool, out: &mut dyn Write) -> Result<Exit, sync::Error> {
    sync_with(env, yes, out, &sync::Git::new(env), &mut confirm)
}

/// [`sync`], through `git`, with the question asked through `ask`.
fn sync_with(
    env: &Env,
    yes: bool,
    out: &mut dyn Write,
    git: &sync::Git,
    ask: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, sync::Error> {
    let pulled = sync::pull(env, git)?;
    if pulled.fast_forwarded > 0 {
        writeln!(
            out,
            "Fast-forwarded {} by {} commit(s) from {}.",
            pulled.branch, pulled.fast_forwarded, pulled.upstream.short
        )
        .map_err(sync::Error::Output)?;
    }
    let report = converge(env, yes, out, ask)?;
    if pulled.ahead > 0 {
        if sync::may_push(&report) {
            sync::push(git, &pulled)?;
            writeln!(
                out,
                "Pushed {} commit(s) to {}.",
                pulled.ahead, pulled.upstream.short
            )
        } else {
            writeln!(
                out,
                "Pushed nothing: {} commit(s) wait for an apply that leaves nothing undone; run \
                 `bx sync` again.",
                pulled.ahead
            )
        }
        .map_err(sync::Error::Output)?;
    }
    Ok(plan::exit(&report, Mode::Apply))
}

/// `bx init`: create the repo when there is none, answer this account's unset
/// values, offer the config already on the machine, then plan and apply
/// exactly as `bx apply` does.
///
/// Questions are asked only when standard input is a terminal and `yes` is
/// not given; see [`init::prepare`]. The plan and its approval are
/// [`apply`]'s, so `yes` is the same approval, and without it or a terminal
/// nothing pending is written.
///
/// # Errors
///
/// Whatever [`init::prepare`] returns, then as [`apply`].
pub fn init(
    env: &Env,
    sets: &[String],
    yes: bool,
    out: &mut dyn Write,
) -> Result<Exit, init::Error> {
    init_with(env, sets, yes, out, &mut init::Terminal, &mut confirm)
}

/// [`init`], with its questions asked through `ask` and `confirm`.
fn init_with(
    env: &Env,
    sets: &[String],
    yes: bool,
    out: &mut dyn Write,
    ask: &mut dyn init::Ask,
    confirm: &mut dyn FnMut() -> Result<bool, Error>,
) -> Result<Exit, init::Error> {
    let prepared = init::prepare(env, sets, env.stdin_tty && !yes, ask)?;
    let mut text = String::new();
    if let Some(repo) = &prepared.created {
        text.push_str(&format!(
            "Created the config repo {} with bx.toml.\n",
            paths::to_portable(repo, &env.home)
        ));
    }
    if let Some(local) = &prepared.saved {
        text.push_str(&format!(
            "Saved this account's answers to {}.\n",
            paths::to_portable(local, &env.home)
        ));
    }
    for row in &prepared.adopted {
        text.push_str(&adoption_row(row));
    }
    if prepared.adoption_deferred {
        text.push_str(
            "Offered nothing to adopt: an interrupted session must be recovered first, \
             as the plan shows. Run `bx init` again once it is.\n",
        );
    }
    out.write_all(text.as_bytes())
        .map_err(init::Error::Output)?;
    Ok(apply_with(env, yes, out, confirm)?)
}

/// What an `apply` that recovered an interrupted session, and did nothing else,
/// says it did.
fn recovered(report: &Report, outcome: &crate::recover::Outcome) -> String {
    use crate::recover::Outcome;

    let done = match outcome {
        Outcome::RolledBack { undone } => {
            format!("Rolled back {undone} write(s) from an interrupted session")
        }
        Outcome::Recorded { entries } => {
            format!("Recorded {entries} write(s) an interrupted session made")
        }
        // A blocked recovery is an error, never an outcome `apply` reports.
        Outcome::Nothing | Outcome::Blocked { .. } => {
            if report
                .interrupted
                .as_ref()
                .is_some_and(|interrupted| interrupted.unreadable)
            {
                "Set aside the journal bx could not read".to_string()
            } else {
                "Found nothing left to recover".to_string()
            }
        }
    };
    format!("{done}; nothing else was applied; run `bx plan` again.")
}

/// `bx secret list`: every declared secret, its ciphertext, and whether this
/// account can decrypt it now.
///
/// The one command that may ask for an identity's passphrase, and only when
/// standard input is a terminal; without one a locked identity is reported as
/// locked. Each secret is checked on its own, so a locked identity is asked
/// for once per secret: nothing keeps a passphrase between them. Nothing is
/// written.
///
/// Exits [`Exit::Converged`] when every secret can be decrypted, and
/// [`Exit::Pending`] when one cannot.
///
/// # Errors
///
/// Whatever loading returns, and [`Error::Output`] when `out` cannot be
/// written. A secret that cannot be read or decrypted is a row, not an error.
pub fn secret_list(env: &Env, out: &mut dyn Write) -> Result<Exit, Error> {
    secret_list_with(env, out, &mut ask_passphrase)
}

/// Ask on the terminal for an identity's passphrase, masked. A prompt that
/// fails or is cancelled is no passphrase, and the identity stays locked.
fn ask_passphrase(shown: &str) -> Option<Passphrase> {
    inquire::Password::new(&format!("Passphrase for {shown}:"))
        .without_confirmation()
        .prompt()
        .ok()
        .map(Passphrase::from)
}

/// [`secret_list`], with the passphrase asked through `ask`.
fn secret_list_with(
    env: &Env,
    out: &mut dyn Write,
    ask: &mut dyn FnMut(&str) -> Option<Passphrase>,
) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let secrets = &inputs.resolved().secrets;
    let identity = secrets.identity_path(inputs.home());
    let shown = secrets.identity_spelling();

    let mut text = String::new();
    let mut all = true;
    for (declared, resolution) in inputs.declared_targets() {
        let Body::Secret(written) = &declared.body else {
            continue;
        };
        let (target, ciphertext, status) = match resolution {
            Resolution::Blocked(entry) => (
                entry.key.clone(),
                written.display().to_string(),
                Err(format!("blocked: {}", entry.hint)),
            ),
            Resolution::Ready(target) => {
                let Body::Secret(rel) = &target.body else {
                    unreachable!("substitution keeps a secret a secret");
                };
                let status = plan::read_repo_file(target, inputs.repo(), rel)
                    .map_err(|error| format!("unreadable: {error}"))
                    .and_then(|bytes| {
                        let unlock = if env.stdin_tty {
                            Unlock::Ask(&mut *ask)
                        } else {
                            Unlock::Never
                        };
                        crate::secret::decrypt(&bytes, &identity, shown, unlock)
                            .map_err(|refusal| format!("not decryptable: {refusal}"))
                    });
                (
                    target.path.as_str().to_string(),
                    rel.display().to_string(),
                    status.map(drop),
                )
            }
        };
        all &= status.is_ok();
        let status = status.map_or_else(|why| why, |()| "decryptable".to_string());
        text.push_str(&format!("  {target}  {ciphertext}  {status}\n"));
    }
    if text.is_empty() {
        text.push_str("No secrets are declared.\n");
    }
    out.write_all(text.as_bytes()).map_err(Error::Output)?;
    Ok(if all { Exit::Converged } else { Exit::Pending })
}

/// `bx add PATH`: adopt a file, or every regular file under a directory, byte
/// for byte.
///
/// Prints one row per path: `+` adopted, `=` already managed, `~` already
/// declared and now owned, `-` passed over inside a directory, `!` refused.
/// Exits 0 when everything named was adopted or already managed, and 2 when
/// something was refused.
///
/// # Errors
///
/// [`adopt::Error::NoPath`] without a path, and whatever locating, loading
/// or adopting returns.
pub fn add(
    env: &Env,
    cwd: &Path,
    path: Option<&str>,
    out: &mut dyn Write,
) -> Result<Exit, adopt::Error> {
    let path = path.ok_or(adopt::Error::NoPath("add"))?;
    let target = adopt::locate(path, cwd, &env.home)?;
    let ctx = adopt::Context::load(env)?;
    let rows = adopt::add(&ctx, &target)?;
    let mut text = String::new();
    for row in &rows {
        text.push_str(&adoption_row(row));
    }
    let adopted = rows
        .iter()
        .filter(|row| matches!(row, Adoption::Adopt { .. }))
        .count();
    text.push_str(&format!(
        "Adopted {adopted} file(s); run `bx plan` to see the machine against the repo.\n"
    ));
    out.write_all(text.as_bytes())
        .map_err(adopt::Error::Output)?;
    Ok(if rows.iter().any(Adoption::needs_attention) {
        Exit::Pending
    } else {
        Exit::Converged
    })
}

/// One `add` row, with its note and any warning on the lines below it.
fn adoption_row(row: &Adoption) -> String {
    let target = row.target();
    match row {
        Adoption::Adopt {
            body,
            reuse,
            warnings,
            ..
        } => {
            let how = if *reuse {
                "declared, reusing"
            } else {
                "copied to"
            };
            let mut line = format!("  + {target}  ({how} {})\n", body.display());
            for warning in warnings {
                line.push_str(&format!(
                    "    warning: {warning}; adopted as written, and bx will write it back as is\n"
                ));
            }
            line
        }
        Adoption::Own { .. } => format!("  ~ {target}  already declared; bx now owns it\n"),
        Adoption::Unchanged { .. } => format!("  = {target}  already managed\n"),
        Adoption::Skipped { note, .. } => format!("  - {target}  skipped: {note}\n"),
        Adoption::Refused { note, .. } => format!("  ! {target}  {note}\n"),
    }
}

/// `bx rm PATH`: stop managing a target, or every target beneath a directory,
/// restoring what bx displaced.
///
/// Exits 0 when everything was handed back, or nothing was managed there, and
/// 2 when a conflict left something as it was.
///
/// # Errors
///
/// [`adopt::Error::NoPath`] without a path, and whatever locating, loading
/// or restoring returns.
pub fn rm(
    env: &Env,
    cwd: &Path,
    path: Option<&str>,
    out: &mut dyn Write,
) -> Result<Exit, adopt::Error> {
    let path = path.ok_or(adopt::Error::NoPath("rm"))?;
    let target = adopt::locate(path, cwd, &env.home)?;
    let ctx = adopt::Context::load(env)?;
    let removals = adopt::rm(&ctx, &target)?;
    let mut text = String::new();
    if removals.is_empty() {
        text.push_str(&format!("{target} is not managed by bx; nothing to do.\n"));
    }
    for removal in &removals {
        text.push_str(&removal_row(removal, ctx.home()));
    }
    out.write_all(text.as_bytes())
        .map_err(adopt::Error::Output)?;
    Ok(
        if removals
            .iter()
            .any(|removal| removal.restored.is_conflict())
        {
            Exit::Pending
        } else {
            Exit::Converged
        },
    )
}

/// One `rm` row.
fn removal_row(removal: &Removal, home: &Path) -> String {
    let target = removal.restored.target();
    let did = match &removal.restored {
        Restored::Reverted { .. } => "put back the file bx replaced".to_string(),
        Restored::Removed { .. } => "removed the file bx created".to_string(),
        Restored::AlreadyGone { .. } => "was already gone".to_string(),
        Restored::Unmanaged { .. } => "left as it is; bx never wrote it".to_string(),
        Restored::Conflict { note, .. } => {
            return format!("  ! {target}  {note}; still managed\n");
        }
    };
    let mut line = format!("  - {target}  {did}");
    for layer in &removal.undeclared {
        line.push_str(&format!(
            "; no longer declared in {}",
            crate::paths::to_portable(layer, home)
        ));
    }
    for body in &removal.bodies {
        line.push_str(&format!("; {} stays in the repo", body.display()));
    }
    line.push('\n');
    line
}

/// Load, decide read-only, and show.
fn show(env: &Env, view: View, out: &mut dyn Write) -> Result<Exit, Error> {
    let inputs = Inputs::load(env)?;
    let report = plan::run(&inputs, Mode::Plan, &mut |_| Ok(false))?;
    emit(out, &report, view, env)?;
    Ok(plan::exit(&report, Mode::Plan))
}

/// Write the rendering of `report`, coloured as the environment allows.
fn emit(out: &mut dyn Write, report: &Report, view: View, env: &Env) -> Result<(), Error> {
    let palette = Palette::resolve(env.no_color, env.stdout_tty);
    out.write_all(plan::render(report, view, palette, &env.home).as_bytes())
        .map_err(Error::Output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::{env, inline, seed};
    use crate::testing::guarded_home;

    fn text(out: &[u8]) -> &str {
        std::str::from_utf8(out).expect("UTF-8 output")
    }

    fn never() -> Result<bool, Error> {
        panic!("nothing should have been asked")
    }

    /// Set on the child that actually calls [`confirm`].
    const CONFIRM_CHILD: &str = "BX_TEST_CONFIRM_CHILD";

    #[test]
    #[ignore = "spawned by the test below; it must run with a stdin that is not a terminal"]
    fn confirm_child() {
        // Without the variable this is someone running `--ignored` by hand,
        // possibly from a terminal, where `prompt` would block on a question
        // nobody is there to answer. Do nothing rather than hang.
        if std::env::var_os(CONFIRM_CHILD).is_none() {
            return;
        }
        let answer = confirm();
        // `Ok(_)` is what both surviving mutants return, so this is the
        // assertion that kills them: with no terminal there is no answer, and
        // a wrapper that invents one would approve a write nobody confirmed.
        assert!(
            matches!(answer, Err(Error::Prompt(inquire::InquireError::NotTTY))),
            "{answer:?}"
        );
    }

    #[test]
    fn confirm_without_a_terminal_is_a_prompt_error_and_never_an_answer() {
        // P42R1 "Untested line: the `inquire` confirmation call". `cargo
        // mutants` reported `confirm -> Ok(true)` and `-> Ok(false)` as missed.
        // The earlier round recorded it as needing a pseudo-terminal and a
        // dependency this pull request does not add, and left it. It does not:
        // the question is what `confirm` does when there is NO terminal, and
        // that is reachable by giving it one that certainly is not.
        //
        // Run in a child rather than here, because `inquire` reads the
        // process's stdin and a test must not depend on how `cargo test` was
        // invoked. In CI stdin is already not a terminal; on a developer's
        // machine it is, and this test would hang waiting for an answer. The
        // child's stdin is `/dev/null` either way, which is the same seam
        // `plan::tests`'s crash harness uses to fix a child's environment.
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "command::tests::confirm_child",
            ])
            .env(CONFIRM_CHILD, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn the confirmation child");

        assert!(
            output.status.success(),
            "the child's assertion failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        // The child really ran the case, rather than being filtered out and
        // reporting success over an empty run.
        let ran = String::from_utf8_lossy(&output.stdout);
        assert!(
            ran.contains("1 passed") && ran.contains("0 failed"),
            "the child ran no test: {ran}"
        );
    }

    #[test]
    fn plan_exits_zero_when_converged_and_two_when_pending() {
        let home = guarded_home();
        seed(home.path(), "");
        let mut out = Vec::new();
        let exit = plan(&env(home.path()), &mut out).expect("plan");
        assert_eq!(exit, Exit::Converged);
        assert_eq!(
            text(&out),
            "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
        );

        seed(home.path(), &inline("~/.a", "a\\n"));
        let mut out = Vec::new();
        let exit = plan(&env(home.path()), &mut out).expect("plan");
        assert_eq!(exit, Exit::Pending);
        assert!(text(&out).starts_with("  + ~/.a  (~/.config/bx/bx.toml:1)\n"));
        assert!(!home.child(".a").exists());
    }

    #[test]
    fn status_shows_what_plan_hides() {
        let home = guarded_home();
        home.write(".a", "a\n");
        seed(home.path(), &inline("~/.a", "a\\n"));

        let mut shown = Vec::new();
        let exit = status(&env(home.path()), &mut shown).expect("status");
        assert_eq!(exit, Exit::Converged);
        assert!(text(&shown).contains("  = ~/.a  ("), "{}", text(&shown));

        let mut hidden = Vec::new();
        let exit = plan(&env(home.path()), &mut hidden).expect("plan");
        assert_eq!(exit, Exit::Converged);
        assert!(!text(&hidden).contains("~/.a"), "{}", text(&hidden));
    }

    #[test]
    fn decision_4_apply_with_yes_writes_without_asking() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let mut out = Vec::new();

        let exit = apply_with(&env(home.path()), true, &mut out, &mut never).expect("apply");

        assert_eq!(exit, Exit::Converged);
        assert!(text(&out).starts_with("  + ~/.a"), "{}", text(&out));
        assert!(
            text(&out).ends_with("Applied 1 change(s).\n"),
            "{}",
            text(&out)
        );
        assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");

        let exit = plan(&env(home.path()), &mut Vec::new()).expect("plan");
        assert_eq!(exit, Exit::Converged);
    }

    #[test]
    fn applied_counts_an_activation_capture_as_a_change() {
        // V1: the interactive file, its `~/.zshrc` region, and the capture.
        let home = guarded_home();
        home.write(".zshrc", "user\n");
        let stub = home.child("stub");
        std::fs::write(&stub, "#!/bin/sh\nprintf 'stub_hook() { :; }\\n'\n").expect("the stub");
        std::fs::set_permissions(
            &stub,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .expect("executable");
        seed(
            home.path(),
            &format!(
                "[[activation]]\nname = \"stub\"\ncommand = [\"{}\"]\n",
                stub.display()
            ),
        );
        let mut out = Vec::new();

        let exit = apply_with(&env(home.path()), true, &mut out, &mut never).expect("apply");

        assert_eq!(exit, Exit::Converged);
        assert!(
            text(&out).contains("  + activation `stub`: run twice, output agreed; cached\n"),
            "{}",
            text(&out)
        );
        assert!(
            text(&out).ends_with("Applied 3 change(s).\n"),
            "{}",
            text(&out)
        );

        // Recorded, so the next apply has nothing to count.
        let mut again = Vec::new();
        let exit = apply_with(&env(home.path()), true, &mut again, &mut never).expect("apply");
        assert_eq!(exit, Exit::Converged);
        assert!(!text(&again).contains("Applied"), "{}", text(&again));
    }

    #[test]
    fn an_external_apply_stopped_short_of_is_named_with_why_and_exits_pending() {
        let home = guarded_home();
        // The declared url leads nowhere that can be fetched from.
        std::fs::write(
            home.child(".gitconfig"),
            format!(
                "[url \"file://{}/nowhere/\"]\n\tinsteadOf = https://example.invalid/\n",
                home.path().display()
            ),
        )
        .expect("~/.gitconfig");
        seed(
            home.path(),
            "[[external]]\npath = \"~/.x\"\nurl = \"https://example.invalid/x\"\n\
             rev = \"0e810e5afa27acbd074398eefbe28d13005dbc15\"\n",
        );
        let mut out = Vec::new();

        let exit = apply_with(&env(home.path()), true, &mut out, &mut never).expect("apply");

        assert_eq!(exit, Exit::Pending);
        let shown = text(&out);
        assert!(
            shown.contains("Applied 0 change(s).\n  ! ~/.x  stopped: "),
            "{shown}"
        );
        assert!(!home.child(".x").exists());
    }

    #[test]
    fn decision_4_apply_without_yes_or_a_terminal_shows_the_plan_and_refuses() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let mut out = Vec::new();

        let error = apply_with(&env(home.path()), false, &mut out, &mut never)
            .expect_err("no confirmation");

        assert!(matches!(error, Error::NeedsConfirmation), "{error:?}");
        assert!(error.to_string().contains("rerun with --yes"), "{error}");
        assert!(text(&out).starts_with("  + ~/.a"), "the plan was not shown");
        assert!(!home.child(".a").exists(), "written without confirmation");
    }

    #[test]
    fn decision_4_apply_on_a_terminal_asks_and_honours_the_answer() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let tty = Env {
            stdin_tty: true,
            ..env(home.path())
        };

        let mut out = Vec::new();
        let mut asked = 0;
        let exit = apply_with(&tty, false, &mut out, &mut || {
            asked += 1;
            Ok(false)
        })
        .expect("a declined apply");
        assert_eq!(exit, Exit::Pending, "a declined apply is still pending");
        assert_eq!(asked, 1);
        assert!(
            text(&out).ends_with("Nothing was written.\n"),
            "{}",
            text(&out)
        );
        assert!(!home.child(".a").exists());

        let exit = apply_with(&tty, false, &mut Vec::new(), &mut || Ok(true)).expect("apply");
        assert_eq!(exit, Exit::Converged);
        assert!(home.child(".a").exists());
    }

    #[test]
    fn apply_with_nothing_to_write_asks_nothing_and_needs_no_confirmation() {
        let home = guarded_home();
        home.write(".mine", "mine\n");
        seed(home.path(), &inline("~/.mine", "bx\\n"));
        let mut out = Vec::new();

        let exit = apply_with(&env(home.path()), false, &mut out, &mut never).expect("apply");

        assert_eq!(exit, Exit::Pending, "a conflict still needs a human");
        assert!(text(&out).starts_with("  ! ~/.mine"), "{}", text(&out));
        assert!(text(&out).ends_with(" unchanged.\n"), "{}", text(&out));
        assert_eq!(std::fs::read(home.child(".mine")).expect("kept"), b"mine\n");
    }

    #[test]
    fn a_failing_question_stops_apply() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let tty = Env {
            stdin_tty: true,
            ..env(home.path())
        };

        let error = apply_with(&tty, false, &mut Vec::new(), &mut || {
            Err(Error::NeedsConfirmation)
        })
        .expect_err("the question failed");

        assert!(matches!(error, Error::NeedsConfirmation), "{error:?}");
        assert!(!home.child(".a").exists());
    }

    #[test]
    fn init_on_a_fresh_machine_creates_the_repo_applies_and_converges_on_a_second_run() {
        use crate::init::tests::Silent;

        let home = guarded_home();
        let mut out = Vec::new();
        let exit = init_with(
            &env(home.path()),
            &[],
            false,
            &mut out,
            &mut Silent,
            &mut never,
        )
        .expect("init");
        assert_eq!(exit, Exit::Converged);
        assert_eq!(
            text(&out),
            "Created the config repo ~/.config/bx with bx.toml.\n\
             Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
        );

        let mut out = Vec::new();
        let exit = init_with(
            &env(home.path()),
            &[],
            false,
            &mut out,
            &mut Silent,
            &mut never,
        )
        .expect("init");
        assert_eq!(exit, Exit::Converged);
        assert_eq!(
            text(&out),
            "Plan: 0 to create, 0 to modify, 0 conflict, 0 blocked, 0 unchanged.\n"
        );
    }

    #[test]
    fn init_answers_adopts_then_applies_with_apply_s_approval_rule() {
        use crate::init::tests::Script;

        let home = guarded_home();
        seed(
            home.path(),
            &format!(
                "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n\n{}",
                inline("~/.greeting", "hi {{who}}\\n")
            ),
        );
        home.write(".zshrc", "z\n");
        let tty = Env {
            stdin_tty: true,
            ..env(home.path())
        };
        let mut script = Script {
            answers: vec!["there"],
            pick: vec!["~/.zshrc"],
            ..Script::default()
        };

        let mut out = Vec::new();
        let mut asked = 0;
        let exit = init_with(&tty, &[], false, &mut out, &mut script, &mut || {
            asked += 1;
            Ok(true)
        })
        .expect("init");

        assert_eq!(exit, Exit::Converged);
        assert_eq!(asked, 1, "the plan was confirmed once, as bx apply asks");
        assert!(
            text(&out).starts_with(
                "Saved this account's answers to ~/.local/state/bx/local.toml.\n  + ~/.zshrc  \
                 (copied to files/.zshrc)\n  + ~/.greeting"
            ),
            "{}",
            text(&out)
        );
        assert!(
            text(&out).ends_with("Applied 1 change(s).\n"),
            "{}",
            text(&out)
        );
        assert_eq!(
            std::fs::read(home.child(".greeting")).expect("applied"),
            b"hi there\n"
        );

        let exit = init_with(
            &tty,
            &[],
            false,
            &mut Vec::new(),
            &mut Script::default(),
            &mut || panic!("nothing to confirm"),
        )
        .expect("init");
        assert_eq!(exit, Exit::Converged);
    }

    #[test]
    fn init_says_it_left_adoption_for_later_while_a_session_is_interrupted() {
        use crate::init::tests::Silent;
        use crate::journal::{Session, SessionKind};

        let home = guarded_home();
        seed(home.path(), "");
        home.write(".zshrc", "z\n");
        let state = crate::state::StateDir::resolve(home.path());
        drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
        let tty = Env {
            stdin_tty: true,
            ..env(home.path())
        };

        let mut out = Vec::new();
        init_with(&tty, &[], false, &mut out, &mut Silent, &mut || Ok(true)).expect("init");

        assert!(
            text(&out).starts_with(
                "Offered nothing to adopt: an interrupted session must be recovered first, \
                 as the plan shows. Run `bx init` again once it is.\n"
            ),
            "{}",
            text(&out)
        );
    }

    #[test]
    fn init_without_yes_or_a_terminal_shows_the_plan_and_writes_nothing_pending() {
        use crate::init::tests::Silent;

        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));

        let error = init_with(
            &env(home.path()),
            &[],
            false,
            &mut Vec::new(),
            &mut Silent,
            &mut never,
        )
        .expect_err("no confirmation");
        assert!(
            matches!(error, init::Error::Plan(Error::NeedsConfirmation)),
            "{error:?}"
        );
        assert!(!home.child(".a").exists());

        let tty = Env {
            stdin_tty: true,
            ..env(home.path())
        };
        let exit = init_with(&tty, &[], true, &mut Vec::new(), &mut Silent, &mut never)
            .expect("--yes asks nothing, on a terminal too");
        assert_eq!(exit, Exit::Converged);
        assert!(home.child(".a").exists());

        let fresh = guarded_home();
        assert!(matches!(
            init_with(
                &env(fresh.path()),
                &[],
                true,
                &mut Refusing,
                &mut Silent,
                &mut never
            ),
            Err(init::Error::Output(_))
        ));
    }

    #[test]
    fn decision_18_an_apply_that_only_recovered_says_what_it_did() {
        use crate::recover::{Interrupted, Outcome};

        let report = Report::default();
        assert_eq!(
            recovered(&report, &Outcome::RolledBack { undone: 2 }),
            "Rolled back 2 write(s) from an interrupted session; nothing else was applied; \
             run `bx plan` again."
        );
        assert_eq!(
            recovered(&report, &Outcome::Recorded { entries: 1 }),
            "Recorded 1 write(s) an interrupted session made; nothing else was applied; run \
             `bx plan` again."
        );
        assert!(
            recovered(&report, &Outcome::Nothing).starts_with("Found nothing left to recover;")
        );

        let unreadable = Report {
            interrupted: Some(Interrupted {
                kind: crate::journal::SessionKind::Apply,
                journal: std::path::PathBuf::from("/state/journal.mpk"),
                complete: false,
                unreadable: true,
                unfinished: Vec::new(),
            }),
            ..Report::default()
        };
        assert!(
            recovered(&unreadable, &Outcome::Nothing)
                .starts_with("Set aside the journal bx could not read;")
        );
    }

    #[test]
    fn a_missing_repo_is_an_error_for_every_command() {
        let home = guarded_home();
        let env = env(home.path());

        assert!(matches!(
            status(&env, &mut Vec::new()),
            Err(Error::RepoMissing(_))
        ));
        assert!(matches!(
            plan(&env, &mut Vec::new()),
            Err(Error::RepoMissing(_))
        ));
        assert!(matches!(
            apply(&env, true, &mut Vec::new()),
            Err(Error::RepoMissing(_))
        ));
    }

    /// A secret target at `~/{name}` whose ciphertext is `secrets/{name}.age`.
    fn secret_target(name: &str) -> String {
        format!(
            "[[target]]\npath = \"~/{name}\"\nsecret = \"secrets/{name}.age\"\nmode = \"0600\"\n"
        )
    }

    /// Encrypt `plaintext` to `recipient` as the repo's `secrets/{name}.age`.
    fn seal(home: &crate::testing::GuardedHome, name: &str, recipient: &str) {
        let path = home.child(format!(".config/bx/secrets/{name}.age"));
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("secrets/");
        std::fs::write(path, crate::secret::tests::encrypt_to(recipient, b"x\n"))
            .expect("the ciphertext");
    }

    fn no_passphrase(_: &str) -> Option<Passphrase> {
        panic!("nothing should have asked for a passphrase")
    }

    #[test]
    fn d1_secret_list_reports_each_secret_and_whether_it_decrypts() {
        use crate::secret::tests::{LOCKED_SSH_PUB, SSH_KEY, SSH_PUB};

        let home = guarded_home();
        home.write(".ssh/id_ed25519", SSH_KEY);
        seal(&home, "one", SSH_PUB);
        seal(&home, "two", LOCKED_SSH_PUB);
        let layer = [
            secret_target("one"),
            inline("~/.plain", "a\\n"),
            secret_target("two"),
            secret_target("absent"),
            "[[value]]\nname = \"who\"\nkind = \"string\"\nrequired = true\n\
             [[target]]\npath = \"~/.w\"\nsecret = \"secrets/{{who}}.age\"\nmode = \"0600\"\n"
                .to_string(),
        ]
        .concat();
        seed(home.path(), &layer);

        let mut out = Vec::new();
        let exit =
            secret_list_with(&env(home.path()), &mut out, &mut no_passphrase).expect("listed");

        assert_eq!(exit, Exit::Pending);
        let lines: Vec<&str> = text(&out).lines().collect();
        assert_eq!(lines.len(), 4, "{}", text(&out));
        assert_eq!(lines[0], "  ~/one  secrets/one.age  decryptable");
        assert!(
            lines[1].starts_with(
                "  ~/two  secrets/two.age  not decryptable: the identity ~/.ssh/id_ed25519 is \
                 not one this secret is encrypted to"
            ),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].starts_with("  ~/absent  secrets/absent.age  unreadable: "),
            "{}",
            lines[2]
        );
        assert!(
            lines[3].starts_with("  ~/.w  secrets/{{who}}.age  blocked: "),
            "{}",
            lines[3]
        );
        assert!(!text(&out).contains("x\n  "), "no plaintext is printed");
    }

    #[test]
    fn d1_secret_list_asks_for_a_locked_identity_only_on_a_terminal_and_per_secret() {
        use crate::secret::tests::{LOCKED_PASSPHRASE, LOCKED_SSH_KEY, LOCKED_SSH_PUB};

        let home = guarded_home();
        home.write(".ssh/id_ed25519", LOCKED_SSH_KEY);
        seal(&home, "one", LOCKED_SSH_PUB);
        seal(&home, "two", LOCKED_SSH_PUB);
        seed(
            home.path(),
            &[secret_target("one"), secret_target("two")].concat(),
        );

        let mut out = Vec::new();
        let exit =
            secret_list_with(&env(home.path()), &mut out, &mut no_passphrase).expect("listed");
        assert_eq!(
            exit,
            Exit::Pending,
            "no terminal: locked, and nothing asked"
        );
        assert!(
            text(&out).contains(
                "  ~/one  secrets/one.age  not decryptable: the identity \
                 ~/.ssh/id_ed25519 is locked by a passphrase"
            ),
            "{}",
            text(&out)
        );

        let tty = Env {
            stdin_tty: true,
            ..env(home.path())
        };
        let mut asked = Vec::new();
        let mut out = Vec::new();
        let exit = secret_list_with(&tty, &mut out, &mut |shown| {
            asked.push(shown.to_string());
            Some(Passphrase::from(LOCKED_PASSPHRASE))
        })
        .expect("listed");
        assert_eq!(exit, Exit::Converged, "{}", text(&out));
        assert_eq!(
            text(&out),
            "  ~/one  secrets/one.age  decryptable\n  ~/two  secrets/two.age  decryptable\n"
        );
        assert_eq!(
            asked,
            ["~/.ssh/id_ed25519", "~/.ssh/id_ed25519"],
            "asked once per secret: nothing keeps a passphrase"
        );
    }

    #[test]
    fn d1_secret_list_with_no_secrets_says_so_and_converges() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let mut out = Vec::new();
        let exit = secret_list(&env(home.path()), &mut out).expect("listed");
        assert_eq!(exit, Exit::Converged);
        assert_eq!(text(&out), "No secrets are declared.\n");

        assert!(matches!(
            secret_list(&env(home.path()), &mut Refusing),
            Err(Error::Output(_))
        ));
    }

    /// Set on the child that actually calls [`ask_passphrase`].
    const PASSPHRASE_CHILD: &str = "BX_TEST_PASSPHRASE_CHILD";

    #[test]
    #[ignore = "spawned by the test below; it must run with a stdin that is not a terminal"]
    fn passphrase_child() {
        if std::env::var_os(PASSPHRASE_CHILD).is_none() {
            return;
        }
        assert!(
            ask_passphrase("~/.ssh/id_ed25519").is_none(),
            "a prompt with no terminal is no passphrase"
        );
    }

    #[test]
    fn a_passphrase_prompt_without_a_terminal_is_no_passphrase() {
        // As `confirm_without_a_terminal_is_a_prompt_error_and_never_an_answer`:
        // in a child whose stdin is certainly not a terminal, so this never
        // hangs on a developer's machine.
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "command::tests::passphrase_child",
            ])
            .env(PASSPHRASE_CHILD, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn the passphrase child");

        let ran = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{ran}");
        assert!(
            ran.contains("1 passed") && ran.contains("0 failed"),
            "the child ran no test: {ran}"
        );
    }

    /// A writer that refuses every byte.
    struct Refusing;

    impl Write for Refusing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("refused"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_output_that_cannot_be_written_is_an_error() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));

        assert!(matches!(
            plan(&env(home.path()), &mut Refusing),
            Err(Error::Output(_))
        ));
        assert!(matches!(
            apply_with(&env(home.path()), true, &mut Refusing, &mut never),
            Err(Error::Output(_))
        ));
        assert!(!home.child(".a").exists(), "written with no plan shown");
    }

    /// A systemd whose every unit is loaded, enabled and failed.
    struct AllFailed;

    impl systemd::Query for AllFailed {
        fn show(&self, names: &[String]) -> Result<Vec<systemd::State>, systemd::Unreachable> {
            Ok(vec![
                systemd::State {
                    load: "loaded".into(),
                    active: "failed".into(),
                    file: "enabled".into(),
                    need_reload: false,
                };
                names.len()
            ])
        }
    }

    #[test]
    fn doctor_checks_written_units_in_the_xdg_unit_directory() {
        let home = guarded_home();
        let xdg = home.child("xdg");
        let env = Env {
            xdg_config_home: Some(xdg.clone().into_os_string()),
            ..env(home.path())
        };
        std::fs::create_dir_all(xdg.join("bx")).expect("the config repo");
        std::fs::write(
            xdg.join("bx/bx.toml"),
            "[[target]]\npath = \"~/xdg/systemd/user/a.service\"\ncontent = \"x\"\n\n\
             [[target]]\npath = \"~/.config/systemd/user/b.service\"\ncontent = \"x\"\n",
        )
        .expect("bx.toml");
        home.write("xdg/systemd/user/a.service", "x");
        home.write(".config/systemd/user/b.service", "x");

        let mut out = Vec::new();
        let exit = doctor_with(&env, &mut out, &AllFailed).expect("doctor");

        assert_eq!(exit, Exit::Pending);
        assert_eq!(
            text(&out),
            "  ! ~/xdg/systemd/user/a.service  (~/xdg/bx/bx.toml:1) has failed; see `systemctl \
             --user status a.service`\nDoctor: 1 finding(s).\n",
            "only the unit in $XDG_CONFIG_HOME/systemd/user is checked"
        );
    }

    #[test]
    fn doctor_with_nothing_to_check_is_converged_and_needs_no_systemd() {
        let home = guarded_home();
        seed(
            home.path(),
            &inline("~/.config/systemd/user/a.service", "x"),
        );

        let mut out = Vec::new();
        let exit = doctor(&env(home.path()), &mut out).expect("doctor");

        assert_eq!(exit, Exit::Converged);
        assert_eq!(text(&out), "Doctor: 0 finding(s).\n");
    }

    #[test]
    fn doctor_without_a_repo_or_an_output_is_an_error() {
        let home = guarded_home();
        assert!(matches!(
            doctor(&env(home.path()), &mut Vec::new()),
            Err(Error::RepoMissing(_))
        ));

        seed(home.path(), "");
        assert!(matches!(
            doctor(&env(home.path()), &mut Refusing),
            Err(Error::Output(_))
        ));
    }

    #[test]
    fn colour_follows_the_terminal_and_no_color() {
        let home = guarded_home();
        seed(home.path(), &inline("~/.a", "a\\n"));
        let rendered = |env: &Env| {
            let mut out = Vec::new();
            plan(env, &mut out).expect("plan");
            String::from_utf8(out).expect("UTF-8")
        };
        let terminal = Env {
            stdout_tty: true,
            ..env(home.path())
        };
        let no_color = Env {
            no_color: true,
            ..terminal.clone()
        };

        assert!(rendered(&terminal).contains('\x1b'));
        assert!(!rendered(&no_color).contains('\x1b'));
        assert!(!rendered(&env(home.path())).contains('\x1b'));
    }

    mod sync_command {
        use super::*;
        use crate::sync;
        use crate::sync::tests::{cloned, commit_all, git, other, rev, run};

        /// Commit `layer` as `bx.toml` on a second machine and push it.
        fn publish_elsewhere(home: &crate::testing::GuardedHome, layer: &str) -> String {
            let other = other(home);
            std::fs::write(other.join("bx.toml"), layer).expect("bx.toml");
            commit_all(home.path(), &other, "elsewhere");
            run(home.path(), &other, &["push", "--quiet"]);
            rev(home.path(), &other, "HEAD")
        }

        #[test]
        fn sync_fast_forwards_applies_and_converges_then_a_second_run_does_nothing() {
            let home = guarded_home();
            let repo = cloned(&home, "");
            let theirs = publish_elsewhere(&home, &inline("~/.a", "a\\n"));
            let env = env(home.path());

            let mut out = Vec::new();
            let exit =
                sync_with(&env, true, &mut out, &git(home.path()), &mut never).expect("sync");

            assert_eq!(exit, Exit::Converged, "{}", text(&out));
            assert!(
                text(&out).starts_with(
                    "Fast-forwarded master by 1 commit(s) from origin/master.\n  + ~/.a"
                ),
                "{}",
                text(&out)
            );
            assert!(
                text(&out).ends_with("Applied 1 change(s).\n"),
                "{}",
                text(&out)
            );
            assert_eq!(std::fs::read(home.child(".a")).expect("written"), b"a\n");
            assert_eq!(rev(home.path(), &repo, "HEAD"), theirs);

            let mut again = Vec::new();
            let exit = sync_with(&env, false, &mut again, &git(home.path()), &mut never)
                .expect("a second sync");
            assert_eq!(exit, Exit::Converged);
            assert!(!text(&again).contains("Fast-forwarded"), "{}", text(&again));
            assert!(!text(&again).contains("Pushed"), "{}", text(&again));
            assert!(!text(&again).contains("Applied"), "{}", text(&again));
            assert_eq!(rev(home.path(), &repo, "HEAD"), theirs);
            assert_eq!(
                rev(home.path(), &home.child("remote.git"), "master"),
                theirs
            );
        }

        #[test]
        fn sync_applies_on_confirmation_and_pushes_what_this_machine_committed() {
            let home = guarded_home();
            let repo = cloned(&home, "");
            std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
            commit_all(home.path(), &repo, "mine");
            let mine = rev(home.path(), &repo, "HEAD");
            let tty = Env {
                stdin_tty: true,
                ..env(home.path())
            };

            let mut out = Vec::new();
            let mut asked = 0;
            let exit = sync_with(&tty, false, &mut out, &git(home.path()), &mut || {
                asked += 1;
                Ok(true)
            })
            .expect("sync");

            assert_eq!(exit, Exit::Converged);
            assert_eq!(asked, 1, "sync asks once");
            assert!(
                text(&out)
                    .ends_with("Applied 1 change(s).\nPushed 1 commit(s) to origin/master.\n"),
                "{}",
                text(&out)
            );
            assert_eq!(rev(home.path(), &home.child("remote.git"), "master"), mine);
        }

        #[test]
        fn a_declined_sync_writes_nothing_and_pushes_nothing() {
            let home = guarded_home();
            let repo = cloned(&home, "");
            std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
            commit_all(home.path(), &repo, "mine");
            let before = rev(home.path(), &home.child("remote.git"), "master");
            let tty = Env {
                stdin_tty: true,
                ..env(home.path())
            };

            let mut out = Vec::new();
            let exit = sync_with(&tty, false, &mut out, &git(home.path()), &mut || Ok(false))
                .expect("a declined sync");

            assert_eq!(exit, Exit::Pending);
            assert!(
                text(&out).ends_with(
                    "Nothing was written.\nPushed nothing: 1 commit(s) wait for an apply that \
                     leaves nothing undone; run `bx sync` again.\n"
                ),
                "{}",
                text(&out)
            );
            assert!(!home.child(".a").exists());
            assert_eq!(
                rev(home.path(), &home.child("remote.git"), "master"),
                before
            );
        }

        #[test]
        fn a_sync_that_leaves_a_conflict_pushes_nothing() {
            let home = guarded_home();
            let repo = cloned(&home, "");
            home.write(".mine", "mine\n");
            std::fs::write(repo.join("bx.toml"), inline("~/.mine", "bx\\n")).expect("bx.toml");
            commit_all(home.path(), &repo, "mine");
            let before = rev(home.path(), &home.child("remote.git"), "master");

            let mut out = Vec::new();
            let exit = sync_with(
                &env(home.path()),
                true,
                &mut out,
                &git(home.path()),
                &mut never,
            )
            .expect("a sync with a conflict");

            assert_eq!(exit, Exit::Pending, "{}", text(&out));
            assert!(text(&out).starts_with("  ! ~/.mine"), "{}", text(&out));
            assert!(
                text(&out).ends_with(
                    "Pushed nothing: 1 commit(s) wait for an apply that leaves nothing undone; \
                     run `bx sync` again.\n"
                ),
                "{}",
                text(&out)
            );
            assert!(!text(&out).contains("Pushed 1"), "{}", text(&out));
            assert_eq!(std::fs::read(home.child(".mine")).expect("kept"), b"mine\n");
            assert_eq!(
                rev(home.path(), &home.child("remote.git"), "master"),
                before
            );
        }

        #[test]
        fn sync_without_yes_or_a_terminal_writes_and_pushes_nothing_pending() {
            let home = guarded_home();
            let repo = cloned(&home, "");
            std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
            commit_all(home.path(), &repo, "mine");
            let before = rev(home.path(), &home.child("remote.git"), "master");

            let error = sync_with(
                &env(home.path()),
                false,
                &mut Vec::new(),
                &git(home.path()),
                &mut never,
            )
            .expect_err("no confirmation");

            assert!(
                matches!(error, sync::Error::Plan(Error::NeedsConfirmation)),
                "{error:?}"
            );
            assert!(!home.child(".a").exists());
            assert_eq!(
                rev(home.path(), &home.child("remote.git"), "master"),
                before
            );
        }

        #[test]
        fn an_interrupted_sync_is_recovered_by_the_next_and_pushes_only_after_it() {
            use crate::journal::{Session, SessionKind};

            let home = guarded_home();
            let repo = cloned(&home, "");
            std::fs::write(repo.join("bx.toml"), inline("~/.a", "a\\n")).expect("bx.toml");
            commit_all(home.path(), &repo, "mine");
            let mine = rev(home.path(), &repo, "HEAD");
            let before = rev(home.path(), &home.child("remote.git"), "master");
            let state = crate::state::StateDir::resolve(home.path());
            drop(Session::open(&state, SessionKind::Apply, home.path(), Vec::new()).expect("open"));
            let env = env(home.path());

            let mut out = Vec::new();
            let exit = sync_with(&env, true, &mut out, &git(home.path()), &mut never)
                .expect("the recovering sync");
            assert_eq!(exit, Exit::Pending);
            assert!(
                text(&out).contains("nothing else was applied"),
                "{}",
                text(&out)
            );
            assert!(text(&out).contains("Pushed nothing"), "{}", text(&out));
            assert_eq!(
                rev(home.path(), &home.child("remote.git"), "master"),
                before
            );
            assert!(!home.child(".a").exists());

            let mut out = Vec::new();
            let exit = sync_with(&env, true, &mut out, &git(home.path()), &mut never)
                .expect("the next sync");
            assert_eq!(exit, Exit::Converged, "{}", text(&out));
            assert!(home.child(".a").exists());
            assert_eq!(rev(home.path(), &home.child("remote.git"), "master"), mine);
        }

        #[test]
        fn a_refused_pull_applies_nothing() {
            let home = guarded_home();
            let repo = cloned(&home, &inline("~/.a", "a\\n"));
            std::fs::write(repo.join("local.toml"), "[values]\n").expect("local.toml");
            commit_all(home.path(), &repo, "oops");

            let mut out = Vec::new();
            let error = sync_with(
                &env(home.path()),
                true,
                &mut out,
                &git(home.path()),
                &mut never,
            )
            .expect_err("state in an outgoing commit");

            assert!(
                matches!(error, sync::Error::WouldPushState { .. }),
                "{error:?}"
            );
            assert!(out.is_empty(), "{}", text(&out));
            assert!(!home.child(".a").exists());
        }

        #[test]
        fn a_sync_that_cannot_write_its_output_is_an_output_error() {
            let home = guarded_home();
            cloned(&home, "");
            publish_elsewhere(&home, "# changed elsewhere\n");
            assert!(matches!(
                sync_with(
                    &env(home.path()),
                    true,
                    &mut Refusing,
                    &git(home.path()),
                    &mut never
                ),
                Err(sync::Error::Output(_))
            ));
        }
    }
}
