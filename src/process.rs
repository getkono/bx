//! A child process run to a deadline, and what it printed collected by the
//! same deadline.
//!
//! [`bounded`] is the one place bx waits on a child with a bound: [`crate::git`]
//! for a question to a remote, and the activation runner in
//! `shell::activation` for a tool's init output. Both need the same things
//! from it, so they share it rather than each keeping a copy that drifts:
//!
//! * each stream is read on its own thread, so a child that fills one pipe
//!   while bx waits on the other cannot stall;
//! * the child is polled until the deadline, then killed — with
//!   [`Options::own_group`] the process group it leads too — and reaped;
//! * a pipe is closed only once every process holding it is gone, so a
//!   process the command left behind holding one — an ssh `ControlPersist`
//!   master, a tool that backgrounds a helper — keeps its stream open after
//!   the command exits. Collecting the streams is therefore bounded by the
//!   same deadline, and a reader still waiting then is left behind rather
//!   than joined. Under [`Options::own_group`] the group is killed then too,
//!   which stops that process unless it left the group;
//! * a stream can be capped, so a child that prints without end costs bx a
//!   bounded amount of memory.
//!
//! The command is not reaped until its streams are collected, so the group's
//! id cannot have passed to another process when it is killed.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, waitid};

/// How often a running child is asked whether it has exited.
const POLL: Duration = Duration::from_millis(5);

/// How [`bounded`] runs a command and reads what it prints.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Options {
    /// Run the command as the leader of a process group of its own, and kill
    /// the whole group when the deadline passes, so the deadline also reaches
    /// what the command started. A group of its own is out of reach of the
    /// Ctrl-C a person presses at the terminal, so this is only for a run
    /// nobody is at the terminal for.
    pub(crate) own_group: bool,
    /// The most standard output may hold, in bytes, or `None` for no bound.
    /// It is read one byte past the bound and then closed, so a child that
    /// keeps writing finds its pipe closed rather than bx's memory growing,
    /// and [`Error::TooLarge`] reports it.
    pub(crate) stdout_limit: Option<usize>,
    /// How much of standard error to keep, in bytes, or `None` for all of it.
    /// The rest is read and discarded until the writer closes it, so a child
    /// that warns at length is never stopped by a closed pipe for it.
    pub(crate) stderr_kept: Option<usize>,
}

/// How a command that ran within its deadline exited, and what it printed.
#[derive(Debug)]
pub(crate) struct Output {
    /// How it exited.
    pub(crate) status: ExitStatus,
    /// Its standard output, at most [`Options::stdout_limit`] bytes.
    pub(crate) stdout: Vec<u8>,
    /// The start of its standard error, at most [`Options::stderr_kept`]
    /// bytes.
    pub(crate) stderr: Vec<u8>,
}

/// Why [`bounded`] has no [`Output`].
#[derive(Debug)]
pub(crate) enum Error {
    /// The command could not be started.
    Spawn(std::io::Error),
    /// Whether the command had exited could not be learned. It was killed.
    Wait(std::io::Error),
    /// The command, or a process left holding its output after it exited,
    /// ran past the deadline. A command still running was killed.
    TimedOut,
    /// Standard output went past [`Options::stdout_limit`], which this holds.
    TooLarge(usize),
}

/// Run `command` with its standard output and error piped, and return how it
/// exited and what it printed, all by `deadline`. See the module's
/// documentation for what is bounded and what is killed.
///
/// # Errors
///
/// [`Error`] when it could not be started or waited for, did not finish or
/// close its output by `deadline`, or printed more than its standard output
/// may hold.
pub(crate) fn bounded(
    command: &mut Command,
    deadline: Instant,
    options: Options,
) -> Result<Output, Error> {
    if options.own_group {
        std::os::unix::process::CommandExt::process_group(command, 0);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(Error::Spawn)?;
    let leader = Pid::from_child(&child);
    let kill = |child: &mut Child| {
        if options.own_group {
            let _ = rustix::process::kill_process_group(leader, Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    };
    let stdout = drain(
        child.stdout.take(),
        options.stdout_limit.map(|limit| limit.saturating_add(1)),
        false,
    );
    let stderr = drain(child.stderr.take(), options.stderr_kept, true);

    // Whether the command has exited, leaving it unreaped. `union`, not `|`,
    // for the reason `state::restore::read` gives.
    let exited = WaitIdOptions::EXITED
        .union(WaitIdOptions::NOHANG)
        .union(WaitIdOptions::NOWAIT);
    loop {
        match waitid(WaitId::Pid(leader), exited) {
            Ok(Some(_)) => break,
            Ok(None) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    kill(&mut child);
                    return Err(Error::TimedOut);
                }
                std::thread::sleep(left.min(POLL));
            }
            Err(error) => {
                kill(&mut child);
                return Err(Error::Wait(error.into()));
            }
        }
    }

    let collect = |stream: &mpsc::Receiver<Vec<u8>>| {
        stream
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()
    };
    let (Some(stdout), Some(stderr)) = (collect(&stdout), collect(&stderr)) else {
        kill(&mut child);
        return Err(Error::TimedOut);
    };
    let status = child.wait().map_err(Error::Wait)?;
    if let Some(limit) = options.stdout_limit
        && stdout.len() > limit
    {
        return Err(Error::TooLarge(limit));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Read `stream` on a thread of its own, keeping at most `kept` bytes of it
/// (all of it for `None`), and once those are kept, read and discard the rest
/// until the writer closes it when `to_end`, or close it at once otherwise.
fn drain(
    stream: Option<impl Read + Send + 'static>,
    kept: Option<usize>,
    to_end: bool,
) -> mpsc::Receiver<Vec<u8>> {
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            let kept = kept.map_or(u64::MAX, |kept| kept as u64);
            let _ = (&mut stream).take(kept).read_to_end(&mut bytes);
            if to_end {
                let _ = std::io::copy(&mut stream, &mut std::io::sink());
            }
        }
        let _ = send.send(bytes);
    });
    receive
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deadline `millis` from now.
    fn within(millis: u64) -> Instant {
        Instant::now() + Duration::from_millis(millis)
    }

    /// `sh -c script`.
    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    /// The pid `sh` wrote to `file`.
    fn pid_in(file: &std::path::Path) -> Pid {
        std::fs::read_to_string(file)
            .expect("the pid")
            .trim()
            .parse()
            .ok()
            .and_then(Pid::from_raw)
            .expect("a process id")
    }

    /// Whether `pid` stops running within two seconds.
    fn stops(pid: Pid) -> bool {
        (0..100).any(|_| {
            let running = runs(pid);
            if running {
                std::thread::sleep(Duration::from_millis(20));
            }
            !running
        })
    }

    #[test]
    fn a_command_past_its_deadline_is_killed() {
        let started = Instant::now();
        let result = bounded(&mut sh("sleep 3"), within(50), Options::default());
        assert!(matches!(result, Err(Error::TimedOut)), "{result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "killed, not waited on"
        );
    }

    #[test]
    fn a_quick_command_returns_its_status_and_both_streams() {
        let output = bounded(
            &mut sh("echo out; echo err >&2; exit 3"),
            within(30_000),
            Options::default(),
        )
        .expect("ran in time");
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
    }

    #[test]
    fn a_command_that_cannot_start_is_a_spawn_error() {
        let result = bounded(
            &mut Command::new("/nonexistent/bx-test"),
            within(1_000),
            Options::default(),
        );
        assert!(matches!(result, Err(Error::Spawn(_))), "{result:?}");
    }

    #[test]
    fn in_a_group_of_its_own_what_the_command_started_is_stopped_too() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let pid_file = scratch.path().join("pid");
        let mut parent = sh(&format!(
            "sleep 30 & echo $! > {}; wait",
            pid_file.display()
        ));
        let own_group = Options {
            own_group: true,
            ..Options::default()
        };
        let result = bounded(&mut parent, within(300), own_group);
        assert!(matches!(result, Err(Error::TimedOut)), "{result:?}");
        let grandchild = pid_in(&pid_file);
        assert!(
            stops(grandchild),
            "the grandchild {grandchild:?} still runs"
        );
    }

    #[test]
    fn a_process_left_holding_the_output_is_bounded_by_the_same_deadline() {
        for own_group in [false, true] {
            let scratch = tempfile::tempdir().expect("a scratch directory");
            let pid_file = scratch.path().join("pid");
            // The command exits at once, leaving `sleep` holding both pipes.
            let mut command = sh(&format!(
                "sleep 30 & echo $! > {}; echo hi",
                pid_file.display()
            ));
            let started = Instant::now();
            let options = Options {
                own_group,
                ..Options::default()
            };
            let result = bounded(&mut command, started + Duration::from_millis(300), options);
            assert!(
                matches!(result, Err(Error::TimedOut)),
                "own_group {own_group}: {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "own_group {own_group}: waited {:?} on the leftover",
                started.elapsed()
            );
            let leftover = pid_in(&pid_file);
            if own_group {
                assert!(stops(leftover), "the leftover {leftover:?} still runs");
            } else {
                // Out of reach without a group; stopped here so the suite
                // leaves nothing behind.
                let _ = rustix::process::kill_process(leftover, Signal::KILL);
            }
        }
    }

    #[test]
    fn a_standard_output_past_its_limit_is_reported_not_buffered() {
        let capped = Options {
            stdout_limit: Some(16),
            ..Options::default()
        };
        // Without end: only a closed pipe stops it.
        let started = Instant::now();
        let result = bounded(&mut sh("yes"), within(10_000), capped);
        assert!(matches!(result, Err(Error::TooLarge(16))), "{result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "not read to the end"
        );
        let output =
            bounded(&mut sh("printf %16s ''"), within(10_000), capped).expect("at the limit");
        assert_eq!(output.stdout.len(), 16);
    }

    #[test]
    fn only_the_start_of_standard_error_is_kept_and_the_rest_is_drained() {
        let kept = Options {
            stderr_kept: Some(8),
            ..Options::default()
        };
        let output = bounded(
            // A closed pipe would fail `head`, and so the command.
            &mut sh("head -c 1000000 /dev/zero >&2 || exit 9; printf ok"),
            within(10_000),
            kept,
        )
        .expect("ran in time");
        assert!(output.status.success(), "{:?}", output.status);
        assert_eq!(output.stderr.len(), 8);
        assert_eq!(output.stdout, b"ok");
    }

    /// Whether `pid` still runs.
    ///
    /// `kill(pid, 0)` answers on every platform: `ESRCH` means no such process,
    /// and anything else, `EPERM` included, means one exists. A killed process
    /// lingers as a zombie until it is reaped, and an orphan is reaped by
    /// whatever adopts it; on Linux that may be a subreaper or a container's
    /// first process that never reaps, so there a process whose `/proc` state
    /// is `Z` no longer runs either. An unreadable `/proc` confirms nothing, so
    /// the process is then judged by `kill` alone, never assumed gone.
    ///
    /// One function with an arm per platform, as `has_cap_fsetid` is, so the
    /// whole of it builds wherever the suite does.
    fn runs(pid: Pid) -> bool {
        let exists = !matches!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH)
        );
        #[cfg(target_os = "linux")]
        {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero()));
            exists && !stat.is_ok_and(|stat| stat.contains(") Z "))
        }
        #[cfg(not(target_os = "linux"))]
        {
            exists
        }
    }
}
