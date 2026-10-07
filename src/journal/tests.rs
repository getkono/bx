//! Fixtures the journal's tests share with one another and with the
//! recovery, restore, plan and doctor suites, and the tests that pin the
//! fixtures themselves — chiefly the rule for a scenario this machine cannot
//! build.

use super::*;

use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::crash::{Crash, FINISH_PHASES, PHASES};
use super::format::{FORMAT, HEADER, MAGIC, NONCE, frame, fresh_nonce};
use crate::fs::Mode;
use crate::state::{ContentHash, ExclusiveLock, Ledger, Mechanism, Prior, StateDir};

/// A target under `home`, both halves of it.
pub(crate) fn target(home: &Path, rel: &str) -> (Portable, PathBuf) {
    let dest = home.join(rel);
    (Portable::from_path(&dest, home).expect("portable"), dest)
}

/// A write request for `rel` under `home`, carrying what is there now as
/// plan's observation.
pub(crate) fn write_to(home: &Path, rel: &str, bytes: &str, mode: Mode) -> Request {
    let (target, dest) = target(home, rel);
    // Observed when the request is built, as plan observes before anything
    // is applied.
    let planned = fs::observe(&dest).expect("plan's observation");
    Request {
        target,
        dest,
        content: Content::Bytes {
            bytes: bytes.as_bytes().to_vec(),
            planned,
        },
        mode,
        ownership: Ownership::Owned(Mechanism::Own),
    }
}

/// A request to make `rel` under `home` a symlink holding `text`, owned
/// by bx, carrying what is there now as plan's observation.
pub(crate) fn link_to(home: &Path, rel: &str, text: &str) -> Request {
    let (target, dest) = target(home, rel);
    let planned = fs::observe(&dest).expect("plan's observation");
    Request {
        target,
        dest,
        content: Content::Link {
            text: PathBuf::from(text),
            planned,
        },
        mode: Mode::LINK,
        ownership: Ownership::Owned(Mechanism::Link),
    }
}

/// Create a file at exactly `mode`, parents included.
pub(crate) fn plant_file(path: &Path, bytes: &str, mode: Mode) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("the fixture's parents");
    }
    std::fs::write(path, bytes).expect("the fixture");
    fs::set_mode(path, mode).expect("the fixture's mode");
}

/// The bytes and mode at `path`, or `None` when nothing is there.
pub(crate) fn peek(path: &Path) -> Option<(Vec<u8>, Mode)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let bytes = std::fs::read(path).expect("a readable fixture");
    Some((bytes, Mode::from_bits(meta.permissions().mode())))
}

/// Whether a directory without write permission refuses this process.
///
/// It does not refuse root, so a test that needs a refused rename or
/// unlink cannot produce one there. A caller that finds `false` restores
/// whatever it broke and then calls [`cannot_build`], which fails unless
/// the skip was opted into.
pub(crate) fn permissions_refuse(dir: &Path) -> bool {
    let probe = dir.join("permission-probe");
    if std::fs::write(&probe, b"").is_err() {
        return true;
    }
    std::fs::remove_file(&probe).expect("remove the probe");
    false
}

/// Why a test that needs a refused write cannot run as this user.
pub(crate) const WRITES_THROUGH_PERMISSIONS: &str = "this process writes through file or directory permissions, so the \
         failure cannot be produced";

/// The variable that turns a scenario this machine cannot build from a
/// failure into a skip.
///
/// r3 round 3, COV1. A test that prints a line and passes when it could
/// not run is not a test: the arms it is the only cover for go unverified
/// while the suite reports green, and nobody reads the line. So an
/// unbuildable scenario **fails**, and the only way to have it skip is to
/// say so in the environment — which is a decision a human takes, and
/// which the gate report then has to carry.
///
/// It is read, never written: `Cargo.toml` forbids `unsafe`, so no test in
/// this crate can set an environment variable. [`report_unbuildable`]
/// takes the answer as an argument so that both of its paths can be
/// tested without one.
pub(crate) const ALLOW_SKIPS: &str = "BX_ALLOW_UNBUILDABLE_SCENARIOS";

/// Whether this run opted out of failing on a scenario it cannot build.
pub(crate) fn skips_allowed() -> bool {
    allows_skips(std::env::var_os(ALLOW_SKIPS).as_deref())
}

/// Whether `value`, as [`ALLOW_SKIPS`] holds it, opts out.
///
/// Exactly `1` opts out. Any other value is not a spelling of "yes" — it
/// is a mistake, and a mistake must not be a silent opt-out. Pure, so a
/// test can drive every spelling in a process that cannot set a variable.
pub(crate) fn allows_skips(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|allow| allow == "1")
}

/// Fail because `name`'s scenario cannot be built here, or skip loudly if
/// [`ALLOW_SKIPS`] says to.
pub(crate) fn cannot_build(name: &str, why: &str) {
    report_unbuildable(name, why, skips_allowed());
}

/// [`cannot_build`] with the opt-out supplied, so a test can drive both
/// paths in a process that cannot change its own environment.
pub(crate) fn report_unbuildable(name: &str, why: &str, allowed: bool) {
    assert!(
        allowed,
        "{name} could not be run on this machine: {why}.\n\
             That is a failure, not a skip: everything this test is the only \
             cover for is now unverified. Run the suite as an unprivileged \
             user, on a kernel with unprivileged user namespaces and with \
             util-linux present; or set {ALLOW_SKIPS}=1 to accept the gap, \
             which leaves it unverified and makes the suite say so.",
    );
    say_out_loud(&format!(
        "INCOMPLETE RUN, opted out with {ALLOW_SKIPS}=1 — {name} did not \
             run: {why}",
    ));
}

/// Put `line` in the test binary's output whether or not it is a failing
/// test's.
///
/// r3 round 4, COV1. `eprintln!` goes through `std::io::_eprint`, which
/// honours libtest's per-thread output capture, so a line printed that way
/// by a *passing* test is printed nowhere at all — which is precisely the
/// case the opt-out exists for. The `Stderr` handle does not consult the
/// capture, so this reaches the report the gate reads.
pub(crate) fn say_out_loud(line: &str) {
    use std::io::Write as _;
    let mut err = std::io::stderr();
    let _ = writeln!(err, "{line}");
    let _ = err.flush();
}

/// A state directory, not yet created, whose files' paths fit Linux's
/// `PATH_MAX` and whose set-aside names do not.
///
/// Every [`crate::state::move_aside`] of its journal or ledger then fails
/// with ENAMETOOLONG, whoever the process runs as — "a name too long for a
/// quarantine suffix", as `state` puts it — while each can still be read,
/// written and locked. `fingerprints.mpk` is the one state file out of
/// reach.
pub(crate) fn state_beyond_set_aside_names(home: &crate::testing::GuardedHome) -> StateDir {
    /// `PATH_MAX`, which counts the terminating NUL.
    const PATH_MAX: usize = 4096;
    const ROOT: usize = 4080;
    let mut root = home.path().as_os_str().to_os_string();
    assert!(root.len() < ROOT - 256, "a home short enough to extend");
    while ROOT - root.len() > 256 {
        root.push(format!("/{}", "d".repeat(200)));
    }
    root.push(format!("/{}", "b".repeat(ROOT - root.len() - 1)));
    let state = StateDir::new(PathBuf::from(root));
    assert_eq!(state.root().as_os_str().len(), ROOT);
    for file in [state.journal(), state.ledger()] {
        assert!(file.as_os_str().len() < PATH_MAX, "{} fits", file.display());
        assert!(
            StateDir::quarantine(&file).as_os_str().len() >= PATH_MAX,
            "its set-aside name does not"
        );
    }
    state
}

/// The names in `dir`, sorted.
pub(crate) fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// A session header for a journal that needs one and does not care what it
/// says.
pub(super) fn some_begin() -> Begin {
    Begin {
        kind: SessionKind::Apply,
        home: PathBuf::from("/home/someone"),
        scope: Vec::new(),
    }
}

/// Where each whole frame in a journal's bytes starts.
pub(crate) fn frame_starts(bytes: &[u8]) -> Vec<usize> {
    let nonce = nonce_of(bytes);
    let mut starts = Vec::new();
    let mut at = HEADER;
    while let Ok((_, next)) = frame(bytes, at, &nonce) {
        starts.push(at);
        at = next;
    }
    starts
}

/// The nonce in a journal's header.
pub(crate) fn nonce_of(bytes: &[u8]) -> [u8; NONCE] {
    bytes[MAGIC.len() + 1..HEADER]
        .try_into()
        .expect("a whole header")
}

/// Write a journal exactly as given: a header, then each record as a frame.
///
/// For journals no session writes - one with no `Begin`, or one whose `End`
/// follows an Intent that has no `Done` - so recovery can be tested against
/// what damage or an earlier bx could leave behind.
pub(crate) fn raw_journal(path: &Path, records: &[Record]) {
    let nonce = fresh_nonce();
    let mut header = MAGIC.to_vec();
    header.push(FORMAT);
    header.extend_from_slice(&nonce);
    std::fs::write(path, &header).expect("write the header");
    let mut journal = Journal {
        file: OpenOptions::new()
            .append(true)
            .open(path)
            .expect("reopen the journal"),
        path: path.to_path_buf(),
        nonce,
    };
    for record in records {
        journal.append(record).expect("append");
    }
}

/// Append an `End` frame to an existing journal.
///
/// What [`Session::finish`] does *before* it saves the ledger — the one
/// window in which a crash leaves a terminated journal and a ledger that is
/// behind it.
pub(crate) fn seal(path: &Path, written: usize) {
    let mut journal = Journal {
        file: OpenOptions::new()
            .append(true)
            .open(path)
            .expect("reopen the journal"),
        path: path.to_path_buf(),
        nonce: nonce_of(&std::fs::read(path).expect("read the journal")),
    };
    journal
        .append(&Record::End(End { written }))
        .expect("append the End frame");
}

/// Every boundary the child can stop at, as `BX_CRASH_AT` spells it.
///
/// Spellings rather than [`Phase`] values, so the harness that drives this
/// can live in the module whose behaviour it is testing without the crash
/// seam having to become part of this module's surface.
pub(crate) fn crash_phases() -> [&'static str; PHASES.len()] {
    PHASES.map(Crash::name)
}

/// Every boundary inside [`Session::finish`], as `BX_CRASH_AT` spells it.
pub(crate) fn finish_crash_phases() -> [&'static str; FINISH_PHASES.len()] {
    FINISH_PHASES.map(Crash::name)
}

/// An Intent that says bx created `dest` holding `bytes`.
pub(super) fn created(target: &Portable, dest: &Path, bytes: &[u8]) -> Record {
    Record::Intent(Intent {
        target: target.clone(),
        dest: dest.to_path_buf(),
        temp: None,
        before: Prior::Absent,
        after: Written::Present {
            digest: ContentHash::of(bytes),
            mode: Mode::DEFAULT_FILE,
        },
        created_dirs: Vec::new(),
        mechanism: Some(Mechanism::Own),
        ledger_written: None,
        dir: false,
        link: false,
    })
}

/// The ledger as it stands on disk under `state`.
pub(super) fn saved_ledger(state: &StateDir, home: &Path) -> Ledger {
    let lock = ExclusiveLock::acquire(state).expect("lock");
    Ledger::open(state, &lock, home)
        .expect("open the ledger")
        .value
}

/// What the parent tells the opt-out child to expect of its environment.
const EXPECT_SKIPS: &str = "BX_TEST_EXPECT_SKIPS";

#[test]
#[ignore = "spawned by the_opt_out_is_read_from_the_environment_not_assumed"]
fn skips_allowed_child() {
    // Returns rather than panics when it was not spawned by its parent, so
    // a bare `cargo test -- --ignored` finds no instructions and does
    // nothing — the shape the other children already had (`r3 round 7`,
    // D3).
    let Some(expected) = std::env::var_os(EXPECT_SKIPS) else {
        return;
    };
    let expected = expected == "yes";
    assert_eq!(
        skips_allowed(),
        expected,
        "with {ALLOW_SKIPS}={:?}",
        std::env::var_os(ALLOW_SKIPS),
    );
    let live = std::panic::catch_unwind(|| cannot_build("live_probe", "a probe"));
    assert_eq!(
        live.is_ok(),
        expected,
        "cannot_build must follow the environment, not its own opinion",
    );
}

#[test]
fn the_opt_out_is_read_from_the_environment_not_assumed() {
    // r3 round 6, COV1. `skips_allowed() -> true` survived the whole
    // suite: the in-process assertion beside it compared the function with
    // an expression that moves with it, and every reported run leaves the
    // variable unset, so no test ever saw the other state. A child can be
    // given any state, which is the tool this lane built for the capture
    // pin, pointed at the thing it was built to reach.
    for (set, expect) in [(None, "no"), (Some("1"), "yes"), (Some("0"), "no")] {
        let mut child =
            std::process::Command::new(std::env::current_exe().expect("the test binary"));
        child
            .args([
                "--exact",
                "--ignored",
                "journal::tests::skips_allowed_child",
            ])
            .env(EXPECT_SKIPS, expect);
        match set {
            Some(value) => child.env(ALLOW_SKIPS, value),
            None => child.env_remove(ALLOW_SKIPS),
        };
        let out = child.output().expect("spawn the opt-out child");
        assert!(
            out.status.success(),
            "{ALLOW_SKIPS}={set:?} should read as {expect}:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    // r3 round 6, COV2. The "unset, or exactly 1" assertion is not
    // vacuous, but no run the gates table reports ever executes it: every
    // one of them leaves the variable unset. A child with `=0` does, and
    // must fail with the sentence that tells the reader what to do — the
    // whole point of refusing a value that looks like an answer.
    let out = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--exact",
            "journal::tests::a_scenario_this_machine_cannot_build_fails_unless_the_run_opted_out",
        ])
        .env(ALLOW_SKIPS, "0")
        .output()
        .expect("spawn the mis-set child");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !out.status.success(),
        "{ALLOW_SKIPS}=0 must not pass for an opt-out:\n{said}",
    );
    assert!(
        said.contains("is not a spelling of the opt-out"),
        "and must say why:\n{said}",
    );
}

#[test]
fn a_scenario_this_machine_cannot_build_fails_unless_the_run_opted_out() {
    // r3 round 4, COV1. Nothing pinned the policy itself: that the default
    // is a failure naming the test and the environment, that only the
    // exact string "1" opts out, and that the opted-in path still puts a
    // line in the report. `Cargo.toml` forbids `unsafe`, so no test here
    // can set an environment variable; `report_unbuildable` takes the
    // answer as an argument so both paths are reachable.
    let refused = std::panic::catch_unwind(|| {
        report_unbuildable("some_test", "there is no way to make it", false);
    })
    .expect_err("the default is a failure, not a skip");
    let said = refused
        .downcast_ref::<String>()
        .expect("a panic message")
        .clone();
    assert!(said.contains("some_test"), "{said}");
    assert!(said.contains("there is no way to make it"), "{said}");
    assert!(said.contains(ALLOW_SKIPS), "names the way out: {said}");
    assert!(
        said.contains("unprivileged"),
        "names the environment: {said}"
    );

    // Opted in, it returns — and says so where the report can see it.
    report_unbuildable("some_test", "there is no way to make it", true);

    // Exactly "1" opts out. Nothing else is a spelling of "yes": an empty
    // value, a "0" or a "true" left over from another tool's convention
    // must not turn the suite's own failures off.
    assert!(allows_skips(Some(std::ffi::OsStr::new("1"))));
    for not_yes in ["", "0", "true", "yes", "1 ", " 1"] {
        assert!(
            !allows_skips(Some(std::ffi::OsStr::new(not_yes))),
            "{not_yes:?} is not an opt-out",
        );
    }
    assert!(!allows_skips(None), "unset is not an opt-out");

    // The environment is in one of the two states the policy recognises.
    // r3 round 5, COV2: the assertion that stood here was `f(x) == f(x)` —
    // it re-spelled `skips_allowed`'s own body and constrained nothing.
    // This one can fail: a `0` or a `false` set in the belief that it
    // turns the opt-out *off* leaves every unbuildable scenario failing
    // while the person who set it thinks otherwise, and that is worth a
    // red suite.
    if let Some(value) = std::env::var_os(ALLOW_SKIPS) {
        assert!(
            value == "1",
            "{ALLOW_SKIPS} is set to {value:?}, which is not a spelling of the \
                 opt-out. Unset it, or set it to exactly 1.",
        );
        say_out_loud(&format!(
            "INCOMPLETE RUN: {ALLOW_SKIPS}=1 is set, so every scenario this \
                 machine cannot build was skipped rather than failed",
        ));
    }

    // What `cannot_build` does with the *live* environment is pinned by
    // `the_opt_out_is_read_from_the_environment_not_assumed`, which gives
    // a child each state in turn. Asserting it here as well would only
    // re-read this run's one state through the same function, which is
    // how `skips_allowed() -> true` survived (r3 round 6, COV1).
}

/// What the say-out-loud child writes through the handle.
const LOUD_MARKER: &str = "bx-say-out-loud-reaches-the-report";

/// What it writes with `eprintln!`, which libtest captures.
const CAPTURED_MARKER: &str = "bx-eprintln-is-swallowed";

#[test]
#[ignore = "spawned by an_opted_in_skip_reaches_the_report_and_eprintln_does_not"]
fn say_out_loud_child() {
    say_out_loud(LOUD_MARKER);
    eprintln!("{CAPTURED_MARKER}");
}

#[test]
fn an_opted_in_skip_reaches_the_report_and_eprintln_does_not() {
    // r3 round 5, COV1. The round-4 repair swapped `eprintln!` for a
    // `Stderr` handle so that an opted-in skip is visible, and nothing
    // pinned it: reverting the one line left the suite green, which is how
    // a repair gets undone by the next edit.
    //
    // The difference is only observable in a process libtest is capturing,
    // and a test cannot turn its own capture on. So the binary is
    // re-invoked for one `#[ignore]`d test, *without* `--nocapture`: the
    // handle write reaches the child's stderr, and the `eprintln!` from
    // the same passing test reaches nowhere.
    let child = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args(["--exact", "--ignored", "journal::tests::say_out_loud_child"])
        // r3 round 6, D2. The child inherits this process's environment,
        // and `RUST_TEST_NOCAPTURE=1` — which `cargo test` sets from
        // `--nocapture` — turns the child's capture off, so the
        // `eprintln!` would reach its stderr and this test would fail on
        // its own premise rather than on the property. Removed rather than
        // tolerated: the premise is that the child *is* capturing.
        .env_remove("RUST_TEST_NOCAPTURE")
        .output()
        .expect("spawn the say-out-loud child");
    let (out, err) = (
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
    assert!(child.status.success(), "the child failed:\n{out}\n{err}");
    assert!(
        err.contains(LOUD_MARKER),
        "`say_out_loud` did not reach the report:\nstdout:\n{out}\nstderr:\n{err}",
    );
    assert!(
        !out.contains(CAPTURED_MARKER) && !err.contains(CAPTURED_MARKER),
        "`eprintln!` from a passing test was expected to be swallowed, and was \
             not — the premise of the repair is wrong:\nstdout:\n{out}\nstderr:\n{err}",
    );
}

/// A directory request for `rel` under `home` at `mode`, carrying what is
/// there now as plan's observation.
pub(crate) fn dir_to(home: &Path, rel: &str, mode: Mode) -> Request {
    let (target, dest) = target(home, rel);
    let planned = fs::observe(&dest).expect("plan's observation");
    Request {
        target,
        dest,
        content: Content::Dir { planned },
        mode,
        ownership: Ownership::Owned(Mechanism::Dir),
    }
}

/// The mode of whatever is at `path`, or `None` when nothing is.
pub(crate) fn mode_at(path: &Path) -> Option<Mode> {
    std::fs::symlink_metadata(path)
        .ok()
        .map(|meta| Mode::from_bits(meta.permissions().mode()))
}

/// Apply `requests` in one session and finish it.
pub(super) fn applied(state: &StateDir, home: &Path, requests: Vec<Request>) {
    let mut session = Session::open(state, SessionKind::Apply, home, Vec::new()).expect("open");
    for request in requests {
        session.apply(request).expect("apply");
    }
    session.finish().expect("finish");
}

/// The text at `path` when a symlink is there, following nothing.
pub(crate) fn link_at(path: &Path) -> Option<PathBuf> {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|meta| meta.file_type().is_symlink())
        .map(|_| std::fs::read_link(path).expect("a readable link"))
}
