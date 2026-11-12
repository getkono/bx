//! `bx secret list` asks for a locked identity's passphrase on the terminal,
//! and what is typed there unlocks it.
//!
//! The binary runs on a pseudo-terminal of its own: in a session of its own,
//! with the terminal as its controlling one and as its standard input, output
//! and error, as a shell started in a terminal window would run it. Its
//! identity is an age identity file encrypted with a passphrase, so listing
//! the one secret encrypted to it needs that passphrase. The test waits for
//! the question, types the passphrase and Enter on the keyboard end, and
//! reads the secret back as decryptable. A prompt that never asks leaves the
//! identity locked, and the secret is listed as not decryptable instead.
//!
//! Starting a session and taking a controlling terminal belong to the child,
//! between `fork` and `exec`, and `Command::pre_exec` is `unsafe`, which
//! `Cargo.toml` forbids under `tests/` too. So the child is this test binary
//! again, running only [`on_its_own_terminal`]: it calls `setsid` and
//! `TIOCSCTTY` on itself, both safe through rustix, and then starts `bx`,
//! which inherits the session, the terminal and the standard streams.
//!
//! Every read is bounded by a deadline, so a prompt that hangs fails the test
//! instead of hanging the suite. The home is a guarded tempdir.

mod common;

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use bx::testing::{GuardedHome, guarded_home};

/// Set on the child to the home its `bx` runs against.
const HOME_VARIABLE: &str = "BX_TEST_PTY_HOME";

/// What unlocks the identity.
const PASSPHRASE: &str = "correct horse";

/// How long each step may take before the test gives up on it. Generous,
/// since a coverage build on a shared runner is slow, and reached only when
/// something is wrong.
const STEP: Duration = Duration::from_secs(60);

#[test]
#[ignore = "started by the test below, on a pseudo-terminal of its own"]
fn on_its_own_terminal() {
    // Without the variable this is someone running `--ignored` by hand,
    // where taking a session of its own would detach the test binary from
    // their terminal. Do nothing.
    let Some(home) = std::env::var_os(HOME_VARIABLE) else {
        return;
    };
    rustix::process::setsid().expect("a session of its own");
    rustix::process::ioctl_tiocsctty(std::io::stdin()).expect("its controlling terminal");
    let status = common::isolated(env!("CARGO_BIN_EXE_bx"))
        .args(["secret", "list"])
        .env("HOME", home)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("run bx");
    assert_eq!(status.code(), Some(0), "bx secret list: {status}");
}

#[test]
fn secret_list_asks_for_the_passphrase_on_the_terminal_and_unlocks_with_it() {
    let home = guarded_home();
    seed(&home);
    let (keyboard, terminal) = pseudo_terminal();
    rustix::termios::tcsetwinsize(
        &terminal,
        rustix::termios::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .expect("a window size");

    let mut child = {
        // Dropped once the child has started, so the child holds the only
        // copies of the terminal end and the keyboard end reads its end of
        // file when the child exits.
        let mut command = Command::new(std::env::current_exe().expect("the test binary"));
        command
            .args(["--exact", "--ignored", "on_its_own_terminal"])
            .env("RUST_TEST_NOCAPTURE", "1")
            .env(HOME_VARIABLE, home.path())
            .stdin(Stdio::from(terminal.try_clone().expect("the terminal")))
            .stdout(Stdio::from(terminal.try_clone().expect("the terminal")))
            .stderr(Stdio::from(terminal));
        command.spawn().expect("start the child")
    };
    let mut keys = File::from(keyboard.try_clone().expect("the keyboard"));
    let screen = read_in_background(File::from(keyboard));
    let mut shown = Vec::new();

    if !shown_within(&screen, &mut shown, "Passphrase for ~/.config/age/key.age") {
        give_up(&mut child, &shown, "no passphrase was asked for");
    }
    keys.write_all(format!("{PASSPHRASE}\r").as_bytes())
        .expect("the passphrase typed");
    if !shown_within(&screen, &mut shown, "secrets/token.age  decryptable") {
        give_up(&mut child, &shown, "the secret was not unlocked");
    }

    let status = exited_within(&mut child, STEP)
        .unwrap_or_else(|| give_up(&mut child, &shown, "the child did not exit"));
    assert!(status.success(), "{status}:\n{}", lossy(&shown));
    assert!(
        !lossy(&shown).contains(PASSPHRASE),
        "the passphrase is masked:\n{}",
        lossy(&shown)
    );
}

/// The repo under `home`: one secret, encrypted to an x25519 key whose
/// identity file is itself encrypted with [`PASSPHRASE`], and `local.toml`
/// naming that file as the identity.
fn seed(home: &GuardedHome) {
    use age::secrecy::ExposeSecret as _;

    let key = age::x25519::Identity::generate();
    let mut locked = age::scrypt::Recipient::new(PASSPHRASE.into());
    // The lowest work factor, so unlocking costs the test nothing.
    locked.set_work_factor(2);
    let identity = encrypt(
        &locked,
        format!("{}\n", key.to_string().expose_secret()).as_bytes(),
    );
    write(home, ".config/age/key.age", &identity);
    write(
        home,
        ".local/state/bx/local.toml",
        b"[secrets]\nidentity = \"~/.config/age/key.age\"\n",
    );
    write(
        home,
        ".config/bx/secrets/token.age",
        &encrypt(&key.to_public(), b"hunter2\n"),
    );
    write(
        home,
        ".config/bx/bx.toml",
        b"[[target]]\npath = \"~/.token\"\nsecret = \"secrets/token.age\"\nmode = \"0600\"\n",
    );
}

/// `plaintext` encrypted to `recipient`.
fn encrypt(recipient: &dyn age::Recipient, plaintext: &[u8]) -> Vec<u8> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient)).expect("a recipient");
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).expect("the output");
    writer.write_all(plaintext).expect("the plaintext");
    writer.finish().expect("the stream");
    ciphertext
}

/// Write `contents` to `rel` under `home`, creating its parents.
fn write(home: &GuardedHome, rel: &str, contents: &[u8]) {
    let path = home.child(rel);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the parents");
    std::fs::write(&path, contents).expect("the file");
}

/// A pseudo-terminal: what is written to the first end is typed on the
/// second, the end a program reads its keys from and writes its screen to.
fn pseudo_terminal() -> (OwnedFd, OwnedFd) {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    let keyboard = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("a pseudo-terminal");
    grantpt(&keyboard).expect("granted");
    unlockpt(&keyboard).expect("unlocked");
    let name = ptsname(&keyboard, Vec::new()).expect("its name");
    let terminal = rustix::fs::open(
        name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("its terminal end");
    (keyboard, terminal)
}

/// What the terminal shows, as it arrives, read on a thread of its own so a
/// read that would block never blocks the test. The channel closes when the
/// terminal end is closed by everything that held it.
fn read_in_background(mut keyboard: File) -> Receiver<Vec<u8>> {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut chunk = [0; 4096];
        // Linux reads `EIO`, and macOS an end of file, once the last
        // terminal end is closed.
        while let Ok(read @ 1..) = keyboard.read(&mut chunk) {
            if send.send(chunk[..read].to_vec()).is_err() {
                break;
            }
        }
    });
    receive
}

/// Whether `text` is on `shown`, the screen so far, within [`STEP`],
/// appending to it whatever arrives meanwhile.
fn shown_within(screen: &Receiver<Vec<u8>>, shown: &mut Vec<u8>, text: &str) -> bool {
    let until = Instant::now() + STEP;
    loop {
        if lossy(shown).contains(text) {
            return true;
        }
        match screen.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(chunk) => shown.extend(chunk),
            Err(_) => return false,
        }
    }
}

/// `child`'s exit status, once it exits within `within`.
fn exited_within(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().expect("the child's status") {
            return Some(status);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Kill `child`, whose session's `bx` the hang-up then ends, and fail with
/// `why` and the screen so far.
fn give_up(child: &mut Child, shown: &[u8], why: &str) -> ! {
    let _ = child.kill();
    let _ = child.wait();
    panic!("{why}; the terminal showed:\n{}", lossy(shown));
}

fn lossy(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}
