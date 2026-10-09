//! `bx self-upgrade`: install the latest release over this one, exactly as a
//! fresh install would.
//!
//! # The installer is fetched, and pinned
//!
//! A fresh install is `curl … install.sh | sh`, and an upgrade is the same
//! script run the same way: fetched from master at [`INSTALLER_URL`], fed to
//! `sh` on its standard input, with `BX_INSTALL_DIR` naming the directory the
//! running binary is in. The script is never embedded, so the binary carries
//! none of its bytes and never runs a stale copy. It carries only the script's
//! SHA-256, [`INSTALLER_SHA256`], and refuses to run a script that does not
//! match it: what master serves is executed only while it is byte for byte the
//! installer this release was built with. A mismatch points the user at
//! [`INSTALL_DOCS_URL`] to reinstall by hand, which is why `install.sh` says at
//! its top to change it only when necessary.
//!
//! # One answer to "what is the latest release"
//!
//! [`Installer::latest`] runs the verified script with `--latest`, so the
//! lookup `bx self-upgrade --check` reports is the one a fresh install
//! performs, and the version found is handed back to the install as
//! `BX_VERSION`, so a release published between the two is not what lands.
//!
//! # Not a managed target
//!
//! The binary is not a file bx manages for the user: no ledger entry, no
//! journal, no environment fragment. Nothing here is reachable from the
//! shell-start path, so the processes it spawns — `curl` or `wget`, then `sh` —
//! cost nothing Invariant 6 budgets. Every child gets the `PATH` it is handed,
//! and every program is found along that same `PATH` by [`detect::locate`], so
//! tests supply their own rather than mutating the process environment.

use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::detect;
use crate::report::Exit;
use crate::state::ContentHash;

/// Where a fresh install fetches the installer from, and so where an upgrade
/// does.
pub const INSTALLER_URL: &str = "https://raw.githubusercontent.com/getkono/bx/master/install.sh";

/// The README's install section, where a user whose installer no longer
/// matches is sent.
pub const INSTALL_DOCS_URL: &str = "https://github.com/getkono/bx#install";

/// The SHA-256 of the `install.sh` this release was built with.
///
/// A literal rather than a build-time digest so that changing the installer is
/// a deliberate act: a test hashes the file and fails until this is updated.
pub const INSTALLER_SHA256: &str =
    "8e5153b2f52eba1ecfee6b5f920662be084af4bbb398abdf2dc269f79d5824ca";

/// Why an upgrade, or the check, did not complete.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Neither `curl` nor `wget` is on `PATH`.
    #[error("neither curl nor wget is on PATH; one is needed to fetch the installer")]
    NoFetcher,
    /// `sh` is not on `PATH`.
    #[error("no `sh` on PATH to run the installer with")]
    NoShell,
    /// A program could not be started.
    #[error("could not run {program}: {source}")]
    Spawn {
        /// The program.
        program: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The installer could not be downloaded.
    #[error("fetching {url} failed ({status}){stderr}")]
    Fetch {
        /// What was fetched.
        url: String,
        /// How the fetcher exited.
        status: ExitStatus,
        /// What it said, as `: …`, or nothing.
        stderr: String,
    },
    /// What master serves is not the installer this release was built with.
    #[error(
        "the installer at {url} is not the one this bx was built with \
         (expected SHA-256 {expected}, found {found}), so it was not run. \
         Reinstall bx as {docs} describes; that bx can upgrade itself again"
    )]
    InstallerChanged {
        /// Where it came from.
        url: &'static str,
        /// The README section to reinstall from.
        docs: &'static str,
        /// The pinned digest.
        expected: &'static str,
        /// The digest of what was served.
        found: String,
    },
    /// The installer could not say what the latest release is.
    #[error("the installer could not find the latest release ({status}){stderr}")]
    Latest {
        /// How it exited.
        status: ExitStatus,
        /// What it said, as `: …`, or nothing.
        stderr: String,
    },
    /// A version that is not `vMAJOR.MINOR.PATCH`.
    #[error("{0:?} is not a release version bx understands")]
    Version(String),
    /// The running binary's location could not be established.
    #[error("could not find the running bx: {0}")]
    CurrentExe(#[source] std::io::Error),
    /// The installer ran and failed.
    #[error("the installer failed ({status}){stderr}")]
    Install {
        /// How it exited.
        status: ExitStatus,
        /// What it said, as `: …`, or nothing.
        stderr: String,
    },
    /// The output could not be written.
    #[error("writing the output: {0}")]
    Output(#[source] std::io::Error),
}

/// `: STDERR` when a child said anything, and nothing otherwise.
fn stderr_suffix(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
}

/// A release version: `MAJOR.MINOR.PATCH`, ordered numerically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Version {
    /// `text` as a version, with or without the tag's leading `v`.
    ///
    /// # Errors
    ///
    /// [`Error::Version`] for anything but three dot-separated decimal numbers.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let invalid = || Error::Version(text.to_string());
        let bare = text.strip_prefix('v').unwrap_or(text);
        let mut parts = bare.split('.').map(|part| {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            part.parse::<u64>().map_err(|_| invalid())
        });
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        Ok(Self {
            major: major?,
            minor: minor?,
            patch: patch?,
        })
    }
}

/// The release tag form, `vMAJOR.MINOR.PATCH`.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The body of `url`, fetched with `curl`, or `wget` when there is no `curl`,
/// found along `path_var` — the preference `install.sh` has.
///
/// A connection that never answers fails after 30 seconds rather than leaving
/// `bx` waiting with nothing on the screen.
///
/// # Errors
///
/// [`Error::NoFetcher`] with neither, [`Error::Spawn`] when it cannot be
/// started, and [`Error::Fetch`] when it fails.
pub fn fetch(url: &str, path_var: &OsStr) -> Result<Vec<u8>, Error> {
    let (program, args): (PathBuf, &[&str]) =
        if let Some(curl) = usable(detect::locate("curl", path_var)) {
            (curl, &["-fsSL", "--connect-timeout", "30"])
        } else if let Some(wget) = usable(detect::locate("wget", path_var)) {
            (wget, &["-qO-", "--timeout=30"])
        } else {
            return Err(Error::NoFetcher);
        };
    tracing::debug!(program = %program.display(), url, "fetching");
    let output = Command::new(&program)
        .args(args)
        .arg(url)
        .env("PATH", path_var)
        .stdin(Stdio::null())
        .output()
        .map_err(|source| Error::Spawn {
            program: program.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::Fetch {
            url: url.to_string(),
            status: output.status,
            stderr: stderr_suffix(&output.stderr),
        });
    }
    Ok(output.stdout)
}

/// The path of a found, executable program.
fn usable(presence: detect::Presence) -> Option<PathBuf> {
    match presence {
        detect::Presence::Present { path } => Some(path),
        detect::Presence::NotExecutable { .. } | detect::Presence::Missing => None,
    }
}

/// An `install.sh` whose digest is [`INSTALLER_SHA256`]: the only form in
/// which bx will run one.
#[derive(Debug)]
pub struct Installer {
    script: Vec<u8>,
}

impl Installer {
    /// `script`, if it is the installer this release was built with.
    ///
    /// # Errors
    ///
    /// [`Error::InstallerChanged`] for any other bytes.
    pub fn verified(script: Vec<u8>) -> Result<Self, Error> {
        let found = ContentHash::of(&script).to_hex();
        if found != INSTALLER_SHA256 {
            return Err(Error::InstallerChanged {
                url: INSTALLER_URL,
                docs: INSTALL_DOCS_URL,
                expected: INSTALLER_SHA256,
                found,
            });
        }
        Ok(Self { script })
    }

    /// `sh -s -- ARGS`, reading this script from its standard input, with
    /// `path_var` as its `PATH`.
    fn command(&self, args: &[&str], path_var: &OsStr) -> Result<(PathBuf, Command), Error> {
        let sh = usable(detect::locate("sh", path_var)).ok_or(Error::NoShell)?;
        let mut command = Command::new(&sh);
        command
            .arg("-s")
            .arg("--")
            .args(args)
            .env("PATH", path_var)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok((sh, command))
    }

    /// Run `command` with this script on its standard input.
    fn run(&self, sh: PathBuf, mut command: Command) -> Result<std::process::Output, Error> {
        let spawn = |source| Error::Spawn {
            program: sh.clone(),
            source,
        };
        let mut child = command.spawn().map_err(spawn)?;
        // The script is a few kilobytes and a pipe holds sixty-four, so the
        // write completes before `sh` has to read any of it.
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&self.script).map_err(spawn)?;
        }
        child.wait_with_output().map_err(spawn)
    }

    /// The latest published release, as `install.sh --latest` finds it.
    ///
    /// # Errors
    ///
    /// [`Error::NoShell`], [`Error::Spawn`], [`Error::Latest`] when the script
    /// fails, and [`Error::Version`] when it prints something that is not a
    /// release version.
    pub fn latest(&self, path_var: &OsStr) -> Result<Version, Error> {
        let (sh, command) = self.command(&["--latest"], path_var)?;
        let output = self.run(sh, command)?;
        if !output.status.success() {
            return Err(Error::Latest {
                status: output.status,
                stderr: stderr_suffix(&output.stderr),
            });
        }
        Version::parse(String::from_utf8_lossy(&output.stdout).trim())
    }

    /// Install `version` into `dir`, exactly as a fresh install with
    /// `BX_VERSION` and `BX_INSTALL_DIR` set would.
    ///
    /// What the installer prints on success is written for a fresh install —
    /// colour it emits whatever the terminal, and a "Next: bx init" an
    /// upgraded user must not follow — so it goes to the debug log, not the
    /// user. Its error output is kept for the failure it explains.
    ///
    /// # Errors
    ///
    /// [`Error::NoShell`], [`Error::Spawn`], and [`Error::Install`] when the
    /// script fails.
    pub fn install(&self, version: Version, dir: &Path, path_var: &OsStr) -> Result<(), Error> {
        let (sh, mut command) = self.command(&[], path_var)?;
        command
            .env("BX_VERSION", version.to_string())
            .env("BX_INSTALL_DIR", dir);
        let output = self.run(sh, command)?;
        tracing::debug!(
            stdout = %String::from_utf8_lossy(&output.stdout),
            "the installer finished"
        );
        if !output.status.success() {
            return Err(Error::Install {
                status: output.status,
                stderr: stderr_suffix(&output.stderr),
            });
        }
        Ok(())
    }
}

/// What `bx self-upgrade` was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// Only report whether a newer release exists.
    pub check: bool,
    /// Install the latest release even when this one is not older.
    pub force: bool,
}

/// `bx self-upgrade`, for the binary at version `current` installed in `dir`,
/// fetching from `url` with programs found along `path_var`.
///
/// `--check` exits [`Exit::Pending`] when a newer release exists and
/// [`Exit::Converged`] otherwise, as `bx plan` does. Without it, an older
/// `current` is upgraded; one that is the latest, or newer than it — a build
/// from source — is left alone unless `force` asks for the latest anyway.
///
/// # Errors
///
/// [`Error::Version`] when `current` is not a version bx can compare, before
/// anything is fetched; whatever fetching, verifying and running the installer
/// return; and [`Error::Output`] when `out` cannot be written.
pub fn run(
    request: Request,
    current: &str,
    dir: &Path,
    url: &str,
    path_var: &OsStr,
    out: &mut dyn Write,
) -> Result<Exit, Error> {
    let current = Version::parse(current)?;
    let installer = Installer::verified(fetch(url, path_var)?)?;
    let latest = installer.latest(path_var)?;
    let order = current.cmp(&latest);
    let say = |out: &mut dyn Write, line: String| -> Result<(), Error> {
        writeln!(out, "{line}").map_err(Error::Output)
    };

    if request.check {
        return match order {
            Ordering::Less => {
                say(
                    out,
                    format!(
                        "bx {current} is installed; {latest} is available. Run `bx self-upgrade`."
                    ),
                )?;
                Ok(Exit::Pending)
            }
            Ordering::Equal => {
                say(out, format!("bx {current} is the latest release."))?;
                Ok(Exit::Converged)
            }
            Ordering::Greater => {
                say(
                    out,
                    format!("bx {current} is newer than the latest release, {latest}."),
                )?;
                Ok(Exit::Converged)
            }
        };
    }

    if order != Ordering::Less && !request.force {
        let relation = if order == Ordering::Equal {
            "already the latest release"
        } else {
            "newer than the latest release"
        };
        say(
            out,
            format!(
                "bx {current} is {relation}, {latest}; nothing to do. `--force` reinstalls {latest}."
            ),
        )?;
        return Ok(Exit::Converged);
    }

    say(
        out,
        format!(
            "Installing bx {latest} over {current} in {}...",
            dir.display()
        ),
    )?;
    out.flush().map_err(Error::Output)?;
    installer.install(latest, dir, path_var)?;
    say(out, format!("Installed bx {latest}."))?;
    Ok(Exit::Converged)
}

/// The directory the running binary is in: the one an upgrade replaces it in.
///
/// `/proc/self/exe` names the file itself, so a `bx` started through its
/// `userbox` link is upgraded where `bx` actually is.
///
/// # Errors
///
/// [`Error::CurrentExe`] when the kernel cannot say.
pub fn install_dir() -> Result<PathBuf, Error> {
    let exe = std::env::current_exe().map_err(Error::CurrentExe)?;
    exe.parent().map(Path::to_path_buf).ok_or_else(|| {
        Error::CurrentExe(std::io::Error::other(format!(
            "{} has no parent directory",
            exe.display()
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    /// The installer in this tree: the bytes master serves once it lands.
    const INSTALL_SH: &[u8] = include_bytes!("../install.sh");

    /// A stand-in for `curl` and `wget` that serves fixture files from `root`
    /// by URL and records each request, so the real `install.sh` runs end to
    /// end without the network.
    fn stub(root: &Path) -> String {
        let root = root.display();
        format!(
            r#"#!/bin/sh
out=
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out="$2"; shift 2 ;;
	-*) shift ;;
	*) url="$1"; shift ;;
	esac
done
case "$url" in
*/install.sh) src="{root}/install.sh" ;;
*/releases/latest) src="{root}/latest.json" ;;
*/releases/download/*) src="{root}/assets/${{url#*/releases/download/}}" ;;
*) src= ;;
esac
printf '%s\n' "$url" >>"{root}/requests"
[ -n "$src" ] && [ -f "$src" ] || {{ echo "404 $url" >&2; exit 22; }}
if [ -n "$out" ]; then cp "$src" "$out"; else cat "$src"; fi
"#
        )
    }

    /// Write the stub serving `root` as `dir/name`, and wait until it can be
    /// executed.
    ///
    /// Another test thread that forks while the stub is open for writing holds
    /// that descriptor until its child calls `exec`, and executing the stub
    /// inside that window fails with `ETXTBSY`. The window closes on its own,
    /// so the stub is run once here, retrying only that error, before any
    /// code under test runs it.
    fn install_stub(dir: &Path, name: &str, root: &Path) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, stub(root)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        for _ in 0..200 {
            match Command::new(&path).stdin(Stdio::null()).output() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("the stub would not run: {e}"),
                Ok(_) => {
                    // The warm-up asked for no URL; forget that it asked.
                    let _ = std::fs::remove_file(root.join("requests"));
                    return path;
                }
            }
        }
        panic!("the stub stayed busy");
    }

    /// A served release: the installer, the `releases/latest` answer, and
    /// one release's assets, behind a stub fetcher.
    struct Served {
        root: TempDir,
        bin: TempDir,
        dir: TempDir,
    }

    impl Served {
        /// `installer` served from master, `latest` as the latest release,
        /// and `latest`'s assets holding a fake `bx`.
        fn new(installer: &[u8], latest: &str) -> Self {
            let served = Self {
                root: TempDir::new().unwrap(),
                bin: TempDir::new().unwrap(),
                dir: TempDir::new().unwrap(),
            };
            let root = served.root.path();
            std::fs::write(root.join("install.sh"), installer).unwrap();
            std::fs::write(
                root.join("latest.json"),
                format!("{{\n  \"url\": \"x\",\n  \"tag_name\": \"{latest}\",\n  \"name\": \"{latest}\"\n}}\n"),
            )
            .unwrap();
            served.release(latest);
            served.fetcher("curl");
            served
        }

        /// `tag`'s tarball and checksum, in the layout the release job uploads.
        fn release(&self, tag: &str) {
            let assets = self.root.path().join("assets").join(tag);
            std::fs::create_dir_all(&assets).unwrap();
            let staging = TempDir::new().unwrap();
            std::fs::write(
                staging.path().join("bx"),
                format!("#!/bin/sh\necho {tag}\n"),
            )
            .unwrap();
            let asset = format!("bx-{}-unknown-linux-musl.tar.gz", std::env::consts::ARCH);
            let status = Command::new("tar")
                .arg("-czf")
                .arg(assets.join(&asset))
                .arg("-C")
                .arg(staging.path())
                .arg("bx")
                .status()
                .unwrap();
            assert!(status.success());
            let digest = ContentHash::of(&std::fs::read(assets.join(&asset)).unwrap()).to_hex();
            std::fs::write(
                assets.join(format!("{asset}.sha256")),
                format!("{digest}  {asset}\n"),
            )
            .unwrap();
        }

        /// The stub, installed as `name` on this harness's `PATH`.
        fn fetcher(&self, name: &str) {
            install_stub(self.bin.path(), name, self.root.path());
        }

        /// The stub first, then the system's `sh`, `tar` and `sha256sum`.
        fn path_var(&self) -> OsString {
            let system = std::env::var_os("PATH").unwrap_or_default();
            std::env::join_paths(
                std::iter::once(self.bin.path().to_path_buf())
                    .chain(std::env::split_paths(&system)),
            )
            .unwrap()
        }

        fn requests(&self) -> String {
            std::fs::read_to_string(self.root.path().join("requests")).unwrap_or_default()
        }

        fn run(&self, request: Request, current: &str) -> (Result<Exit, Error>, String) {
            let mut out = Vec::new();
            let result = run(
                request,
                current,
                self.dir.path(),
                INSTALLER_URL,
                &self.path_var(),
                &mut out,
            );
            (result, String::from_utf8(out).unwrap())
        }

        fn installed(&self) -> Option<String> {
            std::fs::read_to_string(self.dir.path().join("bx")).ok()
        }
    }

    const CHECK: Request = Request {
        check: true,
        force: false,
    };
    const UPGRADE: Request = Request {
        check: false,
        force: false,
    };
    const FORCE: Request = Request {
        check: false,
        force: true,
    };

    #[test]
    fn the_pinned_digest_is_the_installer_in_this_tree() {
        assert_eq!(
            ContentHash::of(INSTALL_SH).to_hex(),
            INSTALLER_SHA256,
            "install.sh changed: every released bx will now refuse to self-upgrade. \
             If that is intended, update INSTALLER_SHA256."
        );
    }

    #[test]
    fn any_other_installer_is_refused_with_where_to_reinstall_from() {
        let err = Installer::verified(b"echo hi\n".to_vec()).unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, Error::InstallerChanged { .. }), "{err:?}");
        assert!(message.contains(INSTALLER_URL), "{message}");
        assert!(message.contains(INSTALL_DOCS_URL), "{message}");
        assert!(message.contains(INSTALLER_SHA256), "{message}");
    }

    #[test]
    fn versions_parse_with_or_without_the_tag_prefix_and_order_numerically() {
        assert_eq!(
            Version::parse("v0.1.1").unwrap(),
            Version::parse("0.1.1").unwrap()
        );
        assert_eq!(Version::parse("0.10.0").unwrap().to_string(), "v0.10.0");
        assert!(Version::parse("v0.10.0").unwrap() > Version::parse("v0.9.9").unwrap());
        assert!(Version::parse("v1.0.0").unwrap() > Version::parse("v0.99.99").unwrap());
        assert!(Version::parse(crate::VERSION).is_ok());
    }

    #[test]
    fn anything_but_three_numbers_is_not_a_version() {
        for text in [
            "",
            "v",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1..3",
            "v1.2.3-rc.1",
            "+1.2.3",
            " 1.2.3",
        ] {
            assert!(
                matches!(Version::parse(text), Err(Error::Version(t)) if t == text),
                "{text:?}"
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn a_version_round_trips_through_its_tag_and_orders_as_its_triple(
            a in (0..u64::MAX, 0..u64::MAX, 0..u64::MAX),
            b in (0..4u64, 0..4u64, 0..4u64),
        ) {
            let version = |(major, minor, patch)| Version { major, minor, patch };
            let tag = version(a).to_string();
            proptest::prop_assert_eq!(&tag, &format!("v{}.{}.{}", a.0, a.1, a.2));
            proptest::prop_assert_eq!(Version::parse(&tag).ok(), Some(version(a)));
            proptest::prop_assert_eq!(Version::parse(&tag[1..]).ok(), Some(version(a)));
            // Small triples, so equal parts and every ordering turn up.
            proptest::prop_assert_eq!(version(b).cmp(&version(a)), b.cmp(&a));
            let small = (a.0 % 4, a.1 % 4, a.2 % 4);
            proptest::prop_assert_eq!(version(b).cmp(&version(small)), b.cmp(&small));
        }
    }

    #[test]
    fn a_childs_stderr_is_its_trimmed_text_after_a_colon_or_nothing() {
        assert_eq!(stderr_suffix(b""), "");
        assert_eq!(stderr_suffix(b"  \n\t"), "");
        assert_eq!(stderr_suffix(b"\n404 https://x\n "), ": 404 https://x");
        assert_eq!(stderr_suffix(b"a\nb\n"), ": a\nb");
        assert_eq!(stderr_suffix(b"bad \xff byte"), ": bad \u{fffd} byte");
    }

    #[test]
    fn an_unparseable_current_version_is_refused_before_any_request() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        for request in [CHECK, UPGRADE, FORCE] {
            let (result, out) = served.run(request, "0.2.0-dev");
            assert!(
                matches!(&result, Err(Error::Version(t)) if t == "0.2.0-dev"),
                "{result:?}"
            );
            assert_eq!(out, "");
        }
        assert_eq!(served.requests(), "", "nothing was fetched");
        assert_eq!(served.installed(), None);
    }

    #[test]
    fn check_reports_a_newer_release_as_pending_and_installs_nothing() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let (result, out) = served.run(CHECK, "0.1.1");
        assert_eq!(result.unwrap(), Exit::Pending);
        assert_eq!(
            out,
            "bx v0.1.1 is installed; v0.2.0 is available. Run `bx self-upgrade`.\n"
        );
        assert!(
            !served.requests().contains("/download/"),
            "{}",
            served.requests()
        );
        assert_eq!(served.installed(), None);
    }

    #[test]
    fn check_at_the_latest_release_is_converged() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let (result, out) = served.run(CHECK, "0.2.0");
        assert_eq!(result.unwrap(), Exit::Converged);
        assert_eq!(out, "bx v0.2.0 is the latest release.\n");
    }

    #[test]
    fn check_from_a_build_newer_than_any_release_is_converged() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let (result, out) = served.run(CHECK, "0.3.0");
        assert_eq!(result.unwrap(), Exit::Converged);
        assert_eq!(out, "bx v0.3.0 is newer than the latest release, v0.2.0.\n");
    }

    #[test]
    fn an_older_bx_is_replaced_by_the_latest_release_as_a_fresh_install_would() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let (result, out) = served.run(UPGRADE, "0.1.1");
        assert_eq!(result.unwrap(), Exit::Converged);
        assert_eq!(
            served.installed().as_deref(),
            Some("#!/bin/sh\necho v0.2.0\n")
        );
        let link = std::fs::read_link(served.dir.path().join("userbox")).unwrap();
        assert_eq!(link, Path::new("bx"));
        // bx's own two lines and nothing of the fresh-install text: no colour
        // regardless of the terminal, and no "Next: bx init".
        assert_eq!(
            out,
            format!(
                "Installing bx v0.2.0 over v0.1.1 in {}...\nInstalled bx v0.2.0.\n",
                served.dir.path().display()
            )
        );
    }

    #[test]
    fn the_latest_release_is_left_alone_unless_forced() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let (result, out) = served.run(UPGRADE, "0.2.0");
        assert_eq!(result.unwrap(), Exit::Converged);
        assert_eq!(
            out,
            "bx v0.2.0 is already the latest release, v0.2.0; nothing to do. \
             `--force` reinstalls v0.2.0.\n"
        );
        assert_eq!(served.installed(), None);
        assert!(
            !served.requests().contains("/download/"),
            "{}",
            served.requests()
        );

        let (result, _) = served.run(FORCE, "0.2.0");
        assert_eq!(result.unwrap(), Exit::Converged);
        assert_eq!(
            served.installed().as_deref(),
            Some("#!/bin/sh\necho v0.2.0\n")
        );
    }

    #[test]
    fn a_build_newer_than_any_release_is_not_downgraded_unless_forced() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let (result, out) = served.run(UPGRADE, "0.3.0");
        assert_eq!(result.unwrap(), Exit::Converged);
        assert!(
            out.contains("newer than the latest release, v0.2.0"),
            "{out}"
        );
        assert_eq!(served.installed(), None);

        let (result, _) = served.run(FORCE, "0.3.0");
        assert_eq!(result.unwrap(), Exit::Converged);
        assert_eq!(
            served.installed().as_deref(),
            Some("#!/bin/sh\necho v0.2.0\n")
        );
    }

    /// `sh -s -- ARGS` over this tree's installer, with only `PATH` set, so
    /// nothing else in this process's environment reaches it.
    fn bare_installer(served: &Served, args: &[&str]) -> std::process::Output {
        let mut child = Command::new("sh")
            .arg("-s")
            .arg("--")
            .args(args)
            .env_clear()
            .env("PATH", served.path_var())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(INSTALL_SH).unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn the_latest_release_is_found_with_no_home_at_all() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let output = bare_installer(&served, &["--latest"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"v0.2.0\n");
    }

    #[test]
    fn the_installer_refuses_an_argument_it_does_not_know() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let output = bare_installer(&served, &["--lates"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unknown argument: --lates"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(served.requests(), "");
    }

    #[test]
    fn a_changed_installer_is_never_run() {
        let mut tampered = INSTALL_SH.to_vec();
        tampered.extend_from_slice(b"touch \"$BX_INSTALL_DIR/ran\"\n");
        let served = Served::new(&tampered, "v0.2.0");
        let (result, out) = served.run(FORCE, "0.1.1");
        assert!(
            matches!(result, Err(Error::InstallerChanged { .. })),
            "{result:?}"
        );
        assert_eq!(out, "");
        assert_eq!(served.requests(), format!("{INSTALLER_URL}\n"));
        assert_eq!(std::fs::read_dir(served.dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn the_version_checked_is_the_version_installed() {
        // The install is handed the tag `--latest` found, not left to look
        // again: only that release's assets are ever requested.
        let served = Served::new(INSTALL_SH, "v0.2.0");
        served.run(UPGRADE, "0.1.1").0.unwrap();
        let requests = served.requests();
        assert!(
            requests.contains("/releases/download/v0.2.0/"),
            "{requests}"
        );
        assert_eq!(
            requests.matches("/releases/latest").count(),
            1,
            "{requests}"
        );
    }

    #[test]
    fn wget_fetches_when_there_is_no_curl() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        // Only the stub `wget` and what it runs: a system `curl` on this
        // `PATH` would be preferred, and would reach the network.
        let only_wget = TempDir::new().unwrap();
        install_stub(only_wget.path(), "wget", served.root.path());
        let system = std::env::var_os("PATH").unwrap_or_default();
        for tool in ["cat", "cp"] {
            let found = usable(detect::locate(tool, &system)).expect(tool);
            std::os::unix::fs::symlink(found, only_wget.path().join(tool)).unwrap();
        }
        assert_eq!(
            fetch(INSTALLER_URL, only_wget.path().as_os_str()).unwrap(),
            INSTALL_SH
        );
        assert_eq!(served.requests(), format!("{INSTALLER_URL}\n"));
    }

    #[test]
    fn neither_curl_nor_wget_is_reported_as_such() {
        let empty = TempDir::new().unwrap();
        let err = fetch(INSTALLER_URL, empty.path().as_os_str()).unwrap_err();
        assert!(matches!(err, Error::NoFetcher), "{err:?}");
    }

    #[test]
    fn a_failed_fetch_names_the_url_and_what_the_fetcher_said() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        let err = fetch("https://example.invalid/nothing", &served.path_var()).unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, Error::Fetch { .. }), "{err:?}");
        assert!(
            message.contains("https://example.invalid/nothing"),
            "{message}"
        );
        assert!(message.contains("404"), "{message}");
    }

    #[test]
    fn no_sh_on_path_is_reported_as_such() {
        let installer = Installer::verified(INSTALL_SH.to_vec()).unwrap();
        let empty = TempDir::new().unwrap();
        let err = installer.latest(empty.path().as_os_str()).unwrap_err();
        assert!(matches!(err, Error::NoShell), "{err:?}");
    }

    #[test]
    fn a_latest_release_nobody_can_find_is_an_error() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        std::fs::write(served.root.path().join("latest.json"), "{}\n").unwrap();
        let (result, _) = served.run(CHECK, "0.1.1");
        let err = result.unwrap_err();
        assert!(matches!(err, Error::Latest { .. }), "{err:?}");
        assert!(
            err.to_string()
                .contains("could not determine the latest release"),
            "{err}"
        );
    }

    #[test]
    fn a_latest_tag_that_is_not_a_version_is_an_error() {
        let served = Served::new(INSTALL_SH, "nightly");
        let (result, _) = served.run(CHECK, "0.1.1");
        assert!(matches!(result, Err(Error::Version(t)) if t == "nightly"));
    }

    #[test]
    fn a_failed_install_reports_what_the_installer_said() {
        let served = Served::new(INSTALL_SH, "v0.2.0");
        std::fs::remove_dir_all(served.root.path().join("assets")).unwrap();
        let (result, _) = served.run(UPGRADE, "0.1.1");
        let err = result.unwrap_err();
        assert!(matches!(err, Error::Install { .. }), "{err:?}");
        assert!(err.to_string().contains("download failed"), "{err}");
        assert_eq!(served.installed(), None);
    }

    #[test]
    fn the_running_binary_has_an_install_directory() {
        let dir = install_dir().unwrap();
        assert!(std::env::current_exe().unwrap().starts_with(&dir));
    }
}
