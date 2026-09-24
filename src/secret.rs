//! Age secrets, decrypted in-process.
//!
//! A secret target's body is an age file in the config repo, and what lands at
//! the target is its plaintext. Decryption happens here, in this process, with
//! the `age` crate: the static binary needs no `age`, `rage` or `sops` on the
//! machine, and no plaintext passes through a pipe or a temporary file on its
//! way to the atomic writer.
//!
//! # The identity
//!
//! One file, named by `identity` under `[secrets]` in the account's
//! `local.toml`, and [`DEFAULT_IDENTITY`] — the account's existing ssh ed25519
//! key — when it names none. Either kind age reads is accepted:
//!
//! * an **age identity file**, one `AGE-SECRET-KEY-1…` per line, with blank
//!   lines and `#` comments allowed, as `age-keygen` writes it; or the same
//!   file encrypted with a passphrase, as `age -p` writes it;
//! * an **ssh private key** age supports, in the OpenSSH or PEM format `ssh-keygen`
//!   writes, with or without a passphrase.
//!
//! # Nothing asks unless the caller says it may
//!
//! A passphrase-protected identity is **locked**, and [`Unlock`] is the only
//! way to open one. `bx plan` and `bx apply` decide every target with
//! [`Unlock::Never`], so a locked identity is a refusal naming the fix, never a
//! prompt: `apply` runs from scripts and timers, and a run that stopped to ask
//! would hang there with nobody to answer. Only `bx secret list` passes
//! [`Unlock::Ask`], and only when standard input is a terminal.
//!
//! Every call reads and unlocks the identity afresh. A passphrase entered for
//! one secret is not kept for the next one: caching it is a later entry's
//! decision, and not one to make by accident.

use std::io::{BufReader, Read as _};
use std::path::Path;

use age::armor::ArmoredReader;
use age::secrecy::SecretString;
use age::{DecryptError, Decryptor};

/// The identity used when `local.toml` names none: the account's existing ssh
/// ed25519 key, spelled portably.
pub const DEFAULT_IDENTITY: &str = "~/.ssh/id_ed25519";

/// The largest identity file bx reads. An ssh key or an age identity file is a
/// few kilobytes; anything much larger is not one, and is not read into memory
/// to find that out.
const IDENTITY_LIMIT: u64 = 64 * 1024;

/// The prefix of the binary age format, and of its armored form.
const AGE_HEADER: &str = "age-encryption.org/";
/// The first line of an armored age file.
const AGE_ARMOR: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// A passphrase, held so it is zeroed when dropped and never printed.
pub type Passphrase = SecretString;

/// Whether, and how, a locked identity may be unlocked.
pub enum Unlock<'a> {
    /// Never ask. What `plan` and `apply` use.
    Never,
    /// Ask through this function, which is handed the identity as the user
    /// would spell it and returns the passphrase, or `None` when the user gave
    /// none.
    Ask(&'a mut dyn FnMut(&str) -> Option<Passphrase>),
}

impl std::fmt::Debug for Unlock<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Never => "Unlock::Never",
            Self::Ask(_) => "Unlock::Ask",
        })
    }
}

/// Why a secret could not be decrypted.
///
/// Each message is a sentence a blocked row can carry as it is: what is wrong,
/// and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Nothing is at the identity path.
    #[error(
        "there is no identity at {identity} to decrypt it with; set `identity` under [secrets] \
         in local.toml to the age or ssh key this secret is encrypted to"
    )]
    NoIdentity {
        /// The identity, spelled portably.
        identity: String,
    },
    /// The identity path could not be read, or is not a regular file.
    #[error("the identity {identity} could not be read: {reason}")]
    Unreadable {
        /// The identity, spelled portably.
        identity: String,
        /// Why.
        reason: String,
    },
    /// The identity file is neither an age identity file nor an ssh private
    /// key age can use.
    #[error(
        "the identity {identity} is neither an age identity nor an ssh private key age can \
         decrypt with; set `identity` under [secrets] in local.toml to one that is"
    )]
    NotAnIdentity {
        /// The identity, spelled portably.
        identity: String,
    },
    /// The identity is protected by a passphrase and nothing may ask for it.
    #[error(
        "the identity {identity} is locked by a passphrase, and bx plan and bx apply never ask \
         for one; set `identity` under [secrets] in local.toml to a key without a passphrase \
         that this secret is encrypted to"
    )]
    Locked {
        /// The identity, spelled portably.
        identity: String,
    },
    /// The passphrase given did not unlock the identity.
    #[error("the passphrase given for {identity} did not unlock it")]
    WrongPassphrase {
        /// The identity, spelled portably.
        identity: String,
    },
    /// The secret's body is not an age file.
    #[error("the secret is not an age file: {reason}")]
    NotAgeFile {
        /// Why.
        reason: String,
    },
    /// The secret is encrypted with a passphrase rather than to recipients.
    #[error(
        "the secret is encrypted with a passphrase rather than to a recipient, and bx decrypts \
         with an identity only; re-encrypt it to the recipients under [secrets]"
    )]
    PassphraseEncrypted,
    /// The identity is not one of the secret's recipients.
    #[error(
        "the identity {identity} is not one this secret is encrypted to; re-encrypt it to that \
         identity's recipient, or set `identity` under [secrets] in local.toml to one it is \
         encrypted to"
    )]
    NoMatchingKey {
        /// The identity, spelled portably.
        identity: String,
    },
    /// The age file is damaged.
    #[error("the secret could not be decrypted: {reason}")]
    Corrupt {
        /// Why.
        reason: String,
    },
}

/// Decrypt `ciphertext` with the identity at `identity`.
///
/// `shown` is the identity as the user spells it, for messages and for the
/// passphrase question. The ciphertext may be binary or armored.
///
/// # Errors
///
/// A [`Refusal`] naming what stopped it. Nothing here is fatal to a run: a
/// refused secret is one blocked target, and the rest of the plan stands.
pub fn decrypt(
    ciphertext: &[u8],
    identity: &Path,
    shown: &str,
    unlock: Unlock<'_>,
) -> Result<Vec<u8>, Refusal> {
    // The ciphertext is judged before the identity is unlocked, so a secret
    // that could never be decrypted costs nobody a passphrase.
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(ciphertext)).map_err(|error| {
        Refusal::NotAgeFile {
            reason: error.to_string(),
        }
    })?;
    if decryptor.is_scrypt() {
        return Err(Refusal::PassphraseEncrypted);
    }

    let keys = unlocked(load(identity, shown)?, shown, unlock)?;
    let mut reader = decryptor
        .decrypt(keys.iter().map(|key| key.as_ref() as &dyn age::Identity))
        .map_err(|error| match error {
            DecryptError::NoMatchingKeys => Refusal::NoMatchingKey {
                identity: shown.to_string(),
            },
            other => Refusal::Corrupt {
                reason: other.to_string(),
            },
        })?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| Refusal::Corrupt {
            reason: error.to_string(),
        })?;
    Ok(plaintext)
}

/// The keys an identity file holds.
type Keys = Vec<Box<dyn age::Identity>>;

/// An identity file, read.
enum Loaded {
    /// Usable as it is.
    Ready(Keys),
    /// An ssh key behind a passphrase.
    LockedSsh(Box<age::ssh::EncryptedKey>),
    /// An age identity file encrypted with a passphrase: the whole file.
    LockedAge(Vec<u8>),
}

/// Read the identity at `path` and say what it is.
fn load(path: &Path, shown: &str) -> Result<Loaded, Refusal> {
    let unreadable = |reason: String| Refusal::Unreadable {
        identity: shown.to_string(),
        reason,
    };
    // Followed through a link, since `~/.ssh/id_ed25519` is often one. A FIFO
    // or a device would block the read or never end it.
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Refusal::NoIdentity {
                identity: shown.to_string(),
            });
        }
        Err(error) => return Err(unreadable(error.to_string())),
    };
    if !meta.is_file() {
        return Err(unreadable("it is not a regular file".to_string()));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(IDENTITY_LIMIT + 1).read_to_end(&mut bytes))
        .map_err(|error| unreadable(error.to_string()))?;
    if bytes.len() as u64 > IDENTITY_LIMIT {
        return Err(Refusal::NotAnIdentity {
            identity: shown.to_string(),
        });
    }
    classify(bytes, shown)
}

/// What an identity file's bytes are.
fn classify(bytes: Vec<u8>, shown: &str) -> Result<Loaded, Refusal> {
    let not_one = || Refusal::NotAnIdentity {
        identity: shown.to_string(),
    };
    let text = String::from_utf8_lossy(&bytes);
    let head = text.trim_start();

    if head.starts_with(AGE_HEADER) || head.starts_with(AGE_ARMOR) {
        return Ok(Loaded::LockedAge(bytes));
    }
    if head.starts_with("-----BEGIN") {
        let key = age::ssh::Identity::from_buffer(BufReader::new(&bytes[..]), None)
            .map_err(|_| not_one())?;
        return match key {
            age::ssh::Identity::Encrypted(key) => Ok(Loaded::LockedSsh(Box::new(key))),
            age::ssh::Identity::Unencrypted(key) => Ok(Loaded::Ready(vec![Box::new(
                age::ssh::Identity::Unencrypted(key),
            )])),
            age::ssh::Identity::Unsupported(_) => Err(not_one()),
        };
    }
    age_keys(&text).ok_or_else(not_one)
}

/// The keys of a plain age identity file, or `None` when it is not one.
///
/// Every line that is not blank and not a `#` comment must be a key, as `age`
/// itself requires: a file with one bad line is not an identity file with one
/// key fewer.
fn age_keys(text: &str) -> Option<Loaded> {
    let mut keys: Keys = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(Box::new(line.parse::<age::x25519::Identity>().ok()?));
    }
    (!keys.is_empty()).then_some(Loaded::Ready(keys))
}

/// The keys of `loaded`, unlocking it when `unlock` allows.
fn unlocked(loaded: Loaded, shown: &str, unlock: Unlock<'_>) -> Result<Keys, Refusal> {
    let locked = || Refusal::Locked {
        identity: shown.to_string(),
    };
    let wrong = || Refusal::WrongPassphrase {
        identity: shown.to_string(),
    };
    let ask = |unlock: Unlock<'_>| match unlock {
        Unlock::Never => None,
        Unlock::Ask(ask) => ask(shown),
    };
    match loaded {
        Loaded::Ready(keys) => Ok(keys),
        Loaded::LockedSsh(key) => {
            let passphrase = ask(unlock).ok_or_else(locked)?;
            let key = key.decrypt(passphrase).map_err(|_| wrong())?;
            Ok(vec![Box::new(age::ssh::Identity::Unencrypted(key))])
        }
        Loaded::LockedAge(bytes) => {
            let passphrase = ask(unlock).ok_or_else(locked)?;
            let not_one = || Refusal::NotAnIdentity {
                identity: shown.to_string(),
            };
            let decryptor =
                Decryptor::new_buffered(ArmoredReader::new(&bytes[..])).map_err(|_| not_one())?;
            let key = age::scrypt::Identity::new(passphrase);
            let mut reader = decryptor
                .decrypt(std::iter::once(&key as &dyn age::Identity))
                .map_err(|_| wrong())?;
            let mut plain = Vec::new();
            reader.read_to_end(&mut plain).map_err(|_| wrong())?;
            match age_keys(&String::from_utf8_lossy(&plain)) {
                Some(Loaded::Ready(keys)) => Ok(keys),
                _ => Err(not_one()),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::testing::guarded_home;

    /// A throwaway ssh ed25519 key made for these tests and nothing else. It
    /// protects nothing: it is a fixture, like the keys in age's own tests.
    pub(crate) const SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAdOKhwq8c9E7HZ+6YBJV3iQ3FyYZLVtxrfmFmOB3NBQwAAAJCD70E1g+9B
NQAAAAtzc2gtZWQyNTUxOQAAACAdOKhwq8c9E7HZ+6YBJV3iQ3FyYZLVtxrfmFmOB3NBQw
AAAECe7hPMPbK9Vucg7rOKN7vZVFzbC3nzCuhYbyKghcDRjR04qHCrxz0Tsdn7pgElXeJD
cXJhktW3Gt+YWY4Hc0FDAAAAB2J4LXRlc3QBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
";
    /// [`SSH_KEY`]'s public half.
    pub(crate) const SSH_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB04qHCrxz0Tsdn7pgElXeJDcXJhktW3Gt+YWY4Hc0FD bx-test";

    /// A throwaway ssh ed25519 key locked with [`LOCKED_PASSPHRASE`], at one
    /// bcrypt round so unlocking it costs a test nothing.
    pub(crate) const LOCKED_SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCLiMjN9p
zBVOXG/inwQBp9AAAAAQAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPlYyLQduJzzIg/6
DL5hn0qoAxJah5O+elpI/PN1ym3hAAAAoCGhQmLuDgzXdPxOuYxHocs12jvH8RkwBn108b
gYZMGvFd5c7i38dqIZIF7iYjY+M48H1g3/qckF7bW2VyJTUx1y/AoU5WHIrkFri1Y6x5sK
BI1kUR4n+pcfByz6lbofkpMFveB7fFGnx7+8QdkojoRf1kjs4cQ4HGhAW20awDKusSvxYc
ffxbALZN3JpDBBEk8TeZk55mo+jjJlOtAf63Q=
-----END OPENSSH PRIVATE KEY-----
";
    /// [`LOCKED_SSH_KEY`]'s public half.
    pub(crate) const LOCKED_SSH_PUB: &str = "ssh-ed25519 \
        AAAAC3NzaC1lZDI1NTE5AAAAIPlYyLQduJzzIg/6DL5hn0qoAxJah5O+elpI/PN1ym3h bx-test-locked";
    /// What unlocks [`LOCKED_SSH_KEY`].
    pub(crate) const LOCKED_PASSPHRASE: &str = "correct horse";

    /// `plaintext` encrypted to the recipient spelled `recipient`, which is an
    /// `age1…` recipient or an ssh public key.
    pub(crate) fn encrypt_to(recipient: &str, plaintext: &[u8]) -> Vec<u8> {
        let recipient: Box<dyn age::Recipient> = match recipient.parse::<age::x25519::Recipient>() {
            Ok(age) => Box::new(age),
            Err(_) => Box::new(
                recipient
                    .parse::<age::ssh::Recipient>()
                    .expect("an age or ssh recipient"),
            ),
        };
        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient.as_ref()))
            .expect("a recipient");
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).expect("the output");
        writer.write_all(plaintext).expect("the plaintext");
        writer.finish().expect("the stream");
        out
    }

    /// `ciphertext` in age's armored form.
    fn armored(ciphertext: &[u8]) -> Vec<u8> {
        use age::armor::{ArmoredWriter, Format};
        let mut out = Vec::new();
        let mut writer = ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor).expect("armor");
        writer.write_all(ciphertext).expect("write");
        writer.finish().expect("finish");
        out
    }

    /// `text` encrypted with `passphrase`, cheaply.
    fn passphrase_encrypted(text: &[u8], passphrase: &str) -> Vec<u8> {
        let mut recipient = age::scrypt::Recipient::new(passphrase.into());
        recipient.set_work_factor(2);
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as _)).expect("a recipient");
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).expect("the output");
        writer.write_all(text).expect("the text");
        writer.finish().expect("the stream");
        out
    }

    fn never(ciphertext: &[u8], identity: &Path) -> Result<Vec<u8>, Refusal> {
        decrypt(ciphertext, identity, "~/id", Unlock::Never)
    }

    fn asking(
        ciphertext: &[u8],
        identity: &Path,
        answer: Option<&str>,
    ) -> Result<Vec<u8>, Refusal> {
        let mut asked = Vec::new();
        let result = decrypt(
            ciphertext,
            identity,
            "~/id",
            Unlock::Ask(&mut |shown| {
                asked.push(shown.to_string());
                answer.map(Passphrase::from)
            }),
        );
        assert_eq!(asked, ["~/id"], "asked once, naming the identity");
        result
    }

    #[test]
    fn an_age_identity_decrypts_binary_and_armored_secrets() {
        let home = guarded_home();
        let key = age::x25519::Identity::generate();
        let file = home.write(
            "id",
            &format!(
                "# created by age-keygen\n\n{}\n",
                age::secrecy::ExposeSecret::expose_secret(&key.to_string())
            ),
        );
        let ciphertext = encrypt_to(&key.to_public().to_string(), b"token\n");

        assert_eq!(never(&ciphertext, &file).expect("binary"), b"token\n");
        assert_eq!(
            never(&armored(&ciphertext), &file).expect("armored"),
            b"token\n"
        );
    }

    #[test]
    fn an_unlocked_ssh_key_decrypts_without_asking() {
        let home = guarded_home();
        let file = home.write("id", SSH_KEY);
        let ciphertext = encrypt_to(SSH_PUB, b"ssh\n");

        assert_eq!(never(&ciphertext, &file).expect("decrypts"), b"ssh\n");
        let mut ask = |_: &str| -> Option<Passphrase> { panic!("an unlocked key was asked for") };
        assert_eq!(
            decrypt(&ciphertext, &file, "~/id", Unlock::Ask(&mut ask)).expect("decrypts"),
            b"ssh\n"
        );
    }

    #[test]
    fn a_locked_ssh_key_is_refused_unless_asking_is_allowed() {
        let home = guarded_home();
        let file = home.write("id", LOCKED_SSH_KEY);
        let ciphertext = encrypt_to(LOCKED_SSH_PUB, b"locked\n");

        let refused = never(&ciphertext, &file).expect_err("never asks");
        assert_eq!(
            refused,
            Refusal::Locked {
                identity: "~/id".to_string()
            }
        );
        assert!(refused.to_string().contains("never ask"), "{refused}");
        assert!(
            refused.to_string().contains("local.toml"),
            "names the fix: {refused}"
        );

        assert_eq!(
            asking(&ciphertext, &file, None),
            Err(Refusal::Locked {
                identity: "~/id".to_string()
            }),
            "no answer is no passphrase"
        );
        assert_eq!(
            asking(&ciphertext, &file, Some("wrong")),
            Err(Refusal::WrongPassphrase {
                identity: "~/id".to_string()
            })
        );
        assert_eq!(
            asking(&ciphertext, &file, Some(LOCKED_PASSPHRASE)).expect("unlocked"),
            b"locked\n"
        );
    }

    #[test]
    fn a_passphrase_encrypted_age_identity_is_locked_too() {
        let home = guarded_home();
        let key = age::x25519::Identity::generate();
        let secret = age::secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let locked = passphrase_encrypted(format!("{secret}\n").as_bytes(), "pass");
        let file = home.child("id");
        std::fs::write(&file, armored(&locked)).expect("the identity");
        let ciphertext = encrypt_to(&key.to_public().to_string(), b"age\n");

        assert!(matches!(
            never(&ciphertext, &file),
            Err(Refusal::Locked { .. })
        ));
        assert!(matches!(
            asking(&ciphertext, &file, Some("nope")),
            Err(Refusal::WrongPassphrase { .. })
        ));
        assert_eq!(
            asking(&ciphertext, &file, Some("pass")).expect("unlocked"),
            b"age\n"
        );

        // Unlocked, but what it held is not an identity.
        std::fs::write(&file, passphrase_encrypted(b"not a key\n", "pass")).expect("rewrite");
        assert!(matches!(
            asking(&ciphertext, &file, Some("pass")),
            Err(Refusal::NotAnIdentity { .. })
        ));
    }

    #[test]
    fn a_missing_identity_names_the_fix() {
        let home = guarded_home();
        let refused = never(&encrypt_to(SSH_PUB, b"x"), &home.child("absent")).expect_err("none");
        assert_eq!(
            refused,
            Refusal::NoIdentity {
                identity: "~/id".to_string()
            }
        );
        assert!(
            refused.to_string().contains("`identity` under [secrets]"),
            "{refused}"
        );
    }

    #[test]
    fn an_identity_that_is_not_a_regular_file_is_not_read() {
        let home = guarded_home();
        std::fs::create_dir(home.child("dir")).expect("a directory");
        assert!(matches!(
            never(&encrypt_to(SSH_PUB, b"x"), &home.child("dir")),
            Err(Refusal::Unreadable { .. })
        ));
    }

    #[test]
    fn a_file_that_is_no_identity_is_refused() {
        let home = guarded_home();
        let ciphertext = encrypt_to(SSH_PUB, b"x");
        let cases: [(&str, String); 5] = [
            ("empty", String::new()),
            ("comments", "# nothing here\n\n".to_string()),
            ("prose", "hello\n".to_string()),
            (
                "a bad line after a key",
                format!(
                    "{}\nnot a key\n",
                    age::secrecy::ExposeSecret::expose_secret(
                        &age::x25519::Identity::generate().to_string()
                    )
                ),
            ),
            (
                "a mangled ssh key",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
                    .to_string(),
            ),
        ];
        for (name, text) in cases {
            let file = home.write(name, &text);
            assert!(
                matches!(
                    never(&ciphertext, &file),
                    Err(Refusal::NotAnIdentity { .. })
                ),
                "{name}"
            );
        }

        let huge = home.child("huge");
        std::fs::write(
            &huge,
            vec![b'#'; usize::try_from(IDENTITY_LIMIT).expect("fits") + 1],
        )
        .expect("a huge file");
        assert!(matches!(
            never(&ciphertext, &huge),
            Err(Refusal::NotAnIdentity { .. })
        ));
    }

    #[test]
    fn a_secret_for_someone_else_names_the_identity() {
        let home = guarded_home();
        let file = home.write("id", SSH_KEY);
        let other = age::x25519::Identity::generate().to_public().to_string();

        let refused = never(&encrypt_to(&other, b"x"), &file).expect_err("not ours");
        assert_eq!(
            refused,
            Refusal::NoMatchingKey {
                identity: "~/id".to_string()
            }
        );
    }

    #[test]
    fn a_body_that_is_not_an_age_file_is_refused_before_anything_is_asked() {
        let home = guarded_home();
        let file = home.write("id", LOCKED_SSH_KEY);
        let mut ask = |_: &str| -> Option<Passphrase> { panic!("asked for a hopeless secret") };

        assert!(matches!(
            decrypt(b"plain text\n", &file, "~/id", Unlock::Ask(&mut ask)),
            Err(Refusal::NotAgeFile { .. })
        ));
        assert_eq!(
            decrypt(
                &passphrase_encrypted(b"x", "p"),
                &file,
                "~/id",
                Unlock::Ask(&mut ask)
            ),
            Err(Refusal::PassphraseEncrypted)
        );
    }

    #[test]
    fn a_truncated_secret_is_corrupt() {
        let home = guarded_home();
        let file = home.write("id", SSH_KEY);
        let mut ciphertext = encrypt_to(SSH_PUB, &[b'x'; 200]);
        ciphertext.truncate(ciphertext.len() - 20);

        assert!(matches!(
            never(&ciphertext, &file),
            Err(Refusal::Corrupt { .. })
        ));
    }

    #[test]
    fn unlock_debug_names_the_variant_and_never_a_passphrase() {
        let mut ask = |_: &str| None;
        assert_eq!(format!("{:?}", Unlock::Never), "Unlock::Never");
        assert_eq!(format!("{:?}", Unlock::Ask(&mut ask)), "Unlock::Ask");
    }
}
