//! The `[secrets]` table: who secrets are encrypted to, and what decrypts them.
//!
//! ```toml
//! # bx.toml, or a module — committed
//! [secrets]
//! recipients = ["age1…", "ssh-ed25519 AAAA… laptop"]
//!
//! # local.toml, in the state directory — never committed
//! [secrets]
//! identity = "~/.config/age/key.txt"   # default ~/.ssh/id_ed25519
//! ```
//!
//! # Each key has one home
//!
//! The recipient list is the repo's: it is public keys, it is what every
//! account's secrets are encrypted to, and an account that kept its own list in
//! `local.toml` would encrypt to recipients nobody else can see. So a
//! `recipients` in `local.toml` is a load error.
//!
//! The identity is the account's: it names a private key on this machine, and
//! a path to one is exactly the account-specific content Invariant 5 keeps out
//! of the repo. So an `identity` in a committed layer is a load error, and the
//! committed mechanism for a shared answer — a default — is
//! [`crate::secret::DEFAULT_IDENTITY`], which is in bx's source.
//!
//! Which layer a table came from is known only once the layer set is loaded,
//! so the parser here records both keys wherever they appear and
//! [`super::merge`] refuses the misplaced one, as it refuses a committed
//! `[values]` table.
//!
//! Recipients are parsed and checked, and nothing more: adding, removing and
//! rotating them is a later entry's.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[secrets]";

/// Every key a `[secrets]` table may carry.
const KEYS: [&str; 2] = ["recipients", "identity"];

/// What one layer's `[secrets]` table says, or what the merged layers say.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Secrets {
    /// Who secrets are encrypted to. Committed layers only.
    pub recipients: Option<Recipients>,
    /// What decrypts them on this account. `local.toml` only.
    pub identity: Option<Identity>,
}

/// The recipient list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipients {
    /// Each an `age1…` recipient or an ssh public key, as written.
    pub keys: Vec<String>,
    /// Where the list was written.
    pub origin: Origin,
}

/// The account's identity file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Where it is, home-relative when it is under the home.
    pub path: Portable,
    /// Where it was named.
    pub origin: Origin,
}

impl Secrets {
    /// Fold a later layer's table over this one, key by key, the later layer
    /// winning, as `[values]` does.
    pub(crate) fn absorb(&mut self, later: &Self) {
        if let Some(recipients) = &later.recipients {
            self.recipients = Some(recipients.clone());
        }
        if let Some(identity) = &later.identity {
            self.identity = Some(identity.clone());
        }
    }

    /// The identity path as the user spells it: the one `local.toml` names, or
    /// the default.
    #[must_use]
    pub fn identity_spelling(&self) -> &str {
        self.identity
            .as_ref()
            .map_or(crate::secret::DEFAULT_IDENTITY, |identity| {
                identity.path.as_str()
            })
    }

    /// Where the identity file is, rendered against `home`.
    #[must_use]
    pub fn identity_path(&self, home: &Path) -> std::path::PathBuf {
        crate::paths::render(self.identity_spelling(), home)
    }
}

/// Parse a `[secrets]` table.
///
/// `text` is the whole layer file, because spans index into it; `home` is what
/// an identity path is parsed against, so it has one spelling.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key this version does not know, and
/// [`Error::BadValue`] for a recipient that is neither an age recipient nor an
/// ssh public key, an empty recipient list, or an identity that is not a usable
/// path.
pub fn parse_secrets(
    table: &Table,
    file: &Path,
    text: &str,
    home: &Path,
) -> Result<Secrets, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let recipients = if table.contains_key("recipients") {
        let keys = ctx.str_array_at(table, "recipients")?;
        if keys.is_empty() {
            return Err(ctx.bad(
                table,
                "recipients",
                "`recipients` lists who secrets are encrypted to, so it names at least one; \
                 remove the key to declare none",
            ));
        }
        if let Some(bad) = keys.iter().find(|key| !super::values::is_recipient(key)) {
            return Err(ctx.bad(
                table,
                "recipients",
                format!("{bad:?} is neither an `age1…` recipient nor an ssh public key"),
            ));
        }
        Some(Recipients {
            keys,
            origin: ctx.key_origin(table, "recipients"),
        })
    } else {
        None
    };

    let identity = ctx
        .str_at(table, "identity")?
        .map(|raw| {
            Portable::parse_in(raw, home)
                .map(|path| Identity {
                    path,
                    origin: ctx.key_origin(table, "identity"),
                })
                .map_err(|error| ctx.bad(table, "identity", error.to_string()))
        })
        .transpose()?;

    Ok(Secrets {
        recipients,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    const HOME: &str = "/var/home/example";
    const AGE: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

    fn parse(text: &str) -> Result<Secrets, Error> {
        parse_str(text, Path::new("bx.toml"), Path::new(HOME)).map(|config| config.secrets)
    }

    fn message(text: &str) -> String {
        parse(text).expect_err("rejected").to_string()
    }

    #[test]
    fn a_layer_without_the_table_says_nothing() {
        assert_eq!(parse("").expect("parses"), Secrets::default());
    }

    #[test]
    fn recipients_and_an_identity_parse_with_their_lines() {
        let secrets = parse(&format!(
            "[secrets]\nrecipients = [\"{AGE}\", \"ssh-ed25519 AAAAC3Nz host\"]\n\
             identity = \"~/.config/age/./key.txt\"\n"
        ))
        .expect("parses");

        let recipients = secrets.recipients.expect("recipients");
        assert_eq!(recipients.keys, [AGE, "ssh-ed25519 AAAAC3Nz host"]);
        assert_eq!(recipients.origin.line, 2);
        let identity = secrets.identity.expect("an identity");
        assert_eq!(
            identity.path.as_str(),
            "~/.config/age/key.txt",
            "normalised"
        );
        assert_eq!(identity.origin.line, 3);
    }

    #[test]
    fn a_bad_recipient_is_named() {
        let message = message("[secrets]\nrecipients = [\"age1\", \"nope\"]\n");
        assert!(message.contains("bx.toml:2"), "{message}");
        assert!(message.contains("\"age1\""), "{message}");
    }

    #[test]
    fn an_empty_recipient_list_is_refused() {
        assert!(message("[secrets]\nrecipients = []\n").contains("at least one"));
    }

    #[test]
    fn an_identity_that_is_not_a_portable_path_is_refused() {
        let relative = message("[secrets]\nidentity = \"key.txt\"\n");
        assert!(relative.contains("bx.toml:2"), "{relative}");

        let absolute = message(&format!("[secrets]\nidentity = \"{HOME}/key.txt\"\n"));
        assert!(
            absolute.contains("write ~/key.txt"),
            "one spelling: {absolute}"
        );
    }

    #[test]
    fn an_unknown_key_or_type_is_refused() {
        assert!(message("[secrets]\npassphrase = \"x\"\n").contains("unknown key `passphrase`"));
        assert!(message("[secrets]\nidentity = 1\n").contains("must be a string"));
        assert!(message("[[secrets]]\nidentity = \"~/k\"\n").contains("a table `[secrets]`"));
    }

    #[test]
    fn the_identity_defaults_to_the_ssh_ed25519_key() {
        let home = Path::new(HOME);
        let default = Secrets::default();
        assert_eq!(default.identity_spelling(), "~/.ssh/id_ed25519");
        assert_eq!(
            default.identity_path(home),
            Path::new("/var/home/example/.ssh/id_ed25519")
        );

        let named = parse("[secrets]\nidentity = \"/etc/bx/key\"\n").expect("parses");
        assert_eq!(named.identity_path(home), Path::new("/etc/bx/key"));
    }

    #[test]
    fn a_later_table_wins_key_by_key() {
        let mut merged = parse(&format!("[secrets]\nrecipients = [\"{AGE}\"]\n")).expect("one");
        merged.absorb(&parse("[secrets]\nidentity = \"~/k\"\n").expect("two"));
        assert_eq!(merged.recipients.as_ref().expect("kept").keys, [AGE]);
        assert_eq!(
            merged.identity.as_ref().expect("added").path.as_str(),
            "~/k"
        );

        merged.absorb(&Secrets::default());
        assert!(
            merged.recipients.is_some() && merged.identity.is_some(),
            "silence keeps"
        );
    }
}
