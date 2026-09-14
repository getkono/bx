//! The crate's one permission type, and the kinds a destination can have.
//!
//! [`Mode`] carries the twelve meaningful bits of a POSIX mode and nothing else
//! — no file type, no `umask` interaction — so a mode read from a ledger entry
//! means the same thing as a mode written into one, and a mode a config author
//! wrote means the same thing as a mode `stat` reported.
//!
//! **This is the file mode, not the plan/apply mode.** `plan::Mode { Plan,
//! Apply }` is a different type in a different module; neither is ever
//! glob-imported, and `config::target::Mode` is a `pub use` of this one.

use std::fmt;
use std::str::FromStr;

use rustix::fs::Mode as RawMode;
use serde::{Deserialize, Serialize};

/// A POSIX file mode: the permission and set-id bits, and nothing else.
///
/// Constructed from raw bits or parsed from the quoted octal form a config file
/// uses, compared by value, and rendered as four octal digits so an error
/// message reads the way `chmod` does. The file-type bits a `stat` returns are
/// deliberately not carried: bx sets permissions, it never changes what a path
/// *is*.
///
/// # Two codecs, because there are two audiences
///
/// One type serves the config schema — where `config::target::Mode` names it —
/// and machine-owned state, where the ledger records what bx wrote. They want
/// opposite encodings, and the serde format says which is which:
///
/// * **not human-readable** (MessagePack, in `ledger.mpk`): a bare `u32`.
///   Length-prefixed, exact, and byte-identical to what the state directory
///   already wrote before this type was collapsed into one.
/// * **human-readable** (TOML, in `bx.toml`): the quoted octal string
///   `"0600"`, parsed by [`Mode::parse_octal`]. A bare TOML integer is refused
///   with the reason: `mode = 600` would be decimal 600, which is `0o1130` —
///   setgid set, and the owner unable to read their own file — and TOML's own
///   octal literal, `0o600`, is not how a mode is written anywhere else.
///
/// Without the split, the transparent `u32` codec the ledger needs would also
/// be the config schema's, and `mode = 600` would deserialise silently into
/// exactly that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mode(u32);

impl Mode {
    /// `0644` — the mode bx gives a generated file with no mode of its own.
    pub const DEFAULT_FILE: Self = Self(0o644);
    /// `0755` — the mode bx gives a directory it creates for a target, and the
    /// mode it gives an implicit parent directory it had to invent.
    pub const DEFAULT_DIR: Self = Self(0o755);
    /// `0600` — owner-only. Every file bx writes inside the state directory,
    /// and every decrypted secret.
    pub const PRIVATE_FILE: Self = Self(0o600);
    /// `0700` — owner-only. The state directory and everything under it.
    pub const PRIVATE_DIR: Self = Self(0o700);

    /// A mode from raw bits. Anything above the twelve permission bits is
    /// discarded, so a `stat` result can be handed over directly.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & 0o7777)
    }

    /// The twelve permission bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0 & 0o7777
    }

    /// Parse the quoted octal form a config file uses.
    ///
    /// **A bare TOML integer is not accepted.** `mode = 600` is decimal 600 and
    /// means nothing at all, and while TOML *does* have an octal literal it is
    /// spelled `0o600`, which is not how a mode is written anywhere else a user
    /// meets one. Only the quoted `mode = "0600"` parses — one spelling, and the
    /// one `chmod`, `ls -l` and every other tool already use. The
    /// [`Deserialize`] impl refuses an integer before it reaches here, naming
    /// the decimal it would have meant. One to four octal digits, so the
    /// setuid, setgid and sticky bits are expressible and a fifth digit is a
    /// typo rather than a silently truncated mode.
    ///
    /// # Errors
    ///
    /// [`ModeError::Invalid`] for anything else.
    pub fn parse_octal(raw: &str) -> Result<Self, ModeError> {
        // `from_str_radix` alone is not enough: it accepts a leading `+`, and it
        // has no opinion about how many digits a mode may have.
        let usable = (1..=4).contains(&raw.len()) && raw.bytes().all(|b| matches!(b, b'0'..=b'7'));

        u32::from_str_radix(raw, 8)
            .ok()
            .filter(|_| usable)
            .map(Self)
            .ok_or_else(|| ModeError::Invalid(raw.to_string()))
    }

    /// The mode to use for a destination of `kind` when the target declared one
    /// — or did not.
    ///
    /// A declared mode is authoritative: it is never widened, narrowed, or
    /// masked by the process `umask`. Only the absence of one falls back, and
    /// the fallback depends on what is being written, not on what is already
    /// there.
    #[must_use]
    pub const fn resolve(declared: Option<Self>, kind: Kind) -> Self {
        match declared {
            Some(mode) => mode,
            None => kind.default_mode(),
        }
    }

    /// Whether any group or other bit is set.
    ///
    /// The question the state directory asks before tightening itself: a
    /// directory holding prior copies of the user's private files must not be
    /// readable by anyone else.
    #[must_use]
    pub const fn is_shared(self) -> bool {
        self.bits() & 0o077 != 0
    }

    /// Whether group or other may **write**.
    ///
    /// This is `ssh`'s `StrictModes` predicate, and `gpg`'s: a group- or
    /// world-writable key, config or directory is refused outright rather than
    /// used with a warning. `doctor` reads it.
    #[must_use]
    pub const fn is_group_or_world_writable(self) -> bool {
        self.bits() & 0o022 != 0
    }

    /// Whether this mode lets someone other than the owner **read or write**
    /// where `narrower` would not.
    ///
    /// The comparison a directory is held to against the files inside it. The
    /// execute bits are deliberately excluded: a directory needs its group and
    /// other execute bits to be traversable at all, and matching a directory's
    /// traversal bit against a file's execute bit is a category error that would
    /// report every ordinary `0755` directory holding an ordinary `0644` file.
    ///
    /// So `0755` is not wider than `0644` — the directory grants exactly the
    /// read the file already grants — but `0755` *is* wider than `0600`, which
    /// is the `~/.ssh` case: a directory anyone may list, holding a file only
    /// the owner may read.
    ///
    /// A directory against **its own declaration** is a different question,
    /// with both sides a directory's mode, and [`Mode::grants_more_than`]
    /// answers it with execute compared.
    #[must_use]
    pub const fn is_wider_than(self, narrower: Self) -> bool {
        /// Group and other, read and write. Execute is not compared.
        const GROUP_AND_OTHER_RW: u32 = 0o066;

        self.bits() & GROUP_AND_OTHER_RW & !narrower.bits() != 0
    }

    /// Whether this mode grants someone other than the owner **any**
    /// permission — read, write or execute — that `declared` does not.
    ///
    /// The comparison a directory is held to against the mode its own
    /// directory target declares. Beside [`Mode::is_shared`] (does anyone else
    /// get anything) and [`Mode::is_wider_than`] (a directory against a file
    /// inside it, where execute is excluded), this is the third predicate, and
    /// here execute is compared: both modes are a directory's, so a group or
    /// other execute bit is traversal on both sides, and a `0711` directory
    /// declared `0700` lets anyone reach a file inside it by name.
    ///
    /// The owner's bits and the setuid, setgid and sticky bits are not
    /// compared: none of them grants anybody else access. So `0711` and `0755`
    /// grant more than `0700`, while `0750` does not grant more than `0755`
    /// and `2700` does not grant more than `0700`.
    #[must_use]
    pub const fn grants_more_than(self, declared: Self) -> bool {
        /// Group and other, read, write and execute.
        const GROUP_AND_OTHER: u32 = 0o077;

        self.bits() & GROUP_AND_OTHER & !declared.bits() != 0
    }

    /// Whether every bit of `required` is set in this mode.
    ///
    /// The question `compare` asks a file target's declared mode: it must
    /// grant its owner `0400`, or bx could not read back what it wrote. Special
    /// bits count like any other, so `2775` includes `0700` and `0600` does
    /// not.
    #[must_use]
    pub const fn includes(self, required: Self) -> bool {
        self.bits() & required.bits() == required.bits()
    }
}

impl FromStr for Mode {
    type Err = ModeError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse_octal(raw)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.bits())
    }
}

impl From<Mode> for RawMode {
    fn from(mode: Mode) -> Self {
        Self::from_bits_truncate(mode.bits())
    }
}

impl Serialize for Mode {
    /// A quoted octal string for a human-readable format, a bare `u32`
    /// otherwise. See the type's documentation for why there are two.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_u32(self.bits())
        }
    }
}

impl<'de> Deserialize<'de> for Mode {
    /// A quoted octal string from a human-readable format, a bare `u32`
    /// otherwise. See the type's documentation for why there are two.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(DeclaredMode)
        } else {
            u32::deserialize(deserializer).map(Self::from_bits)
        }
    }
}

/// Reads the form a config author writes, and refuses the form they meant.
struct DeclaredMode;

impl serde::de::Visitor<'_> for DeclaredMode {
    type Value = Mode;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("one to four octal digits in quotes, like \"0600\"")
    }

    fn visit_str<E: serde::de::Error>(self, raw: &str) -> Result<Mode, E> {
        Mode::parse_octal(raw).map_err(E::custom)
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Mode, E> {
        Err(E::custom(unquoted(&value.to_string())))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Mode, E> {
        Err(E::custom(unquoted(&value.to_string())))
    }
}

/// The message an unquoted mode gets: what it would have meant, and the fix.
fn unquoted(digits: &str) -> String {
    format!(
        "a mode must be quoted: `mode = {digits}` is decimal {digits}, and TOML's own octal \
         literal (0o{digits}) is not how a mode is written anywhere else. Write \
         `mode = \"{digits}\"` if {digits} is the octal you meant"
    )
}

/// A mode that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModeError {
    /// Not one to four octal digits.
    #[error("a mode must be one to four octal digits in quotes, like \"0600\"; got {0:?}")]
    Invalid(String),
}

/// What a path on disk turned out to be.
///
/// Reported by the observation step of an atomic write, which uses
/// `symlink_metadata` and therefore never follows a link: a symlink is a
/// [`Kind::Symlink`], never the kind of whatever it points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Nothing is there.
    Absent,
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link, whether or not it resolves.
    Symlink,
    /// A socket, fifo, or device node.
    Other,
}

impl Kind {
    /// The mode a destination of this kind gets when the target does not say.
    ///
    /// Only a directory differs; everything bx writes bytes into is a file, and
    /// an absent destination is one bx is about to create as a file.
    #[must_use]
    pub const fn default_mode(self) -> Mode {
        match self {
            Self::Dir => Mode::DEFAULT_DIR,
            Self::Absent | Self::File | Self::Symlink | Self::Other => Mode::DEFAULT_FILE,
        }
    }

    /// Whether bx may replace a destination of this kind by writing bytes to it.
    ///
    /// A directory, a socket and a device node are not files and are never
    /// replaced. A symlink is refused for a different reason: `rename(2)` onto a
    /// link's path replaces **the link itself**, so writing "through" one would
    /// silently convert a link the user created into a regular file.
    #[must_use]
    pub const fn is_writable_destination(self) -> bool {
        matches!(self, Self::Absent | Self::File)
    }
}

impl From<std::fs::FileType> for Kind {
    fn from(ty: std::fs::FileType) -> Self {
        if ty.is_symlink() {
            Self::Symlink
        } else if ty.is_dir() {
            Self::Dir
        } else if ty.is_file() {
            Self::File
        } else {
            Self::Other
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            Self::Absent => "nothing",
            Self::File => "a file",
            Self::Dir => "a directory",
            Self::Symlink => "a symlink",
            Self::Other => "not a regular file",
        };
        f.write_str(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mode_keeps_only_the_permission_bits() {
        // 0o100644 is what `stat` reports for a regular file at 0644.
        assert_eq!(Mode::from_bits(0o100_644), Mode::DEFAULT_FILE);
        assert_eq!(Mode::DEFAULT_FILE.bits(), 0o644);
    }

    #[test]
    fn a_mode_parses_the_quoted_octal_form() {
        assert_eq!(Mode::parse_octal("0600").expect("parse").bits(), 0o600);
        assert_eq!(Mode::parse_octal("600").expect("parse").bits(), 0o600);
        assert_eq!(Mode::parse_octal("755").expect("parse").bits(), 0o755);
        assert_eq!(Mode::parse_octal("4755").expect("parse").bits(), 0o4755);
        assert_eq!(Mode::parse_octal("0").expect("parse").bits(), 0);
    }

    #[test]
    fn a_mode_parses_through_from_str_identically() {
        assert_eq!("0600".parse::<Mode>(), Mode::parse_octal("0600"));
        assert_eq!("0o600".parse::<Mode>(), Mode::parse_octal("0o600"));
        assert_eq!("rwx".parse::<Mode>(), Mode::parse_octal("rwx"));
    }

    #[test]
    fn a_mode_rejects_non_octal_and_out_of_range() {
        for raw in [
            "8", "0688", "", "rwx", "+644", "00644", "0o600", " 644", "-1",
        ] {
            assert_eq!(
                Mode::parse_octal(raw),
                Err(ModeError::Invalid(raw.to_string())),
                "{raw:?} must not parse",
            );
        }
    }

    #[test]
    fn a_mode_renders_as_four_octal_digits() {
        assert_eq!(Mode::PRIVATE_FILE.to_string(), "0600");
        assert_eq!(Mode::DEFAULT_FILE.to_string(), "0644");
        assert_eq!(Mode::DEFAULT_DIR.to_string(), "0755");
        assert_eq!(Mode::from_bits(0o7).to_string(), "0007");
    }

    #[test]
    fn the_mode_a_config_author_declares_is_this_mode() {
        // There is one declaration, and `config::target::Mode` names it. No
        // conversion exists because there are no longer two types to convert
        // between — which is the whole point of the collapse.
        let declared = crate::config::target::Mode::parse_octal("0600").expect("a valid mode");
        assert_eq!(declared, Mode::PRIVATE_FILE);
        assert_eq!(crate::config::target::Mode::DEFAULT_DIR, Mode::DEFAULT_DIR);
        assert_eq!(
            crate::config::target::Mode::parse_octal("8"),
            Err(crate::config::target::ModeError::Invalid("8".to_string())),
        );
    }

    #[test]
    fn a_mode_round_trips_through_messagepack() {
        let bytes = rmp_serde::to_vec_named(&Mode::PRIVATE_FILE).expect("encode");
        let back: Mode = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(back, Mode::PRIVATE_FILE);
    }

    #[test]
    fn the_messagepack_encoding_is_the_bare_integer_the_ledger_already_holds() {
        // The machine-owned half of the split codec, pinned as bytes rather
        // than as a round trip: a `ledger.mpk` written before this type carried
        // a config-facing `Deserialize` must still decode, so the encoding is
        // exactly what a bare `u32` produces and nothing else.
        assert_eq!(
            rmp_serde::to_vec_named(&Mode::PRIVATE_FILE).expect("encode"),
            rmp_serde::to_vec_named(&0o600_u32).expect("encode a bare u32"),
        );
        let from_bare: Mode =
            rmp_serde::from_slice(&rmp_serde::to_vec_named(&0o600_u32).expect("encode"))
                .expect("a bare integer decodes as a mode");
        assert_eq!(from_bare, Mode::PRIVATE_FILE);
    }

    /// The shape a `[[target]]` table has where `mode` appears.
    #[derive(Debug, Serialize, Deserialize)]
    struct Declared {
        mode: Mode,
    }

    #[test]
    fn a_declared_mode_is_read_from_the_quoted_octal_form() {
        let declared: Declared =
            toml_edit::de::from_str("mode = \"0600\"").expect("a quoted octal mode");
        assert_eq!(declared.mode, Mode::PRIVATE_FILE);

        // And back out the same way, so a config bx writes is a config bx
        // reads.
        let toml = toml_edit::ser::to_string(&declared).expect("serialise");
        assert_eq!(toml.trim(), "mode = \"0600\"");
    }

    #[test]
    fn a_bare_integer_mode_is_refused_at_the_serde_layer() {
        // `mode = 600` is decimal 600, which is 0o1130: setgid set, owner --x,
        // group -wx, other -w-. The transparent `u32` codec the ledger needs
        // would have accepted it silently, which is why the codec is split.
        let err = toml_edit::de::from_str::<Declared>("mode = 600").expect_err("must be refused");
        let message = err.to_string();
        assert!(message.contains("must be quoted"), "{message}");
        assert!(message.contains("decimal 600"), "{message}");
        assert!(message.contains("mode = \"600\""), "{message}");
        // TOML has an octal literal; the message may not tell the user it does
        // not (the base corrected the same claim in `config::target`).
        assert!(!message.contains("no octal literal"), "{message}");
        assert!(message.contains("0o600"), "{message}");
    }

    #[test]
    fn an_unsigned_integer_mode_is_refused_with_the_same_reason() {
        use serde::de::IntoDeserializer as _;
        use serde::de::value;

        // TOML hands a bare integer to `visit_i64`, but a human-readable
        // format may hand an unsigned one to `visit_u64` — serde's own value
        // deserializers do — and it must get the same refusal, not serde's
        // generic "invalid type".
        let deserializer: value::U64Deserializer<value::Error> = 600_u64.into_deserializer();
        let err = Mode::deserialize(deserializer).expect_err("must be refused");
        let message = err.to_string();
        assert!(message.contains("must be quoted"), "{message}");
        assert!(message.contains("decimal 600"), "{message}");
    }

    #[test]
    fn a_mode_of_the_wrong_type_is_told_the_form_to_write() {
        // Neither a string nor an integer: serde reports the type it found and
        // what the visitor expected, so the expectation is the whole remedy.
        let err = toml_edit::de::from_str::<Declared>("mode = true").expect_err("must be refused");
        let message = err.to_string();
        assert!(
            message.contains("expected one to four octal digits in quotes, like \"0600\""),
            "{message}",
        );
    }

    #[test]
    fn the_four_parser_rejections_survive_the_serde_layer() {
        for raw in ["8", "0688", "+644", "00644"] {
            let err = toml_edit::de::from_str::<Declared>(&format!("mode = \"{raw}\""))
                .expect_err("must be refused");
            assert!(
                err.to_string().contains("one to four octal digits"),
                "{raw:?}: {err}",
            );
        }
    }

    #[test]
    fn an_absent_mode_defaults_by_kind() {
        assert_eq!(Mode::resolve(None, Kind::File), Mode::DEFAULT_FILE);
        assert_eq!(Mode::resolve(None, Kind::Absent), Mode::DEFAULT_FILE);
        assert_eq!(Mode::resolve(None, Kind::Dir), Mode::DEFAULT_DIR);
        assert_eq!(
            Mode::resolve(Some(Mode::PRIVATE_FILE), Kind::Dir),
            Mode::PRIVATE_FILE,
            "a declared mode is authoritative whatever the kind",
        );
    }

    #[test]
    fn a_mode_knows_whether_anyone_else_can_reach_it() {
        assert!(!Mode::PRIVATE_DIR.is_shared());
        assert!(!Mode::PRIVATE_FILE.is_shared());
        assert!(Mode::DEFAULT_DIR.is_shared());
        assert!(Mode::from_bits(0o710).is_shared());
    }

    #[test]
    fn group_or_world_writable_matches_the_ssh_rule() {
        for bits in [0o622, 0o662, 0o666, 0o777, 0o020, 0o002] {
            assert!(
                Mode::from_bits(bits).is_group_or_world_writable(),
                "{bits:04o} is group- or world-writable",
            );
        }
        for bits in [0o600, 0o400, 0o644, 0o755, 0o700, 0o555] {
            assert!(
                !Mode::from_bits(bits).is_group_or_world_writable(),
                "{bits:04o} is not group- or world-writable",
            );
        }
    }

    #[test]
    fn a_directory_is_wider_than_the_private_file_it_holds() {
        // The worked example: ~/.ssh at 0755 holding a 0600 config.
        assert!(Mode::DEFAULT_DIR.is_wider_than(Mode::PRIVATE_FILE));
        // ...but an ordinary ~/.config at 0755 holding an ordinary 0644 file is
        // not a finding, or every target would carry one.
        assert!(!Mode::DEFAULT_DIR.is_wider_than(Mode::DEFAULT_FILE));
        // A group-writable directory is wider than a file that is not.
        assert!(Mode::from_bits(0o775).is_wider_than(Mode::DEFAULT_FILE));
        // 0700 grants nobody else anything, so it is never wider.
        assert!(!Mode::PRIVATE_DIR.is_wider_than(Mode::PRIVATE_FILE));
        assert!(!Mode::PRIVATE_DIR.is_wider_than(Mode::from_bits(0o000)));
    }

    #[test]
    fn a_directory_is_held_to_every_bit_of_its_declaration() {
        // Execute is traversal on both sides, so it counts.
        for bits in [0o711, 0o701, 0o710, 0o755] {
            assert!(
                Mode::from_bits(bits).grants_more_than(Mode::PRIVATE_DIR),
                "{bits:04o} grants more than 0700",
            );
        }
        // Narrower than, or equal to, the declaration grants nothing more.
        assert!(!Mode::PRIVATE_DIR.grants_more_than(Mode::DEFAULT_DIR));
        assert!(!Mode::from_bits(0o750).grants_more_than(Mode::DEFAULT_DIR));
        assert!(!Mode::DEFAULT_DIR.grants_more_than(Mode::DEFAULT_DIR));
        // The owner's bits and the special bits give nobody else anything.
        assert!(!Mode::from_bits(0o2700).grants_more_than(Mode::PRIVATE_DIR));
        assert!(!Mode::from_bits(0o700).grants_more_than(Mode::from_bits(0o500)));
        // Where `is_wider_than` and this differ: execute alone.
        assert!(!Mode::from_bits(0o711).is_wider_than(Mode::PRIVATE_DIR));
    }

    #[test]
    fn a_mode_includes_exactly_the_bits_it_sets() {
        assert!(Mode::PRIVATE_DIR.includes(Mode::PRIVATE_DIR));
        assert!(Mode::from_bits(0o2775).includes(Mode::PRIVATE_DIR));
        assert!(Mode::PRIVATE_FILE.includes(Mode::from_bits(0o400)));
        assert!(Mode::from_bits(0o400).includes(Mode::from_bits(0o400)));
        for bits in [0o600, 0o500, 0o300, 0o077, 0o7077] {
            assert!(
                !Mode::from_bits(bits).includes(Mode::PRIVATE_DIR),
                "{bits:04o} does not include 0700",
            );
        }
        assert!(!Mode::from_bits(0o200).includes(Mode::from_bits(0o400)));
        assert!(!Mode::from_bits(0o373).includes(Mode::from_bits(0o400)));
    }

    #[test]
    fn a_kind_names_what_bx_may_write_over() {
        assert!(Kind::Absent.is_writable_destination());
        assert!(Kind::File.is_writable_destination());
        assert!(!Kind::Dir.is_writable_destination());
        assert!(!Kind::Symlink.is_writable_destination());
        assert!(!Kind::Other.is_writable_destination());
    }

    #[test]
    fn a_kind_defaults_a_directory_wider_than_a_file() {
        assert_eq!(Kind::Dir.default_mode(), Mode::DEFAULT_DIR);
        assert_eq!(Kind::File.default_mode(), Mode::DEFAULT_FILE);
        assert_eq!(Kind::Absent.default_mode(), Mode::DEFAULT_FILE);
        assert_eq!(Kind::Symlink.default_mode(), Mode::DEFAULT_FILE);
        assert_eq!(Kind::Other.default_mode(), Mode::DEFAULT_FILE);
    }

    #[test]
    fn a_kind_reads_as_a_noun_phrase() {
        assert_eq!(Kind::Absent.to_string(), "nothing");
        assert_eq!(Kind::File.to_string(), "a file");
        assert_eq!(Kind::Dir.to_string(), "a directory");
        assert_eq!(Kind::Symlink.to_string(), "a symlink");
        assert_eq!(Kind::Other.to_string(), "not a regular file");
    }

    #[test]
    fn a_kind_comes_from_a_file_type_without_following_a_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").expect("seed");
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");

        let kind_of = |p: &std::path::Path| {
            Kind::from(std::fs::symlink_metadata(p).expect("stat").file_type())
        };
        assert_eq!(kind_of(&file), Kind::File);
        assert_eq!(kind_of(dir.path()), Kind::Dir);
        assert_eq!(kind_of(&link), Kind::Symlink);
    }
}
