//! When an interactive shell asks about followed externals: one `[update]`
//! table, and the interval spelling every key that says "how often" shares.
//!
//! # The `[update]` schema
//!
//! ```toml
//! [update]
//! interval = "7d"   # how long after a check an interactive shell asks again
//! ```
//!
//! Every key is optional. Without one, an interactive shell asks once
//! [`DEFAULT_INTERVAL`] has passed since the last check. The table says
//! nothing about *whether* a shell asks — that is a followed `[[external]]`'s
//! existence — only how often.
//!
//! # Layers
//!
//! `[update]` is one table, not a keyed list, so it merges key by key, the
//! last layer that sets a key winning, as `[history]` does. How often a person
//! wants to be asked is theirs, so it is usually written in `local.toml`; a
//! committed layer may set the default every machine starts from.
//!
//! # Intervals
//!
//! A whole number followed by `h` (hours) or `d` (days): `"12h"`, `"7d"`. No
//! other unit, no fraction and no space. The shortest is one hour, because
//! the background check an interval paces reaches the network, and a machine
//! that may be on a metered or mobile connection is owed a floor.

use std::path::Path;

use toml_edit::Table;

use super::{Ctx, Error, Origin};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[update]";

/// Every key an `[update]` table may carry.
const KEYS: [&str; 1] = ["interval"];

/// How long after a check an interactive shell asks again, when no layer says.
pub const DEFAULT_INTERVAL: Interval = Interval(7 * DAY);

/// Seconds in an hour.
const HOUR: u64 = 60 * 60;

/// Seconds in a day.
const DAY: u64 = 24 * HOUR;

/// The longest interval: ten years. Longer is "never", which is what not
/// following a branch says.
const MAX: u64 = 3650 * DAY;

/// A span of time between two checks, in whole seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Interval(u64);

impl Interval {
    /// One hour: the shortest interval.
    pub const HOUR: Self = Self(HOUR);

    /// The interval in seconds.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }

    /// Parse `"12h"` or `"7d"`.
    ///
    /// # Errors
    ///
    /// The message to report at the key: what the spelling is and why it is
    /// refused.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let refuse = |why: &str| {
            Err(format!(
                "`{raw}` is not an interval: {why}; write a whole number of hours or days, \
                 such as \"12h\" or \"7d\""
            ))
        };
        let Some(unit) = raw.chars().last() else {
            return refuse("it is empty");
        };
        let per = match unit {
            'h' => HOUR,
            'd' => DAY,
            _ => return refuse("it does not end in `h` or `d`"),
        };
        let digits = &raw[..raw.len() - 1];
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return refuse("it does not start with a whole number");
        }
        let Ok(count) = digits.parse::<u64>() else {
            return refuse("the number is too large");
        };
        match count.checked_mul(per) {
            Some(0) => refuse("it is zero; the shortest interval is one hour"),
            Some(seconds) if seconds <= MAX => Ok(Self(seconds)),
            _ => refuse("it is longer than ten years"),
        }
    }
}

impl std::fmt::Display for Interval {
    /// The shortest spelling [`Interval::parse`] reads back as this interval.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_multiple_of(DAY) {
            write!(f, "{}d", self.0 / DAY)
        } else {
            write!(f, "{}h", self.0 / HOUR)
        }
    }
}

/// What one layer's `[update]` table says, or what the merged layers say.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Update {
    /// How long after a check an interactive shell asks again.
    pub interval: Option<Interval>,
    /// Where the table that last set a key was written.
    pub origin: Option<Origin>,
}

impl Update {
    /// Fold a later layer's table over this one, key by key, the later layer
    /// winning.
    pub(crate) fn absorb(&mut self, later: &Self) {
        if let Some(interval) = later.interval {
            self.interval = Some(interval);
            self.origin.clone_from(&later.origin);
        }
    }

    /// The interval in force: the declared one, or [`DEFAULT_INTERVAL`].
    #[must_use]
    pub fn interval(&self) -> Interval {
        self.interval.unwrap_or(DEFAULT_INTERVAL)
    }
}

/// Parse an `[update]` table.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key beyond `interval`, and [`Error::BadValue`] or
/// [`Error::WrongType`] for an `interval` that is not one.
pub fn parse_update(table: &Table, file: &Path, text: &str) -> Result<Update, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;
    let interval = ctx
        .str_at(table, "interval")?
        .map(|raw| Interval::parse(raw).map_err(|message| ctx.bad(table, "interval", message)))
        .transpose()?;
    Ok(Update {
        interval,
        origin: Some(ctx.origin().clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml_edit::Document;

    fn parse(text: &str) -> Result<Update, String> {
        let doc = Document::parse(text).map_err(|e| e.to_string())?;
        let table = doc["update"].as_table().ok_or("no [update]")?;
        parse_update(table, Path::new("/repo/local.toml"), text).map_err(|e| e.to_string())
    }

    #[test]
    fn hours_and_days_parse_and_print_back() {
        for (raw, seconds, shown) in [
            ("1h", HOUR, "1h"),
            ("36h", 36 * HOUR, "36h"),
            ("48h", 2 * DAY, "2d"),
            ("7d", 7 * DAY, "7d"),
            ("3650d", MAX, "3650d"),
        ] {
            let interval = Interval::parse(raw).unwrap();
            assert_eq!(interval.seconds(), seconds, "{raw}");
            assert_eq!(interval.to_string(), shown, "{raw}");
            assert_eq!(Interval::parse(shown), Ok(interval), "{raw}");
        }
    }

    #[test]
    fn an_interval_that_is_not_one_is_refused_with_why() {
        for (raw, says) in [
            ("", "empty"),
            ("7", "does not end"),
            ("7m", "does not end"),
            ("7 d", "does not start with a whole number"),
            ("d", "does not start with a whole number"),
            ("-1d", "does not start with a whole number"),
            ("1.5d", "does not start with a whole number"),
            ("0h", "zero"),
            ("3651d", "ten years"),
            ("99999999999999999999d", "too large"),
            ("9999999999999999h", "ten years"),
        ] {
            let err = Interval::parse(raw).unwrap_err();
            assert!(err.contains(says), "{raw:?}: {err}");
            assert!(err.contains("\"7d\""), "names a spelling to write: {err}");
        }
    }

    #[test]
    fn the_table_parses_merges_and_defaults() {
        let committed = parse("[update]\ninterval = \"3d\"\n").unwrap();
        assert_eq!(committed.interval(), Interval::parse("3d").unwrap());
        assert_eq!(committed.origin.as_ref().unwrap().line, 1);

        let mut merged = Update::default();
        assert_eq!(merged.interval(), DEFAULT_INTERVAL);
        merged.absorb(&committed);
        merged.absorb(&parse("[update]\n").unwrap());
        assert_eq!(
            merged.interval(),
            Interval::parse("3d").unwrap(),
            "unset keeps"
        );
        merged.absorb(&parse("[update]\ninterval = \"12h\"\n").unwrap());
        assert_eq!(
            merged.interval(),
            Interval::parse("12h").unwrap(),
            "later wins"
        );
        assert_eq!(DEFAULT_INTERVAL.to_string(), "7d");
    }

    #[test]
    fn an_unknown_key_or_a_bad_interval_is_a_load_error_at_its_line() {
        let err = parse("[update]\nevery = \"1d\"\n").unwrap_err();
        assert!(err.contains("unknown key `every` in [update]"), "{err}");
        let err = parse("[update]\ninterval = \"soon\"\n").unwrap_err();
        assert!(err.starts_with("/repo/local.toml:2:"), "{err}");
        let err = parse("[update]\ninterval = 7\n").unwrap_err();
        assert!(err.contains("a string"), "{err}");
    }
}
