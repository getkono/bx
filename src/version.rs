//! What `bx --version` and `bx -V` print.
//!
//! bx is installed as a static binary, so its version output is the only way a
//! user reporting a problem can say which build they have. The release alone
//! does not say that: the output also carries the commit, the profile, the
//! compiler and the build time. `build.rs` captures each fact at compile time,
//! best-effort, and a fact it could not establish reads `unknown`.

use std::sync::OnceLock;

/// The commit bx was built from, `-dirty` when the tree had uncommitted
/// changes, or `unknown`.
pub const COMMIT_HASH: &str = env!("BX_COMMIT_HASH");

/// The committer date of that commit, ISO 8601, or `unknown`.
pub const COMMIT_DATE: &str = env!("BX_COMMIT_DATE");

/// The Cargo profile of this build, or `unknown`.
pub const BUILD_PROFILE: &str = env!("BX_BUILD_PROFILE");

/// The compiler's own `--version` line, or `unknown`.
pub const RUSTC_VERSION: &str = env!("BX_RUSTC_VERSION");

/// When the build ran, in seconds since the Unix epoch, or `unknown`.
pub const BUILD_EPOCH: &str = env!("BX_BUILD_EPOCH");

/// The version text for both `--version` and `-V`. clap puts the binary's name
/// before the first line.
pub fn long_version() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| {
        format_version(
            crate::VERSION,
            COMMIT_HASH,
            COMMIT_DATE,
            BUILD_PROFILE,
            RUSTC_VERSION,
            &built(BUILD_EPOCH),
        )
    })
}

/// The layout, apart from the values this build happens to carry.
fn format_version(
    version: &str,
    commit: &str,
    commit_date: &str,
    profile: &str,
    rustc: &str,
    built: &str,
) -> String {
    format!(
        "{version}\n\
         commit:  {commit} ({commit_date})\n\
         profile: {profile}\n\
         rustc:   {rustc}\n\
         built:   {built}"
    )
}

/// `epoch` seconds as a UTC `YYYY-MM-DDTHH:MM:SSZ`, or `unknown` when it is not
/// a count of seconds.
fn built(epoch: &str) -> String {
    epoch
        .parse::<u64>()
        .map_or_else(|_| "unknown".to_string(), utc)
}

/// `seconds` after the Unix epoch as a UTC `YYYY-MM-DDTHH:MM:SSZ`.
///
/// The date is the proleptic Gregorian one, by Neri and Schneider's Euclidean
/// affine functions ("Euclidean affine functions and their application to
/// calendar algorithms", 2022). It counts from 1 March of year 0, so a leap
/// day is the last day of its year. A century is 146 097 quarter days, a
/// four-year cycle 1 461 days, and one affine map takes the day of the year to
/// its month and day of month, the month in its high 16 bits.
pub(crate) fn utc(seconds: u64) -> String {
    // Four times the days since 0000-03-01, plus three: 1970-01-01 is day
    // 719 468 of that count.
    let quarters = seconds / 86_400 * 4 + 2_877_875;
    // Four times the day of the century, plus three: the remainder with its
    // two low bits set is the remainder rounded down to a whole day, plus three.
    let of_century = (quarters % 146_097) | 3;
    let day_of_year = of_century % 1_461 / 4;
    let month_day = 2_141 * day_of_year + 197_913;
    // Counted from March, January and February are months 13 and 14 of the
    // year before.
    let january = day_of_year >= 306;
    let year = quarters / 146_097 * 100 + of_century / 1_461 + u64::from(january);
    let month = month_day / 65_536;
    let month = if january { month - 12 } else { month };
    let day = month_day % 65_536 / 2_141 + 1;
    let of_day = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_is_the_release_then_one_labelled_line_per_fact() {
        assert_eq!(
            format_version(
                "1.2.3",
                "abc123",
                "2026-01-01T00:00:00Z",
                "release",
                "rustc 1.96.0",
                "2026-06-08T12:00:00Z",
            ),
            "1.2.3\n\
             commit:  abc123 (2026-01-01T00:00:00Z)\n\
             profile: release\n\
             rustc:   rustc 1.96.0\n\
             built:   2026-06-08T12:00:00Z"
        );
    }

    #[test]
    fn built_renders_epoch_seconds_as_a_utc_instant() {
        for (epoch, expected) in [
            ("0", "1970-01-01T00:00:00Z"),
            ("86399", "1970-01-01T23:59:59Z"),
            ("86400", "1970-01-02T00:00:00Z"),
            // A leap day, and the days on both sides of it.
            ("951782399", "2000-02-28T23:59:59Z"),
            ("951782400", "2000-02-29T00:00:00Z"),
            ("951868800", "2000-03-01T00:00:00Z"),
            // 2100 is not a leap year.
            ("4107542400", "2100-03-01T00:00:00Z"),
            ("1790135733", "2026-09-23T03:55:33Z"),
            // A year's last second and the next year's first.
            ("1798761599", "2026-12-31T23:59:59Z"),
            ("1798761600", "2027-01-01T00:00:00Z"),
        ] {
            assert_eq!(built(epoch), expected, "{epoch}");
        }
    }

    #[test]
    fn built_is_unknown_for_anything_that_is_not_a_count_of_seconds() {
        for epoch in ["unknown", "", "-1", "12.5", "2026-09-23"] {
            assert_eq!(built(epoch), "unknown", "{epoch:?}");
        }
    }

    #[test]
    fn the_version_text_opens_with_the_release_and_carries_every_fact() {
        let text = long_version();
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 5, "{text}");
        assert_eq!(lines[0], crate::VERSION);
        assert_eq!(lines[1], format!("commit:  {COMMIT_HASH} ({COMMIT_DATE})"));
        assert_eq!(lines[2], format!("profile: {BUILD_PROFILE}"));
        assert_eq!(lines[3], format!("rustc:   {RUSTC_VERSION}"));
        assert_eq!(lines[4], format!("built:   {}", built(BUILD_EPOCH)));
    }
}
