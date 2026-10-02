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
    let Ok(seconds) = epoch.parse::<u64>() else {
        return "unknown".to_string();
    };
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let of_day = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60
    )
}

/// The proleptic Gregorian date `days` after 1970-01-01. Counts from 1 March of
/// year 0, so a leap day is the last day of its year, and in 400-year eras,
/// each exactly 146 097 days long.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
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
